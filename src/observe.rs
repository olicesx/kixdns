//! Read-only observation hooks for the DNS engine.
//!
//! An [`EngineObserver`] receives structured events while the engine
//! processes requests (pipeline selection, rule matches, cache lookups,
//! upstream calls) and when the configuration is loaded or reloaded.
//! It exists so that metrics exporters, structured tracing and tests can
//! consume engine behaviour without depending on engine internals.
//!
//! Design constraints:
//!
//! - Observers cannot influence the engine. Every hook receives borrowed,
//!   immutable data; there is no way to intercept or rewrite a request.
//! - The hot path is not taxed when no observer is installed: the engine
//!   holds an `Option<Arc<dyn EngineObserver>>` and skips event
//!   construction after a single `is_some` check.
//! - Event payloads borrow from the engine (`&str` query names, rule ids,
//!   upstream addresses) instead of allocating. An observer that needs to
//!   keep data past the callback copies what it needs.
//! - All event structs and enums are `#[non_exhaustive]` so fields and
//!   variants can be added without breaking downstream implementations.
//!
//! [`NoopObserver`] is the "no hooks" implementation and [`TracingObserver`]
//! is a reference implementation that forwards every event to `tracing`.
//!
//! ```no_run
//! use std::sync::Arc;
//! use kixdns::engine::Engine;
//! use kixdns::observe::TracingObserver;
//!
//! # fn main() -> anyhow::Result<()> {
//! let cfg = kixdns::config::parse_config(r#"{ "pipelines": [] }"#)?;
//! let cfg = kixdns::matcher::RuntimePipelineConfig::from_config(cfg)?;
//! let engine = Engine::builder(cfg)
//!     .listener_label("default")
//!     .observer(Arc::new(TracingObserver))
//!     .build()?;
//! assert!(engine.observer().is_some());
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, RecordType};

use crate::config::Transport;

/// Receiver of engine events. Every method has an empty default body, so an
/// implementation only overrides the events it cares about.
///
/// Hooks run synchronously on the request path; implementations must be
/// cheap and must never block.
///
/// [`config_loaded`] runs while the engine holds its reload lock. An
/// implementation must not call `Engine::reload` or `Engine::reload_from`
/// from inside it, directly or indirectly: the call would block on the lock
/// it is already under, and every later reload from any thread would block
/// behind it, leaving the engine on its current configuration for good.
///
/// [`config_loaded`]: EngineObserver::config_loaded
#[allow(unused_variables)]
pub trait EngineObserver: Send + Sync + 'static {
    /// A client request entered the engine. Emitted exactly once per request,
    /// including background refresh requests (see
    /// [`RequestContext::background_refresh`]).
    ///
    /// Requests answered on the synchronous fast path have their whole
    /// lifecycle reported in one batch at the answering site, so the moment a
    /// callback arrives says nothing about when that step happened; take
    /// timings from [`RequestOutcome::latency`], not from callback arrival.
    fn request_started(&self, ctx: &RequestContext<'_>) {}

    /// The request left the engine. Paired with [`request_started`]; also
    /// emitted when the request future is dropped before completing (for
    /// example on a listener timeout), with
    /// [`RequestStatus::Cancelled`].
    ///
    /// [`request_started`]: EngineObserver::request_started
    fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome<'_>) {}

    /// A pipeline was chosen for the request: once after pipeline selection
    /// and again for every `jump_to_pipeline` decision.
    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {}

    /// The rule cache was consulted for a pipeline: once per lookup, hit or
    /// miss (a lookup that is skipped, for example during a `continue`
    /// re-evaluation or a background refresh, is not reported).
    fn rule_cache_lookup(&self, ctx: &RequestContext<'_>, event: &RuleCacheLookup<'_>) {}

    /// A rule's matchers were evaluated, whether or not they matched. Request
    /// phase: every candidate rule the pipeline evaluated, in order. Response
    /// phase: once per rule that has response matchers. Rule cache hits replay
    /// only [`rule_matched`], not this event.
    ///
    /// [`rule_matched`]: EngineObserver::rule_matched
    fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {}

    /// A rule's matchers evaluated to true. Request-phase matches are
    /// reported after the pipeline's decision is known, that is after every
    /// candidate's [`rule_evaluated`], so the decision kind is accurate.
    ///
    /// [`rule_evaluated`]: EngineObserver::rule_evaluated
    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {}

    /// A pipeline produced its decision for the request, after rule
    /// evaluation or from a rule cache hit.
    fn decision_made(&self, ctx: &RequestContext<'_>, event: &DecisionMade<'_>) {}

    /// The response cache was consulted for the request. Exactly one
    /// [`cache_hit`] or [`cache_miss`] follows, and neither is ever reported
    /// without a preceding `cache_lookup` of the same request, so hits and
    /// misses always add up to lookups. Background refresh requests bypass
    /// the cache and report none of the three.
    ///
    /// [`cache_hit`]: EngineObserver::cache_hit
    /// [`cache_miss`]: EngineObserver::cache_miss
    fn cache_lookup(&self, ctx: &RequestContext<'_>) {}

    /// The response cache answered the request. Always paired with the
    /// request's [`cache_lookup`].
    ///
    /// [`cache_lookup`]: EngineObserver::cache_lookup
    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit<'_>) {}

    /// The response cache had no usable entry. Always paired with the
    /// request's [`cache_lookup`].
    ///
    /// [`cache_lookup`]: EngineObserver::cache_lookup
    fn cache_miss(&self, ctx: &RequestContext<'_>) {}

    /// An identical query was already in flight, and the request took that
    /// query's answer instead of forwarding its own. Reported when the answer
    /// arrives, in place of the [`upstream_attempt`]s this forward would
    /// have made.
    ///
    /// An upstream failure still ends with an answer: the engine synthesises
    /// SERVFAIL (or serves a stale entry) and shares it, so the request
    /// reports this event and completes with that answer. Only when the query
    /// it waited for ends without one (the engine returned an error, or the
    /// query was cancelled) does the request forward by itself, and then this
    /// is not reported.
    ///
    /// [`upstream_attempt`]: EngineObserver::upstream_attempt
    fn inflight_joined(&self, ctx: &RequestContext<'_>) {}

    /// A query is about to be sent to an upstream server. Every attempt is
    /// followed by exactly one [`upstream_result`], including attempts that
    /// lose a concurrent race ([`UpstreamOutcome::Aborted`]).
    ///
    /// [`upstream_result`]: EngineObserver::upstream_result
    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {}

    /// An upstream attempt completed; strictly one per [`upstream_attempt`].
    ///
    /// [`upstream_attempt`]: EngineObserver::upstream_attempt
    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {}

    /// A configuration became active: the initial load (`build`) and every
    /// successful `reload` / `reload_from`.
    ///
    /// Runs inside the engine's reload lock. Never call `Engine::reload` or
    /// `Engine::reload_from` from here, directly or indirectly: the reload
    /// path of the whole engine would block permanently.
    fn config_loaded(&self, event: &ConfigLoaded<'_>) {}

    /// A hot reload was rejected; the previous configuration stays active.
    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {}
}

/// Immutable description of the request an event belongs to.
///
/// `request_id` is unique for the lifetime of the engine and is the key to
/// correlate all events of one request.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RequestContext<'a> {
    /// Engine-local request identifier, unique per engine instance.
    pub request_id: u64,
    /// Listener label of the engine that handles the request.
    pub listener_label: &'a str,
    /// Client address as seen by the listener.
    pub client: SocketAddr,
    /// Transport the query arrived over, as tagged by the listener that
    /// received it. `None` for background refreshes, and for requests handed
    /// to an engine handle that no listener tagged (see
    /// [`Engine::with_client_transport`]).
    ///
    /// [`Engine::with_client_transport`]: crate::engine::Engine::with_client_transport
    pub transport: Option<ClientTransport>,
    /// Query name, lower-cased, without a trailing dot.
    pub qname: &'a str,
    /// Query type.
    pub qtype: RecordType,
    /// Query class.
    pub qclass: DNSClass,
    /// `true` when the request is an internal cache refresh rather than a
    /// client query. Refresh requests bypass the cache lookup.
    pub background_refresh: bool,
}

/// Transport a client query arrived over. Distinct from the upstream
/// [`Transport`], which also covers ways of sending (`TcpUdp`, DoT, DoQ) that
/// no built-in listener accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientTransport {
    /// Plain DNS over UDP.
    Udp,
    /// Plain DNS over TCP.
    Tcp,
    /// DNS over HTTPS.
    Doh,
}

/// How a request ended.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RequestOutcome<'a> {
    /// Wall-clock time between `request_started` and `request_finished`.
    pub latency: Duration,
    /// Completion status.
    pub status: RequestStatus,
    /// The DNS message the engine produced for the client, in wire format.
    /// Set exactly when [`status`] is [`RequestStatus::Completed`]; a failed
    /// or cancelled request never produced one. The engine lends the bytes
    /// it already holds and parses nothing; an observer that wants the
    /// response code or the records parses them itself.
    ///
    /// These are the bytes before the listener's own rewriting, so they can
    /// differ from what the client receives. A fresh cache hit on the
    /// synchronous fast path is lent as stored: the listener still rewrites
    /// its transaction id and ages its TTLs. A UDP response larger than the
    /// client's limit is truncated by the listener: it sets TC, drops the
    /// records that do not fit and lowers the advertised EDNS payload size to
    /// the client's. The response code is not changed.
    ///
    /// [`status`]: RequestOutcome::status
    pub response: Option<&'a [u8]>,
    /// Why the engine failed the request, with its cause chain. Set exactly
    /// when [`status`] is [`RequestStatus::Failed`].
    ///
    /// [`status`]: RequestOutcome::status
    pub error: Option<&'a str>,
}

/// Completion status of a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RequestStatus {
    /// A response was produced (including SERVFAIL/REFUSED answers built by
    /// the engine itself).
    Completed,
    /// The engine returned an error; the listener answers SERVFAIL.
    Failed,
    /// The request future was dropped before completing.
    Cancelled,
}

/// A rule whose matchers evaluated to true.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RuleMatched<'a> {
    /// Pipeline that owns the rule.
    pub pipeline: &'a str,
    /// Rule name from the configuration.
    pub rule: &'a str,
    /// Whether request or response matchers matched.
    pub phase: RulePhase,
    /// What the match leads to.
    pub decision: DecisionKind,
    /// `true` when the match came from the synchronous fast path
    /// (`handle_packet_fast`), which answers static rules without the full
    /// request pipeline.
    pub fast_path: bool,
}

/// The rule cache was consulted for a pipeline.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RuleCacheLookup<'a> {
    /// Pipeline whose rules were looked up.
    pub pipeline: &'a str,
    /// Whether a valid cached decision was found.
    pub hit: bool,
    /// Number of request-phase rules recorded with the cached decision;
    /// `0` on a miss.
    pub matched_rules: usize,
}

/// A rule's matchers were evaluated.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RuleEvaluated<'a> {
    /// Pipeline that owns the rule.
    pub pipeline: &'a str,
    /// Rule name from the configuration.
    pub rule: &'a str,
    /// Which matcher list was evaluated.
    pub phase: RulePhase,
    /// Whether the matcher chain evaluated to true.
    pub matched: bool,
    /// Number of matchers in the evaluated chain.
    pub matchers: usize,
}

/// A pipeline produced its decision for the request.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DecisionMade<'a> {
    /// Pipeline that produced the decision.
    pub pipeline: &'a str,
    /// Rule that decided, or `None` when no rule matched and the default
    /// upstream applies.
    pub rule: Option<&'a str>,
    /// What was decided.
    pub detail: DecisionDetail<'a>,
}

/// Content of a decision.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum DecisionDetail<'a> {
    /// A response is synthesised locally.
    Static {
        /// Response code of the synthesised answer.
        rcode: ResponseCode,
        /// Number of answer records.
        answers: usize,
    },
    /// The query is forwarded.
    Forward {
        /// Configured upstream string (may list several addresses).
        upstream: &'a str,
        /// Transport the forwarder will use for every listed address, or
        /// `None` when a single value cannot describe the list: any address
        /// carries its own `scheme://` prefix, so the addresses need not share
        /// one transport. The per-address transport is reported by
        /// [`UpstreamAttempt::transport`].
        transport: Option<Transport>,
    },
    /// Processing continues in another pipeline.
    Jump {
        /// Target pipeline.
        pipeline: &'a str,
    },
}

/// Matching phase of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RulePhase {
    /// Request matchers (`matchers`).
    Request,
    /// Response matchers (`response_matchers`).
    Response,
}

/// Outcome of a rule match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecisionKind {
    /// A response is synthesised locally (static, deny, TXT replacement).
    Static,
    /// The query is forwarded to an upstream, or an upstream response is
    /// accepted as is.
    Forward,
    /// Processing continues in another pipeline.
    Jump,
    /// The rule matched but did not decide; evaluation continues with the
    /// next rule (for example log-only rules or `continue`).
    Continue,
}

/// The response cache answered a request.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CacheHit<'a> {
    /// Which kind of entry answered.
    pub kind: CacheHitKind,
    /// Time left before the entry's TTL expires; `None` for stale hits.
    pub remaining_ttl: Option<Duration>,
    /// TTL the entry was cached with, when known.
    pub original_ttl: Option<Duration>,
    /// Upstream whose answer was cached, as recorded when the entry was
    /// stored; `None` when a rule synthesised the cached answer.
    pub source: Option<&'a str>,
}

/// Which kind of cached response answered a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CacheHitKind {
    /// The entry is within its TTL.
    Fresh,
    /// The entry is past its TTL and served immediately (RFC 8767 with
    /// `serve_stale_client_timeout_ms = 0`).
    Stale,
    /// The entry is past its TTL and served because the upstream did not
    /// answer within `serve_stale_client_timeout_ms`.
    StaleClientTimeout,
    /// The entry is past its TTL and served because every upstream attempt
    /// failed.
    StaleUpstreamFailure,
}

/// A query is being sent to an upstream.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct UpstreamAttempt<'a> {
    /// Upstream address without the transport prefix
    /// (for example `1.1.1.1:53` or `dns.example/dns-query`).
    pub upstream: &'a str,
    /// Transport selected for this address.
    pub transport: Transport,
}

/// An upstream attempt completed.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct UpstreamResult<'a> {
    /// Upstream address without the transport prefix.
    pub upstream: &'a str,
    /// Transport selected for this address (from its prefix or the configured
    /// default). One attempt/result pair covers every send made for the
    /// address: a UDP attempt may consist of a hedged retry plus a TCP
    /// fallback, up to three real sends.
    pub transport: Transport,
    /// Transport that actually carried the answer. Differs from `transport`
    /// when a UDP query fell back to TCP (TC bit set, or UDP failed with TCP
    /// fallback enabled) and for `tcp_udp`, where it names the side that won.
    /// Equals `transport` for errors and aborted attempts.
    pub via: Transport,
    /// Result classification.
    pub outcome: UpstreamOutcome,
    /// Time spent on this attempt.
    pub latency: Duration,
    /// Response code of the received answer; `None` when no answer was
    /// received or it could not be parsed.
    pub rcode: Option<ResponseCode>,
    /// TC bit of the received answer; `None` when no answer was received or
    /// it could not be parsed.
    pub truncated: Option<bool>,
    /// Error for [`UpstreamOutcome::Error`]; `None` otherwise.
    pub error: Option<&'a anyhow::Error>,
}

/// Classification of an upstream attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UpstreamOutcome {
    /// A usable response was received.
    Success,
    /// A response was received but discarded (SERVFAIL/REFUSED while other
    /// upstreams of a concurrent set were still pending).
    Rejected,
    /// The attempt failed (timeout, transport error, task failure).
    Error,
    /// The attempt was still in flight when another upstream of the same
    /// concurrent set answered, and was cancelled.
    Aborted,
}

/// A configuration became active. Reported by `Engine::builder(..).build()`
/// with generation `1` and by every `Engine::reload` / `Engine::reload_from`
/// with the generation that call allocated, so generations are strictly
/// increasing and never skip or repeat.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ConfigLoaded<'a> {
    /// Path the configuration was read from, when the loader supplied it
    /// (`EngineBuilder::config_source`, `Engine::reload_from`).
    pub path: Option<&'a Path>,
    /// Monotonic generation counter: `1` for the initial configuration,
    /// incremented by every successful reload.
    pub generation: u64,
    /// Raw configuration text, when the loader supplied it. Observers that
    /// need a fingerprint derive it from this text.
    pub source: Option<&'a str>,
}

/// A hot reload failed and the previous configuration remains active.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ConfigReloadFailed<'a> {
    /// Path of the rejected configuration.
    pub path: &'a Path,
    /// Human-readable error including its cause chain.
    pub error: &'a str,
}

/// Observer that ignores every event. Installing it is equivalent to
/// installing no observer.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopObserver;

impl EngineObserver for NoopObserver {}

/// Reference observer that emits every event as a `tracing` event at
/// `DEBUG` level under the `kixdns::observe` target, with the event kind in
/// the `event` field.
///
/// The `kixdns` binary installs it when started with `--debug`. Library users
/// install it themselves via `Engine::builder(cfg).observer(Arc::new(TracingObserver))`;
/// nothing is installed by default. Narrow the output with
/// `RUST_LOG=kixdns::observe=debug`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingObserver;

const TRACE_TARGET: &str = "kixdns::observe";

/// Response code from a DNS header: the low four bits of byte 3. The
/// extended bits an OPT record may carry are not read; this is a log field,
/// not a parser.
fn header_rcode(message: &[u8]) -> Option<ResponseCode> {
    message
        .get(3)
        .map(|flags| ResponseCode::from(0, flags & 0x0F))
}

impl EngineObserver for TracingObserver {
    fn request_started(&self, ctx: &RequestContext<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "request_started",
            request_id = ctx.request_id,
            listener = ctx.listener_label,
            client = %ctx.client,
            transport = ctx.transport.map(tracing::field::debug),
            qname = ctx.qname,
            qtype = ?ctx.qtype,
            qclass = ?ctx.qclass,
            background_refresh = ctx.background_refresh,
            "request started"
        );
    }

    fn request_finished(&self, ctx: &RequestContext<'_>, outcome: &RequestOutcome<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "request_finished",
            request_id = ctx.request_id,
            status = ?outcome.status,
            latency_us = outcome.latency.as_micros() as u64,
            rcode = outcome.response.and_then(header_rcode).map(tracing::field::display),
            response_bytes = outcome.response.map(<[u8]>::len),
            error = outcome.error,
            "request finished"
        );
    }

    fn pipeline_selected(&self, ctx: &RequestContext<'_>, pipeline: &str) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "pipeline_selected",
            request_id = ctx.request_id,
            pipeline,
            "pipeline selected"
        );
    }

    fn rule_cache_lookup(&self, ctx: &RequestContext<'_>, event: &RuleCacheLookup<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "rule_cache_lookup",
            request_id = ctx.request_id,
            pipeline = event.pipeline,
            hit = event.hit,
            matched_rules = event.matched_rules,
            "rule cache lookup"
        );
    }

    fn rule_evaluated(&self, ctx: &RequestContext<'_>, event: &RuleEvaluated<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "rule_evaluated",
            request_id = ctx.request_id,
            pipeline = event.pipeline,
            rule = event.rule,
            phase = ?event.phase,
            matched = event.matched,
            matchers = event.matchers,
            "rule evaluated"
        );
    }

    fn rule_matched(&self, ctx: &RequestContext<'_>, event: &RuleMatched<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "rule_matched",
            request_id = ctx.request_id,
            pipeline = event.pipeline,
            rule = event.rule,
            phase = ?event.phase,
            decision = ?event.decision,
            fast_path = event.fast_path,
            "rule matched"
        );
    }

    fn decision_made(&self, ctx: &RequestContext<'_>, event: &DecisionMade<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "decision_made",
            request_id = ctx.request_id,
            pipeline = event.pipeline,
            rule = event.rule,
            detail = ?event.detail,
            "decision made"
        );
    }

    fn cache_lookup(&self, ctx: &RequestContext<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "cache_lookup",
            request_id = ctx.request_id,
            "cache lookup"
        );
    }

    fn cache_hit(&self, ctx: &RequestContext<'_>, event: &CacheHit<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "cache_hit",
            request_id = ctx.request_id,
            kind = ?event.kind,
            remaining_ttl_s = event.remaining_ttl.map(|ttl| ttl.as_secs()),
            original_ttl_s = event.original_ttl.map(|ttl| ttl.as_secs()),
            source = event.source,
            "cache hit"
        );
    }

    fn cache_miss(&self, ctx: &RequestContext<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "cache_miss",
            request_id = ctx.request_id,
            "cache miss"
        );
    }

    fn inflight_joined(&self, ctx: &RequestContext<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "inflight_joined",
            request_id = ctx.request_id,
            "joined an in-flight query"
        );
    }

    fn upstream_attempt(&self, ctx: &RequestContext<'_>, event: &UpstreamAttempt<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "upstream_attempt",
            request_id = ctx.request_id,
            upstream = event.upstream,
            transport = ?event.transport,
            "upstream attempt"
        );
    }

    fn upstream_result(&self, ctx: &RequestContext<'_>, event: &UpstreamResult<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "upstream_result",
            request_id = ctx.request_id,
            upstream = event.upstream,
            transport = ?event.transport,
            outcome = ?event.outcome,
            via = ?event.via,
            latency_us = event.latency.as_micros() as u64,
            rcode = event.rcode.map(tracing::field::display),
            truncated = event.truncated,
            error = event.error.map(tracing::field::display),
            "upstream result"
        );
    }

    fn config_loaded(&self, event: &ConfigLoaded<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "config_loaded",
            path = event.path.map(|path| tracing::field::display(path.display())),
            generation = event.generation,
            source_bytes = event.source.map(str::len),
            "config loaded"
        );
    }

    fn config_reload_failed(&self, event: &ConfigReloadFailed<'_>) {
        tracing::debug!(
            target: TRACE_TARGET,
            event = "config_reload_failed",
            path = %event.path.display(),
            error = event.error,
            "config reload failed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_rcode_reads_the_low_four_bits_of_byte_three() {
        assert_eq!(
            header_rcode(&[0x12, 0x34, 0x81, 0x83]),
            Some(ResponseCode::NXDomain)
        );
        assert_eq!(
            header_rcode(&[0x12, 0x34, 0x85, 0xF0]),
            Some(ResponseCode::NoError)
        );
        assert_eq!(header_rcode(&[0x12, 0x34, 0x81]), None);
    }

    #[test]
    fn built_in_observers_accept_every_event() {
        let ctx = RequestContext {
            request_id: 7,
            listener_label: "default",
            client: "127.0.0.1:53000".parse().unwrap(),
            transport: Some(ClientTransport::Udp),
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            background_refresh: false,
        };
        let error = anyhow::anyhow!("boom");
        let observers: [&dyn EngineObserver; 2] = [&NoopObserver, &TracingObserver];
        for observer in observers {
            observer.request_started(&ctx);
            observer.pipeline_selected(&ctx, "main");
            observer.rule_matched(
                &ctx,
                &RuleMatched {
                    pipeline: "main",
                    rule: "static",
                    phase: RulePhase::Request,
                    decision: DecisionKind::Static,
                    fast_path: true,
                },
            );
            observer.cache_lookup(&ctx);
            observer.cache_hit(
                &ctx,
                &CacheHit {
                    kind: CacheHitKind::Fresh,
                    remaining_ttl: Some(Duration::from_secs(30)),
                    original_ttl: Some(Duration::from_secs(60)),
                    source: Some("1.1.1.1:53"),
                },
            );
            observer.cache_miss(&ctx);
            observer.rule_cache_lookup(
                &ctx,
                &RuleCacheLookup {
                    pipeline: "main",
                    hit: false,
                    matched_rules: 0,
                },
            );
            observer.rule_evaluated(
                &ctx,
                &RuleEvaluated {
                    pipeline: "main",
                    rule: "static",
                    phase: RulePhase::Request,
                    matched: true,
                    matchers: 1,
                },
            );
            observer.decision_made(
                &ctx,
                &DecisionMade {
                    pipeline: "main",
                    rule: Some("static"),
                    detail: DecisionDetail::Static {
                        rcode: ResponseCode::NXDomain,
                        answers: 0,
                    },
                },
            );
            observer.inflight_joined(&ctx);
            observer.upstream_attempt(
                &ctx,
                &UpstreamAttempt {
                    upstream: "1.1.1.1:53",
                    transport: Transport::Udp,
                },
            );
            observer.upstream_result(
                &ctx,
                &UpstreamResult {
                    upstream: "1.1.1.1:53",
                    transport: Transport::Udp,
                    via: Transport::Udp,
                    outcome: UpstreamOutcome::Error,
                    latency: Duration::from_millis(3),
                    rcode: None,
                    truncated: None,
                    error: Some(&error),
                },
            );
            // A SERVFAIL header, so the tracing observer reads a response code.
            // 一个 SERVFAIL 头部，让 tracing 观察者读到响应码。
            let servfail = [0x12, 0x34, 0x81, 0x82, 0, 1, 0, 0, 0, 0, 0, 0];
            observer.request_finished(
                &ctx,
                &RequestOutcome {
                    latency: Duration::from_millis(4),
                    status: RequestStatus::Completed,
                    response: Some(&servfail),
                    error: None,
                },
            );
            observer.request_finished(
                &ctx,
                &RequestOutcome {
                    latency: Duration::from_millis(4),
                    status: RequestStatus::Failed,
                    response: None,
                    error: Some("parse request for static: unexpected end of input"),
                },
            );
            observer.config_loaded(&ConfigLoaded {
                path: Some(Path::new("config/pipeline.json")),
                generation: 1,
                source: Some("{}"),
            });
            observer.config_reload_failed(&ConfigReloadFailed {
                path: Path::new("config/pipeline.json"),
                error: "invalid json",
            });
        }
    }
}
