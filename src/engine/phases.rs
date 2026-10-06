use super::Engine;
use crate::cache::CacheEntry;
use crate::config::{Action, Transport};
use crate::engine::observation::{Observed, response_decision_kind};
use crate::engine::response::{extract_ttl, extract_ttl_for_refresh};
use crate::engine::response_log::ResponseInfo;
use crate::engine::rules::{self, ResponseActionResult, ResponseContext};
use crate::engine::types::EngineInner;
use crate::engine::upstream::{UpstreamFailure, reject_failure_reply_on_refresh};
use crate::engine::utils::InflightCleanupGuard;
use crate::engine::utils::engine_helpers::{build_response, build_servfail_response_fast};
use crate::matcher::{RuntimeResponseMatcherWithOp, eval_match_chain};
use crate::observe::{CacheHit, CacheHitKind, RuleEvaluated, RuleMatched, RulePhase};
use crate::proto_utils;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// Result of the Forward phase
pub enum ForwardResult {
    /// Request completed with a response (bytes)
    Success(Bytes),
    /// Request needs to continue (e.g. Action::Continue)
    /// Boxed to reduce enum size (ResponseContext is ~256 bytes)
    Continue(Box<Option<ResponseContext>>),
}
use hickory_proto::serialize::binary::BinDecodable;

/// Standard cache check logic that replicates `handle_packet_internal`'s behavior.
/// Checks Moka cache, validates TTL, patches response, and triggers background refresh if needed.
/// Immutable cache lookup data shared by normal and refresh-wait paths.
pub struct CacheLookupContext<'a> {
    pub state: &'a Arc<EngineInner>,
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub pipeline_id: &'a str,
    pub dedupe_hash: u64,
    pub tx_id: u16,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    /// Observer context of the request; cache hits are reported through it.
    /// 所属请求的观察者上下文；缓存命中通过它上报。
    pub observed: Observed<'a>,
}

/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub fn check_cache(engine: &Engine, context: &CacheLookupContext<'_>) -> Option<Bytes> {
    check_cache_logged(engine, context, &mut ResponseInfo::default())
}

pub(crate) fn check_cache_logged(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    response: &mut ResponseInfo,
) -> Option<Bytes> {
    let CacheLookupContext {
        state,
        qname: qname_ref,
        qtype,
        qclass,
        pipeline_id,
        dedupe_hash,
        tx_id,
        start: _,
        peer,
        observed,
    } = *context;

    // moka 同步缓存自动处理过期，无需检查 expires_at / moka sync cache automatically handles expiration, no need to check expires_at
    if let Some(hit) = engine.cache_get(&dedupe_hash) {
        // Validate hit against query parameters to avoid collisions
        if hit.qtype == u16::from(qtype)
            && hit.pipeline_id.as_ref() == pipeline_id
            && hit.qname.as_ref() == qname_ref
        {
            let elapsed_secs = hit.inserted_at.elapsed().as_secs();

            // Check manual expiration (in case moka hasn't evicted it yet or for strict TTL compliance)
            if elapsed_secs >= hit.original_ttl as u64 {
                // serve_stale disabled → invalidate and miss
                if !state.pipeline.settings.serve_stale {
                    engine.cache_invalidate(&dedupe_hash);
                    return None;
                }
                // Don't serve SERVFAIL/REFUSED as stale
                if hit.rcode == ResponseCode::ServFail || hit.rcode == ResponseCode::Refused {
                    engine.cache_invalidate(&dedupe_hash);
                    return None;
                }

                // Check serve_stale_expire_ttl: how long past original TTL has this been stale?
                // 检查 serve_stale_expire_ttl：此条目已过期多长时间？
                let stale_age = elapsed_secs - hit.original_ttl as u64;
                if state.pipeline.settings.serve_stale_expire_ttl > 0
                    && stale_age > state.pipeline.settings.serve_stale_expire_ttl
                {
                    // Stale entry has exceeded the maximum stale window
                    // 过期条目已超过最大过期窗口
                    engine.cache_invalidate(&dedupe_hash);
                    debug!(
                        event = "serve_stale_expired",
                        qname = %qname_ref,
                        qtype = ?qtype,
                        stale_age = stale_age,
                        serve_stale_expire_ttl = state.pipeline.settings.serve_stale_expire_ttl,
                        "stale entry exceeded serve_stale_expire_ttl, invalidating"
                    );
                    return None;
                }

                // serve_stale_client_timeout_ms > 0: don't serve stale here, let the caller
                // try upstream first with a short timeout (handled in handle_packet_internal).
                // serve_stale_client_timeout_ms > 0: 不在此处返回 stale，
                // 让调用者先尝试上游查询（在 handle_packet_internal 中处理）。
                if state.pipeline.settings.serve_stale_client_timeout_ms > 0 {
                    // Don't invalidate - we still need the stale entry for the client_timeout path.
                    // Spawn background refresh proactively.
                    if hit.upstream.is_some() {
                        engine.spawn_background_refresh(
                            (*state).clone(),
                            dedupe_hash,
                            pipeline_id,
                            qname_ref,
                            qtype,
                            qclass,
                            peer.ip(),
                        );
                    }
                    return None;
                }

                // serve_stale_client_timeout_ms == 0: Serve stale immediately (optimistic mode)
                // RFC 8767: 立即返回 stale 数据 + 后台刷新
                let stale_ttl = state.pipeline.settings.serve_stale_ttl;
                let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);

                // Set all TTLs to serve_stale_ttl
                crate::proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl);

                // Rewrite Transaction ID
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }

                // serve_stale_ttl_reset: reset stale expiry timer by re-inserting with shifted inserted_at
                // 重置过期计时器：通过重新插入条目并将 inserted_at 设置为"刚过期"的时间点
                if state.pipeline.settings.serve_stale_ttl_reset {
                    let new_entry = hit.clone_with_refreshed_ttl();
                    engine.cache_insert(dedupe_hash, std::sync::Arc::new(new_entry));
                }

                // Trigger background refresh to get fresh data
                if hit.upstream.is_some() {
                    engine.spawn_background_refresh(
                        (*state).clone(),
                        dedupe_hash,
                        pipeline_id,
                        qname_ref,
                        qtype,
                        qclass,
                        peer.ip(),
                    );
                }

                debug!(
                    event = "serve_stale_on_ttl_expiry",
                    qname = %qname_ref,
                    qtype = ?qtype,
                    rcode = ?hit.rcode,
                    original_ttl = hit.original_ttl,
                    elapsed_secs = elapsed_secs,
                    stale_ttl = stale_ttl,
                    stale_age = stale_age,
                    ttl_reset = state.pipeline.settings.serve_stale_ttl_reset,
                    client_ip = %peer.ip(),
                    pipeline = %pipeline_id,
                    "RFC 8767: serving stale cache entry on TTL expiry"
                );

                if let Some((observer, ctx)) = observed {
                    observer.cache_hit(
                        ctx,
                        &CacheHit {
                            kind: CacheHitKind::Stale,
                            remaining_ttl: None,
                            original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                        },
                    );
                }
                response.cache_hit = true;
                response.upstream =
                    Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
                return Some(resp_bytes.freeze());
            } else {
                // Cache hit is valid

                // clone bytes and rewrite transaction ID to match requester / 克隆字节并重写事务 ID 以匹配请求者
                let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);

                // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                let elapsed = crate::proto_utils::saturating_u64_to_u32(elapsed_secs);
                if elapsed > 0 {
                    crate::proto_utils::patch_all_ttls(&mut resp_bytes, elapsed);
                }

                // Rewrite Transaction ID
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }
                let resp_bytes = resp_bytes.freeze();

                // ========== NEW: Trigger background refresh before returning cached response ==========
                let cfg = &state.pipeline;

                let remaining_ttl = hit.refresh_ttl.saturating_sub(elapsed);

                // Check if we should trigger background refresh
                let should_refresh = if cfg.settings.cache_background_refresh
                    && hit.upstream.is_some()
                    && hit.refresh_ttl >= cfg.settings.cache_refresh_min_ttl
                {
                    let threshold = (hit.refresh_ttl as u64
                        * cfg.settings.cache_refresh_threshold_percent as u64)
                        / 100;
                    remaining_ttl as u64 <= threshold
                } else {
                    false
                };

                if should_refresh {
                    // Trigger background refresh asynchronously
                    debug!(
                        event = "cache_background_refresh_trigger",
                        qname = %qname_ref,
                        qtype = ?qtype,
                        remaining_ttl = remaining_ttl,
                        original_ttl = hit.original_ttl,
                        refresh_ttl = hit.refresh_ttl,
                        "Triggering background refresh for cached entry"
                    );

                    engine.spawn_background_refresh(
                        (*state).clone(),
                        dedupe_hash,
                        pipeline_id,
                        qname_ref,
                        qtype,
                        qclass,
                        peer.ip(),
                    );
                }

                response.cache_hit = true;
                response.upstream =
                    Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));

                if let Some((observer, ctx)) = observed {
                    observer.cache_hit(
                        ctx,
                        &CacheHit {
                            kind: CacheHitKind::Fresh,
                            remaining_ttl: Some(Duration::from_secs(
                                hit.original_ttl.saturating_sub(elapsed) as u64,
                            )),
                            original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                        },
                    );
                }
                return Some(resp_bytes);
            }
        }
    }
    None
}

/// RFC 8767: Check if a stale (expired but still in moka) cache entry exists.
/// Returns the stale response bytes with TTL set to serve_stale_ttl.
/// RFC 8767: 检查是否存在过期但仍在 moka 中的缓存条目。
/// 返回 TTL 设置为 serve_stale_ttl 的过期响应字节。
///
/// `kind` names the stale-serving path for the observer (client timeout or
/// upstream failure). / `kind` 标明过期服务的路径（客户端超时或上游失败），用于上报观察者。
///
/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub fn check_stale_cache(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    kind: CacheHitKind,
) -> Option<Bytes> {
    check_stale_cache_logged(engine, context, kind, &mut ResponseInfo::default())
}

pub(crate) fn check_stale_cache_logged(
    engine: &Engine,
    context: &CacheLookupContext<'_>,
    kind: CacheHitKind,
    response: &mut ResponseInfo,
) -> Option<Bytes> {
    let CacheLookupContext {
        state,
        qname: qname_ref,
        qtype,
        qclass,
        pipeline_id,
        dedupe_hash,
        tx_id,
        start: _,
        peer,
        observed,
    } = *context;
    if !state.pipeline.settings.serve_stale {
        return None;
    }

    if let Some(hit) = engine.cache_get(&dedupe_hash)
        && hit.qtype == u16::from(qtype)
        && hit.pipeline_id.as_ref() == pipeline_id
        && hit.qname.as_ref() == qname_ref
    {
        let elapsed_secs = hit.inserted_at.elapsed().as_secs();

        // Only serve stale when TTL has actually expired
        // 仅当 TTL 已过期时才提供 stale 数据
        if elapsed_secs >= hit.original_ttl as u64 {
            // Don't serve SERVFAIL/REFUSED as stale / 不提供 SERVFAIL/REFUSED 作为 stale
            if hit.rcode == ResponseCode::ServFail || hit.rcode == ResponseCode::Refused {
                return None;
            }

            // Check serve_stale_expire_ttl: max stale age window
            // 检查 serve_stale_expire_ttl：过期数据的最大可用窗口
            let stale_age = elapsed_secs - hit.original_ttl as u64;
            if state.pipeline.settings.serve_stale_expire_ttl > 0
                && stale_age > state.pipeline.settings.serve_stale_expire_ttl
            {
                return None;
            }

            let stale_ttl = state.pipeline.settings.serve_stale_ttl;

            let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
            resp_bytes.extend_from_slice(&hit.bytes);

            // RFC 8767 §4: Set all TTLs to serve_stale_ttl
            crate::proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl);

            // Rewrite Transaction ID
            if resp_bytes.len() >= 2 {
                let id_bytes = tx_id.to_be_bytes();
                resp_bytes[0] = id_bytes[0];
                resp_bytes[1] = id_bytes[1];
            }

            // serve_stale_ttl_reset: reset stale expiry timer
            // 重置过期计时器
            if state.pipeline.settings.serve_stale_ttl_reset {
                let new_entry = hit.clone_with_refreshed_ttl();
                engine.cache_insert(dedupe_hash, std::sync::Arc::new(new_entry));
            }

            debug!(
                event = "serve_stale",
                qname = %qname_ref,
                qtype = ?qtype,
                rcode = ?hit.rcode,
                original_ttl = hit.original_ttl,
                elapsed_secs = elapsed_secs,
                stale_age = stale_age,
                stale_ttl = stale_ttl,
                client_ip = %peer.ip(),
                pipeline = %pipeline_id,
                "RFC 8767: serving stale cache entry on upstream failure"
            );

            // Also trigger background refresh to try to get fresh data
            // 同时触发后台刷新以尝试获取新数据
            if hit.upstream.is_some() {
                engine.spawn_background_refresh(
                    (*state).clone(),
                    dedupe_hash,
                    pipeline_id,
                    qname_ref,
                    qtype,
                    qclass,
                    peer.ip(),
                );
            }

            if let Some((observer, ctx)) = observed {
                observer.cache_hit(
                    ctx,
                    &CacheHit {
                        kind,
                        remaining_ttl: None,
                        original_ttl: Some(Duration::from_secs(hit.original_ttl as u64)),
                    },
                );
            }
            response.cache_hit = true;
            response.upstream = Some(hit.upstream.clone().unwrap_or_else(|| Arc::from("static")));
            return Some(resp_bytes.freeze());
        }
    }
    None
}
/// Request data required to build and cache a static DNS response.
pub struct StaticDecisionContext<'a> {
    pub packet: &'a [u8],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub pipeline_id: &'a Arc<str>,
    pub dedupe_hash: u64,
    pub min_ttl: Duration,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    /// Pipeline uses a client_ip matcher: skip dns_cache to avoid cross-client
    /// reuse (rule_cache already isolates by client IP in that case).
    pub uses_client_ip: bool,
}

/// Handles Decision::Static.
/// Parses request, builds response, updates cache, and returns bytes.
/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub fn handle_static_decision(
    engine: &Engine,
    context: &StaticDecisionContext<'_>,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> anyhow::Result<Bytes> {
    let StaticDecisionContext {
        packet,
        qname,
        qtype,
        pipeline_id: current_pipeline_id,
        dedupe_hash,
        min_ttl,
        start: _,
        peer: _,
        uses_client_ip,
    } = *context;
    // Need full request for building response / 需要完整请求来构建响应
    let req = Message::from_bytes(packet).context("parse request for static")?;
    let resp_bytes = build_response(&req, rcode, answers)?;

    // Skip dns_cache when the pipeline matches on client_ip: dedupe_hash has no
    // client dimension, so a cached static answer could leak across clients.
    // rule_cache already caches static decisions with client-IP isolation.
    if !uses_client_ip && min_ttl > Duration::from_secs(0) {
        let ttl = crate::proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
        engine.insert_dns_cache_entry(
            dedupe_hash,
            CacheEntry::from_response(
                resp_bytes.clone(),
                rcode,
                None, // Static responses have no upstream
                qname,
                current_pipeline_id.clone(),
                u16::from(qtype),
                (ttl, ttl),
            ),
        );
    }

    Ok(resp_bytes)
}

/// Handles Decision::Forward.
/// Manages Singleflight, upstream forwarding, response matching, and caching.
pub struct ForwardDecisionContext<'a> {
    pub state: &'a Arc<EngineInner>,
    pub packet: &'a [u8],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub tx_id: u16,
    pub pipeline_id: &'a str,
    pub rule_name: &'a str,
    pub dedupe_hash: u64,
    pub min_ttl: Duration,
    pub upstream_timeout: Duration,
    pub start: Instant,
    pub peer: &'a std::net::SocketAddr,
    pub skip_cache: bool,
    pub upstream: &'a str,
    pub pre_split_upstreams: Option<&'a Arc<Vec<Arc<str>>>>,
    pub response_matchers: &'a [RuntimeResponseMatcherWithOp],
    pub response_actions_on_match: &'a [Action],
    pub response_actions_on_miss: &'a [Action],
    pub transport: Option<Transport>,
    pub ecs: Option<&'a crate::config::EcsMode>,
    pub allow_reuse: bool,
    pub reused_response: &'a mut Option<ResponseContext>,
    /// Observer context of the request / 所属请求的观察者上下文
    pub observed: Observed<'a>,
}

/// Does not emit the `dns_response` record; only the engine request path logs it.
/// 不输出 `dns_response` 记录；该记录只由引擎请求路径输出。
pub async fn handle_forward_decision(
    engine: &Engine,
    context: ForwardDecisionContext<'_>,
) -> anyhow::Result<ForwardResult> {
    handle_forward_decision_logged(engine, context, &mut ResponseInfo::default()).await
}

pub(crate) async fn handle_forward_decision_logged(
    engine: &Engine,
    context: ForwardDecisionContext<'_>,
    response: &mut ResponseInfo,
) -> anyhow::Result<ForwardResult> {
    let ForwardDecisionContext {
        state,
        packet,
        qname,
        qtype,
        qclass,
        tx_id,
        pipeline_id,
        rule_name,
        dedupe_hash,
        min_ttl,
        upstream_timeout,
        start,
        peer,
        skip_cache,
        upstream,
        pre_split_upstreams,
        response_matchers,
        response_actions_on_match,
        response_actions_on_miss,
        transport,
        ecs,
        allow_reuse,
        reused_response,
        observed,
    } = context;

    response.upstream = Some(Arc::from(upstream));
    // ECS request rewriting (RFC 7871): modify outgoing packet before forwarding.
    // Only runs on cache-miss path — cache hits and static responses are unaffected.
    //
    // ECS 请求改写 (RFC 7871)：在转发前修改出站包。
    // 仅在缓存未命中路径执行 — 缓存命中和静态响应不受影响。
    let ecs_packet: std::borrow::Cow<[u8]> = match ecs {
        Some(mode) => {
            let modified = crate::ecs::apply_ecs(packet, mode, peer.ip());
            tracing::debug!(
                ecs_mode = ?mode,
                modified = modified.len() != packet.len(),
                "ECS request rewriting applied / 已应用 ECS 请求改写"
            );
            std::borrow::Cow::Owned(modified)
        }
        None => std::borrow::Cow::Borrowed(packet),
    };
    let packet = ecs_packet.as_ref();

    let mut cleanup_guard = None;

    let resp = if allow_reuse {
        if let Some(ctx) = reused_response.take() {
            Ok((ctx.raw, ctx.upstream.to_string()))
        } else {
            if !skip_cache {
                use dashmap::mapref::entry::Entry;
                let rx = match engine.inflight.entry(dedupe_hash) {
                    Entry::Vacant(entry) => {
                        let (tx, _rx) =
                            tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                        entry.insert(tx);
                        cleanup_guard = Some(InflightCleanupGuard::new(
                            engine.inflight.clone(),
                            dedupe_hash,
                        ));
                        None
                    }
                    Entry::Occupied(entry) => {
                        let rx = entry.get().subscribe();
                        Some(rx)
                    }
                };

                if let Some(mut rx) = rx
                    && rx.changed().await.is_ok()
                {
                    let result = rx.borrow().clone();
                    match &result {
                        Ok(bytes) => {
                            let mut resp_mut = BytesMut::from(bytes.as_ref());
                            if resp_mut.len() >= 2 {
                                let id_bytes = tx_id.to_be_bytes();
                                resp_mut[0] = id_bytes[0];
                                resp_mut[1] = id_bytes[1];
                            }
                            response.upstream = Some(Arc::from("inflight"));
                            return Ok(ForwardResult::Success(resp_mut.freeze()));
                        }
                        Err(e) => return Err(anyhow::anyhow!("{}", e)),
                    }
                }
            }
            crate::engine::upstream::forward_upstream(
                engine,
                packet,
                upstream,
                upstream_timeout,
                transport,
                pre_split_upstreams,
                observed,
            )
            .await
        }
    } else {
        if !skip_cache {
            use dashmap::mapref::entry::Entry;
            let rx = match engine.inflight.entry(dedupe_hash) {
                Entry::Vacant(entry) => {
                    let (tx, _rx) =
                        tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                    entry.insert(tx);
                    cleanup_guard = Some(InflightCleanupGuard::new(
                        engine.inflight.clone(),
                        dedupe_hash,
                    ));
                    None
                }
                Entry::Occupied(entry) => {
                    let rx = entry.get().subscribe();
                    Some(rx)
                }
            };

            if let Some(mut rx) = rx
                && rx.changed().await.is_ok()
            {
                let result = rx.borrow().clone();
                match &result {
                    Ok(bytes) => {
                        let mut resp_mut = BytesMut::from(bytes.as_ref());
                        if resp_mut.len() >= 2 {
                            let id_bytes = tx_id.to_be_bytes();
                            resp_mut[0] = id_bytes[0];
                            resp_mut[1] = id_bytes[1];
                        }
                        response.upstream = Some(Arc::from("inflight"));
                        return Ok(ForwardResult::Success(resp_mut.freeze()));
                    }
                    Err(e) => return Err(anyhow::anyhow!("{}", e)),
                }
            }
        }
        crate::engine::upstream::forward_upstream(
            engine,
            packet,
            upstream,
            upstream_timeout,
            transport,
            pre_split_upstreams,
            observed,
        )
        .await
    };
    // Now that a refresh runs the response rules, it takes a failure reply as a
    // failed attempt before they see it, as forward_upstream does for a rule with
    // several upstreams: the refresh takes the failure path such a rule takes,
    // miss actions included, and never caches the reply (see
    // reject_failure_reply_on_refresh).
    // 刷新执行响应规则之后，失败应答在响应规则看到之前就被当作一次失败的尝试，和规则有
    // 多个上游时 forward_upstream 的做法一样：刷新走这样的规则会走的失败路径（包括
    // on_miss 动作），也不缓存这个应答（见 reject_failure_reply_on_refresh）。
    let resp = resp
        .and_then(|reply| reject_failure_reply_on_refresh(skip_cache, &reply.0).map(|()| reply));

    match resp {
        Ok((raw, actual_upstream)) => {
            response.upstream = Some(Arc::from(actual_upstream.as_str()));
            let (rcode, ttl_secs_cache, ttl_secs_refresh, msg_opt, truncated) = if response_matchers
                .is_empty()
                && response_actions_on_match.is_empty()
                && response_actions_on_miss.is_empty()
            {
                if let Some(qr) = proto_utils::parse_response_quick(&raw) {
                    (
                        qr.rcode,
                        qr.min_ttl as u64,
                        qr.max_ttl as u64,
                        None,
                        qr.truncated,
                    )
                } else {
                    let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                    let ttl_cache = extract_ttl(&msg);
                    let ttl_refresh = extract_ttl_for_refresh(&msg);
                    let tc = raw.len() >= 3 && (raw[2] & 0x02) != 0;
                    (
                        msg.metadata.response_code,
                        ttl_cache,
                        ttl_refresh,
                        Some(msg),
                        tc,
                    )
                }
            } else {
                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                let ttl_cache = extract_ttl(&msg);
                let ttl_refresh = extract_ttl_for_refresh(&msg);
                let tc = raw.len() >= 3 && (raw[2] & 0x02) != 0;
                (
                    msg.metadata.response_code,
                    ttl_cache,
                    ttl_refresh,
                    Some(msg),
                    tc,
                )
            };

            // 检查 TCP fallback 配置 / Check TCP fallback configuration
            let enable_tcp_fallback = state.pipeline.settings.enable_tcp_fallback;
            if truncated && transport == Some(Transport::Udp) && enable_tcp_fallback {
                tracing::debug!(event = "tc_flag_retry", upstream = %upstream, "response truncated, retrying with tcp");
                let (tcp_resp, tcp_upstream) = crate::engine::upstream::forward_upstream(
                    engine,
                    packet,
                    upstream,
                    upstream_timeout,
                    Some(Transport::Tcp),
                    pre_split_upstreams,
                    observed,
                )
                .await?;
                if let Some(guard) = cleanup_guard.as_mut() {
                    guard.defuse();
                    engine.notify_inflight_waiters(dedupe_hash, &tcp_resp).await;
                }
                response.upstream = Some(Arc::from(tcp_upstream));
                return Ok(ForwardResult::Success(tcp_resp));
            }

            let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));

            // Try to acquire read locks non-blockingly (fast path for concurrent reads)
            // 尝试非阻塞获取读锁（并发读的快速路径）
            let (resp_match_ok, msg) = {
                let mut geoip_manager = engine.geoip_manager.try_read();
                let mut geosite_manager = engine.geosite_manager.try_read();

                // Fallback to blocking read if try_read fails (rare write operation in progress)
                // 如果 try_read 失败则回退到阻塞读取（罕见的写操作进行中）
                if geoip_manager.is_none() || geosite_manager.is_none() {
                    tracing::debug!("GeoIP/GeoSite lock contention, falling back to blocking read");
                    geoip_manager = Some(engine.geoip_manager.read());
                    geosite_manager = Some(engine.geosite_manager.read());
                }

                let geoip_manager_ref = geoip_manager.as_deref();
                let geosite_manager_ref = geosite_manager.as_deref();

                if let Some(m) = msg_opt {
                    let matched = eval_match_chain(
                        response_matchers,
                        |m| m.operator,
                        |matcher_op| {
                            matcher_op.matcher.matches(
                                upstream,
                                qname,
                                qtype,
                                qclass,
                                &m,
                                geoip_manager_ref,
                                geosite_manager_ref,
                            )
                        },
                    );
                    (matched, m)
                } else {
                    (
                        false,
                        Message::new(
                            0,
                            hickory_proto::op::MessageType::Query,
                            hickory_proto::op::OpCode::Query,
                        ),
                    )
                }
            };

            if !skip_cache
                && !response_matchers.is_empty()
                && let Some((observer, ctx)) = observed
            {
                observer.rule_evaluated(
                    ctx,
                    &RuleEvaluated {
                        pipeline: pipeline_id,
                        rule: rule_name,
                        phase: RulePhase::Response,
                        matched: resp_match_ok,
                        matchers: response_matchers.len(),
                    },
                );
                if resp_match_ok {
                    observer.rule_matched(
                        ctx,
                        &RuleMatched {
                            pipeline: pipeline_id,
                            rule: rule_name,
                            phase: RulePhase::Response,
                            decision: response_decision_kind(response_actions_on_match),
                            fast_path: false,
                        },
                    );
                }
            }

            // A background refresh applies the response rules as a client request
            // does (a failure reply never gets here, see above): an answer a rule
            // continues past, or replaces, must not be what the refresh caches.
            // 后台刷新和客户端请求一样执行响应规则（失败应答到不了这里，见上）：规则
            // 越过或替换掉的应答，不能成为刷新写进缓存的结果。
            let empty_actions = Vec::new();
            let actions_to_run =
                if !response_actions_on_match.is_empty() || !response_actions_on_miss.is_empty() {
                    if resp_match_ok {
                        response_actions_on_match
                    } else {
                        response_actions_on_miss
                    }
                } else {
                    &empty_actions
                };

            if actions_to_run.is_empty() {
                if effective_ttl > Duration::from_secs(0) {
                    let cache_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_cache);
                    let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                    engine.insert_dns_cache_entry(
                        dedupe_hash,
                        CacheEntry::from_response(
                            raw.clone(),
                            rcode,
                            Some(Arc::from(actual_upstream.as_str())),
                            qname,
                            Arc::from(pipeline_id),
                            u16::from(qtype),
                            (cache_ttl, refresh_ttl),
                        ),
                    );
                }
                if let Some(g) = cleanup_guard.as_mut() {
                    g.defuse();
                }
                engine.notify_inflight_waiters(dedupe_hash, &raw).await;

                return Ok(ForwardResult::Success(raw));
            }

            // Handle Actions
            let req_full = if let Ok(r) = Message::from_bytes(packet) {
                r
            } else {
                Message::new(
                    0,
                    hickory_proto::op::MessageType::Query,
                    hickory_proto::op::OpCode::Query,
                )
            };
            let ctx = ResponseContext {
                raw: raw.clone(),
                msg,
                upstream: Arc::from(actual_upstream.as_str()),
                transport: transport.unwrap_or(Transport::Udp),
            };

            let default_upstream = state.pipeline.settings.default_upstream.as_str();
            let response_jump_limit = state.pipeline.settings.response_jump_limit as usize;

            let ctx = rules::ApplyResponseActionsContext {
                engine,
                actions: actions_to_run,
                ctx_opt: Some(ctx),
                req: &req_full,
                packet,
                upstream_timeout,
                response_matchers,
                qname,
                qtype,
                qclass,
                client_ip: peer.ip(),
                upstream_default: default_upstream,
                pipeline_id,
                rule_name,
                remaining_jumps: response_jump_limit,
            };

            let action_result = rules::apply_response_actions_observed(ctx, observed).await?;

            match action_result {
                ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                    // The reply to a response action's forward (see
                    // reject_failure_reply_on_refresh)
                    // 响应动作转发拿到的应答（见 reject_failure_reply_on_refresh）
                    reject_failure_reply_on_refresh(skip_cache, &ctx.raw)?;
                    let ttl_secs_cache = extract_ttl(&ctx.msg);
                    let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                    let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));
                    if effective_ttl > Duration::from_secs(0) {
                        let cache_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_cache);
                        let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                        engine.insert_dns_cache_entry(
                            dedupe_hash,
                            CacheEntry::from_response(
                                ctx.raw.clone(),
                                ctx.msg.metadata.response_code,
                                Some(ctx.upstream.clone()),
                                qname,
                                Arc::from(pipeline_id),
                                u16::from(qtype),
                                (cache_ttl, refresh_ttl),
                            ),
                        );
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                    response.upstream = Some(ctx.upstream);
                    Ok(ForwardResult::Success(ctx.raw))
                }
                ResponseActionResult::Static { bytes, rcode, .. } => {
                    // A SERVFAIL here mostly means the response actions found no
                    // answer either (a response-phase forward failed or ran past its
                    // limit, or the jump limit was reached); a static SERVFAIL the
                    // rules configure is taken the same way. A refresh ends as a
                    // failure rather than cache SERVFAIL over the entry it was
                    // refreshing.
                    // 这里的 SERVFAIL 多半说明响应动作也没拿到应答（响应阶段的转发失败或
                    // 超过次数上限，或到了跳转上限）；规则里配置的静态 SERVFAIL 也按这个
                    // 处理。刷新以失败结束，而不是把 SERVFAIL 写进缓存、盖掉它要刷新的那条。
                    if skip_cache && rcode == ResponseCode::ServFail {
                        return Err(refresh_found_no_answer(
                            "the response actions found no answer",
                        ));
                    }
                    if min_ttl > Duration::from_secs(0) {
                        let ttl = proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
                        engine.insert_dns_cache_entry(
                            dedupe_hash,
                            CacheEntry::from_response(
                                bytes.clone(),
                                rcode,
                                None,
                                qname,
                                Arc::from(pipeline_id),
                                u16::from(qtype),
                                (ttl, ttl),
                            ),
                        );
                    } else if skip_cache {
                        // An answer that is not cached cannot renew the entry, so the
                        // refresh drops it and the next client request runs the rules.
                        // 不缓存的应答无法更新这条缓存，所以刷新把它删掉，下一个客户端
                        // 请求自己执行规则。
                        engine.cache_invalidate(&dedupe_hash);
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine.notify_inflight_waiters(dedupe_hash, &bytes).await;
                    response.upstream = Some(Arc::from("static"));
                    Ok(ForwardResult::Success(bytes))
                }
                ResponseActionResult::Jump {
                    pipeline,
                    remaining_jumps,
                } => {
                    let edns_present = proto_utils::parse_quick(packet, &mut [0u8; 256])
                        .map(|p| p.edns_present)
                        .unwrap_or(false);

                    let resp_bytes = rules::process_response_jump(
                        engine,
                        rules::ResponseJumpContext {
                            state,
                            pipeline_id: pipeline,
                            remaining_jumps,
                            req: &req_full,
                            packet,
                            peer: *peer,
                            qname,
                            qtype,
                            qclass,
                            edns_present,
                            min_ttl,
                            upstream_timeout,
                            skip_cache,
                            observed,
                        },
                        response,
                    )
                    .await?;

                    // The target pipeline's answer is not stored under this key (it
                    // caches under its own, if at all), so on a refresh the entry here
                    // no longer matches the rules and is dropped (see the Static arm).
                    // If the target found no answer, the refresh ends as a failure and
                    // the entry stays.
                    // 目标 pipeline 的应答不会存进这个键（要存也存在它自己的键下），所以刷新
                    // 时这里的条目已经和规则对不上，删掉（同 Static 分支）。目标没拿到应答
                    // 时，刷新以失败结束，条目保留。
                    if skip_cache {
                        if is_servfail(&resp_bytes) {
                            return Err(refresh_found_no_answer("the jump target found no answer"));
                        }
                        engine.cache_invalidate(&dedupe_hash);
                    }
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine
                        .notify_inflight_waiters(dedupe_hash, &resp_bytes)
                        .await;
                    Ok(ForwardResult::Success(resp_bytes))
                }
                ResponseActionResult::Continue { ctx } => {
                    // Defusing here would leave the inflight entry (dedupe_hash)
                    // in the map without ever notifying it: concurrent same-hash
                    // requests wait on rx.changed() forever, and — worse — the
                    // re-evaluated next rule (execution.rs re-applies rules and
                    // forwards again with the same dedupe_hash) finds the entry
                    // Occupied and hangs until the outer timeout, which surfaces
                    // as a client TIMEOUT instead of a fallback answer.
                    // 此处 defuse 会让 inflight 条目（dedupe_hash）留在 map 中且
                    // 永远不通知：并发同 hash 请求会永久等待 rx.changed()，更糟的
                    // 是——continue 后重新评估的下一条规则（execution.rs 重新
                    // apply_rules 并以相同 dedupe_hash 再次转发）会看到 Occupied
                    // 条目并挂起直到外层超时，表现为客户端 TIMEOUT 而非 fallback。
                    //
                    // So: notify waiters with the response received so far, and
                    // let the cleanup guard (kept active) remove the entry on
                    // return, so the next Forward attempt starts fresh.
                    // 因此：先以已收到的响应通知等待者，并让清理守卫（保持 active）
                    // 在返回时移除条目，使下一次 Forward 尝试从全新条目开始。
                    if let Some(ctx_ref) = ctx.as_ref() {
                        engine
                            .notify_inflight_waiters(dedupe_hash, &ctx_ref.raw)
                            .await;
                    }
                    Ok(ForwardResult::Continue(Box::new(ctx)))
                }
            }
        }
        Err(e) => {
            if response_actions_on_miss.is_empty() {
                // Only send SERVFAIL when upstream attempts are fully exhausted.
                // 仅在所有上游尝试都耗尽时发送 SERVFAIL。
                if e.downcast_ref::<UpstreamFailure>().is_none() {
                    return Err(e);
                }

                // RFC 8767: Try to serve stale cache entry before returning SERVFAIL
                // RFC 8767: 在返回 SERVFAIL 之前尝试提供过期缓存
                if let Some(stale_bytes) = check_stale_cache_logged(
                    engine,
                    &CacheLookupContext {
                        state,
                        qname,
                        qtype,
                        qclass,
                        pipeline_id,
                        dedupe_hash,
                        tx_id,
                        start,
                        peer,
                        // A background refresh never looked the cache up, so it
                        // must not report a hit either / 后台刷新没有查过缓存，也不能上报命中
                        observed: if skip_cache { None } else { observed },
                    },
                    CacheHitKind::StaleUpstreamFailure,
                    response,
                ) {
                    warn!(
                        event = "serve_stale_on_upstream_failure",
                        upstream = %upstream,
                        qname = %qname,
                        qtype = ?qtype,
                        client_ip = %peer.ip(),
                        pipeline = %pipeline_id,
                        error = %e,
                        "RFC 8767: upstream failed, serving stale cache"
                    );
                    if let Some(g) = cleanup_guard.as_mut() {
                        g.defuse();
                    }
                    engine
                        .notify_inflight_waiters(dedupe_hash, &stale_bytes)
                        .await;
                    return Ok(ForwardResult::Success(stale_bytes));
                }

                let rcode = ResponseCode::ServFail;
                warn!(
                   event = "upstream_failure",
                   upstream = %upstream,
                   qname = %qname,
                   qtype = ?qtype,
                   rcode = ?rcode,
                   client_ip = %peer.ip(),
                   error = %e,
                   pipeline = %pipeline_id,
                   transport = ?transport,
                   "upstream failed"
                );
                // Fast build SERVFAIL without full request parse
                let rd = packet.get(2).map(|b| b & 0x01 != 0).unwrap_or(false);
                let resp_bytes = match build_servfail_response_fast(
                    tx_id,
                    qname,
                    u16::from(qtype),
                    u16::from(qclass),
                    rd,
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        // Fallback to full parse if fast build fails
                        let req = match Message::from_bytes(packet) {
                            Ok(r) => r,
                            Err(_) => return Err(e),
                        };
                        build_response(&req, rcode, Vec::new()).unwrap_or_default()
                    }
                };

                if let Some(g) = cleanup_guard.as_mut() {
                    g.defuse();
                }
                engine
                    .notify_inflight_waiters(dedupe_hash, &resp_bytes)
                    .await;

                Ok(ForwardResult::Success(resp_bytes))
            } else {
                let req = match Message::from_bytes(packet) {
                    Ok(r) => r,
                    Err(_) => return Err(e),
                };
                let default_upstream = state.pipeline.settings.default_upstream.as_str();
                let response_jump_limit = state.pipeline.settings.response_jump_limit as usize;

                let ctx = rules::ApplyResponseActionsContext {
                    engine,
                    actions: response_actions_on_miss,
                    ctx_opt: None,
                    req: &req,
                    packet,
                    upstream_timeout,
                    response_matchers,
                    qname,
                    qtype,
                    qclass,
                    client_ip: peer.ip(),
                    upstream_default: default_upstream,
                    pipeline_id,
                    rule_name,
                    remaining_jumps: response_jump_limit,
                };
                let action_result = rules::apply_response_actions_observed(ctx, observed).await?;

                match action_result {
                    ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                        // The reply to a miss action's forward / on_miss 动作转发拿到的应答
                        reject_failure_reply_on_refresh(skip_cache, &ctx.raw)?;
                        let ttl_secs_cache = extract_ttl(&ctx.msg);
                        let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                        let effective_ttl =
                            Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));
                        if effective_ttl > Duration::from_secs(0) {
                            let cache_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_cache);
                            let refresh_ttl = proto_utils::saturating_u64_to_u32(ttl_secs_refresh);
                            engine.insert_dns_cache_entry(
                                dedupe_hash,
                                CacheEntry::from_response(
                                    ctx.raw.clone(),
                                    ctx.msg.metadata.response_code,
                                    Some(ctx.upstream.clone()),
                                    qname,
                                    Arc::from(pipeline_id),
                                    u16::from(qtype),
                                    (cache_ttl, refresh_ttl),
                                ),
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        engine.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                        response.upstream = Some(ctx.upstream);
                        Ok(ForwardResult::Success(ctx.raw))
                    }
                    ResponseActionResult::Static { bytes, rcode, .. } => {
                        if min_ttl > Duration::from_secs(0) {
                            let ttl = proto_utils::saturating_u64_to_u32(min_ttl.as_secs());
                            engine.insert_dns_cache_entry(
                                dedupe_hash,
                                CacheEntry::from_response(
                                    bytes.clone(),
                                    rcode,
                                    None,
                                    qname,
                                    Arc::from(pipeline_id),
                                    u16::from(qtype),
                                    (ttl, ttl),
                                ),
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        engine.notify_inflight_waiters(dedupe_hash, &bytes).await;
                        response.upstream = Some(Arc::from("static"));
                        Ok(ForwardResult::Success(bytes))
                    }
                    ResponseActionResult::Jump {
                        pipeline,
                        remaining_jumps,
                    } => {
                        let edns_present = proto_utils::parse_quick(packet, &mut [0u8; 256])
                            .map(|p| p.edns_present)
                            .unwrap_or(false);
                        let req = if let Ok(r) = Message::from_bytes(packet) {
                            r
                        } else {
                            Message::new(
                                0,
                                hickory_proto::op::MessageType::Query,
                                hickory_proto::op::OpCode::Query,
                            )
                        };

                        let resp_bytes = rules::process_response_jump(
                            engine,
                            rules::ResponseJumpContext {
                                state,
                                pipeline_id: pipeline,
                                remaining_jumps,
                                req: &req,
                                packet,
                                peer: *peer,
                                qname,
                                qtype,
                                qclass,
                                edns_present,
                                min_ttl,
                                upstream_timeout,
                                skip_cache,
                                observed,
                            },
                            response,
                        )
                        .await?;

                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        engine
                            .notify_inflight_waiters(dedupe_hash, &resp_bytes)
                            .await;
                        Ok(ForwardResult::Success(resp_bytes))
                    }
                    ResponseActionResult::Continue { ctx } => {
                        // Defuse cleanup guard: we're returning Continue which re-enters
                        // the decision loop. The inflight entry must survive for waiters.
                        // If we don't defuse, Drop will remove the inflight entry without
                        // notifying waiters, causing them to hang forever on rx.changed().
                        if let Some(g) = cleanup_guard.as_mut() {
                            g.defuse();
                        }
                        Ok(ForwardResult::Continue(Box::new(ctx)))
                    }
                }
            }
        }
    }
}

/// The error a background refresh ends with when its rules found no answer: the
/// refresh counts as failed and the cached entry stays.
/// 后台刷新的规则没找到应答时以这个错误结束：算作刷新失败，缓存条目保留。
pub(crate) fn refresh_found_no_answer(reason: &'static str) -> anyhow::Error {
    anyhow::Error::new(UpstreamFailure::new(anyhow::anyhow!(reason)))
}

/// Whether a response carries SERVFAIL / 响应是否为 SERVFAIL
pub(crate) fn is_servfail(bytes: &[u8]) -> bool {
    proto_utils::parse_response_quick(bytes).is_some_and(|qr| qr.rcode == ResponseCode::ServFail)
}

#[cfg(test)]
mod refresh_response_rule_tests {
    use crate::cache::CacheEntry;
    use crate::engine::core::Engine;
    use crate::matcher::RuntimePipelineConfig;
    use bytes::Bytes;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use serde_json::{Value, json};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    const CLIENT: &str = "127.0.0.1:53000";
    /// Nothing listens here, so a fall-through to the default upstream fails.
    /// 这里没有监听，落到默认上游的请求会失败。
    const DEAD_UPSTREAM: &str = "127.0.0.1:9";
    /// What the entry being refreshed holds / 要刷新的那条缓存里的应答
    const OLD: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
    /// What the first rule's upstream answers / 第一条规则的上游回的应答
    const PASSED_OVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    /// What the second rule's upstream answers / 第二条规则的上游回的应答
    const FINAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
    const STATIC: &str = "192.0.2.5";

    /// Local UDP upstream that answers every query with one A record.
    /// 本机 UDP 上游：每个查询都回一条 A 记录。
    async fn spawn_upstream_answering(ip: Ipv4Addr) -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let Some(question) = query.queries.first().cloned() else {
                    continue;
                };
                let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
                resp.add_query(question.clone());
                resp.add_answer(a_record(&question, ip));
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    /// Local UDP upstream that answers every query SERVFAIL.
    /// 本机 UDP 上游：每个查询都回 SERVFAIL。
    async fn spawn_upstream_answering_servfail() -> String {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Ok(query) = Message::from_bytes(&buf[..n]) else {
                    continue;
                };
                let mut resp = Message::new(query.id, MessageType::Response, OpCode::Query);
                resp.metadata.response_code = ResponseCode::ServFail;
                if let Some(question) = query.queries.first() {
                    resp.add_query(question.clone());
                }
                let _ = sock.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }

    fn a_record(question: &Query, ip: Ipv4Addr) -> Record {
        Record::from_rdata(
            question.name().clone(),
            300,
            RData::A(hickory_proto::rr::rdata::A(ip)),
        )
    }

    fn query() -> Message {
        let mut request = Message::new(0x5157, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        request
    }

    fn a_records(bytes: &[u8]) -> Vec<Ipv4Addr> {
        Message::from_bytes(bytes)
            .expect("parse reply")
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => Some(a.0),
                _ => None,
            })
            .collect()
    }

    /// A rule that matches every query / 匹配所有查询的规则
    fn rule(name: &str, actions: Value, response_rules: Value) -> Value {
        let mut rule = json!({ "name": name, "matchers": [{ "type": "any" }], "actions": actions });
        for (key, value) in response_rules.as_object().unwrap() {
            rule[key] = value.clone();
        }
        rule
    }

    fn forward(upstream: &str) -> Value {
        json!([{ "type": "forward", "upstream": upstream }])
    }

    fn answer_static() -> Value {
        json!([{ "type": "static_ip_response", "ip": STATIC }])
    }

    fn jump_to(pipeline: &str) -> Value {
        json!([{ "type": "jump_to_pipeline", "pipeline": pipeline }])
    }

    fn continue_() -> Value {
        json!([{ "type": "continue" }])
    }

    /// A jump target answering statically / 静态应答的跳转目标
    fn static_target() -> Value {
        rule("target", answer_static(), json!({}))
    }

    /// A jump target whose upstream never answers / 上游不应答的跳转目标
    fn failing_target() -> Value {
        rule("target", forward(DEAD_UPSTREAM), json!({}))
    }

    /// An engine whose pipeline "main" holds a cached answer with [`OLD`], as a
    /// client request left it; returns the key a refresh of it uses.
    /// 引擎的 "main" pipeline 里缓存着一条 [`OLD`] 应答，就像客户端请求留下的那样；
    /// 返回刷新它时用的键。
    fn engine_with_a_cached_answer(settings: Value, pipelines: Value) -> (Engine, u64) {
        let mut all_settings =
            json!({ "default_upstream": DEAD_UPSTREAM, "upstream_timeout_ms": 200 });
        for (key, value) in settings.as_object().unwrap() {
            all_settings[key] = value.clone();
        }
        let config: crate::config::PipelineConfig =
            serde_json::from_value(json!({ "settings": all_settings, "pipelines": pipelines }))
                .expect("parse config");
        let engine = Engine::new(
            RuntimePipelineConfig::from_config(config).expect("build runtime config"),
            "test".to_string(),
        )
        .expect("engine");

        let key = cache_an_answer(&engine, "main", OLD, 300);
        (engine, key)
    }

    /// Caches an answer with `ip` for `pipeline` with the given TTL (0: already
    /// stale) and returns its key.
    /// 为 `pipeline` 缓存一条带 `ip` 的应答，TTL 为给定值（0 表示已经过期），返回它的键。
    fn cache_an_answer(engine: &Engine, pipeline: &str, ip: Ipv4Addr, ttl: u32) -> u64 {
        let state = engine.state.load_full();
        let key = Engine::calculate_cache_hash_for_dedupe(
            state.cache_namespace(pipeline),
            pipeline,
            b"example.com",
            RecordType::A,
            DNSClass::IN,
            None,
        );
        let request = query();
        let mut reply = Message::new(request.id, MessageType::Response, OpCode::Query);
        reply.add_query(request.queries[0].clone());
        reply.add_answer(a_record(&request.queries[0], ip));
        engine.insert_dns_cache_entry(
            key,
            CacheEntry::from_response(
                Bytes::from(reply.to_vec().unwrap()),
                ResponseCode::NoError,
                Some(Arc::from(DEAD_UPSTREAM)),
                "example.com",
                Arc::from(pipeline),
                u16::from(RecordType::A),
                (ttl, ttl),
            ),
        );
        key
    }

    /// Runs the call `spawn_background_refresh` makes and returns what the
    /// refreshed key holds afterwards: its A records, or None once dropped.
    /// 执行与 `spawn_background_refresh` 相同的调用，返回之后那个键里的 A 记录，
    /// 被删掉时返回 None。
    async fn refresh(engine: &Engine, key: u64) -> Option<Vec<Ipv4Addr>> {
        let client: SocketAddr = CLIENT.parse().unwrap();
        let state = engine.state.load_full();
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            engine.handle_packet_internal(
                &query().to_vec().unwrap(),
                client,
                true,
                None,
                Some(key),
                Some(state),
            ),
        )
        .await
        .expect("refresh finishes");
        engine.cache.get(&key).map(|entry| a_records(&entry.bytes))
    }

    /// Rule `first` asks the upstream answering [`PASSED_OVER`] with the given
    /// response rules; rule `second` asks the upstream answering [`FINAL`].
    /// 规则 `first` 带着给定的响应规则问回 [`PASSED_OVER`] 的上游；规则 `second`
    /// 问回 [`FINAL`] 的上游。
    async fn refresh_past_the_first_answer(
        response_rules: impl FnOnce(&str, &str) -> Value,
    ) -> Option<Vec<Ipv4Addr>> {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let second = spawn_upstream_answering(FINAL).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule("first", forward(&first), response_rules(&first, &second)),
                rule("second", forward(&second), json!({})),
            ]}]),
        );
        refresh(&engine, key).await
    }

    /// Rule `first` asks the upstream answering [`PASSED_OVER`] and runs the
    /// given actions on its answer; `later_rules` follow it, and pipeline
    /// "other", the jump target, has the single rule `target`.
    /// 规则 `first` 问回 [`PASSED_OVER`] 的上游，并对它的应答执行给定的动作；
    /// `later_rules` 跟在它后面，跳转目标 pipeline "other" 只有一条规则 `target`。
    async fn refresh_with_actions_on_the_answer(
        settings: Value,
        actions_on_match: Value,
        later_rules: Vec<Value>,
        target: Value,
    ) -> Option<Vec<Ipv4Addr>> {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let mut rules = vec![rule(
            "first",
            forward(&first),
            json!({ "response_actions_on_match": actions_on_match }),
        )];
        rules.extend(later_rules);
        let (engine, key) = engine_with_a_cached_answer(
            settings,
            json!([
                { "id": "main", "rules": rules },
                { "id": "other", "rules": [target] }
            ]),
        );
        refresh(&engine, key).await
    }

    #[tokio::test]
    async fn a_refresh_continues_past_an_answer_on_match() {
        let cached = refresh_past_the_first_answer(|first, _| {
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": first }],
                "response_actions_on_match": continue_()
            })
        })
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_continues_past_an_answer_on_miss() {
        let cached = refresh_past_the_first_answer(|_, second| {
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": second }],
                "response_actions_on_miss": continue_()
            })
        })
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_for_an_uncached_static_answer() {
        let cached =
            refresh_with_actions_on_the_answer(json!({}), answer_static(), vec![], static_target())
                .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_caches_a_static_answer_under_min_ttl() {
        let settings = json!({ "min_ttl": 60 });
        let cached =
            refresh_with_actions_on_the_answer(settings, answer_static(), vec![], static_target())
                .await;
        assert_eq!(cached, Some(vec![STATIC.parse().unwrap()]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_the_answer_jumps() {
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            jump_to("other"),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_jump_target_fails() {
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            jump_to("other"),
            vec![],
            failing_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_response_actions_find_no_answer_keeps_the_entry() {
        // With no jumps left the jump action answers SERVFAIL / 跳转次数用完时跳转动作回 SERVFAIL
        let settings = json!({ "min_ttl": 60, "response_jump_limit": 0 });
        let cached =
            refresh_with_actions_on_the_answer(settings, jump_to("other"), vec![], static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_an_action_forward_answers_servfail() {
        let failing = spawn_upstream_answering_servfail().await;
        let settings = json!({ "min_ttl": 60 });
        let cached = refresh_with_actions_on_the_answer(
            settings,
            forward(&failing),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_runs_the_miss_actions_on_a_failure_reply() {
        let failing = spawn_upstream_answering_servfail().await;
        let backup = spawn_upstream_answering(FINAL).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&failing),
                json!({ "response_actions_on_miss": forward(&backup) })
            )]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_on_a_failure_reply_with_response_rules() {
        let failing = spawn_upstream_answering_servfail().await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&failing),
                json!({
                    "response_matchers": [{ "type": "upstream_equals", "value": DEAD_UPSTREAM }],
                    "response_actions_on_miss": answer_static()
                })
            )]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_reaches_a_static_answer() {
        let later = vec![rule("static", answer_static(), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_caches_a_static_answer_a_continue_reaches_under_min_ttl() {
        let later = vec![rule("static", answer_static(), json!({}))];
        let settings = json!({ "min_ttl": 60 });
        let cached =
            refresh_with_actions_on_the_answer(settings, continue_(), later, static_target()).await;
        assert_eq!(cached, Some(vec![STATIC.parse().unwrap()]));
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_reaches_a_jump() {
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_drops_the_entry_when_a_continue_jumps_to_an_answering_target() {
        let answering = spawn_upstream_answering(FINAL).await;
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let target = rule("target", forward(&answering), json!({}));
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, target).await;
        assert_eq!(cached, None);
    }

    #[tokio::test]
    async fn a_refresh_caches_the_answer_of_a_response_action_forward() {
        let replacement = spawn_upstream_answering(FINAL).await;
        let cached = refresh_with_actions_on_the_answer(
            json!({}),
            forward(&replacement),
            vec![],
            static_target(),
        )
        .await;
        assert_eq!(cached, Some(vec![FINAL]));
    }

    #[tokio::test]
    async fn a_refresh_caches_a_deny_under_min_ttl() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({ "min_ttl": 60 }),
            json!([{ "id": "main", "rules": [rule(
                "first",
                forward(&first),
                json!({ "response_actions_on_match": [{ "type": "deny" }] })
            )]}]),
        );
        refresh(&engine, key).await;
        let cached = engine.cache.get(&key).expect("the refresh caches the deny");
        assert_eq!(cached.rcode, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_the_jump_target_gets_a_failure_reply() {
        let failing = spawn_upstream_answering_servfail().await;
        let target = rule(
            "target",
            forward(&failing),
            json!({
                "response_matchers": [{ "type": "upstream_equals", "value": DEAD_UPSTREAM }],
                "response_actions_on_miss": answer_static()
            }),
        );
        let cached =
            refresh_with_actions_on_the_answer(json!({}), jump_to("other"), vec![], target).await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_target_serving_stale() {
        let first = spawn_upstream_answering(PASSED_OVER).await;
        let (engine, key) = engine_with_a_cached_answer(
            json!({ "serve_stale": true }),
            json!([
                { "id": "main", "rules": [
                    rule("first", forward(&first), json!({ "response_actions_on_match": continue_() })),
                    rule("jump", jump_to("other"), json!({})),
                ]},
                { "id": "other", "rules": [failing_target()] }
            ]),
        );
        cache_an_answer(&engine, "other", FINAL, 0);
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_jumps_to_a_failing_target() {
        let later = vec![rule("jump", jump_to("other"), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, failing_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_keeps_the_entry_when_a_continue_ends_in_servfail() {
        // A jump to a pipeline that does not exist answers SERVFAIL / 跳到不存在的 pipeline 回 SERVFAIL
        let later = vec![rule("jump", jump_to("nowhere"), json!({}))];
        let settings = json!({ "min_ttl": 60 });
        let cached =
            refresh_with_actions_on_the_answer(settings, continue_(), later, static_target()).await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_whose_next_rule_fails_keeps_the_entry() {
        let later = vec![rule("dead", forward(DEAD_UPSTREAM), json!({}))];
        let cached =
            refresh_with_actions_on_the_answer(json!({}), continue_(), later, static_target())
                .await;
        assert_eq!(cached, Some(vec![OLD]));
    }

    #[tokio::test]
    async fn a_refresh_that_continues_after_a_failure_keeps_the_entry() {
        let (engine, key) = engine_with_a_cached_answer(
            json!({}),
            json!([{ "id": "main", "rules": [
                rule(
                    "first",
                    forward(DEAD_UPSTREAM),
                    json!({ "response_actions_on_miss": continue_() })
                ),
                rule("static", answer_static(), json!({})),
            ]}]),
        );
        assert_eq!(refresh(&engine, key).await, Some(vec![OLD]));
    }
}
