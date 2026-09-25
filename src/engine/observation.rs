//! Crate-internal helpers for reporting [`crate::observe`] events from the
//! engine. Everything here is only reached after the engine has confirmed an
//! observer is installed, so it may allocate event structs freely.
//! 引擎内部上报观察者事件的辅助函数。仅在确认安装了观察者后才会执行。

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;

use crate::config::{Action, Transport};
use crate::engine::rules::Decision;
use crate::engine::upstream::has_transport_prefix;
use crate::observe::{
    DecisionDetail, DecisionKind, DecisionMade, EngineObserver, RequestContext, RequestOutcome,
    RequestStatus, RuleMatched, RulePhase,
};

/// Observer and request context of the request being processed. The engine
/// checks its `observer` field once per request and threads this pair to
/// every reporting site, so those sites only test a local `Option`.
/// 正在处理的请求的观察者与上下文。引擎每个请求只检查一次 observer 字段，
/// 随后把这对引用传给各上报点，各处只需检查本地 Option。
pub(crate) type Observed<'a> = Option<(&'a dyn EngineObserver, &'a RequestContext<'a>)>;

/// Observer handle for one request. Reports `request_finished` when dropped,
/// so a request whose future is dropped early (listener timeout) is reported
/// as cancelled instead of vanishing.
/// 单个请求的观察者句柄。drop 时上报 request_finished，被提前丢弃的请求上报为取消。
pub(crate) struct ObservedRequest<'a> {
    pub observer: &'a dyn EngineObserver,
    pub ctx: RequestContext<'a>,
    start: Instant,
    status: RequestStatus,
    /// The response lent to `request_finished`; a cheap reference-counted
    /// clone of the bytes the engine returns.
    /// 交给 request_finished 的应答；是引擎返回字节的引用计数克隆，不复制内容。
    response: Option<Bytes>,
    /// The failure reason, formatted once and only when the request failed.
    /// 失败原因；只在请求失败时格式化一次。
    error: Option<String>,
}

impl<'a> ObservedRequest<'a> {
    pub fn new(observer: &'a dyn EngineObserver, ctx: RequestContext<'a>, start: Instant) -> Self {
        Self {
            observer,
            ctx,
            start,
            status: RequestStatus::Cancelled,
            response: None,
            error: None,
        }
    }

    /// Record how the request ended: the response it produced, or why it failed.
    /// 记录请求的结局：产出的应答，或失败的原因。
    pub fn finish(&mut self, result: &anyhow::Result<Bytes>) {
        match result {
            Ok(response) => {
                self.status = RequestStatus::Completed;
                self.response = Some(response.clone());
            }
            Err(error) => {
                self.status = RequestStatus::Failed;
                self.error = Some(format!("{error:#}"));
            }
        }
    }
}

impl Drop for ObservedRequest<'_> {
    fn drop(&mut self) {
        self.observer.request_finished(
            &self.ctx,
            &RequestOutcome {
                latency: self.start.elapsed(),
                status: self.status,
                response: self.response.as_deref(),
                error: self.error.as_deref(),
            },
        );
    }
}

/// Address of the upstream a cache entry was filled from, in the form
/// [`crate::observe::UpstreamResult::upstream`] uses. The entry records the
/// label `forward_upstream` builds, `{transport}:{address}`, whose transport
/// part never contains a colon; rule-synthesised entries record none.
/// 缓存条目来源上游的地址，写法与 UpstreamResult::upstream 一致。条目记录的是
/// forward_upstream 拼出的 `{传输}:{地址}`，传输部分不含冒号；规则生成的条目没有来源。
pub(crate) fn cached_source(upstream: Option<&str>) -> Option<&str> {
    upstream.map(|label| label.split_once(':').map_or(label, |(_, address)| address))
}

/// Kind of a request-phase decision.
pub(crate) fn decision_kind(decision: &Decision) -> DecisionKind {
    match decision {
        Decision::Static { .. } => DecisionKind::Static,
        Decision::Forward { .. } => DecisionKind::Forward,
        Decision::Jump { .. } => DecisionKind::Jump,
    }
}

/// Content of a request-phase decision, borrowed from it.
pub(crate) fn decision_detail(decision: &Decision) -> DecisionDetail<'_> {
    match decision {
        Decision::Static { rcode, answers } => DecisionDetail::Static {
            rcode: *rcode,
            answers: answers.len(),
        },
        Decision::Forward {
            upstream,
            transport,
            ..
        } => DecisionDetail::Forward {
            upstream,
            transport: reported_transport(upstream, *transport),
        },
        Decision::Jump { pipeline } => DecisionDetail::Jump { pipeline },
    }
}

/// Transport to attribute to a forward decision: `None` when any listed
/// address carries its own `scheme://` prefix (the prefix wins when the
/// query is sent), otherwise the configured transport, UDP by default. This
/// mirrors what `forward_upstream` will actually select.
/// 转发决策应报告的传输：任一地址带前缀时为 None（发送时前缀优先），否则为配置的传输，默认 UDP。
pub(crate) fn reported_transport(
    upstream: &str,
    transport: Option<Transport>,
) -> Option<Transport> {
    if upstream
        .split(',')
        .any(|addr| has_transport_prefix(addr.trim()))
    {
        None
    } else {
        Some(transport.unwrap_or(Transport::Udp))
    }
}

/// Report the decision a pipeline reached. `rule` is the deciding rule, or
/// `None` when the default upstream applied. / 上报管线得出的决策；`rule` 为决定性规则，
/// 走默认上游时为 None。
pub(crate) fn report_decision(
    observer: &dyn EngineObserver,
    ctx: &RequestContext<'_>,
    pipeline: &str,
    rule: Option<&str>,
    decision: &Decision,
) {
    observer.decision_made(
        ctx,
        &DecisionMade {
            pipeline,
            rule,
            detail: decision_detail(decision),
        },
    );
}

/// Kind of decision a response-phase action list leads to. An empty list (or
/// log-only) keeps the upstream response, which counts as `Forward`.
/// 响应阶段动作列表导致的决策类型。空列表（或仅日志）表示沿用上游响应，计为 Forward。
pub(crate) fn response_decision_kind(actions: &[Action]) -> DecisionKind {
    for action in actions {
        match action {
            Action::Log { .. } => continue,
            Action::Continue => return DecisionKind::Continue,
            Action::JumpToPipeline { .. } => return DecisionKind::Jump,
            Action::Forward { .. } | Action::Allow => return DecisionKind::Forward,
            Action::StaticResponse { .. }
            | Action::StaticIpResponse { .. }
            | Action::StaticCnameResponse { .. }
            | Action::StaticTxtResponse { .. }
            | Action::Deny
            | Action::ReplaceTxtResponse { .. } => return DecisionKind::Static,
        }
    }
    DecisionKind::Forward
}

/// Report request-phase rule matches in evaluation order. Every rule but the
/// last continued; the last carries `deciding` when a rule produced the
/// decision, and `Continue` when the default upstream applied instead.
/// 按求值顺序上报请求阶段的规则命中：除最后一条外都是 Continue；最后一条在规则
/// 产生决策时携带 `deciding`，否则（走默认上游）为 Continue。
pub(crate) fn report_matched_rules(
    observer: &dyn EngineObserver,
    ctx: &RequestContext<'_>,
    pipeline: &str,
    rules: &[Arc<str>],
    deciding: Option<DecisionKind>,
    fast_path: bool,
) {
    let last = rules.len().saturating_sub(1);
    for (idx, rule) in rules.iter().enumerate() {
        let decision = if idx == last {
            deciding.unwrap_or(DecisionKind::Continue)
        } else {
            DecisionKind::Continue
        };
        observer.rule_matched(
            ctx,
            &RuleMatched {
                pipeline,
                rule,
                phase: RulePhase::Request,
                decision,
                fast_path,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::cached_source;

    #[test]
    fn cached_source_drops_only_the_transport_label() {
        assert_eq!(cached_source(Some("udp:1.1.1.1:53")), Some("1.1.1.1:53"));
        assert_eq!(
            cached_source(Some("tcp:[2606:4700::1111]:53")),
            Some("[2606:4700::1111]:53")
        );
        assert_eq!(
            cached_source(Some("doh:https://dns.google/dns-query")),
            Some("https://dns.google/dns-query")
        );
        assert_eq!(cached_source(None), None);
    }
}
