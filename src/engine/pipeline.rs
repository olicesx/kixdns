use rustc_hash::FxHashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::TXT;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use smallvec::SmallVec;

use crate::config::{Action, Transport};
use crate::engine::utils::parse_rcode;
use crate::lock::RwLock;
use crate::matcher::advanced_rule::CompiledPipeline;
use crate::matcher::geoip::GeoIpManager;
use crate::matcher::geosite::GeoSiteManager;
use crate::matcher::{
    PipelineSelectorQuery, RuntimePipeline, RuntimePipelineConfig, eval_match_chain,
};

use super::core::Engine;
use super::matcher_adapter::{MatcherContext, matcher_matches};
use super::observation::{Observed, decision_kind, report_decision, report_matched_rules};
use super::rules::Decision;
use super::rules::{
    RuleCacheEntry, RuleCacheRecord, calculate_rule_hash, contains_continue, fast_hash_str,
};
use super::types::EngineInner;
use super::{make_static_cname_answer, make_static_ip_answer};
use crate::observe::{RuleCacheLookup, RuleEvaluated, RulePhase};

/// Request and manager references required to select a runtime pipeline.
pub struct PipelineSelectionContext<'a> {
    pub qname: &'a str,
    pub client_ip: IpAddr,
    pub qclass: DNSClass,
    pub edns_present: bool,
    pub qtype: RecordType,
    pub listener_label: &'a str,
    pub geosite_manager: Option<&'a Arc<RwLock<GeoSiteManager>>>,
    pub geoip_manager: Option<&'a Arc<RwLock<GeoIpManager>>>,
}

pub fn select_pipeline<'a>(
    cfg: &'a RuntimePipelineConfig,
    request: &PipelineSelectionContext<'_>,
) -> (Option<&'a RuntimePipeline>, Arc<str>) {
    let qname = request.qname;
    let client_ip = request.client_ip;
    let qclass = request.qclass;
    let edns_present = request.edns_present;
    let qtype = request.qtype;
    let listener_label = request.listener_label;
    let geosite_manager = request.geosite_manager;
    let geoip_manager = request.geoip_manager;
    // Optimization: only acquire geosite/geoip read locks if at least one matcher
    // actually needs them. For the common case (Any/ListenerLabel/Qtype matchers),
    // this avoids two parking_lot RwLock read acquisitions per cache-hit query,
    // eliminating cross-core cache-line bouncing at high QPS.
    //
    // 优化：仅当至少一个匹配器实际需要 geosite/geoip 时才获取读锁。
    // 常见情况（Any/ListenerLabel/Qtype 匹配器）下，避免了每次 cache-hit 查询
    // 获取两个 parking_lot RwLock 读锁，消除高 QPS 下的跨核 cache line 乒乓。
    let needs_geosite = cfg
        .pipeline_select
        .iter()
        .any(|r| r.matchers.iter().any(|m| m.matcher.needs_geosite()));
    let needs_geoip = cfg
        .pipeline_select
        .iter()
        .any(|r| r.matchers.iter().any(|m| m.matcher.needs_geoip()));

    let geosite_guard = if needs_geosite {
        geosite_manager.map(|m| m.read())
    } else {
        None
    };
    let geoip_guard = if needs_geoip {
        geoip_manager.map(|m| m.read())
    } else {
        None
    };
    let geosite_ref = geosite_guard.as_deref();
    let geoip_ref = geoip_guard.as_deref();
    let selector_query = PipelineSelectorQuery {
        listener_label,
        client_ip,
        qname,
        qclass,
        edns_present,
        qtype,
    };

    for rule in &cfg.pipeline_select {
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| {
                m.matcher
                    .matches_with_ready_managers(&selector_query, geoip_ref, geosite_ref)
            },
        );
        if matched && let Some(&idx) = cfg.pipeline_id_index.get(rule.pipeline.as_str()) {
            let p = &cfg.pipelines[idx];
            return (Some(p), p.id.clone());
        }
    }

    match cfg.pipelines.first() {
        Some(p) => (Some(p), p.id.clone()),
        None => (None, Arc::from("default")),
    }
}

/// Immutable request state shared across rule evaluation and rule-cache insertion.
pub struct RuleEvaluationContext<'a> {
    pub client_ip: IpAddr,
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub edns_present: bool,
    pub skip_rules: Option<&'a FxHashSet<Arc<str>>>,
    pub skip_cache: bool,
    /// Observer context of the request being evaluated; `None` disables
    /// rule-match events. / 所属请求的观察者上下文；None 时不上报规则命中。
    pub observed: Observed<'a>,
}

impl<'a> RuleEvaluationContext<'a> {
    pub fn new(
        client_ip: IpAddr,
        qname: &'a str,
        qtype: RecordType,
        qclass: DNSClass,
        edns_present: bool,
        skip_rules: Option<&'a FxHashSet<Arc<str>>>,
        skip_cache: bool,
    ) -> Self {
        Self {
            client_ip,
            qname,
            qtype,
            qclass,
            edns_present,
            skip_rules,
            skip_cache,
            observed: None,
        }
    }

    /// Attach the observer context of the request so rule matches are reported.
    pub fn with_observed(mut self, observed: Observed<'a>) -> Self {
        self.observed = observed;
        self
    }
}

impl Engine {
    pub(crate) fn compiled_for<'a>(
        &self,
        state: &'a EngineInner,
        pipeline_id: &str,
    ) -> Option<&'a CompiledPipeline> {
        state
            .pipeline_index
            .get(pipeline_id)
            .and_then(|&idx| state.compiled_pipelines.get(idx))
    }

    pub fn insert_rule_cache(
        &self,
        hash: u64,
        pipeline_id: Arc<str>,
        request: &RuleEvaluationContext<'_>,
        decision: Decision,
        include_ip: bool,
        matched_rules: &[Arc<str>],
        decided_by_rule: bool,
    ) {
        let RuleEvaluationContext {
            client_ip,
            qname,
            qtype,
            qclass,
            ..
        } = *request;
        let state = self.state.load();
        let ttl = match &decision {
            Decision::Static { answers, .. } => {
                let min_ttl = answers.iter().map(|r| r.ttl).min();
                min_ttl.map(|t| Duration::from_secs(t as u64))
            }
            Decision::Forward {
                response_matchers,
                response_actions_on_match,
                response_actions_on_miss,
                ..
            } => {
                // If it has response-phase logic, it is not "static" in the user's terms.
                // It should expire based on the configured min_ttl.
                if !response_matchers.is_empty()
                    || !response_actions_on_match.is_empty()
                    || !response_actions_on_miss.is_empty()
                {
                    Some(Duration::from_secs(state.pipeline.settings.min_ttl as u64))
                } else {
                    None // Permanent
                }
            }
            _ => {
                // Jump, Allow, Deny: 120秒 TTL（之前是永久）
                // Jump, Allow, Deny: 120 second TTL (previously permanent)
                Some(Duration::from_secs(120))
            }
        };

        // If TTL is 0, do not cache / 如果 TTL 为 0，则不缓存
        if let Some(d) = ttl
            && d.as_secs() == 0
        {
            return;
        }

        let expires_at = ttl.map(|d| Instant::now() + d);

        // 优化：根据配置决定是否包含client_ip
        // Optimization: only include client_ip in cache entry when configured or required by rule
        self.rule_cache.insert(
            hash,
            RuleCacheRecord {
                entry: RuleCacheEntry {
                    pipeline_id,
                    qname_hash: fast_hash_str(qname),
                    qtype: u16::from(qtype),
                    qclass: u16::from(qclass),
                    client_ip: if include_ip { Some(client_ip) } else { None },
                    decision: Arc::new(decision),
                    expires_at,
                },
                matched_rules: request.observed.map(|_| Arc::from(matched_rules)),
                decided_by_rule,
            },
        );
    }

    pub fn apply_rules(
        &self,
        state: &EngineInner,
        pipeline: &RuntimePipeline,
        request: &RuleEvaluationContext<'_>,
    ) -> Decision {
        let RuleEvaluationContext {
            client_ip,
            qname,
            qtype,
            qclass,
            skip_rules,
            skip_cache,
            ..
        } = *request;
        // 1. Check Rule Cache
        // Use hash for lookup to avoid cloning String for key on every lookup
        let include_ip =
            pipeline.uses_client_ip || state.pipeline.settings.cache_background_refresh;
        let rule_hash = calculate_rule_hash(
            state.cache_namespace(&pipeline.id),
            &pipeline.id,
            qname,
            qtype,
            qclass,
            client_ip,
            include_ip,
        );
        let allow_rule_cache_lookup = !skip_cache && skip_rules.is_none_or(|set| set.is_empty());

        if allow_rule_cache_lookup && let Some(record) = self.rule_cache.get(&rule_hash) {
            let entry = &record.entry;
            // Check validity and clean up if expired
            // 检查有效性，如果过期则清理
            if !entry.is_valid() {
                self.rule_cache.remove(&rule_hash);
            } else if entry.matches(&pipeline.id, qname, qtype, qclass, client_ip, include_ip) {
                if let Some((observer, ctx)) = request.observed {
                    let recorded = record.matched_rules.as_deref();
                    observer.rule_cache_lookup(
                        ctx,
                        &RuleCacheLookup {
                            pipeline: &pipeline.id,
                            hit: true,
                            matched_rules: recorded.map_or(0, <[Arc<str>]>::len),
                        },
                    );
                    let deciding_rule = record.decided_by_rule.then(|| recorded?.last()).flatten();
                    if let Some(rules) = recorded {
                        report_matched_rules(
                            observer,
                            ctx,
                            &pipeline.id,
                            rules,
                            deciding_rule.map(|_| decision_kind(&entry.decision)),
                            false,
                        );
                    }
                    report_decision(
                        observer,
                        ctx,
                        &pipeline.id,
                        deciding_rule.map(AsRef::as_ref),
                        &entry.decision,
                    );
                }
                return (*entry.decision).clone();
            }
        }
        if allow_rule_cache_lookup && let Some((observer, ctx)) = request.observed {
            observer.rule_cache_lookup(
                ctx,
                &RuleCacheLookup {
                    pipeline: &pipeline.id,
                    hit: false,
                    matched_rules: 0,
                },
            );
        }

        // 2. Evaluate rules in order; None means no rule decided and the
        //    default upstream applies.
        // 2. 按顺序求值规则；None 表示没有规则做出决策，使用默认上游。
        let mut matched_rules: SmallVec<[Arc<str>; 4]> = SmallVec::new();
        let decided = self.evaluate_rules(state, pipeline, request, &mut matched_rules);
        let decided_by_rule = decided.is_some();
        let decision = decided.unwrap_or_else(|| Decision::Forward {
            upstream: Arc::from(state.pipeline.settings.default_upstream.as_str()),
            pre_split_upstreams: None,
            response_matchers: Vec::new(),
            response_matcher_operator: crate::config::MatchOperator::And,
            response_actions_on_match: Vec::new(),
            response_actions_on_miss: Vec::new(),
            rule_name: Arc::from("default"),
            transport: Some(Transport::Udp),
            ecs: None,
            continue_on_match: false,
            continue_on_miss: false,
            allow_reuse: false,
        });

        if let Some((observer, ctx)) = request.observed {
            report_matched_rules(
                observer,
                ctx,
                &pipeline.id,
                &matched_rules,
                decided_by_rule.then(|| decision_kind(&decision)),
                false,
            );
            report_decision(
                observer,
                ctx,
                &pipeline.id,
                decided_by_rule
                    .then(|| matched_rules.last())
                    .flatten()
                    .map(AsRef::as_ref),
                &decision,
            );
        }
        self.insert_rule_cache(
            rule_hash,
            pipeline.id.clone(),
            request,
            decision.clone(),
            include_ip,
            &matched_rules,
            decided_by_rule,
        );
        decision
    }

    /// Evaluate `pipeline`'s rules in order for `request`. Returns the first
    /// decision, or `None` when every matching rule continued. The names of
    /// the rules whose matchers matched are appended to `matched_rules`.
    /// 按顺序求值规则：返回第一个决策，所有命中规则都继续时返回 None。
    /// 匹配器命中的规则名追加到 `matched_rules`。
    fn evaluate_rules(
        &self,
        state: &EngineInner,
        pipeline: &RuntimePipeline,
        request: &RuleEvaluationContext<'_>,
        matched_rules: &mut SmallVec<[Arc<str>; 4]>,
    ) -> Option<Decision> {
        let RuleEvaluationContext {
            client_ip,
            qname,
            qtype,
            qclass,
            edns_present,
            skip_rules,
            ..
        } = *request;
        // Borrow instead of clone: state lives for the entire function, no heap alloc
        // 借用而非克隆：state 在整个函数生命周期内存活，零堆分配
        let upstream_default = &state.pipeline.settings.default_upstream;

        // 2. Candidate Selection (compiled index if available)
        // SmallVec<[usize; 32]> avoids heap allocation for typical rule sets (<= 32 candidates)
        let mut candidate_indices: SmallVec<[usize; 32]> =
            if let Some(compiled) = self.compiled_for(state, &pipeline.id) {
                compiled.index.get_candidates(qname, qtype)
            } else {
                SmallVec::new()
            };

        if candidate_indices.is_empty() {
            // Fallback to runtime indices
            candidate_indices.extend_from_slice(&pipeline.always_check_rules);

            // 最高优先级：完全域名匹配（O(1)查找）/ Highest priority: exact domain match (O(1) lookup)
            if let Some(indices) = pipeline.domain_exact_index.get(qname) {
                candidate_indices.extend_from_slice(indices);
            }

            // 高频优化：使用 query_type 索引快速过滤
            // High-frequency optimization: use query_type index for fast filtering
            if let Some(indices) = pipeline.query_type_index.get(&qtype) {
                candidate_indices.extend_from_slice(indices);
            }

            let mut search_name = qname;
            loop {
                // 零拷贝优化：Arc<str>可以通过&str查找 / Zero-copy: Arc<str> can be looked up by &str
                if let Some(indices) = pipeline.domain_suffix_index.get(search_name) {
                    candidate_indices.extend_from_slice(indices);
                }

                if let Some(idx) = search_name.find('.') {
                    search_name = &search_name[idx + 1..];
                } else {
                    break;
                }
            }

            candidate_indices.sort_unstable();
            candidate_indices.dedup();
        }

        // 3. Execute Rules
        // 优化：提取 MatcherContext 到循环外部，避免重复构造
        // Optimization: Extract MatcherContext outside loop to avoid repeated construction
        let ctx = MatcherContext {
            qname,
            qclass,
            client_ip,
            edns_present,
            qtype,
            geoip_manager: Some(&self.geoip_manager),
            geosite_manager: Some(&self.geosite_manager),
        };

        'rules: for idx in candidate_indices {
            let rule = match pipeline.rules.get(idx) {
                Some(r) => r,
                None => continue, // Skip if index is out of bounds due to reload race / 如果由于重载竞争导致索引越界，则跳过
            };
            if skip_rules.is_some_and(|set| set.contains(&rule.name)) {
                continue;
            }
            let req_match = eval_match_chain(
                &rule.matchers,
                |m| m.operator,
                |m| {
                    // 直接传递 Arc<RwLock<T>>，让 matcher 内部按需获取锁
                    // Pass Arc<RwLock<T>> directly, let matcher acquire locks on-demand
                    matcher_matches(&m.matcher, &ctx)
                },
            );
            if let Some((observer, observed_ctx)) = request.observed {
                observer.rule_evaluated(
                    observed_ctx,
                    &RuleEvaluated {
                        pipeline: &pipeline.id,
                        rule: &rule.name,
                        phase: RulePhase::Request,
                        matched: req_match,
                        matchers: rule.matchers.len(),
                    },
                );
            }

            if req_match {
                // Names are only needed for observers; skip the clone otherwise
                // 规则名只有观察者需要，无观察者时不做克隆
                if request.observed.is_some() {
                    matched_rules.push(rule.name.clone());
                }
                // Check for multiple Forward actions using pre-computed merge result.
                // The merge was computed at config load time (Rule::compute_merged_forward),
                // eliminating per-request FxHashSet + format! + join overhead.
                // 使用配置加载时预计算的合并结果检查多 Forward action。
                // 合并在配置加载时计算（Rule::compute_merged_forward），
                // 消除每请求的 FxHashSet + format! + join 开销。
                if let Some(merged) = &rule.merged_forward {
                    let d = Decision::Forward {
                        upstream: merged.upstream_str.clone(),
                        pre_split_upstreams: Some(merged.upstream_list.clone()),
                        response_matchers: rule.response_matchers.clone(),
                        response_matcher_operator: rule.response_matcher_operator,
                        response_actions_on_match: rule.response_actions_on_match.clone(),
                        response_actions_on_miss: rule.response_actions_on_miss.clone(),
                        rule_name: rule.name.clone(),
                        transport: None, // Each upstream decides its own transport / 每个 upstream 自行决定 transport
                        ecs: None,
                        continue_on_match: false,
                        continue_on_miss: false,
                        allow_reuse: false,
                    };
                    return Some(d);
                }

                // Single Forward or other actions: use original logic
                // 单个 Forward 或其他 action：按原逻辑处理
                for action in &rule.actions {
                    match action {
                        Action::StaticResponse { rcode } => {
                            let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                            let d = Decision::Static {
                                rcode: code,
                                answers: Vec::new(),
                            };
                            return Some(d);
                        }
                        Action::StaticIpResponse { ip } => {
                            let (rcode, answers) = make_static_ip_answer(qname, request.qtype, ip);
                            let d = Decision::Static { rcode, answers };
                            return Some(d);
                        }
                        Action::StaticCnameResponse { target, ttl } => {
                            let (rcode, answers) =
                                make_static_cname_answer(qname, target, ttl.unwrap_or(300));
                            let d = Decision::Static { rcode, answers };
                            return Some(d);
                        }
                        Action::JumpToPipeline { pipeline: target } => {
                            let d = Decision::Jump {
                                pipeline: Arc::from(target.as_str()),
                            };
                            return Some(d);
                        }
                        Action::Allow => {
                            let d = Decision::Forward {
                                upstream: Arc::from(upstream_default.as_str()),
                                pre_split_upstreams: None,
                                response_matchers: Vec::new(),
                                response_matcher_operator: crate::config::MatchOperator::And,
                                response_actions_on_match: Vec::new(),
                                response_actions_on_miss: Vec::new(),
                                rule_name: rule.name.clone(),
                                transport: Some(Transport::Udp),
                                ecs: None,
                                continue_on_match: false,
                                continue_on_miss: false,
                                allow_reuse: true,
                            };
                            return Some(d);
                        }
                        Action::Deny => {
                            let d = Decision::Static {
                                rcode: ResponseCode::Refused,
                                answers: Vec::new(),
                            };
                            return Some(d);
                        }
                        Action::Forward {
                            upstream,
                            transport,
                            ecs,
                            pre_split_upstreams,
                        } => {
                            let upstream_addr: Arc<str> = upstream
                                .as_ref()
                                .map(|s| Arc::from(s.as_str()))
                                .unwrap_or_else(|| Arc::from(upstream_default.as_str()));
                            let continue_on_match =
                                contains_continue(&rule.response_actions_on_match);
                            let continue_on_miss =
                                contains_continue(&rule.response_actions_on_miss);
                            let d = Decision::Forward {
                                upstream: upstream_addr,
                                pre_split_upstreams: pre_split_upstreams.clone(),
                                response_matchers: rule.response_matchers.clone(),
                                response_matcher_operator: rule.response_matcher_operator,
                                response_actions_on_match: rule.response_actions_on_match.clone(),
                                response_actions_on_miss: rule.response_actions_on_miss.clone(),
                                rule_name: rule.name.clone(),
                                transport: Some(transport.unwrap_or(Transport::Udp)),
                                ecs: ecs.clone(),
                                continue_on_match,
                                continue_on_miss,
                                allow_reuse: false,
                            };
                            return Some(d);
                        }
                        Action::Log { level } => {
                            super::matcher_adapter::log_match(
                                level.as_deref(),
                                &rule.name,
                                qname,
                                client_ip,
                            );
                        }
                        Action::StaticTxtResponse { text, ttl } => {
                            if let Ok(name) = std::str::FromStr::from_str(qname) {
                                let ttl = ttl.unwrap_or(300);
                                let txt = TXT::new(text.to_vec());
                                let record = Record::from_rdata(name, ttl, RData::TXT(txt));
                                let d = Decision::Static {
                                    rcode: ResponseCode::NoError,
                                    answers: vec![record],
                                };
                                return Some(d);
                            }
                            let d = Decision::Static {
                                rcode: ResponseCode::ServFail,
                                answers: Vec::new(),
                            };
                            return Some(d);
                        }
                        Action::ReplaceTxtResponse { .. } => {
                            continue 'rules;
                        }
                        Action::Continue => {
                            continue 'rules;
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod observer_rule_cache_tests {
    use std::sync::Arc;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    use crate::config::PipelineConfig;
    use crate::engine::Engine;
    use crate::matcher::RuntimePipelineConfig;
    use crate::observe::NoopObserver;

    fn runtime() -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9", "min_ttl": 0 },
            "pipelines": [{
                "id": "main",
                "rules": [{
                    "name": "block",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
                }]
            }]
        });
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(cfg).expect("runtime config")
    }

    fn query() -> Vec<u8> {
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str_relaxed("example.com").unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
    }

    /// Collect the `matched_rules` of every rule cache record after one request.
    async fn recorded_rules(engine: Engine) -> Vec<Option<usize>> {
        engine
            .handle_packet(&query(), "127.0.0.1:53000".parse().unwrap())
            .await
            .expect("static answer");
        engine.rule_cache.run_pending_tasks();
        engine
            .rule_cache
            .iter()
            .map(|(_, record)| record.matched_rules.as_ref().map(|rules| rules.len()))
            .collect()
    }

    #[tokio::test]
    async fn rule_cache_records_no_rule_names_without_observer() {
        let engine = Engine::new(runtime(), "test".to_string()).expect("engine");
        let records = recorded_rules(engine).await;
        assert!(
            !records.is_empty(),
            "the request must populate the rule cache"
        );
        assert!(
            records.iter().all(Option::is_none),
            "matched_rules must stay None without an observer: {records:?}"
        );
    }

    #[tokio::test]
    async fn rule_cache_records_rule_names_with_observer() {
        let engine = Engine::builder(runtime())
            .observer(Arc::new(NoopObserver))
            .build()
            .expect("engine");
        let records = recorded_rules(engine).await;
        assert_eq!(records, vec![Some(1)]);
    }
}
