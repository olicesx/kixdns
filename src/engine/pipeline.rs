use std::sync::Arc;
use std::net::IpAddr;
use std::collections::HashSet;
use std::time::{Duration, Instant};

use smallvec::SmallVec;
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};
use hickory_proto::rr::rdata::{A, AAAA, TXT};
use hickory_proto::op::ResponseCode;
use tracing::info;

use crate::config::{Action, Transport};
use crate::lock::RwLock;
use crate::matcher::{RuntimePipeline, RuntimePipelineConfig, eval_match_chain};
use crate::matcher::advanced_rule::CompiledPipeline;
use crate::matcher::geosite::GeoSiteManager;
use crate::matcher::geoip::GeoIpManager;

use super::core::Engine;
use super::types::EngineInner;
use super::rules::Decision;
use super::rules::{RuleCacheEntry, calculate_rule_hash, contains_continue, fast_hash_str};
use super::matcher_adapter::{MatcherContext, matcher_matches};

pub fn select_pipeline<'a>(
    cfg: &'a RuntimePipelineConfig,
    qname: &str,
    client_ip: IpAddr,
    qclass: DNSClass,
    edns_present: bool,
    qtype: RecordType,
    listener_label: &str,
    geosite_manager: Option<&Arc<RwLock<GeoSiteManager>>>,
    geoip_manager: Option<&Arc<RwLock<GeoIpManager>>>,
) -> (Option<&'a RuntimePipeline>, Arc<str>) {
    // 优化：提前获取读锁，避免在循环中重复获取/释放
    // Optimization: Acquire read locks upfront to avoid repeated acquire/release in loop
    let geosite_guard = geosite_manager.map(|m| m.read());
    let geoip_guard = geoip_manager.map(|m| m.read());
    let geosite_ref = geosite_guard.as_deref();
    let geoip_ref = geoip_guard.as_deref();

    for rule in &cfg.pipeline_select {
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| {
                m.matcher.matches_with_ready_managers(
                    listener_label,
                    client_ip,
                    qname,
                    qclass,
                    edns_present,
                    qtype,
                    geoip_ref,
                    geosite_ref,
                )
            },
        );
        if matched {
            if let Some(p) = cfg.pipelines.iter().find(|p| p.id.as_ref() == rule.pipeline.as_str()) {
                return (Some(p), p.id.clone());
            }
        }
    }

    match cfg.pipelines.first() {
        Some(p) => (Some(p), p.id.clone()),
        None => (None, Arc::from("default")),
    }
}

impl Engine {
    pub(crate) fn compiled_for<'a>(&self, state: &'a EngineInner, pipeline_id: &str) -> Option<&'a CompiledPipeline> {
        state.compiled_pipelines
            .iter()
            .find(|p| p.id.as_ref() == pipeline_id)
    }

    pub fn insert_rule_cache(&self, hash: u64, pipeline_id: Arc<str>, qname: &str, client_ip: IpAddr, decision: Decision, uses_client_ip: bool) {
        let state = self.state.load();
        let ttl = match &decision {
            Decision::Static { answers, .. } => {
                let min_ttl = answers.iter().map(|r| r.ttl()).min();
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
        if let Some(d) = ttl {
            if d.as_secs() == 0 {
                return;
            }
        }

        let expires_at = ttl.map(|d| Instant::now() + d);

        // 优化：根据配置决定是否包含client_ip
        // Optimization: only include client_ip in cache entry when configured or required by rule
        let include_ip = uses_client_ip || self.cache_background_refresh;

        self.rule_cache.insert(
            hash,
            RuleCacheEntry {
                pipeline_id,
                qname_hash: fast_hash_str(qname),
                client_ip: if include_ip { Some(client_ip) } else { None },
                decision: Arc::new(decision),
                expires_at,
            },
        );
    }

    pub fn apply_rules(
        &self,
        state: &EngineInner,
        pipeline: &RuntimePipeline,
        client_ip: IpAddr,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        edns_present: bool,
        skip_rules: Option<&HashSet<Arc<str>>>,
        skip_cache: bool,
    ) -> Decision {
        // 1. Check Rule Cache
        // Use hash for lookup to avoid cloning String for key on every lookup
        let rule_hash = calculate_rule_hash(&pipeline.id, qname, client_ip, pipeline.uses_client_ip);
        let allow_rule_cache_lookup = !skip_cache && skip_rules.is_none_or(|set| set.is_empty());
        
        if allow_rule_cache_lookup {
            if let Some(entry) = self.rule_cache.get(&rule_hash) {
                // Check validity and clean up if expired
                // 检查有效性，如果过期则清理
                if !entry.is_valid() {
                    self.rule_cache.remove(&rule_hash);
                } else if entry.matches(&pipeline.id, qname, client_ip, pipeline.uses_client_ip) {
                    return (*entry.decision).clone();
                }
            }
        }

        let upstream_default = state.pipeline.settings.default_upstream.clone();

        // 2. Candidate Selection (compiled index if available)
        // SmallVec<[usize; 32]> avoids heap allocation for typical rule sets (<= 32 candidates)
        let mut candidate_indices: SmallVec<[usize; 32]> = if let Some(compiled) = self.compiled_for(state, &pipeline.id) {
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

            if req_match {
                // 检查是否有多个 forward action / Check for multiple forward actions
                let forward_actions: Vec<_> = rule.actions.iter()
                    .filter_map(|a| match a {
                        Action::Forward { upstream, transport, pre_split_upstreams } => Some((upstream, transport, pre_split_upstreams.clone())),
                        _ => None,
                    })
                    .collect();

                if forward_actions.len() > 1 {
                    // 多个 forward action：按 transport 类型分别合并，并去重 / Multiple forward actions: merge by transport type with deduplication
                    use std::collections::HashSet;

                    let mut tcp_upstreams: HashSet<String> = HashSet::new();
                    let mut udp_upstreams: HashSet<String> = HashSet::new();

                    // 收集并按 transport 分组，同时去重
                    for (upstream_opt, transport_opt, _pre_split) in forward_actions.iter() {
                        if let Some(upstream) = upstream_opt {
                            // 获取这个 action 的 transport
                            let action_transport = transport_opt.unwrap_or(Transport::Udp);

                            // 分割 upstream 字符串（可能包含逗号）
                            for addr in upstream.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                                // 跳过已有协议前缀的地址
                                if addr.contains("://") {
                                    if addr.starts_with("tcp://") {
                                        tcp_upstreams.insert(addr.to_string());
                                    } else if addr.starts_with("udp://") {
                                        udp_upstreams.insert(addr.to_string());
                                    }
                                } else {
                                    // 添加协议前缀
                                    match action_transport {
                                        Transport::Tcp => {
                                            tcp_upstreams.insert(format!("tcp://{}", addr));
                                        }
                                        Transport::Udp => {
                                            udp_upstreams.insert(format!("udp://{}", addr));
                                        }
                                        Transport::TcpUdp => {
                                            // TcpUdp uses both transports, add to both sets
                                            tcp_upstreams.insert(format!("tcp://{}", addr));
                                            udp_upstreams.insert(format!("udp://{}", addr));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 合并所有 upstream（保留协议前缀）
                    let mut all_upstreams: Vec<std::sync::Arc<str>> = Vec::new();
                    all_upstreams.extend(tcp_upstreams.iter().map(|s| std::sync::Arc::from(s.as_str())));
                    all_upstreams.extend(udp_upstreams.iter().map(|s| std::sync::Arc::from(s.as_str())));

                    if all_upstreams.is_empty() {
                        // 所有 upstream 都为空，使用默认
                        info!(
                            event = "multiple_forward_actions",
                            count = forward_actions.len(),
                            "all forward actions have empty upstream, using default"
                        );
                    } else {
                        info!(
                            event = "multiple_forward_actions",
                            count = forward_actions.len(),
                            tcp_count = tcp_upstreams.len(),
                            udp_count = udp_upstreams.len(),
                            total_upstreams = all_upstreams.len(),
                            tcp_upstreams = ?tcp_upstreams,
                            udp_upstreams = ?udp_upstreams,
                            "merged multiple forward actions with transport-specific deduplication"
                        );
                    }

                    let merged_str = if all_upstreams.is_empty() {
                        String::new()
                    } else {
                        all_upstreams.join(",")
                    };

                    let d = Decision::Forward {
                        upstream: Arc::from(if merged_str.is_empty() { "" } else { merged_str.as_str() }),
                        pre_split_upstreams: if all_upstreams.is_empty() { None } else { Some(std::sync::Arc::new(all_upstreams)) },
                        response_matchers: rule.response_matchers.clone(),
                        response_matcher_operator: rule.response_matcher_operator,
                        response_actions_on_match: rule.response_actions_on_match.clone(),
                        response_actions_on_miss: rule.response_actions_on_miss.clone(),
                        rule_name: rule.name.clone(),
                        transport: None, // 让每个 upstream 自己决定 transport / Let each upstream decide its own transport
                        continue_on_match: false,
                        continue_on_miss: false,
                        allow_reuse: false,
                    };
                    self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                    return d;
                }

                // 单个 forward 或其他 action：按原逻辑处理 / Single forward or other actions: use original logic
                for action in &rule.actions {
                    match action {
                        Action::StaticResponse { rcode } => {
                            let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                            let d = Decision::Static {
                                rcode: code,
                                answers: Vec::new(),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::StaticIpResponse { ip } => {
                            if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                                if let Ok(name) = std::str::FromStr::from_str(qname) {
                                    let rdata = match ip_addr {
                                        IpAddr::V4(v4) => RData::A(A(v4)),
                                        IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
                                    };
                                    let record = Record::from_rdata(name, 300, rdata);
                                    let d = Decision::Static {
                                        rcode: ResponseCode::NoError,
                                        answers: vec![record],
                                    };
                                    self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                                    return d;
                                }
                            }
                            let d = Decision::Static {
                                rcode: ResponseCode::ServFail,
                                answers: Vec::new(),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::JumpToPipeline { pipeline: target } => {
                            let d = Decision::Jump {
                                pipeline: Arc::from(target.as_str()),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
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
                                continue_on_match: false,
                                continue_on_miss: false,
                                allow_reuse: true,
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::Deny => {
                            let d = Decision::Static {
                                rcode: ResponseCode::Refused,
                                answers: Vec::new(),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::Forward {
                            upstream,
                            transport,
                            pre_split_upstreams,
                        } => {
                            let upstream_addr: Arc<str> = upstream
                                .as_ref()
                                .map(|s| Arc::from(s.as_str()))
                                .unwrap_or_else(|| Arc::from(upstream_default.as_str()));
                            let continue_on_match = contains_continue(&rule.response_actions_on_match);
                            let continue_on_miss = contains_continue(&rule.response_actions_on_miss);
                            let d = Decision::Forward {
                                upstream: upstream_addr,
                                pre_split_upstreams: pre_split_upstreams.clone(),
                                response_matchers: rule.response_matchers.clone(),
                                response_matcher_operator: rule.response_matcher_operator,
                                response_actions_on_match: rule.response_actions_on_match.clone(),
                                response_actions_on_miss: rule.response_actions_on_miss.clone(),
                                rule_name: rule.name.clone(),
                                transport: Some(transport.unwrap_or(Transport::Udp)),
                                continue_on_match,
                                continue_on_miss,
                                allow_reuse: false,
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::Log { level } => {
                                super::matcher_adapter::log_match(level.as_deref(), &rule.name, qname, client_ip);
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
                                self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                                return d;
                            }
                            let d = Decision::Static {
                                rcode: ResponseCode::ServFail,
                                answers: Vec::new(),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
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

        let d = Decision::Forward {
            upstream: Arc::from(upstream_default.as_str()),
            pre_split_upstreams: None,
            response_matchers: Vec::new(),
            response_matcher_operator: crate::config::MatchOperator::And,
            response_actions_on_match: Vec::new(),
            response_actions_on_miss: Vec::new(),
            rule_name: Arc::from("default"),
            transport: Some(Transport::Udp),
            continue_on_match: false,
            continue_on_miss: false,
            allow_reuse: false,
        };
        self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
        d
    }
}

fn parse_rcode(rcode: &str) -> Option<ResponseCode> {
    match rcode.to_ascii_uppercase().as_str() {
        "NOERROR" => Some(ResponseCode::NoError),
        "FORMERR" => Some(ResponseCode::FormErr),
        "SERVFAIL" => Some(ResponseCode::ServFail),
        "NXDOMAIN" => Some(ResponseCode::NXDomain),
        "NOTIMP" => Some(ResponseCode::NotImp),
        "REFUSED" => Some(ResponseCode::Refused),
        _ => None,
    }
}
