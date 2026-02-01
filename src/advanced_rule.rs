use std::net::IpAddr;
use std::sync::Arc;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{DNSClass, RecordType};
use ipnet::IpNet;
use regex::Regex;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

use crate::config::{Action, MatchOperator};
use crate::engine::{make_static_ip_answer, Decision};
use crate::matcher::eval_match_chain;
use crate::matcher::{RuntimeMatcher, RuntimePipeline, RuntimePipelineConfig, RuntimeRule};

#[derive(Debug, Clone)]
pub struct CompiledPipeline {
    pub id: Arc<str>,
    pub rules: Vec<CompiledRule>,
    pub index: RuleIndex,
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    #[allow(dead_code)]
    pub rule_idx: usize,
    #[allow(dead_code)]
    pub matcher_operator: MatchOperator,
    pub matchers: Vec<CompiledMatcherWithOp>,
    pub precomputed: Option<PrecomputedAction>,
}

#[derive(Debug, Clone)]
pub struct CompiledMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: CompiledMatcher,
}

#[derive(Debug, Clone)]
pub enum CompiledMatcher {
    #[allow(dead_code)]
    DomainExact {
        domain: String,
    },
    DomainSuffix {
        suffix: String,
    },
    ClientIp {
        net: IpNet,
    },
    #[allow(dead_code)]
    QueryType {
        qtype: RecordType,
    },
    Qclass {
        qclass: DNSClass,
    },
    Regex {
        regex: Regex,
    },
    Complex {
        matcher: RuntimeMatcher,
    },
}

#[derive(Debug, Clone)]
pub enum PrecomputedAction {
    Static { rcode: ResponseCode },
    StaticIp { ip: String },
}

#[derive(Debug, Clone, Default)]
pub struct RuleIndex {
    pub domain_exact: FxHashMap<String, Vec<usize>>,
    pub domain_suffix: FxHashMap<String, Vec<usize>>,
    pub query_type: FxHashMap<RecordType, Vec<usize>>,
    pub always_check: Vec<usize>,
}

impl RuleIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(&mut self, rule_idx: usize, rule: &CompiledRule) {
        let and_chain = rule
            .matchers
            .iter()
            .skip(1)
            .all(|m| matches!(m.operator, MatchOperator::And));

        if !and_chain {
            self.always_check.push(rule_idx);
            return;
        }

        let mut indexed = false;
        for m in &rule.matchers {
            match &m.matcher {
                CompiledMatcher::DomainExact { domain } if !domain.is_empty() => {
                    self.domain_exact
                        .entry(domain.clone())
                        .or_default()
                        .push(rule_idx);
                    indexed = true;
                    break;
                }
                CompiledMatcher::DomainSuffix { suffix } if !suffix.is_empty() => {
                    self.domain_suffix
                        .entry(suffix.clone())
                        .or_default()
                        .push(rule_idx);
                    indexed = true;
                    break;
                }
                CompiledMatcher::QueryType { qtype } => {
                    self.query_type.entry(*qtype).or_default().push(rule_idx);
                    indexed = true;
                    break;
                }
                _ => {}
            }
        }

        if !indexed {
            self.always_check.push(rule_idx);
        }
    }

    /// Get candidate rule indices into provided SmallVec to avoid allocation
    /// SmallVec<[usize; 32]> keeps up to 32 candidates on stack (typical case)
    pub fn get_candidates_into(
        &self,
        qname: &str,
        qtype: RecordType,
        out: &mut SmallVec<[usize; 32]>,
    ) {
        out.extend_from_slice(&self.always_check);

        if let Some(indices) = self.domain_exact.get(qname) {
            out.extend_from_slice(indices);
        }

        let mut search_name = qname;
        loop {
            if let Some(indices) = self.domain_suffix.get(search_name) {
                out.extend_from_slice(indices);
            }
            if let Some(idx) = search_name.find('.') {
                search_name = &search_name[idx + 1..];
            } else {
                break;
            }
        }

        if let Some(indices) = self.query_type.get(&qtype) {
            out.extend_from_slice(indices);
        }

        out.sort_unstable();
        out.dedup();
    }

    pub fn get_candidates(&self, qname: &str, qtype: RecordType) -> SmallVec<[usize; 32]> {
        let mut candidates = SmallVec::new();
        self.get_candidates_into(qname, qtype, &mut candidates);
        candidates
    }
}

pub fn compile_pipelines(cfg: &RuntimePipelineConfig) -> Vec<CompiledPipeline> {
    cfg.pipelines.iter().map(|p| compile_pipeline(p)).collect()
}

fn compile_pipeline(p: &RuntimePipeline) -> CompiledPipeline {
    let mut rules = Vec::with_capacity(p.rules.len());
    let mut index = RuleIndex::new();

    for (idx, rule) in p.rules.iter().enumerate() {
        let compiled = compile_rule(rule, idx);
        index.add_rule(idx, &compiled);
        rules.push(compiled);
    }

    CompiledPipeline {
        id: p.id.clone(),
        rules,
        index,
    }
}

fn compile_rule(rule: &RuntimeRule, rule_idx: usize) -> CompiledRule {
    let matchers = rule
        .matchers
        .iter()
        .map(|m| CompiledMatcherWithOp {
            operator: m.operator,
            matcher: compile_matcher(&m.matcher),
        })
        .collect();

    let precomputed = precompute_action(rule);

    CompiledRule {
        rule_idx,
        matcher_operator: rule.matcher_operator,
        matchers,
        precomputed,
    }
}

fn compile_matcher(m: &RuntimeMatcher) -> CompiledMatcher {
    match m {
        RuntimeMatcher::Any => CompiledMatcher::DomainSuffix {
            suffix: String::new(),
        },
        RuntimeMatcher::DomainExact { value } => CompiledMatcher::DomainExact {
            domain: value.clone(),
        },
        RuntimeMatcher::DomainSuffix { value } => CompiledMatcher::DomainSuffix {
            suffix: value.clone(),
        },
        RuntimeMatcher::ClientIp { net } => CompiledMatcher::ClientIp { net: net.clone() },
        RuntimeMatcher::DomainRegex { regex } => CompiledMatcher::Regex {
            regex: regex.clone(),
        },
        RuntimeMatcher::GeoipCountry { country_codes } => CompiledMatcher::Complex {
            matcher: RuntimeMatcher::GeoipCountry {
                country_codes: country_codes.clone(),
            },
        },
        RuntimeMatcher::GeoipPrivate { expect } => CompiledMatcher::Complex {
            matcher: RuntimeMatcher::GeoipPrivate { expect: *expect },
        },
        RuntimeMatcher::Qclass { value } => CompiledMatcher::Qclass { qclass: *value },
        RuntimeMatcher::EdnsPresent { expect } => CompiledMatcher::Complex {
            matcher: RuntimeMatcher::EdnsPresent { expect: *expect },
        },
        RuntimeMatcher::GeoSite { tag } => CompiledMatcher::Complex {
            matcher: RuntimeMatcher::GeoSite { tag: tag.clone() },
        },
        RuntimeMatcher::GeoSiteNot { tag } => CompiledMatcher::Complex {
            matcher: RuntimeMatcher::GeoSiteNot { tag: tag.clone() },
        },
        RuntimeMatcher::Qtype { value } => CompiledMatcher::QueryType { qtype: *value },
    }
}

fn precompute_action(rule: &RuntimeRule) -> Option<PrecomputedAction> {
    let action = rule.actions.first()?;
    match action {
        Action::StaticResponse { rcode } => {
            parse_rcode(rcode).map(|rc| PrecomputedAction::Static { rcode: rc })
        }
        Action::StaticIpResponse { ip } => Some(PrecomputedAction::StaticIp { ip: ip.clone() }),
        Action::Deny => Some(PrecomputedAction::Static {
            rcode: ResponseCode::Refused,
        }),
        _ => None,
    }
}

pub(crate) fn fast_static_match(
    pipeline: &CompiledPipeline,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    client_ip: IpAddr,
    edns_present: bool,
) -> Option<Decision> {
    let candidates = pipeline.index.get_candidates(qname, qtype);
    for idx in candidates {
        let rule = pipeline.rules.get(idx)?;
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| compiled_matcher_matches(&m.matcher, qname, qtype, qclass, client_ip, edns_present),
        );
        if !matched {
            continue;
        }
        // 找到第一个匹配的规则
        // 如果它可预计算，使用快速路径；否则放弃快速路径以保持规则顺序
        if let Some(pre) = &rule.precomputed {
            match pre {
                PrecomputedAction::Static { rcode } => {
                    return Some(Decision::Static {
                        rcode: *rcode,
                        answers: Vec::new(),
                    });
                }
                PrecomputedAction::StaticIp { ip } => {
                    let (rcode, answers) = make_static_ip_answer(qname, ip);
                    return Some(Decision::Static { rcode, answers });
                }
            }
        } else {
            // 第一个匹配的规则不可预计算（如 Forward、Jump 等）
            // 放弃快速路径，让规则走正常路径以保持配置顺序
            // 这确保了像 "domain_regex → forward" 这样的规则不会被
            // 后面的 "domain_suffix → static_ip" 规则跳过
            return None;
        }
    }
    None
}

fn compiled_matcher_matches(
    matcher: &CompiledMatcher,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    client_ip: IpAddr,
    edns_present: bool,
) -> bool {
    match matcher {
        CompiledMatcher::DomainExact { domain } => qname.eq_ignore_ascii_case(domain),
        CompiledMatcher::DomainSuffix { suffix } => {
            if suffix.is_empty() {
                true
            } else {
                qname.ends_with(suffix)
            }
        }
        CompiledMatcher::ClientIp { net } => net.contains(&client_ip),
        CompiledMatcher::QueryType { qtype: rt } => *rt == qtype,
        CompiledMatcher::Qclass { qclass: cls } => *cls == qclass,
        CompiledMatcher::Regex { regex } => regex.is_match(qname),
        CompiledMatcher::Complex { matcher } => match matcher {
            RuntimeMatcher::Any => true,
            RuntimeMatcher::DomainExact { value } => qname.eq_ignore_ascii_case(value),
            RuntimeMatcher::DomainSuffix { value } => qname.ends_with(value),
            RuntimeMatcher::ClientIp { net } => net.contains(&client_ip),
            RuntimeMatcher::DomainRegex { regex } => regex.is_match(qname),
            RuntimeMatcher::GeoipCountry { country_codes: _ } => {
                // GeoIP matching requires GeoIpManager integration
                // For now, return false (will be implemented in Engine integration)
                false
            }
            RuntimeMatcher::GeoipPrivate { expect: _ } => {
                // GeoIP private IP detection requires GeoIpManager integration
                // For now, return false (will be implemented in Engine integration)
                false
            }
            RuntimeMatcher::Qclass { value } => *value == qclass,
            RuntimeMatcher::EdnsPresent { expect } => *expect == edns_present,
            RuntimeMatcher::GeoSite { tag: _ } => {
                // GeoSite matching requires GeoSiteManager integration
                // For now, return false (will be implemented in Engine integration)
                false
            }
            RuntimeMatcher::GeoSiteNot { tag: _ } => {
                // GeoSite negation matching requires GeoSiteManager integration
                // For now, return false (will be implemented in Engine integration)
                false
            }
            RuntimeMatcher::Qtype { value } => *value == qtype,
        },
    }
}

#[inline]
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
