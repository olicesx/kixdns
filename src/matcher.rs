use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, RecordType};
use ipnet::IpNet;
use regex::Regex;

use crate::config::{self, Action, MatchOperator, PipelineConfig};

#[derive(Debug, Clone)]
pub struct RuntimePipelineConfig {
    pub settings: config::GlobalSettings,
    pub pipeline_select: Vec<RuntimePipelineSelectRule>,
    pub pipelines: Vec<RuntimePipeline>,
}

#[derive(Debug, Clone)]
pub struct RuntimePipeline {
    pub id: String,
    pub rules: Vec<RuntimeRule>,
    // Indices for O(1) lookup
    // Maps domain suffix -> list of rule indices that MUST be checked
    pub domain_suffix_index: HashMap<String, Vec<usize>>,
    // Rules that are NOT indexed by domain (must always be checked)
    pub always_check_rules: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct RuntimeRule {
    pub name: String,
    #[allow(dead_code)]
    pub matcher_operator: MatchOperator,
    pub matchers: Vec<RuntimeMatcherWithOp>,
    pub actions: Vec<Action>,
    pub response_matchers: Vec<RuntimeResponseMatcherWithOp>,
    pub response_matcher_operator: MatchOperator,
    pub response_actions_on_match: Vec<Action>,
    pub response_actions_on_miss: Vec<Action>,
}

#[derive(Debug, Clone)]
pub struct RuntimePipelineSelectRule {
    pub pipeline: String,
    pub matchers: Vec<RuntimePipelineSelectorMatcherWithOp>,
    #[allow(dead_code)]
    pub matcher_operator: MatchOperator,
}

#[derive(Debug, Clone)]
pub enum RuntimeMatcher {
    Any,
    DomainSuffix { value: String },
    ClientIp { net: IpNet },
    DomainRegex { regex: Regex },
    Qclass { value: DNSClass },
    EdnsPresent { expect: bool },
}

#[derive(Debug, Clone)]
pub struct RuntimeMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: RuntimeMatcher,
}

#[derive(Debug, Clone)]
pub enum RuntimePipelineSelectorMatcher {
    ListenerLabel { value: String },
    ClientIp { net: IpNet },
    DomainSuffix { value: String },
    DomainRegex { regex: Regex },
    Any,
    Qclass { value: DNSClass },
    EdnsPresent { expect: bool },
}

#[derive(Debug, Clone)]
pub struct RuntimePipelineSelectorMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: RuntimePipelineSelectorMatcher,
}

#[derive(Debug, Clone)]
pub enum RuntimeResponseMatcher {
    UpstreamEquals {
        value: String,
    },
    RequestDomainSuffix {
        value: String,
    },
    RequestDomainRegex {
        regex: Regex,
    },
    ResponseUpstreamIp {
        nets: Vec<IpNet>,
    },
    /// 匹配 Answer 中任意 A/AAAA 记录的 IP / Match IPs of any A/AAAA records in the Answer
    ResponseAnswerIp {
        nets: Vec<IpNet>,
    },
    ResponseType {
        value: String,
    },
    ResponseRcode {
        value: String,
    },
    ResponseQclass {
        value: DNSClass,
    },
    ResponseEdnsPresent {
        expect: bool,
    },
}

#[derive(Debug, Clone)]
pub struct RuntimeResponseMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: RuntimeResponseMatcher,
}

impl RuntimePipelineConfig {
    pub fn from_config(cfg: PipelineConfig) -> anyhow::Result<Self> {
        let mut pipelines = Vec::new();
        for p in cfg.pipelines {
            let mut rules = Vec::new();
            for r in p.rules {
                let mut matchers = Vec::new();
                let mut matchers_all_default = true;
                for m in r.matchers {
                    if m.operator != MatchOperator::And {
                        matchers_all_default = false;
                    }
                    matchers.push(RuntimeMatcherWithOp {
                        operator: m.operator,
                        matcher: RuntimeMatcher::from_config(m.matcher)?,
                    });
                }
                if matchers_all_default
                    && !matchers.is_empty()
                    && r.matcher_operator != MatchOperator::And
                {
                    for m in &mut matchers {
                        m.operator = r.matcher_operator;
                    }
                }

                let mut response_matchers = Vec::new();
                let mut resp_all_default = true;
                for rm in r.response_matchers {
                    if rm.operator != MatchOperator::And {
                        resp_all_default = false;
                    }
                    response_matchers.push(RuntimeResponseMatcherWithOp {
                        operator: rm.operator,
                        matcher: RuntimeResponseMatcher::from_config(rm.matcher)?,
                    });
                }
                if resp_all_default
                    && !response_matchers.is_empty()
                    && r.response_matcher_operator != MatchOperator::And
                {
                    for rm in &mut response_matchers {
                        rm.operator = r.response_matcher_operator;
                    }
                }
                rules.push(RuntimeRule {
                    name: r.name,
                    matcher_operator: r.matcher_operator,
                    matchers,
                    actions: r.actions,
                    response_matchers,
                    response_matcher_operator: r.response_matcher_operator,
                    response_actions_on_match: r.response_actions_on_match,
                    response_actions_on_miss: r.response_actions_on_miss,
                });
            }

            // Build Indices
            let mut domain_suffix_index: HashMap<String, Vec<usize>> = HashMap::new();
            let mut always_check_rules = Vec::new();

            for (idx, rule) in rules.iter().enumerate() {
                let mut indexed = false;
                // Check if rule has a DomainSuffix matcher
                // If it has multiple matchers, we can still index it if it's an AND chain containing DomainSuffix.
                // If it's OR, we can only index if ALL branches are indexable (complex).
                // For simplicity/safety: Only index if we find a DomainSuffix and operator is AND.
                // If operator is OR, we must put it in always_check unless we index all parts.

                if rule.matcher_operator == MatchOperator::And {
                    for m in &rule.matchers {
                        if let RuntimeMatcher::DomainSuffix { value } = &m.matcher {
                            domain_suffix_index
                                .entry(value.clone())
                                .or_default()
                                .push(idx);
                            indexed = true;
                            // We can stop looking for other matchers to index for this rule?
                            // Actually, if we index it under "example.com", we only check it if domain ends in "example.com".
                            // This is correct for AND.
                            break;
                        }
                    }
                }

                if !indexed {
                    always_check_rules.push(idx);
                }
            }

            pipelines.push(RuntimePipeline {
                id: p.id,
                rules,
                domain_suffix_index,
                always_check_rules,
            });
        }

        let mut pipeline_select = Vec::new();
        for s in cfg.pipeline_select {
            let mut matchers = Vec::new();
            let mut all_default = true;
            for m in s.matchers {
                if m.operator != MatchOperator::And {
                    all_default = false;
                }
                matchers.push(RuntimePipelineSelectorMatcherWithOp {
                    operator: m.operator,
                    matcher: RuntimePipelineSelectorMatcher::from_config(m.matcher)?,
                });
            }
            if all_default && !matchers.is_empty() && s.matcher_operator != MatchOperator::And {
                for m in &mut matchers {
                    m.operator = s.matcher_operator;
                }
            }
            pipeline_select.push(RuntimePipelineSelectRule {
                pipeline: s.pipeline,
                matchers,
                matcher_operator: s.matcher_operator,
            });
        }

        Ok(Self {
            settings: cfg.settings,
            pipeline_select,
            pipelines,
        })
    }

    pub fn min_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.settings.min_ttl as u64)
    }

    pub fn upstream_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.settings.upstream_timeout_ms)
    }
}

impl RuntimeMatcher {
    fn from_config(m: config::Matcher) -> anyhow::Result<Self> {
        Ok(match m {
            config::Matcher::Any => RuntimeMatcher::Any,
            config::Matcher::DomainSuffix { value } => RuntimeMatcher::DomainSuffix {
                value: value.to_ascii_lowercase(),
            },
            config::Matcher::ClientIp { cidr } => RuntimeMatcher::ClientIp { net: cidr.parse()? },
            config::Matcher::DomainRegex { value } => RuntimeMatcher::DomainRegex {
                regex: Regex::new(&value)?,
            },
            config::Matcher::Qclass { value } => RuntimeMatcher::Qclass {
                value: parse_dns_class(&value)?,
            },
            config::Matcher::EdnsPresent { expect } => RuntimeMatcher::EdnsPresent { expect },
        })
    }

    #[inline]
    pub fn matches(
        &self,
        qname: &str,
        qclass: DNSClass,
        client_ip: IpAddr,
        edns_present: bool,
    ) -> bool {
        match self {
            RuntimeMatcher::Any => true,
            RuntimeMatcher::DomainSuffix { value } => qname.ends_with(value),
            RuntimeMatcher::ClientIp { net } => net.contains(&client_ip),
            RuntimeMatcher::DomainRegex { regex } => regex.is_match(qname),
            RuntimeMatcher::Qclass { value } => &qclass == value,
            RuntimeMatcher::EdnsPresent { expect } => *expect == edns_present,
        }
    }
}

impl RuntimePipelineSelectorMatcher {
    fn from_config(m: config::PipelineSelectorMatcher) -> anyhow::Result<Self> {
        Ok(match m {
            config::PipelineSelectorMatcher::ListenerLabel { value } => {
                RuntimePipelineSelectorMatcher::ListenerLabel { value }
            }
            config::PipelineSelectorMatcher::ClientIp { cidr } => {
                RuntimePipelineSelectorMatcher::ClientIp { net: cidr.parse()? }
            }
            config::PipelineSelectorMatcher::DomainSuffix { value } => {
                RuntimePipelineSelectorMatcher::DomainSuffix {
                    value: value.to_ascii_lowercase(),
                }
            }
            config::PipelineSelectorMatcher::DomainRegex { value } => {
                RuntimePipelineSelectorMatcher::DomainRegex {
                    regex: Regex::new(&value)?,
                }
            }
            config::PipelineSelectorMatcher::Any => RuntimePipelineSelectorMatcher::Any,
            config::PipelineSelectorMatcher::Qclass { value } => {
                RuntimePipelineSelectorMatcher::Qclass {
                    value: parse_dns_class(&value)?,
                }
            }
            config::PipelineSelectorMatcher::EdnsPresent { expect } => {
                RuntimePipelineSelectorMatcher::EdnsPresent { expect }
            }
        })
    }

    #[inline]
    pub fn matches(
        &self,
        listener_label: &str,
        client_ip: IpAddr,
        qname: &str,
        qclass: DNSClass,
        edns_present: bool,
    ) -> bool {
        match self {
            RuntimePipelineSelectorMatcher::ListenerLabel { value } => {
                value.eq_ignore_ascii_case(listener_label)
            }
            RuntimePipelineSelectorMatcher::ClientIp { net } => net.contains(&client_ip),
            RuntimePipelineSelectorMatcher::DomainSuffix { value } => qname.ends_with(value),
            RuntimePipelineSelectorMatcher::DomainRegex { regex } => regex.is_match(qname),
            RuntimePipelineSelectorMatcher::Any => true,
            RuntimePipelineSelectorMatcher::Qclass { value } => value == &qclass,
            RuntimePipelineSelectorMatcher::EdnsPresent { expect } => *expect == edns_present,
        }
    }
}

#[allow(dead_code)]
pub fn apply_match_operator(op: &MatchOperator, mut results: impl Iterator<Item = bool>) -> bool {
    match op {
        MatchOperator::And => results.all(|b| b),
        MatchOperator::Or => results.any(|b| b),
        MatchOperator::AndNot => !results.any(|b| b),
        MatchOperator::OrNot => !results.all(|b| b),
        MatchOperator::Not => !results.any(|b| b),
    }
}

/// Evaluate a left-to-right chain where each item carries its own operator. / 评估从左到右的链，其中每个项目都带有自己的运算符
/// The first item's result seeds the accumulator; empty chains default to true. / 第一个项目的结果作为累加器的种子；空链默认为 true
#[inline]
pub fn eval_match_chain<T>(
    entries: &[T],
    mut op_of: impl FnMut(&T) -> MatchOperator,
    mut pred: impl FnMut(&T) -> bool,
) -> bool {
    let mut iter = entries.iter();
    let Some(first) = iter.next() else {
        return true;
    };
    let mut acc = pred(first);
    for item in iter {
        let op = op_of(item);
        match op {
            MatchOperator::And => {
                if !acc {
                    continue;
                }
                acc = acc && pred(item);
            }
            MatchOperator::Or => {
                if acc {
                    continue;
                }
                acc = acc || pred(item);
            }
            MatchOperator::AndNot => {
                if !acc {
                    continue;
                }
                acc = acc && !pred(item);
            }
            MatchOperator::OrNot => {
                if acc {
                    continue;
                }
                acc = acc || !pred(item);
            }
            MatchOperator::Not => {
                if !acc {
                    continue;
                }
                acc = acc && !pred(item);
            }
        };
    }
    acc
}

fn try_parse_upstream_ip(upstream: &str) -> Option<IpAddr> {
    upstream
        .parse::<SocketAddr>()
        .ok()
        .map(|sa| sa.ip())
        .or_else(|| upstream.parse::<IpAddr>().ok())
}

impl RuntimeResponseMatcher {
    fn from_config(m: config::ResponseMatcher) -> anyhow::Result<Self> {
        Ok(match m {
            config::ResponseMatcher::UpstreamEquals { value } => {
                RuntimeResponseMatcher::UpstreamEquals { value }
            }
            config::ResponseMatcher::RequestDomainSuffix { value } => {
                RuntimeResponseMatcher::RequestDomainSuffix {
                    value: value.to_ascii_lowercase(),
                }
            }
            config::ResponseMatcher::RequestDomainRegex { value } => {
                RuntimeResponseMatcher::RequestDomainRegex {
                    regex: Regex::new(&value)?,
                }
            }
            config::ResponseMatcher::ResponseUpstreamIp { cidr } => {
                let mut nets = Vec::new();
                for part in cidr.split(',') {
                    let s = part.trim();
                    if s.is_empty() {
                        continue;
                    }
                    nets.push(s.parse()?);
                }
                RuntimeResponseMatcher::ResponseUpstreamIp { nets }
            }
            config::ResponseMatcher::ResponseAnswerIp { cidr } => {
                let mut nets = Vec::new();
                for part in cidr.split(',') {
                    let s = part.trim();
                    if s.is_empty() {
                        continue;
                    }
                    nets.push(s.parse()?);
                }
                RuntimeResponseMatcher::ResponseAnswerIp { nets }
            }
            config::ResponseMatcher::ResponseType { value } => {
                RuntimeResponseMatcher::ResponseType {
                    value: value.to_ascii_uppercase(),
                }
            }
            config::ResponseMatcher::ResponseRcode { value } => {
                RuntimeResponseMatcher::ResponseRcode {
                    value: value.to_ascii_uppercase(),
                }
            }
            config::ResponseMatcher::ResponseQclass { value } => {
                RuntimeResponseMatcher::ResponseQclass {
                    value: parse_dns_class(&value)?,
                }
            }
            config::ResponseMatcher::ResponseEdnsPresent { expect } => {
                RuntimeResponseMatcher::ResponseEdnsPresent { expect }
            }
        })
    }

    pub fn matches(
        &self,
        upstream: &str,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        msg: &Message,
    ) -> bool {
        match self {
            RuntimeResponseMatcher::UpstreamEquals { value } => upstream == value,
            RuntimeResponseMatcher::RequestDomainSuffix { value } => qname.ends_with(value),
            RuntimeResponseMatcher::RequestDomainRegex { regex } => regex.is_match(qname),
            RuntimeResponseMatcher::ResponseUpstreamIp { nets } => try_parse_upstream_ip(upstream)
                .map(|ip| nets.iter().any(|net| net.contains(&ip)))
                .unwrap_or(false),
            RuntimeResponseMatcher::ResponseAnswerIp { nets } => {
                // 检查 Answer 中的 A/AAAA 记录是否有任意 IP 匹配 CIDR
                use hickory_proto::rr::RData;
                let mut found = msg.answers().iter().any(|record| match record.data() {
                    Some(RData::A(a)) => nets
                        .iter()
                        .any(|net| net.contains(&std::net::IpAddr::V4(a.0))),
                    Some(RData::AAAA(aaaa)) => nets
                        .iter()
                        .any(|net| net.contains(&std::net::IpAddr::V6(aaaa.0))),
                    _ => false,
                });
                if !found {
                    found = msg.additionals().iter().any(|record| match record.data() {
                        Some(RData::A(a)) => nets
                            .iter()
                            .any(|net| net.contains(&std::net::IpAddr::V4(a.0))),
                        Some(RData::AAAA(aaaa)) => nets
                            .iter()
                            .any(|net| net.contains(&std::net::IpAddr::V6(aaaa.0))),
                        _ => false,
                    });
                }
                found
            }
            RuntimeResponseMatcher::ResponseType { value } => {
                let rrty = msg
                    .answers()
                    .first()
                    .map(|r| r.record_type())
                    .unwrap_or(qtype);
                format!("{}", rrty) == *value
            }
            RuntimeResponseMatcher::ResponseRcode { value } => {
                let code_str = match msg.response_code() {
                    hickory_proto::op::ResponseCode::NoError => "NOERROR",
                    hickory_proto::op::ResponseCode::FormErr => "FORMERR",
                    hickory_proto::op::ResponseCode::ServFail => "SERVFAIL",
                    hickory_proto::op::ResponseCode::NXDomain => "NXDOMAIN",
                    hickory_proto::op::ResponseCode::NotImp => "NOTIMP",
                    hickory_proto::op::ResponseCode::Refused => "REFUSED",
                    _ => "OTHER",
                };
                code_str == *value
            }
            RuntimeResponseMatcher::ResponseQclass { value } => value == &qclass,
            RuntimeResponseMatcher::ResponseEdnsPresent { expect } => {
                let edns = msg.extensions().is_some();
                edns == *expect
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, ResponseCode};
    use hickory_proto::rr::Name;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{RData, Record};
    use regex::Regex;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    fn build_message(rcode: ResponseCode, edns_present: bool) -> Message {
        let mut msg = Message::new();
        msg.set_response_code(rcode);
        if edns_present {
            msg.set_edns(Edns::new());
        }
        let name = Name::from_str("example.com").unwrap();
        let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        msg.add_answer(record);
        msg
    }

    fn build_message_with_ipv6(rcode: ResponseCode, edns_present: bool) -> Message {
        let mut msg = Message::new();
        msg.set_response_code(rcode);
        if edns_present {
            msg.set_edns(Edns::new());
        }
        let name = Name::from_str("example.com").unwrap();
        let record = Record::from_rdata(
            name,
            300,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        );
        msg.add_answer(record);
        msg
    }

    #[test]
    fn runtime_response_matchers_cover_readme_cases() {
        let qname = "sub.example.com";
        let upstream = "1.1.1.1:53".to_string();
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let msg = build_message(ResponseCode::NoError, true);

        assert!(
            RuntimeResponseMatcher::UpstreamEquals {
                value: upstream.clone()
            }
            .matches(&upstream, qname, qtype, qclass, &msg)
        );
        assert!(
            RuntimeResponseMatcher::RequestDomainSuffix {
                value: "example.com".into()
            }
            .matches(&upstream, qname, qtype, qclass, &msg)
        );
        assert!(
            RuntimeResponseMatcher::RequestDomainRegex {
                regex: Regex::new(".*example\\.com$").unwrap()
            }
            .matches(&upstream, qname, qtype, qclass, &msg)
        );
        assert!(
            RuntimeResponseMatcher::ResponseType { value: "A".into() }
                .matches(&upstream, qname, qtype, qclass, &msg)
        );
        assert!(
            RuntimeResponseMatcher::ResponseRcode {
                value: "NOERROR".into()
            }
            .matches(&upstream, qname, qtype, qclass, &msg)
        );
        assert!(
            RuntimeResponseMatcher::ResponseQclass {
                value: DNSClass::IN
            }
            .matches(&upstream, qname, qtype, qclass, &msg)
        );
        assert!(
            RuntimeResponseMatcher::ResponseEdnsPresent { expect: true }
                .matches(&upstream, qname, qtype, qclass, &msg)
        );
        assert!(
            RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.1.1.0/24".parse().unwrap()],
            }
            .matches(&upstream, qname, qtype, qclass, &msg)
        );

        let msg_no_edns = build_message(ResponseCode::NXDomain, false);
        assert!(
            RuntimeResponseMatcher::ResponseEdnsPresent { expect: false }.matches(
                &upstream,
                qname,
                qtype,
                qclass,
                &msg_no_edns
            )
        );

        let msg_ipv6 = build_message_with_ipv6(ResponseCode::NoError, true);
        assert!(
            RuntimeResponseMatcher::ResponseType {
                value: "AAAA".into()
            }
            .matches(&upstream, qname, RecordType::AAAA, qclass, &msg_ipv6)
        );
    }

    #[test]
    fn apply_match_operator_request_matchers() {
        use std::net::IpAddr;
        let qname = "a.sub.example.com";
        let client_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let qclass = DNSClass::IN;

        let m_and_true = vec![
            RuntimeMatcher::DomainSuffix {
                value: "example.com".into(),
            },
            RuntimeMatcher::Qclass {
                value: DNSClass::IN,
            },
        ];
        let res_and = m_and_true
            .iter()
            .map(|m| m.matches(qname, qclass, client_ip, true));
        assert!(apply_match_operator(&MatchOperator::And, res_and));

        let m_and_false = vec![
            RuntimeMatcher::DomainSuffix {
                value: "example.com".into(),
            },
            RuntimeMatcher::Qclass {
                value: DNSClass::CH,
            },
        ];
        let res_and_false = m_and_false
            .iter()
            .map(|m| m.matches(qname, qclass, client_ip, true));
        assert!(!apply_match_operator(&MatchOperator::And, res_and_false));

        let m_or = vec![
            RuntimeMatcher::DomainSuffix {
                value: "nomatch.local".into(),
            },
            RuntimeMatcher::Qclass {
                value: DNSClass::IN,
            },
        ];
        let res_or = m_or
            .iter()
            .map(|m| m.matches(qname, qclass, client_ip, true));
        assert!(apply_match_operator(&MatchOperator::Or, res_or));

        let m_not_all_false = vec![
            RuntimeMatcher::DomainSuffix {
                value: "nomatch.local".into(),
            },
            RuntimeMatcher::Qclass {
                value: DNSClass::CH,
            },
        ];
        let res_not = m_not_all_false
            .iter()
            .map(|m| m.matches(qname, qclass, client_ip, true));
        // none match -> NOT should be true
        assert!(apply_match_operator(&MatchOperator::Not, res_not));

        let m_not_one_true = vec![
            RuntimeMatcher::DomainSuffix {
                value: "example.com".into(),
            },
            RuntimeMatcher::Qclass {
                value: DNSClass::CH,
            },
        ];
        let res_not_false = m_not_one_true
            .iter()
            .map(|m| m.matches(qname, qclass, client_ip, true));
        // one matches -> NOT should be false
        assert!(!apply_match_operator(&MatchOperator::Not, res_not_false));
    }

    #[test]
    fn apply_match_operator_response_matchers() {
        let qname = "sub.example.com";
        let upstream = "9.9.9.9:53".to_string();
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let msg = build_message(ResponseCode::NoError, true);

        let rm_and_true = vec![
            RuntimeResponseMatcher::UpstreamEquals {
                value: upstream.clone(),
            },
            RuntimeResponseMatcher::RequestDomainSuffix {
                value: "example.com".into(),
            },
        ];
        let res_and = rm_and_true
            .iter()
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg));
        assert!(apply_match_operator(&MatchOperator::And, res_and));

        let rm_or = vec![
            RuntimeResponseMatcher::UpstreamEquals {
                value: "nope:53".into(),
            },
            RuntimeResponseMatcher::RequestDomainSuffix {
                value: "example.com".into(),
            },
        ];
        let res_or = rm_or
            .iter()
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg));
        assert!(apply_match_operator(&MatchOperator::Or, res_or));

        let rm_not_all_false = vec![
            RuntimeResponseMatcher::UpstreamEquals {
                value: "nope:53".into(),
            },
            RuntimeResponseMatcher::RequestDomainSuffix {
                value: "nomatch.local".into(),
            },
        ];
        let res_not = rm_not_all_false
            .iter()
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg));
        assert!(apply_match_operator(&MatchOperator::Not, res_not));

        let rm_not_one_true = vec![
            RuntimeResponseMatcher::UpstreamEquals {
                value: upstream.clone(),
            },
            RuntimeResponseMatcher::RequestDomainSuffix {
                value: "nomatch.local".into(),
            },
        ];
        let res_not_false = rm_not_one_true
            .iter()
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg));
        assert!(!apply_match_operator(&MatchOperator::Not, res_not_false));
    }

    #[test]
    fn apply_match_operator_empty_iterator_boundary() {
        let empty: Vec<bool> = vec![];
        let it = empty.into_iter();
        // And over empty iterator -> true (all true)
        assert!(apply_match_operator(&MatchOperator::And, it.clone()));

        let it2 = std::iter::empty::<bool>();
        // Or over empty iterator -> false (any false)
        assert!(!apply_match_operator(&MatchOperator::Or, it2));

        let it3 = std::iter::empty::<bool>();
        // Not over empty iterator -> true (!any(empty) == true)
        assert!(apply_match_operator(&MatchOperator::Not, it3));
    }

    #[test]
    fn runtime_pipeline_selector_matchers() {
        use std::net::IpAddr;
        let listener_label = "edge-internal";
        let client_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));
        let qname = "svc.example.com";

        assert!(
            RuntimePipelineSelectorMatcher::ListenerLabel {
                value: "edge-internal".into()
            }
            .matches(listener_label, client_ip, qname, DNSClass::IN, false)
        );

        assert!(
            RuntimePipelineSelectorMatcher::ClientIp {
                net: "10.1.2.0/24".parse().unwrap()
            }
            .matches(listener_label, client_ip, qname, DNSClass::IN, false)
        );

        assert!(
            RuntimePipelineSelectorMatcher::DomainSuffix {
                value: "example.com".into()
            }
            .matches(listener_label, client_ip, qname, DNSClass::IN, false)
        );
    }

    #[test]
    fn runtime_matcher_basic_behaviors() {
        use std::net::IpAddr;
        let qname = "Foo.Example.COM".to_ascii_lowercase();
        let client_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 5));
        let qclass = DNSClass::IN;

        // Any always matches
        assert!(RuntimeMatcher::Any.matches(&qname, qclass, client_ip, false));

        // DomainSuffix should match when suffix equals
        assert!(
            RuntimeMatcher::DomainSuffix {
                value: "example.com".into()
            }
            .matches(&qname, qclass, client_ip, false)
        );

        // ClientIp CIDR
        assert!(
            RuntimeMatcher::ClientIp {
                net: "192.0.2.0/24".parse().unwrap()
            }
            .matches(&qname, qclass, client_ip, false)
        );

        // Qclass
        assert!(
            RuntimeMatcher::Qclass {
                value: DNSClass::IN
            }
            .matches(&qname, qclass, client_ip, false)
        );

        // EdnsPresent
        assert!(
            RuntimeMatcher::EdnsPresent { expect: false }.matches(&qname, qclass, client_ip, false)
        );
    }

    #[test]
    fn response_upstream_ip_parsing_and_nonparseable() {
        let qname = "sub.example.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let msg = build_message(ResponseCode::NoError, false);

        // With port
        assert!(
            RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.2.3.0/24".parse().unwrap()]
            }
            .matches("1.2.3.4:53", qname, qtype, qclass, &msg)
        );

        // Plain ip
        assert!(
            RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.2.3.0/24".parse().unwrap()]
            }
            .matches("1.2.3.4", qname, qtype, qclass, &msg)
        );

        // Non-parseable upstream should return false
        assert!(
            !RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.2.3.0/24".parse().unwrap()]
            }
            .matches("not-an-upstream", qname, qtype, qclass, &msg)
        );
    }

    #[test]
    fn domain_regex_case_insensitive_flag() {
        let qname = "Foo.Example.COM";
        // Without (?i) should not match assuming case-sensitive regex
        let re_cs = Regex::new("example\\.com$").unwrap();
        assert!(!RuntimeMatcher::DomainRegex { regex: re_cs }.matches(
            &qname,
            DNSClass::IN,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            false
        ));

        // With (?i) should match
        let re_ci = Regex::new("(?i)example\\.com$").unwrap();
        assert!(RuntimeMatcher::DomainRegex { regex: re_ci }.matches(
            &qname,
            DNSClass::IN,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            false
        ));
    }

    #[test]
    fn response_type_no_answers_uses_qtype_fallback() {
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NoError);
        // no answers added

        let qname = "x.example.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;

        assert!(
            RuntimeResponseMatcher::ResponseType { value: "A".into() }.matches(
                "1.2.3.4:53",
                qname,
                qtype,
                qclass,
                &msg
            )
        );
    }
}

fn parse_dns_class(v: &str) -> anyhow::Result<DNSClass> {
    let upper = v.to_ascii_uppercase();
    let parsed = match upper.as_str() {
        "IN" => DNSClass::IN,
        "CH" | "CHAOS" => DNSClass::CH,
        "HS" => DNSClass::HS,
        _ => anyhow::bail!("unsupported qclass: {upper}"),
    };
    Ok(parsed)
}
