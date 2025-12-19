use std::fs;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use ipnet::IpNet;
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineConfig {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub settings: GlobalSettings,
    /// 多维优先级的 pipeline 选择规则（按顺序评估）。 / Multi-dimensional priority pipeline selection rules (evaluated in order)
    #[serde(default)]
    pub pipeline_select: Vec<PipelineSelectRule>,
    #[serde(default)]
    pub pipelines: Vec<Pipeline>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalSettings {
    /// 最小TTL秒数，缺省0。 / Minimum TTL in seconds, defaults to 0
    #[serde(default = "default_min_ttl")]
    pub min_ttl: u32,
    /// UDP监听地址，缺省0.0.0.0:5353，避免1024以下端口权限问题。 / UDP listen address, defaults to 0.0.0.0:5353, avoiding port permission issues below 1024
    #[serde(default = "default_bind_udp")]
    pub bind_udp: String,
    /// TCP监听地址，缺省0.0.0.0:5353。 / TCP listen address, defaults to 0.0.0.0:5353
    #[serde(default = "default_bind_tcp")]
    pub bind_tcp: String,
    /// Moka 缓存最大条目数（默认 10000） / Moka cache max entries (default 10000)
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: u64,
    /// 默认上游DNS。 / Default upstream DNS
    #[serde(default = "default_upstream")]
    pub default_upstream: String,
    /// 上游超时（毫秒）。 / Upstream timeout (milliseconds)
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    /// 响应阶段 Pipeline 跳转上限。 / Response phase pipeline jump limit
    #[serde(default = "default_response_jump_limit")]
    pub response_jump_limit: u32,
    /// UDP 上游连接池大小。 / UDP upstream connection pool size
    #[serde(default = "default_udp_pool_size")]
    pub udp_pool_size: usize,
    /// TCP 上游连接池大小。 / TCP upstream connection pool size
    #[serde(default = "default_tcp_pool_size")]
    pub tcp_pool_size: usize,
    /// 自适应流控初始 permits 数量。 / Initial permits for adaptive flow control
    #[serde(default = "default_flow_control_initial_permits")]
    pub flow_control_initial_permits: usize,
    /// 自适应流控最小 permits 数量。 / Minimum permits for adaptive flow control
    #[serde(default = "default_flow_control_min_permits")]
    pub flow_control_min_permits: usize,
    /// 自适应流控最大 permits 数量。 / Maximum permits for adaptive flow control
    #[serde(default = "default_flow_control_max_permits")]
    pub flow_control_max_permits: usize,
    /// 上游延迟告急阈值（毫秒）。 / Critical latency threshold (milliseconds)
    #[serde(default = "default_flow_control_latency_threshold_ms")]
    pub flow_control_latency_threshold_ms: u64,
    /// 流控调整间隔（秒）。 / Flow control adjustment interval (seconds)
    #[serde(default = "default_flow_control_adjustment_interval_secs")]
    pub flow_control_adjustment_interval_secs: u64,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            min_ttl: default_min_ttl(),
            bind_udp: default_bind_udp(),
            bind_tcp: default_bind_tcp(),
            default_upstream: default_upstream(),
            upstream_timeout_ms: default_upstream_timeout_ms(),
            response_jump_limit: default_response_jump_limit(),
            udp_pool_size: default_udp_pool_size(),
            tcp_pool_size: default_tcp_pool_size(),
            flow_control_initial_permits: default_flow_control_initial_permits(),
            flow_control_min_permits: default_flow_control_min_permits(),
            flow_control_max_permits: default_flow_control_max_permits(),
            flow_control_latency_threshold_ms: default_flow_control_latency_threshold_ms(),
            flow_control_adjustment_interval_secs: default_flow_control_adjustment_interval_secs(),
            cache_capacity: default_cache_capacity(),
        }
    }

}

fn default_cache_capacity() -> u64 {
    10_000
}

#[derive(Debug, Clone, Deserialize)]
pub struct Pipeline {
    pub id: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub matchers: Vec<MatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub matcher_operator: MatchOperator,
    #[serde(default)]
    pub actions: Vec<Action>,
    /// 响应阶段匹配器，可根据上游、响应类型、rcode等进行判断。 / Response phase matchers, can determine based on upstream, response type, rcode, etc.
    #[serde(default)]
    pub response_matchers: Vec<ResponseMatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub response_matcher_operator: MatchOperator,
    /// 响应匹配成功后执行的动作序列。 / Action sequence to execute after successful response matching
    #[serde(default)]
    pub response_actions_on_match: Vec<Action>,
    /// 响应匹配失败后执行的动作序列。 / Action sequence to execute after failed response matching
    #[serde(default)]
    pub response_actions_on_miss: Vec<Action>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Matcher {
    Any,
    /// 匹配域名后缀，大小写不敏感。 / Match domain suffix, case insensitive
    DomainSuffix {
        value: String,
    },
    /// 域名正则匹配（Rust 正则语法，默认大小写不敏感请自行使用 (?i)）。 / Domain regex matching (Rust regex syntax, use (?i) for case insensitivity by default)
    DomainRegex {
        value: String,
    },
    /// 匹配客户端IP的CIDR。 / Match client IP CIDR
    ClientIp {
        cidr: String,
    },
    /// 匹配查询 QCLASS（如 IN/CH/HS）。 / Match query QCLASS (e.g., IN/CH/HS)
    Qclass {
        value: String,
    },
    /// 是否存在 EDNS 伪记录。 / Whether EDNS pseudo-record exists
    EdnsPresent {
        expect: bool,
    },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PipelineSelectorMatcher {
    /// 入口标签匹配（来自启动参数 listener_label）。 / Entry label matching (from listener_label startup parameter)
    ListenerLabel { value: String },
    /// 客户端IP CIDR。 / Client IP CIDR
    ClientIp { cidr: String },
    /// 请求域名后缀。 / Request domain suffix
    DomainSuffix { value: String },
    /// 请求域名正则。 / Request domain regex
    DomainRegex { value: String },
    /// 任意请求（总是匹配）。 / Any request (always matches)
    Any,
    /// 请求 QCLASS（如 IN/CH/HS）。 / Request QCLASS (e.g., IN/CH/HS)
    Qclass { value: String },
    /// 请求是否携带 EDNS。 / Whether request carries EDNS
    EdnsPresent { expect: bool },
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineSelectRule {
    pub pipeline: String,
    #[serde(default)]
    pub matchers: Vec<PipelineSelectorMatcherWithOp>,
    #[serde(default = "default_match_operator")]
    pub matcher_operator: MatchOperator,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: Matcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PipelineSelectorMatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: PipelineSelectorMatcher,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMatcherWithOp {
    #[serde(default = "default_match_operator")]
    pub operator: MatchOperator,
    #[serde(flatten)]
    pub matcher: ResponseMatcher,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseMatcher {
    /// 匹配使用的上游（字符串相等）。 / Match the upstream used (string equality)
    UpstreamEquals { value: String },
    /// 复用请求域名后缀匹配（便于上游+域名组合策略）。 / Reuse request domain suffix matching (convenient for upstream+domain combination strategy)
    RequestDomainSuffix { value: String },
    /// 请求域名正则匹配。 / Request domain regex matching
    RequestDomainRegex { value: String },
    /// 匹配响应所来自的上游 IP（支持 CIDR）。 / Match the upstream IP from which the response originated (supports CIDR)
    ResponseUpstreamIp { cidr: String },
    /// 匹配响应 Answer 中的 IP 地址（A/AAAA 记录，支持 CIDR）。 / Match IP addresses in response Answer (A/AAAA records, supports CIDR)
    ResponseAnswerIp { cidr: String },
    /// 匹配响应记录类型（如 A/AAAA/CNAME/TXT/MX 等）。 / Match response record type (e.g., A/AAAA/CNAME/TXT/MX, etc.)
    ResponseType { value: String },
    /// 匹配响应的RCode（如 NOERROR/NXDOMAIN/SERVFAIL）。 / Match response RCode (e.g., NOERROR/NXDOMAIN/SERVFAIL)
    ResponseRcode { value: String },
    /// 匹配请求 QCLASS（如 IN/CH/HS）。 / Match request QCLASS (e.g., IN/CH/HS)
    ResponseQclass { value: String },
    /// 响应是否携带 EDNS。 / Whether response carries EDNS
    ResponseEdnsPresent { expect: bool },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// 记录日志，level可选：trace/debug/info/warn/error / Log action, level options: trace/debug/info/warn/error
    Log { level: Option<String> },
    /// 固定响应rcode（如 NXDOMAIN/NOERROR）。 / Static response rcode (e.g., NXDOMAIN/NOERROR)
    StaticResponse { rcode: String },
    /// 返回固定 IP (A/AAAA)。 / Return static IP (A/AAAA)
    StaticIpResponse { ip: String },
    /// 跳转到指定 Pipeline 继续处理。 / Jump to specified Pipeline to continue processing
    JumpToPipeline { pipeline: String },
    /// 终止匹配。请求阶段使用默认上游，响应阶段使用当前响应。 / Terminate matching. Request phase uses default upstream, response phase uses current response
    Allow,
    /// 终止并丢弃（返回 REFUSED）。 / Terminate and drop (return REFUSED)
    Deny,
    /// 透传上游；upstream为空则使用全局默认；transport缺省udp。 / Forward to upstream; use global default if upstream is empty; transport defaults to udp
    Forward {
        upstream: Option<String>,
        #[serde(default)]
        transport: Option<Transport>,
    },
    /// 继续匹配后续规则。响应阶段会复用当前响应结果。 / Continue matching subsequent rules. Response phase will reuse current response result
    Continue,
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchOperator {
    And,
    Or,
    #[serde(alias = "not", alias = "and_not", alias = "and-not", alias = "andnot")]
    AndNot,
    #[serde(alias = "or_not", alias = "or-not", alias = "ornot")]
    OrNot,
    /// Backward compatibility placeholder (not constructed) / 向后兼容占位符（不构造）
    #[serde(skip)]
    #[allow(dead_code)]
    Not,
}

fn default_match_operator() -> MatchOperator {
    MatchOperator::And
}

pub fn load_config(path: &Path) -> Result<PipelineConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read config file: {}", path.display()))?;
    let mut cfg: PipelineConfig = serde_json::from_str(&raw)
        .with_context(|| format!("parse config file: {}", path.display()))?;

    if let Some(version) = cfg.version.as_ref() {
        info!(target = "config", version = %version, "config loaded");
    }

    // 轻量校验：CIDR提前解析，便于后续快速匹配。 / Lightweight validation: parse CIDR in advance for subsequent fast matching
    for pipeline in &mut cfg.pipelines {
        for rule in &mut pipeline.rules {
            for matcher in &rule.matchers {
                if let Matcher::ClientIp { cidr } = &matcher.matcher {
                    let _parsed: IpNet = cidr.parse()?;
                }
            }
            for matcher in &rule.response_matchers {
                if let ResponseMatcher::RequestDomainSuffix { value } = &matcher.matcher {
                    if value.is_empty() {
                        anyhow::bail!("response_matcher request_domain_suffix empty");
                    }
                }
                if let ResponseMatcher::ResponseUpstreamIp { cidr } = &matcher.matcher {
                    for part in cidr.split(',') {
                        let s = part.trim();
                        if !s.is_empty() {
                            let _parsed: IpNet = s.parse()?;
                        }
                    }
                }
                if let ResponseMatcher::ResponseAnswerIp { cidr } = &matcher.matcher {
                    for part in cidr.split(',') {
                        let s = part.trim();
                        if !s.is_empty() {
                            let _parsed: IpNet = s.parse()?;
                        }
                    }
                }
            }
        }
    }

    for sel in &cfg.pipeline_select {
        for m in &sel.matchers {
            if let PipelineSelectorMatcher::ClientIp { cidr } = &m.matcher {
                let _parsed: IpNet = cidr.parse()?;
            }
        }
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_action_fields_default_to_empty() {
        let raw = json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "rule",
                            "actions": [ { "type": "log", "level": "info" } ]
                        }
                    ]
                }
            ]
        });
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let rule = &cfg.pipelines[0].rules[0];
        assert!(rule.response_actions_on_match.is_empty());
        assert!(rule.response_actions_on_miss.is_empty());
    }

    #[test]
    fn rule_operator_defaults_to_and_when_omitted() {
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "rule",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "log", "level": "info" } ]
                        }
                    ]
                }
            ]
        });

        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let rule = &cfg.pipelines[0].rules[0];
        // default should be MatchOperator::And / 默认应为 MatchOperator::And
        assert_eq!(rule.matcher_operator, MatchOperator::And);
        assert_eq!(rule.response_matcher_operator, MatchOperator::And);
    }

    #[test]
    fn flow_control_settings_default_when_omitted() {
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": []
                }
            ]
        });

        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        // Verify flow control settings have correct defaults
        assert_eq!(cfg.settings.flow_control_initial_permits, 500);
        assert_eq!(cfg.settings.flow_control_min_permits, 100);
        assert_eq!(cfg.settings.flow_control_max_permits, 800);
        assert_eq!(cfg.settings.flow_control_latency_threshold_ms, 100);
        assert_eq!(cfg.settings.flow_control_adjustment_interval_secs, 5);
    }

    #[test]
    fn flow_control_settings_can_be_customized() {
        let raw = serde_json::json!({
            "settings": {
                "flow_control_initial_permits": 200,
                "flow_control_min_permits": 50,
                "flow_control_max_permits": 400,
                "flow_control_latency_threshold_ms": 150,
                "flow_control_adjustment_interval_secs": 10
            },
            "pipelines": [
                {
                    "id": "p1",
                    "rules": []
                }
            ]
        });

        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        // Verify custom flow control settings
        assert_eq!(cfg.settings.flow_control_initial_permits, 200);
        assert_eq!(cfg.settings.flow_control_min_permits, 50);
        assert_eq!(cfg.settings.flow_control_max_permits, 400);
        assert_eq!(cfg.settings.flow_control_latency_threshold_ms, 150);
        assert_eq!(cfg.settings.flow_control_adjustment_interval_secs, 10);
    }
}

fn default_min_ttl() -> u32 {
    0
}

fn default_bind_udp() -> String {
    "0.0.0.0:5353".to_string()
}

fn default_bind_tcp() -> String {
    "0.0.0.0:5353".to_string()
}

fn default_upstream() -> String {
    "1.1.1.1:53".to_string()
}

fn default_upstream_timeout_ms() -> u64 {
    2000
}

fn default_response_jump_limit() -> u32 {
    10
}

fn default_udp_pool_size() -> usize {
    64
}

fn default_tcp_pool_size() -> usize {
    64
}

fn default_flow_control_initial_permits() -> usize {
    500
}

fn default_flow_control_min_permits() -> usize {
    100
}

fn default_flow_control_max_permits() -> usize {
    800
}

fn default_flow_control_latency_threshold_ms() -> u64 {
    100
}

fn default_flow_control_adjustment_interval_secs() -> u64 {
    5
}
