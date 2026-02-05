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
    /// 多维优先级的 pipeline 选择规则（按顺序评估）。 / Multi-dimensional priority selection rules (evaluated in order)
    #[serde(default)]
    pub pipeline_select: Vec<PipelineSelectRule>,
    #[serde(default)]
    pub pipelines: Vec<Pipeline>,

    /// 后台刷新专用规则（可选）。如果未配置，将使用默认规则（Any 匹配 + Forward 到原始 upstream）。
    /// Background refresh dedicated rule (optional). If not configured, will use default rule (Any matcher + Forward to original upstream).
    ///
    /// # Purpose
    ///
    /// 为后台刷新提供独立的规则配置，允许自定义后台刷新的行为。
    /// Provide independent rule configuration for background refresh, allowing custom behavior.
    ///
    /// # Design Philosophy
    ///
    /// **后台刷新 = 调用 handle_packet(skip_cache=true)**
    ///
    /// 后台刷新本质上就是向规则引擎发起一个特殊的查询请求，
    /// 使用"后台刷新专用规则"，完全复用规则引擎的所有逻辑。
    ///
    /// **Background refresh = Call handle_packet(skip_cache=true)**
    ///
    /// 后台刷新与正常查询的唯一区别：
    /// - 正常查询：检查缓存 → 规则引擎 → 执行查询
    /// - 后台刷新：跳过缓存 → 规则引擎 → 执行查询
    ///
    /// # Example
    ///
    /// ```json
    /// {
    ///   "background_refresh_rule": {
    ///     "name": "后台刷新专用规则",
    ///     "matchers": [
    ///       {
    ///         "type": "any",
    ///         "operator": "and"
    ///       }
    ///     ],
    ///     "actions": [
    ///       {
    ///         "type": "forward",
    ///         "upstream": "8.8.8.8:53",  // 将在运行时替换为实际 upstream
    ///         "transport": "tcp"
    ///       }
    ///     ],
    ///     "response_matchers": [],
    ///     "response_matcher_operator": "and",
    ///     "response_actions_on_match": [],
    ///     "response_actions_on_miss": []
    ///   }
    /// }
    /// ```
    #[serde(default)]
    pub background_refresh_rule: Option<Rule>,
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
    /// Moka 缓存最大生存时间（秒，默认 86400） / Moka cache max TTL (seconds, default 86400)
    #[serde(default = "default_cache_max_ttl")]
    pub cache_max_ttl: u64,
    /// DashMap shard 数量（0=自动，默认 0）。更多 shards=更少锁竞争但更多内存开销 / DashMap shard count (0=auto, default 0). More shards=less lock contention but more memory overhead
    #[serde(default = "default_dashmap_shards")]
    pub dashmap_shards: usize,
    /// 默认上游DNS。 / Default upstream DNS
    #[serde(default = "default_upstream")]
    pub default_upstream: String,
    /// 预分割的默认上游列表（性能优化） / Pre-split default upstream list (performance optimization)
    #[serde(skip)]
    pub default_upstream_pre_split: Option<std::sync::Arc<Vec<std::sync::Arc<str>>>>,
    /// 上游超时（毫秒）。 / Upstream timeout (milliseconds)
    /// 单次上游请求的超时时间
    #[serde(default = "default_upstream_timeout_ms")]
    pub upstream_timeout_ms: u64,
    /// 整体请求超时（毫秒）。 / Overall request timeout (milliseconds)
    /// 包含 hedge + TCP fallback 的总超时时间。如果未设置，自动计算为 upstream_timeout_ms * 2.5
    /// Total timeout including hedge + TCP fallback. If not set, auto-calculated as upstream_timeout_ms * 2.5
    #[serde(default)]
    pub request_timeout_ms: Option<u64>,
    /// 响应阶段 Pipeline 跳转上限。 / Response phase pipeline jump limit
    #[serde(default = "default_response_jump_limit")]
    pub response_jump_limit: u32,
    /// UDP 上游连接池大小。 / UDP upstream connection pool size
    #[serde(default = "default_udp_pool_size")]
    pub udp_pool_size: usize,
    /// TCP 上游连接池大小。 / TCP upstream connection pool size
    #[serde(default = "default_tcp_pool_size")]
    pub tcp_pool_size: usize,
    /// TCP 健康检查错误阈值（连续失败多少次后重置连接） / TCP health check error threshold (reset connection after N consecutive failures)
    /// 默认 3 次，0 表示禁用健康检查 / Default 3, 0 means disable health check
    #[serde(default = "default_tcp_health_check_error_threshold")]
    pub tcp_health_check_error_threshold: usize,
    /// TCP 连接最大存活时间（秒，超过强制重置） / TCP connection max age (seconds, force reset after this time)
    /// 0 表示禁用连接老化检查 / 0 means disable connection aging check
    #[serde(default = "default_tcp_connection_max_age_seconds")]
    pub tcp_connection_max_age_seconds: u64,
    /// TCP 连接空闲超时（秒，无请求超过此时间重置） / TCP connection idle timeout (seconds, reset if no requests for this time)
    /// 0 表示禁用空闲超时检查 / 0 means disable idle timeout check
    #[serde(default = "default_tcp_connection_idle_timeout_seconds")]
    pub tcp_connection_idle_timeout_seconds: u64,
    /// 是否启用自适应流控（默认false，推荐禁用以获得更好的性能和更简单的行为）
    /// Enable adaptive flow control (default false, recommended disabled for better performance and simpler behavior)
    /// 
    /// 禁用后采用rustdns风格：不限制并发，依赖tokio runtime调度和超时保护
    /// When disabled, use rustdns style: no concurrency limit, rely on tokio runtime scheduling and timeout protection
    #[serde(default = "default_flow_control_enabled")]
    pub flow_control_enabled: bool,
    /// 自适应流控初始 permits 数量（仅在flow_control_enabled=true时有效） / Initial permits for adaptive flow control (only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_initial_permits")]
    pub flow_control_initial_permits: usize,
    /// 自适应流控最小 permits 数量（仅在flow_control_enabled=true时有效） / Minimum permits for adaptive flow control (only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_min_permits")]
    pub flow_control_min_permits: usize,
    /// 自适应流控最大 permits 数量（仅在flow_control_enabled=true时有效） / Maximum permits for adaptive flow control (only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_max_permits")]
    pub flow_control_max_permits: usize,
    /// 上游延迟告急阈值（毫秒，仅在flow_control_enabled=true时有效） / Critical latency threshold (milliseconds, only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_latency_threshold_ms")]
    pub flow_control_latency_threshold_ms: u64,
    /// 流控调整间隔（秒，仅在flow_control_enabled=true时有效） / Flow control adjustment interval (seconds, only effective when flow_control_enabled=true)
    #[serde(default = "default_flow_control_adjustment_interval_secs")]
    pub flow_control_adjustment_interval_secs: u64,
    /// 缓存后台刷新是否启用（默认false） / Enable cache background refresh (default false)
    #[serde(default = "default_cache_background_refresh")]
    pub cache_background_refresh: bool,
    /// 缓存后台刷新阈值（百分比，默认10）。当剩余TTL低于此百分比时触发后台刷新 / Cache background refresh threshold (percentage, default 10). Trigger background refresh when remaining TTL below this percentage
    #[serde(default = "default_cache_refresh_threshold_percent")]
    pub cache_refresh_threshold_percent: u8,
    /// 缓存后台刷新最小TTL（秒，默认5）。防止TTL过短导致无限循环刷新 / Cache background refresh minimum TTL (seconds, default 5). Prevent infinite refresh loop for very short TTLs
    #[serde(default = "default_cache_refresh_min_ttl")]
    pub cache_refresh_min_ttl: u32,
    /// GeoIP 数据库文件路径（MMDB 格式） / GeoIP database file path (MMDB format)
    #[serde(default)]
    pub geoip_db_path: Option<String>,
    /// GeoIP 数据文件路径（V2Ray .dat 格式） / GeoIP data file path (V2Ray .dat format)
    #[serde(default)]
    pub geoip_dat_path: Option<String>,
    /// 是否自动转换 .dat 为 MMDB（默认 false）/ Auto-convert .dat to MMDB (default false)
    #[serde(default)]
    pub geoip_auto_convert: bool,
    /// GeoIP 转换时过滤的国家代码列表 / Country codes to filter during GeoIP conversion
    #[serde(default)]
    pub geoip_filter_countries: Vec<String>,
    /// GeoSite 数据文件路径列表（V2Ray 格式，支持多个文件） / GeoSite data file paths (V2Ray format, supports multiple files)
    #[serde(default)]
    pub geosite_data_paths: Vec<String>,
    /// UDP 失败时是否自动 fallback 到 TCP（默认 true）。 / UDP failure automatically fallbacks to TCP (default true)
    #[serde(default = "default_enable_tcp_fallback")]
    pub enable_tcp_fallback: bool,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        Self {
            min_ttl: default_min_ttl(),
            bind_udp: default_bind_udp(),
            bind_tcp: default_bind_tcp(),
            default_upstream: default_upstream(),
            default_upstream_pre_split: None,
            upstream_timeout_ms: default_upstream_timeout_ms(),
            request_timeout_ms: None, // 默认自动计算 / Auto-calculated by default
            response_jump_limit: default_response_jump_limit(),
            udp_pool_size: default_udp_pool_size(),
            tcp_pool_size: default_tcp_pool_size(),
            tcp_health_check_error_threshold: default_tcp_health_check_error_threshold(),
            tcp_connection_max_age_seconds: default_tcp_connection_max_age_seconds(),
            tcp_connection_idle_timeout_seconds: default_tcp_connection_idle_timeout_seconds(),
            flow_control_enabled: default_flow_control_enabled(),
            flow_control_initial_permits: default_flow_control_initial_permits(),
            flow_control_min_permits: default_flow_control_min_permits(),
            flow_control_max_permits: default_flow_control_max_permits(),
            flow_control_latency_threshold_ms: default_flow_control_latency_threshold_ms(),
            flow_control_adjustment_interval_secs: default_flow_control_adjustment_interval_secs(),
            cache_capacity: default_cache_capacity(),
            cache_max_ttl: default_cache_max_ttl(),
            dashmap_shards: default_dashmap_shards(),
            cache_background_refresh: default_cache_background_refresh(),
            cache_refresh_threshold_percent: default_cache_refresh_threshold_percent(),
            cache_refresh_min_ttl: default_cache_refresh_min_ttl(),
            geoip_db_path: None,
            geoip_dat_path: None,
            geoip_auto_convert: false,
            geoip_filter_countries: Vec::new(),
            geosite_data_paths: Vec::new(),
            enable_tcp_fallback: default_enable_tcp_fallback(),
        }
    }
}

fn default_cache_capacity() -> u64 {
    10_000
}

fn default_cache_max_ttl() -> u64 {
    86400
}

fn default_dashmap_shards() -> usize {
    0 // 0 means use DashMap default (num_cpus * 4)
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
    /// 匹配客户端IP的GeoIP国家代码（大小写不敏感）。 / Match client IP GeoIP country code (case insensitive)
    GeoipCountry {
        country_codes: Vec<String>,
    },
    /// 匹配客户端IP是否为私有IP（内网）。 / Match whether client IP is private (internal network)
    GeoipPrivate {
        expect: bool,
    },
    /// 匹配查询 QCLASS（如 IN/CH/HS）。 / Match query QCLASS (e.g., IN/CH/HS)
    Qclass {
        value: String,
    },
    /// 是否存在 EDNS 伪记录。 / Whether EDNS pseudo-record exists
    EdnsPresent {
        expect: bool,
    },
    /// GeoSite 分类匹配（如 "cn", "google", "category-ads"）。 / GeoSite category matching (e.g., "cn", "google", "category-ads")
    GeoSite {
        value: String,
    },
    /// GeoSite 否定匹配（匹配不在该分类的域名）。 / GeoSite negation matching (match domains NOT in category)
    GeoSiteNot {
        value: String,
    },
    /// 请求 QTYPE（如 A/AAAA/CNAME/TXT/MX 等）。 / Request QTYPE (e.g., A/AAAA/CNAME/TXT/MX, etc.)
    Qtype {
        value: String,
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
    /// GeoSite 分类匹配（如 "cn", "google", "category-ads"）。 / GeoSite category matching (e.g., "cn", "google", "category-ads")
    GeoSite { value: String },
    /// GeoSite 否定匹配（匹配不在该分类的域名）。 / GeoSite negation matching (match domains NOT in category)
    GeoSiteNot { value: String },
    /// 匹配客户端IP的GeoIP国家代码（大小写不敏感）。 / Match client IP GeoIP country code (case insensitive)
    GeoipCountry { country_codes: Vec<String> },
    /// 匹配客户端IP是否为私有IP（内网）。 / Match whether client IP is private (internal network)
    GeoipPrivate { expect: bool },
    /// 请求 QTYPE（如 A/AAAA/CNAME/TXT/MX 等）。 / Request QTYPE (e.g., A/AAAA/CNAME/TXT/MX, etc.)
    Qtype { value: String },
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
    /// 匹配响应中 IP 的 GeoIP 国家代码（大小写不敏感）/ Match GeoIP country code of IPs in response (case insensitive)
    ResponseAnswerIpGeoipCountry { country_codes: Vec<String> },
    /// 匹配响应中 IP 是否为私有 IP / Match whether IPs in response are private IPs
    ResponseAnswerIpGeoipPrivate { expect: bool },
    /// 匹配响应中的请求域名是否属于指定 GeoSite 分类 / Match if request domain in response belongs to specified GeoSite category
    ResponseRequestDomainGeoSite { value: String },
    /// 匹配响应中的请求域名是否不属于指定 GeoSite 分类 / Match if request domain in response does NOT belong to specified GeoSite category
    ResponseRequestDomainGeoSiteNot { value: String },
    /// 匹配响应中 TXT 记录的内容 / Match TXT record content in response
    ResponseTxtContent {
        /// 匹配模式: exact(精确), prefix(前缀), regex(正则) / Match mode: exact, prefix, or regex
        mode: String,
        /// 要匹配的文本 / Text to match
        value: String,
    },
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
    /// 返回固定 TXT 记录。支持单个字符串或字符串数组。 / Return static TXT record. Supports single string or string array.
    StaticTxtResponse {
        /// TXT 记录内容 / TXT record content
        #[serde(deserialize_with = "deserialize_txt_text")]
        text: Vec<String>,
        /// TTL (可选，默认 300) / TTL (optional, default 300)
        #[serde(default)]
        ttl: Option<u32>,
    },
    /// 跳转到指定 Pipeline 继续处理。 / Jump to specified Pipeline to continue processing
    JumpToPipeline { pipeline: String },
    /// 终止匹配。请求阶段使用默认上游，响应阶段使用当前响应。 / Terminate matching. Request phase uses default upstream, response phase uses current response
    Allow,
    /// 终止并丢弃（返回 REFUSED）。 / Terminate and drop (return REFUSED)
    Deny,
    /// 透传上游；upstream为空则使用全局默认；支持逗号分隔或数组格式的多个上游（并发请求取最快结果）；transport缺省udp。 / Forward to upstream; use global default if upstream is empty; supports comma-separated or array format for multiple upstreams (concurrent requests, take fastest result); transport defaults to udp
    Forward {
        #[serde(deserialize_with = "deserialize_upstream")]
        upstream: Option<String>,
        #[serde(default)]
        transport: Option<Transport>,
        /// 预分割的 upstream 列表（性能优化）/ Pre-split upstream list (performance optimization)
        #[serde(skip)]
        pre_split_upstreams: Option<std::sync::Arc<Vec<std::sync::Arc<str>>>>,
    },
    /// 继续匹配后续规则。响应阶段会复用当前响应结果。 / Continue matching subsequent rules. Response phase will reuse current response result
    Continue,
    /// 修改响应中的 TXT 记录 / Modify TXT records in response
    ReplaceTxtResponse {
        /// 新的 TXT 内容 / New TXT content
        #[serde(deserialize_with = "deserialize_txt_text")]
        text: Vec<String>,
    },
}

/// Action 辅助函数 / Action helper functions
impl Action {
    /// 预分割 upstream 字符串以优化性能（在配置加载时调用）/ Pre-split upstream string for performance (call during config loading)
    #[inline]
    pub fn pre_split_upstreams(&mut self) {
        if let Action::Forward {
            upstream,
            pre_split_upstreams,
            ..
        } = self
        {
            if let Some(upstream_str) = upstream {
                let split: Vec<std::sync::Arc<str>> = upstream_str
                    .split(',')
                    .map(|s| std::sync::Arc::from(s.trim()))
                    .filter(|s: &std::sync::Arc<str>| !s.is_empty())
                    .collect();
                *pre_split_upstreams = Some(std::sync::Arc::new(split));
            }
        }
    }
}

impl GlobalSettings {
    /// 预分割默认 upstream 字符串以优化性能（在配置加载时调用）/ Pre-split default upstream string for performance (call during config loading)
    #[inline]
    pub fn pre_split_default_upstream(&mut self) {
        let split: Vec<std::sync::Arc<str>> = self
            .default_upstream
            .split(',')
            .map(|s| std::sync::Arc::from(s.trim()))
            .filter(|s: &std::sync::Arc<str>| !s.is_empty())
            .collect();
        if split.len() > 1 {
            self.default_upstream_pre_split = Some(std::sync::Arc::new(split));
        }
    }

    /// Validate timeout configuration sanity
    /// 验证超时配置的合理性
    pub fn validate_timeouts(&self) -> anyhow::Result<()> {
        // Validate request_timeout >= upstream_timeout
        // 验证 request_timeout >= upstream_timeout
        if let Some(request_timeout) = self.request_timeout_ms {
            if request_timeout < self.upstream_timeout_ms {
                anyhow::bail!(
                    "Configuration error: request_timeout_ms ({request_timeout}) must be >= upstream_timeout_ms ({upstream})\n\
                     配置错误: request_timeout_ms ({request_timeout}) 必须大于等于 upstream_timeout_ms ({upstream})",
                    upstream = self.upstream_timeout_ms
                );
            }

            // Recommended value check (warning only, doesn't block)
            // 建议值检查（警告但不阻止）
            // Recommended value should be at least upstream * 2.5 to allow hedge + TCP fallback to complete
            // 建议值应至少为 upstream * 2.5，以允许 hedge + TCP fallback 完成
            let recommended = self.upstream_timeout_ms * 5 / 2;
            if request_timeout < recommended {
                tracing::warn!(
                    upstream_timeout_ms = self.upstream_timeout_ms,
                    request_timeout_ms = request_timeout,
                    recommended = recommended,
                    "request_timeout_ms may be too short, may interrupt hedge and TCP fallback\n\
                     request_timeout_ms 可能太短，可能会中断 hedge 和 TCP fallback"
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Udp,
    Tcp,
    /// Send both TCP and UDP concurrently, use first response (hedged request)
    /// 同时发送 TCP 和 UDP，使用第一个响应（对冲请求）
    TcpUdp,
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
    // 预分割 upstream 字符串以提高性能 / Pre-split upstream strings for better performance
    // 预分割默认 upstream 以支持并发查询 / Pre-split default upstream for concurrent queries
    cfg.settings.pre_split_default_upstream();

    for pipeline in &mut cfg.pipelines {
        for rule in &mut pipeline.rules {
            for action in &mut rule.actions {
                action.pre_split_upstreams();
            }
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

fn default_tcp_health_check_error_threshold() -> usize {
    3 // 连续 3 次失败后重置连接 / Reset connection after 3 consecutive failures
}

fn default_tcp_connection_max_age_seconds() -> u64 {
    300 // 5 分钟 / 5 minutes
}

fn default_tcp_connection_idle_timeout_seconds() -> u64 {
    60 // 1 分钟 / 1 minute
}

fn default_flow_control_enabled() -> bool {
    false  // 默认禁用，采用rustdns风格 / Default disabled, use rustdns style
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

fn default_cache_background_refresh() -> bool {
    false
}

fn default_cache_refresh_threshold_percent() -> u8 {
    10
}

fn default_cache_refresh_min_ttl() -> u32 {
    5
}

/// 反序列化 upstream 字段，支持字符串、逗号分隔字符串或数组格式
/// Deserialize upstream field, supports string, comma-separated string, or array format
fn deserialize_upstream<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum UpstreamInput {
        String(String),
        Array(Vec<String>),
    }

    let input = Option::<UpstreamInput>::deserialize(deserializer)?;

    match input {
        None => Ok(None),
        Some(UpstreamInput::String(s)) => Ok(Some(s)),
        Some(UpstreamInput::Array(arr)) => {
            if arr.is_empty() {
                Ok(None)
            } else {
                Ok(Some(arr.join(",")))
            }
        }
    }
}

/// 反序列化TXT文本字段，支持单个字符串或字符串数组 / Deserialize TXT text field, supports single string or string array
fn deserialize_txt_text<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TxtTextInput {
        String(String),
        Array(Vec<String>),
    }

    let input = TxtTextInput::deserialize(deserializer)?;

    match input {
        TxtTextInput::String(s) => Ok(vec![s]),
        TxtTextInput::Array(arr) => Ok(arr),
    }
}


fn default_enable_tcp_fallback() -> bool {
    true
}
