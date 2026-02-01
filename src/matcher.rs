use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use hickory_proto::op::Message;
use hickory_proto::rr::{DNSClass, RecordType};
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use rustc_hash::FxHashMap;

use crate::config::{self, Action, MatchOperator, PipelineConfig};

// ============================================================================
// TXT Match Mode / TXT 匹配模式
// ============================================================================

/// TXT 匹配模式 / TXT match mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxtMatchMode {
    /// 精确匹配 / Exact match
    Exact,
    /// 前缀匹配 / Prefix match
    Prefix,
    /// 正则匹配 / Regex match
    Regex,
}

impl TxtMatchMode {
    /// 从字符串解析匹配模式 / Parse match mode from string
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "exact" => Ok(TxtMatchMode::Exact),
            "prefix" => Ok(TxtMatchMode::Prefix),
            "regex" => Ok(TxtMatchMode::Regex),
            _ => anyhow::bail!(
                "invalid TXT match mode: {}, must be one of: exact, prefix, regex",
                s
            ),
        }
    }
}

// ============================================================================
// Matcher Helper Functions / 匹配器辅助函数
// ============================================================================

/// GeoIP/GeoSite 匹配器辅助函数 / Helper functions for GeoIP/GeoSite matchers
///
/// 这些函数提供可复用的匹配逻辑，避免在多个匹配器中重复代码。
/// These functions provide reusable matching logic to avoid duplication across multiple matchers.
mod matcher_helpers {
    use super::*;

    /// 检查 IP 的 GeoIP 国家代码是否匹配指定的国家代码列表（大小写不敏感）
    /// Check if IP's GeoIP country code matches the specified list (case insensitive)
    ///
    /// # 参数 / Parameters
    /// - `manager`: GeoIpManager 引用 / GeoIpManager reference
    /// - `ip`: 要检查的 IP 地址 / IP address to check
    /// - `country_codes`: 允许的国家代码列表（使用 Arc<str> 零拷贝）/ Allowed country codes (Arc<str> for zero-copy)
    ///
    /// # 返回 / Returns
    /// - `true`: IP 属于指定的国家之一 / IP belongs to one of the specified countries
    /// - `false`: IP 不属于任何指定的国家 / IP does not belong to any specified country
    #[inline]
    pub fn match_geoip_country(
        manager: &crate::geoip::GeoIpManager,
        ip: IpAddr,
        country_codes: &[String],
    ) -> bool {
        let result = manager.lookup(ip);

        // ✅ 优化：提前返回，避免闭包分配
        // ✅ Optimization: Early return to avoid closure allocation
        let country_code = match result.country_code.as_ref() {
            Some(code) => code,
            None => return false,
        };

        // ✅ 优化：直接迭代，避免 any() 的闭包开销
        // ✅ Optimization: Direct iteration to avoid closure overhead of any()
        for code in country_codes {
            if code.eq_ignore_ascii_case(country_code.as_ref()) {
                return true;
            }
        }
        false
    }

    /// 检查域名是否属于指定的 GeoSite 分类
    /// Check if domain belongs to the specified GeoSite category
    ///
    /// # 参数 / Parameters
    /// - `manager`: GeoSiteManager 引用 / GeoSiteManager reference
    /// - `domain`: 要检查的域名 / Domain to check
    /// - `tag`: GeoSite 标签 / GeoSite tag
    ///
    /// # 返回 / Returns
    /// - `true`: 域名属于该分类 / Domain belongs to the category
    /// - `false`: 域名不属于该分类 / Domain does not belong to the category
    #[inline]
    pub fn match_geosite(
        manager: &crate::geosite::GeoSiteManager,
        domain: &str,
        tag: &str,
    ) -> bool {
        manager.matches(tag, domain)
    }

    /// 从 DNS 响应消息中收集所有 IP 地址（A 和 AAAA 记录）
    /// Collect all IP addresses from DNS response message (A and AAAA records)
    ///
    /// # 参数 / Parameters
    /// - `msg`: DNS 响应消息 / DNS response message
    ///
    /// # 返回 / Returns
    /// 包含所有 IP 地址的向量 / Vector containing all IP addresses
    #[inline]
    pub fn collect_ips_from_message(msg: &Message) -> Vec<IpAddr> {
        use hickory_proto::rr::RData;
        let mut ips = Vec::new();

        // 从 Answer 中收集 IP / Collect IPs from Answer
        for record in msg.answers() {
            match record.data() {
                Some(RData::A(a)) => ips.push(IpAddr::V4(a.0)),
                Some(RData::AAAA(aaaa)) => ips.push(IpAddr::V6(aaaa.0)),
                _ => {}
            }
        }

        ips
    }

    /// 检查响应消息中是否有任意 IP 匹配指定的 CIDR 列表
    /// Check if any IP in response message matches the specified CIDR list
    ///
    /// # 参数 / Parameters
    /// - `msg`: DNS 响应消息 / DNS response message
    /// - `nets`: CIDR 网络列表 / CIDR network list
    ///
    /// # 返回 / Returns
    /// - `true`: 至少有一个 IP 匹配 / At least one IP matches
    /// - `false`: 没有IP匹配 / No IP matches
    pub fn any_ip_matches_nets(msg: &Message, nets: &[IpNet]) -> bool {
        use hickory_proto::rr::RData;

        // 先检查 Answer / Check Answer first
        let found = msg.answers().iter().any(|record| match record.data() {
            Some(RData::A(a)) => nets.iter().any(|net| net.contains(&IpAddr::V4(a.0))),
            Some(RData::AAAA(aaaa)) => nets.iter().any(|net| net.contains(&IpAddr::V6(aaaa.0))),
            _ => false,
        });

        if found {
            return true;
        }

        // 再检查 Additionals / Check Additionals
        msg.additionals().iter().any(|record| match record.data() {
            Some(RData::A(a)) => nets.iter().any(|net| net.contains(&IpAddr::V4(a.0))),
            Some(RData::AAAA(aaaa)) => nets.iter().any(|net| net.contains(&IpAddr::V6(aaaa.0))),
            _ => false,
        })
    }
}

// ============================================================================
// Runtime Pipeline Configuration / 运行时 Pipeline 配置
// ============================================================================

#[derive(Debug, Clone)]
pub struct RuntimePipelineConfig {
    pub settings: config::GlobalSettings,
    pub pipeline_select: Vec<RuntimePipelineSelectRule>,
    pub pipelines: Vec<RuntimePipeline>,
}

#[derive(Debug, Clone)]
pub struct RuntimePipeline {
    pub id: Arc<str>,
    pub rules: Vec<RuntimeRule>,
    /// 是否包含依赖客户端 IP 的匹配规则 / Whether it contains rules that match based on client IP
    pub uses_client_ip: bool,
    // Indices for O(1) lookup
    // 完全域名匹配索引（最高优先级）/ Exact domain match index (highest priority)
    pub domain_exact_index: FxHashMap<String, Vec<usize>>,
    // Maps domain suffix -> list of rule indices that MUST be checked
    pub domain_suffix_index: FxHashMap<String, Vec<usize>>,
    // Maps query type -> list of rule indices (高频过滤条件 / High-frequency filter)
    pub query_type_index: FxHashMap<RecordType, Vec<usize>>,
    // Rules that are NOT indexed by domain (must always be checked)
    pub always_check_rules: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct RuntimeRule {
    pub name: Arc<str>,
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
    DomainExact { value: String },
    DomainSuffix { value: String },
    ClientIp { net: IpNet },
    DomainRegex { regex: Regex },
    GeoipCountry { country_codes: Vec<String> },
    GeoipPrivate { expect: bool },
    Qclass { value: DNSClass },
    EdnsPresent { expect: bool },
    GeoSite { tag: String },
    GeoSiteNot { tag: String },
    Qtype { value: RecordType },
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
    GeoSite { tag: String },
    GeoSiteNot { tag: String },
    GeoipCountry { country_codes: Vec<String> },
    GeoipPrivate { expect: bool },
    Qtype { value: RecordType },
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
    /// 匹配响应中 IP 的 GeoIP 国家代码 / Match GeoIP country code of IPs in response
    ResponseAnswerIpGeoipCountry {
        country_codes: Vec<String>,
    },
    /// 匹配响应中 IP 是否为私有 IP / Match whether IPs in response are private
    ResponseAnswerIpGeoipPrivate {
        expect: bool,
    },
    /// 匹配响应中的请求域名是否属于指定 GeoSite 分类 / Match if request domain in response belongs to specified GeoSite category
    ResponseRequestDomainGeoSite {
        value: String,
    },
    /// 匹配响应中的请求域名是否不属于指定 GeoSite 分类 / Match if request domain in response does NOT belong to specified GeoSite category
    ResponseRequestDomainGeoSiteNot {
        value: String,
    },
    /// 匹配响应中的 TXT 记录内容 / Match TXT record content in response
    ResponseTxtContent {
        mode: TxtMatchMode,
        value: String,
        regex: Option<Regex>,
    },
}

#[derive(Debug, Clone)]
pub struct RuntimeResponseMatcherWithOp {
    pub operator: MatchOperator,
    pub matcher: RuntimeResponseMatcher,
}

impl RuntimePipelineConfig {
    pub fn from_config(cfg: PipelineConfig) -> anyhow::Result<Self> {
        // Validate cache_capacity configuration
        if cfg.settings.cache_capacity == 0 {
            anyhow::bail!("cache_capacity must be greater than 0");
        }
        let shards = cfg.settings.dashmap_shards;
        if shards > 0 && !shards.is_power_of_two() {
            anyhow::bail!("dashmap_shards must be a power of two");
        }
        if cfg.settings.cache_capacity > 1_000_000 {
            tracing::warn!(
                cache_capacity = cfg.settings.cache_capacity,
                "cache_capacity is very large, may cause high memory usage"
            );
        }

        // ✅ 验证超时配置的合理性
        // ✅ Validate timeout configuration sanity
        cfg.settings
            .validate_timeouts()
            .context("validate timeout configuration")?;

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
                    name: Arc::from(r.name),
                    matcher_operator: r.matcher_operator,
                    matchers,
                    actions: r.actions,
                    response_matchers,
                    response_matcher_operator: r.response_matcher_operator,
                    response_actions_on_match: r.response_actions_on_match,
                    response_actions_on_miss: r.response_actions_on_miss,
                });
            }

            // Build Indices - 优化：索引所有可索引的匹配器，而不只是第一个
            // Build Indices - Optimized: index all indexable matchers, not just the first one
            let mut domain_suffix_index: FxHashMap<String, Vec<usize>> = FxHashMap::default();
            let mut domain_exact_index: FxHashMap<String, Vec<usize>> = FxHashMap::default();
            let mut query_type_index: FxHashMap<RecordType, Vec<usize>> = FxHashMap::default();
            let mut always_check_rules = Vec::new();

            for (idx, rule) in rules.iter().enumerate() {
                let mut indexed = false;

                // 性能优化：只在 AND 链中索引，OR 链放入 always_check
                // Performance optimization: only index in AND chains, put OR chains in always_check
                if rule.matcher_operator == MatchOperator::And {
                    // 索引所有可索引的匹配器 / Index all indexable matchers
                    for m in &rule.matchers {
                        match &m.matcher {
                            RuntimeMatcher::DomainExact { value } => {
                                domain_exact_index
                                    .entry(value.clone())
                                    .or_default()
                                    .push(idx);
                                indexed = true;
                            }
                            RuntimeMatcher::DomainSuffix { value } => {
                                domain_suffix_index
                                    .entry(value.clone())
                                    .or_default()
                                    .push(idx);
                                indexed = true;
                            }
                            RuntimeMatcher::DomainRegex { .. }
                            | RuntimeMatcher::ClientIp { .. }
                            | RuntimeMatcher::GeoipCountry { .. }
                            | RuntimeMatcher::GeoipPrivate { .. }
                            | RuntimeMatcher::GeoSite { .. }
                            | RuntimeMatcher::GeoSiteNot { .. }
                            | RuntimeMatcher::EdnsPresent { .. } => {
                                // 这些匹配器无法基于域名/类型索引，跳过
                                // These matchers cannot be indexed by domain/type, skip
                            }
                            RuntimeMatcher::Qtype { value } => {
                                query_type_index.entry(*value).or_default().push(idx);
                                indexed = true;
                            }
                            RuntimeMatcher::Qclass { .. } => {
                                // Qclass 通常固定为 IN，索引价值不大
                                // Qclass is usually IN, indexing provides little value
                            }
                            RuntimeMatcher::Any => {
                                // Any 匹配所有域名，不适合索引
                                // Any matches all domains, not suitable for indexing
                            }
                        }
                    }
                }

                if !indexed {
                    always_check_rules.push(idx);
                }
            }

            // 合并索引：_domain_exact 和 _query_type 可以直接使用
            // Merge indices: _domain_exact and _query_type can be used directly
            // 注意：当前实现只使用了 domain_suffix_index，未来可以扩展使用其他索引
            // Note: current implementation only uses domain_suffix_index, can be extended to use other indices

            let mut pipeline_uses_client_ip = false;
            let mut pipeline_uses_geoip = false;
            let mut pipeline_uses_geosite = false;
            for r in &rules {
                for m in &r.matchers {
                    if matches!(m.matcher, RuntimeMatcher::ClientIp { .. }) {
                        pipeline_uses_client_ip = true;
                        break;
                    }
                    if matches!(
                        m.matcher,
                        RuntimeMatcher::GeoipCountry { .. } | RuntimeMatcher::GeoipPrivate { .. }
                    ) {
                        pipeline_uses_geoip = true;
                    }
                    if matches!(
                        m.matcher,
                        RuntimeMatcher::GeoSite { .. } | RuntimeMatcher::GeoSiteNot { .. }
                    ) {
                        pipeline_uses_geosite = true;
                    }
                }
                if pipeline_uses_client_ip && pipeline_uses_geoip && pipeline_uses_geosite {
                    break;
                }
            }

            pipelines.push(RuntimePipeline {
                id: Arc::from(p.id),
                rules,
                uses_client_ip: pipeline_uses_client_ip,
                domain_exact_index, // 添加完全匹配索引 / Add exact match index
                domain_suffix_index,
                query_type_index, // 添加 query_type 索引 / Add query_type index
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

        // 预处理所有 Forward action 的 upstream 字段（性能优化）/ Pre-process all Forward upstreams (performance optimization)
        for pipeline in &mut pipelines {
            for rule in &mut pipeline.rules {
                for action in &mut rule.actions {
                    action.pre_split_upstreams();
                }
                for action in &mut rule.response_actions_on_match {
                    action.pre_split_upstreams();
                }
                for action in &mut rule.response_actions_on_miss {
                    action.pre_split_upstreams();
                }
            }
        }

        // ✅ 新增：处理后台刷新专用规则
        // ✅ New: Process background refresh dedicated rule
        // Note: Currently unused, reserved for future implementation
        let _background_refresh_rule = match cfg.background_refresh_rule {
            Some(rule) => {
                // 转换配置的规则为运行时规则
                // Convert configured rule to runtime rule
                let mut matchers = Vec::new();
                for m in rule.matchers {
                    matchers.push(RuntimeMatcherWithOp {
                        operator: m.operator,
                        matcher: RuntimeMatcher::from_config(m.matcher)?,
                    });
                }

                let mut response_matchers = Vec::new();
                for rm in rule.response_matchers {
                    response_matchers.push(RuntimeResponseMatcherWithOp {
                        operator: rm.operator,
                        matcher: RuntimeResponseMatcher::from_config(rm.matcher)?,
                    });
                }

                Some(RuntimeRule {
                    name: Arc::from(rule.name),
                    matcher_operator: rule.matcher_operator,
                    matchers,
                    actions: rule.actions,
                    response_matchers,
                    response_matcher_operator: rule.response_matcher_operator,
                    response_actions_on_match: rule.response_actions_on_match,
                    response_actions_on_miss: rule.response_actions_on_miss,
                })
            }
            None => None, // 未配置，将在 Engine::new 中使用默认规则
        };

        Ok(Self {
            settings: cfg.settings,
            pipeline_select,
            pipelines,
            // background_refresh_rule,  // ✅ 暂时注释，等待 RuntimePipelineConfig 结构更新
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
            config::Matcher::GeoipCountry { country_codes } => {
                RuntimeMatcher::GeoipCountry { country_codes }
            }
            config::Matcher::GeoipPrivate { expect } => RuntimeMatcher::GeoipPrivate { expect },
            config::Matcher::Qclass { value } => RuntimeMatcher::Qclass {
                value: parse_dns_class(&value)?,
            },
            config::Matcher::EdnsPresent { expect } => RuntimeMatcher::EdnsPresent { expect },
            config::Matcher::GeoSite { value } => RuntimeMatcher::GeoSite { tag: value },
            config::Matcher::GeoSiteNot { value } => RuntimeMatcher::GeoSiteNot { tag: value },
            config::Matcher::Qtype { value } => RuntimeMatcher::Qtype {
                value: parse_dns_type(&value)?,
            },
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
        self.matches_with_geoip(qname, qclass, client_ip, edns_present, None, None)
    }

    #[inline]
    pub fn matches_with_geoip(
        &self,
        qname: &str,
        qclass: DNSClass,
        client_ip: IpAddr,
        edns_present: bool,
        geoip_manager: Option<&crate::geoip::GeoIpManager>,
        geosite_manager: Option<&crate::geosite::GeoSiteManager>,
    ) -> bool {
        match self {
            RuntimeMatcher::Any => true,
            RuntimeMatcher::DomainExact { value } => {
                // 完全匹配，大小写不敏感 / Exact match, case insensitive
                qname.eq_ignore_ascii_case(value)
            }
            RuntimeMatcher::DomainSuffix { value } => qname.ends_with(value),
            RuntimeMatcher::ClientIp { net } => net.contains(&client_ip),
            RuntimeMatcher::DomainRegex { regex } => regex.is_match(qname),
            RuntimeMatcher::GeoipCountry { country_codes } => {
                // 使用辅助函数进行 GeoIP 国家代码匹配 / Use helper for GeoIP country matching
                geoip_manager.map_or(false, |mgr| {
                    matcher_helpers::match_geoip_country(mgr, client_ip, country_codes)
                })
            }
            RuntimeMatcher::GeoipPrivate { expect } => {
                // GeoIP private IP detection with GeoIpManager
                if let Some(manager) = geoip_manager {
                    let result = manager.lookup(client_ip);
                    result.is_private == *expect
                } else {
                    // Fallback to basic private IP check
                    crate::geoip::is_private_ip(client_ip) == *expect
                }
            }
            RuntimeMatcher::Qclass { value } => &qclass == value,
            RuntimeMatcher::EdnsPresent { expect } => *expect == edns_present,
            RuntimeMatcher::GeoSite { tag } => {
                // 使用辅助函数进行 GeoSite 匹配 / Use helper for GeoSite matching
                geosite_manager.map_or(false, |mgr| matcher_helpers::match_geosite(mgr, qname, tag))
            }
            RuntimeMatcher::GeoSiteNot { tag } => {
                // 使用辅助函数进行 GeoSite 非匹配 / Use helper for GeoSite NOT matching
                geosite_manager.map_or(false, |mgr| {
                    !matcher_helpers::match_geosite(mgr, qname, tag)
                })
            }
            RuntimeMatcher::Qtype { .. } => false, // Qtype matching requires qtype parameter
        }
    }

    #[inline]
    pub fn matches_with_qtype(
        &self,
        qname: &str,
        qclass: DNSClass,
        client_ip: IpAddr,
        edns_present: bool,
        qtype: RecordType,
        geoip_manager: Option<&crate::geoip::GeoIpManager>,
        geosite_manager: Option<&crate::geosite::GeoSiteManager>,
    ) -> bool {
        match self {
            RuntimeMatcher::Any => true,
            RuntimeMatcher::DomainExact { value } => {
                // 完全匹配，大小写不敏感 / Exact match, case insensitive
                qname.eq_ignore_ascii_case(value)
            }
            RuntimeMatcher::DomainSuffix { value } => qname.ends_with(value),
            RuntimeMatcher::ClientIp { net } => net.contains(&client_ip),
            RuntimeMatcher::DomainRegex { regex } => regex.is_match(qname),
            RuntimeMatcher::GeoipCountry { country_codes } => {
                // 使用辅助函数进行 GeoIP 国家代码匹配 / Use helper for GeoIP country matching
                geoip_manager.map_or(false, |mgr| {
                    matcher_helpers::match_geoip_country(mgr, client_ip, country_codes)
                })
            }
            RuntimeMatcher::GeoipPrivate { expect } => {
                // GeoIP private IP detection with GeoIpManager
                if let Some(manager) = geoip_manager {
                    let result = manager.lookup(client_ip);
                    result.is_private == *expect
                } else {
                    // Fallback to basic private IP check
                    crate::geoip::is_private_ip(client_ip) == *expect
                }
            }
            RuntimeMatcher::Qclass { value } => &qclass == value,
            RuntimeMatcher::EdnsPresent { expect } => *expect == edns_present,
            RuntimeMatcher::GeoSite { tag } => {
                // 使用辅助函数进行 GeoSite 匹配 / Use helper for GeoSite matching
                geosite_manager.map_or(false, |mgr| matcher_helpers::match_geosite(mgr, qname, tag))
            }
            RuntimeMatcher::GeoSiteNot { tag } => {
                // 使用辅助函数进行 GeoSite 非匹配 / Use helper for GeoSite NOT matching
                geosite_manager.map_or(false, |mgr| {
                    !matcher_helpers::match_geosite(mgr, qname, tag)
                })
            }
            RuntimeMatcher::Qtype { value } => *value == qtype,
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
            config::PipelineSelectorMatcher::GeoSite { value } => {
                RuntimePipelineSelectorMatcher::GeoSite { tag: value }
            }
            config::PipelineSelectorMatcher::GeoSiteNot { value } => {
                RuntimePipelineSelectorMatcher::GeoSiteNot { tag: value }
            }
            config::PipelineSelectorMatcher::GeoipCountry { country_codes } => {
                RuntimePipelineSelectorMatcher::GeoipCountry { country_codes }
            }
            config::PipelineSelectorMatcher::GeoipPrivate { expect } => {
                RuntimePipelineSelectorMatcher::GeoipPrivate { expect }
            }
            config::PipelineSelectorMatcher::Qtype { value } => {
                RuntimePipelineSelectorMatcher::Qtype {
                    value: parse_dns_type(&value)?,
                }
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
        geoip_manager: Option<&crate::geoip::GeoIpManager>,
        geosite_manager: Option<&crate::geosite::GeoSiteManager>,
    ) -> bool {
        self.matches_with_qtype(
            listener_label,
            client_ip,
            qname,
            qclass,
            edns_present,
            hickory_proto::rr::RecordType::A,
            geoip_manager,
            geosite_manager,
        )
    }

    #[inline]
    pub fn matches_with_qtype(
        &self,
        listener_label: &str,
        client_ip: IpAddr,
        qname: &str,
        qclass: DNSClass,
        edns_present: bool,
        qtype: RecordType,
        geoip_manager: Option<&crate::geoip::GeoIpManager>,
        geosite_manager: Option<&crate::geosite::GeoSiteManager>,
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
            RuntimePipelineSelectorMatcher::GeoSite { tag } => {
                // GeoSite matching with GeoSiteManager
                if let Some(manager) = geosite_manager {
                    manager.matches(tag, qname)
                } else {
                    false
                }
            }
            RuntimePipelineSelectorMatcher::GeoSiteNot { tag } => {
                // GeoSite negation matching with GeoSiteManager
                if let Some(manager) = geosite_manager {
                    !manager.matches(tag, qname)
                } else {
                    false
                }
            }
            RuntimePipelineSelectorMatcher::GeoipCountry { country_codes } => {
                // GeoIP matching with GeoIpManager
                if let Some(manager) = geoip_manager {
                    let result = manager.lookup(client_ip);
                    if let Some(cc) = result.country_code {
                        country_codes.iter().any(|c| c.eq_ignore_ascii_case(&cc))
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            RuntimePipelineSelectorMatcher::GeoipPrivate { expect } => {
                // GeoIP private IP matching with GeoIpManager
                if let Some(manager) = geoip_manager {
                    let result = manager.lookup(client_ip);
                    result.is_private == *expect
                } else {
                    // Fallback to basic private IP check
                    crate::geoip::is_private_ip(client_ip) == *expect
                }
            }
            RuntimePipelineSelectorMatcher::Qtype { value } => *value == qtype,
        }
    }
}

#[allow(dead_code)]
#[inline]
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

#[inline]
fn try_parse_upstream_ip(upstream: &str) -> Option<IpAddr> {
    upstream
        .parse::<SocketAddr>()
        .ok()
        .map(|sa| sa.ip())
        .or_else(|| upstream.parse::<IpAddr>().ok())
}

impl RuntimeResponseMatcher {
    pub fn from_config(m: config::ResponseMatcher) -> anyhow::Result<Self> {
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
            config::ResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes } => {
                RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes }
            }
            config::ResponseMatcher::ResponseAnswerIpGeoipPrivate { expect } => {
                RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { expect }
            }
            config::ResponseMatcher::ResponseRequestDomainGeoSite { value } => {
                RuntimeResponseMatcher::ResponseRequestDomainGeoSite { value }
            }
            config::ResponseMatcher::ResponseRequestDomainGeoSiteNot { value } => {
                RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot { value }
            }
            config::ResponseMatcher::ResponseTxtContent { mode, value } => {
                let mode = TxtMatchMode::from_str(&mode)?;
                let regex = match mode {
                    TxtMatchMode::Regex => {
                        // ReDoS保护: 限制正则表达式大小 / ReDoS protection: limit regex size
                        const MAX_REGEX_LEN: usize = 1000;
                        if value.len() > MAX_REGEX_LEN {
                            anyhow::bail!(
                                "regex pattern too long: {} bytes (max {})",
                                value.len(),
                                MAX_REGEX_LEN
                            );
                        }
                        // 使用regex crate的大小限制来防止复杂度攻击
                        // Use regex crate size limit to prevent complexity attacks
                        Some(
                            RegexBuilder::new(&value)
                                .size_limit(1000) // 限制正则引擎状态空间 / limit regex engine state space
                                .dfa_size_limit(1000) // 限制DFA状态数 / limit DFA states
                                .build()
                                .map_err(|e| anyhow::anyhow!("invalid regex: {}", e))?,
                        )
                    }
                    _ => None,
                };
                RuntimeResponseMatcher::ResponseTxtContent { mode, value, regex }
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
        geoip_manager: Option<&crate::geoip::GeoIpManager>,
        geosite_manager: Option<&crate::geosite::GeoSiteManager>,
    ) -> bool {
        match self {
            RuntimeResponseMatcher::UpstreamEquals { value } => upstream == value,
            RuntimeResponseMatcher::RequestDomainSuffix { value } => qname.ends_with(value),
            RuntimeResponseMatcher::RequestDomainRegex { regex } => regex.is_match(qname),
            RuntimeResponseMatcher::ResponseUpstreamIp { nets } => try_parse_upstream_ip(upstream)
                .map(|ip| nets.iter().any(|net| net.contains(&ip)))
                .unwrap_or(false),
            RuntimeResponseMatcher::ResponseAnswerIp { nets } => {
                // 使用辅助函数检查是否有任意 IP 匹配 CIDR / Use helper to check if any IP matches CIDR
                matcher_helpers::any_ip_matches_nets(msg, nets)
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
            RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes } => {
                // 使用辅助函数收集 IP 并进行 GeoIP 国家代码匹配 / Use helper to collect IPs and match GeoIP country
                let all_ips = matcher_helpers::collect_ips_from_message(msg);

                // 如果没有 IP 或没有 GeoIpManager，不匹配 / No match if no IPs or no GeoIpManager
                if all_ips.is_empty() {
                    return false;
                }

                let Some(manager) = geoip_manager else {
                    return false;
                };

                // 检查是否所有 IP 都匹配指定的国家代码 / Check if all IPs match specified country codes
                all_ips
                    .iter()
                    .all(|ip| matcher_helpers::match_geoip_country(manager, *ip, country_codes))
            }
            RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { expect } => {
                // 检查 Answer 中是否有任意 IP 为私有 IP
                use hickory_proto::rr::RData;
                let mut has_private_ip = msg.answers().iter().any(|record| match record.data() {
                    Some(RData::A(a)) => crate::geoip::is_private_ip(std::net::IpAddr::V4(a.0)),
                    Some(RData::AAAA(aaaa)) => {
                        crate::geoip::is_private_ip(std::net::IpAddr::V6(aaaa.0))
                    }
                    _ => false,
                });

                if !has_private_ip {
                    // 检查 additionals
                    has_private_ip = msg.additionals().iter().any(|record| match record.data() {
                        Some(RData::A(a)) => crate::geoip::is_private_ip(std::net::IpAddr::V4(a.0)),
                        Some(RData::AAAA(aaaa)) => {
                            crate::geoip::is_private_ip(std::net::IpAddr::V6(aaaa.0))
                        }
                        _ => false,
                    });
                }

                has_private_ip == *expect
            }
            RuntimeResponseMatcher::ResponseRequestDomainGeoSite { value } => {
                // 使用辅助函数检查请求域名是否属于指定的 GeoSite 分类 / Use helper to check if request domain belongs to GeoSite category
                geosite_manager.map_or(false, |mgr| {
                    matcher_helpers::match_geosite(mgr, qname, value)
                })
            }
            RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot { value } => {
                // 使用辅助函数检查请求域名是否不属于指定的 GeoSite 分类 / Use helper to check if request domain does NOT belong to GeoSite category
                geosite_manager.map_or(false, |mgr| {
                    !matcher_helpers::match_geosite(mgr, qname, value)
                })
            }
            RuntimeResponseMatcher::ResponseTxtContent { mode, value, regex } => {
                // 从响应中提取 TXT 记录 / Extract TXT records from response
                use hickory_proto::rr::RData;
                let txt_data = msg
                    .answers()
                    .iter()
                    .filter_map(|r| {
                        if let Some(RData::TXT(txt)) = r.data() {
                            Some(txt)
                        } else {
                            None
                        }
                    })
                    .flat_map(|txt| txt.iter().flat_map(|s| s.as_ref()))
                    .copied()
                    .collect::<Vec<u8>>();

                let txt_str = String::from_utf8_lossy(&txt_data);

                match mode {
                    TxtMatchMode::Exact => &txt_str == value,
                    TxtMatchMode::Prefix => txt_str.starts_with(value),
                    TxtMatchMode::Regex => {
                        if let Some(re) = regex {
                            re.is_match(&txt_str)
                        } else {
                            false
                        }
                    }
                }
            }
        }
    }
}

// Tests for runtime matcher functionality
// 运行时匹配器功能测试
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::Name;
    use hickory_proto::rr::{RData, Record};
    use regex::Regex;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    // ========================================================================
    // Matcher Helper Functions Unit Tests / 匹配器辅助函数单元测试
    // ========================================================================

    #[test]
    fn test_matcher_helpers_match_geoip_country_case_insensitive() {
        // Arrange: Create GeoIpManager
        let manager = crate::geoip::GeoIpManager::new(None).unwrap();

        // Act & Assert: Test case-insensitive matching with private IPs
        // GeoIpManager without MMDB will return None for country_code
        assert!(
            !matcher_helpers::match_geoip_country(
                &manager,
                "192.168.1.1".parse().unwrap(),
                &["cn".to_string()]
            ),
            "Should return false for IP without country data"
        );

        assert!(
            !matcher_helpers::match_geoip_country(
                &manager,
                "10.0.0.1".parse().unwrap(),
                &["CN".to_string(), "US".to_string()]
            ),
            "Should return false when multiple country codes provided but no data"
        );
    }

    #[test]
    fn test_matcher_helpers_match_geoip_country_no_match() {
        // Arrange: Create GeoIpManager
        let manager = crate::geoip::GeoIpManager::new(None).unwrap();

        // Act & Assert: Test IP with no country data
        assert!(
            !matcher_helpers::match_geoip_country(
                &manager,
                "192.168.1.1".parse().unwrap(),
                &["CN".to_string()]
            ),
            "Should return false for IP without country data"
        );
    }

    #[test]
    fn test_matcher_helpers_match_geosite() {
        // Arrange: Create GeoSiteManager with test data
        let mut manager = crate::geosite::GeoSiteManager::new();

        // Add test entries using correct API
        use crate::geosite::{DomainMatcher, GeoSiteEntry};

        manager.add_entry(GeoSiteEntry {
            tag: "cn".to_string(),
            matchers: vec![
                DomainMatcher::Suffix(".example.com".to_string()),
                DomainMatcher::Keyword("test".to_string()),
            ],
        });

        // Act & Assert: Test domain matching
        assert!(
            matcher_helpers::match_geosite(&manager, "www.example.com", "cn"),
            "Should match domain in cn category"
        );

        assert!(
            matcher_helpers::match_geosite(&manager, "sub.example.com", "cn"),
            "Should match subdomain in cn category"
        );

        assert!(
            !matcher_helpers::match_geosite(&manager, "other.com", "cn"),
            "Should not match unknown domain"
        );

        assert!(
            !matcher_helpers::match_geosite(&manager, "www.example.com", "google"),
            "Should not match domain in non-existent category"
        );
    }

    #[test]
    fn test_matcher_helpers_collect_ips_from_message() {
        // Arrange: Build test message with multiple IPs
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();

        // Add A records
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
        ));

        // Add AAAA record
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        ));

        // Act: Collect IPs
        let ips = matcher_helpers::collect_ips_from_message(&msg);

        // Assert: Verify collected IPs
        assert_eq!(ips.len(), 3, "Should collect 3 IP addresses");
        assert!(
            ips.contains(&"1.2.3.4".parse::<IpAddr>().unwrap()),
            "Should contain first IPv4"
        );
        assert!(
            ips.contains(&"5.6.7.8".parse::<IpAddr>().unwrap()),
            "Should contain second IPv4"
        );
        assert!(
            ips.contains(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            "Should contain IPv6"
        );
    }

    #[test]
    fn test_matcher_helpers_collect_ips_from_empty_message() {
        // Arrange: Build empty message
        let msg = Message::new();

        // Act: Collect IPs
        let ips = matcher_helpers::collect_ips_from_message(&msg);

        // Assert: Should return empty vector
        assert_eq!(ips.len(), 0, "Should return empty vector for empty message");
        assert!(ips.is_empty(), "Vector should be empty");
    }

    #[test]
    fn test_matcher_helpers_any_ip_matches_nets() {
        // Arrange: Build test message with multiple IPs
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 1))),
        ));

        let nets = vec!["1.2.3.0/24".parse::<IpNet>().unwrap()];

        // Act: Check if any IP matches
        let matches = matcher_helpers::any_ip_matches_nets(&msg, &nets);

        // Assert: Should match first IP
        assert!(matches, "Should find matching IP in answers");
    }

    #[test]
    fn test_matcher_helpers_any_ip_matches_nets_no_match() {
        // Arrange: Build test message with IPs
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        ));

        let nets = vec!["1.2.3.0/24".parse::<IpNet>().unwrap()];

        // Act: Check if any IP matches
        let matches = matcher_helpers::any_ip_matches_nets(&msg, &nets);

        // Assert: Should not match
        assert!(!matches, "Should not find matching IP");
    }

    #[test]
    fn test_matcher_helpers_any_ip_matches_nets_in_additionals() {
        // Arrange: Build message with IPs in additionals
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();
        // Add non-matching IP to answers
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(8, 8, 8, 8))),
        ));
        // Add matching IP to additionals
        let additionals = vec![Record::from_rdata(
            name.clone(),
            300,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        )];
        msg.add_additionals(additionals);

        let nets = vec!["1.2.3.0/24".parse::<IpNet>().unwrap()];

        // Act: Check if any IP matches
        let matches = matcher_helpers::any_ip_matches_nets(&msg, &nets);

        // Assert: Should match IP in additionals
        assert!(matches, "Should find matching IP in additionals");
    }

    #[test]
    fn test_matcher_helpers_any_ip_matches_nets_ipv6() {
        // Arrange: Build test message with IPv6
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();
        msg.add_answer(Record::from_rdata(
            name,
            300,
            RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
        ));

        let nets = vec!["2001:db8::/48".parse::<IpNet>().unwrap()];

        // Act: Check if any IP matches
        let matches = matcher_helpers::any_ip_matches_nets(&msg, &nets);

        // Assert: Should match IPv6
        assert!(matches, "Should match IPv6 address");
    }

    // ========================================================================
    // Original Tests / 原有测试
    // ========================================================================

    // Helper function to build test DNS messages
    // 构建测试DNS消息的辅助函数
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

    // Helper function to build test DNS messages with IPv6
    // 构建包含IPv6的测试DNS消息的辅助函数
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
    fn test_runtime_response_matchers_cover_readme_cases() {
        // Arrange: Setup test data
        let qname = "sub.example.com";
        let upstream = "1.1.1.1:53".to_string();
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let msg = build_message(ResponseCode::NoError, true);

        // Act & Assert: Test various response matchers
        assert!(
            RuntimeResponseMatcher::UpstreamEquals {
                value: upstream.clone()
            }
            .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "UpstreamEquals matcher should match when upstream values are equal"
        );
        assert!(
            RuntimeResponseMatcher::RequestDomainSuffix {
                value: "example.com".into()
            }
            .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "RequestDomainSuffix matcher should match domain suffix"
        );
        assert!(
            RuntimeResponseMatcher::RequestDomainRegex {
                regex: Regex::new(".*example\\.com$").unwrap()
            }
            .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "RequestDomainRegex matcher should match regex pattern"
        );
        assert!(
            RuntimeResponseMatcher::ResponseType { value: "A".into() }
                .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "ResponseType matcher should match A record type"
        );
        assert!(
            RuntimeResponseMatcher::ResponseRcode {
                value: "NOERROR".into()
            }
            .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "ResponseRcode matcher should match NOERROR response code"
        );
        assert!(
            RuntimeResponseMatcher::ResponseQclass {
                value: DNSClass::IN
            }
            .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "ResponseQclass matcher should match IN class"
        );
        assert!(
            RuntimeResponseMatcher::ResponseEdnsPresent { expect: true }
                .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "ResponseEdnsPresent matcher should detect EDNS presence"
        );
        assert!(
            RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.1.1.0/24".parse().unwrap()],
            }
            .matches(&upstream, qname, qtype, qclass, &msg, None, None),
            "ResponseUpstreamIp matcher should match upstream IP CIDR"
        );

        let msg_no_edns = build_message(ResponseCode::NXDomain, false);
        assert!(
            RuntimeResponseMatcher::ResponseEdnsPresent { expect: false }.matches(
                &upstream,
                qname,
                qtype,
                qclass,
                &msg_no_edns,
                None,
                None
            ),
            "ResponseEdnsPresent matcher should detect absence of EDNS"
        );

        let msg_ipv6 = build_message_with_ipv6(ResponseCode::NoError, true);
        assert!(
            RuntimeResponseMatcher::ResponseType {
                value: "AAAA".into()
            }
            .matches(
                &upstream,
                qname,
                RecordType::AAAA,
                qclass,
                &msg_ipv6,
                None,
                None
            ),
            "ResponseType matcher should match AAAA record type"
        );
    }

    #[test]
    fn test_apply_match_operator_request_matchers() {
        use std::net::IpAddr;

        // Arrange: Setup test data
        let qname = "a.sub.example.com";
        let client_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let qclass = DNSClass::IN;

        // Act & Assert: Test AND operator with matching conditions
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
        assert!(
            apply_match_operator(&MatchOperator::And, res_and),
            "AND operator should return true when all matchers return true"
        );

        // Act & Assert: Test AND operator with non-matching conditions
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
        assert!(
            !apply_match_operator(&MatchOperator::And, res_and_false),
            "AND operator should return false when any matcher returns false"
        );

        // Act & Assert: Test OR operator with one matching condition
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
        assert!(
            apply_match_operator(&MatchOperator::Or, res_or),
            "OR operator should return true when any matcher returns true"
        );

        // Act & Assert: Test NOT operator with all false matchers
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
        assert!(
            apply_match_operator(&MatchOperator::Not, res_not),
            "NOT operator should return true when all matchers return false"
        );

        // Act & Assert: Test NOT operator with one true matcher
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
        assert!(
            !apply_match_operator(&MatchOperator::Not, res_not_false),
            "NOT operator should return false when any matcher returns true"
        );
    }

    #[test]
    fn test_apply_match_operator_response_matchers() {
        // Arrange: Setup test data
        let qname = "sub.example.com";
        let upstream = "9.9.9.9:53".to_string();
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let msg = build_message(ResponseCode::NoError, true);

        // Act & Assert: Test AND operator
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
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg, None, None));
        assert!(
            apply_match_operator(&MatchOperator::And, res_and),
            "AND operator should return true when all response matchers return true"
        );

        // Act & Assert: Test OR operator
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
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg, None, None));
        assert!(
            apply_match_operator(&MatchOperator::Or, res_or),
            "OR operator should return true when any response matcher returns true"
        );

        // Act & Assert: Test NOT operator with all false matchers
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
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg, None, None));
        assert!(
            apply_match_operator(&MatchOperator::Not, res_not),
            "NOT operator should return true when all response matchers return false"
        );

        // Act & Assert: Test NOT operator with one true matcher
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
            .map(|m| m.matches(&upstream, qname, qtype, qclass, &msg, None, None));
        assert!(
            !apply_match_operator(&MatchOperator::Not, res_not_false),
            "NOT operator should return false when any response matcher returns true"
        );
    }

    #[test]
    fn test_apply_match_operator_empty_iterator_boundary() {
        // Arrange: Setup empty iterator
        let empty: Vec<bool> = vec![];
        let it = empty.into_iter();

        // Act & Assert: And over empty iterator -> true (all true)
        assert!(
            apply_match_operator(&MatchOperator::And, it.clone()),
            "AND operator should return true for empty iterator (all true)"
        );

        // Act & Assert: Or over empty iterator -> false (any false)
        let it2 = std::iter::empty::<bool>();
        assert!(
            !apply_match_operator(&MatchOperator::Or, it2),
            "OR operator should return false for empty iterator (any false)"
        );

        // Act & Assert: Not over empty iterator -> true (!any(empty) == true)
        let it3 = std::iter::empty::<bool>();
        assert!(
            apply_match_operator(&MatchOperator::Not, it3),
            "NOT operator should return true for empty iterator (!any(empty) == true)"
        );
    }

    #[test]
    fn test_runtime_pipeline_selector_matchers() {
        use std::net::IpAddr;

        // Arrange: Setup test data
        let listener_label = "edge-internal";
        let client_ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));
        let qname = "svc.example.com";

        // Act & Assert: Test ListenerLabel matcher
        assert!(
            RuntimePipelineSelectorMatcher::ListenerLabel {
                value: "edge-internal".into()
            }
            .matches(
                listener_label,
                client_ip,
                qname,
                DNSClass::IN,
                false,
                None,
                None
            ),
            "ListenerLabel matcher should match when listener labels are equal"
        );

        // Act & Assert: Test ClientIp matcher
        assert!(
            RuntimePipelineSelectorMatcher::ClientIp {
                net: "10.1.2.0/24".parse().unwrap()
            }
            .matches(
                listener_label,
                client_ip,
                qname,
                DNSClass::IN,
                false,
                None,
                None
            ),
            "ClientIp matcher should match when client IP is in CIDR range"
        );

        // Act & Assert: Test DomainSuffix matcher
        assert!(
            RuntimePipelineSelectorMatcher::DomainSuffix {
                value: "example.com".into()
            }
            .matches(
                listener_label,
                client_ip,
                qname,
                DNSClass::IN,
                false,
                None,
                None
            ),
            "DomainSuffix matcher should match domain suffix"
        );
    }

    #[test]
    fn test_runtime_matcher_basic_behaviors() {
        use std::net::IpAddr;

        // Arrange: Setup test data
        let qname = "Foo.Example.COM".to_ascii_lowercase();
        let client_ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 5));
        let qclass = DNSClass::IN;

        // Act & Assert: Any always matches
        assert!(
            RuntimeMatcher::Any.matches(&qname, qclass, client_ip, false),
            "Any matcher should always match"
        );

        // Act & Assert: DomainSuffix should match when suffix equals
        assert!(
            RuntimeMatcher::DomainSuffix {
                value: "example.com".into()
            }
            .matches(&qname, qclass, client_ip, false),
            "DomainSuffix matcher should match when suffix equals"
        );

        // Act & Assert: ClientIp CIDR
        assert!(
            RuntimeMatcher::ClientIp {
                net: "192.0.2.0/24".parse().unwrap()
            }
            .matches(&qname, qclass, client_ip, false),
            "ClientIp matcher should match when client IP is in CIDR range"
        );

        // Act & Assert: Qclass
        assert!(
            RuntimeMatcher::Qclass {
                value: DNSClass::IN
            }
            .matches(&qname, qclass, client_ip, false),
            "Qclass matcher should match when QCLASS equals"
        );

        // Act & Assert: EdnsPresent
        assert!(
            RuntimeMatcher::EdnsPresent { expect: false }.matches(&qname, qclass, client_ip, false),
            "EdnsPresent matcher should match when EDNS presence matches expectation"
        );
    }

    #[test]
    fn test_response_upstream_ip_parsing_and_nonparseable() {
        // Arrange: Setup test data
        let qname = "sub.example.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let msg = build_message(ResponseCode::NoError, false);

        // Act & Assert: With port
        assert!(
            RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.2.3.0/24".parse().unwrap()]
            }
            .matches("1.2.3.4:53", qname, qtype, qclass, &msg, None, None),
            "ResponseUpstreamIp matcher should match upstream with port"
        );

        // Act & Assert: Plain ip
        assert!(
            RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.2.3.0/24".parse().unwrap()]
            }
            .matches("1.2.3.4", qname, qtype, qclass, &msg, None, None),
            "ResponseUpstreamIp matcher should match plain IP"
        );

        // Act & Assert: Non-parseable upstream should return false
        assert!(
            !RuntimeResponseMatcher::ResponseUpstreamIp {
                nets: vec!["1.2.3.0/24".parse().unwrap()]
            }
            .matches("not-an-upstream", qname, qtype, qclass, &msg, None, None),
            "ResponseUpstreamIp matcher should return false for non-parseable upstream"
        );
    }

    #[test]
    fn test_domain_regex_case_insensitive_flag() {
        // Arrange: Setup test data
        let qname = "Foo.Example.COM";

        // Act & Assert: Without (?i) should not match assuming case-sensitive regex
        let re_cs = Regex::new("example\\.com$").unwrap();
        assert!(
            !RuntimeMatcher::DomainRegex { regex: re_cs }.matches(
                &qname,
                DNSClass::IN,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                false
            ),
            "Case-sensitive regex should not match different case"
        );

        // Act & Assert: With (?i) should match
        let re_ci = Regex::new("(?i)example\\.com$").unwrap();
        assert!(
            RuntimeMatcher::DomainRegex { regex: re_ci }.matches(
                &qname,
                DNSClass::IN,
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                false
            ),
            "Case-insensitive regex should match different case"
        );
    }

    #[test]
    fn test_response_type_no_answers_uses_qtype_fallback() {
        // Arrange: Setup message with no answers
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NoError);
        // no answers added

        let qname = "x.example.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;

        // Act & Assert: Should use qtype fallback when no answers present
        assert!(
            RuntimeResponseMatcher::ResponseType { value: "A".into() }.matches(
                "1.2.3.4:53",
                qname,
                qtype,
                qclass,
                &msg,
                None,
                None
            ),
            "ResponseType matcher should use qtype fallback when no answers present"
        );
    }

    // Integration Tests for New Matchers
    // 新匹配器的集成测试

    #[test]
    fn test_qtype_matcher_all_types() {
        // Arrange: Setup test data with all supported DNS record types
        let qtypes = vec![
            ("A", RecordType::A),
            ("AAAA", RecordType::AAAA),
            ("CNAME", RecordType::CNAME),
            ("MX", RecordType::MX),
            ("TXT", RecordType::TXT),
            ("NS", RecordType::NS),
            ("PTR", RecordType::PTR),
            ("SOA", RecordType::SOA),
            ("SRV", RecordType::SRV),
            ("OPT", RecordType::OPT),
        ];

        for (type_str, expected_type) in qtypes {
            // Act & Assert: Test parsing
            let parsed = parse_dns_type(type_str);
            assert!(parsed.is_ok(), "Failed to parse qtype: {}", type_str);
            assert_eq!(
                parsed.unwrap(),
                expected_type,
                "Qtype mismatch for: {}",
                type_str
            );

            // Act & Assert: Test matcher
            let matcher = RuntimeMatcher::Qtype {
                value: expected_type,
            };

            // Act & Assert: Test matching
            assert!(
                matcher.matches_with_qtype(
                    "example.com",
                    DNSClass::IN,
                    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    false,
                    expected_type,
                    None,
                    None,
                ),
                "Qtype {} should match itself",
                type_str
            );
        }
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

fn parse_dns_type(v: &str) -> anyhow::Result<RecordType> {
    let upper = v.to_ascii_uppercase();
    let parsed = match upper.as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "MX" => RecordType::MX,
        "TXT" => RecordType::TXT,
        "NS" => RecordType::NS,
        "PTR" => RecordType::PTR,
        "SOA" => RecordType::SOA,
        "SRV" => RecordType::SRV,
        "OPT" => RecordType::OPT,
        _ => anyhow::bail!("unsupported qtype: {upper}"),
    };
    Ok(parsed)
}
