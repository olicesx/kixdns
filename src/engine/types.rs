use crate::config::{Action, EcsMode, GlobalSettings, MatchOperator};
use crate::matcher::advanced_rule::CompiledPipeline;
use crate::matcher::{
    RuntimeMatcher, RuntimePipeline, RuntimePipelineConfig, RuntimeResponseMatcher,
};
use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::mem::discriminant;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

pub type InflightMap =
    DashMap<u64, watch::Sender<Result<Bytes, Arc<anyhow::Error>>>, FxBuildHasher>;

// ============================================================================
// Fast-path Response / 快速路径响应
// ============================================================================
///
/// - `Direct`: already has correct TXID and can be sent as-is.
/// - `CacheHit`: carries cached bytes (with an old TXID) and the request TXID to patch.
///   Also includes insertion time and original TTL for RFC 1035 §5.2 compliance.
/// - `AsyncNeeded`: cache miss, needs async processing. Contains pre-parsed data to avoid re-parsing.
#[derive(Debug, Clone)]
pub enum FastPathResponse {
    Direct(Bytes),
    CacheHit {
        cached: Bytes,
        tx_id: u16,
        /// Insertion time for TTL calculation / 用于TTL计算的插入时间
        inserted_at: Instant,
    },
    /// Cache miss, needs async processing. Contains pre-parsed data to avoid re-parsing in handle_packet.
    /// 缓存未命中，需要异步处理。包含预解析数据以避免在 handle_packet 中重新解析。
    AsyncNeeded {
        /// Pre-parsed query data to avoid re-parsing / 预解析的查询数据，避免重新解析
        qname: String,
        qtype: u16,
        qclass: u16,
        tx_id: u16,
        edns_present: bool,
        /// Pre-selected pipeline ID to avoid re-selecting / 预选择的 pipeline ID，避免重新选择
        pipeline_id: Arc<str>,
        /// Pre-computed ECS cache key from fast path, avoids recomputation in handle_packet_internal
        /// 快速路径预计算的 ECS 缓存键，避免在 handle_packet_internal 中重新计算
        ecs_key: Option<crate::ecs::EcsKey>,
    },
}

pub struct EngineInner {
    pub pipeline: RuntimePipelineConfig,
    pub compiled_pipelines: Vec<CompiledPipeline>,
    /// O(1) pipeline lookup index: pipeline_id -> index in compiled_pipelines / O(1) 管道查找索引：pipeline_id -> compiled_pipelines 中的索引
    pub pipeline_index: FxHashMap<Arc<str>, usize>,
    /// Response-affecting configuration fingerprint for each pipeline.
    /// It namespaces response/rule/inflight caches across hot reloads while
    /// allowing unchanged pipelines to keep their warm cache entries.
    pub cache_namespaces: FxHashMap<Arc<str>, u64>,
}

impl EngineInner {
    #[inline]
    pub(crate) fn cache_namespace(&self, pipeline_id: &str) -> u64 {
        self.cache_namespaces
            .get(pipeline_id)
            .copied()
            .unwrap_or_default()
    }
}

pub(crate) fn build_cache_namespaces(cfg: &RuntimePipelineConfig) -> FxHashMap<Arc<str>, u64> {
    cfg.pipelines
        .iter()
        .map(|pipeline| {
            let mut hasher = DefaultHasher::new();
            // Global settings can affect forwarding, TTL handling and response
            // processing, so they are part of every pipeline namespace.
            hash_global_settings_semantics(&cfg.settings, &mut hasher);
            hash_pipeline_semantics(pipeline, &mut hasher);
            (pipeline.id.clone(), hasher.finish())
        })
        .collect()
}

fn hash_global_settings_semantics(settings: &GlobalSettings, hasher: &mut impl Hasher) {
    let GlobalSettings {
        min_ttl,
        bind_udp,
        bind_tcp,
        bind_doh,
        doh_tls_cert,
        doh_tls_key,
        doh_path,
        cache_capacity,
        cache_max_ttl,
        dashmap_shards,
        default_upstream,
        default_upstream_pre_split: _,
        upstream_timeout_ms,
        request_timeout_ms,
        response_jump_limit,
        udp_pool_size,
        tcp_pool_size,
        doh_pool_size,
        doh_health_check_error_threshold,
        dot_pool_size,
        doq_pool_size,
        tcp_health_check_error_threshold,
        tcp_connection_max_age_seconds,
        tcp_connection_idle_timeout_seconds,
        doq_connection_idle_timeout_seconds,
        doq_keepalive_interval_ms,
        doq_enable_0rtt,
        flow_control_enabled,
        flow_control_initial_permits,
        flow_control_min_permits,
        flow_control_max_permits,
        flow_control_latency_threshold_ms,
        flow_control_adjustment_interval_secs,
        serve_stale,
        serve_stale_ttl,
        serve_stale_expire_ttl,
        serve_stale_ttl_reset,
        serve_stale_client_timeout_ms,
        cache_background_refresh,
        cache_refresh_threshold_percent,
        cache_refresh_min_ttl,
        geoip_db_path,
        geoip_dat_path,
        geoip_auto_convert,
        geoip_filter_countries,
        geosite_data_paths,
        enable_tcp_fallback,
    } = settings;

    (
        min_ttl,
        bind_udp,
        bind_tcp,
        bind_doh,
        doh_tls_cert,
        doh_tls_key,
        doh_path,
        cache_capacity,
        cache_max_ttl,
        dashmap_shards,
        default_upstream,
    )
        .hash(hasher);
    (
        upstream_timeout_ms,
        request_timeout_ms,
        response_jump_limit,
        udp_pool_size,
        tcp_pool_size,
        doh_pool_size,
        doh_health_check_error_threshold,
        dot_pool_size,
        doq_pool_size,
    )
        .hash(hasher);
    (
        tcp_health_check_error_threshold,
        tcp_connection_max_age_seconds,
        tcp_connection_idle_timeout_seconds,
        doq_connection_idle_timeout_seconds,
        doq_keepalive_interval_ms,
        doq_enable_0rtt,
        flow_control_enabled,
        flow_control_initial_permits,
        flow_control_min_permits,
        flow_control_max_permits,
        flow_control_latency_threshold_ms,
    )
        .hash(hasher);
    (
        flow_control_adjustment_interval_secs,
        serve_stale,
        serve_stale_ttl,
        serve_stale_expire_ttl,
        serve_stale_ttl_reset,
        serve_stale_client_timeout_ms,
        cache_background_refresh,
        cache_refresh_threshold_percent,
        cache_refresh_min_ttl,
    )
        .hash(hasher);
    (
        geoip_db_path,
        geoip_dat_path,
        geoip_auto_convert,
        geoip_filter_countries,
        geosite_data_paths,
        enable_tcp_fallback,
    )
        .hash(hasher);
}

fn hash_pipeline_semantics(pipeline: &RuntimePipeline, hasher: &mut impl Hasher) {
    pipeline.id.hash(hasher);
    hash_ecs_mode(pipeline.ecs.as_ref(), hasher);
    pipeline.rules.len().hash(hasher);
    for rule in &pipeline.rules {
        rule.name.hash(hasher);
        hash_match_operator(rule.matcher_operator, hasher);
        rule.matchers.len().hash(hasher);
        for matcher in &rule.matchers {
            hash_match_operator(matcher.operator, hasher);
            hash_runtime_matcher(&matcher.matcher, hasher);
        }
        rule.actions.len().hash(hasher);
        for action in &rule.actions {
            hash_action(action, hasher);
        }
        rule.response_matchers.len().hash(hasher);
        for matcher in &rule.response_matchers {
            hash_match_operator(matcher.operator, hasher);
            hash_runtime_response_matcher(&matcher.matcher, hasher);
        }
        hash_match_operator(rule.response_matcher_operator, hasher);
        rule.response_actions_on_match.len().hash(hasher);
        for action in &rule.response_actions_on_match {
            hash_action(action, hasher);
        }
        rule.response_actions_on_miss.len().hash(hasher);
        for action in &rule.response_actions_on_miss {
            hash_action(action, hasher);
        }
    }
}

fn hash_match_operator(operator: MatchOperator, hasher: &mut impl Hasher) {
    discriminant(&operator).hash(hasher);
}

fn hash_ecs_mode(mode: Option<&EcsMode>, hasher: &mut impl Hasher) {
    mode.is_some().hash(hasher);
    let Some(mode) = mode else {
        return;
    };
    discriminant(mode).hash(hasher);
    match mode {
        EcsMode::Clear => {}
        EcsMode::FromClientIp {
            prefix_v4,
            prefix_v6,
        } => {
            prefix_v4.hash(hasher);
            prefix_v6.hash(hasher);
        }
        EcsMode::Static { ip, prefix } => {
            ip.hash(hasher);
            prefix.hash(hasher);
        }
    }
}

fn hash_action(action: &Action, hasher: &mut impl Hasher) {
    discriminant(action).hash(hasher);
    match action {
        Action::Log { level } => level.hash(hasher),
        Action::StaticResponse { rcode } => rcode.hash(hasher),
        Action::StaticIpResponse { ip } => ip.hash(hasher),
        Action::StaticCnameResponse { target, ttl } => {
            target.hash(hasher);
            ttl.hash(hasher);
        }
        Action::StaticTxtResponse { text, ttl } => {
            text.hash(hasher);
            ttl.hash(hasher);
        }
        Action::JumpToPipeline { pipeline } => pipeline.hash(hasher),
        Action::Forward {
            upstream,
            transport,
            ecs,
            ..
        } => {
            upstream.hash(hasher);
            transport.hash(hasher);
            hash_ecs_mode(ecs.as_ref(), hasher);
        }
        Action::ReplaceTxtResponse { text } => text.hash(hasher),
        Action::Allow | Action::Deny | Action::Continue => {}
    }
}

fn hash_runtime_matcher(matcher: &RuntimeMatcher, hasher: &mut impl Hasher) {
    discriminant(matcher).hash(hasher);
    match matcher {
        RuntimeMatcher::Any => {}
        RuntimeMatcher::DomainExact { value } | RuntimeMatcher::DomainSuffix { value } => {
            value.hash(hasher)
        }
        RuntimeMatcher::ClientIp { net } => net.hash(hasher),
        RuntimeMatcher::DomainRegex { regex } => regex.as_str().hash(hasher),
        RuntimeMatcher::GeoipCountry { country_codes } => country_codes.hash(hasher),
        RuntimeMatcher::GeoipPrivate { expect } | RuntimeMatcher::EdnsPresent { expect } => {
            expect.hash(hasher)
        }
        RuntimeMatcher::Qclass { value } => u16::from(*value).hash(hasher),
        RuntimeMatcher::GeoSite { tag } | RuntimeMatcher::GeoSiteNot { tag } => tag.hash(hasher),
        RuntimeMatcher::Qtype { value } => u16::from(*value).hash(hasher),
    }
}

fn hash_runtime_response_matcher(matcher: &RuntimeResponseMatcher, hasher: &mut impl Hasher) {
    discriminant(matcher).hash(hasher);
    match matcher {
        RuntimeResponseMatcher::UpstreamEquals { value }
        | RuntimeResponseMatcher::RequestDomainSuffix { value }
        | RuntimeResponseMatcher::ResponseRequestDomainGeoSite { value }
        | RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot { value } => value.hash(hasher),
        RuntimeResponseMatcher::RequestDomainRegex { regex } => regex.as_str().hash(hasher),
        RuntimeResponseMatcher::ResponseUpstreamIp { nets }
        | RuntimeResponseMatcher::ResponseAnswerIp { nets } => nets.hash(hasher),
        RuntimeResponseMatcher::ResponseType { value } => u16::from(*value).hash(hasher),
        RuntimeResponseMatcher::ResponseRcode { value } => value.hash(hasher),
        RuntimeResponseMatcher::ResponseQclass { value } => u16::from(*value).hash(hasher),
        RuntimeResponseMatcher::ResponseEdnsPresent { expect }
        | RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { expect } => expect.hash(hasher),
        RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry { country_codes } => {
            country_codes.hash(hasher)
        }
        RuntimeResponseMatcher::ResponseTxtContent { mode, value, .. } => {
            discriminant(mode).hash(hasher);
            value.hash(hasher);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build_cache_namespaces;
    use crate::config::PipelineConfig;
    use crate::matcher::RuntimePipelineConfig;
    use hickory_proto::rr::RecordType;
    use std::sync::Arc;

    fn runtime_config(first_upstream: &str, second_upstream: &str) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "first",
                    "rules": [
                        {
                            "name": "forward-first-indexed",
                            "matchers": [
                                { "type": "domain_suffix", "value": "www.example.com" },
                                { "type": "qtype", "value": "A" }
                            ],
                            "actions": [{ "type": "forward", "upstream": first_upstream }]
                        },
                        {
                            "name": "forward-first-suffix",
                            "matchers": [{ "type": "domain_suffix", "value": "example.com" }],
                            "actions": [{ "type": "forward", "upstream": first_upstream }]
                        },
                        {
                            "name": "forward-first-regex",
                            "matchers": [{ "type": "domain_regex", "value": "^api[0-9]+\\.example\\.com$" }],
                            "actions": [{ "type": "forward", "upstream": first_upstream }]
                        }
                    ]
                },
                {
                    "id": "second",
                    "rules": [{
                        "name": "forward-second",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": second_upstream }]
                    }]
                }
            ]
        });
        let config: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        RuntimePipelineConfig::from_config(config).expect("build runtime config")
    }

    #[test]
    fn namespace_is_stable_for_identical_configuration() {
        let first = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let mut second = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        second.settings.default_upstream_pre_split = Some(Arc::new(vec![Arc::from("derived")]));
        // Derived lookup indexes are deliberately excluded from the semantic
        // fingerprint. Mutating them must not rotate a cache namespace.
        second.pipelines[0]
            .domain_exact_index
            .insert(Arc::from("derived.example"), vec![0]);
        second.pipelines[0]
            .domain_suffix_index
            .insert(Arc::from("derived.example"), vec![1]);
        second.pipelines[0]
            .query_type_index
            .insert(RecordType::AAAA, vec![2]);

        assert_eq!(
            build_cache_namespaces(&first),
            build_cache_namespaces(&second)
        );
    }

    #[test]
    fn changing_one_pipeline_only_changes_its_namespace() {
        let before = build_cache_namespaces(&runtime_config("8.8.8.8:53", "9.9.9.9:53"));
        let after = build_cache_namespaces(&runtime_config("8.8.4.4:53", "9.9.9.9:53"));

        assert_ne!(before.get("first"), after.get("first"));
        assert_eq!(before.get("second"), after.get("second"));
    }

    #[test]
    fn global_response_setting_changes_all_namespaces() {
        let before_config = runtime_config("8.8.8.8:53", "9.9.9.9:53");
        let mut after_config = before_config.clone();
        after_config.settings.default_upstream = "1.0.0.1:53".to_string();
        let before = build_cache_namespaces(&before_config);
        let after = build_cache_namespaces(&after_config);

        assert_ne!(before.get("first"), after.get("first"));
        assert_ne!(before.get("second"), after.get("second"));
    }
}
