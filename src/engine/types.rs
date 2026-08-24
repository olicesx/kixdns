use crate::matcher::RuntimePipelineConfig;
use crate::matcher::advanced_rule::CompiledPipeline;
use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::{FxBuildHasher, FxHashMap};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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
            format!("{:?}", cfg.settings).hash(&mut hasher);
            format!("{:?}", pipeline).hash(&mut hasher);
            (pipeline.id.clone(), hasher.finish())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::build_cache_namespaces;
    use crate::config::PipelineConfig;
    use crate::matcher::RuntimePipelineConfig;

    fn runtime_config(first_upstream: &str, second_upstream: &str) -> RuntimePipelineConfig {
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "first",
                    "rules": [{
                        "name": "forward-first",
                        "matchers": [{ "type": "any" }],
                        "actions": [{ "type": "forward", "upstream": first_upstream }]
                    }]
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
        let second = runtime_config("8.8.8.8:53", "9.9.9.9:53");

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
