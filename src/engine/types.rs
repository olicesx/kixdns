use std::time::Instant;
use std::sync::Arc;
use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use tokio::sync::watch;
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::advanced_rule::CompiledPipeline;

pub type InflightMap = DashMap<u64, watch::Sender<Result<Bytes, Arc<anyhow::Error>>>, FxBuildHasher>;

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
    },
}

pub struct EngineInner {
    pub pipeline: RuntimePipelineConfig,
    pub compiled_pipelines: Vec<CompiledPipeline>,
}
