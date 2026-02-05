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
#[derive(Debug, Clone)]
pub enum FastPathResponse {
    Direct(Bytes),
    CacheHit { 
        cached: Bytes, 
        tx_id: u16,
        /// Insertion time for TTL calculation / 用于TTL计算的插入时间
        inserted_at: Instant,
    },
}

pub struct EngineInner {
    pub pipeline: RuntimePipelineConfig,
    pub compiled_pipelines: Vec<CompiledPipeline>,
}
