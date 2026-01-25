use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::op::ResponseCode;
use moka::sync::Cache;

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub bytes: Bytes,
    pub rcode: ResponseCode,
    pub source: Arc<str>,
    /// Upstream that provided this response / 提供此响应的上游服务器
    pub upstream: Option<Arc<str>>,
    // Store validation fields to handle hash collisions / 存储验证字段以处理哈希冲突
    pub qname: Arc<str>,
    pub pipeline_id: Arc<str>,
    pub qtype: u16,
    /// RFC 1035 §5.2: Record insertion time for TTL decrement / RFC 1035 §5.2：记录插入时间用于TTL递减
    pub inserted_at: Instant,
    /// Original minimum TTL from upstream response / 上游响应的原始最小TTL
    pub original_ttl: u32,
}

/// Use u64 hash as key to avoid allocation during lookup / 使用 u64 哈希作为键以避免查找时的内存分配
/// ✅ Performance: Wrap in Arc to reduce atomic operations from 5 to 1 per cache hit
/// ✅ 性能优化：使用 Arc 包裹，将缓存命中的原子操作从 5 次减少到 1 次
pub type DnsCache = Cache<u64, Arc<CacheEntry>>;

/// 创建带 TTL 的 DNS 缓存 / Create DNS cache with TTL
#[inline]
pub fn new_cache(max_capacity: u64, ttl_secs: u64) -> DnsCache {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(Duration::from_secs(ttl_secs))
        .build()
}
