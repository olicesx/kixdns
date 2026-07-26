use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use hickory_proto::op::ResponseCode;
use moka::sync::Cache;

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub bytes: Bytes,
    pub rcode: ResponseCode,
    /// Upstream that provided this response / 提供此响应的上游服务器
    pub upstream: Option<Arc<str>>,
    // Store validation fields to handle hash collisions / 存储验证字段以处理哈希冲突
    pub qname: Arc<str>,
    pub pipeline_id: Arc<str>,
    pub qtype: u16,
    /// RFC 1035 §5.2: Record insertion time for TTL decrement / RFC 1035 §5.2：记录插入时间用于TTL递减
    pub inserted_at: Instant,
    /// Original minimum TTL from upstream response / 上游响应的原始最小TTL
    /// Used for cache expiration and TTL patching / 用于缓存过期与 TTL 修正
    pub original_ttl: u32,
    /// Original maximum TTL from upstream response / 上游响应的原始最大TTL
    /// Used for background refresh decisions / 用于后台刷新决策
    pub refresh_ttl: u32,
}

impl CacheEntry {
    /// Derive source label from upstream field / 从 upstream 字段推导来源标签
    pub fn source(&self) -> &str {
        match &self.upstream {
            Some(u) => u.as_ref(),
            None => "static",
        }
    }

    /// Build a cache entry from a DNS response and its cache/refresh TTLs.
    pub fn from_response(
        bytes: Bytes,
        rcode: ResponseCode,
        upstream: Option<Arc<str>>,
        qname: &str,
        pipeline_id: Arc<str>,
        qtype: u16,
        ttls: (u32, u32),
    ) -> Self {
        Self {
            bytes,
            rcode,
            upstream,
            qname: Arc::from(qname),
            pipeline_id,
            qtype,
            inserted_at: Instant::now(),
            original_ttl: ttls.0,
            refresh_ttl: ttls.1,
        }
    }

    /// Clone entry with a refreshed `inserted_at` for serve-stale TTL reset / 克隆条目并刷新 inserted_at 用于过期缓存 TTL 重置
    /// Sets `inserted_at` to `now - original_ttl` so the entry appears freshly expired / 将 inserted_at 设置为 now - original_ttl，使条目看上去刚刚过期
    pub fn clone_with_refreshed_ttl(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            rcode: self.rcode,
            upstream: self.upstream.clone(),
            qname: self.qname.clone(),
            pipeline_id: self.pipeline_id.clone(),
            qtype: self.qtype,
            inserted_at: Instant::now() - Duration::from_secs(self.original_ttl as u64),
            original_ttl: self.original_ttl,
            refresh_ttl: self.refresh_ttl,
        }
    }
}

/// Use u64 hash as key to avoid allocation during lookup / 使用 u64 哈希作为键以避免查找时的内存分配
///  Performance: Wrap in Arc to reduce atomic operations from 5 to 1 per cache hit
///  性能优化：使用 Arc 包裹，将缓存命中的原子操作从 5 次减少到 1 次
pub type DnsCache = Cache<u64, Arc<CacheEntry>>;

/// 创建带 TTL 的 DNS 缓存 / Create DNS cache with TTL
#[inline]
pub fn new_cache(max_capacity: u64, ttl_secs: u64) -> DnsCache {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(Duration::from_secs(ttl_secs))
        .build()
}
