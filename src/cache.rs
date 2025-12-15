use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::ResponseCode;
use moka::sync::Cache;

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub bytes: Bytes,
    pub rcode: ResponseCode,
    pub source: Arc<str>,
    // Store validation fields to handle hash collisions / 存储验证字段以处理哈希冲突
    pub qname: Arc<str>,
    pub pipeline_id: Arc<str>,
    pub qtype: u16,
}

/// Use u64 hash as key to avoid allocation during lookup / 使用 u64 哈希作为键以避免查找时的内存分配
pub type DnsCache = Cache<u64, CacheEntry>;

/// 创建带 TTL 的 DNS 缓存 / Create DNS cache with TTL
#[inline]
pub fn new_cache(max_capacity: u64, ttl_secs: u64) -> DnsCache {
    Cache::builder()
        .max_capacity(max_capacity)
        .time_to_live(Duration::from_secs(ttl_secs))
        .build()
}
