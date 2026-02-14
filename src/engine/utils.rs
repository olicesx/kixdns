use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use hickory_proto::op::{Message, ResponseCode, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, RecordType, Name};
use bytes::Bytes;
use crate::matcher::RuntimePipelineConfig;
use hickory_proto::serialize::binary::{BinEncoder, BinEncodable};
use super::types::InflightMap;

/// RAII Guard for cleaning up inflight request map
/// 为清理进行中请求映射的 RAII Guard
pub struct InflightCleanupGuard {
    pub inflight: Arc<InflightMap>,
    pub hash: u64,
    pub active: bool,
}

impl InflightCleanupGuard {
    pub fn new(inflight: Arc<InflightMap>, hash: u64) -> Self {
        Self { inflight, hash, active: true }
    }
    
    pub fn defuse(&mut self) {
        self.active = false;
    }
}

impl Drop for InflightCleanupGuard {
    fn drop(&mut self) {
        if self.active {
            self.inflight.remove(&self.hash);
        }
    }
}

// ============================================================================
// Engine Helper Functions / 引擎辅助函数
// ============================================================================

/// 引擎辅助函数模块 - 提供可复用的引擎逻辑 / Engine helper functions module - provides reusable engine logic
pub mod engine_helpers {
    use super::*;

    pub fn build_response(req: &Message, rcode: ResponseCode, answers: Vec<hickory_proto::rr::Record>) -> anyhow::Result<Bytes> {
        let mut msg = Message::new();
        msg.set_id(req.id());
        msg.set_message_type(hickory_proto::op::MessageType::Response);
        msg.set_op_code(req.op_code());
        msg.set_response_code(rcode);
        msg.set_recursion_desired(req.recursion_desired());
        msg.set_recursion_available(true);
        msg.add_queries(req.queries().iter().cloned());
        msg.insert_answers(answers);
        
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);
        msg.emit(&mut encoder)?;
        Ok(Bytes::from(buf))
    }

    /// 构建错误响应（ServFail）
    /// Build error response (ServFail)
    #[inline]
    pub fn build_servfail_response(req: &Message) -> anyhow::Result<Bytes> {
        build_response(req, ResponseCode::ServFail, Vec::new())
    }

    /// 快速构建错误响应（ServFail），避免解析完整请求
    /// Fast build ServFail response without parsing full request
    #[inline]
    pub fn build_servfail_response_fast(
        tx_id: u16,
        qname: &str,
        qtype: u16,
        qclass: u16,
        rd: bool,
    ) -> anyhow::Result<Bytes> {
        let mut msg = Message::new();
        msg.set_id(tx_id);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::ServFail);
        msg.set_recursion_desired(rd);
        msg.set_recursion_available(true);

        let name = Name::from_str(qname)?;
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(RecordType::from(qtype));
        query.set_query_class(DNSClass::from(qclass));
        msg.add_query(query);

        let mut buf = Vec::with_capacity(128);
        let mut encoder = BinEncoder::new(&mut buf);
        msg.emit(&mut encoder)?;
        Ok(Bytes::from(buf))
    }

    /// 构建拒绝响应（Refused）
    /// Build refused response (Refused)
    #[inline]
    pub fn build_refused_response(req: &Message) -> anyhow::Result<Bytes> {
        build_response(req, ResponseCode::Refused, Vec::new())
    }
}

// ============================================================================
// Refreshing Bitmap Helpers / 刷新位图辅助函数
// ============================================================================

/// 检查缓存哈希是否正在刷新（零锁读取） / Check if a cache hash is currently being refreshed (zero-lock read)
#[inline]
pub fn is_refreshing(bitmap: &AtomicU64, cache_hash: u64) -> bool {
    let bit_index = cache_hash % 64;
    let mask = 1u64 << bit_index;
    bitmap.load(Ordering::Relaxed) & mask != 0
}

/// 标记缓存哈希为正在刷新（零锁写入） / Mark a cache hash as being refreshed (zero-lock write)
#[inline]
pub fn mark_refreshing(bitmap: &AtomicU64, cache_hash: u64) {
    let bit_index = cache_hash % 64;
    let mask = 1u64 << bit_index;
    bitmap.fetch_or(mask, Ordering::Relaxed);
}

/// 清除缓存哈希的刷新标记（零锁写入） / Clear the refreshing mark for a cache hash (zero-lock write)
#[inline]
pub fn clear_refreshing(bitmap: &AtomicU64, cache_hash: u64) {
    let bit_index = cache_hash % 64;
    let mask = 1u64 << bit_index;
    bitmap.fetch_and(!mask, Ordering::Relaxed);
}

/// RAII Guard for auto-clearing the refreshing bitmap
/// RAII Guard 用于自动清除刷新位图标记
pub struct RefreshingGuard {
    bitmap: Option<Arc<AtomicU64>>,
    cache_hash: Option<u64>,
}

impl RefreshingGuard {
    /// Create a new guard that will clear the refresh mark on drop
    /// 创建一个在 drop 时清除刷新标记的 guard
    pub fn new(bitmap: &Arc<AtomicU64>, cache_hash: u64) -> Self {
        mark_refreshing(bitmap, cache_hash);
        Self {
            bitmap: Some(Arc::clone(bitmap)),
            cache_hash: Some(cache_hash),
        }
    }

    /// Defuse the guard so it won't clear the mark on drop
    /// 让 guard 失效，drop 时不会清除标记
    pub fn defuse(&mut self) {
        self.bitmap = None;
        self.cache_hash = None;
    }

    /// Manually clear the refresh mark early
    /// 手动提前清除刷新标记
    pub fn clear(&mut self) {
        if let (Some(bitmap), Some(hash)) = (&self.bitmap, self.cache_hash) {
            clear_refreshing(bitmap, hash);
        }
        self.defuse();
    }
}

impl Drop for RefreshingGuard {
    fn drop(&mut self) {
        if let (Some(bitmap), Some(hash)) = (&self.bitmap, self.cache_hash) {
            clear_refreshing(bitmap, hash);
        }
    }
}

/// 提取配置中使用的 GeoSite tags / Extract GeoSite tags used in configuration
///
/// 扫描配置以查找所有在匹配器中实际使用的GeoSite标签，这样可以只从数据文件中加载这些标签 / Scans the configuration to find all GeoSite tags actually used in matchers, so we can load only those tags from the data file.
pub fn extract_geosite_tags_from_config(cfg: &RuntimePipelineConfig) -> Vec<String> {
    
    let mut tags_set: HashSet<std::sync::Arc<str>> = HashSet::new();

    // Scan pipeline_select rules / 扫描 pipeline_select 规则
    for rule in &cfg.pipeline_select {
        for matcher in &rule.matchers {
            if let crate::matcher::RuntimePipelineSelectorMatcher::GeoSite { tag } = &matcher.matcher {
                tags_set.insert(tag.clone());
            }
            if let crate::matcher::RuntimePipelineSelectorMatcher::GeoSiteNot { tag } = &matcher.matcher {
                tags_set.insert(tag.clone());
            }
        }
    }

    // Scan all pipeline rules / 扫描所有 pipeline 规则
    for pipeline in &cfg.pipelines {
        for rule in &pipeline.rules {
            // Scan request matchers / 扫描请求匹配器
            for matcher in &rule.matchers {
                if let crate::matcher::RuntimeMatcher::GeoSite { tag } = &matcher.matcher {
                    tags_set.insert(tag.clone());
                }
                if let crate::matcher::RuntimeMatcher::GeoSiteNot { tag } = &matcher.matcher {
                    tags_set.insert(tag.clone());
                }
            }

            // Scan response matchers / 扫描响应匹配器
            for matcher in &rule.response_matchers {
                if let crate::matcher::RuntimeResponseMatcher::ResponseRequestDomainGeoSite { value } = &matcher.matcher {
                    tags_set.insert(value.clone());
                }
                if let crate::matcher::RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot { value } = &matcher.matcher {
                    tags_set.insert(value.clone());
                }
            }
        }
    }

    tags_set.into_iter().map(|s| s.to_string()).collect()
}

/// 检查配置是否使用 GeoIP 匹配器 / Check if configuration uses GeoIP matchers
///
/// 扫描配置以确定是否使用了GeoIP匹配器，这样我们可以对MMDB文件实现延迟加载 / Scans the configuration to determine if any GeoIP matchers are used, so we can implement lazy loading for the MMDB file.
pub fn uses_geoip_matchers(cfg: &RuntimePipelineConfig) -> bool {
    // Scan all pipeline rules / 扫描所有 pipeline 规则
    for pipeline in &cfg.pipelines {
        for rule in &pipeline.rules {
            // Check request matchers / 检查请求匹配器
            for matcher in &rule.matchers {
                if matches!(
                    matcher.matcher,
                    crate::matcher::RuntimeMatcher::GeoipCountry { .. } |
                    crate::matcher::RuntimeMatcher::GeoipPrivate { .. }
                ) {
                    return true;
                }
            }

            // Check response matchers / 检查响应匹配器
            for matcher in &rule.response_matchers {
                if matches!(
                    matcher.matcher,
                    crate::matcher::RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry { .. } |
                    crate::matcher::RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { .. }
                ) {
                    return true;
                }
            }
        }
    }

    false
}
