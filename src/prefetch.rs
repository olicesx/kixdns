//! DNS 预取模块
//!
//! 实现基于热度的域名预取功能，参考 RFC 1034/1035 的缓存机制

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use moka::sync::Cache;
use rustc_hash::{FxBuildHasher, FxHasher};
use tokio::sync::OwnedSemaphorePermit;
use tokio::sync::Semaphore;

use crate::cache::CacheEntry;

/// 预取条目，记录域名的访问统计
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PrefetchEntry {
    pub qname: Arc<str>,
    pub qtype: u16,
    pub upstream: Arc<str>,
    pub access_count: u64,
    pub last_access: Instant,
    pub first_access: Instant,
}

/// 预取配置
#[derive(Debug, Clone)]
pub struct PrefetchConfig {
    pub enabled: bool,

    /// 热度阈值（访问次数）
    pub hot_threshold: u64,

    /// 预取并发数
    pub concurrency: usize,

    /// 预取间隔（避免频繁预取）
    pub min_interval: Duration,

    /// 查询 A 时是否预取 AAAA
    pub ipv6_on_ipv4_enabled: bool,

    /// 查询主域名时是否预取 CDN 域名
    pub cdn_prefetch_enabled: bool,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hot_threshold: 10,
            concurrency: 5,
            min_interval: Duration::from_secs(30),
            ipv6_on_ipv4_enabled: true,
            cdn_prefetch_enabled: true,
        }
    }
}

const CDN_RELATION_CACHE_CAPACITY: u64 = 10_000;
const CDN_RELATION_TTL_SECS: u64 = 600;
const CNAME_CHAIN_LIMIT: usize = 8;
const CNAME_RELATION_LIMIT: usize = 32;

/// 预取任务
#[derive(Debug, Clone)]
pub struct PrefetchJob {
    pub pipeline_id: Arc<str>,
    pub qname: Arc<str>,
    pub qtype: RecordType,
    pub upstream: Arc<str>,
}

/// 预取管理器
pub struct PrefetchManager {
    config: PrefetchConfig,

    // 热度统计：hash -> PrefetchEntry
    hot_domains: DashMap<u64, PrefetchEntry, FxBuildHasher>,
    // 最后预取时间：hash -> Instant
    last_prefetch: DashMap<u64, Instant, FxBuildHasher>,

    // 并发控制
    concurrency: Arc<Semaphore>,

    // CDN 关联映射：hash(pipeline, upstream, domain) -> CDN 域名列表
    cdn_relations: Cache<u64, Arc<Vec<Arc<str>>>>,

    // CDN 关联缓存命中统计
    cdn_relation_lookups: AtomicU64,
    cdn_relation_hits: AtomicU64,
}

impl PrefetchManager {
    /// 创建新的预取管理器
    pub fn new(config: PrefetchConfig) -> Self {
        let hot_domains = DashMap::with_capacity_and_hasher(2048, FxBuildHasher::default());
        let last_prefetch = DashMap::with_capacity_and_hasher(2048, FxBuildHasher::default());
        let concurrency_limit = config.concurrency.max(1);
        let concurrency = Arc::new(Semaphore::new(concurrency_limit));
        let cdn_relations = Cache::builder()
            .max_capacity(CDN_RELATION_CACHE_CAPACITY)
            .time_to_live(Duration::from_secs(CDN_RELATION_TTL_SECS))
            .build();

        Self {
            config,
            hot_domains,
            last_prefetch,
            concurrency,
            cdn_relations,
            cdn_relation_lookups: AtomicU64::new(0),
            cdn_relation_hits: AtomicU64::new(0),
        }
    }

    /// 记录缓存访问并判断是否需要预取
    pub fn record_access(&self, hash: u64, entry: &CacheEntry, _ttl_secs: u64) {
        if !self.config.enabled {
            return;
        }

        let related_domains = if self.config.cdn_prefetch_enabled {
            self.lookup_cdn_relations(
                entry.pipeline_id.as_ref(),
                entry.source.as_ref(),
                entry.qname.as_ref(),
            )
        } else {
            None
        };

        let now = Instant::now();
        let mut prefetch_entry = self
            .hot_domains
            .entry(hash)
            .or_insert_with(|| PrefetchEntry {
                qname: entry.qname.clone(),
                qtype: entry.qtype,
                upstream: entry.source.clone(),
                access_count: 0,
                last_access: now,
                first_access: now,
            });

        prefetch_entry.access_count += 1;
        prefetch_entry.last_access = now;

        let mut hashes_to_mark = Vec::new();
        if prefetch_entry.access_count >= self.config.hot_threshold {
            hashes_to_mark.push(hash);
        }

        if let Some(related) = related_domains {
            for cdn_domain in related.iter() {
                let cdn_hash = Self::calculate_cache_hash(
                    entry.pipeline_id.as_ref(),
                    cdn_domain.as_ref(),
                    entry.qtype,
                );
                let mut cdn_entry =
                    self.hot_domains
                        .entry(cdn_hash)
                        .or_insert_with(|| PrefetchEntry {
                            qname: Arc::clone(cdn_domain),
                            qtype: entry.qtype,
                            upstream: entry.source.clone(),
                            access_count: 0,
                            last_access: now,
                            first_access: now,
                        });
                cdn_entry.access_count += 1;
                cdn_entry.last_access = now;
                if cdn_entry.access_count >= self.config.hot_threshold {
                    hashes_to_mark.push(cdn_hash);
                }
            }
        }

        if !hashes_to_mark.is_empty() {
            for hash in hashes_to_mark {
                self.last_prefetch.entry(hash).or_insert(now);
            }
        }
    }

    /// 根据配置计算需要的相关预取任务
    pub fn related_jobs(
        &self,
        pipeline_id: &Arc<str>,
        qname: &Arc<str>,
        original_qtype: RecordType,
        upstream: &Arc<str>,
    ) -> Vec<PrefetchJob> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut jobs = Vec::new();

        if self.config.ipv6_on_ipv4_enabled && original_qtype == RecordType::A {
            jobs.push(PrefetchJob {
                pipeline_id: Arc::clone(pipeline_id),
                qname: Arc::clone(qname),
                qtype: RecordType::AAAA,
                upstream: Arc::clone(upstream),
            });
        }

        if self.config.cdn_prefetch_enabled {
            if let Some(related) =
                self.lookup_cdn_relations(pipeline_id.as_ref(), upstream.as_ref(), qname.as_ref())
            {
                for cdn_domain in related.iter() {
                    jobs.push(PrefetchJob {
                        pipeline_id: Arc::clone(pipeline_id),
                        qname: Arc::clone(cdn_domain),
                        qtype: original_qtype,
                        upstream: Arc::clone(upstream),
                    });
                }
            }
        }

        jobs
    }

    /// 判断是否满足调度条件（最小间隔、并发限制）
    pub fn try_prepare_job(&self, job: &PrefetchJob) -> Option<OwnedSemaphorePermit> {
        if !self.config.enabled {
            return None;
        }

        let hash = self.job_hash(job);
        let now = Instant::now();

        if let Some(last) = self.last_prefetch.get(&hash) {
            if now.duration_since(*last) < self.config.min_interval {
                return None;
            }
        }
        self.last_prefetch.insert(hash, now);

        match self.concurrency.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(_) => {
                self.last_prefetch.remove(&hash);
                None
            }
        }
    }

    fn job_hash(&self, job: &PrefetchJob) -> u64 {
        let mut hasher = FxHasher::default();
        job.pipeline_id.as_ref().hash(&mut hasher);
        job.qname.as_ref().hash(&mut hasher);
        u16::from(job.qtype).hash(&mut hasher);
        job.upstream.as_ref().hash(&mut hasher);
        hasher.finish()
    }

    /// 读取配置
    #[allow(dead_code)]
    pub fn config(&self) -> &PrefetchConfig {
        &self.config
    }

    /// 解析响应中的 CNAME 关系并注册 CDN 映射
    pub fn register_cdn_relations_from_response(
        &self,
        pipeline_id: &Arc<str>,
        upstream: &Arc<str>,
        origin: &Arc<str>,
        response: &[u8],
    ) {
        if !self.config.enabled || !self.config.cdn_prefetch_enabled {
            return;
        }

        let message = match Message::from_bytes(response) {
            Ok(msg) => msg,
            Err(_) => return,
        };
        self.register_cdn_relations_from_message(pipeline_id, upstream, origin, &message);
    }

    pub fn register_cdn_relations_from_message(
        &self,
        pipeline_id: &Arc<str>,
        upstream: &Arc<str>,
        origin: &Arc<str>,
        message: &Message,
    ) {
        if !self.config.enabled || !self.config.cdn_prefetch_enabled {
            return;
        }

        let origin_norm = Self::normalize_domain_str(origin.as_ref());
        let mut cname_graph: HashMap<Arc<str>, Vec<Arc<str>>> = HashMap::new();

        for record in message.answers() {
            if record.record_type() != RecordType::CNAME {
                continue;
            }
            if let Some(RData::CNAME(target)) = record.data() {
                let owner = Self::normalize_dns_name(record.name());
                let target_norm = Self::normalize_dns_name(target);
                if owner.as_ref() == target_norm.as_ref() {
                    continue;
                }
                cname_graph.entry(owner).or_default().push(target_norm);
            }
        }

        let mut related: Vec<Arc<str>> = Vec::new();
        let mut seen: HashSet<Arc<str>> = HashSet::new();
        let mut queue: VecDeque<(Arc<str>, usize)> = VecDeque::new();

        seen.insert(Arc::clone(&origin_norm));
        queue.push_back((Arc::clone(&origin_norm), 0));

        'walk: while let Some((current, depth)) = queue.pop_front() {
            if depth >= CNAME_CHAIN_LIMIT {
                continue;
            }

            let next_candidates = match cname_graph.get(current.as_ref()) {
                Some(next) => next,
                None => continue,
            };

            for next in next_candidates {
                if next.as_ref() == origin_norm.as_ref() {
                    continue;
                }

                if !seen.insert(Arc::clone(next)) {
                    continue;
                }

                related.push(Arc::clone(next));
                if related.len() >= CNAME_RELATION_LIMIT {
                    break 'walk;
                }
                queue.push_back((Arc::clone(next), depth + 1));
            }
        }

        let key = Self::cdn_relation_key(
            pipeline_id.as_ref(),
            upstream.as_ref(),
            origin_norm.as_ref(),
        );
        if related.is_empty() {
            self.cdn_relations.invalidate(&key);
        } else {
            self.cdn_relations.insert(key, Arc::new(related));
        }
    }

    fn lookup_cdn_relations(
        &self,
        pipeline_id: &str,
        upstream: &str,
        primary: &str,
    ) -> Option<Arc<Vec<Arc<str>>>> {
        let key = Self::cdn_relation_key(pipeline_id, upstream, primary);
        self.cdn_relation_lookups.fetch_add(1, Ordering::Relaxed);
        if let Some(value) = self.cdn_relations.get(&key) {
            self.cdn_relation_hits.fetch_add(1, Ordering::Relaxed);
            Some(value)
        } else {
            None
        }
    }

    pub fn cdn_relation_stats(&self) -> CdnRelationStats {
        let lookups = self.cdn_relation_lookups.load(Ordering::Relaxed);
        let hits = self.cdn_relation_hits.load(Ordering::Relaxed);
        let hit_rate = if lookups == 0 {
            0.0
        } else {
            hits as f64 / lookups as f64
        };

        CdnRelationStats {
            lookups,
            hits,
            hit_rate,
        }
    }

    fn cdn_relation_key(pipeline_id: &str, upstream: &str, primary: &str) -> u64 {
        let mut hasher = FxHasher::default();
        pipeline_id.hash(&mut hasher);
        upstream.hash(&mut hasher);
        for b in primary.as_bytes() {
            hasher.write_u8(b.to_ascii_lowercase());
        }
        hasher.finish()
    }

    fn calculate_cache_hash(pipeline_id: &str, qname: &str, qtype: u16) -> u64 {
        let mut hasher = FxHasher::default();
        pipeline_id.hash(&mut hasher);
        for b in qname.as_bytes() {
            hasher.write_u8(b.to_ascii_lowercase());
        }
        qtype.hash(&mut hasher);
        hasher.finish()
    }

    fn normalize_dns_name(name: &Name) -> Arc<str> {
        let text = name.to_utf8();
        Self::normalize_domain_str(&text)
    }

    fn normalize_domain_str(domain: &str) -> Arc<str> {
        let trimmed = domain.trim_end_matches('.');
        Arc::from(trimmed.to_ascii_lowercase().into_boxed_str())
    }
    /// 获取热度统计信息
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> PrefetchStats {
        let total_domains = self.hot_domains.len();
        let total_accesses: u64 = self.hot_domains.iter().map(|e| e.access_count).sum();

        let hot_domains = self
            .hot_domains
            .iter()
            .filter(|e| e.access_count >= self.config.hot_threshold)
            .count();

        PrefetchStats {
            total_domains,
            hot_domains,
            total_accesses,
        }
    }
}

/// 预取统计信息
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PrefetchStats {
    pub total_domains: usize,
    pub hot_domains: usize,
    pub total_accesses: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct CdnRelationStats {
    pub lookups: u64,
    pub hits: u64,
    pub hit_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefetch_config_default() {
        let config = PrefetchConfig::default();
        assert!(config.enabled);
        assert_eq!(config.hot_threshold, 10);
    }

    #[tokio::test]
    async fn test_prefetch_manager_creation() {
        let config = PrefetchConfig::default();
        let manager = PrefetchManager::new(config);

        let stats = manager.get_stats().await;
        assert_eq!(stats.total_domains, 0);
    }
}
