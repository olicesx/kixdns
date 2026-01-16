//! DNS 预取模块
//! 
//! 实现基于热度的域名预取功能，参考 RFC 1034/1035 的缓存机制

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, RwLock};

use crate::cache::CacheEntry;

/// 预取条目，记录域名的访问统计
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
    /// 是否启用预取
    pub enabled: bool,
    
    /// 热度阈值（访问次数）
    pub hot_threshold: u64,
    
    /// TTL 剩余比例阈值（0-1），当剩余 TTL < 总 TTL * ratio 时触发预取
    pub ttl_ratio: f64,
    
    /// 预取并发数
    pub concurrency: usize,
    
    /// 预取间隔（避免频繁预取）
    pub min_interval: Duration,
}

impl Default for PrefetchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            hot_threshold: 10,
            ttl_ratio: 0.3,
            concurrency: 5,
            min_interval: Duration::from_secs(30),
        }
    }
}

/// 预取管理器
pub struct PrefetchManager {
    config: PrefetchConfig,
    
    // 热度统计：hash -> PrefetchEntry
    hot_domains: Arc<RwLock<HashMap<u64, PrefetchEntry>>>,
    
    // 预取任务队列
    prefetch_tx: mpsc::Sender<u64>,
    
    // 最后预取时间：hash -> Instant
    last_prefetch: Arc<RwLock<HashMap<u64, Instant>>>,
}

impl PrefetchManager {
    /// 创建新的预取管理器
    pub fn new(config: PrefetchConfig) -> Self {
        let (prefetch_tx, _prefetch_rx) = mpsc::channel(1000);
        let hot_domains: Arc<RwLock<HashMap<u64, PrefetchEntry>>> = Arc::new(RwLock::new(HashMap::new()));
        let last_prefetch: Arc<RwLock<HashMap<u64, Instant>>> = Arc::new(RwLock::new(HashMap::new()));
        
        Self {
            config,
            hot_domains,
            prefetch_tx,
            last_prefetch,
        }
    }
    
    /// 记录缓存访问并判断是否需要预取
    pub fn record_access(&self, hash: u64, entry: &CacheEntry, ttl_secs: u64) {
        if !self.config.enabled {
            return;
        }
        
        // 使用 blocking_write 在同步上下文中
        let mut domains = self.hot_domains.blocking_write();
        let prefetch_entry = domains.entry(hash).or_insert_with(|| PrefetchEntry {
            qname: entry.qname.clone(),
            qtype: entry.qtype,
            upstream: entry.source.clone(),
            access_count: 0,
            last_access: Instant::now(),
            first_access: Instant::now(),
        });
        
        prefetch_entry.access_count += 1;
        prefetch_entry.last_access = Instant::now();
        
        // 判断是否需要预取
        if prefetch_entry.access_count >= self.config.hot_threshold {
            // 简化实现：直接发送预取请求
            let _ = self.prefetch_tx.try_send(hash);
        }
    }
    
    /// 获取热度统计信息
    pub async fn get_stats(&self) -> PrefetchStats {
        let domains = self.hot_domains.read().await;
        let total_domains = domains.len();
        let total_accesses: u64 = domains.values().map(|e| e.access_count).sum();
        
        let hot_domains = domains
            .values()
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
#[derive(Debug, Clone)]
pub struct PrefetchStats {
    pub total_domains: usize,
    pub hot_domains: usize,
    pub total_accesses: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prefetch_config_default() {
        let config = PrefetchConfig::default();
        assert!(config.enabled);
        assert_eq!(config.hot_threshold, 10);
        assert_eq!(config.ttl_ratio, 0.3);
    }
    
    #[tokio::test]
    async fn test_prefetch_manager_creation() {
        let config = PrefetchConfig::default();
        let manager = PrefetchManager::new(config);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.total_domains, 0);
    }
}
