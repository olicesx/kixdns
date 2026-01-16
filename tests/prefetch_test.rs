//! DNS 预取功能测试
//! 
//! 测试预取管理器的各种场景

use kixdns::prefetch::{PrefetchManager, PrefetchConfig, PrefetchEntry};
use kixdns::cache::CacheEntry;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;
use hickory_proto::op::ResponseCode;

#[tokio::test]
async fn test_prefetch_manager_creation() {
    let config = PrefetchConfig::default();
    let manager = PrefetchManager::new(config);
    
    let stats = manager.get_stats().await;
    assert_eq!(stats.total_domains, 0);
    assert_eq!(stats.hot_domains, 0);
    assert_eq!(stats.total_accesses, 0);
}

#[tokio::test]
async fn test_prefetch_record_access() {
    let config = PrefetchConfig {
        enabled: true,
        hot_threshold: 5,  // 降低阈值以便测试
        ..Default::default()
    };
    let manager = PrefetchManager::new(config);
    
    // 创建模拟缓存条目
    let entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NoError,
        source: Arc::from("8.8.8.8:53"),
        qname: Arc::from("example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,  // A 记录
    };
    
    let hash = 12345u64;
    
    // 记录多次访问
    for i in 1..=6 {
        manager.record_access(hash, &entry, 300);
        println!("Access count: {}", i);
    }
    
    // 等待预取任务执行
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let stats = manager.get_stats().await;
    assert_eq!(stats.total_domains, 1);
    assert!(stats.total_accesses >= 6);
}

#[tokio::test]
async fn test_prefetch_disabled() {
    let config = PrefetchConfig {
        enabled: false,  // 禁用预取
        ..Default::default()
    };
    let manager = PrefetchManager::new(config);
    
    let entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NoError,
        source: Arc::from("8.8.8.8:53"),
        qname: Arc::from("example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
    };
    
    let hash = 12345u64;
    
    // 记录访问（即使超过阈值也不应触发预取）
    for _ in 0..20 {
        manager.record_access(hash, &entry, 300);
    }
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let stats = manager.get_stats().await;
    // 预取禁用，不应有统计
    assert_eq!(stats.total_domains, 0);
}

#[tokio::test]
async fn test_prefetch_config_default() {
    let config = PrefetchConfig::default();
    assert!(config.enabled);
    assert_eq!(config.hot_threshold, 10);
    assert_eq!(config.ttl_ratio, 0.3);
    assert_eq!(config.concurrency, 5);
    assert_eq!(config.min_interval, Duration::from_secs(30));
}

#[tokio::test]
async fn test_prefetch_entry_creation() {
    let entry = PrefetchEntry {
        qname: Arc::from("test.com"),
        qtype: 1,
        upstream: Arc::from("1.1.1.1:53"),
        access_count: 0,
        last_access: std::time::Instant::now(),
        first_access: std::time::Instant::now(),
    };
    
    assert_eq!(entry.qname, "test.com");
    assert_eq!(entry.qtype, 1);
    assert_eq!(entry.access_count, 0);
}

#[tokio::test]
async fn test_prefetch_min_interval() {
    let config = PrefetchConfig {
        enabled: true,
        hot_threshold: 2,
        min_interval: Duration::from_millis(100),  // 100ms 最小间隔
        ..Default::default()
    };
    let manager = PrefetchManager::new(config);
    
    let entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NoError,
        source: Arc::from("8.8.8.8:53"),
        qname: Arc::from("example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
    };
    
    let hash = 12345u64;
    
    // 第一次触发预取
    manager.record_access(hash, &entry, 300);
    manager.record_access(hash, &entry, 300);
    
    tokio::time::sleep(Duration::from_millis(50)).await;
    
    // 立即再次触发（应该被忽略，因为间隔太短）
    manager.record_access(hash, &entry, 300);
    manager.record_access(hash, &entry, 300);
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let stats = manager.get_stats().await;
    assert_eq!(stats.total_domains, 1);
}

#[tokio::test]
async fn test_prefetch_multiple_domains() {
    let config = PrefetchConfig::default();
    let manager = PrefetchManager::new(config);
    
    let domains = vec![
        ("example.com", 1),
        ("test.com", 1),
        ("github.com", 1),
    ];
    
    for (i, (qname, qtype)) in domains.iter().enumerate() {
        let entry = CacheEntry {
            bytes: Bytes::new(),
            rcode: ResponseCode::NoError,
            source: Arc::from("8.8.8.8:53"),
            qname: Arc::from(*qname),
            pipeline_id: Arc::from("test"),
            qtype: *qtype,
        };
        
        let hash = (i + 1) as u64;
        
        // 每个域名访问 15 次（超过默认阈值 10）
        for _ in 0..15 {
            manager.record_access(hash, &entry, 300);
        }
    }
    
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let stats = manager.get_stats().await;
    assert_eq!(stats.total_domains, 3);
    assert!(stats.total_accesses >= 45);  // 3 domains * 15 accesses
}
