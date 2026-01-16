//! DNS 预取功能测试
//!
//! 测试预取管理器的各种场景

use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use kixdns::cache::CacheEntry;
use kixdns::prefetch::{PrefetchConfig, PrefetchEntry, PrefetchManager};
use std::sync::Arc;
use std::time::Duration;

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
        hot_threshold: 5, // 降低阈值以便测试
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
        qtype: 1, // A 记录
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
        enabled: false, // 禁用预取
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
    assert_eq!(config.concurrency, 5);
    assert_eq!(config.min_interval, Duration::from_secs(30));
    assert!(config.ipv6_on_ipv4_enabled);
    assert!(config.cdn_prefetch_enabled);
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

    assert_eq!(entry.qname.as_ref(), "test.com");
    assert_eq!(entry.qtype, 1);
    assert_eq!(entry.access_count, 0);
}

#[tokio::test]
async fn test_prefetch_min_interval() {
    let config = PrefetchConfig {
        enabled: true,
        hot_threshold: 2,
        min_interval: Duration::from_millis(100), // 100ms 最小间隔
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

    let domains = vec![("example.com", 1), ("test.com", 1), ("github.com", 1)];

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
    assert!(stats.total_accesses >= 45); // 3 domains * 15 accesses
}

#[test]
fn test_related_jobs_generate_ipv6_and_dynamic_cdn() {
    let config = PrefetchConfig::default();
    let manager = PrefetchManager::new(config);
    let pipeline = Arc::from("default");
    let qname = Arc::from("example.com");
    let upstream = Arc::from("8.8.8.8:53");

    let response = build_cname_response("example.com.", "cdn.example.com.");
    manager.register_cdn_relations_from_response(&pipeline, &upstream, &qname, &response);

    let jobs = manager.related_jobs(&pipeline, &qname, RecordType::A, &upstream);
    assert_eq!(jobs.len(), 2);
    assert!(jobs.iter().any(|job| job.qtype == RecordType::AAAA));
    assert!(
        jobs.iter()
            .any(|job| job.qtype == RecordType::A && job.qname.as_ref() == "cdn.example.com")
    );
}

#[test]
fn test_related_jobs_respect_feature_flags() {
    let mut config = PrefetchConfig::default();
    config.ipv6_on_ipv4_enabled = false;
    let manager = PrefetchManager::new(config.clone());
    let pipeline = Arc::from("p1");
    let qname = Arc::from("example.com");
    let upstream = Arc::from("1.1.1.1:53");

    let response = build_cname_response("example.com.", "cdn.example.com.");
    manager.register_cdn_relations_from_response(&pipeline, &upstream, &qname, &response);

    let jobs = manager.related_jobs(&pipeline, &qname, RecordType::A, &upstream);
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].qname.as_ref(), "cdn.example.com");
    assert_eq!(jobs[0].qtype, RecordType::A);

    let mut config_cdn_disabled = config;
    config_cdn_disabled.ipv6_on_ipv4_enabled = true;
    config_cdn_disabled.cdn_prefetch_enabled = false;
    let manager_cdn_disabled = PrefetchManager::new(config_cdn_disabled);
    let jobs_ipv6 = manager_cdn_disabled.related_jobs(&pipeline, &qname, RecordType::A, &upstream);
    assert_eq!(jobs_ipv6.len(), 1);
    assert_eq!(jobs_ipv6[0].qtype, RecordType::AAAA);
    assert_eq!(jobs_ipv6[0].qname.as_ref(), "example.com");
}

#[test]
fn test_cname_multi_branch_resolution() {
    let mut config = PrefetchConfig::default();
    config.ipv6_on_ipv4_enabled = false;
    let manager = PrefetchManager::new(config);
    let pipeline = Arc::from("p1");
    let qname = Arc::from("example.com");
    let upstream = Arc::from("1.1.1.1:53");

    let response = build_cname_response_multi(&[
        ("example.com.", "cdn-a.example.com."),
        ("example.com.", "cdn-b.example.com."),
        ("cdn-a.example.com.", "edge-a.example.com."),
    ]);
    manager.register_cdn_relations_from_response(&pipeline, &upstream, &qname, &response);

    let jobs = manager.related_jobs(&pipeline, &qname, RecordType::A, &upstream);
    let names: Vec<&str> = jobs.iter().map(|j| j.qname.as_ref()).collect();
    assert!(names.contains(&"cdn-a.example.com"));
    assert!(names.contains(&"cdn-b.example.com"));
    assert!(names.contains(&"edge-a.example.com"));
}

#[test]
fn test_cdn_relation_cache_hit_stats() {
    let mut config = PrefetchConfig::default();
    config.ipv6_on_ipv4_enabled = false;
    let manager = PrefetchManager::new(config);
    let pipeline = Arc::from("p1");
    let qname = Arc::from("example.com");
    let upstream = Arc::from("1.1.1.1:53");

    let _ = manager.related_jobs(&pipeline, &qname, RecordType::A, &upstream);
    let stats = manager.cdn_relation_stats();
    assert_eq!(stats.lookups, 1);
    assert_eq!(stats.hits, 0);

    let response = build_cname_response("example.com.", "cdn.example.com.");
    manager.register_cdn_relations_from_response(&pipeline, &upstream, &qname, &response);

    let _ = manager.related_jobs(&pipeline, &qname, RecordType::A, &upstream);
    let stats = manager.cdn_relation_stats();
    assert_eq!(stats.lookups, 2);
    assert_eq!(stats.hits, 1);
    assert!(stats.hit_rate > 0.0);
}

fn build_cname_response(origin: &str, target: &str) -> Vec<u8> {
    build_cname_response_multi(&[(origin, target)])
}

fn build_cname_response_multi(records: &[(&str, &str)]) -> Vec<u8> {
    let mut message = Message::new();
    message.set_message_type(MessageType::Response);
    message.set_id(0);

    for (origin, target) in records {
        let origin_name = Name::from_ascii(origin).unwrap();
        let target_name = Name::from_ascii(target).unwrap();
        let record = Record::from_rdata(origin_name, 60, RData::CNAME(CNAME(target_name)));
        message.add_answer(record);
    }
    let mut buf = Vec::new();
    {
        let mut encoder = BinEncoder::new(&mut buf);
        message.emit(&mut encoder).unwrap();
    }
    buf
}
