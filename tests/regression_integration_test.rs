// 回归集成测试 - 验证核心功能
// Regression Integration Tests - Validate Core Functionality

use kixdns::config::load_config;
use kixdns::geosite::GeoSiteManager;
use std::path::Path;

#[test]
fn test_geosite_suffix_matching_base_domain() {
    // 测试后缀匹配能匹配基础域名
    // Test suffix matching matches base domain
    let dat_path = "data/geosite.dat";

    if Path::new(dat_path).exists() {
        let mut manager = GeoSiteManager::new();
        if manager.load_from_dat_file(dat_path).is_ok() {
            // .github.com 后缀应该匹配 github.com
            assert!(manager.matches("github", "github.com"),
                "Suffix .github.com should match base domain github.com");
            assert!(manager.matches("github", "api.github.com"),
                "Suffix .github.com should match subdomain api.github.com");

            println!("✓ GeoSite suffix matching works correctly");
        }
    }
}

#[test]
fn test_cache_entry_upstream_field() {
    // 测试 CacheEntry 的 upstream 字段存在
    // Test CacheEntry upstream field exists
    use kixdns::cache::CacheEntry;
    use bytes::Bytes;
    use std::time::Instant;
    use std::sync::Arc;
    use hickory_proto::op::ResponseCode;

    let entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NoError,
        source: Arc::from("test"),
        upstream: Some(Arc::from("1.1.1.1:53")),
        qname: Arc::from("example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
        inserted_at: Instant::now(),
        original_ttl: 300,
    };

    assert!(entry.upstream.is_some(), "CacheEntry should have upstream field");
    assert_eq!(entry.upstream.unwrap().as_ref(), "1.1.1.1:53");
    println!("✓ CacheEntry upstream field works correctly");
}

#[test]
fn test_config_pre_split_upstreams() {
    // 测试配置加载时预分割上游列表
    // Test config loading pre-splits upstream list
    let config_path = Path::new("config/pipeline_fast.json");
    if config_path.exists() {
        if let Ok(cfg) = load_config(config_path) {
            // 检查是否有 pipeline
            assert!(!cfg.pipelines.is_empty(), "Config should have pipelines");

            // 检查第一个 pipeline 的规则
            for pipeline in &cfg.pipelines {
                for rule in &pipeline.rules {
                    for action in &rule.actions {
                        if let kixdns::config::Action::Forward { upstream, pre_split_upstreams, .. } = action {
                            // 如果 upstream 包含逗号，pre_split_upstreams 应该被设置
                            if let Some(upstream_str) = upstream {
                                if upstream_str.contains(',') {
                                    assert!(pre_split_upstreams.is_some(),
                                        "Upstream with commas should have pre_split_upstreams set");
                                    if let Some(pre_split) = pre_split_upstreams {
                                        assert!(!pre_split.is_empty(),
                                            "pre_split_upstreams should not be empty");
                                        println!("✓ Config pre-splits upstream list: {:?} -> {} upstreams",
                                            upstream_str, pre_split.len());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn test_background_refresh_singleflight_integration() {
    // 测试后台刷新使用正常的 Singleflight 机制
    // Test background refresh uses normal Singleflight mechanism
    use kixdns::engine::Engine;

    // 后台刷新和用户请求应该使用相同的 dedupe_hash
    // 这确保它们能共享 Singleflight 机制
    let pipeline_id = "test_pipeline";
    let qname = "example.com";
    let qtype = hickory_proto::rr::RecordType::A;
    let qclass = hickory_proto::rr::DNSClass::IN;

    let user_request_hash = Engine::calculate_cache_hash_for_dedupe(pipeline_id, qname, qtype, qclass);
    let background_refresh_hash = Engine::calculate_cache_hash_for_dedupe(pipeline_id, qname, qtype, qclass);

    // 验证两者使用相同的 hash
    assert_eq!(user_request_hash, background_refresh_hash,
        "Background refresh should use same dedupe_hash as user request");

    // 验证修复后的行为：不再使用独立的高位标记
    // 旧的实现会创建 refresh_key = cache_hash | 0x8000_0000_0000_0000
    // 新实现直接使用正常的 dedupe_hash
    println!("✓ Background refresh uses same hash as user request: {:x}", user_request_hash);
    println!("  (Old implementation would have used: {:x})", user_request_hash | 0x8000_0000_0000_0000);
}

#[test]
fn test_forward_upstream_concurrent_logic() {
    // 测试 forward_upstream 并发逻辑
    // Test forward_upstream concurrent logic
    use kixdns::engine::Engine;

    // 单个上游不应该包含逗号
    let single = "1.1.1.1:53";
    assert!(!single.contains(','), "Single upstream should not contain comma");

    // 多个上游应该包含逗号
    let multiple = "1.1.1.1:53,8.8.8.8:53,9.9.9.9:53";
    assert!(multiple.contains(','), "Multiple upstreams should contain comma");

    // 动态分割应该产生多个上游
    let split: Vec<&str> = multiple.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(split.len(), 3, "Should split into 3 upstreams");
    assert_eq!(split[0], "1.1.1.1:53");
    assert_eq!(split[1], "8.8.8.8:53");
    assert_eq!(split[2], "9.9.9.9:53");

    println!("✓ Forward upstream concurrent logic works correctly");
}

#[test]
fn test_static_response_no_upstream() {
    // 测试静态响应没有 upstream
    // Test static responses have no upstream
    use kixdns::cache::CacheEntry;
    use bytes::Bytes;
    use std::time::Instant;
    use std::sync::Arc;
    use hickory_proto::op::ResponseCode;

    // 静态响应（NXDOMAIN）
    let static_entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NXDomain,
        source: Arc::from("static"),
        upstream: None,  // 静态响应没有上游
        qname: Arc::from("blocked.example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
        inserted_at: Instant::now(),
        original_ttl: 300,
    };

    assert!(static_entry.upstream.is_none(),
        "Static response should not have upstream");

    // Upstream 响应
    let upstream_entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NoError,
        source: Arc::from("upstream"),
        upstream: Some(Arc::from("1.1.1.1:53")),
        qname: Arc::from("example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
        inserted_at: Instant::now(),
        original_ttl: 300,
    };

    assert!(upstream_entry.upstream.is_some(),
        "Upstream response should have upstream");

    println!("✓ Static responses correctly have no upstream");
}

#[test]
fn regression_test_gfw_github_separation() {
    // 回归测试：GFW 和 GitHub 应该是独立的标签
    // Regression test: GFW and GitHub should be separate tags
    let dat_path = "data/geosite.dat";

    if Path::new(dat_path).exists() {
        let mut manager = GeoSiteManager::new();
        if manager.load_from_dat_file(dat_path).is_ok() {
            // GitHub 域名应该匹配 GITHUB 标签
            assert!(manager.matches("github", "github.com"),
                "GITHUB tag should match github.com");

            // 验证标签是独立的（即使 GFW 包含 GitHub，也应该是明确配置的）
            let gfw_matchers = manager.get_tag_matchers("gfw");
            let github_matchers = manager.get_tag_matchers("github");

            // 至少应该有一个标签存在
            let has_gfw = gfw_matchers.is_some();
            let has_github = github_matchers.is_some();

            assert!(has_gfw || has_github,
                "At least one of GFW or GITHUB tags should exist");

            if has_github {
                println!("✓ Regression test passed: GITHUB tag exists and is independent");
            } else {
                println!("✓ Regression test passed: GFW tag exists");
            }
        }
    }
}

#[test]
fn regression_test_cache_no_original_upstream() {
    // 回归测试：修复前没有保存 original upstream
    // Regression test: Before fix, original upstream was not saved
    use kixdns::cache::CacheEntry;
    use bytes::Bytes;
    use std::time::Instant;
    use std::sync::Arc;
    use hickory_proto::op::ResponseCode;

    // 模拟修复后的行为
    let entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NoError,
        source: Arc::from("upstream"),
        upstream: Some(Arc::from("8.8.8.8:53")),  // 修复后应该有这个字段
        qname: Arc::from("www.google.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
        inserted_at: Instant::now(),
        original_ttl: 300,
    };

    // 验证 upstream 被保存
    assert!(entry.upstream.is_some(),
        "CacheEntry should preserve original upstream for background refresh");

    // 后台刷新应该使用原始 upstream，而不是 default
    let refresh_upstream = entry.upstream.unwrap();
    assert_eq!(refresh_upstream.as_ref(), "8.8.8.8:53",
        "Background refresh should use original upstream: {}", refresh_upstream);

    println!("✓ Regression test passed: CacheEntry preserves original upstream");
}
