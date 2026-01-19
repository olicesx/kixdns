// 测试 Pipeline Selector 中的 GeoSite 匹配器集成
// Test GeoSite matcher integration in Pipeline Selector

use kixdns::config::{GlobalSettings, PipelineConfig};
use kixdns::geosite::GeoSiteManager;
use kixdns::matcher::RuntimePipelineConfig;
use serde_json::json;

#[test]
fn test_pipeline_selector_geosite_matcher() {
    // 创建包含 GeoSite 匹配器的配置
    // Create config with GeoSite matcher in pipeline selector
    let raw = json!({
        "settings": {
            "default_upstream": "1.1.1.1:53"
        },
        "pipelines": [
            { "id": "p1", "rules": [] },
            { "id": "p2", "rules": [] },
            { "id": "p3", "rules": [] }
        ],
        "pipeline_select": [
            {
                "pipeline": "p2",
                "matchers": [
                    { "type": "geo_site", "value": "cn" }
                ]
            },
            {
                "pipeline": "p3",
                "matchers": [
                    { "type": "geo_site", "value": "google" }
                ]
            }
        ]
    });

    let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

    // 创建 GeoSiteManager 并添加测试数据
    // Create GeoSiteManager and add test data
    let mut geosite_manager = GeoSiteManager::new(100, 60);
    
    // 合并所有 GeoSite 数据到一个 JSON 中
    // Merge all GeoSite data into one JSON
    let v2ray_all_data = r#"
    {
        "entries": [
            {
                "tag": "cn",
                "domains": [
                    "domain:baidu.com",
                    "domain:qq.com",
                    "*.cn"
                ]
            },
            {
                "tag": "google",
                "domains": [
                    "domain:google.com",
                    "domain:youtube.com",
                    "domain:gmail.com"
                ]
            }
        ]
    }
    "#;
    geosite_manager.load_from_v2ray_string(v2ray_all_data).expect("load all data");
    
    println!("Tags after load: {:?}", geosite_manager.tags());
    println!("Has cn tag: {}", geosite_manager.has_tag("cn"));
    println!("Has google tag: {}", geosite_manager.has_tag("google"));

    // 测试 CN 域名应该选择 p2
    // Test CN domains should select p2
    println!("Testing baidu.com...");
    println!("GeoSiteManager has cn tag: {}", geosite_manager.has_tag("cn"));
    println!("baidu.com matches cn: {}", geosite_manager.matches("cn", "baidu.com"));
    
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "baidu.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    println!("Selected pipeline: {:?}", id);
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p2");

    // 测试 Google 域名应该选择 p3
    // Test Google domains should select p3
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "google.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p3");

    // 测试其他域名应该选择默认 pipeline (p1)
    // Test other domains should select default pipeline (p1)
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "example.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p1");
}

#[test]
fn test_pipeline_selector_geosite_not_matcher() {
    // 测试 GeoSiteNot 匹配器
    // Test GeoSiteNot matcher
    let raw = json!({
        "settings": {
            "default_upstream": "1.1.1.1:53"
        },
        "pipelines": [
            { "id": "p1", "rules": [] },
            { "id": "p2", "rules": [] }
        ],
        "pipeline_select": [
            {
                "pipeline": "p2",
                "matchers": [
                    { "type": "geo_site_not", "value": "cn" }
                ]
            }
        ]
    });

    let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

    let mut geosite_manager = GeoSiteManager::new(100, 60);
    
    let v2ray_cn_data = r#"
    {
        "entries": [
            {
                "tag": "cn",
                "domains": [
                    "domain:baidu.com",
                    "domain:qq.com"
                ]
            }
        ]
    }
    "#;
    geosite_manager.load_from_v2ray_string(v2ray_cn_data).expect("load CN data");

    // 非 CN 域名应该选择 p2
    // Non-CN domains should select p2
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "google.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p2");

    // CN 域名应该选择默认 pipeline (p1)
    // CN domains should select default pipeline (p1)
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "baidu.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p1");
}

#[test]
fn test_pipeline_selector_geosite_with_or_operator() {
    // 测试 GeoSite 与 OR 操作符的组合
    // Test GeoSite with OR operator
    let raw = json!({
        "settings": {
            "default_upstream": "1.1.1.1:53"
        },
        "pipelines": [
            { "id": "p1", "rules": [] },
            { "id": "p2", "rules": [] }
        ],
        "pipeline_select": [
            {
                "pipeline": "p2",
                "matcher_operator": "or",
                "matchers": [
                    { "type": "geo_site", "value": "cn" },
                    { "type": "geo_site", "value": "google" }
                ]
            }
        ]
    });

    let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

    let mut geosite_manager = GeoSiteManager::new(100, 60);
    
    let v2ray_data = r#"
    {
        "entries": [
            {
                "tag": "cn",
                "domains": ["domain:baidu.com"]
            },
            {
                "tag": "google",
                "domains": ["domain:google.com"]
            }
        ]
    }
    "#;
    geosite_manager.load_from_v2ray_string(v2ray_data).expect("load data");

    // CN 域名应该匹配
    // CN domain should match
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "baidu.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p2");

    // Google 域名也应该匹配
    // Google domain should also match
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "google.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p2");

    // 其他域名不应该匹配
    // Other domains should not match
    let (opt, id) = kixdns::engine::select_pipeline(
        &runtime,
        "example.com",
        "127.0.0.1".parse().unwrap(),
        hickory_proto::rr::DNSClass::IN,
        false,
        "default",
        Some(&geosite_manager),
    );
    assert!(opt.is_some());
    assert_eq!(id.as_ref(), "p1");
}
