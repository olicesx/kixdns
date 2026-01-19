// GeoSite Engine Integration Test
// 测试 GeoSite 在 Engine 中的集成

use kixdns::config::PipelineConfig;
use kixdns::engine::Engine;
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::geosite::{GeoSiteEntry, GeoSiteManager, DomainMatcher};
use std::net::IpAddr;

#[test]
fn test_geosite_matcher_with_data() {
    // 创建 GeoSiteManager 并添加数据
    let mut manager = GeoSiteManager::new(100, 60);
    
    let entries = vec![
        GeoSiteEntry {
            tag: "cn".to_string(),
            matchers: vec![
                DomainMatcher::Full("example.com.cn".to_string()),
                DomainMatcher::Suffix(".cn".to_string()),
            ],
        },
    ];
    
    manager.reload(entries);
    
    // 测试匹配
    assert!(manager.matches("cn", "example.com.cn"));
    assert!(manager.matches("cn", "test.example.com.cn"));
    assert!(!manager.matches("cn", "example.com"));
    
    // 测试否定匹配
    assert!(!manager.matches("cn", "google.com"));
}

#[test]
fn test_geosite_not_matcher() {
    let mut manager = GeoSiteManager::new(100, 60);
    
    let entries = vec![
        GeoSiteEntry {
            tag: "cn".to_string(),
            matchers: vec![
                DomainMatcher::Suffix(".cn".to_string()),
            ],
        },
    ];
    
    manager.reload(entries);
    
    // GeoSiteNot 应该匹配不在 CN 分类中的域名
    // 注意：GeoSiteNot 在 matcher 中实现为 !manager.matches()
    // 这里我们测试基础的 matches 方法
    assert!(manager.matches("cn", "example.com.cn"));
    assert!(!manager.matches("cn", "google.com"));
}

#[test]
fn test_geosite_engine_has_manager() {
    // 创建一个简单的配置
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "1.1.1.1:53"
        },
        "pipelines": [
            {
                "id": "test_pipeline",
                "rules": []
            }
        ]
    });

    let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");

    // 创建 Engine（需要在 Tokio runtime 中）
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let engine = Engine::new(runtime.clone(), "test".to_string());

        // 验证 Engine 有 GeoSiteManager
        assert_eq!(engine.geosite_manager.tags().len(), 0, "初始时 GeoSiteManager 应该是空的");
        
        // 验证 GeoSiteManager 可以使用
        assert!(!engine.geosite_manager.has_tag("cn"));
        assert!(!engine.geosite_manager.matches("cn", "example.com"));
    });
}

