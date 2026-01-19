// V2Ray GeoSite 文件加载测试
use kixdns::geosite::{GeoSiteManager, V2RayGeoSiteList};

#[test]
fn test_v2ray_format_parsing() {
    // 创建 V2Ray 格式的 JSON 数据
    let json_data = r#"
    {
        "entries": [
            {
                "tag": "cn",
                "domains": [
                    "domain:example.com.cn",
                    ".cn",
                    "keyword:baidu",
                    "regexp:^.*\\.google\\.cn$"
                ]
            },
            {
                "tag": "google",
                "domains": [
                    "domain:google.com",
                    ".google.com",
                    ".googleapis.com",
                    ".googletagmanager.com"
                ]
            },
            {
                "tag": "category-ads",
                "domains": [
                    "keyword:ads",
                    ".adserver.com",
                    ".doubleclick.net"
                ]
            }
        ]
    }
    "#;

    // 解析 JSON
    let v2ray_data: V2RayGeoSiteList = serde_json::from_str(json_data)
        .expect("parse V2Ray format");
    
    // 验证解析结果
    assert_eq!(v2ray_data.entries.len(), 3);
    assert_eq!(v2ray_data.entries[0].tag, "cn");
    assert_eq!(v2ray_data.entries[0].domains.len(), 4);
    assert_eq!(v2ray_data.entries[1].tag, "google");
    assert_eq!(v2ray_data.entries[1].domains.len(), 4);
}

#[test]
fn test_load_from_v2ray_string() {
    let mut manager = GeoSiteManager::new(100, 60);
    
    let json_data = r#"
    {
        "entries": [
            {
                "tag": "test",
                "domains": [
                    "domain:example.com",
                    ".test.com",
                    "keyword:test"
                ]
            }
        ]
    }
    "#;

    let count = manager.load_from_v2ray_string(json_data).expect("load from string");
    
    assert_eq!(count, 1);
    assert!(manager.has_tag("test"));
    assert!(manager.matches("test", "example.com"));
    assert!(manager.matches("test", "www.test.com"));
    assert!(manager.matches("test", "mytest.com"));
    assert!(!manager.matches("test", "google.com"));
}

#[test]
fn test_v2ray_domain_conversion() {
    let mut manager = GeoSiteManager::new(100, 60);
    
    let json_data = r#"
    {
        "entries": [
            {
                "tag": "cn",
                "domains": [
                    "domain:example.com.cn",
                    ".cn",
                    "keyword:baidu",
                    "regexp:^.*\\.baidu\\.com$"
                ]
            }
        ]
    }
    "#;

    manager.load_from_v2ray_string(json_data).expect("load from string");
    
    // 测试完整域名匹配
    assert!(manager.matches("cn", "example.com.cn"));
    // 注意：domain: 只匹配完整域名，不匹配子域名
    // assert!(!manager.matches("cn", "www.example.com.cn"));
    
    // 测试后缀匹配
    assert!(manager.matches("cn", "test.cn"));
    assert!(manager.matches("cn", "www.test.cn"));
    
    // 测试关键词匹配
    assert!(manager.matches("cn", "baidu.com"));
    assert!(manager.matches("cn", "www.baidu.com"));
    
    // 测试正则匹配
    assert!(manager.matches("cn", "test.baidu.com"));
    assert!(!manager.matches("cn", "test.google.com"));
}

#[test]
fn test_v2ray_wildcard_domains() {
    let mut manager = GeoSiteManager::new(100, 60);
    
    let json_data = r#"
    {
        "entries": [
            {
                "tag": "test",
                "domains": [
                    "*.example.com",
                    "test.*.com"
                ]
            }
        ]
    }
    "#;

    manager.load_from_v2ray_string(json_data).expect("load from wildcard domains");
    
    // 测试通配符匹配（应该转换为正则）
    // *.example.com → ^.*\.example\.com$ 匹配任意子域名
    assert!(manager.matches("test", "www.example.com"));
    assert!(manager.matches("test", "api.example.com"));
    assert!(!manager.matches("test", "example.com")); // 根域名不匹配（需要子域名）
    
    // test.*.com → ^test\..*\.com$ 匹配 test.任意字符.com
    assert!(manager.matches("test", "test.api.com"));
    assert!(manager.matches("test", "test.www.com"));
    assert!(!manager.matches("test", "test123.com")); // 缺少中间的点，不匹配
    assert!(!manager.matches("test", "test.com")); // 缺少中间部分，不匹配
}
