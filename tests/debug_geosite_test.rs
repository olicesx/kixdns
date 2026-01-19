// 调试 GeoSite 匹配问题
// Debug GeoSite matching issue

use kixdns::config::PipelineConfig;
use kixdns::geosite::GeoSiteManager;
use kixdns::matcher::RuntimePipelineConfig;
use serde_json::json;

#[test]
fn debug_geosite_matching() {
    // 创建 GeoSiteManager 并添加测试数据
    let mut geosite_manager = GeoSiteManager::new(100, 60);
    
    let v2ray_cn_data = r#"
    {
        "entries": [
            {
                "tag": "cn",
                "domains": [
                    "domain:baidu.com",
                    "domain:qq.com",
                    "*.cn"
                ]
            }
        ]
    }
    "#;
    
    let loaded = geosite_manager.load_from_v2ray_string(v2ray_cn_data);
    println!("Load result: {:?}", loaded);
    
    // 测试匹配
    assert!(geosite_manager.matches("cn", "baidu.com"), "baidu.com should match cn");
    assert!(geosite_manager.matches("cn", "qq.com"), "qq.com should match cn");
    assert!(geosite_manager.matches("cn", "test.cn"), "test.cn should match cn");
    assert!(!geosite_manager.matches("cn", "google.com"), "google.com should not match cn");
    
    println!("All GeoSite matching tests passed!");
}
