//! GeoSite 热重载功能测试
//! 
//! 测试 GeoSite 数据文件的热重载功能，包括：
//! - 文件监控启动
//! - 文件修改触发重载
//! - 数据正确更新

use std::fs;

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试热重载功能的基本流程
    #[test]
    fn test_geosite_hot_reload_basic() {
        // 创建临时测试文件
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("geosite_test_hot.json");
        
        // 初始数据：只有 google 分类
        let initial_data = r#"{
            "entries": [
                {
                    "tag": "google",
                    "domains": ["google.com", "google.com.hk"]
                }
            ]
        }"#;
        
        fs::write(&test_file, initial_data)
            .expect("Failed to write initial test file");
        
        // 创建 GeoSiteManager 并加载数据
        let mut manager = kixdns::geosite::GeoSiteManager::new(100, 60);
        manager.load_from_v2ray_file(&test_file)
            .expect("Failed to load initial data");
        
        // 验证初始数据
        assert!(manager.matches("google", "test.google.com"));
        assert!(!manager.matches("youtube", "test.youtube.com"));
        
        // 修改文件：添加 youtube 分类
        let updated_data = r#"{
            "entries": [
                {
                    "tag": "google",
                    "domains": ["google.com", "google.com.hk"]
                },
                {
                    "tag": "youtube",
                    "domains": ["youtube.com", "youtu.be"]
                }
            ]
        }"#;
        
        fs::write(&test_file, updated_data)
            .expect("Failed to write updated test file");
        
        // 重新加载数据
        manager.load_from_v2ray_file(&test_file)
            .expect("Failed to load updated data");
        
        // 验证更新后的数据
        assert!(manager.matches("google", "test.google.com"));
        assert!(manager.matches("youtube", "www.youtube.com"));
        
        // 清理测试文件
        let _ = fs::remove_file(&test_file);
    }

    /// 测试热重载时的数据合并
    #[test]
    fn test_geosite_hot_reload_merge() {
        let temp_dir = std::env::temp_dir();
        let test_file1 = temp_dir.join("geosite_merge_1.json");
        let test_file2 = temp_dir.join("geosite_merge_2.json");
        
        // 第一个文件：google 分类
        let data1 = r#"{
            "entries": [
                {
                    "tag": "google",
                    "domains": ["google.com"]
                }
            ]
        }"#;
        
        // 第二个文件：youtube 分类
        let data2 = r#"{
            "entries": [
                {
                    "tag": "youtube",
                    "domains": ["youtube.com"]
                }
            ]
        }"#;
        
        fs::write(&test_file1, data1).expect("Failed to write test file 1");
        fs::write(&test_file2, data2).expect("Failed to write test file 2");
        
        // 创建 GeoSiteManager 并加载两个文件
        let mut manager = kixdns::geosite::GeoSiteManager::new(100, 60);
        manager.load_from_v2ray_file(&test_file1).expect("Failed to load file 1");
        manager.load_from_v2ray_file(&test_file2).expect("Failed to load file 2");
        
        // 验证两个分类都存在
        assert!(manager.matches("google", "test.google.com"));
        assert!(manager.matches("youtube", "test.youtube.com"));
        
        // 清理测试文件
        let _ = fs::remove_file(&test_file1);
        let _ = fs::remove_file(&test_file2);
    }

    /// 测试热重载时的数据替换
    #[test]
    fn test_geosite_hot_reload_replace() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("geosite_replace.json");
        
        // 初始数据：少量域名
        let initial_data = r#"{
            "entries": [
                {
                    "tag": "test",
                    "domains": ["example.com"]
                }
            ]
        }"#;
        
        fs::write(&test_file, initial_data).expect("Failed to write initial file");
        
        let mut manager = kixdns::geosite::GeoSiteManager::new(100, 60);
        manager.load_from_v2ray_file(&test_file).expect("Failed to load initial data");
        
        // 验证初始数据
        assert!(manager.matches("test", "example.com"));
        assert!(!manager.matches("test", "test.example.org"));
        
        // 更新数据：更多域名
        let updated_data = r#"{
            "entries": [
                {
                    "tag": "test",
                    "domains": ["example.com", "example.org", "keyword:test"]
                }
            ]
        }"#;
        
        fs::write(&test_file, updated_data).expect("Failed to write updated file");
        manager.load_from_v2ray_file(&test_file).expect("Failed to load updated data");
        
        // 验证更新后的数据
        assert!(manager.matches("test", "example.com"));
        assert!(manager.matches("test", "example.org"));
        assert!(manager.matches("test", "mytest.com"));
        
        // 清理测试文件
        let _ = fs::remove_file(&test_file);
    }

    /// 测试热重载时的错误处理
    #[test]
    fn test_geosite_hot_reload_error_handling() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("geosite_error.json");
        
        // 初始有效数据
        let initial_data = r#"{
            "entries": [
                {
                    "tag": "test",
                    "domains": ["example.com"]
                }
            ]
        }"#;
        
        fs::write(&test_file, initial_data).expect("Failed to write initial file");
        
        let mut manager = kixdns::geosite::GeoSiteManager::new(100, 60);
        manager.load_from_v2ray_file(&test_file).expect("Failed to load initial data");
        
        // 验证初始数据
        assert!(manager.matches("test", "example.com"));
        
        // 写入无效 JSON
        let invalid_data = r#"{
            "test": [
                "domain:example.com",
            ]
        }"#; // 无效的 JSON（末尾有逗号）
        
        fs::write(&test_file, invalid_data).expect("Failed to write invalid file");
        
        // 尝试加载应该失败
        let result = manager.load_from_v2ray_file(&test_file);
        assert!(result.is_err(), "Loading invalid JSON should fail");
        
        // 验证原有数据仍然可用
        assert!(manager.matches("test", "example.com"));
        
        // 清理测试文件
        let _ = fs::remove_file(&test_file);
    }

    /// 测试热重载时的缓存失效
    #[test]
    fn test_geosite_hot_reload_cache_invalidation() {
        let temp_dir = std::env::temp_dir();
        let test_file = temp_dir.join("geosite_cache.json");
        
        // 初始数据
        let initial_data = r#"{
            "entries": [
                {
                    "tag": "test",
                    "domains": ["example.com", "keyword:test"]
                }
            ]
        }"#;
        
        fs::write(&test_file, initial_data).expect("Failed to write initial file");
        
        let mut manager = kixdns::geosite::GeoSiteManager::new(100, 60);
        manager.load_from_v2ray_file(&test_file).expect("Failed to load initial data");
        
        // 第一次匹配：缓存命中
        assert!(manager.matches("test", "test.example.com"));
        
        // 第二次匹配：缓存命中
        assert!(manager.matches("test", "test.example.com"));
        
        // 更新数据
        let updated_data = r#"{
            "entries": [
                {
                    "tag": "test",
                    "domains": ["example.com", "keyword:test", "keyword:example"]
                }
            ]
        }"#;
        
        fs::write(&test_file, updated_data).expect("Failed to write updated file");
        manager.load_from_v2ray_file(&test_file).expect("Failed to load updated data");
        
        // 重新加载后缓存应该失效，新规则应该生效
        assert!(manager.matches("test", "test.example.com"));
        assert!(manager.matches("test", "myexample.com"));
        
        // 清理测试文件
        let _ = fs::remove_file(&test_file);
    }
}
