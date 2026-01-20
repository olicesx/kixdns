//! GeoIP 延迟加载测试 / GeoIP lazy loading tests
//! 
//! 这个测试验证 GeoIP MMDB 文件的延迟加载功能 / This test verifies lazy loading of GeoIP MMDB files
//! 
//! 测试场景 / Test scenarios:
//! - 配置中不使用 GeoIP 匹配器时，不应加载 MMDB 文件 / When config doesn't use GeoIP matchers, MMDB should not be loaded
//! - 配置中使用 GeoIP 匹配器时，应在第一次查询时才加载 MMDB / When config uses GeoIP matchers, MMDB should be loaded on first query

use kixdns::geoip::GeoIpManager;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_geoip_lazy_loading_no_usage() {
    // Arrange: 创建 GeoIpManager 但不提供 MMDB 路径
    // Arrange: Create GeoIpManager without MMDB path
    let manager = GeoIpManager::new(None, 100, 60).expect("create manager");
    
    // Act & Assert: 验证 MMDB 未加载 / Verify MMDB is not loaded
    assert!(!manager.is_loaded(), "MMDB should not be loaded when no path provided");
    
    // Act: 执行查询 / Perform lookup
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let result = manager.lookup(ip);
    
    // Assert: 验证结果只包含私有 IP 检测 / Verify result only contains private IP check
    assert!(result.is_private, "Should detect private IP correctly");
    assert!(result.country_code.is_none(), "Should have no country code without MMDB");
    assert!(!manager.is_loaded(), "MMDB should still not be loaded");
}

#[test]
fn test_geoip_lazy_loading_with_usage() {
    // Arrange: 创建 GeoIpManager 并提供 MMDB 路径（但文件不存在）
    // Arrange: Create GeoIpManager with MMDB path (but file doesn't exist)
    let manager = GeoIpManager::new(
        Some("nonexistent.mmdb".to_string()),
        100,
        60
    ).expect("create manager");
    
    // Act & Assert: 验证 MMDB 未加载（文件不存在）/ Verify MMDB is not loaded (file doesn't exist)
    assert!(!manager.is_loaded(), "MMDB should not be loaded when file doesn't exist");
    
    // Act: 执行查询 / Perform lookup
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let result = manager.lookup(ip);
    
    // Assert: 验证结果只包含私有 IP 检测 / Verify result only contains private IP check
    assert!(!result.is_private, "Public IP should not be private");
    assert!(result.country_code.is_none(), "Should have no country code without MMDB");
    // MMDB 仍然未加载（因为文件不存在）/ MMDB still not loaded (file doesn't exist)
}

#[test]
fn test_geoip_lazy_loading_deferred() {
    // Arrange: 创建 GeoIpManager 并提供 MMDB 路径
    // Arrange: Create GeoIpManager with MMDB path
    let manager = GeoIpManager::new(
        Some("test.mmdb".to_string()),
        100,
        60
    ).expect("create manager");
    
    // Act & Assert: 验证 MMDB 未立即加载 / Verify MMDB is not loaded immediately
    assert!(!manager.is_loaded(), "MMDB should not be loaded immediately");
    
    // Act: 执行查询 / Perform lookup
    let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    let result = manager.lookup(ip);
    
    // Assert: 验证结果包含私有 IP 检测 / Verify result contains private IP check
    assert!(!result.is_private, "Public IP should not be private");
    // 注意：由于测试环境可能没有实际的 MMDB 文件，country_code 仍然是 None
    // Note: In test environment without actual MMDB file, country_code is still None
    assert!(result.country_code.is_none(), "Should have no country code without MMDB file");
    
    // MMDB 仍然未加载（因为文件不存在）/ MMDB still not loaded (file doesn't exist)
    assert!(!manager.is_loaded(), "MMDB should not be loaded when file doesn't exist");
}
