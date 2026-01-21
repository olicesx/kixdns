// 测试后缀匹配自身功能
// Test suffix matching with itself

use kixdns::geosite::{GeoSiteManager, GeoSiteEntry, DomainMatcher};

#[test]
fn test_suffix_matches_itself() {
    // 测试 .github.com 能匹配 github.com
    let mut manager = GeoSiteManager::new();

    manager.add_entry(GeoSiteEntry {
        tag: "test".to_string(),
        matchers: vec![
            DomainMatcher::Suffix(".github.com".to_string()),
        ],
    });

    // 测试：后缀应该匹配自身
    assert!(manager.matches("test", "github.com"),
        "Suffix .github.com should match github.com");
    assert!(manager.matches("test", "www.github.com"),
        "Suffix .github.com should match www.github.com");
    assert!(manager.matches("test", "api.github.com"),
        "Suffix .github.com should match api.github.com");

    println!("✓ 后缀匹配自身功能正常");
}

#[test]
fn test_suffix_without_dot() {
    // 测试不带点的后缀匹配
    let mut manager = GeoSiteManager::new();

    manager.add_entry(GeoSiteEntry {
        tag: "cn".to_string(),
        matchers: vec![
            DomainMatcher::Suffix(".cn".to_string()),
        ],
    });

    // 测试：带点的后缀应该能匹配域名本身
    assert!(manager.matches("cn", "cn"),
        "Suffix .cn should match cn");
    assert!(manager.matches("cn", "baidu.cn"),
        "Suffix .cn should match baidu.cn");
    assert!(manager.matches("cn", "www.baidu.cn"),
        "Suffix .cn should match www.baidu.cn");

    println!("✓ 不带点后缀匹配功能正常");
}

#[test]
fn test_full_vs_suffix_match() {
    // 测试 Full 和 Suffix 的区别
    let mut manager = GeoSiteManager::new();

    manager.add_entry(GeoSiteEntry {
        tag: "test".to_string(),
        matchers: vec![
            DomainMatcher::Full("example.com".to_string()),
            DomainMatcher::Suffix(".test.com".to_string()),
        ],
    });

    // Full 只匹配完全相同的域名
    assert!(manager.matches("test", "example.com"),
        "Full should match exact domain");
    assert!(!manager.matches("test", "www.example.com"),
        "Full should not match subdomain");

    // Suffix 匹配自身和子域名
    assert!(manager.matches("test", "test.com"),
        "Suffix should match domain itself");
    assert!(manager.matches("test", "www.test.com"),
        "Suffix should match subdomain");

    println!("✓ Full 和 Suffix 区别正确");
}

#[test]
fn test_domain_matcher_directly() {
    // 直接测试 DomainMatcher
    let matcher = DomainMatcher::Suffix(".github.com".to_string());

    assert!(matcher.matches("github.com"),
        "Suffix .github.com should match github.com");
    assert!(matcher.matches("www.github.com"),
        "Suffix .github.com should match www.github.com");
    assert!(!matcher.matches("github.com.hk"),
        "Suffix .github.com should not match github.com.hk");

    println!("✓ DomainMatcher 直接测试通过");
}
