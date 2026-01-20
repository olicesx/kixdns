// GeoIP 和 GeoSite 集成测试
// Integration tests for GeoIP and GeoSite functionality

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

use kixdns::geoip::GeoIpManager;
use kixdns::geosite::GeoSiteManager;

#[test]
fn test_geoip_dat_file_loading() {
    // 测试 GeoIP .dat 文件加载
    // Test GeoIP .dat file loading
    
    let dat_path = PathBuf::from("data/geoip.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geoip.dat not found");
        return;
    }
    
    let start = Instant::now();
    let mut manager = GeoIpManager::new(None, 10000, 3600).unwrap();
    let result = manager.load_from_dat_file(&dat_path);
    let elapsed = start.elapsed();
    
    assert!(result.is_ok(), "Failed to load GeoIP .dat file: {:?}", result.err());
    
    let count = result.unwrap();
    println!("✓ GeoIP .dat file loaded {} entries in {:?}", count, elapsed);
    
    // 验证加载了足够的条目
    assert!(count > 100000, "Expected at least 100k GeoIP entries, got {}", count);
}

#[test]
fn test_geoip_lookup_performance() {
    // 测试 GeoIP 查询性能
    // Test GeoIP lookup performance
    
    let dat_path = PathBuf::from("data/geoip.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geoip.dat not found");
        return;
    }
    
    // 加载 GeoIP 数据
    let mut manager = GeoIpManager::new(None, 10000, 3600).unwrap();
    let _ = manager.load_from_dat_file(&dat_path).unwrap();
    
    // 测试 IP 列表（包含各种公网 IP）
    let test_ips = vec![
        "8.8.8.8",           // Google DNS
        "1.1.1.1",           // Cloudflare DNS
        "114.114.114.114",  // 114 DNS
        "223.5.5.5",        // AliDNS
        "180.76.76.76",     // DNSPod
        "39.156.66.10",     // 中国电信
        "61.128.128.66",    // 中国联通
        "211.136.112.61",   // 中国移动
        "202.96.128.86",    // 中国教育网
        "47.104.17.18",     // 阿里云
    ];
    
    // 预热缓存
    for ip_str in &test_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let _ = manager.lookup(ip);
    }
    
    // 性能测试：10000 次查询
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        for ip_str in &test_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let _ = manager.lookup(ip);
        }
    }
    
    let elapsed = start.elapsed();
    let total_lookups = iterations * test_ips.len();
    let avg_latency = elapsed.as_micros() as f64 / total_lookups as f64;
    
    println!("✓ GeoIP lookup performance:");
    println!("  Total lookups: {}", total_lookups);
    println!("  Total time: {:?}", elapsed);
    println!("  Average latency: {:.2} μs", avg_latency);
    println!("  Throughput: {:.0} lookups/sec", total_lookups as f64 / elapsed.as_secs_f64());
    
    // 性能要求：平均延迟应小于 100 μs
    assert!(avg_latency < 100.0, "GeoIP lookup too slow: {:.2} μs", avg_latency);
}

#[test]
fn test_geoip_china_ips() {
    // 测试中国 IP 的识别
    // Test Chinese IP identification
    
    let dat_path = PathBuf::from("data/geoip.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geoip.dat not found");
        return;
    }
    
    let mut manager = GeoIpManager::new(None, 10000, 3600).unwrap();
    let _ = manager.load_from_dat_file(&dat_path).unwrap();
    
    // 中国 IP 列表
    let china_ips = vec![
        "39.156.66.10",
        "61.128.128.66",
        "211.136.112.61",
        "202.96.128.86",
        "120.241.0.1",
    ];
    
    let mut china_count = 0;
    for ip_str in &china_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let result = manager.lookup(ip);
        
        if let Some(country_code) = &result.country_code {
            if country_code == "CN" {
                china_count += 1;
                println!("✓ {} -> CN (correct)", ip_str);
            } else {
                println!("✗ {} -> {} (expected CN)", ip_str, country_code);
            }
        } else {
            println!("✗ {} -> No country code", ip_str);
        }
    }
    
    println!("✓ Chinese IP recognition: {}/{}", china_count, china_ips.len());
    assert!(china_count >= china_ips.len() / 2, 
           "Expected at least half of Chinese IPs to be recognized");
}

#[test]
fn test_geosite_dat_file_loading() {
    // 测试 GeoSite .dat 文件加载
    // Test GeoSite .dat file loading
    
    let dat_path = PathBuf::from("data/geosite.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geosite.dat not found");
        return;
    }
    
    let start = Instant::now();
    let mut manager = GeoSiteManager::new(10000, 3600);
    let result = manager.load_from_dat_file(&dat_path);
    let elapsed = start.elapsed();
    
    assert!(result.is_ok(), "Failed to load GeoSite .dat file: {:?}", result.err());
    
    let count = result.unwrap();
    println!("✓ GeoSite .dat file loaded {} entries in {:?}", count, elapsed);
    
    // 验证加载了足够的条目
    assert!(count > 1000, "Expected at least 1000 GeoSite entries, got {}", count);
}

#[test]
fn test_geosite_selective_loading() {
    // 测试 GeoSite 按需加载
    // Test GeoSite selective loading
    
    let dat_path = PathBuf::from("data/geosite.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geosite.dat not found");
        return;
    }
    
    // 只加载几个常用的 tag
    let tags_to_load: Vec<String> = vec!["cn".into(), "google".into(), "github".into(), "apple".into(), "microsoft".into()];
    
    let start = Instant::now();
    let mut manager = GeoSiteManager::new(10000, 3600);
    let result = manager.load_from_dat_file_selective(&dat_path, &tags_to_load);
    let elapsed = start.elapsed();
    
    assert!(result.is_ok(), "Failed to load GeoSite selectively: {:?}", result.err());
    
    let count = result.unwrap();
    println!("✓ GeoSite selective loading: {} tags in {:?}", count, elapsed);
    
    // 验证加载的 tag 数量
    assert!(count > 0 && count <= tags_to_load.len(), 
           "Expected 1-{} tags, got {}", tags_to_load.len(), count);
}

#[test]
fn test_geosite_matching_performance() {
    // 测试 GeoSite 匹配性能
    // Test GeoSite matching performance
    
    let dat_path = PathBuf::from("data/geosite.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geosite.dat not found");
        return;
    }
    
    // 加载所有 GeoSite 数据
    let mut manager = GeoSiteManager::new(10000, 3600);
    let _ = manager.load_from_dat_file(&dat_path).unwrap();
    
    // 测试域名列表（包含各种常见域名）
    let test_domains = vec![
        "www.baidu.com",
        "www.google.com",
        "www.github.com",
        "www.apple.com",
        "www.microsoft.com",
        "www.taobao.com",
        "www.qq.com",
        "www.youtube.com",
        "www.facebook.com",
        "www.amazon.com",
    ];
    
    // 预热缓存
    for domain in &test_domains {
        let _ = manager.matches("cn", domain);
    }
    
    // 性能测试：10000 次匹配
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        for domain in &test_domains {
            let _ = manager.matches("cn", domain);
        }
    }
    
    let elapsed = start.elapsed();
    let total_matches = iterations * test_domains.len();
    let avg_latency = elapsed.as_micros() as f64 / total_matches as f64;
    
    println!("✓ GeoSite matching performance:");
    println!("  Total matches: {}", total_matches);
    println!("  Total time: {:?}", elapsed);
    println!("  Average latency: {:.2} μs", avg_latency);
    println!("  Throughput: {:.0} matches/sec", total_matches as f64 / elapsed.as_secs_f64());
    
    // 性能要求：平均延迟应小于 50 μs
    assert!(avg_latency < 50.0, "GeoSite matching too slow: {:.2} μs", avg_latency);
}

#[test]
fn test_geosite_cn_matching() {
    // 测试中国域名匹配
    // Test Chinese domain matching
    
    let dat_path = PathBuf::from("data/geosite.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geosite.dat not found");
        return;
    }
    
    let mut manager = GeoSiteManager::new(10000, 3600);
    let _ = manager.load_from_dat_file(&dat_path).unwrap();
    
    // 中国域名列表
    let china_domains = vec![
        "www.baidu.com",
        "www.taobao.com",
        "www.qq.com",
        "www.jd.com",
        "www.weibo.com",
    ];
    
    let mut match_count = 0;
    for domain in &china_domains {
        if manager.matches("cn", domain) {
            match_count += 1;
            println!("✓ {} -> CN (matched)", domain);
        } else {
            println!("✗ {} -> CN (not matched)", domain);
        }
    }
    
    println!("✓ Chinese domain matching: {}/{}", match_count, china_domains.len());
    assert!(match_count >= china_domains.len() / 2, 
           "Expected at least half of Chinese domains to match");
}

#[test]
fn test_geosite_multiple_tags() {
    // 测试多个 tag 的匹配
    // Test matching against multiple tags
    
    let dat_path = PathBuf::from("data/geosite.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geosite.dat not found");
        return;
    }
    
    let mut manager = GeoSiteManager::new(10000, 3600);
    let _ = manager.load_from_dat_file(&dat_path).unwrap();
    
    // 测试域名
    let test_domain = "www.google.com";
    let test_tags = vec!["cn", "google", "github"];
    
    println!("Testing domain: {}", test_domain);
    for tag in &test_tags {
        let matches = manager.matches(tag, test_domain);
        println!("  tag='{}': {}", tag, if matches { "✓ matched" } else { "✗ not matched" });
    }
    
    // 验证 google tag 能匹配
    assert!(manager.matches("google", test_domain), 
           "Expected 'google' tag to match www.google.com");
}

#[test]
fn test_geoip_private_ip_detection() {
    // 测试私有 IP 检测
    // Test private IP detection
    
    let manager = GeoIpManager::new(None, 10000, 3600).unwrap();
    
    let private_ips = vec![
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
    ];
    
    for ip_str in &private_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let result = manager.lookup(ip);
        
        assert!(result.is_private, "Expected {} to be private", ip_str);
        println!("✓ {} -> private (correct)", ip_str);
    }
    
    let public_ips = vec![
        "8.8.8.8",
        "1.1.1.1",
        "114.114.114.114",
    ];
    
    for ip_str in &public_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let result = manager.lookup(ip);
        
        assert!(!result.is_private, "Expected {} to be public", ip_str);
        println!("✓ {} -> public (correct)", ip_str);
    }
}

#[test]
fn test_combined_geoip_geosite_performance() {
    // 测试 GeoIP + GeoSite 组合性能
    // Test combined GeoIP + GeoSite performance
    
    let geoip_path = PathBuf::from("data/geoip.dat");
    let geosite_path = PathBuf::from("data/geosite.dat");
    
    if !geoip_path.exists() || !geosite_path.exists() {
        println!("Skipping test: data files not found");
        return;
    }
    
    // 加载数据
    let mut geoip_manager = GeoIpManager::new(None, 10000, 3600).unwrap();
    let _ = geoip_manager.load_from_dat_file(&geoip_path).unwrap();
    
    let mut geosite_manager = GeoSiteManager::new(10000, 3600);
    let _ = geosite_manager.load_from_dat_file(&geosite_path).unwrap();
    
    // 模拟 DNS 查询场景：同时检查 GeoIP 和 GeoSite
    let test_cases = vec![
        ("8.8.8.8", "www.google.com"),
        ("39.156.66.10", "www.baidu.com"),
        ("1.1.1.1", "www.github.com"),
    ];
    
    // 性能测试：10000 次组合查询
    let iterations = 10000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        for (ip_str, domain) in &test_cases {
            let ip: IpAddr = ip_str.parse().unwrap();
            let _ = geoip_manager.lookup(ip);
            let _ = geosite_manager.matches("cn", domain);
        }
    }
    
    let elapsed = start.elapsed();
    let total_queries = iterations * test_cases.len();
    let avg_latency = elapsed.as_micros() as f64 / total_queries as f64;
    
    println!("✓ Combined GeoIP + GeoSite performance:");
    println!("  Total queries: {}", total_queries);
    println!("  Total time: {:?}", elapsed);
    println!("  Average latency: {:.2} μs", avg_latency);
    println!("  Throughput: {:.0} queries/sec", total_queries as f64 / elapsed.as_secs_f64());
    
    // 性能要求：组合查询延迟应小于 200 μs
    assert!(avg_latency < 200.0, "Combined query too slow: {:.2} μs", avg_latency);
}

#[test]
fn test_cache_effectiveness() {
    // 测试缓存有效性
    // Test cache effectiveness
    
    let dat_path = PathBuf::from("data/geoip.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geoip.dat not found");
        return;
    }
    
    let mut manager = GeoIpManager::new(None, 100, 60).unwrap();
    let _ = manager.load_from_dat_file(&dat_path).unwrap();
    
    let test_ip: IpAddr = "8.8.8.8".parse().unwrap();
    
    // 第一次查询（缓存未命中）
    let start1 = Instant::now();
    let result1 = manager.lookup(test_ip);
    let elapsed1 = start1.elapsed();
    
    // 第二次查询（缓存命中）
    let start2 = Instant::now();
    let result2 = manager.lookup(test_ip);
    let elapsed2 = start2.elapsed();
    
    println!("✓ Cache effectiveness:");
    println!("  First lookup: {:?}", elapsed1);
    println!("  Second lookup: {:?}", elapsed2);
    println!("  Speedup: {:.2}x", elapsed1.as_nanos() as f64 / elapsed2.as_nanos() as f64);
    
    // 验证缓存命中更快
    assert!(elapsed2 < elapsed1, "Cache should make lookup faster");
    assert_eq!(result1.country_code, result2.country_code, "Results should be identical");
}
