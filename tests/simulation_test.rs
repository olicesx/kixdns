// GeoSite + GeoIP 仿真测试
// Simulation tests for GeoSite and GeoIP routing

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

use kixdns::config::PipelineConfig;
use kixdns::engine::Engine;
use kixdns::geoip::GeoIpManager;
use kixdns::geosite::GeoSiteManager;
use kixdns::matcher::RuntimePipelineConfig;

#[test]
fn test_simulation_geosite_routing() {
    // ========== Arrange ==========
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .try_init()
        .ok();

    let config_path = PathBuf::from("config/test_geosite_geoip.json");
    if !config_path.exists() {
        println!("Skipping test: config file not found");
        return;
    }

    // 加载配置
    let config_content = fs::read_to_string(&config_path)
        .expect("read config file");
    let config: PipelineConfig = serde_json::from_str(&config_content)
        .expect("parse config");

    // 加载 GeoSite 和 GeoIP 数据
    let mut geosite_manager = GeoSiteManager::new();
    let geosite_path = PathBuf::from("data/geosite.dat");
    if geosite_path.exists() {
        let count = geosite_manager.load_from_dat_file(&geosite_path)
            .expect("load GeoSite data");
        println!("✓ Loaded {} GeoSite entries", count);
    } else {
        println!("✗ GeoSite data file not found, skipping GeoSite tests");
        return;
    }

    let mut geoip_manager = GeoIpManager::new(None)
        .expect("create GeoIP manager");
    let geoip_path = PathBuf::from("data/geoip.dat");
    if geoip_path.exists() {
        let count = geoip_manager.load_from_dat_file(&geoip_path)
            .expect("load GeoIP data");
        println!("✓ Loaded {} GeoIP entries", count);
    } else {
        println!("✗ GeoIP data file not found, skipping GeoIP tests");
        return;
    }

    // 创建 Runtime 配置
    let runtime_config = RuntimePipelineConfig::from_config(config)
        .expect("create runtime config");

    // ========== Act & Assert ==========
    // 测试用例: (domain, expected_pipeline_description)
    // 注意:检查 .dat 文件中实际有哪些 tag
    let test_cases = vec![
        ("www.baidu.com", "china_direct", "CN domain"),
        ("www.taobao.com", "china_direct", "CN domain"),
        ("www.qq.com", "china_direct", "CN domain"),
        ("www.google.com", "google_direct", "Google domain"),
        ("www.github.com", "github_direct", "GitHub domain"),
        ("www.cloudflare.com", "default_forward", "Other domain (Cloudflare)"),
        ("www.amazon.com", "default_forward", "Other domain (Amazon)"),
    ];

    println!("\n=== GeoSite Routing Simulation ===");
    for (domain, expected_pipeline, description) in test_cases {
        let start = Instant::now();

        // 测试 GeoSite 匹配
        let cn_match = geosite_manager.matches("cn", domain);
        let google_match = geosite_manager.matches("google", domain);
        let github_match = geosite_manager.matches("github", domain);

        let elapsed = start.elapsed();

        // 判断预期路由
        let matched_pipeline = if cn_match {
            "china_direct"
        } else if google_match {
            "google_direct"
        } else if github_match {
            "github_direct"
        } else {
            "default_forward"
        };

        let status = if matched_pipeline == expected_pipeline {
            "✓"
        } else {
            "✗"
        };

        println!("{} {} -> {} (expected {}, {}) [{:?}]",
            status,
            domain,
            matched_pipeline,
            expected_pipeline,
            description,
            elapsed
        );

        assert_eq!(matched_pipeline, expected_pipeline,
            "Domain {} should route to {}", domain, expected_pipeline);
    }
}

#[test]
fn test_simulation_geoip_routing() {
    // ========== Arrange ==========
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .try_init()
        .ok();

    let mut geoip_manager = GeoIpManager::new(None)
        .expect("create GeoIP manager");

    let geoip_path = PathBuf::from("data/geoip.dat");
    if !geoip_path.exists() {
        println!("Skipping test: data/geoip.dat not found");
        return;
    }

    let _ = geoip_manager.load_from_dat_file(&geoip_path)
        .expect("load GeoIP data");

    // ========== Act & Assert ==========
    // 测试用例: (ip, expected_country_code, description)
    // 注意:.dat 文件将私有 IP 标记为 "PRIVATE" 国家代码
    let test_cases = vec![
        ("39.156.66.10", Some("CN"), "Alibaba CDN"),
        ("61.128.128.66", Some("CN"), "China Unicom"),
        ("211.136.112.61", Some("CN"), "China Mobile"),
        ("202.96.128.86", Some("CN"), "CERNET"),
        ("8.8.8.8", Some("GOOGLE"), "Google DNS"),
        ("1.1.1.1", Some("AU"), "Cloudflare DNS"),
        ("114.114.114.114", Some("CN"), "114 DNS"),
        ("223.5.5.5", Some("CN"), "AliDNS"),
        ("10.0.0.1", Some("PRIVATE"), "Private IP (marked as PRIVATE in .dat)"),
        ("192.168.1.1", Some("PRIVATE"), "Private IP (marked as PRIVATE in .dat)"),
        ("127.0.0.1", Some("PRIVATE"), "Loopback (marked as PRIVATE in .dat)"),
    ];

    println!("\n=== GeoIP Routing Simulation ===");
    for (ip_str, expected_country, description) in test_cases {
        let start = Instant::now();

        let ip: IpAddr = ip_str.parse().expect("parse IP");
        let result = geoip_manager.lookup(ip);

        let elapsed = start.elapsed();

        let country_match = result.country_code.as_deref() == expected_country;

        let status = if country_match && result.is_private == expected_country.is_none() {
            "✓"
        } else {
            "✗"
        };

        println!("{} {} -> {:?} (expected {:?}), private={} [{:?}]",
            status,
            ip_str,
            result.country_code,
            expected_country,
            result.is_private,
            elapsed
        );

        assert_eq!(result.country_code.as_deref(), expected_country,
            "IP {} should resolve to {:?}", ip_str, expected_country);
    }
}

#[test]
fn test_simulation_combined_routing() {
    // ========== Arrange ==========
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .try_init()
        .ok();

    let mut geosite_manager = GeoSiteManager::new();
    let mut geoip_manager = GeoIpManager::new(None).unwrap();

    let geosite_path = PathBuf::from("data/geosite.dat");
    let geoip_path = PathBuf::from("data/geoip.dat");

    if !geosite_path.exists() || !geoip_path.exists() {
        println!("Skipping test: data files not found");
        return;
    }

    let _ = geosite_manager.load_from_dat_file(&geosite_path).expect("load GeoSite");
    let _ = geoip_manager.load_from_dat_file(&geoip_path).expect("load GeoIP");

    // ========== Act & Assert ==========
    // 综合测试用例: (domain, client_ip, geosite_tag, geoip_country, description)
    // 注意:.dat 文件对某些 IP 有特殊标记(如 8.8.8.8 -> GOOGLE, 私有 IP -> PRIVATE)
    let test_cases = vec![
        ("www.baidu.com", "39.156.66.10", Some("cn"), Some("CN"), "CN domain + CN IP"),
        ("www.google.com", "8.8.8.8", Some("google"), Some("GOOGLE"), "Google domain + GOOGLE IP"),
        ("www.github.com", "192.168.1.1", Some("github"), Some("PRIVATE"), "GitHub domain + Private IP"),
        ("www.cloudflare.com", "39.156.66.10", None, Some("CN"), "Cloudflare domain + CN IP"),
        ("www.amazon.com", "1.1.1.1", None, Some("AU"), "Amazon domain + AU IP"),
    ];

    println!("\n=== Combined GeoSite + GeoIP Routing Simulation ===");
    println!("{:<25} {:<15} {:<10} {:<10} {:<20}",
        "Domain", "Client IP", "GeoSite", "GeoIP", "Routing Decision");

    for (domain, client_ip_str, expected_geosite, expected_geoip, description) in test_cases {
        let start = Instant::now();

        // GeoSite 检查
        let geosite_result = if geosite_manager.matches("cn", domain) {
            "cn"
        } else if geosite_manager.matches("google", domain) {
            "google"
        } else if geosite_manager.matches("github", domain) {
            "github"
        } else {
            ""
        };

        // GeoIP 检查
        let client_ip: IpAddr = client_ip_str.parse().expect("parse IP");
        let geoip_result = geoip_manager.lookup(client_ip);
        let geoip_country = geoip_result.country_code.as_deref().unwrap_or("");
        let is_private = geoip_result.is_private || geoip_country == "PRIVATE";

        // 路由决策
        let routing = if !geosite_result.is_empty() {
            format!("GeoSite:{}", geosite_result)
        } else if is_private {
            "DENY (private IP)".to_string()
        } else if !geoip_country.is_empty() {
            format!("GeoIP:{}", geoip_country)
        } else {
            "DEFAULT".to_string()
        };

        let elapsed = start.elapsed();

        let geosite_match = geosite_result == expected_geosite.unwrap_or("");
        let geoip_match = geoip_result.country_code.as_deref() == expected_geoip;

        let status = if geosite_match && geoip_match { "✓" } else { "✗" };

        println!("{} {:<25} {:<15} {:<10} {:<10} {:<20} [{:?}]",
            status,
            domain,
            client_ip_str,
            geosite_result,
            geoip_country,
            routing,
            elapsed
        );

        // 验证结果
        assert_eq!(geosite_result, expected_geosite.unwrap_or(""),
            "GeoSite mismatch for {}", description);
        assert_eq!(geoip_result.country_code.as_deref(), expected_geoip,
            "GeoIP mismatch for {}", description);
    }

    println!("\n✓ All combined routing tests passed!");
}

#[test]
fn test_simulation_performance() {
    // ========== Arrange ==========
    let mut geosite_manager = GeoSiteManager::new();
    let mut geoip_manager = GeoIpManager::new(None).unwrap();

    let geosite_path = PathBuf::from("data/geosite.dat");
    let geoip_path = PathBuf::from("data/geoip.dat");

    if !geosite_path.exists() || !geoip_path.exists() {
        println!("Skipping performance test: data files not found");
        return;
    }

    let _ = geosite_manager.load_from_dat_file(&geosite_path).expect("load GeoSite");
    let _ = geoip_manager.load_from_dat_file(&geoip_path).expect("load GeoIP");

    // ========== Act ==========
    let test_domains = vec![
        "www.baidu.com", "www.google.com", "www.github.com",
        "www.taobao.com", "www.qq.com", "www.youtube.com",
    ];
    let test_ips = vec![
        "39.156.66.10", "8.8.8.8", "1.1.1.1",
        "61.128.128.66", "114.114.114.114", "223.5.5.5",
    ];

    // 预热
    for domain in &test_domains {
        let _ = geosite_manager.matches("cn", domain);
    }
    for ip_str in &test_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let _ = geoip_manager.lookup(ip);
    }

    // 性能测试
    let iterations = 10000;
    let start = Instant::now();

    for _ in 0..iterations {
        // GeoSite 查询
        for domain in &test_domains {
            let _ = geosite_manager.matches("cn", domain);
        }

        // GeoIP 查询
        for ip_str in &test_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let _ = geoip_manager.lookup(ip);
        }
    }

    let elapsed = start.elapsed();
    let total_queries = iterations * (test_domains.len() + test_ips.len());
    let avg_latency = elapsed.as_micros() as f64 / total_queries as f64;
    let throughput = total_queries as f64 / elapsed.as_secs_f64();

    // ========== Assert ==========
    println!("\n=== Performance Simulation Results ===");
    println!("Total iterations: {}", iterations);
    println!("Total queries: {}", total_queries);
    println!("Total time: {:?}", elapsed);
    println!("Average latency: {:.2} μs/query", avg_latency);
    println!("Throughput: {:.0} queries/sec", throughput);

    // 性能要求
    assert!(avg_latency < 10.0, "Average latency too high: {:.2} μs", avg_latency);
    println!("✓ Performance test passed!");
}
