// GeoIP/GeoSite 性能压测
// Performance stress tests for GeoIP and GeoSite

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use kixdns::geoip::GeoIpManager;
use kixdns::geosite::GeoSiteManager;

#[test]
fn test_geoip_lookup_latency_benchmark() {
    // ========== Arrange ==========
    let mut geoip_manager = GeoIpManager::new(None).unwrap();
    let geoip_path = PathBuf::from("data/geoip.dat");

    if !geoip_path.exists() {
        println!("Skipping: data/geoip.dat not found");
        return;
    }

    geoip_manager.load_from_dat_file(&geoip_path).expect("load GeoIP");

    // 测试IP列表（涵盖不同场景）
    let test_ips: Vec<IpAddr> = vec![
        "39.156.66.10",    // 中国 IP
        "8.8.8.8",          // Google DNS
        "1.1.1.1",          // Cloudflare DNS
        "192.168.1.1",      // 私有 IP
        "114.114.114.114",  // 国内 DNS
        "223.5.5.5",        // AliDNS
        "211.136.112.61",   // 中国移动
        "61.128.128.66",    // 中国联通
        "202.96.128.86",    // CERNET
        "10.0.0.1",         // 私有 IP
    ].into_iter().map(|s| s.parse().unwrap()).collect();

    // ========== Act: 预热 ==========
    for _ in 0..1000 {
        for ip in &test_ips {
            let _ = geoip_manager.lookup(*ip);
        }
    }

    // ========== Act: 性能测试 ==========
    let iterations = 100_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for ip in &test_ips {
            let _ = geoip_manager.lookup(*ip);
        }
    }

    let elapsed = start.elapsed();
    let total_queries = iterations * test_ips.len();
    let avg_latency_us = elapsed.as_micros() as f64 / total_queries as f64;
    let queries_per_sec = total_queries as f64 / elapsed.as_secs_f64();

    // ========== Assert ==========
    println!("\n=== GeoIP Lookup Latency Benchmark ===");
    println!("Total queries: {}", total_queries);
    println!("Total time: {:?}", elapsed);
    println!("Average latency: {:.2} μs/query", avg_latency_us);
    println!("Throughput: {:.0} queries/sec", queries_per_sec);

    // 性能要求：平均延迟应 < 5μs
    assert!(avg_latency_us < 5.0, "GeoIP lookup too slow: {:.2} μs", avg_latency_us);
    println!("✓ GeoIP latency test passed!");
}

#[test]
fn test_geosite_match_latency_benchmark() {
    // ========== Arrange ==========
    let mut geosite_manager = GeoSiteManager::new();
    let geosite_path = PathBuf::from("data/geosite.dat");

    if !geosite_path.exists() {
        println!("Skipping: data/geosite.dat not found");
        return;
    }

    geosite_manager.load_from_dat_file(&geosite_path).expect("load GeoSite");

    // 测试域名列表
    let test_domains = vec![
        ("www.baidu.com", "cn"),
        ("www.google.com", "google"),
        ("www.github.com", "github"),
        ("www.taobao.com", "cn"),
        ("www.youtube.com", "google"),
        ("www.qq.com", "cn"),
    ];

    // ========== Act: 预热 ==========
    for _ in 0..1000 {
        for (domain, tag) in &test_domains {
            let _ = geosite_manager.matches(tag, domain);
        }
    }

    // ========== Act: 性能测试 ==========
    let iterations = 100_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for (domain, tag) in &test_domains {
            let _ = geosite_manager.matches(tag, domain);
        }
    }

    let elapsed = start.elapsed();
    let total_queries = iterations * test_domains.len();
    let avg_latency_us = elapsed.as_micros() as f64 / total_queries as f64;
    let queries_per_sec = total_queries as f64 / elapsed.as_secs_f64();

    // ========== Assert ==========
    println!("\n=== GeoSite Match Latency Benchmark ===");
    println!("Total queries: {}", total_queries);
    println!("Total time: {:?}", elapsed);
    println!("Average latency: {:.2} μs/query", avg_latency_us);
    println!("Throughput: {:.0} queries/sec", queries_per_sec);

    // 性能要求：平均延迟应 < 2μs
    assert!(avg_latency_us < 2.0, "GeoSite match too slow: {:.2} μs", avg_latency_us);
    println!("✓ GeoSite latency test passed!");
}

#[test]
fn test_concurrent_geoip_lookup_stress() {
    // ========== Arrange ==========
    let mut geoip_manager = GeoIpManager::new(None).unwrap();
    let geoip_path = PathBuf::from("data/geoip.dat");

    if !geoip_path.exists() {
        println!("Skipping: data/geoip.dat not found");
        return;
    }

    geoip_manager.load_from_dat_file(&geoip_path).expect("load GeoIP");

    let geoip_manager = Arc::new(std::sync::Mutex::new(geoip_manager));

    // 测试参数
    let num_threads = 8;
    let queries_per_thread = 10_000;
    let test_ips: Vec<IpAddr> = vec![
        "39.156.66.10", "8.8.8.8", "1.1.1.1", "192.168.1.1", "114.114.114.114",
        "223.5.5.5", "211.136.112.61", "61.128.128.66", "202.96.128.86", "10.0.0.1",
    ].into_iter().map(|s| s.parse().unwrap()).collect();

    // ========== Act: 并发压测 ==========
    let start = Instant::now();

    let mut handles = vec![];
    for _thread_id in 0..num_threads {
        let manager_clone = geoip_manager.clone();
        let ips = test_ips.clone();

        let handle = thread::spawn(move || {
            let mut local_count = 0;
            for i in 0..queries_per_thread {
                let ip = ips[i % ips.len()];
                let _ = manager_clone.lock().unwrap().lookup(ip);
                local_count += 1;
            }
            local_count
        });

        handles.push(handle);
    }

    // 等待所有线程完成
    let total_queries: usize = handles.into_iter()
        .map(|h| h.join().unwrap())
        .sum();

    let elapsed = start.elapsed();

    // ========== Assert ==========
    println!("\n=== Concurrent GeoIP Lookup Stress Test ===");
    println!("Threads: {}", num_threads);
    println!("Total queries: {}", total_queries);
    println!("Total time: {:?}", elapsed);
    println!("Throughput: {:.0} queries/sec", total_queries as f64 / elapsed.as_secs_f64());
    println!("Average latency: {:.2} μs/query", elapsed.as_micros() as f64 / total_queries as f64);

    // 性能要求：并发吞吐量应 > 500k queries/sec
    let throughput = total_queries as f64 / elapsed.as_secs_f64();
    assert!(throughput > 500_000.0, "Concurrent throughput too low: {:.0} qps", throughput);
    println!("✓ Concurrent stress test passed!");
}

#[test]
fn test_cache_hit_rate_analysis() {
    // ========== Arrange ==========
    let mut geoip_manager = GeoIpManager::new(None).unwrap();
    let geoip_path = PathBuf::from("data/geoip.dat");

    if !geoip_path.exists() {
        println!("Skipping: data/geoip.dat not found");
        return;
    }

    geoip_manager.load_from_dat_file(&geoip_path).expect("load GeoIP");

    // 模拟真实场景：部分IP会被重复查询
    let popular_ips = vec![
        "39.156.66.10", "8.8.8.8", "114.114.114.114"
    ].into_iter().map(|s| s.parse().unwrap()).collect::<Vec<IpAddr>>();

    let long_tail_ips: Vec<IpAddr> = (0..100).map(|i| {
        format!("{}.{}.{}.{}", i % 256, (i / 256) % 256, (i / 65536) % 256, i / 16777216)
            .parse().unwrap()
    }).collect();

    // ========== Act: 混合查询模式 ==========
    let iterations = 10_000;
    let start = Instant::now();

    for i in 0..iterations {
        // 80% 热门IP，20% 长尾IP
        let ip = if i % 5 < 4 {
            &popular_ips[i % popular_ips.len()]
        } else {
            &long_tail_ips[i % long_tail_ips.len()]
        };
        let _ = geoip_manager.lookup(*ip);
    }

    let elapsed = start.elapsed();

    // ========== Assert ==========
    println!("\n=== Cache Hit Rate Analysis ===");
    println!("Query pattern: 80% hot IPs, 20% long-tail IPs");
    println!("Total queries: {}", iterations);
    println!("Total time: {:?}", elapsed);
    println!("Average latency: {:.2} μs/query", elapsed.as_micros() as f64 / iterations as f64);
    println!("Throughput: {:.0} queries/sec", iterations as f64 / elapsed.as_secs_f64());

    // 缓存应该显著提升性能
    let avg_latency_us = elapsed.as_micros() as f64 / iterations as f64;
    assert!(avg_latency_us < 3.0, "Cache performance too low: {:.2} μs", avg_latency_us);
    println!("✓ Cache hit rate test passed!");
}

#[test]
fn test_memory_usage_analysis() {
    // ========== Arrange ==========
    let start_mem = get_memory_usage();

    let mut geoip_manager = GeoIpManager::new(None).unwrap();
    let mut geosite_manager = GeoSiteManager::new();

    let geoip_path = PathBuf::from("data/geoip.dat");
    let geosite_path = PathBuf::from("data/geosite.dat");

    if !geoip_path.exists() || !geosite_path.exists() {
        println!("Skipping: data files not found");
        return;
    }

    // ========== Act: 加载数据 ==========
    let geoip_count = geoip_manager.load_from_dat_file(&geoip_path).expect("load GeoIP");
    let geosite_count = geosite_manager.load_from_dat_file(&geosite_path).expect("load GeoSite");

    let end_mem = get_memory_usage();

    // ========== Assert ==========
    println!("\n=== Memory Usage Analysis ===");
    println!("GeoIP entries: {}", geoip_count);
    println!("GeoSite entries: {}", geosite_count);
    println!("Memory used: {:.2} MB", (end_mem - start_mem) as f64 / 1024.0 / 1024.0);

    // 内存使用应该合理（< 500MB）
    let mem_used_mb = (end_mem - start_mem) as f64 / 1024.0 / 1024.0;
    assert!(mem_used_mb < 500.0, "Memory usage too high: {:.2} MB", mem_used_mb);
    println!("✓ Memory usage test passed!");
}

// 辅助函数：获取当前进程内存使用（字节）
#[cfg(windows)]
fn get_memory_usage() -> usize {
    use std::process::Command;

    // 使用 PowerShell 获取内存使用（字节）
    let output = Command::new("powershell")
        .args(&["-Command", "(Get-Process -Id $PID).WorkingSet64"])
        .output()
        .unwrap();

    if output.status.success() {
        let mem_str = String::from_utf8_lossy(&output.stdout);
        mem_str.trim().parse().unwrap_or(0)
    } else {
        0
    }
}

#[cfg(not(windows))]
fn get_memory_usage() -> usize {
    // Linux/macOS 平台（ps 返回的是 KB）
    use std::process::Command;

    let output = Command::new("ps")
        .args(&["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();

    if output.status.success() {
        let mem_str = String::from_utf8_lossy(&output.stdout);
        mem_str.trim().parse::<usize>().unwrap_or(0) * 1024 // KB 转 Bytes
    } else {
        0
    }
}
