// GeoSite 性能基准测试
// 
// 测试 GeoSite 匹配器的性能表现

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use kixdns::geosite::{GeoSiteManager, DomainMatcher, GeoSiteEntry};
use std::time::Duration;

/// 基准测试：域名完全匹配
fn bench_domain_matcher_full(c: &mut Criterion) {
    let matcher = DomainMatcher::Full("example.com".to_string());
    
    c.bench_function("domain_matcher_full_hit", |b| {
        b.iter(|| {
            black_box(matcher.matches("example.com"))
        })
    });
}

/// 基准测试：域名后缀匹配
fn bench_domain_matcher_suffix(c: &mut Criterion) {
    let matcher = DomainMatcher::Suffix("example.com".to_string());
    
    c.bench_function("domain_matcher_suffix_hit", |b| {
        b.iter(|| {
            black_box(matcher.matches("www.example.com"))
        })
    });
}

/// 基准测试：域名关键字匹配
fn bench_domain_matcher_keyword(c: &mut Criterion) {
    let matcher = DomainMatcher::Keyword("test".to_string());
    
    c.bench_function("domain_matcher_keyword_hit", |b| {
        b.iter(|| {
            black_box(matcher.matches("test.com"))
        })
    });
}

/// 基准测试：GeoSite 管理器 - 缓存命中
fn bench_geosite_manager_cache_hit(c: &mut Criterion) {
    let mut manager = GeoSiteManager::new(10000, 3600);
    
    // 添加测试数据
    let domains = vec![
        DomainMatcher::Full("example.com".to_string()),
        DomainMatcher::Full("test.com".to_string()),
        DomainMatcher::Full("google.com".to_string()),
    ];
    
    for matcher in domains {
        let entry = GeoSiteEntry {
            tag: "test".to_string(),
            matchers: vec![matcher],
        };
        manager.add_entry(entry);
    }
    
    // 预热缓存
    for _ in 0..100 {
        let _ = manager.matches("test", "example.com");
    }
    
    c.bench_function("geosite_manager_cache_hit", |b| {
        b.iter(|| {
            black_box(manager.matches("test", "example.com"))
        })
    });
}

/// 基准测试：GeoSite 管理器 - 缓存未命中
fn bench_geosite_manager_cache_miss(c: &mut Criterion) {
    let mut manager = GeoSiteManager::new(10000, 3600);
    
    // 添加测试数据
    let domains = vec![
        DomainMatcher::Full("example.com".to_string()),
        DomainMatcher::Full("test.com".to_string()),
    ];
    
    for matcher in domains {
        let entry = GeoSiteEntry {
            tag: "test".to_string(),
            matchers: vec![matcher],
        };
        manager.add_entry(entry);
    }
    
    c.bench_function("geosite_manager_cache_miss", |b| {
        b.iter(|| {
            black_box(manager.matches("test", "nonexistent.com"))
        })
    });
}

/// 基准测试：不同数据集大小的性能
fn bench_geosite_manager_dataset_size(c: &mut Criterion) {
    let sizes = vec![100, 1000, 10000];
    let test_domain = "test999.com";
    
    let mut group = c.benchmark_group("dataset_size");
    
    for size in sizes {
        let mut manager = GeoSiteManager::new(size * 10, 3600);
        
        // 添加测试数据
        for i in 0..size {
            let matcher = DomainMatcher::Full(format!("test{}.com", i));
            let entry = GeoSiteEntry {
                tag: "test".to_string(),
                matchers: vec![matcher],
            };
            manager.add_entry(entry);
        }
        
        // 添加测试域名
        let test_matcher = DomainMatcher::Full(test_domain.to_string());
        let test_entry = GeoSiteEntry {
            tag: "test".to_string(),
            matchers: vec![test_matcher],
        };
        manager.add_entry(test_entry);
        
        // 预热缓存
        for _ in 0..100 {
            let _ = manager.matches("test", test_domain);
        }
        
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(manager.matches("test", test_domain))
            })
        });
    }
    
    group.finish();
}

/// 基准测试：后缀索引性能
fn bench_geosite_manager_suffix_index(c: &mut Criterion) {
    let mut manager = GeoSiteManager::new(10000, 3600);
    
    // 添加大量后缀域名
    for i in 0..1000 {
        let matcher = DomainMatcher::Suffix(format!("test{}.example.com", i));
        let entry = GeoSiteEntry {
            tag: "test".to_string(),
            matchers: vec![matcher],
        };
        manager.add_entry(entry);
    }
    
    // 测试不同深度的子域名匹配
    let mut group = c.benchmark_group("suffix_depth");
    
    group.bench_function("depth_1", |b| {
        b.iter(|| {
            black_box(manager.matches("test", "sub.example.com"))
        })
    });
    
    group.bench_function("depth_2", |b| {
        b.iter(|| {
            black_box(manager.matches("test", "www.sub.example.com"))
        })
    });
    
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .sample_size(100);
    targets =
        bench_domain_matcher_full,
        bench_domain_matcher_suffix,
        bench_domain_matcher_keyword,
        bench_geosite_manager_cache_hit,
        bench_geosite_manager_cache_miss,
        bench_geosite_manager_dataset_size,
        bench_geosite_manager_suffix_index
}

criterion_main!(benches);
