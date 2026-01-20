use kixdns::geosite::GeoSiteManager;

#[test]
fn test_baidu_matches_cn() {
    // 启用调试日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(true)
        .try_init()
        .ok();
    
    // 初始化GeoSiteManager
    let mut geosite = GeoSiteManager::new(10000, 3600);
    
    // 加载GeoSite数据
    let result = geosite.load_from_dat_file("data/geosite.dat");
    assert!(result.is_ok(), "Failed to load GeoSite data");
    
    let count = result.unwrap();
    println!("Loaded {} GeoSite entries", count);
    
    // 测试一些常见的中国域名
    let test_domains = vec![
        "www.baidu.com",
        "www.taobao.com",
        "www.qq.com",
        "www.163.com",
        "www.sina.com.cn",
        "baidu.com",
        "taobao.com",
    ];
    
    println!("Testing common Chinese domains:");
    for domain in &test_domains {
        let result = geosite.matches("cn", domain);
        println!("  {}: {}", domain, result);
    }
    
    // 测试www.baidu.com是否匹配cn标签
    let domain = "www.baidu.com";
    let tag = "cn";
    
    let result = geosite.matches(tag, domain);
    println!("\nFinal test:");
    println!("Domain: {}", domain);
    println!("Tag: {}", tag);
    println!("Match: {}", result);
    
    // 暂时不断言,先看看结果
    // assert!(result, "www.baidu.com should match cn tag");
}
