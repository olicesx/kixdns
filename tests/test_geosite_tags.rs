// 测试 GeoSite 标签列表
// Test GeoSite tag listing

use kixdns::geosite::GeoSiteManager;

#[test]
fn test_list_geosite_tags() {
    let dat_path = "data/geosite.dat";

    // 检查文件是否存在
    if std::path::Path::new(dat_path).exists() {
        let mut manager = GeoSiteManager::new();
        let result = manager.load_from_dat_file(dat_path);

        match result {
            Ok(count) => {
                println!("\n成功加载 {} 个 GeoSite 标签\n", count);

                // 获取所有标签
                let tags = manager.tags();

                // 查找 GFW 和 GITHUB 相关标签
                println!("=== GFW 相关标签 ===");
                for tag in tags.iter().filter(|t| t.to_uppercase().contains("GFW")) {
                    println!("  - {}", tag);
                }

                println!("\n=== GITHUB 相关标签 ===");
                for tag in tags.iter().filter(|t| t.to_uppercase().contains("GITHUB")) {
                    println!("  - {}", tag);
                }

                // 检查 GITHUB 标签的详细配置
                if let Some(matchers) = manager.get_tag_matchers("github") {
                    println!("\n=== GITHUB 标签详细配置 ===");
                    println!("包含 {} 个匹配规则:\n", matchers.len());

                    for (i, matcher) in matchers.iter().enumerate() {
                        match matcher {
                            kixdns::geosite::DomainMatcher::Full(domain) => {
                                if domain.contains("github.com") {
                                    println!("{:3}. [Full] {} <<<", i + 1, domain);
                                } else {
                                    println!("{:3}. [Full] {}", i + 1, domain);
                                }
                            }
                            kixdns::geosite::DomainMatcher::Suffix(suffix) => {
                                if suffix.contains("github.com") {
                                    println!("{:3}. [Suffix] {} <<<", i + 1, suffix);
                                } else {
                                    println!("{:3}. [Suffix] {}", i + 1, suffix);
                                }
                            }
                            kixdns::geosite::DomainMatcher::Keyword(keyword) => {
                                if keyword.contains("github") {
                                    println!("{:3}. [Keyword] {} <<<", i + 1, keyword);
                                } else {
                                    println!("{:3}. [Keyword] {}", i + 1, keyword);
                                }
                            }
                            kixdns::geosite::DomainMatcher::Regex(_) => {
                                println!("{:3}. [Regex] ...", i + 1);
                            }
                        }
                    }

                    // 测试匹配
                    println!("\n=== 测试匹配 ===");
                    let test_domains = vec![
                        "github.com",
                        "www.github.com",
                        "api.github.com",
                        "gist.github.com",
                    ];

                    for domain in test_domains {
                        let matches = manager.matches("github", domain);
                        println!("  {} -> {}", domain, if matches { "✓ 匹配" } else { "✗ 不匹配" });
                    }
                } else {
                    println!("\n[WARN] 未找到 GITHUB 标签");
                }

                println!("\n=== 所有标签列表 (前50个) ===");
                for (i, tag) in tags.iter().take(50).enumerate() {
                    println!("  {:3}. {}", i + 1, tag);
                }
            }
            Err(e) => {
                println!("加载失败: {:?}", e);
            }
        }
    } else {
        println!("文件不存在: {}", dat_path);
    }
}
