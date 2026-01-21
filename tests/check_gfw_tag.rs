// 检查 GFW 标签的详细内容
// Check GFW tag details

use kixdns::geosite::GeoSiteManager;

#[test]
fn check_gfw_tag_details() {
    let dat_path = "data/geosite.dat";

    if std::path::Path::new(dat_path).exists() {
        let mut manager = GeoSiteManager::new();
        let result = manager.load_from_dat_file(dat_path);

        if result.is_ok() {
            println!("\n=== GFW 标签详细配置 ===\n");

            if let Some(matchers) = manager.get_tag_matchers("gfw") {
                println!("包含 {} 个匹配规则:\n", matchers.len());

                for (i, matcher) in matchers.iter().enumerate() {
                    match matcher {
                        kixdns::geosite::DomainMatcher::Full(domain) => {
                            println!("{:4}. [Full] {}", i + 1, domain);
                        }
                        kixdns::geosite::DomainMatcher::Suffix(suffix) => {
                            println!("{:4}. [Suffix] {}", i + 1, suffix);
                        }
                        kixdns::geosite::DomainMatcher::Keyword(keyword) => {
                            println!("{:4}. [Keyword] {}", i + 1, keyword);
                        }
                        kixdns::geosite::DomainMatcher::Regex(_) => {
                            println!("{:4}. [Regex] ...", i + 1);
                        }
                    }
                }

                // 测试匹配
                println!("\n=== 测试 GFW 标签匹配 ===\n");
                let test_domains = vec![
                    "github.com",
                    "www.github.com",
                    "google.com",
                    "youtube.com",
                ];

                for domain in test_domains {
                    let matches = manager.matches("gfw", domain);
                    println!("  {} -> {}", domain, if matches { "✓ 匹配" } else { "✗ 不匹配" });
                }
            } else {
                println!("未找到 GFW 标签");
            }
        }
    }
}
