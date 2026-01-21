// 专门测试 GitHub 域名匹配
// Specific test for GitHub domain matching

use kixdns::geosite::GeoSiteManager;

#[test]
fn test_github_domains_matching() {
    let dat_path = "data/geosite.dat";

    if std::path::Path::new(dat_path).exists() {
        let mut manager = GeoSiteManager::new();
        let result = manager.load_from_dat_file(dat_path);

        if result.is_ok() {
            println!("\n=== GitHub 域名匹配测试 ===\n");

            // 测试各种 GitHub 域名
            let test_domains = vec![
                ("github.com", true),          // 现在应该匹配！
                ("www.github.com", true),
                ("api.github.com", true),
                ("gist.github.com", true),
                ("raw.githubusercontent.com", true),
                ("githubnot.com", false),      // 不应该匹配
                ("notgithub.com", false),      // 不应该匹配
            ];

            let mut all_passed = true;

            for (domain, expected) in test_domains {
                let matches = manager.matches("github", domain);
                let passed = matches == expected;

                if passed {
                    println!("  ✓ {} -> {} (预期: {})",
                        domain,
                        if matches { "匹配" } else { "不匹配" },
                        if expected { "匹配" } else { "不匹配" }
                    );
                } else {
                    println!("  ✗ {} -> {} (预期: {}) ❌ 失败",
                        domain,
                        if matches { "匹配" } else { "不匹配" },
                        if expected { "匹配" } else { "不匹配" }
                    );
                    all_passed = false;
                }

                assert!(passed, "域名 {} 匹配结果不符合预期", domain);
            }

            println!("\n所有测试通过！✅");
        }
    }
}

#[test]
fn test_gfw_not_matching_github() {
    let dat_path = "data/geosite.dat";

    if std::path::Path::new(dat_path).exists() {
        let mut manager = GeoSiteManager::new();
        let result = manager.load_from_dat_file(dat_path);

        if result.is_ok() {
            println!("\n=== GFW 标签不包含 GitHub 测试 ===\n");

            // 验证 GFW 标签不匹配 github.com
            let github_domains = vec![
                "github.com",
                "www.github.com",
                "api.github.com",
            ];

            for domain in github_domains {
                let matches = manager.matches("gfw", domain);
                println!("  gfw 标签匹配 {} -> {}",
                    domain,
                    if matches { "匹配" } else { "不匹配" }
                );
                assert!(!matches, "GFW 标签不应该匹配 {}", domain);
            }

            println!("\n✅ GFW 标签确实不包含 GitHub 域名");
        }
    }
}
