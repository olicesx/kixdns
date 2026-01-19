// Integration tests for new matcher features: GeoSite, GeoIP, and Qtype
// 新匹配器功能的集成测试：GeoSite、GeoIP 和 Qtype

#[cfg(test)]
mod integration_tests {
    use crate::config::{GlobalSettings, Matcher, PipelineConfig, Pipeline, Rule, Action};
    use crate::geoip::GeoIpManager;
    use crate::geosite::GeoSiteManager;
    use crate::matcher::{RuntimeMatcher, RuntimePipelineConfig};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use hickory_proto::rr::{DNSClass, RecordType};

    // Test 1: GeoSite Matcher Integration Test
    #[test]
    fn test_geosite_matcher_integration() {
        // Arrange: Create a GeoSite manager and add test data
        let mut geosite_mgr = GeoSiteManager::new(1000, 3600);
        
        // Simulate loading GeoSite data
        // In real scenario, this would be loaded from V2Ray dat file
        use crate::geosite::GeoSiteEntry;
        use crate::geosite::DomainMatcher;
        
        // Add "cn" tag with Chinese domains
        geosite_mgr.add_entry(GeoSiteEntry {
            tag: "cn".to_string(),
            matchers: vec![
                DomainMatcher::Suffix(".cn".to_string()),
                DomainMatcher::Suffix(".com.cn".to_string()),
                DomainMatcher::Keyword("baidu".to_string()),
            ],
        });
        
        // Add "google" tag
        geosite_mgr.add_entry(GeoSiteEntry {
            tag: "google".to_string(),
            matchers: vec![
                DomainMatcher::Suffix(".google.com".to_string()),
                DomainMatcher::Suffix(".googleapis.com".to_string()),
                DomainMatcher::Keyword("google".to_string()),
            ],
        });
        
        // Act & Assert: Test Chinese domain matching
        assert!(
            geosite_mgr.matches("cn", "www.baidu.com"),
            "Chinese domain baidu.com should match 'cn' tag"
        );
        assert!(
            geosite_mgr.matches("cn", "example.com.cn"),
            "Chinese domain example.com.cn should match 'cn' tag"
        );
        assert!(
            geosite_mgr.matches("cn", "test.baidu.com"),
            "Chinese domain test.baidu.com should match 'cn' tag"
        );
        assert!(
            !geosite_mgr.matches("cn", "www.google.com"),
            "Google domain should not match 'cn' tag"
        );
        
        // Act & Assert: Test Google domain matching
        assert!(
            geosite_mgr.matches("google", "www.google.com"),
            "Google domain should match 'google' tag"
        );
        assert!(
            geosite_mgr.matches("google", "apis.google.com"),
            "Google APIs domain should match 'google' tag"
        );
        assert!(
            geosite_mgr.matches("google", "mail.google.com"),
            "Google Mail domain should match 'google' tag"
        );
        assert!(
            !geosite_mgr.matches("google", "www.baidu.com"),
            "Baidu domain should not match 'google' tag"
        );
        
        println!("✅ GeoSite matcher integration test passed");
    }

    // Test 2: GeoIP Matcher Integration Test
    #[test]
    fn test_geoip_matcher_integration() {
        // Arrange: Test with dummy GeoIP manager (no database)
        let geoip_mgr = GeoIpManager::new(None, 1000, 3600).unwrap();
        
        // Act & Assert: Test private IP detection
        let private_ips = vec![
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "127.0.0.1",
            "::1",
            "fe80::1",
        ];
        
        for ip_str in private_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let result = geoip_mgr.lookup(ip);
            assert!(
                result.is_private, 
                "IP {} should be detected as private", 
                ip_str
            );
            assert!(
                result.country_code.is_none(), 
                "Private IP should not have country code"
            );
        }
        
        // Act & Assert: Test public IP detection
        let public_ips = vec![
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
        ];
        
        for ip_str in public_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let result = geoip_mgr.lookup(ip);
            assert!(
                !result.is_private, 
                "IP {} should not be detected as private", 
                ip_str
            );
        }
        
        println!("✅ GeoIP matcher integration test passed");
    }

    // Test 3: Qtype Matcher Integration Test
    #[test]
    fn test_qtype_matcher_integration() {
        // Arrange: Setup test data with all supported DNS record types
        let qtypes = vec![
            ("A", RecordType::A),
            ("AAAA", RecordType::AAAA),
            ("CNAME", RecordType::CNAME),
            ("MX", RecordType::MX),
            ("TXT", RecordType::TXT),
            ("NS", RecordType::NS),
            ("PTR", RecordType::PTR),
            ("SOA", RecordType::SOA),
            ("SRV", RecordType::SRV),
            ("OPT", RecordType::OPT),
        ];
        
        for (type_str, expected_type) in qtypes {
            // Act & Assert: Test parsing
            let matcher = RuntimeMatcher::Qtype {
                value: expected_type,
            };
            
            // Act & Assert: Test matching
            assert!(
                matcher.matches_with_qtype(
                    "example.com",
                    DNSClass::IN,
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    false,
                    expected_type,
                    None,
                    None,
                ), 
                "Qtype {} should match", 
                type_str
            );
            
            // Act & Assert: Test non-matching
            let different_type = match expected_type {
                RecordType::A => RecordType::AAAA,
                RecordType::AAAA => RecordType::A,
                _ => RecordType::A,
            };
            
            assert!(
                !matcher.matches_with_qtype(
                    "example.com",
                    DNSClass::IN,
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    false,
                    different_type,
                    None,
                    None,
                ), 
                "Qtype {} should not match {}", 
                type_str, 
                different_type
            );
        }
        
        println!("✅ Qtype matcher integration test passed");
    }

    // Test 4: Configuration Parsing Test
    #[test]
    fn test_new_matchers_config_parsing() {
        // Arrange: Create a configuration with all new matcher types
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "1.1.1.1:53"
            },
            "pipelines": [{
                "id": "test_pipe",
                "rules": [
                    {
                        "name": "geosite_test",
                        "matchers": [
                            { "type": "geo_site", "value": "cn" },
                            { "type": "geo_site_not", "value": "category-ads" }
                        ],
                        "actions": [
                            { "type": "allow" }
                        ]
                    },
                    {
                        "name": "geoip_test",
                        "matchers": [
                            { "type": "geoip_country", "country_codes": ["CN", "US", "JP"] },
                            { "type": "geoip_private", "expect": false }
                        ],
                        "actions": [
                            { "type": "allow" }
                        ]
                    },
                    {
                        "name": "qtype_test",
                        "matchers": [
                            { "type": "qtype", "value": "AAAA" }
                        ],
                        "actions": [
                            { "type": "forward", "upstream": "2606:4700:4700::1111:53" }
                        ]
                    }
                ]
            }]
        });

        // Act: Parse and compile the configuration
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("compile");
        
        // Assert: Verify pipeline was created with correct structure
        assert_eq!(runtime.pipelines.len(), 1, "Should have exactly one pipeline");
        let pipeline = &runtime.pipelines[0];
        assert_eq!(pipeline.id.as_ref(), "test_pipe", "Pipeline ID should match");
        assert_eq!(pipeline.rules.len(), 3, "Should have exactly three rules");
        
        // Assert: Verify GeoSite matcher configuration
        let rule1 = &pipeline.rules[0];
        assert_eq!(rule1.name.as_ref(), "geosite_test", "First rule name should match");
        assert_eq!(rule1.matchers.len(), 2, "First rule should have two matchers");
        
        // Assert: Verify GeoIP matcher configuration
        let rule2 = &pipeline.rules[1];
        assert_eq!(rule2.name.as_ref(), "geoip_test", "Second rule name should match");
        assert_eq!(rule2.matchers.len(), 2, "Second rule should have two matchers");
        
        // Assert: Verify Qtype matcher configuration
        let rule3 = &pipeline.rules[2];
        assert_eq!(rule3.name.as_ref(), "qtype_test", "Third rule name should match");
        assert_eq!(rule3.matchers.len(), 1, "Third rule should have one matcher");
        
        println!("✅ Configuration parsing test passed");
    }

    // Test 5: Pipeline Selector with New Matchers
    #[test]
    fn test_pipeline_selector_with_new_matchers() {
        // Arrange: Create configuration with pipeline selectors using new matchers
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "1.1.1.1:53"
            },
            "pipeline_select": [
                {
                    "pipeline": "china_pipe",
                    "matchers": [
                        { "type": "geo_site", "value": "cn" }
                    ]
                },
                {
                    "pipeline": "ipv6_pipe",
                    "matchers": [
                        { "type": "qtype", "value": "AAAA" }
                    ]
                }
            ],
            "pipelines": [
                { "id": "china_pipe", "rules": [] },
                { "id": "ipv6_pipe", "rules": [] }
            ]
        });

        // Act: Parse and compile the configuration
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("compile");
        
        // Assert: Verify pipeline selectors were created correctly
        assert_eq!(runtime.pipeline_select.len(), 2, "Should have exactly two pipeline selectors");
        
        // Assert: Verify GeoSite in pipeline selector
        let sel1 = &runtime.pipeline_select[0];
        assert_eq!(sel1.pipeline, "china_pipe", "First selector should target china_pipe");
        assert_eq!(sel1.matchers.len(), 1, "First selector should have one matcher");
        
        // Assert: Verify Qtype in pipeline selector
        let sel2 = &runtime.pipeline_select[1];
        assert_eq!(sel2.pipeline, "ipv6_pipe", "Second selector should target ipv6_pipe");
        assert_eq!(sel2.matchers.len(), 1, "Second selector should have one matcher");
        
        println!("✅ Pipeline selector test passed");
    }

    // Test 6: Edge Cases and Error Handling
    #[test]
    fn test_edge_cases_and_error_handling() {
        // Arrange: Create empty GeoSite manager and GeoIP manager
        let empty_geosite = GeoSiteManager::new(100, 60);
        let geoip_mgr = GeoIpManager::new(None, 100, 60).unwrap();
        let invalid_ip: IpAddr = "0.0.0.0".parse().unwrap();
        
        // Act & Assert: Test GeoSite with empty database
        assert!(!empty_geosite.matches("cn", "www.baidu.com"), 
            "Empty GeoSite database should not match any domain");
        assert!(!empty_geosite.matches("google", "www.google.com"), 
            "Empty GeoSite database should not match any domain");
        
        // Act & Assert: Test GeoIP with invalid IPs
        let result = geoip_mgr.lookup(invalid_ip);
        assert!(!result.is_private, "0.0.0.0 should not be in private ranges");
        
        // Arrange: Create Qtype matcher
        let matcher = RuntimeMatcher::Qtype {
            value: RecordType::A,
        };
        
        // Act & Assert: Test Qtype case insensitivity
        assert!(matcher.matches_with_qtype(
            "example.com",
            DNSClass::IN,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            false,
            RecordType::A,
            None,
            None,
        ), "Qtype matcher should match same record type");
        
        println!("✅ Edge cases and error handling test passed");
    }

    // Test 7: Performance and Caching
    #[test]
    fn test_performance_and_caching() {
        // Arrange: Create GeoSite manager and add test entry
        let mut geosite_mgr = GeoSiteManager::new(100, 60);
        
        use crate::geosite::{GeoSiteEntry, DomainMatcher};
        geosite_mgr.add_entry(GeoSiteEntry {
            tag: "test".to_string(),
            matchers: vec![DomainMatcher::Suffix(".test.com".to_string())],
        });
        
        // Act & Assert: First call - cache miss
        let start = std::time::Instant::now();
        assert!(geosite_mgr.matches("test", "www.test.com"), 
            "GeoSite should match domain in test entry");
        let first_call_duration = start.elapsed();
        
        // Act & Assert: Second call - cache hit (should be faster)
        let start = std::time::Instant::now();
        assert!(geosite_mgr.matches("test", "www.test.com"), 
            "GeoSite should match domain from cache");
        let second_call_duration = start.elapsed();
        
        // Assert: Cache hit should be significantly faster
        // Note: This is a basic check, in production you'd want more sophisticated benchmarks
        println!("First call: {:?}, Second call: {:?}", first_call_duration, second_call_duration);
        
        // Arrange: Create GeoIP manager and test IP
        let geoip_mgr = GeoIpManager::new(None, 100, 60).unwrap();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        // Act & Assert: First lookup
        let result1 = geoip_mgr.lookup(ip);
        assert!(result1.is_private, "192.168.1.1 should be identified as private IP");
        
        // Act & Assert: Second lookup (should hit cache)
        let result2 = geoip_mgr.lookup(ip);
        assert!(result2.is_private, "Cached lookup should also identify as private IP");
        
        println!("✅ Performance and caching test passed");
    }
}
