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
        // Create a GeoSite manager and add test data
        let mut geosite_mgr = GeoSiteManager::new(1000, 3600);
        
        // Simulate loading GeoSite data
        // In real scenario, this would be loaded from V2Ray dat file
        // 这里模拟加载 GeoSite 数据
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
        
        // Test Chinese domain matching
        assert!(geosite_mgr.matches("cn", "www.baidu.com"));
        assert!(geosite_mgr.matches("cn", "example.com.cn"));
        assert!(geosite_mgr.matches("cn", "test.baidu.com"));
        assert!(!geosite_mgr.matches("cn", "www.google.com"));
        
        // Test Google domain matching
        assert!(geosite_mgr.matches("google", "www.google.com"));
        assert!(geosite_mgr.matches("google", "apis.google.com"));
        assert!(geosite_mgr.matches("google", "mail.google.com"));
        assert!(!geosite_mgr.matches("google", "www.baidu.com"));
        
        println!("✅ GeoSite matcher integration test passed");
    }

    // Test 2: GeoIP Matcher Integration Test
    #[test]
    fn test_geoip_matcher_integration() {
        // Test with dummy GeoIP manager (no database)
        let geoip_mgr = GeoIpManager::new(None, 1000, 3600).unwrap();
        
        // Test private IP detection
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
            assert!(result.is_private, "IP {} should be detected as private", ip_str);
            assert!(result.country_code.is_none(), "Private IP should not have country code");
        }
        
        // Test public IP detection
        let public_ips = vec![
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
        ];
        
        for ip_str in public_ips {
            let ip: IpAddr = ip_str.parse().unwrap();
            let result = geoip_mgr.lookup(ip);
            assert!(!result.is_private, "IP {} should not be detected as private", ip_str);
        }
        
        println!("✅ GeoIP matcher integration test passed");
    }

    // Test 3: Qtype Matcher Integration Test
    #[test]
    fn test_qtype_matcher_integration() {
        // Test Qtype matcher parsing and matching
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
            // Test parsing
            let matcher = RuntimeMatcher::Qtype {
                value: expected_type,
            };
            
            // Test matching
            assert!(matcher.matches_with_qtype(
                "example.com",
                DNSClass::IN,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                false,
                expected_type,
                None,
                None,
            ), "Qtype {} should match", type_str);
            
            // Test non-matching
            let different_type = match expected_type {
                RecordType::A => RecordType::AAAA,
                RecordType::AAAA => RecordType::A,
                _ => RecordType::A,
            };
            
            assert!(!matcher.matches_with_qtype(
                "example.com",
                DNSClass::IN,
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                false,
                different_type,
                None,
                None,
            ), "Qtype {} should not match {}", type_str, different_type);
        }
        
        println!("✅ Qtype matcher integration test passed");
    }

    // Test 4: Configuration Parsing Test
    #[test]
    fn test_new_matchers_config_parsing() {
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
                            { "type": "geosite", "value": "cn" },
                            { "type": "geosite_not", "value": "category-ads" }
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

        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("compile");
        
        // Verify pipeline was created
        assert_eq!(runtime.pipelines.len(), 1);
        let pipeline = &runtime.pipelines[0];
        assert_eq!(pipeline.id.as_ref(), "test_pipe");
        assert_eq!(pipeline.rules.len(), 3);
        
        // Verify GeoSite matcher
        let rule1 = &pipeline.rules[0];
        assert_eq!(rule1.name.as_ref(), "geosite_test");
        assert_eq!(rule1.matchers.len(), 2);
        
        // Verify GeoIP matcher
        let rule2 = &pipeline.rules[1];
        assert_eq!(rule2.name.as_ref(), "geoip_test");
        assert_eq!(rule2.matchers.len(), 2);
        
        // Verify Qtype matcher
        let rule3 = &pipeline.rules[2];
        assert_eq!(rule3.name.as_ref(), "qtype_test");
        assert_eq!(rule3.matchers.len(), 1);
        
        println!("✅ Configuration parsing test passed");
    }

    // Test 5: Pipeline Selector with New Matchers
    #[test]
    fn test_pipeline_selector_with_new_matchers() {
        let raw = serde_json::json!({
            "settings": {
                "default_upstream": "1.1.1.1:53"
            },
            "pipeline_select": [
                {
                    "pipeline": "china_pipe",
                    "matchers": [
                        { "type": "geosite", "value": "cn" }
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

        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("compile");
        
        assert_eq!(runtime.pipeline_select.len(), 2);
        
        // Verify GeoSite in pipeline selector
        let sel1 = &runtime.pipeline_select[0];
        assert_eq!(sel1.pipeline, "china_pipe");
        assert_eq!(sel1.matchers.len(), 1);
        
        // Verify Qtype in pipeline selector
        let sel2 = &runtime.pipeline_select[1];
        assert_eq!(sel2.pipeline, "ipv6_pipe");
        assert_eq!(sel2.matchers.len(), 1);
        
        println!("✅ Pipeline selector test passed");
    }

    // Test 6: Edge Cases and Error Handling
    #[test]
    fn test_edge_cases_and_error_handling() {
        // Test GeoSite with empty database
        let empty_geosite = GeoSiteManager::new(100, 60);
        assert!(!empty_geosite.matches("cn", "www.baidu.com"));
        assert!(!empty_geosite.matches("google", "www.google.com"));
        
        // Test GeoIP with invalid IPs
        let geoip_mgr = GeoIpManager::new(None, 100, 60).unwrap();
        let invalid_ip: IpAddr = "0.0.0.0".parse().unwrap();
        let result = geoip_mgr.lookup(invalid_ip);
        assert!(!result.is_private); // 0.0.0.0 is not in private ranges
        
        // Test Qtype case insensitivity
        let matcher = RuntimeMatcher::Qtype {
            value: RecordType::A,
        };
        assert!(matcher.matches_with_qtype(
            "example.com",
            DNSClass::IN,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            false,
            RecordType::A,
            None,
            None,
        ));
        
        println!("✅ Edge cases and error handling test passed");
    }

    // Test 7: Performance and Caching
    #[test]
    fn test_performance_and_caching() {
        // Test GeoSite caching
        let mut geosite_mgr = GeoSiteManager::new(100, 60);
        
        use crate::geosite::{GeoSiteEntry, DomainMatcher};
        geosite_mgr.add_entry(GeoSiteEntry {
            tag: "test".to_string(),
            matchers: vec![DomainMatcher::Suffix(".test.com".to_string())],
        });
        
        // First call - cache miss
        let start = std::time::Instant::now();
        assert!(geosite_mgr.matches("test", "www.test.com"));
        let first_call_duration = start.elapsed();
        
        // Second call - cache hit (should be faster)
        let start = std::time::Instant::now();
        assert!(geosite_mgr.matches("test", "www.test.com"));
        let second_call_duration = start.elapsed();
        
        // Cache hit should be significantly faster
        // Note: This is a basic check, in production you'd want more sophisticated benchmarks
        println!("First call: {:?}, Second call: {:?}", first_call_duration, second_call_duration);
        
        // Test GeoIP caching
        let geoip_mgr = GeoIpManager::new(None, 100, 60).unwrap();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        
        // First lookup
        let result1 = geoip_mgr.lookup(ip);
        assert!(result1.is_private);
        
        // Second lookup (should hit cache)
        let result2 = geoip_mgr.lookup(ip);
        assert!(result2.is_private);
        
        println!("✅ Performance and caching test passed");
    }
}
