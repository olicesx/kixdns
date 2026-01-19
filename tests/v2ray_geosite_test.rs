//! # V2Ray GeoSite Format Tests
//!
//! ## Purpose
//! Tests for V2Ray format GeoSite data parsing and loading.
//!
//! ## Test Categories
//! - Unit tests: JSON parsing, domain format conversion
//! - Integration tests: GeoSiteManager with V2Ray data
//!
//! ## Test Data
//! - Source: Embedded JSON strings in V2Ray format
//! - Format: V2Ray GeoSite JSON specification

// Copyright (c) 2026 KixDNS Contributors
// SPDX-License-Identifier: MIT

use kixdns::geosite::{GeoSiteManager, V2RayGeoSiteList};

// ========== Test Constants ==========

const V2RAY_TEST_DATA: &str = r#"
{
    "entries": [
        {
            "tag": "cn",
            "domains": [
                "domain:example.com.cn",
                ".cn",
                "keyword:baidu",
                "regexp:^.*\\.google\\.cn$"
            ]
        },
        {
            "tag": "google",
            "domains": [
                "domain:google.com",
                ".google.com",
                ".googleapis.com",
                ".googletagmanager.com"
            ]
        },
        {
            "tag": "category-ads",
            "domains": [
                "keyword:ads",
                ".adserver.com",
                ".doubleclick.net"
            ]
        }
    ]
}
"#;

// ========== Unit Tests ==========

#[test]
fn test_v2ray_format_parsing_returns_correct_structure() {
    // ========== Arrange ==========
    // V2RAY_TEST_DATA is defined above

    // ========== Act ==========
    let v2ray_data: V2RayGeoSiteList = serde_json::from_str(V2RAY_TEST_DATA)
        .expect("Failed to parse V2Ray format");

    // ========== Assert ==========
    assert_eq!(v2ray_data.entries.len(), 3, "Should have 3 entries");
    assert_eq!(v2ray_data.entries[0].tag, "cn", "First entry should be CN");
    assert_eq!(v2ray_data.entries[0].domains.len(), 4, "CN entry should have 4 domains");
    assert_eq!(v2ray_data.entries[1].tag, "google", "Second entry should be Google");
    assert_eq!(v2ray_data.entries[1].domains.len(), 4, "Google entry should have 4 domains");
}

#[test]
fn test_load_from_v2ray_string_loads_single_entry() {
    // ========== Arrange ==========
    let mut manager = GeoSiteManager::new(100, 60);
    let json_data = r#"
    {
        "entries": [
            {
                "tag": "test",
                "domains": [
                    "domain:example.com",
                    ".test.com",
                    "keyword:test"
                ]
            }
        ]
    }
    "#;

    // ========== Act ==========
    let count = manager.load_from_v2ray_string(json_data)
        .expect("Failed to load from V2Ray string");

    // ========== Assert ==========
    assert_eq!(count, 1, "Should load 1 entry");
    assert!(manager.has_tag("test"), "Should have test tag");
    assert!(manager.matches("test", "example.com"), "Should match exact domain");
    assert!(manager.matches("test", "www.test.com"), "Should match suffix");
    assert!(manager.matches("test", "mytest.com"), "Should match keyword");
    assert!(!manager.matches("test", "google.com"), "Should not match unrelated domain");
}

#[test]
fn test_v2ray_domain_conversion_converts_all_formats() {
    // ========== Arrange ==========
    let mut manager = GeoSiteManager::new(100, 60);
    let json_data = r#"
    {
        "entries": [
            {
                "tag": "cn",
                "domains": [
                    "domain:example.com.cn",
                    ".cn",
                    "keyword:baidu",
                    "regexp:^.*\\.baidu\\.com$"
                ]
            }
        ]
    }
    "#;

    // ========== Act ==========
    manager.load_from_v2ray_string(json_data)
        .expect("Failed to load V2Ray data");

    // ========== Assert ==========
    // Test full domain matching
    assert!(manager.matches("cn", "example.com.cn"), "Should match full domain");
    // Note: domain: matches exact domain and subdomains in current implementation
    assert!(manager.matches("cn", "www.example.com.cn"), 
        "Full domain matcher should match subdomains");

    // Test suffix matching
    assert!(manager.matches("cn", "test.cn"), "Should match suffix");
    assert!(manager.matches("cn", "www.test.cn"), "Should match suffix with subdomain");

    // Test keyword matching
    assert!(manager.matches("cn", "baidu.com"), "Should match keyword");
    assert!(manager.matches("cn", "www.baidu.com"), "Should match keyword in subdomain");

    // Test regex matching
    assert!(manager.matches("cn", "test.baidu.com"), "Should match regex pattern");
    assert!(!manager.matches("cn", "test.google.com"), "Should not match unrelated domain");
}

#[test]
fn test_v2ray_wildcard_domains_converts_to_regex() {
    // ========== Arrange ==========
    let mut manager = GeoSiteManager::new(100, 60);
    let json_data = r#"
    {
        "entries": [
            {
                "tag": "test",
                "domains": [
                    "*.example.com",
                    "test.*.com"
                ]
            }
        ]
    }
    "#;

    // ========== Act ==========
    manager.load_from_v2ray_string(json_data)
        .expect("Failed to load wildcard domains");

    // ========== Assert ==========
    // Wildcard *.example.com → ^.*\.example\.com$ matches any subdomain
    assert!(manager.matches("test", "www.example.com"), 
        "Should match subdomain with wildcard");
    assert!(manager.matches("test", "api.example.com"), 
        "Should match another subdomain");
    assert!(!manager.matches("test", "example.com"), 
        "Root domain should not match wildcard (requires subdomain)");

    // Wildcard test.*.com → ^test\..*\.com$ matches test.anything.com
    assert!(manager.matches("test", "test.api.com"), 
        "Should match test.api.com");
    assert!(manager.matches("test", "test.www.com"), 
        "Should match test.www.com");
    assert!(!manager.matches("test", "test123.com"), 
        "Should not match without middle dot");
    assert!(!manager.matches("test", "test.com"), 
        "Should not match without middle part");
}
