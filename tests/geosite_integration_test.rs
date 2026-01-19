//! # GeoSite Engine Integration Tests
//!
//! ## Purpose
//! Tests for GeoSite matcher integration with the DNS engine.
//!
//! ## Test Categories
//! - Unit tests: GeoSiteManager with direct data
//! - Integration tests: GeoSite with Engine and pipeline selection
//!
//! ## Test Data
//! - Source: Programmatically created test entries
//! - Format: GeoSiteEntry structures

// Copyright (c) 2026 KixDNS Contributors
// SPDX-License-Identifier: MIT

use kixdns::config::PipelineConfig;
use kixdns::engine::Engine;
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::geosite::{GeoSiteEntry, GeoSiteManager, DomainMatcher};

// ========== Helper Functions ==========

fn create_test_manager() -> GeoSiteManager {
    GeoSiteManager::new(100, 60)
}

fn create_test_entry(tag: &str, domains: Vec<&str>) -> GeoSiteEntry {
    GeoSiteEntry {
        tag: tag.to_string(),
        matchers: domains.into_iter()
            .map(|d| DomainMatcher::Full(d.to_string()))
            .collect(),
    }
}

// ========== Unit Tests ==========

#[test]
fn test_geosite_matcher_with_data_matches_domains() {
    // ========== Arrange ==========
    let mut manager = create_test_manager();
    
    let entries = vec![
        GeoSiteEntry {
            tag: "cn".to_string(),
            matchers: vec![
                DomainMatcher::Full("example.com.cn".to_string()),
                DomainMatcher::Suffix(".cn".to_string()),
            ],
        },
    ];
    
    // ========== Act ==========
    manager.reload(entries);

    // ========== Assert ==========
    assert!(manager.matches("cn", "example.com.cn"), 
        "Should match exact domain");
    assert!(manager.matches("cn", "test.example.com.cn"), 
        "Should match subdomain with suffix");
    assert!(!manager.matches("cn", "example.com"), 
        "Should not match unrelated domain");
    assert!(!manager.matches("cn", "google.com"), 
        "Should not match Google domain");
}

#[test]
fn test_geosite_not_matcher_excludes_category() {
    // ========== Arrange ==========
    let mut manager = create_test_manager();
    
    let entries = vec![
        GeoSiteEntry {
            tag: "cn".to_string(),
            matchers: vec![
                DomainMatcher::Suffix(".cn".to_string()),
            ],
        },
    ];
    
    manager.reload(entries);

    // ========== Act & Assert ==========
    // GeoSiteNot should match domains NOT in CN category
    // Note: GeoSiteNot in matcher is implemented as !manager.matches()
    assert!(manager.matches("cn", "example.com.cn"), 
        "CN domain should match CN category");
    assert!(!manager.matches("cn", "google.com"), 
        "Non-CN domain should not match CN category");
}

#[test]
fn test_geosite_engine_has_manager() {
    // ========== Arrange ==========
    let raw = serde_json::json!({
        "settings": {
            "default_upstream": "1.1.1.1:53"
        },
        "pipelines": [
            {
                "id": "test_pipeline",
                "rules": []
            }
        ]
    });

    let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");

    // ========== Act & Assert ==========
    // Create Engine (requires Tokio runtime)
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let engine = Engine::new(runtime.clone(), "test".to_string());

        // Verify Engine has GeoSiteManager
        let geosite_manager = engine.geosite_manager.lock().unwrap();
        // Note: GeoSiteManager starts empty, no tags by default
        assert!(!geosite_manager.has_tag("cn"), 
            "Should not have CN tag initially");
        assert!(!geosite_manager.matches("cn", "example.com"), 
            "Should not match example.com initially");
    });
}
