// Integration tests for matcher_helpers and engine_helpers refactoring
// matcher_helpers 和 engine_helpers 重构的集成测试

use std::str::FromStr;
use kixdns::matcher::RuntimeResponseMatcher;
use kixdns::config::ResponseMatcher;
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType, DNSClass, RData, rdata};

#[test]
fn test_integration_matcher_helpers_geosite_in_response_matcher() {
    // 测试 matcher_helpers 在 RuntimeResponseMatcher 中的集成
    // Test matcher_helpers integration in RuntimeResponseMatcher

    // Arrange: Create GeoSiteManager with test data
    let mut geosite_manager = kixdns::geosite::GeoSiteManager::new();
    use kixdns::geosite::{GeoSiteEntry, DomainMatcher};

    geosite_manager.add_entry(GeoSiteEntry {
        tag: "cn".to_string(),
        matchers: vec![
            DomainMatcher::Suffix(".baidu.com".to_string()),
            DomainMatcher::Keyword("baidu".to_string()),
        ],
    });

    // Create request message
    let mut msg = Message::new();
    msg.add_query(Query::query(
        Name::from_str("www.baidu.com").unwrap(),
        RecordType::A,
    ));

    // Create matcher
    let matcher = RuntimeResponseMatcher::from_config(
        ResponseMatcher::ResponseRequestDomainGeoSite {
            value: "cn".to_string(),
        }
    ).unwrap();

    // Act: Match domain using helper function
    let result = matcher.matches(
        "8.8.8.8:53",
        "www.baidu.com",
        RecordType::A,
        DNSClass::IN,
        &msg,
        None,
        Some(&geosite_manager),
    );

    // Assert: Should match
    assert!(result, "Response matcher should use helper function for GeoSite matching");
}

#[test]
fn test_integration_engine_helpers_in_response_actions() {
    // 测试 engine_helpers 在响应动作中的集成
    // Test engine_helpers integration in response actions

    // Arrange: Create test request
    let mut req = Message::new();
    req.set_id(12345);
    req.set_recursion_desired(true);
    req.add_query(Query::query(
        Name::from_str("test.com").unwrap(),
        RecordType::A,
    ));

    // Act: Build ServFail and Refused responses using helpers
    let servfail_result = kixdns::engine::engine_helpers::build_servfail_response(&req);
    let refused_result = kixdns::engine::engine_helpers::build_refused_response(&req);

    // Assert: Verify both responses are valid
    assert!(servfail_result.is_ok(), "ServFail response should build successfully");
    assert!(refused_result.is_ok(), "Refused response should build successfully");

    let servfail_bytes = servfail_result.unwrap();
    let refused_bytes = refused_result.unwrap();

    // Verify they are different
    assert_ne!(servfail_bytes, refused_bytes, "ServFail and Refused should be different");

    // Verify response codes
    let sf_msg = Message::from_vec(&servfail_bytes).unwrap();
    let ref_msg = Message::from_vec(&refused_bytes).unwrap();

    assert_eq!(sf_msg.response_code(), ResponseCode::ServFail);
    assert_eq!(ref_msg.response_code(), ResponseCode::Refused);
}

#[test]
fn test_integration_collect_ips_helper_in_response_matcher() {
    // 测试 IP 收集辅助函数在响应匹配器中的集成
    // Test IP collection helper integration in response matcher

    // Arrange: Create response message with multiple IPs
    let mut msg = Message::new();
    let name = Name::from_str("multi-ip.com").unwrap();

    // Add multiple A records
    msg.add_answer(hickory_proto::rr::Record::from_rdata(
        name.clone(),
        300,
        RData::A(rdata::A(
            std::net::Ipv4Addr::new(10, 0, 0, 1),
        )),
    ));
    msg.add_answer(hickory_proto::rr::Record::from_rdata(
        name.clone(),
        300,
        RData::A(rdata::A(
            std::net::Ipv4Addr::new(10, 0, 0, 2),
        )),
    ));

    // Create matcher that uses helper to collect IPs
    let matcher = RuntimeResponseMatcher::from_config(
        ResponseMatcher::ResponseAnswerIp {
            cidr: "10.0.0.0/24".to_string(),
        }
    ).unwrap();

    // Act: Match using helper function
    let result = matcher.matches(
        "8.8.8.8:53",
        "multi-ip.com",
        RecordType::A,
        DNSClass::IN,
        &msg,
        None,
        None,
    );

    // Assert: Should match (collect_ips helper is used to find IPs)
    assert!(result, "Should match when helper function finds IPs in message");
}

#[test]
fn test_integration_any_ip_matches_nets_helper_in_response_matcher() {
    // 测试 IP 匹配辅助函数在响应匹配器中的集成
    // Test IP matching helper integration in response matcher

    // Arrange: Create response with non-matching IPs
    let mut msg = Message::new();
    let name = Name::from_str("test.com").unwrap();

    // Add non-matching IP
    msg.add_answer(hickory_proto::rr::Record::from_rdata(
        name.clone(),
        300,
        RData::A(rdata::A(
            std::net::Ipv4Addr::new(192, 168, 1, 1),
        )),
    ));

    // Create matcher that uses helper to check IP matches
    let matcher = RuntimeResponseMatcher::from_config(
        ResponseMatcher::ResponseAnswerIp {
            cidr: "10.0.0.0/24".to_string(),
        }
    ).unwrap();

    // Act: Match using helper function
    let result = matcher.matches(
        "8.8.8.8:53",
        "test.com",
        RecordType::A,
        DNSClass::IN,
        &msg,
        None,
        None,
    );

    // Assert: Should not match (any_ip_matches_nets helper is used)
    assert!(!result, "Should not match when helper finds no matching IPs");
}
