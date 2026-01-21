/// Test for TTL extraction with multiple A/AAAA records
/// 测试多个 A/AAAA 记录的 TTL 提取

use hickory_proto::op::Message;
use hickory_proto::rr::{Name, Record};
use hickory_proto::rr::rdata::{A, AAAA};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;
    use kixdns::engine::{extract_ttl, extract_ttl_for_refresh};

    /// Test extract_ttl (min) - for cache entries
    #[test]
    fn test_extract_ttl_uses_min() {
        // Arrange: Create message with different TTLs
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();

        // Add records with different TTLs
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,  // TTL = 300
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            73,   // TTL = 73 (minimum)
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(5, 6, 7, 8)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            150,  // TTL = 150
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(9, 10, 11, 12)))
        ));

        // Act: Extract TTL for cache
        let ttl = extract_ttl(&msg);

        // Assert: Should return minimum TTL
        assert_eq!(ttl, 73, "extract_ttl should return minimum TTL for cache entries");
    }

    /// Test extract_ttl_for_refresh (max) - for refresh timing
    #[test]
    fn test_extract_ttl_for_refresh_uses_max() {
        // Arrange: Create message with different TTLs
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();

        // Add records with different TTLs
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,  // TTL = 300 (maximum)
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            73,   // TTL = 73
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(5, 6, 7, 8)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            150,  // TTL = 150
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(9, 10, 11, 12)))
        ));

        // Act: Extract TTL for refresh timing
        let ttl = extract_ttl_for_refresh(&msg);

        // Assert: Should return maximum TTL
        assert_eq!(ttl, 300, "extract_ttl_for_refresh should return maximum TTL for refresh timing");
    }

    /// Test real-world scenario: hanime1.me with 3 A records
    #[test]
    fn test_hanime1_me_scenario() {
        // Arrange: Simulate hanime1.me response
        let mut msg = Message::new();
        let name = Name::from_str("hanime1.me").unwrap();

        // hanime1.me returns 3 A records with TTL=73
        msg.add_answer(Record::from_rdata(
            name.clone(),
            73,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(104, 26, 9, 104)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            73,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(172, 67, 74, 156)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            73,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(104, 26, 8, 104)))
        ));

        // Act & Assert: Both should return 73 (all TTLs are equal)
        let ttl_cache = extract_ttl(&msg);
        let ttl_refresh = extract_ttl_for_refresh(&msg);

        assert_eq!(ttl_cache, 73, "All TTLs are 73, min should be 73");
        assert_eq!(ttl_refresh, 73, "All TTLs are 73, max should be 73");
    }

    /// Test scenario with mixed A and AAAA records
    #[test]
    fn test_mixed_a_aaaa_records() {
        // Arrange: Create message with A and AAAA records
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();

        // A records with TTL=300
        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))
        ));

        // AAAA record with TTL=150
        msg.add_answer(Record::from_rdata(
            name.clone(),
            150,
            hickory_proto::rr::RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        ));

        // Act & Assert
        let ttl_cache = extract_ttl(&msg);
        let ttl_refresh = extract_ttl_for_refresh(&msg);

        assert_eq!(ttl_cache, 150, "Cache should use min TTL (150)");
        assert_eq!(ttl_refresh, 300, "Refresh should use max TTL (300)");
    }

    /// Test refresh timing calculation
    #[test]
    fn test_refresh_timing_calculation() {
        // Arrange: Message with TTLs [300, 73, 150]
        let mut msg = Message::new();
        let name = Name::from_str("example.com").unwrap();

        msg.add_answer(Record::from_rdata(
            name.clone(),
            300,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(1, 2, 3, 4)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            73,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(5, 6, 7, 8)))
        ));
        msg.add_answer(Record::from_rdata(
            name.clone(),
            150,
            hickory_proto::rr::RData::A(A(Ipv4Addr::new(9, 10, 11, 12)))
        ));

        // Act: Extract TTLs
        let ttl_cache = extract_ttl(&msg);
        let ttl_refresh = extract_ttl_for_refresh(&msg);

        // Calculate refresh threshold (20%)
        let threshold_cache = ttl_cache * 20 / 100;
        let threshold_refresh = ttl_refresh * 20 / 100;

        // Assert: Refresh timing should be based on max TTL
        assert_eq!(ttl_cache, 73, "Cache TTL should be 73");
        assert_eq!(ttl_refresh, 300, "Refresh TTL should be 300");
        assert_eq!(threshold_cache, 14, "Cache threshold: 73 * 20% = 14");
        assert_eq!(threshold_refresh, 60, "Refresh threshold: 300 * 20% = 60");

        println!("\n=== Refresh Timing Comparison ===");
        println!("Using min TTL (73):");
        println!("  - Threshold: 14 seconds");
        println!("  - Refresh triggers after: 73 - 14 = 59 seconds");
        println!("\nUsing max TTL (300):");
        println!("  - Threshold: 60 seconds");
        println!("  - Refresh triggers after: 300 - 60 = 240 seconds");
        println!("\nBenefit: 181 seconds (3 minutes) less frequent upstream queries!");
    }

    /// Test empty response
    #[test]
    fn test_empty_response() {
        // Arrange: Empty message
        let msg = Message::new();

        // Act & Assert
        let ttl_cache = extract_ttl(&msg);
        let ttl_refresh = extract_ttl_for_refresh(&msg);

        assert_eq!(ttl_cache, 0, "Empty response should return 0");
        assert_eq!(ttl_refresh, 0, "Empty response should return 0");
    }
}
