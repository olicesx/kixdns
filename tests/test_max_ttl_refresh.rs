// Test for max_ttl background refresh fix
// 测试 max_ttl 后台刷新修复

#[cfg(test)]
mod tests {
    use kixdns::proto_utils::parse_response_quick;

    #[test]
    fn test_parse_response_quick_returns_max_ttl() {
        // Arrange: Build a DNS response packet with multiple records having different TTLs
        // 构建一个包含多个不同 TTL 记录的 DNS 响应包
        let mut packet = vec![
            // Header (12 bytes)
            0x00, 0x00,  // Transaction ID
            0x84, 0x00,  // Flags: Response, Authoritative, No Error
            0x00, 0x01,  // QDCOUNT: 1
            0x00, 0x02,  // ANCOUNT: 2 (two answers with different TTLs)
            0x00, 0x00,  // NSCOUNT: 0
            0x00, 0x00,  // ARCOUNT: 0
        ];

        // Question: example.com IN A
        // Question section
        let qname = b"\x07example\x03com\x00";
        packet.extend_from_slice(qname);
        packet.extend_from_slice(&[0x00, 0x01]);  // Type: A
        packet.extend_from_slice(&[0x00, 0x01]);  // Class: IN

        // Answer 1: example.com A 1.2.3.4 TTL=300
        // Answer 1: A record with TTL=300
        packet.extend_from_slice(qname);
        packet.extend_from_slice(&[0x00, 0x01]);  // Type: A
        packet.extend_from_slice(&[0x00, 0x01]);  // Class: IN
        packet.extend_from_slice(&300u32.to_be_bytes());  // TTL: 300
        packet.extend_from_slice(&[0x00, 0x04]);  // RDLENGTH: 4
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);  // RDATA: 1.2.3.4

        // Answer 2: example.com CNAME www.example.com TTL=45
        // Answer 2: CNAME record with TTL=45
        let cname = b"\x03www\x07example\x03com\x00";
        packet.extend_from_slice(qname);
        packet.extend_from_slice(&[0x00, 0x05]);  // Type: CNAME
        packet.extend_from_slice(&[0x00, 0x01]);  // Class: IN
        packet.extend_from_slice(&45u32.to_be_bytes());  // TTL: 45
        packet.extend_from_slice(&[0x00, 0x13]);  // RDLENGTH: 19
        packet.extend_from_slice(cname);  // RDATA: www.example.com

        // Act: Parse the response
        // 解析响应
        let result = parse_response_quick(&packet);

        // Assert: Verify both min_ttl and max_ttl are correct
        // 验证 min_ttl 和 max_ttl 都正确
        assert!(result.is_some(), "Parse should succeed");
        let qr = result.unwrap();
        assert_eq!(qr.min_ttl, 45, "min_ttl should be 45 (CNAME)");
        assert_eq!(qr.max_ttl, 300, "max_ttl should be 300 (A record)");
    }

    #[test]
    fn test_parse_response_quick_single_record() {
        // Arrange: Build a DNS response with a single record
        // 构建只有一个记录的 DNS 响应
        let mut packet = vec![
            // Header
            0x00, 0x00,  // Transaction ID
            0x84, 0x00,  // Flags
            0x00, 0x01,  // QDCOUNT: 1
            0x00, 0x01,  // ANCOUNT: 1
            0x00, 0x00,  // NSCOUNT: 0
            0x00, 0x00,  // ARCOUNT: 0
        ];

        // Question
        let qname = b"\x07example\x03com\x00";
        packet.extend_from_slice(qname);
        packet.extend_from_slice(&[0x00, 0x01]);  // Type: A
        packet.extend_from_slice(&[0x00, 0x01]);  // Class: IN

        // Answer: TTL=120
        // Answer: TTL=120
        packet.extend_from_slice(qname);
        packet.extend_from_slice(&[0x00, 0x01]);  // Type: A
        packet.extend_from_slice(&[0x00, 0x01]);  // Class: IN
        packet.extend_from_slice(&120u32.to_be_bytes());  // TTL: 120
        packet.extend_from_slice(&[0x00, 0x04]);  // RDLENGTH: 4
        packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]);  // RDATA: 5.6.7.8

        // Act
        let result = parse_response_quick(&packet);

        // Assert: min_ttl and max_ttl should be the same for single record
        // 对于单个记录，min_ttl 和 max_ttl 应该相同
        assert!(result.is_some());
        let qr = result.unwrap();
        assert_eq!(qr.min_ttl, 120);
        assert_eq!(qr.max_ttl, 120);
    }

    #[test]
    fn test_parse_response_quick_no_answers() {
        // Arrange: Build a DNS response with no answers (NXDOMAIN)
        // 构建没有答案的 DNS 响应（NXDOMAIN）
        let packet = vec![
            // Header
            0x00, 0x00,  // Transaction ID
            0x84, 0x03,  // Flags: Response, NXDOMAIN (RCODE=3)
            0x00, 0x01,  // QDCOUNT: 1
            0x00, 0x00,  // ANCOUNT: 0
            0x00, 0x00,  // NSCOUNT: 0
            0x00, 0x00,  // ARCOUNT: 0
        ];

        // Question
        let qname = b"\x07example\x03com\x00";
        let mut full_packet = packet.clone();
        full_packet.extend_from_slice(qname);
        full_packet.extend_from_slice(&[0x00, 0x01]);  // Type: A
        full_packet.extend_from_slice(&[0x00, 0x01]);  // Class: IN

        // Act
        let result = parse_response_quick(&full_packet);

        // Assert: Should return 0 for both min_ttl and max_ttl when no answers
        // 当没有答案时，min_ttl 和 max_ttl 都应该返回 0
        assert!(result.is_some());
        let qr = result.unwrap();
        assert_eq!(qr.min_ttl, 0);
        assert_eq!(qr.max_ttl, 0);
    }
}
