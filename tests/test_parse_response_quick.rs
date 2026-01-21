// 测试 parse_response_quick 的 min_ttl 行为
use kixdns::proto_utils::parse_response_quick;

#[test]
fn test_parse_response_quick_with_cname_and_a() {
    println!("\n=== 测试 parse_response_quick 的 min_ttl 提取 ===\n");

    // 构造一个 DNS 响应：包含 CNAME (TTL=2) 和 A (TTL=300)
    // Header: ID=0, QR=1, QDCOUNT=1, ANCOUNT=2
    let mut packet = vec![0u8; 12];
    packet[2] = 0x80; // QR=1
    packet[5] = 1;    // QDCOUNT=1
    packet[7] = 2;    // ANCOUNT=2 (CNAME + A)

    // Question: www.youtube.com
    packet.extend_from_slice(b"\x03www\x07youtube\x03com\x00\x00\x01\x00\x01");

    // Answer 1: CNAME with TTL=2
    let cname_start = packet.len();
    packet.extend_from_slice(b"\xc0\x0c"); // compressed name
    packet.extend_from_slice(&[0x00, 0x05]); // CNAME type
    packet.extend_from_slice(&[0x00, 0x01]); // IN class
    packet.extend_from_slice(&2u32.to_be_bytes()); // TTL=2 ⚠️
    packet.extend_from_slice(&[0x00, 0x08]); // RDLen=8
    packet.extend_from_slice(b"\x03www\x01a\x00"); // www.a.

    // Answer 2: A with TTL=300
    let a_start = packet.len();
    packet.extend_from_slice(b"\xc0\x0c"); // compressed name
    packet.extend_from_slice(&[0x00, 0x01]); // A type
    packet.extend_from_slice(&[0x00, 0x01]); // IN class
    packet.extend_from_slice(&300u32.to_be_bytes()); // TTL=300 ⚠️
    packet.extend_from_slice(&[0x00, 0x04]); // RDLen=4
    packet.extend_from_slice(&[1, 2, 3, 4]); // IP=1.2.3.4

    // 验证 CNAME TTL
    let cname_ttl = u32::from_be_bytes([
        packet[cname_start + 6],
        packet[cname_start + 7],
        packet[cname_start + 8],
        packet[cname_start + 9],
    ]);
    assert_eq!(cname_ttl, 2, "CNAME TTL 应该是 2");

    // 验证 A TTL
    let a_ttl = u32::from_be_bytes([
        packet[a_start + 6],
        packet[a_start + 7],
        packet[a_start + 8],
        packet[a_start + 9],
    ]);
    assert_eq!(a_ttl, 300, "A TTL 应该是 300");

    // 调用 parse_response_quick
    if let Some(qr) = parse_response_quick(&packet) {
        println!("parse_response_quick 结果：");
        println!("  rcode: {:?}", qr.rcode);
        println!("  min_ttl: {}", qr.min_ttl);
        println!();

        if qr.min_ttl == 2 {
            println!("❌ 问题确认：min_ttl 取的是 CNAME 的 TTL=2，而不是 A 记录的 TTL=300");
            println!();
            println!("后果：");
            println!("  1. 缓存保存 original_ttl=2");
            println!("  2. 2 >= 6 条件失败");
            println!("  3. 不会触发预取");
            println!();
            println!("解决方案：");
            println!("  修改 parse_response_quick 或 extract_ttl，");
            println!("  优先使用 A/AAAA 记录的 TTL，而不是所有记录的最小 TTL。");
        }
    } else {
        println!("❌ parse_response_quick 返回 None");
    }
}

#[test]
fn test_only_a_records() {
    println!("\n=== 测试只有 A 记录的情况 ===\n");

    // 构造一个 DNS 响应：只包含 A (TTL=300)
    let mut packet = vec![0u8; 12];
    packet[2] = 0x80; // QR=1
    packet[5] = 1;    // QDCOUNT=1
    packet[7] = 1;    // ANCOUNT=1

    // Question: example.com
    packet.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");

    // Answer: A with TTL=300
    packet.extend_from_slice(b"\xc0\x0c");
    packet.extend_from_slice(&[0x00, 0x01]); // A type
    packet.extend_from_slice(&[0x00, 0x01]); // IN class
    packet.extend_from_slice(&300u32.to_be_bytes()); // TTL=300
    packet.extend_from_slice(&[0x00, 0x04]); // RDLen=4
    packet.extend_from_slice(&[1, 2, 3, 4]); // IP=1.2.3.4

    if let Some(qr) = parse_response_quick(&packet) {
        println!("parse_response_quick 结果：");
        println!("  min_ttl: {}", qr.min_ttl);

        if qr.min_ttl == 300 {
            println!("✅ 正确：min_ttl=300");
        } else {
            println!("❌ 错误：min_ttl 应该是 300，实际是 {}", qr.min_ttl);
        }
    }
}
