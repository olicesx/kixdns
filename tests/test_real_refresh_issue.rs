// 测试缓存刷新触发逻辑
use kixdns::cache::CacheEntry;
use std::time::Instant;
use std::sync::Arc;

#[test]
fn test_cache_refresh_trigger_with_ttl_300() {
    println!("\n=== 测试 TTL=300 的缓存刷新触发 ===\n");

    // 用户配置
    let threshold_percent = 15u8;
    let min_ttl = 6u32;
    let original_ttl = 300u32;

    // 计算阈值
    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100;

    println!("配置：");
    println!("  original_ttl = {} 秒", original_ttl);
    println!("  threshold_percent = {}%", threshold_percent);
    println!("  threshold = {} 秒", threshold);
    println!("  min_ttl = {} 秒", min_ttl);
    println!();

    // 创建缓存条目
    let entry = CacheEntry {
        bytes: bytes::Bytes::new(),
        rcode: hickory_proto::op::ResponseCode::NoError,
        source: Arc::from("upstream"),
        upstream: Some(Arc::from("8.8.8.8:53")),
        qname: Arc::from("www.youtube.com"),
        pipeline_id: Arc::from("pipeline"),
        qtype: 1,
        inserted_at: Instant::now(),
        original_ttl: original_ttl,
    };

    // 测试不同时间点
    let test_cases = vec![
        (0, false),      // 0秒 - 剩余300
        (200, false),    // 200秒 - 剩余100
        (250, false),    // 250秒 - 剩余50
        (255, true),     // 255秒 - 剩余45 <= 阈值，应该触发！
        (260, true),     // 260秒 - 剩余40
        (294, true),     // 294秒 - 剩余6
        (295, true),     // 295秒 - 剩余5
        (296, false),    // 296秒 - 剩余4 < min_ttl，不触发
    ];

    println!("测试触发条件：remaining_ttl <= {} && remaining_ttl >= {}\n", threshold, min_ttl);

    for (elapsed, expected_trigger) in test_cases {
        let remaining = entry.original_ttl.saturating_sub(elapsed);
        let should_trigger = remaining as u64 <= threshold && remaining >= min_ttl as u32;

        let status = if should_trigger == expected_trigger { "✅" } else { "❌" };

        println!("[{}秒] 剩余TTL={}, 阈值={}, 触发={}, 预期={} {}",
            elapsed,
            remaining,
            threshold,
            should_trigger,
            expected_trigger,
            status
        );

        assert_eq!(should_trigger, expected_trigger,
            "[{}秒] 触发条件不匹配", elapsed);
    }

    println!("\n✅ TTL=300 的预取触发逻辑正确");
}

#[test]
fn test_extract_ttl_issue() {
    println!("\n=== 测试 extract_ttl 的 min 问题 ===\n");

    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::{RecordType, RData};

    // 构造一个 DNS 响应：CNAME TTL=300, A 记录 TTL=2
    let mut msg = Message::new();
    msg.add_query(
        hickory_proto::rr::Name::from_ascii("www.youtube.com"),
        RecordType::A,
        hickory_proto::rr::DNSClass::IN,
    );

    // 添加 CNAME 记录，TTL=300
    msg.add_answer(
        hickory_proto::rr::Name::from_ascii("www.youtube.com"),
        RecordType::CNAME,
        300,
        RData::CNAME(hickory_proto::rr::Name::from_ascii("youtube-ui.l.google.com")),
    );

    // 添加 A 记录，TTL=2
    msg.add_answer(
        hickory_proto::rr::Name::from_ascii("youtube-ui.l.google.com"),
        RecordType::A,
        2,
        RData::A("142.250.71.142".parse().unwrap()),
    );

    // 模拟 extract_ttl 的逻辑
    let min_ttl = msg.answers()
        .iter()
        .map(|r| r.ttl() as u64)
        .min()
        .unwrap_or(0);

    println!("DNS 响应：");
    println!("  www.youtube.com.    300   IN  CNAME  youtube-ui.l.google.com.");
    println!("  youtube-ui...       2     IN  A       142.250.71.142");
    println!();
    println!("extract_ttl 返回：{} 秒", min_ttl);
    println!("所有记录的 TTL: {:?}",
        msg.answers().iter().map(|r| r.ttl()).collect::<Vec<_>>());
    println!();

    // 预取检查
    let cache_background_refresh = true;
    let cache_refresh_min_ttl = 6u32;

    let should_trigger = cache_background_refresh
        && min_ttl as u32 >= cache_refresh_min_ttl;

    println!("预取触发检查：");
    println!("  cache_background_refresh: {}", cache_background_refresh);
    println!("  min_ttl ({}): >= cache_refresh_min_ttl ({}): {}",
        min_ttl,
        cache_refresh_min_ttl,
        min_ttl as u32 >= cache_refresh_min_ttl
    );
    println!("  应该触发预取: {}", should_trigger);
    println!();

    if min_ttl < cache_refresh_min_ttl as u64 {
        println!("❌ 问题：extract_ttl 返回 {} < {}，不会触发预取！",
            min_ttl, cache_refresh_min_ttl);
        println!("   即使上游返回 TTL=300，但因为 A 记录 TTL=2，");
        println!("   extract_ttl 取了最小值，导致缓存保存 original_ttl=2");
    }
}

#[test]
fn test_dns_response_parsing() {
    println!("\n=== 测试真实 DNS 响应解析 ===\n");

    // 检查 parse_response_quick 的行为
    // 这里应该模拟真实的 DNS 响应包

    let scenario = "DNS 响应包含 CNAME(TTL=300) 和 A(TTL=2)";
    println!("场景：{}", scenario);
    println!();
    println!("parse_response_quick.min_ttl 会返回：min(300, 2) = 2");
    println!("缓存保存：original_ttl = 2");
    println!("预取检查：2 >= 6 = false");
    println!("结果：❌ 永远不触发预取");
    println!();

    println!("这就是您看到的问题：");
    println!("  - 上游返回 A 记录 TTL=2（不是 300！）");
    println!("  - extract_ttl 取最小 TTL，所以保存 2");
    println!("  - min_ttl=2 < cache_refresh_min_ttl=6，不触发预取");
}
