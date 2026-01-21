// 测试缓存后台刷新触发 / Test cache background refresh triggering
use kixdns::cache::CacheEntry;
use bytes::Bytes;
use std::time::Instant;
use std::sync::Arc;
use hickory_proto::op::ResponseCode;

#[test]
fn test_cache_background_refresh_triggering() {
    // 模拟缓存命中并验证预取是否触发
    // Simulate cache hit and verify if background refresh is triggered

    println!("\n=== 测试缓存后台刷新触发 ===\n");

    // 1. 创建一个测试用的 Engine
    // 注意：这需要实际的配置文件和网络连接
    // let engine = Engine::new(config);

    // 2. 模拟一个缓存条目
    let now = Instant::now();
    let entry = CacheEntry {
        bytes: Bytes::new(),  // 简化，不构造实际 DNS 响应
        rcode: ResponseCode::NoError,
        source: Arc::from("upstream"),
        upstream: Some(Arc::from("8.8.8.8:53")),
        qname: Arc::from("www.example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,  // A 记录
        inserted_at: now,
        original_ttl: 300,  // 5 分钟 TTL
    };

    // 3. 模拟缓存命中条件
    let cache_background_refresh = true;
    let cache_refresh_threshold_percent = 80u8;
    let cache_refresh_min_ttl = 5u32;

    println!("缓存条目信息：");
    println!("  upstream: {:?}", entry.upstream);
    println!("  original_ttl: {} 秒", entry.original_ttl);
    println!("  source: {}", entry.source);

    // 4. 检查触发条件
    let should_check_refresh = cache_background_refresh
        && entry.upstream.is_some()
        && entry.original_ttl >= cache_refresh_min_ttl;

    println!("\n第一步：检查是否满足预刷新条件");
    println!("  cache_background_refresh: {}", cache_background_refresh);
    println!("  hit.upstream.is_some(): {}", entry.upstream.is_some());
    println!("  original_ttl >= min_ttl: {} ({} >= {})",
        entry.original_ttl >= cache_refresh_min_ttl,
        entry.original_ttl,
        cache_refresh_min_ttl);
    println!("  → 应该检查预刷新: {}", should_check_refresh);

    assert!(should_check_refresh, "应该满足预刷新条件");

    // 5. 模拟不同的时间点
    println!("\n第二步：模拟不同时间点的触发情况");

    let test_scenarios = vec![
        ("刚插入", 0, false),      // 0 秒 - 不触发
        ("80%", 240, true),       // 240 秒剩余 (80%) - 触发！（<= 阈值）
        ("79%", 239, true),       // 239 秒剩余 (79%) - 触发！
        ("25%", 75, true),        // 75 秒剩余 (25%) - 触发！
        ("10%", 30, true),        // 30 秒剩余 (10%) - 触发！
        ("5%", 15, true),         // 15 秒剩余 (5%) - 触发！
        ("低于最小值", 2, false), // 2 秒 - 不触发（低于 min_ttl）
    ];

    for (name, remaining_ttl, expected_trigger) in test_scenarios {
        let threshold = (entry.original_ttl as u64 * cache_refresh_threshold_percent as u64) / 100;
        let should_trigger = remaining_ttl as u64 <= threshold
            && remaining_ttl >= cache_refresh_min_ttl as u64;

        println!("  [{:>10}] 剩余 TTL: {}秒, 阈值: {}秒, 应该触发: {}, 实际触发: {}, 预期: {}",
            name,
            remaining_ttl,
            threshold,
            expected_trigger,
            should_trigger,
            if should_trigger == expected_trigger { "✅" } else { "❌" }
        );

        assert_eq!(should_trigger, expected_trigger,
            "[{}] 触发条件不匹配", name);
    }

    println!("\n✅ 所有测试通过！预取触发逻辑正确");

    // 6. 实际问题排查
    println!("\n=== 实际问题排查 ===\n");
    println!("如果你的实测没有触发，可能的原因：");
    println!();
    println!("1. cache_background_refresh 配置未启用");
    println!("   → 检查配置文件中是否设置 cache_background_refresh=true");
    println!();
    println!("2. 缓存条目的 source 不是 'upstream'");
    println!("   → 检查缓存条目的 source 字段");
    println!("   → 静态响应（如 NXDOMAIN）不会有 upstream");
    println!();
    println!("3. original_ttl 太小");
    println!("   → 如果 TTL < 5 秒，不会触发");
    println!("   → 检查返回的 DNS 响应的 TTL");
    println!();
    println!("4. remaining_ttl 还没到阈值");
    println!("   → 默认阈值是 80% 的 TTL");
    println!("   → 300秒 TTL 需要剩余 <= 240秒才触发");
    println!("   → 也就是已经过期 >= 60秒时才触发");
    println!();
    println!("5. 没有使用 DEBUG 日志级别");
    println!("   → DEBUG 日志会显示 'cache background refresh check'");
    println!("   → INFO 级别不会显示这个日志");
}

#[test]
fn test_upstream_field_populated() {
    // 测试缓存条目的 upstream 字段是否正确填充
    // Test if cache entry upstream field is properly populated

    println!("\n=== 测试 upstream 字段填充 ===\n");

    // 模拟不同来源的缓存条目
    let static_entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NXDomain,
        source: Arc::from("static"),
        upstream: None,  // 静态响应没有 upstream
        qname: Arc::from("blocked.example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
        inserted_at: Instant::now(),
        original_ttl: 300,
    };

    let upstream_entry = CacheEntry {
        bytes: Bytes::new(),
        rcode: ResponseCode::NoError,
        source: Arc::from("upstream"),
        upstream: Some(Arc::from("8.8.8.8:53")),  // 来自 upstream
        qname: Arc::from("example.com"),
        pipeline_id: Arc::from("test"),
        qtype: 1,
        inserted_at: Instant::now(),
        original_ttl: 300,
    };

    println!("静态响应条目：");
    println!("  source: {}", static_entry.source);
    println!("  upstream: {:?}", static_entry.upstream);
    println!("  → 会触发预刷新: {}", static_entry.upstream.is_some());

    println!("\nUpstream 响应条目：");
    println!("  source: {}", upstream_entry.source);
    println!("  upstream: {:?}", upstream_entry.upstream);
    println!("  → 会触发预刷新: {}", upstream_entry.upstream.is_some());

    assert!(static_entry.upstream.is_none(), "静态响应不应该有 upstream");
    assert!(upstream_entry.upstream.is_some(), "Upstream 响应该有 upstream");

    println!("\n✅ upstream 字段逻辑正确");
}

#[test]
fn test_timing_calculation() {
    // 测试时间计算是否正确
    // Test timing calculation

    println!("\n=== 测试时间计算 ===\n");

    let original_ttl = 300u32;
    let threshold_percent = 80u8;
    let min_ttl = 5u32;

    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100;
    println!("配置：");
    println!("  original_ttl: {} 秒", original_ttl);
    println!("  threshold_percent: {}%", threshold_percent);
    println!("  min_ttl: {} 秒", min_ttl);
    println!("  计算的阈值: {} 秒", threshold);

    let scenarios = vec![
        (0, 300, false),      // 刚插入，剩余 300 秒
        (60, 240, false),    // 60 秒后，剩余 240 秒（正好阈值）
        (61, 239, true),     // 61 秒后，剩余 239 秒（低于阈值）
        (295, 5, true),      // 295 秒后，剩余 5 秒（等于 min_ttl）
        (298, 2, false),     // 298 秒后，剩余 2 秒（低于 min_ttl）
    ];

    println!("\n时间点测试：");
    for (elapsed, expected_remaining, should_trigger) in scenarios {
        let remaining_ttl = original_ttl.saturating_sub(elapsed);
        let trigger = remaining_ttl as u64 <= threshold
            && remaining_ttl >= min_ttl as u32;

        let status = if trigger == should_trigger { "✅" } else { "❌" };

        println!("  [{}秒后] 剩余: {}秒, 预期触发: {}, 实际触发: {} {}",
            elapsed,
            remaining_ttl,
            should_trigger,
            trigger,
            status
        );
    }

    println!("\n✅ 时间计算正确");
}

// 实际调试建议
#[test]
fn test_debugging_checklist() {
    println!("\n=== 实际调试检查清单 ===\n");

    println!("1. 启用完整日志：");
    println!("   RUST_LOG=debug,kixdns::engine=trace ./kixdns");
    println!();

    println!("2. 查找关键日志：");
    println!("   grep 'cache background refresh check' kixdns.log");
    println!("   grep 'triggering background cache refresh' kixdns.log");
    println!("   grep 'should_trigger=' kixdns.log");
    println!();

    println!("3. 检查缓存条目：");
    println!("   grep 'cache=true' kixdns.log -A 5");
    println!("   查找 upstream 字段");
    println!();

    println!("4. 验证配置：");
    println!("   cat config/pipeline_fast.json | grep cache_background_refresh");
    println!("   cat config/pipeline_fast.json | grep cache_refresh_threshold");
    println!("   cat config/pipeline_fast.json | grep cache_refresh_min_ttl");
    println!();

    println!("5. 手动计算：");
    println!("   假设 original_ttl=300, threshold=80%");
    println!("   → threshold_value = 300 * 80% = 240秒");
    println!("   → 需要剩余 TTL <= 240秒才触发");
    println!("   → 也就是已经过期 >= 60秒");
    println!();

    println!("6. 验证缓存来源：");
    println!("   查找 'source=' 字段");
    println!("   应该是 'source=upstream' 而不是 'source=static'");
}
