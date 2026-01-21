// 诊断测试：为什么预取没有触发
#[test]
fn diagnose_refresh_not_triggering() {
    println!("\n=== 诊断：预取没有触发 ===\n");

    // 用户的场景
    let original_ttl = 300u32;
    let threshold_percent = 50u8;
    let min_ttl = 50u32;

    println!("用户配置：");
    println!("  cache_refresh_threshold_percent = {}%", threshold_percent);
    println!("  cache_refresh_min_ttl = {} 秒", min_ttl);
    println!();

    // 触发条件检查（src/engine.rs:740-742）
    println!("预取触发的三个必要条件：");
    println!("  1. cache_background_refresh = true");
    println!("  2. hit.upstream.is_some() = true");
    println!("  3. hit.original_ttl >= cache_refresh_min_ttl");
    println!();

    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100;

    // 场景 1: 等待 150 秒
    let elapsed = 150u32;
    let remaining = original_ttl.saturating_sub(elapsed);

    println!("场景：经过 {} 秒后查询", elapsed);
    println!("  original_ttl = {}", original_ttl);
    println!("  elapsed_secs = {}", elapsed);
    println!("  remaining_ttl = {}", remaining);
    println!("  threshold = {} ({} * {}%)", threshold, original_ttl, threshold_percent);
    println!();

    // 检查触发条件
    let cond1 = true;  // 假设配置正确
    let cond2 = true;  // 假设有 upstream
    let cond3 = original_ttl >= min_ttl;

    let trigger_condition = remaining as u64 <= threshold && remaining >= min_ttl as u32;

    println!("触发条件检查：");
    println!("  条件 1: cache_background_refresh = true → {}", cond1);
    println!("  条件 2: upstream.is_some() = true → ? ⚠️");
    println!("  条件 3: original_ttl >= min_ttl ({} >= {}) → {}", original_ttl, min_ttl, cond3);
    println!("  条件 4: remaining <= threshold ({} <= {}) → {}", remaining, threshold, remaining as u64 <= threshold);
    println!("  条件 5: remaining >= min_ttl ({} >= {}) → {}", remaining, min_ttl, remaining >= min_ttl as u32);
    println!();

    if trigger_condition {
        println!("✅ 理论上应该触发预取");
        println!();
        println!("如果没有触发，可能的原因：");
        println!();
        println!("1. ⚠️ cache_background_refresh 配置未生效");
        println!("   → 检查配置文件中是否设置 cache_background_refresh=true");
        println!("   → 检查配置文件位置和格式");
        println!();
        println!("2. ⚠️ hit.upstream.is_some() 返回 false");
        println!("   → 缓存条目的 upstream 字段为 None");
        println!("   → 可能原因：");
        println!("     - 缓存来自静态响应（不是 upstream）");
        println!("     - upstream 字段没有正确写入");
        println!("   → 验证方法：查看日志中的 upstream 字段");
        println!();
        println!("3. ⚠️ 日志级别不够");
        println!("   → 预取日志是 INFO 级别");
        println!("   → 如果使用更高级别，可能看不到日志");
        println!();
    } else {
        println!("❌ 不满足触发条件");
    }

    assert!(trigger_condition, "理论上应该触发");
}

#[test]
fn test_upstream_field_critical() {
    println!("\n=== 关键检查：upstream 字段 ===\n");

    println!("为什么 upstream 字段可能是 None？");
    println!();

    println!("情况 1: 静态响应");
    println!("  - Decision::Static { rcode: NXDomain }");
    println!("  - 缓存写入时 upstream = None");
    println!("  - 不会触发预取 ✅ 正确");
    println!();

    println!("情况 2: Forward 响应，但 upstream 字段未写入");
    println!("  - Decision::Forward { upstream: ... }");
    println!("  - 应该写入 upstream = Some(...)");
    println!("  - 但如果代码有问题，可能写入 None");
    println!();

    println!("关键代码位置（src/engine.rs:1297-1298）：");
    println!("  self.insert_dns_cache_entry(");
    println!("      ...,");
    println!("      Arc::from(actual_upstream.as_str()),  // source");
    println!("      Some(Arc::from(actual_upstream.as_str())),  // upstream ← 关键！");
    println!("      ...,");
    println!("  );");
    println!();

    println!("如果这段代码没有执行，upstream 就是 None");
    println!("可能的原因：");
    println!("  1. 走了其他代码路径（如静态响应）");
    println!("  2. actual_upstream 变量未定义");
    println!("  3. 缓存插入逻辑有问题");
    println!();
}

#[test]
fn test_config_verification() {
    println!("\n=== 配置验证检查清单 ===\n");

    println!("完整的配置文件应该包含：");
    println!();
    println!("{{");
    println!("  \"version\": \"1.0\",");
    println!("  \"settings\": {{");
    println!("    \"cache_background_refresh\": true,    ← 必须！");
    println!("    \"cache_refresh_threshold_percent\": 50,");
    println!("    \"cache_refresh_min_ttl\": 50");
    println!("  }},");
    println!("  \"pipelines\": [...] ");
    println!("}}");
    println!();

    println!("验证步骤：");
    println!();
    println!("1. 检查配置文件：");
    println!("   cat config/pipeline_fast.json | grep cache_background_refresh");
    println!();
    println!("2. 检查日志级别：");
    println!("   RUST_LOG=info ./kixdns");
    println!();
    println!("3. 查找关键日志：");
    println!("   grep \"cache background refresh check\" kixdns.log");
    println!();
    println!("4. 检查日志中的字段：");
    println!("   应该看到：");
    println!("   - original_ttl");
    println!("   - elapsed_secs");
    println!("   - remaining_ttl");
    println!("   - threshold_value");
    println!("   - should_trigger");
    println!("   - upstream ← 关键：应该是 Some(...) 而不是 None");
    println!();
}

#[test]
fn test_timing_calculation_with_user_values() {
    println!("\n=== 用用户实际值计算 ===\n");

    // 用户实际观察到的值
    let original_ttl = 300u32;
    let threshold_percent = 50u8;
    let min_ttl = 50u32;
    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100; // 150

    println!("配置：");
    println!("  cache_refresh_threshold_percent = {}%", threshold_percent);
    println!("  cache_refresh_min_ttl = {} 秒", min_ttl);
    println!("  计算的阈值 = {} 秒", threshold);
    println!();

    let test_times = vec![
        0u32,    // 刚插入
        100u32,  // 100 秒后
        149u32,  // 149 秒后
        150u32,  // 150 秒后（用户观察到的）
        151u32,  // 151 秒后
        200u32,  // 200 秒后
    ];

    println!("时间序列分析：");
    for elapsed in test_times {
        let remaining = original_ttl.saturating_sub(elapsed);
        let should_trigger = remaining as u64 <= threshold && remaining >= min_ttl as u32;

        let status = if should_trigger { "✅ 触发" } else { "  不触发" };

        println!("  T+{:>3}秒: 剩余 TTL={:>3}秒, 应该触发: {} {}",
            elapsed, remaining, should_trigger, status);
    }

    println!();
    println!("用户观察：");
    println!("  T+150秒: TTL=150 → 预期触发，实际未触发 ❌");
    println!("  T+151秒: TTL=149 → 预期触发，实际未触发 ❌");
    println!("  T+152秒: TTL=148 → 预期触发，实际未触发 ❌");
    println!();

    println!("结论：");
    println!("  如果日志级别正确（INFO），应该能看到预取日志");
    println!("  如果看不到任何日志，说明条件 1、2、3 中有某个不满足");
}
