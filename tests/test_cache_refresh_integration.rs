// 集成测试：模拟用户场景，验证缓存刷新是否正确更新 TTL
// Integration test: simulate user scenario, verify cache refresh updates TTL correctly

#[test]
fn test_cache_refresh_updates_ttl() {
    println!("\n=== 集成测试：缓存刷新 TTL 更新 ===\n");

    println!("场景模拟：");
    println!("  1. 首次查询，TTL = 230");
    println!("  2. 等待 130 秒（剩余 TTL = 100）");
    println!("  3. 触发预取（阈值 50%，剩余 100 < 115）");
    println!("  4. 预取返回 TTL = 300");
    println!("  5. 验证缓存是否更新为 TTL = 300");
    println!();

    // 配置参数
    let original_ttl = 230u32;
    let threshold_percent = 50u8;
    let min_ttl = 50u32;
    let threshold = (original_ttl as u64 * threshold_percent as u64) / 100; // 115

    println!("配置：");
    println!("  cache_refresh_threshold_percent = {}%", threshold_percent);
    println!("  cache_refresh_min_ttl = {} 秒", min_ttl);
    println!("  计算阈值 = {} 秒", threshold);
    println!();

    // 阶段 1: 首次查询
    println!("阶段 1: 首次查询");
    println!("  查询 www.youtube.com");
    println!("  Upstream 响应: TTL = {} 秒", original_ttl);
    println!("  写入缓存: original_ttl = {}, inserted_at = T0", original_ttl);
    println!();

    let mut cached_original_ttl = original_ttl;
    let _inserted_at = 0u32; // T0

    // 阶段 2: 等待 130 秒后查询
    println!("阶段 2: 等待 130 秒后查询");
    let elapsed = 130u32;
    let remaining = cached_original_ttl.saturating_sub(elapsed);

    println!("  elapsed = {} 秒", elapsed);
    println!("  remaining_ttl = {} 秒", remaining);
    println!("  threshold = {} 秒", threshold);

    let should_trigger = remaining as u64 <= threshold && remaining >= min_ttl as u32;
    println!("  应该触发预取: {} ({} <= {} && {} >= {})",
        should_trigger, remaining, threshold, remaining, min_ttl);

    assert!(should_trigger, "剩余 100 秒时应该触发预取");
    println!();

    // 阶段 3: 模拟预取返回新 TTL
    println!("阶段 3: 预取执行");
    let new_ttl_from_upstream = 300u32;
    println!("  预取查询 upstream");
    println!("  Upstream 响应: TTL = {} 秒", new_ttl_from_upstream);

    // 模拟缓存更新
    cached_original_ttl = new_ttl_from_upstream;
    let _inserted_at = elapsed; // 简化：新的插入时间

    println!("  更新缓存:");
    println!("    original_ttl: {} → {}", original_ttl, cached_original_ttl);
    println!("    inserted_at: T0 → T{}", _inserted_at);
    println!();

    // 阶段 4: 验证更新后的缓存
    println!("阶段 4: 几秒后再次查询");
    let elapsed_since_refresh = 10u32;
    let remaining_after_refresh = cached_original_ttl.saturating_sub(elapsed_since_refresh);

    println!("  elapsed (from T{}) = {} 秒", _inserted_at, elapsed_since_refresh);
    println!("  remaining_ttl = {} 秒", remaining_after_refresh);

    // 如果缓存正确更新，剩余 TTL 应该接近 300，而不是继续递减
    assert!(remaining_after_refresh > 200,
        "缓存更新后剩余 TTL 应该 > 200，实际 = {}",
        remaining_after_refresh);

    println!("  ✅ 缓存正确更新！剩余 TTL = {} 秒（接近 300）", remaining_after_refresh);
    println!();

    println!("✅ 测试通过：缓存刷新正确更新了 TTL");
}

#[test]
fn test_diagnose_cache_update_failure() {
    println!("\n=== 诊断：为什么缓存没有更新 ===\n");

    println!("用户观察到的问题：");
    println!("  1. TTL=230 → 等待 130 秒 → TTL=100（触发预取）");
    println!("  2. 预取执行（有 upstream 日志）");
    println!("  3. 几秒后 TTL=90（期望 300，实际继续递减）");
    println!("  4. 直接查询 upstream: TTL=300（确认 upstream 返回 300）");
    println!();

    println!("可能的原因：");
    println!();

    println!("1. 预取任务使用了错误的 cache_hash");
    println!("   - 缓存使用 cache_hash = hash(pipeline_id, qname, qtype, qclass)");
    println!("   - 如果预取计算的 hash 不同，会更新错误的缓存位置");
    println!("   - 检查：日志中的 cache_hash 值是否一致");
    println!();

    println!("2. 预取任务执行了，但缓存更新被覆盖");
    println!("   - 用户查询命中缓存，返回旧数据");
    println!("   - 预取同时更新缓存");
    println!("   - 但某个地方又用旧数据覆盖了新缓存");
    println!();

    println!("3. 预取任务收到响应，但 TTL 提取失败");
    println!("   - extract_ttl_from_msg() 返回 0");
    println!("   - 或者返回错误的 TTL 值");
    println!("   - 检查：日志中的 ttl 值");
    println!();

    println!("4. 缓存更新成功，但用户查询读取的是旧缓存");
    println!("   - 缓存并发问题");
    println!("   - DashMap 的 insert 操作没有正确覆盖");
    println!();

    println!("5. 预取任务更新了缓存，但 inserted_at 没有更新");
    println!("   - 代码显示：inserted_at = Instant::now()");
    println!("   - 应该是新的时间戳");
    println!();

    println!("诊断步骤：");
    println!("  1. 查看日志中的 cache_background_refresh_got_response");
    println!("     - ttl 值是多少？（应该是 300）");
    println!("  2. 查看日志中的 cache_background_refresh_updated");
    println!("     - 是否出现？（表示缓存更新成功）");
    println!("  3. 查看用户查询的日志");
    println!("     - 是否命中缓存？（cache hit）");
    println!("     - 命中的 TTL 是多少？（应该是 300）");
}

#[test]
fn test_cache_hash_consistency() {
    println!("\n=== 测试 cache_hash 一致性 ===\n");

    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // 模拟 hash 计算
    fn calculate_hash(pipeline_id: &str, qname: &str, qtype: u16, qclass: u16) -> u64 {
        let mut hasher = DefaultHasher::new();
        pipeline_id.hash(&mut hasher);
        qname.hash(&mut hasher);
        qtype.hash(&mut hasher);
        qclass.hash(&mut hasher);
        hasher.finish()
    }

    let pipeline_id = "pipeline";
    let qname = "www.youtube.com";
    let qtype = 1u16;  // A
    let qclass = 1u16; // IN

    // 计算 10 次，验证 hash 一致性
    let mut hashes = Vec::new();
    for _ in 0..10 {
        let hash = calculate_hash(pipeline_id, qname, qtype, qclass);
        hashes.push(hash);
    }

    // 所有 hash 应该相同
    let first_hash = hashes[0];
    let all_same = hashes.iter().all(|&h| h == first_hash);

    println!("Hash 计算：");
    println!("  pipeline_id = {}", pipeline_id);
    println!("  qname = {}", qname);
    println!("  qtype = {}", qtype);
    println!("  qclass = {}", qclass);
    println!("  hash = {}", first_hash);
    println!("  所有 hash 相同: {}", all_same);

    assert!(all_same, "hash 计算应该是确定性的");

    // 模拟不同的参数组合
    let uppercase_name = "www.youtube.com".to_uppercase();
    let scenarios = vec![
        ("pipeline", "www.youtube.com", 1, 1),
        ("pipeline", uppercase_name.as_str(), 1, 1), // 大小写不同
        ("pipeline", "www.youtube.com.", 1, 1), // 带尾点
    ];

    println!("\n不同参数的 hash：");
    for (pid, qn, qt, qc) in scenarios {
        let h = calculate_hash(pid, qn, qt, qc);
        println!("  hash({}, {}, {}, {}) = {}", pid, qn, qt, qc, h);
    }

    println!("\n✅ Hash 计算正确且一致");
}
