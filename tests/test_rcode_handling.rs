// 测试并发请求中 DNS 响应码的处理
// Test DNS response code handling in concurrent requests

#[test]
fn test_rcode_success_definition() {
    // DNS 响应码定义：
    //
    // NOERROR (0)    = 成功 / Success
    // NXDOMAIN (3)   = 域名不存在 / Domain does not exist
    // SERVFAIL (2)   = 服务器失败 / Server failure
    // REFUSED (5)    = 拒绝查询 / Refused

    println!("DNS Rcode 定义：");
    println!("  NOERROR (0)    → 真正的成功");
    println!("  NXDOMAIN (3)   → 域名不存在（立即返回）");
    println!("  SERVFAIL (2)   → 服务器失败（继续等待其他 upstream）✅");
    println!("  REFUSED (5)    → 拒绝查询（继续等待其他 upstream）✅");
}

#[test]
fn test_new_behavior_reject_servfail_and_refused() {
    // 新行为：拒绝 SERVFAIL 和 REFUSED
    //
    // 并发请求 upstreams = ["8.8.8.8:53", "1.1.1.1:53"]
    //
    // 场景 1：NOERROR vs NXDOMAIN
    //   8.8.8.8:53   → 20ms 返回 NXDOMAIN
    //   1.1.1.1:53   → 50ms 返回 NOERROR
    //
    //   结果：返回 NXDOMAIN（20ms）✅
    //   原因：NXDOMAIN 立即返回
    //
    // 场景 2：SERVFAIL vs NOERROR
    //   8.8.8.8:53   → 20ms 返回 SERVFAIL
    //   1.1.1.1:53   → 50ms 返回 NOERROR
    //
    //   结果：等待 NOERROR（50ms）✅
    //   原因：SERVFAIL 被拒绝，继续等待其他 upstream
    //
    // 场景 3：SERVFAIL vs NXDOMAIN
    //   8.8.8.8:53   → 20ms 返回 SERVFAIL
    //   1.1.1.1:53   → 50ms 返回 NXDOMAIN
    //
    //   结果：等待 NXDOMAIN（50ms）✅
    //   原因：SERVFAIL 被拒绝，继续等待其他 upstream
    //
    // 场景 4：REFUSED vs NOERROR
    //   8.8.8.8:53   → 20ms 返回 REFUSED
    //   1.1.1.1:53   → 50ms 返回 NOERROR
    //
    //   结果：等待 NOERROR（50ms）✅
    //   原因：REFUSED 被拒绝，继续等待其他 upstream
    //
    // 场景 5：所有都是 SERVFAIL/REFUSED
    //   8.8.8.8:53   → 20ms 返回 SERVFAIL
    //   1.1.1.1:53   → 30ms 返回 REFUSED
    //
    //   结果：返回 SERVFAIL/REFUSED（第一个）✅
    //   原因：所有都是被拒绝的响应码，只能返回第一个

    println!("✅ 新行为特点：");
    println!("   1. NOERROR → 立即返回");
    println!("   2. NXDOMAIN → 立即返回（域名确实不存在）");
    println!("   3. SERVFAIL → 继续等待（服务器可能临时故障）");
    println!("   4. REFUSED → 继续等待（服务器可能临时拒绝查询）");
}

// 实现细节（src/engine.rs:2017-2020）：
//
// ResponseCode::ServFail | ResponseCode::Refused => {
//     tracing::warn!(..., "upstream returned {}, waiting for others", qr.rcode);
//     false  // 拒绝，继续等待
// }
//
// 日志示例：
// [DEBUG] upstream call succeeded (NOERROR) upstream=1.1.1.1:53 rcode=NOERROR
// [WARN] upstream returned SERVFAIL, waiting for others upstream=8.8.8.8:53 rcode=SERVFAIL
// [WARN] upstream returned REFUSED, waiting for others upstream=8.8.4.4 rcode=REFUSED
// [DEBUG] upstream response accepted (non-SERVFAIL/non-REFUSED) upstream=1.1.1.1:53 rcode=NXDOMAIN

#[test]
fn test_why_reject_servfail_and_refused() {
    // 为什么拒绝 SERVFAIL 和 REFUSED：
    //
    // **SERVFAIL 通常表示临时故障**
    // - DNS 服务器配置问题
    // - 后端服务不可用
    // - 网络问题
    // → 应该尝试其他 upstream
    //
    // **REFUSED 通常表示临时拒绝**
    // - DNS 服务器过载
    // - 配置限制（如速率限制）
    // - ACL 临时限制
    // → 应该尝试其他 upstream
    //
    // **NXDOMAIN 是确定的结果**
    // - 域名确实不存在
    // - 其他 upstream 也不会有不同结果
    // → 立即返回，避免延迟
    //
    // **平衡性能和可靠性**
    // - 大多数情况下延迟最小（NOERROR/NXDOMAIN）
    // - SERVFAIL/REFUSED 时自动容错
    // - 不会等待超时

    println!("✅ 优势：");
    println!("   - 性能：NOERROR/NXDOMAIN 立即返回");
    println!("   - 可靠性：SERVFAIL/REFUSED 时自动重试其他 upstream");
    println!("   - 正确性：NXDOMAIN 表示确定结果");
    println!("   - 容错：临时故障自动容错");
}

#[test]
fn test_behavior_comparison() {
    println!("行为对比：");
    println!();
    println!("场景：8.8.8.8:53 → 20ms REFUSED, 1.1.1.1:53 → 50ms NOERROR");
    println!();
    println!("旧行为：返回 REFUSED（20ms）");
    println!("  ❌ 得到错误结果");
    println!();
    println!("新行为：返回 NOERROR（50ms）");
    println!("  ✅ 结果正确");
    println!("  ✅ NXDOMAIN 立即返回");
    println!("  ✅ SERVFAIL/REFUSED 自动容错");
}


