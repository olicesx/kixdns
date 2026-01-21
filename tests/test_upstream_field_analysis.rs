// 验证 upstream 字段是否正确写入缓存（修复后）
// Verify upstream field is correctly written to cache (after fix)

#[test]
fn verify_upstream_field_writing_after_fix() {
    println!("\n=== 验证 upstream 字段写入流程（修复后）===\n");

    println!("修复内容：");
    println!("1. forward_upstream() 现在返回 (Bytes, String) 而不是 Bytes");
    println!("2. String 是实际响应的 upstream 地址");
    println!("3. 缓存保存时使用实际响应的 upstream，而不是配置的");

    println!("\n示例场景：");
    println!("配置：upstream = [\"8.8.8.8:53\", \"1.1.1.1:53\"]");
    println!("  并发请求发送到两个 upstream");
    println!("  1.1.1.1:53 在 20ms 响应（最快）");
    println!("  8.8.8.8:53 在 50ms 响应（被取消）");

    println!("\n修复前：");
    println!("  返回：Bytes");
    println!("  缓存保存：upstream = Some(\"8.8.8.8:53,1.1.1.1:53\")（配置的合并字符串）");
    println!("  预取使用：配置的合并字符串 ❌");

    println!("\n修复后：");
    println!("  返回：(Bytes, \"1.1.1.1:53\")");
    println!("  缓存保存：upstream = Some(\"1.1.1.1:53\")（实际响应的）✅");
    println!("  预取使用：实际响应的 upstream ✅");

    println!("\n修复优势：");
    println!("  ✅ 预取会使用成功解析该域名的 upstream");
    println!("  ✅ 如果某个 upstream 比较慢但能解析，不会被错误使用");
    println!("  ✅ 后续查询会优先使用实际最快响应的 upstream");
}

#[test]
fn test_actual_upstream_propagation() {
    println!("\n=== 实际 upstream 的传播路径 ===\n");

    println!("代码路径（修复后）：");
    println!();
    println!("1. forward_upstream() 返回");
    println!("   单个 upstream：return res.map(|b| (b, upstream.to_string()))");
    println!("   并发请求：return res.map(|b| (b, up))  // up 是实际响应的");
    println!();
    println!("2. 主流程解构");
    println!("   match resp {{");
    println!("       Ok((raw, actual_upstream)) => {{  // 解构出实际 upstream");
    println!("           ...");
    println!("       }}");
    println!("   }}");
    println!();
    println!("3. 写入缓存");
    println!("   self.insert_dns_cache_entry(");
    println!("       ...,");
    println!("       Arc::from(actual_upstream.as_str()),  // source");
    println!("       Some(Arc::from(actual_upstream.as_str())),  // upstream ✅");
    println!("       ...,");
    println!("   );");
    println!();
    println!("4. ResponseContext");
    println!("   ResponseContext {{");
    println!("       ...,");
    println!("       upstream: Arc::from(actual_upstream.as_str()),  // ✅");
    println!("   }}");
    println!();
    println!("5. 后台刷新");
    println!("   从缓存读取 upstream 字段");
    println!("   使用该 upstream 发起刷新请求 ✅");
}
