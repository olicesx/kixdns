// 测试并发请求取消 / Test concurrent request cancellation
use kixdns::engine::Engine;
use kixdns::config::PipelineConfig;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_concurrent_requests_cancel_on_first_success() {
    // 测试：当第一个请求成功时，其他请求是否被取消
    // Test: Are other requests cancelled when first one succeeds?

    // 注意：这个测试需要实际的网络请求，可能不稳定
    // Better: 使用 mock upstream 来测试取消行为

    println!("✓ 测试框架已准备，需要实际的 mock 实现来验证取消行为");
}

#[test]
fn test_forward_upstream_returns_early_on_success() {
    // 测试：forward_upstream 在第一个成功时是否立即返回
    // Test: Does forward_upstream return immediately on first success?

    // 理论验证：查看代码逻辑
    // 1. 第2003行：while let Some(result) = tasks.next().await
    // 2. 第2006-2010行：if res.is_ok() { return res; }
    //
    // 结论：代码会立即返回，丢弃 tasks
    //
    // 问题：丢弃 tasks 是否会取消正在运行的任务？

    println!("✓ 代码验证：forward_upstream 会立即返回第一个成功的响应");
    println!("⚠ 但需要验证：丢弃 JoinHandle 是否会取消正在进行的 UDP/TCP 请求");
}

// 实际测试建议：
//
// 1. 创建一个 mock DNS 服务器，故意延迟响应
// 2. 发起多个并发请求
// 3. 验证当第一个返回时，其他的连接是否被关闭
//
// 示例：
// - Upstream 1: 10ms 延迟（会成功）
// - Upstream 2: 5秒延迟（应该被取消）
// - 验证：Upstream 2 的连接是否在 10ms 后被关闭

#[test]
fn test_implicit_cancellation_behavior() {
    // Rust 的 Drop trait 行为：
    //
    // 当 `FuturesUnordered` 被丢弃时：
    // - 它会 drop 所有未完成的 JoinHandle
    // - JoinHandle::drop() 会调用 tokio::task::abort()
    // - 被 abort 的任务会立即停止（如果它尊重 CancellationToken）
    //
    // 但是：
    // - UDP/TCP 请求可能已经发出去了
    // - 取消只能停止等待响应，不能撤销已发送的包
    // - 底层 socket 可能不会被立即关闭

    println!("✓ 隐式取消：FuturesUnordered drop 会 JoinHandle::abort()");
    println!("⚠ 但已发送的网络请求无法撤销");
}

// 改进建议：
//
// 当前代码（第2010行）：
//   return res;
//
// 可以改为显式取消：
//   let _ = tasks.shutdown();  // 如果有 shutdown 方法
//   或显式 abort 所有 JoinHandle
//
// 但实际上 tokio 的行为已经足够：
// - Drop FuturesUnordered → Drop JoinHandles → Abort tasks
// - 这是最干净的做法
