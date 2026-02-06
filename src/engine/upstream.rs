use std::time::Duration;
use std::sync::atomic::Ordering;


use bytes::Bytes;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug};
use hickory_proto::op::ResponseCode;
use futures::future::select;

use crate::config::Transport;
use super::Engine;

/// Error indicating that all upstream attempts have been exhausted.
/// 表示所有 upstream 尝试均已耗尽的错误。
#[derive(Debug)]
pub struct UpstreamFailure {
    source: anyhow::Error,
}

impl UpstreamFailure {
    pub fn new(source: anyhow::Error) -> Self {
        Self { source }
    }
}

impl std::fmt::Display for UpstreamFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "all upstreams failed")
    }
}

impl std::error::Error for UpstreamFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Parse upstream address with optional protocol prefix.
/// 解析带有可选协议前缀的 upstream 地址。
///
/// Returns (address_without_prefix, transport).
/// 返回 (去除前缀的地址, 传输协议)。
///
/// Examples:
/// - "tcp://1.1.1.1:53" -> ("1.1.1.1:53", Transport::Tcp)
/// - "udp://1.1.1.1:53" -> ("1.1.1.1:53", Transport::Udp)
/// - "1.1.1.1:53" -> ("1.1.1.1:53", default_transport)
fn parse_upstream_addr(addr: &str, default_transport: Transport) -> (&str, Transport) {
    if let Some(idx) = addr.find("://") {
        let protocol = &addr[..idx];
        let address = &addr[idx + 3..];
        let transport = match protocol.to_lowercase().as_str() {
            "tcp" => Transport::Tcp,
            "udp" => Transport::Udp,
            _ => default_transport,
        };
        (address, transport)
    } else {
        (addr, default_transport)
    }
}

/// Hedge 超时除数：第一次尝试使用 1/N 的时间，为 TCP fallback 预留时间 / Hedge timeout divisor: first attempt uses 1/N of the budget to reserve time for TCP fallback
const HEDGE_TIMEOUT_DIVISOR: u32 = 3;

/// Send both TCP and UDP concurrently, return first successful response (hedged request).
/// 同时发送 TCP 和 UDP，返回第一个成功响应（对冲请求）。
///
/// Returns (response_bytes, protocol_name).
/// 返回 (响应字节, 协议名称)。
async fn fallback_after_primary_failure(
    other_task: tokio::task::JoinHandle<anyhow::Result<Bytes>>,
    remaining: Duration,
    primary_label: &'static str,
    primary_err: anyhow::Error,
    primary_is_task_error: bool,
    other_label: &'static str,
) -> anyhow::Result<(Bytes, &'static str)> {
    if remaining.is_zero() {
        other_task.abort();
        if primary_is_task_error {
            return Err(anyhow::anyhow!("{} task error: {}", primary_label, primary_err));
        }
        return Err(anyhow::anyhow!(
            "{} failed and no time left for {}: {}",
            primary_label,
            other_label,
            primary_err
        ));
    }

    let prefix = if primary_is_task_error { "task error" } else { "failed" };
    match timeout(remaining, other_task).await {
        Ok(Ok(Ok(bytes))) => Ok((bytes, other_label)),
        Ok(Ok(Err(other_err))) => Err(anyhow::anyhow!(
            "{} {}: {}; {} failed: {}",
            primary_label,
            prefix,
            primary_err,
            other_label,
            other_err
        )),
        Ok(Err(join_err)) => Err(anyhow::anyhow!(
            "{} {}: {}; {} task error: {}",
            primary_label,
            prefix,
            primary_err,
            other_label,
            join_err
        )),
        Err(_) => Err(anyhow::anyhow!(
            "{} {}: {}; {} timed out",
            primary_label,
            prefix,
            primary_err,
            other_label
        )),
    }
}

async fn forward_tcp_udp_dual(
    engine: &Engine,
    packet: &[u8],
    addr: &str,
    timeout_dur: Duration,
) -> anyhow::Result<(Bytes, &'static str)> {
    let engine_udp = engine.clone();
    let engine_tcp = engine.clone();
    let packet_udp = packet.to_vec();
    let packet_tcp = packet.to_vec();
    let addr_udp = addr.to_string();
    let addr_tcp = addr.to_string();

    let udp_task = tokio::spawn(async move {
        forward_udp_smart(&engine_udp, &packet_udp, &addr_udp, timeout_dur).await
    });

    let tcp_task = tokio::spawn(async move {
        engine_tcp.tcp_mux.send(&packet_tcp, &addr_tcp, timeout_dur).await
    });

    let start = std::time::Instant::now();

    // Wait for first successful response / 等待第一个成功响应
    match select(udp_task, tcp_task).await {
        futures::future::Either::Left((result, tcp_task)) => {
            match result {
                Ok(Ok(bytes)) => {
                    tcp_task.abort();
                    Ok((bytes, "udp"))
                }
                Ok(Err(err)) => {
                    let remaining = timeout_dur
                        .checked_sub(start.elapsed())
                        .unwrap_or_else(|| Duration::from_millis(0));
                    fallback_after_primary_failure(
                        tcp_task,
                        remaining,
                        "udp",
                        err,
                        false,
                        "tcp",
                    )
                    .await
                }
                Err(join_err) => {
                    let remaining = timeout_dur
                        .checked_sub(start.elapsed())
                        .unwrap_or_else(|| Duration::from_millis(0));
                    fallback_after_primary_failure(
                        tcp_task,
                        remaining,
                        "udp",
                        anyhow::anyhow!(join_err),
                        true,
                        "tcp",
                    )
                    .await
                }
            }
        }
        futures::future::Either::Right((result, udp_task)) => {
            match result {
                Ok(Ok(bytes)) => {
                    udp_task.abort();
                    Ok((bytes, "tcp"))
                }
                Ok(Err(err)) => {
                    let remaining = timeout_dur
                        .checked_sub(start.elapsed())
                        .unwrap_or_else(|| Duration::from_millis(0));
                    fallback_after_primary_failure(
                        udp_task,
                        remaining,
                        "tcp",
                        err,
                        false,
                        "udp",
                    )
                    .await
                }
                Err(join_err) => {
                    let remaining = timeout_dur
                        .checked_sub(start.elapsed())
                        .unwrap_or_else(|| Duration::from_millis(0));
                    fallback_after_primary_failure(
                        udp_task,
                        remaining,
                        "tcp",
                        anyhow::anyhow!(join_err),
                        true,
                        "udp",
                    )
                    .await
                }
            }
        }
    }
}

/// 默认最小 hedge 超时毫秒数（当计算值过小时使用） / Default minimum hedge timeout in milliseconds (used when calculated value is too small)
const DEFAULT_HEDGE_TIMEOUT_MS: u64 = 100;

/// Forward DNS request to multiple upstreams concurrently (Happy Eyeballs / Hedged Request)
/// 并发转发 DNS 请求到多个上游 (Happy Eyeballs / Hedged Request)
///
/// Returns the first successful response and the name of the winning upstream.
/// 返回第一个成功的响应和获胜的上游名称。
pub async fn forward_upstream(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    transport: Option<Transport>,
    pre_split_upstreams: Option<&std::sync::Arc<Vec<std::sync::Arc<str>>>>,
) -> anyhow::Result<(Bytes, String)> {
    // 如果 transport 为 None，使用默认 UDP
    let default_transport = transport.unwrap_or(Transport::Udp);

    // 使用预分割数据或动态分割 / Use pre-split data or dynamic splitting
    // 使用 Arc<str> 避免克隆 / Use Arc<str> to avoid cloning
    let upstreams: Vec<std::sync::Arc<str>> = if let Some(pre_split) = pre_split_upstreams {
        pre_split.iter().cloned().collect()
    } else if !upstream.contains(',') {
        // 单个上游：直接转发 / Single upstream: direct forward
        vec![std::sync::Arc::from(upstream)]
    } else {
        upstream.split(',').map(|s| s.trim()).map(|s| std::sync::Arc::from(s)).filter(|s: &std::sync::Arc<str>| !s.is_empty()).collect()
    };

    // 快速路径：只有一个上游时，直接调用避免 spawn 开销
    // Fast path: direct call when only one upstream, avoiding spawn overhead
    if upstreams.len() == 1 {
        let up = &upstreams[0];

        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_addr) = parse_upstream_addr(up, default_transport);

        let start = std::time::Instant::now();
        let (res, proto): (anyhow::Result<Bytes>, &str) = match transport_for_addr {
            Transport::Udp => {
                let r = forward_udp_smart(engine, packet, addr, timeout_dur).await;
                (r, "udp")
            }
            Transport::Tcp => {
                let r = engine.tcp_mux.send(packet, addr, timeout_dur).await;
                (r, "tcp")
            }
            Transport::TcpUdp => {
                // Dual-send: spawn both TCP and UDP concurrently, use first response
                // 双发：同时发送 TCP 和 UDP，使用第一个响应
                forward_tcp_udp_dual(engine, packet, addr, timeout_dur)
                    .await
                    .map(|(bytes, proto)| (Ok(bytes), proto))
                    .unwrap_or_else(|e| (Err(e), "udp"))
            }
        };
        let dur = start.elapsed();

        let upstream_with_proto = format!("{}:{}", proto, addr);

        match res {
            Ok(ref bytes) => {
             // 记录成功指标 / Record success metrics
             // Increment upstream metrics - 原子操作
             engine.metrics_upstream_calls.fetch_add(1, Ordering::Relaxed);
             engine.metrics_upstream_ns_total.fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
             engine.metrics_last_upstream_latency_ns.store(dur.as_nanos() as u64, Ordering::Relaxed);
             
             // Quick check rcode logging
             if let Some(qr) = crate::proto_utils::parse_response_quick(bytes) {
                tracing::debug!(upstream=%up, upstream_ns = dur.as_nanos() as u64, rcode = %qr.rcode, "upstream call succeeded");
             }
             return Ok((bytes.clone(), upstream_with_proto));
            }
            Err(err) => {
                // 失败时不构造 prefix，只 warn
                tracing::warn!(upstream=%up, error=%err, elapsed_ns = dur.as_nanos() as u64, "single upstream call failed");
                return Err(anyhow::Error::new(UpstreamFailure::new(err)));
            }
        }
    }

    // Multiple upstreams: use JoinSet for concurrency
    // 多个上游：使用 JoinSet 进行并发
    let mut tasks = JoinSet::new();
    let packet_owned = packet.to_vec();
    let mut last_err: Option<anyhow::Error> = None;

    for up in upstreams {
        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_task) = parse_upstream_addr(&up, default_transport);

        let engine = engine.clone();
        let packet = packet_owned.clone();
        let addr_owned = addr.to_string();

        tasks.spawn(async move {
            let start = std::time::Instant::now();
            let (proto, res) = match transport_for_task {
                Transport::Udp => {
                    let r = forward_udp_smart(&engine, &packet, &addr_owned, timeout_dur).await;
                    ("udp", r)
                }
                Transport::Tcp => {
                    let r = engine.tcp_mux.send(&packet, &addr_owned, timeout_dur).await;
                    ("tcp", r)
                }
                Transport::TcpUdp => {
                    // Dual-send: spawn both TCP and UDP concurrently, use first response
                    // 双发：同时发送 TCP 和 UDP，使用第一个响应
                    match forward_tcp_udp_dual(&engine, &packet, &addr_owned, timeout_dur).await {
                        Ok((bytes, proto)) => (proto, Ok(bytes)),
                        Err(e) => ("udp", Err(e)),
                    }
                }
            };

            // Note: for TcpUdp, timing includes both tasks' spawn/abort overhead
            // 注意：对于 TcpUdp，计时包含两个任务的 spawn/abort 开销
            let upstream_with_proto = format!("{}:{}", proto, addr_owned);
            let dur = start.elapsed();
            (upstream_with_proto, res, dur)
        });
    }

    // 等待第一个成功响应 / Wait for first successful response
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((up_proto, res, dur)) => {
                match res {
                    Ok(bytes) => {

                    // 快速解析响应码 / Quick parse response code
                    let should_accept = if let Some(qr) = crate::proto_utils::parse_response_quick(&bytes) {
                         match qr.rcode {
                            ResponseCode::NoError => true,
                            ResponseCode::ServFail | ResponseCode::Refused => false,
                            _ => true,
                         }
                    } else {
                        true
                    };

                    if should_accept {
                         engine.metrics_upstream_calls.fetch_add(1, Ordering::Relaxed);
                         engine.metrics_upstream_ns_total.fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
                         engine.metrics_last_upstream_latency_ns.store(dur.as_nanos() as u64, Ordering::Relaxed);

                        // 显式取消其他正在进行的任务
                        if !tasks.is_empty() {
                            tasks.abort_all();
                        }

                        return Ok((bytes, up_proto));
                    }
                }
                    Err(err) => {
                        tracing::warn!(upstream=%up_proto, error=%err, elapsed_ns = dur.as_nanos() as u64, "upstream call failed, waiting for others");
                        last_err = Some(err);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "upstream task join error, waiting for others");
                last_err = Some(anyhow::anyhow!(e));
            }
        }
    }

    // 所有上游都失败 / All upstreams failed
    let err = last_err.unwrap_or_else(|| anyhow::anyhow!("all upstreams failed"));
    Err(anyhow::Error::new(UpstreamFailure::new(err)))
}


/// UDP forwarder with hedged retry and TCP fallback for better tail latency.
async fn forward_udp_smart(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
) -> anyhow::Result<Bytes> {
    // 获取 TCP fallback 配置（Copy bool 值，避免持有 Guard 跨 await）
    // Get TCP fallback config (Copy bool value to avoid holding Guard across await)
    let enable_tcp_fallback = engine.state.load().pipeline.settings.enable_tcp_fallback;

    // Split timeout: first attempt uses 1/N budget (leaving room for TCP fallback)
    // 分割超时：第一次尝试使用 1/N 时间（为 TCP fallback 留出空间）
    let hedge_timeout = timeout_dur
        .checked_div(HEDGE_TIMEOUT_DIVISOR)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_HEDGE_TIMEOUT_MS).max(timeout_dur));
    let attempts = [hedge_timeout, timeout_dur];

    for (idx, dur) in attempts.iter().enumerate() {
        match engine.udp_client.send(packet, upstream, *dur).await {
            Ok(bytes) => {
                // RFC 1035: Check TC (Truncated) flag using quick parse - 使用快速解析检查 TC 标志
                if let Some(qr) = crate::proto_utils::parse_response_quick(&bytes) {
                    if qr.truncated && enable_tcp_fallback {
                        debug!(event = "tc_flag_fallback", upstream = %upstream, "udp response truncated, retrying with tcp");
                        return engine.tcp_mux.send(packet, upstream, timeout_dur).await;
                    }
                }
                return Ok(bytes);
            }
            Err(err) => {
                debug!(
                    event = "udp_forward_retry",
                    upstream = %upstream,
                    attempt = idx + 1,
                    timeout_ms = dur.as_millis() as u64,
                    error = %err,
                    "udp forward attempt failed",
                );
                if idx + 1 == attempts.len() {
                    if enable_tcp_fallback {
                        // Last UDP attempt, try TCP fallback before failing.
                        debug!(event = "udp_forward_fallback_tcp", upstream = %upstream, "falling back to tcp");
                        return engine.tcp_mux.send(packet, upstream, timeout_dur).await;
                    }
                }
            }
        }
    }

    // Should never reach here because we either return on success or fallback.
    // However, if TCP fallback is disabled, we might reach here if all UDP attempts fail.
    // 如果 TCP fallback 被禁用，若所有 UDP 尝试均失败，可能会到达此处。
    anyhow::bail!("all udp attempts failed and tcp fallback disabled")
}
