use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use futures::future::select;
use hickory_proto::op::ResponseCode;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::debug;

use super::Engine;
use crate::config::Transport;
use crate::observe::{UpstreamAttempt, UpstreamOutcome, UpstreamResult};

use super::observation::Observed;

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

/// Whether an upstream address carries a `scheme://` transport prefix, which
/// [`parse_upstream_addr`] lets override the configured transport.
/// 上游地址是否带 `scheme://` 传输前缀（parse_upstream_addr 以前缀覆盖配置的传输）。
pub(crate) fn has_transport_prefix(addr: &str) -> bool {
    addr.contains("://")
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
/// - "dot://1.1.1.1:853" -> ("1.1.1.1:853", Transport::Dot)
/// - "doq://dns.example.com:853" -> ("dns.example.com:853", Transport::Doq)
/// - "doh://dns.example.com/dns-query" -> ("dns.example.com/dns-query", Transport::Doh)
/// - "https://dns.example.com/dns-query" -> ("dns.example.com/dns-query", Transport::Doh)
/// - "1.1.1.1:53" -> ("1.1.1.1:53", default_transport)
fn parse_upstream_addr(addr: &str, default_transport: Transport) -> (&str, Transport) {
    if let Some(idx) = addr.find("://") {
        let protocol = &addr[..idx];
        let address = &addr[idx + 3..];
        let transport = match protocol.to_lowercase().as_str() {
            "tcp" => Transport::Tcp,
            "udp" => Transport::Udp,
            "tcp+udp" | "udp+tcp" => Transport::TcpUdp,
            "doh" | "https" => Transport::Doh,
            "dot" | "tls" => Transport::Dot,
            "doq" | "quic" => Transport::Doq,
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
            return Err(anyhow::anyhow!(
                "{} task error: {}",
                primary_label,
                primary_err
            ));
        }
        return Err(anyhow::anyhow!(
            "{} failed and no time left for {}: {}",
            primary_label,
            other_label,
            primary_err
        ));
    }

    let prefix = if primary_is_task_error {
        "task error"
    } else {
        "failed"
    };
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
    // Use Bytes for cheap clone (refcount) instead of Vec full copy
    // 使用 Bytes 实现低成本克隆（引用计数）而非 Vec 全量拷贝
    let packet_shared = Bytes::copy_from_slice(packet);
    let packet_udp = packet_shared.clone();
    let packet_tcp = packet_shared.clone();
    let addr_udp = addr.to_string();
    let addr_tcp = addr.to_string();

    let udp_task = tokio::spawn(async move {
        // Disable TCP fallback here to avoid duplicate TCP sends when dual-send is enabled.
        forward_udp_smart(&engine_udp, &packet_udp, &addr_udp, timeout_dur, false).await
    });

    let tcp_task = tokio::spawn(async move {
        engine_tcp
            .tcp_mux
            .send(&packet_tcp, &addr_tcp, timeout_dur)
            .await
    });

    let start = std::time::Instant::now();

    // Wait for first successful response / 等待第一个成功响应
    match select(udp_task, tcp_task).await {
        futures::future::Either::Left((result, tcp_task)) => match result {
            Ok(Ok(bytes)) => {
                tcp_task.abort();
                Ok((bytes, "udp"))
            }
            Ok(Err(err)) => {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or_else(|| Duration::from_millis(0));
                fallback_after_primary_failure(tcp_task, remaining, "udp", err, false, "tcp").await
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
        },
        futures::future::Either::Right((result, udp_task)) => match result {
            Ok(Ok(bytes)) => {
                udp_task.abort();
                Ok((bytes, "tcp"))
            }
            Ok(Err(err)) => {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or_else(|| Duration::from_millis(0));
                fallback_after_primary_failure(udp_task, remaining, "tcp", err, false, "udp").await
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
        },
    }
}

/// 默认最小 hedge 超时毫秒数（当计算值过小时使用） / Default minimum hedge timeout in milliseconds (used when calculated value is too small)
const DEFAULT_HEDGE_TIMEOUT_MS: u64 = 100;

/// Forward DNS request to multiple upstreams concurrently (Happy Eyeballs / Hedged Request)
/// 并发转发 DNS 请求到多个上游 (Happy Eyeballs / Hedged Request)
///
/// Returns the first successful response and the name of the winning upstream.
/// 返回第一个成功的响应和获胜的上游名称。
///
/// `observed` is the observer context of the request; every attempt and its
/// result is reported through it. / `observed` 为所属请求的观察者上下文，每次尝试及其结果都经它上报。
pub async fn forward_upstream(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    transport: Option<Transport>,
    pre_split_upstreams: Option<&std::sync::Arc<Vec<std::sync::Arc<str>>>>,
    observed: Observed<'_>,
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
        upstream
            .split(',')
            .map(|s| s.trim())
            .map(std::sync::Arc::from)
            .filter(|s: &std::sync::Arc<str>| !s.is_empty())
            .collect()
    };

    // 快速路径：只有一个上游时，直接调用避免 spawn 开销
    // Fast path: direct call when only one upstream, avoiding spawn overhead
    if upstreams.len() == 1 {
        let up = &upstreams[0];

        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_addr) = parse_upstream_addr(up, default_transport);
        if let Some((observer, ctx)) = observed {
            observer.upstream_attempt(
                ctx,
                &UpstreamAttempt {
                    upstream: addr,
                    transport: transport_for_addr,
                },
            );
        }

        let start = std::time::Instant::now();
        // `via` is the transport that actually carried the answer (UDP may fall
        // back to TCP) / `via` 为实际带回答案的传输（UDP 可能回退到 TCP）
        let (res, proto, via): (anyhow::Result<Bytes>, &str, Transport) = match transport_for_addr {
            Transport::Udp => {
                match forward_udp_smart_via(engine, packet, addr, timeout_dur, true).await {
                    Ok((bytes, via)) => (Ok(bytes), "udp", via),
                    Err(err) => (Err(err), "udp", Transport::Udp),
                }
            }
            Transport::Tcp => {
                let r = engine.tcp_mux.send(packet, addr, timeout_dur).await;
                (r, "tcp", Transport::Tcp)
            }
            Transport::TcpUdp => {
                // Dual-send: spawn both TCP and UDP concurrently, use first response
                // 双发：同时发送 TCP 和 UDP，使用第一个响应
                forward_tcp_udp_dual(engine, packet, addr, timeout_dur)
                    .await
                    .map(|(bytes, proto)| (Ok(bytes), proto, label_transport(proto)))
                    .unwrap_or_else(|e| (Err(e), "udp", Transport::TcpUdp))
            }
            Transport::Doh => {
                let r = engine.doh_client.send(packet, addr, timeout_dur).await;
                (r, "doh", Transport::Doh)
            }
            Transport::Dot => {
                let r = engine.dot_mux.send(packet, addr, timeout_dur).await;
                (r, "dot", Transport::Dot)
            }
            Transport::Doq => {
                let r = engine.doq_client.send(packet, addr, timeout_dur).await;
                (r, "doq", Transport::Doq)
            }
        };
        let dur = start.elapsed();

        let upstream_with_proto = format!("{}:{}", proto, addr);

        match res {
            Ok(ref bytes) => {
                // Quick check rcode / 快速解析响应码
                let quick = crate::proto_utils::parse_response_quick(bytes);
                if let Some((observer, ctx)) = observed {
                    observer.upstream_result(
                        ctx,
                        &UpstreamResult {
                            upstream: addr,
                            transport: transport_for_addr,
                            via,
                            outcome: UpstreamOutcome::Success,
                            latency: dur,
                            rcode: quick.as_ref().map(|qr| qr.rcode),
                            truncated: quick.as_ref().map(|qr| qr.truncated),
                            error: None,
                        },
                    );
                }
                // 记录成功指标 / Record success metrics
                // Increment upstream metrics - 原子操作
                engine
                    .metrics_upstream_calls
                    .fetch_add(1, Ordering::Relaxed);
                engine
                    .metrics_upstream_ns_total
                    .fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
                engine
                    .metrics_last_upstream_latency_ns
                    .store(dur.as_nanos() as u64, Ordering::Relaxed);

                if let Some(qr) = quick {
                    tracing::debug!(upstream=%up, upstream_ns = dur.as_nanos() as u64, rcode = %qr.rcode, "upstream call succeeded");
                }
                return Ok((bytes.clone(), upstream_with_proto));
            }
            Err(err) => {
                if let Some((observer, ctx)) = observed {
                    observer.upstream_result(
                        ctx,
                        &UpstreamResult {
                            upstream: addr,
                            transport: transport_for_addr,
                            via: transport_for_addr,
                            outcome: UpstreamOutcome::Error,
                            latency: dur,
                            rcode: None,
                            truncated: None,
                            error: Some(&err),
                        },
                    );
                }
                // 失败时不构造 prefix，只 warn
                tracing::warn!(upstream=%up, error=%err, elapsed_ns = dur.as_nanos() as u64, "single upstream call failed");
                return Err(anyhow::Error::new(UpstreamFailure::new(err)));
            }
        }
    }

    // Multiple upstreams: use JoinSet for concurrency
    // 多个上游：使用 JoinSet 进行并发
    let mut tasks = JoinSet::new();
    // Use Bytes for cheap clone (refcount) instead of Vec full copy
    // 使用 Bytes 实现低成本克隆（引用计数）而非 Vec 全量拷贝
    let packet_owned = Bytes::copy_from_slice(packet);
    let mut last_err: Option<anyhow::Error> = None;
    // Attempts that have not reported a result yet, so losers of the race can
    // be reported as aborted; only tracked for an observer.
    // 尚未上报结果的尝试，用于把竞争失败者上报为已取消；仅在有观察者时跟踪。
    let mut pending: Option<Vec<(String, Transport, std::time::Instant)>> =
        observed.map(|_| Vec::new());

    // If any TCP/TCP+UDP upstream is present, avoid UDP->TCP fallback to prevent duplicate TCP sends
    // 如果同一批次已有 TCP/TCP+UDP 上游，禁用 UDP->TCP fallback，避免重复 TCP 发送
    let has_tcp_task = upstreams.iter().any(|up| {
        let (_, t) = parse_upstream_addr(up, default_transport);
        matches!(t, Transport::Tcp | Transport::TcpUdp)
    });

    for up in upstreams {
        // 解析地址中的协议前缀 / Parse protocol prefix from address
        let (addr, transport_for_task) = parse_upstream_addr(&up, default_transport);
        if let Some((observer, ctx)) = observed {
            observer.upstream_attempt(
                ctx,
                &UpstreamAttempt {
                    upstream: addr,
                    transport: transport_for_task,
                },
            );
        }

        if let Some(pending) = pending.as_mut() {
            pending.push((
                addr.to_string(),
                transport_for_task,
                std::time::Instant::now(),
            ));
        }

        let engine = engine.clone();
        let packet = packet_owned.clone();
        let addr_owned = addr.to_string();

        tasks.spawn(async move {
            let start = std::time::Instant::now();
            let (proto, res, via) = match transport_for_task {
                Transport::Udp => {
                    match forward_udp_smart_via(
                        &engine,
                        &packet,
                        &addr_owned,
                        timeout_dur,
                        !has_tcp_task,
                    )
                    .await
                    {
                        Ok((bytes, via)) => ("udp", Ok(bytes), via),
                        Err(err) => ("udp", Err(err), Transport::Udp),
                    }
                }
                Transport::Tcp => {
                    let r = engine.tcp_mux.send(&packet, &addr_owned, timeout_dur).await;
                    ("tcp", r, Transport::Tcp)
                }
                Transport::TcpUdp => {
                    // Dual-send: spawn both TCP and UDP concurrently, use first response
                    // 双发：同时发送 TCP 和 UDP，使用第一个响应
                    match forward_tcp_udp_dual(&engine, &packet, &addr_owned, timeout_dur).await {
                        Ok((bytes, proto)) => (proto, Ok(bytes), label_transport(proto)),
                        Err(e) => ("udp", Err(e), Transport::TcpUdp),
                    }
                }
                Transport::Doh => {
                    let r = engine
                        .doh_client
                        .send(&packet, &addr_owned, timeout_dur)
                        .await;
                    ("doh", r, Transport::Doh)
                }
                Transport::Dot => {
                    let r = engine.dot_mux.send(&packet, &addr_owned, timeout_dur).await;
                    ("dot", r, Transport::Dot)
                }
                Transport::Doq => {
                    let r = engine
                        .doq_client
                        .send(&packet, &addr_owned, timeout_dur)
                        .await;
                    ("doq", r, Transport::Doq)
                }
            };

            // Note: for TcpUdp, timing includes both tasks' spawn/abort overhead
            // 注意：对于 TcpUdp，计时包含两个任务的 spawn/abort 开销
            let upstream_with_proto = format!("{}:{}", proto, addr_owned);
            let dur = start.elapsed();
            (
                upstream_with_proto,
                addr_owned,
                transport_for_task,
                via,
                res,
                dur,
            )
        });
    }

    // 等待第一个成功响应 / Wait for first successful response
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((up_proto, addr, transport_for_task, via, res, dur)) => {
                if let Some(pending) = pending.as_mut()
                    && let Some(idx) = pending
                        .iter()
                        .position(|(a, t, _)| *a == addr && *t == transport_for_task)
                {
                    pending.swap_remove(idx);
                }
                // Report the outcome of this attempt / 上报本次尝试的结果
                let report = |outcome: UpstreamOutcome,
                              rcode: Option<ResponseCode>,
                              truncated: Option<bool>,
                              error: Option<&anyhow::Error>| {
                    if let Some((observer, ctx)) = observed {
                        observer.upstream_result(
                            ctx,
                            &UpstreamResult {
                                upstream: &addr,
                                transport: transport_for_task,
                                via,
                                outcome,
                                latency: dur,
                                rcode,
                                truncated,
                                error,
                            },
                        );
                    }
                };
                match res {
                    Ok(bytes) => {
                        // 快速解析响应码 / Quick parse response code
                        let quick = crate::proto_utils::parse_response_quick(&bytes);
                        let rcode = quick.as_ref().map(|qr| qr.rcode);
                        let truncated = quick.as_ref().map(|qr| qr.truncated);
                        let should_accept = if let Some(qr) = quick {
                            match qr.rcode {
                                ResponseCode::NoError => true,
                                ResponseCode::ServFail | ResponseCode::Refused => false,
                                _ => true,
                            }
                        } else {
                            true
                        };

                        if should_accept {
                            report(UpstreamOutcome::Success, rcode, truncated, None);
                            engine
                                .metrics_upstream_calls
                                .fetch_add(1, Ordering::Relaxed);
                            engine
                                .metrics_upstream_ns_total
                                .fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
                            engine
                                .metrics_last_upstream_latency_ns
                                .store(dur.as_nanos() as u64, Ordering::Relaxed);

                            // The remaining attempts lose the race / 其余尝试竞争失败
                            if let Some(pending) = pending.as_ref() {
                                report_aborted(observed, pending);
                            }
                            // 显式取消其他正在进行的任务
                            if !tasks.is_empty() {
                                tasks.abort_all();
                            }

                            return Ok((bytes, up_proto));
                        }
                        report(UpstreamOutcome::Rejected, rcode, truncated, None);
                    }
                    Err(err) => {
                        report(UpstreamOutcome::Error, None, None, Some(&err));
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

    // Attempts whose task never reported (join error) / 任务未能上报结果的尝试（join 错误）
    if let Some(pending) = pending.as_ref() {
        report_aborted(observed, pending);
    }

    // 所有上游都失败 / All upstreams failed
    let err = last_err.unwrap_or_else(|| anyhow::anyhow!("all upstreams failed"));
    Err(anyhow::Error::new(UpstreamFailure::new(err)))
}

/// Report every attempt still in flight as aborted / 把仍在飞的尝试上报为已取消
fn report_aborted(observed: Observed<'_>, pending: &[(String, Transport, std::time::Instant)]) {
    if let Some((observer, ctx)) = observed {
        for (upstream, transport, started) in pending {
            observer.upstream_result(
                ctx,
                &UpstreamResult {
                    upstream,
                    transport: *transport,
                    via: *transport,
                    outcome: UpstreamOutcome::Aborted,
                    latency: started.elapsed(),
                    rcode: None,
                    truncated: None,
                    error: None,
                },
            );
        }
    }
}

/// Transport named by a `tcp_udp` race label / `tcp_udp` 竞争标签对应的传输
fn label_transport(label: &str) -> Transport {
    if label == "tcp" {
        Transport::Tcp
    } else {
        Transport::Udp
    }
}

/// UDP forwarder with hedged retry and TCP fallback for better tail latency.
async fn forward_udp_smart(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    allow_tcp_fallback: bool,
) -> anyhow::Result<Bytes> {
    forward_udp_smart_via(engine, packet, upstream, timeout_dur, allow_tcp_fallback)
        .await
        .map(|(bytes, _)| bytes)
}

/// [`forward_udp_smart`] that also returns the transport that carried the
/// answer: UDP, or TCP after a TC-bit retry or a UDP-failure fallback.
/// 同 [`forward_udp_smart`]，并返回实际带回答案的传输（UDP，或 TC/失败回退后的 TCP）。
async fn forward_udp_smart_via(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
    allow_tcp_fallback: bool,
) -> anyhow::Result<(Bytes, Transport)> {
    // 获取 TCP fallback 配置（Copy bool 值，避免持有 Guard 跨 await）
    // Get TCP fallback config (Copy bool value to avoid holding Guard across await)
    let enable_tcp_fallback =
        allow_tcp_fallback && engine.state.load().pipeline.settings.enable_tcp_fallback;

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
                if let Some(qr) = crate::proto_utils::parse_response_quick(&bytes)
                    && qr.truncated
                    && enable_tcp_fallback
                {
                    debug!(event = "tc_flag_fallback", upstream = %upstream, "udp response truncated, retrying with tcp");
                    return engine
                        .tcp_mux
                        .send(packet, upstream, timeout_dur)
                        .await
                        .map(|bytes| (bytes, Transport::Tcp));
                }
                return Ok((bytes, Transport::Udp));
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
                if idx + 1 == attempts.len() && enable_tcp_fallback {
                    // Last UDP attempt, try TCP fallback before failing.
                    debug!(event = "udp_forward_fallback_tcp", upstream = %upstream, "falling back to tcp");
                    return engine
                        .tcp_mux
                        .send(packet, upstream, timeout_dur)
                        .await
                        .map(|bytes| (bytes, Transport::Tcp));
                }
            }
        }
    }

    // Should never reach here because we either return on success or fallback.
    // However, if TCP fallback is disabled, we might reach here if all UDP attempts fail.
    // 如果 TCP fallback 被禁用，若所有 UDP 尝试均失败，可能会到达此处。
    anyhow::bail!("all udp attempts failed and tcp fallback disabled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalSettings;
    use crate::matcher::RuntimePipelineConfig;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use rustc_hash::FxHashMap;
    use rustls::crypto::ring;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_parse_upstream_addr_with_protocol_prefix() {
        // Test that protocol prefixes are correctly extracted
        // 测试协议前缀是否正确提取

        // DoQ with prefix
        let (addr, transport) = parse_upstream_addr("doq://223.5.5.5:853", Transport::Udp);
        assert_eq!(addr, "223.5.5.5:853");
        assert_eq!(transport, Transport::Doq);

        // DoH with prefix
        let (addr, transport) = parse_upstream_addr("doh://dns.google/dns-query", Transport::Udp);
        assert_eq!(addr, "dns.google/dns-query");
        assert_eq!(transport, Transport::Doh);

        // HTTPS (alias for DoH)
        let (addr, transport) =
            parse_upstream_addr("https://dns.example.com/dns-query", Transport::Udp);
        assert_eq!(addr, "dns.example.com/dns-query");
        assert_eq!(transport, Transport::Doh);

        // DoT with prefix
        let (addr, transport) = parse_upstream_addr("dot://1.1.1.1:853", Transport::Udp);
        assert_eq!(addr, "1.1.1.1:853");
        assert_eq!(transport, Transport::Dot);

        // TLS (alias for DoT)
        let (addr, transport) = parse_upstream_addr("tls://dns.example.com:853", Transport::Udp);
        assert_eq!(addr, "dns.example.com:853");
        assert_eq!(transport, Transport::Dot);

        // TCP with prefix
        let (addr, transport) = parse_upstream_addr("tcp://8.8.8.8:53", Transport::Udp);
        assert_eq!(addr, "8.8.8.8:53");
        assert_eq!(transport, Transport::Tcp);

        // UDP with prefix
        let (addr, transport) = parse_upstream_addr("udp://1.1.1.1:53", Transport::Tcp);
        assert_eq!(addr, "1.1.1.1:53");
        assert_eq!(transport, Transport::Udp);

        // TCP+UDP with prefix
        let (addr, transport) = parse_upstream_addr("tcp+udp://8.8.8.8:53", Transport::Udp);
        assert_eq!(addr, "8.8.8.8:53");
        assert_eq!(transport, Transport::TcpUdp);

        // No prefix - use default
        let (addr, transport) = parse_upstream_addr("8.8.8.8:53", Transport::Udp);
        assert_eq!(addr, "8.8.8.8:53");
        assert_eq!(transport, Transport::Udp);

        // No prefix with different default
        let (addr, transport) = parse_upstream_addr("1.1.1.1:53", Transport::Tcp);
        assert_eq!(addr, "1.1.1.1:53");
        assert_eq!(transport, Transport::Tcp);

        // Case insensitive protocol
        let (addr, transport) = parse_upstream_addr("DOQ://223.5.5.5:853", Transport::Udp);
        assert_eq!(addr, "223.5.5.5:853");
        assert_eq!(transport, Transport::Doq);

        // QUIC (alias for DoQ)
        let (addr, transport) = parse_upstream_addr("quic://dns.example.com:853", Transport::Udp);
        assert_eq!(addr, "dns.example.com:853");
        assert_eq!(transport, Transport::Doq);
    }

    #[test]
    fn test_transport_field_can_be_omitted_with_url_prefix() {
        // This test verifies that when upstream URL contains a protocol prefix,
        // the transport field can be omitted in configuration.
        // 这个测试验证当 upstream URL 包含协议前缀时，
        // 配置中可以省略 transport 字段。

        // Simulate: { "upstream": "doq://223.5.5.5:853" } (no transport field)
        // transport field would be None, which becomes Transport::Udp as default
        let default_transport = Transport::Udp;

        // parse_upstream_addr should extract DoQ from the URL prefix
        let (addr, transport) = parse_upstream_addr("doq://223.5.5.5:853", default_transport);
        assert_eq!(addr, "223.5.5.5:853");
        assert_eq!(
            transport,
            Transport::Doq,
            "URL prefix should override default transport"
        );

        // Simulate: { "upstream": "doh://dns.google/dns-query" } (no transport field)
        let (addr, transport) =
            parse_upstream_addr("doh://dns.google/dns-query", default_transport);
        assert_eq!(addr, "dns.google/dns-query");
        assert_eq!(
            transport,
            Transport::Doh,
            "URL prefix should override default transport"
        );
    }

    #[test]
    fn test_doq_url_with_0rtt_parameter() {
        // Test that DoQ URLs with 0rtt parameter are parsed correctly
        // 测试带 0rtt 参数的 DoQ URL 是否正确解析

        // DoQ with 0rtt=false
        let (addr, transport) =
            parse_upstream_addr("doq://223.5.5.5:853?0rtt=false", Transport::Udp);
        assert_eq!(addr, "223.5.5.5:853?0rtt=false");
        assert_eq!(transport, Transport::Doq);

        // DoQ with 0rtt=true
        let (addr, transport) =
            parse_upstream_addr("doq://dns.google:853?0rtt=true", Transport::Udp);
        assert_eq!(addr, "dns.google:853?0rtt=true");
        assert_eq!(transport, Transport::Doq);

        // DoQ with SNI parameter
        let (addr, transport) = parse_upstream_addr(
            "doq://dns.example.com:853?sni=dns.example.com",
            Transport::Udp,
        );
        assert_eq!(addr, "dns.example.com:853?sni=dns.example.com");
        assert_eq!(transport, Transport::Doq);

        // DoQ with both 0rtt and SNI
        let (addr, transport) = parse_upstream_addr(
            "doq://dns.example.com:853?0rtt=false&sni=dns.example.com",
            Transport::Udp,
        );
        assert_eq!(addr, "dns.example.com:853?0rtt=false&sni=dns.example.com");
        assert_eq!(transport, Transport::Doq);
    }

    fn build_test_engine(enable_tcp_fallback: bool) -> Engine {
        let settings = GlobalSettings {
            default_upstream: "127.0.0.1:0".to_string(),
            enable_tcp_fallback,
            udp_pool_size: 1,
            tcp_pool_size: 1,
            ..GlobalSettings::default()
        };
        let runtime = RuntimePipelineConfig {
            settings,
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
            pipeline_id_index: FxHashMap::default(),
        };
        Engine::new(runtime, "test".to_string()).expect("initialize test engine")
    }

    fn build_dns_query_packet(qname: &str) -> Vec<u8> {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let name = Name::from_str(qname).expect("qname");
        msg.add_query(Query::query(name, RecordType::A));
        msg.to_vec().expect("encode dns query")
    }

    /// 在同一个端口上绑好 UDP 与 TCP，返回两者与它们共用的地址
    /// Bind UDP and TCP on one port and return both along with the shared address
    ///
    /// 两个 socket 必须是同一个端口，不能各绑各的：TCP 回退连的就是 upstream 的
    /// host:port，测试正是靠"有没有连到这个端口"来判断有没有回退。别顺手把它
    /// 简化成两个独立端口。
    /// The two sockets have to share one port rather than bind independently:
    /// TCP fallback dials the upstream's own host:port, and the test detects a
    /// fallback precisely by whether that port is connected to. Do not simplify
    /// this into two separate ports.
    ///
    /// 顺序是先 UDP 后 TCP。反过来会偶发 EADDRINUSE：TCP 的临时端口分配器不看
    /// UDP 占用，而整套测试并行跑时各 engine 的上游池都持有临时 UDP socket，
    /// TCP 拿到的端口可能已经被其中一个占着，第二个 UDP 绑上去就是 errno 98。
    /// 先拿 UDP 端口则把冲突面缩到"同进程的 TCP listener"，这套件里基本只有一个。
    /// UDP first, then TCP. The other order flakes with EADDRINUSE: the TCP
    /// ephemeral allocator does not look at UDP occupancy, and with the suite
    /// running in parallel every engine's upstream pool holds ephemeral UDP
    /// sockets, so the port TCP hands out may already be taken and the second
    /// UDP bind returns errno 98. Taking the UDP port first narrows the conflict
    /// to this process's own TCP listeners, of which there is essentially one.
    async fn bind_udp_and_tcp_on_one_port() -> (
        tokio::net::UdpSocket,
        tokio::net::TcpListener,
        std::net::SocketAddr,
    ) {
        // 第二道防线：那个端口偶尔也可能正被别的 TCP listener 占着，重绑即可。
        // 这不是替代上面的顺序，只是兜住剩下的那一小类。
        // Second line of defence: that port can still be held by another TCP
        // listener now and then, so rebind. It does not replace the ordering
        // above, it only covers the small class that is left.
        for _ in 0..16 {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind udp");
            let addr = udp.local_addr().expect("udp addr");
            match tokio::net::TcpListener::bind(addr).await {
                Ok(tcp) => return (udp, tcp, addr),
                Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(err) => panic!("bind tcp on the udp port: {err}"),
            }
        }
        panic!("could not find a port free for both udp and tcp after 16 attempts");
    }

    #[tokio::test]
    async fn udp_truncated_response_does_not_fallback_to_tcp_when_disallowed() {
        let _ = ring::default_provider().install_default();

        let (udp_socket, tcp_listener, upstream_addr) = bind_udp_and_tcp_on_one_port().await;

        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let tcp_hits_clone = Arc::clone(&tcp_hits);
        let tcp_task = tokio::spawn(async move {
            if let Ok(Ok((mut stream, _))) =
                tokio::time::timeout(Duration::from_millis(500), tcp_listener.accept()).await
            {
                tcp_hits_clone.fetch_add(1, Ordering::SeqCst);
                let mut len_buf = [0u8; 2];
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    stream.read_exact(&mut len_buf),
                )
                .await;
            }
        });

        let udp_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = udp_socket.recv_from(&mut buf).await.expect("udp recv");
            let mut resp = buf[..len].to_vec();
            if resp.len() >= 4 {
                resp[2] = 0x82; // QR=1, TC=1
                resp[3] = 0x00;
            }
            let _ = udp_socket.send_to(&resp, peer).await;
            resp
        });

        let engine = build_test_engine(true);
        let packet = build_dns_query_packet("example.com");

        let resp = forward_udp_smart(
            &engine,
            &packet,
            &upstream_addr.to_string(),
            Duration::from_millis(500),
            false,
        )
        .await
        .expect("udp response");

        let udp_resp = udp_task.await.expect("udp task");
        assert_eq!(resp[2], 0x82, "tc flag should be set in udp response");
        assert_eq!(resp[3], 0x00, "response flags should match truncated reply");
        assert_eq!(
            resp.as_ref()[2..],
            udp_resp.as_slice()[2..],
            "should return udp response without tcp fallback (ignoring txid rewrite)"
        );

        let _ = tcp_task.await;
        assert_eq!(
            tcp_hits.load(Ordering::SeqCst),
            0,
            "tcp fallback should be disabled in dual-send udp path"
        );
    }
}
