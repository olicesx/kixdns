use std::time::Duration;
use std::sync::atomic::Ordering;


use bytes::Bytes;
use tokio::task::JoinSet;
use tracing::{debug};
use hickory_proto::op::ResponseCode;

use crate::config::Transport;
use super::Engine;

/// Hedge 超时除数：第一次尝试使用 1/N 的时间，为 TCP fallback 预留时间 / Hedge timeout divisor: first attempt uses 1/N of the budget to reserve time for TCP fallback
const HEDGE_TIMEOUT_DIVISOR: u32 = 3;

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
        
        // 构造返回的 protocol prefix (tcp:.../udp:...)
        // Construct return protocol prefix
        let upstream_with_proto = match default_transport {
            Transport::Tcp => format!("tcp:{}", up),
            Transport::Udp => format!("udp:{}", up),
        };

        let start = std::time::Instant::now();
        let res = match default_transport {
             Transport::Udp => forward_udp_smart(engine, packet, up, timeout_dur).await,
             Transport::Tcp => engine.tcp_mux.send(packet, up, timeout_dur).await,
        };
        let dur = start.elapsed();

        if let Ok(ref bytes) = res {
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
        } else {
             // 失败时不构造 prefix，只 warn
             tracing::warn!(upstream=%up, error=%res.as_ref().unwrap_err(), elapsed_ns = dur.as_nanos() as u64, "single upstream call failed");
             return res.map(|b| (b, upstream_with_proto));
        }
    }

    // Multiple upstreams: use JoinSet for concurrency
    // 多个上游：使用 JoinSet 进行并发
    let mut tasks = JoinSet::new();
    let packet_owned = packet.to_vec();

    for up in upstreams {
        // No to_string() allocation needed, Arc<str> is cheap to clone
        let engine = engine.clone();
        let packet = packet_owned.clone();
        let transport_for_task = default_transport;

        tasks.spawn(async move {
            let upstream_with_proto = match transport_for_task {
                Transport::Tcp => format!("tcp:{}", up),
                Transport::Udp => format!("udp:{}", up),
            };

            let start = std::time::Instant::now();
            let res = match transport_for_task {
                Transport::Udp => forward_udp_smart(&engine, &packet, &up, timeout_dur).await,
                Transport::Tcp => engine.tcp_mux.send(&packet, &up, timeout_dur).await,
            };
            let dur = start.elapsed();
            (upstream_with_proto, res, dur)
        });
    }

    // 等待第一个成功响应 / Wait for first successful response
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((up_proto, res, dur)) => {
                if res.is_ok() {
                    let bytes = res.as_ref().unwrap();

                    // 快速解析响应码 / Quick parse response code
                    let should_accept = if let Some(qr) = crate::proto_utils::parse_response_quick(bytes) {
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

                        return res.map(|b| (b, up_proto));
                    }
                } else {
                    tracing::warn!(upstream=%up_proto, error=%res.as_ref().unwrap_err(), elapsed_ns = dur.as_nanos() as u64, "upstream call failed, waiting for others");
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "upstream task join error, waiting for others");
            }
        }
    }

    // 所有上游都失败 / All upstreams failed
    anyhow::bail!("all upstreams failed")
}


/// UDP forwarder with hedged retry and TCP fallback for better tail latency.
async fn forward_udp_smart(
    engine: &Engine,
    packet: &[u8],
    upstream: &str,
    timeout_dur: Duration,
) -> anyhow::Result<Bytes> {
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
                    if qr.truncated {
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
                    // Last UDP attempt, try TCP fallback before failing.
                    debug!(event = "udp_forward_fallback_tcp", upstream = %upstream, "falling back to tcp");
                    return engine.tcp_mux.send(packet, upstream, timeout_dur).await;
                }
            }
        }
    }

    // Should never reach here because we either return on success or fallback.
    anyhow::bail!("udp forward failed")
}
