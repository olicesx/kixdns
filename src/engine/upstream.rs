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
        // Disable TCP fallback here to avoid duplicate TCP sends when dual-send is enabled.
        forward_udp_smart(&engine_udp, &packet_udp, &addr_udp, timeout_dur, false).await
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
                let r = forward_udp_smart(engine, packet, addr, timeout_dur, true).await;
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
            Transport::Doh => {
                let r = engine.doh_client.send(packet, addr, timeout_dur).await;
                (r, "doh")
            }
            Transport::Dot => {
                let r = engine.dot_mux.send(packet, addr, timeout_dur).await;
                (r, "dot")
            }
            Transport::Doq => {
                let r = engine.doq_client.send(packet, addr, timeout_dur).await;
                (r, "doq")
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

    // If any TCP/TCP+UDP upstream is present, avoid UDP->TCP fallback to prevent duplicate TCP sends
    // 如果同一批次已有 TCP/TCP+UDP 上游，禁用 UDP->TCP fallback，避免重复 TCP 发送
    let has_tcp_task = upstreams.iter().any(|up| {
        let (_, t) = parse_upstream_addr(up, default_transport);
        matches!(t, Transport::Tcp | Transport::TcpUdp)
    });

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
                    let r = forward_udp_smart(&engine, &packet, &addr_owned, timeout_dur, !has_tcp_task).await;
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
                Transport::Doh => {
                    let r = engine.doh_client.send(&packet, &addr_owned, timeout_dur).await;
                    ("doh", r)
                }
                Transport::Dot => {
                    let r = engine.dot_mux.send(&packet, &addr_owned, timeout_dur).await;
                    ("dot", r)
                }
                Transport::Doq => {
                    let r = engine.doq_client.send(&packet, &addr_owned, timeout_dur).await;
                    ("doq", r)
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
    allow_tcp_fallback: bool,
) -> anyhow::Result<Bytes> {
    // 获取 TCP fallback 配置（Copy bool 值，避免持有 Guard 跨 await）
    // Get TCP fallback config (Copy bool value to avoid holding Guard across await)
    let enable_tcp_fallback = allow_tcp_fallback
        && engine.state.load().pipeline.settings.enable_tcp_fallback;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GlobalSettings;
    use crate::matcher::RuntimePipelineConfig;
    use hickory_proto::op::{Message, MessageType, Query};
    use hickory_proto::rr::{Name, RecordType};
    use rustls::crypto::ring;
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
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
        let (addr, transport) = parse_upstream_addr("https://dns.example.com/dns-query", Transport::Udp);
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
        assert_eq!(transport, Transport::Doq, "URL prefix should override default transport");

        // Simulate: { "upstream": "doh://dns.google/dns-query" } (no transport field)
        let (addr, transport) = parse_upstream_addr("doh://dns.google/dns-query", default_transport);
        assert_eq!(addr, "dns.google/dns-query");
        assert_eq!(transport, Transport::Doh, "URL prefix should override default transport");
    }

    #[test]
    fn test_doq_url_with_0rtt_parameter() {
        // Test that DoQ URLs with 0rtt parameter are parsed correctly
        // 测试带 0rtt 参数的 DoQ URL 是否正确解析

        // DoQ with 0rtt=false
        let (addr, transport) = parse_upstream_addr("doq://223.5.5.5:853?0rtt=false", Transport::Udp);
        assert_eq!(addr, "223.5.5.5:853?0rtt=false");
        assert_eq!(transport, Transport::Doq);

        // DoQ with 0rtt=true
        let (addr, transport) = parse_upstream_addr("doq://dns.google:853?0rtt=true", Transport::Udp);
        assert_eq!(addr, "dns.google:853?0rtt=true");
        assert_eq!(transport, Transport::Doq);

        // DoQ with SNI parameter
        let (addr, transport) = parse_upstream_addr("doq://dns.example.com:853?sni=dns.example.com", Transport::Udp);
        assert_eq!(addr, "dns.example.com:853?sni=dns.example.com");
        assert_eq!(transport, Transport::Doq);

        // DoQ with both 0rtt and SNI
        let (addr, transport) = parse_upstream_addr("doq://dns.example.com:853?0rtt=false&sni=dns.example.com", Transport::Udp);
        assert_eq!(addr, "dns.example.com:853?0rtt=false&sni=dns.example.com");
        assert_eq!(transport, Transport::Doq);
    }

    fn build_test_engine(enable_tcp_fallback: bool) -> Engine {
        let mut settings = GlobalSettings::default();
        settings.default_upstream = "127.0.0.1:0".to_string();
        settings.enable_tcp_fallback = enable_tcp_fallback;
        settings.udp_pool_size = 1;
        settings.tcp_pool_size = 1;
        let runtime = RuntimePipelineConfig {
            settings,
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
        };
        Engine::new(runtime, "test".to_string())
    }

    fn build_dns_query_packet(qname: &str) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        let name = Name::from_str(qname).expect("qname");
        msg.add_query(Query::query(name, RecordType::A));
        msg.to_vec().expect("encode dns query")
    }

    #[tokio::test]
    async fn udp_truncated_response_does_not_fallback_to_tcp_when_disallowed() {
        let _ = ring::default_provider().install_default();

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp");
        let tcp_addr = tcp_listener.local_addr().expect("tcp addr");

        let udp_socket = tokio::net::UdpSocket::bind(tcp_addr)
            .await
            .expect("bind udp");
        let upstream_addr = udp_socket.local_addr().expect("udp addr");

        let tcp_hits = Arc::new(AtomicUsize::new(0));
        let tcp_hits_clone = Arc::clone(&tcp_hits);
        let tcp_task = tokio::spawn(async move {
            if let Ok(Ok((mut stream, _))) = tokio::time::timeout(
                Duration::from_millis(500),
                tcp_listener.accept(),
            )
            .await
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
