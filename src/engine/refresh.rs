use std::net::IpAddr;

use hickory_proto::rr::{DNSClass, RecordType};
use tracing::{error, warn};

use crate::engine::Engine;
use crate::engine::utils::{RefreshingGuard, is_refreshing};

/// spawn_background_refresh spawns a task to refresh a DNS record in the background.
///
/// 防止无限循环的保护措施：
/// Protection against infinite loops:
/// 1. 检查 is_refreshing
/// 2. 后台请求设置 skip_cache=true
/// 3. RefreshingGuard 确保刷新标记在任务完成后被清除
///
/// `peer_ip` is the original client IP from the request that triggered this refresh.
/// It must be the real client IP — not loopback — so that:
/// - ECS injection (RFC 7871) uses the correct client subnet
/// - Pipeline selection matches the original request path
///
/// `peer_ip` 是触发刷新的原始请求的客户端 IP。
/// 必须使用真实客户端 IP 而非回环地址，以确保：
/// - ECS 注入 (RFC 7871) 使用正确的客户端子网
/// - Pipeline 选择与原始请求路径一致
pub fn spawn_background_refresh(
    engine: &Engine,
    cache_hash: u64,
    pipeline_id: &str,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    peer_ip: IpAddr,
    _upstream: Option<&str>, // Reserved for future use
) {
    // FIX: Check if already refreshing to prevent duplicate refreshes
    // 修复：检查是否已在刷新，防止重复刷新
    // OPTIMIZATION: Hybrid bloom filter + DashSet check
    // 优化：混合布隆过滤器 + DashSet 检查
    if is_refreshing(
        &engine.refreshing_bitmap,
        &engine.refreshing_set,
        cache_hash,
    ) {
        return;
    }

    // Step 1: Construct standard DNS query packet
    // 步骤 1：构造标准 DNS 查询包
    let packet = match engine.construct_dns_packet(qname, qtype, qclass) {
        Ok(pkt) => pkt,
        Err(e) => {
            error!(
                event = "background_refresh_construct_packet_failed",
                qname = %qname,
                qtype = ?qtype,
                error = %e,
                "Failed to construct DNS packet for background refresh"
            );
            return;
        }
    };

    // Step 2: Create RefreshingGuard and spawn background task
    // 步骤 2：创建 RefreshingGuard 并生成后台任务
    // RefreshingGuard will auto-clear the bitmap on drop via RAII
    // RefreshingGuard 会在 drop 时通过 RAII 自动清除位图标记
    let _guard = RefreshingGuard::new(
        &engine.refreshing_bitmap,
        &engine.refreshing_set,
        cache_hash,
    );
    let engine = engine.clone();
    let qname_owned = qname.to_string();
    let pipeline_id_owned = pipeline_id.to_string();

    tokio::spawn(async move {
        // Move guard into the async task so it clears when task completes
        // 将 guard 移动到异步任务中，这样任务完成时会清除标记
        let _guard = _guard;

        // Use original client peer IP for correct ECS injection (RFC 7871) and pipeline selection.
        // Port is irrelevant — only .ip() is consumed downstream.
        //
        // 使用原始客户端 peer IP 确保正确的 ECS 注入 (RFC 7871) 和 pipeline 选择。
        // 端口无关 — 下游仅消费 .ip()。
        let peer_addr = std::net::SocketAddr::new(peer_ip, 53);

        // Call handle_packet_internal with skip_cache=true and explicit cache_hash.
        // Together with the original peer_ip, this ensures the background refresh
        // both writes to the correct cache slot AND injects the correct ECS (RFC 7871).
        //
        // 调用 handle_packet_internal 并设置 skip_cache=true，传入显式 cache_hash。
        // 配合原始 peer_ip，确保后台刷新既写入正确的缓存槽，又注入正确的 ECS (RFC 7871)。
        let result = engine
            .handle_packet_internal(&packet, peer_addr, true, None, Some(cache_hash))
            .await;

        match result {
            Ok(_resp_bytes) => {
                warn!(
                    event = "background_refresh_success",
                    qname = %qname_owned,
                    qtype = ?qtype,
                    pipeline_id = %pipeline_id_owned,
                    "Background refresh completed successfully"
                );
            }
            Err(e) => {
                warn!(
                    event = "background_refresh_failed",
                    qname = %qname_owned,
                    qtype = ?qtype,
                    pipeline_id = %pipeline_id_owned,
                    error = %e,
                    "Background refresh failed"
                );
                // Keep the refresh marker during a short retry backoff. This reuses the existing
                // singleflight state and prevents repeated stale hits from spawning a retry storm.
                // 在短暂退避期间保留刷新标记，避免 stale 请求持续触发失败重试。
                tokio::time::sleep(std::time::Duration::from_secs(
                    engine.cache_refresh_min_ttl.max(1) as u64,
                ))
                .await;
            }
        }
        // _guard dropped here, automatically clearing the refresh mark
        // _guard 在此处 drop，自动清除刷新标记
    });
}
