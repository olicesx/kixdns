use hickory_proto::rr::{DNSClass, RecordType};
use tracing::{warn, error};

use crate::engine::Engine;
use crate::engine::utils::{is_refreshing, RefreshingGuard};

/// spawn_background_refresh spawns a task to refresh a DNS record in the background.
///
/// 防止无限循环的保护措施：
/// Protection against infinite loops:
/// 1. 检查 is_refreshing
/// 2. 后台请求设置 skip_cache=true
/// 3. RefreshingGuard 确保刷新标记在任务完成后被清除
pub fn spawn_background_refresh(
    engine: &Engine,
    cache_hash: u64,
    pipeline_id: &str,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    _upstream: Option<&str>,  // Reserved for future use
) {
    // FIX: Check if already refreshing to prevent duplicate refreshes
    // 修复：检查是否已在刷新，防止重复刷新
    // OPTIMIZATION: Zero-lock check using bitmap
    // 优化：使用位图进行零锁检查
    if is_refreshing(&engine.refreshing_bitmap, cache_hash) {
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
    let _guard = RefreshingGuard::new(&engine.refreshing_bitmap, cache_hash);
    let engine = engine.clone();
    let qname_owned = qname.to_string();
    let pipeline_id_owned = pipeline_id.to_string();

    tokio::spawn(async move {
        // Move guard into the async task so it clears when task completes
        // 将 guard 移动到异步任务中，这样任务完成时会清除标记
        let _guard = _guard;

        // Use loopback address as peer (background refresh is internal)
        // 使用回环地址作为 peer（后台刷新是内部的）
        let peer_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 53);

        // Call handle_packet_internal with skip_cache=true
        // 调用 handle_packet_internal 并设置 skip_cache=true
        let result = engine.handle_packet_internal(&packet, peer_addr, true).await;

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
            }
        }
        // _guard dropped here, automatically clearing the refresh mark
        // _guard 在此处 drop，自动清除刷新标记
    });
}
