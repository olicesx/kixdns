use hickory_proto::rr::{DNSClass, RecordType};
use tracing::{debug, error};

use crate::engine::Engine;
use crate::engine::utils::{is_refreshing, mark_refreshing};

/// spawn_background_refresh spawns a task to refresh a DNS record in the background.
/// 
/// 防止无限循环的保护措施：
/// Protection against infinite loops:
/// 1. 检查 is_refreshing
/// 2. 后台请求设置 skip_cache=true
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
        debug!(
            event = "background_refresh_skipped",
            qname = %qname,
            qtype = ?qtype,
            cache_hash = cache_hash,
            "Background refresh already in progress, skipping"
        );
        return;
    }

    // OPTIMIZATION: Mark as refreshing using bitmap (zero-lock write)
    // 优化：使用位图标记为正在刷新（零锁写入）
    mark_refreshing(&engine.refreshing_bitmap, cache_hash);

    // NEW DESIGN: Background refresh calls handle_packet_internal(skip_cache=true)
    // 新设计：后台刷新调用 handle_packet_internal(skip_cache=true)
    // This completely reuses the rule engine and query logic
    // 这完全重用了规则引擎和查询逻辑
    
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

    // Step 2: Call handle_packet_internal with skip_cache=true
    // 步骤 2：调用 handle_packet_internal 并设置 skip_cache=true
    let engine = engine.clone();
    let qname_owned = qname.to_string();
    let pipeline_id_owned = pipeline_id.to_string();
    
    tokio::spawn(async move {
        // Use loopback address as peer (background refresh is internal)
        // 使用回环地址作为 peer（后台刷新是内部的）
        let peer_addr = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)), 53);
        
        // Call handle_packet_internal with skip_cache=true
        // 调用 handle_packet_internal 并设置 skip_cache=true
        let result = engine.handle_packet_internal(&packet, peer_addr, true).await;
        
        match result {
            Ok(_resp_bytes) => {
                debug!(
                    event = "background_refresh_success",
                    qname = %qname_owned,
                    qtype = ?qtype,
                    pipeline_id = %pipeline_id_owned,
                    "Background refresh completed successfully"
                );
            }
            Err(e) => {
                 debug!(
                    event = "background_refresh_failed",
                    qname = %qname_owned,
                    qtype = ?qtype,
                    pipeline_id = %pipeline_id_owned,
                    error = %e,
                    "Background refresh failed"
                );
            }
        }
    });
}
