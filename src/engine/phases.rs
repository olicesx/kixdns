use std::time::{Instant, Duration};
use std::sync::Arc;
use bytes::{Bytes, BytesMut};
use hickory_proto::rr::{DNSClass, RecordType, Record};
use hickory_proto::op::{Message, ResponseCode};
use anyhow::Context;
use tracing::{debug, info, warn};
use super::Engine;
use crate::proto_utils;
use crate::cache::CacheEntry;
use crate::engine::utils::engine_helpers::{build_response, build_servfail_response_fast};
use crate::engine::utils::InflightCleanupGuard;
use crate::engine::upstream::UpstreamFailure;
use crate::matcher::{eval_match_chain, RuntimeResponseMatcherWithOp};
use crate::config::{MatchOperator, Action, Transport};
use crate::engine::rules::{self, ResponseContext, ResponseActionResult};
use crate::engine::response::{extract_ttl, extract_ttl_for_refresh};

/// Result of the Forward phase
pub enum ForwardResult {
    /// Request completed with a response (bytes)
    Success(Bytes),
    /// Request needs to continue (e.g. Action::Continue)
    /// Boxed to reduce enum size (ResponseContext is ~256 bytes)
    Continue(Box<Option<ResponseContext>>),
}
use hickory_proto::serialize::binary::BinDecodable;

/// Standard cache check logic that replicates `handle_packet_internal`'s behavior.
/// Checks Moka cache, validates TTL, patches response, and triggers background refresh if needed.
pub fn check_cache(
    engine: &Engine,
    qname_ref: &str,
    qtype: RecordType,
    qclass: DNSClass,
    pipeline_id: &str,
    dedupe_hash: u64,
    tx_id: u16,
    start: Instant,
    peer: &std::net::SocketAddr,
) -> Option<Bytes> {
    // moka 同步缓存自动处理过期，无需检查 expires_at / moka sync cache automatically handles expiration, no need to check expires_at
    if let Some(hit) = engine.cache.get(&dedupe_hash) {
        // Validate hit against query parameters to avoid collisions
        if hit.qtype == u16::from(qtype) && hit.pipeline_id.as_ref() == pipeline_id && hit.qname.as_ref() == qname_ref {
            let elapsed_secs = hit.inserted_at.elapsed().as_secs();
            
            // Check manual expiration (in case moka hasn't evicted it yet or for strict TTL compliance)
            if elapsed_secs >= hit.original_ttl as u64 {
                // serve_stale disabled → invalidate and miss
                if !engine.serve_stale {
                    engine.cache.invalidate(&dedupe_hash);
                    return None;
                }
                // Don't serve SERVFAIL/REFUSED as stale
                if hit.rcode == ResponseCode::ServFail || hit.rcode == ResponseCode::Refused {
                    engine.cache.invalidate(&dedupe_hash);
                    return None;
                }
                
                // Check serve_stale_expire_ttl: how long past original TTL has this been stale?
                // 检查 serve_stale_expire_ttl：此条目已过期多长时间？
                let stale_age = elapsed_secs - hit.original_ttl as u64;
                if engine.serve_stale_expire_ttl > 0 && stale_age > engine.serve_stale_expire_ttl {
                    // Stale entry has exceeded the maximum stale window
                    // 过期条目已超过最大过期窗口
                    engine.cache.invalidate(&dedupe_hash);
                    debug!(
                        event = "serve_stale_expired",
                        qname = %qname_ref,
                        qtype = ?qtype,
                        stale_age = stale_age,
                        serve_stale_expire_ttl = engine.serve_stale_expire_ttl,
                        "stale entry exceeded serve_stale_expire_ttl, invalidating"
                    );
                    return None;
                }
                
                // serve_stale_client_timeout_ms > 0: don't serve stale here, let the caller
                // try upstream first with a short timeout (handled in handle_packet_internal).
                // serve_stale_client_timeout_ms > 0: 不在此处返回 stale，
                // 让调用者先尝试上游查询（在 handle_packet_internal 中处理）。
                if engine.serve_stale_client_timeout_ms > 0 {
                    // Don't invalidate - we still need the stale entry for the client_timeout path.
                    // Spawn background refresh proactively.
                    if let Some(upstream_ref) = hit.upstream.as_deref() {
                        engine.spawn_background_refresh(
                            dedupe_hash,
                            pipeline_id,
                            qname_ref,
                            qtype,
                            qclass,
                            Some(upstream_ref),
                        );
                    }
                    return None;
                }

                // serve_stale_client_timeout_ms == 0: Serve stale immediately (optimistic mode)
                // RFC 8767: 立即返回 stale 数据 + 后台刷新
                let stale_ttl = engine.serve_stale_ttl;
                let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);
                
                // Set all TTLs to serve_stale_ttl
                crate::proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl);
                
                // Rewrite Transaction ID
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }
                
                // serve_stale_ttl_reset: reset stale expiry timer by re-inserting with shifted inserted_at
                // 重置过期计时器：通过重新插入条目并将 inserted_at 设置为"刚过期"的时间点
                if engine.serve_stale_ttl_reset {
                    let new_entry = crate::cache::CacheEntry {
                        bytes: hit.bytes.clone(),
                        rcode: hit.rcode,
                        source: hit.source.clone(),
                        upstream: hit.upstream.clone(),
                        qname: hit.qname.clone(),
                        pipeline_id: hit.pipeline_id.clone(),
                        qtype: hit.qtype,
                        // Reset inserted_at so that stale_age starts from 0 again
                        // 重置 inserted_at 使 stale_age 从 0 重新开始
                        inserted_at: Instant::now() - Duration::from_secs(hit.original_ttl as u64),
                        original_ttl: hit.original_ttl,
                        refresh_ttl: hit.refresh_ttl,
                    };
                    engine.cache.insert(dedupe_hash, std::sync::Arc::new(new_entry));
                }

                // Trigger background refresh to get fresh data
                if let Some(upstream_ref) = hit.upstream.as_deref() {
                    engine.spawn_background_refresh(
                        dedupe_hash,
                        pipeline_id,
                        qname_ref,
                        qtype,
                        qclass,
                        Some(upstream_ref),
                    );
                }
                
                debug!(
                    event = "serve_stale_on_ttl_expiry",
                    qname = %qname_ref,
                    qtype = ?qtype,
                    rcode = ?hit.rcode,
                    original_ttl = hit.original_ttl,
                    elapsed_secs = elapsed_secs,
                    stale_ttl = stale_ttl,
                    stale_age = stale_age,
                    ttl_reset = engine.serve_stale_ttl_reset,
                    client_ip = %peer.ip(),
                    pipeline = %pipeline_id,
                    "RFC 8767: serving stale cache entry on TTL expiry"
                );
                
                return Some(resp_bytes.freeze());
            } else {
                // Cache hit is valid
                let latency = start.elapsed();
                
                // clone bytes and rewrite transaction ID to match requester / 克隆字节并重写事务 ID 以匹配请求者
                let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);

                // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                let elapsed = elapsed_secs as u32;
                if elapsed > 0 {
                    crate::proto_utils::patch_all_ttls(&mut resp_bytes, elapsed);
                }

                // Rewrite Transaction ID
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }
                let resp_bytes = resp_bytes.freeze();
                
                // ========== NEW: Trigger background refresh before returning cached response ==========
                let cfg = &engine.state.load().pipeline;
                
                let remaining_ttl = hit.refresh_ttl.saturating_sub(elapsed);
                
                // Check if we should trigger background refresh
                let should_refresh = if cfg.settings.cache_background_refresh
                    && hit.upstream.is_some()
                    && hit.refresh_ttl >= cfg.settings.cache_refresh_min_ttl
                {
                    let threshold = (hit.refresh_ttl as u64 * cfg.settings.cache_refresh_threshold_percent as u64) / 100;
                    remaining_ttl as u64 <= threshold
                } else {
                    false
                };

                if should_refresh {
                    // Trigger background refresh asynchronously
                    debug!(
                        event = "cache_background_refresh_trigger",
                        qname = %qname_ref,
                        qtype = ?qtype,
                        remaining_ttl = remaining_ttl,
                        original_ttl = hit.original_ttl,
                        refresh_ttl = hit.refresh_ttl,
                        "Triggering background refresh for cached entry"
                    );
                    
                    engine.spawn_background_refresh(
                        dedupe_hash,
                        pipeline_id,
                        qname_ref,
                        qtype,
                        qclass,
                        hit.upstream.as_deref(), // Pass upstream if available
                    );
                }

                debug!(
                    event = "dns_response",
                    upstream = %hit.source,
                    qname = %qname_ref,
                    qtype = ?qtype,
                    rcode = ?hit.rcode,
                    original_ttl = hit.original_ttl,
                    refresh_ttl = hit.refresh_ttl,
                    elapsed_secs = elapsed,
                    latency_ms = latency.as_millis() as u64,
                    client_ip = %peer.ip(),
                    pipeline = %pipeline_id,
                    cache = true,
                    "cache hit"
                );

                return Some(resp_bytes);
            }
        }
    }
    None
}

/// RFC 8767: Check if a stale (expired but still in moka) cache entry exists.
/// Returns the stale response bytes with TTL set to serve_stale_ttl.
/// RFC 8767: 检查是否存在过期但仍在 moka 中的缓存条目。
/// 返回 TTL 设置为 serve_stale_ttl 的过期响应字节。
pub fn check_stale_cache(
    engine: &Engine,
    qname_ref: &str,
    qtype: RecordType,
    qclass: DNSClass,
    pipeline_id: &str,
    dedupe_hash: u64,
    tx_id: u16,
    peer: &std::net::SocketAddr,
) -> Option<Bytes> {
    if !engine.serve_stale {
        return None;
    }

    if let Some(hit) = engine.cache.get(&dedupe_hash) {
        if hit.qtype == u16::from(qtype)
            && hit.pipeline_id.as_ref() == pipeline_id
            && hit.qname.as_ref() == qname_ref
        {
            let elapsed_secs = hit.inserted_at.elapsed().as_secs();

            // Only serve stale when TTL has actually expired
            // 仅当 TTL 已过期时才提供 stale 数据
            if elapsed_secs >= hit.original_ttl as u64 {
                // Don't serve SERVFAIL/REFUSED as stale / 不提供 SERVFAIL/REFUSED 作为 stale
                if hit.rcode == ResponseCode::ServFail || hit.rcode == ResponseCode::Refused {
                    return None;
                }

                // Check serve_stale_expire_ttl: max stale age window
                // 检查 serve_stale_expire_ttl：过期数据的最大可用窗口
                let stale_age = elapsed_secs - hit.original_ttl as u64;
                if engine.serve_stale_expire_ttl > 0 && stale_age > engine.serve_stale_expire_ttl {
                    return None;
                }

                let stale_ttl = engine.serve_stale_ttl;

                let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);

                // RFC 8767 §4: Set all TTLs to serve_stale_ttl
                crate::proto_utils::set_all_ttls(&mut resp_bytes, stale_ttl);

                // Rewrite Transaction ID
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }

                // serve_stale_ttl_reset: reset stale expiry timer
                // 重置过期计时器
                if engine.serve_stale_ttl_reset {
                    let new_entry = crate::cache::CacheEntry {
                        bytes: hit.bytes.clone(),
                        rcode: hit.rcode,
                        source: hit.source.clone(),
                        upstream: hit.upstream.clone(),
                        qname: hit.qname.clone(),
                        pipeline_id: hit.pipeline_id.clone(),
                        qtype: hit.qtype,
                        inserted_at: Instant::now() - Duration::from_secs(hit.original_ttl as u64),
                        original_ttl: hit.original_ttl,
                        refresh_ttl: hit.refresh_ttl,
                    };
                    engine.cache.insert(dedupe_hash, std::sync::Arc::new(new_entry));
                }

                debug!(
                    event = "serve_stale",
                    qname = %qname_ref,
                    qtype = ?qtype,
                    rcode = ?hit.rcode,
                    original_ttl = hit.original_ttl,
                    elapsed_secs = elapsed_secs,
                    stale_age = stale_age,
                    stale_ttl = stale_ttl,
                    client_ip = %peer.ip(),
                    pipeline = %pipeline_id,
                    "RFC 8767: serving stale cache entry on upstream failure"
                );

                // Also trigger background refresh to try to get fresh data
                // 同时触发后台刷新以尝试获取新数据
                if let Some(upstream_ref) = hit.upstream.as_deref() {
                    engine.spawn_background_refresh(
                        dedupe_hash,
                        pipeline_id,
                        qname_ref,
                        qtype,
                        qclass,
                        Some(upstream_ref),
                    );
                }

                return Some(resp_bytes.freeze());
            }
        }
    }
    None
}



/// Handles Decision::Static.
/// Parses request, builds response, updates cache, and returns bytes.
pub fn handle_static_decision(
    engine: &Engine,
    packet: &[u8],
    qname: &str,
    qtype: RecordType,
    current_pipeline_id: &Arc<str>,
    dedupe_hash: u64,
    min_ttl: Duration,
    start: Instant,
    peer: &std::net::SocketAddr,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> anyhow::Result<Bytes> {
    // Need full request for building response / 需要完整请求来构建响应
    let req = Message::from_bytes(packet).context("parse request for static")?;
    let resp_bytes = build_response(&req, rcode, answers)?;
    
    if min_ttl > Duration::from_secs(0) {
        let entry = CacheEntry {
            bytes: resp_bytes.clone(),
            rcode,
            source: Arc::from("static"),
            upstream: None,  // Static responses have no upstream
            qname: Arc::from(qname),
            pipeline_id: current_pipeline_id.clone(),
            qtype: u16::from(qtype),
            inserted_at: Instant::now(),
            original_ttl: min_ttl.as_secs() as u32,
            refresh_ttl: min_ttl.as_secs() as u32,
        };
        engine.cache.insert(dedupe_hash, Arc::new(entry));
    }
    
    let latency = start.elapsed();
    info!(
        event = "dns_response",
        upstream = "static",
        qname = %qname,
        qtype = ?qtype,
        rcode = ?rcode,
        latency_ms = latency.as_millis() as u64,
        client_ip = %peer.ip(),
        pipeline = %current_pipeline_id,
        cache = false,
        "static response"
    );
    Ok(resp_bytes)
}

/// Handles Decision::Forward.
/// Manages Singleflight, upstream forwarding, response matching, and caching.
#[allow(clippy::too_many_arguments)]
pub async fn handle_forward_decision(
    engine: &Engine,
    packet: &[u8],
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    tx_id: u16,
    pipeline_id: &str,
    rule_name: &str,
    dedupe_hash: u64,
    min_ttl: Duration,
    upstream_timeout: Duration,
    start: Instant,
    peer: &std::net::SocketAddr,
    skip_cache: bool,
    // Decision fields
    upstream: &str,
    pre_split_upstreams: Option<&Arc<Vec<Arc<str>>>>,
    response_matchers: &[RuntimeResponseMatcherWithOp],
    _response_matcher_operator: MatchOperator,
    response_actions_on_match: &[Action],
    response_actions_on_miss: &[Action],
    transport: Option<Transport>,
    allow_reuse: bool,
    reused_response: &mut Option<ResponseContext>,
) -> anyhow::Result<ForwardResult> {
    let mut cleanup_guard = None;

    let resp = if allow_reuse {
        if let Some(ctx) = reused_response.take() {
            Ok((ctx.raw, ctx.upstream.to_string()))
        } else {
            if !skip_cache {
                use dashmap::mapref::entry::Entry;
                let rx = match engine.inflight.entry(dedupe_hash) {
                    Entry::Vacant(entry) => {
                        let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                        entry.insert(tx);
                        cleanup_guard = Some(InflightCleanupGuard::new(engine.inflight.clone(), dedupe_hash));
                        None
                    }
                    Entry::Occupied(entry) => {
                        let rx = entry.get().subscribe();
                        Some(rx)
                    }
                };

                if let Some(mut rx) = rx {
                    if let Ok(_) = rx.changed().await {
                        let result = rx.borrow().clone();
                        match &result {
                            Ok(bytes) => {
                                let mut resp_mut = BytesMut::from(bytes.as_ref());
                                if resp_mut.len() >= 2 {
                                    let id_bytes = tx_id.to_be_bytes();
                                    resp_mut[0] = id_bytes[0];
                                    resp_mut[1] = id_bytes[1];
                                }
                                return Ok(ForwardResult::Success(resp_mut.freeze()));
                            }
                            Err(e) => return Err(anyhow::anyhow!("{}", e)),
                        }
                    }
                }
            }
            crate::engine::upstream::forward_upstream(engine, packet, upstream, upstream_timeout, transport, pre_split_upstreams).await
        }
    } else {
        if !skip_cache {
            use dashmap::mapref::entry::Entry;
             let rx = match engine.inflight.entry(dedupe_hash) {
                Entry::Vacant(entry) => {
                    let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                    entry.insert(tx);
                    cleanup_guard = Some(InflightCleanupGuard::new(engine.inflight.clone(), dedupe_hash));
                    None
                }
                Entry::Occupied(entry) => {
                    let rx = entry.get().subscribe();
                    Some(rx)
                }
            };


            if let Some(mut rx) = rx {
                if let Ok(_) = rx.changed().await {
                    let result = rx.borrow().clone();
                    match &result {
                        Ok(bytes) => {
                            let mut resp_mut = BytesMut::from(bytes.as_ref());
                            if resp_mut.len() >= 2 {
                                let id_bytes = tx_id.to_be_bytes();
                                resp_mut[0] = id_bytes[0];
                                resp_mut[1] = id_bytes[1];
                            }
                            return Ok(ForwardResult::Success(resp_mut.freeze()));
                        }
                        Err(e) => return Err(anyhow::anyhow!("{}", e)),
                    }
                }
            }
        }
        crate::engine::upstream::forward_upstream(engine, packet, upstream, upstream_timeout, transport, pre_split_upstreams).await
    };

    match resp {
        Ok((raw, actual_upstream)) => {
            let (rcode, ttl_secs_cache, ttl_secs_refresh, msg_opt, truncated) = if response_matchers.is_empty() && response_actions_on_match.is_empty() && response_actions_on_miss.is_empty() {
                if let Some(qr) = proto_utils::parse_response_quick(&raw) {
                    (qr.rcode, qr.min_ttl as u64, qr.max_ttl as u64, None, qr.truncated)
                } else {
                    let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                    let ttl_cache = extract_ttl(&msg);
                    let ttl_refresh = extract_ttl_for_refresh(&msg);
                    let tc = raw.len() >= 3 && (raw[2] & 0x02) != 0;
                    (msg.response_code(), ttl_cache, ttl_refresh, Some(msg), tc)
                }
            } else {
                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                let ttl_cache = extract_ttl(&msg);
                let ttl_refresh = extract_ttl_for_refresh(&msg);
                let tc = raw.len() >= 3 && (raw[2] & 0x02) != 0;
                (msg.response_code(), ttl_cache, ttl_refresh, Some(msg), tc)
            };

            // 检查 TCP fallback 配置 / Check TCP fallback configuration
            let enable_tcp_fallback = engine.state.load().pipeline.settings.enable_tcp_fallback;
            if truncated && transport == Some(Transport::Udp) && enable_tcp_fallback {
                tracing::debug!(event = "tc_flag_retry", upstream = %upstream, "response truncated, retrying with tcp");
                drop(cleanup_guard);
                let (tcp_resp, _) = crate::engine::upstream::forward_upstream(engine, packet, upstream, upstream_timeout, Some(Transport::Tcp), pre_split_upstreams).await?;
                if let Some(_g) = engine.inflight.get(&dedupe_hash) {
                    engine.notify_inflight_waiters(dedupe_hash, &tcp_resp).await;
                }
                return Ok(ForwardResult::Success(tcp_resp));
            }

            let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));

            // Try to acquire read locks non-blockingly (fast path for concurrent reads)
            // 尝试非阻塞获取读锁（并发读的快速路径）
            let (resp_match_ok, msg) = {
                let mut geoip_manager = engine.geoip_manager.try_read();
                let mut geosite_manager = engine.geosite_manager.try_read();

                // Fallback to blocking read if try_read fails (rare write operation in progress)
                // 如果 try_read 失败则回退到阻塞读取（罕见的写操作进行中）
                if geoip_manager.is_none() || geosite_manager.is_none() {
                    tracing::debug!("GeoIP/GeoSite lock contention, falling back to blocking read");
                    geoip_manager = Some(engine.geoip_manager.read());
                    geosite_manager = Some(engine.geosite_manager.read());
                }

                let geoip_manager_ref = geoip_manager.as_deref();
                let geosite_manager_ref = geosite_manager.as_deref();

                if let Some(m) = msg_opt {
                    if skip_cache {
                        (true, m)
                    } else {
                        let matched = eval_match_chain(
                            response_matchers,
                            |m| m.operator,
                            |matcher_op| matcher_op.matcher.matches(upstream, qname, qtype, qclass, &m, geoip_manager_ref, geosite_manager_ref),
                        );
                        (matched, m)
                    }
                } else {
                    (false, Message::new())
                }
            };

            let empty_actions = Vec::new();
            let actions_to_run = if skip_cache {
                &empty_actions
            } else if !response_actions_on_match.is_empty() || !response_actions_on_miss.is_empty() {
                if resp_match_ok {
                    response_actions_on_match
                } else {
                    response_actions_on_miss
                }
            } else {
                &empty_actions
            };

            if actions_to_run.is_empty() {
                if effective_ttl > Duration::from_secs(0) {
                    engine.insert_dns_cache_entry(
                        dedupe_hash,
                        raw.clone(),
                        rcode,
                        Arc::from(actual_upstream.as_str()),
                        Some(Arc::from(actual_upstream.as_str())),
                        qname,
                        Arc::from(pipeline_id),
                        qtype,
                        ttl_secs_cache as u32,
                        ttl_secs_refresh as u32,
                    );
                }
                if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                engine.notify_inflight_waiters(dedupe_hash, &raw).await;
                
                info!(
                    event = "dns_response",
                    upstream = %actual_upstream,
                    qname = %qname,
                    qtype = ?qtype,
                    rcode = ?rcode,
                    latency_ms = start.elapsed().as_millis() as u64,
                    client_ip = %peer.ip(),
                    pipeline = %pipeline_id,
                    cache = effective_ttl > Duration::from_secs(0),
                    resp_match = resp_match_ok,
                    transport = ?transport,
                    "forwarded"
                );
                
                return Ok(ForwardResult::Success(raw));
            }
            
            // Handle Actions
            let req_full = if let Ok(r) = Message::from_bytes(packet) { r } else { Message::new() };
            let ctx = ResponseContext {
                raw: raw.clone(),
                msg,
                upstream: Arc::from(actual_upstream.as_str()),
                transport: transport.unwrap_or(Transport::Udp),
            };

            let state = engine.state.load(); // Load state for config access
            let default_upstream = state.pipeline.settings.default_upstream.as_str();
            let response_jump_limit = state.pipeline.settings.response_jump_limit as usize;

            let ctx = rules::ApplyResponseActionsContext {
                engine,
                actions: actions_to_run,
                ctx_opt: Some(ctx),
                req: &req_full,
                packet,
                upstream_timeout,
                response_matchers,
                qname,
                qtype,
                qclass,
                client_ip: peer.ip(),
                upstream_default: default_upstream,
                pipeline_id,
                rule_name,
                remaining_jumps: response_jump_limit,
            };

            let action_result = rules::apply_response_actions(ctx).await?;

            match action_result {
                ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                    let ttl_secs_cache = extract_ttl(&ctx.msg); 
                    let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                    let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));
                     if effective_ttl > Duration::from_secs(0) {
                        engine.insert_dns_cache_entry(
                            dedupe_hash,
                            ctx.raw.clone(),
                            ctx.msg.response_code(),
                            ctx.upstream.clone(),
                            Some(ctx.upstream.clone()),
                            qname,
                            Arc::from(pipeline_id),
                            qtype,
                            ttl_secs_cache as u32,
                            ttl_secs_refresh as u32,
                        );
                    }
                    if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                    engine.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                    Ok(ForwardResult::Success(ctx.raw))
                },
                ResponseActionResult::Static { bytes, rcode, source } => {
                    if min_ttl > Duration::from_secs(0) {
                        engine.insert_dns_cache_entry(
                            dedupe_hash,
                            bytes.clone(),
                            rcode,
                            Arc::from(source),
                            None,
                            qname,
                            Arc::from(pipeline_id),
                            qtype,
                            min_ttl.as_secs() as u32,
                            min_ttl.as_secs() as u32,
                        );
                    }
                    if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                    engine.notify_inflight_waiters(dedupe_hash, &bytes).await;
                    Ok(ForwardResult::Success(bytes))
                },
                ResponseActionResult::Jump { pipeline, remaining_jumps } => {
                     let edns_present = proto_utils::parse_quick(packet, &mut [0u8; 256]).map(|p| p.edns_present).unwrap_or(false);
                     
                     let resp_bytes = rules::process_response_jump(
                        engine,
                        &state,
                        pipeline,
                        remaining_jumps,
                        &req_full,
                        packet,
                        *peer,
                        qname,
                        qtype,
                        qclass,
                        edns_present,
                        min_ttl,
                        upstream_timeout,
                        skip_cache
                     ).await?;
                     
                     if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                     engine.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                     Ok(ForwardResult::Success(resp_bytes))
                },
                ResponseActionResult::Continue { ctx } => {
                    if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                    Ok(ForwardResult::Continue(Box::new(ctx)))
                }
            }
        }
        Err(e) => {
             if response_actions_on_miss.is_empty() {
                 // Only send SERVFAIL when upstream attempts are fully exhausted.
                 // 仅在所有上游尝试都耗尽时发送 SERVFAIL。
                 if e.downcast_ref::<UpstreamFailure>().is_none() {
                     return Err(e);
                 }

                 // RFC 8767: Try to serve stale cache entry before returning SERVFAIL
                 // RFC 8767: 在返回 SERVFAIL 之前尝试提供过期缓存
                 if let Some(stale_bytes) = check_stale_cache(
                     engine,
                     qname,
                     qtype,
                     qclass,
                     pipeline_id,
                     dedupe_hash,
                     tx_id,
                     peer,
                 ) {
                     warn!(
                         event = "serve_stale_on_upstream_failure",
                         upstream = %upstream,
                         qname = %qname,
                         qtype = ?qtype,
                         client_ip = %peer.ip(),
                         pipeline = %pipeline_id,
                         error = %e,
                         "RFC 8767: upstream failed, serving stale cache"
                     );
                     if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                     engine.notify_inflight_waiters(dedupe_hash, &stale_bytes).await;
                     return Ok(ForwardResult::Success(stale_bytes));
                 }

                 let rcode = ResponseCode::ServFail;
                 warn!(
                    event = "dns_response",
                    upstream = %upstream,
                    qname = %qname,
                    qtype = ?qtype,
                    rcode = ?rcode,
                    client_ip = %peer.ip(),
                    error = %e,
                    pipeline = %pipeline_id,
                    transport = ?transport,
                    "upstream failed"
                 );
                 // Fast build SERVFAIL without full request parse
                 let rd = packet.get(2).map(|b| b & 0x01 != 0).unwrap_or(false);
                 let resp_bytes = match build_servfail_response_fast(
                     tx_id,
                     qname,
                     u16::from(qtype),
                     u16::from(qclass),
                     rd,
                 ) {
                     Ok(bytes) => bytes,
                     Err(_) => {
                         // Fallback to full parse if fast build fails
                         let req = match Message::from_bytes(packet) {
                             Ok(r) => r,
                             Err(_) => return Err(e),
                         };
                         build_response(&req, rcode, Vec::new()).unwrap_or_default()
                     }
                 };

                 if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                 engine.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                 
                 Ok(ForwardResult::Success(resp_bytes))
             } else {
                 let req = match Message::from_bytes(packet) {
                     Ok(r) => r,
                     Err(_) => return Err(e),
                 };
                 let state = engine.state.load();
                 let default_upstream = state.pipeline.settings.default_upstream.as_str();
                 let response_jump_limit = state.pipeline.settings.response_jump_limit as usize;

                 let ctx = rules::ApplyResponseActionsContext {
                     engine,
                     actions: response_actions_on_miss,
                     ctx_opt: None,
                     req: &req,
                     packet,
                     upstream_timeout,
                     response_matchers,
                     qname,
                     qtype,
                     qclass,
                     client_ip: peer.ip(),
                     upstream_default: default_upstream,
                     pipeline_id,
                     rule_name,
                     remaining_jumps: response_jump_limit,
                 };
                 let action_result = rules::apply_response_actions(ctx).await?;

                match action_result {
                    ResponseActionResult::Upstream { ctx, resp_match: _ } => {
                        let ttl_secs_cache = extract_ttl(&ctx.msg); 
                        let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                        let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));
                        if effective_ttl > Duration::from_secs(0) {
                            engine.insert_dns_cache_entry(
                                dedupe_hash,
                                ctx.raw.clone(),
                                ctx.msg.response_code(),
                                ctx.upstream.clone(),
                                Some(ctx.upstream.clone()),
                                qname,
                                Arc::from(pipeline_id),
                                qtype,
                                ttl_secs_cache as u32,
                                ttl_secs_refresh as u32,
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                        engine.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                        Ok(ForwardResult::Success(ctx.raw))
                    },
                    ResponseActionResult::Static { bytes, rcode, source } => {
                        if min_ttl > Duration::from_secs(0) {
                            engine.insert_dns_cache_entry(
                                dedupe_hash,
                                bytes.clone(),
                                rcode,
                                Arc::from(source),
                                None,
                                qname,
                                Arc::from(pipeline_id),
                                qtype,
                                min_ttl.as_secs() as u32,
                                min_ttl.as_secs() as u32,
                            );
                        }
                        if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                        engine.notify_inflight_waiters(dedupe_hash, &bytes).await;
                        Ok(ForwardResult::Success(bytes))
                    },
                    ResponseActionResult::Jump { pipeline, remaining_jumps } => {
                        let edns_present = proto_utils::parse_quick(packet, &mut [0u8; 256]).map(|p| p.edns_present).unwrap_or(false);
                        let req = if let Ok(r) = Message::from_bytes(packet) { r } else { Message::new() };

                        let resp_bytes = rules::process_response_jump(
                            engine,
                            &state,
                            pipeline,
                            remaining_jumps,
                            &req,
                            packet,
                            *peer,
                            qname,
                            qtype,
                            qclass,
                            edns_present,
                            min_ttl,
                            upstream_timeout,
                            skip_cache
                        ).await?;
                        
                        if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                        engine.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                        Ok(ForwardResult::Success(resp_bytes))
                    },
                    ResponseActionResult::Continue { ctx } => {
                        Ok(ForwardResult::Continue(Box::new(ctx)))
                    }
                }
             }
        }
    }
}
