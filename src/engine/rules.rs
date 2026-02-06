use std::sync::Arc;
use std::time::{Duration, Instant};
use std::net::{IpAddr, SocketAddr};
use std::hash::{Hash, Hasher};
use std::collections::HashSet;
use bytes::{Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Record, RecordType, DNSClass, RData};
use hickory_proto::rr::rdata::TXT;
use hickory_proto::serialize::binary::BinDecodable;
use rustc_hash::FxHasher;
use tracing::warn;
use anyhow::Context;

use crate::config::{Action, Transport};
use crate::matcher::RuntimeResponseMatcherWithOp;
use crate::engine::core::Engine;
use crate::engine::types::EngineInner;
use crate::engine::types::InflightMap;
use crate::engine::utils::engine_helpers::{self, build_response};
use crate::engine::response::{make_static_ip_answer, make_static_txt_answer, extract_ttl, extract_ttl_for_refresh};
use crate::engine::matcher_adapter::log_match;
use crate::matcher::eval_match_chain;
use crate::cache::CacheEntry;

#[derive(Debug, Clone)]
pub enum Decision {
    Static {
        rcode: ResponseCode,
        answers: Vec<Record>,
    },
    Forward {
        upstream: Arc<str>,
        /// Pre-split upstream list (performance optimization) / 预分割的 upstream 列表（性能优化）
        #[allow(dead_code)]
        pre_split_upstreams: Option<std::sync::Arc<Vec<std::sync::Arc<str>>>>,
        response_matchers: Vec<RuntimeResponseMatcherWithOp>,
        response_matcher_operator: crate::config::MatchOperator,
        response_actions_on_match: Vec<Action>,
        response_actions_on_miss: Vec<Action>,
        rule_name: Arc<str>,
        transport: Option<Transport>, // None means each upstream decides itself (via protocol prefix) / None 表示每个 upstream 自己决定（通过协议前缀）
        #[allow(dead_code)]
        continue_on_match: bool,
        #[allow(dead_code)]
        continue_on_miss: bool,
        allow_reuse: bool,
    },
    Jump {
        pipeline: Arc<str>,
    },
}

#[derive(Clone, Debug)]
pub struct ResponseContext {
    pub raw: Bytes,
    pub msg: Message,
    pub upstream: Arc<str>,
    pub transport: Transport,
}

#[derive(Debug)]
pub enum ResponseActionResult {
    Upstream {
        ctx: ResponseContext,
        resp_match: bool,
    },
    Static {
        bytes: Bytes,
        rcode: ResponseCode,
        source: &'static str,
    },
    Jump {
        pipeline: Arc<str>,
        remaining_jumps: usize,
    },
    Continue {
        ctx: Option<ResponseContext>,
    },
}

#[inline]
pub fn calculate_rule_hash(
    pipeline_id: &str,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    client_ip: IpAddr,
    uses_client_ip: bool,
) -> u64 {
    let mut hasher = FxHasher::default();
    pipeline_id.hash(&mut hasher);
    qname.hash(&mut hasher);
    u16::from(qtype).hash(&mut hasher);
    u16::from(qclass).hash(&mut hasher);
    if uses_client_ip {
        client_ip.hash(&mut hasher);
    }
    hasher.finish()
}

#[derive(Clone)]
pub struct RuleCacheEntry {
    pub pipeline_id: Arc<str>,
    pub qname_hash: u64,
    pub qtype: u16,
    pub qclass: u16,
    pub client_ip: Option<IpAddr>,
    pub decision: Arc<Decision>,
    /// Expiration time based on DNS TTL / 基于 DNS TTL 的过期时间
    pub expires_at: Option<Instant>,
}

impl RuleCacheEntry {
    pub fn new(
        pipeline_id: Arc<str>,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        client_ip: IpAddr,
        decision: Decision,
        uses_client_ip: bool,
    ) -> Self {
        Self {
            pipeline_id,
            qname_hash: fast_hash_str(qname),
            qtype: u16::from(qtype),
            qclass: u16::from(qclass),
            client_ip: if uses_client_ip { Some(client_ip) } else { None },
            decision: Arc::new(decision),
            expires_at: None,
        }
    }

    #[inline]
    pub fn matches(
        &self,
        pipeline_id: &str,
        qname: &str,
        qtype: RecordType,
        qclass: DNSClass,
        client_ip: IpAddr,
        uses_client_ip: bool,
    ) -> bool {
        // Check expiration first / 首先检查过期
        if let Some(expires) = self.expires_at {
            if Instant::now() > expires {
                return false;
            }
        }

        if self.qtype != u16::from(qtype) || self.qclass != u16::from(qclass) {
            return false;
        }

        if uses_client_ip {
            if self.client_ip != Some(client_ip) {
                return false;
            }
        } else if self.client_ip.is_some() {
            // Entry has IP but we don't care now? 
            // This case shouldn't happen if we use the same uses_client_ip for both hash and entry.
            return false;
        }

        self.pipeline_id.as_ref() == pipeline_id
            && self.qname_hash == fast_hash_str(qname)
    }

    /// Check if entry is still valid (not expired)
    /// 检查条目是否仍然有效（未过期）
    #[inline]
    pub fn is_valid(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Instant::now() <= expires
        } else {
            true  // No expiration = permanent
        }
    }
}

#[inline]
pub fn fast_hash_str(s: &str) -> u64 {
    let mut h = FxHasher::default();
    s.hash(&mut h);
    h.finish()
}

/// 辅助函数：获取 GeoIP 和 GeoSite 锁（带非阻塞快速路径）
/// Helper function: Acquire GeoIP and GeoSite locks (with non-blocking fast path)
/// 
/// 优化：消除重复的锁获取逻辑 / Optimization: Eliminate duplicate lock acquisition logic
#[inline]
fn acquire_geo_locks<'a>(
    engine: &'a Engine,
) -> (
    Option<crate::lock::RwLockReadGuard<'a, crate::matcher::geoip::GeoIpManager>>,
    Option<crate::lock::RwLockReadGuard<'a, crate::matcher::geosite::GeoSiteManager>>,
) {
    // Try to acquire read locks non-blockingly (fast path for concurrent reads)
    // 尝试非阻塞获取读锁（并发读的快速路径）
    let mut geoip_manager = engine.geoip_manager.try_read();
    let mut geosite_manager = engine.geosite_manager.try_read();

    // Fallback to blocking read if try_read fails (rare write operation in progress)
    // 如果 try_read 失败则回退到阻塞读取（罕见的写操作进行中）
    if geoip_manager.is_none() || geosite_manager.is_none() {
        tracing::debug!("GeoIP/GeoSite lock contention, falling back to blocking read");
        geoip_manager = Some(engine.geoip_manager.read());
        geosite_manager = Some(engine.geosite_manager.read());
    }

    (geoip_manager, geosite_manager)
}

#[inline]
pub fn contains_continue(actions: &[Action]) -> bool {
    actions.iter().any(|action| matches!(action, Action::Continue))
}

fn parse_rcode(rcode: &str) -> Option<ResponseCode> {
    match rcode.to_ascii_uppercase().as_str() {
        "NOERROR" => Some(ResponseCode::NoError),
        "FORMERR" => Some(ResponseCode::FormErr),
        "SERVFAIL" => Some(ResponseCode::ServFail),
        "NXDOMAIN" => Some(ResponseCode::NXDomain),
        "NOTIMP" => Some(ResponseCode::NotImp),
        "REFUSED" => Some(ResponseCode::Refused),
        _ => None,
    }
}

pub struct ApplyResponseActionsContext<'a> {
    pub engine: &'a Engine,
    pub actions: &'a [Action],
    pub ctx_opt: Option<ResponseContext>,
    pub req: &'a Message,
    pub packet: &'a [u8],
    pub upstream_timeout: Duration,
    pub response_matchers: &'a [RuntimeResponseMatcherWithOp],
    pub qname: &'a str,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub client_ip: IpAddr,
    pub upstream_default: &'a str,
    pub pipeline_id: &'a str,
    pub rule_name: &'a str,
    pub remaining_jumps: usize,
}

pub(crate) async fn apply_response_actions(
    mut ctx: ApplyResponseActionsContext<'_>,
) -> anyhow::Result<ResponseActionResult> {
    const MAX_RESPONSE_FORWARDS: usize = 4;
    let mut forward_attempts = 0usize;

    for action in ctx.actions {
        match action {
            Action::Log { level } => {
                log_match(level.as_deref(), ctx.rule_name, ctx.qname, ctx.client_ip);
            }
            Action::StaticResponse { rcode } => {
                let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                let bytes = build_response(ctx.req, code, Vec::new())?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode: code,
                    source: "response_action",
                });
            }
            Action::StaticIpResponse { ip } => {
                let (rcode, answers) = make_static_ip_answer(ctx.qname, ip);
                let bytes = build_response(ctx.req, rcode, answers)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode,
                    source: "response_action",
                });
            }
            Action::StaticTxtResponse { text, ttl } => {
                let ttl = ttl.unwrap_or(300);
                let (rcode, answers) = make_static_txt_answer(ctx.qname, text, ttl);
                let bytes = build_response(ctx.req, rcode, answers)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode,
                    source: "response_action",
                });
            }
            Action::JumpToPipeline { pipeline } => {
                if ctx.remaining_jumps == 0 {
                    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        source: "response_action",
                    });
                }
                return Ok(ResponseActionResult::Jump {
                    pipeline: Arc::from(pipeline.as_str()),
                    remaining_jumps: ctx.remaining_jumps - 1,
                });
            }
            Action::Allow => {
                if let Some(resp_ctx) = ctx.ctx_opt {
                    // 优化：使用辅助函数获取锁，消除重复代码
                    // Optimization: Use helper function to acquire locks, eliminate duplicate code
                    let (geoip_manager, geosite_manager) = acquire_geo_locks(ctx.engine);
                    let geoip_manager_ref = geoip_manager.as_deref();
                    let geosite_manager_ref = geosite_manager.as_deref();

                    let resp_match = eval_match_chain(
                        ctx.response_matchers,
                        |m| m.operator,
                        |m| {
                            m.matcher.matches(
                                &resp_ctx.upstream,
                                ctx.qname,
                                ctx.qtype,
                                ctx.qclass,
                                &resp_ctx.msg,
                                geoip_manager_ref,
                                geosite_manager_ref,
                            )
                        },
                    );
                    return Ok(ResponseActionResult::Upstream {
                        ctx: resp_ctx,
                        resp_match,
                    });
                } else {
                    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                    return Ok(ResponseActionResult::Static {
                         bytes,
                         rcode: ResponseCode::ServFail,
                         source: "response_action",
                    });
                }
            }
             Action::Deny => {
                let bytes = engine_helpers::build_refused_response(ctx.req)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode: ResponseCode::Refused,
                    source: "response_action",
                });
            }
            Action::Continue => {
                return Ok(ResponseActionResult::Continue { ctx: ctx.ctx_opt });
            }
            Action::ReplaceTxtResponse { text } => {
                if let Some(ref resp_ctx) = ctx.ctx_opt {
                    let name = resp_ctx.msg.queries().first()
                        .map(|q| q.name().clone())
                        .ok_or_else(|| anyhow::anyhow!("No query name"))?;

                    // Create new TXT record / 创建新的 TXT 记录
                    let txt = TXT::new(text.to_vec());
                    let record = Record::from_rdata(name, 300, RData::TXT(txt));

                    // Replace TXT records in answers / 替换答案中的 TXT 记录
                    let new_answers = vec![record];
                    let rcode = resp_ctx.msg.response_code();

                    let bytes = build_response(ctx.req, rcode, new_answers)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode,
                        source: "replace_txt",
                    });
                }
                let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                return Ok(ResponseActionResult::Static {
                    bytes,
                    rcode: ResponseCode::ServFail,
                    source: "response_action",
                });
            }
            Action::Forward {
                upstream,
                transport,
                pre_split_upstreams,
            } => {
                forward_attempts += 1;
                if forward_attempts > MAX_RESPONSE_FORWARDS {
                    warn!(
                        event = "dns_response",
                        qname = %ctx.qname,
                        qtype = ?ctx.qtype,
                        client_ip = %ctx.client_ip,
                        pipeline = %ctx.pipeline_id,
                        rule = %ctx.rule_name,
                        "response actions exceeded forward limit"
                    );
                    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        source: "response_action",
                    });
                }

                let upstream_addr: Arc<str> = upstream.as_ref().map(|s| Arc::from(s.as_str())).unwrap_or_else(|| {
                    ctx.ctx_opt
                        .as_ref()
                        .map(|c| c.upstream.clone())
                        .unwrap_or_else(|| Arc::from(ctx.upstream_default))
                });
                let use_transport = transport.unwrap_or(Transport::Udp);
                let (raw, actual_upstream) = match crate::engine::upstream::forward_upstream(ctx.engine, ctx.packet, &upstream_addr, ctx.upstream_timeout, Some(use_transport), pre_split_upstreams.as_ref())
                    .await
                {
                    Ok(result) => result,
                    Err(err) => {
                        warn!(
                            event = "dns_response",
                            upstream = %upstream_addr,
                            qname = %ctx.qname,
                            qtype = ?ctx.qtype,
                            client_ip = %ctx.client_ip,
                            pipeline = %ctx.pipeline_id,
                            rule = %ctx.rule_name,
                            error = %err,
                            "response action forward failed"
                        );
                        let bytes = engine_helpers::build_servfail_response(ctx.req)?;
                        return Ok(ResponseActionResult::Static {
                            bytes,
                            rcode: ResponseCode::ServFail,
                            source: "response_action",
                        });
                    }
                };
                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                ctx.ctx_opt = Some(ResponseContext {
                    raw,
                    msg,
                    upstream: Arc::from(actual_upstream.as_str()),  // Use actual responding upstream
                    transport: use_transport,
                });
            }
        }
    }

    if let Some(resp_ctx) = ctx.ctx_opt {
        // 优化：使用辅助函数获取锁，消除重复代码
        // Optimization: Use helper function to acquire locks, eliminate duplicate code
        let (geoip_manager, geosite_manager) = acquire_geo_locks(ctx.engine);
        let geoip_manager_ref = geoip_manager.as_deref();
        let geosite_manager_ref = geosite_manager.as_deref();

        let resp_match = eval_match_chain(
            ctx.response_matchers,
            |m| m.operator,
            |m| m.matcher.matches(&resp_ctx.upstream, ctx.qname, ctx.qtype, ctx.qclass, &resp_ctx.msg, geoip_manager_ref, geosite_manager_ref),
        );
        return Ok(ResponseActionResult::Upstream { ctx: resp_ctx, resp_match });
    }

    let bytes = engine_helpers::build_servfail_response(ctx.req)?;
    Ok(ResponseActionResult::Static {
        bytes,
        rcode: ResponseCode::ServFail,
        source: "response_action",
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_response_jump(
    engine: &Engine,
    state: &EngineInner,
    mut pipeline_id: Arc<str>,
    mut remaining_jumps: usize,
    req: &Message,
    packet: &[u8],
    peer: SocketAddr,
    qname: &str,
    qtype: RecordType,
    qclass: DNSClass,
    edns_present: bool,
    min_ttl: Duration,
    upstream_timeout: Duration,
    skip_cache: bool,
) -> anyhow::Result<Bytes> {
    let cfg = &state.pipeline;
    struct InflightCleanupGuard {
        inflight: Arc<InflightMap>,
        hash: u64,
        active: bool,
    }

    impl InflightCleanupGuard {
        fn new(inflight: Arc<InflightMap>, hash: u64) -> Self {
            Self { inflight, hash, active: true }
        }
        
        fn defuse(&mut self) {
            self.active = false;
        }
    }

    impl Drop for InflightCleanupGuard {
        fn drop(&mut self) {
            if self.active {
                self.inflight.remove(&self.hash);
            }
        }
    }

    let mut skip_rules: HashSet<Arc<str>> = HashSet::new();
    let mut reused_response: Option<ResponseContext> = None;
    let mut inflight_hashes = Vec::new();
    let mut cleanup_guards: Vec<InflightCleanupGuard> = Vec::new();

    loop {
        if remaining_jumps == 0 {
            let resp_bytes = engine_helpers::build_servfail_response(req)?;
            for g in &mut cleanup_guards { g.defuse(); }
            for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &resp_bytes).await; }
            return Ok(resp_bytes);
        }

        let Some(pipeline) = state.pipeline.pipelines.iter().find(|p| p.id == pipeline_id) else {
            let resp_bytes = engine_helpers::build_servfail_response(req)?;
            for g in &mut cleanup_guards { g.defuse(); }
            for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &resp_bytes).await; }
            return Ok(resp_bytes);
        };

        let dedupe_hash = Engine::calculate_cache_hash_for_dedupe(&pipeline_id, qname.as_bytes(), qtype, qclass);
        
        let mut decision = engine.apply_rules(
            state,
            pipeline,
            peer.ip(),
            qname,
            qtype,
            qclass,
            edns_present,
            if skip_rules.is_empty() {
                None
            } else {
                Some(&skip_rules)
            },
            skip_cache,
        );

        // Resolve nested rule-level jumps first
        let mut local_jumps = remaining_jumps;
        loop {
            if let Decision::Jump { pipeline } = decision {
                if local_jumps == 0 {
                    let resp_bytes = engine_helpers::build_servfail_response(req)?;
                    for g in &mut cleanup_guards { g.defuse(); }
                    for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &resp_bytes).await; }
                    return Ok(resp_bytes);
                }
                pipeline_id = pipeline;
                local_jumps -= 1;
                if let Some(next_pipeline) = state.pipeline.pipelines.iter().find(|p| p.id == pipeline_id) {
                    skip_rules.clear();
                    decision = engine.apply_rules(
                        state,
                        next_pipeline,
                        peer.ip(),
                        qname,
                        qtype,
                        qclass,
                        edns_present,
                        None,
                        skip_cache,
                    );
                    continue;
                } else {
                    let resp_bytes = engine_helpers::build_servfail_response(req)?;
                    for g in &mut cleanup_guards { g.defuse(); }
                    for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &resp_bytes).await; }
                    return Ok(resp_bytes);
                }
            }
            break;
        }

        remaining_jumps = local_jumps;

        match decision {
            Decision::Static { rcode, answers } => {
                let resp_bytes = build_response(req, rcode, answers)?;
                let entry = CacheEntry {
                    bytes: resp_bytes.clone(),
                    rcode,
                    source: Arc::from("static"),
                    upstream: None,  // Static responses have no upstream
                    qname: Arc::from(qname),
                    pipeline_id: pipeline_id.clone(),
                    qtype: u16::from(qtype),
                    inserted_at: Instant::now(),
                    original_ttl: min_ttl.as_secs() as u32,
                };
                engine.cache.insert(dedupe_hash, Arc::new(entry));
                for g in &mut cleanup_guards { g.defuse(); }
                for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &resp_bytes).await; }
                return Ok(resp_bytes);
            }
            Decision::Forward {
                upstream,
                pre_split_upstreams,
                response_matchers,
                response_matcher_operator: _response_matcher_operator,
                response_actions_on_match,
                response_actions_on_miss,
                rule_name,
                transport,
                continue_on_match: _,
                continue_on_miss: _,
                allow_reuse,
            } => {
                let resp = if allow_reuse {
                    if let Some(ctx) = reused_response.take() {
                        Ok((ctx.raw, ctx.upstream.to_string()))
                    } else {
                        // FIX: Background refresh must skip inflight check
                        // 修复：后台刷新必须跳过 inflight 检查
                        if !skip_cache {
                            use dashmap::mapref::entry::Entry;
                            let rx = match engine.inflight.entry(dedupe_hash) {
                                Entry::Vacant(entry) => {
                                    // No other request in progress, create watch channel
                                    // 没有其他请求在进行,创建 watch channel
                                    let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                                    entry.insert(tx);
                                    cleanup_guards.push(InflightCleanupGuard::new(engine.inflight.clone(), dedupe_hash));
                                    inflight_hashes.push(dedupe_hash);
                                    None
                                }
                                Entry::Occupied(entry) => {
                                    // Another request in progress, subscribe to its result
                                    // 已有请求在进行,订阅其结果
                                    let rx = entry.get().subscribe();
                                    Some(rx)
                                }
                            };

                            if let Some(mut rx) = rx {
                                // watch channel uses changed() to wait for updates
                                // watch channel 使用 changed() 等待更新
                                match rx.changed().await {
                                    Ok(_) => {
                                        // Clone result to avoid holding RwLockReadGuard across await
                                        // 克隆结果以避免在 await 跨度持有 RwLockReadGuard
                                        let result = rx.borrow().clone();
                                        match &result {
                                            Ok(bytes) => {
                                                // Rewrite Transaction ID for followers using BytesMut
                                                let mut resp_mut = BytesMut::from(bytes.as_ref());
                                                if resp_mut.len() >= 2 {
                                                    let id_bytes = req.id().to_be_bytes();
                                                    resp_mut[0] = id_bytes[0];
                                                    resp_mut[1] = id_bytes[1];
                                                }
                                                let resp_bytes = resp_mut.freeze();

                                                for g in &mut cleanup_guards { g.defuse(); }
                                                for h in &inflight_hashes { engine.notify_inflight_waiters(*h, bytes).await; }
                                                return Ok(resp_bytes);
                                            }
                                            Err(e) => return Err(anyhow::anyhow!("{}", e)),
                                        }
                                    }
                                    Err(_) => {
                                        // sender dropped, fallthrough to attempt upstream
                                    }
                                }
                            }
                        }
                        crate::engine::upstream::forward_upstream(engine, packet, &upstream, upstream_timeout, transport, pre_split_upstreams.as_ref()).await
                    }
                } else {
                    // If reuse is not allowed (e.g. explicit Forward action), we must clear any reused response
                    // and force a new request.
                    
                    // FIX: Background refresh must skip inflight check
                    // 修复：后台刷新必须跳过 inflight 检查
                    if !skip_cache {
                        use dashmap::mapref::entry::Entry;
                        let rx = match engine.inflight.entry(dedupe_hash) {
                            Entry::Vacant(entry) => {
                                // No other request in progress, create watch channel
                                // 没有其他请求在进行,创建 watch channel
                                let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                                entry.insert(tx);
                                cleanup_guards.push(InflightCleanupGuard::new(engine.inflight.clone(), dedupe_hash));
                                inflight_hashes.push(dedupe_hash);
                                None
                            }
                            Entry::Occupied(entry) => {
                                // Another request in progress, subscribe to its result
                                // 已有请求在进行,订阅其结果
                                let rx = entry.get().subscribe();
                                Some(rx)
                            }
                        };

                        if let Some(mut rx) = rx {
                            // watch channel uses changed() to wait for updates
                            // watch channel 使用 changed() 等待更新
                            match rx.changed().await {
                                Ok(_) => {
                                    // Clone result to avoid holding RwLockReadGuard across await
                                    // 克隆结果以避免在 await 跨度持有 RwLockReadGuard
                                    let result = rx.borrow().clone();
                                    match &result {
                                        Ok(bytes) => {
                                            // Rewrite Transaction ID for followers using BytesMut
                                            let mut resp_mut = BytesMut::from(bytes.as_ref());
                                            if resp_mut.len() >= 2 {
                                                let id_bytes = req.id().to_be_bytes();
                                                resp_mut[0] = id_bytes[0];
                                                resp_mut[1] = id_bytes[1];
                                            }
                                            let resp_bytes = resp_mut.freeze();

                                            for g in &mut cleanup_guards { g.defuse(); }
                                            for h in &inflight_hashes { engine.notify_inflight_waiters(*h, bytes).await; }
                                            return Ok(resp_bytes);
                                        }
                                        Err(e) => return Err(anyhow::anyhow!("{}", e)),
                                    }
                                }
                                Err(_) => {
                                    // sender dropped, fallthrough to attempt upstream
                                }
                            }
                        }
                    }
                    crate::engine::upstream::forward_upstream(engine, packet, &upstream, upstream_timeout, transport, pre_split_upstreams.as_ref()).await
                };

                match resp {
                    Ok((raw, actual_upstream)) => {
                        let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                        // Extract TTL for cache entry (use min for RFC 1035 compliance)
                        // 提取 TTL 用于缓存条目 (使用最小值符合 RFC 1035)
                        let ttl_secs_cache = extract_ttl(&msg);
                        // Extract TTL for refresh timing (use max to avoid premature refresh)
                        // 提取 TTL 用于刷新时机 (使用最大值避免过早刷新)
                        let ttl_secs_refresh = extract_ttl_for_refresh(&msg);
                        let effective_ttl = Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));

                        // Get manager references for GeoIP/GeoSite matching in response matchers
                        // Try to acquire read locks non-blockingly (fast path for concurrent reads)
                        // Use scope to ensure locks are released immediately after use
                        // 获取 manager 引用以用于响应匹配器中的 GeoIP/GeoSite 匹配
                        // 尝试非阻塞获取读锁（并发读的快速路径）
                        // 使用作用域确保锁在使用后立即释放
                        let resp_match_ok = {
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

                            eval_match_chain(
                                &response_matchers,
                                |m| m.operator,
                                |m| m.matcher.matches(&upstream, qname, qtype, qclass, &msg, geoip_manager_ref, geosite_manager_ref),
                            )
                        }; // guards are dropped here / 锁在此处释放

                        let actions_to_run = if !response_actions_on_match.is_empty()
                            || !response_actions_on_miss.is_empty()
                        {
                            if resp_match_ok {
                                &response_actions_on_match
                            } else {
                                &response_actions_on_miss
                            }
                        } else {
                            &Vec::new()
                        };

                        if actions_to_run.is_empty() {
                            if resp_match_ok && effective_ttl > Duration::from_secs(0) {
                                let entry = CacheEntry {
                                    bytes: raw.clone(),
                                    rcode: msg.response_code(),
                                    source: Arc::from(actual_upstream.as_str()),
                                    upstream: Some(Arc::from(actual_upstream.as_str())),
                                    qname: Arc::from(qname),
                                    pipeline_id: pipeline_id.clone(),
                                    qtype: u16::from(qtype),
                                    inserted_at: Instant::now(),
                                    original_ttl: ttl_secs_refresh as u32,  // Use max TTL for refresh timing / 使用最大 TTL 作为刷新时机
                                };
                                engine.cache.insert(dedupe_hash, Arc::new(entry));
                            }
                            for g in &mut cleanup_guards { g.defuse(); }
                            for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &raw).await; }
                            return Ok(raw);
                        }

                        let ctx = ResponseContext {
                            raw,
                            msg,
                            upstream: Arc::from(actual_upstream.as_str()),  // Use actual responding upstream
                            transport: transport.unwrap_or(Transport::Udp),
                        };
                        let apply_ctx = ApplyResponseActionsContext {
                            engine,
                            actions: actions_to_run,
                            ctx_opt: Some(ctx),
                            req,
                            packet,
                            upstream_timeout,
                            response_matchers: &response_matchers,
                            qname,
                            qtype,
                            qclass,
                            client_ip: peer.ip(),
                            upstream_default: cfg.settings.default_upstream.as_str(),
                            pipeline_id: &pipeline_id,
                            rule_name: &rule_name,
                            remaining_jumps,
                        };
                        let action_result = apply_response_actions(apply_ctx)
                            .await?;

                        match action_result {
                            ResponseActionResult::Upstream { ctx, resp_match } => {
                                // Extract TTL for cache entry (use min for RFC 1035 compliance)
                                // 提取 TTL 用于缓存条目 (使用最小值符合 RFC 1035)
                                let ttl_secs_cache = extract_ttl(&ctx.msg);
                                // Extract TTL for refresh timing (use max to avoid premature refresh)
                                // 提取 TTL 用于刷新时机 (使用最大值避免过早刷新)
                                let ttl_secs_refresh = extract_ttl_for_refresh(&ctx.msg);
                                let effective_ttl =
                                    Duration::from_secs(ttl_secs_cache.max(min_ttl.as_secs()));
                                if resp_match && effective_ttl > Duration::from_secs(0) {
                                    let entry = CacheEntry {
                                        bytes: ctx.raw.clone(),
                                        rcode: ctx.msg.response_code(),
                                        source: ctx.upstream.clone(),
                                        upstream: Some(ctx.upstream.clone()),
                                        qname: Arc::from(qname),
                                        pipeline_id: pipeline_id.clone(),
                                        qtype: u16::from(qtype),
                                        inserted_at: Instant::now(),
                                        original_ttl: ttl_secs_refresh as u32,  // Use max TTL for refresh timing / 使用最大 TTL 作为刷新时机
                                    };
                                    engine.cache.insert(dedupe_hash, Arc::new(entry));
                                }
                                for g in &mut cleanup_guards { g.defuse(); }
                                for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &ctx.raw).await; }
                                return Ok(ctx.raw);
                            }
                            ResponseActionResult::Static { bytes, .. } => {
                                for g in &mut cleanup_guards { g.defuse(); }
                                for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &bytes).await; }
                                return Ok(bytes);
                            }
                            ResponseActionResult::Jump { pipeline, remaining_jumps: next_remaining } => {
                                pipeline_id = pipeline;
                                remaining_jumps = next_remaining;
                                continue;
                            }
                            ResponseActionResult::Continue { ctx } => {
                                reused_response = ctx;
                                skip_rules.insert(rule_name.clone());
                                continue;
                            }
                        }
                    }
                    Err(_err) => {
                        let resp_bytes = engine_helpers::build_servfail_response(req)?;
                        for g in &mut cleanup_guards { g.defuse(); }
                        for h in &inflight_hashes { engine.notify_inflight_waiters(*h, &resp_bytes).await; }
                        return Ok(resp_bytes);
                    }
                }
            }
            Decision::Jump { pipeline } => {
                pipeline_id = pipeline;
                if remaining_jumps > 0 {
                    remaining_jumps -= 1;
                    continue;
                } else {
                    let resp_bytes = engine_helpers::build_servfail_response(req)?;
                    return Ok(resp_bytes);
                }
            }
        }
    }
}
