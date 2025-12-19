use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
use dashmap::DashMap;
use rustc_hash::{FxHasher, FxBuildHasher};
use socket2::{Domain, Protocol, Socket, Type};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use moka::sync::Cache;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpStream, UdpSocket,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::cache::{CacheEntry, DnsCache, new_cache};
use crate::advanced_rule::{CompiledPipeline, compile_pipelines, fast_static_match};
use crate::config::{Action, Transport};
use crate::matcher::{
    RuntimePipeline, RuntimePipelineConfig, RuntimeResponseMatcherWithOp, eval_match_chain,
};
use crate::proto_utils::{parse_quick, build_static_response_fast};

/// Fast-path response for UDP workers.
///
/// - `Direct`: already has correct TXID and can be sent as-is.
/// - `CacheHit`: carries cached bytes (with an old TXID) and the request TXID to patch.
#[derive(Debug, Clone)]
pub enum FastPathResponse {
    Direct(Bytes),
    CacheHit { cached: Bytes, tx_id: u16 },
}

pub struct EngineInner {
    pub pipeline: RuntimePipelineConfig,
    pub compiled_pipelines: Vec<CompiledPipeline>,
}

thread_local! {
    static ENGINE_CANDIDATE_CACHE: std::cell::RefCell<Vec<usize>> = std::cell::RefCell::new(Vec::with_capacity(128));
}

#[derive(Clone)]
pub struct Engine {
    state: Arc<ArcSwap<EngineInner>>,
    cache: DnsCache,
    udp_client: Arc<UdpClient>,
    tcp_mux: Arc<TcpMultiplexer>,
    listener_label: Arc<str>,
    // Rule execution result cache: Hash -> (Key, Decision) / 规则执行结果缓存：哈希 -> (键, 决策)
    // Key is stored to verify collisions / 存储键以验证冲突
    rule_cache: Cache<u64, RuleCacheEntry, FxBuildHasher>,
    // Runtime metrics for diagnosing concurrency and upstream latency / 运行时指标，用于诊断并发和上游延迟
    pub metrics_inflight: Arc<AtomicUsize>,
    pub metrics_total_requests: Arc<AtomicU64>,
    pub metrics_fastpath_hits: Arc<AtomicU64>,
    pub metrics_upstream_ns_total: Arc<AtomicU64>,
    pub metrics_upstream_calls: Arc<AtomicU64>,
    // Per-request id generator for tracing / 每个请求的 ID 生成器用于追踪
    pub request_id_counter: Arc<AtomicU64>,
    // In-flight dedupe map: cache_hash -> waiters / 进行中的去重映射：缓存哈希 -> 等待者
    pub inflight: Arc<DashMap<u64, Vec<oneshot::Sender<anyhow::Result<Bytes>>>, FxBuildHasher>>,
}

impl Engine {
    pub fn new(cfg: RuntimePipelineConfig, listener_label: String) -> Self {
        // moka 缓存：最大 10000 条，默认 TTL 300 秒（会被实际 TTL 覆盖） / moka cache: max 10000 entries, default TTL 300 seconds (will be overridden by actual TTL)
        let cache = new_cache(10_000, 300);
        // Rule cache: 100k entries, 60s TTL / 规则缓存：10万条，60秒 TTL
        let rule_cache = Cache::builder()
            .max_capacity(100_000)
            .time_to_live(Duration::from_secs(60))
            .build_with_hasher(FxBuildHasher::default());

        // UDP socket pool size from config / 从配置获取 UDP 套接字池大小
        let udp_pool_size = cfg.settings.udp_pool_size;
        let tcp_pool_size = cfg.settings.tcp_pool_size;
        let compiled = compile_pipelines(&cfg);
        
        let state = Arc::new(ArcSwap::from_pointee(EngineInner {
            pipeline: cfg,
            compiled_pipelines: compiled,
        }));

        Self {
            state,
            cache,
            udp_client: Arc::new(UdpClient::new(udp_pool_size)),
            tcp_mux: Arc::new(TcpMultiplexer::new(tcp_pool_size)),
            listener_label: Arc::from(listener_label),
            rule_cache,
            metrics_inflight: Arc::new(AtomicUsize::new(0)),
            metrics_total_requests: Arc::new(AtomicU64::new(0)),
            metrics_fastpath_hits: Arc::new(AtomicU64::new(0)),
            metrics_upstream_ns_total: Arc::new(AtomicU64::new(0)),
            metrics_upstream_calls: Arc::new(AtomicU64::new(0)),
            request_id_counter: Arc::new(AtomicU64::new(1)),
            inflight: Arc::new(DashMap::with_hasher(FxBuildHasher::default())),
        }
    }

    /// 重新加载配置并更新编译后的管线 / Reload configuration and update compiled pipelines
    pub fn reload(&self, new_cfg: RuntimePipelineConfig) {
        let compiled = compile_pipelines(&new_cfg);
        self.state.store(Arc::new(EngineInner {
            pipeline: new_cfg,
            compiled_pipelines: compiled,
        }));
        // 清除规则缓存以确保新规则立即生效 / Clear rule cache to ensure new rules take effect immediately
        self.rule_cache.invalidate_all();
    }

    #[inline]
    fn calculate_cache_hash_for_dedupe(pipeline_id: &str, qname: &str, qtype: hickory_proto::rr::RecordType) -> u64 {
        let mut h = FxHasher::default();
        pipeline_id.hash(&mut h);
        qname.to_ascii_lowercase().hash(&mut h);
        // RecordType implements Copy+Debug, hash by its u16 representation / RecordType 实现了 Copy+Debug，使用其 u16 表示进行哈希
        u16::from(qtype).hash(&mut h);
        h.finish()
    }

    #[allow(dead_code)]
    pub fn metrics_snapshot(&self) -> String {
        let inflight = self.metrics_inflight.load(Ordering::Relaxed);
        let total = self.metrics_total_requests.load(Ordering::Relaxed);
        let fast = self.metrics_fastpath_hits.load(Ordering::Relaxed);
        let up_ns = self.metrics_upstream_ns_total.load(Ordering::Relaxed);
        let up_calls = self.metrics_upstream_calls.load(Ordering::Relaxed);
        let avg_up_ns = if up_calls > 0 { up_ns / up_calls } else { 0 };
        format!(
            "inflight={} total={} fastpath_hits={} upstream_avg_us={}",
            inflight,
            total,
            fast,
            avg_up_ns as f64 / 1000.0
        )
    }

    /// 快速路径：同步尝试缓存命中 / Fast path: synchronous cache hit attempt
    /// 返回 Ok(Some(bytes)) 表示缓存命中，可直接返回 / Return Ok(Some(bytes)) means cache hit, can return directly
    /// 返回 Ok(None) 表示需要异步处理（上游转发） / Return Ok(None) means async processing needed (upstream forwarding)
    /// 返回 Err 表示解析错误 / Return Err means parsing error
    #[inline]
    pub fn handle_packet_fast(
        &self,
        packet: &[u8],
        peer: SocketAddr,
    ) -> anyhow::Result<Option<FastPathResponse>> {
        // 快速解析，避免完整 Message 解析和大量分配 / Quick parsing, avoiding full Message parsing and massive allocations
        // 使用栈上缓冲区避免 String 分配 / Use stack buffer to avoid String allocation
        let mut qname_buf = [0u8; 256];
        let req_id = self.request_id_counter.fetch_add(1, Ordering::Relaxed);
        let t_start = std::time::Instant::now();
        let q = match parse_quick(packet, &mut qname_buf) {
            Some(q) => q,
            None => {
                // quick parse failed / 快速解析失败
                let elapsed = t_start.elapsed().as_nanos();
                tracing::debug!(request_id = req_id, phase = "parse_quick_fail", elapsed_ns = elapsed, "fastpath parse failed");
                return Ok(None);
            }
        };
        // Count incoming quick-parsed requests / 计数进入的快速解析请求
        self.metrics_total_requests.fetch_add(1, Ordering::Relaxed);
        let t_after_parse = t_start.elapsed();
        
        // 获取 pipeline ID / Get pipeline ID
        let state = self.state.load();
        let cfg = &state.pipeline;
        let qclass = DNSClass::from(q.qclass);
        let (_pipeline_opt, pipeline_id) = select_pipeline(
            cfg,
            q.qname,
            peer.ip(),
            qclass,
            q.edns_present,
            &self.listener_label,
        );
        
        // 1. Check Response Cache (L2) / 1. 检查响应缓存（L2）
        // TODO: Optimize CacheKey to avoid Arc allocation on lookup? / TODO：优化 CacheKey 以避免查找时的 Arc 分配？
        // Currently we still allocate Arc<str> in CacheKey::new. / 目前我们仍然在 CacheKey::new 中分配 Arc<str>
        // But we saved the String allocation in parse_quick. / 但我们在 parse_quick 中节省了 String 分配
        let qtype = hickory_proto::rr::RecordType::from(q.qtype);
        let cache_hash = Self::calculate_cache_hash_for_dedupe(&pipeline_id, q.qname, qtype);
        
        if let Some(hit) = self.cache.get(&cache_hash) {
            // Verify collision / 验证冲突
            if hit.qtype == u16::from(qtype) && hit.qname.as_ref() == q.qname && hit.pipeline_id.as_ref() == pipeline_id {
                self.metrics_fastpath_hits.fetch_add(1, Ordering::Relaxed);
                let elapsed = t_after_parse.as_nanos();
                tracing::debug!(request_id = req_id, phase = "cache_hit", elapsed_ns = elapsed, "fastpath cache hit");
                return Ok(Some(FastPathResponse::CacheHit {
                    cached: hit.bytes.clone(),
                    tx_id: q.tx_id,
                }));
            }
        }

        // 2. Compiled rule fast-path for static decisions / 2. 编译规则的静态决策快速路径
        if let Some(compiled) = self.compiled_for(&state, &pipeline_id) {
            let qclass = DNSClass::from(q.qclass);
            if let Some(decision) = fast_static_match(
                &compiled,
                q.qname,
                qtype,
                qclass,
                peer.ip(),
                q.edns_present,
            ) {
                if let Decision::Static { rcode, answers } = decision {
                    if answers.is_empty() {
                        // 优化：使用预编码模板快速生成响应 / Optimization: use pre-encoded template for fast response generation
                        if let Some(bytes) = build_static_response_fast(packet, rcode) {
                            self.metrics_fastpath_hits.fetch_add(1, Ordering::Relaxed);
                            let elapsed_ns = t_start.elapsed().as_nanos();
                            tracing::debug!(request_id = req_id, phase = "fast_static_preencoded", elapsed_ns = elapsed_ns, "fast static match preencoded");
                            return Ok(Some(FastPathResponse::Direct(Bytes::from(bytes))));
                        }
                    }

                    let resp = build_fast_static_response(
                        q.tx_id,
                        q.qname,
                        q.qtype,
                        q.qclass,
                        rcode,
                        &answers,
                    )?;
                    self.metrics_fastpath_hits.fetch_add(1, Ordering::Relaxed);
                    let elapsed_ns = t_start.elapsed().as_nanos();
                    tracing::debug!(request_id = req_id, phase = "fast_static", elapsed_ns = elapsed_ns, "fast static match");
                    return Ok(Some(FastPathResponse::Direct(resp)));
                }
            }
        }

        // 3. Check Rule Cache (L1) for Static Responses / 3. 检查规则缓存（L1）的静态响应
        // Zero-allocation lookup using hash / 使用哈希的零分配查找
        let rule_hash = calculate_rule_hash(&pipeline_id, q.qname, peer.ip());
        if let Some(entry) = self.rule_cache.get(&rule_hash) {
            if entry.matches(&pipeline_id, q.qname, peer.ip()) {
                if let Decision::Static { rcode, answers } = &entry.decision {
                    let resp = build_fast_static_response(
                        q.tx_id,
                        q.qname,
                        q.qtype,
                        q.qclass,
                        *rcode,
                        answers,
                    )?;
                    self.metrics_fastpath_hits.fetch_add(1, Ordering::Relaxed);
                    let elapsed_ns = t_start.elapsed().as_nanos();
                    tracing::debug!(request_id = req_id, phase = "rule_cache_hit", elapsed_ns = elapsed_ns, "rule cache hit");
                    return Ok(Some(FastPathResponse::Direct(resp)));
                }
            }
        }
        // Log timing up to fastpath checks / 记录到快速路径检查的时间
        let elapsed_ns = t_start.elapsed().as_nanos();
        tracing::debug!(request_id = req_id, phase = "fastpath_checks_done", elapsed_ns = elapsed_ns, "fastpath checks done, falling back to async path");
        
        // 缓存未命中，需要异步处理 / Cache miss, need async processing
        Ok(None)
    }

    #[inline]
    pub async fn handle_packet(&self, packet: &[u8], peer: SocketAddr) -> anyhow::Result<Bytes> {
        // Track requests and inflight concurrency for diagnostics. / 跟踪请求和进行中的并发以进行诊断
        let _req_id = self.request_id_counter.fetch_add(1, Ordering::Relaxed);
        self.metrics_total_requests.fetch_add(1, Ordering::Relaxed);
        struct InflightGuard(Arc<AtomicUsize>);
        impl Drop for InflightGuard {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.metrics_inflight.fetch_add(1, Ordering::Relaxed);
        let _inflight_guard = InflightGuard(self.metrics_inflight.clone());
        let state = self.state.load();
        let cfg = &state.pipeline;
        let min_ttl = cfg.min_ttl();
        let upstream_timeout = cfg.upstream_timeout();
        let response_jump_limit = cfg.settings.response_jump_limit as usize;

        // Lazy Parse: Use quick parse first / 延迟解析：首先使用快速解析
        let mut qname_buf = [0u8; 256];
        let (qname_cow, qtype, qclass, tx_id, edns_present) = if let Some(q) = parse_quick(packet, &mut qname_buf) {
            (std::borrow::Cow::Borrowed(q.qname), hickory_proto::rr::RecordType::from(q.qtype), DNSClass::from(q.qclass), q.tx_id, q.edns_present)
        } else {
            // Fallback to full parse if quick parse fails (unlikely for standard queries) / 如果快速解析失败则回退到完整解析（对于标准查询不太可能）
            let req = Message::from_bytes(packet).context("parse request")?;
            let question = req.queries().first().context("empty question")?;
            (
                std::borrow::Cow::Owned(question.name().to_lowercase().to_string()),
                question.query_type(),
                question.query_class(),
                req.id(),
                req.extensions().is_some(),
            )
        };
        let qname_ref = &qname_cow;

        let start = std::time::Instant::now();

        let (pipeline_opt, pipeline_id) = select_pipeline(
            cfg,
            qname_ref,
            peer.ip(),
            qclass,
            edns_present,
            &self.listener_label,
        );

        let dedupe_hash = Self::calculate_cache_hash_for_dedupe(&pipeline_id, qname_ref, qtype);
        // moka 同步缓存自动处理过期，无需检查 expires_at / moka sync cache automatically handles expiration, no need to check expires_at
        if let Some(hit) = self.cache.get(&dedupe_hash) {
            if hit.qtype == u16::from(qtype) && hit.qname.as_ref() == *qname_ref && hit.pipeline_id.as_ref() == pipeline_id {
                let latency = start.elapsed();
                // clone bytes and rewrite transaction ID to match requester / 克隆字节并重写事务 ID 以匹配请求者
                let mut resp_bytes = bytes::BytesMut::with_capacity(hit.bytes.len());
                resp_bytes.extend_from_slice(&hit.bytes);
                if resp_bytes.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_bytes[0] = id_bytes[0];
                    resp_bytes[1] = id_bytes[1];
                }
                let resp_bytes = resp_bytes.freeze();
                debug!(
                    event = "dns_response",
                    upstream = %hit.source,
                    qname = %qname_ref,
                    qtype = ?qtype,
                    rcode = ?hit.rcode,
                    latency_ms = latency.as_millis() as u64,
                    client_ip = %peer.ip(),
                    pipeline = %pipeline_id,
                    cache = true,
                    "cache hit"
                );
                return Ok(resp_bytes);
            }
        }

        let qname = qname_cow.into_owned();
        let mut skip_rules = HashSet::new();
        let mut current_pipeline_id = pipeline_id.clone();
        let mut dedupe_hash = Self::calculate_cache_hash_for_dedupe(&current_pipeline_id, &qname, qtype);
        let mut dedupe_registered = false;
        let mut reused_response: Option<ResponseContext> = None;

        let mut decision = match pipeline_opt {
            Some(p) => self.apply_rules(&state, p, peer.ip(), &qname, qtype, qclass, edns_present, None),
            None => Decision::Forward {
                upstream: cfg.settings.default_upstream.clone(),
                response_matchers: Vec::new(),
                response_matcher_operator: crate::config::MatchOperator::And,
                response_actions_on_match: Vec::new(),
                response_actions_on_miss: Vec::new(),
                rule_name: "default".to_string(),
                transport: Transport::Udp,
                continue_on_match: false,
                continue_on_miss: false,
                allow_reuse: false,
            },
        };

        struct InflightCleanupGuard {
            inflight: Arc<DashMap<u64, Vec<oneshot::Sender<anyhow::Result<Bytes>>>, FxBuildHasher>>,
            hash: u64,
            active: bool,
        }

        impl InflightCleanupGuard {
            fn new(inflight: Arc<DashMap<u64, Vec<oneshot::Sender<anyhow::Result<Bytes>>>, FxBuildHasher>>, hash: u64) -> Self {
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

        'decision_loop: loop {
            let mut jump_count = 0;
            loop {
                if let Decision::Jump { pipeline } = &decision {
                    jump_count += 1;
                    if jump_count > response_jump_limit {
                        warn!("max jump limit reached");
                        decision = Decision::Static {
                            rcode: ResponseCode::ServFail,
                            answers: Vec::new(),
                        };
                        break;
                    }
                    if let Some(p) = cfg.pipelines.iter().find(|p| p.id.as_ref() == *pipeline) {
                        current_pipeline_id = pipeline.clone();
                        dedupe_hash = Self::calculate_cache_hash_for_dedupe(&current_pipeline_id, &qname, qtype);
                        dedupe_registered = false;
                        skip_rules.clear();
                        decision = self.apply_rules(
                            &state,
                            p,
                            peer.ip(),
                            &qname,
                            qtype,
                            qclass,
                            edns_present,
                            None,
                        );
                        continue;
                    } else {
                        warn!("jump target pipeline not found: {}", pipeline);
                        decision = Decision::Static {
                            rcode: ResponseCode::ServFail,
                            answers: Vec::new(),
                        };
                        break;
                    }
                } else {
                    break;
                }
            }

            match decision {
            Decision::Jump { .. } => {
                anyhow::bail!("unresolved pipeline jump");
            }
            Decision::Static { rcode, answers } => {
                // Need full request for building response / 需要完整请求来构建响应
                let req = Message::from_bytes(packet).context("parse request for static")?;
                let resp_bytes = build_response(&req, rcode, answers)?;
                if min_ttl > Duration::from_secs(0) {
                    let entry = CacheEntry {
                        bytes: resp_bytes.clone(),
                        rcode,
                        source: Arc::from("static"),
                        qname: Arc::from(qname.as_str()),
                        pipeline_id: Arc::from(current_pipeline_id.as_str()),
                        qtype: u16::from(qtype),
                    };
                    self.cache.insert(dedupe_hash, entry);
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
                return Ok(resp_bytes);
            }
            Decision::Forward {
                upstream,
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
                let mut cleanup_guard = None;
                let resp = if allow_reuse && reused_response.is_some() {
                    Ok(reused_response.take().unwrap().raw)
                } else {
                    // In-flight merging logic / 合并进行中的重复请求逻辑
                    if !dedupe_registered {
                        use dashmap::mapref::entry::Entry;
                        let rx = match self.inflight.entry(dedupe_hash) {
                            Entry::Occupied(mut entry) => {
                                let (tx, rx) = oneshot::channel();
                                entry.get_mut().push(tx);
                                Some(rx)
                            }
                            Entry::Vacant(entry) => {
                                entry.insert(Vec::new());
                                dedupe_registered = true;
                                cleanup_guard = Some(InflightCleanupGuard::new(self.inflight.clone(), dedupe_hash));
                                None
                            }
                        };

                        if let Some(rx) = rx {
                            match rx.await {
                                Ok(Ok(bytes)) => {
                                    let mut resp_vec = bytes.to_vec();
                                    if resp_vec.len() >= 2 {
                                        let id_bytes = tx_id.to_be_bytes();
                                        resp_vec[0] = id_bytes[0];
                                        resp_vec[1] = id_bytes[1];
                                    }
                                    return Ok(Bytes::from(resp_vec));
                                }
                                Ok(Err(e)) => return Err(e),
                                Err(_) => {
                                    // sender dropped, fallthrough to attempt upstream
                                }
                            }
                        }
                    }
                    self.forward_upstream(packet, &upstream, upstream_timeout, transport).await
                };

                match resp {
                    Ok(raw) => {
                        // Optimization: Use quick response parse if no complex matching is needed
                        let (rcode, ttl_secs, msg_opt) = if response_matchers.is_empty() && response_actions_on_match.is_empty() && response_actions_on_miss.is_empty() {
                            if let Some(qr) = crate::proto_utils::parse_response_quick(&raw) {
                                (qr.rcode, qr.min_ttl as u64, None)
                            } else {
                                // Fallback
                                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                                let ttl = extract_ttl(&msg);
                                (msg.response_code(), ttl, Some(msg))
                            }
                        } else {
                            let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                            let ttl = extract_ttl(&msg);
                            (msg.response_code(), ttl, Some(msg))
                        };

                        let effective_ttl = Duration::from_secs(ttl_secs.max(min_ttl.as_secs()));

                        let (resp_match_ok, msg) = if let Some(m) = msg_opt {
                            let matched = eval_match_chain(
                                &response_matchers,
                                |m| m.operator,
                                |matcher_op| matcher_op.matcher.matches(&upstream, &qname, qtype, qclass, &m),
                            );
                            (matched, m)
                        } else {
                            (false, Message::new()) // Dummy message, won't be used as actions are empty
                        };

                        let empty_actions = Vec::new();
                        let actions_to_run = if !response_actions_on_match.is_empty()
                            || !response_actions_on_miss.is_empty()
                        {
                            if resp_match_ok {
                                &response_actions_on_match
                            } else {
                                &response_actions_on_miss
                            }
                        } else {
                            &empty_actions
                        };

                        if actions_to_run.is_empty() {
                            if effective_ttl > Duration::from_secs(0) {
                                let entry = CacheEntry {
                                    bytes: raw.clone(),
                                    rcode,
                                    source: Arc::from(upstream.as_str()),
                                    qname: Arc::from(qname.as_str()),
                                    pipeline_id: Arc::from(pipeline_id.as_str()),
                                    qtype: u16::from(qtype),
                                };
                                self.cache.insert(dedupe_hash, entry);
                            }
                            if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                            self.notify_inflight_waiters(dedupe_hash, &raw).await;
                            let latency = start.elapsed();
                            info!(
                                event = "dns_response",
                                upstream = %upstream,
                                qname = %qname,
                                qtype = ?qtype,
                                rcode = ?rcode,
                                latency_ms = latency.as_millis() as u64,
                                client_ip = %peer.ip(),
                                pipeline = %pipeline_id,
                                cache = effective_ttl > Duration::from_secs(0),
                                resp_match = resp_match_ok,
                                transport = ?transport,
                                "forwarded"
                            );
                            return Ok(raw);
                        }
                        
                        // If we have actions, we MUST have parsed the message fully above
                        // Re-construct req if needed (it was lazily parsed or not)
                        // But wait, `req` variable is now potentially uninitialized or moved?
                        // Actually `req` was defined at top of function but we made it lazy.
                        // We need to ensure `req` is available here if we need to run actions.
                        let req_full = if let Ok(r) = Message::from_bytes(packet) { r } else { Message::new() }; // Re-parse if needed for actions

                        let ctx = ResponseContext {
                            raw: raw.clone(),
                            msg,
                            upstream: upstream.clone(),
                            transport,
                        };
                        let action_result = self
                            .apply_response_actions(
                                actions_to_run,
                                Some(ctx),
                                &req_full,
                                packet,
                                upstream_timeout,
                                &response_matchers,
                                &qname,
                                qtype,
                                qclass,
                                peer.ip(),
                                cfg.settings.default_upstream.as_str(),
                                &pipeline_id,
                                &rule_name,
                                response_jump_limit,
                            )
                            .await?;

                        match action_result {
                            ResponseActionResult::Upstream { ctx, resp_match } => {
                                let ttl_secs = extract_ttl(&ctx.msg);
                                let effective_ttl =
                                    Duration::from_secs(ttl_secs.max(min_ttl.as_secs()));
                                if effective_ttl > Duration::from_secs(0) {
                                    let entry = CacheEntry {
                                        bytes: ctx.raw.clone(),
                                        rcode: ctx.msg.response_code(),
                                        source: Arc::from(ctx.upstream.as_str()),
                                        qname: Arc::from(qname.as_str()),
                                        pipeline_id: Arc::from(pipeline_id.as_str()),
                                        qtype: u16::from(qtype),
                                    };
                                    self.cache.insert(dedupe_hash, entry);
                                }
                                if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                                self.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                                let latency = start.elapsed();
                                info!(
                                    event = "dns_response",
                                    upstream = %ctx.upstream,
                                    qname = %qname,
                                    qtype = ?qtype,
                                    rcode = ?ctx.msg.response_code(),
                                    latency_ms = latency.as_millis() as u64,
                                    client_ip = %peer.ip(),
                                    pipeline = %pipeline_id,
                                    cache = effective_ttl > Duration::from_secs(0),
                                    resp_match = resp_match,
                                    transport = ?ctx.transport,
                                    "forwarded"
                                );
                                return Ok(ctx.raw);
                            }
                            ResponseActionResult::Static {
                                bytes,
                                rcode,
                                source,
                            } => {
                                if min_ttl > Duration::from_secs(0) {
                                    let entry = CacheEntry {
                                        bytes: bytes.clone(),
                                        rcode,
                                        source: Arc::from(source),
                                        qname: Arc::from(qname.as_str()),
                                        pipeline_id: Arc::from(current_pipeline_id.as_str()),
                                        qtype: u16::from(qtype),
                                    };
                                    self.cache.insert(dedupe_hash, entry);
                                }
                                if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                                self.notify_inflight_waiters(dedupe_hash, &bytes).await;
                                let latency = start.elapsed();
                                info!(
                                    event = "dns_response",
                                    upstream = %source,
                                    qname = %qname,
                                    qtype = ?qtype,
                                    rcode = ?rcode,
                                    latency_ms = latency.as_millis() as u64,
                                    client_ip = %peer.ip(),
                                    pipeline = %current_pipeline_id,
                                    cache = min_ttl > Duration::from_secs(0),
                                    resp_match = false,
                                    transport = ?transport,
                                    "response_action_static"
                                );
                                return Ok(bytes);
                            }
                                ResponseActionResult::Jump { pipeline, remaining_jumps } => {
                                let req = Message::from_bytes(packet).context("parse request")?;
                                let resp_bytes = self
                                    .process_response_jump(
                                        &state,
                                        pipeline,
                                        remaining_jumps,
                                        &req,
                                        packet,
                                        peer,
                                        &qname,
                                        qtype,
                                        qclass,
                                        edns_present,
                                        min_ttl,
                                        upstream_timeout,
                                    )
                                    .await?;
                                if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                                self.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                                return Ok(resp_bytes);
                            }
                                ResponseActionResult::Continue { ctx } => {
                                    if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                                    // Do NOT notify waiters yet, as we are continuing to find a better response.
                                    // Waiters will be notified when the final decision is reached.

                                    reused_response = ctx;
                                    skip_rules.insert(rule_name.clone());
                                    let skip_ref = if skip_rules.is_empty() {
                                        None
                                    } else {
                                        Some(&skip_rules)
                                    };
                                    let pipeline = cfg
                                        .pipelines
                                        .iter()
                                        .find(|p| p.id.as_ref() == current_pipeline_id)
                                        .expect("pipeline missing while continuing");
                                    decision = self.apply_rules(
                                        &state,
                                        pipeline,
                                        peer.ip(),
                                        &qname,
                                        qtype,
                                        qclass,
                                        edns_present,
                                        skip_ref,
                                    );
                                    continue 'decision_loop;
                                }
                        }
                    }
                    Err(err) => {
                        if response_actions_on_miss.is_empty() {
                            let rcode = ResponseCode::ServFail;
                            warn!(
                                event = "dns_response",
                                upstream = %upstream,
                                qname = %qname,
                                qtype = ?qtype,
                                rcode = ?rcode,
                                client_ip = %peer.ip(),
                                error = %err,
                                pipeline = %current_pipeline_id,
                                transport = ?transport,
                                "upstream failed"
                            );
                            let req = Message::from_bytes(packet).context("parse request")?;
                            let resp_bytes = build_response(&req, rcode, Vec::new())?;
                            if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                            self.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                            return Ok(resp_bytes);
                        } else {
                            let req = Message::from_bytes(packet).context("parse request")?;
                            let action_result = self
                                .apply_response_actions(
                                    &response_actions_on_miss,
                                    None,
                                    &req,
                                    packet,
                                    upstream_timeout,
                                    &response_matchers,
                                    &qname,
                                    qtype,
                                    qclass,
                                    peer.ip(),
                                    cfg.settings.default_upstream.as_str(),
                                    &pipeline_id,
                                    &rule_name,
                                    response_jump_limit,
                                )
                                .await?;
                            match action_result {
                                    ResponseActionResult::Upstream { ctx, resp_match } => {
                                        let ttl_secs = extract_ttl(&ctx.msg);
                                        let effective_ttl =
                                            Duration::from_secs(ttl_secs.max(min_ttl.as_secs()));
                                        if resp_match && effective_ttl > Duration::from_secs(0) {
                                            let entry = CacheEntry {
                                                bytes: ctx.raw.clone(),
                                                rcode: ctx.msg.response_code(),
                                                source: Arc::from(ctx.upstream.as_str()),
                                                qname: Arc::from(qname.as_str()),
                                                pipeline_id: Arc::from(pipeline_id.as_str()),
                                                qtype: u16::from(qtype),
                                            };
                                            self.cache.insert(dedupe_hash, entry);
                                        }
                                        self.notify_inflight_waiters(dedupe_hash, &ctx.raw).await;
                                        return Ok(ctx.raw);
                                    }
                                    ResponseActionResult::Static { bytes, .. } => {
                                        self.notify_inflight_waiters(dedupe_hash, &bytes).await;
                                        return Ok(bytes);
                                    }
                                    ResponseActionResult::Jump { pipeline, remaining_jumps } => {
                                        let req = Message::from_bytes(packet).context("parse request")?;
                                        let resp_bytes = self
                                            .process_response_jump(
                                                &state,
                                                pipeline,
                                                remaining_jumps,
                                                &req,
                                                packet,
                                                peer,
                                                &qname,
                                                qtype,
                                                qclass,
                                                edns_present,
                                                min_ttl,
                                                upstream_timeout,
                                            )
                                            .await?;
                                        self.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                                        return Ok(resp_bytes);
                                    }
                                    ResponseActionResult::Continue { ctx } => {
                                        if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                                        reused_response = ctx;
                                        skip_rules.insert(rule_name.clone());
                                        let skip_ref = if skip_rules.is_empty() {
                                            None
                                        } else {
                                            Some(&skip_rules)
                                        };
                                        let pipeline = cfg
                                            .pipelines
                                            .iter()
                                            .find(|p| p.id.as_ref() == current_pipeline_id)
                                            .expect("pipeline missing while continuing");
                                        decision = self.apply_rules(
                                            &state,
                                            pipeline,
                                            peer.ip(),
                                            &qname,
                                            qtype,
                                            qclass,
                                            edns_present,
                                            skip_ref,
                                        );
                                        continue 'decision_loop;
                                    }
                            }
                        }
                    }
                }
            }
        }
    }
}

    #[inline]
    fn apply_rules(
        &self,
        state: &EngineInner,
        pipeline: &RuntimePipeline,
        client_ip: IpAddr,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
        edns_present: bool,
        skip_rules: Option<&HashSet<String>>,
    ) -> Decision {
        // 1. Check Rule Cache
        let rule_hash = calculate_rule_hash(&pipeline.id, qname, client_ip);
        let allow_rule_cache_lookup = skip_rules.map_or(true, |set| set.is_empty());
        
        if allow_rule_cache_lookup {
            if let Some(entry) = self.rule_cache.get(&rule_hash) {
                if entry.matches(&pipeline.id, qname, client_ip) {
                    return entry.decision.clone();
                }
            }
        }

        // 2. Candidate Selection (compiled index if available)
        let decision = ENGINE_CANDIDATE_CACHE.with(|cache| {
            let mut candidates = cache.borrow_mut();
            if let Some(compiled) = self.compiled_for(state, &pipeline.id) {
                compiled.index.fill_candidates(qname, qtype, &mut candidates);
            } else {
                // Fallback to runtime indices
                candidates.clear();
                candidates.extend_from_slice(&pipeline.always_check_rules);

                let mut search_name = qname;
                loop {
                    if let Some(indices) = pipeline.domain_suffix_index.get(search_name) {
                        candidates.extend_from_slice(indices);
                    }

                    if let Some(idx) = search_name.find('.') {
                        search_name = &search_name[idx + 1..];
                    } else {
                        break;
                    }
                }

                candidates.sort_unstable();
                candidates.dedup();
            }

            // 3. Execute Rules
            'rules: for &idx in candidates.iter() {
                let rule = match pipeline.rules.get(idx) {
                    Some(r) => r,
                    None => continue,
                };
                if skip_rules.map_or(false, |set| set.contains(&rule.name)) {
                    continue;
                }
                let req_match = eval_match_chain(
                    &rule.matchers,
                    |m| m.operator,
                    |m| matcher_matches(&m.matcher, qname, qclass, client_ip, edns_present),
                );

                if req_match {
                    for action in &rule.actions {
                        match action {
                            Action::StaticResponse { rcode } => {
                                let code = parse_rcode(&rcode).unwrap_or(ResponseCode::NXDomain);
                                let d = Decision::Static {
                                    rcode: code,
                                    answers: Vec::new(),
                                };
                                self.rule_cache.insert(
                                    rule_hash,
                                    RuleCacheEntry {
                                        pipeline_id: pipeline.id.clone(),
                                        qname_hash: fast_hash_str(qname),
                                        client_ip,
                                        decision: d.clone(),
                                    },
                                );
                                return Some(d);
                            }
                            Action::StaticIpResponse { ip } => {
                                if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                                    if let Ok(name) = std::str::FromStr::from_str(qname) {
                                        let rdata = match ip_addr {
                                            IpAddr::V4(v4) => RData::A(A(v4)),
                                            IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
                                        };
                                        let record = Record::from_rdata(name, 300, rdata);
                                        let d = Decision::Static {
                                            rcode: ResponseCode::NoError,
                                            answers: vec![record],
                                        };
                                        self.rule_cache.insert(
                                            rule_hash,
                                            RuleCacheEntry {
                                                pipeline_id: pipeline.id.clone(),
                                                qname_hash: fast_hash_str(qname),
                                                client_ip,
                                                decision: d.clone(),
                                            },
                                        );
                                        return Some(d);
                                    }
                                }
                                let d = Decision::Static {
                                    rcode: ResponseCode::ServFail,
                                    answers: Vec::new(),
                                };
                                self.rule_cache.insert(
                                    rule_hash,
                                    RuleCacheEntry {
                                        pipeline_id: pipeline.id.clone(),
                                        qname_hash: fast_hash_str(qname),
                                        client_ip,
                                        decision: d.clone(),
                                    },
                                );
                                return Some(d);
                            }
                            Action::JumpToPipeline { pipeline: target } => {
                                let d = Decision::Jump {
                                    pipeline: target.clone(),
                                };
                                self.rule_cache.insert(
                                    rule_hash,
                                    RuleCacheEntry {
                                        pipeline_id: pipeline.id.clone(),
                                        qname_hash: fast_hash_str(qname),
                                        client_ip,
                                        decision: d.clone(),
                                    },
                                );
                                return Some(d);
                            }
                            Action::Allow => {
                                let d = Decision::Forward {
                                    upstream: state.pipeline.settings.default_upstream.clone(),
                                    response_matchers: Vec::new(),
                                    response_matcher_operator: crate::config::MatchOperator::And,
                                    response_actions_on_match: Vec::new(),
                                    response_actions_on_miss: Vec::new(),
                                    rule_name: rule.name.clone(),
                                    transport: Transport::Udp,
                                    continue_on_match: false,
                                    continue_on_miss: false,
                                    allow_reuse: true,
                                };
                                self.rule_cache.insert(
                                    rule_hash,
                                    RuleCacheEntry {
                                        pipeline_id: pipeline.id.clone(),
                                        qname_hash: fast_hash_str(qname),
                                        client_ip,
                                        decision: d.clone(),
                                    },
                                );
                                return Some(d);
                            }
                            Action::Deny => {
                                let d = Decision::Static {
                                    rcode: ResponseCode::Refused,
                                    answers: Vec::new(),
                                };
                                self.rule_cache.insert(
                                    rule_hash,
                                    RuleCacheEntry {
                                        pipeline_id: pipeline.id.clone(),
                                        qname_hash: fast_hash_str(qname),
                                        client_ip,
                                        decision: d.clone(),
                                    },
                                );
                                return Some(d);
                            }
                            Action::Forward {
                                upstream,
                                transport,
                            } => {
                                let upstream_addr = upstream
                                    .as_ref()
                                    .cloned()
                                    .unwrap_or_else(|| state.pipeline.settings.default_upstream.clone());
                                let continue_on_match = contains_continue(&rule.response_actions_on_match);
                                let continue_on_miss = contains_continue(&rule.response_actions_on_miss);
                                let d = Decision::Forward {
                                    upstream: upstream_addr,
                                    response_matchers: rule.response_matchers.clone(),
                                    response_matcher_operator: rule.response_matcher_operator,
                                    response_actions_on_match: rule.response_actions_on_match.clone(),
                                    response_actions_on_miss: rule.response_actions_on_miss.clone(),
                                    rule_name: rule.name.clone(),
                                    transport: transport.unwrap_or(Transport::Udp),
                                    continue_on_match,
                                    continue_on_miss,
                                    allow_reuse: false,
                                };
                                if !continue_on_match && !continue_on_miss {
                                    self.rule_cache.insert(
                                        rule_hash,
                                        RuleCacheEntry {
                                            pipeline_id: pipeline.id.clone(),
                                            qname_hash: fast_hash_str(qname),
                                            client_ip,
                                            decision: d.clone(),
                                        },
                                    );
                                }
                                return Some(d);
                            }
                            Action::Log { level } => {
                                log_match(level.as_deref(), rule.name.as_str(), qname, client_ip);
                            }
                            Action::Continue => {
                                continue 'rules;
                            }
                        }
                    }
                }
            }
            None
        });

        if let Some(d) = decision {
            return d;
        }

        let d = Decision::Forward {
            upstream: state.pipeline.settings.default_upstream.clone(),
            response_matchers: Vec::new(),
            response_matcher_operator: crate::config::MatchOperator::And,
            response_actions_on_match: Vec::new(),
            response_actions_on_miss: Vec::new(),
            rule_name: "default".to_string(),
            transport: Transport::Udp,
            continue_on_match: false,
            continue_on_miss: false,
            allow_reuse: false,
        };
        self.rule_cache.insert(
            rule_hash,
            RuleCacheEntry {
                pipeline_id: pipeline.id.clone(),
                qname_hash: fast_hash_str(qname),
                client_ip,
                decision: d.clone(),
            },
        );
        d
    }

    async fn forward_upstream(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
        transport: Transport,
    ) -> anyhow::Result<Bytes> {
        let start = std::time::Instant::now();
        let res = match transport {
            Transport::Udp => self.forward_udp_smart(packet, upstream, timeout_dur).await,
            Transport::Tcp => self.tcp_mux.send(packet, upstream, timeout_dur).await,
        };
        if let Ok(_) = &res {
            let dur = start.elapsed();
            self.metrics_upstream_calls.fetch_add(1, Ordering::Relaxed);
            self.metrics_upstream_ns_total.fetch_add(dur.as_nanos() as u64, Ordering::Relaxed);
            tracing::debug!(upstream=%upstream, upstream_ns = dur.as_nanos() as u64, "upstream call latency");
        } else if let Err(e) = &res {
            let dur = start.elapsed();
            tracing::warn!(upstream=%upstream, error=%e, elapsed_ns = dur.as_nanos() as u64, "upstream call failed");
        }
        res
    }

    /// UDP forwarder with hedged retry and TCP fallback for better tail latency.
    async fn forward_udp_smart(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        // Split timeout: first attempt uses half budget, second uses full budget.
        let hedge_timeout = timeout_dur
            .checked_div(2)
            .unwrap_or_else(|| Duration::from_millis(50).max(timeout_dur));
        let attempts = [hedge_timeout, timeout_dur];

        for (idx, dur) in attempts.iter().enumerate() {
            match self.udp_client.send(packet, upstream, *dur).await {
                Ok(bytes) => return Ok(bytes),
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
                        return self.tcp_mux.send(packet, upstream, timeout_dur).await;
                    }
                }
            }
        }

        // Should never reach here because we either return on success or fallback.
        anyhow::bail!("udp forward failed")
    }

    async fn notify_inflight_waiters(&self, dedupe_hash: u64, bytes: &Bytes) {
        let waiters = self.inflight.remove(&dedupe_hash).map(|(_, v)| v).unwrap_or_default();
        for tx in waiters {
            let _ = tx.send(Ok(bytes.clone()));
        }
    }

    async fn apply_response_actions(
        &self,
        actions: &[Action],
        mut ctx_opt: Option<ResponseContext>,
        req: &Message,
        packet: &[u8],
        upstream_timeout: Duration,
        response_matchers: &[RuntimeResponseMatcherWithOp],
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
        client_ip: IpAddr,
        upstream_default: &str,
        pipeline_id: &str,
        rule_name: &str,
        remaining_jumps: usize,
    ) -> anyhow::Result<ResponseActionResult> {
        const MAX_RESPONSE_FORWARDS: usize = 4;
        let mut forward_attempts = 0usize;

        for action in actions {
            match action {
                Action::Log { level } => {
                    log_match(level.as_deref(), rule_name, qname, client_ip);
                }
                Action::StaticResponse { rcode } => {
                    let code = parse_rcode(rcode).unwrap_or(ResponseCode::NXDomain);
                    let bytes = build_response(req, code, Vec::new())?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: code,
                        source: "response_action",
                    });
                }
                Action::StaticIpResponse { ip } => {
                    let (rcode, answers) = make_static_ip_answer(qname, ip);
                    let bytes = build_response(req, rcode, answers)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode,
                        source: "response_action",
                    });
                }
                Action::JumpToPipeline { pipeline } => {
                    if remaining_jumps == 0 {
                        let bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                        return Ok(ResponseActionResult::Static {
                            bytes,
                            rcode: ResponseCode::ServFail,
                            source: "response_action",
                        });
                    }
                    return Ok(ResponseActionResult::Jump {
                        pipeline: pipeline.clone(),
                        remaining_jumps: remaining_jumps - 1,
                    });
                }
                Action::Allow => {
                    if let Some(ctx) = ctx_opt {
                        let resp_match = eval_match_chain(
                            response_matchers,
                            |m| m.operator,
                            |m| m.matcher.matches(&ctx.upstream, qname, qtype, qclass, &ctx.msg),
                        );
                        return Ok(ResponseActionResult::Upstream { ctx, resp_match });
                    }
                    let bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        source: "response_action",
                    });
                }
                Action::Deny => {
                    let bytes = build_response(req, ResponseCode::Refused, Vec::new())?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::Refused,
                        source: "response_action",
                    });
                }
                Action::Continue => {
                    return Ok(ResponseActionResult::Continue { ctx: ctx_opt });
                }
                Action::Forward {
                    upstream,
                    transport,
                } => {
                    forward_attempts += 1;
                    if forward_attempts > MAX_RESPONSE_FORWARDS {
                        warn!(
                            event = "dns_response",
                            qname = %qname,
                            qtype = ?qtype,
                            client_ip = %client_ip,
                            pipeline = %pipeline_id,
                            rule = %rule_name,
                            "response actions exceeded forward limit"
                        );
                        let bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                        return Ok(ResponseActionResult::Static {
                            bytes,
                            rcode: ResponseCode::ServFail,
                            source: "response_action",
                        });
                    }

                    let upstream_addr = upstream.as_ref().cloned().unwrap_or_else(|| {
                        ctx_opt
                            .as_ref()
                            .map(|ctx| ctx.upstream.clone())
                            .unwrap_or_else(|| upstream_default.to_string())
                    });
                    let use_transport = transport.unwrap_or(Transport::Udp);
                    let raw = match self
                        .forward_upstream(packet, &upstream_addr, upstream_timeout, use_transport)
                        .await
                    {
                        Ok(bytes) => bytes,
                        Err(err) => {
                            warn!(
                                event = "dns_response",
                                upstream = %upstream_addr,
                                qname = %qname,
                                qtype = ?qtype,
                                client_ip = %client_ip,
                                pipeline = %pipeline_id,
                                rule = %rule_name,
                                error = %err,
                                "response action forward failed"
                            );
                            let bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                            return Ok(ResponseActionResult::Static {
                                bytes,
                                rcode: ResponseCode::ServFail,
                                source: "response_action",
                            });
                        }
                    };
                    let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                    ctx_opt = Some(ResponseContext {
                        raw,
                        msg,
                        upstream: upstream_addr,
                        transport: use_transport,
                    });
                }
            }
        }

        if let Some(ctx) = ctx_opt {
            let resp_match = eval_match_chain(
                response_matchers,
                |m| m.operator,
                |m| m.matcher.matches(&ctx.upstream, qname, qtype, qclass, &ctx.msg),
            );
            return Ok(ResponseActionResult::Upstream { ctx, resp_match });
        }

        let bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
        Ok(ResponseActionResult::Static {
            bytes,
            rcode: ResponseCode::ServFail,
            source: "response_action",
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_response_jump(
        &self,
        state: &EngineInner,
        mut pipeline_id: String,
        mut remaining_jumps: usize,
        req: &Message,
        packet: &[u8],
        peer: SocketAddr,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
        edns_present: bool,
        min_ttl: Duration,
        upstream_timeout: Duration,
    ) -> anyhow::Result<Bytes> {
        let cfg = &state.pipeline;
        struct InflightCleanupGuard {
            inflight: Arc<DashMap<u64, Vec<oneshot::Sender<anyhow::Result<Bytes>>>, FxBuildHasher>>,
            hash: u64,
            active: bool,
        }

        impl InflightCleanupGuard {
            fn new(inflight: Arc<DashMap<u64, Vec<oneshot::Sender<anyhow::Result<Bytes>>>, FxBuildHasher>>, hash: u64) -> Self {
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

        let mut skip_rules = HashSet::new();
        let mut reused_response: Option<ResponseContext> = None;
        let mut inflight_hashes = Vec::new();
        let mut cleanup_guards: Vec<InflightCleanupGuard> = Vec::new();

        loop {
            if remaining_jumps == 0 {
                let resp_bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                for g in &mut cleanup_guards { g.defuse(); }
                for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
                return Ok(resp_bytes);
            }

            let Some(pipeline) = state.pipeline.pipelines.iter().find(|p| p.id.as_ref() == pipeline_id) else {
                let resp_bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                for g in &mut cleanup_guards { g.defuse(); }
                for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
                return Ok(resp_bytes);
            };

            let dedupe_hash = Self::calculate_cache_hash_for_dedupe(&pipeline_id, qname, qtype);
            
            let mut decision = self.apply_rules(
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
            );

            // Resolve nested rule-level jumps first
            let mut local_jumps = remaining_jumps;
            loop {
                if let Decision::Jump { pipeline } = decision {
                    if local_jumps == 0 {
                        let resp_bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                        for g in &mut cleanup_guards { g.defuse(); }
                        for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
                        return Ok(resp_bytes);
                    }
                    pipeline_id = pipeline;
                    local_jumps -= 1;
                    if let Some(next_pipeline) = state.pipeline.pipelines.iter().find(|p| p.id.as_ref() == pipeline_id) {
                        skip_rules.clear();
                        decision = self.apply_rules(
                            state,
                            next_pipeline,
                            peer.ip(),
                            qname,
                            qtype,
                            qclass,
                            edns_present,
                            None,
                        );
                        continue;
                    } else {
                        let resp_bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                        for g in &mut cleanup_guards { g.defuse(); }
                        for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
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
                        qname: Arc::from(qname),
                        pipeline_id: Arc::from(pipeline_id.as_str()),
                        qtype: u16::from(qtype),
                    };
                    self.cache.insert(dedupe_hash, entry);
                    for g in &mut cleanup_guards { g.defuse(); }
                    for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
                    return Ok(resp_bytes);
                }
                Decision::Forward {
                    upstream,
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
                            Ok(ctx.raw)
                        } else {
                            {
                                use dashmap::mapref::entry::Entry;
                                let rx = match self.inflight.entry(dedupe_hash) {
                                    Entry::Occupied(mut entry) => {
                                        let (tx, rx) = oneshot::channel();
                                        entry.get_mut().push(tx);
                                        Some(rx)
                                    }
                                    Entry::Vacant(entry) => {
                                        entry.insert(Vec::new());
                                        cleanup_guards.push(InflightCleanupGuard::new(self.inflight.clone(), dedupe_hash));
                                        inflight_hashes.push(dedupe_hash);
                                        None
                                    }
                                };

                                if let Some(rx) = rx {
                                    match rx.await {
                                        Ok(Ok(bytes)) => {
                                            // Rewrite Transaction ID for followers
                                            let mut resp_vec = bytes.to_vec();
                                            if resp_vec.len() >= 2 {
                                                let id_bytes = req.id().to_be_bytes();
                                                resp_vec[0] = id_bytes[0];
                                                resp_vec[1] = id_bytes[1];
                                            }
                                            let resp_bytes = Bytes::from(resp_vec);

                                            for g in &mut cleanup_guards { g.defuse(); }
                                            for h in &inflight_hashes { self.notify_inflight_waiters(*h, &bytes).await; }
                                            return Ok(resp_bytes);
                                        }
                                        Ok(Err(e)) => return Err(e),
                                        Err(_) => {
                                            // sender dropped, fallthrough to attempt upstream
                                        }
                                    }
                                }
                            }
                            self.forward_upstream(packet, &upstream, upstream_timeout, transport).await
                        }
                    } else {
                        // If reuse is not allowed (e.g. explicit Forward action), we must clear any reused response
                        // and force a new request.
                        
                        {
                            use dashmap::mapref::entry::Entry;
                            let rx = match self.inflight.entry(dedupe_hash) {
                                Entry::Occupied(mut entry) => {
                                    let (tx, rx) = oneshot::channel();
                                    entry.get_mut().push(tx);
                                    Some(rx)
                                }
                                Entry::Vacant(entry) => {
                                    entry.insert(Vec::new());
                                    cleanup_guards.push(InflightCleanupGuard::new(self.inflight.clone(), dedupe_hash));
                                    inflight_hashes.push(dedupe_hash);
                                    None
                                }
                            };

                            if let Some(rx) = rx {
                                match rx.await {
                                    Ok(Ok(bytes)) => {
                                        // Rewrite Transaction ID for followers
                                        let mut resp_vec = bytes.to_vec();
                                        if resp_vec.len() >= 2 {
                                            let id_bytes = req.id().to_be_bytes();
                                            resp_vec[0] = id_bytes[0];
                                            resp_vec[1] = id_bytes[1];
                                        }
                                        let resp_bytes = Bytes::from(resp_vec);

                                        for g in &mut cleanup_guards { g.defuse(); }
                                        for h in &inflight_hashes { self.notify_inflight_waiters(*h, &bytes).await; }
                                        return Ok(resp_bytes);
                                    }
                                    Ok(Err(e)) => return Err(e),
                                    Err(_) => {
                                        // sender dropped, fallthrough to attempt upstream
                                    }
                                }
                            }
                        }
                        self.forward_upstream(packet, &upstream, upstream_timeout, transport).await
                    };

                    match resp {
                        Ok(raw) => {
                            let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                            let ttl_secs = extract_ttl(&msg);
                            let effective_ttl = Duration::from_secs(ttl_secs.max(min_ttl.as_secs()));

                            let resp_match_ok = eval_match_chain(
                                &response_matchers,
                                |m| m.operator,
                                |m| m.matcher.matches(&upstream, qname, qtype, qclass, &msg),
                            );

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
                                        source: Arc::from(upstream.as_str()),
                                        qname: Arc::from(qname),
                                        pipeline_id: Arc::from(pipeline_id.as_str()),
                                        qtype: u16::from(qtype),
                                    };
                                    self.cache.insert(dedupe_hash, entry);
                                }
                                for g in &mut cleanup_guards { g.defuse(); }
                                for h in &inflight_hashes { self.notify_inflight_waiters(*h, &raw).await; }
                                return Ok(raw);
                            }

                            let ctx = ResponseContext {
                                raw,
                                msg,
                                upstream: upstream.clone(),
                                transport,
                            };
                            let action_result = self
                                .apply_response_actions(
                                    actions_to_run,
                                    Some(ctx),
                                    req,
                                    packet,
                                    upstream_timeout,
                                    &response_matchers,
                                    qname,
                                    qtype,
                                    qclass,
                                    peer.ip(),
                                    cfg.settings.default_upstream.as_str(),
                                    &pipeline_id,
                                    &rule_name,
                                    remaining_jumps,
                                )
                                .await?;

                            match action_result {
                                ResponseActionResult::Upstream { ctx, resp_match } => {
                                    let ttl_secs = extract_ttl(&ctx.msg);
                                    let effective_ttl =
                                        Duration::from_secs(ttl_secs.max(min_ttl.as_secs()));
                                    if resp_match && effective_ttl > Duration::from_secs(0) {
                                        let entry = CacheEntry {
                                            bytes: ctx.raw.clone(),
                                            rcode: ctx.msg.response_code(),
                                            source: Arc::from(ctx.upstream.as_str()),
                                            qname: Arc::from(qname),
                                            pipeline_id: Arc::from(pipeline_id.as_str()),
                                            qtype: u16::from(qtype),
                                        };
                                        self.cache.insert(dedupe_hash, entry);
                                    }
                                    for g in &mut cleanup_guards { g.defuse(); }
                                    for h in &inflight_hashes { self.notify_inflight_waiters(*h, &ctx.raw).await; }
                                    return Ok(ctx.raw);
                                }
                                ResponseActionResult::Static { bytes, .. } => {
                                    for g in &mut cleanup_guards { g.defuse(); }
                                    for h in &inflight_hashes { self.notify_inflight_waiters(*h, &bytes).await; }
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
                            let resp_bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                            for g in &mut cleanup_guards { g.defuse(); }
                            for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
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
                        let resp_bytes = build_response(req, ResponseCode::ServFail, Vec::new())?;
                        return Ok(resp_bytes);
                    }
                }
            }
        }
    }
}

fn select_pipeline<'a>(
    cfg: &'a RuntimePipelineConfig,
    qname: &str,
    client_ip: IpAddr,
    qclass: DNSClass,
    edns_present: bool,
    listener_label: &str,
) -> (Option<&'a RuntimePipeline>, String) {
    for rule in &cfg.pipeline_select {
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| m.matcher.matches(listener_label, client_ip, qname, qclass, edns_present),
        );
        if matched {
            if let Some(p) = cfg.pipelines.iter().find(|p| p.id.as_ref() == rule.pipeline) {
                return (Some(p), p.id.to_string());
            }
        }
    }

    match cfg.pipelines.first() {
        Some(p) => (Some(p), p.id.to_string()),
        None => (None, "default".to_string()),
    }
}

impl Engine {
    #[inline]
    fn compiled_for(&self, state: &EngineInner, pipeline_id: &str) -> Option<CompiledPipeline> {
        state.compiled_pipelines
            .iter()
            .find(|p| p.id.as_ref() == pipeline_id)
            .cloned()
    }
}

struct UdpSocketState {
    socket: Arc<UdpSocket>,
    // Key: Upstream ID (newly generated)
    // Value: (Original ID, Upstream Address, Sender)
    inflight: Arc<DashMap<u16, (u16, SocketAddr, oneshot::Sender<anyhow::Result<Bytes>>)>>,
    next_id: AtomicU16,
}

/// 高性能 UDP 客户端池，使用 channel 分发 socket / High-performance UDP client pool using channel for socket distribution
struct UdpClient {
    pool: Vec<UdpSocketState>,
    next_idx: AtomicUsize,
}

impl UdpClient {
    fn new(size: usize) -> Self {
        let mut pool = Vec::with_capacity(size);
        if size > 0 {
            for _ in 0..size {
                // Use socket2 to set buffer sizes
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).expect("create socket");
                // Set buffer sizes to 4MB to prevent packet loss under load
                if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
                    warn!("failed to set udp recv buffer size: {}", e);
                }
                if let Err(e) = socket.set_send_buffer_size(4 * 1024 * 1024) {
                    warn!("failed to set udp send buffer size: {}", e);
                }
                socket.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into()).expect("bind");
                socket.set_nonblocking(true).expect("set nonblocking");
                
                let std_sock: std::net::UdpSocket = socket.into();
                let socket = Arc::new(tokio::net::UdpSocket::from_std(std_sock).expect("from_std"));
                let inflight = Arc::new(DashMap::new());
                
                let state = UdpSocketState {
                    socket: socket.clone(),
                    inflight: inflight.clone(),
                    next_id: AtomicU16::new(0),
                };
                pool.push(state);

                let socket_clone = socket.clone();
                let inflight_clone = inflight.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match socket_clone.recv_from(&mut buf).await {
                            Ok((len, src)) => {
                                if len >= 2 {
                                    let id = u16::from_be_bytes([buf[0], buf[1]]);
                                    if let Some((_, (original_id, expected_addr, tx))) = inflight_clone.remove(&id) {
                                        if src == expected_addr {
                                            // Restore original ID
                                            let mut resp_data = buf[..len].to_vec();
                                            let orig_bytes = original_id.to_be_bytes();
                                            resp_data[0] = orig_bytes[0];
                                            resp_data[1] = orig_bytes[1];
                                            let _ = tx.send(Ok(Bytes::from(resp_data)));
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("UDP pool recv error: {}", e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                });
            }
        }
        Self {
            pool,
            next_idx: AtomicUsize::new(0),
        }
    }

    #[inline]
    async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        if self.pool.is_empty() {
            // Use a fresh socket for every request to avoid race conditions
            // caused by sharing sockets in the pool without a dispatcher.
            // Use socket2 to set buffer sizes
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).context("create socket")?;
            if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
                warn!("failed to set udp recv buffer size: {}", e);
            }
            if let Err(e) = socket.set_send_buffer_size(4 * 1024 * 1024) {
                warn!("failed to set udp send buffer size: {}", e);
            }
            socket.bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into()).context("bind")?;
            socket.set_nonblocking(true).context("set nonblocking")?;
            let sock = tokio::net::UdpSocket::from_std(socket.into()).context("from_std")?;

            let addr: SocketAddr = upstream.parse().context("invalid upstream address")?;
            sock.connect(addr).await?;
            sock.send(packet).await?;

            let mut buf = [0u8; 4096];
            let recv_res = timeout(timeout_dur, async {
                loop {
                    let size = sock.recv(&mut buf).await?;
                    // Since we connected to the upstream, we only receive packets from it.
                    // And since it's a fresh socket, any packet is likely our response.
                    if size >= 2 && packet.len() >= 2 {
                        if buf[0] == packet[0] && buf[1] == packet[1] {
                            return Ok::<_, anyhow::Error>(Bytes::copy_from_slice(&buf[..size]));
                        }
                    } else {
                        // Fallback for weird packets, though DNS should have ID.
                        return Ok::<_, anyhow::Error>(Bytes::copy_from_slice(&buf[..size]));
                    }
                }
            })
            .await;

            return match recv_res {
                Ok(Ok(bytes)) => Ok(bytes),
                Ok(Err(err)) => Err(err),
                Err(_) => anyhow::bail!("udp timeout"),
            };
        }

        // Pool logic
        let idx = self.next_idx.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        let state = &self.pool[idx];
        let addr: SocketAddr = upstream.parse().context("invalid upstream address")?;

        if packet.len() < 2 {
            return Err(anyhow::anyhow!("packet too short"));
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // Find a free ID
        let mut attempts = 0;
        let mut new_id;
        loop {
            new_id = state.next_id.fetch_add(1, Ordering::AcqRel);
            if !state.inflight.contains_key(&new_id) {
                break;
            }
            attempts += 1;
            if attempts > 100 {
                warn!("udp pool exhausted: socket_idx={} inflight_count={}", idx, state.inflight.len());
                return Err(anyhow::anyhow!("udp pool exhausted (too many inflight requests)"));
            }
        }

        let (tx, rx) = oneshot::channel();
        state.inflight.insert(new_id, (original_id, addr, tx));

        // Rewrite packet with new ID
        let mut new_packet = packet.to_vec();
        let id_bytes = new_id.to_be_bytes();
        new_packet[0] = id_bytes[0];
        new_packet[1] = id_bytes[1];

        if let Err(e) = state.socket.send_to(&new_packet, addr).await {
            state.inflight.remove(&new_id);
            return Err(e.into());
        }

        match timeout(timeout_dur, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(anyhow::anyhow!("channel closed")),
            Err(_) => {
                state.inflight.remove(&new_id);
                Err(anyhow::anyhow!("upstream timeout"))
            }
        }
    }
}

/// TCP 连接复用器，使用 DashMap 管理连接池 / TCP connection multiplexer, managing connection pool with DashMap
struct TcpMultiplexer {
    pools: dashmap::DashMap<String, Arc<TcpConnectionPool>>,
    pool_size: usize,
}

struct TcpConnectionPool {
    clients: Vec<Arc<TcpMuxClient>>,
    next_idx: AtomicUsize,
}

impl TcpMultiplexer {
    fn new(pool_size: usize) -> Self {
        Self {
            pools: dashmap::DashMap::new(),
            pool_size,
        }
    }

    #[inline]
    async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let pool = self
            .pools
            .entry(upstream.to_string())
            .or_insert_with(|| {
                let mut clients = Vec::with_capacity(self.pool_size);
                let size = if self.pool_size == 0 { 1 } else { self.pool_size };
                for _ in 0..size {
                    clients.push(Arc::new(TcpMuxClient::new(upstream.to_string())));
                }
                Arc::new(TcpConnectionPool {
                    clients,
                    next_idx: AtomicUsize::new(0),
                })
            })
            .clone();
        
        let idx = pool.next_idx.fetch_add(1, Ordering::Relaxed) % pool.clients.len();
        pool.clients[idx].send(packet, timeout_dur).await
    }
}

struct TcpMuxClient {
    upstream: String,
    conn: Arc<Mutex<Option<OwnedWriteHalf>>>,
    pending: Arc<dashmap::DashMap<u16, Pending>>,
    next_id: AtomicU16,
    inflight_limit: Arc<Semaphore>,
    write_lock: Mutex<()>,
}

struct Pending {
    original_id: u16,
    tx: oneshot::Sender<anyhow::Result<Bytes>>,
}

impl TcpMuxClient {
    fn new(upstream: String) -> Self {
        Self {
            upstream,
            conn: Arc::new(Mutex::new(None)),
            pending: Arc::new(dashmap::DashMap::new()),
            next_id: AtomicU16::new(1),
            inflight_limit: Arc::new(Semaphore::new(128)),
            write_lock: Mutex::new(()),
        }
    }

    async fn ensure_conn(&self) -> anyhow::Result<()> {
        let mut guard = self.conn.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let stream = TcpStream::connect(&self.upstream).await?;
        let (read_half, write_half) = stream.into_split();
        *guard = Some(write_half);
        drop(guard);
        self.spawn_reader(read_half).await;
        Ok(())
    }

    async fn spawn_reader(&self, mut reader: OwnedReadHalf) {
        let pending = Arc::clone(&self.pending);
        let upstream = self.upstream.clone();
        let conn = Arc::clone(&self.conn);
        tokio::spawn(async move {
            loop {
                let mut len_buf = [0u8; 2];
                if let Err(err) = reader.read_exact(&mut len_buf).await {
                    debug!(target = "tcp_mux", upstream = %upstream, error = %err, "tcp read len failed");
                    Self::fail_all_async(&pending, anyhow::anyhow!("tcp read len failed"), &conn)
                        .await;
                    break;
                }
                let resp_len = u16::from_be_bytes(len_buf) as usize;
                let mut buf = vec![0u8; resp_len];
                if let Err(err) = reader.read_exact(&mut buf).await {
                    debug!(target = "tcp_mux", upstream = %upstream, error = %err, "tcp read body failed");
                    Self::fail_all_async(&pending, anyhow::anyhow!("tcp read body failed"), &conn)
                        .await;
                    break;
                }

                if resp_len < 2 {
                    continue;
                }
                let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                if let Some((_, p)) = pending.remove(&resp_id) {
                    buf[0..2].copy_from_slice(&p.original_id.to_be_bytes());
                    let _ = p.tx.send(Ok(Bytes::from(buf)));
                } else {
                    debug!(target = "tcp_mux", upstream = %upstream, resp_id, "response with unknown id");
                }
            }
        });
    }

    async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for tcp");
        }
        
        // 1. Acquire semaphore with timeout
        let _permit = timeout(timeout_dur, self.inflight_limit.acquire())
            .await
            .map_err(|_| anyhow::anyhow!("tcp inflight limit semaphore timeout"))??;

        let elapsed = start.elapsed();
        if elapsed >= timeout_dur {
             anyhow::bail!("tcp timeout before processing");
        }
        let remaining = timeout_dur - elapsed;

        let original_id = u16::from_be_bytes([packet[0], packet[1]]);
        let (mut new_packet, new_id) = self.rewrite_id(packet).await?;

        let (tx, rx) = oneshot::channel();
        self.pending.insert(new_id, Pending { original_id, tx });

        // 2. Ensure connection and write with remaining timeout
        let write_res = timeout(remaining, async {
            self.ensure_conn().await?;
            let mut out = Vec::with_capacity(2 + new_packet.len());
            out.extend_from_slice(&(new_packet.len() as u16).to_be_bytes());
            out.append(&mut new_packet);

            let _wguard = self.write_lock.lock().await;
            let mut guard = self.conn.lock().await;
            let writer = guard.as_mut().context("tcp write half missing")?;
            writer.write_all(&out).await?;
            Ok::<(), anyhow::Error>(())
        }).await;

        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                self.remove_pending(new_id).await;
                Self::reset_conn(&self.conn).await;
                return Err(err);
            }
            Err(_) => {
                self.remove_pending(new_id).await;
                Self::reset_conn(&self.conn).await;
                anyhow::bail!("tcp write/connect timeout");
            }
        }

        // 3. Wait for response
        let elapsed_after_write = start.elapsed();
        if elapsed_after_write >= timeout_dur {
            self.remove_pending(new_id).await;
            anyhow::bail!("tcp timeout waiting for response");
        }
        let final_remaining = timeout_dur - elapsed_after_write;

        let resp = match timeout(final_remaining, rx).await {
            Ok(Ok(r)) => r?,
            Ok(Err(_canceled)) => {
                self.remove_pending(new_id).await;
                anyhow::bail!("tcp response canceled")
            }
            Err(_elapsed) => {
                self.remove_pending(new_id).await;
                Self::reset_conn(&self.conn).await;
                anyhow::bail!("tcp response timeout")
            }
        };
        Ok(resp)
    }

    async fn rewrite_id(&self, packet: &[u8]) -> anyhow::Result<(Vec<u8>, u16)> {
        let mut tries = 0;
        let new_id = loop {
            let cand = self.next_id.fetch_add(1, Ordering::Relaxed);
            tries += 1;
            let in_use = self.pending.contains_key(&cand);
            if !in_use {
                break cand;
            }
            if tries > u16::MAX as usize {
                anyhow::bail!("no available dns ids for tcp mux");
            }
        };
        let mut buf = packet.to_vec();
        buf[0..2].copy_from_slice(&new_id.to_be_bytes());
        Ok((buf, new_id))
    }

    async fn remove_pending(&self, id: u16) {
        self.pending.remove(&id);
    }

    async fn fail_all_async(
        pending: &Arc<dashmap::DashMap<u16, Pending>>,
        err: anyhow::Error,
        conn: &Arc<Mutex<Option<OwnedWriteHalf>>>,
    ) {
        let err_msg = err.to_string();
        let keys: Vec<u16> = pending.iter().map(|item| *item.key()).collect();
        for key in keys {
            if let Some((_, p)) = pending.remove(&key) {
                let _ = p.tx.send(Err(anyhow::anyhow!(err_msg.clone())));
            }
        }
        Self::reset_conn(conn).await;
    }

    async fn reset_conn(conn: &Arc<Mutex<Option<OwnedWriteHalf>>>) {
        let mut cg = conn.lock().await;
        *cg = None;
    }
}

fn matcher_matches(
    matcher: &crate::matcher::RuntimeMatcher,
    qname: &str,
    qclass: DNSClass,
    client_ip: IpAddr,
    edns_present: bool,
) -> bool {
    matcher.matches(qname, qclass, client_ip, edns_present)
}

fn log_match(level: Option<&str>, rule_name: &str, qname: &str, client_ip: IpAddr) {
    match level.unwrap_or("info") {
        "trace" => {
            tracing::trace!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "trace")
        }
        "debug" => {
            tracing::debug!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "debug")
        }
        "warn" => {
            tracing::warn!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "warn")
        }
        "error" => {
            tracing::error!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "error")
        }
        _ => {
            tracing::info!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "info")
        }
    }
}

#[inline]
fn build_fast_static_response(
    tx_id: u16,
    qname: &str,
    qtype: u16,
    qclass: u16,
    rcode: ResponseCode,
    answers: &Vec<Record>,
) -> anyhow::Result<Bytes> {
    let mut msg = Message::new();
    msg.set_id(tx_id);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.set_recursion_available(true);
    msg.set_authoritative(false);
    msg.set_response_code(rcode);

    // Build question from quick parse data
    let name = Name::from_str(qname)?;
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(hickory_proto::rr::RecordType::from(qtype));
    let qclass = DNSClass::from(qclass);
    query.set_query_class(qclass);
    msg.add_query(query);

    for ans in answers {
        msg.add_answer(ans.clone());
    }

    let mut out = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut out);
        msg.emit(&mut encoder)?;
    }
    Ok(Bytes::from(out))
}

pub(crate) fn make_static_ip_answer(qname: &str, ip: &str) -> (ResponseCode, Vec<Record>) {
    if let Ok(ip_addr) = ip.parse::<IpAddr>() {
        if let Ok(name) = Name::from_str(qname) {
            let rdata = match ip_addr {
                IpAddr::V4(v4) => RData::A(A(v4)),
                IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
            };
            let record = Record::from_rdata(name, 300, rdata);
            return (ResponseCode::NoError, vec![record]);
        }
    }
    (ResponseCode::ServFail, Vec::new())
}

#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests {
    use super::*;
    use crate::config::{GlobalSettings, MatchOperator};
    use hickory_proto::rr::RecordType;
    use std::net::Ipv4Addr;
    use crate::matcher::RuntimeResponseMatcher;
    use futures::future::join_all;
    use tokio::time::{timeout, Duration};

    #[test]
    fn make_static_ip_answer_returns_ipv4_record() {
        let (rcode, answers) = make_static_ip_answer("example.com", "1.2.3.4");
        assert_eq!(rcode, ResponseCode::NoError);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].record_type(), RecordType::A);
    }

    #[test]
    fn make_static_ip_answer_returns_ipv6_record() {
        let (rcode, answers) = make_static_ip_answer("example.com", "2001:db8::1");
        assert_eq!(rcode, ResponseCode::NoError);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].record_type(), RecordType::AAAA);
    }

    #[tokio::test]
    async fn tcp_mux_rewrite_id_no_deadlock_under_contention() {
        // Prepare a client with many pending IDs to force contention on the pending lock.
        let client = Arc::new(TcpMuxClient::new("127.0.0.1:0".to_string()));
        for id in 1u16..200u16 {
            client.pending.insert(
                id,
                Pending {
                    original_id: id,
                    tx: oneshot::channel().0,
                },
            );
        }

        // Spawn many concurrent rewrite_id calls; they must all complete quickly and yield unique IDs.
        let tasks = (0..64)
            .map(|_| {
                let client = Arc::clone(&client);
                async move {
                    let dummy = vec![0u8; 4];
                    client.rewrite_id(&dummy).await.map(|(_, id)| id)
                }
            })
            .collect::<Vec<_>>();

        let results = timeout(Duration::from_millis(500), join_all(tasks))
            .await
            .expect("rewrite_id stalled under contention");

        let mut ids = std::collections::HashSet::new();
        for r in results {
            let id = r.expect("rewrite_id failed");
            assert!(ids.insert(id), "duplicate id allocated under contention");
        }
    }

    #[test]
    fn make_static_ip_answer_rejects_invalid_input() {
        let (rcode, answers) = make_static_ip_answer("example.com", "not-an-ip");
        assert_eq!(rcode, ResponseCode::ServFail);
        assert!(answers.is_empty());
    }

    #[test]
    fn pipeline_select_picks_matching_pipeline() {
        let raw = serde_json::json!({
            "pipelines": [
                { "id": "p1", "rules": [] },
                { "id": "p2", "rules": [] }
            ],
            "pipeline_select": [
                { "pipeline": "p2", "matchers": [ { "type": "listener_label", "value": "edge" } ] }
            ]
        });

        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

        let (opt, id) = select_pipeline(
            &runtime,
            "any.example.com",
            "127.0.0.1".parse().unwrap(),
            hickory_proto::rr::DNSClass::IN,
            false,
            "edge",
        );
        assert!(opt.is_some());
        assert_eq!(id, "p2");
    }

    #[test]
    fn pipeline_select_respects_match_operator_or() {
        let raw = serde_json::json!({
            "pipelines": [
                { "id": "p1", "rules": [] },
                { "id": "p2", "rules": [] }
            ],
            "pipeline_select": [
                {
                    "pipeline": "p2",
                    "matcher_operator": "or",
                    "matchers": [
                        { "type": "listener_label", "value": "edge" },
                        { "type": "domain_suffix", "value": ".internal" }
                    ]
                }
            ]
        });

        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

        let (opt, id) = select_pipeline(
            &runtime,
            "example.com",
            "127.0.0.1".parse().unwrap(),
            hickory_proto::rr::DNSClass::IN,
            false,
            "edge",
        );
        assert!(opt.is_some());
        assert_eq!(id, "p2");
    }

    #[allow(dead_code)]
    #[tokio::test]
    async fn apply_rules_static_and_forward_allow_jump() {
        // build a config with rules exercising StaticResponse, Forward, Allow, Jump
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "p",
                    "rules": [
                        {
                            "name": "static",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "static_response", "rcode": "NXDOMAIN" } ]
                        }
                    ]
                }
            ]
        });

        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg.clone()).expect("runtime");

        let arc = Arc::new(ArcSwap::from_pointee(runtime.clone()));
        let engine = Engine::new(arc.clone(), "lbl".to_string());

        // StaticResponse should return Static decision
        let decision = engine.apply_rules(
            &runtime,
            &runtime.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "a.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
        );
        match decision {
            Decision::Static { rcode, .. } => assert_eq!(rcode, ResponseCode::NXDomain),
            _ => panic!("expected static"),
        }

        // Now test Forward action returns Forward with provided upstream and response matchers
        let raw2 = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "p2",
                    "rules": [
                        {
                            "name": "fwd",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "forward", "upstream": "8.8.8.8:53" } ],
                            "response_matchers": [ { "type": "upstream_equals", "value": "8.8.8.8:53" } ],
                            "response_matcher_operator": "and"
                        }
                    ]
                }
            ]
        });
        let cfg2: crate::config::PipelineConfig = serde_json::from_value(raw2).expect("parse");
        let runtime2 = RuntimePipelineConfig::from_config(cfg2.clone()).expect("runtime");
        let arc2 = Arc::new(arc_swap::ArcSwap::from_pointee(runtime2.clone()));
        let engine2 = Engine::new(arc2.clone(), "lbl".to_string());

        let decision2 = engine2.apply_rules(
            &runtime2,
            &runtime2.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "x.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
        );
        match decision2 {
            Decision::Forward {
                upstream,
                response_matchers,
                response_matcher_operator,
                ..
            } => {
                assert_eq!(upstream, "8.8.8.8:53");
                assert_eq!(response_matchers.len(), 1);
                assert_eq!(response_matcher_operator, crate::config::MatchOperator::And);
            }
            _ => panic!("expected forward"),
        }

        // Allow action -> forward to default upstream
        let raw3 = serde_json::json!({
            "settings": { "default_upstream": "1.2.3.4:53" },
            "pipelines": [ { "id": "p3", "rules": [ { "name": "a", "matchers": [ { "type": "any" } ], "actions": [ { "type": "allow" } ] } ] } ]
        });
        let cfg3: crate::config::PipelineConfig = serde_json::from_value(raw3).expect("parse");
        let runtime3 = RuntimePipelineConfig::from_config(cfg3.clone()).expect("runtime");
        let arc3 = Arc::new(arc_swap::ArcSwap::from_pointee(runtime3.clone()));
        let engine3 = Engine::new(arc3.clone(), "lbl".to_string());

        let decision3 = engine3.apply_rules(
            &runtime3,
            &runtime3.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "y.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
        );
        match decision3 {
            Decision::Forward { upstream, .. } => assert_eq!(upstream, "1.2.3.4:53"),
            _ => panic!("expected forward from allow"),
        }

        // JumpToPipeline
        let raw4 = serde_json::json!({
            "pipelines": [ { "id": "p4", "rules": [ { "name": "j", "matchers": [ { "type": "any" } ], "actions": [ { "type": "jump_to_pipeline", "pipeline": "other" } ] } ] } ]
        });
        let cfg4: crate::config::PipelineConfig = serde_json::from_value(raw4).expect("parse");
        let runtime4 = RuntimePipelineConfig::from_config(cfg4.clone()).expect("runtime");
        let arc4 = Arc::new(arc_swap::ArcSwap::from_pointee(runtime4.clone()));
        let engine4 = Engine::new(arc4.clone(), "lbl".to_string());

        let decision4 = engine4.apply_rules(
            &runtime4,
            &runtime4.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "z.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
        );
        match decision4 {
            Decision::Jump { pipeline } => assert_eq!(pipeline, "other"),
            _ => panic!("expected jump"),
        }
    }

    const TEST_UPSTREAM: &str = "1.1.1.1:53";

    fn build_test_engine() -> Engine {
        let runtime = RuntimePipelineConfig {
            settings: GlobalSettings {
                default_upstream: TEST_UPSTREAM.to_string(),
                ..Default::default()
            },
            pipeline_select: Vec::new(),
            pipelines: Vec::new(),
        };
        let arc = Arc::new(arc_swap::ArcSwap::from_pointee(runtime.clone()));
        Engine::new(arc, "lbl".to_string())
    }

    fn build_response_context() -> ResponseContext {
        let mut msg = Message::new();
        msg.set_response_code(ResponseCode::NoError);
        let name = Name::from_str("example.com").expect("name");
        let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        msg.add_answer(record);
        ResponseContext {
            raw: Bytes::from_static(b"resp"),
            msg,
            upstream: TEST_UPSTREAM.to_string(),
            transport: Transport::Udp,
        }
    }

    #[tokio::test]
    async fn response_actions_allow_returns_upstream_on_match() {
        let engine = build_test_engine();
        let ctx = build_response_context();
        let req = Message::new();
        let actions = [Action::Allow];
        let response_matchers = vec![RuntimeResponseMatcherWithOp {
            operator: MatchOperator::And,
            matcher: RuntimeResponseMatcher::ResponseType { value: "A".into() },
        }];
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = engine
            .apply_response_actions(
                &actions,
                Some(ctx),
                &req,
                &packet,
                Duration::from_secs(1),
                &response_matchers,
                "example.com",
                RecordType::A,
                DNSClass::IN,
                client_ip,
                TEST_UPSTREAM,
                "pipeline",
                "rule",
                10,
            )
            .await
            .expect("response actions allow should succeed");

        match result {
            ResponseActionResult::Upstream { ctx, resp_match } => {
                assert!(resp_match);
                assert_eq!(ctx.upstream, TEST_UPSTREAM);
            }
            _ => panic!("expected upstream result"),
        }
    }

    #[tokio::test]
    async fn response_actions_allow_reports_miss_when_matchers_fail() {
        let engine = build_test_engine();
        let ctx = build_response_context();
        let req = Message::new();
        let actions = [Action::Allow];
        let response_matchers = vec![RuntimeResponseMatcherWithOp {
            operator: MatchOperator::And,
            matcher: RuntimeResponseMatcher::ResponseType {
                value: "AAAA".into(),
            },
        }];
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = engine
            .apply_response_actions(
                &actions,
                Some(ctx),
                &req,
                &packet,
                Duration::from_secs(1),
                &response_matchers,
                "example.com",
                RecordType::A,
                DNSClass::IN,
                client_ip,
                TEST_UPSTREAM,
                "pipeline",
                "rule",
                10,
            )
            .await
            .expect("response actions allow should succeed even on miss");

        match result {
            ResponseActionResult::Upstream { resp_match, .. } => assert!(!resp_match),
            _ => panic!("expected upstream result"),
        }
    }

    #[tokio::test]
    async fn response_actions_deny_returns_refused() {
        let engine = build_test_engine();
        let req = Message::new();
        let actions = [Action::Deny];
        let response_matchers: Vec<RuntimeResponseMatcherWithOp> = Vec::new();
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let result = engine
            .apply_response_actions(
                &actions,
                None,
                &req,
                &packet,
                Duration::from_secs(1),
                &response_matchers,
                "example.com",
                RecordType::A,
                DNSClass::IN,
                client_ip,
                TEST_UPSTREAM,
                "pipeline",
                "rule",
                10,
            )
            .await
            .expect("response actions deny should return static");

        match result {
            ResponseActionResult::Static { rcode, source, .. } => {
                assert_eq!(rcode, ResponseCode::Refused);
                assert_eq!(source, "response_action");
            }
            _ => panic!("expected static refused"),
        }
    }
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

#[inline]
fn build_response(
    req: &Message,
    rcode: ResponseCode,
    answers: Vec<Record>,
) -> anyhow::Result<Bytes> {
    let mut msg = Message::new();
    msg.set_id(req.id());
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(req.recursion_desired());
    msg.set_recursion_available(true);
    msg.set_authoritative(false);
    msg.set_response_code(rcode);

    let queries: Vec<Query> = req.queries().iter().cloned().collect();
    msg.add_queries(queries);
    for ans in answers {
        msg.add_answer(ans);
    }

    let mut out = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut out);
        msg.emit(&mut encoder)?;
    }
    Ok(Bytes::from(out))
}

fn extract_ttl(msg: &Message) -> u64 {
    let ttl_answers = msg
        .answers()
        .iter()
        .map(|r| r.ttl() as u64)
        .collect::<Vec<_>>();
    ttl_answers.into_iter().min().unwrap_or(0)
}

// 已使用 moka 自动过期缓存，无需手动 GC

#[derive(Debug, Clone)]
pub(crate) enum Decision {
    Static {
        rcode: ResponseCode,
        answers: Vec<Record>,
    },
    Forward {
        upstream: String,
        response_matchers: Vec<RuntimeResponseMatcherWithOp>,
        response_matcher_operator: crate::config::MatchOperator,
        response_actions_on_match: Vec<Action>,
        response_actions_on_miss: Vec<Action>,
        rule_name: String,
        transport: Transport,
        #[allow(dead_code)]
        continue_on_match: bool,
        #[allow(dead_code)]
        continue_on_miss: bool,
        allow_reuse: bool,
    },
    Jump {
        pipeline: String,
    },
}

#[derive(Clone, Debug)]
struct ResponseContext {
    raw: Bytes,
    msg: Message,
    upstream: String,
    transport: Transport,
}

#[derive(Debug)]
enum ResponseActionResult {
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
        pipeline: String,
        remaining_jumps: usize,
    },
    Continue {
        ctx: Option<ResponseContext>,
    },
}

#[inline]
fn calculate_rule_hash(pipeline_id: &str, qname: &str, client_ip: IpAddr) -> u64 {
    let mut hasher = FxHasher::default();
    pipeline_id.hash(&mut hasher);
    qname.hash(&mut hasher);
    client_ip.hash(&mut hasher);
    hasher.finish()
}

#[derive(Clone)]
struct RuleCacheEntry {
    pipeline_id: Arc<str>,
    qname_hash: u64,
    client_ip: IpAddr,
    decision: Decision,
}

impl RuleCacheEntry {
    #[inline]
    fn matches(&self, pipeline_id: &str, qname: &str, client_ip: IpAddr) -> bool {
        self.client_ip == client_ip
            && self.pipeline_id.as_ref() == pipeline_id
            && self.qname_hash == fast_hash_str(qname)
    }
}

#[inline]
fn fast_hash_str(s: &str) -> u64 {
    let mut h = FxHasher::default();
    s.hash(&mut h);
    h.finish()
}

fn contains_continue(actions: &[Action]) -> bool {
    actions.iter().any(|action| matches!(action, Action::Continue))
}


// Minimal fallback pipeline when none provided.
