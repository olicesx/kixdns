use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Context;

use bytes::Bytes;
use rustc_hash::FxHasher;

use hickory_proto::op::{Message, ResponseCode};
#[cfg(test)]
use hickory_proto::rr::rdata::A;
#[cfg(test)]
use hickory_proto::rr::Name;
use hickory_proto::rr::DNSClass;



use hickory_proto::serialize::binary::BinDecodable;
use tracing::warn;

use crate::cache::CacheEntry;
use crate::matcher::advanced_rule::{compile_pipelines, fast_static_match};
use crate::config::Transport;
use crate::matcher::RuntimePipelineConfig;
use crate::proto_utils::parse_quick;

use super::response::build_fast_static_response;
use super::types::{EngineInner, FastPathResponse};
use super::utils::{
    is_refreshing,
    engine_helpers,
};
use crate::engine::rules::{ResponseContext, calculate_rule_hash, Decision};



// ============================================================================
// Constants / 常量
// ============================================================================







use super::core::Engine;
use super::pipeline::select_pipeline;





// ============================================================================
// Refreshing Bitmap Helpers / 刷新位图辅助函数
// ============================================================================





impl Engine {


    /// Reload configuration and update compiled pipelines / 重新加载配置并更新编译后的管线
    pub fn reload(&self, new_cfg: RuntimePipelineConfig) {
        let compiled = compile_pipelines(&new_cfg);
        self.state.store(Arc::new(EngineInner {
            pipeline: new_cfg,
            compiled_pipelines: compiled,
        }));
        // Clear rule cache to ensure new rules take effect immediately / 清除规则缓存以确保新规则立即生效
        self.rule_cache.invalidate_all();
        // Reset background refresh rule to allow re-initialization with new config
        // 重置后台刷新规则以允许使用新配置重新初始化
        // Note: OnceLock cannot be reset, so we rely on the fact that the rule is
        // initialized from the current pipeline config via get_background_refresh_rule()
        // 注意：OnceLock 无法重置，所以我们依赖规则通过 get_background_refresh_rule()
        // 从当前 pipeline 配置初始化的事实
    }

    /// Get or initialize the background refresh dedicated rule
    /// 获取或初始化后台刷新专用规则
    /// 
    /// Design: Uses OnceLock for thread-safe lazy initialization
    /// 设计：使用 OnceLock 实现线程安全的延迟初始化
    /// - First call: Creates rule from config or default
    /// - Subsequent calls: Returns cached rule
    /// - 首次调用：从配置或默认创建规则
    /// - 后续调用：返回缓存的规则
    #[allow(dead_code)]
    fn get_background_refresh_rule(&self) -> Option<Arc<crate::matcher::RuntimeRule>> {
        // 暂时返回 None，等待 RuntimePipelineConfig 结构更新
        // Temporarily return None, waiting for RuntimePipelineConfig structure update
        None
    }

    /// 动态调整 flow control permits 基于系统负载和延迟 / Adaptively adjust flow control permits based on system load and latency
    pub fn adjust_flow_control(&self) {
        if let Some(state) = &self.flow_control_state {
            let latest_latency = self.metrics_last_upstream_latency_ns.load(Ordering::Relaxed);
            state.adjust(&self.permit_manager, latest_latency);
        }
    }

    /// Get the configured upstream timeout in milliseconds
    /// 获取配置的上游超时时间（毫秒）
    #[inline]
    pub fn get_upstream_timeout_ms(&self) -> u64 {
        self.state.load().pipeline.settings.upstream_timeout_ms
    }

    /// Get the overall request timeout in milliseconds (including hedge + TCP fallback)
    /// 获取整体请求超时时间（毫秒），包含 hedge + TCP fallback
    ///
    /// 如果用户显式配置了 request_timeout_ms，使用配置值
    /// 否则自动计算为 upstream_timeout_ms * 2.5
    /// If request_timeout_ms is explicitly configured, use that value
    /// Otherwise auto-calculate as upstream_timeout_ms * 2.5
    #[inline]
    pub fn get_request_timeout_ms(&self) -> u64 {
        let state = self.state.load();
        let settings = &state.pipeline.settings;

        // 如果用户显式配置了 request_timeout，使用配置值
        // If user explicitly configured request_timeout, use that value
        if let Some(timeout) = settings.request_timeout_ms {
            timeout
        } else {
            // 自动计算：hedge(1/3) + full(1x) + tcp_fallback(1x) + 余量
            // - hedge 通常提前返回，不计入最大时间
            // - 实际路径：hedge 尝试 → full 尝试 → tcp fallback
            // - 最大时间：upstream * 2.5（保守估计）
            // Auto-calculate: hedge(1/3) + full(1x) + tcp_fallback(1x) + margin
            // - hedge usually returns early, not counted in max time
            // - Actual path: hedge attempt → full attempt → tcp fallback
            // - Max time: upstream * 2.5 (conservative estimate)
            settings.upstream_timeout_ms * 5 / 2  // * 2.5
        }
    }

    /// Mark TCP external timeout for a specific upstream
    /// 标记特定上游的 TCP 外部超时
    ///
    /// 当 TCP worker 发生外部超时时调用此方法，记录错误并可能触发连接重置
    /// Call this method when TCP worker external timeout occurs, recording errors and possibly triggering connection reset
    pub fn mark_tcp_timeout(&self, upstream: &str) {
        self.tcp_mux.mark_timeout(upstream);
    }

    /// Increment total_requests counter using simple atomic operation
    #[inline]
    fn incr_total_requests(&self) {
        self.metrics_total_requests.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment fastpath_hits counter using simple atomic operation
    #[inline]
    fn incr_fastpath_hits(&self) {
        self.metrics_fastpath_hits.fetch_add(1, Ordering::Relaxed);
    }



    #[inline]
    pub fn calculate_cache_hash_for_dedupe(pipeline_id: &str, qname: &[u8], qtype: hickory_proto::rr::RecordType, qclass: hickory_proto::rr::DNSClass) -> u64 {
        let mut h = FxHasher::default();
        pipeline_id.hash(&mut h);
        // Hash qname case-insensitively without allocation / 不分配内存地进行不区分大小写的 qname 哈希
        // qname is already lowercased from parse_quick() / qname 已经在 parse_quick() 中转为小写
        for b in qname {
            h.write_u8(*b);
        }
        // RecordType implements Copy+Debug, hash by its u16 representation / RecordType 实现了 Copy+Debug，使用其 u16 表示进行哈希
        u16::from(qtype).hash(&mut h);
        // DNSClass implements Copy+Debug, hash by its u16 representation / DNSClass 实现了 Copy+Debug，使用其 u16 表示进行哈希
        u16::from(qclass).hash(&mut h);
        h.finish()
    }

    /// Helper: create and insert DNS cache entry / 辅助函数：创建并插入 DNS 缓存条目
    /// Eliminate duplicate CacheEntry construction code / 消除重复的 CacheEntry 构造代码
    #[inline]
    pub(crate) fn insert_dns_cache_entry(
        &self,
        cache_hash: u64,
        bytes: Bytes,
        rcode: ResponseCode,
        source: Arc<str>,
        upstream: Option<Arc<str>>,
        qname: &str,
        pipeline_id: Arc<str>,
        qtype: hickory_proto::rr::RecordType,
        original_ttl: u32,
    ) {
        let entry = CacheEntry {
            bytes,
            rcode,
            source,
            upstream,
            qname: Arc::from(qname),  // 一次 Arc::from，避免多次
            pipeline_id,
            qtype: u16::from(qtype),
            inserted_at: Instant::now(),
            original_ttl,
        };
        self.cache.insert(cache_hash, Arc::new(entry));
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

    /// Fast path: synchronous cache hit attempt / 快速路径：同步尝试缓存命中
    /// Return Ok(Some(bytes)) means cache hit, can return directly / 返回 Ok(Some(bytes)) 表示缓存命中，可直接返回
    /// Return Ok(None) means async processing needed (upstream forwarding) / 返回 Ok(None) 表示需要异步处理（上游转发）
    /// Return Err means parsing error / 返回 Err 表示解析错误
    #[inline]
    pub fn handle_packet_fast(
        &self,
        packet: &[u8],
        peer: SocketAddr,
    ) -> anyhow::Result<Option<FastPathResponse>> {
        // Quick parsing, avoiding full Message parsing and massive allocations / 快速解析，避免完整 Message 解析和大量分配
        // Use stack buffer to avoid String allocation / 使用栈上缓冲区避免 String 分配
        let mut qname_buf = [0u8; 256];
        let q = match parse_quick(packet, &mut qname_buf) {
            Some(q) => q,
            None => {
                // Quick parse failed, fallback to async path / 快速解析失败，回退到异步路径
                return Ok(None);
            }
        };
        // Count incoming quick-parsed requests / 计数进入的快速解析请求
        self.incr_total_requests();
        
        // Get pipeline ID / 获取 pipeline ID
        let state = self.state.load();
        let cfg = &state.pipeline;
        let qclass = DNSClass::from(q.qclass);
        let qtype = hickory_proto::rr::RecordType::from(q.qtype);
        // GeoSiteManager uses FxHashMap protected by RwLock, no additional locks needed
        // GeoSiteManager 使用 FxHashMap + RwLock 保护，无需额外锁
        // Use unchecked conversion for performance (qname_bytes is validated UTF-8)
        // 使用未检查转换以提高性能（qname_bytes 是已验证的 UTF-8）
        let qname_str = q.qname_str_unchecked();
        let (pipeline_opt, pipeline_id) = select_pipeline(
            cfg,
            qname_str,
            peer.ip(),
            qclass,
            q.edns_present,
            qtype,
            &self.listener_label,
            Some(&self.geosite_manager),
            Some(&self.geoip_manager),
        );
        
        // 1. Check Response Cache (L2) / 1. 检查响应缓存（L2）
        let cache_hash = Self::calculate_cache_hash_for_dedupe(&pipeline_id, q.qname_bytes, qtype, qclass);

        if let Some(hit) = self.cache.get(&cache_hash) {
            // Verify collision / 验证冲突
            if hit.qtype == u16::from(qtype) && q.qname_matches(hit.qname.as_ref()) && hit.pipeline_id == pipeline_id {
                // Check if expired / 检查是否已过期
                let elapsed_secs = hit.inserted_at.elapsed().as_secs() as u32;
                if elapsed_secs >= hit.original_ttl {
                    self.cache.invalidate(&cache_hash);
                } else {
                    // Cache background refresh: trigger async refresh when TTL < threshold percentage
                    // 缓存后台刷新：当TTL < 阈值百分比时，触发异步刷新
                    // Only refresh cache entries that came from an upstream server
                    // 只有来自 upstream 的缓存条目才进行预取刷新
                    if self.cache_background_refresh
                        && hit.upstream.is_some()
                        && hit.original_ttl >= self.cache_refresh_min_ttl
                    {
                        // Calculate remaining TTL and refresh threshold
                        // 计算剩余 TTL 和刷新阈值
                        let remaining_ttl = hit.original_ttl.saturating_sub(elapsed_secs);
                        let threshold = (hit.original_ttl as u64 * self.cache_refresh_threshold_percent as u64) / 100;

                        // OPTIMIZATION: Zero-lock check using bitmap / 优化：使用位图进行零锁检查
                        let is_refreshing = is_refreshing(&self.refreshing_bitmap, cache_hash);

                        tracing::warn!(
                            original_ttl = hit.original_ttl,
                            elapsed_secs = elapsed_secs,
                            remaining_ttl = remaining_ttl,
                            threshold_percent = self.cache_refresh_threshold_percent,
                            threshold_value = threshold,
                            min_ttl = self.cache_refresh_min_ttl,
                            is_refreshing = is_refreshing,
                            should_trigger = !is_refreshing && remaining_ttl as u64 <= threshold,
                            upstream = ?hit.upstream,
                            qname = %q.qname_str_unchecked(),  // Use unchecked for performance / 使用未检查版本以提高性能
                            "cache background refresh check"
                        );

                        if !is_refreshing && remaining_ttl as u64 <= threshold {
                            // Trigger background refresh (async, don't block current request)
                            // 触发后台刷新（异步，不阻塞当前请求）
                            // Note: RefreshingGuard inside spawn_background_refresh will handle cleanup
                            // 注意：spawn_background_refresh 内部的 RefreshingGuard 将处理清理
                            let qname_str = q.qname_str_unchecked();  // Zero-allocation / 零分配
                            tracing::warn!(
                                qname = %qname_str,
                                original_ttl = hit.original_ttl,
                                remaining_ttl = remaining_ttl,
                                "triggering background cache refresh"
                            );
                            self.spawn_background_refresh(
                                cache_hash,
                                &pipeline_id,
                                qname_str,
                                qtype,
                                qclass,
                                hit.upstream.as_deref(),
                            );
                        }
                    }

                    // Return current cache immediately, don't wait for refresh to complete
                    // 直接返回当前缓存，不等待刷新完成
                    // Next query will automatically use refreshed new cache (if completed)
                    // 下次查询时会自动使用刷新后的新缓存（如果已完成）
                    self.incr_fastpath_hits();
                    return Ok(Some(FastPathResponse::CacheHit {
                        cached: hit.bytes.clone(),
                        tx_id: q.tx_id,
                        inserted_at: hit.inserted_at,
                    }));
                }
            }
        }

        // 2. Compiled rule fast-path for static decisions / 2. 编译规则的静态决策快速路径
        if let Some(compiled) = self.compiled_for(&state, &pipeline_id) {
            let qclass = DNSClass::from(q.qclass);
            let qname_str = q.qname_str_unchecked();  // Zero-allocation / 零分配
            if let Some(decision) = fast_static_match(
                compiled,
                qname_str,
                qtype,
                qclass,
                peer.ip(),
                q.edns_present,
            ) {
                if let Decision::Static { rcode, answers } = decision {
                    let resp = build_fast_static_response(
                        q.tx_id,
                        qname_str,
                        q.qtype,
                        q.qclass,
                        rcode,
                        &answers,
                    )?;
                    self.incr_fastpath_hits();
                    return Ok(Some(FastPathResponse::Direct(resp)));
                }
            }
        }

        // 3. Check Rule Cache (L1) for Static Responses / 3. 检查规则缓存（L1）的静态响应
        // Zero-allocation lookup using hash / 使用哈希的零分配查找
        if let Some(p) = pipeline_opt {
            // Optimization: only include IP in hash when rule uses client_ip matcher or config requires it
            // 优化：仅当规则使用client_ip匹配器或配置要求时才包含IP在哈希中
            let include_ip_in_hash = p.uses_client_ip || self.cache_background_refresh;
            let rule_hash = calculate_rule_hash(&pipeline_id, qname_str, peer.ip(), include_ip_in_hash);
            if let Some(entry) = self.rule_cache.get(&rule_hash) {
                // Check if entry is valid before using
                // 在使用前检查条目是否有效
                if !entry.is_valid() {
                    // Remove expired entry
                    // 删除过期条目
                    self.rule_cache.remove(&rule_hash);
                } else if entry.matches(&pipeline_id, qname_str, peer.ip(), include_ip_in_hash) {
                    if let Decision::Static { rcode, answers } = entry.decision.as_ref() {
                        let resp = build_fast_static_response(
                            q.tx_id,
                            qname_str,
                            q.qtype,
                            q.qclass,
                            *rcode,
                            answers,
                        )?;
                        self.incr_fastpath_hits();
                        return Ok(Some(FastPathResponse::Direct(resp)));
                    }
                }
            }
        }
        
        // Cache miss, need async processing / 缓存未命中，需要异步处理
        Ok(None)
    }



    pub async fn handle_packet(&self, packet: &[u8], peer: SocketAddr) -> anyhow::Result<Bytes> {
        self.handle_packet_internal(packet, peer, false).await
    }

    /// Internal handle_packet implementation with skip_cache option
    /// 内部 handle_packet 实现，支持跳过缓存选项
    /// 
    /// Design: Background refresh calls this with skip_cache=true to:
    /// 设计：后台刷新使用 skip_cache=true 调用以：
    /// 1. Skip cache lookup (avoid returning stale cache)
    /// 2. Skip cache hit metrics (avoid inflating hit rate)
    /// 3. Always query upstream (get fresh data)
    /// 1. 跳过缓存查找（避免返回陈旧缓存）
    /// 2. 跳过缓存命中指标（避免虚高命中率）
    /// 3. 始终查询上游（获取最新数据）
    pub(crate) async fn handle_packet_internal(&self, packet: &[u8], peer: SocketAddr, skip_cache: bool) -> anyhow::Result<Bytes> {
        // Track requests and inflight concurrency for diagnostics. / 跟踪请求和进行中的并发以进行诊断
        let _req_id = self.request_id_counter.fetch_add(1, Ordering::Relaxed);
        self.incr_total_requests();
        struct InflightGuard<'a>(&'a AtomicUsize);
        impl<'a> Drop for InflightGuard<'a> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        self.metrics_inflight.fetch_add(1, Ordering::Relaxed);
        let _inflight_guard = InflightGuard(&self.metrics_inflight);
        let state = self.state.load();
        let cfg = &state.pipeline;
        let min_ttl = cfg.min_ttl();
        let upstream_timeout = cfg.upstream_timeout();
        let response_jump_limit = cfg.settings.response_jump_limit as usize;

        // Lazy Parse: Use quick parse first / 延迟解析：首先使用快速解析
        let mut qname_buf = [0u8; 256];
        let (qname_cow, qtype, qclass, tx_id, edns_present) = if let Some(q) = parse_quick(packet, &mut qname_buf) {
            // Use unchecked conversion to avoid double allocation / 使用未检查转换避免双重分配
            // SAFETY: qname_bytes is validated ASCII from parse_quick()
            // ASCII is always valid UTF-8, so this is safe
            // 安全性：qname_bytes 在 parse_quick() 中已验证为 ASCII
            // ASCII 始终是有效的 UTF-8，所以这是安全的
            //
            // In debug builds, we validate to catch any issues early
            // 在 debug 构建中，我们验证以尽早发现问题
            let qname_str = {
                #[cfg(debug_assertions)]
                {
                    std::str::from_utf8(q.qname_bytes).expect("qname_bytes should be valid UTF-8")
                }
                #[cfg(not(debug_assertions))]
                unsafe {
                    std::str::from_utf8_unchecked(q.qname_bytes)
                }
            };
            (std::borrow::Cow::Borrowed(qname_str), hickory_proto::rr::RecordType::from(q.qtype), DNSClass::from(q.qclass), q.tx_id, q.edns_present)
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

        // Scope geosite_mgr to ensure lock is released before await
        // 限制 geosite_mgr 的作用域，确保在 await 之前释放锁
        let (pipeline_opt, pipeline_id) = {
            // GeoSiteManager now uses DashMap, no Mutex lock needed
            // GeoSiteManager 现在使用 DashMap，无需 Mutex 锁
            select_pipeline(
                cfg,
                qname_ref,
                peer.ip(),
                qclass,
                edns_present,
                qtype,
                &self.listener_label,
                Some(&self.geosite_manager),
                Some(&self.geoip_manager),
            )
        }; // geosite_mgr 在这里释放 / geosite_mgr released here

        // Convert qname_ref to bytes for hash calculation / 将 qname_ref 转换为 bytes 进行哈希计算
        let qname_bytes = qname_ref.as_bytes();
        let dedupe_hash = Self::calculate_cache_hash_for_dedupe(&pipeline_id, qname_bytes, qtype, qclass);
        
        // Background refresh: Skip cache lookup when skip_cache=true
        // 后台刷新：当 skip_cache=true 时跳过缓存查找
        if !skip_cache {
            if let Some(resp_bytes) = phases::check_cache(
                self,
                qname_ref,
                qtype,
                qclass,
                &pipeline_id,
                dedupe_hash,
                tx_id,
                start,
                &peer,
            ) {
                return Ok(resp_bytes);
            }
        }

        let qname = qname_cow.into_owned();
        let mut skip_rules: HashSet<Arc<str>> = HashSet::new();
        let mut current_pipeline_id = pipeline_id.clone();
        // Convert qname String to bytes for hash calculation / 将 qname String 转换为 bytes 进行哈希计算
        let qname_bytes = qname.as_bytes();
        let mut dedupe_hash = Self::calculate_cache_hash_for_dedupe(&current_pipeline_id, qname_bytes, qtype, qclass);
        let mut reused_response: Option<ResponseContext> = None;

        let mut decision = match pipeline_opt {
            Some(p) => self.apply_rules(&state, p, peer.ip(), &qname, qtype, qclass, edns_present, None, skip_cache),
            None => {
                // 使用预分割的默认 upstream 以支持并发查询 / Use pre-split default upstream for concurrent queries
                let (upstream, pre_split) = if let Some(pre) = &cfg.settings.default_upstream_pre_split {
                    (Arc::from(cfg.settings.default_upstream.as_str()), Some(pre.clone()))
                } else {
                    (Arc::from(cfg.settings.default_upstream.as_str()), None)
                };
                
                Decision::Forward {
                    upstream,
                    pre_split_upstreams: pre_split,
                    response_matchers: Vec::new(),
                    response_matcher_operator: crate::config::MatchOperator::And,
                    response_actions_on_match: Vec::new(),
                    response_actions_on_miss: Vec::new(),
                    rule_name: Arc::from("default"),
                    transport: Some(Transport::Udp),
                    continue_on_match: false,
                    continue_on_miss: false,
                    allow_reuse: false,
                }
            },
        };

        // DESIGN NOTE: InflightCleanupGuard safety analysis
        // 设计说明：InflightCleanupGuard 安全性分析
        //
        // Safety Guarantee: No race condition exists
        // 安全性保证：不存在竞态条件
        //
        // The guard is always used as a local stack variable (never shared via Arc/Mutex).
        // Rust's ownership model guarantees that:
        // - Mutable borrow via as_mut() (for defuse()) and Drop execution are mutually exclusive
        // - The compiler prevents concurrent access at compile time
        //
        // 该守卫始终作为局部栈变量使用（从不通过 Arc/Mutex 共享）。
        // Rust 所有权模型保证：
        // - 通过 as_mut() 的可变借用（用于 defuse()）和 Drop 执行互斥
        // - 编译器在编译期阻止并发访问
        //
        // This is a standard Rust RAII pattern that is safe and idiomatic.
        // 这是标准的 Rust RAII 模式，安全且符合惯用法。

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
                    if let Some(p) = cfg.pipelines.iter().find(|p| p.id.as_ref() == pipeline.as_ref()) {
                        current_pipeline_id = p.id.clone();
                        dedupe_hash = Self::calculate_cache_hash_for_dedupe(&current_pipeline_id, qname_bytes, qtype, qclass);
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
                            skip_cache,
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
                return phases::handle_static_decision(
                    self,
                    packet,
                    &qname,
                    qtype,
                    &current_pipeline_id,
                    dedupe_hash,
                    min_ttl,
                    start,
                    &peer,
                    rcode,
                    answers,
                );
            }
            Decision::Forward {
                upstream,
                pre_split_upstreams,
                response_matchers,
                response_matcher_operator,
                response_actions_on_match,
                response_actions_on_miss,
                rule_name,
                transport,
                continue_on_match: _,
                continue_on_miss: _,
                allow_reuse,
            } => {
                let res = phases::handle_forward_decision(
                    self,
                    packet,
                    &qname,
                    qtype,
                    qclass,
                    tx_id,
                    &current_pipeline_id,
                    &rule_name,
                    dedupe_hash,
                    min_ttl,
                    upstream_timeout,
                    start,
                    &peer,
                    skip_cache,
                    &upstream,
                    pre_split_upstreams.as_ref(),
                    &response_matchers,
                    response_matcher_operator,
                    &response_actions_on_match,
                    &response_actions_on_miss,
                    transport,
                    allow_reuse,
                    &mut reused_response,
                ).await;

                match res {
                    Ok(phases::ForwardResult::Success(bytes)) => return Ok(bytes),
                    Ok(phases::ForwardResult::Continue(ctx)) => {
                        reused_response = *ctx;
                        skip_rules.insert(rule_name.clone());
                        let skip_ref = if skip_rules.is_empty() {
                            None
                        } else {
                            Some(&skip_rules)
                        };
                        
                        let pipeline = if let Some(p) = cfg.pipelines.iter().find(|p| p.id == current_pipeline_id) {
                            p
                        } else {
                            warn!("pipeline missing while continuing: {}", current_pipeline_id);
                            let req = Message::from_bytes(packet).context("parse request")?;
                            return engine_helpers::build_servfail_response(&req);
                        };

                        decision = self.apply_rules(
                            &state,
                            pipeline,
                            peer.ip(),
                            &qname,
                            qtype,
                            qclass,
                            edns_present,
                            skip_ref,
                            skip_cache,
                        );
                        continue 'decision_loop;
                    },
                    Err(e) => return Err(e),
                }
            }
        }
    }
}


    pub(crate) async fn notify_inflight_waiters(&self, dedupe_hash: u64, bytes: &Bytes) {
        // ========== NEW: Use tokio::watch for lock-free notification ==========
        // 使用 tokio::watch 实现无锁通知
        // Remove the watch sender from inflight map and send result
        // 从 inflight map 移除 watch sender 并发送结果
        if let Some((_, tx)) = self.inflight.remove(&dedupe_hash) {
            // Send result to all waiters (lock-free)
            // 向所有等待者发送结果 (无锁)
            let _ = tx.send(Ok(bytes.clone()));
        }
    }

    /// 缓存后台刷新：当TTL即将过期时，异步刷新缓存条目
    /// Cache background refresh: asynchronously refresh cache entry when TTL is about to expire
    ///
    /// 防止无限循环的保护措施：
    /// Protection against infinite loops:
    /// 1. 检查 original_ttl >= cache_refresh_min_ttl（默认5秒）
    /// 2. 使用与正常请求相同的 Singleflight 机制（inflight map）
    /// 3. 刷新失败不会删除现有缓存条目
    pub(crate) fn spawn_background_refresh(
        &self,
        cache_hash: u64,
        pipeline_id: &str,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
        upstream: Option<&str>,  // Reserved for future use
    ) {
        crate::engine::refresh::spawn_background_refresh(
            self,
            cache_hash,
            pipeline_id,
            qname,
            qtype,
            qclass,
            upstream
        )
    }

    /// Construct standard DNS query packet using hickory_proto
    /// 使用 hickory_proto 构造标准 DNS 查询包
    /// 
    /// Design: Use hickory-proto to ensure RFC compliance
    /// 设计：使用 hickory-proto 确保 RFC 合规性
    /// - Generates valid TXID (not 0)
    /// - Sets proper flags (recursion desired)
    /// - Encodes QNAME correctly
    /// - 生成有效的 TXID（不是 0）
    /// - 设置正确的标志（需要递归）
    /// - 正确编码 QNAME
    pub(crate) fn construct_dns_packet(
        &self,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        _qclass: DNSClass,  // Currently defaults to IN class, parameter reserved for future use
    ) -> anyhow::Result<Bytes> {
        use hickory_proto::op::{Message, MessageType, Query};
        use hickory_proto::rr::Name;
        
        // Generate unique TXID (not 0!)
        // 生成唯一的 TXID（不是 0！）
        let tx_id = self.request_id_counter.fetch_add(1, Ordering::Relaxed) as u16;
        
        // Build DNS query message
        // 构建 DNS 查询消息
        let mut msg = Message::new();
        msg.set_id(tx_id);
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        
        // Add question section
        // 添加问题部分
        let name = Name::from_str(qname)?;
        let query = Query::query(name.clone(), qtype);
        msg.add_query(query);
        
        // Serialize to bytes
        // 序列化为字节
        let bytes = msg.to_vec()?;
        
        Ok(Bytes::from(bytes))
    }
}

use super::phases;




#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use hickory_proto::rr::{Record, RData};
    use crate::engine::rules::*;
    use crate::engine::response::*;
    use crate::config::{GlobalSettings, MatchOperator, Action};
    use crate::matcher::RuntimeResponseMatcherWithOp;
    use hickory_proto::rr::RecordType;
    use hickory_proto::op::{Message, OpCode, Query};
    use std::sync::Arc;

    // ========================================================================
    // Engine Helper Functions Unit Tests / 引擎辅助函数单元测试
    // ========================================================================

    #[test]
    fn test_engine_helpers_build_servfail_response() {
        // Arrange: Create test request
        let mut req = Message::new();
        req.set_id(12345);
        req.set_op_code(OpCode::Query);
        req.set_recursion_desired(true);
        let query = Query::query(Name::from_str("example.com").unwrap(), RecordType::A);
        req.add_query(query);

        // Act: Build ServFail response
        let result = engine_helpers::build_servfail_response(&req);

        // Assert: Verify response
        assert!(result.is_ok(), "Should successfully build ServFail response");
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "Response should not be empty");

        // Verify it's a valid DNS message
        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.id(), 12345, "TXID should be preserved");
        assert_eq!(msg.response_code(), ResponseCode::ServFail, "Should be ServFail");
        assert_eq!(msg.op_code(), OpCode::Query, "Should be Query opcode");
        assert!(msg.recursion_desired(), "RD flag should be preserved");
        assert_eq!(msg.queries().len(), 1, "Should have one query");
    }

    #[test]
    fn test_engine_helpers_build_refused_response() {
        // Arrange: Create test request
        let mut req = Message::new();
        req.set_id(54321);
        req.set_op_code(OpCode::Query);
        let query = Query::query(Name::from_str("example.com").unwrap(), RecordType::A);
        req.add_query(query);

        // Act: Build Refused response
        let result = engine_helpers::build_refused_response(&req);

        // Assert: Verify response
        assert!(result.is_ok(), "Should successfully build Refused response");
        let bytes = result.unwrap();
        assert!(!bytes.is_empty(), "Response should not be empty");

        // Verify it's a valid DNS message
        let msg = Message::from_bytes(&bytes).unwrap();
        assert_eq!(msg.id(), 54321, "TXID should be preserved");
        assert_eq!(msg.response_code(), ResponseCode::Refused, "Should be Refused");
        assert_eq!(msg.queries().len(), 1, "Should have one query");
    }

    #[test]
    fn test_engine_helpers_build_servfail_vs_refused_different() {
        // Arrange: Create test request
        let mut req = Message::new();
        req.set_id(11111);
        let query = Query::query(Name::from_str("test.com").unwrap(), RecordType::A);
        req.add_query(query);

        // Act: Build both response types
        let servfail = engine_helpers::build_servfail_response(&req).unwrap();
        let refused = engine_helpers::build_refused_response(&req).unwrap();

        // Assert: Should produce different responses
        assert_ne!(servfail, refused, "ServFail and Refused should be different");

        // Verify different response codes
        let sf_msg = Message::from_bytes(&servfail).unwrap();
        let ref_msg = Message::from_bytes(&refused).unwrap();
        assert_eq!(sf_msg.response_code(), ResponseCode::ServFail);
        assert_eq!(ref_msg.response_code(), ResponseCode::Refused);
    }

    // ========================================================================
    // Original Engine Tests / 原有引擎测试
    // ========================================================================
    use std::net::Ipv4Addr;
    use crate::matcher::RuntimeResponseMatcher;
    use tokio::time::Duration;

    #[test]
    fn make_static_ip_answer_returns_ipv4_record() {
        // Arrange: Define test domain and IPv4 address
        let domain = "example.com";
        let ipv4 = "1.2.3.4";
        
        // Act: Generate static IP answer
        let (rcode, answers) = make_static_ip_answer(domain, ipv4);
        
        // Assert: Verify response code and record type
        assert_eq!(rcode, ResponseCode::NoError, "Should return NoError for valid IP");
        assert_eq!(answers.len(), 1, "Should have exactly one answer");
        assert_eq!(answers[0].record_type(), RecordType::A, "Should be A record for IPv4");
    }

    #[test]
    fn make_static_ip_answer_returns_ipv6_record() {
        // Arrange: Define test domain and IPv6 address
        let domain = "example.com";
        let ipv6 = "2001:db8::1";
        
        // Act: Generate static IP answer
        let (rcode, answers) = make_static_ip_answer(domain, ipv6);
        
        // Assert: Verify response code and record type
        assert_eq!(rcode, ResponseCode::NoError, "Should return NoError for valid IP");
        assert_eq!(answers.len(), 1, "Should have exactly one answer");
        assert_eq!(answers[0].record_type(), RecordType::AAAA, "Should be AAAA record for IPv6");
    }

    #[test]
    fn make_static_ip_answer_rejects_invalid_input() {
        // Arrange: Define test domain and invalid IP
        let domain = "example.com";
        let invalid_ip = "not-an-ip";
        
        // Act: Generate static IP answer with invalid input
        let (rcode, answers) = make_static_ip_answer(domain, invalid_ip);
        
        // Assert: Verify ServFail response and empty answers
        assert_eq!(rcode, ResponseCode::ServFail, "Should return ServFail for invalid IP");
        assert!(answers.is_empty(), "Should have no answers for invalid IP");
    }



    #[test]
    fn pipeline_select_picks_matching_pipeline() {
        // Arrange: Create configuration with pipeline selection rules
        let raw = serde_json::json!({
            "pipelines": [
                { "id": "p1", "rules": [] },
                { "id": "p2", "rules": [] }
            ],
            "pipeline_select": [
                { "pipeline": "p2", "matchers": [ { "type": "listener_label", "value": "edge" } ] }
            ]
        });

        // Act: Parse and compile configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

        // Act: Select pipeline for edge listener
        let (opt, id) = select_pipeline(
            &runtime,
            "any.example.com",
            "127.0.0.1".parse().unwrap(),
            hickory_proto::rr::DNSClass::IN,
            false,
            hickory_proto::rr::RecordType::A,
            "edge",
            None,
            None,
        );
        
        // Assert: Verify correct pipeline was selected
        assert!(opt.is_some(), "Should find matching pipeline");
        assert_eq!(id.as_ref(), "p2", "Should select p2 pipeline for edge listener");
    }

    #[test]
    fn pipeline_select_respects_match_operator_or() {
        // Arrange: Create configuration with OR operator in pipeline selector
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

        // Act: Parse and compile configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime");

        // Act: Select pipeline for edge listener
        let (opt, id) = select_pipeline(
            &runtime,
            "example.com",
            "127.0.0.1".parse().unwrap(),
            hickory_proto::rr::DNSClass::IN,
            false,
            hickory_proto::rr::RecordType::A,
            "edge",
            None,
            None,
        );
        
        // Assert: Verify correct pipeline was selected
        assert!(opt.is_some(), "Should find matching pipeline");
        assert_eq!(id.as_ref(), "p2", "Should select p2 pipeline for edge listener");
    }

    #[allow(dead_code)]
    #[tokio::test]
    async fn apply_rules_static_and_forward_allow_jump() {
        // Arrange: Build a config with rules exercising StaticResponse, Forward, Allow, Jump
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

        // Act: Parse configuration and create engine
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let runtime = RuntimePipelineConfig::from_config(cfg.clone()).expect("runtime");
        let engine = Engine::new(runtime.clone(), "lbl".to_string());
        let state = engine.state.load();

        // Act: Apply rules - StaticResponse should return Static decision
        let decision = engine.apply_rules(
            &state,
            &state.pipeline.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "a.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
            false,  // skip_cache
        );

        // Assert: Verify StaticResponse returns NXDOMAIN
        match decision {
            Decision::Static { rcode, .. } => assert_eq!(rcode, ResponseCode::NXDomain, "StaticResponse should return NXDOMAIN"),
            _ => panic!("expected static decision"),
        }

        // Arrange: Test Forward action with provided upstream and response matchers
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
        let engine2 = Engine::new(runtime2.clone(), "lbl".to_string());
        let state2 = engine2.state.load();

        // Act: Apply rules - Forward should return Forward decision with upstream and matchers
        let decision2 = engine2.apply_rules(
            &state2,
            &state2.pipeline.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "x.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
            false,  // skip_cache
        );

        // Assert: Verify Forward action returns correct upstream and matchers
        match decision2 {
            Decision::Forward {
                upstream,
                response_matchers,
                response_matcher_operator,
                ..
            } => {
                assert_eq!(upstream.as_ref(), "8.8.8.8:53", "Forward should use configured upstream");
                assert_eq!(response_matchers.len(), 1, "Forward should have one response matcher");
                assert_eq!(response_matcher_operator, crate::config::MatchOperator::And, "Forward should use AND operator");
            }
            _ => panic!("expected forward decision"),
        }

        // Arrange: Test Allow action - should forward to default upstream
        let raw3 = serde_json::json!({
            "settings": { "default_upstream": "1.2.3.4:53" },
            "pipelines": [ { "id": "p3", "rules": [ { "name": "a", "matchers": [ { "type": "any" } ], "actions": [ { "type": "allow" } ] } ] } ]
        });
        let cfg3: crate::config::PipelineConfig = serde_json::from_value(raw3).expect("parse");
        let runtime3 = RuntimePipelineConfig::from_config(cfg3.clone()).expect("runtime");
        let engine3 = Engine::new(runtime3.clone(), "lbl".to_string());
        let state3 = engine3.state.load();

        // Act: Apply rules - Allow should forward to default upstream
        let decision3 = engine3.apply_rules(
            &state3,
            &state3.pipeline.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "y.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
            false,  // skip_cache
        );

        // Assert: Verify Allow action forwards to default upstream
        match decision3 {
            Decision::Forward { upstream, .. } => assert_eq!(upstream.as_ref(), "1.2.3.4:53", "Allow should forward to default upstream"),
            _ => panic!("expected forward decision from allow"),
        }

        // Arrange: Test JumpToPipeline action
        let raw4 = serde_json::json!({
            "pipelines": [ { "id": "p4", "rules": [ { "name": "j", "matchers": [ { "type": "any" } ], "actions": [ { "type": "jump_to_pipeline", "pipeline": "other" } ] } ] } ]
        });
        let cfg4: crate::config::PipelineConfig = serde_json::from_value(raw4).expect("parse");
        let runtime4 = RuntimePipelineConfig::from_config(cfg4.clone()).expect("runtime");
        let engine4 = Engine::new(runtime4.clone(), "lbl".to_string());
        let state4 = engine4.state.load();

        // Act: Apply rules - JumpToPipeline should return Jump decision
        let decision4 = engine4.apply_rules(
            &state4,
            &state4.pipeline.pipelines[0],
            "127.0.0.1".parse().unwrap(),
            "z.example.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            false,
            None,
            false,  // skip_cache
        );

        // Assert: Verify JumpToPipeline returns correct target pipeline
        match decision4 {
            Decision::Jump { pipeline } => assert_eq!(pipeline.as_ref(), "other", "JumpToPipeline should jump to target pipeline"),
            _ => panic!("expected jump decision"),
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
        Engine::new(runtime, "lbl".to_string())
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
            upstream: Arc::from(TEST_UPSTREAM),
            transport: Transport::Udp,
        }
    }

    #[tokio::test]
    async fn response_actions_allow_returns_upstream_on_match() {
        // Arrange: Build test engine and response context
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

        // Act: Apply response actions with Allow action
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: Some(ctx),
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &response_matchers,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip,
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions allow should succeed");

        // Assert: Verify Allow action returns upstream result with match=true
        match result {
            ResponseActionResult::Upstream { ctx, resp_match } => {
                assert!(resp_match, "Allow action should match response type");
                assert_eq!(ctx.upstream.as_ref(), TEST_UPSTREAM, "Allow should use test upstream");
            }
            _ => panic!("expected upstream result"),
        }
    }

    #[tokio::test]
    async fn response_actions_allow_reports_miss_when_matchers_fail() {
        // Arrange: Build test engine and response context with non-matching response matcher
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

        // Act: Apply response actions with Allow action and non-matching matcher
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: Some(ctx),
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &response_matchers,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip,
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions allow should succeed even on miss");

        // Assert: Verify Allow action reports match failure
        match result {
            ResponseActionResult::Upstream { resp_match, .. } => assert!(!resp_match, "Allow should report matcher miss"),
            _ => panic!("expected upstream result"),
        }
    }

    #[tokio::test]
    async fn response_actions_deny_returns_refused() {
        // Arrange: Build test engine with Deny action
        let engine = build_test_engine();
        let req = Message::new();
        let actions = [Action::Deny];
        let response_matchers: Vec<RuntimeResponseMatcherWithOp> = Vec::new();
        let packet = [0u8];
        let client_ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Act: Apply response actions with Deny action
        let ctx = crate::engine::rules::ApplyResponseActionsContext {
            engine: &engine,
            actions: &actions,
            ctx_opt: None,
            req: &req,
            packet: &packet,
            upstream_timeout: Duration::from_secs(1),
            response_matchers: &response_matchers,
            qname: "example.com",
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            client_ip,
            upstream_default: TEST_UPSTREAM,
            pipeline_id: "pipeline",
            rule_name: "rule",
            remaining_jumps: 10,
        };
        let result = apply_response_actions(ctx)
            .await
            .expect("response actions deny should return static");

        // Assert: Verify Deny action returns Refused response code
        match result {
            ResponseActionResult::Static { rcode, source, .. } => {
                assert_eq!(rcode, ResponseCode::Refused, "Deny should return Refused");
                assert_eq!(source, "response_action", "Source should be response_action");
            }
            _ => panic!("expected static refused"),
        }
    }

    #[test]
    fn test_calculate_rule_hash_respects_uses_client_ip() {
        // Arrange: Define test data with different IPs
        let pipeline_id = "test_p";
        let qname = "example.com";
        let ip1 = "1.2.3.4".parse::<IpAddr>().unwrap();
        let ip2 = "5.6.7.8".parse::<IpAddr>().unwrap();

        // Act & Assert: When uses_client_ip is false, both IPs should result in the same hash
        let h1_no_ip = calculate_rule_hash(pipeline_id, qname, ip1, false);
        let h2_no_ip = calculate_rule_hash(pipeline_id, qname, ip2, false);
        assert_eq!(h1_no_ip, h2_no_ip, "Hashes should match when IP is ignored");

        // Act & Assert: When uses_client_ip is true, different IPs should result in different hashes
        let h1_with_ip = calculate_rule_hash(pipeline_id, qname, ip1, true);
        let h2_with_ip = calculate_rule_hash(pipeline_id, qname, ip2, true);
        assert_ne!(h1_with_ip, h2_with_ip, "Hashes should differ when IP is included");
        
        // Assert: Hash with IP should differ from hash without IP
        assert_ne!(h1_no_ip, h1_with_ip, "Hash with IP should differ from hash without IP");
    }

    #[tokio::test]
    async fn test_cache_expiration_triggers_requery() {
        // Arrange: Build engine and insert expired cache entry
        let engine = build_test_engine();
        let pipeline_id = Arc::from("default");
        let qname = "expire.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;
        let dedupe_hash = Engine::calculate_cache_hash_for_dedupe(&pipeline_id, qname.as_bytes(), qtype, qclass);

        // Insert an entry that expired 5 seconds ago
        let entry = CacheEntry {
            bytes: Bytes::from_static(b"old_resp"),
            rcode: ResponseCode::NoError,
            source: Arc::from("old_source"),
            upstream: None,
            qname: Arc::from(qname),
            pipeline_id: pipeline_id.clone(),
            qtype: u16::from(qtype),
            inserted_at: Instant::now() - Duration::from_secs(10),
            original_ttl: 5, // Expired 5 seconds ago
        };
        engine.cache.insert(dedupe_hash, Arc::new(entry));

        // Act: Create DNS query packet and check fast path
        let mut packet = vec![0u8; 12];
        packet[0] = 0xAA; packet[1] = 0xBB; // TXID
        packet[5] = 1; // QDCOUNT
        packet.extend_from_slice(b"\x06expire\x03com\x00\x00\x01\x00\x01");

        let peer = "127.0.0.1:12345".parse().unwrap();
        let fast_res = engine.handle_packet_fast(&packet, peer).unwrap();

        // Assert: Verify expired cache results in None (cache miss)
        assert!(fast_res.is_none(), "Expired cache should result in None from handle_packet_fast");
        
        // Assert: Verify cache entry was invalidated
        assert!(engine.cache.get(&dedupe_hash).is_none(), "Cache entry should be removed after expiration check");
    }

    #[test]
    fn test_rule_cache_entry_matches_respects_uses_client_ip() {
        // Arrange: Define test data with different IPs
        let pipeline_id: Arc<str> = Arc::from("test_p");
        let qname = "example.com";
        let ip1 = "1.2.3.4".parse::<IpAddr>().unwrap();
        let ip2 = "5.6.7.8".parse::<IpAddr>().unwrap();
        let decision = Arc::new(Decision::Static { rcode: ResponseCode::NoError, answers: vec![] });

        // Arrange: Entry created WITHOUT IP
        let entry_no_ip = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            client_ip: None,
            decision: decision.clone(),
            expires_at: None,
        };

        // Act & Assert: Should match any IP if we don't care about it
        assert!(entry_no_ip.matches("test_p", qname, ip1, false), "Entry without IP should match any IP when uses_client_ip is false");
        assert!(entry_no_ip.matches("test_p", qname, ip2, false), "Entry without IP should match any IP when uses_client_ip is false");
        
        // Act & Assert: Should NOT match if we now care about IP (since entry doesn't have it)
        assert!(!entry_no_ip.matches("test_p", qname, ip1, true), "Entry without IP should not match when uses_client_ip is true");

        // Arrange: Entry created WITH IP
        let entry_with_ip = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            client_ip: Some(ip1),
            decision,
            expires_at: None,
        };

        // Act & Assert: Should match same IP if we care
        assert!(entry_with_ip.matches("test_p", qname, ip1, true), "Entry with IP should match same IP when uses_client_ip is true");
        // Act & Assert: Should NOT match different IP if we care
        assert!(!entry_with_ip.matches("test_p", qname, ip2, true), "Entry with IP should not match different IP when uses_client_ip is true");
        // Act & Assert: Should NOT match even same IP if we don't care now (safety check)
        assert!(!entry_with_ip.matches("test_p", qname, ip1, false), "Entry with IP should not match when uses_client_ip is false");
    }

    #[test]
    fn test_rule_cache_expiration() {
        // Arrange: Define test data
        let pipeline_id: Arc<str> = Arc::from("test_p");
        let qname = "expire.com";
        let ip = "1.2.3.4".parse::<IpAddr>().unwrap();
        let decision = Arc::new(Decision::Static { rcode: ResponseCode::NoError, answers: vec![] });

        // Arrange: Expired entry
        let entry_expired = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            client_ip: None,
            decision: decision.clone(),
            expires_at: Some(Instant::now() - Duration::from_secs(1)),
        };
        
        // Act & Assert: Expired entry should not match
        assert!(!entry_expired.matches("test_p", qname, ip, false), "Expired entry should not match");

        // Arrange: Fresh entry
        let entry_fresh = RuleCacheEntry {
            pipeline_id: pipeline_id.clone(),
            qname_hash: fast_hash_str(qname),
            client_ip: None,
            decision,
            expires_at: Some(Instant::now() + Duration::from_secs(60)),
        };
        
        // Act & Assert: Fresh entry should match
        assert!(entry_fresh.matches("test_p", qname, ip, false), "Fresh entry should match");
    }

    /// 测试 DNS 响应缓存键包含 QCLASS
    #[test]
    fn test_cache_hash_includes_qclass() {
        // Arrange: Define test data
        let pipeline_id = "default";
        let qname = "example.com";
        let qtype = RecordType::A;
        let qclass_in = DNSClass::IN;
        let qclass_ch = DNSClass::CH;

        // Act: Calculate hashes for same QNAME+QTYPE but different QCLASS
        let hash_in = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname.as_bytes(), 
            qtype, 
            qclass_in
        );
        let hash_ch = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname.as_bytes(), 
            qtype, 
            qclass_ch
        );

        // Assert: Verify different QCLASS produces different hashes
        assert_ne!(
            hash_in, 
            hash_ch, 
            "Different QCLASS should produce different cache hashes"
        );

        // Act: Calculate hash for same QCLASS to verify consistency
        let hash_in2 = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname.as_bytes(), 
            qtype, 
            qclass_in
        );

        // Assert: Verify same QCLASS produces same hash
        assert_eq!(
            hash_in, 
            hash_in2, 
            "Same QCLASS should produce same cache hash"
        );
    }

    /// 测试域名大小写不敏感
    #[test]
    fn test_cache_hash_case_insensitive() {
        // Arrange: Define test data with different case variations
        let pipeline_id = "default";
        let qname_lower = "example.com";
        let qname_upper = "EXAMPLE.COM";
        let qname_mixed = "ExAmPlE.cOm";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;

        // Act: Calculate hashes for different case variations
        // Note: In parse_quick(), qname is already lowercased before being passed to this function
        // So we simulate that behavior by lowercasing the input first
        // 注意：在 parse_quick() 中，qname 在传递给此函数之前已经转为小写
        // 所以我们通过先小写输入来模拟这种行为
        let hash1 = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname_lower.to_lowercase().as_bytes(), 
            qtype, 
            qclass
        );
        let hash2 = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname_upper.to_lowercase().as_bytes(), 
            qtype, 
            qclass
        );
        let hash3 = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname_mixed.to_lowercase().as_bytes(), 
            qtype, 
            qclass
        );

        // Assert: Verify case-insensitive hashing produces same results
        assert_eq!(
            hash1, 
            hash2, 
            "QNAME hash should be case-insensitive"
        );
        assert_eq!(
            hash1, 
            hash3, 
            "QNAME hash should be case-insensitive"
        );
    }

    /// 测试不同 QTYPE 的哈希也不同
    #[test]
    fn test_cache_hash_different_qtype() {
        // Arrange: Define test data with different query types
        let pipeline_id = "default";
        let qname = "example.com";
        let qtype_a = RecordType::A;
        let qtype_aaaa = RecordType::AAAA;
        let qclass = DNSClass::IN;

        // Act: Calculate hashes for different QTYPE values
        let hash_a = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname.as_bytes(), 
            qtype_a, 
            qclass
        );
        let hash_aaaa = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname.as_bytes(), 
            qtype_aaaa, 
            qclass
        );

        // Assert: Verify different QTYPE produces different hashes
        assert_ne!(
            hash_a, 
            hash_aaaa, 
            "Different QTYPE should produce different cache hashes"
        );
    }

    /// 测试不同 QNAME 的哈希也不同
    #[test]
    fn test_cache_hash_different_qname() {
        // Arrange: Define test data with different domain names
        let pipeline_id = "default";
        let qname1 = "example.com";
        let qname2 = "test.com";
        let qtype = RecordType::A;
        let qclass = DNSClass::IN;

        // Act: Calculate hashes for different QNAME values
        let hash1 = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname1.as_bytes(), 
            qtype, 
            qclass
        );
        let hash2 = Engine::calculate_cache_hash_for_dedupe(
            pipeline_id, 
            qname2.as_bytes(), 
            qtype, 
            qclass
        );

        // Assert: Verify different QNAME produces different hashes
        assert_ne!(
            hash1, 
            hash2, 
            "Different QNAME should produce different cache hashes"
        );
    }

    /// 测试 fast_static_match 不会跳过不可预计算的规则
    ///
    /// 这是一个回归测试，用于验证以下场景：
    /// - 规则1：domain_regex("^_acme") → forward（不可预计算）
    /// - 规则2：domain_suffix("mydomain.com") → static_ip（可预计算）
    /// - 查询：_acme-challenge.mydomain.com
    ///
    /// 预期行为：第一条规则应该生效（forward），而不是第二条规则（static_ip）
    ///
    /// 修复前：fast_static_match 会跳过不可预计算的规则，直接返回可预计算的规则结果
    /// 修复后：fast_static_match 在遇到第一个匹配但不可预计算的规则时放弃快速路径
    #[test]
    fn test_fast_static_match_preserves_rule_order() {
        use crate::matcher::advanced_rule::{compile_pipelines, fast_static_match};

        // Arrange: 构建一个配置，模拟用户的问题场景
        let raw = serde_json::json!({
            "settings": { "default_upstream": "1.1.1.1:53" },
            "pipelines": [
                {
                    "id": "test",
                    "rules": [
                        {
                            "name": "acme-forward",
                            "matchers": [{ "type": "domain_regex", "value": "^_acme" }],
                            "actions": [{ "type": "forward", "upstream": "223.5.5.5:53" }]
                        },
                        {
                            "name": "mydomain-static",
                            "matchers": [{ "type": "domain_suffix", "value": "mydomain.com" }],
                            "actions": [{ "type": "static_ip_response", "ip": "192.168.16.42" }]
                        }
                    ]
                }
            ]
        });

        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("runtime config");
        let compiled = compile_pipelines(&runtime);

        // Act: 调用 fast_static_match 查询 _acme-challenge.mydomain.com
        let result = fast_static_match(
            &compiled[0],
            "_acme-challenge.mydomain.com",
            hickory_proto::rr::RecordType::TXT,
            hickory_proto::rr::DNSClass::IN,
            "127.0.0.1".parse().unwrap(),
            false,
        );

        // Assert: fast_static_match 应该返回 None
        // 原因：第一条规则（domain_regex("^_acme")）匹配但不可预计算，
        // 所以 fast_static_match 应该放弃快速路径，让规则走正常路径
        assert!(
            result.is_none(),
            "fast_static_match 应该返回 None，因为第一个匹配的规则不可预计算"
        );

        // 验证：如果查询一个只匹配第二条规则的域名，应该返回静态 IP
        let result2 = fast_static_match(
            &compiled[0],
            "other.mydomain.com",
            hickory_proto::rr::RecordType::A,
            hickory_proto::rr::DNSClass::IN,
            "127.0.0.1".parse().unwrap(),
            false,
        );

        assert!(
            result2.is_some(),
            "fast_static_match 应该返回 Some，因为第一个匹配的规则可预计算"
        );

        // 验证返回的是静态 IP 决策
        match result2.unwrap() {
            Decision::Static { rcode, answers } => {
                assert_eq!(rcode, ResponseCode::NoError);
                assert!(!answers.is_empty(), "应该有静态 IP 答案");
            }
            _ => panic!("应该返回 Static 决策"),
        }
    }
}





// Multi-upstream parsing tests / 多上游解析测试
// Tests for parsing and validating multi-upstream configurations
#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests_multi_upstream {
    use crate::config::Action;

    #[test]
    fn test_parse_multi_upstream_comma_separated() {
        // Arrange: Create configuration with comma-separated upstream list
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "multi",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { 
                                "type": "forward", 
                                "upstream": "1.1.1.1:53,8.8.8.8:53,9.9.9.9:53" 
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];
        
        // Assert: Verify upstream is parsed correctly as comma-separated string
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert_eq!(upstream.as_ref().map(|s| s.as_str()), Some("1.1.1.1:53,8.8.8.8:53,9.9.9.9:53"), "Comma-separated upstream should be preserved");
            }
            _ => panic!("expected forward action"),
        }
    }

    #[test]
    fn test_parse_multi_upstream_array() {
        // Arrange: Create configuration with array of upstreams
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "multi",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { 
                                "type": "forward", 
                                "upstream": ["1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"]
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];
        
        // Assert: Verify upstream array is converted to comma-separated string
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert_eq!(upstream.as_ref().map(|s| s.as_str()), Some("1.1.1.1:53,8.8.8.8:53,9.9.9.9:53"), "Array upstream should be joined with commas");
            }
            _ => panic!("expected forward action"),
        }
    }

    #[test]
    fn test_parse_multi_upstream_empty_array() {
        // Arrange: Create configuration with empty upstream array
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "empty",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { 
                                "type": "forward", 
                                "upstream": []
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];
        
        // Assert: Verify empty array results in None upstream
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert!(upstream.is_none(), "Empty upstream array should result in None");
            }
            _ => panic!("expected forward action"),
        }
    }

    #[test]
    fn test_parse_multi_upstream_single_element() {
        // Arrange: Create configuration with single-element upstream array
        let raw = serde_json::json!({
            "pipelines": [
                {
                    "id": "p1",
                    "rules": [
                        {
                            "name": "single",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { 
                                "type": "forward", 
                                "upstream": ["1.1.1.1:53"]
                            } ]
                        }
                    ]
                }
            ]
        });

        // Act: Parse configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).expect("parse");
        let rule = &cfg.pipelines[0].rules[0];
        
        // Assert: Verify single-element array is converted to string
        match &rule.actions[0] {
            Action::Forward { upstream, .. } => {
                assert_eq!(upstream.as_ref().map(|s| s.as_str()), Some("1.1.1.1:53"), "Single-element array should be converted to string");
            }
            _ => panic!("expected forward action"),
        }
    }
}
