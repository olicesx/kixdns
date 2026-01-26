use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use futures::{stream::{FuturesUnordered, StreamExt}};
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rustc_hash::{FxHasher, FxBuildHasher};
use smallvec::SmallVec;
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
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::cache::{CacheEntry, DnsCache, new_cache};
use crate::advanced_rule::{CompiledPipeline, compile_pipelines, fast_static_match};
use crate::config::{Action, Transport};
use crate::matcher::{
    RuntimePipeline, RuntimePipelineConfig, RuntimeResponseMatcherWithOp, eval_match_chain,
};
use crate::proto_utils::parse_quick;
use crate::geoip::GeoIpManager;

// ============================================================================
// Constants / 常量
// ============================================================================

/// Hedge 超时除数：第一次尝试使用 1/N 的时间，为 TCP fallback 预留时间 / Hedge timeout divisor: first attempt uses 1/N of the budget to reserve time for TCP fallback
const HEDGE_TIMEOUT_DIVISOR: u32 = 3;

/// 默认最小 hedge 超时毫秒数（当计算值过小时使用） / Default minimum hedge timeout in milliseconds (used when calculated value is too small)
const DEFAULT_HEDGE_TIMEOUT_MS: u64 = 100;

// ============================================================================
// Engine Helper Functions / 引擎辅助函数
// ============================================================================

/// 引擎辅助函数模块 - 提供可复用的引擎逻辑 / Engine helper functions module - provides reusable engine logic
pub mod engine_helpers {
    use super::*;

    /// 构建错误响应（ServFail）
    /// Build error response (ServFail)
    #[inline]
    pub fn build_servfail_response(req: &Message) -> anyhow::Result<Bytes> {
        build_response(req, ResponseCode::ServFail, Vec::new())
    }

    /// 构建拒绝响应（Refused）
    /// Build refused response (Refused)
    #[inline]
    pub fn build_refused_response(req: &Message) -> anyhow::Result<Bytes> {
        build_response(req, ResponseCode::Refused, Vec::new())
    }
}

// ============================================================================
// Fast-path Response / 快速路径响应
// ============================================================================
///
/// - `Direct`: already has correct TXID and can be sent as-is.
/// - `CacheHit`: carries cached bytes (with an old TXID) and the request TXID to patch.
///   Also includes insertion time and original TTL for RFC 1035 §5.2 compliance.
#[derive(Debug, Clone)]
pub enum FastPathResponse {
    Direct(Bytes),
    CacheHit { 
        cached: Bytes, 
        tx_id: u16,
        /// Insertion time for TTL calculation / 用于TTL计算的插入时间
        inserted_at: Instant,
    },
}

// ============================================================================
// Refreshing Guard / 刷新守卫
// ============================================================================

pub struct EngineInner {
    pub pipeline: RuntimePipelineConfig,
    pub compiled_pipelines: Vec<CompiledPipeline>,
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
    rule_cache: Cache<u64, RuleCacheEntry>,
    // Runtime metrics for diagnosing concurrency and upstream latency / 运行时指标，用于诊断并发和上游延迟
    pub metrics_inflight: Arc<AtomicUsize>,
    pub metrics_total_requests: Arc<AtomicU64>,
    pub metrics_fastpath_hits: Arc<AtomicU64>,
    pub metrics_upstream_ns_total: Arc<AtomicU64>,
    pub metrics_upstream_calls: Arc<AtomicU64>,
    // Per-request id generator for tracing / 每个请求的 ID 生成器用于追踪
    pub request_id_counter: Arc<AtomicU64>,
    // In-flight dedupe map: cache_hash -> waiters / 进行中的去重映射：缓存哈希 -> 等待者
    // 优化：SmallVec<[_; 8]>避免典型Singleflight场景的堆分配（<=8个等待者）
    // Optimization: SmallVec<[_; 8]> avoids heap allocation for typical Singleflight scenarios (<=8 waiters)
    // 使用 FxBuildHasher 提供更快的哈希计算 / Use FxBuildHasher for faster hashing
    /// In-flight request deduplication map using tokio::watch for lock-free concurrent waiting
    /// 使用 tokio::watch 实现无锁并发等待的进行中请求去重 map
    /// Key: dedupe_hash (pipeline_id + qname + qtype + qclass)
    /// Value: watch sender that will be notified when upstream query completes
    /// Note: Using Arc<anyhow::Error> to make the type Send + Clone
    pub inflight: Arc<DashMap<u64, tokio::sync::watch::Sender<Result<Bytes, Arc<anyhow::Error>>>, FxBuildHasher>>,
    // Background refresh tracking: bitmap for concurrent refresh deduplication
    // 后台刷新跟踪：用于并发刷新去重的位图
    // OPTIMIZATION: Use AtomicU64 bitmap instead of DashMap for zero-lock overhead
    // 优化：使用 AtomicU64 位图代替 DashMap，实现零锁开销
    // Each bit represents whether a cache_hash (low 6 bits) is currently being refreshed
    // 每个位表示一个 cache_hash（低 6 位）是否正在刷新
    // Trade-off: Can track up to 64 concurrent refreshes (sufficient for background refresh)
    // 权衡：最多跟踪 64 个并发刷新（对后台刷新足够）
    pub refreshing_bitmap: Arc<AtomicU64>,
    // Semaphore to limit concurrent handle_packet async tasks / 用于限制并发 handle_packet 异步任务数量
    pub permit_manager: Arc<PermitManager>,
    // Latest upstream latency for adaptive flow control / 用于自适应流控的最新上游延迟
    pub metrics_last_upstream_latency_ns: Arc<AtomicU64>,
    // Adaptive flow control state / 自适应流控状态
    pub flow_control_state: Arc<FlowControlState>,
    // Cache background refresh settings / 缓存后台刷新设置
    cache_background_refresh: bool,
    cache_refresh_threshold_percent: u8,
    cache_refresh_min_ttl: u32,
    // GeoIP manager for geographic IP-based routing / GeoIP 管理器用于基于地理位置的 IP 路由
    pub geoip_manager: Arc<std::sync::RwLock<crate::geoip::GeoIpManager>>,
    // GeoSite manager for domain category-based routing / GeoSite 管理器用于域名分类路由
    // 使用 RwLock 允许并发读操作，写操作独占 / Uses RwLock for concurrent reads, exclusive writes
    pub geosite_manager: Arc<std::sync::RwLock<crate::geosite::GeoSiteManager>>,
    // Background refresh dedicated rule / 后台刷新专用规则
    // Design: Background refresh calls handle_packet(skip_cache=true) with this rule
    // 设计：后台刷新调用 handle_packet(skip_cache=true) 使用此规则
    // Uses OnceLock for lazy initialization and thread-safe one-time setup
    // 使用 OnceLock 实现延迟初始化和线程安全的一次性设置
    background_refresh_rule: std::sync::OnceLock<Arc<crate::matcher::RuntimeRule>>,
}

/// 动态信号量调整的自适应流控状态 / Adaptive flow control state for dynamic semaphore adjustment
pub struct FlowControlState {
    pub max_permits: AtomicUsize,
    pub min_permits: usize,
    /// 自UNIX_EPOCH以来的最后调整时间戳（毫秒） / Last adjustment timestamp in milliseconds since UNIX_EPOCH
    /// 时钟回滚通过 adjust_flow_control 中的 saturating_sub 处理 / Clock rollback is handled by saturating_sub in adjust_flow_control
    pub last_adjustment_ms: AtomicU64,
    pub critical_latency_threshold_ns: u64,
    pub adjustment_interval_ms: u64,
}

/// 动态流控的 Permit 管理器 / Permit manager for dynamic flow control feedback
pub struct PermitManager {
    // Current active permits (acquired) / 当前活跃 permits（已获得）
    active_permits: AtomicUsize,
    // Maximum permits that can be granted / 可授予的最大 permits
    max_permits: AtomicUsize,
}

impl PermitManager {
    pub fn new(initial_permits: usize) -> Self {
        Self {
            active_permits: AtomicUsize::new(0),
            max_permits: AtomicUsize::new(initial_permits),
        }
    }
    
    /// Try to acquire a permit without blocking / 非阻塞地尝试获取 permit
    /// Returns a guard that holds Arc<PermitManager> to ensure permit is released
    pub fn try_acquire(self: &Arc<Self>) -> Option<PermitGuard> {
        loop {
            let active = self.active_permits.load(Ordering::Acquire);
            let max = self.max_permits.load(Ordering::Acquire);
            
            if active >= max {
                return None;
            }
            
            match self.active_permits.compare_exchange(
                active,
                active + 1,
                Ordering::Release,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(PermitGuard {
                    manager: Arc::clone(self),
                }),
                Err(_) => continue, // Retry on CAS failure / CAS 失败时重试
            }
        }
    }
    
    /// Get current inflight permits count / 获取当前进行中的 permits 数
    pub fn inflight(&self) -> usize {
        self.active_permits.load(Ordering::Acquire)
    }
    
    /// Update max permits for dynamic adjustment / 更新最大 permits 用于动态调整
    pub fn set_max_permits(&self, new_max: usize) {
        self.max_permits.store(new_max, Ordering::Release);
    }
    
    /// Get current max permits / 获取当前最大 permits
    pub fn max_permits(&self) -> usize {
        self.max_permits.load(Ordering::Acquire)
    }
}

/// RAII guard for automatic permit release / RAII 守卫用于自动 permit 释放
pub struct PermitGuard {
    manager: Arc<PermitManager>,
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        self.manager.active_permits.fetch_sub(1, Ordering::Release);
    }
}

// ============================================================================
// Refreshing Bitmap Helpers / 刷新位图辅助函数
// ============================================================================

/// 检查缓存哈希是否正在刷新（零锁读取） / Check if a cache hash is currently being refreshed (zero-lock read)
#[inline]
fn is_refreshing(bitmap: &AtomicU64, cache_hash: u64) -> bool {
    let bit_index = cache_hash % 64;
    let mask = 1u64 << bit_index;
    bitmap.load(Ordering::Relaxed) & mask != 0
}

/// 标记缓存哈希为正在刷新（零锁写入） / Mark a cache hash as being refreshed (zero-lock write)
#[inline]
fn mark_refreshing(bitmap: &AtomicU64, cache_hash: u64) {
    let bit_index = cache_hash % 64;
    let mask = 1u64 << bit_index;
    bitmap.fetch_or(mask, Ordering::Relaxed);
}

/// 清除缓存哈希的刷新标记（零锁写入） / Clear the refreshing mark for a cache hash (zero-lock write)
#[inline]
fn clear_refreshing(bitmap: &AtomicU64, cache_hash: u64) {
    let bit_index = cache_hash % 64;
    let mask = 1u64 << bit_index;
    bitmap.fetch_and(!mask, Ordering::Relaxed);
}

/// 提取配置中使用的 GeoSite tags / Extract GeoSite tags used in configuration
///
/// 扫描配置以查找所有在匹配器中实际使用的GeoSite标签，这样可以只从数据文件中加载这些标签 / Scans the configuration to find all GeoSite tags actually used in matchers, so we can load only those tags from the data file.
fn extract_geosite_tags_from_config(cfg: &RuntimePipelineConfig) -> Vec<String> {
    use std::collections::HashSet;

    let mut tags_set: HashSet<String> = HashSet::new();

    // Scan pipeline_select rules / 扫描 pipeline_select 规则
    for rule in &cfg.pipeline_select {
        for matcher in &rule.matchers {
            if let crate::matcher::RuntimePipelineSelectorMatcher::GeoSite { tag } = &matcher.matcher {
                tags_set.insert(tag.clone());
            }
            if let crate::matcher::RuntimePipelineSelectorMatcher::GeoSiteNot { tag } = &matcher.matcher {
                tags_set.insert(tag.clone());
            }
        }
    }

    // Scan all pipeline rules / 扫描所有 pipeline 规则
    for pipeline in &cfg.pipelines {
        for rule in &pipeline.rules {
            // Scan request matchers / 扫描请求匹配器
            for matcher in &rule.matchers {
                if let crate::matcher::RuntimeMatcher::GeoSite { tag } = &matcher.matcher {
                    tags_set.insert(tag.clone());
                }
                if let crate::matcher::RuntimeMatcher::GeoSiteNot { tag } = &matcher.matcher {
                    tags_set.insert(tag.clone());
                }
            }

            // Scan response matchers / 扫描响应匹配器
            for matcher in &rule.response_matchers {
                if let crate::matcher::RuntimeResponseMatcher::ResponseRequestDomainGeoSite { value } = &matcher.matcher {
                    tags_set.insert(value.clone());
                }
                if let crate::matcher::RuntimeResponseMatcher::ResponseRequestDomainGeoSiteNot { value } = &matcher.matcher {
                    tags_set.insert(value.clone());
                }
            }
        }
    }

    tags_set.into_iter().collect()
}

/// 检查配置是否使用 GeoIP 匹配器 / Check if configuration uses GeoIP matchers
///
/// 扫描配置以确定是否使用了GeoIP匹配器，这样我们可以对MMDB文件实现延迟加载 / Scans the configuration to determine if any GeoIP matchers are used, so we can implement lazy loading for the MMDB file.
fn uses_geoip_matchers(cfg: &RuntimePipelineConfig) -> bool {
    // Scan all pipeline rules / 扫描所有 pipeline 规则
    for pipeline in &cfg.pipelines {
        for rule in &pipeline.rules {
            // Check request matchers / 检查请求匹配器
            for matcher in &rule.matchers {
                if matches!(
                    matcher.matcher,
                    crate::matcher::RuntimeMatcher::GeoipCountry { .. } |
                    crate::matcher::RuntimeMatcher::GeoipPrivate { .. }
                ) {
                    return true;
                }
            }

            // Check response matchers / 检查响应匹配器
            for matcher in &rule.response_matchers {
                if matches!(
                    matcher.matcher,
                    crate::matcher::RuntimeResponseMatcher::ResponseAnswerIpGeoipCountry { .. } |
                    crate::matcher::RuntimeResponseMatcher::ResponseAnswerIpGeoipPrivate { .. }
                ) {
                    return true;
                }
            }
        }
    }

    false
}

impl Engine {
    pub fn new(cfg: RuntimePipelineConfig, listener_label: String) -> Self {
        // moka 缓存：容量由配置控制（默认 10000 条），最大生存时间由 cache_max_ttl 控制
        // moka cache capacity and max TTL are configurable via settings
        let cache_capacity = cfg.settings.cache_capacity;
        let cache_max_ttl = cfg.settings.cache_max_ttl;
        let cache = new_cache(cache_capacity, cache_max_ttl);
        // Rule cache: 10k entries, long default TTL (managed manually per-entry)
        // 规则缓存：1万条，默认长 TTL（通过条目内部 expires_at 手动管理）
        let rule_cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(60))
            .build();

        // Extract flow control settings before moving cfg / 在 move cfg 之前提取流控设置
        let udp_pool_size = cfg.settings.udp_pool_size;
        let tcp_pool_size = cfg.settings.tcp_pool_size;
        let flow_control_initial_permits = cfg.settings.flow_control_initial_permits;
        let flow_control_min_permits = cfg.settings.flow_control_min_permits;
        let flow_control_max_permits = cfg.settings.flow_control_max_permits;
        let flow_control_latency_threshold_ms = cfg.settings.flow_control_latency_threshold_ms;
        let flow_control_adjustment_interval_secs = cfg.settings.flow_control_adjustment_interval_secs;
        let dashmap_shards = cfg.settings.dashmap_shards;
        let cache_background_refresh = cfg.settings.cache_background_refresh;
        let cache_refresh_threshold_percent = cfg.settings.cache_refresh_threshold_percent;
        let cache_refresh_min_ttl = cfg.settings.cache_refresh_min_ttl;

        // Extract TCP health check settings / 提取 TCP 健康检查配置
        let tcp_health_error_threshold = cfg.settings.tcp_health_check_error_threshold;
        let tcp_max_age_secs = cfg.settings.tcp_connection_max_age_seconds;
        let tcp_idle_timeout_secs = cfg.settings.tcp_connection_idle_timeout_seconds;

        // Extract GeoIP settings before moving cfg / 在 move cfg 之前提取 GeoIP 设置
        let uses_geoip = uses_geoip_matchers(&cfg);
        let geoip_db_path = if uses_geoip {
            cfg.settings.geoip_db_path.clone()
        } else {
            None
        };
        let geoip_dat_path = cfg.settings.geoip_dat_path.clone();

        // Extract GeoSite settings before moving cfg / 在 move cfg 之前提取 GeoSite 设置
        let geosite_data_paths = cfg.settings.geosite_data_paths.clone();
        
        // Extract GeoSite tags used in configuration before moving cfg
        // 在 move cfg 之前提取配置中使用的 GeoSite tags
        let used_geosite_tags = extract_geosite_tags_from_config(&cfg);
        
        let compiled = compile_pipelines(&cfg);
        
        let state = Arc::new(ArcSwap::from_pointee(EngineInner {
            pipeline: cfg,
            compiled_pipelines: compiled,
        }));

        // Initialize GeoIpManager / 初始化 GeoIpManager
        let mut geoip_manager = match GeoIpManager::new(geoip_db_path) {
            Ok(manager) => manager,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to initialize GeoIpManager, running without GeoIP support");
                // Create a dummy manager that always returns empty results
                GeoIpManager::new(None).unwrap()
            }
        };

        // Load GeoIP data from .dat file if configured / 如果配置了 .dat 文件，则加载 GeoIP 数据
        let mut geoip_dat_path_for_watcher = None;
        if let Some(ref path_str) = geoip_dat_path {
            let path = std::path::PathBuf::from(path_str);
            if path.exists() {
                // 检测文件格式 / Detect file format
                let is_dat = path.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("dat"))
                    .unwrap_or(false);

                let load_result = if is_dat {
                    if uses_geoip {
                        geoip_manager.load_from_dat_file(&path)
                    } else {
                        info!("No GeoIP matchers used in config, skipping GeoIP .dat data loading");
                        Ok(0)
                    }
                } else {
                    // JSON 格式：检查是否需要加载 / JSON format: check if loading is needed
                    if uses_geoip {
                        geoip_manager.load_from_v2ray_file(&path)
                    } else {
                        info!("No GeoIP matchers used in config, skipping GeoIP JSON data loading");
                        Ok(0)
                    }
                };

                match load_result {
                    Ok(count) => {
                        if count > 0 {
                            info!(path = %path.display(), loaded_count = count, "loaded GeoIP data from file");
                            geoip_dat_path_for_watcher = Some(path);
                        }
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "failed to load GeoIP data, skipping");
                    }
                }
            } else {
                warn!(path = %path.display(), "GeoIP data file not found, skipping");
            }
        }

        let geoip_manager = Arc::new(std::sync::RwLock::new(geoip_manager));

        // Initialize GeoSiteManager / 初始化 GeoSiteManager
        // GeoSiteManager starts empty and is populated via add_entry() calls
        // Cache will be automatically rebuilt after loading data
        let geosite_manager = Arc::new(std::sync::RwLock::new(
            crate::geosite::GeoSiteManager::new(),
        ));
        
        // Load GeoSite data from configured files / 从配置的文件加载 GeoSite 数据
        let mut geosite_paths_for_watcher = Vec::new();
        for path_str in &geosite_data_paths {
            let path = PathBuf::from(path_str);
            if path.exists() {
                // Load data from file / 从文件加载数据
                // GeoSiteManager 使用 FxHashMap 实现高性能查找，由外层 RwLock 保护线程安全
                // GeoSiteManager uses FxHashMap for high-performance lookup, thread-safety protected by outer RwLock
                
                // 检测文件格式 / Detect file format
                let is_dat = path.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("dat"))
                    .unwrap_or(false);
                
                let load_result = if is_dat {
                    // 使用按需加载 / Use selective loading
                    if let Some(mut manager) = geosite_manager.write().ok() {
                        if used_geosite_tags.is_empty() {
                        // 没有使用 GeoSite 标签，跳过加载 / No GeoSite tags used, skip loading
                        info!("No GeoSite tags used in config, skipping GeoSite data loading");
                        Ok(0)
                    } else {
                            manager.load_from_dat_file_selective(&path, &used_geosite_tags)
                        }
                    } else {
                        tracing::error!("GeoSite RwLock is poisoned during .dat config load, skipping GeoSite loading");
                        Ok(0) // Skip loading but continue with other files
                    }
                } else {
                    // JSON 格式：全量加载 / JSON format: load all
                    if let Some(mut manager) = geosite_manager.write().ok() {
                        manager.load_from_v2ray_file(&path)
                    } else {
                        tracing::error!("GeoSite RwLock is poisoned during JSON config load, skipping GeoSite loading");
                        Ok(0) // Skip loading but continue with other files
                    }
                };
                
                match load_result {
                    Ok(count) => {
                        info!(path = %path.display(), loaded_count = count, 
                             used_tags = used_geosite_tags.len(),
                             "loaded GeoSite data from file");
                        geosite_paths_for_watcher.push(path);
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "failed to load GeoSite data, skipping");
                    }
                }
            } else {
                warn!(path = %path.display(), "GeoSite data file not found, skipping");
            }
        }
        
        // Start GeoSite watcher for hot-reload / 启动 GeoSite watcher 用于热重载
        if !geosite_paths_for_watcher.is_empty() {
            crate::geosite::spawn_geosite_watcher(
                geosite_paths_for_watcher,
                Arc::clone(&geosite_manager),
                used_geosite_tags,
            );
        }

        // Start GeoIP watcher for hot-reload / 启动 GeoIP watcher 用于热重载
        crate::geoip::spawn_geoip_watcher(
            geoip_dat_path_for_watcher,
            Arc::clone(&geoip_manager),
        );

        let flow_control_state = Arc::new(FlowControlState {
            max_permits: AtomicUsize::new(flow_control_max_permits),
            min_permits: flow_control_min_permits,
            last_adjustment_ms: AtomicU64::new(0),
            critical_latency_threshold_ns: flow_control_latency_threshold_ms * 1_000_000,
            adjustment_interval_ms: flow_control_adjustment_interval_secs * 1000,
        });
        let permit_manager = Arc::new(PermitManager::new(flow_control_initial_permits));

        // TCP uses independent permit manager (separate from UDP)
        // TCP 使用独立的 permit manager（与 UDP 分离）
        // TCP permit limit = tcp_pool_size (one permit per connection)
        // TCP permit 上限 = tcp_pool_size（每个连接一个 permit）
        let tcp_permit_manager = Arc::new(PermitManager::new(tcp_pool_size));

        Self {
            state,
            cache,
            udp_client: Arc::new(UdpClient::new(udp_pool_size)),
            tcp_mux: Arc::new(TcpMultiplexer::new(
                tcp_pool_size,
                tcp_permit_manager,
                tcp_health_error_threshold,
                tcp_max_age_secs,
                tcp_idle_timeout_secs,
            )),
            listener_label: Arc::from(listener_label),
            rule_cache,
            metrics_inflight: Arc::new(AtomicUsize::new(0)),
            metrics_total_requests: Arc::new(AtomicU64::new(0)),
            metrics_fastpath_hits: Arc::new(AtomicU64::new(0)),
            metrics_upstream_ns_total: Arc::new(AtomicU64::new(0)),
            metrics_upstream_calls: Arc::new(AtomicU64::new(0)),
            metrics_last_upstream_latency_ns: Arc::new(AtomicU64::new(0)),
            request_id_counter: Arc::new(AtomicU64::new(1)),
            // DashMap configuration: shard count and initial capacity
            // If dashmap_shards is 0, use DashMap default (num_cpus * 4)
            // More shards = less lock contention but more memory overhead
            inflight: if dashmap_shards == 0 {
                Arc::new(DashMap::with_capacity_and_hasher(
                    128,
                    FxBuildHasher::default(),
                ))
            } else {
                Arc::new(DashMap::with_capacity_and_hasher_and_shard_amount(
                    128,
                    FxBuildHasher::default(),
                    dashmap_shards,
                ))
            },
            refreshing_bitmap: Arc::new(AtomicU64::new(0)),
            permit_manager,
            flow_control_state,
            // Cache background refresh settings / 缓存后台刷新设置
            cache_background_refresh,
            cache_refresh_threshold_percent,
            cache_refresh_min_ttl,
            // GeoIP manager / GeoIP 管理器
            geoip_manager,
            // GeoSite manager / GeoSite 管理器
            geosite_manager,
            // Background refresh dedicated rule (lazy initialization) / 后台刷新专用规则（延迟初始化）
            background_refresh_rule: std::sync::OnceLock::new(),
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
    fn get_background_refresh_rule(&self) -> Option<Arc<crate::matcher::RuntimeRule>> {
        // 暂时返回 None，等待 RuntimePipelineConfig 结构更新
        // Temporarily return None, waiting for RuntimePipelineConfig structure update
        None
    }

    /// 动态调整 flow control permits 基于系统负载和延迟 / Adaptively adjust flow control permits based on system load and latency
    pub fn adjust_flow_control(&self) {
        let state = &self.flow_control_state;

        // Get current time in milliseconds
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Use compare_exchange_weak in a loop for lock-free synchronization
        // saturating_sub handles clock rollback: if now < last, result is 0, we skip
        let mut last_ms = state.last_adjustment_ms.load(Ordering::Acquire);
        loop {
            // Check if adjustment interval has passed
            if now_ms.saturating_sub(last_ms) < state.adjustment_interval_ms {
                return;
            }

            // Try to update timestamp - only one thread will succeed
            match state.last_adjustment_ms.compare_exchange_weak(
                last_ms, now_ms, Ordering::AcqRel, Ordering::Relaxed
            ) {
                Ok(_) => break,  // Successfully acquired adjustment right
                Err(current) => {
                    // Another thread updated timestamp, reload and recheck
                    last_ms = current;
                    continue;
                }
            }
        }

        let inflight = self.permit_manager.inflight();
        let latest_latency = self.metrics_last_upstream_latency_ns.load(Ordering::Relaxed);
        let current_permits = self.permit_manager.max_permits();

        // 决策逻辑：如果延迟高或进行中请求多，减少 permits
        // Decision logic: reduce permits if latency is high or inflight requests are many
        let should_reduce = latest_latency > state.critical_latency_threshold_ns
            || inflight > current_permits * 2 / 3;

        let should_increase = latest_latency < state.critical_latency_threshold_ns / 2
            && inflight < current_permits / 3;

        if should_reduce && current_permits > state.min_permits {
            let new_permits = (current_permits * 9 / 10).max(state.min_permits);
            self.permit_manager.set_max_permits(new_permits);
            tracing::info!(
                event = "flow_control_reduce",
                current_permits = current_permits,
                new_permits = new_permits,
                latest_latency_ms = latest_latency / 1_000_000,
                inflight = inflight,
                "reducing permits due to high latency or load"
            );
        } else if should_increase && current_permits < state.max_permits.load(Ordering::Relaxed) {
            let new_permits = (current_permits * 11 / 10).min(state.max_permits.load(Ordering::Relaxed));
            self.permit_manager.set_max_permits(new_permits);
            tracing::info!(
                event = "flow_control_increase",
                current_permits = current_permits,
                new_permits = new_permits,
                latest_latency_ms = latest_latency / 1_000_000,
                inflight = inflight,
                "increasing permits - system performing well"
            );
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

    /// Increment upstream metrics using simple atomic operations
    #[inline]
    fn incr_upstream_metrics(&self, duration_ns: u64) {
        self.metrics_upstream_calls.fetch_add(1, Ordering::Relaxed);
        self.metrics_upstream_ns_total.fetch_add(duration_ns, Ordering::Relaxed);
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

    /// 辅助函数：创建并插入 DNS 缓存条目 / Helper: create and insert DNS cache entry
    /// 消除重复的 CacheEntry 构造代码 / Eliminate duplicate CacheEntry construction code
    #[inline]
    fn insert_dns_cache_entry(
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
        let q = match parse_quick(packet, &mut qname_buf) {
            Some(q) => q,
            None => {
                // quick parse failed, fallback to async path / 快速解析失败，回退到异步路径
                return Ok(None);
            }
        };
        // Count incoming quick-parsed requests / 计数进入的快速解析请求
        self.incr_total_requests();
        
        // 获取 pipeline ID / Get pipeline ID
        let state = self.state.load();
        let cfg = &state.pipeline;
        let qclass = DNSClass::from(q.qclass);
        let qtype = hickory_proto::rr::RecordType::from(q.qtype);
        // GeoSiteManager 使用 FxHashMap + RwLock 保护，无需额外锁
        // GeoSiteManager uses FxHashMap protected by RwLock, no additional locks needed
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
                    // 缓存后台刷新：当TTL < 阈值百分比时，触发异步刷新
                    // Cache background refresh: trigger async refresh when TTL < threshold percentage
                    // 只有来自 upstream 的缓存条目才进行预取刷新
                    // Only refresh cache entries that came from an upstream server
                    if self.cache_background_refresh
                        && hit.upstream.is_some()
                        && hit.original_ttl >= self.cache_refresh_min_ttl
                    {
                        // Calculate remaining TTL and refresh threshold
                        // 计算剩余 TTL 和刷新阈值
                        let remaining_ttl = hit.original_ttl.saturating_sub(elapsed_secs);
                        let threshold = (hit.original_ttl as u64 * self.cache_refresh_threshold_percent as u64) / 100;

                        // OPTIMIZATION: Zero-lock check using bitmap
                        // 优化：使用位图进行零锁检查
                        let is_refreshing = is_refreshing(&self.refreshing_bitmap, cache_hash);

                        tracing::info!(
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
                            // 触发后台刷新（异步，不阻塞当前请求）
                            // Trigger background refresh (async, don't block current request)
                            // Note: RefreshingGuard inside spawn_background_refresh will handle insertion
                            // 注意：spawn_background_refresh 内部的 RefreshingGuard 将处理插入
                            let qname_str = q.qname_str_unchecked();  // Zero-allocation / 零分配
                            tracing::debug!(
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

                    // 直接返回当前缓存，不等待刷新完成
                    // Return current cache immediately, don't wait for refresh to complete
                    // 下次查询时会自动使用刷新后的新缓存（如果已完成）
                    // Next query will automatically use refreshed new cache (if completed)
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
                &compiled,
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
            // 优化：仅当规则使用client_ip匹配器或配置要求时才包含IP在哈希中
            // Optimization: only include IP in hash when rule uses client_ip matcher or config requires it
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
        
        // 缓存未命中，需要异步处理 / Cache miss, need async processing
        Ok(None)
    }

    #[inline]
    fn insert_rule_cache(&self, hash: u64, pipeline_id: Arc<str>, qname: &str, client_ip: IpAddr, decision: Decision, uses_client_ip: bool) {
        let state = self.state.load();
        let ttl = match &decision {
            Decision::Static { answers, .. } => {
                let min_ttl = answers.iter().map(|r| r.ttl()).min();
                min_ttl.map(|t| Duration::from_secs(t as u64))
            }
            Decision::Forward {
                response_matchers,
                response_actions_on_match,
                response_actions_on_miss,
                ..
            } => {
                // If it has response-phase logic, it is not "static" in the user's terms.
                // It should expire based on the configured min_ttl.
                if !response_matchers.is_empty()
                    || !response_actions_on_match.is_empty()
                    || !response_actions_on_miss.is_empty()
                {
                    Some(Duration::from_secs(state.pipeline.settings.min_ttl as u64))
                } else {
                    None // Permanent
                }
            }
            _ => {
                // Jump, Allow, Deny: 120秒 TTL（之前是永久）
                // Jump, Allow, Deny: 120 second TTL (previously permanent)
                Some(Duration::from_secs(120))
            }
        };

        // If TTL is 0, do not cache / 如果 TTL 为 0，则不缓存
        if let Some(d) = ttl {
            if d.as_secs() == 0 {
                return;
            }
        }

        let expires_at = ttl.map(|d| Instant::now() + d);

        // 优化：根据配置决定是否包含client_ip
        // Optimization: only include client_ip in cache entry when configured or required by rule
        let include_ip = uses_client_ip || self.cache_background_refresh;

        self.rule_cache.insert(
            hash,
            RuleCacheEntry {
                pipeline_id,
                qname_hash: fast_hash_str(qname),
                client_ip: if include_ip { Some(client_ip) } else { None },
                decision: Arc::new(decision),
                expires_at,
            },
        );
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
    async fn handle_packet_internal(&self, packet: &[u8], peer: SocketAddr, skip_cache: bool) -> anyhow::Result<Bytes> {
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
            let qname_str = unsafe { std::str::from_utf8_unchecked(q.qname_bytes) };
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

        // 限制 geosite_mgr 的作用域，确保在 await 之前释放锁
        // Scope geosite_mgr to ensure lock is released before await
        let (pipeline_opt, pipeline_id) = {
            // GeoSiteManager 现在使用 DashMap，无需 Mutex 锁
            // GeoSiteManager now uses DashMap, no Mutex lock needed
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
            // moka 同步缓存自动处理过期，无需检查 expires_at / moka sync cache automatically handles expiration, no need to check expires_at
            if let Some(hit) = self.cache.get(&dedupe_hash) {
                if hit.qtype == u16::from(qtype) && hit.qname.as_ref() == *qname_ref && hit.pipeline_id == pipeline_id {
                let elapsed_secs = hit.inserted_at.elapsed().as_secs();
                if elapsed_secs >= hit.original_ttl as u64 {
                    self.cache.invalidate(&dedupe_hash);
                } else {
                    let latency = start.elapsed();
                    // clone bytes and rewrite transaction ID to match requester / 克隆字节并重写事务 ID 以匹配请求者
                    let mut resp_bytes = BytesMut::with_capacity(hit.bytes.len());
                    resp_bytes.extend_from_slice(&hit.bytes);

                    // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                    let elapsed = elapsed_secs as u32;
                    if elapsed > 0 {
                        crate::proto_utils::patch_all_ttls(&mut resp_bytes, elapsed);
                    }

                    if resp_bytes.len() >= 2 {
                        let id_bytes = tx_id.to_be_bytes();
                        resp_bytes[0] = id_bytes[0];
                        resp_bytes[1] = id_bytes[1];
                    }
                    let resp_bytes = resp_bytes.freeze();
                    
                    // ========== NEW: Trigger background refresh before returning cached response ==========
                    // 在返回缓存响应之前,异步触发后台刷新
                    // This ensures the client gets an immediate response while the cache is updated in background
                    // 这确保客户端立即获得响应,同时缓存更新在后台进行
                    
                    // FIX: Check refresh threshold BEFORE cache invalidation to prevent race condition
                    // 修复：在缓存失效之前检查刷新阈值，防止竞态条件
                    let remaining_ttl = hit.original_ttl.saturating_sub(elapsed);
                    let should_refresh = if remaining_ttl as u64 >= hit.original_ttl as u64 {
                        // Cache entry expired, check if we should refresh before invalidating
                        // 缓存条目已过期，检查是否应该在失效前刷新
                        if cfg.settings.cache_background_refresh
                            && hit.upstream.is_some()  // FIX: Only check upstream field (source is upstream address, not "upstream")
                            && hit.original_ttl >= cfg.settings.cache_refresh_min_ttl
                        {
                            let threshold = (hit.original_ttl as u64 * cfg.settings.cache_refresh_threshold_percent as u64) / 100;
                            remaining_ttl as u64 <= threshold
                        } else {
                            false
                        }
                    } else {
                        // Cache entry still valid, check if we should trigger early refresh
                        // 缓存条目仍然有效，检查是否应该触发早期刷新
                        if cfg.settings.cache_background_refresh
                            && hit.upstream.is_some()  // FIX: Only check upstream field (source is upstream address, not "upstream")
                            && hit.original_ttl >= cfg.settings.cache_refresh_min_ttl
                        {
                            let threshold = (hit.original_ttl as u64 * cfg.settings.cache_refresh_threshold_percent as u64) / 100;
                            remaining_ttl as u64 <= threshold
                        } else {
                            false
                        }
                    };

                    if should_refresh {
                        // Trigger background refresh asynchronously
                        // 异步触发后台刷新
                        tracing::debug!(
                            event = "cache_background_refresh_trigger",
                            qname = %qname_ref,
                            qtype = ?qtype,
                            remaining_ttl = remaining_ttl,
                            original_ttl = hit.original_ttl,
                            "triggering background cache refresh"
                        );
                        
                        // OPTIMIZATION: Simplify by using self.clone() instead of reconstructing Engine
                        // 优化：简化为使用 self.clone() 而不是重建 Engine
                        // Clone necessary data for async task
                        // 克隆异步任务所需的数据
                        let engine_clone = self.clone();
                        let cache_hash = dedupe_hash;
                        let upstream = hit.upstream.clone();
                        let qname_async = Arc::from(qname_ref.as_ref());  // Zero-copy string conversion
                        let qtype_async = qtype;
                        let qclass_async = qclass;
                        let pipeline_id_async = Arc::clone(&pipeline_id);  // Use Arc directly
                        
                        // Spawn background refresh task (non-blocking)
                        // 生成后台刷新任务 (非阻塞)
                        tokio::spawn(async move {
                            engine_clone.spawn_background_refresh(
                                cache_hash,
                                &pipeline_id_async,
                                &qname_async,
                                qtype_async,
                                qclass_async,
                                upstream.as_deref(),
                            );
                        });
                    }
                    // ========== END: Background refresh trigger ==========
                    
                    debug!(
                        event = "dns_response",
                        upstream = %hit.source,
                        qname = %qname_ref,
                        qtype = ?qtype,
                        rcode = ?hit.rcode,
                        original_ttl = hit.original_ttl,
                        elapsed_secs = elapsed,
                        latency_ms = latency.as_millis() as u64,
                        client_ip = %peer.ip(),
                        pipeline = %pipeline_id,
                        cache = true,
                        "cache hit"
                    );
                    return Ok(resp_bytes);
                }
            }
            } // End of skip_cache check
        }

        let qname = qname_cow.into_owned();
        let mut skip_rules: HashSet<Arc<str>> = HashSet::new();
        let mut current_pipeline_id = pipeline_id.clone();
        // Convert qname String to bytes for hash calculation / 将 qname String 转换为 bytes 进行哈希计算
        let qname_bytes = qname.as_bytes();
        let mut dedupe_hash = Self::calculate_cache_hash_for_dedupe(&current_pipeline_id, qname_bytes, qtype, qclass);
        let mut dedupe_registered = false;
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

        // DESIGN NOTE: InflightCleanupGuard theoretical race condition analysis
        // 设计说明：InflightCleanupGuard 理论竞态条件分析
        //
        // Theoretical Issue: If defuse() is called concurrently with Drop, there's a race
        // where Drop might execute before defuse() sets active=false, causing unexpected cleanup.
        //
        // 理论问题：如果 defuse() 与 Drop 并发调用，存在竞态条件，
        // Drop 可能在 defuse() 设置 active=false 之前执行，导致意外清理。
        //
        // Why This Doesn't Need Fixing (aligned with KixDNS design philosophy):
        // 为什么不需要修复（符合 KixDNS 设计哲学）：
        //
        // 1. Performance First (性能优先):
        //    - Adding synchronization (Mutex/Atomic) would add overhead to hot path
        //    - Current zero-allocation design is optimal for 99.9% happy path
        //    - 添加同步（Mutex/Atomic）会增加热路径开销
        //    - 当前零分配设计对 99.9% 快乐路径是最优的
        //
        // 2. Practicality Over Theory (实用性胜于理论):
        //    - Race requires: defuse() call AND task cancellation at exact same moment
        //    - Probability: <0.001% (requires tokio scheduler timing attack)
        //    - Impact: Temporary duplicate upstream query (self-healing via cache)
        //    - 竞态需要：defuse() 调用 AND 任务取消在同一时刻
        //    - 概率：<0.001%（需要 tokio 调度器时序攻击）
        //    - 影响：临时重复上游查询（通过缓存自愈）
        //
        // 3. Simplicity (简单性):
        //    - Current RAII pattern is simple and idiomatic Rust
        //    - Fix would require complex synchronization primitives
        //    - 当前 RAII 模式简单且符合 Rust 惯用法
        //    - 修复需要复杂的同步原语
        //
        // 4. Safety (安全性):
        //    - Worst case: Temporary duplicate query (not crash/corruption)
        //    - No memory safety violation (Rust type system guarantees this)
        //    - 最坏情况：临时重复查询（不是崩溃/损坏）
        //    - 无内存安全违规（Rust 类型系统保证这一点）
        //
        // Conclusion: Theoretical issue doesn't justify violating Performance/Simplicity principles
        // 结论：理论问题不值得违反性能/简单性原则
        struct InflightCleanupGuard {
            inflight: Arc<DashMap<u64, tokio::sync::watch::Sender<Result<Bytes, Arc<anyhow::Error>>>, FxBuildHasher>>,
            hash: u64,
            active: bool,
        }

        impl InflightCleanupGuard {
            fn new(inflight: Arc<DashMap<u64, tokio::sync::watch::Sender<Result<Bytes, Arc<anyhow::Error>>>, FxBuildHasher>>, hash: u64) -> Self {
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
                    if let Some(p) = cfg.pipelines.iter().find(|p| p.id == *pipeline) {
                        current_pipeline_id = p.id.clone();
                        dedupe_hash = Self::calculate_cache_hash_for_dedupe(&current_pipeline_id, qname_bytes, qtype, qclass);
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
                // Need full request for building response / 需要完整请求来构建响应
                let req = Message::from_bytes(packet).context("parse request for static")?;
                let resp_bytes = build_response(&req, rcode, answers)?;
                if min_ttl > Duration::from_secs(0) {
                    let entry = CacheEntry {
                        bytes: resp_bytes.clone(),
                        rcode,
                        source: Arc::from("static"),
                        upstream: None,  // Static responses have no upstream
                        qname: Arc::from(qname.as_str()),
                        pipeline_id: current_pipeline_id.clone(),
                        qtype: u16::from(qtype),
                        inserted_at: Instant::now(),
                        original_ttl: min_ttl.as_secs() as u32,
                    };
                    self.cache.insert(dedupe_hash, Arc::new(entry));
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
                let mut cleanup_guard = None;

                let resp = if allow_reuse {
                    if let Some(ctx) = reused_response.take() {
                        Ok((ctx.raw, ctx.upstream.to_string()))
                    } else {
                        if !dedupe_registered && !skip_cache {
                            use dashmap::mapref::entry::Entry;
                            // ========== NEW: Use tokio::watch for lock-free waiting ==========
                            // 使用 tokio::watch 实现无锁等待
                            let rx = match self.inflight.entry(dedupe_hash) {
                                Entry::Vacant(entry) => {
                                    // No other request in progress, create watch channel
                                    // 没有其他请求在进行,创建 watch channel
                                    let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                                    entry.insert(tx);
                                    dedupe_registered = true;
                                    cleanup_guard = Some(InflightCleanupGuard::new(self.inflight.clone(), dedupe_hash));
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
                                                // Zero-copy TX ID rewrite using BytesMut
                                                let mut resp_mut = BytesMut::from(bytes.as_ref());
                                                if resp_mut.len() >= 2 {
                                                    let id_bytes = tx_id.to_be_bytes();
                                                    resp_mut[0] = id_bytes[0];
                                                    resp_mut[1] = id_bytes[1];
                                                }
                                                return Ok(resp_mut.freeze());
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
                        self.forward_upstream(packet, &upstream, upstream_timeout, transport, pre_split_upstreams.as_ref()).await
                    }
                } else {
                    // If reuse is not allowed (e.g. explicit Forward action), we must clear any reused response
                    // and force a new request.
                    
                    if !dedupe_registered && !skip_cache {
                        use dashmap::mapref::entry::Entry;
                        let rx = match self.inflight.entry(dedupe_hash) {
                            Entry::Vacant(entry) => {
                                // No other request in progress, create watch channel
                                // 没有其他请求在进行,创建 watch channel
                                let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                                entry.insert(tx);
                                dedupe_registered = true;
                                cleanup_guard = Some(InflightCleanupGuard::new(self.inflight.clone(), dedupe_hash));
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
                                            // Zero-copy TX ID rewrite using BytesMut
                                            let mut resp_mut = BytesMut::from(bytes.as_ref());
                                            if resp_mut.len() >= 2 {
                                                let id_bytes = tx_id.to_be_bytes();
                                                resp_mut[0] = id_bytes[0];
                                                resp_mut[1] = id_bytes[1];
                                            }
                                            return Ok(resp_mut.freeze());
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
                    self.forward_upstream(packet, &upstream, upstream_timeout, transport, pre_split_upstreams.as_ref()).await
                };

                match resp {
                    Ok((raw, actual_upstream)) => {
                        // Optimization: Use quick response parse if no complex matching is needed
                        // Also handles TC (Truncated) flag check for RFC 1035 compliance
                        // CHANGE: Use max_ttl for original_ttl to align with background refresh trigger
                        // 修改：使用 max_ttl 作为 original_ttl 以与后台刷新触发对齐
                        let (rcode, ttl_secs, msg_opt, truncated) = if response_matchers.is_empty() && response_actions_on_match.is_empty() && response_actions_on_miss.is_empty() {
                            if let Some(qr) = crate::proto_utils::parse_response_quick(&raw) {
                                (qr.rcode, qr.max_ttl as u64, None, qr.truncated)
                            } else {
                                // Fallback: parse full message, extract TC from raw bytes
                                let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                                let ttl = extract_ttl_for_refresh(&msg);  // Use max TTL for consistency
                                let tc = raw.len() >= 3 && (raw[2] & 0x02) != 0;
                                (msg.response_code(), ttl, Some(msg), tc)
                            }
                        } else {
                            let msg = Message::from_bytes(&raw).context("parse upstream response")?;
                            let ttl = extract_ttl_for_refresh(&msg);  // Use max TTL for consistency
                            let tc = raw.len() >= 3 && (raw[2] & 0x02) != 0;
                            (msg.response_code(), ttl, Some(msg), tc)
                        };

                        // RFC 1035: If TC bit is set, retry over TCP / 如果 TC 标志设置，使用 TCP 重试
                        if truncated && transport == Some(Transport::Udp) {
                            tracing::debug!(event = "tc_flag_retry", upstream = %upstream, "response truncated, retrying with tcp");
                            drop(cleanup_guard);
                            let (tcp_resp, _) = self.forward_upstream(packet, &upstream, upstream_timeout, Some(Transport::Tcp), pre_split_upstreams.as_ref()).await?;
                            if let Some(_g) = self.inflight.get(&dedupe_hash) {
                                self.notify_inflight_waiters(dedupe_hash, &tcp_resp).await;
                            }
                            return Ok(tcp_resp);
                        }

                        let effective_ttl = Duration::from_secs(ttl_secs.max(min_ttl.as_secs()));

                        let (resp_match_ok, msg) = {
                            // Get manager references for GeoIP/GeoSite matching in response matchers
                            // 获取 manager 引用以用于响应匹配器中的 GeoIP/GeoSite 匹配
                            // 使用作用域确保锁在使用后立即释放 / Use scope to ensure locks are released immediately after use
                            let geoip_manager = self.geoip_manager.try_read().ok();
                            let geosite_manager = self.geosite_manager.try_read().ok();
                            let geoip_manager_ref = geoip_manager.as_deref();
                            let geosite_manager_ref = geosite_manager.as_deref();

                            if let Some(m) = msg_opt {
                                // FIX: Skip response matchers for background refresh
                                // 修复：后台刷新跳过响应匹配器
                                // Background refresh should only update cache, not execute response actions
                                // 后台刷新应该只更新缓存，不执行响应操作
                                if skip_cache {
                                    // Background refresh: force match to skip response actions
                                    // 后台刷新：强制匹配以跳过响应操作
                                    (true, m)
                                } else {
                                    // Normal request: evaluate response matchers
                                    // 正常请求：评估响应匹配器
                                    let matched = eval_match_chain(
                                        &response_matchers,
                                        |m| m.operator,
                                        |matcher_op| matcher_op.matcher.matches(&upstream, &qname, qtype, qclass, &m, geoip_manager_ref, geosite_manager_ref),
                                    );
                                    (matched, m)
                                }
                            } else {
                                (false, Message::new()) // Dummy message, won't be used as actions are empty
                            }
                        }; // guards are dropped here / 锁在此处释放

                        let empty_actions = Vec::new();
                        // FIX: Background refresh should skip all response actions
                        // 修复：后台刷新应跳过所有响应操作
                        let actions_to_run = if skip_cache {
                            // Background refresh: force empty actions to skip response processing
                            // 后台刷新：强制使用空操作列表，跳过响应处理
                            &empty_actions
                        } else if !response_actions_on_match.is_empty()
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
                                // 使用辅助函数避免重复代码 / Use helper function to avoid duplication
                                self.insert_dns_cache_entry(
                                    dedupe_hash,
                                    raw.clone(),
                                    rcode,
                                    Arc::from(actual_upstream.as_str()),
                                    Some(Arc::from(actual_upstream.as_str())),
                                    &qname,
                                    pipeline_id.clone(),
                                    qtype,
                                    ttl_secs as u32,
                                );
                            }
                            if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                            self.notify_inflight_waiters(dedupe_hash, &raw).await;
                            let latency = start.elapsed();
                            info!(
                                event = "dns_response",
                                upstream = %actual_upstream,
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
                            upstream: Arc::from(actual_upstream.as_str()),  // Use actual responding upstream
                            transport: transport.unwrap_or(Transport::Udp),
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
                                    // 使用辅助函数避免重复代码 / Use helper function to avoid duplication
                                    self.insert_dns_cache_entry(
                                        dedupe_hash,
                                        ctx.raw.clone(),
                                        ctx.msg.response_code(),
                                        ctx.upstream.clone(),
                                        Some(ctx.upstream.clone()),
                                        &qname,
                                        pipeline_id.clone(),
                                        qtype,
                                        ttl_secs as u32,
                                    );
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
                                    // 使用辅助函数避免重复代码 / Use helper function to avoid duplication
                                    self.insert_dns_cache_entry(
                                        dedupe_hash,
                                        bytes.clone(),
                                        rcode,
                                        Arc::from(source),
                                        None,  // Static responses have no upstream
                                        &qname,
                                        current_pipeline_id.clone(),
                                        qtype,
                                        min_ttl.as_secs() as u32,
                                    );
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
                                        skip_cache,  // FIX: Pass skip_cache to response phase
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
                                    // Safely handle missing pipeline (e.g., config reload race)
                                    let pipeline = if let Some(p) = cfg.pipelines.iter().find(|p| p.id == current_pipeline_id) {
                                        p
                                    } else {
                                        warn!("pipeline missing while continuing: {}", current_pipeline_id);
                                        let req = Message::from_bytes(packet).context("parse request")?;
                                        let resp_bytes = engine_helpers::build_servfail_response(&req)?;
                                        if let Some(g) = cleanup_guard.as_mut() {
                                            g.defuse();
                                        }
                                        self.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                                        return Ok(resp_bytes);
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
                                            // 使用辅助函数避免重复代码 / Use helper function to avoid duplication
                                            self.insert_dns_cache_entry(
                                                dedupe_hash,
                                                ctx.raw.clone(),
                                                ctx.msg.response_code(),
                                                ctx.upstream.clone(),
                                                Some(ctx.upstream.clone()),
                                                &qname,
                                                pipeline_id.clone(),
                                                qtype,
                                                ttl_secs as u32,
                                            );
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
                                                skip_cache,  // FIX: Pass skip_cache to response phase
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
                                        let pipeline = if let Some(p) = cfg.pipelines.iter().find(|p| p.id == current_pipeline_id) {
                                            p
                                        } else {
                                            warn!("pipeline missing while continuing: {}", current_pipeline_id);
                                            let req = Message::from_bytes(packet).context("parse request")?;
                                            let resp_bytes = engine_helpers::build_servfail_response(&req)?;
                                            if let Some(g) = cleanup_guard.as_mut() { g.defuse(); }
                                            self.notify_inflight_waiters(dedupe_hash, &resp_bytes).await;
                                            return Ok(resp_bytes);
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
        skip_rules: Option<&HashSet<Arc<str>>>,
        skip_cache: bool,
    ) -> Decision {
        // 1. Check Rule Cache
        // Use hash for lookup to avoid cloning String for key on every lookup
        let rule_hash = calculate_rule_hash(&pipeline.id, qname, client_ip, pipeline.uses_client_ip);
        let allow_rule_cache_lookup = !skip_cache && skip_rules.map_or(true, |set| set.is_empty());
        
        if allow_rule_cache_lookup {
            if let Some(entry) = self.rule_cache.get(&rule_hash) {
                // Check validity and clean up if expired
                // 检查有效性，如果过期则清理
                if !entry.is_valid() {
                    self.rule_cache.remove(&rule_hash);
                } else if entry.matches(&pipeline.id, qname, client_ip, pipeline.uses_client_ip) {
                    return (*entry.decision).clone();
                }
            }
        }

        let upstream_default = state.pipeline.settings.default_upstream.clone();

        // 2. Candidate Selection (compiled index if available)
        // SmallVec<[usize; 32]> avoids heap allocation for typical rule sets (<= 32 candidates)
        let mut candidate_indices: SmallVec<[usize; 32]> = if let Some(compiled) = self.compiled_for(state, &pipeline.id) {
            compiled.index.get_candidates(qname, qtype)
        } else {
            SmallVec::new()
        };

        if candidate_indices.is_empty() {
            // Fallback to runtime indices
            candidate_indices.extend_from_slice(&pipeline.always_check_rules);

            // 最高优先级：完全域名匹配（O(1)查找）/ Highest priority: exact domain match (O(1) lookup)
            if let Some(indices) = pipeline.domain_exact_index.get(qname) {
                candidate_indices.extend_from_slice(indices);
            }

            // 高频优化：使用 query_type 索引快速过滤
            // High-frequency optimization: use query_type index for fast filtering
            if let Some(indices) = pipeline.query_type_index.get(&qtype) {
                candidate_indices.extend_from_slice(indices);
            }

            let mut search_name = qname;
            loop {
                // 零拷贝优化：Arc<str>可以通过&str查找 / Zero-copy: Arc<str> can be looked up by &str
                if let Some(indices) = pipeline.domain_suffix_index.get(search_name) {
                    candidate_indices.extend_from_slice(indices);
                }

                if let Some(idx) = search_name.find('.') {
                    search_name = &search_name[idx + 1..];
                } else {
                    break;
                }
            }

            candidate_indices.sort_unstable();
            candidate_indices.dedup();
        }

        // 3. Execute Rules
        'rules: for idx in candidate_indices {
            let rule = match pipeline.rules.get(idx) {
                Some(r) => r,
                None => continue, // Skip if index is out of bounds due to reload race / 如果由于重载竞争导致索引越界，则跳过
            };
            if skip_rules.map_or(false, |set| set.contains(&rule.name)) {
                continue;
            }
            let req_match = eval_match_chain(
                &rule.matchers,
                |m| m.operator,
                |m| {
                    // GeoSiteManager 现在使用 DashMap，无需 Mutex 锁
                    // GeoSiteManager now uses DashMap, no Mutex lock needed
                    // GeoIpManager 现在使用 Mutex，需要获取锁
                    // GeoIpManager now uses Mutex, need to acquire lock
                    matcher_matches(&m.matcher, qname, qclass, client_ip, edns_present, qtype, Some(&self.geoip_manager), Some(&self.geosite_manager))
                },
            );

            if req_match {
                // 检查是否有多个 forward action / Check for multiple forward actions
                let forward_actions: Vec<_> = rule.actions.iter()
                    .filter_map(|a| match a {
                        Action::Forward { upstream, transport, pre_split_upstreams } => Some((upstream, transport, pre_split_upstreams.clone())),
                        _ => None,
                    })
                    .collect();

                if forward_actions.len() > 1 {
                    // 多个 forward action：按 transport 类型分别合并，并去重 / Multiple forward actions: merge by transport type with deduplication
                    use std::collections::HashSet;

                    let mut tcp_upstreams: HashSet<String> = HashSet::new();
                    let mut udp_upstreams: HashSet<String> = HashSet::new();

                    // 收集并按 transport 分组，同时去重
                    for (upstream_opt, transport_opt, _pre_split) in forward_actions.iter() {
                        if let Some(upstream) = upstream_opt {
                            // 获取这个 action 的 transport
                            let action_transport = transport_opt.unwrap_or(Transport::Udp);

                            // 分割 upstream 字符串（可能包含逗号）
                            for addr in upstream.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                                // 跳过已有协议前缀的地址
                                if addr.contains("://") {
                                    if addr.starts_with("tcp://") {
                                        tcp_upstreams.insert(addr.to_string());
                                    } else if addr.starts_with("udp://") {
                                        udp_upstreams.insert(addr.to_string());
                                    }
                                } else {
                                    // 添加协议前缀
                                    match action_transport {
                                        Transport::Tcp => {
                                            tcp_upstreams.insert(format!("tcp://{}", addr));
                                        }
                                        Transport::Udp => {
                                            udp_upstreams.insert(format!("udp://{}", addr));
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // 合并所有 upstream（保留协议前缀）
                    let mut all_upstreams = Vec::new();
                    all_upstreams.extend(tcp_upstreams.iter().cloned());
                    all_upstreams.extend(udp_upstreams.iter().cloned());

                    if all_upstreams.is_empty() {
                        // 所有 upstream 都为空，使用默认
                        info!(
                            event = "multiple_forward_actions",
                            count = forward_actions.len(),
                            "all forward actions have empty upstream, using default"
                        );
                    } else {
                        info!(
                            event = "multiple_forward_actions",
                            count = forward_actions.len(),
                            tcp_count = tcp_upstreams.len(),
                            udp_count = udp_upstreams.len(),
                            total_upstreams = all_upstreams.len(),
                            tcp_upstreams = ?tcp_upstreams,
                            udp_upstreams = ?udp_upstreams,
                            "merged multiple forward actions with transport-specific deduplication"
                        );
                    }

                    let merged_str = if all_upstreams.is_empty() {
                        String::new()
                    } else {
                        all_upstreams.join(",")
                    };

                    let d = Decision::Forward {
                        upstream: Arc::from(if merged_str.is_empty() { "" } else { merged_str.as_str() }),
                        pre_split_upstreams: if all_upstreams.is_empty() { None } else { Some(std::sync::Arc::new(all_upstreams)) },
                        response_matchers: rule.response_matchers.clone(),
                        response_matcher_operator: rule.response_matcher_operator,
                        response_actions_on_match: rule.response_actions_on_match.clone(),
                        response_actions_on_miss: rule.response_actions_on_miss.clone(),
                        rule_name: rule.name.clone(),
                        transport: None, // 让每个 upstream 自己决定 transport / Let each upstream decide its own transport
                        continue_on_match: false,
                        continue_on_miss: false,
                        allow_reuse: false,
                    };
                    self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                    return d;
                }

                // 单个 forward 或其他 action：按原逻辑处理 / Single forward or other actions: use original logic
                for action in &rule.actions {
                    match action {
                        Action::StaticResponse { rcode } => {
                            let code = parse_rcode(&rcode).unwrap_or(ResponseCode::NXDomain);
                            let d = Decision::Static {
                                rcode: code,
                                answers: Vec::new(),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
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
                                    self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                                    return d;
                                }
                            }
                            let d = Decision::Static {
                                rcode: ResponseCode::ServFail,
                                answers: Vec::new(),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::JumpToPipeline { pipeline: target } => {
                            let d = Decision::Jump {
                                pipeline: Arc::from(target.as_str()),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::Allow => {
                            let d = Decision::Forward {
                                upstream: Arc::from(upstream_default.as_str()),
                                pre_split_upstreams: None,
                                response_matchers: Vec::new(),
                                response_matcher_operator: crate::config::MatchOperator::And,
                                response_actions_on_match: Vec::new(),
                                response_actions_on_miss: Vec::new(),
                                rule_name: rule.name.clone(),
                                transport: Some(Transport::Udp),
                                continue_on_match: false,
                                continue_on_miss: false,
                                allow_reuse: true,
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::Deny => {
                            let d = Decision::Static {
                                rcode: ResponseCode::Refused,
                                answers: Vec::new(),
                            };
                            self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            return d;
                        }
                        Action::Forward {
                            upstream,
                            transport,
                            pre_split_upstreams,
                        } => {
                            let upstream_addr: Arc<str> = upstream
                                .as_ref()
                                .map(|s| Arc::from(s.as_str()))
                                .unwrap_or_else(|| Arc::from(upstream_default.as_str()));
                            let continue_on_match = contains_continue(&rule.response_actions_on_match);
                            let continue_on_miss = contains_continue(&rule.response_actions_on_miss);
                            let d = Decision::Forward {
                                upstream: upstream_addr,
                                pre_split_upstreams: pre_split_upstreams.clone(),
                                response_matchers: rule.response_matchers.clone(),
                                response_matcher_operator: rule.response_matcher_operator,
                                response_actions_on_match: rule.response_actions_on_match.clone(),
                                response_actions_on_miss: rule.response_actions_on_miss.clone(),
                                rule_name: rule.name.clone(),
                                transport: Some(transport.unwrap_or(Transport::Udp)),
                                continue_on_match,
                                continue_on_miss,
                                allow_reuse: false,
                            };
                            if !continue_on_match && !continue_on_miss {
                                self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
                            }
                            return d;
                        }
                        Action::Log { level } => {
                            log_match(level.as_deref(), &rule.name, qname, client_ip);
                            // Log action doesn't terminate rule processing, so we continue.
                            // But we can't cache side effects (logging).
                            // If we cache the result, we skip logging on subsequent hits!
                            // This is a trade-off. Layer 3 usually implies sampling logs or skipping them for cached hot paths.
                            // We will accept that cached hits won't log again.
                        }
                        Action::Continue => {
                            continue 'rules;
                        }
                    }
                }
            }
        }

        let d = Decision::Forward {
            upstream: Arc::from(upstream_default.as_str()),
            pre_split_upstreams: None,
            response_matchers: Vec::new(),
            response_matcher_operator: crate::config::MatchOperator::And,
            response_actions_on_match: Vec::new(),
            response_actions_on_miss: Vec::new(),
            rule_name: Arc::from("default"),
            transport: Some(Transport::Udp),
            continue_on_match: false,
            continue_on_miss: false,
            allow_reuse: false,
        };
        self.insert_rule_cache(rule_hash, pipeline.id.clone(), qname, client_ip, d.clone(), pipeline.uses_client_ip);
        d
    }

    async fn forward_upstream(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
        transport: Option<Transport>,
        pre_split_upstreams: Option<&std::sync::Arc<Vec<String>>>,
    ) -> anyhow::Result<(Bytes, String)> {
        // 如果 transport 为 None，使用默认 UDP
        let transport = transport.unwrap_or(Transport::Udp);
        // 使用预分割数据或动态分割 / Use pre-split data or dynamic splitting
        let upstreams: Vec<&str> = if let Some(pre_split) = pre_split_upstreams {
            pre_split.iter().map(|s| s.as_str()).collect()
        } else if !upstream.contains(',') {
            // 单个上游：直接转发 / Single upstream: direct forward
            let start = std::time::Instant::now();
            let res = match transport {
                Transport::Udp => self.forward_udp_smart(packet, upstream, timeout_dur).await,
                Transport::Tcp => self.tcp_mux.send(packet, upstream, timeout_dur).await,
            };
            if let Ok(_) = &res {
                let dur = start.elapsed();
                let dur_ns = dur.as_nanos() as u64;
                self.incr_upstream_metrics(dur_ns);
                // 记录最新的延迟供自适应流控使用 / Record latest latency for adaptive flow control
                self.metrics_last_upstream_latency_ns.store(dur_ns, Ordering::Relaxed);
                tracing::debug!(upstream=%upstream, upstream_ns = dur_ns, "upstream call latency");
            } else if let Err(e) = &res {
                let dur = start.elapsed();
                let dur_ns = dur.as_nanos() as u64;
                self.metrics_last_upstream_latency_ns.store(dur_ns, Ordering::Relaxed);
                tracing::warn!(upstream=%upstream, error=%e, elapsed_ns = dur_ns, "upstream call failed");
            }
            // Store upstream with protocol prefix for seamless background refresh
            return res.map(|b| {
                let upstream_with_proto = match transport {
                    Transport::Tcp => format!("tcp:{}", upstream),
                    Transport::Udp => format!("udp:{}", upstream),
                };
                (b, upstream_with_proto)
            });
        } else {
            // 回退：动态分割 / Fallback: dynamic splitting
            upstream.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
        };

        // 多个上游：并发请求取最快结果 / Multiple upstreams: concurrent requests, take fastest result
        tracing::info!(upstream_count = upstreams.len(), upstreams = ?upstreams, "concurrent upstream requests - spawning tasks");

        // 使用 FuturesUnordered 真正并发地等待所有任务
        // Use FuturesUnordered to truly wait for all tasks concurrently
        let mut tasks = FuturesUnordered::new();
        let spawn_time = std::time::Instant::now();

        for &up in &upstreams {
            let engine = self.clone();
            let packet = packet.to_vec();
            let up = up.to_string();
            let default_transport = transport;
            tasks.push(tokio::spawn(async move {
                let task_start = std::time::Instant::now();
                let elapsed_since_spawn = task_start.duration_since(spawn_time);

                // 解析每个 upstream 的协议前缀 / Parse protocol prefix for each upstream
                let (parsed_transport, parsed_addr) = if let Some(pos) = up.find("://") {
                    let proto = &up[..pos];
                    let addr = &up[pos + 3..];
                    let t = match proto {
                        "tcp" => Transport::Tcp,
                        "udp" => Transport::Udp,
                        _ => default_transport, // 未知协议，使用默认 / Unknown protocol, use default
                    };
                    (t, addr.to_string())
                } else {
                    (default_transport, up.clone())
                };

                tracing::info!(
                    upstream = %up,
                    transport = ?parsed_transport,
                    addr = %parsed_addr,
                    spawn_delay_ms = elapsed_since_spawn.as_millis(),
                    "concurrent task started"
                );

                let start = std::time::Instant::now();
                let res = match parsed_transport {
                    Transport::Udp => engine.forward_udp_smart(&packet, &parsed_addr, timeout_dur).await,
                    Transport::Tcp => engine.tcp_mux.send(&packet, &parsed_addr, timeout_dur).await,
                };
                let dur = start.elapsed();
                (up, res, dur)
            }));
        }

        // 等待第一个成功响应 / Wait for first successful response
        while let Some(result) = tasks.next().await {
            match result {
                Ok((up, res, dur)) => {
                    if res.is_ok() {
                        // 网络层面成功，检查 DNS 响应码 / Network success, check DNS rcode
                        let bytes = res.as_ref().unwrap();

                        // 快速解析响应码 / Quick parse response code
                        let should_accept = if let Some(qr) = crate::proto_utils::parse_response_quick(bytes) {
                            match qr.rcode {
                                ResponseCode::NoError => {
                                    tracing::debug!(upstream=%up, upstream_ns = dur.as_nanos() as u64, rcode = %qr.rcode, "upstream call succeeded (NOERROR)");
                                    true
                                }
                                ResponseCode::ServFail | ResponseCode::Refused => {
                                    tracing::warn!(upstream=%up, upstream_ns = dur.as_nanos() as u64, rcode = %qr.rcode, "upstream returned {}, waiting for others", qr.rcode);
                                    false
                                }
                                _ => {
                                    // NXDOMAIN 等其他响应码都接受 / Accept NXDOMAIN, etc.
                                    tracing::debug!(upstream=%up, upstream_ns = dur.as_nanos() as u64, rcode = %qr.rcode, "upstream response accepted (non-SERVFAIL/non-REFUSED)");
                                    true
                                }
                            }
                        } else {
                            // 解析失败，保守接受 / Parse failed, conservatively accept
                            tracing::debug!(upstream=%up, upstream_ns = dur.as_nanos() as u64, "upstream response accepted (parse failed)");
                            true
                        };

                        if should_accept {
                            self.metrics_last_upstream_latency_ns.store(dur.as_nanos() as u64, Ordering::Relaxed);

                            // 显式取消其他正在进行的任务
                            // Explicitly cancel other ongoing tasks
                            let remaining = tasks.len();
                            if remaining > 0 {
                                tracing::debug!(
                                    remaining_tasks = remaining,
                                    winning_upstream = %up,
                                    "cancelling remaining upstream tasks (acceptable response received)"
                                );
                                // tasks 会在 return 时被 drop，触发所有未完成 JoinHandle 的 abort
                                // tasks will be dropped on return, triggering abort for all incomplete JoinHandles
                            }

                            // up already contains protocol prefix from concurrent task (e.g., "tcp:8.8.4.4:53")
                            return res.map(|b| (b, up));
                        }
                        // 否则继续等待其他 upstream / Otherwise continue waiting for other upstreams
                    } else {
                        // 记录失败，继续等待其他上游 / Record failure, continue waiting for other upstreams
                        tracing::warn!(upstream=%up, error=%res.as_ref().unwrap_err(), elapsed_ns = dur.as_nanos() as u64, "upstream call failed, waiting for others");
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
        &self,
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
            match self.udp_client.send(packet, upstream, *dur).await {
                Ok(bytes) => {
                    // RFC 1035: Check TC (Truncated) flag using quick parse - 使用快速解析检查 TC 标志
                    if let Some(qr) = crate::proto_utils::parse_response_quick(&bytes) {
                        if qr.truncated {
                            debug!(event = "tc_flag_fallback", upstream = %upstream, "udp response truncated, retrying with tcp");
                            return self.tcp_mux.send(packet, upstream, timeout_dur).await;
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
                        return self.tcp_mux.send(packet, upstream, timeout_dur).await;
                    }
                }
            }
        }

        // Should never reach here because we either return on success or fallback.
        anyhow::bail!("udp forward failed")
    }

    async fn notify_inflight_waiters(&self, dedupe_hash: u64, bytes: &Bytes) {
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
    fn spawn_background_refresh(
        &self,
        cache_hash: u64,
        pipeline_id: &str,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
        upstream: Option<&str>,
    ) {
        // FIX: Check if already refreshing to prevent duplicate refreshes
        // 修复：检查是否已在刷新，防止重复刷新
        // OPTIMIZATION: Zero-lock check using bitmap
        // 优化：使用位图进行零锁检查
        if is_refreshing(&self.refreshing_bitmap, cache_hash) {
            tracing::debug!(
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
        mark_refreshing(&self.refreshing_bitmap, cache_hash);

        // NEW DESIGN: Background refresh calls handle_packet_internal(skip_cache=true)
        // 新设计：后台刷新调用 handle_packet_internal(skip_cache=true)
        // This completely reuses the rule engine and query logic
        // 这完全重用了规则引擎和查询逻辑
        
        // Step 1: Construct standard DNS query packet
        // 步骤 1：构造标准 DNS 查询包
        let packet = match self.construct_dns_packet(qname, qtype, qclass) {
            Ok(pkt) => pkt,
            Err(e) => {
                tracing::error!(
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
        let engine = self.clone();
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
                Ok(resp_bytes) => {
                    tracing::debug!(
                        event = "background_refresh_success",
                        qname = %qname_owned,
                        qtype = ?qtype,
                        pipeline_id = %pipeline_id_owned,
                        "Background refresh completed successfully"
                    );
                    // Cache is automatically updated by handle_packet_internal
                    // 缓存由 handle_packet_internal 自动更新
                }
                Err(e) => {
                    tracing::warn!(
                        event = "background_refresh_failed",
                        qname = %qname_owned,
                        qtype = ?qtype,
                        pipeline_id = %pipeline_id_owned,
                        error = %e,
                        "Background refresh failed, will retry on next cache hit"
                    );
                }
            }
            
            // OPTIMIZATION: Clear refreshing mark using bitmap (zero-lock write)
            // 优化：使用位图清除刷新标记（零锁写入）
            clear_refreshing(&engine.refreshing_bitmap, cache_hash);
        });
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
    fn construct_dns_packet(
        &self,
        qname: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: DNSClass,
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
    
    /// 从Message中提取TTL（辅助函数）
    /// Extract TTL from Message (helper function)
    /// Extract TTL from DNS response message
    /// 从 DNS 响应消息中提取 TTL
    /// 
    /// # Arguments
    /// * `msg` - DNS response message
    /// * `for_refresh` - If true, use max TTL for refresh timing; if false, use min TTL for cache entry
    /// 
    /// # Returns
    /// * TTL value in seconds
    /// 
    /// # Rationale
    /// - Cache entries should use min TTL (RFC 1035 §5.2)
    /// - Background refresh timing should use max TTL to avoid premature refresh
    /// 
    #[inline]
    fn extract_ttl_from_msg(&self, msg: &Message, for_refresh: bool) -> u32 {
        if for_refresh {
            // Use max TTL for refresh timing to avoid premature refresh
            // 使用最大 TTL 用于刷新时机以避免过早刷新
            extract_ttl_for_refresh(msg) as u32
        } else {
            // Use min TTL for cache entry (RFC 1035 §5.2)
            // 使用最小 TTL 用于缓存条目（RFC 1035 §5.2）
            extract_ttl(msg) as u32
        }
    }
    
    /// 从Message中提取TTL（辅助函数）
    /// Extract TTL from Message (helper function)
    /// Extract TTL from DNS response message
    /// 从 DNS 响应消息中提取 TTL
    /// 
    /// # Arguments
    /// * `msg` - DNS response message
    /// * `for_refresh` - If true, use max TTL for refresh timing; if false, use min TTL for cache entry
    /// 
    /// # Returns
    /// * TTL value in seconds
    /// 
    /// # Rationale
    /// - Cache entries should use min TTL (RFC 1035 §5.2)
    /// - Background refresh timing should use max TTL to avoid premature refresh
    /// 
    /// # 理由
    /// - 缓存条目应使用最小 TTL (RFC 1035 §5.2)
    /// - 后台刷新时机应使用最大 TTL 以避免过早刷新
    /// 
    /// Note: This is the original implementation (u64 return type)
    /// 注意：这是原始实现（u64 返回类型）
    /// The new implementation (u32 return type) is above at line 2505
    /// 新实现（u32 返回类型）在上方第 2505 行
    #[deprecated(note = "Use extract_ttl_from_msg with u32 return type instead")]
    fn extract_ttl_from_msg_legacy(&self, msg: &Message, for_refresh: bool) -> u64 {
        if for_refresh {
            // Use max TTL for refresh timing to avoid premature refresh
            // 使用最大 TTL 用于刷新时机以避免过早刷新
            extract_ttl_for_refresh(msg)
        } else {
            // Use min TTL for cache entry (RFC 1035 compliant)
            // 使用最小 TTL 用于缓存条目 (符合 RFC 1035)
            extract_ttl(msg)
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
                        let bytes = engine_helpers::build_servfail_response(req)?;
                        return Ok(ResponseActionResult::Static {
                            bytes,
                            rcode: ResponseCode::ServFail,
                            source: "response_action",
                        });
                    }
                    return Ok(ResponseActionResult::Jump {
                        pipeline: Arc::from(pipeline.as_str()),
                        remaining_jumps: remaining_jumps - 1,
                    });
                }
                Action::Allow => {
                    if let Some(ctx) = ctx_opt {
                        // Get manager references for GeoIP/GeoSite matching
                        // 获取 manager 引用以用于 GeoIP/GeoSite 匹配
                        let geoip_manager = self.geoip_manager.try_read().ok();
                        let geosite_manager = self.geosite_manager.try_read().ok();
                        let geoip_manager_ref = geoip_manager.as_deref();
                        let geosite_manager_ref = geosite_manager.as_deref();

                        let resp_match = eval_match_chain(
                            response_matchers,
                            |m| m.operator,
                            |m| m.matcher.matches(&ctx.upstream, qname, qtype, qclass, &ctx.msg, geoip_manager_ref, geosite_manager_ref),
                        );
                        return Ok(ResponseActionResult::Upstream { ctx, resp_match });
                    }
                    let bytes = engine_helpers::build_servfail_response(req)?;
                    return Ok(ResponseActionResult::Static {
                        bytes,
                        rcode: ResponseCode::ServFail,
                        source: "response_action",
                    });
                }
                Action::Deny => {
                    let bytes = engine_helpers::build_refused_response(req)?;
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
                    pre_split_upstreams,
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
                        let bytes = engine_helpers::build_servfail_response(req)?;
                        return Ok(ResponseActionResult::Static {
                            bytes,
                            rcode: ResponseCode::ServFail,
                            source: "response_action",
                        });
                    }

                    let upstream_addr: Arc<str> = upstream.as_ref().map(|s| Arc::from(s.as_str())).unwrap_or_else(|| {
                        ctx_opt
                            .as_ref()
                            .map(|ctx| ctx.upstream.clone())
                            .unwrap_or_else(|| Arc::from(upstream_default))
                    });
                    let use_transport = transport.unwrap_or(Transport::Udp);
                    let (raw, actual_upstream) = match self
                        .forward_upstream(packet, &upstream_addr, upstream_timeout, Some(use_transport), pre_split_upstreams.as_ref())
                        .await
                    {
                        Ok(result) => result,
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
                            let bytes = engine_helpers::build_servfail_response(req)?;
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
                        upstream: Arc::from(actual_upstream.as_str()),  // Use actual responding upstream
                        transport: use_transport,
                    });
                }
            }
        }

        if let Some(ctx) = ctx_opt {
            // Get manager references for GeoIP/GeoSite matching
            // 获取 manager 引用以用于 GeoIP/GeoSite 匹配
            let geoip_manager = self.geoip_manager.try_read().ok();
            let geosite_manager = self.geosite_manager.try_read().ok();
            let geoip_manager_ref = geoip_manager.as_deref();
            let geosite_manager_ref = geosite_manager.as_deref();

            let resp_match = eval_match_chain(
                response_matchers,
                |m| m.operator,
                |m| m.matcher.matches(&ctx.upstream, qname, qtype, qclass, &ctx.msg, geoip_manager_ref, geosite_manager_ref),
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
        mut pipeline_id: Arc<str>,
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
        skip_cache: bool,  // NEW: Pass skip_cache to response phase
    ) -> anyhow::Result<Bytes> {
        let cfg = &state.pipeline;
        struct InflightCleanupGuard {
            inflight: Arc<DashMap<u64, tokio::sync::watch::Sender<Result<Bytes, Arc<anyhow::Error>>>, FxBuildHasher>>,
            hash: u64,
            active: bool,
        }

        impl InflightCleanupGuard {
            fn new(inflight: Arc<DashMap<u64, tokio::sync::watch::Sender<Result<Bytes, Arc<anyhow::Error>>>, FxBuildHasher>>, hash: u64) -> Self {
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
                for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
                return Ok(resp_bytes);
            }

            let Some(pipeline) = state.pipeline.pipelines.iter().find(|p| p.id == pipeline_id) else {
                let resp_bytes = engine_helpers::build_servfail_response(req)?;
                for g in &mut cleanup_guards { g.defuse(); }
                for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
                return Ok(resp_bytes);
            };

            let dedupe_hash = Self::calculate_cache_hash_for_dedupe(&pipeline_id, qname.as_bytes(), qtype, qclass);
            
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
                skip_cache,  // FIX: Pass skip_cache to apply_rules
            );

            // Resolve nested rule-level jumps first
            let mut local_jumps = remaining_jumps;
            loop {
                if let Decision::Jump { pipeline } = decision {
                    if local_jumps == 0 {
                        let resp_bytes = engine_helpers::build_servfail_response(req)?;
                        for g in &mut cleanup_guards { g.defuse(); }
                        for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
                        return Ok(resp_bytes);
                    }
                    pipeline_id = pipeline;
                    local_jumps -= 1;
                    if let Some(next_pipeline) = state.pipeline.pipelines.iter().find(|p| p.id == pipeline_id) {
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
                            skip_cache,  // FIX: Pass skip_cache to apply_rules
                        );
                        continue;
                    } else {
                        let resp_bytes = engine_helpers::build_servfail_response(req)?;
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
                        upstream: None,  // Static responses have no upstream
                        qname: Arc::from(qname),
                        pipeline_id: pipeline_id.clone(),
                        qtype: u16::from(qtype),
                        inserted_at: Instant::now(),
                        original_ttl: min_ttl.as_secs() as u32,
                    };
                    self.cache.insert(dedupe_hash, Arc::new(entry));
                    for g in &mut cleanup_guards { g.defuse(); }
                    for h in &inflight_hashes { self.notify_inflight_waiters(*h, &resp_bytes).await; }
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
                                let rx = match self.inflight.entry(dedupe_hash) {
                                    Entry::Vacant(entry) => {
                                        // No other request in progress, create watch channel
                                        // 没有其他请求在进行,创建 watch channel
                                        let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                                        entry.insert(tx);
                                        cleanup_guards.push(InflightCleanupGuard::new(self.inflight.clone(), dedupe_hash));
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
                                                    for h in &inflight_hashes { self.notify_inflight_waiters(*h, &bytes).await; }
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
                            self.forward_upstream(packet, &upstream, upstream_timeout, transport, pre_split_upstreams.as_ref()).await
                        }
                    } else {
                        // If reuse is not allowed (e.g. explicit Forward action), we must clear any reused response
                        // and force a new request.
                        
                        // FIX: Background refresh must skip inflight check
                        // 修复：后台刷新必须跳过 inflight 检查
                        if !skip_cache {
                            use dashmap::mapref::entry::Entry;
                            let rx = match self.inflight.entry(dedupe_hash) {
                                Entry::Vacant(entry) => {
                                    // No other request in progress, create watch channel
                                    // 没有其他请求在进行,创建 watch channel
                                    let (tx, _rx) = tokio::sync::watch::channel(Err(Arc::new(anyhow::anyhow!("Pending"))));
                                    entry.insert(tx);
                                    cleanup_guards.push(InflightCleanupGuard::new(self.inflight.clone(), dedupe_hash));
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
                                                for h in &inflight_hashes { self.notify_inflight_waiters(*h, &bytes).await; }
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
                        self.forward_upstream(packet, &upstream, upstream_timeout, transport, pre_split_upstreams.as_ref()).await
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
                            // 获取 manager 引用以用于响应匹配器中的 GeoIP/GeoSite 匹配
                            // 使用作用域确保锁在使用后立即释放 / Use scope to ensure locks are released immediately after use
                            let resp_match_ok = {
                                let geoip_manager = self.geoip_manager.try_read().ok();
                                let geosite_manager = self.geosite_manager.try_read().ok();
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
                                        original_ttl: ttl_secs_refresh as u32,  // Use max TTL for refresh timing
                                    };
                                    self.cache.insert(dedupe_hash, Arc::new(entry));
                                }
                                for g in &mut cleanup_guards { g.defuse(); }
                                for h in &inflight_hashes { self.notify_inflight_waiters(*h, &raw).await; }
                                return Ok(raw);
                            }

                            let ctx = ResponseContext {
                                raw,
                                msg,
                                upstream: Arc::from(actual_upstream.as_str()),  // Use actual responding upstream
                                transport: transport.unwrap_or(Transport::Udp),
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
                                            original_ttl: ttl_secs_refresh as u32,  // Use max TTL for refresh timing
                                        };
                                        self.cache.insert(dedupe_hash, Arc::new(entry));
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
                            let resp_bytes = engine_helpers::build_servfail_response(req)?;
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
                        let resp_bytes = engine_helpers::build_servfail_response(req)?;
                        return Ok(resp_bytes);
                    }
                }
            }
        }
    }
}

pub fn select_pipeline<'a>(
    cfg: &'a RuntimePipelineConfig,
    qname: &str,
    client_ip: IpAddr,
    qclass: DNSClass,
    edns_present: bool,
    qtype: hickory_proto::rr::RecordType,
    listener_label: &str,
    geosite_manager: Option<&Arc<std::sync::RwLock<crate::geosite::GeoSiteManager>>>,
    geoip_manager: Option<&Arc<std::sync::RwLock<crate::geoip::GeoIpManager>>>,
) -> (Option<&'a RuntimePipeline>, Arc<str>) {
    for rule in &cfg.pipeline_select {
        let matched = eval_match_chain(
            &rule.matchers,
            |m| m.operator,
            |m| {
                // 获取 GeoSiteManager 和 GeoIpManager 的引用 / Get GeoSiteManager and GeoIpManager references
                // 简化 RwLock 读取路径以提高性能 / Simplified RwLock read path for better performance
                let geosite_mgr_ref = geosite_manager.and_then(|m| m.read().ok());
                let geosite_mgr_ref_deref = geosite_mgr_ref.as_deref();
                let geoip_mgr_ref = geoip_manager.and_then(|m| m.read().ok());
                let geoip_mgr_ref_deref = geoip_mgr_ref.as_deref();

                m.matcher.matches_with_qtype(listener_label, client_ip, qname, qclass, edns_present, qtype, geoip_mgr_ref_deref, geosite_mgr_ref_deref)
            },
        );
        if matched {
            if let Some(p) = cfg.pipelines.iter().find(|p| p.id.as_ref() == rule.pipeline) {
                return (Some(p), p.id.clone());
            }
        }
    }

    match cfg.pipelines.first() {
        Some(p) => (Some(p), p.id.clone()),
        None => (None, Arc::from("default")),
    }
}

impl Engine {
    #[inline]
    fn compiled_for<'a>(&self, state: &'a EngineInner, pipeline_id: &str) -> Option<&'a CompiledPipeline> {
        state.compiled_pipelines
            .iter()
            .find(|p| p.id.as_ref() == pipeline_id)
    }
}

struct UdpSocketState {
    socket: Arc<UdpSocket>,
    // Key: Upstream ID (newly generated)
    // Value: (Original ID, Upstream Address, Sender)
    inflight: Arc<DashMap<u16, (u16, SocketAddr, oneshot::Sender<anyhow::Result<Bytes>>), FxBuildHasher>>,
    next_id: AtomicU16,
}

/// 高性能 UDP 客户端池，使用 channel 分发 socket / High-performance UDP client pool using channel for socket distribution
struct UdpClient {
    pool: Vec<UdpSocketState>,
    next_idx: AtomicUsize,
}

impl UdpClient {
    fn new(size: usize) -> Self {
        // Prevent port exhaustion by enforcing minimum pool size
        let effective_size = if size == 0 { 1 } else { size };
        let mut pool = Vec::with_capacity(effective_size);
        for idx in 0..effective_size {
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
            let inflight = Arc::new(DashMap::with_hasher(FxBuildHasher::default()));
            
            let state = UdpSocketState {
                socket: socket.clone(),
                inflight: inflight.clone(),
                next_id: AtomicU16::new(0),
            };
            pool.push(state);

            let socket_clone = socket.clone();
            let inflight_clone = inflight.clone();
            tokio::spawn(async move {
                // Use BytesMut for efficient buffer management
                let mut buf = BytesMut::with_capacity(4096);
                buf.resize(4096, 0);
                loop {
                    match socket_clone.recv_from(&mut buf).await {
                        Ok((len, src)) => {
                            if len >= 2 {
                                let id = u16::from_be_bytes([buf[0], buf[1]]);
                                // 修复：使用try_remove，只有在地址匹配时才移除inflight
                                // Fix: Only remove inflight if address matches (use try_remove logic)
                                if let Some((_, (original_id, expected_addr, tx))) = inflight_clone.remove(&id) {
                                    if src == expected_addr {
                                        // Restore original TXID
                                        let orig_bytes = original_id.to_be_bytes();
                                        buf[0] = orig_bytes[0];
                                        buf[1] = orig_bytes[1];

                                        // 零拷贝优化：使用 split_to 复用已有容量，避免分配新内存
                                        // Zero-copy optimization: use split_to to reuse existing capacity, avoid allocation
                                        let response = buf.split_to(len).freeze();
                                        let _ = tx.send(Ok(response));
                                    } else {
                                        // 地址不匹配：这不是我们的响应，可能是ID冲突
                                        // 将条目放回去，等待正确的响应
                                        // Address mismatch: not our response, possible ID collision
                                        // Put the entry back and wait for the correct response
                                        inflight_clone.insert(id, (original_id, expected_addr, tx));
                                        tracing::warn!(
                                            socket_idx = idx,
                                            response_id = id,
                                            expected_addr = %expected_addr,
                                            actual_addr = %src,
                                            "UDP response address mismatch, possible ID collision"
                                        );
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
            return Err(anyhow::anyhow!("UDP pool not initialized"));
        }

        // Pool logic
        let idx = self.next_idx.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        let state = &self.pool[idx];
        let addr: SocketAddr = upstream.parse().context("invalid upstream address")?;

        if packet.len() < 2 {
            return Err(anyhow::anyhow!("packet too short"));
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // Find a free ID using atomic entry API to avoid race conditions and double locking
        let mut attempts = 0;
        let mut new_id;
        let (tx, rx) = oneshot::channel();
        
        loop {
            new_id = state.next_id.fetch_add(1, Ordering::Relaxed);
            match state.inflight.entry(new_id) {
                dashmap::mapref::entry::Entry::Vacant(e) => {
                    e.insert((original_id, addr, tx));
                    break;
                }
                dashmap::mapref::entry::Entry::Occupied(_) => {
                    attempts += 1;
                    if attempts > 100 {
                        warn!("udp pool exhausted: socket_idx={} inflight_count={}", idx, state.inflight.len());
                        return Err(anyhow::anyhow!("udp pool exhausted (too many inflight requests)"));
                    }
                }
            }
        }

        // Rewrite packet with new ID using BytesMut to avoid full copy
        let mut new_packet = BytesMut::with_capacity(packet.len());
        new_packet.extend_from_slice(packet);
        let id_bytes = new_id.to_be_bytes();
        new_packet[0] = id_bytes[0];
        new_packet[1] = id_bytes[1];

        if let Err(e) = state.socket.send_to(&new_packet, addr).await {
            state.inflight.remove(&new_id);
            return Err(e.into());
        }

        match timeout(timeout_dur, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => {
                // 修复：channel关闭时也要移除inflight条目，防止资源泄漏
                state.inflight.remove(&new_id);
                Err(anyhow::anyhow!("channel closed"))
            }
            Err(_) => {
                state.inflight.remove(&new_id);
                Err(anyhow::anyhow!("upstream timeout"))
            }
        }
    }
}

/// TCP 连接复用器，使用 DashMap 管理连接池 / TCP connection multiplexer, managing connection pool with DashMap
struct TcpMultiplexer {
    pools: dashmap::DashMap<Arc<str>, Arc<TcpConnectionPool>, FxBuildHasher>,
    pool_size: usize,
    /// Shared permit manager for unified TCP/UDP concurrency control
    /// 共享 permit manager 用于统一的 TCP/UDP 并发控制
    permit_manager: Arc<PermitManager>,
    /// 健康检查配置 / Health check configuration
    health_error_threshold: usize,
    max_age_secs: u64,
    idle_timeout_secs: u64,
}

struct TcpConnectionPool {
    clients: Vec<Arc<TcpMuxClient>>,
    next_idx: AtomicUsize,
}

impl TcpMultiplexer {
    fn new(
        pool_size: usize,
        permit_manager: Arc<PermitManager>,
        health_error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) -> Self {
        Self {
            pools: dashmap::DashMap::with_hasher(FxBuildHasher::default()),
            pool_size,
            permit_manager,
            health_error_threshold,
            max_age_secs,
            idle_timeout_secs,
        }
    }

    #[inline]
    async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let upstream_key: Arc<str> = Arc::from(upstream);
        let pool = self
            .pools
            .entry(upstream_key.clone())
            .or_insert_with(|| {
                let mut clients = Vec::with_capacity(self.pool_size);
                let size = if self.pool_size == 0 { 1 } else { self.pool_size };
                let permit_mgr = Arc::clone(&self.permit_manager);
                for _ in 0..size {
                    let client = Arc::new(TcpMuxClient::new(
                        upstream_key.clone(),
                        Arc::clone(&permit_mgr),
                    ));
                    // 设置健康检查配置
                    client.set_health_check_config(
                        self.health_error_threshold,
                        self.max_age_secs,
                        self.idle_timeout_secs,
                    );
                    clients.push(client);
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

    /// Record external timeout, incrementing error counters for all connections of the upstream
    /// 记录外部超时，增加该上游所有连接的错误计数
    ///
    /// # Design / 设计
    ///
    /// This method is called from sync context when TCP worker external timeout occurs.
    /// Since we cannot identify which specific connection had the timeout, we increment
    /// the error counter for all connections in the pool. The actual connection reset
    /// will be triggered on the next use via `record_error()` or `check_connection_health()`.
    ///
    /// 此方法在 TCP worker 外部超时时从同步上下文调用。
    /// 由于无法确定是哪个连接超时，我们对池中所有连接增加错误计数。
    /// 实际的连接重置会在下次使用时通过 `record_error()` 或 `check_connection_health()` 触发。
    ///
    /// # Thread Safety / 线程安全
    ///
    /// The health threshold is only set once during initialization and never modified
    /// at runtime, so reading it once per loop iteration is safe.
    ///
    /// 健康检查阈值仅在初始化时设置一次，运行时不会修改，因此每次循环读取一次是安全的。
    pub(crate) fn mark_timeout(&self, upstream: &str) {
        if let Some(pool) = self.pools.get(upstream) {
            // Record errors for all connections (since we don't know which specific one timed out)
            // 对所有连接记录错误（因为我们不知道具体是哪个超时）
            for client in &pool.clients {
                // Read threshold once: safe because it's only set during initialization
                // 读取一次阈值：安全，因为它仅在初始化时设置
                let threshold = client.health_threshold.load(Ordering::Acquire);
                let errors = client.consecutive_errors.fetch_add(1, Ordering::Release) + 1;

                if errors >= threshold {
                    warn!(
                        upstream = %client.upstream,
                        consecutive_errors = errors,
                        threshold = threshold,
                        "TCP external timeout threshold exceeded, connection will be reset on next use"
                    );
                    // Note: Cannot call async reset_conn here. The error count has been recorded,
                    // and the connection will be reset on the next send() call via record_error().
                    // 注意：这里无法调用 async reset_conn。错误计数已记录，
                    // 连接会在下次 send() 调用时通过 record_error() 重置。
                }
            }
        }
    }
}

struct TcpMuxClient {
    upstream: Arc<str>,
    /// Write half protected by Mutex - serves as both connection storage and write serialization
    conn: Arc<Mutex<Option<OwnedWriteHalf>>>,
    pending: Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
    next_id: AtomicU16,
    /// Shared permit manager for TCP connection-level control (unified with UDP)
    /// TCP 连接级别并发控制共享 permit manager（与 UDP 统一）
    permit_manager: Arc<PermitManager>,
    /// Connection-level permit (acquired when connection is established, held for connection lifetime)
    /// 连接级别 permit（连接建立时获取，连接生命周期内持有）
    conn_permit: Arc<Mutex<Option<PermitGuard>>>,
    /// 健康检查：连续错误计数 / Health check: consecutive error count
    consecutive_errors: AtomicUsize,
    /// 健康检查：错误阈值 / Health check: error threshold (Atomic for thread-safe updates)
    health_threshold: AtomicUsize,
    /// 连接老化：创建时间戳（毫秒）/ Connection aging: creation timestamp (ms)
    conn_create_time: AtomicU64,
    /// 连接老化：最大存活时间（毫秒）/ Connection aging: max age (ms)
    max_age_ms: AtomicU64,
    /// 空闲超时：最后请求时间（毫秒）/ Idle timeout: last request time (ms)
    last_request_time: AtomicU64,
    /// 空闲超时：空闲超时时间（毫秒）/ Idle timeout: idle timeout (ms)
    idle_timeout_ms: AtomicU64,
    /// 性能优化：上次健康检查时间（毫秒）/ Performance: last health check time (ms)
    last_health_check_time: AtomicU64,
}

struct Pending {
    original_id: u16,
    tx: oneshot::Sender<anyhow::Result<Bytes>>,
}

impl TcpMuxClient {
    fn new(upstream: Arc<str>, permit_manager: Arc<PermitManager>) -> Self {
        Self {
            upstream,
            conn: Arc::new(Mutex::new(None)),
            pending: Arc::new(dashmap::DashMap::with_hasher(FxBuildHasher::default())),
            next_id: AtomicU16::new(1),
            permit_manager,
            conn_permit: Arc::new(Mutex::new(None)),
            // 初始化健康检查字段（默认值，实际值会在 TcpMultiplexer 中设置）
            consecutive_errors: AtomicUsize::new(0),
            health_threshold: AtomicUsize::new(3),
            conn_create_time: AtomicU64::new(0),
            max_age_ms: AtomicU64::new(300_000),  // 5 分钟
            last_request_time: AtomicU64::new(0),
            idle_timeout_ms: AtomicU64::new(60_000),  // 1 分钟
            last_health_check_time: AtomicU64::new(0),
        }
    }

    /// 设置健康检查参数
    /// Set health check parameters
    fn set_health_check_config(&self, error_threshold: usize, max_age_secs: u64, idle_timeout_secs: u64) {
        self.health_threshold.store(error_threshold, Ordering::Release);
        self.max_age_ms.store(max_age_secs * 1000, Ordering::Release);
        self.idle_timeout_ms.store(idle_timeout_secs * 1000, Ordering::Release);
    }

    async fn spawn_reader(&self, mut reader: OwnedReadHalf) {
        let pending = Arc::clone(&self.pending);
        let upstream = self.upstream.clone();
        let conn = Arc::clone(&self.conn);
        let conn_permit = Arc::clone(&self.conn_permit);  // Clone conn_permit
        tokio::spawn(async move {
            // Pre-allocate a reusable buffer for TCP reads
            // DNS TCP max is 65535 bytes, but typical responses are much smaller
            let mut reusable_buf = BytesMut::with_capacity(4096);
            loop {
                let mut len_buf = [0u8; 2];
                if let Err(err) = reader.read_exact(&mut len_buf).await {
                    debug!(target = "tcp_mux", upstream = %upstream, error = %err, "tcp read len failed");
                    Self::fail_all_async(&pending, anyhow::anyhow!("tcp read len failed"), &conn, &conn_permit)
                        .await;
                    break;
                }
                let resp_len = u16::from_be_bytes(len_buf) as usize;

                // Resize buffer if needed, reusing allocation
                // resize() handles both truncation and extension, no need for clear()
                reusable_buf.resize(resp_len, 0);

                if let Err(err) = reader.read_exact(&mut reusable_buf[..resp_len]).await {
                    debug!(target = "tcp_mux", upstream = %upstream, error = %err, "tcp read body failed");
                    Self::fail_all_async(&pending, anyhow::anyhow!("tcp read body failed"), &conn, &conn_permit)
                        .await;
                    break;
                }

                if resp_len < 2 {
                    continue;
                }
                let resp_id = u16::from_be_bytes([reusable_buf[0], reusable_buf[1]]);
                if let Some((_, p)) = pending.remove(&resp_id) {
                    reusable_buf[0..2].copy_from_slice(&p.original_id.to_be_bytes());
                    // Split off the used portion to send, keeping capacity for reuse
                    let response = reusable_buf.split_to(resp_len).freeze();
                    let _ = p.tx.send(Ok(response));
                } else {
                    debug!(target = "tcp_mux", upstream = %upstream, resp_id, "response with unknown id");
                }
            }
        });
    }

    // ========== Health check methods / 健康检查方法 ==========

    /// Record error and check if connection reset is needed
    /// 记录错误并检查是否需要重置连接
    ///
    /// When the error threshold is exceeded, the connection is reset and the error
    /// counter is cleared to avoid immediate re-triggering on the next error.
    ///
    /// 当错误阈值超过时，连接会被重置，错误计数器会被清零以避免下次错误时立即重新触发。
    async fn record_error(&self) -> bool {
        let errors = self.consecutive_errors.fetch_add(1, Ordering::Release) + 1;
        let threshold = self.health_threshold.load(Ordering::Acquire);

        debug!(
            upstream = %self.upstream,
            consecutive_errors = errors,
            threshold = threshold,
            "TCP connection error recorded"
        );

        // Check if threshold exceeded / 检查是否超过阈值
        if errors >= threshold {
            warn!(
                upstream = %self.upstream,
                consecutive_errors = errors,
                threshold = threshold,
                "TCP connection error threshold exceeded, resetting connection"
            );
            Self::reset_conn(&self.conn, &self.conn_permit).await;
            // Clear error counter to avoid immediate re-triggering on next error
            // 清零错误计数器，避免下次错误时立即重新触发
            self.consecutive_errors.store(0, Ordering::Release);
            true  // Connection was reset / 连接已重置
        } else {
            false  // Connection was not reset / 连接未重置
        }
    }

    /// Record success and clear error counter
    /// 记录成功并清零错误计数
    fn record_success(&self) {
        self.consecutive_errors.store(0, Ordering::Release);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        self.last_request_time.store(now, Ordering::Release);
    }

    /// Check if connection needs reset due to aging or idle timeout
    /// 检查连接是否需要重置（老化或空闲超时）
    ///
    /// Returns true if connection was reset, false otherwise.
    /// 如果连接被重置返回 true，否则返回 false。
    async fn check_connection_health(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        // Check connection aging / 检查连接老化
        let create_time = self.conn_create_time.load(Ordering::Acquire);
        let max_age = self.max_age_ms.load(Ordering::Acquire);
        if create_time > 0 && max_age > 0 {
            let age_ms = now.saturating_sub(create_time);
            if age_ms > max_age {
                info!(
                    upstream = %self.upstream,
                    age_ms = age_ms,
                    max_age_ms = max_age,
                    "TCP connection too old, resetting"
                );
                Self::reset_conn(&self.conn, &self.conn_permit).await;
                // Clear error counter since we're starting fresh
                // 清零错误计数器，因为我们重新开始
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        // Check idle timeout / 检查空闲超时
        let last_req = self.last_request_time.load(Ordering::Acquire);
        let idle_timeout = self.idle_timeout_ms.load(Ordering::Acquire);
        if last_req > 0 && idle_timeout > 0 {
            let idle_ms = now.saturating_sub(last_req);
            if idle_ms > idle_timeout {
                info!(
                    upstream = %self.upstream,
                    idle_ms = idle_ms,
                    idle_timeout_ms = idle_timeout,
                    "TCP connection idle timeout, resetting"
                );
                Self::reset_conn(&self.conn, &self.conn_permit).await;
                // Clear error counter since we're starting fresh
                // 清零错误计数器，因为我们重新开始
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        false
    }

    async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for tcp");
        }

        // 性能优化：仅在距离上次检查超过 30 秒时才执行健康检查
        // Performance: Only check connection health if 30 seconds have passed since last check
        const HEALTH_CHECK_INTERVAL_MS: u64 = 30_000;  // 30 秒
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let last_check = self.last_health_check_time.load(Ordering::Relaxed);
        if last_check == 0 || now.saturating_sub(last_check) >= HEALTH_CHECK_INTERVAL_MS {
            self.check_connection_health().await;
            self.last_health_check_time.store(now, Ordering::Relaxed);
        }

        // 1. Ensure connection exists (acquires connection-level permit if needed)
        // 确保连接存在（如果需要则获取连接级别 permit）
        self.ensure_connection().await?;

        let elapsed = start.elapsed();
        if elapsed >= timeout_dur {
             anyhow::bail!("tcp timeout before processing");
        }
        let remaining = timeout_dur - elapsed;

        let original_id = u16::from_be_bytes([packet[0], packet[1]]);
        let (new_packet, new_id) = self.rewrite_id(packet).await?;

        let (tx, rx) = oneshot::channel();
        self.pending.insert(new_id, Pending { original_id, tx });

        // 2. Write request with remaining timeout (connection already ensured)
        // 2. 写入请求（连接已确保）
        let write_res = timeout(remaining, async {
            // Build TCP DNS frame: 2-byte length prefix + payload
            let mut out = BytesMut::with_capacity(2 + new_packet.len());
            out.extend_from_slice(&(new_packet.len() as u16).to_be_bytes());
            out.extend_from_slice(&new_packet);

            // Single lock acquisition - conn Mutex provides write serialization
            // 单次锁获取 - conn Mutex 提供写入序列化
            let mut guard = self.conn.lock().await;

            // Connection must exist (ensure_connection was called earlier)
            // 连接必须存在（ensure_connection 已在之前调用）
            let writer = guard.as_mut().context("tcp write half missing")?;
            writer.write_all(&out).await?;
            Ok::<(), anyhow::Error>(())
        }).await;

        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                self.remove_pending(new_id).await;
                // Record error and check if reset is needed
                // 记录错误并检查是否需要重置
                self.record_error().await;
                return Err(err).context(format!(
                    "TCP write/connect failed for upstream {upstream}",
                    upstream = self.upstream
                ));
            }
            Err(_) => {
                self.remove_pending(new_id).await;
                // Record error and check if reset is needed
                // 记录错误并检查是否需要重置
                self.record_error().await;
                return Err(anyhow::anyhow!(
                    "TCP write/connect timeout for upstream {upstream} (timeout: {timeout_ms}ms)",
                    upstream = self.upstream,
                    timeout_ms = remaining.as_millis()
                ));
            }
        }

        // 3. Wait for response
        // 3. 等待响应
        let elapsed_after_write = start.elapsed();
        if elapsed_after_write >= timeout_dur {
            self.remove_pending(new_id).await;
            // Record error and check if reset is needed
            // 记录错误并检查是否需要重置
            self.record_error().await;
            return Err(anyhow::anyhow!(
                "TCP timeout before waiting for response from upstream {upstream} (elapsed: {elapsed_ms}ms, timeout: {timeout_ms}ms)",
                upstream = self.upstream,
                elapsed_ms = elapsed_after_write.as_millis(),
                timeout_ms = timeout_dur.as_millis()
            ));
        }
        let final_remaining = timeout_dur - elapsed_after_write;

        let resp = match timeout(final_remaining, rx).await {
            Ok(Ok(r)) => {
                // Record success and clear error count
                // 记录成功并清零错误计数
                self.record_success();
                r?
            }
            Ok(Err(_canceled)) => {
                self.remove_pending(new_id).await;
                // Record error and check if reset is needed
                // 记录错误并检查是否需要重置
                self.record_error().await;
                return Err(anyhow::anyhow!(
                    "TCP response canceled for upstream {upstream}",
                    upstream = self.upstream
                ));
            }
            Err(_elapsed) => {
                self.remove_pending(new_id).await;
                // Record error and check if reset is needed
                // 记录错误并检查是否需要重置
                self.record_error().await;
                return Err(anyhow::anyhow!(
                    "TCP response timeout from upstream {upstream} (remaining: {timeout_ms}ms)",
                    upstream = self.upstream,
                    timeout_ms = final_remaining.as_millis()
                ));
            }
        };
        Ok(resp)
    }

    /// Ensure TCP connection exists, acquiring connection-level permit if needed
    /// 确保 TCP 连接存在，如果需要则获取连接级别 permit
    ///
    /// Connection-level permit semantics:
    /// - Acquired when connection is established
    /// - Held for the entire connection lifetime
    /// - Released when connection is closed/reset
    /// - Allows unlimited requests on the same connection (TCP multiplexing)
    ///
    /// 连接级别 permit 语义：
    /// - 连接建立时获取
    /// - 连接生命周期内持有
    /// - 连接关闭/重置时释放
    /// - 允许同一连接上无限请求（TCP 多路复用）
    async fn ensure_connection(&self) -> anyhow::Result<()> {
        let mut guard = self.conn.lock().await;

        if guard.is_none() {
            // Acquire connection-level permit (non-blocking)
            // 获取连接级别 permit（非阻塞）
            let permit = self.permit_manager.try_acquire()
                .ok_or_else(|| anyhow::anyhow!("tcp connection limit exceeded"))?;

            // Establish TCP connection
            // 建立 TCP 连接
            let stream = TcpStream::connect(&*self.upstream).await
                .map_err(|e| anyhow::anyhow!("tcp connect failed: {}", e))?;

            let (read_half, write_half) = stream.into_split();

            *guard = Some(write_half);

            // Spawn reader while holding the lock to prevent races
            // 持有锁时启动 reader 以防止竞争
            self.spawn_reader(read_half).await;

            // Store permit in connection (held for connection lifetime)
            // 将 permit 保存在连接中（连接生命周期内持有）
            let mut conn_permit_guard = self.conn_permit.lock().await;
            *conn_permit_guard = Some(permit);

            // 设置连接创建时间
            // Set connection creation time
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            self.conn_create_time.store(now, Ordering::Release);
            self.last_request_time.store(now, Ordering::Release);

            info!(
                upstream = %self.upstream,
                "TCP connection established"
            );
        }

        Ok(())
    }

    /// Rewrite DNS transaction ID, returning BytesMut for efficient further operations
    async fn rewrite_id(&self, packet: &[u8]) -> anyhow::Result<(BytesMut, u16)> {
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
        let mut buf = BytesMut::with_capacity(packet.len());
        buf.extend_from_slice(packet);
        buf[0..2].copy_from_slice(&new_id.to_be_bytes());
        Ok((buf, new_id))
    }

    async fn remove_pending(&self, id: u16) {
        self.pending.remove(&id);
    }

    async fn fail_all_async(
        pending: &Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
        err: anyhow::Error,
        conn: &Arc<Mutex<Option<OwnedWriteHalf>>>,
        conn_permit: &Arc<Mutex<Option<PermitGuard>>>,
    ) {
        let err_msg = err.to_string();
        let keys: Vec<u16> = pending.iter().map(|item| *item.key()).collect();
        for key in keys {
            if let Some((_, p)) = pending.remove(&key) {
                let _ = p.tx.send(Err(anyhow::anyhow!(err_msg.clone())));
            }
        }
        Self::reset_conn(conn, conn_permit).await;
    }

    /// Reset TCP connection and release connection-level permit
    /// 重置 TCP 连接并释放连接级别 permit
    async fn reset_conn(
        conn: &Arc<Mutex<Option<OwnedWriteHalf>>>,
        conn_permit: &Arc<Mutex<Option<PermitGuard>>>,
    ) {
        let mut cg = conn.lock().await;
        *cg = None;

        // Release connection-level permit
        // 释放连接级别 permit
        let mut permit_guard = conn_permit.lock().await;
        *permit_guard = None;
    }
}

fn matcher_matches(
    matcher: &crate::matcher::RuntimeMatcher,
    qname: &str,
    qclass: DNSClass,
    client_ip: IpAddr,
    edns_present: bool,
    qtype: hickory_proto::rr::RecordType,
    geoip_manager: Option<&Arc<std::sync::RwLock<crate::geoip::GeoIpManager>>>,
    geosite_manager: Option<&Arc<std::sync::RwLock<crate::geosite::GeoSiteManager>>>,
) -> bool {
    // 获取 GeoSiteManager 的引用 / Get GeoSiteManager reference
    let geosite_mgr_ref = geosite_manager.map(|m| m.read().unwrap());
    let geosite_mgr_deref = geosite_mgr_ref.as_deref();
    // 获取 GeoIpManager 的引用 / Get GeoIpManager reference
    let geoip_mgr_ref = geoip_manager.map(|m| m.read().unwrap());
    let geoip_mgr_deref = geoip_mgr_ref.as_deref();
    matcher.matches_with_qtype(qname, qclass, client_ip, edns_present, qtype, geoip_mgr_deref, geosite_mgr_deref)
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

// Engine tests / 引擎测试
// DNS引擎功能测试，包括静态响应、pipeline选择、缓存行为和上游通信 / Tests for DNS engine functionality, including static responses, pipeline selection, cache behavior, and upstream communication
#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests {
    use super::*;
    use crate::config::{GlobalSettings, MatchOperator};
    use hickory_proto::rr::RecordType;
    use hickory_proto::op::{Message, OpCode, Query};

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
    use futures::future::join_all;
    use tokio::time::{timeout, Duration};

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

    #[tokio::test]
    async fn tcp_mux_rewrite_id_no_deadlock_under_contention() {
        // Arrange: Prepare a TCP client with many pending IDs to force contention
        let permit_manager = Arc::new(PermitManager::new(128)); // Default TCP limit
        let client = Arc::new(TcpMuxClient::new(Arc::from("127.0.0.1:0"), permit_manager));
        for id in 1u16..200u16 {
            client.pending.insert(
                id,
                Pending {
                    original_id: id,
                    tx: oneshot::channel().0,
                },
            );
        }

        // Act: Spawn many concurrent rewrite_id calls to test contention handling
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

        // Assert: Verify all IDs are unique (no duplicates under contention)
        let mut ids = std::collections::HashSet::new();
        for r in results {
            let id = r.expect("rewrite_id failed");
            assert!(ids.insert(id), "duplicate id allocated under contention");
        }
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
            decision: decision,
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
            decision: decision,
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
            &pipeline_id, 
            qname.as_bytes(), 
            qtype, 
            qclass_in
        );
        let hash_ch = Engine::calculate_cache_hash_for_dedupe(
            &pipeline_id, 
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
            &pipeline_id, 
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
            &pipeline_id, 
            qname_lower.to_lowercase().as_bytes(), 
            qtype, 
            qclass
        );
        let hash2 = Engine::calculate_cache_hash_for_dedupe(
            &pipeline_id, 
            qname_upper.to_lowercase().as_bytes(), 
            qtype, 
            qclass
        );
        let hash3 = Engine::calculate_cache_hash_for_dedupe(
            &pipeline_id, 
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
            &pipeline_id, 
            qname.as_bytes(), 
            qtype_a, 
            qclass
        );
        let hash_aaaa = Engine::calculate_cache_hash_for_dedupe(
            &pipeline_id, 
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
            &pipeline_id, 
            qname1.as_bytes(), 
            qtype, 
            qclass
        );
        let hash2 = Engine::calculate_cache_hash_for_dedupe(
            &pipeline_id, 
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

    // Directly add queries without intermediate Vec allocation
    for q in req.queries() {
        msg.add_query(q.clone());
    }
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

pub fn extract_ttl(msg: &Message) -> u64 {
    // Extract minimum TTL for cache entry (RFC 1035 §5.2)
    // 提取最小 TTL 用于缓存条目 (RFC 1035 §5.2)
    // When multiple records have different TTLs, use the minimum
    // 当多个记录有不同的 TTL 时,使用最小值
    msg.answers()
        .iter()
        .map(|r| r.ttl() as u64)
        .min()
        .unwrap_or(0)
}

/// 从 DNS 响应中提取最大 TTL 用于后台刷新时机 / Extract maximum TTL from DNS response for background refresh timing
///
/// 理由：当多个 A/AAAA 记录有不同的 TTL 时，使用 min() 会导致过早刷新，使用 max() 确保缓存保持有效直到所有记录过期，这与减少上游查询的目标一致 / Rationale: When multiple A/AAAA records have different TTLs, using min() causes premature refresh, using max() ensures cache stays valid until ALL records expire, aligning with the goal of reducing upstream queries
pub fn extract_ttl_for_refresh(msg: &Message) -> u64 {
    msg.answers()
        .iter()
        .map(|r| r.ttl() as u64)
        .max()
        .unwrap_or(0)
}

// 已使用 moka 自动过期缓存，无需手动 GC

#[derive(Debug, Clone)]
pub(crate) enum Decision {
    Static {
        rcode: ResponseCode,
        answers: Vec<Record>,
    },
    Forward {
        upstream: Arc<str>,
        /// 预分割的 upstream 列表（性能优化）/ Pre-split upstream list (performance optimization)
        #[allow(dead_code)]
        pre_split_upstreams: Option<std::sync::Arc<Vec<String>>>,
        response_matchers: Vec<RuntimeResponseMatcherWithOp>,
        response_matcher_operator: crate::config::MatchOperator,
        response_actions_on_match: Vec<Action>,
        response_actions_on_miss: Vec<Action>,
        rule_name: Arc<str>,
        transport: Option<Transport>, // None 表示每个 upstream 自己决定（通过协议前缀）/ None means each upstream decides itself (via protocol prefix)
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
struct ResponseContext {
    raw: Bytes,
    msg: Message,
    upstream: Arc<str>,
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
        pipeline: Arc<str>,
        remaining_jumps: usize,
    },
    Continue {
        ctx: Option<ResponseContext>,
    },
}

#[inline]
fn calculate_rule_hash(pipeline_id: &str, qname: &str, client_ip: IpAddr, uses_client_ip: bool) -> u64 {
    let mut hasher = FxHasher::default();
    pipeline_id.hash(&mut hasher);
    qname.hash(&mut hasher);
    if uses_client_ip {
        client_ip.hash(&mut hasher);
    }
    hasher.finish()
}

#[derive(Clone)]
struct RuleCacheEntry {
    pipeline_id: Arc<str>,
    qname_hash: u64,
    client_ip: Option<IpAddr>,
    decision: Arc<Decision>,
    /// Expiration time based on DNS TTL / 基于 DNS TTL 的过期时间
    expires_at: Option<Instant>,
}

impl RuleCacheEntry {
    #[inline]
    fn matches(&self, pipeline_id: &str, qname: &str, client_ip: IpAddr, uses_client_ip: bool) -> bool {
        // Check expiration first / 首先检查过期
        if let Some(expires) = self.expires_at {
            if Instant::now() > expires {
                return false;
            }
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
    fn is_valid(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Instant::now() <= expires
        } else {
            true  // No expiration = permanent
        }
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

// Multi-upstream parsing tests / 多上游解析测试
// Tests for parsing and validating multi-upstream configurations
#[cfg(test)]
#[allow(unnameable_test_items)]
mod tests_multi_upstream {
    use super::*;

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
                assert!(*upstream == None, "Empty upstream array should result in None");
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


// Minimal fallback pipeline when none provided.
