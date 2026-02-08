use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicUsize, AtomicU64};

use dashmap::DashMap;
use arc_swap::ArcSwap;
use moka::sync::Cache;
use rustc_hash::FxBuildHasher;
use tracing::{info, warn};

use crate::cache::{DnsCache, new_cache};
use crate::lock::RwLock;
use crate::matcher::RuntimePipelineConfig;
use crate::matcher::geoip::GeoIpManager;
use crate::matcher::geosite::GeoSiteManager;
use crate::matcher::advanced_rule::compile_pipelines;
use super::utils::{extract_geosite_tags_from_config, uses_geoip_matchers};

use super::concurrency::{PermitManager, FlowControlState};
use super::types::{EngineInner, InflightMap};
use super::rules::RuleCacheEntry;
use super::transport::{UdpClient, TcpMultiplexer, DohClient, DotMultiplexer, DoqClient};

#[derive(Clone)]
pub struct Engine {
    pub(crate) state: Arc<ArcSwap<EngineInner>>,
    pub(crate) cache: DnsCache,
    pub(crate) udp_client: Arc<UdpClient>,
    pub(crate) tcp_mux: Arc<TcpMultiplexer>,
    pub(crate) doh_client: Arc<DohClient>,
    pub(crate) dot_mux: Arc<DotMultiplexer>,
    pub(crate) doq_client: Arc<DoqClient>,
    pub listener_label: Arc<str>,
    // Rule execution result cache: Hash -> (Key, Decision) / 规则执行结果缓存：哈希 -> (键, 决策)
    // Key is stored to verify collisions / 存储键以验证冲突
    pub(crate) rule_cache: Cache<u64, RuleCacheEntry>,
    // Runtime metrics for diagnosing concurrency and upstream latency / 运行时指标，用于诊断并发和上游延迟
    pub metrics_inflight: Arc<AtomicUsize>,
    pub metrics_total_requests: Arc<AtomicU64>,
    pub metrics_fastpath_hits: Arc<AtomicU64>,
    pub metrics_parse_quick_failures: Arc<AtomicU64>,
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
    pub inflight: Arc<InflightMap>,
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
    // Adaptive flow control state (None when flow control is disabled) / 自适应流控状态（禁用流控时为None）
    pub flow_control_state: Option<Arc<FlowControlState>>,
    // Cache background refresh settings / 缓存后台刷新设置
    pub(crate) cache_background_refresh: bool,
    pub(crate) cache_refresh_threshold_percent: u8,
    pub(crate) cache_refresh_min_ttl: u32,
    // RFC 8767: Serve stale cache on upstream failure / RFC 8767: 上游失败时提供过期缓存
    pub(crate) serve_stale: bool,
    pub(crate) serve_stale_ttl: u32,
    // GeoIP manager for geographic IP-based routing / GeoIP 管理器用于基于地理位置的 IP 路由
    pub geoip_manager: Arc<RwLock<GeoIpManager>>,
    // GeoSite manager for domain category-based routing / GeoSite 管理器用于域名分类路由
    // 使用 RwLock 允许并发读操作，写操作独占 / Uses RwLock for concurrent reads, exclusive writes
    pub geosite_manager: Arc<RwLock<GeoSiteManager>>,
    // Background refresh dedicated rule / 后台刷新专用规则
    // Design: Background refresh calls handle_packet(skip_cache=true) with this rule
    // 设计：后台刷新调用 handle_packet(skip_cache=true) 使用此规则
    // Uses OnceLock for lazy initialization and thread-safe one-time setup
    // 使用 OnceLock 实现延迟初始化和线程安全的一次性设置
    // Note: Currently reserved for future implementation
    #[allow(dead_code)]
    pub(crate) background_refresh_rule: std::sync::OnceLock<Arc<crate::matcher::RuntimeRule>>,
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
        let doh_pool_size = cfg.settings.doh_pool_size;
        let dot_pool_size = cfg.settings.dot_pool_size;
        let doq_pool_size = cfg.settings.doq_pool_size;
        let doq_idle_timeout_secs = cfg.settings.doq_connection_idle_timeout_seconds;
        let doq_keepalive_interval_ms = cfg.settings.doq_keepalive_interval_ms;
        let doq_enable_0rtt = cfg.settings.doq_enable_0rtt;
        let flow_control_enabled = cfg.settings.flow_control_enabled;
        let flow_control_initial_permits = cfg.settings.flow_control_initial_permits;
        let flow_control_min_permits = cfg.settings.flow_control_min_permits;
        let flow_control_max_permits = cfg.settings.flow_control_max_permits;
        let flow_control_latency_threshold_ms = cfg.settings.flow_control_latency_threshold_ms;
        let flow_control_adjustment_interval_secs = cfg.settings.flow_control_adjustment_interval_secs;
        let dashmap_shards = cfg.settings.dashmap_shards;
        let cache_background_refresh = cfg.settings.cache_background_refresh;
        let cache_refresh_threshold_percent = cfg.settings.cache_refresh_threshold_percent;
        let cache_refresh_min_ttl = cfg.settings.cache_refresh_min_ttl;
        let serve_stale = cfg.settings.serve_stale;
        let serve_stale_ttl = cfg.settings.serve_stale_ttl;

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
                // This should never fail with None parameter
                GeoIpManager::new(None)
                    .expect("GeoIpManager::new(None) should always succeed")
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
                        info!(path = %path.display(), loaded_count = count, "loaded GeoIP data from file");
                        geoip_dat_path_for_watcher = Some(path);
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "failed to load GeoIP data, skipping");
                    }
                }
            } else {
                warn!(path = %path.display(), "GeoIP data file not found, skipping");
            }
        }

        let geoip_manager = Arc::new(RwLock::new(geoip_manager));

        // Initialize GeoSiteManager / 初始化 GeoSiteManager
        // GeoSiteManager starts empty and is populated via add_entry() calls
        // Cache will be automatically rebuilt after loading data
        let geosite_manager = Arc::new(RwLock::new(
            crate::matcher::geosite::GeoSiteManager::new(),
        ));
        
        // Load GeoSite data from configured files / 从配置的文件加载 GeoSite 数据
        let mut geosite_paths_for_watcher = Vec::new();
        for path_str in &geosite_data_paths {
            let path = std::path::PathBuf::from(path_str);
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
                    // parking_lot::RwLock::write() 返回 guard 直接，不会中毒
                    let mut manager = geosite_manager.write();
                    if used_geosite_tags.is_empty() {
                        // 没有使用 GeoSite 标签，跳过加载 / No GeoSite tags used, skip loading
                        info!("No GeoSite tags used in config, skipping GeoSite data loading");
                        Ok(0)
                    } else {
                        manager.load_from_dat_file_selective(&path, &used_geosite_tags)
                    }
                } else {
                    // JSON 格式：全量加载 / JSON format: load all
                    // parking_lot::RwLock::write() 返回 guard 直接，不会中毒
                    let mut manager = geosite_manager.write();
                    manager.load_from_v2ray_file(&path)
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
            crate::matcher::geosite::spawn_geosite_watcher(
                geosite_paths_for_watcher,
                Arc::clone(&geosite_manager),
                used_geosite_tags,
            );
        }

        // Start GeoIP watcher for hot-reload / 启动 GeoIP watcher 用于热重载
        crate::matcher::geoip::spawn_geoip_watcher(
            geoip_dat_path_for_watcher,
            Arc::clone(&geoip_manager),
        );

        // 根据配置决定是否启用流控 / Decide whether to enable flow control based on configuration
        // 如果禁用流控，使用usize::MAX作为max_permits，实现"无限制"模式
        // When flow control is disabled, use usize::MAX as max_permits for "unlimited" mode
        let (permit_manager, flow_control_state) = if flow_control_enabled {
            let pm = Arc::new(PermitManager::new(flow_control_initial_permits));
            pm.set_max_permits(flow_control_max_permits);
            (pm, Some(Arc::new(FlowControlState {
                max_permits: AtomicUsize::new(flow_control_max_permits),
                min_permits: flow_control_min_permits,
                last_adjustment_ms: AtomicU64::new(0),
                critical_latency_threshold_ns: flow_control_latency_threshold_ms * 1_000_000,
                adjustment_interval_ms: flow_control_adjustment_interval_secs * 1000,
            })))
        } else {
            // 无限制模式：创建一个max_permits=usize::MAX的PermitManager
            // Unlimited mode: create a PermitManager with max_permits=usize::MAX
            let pm = Arc::new(PermitManager::new_unlimited());
            (pm, None)
        };

        // TCP pool size is per-upstream; each upstream gets its own permit manager
        // TCP 连接池大小为"每个 upstream"独立配置；每个 upstream 有各自的 permit manager

        // Collect TCP upstreams for warmup / 收集 TCP upstream 用于预热
        let tcp_upstreams = state.load().pipeline.collect_tcp_upstreams();

        let tcp_mux = Arc::new(TcpMultiplexer::new(
            tcp_pool_size,
            tcp_health_error_threshold,
            tcp_max_age_secs,
            tcp_idle_timeout_secs,
        ));

        let dot_mux = Arc::new(DotMultiplexer::new(
            dot_pool_size,
            tcp_health_error_threshold,
            tcp_max_age_secs,
            tcp_idle_timeout_secs,
        ).expect("initialize DoT multiplexer"));

        let doh_client = Arc::new(DohClient::new(doh_pool_size).expect("initialize DoH client"));
        let doq_client = Arc::new(DoqClient::new(
            doq_pool_size,
            doq_idle_timeout_secs,
            doq_keepalive_interval_ms,
            doq_enable_0rtt,
        ).expect("initialize DoQ client"));

        // Warm up TCP connection pools (create 1 connection per upstream)
        // 预热 TCP 连接池（每个 upstream 创建 1 个连接）
        tcp_mux.warm_up_pools(&tcp_upstreams);

        Self {
            state,
            cache,
            udp_client: Arc::new(UdpClient::new(udp_pool_size)),
            tcp_mux,
            doh_client,
            dot_mux,
            doq_client,
            listener_label: Arc::from(listener_label),
            rule_cache,
            metrics_inflight: Arc::new(AtomicUsize::new(0)),
            metrics_total_requests: Arc::new(AtomicU64::new(0)),
            metrics_fastpath_hits: Arc::new(AtomicU64::new(0)),
            metrics_parse_quick_failures: Arc::new(AtomicU64::new(0)),
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
                    FxBuildHasher,
                ))
            } else {
                Arc::new(DashMap::with_capacity_and_hasher_and_shard_amount(
                    128,
                    FxBuildHasher,
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
            // RFC 8767: Serve stale cache settings / RFC 8767: 过期缓存设置
            serve_stale,
            serve_stale_ttl,
            // GeoIP manager / GeoIP 管理器
            geoip_manager,
            // GeoSite manager / GeoSite 管理器
            geosite_manager,
            // Background refresh dedicated rule (lazy initialization) / 后台刷新专用规则（延迟初始化）
            background_refresh_rule: std::sync::OnceLock::new(),
        }
    }
}
