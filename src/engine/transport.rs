use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicUsize, AtomicU64, Ordering};
use std::time::Duration;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use dashmap::mapref::entry;
use rustc_hash::FxBuildHasher;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, tcp::{OwnedReadHalf, OwnedWriteHalf}};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use super::concurrency::{PermitManager, PermitGuard};

/// Type alias for UDP inflight request tracking
/// ID -> (OriginalID, ExpectedAddr, Sender)
type UdpInflightMap = DashMap<u16, (u16, SocketAddr, oneshot::Sender<anyhow::Result<Bytes>>), FxBuildHasher>;

struct UdpSocketState {
    socket: Arc<tokio::net::UdpSocket>,
    /// Inflight map: ID -> (OriginalID, ExpectedAddr, Sender)
    /// Note: Using FxBuildHasher for performance
    inflight: Arc<UdpInflightMap>,
    next_id: AtomicU16,
}

pub struct UdpClient {
    pool: Vec<UdpSocketState>,
    next_idx: AtomicUsize,
}

impl UdpClient {
    pub fn new(size: usize) -> Self {
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
            socket.bind(&"0.0.0.0:0".parse::<SocketAddr>().expect("parse ephemeral address").into()).expect("bind");
            socket.set_nonblocking(true).expect("set nonblocking");
            
            let std_sock: std::net::UdpSocket = socket.into();
            let socket = Arc::new(tokio::net::UdpSocket::from_std(std_sock).expect("from_std"));
            let inflight = Arc::new(DashMap::with_hasher(FxBuildHasher));

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
                loop {
                    // Reset buffer: keep capacity but length=0
                    // 重置缓冲区：保留容量但长度设为 0
                    buf.clear();
                    
                    // Use recv_buf_from to write directly into uninitialized memory part of BytesMut
                    // avoid zero-filling overhead from resize()
                    // 使用 recv_buf_from 直接写入 BytesMut 的未初始化内存部分，避免 resize() 的置零开销
                    if buf.capacity() < 4096 {
                        buf.reserve(4096 - buf.capacity());
                    }

                    match socket_clone.recv_buf_from(&mut buf).await {
                        Ok((_len, src)) => {
                            let len = buf.len();
                            if len >= 2 {
                                let id = u16::from_be_bytes([buf[0], buf[1]]);
                                // 修复：使用 Entry API 原子操作，避免 remove-then-insert 导致的竞态条件
                                // Fix: Use Entry API for atomic operations to avoid remove-then-insert race condition
                                if let entry::Entry::Occupied(entry) = inflight_clone.entry(id) {
                                    let (_, expected_addr, _) = entry.get();
                                    if src == *expected_addr {
                                        let (_, (original_id, _, tx)) = entry.remove_entry();

                                        // Restore original TXID
                                        let orig_bytes = original_id.to_be_bytes();
                                        buf[0] = orig_bytes[0];
                                        buf[1] = orig_bytes[1];

                                        // 零拷贝优化：使用 split_to 复用已有容量，避免分配新内存
                                        let response = buf.split_to(len).freeze();

                                        if tx.send(Ok(response)).is_err() {
                                            tracing::debug!(
                                                socket_idx = idx,
                                                response_id = id,
                                                "Failed to send UDP response, channel already closed"
                                            );
                                        }
                                    } else {
                                        // Address mismatch: keep entry and wait for correct response
                                        // 地址不匹配：保留条目等待正确响应（可能是网络攻击或路由异常）
                                        tracing::warn!(
                                            socket_idx = idx,
                                            response_id = id,
                                            expected_addr = %expected_addr,
                                            actual_addr = %src,
                                            "UDP response address mismatch, possible spoofing or routing anomaly"
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
    pub async fn send(
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
                entry::Entry::Vacant(e) => {
                    e.insert((original_id, addr, tx));
                    break;
                }
                entry::Entry::Occupied(_) => {
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
pub struct TcpMultiplexer {
    pools: dashmap::DashMap<Arc<str>, Arc<TcpConnectionPool>, FxBuildHasher>,
    pool_size: usize,
    /// Per-upstream permit manager is created when pool is initialized
    /// 每个 upstream 在初始化连接池时创建独立的 permit manager
    /// 健康检查配置 / Health check configuration
    health_error_threshold: usize,
    max_age_secs: u64,
    idle_timeout_secs: u64,
}

pub struct TcpConnectionPool {
    clients: Vec<Arc<TcpMuxClient>>,
    next_idx: AtomicUsize,
}

impl TcpMultiplexer {
    pub fn new(
        pool_size: usize,
        health_error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) -> Self {
        Self {
            pools: dashmap::DashMap::with_hasher(FxBuildHasher),
            pool_size,
            health_error_threshold,
            max_age_secs,
            idle_timeout_secs,
        }
    }

    /// Warm up connection pools for given upstreams.
    /// 为给定的 upstream 预热连接池。
    ///
    /// This creates a minimal pool with 1 connection per upstream to avoid
    /// lazy initialization overhead on first query.
    /// 这会为每个 upstream 创建只包含 1 个连接的最小连接池，以避免首次查询时的懒加载开销。
    pub fn warm_up_pools(&self, upstreams: &std::collections::HashSet<String>) {
        use tracing::info;

        if upstreams.is_empty() {
            info!("No TCP upstreams to warm up");
            return;
        }

        info!(
            count = upstreams.len(),
            "Warming up TCP connection pools..."
        );

        for upstream in upstreams {
            let upstream_key: Arc<str> = Arc::from(upstream.as_str());
            // Use entry().or_insert_with() to create pool only if it doesn't exist
            // 使用 entry().or_insert_with() 仅在连接池不存在时创建
            self.pools.entry(upstream_key.clone()).or_insert_with(|| {
                // Warm up: create only 1 client instead of full pool_size
                // 预热：只创建 1 个客户端而不是完整的 pool_size
                let permit_mgr = Arc::new(PermitManager::new(1));
                let client = Arc::new(TcpMuxClient::new(
                    upstream_key.clone(),
                    Arc::clone(&permit_mgr),
                ));
                client.set_health_check_config(
                    self.health_error_threshold,
                    self.max_age_secs,
                    self.idle_timeout_secs,
                );
                Arc::new(TcpConnectionPool {
                    clients: vec![client],
                    next_idx: AtomicUsize::new(0),
                })
            });

            // Drop the reference immediately, we just wanted to ensure the pool exists
            // 立即释放引用，我们只是想确保连接池存在
        }

        info!(
            count = upstreams.len(),
            "TCP connection pools warmed up successfully"
        );
    }

    /// Test-only helper to initialize or get a pool without network operations
    /// This mirrors the production pool initialization logic used in send().
    #[cfg(test)]
    pub fn get_or_init_pool_for_test(&self, upstream: &str) -> Arc<TcpConnectionPool> {
        let upstream_key: Arc<str> = Arc::from(upstream);
        self.pools
            .entry(upstream_key.clone())
            .or_insert_with(|| {
                let mut clients = Vec::with_capacity(self.pool_size);
                let size = if self.pool_size == 0 { 1 } else { self.pool_size };
                // Create per-upstream permit manager to avoid global TCP limit
                let permit_mgr = Arc::new(PermitManager::new(size));
                for _ in 0..size {
                    let client = Arc::new(TcpMuxClient::new(
                        upstream_key.clone(),
                        Arc::clone(&permit_mgr),
                    ));
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
            .clone()
    }

    #[inline]
    pub async fn send(
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
                // Create per-upstream permit manager to avoid global TCP limit
                // 为每个 upstream 创建独立的 permit manager，避免全局 TCP 限制
                let permit_mgr = Arc::new(PermitManager::new(size));
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

pub struct TcpMuxClient {
    pub upstream: Arc<str>,
    /// Write half protected by Mutex - serves as both connection storage and write serialization
    conn: Arc<Mutex<Option<OwnedWriteHalf>>>,
    pending: Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
    next_id: AtomicU16,
    /// Per-upstream permit manager for TCP connection-level control
    /// TCP 连接级别并发控制的 per-upstream permit manager
    pub permit_manager: Arc<PermitManager>,
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
            pending: Arc::new(dashmap::DashMap::with_hasher(FxBuildHasher)),
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
                // Ensure buffer has enough space for length prefix
                // 确保缓冲区有足够空间读取长度前缀
                if reusable_buf.capacity() < 2 {
                     reusable_buf.reserve(4096);
                }

                let mut len_buf = [0u8; 2];
                if let Err(err) = reader.read_exact(&mut len_buf).await {
                    debug!(target = "tcp_mux", upstream = %upstream, error = %err, "tcp read len failed");
                    Self::fail_all_async(&pending, anyhow::anyhow!("tcp read len failed"), &conn, &conn_permit)
                        .await;
                    break;
                }
                let resp_len = u16::from_be_bytes(len_buf) as usize;

                // Resize buffer if needed, reusing allocation (and ensure capacity)
                // resize() handles both truncation and extension, no need for clear()
                if reusable_buf.capacity() < resp_len {
                    reusable_buf.reserve(resp_len.max(4096));
                }
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
            .expect("SystemTime should be after UNIX_EPOCH")
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
            .expect("SystemTime should be after UNIX_EPOCH")
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
            .expect("SystemTime should be after UNIX_EPOCH")
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
        
        // 生成通道
        let (tx, rx) = oneshot::channel();
        
        // 原子操作：分配 ID 并注册到 pending map，避免竞态条件
        let (new_packet, new_id) = self.register_pending(packet, original_id, tx).await?;

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
                .expect("SystemTime should be after UNIX_EPOCH")
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

    /// Rewrite DNS transaction ID and register in pending map atomically, returning BytesMut for efficient further operations
    /// 原子操作：重写 DNS 事务 ID 并注册到 pending map，返回 BytesMut 以进行高效的后续操作
    async fn register_pending(
        &self, 
        packet: &[u8], 
        original_id: u16, 
        tx: oneshot::Sender<anyhow::Result<Bytes>>
    ) -> anyhow::Result<(BytesMut, u16)> {
        let mut tries = 0;
        let new_id = loop {
            let cand = self.next_id.fetch_add(1, Ordering::Relaxed);
            tries += 1;
            
            // Use Entry API to check vacancy and insert atomically
            // 使用 Entry API 检查空位并原子插入
            if let entry::Entry::Vacant(e) = self.pending.entry(cand) {
                e.insert(Pending { original_id, tx });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;
    use futures::future::join_all;

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

        // Act: Spawn many concurrent register_pending calls to test contention handling
        let tasks = (0..64)
            .map(|_| {
                let client = Arc::clone(&client);
                async move {
                    let dummy = vec![0u8; 4];
                    let (tx, _) = oneshot::channel();
                    client.register_pending(&dummy, 0, tx).await.map(|(_, id)| id)
                }
            })
            .collect::<Vec<_>>();

        let results = timeout(Duration::from_millis(500), join_all(tasks))
            .await
            .expect("register_pending stalled under contention");

        // Assert: Verify all IDs are unique (no duplicates under contention)
        let mut ids = std::collections::HashSet::new();
        for r in results {
            let id = r.expect("register_pending failed");
            assert!(ids.insert(id), "duplicate id allocated under contention");
        }
    }

    #[test]
    fn test_tcp_pool_per_upstream_permit_manager_isolated() {
        // ========== Arrange ==========
        let mux = TcpMultiplexer::new(2, 3, 0, 0);

        // ========== Act ==========
        let pool_a = mux.get_or_init_pool_for_test("1.1.1.1:53");
        let pool_b = mux.get_or_init_pool_for_test("8.8.8.8:53");
        let permit_a = Arc::clone(&pool_a.clients[0].permit_manager);
        let permit_b = Arc::clone(&pool_b.clients[0].permit_manager);

        // ========== Assert ==========
        assert_eq!(pool_a.clients.len(), 2, "Pool A should have two clients");
        assert_eq!(pool_b.clients.len(), 2, "Pool B should have two clients");
        assert!(
            Arc::ptr_eq(&permit_a, &pool_a.clients[1].permit_manager),
            "All clients in the same pool should share one permit manager"
        );
        assert!(
            Arc::ptr_eq(&permit_b, &pool_b.clients[1].permit_manager),
            "All clients in the same pool should share one permit manager"
        );
        assert!(
            !Arc::ptr_eq(&permit_a, &permit_b),
            "Different upstreams should have distinct permit managers"
        );
        assert_eq!(permit_a.max_permits(), 2, "Permit manager should match pool size for upstream A");
        assert_eq!(permit_b.max_permits(), 2, "Permit manager should match pool size for upstream B");
    }
}
