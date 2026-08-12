use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use dashmap::mapref::entry;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{
    Connection as QuicConnection, Endpoint as QuicEndpoint, TransportConfig as QuicTransportConfig,
};
use reqwest::Client as DohHttpClient;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HOST};
use rustc_hash::FxBuildHasher;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{
    TcpStream,
    tcp::{OwnedReadHalf, OwnedWriteHalf},
};
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use url::Url;
use webpki_roots::TLS_SERVER_ROOTS;

use super::concurrency::{PermitGuard, PermitManager};

#[inline]
fn unix_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

/// Type alias for UDP inflight request tracking
/// ID -> (OriginalID, ExpectedAddr, Sender)
type UdpInflightMap =
    DashMap<u16, (u16, SocketAddr, oneshot::Sender<anyhow::Result<Bytes>>), FxBuildHasher>;

/// RAII Guard to ensure inflight entries are removed even on cancellation/panic
/// RAII Guard 确保即使在取消或 panic 时也能移除 inflight 条目
struct InflightGuard {
    inflight: Arc<UdpInflightMap>,
    id: u16,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.id);
    }
}

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
    pub fn new(size: usize) -> anyhow::Result<Self> {
        // Prevent port exhaustion by enforcing minimum pool size
        let effective_size = if size == 0 { 1 } else { size };
        let mut pool = Vec::with_capacity(effective_size);
        for idx in 0..effective_size {
            // Use socket2 to set buffer sizes
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
                .context("create UDP pool socket")?;
            // Set buffer sizes to 4MB to prevent packet loss under load
            if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
                warn!("failed to set udp recv buffer size: {}", e);
            }
            if let Err(e) = socket.set_send_buffer_size(4 * 1024 * 1024) {
                warn!("failed to set udp send buffer size: {}", e);
            }
            let bind_addr = SocketAddr::from(([0, 0, 0, 0], 0));
            socket
                .bind(&bind_addr.into())
                .context("bind UDP pool socket")?;
            socket
                .set_nonblocking(true)
                .context("set UDP pool socket nonblocking")?;

            let std_sock: std::net::UdpSocket = socket.into();
            let socket = Arc::new(
                tokio::net::UdpSocket::from_std(std_sock)
                    .context("create Tokio UDP pool socket")?,
            );
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
                                        let resp_len = response.len();

                                        if tx.send(Ok(response)).is_err() {
                                            tracing::debug!(
                                                socket_idx = idx,
                                                original_id = original_id,
                                                response_id = id,
                                                response_len = resp_len,
                                                "Failed to send UDP response, channel already closed"
                                            );
                                        } else {
                                            tracing::trace!(
                                                socket_idx = idx,
                                                original_id = original_id,
                                                response_id = id,
                                                response_len = resp_len,
                                                "UDP response sent successfully"
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
        Ok(Self {
            pool,
            next_idx: AtomicUsize::new(0),
        })
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

        // Find a free ID using atomic entry API
        // 使用原子 Entry API 查找空闲 ID
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
                        warn!(
                            "udp pool exhausted: socket_idx={} inflight_count={}",
                            idx,
                            state.inflight.len()
                        );
                        return Err(anyhow::anyhow!(
                            "udp pool exhausted (too many inflight requests)"
                        ));
                    }
                }
            }
        }

        // RAII Guard: ensures entry is removed from map when guard is dropped
        // (e.g. timeout, cancel, early return)
        // RAII Guard：确保在 guard 丢弃时（超时、取消、提前返回）移除条目
        let _guard = InflightGuard {
            inflight: state.inflight.clone(),
            id: new_id,
        };

        // Rewrite packet with new ID using BytesMut to avoid full copy
        let mut new_packet = BytesMut::with_capacity(packet.len());
        new_packet.extend_from_slice(packet);
        let id_bytes = new_id.to_be_bytes();
        new_packet[0] = id_bytes[0];
        new_packet[1] = id_bytes[1];

        if let Err(e) = state.socket.send_to(&new_packet, addr).await {
            // Guard will remove inflight entry automatically
            return Err(e.into());
        }

        match timeout(timeout_dur, rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => {
                // Channel closed by receiver (should not happen normally unless logic error or panic)
                Err(anyhow::anyhow!("channel closed"))
            }
            Err(_) => Err(anyhow::anyhow!("upstream timeout")),
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
    pub fn warm_up_pools(&self, upstreams: &rustc_hash::FxHashSet<String>) {
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
                let size = if self.pool_size == 0 {
                    1
                } else {
                    self.pool_size
                };
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
                let size = if self.pool_size == 0 {
                    1
                } else {
                    self.pool_size
                };
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
    /// Generation counter to detect stale readers
    /// 代数计数器，用于检测过期的 reader (Wrapped in Arc for sharing with spawned tasks)
    generation: Arc<AtomicU64>,
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
    /// Reader 取消令牌 / Reader cancellation token
    read_cancel: Mutex<CancellationToken>,
}

struct Pending {
    original_id: u16,
    tx: oneshot::Sender<anyhow::Result<Bytes>>,
}

/// RAII Guard for TCP pending requests to ensure cleanup on cancellation
struct TcpPendingGuard {
    pending: Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
    id: u16,
}

impl Drop for TcpPendingGuard {
    fn drop(&mut self) {
        self.pending.remove(&self.id);
    }
}

impl TcpMuxClient {
    fn new(upstream: Arc<str>, permit_manager: Arc<PermitManager>) -> Self {
        Self {
            upstream,
            conn: Arc::new(Mutex::new(None)),
            pending: Arc::new(dashmap::DashMap::with_hasher(FxBuildHasher)),
            next_id: AtomicU16::new(1),
            permit_manager,
            generation: Arc::new(AtomicU64::new(0)),
            conn_permit: Arc::new(Mutex::new(None)),
            // 初始化健康检查字段（默认值，实际值会在 TcpMultiplexer 中设置）
            consecutive_errors: AtomicUsize::new(0),
            health_threshold: AtomicUsize::new(3),
            conn_create_time: AtomicU64::new(0),
            max_age_ms: AtomicU64::new(300_000), // 5 分钟
            last_request_time: AtomicU64::new(0),
            idle_timeout_ms: AtomicU64::new(60_000), // 1 分钟
            last_health_check_time: AtomicU64::new(0),
            read_cancel: Mutex::new(CancellationToken::new()),
        }
    }

    /// 设置健康检查参数
    /// Set health check parameters
    fn set_health_check_config(
        &self,
        error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) {
        self.health_threshold
            .store(error_threshold, Ordering::Release);
        self.max_age_ms
            .store(max_age_secs * 1000, Ordering::Release);
        self.idle_timeout_ms
            .store(idle_timeout_secs * 1000, Ordering::Release);
    }

    async fn spawn_reader(
        &self,
        mut reader: OwnedReadHalf,
        cancel_token: CancellationToken,
        my_generation: u64,
        global_generation: Arc<AtomicU64>,
    ) {
        let pending = Arc::clone(&self.pending);
        let upstream = self.upstream.clone();
        let conn = Arc::clone(&self.conn);
        let conn_permit = Arc::clone(&self.conn_permit); // Clone conn_permit

        tokio::spawn(async move {
            // Pre-allocate a reusable buffer for TCP reads
            // DNS TCP max is 65535 bytes, but typical responses are much smaller
            let mut reusable_buf = BytesMut::with_capacity(4096);
            loop {
                // Check if this reader is still valid (Zombie Check)
                // 检查此 reader 是否仍然有效（僵尸检测）
                if global_generation.load(Ordering::Relaxed) != my_generation {
                    debug!(target = "tcp_mux", upstream = %upstream, gen = my_generation, "TCP reader detected older generation, exiting silently");
                    return;
                }

                // Ensure buffer has enough space for length prefix
                // 确保缓冲区有足够空间读取长度前缀
                if reusable_buf.capacity() < 2 {
                    reusable_buf.reserve(4096);
                }

                let mut len_buf = [0u8; 2];
                // Cancellation: select! interrupts blocked read_exact on reset
                // 取消机制：select! 在 reset 时中断阻塞的 read_exact
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!(target = "tcp_mux", upstream = %upstream, gen = my_generation, "TCP reader cancelled by reset, exiting");
                        return;
                    }
                    result = reader.read_exact(&mut len_buf) => {
                        if let Err(err) = result {
                            // Check generation again before resetting anything
                            if global_generation.load(Ordering::Relaxed) == my_generation {
                                debug!(target = "tcp_mux", upstream = %upstream, error = %err, "tcp read len failed");
                                Self::fail_all_async(
                                    &pending,
                                    anyhow::anyhow!("tcp read len failed"),
                                    &conn,
                                    &conn_permit,
                                )
                                .await;
                            } else {
                                debug!(target = "tcp_mux", upstream = %upstream, gen = my_generation, "TCP reader failed but generation changed, ignoring");
                            }
                            break;
                        }
                    }
                }
                let resp_len = u16::from_be_bytes(len_buf) as usize;

                // Resize buffer if needed, reusing allocation (and ensure capacity)
                // resize() handles both truncation and extension, no need for clear()
                if reusable_buf.capacity() < resp_len {
                    reusable_buf.reserve(resp_len.max(4096));
                }
                reusable_buf.resize(resp_len, 0);

                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!(target = "tcp_mux", upstream = %upstream, gen = my_generation, "TCP reader cancelled by reset during body read, exiting");
                        return;
                    }
                    result = reader.read_exact(&mut reusable_buf[..resp_len]) => {
                        if let Err(err) = result {
                            // Check generation again
                            if global_generation.load(Ordering::Relaxed) == my_generation {
                                debug!(target = "tcp_mux", upstream = %upstream, error = %err, "tcp read body failed");
                                Self::fail_all_async(
                                    &pending,
                                    anyhow::anyhow!("tcp read body failed"),
                                    &conn,
                                    &conn_permit,
                                )
                                .await;
                            }
                            break;
                        }
                    }
                }

                if resp_len < 2 {
                    continue;
                }
                let resp_id = u16::from_be_bytes([reusable_buf[0], reusable_buf[1]]);
                if let Some((_, p)) = pending.remove(&resp_id) {
                    let orig = p.original_id;
                    reusable_buf[0..2].copy_from_slice(&p.original_id.to_be_bytes());
                    // Split off the used portion to send, keeping capacity for reuse
                    let response = reusable_buf.split_to(resp_len).freeze();
                    match p.tx.send(Ok(response)) {
                        Ok(()) => {
                            tracing::trace!(
                                target = "tcp_mux",
                                upstream = %upstream,
                                resp_id,
                                original_id = orig,
                                response_len = resp_len,
                                "TCP mux response sent successfully"
                            );
                        }
                        Err(_) => {
                            tracing::debug!(
                                target = "tcp_mux",
                                upstream = %upstream,
                                resp_id,
                                original_id = orig,
                                "TCP mux response send failed, channel already closed"
                            );
                        }
                    }
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
            self.reset().await;
            // Clear error counter to avoid immediate re-triggering on next error
            // 清零错误计数器，避免下次错误时立即重新触发
            self.consecutive_errors.store(0, Ordering::Release);
            true // Connection was reset / 连接已重置
        } else {
            false // Connection was not reset / 连接未重置
        }
    }

    /// Record success and clear error counter
    /// 记录成功并清零错误计数
    fn record_success(&self) {
        self.consecutive_errors.store(0, Ordering::Release);
        let now = unix_time_millis();
        self.last_request_time.store(now, Ordering::Release);
    }

    /// Check if connection needs reset due to aging or idle timeout
    /// 检查连接是否需要重置（老化或空闲超时）
    ///
    /// Returns true if connection was reset, false otherwise.
    /// 如果连接被重置返回 true，否则返回 false。
    async fn check_connection_health(&self) -> bool {
        let now = unix_time_millis();

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
                self.reset().await;
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
                self.reset().await;
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

        // Check if we are reusing an existing connection (for potential retry strategy)
        // 检查我们是否在重用现有连接（用于潜在的重试策略）
        let is_reused = {
            let guard = self.conn.lock().await;
            guard.is_some()
        };

        match self.send_attempt(packet, timeout_dur).await {
            Ok(res) => Ok(res),
            Err(err) => {
                // TRANSPARENT RETRY: If connection was reused and failed with transport error, retry once with fresh connection
                // 透明重试：如果连接是复用的并且因传输错误失败，则使用新连接重试一次
                if is_reused {
                    let elapsed = start.elapsed();
                    // Calculate remaining budget, but ensure at least 1.5s for the fresh attempt
                    // 计算剩余预算，但确认为新尝试保留至少 1.5s
                    let remaining = if timeout_dur > elapsed {
                        timeout_dur - elapsed
                    } else {
                        Duration::from_millis(0)
                    };

                    // Only retry if we have budget OR if we decide reliability > strict timeout
                    // Strategy: If剩余时间 < 1s, we grant a "grace period" of 1s to save the query
                    let retry_timeout = if remaining.as_millis() < 1000 {
                        Duration::from_millis(1500)
                    } else {
                        remaining
                    };

                    tracing::warn!(
                        upstream = %self.upstream,
                        error = %err,
                        retry_timeout_ms = retry_timeout.as_millis(),
                        "Connection reuse failed, performing transparent retry with fresh connection"
                    );

                    // Connection should have been reset by send_attempt already upon error
                    // send_attempt 出错时连接应该已经被重置
                    return self.send_attempt(packet, retry_timeout).await;
                }
                Err(err)
            }
        }
    }

    async fn send_attempt(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();

        // 性能优化：仅在距离上次检查超过 30 秒时才执行健康检查
        // Performance: Only check connection health if 30 seconds have passed since last check
        const HEALTH_CHECK_INTERVAL_MS: u64 = 30_000; // 30 秒
        let now = unix_time_millis();
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

        // RAII Guard: ensures entry is removed from map when guard is dropped
        // RAII Guard：确保在 guard 丢弃时（超时、取消、提前返回）移除条目
        let _guard = TcpPendingGuard {
            pending: self.pending.clone(),
            id: new_id,
        };

        // 2. Write request with remaining timeout (connection already ensured)
        // 2. 写入请求（连接已确保）
        let write_res = timeout(remaining, async {
            // Frame already contains length prefix + payload — write directly, no second copy.
            // 帧已包含长度前缀 + 负载——直接写入，无二次拷贝。
            let mut guard = self.conn.lock().await;

            // Connection must exist (ensure_connection was called earlier)
            // 连接必须存在（ensure_connection 已在之前调用）
            // Pre-flight check: if writer is closed or broken, fail fast
            let writer = guard.as_mut().context("tcp write half missing")?;

            // Note: OwnedWriteHalf doesn't support peek/checking error directly easily without shared socket access.
            // But if the previous read failed, guard should be None (reset).
            // The fact we are here means 'guard' is Some, so we think connection is alive.
            // Writing to a closed socket usually triggers error immediately on Linux/BSD.

            if let Err(e) = writer.write_all(&new_packet).await {
                return Err(anyhow::anyhow!(e).context("tcp write failed"));
            }
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                // Guard will remove pending entry automatically
                // Guard 会自动移除 pending 条目

                // Record error and FORCE RESET on write failure (socket likely dead)
                // 记录错误并在写入失败时强制重置（socket 可能已死）
                self.record_error().await;
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);

                return Err(err).context(format!(
                    "TCP write/connect failed for upstream {upstream}",
                    upstream = self.upstream
                ));
            }
            Err(_) => {
                // Guard will remove pending entry automatically

                // Record error and FORCE RESET on write timeout
                // 记录错误并在写入超时时强制重置
                self.record_error().await;
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);

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
            // Guard will remove pending entry automatically

            // Record error and FORCE RESET on prereq timeout
            // 记录错误并在超时时强制重置
            self.record_error().await;
            self.reset().await;
            self.consecutive_errors.store(0, Ordering::Release);

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
                // Guard will remove pending entry automatically

                // Record error but DO NOT reset - Mux handles ignored responses
                // 记录错误但不重置 - Mux 会处理被忽略的响应
                self.record_error().await;
                return Err(anyhow::anyhow!(
                    "TCP response canceled for upstream {upstream}",
                    upstream = self.upstream
                ));
            }
            Err(_elapsed) => {
                // Guard will remove pending entry automatically

                // Record error and FORCE RESET on response timeout (connection likely dead/stalled)
                // 记录错误并在响应超时时强制重置（连接可能死锁/停滞）
                self.record_error().await;
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);

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
        // First, check if we need to reconnect based on error state
        // 首先，根据错误状态检查是否需要重连
        let errors = self.consecutive_errors.load(Ordering::Acquire);
        let needs_reset = errors > 0;

        if needs_reset {
            debug!(
                upstream = %self.upstream,
                consecutive_errors = errors,
                "TCP connection has errors, resetting before ensure"
            );
            self.reset().await;
        }

        let mut guard = self.conn.lock().await;

        if guard.is_none() {
            // Acquire connection-level permit (non-blocking)
            // 获取连接级别 permit（非阻塞）
            let permit = self
                .permit_manager
                .try_acquire()
                .ok_or_else(|| anyhow::anyhow!("tcp connection limit exceeded"))?;

            // Establish TCP connection
            // 建立 TCP 连接
            let stream = TcpStream::connect(&*self.upstream)
                .await
                .map_err(|e| anyhow::anyhow!("tcp connect failed: {}", e))?;

            // Configure socket options for robustness
            // 配置 socket 选项以增强健壮性
            let _ = stream.set_nodelay(true);

            // Set Check to 5s to detect dead connections faster (Aggressive Keepalive)
            let sock = SockRef::from(&stream);
            let mut ka = TcpKeepalive::new();
            ka = ka.with_time(Duration::from_secs(5));
            ka = ka.with_interval(Duration::from_secs(2));

            // Explicitly enable SO_KEEPALIVE (Essential for Windows/Linux)
            if let Err(e) = sock.set_keepalive(true) {
                warn!(upstream = %self.upstream, error = %e, "Failed to enable SO_KEEPALIVE");
            }
            if let Err(e) = sock.set_tcp_keepalive(&ka) {
                warn!(upstream = %self.upstream, error = %e, "Failed to set TCP keepalive params");
            }

            let (read_half, write_half) = stream.into_split();

            *guard = Some(write_half);

            // Increment generation for new connection
            // 为新连接增加代数
            let new_gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;

            // Create fresh cancellation token for this connection lifecycle
            // 为此连接生命周期创建新的取消令牌
            let new_token = CancellationToken::new();

            // Spawn reader while holding the lock to prevent races
            // 持有锁时启动 reader 以防止竞争
            self.spawn_reader(
                read_half,
                new_token.clone(),
                new_gen,
                self.generation.clone(),
            )
            .await;

            // Store token AFTER spawn so reset() can only cancel a live reader
            // 在 spawn 之后存储 token，确保 reset() 只能取消已启动的 reader
            {
                let mut token_guard = self.read_cancel.lock().await;
                *token_guard = new_token;
            }

            // Store permit in connection (held for connection lifetime)
            // 将 permit 保存在连接中（连接生命周期内持有）
            let mut conn_permit_guard = self.conn_permit.lock().await;
            *conn_permit_guard = Some(permit);

            // 设置连接创建时间
            // Set connection creation time
            let now = unix_time_millis();
            self.conn_create_time.store(now, Ordering::Release);
            self.last_request_time.store(now, Ordering::Release);

            // Clear error count for new connection
            // 清除新连接的错误计数
            self.consecutive_errors.store(0, Ordering::Release);

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
        tx: oneshot::Sender<anyhow::Result<Bytes>>,
    ) -> anyhow::Result<(BytesMut, u16)> {
        // Serialize registration with connection teardown so a failed reader cannot miss a waiter.
        // 将 pending 注册与连接清理串行化，避免失败的 reader 遗漏 waiter。
        let conn_guard = self.conn.lock().await;
        if conn_guard.is_none() {
            anyhow::bail!("connection closed before registration");
        }

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
        drop(conn_guard);

        // Build complete TCP wire frame (2-byte length prefix + DNS message with rewritten ID).
        // Caller writes this directly without further copying — saves one memcpy per request.
        // 构建完整 TCP wire frame（2 字节长度前缀 + 改写 ID 后的 DNS 消息）。
        // 调用方直接写入此帧，无需二次拷贝——每请求省一次 memcpy。
        let mut frame = BytesMut::with_capacity(2 + packet.len());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);
        let id_bytes = new_id.to_be_bytes();
        frame[2] = id_bytes[0]; // TXID at offset 2 (after length prefix) / 偏移 2 处（长度前缀之后）
        frame[3] = id_bytes[1];
        Ok((frame, new_id))
    }

    async fn fail_all_async(
        pending: &Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
        err: anyhow::Error,
        conn: &Arc<Mutex<Option<OwnedWriteHalf>>>,
        conn_permit: &Arc<Mutex<Option<PermitGuard>>>,
    ) {
        let err_msg = err.to_string();
        // Hold the connection lock while resetting and draining. register_pending uses the same
        // lock, so it either registers before this drain or observes the closed connection.
        let mut conn_guard = conn.lock().await;
        *conn_guard = None;
        let keys: Vec<u16> = pending.iter().map(|item| *item.key()).collect();
        for key in keys {
            if let Some((_, p)) = pending.remove(&key) {
                let _ = p.tx.send(Err(anyhow::anyhow!(err_msg.clone())));
            }
        }
        let mut permit_guard = conn_permit.lock().await;
        *permit_guard = None;
    }

    /// Reset connection: cancel reader task, then drop write half and release permit
    /// 重置连接：取消 reader 任务，然后丢弃写半部并释放许可
    ///
    /// The cancellation token interrupts the reader's blocked read so it
    /// exits immediately instead of leaking the TCP connection.
    /// 取消令牌中断 reader 阻塞的读取操作，使其立即退出而非泄漏 TCP 连接。
    async fn reset(&self) {
        self.read_cancel.lock().await.cancel();
        Self::reset_conn(&self.conn, &self.conn_permit).await;
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

// ===================== DoH (DNS over HTTPS) =====================

/// Marker for HTTP status errors: the connection itself is healthy, so retrying
/// won't help (only transport-level errors indicate a possibly dead connection).
/// HTTP 状态码错误标记：连接本身正常，重试无益
/// （只有传输层错误才指示连接可能已死）
#[derive(Debug)]
struct DohHttpStatusError(anyhow::Error);

impl std::fmt::Display for DohHttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DohHttpStatusError {}

pub struct DohClient {
    /// Hot-swappable reqwest client (its connection pool). Replacing it drops the
    /// old pool, which is the only way to evict half-open/dead connections that
    /// reqwest cannot detect (DoH uses POST, which hyper won't auto-retry).
    /// 可热替换的 reqwest 客户端（其连接池）。替换即丢弃旧池，
    /// 这是清除 reqwest 无法检测的半开/死连接的唯一手段
    /// （DoH 用 POST，hyper 不会自动重试）
    client: ArcSwap<DohHttpClient>,
    pool_max_idle_per_host: usize,
    /// Per-upstream consecutive transport-error counts. Mirrors the mux clients'
    /// consecutive_errors, but keyed by upstream since the reqwest pool is per-host.
    /// per-upstream 连续传输错误计数。对齐 mux 的 consecutive_errors，
    /// 因 reqwest 连接池是 per-host 的，按 upstream 维度计数
    error_counts: DashMap<Arc<str>, usize, FxBuildHasher>,
    /// Threshold of consecutive transport errors that triggers a pool rebuild.
    /// 触发连接池重建的连续传输错误阈值
    health_error_threshold: usize,
}

impl DohClient {
    pub fn new(
        pool_max_idle_per_host: usize,
        health_error_threshold: usize,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: ArcSwap::from_pointee(Self::build_client(pool_max_idle_per_host)?),
            pool_max_idle_per_host,
            error_counts: DashMap::with_hasher(FxBuildHasher),
            health_error_threshold,
        })
    }

    /// Build a fresh reqwest client. Used for both initial construction and pool
    /// rebuilds (the latter evicts dead/half-open connections).
    /// 构建新的 reqwest 客户端，用于初始构造和连接池重建（后者驱逐死/半开连接）
    fn build_client(pool_max_idle_per_host: usize) -> anyhow::Result<DohHttpClient> {
        DohHttpClient::builder()
            .http2_adaptive_window(true)
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(pool_max_idle_per_host.max(1))
            .build()
            .context("build doh http client")
    }

    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let (url, host_override) = build_doh_url(upstream)?;
        let host = host_override.as_deref();

        let start = tokio::time::Instant::now();
        match self.send_once(packet, &url, host, timeout_dur).await {
            Ok(bytes) => {
                self.record_success(upstream);
                Ok(bytes)
            }
            Err(err) if is_transport_error(&err) => {
                // TRANSPARENT RETRY: DNS queries are semantically idempotent, so a
                // single retry is safe. record_error() may rebuild the pool first;
                // the retry then loads the fresh client (new connections).
                // 透明重试：DNS 查询语义幂等，单次重试安全。
                // record_error() 可能先重建连接池，重试时加载新客户端（新连接）。
                let rebuilt = self.record_error(upstream);
                let remaining = timeout_dur.saturating_sub(start.elapsed());
                // Mirror TcpMuxClient: guarantee >= 1.5s budget for the fresh attempt.
                // 对齐 TcpMuxClient：为新尝试保证至少 1.5s 预算
                let retry_timeout = if remaining < Duration::from_secs(1) {
                    Duration::from_millis(1500)
                } else {
                    remaining
                };
                warn!(
                    upstream = upstream,
                    error = %err,
                    pool_rebuilt = rebuilt,
                    retry_timeout_ms = retry_timeout.as_millis() as u64,
                    "DoH transport error, performing transparent retry"
                );
                self.send_once(packet, &url, host, retry_timeout).await
            }
            Err(e) => Err(e),
        }
    }

    /// Single attempt: send the request and read the body within a timeout.
    /// 单次尝试：在超时内发送请求并读取响应体
    async fn send_once(
        &self,
        packet: &[u8],
        url: &Url,
        host_override: Option<&str>,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        // load_full() returns an owned Arc<Client>, keeping the Future Send across
        // await points (an ArcSwap Guard would not). The Arc is cheap to hold.
        // load_full() 返回 owned Arc<Client>，保持 Future 跨 await 点 Send
        // （ArcSwap 的 Guard 不满足）。持有 Arc 很廉价。
        let client = self.client.load_full();

        let mut req = client
            .post(url.clone())
            .header(ACCEPT, "application/dns-message")
            .header(CONTENT_TYPE, "application/dns-message")
            .body(packet.to_vec());

        if let Some(host) = host_override {
            req = req.header(HOST, host);
        }

        // Wrap entire operation (send + read body) in a single timeout to prevent
        // hanging if the server sends headers but delays the body.
        // 将整个操作（发送 + 读取响应体）包裹在单个超时中，
        // 防止服务器发送头信息但延迟响应体时挂起。
        let result = timeout(timeout_dur, async {
            let resp = req.send().await.context("doh request send failed")?;

            let status = resp.status();
            if !status.is_success() {
                // Wrap as DohHttpStatusError so the caller knows the connection is
                // fine and a retry won't help.
                // 包装为 DohHttpStatusError，让调用方知道连接正常、重试无益
                return Err(anyhow::Error::new(DohHttpStatusError(anyhow::anyhow!(
                    "doh http status {status}"
                ))));
            }

            resp.bytes().await.context("read doh response body")
        })
        .await;

        match result {
            Ok(Ok(bytes)) => Ok(bytes),
            // reqwest send / IO / body error — transport-level, retryable
            // reqwest 发送 / IO / 响应体错误 —— 传输层，可重试
            Ok(Err(e)) => Err(e),
            // Timeout — transport-level, retryable
            // 超时 —— 传输层，可重试
            Err(_elapsed) => Err(anyhow::anyhow!("doh request timeout")),
        }
    }

    /// Record a consecutive transport error for the upstream. When the count
    /// reaches the threshold, rebuild the reqwest client (evicting the dead
    /// connection pool) and reset the counter. Returns true if rebuilt.
    /// 记录 upstream 的连续传输错误。计数达阈值时重建 reqwest 客户端
    /// （驱逐死连接池）并清零计数。重建返回 true。
    fn record_error(&self, upstream: &str) -> bool {
        let mut count = self
            .error_counts
            .entry(Arc::<str>::from(upstream))
            .or_insert(0);
        *count += 1;
        if *count >= self.health_error_threshold {
            match Self::build_client(self.pool_max_idle_per_host) {
                Ok(new_client) => {
                    // Swap in a fresh client; the old pool is released once in-flight
                    // requests holding a cloned Arc finish.
                    // 替换为新客户端；旧池在持有 Arc 副本的在途请求结束后释放
                    self.client.store(Arc::new(new_client));
                    warn!(
                        upstream = upstream,
                        consecutive_errors = *count,
                        threshold = self.health_error_threshold,
                        "DoH error threshold exceeded, rebuilding connection pool"
                    );
                    *count = 0;
                    true
                }
                Err(e) => {
                    warn!(
                        upstream = upstream,
                        error = %e,
                        "failed to rebuild DoH client, keeping old pool"
                    );
                    false
                }
            }
        } else {
            debug!(
                upstream = upstream,
                consecutive_errors = *count,
                threshold = self.health_error_threshold,
                "DoH transport error recorded"
            );
            false
        }
    }

    /// Clear the consecutive error counter on success (mirrors record_success).
    /// 成功时清零连续错误计数（对齐 record_success）
    fn record_success(&self, upstream: &str) {
        if let Some(mut count) = self.error_counts.get_mut(upstream) {
            *count = 0;
        }
    }
}

/// A transport-level error is anything that is NOT an HTTP status error: timeouts,
/// connection failures, and IO errors all indicate a possibly dead connection and
/// are safe to retry once (DoH queries are semantically idempotent).
/// 传输层错误 = 非 HTTP 状态码错误：超时、连接失败、IO 错误都指示连接可能已死，
/// 单次重试安全（DoH 查询语义幂等）
fn is_transport_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<DohHttpStatusError>().is_none()
}

fn build_doh_url(upstream: &str) -> anyhow::Result<(Url, Option<String>)> {
    let url_str = if upstream.starts_with("http://") || upstream.starts_with("https://") {
        upstream.to_string()
    } else if let Some(stripped) = upstream.strip_prefix("doh://") {
        format!("https://{}", stripped)
    } else {
        format!("https://{}", upstream)
    };

    let mut url = Url::parse(&url_str).context("invalid doh url")?;

    // Default path for DoH if not provided
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/dns-query");
    }

    let mut host_override: Option<String> = None;
    if url.query().is_some() {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in url.query_pairs() {
            if k.eq_ignore_ascii_case("host") {
                if !v.is_empty() {
                    host_override = Some(v.to_string());
                }
            } else {
                serializer.append_pair(&k, &v);
            }
        }
        let new_query = serializer.finish();
        if new_query.is_empty() {
            url.set_query(None);
        } else {
            url.set_query(Some(&new_query));
        }
    }

    Ok((url, host_override))
}

// ===================== DoT (DNS over TLS) =====================

type DotTlsStream = tokio_rustls::client::TlsStream<TcpStream>;
type DotReadHalf = tokio::io::ReadHalf<DotTlsStream>;
type DotWriteHalf = tokio::io::WriteHalf<DotTlsStream>;

#[derive(Clone)]
struct DotTarget {
    connect_addr: Arc<str>,
    sni: Arc<str>,
}

/// DoT (DNS over TLS) 多路复用器，管理多个上游的连接池
/// DoT (DNS over TLS) multiplexer, managing connection pools for multiple upstreams
///
/// 参考 RFC 7858 (DNS over TLS) 实现
/// Implements RFC 7858 (DNS over TLS)
pub struct DotMultiplexer {
    pools: dashmap::DashMap<Arc<str>, Arc<DotConnectionPool>, FxBuildHasher>,
    pool_size: usize,
    tls_config: Arc<ClientConfig>,
    health_error_threshold: usize,
    max_age_secs: u64,
    idle_timeout_secs: u64,
}

/// DoT (DNS over TLS) 连接池
/// DoT (DNS over TLS) connection pool
///
/// 参考 RFC 7858 (DNS over TLS) 实现
/// Implements RFC 7858 (DNS over TLS)
pub struct DotConnectionPool {
    clients: Vec<Arc<DotMuxClient>>,
    next_idx: AtomicUsize,
}

/// DoT (DNS over TLS) 多路复用客户端，管理单个上游的 TLS 连接
/// DoT (DNS over TLS) multiplexing client, managing TLS connection for a single upstream
///
/// 参考 RFC 7858 (DNS over TLS) 实现
/// Implements RFC 7858 (DNS over TLS)
pub struct DotMuxClient {
    pub upstream: Arc<str>,
    target: Mutex<Option<DotTarget>>,
    tls_config: Arc<ClientConfig>,
    conn: Arc<Mutex<Option<DotWriteHalf>>>,
    pending: Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
    next_id: AtomicU16,
    pub permit_manager: Arc<PermitManager>,
    generation: Arc<AtomicU64>,
    conn_permit: Arc<Mutex<Option<PermitGuard>>>,
    consecutive_errors: AtomicUsize,
    health_threshold: AtomicUsize,
    conn_create_time: AtomicU64,
    max_age_ms: AtomicU64,
    last_request_time: AtomicU64,
    idle_timeout_ms: AtomicU64,
    last_health_check_time: AtomicU64,
    /// Reader 取消令牌 / Reader cancellation token
    read_cancel: Mutex<CancellationToken>,
}

impl DotMultiplexer {
    pub fn new(
        pool_size: usize,
        health_error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) -> anyhow::Result<Self> {
        let tls_config = build_tls_client_config()?;
        Ok(Self {
            pools: dashmap::DashMap::with_hasher(FxBuildHasher),
            pool_size,
            tls_config: Arc::new(tls_config),
            health_error_threshold,
            max_age_secs,
            idle_timeout_secs,
        })
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
                let mut clients = Vec::with_capacity(self.pool_size.max(1));
                let size = if self.pool_size == 0 {
                    1
                } else {
                    self.pool_size
                };
                let permit_mgr = Arc::new(PermitManager::new(size));
                for _ in 0..size {
                    let client = Arc::new(DotMuxClient::new(
                        upstream_key.clone(),
                        Arc::clone(&self.tls_config),
                        Arc::clone(&permit_mgr),
                    ));
                    client.set_health_check_config(
                        self.health_error_threshold,
                        self.max_age_secs,
                        self.idle_timeout_secs,
                    );
                    clients.push(client);
                }
                Arc::new(DotConnectionPool {
                    clients,
                    next_idx: AtomicUsize::new(0),
                })
            })
            .clone();

        let idx = pool.next_idx.fetch_add(1, Ordering::Relaxed) % pool.clients.len();
        pool.clients[idx].send(packet, timeout_dur).await
    }
}

impl DotMuxClient {
    fn new(
        upstream: Arc<str>,
        tls_config: Arc<ClientConfig>,
        permit_manager: Arc<PermitManager>,
    ) -> Self {
        Self {
            upstream,
            target: Mutex::new(None),
            tls_config,
            conn: Arc::new(Mutex::new(None)),
            pending: Arc::new(dashmap::DashMap::with_hasher(FxBuildHasher)),
            next_id: AtomicU16::new(1),
            permit_manager,
            generation: Arc::new(AtomicU64::new(0)),
            conn_permit: Arc::new(Mutex::new(None)),
            consecutive_errors: AtomicUsize::new(0),
            health_threshold: AtomicUsize::new(3),
            conn_create_time: AtomicU64::new(0),
            max_age_ms: AtomicU64::new(300_000),
            last_request_time: AtomicU64::new(0),
            idle_timeout_ms: AtomicU64::new(60_000),
            last_health_check_time: AtomicU64::new(0),
            read_cancel: Mutex::new(CancellationToken::new()),
        }
    }

    fn set_health_check_config(
        &self,
        error_threshold: usize,
        max_age_secs: u64,
        idle_timeout_secs: u64,
    ) {
        self.health_threshold
            .store(error_threshold, Ordering::Release);
        self.max_age_ms
            .store(max_age_secs * 1000, Ordering::Release);
        self.idle_timeout_ms
            .store(idle_timeout_secs * 1000, Ordering::Release);
    }

    async fn spawn_reader(
        &self,
        mut reader: DotReadHalf,
        cancel_token: CancellationToken,
        my_generation: u64,
        global_generation: Arc<AtomicU64>,
    ) {
        let pending = Arc::clone(&self.pending);
        let upstream = self.upstream.clone();
        let conn = Arc::clone(&self.conn);
        let conn_permit = Arc::clone(&self.conn_permit);

        tokio::spawn(async move {
            let mut reusable_buf = BytesMut::with_capacity(4096);
            loop {
                if global_generation.load(Ordering::Relaxed) != my_generation {
                    debug!(target = "dot_mux", upstream = %upstream, gen = my_generation, "DoT reader older generation, exiting");
                    return;
                }

                let mut len_buf = [0u8; 2];
                // Cancellation: select! interrupts blocked read_exact on reset
                // 取消机制：select! 在 reset 时中断阻塞的 read_exact
                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!(target = "dot_mux", upstream = %upstream, gen = my_generation, "DoT reader cancelled by reset, exiting");
                        return;
                    }
                    result = reader.read_exact(&mut len_buf) => {
                        if let Err(err) = result {
                            if global_generation.load(Ordering::Relaxed) == my_generation {
                                debug!(target = "dot_mux", upstream = %upstream, error = %err, "dot read len failed");
                                Self::fail_all_async(
                                    &pending,
                                    anyhow::anyhow!("dot read len failed"),
                                    &conn,
                                    &conn_permit,
                                )
                                .await;
                            }
                            break;
                        }
                    }
                }
                let resp_len = u16::from_be_bytes(len_buf) as usize;
                if reusable_buf.capacity() < resp_len {
                    reusable_buf.reserve(resp_len.max(4096));
                }
                reusable_buf.resize(resp_len, 0);

                tokio::select! {
                    _ = cancel_token.cancelled() => {
                        debug!(target = "dot_mux", upstream = %upstream, gen = my_generation, "DoT reader cancelled by reset during body read, exiting");
                        return;
                    }
                    result = reader.read_exact(&mut reusable_buf[..resp_len]) => {
                        if let Err(err) = result {
                            if global_generation.load(Ordering::Relaxed) == my_generation {
                                debug!(target = "dot_mux", upstream = %upstream, error = %err, "dot read body failed");
                                Self::fail_all_async(
                                    &pending,
                                    anyhow::anyhow!("dot read body failed"),
                                    &conn,
                                    &conn_permit,
                                )
                                .await;
                            }
                            break;
                        }
                    }
                }

                if resp_len < 2 {
                    continue;
                }
                let resp_id = u16::from_be_bytes([reusable_buf[0], reusable_buf[1]]);
                if let Some((_, p)) = pending.remove(&resp_id) {
                    let orig = p.original_id;
                    reusable_buf[0..2].copy_from_slice(&p.original_id.to_be_bytes());
                    let response = reusable_buf.split_to(resp_len).freeze();
                    let _ = p.tx.send(Ok(response));
                    tracing::trace!(
                        target = "dot_mux",
                        upstream = %upstream,
                        resp_id,
                        original_id = orig,
                        response_len = resp_len,
                        "DoT response sent"
                    );
                } else {
                    debug!(target = "dot_mux", upstream = %upstream, resp_id, "dot response with unknown id");
                }
            }
        });
    }

    async fn record_error(&self) -> bool {
        let errors = self.consecutive_errors.fetch_add(1, Ordering::Release) + 1;
        let threshold = self.health_threshold.load(Ordering::Acquire);

        if errors >= threshold {
            warn!(
                upstream = %self.upstream,
                consecutive_errors = errors,
                threshold = threshold,
                "DoT connection error threshold exceeded, resetting"
            );
            self.reset().await;
            self.consecutive_errors.store(0, Ordering::Release);
            true
        } else {
            false
        }
    }

    fn record_success(&self) {
        self.consecutive_errors.store(0, Ordering::Release);
        let now = unix_time_millis();
        self.last_request_time.store(now, Ordering::Release);
    }

    async fn check_connection_health(&self) -> bool {
        let now = unix_time_millis();

        let create_time = self.conn_create_time.load(Ordering::Acquire);
        let max_age = self.max_age_ms.load(Ordering::Acquire);
        if create_time > 0 && max_age > 0 {
            let age_ms = now.saturating_sub(create_time);
            if age_ms > max_age {
                info!(
                    upstream = %self.upstream,
                    age_ms = age_ms,
                    max_age_ms = max_age,
                    "DoT connection too old, resetting"
                );
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        let last_req = self.last_request_time.load(Ordering::Acquire);
        let idle_timeout = self.idle_timeout_ms.load(Ordering::Acquire);
        if last_req > 0 && idle_timeout > 0 {
            let idle_ms = now.saturating_sub(last_req);
            if idle_ms > idle_timeout {
                info!(
                    upstream = %self.upstream,
                    idle_ms = idle_ms,
                    idle_timeout_ms = idle_timeout,
                    "DoT connection idle timeout, resetting"
                );
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        false
    }

    async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for dot");
        }

        let is_reused = {
            let guard = self.conn.lock().await;
            guard.is_some()
        };

        match self.send_attempt(packet, timeout_dur).await {
            Ok(res) => Ok(res),
            Err(err) => {
                if is_reused {
                    let elapsed = start.elapsed();
                    let remaining = if timeout_dur > elapsed {
                        timeout_dur - elapsed
                    } else {
                        Duration::from_millis(0)
                    };
                    let retry_timeout = if remaining.as_millis() < 1000 {
                        Duration::from_millis(1500)
                    } else {
                        remaining
                    };
                    tracing::warn!(
                        upstream = %self.upstream,
                        error = %err,
                        retry_timeout_ms = retry_timeout.as_millis(),
                        "DoT reuse failed, retrying with fresh connection"
                    );
                    return self.send_attempt(packet, retry_timeout).await;
                }
                Err(err)
            }
        }
    }

    async fn send_attempt(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let start = tokio::time::Instant::now();

        const HEALTH_CHECK_INTERVAL_MS: u64 = 30_000;
        let now = unix_time_millis();
        let last_check = self.last_health_check_time.load(Ordering::Relaxed);
        if last_check == 0 || now.saturating_sub(last_check) >= HEALTH_CHECK_INTERVAL_MS {
            self.check_connection_health().await;
            self.last_health_check_time.store(now, Ordering::Relaxed);
        }

        self.ensure_connection().await?;

        let elapsed = start.elapsed();
        if elapsed >= timeout_dur {
            anyhow::bail!("dot timeout before processing");
        }
        let remaining = timeout_dur - elapsed;

        let original_id = u16::from_be_bytes([packet[0], packet[1]]);
        let (tx, rx) = oneshot::channel();
        let (new_packet, new_id) = self.register_pending(packet, original_id, tx).await?;

        let _guard = TcpPendingGuard {
            pending: self.pending.clone(),
            id: new_id,
        };

        let write_res = timeout(remaining, async {
            // Frame already contains length prefix + payload — write directly, no second copy.
            // 帧已包含长度前缀 + 负载——直接写入，无二次拷贝。
            let mut guard = self.conn.lock().await;
            let writer = guard.as_mut().context("dot write half missing")?;
            if let Err(e) = writer.write_all(&new_packet).await {
                return Err(anyhow::anyhow!(e).context("dot write failed"));
            }
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match write_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                self.record_error().await;
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);

                return Err(err).context(format!(
                    "DoT write/connect failed for upstream {upstream}",
                    upstream = self.upstream
                ));
            }
            Err(_) => {
                self.record_error().await;
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);

                return Err(anyhow::anyhow!(
                    "DoT write/connect timeout for upstream {upstream} (timeout: {timeout_ms}ms)",
                    upstream = self.upstream,
                    timeout_ms = remaining.as_millis()
                ));
            }
        }

        let elapsed_after_write = start.elapsed();
        if elapsed_after_write >= timeout_dur {
            self.record_error().await;
            self.reset().await;
            self.consecutive_errors.store(0, Ordering::Release);

            return Err(anyhow::anyhow!(
                "DoT timeout before waiting for response from upstream {upstream} (elapsed: {elapsed_ms}ms, timeout: {timeout_ms}ms)",
                upstream = self.upstream,
                elapsed_ms = elapsed_after_write.as_millis(),
                timeout_ms = timeout_dur.as_millis()
            ));
        }
        let final_remaining = timeout_dur - elapsed_after_write;

        let resp = match timeout(final_remaining, rx).await {
            Ok(Ok(r)) => {
                self.record_success();
                r?
            }
            Ok(Err(_canceled)) => {
                self.record_error().await;
                return Err(anyhow::anyhow!(
                    "DoT response canceled for upstream {upstream}",
                    upstream = self.upstream
                ));
            }
            Err(_) => {
                self.record_error().await;
                self.reset().await;
                self.consecutive_errors.store(0, Ordering::Release);

                return Err(anyhow::anyhow!(
                    "DoT response timeout from upstream {upstream} (remaining: {timeout_ms}ms)",
                    upstream = self.upstream,
                    timeout_ms = final_remaining.as_millis()
                ));
            }
        };
        Ok(resp)
    }

    async fn ensure_connection(&self) -> anyhow::Result<()> {
        let errors = self.consecutive_errors.load(Ordering::Acquire);
        let needs_reset = errors > 0;

        if needs_reset {
            debug!(
                upstream = %self.upstream,
                consecutive_errors = errors,
                "DoT connection has errors, resetting before ensure"
            );
            self.reset().await;
        }

        let mut guard = self.conn.lock().await;
        if guard.is_none() {
            let permit = self
                .permit_manager
                .try_acquire()
                .ok_or_else(|| anyhow::anyhow!("dot connection limit exceeded"))?;

            let target = {
                let mut guard = self.target.lock().await;
                if guard.is_none() {
                    *guard = Some(parse_dot_target(&self.upstream)?);
                }
                guard
                    .as_ref()
                    .context("dot target missing after initialization")?
                    .clone()
            };

            let stream = TcpStream::connect(&*target.connect_addr)
                .await
                .map_err(|e| anyhow::anyhow!("dot connect failed: {}", e))?;

            let _ = stream.set_nodelay(true);
            let sock = SockRef::from(&stream);
            let mut ka = TcpKeepalive::new();
            ka = ka.with_time(Duration::from_secs(5));
            ka = ka.with_interval(Duration::from_secs(2));
            let _ = sock.set_keepalive(true);
            let _ = sock.set_tcp_keepalive(&ka);

            let tls_connector = TlsConnector::from(self.tls_config.clone());
            let server_name = build_server_name(&target.sni)?;
            let tls_stream = tls_connector
                .connect(server_name, stream)
                .await
                .context("dot tls handshake failed")?;

            let (read_half, write_half) = tokio::io::split(tls_stream);
            *guard = Some(write_half);

            let new_gen = self.generation.fetch_add(1, Ordering::Relaxed) + 1;

            // Create fresh cancellation token for this connection lifecycle
            // 为此连接生命周期创建新的取消令牌
            let new_token = CancellationToken::new();

            self.spawn_reader(
                read_half,
                new_token.clone(),
                new_gen,
                self.generation.clone(),
            )
            .await;

            // Store token AFTER spawn so reset() can only cancel a live reader
            // 在 spawn 之后存储 token，确保 reset() 只能取消已启动的 reader
            {
                let mut token_guard = self.read_cancel.lock().await;
                *token_guard = new_token;
            }

            let mut conn_permit_guard = self.conn_permit.lock().await;
            *conn_permit_guard = Some(permit);

            let now = unix_time_millis();
            self.conn_create_time.store(now, Ordering::Release);
            self.last_request_time.store(now, Ordering::Release);
            self.consecutive_errors.store(0, Ordering::Release);

            info!(upstream = %self.upstream, "DoT connection established");
        }

        Ok(())
    }

    async fn register_pending(
        &self,
        packet: &[u8],
        original_id: u16,
        tx: oneshot::Sender<anyhow::Result<Bytes>>,
    ) -> anyhow::Result<(BytesMut, u16)> {
        // Serialize registration with connection teardown so a failed reader cannot miss a waiter.
        // 将 pending 注册与连接清理串行化，避免失败的 reader 遗漏 waiter。
        let conn_guard = self.conn.lock().await;
        if conn_guard.is_none() {
            anyhow::bail!("connection closed before registration");
        }

        let mut tries = 0;
        let new_id = loop {
            let cand = self.next_id.fetch_add(1, Ordering::Relaxed);
            tries += 1;
            if let entry::Entry::Vacant(e) = self.pending.entry(cand) {
                e.insert(Pending { original_id, tx });
                break cand;
            }
            if tries > u16::MAX as usize {
                anyhow::bail!("no available dns ids for dot mux");
            }
        };
        drop(conn_guard);

        // Build complete DoT wire frame (2-byte length prefix + DNS message with rewritten ID).
        // Caller writes this directly without further copying — saves one memcpy per request.
        // 构建完整 DoT wire frame（2 字节长度前缀 + 改写 ID 后的 DNS 消息）。
        // 调用方直接写入此帧，无需二次拷贝——每请求省一次 memcpy。
        let mut frame = BytesMut::with_capacity(2 + packet.len());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(packet);
        let id_bytes = new_id.to_be_bytes();
        frame[2] = id_bytes[0]; // TXID at offset 2 (after length prefix) / 偏移 2 处（长度前缀之后）
        frame[3] = id_bytes[1];
        Ok((frame, new_id))
    }

    async fn fail_all_async(
        pending: &Arc<dashmap::DashMap<u16, Pending, FxBuildHasher>>,
        err: anyhow::Error,
        conn: &Arc<Mutex<Option<DotWriteHalf>>>,
        conn_permit: &Arc<Mutex<Option<PermitGuard>>>,
    ) {
        let err_msg = err.to_string();
        // Hold the connection lock while resetting and draining. register_pending uses the same
        // lock, so it either registers before this drain or observes the closed connection.
        let mut conn_guard = conn.lock().await;
        *conn_guard = None;
        let keys: Vec<u16> = pending.iter().map(|item| *item.key()).collect();
        for key in keys {
            if let Some((_, p)) = pending.remove(&key) {
                let _ = p.tx.send(Err(anyhow::anyhow!(err_msg.clone())));
            }
        }
        let mut permit_guard = conn_permit.lock().await;
        *permit_guard = None;
    }

    /// Reset connection: cancel reader task, then drop write half and release permit
    /// 重置连接：取消 reader 任务，然后丢弃写半部并释放许可
    ///
    /// The cancellation token interrupts the reader's blocked read so it
    /// exits immediately instead of leaking the TLS connection.
    /// 取消令牌中断 reader 阻塞的读取操作，使其立即退出而非泄漏 TLS 连接。
    async fn reset(&self) {
        self.read_cancel.lock().await.cancel();
        Self::reset_conn(&self.conn, &self.conn_permit).await;
    }

    async fn reset_conn(
        conn: &Arc<Mutex<Option<DotWriteHalf>>>,
        conn_permit: &Arc<Mutex<Option<PermitGuard>>>,
    ) {
        let mut cg = conn.lock().await;
        *cg = None;
        let mut permit_guard = conn_permit.lock().await;
        *permit_guard = None;
    }
}

fn build_tls_client_config() -> anyhow::Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Ok(config)
}

fn build_server_name(name: &str) -> anyhow::Result<ServerName<'static>> {
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        let ip = rustls::pki_types::IpAddr::from(ip);
        Ok(ServerName::IpAddress(ip))
    } else {
        ServerName::try_from(name.to_string()).context("invalid tls server name")
    }
}

fn parse_dot_target(upstream: &str) -> anyhow::Result<DotTarget> {
    let url = if upstream.contains("://") {
        Url::parse(upstream)
    } else {
        Url::parse(&format!("dot://{}", upstream))
    }
    .context("invalid dot upstream url")?;

    let host = url.host_str().context("dot upstream missing host")?;
    let port = url.port().unwrap_or(853);

    if !url.path().is_empty() && url.path() != "/" {
        anyhow::bail!("dot upstream should not contain path");
    }

    let mut sni: Option<String> = None;
    if url.query().is_some() {
        for (k, v) in url.query_pairs() {
            if (k.eq_ignore_ascii_case("sni") || k.eq_ignore_ascii_case("servername"))
                && !v.is_empty()
            {
                sni = Some(v.to_string());
            }
        }
    }

    let connect_addr = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };

    let sni_value = sni.unwrap_or_else(|| host.to_string());

    Ok(DotTarget {
        connect_addr: Arc::from(connect_addr.as_str()),
        sni: Arc::from(sni_value.as_str()),
    })
}

// ===================== DoQ (DNS over QUIC) =====================

const MAX_DNS_MESSAGE_SIZE: usize = 65_535;

#[derive(Clone)]
struct DoqTarget {
    host: Arc<str>,
    port: u16,
    sni: Arc<str>,
    /// Enable 0-RTT for this specific upstream (overrides global setting)
    /// 为此特定上游启用 0-RTT（覆盖全局设置）
    /// None = use global setting, Some(true) = force enable, Some(false) = force disable
    /// None = 使用全局设置，Some(true) = 强制启用，Some(false) = 强制禁用
    enable_0rtt: Option<bool>,
}

struct DoqRuntime {
    endpoint_v4: QuicEndpoint,
    endpoint_v6: QuicEndpoint,
    enable_0rtt: bool,
}

struct DoqConnectionInfo {
    conn: QuicConnection,
    used_0rtt: bool,
}

/// DoQ (DNS over QUIC) 连接池
/// DoQ (DNS over QUIC) connection pool
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub struct DoqConnectionPool {
    clients: Vec<Arc<DoqMuxClient>>,
    next_idx: AtomicUsize,
}

/// DoQ (DNS over QUIC) 客户端，管理多个上游的 QUIC 连接池
/// DoQ (DNS over QUIC) client, managing QUIC connection pools for multiple upstreams
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub struct DoqClient {
    pools: DashMap<Arc<str>, Arc<DoqConnectionPool>, FxBuildHasher>,
    pool_size: usize,
    runtime: Arc<DoqRuntime>,
}

/// DoQ (DNS over QUIC) 多路复用客户端，管理单个上游的 QUIC 连接
/// DoQ (DNS over QUIC) multiplexing client, managing QUIC connection for a single upstream
///
/// 参考 RFC 9250 (DNS over Dedicated QUIC Connections) 实现
/// Implements RFC 9250 (DNS over Dedicated QUIC Connections)
pub struct DoqMuxClient {
    upstream: Arc<str>,
    target: Mutex<Option<DoqTarget>>,
    connection: Mutex<Option<QuicConnection>>,
    runtime: Arc<DoqRuntime>,
    /// Track whether 0-RTT has been rejected by the server for auto-fallback
    /// 跟踪服务器是否拒绝了 0-RTT，用于自动回退
    /// Once rejected, 0-RTT will be skipped for subsequent connections
    /// 一旦被拒绝，后续连接将跳过 0-RTT
    zero_rtt_rejected: std::sync::atomic::AtomicBool,
    /// 健康检查：连续错误计数 / Health check: consecutive error count
    consecutive_errors: AtomicUsize,
    /// 健康检查：错误阈值 / Health check: error threshold
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

impl DoqClient {
    pub fn new(
        pool_size: usize,
        idle_timeout_secs: u64,
        keepalive_interval_ms: u64,
        enable_0rtt: bool,
    ) -> anyhow::Result<Self> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(TLS_SERVER_ROOTS.iter().cloned());
        let mut tls = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"doq".to_vec()];
        tls.enable_early_data = enable_0rtt;

        // Security warning: 0-RTT (early data) is vulnerable to replay attacks
        // per RFC 8446 §8 and RFC 9001 §5.4. DNS queries are idempotent, so
        // replay impact is limited to redundant lookups and potential cache
        // timing side-channels. Only enable 0-RTT in trusted network environments.
        // 安全警告：0-RTT（早期数据）容易受到重放攻击（RFC 8446 §8, RFC 9001 §5.4）。
        // DNS 查询是幂等的，因此重放影响仅限于冗余查询和潜在的缓存时序侧信道。
        // 仅在可信网络环境中启用 0-RTT。
        if enable_0rtt {
            tracing::warn!(
                "DoQ 0-RTT enabled: vulnerable to replay attacks (RFC 8446 §8). \
                 DNS queries are idempotent but an attacker can observe timing patterns. \
                 Disable 0-RTT in untrusted environments."
            );
        }

        let quic_crypto = QuicClientConfig::try_from(tls).context("build quic client config")?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let mut transport_config = QuicTransportConfig::default();

        // Set initial RTT to 100ms (idoq best practice)
        // This helps QUIC estimate initial round-trip time for better congestion control
        // 设置初始 RTT 为 100ms（idoq 最佳实践）
        // 这有助于 QUIC 估算初始往返时间，以实现更好的拥塞控制
        transport_config.initial_rtt(Duration::from_millis(100));

        // Set max concurrent streams (idoq best practice)
        // 设置最大并发流数（idoq 最佳实践）
        transport_config.max_concurrent_bidi_streams(100u32.into());
        transport_config.max_concurrent_uni_streams(100u32.into());

        if keepalive_interval_ms > 0 {
            transport_config
                .keep_alive_interval(Some(Duration::from_millis(keepalive_interval_ms)));
        }
        if idle_timeout_secs > 0 {
            let idle_timeout = Duration::from_secs(idle_timeout_secs)
                .try_into()
                .context("invalid doq idle timeout")?;
            transport_config.max_idle_timeout(Some(idle_timeout));
        }
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint_v4 = QuicEndpoint::client("0.0.0.0:0".parse()?)?;
        endpoint_v4.set_default_client_config(client_config.clone());

        let endpoint_v6 = match QuicEndpoint::client("[::]:0".parse()?) {
            Ok(mut ep) => {
                ep.set_default_client_config(client_config);
                ep
            }
            Err(e) => {
                warn!(error = %e, "Failed to bind IPv6 QUIC endpoint, falling back to IPv4 only");
                endpoint_v4.clone()
            }
        };

        let runtime = Arc::new(DoqRuntime {
            endpoint_v4,
            endpoint_v6,
            enable_0rtt,
        });

        Ok(Self {
            pools: DashMap::with_hasher(FxBuildHasher),
            pool_size: if pool_size == 0 { 1 } else { pool_size },
            runtime,
        })
    }

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
                for _ in 0..self.pool_size {
                    clients.push(Arc::new(DoqMuxClient::new(
                        upstream_key.clone(),
                        Arc::clone(&self.runtime),
                    )));
                }
                Arc::new(DoqConnectionPool {
                    clients,
                    next_idx: AtomicUsize::new(0),
                })
            })
            .clone();

        let idx = pool.next_idx.fetch_add(1, Ordering::Relaxed) % pool.clients.len();
        pool.clients[idx].send(packet, timeout_dur).await
    }
}

impl DoqMuxClient {
    fn new(upstream: Arc<str>, runtime: Arc<DoqRuntime>) -> Self {
        Self {
            upstream,
            target: Mutex::new(None),
            connection: Mutex::new(None),
            runtime,
            zero_rtt_rejected: std::sync::atomic::AtomicBool::new(false),
            consecutive_errors: AtomicUsize::new(0),
            health_threshold: AtomicUsize::new(3),
            conn_create_time: AtomicU64::new(0),
            max_age_ms: AtomicU64::new(30 * 60 * 1000), // 30 minutes default
            last_request_time: AtomicU64::new(0),
            idle_timeout_ms: AtomicU64::new(5 * 60 * 1000), // 5 minutes default
            last_health_check_time: AtomicU64::new(0),
        }
    }

    /// Record an error and check if connection should be reset
    /// 记录错误并检查是否需要重置连接
    async fn record_error(&self) -> bool {
        let errors = self.consecutive_errors.fetch_add(1, Ordering::Release) + 1;
        let threshold = self.health_threshold.load(Ordering::Acquire);
        if errors >= threshold {
            warn!(
                upstream = %self.upstream,
                consecutive_errors = errors,
                threshold = threshold,
                "DoQ connection error threshold exceeded, resetting connection"
            );
            self.reset_connection().await;
            self.consecutive_errors.store(0, Ordering::Release);
            true
        } else {
            false
        }
    }

    /// Record success and clear error counter
    /// 记录成功并清零错误计数
    fn record_success(&self) {
        self.consecutive_errors.store(0, Ordering::Release);
        let now = unix_time_millis();
        self.last_request_time.store(now, Ordering::Release);
    }

    /// Check if connection needs reset due to aging or idle timeout
    /// 检查连接是否需要重置（老化或空闲超时）
    async fn check_connection_health(&self) -> bool {
        let now = unix_time_millis();

        // Throttle health checks: only check once per second
        let last_check = self.last_health_check_time.load(Ordering::Acquire);
        if now.saturating_sub(last_check) < 1000 {
            return false;
        }
        self.last_health_check_time.store(now, Ordering::Release);

        // Check connection aging
        let create_time = self.conn_create_time.load(Ordering::Acquire);
        let max_age = self.max_age_ms.load(Ordering::Acquire);
        if create_time > 0 && max_age > 0 {
            let age_ms = now.saturating_sub(create_time);
            if age_ms > max_age {
                info!(
                    upstream = %self.upstream,
                    age_ms = age_ms,
                    max_age_ms = max_age,
                    "DoQ connection too old, resetting"
                );
                self.reset_connection().await;
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        // Check idle timeout
        let last_req = self.last_request_time.load(Ordering::Acquire);
        let idle_timeout = self.idle_timeout_ms.load(Ordering::Acquire);
        if last_req > 0 && idle_timeout > 0 {
            let idle_ms = now.saturating_sub(last_req);
            if idle_ms > idle_timeout {
                info!(
                    upstream = %self.upstream,
                    idle_ms = idle_ms,
                    idle_timeout_ms = idle_timeout,
                    "DoQ connection idle too long, resetting"
                );
                self.reset_connection().await;
                self.consecutive_errors.store(0, Ordering::Release);
                return true;
            }
        }

        false
    }

    pub async fn send(&self, packet: &[u8], timeout_dur: Duration) -> anyhow::Result<Bytes> {
        let target = {
            let mut guard = self.target.lock().await;
            if guard.is_none() {
                *guard = Some(parse_doq_target(&self.upstream)?);
            }
            guard
                .as_ref()
                .context("doq target missing after initialization")?
                .clone()
        };

        if target.host.is_empty() {
            anyhow::bail!("invalid doq upstream: {}", self.upstream);
        }

        self.send_with_retry(&target, packet, timeout_dur, true)
            .await
    }

    async fn send_with_retry(
        &self,
        target: &DoqTarget,
        packet: &[u8],
        timeout_dur: Duration,
        allow_retry: bool,
    ) -> anyhow::Result<Bytes> {
        // RFC 9250 §4.2.1: DNS Message ID over DoQ MUST be set to 0.
        // We preserve original ID for local correlation and restore it in the final response.
        // RFC 9250 §4.2.1：DoQ 上的 DNS Message ID 必须为 0。
        // 我们保留原始 ID 用于本地关联，并在最终响应中恢复。
        if packet.len() < 2 {
            anyhow::bail!("dns packet too short for doq");
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        let mut allow_retry = allow_retry;
        let mut timeout_dur = timeout_dur;

        loop {
            // Check connection health (aging, idle timeout) before each attempt
            // 每次尝试前检查连接健康状态（老化、空闲超时）
            self.check_connection_health().await;

            let start = tokio::time::Instant::now();
            let info = self.get_or_connect(target, timeout_dur).await?;
            let conn = info.conn;
            let used_0rtt = info.used_0rtt;

            // RFC 9250 §4.2: DNS messages sent over QUIC streams MUST be prefixed
            // with a 2-octet length field, followed by the DNS message content.
            // Each query uses a separate bidirectional stream; the message boundary
            // is signalled by FIN.
            // RFC 9250 §4.2: QUIC 流上的 DNS 消息必须使用 2 字节长度前缀，
            // 后跟 DNS 消息内容。每个查询使用单独的双向流；消息边界由 FIN 信号标识。
            let resp = timeout(timeout_dur, async {
                let (mut send, mut recv) = conn.open_bi().await
                    .context("doq open stream failed")?;

                // RFC 9250 §4.2: DNS messages sent over QUIC streams MUST be prefixed
                // with a 2-octet length field, followed by the DNS message content.
                // Each query uses a separate bidirectional stream; the message boundary
                // is signalled by FIN.
                // RFC 9250 §4.2: QUIC 流上的 DNS 消息必须使用 2 字节长度前缀，
                // 后跟 DNS 消息内容。每个查询使用单独的双向流；消息边界由 FIN 信号标识。
                //
                // RFC 9250 §4.2.1: DNS Message ID MUST be 0 over DoQ.
                // Build complete wire frame in one allocation, no intermediate copy.
                // RFC 9250 §4.2.1: DoQ 上 DNS Message ID 必须为 0。
                // 单次分配构建完整 wire frame，无中间拷贝。
                let mut frame = Vec::with_capacity(2 + packet.len());
                frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
                frame.extend_from_slice(packet);
                frame[2] = 0; // Message ID = 0 (RFC 9250 §4.2.1) / 消息 ID = 0
                frame[3] = 0;

                send.write_all(&frame).await.context("doq send query failed")?;
                let _ = send.finish();

                // Read response: 2-byte length prefix followed by DNS message
                // 读取响应：2 字节长度前缀，后跟 DNS 消息
                // Note: The server sends the response and closes the stream with FIN
                // We need to read all data until FIN, then parse the length prefix
                // 注意：服务器发送响应后用 FIN 关闭流
                // 我们需要读取所有数据直到 FIN，然后解析长度前缀
                let mut all_data = match recv.read_to_end(MAX_DNS_MESSAGE_SIZE + 2).await {
                    Ok(data) => data,
                    Err(e) => {
                        // Check if this is a connection closed error
                        // 检查是否是连接关闭错误
                        if e.to_string().contains("closed by peer") || e.to_string().contains("connection lost") {
                            anyhow::bail!("doq connection closed by server (possible protocol error or server does not support DoQ)");
                        }
                        return Err(e).context("doq read response failed");
                    }
                };

                if all_data.is_empty() {
                    anyhow::bail!("doq received empty response (server closed stream without sending data)");
                }

                if all_data.len() < 2 {
                    anyhow::bail!("doq response too short: {} bytes", all_data.len());
                }

                let msg_len = u16::from_be_bytes([all_data[0], all_data[1]]) as usize;

                // idoq-style length validation: response length must match length prefix
                // idoq 风格的长度验证：响应长度必须匹配长度前缀
                if all_data.len() != 2 + msg_len {
                    anyhow::bail!(
                        "doq length mismatch: expected {} bytes (2 + {}), got {} bytes. \
                        This may indicate data corruption or server protocol violation.",
                        2 + msg_len, msg_len, all_data.len()
                    );
                }

                let buf = &all_data[2..2 + msg_len];
                if buf.len() < 2 {
                    // DNS message must be at least 2 bytes for TXID restoration.
                    // Also prevents all_data[2..4] index out of bounds when msg_len < 2.
                    // DNS 消息必须至少 2 字节才能恢复 TXID。
                    // 同时防止 msg_len < 2 时 all_data[2..4] 越界。
                    anyhow::bail!("doq DNS message too short: {} bytes", msg_len);
                }
                // Restore original DNS Message ID in-place (Vec<u8> is mutable).
                // Bytes::from(Vec) takes ownership of the heap allocation (zero-copy).
                // slice(2..) returns a view past the length prefix (zero-copy, shares allocation).
                // 原地恢复原始 DNS Message ID（Vec<u8> 可变）。
                // Bytes::from(Vec) 接管堆分配（零拷贝）。
                // slice(2..) 返回跳过长度前缀的视图（零拷贝，共享分配）。
                all_data[2..4].copy_from_slice(&original_id.to_be_bytes());
                Ok(Bytes::from(all_data).slice(2..))
            }).await;

            match resp {
                Ok(Ok(bytes)) => {
                    self.record_success();
                    return Ok(bytes);
                }
                Ok(Err(err)) => {
                    let err_str = err.to_string();
                    let already_reset = self.record_error().await;
                    if !already_reset {
                        // Only reset if record_error() didn't already reset (below threshold)
                        self.reset_connection().await;
                    }
                    if allow_retry && used_0rtt && self.should_retry_without_0rtt(target, &err_str)
                    {
                        self.disable_zero_rtt();
                        let remaining = timeout_dur.saturating_sub(start.elapsed());
                        if remaining.is_zero() {
                            return Err(err);
                        }
                        warn!(
                            upstream = %self.upstream,
                            error = %err,
                            "DoQ 0-RTT likely rejected (connection closed/stream error), retrying without 0-RTT"
                        );
                        allow_retry = false;
                        timeout_dur = remaining;
                        continue;
                    }
                    return Err(err);
                }
                Err(_) => {
                    if allow_retry && used_0rtt {
                        self.disable_zero_rtt();
                        let remaining = timeout_dur.saturating_sub(start.elapsed());
                        if remaining.is_zero() {
                            self.reset_connection().await;
                            return Err(anyhow::anyhow!("doq timeout"));
                        }
                        warn!(
                            upstream = %self.upstream,
                            "DoQ 0-RTT timeout detected, retrying without 0-RTT"
                        );
                        self.reset_connection().await;
                        allow_retry = false;
                        timeout_dur = remaining;
                        continue;
                    }

                    // Timeout occurred - check if this was a 0-RTT connection
                    // 超时发生 - 检查是否是 0-RTT 连接
                    let was_rejected = self
                        .zero_rtt_rejected
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if !was_rejected {
                        // Mark 0-RTT as rejected for this upstream (cached until restart)
                        // 标记此上游的 0-RTT 为被拒绝（缓存直到重启）
                        self.zero_rtt_rejected
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                        warn!(
                            upstream = %self.upstream,
                            "DoQ 0-RTT timeout detected, automatically disabling 0-RTT for this upstream. \
                            Future connections will use normal handshake. This status is cached until restart. \
                            To re-enable 0-RTT, restart the server or use ?0rtt=true in the upstream URL."
                        );
                    }
                    let already_reset = self.record_error().await;
                    if !already_reset {
                        self.reset_connection().await;
                    }
                    return Err(anyhow::anyhow!("doq timeout"));
                }
            }
        }
    }

    fn should_retry_without_0rtt(&self, target: &DoqTarget, err: &str) -> bool {
        let enable_0rtt = target.enable_0rtt.unwrap_or(self.runtime.enable_0rtt);
        if !enable_0rtt {
            return false;
        }
        if self
            .zero_rtt_rejected
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        err.contains("doq connection closed by server")
            || err.contains("closed by peer")
            || err.contains("connection lost")
            || err.contains("stream reset")
            || err.contains("ConnectionClosed")
            || err.contains("reset by peer")
    }

    fn disable_zero_rtt(&self) {
        let was_rejected = self
            .zero_rtt_rejected
            .load(std::sync::atomic::Ordering::Relaxed);
        if !was_rejected {
            self.zero_rtt_rejected
                .store(true, std::sync::atomic::Ordering::Relaxed);
            warn!(
                upstream = %self.upstream,
                "DoQ 0-RTT rejected or unstable, disabling 0-RTT for this upstream until restart"
            );
        }
    }
    async fn get_or_connect(
        &self,
        target: &DoqTarget,
        timeout_dur: Duration,
    ) -> anyhow::Result<DoqConnectionInfo> {
        // Single-lock pattern: acquire lock once, check + create in one critical section.
        // This prevents the TOCTOU race where two coroutines both pass the first check,
        // then both create connections, wasting one.
        // 单锁模式：一次获取锁，检查+创建在一个临界区内完成。
        // 防止两个协程同时通过第一次检查后都创建连接、浪费一个的竞态。
        let mut guard = self.connection.lock().await;
        if let Some(conn) = guard.as_ref() {
            return Ok(DoqConnectionInfo {
                conn: conn.clone(),
                used_0rtt: false,
            });
        }

        let (conn, used_0rtt) = self.connect_new(target, timeout_dur).await?;
        *guard = Some(conn.clone());

        // Record connection creation time for aging checks
        // 记录连接创建时间用于老化检查
        let now = unix_time_millis();
        self.conn_create_time.store(now, Ordering::Release);
        self.last_request_time.store(now, Ordering::Release);

        Ok(DoqConnectionInfo { conn, used_0rtt })
    }

    async fn connect_new(
        &self,
        target: &DoqTarget,
        timeout_dur: Duration,
    ) -> anyhow::Result<(QuicConnection, bool)> {
        let addr_str = format!("{}:{}", target.host, target.port);
        let addrs = tokio::net::lookup_host(&addr_str)
            .await
            .context("doq resolve failed")?;

        // 优先使用 IPv4 地址，避免 IPv6 连接问题
        // Prefer IPv4 addresses to avoid IPv6 connection issues
        // 某些网络的 IPv6 连接不稳定或 MTU 限制导致 QUIC Initial 数据包发送失败
        // Some networks have unstable IPv6 or MTU limits causing QUIC Initial packet send failures
        let addrs_vec: Vec<_> = addrs.collect();
        let addr = addrs_vec
            .iter()
            .find(|a| a.is_ipv4())
            .or_else(|| addrs_vec.first())
            .context("doq resolve returned no addresses")?;

        let addr = *addr;

        let endpoint = if addr.is_ipv6() {
            &self.runtime.endpoint_v6
        } else {
            &self.runtime.endpoint_v4
        };
        let connecting = endpoint
            .connect(addr, target.sni.as_ref())
            .context("doq connect failed")?;

        // Determine whether to enable 0-RTT for this specific upstream
        // 决定是否为此特定上游启用 0-RTT
        // Priority: target setting > global setting
        // 优先级：上游设置 > 全局设置
        let enable_0rtt = target.enable_0rtt.unwrap_or(self.runtime.enable_0rtt);

        // Auto-fallback: if 0-RTT was previously rejected, skip it for this connection
        // 自动回退：如果 0-RTT 之前被拒绝，跳过本次连接的 0-RTT
        let was_rejected = self
            .zero_rtt_rejected
            .load(std::sync::atomic::Ordering::Relaxed);
        let should_try_0rtt = enable_0rtt && !was_rejected;

        if should_try_0rtt {
            match connecting.into_0rtt() {
                Ok((conn, _zero_rtt_accepted)) => {
                    // 0-RTT connection established
                    // Note: Some DoQ servers (e.g., Alibaba DNS) may reject 0-RTT data
                    // If you see timeouts, the system will automatically disable 0-RTT for this upstream
                    // 0-RTT 连接已建立
                    // 注意：某些 DoQ 服务器（如阿里 DNS）可能拒绝 0-RTT 数据
                    // 如果遇到超时，系统将自动为此上游禁用 0-RTT
                    debug!(
                        upstream = %self.upstream,
                        "DoQ 0-RTT connection established"
                    );
                    return Ok((conn, true));
                }
                Err(connecting) => {
                    // 0-RTT not available (no previous session), fall back to normal connect
                    // 0-RTT 不可用（无先前会话），回退到正常连接
                    let connection = timeout(timeout_dur, connecting)
                        .await
                        .context("doq connect timeout")??;
                    return Ok((connection, false));
                }
            }
        }

        let connection = timeout(timeout_dur, connecting)
            .await
            .context("doq connect timeout")??;

        Ok((connection, false))
    }

    async fn reset_connection(&self) {
        let mut guard = self.connection.lock().await;
        *guard = None;
        // Reset connection creation time so aging checks start fresh on reconnect
        self.conn_create_time.store(0, Ordering::Release);
    }
}

fn parse_doq_target(upstream: &str) -> anyhow::Result<DoqTarget> {
    let url = if upstream.contains("://") {
        Url::parse(upstream)
    } else {
        Url::parse(&format!("doq://{}", upstream))
    }
    .context("invalid doq upstream url")?;

    let host = url.host_str().context("doq upstream missing host")?;
    let port = url.port().unwrap_or(853);

    if !url.path().is_empty() && url.path() != "/" {
        anyhow::bail!("doq upstream should not contain path");
    }

    let mut sni: Option<String> = None;
    let mut enable_0rtt: Option<bool> = None;
    if url.query().is_some() {
        for (k, v) in url.query_pairs() {
            if k.eq_ignore_ascii_case("sni") || k.eq_ignore_ascii_case("servername") {
                if !v.is_empty() {
                    sni = Some(v.to_string());
                }
            } else if k.eq_ignore_ascii_case("0rtt") || k.eq_ignore_ascii_case("enable_0rtt") {
                // Parse 0rtt parameter: true/false/1/0
                // 解析 0rtt 参数：true/false/1/0
                enable_0rtt = match v.to_lowercase().as_str() {
                    "true" | "1" | "yes" | "on" => Some(true),
                    "false" | "0" | "no" | "off" => Some(false),
                    _ => {
                        warn!("invalid doq 0rtt value: {}, ignoring", v);
                        None
                    }
                };
            }
        }
    }

    let is_ip = host.parse::<std::net::IpAddr>().is_ok();
    if sni.is_none() && is_ip {
        anyhow::bail!(
            "doq upstream with IP address requires explicit sni (e.g. doq://223.5.5.5:853?sni=alidns.com)"
        );
    }

    let sni_value = sni.unwrap_or_else(|| host.to_string());

    Ok(DoqTarget {
        host: Arc::from(host),
        port,
        sni: Arc::from(sni_value.as_str()),
        enable_0rtt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;
    use std::time::Duration;
    use tokio::time::timeout;

    async fn connected_tcp_write_half() -> (OwnedWriteHalf, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TCP test listener");
        let addr = listener.local_addr().expect("read TCP test address");
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client = client.expect("connect TCP test client");
        let (server, _) = server.expect("accept TCP test client");
        let (_, write_half) = client.into_split();
        (write_half, server)
    }

    #[test]
    fn doq_query_message_id_must_be_zero() {
        // Verify RFC 9250 §4.2.1: DoQ DNS Message ID MUST be set to 0.
        // The inline frame construction logic (from send_with_retry) zeroes bytes [2..4].
        // 验证 RFC 9250 §4.2.1: DoQ DNS Message ID 必须为 0。
        // 内联帧构建逻辑（来自 send_with_retry）将字节 [2..4] 置零。
        let packet = [0x12, 0x34, 0x01, 0x00, 0xaa, 0xbb];
        let mut frame = Vec::with_capacity(2 + packet.len());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(&packet);
        frame[2] = 0;
        frame[3] = 0;

        assert_eq!(frame.len(), 2 + packet.len());
        assert_eq!(&frame[0..2], &(packet.len() as u16).to_be_bytes());
        assert_eq!(&frame[2..4], &[0x00, 0x00]);
        assert_eq!(&frame[4..], &packet[2..]);
    }

    #[test]
    fn doq_response_restores_original_message_id() {
        // Verify zero-copy response ID restoration (from send_with_retry):
        // all_data layout: [2 bytes length prefix][DNS message with ID=0]
        // After restoration: ID at offset 2 is replaced with original_id, then slice(2..).
        // 验证零拷贝响应 ID 恢复（来自 send_with_retry）：
        // all_data 布局: [2 字节长度前缀][ID=0 的 DNS 消息]
        // 恢复后: 偏移 2 处的 ID 替换为 original_id，然后 slice(2..)。
        let mut all_data: Vec<u8> = vec![0x00, 0x04, 0x00, 0x00, 0x81, 0x80]; // [len=4][ID=0][flags]
        let original_id: u16 = 0x1234;
        all_data[2..4].copy_from_slice(&original_id.to_be_bytes());
        let restored = bytes::Bytes::from(all_data).slice(2..);

        assert_eq!(&restored[0..2], &[0x12, 0x34]);
        assert_eq!(&restored[2..], &[0x81, 0x80]);
    }

    #[test]
    fn doq_response_short_message_does_not_panic() {
        // Regression test: msg_len < 2 must bail! instead of panicking on all_data[2..4].
        // 回归测试: msg_len < 2 时必须 bail! 而非 all_data[2..4] 越界 panic。
        // all_data layout: [len=1][0xAB] — total 3 bytes, msg_len=1
        let all_data: Vec<u8> = vec![0x00, 0x01, 0xAB];
        let msg_len = u16::from_be_bytes([all_data[0], all_data[1]]) as usize;
        let buf = &all_data[2..2 + msg_len];
        // This is the guard added to prevent panic:
        // 这是为防止 panic 而添加的保护：
        assert!(
            buf.len() < 2,
            "msg_len < 2 should trigger bail, not proceed to copy_from_slice"
        );
    }

    #[test]
    fn doq_target_requires_sni_for_ip() {
        assert!(parse_doq_target("doq://223.5.5.5:853").is_err());
        assert!(parse_doq_target("doq://223.5.5.5:853?sni=alidns.com").is_ok());
        assert!(parse_doq_target("doq://dns.alidns.com:853").is_ok());
    }

    #[test]
    fn doh_record_error_rebuilds_pool_at_threshold() {
        // Verify the core self-healing contract: consecutive transport errors below
        // the threshold accumulate without rebuilding; reaching it rebuilds the pool
        // (a fresh reqwest::Client is the only way to evict dead/half-open connections
        // that reqwest cannot detect on its own).
        // 验证核心自愈契约：连续传输错误在阈值前累积不重建；
        // 达阈值时重建连接池（新 reqwest::Client 是清除 reqwest 自身无法检测的
        // 死/半开连接的唯一手段）。
        let client = DohClient::new(8, 3).expect("build doh client");
        let upstream = "doh:8.8.8.8";

        let ptr_before = Arc::as_ptr(&client.client.load_full()) as usize;
        // Two errors stay below the threshold (3): no rebuild.
        assert!(!client.record_error(upstream), "no rebuild before threshold (1/3)");
        assert!(!client.record_error(upstream), "no rebuild before threshold (2/3)");
        assert_eq!(
            Arc::as_ptr(&client.client.load_full()) as usize,
            ptr_before,
            "client pointer must be unchanged below threshold"
        );
        // Third error reaches the threshold: pool rebuilt.
        assert!(client.record_error(upstream), "rebuild at threshold (3/3)");
        assert_ne!(
            Arc::as_ptr(&client.client.load_full()) as usize,
            ptr_before,
            "client pointer must change after rebuild"
        );
    }

    #[test]
    fn doh_record_success_resets_counter() {
        // record_success clears the per-upstream counter so a transient blip does
        // not accumulate toward a rebuild across an intervening healthy request.
        // record_success 清零 per-upstream 计数，避免偶发错误跨健康请求累积到重建。
        let client = DohClient::new(8, 3).expect("build doh client");
        let upstream = "doh:1.1.1.1";

        client.record_error(upstream);
        client.record_error(upstream);
        client.record_success(upstream); // reset to 0
        // Counter restarted: need 3 more to rebuild, not just 1.
        assert!(!client.record_error(upstream), "counter reset: 1/3 after success");
        assert!(!client.record_error(upstream), "counter reset: 2/3 after success");
        assert!(client.record_error(upstream), "counter reset: rebuild at 3/3");
    }

    #[test]
    fn doh_error_counts_are_isolated_per_upstream() {
        // Mirrors mux clients' per-upstream consecutive_errors isolation: errors on
        // one upstream must not inflate another upstream's count.
        // 对齐 mux 的 per-upstream consecutive_errors 隔离：
        // 一个 upstream 的错误不得累加到另一个 upstream。
        let client = DohClient::new(8, 3).expect("build doh client");

        client.record_error("doh:8.8.8.8");
        client.record_error("doh:8.8.8.8");
        // A success on a *different* upstream must not touch 8.8.8.8's count.
        client.record_success("doh:1.1.1.1");
        // 8.8.8.8 still at 2 — the 3rd error rebuilds.
        assert!(
            client.record_error("doh:8.8.8.8"),
            "isolated counter reaches threshold independently"
        );
    }

    #[test]
    fn doh_is_transport_error_classifies_correctly() {
        // Only HTTP status errors are non-transport (connection is healthy, retry is
        // useless). Everything else (timeout / connect / IO) indicates a possibly
        // dead connection and is safe to retry once (DoH queries are idempotent).
        // 只有 HTTP 状态码错误是非传输的（连接健康，重试无益）。
        // 其余（超时/连接/IO）都指示连接可能已死，单次重试安全（DoH 查询语义幂等）。
        let timeout_err = anyhow::anyhow!("doh request timeout");
        assert!(is_transport_error(&timeout_err), "timeout is transport-level");

        // A reqwest-style error wrapped via .context() must still classify as
        // transport (downcast finds no DohHttpStatusError at the top of the chain).
        // 经 .context() 包装的 reqwest 风格错误仍须归类为传输错误
        // （downcast 在链顶找不到 DohHttpStatusError）。
        let send_err = anyhow::anyhow!("doh request send failed").context("wrapped");
        assert!(is_transport_error(&send_err), "wrapped send error is transport-level");

        let status_err = anyhow::Error::new(DohHttpStatusError(anyhow::anyhow!(
            "doh http status 503 Server Error"
        )));
        assert!(!is_transport_error(&status_err), "HTTP status is NOT transport-level");
    }

    #[tokio::test]
    async fn reqwest_client_drop_closes_pooled_connections() {
        // Empirical foundation of DohClient's pool-rebuild healing: dropping a
        // reqwest::Client closes the keep-alive connections held in its pool. If
        // this did not hold, rebuilding the client (store a fresh Arc<Client>)
        // could NOT evict dead/half-open connections and issue #41 would persist.
        // DohClient 连接池重建自愈的实证基础：drop reqwest::Client 会关闭其连接池中
        // 的 keep-alive 连接。若不成立，重建客户端（store 新 Arc<Client>）无法驱逐
        // 死/半开连接，issue #41 将无法解决。
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Minimal HTTP/1.1 keep-alive server: serve one request, then block reading
        // until the peer closes the connection.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("read test addr");

        let server_task = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 1024];
            let _ = sock.read(&mut buf).await; // read request
            let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
            sock.write_all(resp).await.expect("write response");
            // Block until peer closes; Ok(0) = clean EOF (connection closed by client).
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        });

        let url = format!("http://{addr}/");
        {
            // Long idle timeout so only an explicit Client drop can close the
            // connection within the test window (not the idle reaper).
            // 长 idle 超时，确保测试窗口内只有显式 drop Client 能关闭连接（而非 idle 回收）。
            let client = DohHttpClient::builder()
                .pool_idle_timeout(Duration::from_secs(60))
                .build()
                .expect("build client");
            let resp = client.get(&url).send().await.expect("send");
            assert!(resp.status().is_success());
            drop(resp.bytes().await.expect("read body")); // drain → connection returns to pool
            // client dropped at end of this block → pool torn down
        }

        // pool_idle_timeout is 60s; if the drop did not close the connection the
        // server would only observe EOF after ~60s. A 5s window therefore proves
        // the closure was caused by the drop.
        // pool_idle_timeout 为 60s；若 drop 未关闭连接，server 要等约 60s 才观察到 EOF。
        // 5s 窗口因此证明关闭由 drop 引起。
        let joined = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server did not observe close within 5s of drop; pool_idle_timeout=60s means only the drop could close it");
        let clean_eof = joined.expect("server task join");
        assert!(clean_eof, "server saw an error instead of clean EOF on Client drop");
    }

    #[tokio::test]
    async fn tcp_mux_rewrite_id_no_deadlock_under_contention() {
        // Arrange: Prepare a TCP client with many pending IDs to force contention
        let permit_manager = Arc::new(PermitManager::new(128)); // Default TCP limit
        let client = Arc::new(TcpMuxClient::new(Arc::from("127.0.0.1:0"), permit_manager));
        let (write_half, _server) = connected_tcp_write_half().await;
        *client.conn.lock().await = Some(write_half);
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
                    client
                        .register_pending(&dummy, 0, tx)
                        .await
                        .map(|(_, id)| id)
                }
            })
            .collect::<Vec<_>>();

        let results = timeout(Duration::from_millis(500), join_all(tasks))
            .await
            .expect("register_pending stalled under contention");

        // Assert: Verify all IDs are unique (no duplicates under contention)
        let mut ids = rustc_hash::FxHashSet::default();
        for r in results {
            let id = r.expect("register_pending failed");
            assert!(ids.insert(id), "duplicate id allocated under contention");
        }
    }

    #[tokio::test]
    async fn tcp_fail_all_cannot_miss_a_concurrent_registration() {
        let permit_manager = Arc::new(PermitManager::new(1));
        let client = Arc::new(TcpMuxClient::new(Arc::from("127.0.0.1:0"), permit_manager));
        let (write_half, _server) = connected_tcp_write_half().await;
        *client.conn.lock().await = Some(write_half);

        // Hold the connection lock so registration queues before fail_all. The old implementation
        // took its pending snapshot before this lock, then allowed the queued registration to land
        // after the snapshot. The waiter was never notified.
        let conn_guard = client.conn.lock().await;
        let register_client = Arc::clone(&client);
        let register = tokio::spawn(async move {
            let packet = [0u8; 4];
            let (tx, rx) = oneshot::channel();
            let result = register_client.register_pending(&packet, 0, tx).await;
            (result, rx)
        });
        tokio::task::yield_now().await;

        let pending = Arc::clone(&client.pending);
        let conn = Arc::clone(&client.conn);
        let conn_permit = Arc::clone(&client.conn_permit);
        let fail_all = tokio::spawn(async move {
            TcpMuxClient::fail_all_async(
                &pending,
                anyhow::anyhow!("reader failed"),
                &conn,
                &conn_permit,
            )
            .await;
        });
        tokio::task::yield_now().await;
        drop(conn_guard);

        let (registration, receiver) = register.await.expect("join registration task");
        registration.expect("registration should complete before teardown");
        fail_all.await.expect("join fail_all task");

        assert!(client.pending.is_empty());
        let result = timeout(Duration::from_millis(100), receiver)
            .await
            .expect("pending waiter was not notified")
            .expect("pending sender was dropped without a result");
        assert!(result.is_err(), "reader failure should reach the waiter");
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
        assert_eq!(
            permit_a.max_permits(),
            2,
            "Permit manager should match pool size for upstream A"
        );
        assert_eq!(
            permit_b.max_permits(),
            2,
            "Permit manager should match pool size for upstream B"
        );
    }
}
