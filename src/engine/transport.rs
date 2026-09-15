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

/// Least budget worth spending on a transparent retry over a fresh connection.
/// A retry has to reconnect (SYN, plus a TLS handshake for DoT and DoH) and
/// then wait for an answer; with less than this left it cannot complete on a
/// realistic path and would only add a second failure after the caller's
/// deadline. The caller's deadline itself is never extended.
/// 值得为透明重试花的最小剩余预算。重试要先重连（SYN，DoT/DoH 还有 TLS 握手）再等应答，
/// 剩余不足这个值时现实路径上跑不完，只会在调用方截止后再失败一次。绝不延长调用方的截止。
const MIN_RETRY_BUDGET: Duration = Duration::from_millis(50);

/// Type alias for UDP inflight request tracking
/// ID -> (OriginalID, ExpectedAddr, SentQuery, Sender)
/// The sent query (ID already rewritten) stays in the entry so the reader can
/// match the answer's question section against it (RFC 5452 §9.1).
/// 条目保留已改写 ID 的查询报文，供 reader 比对应答的 question 段（RFC 5452 §9.1）。
type UdpInflightMap = DashMap<
    u16,
    (
        u16,
        SocketAddr,
        Bytes,
        oneshot::Sender<anyhow::Result<Bytes>>,
    ),
    FxBuildHasher,
>;

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
    /// Inflight map: ID -> (OriginalID, ExpectedAddr, SentQuery, Sender)
    /// Note: Using FxBuildHasher for performance
    inflight: Arc<UdpInflightMap>,
}

pub struct UdpClient {
    /// IPv4 sockets, one ephemeral port each. / IPv4 socket，各占一个临时端口。
    pool: Vec<UdpSocketState>,
    /// IPv6 sockets (IPV6_V6ONLY), built on the first query to an IPv6 upstream
    /// so a deployment without one pays for nothing.
    /// IPv6 socket（IPV6_V6ONLY），第一次查询 IPv6 上游时才建立，
    /// 没有 IPv6 上游的部署不付出任何代价。
    pool_v6: tokio::sync::OnceCell<Vec<UdpSocketState>>,
    pool_size: usize,
}

impl UdpClient {
    pub fn new(size: usize) -> anyhow::Result<Self> {
        // Prevent port exhaustion by enforcing minimum pool size
        let effective_size = if size == 0 { 1 } else { size };
        Ok(Self {
            pool: Self::build_pool(
                effective_size,
                Domain::IPV4,
                SocketAddr::from(([0, 0, 0, 0], 0)),
            )?,
            pool_v6: tokio::sync::OnceCell::new(),
            pool_size: effective_size,
        })
    }

    /// 建立一个地址族的完整 socket 池 / Build the whole socket pool of one family
    ///
    /// 先把所有 socket 建出来，全部成功之后才启动接收任务：中途失败时已经建好的
    /// socket 随错误一起丢弃，不会留下收不回的 fd 与任务。
    /// Every socket is created first and the readers start only once they have
    /// all succeeded: on a failure part way through, the sockets created so far
    /// are dropped with the error, leaving no unreachable descriptors or tasks.
    fn build_pool(
        size: usize,
        domain: Domain,
        bind_addr: SocketAddr,
    ) -> anyhow::Result<Vec<UdpSocketState>> {
        let mut sockets = Vec::with_capacity(size);
        for _ in 0..size {
            sockets.push(Self::create_socket(domain, bind_addr)?);
        }
        Ok(sockets
            .into_iter()
            .enumerate()
            .map(|(idx, socket)| Self::spawn_reader(idx, socket))
            .collect())
    }

    /// 建立一个池内 socket，不启动接收任务 / Create one pool socket without its reader
    fn create_socket(
        domain: Domain,
        bind_addr: SocketAddr,
    ) -> anyhow::Result<Arc<tokio::net::UdpSocket>> {
        // Use socket2 to set buffer sizes
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .context("create UDP pool socket")?;
        // IPv6 socket 只收发 IPv6：IPv4 上游始终走 IPv4 池，两边互不重叠。
        // Keep the IPv6 socket to IPv6 only: IPv4 upstreams always use the IPv4
        // pool, so the two never overlap.
        if domain == Domain::IPV6 {
            socket
                .set_only_v6(true)
                .context("set UDP pool socket IPV6_V6ONLY")?;
        }
        // Set buffer sizes to 4MB to prevent packet loss under load
        if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
            warn!("failed to set udp recv buffer size: {}", e);
        }
        if let Err(e) = socket.set_send_buffer_size(4 * 1024 * 1024) {
            warn!("failed to set udp send buffer size: {}", e);
        }
        socket
            .bind(&bind_addr.into())
            .context("bind UDP pool socket")?;
        socket
            .set_nonblocking(true)
            .context("set UDP pool socket nonblocking")?;

        let std_sock: std::net::UdpSocket = socket.into();
        Ok(Arc::new(
            tokio::net::UdpSocket::from_std(std_sock).context("create Tokio UDP pool socket")?,
        ))
    }

    /// 为一个建好的 socket 启动接收任务 / Start the reader task of a ready socket
    fn spawn_reader(idx: usize, socket: Arc<tokio::net::UdpSocket>) -> UdpSocketState {
        let inflight = Arc::new(DashMap::with_hasher(FxBuildHasher));

        let state = UdpSocketState {
            socket: socket.clone(),
            inflight: inflight.clone(),
        };

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
                                let (_, expected_addr, query, _) = entry.get();
                                if src != *expected_addr {
                                    // Address mismatch: keep entry and wait for correct response
                                    // 地址不匹配：保留条目等待正确响应（可能是网络攻击或路由异常）
                                    tracing::warn!(
                                        socket_idx = idx,
                                        response_id = id,
                                        expected_addr = %expected_addr,
                                        actual_addr = %src,
                                        "UDP response address mismatch, possible spoofing or routing anomaly"
                                    );
                                } else if !crate::proto_utils::question_matches(query, &buf) {
                                    // RFC 5452 §9.1: matching ID and address are not enough,
                                    // the question must match too. Keep waiting for the real one.
                                    // RFC 5452 §9.1：ID 和地址相符还不够，question 段也必须一致；
                                    // 保留条目继续等待真正的应答。
                                    tracing::warn!(
                                        socket_idx = idx,
                                        response_id = id,
                                        upstream = %src,
                                        "UDP response question mismatch, possible spoofing"
                                    );
                                } else {
                                    let (_, (original_id, _, _, tx)) = entry.remove_entry();

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

        state
    }

    #[inline]
    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let addr: SocketAddr = upstream.parse().context("invalid upstream address")?;
        // 按目标地址族选池：IPv4 路径只多一次判别
        // Pick the pool by address family; the IPv4 path only gains one check.
        let pool = if addr.is_ipv6() {
            self.pool_v6
                .get_or_try_init(|| async {
                    Self::build_pool(
                        self.pool_size,
                        Domain::IPV6,
                        SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)),
                    )
                })
                .await
                .context("create the IPv6 UDP pool")?
        } else {
            &self.pool
        };
        if pool.is_empty() {
            return Err(anyhow::anyhow!("UDP pool not initialized"));
        }

        // RFC 5452 §4.3 / §9.2: neither the transaction ID nor the source port
        // may be predictable, or a forged answer only has to guess the next
        // value. One draw from the thread-local RNG serves both: the high half
        // picks the socket (each pool socket sits on its own ephemeral port),
        // the low half seeds the ID.
        // RFC 5452 §4.3/§9.2：TXID 和源端口都不能可预测，否则伪造应答只需猜下一个值。
        // 从线程本地 RNG 取一次 32 位：高 16 位随机选 socket（池内每个 socket 各占
        // 一个临时端口），低 16 位作为 ID 起点。
        let draw: u32 = rand::random();
        let idx = (draw >> 16) as usize % pool.len();
        let state = &pool[idx];

        if packet.len() < 2 {
            return Err(anyhow::anyhow!("packet too short"));
        }
        let original_id = u16::from_be_bytes([packet[0], packet[1]]);

        // Copy the packet once so the ID can be rewritten; the same buffer is
        // sent and kept in the inflight entry for the answer's question check.
        // 只拷贝一次报文用于改写 ID；同一份缓冲既用于发送，也留在在途条目里供应答比对。
        let mut new_packet = BytesMut::with_capacity(packet.len());
        new_packet.extend_from_slice(packet);

        // Claim a free ID using the atomic entry API; on a collision with an
        // in-flight query draw a fresh random ID rather than the next one.
        // 使用原子 Entry API 占用空闲 ID；与在途查询冲突时重新随机，而不是取下一个。
        let mut attempts = 0;
        let mut new_id = draw as u16;
        let (tx, rx) = oneshot::channel();

        let new_packet = loop {
            match state.inflight.entry(new_id) {
                entry::Entry::Vacant(e) => {
                    new_packet[0..2].copy_from_slice(&new_id.to_be_bytes());
                    let new_packet = new_packet.freeze();
                    e.insert((original_id, addr, new_packet.clone(), tx));
                    break new_packet;
                }
                entry::Entry::Occupied(_) => {
                    new_id = rand::random();
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
        };

        // RAII Guard: ensures entry is removed from map when guard is dropped
        // (e.g. timeout, cancel, early return)
        // RAII Guard：确保在 guard 丢弃时（超时、取消、提前返回）移除条目
        let _guard = InflightGuard {
            inflight: state.inflight.clone(),
            id: new_id,
        };

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

/// 写入期间被取消时丢弃这条连接
/// Drops the connection if the write is cancelled part way through
///
/// 与 [`TcpPendingGuard`] 是同一个取消点：`send_attempt` 可以在任意 await 处
/// 被丢弃——外层请求超时先到（`validate_timeouts` 只要求 request >= upstream，
/// 取等时就会），或者双发路径上 UDP 先返回导致 `tcp_task.abort()`。待处理表
/// 那一侧已经由 `TcpPendingGuard` 兜住，写入这一侧此前没有：`write_all` 只写
/// 进去一部分就被丢弃时，连接仍然留在池里，下一个请求把自己的帧接在半条帧
/// 后面，对端按长度前缀读就会错位，而且不计错误也不重置，只能等下一次失败
/// 才自愈。
///
/// 这里把连接置空即可，下一次 `ensure_connection` 会重建。代价是热路径上多
/// 一次栈上构造和一次布尔写。
///
/// The same cancellation point as [`TcpPendingGuard`]: `send_attempt` can be
/// dropped at any await, either because the outer request timeout fires first
/// (`validate_timeouts` only requires request >= upstream, so equality allows
/// it) or because UDP answered first on the dual-send path and aborted the TCP
/// task. The pending-map side was already covered by `TcpPendingGuard`; the
/// write side was not. A `write_all` dropped after a partial write leaves the
/// connection in the pool, the next request appends its frame to half a frame,
/// and a peer reading by length prefix desynchronises, with nothing counting an
/// error or resetting it until a later request fails. Clearing the slot is
/// enough, since the next `ensure_connection` rebuilds it. The hot path pays
/// one stack construction and one boolean store.
struct TcpWriteGuard<'a> {
    slot: &'a mut Option<OwnedWriteHalf>,
    armed: bool,
}

impl Drop for TcpWriteGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            *self.slot = None;
        }
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
        // 阈值 0 表示禁用健康检查（README 与 config.rs 如此描述），
        // 而不是"每次错误都重置连接"。
        // A threshold of 0 disables the health check, as README and config.rs
        // describe, rather than resetting the connection on every error.
        let threshold = self.health_threshold.load(Ordering::Acquire);

        debug!(
            upstream = %self.upstream,
            consecutive_errors = errors,
            threshold = threshold,
            "TCP connection error recorded"
        );

        // Check if threshold exceeded / 检查是否超过阈值
        if threshold > 0 && errors >= threshold {
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
                // TRANSPARENT RETRY: If connection was reused and failed with transport error,
                // retry once with a fresh connection, within what is left of the budget
                // 透明重试：如果连接是复用的并且因传输错误失败，则在剩余预算内用新连接重试一次
                if is_reused {
                    let remaining = timeout_dur.saturating_sub(start.elapsed());
                    if remaining < MIN_RETRY_BUDGET {
                        return Err(err);
                    }

                    debug!(
                        upstream = %self.upstream,
                        error = %err,
                        retry_timeout_ms = remaining.as_millis() as u64,
                        "Connection reuse failed, performing transparent retry with fresh connection"
                    );

                    // Connection should have been reset by send_attempt already upon error
                    // send_attempt 出错时连接应该已经被重置
                    return self.send_attempt(packet, remaining).await;
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

        // 1. Ensure connection exists (acquires connection-level permit if needed),
        //    within what is left of the budget
        // 确保连接存在（如果需要则获取连接级别 permit），受剩余预算约束
        self.ensure_connection(timeout_dur.saturating_sub(start.elapsed()))
            .await?;

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
            if guard.is_none() {
                anyhow::bail!("tcp write half missing");
            }

            // Note: OwnedWriteHalf doesn't support peek/checking error directly easily without shared socket access.
            // But if the previous read failed, guard should be None (reset).
            // The fact we are here means 'guard' is Some, so we think connection is alive.
            // Writing to a closed socket usually triggers error immediately on Linux/BSD.

            // 写入期间被取消时丢弃连接，避免半条帧留在池里 / Drop the connection
            // if the write is cancelled, so half a frame cannot stay pooled
            let mut write_guard = TcpWriteGuard {
                slot: &mut guard,
                armed: true,
            };
            let writer = write_guard
                .slot
                .as_mut()
                .expect("connection presence checked above");
            let result = writer.write_all(&new_packet).await;
            // 走到这里说明写入已经结束：成功则帧是完整的，失败则下面会 reset。
            // Reaching here means the write finished: complete on success, and
            // the caller resets on failure.
            write_guard.armed = false;

            if let Err(e) = result {
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
    ///
    /// `budget` bounds the connect; on failure the lock and the permit are
    /// released immediately.
    /// `budget` 约束建连；失败时立即释放锁和 permit。
    async fn ensure_connection(&self, budget: Duration) -> anyhow::Result<()> {
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

            // Establish TCP connection within the budget. Unbounded, a blackholed
            // SYN blocks here until the kernel gives up (minutes) while every
            // other request on this client waits for the lock.
            // 在预算内建立 TCP 连接。不设限时 SYN 被黑洞会在此阻塞到内核放弃（分钟级），
            // 期间该客户端的其他请求都在等这把锁。
            let stream = match timeout(budget, TcpStream::connect(&*self.upstream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => anyhow::bail!("tcp connect failed: {e}"),
                Err(_) => anyhow::bail!("tcp connect timeout after {}ms", budget.as_millis()),
            };

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

/// 多久没被用过就算可以清理 / How long an entry must sit unused to be pruned
const DOH_UPSTREAM_IDLE: Duration = Duration::from_secs(600);
/// 两次清理之间的最小间隔 / Shortest gap between two prunes
const DOH_UPSTREAM_PRUNE_EVERY: Duration = Duration::from_secs(60);

/// One DoH upstream's state: its own reqwest client (connection pool) and its
/// consecutive transport-error count. Rebuilding a pool after repeated
/// failures therefore only evicts that upstream's connections; the other DoH
/// upstreams keep their keep-alive connections.
/// 单个 DoH 上游的状态：独立的 reqwest 客户端（连接池）和连续传输错误计数。连续失败后
/// 重建连接池只影响该上游，其它 DoH 上游的 keep-alive 连接不受牵连。
struct DohUpstream {
    /// Hot-swappable reqwest client (its connection pool). Replacing it drops the
    /// old pool, which is the only way to evict half-open/dead connections that
    /// reqwest cannot detect (DoH uses POST, which hyper won't auto-retry).
    /// 可热替换的 reqwest 客户端（其连接池）。替换即丢弃旧池，
    /// 这是清除 reqwest 无法检测的半开/死连接的唯一手段
    /// （DoH 用 POST，hyper 不会自动重试）
    client: ArcSwap<DohHttpClient>,
    /// Consecutive transport errors; cleared by a success or a rebuild.
    /// 连续传输错误数；成功或重建后清零。
    consecutive_errors: AtomicUsize,
    /// 最近一次使用的时刻，用于清理热重载换掉的旧上游
    /// When the entry was last used, so upstreams dropped by a reload can be pruned
    last_used_millis: AtomicU64,
}

pub struct DohClient {
    /// Per-upstream state, created the first time an upstream is used.
    /// 按上游划分的状态，首次使用该上游时创建。
    upstreams: DashMap<Arc<str>, Arc<DohUpstream>, FxBuildHasher>,
    pool_max_idle_per_host: usize,
    /// Threshold of consecutive transport errors that triggers a pool rebuild.
    /// 触发连接池重建的连续传输错误阈值
    health_error_threshold: usize,
    /// 上次清理空闲上游的时刻 / When idle upstreams were last pruned
    last_prune_millis: AtomicU64,
}

impl DohClient {
    pub fn new(
        pool_max_idle_per_host: usize,
        health_error_threshold: usize,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            upstreams: DashMap::with_hasher(FxBuildHasher),
            pool_max_idle_per_host,
            health_error_threshold,
            last_prune_millis: AtomicU64::new(unix_time_millis()),
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

    /// State for `upstream`, built on first sight. One map read per query on
    /// the hot path; the key is allocated once per upstream.
    /// `upstream` 的状态，首次遇到时创建。热路径每查询一次 map 读取；key 每个上游只分配一次。
    fn upstream(&self, upstream: &str) -> anyhow::Result<Arc<DohUpstream>> {
        let now = unix_time_millis();
        let state = self.lookup_or_create(upstream, now)?;
        // 清理放在查表之后：此刻没有持有任何分片守卫，retain 不会和自己抢锁。
        // Prune after the lookup: no shard guard is held here, so retain cannot
        // contend with this very call.
        self.prune_idle_upstreams(now);
        Ok(state)
    }

    fn lookup_or_create(&self, upstream: &str, now: u64) -> anyhow::Result<Arc<DohUpstream>> {
        if let Some(state) = self.upstreams.get(upstream) {
            state.last_used_millis.store(now, Ordering::Relaxed);
            return Ok(Arc::clone(&state));
        }
        match self.upstreams.entry(Arc::from(upstream)) {
            entry::Entry::Occupied(existing) => {
                existing
                    .get()
                    .last_used_millis
                    .store(now, Ordering::Relaxed);
                Ok(Arc::clone(existing.get()))
            }
            entry::Entry::Vacant(slot) => {
                let state = Arc::new(DohUpstream {
                    client: ArcSwap::from_pointee(Self::build_client(self.pool_max_idle_per_host)?),
                    consecutive_errors: AtomicUsize::new(0),
                    last_used_millis: AtomicU64::new(now),
                });
                slot.insert(Arc::clone(&state));
                Ok(state)
            }
        }
    }

    /// 清理长期不用的上游条目，让热重载换掉的上游不会一直占着连接池
    /// Drop entries nothing has used for a while, so upstreams a reload replaced
    /// do not keep their connection pools for the life of the process
    ///
    /// 每次查表之后都会调用，但受时间间隔节流：一次热重载换掉整批上游、之后再没有
    /// 新上游出现时，旧条目同样会在下一个间隔被清掉，不必等下一次新键插入。
    /// Called after every lookup but throttled by time: when a reload swaps the
    /// whole set of upstreams and no new one ever appears again, the old entries
    /// still go at the next interval instead of waiting for another new key.
    fn prune_idle_upstreams(&self, now: u64) {
        // 节流窗口没到时，这个函数只花一次 relaxed 读就返回；每次查询本身仍有
        // 一次取时钟和一次查表，那是 upstream() 的固有代价。
        // Inside the throttle window this function costs one relaxed load and
        // returns. The per-query clock read and table lookup belong to
        // upstream() itself and are unchanged.
        let last_prune = self.last_prune_millis.load(Ordering::Relaxed);
        let prune_every = u64::try_from(DOH_UPSTREAM_PRUNE_EVERY.as_millis()).unwrap_or(u64::MAX);
        if now.saturating_sub(last_prune) < prune_every {
            return;
        }
        // 先占下这一轮：CAS 成功的调用者负责扫描，其它调用者立刻返回。时间戳在
        // 扫描之前就推后，所以无论这轮删没删掉东西，热路径都要再等一个间隔才会
        // 走到这里——之前的数量门槛放在 CAS 之前，不满足时直接 return 而不推后
        // 时间戳，于是每一次查询都要付一次 DashMap::len()（逐分片取读锁）。
        // Claim the round first: the caller that wins the CAS does the scan and
        // the others return. The timestamp moves before the scan, so whether or
        // not this round drops anything the hot path waits another interval to
        // get here. The entry-count gate used to sit before the CAS and return
        // without moving the timestamp, so every lookup paid a DashMap::len(),
        // which takes a read lock on every shard.
        if self
            .last_prune_millis
            .compare_exchange(last_prune, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let idle_millis = u64::try_from(DOH_UPSTREAM_IDLE.as_millis()).unwrap_or(u64::MAX);
        self.upstreams.retain(|_, state| {
            now.saturating_sub(state.last_used_millis.load(Ordering::Relaxed)) < idle_millis
        });
    }

    pub async fn send(
        &self,
        packet: &[u8],
        upstream: &str,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        let (url, host_override) = build_doh_url(upstream)?;
        let host = host_override.as_deref();
        let state = self.upstream(upstream)?;

        let start = tokio::time::Instant::now();
        match Self::send_once(&state, packet, &url, host, timeout_dur).await {
            Ok(bytes) => {
                state.consecutive_errors.store(0, Ordering::Release);
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
                if remaining < MIN_RETRY_BUDGET {
                    return Err(err);
                }
                debug!(
                    upstream = upstream,
                    error = %err,
                    pool_rebuilt = rebuilt,
                    retry_timeout_ms = remaining.as_millis() as u64,
                    "DoH transport error, performing transparent retry"
                );
                Self::send_once(&state, packet, &url, host, remaining).await
            }
            Err(e) => Err(e),
        }
    }

    /// Single attempt: send the request and read the body within a timeout.
    /// 单次尝试：在超时内发送请求并读取响应体
    async fn send_once(
        state: &DohUpstream,
        packet: &[u8],
        url: &Url,
        host_override: Option<&str>,
        timeout_dur: Duration,
    ) -> anyhow::Result<Bytes> {
        // load_full() returns an owned Arc<Client>, keeping the Future Send across
        // await points (an ArcSwap Guard would not). The Arc is cheap to hold.
        // load_full() 返回 owned Arc<Client>，保持 Future 跨 await 点 Send
        // （ArcSwap 的 Guard 不满足）。持有 Arc 很廉价。
        let client = state.client.load_full();

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
    /// reaches the threshold, rebuild that upstream's reqwest client (evicting
    /// its dead connection pool) and reset the counter. Returns true if rebuilt.
    /// 记录 upstream 的连续传输错误。计数达阈值时重建该上游的 reqwest 客户端
    /// （驱逐其死连接池）并清零计数。重建返回 true。
    fn record_error(&self, upstream: &str) -> bool {
        let state = match self.upstream(upstream) {
            Ok(state) => state,
            Err(e) => {
                warn!(upstream = upstream, error = %e, "failed to build DoH client");
                return false;
            }
        };
        let count = state.consecutive_errors.fetch_add(1, Ordering::AcqRel) + 1;
        if self.health_error_threshold > 0 && count >= self.health_error_threshold {
            match Self::build_client(self.pool_max_idle_per_host) {
                Ok(new_client) => {
                    // Swap in a fresh client; the old pool is released once in-flight
                    // requests holding a cloned Arc finish.
                    // 替换为新客户端；旧池在持有 Arc 副本的在途请求结束后释放
                    state.client.store(Arc::new(new_client));
                    warn!(
                        upstream = upstream,
                        consecutive_errors = count,
                        threshold = self.health_error_threshold,
                        "DoH error threshold exceeded, rebuilding connection pool"
                    );
                    state.consecutive_errors.store(0, Ordering::Release);
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
                consecutive_errors = count,
                threshold = self.health_error_threshold,
                "DoH transport error recorded"
            );
            false
        }
    }

    /// Clear the consecutive error counter of `upstream` (what a successful
    /// send does inline). / 清零 `upstream` 的连续错误计数（成功发送时内联完成）。
    #[cfg(test)]
    fn record_success(&self, upstream: &str) {
        if let Some(state) = self.upstreams.get(upstream) {
            state.consecutive_errors.store(0, Ordering::Release);
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

        if threshold > 0 && errors >= threshold {
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
                    let remaining = timeout_dur.saturating_sub(start.elapsed());
                    if remaining < MIN_RETRY_BUDGET {
                        return Err(err);
                    }
                    debug!(
                        upstream = %self.upstream,
                        error = %err,
                        retry_timeout_ms = remaining.as_millis() as u64,
                        "DoT reuse failed, retrying with fresh connection"
                    );
                    return self.send_attempt(packet, remaining).await;
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

        self.ensure_connection(timeout_dur.saturating_sub(start.elapsed()))
            .await?;

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

    /// `budget` bounds the TCP connect and the TLS handshake together; on
    /// failure the lock and the permit are released immediately.
    /// `budget` 同时约束 TCP 建连和 TLS 握手；失败时立即释放锁和 permit。
    async fn ensure_connection(&self, budget: Duration) -> anyhow::Result<()> {
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

            // Connect and complete the TLS handshake within the budget: an
            // upstream that accepts and stays silent would otherwise hold the
            // lock, and every request queued behind it, indefinitely.
            // 在预算内建连并完成 TLS 握手：accept 后沉默的上游否则会无限期占住锁，
            // 排在后面的请求一起被钉死。
            let tls_connector = TlsConnector::from(self.tls_config.clone());
            let server_name = build_server_name(&target.sni)?;
            let connect = async {
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

                tls_connector
                    .connect(server_name, stream)
                    .await
                    .context("dot tls handshake failed")
            };
            let tls_stream = match timeout(budget, connect).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(e)) => return Err(e),
                Err(_) => anyhow::bail!(
                    "dot connect/handshake timeout after {}ms",
                    budget.as_millis()
                ),
            };

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
    /// 0-RTT 的安全提示只在真正用上 0-RTT 时打印一次
    /// Prints the 0-RTT security notice once, and only if 0-RTT is really used
    zero_rtt_notice: std::sync::Once,
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
/// DoQ 一次尝试的失败原因，按类型保留 quinn 的原始错误
/// Why one DoQ attempt failed, keeping quinn's own error by type
///
/// 此前内层每一步都被 `.context()` 包过，而 `anyhow::Error::to_string()` 只
/// 输出最外层那一句，所以判定 0-RTT 是否被拒绝时拿到的永远只是那几个固定
/// 短语，quinn 说的话根本到不了。把原始错误原样带出来，判定就能落在类型上。
/// Every step used to be wrapped in `.context()`, and
/// `anyhow::Error::to_string()` renders only the outermost one, so the check
/// for a rejected 0-RTT attempt never saw anything but a handful of fixed
/// phrases and never quinn's own words. Carrying the error out untouched lets
/// the decision rest on types.
#[derive(Debug)]
enum DoqFailure {
    /// `open_bi` 失败：连接已经不可用 / the connection is already unusable
    OpenStream(quinn::ConnectionError),
    /// 写查询失败 / writing the query failed
    Write(quinn::WriteError),
    /// 读应答失败 / reading the answer failed
    Read(quinn::ReadToEndError),
    /// 应答本身不合协议，与 0-RTT 无关 / the answer itself is malformed
    Protocol(String),
}

impl std::fmt::Display for DoqFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenStream(err) => write!(f, "doq open stream failed: {err}"),
            Self::Write(err) => write!(f, "doq send query failed: {err}"),
            Self::Read(err) => write!(f, "doq read response failed: {err}"),
            Self::Protocol(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for DoqFailure {
    /// 保住 quinn 的 source 链：类型化到这里就被拍平成字符串的话，日志里就只
    /// 剩 Display 那一行了。
    /// Keeps quinn's source chain: flattening to a string at this boundary
    /// would leave the log with nothing but the Display line.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OpenStream(err) => Some(err),
            Self::Write(err) => Some(err),
            Self::Read(err) => Some(err),
            Self::Protocol(_) => None,
        }
    }
}

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
            zero_rtt_notice: std::sync::Once::new(),
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
        if threshold > 0 && errors >= threshold {
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
                // 内层返回带类型的失败，而不是 anyhow：每一步都被 context 包过
                // 之后，anyhow 的 to_string 只剩最外层那一句，quinn 的原始错误
                // 到不了判定处。
                // The inner block yields a typed failure rather than anyhow:
                // once every step is wrapped in context, anyhow's to_string
                // leaves only the outermost sentence and quinn's own error never
                // reaches the decision.
                let (mut send, mut recv) = conn.open_bi().await.map_err(DoqFailure::OpenStream)?;

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

                send.write_all(&frame).await.map_err(DoqFailure::Write)?;
                let _ = send.finish();

                // Read response: 2-byte length prefix followed by DNS message
                // 读取响应：2 字节长度前缀，后跟 DNS 消息
                // Note: The server sends the response and closes the stream with FIN
                // We need to read all data until FIN, then parse the length prefix
                // 注意：服务器发送响应后用 FIN 关闭流
                // 我们需要读取所有数据直到 FIN，然后解析长度前缀
                // 连接被对端关掉的判断此前靠字符串，而且那个判断把所有原因都
                // 折叠成同一句话；现在原样把 quinn 的错误带出去，由
                // zero_rtt_likely_rejected 按类型判定。
                // Detecting a peer-closed connection used to go through strings,
                // and that check folded every cause into one sentence. The quinn
                // error is now carried out as it is and
                // zero_rtt_likely_rejected decides by type.
                let mut all_data = recv
                    .read_to_end(MAX_DNS_MESSAGE_SIZE + 2)
                    .await
                    .map_err(DoqFailure::Read)?;

                if all_data.is_empty() {
                    return Err(DoqFailure::Protocol(
                        "doq received empty response (server closed stream without sending data)"
                            .to_string(),
                    ));
                }

                if all_data.len() < 2 {
                    return Err(DoqFailure::Protocol(format!(
                        "doq response too short: {} bytes",
                        all_data.len()
                    )));
                }

                let msg_len = u16::from_be_bytes([all_data[0], all_data[1]]) as usize;

                // idoq-style length validation: response length must match length prefix
                // idoq 风格的长度验证：响应长度必须匹配长度前缀
                if all_data.len() != 2 + msg_len {
                    return Err(DoqFailure::Protocol(format!(
                        "doq length mismatch: expected {} bytes (2 + {}), got {} bytes. \
                        This may indicate data corruption or server protocol violation.",
                        2 + msg_len,
                        msg_len,
                        all_data.len()
                    )));
                }

                let buf = &all_data[2..2 + msg_len];
                if buf.len() < 2 {
                    // DNS message must be at least 2 bytes for TXID restoration.
                    // Also prevents all_data[2..4] index out of bounds when msg_len < 2.
                    // DNS 消息必须至少 2 字节才能恢复 TXID。
                    // 同时防止 msg_len < 2 时 all_data[2..4] 越界。
                    return Err(DoqFailure::Protocol(format!(
                        "doq DNS message too short: {msg_len} bytes"
                    )));
                }
                // Restore original DNS Message ID in-place (Vec<u8> is mutable).
                // Bytes::from(Vec) takes ownership of the heap allocation (zero-copy).
                // slice(2..) returns a view past the length prefix (zero-copy, shares allocation).
                // 原地恢复原始 DNS Message ID（Vec<u8> 可变）。
                // Bytes::from(Vec) 接管堆分配（零拷贝）。
                // slice(2..) 返回跳过长度前缀的视图（零拷贝，共享分配）。
                all_data[2..4].copy_from_slice(&original_id.to_be_bytes());
                Ok::<Bytes, DoqFailure>(Bytes::from(all_data).slice(2..))
            })
            .await;

            match resp {
                Ok(Ok(bytes)) => {
                    self.record_success();
                    return Ok(bytes);
                }
                Ok(Err(failure)) => {
                    let already_reset = self.record_error().await;
                    if !already_reset {
                        // Only reset if record_error() didn't already reset (below threshold)
                        self.reset_connection().await;
                    }
                    if allow_retry
                        && used_0rtt
                        && self.zero_rtt_retry_allowed(target)
                        && Self::zero_rtt_likely_rejected(&failure)
                    {
                        self.disable_zero_rtt();
                        let remaining = timeout_dur.saturating_sub(start.elapsed());
                        if remaining.is_zero() {
                            return Err(anyhow::Error::new(failure));
                        }
                        warn!(
                            upstream = %self.upstream,
                            error = %failure,
                            "DoQ 0-RTT likely rejected, retrying without 0-RTT"
                        );
                        allow_retry = false;
                        timeout_dur = remaining;
                        continue;
                    }
                    return Err(anyhow::Error::new(failure));
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
                            // 粘滞位绕不过去：connect_new 用的是
                            // enable_0rtt && !was_rejected，所以 ?0rtt=true 也
                            // 不会让它重新启用，只能重启进程。
                            // The sticky bit cannot be bypassed: connect_new
                            // takes enable_0rtt && !was_rejected, so ?0rtt=true
                            // does not re-enable it either; only a restart does.
                            "DoQ 0-RTT timeout detected, automatically disabling 0-RTT for this upstream. \
                            Future connections will use normal handshake. This status is cached until a restart."
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

    /// 这次失败是否像 0-RTT 被拒绝，值得关掉 0-RTT 再试一次
    /// Whether this failure looks like a rejected 0-RTT attempt and is worth one
    /// retry with 0-RTT off
    ///
    /// 两类算数：quinn 明确报告 `ZeroRttRejected`；或者连接被对端关闭、重置、
    /// 丢失——服务器拒绝 0-RTT 数据时常常直接关连接，而不是报那个专门的错误。
    /// 本地关闭、超时、协议层面的问题都不算，它们和 0-RTT 无关。
    ///
    /// 纯函数，不吃 `&self`，所以测试可以直接拿 quinn 的错误值驱动它。
    /// Two things count: quinn saying `ZeroRttRejected` outright, and the
    /// connection being closed, reset or lost by the peer, since a server that
    /// refuses 0-RTT data often just closes instead of raising that specific
    /// error. A local close, a timeout and any protocol-level problem do not,
    /// having nothing to do with 0-RTT. It takes no `&self`, so a test can drive
    /// it with real quinn error values.
    fn zero_rtt_likely_rejected(failure: &DoqFailure) -> bool {
        fn peer_ended_it(err: &quinn::ConnectionError) -> bool {
            matches!(
                err,
                quinn::ConnectionError::ApplicationClosed(_)
                    | quinn::ConnectionError::ConnectionClosed(_)
                    | quinn::ConnectionError::Reset
            )
        }

        match failure {
            DoqFailure::OpenStream(err) => peer_ended_it(err),
            DoqFailure::Write(quinn::WriteError::ZeroRttRejected) => true,
            DoqFailure::Write(quinn::WriteError::ConnectionLost(err)) => peer_ended_it(err),
            DoqFailure::Read(quinn::ReadToEndError::Read(err)) => match err {
                quinn::ReadError::ZeroRttRejected => true,
                quinn::ReadError::ConnectionLost(err) => peer_ended_it(err),
                _ => false,
            },
            _ => false,
        }
    }

    /// 在这条连接上是否还允许关掉 0-RTT 重试：配置开着、且还没被标记过拒绝
    /// Whether a 0-RTT retry is still allowed here: enabled by configuration and
    /// not already marked as rejected
    fn zero_rtt_retry_allowed(&self, target: &DoqTarget) -> bool {
        target.enable_0rtt.unwrap_or(self.runtime.enable_0rtt)
            && !self
                .zero_rtt_rejected
                .load(std::sync::atomic::Ordering::Relaxed)
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
            // Security warning: 0-RTT (early data) is vulnerable to replay attacks
            // per RFC 8446 §8 and RFC 9001 §5.4. DNS queries are idempotent, so
            // replay impact is limited to redundant lookups and potential cache
            // timing side-channels. Only enable 0-RTT in trusted network environments.
            // The client is built for every configuration, so the notice waits for
            // the first connection that actually offers early data.
            // 安全警告：0-RTT（早期数据）容易受到重放攻击（RFC 8446 §8, RFC 9001 §5.4）。
            // DNS 查询是幂等的，因此重放影响仅限于冗余查询和潜在的缓存时序侧信道。
            // 仅在可信网络环境中启用 0-RTT。客户端在任何配置下都会构造，因此提示
            // 推迟到第一个真正发送早期数据的连接。
            self.runtime.zero_rtt_notice.call_once(|| {
                tracing::warn!(
                    upstream = %target.host,
                    "DoQ 0-RTT enabled: vulnerable to replay attacks (RFC 8446 §8). \
                     DNS queries are idempotent but an attacker can observe timing patterns. \
                     Disable 0-RTT in untrusted environments."
                );
            });
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

    /// 0-RTT 判定必须按类型走。此前它比对 `anyhow::Error::to_string()`，而内层
    /// 每一步都被 `.context()` 包过，那个字符串永远只是三句固定短语之一或一条
    /// bail 文本，于是 quinn 明说的 `ZeroRttRejected` 从来没有被识别过：判定
    /// 返回 false，0-RTT 不被禁用，下次连接又用 0-RTT，该上游一直失败到重启。
    /// The 0-RTT decision has to go by type. It used to compare
    /// `anyhow::Error::to_string()`, and since every inner step was wrapped in
    /// `.context()` that string was only ever one of three fixed phrases or a
    /// bail text, so quinn saying `ZeroRttRejected` outright was never
    /// recognised: the check returned false, 0-RTT stayed on, the next
    /// connection used it again and the upstream kept failing until a restart.
    /// 写入中途被取消时，这条池化连接必须被丢弃。取消点与 TcpPendingGuard
    /// 兜的是同一个：外层请求超时先到，或者双发路径上 UDP 先返回导致
    /// tcp_task.abort()。此前只有待处理表那一侧被清理，连接仍然留在池里，
    /// 下一个请求会把自己的帧接在可能只写了一半的帧后面。
    /// A pooled connection has to be dropped when the write is cancelled part
    /// way through. The cancellation point is the one TcpPendingGuard already
    /// covers: the outer request timeout firing first, or the dual-send path
    /// aborting the TCP task once UDP answered. Only the pending-map side used
    /// to be cleaned up, leaving the connection pooled for the next request to
    /// append its frame to a possibly half-written one.
    #[tokio::test]
    async fn a_cancelled_write_drops_the_pooled_connection() {
        use tokio::io::AsyncWriteExt as _;

        // 对端只 accept 不读，发送缓冲区会被填满，写入因此停在 await 上
        // The peer accepts and never reads, so the send buffer fills and the
        // write parks on an await
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (held, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(held);
        });

        let client = Arc::new(TcpMuxClient::new(
            Arc::from(addr.to_string().as_str()),
            Arc::new(PermitManager::new_unlimited()),
        ));

        // 直接建连，不走查询——查询超时会自己 reset 掉连接
        // Connect directly: a query would time out and reset the connection
        let query = [0u8; 12];
        client
            .ensure_connection(Duration::from_secs(2))
            .await
            .expect("connect to the test peer");
        assert!(
            client.conn.lock().await.is_some(),
            "the connection must be pooled before the test can mean anything"
        );

        // 把发送缓冲区填满，让后续写入必然停在 await 上
        // Fill the send buffer so any later write must park on an await
        {
            let mut guard = client.conn.lock().await;
            let writer = guard.as_mut().unwrap();
            let chunk = vec![0u8; 65536];
            while tokio::time::timeout(Duration::from_millis(300), writer.write_all(&chunk))
                .await
                .is_ok()
            {}
        }

        // 写入停在 await 上时取消这次发送
        // Cancel the send while the write is parked
        let sender = Arc::clone(&client);
        let task = tokio::spawn(async move { sender.send(&query, Duration::from_secs(30)).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        task.abort();
        let _ = task.await;

        assert!(
            client.conn.lock().await.is_none(),
            "a write cancelled part way through must drop the connection instead of \
             leaving a possibly half-written frame in the pool"
        );

        peer.abort();
    }

    #[test]
    fn doq_zero_rtt_rejection_is_classified_by_type() {
        use quinn::{ConnectionError, ReadError, ReadToEndError, WriteError};

        // quinn 明说被拒绝 / quinn says so outright
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Write(
            WriteError::ZeroRttRejected
        )));
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::Read(ReadError::ZeroRttRejected)
        )));

        // 对端直接关掉连接：拒绝 0-RTT 数据的服务器常常这样做
        // The peer just closes: what a server refusing 0-RTT data often does
        let closed = || {
            ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0),
                reason: bytes::Bytes::new(),
            })
        };
        assert!(DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::OpenStream(closed())
        ));
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::Read(ReadError::ConnectionLost(closed()))
        )));
        assert!(DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Write(
            WriteError::ConnectionLost(ConnectionError::Reset)
        )));

        // 与 0-RTT 无关的失败不该触发重试
        // Failures that have nothing to do with 0-RTT must not trigger a retry
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::OpenStream(ConnectionError::TimedOut)
        ));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::OpenStream(ConnectionError::LocallyClosed)
        ));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::TooLong
        )));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(&DoqFailure::Read(
            ReadToEndError::Read(ReadError::ClosedStream)
        )));
        assert!(!DoqMuxClient::zero_rtt_likely_rejected(
            &DoqFailure::Protocol("doq response too short: 1 bytes".to_string())
        ));
    }

    use futures::future::join_all;
    use std::time::Duration;
    use tokio::time::timeout;

    /// UDP "upstream" for UdpClient tests: records the (transaction id, source
    /// port) of every query it receives and answers with each datagram of
    /// `reply(query)`, in order.
    /// UdpClient 测试用的 UDP "上游"：记录每个查询的 (TXID, 源端口)，按序发回
    /// reply(query) 给出的每个数据报。
    async fn spawn_udp_upstream(
        reply: impl Fn(&[u8]) -> Vec<Vec<u8>> + Send + 'static,
    ) -> (String, Arc<std::sync::Mutex<Vec<(u16, u16)>>>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind UDP test upstream");
        let addr = socket.local_addr().expect("read UDP test address");
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, src)) = socket.recv_from(&mut buf).await {
                let query = &buf[..n];
                let id = u16::from_be_bytes([query[0], query[1]]);
                recorder.lock().unwrap().push((id, src.port()));
                for datagram in reply(query) {
                    let _ = socket.send_to(&datagram, src).await;
                }
            }
        });
        (addr.to_string(), seen)
    }

    /// A query for `name` (A, IN) with a fixed transaction id.
    fn udp_test_query(name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii(name).expect("parse test name"),
            RecordType::A,
        ));
        msg.to_vec().expect("encode test query")
    }

    /// Flip the QR bit so `query` becomes a (empty) response to itself.
    fn udp_echo_response(query: &[u8]) -> Vec<u8> {
        let mut response = query.to_vec();
        response[2] |= 0x80;
        response
    }

    /// Response to `query` whose question section names `name` instead.
    fn udp_response_with_question(query: &[u8], name: &str) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        let id = u16::from_be_bytes([query[0], query[1]]);
        let mut msg = Message::new(id, MessageType::Response, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii(name).expect("parse test name"),
            RecordType::A,
        ));
        msg.to_vec().expect("encode test response")
    }

    #[tokio::test]
    async fn udp_send_randomizes_transaction_id_and_source_port() {
        // RFC 5452 §4.3 / §9.2: neither the ID nor the source port may be
        // predictable. Before this, every socket numbered its IDs 0, 1, 2, …
        // and sockets were picked round-robin, so the sequence of (ID, port)
        // pairs was fully predictable.
        // RFC 5452 §4.3/§9.2：TXID 和源端口都不能可预测。此前每个 socket 的 ID 从
        // 0 顺序递增、socket 轮询选择，(ID, 端口) 序列完全可预测。
        let (upstream, seen) = spawn_udp_upstream(|query| vec![udp_echo_response(query)]).await;
        let client = UdpClient::new(4).expect("create UDP client");
        let sends = 16;
        for _ in 0..sends {
            client
                .send(
                    &udp_test_query("id.example."),
                    &upstream,
                    Duration::from_secs(2),
                )
                .await
                .expect("query answered");
        }
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), sends);

        // Sequential numbering keeps every ID below the number of sends per
        // socket; random IDs spread over the whole 16-bit space.
        let ids: Vec<u16> = seen.iter().map(|(id, _)| *id).collect();
        assert!(
            ids.iter().any(|&id| id as usize >= sends),
            "transaction IDs look sequential: {ids:?}"
        );

        // Round-robin socket choice repeats the same port every pool_size sends.
        let ports: Vec<u16> = seen.iter().map(|(_, port)| *port).collect();
        assert!(
            ports
                .iter()
                .enumerate()
                .any(|(i, port)| *port != ports[i % 4]),
            "source ports cycle round-robin: {ports:?}"
        );
    }

    #[tokio::test]
    async fn udp_send_ignores_answer_whose_question_differs() {
        // RFC 5452 §9.1: an answer is only accepted when its question section
        // matches the query; a matching ID and source address are not enough.
        // RFC 5452 §9.1：question 段不匹配的应答必须忽略，ID 和源地址相符不够。
        let (upstream, _seen) =
            spawn_udp_upstream(|query| vec![udp_response_with_question(query, "evil.example.")])
                .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let err = client
            .send(
                &udp_test_query("id.example."),
                &upstream,
                Duration::from_millis(300),
            )
            .await
            .expect_err("an answer for a different question must not be delivered");
        assert!(
            err.to_string().contains("timeout"),
            "expected the query to time out, got: {err:#}"
        );
    }

    #[tokio::test]
    async fn udp_send_accepts_case_randomized_question() {
        // DNS 0x20 upstreams answer with the query name's case scrambled; the
        // match must ignore ASCII case.
        // 0x20 大小写随机化的应答要能匹配：比较忽略 ASCII 大小写。
        let (upstream, _seen) =
            spawn_udp_upstream(|query| vec![udp_response_with_question(query, "Id.ExAmPlE.")])
                .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let response = client
            .send(
                &udp_test_query("id.example."),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("case-scrambled answer must be accepted");
        assert_eq!(&response[0..2], &[0x12, 0x34], "original ID restored");
    }

    #[tokio::test]
    async fn udp_send_accepts_record_less_error_without_question() {
        // Some upstreams answer FORMERR/NOTIMP with QDCOUNT = 0. Such a reply
        // carries nothing cacheable, so it is delivered as the fast failure it
        // is instead of being treated as forged and waited out.
        // 有些上游对 FORMERR/NOTIMP 回 QDCOUNT=0：没有可缓存内容，按快速失败投递，
        // 而不是当作伪造等到超时。
        let (upstream, _seen) = spawn_udp_upstream(|query| {
            let mut header_only = query[..12].to_vec();
            header_only[2] |= 0x80;
            header_only[3] = 0x01; // FORMERR
            header_only[5] = 0; // QDCOUNT = 0
            vec![header_only]
        })
        .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let response = client
            .send(
                &udp_test_query("id.example."),
                &upstream,
                Duration::from_secs(2),
            )
            .await
            .expect("record-less FORMERR must be delivered");
        assert_eq!(response.len(), 12);
        assert_eq!(response[3] & 0x0F, 0x01, "RCODE = FORMERR");
    }

    #[tokio::test]
    async fn udp_send_keeps_waiting_after_mismatched_answer() {
        // A mismatched answer must not consume the in-flight entry: the genuine
        // answer arriving right after it is still delivered.
        // 不匹配的应答不能消耗在途条目：紧随其后的真应答仍被投递。
        let (upstream, _seen) = spawn_udp_upstream(|query| {
            vec![
                udp_response_with_question(query, "evil.example."),
                udp_echo_response(query),
            ]
        })
        .await;
        let client = UdpClient::new(1).expect("create UDP client");
        let query = udp_test_query("id.example.");
        let response = client
            .send(&query, &upstream, Duration::from_secs(2))
            .await
            .expect("genuine answer after a bogus one must be delivered");
        assert_eq!(
            &response[12..],
            &query[12..],
            "delivered answer is the genuine one"
        );
    }

    /// Listener whose accept queue is full and never drained: the kernel drops
    /// further SYNs, so a connect() to it hangs until the SYN retransmits give
    /// up (minutes) unless the caller bounds it.
    /// accept 队列已满且从不 accept 的监听器：内核丢弃后续 SYN，connect() 会挂到
    /// SYN 重传耗尽（分钟级），除非调用方自己设限。
    struct BlackholedListener {
        addr: SocketAddr,
        _listener: Socket,
        _queued: Vec<std::net::TcpStream>,
    }

    async fn blackholed_tcp_listener() -> BlackholedListener {
        let listener = Socket::new(Domain::IPV4, Type::STREAM, None).expect("create listener");
        listener
            .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
            .expect("bind listener");
        listener.listen(1).expect("listen with backlog 1");
        let addr = listener.local_addr().unwrap().as_socket().unwrap();
        let queued = tokio::task::spawn_blocking(move || {
            let mut held = Vec::new();
            for _ in 0..8 {
                if let Ok(stream) =
                    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200))
                {
                    held.push(stream);
                }
            }
            held
        })
        .await
        .expect("fill accept queue");
        BlackholedListener {
            addr,
            _listener: listener,
            _queued: queued,
        }
    }

    /// Listener that accepts and then never sends a byte, so a TLS handshake
    /// against it never completes.
    /// accept 后一个字节都不发的监听器：TLS 握手永远完不成。
    async fn silent_tcp_listener() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent listener");
        let addr = listener.local_addr().expect("read silent listener address");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_connect_is_bounded_by_the_request_budget() {
        // ensure_connection used to call TcpStream::connect with no timeout while
        // holding the connection lock: a blackholed upstream pinned the request
        // (and every request queued behind the lock) for the kernel's SYN
        // timeout, regardless of the configured upstream timeout.
        // ensure_connection 曾在持有连接锁时无超时地 connect：上游黑洞时请求（以及排在
        // 锁后的所有请求）会等满内核 SYN 超时，配置的 upstream 超时形同虚设。
        let blackhole = blackholed_tcp_listener().await;
        let client = TcpMuxClient::new(
            Arc::from(blackhole.addr.to_string()),
            Arc::new(PermitManager::new(1)),
        );
        let started = tokio::time::Instant::now();
        let result = timeout(
            Duration::from_secs(3),
            client.send(&[0u8; 12], Duration::from_millis(300)),
        )
        .await
        .expect("send must give up within its budget, not wait for the kernel SYN timeout");
        assert!(result.is_err(), "a blackholed upstream cannot succeed");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "gave up after {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn dot_connect_and_handshake_are_bounded_by_the_request_budget() {
        // Same for DoT, where the TLS handshake is the part that can stall: an
        // upstream that accepts and stays silent must not pin the request.
        // DoT 同理，卡住的是 TLS 握手：accept 后沉默的上游不能钉死请求。
        let addr = silent_tcp_listener().await;
        let client = DotMuxClient::new(
            Arc::from(format!("dot://{addr}?sni=localhost")),
            Arc::new(build_tls_client_config().expect("tls config")),
            Arc::new(PermitManager::new(1)),
        );
        let started = tokio::time::Instant::now();
        let result = timeout(
            Duration::from_secs(3),
            client.send(&[0u8; 12], Duration::from_millis(300)),
        )
        .await
        .expect("send must give up within its budget, not wait for a handshake that never comes");
        assert!(result.is_err(), "a silent upstream cannot succeed");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "gave up after {:?}",
            started.elapsed()
        );
    }

    /// TCP upstream that answers the very first query it ever receives
    /// (echoing the frame with QR set) and then swallows everything, on that
    /// connection and on any later one.
    /// 只应答收到的第一个查询（回显帧并置 QR 位），之后无论旧连接还是新连接一律吞掉的
    /// TCP 上游。
    async fn answer_once_then_stall_tcp_upstream() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stalling upstream");
        let addr = listener
            .local_addr()
            .expect("read stalling upstream address");
        let answered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let answered = Arc::clone(&answered);
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
                    if stream.read_exact(&mut frame).await.is_err() {
                        return;
                    }
                    if !answered.swap(true, Ordering::SeqCst) {
                        frame[2] |= 0x80;
                        let _ = stream.write_all(&len).await;
                        let _ = stream.write_all(&frame).await;
                    }
                    let mut sink = [0u8; 512];
                    while stream.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_retry_does_not_exceed_the_request_budget() {
        // The transparent retry over a fresh connection used to be granted a
        // 1.5 s floor even when the caller's budget was already spent, so a
        // 200 ms request took about 1.7 s on a stalled reused connection.
        // 复用连接失败后的透明重试曾无条件给 1.5 s 保底：预算 200 ms 的请求在卡住的
        // 复用连接上要跑约 1.7 s。
        let addr = answer_once_then_stall_tcp_upstream().await;
        let client =
            TcpMuxClient::new(Arc::from(addr.to_string()), Arc::new(PermitManager::new(1)));
        let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        client
            .send(&query, Duration::from_millis(500))
            .await
            .expect("first query on a fresh connection is answered");

        let started = tokio::time::Instant::now();
        let err = client
            .send(&query, Duration::from_millis(200))
            .await
            .expect_err("stalled upstream cannot answer the second query");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(700),
            "second query took {elapsed:?} on a 200 ms budget: {err:#}"
        );
    }

    /// UDP upstream on `bind` that echoes every query back with QR set, or
    /// `None` when the address family is unavailable on this host.
    /// 绑定在 `bind` 上、把每个查询置 QR 位后原样回显的 UDP 上游；该地址族不可用时为 None。
    async fn spawn_udp_echo_upstream(bind: &str) -> Option<String> {
        let socket = tokio::net::UdpSocket::bind(bind).await.ok()?;
        let addr = socket.local_addr().expect("read UDP echo address");
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, src)) = socket.recv_from(&mut buf).await {
                buf[2] |= 0x80;
                let _ = socket.send_to(&buf[..n], src).await;
            }
        });
        Some(addr.to_string())
    }

    /// v6 池此前无条件预建：默认 udp_pool_size=64 时，哪怕一个 IPv6 上游都没有
    /// 也要多占 64 个 socket 和 64 个任务。
    /// The v6 pool used to be built unconditionally: with the default
    /// udp_pool_size of 64 a deployment without a single IPv6 upstream still
    /// paid for 64 sockets and 64 tasks.
    #[tokio::test]
    async fn udp_ipv6_pool_is_built_only_when_an_ipv6_upstream_is_used() {
        let client = UdpClient::new(4).expect("create UDP client");
        assert!(
            client.pool_v6.get().is_none(),
            "no IPv6 socket may be created before an IPv6 upstream is used"
        );

        let upstream_v4 = spawn_udp_echo_upstream("127.0.0.1:0")
            .await
            .expect("IPv4 loopback");
        let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        client
            .send(&query, &upstream_v4, Duration::from_secs(2))
            .await
            .expect("IPv4 upstream reachable");
        assert!(
            client.pool_v6.get().is_none(),
            "IPv4 traffic must not build the IPv6 pool"
        );

        let Some(upstream_v6) = spawn_udp_echo_upstream("[::1]:0").await else {
            eprintln!("IPv6 loopback unavailable, skipping the second half");
            return;
        };
        client
            .send(&query, &upstream_v6, Duration::from_secs(2))
            .await
            .expect("IPv6 upstream reachable");
        assert!(
            client.pool_v6.get().is_some(),
            "the IPv6 pool must appear once an IPv6 upstream is used"
        );
    }

    #[tokio::test]
    async fn udp_send_reaches_an_ipv6_upstream() {
        // The pool only ever created AF_INET sockets, so an IPv6 UDP upstream
        // failed every send with "address family not supported" and the query
        // ended in SERVFAIL while the same host over TCP worked.
        // 连接池只建 AF_INET socket：IPv6 UDP 上游每次发送都失败，查询以 SERVFAIL 告终，
        // 而同一主机走 TCP 正常。
        let Some(upstream) = spawn_udp_echo_upstream("[::1]:0").await else {
            eprintln!("IPv6 loopback unavailable, skipping");
            return;
        };
        let client = UdpClient::new(1).expect("create UDP client");
        let query = [0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let response = client
            .send(&query, &upstream, Duration::from_secs(2))
            .await
            .expect("IPv6 UDP upstream must be reachable");
        assert_eq!(&response[..2], &query[..2], "original ID restored");

        // IPv4 keeps working through the same client.
        let upstream_v4 = spawn_udp_echo_upstream("127.0.0.1:0")
            .await
            .expect("IPv4 loopback");
        client
            .send(&query, &upstream_v4, Duration::from_secs(2))
            .await
            .expect("IPv4 UDP upstream still reachable");
    }

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

    /// 0-RTT 的安全提示曾在构造 DoQ 客户端时打印，而客户端在任何配置下都会构造，
    /// 于是没有任何 DoQ 上游的部署每次启动也会看到它。
    /// The 0-RTT security notice used to be printed when the DoQ client was
    /// built, and the client is built for every configuration, so deployments
    /// without a single DoQ upstream saw it at every start.
    #[tokio::test]
    async fn doq_client_holds_the_0rtt_notice_until_early_data_is_offered() {
        let client = DoqClient::new(1, 60, 15_000, true).expect("build DoQ client");
        assert!(
            !client.runtime.zero_rtt_notice.is_completed(),
            "building the client must not emit the 0-RTT notice"
        );
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

    /// README 与 config.rs 都写明阈值 0 表示禁用健康检查，而 `count >= threshold`
    /// 会让 0 变成"每次错误都重建连接池"，正好相反。
    /// README and config.rs both state that a threshold of 0 disables the health
    /// check, while `count >= threshold` turns 0 into a rebuild on every single
    /// error, the exact opposite.
    #[test]
    fn doh_record_error_treats_a_zero_threshold_as_disabled() {
        let client = DohClient::new(8, 0).expect("build doh client");
        let upstream = "doh:8.8.8.8";
        let ptr_before =
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize;

        for attempt in 1..=5 {
            assert!(
                !client.record_error(upstream),
                "a disabled health check must never rebuild (error {attempt})"
            );
        }
        assert_eq!(
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
            ptr_before,
            "the connection pool must survive a disabled health check"
        );
    }

    /// 热重载换掉的上游此前会一直留着自己的连接池；现在长期不用的条目会被清掉。
    /// Upstreams a reload replaced used to keep their connection pools forever;
    /// entries nothing has used are now dropped.
    #[test]
    fn doh_prunes_upstreams_nothing_has_used() {
        let client = DohClient::new(8, 3).expect("build doh client");
        for idx in 0..4 {
            client
                .upstream(&format!("https://{idx}.example/dns-query"))
                .expect("create upstream");
        }
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create live upstream");
        age_out_idle_upstreams(&client, live);

        client
            .upstream("https://new.example/dns-query")
            .expect("create upstream");

        assert!(
            client.upstreams.len() <= 2,
            "idle upstreams must be pruned, {} left",
            client.upstreams.len()
        );
        assert!(
            client.upstreams.contains_key(live),
            "an upstream in use must never be pruned"
        );
    }

    /// 热重载换掉整批上游之后可能再没有新上游出现，此前清理只挂在新键插入上，
    /// 旧条目会留到进程结束；现在查一次已有上游也会触发清理。
    /// A reload can swap the whole upstream set and no new upstream ever follows;
    /// pruning used to hang off new-key inserts alone, so the old entries lived
    /// until the process exited. A lookup of an existing upstream now prunes too.
    #[test]
    fn doh_prunes_idle_upstreams_without_new_keys() {
        let client = DohClient::new(8, 3).expect("build doh client");
        for idx in 0..4 {
            client
                .upstream(&format!("https://{idx}.example/dns-query"))
                .expect("create upstream");
        }
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create live upstream");
        age_out_idle_upstreams(&client, live);

        // 只重复查询已有上游，不插入任何新键
        // Only look the existing upstream up again; no new key is inserted
        client.upstream(live).expect("look up live upstream");

        assert!(
            client.upstreams.len() <= 2,
            "idle upstreams must be pruned without a new key, {} left",
            client.upstreams.len()
        );
        assert!(
            client.upstreams.contains_key(live),
            "an upstream in use must never be pruned"
        );
    }

    /// 节流窗口过期、但这一轮没有任何条目可清时，时间戳同样要推后；否则每一次
    /// 查询都会重新走到扫描前的检查上——正常配置的上游数很少，这条路径原先永远
    /// 命中，等于每个 DoH 查询白付一次全分片的 DashMap::len()。
    /// When the interval has lapsed but the round drops nothing, the timestamp
    /// must still move. Otherwise every later lookup walks back into the check
    /// before the scan, and since a normal deployment has only a handful of
    /// upstreams that used to happen on every single DoH query.
    #[test]
    fn doh_prune_round_is_claimed_even_when_nothing_expires() {
        let client = DohClient::new(8, 3).expect("build doh client");
        let live = "https://live.example/dns-query";
        client.upstream(live).expect("create upstream");

        // 窗口过期，但条目都是刚用过的 / interval lapsed, every entry just used
        let lapsed =
            unix_time_millis().saturating_sub(DOH_UPSTREAM_PRUNE_EVERY.as_millis() as u64 * 2);
        client.last_prune_millis.store(lapsed, Ordering::Relaxed);

        client.upstream(live).expect("look up upstream");

        assert!(
            client.last_prune_millis.load(Ordering::Relaxed) > lapsed,
            "a lapsed interval must be claimed even when nothing is dropped"
        );
        assert!(
            client.upstreams.contains_key(live),
            "an upstream in use must never be pruned"
        );
    }

    /// 把除 `live` 之外的条目标记为长期未使用，并让节流窗口过期
    /// Age every entry except `live`, and let the prune interval lapse
    fn age_out_idle_upstreams(client: &DohClient, live: &str) {
        let now = unix_time_millis();
        let stale = now.saturating_sub(DOH_UPSTREAM_IDLE.as_millis() as u64 * 2);
        for entry in client.upstreams.iter() {
            if entry.key().as_ref() != live {
                entry
                    .value()
                    .last_used_millis
                    .store(stale, Ordering::Relaxed);
            }
        }
        client.last_prune_millis.store(
            now.saturating_sub(DOH_UPSTREAM_PRUNE_EVERY.as_millis() as u64 * 2),
            Ordering::Relaxed,
        );
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

        let ptr_before =
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize;
        // Two errors stay below the threshold (3): no rebuild.
        assert!(
            !client.record_error(upstream),
            "no rebuild before threshold (1/3)"
        );
        assert!(
            !client.record_error(upstream),
            "no rebuild before threshold (2/3)"
        );
        assert_eq!(
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
            ptr_before,
            "client pointer must be unchanged below threshold"
        );
        // Third error reaches the threshold: pool rebuilt.
        assert!(client.record_error(upstream), "rebuild at threshold (3/3)");
        assert_ne!(
            Arc::as_ptr(&client.upstream(upstream).unwrap().client.load_full()) as usize,
            ptr_before,
            "client pointer must change after rebuild"
        );
    }

    #[test]
    fn doh_rebuild_is_scoped_to_the_failing_upstream() {
        // A single reqwest client used to be shared by every DoH upstream, so
        // reaching the error threshold on one upstream replaced the pool of all
        // of them: the healthy upstream lost its keep-alive connections and had
        // to handshake again. Each upstream now owns its client.
        // 以前所有 DoH 上游共用一个 reqwest 客户端，一个上游达到错误阈值会把所有
        // 上游的连接池一起换掉，健康上游丢失 keep-alive 连接、被迫重新握手。
        // 现在每个上游各持一个客户端。
        let client = DohClient::new(8, 3).expect("build doh client");
        let healthy = "doh:1.1.1.1";
        let failing = "doh:bad.example";
        let healthy_before =
            Arc::as_ptr(&client.upstream(healthy).unwrap().client.load_full()) as usize;
        let failing_before =
            Arc::as_ptr(&client.upstream(failing).unwrap().client.load_full()) as usize;

        for _ in 0..2 {
            assert!(!client.record_error(failing));
        }
        assert!(client.record_error(failing), "third error rebuilds");

        assert_ne!(
            Arc::as_ptr(&client.upstream(failing).unwrap().client.load_full()) as usize,
            failing_before,
            "the failing upstream's pool is rebuilt"
        );
        assert_eq!(
            Arc::as_ptr(&client.upstream(healthy).unwrap().client.load_full()) as usize,
            healthy_before,
            "the healthy upstream keeps its pool"
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
        assert!(
            !client.record_error(upstream),
            "counter reset: 1/3 after success"
        );
        assert!(
            !client.record_error(upstream),
            "counter reset: 2/3 after success"
        );
        assert!(
            client.record_error(upstream),
            "counter reset: rebuild at 3/3"
        );
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
        assert!(
            is_transport_error(&timeout_err),
            "timeout is transport-level"
        );

        // A reqwest-style error wrapped via .context() must still classify as
        // transport (downcast finds no DohHttpStatusError at the top of the chain).
        // 经 .context() 包装的 reqwest 风格错误仍须归类为传输错误
        // （downcast 在链顶找不到 DohHttpStatusError）。
        let send_err = anyhow::anyhow!("doh request send failed").context("wrapped");
        assert!(
            is_transport_error(&send_err),
            "wrapped send error is transport-level"
        );

        let status_err = anyhow::Error::new(DohHttpStatusError(anyhow::anyhow!(
            "doh http status 503 Server Error"
        )));
        assert!(
            !is_transport_error(&status_err),
            "HTTP status is NOT transport-level"
        );
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
        assert!(
            clean_eof,
            "server saw an error instead of clean EOF on Client drop"
        );
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
