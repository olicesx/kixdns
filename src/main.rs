use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use kixdns::config::load_config;
use kixdns::engine::{Engine, FastPathResponse, PreParsedData, engine_helpers};
use kixdns::matcher::RuntimePipelineConfig;
use kixdns::proto_utils::{is_standard_query_header, truncate_udp_response};
use kixdns::watcher;

#[derive(Parser, Debug)]
#[command(author, version, about = "KixDNS async DNS with hot-reload pipelines", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run DNS server / 运行 DNS 服务器
    Run {
        /// 配置文件路径（JSON） / Config file path (JSON)
        #[arg(short = 'c', long = "config", default_value = "config/pipeline.json")]
        config: PathBuf,
        /// 监听实例标签，用于 pipeline 选择（可选）。 / Listener instance label for pipeline selection (optional)
        #[arg(long = "listener-label", default_value = "default")]
        listener_label: String,
        /// 启用调试日志 / Enable debug logging
        #[arg(long = "debug", default_value_t = false)]
        debug: bool,
        /// UDP worker 数量（默认 CPU 核心数） / Number of UDP workers (defaults to CPU core count)
        #[arg(long = "udp-workers", default_value_t = 0)]
        udp_workers_count: usize,
    },
    /// Convert GeoIP .dat to MMDB format / 转换 GeoIP .dat 为 MMDB 格式
    ConvertGeoIp {
        /// 输入 .dat 文件路径 / Input .dat file path
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// 输出 MMDB 文件路径 / Output MMDB file path
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// 过滤国家代码（逗号分隔，如 CN,US,JP）/ Filter country codes (comma-separated, e.g., CN,US,JP)
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        Some(Commands::ConvertGeoIp {
            input,
            output,
            filter,
        }) => {
            // Convert GeoIP .dat to MMDB
            let filter_countries: Option<Vec<String>> =
                filter.map(|f| f.split(',').map(|s| s.trim().to_uppercase()).collect());

            let filter_slice = filter_countries.as_deref();

            match kixdns::matcher::geoip::GeoIpManager::convert_dat_to_mmdb(
                &input,
                &output,
                filter_slice,
            ) {
                Ok(stats) => {
                    println!("Conversion completed successfully:\n{}", stats);
                    Ok(())
                }
                Err(e) => {
                    error!("Conversion failed: {}", e);
                    Err(e)
                }
            }
        }
        Some(Commands::Run {
            config,
            listener_label,
            debug,
            udp_workers_count,
        }) => run_dns_server(config, listener_label, debug, udp_workers_count).await,
        None => {
            // No subcommand provided - run DNS server with defaults
            run_dns_server(
                PathBuf::from("config/pipeline.json"),
                "default".to_string(),
                false,
                0,
            )
            .await
        }
    }
}

/// 运行 DNS 服务器 / Run DNS server
/// 提取公共逻辑以消除代码重复 / Extract common logic to eliminate code duplication
async fn run_dns_server(
    config: PathBuf,
    listener_label: String,
    debug: bool,
    udp_workers_count: usize,
) -> anyhow::Result<()> {
    // Run DNS server
    init_tracing(debug);

    // Install default CryptoProvider for rustls
    // 安装 rustls 的默认 CryptoProvider
    // This is required for rustls 0.23+ when multiple crypto backends are available
    // 当有多个加密后端可用时，rustls 0.23+ 需要此调用
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))?;

    let cfg = load_config(&config).context("load initial config")?;
    let cfg = RuntimePipelineConfig::from_config(cfg).context("compile matchers")?;
    let bind_addr: SocketAddr = cfg.settings.bind_udp.parse().context("parse bind addr")?;
    let bind_tcp: SocketAddr = cfg
        .settings
        .bind_tcp
        .parse()
        .context("parse tcp bind addr")?;

    // 在 cfg 被 move 到 Engine 之前提取 DoH 配置
    // Extract DoH config before cfg is moved into Engine
    let doh_config: Option<(SocketAddr, String, String, String)> =
        if let Some(ref bind_doh) = cfg.settings.bind_doh {
            let addr: SocketAddr = bind_doh.parse().context("parse doh bind addr")?;
            let cert = cfg
                .settings
                .doh_tls_cert
                .as_ref()
                .context("doh_tls_cert is required when bind_doh is set")?
                .clone();
            let key = cfg
                .settings
                .doh_tls_key
                .as_ref()
                .context("doh_tls_key is required when bind_doh is set")?
                .clone();
            let path = cfg.settings.doh_path.clone();
            Some((addr, cert, key, path))
        } else {
            None
        };

    let engine = Engine::new(cfg, listener_label.clone()).context("initialize DNS engine")?;

    watcher::spawn(config.clone(), engine.clone());

    // UDP worker 数量：默认为 CPU 核心数，最少 1 个 / UDP worker count: defaults to CPU core count, minimum 1
    let udp_workers_final = if udp_workers_count > 0 {
        udp_workers_count
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    };

    info!(bind_udp = %bind_addr, bind_tcp = %bind_tcp, udp_workers_count = udp_workers_final, "dns server started");

    let mut all_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    #[cfg(unix)]
    {
        // ✅ OpenBSD 兼容性方案：双 socket（IPv4 + IPv6）+ 零拷贝 recv_buf_from
        // ✅ OpenBSD compatibility: dual sockets (IPv4 + IPv6) + zero-copy recv_buf_from
        // 为每个地址族创建独立的 socket 和 workers，避免 sockaddr 大小断言失败
        // Create separate sockets and workers for each address family to avoid sockaddr size assertion failures

        // ✅ OpenBSD 兼容性方案：双 socket（IPv4 + IPv6）+ 零拷贝 recv_buf_from
        // ✅ OpenBSD compatibility: dual sockets (IPv4 + IPv6) + zero-copy recv_buf_from
        // 为每个地址族创建独立的 socket 和 workers，避免 sockaddr 大小断言失败
        // Create separate sockets and workers for each address family to avoid sockaddr size assertion failures

        // 根据配置地址决定创建哪种 socket / Determine which socket type to create based on config
        // IPv6 unspecified address (::) 需要同时创建 IPv4 和 IPv6 socket
        // IPv6 other addresses 只创建 IPv6 socket
        // IPv4 addresses 只创建 IPv4 socket
        let needs_ipv4 =
            bind_addr.is_ipv4() || (bind_addr.is_ipv6() && bind_addr.ip().is_unspecified());
        let needs_ipv6 = bind_addr.is_ipv6();

        if needs_ipv4 {
            let workers_per_family = if needs_ipv6 {
                udp_workers_final.div_ceil(2)
            } else {
                udp_workers_final
            };
            spawn_ipv4_udp_workers(
                bind_addr,
                workers_per_family,
                engine.clone(),
                &mut all_handles,
            )?;
        }

        if needs_ipv6 {
            let workers_per_family = if needs_ipv4 {
                udp_workers_final.div_ceil(2)
            } else {
                udp_workers_final
            };
            spawn_ipv6_udp_workers(
                bind_addr,
                workers_per_family,
                engine.clone(),
                &mut all_handles,
            )?;
        }
    }

    #[cfg(not(unix))]
    {
        // Non-Unix: create a single shared socket and spawn workers that share it / 非 Unix：创建单个共享套接字并生成共享它的工作线程
        // Use socket2 to set buffer sizes / 使用 socket2 设置缓冲区大小
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket =
            Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create socket")?;

        // ✅ Windows 上设置 IPV6_V6ONLY=0 以支持双栈，与 Linux 行为一致
        // ✅ On Windows, set IPV6_V6ONLY=0 for dual-stack support, consistent with Linux behavior
        if domain == Domain::IPV6 {
            if let Err(e) = socket.set_only_v6(false) {
                debug!(
                    "failed to set IPV6_V6ONLY=0: {}, IPv4 may not work on [::] bind",
                    e
                );
            } else {
                info!("UDP IPv6 socket set to dual-stack mode (IPV6_V6ONLY=0)");
            }
        }

        // Set buffer sizes to prevent packet loss under load
        // Try 4MB first, then fall back to 1MB if it fails
        let desired_size = 4 * 1024 * 1024;
        let fallback_size = 1024 * 1024;

        if let Err(e) = socket.set_recv_buffer_size(desired_size) {
            debug!(
                "failed to set udp recv buffer to {} bytes: {}, trying {}",
                desired_size, e, fallback_size
            );
            let _ = socket.set_recv_buffer_size(fallback_size);
        }
        if let Err(e) = socket.set_send_buffer_size(desired_size) {
            debug!(
                "failed to set udp send buffer to {} bytes: {}, trying {}",
                desired_size, e, fallback_size
            );
            let _ = socket.set_send_buffer_size(fallback_size);
        }

        socket.set_nonblocking(true).context("set nonblocking")?;
        socket.bind(&bind_addr.into()).context("bind socket")?;

        let udp_socket = Arc::new(UdpSocket::from_std(socket.into()).context("from_std")?);
        for worker_id in 0..udp_workers_final {
            let engine = engine.clone();
            let socket = Arc::clone(&udp_socket);
            let handle = tokio::spawn(async move {
                if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                    error!(worker_id, error = %err, "udp worker exited");
                }
            });
            all_handles.push(handle);
        }
    }

    // TCP listener / TCP 监听器
    // ✅ 双 socket 方案，与 UDP 行为一致 / Dual-socket approach, consistent with UDP
    let needs_ipv4_tcp =
        bind_tcp.is_ipv4() || (bind_tcp.is_ipv6() && bind_tcp.ip().is_unspecified());

    // --- 启动 IPv4 TCP 监听 / Start IPv4 TCP listener ---
    if needs_ipv4_tcp {
        let addr = if bind_tcp.is_ipv4() {
            bind_tcp
        } else {
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                bind_tcp.port(),
            )
        };
        // 纯 IPv4 绑定，不受 bindv6only 影响 / Pure IPv4 bind, unaffected by bindv6only
        let listener = TcpListener::bind(addr).await.context("bind ipv4 tcp")?;
        let engine = engine.clone();
        let h = tokio::spawn(async move {
            if let Err(err) = run_tcp(listener, engine).await {
                error!(error = %err, "ipv4 tcp server exited");
            }
        });
        all_handles.push(h);
    }

    // --- 启动 IPv6 TCP 监听 / Start IPv6 TCP listener ---
    if bind_tcp.is_ipv6() {
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;

        // ⭐️ 核心：强制 IPV6_V6ONLY=1，避免和 IPv4 监听器冲突
        // ⭐️ Key: force IPV6_V6ONLY=1 to avoid conflict with IPv4 listener
        socket
            .set_only_v6(true)
            .context("set ipv6 only for kixdns")?;
        socket.set_reuse_address(true)?;

        socket
            .bind(&bind_tcp.into())
            .context("bind ipv6 tcp socket")?;
        socket.listen(128)?;
        socket.set_nonblocking(true)?;

        let listener = TcpListener::from_std(socket.into())?;
        let engine = engine.clone();
        let h = tokio::spawn(async move {
            if let Err(err) = run_tcp(listener, engine).await {
                error!(error = %err, "ipv6 tcp server exited");
            }
        });
        all_handles.push(h);
    }

    // DoH listener — 仅在配置了 bind_doh 时启动 / DoH listener — only if bind_doh is configured
    if let Some((doh_addr, cert_path, key_path, doh_path)) = doh_config {
        let engine = engine.clone();
        let h = tokio::spawn(async move {
            if let Err(err) =
                kixdns::doh_server::run_doh(doh_addr, &cert_path, &key_path, engine, doh_path).await
            {
                error!(error = %err, "DoH server exited");
            }
        });
        all_handles.push(h);
    }

    // 等待所有任务 / Wait for all tasks
    for h in all_handles {
        let _ = h.await;
    }

    Ok(())
}

fn init_tracing(debug: bool) {
    // 默认仅保留错误日志以平衡性能与可观测性，除非显式指定
    // Default to error-level logging to balance performance with observability unless explicitly enabled
    let fmt_layer = fmt::layer()
        .with_timer(fmt::time::LocalTime::rfc_3339())
        .with_target(false)
        .with_ansi(false)
        .with_level(debug);

    let level = if debug { "debug" } else { "error" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

// 为 IPv4 地址创建并启动 UDP workers / Create and spawn UDP workers for IPv4 address
#[cfg(unix)]
fn spawn_ipv4_udp_workers(
    bind_addr: SocketAddr,
    worker_count: usize,
    engine: Engine,
    all_handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let ipv4_addr: SocketAddr = if bind_addr.is_ipv4() {
        bind_addr
    } else {
        // 预编译的常量地址，避免 unwrap / Precompiled constant address, avoid unwrap
        // 使用配置中的端口号而非硬编码 / Use port from config instead of hardcoded
        SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            bind_addr.port(),
        )
    };

    info!(bind_addr = %ipv4_addr, workers = worker_count, "Starting IPv4 UDP workers");

    // ✅ Per-worker SO_REUSEPORT_LB sockets: each worker gets its own fd.
    // On FreeBSD, SO_REUSEPORT_LB enables kernel hash-based packet distribution
    // across sockets. On Linux, SO_REUSEPORT already includes this behavior.
    // This gives perfect multi-core scaling with zero contention — each worker
    // owns its socket, no Arc<UdpSocket> sharing, no reactor thundering herd.
    //
    // ✅ 每 worker 独立 SO_REUSEPORT_LB socket：每个 worker 拥有自己的 fd。
    // FreeBSD 上 SO_REUSEPORT_LB 启用内核级哈希分发，
    // Linux 上 SO_REUSEPORT 已自带此行为。
    // 实现无竞争的多核扩展——每个 worker 独占 socket，
    // 无 Arc<UdpSocket> 共享，无 reactor 惊群效应。
    for worker_id in 0..worker_count {
        let engine = engine.clone();
        let std_socket = create_reuseport_udp_socket(ipv4_addr)
            .with_context(|| format!("create ipv4 udp socket for worker {}", worker_id))?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let handle = tokio::spawn(async move {
            if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                error!(worker_id, error = %err, "IPv4 udp worker exited");
            }
        });
        all_handles.push(handle);
    }

    Ok(())
}

// 为 IPv6 地址创建并启动 UDP workers / Create and spawn UDP workers for IPv6 address
#[cfg(unix)]
fn spawn_ipv6_udp_workers(
    bind_addr: SocketAddr,
    worker_count: usize,
    engine: Engine,
    all_handles: &mut Vec<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let ipv6_addr: SocketAddr = if bind_addr.is_ipv6() {
        bind_addr
    } else {
        // 预编译的常量地址，避免 unwrap / Precompiled constant address, avoid unwrap
        // 使用配置中的端口号而非硬编码 / Use port from config instead of hardcoded
        SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            bind_addr.port(),
        )
    };

    info!(bind_addr = %ipv6_addr, workers = worker_count, "Starting IPv6 UDP workers");

    // ✅ Per-worker SO_REUSEPORT_LB sockets (same rationale as IPv4)
    // ✅ 每 worker 独立 SO_REUSEPORT_LB socket（同 IPv4）
    for worker_id in 0..worker_count {
        let engine = engine.clone();
        let std_socket = create_reuseport_udp_socket(ipv6_addr)
            .with_context(|| format!("create ipv6 udp socket for worker {}", worker_id))?;
        let socket = Arc::new(UdpSocket::from_std(std_socket)?);
        let handle = tokio::spawn(async move {
            if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                error!(worker_id, error = %err, "IPv6 udp worker exited");
            }
        });
        all_handles.push(handle);
    }

    Ok(())
}

// 在 Unix 上创建带 SO_REUSEPORT 的 UDP socket；非 Unix 使用标准绑定 / Create UDP socket with SO_REUSEPORT on Unix; use standard binding on non-Unix
#[cfg(unix)]
fn create_reuseport_udp_socket(addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;

    // ✅ OpenBSD/FreeBSD 安全措施：为 IPv6 socket 显式设置 IPV6_V6ONLY=1
    // ✅ OpenBSD/FreeBSD safety: explicitly set IPV6_V6ONLY=1 for IPv6 sockets
    // 双 socket 方案下，IPv6 socket 只处理 IPv6 流量，确保地址族一致性，避免 sockaddr 大小断言失败
    // With dual-socket approach, IPv6 socket only handles IPv6 traffic, ensuring address family consistency
    // 这使得我们可以安全地使用零拷贝的 recv_buf_from
    // This allows us to safely use zero-copy recv_buf_from
    if domain == Domain::IPV6
        && let Err(e) = kixdns::socket_utils::set_ipv6_v6only(&socket, true)
    {
        tracing::warn!(
            "Failed to set IPV6_V6ONLY=1: {}, this may cause issues on OpenBSD",
            e
        );
    }

    // Try to set SO_REUSEPORT_LB (FreeBSD) or SO_REUSEPORT (Linux) via safe wrapper
    // 尝试通过安全封装设置 SO_REUSEPORT_LB (FreeBSD) 或 SO_REUSEPORT (Linux)
    if let Err(e) = kixdns::socket_utils::set_reuseport_lb(&socket) {
        // Log warning if SO_REUSEPORT_LB fails / SO_REUSEPORT_LB 失败时记录警告
        tracing::warn!(
            "SO_REUSEPORT_LB failed: {}, falling back to plain SO_REUSEPORT",
            e
        );
        if let Err(e2) = kixdns::socket_utils::set_reuseport(&socket, true) {
            tracing::warn!("SO_REUSEPORT also failed: {}", e2);
        }
    }

    // Set buffer sizes to prevent packet loss under load
    // Try 4MB first, then fall back to 1MB if it fails
    let desired_size = 4 * 1024 * 1024;
    let fallback_size = 1024 * 1024;

    if let Err(e) = socket.set_recv_buffer_size(desired_size) {
        debug!(
            "failed to set udp recv buffer to {} bytes: {}, trying {}",
            desired_size, e, fallback_size
        );
        let _ = socket.set_recv_buffer_size(fallback_size);
    }
    if let Err(e) = socket.set_send_buffer_size(desired_size) {
        debug!(
            "failed to set udp send buffer to {} bytes: {}, trying {}",
            desired_size, e, fallback_size
        );
        let _ = socket.set_send_buffer_size(fallback_size);
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// 构造严格校验的 SERVFAIL（仅合法标准查询；畸形/响应包返回 None 静默）
/// Build strict SERVFAIL for validated standard queries only (malformed/response packets stay silent)
fn listener_servfail(request: &[u8]) -> Option<bytes::Bytes> {
    engine_helpers::try_build_servfail_response_from_wire(request)
}

/// 发送 UDP 数据报：try_send_to 优先（避免 reactor 开销），WouldBlock 回退异步
/// Send UDP datagram: try non-blocking first, async fallback on WouldBlock
async fn send_udp_datagram(
    socket: &UdpSocket,
    data: &[u8],
    peer: SocketAddr,
) -> std::io::Result<usize> {
    match socket.try_send_to(data, peer) {
        Ok(sent) => Ok(sent),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            socket.send_to(data, peer).await
        }
        Err(error) => Err(error),
    }
}

/// 发送 UDP 响应：超限响应截断（RFC 6891）+ try_send_to 优先，WouldBlock 回退异步
/// Send UDP response: truncate oversized (RFC 6891), try non-blocking first, async fallback on WouldBlock
async fn send_udp_response(socket: &UdpSocket, request: &[u8], response: &[u8], peer: SocketAddr) {
    // 截断超限响应，避免 UDP 报文超过客户端声明上限 / Truncate to the client's advertised UDP limit
    let truncated = truncate_udp_response(request, response);
    let response = truncated.as_deref().unwrap_or(response);
    if let Err(error) = send_udp_datagram(socket, response, peer).await {
        debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
    }
}

/// 非阻塞发送 UDP 响应（过载保护路径）：截断 + 纯 try_send_to，WouldBlock 背压丢弃
/// Non-blocking UDP send for overload paths: truncate + try_send_to only; drop on WouldBlock
fn try_send_udp_response(socket: &UdpSocket, request: &[u8], response: &[u8], peer: SocketAddr) {
    let truncated = truncate_udp_response(request, response);
    let response = truncated.as_deref().unwrap_or(response);
    if let Err(error) = socket.try_send_to(response, peer)
        && error.kind() != std::io::ErrorKind::WouldBlock
    {
        debug!(%peer, %error, response_len = response.len(), "failed to send UDP response");
    }
    // WouldBlock: 发送缓冲满，丢弃（背压）/ send buffer full, drop (backpressure)
}

/// 异步发送 SERVFAIL（处理失败/超时路径）
async fn send_udp_servfail(socket: &UdpSocket, request: &[u8], peer: SocketAddr) {
    let Some(response) = listener_servfail(request) else {
        return;
    };
    send_udp_response(socket, request, &response, peer).await;
}

/// 非阻塞发送 SERVFAIL（permit 耗尽路径，避免阻塞接收循环）
fn try_send_udp_servfail(socket: &UdpSocket, request: &[u8], peer: SocketAddr) {
    let Some(response) = listener_servfail(request) else {
        return;
    };
    try_send_udp_response(socket, request, &response, peer);
}

/// 高性能 UDP worker：直接在接收循环中处理请求，避免 spawn 开销 / High-performance UDP worker: process requests directly in receive loop, avoiding spawn overhead
async fn run_udp_worker(
    worker_id: usize,
    socket: Arc<UdpSocket>,
    engine: Engine,
) -> anyhow::Result<()> {
    // 预分配缓冲区 / Pre-allocate buffer
    // 使用 BytesMut 避免 Bytes::copy_from_slice 的内存分配 / Use BytesMut to avoid memory allocation in Bytes::copy_from_slice
    use bytes::BytesMut;
    let mut buf = BytesMut::with_capacity(4096);
    // 复用发送缓冲区：用于缓存命中时 patch TXID，避免每包堆分配 / Reuse send buffer to patch TXID on cache hits, avoiding per-packet heap allocation
    let mut send_buf = BytesMut::with_capacity(512);

    // 自适应流控：每 100 个请求检查一次是否需要调整 permits
    // Adaptive flow control: check if adjustment needed every 100 requests
    let mut request_count = 0u32;

    info!(worker_id, "UDP worker started");

    loop {
        // 确保有足够的空间 / Ensure sufficient space
        if buf.capacity() < 4096 {
            buf.reserve(4096 - buf.len());
        }

        // ✅ Hybrid recv: try non-blocking first, fall back to async on EAGAIN.
        // Under load, this eliminates tokio reactor overhead (epoll_wait +
        // task wake/schedule cycle) per packet. Under no load, falls back to
        // async await so the worker yields and doesn't waste CPU.
        //
        // ✅ 混合接收：先尝试非阻塞，EAGAIN 时回退到异步。
        // 高负载时消除每包的 tokio reactor 开销（epoll_wait + 任务唤醒/调度循环）。
        // 空闲时回退到异步 await，worker 让出 CPU 不浪费。
        let (_len, peer) = match socket.try_recv_buf_from(&mut buf) {
            Ok(result) => result,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No packet available right now — yield to tokio / 当前无包可读 — 让出 tokio
                match socket.recv_buf_from(&mut buf).await {
                    Ok(result) => result,
                    Err(_) => continue,
                }
            }
            Err(_) => continue,
        };
        {
            // 零拷贝获取 Bytes / Zero-copy obtain Bytes
            let packet_bytes = buf.split().freeze();
            if !is_standard_query_header(&packet_bytes) {
                continue;
            }

            // 每 100 个请求检查一次流控调整 / Check flow control adjustment every 100 requests
            request_count += 1;
            if request_count >= 100 {
                request_count = 0;
                engine.adjust_flow_control(); // Now synchronous with atomic CAS
            }

            // ✅ 优化：使用 handle_packet_fast 避免重复解析
            // ✅ Optimization: Use handle_packet_fast to avoid re-parsing
            // 如果缓存命中，直接返回；如果缓存未命中，返回预解析的数据
            // If cache hit, return directly; if cache miss, return pre-parsed data
            match engine.handle_packet_fast(&packet_bytes, peer) {
                Ok(Some(FastPathResponse::Direct(bytes))) => {
                    // 已包含正确 TXID，可直接发送 / Already contains correct TXID
                    send_udp_response(&socket, &packet_bytes, &bytes, peer).await;
                }
                Ok(Some(FastPathResponse::CacheHit {
                    cached,
                    tx_id,
                    inserted_at,
                })) => {
                    // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                    let elapsed =
                        kixdns::proto_utils::saturating_u64_to_u32(inserted_at.elapsed().as_secs());

                    if elapsed == 0 && cached.len() >= 2 {
                        // Fast path: TTL hasn't decayed, only TXID (2 bytes) needs patching.
                        // Copy to reusable send_buf, patch TXID only, use try_send_to
                        // (non-blocking) to avoid tokio reactor overhead. Falls back to
                        // async send_to on EAGAIN.
                        //
                        // 快速路径：TTL 未衰减，只需 patch TXID（2 字节）。
                        // 拷贝到复用的 send_buf，仅 patch TXID，使用 try_send_to（非阻塞）
                        // 避免 tokio reactor 开销。EAGAIN 时回退到异步 send_to。
                        send_buf.clear();
                        send_buf.extend_from_slice(&cached);
                        let id_bytes = tx_id.to_be_bytes();
                        send_buf[0] = id_bytes[0];
                        send_buf[1] = id_bytes[1];
                        send_udp_response(&socket, &packet_bytes, &send_buf, peer).await;
                    } else {
                        // Slow path: TTL has decayed, must patch all TTLs in-place.
                        // 慢速路径：TTL 已衰减，必须原地 patch 所有 TTL。
                        send_buf.clear();
                        if send_buf.capacity() < cached.len() {
                            send_buf.reserve(cached.len() - send_buf.capacity());
                        }
                        send_buf.extend_from_slice(&cached);
                        if elapsed > 0 {
                            kixdns::proto_utils::patch_all_ttls(&mut send_buf, elapsed);
                        }
                        if send_buf.len() >= 2 {
                            let id_bytes = tx_id.to_be_bytes();
                            send_buf[0] = id_bytes[0];
                            send_buf[1] = id_bytes[1];
                        }
                        send_udp_response(&socket, &packet_bytes, &send_buf, peer).await;
                    }
                }
                Ok(Some(FastPathResponse::AsyncNeeded {
                    qname,
                    qtype,
                    qclass,
                    tx_id,
                    edns_present,
                    pipeline_id,
                    ecs_key,
                })) => {
                    // 缓存未命中，使用预解析的数据避免重复解析
                    // Cache miss, use pre-parsed data to avoid re-parsing
                    let permit_mgr = Arc::clone(&engine.permit_manager);
                    let timeout_ms = engine.get_request_timeout_ms();
                    let timeout_dur = Duration::from_millis(timeout_ms);

                    // 非阻塞式 try_acquire，避免在接收循环中 await / Non-blocking try_acquire to avoid await in receive loop
                    if let Some(permit) = permit_mgr.try_acquire() {
                        let engine = engine.clone();
                        let socket = Arc::clone(&socket);
                        let packet_bytes = packet_bytes.clone();
                        tokio::spawn(async move {
                            let _permit = permit; // 自动释放 / Auto-release on drop

                            // ✅ 传递预解析数据给 handle_packet_internal，避免重复解析
                            // ✅ Pass pre-parsed data to handle_packet_internal to avoid re-parsing
                            match tokio::time::timeout(
                                timeout_dur,
                                engine.handle_packet_internal_with_pre_parsed(
                                    &packet_bytes,
                                    peer,
                                    false,
                                    PreParsedData::new(
                                        qname,
                                        qtype,
                                        qclass,
                                        tx_id,
                                        edns_present,
                                        pipeline_id,
                                        ecs_key,
                                    ),
                                ),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    send_udp_response(&socket, &packet_bytes, &resp, peer).await;
                                }
                                Ok(Err(e)) => {
                                    debug!(error = %e, "handle_packet error, returning SERVFAIL");
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                                Err(_) => {
                                    warn!(
                                        timeout_ms,
                                        upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                                        "request timeout after hedge and fallback exhausted"
                                    );
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                            }
                        });
                    } else {
                        // 过载保护：permit 耗尽，用预解析数据快速构造 SERVFAIL 并非阻塞发送（背压丢弃）
                        // Overload: permit exhausted, fast SERVFAIL from pre-parsed data with non-blocking send
                        if let Ok(resp) = engine_helpers::build_servfail_response_fast(
                            tx_id,
                            &qname,
                            qtype,
                            qclass,
                            packet_bytes[2] & 0x01 != 0,
                        ) {
                            try_send_udp_response(&socket, &packet_bytes, &resp, peer);
                        }
                    }
                }
                Ok(None) => {
                    // 快速解析失败，回退到完整处理
                    // Fast parse failed, fallback to full processing
                    let permit_mgr = Arc::clone(&engine.permit_manager);
                    let timeout_ms = engine.get_request_timeout_ms();
                    let timeout_dur = Duration::from_millis(timeout_ms);

                    // 非阻塞式 try_acquire，避免在接收循环中 await / Non-blocking try_acquire to avoid await in receive loop
                    if let Some(permit) = permit_mgr.try_acquire() {
                        let engine = engine.clone();
                        let socket = Arc::clone(&socket);
                        let packet_bytes = packet_bytes.clone();
                        tokio::spawn(async move {
                            let _permit = permit; // 自动释放 / Auto-release on drop
                            match tokio::time::timeout(
                                timeout_dur,
                                engine.handle_packet(&packet_bytes, peer),
                            )
                            .await
                            {
                                Ok(Ok(resp)) => {
                                    send_udp_response(&socket, &packet_bytes, &resp, peer).await;
                                }
                                Ok(Err(e)) => {
                                    debug!(error = %e, "handle_packet error, returning SERVFAIL");
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                                Err(_) => {
                                    warn!(
                                        timeout_ms,
                                        upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                                        "request timeout"
                                    );
                                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                                }
                            }
                        });
                    } else {
                        // 过载保护：permit 耗尽，非阻塞 SERVFAIL（背压丢弃，不阻塞接收循环）
                        // Overload: permit exhausted, non-blocking SERVFAIL with backpressure drop
                        try_send_udp_servfail(&socket, &packet_bytes, peer);
                    }
                }
                Err(error) => {
                    debug!(%error, "UDP fast-path error, returning SERVFAIL for valid query");
                    send_udp_servfail(&socket, &packet_bytes, peer).await;
                }
            }
        }
    }
}

async fn run_tcp(listener: TcpListener, engine: Engine) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        // RFC 1035 §4.2.2: DNS-over-TCP uses a 2-byte length prefix per message.
        // Disable Nagle's algorithm (TCP_NODELAY) to prevent the length-prefix write
        // and body write from being coalesced, which interacts badly with the peer's
        // delayed-ACK timer and adds ~40 ms latency per query.
        //
        // 禁用 Nagle 算法 (TCP_NODELAY)，避免长度前缀和包体两次写入被合并，
        // 否则与对端的 delayed-ACK 定时器交互导致每查询约 40ms 延迟。
        stream.set_nodelay(true).ok();
        let engine = engine.clone();
        tokio::spawn(async move {
            let _ = handle_tcp_conn(stream, peer, engine).await;
        });
    }
}

async fn handle_tcp_conn(
    mut stream: TcpStream,
    peer: SocketAddr,
    engine: Engine,
) -> anyhow::Result<()> {
    const MAX_TCP_FRAME: usize = 64 * 1024;
    let mut len_buf = [0u8; 2];

    // ✅ 获取整体请求超时（包含 hedge + TCP fallback）
    // ✅ Get overall request timeout (including hedge + TCP fallback)
    let timeout_ms = engine.get_request_timeout_ms();

    // Reusable buffer to avoid per-frame heap allocation / 可复用缓冲区，避免每帧堆分配
    // 使用 BytesMut 以支持零拷贝操作 / Use BytesMut for zero-copy operations
    let mut buf = bytes::BytesMut::with_capacity(MAX_TCP_FRAME);

    loop {
        if let Err(err) = stream.read_exact(&mut len_buf).await {
            if err.kind() != std::io::ErrorKind::UnexpectedEof {
                return Err(err.into());
            }
            return Ok(());
        }
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        if frame_len == 0 || frame_len > MAX_TCP_FRAME {
            return Ok(());
        }

        // Reuse buffer: resize to exact frame length / 复用缓冲区：调整到精确帧长度
        // resize() is safe and efficient - it only initializes new bytes if growing
        buf.clear();
        buf.resize(frame_len, 0);
        if stream.read_exact(&mut buf).await.is_err() {
            return Ok(());
        }

        // ✅ 优化：使用 handle_packet_fast 进行快速路径检查
        // ✅ Optimization: Use handle_packet_fast for fast path check
        // 统一 UDP 和 TCP 的行为，避免重复解析
        // Unify UDP and TCP behavior to avoid re-parsing
        let packet_bytes = buf.split().freeze();
        if !is_standard_query_header(&packet_bytes) {
            return Ok(());
        }
        let timeout_dur = Duration::from_millis(timeout_ms);

        let resp = match engine.handle_packet_fast(&packet_bytes, peer) {
            Ok(Some(FastPathResponse::Direct(bytes))) => {
                // 快速路径命中：直接返回 / Fast path hit: return directly
                bytes
            }
            Ok(Some(FastPathResponse::CacheHit {
                cached,
                tx_id,
                inserted_at,
            })) => {
                // 缓存命中：patch TXID / Cache hit: patch TXID
                let mut resp_buf = bytes::BytesMut::with_capacity(cached.len());
                resp_buf.extend_from_slice(&cached);

                // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                let elapsed =
                    kixdns::proto_utils::saturating_u64_to_u32(inserted_at.elapsed().as_secs());
                if elapsed > 0 {
                    kixdns::proto_utils::patch_all_ttls(&mut resp_buf, elapsed);
                }

                if resp_buf.len() >= 2 {
                    let id_bytes = tx_id.to_be_bytes();
                    resp_buf[0] = id_bytes[0];
                    resp_buf[1] = id_bytes[1];
                }
                resp_buf.freeze()
            }
            Ok(Some(FastPathResponse::AsyncNeeded {
                qname,
                qtype,
                qclass,
                tx_id,
                edns_present,
                pipeline_id,
                ecs_key,
            })) => {
                // 缓存未命中：使用预解析数据避免重复解析
                // Cache miss: use pre-parsed data to avoid re-parsing
                match tokio::time::timeout(
                    timeout_dur,
                    engine.handle_packet_internal_with_pre_parsed(
                        &packet_bytes,
                        peer,
                        false,
                        PreParsedData::new(
                            qname,
                            qtype,
                            qclass,
                            tx_id,
                            edns_present,
                            pipeline_id,
                            ecs_key,
                        ),
                    ),
                )
                .await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(error)) => {
                        debug!(%error, "TCP request processing error, returning SERVFAIL");
                        let Some(response) = listener_servfail(&packet_bytes) else {
                            return Ok(());
                        };
                        response
                    }
                    Err(_) => {
                        warn!(
                            timeout_ms,
                            upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                            "TCP request timeout after hedge and fallback exhausted"
                        );
                        let Some(response) = listener_servfail(&packet_bytes) else {
                            return Ok(());
                        };
                        response
                    }
                }
            }
            Ok(None) => {
                // 快速解析失败，回退到完整处理
                // Fast parse failed, fallback to full processing
                match tokio::time::timeout(timeout_dur, engine.handle_packet(&packet_bytes, peer))
                    .await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(error)) => {
                        debug!(%error, "TCP request processing error, returning SERVFAIL");
                        let Some(response) = listener_servfail(&packet_bytes) else {
                            return Ok(());
                        };
                        response
                    }
                    Err(_) => {
                        warn!(
                            timeout_ms,
                            upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                            "TCP request timeout"
                        );
                        let Some(response) = listener_servfail(&packet_bytes) else {
                            return Ok(());
                        };
                        response
                    }
                }
            }
            Err(error) => {
                debug!(%error, "TCP fast-path error, returning SERVFAIL for valid query");
                let Some(response) = listener_servfail(&packet_bytes) else {
                    return Ok(());
                };
                response
            }
        };

        if resp.len() <= u16::MAX as usize {
            // DNS-over-TCP framing must be written completely; a successful
            // write_vectored call may still be partial.
            // write_vectored 可能部分写入，必须用 write_all 保证完整帧。
            let mut frame = Vec::with_capacity(2 + resp.len());
            frame.extend_from_slice(&(resp.len() as u16).to_be_bytes());
            frame.extend_from_slice(&resp);
            if stream.write_all(&frame).await.is_err() {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinDecodable;
    use std::str::FromStr;

    #[ctor::ctor]
    fn init_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    fn static_engine() -> Engine {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:9" },
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "static",
                    "matchers": [{ "type": "any" }],
                    "actions": [{ "type": "static_ip_response", "ip": "192.0.2.1" }]
                }]
            }]
        }))
        .expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
        Engine::new(runtime, "test".to_string()).expect("initialize engine")
    }

    fn dns_query() -> Vec<u8> {
        let mut message = Message::new(0xCAFE, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_str("data.xiaoheihe.cn").unwrap(),
            RecordType::A,
        ));
        message.to_vec().unwrap()
    }

    #[tokio::test]
    async fn udp_static_fast_path_rejects_non_query_and_malformed_additional_records() {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), static_engine()));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut qr_response = dns_query();
        qr_response[2] |= 0x80;

        let mut missing_additional = dns_query();
        missing_additional[11] = 1;

        let mut truncated_edns = dns_query();
        truncated_edns[11] = 1;
        truncated_edns.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 4, 0, 1]);

        let mut invalid_pointer = dns_query();
        invalid_pointer[11] = 1;
        invalid_pointer.extend_from_slice(&[0xC0, 0xFF, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);

        let mut response_buf = [0u8; 512];
        for (case, packet) in [
            ("QR=1", qr_response),
            ("missing Additional RR", missing_additional),
            ("truncated EDNS RDATA", truncated_edns),
            ("invalid Additional compression pointer", invalid_pointer),
        ] {
            client.send_to(&packet, server_addr).await.unwrap();
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    client.recv_from(&mut response_buf),
                )
                .await
                .is_err(),
                "{case} must be rejected before static/cache fast paths"
            );
        }

        worker.abort();
    }

    fn forwarding_engine() -> Engine {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": "127.0.0.1:9",
                "flow_control_enabled": true,
                "flow_control_initial_permits": 1,
                "flow_control_min_permits": 1,
                "flow_control_max_permits": 1
            },
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{
                        "type": "forward",
                        "upstream": "127.0.0.1:9",
                        "transport": "udp"
                    }]
                }]
            }]
        }))
        .expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
        Engine::new(runtime, "test".to_string()).expect("initialize engine")
    }

    fn doh_timeout_engine(upstream: &str) -> Engine {
        use kixdns::config::PipelineConfig;

        let config: PipelineConfig = serde_json::from_value(serde_json::json!({
            "settings": {
                "default_upstream": upstream,
                "upstream_timeout_ms": 50,
                "request_timeout_ms": 50
            },
            "pipelines": [{
                "id": "p",
                "rules": [{
                    "name": "forward",
                    "matchers": [{ "type": "any" }],
                    "actions": [{
                        "type": "forward",
                        "upstream": upstream,
                        "transport": "doh"
                    }]
                }]
            }]
        }))
        .expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(config).expect("build runtime config");
        Engine::new(runtime, "test".to_string()).expect("initialize engine")
    }

    #[tokio::test]
    async fn udp_send_datagram_surfaces_socket_errors() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ipv6_peer: SocketAddr = "[::1]:53".parse().unwrap();
        assert!(send_udp_datagram(&socket, b"dns", ipv6_peer).await.is_err());
    }

    #[tokio::test]
    async fn udp_permit_exhaustion_returns_servfail_but_malformed_packet_is_silent() {
        let engine = forwarding_engine();
        engine.permit_manager.set_max_permits(0);

        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client.send_to(&dns_query(), server_addr).await.unwrap();
        let mut response_buf = [0u8; 512];
        let (response_len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
                .await
                .expect("valid query should receive a response")
                .unwrap();
        let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
        assert_eq!(response.metadata.id, 0xCAFE);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);

        client.send_to(&[0x12, 0x34], server_addr).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                client.recv_from(&mut response_buf),
            )
            .await
            .is_err(),
            "malformed UDP packets must not receive a reflected response"
        );

        worker.abort();
    }

    #[tokio::test]
    async fn udp_hanging_doh_returns_servfail() {
        let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();
        let blackhole_task = tokio::spawn(async move {
            if let Ok((_stream, _)) = blackhole.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let upstream = format!("https://{blackhole_addr}/dns-query");
        let engine = doh_timeout_engine(&upstream);
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let server_addr = server.local_addr().unwrap();
        let worker = tokio::spawn(run_udp_worker(0, Arc::clone(&server), engine));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        client.send_to(&dns_query(), server_addr).await.unwrap();
        let mut response_buf = [0u8; 512];
        let (response_len, _) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut response_buf))
                .await
                .expect("timed-out query should receive SERVFAIL")
                .unwrap();
        let response = Message::from_bytes(&response_buf[..response_len]).unwrap();
        assert_eq!(response.metadata.id, 0xCAFE);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);

        worker.abort();
        blackhole_task.abort();
    }

    #[tokio::test]
    async fn tcp_hanging_doh_returns_complete_servfail_frame() {
        let blackhole = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();
        let blackhole_task = tokio::spawn(async move {
            if let Ok((_stream, _)) = blackhole.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let upstream = format!("https://{blackhole_addr}/dns-query");
        let engine = doh_timeout_engine(&upstream);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(listener_addr).await.unwrap();
            let query = dns_query();
            let mut frame = Vec::with_capacity(2 + query.len());
            frame.extend_from_slice(&(query.len() as u16).to_be_bytes());
            frame.extend_from_slice(&query);
            client.write_all(&frame).await.unwrap();

            let mut len_buf = [0u8; 2];
            tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut len_buf))
                .await
                .expect("TCP query should receive a length prefix")
                .unwrap();
            let response_len = u16::from_be_bytes(len_buf) as usize;
            let mut response = vec![0u8; response_len];
            tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut response))
                .await
                .expect("TCP query should receive the complete DNS frame")
                .unwrap();
            response
        });

        let (server_stream, peer) = listener.accept().await.unwrap();
        let server_task = tokio::spawn(handle_tcp_conn(server_stream, peer, engine));
        let response_bytes = client_task.await.unwrap();
        let response = Message::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.metadata.id, 0xCAFE);
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.queries.len(), 1);

        server_task.abort();
        blackhole_task.abort();
    }

    #[tokio::test]
    async fn udp_response_truncates_oversized_payload() {
        use hickory_proto::rr::{RData, Record, rdata::TXT};

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // 客户端无 EDNS → 512 字节限制 / Client without EDNS → 512-byte limit
        let request = dns_query();
        // 构造 >512 字节的大 TXT 响应 / Build a large TXT response (>512 bytes)
        let name = Name::from_str("data.xiaoheihe.cn.").unwrap();
        let mut big = Message::new(0xCAFE, MessageType::Response, OpCode::Query);
        big.metadata.recursion_desired = true;
        big.metadata.recursion_available = true;
        big.add_query(Query::query(name.clone(), RecordType::TXT));
        for i in 0..20 {
            let text = format!("verification-{i:02}-{}", "x".repeat(180));
            big.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![text])),
            ));
        }
        let big_response = big.to_vec().unwrap();
        assert!(big_response.len() > 512);

        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            send_udp_response(&server, &buf[..len], &big_response, peer).await;
        });

        client.send_to(&request, server_addr).await.unwrap();
        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buf))
            .await
            .expect("client should receive a truncated response")
            .unwrap();
        let resp = Message::from_bytes(&buf[..len]).unwrap();
        assert!(len <= 512, "response must fit the 512-byte UDP limit");
        assert!(resp.metadata.truncation, "TC bit must be set");
        assert_eq!(resp.queries.len(), 1);
        assert_eq!(resp.metadata.id, 0xCAFE);
    }
}
