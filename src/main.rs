use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{error, info, debug, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use kixdns::config::load_config;
use kixdns::engine::{Engine, FastPathResponse};
use kixdns::matcher::RuntimePipelineConfig;
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
        Some(Commands::ConvertGeoIp { input, output, filter }) => {
            // Convert GeoIP .dat to MMDB
            let filter_countries: Option<Vec<String>> = filter
                .map(|f| f.split(',').map(|s| s.trim().to_uppercase()).collect());

            let filter_slice = filter_countries.as_deref();

            match kixdns::matcher::geoip::GeoIpManager::convert_dat_to_mmdb(&input, &output, filter_slice) {
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
        Some(Commands::Run { config, listener_label, debug, udp_workers_count }) => {
            run_dns_server(config, listener_label, debug, udp_workers_count).await
        }
        None => {
            // No subcommand provided - run DNS server with defaults
            run_dns_server(
                PathBuf::from("config/pipeline.json"),
                "default".to_string(),
                false,
                0,
            ).await
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

            let cfg = load_config(&config).context("load initial config")?;
            let cfg = RuntimePipelineConfig::from_config(cfg).context("compile matchers")?;
            let bind_addr: SocketAddr = cfg.settings.bind_udp.parse().context("parse bind addr")?;
            let bind_tcp: SocketAddr = cfg
                .settings
                .bind_tcp
                .parse()
                .context("parse tcp bind addr")?;

            let engine = Engine::new(cfg, listener_label.clone());

            watcher::spawn(config.clone(), engine.clone());

            // UDP worker 数量：默认为 CPU 核心数，最少 1 个 / UDP worker count: defaults to CPU core count, minimum 1
            let udp_workers_final = if udp_workers_count > 0 {
                udp_workers_count
            } else {
                num_cpus::get()
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
                let needs_ipv4 = bind_addr.is_ipv4() ||
                    (bind_addr.is_ipv6() && bind_addr.ip().is_unspecified());
                let needs_ipv6 = bind_addr.is_ipv6();

                if needs_ipv4 {
                    let workers_per_family = if needs_ipv6 {
                        udp_workers_final.div_ceil(2)
                    } else {
                        udp_workers_final
                    };
                    spawn_ipv4_udp_workers(bind_addr, workers_per_family, engine.clone(), &mut all_handles)?;
                }

                if needs_ipv6 {
                    let workers_per_family = if needs_ipv4 {
                        udp_workers_final.div_ceil(2)
                    } else {
                        udp_workers_final
                    };
                    spawn_ipv6_udp_workers(bind_addr, workers_per_family, engine.clone(), &mut all_handles)?;
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
                        debug!("failed to set IPV6_V6ONLY=0: {}, IPv4 may not work on [::] bind", e);
                    } else {
                        info!("UDP IPv6 socket set to dual-stack mode (IPV6_V6ONLY=0)");
                    }
                }

                // Set buffer sizes to prevent packet loss under load
                // Try 4MB first, then fall back to 1MB if it fails
                let desired_size = 4 * 1024 * 1024;
                let fallback_size = 1024 * 1024;

                if let Err(e) = socket.set_recv_buffer_size(desired_size) {
                    debug!("failed to set udp recv buffer to {} bytes: {}, trying {}", desired_size, e, fallback_size);
                    let _ = socket.set_recv_buffer_size(fallback_size);
                }
                if let Err(e) = socket.set_send_buffer_size(desired_size) {
                    debug!("failed to set udp send buffer to {} bytes: {}, trying {}", desired_size, e, fallback_size);
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
            let needs_ipv4_tcp = bind_tcp.is_ipv4() || (bind_tcp.is_ipv6() && bind_tcp.ip().is_unspecified());

            // --- 启动 IPv4 TCP 监听 / Start IPv4 TCP listener ---
            if needs_ipv4_tcp {
                let addr = if bind_tcp.is_ipv4() {
                    bind_tcp
                } else {
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), bind_tcp.port())
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
                socket.set_only_v6(true).context("set ipv6 only for kixdns")?;
                socket.set_reuse_address(true)?;

                socket.bind(&bind_tcp.into()).context("bind ipv6 tcp socket")?;
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
        SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), bind_addr.port())
    };

    info!(bind_addr = %ipv4_addr, workers = worker_count, "Starting IPv4 UDP workers");

    for worker_id in 0..worker_count {
        let engine = engine.clone();
        let std_socket = create_reuseport_udp_socket(ipv4_addr)
            .with_context(|| format!("create ipv4 udp socket for worker {}", worker_id))?;
        let socket = UdpSocket::from_std(std_socket)?;
        let handle = tokio::spawn(async move {
            if let Err(err) = run_udp_worker(worker_id, Arc::new(socket), engine).await {
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
        SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), bind_addr.port())
    };

    info!(bind_addr = %ipv6_addr, workers = worker_count, "Starting IPv6 UDP workers");

    for worker_id in 0..worker_count {
        let engine = engine.clone();
        let std_socket = create_reuseport_udp_socket(ipv6_addr)
            .with_context(|| format!("create ipv6 udp socket for worker {}", worker_id))?;
        let socket = UdpSocket::from_std(std_socket)?;
        let handle = tokio::spawn(async move {
            if let Err(err) = run_udp_worker(worker_id, Arc::new(socket), engine).await {
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
    if domain == Domain::IPV6 {
        if let Err(e) = kixdns::socket_utils::set_ipv6_v6only(&socket, true) {
            tracing::warn!("Failed to set IPV6_V6ONLY=1: {}, this may cause issues on OpenBSD", e);
        }
    }

    // Try to set SO_REUSEPORT via safe wrapper / 尝试通过安全封装设置 SO_REUSEPORT
    if let Err(e) = kixdns::socket_utils::set_reuseport(&socket, true) {
        // Log warning if SO_REUSEPORT fails / SO_REUSEPORT 失败时记录警告
        tracing::warn!("SO_REUSEPORT failed: {}, falling back to shared socket", e);
    }

    // Set buffer sizes to prevent packet loss under load
    // Try 4MB first, then fall back to 1MB if it fails
    let desired_size = 4 * 1024 * 1024;
    let fallback_size = 1024 * 1024;

    if let Err(e) = socket.set_recv_buffer_size(desired_size) {
        debug!("failed to set udp recv buffer to {} bytes: {}, trying {}", desired_size, e, fallback_size);
        let _ = socket.set_recv_buffer_size(fallback_size);
    }
    if let Err(e) = socket.set_send_buffer_size(desired_size) {
        debug!("failed to set udp send buffer to {} bytes: {}, trying {}", desired_size, e, fallback_size);
        let _ = socket.set_send_buffer_size(fallback_size);
    }

    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
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

        // ✅ 使用 tokio 的 recv_buf_from 配合 BytesMut，实现零拷贝的高性能接收
        // ✅ Use tokio's recv_buf_from with BytesMut for zero-copy high-performance reception
        // 由于使用双 socket 方案（IPv4 + IPv6 分离），不会出现混合地址族的 sockaddr 问题
        // Since we use dual-socket approach (IPv4 + IPv6 separated), no mixed address family sockaddr issues
        match socket.recv_buf_from(&mut buf).await {
            Ok((_len, peer)) => {
                // 零拷贝获取 Bytes / Zero-copy obtain Bytes
                let packet_bytes = buf.split().freeze();

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
                        let _ = socket.send_to(&bytes, peer).await;
                    }
                    Ok(Some(FastPathResponse::CacheHit { cached, tx_id, inserted_at })) => {
                        // 复用 send_buf：copy + patch TXID / Reuse send_buf: copy + patch TXID
                        send_buf.clear();
                        if send_buf.capacity() < cached.len() {
                            send_buf.reserve(cached.len() - send_buf.capacity());
                        }
                        send_buf.extend_from_slice(&cached);

                        // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                        let elapsed = inserted_at.elapsed().as_secs() as u32;
                        if elapsed > 0 {
                            kixdns::proto_utils::patch_all_ttls(&mut send_buf, elapsed);
                        }

                        if send_buf.len() >= 2 {
                            let id_bytes = tx_id.to_be_bytes();
                            send_buf[0] = id_bytes[0];
                            send_buf[1] = id_bytes[1];
                        }
                        let _ = socket.send_to(&send_buf, peer).await;
                    }
                    Ok(Some(FastPathResponse::AsyncNeeded { qname, qtype, qclass, tx_id, edns_present, pipeline_id })) => {
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
                                        qname,
                                        qtype,
                                        qclass,
                                        tx_id,
                                        edns_present,
                                        pipeline_id,
                                    )
                                ).await {
                                    Ok(Ok(resp)) => {
                                        let _ = socket.send_to(&resp, peer).await;
                                    }
                                    Ok(Err(e)) => {
                                        debug!(error = %e, "handle_packet error");
                                    }
                                    Err(_) => {
                                        warn!(
                                            timeout_ms,
                                            upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                                            "request timeout after hedge and fallback exhausted"
                                        );
                                    }
                                }
                            });
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
                                match tokio::time::timeout(timeout_dur, engine.handle_packet(&packet_bytes, peer)).await {
                                    Ok(Ok(resp)) => {
                                        let _ = socket.send_to(&resp, peer).await;
                                    }
                                    Ok(Err(e)) => {
                                        debug!(error = %e, "handle_packet error");
                                    }
                                    Err(_) => {
                                        warn!(
                                            timeout_ms,
                                            upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                                            "request timeout"
                                        );
                                    }
                                }
                            });
                        }
                    }
                    Err(_) => {
                        // 解析错误，忽略 / Parse error, ignore
                    }
                }
            }
            Err(e) => {
                // 接收错误，清除缓冲区并继续 / Receive error, clear buffer and continue
                debug!(error = %e, "UDP recv error");
                buf.clear();
            }
        }
    }
}

async fn run_tcp(listener: TcpListener, engine: Engine) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
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
        let timeout_dur = Duration::from_millis(timeout_ms);

        let resp = match engine.handle_packet_fast(&packet_bytes, peer) {
            Ok(Some(FastPathResponse::Direct(bytes))) => {
                // 快速路径命中：直接返回 / Fast path hit: return directly
                bytes
            }
            Ok(Some(FastPathResponse::CacheHit { cached, tx_id, inserted_at })) => {
                // 缓存命中：patch TXID / Cache hit: patch TXID
                let mut resp_buf = bytes::BytesMut::with_capacity(cached.len());
                resp_buf.extend_from_slice(&cached);

                // RFC 1035 §5.2: Patch TTL based on residence time / 根据停留时间修正 TTL
                let elapsed = inserted_at.elapsed().as_secs() as u32;
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
            Ok(Some(FastPathResponse::AsyncNeeded { qname, qtype, qclass, tx_id, edns_present, pipeline_id })) => {
                // 缓存未命中：使用预解析数据避免重复解析
                // Cache miss: use pre-parsed data to avoid re-parsing
                match tokio::time::timeout(
                    timeout_dur,
                    engine.handle_packet_internal_with_pre_parsed(
                        &packet_bytes,
                        peer,
                        false,
                        qname,
                        qtype,
                        qclass,
                        tx_id,
                        edns_present,
                        pipeline_id,
                    )
                ).await {
                    Ok(Ok(r)) => r,
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => {
                        warn!(
                            timeout_ms,
                            upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                            "TCP request timeout after hedge and fallback exhausted"
                        );
                        return Ok(()); // 关闭连接 / Close connection
                    }
                }
            }
            Ok(None) => {
                // 快速解析失败，回退到完整处理
                // Fast parse failed, fallback to full processing
                match tokio::time::timeout(timeout_dur, engine.handle_packet(&packet_bytes, peer)).await {
                    Ok(Ok(r)) => r,
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => {
                        warn!(
                            timeout_ms,
                            upstream_timeout_ms = engine.get_upstream_timeout_ms(),
                            "TCP request timeout"
                        );
                        return Ok(()); // 关闭连接 / Close connection
                    }
                }
            }
            Err(_) => {
                // 解析错误，关闭连接 / Parse error, close connection
                return Ok(());
            }
        };

        if resp.len() <= u16::MAX as usize {
            let len_bytes = (resp.len() as u16).to_be_bytes();
            if stream.write_all(&len_bytes).await.is_err() {
                return Ok(());
            }
            if stream.write_all(&resp).await.is_err() {
                return Ok(());
            }
        }
    }
}
