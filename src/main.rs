mod advanced_rule;
mod cache;
mod config;
mod engine;
mod matcher;
mod proto_utils;
mod watcher;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use bytes::Bytes;
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::load_config;
use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

#[derive(Parser, Debug)]
#[command(author, version, about = "KixDNS async DNS with hot-reload pipelines", long_about = None)]
struct Args {
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
    udp_workers: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    init_tracing(args.debug);

    let cfg = load_config(&args.config).context("load initial config")?;
    let cfg = RuntimePipelineConfig::from_config(cfg).context("compile matchers")?;
    let bind_addr: SocketAddr = cfg.settings.bind_udp.parse().context("parse bind addr")?;
    let bind_tcp: SocketAddr = cfg
        .settings
        .bind_tcp
        .parse()
        .context("parse tcp bind addr")?;

    let pipeline = Arc::new(ArcSwap::from_pointee(cfg));
    let engine = Engine::new(pipeline.clone(), args.listener_label.clone());

    watcher::spawn(args.config.clone(), pipeline.clone());

    // UDP worker 数量：默认为 CPU 核心数，最少 1 个 / UDP worker count: defaults to CPU core count, minimum 1
    let udp_workers = if args.udp_workers > 0 {
        args.udp_workers
    } else {
        num_cpus::get()
    };

    info!(bind_udp = %bind_addr, bind_tcp = %bind_tcp, udp_workers = udp_workers, "dns server started");

    let mut udp_handles = Vec::with_capacity(udp_workers);

    #[cfg(unix)]
    {
        // On Unix create individual sockets with SO_REUSEPORT so kernel distributes packets / 在 Unix 上创建带有 SO_REUSEPORT 的独立套接字，以便内核分发数据包
        for worker_id in 0..udp_workers {
            let engine = engine.clone();
            let std_socket = create_reuseport_udp_socket(bind_addr)
                .with_context(|| format!("create udp socket for worker {}", worker_id))?;
            let socket = UdpSocket::from_std(std_socket)?;
            let handle = tokio::spawn(async move {
                if let Err(err) = run_udp_worker(worker_id, Arc::new(socket), engine).await {
                    error!(worker_id, error = %err, "udp worker exited");
                }
            });
            udp_handles.push(handle);
        }
    }

    #[cfg(not(unix))]
    {
        // Non-Unix: create a single shared socket and spawn workers that share it / 非 Unix：创建单个共享套接字并生成共享它的工作线程
        // Use socket2 to set buffer sizes / 使用 socket2 设置缓冲区大小
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if bind_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).context("create socket")?;
        let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
        let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
        socket.set_nonblocking(true).context("set nonblocking")?;
        socket.bind(&bind_addr.into()).context("bind socket")?;
        
        let udp_socket = Arc::new(UdpSocket::from_std(socket.into()).context("from_std")?);
        for worker_id in 0..udp_workers {
            let engine = engine.clone();
            let socket = Arc::clone(&udp_socket);
            let handle = tokio::spawn(async move {
                if let Err(err) = run_udp_worker(worker_id, socket, engine).await {
                    error!(worker_id, error = %err, "udp worker exited");
                }
            });
            udp_handles.push(handle);
        }
    }

    // TCP listener / TCP 监听器
    let tcp_listener = TcpListener::bind(bind_tcp)
        .await
        .context("bind tcp listener")?;
    let tcp_engine = engine.clone();
    let tcp_handle = tokio::spawn(async move {
        if let Err(err) = run_tcp(tcp_listener, tcp_engine).await {
            error!(error = %err, "tcp server exited");
        }
    });

    // 等待所有任务 / Wait for all tasks
    let _ = tcp_handle.await;
    for h in udp_handles {
        let _ = h.await;
    }

    Ok(())
}

fn init_tracing(debug: bool) {
    // 为压测降低日志开销：默认禁用 JSON，非 debug 仅 warn / Reduce logging overhead for benchmarking: disable JSON by default, warn-only in non-debug mode
    let fmt_layer = fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_level(debug);

    let level = if debug { "debug" } else { "warn" };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .init();
}

// 在 Unix 上创建带 SO_REUSEPORT 的 UDP socket；非 Unix 使用标准绑定 / Create UDP socket with SO_REUSEPORT on Unix; use standard binding on non-Unix
#[cfg(unix)]
fn create_reuseport_udp_socket(addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::os::unix::io::AsRawFd;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    // Try to set SO_REUSEPORT via libc to avoid depending on socket2 method availability / 尝试通过 libc 设置 SO_REUSEPORT，避免依赖 socket2 方法的可用性
    #[allow(unused_imports)]
    use libc::{SO_REUSEPORT, SOL_SOCKET, c_int, c_void, setsockopt, socklen_t};
    let val: c_int = 1;
    let fd = socket.as_raw_fd();
    let ret = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEPORT,
            &val as *const _ as *const c_void,
            std::mem::size_of_val(&val) as socklen_t,
        )
    };
    if ret != 0 {
        // non-fatal: continue without reuseport / 非致命错误：不使用 reuseport 继续
    }
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

/// 高性能 UDP worker：直接在接收循环中处理请求，避免 spawn 开销 / High-performance UDP worker: process requests directly in receive loop, avoiding spawn overhead
async fn run_udp_worker(
    _worker_id: usize,
    socket: Arc<UdpSocket>,
    engine: Engine,
) -> anyhow::Result<()> {
    // 预分配缓冲区 / Pre-allocate buffer
    // 使用 BytesMut 避免 Bytes::copy_from_slice 的内存分配 / Use BytesMut to avoid memory allocation in Bytes::copy_from_slice
    use bytes::BytesMut;
    let mut buf = BytesMut::with_capacity(4096);

    loop {
        // 确保有足够的空间 / Ensure sufficient space
        if buf.capacity() < 4096 {
            buf.reserve(4096 - buf.len());
        }
        // 这是一个 unsafe 操作，因为 recv_from 需要 &mut [u8]，但 BytesMut 未初始化的部分不能直接给 safe Rust / This is an unsafe operation because recv_from requires &mut [u8], but uninitialized parts of BytesMut cannot be directly given to safe Rust
        // 但是 tokio 的 UdpSocket::recv_buf 支持 BytesMut，不过这里我们用标准 recv_from / However, tokio's UdpSocket::recv_buf supports BytesMut, but we use standard recv_from here
        // 简单起见，我们先 resize，然后 truncate / For simplicity, we resize first, then truncate
        // 性能损耗极小，因为 resize 0u8 也是 memset / Performance loss is minimal because resize 0u8 is also memset
        unsafe { buf.set_len(buf.capacity()); }
        
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                unsafe { buf.set_len(len); }
                // 零拷贝获取 Bytes / Zero-copy obtain Bytes
                let packet_bytes = buf.split().freeze();
                
                // 快速路径：尝试同步处理（缓存命中等场景） / Fast path: try synchronous handling (cache hit scenarios, etc.)
                match engine.handle_packet_fast(&packet_bytes, peer) {
                    Ok(Some(resp)) => {
                        // 缓存命中，直接发送 / Cache hit, send directly
                        let _ = socket.send_to(&resp, peer).await;
                    }
                    Ok(None) => {
                        // 需要异步处理（上游转发），spawn 处理 / Need async processing (upstream forwarding), spawn for handling
                        // packet_bytes 已经是 Bytes，无需再次 copy / packet_bytes is already Bytes, no need to copy again
                        let engine = engine.clone();
                        let socket = Arc::clone(&socket);
                        tokio::spawn(async move {
                            if let Ok(resp) = engine.handle_packet(&packet_bytes, peer).await {
                                let _ = socket.send_to(&resp, peer).await;
                            }
                        });
                    }
                    Err(_) => {
                        // 解析错误，忽略 / Parse error, ignore
                    }
                }
                
                // 重置 buffer 供下次使用 (split 后 buf 为空，需要 reserve) / Reset buffer for next use (buf is empty after split, need reserve)
                // 实际上 split() 拿走了所有权，buf 变为空。 / Actually split() takes ownership, buf becomes empty
                // 下次循环开头会 reserve。 / Will reserve at the beginning of next loop
            }
            Err(_) => {
                // 继续接收，不退出 / Continue receiving, don't exit
                // 如果出错，buf 长度可能不对，重置 / If error occurs, buf length might be wrong, reset
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

        let mut buf = vec![0u8; frame_len];
        if stream.read_exact(&mut buf).await.is_err() {
            return Ok(());
        }

        let resp = match engine.handle_packet(&buf, peer).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
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
