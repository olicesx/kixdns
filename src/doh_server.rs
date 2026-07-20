//! DoH (DNS over HTTPS) inbound server — RFC 8484
//!
//! 架构：TLS terminator → HTTP/1.1 handler → Engine 入口
//! 完全复用 Engine 的 `handle_packet_fast` / `handle_packet_internal_with_pre_parsed`，
//! 不重复任何 DNS 处理逻辑。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::engine::{Engine, FastPathResponse};
use crate::proto_utils;

const MAX_DNS_MESSAGE: usize = 64 * 1024;

/// 启动 DoH 服务器 / Start DoH server
pub async fn run_doh(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    engine: Engine,
) -> anyhow::Result<()> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build TLS server config")?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(addr).await.context("bind doh tcp")?;

    info!(%addr, "DoH server listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let engine = engine.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // hyper 1.x 需要 TokioIo 适配器包装 IO
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let engine = engine.clone();
                        async move { handle_doh_request(req, peer, engine).await }
                    });
                    let _ = http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, svc)
                        .await;
                }
                Err(e) => {
                    warn!(error = %e, "DoH TLS handshake failed");
                }
            }
        });
    }
}

/// 处理单个 DoH 请求 / Handle a single DoH request
async fn handle_doh_request(
    req: Request<hyper::body::Incoming>,
    peer: SocketAddr,
    engine: Engine,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // RFC 8484 §4.1: POST with application/dns-message
    // RFC 8484 §4.1.5: GET with ?dns=base64url
    let dns_wire = match (req.method(), req.uri().path()) {
        (&Method::POST, "/dns-query") => {
            match req.into_body().collect().await {
                Ok(collected) => {
                    let body = collected.to_bytes();
                    if body.len() > MAX_DNS_MESSAGE {
                        return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
                    }
                    body
                }
                Err(_) => return Ok(error_response(StatusCode::BAD_REQUEST)),
            }
        }
        (&Method::GET, "/dns-query") => {
            match extract_get_dns_param(req.uri().query().unwrap_or("")) {
                Some(data) => data,
                None => return Ok(error_response(StatusCode::BAD_REQUEST)),
            }
        }
        _ => return Ok(error_response(StatusCode::NOT_FOUND)),
    };

    if dns_wire.len() < 12 {
        return Ok(error_response(StatusCode::BAD_REQUEST));
    }

    // ✅ 复用 Engine 公共入口 — 与 TCP/UDP 入站完全一致
    let resp = process_dns_wire(&dns_wire, peer, &engine).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/dns-message")
        .header("cache-control", "max-age=0")
        .body(Full::new(resp))
        .unwrap())
}

/// 从 GET ?dns=base64url 提取 DNS 报文 / Extract DNS wire from GET ?dns=base64url
fn extract_get_dns_param(query: &str) -> Option<Bytes> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix("dns=") {
            let decoded = URL_SAFE_NO_PAD.decode(val).ok()?;
            if !decoded.is_empty() {
                return Some(Bytes::from(decoded));
            }
        }
    }
    None
}

/// 处理 DNS wire 报文，返回响应 bytes
/// 完全复用 Engine 的 handle_packet_fast 快速路径 + handle_packet 完整路径
async fn process_dns_wire(packet: &[u8], peer: SocketAddr, engine: &Engine) -> Bytes {
    let timeout_ms = engine.get_request_timeout_ms();
    let timeout_dur = Duration::from_millis(timeout_ms);

    match engine.handle_packet_fast(packet, peer) {
        Ok(Some(FastPathResponse::Direct(bytes))) => bytes,
        Ok(Some(FastPathResponse::CacheHit {
            cached,
            tx_id,
            inserted_at,
        })) => {
            let mut resp_buf = bytes::BytesMut::with_capacity(cached.len());
            resp_buf.extend_from_slice(&cached);

            let elapsed = inserted_at.elapsed().as_secs() as u32;
            if elapsed > 0 {
                proto_utils::patch_all_ttls(&mut resp_buf, elapsed);
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
        })) => {
            match tokio::time::timeout(
                timeout_dur,
                engine.handle_packet_internal_with_pre_parsed(
                    packet, peer, false, qname, qtype, qclass, tx_id, edns_present,
                    pipeline_id,
                ),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    warn!(error = %e, "DoH request processing error");
                    empty_dns_response(packet)
                }
                Err(_) => {
                    warn!(timeout_ms, "DoH request timeout");
                    empty_dns_response(packet)
                }
            }
        }
        Ok(None) => {
            // 快速解析失败，回退到完整处理 / Fast parse failed, fallback to full processing
            match tokio::time::timeout(timeout_dur, engine.handle_packet(packet, peer)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    warn!(error = %e, "DoH full parse error");
                    empty_dns_response(packet)
                }
                Err(_) => {
                    warn!(timeout_ms, "DoH request timeout (full)");
                    empty_dns_response(packet)
                }
            }
        }
        Err(_) => empty_dns_response(packet),
    }
}

/// 构造空 DNS 响应（SERVFAIL） / Build empty SERVFAIL response
fn empty_dns_response(request: &[u8]) -> Bytes {
    if request.len() < 2 {
        return Bytes::new();
    }
    // 复制前 2 字节（TXID），设 QR=1 + RCODE=2 (SERVFAIL)
    let mut resp = vec![0u8; 12];
    resp[0] = request[0];
    resp[1] = request[1];
    resp[2] = 0x80; // QR=1, Opcode=0, AA=0, TC=0, RD=0
    resp[3] = 0x02; // RA=0, Z=0, RCODE=2 (SERVFAIL)
    Bytes::from(resp)
}

fn error_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// 从 PEM 文件加载证书 / Load certificates from PEM file
fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let file = std::fs::File::open(path).context("open cert file")?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse PEM certificates")
}

/// 从 PEM 文件加载私钥 / Load private key from PEM file
fn load_private_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path).context("open key file")?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .context("parse PEM private key")?
        .context("no private key found in PEM file")
}
