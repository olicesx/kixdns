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
#[cfg(test)]
use hickory_proto::op::{Message, ResponseCode};
#[cfg(test)]
use hickory_proto::serialize::binary::BinDecodable;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::engine::{Engine, FastPathResponse, PreParsedData, engine_helpers};
use crate::proto_utils;

const MAX_DNS_MESSAGE: usize = 64 * 1024;

/// 启动 DoH 服务器 / Start DoH server
pub async fn run_doh(
    addr: SocketAddr,
    cert_path: &str,
    key_path: &str,
    engine: Engine,
    doh_path: String,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await.context("bind doh tcp")?;
    info!(%addr, %doh_path, "DoH server listening");
    run_doh_with_listener(listener, cert_path, key_path, engine, doh_path).await
}

/// 从已绑定的 TcpListener 启动 DoH 服务器（便于测试获取实际端口）
/// Start DoH server from a pre-bound TcpListener (allows tests to discover the actual port)
pub async fn run_doh_with_listener(
    listener: TcpListener,
    cert_path: &str,
    key_path: &str,
    engine: Engine,
    doh_path: String,
) -> anyhow::Result<()> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build TLS server config")?;

    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let engine = engine.clone();
        let doh_path = doh_path.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    // hyper 1.x 需要 TokioIo 适配器包装 IO
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let engine = engine.clone();
                        let doh_path = doh_path.clone();
                        async move { handle_doh_request(req, peer, engine, &doh_path).await }
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
    doh_path: &str,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    // RFC 8484 §4.1: POST with application/dns-message
    // RFC 8484 §4.1.5: GET with ?dns=base64url
    let dns_wire = match (req.method(), req.uri().path()) {
        (&Method::POST, path) if path == doh_path => match req.into_body().collect().await {
            Ok(collected) => {
                let body = collected.to_bytes();
                if body.len() > MAX_DNS_MESSAGE {
                    return Ok(error_response(StatusCode::PAYLOAD_TOO_LARGE));
                }
                body
            }
            Err(_) => return Ok(error_response(StatusCode::BAD_REQUEST)),
        },
        (&Method::GET, path) if path == doh_path => {
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
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
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

            let elapsed = proto_utils::saturating_u64_to_u32(inserted_at.elapsed().as_secs());
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
            ecs_key,
        })) => {
            match tokio::time::timeout(
                timeout_dur,
                engine.handle_packet_internal_with_pre_parsed(
                    packet,
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
    engine_helpers::build_servfail_response_from_wire(request)
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

// ============================================================================
// Tests / 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Install rustls crypto provider for tests that create Engine (which internally creates TLS clients).
    #[ctor::ctor]
    fn init_crypto() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }

    // ---- extract_get_dns_param ----

    #[test]
    fn test_extract_get_dns_param_valid() {
        // A minimal DNS query for example.com A record
        let dns_wire = [
            0xAB, 0xCD, // TXID
            0x01, 0x00, // Flags: standard query, RD=1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, // null terminator
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
        ];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        let query = format!("dns={encoded}");
        let result = extract_get_dns_param(&query);
        assert!(result.is_some(), "should decode valid base64url");
        assert_eq!(result.unwrap().as_ref(), &dns_wire[..]);
    }

    #[test]
    fn test_extract_get_dns_param_missing_param() {
        assert!(extract_get_dns_param("foo=bar").is_none());
        assert!(extract_get_dns_param("").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_empty_value() {
        assert!(extract_get_dns_param("dns=").is_none());
        assert!(extract_get_dns_param("dns=&foo=bar").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_multiple_params() {
        let dns_wire = [0x00; 12];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        // dns= should be found among multiple params
        let query = format!("foo=bar&dns={encoded}&baz=qux");
        let result = extract_get_dns_param(&query);
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_ref(), &dns_wire[..]);
    }

    #[test]
    fn test_extract_get_dns_param_invalid_base64() {
        assert!(extract_get_dns_param("dns=!!!invalid").is_none());
    }

    #[test]
    fn test_extract_get_dns_param_standard_base64url_no_pad() {
        // RFC 8484 uses base64url without padding
        let dns_wire = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x12];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_wire);
        let result = extract_get_dns_param(&format!("dns={encoded}"));
        assert!(result.is_some());
    }

    // ---- empty_dns_response ----

    #[test]
    fn test_empty_dns_response_preserves_txid() {
        let request = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let resp = empty_dns_response(&request);
        assert_eq!(resp.len(), 12);
        assert_eq!(resp[0], 0x12, "TXID high byte preserved");
        assert_eq!(resp[1], 0x34, "TXID low byte preserved");
    }

    #[test]
    fn test_empty_dns_response_qr_and_rcode() {
        let request = [0xAB, 0xCD];
        let resp = empty_dns_response(&request);
        assert_eq!(resp.len(), 12);
        // Byte 2: QR=1, Opcode=0, AA=0, TC=0, RD=0 → 0x80
        assert_eq!(resp[2], 0x80, "QR should be 1");
        // Byte 3: RA=1, Z=0, RCODE=2 (SERVFAIL) → 0x82
        assert_eq!(resp[3], 0x82, "RA and SERVFAIL should be set");
    }

    #[test]
    fn test_empty_dns_response_short_input() {
        let resp = empty_dns_response(&[0xFF]);
        assert!(resp.is_empty(), "input < 2 bytes should return empty");
        let resp = empty_dns_response(&[]);
        assert!(resp.is_empty());
    }

    #[test]
    fn test_empty_dns_response_preserves_question() {
        let request = make_dns_query_a("question.example.com", 0x1234);
        let response = empty_dns_response(&request);
        let decoded = Message::from_bytes(&response).expect("decode SERVFAIL response");

        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(decoded.queries.len(), 1);
        assert_eq!(decoded.queries[0].name().to_utf8(), "question.example.com.");
    }

    // ---- error_response ----

    #[test]
    fn test_error_response_status() {
        let resp = error_response(StatusCode::NOT_FOUND);
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = error_response(StatusCode::BAD_REQUEST);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = error_response(StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ---- process_dns_wire (with static-response Engine) ----

    fn make_static_engine(rcode: &str) -> Engine {
        use crate::config::PipelineConfig;
        use crate::matcher::RuntimePipelineConfig;

        let raw = serde_json::json!({
            "settings": { "default_upstream": "127.0.0.1:5300" },
            "pipelines": [
                {
                    "id": "p",
                    "rules": [
                        {
                            "name": "static",
                            "matchers": [ { "type": "any" } ],
                            "actions": [ { "type": "static_response", "rcode": rcode } ]
                        }
                    ]
                }
            ]
        });
        let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
        let runtime = RuntimePipelineConfig::from_config(cfg).expect("build runtime");
        Engine::new(runtime, "test".to_string()).expect("initialize test engine")
    }

    fn make_dns_query_a(domain: &str, txid: u16) -> Vec<u8> {
        use hickory_proto::op::{Message, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let mut msg = Message::new(txid, hickory_proto::op::MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    #[tokio::test]
    async fn test_process_dns_wire_static_nxdomain() {
        let engine = make_static_engine("NXDOMAIN");
        let query = make_dns_query_a("test.example.com", 0x4242);
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let resp = process_dns_wire(&query, peer, &engine).await;

        // Should be a valid DNS response
        assert!(resp.len() >= 12, "response should be >= 12 bytes");
        // TXID preserved
        assert_eq!(resp[0], 0x42, "TXID high byte preserved");
        assert_eq!(resp[1], 0x42, "TXID low byte preserved");
        // QR=1
        assert_eq!(resp[2] & 0x80, 0x80, "QR bit should be set");
        // RCODE = NXDOMAIN (3)
        assert_eq!(resp[3] & 0x0F, 0x03, "RCODE should be NXDOMAIN (3)");
    }

    #[tokio::test]
    async fn test_process_dns_wire_static_noerror() {
        let engine = make_static_engine("NOERROR");
        let query = make_dns_query_a("ok.example.com", 0x0001);
        let peer: SocketAddr = "127.0.0.1:9999".parse().unwrap();

        let resp = process_dns_wire(&query, peer, &engine).await;

        assert!(resp.len() >= 12);
        assert_eq!(resp[0], 0x00, "TXID high byte preserved");
        assert_eq!(resp[1], 0x01, "TXID low byte preserved");
        // RCODE = NOERROR (0)
        assert_eq!(resp[3] & 0x0F, 0x00, "RCODE should be NOERROR (0)");
    }

    #[tokio::test]
    async fn test_process_dns_wire_short_query_returns_servfail() {
        // Query shorter than DNS header — fast parse fails → fallback → SERVFAIL
        let engine = make_static_engine("NXDOMAIN");
        let short = [0x12, 0x34, 0x00]; // only 3 bytes, not a valid DNS message
        let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();

        let resp = process_dns_wire(&short, peer, &engine).await;

        // Should return a SERVFAIL response preserving TXID
        assert_eq!(resp.len(), 12);
        assert_eq!(resp[0], 0x12, "TXID high byte preserved");
        assert_eq!(resp[1], 0x34, "TXID low byte preserved");
        assert_eq!(resp[3] & 0x0F, 0x02, "RCODE should be SERVFAIL (2)");
    }

    // ---- MAX_DNS_MESSAGE size guard ----

    #[test]
    fn test_max_dns_message_constant() {
        // RFC 1035 limits DNS messages to 65535 bytes; we cap at 64KB for safety
        assert_eq!(MAX_DNS_MESSAGE, 64 * 1024);
    }
}
