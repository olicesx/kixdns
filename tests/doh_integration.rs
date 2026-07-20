//! DoH (RFC 8484) integration tests
//!
//! Full-stack tests: self-signed TLS cert → HTTP/1.1 → DNS engine → wire response.
//! Tests both POST (RFC 8484 §4.1) and GET (§4.1.5) methods, error paths,
//! and the 64 KiB message-size guard.

use std::str::FromStr;
use std::time::Duration;

use base64::engine::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;

use kixdns::config::PipelineConfig;
use kixdns::doh_server::run_doh_with_listener;
use kixdns::engine::Engine;
use kixdns::matcher::RuntimePipelineConfig;

/// Install the rustls crypto provider before any test runs.
/// Required because the test binary needs TLS for both the DoH server and reqwest client.
#[ctor::ctor]
fn init() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install crypto provider");
}

// ============================================================================
// Helpers / 辅助函数
// ============================================================================

/// Build an Engine that always returns a static NXDOMAIN for any query.
fn make_nxdomain_engine() -> Engine {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:5300" },
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "block-all",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
            }]
        }]
    });
    let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(cfg).expect("build runtime");
    Engine::new(runtime, "test".to_string())
}

/// Build an Engine that returns a fixed static IP (1.2.3.4) for A queries.
fn make_static_ip_engine() -> Engine {
    let raw = serde_json::json!({
        "settings": { "default_upstream": "127.0.0.1:5300" },
        "pipelines": [{
            "id": "p",
            "rules": [{
                "name": "static-ip",
                "matchers": [{ "type": "any" }],
                "actions": [{ "type": "static_ip_response", "ip": "1.2.3.4" }]
            }]
        }]
    });
    let cfg: PipelineConfig = serde_json::from_value(raw).expect("parse config");
    let runtime = RuntimePipelineConfig::from_config(cfg).expect("build runtime");
    Engine::new(runtime, "test".to_string())
}

/// Generate a self-signed TLS certificate, write cert + key PEM to temp files.
fn make_test_cert() -> (tempfile::TempDir, String, String) {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, "kixdns-test");

    let key_pair = KeyPair::generate().expect("generate key pair");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");

    let dir = tempfile::TempDir::new().expect("tempdir");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::write(&cert_path, cert.pem()).expect("write cert pem");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key pem");

    (
        dir,
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Build a DNS A query in wire format.
fn make_dns_query(domain: &str, txid: u16) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_id(txid);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
    msg.to_vec().unwrap()
}

/// reqwest client that trusts our self-signed cert.
fn make_https_client() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build client")
}

/// Holds the running DoH test server and keeps temp cert files alive.
struct DohTestServer {
    port: u16,
    _cert_dir: tempfile::TempDir,
}

/// Start a DoH server on an ephemeral port. The TLS cert/key files live for
/// the lifetime of the returned `DohTestServer`.
async fn start_doh(engine: Engine) -> DohTestServer {
    let (dir, cert_path, key_path) = make_test_cert();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();

    tokio::spawn(async move {
        let _ = run_doh_with_listener(
            listener,
            &cert_path,
            &key_path,
            engine,
            "/dns-query".to_string(),
        )
        .await;
    });

    // Brief delay to let the spawned task load certs and enter accept loop
    tokio::time::sleep(Duration::from_millis(50)).await;

    DohTestServer {
        port,
        _cert_dir: dir,
    }
}

fn doh_url(port: u16) -> String {
    format!("https://127.0.0.1:{port}/dns-query")
}

// ============================================================================
// POST method tests (RFC 8484 §4.1)
// ============================================================================

#[tokio::test]
async fn test_doh_post_nxdomain() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client();

    let query = make_dns_query("blocked.example.com", 0x1234);
    let resp = client
        .post(doh_url(server.port))
        .header("content-type", "application/dns-message")
        .body(query)
        .send()
        .await
        .expect("POST request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .expect("content-type header"),
        "application/dns-message"
    );

    let body = resp.bytes().await.expect("read body");
    assert!(
        body.len() >= 12,
        "response must be >= 12 bytes (DNS header)"
    );
    // TXID preserved
    assert_eq!(body[0], 0x12, "TXID high byte");
    assert_eq!(body[1], 0x34, "TXID low byte");
    // QR=1
    assert_eq!(body[2] & 0x80, 0x80, "QR bit must be set");
    // RCODE = NXDOMAIN (3)
    assert_eq!(body[3] & 0x0F, 0x03, "RCODE must be NXDOMAIN");
}

#[tokio::test]
async fn test_doh_post_static_ip() {
    let server = start_doh(make_static_ip_engine()).await;
    let client = make_https_client();

    let query = make_dns_query("static.example.com", 0xBEEF);
    let resp = client
        .post(doh_url(server.port))
        .header("content-type", "application/dns-message")
        .body(query)
        .send()
        .await
        .expect("POST request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body = resp.bytes().await.expect("read body");
    // Parse the DNS response
    let msg = Message::from_bytes(&body).expect("parse DNS response");
    assert_eq!(msg.id(), 0xBEEF, "TXID preserved");
    assert_eq!(
        msg.response_code(),
        hickory_proto::op::ResponseCode::NoError,
        "should be NOERROR"
    );
    // Should have at least one A record = 1.2.3.4
    let a_records: Vec<_> = msg
        .answers()
        .iter()
        .filter(|r| r.record_type() == RecordType::A)
        .collect();
    assert!(!a_records.is_empty(), "should have A records");
    // Check the IP address
    let ip = a_records[0]
        .data()
        .and_then(|d| d.as_a())
        .expect("A record data");
    assert_eq!(ip.0, std::net::Ipv4Addr::new(1, 2, 3, 4));
}

// ============================================================================
// GET method tests (RFC 8484 §4.1.5)
// ============================================================================

#[tokio::test]
async fn test_doh_get_nxdomain() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client();

    let query = make_dns_query("get.example.com", 0x0042);
    let encoded = URL_SAFE_NO_PAD.encode(&query);
    let url = format!("{}?dns={encoded}", doh_url(server.port));

    let resp = client.get(&url).send().await.expect("GET request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let body = resp.bytes().await.expect("read body");
    assert!(body.len() >= 12, "response must be >= 12 bytes");
    assert_eq!(body[0], 0x00, "TXID high byte");
    assert_eq!(body[1], 0x42, "TXID low byte");
    assert_eq!(body[2] & 0x80, 0x80, "QR bit");
    assert_eq!(body[3] & 0x0F, 0x03, "RCODE = NXDOMAIN");
}

#[tokio::test]
async fn test_doh_get_missing_dns_param() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client();

    // GET without ?dns= parameter
    let resp = client
        .get(doh_url(server.port)) // no query string
        .send()
        .await
        .expect("GET request");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ============================================================================
// Error path tests
// ============================================================================

#[tokio::test]
async fn test_doh_wrong_path_returns_404() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client();

    let query = make_dns_query("test.example.com", 0x0001);

    let resp = client
        .post(format!("https://127.0.0.1:{}/not-dns-query", server.port))
        .header("content-type", "application/dns-message")
        .body(query)
        .send()
        .await
        .expect("POST request");

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_doh_wrong_method_returns_404() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client();

    // PUT should not be supported
    let resp = client
        .put(doh_url(server.port))
        .body(vec![0u8; 12])
        .send()
        .await
        .expect("PUT request");

    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_doh_post_too_large() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client();

    // 70 KiB body, well over the 64 KiB limit
    let oversized = vec![0xAAu8; 70 * 1024];

    let resp = client
        .post(doh_url(server.port))
        .header("content-type", "application/dns-message")
        .body(oversized)
        .send()
        .await
        .expect("POST request");

    assert_eq!(resp.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_doh_post_short_body() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client();

    // Body shorter than 12-byte DNS header
    let short = vec![0x00u8; 5];

    let resp = client
        .post(doh_url(server.port))
        .header("content-type", "application/dns-message")
        .body(short)
        .send()
        .await
        .expect("POST request");

    // The server checks dns_wire.len() < 12 → returns BAD_REQUEST
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ============================================================================
// Concurrent request test
// ============================================================================

#[tokio::test]
async fn test_doh_concurrent_requests() {
    let server = start_doh(make_nxdomain_engine()).await;
    let client = make_https_client().clone();

    let urls: Vec<_> = (0..10u16)
        .map(|i| {
            let query = make_dns_query(&format!("r{i}.example.com"), i);
            let req = client
                .post(doh_url(server.port))
                .header("content-type", "application/dns-message")
                .body(query)
                .send();
            req
        })
        .collect();

    let results = futures::future::join_all(urls).await;

    for (i, resp) in results.into_iter().enumerate() {
        let resp = resp.expect("request should succeed");
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        let body = resp.bytes().await.expect("body");
        assert!(body.len() >= 12);
        // Each response preserves its own TXID
        let txid = u16::from_be_bytes([body[0], body[1]]);
        assert_eq!(txid, i as u16, "TXID should be {i}");
        assert_eq!(body[3] & 0x0F, 0x03, "NXDOMAIN");
    }
}
