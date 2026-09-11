//! DoH (RFC 8484) integration tests
//!
//! Full-stack tests: self-signed TLS cert → HTTP/1.1 → DNS engine → wire response.
//! Tests both POST (RFC 8484 §4.1) and GET (§4.1.5) methods, error paths,
//! the 64 KiB message-size guard, and TLS certificate hot-reload.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use base64::engine::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
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
    Engine::new(runtime, "test".to_string()).expect("initialize test engine")
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
    Engine::new(runtime, "test".to_string()).expect("initialize test engine")
}

/// Generate a fresh self-signed cert/key PEM pair in memory. The common name
/// distinguishes identities; SANs cover both `localhost` and `127.0.0.1` so
/// fully-verifying clients can connect to `https://127.0.0.1:{port}`.
fn generate_cert_pem_pair(common_name: &str) -> (String, String) {
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    let key_pair = KeyPair::generate().expect("generate key pair");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");
    (cert.pem(), key_pair.serialize_pem())
}

/// Generate a self-signed TLS certificate, write cert + key PEM to temp files.
fn make_test_cert() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let (cert_pem, key_pem) = generate_cert_pem_pair("kixdns-test");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    std::fs::write(&cert_path, cert_pem).expect("write cert pem");
    std::fs::write(&key_path, key_pem).expect("write key pem");

    (
        dir,
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Build a DNS A query in wire format.
fn make_dns_query(domain: &str, txid: u16) -> Vec<u8> {
    let mut msg = Message::new(txid, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
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

/// Fully-verifying client that trusts exactly the given self-signed PEM
/// (plus the built-in public roots, which our test identities are not in).
fn make_client_trusting(cert_pem: &str) -> reqwest::Client {
    let root = reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("parse root pem");
    reqwest::Client::builder()
        .add_root_certificate(root)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("build client")
}

/// Do a DoH POST query; true iff the server answered OK over a verified TLS chain.
async fn doh_query_ok(client: &reqwest::Client, port: u16, txid: u16) -> bool {
    client
        .post(doh_url(port))
        .header("content-type", "application/dns-message")
        .body(make_dns_query("reload.example.com", txid))
        .send()
        .await
        .is_ok_and(|r| r.status() == reqwest::StatusCode::OK)
}

/// Atomically replace file contents (write sibling tmp + rename over target),
/// like acme.sh/certbot deploy hooks, so the watcher sees a single swap.
fn atomically_replace(path: &Path, contents: &str) {
    let tmp = path.with_extension("renew.tmp");
    std::fs::write(&tmp, contents).expect("write tmp file");
    std::fs::rename(&tmp, path).expect("atomic rename");
}

/// Spawn the DoH server on a pre-bound listener and wait for it to enter the
/// accept loop.
async fn spawn_doh(
    listener: tokio::net::TcpListener,
    engine: Engine,
    cert_path: &str,
    key_path: &str,
) {
    let cert_path = cert_path.to_string();
    let key_path = key_path.to_string();
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

    spawn_doh(listener, engine, &cert_path, &key_path).await;

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
    assert_eq!(msg.metadata.id, 0xBEEF, "TXID preserved");
    assert_eq!(
        msg.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError,
        "should be NOERROR"
    );
    // Should have at least one A record = 1.2.3.4
    let a_records: Vec<_> = msg
        .answers
        .iter()
        .filter(|r| r.record_type() == RecordType::A)
        .collect();
    assert!(!a_records.is_empty(), "should have A records");
    // Check the IP address
    let ip = match &a_records[0].data {
        hickory_proto::rr::RData::A(a) => a,
        _ => panic!("expected A record"),
    };
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

            client
                .post(doh_url(server.port))
                .header("content-type", "application/dns-message")
                .body(query)
                .send()
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

// ============================================================================
// TLS certificate auto-reload tests (issue #43)
// ============================================================================

/// Wait until the server verifies against `client`'s trust anchor, i.e. it
/// serves the certificate the client trusts. Polls to ride out watcher latency.
async fn poll_until_served(client: &reqwest::Client, port: u16, txid: u16) -> bool {
    for _ in 0..100 {
        if doh_query_ok(client, port, txid).await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// End-to-end renewal: swap cert+key files on disk while the server runs; new
/// connections must verify against the renewed identity without a restart.
#[tokio::test]
async fn test_doh_tls_cert_auto_reload() {
    let (_dir, cert_path, key_path) = make_test_cert();
    let cert_a_pem = std::fs::read_to_string(&cert_path).expect("read cert A");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    spawn_doh(listener, make_nxdomain_engine(), &cert_path, &key_path).await;

    let (cert_b_pem, key_b_pem) = generate_cert_pem_pair("kixdns-test-renewed");
    let client_a = make_client_trusting(&cert_a_pem);
    let client_b = make_client_trusting(&cert_b_pem);

    // Before renewal: identity A is served, B is rejected.
    assert!(
        doh_query_ok(&client_a, port, 0x0001).await,
        "client trusting A must work before reload"
    );
    assert!(
        !doh_query_ok(&client_b, port, 0x0002).await,
        "client trusting B must fail before reload"
    );

    // Renewal: atomically swap both files, like acme.sh/certbot deploy hooks.
    atomically_replace(Path::new(&cert_path), &cert_b_pem);
    atomically_replace(Path::new(&key_path), &key_b_pem);

    assert!(
        poll_until_served(&client_b, port, 0x0003).await,
        "server must serve the renewed certificate without restart"
    );
    // Fresh pool: the old client's keep-alive connection predates the swap, so
    // reuse would succeed without exercising the new handshake.
    let client_a_fresh = make_client_trusting(&cert_a_pem);
    assert!(
        !doh_query_ok(&client_a_fresh, port, 0x0004).await,
        "client trusting A must fail after reload"
    );
}

/// Failure safety: an invalid key on disk must not degrade the running server —
/// it keeps serving the last good certificate and adopts new files once valid.
#[tokio::test]
async fn test_doh_tls_cert_reload_failure_keeps_last_good() {
    let (_dir, cert_path, key_path) = make_test_cert();
    let cert_a_pem = std::fs::read_to_string(&cert_path).expect("read cert A");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    spawn_doh(listener, make_nxdomain_engine(), &cert_path, &key_path).await;

    let (cert_b_pem, key_b_pem) = generate_cert_pem_pair("kixdns-test-recovered");
    let client_a = make_client_trusting(&cert_a_pem);
    let client_b = make_client_trusting(&cert_b_pem);

    // Corrupt the key: reload attempts must fail and keep serving A.
    atomically_replace(Path::new(&key_path), "definitely not a pem\n");
    // Give the watcher time to attempt (and reject) the broken state.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        doh_query_ok(&client_a, port, 0x0011).await,
        "server must keep serving the last good certificate after a failed reload"
    );

    // Once cert+key are valid again, the server adopts them.
    atomically_replace(Path::new(&cert_path), &cert_b_pem);
    atomically_replace(Path::new(&key_path), &key_b_pem);
    assert!(
        poll_until_served(&client_b, port, 0x0012).await,
        "server must adopt the certificate once files are valid again"
    );
    // Fresh pool: see test_doh_tls_cert_auto_reload.
    let client_a_fresh = make_client_trusting(&cert_a_pem);
    assert!(
        !doh_query_ok(&client_a_fresh, port, 0x0013).await,
        "retired identity must be gone after recovery"
    );
}
