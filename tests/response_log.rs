//! Client response logs must count answers, not cache insertions or refresh work.
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use kixdns::config::parse_config;
use kixdns::engine::{Engine, FastPathResponse, PreParsedData};
use kixdns::matcher::RuntimePipelineConfig;
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

impl Write for Log {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Log {
    fn capture(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_env_filter("warn,kixdns::engine::phases=info")
                .json()
                .with_writer(move || writer.clone())
                .finish(),
        )
    }

    fn responses(&self) -> Vec<Value> {
        self.events("dns_response")
    }

    fn events(&self, event: &str) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap()["fields"].clone())
            .filter(|fields| fields["event"] == event)
            .collect()
    }
}

fn query() -> Vec<u8> {
    let mut message = Message::new(42, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii("cache.test").unwrap(),
        RecordType::A,
    ));
    message.to_vec().unwrap()
}

fn peer() -> SocketAddr {
    "127.0.0.1:53000".parse().unwrap()
}

async fn upstream_with_ttl(ttl: u32) -> (String, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut buf = [0; 1500];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let request = Message::from_bytes(&buf[..n]).unwrap();
            let question = request.queries[0].clone();
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.add_query(question.clone());
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                ttl,
                RData::A(A(Ipv4Addr::LOCALHOST)),
            ));
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (addr, task)
}

async fn upstream() -> (String, tokio::task::JoinHandle<()>) {
    upstream_with_ttl(60).await
}

fn engine(upstream: &str) -> Engine {
    configured(json!({
        "settings": {"default_upstream": upstream, "cache_background_refresh": false},
        "pipelines": []
    }))
}

fn configured(config: Value) -> Engine {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Engine::builder(
        RuntimePipelineConfig::from_config(parse_config(&config.to_string()).unwrap()).unwrap(),
    )
    .build()
    .unwrap()
}

#[tokio::test]
async fn forwarded_response_is_not_a_cache_hit() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    engine(&addr).handle_packet(&query(), peer()).await.unwrap();
    task.abort();
    let responses = log.responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0]["cache"], false,
        "a cacheable upstream answer is not a cache hit"
    );
}

#[tokio::test]
async fn info_logs_include_fast_and_slow_cache_hits() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    let engine = engine(&addr);
    let packet = query();
    engine.handle_packet(&packet, peer()).await.unwrap();
    assert!(matches!(
        engine.handle_packet_fast(&packet, peer()).unwrap(),
        Some(FastPathResponse::CacheHit { .. })
    ));
    engine.handle_packet(&packet, peer()).await.unwrap();
    task.abort();
    let responses = log.responses();
    assert_eq!(
        responses.len(),
        3,
        "three client answers need three INFO response records: {responses:?}"
    );
    assert_eq!(
        responses
            .iter()
            .map(|r| r["cache"].clone())
            .collect::<Vec<_>>(),
        vec![json!(false), json!(true), json!(true)]
    );
    assert!(
        responses
            .iter()
            .all(|r| r["cache"] == r["cache_hit"] && r["status"] == "completed")
    );
}

#[tokio::test]
async fn background_refresh_is_not_a_client_response() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    let engine = engine(&addr);
    let pre = PreParsedData::new("cache.test".into(), 1, 1, 42, false, "default".into(), None);
    engine
        .handle_packet_internal_with_pre_parsed(&query(), peer(), true, pre)
        .await
        .unwrap();
    task.abort();
    assert!(
        log.responses().is_empty(),
        "refresh work must not inflate client queries"
    );
    engine.handle_packet(&query(), peer()).await.unwrap();
    let responses = log.responses();
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0]["cache_hit"], true);
}

#[tokio::test]
async fn static_fast_path_and_cached_static_answer_are_distinct() {
    let log = Log::default();
    let _capture = log.capture();
    let engine = configured(json!({
        "settings": {"default_upstream": "127.0.0.1:9", "min_ttl": 60},
        "pipelines": [{"id": "main", "rules": [{
            "name": "block", "matchers": [{"type": "any"}],
            "actions": [{"type": "static_response", "rcode": "NXDOMAIN"}]
        }]}]
    }));
    let packet = query();
    assert!(matches!(
        engine.handle_packet_fast(&packet, peer()).unwrap(),
        Some(FastPathResponse::Direct(_))
    ));
    engine.handle_packet(&packet, peer()).await.unwrap();
    assert!(matches!(
        engine.handle_packet_fast(&packet, peer()).unwrap(),
        Some(FastPathResponse::CacheHit { .. })
    ));
    let responses = log.responses();
    assert_eq!(responses.len(), 3);
    assert_eq!(
        responses
            .iter()
            .map(|r| r["cache_hit"].clone())
            .collect::<Vec<_>>(),
        vec![json!(false), json!(false), json!(true)]
    );
    assert!(
        responses.iter().all(|r| r["rcode"] == "NXDomain"
            && r["pipeline"] == "main"
            && r["upstream"] == "static")
    );
}

#[tokio::test]
async fn inflight_followers_each_count_once_without_claiming_a_cache_hit() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream().await;
    let engine = engine(&addr);
    let packet = query();
    let second_peer = "127.0.0.2:53001".parse().unwrap();
    let (first, second) = tokio::join!(
        engine.handle_packet(&packet, peer()),
        engine.handle_packet(&packet, second_peer)
    );
    first.unwrap();
    second.unwrap();
    task.abort();
    let responses = log.responses();
    assert_eq!(responses.len(), 2);
    assert!(responses.iter().all(|r| r["cache_hit"] == false));
    assert!(responses.iter().any(|r| r["upstream"] == "inflight"));
    assert!(responses.iter().any(|r| r["client_ip"] == "127.0.0.2"));
}

#[tokio::test]
async fn stale_answer_counts_once_and_its_refresh_does_not_count() {
    let log = Log::default();
    let _capture = log.capture();
    let (addr, task) = upstream_with_ttl(1).await;
    let engine = configured(json!({
        "settings": {"default_upstream": addr, "serve_stale": true, "serve_stale_client_timeout_ms": 0, "cache_background_refresh": false},
        "pipelines": []
    }));
    let packet = query();
    engine.handle_packet(&packet, peer()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    engine.handle_packet(&packet, peer()).await.unwrap();
    // Let the automatically spawned refresh complete before checking the count.
    tokio::time::sleep(Duration::from_millis(50)).await;
    task.abort();
    let responses = log.responses();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[1]["cache_hit"], true);
    assert_eq!(responses[1]["rcode"], "NoError");
}

#[tokio::test]
async fn cancelled_request_does_not_invent_a_response_or_rcode() {
    let log = Log::default();
    let _capture = log.capture();
    let silent = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let engine = engine(&silent.local_addr().unwrap().to_string());
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            engine.handle_packet(&query(), peer())
        )
        .await
        .is_err()
    );
    assert!(log.responses().is_empty());
    let finished = log.events("dns_request_finished");
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0]["status"], "cancelled");
    assert!(finished[0].get("rcode").is_none());
}
