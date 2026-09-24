//! One INFO response record per answer produced by the engine, including fast paths.
//! This is not a delivery receipt. Failed/cancelled requests use a separate event;
//! retries and background refresh are not client responses.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::serialize::binary::BinDecodable;

#[derive(Default)]
pub(crate) struct ResponseInfo {
    pub pipeline: Option<Arc<str>>,
    pub upstream: Option<Arc<str>>,
    pub cache_hit: bool,
}

pub(crate) struct ResponseLog<'a> {
    pub info: ResponseInfo,
    qname: &'a str,
    qtype: RecordType,
    peer: SocketAddr,
    start: Instant,
    enabled: bool,
    rcode: Option<ResponseCode>,
    status: &'static str,
}

impl<'a> ResponseLog<'a> {
    pub fn new(
        qname: &'a str,
        qtype: RecordType,
        peer: SocketAddr,
        pipeline: Arc<str>,
        start: Instant,
        background: bool,
    ) -> Self {
        Self {
            info: ResponseInfo {
                pipeline: Some(pipeline),
                ..Default::default()
            },
            qname,
            qtype,
            peer,
            start,
            enabled: !background
                && tracing::enabled!(target: "kixdns::engine::phases", tracing::Level::INFO),
            // No response exists yet; never infer an RCODE from a dropped future.
            rcode: None,
            status: "cancelled",
        }
    }

    pub fn answered(&mut self, bytes: &[u8]) {
        if !self.enabled {
            return;
        }
        self.rcode = crate::proto_utils::parse_response_quick(bytes)
            .map(|response| response.rcode)
            .or_else(|| {
                Message::from_bytes(bytes)
                    .ok()
                    .map(|message| message.metadata.response_code)
            });
        self.status = "completed";
    }

    pub fn finish(&mut self, result: &anyhow::Result<Bytes>) {
        match result {
            Ok(bytes) => self.answered(bytes),
            Err(_) => self.status = "failed",
        }
    }
}

impl Drop for ResponseLog<'_> {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }
        let rcode = self.rcode.map(|code| format!("{code:?}"));
        // Keep the existing target so deployed RUST_LOG filters still work.
        tracing::info!(
            target: "kixdns::engine::phases",
            event = if rcode.is_some() { "dns_response" } else { "dns_request_finished" },
            qname = %self.qname,
            qtype = ?self.qtype,
            client_ip = %self.peer.ip(),
            pipeline = self.info.pipeline.as_deref().unwrap_or(""),
            upstream = self.info.upstream.as_deref().unwrap_or(""),
            rcode = rcode.as_deref(),
            cache = self.info.cache_hit,
            cache_hit = self.info.cache_hit,
            latency_ms = self.start.elapsed().as_millis() as u64,
            status = self.status,
            "client request finished"
        );
    }
}
