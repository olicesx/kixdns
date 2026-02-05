use std::str::FromStr;
use std::net::IpAddr;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Record, Name, RData, rdata::{A, AAAA, TXT}, DNSClass};
use hickory_proto::serialize::binary::{BinEncoder, BinEncodable};
use bytes::Bytes;
use tracing::warn;

#[inline]
pub(crate) fn build_fast_static_response(
    tx_id: u16,
    qname: &str,
    qtype: u16,
    qclass: u16,
    rcode: ResponseCode,
    answers: &Vec<Record>,
) -> anyhow::Result<Bytes> {
    let mut msg = Message::new();
    msg.set_id(tx_id);
    msg.set_message_type(MessageType::Response);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.set_recursion_available(true);
    msg.set_authoritative(false);
    msg.set_response_code(rcode);

    // Build question from quick parse data
    let name = Name::from_str(qname)?;
    let mut query = Query::new();
    query.set_name(name);
    query.set_query_type(hickory_proto::rr::RecordType::from(qtype));
    let qclass = DNSClass::from(qclass);
    query.set_query_class(qclass);
    msg.add_query(query);

    for ans in answers {
        msg.add_answer(ans.clone());
    }

    let mut out = Vec::with_capacity(512);
    {
        let mut encoder = BinEncoder::new(&mut out);
        msg.emit(&mut encoder)?;
    }
    Ok(Bytes::from(out))
}

pub(crate) fn make_static_ip_answer(qname: &str, ip: &str) -> (ResponseCode, Vec<Record>) {
    if let Ok(ip_addr) = ip.parse::<IpAddr>() {
        if let Ok(name) = Name::from_str(qname) {
            let rdata = match ip_addr {
                IpAddr::V4(v4) => RData::A(A(v4)),
                IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
            };
            let record = Record::from_rdata(name, 300, rdata);
            return (ResponseCode::NoError, vec![record]);
        }
    }
    (ResponseCode::ServFail, Vec::new())
}

/// 创建静态TXT记录响应 / Create static TXT record response
///
/// RFC 1035 TXT记录规范:
/// - 单个TXT段最大255字节
/// - 总大小不超过65535字节
pub(crate) fn make_static_txt_answer(
    qname: &str,
    text: &[String],
    ttl: u32,
) -> (ResponseCode, Vec<Record>) {
    // 验证TXT记录大小 / Validate TXT record size
    const MAX_SEGMENT_SIZE: usize = 255;
    const MAX_TOTAL_SIZE: usize = 65535;

    let mut total_size = 0usize;
    for txt_part in text {
        // 检查单个段大小 / Check individual segment size
        if txt_part.len() > MAX_SEGMENT_SIZE {
            warn!(
                qname = %qname,
                size = txt_part.len(),
                max = MAX_SEGMENT_SIZE,
                "TXT record segment exceeds 255 bytes"
            );
            return (ResponseCode::ServFail, Vec::new());
        }
        total_size = total_size.saturating_add(txt_part.len());
        if total_size > MAX_TOTAL_SIZE {
            warn!(
                qname = %qname,
                size = total_size,
                max = MAX_TOTAL_SIZE,
                "TXT record total size exceeds 65535 bytes"
            );
            return (ResponseCode::ServFail, Vec::new());
        }
    }

    if let Ok(name) = Name::from_str(qname) {
        let txt = TXT::new(text.to_vec());
        let record = Record::from_rdata(name, ttl, RData::TXT(txt));
        return (ResponseCode::NoError, vec![record]);
    }
    (ResponseCode::ServFail, Vec::new())
}

/// 从 DNS 响应中提取最大 TTL 用于后台刷新时机 / Extract maximum TTL from DNS response for background refresh timing
#[inline]
pub fn extract_ttl_for_refresh(msg: &Message) -> u64 {
    msg.answers()
        .iter()
        .map(|r| r.ttl() as u64)
        .max()
        .unwrap_or(0)
}

/// 从 DNS 响应中提取最小 TTL 用于缓存条目 / Extract minimum TTL from DNS response for cache entry
/// RFC 1035 §5.2 calls for using minimum TTL of the RRset
#[inline]
pub fn extract_ttl(msg: &Message) -> u64 {
    msg.answers()
        .iter()
        .map(|r| r.ttl() as u64)
        .min()
        .unwrap_or(0)
}

