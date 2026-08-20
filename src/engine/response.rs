use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{
    DNSClass, Name, RData, Record, RecordType,
    rdata::{A, AAAA, CNAME, TXT},
};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::net::IpAddr;
use std::str::FromStr;
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
    let mut msg = Message::new(tx_id, MessageType::Response, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.metadata.recursion_available = true;
    msg.metadata.authoritative = false;
    msg.metadata.response_code = rcode;

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

pub(crate) fn make_static_ip_answer(
    qname: &str,
    qtype: RecordType,
    ips: &str,
) -> (ResponseCode, Vec<Record>) {
    let Ok(name) = Name::from_str(qname) else {
        return (ResponseCode::ServFail, Vec::new());
    };

    // Parse the complete list first so invalid entries still fail atomically,
    // even when their address family is not relevant to this query.
    let mut parsed_ips = Vec::new();
    for ip in ips.split(',') {
        let Ok(ip_addr) = ip.trim().parse::<IpAddr>() else {
            return (ResponseCode::ServFail, Vec::new());
        };
        parsed_ips.push(ip_addr);
    }

    let answers = parsed_ips
        .into_iter()
        .filter_map(|ip_addr| match (qtype, ip_addr) {
            (RecordType::A | RecordType::ANY, IpAddr::V4(v4)) => Some(RData::A(A(v4))),
            (RecordType::AAAA | RecordType::ANY, IpAddr::V6(v6)) => Some(RData::AAAA(AAAA(v6))),
            _ => None,
        })
        .map(|rdata| Record::from_rdata(name.clone(), 300, rdata))
        .collect();

    (ResponseCode::NoError, answers)
}

/// 创建静态 CNAME 记录响应 / Create a static CNAME record response
pub(crate) fn make_static_cname_answer(
    qname: &str,
    target: &str,
    ttl: u32,
) -> (ResponseCode, Vec<Record>) {
    let target = target.trim();
    if target.is_empty() {
        return (ResponseCode::ServFail, Vec::new());
    }

    let (Ok(name), Ok(target)) = (Name::from_str(qname), Name::from_str(target)) else {
        return (ResponseCode::ServFail, Vec::new());
    };

    let record = Record::from_rdata(name, ttl, RData::CNAME(CNAME(target)));
    (ResponseCode::NoError, vec![record])
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
    let answer_max = msg.answers.iter().map(|r| r.ttl as u64).max();
    match answer_max {
        Some(t) => t,
        // No answers: negative response (NXDOMAIN/NODATA) — use SOA from authority
        // per RFC 2308 §5 / 无答案：否定响应 (NXDOMAIN/NODATA) — 按 RFC 2308 §5 从 authority 的 SOA 提取
        None => extract_soa_negative_ttl(msg),
    }
}

/// 从 DNS 响应中提取最小 TTL 用于缓存条目 / Extract minimum TTL from DNS response for cache entry
/// RFC 1035 §5.2 calls for using minimum TTL of the RRset.
/// RFC 2308 §5: For negative responses (NXDOMAIN/NODATA), the negative cache
/// TTL is min(SOA.minimum, SOA.ttl) from the authority section. If no SOA is
/// present, returns 0 (must not be cached per RFC 2308 §4).
///
/// RFC 2308 §5: 否定响应 (NXDOMAIN/NODATA) 的负缓存 TTL 为 authority 中 SOA 的
/// min(SOA.minimum, SOA.ttl)。无 SOA 时返回 0（按 RFC 2308 §4 不可缓存）。
#[inline]
pub fn extract_ttl(msg: &Message) -> u64 {
    let answer_min = msg.answers.iter().map(|r| r.ttl as u64).min();
    match answer_min {
        Some(t) => t,
        // No answers: negative response (NXDOMAIN/NODATA) — use SOA from authority
        // per RFC 2308 §5 / 无答案：否定响应 (NXDOMAIN/NODATA) — 按 RFC 2308 §5 从 authority 的 SOA 提取
        None => extract_soa_negative_ttl(msg),
    }
}

/// Extract negative caching TTL from SOA in the authority section (RFC 2308 §5).
/// Returns min(SOA.minimum_field, SOA.ttl), or 0 if no SOA present.
///
/// 从 authority 中的 SOA 提取负缓存 TTL (RFC 2308 §5)。
/// 返回 min(SOA.minimum_field, SOA.ttl)，无 SOA 时返回 0。
#[inline]
fn extract_soa_negative_ttl(msg: &Message) -> u64 {
    for record in &msg.authorities {
        if let RData::SOA(soa) = &record.data {
            let soa_min = soa.minimum as u64;
            let soa_ttl = record.ttl as u64;
            return soa_min.min(soa_ttl);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::SOA;

    #[test]
    fn static_cname_answer_uses_configured_target_and_ttl() {
        let (rcode, answers) = make_static_cname_answer("alias.example.", "origin.example.", 120);

        assert_eq!(rcode, ResponseCode::NoError);
        assert_eq!(answers.len(), 1);
        assert_eq!(&answers[0].name, &Name::from_str("alias.example.").unwrap());
        assert_eq!(answers[0].ttl, 120);
        match &answers[0].data {
            RData::CNAME(CNAME(target)) => {
                assert_eq!(target, &Name::from_str("origin.example.").unwrap());
            }
            other => panic!("unexpected static CNAME answer: {other:?}"),
        }
    }

    #[test]
    fn static_cname_answer_rejects_invalid_names() {
        for (qname, target) in [
            ("invalid name", "origin.example."),
            ("alias.example.", "invalid name"),
            ("alias.example.", ""),
        ] {
            let (rcode, answers) = make_static_cname_answer(qname, target, 300);
            assert_eq!(rcode, ResponseCode::ServFail);
            assert!(answers.is_empty());
        }
    }

    #[test]
    fn test_extract_ttl_positive_response() {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        let name = Name::from_str("example.com.").unwrap();
        let rec = Record::from_rdata(name, 300, RData::A(A(std::net::Ipv4Addr::LOCALHOST)));
        msg.add_answer(rec);
        assert_eq!(extract_ttl(&msg), 300);
        assert_eq!(extract_ttl_for_refresh(&msg), 300);
    }

    #[test]
    fn test_extract_ttl_nxdomain_with_soa() {
        // RFC 2308 §5: NXDOMAIN with SOA in authority section
        // Negative cache TTL = min(SOA.minimum, SOA.ttl)
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        let mname = Name::from_str("ns1.example.com.").unwrap();
        let rname = Name::from_str("admin.example.com.").unwrap();
        let soa = SOA::new(mname, rname, 1, 3600, 900, 1209600, 60); // minimum=60
        let name = Name::from_str("example.com.").unwrap();
        // SOA TTL = 300, minimum = 60 → min = 60
        let rec = Record::from_rdata(name, 300, RData::SOA(soa));
        msg.add_authority(rec);

        assert_eq!(extract_ttl(&msg), 60); // min(60, 300)
    }

    #[test]
    fn test_extract_ttl_nxdomain_soa_ttl_lower_than_minimum() {
        // When SOA TTL < SOA.minimum, the lower value should be used
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        let mname = Name::from_str("ns1.example.com.").unwrap();
        let rname = Name::from_str("admin.example.com.").unwrap();
        let soa = SOA::new(mname, rname, 1, 3600, 900, 1209600, 3600); // minimum=3600
        let name = Name::from_str("example.com.").unwrap();
        // SOA TTL = 30, minimum = 3600 → min = 30
        let rec = Record::from_rdata(name, 30, RData::SOA(soa));
        msg.add_authority(rec);

        assert_eq!(extract_ttl(&msg), 30); // min(3600, 30)
    }

    #[test]
    fn test_extract_ttl_nxdomain_no_soa() {
        // RFC 2308 §4: NXDOMAIN without SOA must not be cached (TTL = 0)
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NXDomain;
        // No authority section records

        assert_eq!(extract_ttl(&msg), 0);
        assert_eq!(extract_ttl_for_refresh(&msg), 0);
    }
}
