use std::str::from_utf8;

/// 快速解析结果，尽可能零拷贝 / Quick parse result with zero-copy where possible
pub struct QuickQuery<'a> {
    pub tx_id: u16,
    pub qname: &'a str,
    pub qtype: u16,
    pub qclass: u16,
}

/// 仅解析 DNS 头部和第一个 Query，用于快速缓存查找 / Parse only DNS header and first query for quick cache lookup
/// 避免 hickory-proto Message::from_bytes 的全量解析和分配开销 / Avoid full parsing and allocation overhead of hickory-proto Message::from_bytes
/// buf: 用于存储归一化（小写）域名的缓冲区，建议至少 256 字节 / buf: buffer for storing normalized (lowercase) domain name, recommend at least 256 bytes
pub fn parse_quick<'a>(packet: &[u8], buf: &'a mut [u8]) -> Option<QuickQuery<'a>> {
    if packet.len() < 12 {
        return None;
    }

    // 1. Transaction ID / 事务ID
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);

    // 2. Flags (QDCOUNT at offset 4) / 标志位（QDCOUNT 在偏移量 4）
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    if qd_count == 0 {
        return None;
    }

    // 3. Parse QName (start at offset 12) / 解析查询名称（从偏移量 12 开始）
    let mut pos = 12;
    let mut buf_pos = 0;

    let mut jumped = false;
    let mut max_jumps = 5;
    let mut current_pos = pos;
    let packet_len = packet.len();

    loop {
        if current_pos >= packet_len {
            return None;
        }
        let len = packet[current_pos];

        if len == 0 {
            // End of name / 名称结束
            if !jumped {
                pos = current_pos + 1;
            }
            break;
        }

        if (len & 0xC0) == 0xC0 {
            // Compression pointer / 压缩指针
            if packet_len < current_pos + 2 {
                return None;
            }
            if !jumped {
                pos = current_pos + 2;
                jumped = true;
            }
            let offset = (((len as u16) & 0x3F) << 8) | (packet[current_pos + 1] as u16);
            current_pos = offset as usize;
            max_jumps -= 1;
            if max_jumps == 0 {
                return None; // Loop detection / 循环检测
            }
            continue;
        }

        // Label / 标签
        let label_len = len as usize;
        current_pos += 1;
        if packet_len < current_pos + label_len {
            return None;
        }

        if buf_pos > 0 {
            if buf_pos >= buf.len() {
                return None;
            }
            buf[buf_pos] = b'.';
            buf_pos += 1;
        }

        let label_bytes = &packet[current_pos..current_pos + label_len];

        // Optimize: process bytes directly to avoid UTF-8 validation per label / 优化：直接处理字节以避免每个标签的 UTF-8 验证
        // DNS labels are typically ASCII (or Punycode). / DNS 标签通常是 ASCII（或 Punycode）
        // If raw UTF-8 is used, to_ascii_lowercase on bytes is safe (leaves non-ASCII bytes unchanged). / 如果使用原始 UTF-8，字节上的 to_ascii_lowercase 是安全的（保留非 ASCII 字节不变）
        for &b in label_bytes {
            if buf_pos >= buf.len() {
                return None;
            }
            buf[buf_pos] = b.to_ascii_lowercase();
            buf_pos += 1;
        }

        current_pos += label_len;
    }

    // 4. QType / 查询类型
    if packet.len() < pos + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);

    // Return slice of buf / 返回缓冲区的切片
    let qname = from_utf8(&buf[..buf_pos]).ok()?;

    Some(QuickQuery {
        tx_id,
        qname,
        qtype,
        qclass,
    })
}

/// 快速解析响应包，仅提取 RCODE 和最小 TTL / Quick parse response packet, extracting only RCODE and minimum TTL
/// 避免全量解析 Message / Avoid full Message parsing
pub struct QuickResponse {
    pub rcode: hickory_proto::op::ResponseCode,
    pub min_ttl: u32,
}

pub fn parse_response_quick(packet: &[u8]) -> Option<QuickResponse> {
    if packet.len() < 12 {
        return None;
    }

    // 1. RCODE (Flags at offset 2-3) / RCODE（偏移量 2-3 的标志位）
    // Flags: QR(1) Opcode(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4) / 标志位：QR(1) Opcode(4) AA(1) TC(1) RD(1) RA(1) Z(3) RCODE(4)
    // Byte 3 (index 3) contains RCODE in lower 4 bits / 字节 3（索引 3）在低 4 位包含 RCODE
    let rcode_u8 = packet[3] & 0x0F;
    let rcode = hickory_proto::op::ResponseCode::from(0, rcode_u8);

    // 2. Counts / 计数
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    // We don't strictly need NS and AR counts for TTL, but we iterate through them if we want to be thorough. / 对于 TTL，我们并不严格需要 NS 和 AR 计数，但如果想彻底，可以遍历它们
    // For caching, we usually care about Answer section TTLs. / 对于缓存，我们通常关心 Answer 部分的 TTL
    
    if an_count == 0 {
        return Some(QuickResponse { rcode, min_ttl: 0 });
    }

    let mut pos = 12;
    let packet_len = packet.len();

    // Skip Questions / 跳过问题部分
    for _ in 0..qd_count {
        // Skip Name / 跳过名称
        loop {
            if pos >= packet_len { return None; }
            let len = packet[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + (len as usize);
        }
        // Skip Type(2) + Class(2) / 跳过类型(2) + 类别(2)
        pos += 4;
    }

    let mut min_ttl = u32::MAX;

    // Scan Answers / 扫描应答部分
    for _ in 0..an_count {
        // Skip Name / 跳过名称
        loop {
            if pos >= packet_len { return None; }
            let len = packet[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + (len as usize);
        }

        if pos + 10 > packet_len { return None; }
        
        // Type(2) Class(2) TTL(4) RDLen(2) / 类型(2) 类别(2) TTL(4) 数据长度(2)
        // Offset 0: Type / 偏移量 0：类型
        // Offset 2: Class / 偏移量 2：类别
        // Offset 4: TTL / 偏移量 4：TTL
        // Offset 8: RDLen / 偏移量 8：数据长度
        
        let ttl = u32::from_be_bytes([packet[pos + 4], packet[pos + 5], packet[pos + 6], packet[pos + 7]]);
        if ttl < min_ttl {
            min_ttl = ttl;
        }

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rd_len;
    }

    if min_ttl == u32::MAX {
        min_ttl = 0;
    }

    Some(QuickResponse { rcode, min_ttl })
}
