use std::borrow::Cow;

/// 快速解析结果，尽可能零拷贝 / Quick parse result with zero-copy where possible
pub struct QuickQuery<'a> {
    pub tx_id: u16,
    pub qname: Cow<'a, str>,
    pub qtype: u16,
    pub qclass: u16,
    pub edns_present: bool,
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

    // 2. Counts / 计数
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]);

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

        // Performance optimization: Check if label needs lowercasing
        // Most DNS labels are already lowercase, so we can avoid the copy in common case
        // Use simple loop for better cache locality and early break
        let mut needs_lowercase = false;
        for &b in label_bytes {
            if b.is_ascii_uppercase() {
                needs_lowercase = true;
                break;
            }
        }
        
        // Copy label bytes to buffer
        if buf_pos + label_len > buf.len() {
            return None;
        }
        
        if needs_lowercase {
            // Only lowercase if necessary
            for &b in label_bytes {
                buf[buf_pos] = b.to_ascii_lowercase();
                buf_pos += 1;
            }
        } else {
            // Zero-copy: just copy the bytes as-is
            buf[buf_pos..buf_pos + label_len].copy_from_slice(label_bytes);
            buf_pos += label_len;
        }

        current_pos += label_len;
    }

    // 4. QType / 查询类型
    if packet.len() < pos + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    pos += 4;

    // 5. Check for EDNS in Additional section / 在附加部分检查 EDNS
    let mut edns_present = false;
    if ar_count > 0 && an_count == 0 && ns_count == 0 {
        // Fast-path optimization: for standard query messages, AN and NS are expected to be 0.
        // We only scan the Additional section in this common case to keep parsing fast, which may miss EDNS
        // in non-standard messages (e.g., UPDATE, or responses mistakenly treated as queries).
        // 快速路径优化：对于标准查询消息，AN 和 NS 通常为 0。仅在这种常见情况下扫描 Additional 以提升性能，
        // 这在非标准消息（例如 UPDATE，或被误当作查询处理的响应）中可能漏检 EDNS。
        let mut ar_pos = pos;
        for _ in 0..ar_count {
            if ar_pos >= packet.len() {
                break;
            }
            let name_byte = packet[ar_pos];
            let next_pos = if name_byte == 0 {
                ar_pos + 1
            } else {
                skip_name(packet, ar_pos).unwrap_or(packet.len())
            };

            if next_pos + 10 > packet.len() {
                break;
            }
            let rr_type = u16::from_be_bytes([packet[next_pos], packet[next_pos + 1]]);
            if rr_type == 41 {
                // OPT
                edns_present = true;
                break;
            }
            let rd_len = u16::from_be_bytes([packet[next_pos + 8], packet[next_pos + 9]]);

            // Validate arithmetic to prevent overflow and ensure entire record fits in packet
            let rd_len_usize = rd_len as usize;
            // Check packet length first to avoid underflow in subsequent arithmetic
            if packet.len() < 10 + rd_len_usize {
                break;
            }
            if next_pos > packet.len() - 10 - rd_len_usize {
                break;
            }
            ar_pos = next_pos + 10 + rd_len_usize;
        }
    }

    // Return slice of buf as string
    // RFC 1035-compliant: DNS labels are octet strings, not necessarily valid UTF-8.
    // We use from_utf8_lossy to avoid rejecting non-UTF-8 labels while maintaining
    // case-insensitive ASCII comparison behavior. Invalid UTF-8 bytes are replaced
    // with the Unicode replacement character (U+FFFD).
    let qname = String::from_utf8_lossy(&buf[..buf_pos]);

    Some(QuickQuery {
        tx_id,
        qname,
        qtype,
        qclass,
        edns_present,
    })
}

/// Maximum number of compression pointer jumps allowed to prevent infinite loops
const MAX_COMPRESSION_JUMPS: u32 = 5;

/// 跳过 DNS 名称并返回下一个位置 / Skip DNS name and return next position
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    let packet_len = packet.len();
    let mut max_jumps = MAX_COMPRESSION_JUMPS;

    loop {
        if pos >= packet_len {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            return Some(pos + 1);
        }

        if (len & 0xC0) == 0xC0 {
            // Compression pointer - check bounds before returning
            if pos + 2 > packet_len {
                return None;
            }

            // Follow compression pointer to prevent infinite loops
            max_jumps -= 1;
            if max_jumps == 0 {
                return None;
            }

            let offset = (((len as u16) & 0x3F) << 8) | (packet[pos + 1] as u16);
            let offset_usize = offset as usize;

            // Validate that compression pointer offset is within packet bounds
            if offset_usize >= packet_len {
                return None;
            }

            pos = offset_usize;
            continue;
        }

        // Regular label - check bounds before advancing
        let new_pos = pos + 1 + len as usize;
        if new_pos > packet_len {
            return None;
        }
        pos = new_pos;
    }
}

/// 快速解析响应包，仅提取 RCODE、TC 标志和最小 TTL / Quick parse response packet, extracting only RCODE, TC flag and minimum TTL
/// 避免全量解析 Message / Avoid full Message parsing
#[derive(Debug, Clone)]
pub struct QuickResponse {
    pub rcode: hickory_proto::op::ResponseCode,
    pub min_ttl: u32,
    /// TC (Truncated) flag - 响应被截断，应使用 TCP 重试 / Response was truncated, retry with TCP
    #[allow(dead_code)]
    pub truncated: bool,
}

pub fn parse_response_quick(packet: &[u8]) -> Option<QuickResponse> {
    if packet.len() < 12 {
        return None;
    }

    // 1. Flags (Byte 2-3) / 标志位（字节 2-3）
    // Byte 2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
    // Byte 3: RA(1) Z(3) RCODE(4)
    let flags_byte2 = packet[2];
    let truncated = (flags_byte2 & 0x02) != 0;  // TC bit at position 1

    let rcode_u8 = packet[3] & 0x0F;
    let rcode = hickory_proto::op::ResponseCode::from(0, rcode_u8);

    // 2. Counts / 计数
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    // We don't strictly need NS and AR counts for TTL, but we iterate through them if we want to be thorough. / 对于 TTL，我们并不严格需要 NS 和 AR 计数，但如果想彻底，可以遍历它们
    // For caching, we usually care about Answer section TTLs. / 对于缓存，我们通常关心 Answer 部分的 TTL

    if an_count == 0 {
        return Some(QuickResponse { rcode, min_ttl: 0, truncated });
    }

    let mut pos = 12;
    let packet_len = packet.len();

    // Skip Questions / 跳过问题部分
    for _ in 0..qd_count {
        // Skip Name / 跳过名称
        loop {
            if pos >= packet_len {
                return None;
            }
            let len = packet[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                if pos + 2 > packet_len {
                    return None;
                }
                pos += 2;
                break;
            }
            let jump_len = 1 + (len as usize);
            if pos + jump_len > packet_len {
                return None;
            }
            pos += jump_len;
        }
        // Skip Type(2) + Class(2) / 跳过类型(2) + 类别(2)
        if pos + 4 > packet_len {
            return None;
        }
        pos += 4;
    }

    let mut min_ttl = u32::MAX;

    // Scan Answers / 扫描应答部分
    for _ in 0..an_count {
        // Skip Name / 跳过名称
        loop {
            if pos >= packet_len {
                return None;
            }
            let len = packet[pos];
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                if pos + 2 > packet_len {
                    return None;
                }
                pos += 2;
                break;
            }
            let jump_len = 1 + (len as usize);
            if pos + jump_len > packet_len {
                return None;
            }
            pos += jump_len;
        }

        if pos + 10 > packet_len {
            return None;
        }

        // Type(2) Class(2) TTL(4) RDLen(2) / 类型(2) 类别(2) TTL(4) 数据长度(2)
        // Offset 0: Type / 偏移量 0：类型
        // Offset 2: Class / 偏移量 2：类别
        // Offset 4: TTL / 偏移量 4：TTL
        // Offset 8: RDLen / 偏移量 8：数据长度

        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        if ttl < min_ttl {
            min_ttl = ttl;
        }

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rd_len;
    }

    if min_ttl == u32::MAX {
        min_ttl = 0;
    }

    Some(QuickResponse { rcode, min_ttl, truncated })
}
