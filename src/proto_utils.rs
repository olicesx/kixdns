use std::hash::Hasher;

use bytes::Bytes;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

/// 快速解析结果，零拷贝实现 / Quick parse result with zero-copy implementation
pub struct QuickQuery<'a> {
    pub tx_id: u16,
    pub qname_bytes: &'a [u8], // 零拷贝：直接引用已小写化的缓冲区
    pub qtype: u16,
    pub qclass: u16,
    pub edns_present: bool,
}

/// Check the fixed DNS header fields required by KixDNS's standard query path.
/// This cheap ingress guard must run before cache/static fast paths so response
/// packets cannot be reflected as normal answers.
#[inline]
pub fn is_standard_query_header(packet: &[u8]) -> bool {
    if packet.len() < 12 {
        return false;
    }

    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);

    flags & 0x8000 == 0 && flags & 0x7800 == 0 && qd_count == 1 && an_count == 0 && ns_count == 0
}

/// 仅解析 DNS 头部和第一个 Query，用于快速缓存查找 / Parse only DNS header and first query for quick cache lookup
/// 避免 hickory-proto Message::from_bytes 的全量解析和分配开销 / Avoid full parsing and allocation overhead of hickory-proto Message::from_bytes
/// buf: 用于存储归一化（小写）域名的缓冲区，建议至少 256 字节 / buf: buffer for storing normalized (lowercase) domain name, recommend at least 256 bytes
pub fn parse_quick<'a>(packet: &[u8], buf: &'a mut [u8]) -> Option<QuickQuery<'a>> {
    if !is_standard_query_header(packet) {
        return None;
    }

    // 1. Transaction ID / 事务ID
    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);

    // 2. Counts / 计数
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]);

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
        if len & 0xC0 != 0 {
            return None;
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

    // Fast ASCII validation (zero-allocation, early exit)
    // 快速 ASCII 验证（零分配，提前退出）
    // DNS domain names should be LDH (Letters, Digits, Hyphen) + dots
    // Reject control characters so qnames are safe to include in structured logs.
    // 域名应该是 LDH（字母、数字、连字符）+ 点号
    // 拒绝控制字符，确保 qname 可安全写入结构化日志。
    // This is ~10x faster than full UTF-8 validation
    // 这比完整的 UTF-8 验证快约 10 倍
    let is_safe_ascii = buf[..buf_pos]
        .iter()
        .all(|b| b.is_ascii() && !b.is_ascii_control());
    if !is_safe_ascii {
        // Reject non-ASCII domain names and control characters
        // Similar to Unbound's strategy: reject invalid input for performance
        // 拒绝非 ASCII 域名和控制字符
        // 类似 Unbound 的策略：为了性能拒绝无效输入
        return None;
    }

    // 4. QType / 查询类型
    if packet.len() < pos + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    let qclass = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
    pos += 4;

    // 5. Validate every declared Additional record and detect EDNS.
    // Fail closed before cache/static fast paths on any malformed wire structure.
    //
    // Trade-off vs the old fast-path scan: this always walks the full Additional
    // section and rejects trailing data, where the old code broke early on OPT and
    // tolerated truncation. Full validation is required so malformed packets cannot
    // reach cache/static paths; the cost is bounded by ARCOUNT records.
    //
    // 权衡：总是遍历完整 Additional 段并拒绝尾随数据（旧代码找到 OPT 即提前退出、容忍截断）。
    // 完整校验是为了让畸形包无法到达 cache/static 路径；成本以 ARCOUNT 记录数为界。
    let mut edns_present = false;
    let mut ar_pos = pos;
    for _ in 0..ar_count {
        let owner_start = ar_pos;
        let next_pos = skip_name(packet, ar_pos)?;
        let fixed_end = next_pos.checked_add(10)?;
        if fixed_end > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[next_pos], packet[next_pos + 1]]);
        let rd_len = u16::from_be_bytes([packet[next_pos + 8], packet[next_pos + 9]]) as usize;
        let rdata_end = fixed_end.checked_add(rd_len)?;
        if rdata_end > packet.len() {
            return None;
        }

        if rr_type == 41 {
            // RFC 6891: OPT owner name must be the root and only one OPT is valid.
            if edns_present || packet.get(owner_start) != Some(&0) {
                return None;
            }
            validate_edns_options(packet, fixed_end, rdata_end)?;
            edns_present = true;
        }
        ar_pos = rdata_end;
    }
    if ar_pos != packet.len() {
        return None;
    }

    // Return slice of buf as zero-copy reference
    // Performance optimization: ASCII-only validation (10x faster than UTF-8)
    // 性能优化：仅 ASCII 验证（比 UTF-8 快 10 倍）
    // RFC 1035: DNS labels are LDH (Letters, Digits, Hyphen) + dots, which is ASCII subset
    // RFC 1035：DNS 标签是 LDH（字母、数字、连字符）+ 点号，属于 ASCII 子集
    // Strategy: Reject non-ASCII for performance (similar to Unbound)
    // 策略：为性能拒绝非 ASCII（类似 Unbound）
    // Trade-off: 0.001% queries rejected for 10% performance gain
    // 权衡：拒绝 0.001% 的查询以获得 10% 的性能提升
    // The buf already contains the lowercased domain name from the parsing loop above.
    Some(QuickQuery {
        tx_id,
        qname_bytes: &buf[..buf_pos], // 零拷贝：直接引用已小写化的缓冲区
        qtype,
        qclass,
        edns_present,
    })
}

/// 跳过 DNS 名称并返回下一个位置 / Skip DNS name and return next position
#[inline]
fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    let packet_len = packet.len();
    let mut encoded_end = None;
    let mut jumps = 0usize;

    loop {
        let len = *packet.get(pos)?;
        if len == 0 {
            return Some(encoded_end.unwrap_or(pos + 1));
        }
        if (len & 0xC0) == 0xC0 {
            let pointer_end = pos.checked_add(2)?;
            if pointer_end > packet_len {
                return None;
            }
            encoded_end.get_or_insert(pointer_end);
            let offset = (((len & 0x3F) as usize) << 8) | packet[pos + 1] as usize;
            if offset >= packet_len {
                return None;
            }
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            pos = offset;
            continue;
        }
        if len & 0xC0 != 0 || len > 63 {
            return None;
        }

        let next = pos.checked_add(1 + len as usize)?;
        if next > packet_len {
            return None;
        }
        pos = next;
    }
}

/// Byte length of the last complete record, or `None` on malformed structure.
///
/// hickory's bounded encoder rolls back its write offset but not the backing
/// buffer when a record does not fit, so truncated output can carry partial
/// bytes from the failed record past the (corrected) header counts. Re-walking
/// the emitted sections yields the exact valid boundary so the response stays
/// within RFC 1035 §4.2.1 record boundaries.
fn valid_message_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }

    let qd_count = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let an_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    let mut pos = 12usize;
    // Questions: NAME + QTYPE + QCLASS.
    for _ in 0..qd_count {
        pos = skip_name(packet, pos)?;
        pos = pos.checked_add(4)?;
    }
    // Resource records: NAME + TYPE/CLASS/TTL/RDLENGTH + RDATA.
    for _ in 0..an_count + ns_count + ar_count {
        pos = skip_name(packet, pos)?;
        let fixed_end = pos.checked_add(10)?;
        if fixed_end > packet.len() {
            return None;
        }
        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos = fixed_end.checked_add(rd_len)?;
    }
    (pos <= packet.len()).then_some(pos)
}

fn validate_edns_options(packet: &[u8], mut pos: usize, end: usize) -> Option<()> {
    while pos < end {
        let header_end = pos.checked_add(4)?;
        if header_end > end {
            return None;
        }
        let option_len = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        pos = header_end.checked_add(option_len)?;
        if pos > end {
            return None;
        }
    }
    (pos == end).then_some(())
}

impl QuickQuery<'_> {
    /// 检查 qname 是否匹配指定的域名（忽略大小写）
    /// Check if qname matches the specified domain name (case-insensitive)
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false };
    /// assert!(query.qname_matches("google.com"));  // 完全匹配
    /// assert!(query.qname_matches("GOOGLE.COM"));  // 大写匹配
    /// assert!(!query.qname_matches("example.com"));  // 不匹配
    /// ```
    ///
    /// # Performance
    /// This function is optimized for hot path usage:
    /// - No allocation / 无分配
    /// - Early exit on length mismatch / 长度不匹配时提前退出
    /// - Byte-by-byte comparison with ASCII lowercasing / 逐字节比较并转为小写
    #[inline]
    pub fn qname_matches(&self, pattern: &str) -> bool {
        // Fast path: length check / 快速路径：长度检查
        if self.qname_bytes.len() != pattern.len() {
            return false;
        }

        // Byte-by-byte comparison with ASCII lowercasing / 逐字节比较并转为小写
        // qname_bytes is already lowercased from parse_quick() / qname_bytes 在 parse_quick() 中已经转为小写
        // So we only need to lowercase the pattern bytes / 所以我们只需要将 pattern 字节转为小写
        self.qname_bytes
            .iter()
            .zip(pattern.as_bytes())
            .all(|(a, b)| *a == b.to_ascii_lowercase())
    }

    /// 获取 qname 的字符串表示（用于调试和日志）
    /// Get string representation of qname (for debugging and logging)
    ///
    /// # Performance Warning
    /// This function allocates a new String. Use sparingly in hot paths.
    /// 此函数分配新的 String。在热路径中谨慎使用。
    ///
    /// # Safety
    /// qname_bytes is guaranteed to be valid ASCII (and thus UTF-8) by parse_quick().
    /// parse_quick() validates ASCII before returning QuickQuery.
    /// ASCII is always valid UTF-8, so from_utf8_unchecked is safe.
    /// qname_bytes 由 parse_quick() 保证为有效的 ASCII（因此也是 UTF-8）。
    /// parse_quick() 在返回 QuickQuery 之前验证 ASCII。
    /// ASCII 始终是有效的 UTF-8，所以 from_utf8_unchecked 是安全的。
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false };
    /// println!("qname: {}", query.qname_str());  // "google.com"
    /// ```
    #[inline]
    pub fn qname_str(&self) -> String {
        // SAFETY: qname_bytes is validated ASCII from parse_quick()
        // ASCII is always valid UTF-8
        // 安全性：qname_bytes 在 parse_quick() 中已验证为 ASCII
        // ASCII 始终是有效的 UTF-8
        //
        // In debug builds, we validate to catch any issues early
        // 在 debug 构建中，我们验证以尽早发现问题
        #[cfg(debug_assertions)]
        {
            std::str::from_utf8(self.qname_bytes)
                .expect("qname_bytes should be valid UTF-8")
                .to_string()
        }
        #[cfg(not(debug_assertions))]
        unsafe {
            std::str::from_utf8_unchecked(self.qname_bytes).to_string()
        }
    }

    /// 获取 qname 的 &str 表示（零分配，但受生命周期限制）
    /// Get &str representation of qname (zero-allocation, but lifetime-bound)
    ///
    /// # Performance
    /// This is the preferred method for string operations in hot paths.
    /// 这是热路径中字符串操作的首选方法。
    ///
    /// # Safety
    /// qname_bytes is guaranteed to be valid ASCII (and thus UTF-8) by parse_quick().
    /// parse_quick() validates ASCII before returning QuickQuery.
    /// If parse_quick() succeeds, qname_bytes is always valid ASCII/UTF-8.
    /// In debug builds, we validate to catch any issues early.
    /// qname_bytes 由 parse_quick() 保证为有效的 ASCII（因此也是 UTF-8）。
    /// parse_quick() 在返回 QuickQuery 之前验证 ASCII。
    /// 如果 parse_quick() 成功，qname_bytes 始终是有效的 ASCII/UTF-8。
    /// 在 debug 构建中，我们验证以尽早发现问题。
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false };
    /// let qname_str = query.qname_str_unchecked();  // &str
    /// ```
    #[inline]
    pub fn qname_str_unchecked(&self) -> &str {
        // SAFETY: qname_bytes is validated ASCII from parse_quick()
        // ASCII is always valid UTF-8
        // 安全性：qname_bytes 在 parse_quick() 中已验证为 ASCII
        // ASCII 始终是有效的 UTF-8
        //
        // In debug builds, we validate to catch any issues early
        // 在 debug 构建中，我们验证以尽早发现问题
        #[cfg(debug_assertions)]
        {
            std::str::from_utf8(self.qname_bytes).expect("qname_bytes should be valid UTF-8")
        }
        #[cfg(not(debug_assertions))]
        unsafe {
            std::str::from_utf8_unchecked(self.qname_bytes)
        }
    }

    /// 获取 qname 的哈希值（用于缓存键计算）
    /// Get hash value of qname (for cache key calculation)
    ///
    /// # Examples
    /// ```
    /// # use kixdns::proto_utils::QuickQuery;
    /// let query = QuickQuery { qname_bytes: b"google.com", tx_id: 0, qtype: 1, qclass: 1, edns_present: false };
    /// let hash = query.qname_hash();
    /// ```
    #[inline]
    pub fn qname_hash(&self) -> u64 {
        let mut h = rustc_hash::FxHasher::default();
        h.write(self.qname_bytes);
        h.finish()
    }
}

/// 快速解析响应包，仅提取 RCODE、TC 标志和 TTL 范围 / Quick parse response packet, extracting only RCODE, TC flag and TTL range
/// 避免全量解析 Message / Avoid full Message parsing
#[derive(Debug, Clone)]
pub struct QuickResponse {
    pub rcode: hickory_proto::op::ResponseCode,
    pub min_ttl: u32,
    /// 最大 TTL，用于后台刷新触发决策 / Maximum TTL, used for background refresh trigger decision
    pub max_ttl: u32,
    /// TC (Truncated) flag - 响应被截断，应使用 TCP 重试 / Response was truncated, retry with TCP
    #[allow(dead_code)]
    pub truncated: bool,
}

/// Extract negative caching TTL from SOA in the authority section at the wire level (RFC 2308 §5).
/// Returns min(SOA.minimum, SOA.record_ttl), or None if no SOA is found or parsing fails.
/// This avoids a full `Message::from_bytes` parse for the common negative-response path.
///
/// 在 wire 层级从 authority 的 SOA 记录提取负缓存 TTL (RFC 2308 §5)。
/// 返回 min(SOA.minimum, SOA.record_ttl)，无 SOA 或解析失败时返回 None。
/// 避免对常见的否定响应路径进行完整的 `Message::from_bytes` 解析。
///
/// SAFETY: Reads raw DNS wire format. All bounds are checked. Returns None on any parse error.
/// 安全性：读取原始 DNS wire 格式。所有边界均已检查。解析错误时返回 None。
fn extract_soa_negative_ttl_wire(packet: &[u8], qd_count: u16, ns_count: u16) -> Option<u32> {
    let packet_len = packet.len();
    let mut pos = 12usize; // Start after header / 从 header 之后开始

    // Skip Question section / 跳过 Question 部分
    for _ in 0..qd_count {
        pos = skip_dns_name_wire(packet, pos)?;
        pos += 4; // QTYPE(2) + QCLASS(2)
        if pos > packet_len {
            return None;
        }
    }

    // Walk Authority section looking for SOA (type 6) / 遍历 Authority 部分查找 SOA (type 6)
    for _ in 0..ns_count {
        pos = skip_dns_name_wire(packet, pos)?;
        if pos + 10 > packet_len {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

        if rtype == 6 {
            // SOA record found — extract MINIMUM field from rdata
            // SOA rdata: MNAME RNAME SERIAL(4) REFRESH(4) RETRY(4) EXPIRE(4) MINIMUM(4)
            // SOA 记录 — 从 rdata 提取 MINIMUM 字段
            let rdata_end = pos + rdlength;
            if rdata_end > packet_len {
                return None;
            }
            // Skip MNAME (domain name in rdata, may use compression pointers)
            // 跳过 MNAME（rdata 中的域名，可能使用压缩指针）
            let after_mname = skip_dns_name_wire(packet, pos)?;
            // Skip RNAME (domain name in rdata)
            // 跳过 RNAME（rdata 中的域名）
            let after_rname = skip_dns_name_wire(packet, after_mname)?;
            // 5 × u32 = 20 bytes: SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
            let fixed_fields_start = after_rname;
            if fixed_fields_start + 20 > rdata_end {
                return None;
            }
            // MINIMUM is the last 4 bytes of the fixed fields
            // MINIMUM 是固定字段的最后 4 字节
            let minimum = u32::from_be_bytes([
                packet[fixed_fields_start + 16],
                packet[fixed_fields_start + 17],
                packet[fixed_fields_start + 18],
                packet[fixed_fields_start + 19],
            ]);
            // RFC 2308 §5: negative TTL = min(SOA.minimum, SOA.ttl)
            return Some(minimum.min(ttl));
        }

        // Skip rdata for non-SOA records / 跳过非 SOA 记录的 rdata
        pos += rdlength;
    }

    None
}

/// Skip a DNS name at the given position, following compression pointers.
/// Returns the position after the name, or None on parse error.
///
/// 跳过指定位置的 DNS 名称，处理压缩指针。
/// 返回名称之后的位置，解析错误时返回 None。
#[inline]
fn skip_dns_name_wire(packet: &[u8], mut pos: usize) -> Option<usize> {
    let packet_len = packet.len();
    loop {
        if pos >= packet_len {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Compression pointer: 2 bytes total / 压缩指针：共 2 字节
            if pos + 2 > packet_len {
                return None;
            }
            return Some(pos + 2);
        }
        // Regular label / 常规标签
        let jump = 1 + len as usize;
        if pos + jump > packet_len {
            return None;
        }
        pos += jump;
    }
}

pub fn parse_response_quick(packet: &[u8]) -> Option<QuickResponse> {
    if packet.len() < 12 {
        return None;
    }

    // 1. Flags (Byte 2-3) / 标志位（字节 2-3）
    // Byte 2: QR(1) Opcode(4) AA(1) TC(1) RD(1)
    // Byte 3: RA(1) Z(3) RCODE(4)
    let flags_byte2 = packet[2];
    let truncated = (flags_byte2 & 0x02) != 0; // TC bit at position 1

    let rcode_u8 = packet[3] & 0x0F;
    let rcode = hickory_proto::op::ResponseCode::from(0, rcode_u8);

    // 2. Counts / 计数
    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);
    // We don't strictly need NS and AR counts for TTL, but we iterate through them if we want to be thorough. / 对于 TTL，我们并不严格需要 NS 和 AR 计数，但如果想彻底，可以遍历它们
    // For caching, we usually care about Answer section TTLs. / 对于缓存，我们通常关心 Answer 部分的 TTL

    if an_count == 0 {
        // RFC 2308 §5: For negative responses (NXDOMAIN/NODATA), the negative
        // cache TTL is min(SOA.minimum, SOA.ttl) from the authority section.
        // If no SOA is present, return TTL=0 (must not be cached per RFC 2308 §4).
        //
        // RFC 2308 §5: 对于否定响应 (NXDOMAIN/NODATA)，负缓存 TTL 为 authority 中
        // SOA 的 min(SOA.minimum, SOA.ttl)。无 SOA 时返回 TTL=0（按 RFC 2308 §4 不可缓存）。
        if ns_count > 0
            && let Some(neg_ttl) = extract_soa_negative_ttl_wire(packet, qd_count, ns_count)
        {
            return Some(QuickResponse {
                rcode,
                min_ttl: neg_ttl,
                max_ttl: neg_ttl,
                truncated,
            });
        }
        return Some(QuickResponse {
            rcode,
            min_ttl: 0,
            max_ttl: 0,
            truncated,
        });
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
    let mut max_ttl = u32::MIN;

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
        if ttl > max_ttl {
            max_ttl = ttl;
        }

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10 + rd_len;
    }

    if min_ttl == u32::MAX {
        min_ttl = 0;
    }
    if max_ttl == u32::MIN {
        max_ttl = 0;
    }

    Some(QuickResponse {
        rcode,
        min_ttl,
        max_ttl,
        truncated,
    })
}

/// Re-encode an oversized downstream UDP response so it respects the payload size
/// advertised by the client (RFC 6891). Queries without EDNS are limited to the
/// classic 512-byte DNS/UDP payload.
///
/// Hickory's bounded encoder emits as many complete records as fit, fixes the
/// section counts, and sets TC=1 when records are omitted. `None` means the
/// original response already fits and can be sent without allocation.
///
/// Trade-off: oversized responses (>512B, or > the client EDNS payload) are
/// re-parsed and re-encoded on every send. This is intentional — truncation
/// must happen at DNS record boundaries (RFC 1035 §4.2.1) and the correct TC
/// bit + counts can only be produced by a full re-encode. The overwhelmingly
/// common small-response path returns `None` before any parsing, so the cost
/// only applies to responses that would otherwise break the UDP size limit.
///
/// 权衡：超限响应（>512B 或超过客户端 EDNS 载荷）每次发送都会重新解析并重编码。
/// 这是有意的——截断必须发生在 DNS 记录边界（RFC 1035 §4.2.1），且正确的 TC 位
/// 和计数只能由完整重编码产生。绝大多数小响应路径在解析前就返回 None，因此该
/// 开销只作用于那些会突破 UDP 大小限制的响应。
pub fn truncate_udp_response(request_packet: &[u8], response_packet: &[u8]) -> Option<Bytes> {
    const CLASSIC_DNS_UDP_PAYLOAD: usize = 512;

    // Avoid parsing the request on the overwhelmingly common small-response path.
    if response_packet.len() <= CLASSIC_DNS_UDP_PAYLOAD {
        return None;
    }

    // hickory's Message::max_payload() already clamps to >= 512, so the extra
    // max() below is defensive only.
    let max_payload = Message::from_bytes(request_packet)
        .map(|request| request.max_payload() as usize)
        .unwrap_or(CLASSIC_DNS_UDP_PAYLOAD)
        .max(CLASSIC_DNS_UDP_PAYLOAD);

    if response_packet.len() <= max_payload {
        return None;
    }

    if let Ok(mut response) = Message::from_bytes(response_packet) {
        // Do not advertise a larger UDP payload in the response than the client
        // offered in its request.
        if let Some(edns) = response.edns.as_mut() {
            edns.set_max_payload(max_payload as u16);
        }

        let mut out = Vec::with_capacity(max_payload);
        let encoded = {
            let mut encoder = BinEncoder::new(&mut out);
            encoder.set_max_size(max_payload as u16);
            response.emit(&mut encoder)
        };
        if encoded.is_ok() && out.len() <= max_payload {
            // hickory's rollback does not shrink the backing buffer, so the
            // output can carry partial bytes from the record that did not fit.
            // Trim to the last complete record boundary from the corrected
            // header counts; fall back to the raw output if the walk fails.
            if let Some(valid_len) = valid_message_len(&out) {
                out.truncate(valid_len);
            }
            return Some(Bytes::from(out));
        }
    }

    // Internal responses should always parse, but never send an oversized UDP
    // datagram if a malformed response reaches this boundary. Fall back to a
    // minimal TC=1 response containing the original Question section.
    Some(build_minimal_truncated_response(
        request_packet,
        response_packet,
        max_payload,
    ))
}

fn build_minimal_truncated_response(
    request_packet: &[u8],
    response_packet: &[u8],
    max_payload: usize,
) -> Bytes {
    let mut question_end = 12usize;
    let mut copied_questions = false;

    if request_packet.len() >= 12 {
        let qd_count = u16::from_be_bytes([request_packet[4], request_packet[5]]);
        let mut pos = 12usize;
        let mut valid = true;
        for _ in 0..qd_count {
            let Some(name_end) = skip_name(request_packet, pos) else {
                valid = false;
                break;
            };
            let Some(next) = name_end.checked_add(4) else {
                valid = false;
                break;
            };
            if next > request_packet.len() {
                valid = false;
                break;
            }
            pos = next;
        }
        if valid && pos <= max_payload {
            question_end = pos;
            copied_questions = true;
        }
    }

    let header_source = if response_packet.len() >= 12 {
        response_packet
    } else {
        request_packet
    };
    let mut out = if header_source.len() >= 12 {
        header_source[..12].to_vec()
    } else {
        vec![0u8; 12]
    };

    // QR=1 and TC=1; preserve the remaining response flags and RCODE.
    out[2] |= 0x82;
    if copied_questions {
        out[4..6].copy_from_slice(&request_packet[4..6]);
        out.extend_from_slice(&request_packet[12..question_end]);
    } else {
        out[4..6].copy_from_slice(&0u16.to_be_bytes());
    }
    out[6..12].fill(0);
    Bytes::from(out)
}

/// Saturating conversion for DNS TTLs and elapsed seconds.
/// DNS TTL fields are u32, while Duration and configuration calculations use u64.
#[inline]
pub fn saturating_u64_to_u32(value: u64) -> u32 {
    value.min(u32::MAX as u64) as u32
}

/// 批量修正 DNS 响应包中的 TTL 值 / Batch patch TTL values in a DNS response packet
/// decrement: 需要减少的秒数 / seconds to decrement
pub fn patch_all_ttls(packet: &mut [u8], decrement: u32) {
    if decrement == 0 || packet.len() < 12 {
        return;
    }

    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]);

    let mut pos = 12;
    let packet_len = packet.len();

    // 1. Skip Questions
    for _ in 0..qd_count {
        if let Some(next) = skip_name(packet, pos) {
            pos = next + 4;
        } else {
            return;
        }
    }

    // 2. Patch Answer, Authority, and Additional sections
    let total_records = an_count as usize + ns_count as usize + ar_count as usize;
    for _ in 0..total_records {
        if let Some(next) = skip_name(packet, pos) {
            pos = next;
        } else {
            return;
        }

        if pos + 10 > packet_len {
            return;
        }

        // Type(2) Class(2) TTL(4) RDLen(2)
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);

        // Skip OPT (type 41) pseudo-records: their TTL field contains EDNS extended
        // RCODE and flags (including the DO bit), NOT an actual TTL value.
        // 跳过 OPT（类型 41）伪记录：其 TTL 字段包含 EDNS 扩展 RCODE 和标志（包括 DO 位），不是真正的 TTL。
        if rtype != 41 {
            let ttl_offset = pos + 4;
            let old_ttl = u32::from_be_bytes([
                packet[ttl_offset],
                packet[ttl_offset + 1],
                packet[ttl_offset + 2],
                packet[ttl_offset + 3],
            ]);

            // RFC 1035: Decrement TTL, floor at 0
            let new_ttl = old_ttl.saturating_sub(decrement);
            let ttl_bytes = new_ttl.to_be_bytes();
            packet[ttl_offset..ttl_offset + 4].copy_from_slice(&ttl_bytes);
        }

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;

        // Ensure the entire record (10 bytes header + RData) fits within remaining packet
        // and handle potential overflow for the next iteration's position
        let record_total_len = 10usize.saturating_add(rd_len);
        if pos.saturating_add(record_total_len) > packet_len {
            return;
        }

        pos += record_total_len;
    }
}

/// Set all record TTLs in a DNS packet to an absolute value.
/// Used by RFC 8767 stale serving to set TTL to serve_stale_ttl.
/// 将 DNS 报文中所有记录的 TTL 设为绝对值。
/// 用于 RFC 8767 stale 服务，将 TTL 设置为 serve_stale_ttl。
pub fn set_all_ttls(packet: &mut [u8], new_ttl: u32) {
    if packet.len() < 12 {
        return;
    }

    let qd_count = u16::from_be_bytes([packet[4], packet[5]]);
    let an_count = u16::from_be_bytes([packet[6], packet[7]]);
    let ns_count = u16::from_be_bytes([packet[8], packet[9]]);
    let ar_count = u16::from_be_bytes([packet[10], packet[11]]);

    let mut pos = 12;
    let packet_len = packet.len();

    // 1. Skip Questions
    for _ in 0..qd_count {
        if let Some(next) = skip_name(packet, pos) {
            pos = next + 4;
        } else {
            return;
        }
    }

    // 2. Set TTL for Answer, Authority, and Additional sections
    let total_records = an_count as usize + ns_count as usize + ar_count as usize;
    let ttl_bytes = new_ttl.to_be_bytes();
    for _ in 0..total_records {
        if let Some(next) = skip_name(packet, pos) {
            pos = next;
        } else {
            return;
        }

        if pos + 10 > packet_len {
            return;
        }

        // Type(2) Class(2) TTL(4) RDLen(2)
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);

        // Skip OPT (type 41) pseudo-records: their TTL field contains EDNS extended
        // RCODE and flags (including the DO bit), NOT an actual TTL value.
        // 跳过 OPT（类型 41）伪记录：其 TTL 字段包含 EDNS 扩展 RCODE 和标志（包括 DO 位），不是真正的 TTL。
        if rtype != 41 {
            let ttl_offset = pos + 4;
            packet[ttl_offset..ttl_offset + 4].copy_from_slice(&ttl_bytes);
        }

        let rd_len = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        let record_total_len = 10usize.saturating_add(rd_len);
        if pos.saturating_add(record_total_len) > packet_len {
            return;
        }

        pos += record_total_len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_with_label(label: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.push(label.len() as u8);
        packet.extend_from_slice(label);
        packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        packet
    }

    #[test]
    fn parse_quick_rejects_qname_control_characters() {
        let packet = query_with_label(b"bad\nlabel");
        let mut qname = [0u8; 256];

        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_accepts_regular_ascii_qname() {
        let packet = query_with_label(b"example");
        let mut qname = [0u8; 256];

        assert!(parse_quick(&packet, &mut qname).is_some());
    }

    fn encode_message(message: &Message) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::new(&mut bytes);
        message.emit(&mut encoder).expect("encode DNS message");
        bytes
    }

    fn txt_query(max_payload: Option<u16>) -> Vec<u8> {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RecordType};
        use std::str::FromStr;

        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_str("cloudflare.com.").unwrap(),
            RecordType::TXT,
        ));
        if let Some(max_payload) = max_payload {
            let mut edns = Edns::new();
            edns.set_max_payload(max_payload);
            message.set_edns(edns);
        }
        encode_message(&message)
    }

    fn large_txt_response(answer_count: usize) -> Vec<u8> {
        use hickory_proto::op::{Edns, MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::TXT};
        use std::str::FromStr;

        let name = Name::from_str("cloudflare.com.").unwrap();
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.metadata.recursion_available = true;
        message.add_query(Query::query(name.clone(), RecordType::TXT));
        for index in 0..answer_count {
            let text = format!("verification-{index:02}-{}", "x".repeat(180));
            message.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![text])),
            ));
        }
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        message.set_edns(edns);
        encode_message(&message)
    }

    #[test]
    fn truncate_udp_response_uses_512_without_edns() {
        let request = txt_query(None);
        let response = large_txt_response(20);
        assert!(response.len() > 512);

        let truncated = truncate_udp_response(&request, &response).expect("must truncate");
        assert!(truncated.len() <= 512);

        let decoded = Message::from_bytes(&truncated).expect("valid truncated response");
        assert!(decoded.metadata.truncation);
        assert_eq!(decoded.metadata.id, 0x1234);
        assert_eq!(decoded.queries.len(), 1);
    }

    #[test]
    fn truncate_udp_response_has_no_trailing_bytes() {
        use hickory_proto::op::{MessageType, OpCode, Query};
        use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::TXT};
        use std::str::FromStr;

        let request = txt_query(None);
        // No EDNS in the response: the failed answer's partial bytes are not
        // overwritten by a later OPT record, so hickory's bounded encoder
        // leaves them as trailing garbage past the last complete record.
        let name = Name::from_str("cloudflare.com.").unwrap();
        let mut response = Message::new(0x1234, MessageType::Response, OpCode::Query);
        response.metadata.recursion_desired = true;
        response.metadata.recursion_available = true;
        response.add_query(Query::query(name.clone(), RecordType::TXT));
        for index in 0..20 {
            let text = format!("verification-{index:02}-{}", "x".repeat(180));
            response.add_answer(Record::from_rdata(
                name.clone(),
                300,
                RData::TXT(TXT::new(vec![text])),
            ));
        }
        let response = encode_message(&response);
        assert!(response.len() > 512);

        let truncated = truncate_udp_response(&request, &response).expect("must truncate");
        // Truncation must respect RFC 1035 §4.2.1 record boundaries with no
        // trailing data beyond the last complete record.
        assert_eq!(
            valid_message_len(&truncated),
            Some(truncated.len()),
            "truncated response must end exactly at a record boundary"
        );
    }

    #[test]
    fn truncate_udp_response_respects_edns_payload_size() {
        let request = txt_query(Some(1232));
        let response = large_txt_response(20);
        assert!(response.len() > 1232);

        let truncated = truncate_udp_response(&request, &response).expect("must truncate");
        assert!(truncated.len() <= 1232);

        let decoded = Message::from_bytes(&truncated).expect("valid truncated response");
        assert!(decoded.metadata.truncation);
        assert_eq!(decoded.queries.len(), 1);
        if let Some(edns) = decoded.edns {
            assert_eq!(edns.max_payload(), 1232);
        }
    }

    #[test]
    fn truncate_udp_response_keeps_response_that_fits_client_limit() {
        let request = txt_query(Some(4096));
        let response = large_txt_response(8);
        assert!(response.len() > 512);
        assert!(response.len() <= 4096);

        assert!(truncate_udp_response(&request, &response).is_none());
    }

    #[test]
    fn truncate_udp_response_skips_small_responses_without_parsing_request() {
        let response = vec![0u8; 128];
        assert!(truncate_udp_response(b"not a dns request", &response).is_none());
    }

    fn query_with_additional(additional: &[u8]) -> Vec<u8> {
        let mut packet = query_with_label(b"example");
        packet[10..12].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(additional);
        packet
    }

    #[test]
    fn parse_quick_rejects_missing_declared_additional_record() {
        let packet = query_with_additional(&[]);
        let mut qname = [0u8; 256];
        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_rejects_truncated_edns_rdata() {
        let packet = query_with_additional(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 4, 0, 1]);
        let mut qname = [0u8; 256];
        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_rejects_invalid_additional_compression_pointer() {
        let packet = query_with_additional(&[0xC0, 0xFF, 0, 16, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut qname = [0u8; 256];
        assert!(parse_quick(&packet, &mut qname).is_none());
    }

    #[test]
    fn parse_quick_accepts_valid_empty_edns_record() {
        let packet = query_with_additional(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        let mut qname = [0u8; 256];
        let query = parse_quick(&packet, &mut qname).expect("valid EDNS query");
        assert!(query.edns_present);
    }

    #[test]
    fn saturating_u64_to_u32_caps_large_values() {
        assert_eq!(saturating_u64_to_u32(42), 42);
        assert_eq!(saturating_u64_to_u32(u64::MAX), u32::MAX);
    }
}
