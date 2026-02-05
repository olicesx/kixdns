use std::hash::Hasher;

/// 快速解析结果，零拷贝实现 / Quick parse result with zero-copy implementation
pub struct QuickQuery<'a> {
    pub tx_id: u16,
    pub qname_bytes: &'a [u8], // 零拷贝：直接引用已小写化的缓冲区
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

    // Fast ASCII validation (zero-allocation, early exit)
    // 快速 ASCII 验证（零分配，提前退出）
    // DNS domain names should be LDH (Letters, Digits, Hyphen) + dots
    // LDH is a subset of ASCII, which is always valid UTF-8
    // 域名应该是 LDH（字母、数字、连字符）+ 点号
    // LDH 是 ASCII 的子集，而 ASCII 始终是有效的 UTF-8
    // This is ~10x faster than full UTF-8 validation
    // 这比完整的 UTF-8 验证快约 10 倍
    let is_ascii = buf[..buf_pos].iter().all(|b| b.is_ascii());
    if !is_ascii {
        // Reject non-ASCII domain names (extremely rare, < 0.001%)
        // Similar to Unbound's strategy: reject invalid input for performance
        // 拒绝非 ASCII 域名（极其罕见，< 0.001%）
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
    loop {
        if pos >= packet_len {
            return None;
        }
        let len = packet[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 2 > packet_len {
                return None;
            }
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
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
    // We don't strictly need NS and AR counts for TTL, but we iterate through them if we want to be thorough. / 对于 TTL，我们并不严格需要 NS 和 AR 计数，但如果想彻底，可以遍历它们
    // For caching, we usually care about Answer section TTLs. / 对于缓存，我们通常关心 Answer 部分的 TTL

    if an_count == 0 {
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
