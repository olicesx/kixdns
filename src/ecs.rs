//! EDNS Client Subnet (ECS) wire manipulation — RFC 7871
//! EDNS 客户端子网 (ECS) wire 操作 — RFC 7871
//!
//! Provides request-side ECS injection/stripping for the `Forward` action.
//! Only runs on cache-miss path (inside `handle_forward_decision`), so the
//! hot path (cache hit / static response) is never affected.
//!
//! 为 `Forward` 动作提供请求侧 ECS 注入/剥离。
//! 仅在缓存未命中路径（`handle_forward_decision` 内部）执行，
//! 热路径（缓存命中 / 静态响应）完全不受影响。

use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv6Addr};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};

use crate::config::EcsMode;

/// Default IPv4 source prefix length (RFC 7871 §11.1 recommendation)
/// 默认 IPv4 源前缀长度（RFC 7871 §11.1 建议）
pub const DEFAULT_PREFIX_V4: u8 = 24;

/// Default IPv6 source prefix length
/// 默认 IPv6 源前缀长度
pub const DEFAULT_PREFIX_V6: u8 = 56;

/// Apply ECS transformation to a DNS wire packet, returning modified bytes.
/// 对 DNS wire 包应用 ECS 变换，返回修改后的字节。
///
/// Returns the original packet bytes if:
/// - Mode is `Clear` but no ECS exists (no-op)
/// - Client IP is private (privacy protection, RFC 1918/ULA/loopback)
/// - Static IP is invalid
/// - Message parsing fails (malformed query)
///
/// 以下情况返回原始包字节：
/// - 模式为 `Clear` 但不存在 ECS（无需操作）
/// - 客户端 IP 为私有地址（隐私保护，RFC 1918/ULA/loopback）
/// - 静态 IP 无效
/// - 消息解析失败（畸形查询）
pub fn apply_ecs(packet: &[u8], mode: &EcsMode, peer_ip: IpAddr) -> Vec<u8> {
    match mode {
        EcsMode::Clear => strip_ecs(packet),
        EcsMode::FromClientIp {
            prefix_v4,
            prefix_v6,
        } => {
            if is_private_ip(&peer_ip) {
                return packet.to_vec();
            }
            let prefix = match peer_ip {
                IpAddr::V4(_) => *prefix_v4,
                IpAddr::V6(_) => *prefix_v6,
            };
            inject_ecs(packet, peer_ip, prefix)
        }
        EcsMode::Static { ip, prefix } => match ip.parse::<IpAddr>() {
            Ok(parsed) => inject_ecs(packet, parsed, *prefix),
            Err(_) => {
                tracing::warn!(ip = %ip, "invalid static ECS IP, skipping injection / 静态 ECS IP 无效，跳过注入");
                packet.to_vec()
            }
        },
    }
}

/// Inject (or replace) ECS OPT option into a DNS wire packet.
/// 向 DNS wire 包注入（或替换）ECS OPT 选项。
///
/// Uses hickory-proto `Message` round-trip for correctness — OPT pseudo-record
/// manipulation involves variable-length TLV encoding and ARCOUNT updates that
/// are error-prone at wire level. This only runs on cache-miss path.
///
/// 使用 hickory-proto `Message` 往返保证正确性 — OPT 伪记录操作涉及变长 TLV
/// 编码和 ARCOUNT 更新，在 wire 层操作容易出错。此函数仅在缓存未命中路径执行。
fn inject_ecs(packet: &[u8], addr: IpAddr, source_prefix: u8) -> Vec<u8> {
    let mut msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(e) => {
            tracing::debug!(error = %e, "ECS inject: failed to parse message, forwarding as-is / ECS 注入：解析消息失败，原样转发");
            return packet.to_vec();
        }
    };

    let subnet = ClientSubnet::new(addr, source_prefix, 0);

    // Insert or replace ECS option in the EDNS extensions
    // 在 EDNS 扩展中插入或替换 ECS 选项
    match msg.extensions_mut() {
        Some(edns) => {
            edns.options_mut().insert(EdnsOption::Subnet(subnet));
        }
        None => {
            // No existing OPT record — create one with default EDNS parameters and insert ECS
            // 不存在 OPT 记录 — 创建默认 EDNS 参数并插入 ECS
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(1232);
            edns.options_mut().insert(EdnsOption::Subnet(subnet));
            *msg.extensions_mut() = Some(edns);
        }
    }

    match msg.to_vec() {
        Ok(buf) => buf,
        Err(e) => {
            tracing::debug!(error = %e, "ECS inject: failed to re-encode message, forwarding as-is / ECS 注入：重新编码消息失败，原样转发");
            packet.to_vec()
        }
    }
}

/// Strip ECS OPT option from a DNS wire packet.
/// 从 DNS wire 包中剥离 ECS OPT 选项。
///
/// If no ECS option exists, returns the original packet unchanged.
/// 如果不存在 ECS 选项，原样返回原始包。
fn strip_ecs(packet: &[u8]) -> Vec<u8> {
    let mut msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(_) => return packet.to_vec(),
    };

    let has_ecs = msg
        .extensions()
        .as_ref()
        .and_then(|e| e.options().as_ref().get(&EdnsCode::Subnet))
        .is_some();

    if !has_ecs {
        return packet.to_vec();
    }

    if let Some(edns) = msg.extensions_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }

    match msg.to_vec() {
        Ok(buf) => buf,
        Err(_) => packet.to_vec(),
    }
}

/// Check if an IP address is private/internal (RFC 1918, ULA, loopback, link-local).
/// 检查 IP 地址是否为私有/内网地址 (RFC 1918, ULA, loopback, link-local)。
///
/// Private addresses must never be leaked via ECS.
/// 私有地址绝不能通过 ECS 泄露。
pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()       // RFC 1918: 10/8, 172.16/12, 192.168/16
            || v4.is_loopback()   // 127/8
            || v4.is_link_local() // 169.254/16
            || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()                    // ::1
            || v6.is_unspecified()              // ::
            || is_ula_v6(v6)                    // fc00::/7 (RFC 4193)
            || v6.is_unicast_link_local() // fe80::/10
        }
    }
}

/// Check if IPv6 address is Unique Local Address (ULA, fc00::/7).
/// 检查 IPv6 地址是否为唯一本地地址 (ULA, fc00::/7)。
fn is_ula_v6(v6: &Ipv6Addr) -> bool {
    // ULA range: fc00::/7 — check first byte's top 7 bits
    // ULA 范围：fc00::/7 — 检查首字节的高 7 位
    let octets = v6.octets();
    (octets[0] & 0xFE) == 0xFC
}

// ============================================================================
// EcsKey — Cache isolation identifier (RFC 7871)
// EcsKey — 缓存隔离标识 (RFC 7871)
// ============================================================================

/// ECS subnet identifier for cache hash, zero-alloc on stack.
/// 用于 cache hash 的 ECS 子网标识，栈上零分配。
///
/// Used to isolate cache entries by client subnet so that different
/// geographic regions get distinct cached responses.
/// 用于按客户端子网隔离缓存条目，使不同地理区域获得不同的缓存响应。
#[derive(Clone, Copy, Debug)]
pub struct EcsKey {
    /// Address family: 1=IPv4, 2=IPv6 / 地址族：1=IPv4, 2=IPv6
    pub family: u16,
    /// Source prefix length / 源前缀长度
    pub source_prefix: u8,
    /// Address bytes (up to 16 for IPv6) / 地址字节（IPv6 最多 16 字节）
    pub addr: [u8; 16],
    /// Number of valid bytes in `addr` / `addr` 中有效字节数
    pub addr_len: u8,
}

impl EcsKey {
    /// Compute cache key from pipeline ECS config + peer IP.
    /// 从 Pipeline ECS 配置 + peer IP 计算缓存键。
    ///
    /// Returns `None` when ECS should NOT be part of the cache key:
    /// - `Clear` mode (no isolation needed)
    /// - `FromClientIp` with private/loopback IP (privacy protection)
    /// 以下情况返回 `None`（ECS 不进入 cache key）：
    /// - `Clear` 模式（无需隔离）
    /// - `FromClientIp` 但 peer IP 为私有/回环地址（隐私保护）
    pub fn from_pipeline_config(ecs_mode: &EcsMode, peer_ip: IpAddr) -> Option<Self> {
        match ecs_mode {
            EcsMode::Clear => None,
            EcsMode::FromClientIp {
                prefix_v4,
                prefix_v6,
            } => {
                if is_private_ip(&peer_ip) {
                    return None;
                }
                Some(Self::from_ip(peer_ip, *prefix_v4, *prefix_v6))
            }
            EcsMode::Static { ip, prefix } => match ip.parse::<IpAddr>() {
                Ok(parsed) => {
                    let pv4 = *prefix;
                    // Static IPv6 uses full address for deterministic caching
                    // 静态 IPv6 使用完整地址以确保确定性缓存
                    let pv6 = 128u8;
                    Some(Self::from_ip(parsed, pv4, pv6))
                }
                Err(_) => None,
            },
        }
    }

    /// Build EcsKey from an IP address with prefix masking.
    /// 从 IP 地址和前缀掩码构建 EcsKey。
    fn from_ip(ip: IpAddr, prefix_v4: u8, prefix_v6: u8) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let mut addr = [0u8; 16];
                addr[..4].copy_from_slice(&v4.octets());
                let p = prefix_v4.min(32);
                mask_address(&mut addr, p, 32);
                let bytes_used = ((p as usize) + 7) / 8;
                Self {
                    family: 1,
                    source_prefix: p,
                    addr,
                    addr_len: bytes_used.min(4) as u8,
                }
            }
            IpAddr::V6(v6) => {
                let mut addr = v6.octets();
                let p = prefix_v6.min(128);
                mask_address(&mut addr, p, 128);
                let bytes_used = ((p as usize) + 7) / 8;
                Self {
                    family: 2,
                    source_prefix: p,
                    addr,
                    addr_len: bytes_used.min(16) as u8,
                }
            }
        }
    }

    /// Feed all identifying fields into a hasher for cache deduplication.
    /// 将所有标识字段喂入 hasher 以进行缓存去重。
    #[inline]
    pub fn hash_into<H: Hasher>(&self, h: &mut H) {
        self.family.hash(h);
        self.source_prefix.hash(h);
        h.write(&self.addr[..self.addr_len as usize]);
    }
}

/// Mask an address buffer to the given prefix length (in-place).
/// 将地址缓冲区掩码到指定前缀长度（原地操作）。
fn mask_address(addr: &mut [u8], prefix: u8, total_bits: u8) {
    if prefix >= total_bits {
        return;
    }
    let p = prefix as usize;
    let bytes_used = (p + 7) / 8;
    let bit = p % 8;
    if bit > 0 && bytes_used > 0 {
        addr[bytes_used - 1] &= 0xFF << (8 - bit);
    }
    // Compute end index before mutable borrow to avoid borrow checker conflict
    // 在可变借用前计算结束索引以避免借用检查器冲突
    let end = (total_bits as usize / 8).min(addr.len());
    for b in &mut addr[bytes_used..end] {
        *b = 0;
    }
}

/// Trivial test helper: check if ECS exists in a wire packet.
/// 简单测试辅助：检查 wire 包中是否存在 ECS。
#[cfg(test)]
pub(crate) fn has_ecs(packet: &[u8]) -> bool {
    let msg = match Message::from_vec(packet) {
        Ok(m) => m,
        Err(_) => return false,
    };
    msg.extensions()
        .as_ref()
        .and_then(|e| e.options().as_ref().get(&EdnsCode::Subnet))
        .is_some()
}

/// Extract ECS subnet info from a wire packet (for testing).
/// ClientSubnet fields are private in hickory-proto 0.24, so we serialize
/// to wire bytes and parse manually.
///
/// 从 wire 包中提取 ECS 子网信息（用于测试）。
/// hickory-proto 0.24 中 ClientSubnet 字段为私有，
/// 因此序列化为 wire 字节后手动解析。
#[cfg(test)]
pub(crate) fn extract_ecs_info(packet: &[u8]) -> Option<(IpAddr, u8, u8)> {
    let msg = Message::from_vec(packet).ok()?;
    let edns = msg.extensions().as_ref()?;
    let cs = match edns.options().as_ref().get(&EdnsCode::Subnet)? {
        EdnsOption::Subnet(cs) => cs,
        _ => return None,
    };
    // Serialize ClientSubnet to wire bytes, then parse manually
    // 将 ClientSubnet 序列化为 wire 字节，然后手动解析
    let wire: Vec<u8> = std::convert::TryFrom::try_from(cs).ok()?;
    if wire.len() < 4 {
        return None;
    }
    let family = u16::from_be_bytes([wire[0], wire[1]]);
    let source_prefix = wire[2];
    let scope_prefix = wire[3];
    let addr_bytes_needed = ((source_prefix as usize) + 7) / 8;
    let addr = match family {
        1 => {
            let mut octets = [0u8; 4];
            let copy_len = addr_bytes_needed.min(4);
            if wire.len() >= 4 + copy_len {
                octets[..copy_len].copy_from_slice(&wire[4..4 + copy_len]);
            }
            IpAddr::V4(std::net::Ipv4Addr::from(octets))
        }
        2 => {
            let mut octets = [0u8; 16];
            let copy_len = addr_bytes_needed.min(16);
            if wire.len() >= 4 + copy_len {
                octets[..copy_len].copy_from_slice(&wire[4..4 + copy_len]);
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some((addr, source_prefix, scope_prefix))
}

// ============================================================================
// Tests / 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

    /// Build a minimal DNS query wire packet for testing.
    /// 构建最小化 DNS 查询 wire 包用于测试。
    fn make_query(domain: &str, txid: u16) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(txid);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
        msg.to_vec().unwrap()
    }

    /// Build a DNS query with an existing OPT record (no ECS).
    /// 构建带 OPT 记录（无 ECS）的 DNS 查询。
    fn make_query_with_opt(domain: &str, txid: u16) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(txid);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(Name::from_str(domain).unwrap(), RecordType::A));
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        *msg.extensions_mut() = Some(edns);
        msg.to_vec().unwrap()
    }

    // ---- inject_ecs ----

    #[test]
    fn test_inject_ecs_into_plain_query() {
        let query = make_query("example.com", 0x1234);
        let modified = inject_ecs(&query, IpAddr::V4("203.0.113.5".parse().unwrap()), 24);

        assert!(has_ecs(&modified), "ECS should be present after injection");
        let (addr, src_prefix, scope) = extract_ecs_info(&modified).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
        assert_eq!(src_prefix, 24);
        assert_eq!(scope, 0, "query scope must be 0 / 查询 scope 必须为 0");
    }

    #[test]
    fn test_inject_ecs_into_query_with_existing_opt() {
        let query = make_query_with_opt("example.com", 0x1234);
        let modified = inject_ecs(&query, IpAddr::V4("203.0.113.5".parse().unwrap()), 24);

        assert!(has_ecs(&modified));
        let (addr, _, _) = extract_ecs_info(&modified).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
    }

    #[test]
    fn test_inject_ecs_v6() {
        let query = make_query("example.com", 0x1234);
        let v6: Ipv6Addr = "2001:db8:abcd:1234::5".parse().unwrap();
        let modified = inject_ecs(&query, IpAddr::V6(v6), 56);

        assert!(has_ecs(&modified));
        let (addr, src_prefix, _) = extract_ecs_info(&modified).unwrap();
        assert_eq!(src_prefix, 56);
        // Address should be truncated to /56 (first 7 bytes)
        // 地址应截断为 /56（前 7 字节）
        match addr {
            IpAddr::V6(v6_addr) => {
                let octets = v6_addr.octets();
                assert_eq!(&octets[..7], &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12]);
            }
            _ => panic!("expected IPv6 address"),
        }
    }

    #[test]
    fn test_inject_ecs_replaces_existing() {
        // First inject
        // 第一次注入
        let query = make_query("example.com", 0x1234);
        let modified = inject_ecs(&query, IpAddr::V4("203.0.113.5".parse().unwrap()), 24);
        assert!(has_ecs(&modified));

        // Inject again with different subnet — should replace, not duplicate
        // 用不同子网再次注入 — 应替换而非重复
        let re_modified = inject_ecs(&modified, IpAddr::V4("198.51.100.5".parse().unwrap()), 24);
        let (addr, _, _) = extract_ecs_info(&re_modified).unwrap();
        assert_eq!(addr, IpAddr::V4("198.51.100.0".parse().unwrap()));
    }

    // ---- strip_ecs ----

    #[test]
    fn test_strip_ecs_removes_ecs() {
        let query = make_query("example.com", 0x1234);
        let injected = inject_ecs(&query, IpAddr::V4("203.0.113.5".parse().unwrap()), 24);
        assert!(has_ecs(&injected));

        let stripped = strip_ecs(&injected);
        assert!(!has_ecs(&stripped), "ECS should be removed / ECS 应被移除");
    }

    #[test]
    fn test_strip_ecs_no_ecs_is_noop() {
        let query = make_query("example.com", 0x1234);
        assert!(!has_ecs(&query));

        let result = strip_ecs(&query);
        assert!(!has_ecs(&result));
    }

    // ---- apply_ecs (integration) ----

    #[test]
    fn test_apply_ecs_clear_mode() {
        let query = make_query("example.com", 0x1234);
        let injected = inject_ecs(&query, IpAddr::V4("203.0.113.5".parse().unwrap()), 24);

        let mode = EcsMode::Clear;
        let result = apply_ecs(&injected, &mode, "127.0.0.1".parse().unwrap());
        assert!(!has_ecs(&result));
    }

    #[test]
    fn test_apply_ecs_from_client_ip_v4() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let peer: IpAddr = "203.0.113.42".parse().unwrap();
        let result = apply_ecs(&query, &mode, peer);

        assert!(has_ecs(&result));
        let (addr, prefix, _) = extract_ecs_info(&result).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_apply_ecs_from_client_ip_private_skipped() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };

        // RFC 1918 private — should not inject
        // RFC 1918 私有地址 — 不应注入
        for ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1"] {
            let peer: IpAddr = ip.parse().unwrap();
            let result = apply_ecs(&query, &mode, peer);
            assert!(
                !has_ecs(&result),
                "private IP {ip} should not get ECS / 私有 IP 不应注入 ECS"
            );
        }

        // IPv6 ULA — should not inject
        // IPv6 ULA — 不应注入
        let ula: IpAddr = "fd00::1".parse().unwrap();
        let result = apply_ecs(&query, &mode, ula);
        assert!(
            !has_ecs(&result),
            "ULA should not get ECS / ULA 不应注入 ECS"
        );

        // IPv6 loopback
        let lo: IpAddr = "::1".parse().unwrap();
        let result = apply_ecs(&query, &mode, lo);
        assert!(!has_ecs(&result), "::1 should not get ECS");
    }

    #[test]
    fn test_apply_ecs_static_mode() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::Static {
            ip: "203.0.113.0".to_string(),
            prefix: 24,
        };
        let result = apply_ecs(&query, &mode, "127.0.0.1".parse().unwrap());

        assert!(has_ecs(&result));
        let (addr, prefix, _) = extract_ecs_info(&result).unwrap();
        assert_eq!(addr, IpAddr::V4("203.0.113.0".parse().unwrap()));
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_apply_ecs_static_invalid_ip_skipped() {
        let query = make_query("example.com", 0x1234);
        let mode = EcsMode::Static {
            ip: "not.an.ip.addr".to_string(),
            prefix: 24,
        };
        let result = apply_ecs(&query, &mode, "8.8.8.8".parse().unwrap());
        assert!(
            !has_ecs(&result),
            "invalid IP should not inject / 无效 IP 不应注入"
        );
    }

    #[test]
    fn test_apply_ecs_malformed_packet_passes_through() {
        let garbage = [0x00; 5];
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let result = apply_ecs(&garbage, &mode, "8.8.8.8".parse().unwrap());
        assert_eq!(
            result,
            garbage.to_vec(),
            "malformed packet should pass through / 畸形包应原样通过"
        );
    }

    // ---- is_private_ip ----

    #[test]
    fn test_is_private_ip() {
        // Private v4
        assert!(is_private_ip(&"10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"127.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse::<IpAddr>().unwrap()));

        // Public v4
        assert!(!is_private_ip(&"8.8.8.8".parse::<IpAddr>().unwrap()));
        assert!(!is_private_ip(&"203.0.113.1".parse::<IpAddr>().unwrap()));

        // Private v6
        assert!(is_private_ip(&"::1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"fd00::1".parse::<IpAddr>().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse::<IpAddr>().unwrap()));

        // Public v6
        assert!(!is_private_ip(
            &"2001:4860:4860::8888".parse::<IpAddr>().unwrap()
        ));
        assert!(!is_private_ip(
            &"2606:4700::1111".parse::<IpAddr>().unwrap()
        ));
    }

    // ---- EcsKey (cache isolation) ----

    #[test]
    fn test_ecs_key_from_client_ip_v4() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let key = EcsKey::from_pipeline_config(&mode, "203.0.113.42".parse().unwrap()).unwrap();

        assert_eq!(key.family, 1);
        assert_eq!(key.source_prefix, 24);
        // /24 means first 3 bytes are significant
        assert_eq!(key.addr_len, 3);
        assert_eq!(&key.addr[..3], &[203, 0, 113]);
    }

    #[test]
    fn test_ecs_key_from_client_ip_v6() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        let peer: IpAddr = "2001:db8:abcd:1234::5".parse().unwrap();
        let key = EcsKey::from_pipeline_config(&mode, peer).unwrap();

        assert_eq!(key.family, 2);
        assert_eq!(key.source_prefix, 56);
        // /56 means first 7 bytes are significant
        assert_eq!(key.addr_len, 7);
        assert_eq!(&key.addr[..7], &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12]);
    }

    #[test]
    fn test_ecs_key_from_client_ip_private_returns_none() {
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };
        // Private IPs should not produce an ECS key (privacy protection)
        // 私有 IP 不应产生 ECS key（隐私保护）
        assert!(EcsKey::from_pipeline_config(&mode, "10.0.0.1".parse().unwrap()).is_none());
        assert!(EcsKey::from_pipeline_config(&mode, "127.0.0.1".parse().unwrap()).is_none());
        assert!(EcsKey::from_pipeline_config(&mode, "192.168.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn test_ecs_key_clear_returns_none() {
        let mode = EcsMode::Clear;
        let key = EcsKey::from_pipeline_config(&mode, "8.8.8.8".parse().unwrap());
        assert!(
            key.is_none(),
            "Clear mode should not produce ECS key / Clear 模式不应产生 ECS key"
        );
    }

    #[test]
    fn test_ecs_key_static_mode() {
        let mode = EcsMode::Static {
            ip: "203.0.113.0".to_string(),
            prefix: 24,
        };
        let key = EcsKey::from_pipeline_config(&mode, "127.0.0.1".parse().unwrap()).unwrap();

        assert_eq!(key.family, 1);
        assert_eq!(key.source_prefix, 24);
        assert_eq!(&key.addr[..3], &[203, 0, 113]);
    }

    #[test]
    fn test_ecs_key_static_invalid_ip_returns_none() {
        let mode = EcsMode::Static {
            ip: "not.an.ip".to_string(),
            prefix: 24,
        };
        let key = EcsKey::from_pipeline_config(&mode, "8.8.8.8".parse().unwrap());
        assert!(key.is_none());
    }

    #[test]
    fn test_ecs_key_cache_hash_isolation() {
        use rustc_hash::FxHasher;
        use std::hash::Hasher;

        // Same IP, different /24 subnets should produce different EcsKeys
        // 相同 IP 段，不同 /24 子网应产生不同的 EcsKey
        let mode = EcsMode::FromClientIp {
            prefix_v4: 24,
            prefix_v6: 56,
        };

        let key1 = EcsKey::from_pipeline_config(&mode, "203.0.113.5".parse().unwrap()).unwrap();
        let key2 = EcsKey::from_pipeline_config(&mode, "203.0.113.100".parse().unwrap()).unwrap();
        let key3 = EcsKey::from_pipeline_config(&mode, "203.0.200.5".parse().unwrap()).unwrap();

        // Same /24 → same key
        assert_eq!(key1.addr[..3], key2.addr[..3]);

        // Different /24 → different key
        assert_ne!(key1.addr[..3], key3.addr[..3]);

        // Different EcsKeys → different hashes
        let mut h1 = FxHasher::default();
        key1.hash_into(&mut h1);
        let mut h3 = FxHasher::default();
        key3.hash_into(&mut h3);
        assert_ne!(
            h1.finish(),
            h3.finish(),
            "Different /24 subnets must produce different hashes / 不同 /24 子网必须产生不同的哈希"
        );
    }

    #[test]
    fn test_ecs_key_prefix_masking() {
        // /20 prefix: first 2 bytes + masked 3rd byte
        // /20 前缀：前 2 字节完整 + 第 3 字节掩码
        let mode = EcsMode::FromClientIp {
            prefix_v4: 20,
            prefix_v6: 56,
        };
        let key = EcsKey::from_pipeline_config(&mode, "203.0.113.5".parse().unwrap()).unwrap();

        // /20 = 20 bits = 2.5 bytes → 3 bytes used, 3rd byte masked to top 4 bits
        assert_eq!(key.addr_len, 3);
        assert_eq!(key.addr[0], 203);
        assert_eq!(key.addr[1], 0);
        // 113 & 0xF0 = 112 (0x70)
        assert_eq!(key.addr[2], 112);
    }
}
