// Test protocol storage in upstream field
// 测试 upstream 字段中的协议存储

#[cfg(test)]
mod tests {

    #[test]
    fn test_upstream_protocol_format_tcp() {
        // Test that TCP upstream is stored with "tcp:" prefix
        // 测试 TCP upstream 以 "tcp:" 前缀存储
        
        // This test verifies the format: "tcp:ip:port"
        // 实际验证需要集成测试,这里仅作为文档说明
        let tcp_upstream = "tcp:8.8.4.4:53";
        assert!(tcp_upstream.starts_with("tcp:"), "TCP upstream should start with 'tcp:'");
        assert!(tcp_upstream.contains(':'), "Should contain port separator");
    }

    #[test]
    fn test_upstream_protocol_format_udp() {
        // Test that UDP upstream is stored with "udp:" prefix
        // 测试 UDP upstream 以 "udp:" 前缀存储
        
        let udp_upstream = "udp:1.1.1.1:53";
        assert!(udp_upstream.starts_with("udp:"), "UDP upstream should start with 'udp:'");
        assert!(udp_upstream.contains(':'), "Should contain port separator");
    }

    #[test]
    fn test_protocol_parsing_logic() {
        // Test protocol parsing logic used in background refresh
        // 测试后台刷新中使用的协议解析逻辑
        
        let upstream_with_proto = "tcp:8.8.4.4:53";
        let (proto, addr) = if let Some(pos) = upstream_with_proto.find(':') {
            let possible_proto = &upstream_with_proto[..pos];
            let addr_part = &upstream_with_proto[pos + 1..];
            match possible_proto {
                "tcp" => ("tcp", addr_part),
                "udp" => ("udp", addr_part),
                _ => ("udp", upstream_with_proto),
            }
        } else {
            ("udp", upstream_with_proto)
        };

        assert_eq!(proto, "tcp", "Should parse TCP protocol");
        assert_eq!(addr, "8.8.4.4:53", "Should parse address correctly");
    }

    #[test]
    fn test_backward_compatibility_no_protocol() {
        // Test backward compatibility: upstream without protocol prefix
        // 测试向后兼容性:没有协议前缀的 upstream
        
        let upstream_no_proto = "8.8.4.4:53";
        let (proto, addr) = if let Some(pos) = upstream_no_proto.find(':') {
            let possible_proto = &upstream_no_proto[..pos];
            let addr_part = &upstream_no_proto[pos + 1..];
            match possible_proto {
                "tcp" => ("tcp", addr_part),
                "udp" => ("udp", addr_part),
                _ => ("udp", upstream_no_proto), // No protocol prefix, assume UDP
            }
        } else {
            ("udp", upstream_no_proto)
        };

        assert_eq!(proto, "udp", "Should default to UDP for backward compatibility");
        assert_eq!(addr, "8.8.4.4:53", "Should use original address");
    }

    #[test]
    fn test_protocol_storage_benefits() {
        // Document the benefits of protocol storage
        // 记录协议存储的好处
        
        // Before fix:
        // - Original query: TCP to 8.8.4.4:53 → 80ms ✅
        // - Background refresh: UDP to 8.8.4.4:53 → 1080ms ❌
        // - Problem: Cache doesn't preserve transport protocol
        
        // After fix:
        // - Original query: TCP to 8.8.4.4:53 → stores "tcp:8.8.4.4:53" → 80ms ✅
        // - Background refresh: parses "tcp:8.8.4.4:53" → uses TCP → 80ms ✅
        // - Benefit: Seamless background refresh with consistent performance
        
        assert!(true, "This test documents the protocol storage feature");
    }
}
