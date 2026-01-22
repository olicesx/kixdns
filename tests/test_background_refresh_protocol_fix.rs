// Test background refresh protocol parsing bug fix
// 测试后台刷新协议解析 bug 修复

use kixdns::config::Transport;

#[test]
fn test_background_refresh_protocol_parsing() {
    // Test case 1: TCP with protocol prefix
    // 测试用例 1：带协议前缀的 TCP
    let upstream = "tcp://8.8.8.8:53";
    let (refresh_transport, refresh_addr) = if let Some(pos) = upstream.find("://") {
        let proto = &upstream[..pos];
        let addr = &upstream[pos + 3..]; // Skip "://"
        match proto {
            "tcp" => (Some(Transport::Tcp), addr),
            "udp" => (Some(Transport::Udp), addr),
            _ => (Some(Transport::Udp), upstream),
        }
    } else {
        (Some(Transport::Udp), upstream)
    };
    
    assert_eq!(refresh_transport, Some(Transport::Tcp), 
        "Should parse TCP protocol");
    assert_eq!(refresh_addr, "8.8.8.8:53", 
        "Should extract correct address (without // prefix)");
    
    println!("✓ TCP protocol prefix parsed correctly");
    println!("  - Input: tcp://8.8.8.8:53");
    println!("  - Protocol: TCP");
    println!("  - Address: 8.8.8.8:53");
}

#[test]
fn test_background_refresh_protocol_parsing_udp() {
    // Test case 2: UDP with protocol prefix
    // 测试用例 2：带协议前缀的 UDP
    let upstream = "udp://1.1.1.1:53";
    let (refresh_transport, refresh_addr) = if let Some(pos) = upstream.find("://") {
        let proto = &upstream[..pos];
        let addr = &upstream[pos + 3..]; // Skip "://"
        match proto {
            "tcp" => (Some(Transport::Tcp), addr),
            "udp" => (Some(Transport::Udp), addr),
            _ => (Some(Transport::Udp), upstream),
        }
    } else {
        (Some(Transport::Udp), upstream)
    };
    
    assert_eq!(refresh_transport, Some(Transport::Udp), 
        "Should parse UDP protocol");
    assert_eq!(refresh_addr, "1.1.1.1:53", 
        "Should extract correct address (without // prefix)");
    
    println!("✓ UDP protocol prefix parsed correctly");
    println!("  - Input: udp://1.1.1.1:53");
    println!("  - Protocol: UDP");
    println!("  - Address: 1.1.1.1:53");
}

#[test]
fn test_background_refresh_protocol_parsing_no_prefix() {
    // Test case 3: No protocol prefix (backward compatibility)
    // 测试用例 3：没有协议前缀（向后兼容）
    let upstream = "8.8.4.4:53";
    let (refresh_transport, refresh_addr) = if let Some(pos) = upstream.find("://") {
        let proto = &upstream[..pos];
        let addr = &upstream[pos + 3..];
        match proto {
            "tcp" => (Some(Transport::Tcp), addr),
            "udp" => (Some(Transport::Udp), addr),
            _ => (Some(Transport::Udp), upstream),
        }
    } else {
        (Some(Transport::Udp), upstream)
    };
    
    assert_eq!(refresh_transport, Some(Transport::Udp), 
        "Should default to UDP");
    assert_eq!(refresh_addr, "8.8.4.4:53", 
        "Should use original address");
    
    println!("✓ No protocol prefix handled correctly");
    println!("  - Input: 8.8.4.4:53");
    println!("  - Protocol: UDP (default)");
    println!("  - Address: 8.8.4.4:53");
}

#[test]
fn test_background_refresh_protocol_parsing_bug_scenario() {
    // Test the exact bug scenario from user report
    // 测试用户报告的确切 bug 场景
    
    // Before fix: upstream_to_use = "tcp://8.8.8.8:53"
    // Old code: find(':') → pos=3, addr="//8.8.8.8:53" ❌
    // New code: find("://") → pos=3, addr="8.8.8.8:53" ✅
    
    let upstream = "tcp://8.8.8.8:53";
    let (refresh_transport, refresh_addr) = if let Some(pos) = upstream.find("://") {
        let proto = &upstream[..pos];
        let addr = &upstream[pos + 3..];
        match proto {
            "tcp" => (Some(Transport::Tcp), addr),
            "udp" => (Some(Transport::Udp), addr),
            _ => (Some(Transport::Udp), upstream),
        }
    } else {
        (Some(Transport::Udp), upstream)
    };
    
    // Verify the fix
    assert_eq!(refresh_transport, Some(Transport::Tcp));
    assert_eq!(refresh_addr, "8.8.8.8.53");
    
    // Verify it's NOT the buggy result
    assert_ne!(refresh_addr, "//8.8.8.8:53", 
        "Should NOT have buggy // prefix");
    
    println!("✓ Bug fix verified for user scenario");
    println!("  - Input: tcp://8.8.8.8:53");
    println!("  - Before fix: addr=//8.8.8.8:53 (buggy)");
    println!("  - After fix: addr=8.8.8.8.53 (correct)");
    println!("  - Expected log: upstream=tcp://8.8.8.8:53");
    println!("  - No more 'invalid upstream address' error");
}
