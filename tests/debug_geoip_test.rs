// GeoIP 调试测试
use std::net::IpAddr;
use kixdns::geoip::GeoIpManager;

#[test]
fn test_debug_geoip_china_ip() {
    use std::path::PathBuf;

    let dat_path = PathBuf::from("data/geoip.dat");
    if !dat_path.exists() {
        println!("Skipping test: data/geoip.dat not found");
        return;
    }

    let mut manager = GeoIpManager::new(None, 10000, 3600).unwrap();
    let count = manager.load_from_dat_file(&dat_path).unwrap();
    println!("Loaded {} GeoIP entries", count);

    // 测试几个 IP
    let test_ips = vec![
        "39.156.66.10",   // 中国
        "8.8.8.8",        // 美国 Google
        "1.1.1.1",        // 澳大利亚 Cloudflare
    ];

    for ip_str in test_ips {
        let test_ip: IpAddr = ip_str.parse().unwrap();
        let result = manager.lookup(test_ip);

        println!("\nIP: {}", ip_str);
        println!("Country code: {:?}", result.country_code);

        // 手动计算 IP 的 u32 表示
        if let IpAddr::V4(ipv4) = test_ip {
            let octets = ipv4.octets();
            let ip_u32_be = (octets[0] as u32) << 24
                | (octets[1] as u32) << 16
                | (octets[2] as u32) << 8
                | (octets[3] as u32);

            println!("IP octets: {:?}", octets);
            println!("IP as u32 (BE): 0x{:08x} ({})", ip_u32_be, ip_u32_be);
        }
    }
}
