use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache as MokaCache;
use serde::Deserialize;

/// MaxMind GeoLite2-Country 数据库结构 / MaxMind GeoLite2-Country database structure
#[derive(Deserialize)]
struct MaxMindCountryRecord {
    country: Option<MaxMindCountry>,
    registered_country: Option<MaxMindCountry>,
    represented_country: Option<MaxMindCountry>,
}

#[derive(Deserialize)]
struct MaxMindCountry {
    iso_code: Option<String>,
}

/// MaxMind GeoIP 数据库管理器 / MaxMind GeoIP database manager
pub struct GeoIpManager {
    /// MaxMind DB reader (使用内存映射，线程安全) / MaxMind DB reader (memory-mapped, thread-safe)
    reader: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    /// 查询结果缓存（IP -> GeoIP 结果） / Query result cache (IP -> GeoIP result)
    cache: MokaCache<IpAddr, GeoIpResult>,
}

/// GeoIP 查询结果 / GeoIP query result
#[derive(Debug, Clone)]
pub struct GeoIpResult {
    /// ISO 3166-1 alpha-2 国家代码（如 "CN", "US"） / ISO 3166-1 alpha-2 country code (e.g., "CN", "US")
    pub country_code: Option<String>,
    /// 是否为私有 IP 地址 / Whether it's a private IP address
    pub is_private: bool,
}

impl GeoIpManager {
    /// 创建新的 GeoIP 管理器 / Create new GeoIP manager
    /// 
    /// # 参数 / Parameters
    /// - `db_path`: MMDB 文件路径（可选） / MMDB file path (optional)
    /// - `cache_capacity`: 缓存容量 / Cache capacity
    /// - `cache_ttl`: 缓存 TTL（秒） / Cache TTL (seconds)
    pub fn new(
        db_path: Option<String>,
        cache_capacity: u64,
        cache_ttl: u64,
    ) -> anyhow::Result<Self> {
        let reader: Result<Option<maxminddb::Reader<Vec<u8>>>, anyhow::Error> = if let Some(path) = db_path {
            if !std::path::Path::new(&path).exists() {
                tracing::warn!(geoip_db = %path, "GeoIP database file not found");
                Ok(None)
            } else {
                match maxminddb::Reader::open_readfile(&path) {
                    Ok(reader) => {
                        tracing::info!(
                            geoip_db = %path,
                            "GeoIP database loaded successfully"
                        );
                        Ok(Some(reader))
                    }
                    Err(e) => {
                        tracing::warn!(
                            geoip_db = %path,
                            error = %e,
                            "Failed to open GeoIP database"
                        );
                        Ok(None)
                    }
                }
            }
        } else {
            tracing::debug!("No GeoIP database path configured");
            Ok(None)
        };

        let cache = MokaCache::builder()
            .max_capacity(cache_capacity)
            .time_to_live(Duration::from_secs(cache_ttl))
            .build();

        Ok(Self {
            reader: Arc::new(reader?),
            cache,
        })
    }

    /// 查询 IP 的 GeoIP 信息 / Lookup GeoIP information for an IP address
    /// 
    /// # 参数 / Parameters
    /// - `ip`: 要查询的 IP 地址 / IP address to lookup
    /// 
    /// # 返回 / Returns
    /// GeoIP 查询结果（包含国家代码和私有 IP 标志） / GeoIP result (with country code and private IP flag)
    #[inline]
    pub fn lookup(&self, ip: IpAddr) -> GeoIpResult {
        // 先查缓存 / Check cache first
        if let Some(result) = self.cache.get(&ip) {
            return result.clone();
        }

        // 查询 MMDB / Query MMDB
        let result = if let Some(reader) = self.reader.as_ref() {
            self.lookup_mmdb(reader, ip)
        } else {
            // 没有 MMDB 文件，只检测私有 IP / No MMDB file, only check private IP
            GeoIpResult {
                country_code: None,
                is_private: is_private_ip(ip),
            }
        };

        // 更新缓存 / Update cache
        self.cache.insert(ip, result.clone());
        result
    }

    /// 从 MMDB 查询 / Lookup from MMDB
    fn lookup_mmdb(&self, reader: &maxminddb::Reader<Vec<u8>>, ip: IpAddr) -> GeoIpResult {
        // 使用 MaxMind 数据结构进行查询 / Use MaxMind data structure for lookup
        match reader.lookup::<MaxMindCountryRecord>(ip) {
            Ok(record) => {
                // 尝试从多个字段获取国家代码 / Try to get country code from multiple fields
                // 优先级: country > registered_country > represented_country
                // Priority: country > registered_country > represented_country
                let country_code = record
                    .country
                    .or(record.registered_country)
                    .or(record.represented_country)
                    .and_then(|c| c.iso_code)
                    .map(|s| s.to_uppercase());
                
                GeoIpResult {
                    country_code,
                    is_private: is_private_ip(ip),
                }
            }
            Err(_) => {
                // 查询失败，回退到私有 IP 检测 / Lookup failed, fallback to private IP check
                GeoIpResult {
                    country_code: None,
                    is_private: is_private_ip(ip),
                }
            }
        }
    }

    /// 重新加载 MMDB 数据库 / Reload MMDB database
    /// 
    /// # 参数 / Parameters
    /// - `db_path`: 新的 MMDB 文件路径 / New MMDB file path
    pub fn reload(&mut self, db_path: Option<String>) -> anyhow::Result<()> {
        if let Some(path) = db_path {
            match maxminddb::Reader::open_readfile(&path) {
                Ok(reader) => {
                    self.reader = Arc::new(Some(reader));
                    self.cache.invalidate_all();
                    tracing::info!(
                        geoip_db = %path,
                        "GeoIP database reloaded successfully"
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!(
                        geoip_db = %path,
                        error = %e,
                        "Failed to reload GeoIP database"
                    );
                    Err(e.into())
                }
            }
        } else {
            tracing::debug!("No GeoIP database path to reload");
            Ok(())
        }
    }

    /// 检查 MMDB 是否已加载 / Check if MMDB is loaded
    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }
}

/// 检查 IP 是否为私有地址 / Check if IP is private address
/// 这是一个公开的工具函数，供 matcher 使用 / This is a public utility function for matchers
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.segments()[0] == 0xfe80 // ULA (Unique Local Address)
                || (ipv6.segments()[0] == 0xfc00 || ipv6.segments()[0] == 0xfd00) // Reserved for documentation
        }
    }
}

// GeoIP tests / GeoIP 测试
// Tests for GeoIP manager functionality, private IP detection, and configuration parsing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_private_ip() {
        // Arrange: Define test IPs for various private and public ranges
        // IPv4 private addresses / IPv4 私有地址
        let ipv4_private = vec![
            "10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"
        ];
        // IPv4 public addresses / IPv4 公网地址
        let ipv4_public = vec![
            "8.8.8.8", "1.1.1.1"
        ];
        // IPv6 loopback and ULA / IPv6 回环地址和ULA
        let ipv6_private = vec![
            "::1", "fe80::1", "fc00::1", "fd00::1"
        ];
        
        // Act & Assert: Verify IPv4 private addresses are detected
        for ip_str in ipv4_private {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(is_private_ip(ip), "{} should be detected as private", ip_str);
        }
        
        // Act & Assert: Verify IPv4 public addresses are not private
        for ip_str in ipv4_public {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(!is_private_ip(ip), "{} should not be detected as private", ip_str);
        }
        
        // Act & Assert: Verify IPv6 private addresses are detected
        for ip_str in ipv6_private {
            let ip: IpAddr = ip_str.parse().unwrap();
            assert!(is_private_ip(ip), "{} should be detected as private", ip_str);
        }
    }

    #[test]
    fn test_geoip_manager_no_db() {
        // Arrange: Create GeoIpManager without MMDB file
        let manager = GeoIpManager::new(None, 1000, 3600).unwrap();
        let test_ip: IpAddr = "8.8.8.8".parse().unwrap();
        
        // Act & Assert: Verify manager is not loaded
        assert!(!manager.is_loaded(), "Manager should not be loaded without MMDB file");
        
        // Act: Lookup IP address
        let result = manager.lookup(test_ip);
        
        // Assert: Verify lookup returns empty result for unloaded manager
        assert_eq!(result.country_code, None, "Country code should be None without MMDB");
        assert!(!is_private_ip(test_ip), "8.8.8.8 should not be a private IP");
    }

    #[test]
    fn test_geoip_country_code_extraction() {
        // Arrange: Define MMDB file path and test IPs
        let db_path = "tests/data/GeoLite2-Country.mmdb";
        let us_ip: IpAddr = "8.8.8.8".parse().unwrap();
        let cn_ip: IpAddr = "1.2.4.0".parse().unwrap();
        
        // Act & Assert: Skip test if MMDB file not available
        if !std::path::Path::new(db_path).exists() {
            println!("Skipping test_geoip_country_code_extraction: MMDB file not found at {}", db_path);
            return;
        }
        
        // Act: Create GeoIpManager with MMDB file
        let manager = GeoIpManager::new(
            Some(db_path.to_string()),
            1000,
            3600,
        ).unwrap();
        
        // Assert: Verify manager is loaded
        assert!(manager.is_loaded(), "Manager should be loaded with MMDB file");
        
        // Act: Lookup US IP (8.8.8.8 is Google DNS)
        let result = manager.lookup(us_ip);
        
        // Assert: Verify US country code
        assert_eq!(result.country_code.as_deref(), Some("US"), 
            "8.8.8.8 should resolve to US country code");
        assert!(!result.is_private, "8.8.8.8 should not be private IP");
        
        // Act: Lookup CN IP (1.2.4.0 is China)
        let result = manager.lookup(cn_ip);
        
        // Assert: Verify CN country code
        assert_eq!(result.country_code.as_deref(), Some("CN"), 
            "1.2.4.0 should resolve to CN country code");
        assert!(!result.is_private, "1.2.4.0 should not be private IP");
    }

    #[test]
    fn test_geoip_config_parsing() {
        // Arrange: Create configuration with GeoIP country matcher
        let raw = serde_json::json!({
            "pipelines": [{
                "id": "test",
                "rules": [{
                    "name": "china_rule",
                    "matchers": [{
                        "type": "geoip_country",
                        "country_codes": ["CN", "US", "JP"]
                    }],
                    "actions": [{
                        "type": "allow"
                    }]
                }]
            }]
        });

        // Act: Parse the configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).unwrap();
        let rule = &cfg.pipelines[0].rules[0];
        
        // Assert: Verify rule name and matcher count
        assert_eq!(rule.name, "china_rule", "Rule name should match");
        assert_eq!(rule.matchers.len(), 1, "Should have exactly one matcher");
        
        // Assert: Verify GeoipCountry matcher with country codes
        if let crate::config::Matcher::GeoipCountry { country_codes } = &rule.matchers[0].matcher {
            assert_eq!(country_codes, &vec!["CN".to_string(), "US".to_string(), "JP".to_string()],
                "Country codes should match configuration");
        } else {
            panic!("Expected GeoipCountry matcher");
        }
    }

    #[test]
    fn test_geoip_private_config_parsing() {
        // Arrange: Create configuration with GeoIP private matcher
        let raw = serde_json::json!({
            "pipelines": [{
                "id": "test",
                "rules": [{
                    "name": "private_rule",
                    "matchers": [{
                        "type": "geoip_private",
                        "expect": true
                    }],
                    "actions": [{
                        "type": "deny"
                    }]
                }]
            }]
        });

        // Act: Parse the configuration
        let cfg: crate::config::PipelineConfig = serde_json::from_value(raw).unwrap();
        let rule = &cfg.pipelines[0].rules[0];
        
        // Assert: Verify rule name and matcher count
        assert_eq!(rule.name, "private_rule", "Rule name should match");
        assert_eq!(rule.matchers.len(), 1, "Should have exactly one matcher");
        
        // Assert: Verify GeoipPrivate matcher with expect value
        if let crate::config::Matcher::GeoipPrivate { expect } = &rule.matchers[0].matcher {
            assert_eq!(*expect, true, "GeoipPrivate expect should be true");
        } else {
            panic!("Expected GeoipPrivate matcher");
        }
    }
}
