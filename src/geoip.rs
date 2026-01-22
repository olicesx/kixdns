use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use moka::sync::Cache as MokaCache;
use notify::Watcher;
use serde::Deserialize;

// Re-export from geoip_converter module
// Note: geoip_converter is a sibling module at the crate root level
pub use crate::geoip_converter::{ConversionStats, convert_dat_to_mmdb};

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

/// V2Ray GeoIP .dat 文件格式 / V2Ray GeoIP .dat file format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoIP {
    /// 国家代码 / Country code
    pub country_code: String,
    /// IP 地址列表 / IP address list
    pub ips: Vec<String>,
}

/// V2Ray GeoIP 列表格式 / V2Ray GeoIP list format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoIPList {
    /// GeoIP 条目列表 / GeoIP entries
    pub entries: Vec<V2RayGeoIP>,
}

/// IP 段（用于快速匹配）/ IP range for fast matching
#[derive(Debug, Clone)]
pub struct IpRange {
    /// 起始 IP 地址 / Start IP address
    pub start: u32,
    /// 结束 IP 地址 / End IP address
    pub end: u32,
    /// 国家代码 / Country code
    pub country_code: String,
}

impl IpRange {
    /// 检查 IP 是否在范围内 / Check if IP is in range
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.start && ip <= self.end
    }
}

/// V2Ray .dat 文件使用 protobuf 格式
/// MaxMind GeoIP 数据库管理器 / MaxMind GeoIP database manager
pub struct GeoIpManager {
    /// MaxMind DB reader (使用内存映射，线程安全) / MaxMind DB reader (memory-mapped, thread-safe)
    reader: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    /// MMDB 文件路径（用于延迟加载）/ MMDB file path (for lazy loading)
    db_path: Option<String>,
    /// IP 范围列表（从 .dat 文件加载）/ IP range list (loaded from .dat file)
    ip_ranges: Vec<IpRange>,
    /// 查询结果缓存（IP -> GeoIP 结果） / Query result cache (IP -> GeoIP result)
    cache: MokaCache<IpAddr, GeoIpResult>,
}

/// GeoIP 查询结果 / GeoIP query result
#[derive(Debug, Clone)]
pub struct GeoIpResult {
    /// ISO 3166-1 alpha-2 国家代码（如 "CN", "US"） / ISO 3166-1 alpha-2 country code (e.g., "CN", "US")
    /// 使用 Arc<str> 实现零拷贝 clone / Use Arc<str> for zero-copy clone
    pub country_code: Option<Arc<str>>,
    /// 是否为私有 IP 地址 / Whether it's a private IP address
    pub is_private: bool,
}

impl GeoIpManager {
    /// 创建新的 GeoIP 管理器 / Create new GeoIP manager
    ///
    /// # 参数 / Parameters
    /// - `db_path`: MMDB 文件路径（可选）/ MMDB file path (optional)
    ///
    /// 此方法会立即加载 MMDB 文件（如果配置了路径），不再使用懒加载。
    /// This method loads the MMDB file immediately (if path is configured), no longer using lazy loading.
    pub fn new(db_path: Option<String>) -> anyhow::Result<Self> {
        // 初始时创建一个小缓存，加载数据后会根据实际条数重建
        let cache = MokaCache::builder()
            .max_capacity(1000)
            .build();

        // 立即加载 MMDB 文件（如果配置了）/ Load MMDB file immediately (if configured)
        let reader = if let Some(ref path) = db_path {
            if std::path::Path::new(path).exists() {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(r) => {
                        tracing::info!(geoip_db = %path, "GeoIP database loaded successfully");
                        Some(r)
                    }
                    Err(e) => {
                        tracing::warn!(geoip_db = %path, error = %e, "Failed to open GeoIP database");
                        None
                    }
                }
            } else {
                tracing::warn!(geoip_db = %path, "GeoIP database file not found");
                None
            }
        } else {
            None
        };

        Ok(Self {
            reader: Arc::new(reader),
            db_path,
            ip_ranges: Vec::new(),
            cache,
        })
    }

    /// 重建缓存（在加载数据后调用）/ Rebuild cache (call after loading data)
    fn rebuild_cache(&mut self) {
        // 根据实际加载的 IP 范围数量设置缓存大小
        // 缓存大小为实际条数的 2 倍，最小 10000，最大 1000000
        let entry_count = self.ip_ranges.len();
        let cache_capacity = (entry_count * 2).clamp(10_000, 1_000_000) as u64;

        tracing::info!(
            geoip_entries = entry_count,
            cache_capacity = cache_capacity,
            "Rebuilding GeoIP cache"
        );

        self.cache = MokaCache::builder()
            .max_capacity(cache_capacity)
            .build();
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

        // 查询 MMDB 或 IP 范围 / Query MMDB or IP ranges
        let result = if let Some(reader) = self.reader.as_ref() {
            self.lookup_mmdb(reader, ip)
        } else if !self.ip_ranges.is_empty() {
            // 使用 .dat 文件的 IP 范围 / Use IP ranges from .dat file
            self.lookup_dat(ip)
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
                // 零拷贝优化：使用 Arc<str> 避免克隆时的内存分配
                // Zero-copy optimization: use Arc<str> to avoid allocation on clone
                let country_code = record
                    .country
                    .or(record.registered_country)
                    .or(record.represented_country)
                    .and_then(|c| c.iso_code)
                    .map(|s| Arc::from(s.to_uppercase().as_str()));

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

    /// 从 .dat 文件的 IP 范围查询 / Lookup from .dat file IP ranges
    fn lookup_dat(&self, ip: IpAddr) -> GeoIpResult {
        let ip_u32 = match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                (octets[0] as u32) << 24
                    | (octets[1] as u32) << 16
                    | (octets[2] as u32) << 8
                    | (octets[3] as u32)
            }
            IpAddr::V6(ipv6) => {
                // 简化：只取前 4 个字节 / Simplification: only use first 4 bytes
                let segments = ipv6.segments();
                (segments[0] as u32) << 24
                    | (segments[1] as u32) << 16
                    | (segments[2] as u32) << 8
                    | (segments[3] as u32)
            }
        };

        // 使用二分查找 / Use binary search
        match self.ip_ranges.binary_search_by_key(&ip_u32, |range| range.start) {
            Ok(idx) => {
                // 完全匹配起始 IP / Exact match on start IP
                let range = &self.ip_ranges[idx];
                if ip_u32 <= range.end {
                    return GeoIpResult {
                        // 零拷贝优化：将 String 转为 Arc<str> 以便后续 clone 无需分配
                        // Zero-copy: convert String to Arc<str> for clone without allocation
                        country_code: Some(Arc::from(range.country_code.as_str())),
                        is_private: crate::geoip::is_private_ip(ip),
                    };
                }
            }
            Err(idx) => {
                // 检查相邻的范围 / Check adjacent ranges
                if idx > 0 {
                    let range = &self.ip_ranges[idx - 1];
                    if ip_u32 >= range.start && ip_u32 <= range.end {
                        return GeoIpResult {
                            country_code: Some(Arc::from(range.country_code.as_str())),
                            is_private: crate::geoip::is_private_ip(ip),
                        };
                    }
                }
                if idx < self.ip_ranges.len() {
                    let range = &self.ip_ranges[idx];
                    if ip_u32 >= range.start && ip_u32 <= range.end {
                        return GeoIpResult {
                            country_code: Some(Arc::from(range.country_code.as_str())),
                            is_private: crate::geoip::is_private_ip(ip),
                        };
                    }
                }
            }
        }

        // 未找到匹配 / No match found
        GeoIpResult {
            country_code: None,
            is_private: crate::geoip::is_private_ip(ip),
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

    /// 获取 IP 范围数量(仅用于调试)/ Get IP range count (debug only)
    pub fn ip_range_count(&self) -> usize {
        self.ip_ranges.len()
    }

    /// 从 V2Ray .dat 文件加载 GeoIP 数据 / Load GeoIP data from V2Ray .dat file
    ///
    /// 文件格式 / File format:
    /// - Header: 4 bytes magic (0x0D 0x0A 0x0D 0x0A)
    /// - Index section: country_code_count (2 bytes) + entries
    /// - Data section: IP ranges for each country
/// 从 V2Ray .dat 文件加载 GeoIP 数据
    /// 
    /// V2Ray .dat 文件使用 protobuf 编码，包含国家代码和 IP 范围
    /// V2Ray .dat files use protobuf encoding, containing country codes and IP ranges
    pub fn load_from_dat_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let data = std::fs::read(path)?;
        
        // V2Ray .dat 文件格式分析 / V2Ray .dat file format analysis
        // 外层结构：repeated GeoIP 条目 / Outer structure: repeated GeoIP entries
        // 每个 GeoIP 条目包含 / Each GeoIP entry contains:
        //   - country_code (string, field tag 0x0A)
        //   - ip_range (repeated message, field tag 0x12)
        // 每个 IP 范围包含 / Each IP range contains:
        //   - ip_range (bytes, field tag 0x0A) - 4字节起始IP + 4字节结束IP
        //   - prefix_len (uint32, field tag 0x10) - 前缀长度
        
        self.ip_ranges.clear();
        let mut pos = 0;
        let mut count = 0;
        
        while pos < data.len() {
            // 读取外层字段标签 / Read outer field tag
            if pos >= data.len() {
                break;
            }
            
            let field_tag = data[pos];
            pos += 1;
            
            // 解析 varint 长度 / Parse varint length
            let entry_len = parse_varint(&data, &mut pos)?;
            
            // 检查是否有足够的数据 / Check if we have enough data
            if pos + entry_len > data.len() {
                break;
            }
            
            let entry_end = pos + entry_len;
            
            // field_tag = 0x0A 表示 GeoIP 条目 / field_tag = 0x0A indicates GeoIP entry
            if field_tag == 0x0A {
                let mut country_code = String::new();
                
                // 解析 GeoIP 条目内容 / Parse GeoIP entry content
                while pos < entry_end {
                    let inner_tag = data[pos];
                    pos += 1;
                    
                    let inner_len = parse_varint(&data, &mut pos)?;
                    
                    if pos + inner_len > entry_end {
                        break;
                    }
                    
                    match inner_tag {
                        // 0x0A: country_code (string)
                        0x0A => {
                            if let Ok(code) = std::str::from_utf8(&data[pos..pos + inner_len]) {
                                country_code = code.to_string();
                            }
                            pos += inner_len;
                        }
                        // 0x12: cidr (repeated CIDR message)
                        0x12 => {
                            // V2Ray 的 cidr 字段包含多个 CIDR message
                            // V2Ray's cidr field contains multiple CIDR messages
                            // 每个 CIDR message 包含: ip (bytes, field 1) 和 prefix (uint32, field 2)
                            // Each CIDR message contains: ip (bytes, field 1) and prefix (uint32, field 2)

                            let mut cidr_pos = pos;
                            let cidr_end = pos + inner_len;

                            while cidr_pos < cidr_end {
                                // 读取 CIDR 内嵌的第一个 field tag
                                if cidr_pos >= cidr_end {
                                    break;
                                }

                                // 先读取 ip (field 1, tag 0x0A)
                                if cidr_pos >= cidr_end || data[cidr_pos] != 0x0A {
                                    // 跳过不符合预期的数据
                                    break;
                                }
                                cidr_pos += 1; // skip 0x0A

                                let ip_len = parse_varint(&data, &mut cidr_pos)?;
                                if ip_len != 4 || cidr_pos + 4 > cidr_end {
                                    break;
                                }

                                let ip_bytes = [
                                    data[cidr_pos],
                                    data[cidr_pos + 1],
                                    data[cidr_pos + 2],
                                    data[cidr_pos + 3],
                                ];
                                cidr_pos += 4;

                                // 读取 prefix (field 2, tag 0x10)
                                if cidr_pos >= cidr_end || data[cidr_pos] != 0x10 {
                                    break;
                                }
                                cidr_pos += 1; // skip 0x10

                                let prefix = parse_varint(&data, &mut cidr_pos)?;

                                // 根据 IP 和前缀长度计算范围
                                let start = u32::from_be_bytes(ip_bytes);

                                // 计算 end IP
                                let end = if prefix >= 32 {
                                    // /32 表示单个 IP
                                    start
                                } else {
                                    // start + (2^(32-prefix) - 1)
                                    // 使用 saturating_add 防止溢出
                                    let shift = (32 - prefix) as u32;
                                    let host_count = 1u32.wrapping_shl(shift);
                                    if prefix == 0 {
                                        // /0 表示整个 IPv4 空间
                                        u32::MAX
                                    } else {
                                        start.saturating_add(host_count).saturating_sub(1)
                                    }
                                };

                                tracing::debug!(target = "geoip",
                                    country = %country_code,
                                    ip = %std::net::Ipv4Addr::from(start),
                                    prefix = prefix,
                                    start = start,
                                    end = end,
                                    "parsed CIDR"
                                );

                                self.ip_ranges.push(IpRange {
                                    start,
                                    end,
                                    country_code: country_code.clone(),
                                });
                                count += 1;
                            }

                            // 更新 pos
                            pos = cidr_end;
                        }
                        _ => {
                            // 跳过未知字段 / Skip unknown field
                            pos += inner_len;
                        }
                    }
                }
            } else {
                // 跳过未知字段 / Skip unknown field
                pos = entry_end;
            }
        }

        tracing::info!("loaded {} GeoIP entries from .dat file", count);

        // 排序 IP 范围以支持二分查找 / Sort IP ranges to support binary search
        if !self.ip_ranges.is_empty() {
            self.ip_ranges.sort_by_key(|r| r.start);
            tracing::debug!("First 3 IP ranges (after sorting):");
            for (i, range) in self.ip_ranges.iter().take(3).enumerate() {
                tracing::debug!("  {}: 0x{:08x} - 0x{:08x} -> {}",
                    i, range.start, range.end, range.country_code);
            }
        }

        // 根据实际加载的条数重建缓存
        self.rebuild_cache();

        Ok(count)
    }

    /// 从 V2Ray JSON 文件加载 GeoIP 数据 / Load GeoIP data from V2Ray JSON file
    pub fn load_from_v2ray_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let data = std::fs::read_to_string(path)?;
        let list: V2RayGeoIPList = serde_json::from_str(&data)?;

        self.ip_ranges.clear();

        for geoip in list.entries {
            for ip_str in &geoip.ips {
                if let Ok(net) = ip_str.parse::<ipnet::IpNet>() {
                    if let ipnet::IpNet::V4(v4net) = net {
                        let start = u32::from(v4net.network());
                        let prefix_len = v4net.prefix_len() as u32;
                        let end = start + (1u32 << (32 - prefix_len)) - 1;

                        self.ip_ranges.push(IpRange {
                            start,
                            end,
                            country_code: geoip.country_code.clone(),
                        });
                    }
                }
            }
        }

        // 排序 IP 范围以支持二分查找 / Sort IP ranges to support binary search
        self.ip_ranges.sort_by_key(|r| r.start);

        // 根据实际加载的条数重建缓存
        self.rebuild_cache();

        Ok(self.ip_ranges.len())
    }

    /// 转换 .dat 为 MMDB 格式
    /// Convert .dat to MMDB format
    ///
    /// # 参数 / Parameters
    /// - `dat_path`: V2Ray .dat 文件路径 / V2Ray .dat file path
    /// - `mmdb_path`: 输出 MMDB 文件路径 / Output MMDB file path
    /// - `filter_countries`: 可选的国家代码过滤列表 / Optional country code filter list
    pub fn convert_dat_to_mmdb(
        dat_path: &Path,
        mmdb_path: &Path,
        filter_countries: Option<&[String]>,
    ) -> anyhow::Result<ConversionStats> {
        convert_dat_to_mmdb(dat_path, mmdb_path, filter_countries)
    }

    /// 自动转换并加载
    /// Auto-convert and load
    ///
    /// 如果 MMDB 文件不存在但 .dat 文件存在，自动转换并加载
    /// If MMDB file doesn't exist but .dat file exists, auto-convert and load
    ///
    /// # 参数 / Parameters
    /// - `dat_path`: V2Ray .dat 文件路径 / V2Ray .dat file path
    /// - `mmdb_path`: 输出 MMDB 文件路径 / Output MMDB file path
    pub fn auto_convert_and_load(
        dat_path: &Path,
        mmdb_path: &Path,
    ) -> anyhow::Result<Self> {
        // Check if MMDB already exists
        if mmdb_path.exists() {
            tracing::info!(
                mmdb = %mmdb_path.display(),
                "MMDB file already exists, loading directly"
            );
            return Self::new(Some(mmdb_path.to_string_lossy().to_string()));
        }

        // Check if .dat file exists
        if !dat_path.exists() {
            anyhow::bail!(
                "Neither MMDB nor .dat file exists: mmdb={}, dat={}",
                mmdb_path.display(),
                dat_path.display()
            );
        }

        tracing::info!(
            dat = %dat_path.display(),
            mmdb = %mmdb_path.display(),
            "MMDB not found, converting from .dat file"
        );

        // Perform conversion
        let stats = Self::convert_dat_to_mmdb(dat_path, mmdb_path, None)?;

        tracing::info!(
            "Conversion successful: {} countries, {} IPv4 ranges, {} IPv6 ranges",
            stats.countries_count,
            stats.ipv4_ranges_count,
            stats.ipv6_ranges_count
        );

        // Load the converted MMDB
        Self::new(Some(mmdb_path.to_string_lossy().to_string()))
    }
}

/// 解析 varint / Parse varint
fn parse_varint(data: &[u8], pos: &mut usize) -> anyhow::Result<usize> {
    let mut result = 0usize;
    let mut shift = 0;
    
    loop {
        if *pos >= data.len() {
            anyhow::bail!("unexpected end of file");
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    
    Ok(result)
}

/// 检测 IP 是否为私有地址 / Detect if IP is private address
#[inline]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()
                || ipv4.is_private()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            let seg0 = ipv6.segments()[0];
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || (seg0 & 0xffc0) == 0xfe80  // Link-local addresses (fe80::/10)
                || (seg0 & 0xfe00) == 0xfc00  // Unique Local Addresses (fc00::/7)
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
        let manager = GeoIpManager::new(None).unwrap();
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

/// 启动 GeoIP watcher 用于热重载 / Spawn GeoIP watcher for hot-reload
///
/// 监听 .dat 文件变化并自动重新加载 GeoIP 数据
/// Watches .dat file changes and automatically reloads GeoIP data
pub fn spawn_geoip_watcher(
    dat_path: Option<PathBuf>,
    manager: Arc<std::sync::RwLock<GeoIpManager>>,
) {
    let path = match dat_path {
        Some(p) => p,
        None => return,
    };

    // 使用阻塞线程持有watcher，避免异步生命周期问题
    // Use blocking thread to hold watcher, avoiding async lifetime issues
    thread::spawn(move || {
        if let Err(err) = run_geoip_watcher(path, manager) {
            tracing::warn!(target = "geoip_watcher", error = %err, "GeoIP watcher exited with error");
        }
    });
}

/// 运行 GeoIP watcher / Run GeoIP watcher
fn run_geoip_watcher(
    path: PathBuf,
    manager: Arc<std::sync::RwLock<GeoIpManager>>,
) -> notify::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: notify::RecommendedWatcher = notify::Watcher::new(tx, notify::Config::default())?;
    
    // 监听 GeoIP .dat 文件 / Watch GeoIP .dat file
    watcher.watch(&path, notify::RecursiveMode::NonRecursive)?;
    tracing::info!(target = "geoip_watcher", path = %path.display(), "watching GeoIP file");

    tracing::info!(target = "geoip_watcher", "GeoIP watcher started");

    for res in rx {
        match res {
            Ok(event) => {
                // 仅在数据更改时重载 / Only reload on data changes
                if !event.kind.is_modify() && !event.kind.is_create() {
                    continue;
                }

                let event_path = &event.paths[0];
                
                // 检测文件格式 / Detect file format
                let is_dat = event_path.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("dat"))
                    .unwrap_or(false);
                
                // 简单的重试机制来处理文件写入竞争 / Simple retry mechanism to handle file write races
                let mut retries = 5;
                while retries > 0 {
                    let load_result = if is_dat {
                        // 加载 .dat 格式 / Load .dat format
                        let mut manager_guard = manager.write().unwrap();
                        manager_guard.load_from_dat_file(event_path)
                    } else {
                        // 加载 V2Ray JSON 格式 / Load V2Ray JSON format
                        let mut manager_guard = manager.write().unwrap();
                        manager_guard.load_from_v2ray_file(event_path)
                    };
                    
                    match load_result {
                        Ok(count) => {
                            tracing::info!(
                                target = "geoip_watcher",
                                path = %event_path.display(),
                                loaded_count = count,
                                "GeoIP data reloaded"
                            );
                            break;
                        }
                        Err(err) => {
                            retries -= 1;
                            if retries == 0 {
                                tracing::warn!(
                                    target = "geoip_watcher",
                                    path = %event_path.display(),
                                    error = %err,
                                    "GeoIP reload failed after retries"
                                );
                            } else {
                                // 稍等后重试 / Wait a bit and retry
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                        }
                    }
                }
            }
            Err(err) => {
                tracing::warn!(target = "geoip_watcher", error = %err, "watcher event error");
            }
        }
    }
    Ok(())
}
