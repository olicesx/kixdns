//! GeoIP .dat to MMDB converter
//!
//! 将 V2Ray GeoIP .dat 文件转换为 MaxMind MMDB 格式
//! Convert V2Ray GeoIP .dat files to MaxMind MMDB format

use anyhow::{Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use prost::Message;
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use tracing::info;

/// V2Ray GeoIP .dat 文件格式
/// V2Ray GeoIP .dat file format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoIP {
    pub country_code: String,
    pub ips: Vec<String>,
}

/// V2Ray GeoIP 列表格式
/// V2Ray GeoIP list format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoIPList {
    pub entries: Vec<V2RayGeoIP>,
}

/// MMDB 输出数据结构
/// MMDB output data structure
#[derive(Debug, Clone, Serialize)]
struct MmdbCountryData {
    #[serde(rename = "country")]
    country: MmdbCountry,
}

#[derive(Debug, Clone, Serialize)]
struct MmdbCountry {
    #[serde(rename = "iso_code")]
    iso_code: String,
}

/// 转换统计信息
/// Conversion statistics
#[derive(Debug, Clone)]
pub struct ConversionStats {
    pub source_file_size: u64,
    pub output_file_size: u64,
    pub countries_count: usize,
    pub ipv4_ranges_count: usize,
    pub ipv6_ranges_count: usize,
    pub filtered_countries: Option<Vec<String>>,
}

impl std::fmt::Display for ConversionStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Conversion Statistics:")?;
        writeln!(f, "  Source file size: {} bytes", self.source_file_size)?;
        writeln!(f, "  Output file size: {} bytes", self.output_file_size)?;
        writeln!(f, "  Countries: {}", self.countries_count)?;
        writeln!(f, "  IPv4 ranges: {}", self.ipv4_ranges_count)?;
        writeln!(f, "  IPv6 ranges: {}", self.ipv6_ranges_count)?;
        if let Some(ref filtered) = self.filtered_countries {
            writeln!(f, "  Filtered countries: {:?}", filtered)?;
        }
        Ok(())
    }
}

/// 转换配置
/// Conversion configuration
#[derive(Debug, Clone)]
pub struct ConversionConfig {
    pub source_path: Box<Path>,
    pub output_path: Box<Path>,
    pub filter_countries: Option<Vec<String>>,
}

impl ConversionConfig {
    pub fn new(source: &Path, output: &Path) -> Self {
        Self {
            source_path: source.to_path_buf().into_boxed_path(),
            output_path: output.to_path_buf().into_boxed_path(),
            filter_countries: None,
        }
    }

    pub fn with_filter(mut self, countries: Vec<String>) -> Self {
        self.filter_countries = Some(countries);
        self
    }
}

/// GeoIP 转换器
/// GeoIP converter
pub struct GeoIpConverter {
    country_to_nets: HashMap<String, Vec<IpNet>>,
}

impl GeoIpConverter {
    pub fn new() -> Self {
        Self {
            country_to_nets: HashMap::default(),
        }
    }

    /// 从 V2Ray .dat 文件加载
    /// Load from V2Ray .dat file
    /// 从 V2Ray .dat 文件加载
    /// Load from V2Ray .dat file
    pub fn load_from_dat_file(&mut self, path: &Path) -> Result<usize> {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read .dat file: {}", path.display()))?;

        // 使用 Google 标准 protobuf 库 (prost) 解析，与 dae pkg/geodata 对齐
        let list = super::geoip_proto::GeoIPList::decode(data.as_slice())
            .context("Failed to decode .dat file as protobuf GeoIPList")?;

        let mut count = 0;
        for entry in list.entry {
            let country_code = entry.country_code.to_uppercase();
            let mut cidr_list = Vec::new();
            for cidr in entry.cidr {
                match cidr.ip.len() {
                    4 => {
                        let ipv4 =
                            std::net::Ipv4Addr::new(cidr.ip[0], cidr.ip[1], cidr.ip[2], cidr.ip[3]);
                        if let Ok(net) = Ipv4Net::new(ipv4, cidr.prefix as u8) {
                            cidr_list.push(IpNet::V4(net));
                        }
                    }
                    16 => {
                        let mut ipv6_bytes = [0u8; 16];
                        ipv6_bytes.copy_from_slice(&cidr.ip);
                        let ipv6 = std::net::Ipv6Addr::from(ipv6_bytes);
                        if let Ok(net) = Ipv6Net::new(ipv6, cidr.prefix as u8) {
                            cidr_list.push(IpNet::V6(net));
                        }
                    }
                    _ => {}
                }
            }

            if !country_code.is_empty() && !cidr_list.is_empty() {
                let entry_count = cidr_list.len();
                self.country_to_nets
                    .entry(country_code)
                    .or_default()
                    .extend(cidr_list);
                count += entry_count;
            }
        }

        info!(
            "Loaded {} CIDR entries for {} countries from .dat file",
            count,
            self.country_to_nets.len()
        );

        Ok(count)
    }
    pub fn load_from_v2ray_file(&mut self, path: &Path) -> Result<usize> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read JSON file: {}", path.display()))?;

        let list: V2RayGeoIPList =
            serde_json::from_str(&data).context("Failed to parse V2Ray GeoIP JSON")?;

        let mut count = 0;

        for geoip in list.entries {
            for ip_str in &geoip.ips {
                if let Ok(net) = ip_str.parse::<IpNet>() {
                    self.country_to_nets
                        .entry(geoip.country_code.clone())
                        .or_default()
                        .push(net);
                    count += 1;
                }
            }
        }

        info!(
            "Loaded {} CIDR entries for {} countries from JSON file",
            count,
            self.country_to_nets.len()
        );

        Ok(count)
    }

    /// 合并重叠或相邻的 CIDR
    /// Merge overlapping or adjacent CIDRs
    pub fn merge_cidrs(&mut self) {
        for nets in self.country_to_nets.values_mut() {
            // Separate IPv4 and IPv6
            let mut ipv4_nets: Vec<Ipv4Net> = Vec::new();
            let mut ipv6_nets: Vec<Ipv6Net> = Vec::new();

            for net in nets.drain(..) {
                match net {
                    IpNet::V4(v4) => ipv4_nets.push(v4),
                    IpNet::V6(v6) => ipv6_nets.push(v6),
                }
            }

            // Sort and merge IPv4
            if !ipv4_nets.is_empty() {
                ipv4_nets.sort();
                ipv4_nets = merge_ipv4_nets(ipv4_nets);
            }

            // Sort and merge IPv6
            if !ipv6_nets.is_empty() {
                ipv6_nets.sort();
                ipv6_nets = merge_ipv6_nets(ipv6_nets);
            }

            // Put back
            for net in ipv4_nets {
                nets.push(IpNet::V4(net));
            }
            for net in ipv6_nets {
                nets.push(IpNet::V6(net));
            }
        }

        info!("CIDR merging completed");
    }

    /// 应用国家代码过滤
    /// Apply country code filter
    pub fn filter_countries(&mut self, filter: &[String]) {
        let filter_set: HashSet<String> = filter.iter().map(|s| s.to_uppercase()).collect();

        self.country_to_nets
            .retain(|country, _| filter_set.contains(country));

        info!(
            "After filtering: {} countries remain",
            self.country_to_nets.len()
        );
    }

    /// 写入 MMDB 文件
    /// Write to MMDB file
    pub fn write_mmdb(&self, source_path: &Path, output_path: &Path) -> Result<ConversionStats> {
        use maxminddb_writer::{Database, metadata::IpVersion, paths::IpAddrWithMask};
        use std::io::Write;

        let mut db = Database::default();

        // Set metadata
        db.metadata.database_type = "KixDNS GeoIP".to_string();
        db.metadata.description.insert(
            "en".to_string(),
            "GeoIP database converted from V2Ray .dat format".to_string(),
        );
        db.metadata.ip_version = IpVersion::V6;

        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        for (country_code, nets) in &self.country_to_nets {
            let country_data = MmdbCountryData {
                country: MmdbCountry {
                    iso_code: country_code.clone(),
                },
            };

            let data_ref = db
                .insert_value(&country_data)
                .with_context(|| format!("Failed to insert data for country: {}", country_code))?;

            for net in nets {
                let path_str = format!("{}/{}", net.addr(), net.prefix_len());
                if let Ok(path) = path_str.parse::<IpAddrWithMask>() {
                    db.insert_node(path, data_ref);
                    match net {
                        IpNet::V4(_) => ipv4_count += 1,
                        IpNet::V6(_) => ipv6_count += 1,
                    }
                }
            }
        }

        // Write to file
        let file = File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;
        let mut writer = BufWriter::new(file);
        db.write_to(&mut writer)
            .context("Failed to write MMDB database")?;
        writer.flush().context("Failed to flush output")?;

        // Get file sizes
        let source_size = std::fs::metadata(source_path).map(|m| m.len()).unwrap_or(0);
        let output_size = std::fs::metadata(output_path)
            .map(|m| m.len())
            .with_context(|| {
                format!("Failed to get output file size: {}", output_path.display())
            })?;

        Ok(ConversionStats {
            source_file_size: source_size,
            output_file_size: output_size,
            countries_count: self.country_to_nets.len(),
            ipv4_ranges_count: ipv4_count,
            ipv6_ranges_count: ipv6_count,
            filtered_countries: None,
        })
    }
}

impl Default for GeoIpConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// 合并 IPv4 网络
/// Merge IPv4 networks
fn merge_ipv4_nets(mut nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    if nets.is_empty() {
        return nets;
    }

    nets.sort();

    let mut merged = Vec::new();
    let mut current = nets[0];

    for next in &nets[1..] {
        // Check if networks overlap or are adjacent
        if networks_overlap_v4(&current, next) || are_adjacent_ipv4(&current, next) {
            // Merge by expanding current
            current = merge_two_ipv4(&current, next);
        } else {
            merged.push(current);
            current = *next;
        }
    }

    merged.push(current);
    merged
}

/// 合并 IPv6 网络
/// Merge IPv6 networks
fn merge_ipv6_nets(mut nets: Vec<Ipv6Net>) -> Vec<Ipv6Net> {
    if nets.is_empty() {
        return nets;
    }

    nets.sort();

    let mut merged = Vec::new();
    let mut current = nets[0];

    for next in &nets[1..] {
        if networks_overlap_v6(&current, next) || are_adjacent_ipv6(&current, next) {
            current = merge_two_ipv6(&current, next);
        } else {
            merged.push(current);
            current = *next;
        }
    }

    merged.push(current);
    merged
}

/// 检查两个 IPv4 网络是否重叠
/// Check if two IPv4 networks overlap
fn networks_overlap_v4(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    a.contains(&b.addr()) || b.contains(&a.addr())
}

/// 检查两个 IPv6 网络是否重叠
/// Check if two IPv6 networks overlap
fn networks_overlap_v6(a: &Ipv6Net, b: &Ipv6Net) -> bool {
    a.contains(&b.addr()) || b.contains(&a.addr())
}

/// 检查两个 IPv4 网络是否相邻
/// Check if two IPv4 networks are adjacent
fn are_adjacent_ipv4(a: &Ipv4Net, b: &Ipv4Net) -> bool {
    let a_end = u32::from(a.addr()) | u32::MAX.wrapping_shr(u32::from(a.prefix_len()));
    let b_start = u32::from(b.addr());
    a_end.wrapping_add(1) == b_start
}

/// 检查两个 IPv6 网络是否相邻
/// Check if two IPv6 networks are adjacent
fn are_adjacent_ipv6(a: &Ipv6Net, b: &Ipv6Net) -> bool {
    let a_end = u128::from(a.addr()) | u128::MAX.wrapping_shr(u32::from(a.prefix_len()));
    let b_start = u128::from(b.addr());
    a_end.wrapping_add(1) == b_start
}

/// 合并两个 IPv4 网络
/// Merge two IPv4 networks
fn merge_two_ipv4(a: &Ipv4Net, b: &Ipv4Net) -> Ipv4Net {
    let a_start = u32::from(a.addr());
    let a_end = a_start | u32::MAX.wrapping_shr(u32::from(a.prefix_len()));
    let b_start = u32::from(b.addr());
    let b_end = b_start | u32::MAX.wrapping_shr(u32::from(b.prefix_len()));

    let new_start = a_start.min(b_start);
    let new_end = a_end.max(b_end);

    // Find the minimal prefix that covers both
    let mut prefix = 32u8;
    while prefix > 0 {
        let mask = u32::MAX << (32 - prefix);
        if (new_start & mask) == (new_end & mask) {
            break;
        }
        prefix -= 1;
    }
    // Align the start address to the covering prefix's network boundary,
    // otherwise Ipv4Net::new errors and unwrap panics (e.g. merging
    // 1.2.3.0/24 + 1.2.4.0/24 → prefix 21, start must become 1.2.0.0).
    let aligned_start = if prefix == 0 {
        0
    } else {
        new_start & (u32::MAX << (32 - prefix))
    };
    Ipv4Net::new(std::net::Ipv4Addr::from(aligned_start), prefix).unwrap()
}

/// 合并两个 IPv6 网络
/// Merge two IPv6 networks
fn merge_two_ipv6(a: &Ipv6Net, b: &Ipv6Net) -> Ipv6Net {
    let a_start = u128::from(a.addr());
    let a_end = a_start | u128::MAX.wrapping_shr(u32::from(a.prefix_len()));
    let b_start = u128::from(b.addr());
    let b_end = b_start | u128::MAX.wrapping_shr(u32::from(b.prefix_len()));

    let new_start = a_start.min(b_start);
    let new_end = a_end.max(b_end);

    let mut prefix = 128u8;
    while prefix > 0 {
        let mask = u128::MAX << (128 - prefix);
        if (new_start & mask) == (new_end & mask) {
            break;
        }
        prefix -= 1;
    }

    // Align the start address to the covering prefix's network boundary
    let aligned_start = if prefix == 0 {
        0
    } else {
        new_start & (u128::MAX << (128 - prefix))
    };
    Ipv6Net::new(std::net::Ipv6Addr::from(aligned_start), prefix).unwrap()
}

/// 转换 .dat 为 MMDB 格式
/// Convert .dat to MMDB format
///
/// # 参数 / Parameters
/// - `dat_path`: V2Ray .dat 文件路径 / V2Ray .dat file path
/// - `mmdb_path`: 输出 MMDB 文件路径 / Output MMDB file path
/// - `filter`: 可选的国家代码过滤列表 / Optional country code filter list
///
/// # 返回 / Returns
/// 转换统计信息 / Conversion statistics
pub fn convert_dat_to_mmdb(
    dat_path: &Path,
    mmdb_path: &Path,
    filter: Option<&[String]>,
) -> Result<ConversionStats> {
    info!(
        "Starting conversion: {} -> {}",
        dat_path.display(),
        mmdb_path.display()
    );

    let mut converter = GeoIpConverter::new();

    // Detect file type and load
    let is_dat = dat_path
        .extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("dat"))
        .unwrap_or(false);

    if is_dat {
        converter.load_from_dat_file(dat_path)?;
    } else {
        converter.load_from_v2ray_file(dat_path)?;
    }

    // Apply filter if provided
    if let Some(filter) = filter
        && !filter.is_empty()
    {
        info!("Applying country filter: {:?}", filter);
        converter.filter_countries(filter);
    }

    // Merge CIDRs
    converter.merge_cidrs();

    // Write MMDB
    let stats = converter.write_mmdb(dat_path, mmdb_path)?;

    info!("Conversion completed:\n{}", stats);

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4net(s: &str) -> Ipv4Net {
        s.parse().unwrap()
    }
    fn v6net(s: &str) -> Ipv6Net {
        s.parse().unwrap()
    }

    #[test]
    fn test_are_adjacent_ipv4_correct() {
        // 1.2.3.0/24 与 1.2.4.0/24 相邻:end=1.2.3.255, +1 = 1.2.4.0
        let a = v4net("1.2.3.0/24");
        let b = v4net("1.2.4.0/24");
        assert!(are_adjacent_ipv4(&a, &b), "1.2.3.0/24 与 1.2.4.0/24 应相邻");
        // 旧 bug:!u32::MAX << 8 = 0 → a_end = a_start = 1.2.3.0 → 误判不相邻
    }

    #[test]
    fn test_merge_two_ipv4_overlap_correct() {
        // 重叠:1.2.3.0/24 + 1.2.3.128/25 → 1.2.3.0/24
        let m = merge_two_ipv4(&v4net("1.2.3.0/24"), &v4net("1.2.3.128/25"));
        assert_eq!(m.to_string(), "1.2.3.0/24");
    }

    #[test]
    fn test_merge_adjacent_ipv4_crosses_network_boundary() {
        // 相邻跨 /23 边界:1.2.3.0/24 + 1.2.4.0/24 → 最小覆盖 1.2.0.0/21
        let m = merge_two_ipv4(&v4net("1.2.3.0/24"), &v4net("1.2.4.0/24"));
        assert_eq!(m.to_string(), "1.2.0.0/21");
        // 旧 bug:new_end 被算成 1.2.4.0 → prefix 22 → 且 start 未对齐会 panic
    }

    #[test]
    fn test_merge_ipv6_halves_correct() {
        // 2001:db8::/33 + 2001:db8:8000::/33 → 2001:db8::/32
        let m = merge_two_ipv6(&v6net("2001:db8::/33"), &v6net("2001:db8:8000::/33"));
        assert_eq!(m.to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_merge_ipv4_nets_chain() {
        // 三段连续 /24 → 合并成一个 /22 网络
        let nets = vec![
            v4net("10.0.0.0/24"),
            v4net("10.0.1.0/24"),
            v4net("10.0.2.0/24"),
            v4net("10.0.3.0/24"),
        ];
        let merged = merge_ipv4_nets(nets);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].to_string(), "10.0.0.0/22");
    }
}
