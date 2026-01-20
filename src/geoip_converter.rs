//! GeoIP .dat to MMDB converter
//!
//! 将 V2Ray GeoIP .dat 文件转换为 MaxMind MMDB 格式
//! Convert V2Ray GeoIP .dat files to MaxMind MMDB format

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use anyhow::{Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
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
        write!(f, "Conversion Statistics:\n")?;
        write!(f, "  Source file size: {} bytes\n", self.source_file_size)?;
        write!(f, "  Output file size: {} bytes\n", self.output_file_size)?;
        write!(f, "  Countries: {}\n", self.countries_count)?;
        write!(f, "  IPv4 ranges: {}\n", self.ipv4_ranges_count)?;
        write!(f, "  IPv6 ranges: {}\n", self.ipv6_ranges_count)?;
        if let Some(ref filtered) = self.filtered_countries {
            write!(f, "  Filtered countries: {:?}\n", filtered)?;
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
            country_to_nets: HashMap::new(),
        }
    }

    /// 从 V2Ray .dat 文件加载
    /// Load from V2Ray .dat file
    pub fn load_from_dat_file(&mut self, path: &Path) -> Result<usize> {
        let data = std::fs::read(path)
            .with_context(|| format!("Failed to read .dat file: {}", path.display()))?;

        let mut pos = 0;
        let mut count = 0;

        while pos < data.len() {
            if pos >= data.len() {
                break;
            }

            let field_tag = data[pos];
            pos += 1;

            let entry_len = parse_varint(&data, &mut pos)
                .context("Failed to parse varint for entry length")?;

            if pos + entry_len > data.len() {
                break;
            }

            let entry_end = pos + entry_len;

            if field_tag == 0x0A {
                let mut country_code = String::new();
                let mut cidr_list = Vec::new();

                while pos < entry_end {
                    let inner_tag = data[pos];
                    pos += 1;

                    let inner_len = parse_varint(&data, &mut pos)
                        .context("Failed to parse varint for inner field")?;

                    if pos + inner_len > entry_end {
                        break;
                    }

                    match inner_tag {
                        0x0A => {
                            if let Ok(code) = std::str::from_utf8(&data[pos..pos + inner_len]) {
                                country_code = code.to_uppercase();
                            }
                            pos += inner_len;
                        }
                        0x12 => {
                            let mut cidr_pos = pos;
                            let cidr_end = pos + inner_len;

                            while cidr_pos < cidr_end {
                                if cidr_pos >= cidr_end {
                                    break;
                                }

                                // Parse IP (field 1, tag 0x0A)
                                if cidr_pos >= cidr_end || data[cidr_pos] != 0x0A {
                                    break;
                                }
                                cidr_pos += 1;

                                let ip_len = parse_varint(&data, &mut cidr_pos)?;
                                if ip_len != 4 || cidr_pos + 4 > cidr_end {
                                    // Only support IPv4 for now
                                    break;
                                }

                                let ip_bytes = [
                                    data[cidr_pos],
                                    data[cidr_pos + 1],
                                    data[cidr_pos + 2],
                                    data[cidr_pos + 3],
                                ];
                                cidr_pos += 4;

                                // Parse prefix (field 2, tag 0x10)
                                if cidr_pos >= cidr_end || data[cidr_pos] != 0x10 {
                                    break;
                                }
                                cidr_pos += 1;

                                let prefix = parse_varint(&data, &mut cidr_pos)?;

                                // Create IPv4 network
                                let ipv4 = std::net::Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
                                if let Ok(net) = Ipv4Net::new(ipv4, prefix as u8) {
                                    cidr_list.push(IpNet::V4(net));
                                }
                            }

                            pos = cidr_end;
                        }
                        _ => {
                            pos += inner_len;
                        }
                    }
                }

                if !country_code.is_empty() && !cidr_list.is_empty() {
                    let entry_count = cidr_list.len();
                    self.country_to_nets
                        .entry(country_code)
                        .or_insert_with(Vec::new)
                        .extend(cidr_list);
                    count += entry_count;
                }
            } else {
                pos = entry_end;
            }
        }

        info!(
            "Loaded {} CIDR entries for {} countries from .dat file",
            count,
            self.country_to_nets.len()
        );

        Ok(count)
    }

    /// 从 V2Ray JSON 文件加载
    /// Load from V2Ray JSON file
    pub fn load_from_v2ray_file(&mut self, path: &Path) -> Result<usize> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read JSON file: {}", path.display()))?;

        let list: V2RayGeoIPList = serde_json::from_str(&data)
            .context("Failed to parse V2Ray GeoIP JSON")?;

        let mut count = 0;

        for geoip in list.entries {
            for ip_str in &geoip.ips {
                if let Ok(net) = ip_str.parse::<IpNet>() {
                    self.country_to_nets
                        .entry(geoip.country_code.clone())
                        .or_insert_with(Vec::new)
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
        for (_, nets) in self.country_to_nets.iter_mut() {
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
        let filter_set: HashSet<String> = filter
            .iter()
            .map(|s| s.to_uppercase())
            .collect();

        self.country_to_nets.retain(|country, _| {
            filter_set.contains(country)
        });

        info!(
            "After filtering: {} countries remain",
            self.country_to_nets.len()
        );
    }

    /// 写入 MMDB 文件
    /// Write to MMDB file
    pub fn write_mmdb(&self, output_path: &Path) -> Result<ConversionStats> {
        use maxminddb_writer::{Database, metadata::IpVersion, paths::IpAddrWithMask};
        use std::io::Write;

        let mut db = Database::default();

        // Set metadata
        db.metadata.database_type = "KixDNS GeoIP".to_string();
        db.metadata.description.insert("en".to_string(), "GeoIP database converted from V2Ray .dat format".to_string());
        db.metadata.ip_version = IpVersion::V6;

        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        for (country_code, nets) in &self.country_to_nets {
            let country_data = MmdbCountryData {
                country: MmdbCountry {
                    iso_code: country_code.clone(),
                },
            };

            let data_ref = db.insert_value(&country_data)
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
        writer.flush()
            .context("Failed to flush output")?;

        // Get file sizes
        let source_size = std::fs::metadata(self.country_to_nets.keys().next()
            .map(|_| "unknown").unwrap_or_default())
            .map(|m| m.len())
            .unwrap_or(0);
        let output_size = std::fs::metadata(output_path)
            .map(|m| m.len())
            .with_context(|| format!("Failed to get output file size: {}", output_path.display()))?;

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
    let a_end = u32::from(a.addr()) | (!u32::MAX << (32 - a.prefix_len()));
    let b_start = u32::from(b.addr());
    a_end.wrapping_add(1) == b_start
}

/// 检查两个 IPv6 网络是否相邻
/// Check if two IPv6 networks are adjacent
fn are_adjacent_ipv6(a: &Ipv6Net, b: &Ipv6Net) -> bool {
    let a_end = u128::from(a.addr()) | (!u128::MAX << (128 - a.prefix_len()));
    let b_start = u128::from(b.addr());
    a_end.wrapping_add(1) == b_start
}

/// 合并两个 IPv4 网络
/// Merge two IPv4 networks
fn merge_two_ipv4(a: &Ipv4Net, b: &Ipv4Net) -> Ipv4Net {
    let a_start = u32::from(a.addr());
    let a_end = a_start | (!u32::MAX << (32 - a.prefix_len()));
    let b_start = u32::from(b.addr());
    let b_end = b_start | (!u32::MAX << (32 - b.prefix_len()));

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

    Ipv4Net::new(std::net::Ipv4Addr::from(new_start), prefix).unwrap()
}

/// 合并两个 IPv6 网络
/// Merge two IPv6 networks
fn merge_two_ipv6(a: &Ipv6Net, b: &Ipv6Net) -> Ipv6Net {
    let a_start = u128::from(a.addr());
    let a_end = a_start | (!u128::MAX << (128 - a.prefix_len()));
    let b_start = u128::from(b.addr());
    let b_end = b_start | (!u128::MAX << (128 - b.prefix_len()));

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

    Ipv6Net::new(std::net::Ipv6Addr::from(new_start), prefix).unwrap()
}

/// 解析 varint
/// Parse varint
fn parse_varint(data: &[u8], pos: &mut usize) -> Result<usize> {
    let mut result = 0usize;
    let mut shift = 0;

    loop {
        if *pos >= data.len() {
            anyhow::bail!("Unexpected end of file while parsing varint");
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
    let is_dat = dat_path.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case("dat"))
        .unwrap_or(false);

    if is_dat {
        converter.load_from_dat_file(dat_path)?;
    } else {
        converter.load_from_v2ray_file(dat_path)?;
    }

    // Apply filter if provided
    if let Some(filter) = filter {
        if !filter.is_empty() {
            info!("Applying country filter: {:?}", filter);
            converter.filter_countries(filter);
        }
    }

    // Merge CIDRs
    converter.merge_cidrs();

    // Write MMDB
    let stats = converter.write_mmdb(mmdb_path)?;

    info!("Conversion completed:\n{}", stats);

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_varint() {
        let data = [0x96, 0x01]; // 150 in varint
        let mut pos = 0;
        let result = parse_varint(&data, &mut pos).unwrap();
        assert_eq!(result, 150);
    }

    #[test]
    fn test_networks_overlap_v4() {
        let net1 = Ipv4Net::new("192.168.0.0".parse().unwrap(), 24).unwrap();
        let net2 = Ipv4Net::new("192.168.0.128".parse().unwrap(), 25).unwrap();
        assert!(networks_overlap_v4(&net1, &net2));
    }

    #[test]
    fn test_geoip_converter_new() {
        let converter = GeoIpConverter::new();
        assert!(converter.country_to_nets.is_empty());
    }
}
