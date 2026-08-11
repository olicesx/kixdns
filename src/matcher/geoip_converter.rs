//! GeoIP .dat to MMDB converter
//!
//! 将 V2Ray GeoIP .dat 文件转换为 MaxMind MMDB 格式
//! Convert V2Ray GeoIP .dat files to MaxMind MMDB format

use anyhow::{Context, Result};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use maxminddb_writer::paths::IpAddrWithMask;
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
        use maxminddb_writer::{Database, metadata::IpVersion};
        use std::io::Write;

        let mut db = Database::default();

        // Set metadata
        // 标准字段：libmaxminddb 要求 binary_format_major_version 与 build_epoch 非零，
        // 否则报 "Is this a valid MaxMind DB file?"
        db.metadata.database_type = "KixDNS GeoIP".to_string();
        db.metadata.description.insert(
            "en".to_string(),
            "GeoIP database converted from V2Ray .dat format".to_string(),
        );
        db.metadata.ip_version = IpVersion::V6;
        db.metadata.binary_format_major_version = 2;
        db.metadata.binary_format_minor_version = 0;
        db.metadata.build_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1);
        db.metadata.languages = vec!["en".to_string()];

        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        // 收集所有插入项后统一排序插入：按 prefix 升序（父网段先插），
        // 规避 maxminddb-writer 的 NodeTree::insert 先子后父覆盖丢失子网的 bug
        let mut inserts = Vec::new();
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
                let Some(path) = ip_net_to_mmdb_path(net) else {
                    continue;
                };
                inserts.push((path.mask, data_ref, path));
                match net {
                    IpNet::V4(_) => ipv4_count += 1,
                    IpNet::V6(_) => ipv6_count += 1,
                }
            }
        }

        inserts.sort_by_key(|(mask, _, _)| *mask);
        for (_, data_ref, path) in inserts {
            db.insert_node(path, data_ref);
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

/// 将 IP 网段转换为 MMDB 插入路径
/// Convert an IP network to an MMDB insertion path
///
/// IPv4 必须嵌入 `::/96`（前 96 位全 0 的 IPv6 地址），因为所有 maxminddb
/// reader（Rust / libmaxminddb / Python）查询 IPv4 时都从树第 96 位（::/96
/// 子树根）开始。maxminddb-writer 0.1.1 本身不处理嵌入，直接插树根会导致
/// IPv4 网段全部落空。
fn ip_net_to_mmdb_path(net: &IpNet) -> Option<IpAddrWithMask> {
    match net {
        IpNet::V4(v4) => {
            let o = v4.addr().octets();
            let ipv6 = std::net::Ipv6Addr::new(
                0,
                0,
                0,
                0,
                0,
                0,
                ((o[0] as u16) << 8) | o[1] as u16,
                ((o[2] as u16) << 8) | o[3] as u16,
            );
            Some(IpAddrWithMask::new(
                std::net::IpAddr::V6(ipv6),
                v4.prefix_len() + 96,
            ))
        }
        IpNet::V6(v6) => Some(IpAddrWithMask::new(
            std::net::IpAddr::V6(v6.addr()),
            v6.prefix_len(),
        )),
    }
}

impl Default for GeoIpConverter {
    fn default() -> Self {
        Self::new()
    }
}

/// 合并 IPv4 网络
/// Merge IPv4 networks
///
/// 标准 CIDR 精确合并：完全包含取大者；同前缀的兄弟子网（低半 + 高半）
/// 合并为父网络；否则保持独立。合并后回退与已合并的前一个网络再尝试
/// 合并（链式），确保 4 个连续 /24 → /22。
fn merge_ipv4_nets(mut nets: Vec<Ipv4Net>) -> Vec<Ipv4Net> {
    nets.sort();

    let mut merged: Vec<Ipv4Net> = Vec::new();
    for net in nets {
        let mut current = net;
        loop {
            if let Some(last) = merged.last() {
                if last.contains(&current.addr()) && last.contains(&current.broadcast()) {
                    // current 完全被 last 覆盖，丢弃
                    break;
                }
                if current.contains(&last.addr()) && current.contains(&last.broadcast()) {
                    // last 完全被 current 覆盖，替换 last 后继续尝试与更前的合并
                    merged.pop();
                    continue;
                }
                if let Some(combined) = try_merge_ipv4(last, &current) {
                    merged.pop();
                    current = combined;
                    continue;
                }
            }
            merged.push(current);
            break;
        }
    }
    merged
}

/// 合并 IPv6 网络
/// Merge IPv6 networks
fn merge_ipv6_nets(mut nets: Vec<Ipv6Net>) -> Vec<Ipv6Net> {
    nets.sort();

    let mut merged: Vec<Ipv6Net> = Vec::new();
    for net in nets {
        let mut current = net;
        loop {
            if let Some(last) = merged.last() {
                if last.contains(&current.addr()) && last.contains(&current.broadcast()) {
                    break;
                }
                if current.contains(&last.addr()) && current.contains(&last.broadcast()) {
                    merged.pop();
                    continue;
                }
                if let Some(combined) = try_merge_ipv6(last, &current) {
                    merged.pop();
                    current = combined;
                    continue;
                }
            }
            merged.push(current);
            break;
        }
    }
    merged
}

/// 尝试将两个 IPv4 网络精确合并为父网络
/// Try to merge two IPv4 networks into their parent network
///
/// 仅当 `a` 是父网络的下半子网、`b` 是其相邻的高半兄弟子网时才可合并，
/// 合并结果恰好等于两者的并集（不会多覆盖地址）。返回 `None` 表示不可合并。
fn try_merge_ipv4(a: &Ipv4Net, b: &Ipv4Net) -> Option<Ipv4Net> {
    if a.prefix_len() != b.prefix_len() || a.prefix_len() == 0 {
        return None;
    }
    let shift = 32 - a.prefix_len();
    let a_addr = u32::from(a.addr());
    let b_addr = u32::from(b.addr());
    if (a_addr & (1 << shift)) == 0 && b_addr == (a_addr | (1 << shift)) {
        Ipv4Net::new(
            std::net::Ipv4Addr::from(a_addr & !(1 << shift)),
            a.prefix_len() - 1,
        )
        .ok()
    } else {
        None
    }
}

/// 尝试将两个 IPv6 网络精确合并为父网络
/// Try to merge two IPv6 networks into their parent network
fn try_merge_ipv6(a: &Ipv6Net, b: &Ipv6Net) -> Option<Ipv6Net> {
    if a.prefix_len() != b.prefix_len() || a.prefix_len() == 0 {
        return None;
    }
    let shift = 128 - a.prefix_len();
    let a_addr = u128::from(a.addr());
    let b_addr = u128::from(b.addr());
    if (a_addr & (1 << shift)) == 0 && b_addr == (a_addr | (1 << shift)) {
        Ipv6Net::new(
            std::net::Ipv6Addr::from(a_addr & !(1 << shift)),
            a.prefix_len() - 1,
        )
        .ok()
    } else {
        None
    }
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
    fn test_merge_ipv4_siblings_into_parent() {
        // 兄弟子网:1.2.2.0/24 + 1.2.3.0/24 → 1.2.2.0/23（精确合并，不多覆盖）
        let a = v4net("1.2.2.0/24");
        let b = v4net("1.2.3.0/24");
        assert_eq!(try_merge_ipv4(&a, &b).unwrap().to_string(), "1.2.2.0/23");
    }

    #[test]
    fn test_merge_ipv4_non_sibling_adjacent_not_merged() {
        // 相邻但非兄弟:1.2.3.0/24 + 1.2.4.0/24 不能合并
        // （并集 1.2.3.0-1.2.4.255 无法用单个网络精确表达，合并会多覆盖
        //   1.2.0.0-1.2.2.255 与 1.2.5.0-1.2.7.255——即旧实现产出的 1.2.0.0/21）
        let nets = vec![v4net("1.2.3.0/24"), v4net("1.2.4.0/24")];
        let merged = merge_ipv4_nets(nets);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].to_string(), "1.2.3.0/24");
        assert_eq!(merged[1].to_string(), "1.2.4.0/24");
    }

    #[test]
    fn test_merge_ipv4_overlap_keeps_larger() {
        // 完全包含:1.2.3.0/24 + 1.2.3.128/25 → 保留较大的 1.2.3.0/24
        let nets = vec![v4net("1.2.3.0/24"), v4net("1.2.3.128/25")];
        let merged = merge_ipv4_nets(nets);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].to_string(), "1.2.3.0/24");
    }

    #[test]
    fn test_merge_ipv6_halves_correct() {
        // 兄弟子网:2001:db8::/33 + 2001:db8:8000::/33 → 2001:db8::/32
        let a = v6net("2001:db8::/33");
        let b = v6net("2001:db8:8000::/33");
        assert_eq!(try_merge_ipv6(&a, &b).unwrap().to_string(), "2001:db8::/32");
    }

    #[test]
    fn test_merge_ipv4_nets_chain() {
        // 四个连续 /24 → 链式合并成一个 /22 网络
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

    #[test]
    fn test_merge_ipv4_issue40_no_over_merge() {
        // issue #40 场景:相邻 /24 序列，只有能精确合并的才合并。
        // 1.2.2.0/24 + 1.2.3.0/24 → 1.2.2.0/23；1.2.3.0/24 与 1.2.4.0/24 不合并
        let nets = vec![
            v4net("1.2.2.0/24"),
            v4net("1.2.3.0/24"),
            v4net("1.2.4.0/24"),
        ];
        let merged = merge_ipv4_nets(nets);
        let strs: Vec<String> = merged.iter().map(|n| n.to_string()).collect();
        assert_eq!(strs, vec!["1.2.2.0/23", "1.2.4.0/24"]);
    }

    #[test]
    fn test_mmdb_roundtrip_ipv4_ipv6() {
        use serde::Deserialize;

        #[derive(Deserialize, Debug)]
        struct CountryRec {
            country: Option<CountryIso>,
        }
        #[derive(Deserialize, Debug)]
        struct CountryIso {
            iso_code: Option<String>,
        }

        let mut converter = GeoIpConverter::new();
        // CN: 1.2.3.0/24（IPv4）; US: 2001:db8::/32（IPv6）
        converter
            .country_to_nets
            .insert("CN".to_string(), vec![IpNet::V4(v4net("1.2.3.0/24"))]);
        converter
            .country_to_nets
            .insert("US".to_string(), vec![IpNet::V6(v6net("2001:db8::/32"))]);
        converter.merge_cidrs();

        let dir = std::env::temp_dir().join(format!("kixdns_mmdb_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.dat");
        let out = dir.join("out.mmdb");
        std::fs::write(&src, b"placeholder").unwrap();

        let stats = converter.write_mmdb(&src, &out).unwrap();
        assert_eq!(stats.ipv4_ranges_count, 1);
        assert_eq!(stats.ipv6_ranges_count, 1);

        let bytes = std::fs::read(&out).unwrap();
        // 结构自校验:树区(6B/节点) + 16B separator + data + marker 不应越界
        let marker = b"\xab\xcd\xefMaxMind.com";
        let marker_idx = bytes
            .windows(marker.len())
            .rposition(|w| w == marker)
            .expect("metadata marker not found");
        assert!(marker_idx < bytes.len(), "metadata 越界");
        let tree_end = bytes
            .windows(16)
            .position(|w| w == [0u8; 16])
            .expect("data section separator not found");
        assert!(tree_end < marker_idx, "树区应位于 data 之前");

        let reader = maxminddb::Reader::from_source(&bytes).unwrap();
        // metadata 标准字段（libmaxminddb 兼容）
        assert_eq!(reader.metadata.binary_format_major_version, 2);
        assert!(
            reader.metadata.build_epoch > 0,
            "build_epoch 应为非零时间戳"
        );
        assert_eq!(reader.metadata.ip_version, 6);

        // IPv4 查询应命中 CN（修复前:IPv4 未嵌入 ::/96，全部落空）
        let rec: CountryRec = reader.lookup("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(rec.country.unwrap().iso_code.as_deref(), Some("CN"));
        // IPv6 查询应命中 US
        let rec: CountryRec = reader.lookup("2001:db8::1".parse().unwrap()).unwrap();
        assert_eq!(rec.country.unwrap().iso_code.as_deref(), Some("US"));
        // 未命中网段应报错而不是返回错误国家
        assert!(
            reader
                .lookup::<CountryRec>("9.9.9.9".parse().unwrap())
                .is_err()
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
