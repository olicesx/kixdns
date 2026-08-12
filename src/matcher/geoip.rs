use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use anyhow::Context;
use moka::sync::Cache as MokaCache;
use notify::Watcher;
use prost::Message;
use rustc_hash::FxHashMap;
use serde::Deserialize;

// Re-export from geoip_converter module
// Note: geoip_converter is a sibling module at the crate root level
pub use crate::lock::RwLock;
pub use crate::matcher::geoip_converter::{ConversionStats, convert_dat_to_mmdb};

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
    #[inline]
    pub fn contains(&self, ip: u32) -> bool {
        ip >= self.start && ip <= self.end
    }
}

/// IPv6 段（用于快速匹配）/ IPv6 range for fast matching
#[derive(Debug, Clone)]
pub struct IpRangeV6 {
    /// 起始 IP 地址（u128 大端序）/ Start IP address (u128 big-endian)
    pub start: u128,
    /// 结束 IP 地址（u128 大端序）/ End IP address (u128 big-endian)
    pub end: u128,
    /// 国家代码 / Country code
    pub country_code: String,
}

impl IpRangeV6 {
    /// 检查 IPv6 是否在范围内 / Check if IPv6 is in range
    #[inline]
    pub fn contains(&self, ip: u128) -> bool {
        ip >= self.start && ip <= self.end
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4Range {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, Copy)]
struct Ipv6Range {
    start: u128,
    end: u128,
}

#[derive(Debug, Default)]
struct GeoIpTagIndex {
    ipv4_ranges: Vec<Ipv4Range>,
    ipv6_ranges: Vec<Ipv6Range>,
    raw_ipv4_ranges: Vec<Ipv4Range>,
    raw_ipv6_ranges: Vec<Ipv6Range>,
}

impl GeoIpTagIndex {
    fn finalize(&mut self) {
        self.raw_ipv4_ranges = self.ipv4_ranges.clone();
        self.raw_ipv4_ranges
            .sort_unstable_by_key(|range| range.start);
        self.raw_ipv6_ranges = self.ipv6_ranges.clone();
        self.raw_ipv6_ranges
            .sort_unstable_by_key(|range| range.start);
        merge_ipv4_ranges(&mut self.ipv4_ranges);
        merge_ipv6_ranges(&mut self.ipv6_ranges);
    }

    #[inline]
    fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                let index = self.ipv4_ranges.partition_point(|range| range.start <= ip);
                index > 0 && self.ipv4_ranges[index - 1].end >= ip
            }
            IpAddr::V6(ip) => {
                let ip = u128::from(ip);
                let index = self.ipv6_ranges.partition_point(|range| range.start <= ip);
                index > 0 && self.ipv6_ranges[index - 1].end >= ip
            }
        }
    }

    fn matching_range(&self, ip: IpAddr) -> Option<(u128, u128)> {
        match ip {
            IpAddr::V4(ip) => {
                let ip = u32::from(ip);
                most_specific_ipv4(&self.raw_ipv4_ranges, ip)
                    .map(|range| (u128::from(range.start), u128::from(range.end)))
            }
            IpAddr::V6(ip) => most_specific_ipv6(&self.raw_ipv6_ranges, u128::from(ip))
                .map(|range| (range.start, range.end)),
        }
    }

    #[inline]
    fn range_count(&self) -> usize {
        self.ipv4_ranges.len() + self.ipv6_ranges.len()
    }
}

/// V2Ray .dat 文件使用 protobuf 格式
/// MaxMind GeoIP 数据库管理器 / MaxMind GeoIP database manager
pub struct GeoIpManager {
    /// MaxMind DB reader (使用内存映射，线程安全) / MaxMind DB reader (memory-mapped, thread-safe)
    reader: Arc<Option<maxminddb::Reader<Vec<u8>>>>,
    /// MMDB 文件路径（用于延迟加载）/ MMDB file path (for lazy loading)
    /// Note: Reserved for future hot-reload functionality
    #[allow(dead_code)]
    db_path: Option<String>,
    /// 按标签分组的 IP 范围索引（从 .dat/JSON 文件加载）
    /// IP range indexes grouped by tag (loaded from .dat/JSON files)
    tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex>,
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
        let cache = MokaCache::builder().max_capacity(1000).build();

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
            tag_indexes: FxHashMap::default(),
            cache,
        })
    }

    /// 重建缓存（在加载数据后调用）/ Rebuild cache (call after loading data)
    fn rebuild_cache(&mut self) {
        // 根据实际加载的 IP 范围数量设置缓存大小
        // 缓存大小为实际条数的 2 倍，最小 10000，最大 1000000
        let entry_count = self.ip_range_count();
        let cache_capacity = (entry_count * 2).clamp(10_000, 1_000_000) as u64;

        tracing::info!(
            geoip_entries = entry_count,
            cache_capacity = cache_capacity,
            "Rebuilding GeoIP cache"
        );

        self.cache = MokaCache::builder().max_capacity(cache_capacity).build();
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
        } else if !self.tag_indexes.is_empty() {
            // 使用 .dat/JSON 文件中的国家标签 / Use country tags from .dat/JSON files
            self.lookup_dat_country(ip)
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

    /// 检查 IP 是否属于指定标签 / Check whether an IP belongs to a tag.
    #[inline]
    pub fn matches_tag(&self, ip: IpAddr, tag: &str) -> bool {
        let normalized;
        let tag = if tag.bytes().all(|b| !b.is_ascii_lowercase()) {
            tag
        } else {
            normalized = tag.to_ascii_uppercase();
            &normalized
        };

        if self.reader.as_ref().is_some() && is_country_tag(tag) {
            return self
                .lookup(ip)
                .country_code
                .is_some_and(|code| code.eq_ignore_ascii_case(tag));
        }

        self.tag_indexes
            .get(tag)
            .is_some_and(|index| index.contains(ip))
    }

    /// 检查 IP 是否属于任一指定标签 / Check whether an IP belongs to any requested tag.
    #[inline]
    pub fn matches_any_tag(&self, ip: IpAddr, tags: &[Arc<str>]) -> bool {
        let has_mmdb = self.reader.as_ref().is_some();
        let mmdb_country = has_mmdb.then(|| self.lookup(ip).country_code).flatten();

        for tag in tags {
            let normalized;
            let tag = if tag.bytes().all(|b| !b.is_ascii_lowercase()) {
                tag.as_ref()
            } else {
                normalized = tag.to_ascii_uppercase();
                &normalized
            };

            if has_mmdb && is_country_tag(tag) {
                if mmdb_country
                    .as_ref()
                    .is_some_and(|country_code| country_code.eq_ignore_ascii_case(tag))
                {
                    return true;
                }
                continue;
            }

            if self
                .tag_indexes
                .get(tag)
                .is_some_and(|index| index.contains(ip))
            {
                return true;
            }
        }
        false
    }

    /// 返回 IP 命中的全部标签，主要用于诊断和管理接口。
    /// Return all tags matching an IP, primarily for diagnostics and management APIs.
    pub fn lookup_tags(&self, ip: IpAddr) -> Vec<Arc<str>> {
        let has_mmdb = self.reader.as_ref().is_some();
        let mut tags: Vec<_> = self.lookup(ip).country_code.into_iter().collect();
        tags.extend(
            self.tag_indexes
                .iter()
                .filter(|(tag, index)| index.contains(ip) && (!has_mmdb || !is_country_tag(tag)))
                .map(|(tag, _)| Arc::clone(tag)),
        );
        tags.sort_unstable_by(|a, b| a.as_ref().cmp(b.as_ref()));
        tags.dedup();
        tags
    }

    /// 从 .dat/JSON 数据中查询传统单标签结果，优先返回两位国家代码。
    /// Lookup the legacy single-tag result, preferring a two-letter country code.
    fn lookup_dat_country(&self, ip: IpAddr) -> GeoIpResult {
        let mut country_match = None;
        let mut named_match = None;

        for (tag, index) in &self.tag_indexes {
            let Some((start, end)) = index.matching_range(ip) else {
                continue;
            };

            let target = if is_country_tag(tag) {
                &mut country_match
            } else {
                &mut named_match
            };
            if is_more_specific(target, tag, start, end) {
                *target = Some((Arc::clone(tag), start, end));
            }
        }

        GeoIpResult {
            country_code: country_match.or(named_match).map(|(tag, _, _)| tag),
            is_private: is_private_ip(ip),
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

    /// 检查 GeoIP 数据是否已加载 / Check whether any GeoIP data is loaded.
    #[inline]
    pub fn is_loaded(&self) -> bool {
        self.reader.is_some() || !self.tag_indexes.is_empty()
    }

    /// 获取去重合并后的 IP 范围数量（仅用于调试）。
    /// Get the deduplicated and merged IP range count (debug only).
    #[inline]
    pub fn ip_range_count(&self) -> usize {
        self.tag_indexes
            .values()
            .map(GeoIpTagIndex::range_count)
            .sum()
    }

    /// 从 V2Ray .dat 文件加载 GeoIP 数据 / Load GeoIP data from V2Ray .dat file
    ///
    /// 文件格式 / File format:
    /// - Header: 4 bytes magic (0x0D 0x0A 0x0D 0x0A)
    /// - Index section: country_code_count (2 bytes) + entries
    /// - Data section: IP ranges for each country
    ///
    /// 从 V2Ray .dat 文件加载 GeoIP 数据
    ///
    /// V2Ray .dat 文件使用 protobuf 编码，包含国家代码和 IP 范围
    /// V2Ray .dat files use protobuf encoding, containing country codes and IP ranges
    /// V2Ray .dat 文件使用 protobuf 编码，包含国家代码和 IP 范围
    /// V2Ray .dat files use protobuf encoding, containing country codes and IP ranges
    pub fn load_from_dat_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let data = std::fs::read(path)?;

        // 使用 Google 标准 protobuf 库 (prost) 解析，与 dae pkg/geodata 对齐。
        // 手写 wire 解析假设字段顺序固定、无未知字段，任何 .dat 格式变体
        // 都会产生静默错位或错误网段。
        let list = super::geoip_proto::GeoIPList::decode(data.as_slice())
            .context("failed to decode geoip.dat as protobuf GeoIPList")?;

        let mut tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex> = FxHashMap::default();
        let mut count = 0;
        let mut ipv4_count = 0;
        let mut ipv6_count = 0;

        for entry in list.entry {
            let country_code = entry.country_code.to_ascii_uppercase();
            if country_code.is_empty() {
                continue;
            }
            for cidr in entry.cidr {
                match cidr.ip.len() {
                    4 => {
                        let mut ip_bytes = [0u8; 4];
                        ip_bytes.copy_from_slice(&cidr.ip);
                        let start = u32::from_be_bytes(ip_bytes);
                        let end = if cidr.prefix >= 32 {
                            // /32 或异常前缀按单 IP 处理
                            start
                        } else if cidr.prefix == 0 {
                            // /0 表示整个 IPv4 空间
                            u32::MAX
                        } else {
                            let host_count = 1u32.wrapping_shl(32 - cidr.prefix);
                            start.saturating_add(host_count).saturating_sub(1)
                        };
                        get_or_insert_tag_index(&mut tag_indexes, &country_code)
                            .ipv4_ranges
                            .push(Ipv4Range { start, end });
                        count += 1;
                        ipv4_count += 1;
                    }
                    16 => {
                        let mut ip_bytes = [0u8; 16];
                        ip_bytes.copy_from_slice(&cidr.ip);
                        let start = u128::from_be_bytes(ip_bytes);
                        let end = if cidr.prefix >= 128 {
                            start
                        } else if cidr.prefix == 0 {
                            u128::MAX
                        } else {
                            let host_count = 1u128.wrapping_shl(128 - cidr.prefix);
                            start.saturating_add(host_count).saturating_sub(1)
                        };
                        get_or_insert_tag_index(&mut tag_indexes, &country_code)
                            .ipv6_ranges
                            .push(Ipv6Range { start, end });
                        count += 1;
                        ipv6_count += 1;
                    }
                    len => {
                        tracing::debug!(
                            target = "geoip",
                            len,
                            "skipping CIDR with unsupported IP length"
                        );
                    }
                }
            }
        }

        for index in tag_indexes.values_mut() {
            index.finalize();
        }
        self.tag_indexes = tag_indexes;

        tracing::info!(
            geoip_entries = count,
            geoip_tags = self.tag_indexes.len(),
            ipv4_entries = ipv4_count,
            ipv6_entries = ipv6_count,
            merged_ranges = self.ip_range_count(),
            "loaded GeoIP tag indexes from .dat file"
        );

        self.rebuild_cache();

        Ok(count)
    }
    pub fn load_from_v2ray_file(&mut self, path: &Path) -> anyhow::Result<usize> {
        let data = std::fs::read_to_string(path)?;
        let list: V2RayGeoIPList = serde_json::from_str(&data)?;
        let mut tag_indexes: FxHashMap<Arc<str>, GeoIpTagIndex> = FxHashMap::default();
        let mut count = 0;

        for geoip in list.entries {
            let tag = geoip.country_code.to_ascii_uppercase();
            if tag.is_empty() {
                continue;
            }
            let index = get_or_insert_tag_index(&mut tag_indexes, &tag);

            for ip_str in &geoip.ips {
                match ip_str.parse::<ipnet::IpNet>() {
                    Ok(ipnet::IpNet::V4(v4net)) => {
                        index.ipv4_ranges.push(Ipv4Range {
                            start: u32::from(v4net.network()),
                            end: u32::from(v4net.broadcast()),
                        });
                        count += 1;
                    }
                    Ok(ipnet::IpNet::V6(v6net)) => {
                        index.ipv6_ranges.push(Ipv6Range {
                            start: u128::from(v6net.network()),
                            end: u128::from(v6net.broadcast()),
                        });
                        count += 1;
                    }
                    Err(_) => continue,
                }
            }
        }

        for index in tag_indexes.values_mut() {
            index.finalize();
        }
        self.tag_indexes = tag_indexes;
        self.rebuild_cache();

        Ok(count)
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
    pub fn auto_convert_and_load(dat_path: &Path, mmdb_path: &Path) -> anyhow::Result<Self> {
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

fn get_or_insert_tag_index<'a>(
    indexes: &'a mut FxHashMap<Arc<str>, GeoIpTagIndex>,
    tag: &str,
) -> &'a mut GeoIpTagIndex {
    if !indexes.contains_key(tag) {
        indexes.insert(Arc::from(tag), GeoIpTagIndex::default());
    }
    indexes
        .get_mut(tag)
        .expect("GeoIP tag index must exist after insertion")
}

fn merge_ipv4_ranges(ranges: &mut Vec<Ipv4Range>) {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Ipv4Range> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

fn merge_ipv6_ranges(ranges: &mut Vec<Ipv6Range>) {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<Ipv6Range> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    *ranges = merged;
}

fn most_specific_ipv4(ranges: &[Ipv4Range], ip: u32) -> Option<Ipv4Range> {
    let index = ranges.partition_point(|range| range.start <= ip);
    ranges[..index]
        .iter()
        .filter(|range| range.end >= ip)
        .min_by_key(|range| (range.end - range.start, std::cmp::Reverse(range.start)))
        .copied()
}

fn most_specific_ipv6(ranges: &[Ipv6Range], ip: u128) -> Option<Ipv6Range> {
    let index = ranges.partition_point(|range| range.start <= ip);
    ranges[..index]
        .iter()
        .filter(|range| range.end >= ip)
        .min_by_key(|range| (range.end - range.start, std::cmp::Reverse(range.start)))
        .copied()
}

#[inline]
fn is_country_tag(tag: &str) -> bool {
    tag.len() == 2 && tag.bytes().all(|byte| byte.is_ascii_alphabetic())
}

fn is_more_specific(
    current: &Option<(Arc<str>, u128, u128)>,
    tag: &str,
    start: u128,
    end: u128,
) -> bool {
    match current {
        None => true,
        Some((current_tag, current_start, current_end)) => {
            let span = end - start;
            let current_span = *current_end - *current_start;
            span < current_span
                || (span == current_span && start > *current_start)
                || (span == current_span && start == *current_start && tag < current_tag.as_ref())
        }
    }
}

/// 检测 IP 是否为私有地址 / Detect if IP is private address
#[inline]
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback() || ipv4.is_private() || ipv4.is_link_local() || ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            let seg0 = ipv6.segments()[0];
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || (seg0 & 0xffc0) == 0xfe80  // Link-local addresses (fe80::/10)
                || (seg0 & 0xfe00) == 0xfc00 // Unique Local Addresses (fc00::/7)
        }
    }
}

/// 启动 GeoIP watcher 用于热重载 / Spawn GeoIP watcher for hot-reload
///
/// 监听 .dat 文件变化并自动重新加载 GeoIP 数据
/// Watches .dat file changes and automatically reloads GeoIP data
///
/// 注意：通过监控父目录而非直接监控文件本身来支持原子替换（mv）操作。
/// Linux inotify 监控 inode，原子替换创建新 inode，直接监控文件会丢失事件。
/// Note: Watches the parent directory instead of the file itself to support
/// atomic replacement (mv). Linux inotify watches inodes; atomic replacement
/// creates a new inode that would be missed when watching the file directly.
pub fn spawn_geoip_watcher(dat_path: Option<PathBuf>, manager: Arc<RwLock<GeoIpManager>>) {
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
fn run_geoip_watcher(path: PathBuf, manager: Arc<RwLock<GeoIpManager>>) -> notify::Result<()> {
    // Watch the parent directory instead of the file itself,
    // so that atomic replacement (mv newfile geoip.dat) is properly detected.
    let parent_dir = path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .to_path_buf();
    let target_file_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: notify::RecommendedWatcher =
        notify::Watcher::new(tx, notify::Config::default())?;

    watcher.watch(&parent_dir, notify::RecursiveMode::NonRecursive)?;
    tracing::info!(target = "geoip_watcher", path = %parent_dir.display(), filename = ?target_file_name, "watching GeoIP file parent directory (atomic-replacement safe)");

    tracing::info!(target = "geoip_watcher", "GeoIP watcher started");

    for res in rx {
        match res {
            Ok(event) => {
                // Check if the event is for the file we care about
                let is_target_file = event
                    .paths
                    .iter()
                    .any(|p| p.file_name() == Some(&target_file_name));
                if !is_target_file {
                    continue;
                }

                // 仅在数据更改时重载 / Only reload on data changes
                if !event.kind.is_modify() && !event.kind.is_create() {
                    continue;
                }

                // 检测文件格式 / Detect file format
                let is_dat = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("dat"))
                    .unwrap_or(false);

                // 简单的重试机制来处理文件写入竞争 / Simple retry mechanism to handle file write races
                let mut retries = 5;
                while retries > 0 {
                    // parking_lot::RwLock::write() 返回 guard 直接，不会中毒
                    // parking_lot::RwLock does not have poison state
                    let load_result = if is_dat {
                        manager.write().load_from_dat_file(&path)
                    } else {
                        manager.write().load_from_v2ray_file(&path)
                    };

                    match load_result {
                        Ok(count) => {
                            tracing::info!(
                                target = "geoip_watcher",
                                path = %path.display(),
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
                                    path = %path.display(),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 V2Ray .dat 格式的 protobuf 字节（含 v4 和/或 v6 CIDR）
    /// Build V2Ray .dat protobuf bytes (with v4 and/or v6 CIDRs)
    fn build_dat(country: &str, v4: Option<([u8; 4], u8)>, v6: Option<([u8; 16], u8)>) -> Vec<u8> {
        let mut entry = Vec::new();
        // country_code (field 1, tag 0x0A)
        entry.push(0x0A);
        entry.push(country.len() as u8);
        entry.extend_from_slice(country.as_bytes());
        // cidr (field 2, tag 0x12) —— 每个 CIDR 一个独立 message (repeated, 与真实 .dat 一致)
        let mut push_cidr = |ip_bytes: &[u8], prefix: u8| {
            let mut msg = Vec::new();
            msg.push(0x0A); // field 1: ip (bytes)
            msg.push(ip_bytes.len() as u8);
            msg.extend_from_slice(ip_bytes);
            msg.push(0x10); // field 2: prefix (varint)
            msg.push(prefix);
            entry.push(0x12);
            entry.push(msg.len() as u8);
            entry.extend_from_slice(&msg);
        };
        if let Some((ip, prefix)) = v4 {
            push_cidr(&ip, prefix);
        }
        if let Some((ip, prefix)) = v6 {
            push_cidr(&ip, prefix);
        }

        let mut dat = Vec::new();
        dat.push(0x0A); // outer field: GeoIP entry
        dat.push(entry.len() as u8);
        dat.extend_from_slice(&entry);
        dat
    }

    #[test]
    fn test_load_dat_includes_ipv6() {
        // 2001:db8::/32 (v6) + 1.2.3.0/24 (v4)
        let v6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let v4: [u8; 4] = [1, 2, 3, 0];
        let dat = build_dat("CN", Some((v4, 24)), Some((v6, 32)));

        let mut path = std::env::temp_dir();
        path.push("geoip_test_v6.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        let count = mgr.load_from_dat_file(&path).unwrap();
        assert_eq!(count, 2, "应加载 2 条（v4 + v6）");
        assert_eq!(mgr.ip_range_count(), 2, "IPv4 和 IPv6 段都应保留");

        // IPv6 查询应匹配国家 / IPv6 lookup should match the country
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        let res = mgr.lookup(ip);
        assert_eq!(res.country_code.as_deref(), Some("CN"));

        // 不在段内的 IPv6 不应误匹配 / IPv6 outside the range must not match
        let miss: std::net::IpAddr = "2001:db9::1".parse().unwrap();
        assert_eq!(mgr.lookup(miss).country_code, None);

        // IPv4 查询仍然正常 / IPv4 lookup still works
        let v4ip: std::net::IpAddr = "1.2.3.5".parse().unwrap();
        assert_eq!(mgr.lookup(v4ip).country_code.as_deref(), Some("CN"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_json_includes_ipv6() {
        let json = r#"{
            "entries": [
                {
                    "country_code": "JP",
                    "ips": ["2001:db8:1::/48", "198.51.100.0/24"]
                }
            ]
        }"#;
        let mut path = std::env::temp_dir();
        path.push("geoip_test_v6.json");
        std::fs::write(&path, json).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        let count = mgr.load_from_v2ray_file(&path).unwrap();
        assert_eq!(count, 2, "JSON 应加载 v4 + v6");
        assert_eq!(mgr.ip_range_count(), 2, "JSON IPv4 和 IPv6 段都应保留");

        let ip: std::net::IpAddr = "2001:db8:1::1234".parse().unwrap();
        let res = mgr.lookup(ip);
        assert_eq!(res.country_code.as_deref(), Some("JP"));

        let _ = std::fs::remove_file(&path);
    }

    /// 构造嵌套重叠的 .dat(CN /8 大网段内嵌 US /24,IPv4+IPv6)
    /// Build a .dat with nested overlapping networks (CN /8 containing US /24)
    fn build_nested_dat() -> Vec<u8> {
        use prost::Message;
        let v6_cn: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let v6_us: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let list = super::super::geoip_proto::GeoIPList {
            entry: vec![
                super::super::geoip_proto::GeoIP {
                    country_code: "CN".to_string(),
                    cidr: vec![
                        super::super::geoip_proto::Cidr {
                            ip: vec![10, 0, 0, 0],
                            prefix: 8,
                        },
                        super::super::geoip_proto::Cidr {
                            ip: v6_cn.to_vec(),
                            prefix: 32,
                        },
                    ],
                },
                super::super::geoip_proto::GeoIP {
                    country_code: "US".to_string(),
                    cidr: vec![
                        super::super::geoip_proto::Cidr {
                            ip: vec![10, 1, 2, 0],
                            prefix: 24,
                        },
                        super::super::geoip_proto::Cidr {
                            ip: v6_us.to_vec(),
                            prefix: 48,
                        },
                    ],
                },
            ],
        };
        list.encode_to_vec()
    }

    #[test]
    fn test_most_specific_handles_crossing_overlaps() {
        let ipv4_ranges = [
            Ipv4Range { start: 40, end: 55 },
            Ipv4Range { start: 45, end: 70 },
        ];
        let ipv4_match = most_specific_ipv4(&ipv4_ranges, 50).unwrap();
        assert_eq!((ipv4_match.start, ipv4_match.end), (40, 55));

        let ipv6_ranges = [
            Ipv6Range { start: 40, end: 55 },
            Ipv6Range { start: 45, end: 70 },
        ];
        let ipv6_match = most_specific_ipv6(&ipv6_ranges, 50).unwrap();
        assert_eq!((ipv6_match.start, ipv6_match.end), (40, 55));
    }

    #[test]
    fn test_lookup_nested_overlap_most_specific() {
        let dat = build_nested_dat();
        let mut path = std::env::temp_dir();
        path.push("geoip_test_nested.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        mgr.load_from_dat_file(&path).unwrap();

        let us: IpAddr = "10.1.2.5".parse().unwrap();
        assert_eq!(mgr.lookup(us).country_code.as_deref(), Some("US"));
        let b1: IpAddr = "10.1.2.255".parse().unwrap();
        assert_eq!(mgr.lookup(b1).country_code.as_deref(), Some("US"));
        let cn: IpAddr = "10.1.3.5".parse().unwrap();
        assert_eq!(mgr.lookup(cn).country_code.as_deref(), Some("CN"));
        let b2: IpAddr = "10.1.3.0".parse().unwrap();
        assert_eq!(mgr.lookup(b2).country_code.as_deref(), Some("CN"));
        let cn2: IpAddr = "10.200.1.1".parse().unwrap();
        assert_eq!(mgr.lookup(cn2).country_code.as_deref(), Some("CN"));

        let us6: IpAddr = "2001:db8:1::1".parse().unwrap();
        assert_eq!(mgr.lookup(us6).country_code.as_deref(), Some("US"));
        let cn6: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert_eq!(mgr.lookup(cn6).country_code.as_deref(), Some("CN"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_lookup_preserves_same_tag_nested_specificity() {
        let json = r#"{
            "entries": [
                {
                    "country_code": "CN",
                    "ips": ["10.0.0.0/8", "10.1.0.0/16", "2001:db8::/32", "2001:db8:1::/48"]
                },
                {
                    "country_code": "US",
                    "ips": ["10.0.0.0/12", "2001:db8::/40"]
                }
            ]
        }"#;
        let path = std::env::temp_dir().join("geoip_test_same_tag_nested.json");
        std::fs::write(&path, json).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        assert_eq!(mgr.load_from_v2ray_file(&path).unwrap(), 6);

        let cn4: IpAddr = "10.1.1.1".parse().unwrap();
        assert!(mgr.matches_tag(cn4, "CN"));
        assert!(mgr.matches_tag(cn4, "US"));
        assert_eq!(mgr.lookup(cn4).country_code.as_deref(), Some("CN"));
        let us4: IpAddr = "10.2.1.1".parse().unwrap();
        assert_eq!(mgr.lookup(us4).country_code.as_deref(), Some("US"));

        let cn6: IpAddr = "2001:db8:1::1".parse().unwrap();
        assert!(mgr.matches_tag(cn6, "CN"));
        assert!(mgr.matches_tag(cn6, "US"));
        assert_eq!(mgr.lookup(cn6).country_code.as_deref(), Some("CN"));
        let us6: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert_eq!(mgr.lookup(us6).country_code.as_deref(), Some("US"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_overlapping_dat_tags_match_independently() {
        let mut dat = build_dat("AU", Some(([1, 1, 1, 0], 24)), None);
        dat.extend(build_dat("cloudflare", Some(([1, 1, 1, 0], 24)), None));

        let mut path = std::env::temp_dir();
        path.push("geoip_test_overlapping_tags.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        assert_eq!(mgr.load_from_dat_file(&path).unwrap(), 2);

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "AU"));
        assert!(mgr.matches_tag(ip, "cloudflare"));
        assert!(!mgr.matches_tag(ip, "netflix"));
        assert!(mgr.matches_any_tag(ip, &[Arc::from("NETFLIX"), Arc::from("CLOUDFLARE")]));
        assert_eq!(mgr.lookup(ip).country_code.as_deref(), Some("AU"));
        assert_eq!(
            mgr.lookup_tags(ip),
            vec![Arc::from("AU"), Arc::from("CLOUDFLARE")]
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_lookup_preserves_named_tag_only_dat_behavior() {
        let dat = build_dat("cloudflare", Some(([1, 1, 1, 0], 24)), None);
        let mut path = std::env::temp_dir();
        path.push("geoip_test_named_tag_only.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut mgr = GeoIpManager::new(None).unwrap();
        mgr.load_from_dat_file(&path).unwrap();

        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(mgr.lookup(ip).country_code.as_deref(), Some("CLOUDFLARE"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_mmdb_country_precedence_keeps_named_dat_tags() {
        let network = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mmdb_source = build_dat("US", None, Some((network, 32)));
        let mut dat = build_dat("CN", None, Some((network, 16)));
        dat.extend(build_dat("CLOUDFLARE", None, Some((network, 16))));
        let temp_dir = std::env::temp_dir();
        let mmdb_source_path = temp_dir.join("geoip_test_mmdb_source.dat");
        let dat_path = temp_dir.join("geoip_test_mmdb_precedence.dat");
        let mmdb_path = temp_dir.join("geoip_test_mmdb_precedence.mmdb");
        std::fs::write(&mmdb_source_path, mmdb_source).unwrap();
        std::fs::write(&dat_path, dat).unwrap();
        GeoIpManager::convert_dat_to_mmdb(&mmdb_source_path, &mmdb_path, None).unwrap();

        let mut mgr = GeoIpManager::new(Some(mmdb_path.to_string_lossy().into_owned())).unwrap();
        mgr.load_from_dat_file(&dat_path).unwrap();

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(mgr.matches_tag(ip, "US"));
        assert!(!mgr.matches_tag(ip, "CN"));
        assert!(mgr.matches_tag(ip, "CLOUDFLARE"));
        assert!(mgr.matches_any_tag(ip, &[Arc::from("CN"), Arc::from("CLOUDFLARE")]));
        assert_eq!(
            mgr.lookup_tags(ip),
            vec![Arc::from("CLOUDFLARE"), Arc::from("US")]
        );
        assert!(
            mgr.cache.get(&ip).is_some(),
            "MMDB matches should use cache"
        );

        let mmdb_miss: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(!mgr.matches_tag(mmdb_miss, "CN"));
        assert!(mgr.matches_tag(mmdb_miss, "CLOUDFLARE"));
        assert_eq!(mgr.lookup(mmdb_miss).country_code, None);
        assert_eq!(mgr.lookup_tags(mmdb_miss), vec![Arc::from("CLOUDFLARE")]);

        drop(mgr);
        let _ = std::fs::remove_file(mmdb_source_path);
        let _ = std::fs::remove_file(dat_path);
        let _ = std::fs::remove_file(mmdb_path);
    }
}
