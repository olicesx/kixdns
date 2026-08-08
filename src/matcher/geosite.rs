// GeoSite 域名分类匹配器 / GeoSite domain category matcher
// 支持基于域名分类的路由决策 / Supports routing decisions based on domain categorization

use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::Context;
use moka::sync::Cache as MokaCache;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use regex::{Regex, RegexBuilder};
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::lock::RwLock;

/// 域名匹配器类型 / Domain matcher type
#[derive(Debug, Clone)]
pub enum DomainMatcher {
    /// 完全匹配 / Full domain match
    Full(String),
    /// 后缀匹配 / Suffix match
    Suffix(String),
    /// 关键词匹配 / Keyword match
    Keyword(String),
    /// 正则匹配 / Regex match
    Regex(Regex),
}

impl DomainMatcher {
    /// 检查域名是否匹配 / Check if domain matches
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            DomainMatcher::Full(pattern) => domain.eq_ignore_ascii_case(pattern),
            DomainMatcher::Suffix(suffix) => {
                // 移除前导点后再进行匹配，让 .github.com 也能匹配 github.com
                // Remove leading dot for matching, so .github.com can match github.com
                let suffix_clean = if let Some(stripped) = suffix.strip_prefix('.') {
                    stripped
                } else {
                    suffix
                };
                domain.eq_ignore_ascii_case(suffix_clean) || domain.ends_with(suffix)
            }
            DomainMatcher::Keyword(keyword) => {
                // 智能检查：先看是否需要转换 / Smart check: see if conversion is needed
                if domain.bytes().all(|b| !b.is_ascii_uppercase()) {
                    // domain 已经是小写，零分配比较 / domain already lowercase, zero-allocation
                    domain.contains(keyword)
                } else {
                    // 需要转换 / Need conversion
                    domain
                        .to_ascii_lowercase()
                        .contains(&keyword.to_ascii_lowercase())
                }
            }
            DomainMatcher::Regex(regex) => regex.is_match(domain),
        }
    }
}

/// GeoSite 条目 / GeoSite entry
#[derive(Debug, Clone)]
pub struct GeoSiteEntry {
    pub tag: String,
    pub matchers: Vec<DomainMatcher>,
}

impl GeoSiteEntry {
    /// 标准化：将所有匹配器转换为小写（配置加载时调用）
    /// Normalization: convert all matchers to lowercase (called during config loading)
    #[inline]
    pub fn normalized(mut self) -> Self {
        for matcher in &mut self.matchers {
            match matcher {
                DomainMatcher::Full(domain) => *domain = domain.to_ascii_lowercase(),
                DomainMatcher::Suffix(suffix) => *suffix = suffix.to_ascii_lowercase(),
                DomainMatcher::Keyword(keyword) => *keyword = keyword.to_ascii_lowercase(),
                DomainMatcher::Regex(_) => {} // 正则不转换 / Regex not converted
            }
        }
        self
    }
}

/// GeoSite 数据库管理器 / GeoSite database manager
/// 使用 FxHashMap 实现高性能查找（由外层 RwLock 保护线程安全）/ Uses FxHashMap for high-performance lookup (thread-safety protected by outer RwLock)
pub struct GeoSiteManager {
    // Tag -> Domain matchers
    database: FxHashMap<String, Vec<DomainMatcher>>,
    // Suffix index for O(1) lookup
    suffix_index: FxHashMap<String, Vec<String>>,
    // Query cache: hash(tag, domain) -> bool (零分配优化 / zero-allocation optimization)
    cache: MokaCache<u64, bool>,
}

impl Default for GeoSiteManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoSiteManager {
    /// 创建新的 GeoSite 管理器 / Create new GeoSite manager
    pub fn new() -> Self {
        // 初始时创建一个小缓存，加载数据后会根据实际条数重建
        Self {
            database: FxHashMap::default(),
            suffix_index: FxHashMap::default(),
            cache: MokaCache::builder().max_capacity(1000).build(),
        }
    }

    /// 重建缓存（在加载数据后调用）/ Rebuild cache (call after loading data)
    fn rebuild_cache(&mut self) {
        // 根据实际加载的域名数量设置缓存大小
        // 统计所有标签的域名总数
        let total_domains: usize = self.database.values().map(|matchers| matchers.len()).sum();

        // 缓存大小为域名总数的 2 倍，最小 10000，最大 1000000
        let cache_capacity = (total_domains * 2).clamp(10_000, 1_000_000) as u64;

        tracing::info!(
            geosite_tags = self.database.len(),
            total_domains = total_domains,
            cache_capacity = cache_capacity,
            "Rebuilding GeoSite cache"
        );

        self.cache = MokaCache::builder().max_capacity(cache_capacity).build();
    }

    /// 添加 GeoSite 条目 / Add GeoSite entry
    pub fn add_entry(&mut self, entry: GeoSiteEntry) {
        // 在添加时自动标准化 / Auto-normalize on add
        let normalized = entry.normalized();
        let tag = normalized.tag.clone();

        // Build suffix index
        for matcher in &normalized.matchers {
            if let DomainMatcher::Suffix(suffix) = matcher {
                self.suffix_index
                    .entry(suffix.clone())
                    .or_default()
                    .push(tag.clone());
            }
        }

        self.database.insert(tag, normalized.matchers);
    }

    /// 检查域名是否匹配指定的 GeoSite 标签 / Check if domain matches specified GeoSite tag
    ///
    /// # 参数 / Parameters
    /// - `tag`: GeoSite 标签（如 "cn", "google", "category-ads"）/ GeoSite tag
    /// - `domain`: 要检查的域名 / Domain to check
    ///
    /// # 返回 / Returns
    /// - `true`: 域名匹配该标签 / Domain matches the tag
    /// - `false`: 域名不匹配该标签 / Domain does not match the tag
    #[inline]
    pub fn matches(&self, tag: &str, domain: &str) -> bool {
        // 零分配优化：使用哈希值作为缓存键 / Zero-allocation optimization: use hash as cache key
        // 使用 FxHasher 计算组合哈希 / Use FxHasher to compute combined hash
        let mut hasher = FxHasher::default();
        tag.hash(&mut hasher);
        domain.hash(&mut hasher);
        let key = hasher.finish();

        // 检查缓存 / Check cache
        if let Some(result) = self.cache.get(&key) {
            return result;
        }

        let result = self.matches_impl(tag, domain);
        self.cache.insert(key, result);
        result
    }

    /// 检查域名是否匹配指定的 GeoSite 标签（内部实现）/ Internal implementation
    fn matches_impl(&self, tag: &str, domain: &str) -> bool {
        // 不区分大小写：将 tag 转换为小写再查找 / Case insensitive: convert tag to lowercase before lookup
        let tag_lower = tag.to_ascii_lowercase();

        if let Some(matchers) = self.database.get(&tag_lower) {
            for matcher in matchers {
                if self.matcher_matches(matcher, domain) {
                    return true;
                }
            }
        }
        false
    }

    /// 检查单个域名匹配器 / Check single domain matcher
    fn matcher_matches(&self, matcher: &DomainMatcher, domain: &str) -> bool {
        match matcher {
            DomainMatcher::Full(d) => {
                // 完全匹配，不区分大小写 / Full match, case insensitive
                // d 已经在加载时预小写 / d already lowercased during loading
                domain.eq_ignore_ascii_case(d)
            }
            DomainMatcher::Suffix(s) => {
                // 后缀匹配，不区分大小写 / Suffix match, case insensitive
                // s 已经在加载时预小写 / s already lowercased during loading
                // 移除前导点后再进行匹配，让 .github.com 也能匹配 github.com
                // Remove leading dot for matching, so .github.com can match github.com
                let s_clean = if let Some(stripped) = s.strip_prefix('.') {
                    stripped
                } else {
                    s
                };

                // 先尝试完全匹配（快速路径）/ Try exact match first (fast path)
                if domain.eq_ignore_ascii_case(s_clean) {
                    return true;
                }
                // 再尝试后缀匹配 / Then try suffix match
                if domain.ends_with(s) {
                    return true;
                }

                // 兜底：转换后比较 / Fallback: compare after conversion
                domain.to_ascii_lowercase().ends_with(s)
            }
            DomainMatcher::Keyword(k) => {
                // 关键词匹配，不区分大小写 / Keyword match, case insensitive
                // k 已经在加载时预小写 / k already lowercased during loading
                // 智能检查：先看是否需要转换 / Smart check: see if conversion is needed
                if domain.bytes().all(|b| !b.is_ascii_uppercase()) {
                    // domain 已经是小写，零分配比较 / domain already lowercase, zero-allocation compare
                    domain.contains(k)
                } else {
                    // 需要转换 / Need conversion
                    domain.to_ascii_lowercase().contains(k)
                }
            }
            DomainMatcher::Regex(re) => {
                // 正则匹配 / Regex match
                re.is_match(domain)
            }
        }
    }

    /// 重新加载数据库 / Reload database
    ///
    /// # 参数 / Parameters
    /// - `entries`: 新的 GeoSite 条目列表 / New GeoSite entries
    pub fn reload(&mut self, entries: Vec<GeoSiteEntry>) {
        self.database.clear();
        self.suffix_index.clear();
        self.cache.invalidate_all();

        for entry in entries {
            self.add_entry(entry);
        }
    }

    /// 获取已加载的标签列表 / Get list of loaded tags
    #[inline]
    pub fn tags(&self) -> Vec<String> {
        self.database.keys().cloned().collect()
    }

    /// 检查标签是否已加载 / Check if tag is loaded
    #[inline]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.database.contains_key(tag)
    }

    /// 获取标签的所有域名匹配器（仅用于调试）/ Get all domain matchers for a tag (debug only)
    #[inline]
    pub fn get_tag_matchers(&self, tag: &str) -> Option<Vec<DomainMatcher>> {
        self.database.get(tag).cloned()
    }
}

/// V2Ray .dat 文件格式常量 / V2Ray .dat file format constants
mod dat_format {
    /// 文件头魔数 / File header magic number
    /// Note: Reserved for future dat file format parsing
    #[allow(dead_code)]
    pub const HEADER_MAGIC: &[u8; 4] = b"\x0D\x0A\x0D\x0A";

    /// 域名类型常量 / Domain type constants
    /// Note: Reserved for future use in dat file parsing
    #[allow(dead_code)]
    pub const TYPE_FULL: u8 = 0x01; // 完整匹配 / Full match
    #[allow(dead_code)]
    pub const TYPE_SUBDOMAIN: u8 = 0x02; // 子域名匹配 / Subdomain match
    #[allow(dead_code)]
    pub const TYPE_KEYWORD: u8 = 0x03; // 关键词匹配 / Keyword match
    #[allow(dead_code)]
    pub const TYPE_REGEX: u8 = 0x04; // 正则匹配 / Regex match
}

/// V2Ray GeoSite 数据格式 / V2Ray GeoSite data format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoSite {
    /// Tag 名称 / Tag name
    pub tag: String,
    /// 域名列表 / Domain list
    pub domains: Vec<String>,
}

/// V2Ray GeoSite 列表格式 / V2Ray GeoSite list format
#[derive(Debug, Clone, Deserialize)]
pub struct V2RayGeoSiteList {
    /// GeoSite 条目列表 / GeoSite entries
    pub entries: Vec<V2RayGeoSite>,
}

/// .dat 文件索引条目 / .dat file index entry
/// Note: Reserved for future optimization of dat file parsing
#[allow(dead_code)]
#[derive(Debug, Clone)]
struct DatIndexEntry {
    /// Tag 名称 / Tag name
    tag: String,
    /// 在数据段中的偏移量 / Offset in data section
    offset: u32,
    /// 数据长度 / Data length
    length: u32,
}

/// Split a GeoSite tag with optional `@attr` filter into (base, Option<attr>)
/// `category-games@cn` → (`category-games`, Some(`cn`))
/// `category-games`    → (`category-games`, None)
fn split_tag_attr(tag: &str) -> (&str, Option<&str>) {
    match tag.split_once('@') {
        Some((base, attr)) if !base.is_empty() && !attr.is_empty() => (base, Some(attr)),
        _ => (tag, None),
    }
}

/// Check if a domain's attributes satisfy the `@attr` filter
/// `cn`   → domain must have attribute `cn`
/// `!cn`  → domain must NOT have attribute `cn`
///
/// Note: `!` negation is a kixdns extension. V2Ray matches `@!cn` as a literal
/// attribute key (not negation), so configs ported from V2Ray behave differently.
fn attr_filter_matches(attrs: &[String], filter: &str) -> bool {
    if let Some(neg) = filter.strip_prefix('!') {
        !attrs.iter().any(|a| a.eq_ignore_ascii_case(neg))
    } else {
        attrs.iter().any(|a| a.eq_ignore_ascii_case(filter))
    }
}

/// Parse a V2Ray Domain.Attribute protobuf message to extract the key field
/// Attribute { string key = 1; oneof typed_value { ... } }
fn parse_attribute_key(data: &[u8]) -> Option<String> {
    let mut pos = 0;
    while pos < data.len() {
        let field_tag = data[pos] >> 3;
        let wire_type = data[pos] & 0x07;
        pos += 1;

        match field_tag {
            1 => {
                let len = parse_varint(data, &mut pos).ok()?;
                if pos + len > data.len() {
                    return None;
                }
                return std::str::from_utf8(&data[pos..pos + len])
                    .ok()
                    .map(|s| s.to_ascii_lowercase());
            }
            _ => match wire_type {
                0 => {
                    parse_varint(data, &mut pos).ok()?;
                }
                1 => {
                    pos += 8;
                }
                5 => {
                    pos += 4;
                }
                2 => {
                    let len = parse_varint(data, &mut pos).ok()?;
                    pos += len;
                }
                _ => return None,
            },
        }
    }
    None
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

impl GeoSiteManager {
    /// 从 V2Ray 格式文件加载 GeoSite 数据 / Load GeoSite data from V2Ray format file
    ///
    /// # 参数 / Parameters
    /// - `path`: 文件路径 / File path
    ///
    /// # 返回 / Returns
    /// 返回加载的条目数量 / Returns the number of loaded entries
    ///
    /// # 错误 / Errors
    /// 如果文件不存在或格式错误，返回错误 / Returns error if file doesn't exist or format is invalid
    ///
    /// # 示例 / Example
    /// ```no_run
    /// use kixdns::matcher::geosite::GeoSiteManager;
    /// let mut manager = GeoSiteManager::new();
    /// let count = manager.load_from_v2ray_file("geosite.json").unwrap();
    /// println!("Loaded {} GeoSite entries", count);
    /// ```
    pub fn load_from_v2ray_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize> {
        let path = path.as_ref();

        // 检测文件格式：.dat 或 .json / Detect file format: .dat or .json
        let is_dat = path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.eq_ignore_ascii_case("dat"))
            .unwrap_or(false);

        if is_dat {
            // 加载 .dat 格式 / Load .dat format
            return self.load_from_dat_file(path);
        }

        // 加载 JSON 格式 / Load JSON format
        let content = fs::read_to_string(path)
            .with_context(|| format!("read geosite file: {}", path.display()))?;

        let v2ray_data: V2RayGeoSiteList =
            serde_json::from_str(&content).with_context(|| "parse V2Ray GeoSite JSON format")?;

        let count = v2ray_data.entries.len();

        let entries = self.convert_v2ray_to_entries(v2ray_data);

        for entry in entries {
            self.add_entry(entry);
        }

        Ok(count)
    }

    /// 从 .dat 文件按需加载指定的 GeoSite tags / Load specified GeoSite tags from .dat file on-demand
    ///
    /// # 参数 / Parameters
    /// - `path`: .dat 文件路径 / .dat file path
    /// - `tags`: 需要加载的 tag 列表 / List of tags to load
    ///
    /// # 返回 / Returns
    /// 返回实际加载的条目数量 / Returns the number of entries actually loaded
    ///
    /// # 错误 / Errors
    /// 如果文件不存在或格式错误，返回错误 / Returns error if file doesn't exist or format is invalid
    pub fn load_from_dat_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize> {
        let path = path.as_ref();

        // 读取文件内容 / Read file content
        let content =
            fs::read(path).with_context(|| format!("read .dat file: {}", path.display()))?;

        // V2Ray .dat 文件格式分析 / V2Ray .dat file format analysis
        // 外层结构：repeated GeoSite 条目 / Outer structure: repeated GeoSite entries
        // 每个 GeoSite 条目包含 / Each GeoSite entry contains:
        //   - tag (string, field tag 0x0A)
        //   - domains (repeated message, field tag 0x12)
        //     每个域名包含 / Each domain contains:
        //       - type (uint64, field tag 0x08)
        //       - value (string, field tag 0x12)

        let mut pos = 0;
        let mut loaded_count = 0;

        while pos < content.len() {
            // 读取外层字段标签 / Read outer field tag
            if pos >= content.len() {
                break;
            }

            let field_tag = content[pos];
            pos += 1;

            // 解析 varint 长度 / Parse varint length
            let entry_len = parse_varint(&content, &mut pos)?;

            // 检查是否有足够的数据 / Check if we have enough data
            if pos + entry_len > content.len() {
                break;
            }

            let entry_end = pos + entry_len;

            // field_tag = 0x0A 表示 GeoSite 条目 (field 1, wire type 2: string)
            // field_tag = 0x0A indicates GeoSite entry (field 1, wire type 2: string)
            if field_tag == 0x0A {
                let mut tag = String::new();
                let mut matchers: Vec<DomainMatcher> = Vec::new();

                // 解析 GeoSite 条目内容 / Parse GeoSite entry content
                while pos < entry_end {
                    let inner_tag = content[pos];
                    pos += 1;

                    let inner_len = parse_varint(&content, &mut pos)?;

                    if pos + inner_len > entry_end {
                        break;
                    }

                    match inner_tag {
                        // 0x0A: country_code (string, field 1)
                        0x0A => {
                            if let Ok(tag_str) = std::str::from_utf8(&content[pos..pos + inner_len])
                            {
                                tag = tag_str.to_string();
                                tracing::debug!(target = "geosite", tag = %tag_str, "parsed GeoSite country_code");
                            }
                            pos += inner_len;
                        }
                        // 0x12: domain (repeated Domain message, field 2)
                        0x12 => {
                            // V2Ray 的 domain 字段是 repeated Domain 消息
                            // V2Ray's domain field is repeated Domain messages
                            // 每个 Domain 消息包含: type (field 1) 和 value (field 2)
                            // Each Domain message contains: type (field 1) and value (field 2)
                            let domains_data = &content[pos..pos + inner_len];
                            match self.parse_v2ray_domains(domains_data) {
                                Ok(parsed) => {
                                    let count = parsed.len();
                                    matchers.extend(parsed.into_iter().map(|(m, _)| m));
                                    tracing::debug!(target = "geosite", tag = %tag,
                                                 count = count,
                                                 "parsed domains from V2Ray protobuf format");
                                }
                                Err(err) => {
                                    tracing::warn!(target = "geosite", tag = %tag, error = %err,
                                                  "failed to parse V2Ray domains, skipping tag");
                                }
                            }
                            pos += inner_len;
                        }
                        _ => {
                            // 跳过未知字段 / Skip unknown field
                            pos += inner_len;
                        }
                    }
                }

                // 使用解析好的 matchers / Use parsed matchers
                if !tag.is_empty() && !matchers.is_empty() {
                    tracing::info!(target = "geosite", tag = %tag, 
                                domain_count = matchers.len(),
                                "loaded GeoSite tag with domains");
                    // 将 tag 转换为小写以支持大小写不敏感的匹配 / Convert tag to lowercase for case-insensitive matching
                    let tag_lower = tag.to_lowercase();
                    tracing::debug!(target = "geosite", original_tag = %tag, tag_lower = %tag_lower,
                                 "inserting tag into database");
                    self.database.insert(tag_lower, matchers);
                    loaded_count += 1;
                } else if !tag.is_empty() {
                    tracing::warn!(target = "geosite", tag = %tag,
                                  "tag has no valid domains, skipping");
                }
            } else {
                // 跳过未知字段 / Skip unknown field
                pos = entry_end;
            }
        }

        // 根据实际加载的条数重建缓存
        self.rebuild_cache();

        info!(
            target = "geosite",
            loaded_count = loaded_count,
            "loaded GeoSite data from V2Ray .dat file"
        );
        Ok(loaded_count)
    }

    /// 解析 varint / Parse varint
    /// Note: Reserved for future use in dat file parsing
    #[allow(dead_code)]
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

    /// 从 .dat 文件按需加载指定的 GeoSite tags / Load specified GeoSite tags from .dat file on-demand
    ///
    /// # 参数 / Parameters
    /// - `path`: .dat 文件路径 / .dat file path
    /// - `tags`: 需要加载的 tag 列表 / List of tags to load
    ///
    /// # 返回 / Returns
    /// 返回实际加载的条目数量 / Returns the number of entries actually loaded
    ///
    /// # 错误 / Errors
    /// 如果文件不存在或格式错误，返回错误 / Returns error if file doesn't exist or format is invalid
    pub fn load_from_dat_file_selective<P: AsRef<Path>>(
        &mut self,
        path: P,
        tags: &[String],
    ) -> anyhow::Result<usize> {
        if tags.is_empty() {
            return Ok(0);
        }

        // Pre-process tags: split `tag@attr` syntax into (base, attr_filter)
        // Map: base_tag_lower → Vec<(store_tag_lower, Option<attr_filter>)>
        let mut tag_requests: FxHashMap<String, Vec<(String, Option<String>)>> =
            FxHashMap::default();
        for tag in tags {
            let (base, attr) = split_tag_attr(tag);
            tag_requests
                .entry(base.to_lowercase())
                .or_default()
                .push((tag.to_lowercase(), attr.map(|a| a.to_lowercase())));
        }

        info!(target = "geosite", requested_tags = ?tags,
             "loading GeoSite data selectively from .dat file");

        // 读取文件内容 / Read file content
        let content = fs::read(path.as_ref())
            .with_context(|| format!("read .dat file: {}", path.as_ref().display()))?;

        let mut pos = 0;
        let mut loaded_count = 0;

        while pos < content.len() {
            if pos >= content.len() {
                break;
            }

            let field_tag = content[pos];
            pos += 1;

            let entry_len = parse_varint(&content, &mut pos)?;

            if pos + entry_len > content.len() {
                break;
            }

            let entry_end = pos + entry_len;

            // field_tag = 0x0A 表示 GeoSite 条目
            if field_tag == 0x0A {
                let mut tag = String::new();

                // 先解析 tag，判断是否需要加载 / Parse tag first to check if we need to load it
                let temp_pos = pos;
                // Clone matching requests out of the map to release the borrow before mutating self
                let matching_requests: Option<Vec<(String, Option<String>)>> = loop {
                    if pos >= entry_end {
                        break None;
                    }
                    let inner_tag = content[pos];
                    pos += 1;
                    let inner_len = parse_varint(&content, &mut pos)?;
                    if pos + inner_len > entry_end {
                        break None;
                    }
                    // 0x0A: tag/country_code (string, field 1)
                    if inner_tag == 0x0A {
                        if let Ok(tag_str) =
                            std::str::from_utf8(&content[pos..pos + inner_len])
                        {
                            tag = tag_str.to_string();
                            let tag_lower = tag.to_lowercase();
                            // Match against base tags (supports `@attr` split)
                            if let Some(reqs) = tag_requests.get(&tag_lower) {
                                debug!(target = "geosite", tag = %tag_str,
                                      "loading requested tag");
                                break Some(reqs.clone());
                            } else {
                                debug!(target = "geosite", tag = %tag_str,
                                       "skipping unwanted tag");
                            }
                        }
                        break None;
                    }
                    pos += inner_len;
                };

                if let Some(requests) = matching_requests {
                    // 重新解析整个条目，提取 domains + attributes
                    pos = temp_pos;
                    let mut all_domains: Vec<(DomainMatcher, Vec<String>)> = Vec::new();

                    while pos < entry_end {
                        let inner_tag = content[pos];
                        pos += 1;
                        let inner_len = parse_varint(&content, &mut pos)?;
                        if pos + inner_len > entry_end {
                            break;
                        }
                        match inner_tag {
                            0x0A => {
                                pos += inner_len;
                            }
                            0x12 => {
                                let domains_data = &content[pos..pos + inner_len];
                                match self.parse_v2ray_domains(domains_data) {
                                    Ok(parsed) => {
                                        all_domains.extend(parsed);
                                    }
                                    Err(err) => {
                                        warn!(target = "geosite", tag = %tag, error = %err,
                                             "failed to parse V2Ray domains, skipping domain entry");
                                    }
                                }
                                pos += inner_len;
                            }
                            _ => {
                                pos += inner_len;
                            }
                        }
                    }

                    // For each request, apply attribute filter and store under original tag
                    for (store_tag, attr_filter) in &requests {
                        let matchers: Vec<DomainMatcher> = all_domains
                            .iter()
                            .filter(|(_, attrs)| match attr_filter {
                                None => true,
                                Some(f) => attr_filter_matches(attrs, f),
                            })
                            .cloned()
                            .map(|(m, _)| m)
                            .collect();

                        if !matchers.is_empty() {
                            info!(target = "geosite", tag = %store_tag,
                                  domain_count = matchers.len(),
                                  attr_filter = ?attr_filter,
                                  "loaded GeoSite tag with domains");
                            self.database.insert(store_tag.clone(), matchers);
                            loaded_count += 1;
                        } else {
                            warn!(target = "geosite", tag = %store_tag,
                                  attr_filter = ?attr_filter,
                                  "no domains matched attribute filter");
                        }
                    }
                } else {
                    pos = entry_end;
                }
            } else {
                pos = entry_end;
            }
        }

        info!(
            target = "geosite",
            loaded_count = loaded_count,
            requested_count = tags.len(),
            "selectively loaded GeoSite data from .dat file"
        );

        Ok(loaded_count)
    }

    /// 解析 .dat 格式的域名列表 / Parse domain list in .dat format
    /// Note: Reserved for future use in dat file parsing
    #[allow(dead_code)]
    #[allow(clippy::regex_creation_in_loops)]
    fn parse_dat_domain_list(&self, data: &[u8]) -> anyhow::Result<Vec<DomainMatcher>> {
        let mut matchers = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            // 读取域名类型 / Read domain type
            let domain_type = data[pos];
            pos += 1;

            // 读取域名长度 / Read domain length
            if pos + 2 > data.len() {
                break;
            }
            let domain_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + domain_len > data.len() {
                anyhow::bail!("invalid domain data: incomplete domain string");
            }

            // 读取域名字符串 / Read domain string
            let domain = String::from_utf8_lossy(&data[pos..pos + domain_len]).to_string();
            pos += domain_len;

            // 根据类型创建匹配器 / Create matcher based on type
            let matcher = match domain_type {
                dat_format::TYPE_FULL => DomainMatcher::Full(domain),
                dat_format::TYPE_SUBDOMAIN => DomainMatcher::Suffix(domain),
                dat_format::TYPE_KEYWORD => DomainMatcher::Keyword(domain),
                dat_format::TYPE_REGEX => match RegexBuilder::new(&domain)
                    .size_limit(1_000_000) // 1MB state space limit
                    .dfa_size_limit(1_000_000) // 1MB DFA limit
                    .build()
                {
                    Ok(re) => DomainMatcher::Regex(re),
                    Err(err) => {
                        warn!(target = "geosite", pattern = %domain, error = %err,
                                 "invalid regex pattern, using empty regex");
                        DomainMatcher::Regex(Regex::new(r"^$").unwrap())
                    }
                },
                _ => {
                    warn!(target = "geosite", type = domain_type, 
                         "unknown domain type, using suffix matcher");
                    DomainMatcher::Suffix(domain)
                }
            };

            matchers.push(matcher);
        }

        Ok(matchers)
    }

    /// 解析 V2Ray protobuf 格式的 Domain 消息列表 / Parse V2Ray protobuf format Domain message list
    ///
    /// V2Ray .dat 文件中的 domains 字段是 repeated Domain 消息
    /// The domains field in V2Ray .dat file is repeated Domain messages
    /// 每个 Domain 消息包含: type (field 1, varint) 和 value (field 2, string)
    /// Each Domain message contains: type (field 1, varint) and value (field 2, string)
    /// 解析 V2Ray protobuf 格式的 Domain 消息列表 / Parse V2Ray protobuf format Domain message list
    ///
    /// V2Ray .dat 文件中的 domains 字段是 repeated Domain 消息
    /// The domains field in V2Ray .dat file is repeated Domain messages
    /// 每个 Domain 消息包含: type (field 1, varint) 和 value (field 2, string)
    /// Each Domain message contains: type (field 1, varint) and value (field 2, string)
    /// Returns (DomainMatcher, attribute_keys) pairs — attribute keys enable `@attr` filtering
    #[allow(clippy::regex_creation_in_loops)]
    fn parse_v2ray_domains(&self, data: &[u8]) -> anyhow::Result<Vec<(DomainMatcher, Vec<String>)>> {
        let mut results = Vec::new();
        let mut pos = 0;

        let mut current_matcher: Option<DomainMatcher> = None;
        let mut current_attrs: Vec<String> = Vec::new();

        tracing::debug!(
            target = "geosite",
            data_len = data.len(),
            "starting to parse V2Ray domains"
        );

        while pos < data.len() {
            // 读取 field tag 和 wire type / Read field tag and wire type
            let field_tag = data[pos] >> 3;
            let wire_type = data[pos] & 0x07;
            pos += 1;

            match field_tag {
                1 => {
                    // field 1: type (varint, wire_type 0)
                    if wire_type != 0 {
                        anyhow::bail!("invalid wire type for type field");
                    }
                    let domain_type = parse_varint(data, &mut pos)?;

                    // 读取 field 2: value (string, wire_type 2)
                    if pos >= data.len() || data[pos] >> 3 != 2 {
                        anyhow::bail!("missing value field after type field");
                    }
                    pos += 1; // skip field tag

                    let value_len = parse_varint(data, &mut pos)?;

                    if pos + value_len > data.len() {
                        anyhow::bail!("invalid domain data: incomplete value string");
                    }

                    let domain_value =
                        String::from_utf8_lossy(&data[pos..pos + value_len]).to_string();
                    pos += value_len;

                    // 根据 V2Ray Domain.Type 创建匹配器 / Create matcher based on V2Ray Domain.Type
                    let matcher = match domain_type {
                        0 => DomainMatcher::Keyword(domain_value), // Plain
                        1 => {
                            // Regex
                            match RegexBuilder::new(&domain_value)
                                .size_limit(1_000_000)
                                .dfa_size_limit(1_000_000)
                                .build()
                            {
                                Ok(re) => DomainMatcher::Regex(re),
                                Err(err) => {
                                    warn!(target = "geosite", pattern = %domain_value, error = %err,
                                         "invalid regex pattern, using empty regex");
                                    DomainMatcher::Regex(Regex::new(r"^$").unwrap())
                                }
                            }
                        }
                        2 => {
                            // RootDomain - 转换为 Suffix 匹配器 / Convert to Suffix matcher
                            DomainMatcher::Suffix(format!(".{}", domain_value))
                        }
                        3 => DomainMatcher::Full(domain_value), // Full
                        _ => {
                            warn!(target = "geosite", type = domain_type,
                                 "unknown V2Ray domain type, using full matcher");
                            DomainMatcher::Full(domain_value)
                        }
                    };
                    current_matcher = Some(matcher);
                }
                2 => {
                    // field 2: value (string, wire_type 2) — standalone, skip
                    if wire_type != 2 {
                        anyhow::bail!("invalid wire type for value field");
                    }
                    let value_len = parse_varint(data, &mut pos)?;
                    if pos + value_len > data.len() {
                        anyhow::bail!("invalid domain data: incomplete value string");
                    }
                    pos += value_len;
                }
                3 => {
                    // field 3: attribute (repeated Attribute message, wire_type 2)
                    // Domain.Attribute { string key = 1; oneof typed_value { ... } }
                    if wire_type != 2 {
                        anyhow::bail!("invalid wire type for attribute field");
                    }
                    let attr_len = parse_varint(data, &mut pos)?;
                    if pos + attr_len > data.len() {
                        anyhow::bail!("invalid domain data: incomplete attribute");
                    }
                    if let Some(key) = parse_attribute_key(&data[pos..pos + attr_len]) {
                        current_attrs.push(key);
                    }
                    pos += attr_len;
                }
                _ => {
                    // 跳过未知字段 / Skip unknown field
                    match wire_type {
                        0 => {
                            parse_varint(data, &mut pos)?;
                        }
                        1 => {
                            if pos + 8 > data.len() {
                                anyhow::bail!("invalid domain data: incomplete fixed64");
                            }
                            pos += 8;
                        }
                        5 => {
                            if pos + 4 > data.len() {
                                anyhow::bail!("invalid domain data: incomplete fixed32");
                            }
                            pos += 4;
                        }
                        2 => {
                            let len = parse_varint(data, &mut pos)?;
                            if pos + len > data.len() {
                                anyhow::bail!("invalid domain data: incomplete length-delimited");
                            }
                            pos += len;
                        }
                        _ => {
                            anyhow::bail!("unknown wire type: {}", wire_type);
                        }
                    }
                }
            }
        }

        if let Some(matcher) = current_matcher.take() {
            results.push((matcher, std::mem::take(&mut current_attrs)));
        }

        tracing::debug!(
            target = "geosite",
            result_count = results.len(),
            "parsed V2Ray domains"
        );

        Ok(results)
    }

    /// 从 V2Ray 格式字符串加载 GeoSite 数据 / Load GeoSite data from V2Ray format string
    ///
    /// # 参数 / Parameters
    /// - `json_str`: JSON 字符串 / JSON string
    ///
    /// # 返回 / Returns
    /// 返回加载的条目数量 / Returns the number of loaded entries
    ///
    /// # 错误 / Errors
    /// 如果 JSON 格式错误，返回错误 / Returns error if JSON format is invalid
    pub fn load_from_v2ray_string(&mut self, json_str: &str) -> anyhow::Result<usize> {
        let v2ray_data: V2RayGeoSiteList =
            serde_json::from_str(json_str).with_context(|| "parse V2Ray GeoSite JSON format")?;

        let count = v2ray_data.entries.len();

        let entries = self.convert_v2ray_to_entries(v2ray_data);

        // 逐个添加条目，保留现有数据 / Add entries one by one, preserving existing data
        for entry in entries {
            self.add_entry(entry);
        }

        // 根据实际加载的条数重建缓存
        self.rebuild_cache();

        Ok(count)
    }

    /// 转换 V2Ray 格式为 GeoSiteEntry 列表 / Convert V2Ray format to GeoSiteEntry list
    fn convert_v2ray_to_entries(&self, v2ray_data: V2RayGeoSiteList) -> Vec<GeoSiteEntry> {
        v2ray_data
            .entries
            .into_iter()
            .map(|v2ray_entry| {
                // 将域名列表转换为 DomainMatcher 列表
                // Convert domain list to DomainMatcher list
                let matchers = v2ray_entry
                    .domains
                    .into_iter()
                    .map(|domain| {
                        // 根据域名格式选择合适的匹配器
                        // Select appropriate matcher based on domain format
                        if domain.starts_with("regexp:") {
                            // 正则匹配器 / Regex matcher
                            let pattern = domain.trim_start_matches("regexp:");
                            DomainMatcher::Regex(
                                RegexBuilder::new(pattern)
                                    .size_limit(1_000_000)
                                    .dfa_size_limit(1_000_000)
                                    .build()
                                    .unwrap_or_else(|_| Regex::new(r"^$").unwrap()),
                            )
                        } else if domain.starts_with("domain:") {
                            // 完整域名匹配器 / Full domain matcher
                            let pattern = domain.trim_start_matches("domain:");
                            DomainMatcher::Full(pattern.to_string())
                        } else if domain.starts_with("keyword:") {
                            // 关键词匹配器 / Keyword matcher
                            let pattern = domain.trim_start_matches("keyword:");
                            DomainMatcher::Keyword(pattern.to_string())
                        } else {
                            // 默认为后缀匹配器 / Default to suffix matcher
                            // 如果域名包含通配符，使用正则
                            if domain.contains('*') {
                                let pattern = domain.replace('.', r"\.").replace('*', ".*");
                                DomainMatcher::Regex(
                                    RegexBuilder::new(&format!("^{}$", pattern))
                                        .size_limit(1_000_000)
                                        .dfa_size_limit(1_000_000)
                                        .build()
                                        .unwrap_or_else(|_| Regex::new(r"^$").unwrap()),
                                )
                            } else {
                                DomainMatcher::Suffix(domain)
                            }
                        }
                    })
                    .collect();

                GeoSiteEntry {
                    tag: v2ray_entry.tag,
                    matchers,
                }
            })
            .collect()
    }
}

/// 启动 GeoSite 数据文件热重载监控 / Start GeoSite data file hot-reload monitoring
///
/// # 参数 / Parameters
/// - `paths`: GeoSite 数据文件路径列表 / GeoSite data file path list
/// - `manager`: GeoSiteManager 实例（通过 Arc 共享）/ GeoSiteManager instance (shared via Arc)
/// - `tags`: 需要加载的 tag 列表（空表示全部加载）/ List of tags to load (empty means load all)
pub fn spawn_geosite_watcher(
    paths: Vec<PathBuf>,
    manager: Arc<RwLock<GeoSiteManager>>,
    tags: Vec<String>,
) {
    if paths.is_empty() {
        return;
    }

    // 使用阻塞线程持有watcher，避免异步生命周期问题
    // Use blocking thread to hold watcher, avoiding async lifetime issues
    thread::spawn(move || {
        if let Err(err) = run_geosite_watcher(paths, manager, tags) {
            warn!(target = "geosite_watcher", error = %err, "GeoSite watcher exited with error");
        }
    });
}

/// 运行 GeoSite watcher / Run GeoSite watcher
fn run_geosite_watcher(
    paths: Vec<PathBuf>,
    manager: Arc<RwLock<GeoSiteManager>>,
    tags: Vec<String>,
) -> notify::Result<()> {
    // Watch parent directories instead of individual files.
    // Linux inotify watches inodes; atomic replacement (mv newfile oldfile)
    // creates a new inode that would be missed when watching files directly.
    // By watching parent directories, we capture IN_MOVED_TO/IN_CREATE events
    // for the target filenames, properly detecting atomic replacements.

    // Collect unique parent directories and their target filenames
    let mut dir_watches: FxHashMap<PathBuf, Vec<std::ffi::OsString>> = FxHashMap::default();
    for p in &paths {
        let parent = p
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        let fname = p.file_name().map(|s| s.to_os_string()).unwrap_or_default();
        dir_watches.entry(parent).or_default().push(fname);
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default())?;

    // Watch all unique parent directories
    for (dir, file_names) in &dir_watches {
        watcher.watch(dir, RecursiveMode::NonRecursive)?;
        info!(target = "geosite_watcher", path = %dir.display(), filenames = ?file_names, "watching GeoSite file parent directory (atomic-replacement safe)");
    }

    info!(target = "geosite_watcher", "GeoSite watcher started");

    // Build a set of target filenames for quick event matching
    let target_filenames: FxHashSet<std::ffi::OsString> = dir_watches
        .values()
        .flat_map(|v| v.iter().cloned())
        .collect();

    for res in rx {
        match res {
            Ok(event) => {
                // Check if the event is for any file we care about
                let is_target_file = event.paths.iter().any(|p| {
                    p.file_name()
                        .is_some_and(|fname| target_filenames.contains(fname))
                });
                if !is_target_file {
                    continue;
                }

                // 仅在数据更改时重载 / Only reload on data changes
                if !event.kind.is_modify() && !event.kind.is_create() {
                    continue;
                }

                // Find the matching original path for this event
                let matching_path = event.paths.iter().find(|p| {
                    p.file_name()
                        .is_some_and(|fname| target_filenames.contains(fname))
                });
                let path = match matching_path {
                    Some(p) => p.clone(),
                    None => continue,
                };

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
                        // 加载 .dat 格式 / Load .dat format
                        let mut guard = manager.write();
                        if tags.is_empty() {
                            guard.load_from_dat_file(&path)
                        } else {
                            guard.load_from_dat_file_selective(&path, &tags)
                        }
                    } else {
                        // 加载 JSON 格式 / Load JSON format
                        std::fs::read_to_string(&path)
                            .with_context(|| format!("read GeoSite file: {}", path.display()))
                            .and_then(|json_str| {
                                serde_json::from_str::<V2RayGeoSiteList>(&json_str)
                                    .with_context(|| "parse V2Ray GeoSite JSON format")
                            })
                            .map(|v2ray_data| {
                                let mut guard = manager.write();
                                let entries = guard.convert_v2ray_to_entries(v2ray_data);
                                let loaded_count = entries.len();
                                guard.reload(entries);
                                loaded_count
                            })
                    };

                    match load_result {
                        Ok(loaded_count) => {
                            info!(target = "geosite_watcher", path = %path.display(),
                                 loaded_count = loaded_count,
                                 "GeoSite data reloaded");
                            break;
                        }
                        Err(err) => {
                            retries -= 1;
                            if retries == 0 {
                                warn!(target = "geosite_watcher", path = %path.display(),
                                     error = %err,
                                     "GeoSite reload failed, keeping old data");
                            } else {
                                // 稍等后重试 / Wait a bit and retry
                                std::thread::sleep(Duration::from_millis(100));
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!(target = "geosite_watcher", error = %err, "watcher event error");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(mut value: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                bytes.push(byte);
                break;
            }
            bytes.push(byte | 0x80);
        }
        bytes
    }

    fn encode_varint_field(field_number: u8, value: usize) -> Vec<u8> {
        let mut result = vec![(field_number << 3) | 0];
        result.extend(encode_varint(value));
        result
    }

    fn encode_ld(field_number: u8, data: &[u8]) -> Vec<u8> {
        let mut result = vec![(field_number << 3) | 2];
        result.extend(encode_varint(data.len()));
        result.extend_from_slice(data);
        result
    }

    fn encode_str(field_number: u8, s: &str) -> Vec<u8> {
        encode_ld(field_number, s.as_bytes())
    }

    /// Build a Domain protobuf message
    fn build_domain(domain_type: usize, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut msg = encode_varint_field(1, domain_type);
        msg.extend(encode_str(2, value));
        for attr in attrs {
            let attr_msg = encode_str(1, attr); // Attribute.key
            msg.extend(encode_ld(3, &attr_msg)); // repeated attribute
        }
        msg
    }

    /// Build a GeoSite entry
    fn build_geosite(tag: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut msg = encode_str(1, tag);
        for d in domains {
            msg.extend(encode_ld(2, d));
        }
        msg
    }

    /// Build a GeoSiteList (.dat file content)
    fn build_dat(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut result = Vec::new();
        for entry in entries {
            result.extend(encode_ld(1, entry));
        }
        result
    }

    #[test]
    fn test_split_tag_attr() {
        assert_eq!(split_tag_attr("category-games"), ("category-games", None));
        assert_eq!(
            split_tag_attr("category-games@cn"),
            ("category-games", Some("cn"))
        );
        assert_eq!(
            split_tag_attr("category-games@!cn"),
            ("category-games", Some("!cn"))
        );
        // Edge: empty parts → no split
        assert_eq!(split_tag_attr("tag@"), ("tag@", None));
        assert_eq!(split_tag_attr("@cn"), ("@cn", None));
    }

    #[test]
    fn test_attr_filter_matches() {
        let cn = vec!["cn".to_string()];
        assert!(attr_filter_matches(&cn, "cn"));
        assert!(!attr_filter_matches(&cn, "!cn"));
        assert!(!attr_filter_matches(&[], "cn"));
        assert!(attr_filter_matches(&[], "!cn"));
        // case insensitive
        assert!(attr_filter_matches(&["CN".to_string()], "cn"));
    }

    #[test]
    fn test_parse_attribute_key() {
        // Attribute { key = "cn" }
        let attr = encode_str(1, "cn");
        assert_eq!(parse_attribute_key(&attr), Some("cn".to_string()));

        // Attribute with extra fields (bool_value)
        let mut attr = encode_str(1, "geolocation");
        attr.extend(encode_varint_field(2, 1)); // bool_value = true
        assert_eq!(parse_attribute_key(&attr), Some("geolocation".to_string()));

        // Empty message
        assert_eq!(parse_attribute_key(&[]), None);
    }

    #[test]
    fn test_geosite_attr_filter_end_to_end() {
        let domains = vec![
            build_domain(3, "example.com", &["cn"]), // Full match, has @cn
            build_domain(3, "other.com", &[]),       // Full match, no attrs
        ];
        let entry = build_geosite("TEST", &domains);
        let dat = build_dat(&[entry]);

        let dir = std::env::temp_dir();
        let path = dir.join("kixdns_test_attr.dat");
        std::fs::write(&path, &dat).unwrap();

        // @cn: only example.com
        let mut m1 = GeoSiteManager::new();
        m1.load_from_dat_file_selective(&path, &["test@cn".to_string()])
            .unwrap();
        assert!(m1.matches("test@cn", "example.com"));
        assert!(!m1.matches("test@cn", "other.com"));

        // no filter: both
        let mut m2 = GeoSiteManager::new();
        m2.load_from_dat_file_selective(&path, &["test".to_string()])
            .unwrap();
        assert!(m2.matches("test", "example.com"));
        assert!(m2.matches("test", "other.com"));

        // @!cn: only other.com
        let mut m3 = GeoSiteManager::new();
        m3.load_from_dat_file_selective(&path, &["test@!cn".to_string()])
            .unwrap();
        assert!(!m3.matches("test@!cn", "example.com"));
        assert!(m3.matches("test@!cn", "other.com"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_geosite_attr_and_plain_same_base() {
        // Request both `test` and `test@cn` — both should load from same .dat entry
        let domains = vec![
            build_domain(3, "a.com", &["cn"]),
            build_domain(3, "b.com", &[]),
        ];
        let entry = build_geosite("DUAL", &domains);
        let dat = build_dat(&[entry]);

        let dir = std::env::temp_dir();
        let path = dir.join("kixdns_test_dual.dat");
        std::fs::write(&path, &dat).unwrap();

        let mut m = GeoSiteManager::new();
        let count = m
            .load_from_dat_file_selective(&path, &["dual".to_string(), "dual@cn".to_string()])
            .unwrap();
        assert_eq!(count, 2); // both loaded

        assert!(m.matches("dual", "a.com"));
        assert!(m.matches("dual", "b.com"));
        assert!(m.matches("dual@cn", "a.com"));
        assert!(!m.matches("dual@cn", "b.com"));

        let _ = std::fs::remove_file(&path);
    }
}
