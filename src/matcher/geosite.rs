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
use regex::Regex;
use rustc_hash::FxHashMap;
use rustc_hash::FxHasher;
use serde::Deserialize;
use tracing::{debug, info, warn};

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
                let suffix_clean = if suffix.starts_with('.') {
                    &suffix[1..]
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
        let total_domains: usize = self
            .database.values().map(|matchers| matchers.len())
            .sum();

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
                let s_clean = if s.starts_with('.') { &s[1..] } else { s };

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
                                Ok(parsed_matchers) => {
                                    let count = parsed_matchers.len();
                                    matchers.extend(parsed_matchers);
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

        // 创建 tag 查找集合（小写）/ Create tag lookup set (lowercase)
        let tags_set: std::collections::HashSet<String> =
            tags.iter().map(|s| s.to_lowercase()).collect();

        info!(target = "geosite", requested_tags = ?tags,
             "loading GeoSite data selectively from .dat file");

        // 读取文件内容 / Read file content
        let content = fs::read(path.as_ref())
            .with_context(|| format!("read .dat file: {}", path.as_ref().display()))?;

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

            // field_tag = 0x0A 表示 GeoSite 条目
            if field_tag == 0x0A {
                let mut tag = String::new();
                let mut tag_found = false;

                // 先解析 tag，判断是否需要加载 / Parse tag first to check if we need to load it
                let temp_pos = pos;
                while pos < entry_end {
                    let inner_tag = content[pos];
                    pos += 1;

                    let inner_len = parse_varint(&content, &mut pos)?;

                    if pos + inner_len > entry_end {
                        break;
                    }

                    // 0x0A: tag/country_code (string, field 1)
                    if inner_tag == 0x0A {
                        if let Ok(tag_str) = std::str::from_utf8(&content[pos..pos + inner_len]) {
                            tag = tag_str.to_string();
                            let tag_lower = tag.to_lowercase();

                            // 检查是否在需要的列表中 / Check if in requested list
                            tag_found = tags_set.contains(&tag_lower);

                            if tag_found {
                                debug!(target = "geosite", tag = %tag_str,
                                      "loading requested tag");
                            } else {
                                debug!(target = "geosite", tag = %tag_str,
                                       "skipping unwanted tag");
                            }
                        }
                        // Skip remaining tag field data and break
                        // pos += inner_len is implicitly handled by break
                        break; // tag 字段后直接跳过，不再继续解析 / Skip after tag field
                    }

                    // 跳过非 tag 字段 / Skip non-tag fields
                    pos += inner_len;
                }

                // 如果 tag 在需要列表中，重新解析整个条目 / If tag is requested, re-parse entire entry
                if tag_found {
                    // 重置位置到条目开始 / Reset position to entry start
                    pos = temp_pos;
                    let mut matchers: Vec<DomainMatcher> = Vec::new();

                    while pos < entry_end {
                        let inner_tag = content[pos];
                        pos += 1;

                        let inner_len = parse_varint(&content, &mut pos)?;

                        if pos + inner_len > entry_end {
                            break;
                        }

                        match inner_tag {
                            // 0x0A: tag (string, field 1)
                            0x0A => {
                                if let Ok(tag_str) =
                                    std::str::from_utf8(&content[pos..pos + inner_len])
                                {
                                    tag = tag_str.to_string();
                                }
                                pos += inner_len;
                            }
                            // 0x12: domain (repeated Domain message, field 2)
                            0x12 => {
                                let domains_data = &content[pos..pos + inner_len];
                                match self.parse_v2ray_domains(domains_data) {
                                    Ok(parsed_matchers) => {
                                        let count = parsed_matchers.len();
                                        matchers.extend(parsed_matchers);
                                        debug!(target = "geosite", tag = %tag,
                                             count = count,
                                             "parsed domains from V2Ray protobuf format");
                                    }
                                    Err(err) => {
                                        warn!(target = "geosite", tag = %tag, error = %err,
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

                    // 添加到 database / Add to database
                    if !tag.is_empty() && !matchers.is_empty() {
                        info!(target = "geosite", tag = %tag,
                              domain_count = matchers.len(),
                              "loaded GeoSite tag with domains");
                        let tag_lower = tag.to_lowercase();
                        self.database.insert(tag_lower, matchers);
                        loaded_count += 1;
                    }
                } else {
                    // tag 不在需要列表中，跳过此条目 / Tag not in requested list, skip this entry
                    pos = entry_end;
                }
            } else {
                // 跳过非 GeoSite 条目 / Skip non-GeoSite entries
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
                dat_format::TYPE_REGEX => match Regex::new(&domain) {
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
    fn parse_v2ray_domains(&self, data: &[u8]) -> anyhow::Result<Vec<DomainMatcher>> {
        let mut matchers = Vec::new();
        let mut pos = 0;

        tracing::debug!(
            target = "geosite",
            data_len = data.len(),
            "starting to parse V2Ray domains"
        );

        // 打印前 20 字节的十六进制数据 / Print first 20 bytes in hex
        let hex_data: String = data
            .iter()
            .take(20)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        tracing::debug!(target = "geosite", hex_data = %hex_data, "first 20 bytes of data");

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
                    // 对于 varint,直接读取值 / For varint, read value directly
                    let domain_type = parse_varint(data, &mut pos)?;

                    tracing::debug!(
                        target = "geosite",
                        domain_type = domain_type,
                        "parsed domain type"
                    );

                    // 读取 field 2: value (string, wire_type 2)
                    if pos >= data.len() || data[pos] >> 3 != 2 {
                        anyhow::bail!("missing value field after type field");
                    }
                    pos += 1; // skip field tag

                    let value_len = parse_varint(data, &mut pos)?;

                    tracing::debug!(
                        target = "geosite",
                        value_len = value_len,
                        "parsed value length"
                    );

                    if pos + value_len > data.len() {
                        anyhow::bail!("invalid domain data: incomplete value string");
                    }

                    let domain_value =
                        String::from_utf8_lossy(&data[pos..pos + value_len]).to_string();
                    pos += value_len;

                    tracing::debug!(target = "geosite", domain_value = %domain_value, "parsed domain value");

                    // 根据 V2Ray Domain.Type 创建匹配器 / Create matcher based on V2Ray Domain.Type
                    let matcher = match domain_type {
                        0 => DomainMatcher::Keyword(domain_value), // Plain
                        1 => {
                            // Regex
                            match Regex::new(&domain_value) {
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

                    matchers.push(matcher);
                }
                2 => {
                    // field 2: value (string, wire_type 2)
                    if wire_type != 2 {
                        anyhow::bail!("invalid wire type for value field");
                    }
                    // 读取长度 / Read length
                    let value_len = parse_varint(data, &mut pos)?;

                    if pos + value_len > data.len() {
                        anyhow::bail!("invalid domain data: incomplete value string");
                    }

                    // 跳过 value 数据 (这种情况不应该发生,因为 value 应该跟在 type 后面)
                    // Skip value data (this shouldn't happen as value should follow type)
                    pos += value_len;
                }
                _ => {
                    // 跳过未知字段 / Skip unknown field
                    match wire_type {
                        0 => {
                            // varint, 读取并跳过 / varint, read and skip
                            parse_varint(data, &mut pos)?;
                        }
                        1 | 5 => {
                            // 64-bit fixed, 跳过 8 字节 / 64-bit fixed, skip 8 bytes
                            if pos + 8 > data.len() {
                                anyhow::bail!("invalid domain data: incomplete fixed64");
                            }
                            pos += 8;
                        }
                        2 => {
                            // length-delimited, 读取长度并跳过 / length-delimited, read length and skip
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

        tracing::debug!(
            target = "geosite",
            matcher_count = matchers.len(),
            "parsed V2Ray domains"
        );

        Ok(matchers)
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
                                Regex::new(pattern).unwrap_or_else(|_| Regex::new(r"^$").unwrap()),
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
                                    Regex::new(&format!("^{}$", pattern))
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
    manager: Arc<std::sync::RwLock<GeoSiteManager>>,
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
    manager: Arc<std::sync::RwLock<GeoSiteManager>>,
    tags: Vec<String>,
) -> notify::Result<()> {
    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default())?;

    // 监听所有 GeoSite 数据文件 / Watch all GeoSite data files
    for path in &paths {
        watcher.watch(path, RecursiveMode::NonRecursive)?;
        info!(target = "geosite_watcher", path = %path.display(), "watching GeoSite file");
    }

    info!(target = "geosite_watcher", "GeoSite watcher started");

    for res in rx {
        match res {
            Ok(event) => {
                // 仅在数据更改时重载 / Only reload on data changes
                if !event.kind.is_modify() && !event.kind.is_create() {
                    continue;
                }

                let path = &event.paths[0];

                // 检测文件格式 / Detect file format
                let is_dat = path
                    .extension()
                    .and_then(|s| s.to_str())
                    .map(|s| s.eq_ignore_ascii_case("dat"))
                    .unwrap_or(false);

                // 简单的重试机制来处理文件写入竞争 / Simple retry mechanism to handle file write races
                let mut retries = 5;
                while retries > 0 {
                    let load_result = if is_dat {
                        // 加载 .dat 格式 / Load .dat format
                        // 安全地获取写锁，避免 RwLock 被污染时 panic / Safely acquire write lock to avoid panic if RwLock is poisoned
                        match manager.write() {
                            Ok(mut guard) => {
                                if tags.is_empty() {
                                    // 加载所有 tags / Load all tags
                                    guard.load_from_dat_file(path)
                                } else {
                                    // 按需加载指定的 tags / Load specified tags on-demand
                                    guard.load_from_dat_file_selective(path, &tags)
                                }
                            }
                            Err(e) => {
                                let mut guard = e.into_inner();
                                warn!(
                                    target = "geosite_watcher",
                                    "RwLock was poisoned, recovering and attempting reload"
                                );
                                if tags.is_empty() {
                                    guard.load_from_dat_file(path)
                                } else {
                                    guard.load_from_dat_file_selective(path, &tags)
                                }
                            }
                        }
                    } else {
                        // 加载 JSON 格式 / Load JSON format
                        std::fs::read_to_string(path)
                            .with_context(|| format!("read GeoSite file: {}", path.display()))
                            .and_then(|json_str| {
                                serde_json::from_str::<V2RayGeoSiteList>(&json_str)
                                    .with_context(|| "parse V2Ray GeoSite JSON format")
                            })
                            .map(|v2ray_data| {
                                // 安全地获取写锁 / Safely acquire write lock
                                match manager.write() {
                                    Ok(mut guard) => {
                                        let entries = guard.convert_v2ray_to_entries(v2ray_data);
                                        let loaded_count = entries.len();
                                        guard.reload(entries);
                                        loaded_count
                                    }
                                    Err(e) => {
                                        let mut guard = e.into_inner();
                                        warn!(
                                            target = "geosite_watcher",
                                            "RwLock was poisoned during JSON reload, recovering"
                                        );
                                        let entries = guard.convert_v2ray_to_entries(v2ray_data);
                                        let loaded_count = entries.len();
                                        guard.reload(entries);
                                        loaded_count
                                    }
                                }
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
