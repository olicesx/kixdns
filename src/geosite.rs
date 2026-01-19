// GeoSite 域名分类匹配器 / GeoSite domain category matcher
// 支持基于域名分类的路由决策 / Supports routing decisions based on domain categorization

use std::collections::HashMap;
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
use rustc_hash::FxHasher;
use serde::Deserialize;
use tracing::{info, warn};

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
            DomainMatcher::Full(pattern) => {
                domain.eq_ignore_ascii_case(pattern)
            }
            DomainMatcher::Suffix(suffix) => {
                domain.eq_ignore_ascii_case(suffix) || domain.ends_with(suffix)
            }
            DomainMatcher::Keyword(keyword) => {
                domain.to_ascii_lowercase().contains(&keyword.to_ascii_lowercase())
            }
            DomainMatcher::Regex(regex) => {
                regex.is_match(domain)
            }
        }
    }
}

/// GeoSite 条目 / GeoSite entry
#[derive(Debug, Clone)]
pub struct GeoSiteEntry {
    pub tag: String,
    pub matchers: Vec<DomainMatcher>,
}

/// GeoSite 数据库管理器 / GeoSite database manager
pub struct GeoSiteManager {
    // Tag -> Domain matchers
    database: HashMap<String, Vec<DomainMatcher>>,
    // Suffix index for O(1) lookup
    suffix_index: HashMap<String, Vec<String>>,
    // Query cache: hash(tag, domain) -> bool (零分配优化 / zero-allocation optimization)
    cache: MokaCache<u64, bool>,
}

impl GeoSiteManager {
    /// 创建新的 GeoSite 管理器 / Create new GeoSite manager
    /// 
    /// # 参数 / Parameters
    /// - `cache_capacity`: 缓存容量 / Cache capacity
    /// - `cache_ttl`: 缓存TTL（秒）/ Cache TTL (seconds)
    pub fn new(cache_capacity: u64, cache_ttl: u64) -> Self {
        Self {
            database: HashMap::new(),
            suffix_index: HashMap::new(),
            cache: MokaCache::builder()
                .max_capacity(cache_capacity)
                .time_to_live(Duration::from_secs(cache_ttl))
                .build(),
        }
    }

    /// 添加 GeoSite 条目 / Add GeoSite entry
    pub fn add_entry(&mut self, entry: GeoSiteEntry) {
        let tag = entry.tag.clone();
        
        // Build suffix index
        for matcher in &entry.matchers {
            if let DomainMatcher::Suffix(suffix) = matcher {
                self.suffix_index
                    .entry(suffix.clone())
                    .or_default()
                    .push(tag.clone());
            }
        }
        
        self.database.insert(tag, entry.matchers);
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
        if let Some(matchers) = self.database.get(tag) {
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
                domain.eq_ignore_ascii_case(d)
            }
            DomainMatcher::Suffix(s) => {
                // 后缀匹配，不区分大小写 / Suffix match, case insensitive
                let domain_lower = domain.to_ascii_lowercase();
                let suffix_lower = s.to_ascii_lowercase();
                domain_lower.ends_with(&suffix_lower)
            }
            DomainMatcher::Keyword(k) => {
                // 关键词匹配，不区分大小写 / Keyword match, case insensitive
                domain.to_ascii_lowercase().contains(&k.to_ascii_lowercase())
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
    pub fn tags(&self) -> Vec<String> {
        self.database.keys().cloned().collect()
    }

    /// 检查标签是否已加载 / Check if tag is loaded
    pub fn has_tag(&self, tag: &str) -> bool {
        self.database.contains_key(tag)
    }
}

// GeoSite tests / GeoSite 测试
// Tests for GeoSite domain matching, manager functionality, and caching
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matcher_full() {
        // Arrange: Create a full domain matcher
        let matcher = DomainMatcher::Full("google.com".to_string());
        
        // Act & Assert: Verify exact match
        assert!(matcher.matches("google.com"), "Should match exact domain");
        assert!(matcher.matches("GOOGLE.COM"), "Should match case-insensitively");
        assert!(!matcher.matches("www.google.com"), "Should not match subdomain");
    }

    #[test]
    fn test_domain_matcher_suffix() {
        // Arrange: Create a suffix domain matcher
        let matcher = DomainMatcher::Suffix(".google.com".to_string());
        
        // Act & Assert: Verify suffix matching
        assert!(matcher.matches("www.google.com"), "Should match subdomain with suffix");
        assert!(matcher.matches("mail.google.com"), "Should match subdomain with suffix");
        assert!(!matcher.matches("google.com.hk"), "Should not match different TLD");
    }

    #[test]
    fn test_domain_matcher_keyword() {
        // Arrange: Create a keyword domain matcher
        let matcher = DomainMatcher::Keyword("google".to_string());
        
        // Act & Assert: Verify keyword matching
        assert!(matcher.matches("www.google.com"), "Should match domain containing keyword");
        assert!(matcher.matches("googleapis.com"), "Should match domain containing keyword");
        assert!(!matcher.matches("www.bing.com"), "Should not match domain without keyword");
    }

    #[test]
    fn test_geosite_manager() {
        // Arrange: Create GeoSite manager and add Google category
        let mut manager = GeoSiteManager::new(1000, 3600);
        
        manager.add_entry(GeoSiteEntry {
            tag: "google".to_string(),
            matchers: vec![
                DomainMatcher::Full("google.com".to_string()),
                DomainMatcher::Suffix(".google.com".to_string()),
                DomainMatcher::Suffix(".googleapis.com".to_string()),
            ],
        });

        // Act & Assert: Test Google domain matches
        assert!(manager.matches("google", "google.com"), 
            "Should match exact Google domain");
        assert!(manager.matches("google", "www.google.com"), 
            "Should match Google subdomain");
        assert!(manager.matches("google", "mail.google.com"), 
            "Should match Google subdomain");
        assert!(manager.matches("google", "dns.googleapis.com"), 
            "Should match Google APIs domain");
        assert!(!manager.matches("google", "www.bing.com"), 
            "Should not match non-Google domain");
    }

    #[test]
    fn test_geosite_manager_cache() {
        // Arrange: Create GeoSite manager and add test entry
        let mut manager = GeoSiteManager::new(1000, 3600);
        
        manager.add_entry(GeoSiteEntry {
            tag: "test".to_string(),
            matchers: vec![
                DomainMatcher::Full("example.com".to_string()),
            ],
        });

        // Act & Assert: First call - not cached
        assert!(manager.matches("test", "example.com"), 
            "Should match domain on first call");
        
        // Act & Assert: Second call - should use cache
        assert!(manager.matches("test", "example.com"), 
            "Should match domain from cache");
    }

    #[test]
    fn test_geosite_manager_multiple_tags() {
        // Arrange: Create GeoSite manager and add multiple categories
        let mut manager = GeoSiteManager::new(1000, 3600);
        
        // Add CN category
        manager.add_entry(GeoSiteEntry {
            tag: "cn".to_string(),
            matchers: vec![
                DomainMatcher::Suffix(".cn".to_string()),
                DomainMatcher::Suffix(".com.cn".to_string()),
                DomainMatcher::Keyword("baidu".to_string()),
            ],
        });

        // Add category-ads
        manager.add_entry(GeoSiteEntry {
            tag: "category-ads".to_string(),
            matchers: vec![
                DomainMatcher::Keyword("ads".to_string()),
                DomainMatcher::Suffix(".adserver.com".to_string()),
            ],
        });

        // Act & Assert: Test CN matches
        assert!(manager.matches("cn", "www.baidu.com"), 
            "Should match CN domain with baidu keyword");
        assert!(manager.matches("cn", "example.com.cn"), 
            "Should match CN domain with .com.cn suffix");
        assert!(!manager.matches("cn", "www.google.com"), 
            "Should not match non-CN domain");

        // Act & Assert: Test ads matches
        assert!(manager.matches("category-ads", "ads.google.com"), 
            "Should match ads domain with ads keyword");
        assert!(manager.matches("category-ads", "tracker.adserver.com"), 
            "Should match ads domain with .adserver.com suffix");
        assert!(!manager.matches("category-ads", "www.google.com"), 
            "Should not match non-ads domain");
    }
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
    /// use kixdns::geosite::GeoSiteManager;
    /// let mut manager = GeoSiteManager::new(10000, 3600);
    /// let count = manager.load_from_v2ray_file("geosite.json").unwrap();
    /// println!("Loaded {} GeoSite entries", count);
    /// ```
    pub fn load_from_v2ray_file<P: AsRef<Path>>(&mut self, path: P) -> anyhow::Result<usize> {
        // 读取文件内容 / Read file content
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("read geosite file: {}", path.as_ref().display()))?;
        
        // 解析 JSON / Parse JSON
        let v2ray_data: V2RayGeoSiteList = serde_json::from_str(&content)
            .with_context(|| "parse V2Ray GeoSite JSON format")?;
        
        let count = v2ray_data.entries.len();
        
        // 转换为 GeoSiteEntry 并加载 / Convert to GeoSiteEntry and load
        let entries = self.convert_v2ray_to_entries(v2ray_data);
        
        // 逐个添加条目，保留现有数据 / Add entries one by one, preserving existing data
        for entry in entries {
            self.add_entry(entry);
        }
        
        Ok(count)
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
        let v2ray_data: V2RayGeoSiteList = serde_json::from_str(json_str)
            .with_context(|| "parse V2Ray GeoSite JSON format")?;
        
        let count = v2ray_data.entries.len();
        
        let entries = self.convert_v2ray_to_entries(v2ray_data);
        
        // 逐个添加条目，保留现有数据 / Add entries one by one, preserving existing data
        for entry in entries {
            self.add_entry(entry);
        }
        
        Ok(count)
    }
    
    /// 转换 V2Ray 格式为 GeoSiteEntry 列表 / Convert V2Ray format to GeoSiteEntry list
    fn convert_v2ray_to_entries(&self, v2ray_data: V2RayGeoSiteList) -> Vec<GeoSiteEntry> {
        v2ray_data.entries.into_iter().map(|v2ray_entry| {
            // 将域名列表转换为 DomainMatcher 列表
            // Convert domain list to DomainMatcher list
            let matchers = v2ray_entry.domains.into_iter().map(|domain| {
                // 根据域名格式选择合适的匹配器
                // Select appropriate matcher based on domain format
                if domain.starts_with("regexp:") {
                    // 正则匹配器 / Regex matcher
                    let pattern = domain.trim_start_matches("regexp:");
                    DomainMatcher::Regex(
                        Regex::new(pattern).unwrap_or_else(|_| Regex::new(r"^$").unwrap())
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
                            Regex::new(&format!("^{}$", pattern)).unwrap_or_else(|_| Regex::new(r"^$").unwrap())
                        )
                    } else {
                        DomainMatcher::Suffix(domain)
                    }
                }
            }).collect();
            
            GeoSiteEntry {
                tag: v2ray_entry.tag,
                matchers,
            }
        }).collect()
    }
}

/// 启动 GeoSite 数据文件热重载监控 / Start GeoSite data file hot-reload monitoring
/// 
/// # 参数 / Parameters
/// - `paths`: GeoSite 数据文件路径列表 / GeoSite data file path list
/// - `manager`: GeoSiteManager 实例（通过 Arc 共享）/ GeoSiteManager instance (shared via Arc)
pub fn spawn_geosite_watcher(paths: Vec<PathBuf>, manager: Arc<std::sync::Mutex<GeoSiteManager>>) {
    if paths.is_empty() {
        return;
    }

    // 使用阻塞线程持有watcher，避免异步生命周期问题
    // Use blocking thread to hold watcher, avoiding async lifetime issues
    thread::spawn(move || {
        if let Err(err) = run_geosite_watcher(paths, manager) {
            warn!(target = "geosite_watcher", error = %err, "GeoSite watcher exited with error");
        }
    });
}

/// 运行 GeoSite watcher / Run GeoSite watcher
fn run_geosite_watcher(
    paths: Vec<PathBuf>,
    manager: Arc<std::sync::Mutex<GeoSiteManager>>,
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
                
                // 简单的重试机制来处理文件写入竞争 / Simple retry mechanism to handle file write races
                let mut retries = 5;
                while retries > 0 {
                    match std::fs::read_to_string(path)
                        .with_context(|| format!("read GeoSite file: {}", path.display()))
                        .and_then(|json_str| {
                            serde_json::from_str::<V2RayGeoSiteList>(&json_str)
                                .with_context(|| "parse V2Ray GeoSite JSON format")
                        })
                    {
                        Ok(v2ray_data) => {
                            // 转换并重新加载数据 / Convert and reload data
                            let mut manager_guard = manager.lock().unwrap();
                            let entries = manager_guard.convert_v2ray_to_entries(v2ray_data);
                            let loaded_count = entries.len();
                            manager_guard.reload(entries);
                            
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

