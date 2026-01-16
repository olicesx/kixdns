# DNS 预取功能集成指南

本文档说明如何将 DNS 预取功能集成到 KixDNS 项目中。

## 📋 目录

1. [功能概述](#功能概述)
2. [RFC 参考](#rfc-参考)
3. [集成步骤](#集成步骤)
4. [配置说明](#配置说明)
5. [性能优化](#性能优化)
6. [监控与调试](#监控与调试)

---

## 功能概述

### 什么是 DNS 预取？

DNS 预取（DNS Prefetching）是一种优化技术，在用户实际请求域名之前预先解析 DNS 记录。这样可以：

- **降低延迟**：缓存命中时直接返回，无需等待上游查询
- **减少上游负载**：合并重复查询
- **提升用户体验**：响应更快

### 相关 RFC 标准

| RFC | 标题 | 相关章节 | 说明 |
|-----|------|----------|------|
| RFC 1034 | Domain Names - Concepts and Facilities | 4.3.3 | 缓存策略与 TTL 处理 |
| RFC 1035 | Domain Names - Implementation | 7 | 缓存实现建议 |
| RFC 8499 | DNS Terminology | 7 | 预取术语定义 |

### 实现特性

✅ **热度统计**：自动识别高频查询域名  
✅ **智能预取**：在缓存即将过期时主动刷新  
✅ **连接预热**：启动时预建立上游连接  
✅ **可配置**：灵活的配置选项  
✅ **低开销**：异步执行，不影响主流程  

---

## 集成步骤

### 步骤 1: 添加模块声明

在 `src/lib.rs` 中添加：

```rust
pub mod prefetch;
```

### 步骤 2: 更新配置结构

在 `src/config.rs` 中添加预取配置：

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct PrefetchSettings {
    /// 是否启用预取
    #[serde(default = "default_prefetch_enabled")]
    pub prefetch_enabled: bool,
    
    /// 热度阈值（访问次数）
    #[serde(default = "default_prefetch_hot_threshold")]
    pub prefetch_hot_threshold: u64,
    
    /// TTL 剩余比例阈值（0-1）
    #[serde(default = "default_prefetch_ttl_ratio")]
    pub prefetch_ttl_ratio: f64,
    
    /// 预取并发数
    #[serde(default = "default_prefetch_concurrency")]
    pub prefetch_concurrency: usize,
    
    /// 预取最小间隔（秒）
    #[serde(default = "default_prefetch_min_interval")]
    pub prefetch_min_interval_secs: u64,
}

// 默认值函数
fn default_prefetch_enabled() -> bool { true }
fn default_prefetch_hot_threshold() -> u64 { 10 }
fn default_prefetch_ttl_ratio() -> f64 { 0.3 }
fn default_prefetch_concurrency() -> usize { 5 }
fn default_prefetch_min_interval_secs() -> u64 { 30 }

// 在 GlobalSettings 中添加
#[derive(Debug, Clone, Deserialize)]
pub struct GlobalSettings {
    // ... 现有字段 ...
    
    /// 预取配置
    #[serde(default)]
    pub prefetch: PrefetchSettings,
}
```

### 步骤 3: 集成到 Engine

在 `src/engine.rs` 中集成预取管理器：

```rust
use crate::prefetch::{PrefetchManager, PrefetchConfig};

pub struct Engine {
    // ... 现有字段 ...
    
    // 预取管理器
    prefetch_manager: Arc<PrefetchManager>,
}

impl Engine {
    pub fn new(cfg: RuntimePipelineConfig, listener_label: String) -> Self {
        // ... 现有代码 ...
        
        // 创建预取管理器
        let prefetch_config = PrefetchConfig {
            enabled: cfg.settings.prefetch.prefetch_enabled,
            hot_threshold: cfg.settings.prefetch.prefetch_hot_threshold,
            ttl_ratio: cfg.settings.prefetch.prefetch_ttl_ratio,
            concurrency: cfg.settings.prefetch.prefetch_concurrency,
            min_interval: Duration::from_secs(
                cfg.settings.prefetch.prefetch_min_interval_secs
            ),
        };
        let prefetch_manager = Arc::new(PrefetchManager::new(prefetch_config));
        
        Self {
            // ... 现有字段 ...
            prefetch_manager,
        }
    }
    
    // 在缓存命中时记录访问
    fn handle_cache_hit(&self, hash: u64, entry: &CacheEntry, ttl_secs: u64) {
        // 记录访问以进行热度统计
        self.prefetch_manager.record_access(hash, entry, ttl_secs);
        
        // ... 现有缓存命中处理 ...
    }
}
```

### 步骤 4: 更新配置编辑器

在 `tools/config_editor.html` 中添加预取配置 UI：

```html
<!-- 在高级配置部分添加 -->
<hr>
<h6 class="fw-bold mb-2 text-info">DNS 预取配置 (Prefetch)</h6>
<div class="row g-3">
    <div class="col-md-3">
        <label class="form-label">启用预取</label>
        <div class="form-check form-switch">
            <input class="form-check-input" type="checkbox" 
                   v-model="config.settings.prefetch.prefetch_enabled">
            <label class="form-check-label">启用</label>
        </div>
    </div>
    <div class="col-md-3">
        <label class="form-label">热度阈值</label>
        <input type="number" class="form-control" 
               v-model.number="config.settings.prefetch.prefetch_hot_threshold"
               placeholder="10">
        <div class="form-text small">访问次数超过此值触发预取</div>
    </div>
    <div class="col-md-3">
        <label class="form-label">TTL 比例</label>
        <input type="number" class="form-control" 
               v-model.number="config.settings.prefetch.prefetch_ttl_ratio"
               step="0.1" min="0" max="1" placeholder="0.3">
        <div class="form-text small">剩余 TTL 比例阈值</div>
    </div>
    <div class="col-md-3">
        <label class="form-label">并发数</label>
        <input type="number" class="form-control" 
               v-model.number="config.settings.prefetch.prefetch_concurrency"
               min="1" max="20" placeholder="5">
        <div class="form-text small">同时进行的预取任务数</div>
    </div>
</div>
```

### 步骤 5: 更新默认配置

在配置编辑器的默认配置中添加：

```javascript
prefetch: {
    prefetch_enabled: true,
    prefetch_hot_threshold: 10,
    prefetch_ttl_ratio: 0.3,
    prefetch_concurrency: 5,
    prefetch_min_interval_secs: 30
}
```

---

## 配置说明

### 配置参数详解

| 参数 | 类型 | 默认值 | 说明 |
|-----|------|--------|------|
| `prefetch_enabled` | bool | true | 是否启用预取功能 |
| `prefetch_hot_threshold` | u64 | 10 | 热度阈值，访问次数超过此值触发预取 |
| `prefetch_ttl_ratio` | f64 | 0.3 | TTL 剩余比例，0-1 之间 |
| `prefetch_concurrency` | usize | 5 | 预取并发数，控制同时进行的预取任务 |
| `prefetch_min_interval_secs` | u64 | 30 | 最小预取间隔（秒），避免频繁预取 |

### 推荐配置场景

#### 场景 1: 高流量生产环境

```json
{
  "prefetch": {
    "prefetch_enabled": true,
    "prefetch_hot_threshold": 5,
    "prefetch_ttl_ratio": 0.5,
    "prefetch_concurrency": 10,
    "prefetch_min_interval_secs": 20
  }
}
```

**说明**：更激进的预取策略，适合高并发场景。

#### 场景 2: 低延迟优化

```json
{
  "prefetch": {
    "prefetch_enabled": true,
    "prefetch_hot_threshold": 3,
    "prefetch_ttl_ratio": 0.7,
    "prefetch_concurrency": 15,
    "prefetch_min_interval_secs": 15
  }
}
```

**说明**：最低延迟配置，预取更频繁。

#### 场景 3: 资源受限环境

```json
{
  "prefetch": {
    "prefetch_enabled": true,
    "prefetch_hot_threshold": 20,
    "prefetch_ttl_ratio": 0.2,
    "prefetch_concurrency": 2,
    "prefetch_min_interval_secs": 60
  }
}
```

**说明**：保守配置，减少资源消耗。

---

## 性能优化

### 预取效果评估

#### 指标监控

```rust
// 在 PrefetchManager 中添加统计
pub struct PrefetchMetrics {
    pub total_prefetches: AtomicU64,
    pub successful_prefetches: AtomicU64,
    pub cache_hits_from_prefetch: AtomicU64,
    pub avg_prefetch_latency: AtomicU64,
}
```

#### 预期收益

- **缓存命中率提升**: 10-30%
- **平均延迟降低**: 20-50ms（P99）
- **上游查询减少**: 15-40%

### 性能调优建议

1. **热度阈值调整**
   - 观察访问日志，识别真正的热点域名
   - 根据实际流量模式调整阈值

2. **TTL 比例优化**
   - 短 TTL（< 60s）：使用较高比例（0.5-0.7）
   - 长 TTL（> 300s）：使用较低比例（0.2-0.3）

3. **并发数控制**
   - CPU 密集型：降低并发（2-5）
   - IO 密集型：提高并发（10-20）

4. **内存管理**
   - 限制热度统计表大小
   - 定期清理冷门域名记录

---

## 监控与调试

### 日志级别

```rust
// 启用预取调试日志
tracing::info!(target = "prefetch", qname = %qname, "Prefetching domain");
tracing::debug!(target = "prefetch", hash = %hash, "Cache hit from prefetch");
tracing::warn!(target = "prefetch", error = %e, "Prefetch failed");
```

### 指标导出

```rust
// 暴露 Prometheus 指标
use prometheus::{IntCounter, Histogram};

lazy_static! {
    static ref PREFETCH_TOTAL: IntCounter = register_int_counter!(
        "kixdns_prefetch_total",
        "Total number of prefetch attempts"
    ).unwrap();
    
    static ref PREFETCH_LATENCY: Histogram = register_histogram!(
        "kixdns_prefetch_latency_seconds",
        "Prefetch operation latency"
    ).unwrap();
}
```

### 调试命令

```bash
# 查看预取统计
curl http://localhost:9090/metrics | grep prefetch

# 查看热度域名
curl http://localhost:9090/debug/prefetch/hot_domains

# 手动触发预取
curl -X POST http://localhost:9090/debug/prefetch/trigger \
  -H "Content-Type: application/json" \
  -d '{"qname": "example.com", "qtype": 1}'
```

---

## 常见问题

### Q1: 预取会增加上游负载吗？

**A**: 不会。预取只在缓存即将过期时执行，实际上减少了上游查询次数（通过合并重复请求）。

### Q2: 如何禁用预取？

**A**: 设置 `prefetch_enabled: false` 即可完全禁用。

### Q3: 预取会影响内存使用吗？

**A**: 影响很小。热度统计表只存储元数据，不存储实际的 DNS 响应。

### Q4: 预取会泄露隐私吗？

**A**: 不会。预取只基于实际的查询历史，不会主动查询用户未访问的域名。

---

## 下一步优化

### 高级特性

1. **智能预取策略**
   - 基于时间段的预取（工作时间 vs 非工作时间）
   - 基于用户行为的预取（移动端 vs 桌面端）

2. **关联域名预取**
   - 查询 A 记录时预取 AAAA 记录
   - 查询主域名时预取 CDN 域名

3. **分布式预取**
   - 多实例协同预取
   - 预取结果共享

4. **机器学习优化**
   - 预测下一个查询的域名
   - 动态调整预取策略

---

## 参考资料

- [RFC 1034 - Domain Names - Concepts and Facilities](https://datatracker.ietf.org/doc/html/rfc1034)
- [RFC 1035 - Domain Names - Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 8499 - DNS Terminology](https://datatracker.ietf.org/doc/html/rfc8499)
- [Chrome DNS Prefetching](https://developer.chrome.com/blog/chrome-43-beta-dns-prefetching/)
- [Firefox DNS Prefetching](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control)

---

## 贡献

欢迎提交 Issue 和 Pull Request 来改进预取功能！

---

**文档版本**: 1.0  
**最后更新**: 2026-01-16  
**维护者**: KixDNS Team
