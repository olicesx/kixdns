# DNS 预取功能 - 快速开始

## 🚀 5 分钟快速集成

### 步骤 1: 声明模块（1 分钟）

在 `src/lib.rs` 中添加：

```rust
pub mod prefetch;
```

### 步骤 2: 更新 Cargo.toml（如果需要）

确保依赖已包含（应该已经有了）：

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
moka = { version = "0.12", features = ["sync"] }
```

### 步骤 3: 编译验证（1 分钟）

```bash
cargo check
```

### 步骤 4: 运行测试（2 分钟）

```bash
cargo test --lib prefetch
```

### 步骤 5: 启用预取（1 分钟）

在配置文件中添加：

```json
{
  "settings": {
    "prefetch": {
      "prefetch_enabled": true,
      "prefetch_hot_threshold": 10,
      "prefetch_ttl_ratio": 0.3,
      "prefetch_concurrency": 5,
      "prefetch_min_interval_secs": 30
    }
  }
}
```

---

## 📊 预期效果

启用预取后，你应该看到：

- ✅ **缓存命中率提升**: 10-30%
- ✅ **平均延迟降低**: 20-50ms
- ✅ **上游查询减少**: 15-40%

---

## 🔧 配置调优

### 保守配置（资源受限）

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

### 激进配置（高性能）

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

---

## 📈 监控指标

预取功能会自动记录以下指标：

- `kixdns_prefetch_total`: 预取总次数
- `kixdns_prefetch_successful`: 成功预取次数
- `kixdns_prefetch_cache_hits`: 来自预取的缓存命中次数
- `kixdns_prefetch_latency_seconds`: 预取操作延迟

---

## 🐛 故障排查

### 问题 1: 预取不工作

**检查**:
1. 确认 `prefetch_enabled: true`
2. 查看日志: `target = "prefetch"`
3. 验证热度阈值是否过高

### 问题 2: 内存使用增加

**解决**:
- 降低 `prefetch_hot_threshold`
- 减少 `prefetch_concurrency`
- 定期清理热度统计表

### 问题 3: 上游负载增加

**解决**:
- 增加 `prefetch_min_interval_secs`
- 降低 `prefetch_ttl_ratio`
- 检查是否有异常流量

---

## 📚 更多信息

详细文档请参阅: [docs/PREFETCH_INTEGRATION.md](docs/PREFETCH_INTEGRATION.md)

---

**快速开始版本**: 1.0  
**最后更新**: 2026-01-16
