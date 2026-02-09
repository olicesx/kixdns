# KixDNS 配置编辑器

一个可视化的 Web 配置编辑器，用于编辑 KixDNS 的 pipeline.json 配置文件。

## 功能特性

### 核心功能

- ✅ **可视化配置编辑**: 无需手写 JSON，通过表单界面配置所有设置
- ✅ **实时预览**: 左侧编辑，右侧实时显示 JSON 预览
- ✅ **流程图生成**: 自动生成 Mermaid 流程图，可视化配置逻辑
- ✅ **导入/导出**: 支持导入现有配置文件，导出配置为 JSON

### 新增功能

#### GeoIP 配置支持

- **MMDB 文件路径配置**: 指定 MaxMind GeoLite2-Country.mmdb 文件路径
- **延迟加载**: 只在配置使用 GeoIP 时才加载 MMDB 文件
- **缓存配置**: 配置 GeoIP 查询结果的缓存容量和 TTL
- **匹配器支持**: 
  - GeoIP Country 匹配器（按国家代码匹配）
  - GeoIP Private 匹配器（匹配私有 IP 地址）

#### GeoSite 配置支持

- **多文件支持**: 支持配置多个 GeoSite 数据文件（.dat 或 .json 格式）
- **按需加载**: 只在配置使用 GeoSite 时才加载数据文件
- **选择性加载**: 只加载配置中使用的 GeoSite tags
- **匹配器支持**:
  - GeoSite 匹配器（匹配域名分类）
  - GeoSite Not 匹配器（排除域名分类）

#### 调用语法支持

**GeoSite 调用语法**:
```json
{ "type": "geo_site", "value": "geosite:cn" }
```

**GeoIP 调用语法**:
```json
{ "type": "geoip_country", "country_codes": "geoip:CN" }
```

## 使用方法

### 1. 打开配置编辑器

在浏览器中打开 `tools/config_editor.html`

### 2. 配置 GeoIP

在"全局设置"卡片中：

1. 找到"GeoIP 配置"部分
2. 输入 MMDB 文件路径（如 `GeoLite2-Country.mmdb`）
3. 配置缓存容量（默认 10000）和 TTL（默认 3600 秒）

### 3. 配置 GeoSite

在"全局设置"卡片中：

1. 找到 "GeoSite 配置"部分
2. 点击"+ 添加文件"按钮
3. 输入 GeoSite 数据文件路径（如 `geosite.dat`）
4. 可以添加多个文件

### 4. 添加匹配器

在 Pipeline 规则中：

1. 选择匹配器类型：
   - `geo_site`: GeoSite 分类匹配
   - `geo_site_not`: GeoSite 否定匹配
   - `geoip_country`: GeoIP 国家匹配
   - `geoip_private`: GeoIP 私有 IP 匹配

2. 输入匹配值：
   - GeoSite: 输入 tag 名称（如 `cn`, `google`）
   - GeoIP Country: 输入国家代码（如 `CN`, `US`）

### 5. 下载配置

点击"下载 JSON"按钮，保存配置文件

### 6. 应用配置

```bash
kixdns --config /path/to/pipeline.json
```

## 上游传输协议支持

配置编辑器的 `forward` 动作已支持以下传输：

- `udp` / `tcp` / `tcp_udp`
- `doh`（DNS over HTTPS）
- `dot`（DNS over TLS）
- `doq`（DNS over QUIC）

### Transport 字段省略规则

**当 `upstream` 包含协议前缀时，`transport` 字段可以省略**：

```json
{
  "actions": [
    {
      "type": "forward",
      "upstream": "doq://223.5.5.5:853?0rtt=false"
      // transport 字段可以省略，会自动从 upstream URL 推断
    },
    {
      "type": "forward",
      "upstream": "doh://dns.google/dns-query"
      // transport 字段可以省略
    },
    {
      "type": "forward",
      "upstream": "8.8.8.8:53",
      "transport": "udp"
      // 没有 URL 前缀时，需要指定 transport（默认 udp）
    }
  ]
}
```

**优先级**：URL 协议前缀 > `transport` 字段 > 默认值 (udp)

### 支持的 URL 前缀

| 前缀 | 传输协议 | 别名 |
|---|---|---|
| `udp://` | UDP | - |
| `tcp://` | TCP | - |
| `tcp+udp://` / `udp+tcp://` | TCP+UDP 并发 | - |
| `doh://` | DoH | `https://` |
| `dot://` | DoT | `tls://` |
| `doq://` | DoQ | `quic://` |

### DoQ 0-RTT 每上游单独配置

配置编辑器新增以下字段：

- `doh_pool_size`：DoH 每个上游最大空闲连接数（默认 8）
- `dot_pool_size`：DoT 连接池大小（默认 64）
- `doq_pool_size`：DoQ 连接池大小（默认 16）
- `doq_connection_idle_timeout_seconds`：DoQ 空闲超时（默认 60）
- `doq_keepalive_interval_ms`：DoQ keepalive 间隔（默认 15000）
- `doq_enable_0rtt`：是否启用 DoQ 0-RTT（默认 true，自动检测并回退）

**DoQ 0-RTT 自动回退与缓存**：

系统会自动检测服务器是否支持 0-RTT，并缓存检测结果：
- 首次连接时尝试 0-RTT（默认启用）
- 如果超时或被拒绝，自动禁用该上游的 0-RTT
- 检测结果缓存在进程生命周期内，直到重启
- 配置重载时保持缓存状态（连接池不重建）
- 无需手动配置，系统自动优化

**缓存机制**：
- 每个上游独立维护 0-RTT 支持状态
- 状态存储在 `DoqMuxClient` 中，使用 `AtomicBool` 标记
- 配置重载时连接池保持不变，缓存状态持久
- 重启服务时清空所有缓存，重新检测

**DoQ 0-RTT 每上游单独配置**（可选）：

可以通过 URL 查询参数为每个 DoQ upstream 单独配置 0-RTT，覆盖全局设置：

```json
{
  "actions": [
    {
      "type": "forward",
      "upstream": "doq://223.5.5.5:853"
      // 系统自动检测并禁用不支持的 0-RTT，无需手动配置
    },
    {
      "type": "forward",
      "upstream": "doq://dns.google:853?0rtt=false"
      // 可选：强制禁用 0-RTT（覆盖全局设置）
    },
    {
      "type": "forward",
      "upstream": "doq://cloudflare-dns.com:853?0rtt=true"
      // 可选：强制启用 0-RTT（即使自动检测禁用了）
    }
  ]
}
```

支持的参数值：
- `0rtt=true` 或 `0rtt=1` 或 `0rtt=yes` 或 `0rtt=on`：强制启用 0-RTT
- `0rtt=false` 或 `0rtt=0` 或 `0rtt=no` 或 `0rtt=off`：强制禁用 0-RTT
- 未指定：使用全局 `doq_enable_0rtt` 设置

### RFC 8767 过期缓存 (Serve Stale)

当上游 DNS 服务器不可用时，RFC 8767 允许返回已过期的缓存记录而不是 SERVFAIL，从而提升 DNS 弹性。
设置对齐 Unbound 的 Serve Expired 配置。

- `serve_stale`：是否启用过期缓存（默认 false）。对应 Unbound `serve-expired`
- `serve_stale_ttl`：过期缓存响应的 TTL（秒，默认 30）。对应 Unbound `serve-expired-reply-ttl`
- `serve_stale_expire_ttl`：缓存过期后可服务的最大时间窗口（秒，默认 86400）。0=无限制。对应 Unbound `serve-expired-ttl`
- `serve_stale_ttl_reset`：每次返回过期数据时重置过期时间窗口（默认 true）。对应 Unbound `serve-expired-ttl-reset`
- `serve_stale_client_timeout_ms`：返回过期数据前尝试上游查询的时间（毫秒，默认 0）。对应 Unbound `serve-expired-client-timeout`
  - 0 = 立即返回过期缓存（乐观模式），后台刷新
  - \>0 = 先尝试上游查询，超时后返回过期缓存

工作原理：
1. 缓存条目 TTL 过期后，仍保留在 moka 缓存中（受 `cache_max_ttl` 限制绝对生存时间，`serve_stale_expire_ttl` 限制过期窗口）
2. `client_timeout_ms=0`（乐观模式）：TTL 过期后立即返回 stale 数据 + 后台异步刷新
3. `client_timeout_ms>0`：先尝试上游查询等待 N 毫秒，如果在超时内获得新鲜数据则返回新鲜数据，否则返回 stale 数据
4. 上游查询失败（无论 client_timeout 设置）时，返回过期缓存而非 SERVFAIL
5. `serve_stale_ttl_reset=true` 时，每次返回 stale 数据都会重置过期计时器，确保频繁访问的域名不会因 `serve_stale_expire_ttl` 超时

## 配置示例

### 示例 1：国内网站分流

```json
{
  "settings": {
    "geoip_db_path": "GeoLite2-Country.mmdb",
    "geosite_data_paths": ["geosite.dat"]
  },
  "pipeline_select": [
    {
      "pipeline": "domestic",
      "matchers": [
        { "type": "geo_site", "value": "cn" }
      ]
    }
  ],
  "pipelines": [
    {
      "id": "domestic",
      "rules": [
        {
          "name": "china_sites",
          "matchers": [
            { "type": "geo_site", "value": "cn" }
          ],
          "actions": [
            { "type": "forward", "upstream": "114.114.114.114:53" }
          ]
        }
      ]
    }
  ]
}
```

### 示例 2：按客户端 IP 分流

```json
{
  "settings": {
    "geoip_db_path": "GeoLite2-Country.mmdb"
  },
  "pipelines": [
    {
      "id": "china",
      "rules": [
        {
          "name": "china_ip",
          "matchers": [
            { "type": "geoip_country", "country_codes": "CN" }
          ],
          "actions": [
            { "type": "forward", "upstream": "114.114.114.114:53" }
          ]
        }
      ]
    }
  ]
}
```

## 技术细节

### 配置格式

配置编辑器生成的 JSON 格式符合 KixDNS 的配置规范：

- **版本**: `version` 字段标识配置版本
- **全局设置**: `settings` 对象包含所有全局配置
- **Pipeline 选择**: `pipeline_select` 数组定义分流规则
- **Pipeline**: `pipelines` 数组定义处理流程

### 字段映射

配置编辑器中的字段名与 Rust 代码中的字段名完全对应：

- `geoip_db_path` → `GlobalSettings::geoip_db_path`
- `geosite_data_paths` → `GlobalSettings::geosite_data_paths`
- `geoip_cache_capacity` → `GlobalSettings::geoip_cache_capacity`
- `geoip_cache_ttl` → `GlobalSettings::geoip_cache_ttl`

### 匹配器类型

配置编辑器中的匹配器类型使用 snake_case 格式：

- `geo_site` → `Matcher::GeoSite`
- `geo_site_not` → `Matcher::GeoSiteNot`
- `geoip_country` → `Matcher::GeoipCountry`
- `geoip_private` → `Matcher::GeoipPrivate`

## 注意事项

1. **文件路径**:
   - 支持相对路径和绝对路径
   - 相对路径相对于 KixDNS 的工作目录

2. **延迟加载**:
   - GeoIP MMDB 只在配置使用 GeoIP 匹配器时才加载
   - GeoSite .dat 文件只在配置使用 GeoSite 匹配器时才加载
   - 如果配置中不使用这些匹配器，文件不会被加载

3. **默认值**:
   - 不设置默认的 `geoip.mmdb` 或 `geosite.dat`
   - 必须在配置中明确指定文件路径

4. **调用语法**:
   - 调用语法是实验性功能
   - 标准格式和调用语法在功能上完全相同
   - 调用语法提供了一种更简洁的写法

## 相关文档

- [配置编辑器使用指南](config_editor_guide.md)
- [GeoIP 延迟加载分析](geoip_partial_loading_analysis.md)
- [缓存机制分析](caching_analysis.md)
- [KixDNS README](../README.md)
