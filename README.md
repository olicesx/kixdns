# KixDNS

**注意：本项目完全由 AI 构建（内容、文档与初始实现均由 AI 生成）。**

KixDNS 是用 Rust 开发的高性能、可扩展 DNS 服务器，面向低延迟、高并发以及复杂路由场景。 

## 主要特性

### 🚀 高性能
- **零拷贝网络**：使用 `BytesMut` 实现 UDP 收包的零拷贝处理，尽量减少内存复制
- **延迟解析**：实现"延迟请求解析"，普通转发场景避免对包进行完整反序列化，降低开销
- **轻量化响应解析**：在不需要完整解析时快速扫描上游响应以提取 `RCODE` 与最小 TTL（零分配）
- **快速哈希**：内部数据结构采用 `rustc-hash` 以获得更快的哈希性能
- **高并发**：基于 `tokio` 异步 IO，使用 `DashMap` / `moka` 等并发数据结构进行状态管理
- **自适应流控**：基于上游延迟动态调整并发限制（`PermitManager`），防止上游过载
- **SO_REUSEPORT**：在 Unix 系统上支持多 worker 共享端口，充分利用多核
- **双 Socket 架构**：IPv4/IPv6 分离 Socket，兼容 OpenBSD 等系统

### 🔧 灵活架构
- **Pipeline 选择规则**：支持基于监听器标签、客户端 IP、域名、QCLASS、EDNS、GeoSite 等多维路由
- **匹配器运算符**：支持 AND、OR、AND_NOT、OR_NOT、NOT 逻辑组合
- **两阶段处理**：请求阶段匹配 + 响应阶段匹配，支持二次决策和动作
- **监听器标签**：同一实例可为不同标签提供不同 Pipeline
- **上游传输选项**：上游支持 UDP/TCP/DoH/DoT/DoQ 传输协议选择
- **URL 协议前缀**：支持 `udp://`、`tcp://`、`doh://`、`dot://`、`doq://` 等前缀自动识别

### 💾 缓存与去重
- **内存缓存**：集成高性能缓存（`moka`），支持可配置容量和最大 TTL
- **智能 TTL**：遵循上游 TTL，同步支持可配置的最小 TTL
- **Singleflight 去重**：使用 `tokio::watch::channel` 实现零分配的并发去重，防止缓存击穿
- **后台刷新**：TTL 即将过期时自动触发后台刷新，使用 AtomicU64 bitmap 去重
- **Serve Stale (RFC 8767)**：上游不可用时返回过期缓存，提升服务弹性

### 🌍 GeoIP 支持
- **MaxMind GeoIP 数据库集成**：支持 MMDB 格式的 GeoIP2/GeoLite2 数据库
- **国家代码匹配**：根据客户端 IP 的国家代码进行路由（如 CN、US、JP）
- **私有 IP 检测**：自动识别内网/私有 IP 地址段
- **高性能缓存**：可配置的查询结果缓存，减少数据库查询开销
- **数据库热重载**：支持数据库文件更新后自动重新加载
- **懒加载机制**：仅在配置中使用 GeoIP 匹配器时才加载数据库

### 🎯 GeoSite 支持
- **域名分类匹配**：支持基于域名分类的路由决策（如 cn、google、category-ads）
- **V2Ray 格式支持**：兼容 V2Ray domain-list-community 数据格式
- **多种匹配模式**：完全匹配（`domain:`）、后缀匹配（`.`）、关键词匹配（`keyword:`）、正则匹配（`regexp:`）
- **后缀索引优化**：O(1) 查找性能，支持大规模域名列表
- **数据热重载**：支持 GeoSite 数据文件更新后自动重新加载
- **正向和否定匹配**：支持 `geosite` 和 `geosite_not` 两种匹配器

### 🔌 DNS-over-QUIC (DoQ)
- **0-RTT 自动检测**：首次连接尝试 0-RTT，服务器拒绝时自动禁用并缓存结果
- **零分配缓存**：使用 `AtomicBool` 实现零开销的检测结果缓存
- **配置热加载兼容**：配置重载时保留检测结果，连接池不会重建
- **SNI 强制支持**：IP 上游必须显式设置 `sni` 参数以满足 RFC 9250
- **RFC 9250 合规**：强制 message-id=0 并恢复客户端 transaction ID

### 🛡️ DNS 污染响应过滤
- **响应阶段 IP 匹配**：支持 `response_answer_ip` 匹配器检测污染 IP
- **自动上游切换**：检测到污染响应时自动切换到备用上游重新查询
- **灵活降级策略**：支持 TCP fallback、多级上游兜底等策略

### 📊 监控与运维
- **配置热重载**：使用 `ArcSwap` 实现无锁的配置热重载，`notify` 监控文件变化
- **结构化日志**：基于 `tracing` 的 JSON 格式日志输出
- **自适应流控参数可配置**：可根据上游特性调整流控策略
- **WebSocket 诊断工具**：内置 `diagnose.html` 工具用于测试 DNS 查询
- **可视化配置编辑器**：内置 `config_editor.html` 用于生成和管理 Pipeline 配置

## 命令行参数

```
kixdns [OPTIONS]

OPTIONS:
  -c, --config <FILE>          配置文件路径 [默认: config/pipeline.json]
      --listener-label <LABEL> 监听器标签，用于 Pipeline 选择 [默认: default]
      --debug                  启用调试日志
      --udp-workers <NUM>      UDP worker 数量 [默认: CPU 核心数]
  -h, --help                   显示帮助信息
  -V, --version               显示版本信息
```

## 配置格式

### 配置结构

配置采用 JSON 格式，顶层结构如下：

```json
{
  "version": "1.0",
  "settings": { ... },
  "pipeline_select": [ ... ],
  "pipelines": [ ... ]
}
```

### GlobalSettings 配置项

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| min_ttl | uint | 0 | 最小 TTL (秒) |
| bind_udp | string | 0.0.0.0:5353 | UDP 监听地址 |
| bind_tcp | string | 0.0.0.0:5353 | TCP 监听地址 |
| cache_capacity | uint | 10000 | 缓存最大条目数 |
| cache_max_ttl | uint | 86400 | 缓存最大生存时间 (秒) |
| dashmap_shards | uint | 0 | DashMap 分片数 (0=自动) |
| default_upstream | string | 1.1.1.1:53 | 默认上游 DNS |
| upstream_timeout_ms | uint | 2000 | 上游超时 (毫秒) |
| response_jump_limit | uint | 10 | 响应 Pipeline 跳转上限 |
| udp_pool_size | uint | 64 | UDP 上游连接池大小 |
| tcp_pool_size | uint | 64 | TCP 上游连接池大小 |
| doh_pool_size | uint | 8 | DoH 每个上游最大空闲连接数 |
| dot_pool_size | uint | 64 | DoT 连接池大小 |
| doq_pool_size | uint | 16 | DoQ 连接池大小 |
| doq_connection_idle_timeout_seconds | uint | 60 | DoQ 空闲超时 (秒) |
| doq_keepalive_interval_ms | uint | 15000 | DoQ keepalive 间隔 (毫秒) |
| doq_enable_0rtt | bool | true | 启用 DoQ 0-RTT (自动检测并回退) |
| flow_control_initial_permits | uint | 500 | 流控初始 permits |
| flow_control_min_permits | uint | 100 | 流控最小 permits |
| flow_control_max_permits | uint | 800 | 流控最大 permits |
| flow_control_latency_threshold_ms | uint | 100 | 延迟告急阈值 (毫秒) |
| flow_control_adjustment_interval_secs | uint | 5 | 流控调整间隔 (秒) |
| cache_background_refresh | bool | false | 启用缓存后台刷新 |
| cache_refresh_threshold_percent | uint | 10 | 后台刷新阈值 (剩余 TTL 百分比) |
| cache_refresh_min_ttl | uint | 5 | 后台刷新最小 TTL (秒) |
| **serve_stale** | bool | false | 启用 RFC 8767 过期缓存 |
| **serve_stale_ttl** | uint | 30 | 过期缓存响应的 TTL (秒) |
| **serve_stale_expire_ttl** | uint | 86400 | 过期缓存最大时间窗口 (秒，0=无限制) |
| **serve_stale_ttl_reset** | bool | true | 每次返回过期数据时重置过期计时器 |
| **serve_stale_client_timeout_ms** | uint | 0 | 返回过期数据前尝试上游查询的时间 (毫秒) |
| **geoip_db_path** | string | null | GeoIP 数据库文件路径（MMDB 格式） |
| **geoip_cache_capacity** | uint | 10000 | GeoIP 查询结果缓存容量 |
| **geoip_cache_ttl** | uint | 3600 | GeoIP 查询结果缓存 TTL（秒） |
| **geosite_data_paths** | array | [] | GeoSite 数据文件路径列表（V2Ray 格式) |

### Pipeline 选择匹配器类型

用于 `pipeline_select` 中，决定请求进入哪个 Pipeline：

| 类型 | 参数 | 说明 |
|------|------|------|
| listener_label | value | 监听器标签匹配 |
| client_ip | cidr | 客户端 IP CIDR 匹配 |
| domain_suffix | value | 域名后缀匹配 |
| domain_regex | value | 域名正则匹配 |
| qclass | value | 查询 QCLASS 匹配 (IN/CH/HS) |
| edns_present | expect | EDNS 存在性检查 (true/false) |
| **geosite** | value | 域名分类匹配（如 cn、google） |
| **geosite_not** | value | 域名分类否定匹配 |
| any | - | 任意匹配 |

### 请求匹配器类型

用于 Pipeline 规则中，匹配请求阶段：

| 类型 | 参数 | 说明 |
|------|------|------|
| any | - | 任意匹配 |
| domain_suffix | value | 域名后缀匹配 |
| domain_regex | value | 域名正则匹配 |
| client_ip | cidr | 客户端 IP CIDR 匹配 |
| qclass | value | 查询 QCLASS 匹配 (IN/CH/HS) |
| edns_present | expect | EDNS 存在性检查 (true/false) |
| **geoip_country** | country_codes | 客户端 IP 国家代码匹配（如 CN、US） |
| **geoip_private** | expect | 客户端 IP 是否为私有 IP（内网） |
| **geosite** | value | 域名分类匹配（如 cn、google、category-ads） |
| **geosite_not** | value | 域名分类否定匹配（不在该分类的域名） |

### 响应匹配器类型

用于 Pipeline 规则的 `response_matchers` 中，匹配响应阶段：

| 类型 | 参数 | 说明 |
|------|------|------|
| upstream_equals | value | 上游字符串相等匹配 |
| request_domain_suffix | value | 请求域名后缀匹配 |
| request_domain_regex | value | 请求域名正则匹配 |
| response_upstream_ip | cidr | 响应上游 IP CIDR 匹配 |
| response_answer_ip | cidr | 响应 Answer 中 IP CIDR 匹配 |
| response_type | value | 响应记录类型匹配 (A/AAAA/CNAME 等) |
| response_rcode | value | 响应 RCode 匹配 (NOERROR/NXDOMAIN 等) |
| response_qclass | value | 响应 QCLASS 匹配 |
| response_edns_present | expect | 响应 EDNS 存在性检查 (true/false) |

### 动作类型

| 类型 | 参数 | 说明 |
|------|------|------|
| log | level, message | 记录日志 |
| static_response | rcode | 返回静态 RCode 响应 |
| static_ip_response | rcode, ips | 返回静态 IP 响应 |
| jump_to_pipeline | pipeline | 跳转到指定 Pipeline |
| allow | - | 终止匹配，使用默认上游/当前响应 |
| deny | - | 终止并返回 REFUSED |
| forward | upstream, transport | 转发到上游 (transport: udp/tcp/tcp_udp/doh/dot/doq，可省略) |
| continue | - | 继续匹配后续规则 |

**Transport 字段省略规则**：

- 当 `upstream` 包含协议前缀时，`transport` 字段可省略
- 支持的 URL 前缀：`udp://`、`tcp://`、`doh://`、`https://`、`dot://`、`tls://`、`doq://`、`quic://`
- 优先级：URL 协议前缀 > `transport` 字段 > 默认值 (udp)

示例：
```json
{ "type": "forward", "upstream": "doq://223.5.5.5:853?sni=dns.alidns.com&0rtt=false" }
{ "type": "forward", "upstream": "doh://dns.google/dns-query" }
{ "type": "forward", "upstream": "8.8.8.8:53", "transport": "tcp" }
```

### 匹配器运算符

匹配器支持逻辑运算符组合：

| 运算符 | 说明 |
|--------|------|
| and | 逻辑与 (默认) |
| or | 逻辑或 |
| and_not | 逻辑与非 |
| or_not | 逻辑或非 |
| not | 逻辑非 |

## 配置示例

### GeoIP 基于国家的路由

以下配置展示了如何使用 GeoIP 匹配器根据客户端 IP 的国家代码进行路由：

```json
{
  "version": "1.0",
  "settings": {
    "min_ttl": 30,
    "bind_udp": "0.0.0.0:5353",
    "default_upstream": "1.1.1.1:53",
    "geoip_db_path": "data/GeoLite2-Country.mmdb",
    "geoip_cache_capacity": 10000,
    "geoip_cache_ttl": 3600
  },
  "pipelines": [
    {
      "id": "china-domestic",
      "rules": [
        {
          "name": "china-clients",
          "matchers": [
            { "type": "geoip_country", "country_codes": ["CN"] }
          ],
          "actions": [
            { "type": "log", "level": "info" },
            { "type": "forward", "upstream": "223.5.5.5:53" }
          ]
        }
      ]
    },
    {
      "id": "international",
      "rules": [
        {
          "name": "non-china-clients",
          "matchers": [
            { "type": "geoip_country", "country_codes": ["US", "JP", "KR"] }
          ],
          "actions": [
            { "type": "forward", "upstream": "8.8.8.8:53" }
          ]
        }
      ]
    }
  ]
}
```

## 缓存与过期处理

### RFC 8767 过期缓存 (Serve Stale)

当上游 DNS 服务器不可用时，RFC 8767 允许返回已过期的缓存记录而不是 SERVFAIL，从而提升 DNS 弹性。设置对齐 Unbound 的 Serve Expired 配置。

**配置项**：

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| serve_stale | bool | false | 启用过期缓存 |
| serve_stale_ttl | uint | 30 | 过期缓存响应的 TTL (秒) |
| serve_stale_expire_ttl | uint | 86400 | 过期缓存最大时间窗口 (秒，0=无限制) |
| serve_stale_ttl_reset | bool | true | 每次返回过期数据时重置过期计时器 |
| serve_stale_client_timeout_ms | uint | 0 | 返回过期数据前尝试上游查询的时间 (毫秒) |

**工作模式**：

1. **乐观模式** (`client_timeout_ms=0`)：
   - TTL 过期后立即返回过期数据
   - 同时触发后台异步刷新
   - 适用于对延迟敏感的场景

2. **等待模式** (`client_timeout_ms>0`)：
   - TTL 过期后先尝试上游查询 N 毫秒
   - 如果在超时内获得新鲜数据则返回新鲜数据
   - 否则返回过期数据
   - 适用于对数据新鲜度敏感的场景

**示例配置**：

```json
{
  "settings": {
    "serve_stale": true,
    "serve_stale_ttl": 30,
    "serve_stale_expire_ttl": 86400,
    "serve_stale_ttl_reset": true,
    "serve_stale_client_timeout_ms": 0
  }
}
```

### 缓存后台刷新

启用后台刷新可以在缓存 TTL 即将过期时自动刷新，减少缓存未命中。

**配置项**：

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| cache_background_refresh | bool | false | 启用缓存后台刷新 |
| cache_refresh_threshold_percent | uint | 10 | 后台刷新阈值 (剩余 TTL 百分比) |
| cache_refresh_min_ttl | uint | 5 | 后台刷新最小 TTL (秒) |

**工作原理**：

- 当剩余 TTL 低于原始 TTL 的指定百分比时触发后台刷新
- 后台刷新使用 `skip_cache=true` 避免返回过期数据
- 刷新失败不影响现有缓存条目
- 防止 TTL 过短导致无限循环刷新

**示例配置**：

```json
{
  "settings": {
    "cache_background_refresh": true,
    "cache_refresh_threshold_percent": 10,
    "cache_refresh_min_ttl": 5
  }
}
```

### DoQ 传输协议

DoQ (DNS-over-QUIC) 是基于 QUIC 协议的 DNS 传输方式，提供更好的性能和安全性。

#### 0-RTT 自动检测

KixDNS 实现了智能的 0-RTT (Zero Round Trip Time) 自动检测机制：

- **默认启用**：`doq_enable_0rtt` 默认为 `true`
- **自动降级**：当服务器拒绝 0-RTT 连接时，自动禁用并缓存结果
- **零开销**：使用 `AtomicBool` 实现零分配的缓存机制
- **配置热加载**：配置重载时保留检测结果（连接池不会重建）

**工作原理**：

1. 首次连接尝试使用 0-RTT 加速
2. 如果服务器拒绝（返回 0-RTT rejected），自动禁用该上游的 0-RTT
3. 后续连接自动使用 1-RTT，避免请求丢失
4. 检测结果缓存在内存中，无需重复检测

**配置选项**：

```json
{
  "settings": {
    "doq_enable_0rtt": true,
    "doq_pool_size": 8
  }
}
```

**上游级别配置**：

可以通过 URL 查询参数为特定上游配置 0-RTT：

```json
{
  "actions": [
    {
      "type": "forward",
      "upstream": "doq://223.5.5.5:853?sni=dns.alidns.com&0rtt=false"
    }
  ]
}
```

当 DoQ 上游使用 IP（例如 `223.5.5.5`）时，必须显式设置 `sni` 参数；
否则会因为无法确定 TLS Server Name 而被拒绝。

**支持的查询参数**：

- `0rtt=true` - 强制启用 0-RTT
- `0rtt=false` - 强制禁用 0-RTT
- 未指定时使用全局 `doq_enable_0rtt` 设置

**传输协议前缀**：

支持以下协议前缀（可省略 `transport` 字段）：

- `udp://` - UDP
- `tcp://` - TCP
- `tcp+udp://` - TCP + UDP
- `doh://` 或 `https://` - DNS-over-HTTPS
- `dot://` 或 `tls://` - DNS-over-TLS
- `doq://` 或 `quic://` - DNS-over-QUIC

### GeoSite 域名分类路由

以下配置展示了如何使用 GeoSite 匹配器根据域名分类进行路由：

```json
{
  "version": "1.0",
  "settings": {
    "min_ttl": 30,
    "bind_udp": "0.0.0.0:5353",
    "default_upstream": "1.1.1.1:53",
    "geosite_data_paths": [
      "data/geosite-cn.json",
      "data/geosite-google.json"
    ]
  },
  "pipelines": [
    {
      "id": "cn-domains",
      "rules": [
        {
          "name": "china-domains",
          "matchers": [
            { "type": "geosite", "value": "cn" }
          ],
          "actions": [
            { "type": "log", "level": "info" },
            { "type": "forward", "upstream": "223.5.5.5:53" }
          ]
        }
      ]
    },
    {
      "id": "google-services",
      "rules": [
        {
          "name": "google-domains",
          "matchers": [
            { "type": "geosite", "value": "google" }
          ],
          "actions": [
            { "type": "forward", "upstream": "8.8.8.8:53", "transport": "tcp" }
          ]
        }
      ]
    },
    {
      "id": "block-ads",
      "rules": [
        {
          "name": "ad-block",
          "matchers": [
            { "type": "geosite", "value": "category-ads" }
          ],
          "actions": [
            { "type": "static_response", "rcode": "NXDOMAIN" }
          ]
        }
      ]
    }
  ]
}
```

### GeoSite 否定匹配

使用 `geosite_not` 匹配器来排除特定分类的域名：

```json
{
  "pipelines": [
    {
      "id": "non-cn-domains",
      "rules": [
        {
          "name": "exclude-china",
          "matchers": [
            { "type": "geosite_not", "value": "cn" }
          ],
          "actions": [
            { "type": "forward", "upstream": "8.8.8.8:53" }
          ]
        }
      ]
    }
  ]
}
```

### V2Ray GeoSite 数据格式

GeoSite 数据文件使用 V2Ray 格式（JSON）：

```json
{
  "entries": [
    {
      "tag": "cn",
      "domains": [
        "domain:example.com",
        "keyword:test",
        "regexp:^.*\\.example\\.com$",
        "full:www.example.com",
        ".example.com"
      ]
    }
  ]
}
```

**域名类型说明**：
- `domain:example.com` - 完全匹配
- `keyword:test` - 关键词匹配（包含 "test" 的域名）
- `regexp:^.*\\.example\\.com$` - 正则表达式匹配
- `full:www.example.com` - 完全匹配（与 domain: 相同）
- `.example.com` - 后缀匹配（推荐，性能最佳）

### DNS 污染响应过滤

以下配置展示了如何使用响应阶段匹配器来过滤 DNS 污染响应。当上游返回污染 IP（如 `127.0.0.0/8` 或 `0.0.0.0/8`）时，自动切换到备用上游重新查询：

```json
{
  "version": "1.0",
  "settings": {
    "min_ttl": 5,
    "bind_udp": "0.0.0.0:53",
    "bind_tcp": "0.0.0.0:53",
    "default_upstream": "223.5.5.5:53",
    "upstream_timeout_ms": 1500,
    "udp_pool_size": 128,
    "flow_control_latency_threshold_ms": 200,
    "flow_control_max_permits": 8000,
    "flow_control_min_permits": 1000,
    "flow_control_initial_permits": 5000
  },
  "pipeline_select": [
    {
      "pipeline": "过滤响应",
      "matchers": []
    }
  ],
  "pipelines": [
    {
      "id": "过滤响应",
      "rules": [
        {
          "name": "污染命中",
          "matchers": [{ "type": "any" }],
          "actions": [
            {
              "type": "forward",
              "upstream": "223.5.5.5:53",
              "transport": "udp"
            }
          ],
          "response_matchers": [
            {
              "type": "response_answer_ip",
              "cidr": "127.0.0.0/8,0.0.0.0/8"
            }
          ],
          "response_actions_on_match": [
            { "type": "continue" }
          ],
          "response_actions_on_miss": [
            { "type": "allow" }
          ]
        },
        {
          "name": "备用上游",
          "matchers": [{ "type": "any" }],
          "actions": [
            {
              "type": "forward",
              "upstream": "8.8.4.4:53",
              "transport": "tcp"
            }
          ],
          "response_matchers": [
            {
              "type": "response_upstream_ip",
              "cidr": "8.8.4.4/32"
            }
          ],
          "response_actions_on_match": [
            { "type": "allow" }
          ]
        }
      ]
    }
  ]
}
```

**工作原理**：
1. 第一条规则先向主上游 `223.5.5.5:53` 发起查询
2. 如果响应中包含污染 IP（`127.0.0.0/8` 或 `0.0.0.0/8`），执行 `continue` 继续下一条规则
3. 第二条规则通过 TCP 连接备用上游 `8.8.4.4:53` 重新查询，获取正确结果

### 完整配置示例

以下是 `config/pipeline.json` 的完整示例：

```json
{
  "version": "1.0",
  "settings": {
    "min_ttl": 30,
    "bind_udp": "0.0.0.0:5353",
    "bind_tcp": "0.0.0.0:5353",
    "default_upstream": "1.1.1.1:53",
    "upstream_timeout_ms": 2000
  },
  "pipeline_select": [
    {
      "pipeline": "internal_pipe",
      "matchers": [ { "type": "listener_label", "value": "edge-internal" } ]
    },
    {
      "pipeline": "internal_pipe",
      "matchers": [ { "type": "client_ip", "cidr": "10.0.0.0/8" } ]
    },
    {
      "pipeline": "large_tcp",
      "matchers": [ { "type": "domain_suffix", "value": ".large.example" } ]
    },
    {
      "pipeline": "regex_qclass_pipe",
      "matchers": [
        { "type": "domain_regex", "value": "(?i)\\bvideo\\.(example|test)\\." },
        { "type": "qclass", "value": "IN" }
      ]
    },
    {
      "pipeline": "main_inbound",
      "matchers": [ { "type": "domain_suffix", "value": ".internal" } ]
    }
  ],
  "pipelines": [
    {
      "id": "internal_pipe",
      "rules": [
        {
          "name": "internal_tcp_forward",
          "matchers": [ { "type": "any" } ],
          "actions": [
            { "type": "log", "level": "info" },
            { "type": "forward", "upstream": "10.0.0.53:53", "transport": "tcp" }
          ],
          "response_matchers": [
            { "type": "upstream_equals", "value": "10.0.0.53:53" },
            { "type": "response_rcode", "value": "NOERROR" }
          ]
        }
      ]
    },
    {
      "id": "large_tcp",
      "rules": [
        {
          "name": "large_tcp_forward",
          "matchers": [ { "type": "any" } ],
          "actions": [
            { "type": "log", "level": "info" },
            { "type": "forward", "upstream": "8.8.8.8:53", "transport": "tcp" }
          ],
          "response_matchers": [
            { "type": "response_rcode", "value": "NOERROR" }
          ]
        }
      ]
    },
    {
      "id": "regex_qclass_pipe",
      "rules": [
        {
          "name": "regex_edns_forward",
          "matchers": [
            { "type": "edns_present", "expect": true }
          ],
          "actions": [
            { "type": "forward", "upstream": "9.9.9.9:53", "transport": "udp" }
          ],
          "response_matchers": [
            { "type": "request_domain_regex", "value": "(?i)\\.video\\." },
            { "type": "response_qclass", "value": "IN" },
            { "type": "response_edns_present", "expect": true },
            { "type": "response_rcode", "value": "NOERROR" }
          ]
        }
      ]
    },
    {
      "id": "main_inbound",
      "rules": [
        {
          "name": "block_malware",
          "matchers": [
            { "type": "domain_suffix", "value": ".bad.example" }
          ],
          "actions": [
            { "type": "log", "level": "warn" },
            { "type": "static_response", "rcode": "NXDOMAIN" }
          ],
          "response_matchers": []
        },
        {
          "name": "internal_forward",
          "matchers": [
            { "type": "domain_suffix", "value": ".internal" },
            { "type": "client_ip", "cidr": "10.0.0.0/8" }
          ],
          "actions": [
            { "type": "log", "level": "info" },
            { "type": "forward", "upstream": "10.0.0.53:53" }
          ],
          "response_matchers": [
            { "type": "upstream_equals", "value": "10.0.0.53:53" },
            { "type": "request_domain_suffix", "value": ".internal" },
            { "type": "response_rcode", "value": "NOERROR" }
          ]
        },
        {
          "name": "default_forward",
          "matchers": [ { "type": "any" } ],
          "actions": [ { "type": "forward", "upstream": null, "transport": "udp" } ],
          "response_matchers": [
            { "type": "response_rcode", "value": "NOERROR" }
          ]
        }
      ]
    }
  ]
}
```

## 启动示例

### 本地构建

```bash
cargo build --release
```

### 直接运行

```bash
# 使用默认配置文件 config/pipeline.json
./target/release/kixdns

# 指定配置文件
./target/release/kixdns --config /etc/kixdns/pipeline.json

# 使用监听器标签
./target/release/kixdns --listener-label edge-internal
```

### 作为 systemd 服务

创建 unit 文件 `/etc/systemd/system/kixdns.service`：

```ini
[Unit]
Description=KixDNS
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kixdns --config /etc/kixdns/pipeline.json
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

部署步骤：

```bash
# 安装二进制
sudo install -m 0755 target/release/kixdns /usr/local/bin/kixdns
sudo mkdir -p /etc/kixdns
sudo cp config/pipeline.json /etc/kixdns/

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable --now kixdns
```

### Docker 运行

```bash
docker run --rm -p 5353:5353/udp -p 5353:5353/tcp \
  -v $(pwd)/config/pipeline.json:/etc/kixdns/pipeline.json \
  your-image/kixdns:latest --config /etc/kixdns/pipeline.json
```

## 技术栈

| 组件 | 用途 |
|------|------|
| tokio | 异步运行时 |
| hickory-proto | DNS 协议实现 |
| moka | 高性能缓存 |
| dashmap | 并发哈希映射 |
| rustc-hash | 快速哈希 |
| bytes | 零拷贝字节操作 |
| smallvec | 小向量优化 |
| arc-swap | 原子引用交换（配置热重载） |
| socket2 | 底层 socket 控制 |
| regex | 正则表达式 |
| ipnet | IP 网络地址处理 |
| tracing | 结构化日志 |
| clap | 命令行参数解析 |
| notify | 配置文件监控 |

## 附带工具

项目包含一个基于浏览器的配置编辑器，用于生成和管理 `pipeline` 的 JSON 配置文件：

- 位置：`tools/config_editor.html`
- 使用方法：在现代浏览器中打开该 HTML 文件并按页面说明导出配置

## 许可证

本项目采用 GNU 通用公共许可证 v3.0（GPL-3.0）发布，详见 `LICENSE` 文件。
