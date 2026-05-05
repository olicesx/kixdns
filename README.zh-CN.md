# KixDNS

**[English](./README.md)** | **[简体中文](./README.zh-CN.md)**

高性能、非递归 DNS 转发服务器，使用 Rust 开发，面向低延迟、高并发场景，支持灵活的 Pipeline 路由规则和热重载配置。

## 特性

### 🚀 高性能
- **零拷贝 UDP 处理** — 基于 `BytesMut` 的收包处理，最小化内存复制
- **延迟请求解析** — 普通转发场景无需完整反序列化，直接透传
- **轻量响应扫描** — 零分配提取上游响应的 RCODE 与最小 TTL
- **快速哈希** — 内部数据结构采用 `rustc-hash` (FxHash)
- **异步 I/O** — 基于 `tokio`，使用 `DashMap` / `moka` 并发状态管理
- **自适应流控** — `PermitManager` 根据上游延迟动态调整并发
- **SO_REUSEPORT** — Unix 多 worker 共享端口，充分利用多核
- **双 Socket 架构** — IPv4/IPv6 分离 Socket，兼容 OpenBSD

### 🔧 灵活路由
- **Pipeline 选择规则** — 按监听器标签、客户端 IP、域名、QCLASS、EDNS、GeoSite 等多维路由
- **匹配器逻辑运算** — AND、OR、AND_NOT、OR_NOT、NOT 组合
- **两阶段处理** — 请求匹配 + 响应匹配，支持二次决策
- **监听器标签** — 同一实例为不同标签提供不同 Pipeline
- **多种上游传输** — UDP / TCP / DoH (RFC 8484) / DoT / DoQ (RFC 9250)
- **URL 协议前缀** — `udp://`、`tcp://`、`doh://`、`dot://`、`doq://` 自动识别

### 💾 缓存与可靠性
- **内存缓存** — 高性能 `moka` 缓存，可配置容量和最大 TTL
- **智能 TTL** — 遵循上游 TTL，支持可配置的最小 TTL 下限
- **Singleflight 去重** — 基于 `tokio::watch` 的零分配并发去重，防止缓存击穿
- **后台刷新** — TTL 即将过期时自动后台刷新，Hybrid Bloom Filter + DashSet 去重
- **Serve Stale (RFC 8767)** — 上游不可用时返回过期缓存，提升弹性

### 🌍 GeoIP 与 GeoSite
- **MaxMind GeoIP 集成** — 支持 MMDB 格式 GeoIP2/GeoLite2 数据库
- **私有 IP 检测** — 自动识别内网/私有 IP 地址段
- **V2Ray GeoSite 支持** — 域名分类路由（cn、google、category-ads 等）
- **数据库热重载** — 文件变化自动重新加载，懒加载机制

### 🔌 DNS-over-QUIC (DoQ)
- **0-RTT 自动检测** — 首次尝试 0-RTT，服务器拒绝时自动禁用并缓存
- **零开销缓存** — `AtomicBool` 检测结果缓存
- **RFC 9250 合规** — 强制 message-id=0 并恢复客户端 transaction ID

### 🛡️ DNS 污染过滤
- **响应阶段 IP 匹配** — `response_answer_ip` 检测污染响应
- **自动上游切换** — 检测到污染时自动切换备用上游
- **灵活降级策略** — TCP 回退、多级上游兜底

### 📊 运维
- **配置热重载** — `ArcSwap` 无锁热重载，`notify` 监控文件变化
- **结构化日志** — 基于 `tracing` 的 JSON 日志输出
- **可配置流控** — 按 deployment 调整 permit 范围和延迟阈值

## 快速开始

### 构建

```bash
cargo build --release
```

### 运行

```bash
# 默认配置: config/pipeline.json
./target/release/kixdns

# 指定配置文件
./target/release/kixdns --config /etc/kixdns/pipeline.json

# 使用监听器标签
./target/release/kixdns --listener-label edge-internal

# 调试模式
./target/release/kixdns --debug
```

### 命令行参数

```
kixdns [OPTIONS]

OPTIONS:
  -c, --config <FILE>          配置文件路径 [默认: config/pipeline.json]
      --listener-label <LABEL> 监听器标签 [默认: default]
      --debug                  启用调试日志
      --udp-workers <NUM>      UDP worker 数量 [默认: CPU 核心数]
  -h, --help                   显示帮助
  -V, --version                显示版本
```

### systemd 服务

创建 `/etc/systemd/system/kixdns.service`：

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

```bash
sudo install -m 0755 target/release/kixdns /usr/local/bin/kixdns
sudo mkdir -p /etc/kixdns
sudo cp config/pipeline.json /etc/kixdns/
sudo systemctl daemon-reload
sudo systemctl enable --now kixdns
```

## 配置

配置采用 JSON 格式，顶层结构如下：

```json
{
  "version": "1.0",
  "settings": { ... },
  "pipeline_select": [ ... ],
  "pipelines": [ ... ]
}
```

### 全局设置

- `min_ttl` — 最小 TTL，秒（默认: 0）
- `bind_udp` — UDP 监听地址（默认: `0.0.0.0:5353`）
- `bind_tcp` — TCP 监听地址（默认: `0.0.0.0:5353`）
- `cache_capacity` — 缓存最大条目数（默认: 10000）
- `cache_max_ttl` — 缓存最大 TTL，秒（默认: 86400）
- `default_upstream` — 默认上游 DNS（默认: `1.1.1.1:53`）
- `upstream_timeout_ms` — 上游超时（默认: 2000）
- `response_jump_limit` — 响应阶段 Pipeline 跳转上限（默认: 10）
- `udp_pool_size` — UDP 上游连接池大小（默认: 64）
- `tcp_pool_size` — TCP 上游连接池大小（默认: 64）
- `doh_pool_size` — DoH 每上游最大空闲连接（默认: 8）
- `dot_pool_size` — DoT 连接池大小（默认: 64）
- `doq_pool_size` — DoQ 连接池大小（默认: 16）
- `doq_connection_idle_timeout_seconds` — DoQ 空闲超时（默认: 60）
- `doq_keepalive_interval_ms` — DoQ keepalive 间隔（默认: 15000）
- `doq_enable_0rtt` — 启用 DoQ 0-RTT 自动检测（默认: true）
- `flow_control_initial_permits` — 流控初始 permits（默认: 500）
- `flow_control_min_permits` — 最小 permits（默认: 100）
- `flow_control_max_permits` — 最大 permits（默认: 800）
- `flow_control_latency_threshold_ms` — 延迟告急阈值（默认: 100）
- `flow_control_adjustment_interval_secs` — 流控调整间隔（默认: 5）
- `cache_background_refresh` — 启用后台缓存刷新（默认: false）
- `cache_refresh_threshold_percent` — 刷新阈值，剩余 TTL 百分比（默认: 10）
- `cache_refresh_min_ttl` — 后台刷新最小 TTL（默认: 5）
- `serve_stale` — 启用 RFC 8767 过期缓存（默认: false）
- `serve_stale_ttl` — 过期缓存响应 TTL（默认: 30）
- `serve_stale_expire_ttl` — 过期缓存最大时间窗口，秒（默认: 86400）
- `serve_stale_ttl_reset` — 每次返回过期数据时重置计时器（默认: true）
- `serve_stale_client_timeout_ms` — 返回过期数据前尝试上游的时间（默认: 0）
- `geoip_db_path` — GeoIP MMDB 数据库路径
- `geoip_cache_capacity` — GeoIP 查询缓存容量（默认: 10000）
- `geoip_cache_ttl` — GeoIP 缓存 TTL，秒（默认: 3600）
- `geosite_data_paths` — V2Ray GeoSite 数据文件路径列表

### 匹配器类型

#### Pipeline 选择匹配器

| 类型 | 参数 | 说明 |
|------|------|------|
| `listener_label` | `value` | 监听器标签匹配 |
| `client_ip` | `cidr` | 客户端 IP CIDR 匹配 |
| `domain_suffix` | `value` | 域名后缀匹配 |
| `domain_regex` | `value` | 域名正则匹配 |
| `qclass` | `value` | QCLASS 匹配 (IN/CH/HS) |
| `edns_present` | `expect` | EDNS 存在性检查 |
| `geosite` | `value` | GeoSite 域名分类匹配 |
| `geosite_not` | `value` | GeoSite 否定匹配 |
| `any` | — | 任意匹配 |

#### 请求匹配器

与 Pipeline 选择匹配器相同，额外支持：

| 类型 | 参数 | 说明 |
|------|------|------|
| `geoip_country` | `country_codes` | 客户端 IP 国家代码 (CN、US 等) |
| `geoip_private` | `expect` | 私有/内网 IP 检测 |

#### 响应匹配器

| 类型 | 参数 | 说明 |
|------|------|------|
| `upstream_equals` | `value` | 上游字符串精确匹配 |
| `request_domain_suffix` | `value` | 请求域名后缀匹配 |
| `request_domain_regex` | `value` | 请求域名正则匹配 |
| `response_upstream_ip` | `cidr` | 上游 IP CIDR 匹配 |
| `response_answer_ip` | `cidr` | Answer 段 IP CIDR 匹配 |
| `response_type` | `value` | 记录类型匹配 (A/AAAA/CNAME) |
| `response_rcode` | `value` | RCODE 匹配 (NOERROR/NXDOMAIN) |
| `response_qclass` | `value` | QCLASS 匹配 |
| `response_edns_present` | `expect` | EDNS 存在性检查 |

### 动作类型

| 类型 | 参数 | 说明 |
|------|------|------|
| `log` | `level`, `message` | 记录日志 |
| `static_response` | `rcode` | 返回静态 RCODE |
| `static_ip_response` | `rcode`, `ips` | 返回静态 IP 响应 |
| `jump_to_pipeline` | `pipeline` | 跳转到指定 Pipeline |
| `allow` | — | 接受当前响应 |
| `deny` | — | 返回 REFUSED |
| `forward` | `upstream`, `transport` | 转发到上游 |
| `continue` | — | 继续匹配下一条规则 |

**传输选项**: `udp`、`tcp`、`tcp_udp`、`doh`、`dot`、`doq`（上游 URL 含协议前缀时可省略）

**URL 前缀**: `udp://`、`tcp://`、`tcp+udp://`、`doh://`、`https://`、`dot://`、`tls://`、`doq://`、`quic://`

### 逻辑运算符

匹配器支持逻辑组合：

| 运算符 | 说明 |
|--------|------|
| `and` | 逻辑与（默认） |
| `or` | 逻辑或 |
| `and_not` | 逻辑与非 |
| `or_not` | 逻辑或非 |
| `not` | 逻辑非 |

## 配置示例

### GeoIP 按国家路由

```json
{
  "version": "1.0",
  "settings": {
    "min_ttl": 30,
    "bind_udp": "0.0.0.0:5353",
    "default_upstream": "1.1.1.1:53",
    "geoip_db_path": "data/GeoLite2-Country.mmdb"
  },
  "pipelines": [
    {
      "id": "china-domestic",
      "rules": [{
        "name": "china-clients",
        "matchers": [{ "type": "geoip_country", "country_codes": ["CN"] }],
        "actions": [
          { "type": "log", "level": "info" },
          { "type": "forward", "upstream": "223.5.5.5:53" }
        ]
      }]
    },
    {
      "id": "international",
      "rules": [{
        "name": "non-china",
        "matchers": [{ "type": "geoip_country", "country_codes": ["US", "JP", "KR"] }],
        "actions": [{ "type": "forward", "upstream": "8.8.8.8:53" }]
      }]
    }
  ]
}
```

### GeoSite 域名分类路由

```json
{
  "version": "1.0",
  "settings": {
    "geosite_data_paths": ["data/geosite-cn.json", "data/geosite-google.json"]
  },
  "pipelines": [
    {
      "id": "cn-domains",
      "rules": [{
        "name": "china-domains",
        "matchers": [{ "type": "geosite", "value": "cn" }],
        "actions": [{ "type": "forward", "upstream": "223.5.5.5:53" }]
      }]
    },
    {
      "id": "block-ads",
      "rules": [{
        "name": "ad-block",
        "matchers": [{ "type": "geosite", "value": "category-ads" }],
        "actions": [{ "type": "static_response", "rcode": "NXDOMAIN" }]
      }]
    }
  ]
}
```

### DNS 污染过滤

```json
{
  "version": "1.0",
  "settings": {
    "default_upstream": "223.5.5.5:53",
    "upstream_timeout_ms": 1500
  },
  "pipelines": [{
    "id": "filter",
    "rules": [
      {
        "name": "check-pollution",
        "matchers": [{ "type": "any" }],
        "actions": [{ "type": "forward", "upstream": "223.5.5.5:53", "transport": "udp" }],
        "response_matchers": [{ "type": "response_answer_ip", "cidr": "127.0.0.0/8,0.0.0.0/8" }],
        "response_actions_on_match": [{ "type": "continue" }],
        "response_actions_on_miss": [{ "type": "allow" }]
      },
      {
        "name": "fallback",
        "matchers": [{ "type": "any" }],
        "actions": [{ "type": "forward", "upstream": "8.8.4.4:53", "transport": "tcp" }]
      }
    ]
  }]
}
```

### Serve Stale (RFC 8767)

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

### DoQ 与 0-RTT

```json
{
  "settings": {
    "doq_enable_0rtt": true,
    "doq_pool_size": 8
  },
  "pipelines": [{
    "id": "doq-upstream",
    "rules": [{
      "name": "alidns-doq",
      "matchers": [{ "type": "any" }],
      "actions": [{
        "type": "forward",
        "upstream": "doq://223.5.5.5:853?sni=dns.alidns.com&0rtt=false"
      }]
    }]
  }]
}
```

## 技术栈

- **tokio** — 异步运行时
- **hickory-proto** — DNS 协议
- **moka** — 高性能缓存
- **dashmap** — 并发哈希映射
- **rustc-hash** — 快速哈希 (FxHash)
- **quinn** — QUIC/DoQ 传输
- **reqwest** — HTTP/DoH 客户端
- **tokio-rustls** — TLS (DoT/DoQ)
- **maxminddb** — GeoIP MMDB 查询
- **arc-swap** — 无锁配置热重载
- **notify** — 文件变化检测
- **clap** — 命令行参数解析
- **tracing** — 结构化日志

## 工具

- `tools/config_editor.html` — 浏览器端 Pipeline 配置编辑器
- `tools/diagnose.html` — 基于 WebSocket 的 DNS 查询诊断工具

## 从源码构建

**依赖**: Rust 1.82+ (edition 2024)

```bash
git clone https://github.com/olicesx/kixdns.git
cd kixdns
cargo build --release
```

Release profile 使用 `opt-level = 3`、`lto = "fat"`、`codegen-units = 1`、`strip = true` 以获得最佳性能。

## 许可证

[GPL-3.0](LICENSE)
