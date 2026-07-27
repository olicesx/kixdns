# KixDNS 工具说明

本目录包含浏览器配置编辑器、编辑器 smoke-check 页面，以及一个用于查看 GeoSite .dat 标签的独立源码文件。

## config_editor.html

tools/config_editor.html 是一个静态 HTML 配置编辑器。它使用 Vue 3、Bootstrap 5 和 Mermaid CDN 资源，因此打开时浏览器需要访问对应公共 CDN。

## 功能特性

### 核心功能

- ✅ **可视化配置编辑**：通过表单编辑 settings、Pipeline、规则、匹配器和动作，无需手写完整 JSON。
- ✅ **实时预览**：左侧编辑，右侧实时显示序列化后的 JSON。
- ✅ **流程图生成**：根据 Pipeline 和规则生成 Mermaid 流程图。
- ✅ **导入/导出**：导入现有 JSON，编辑后下载配置文件。

### GeoIP 与 GeoSite

- **MMDB 与 .dat 路径**：配置 MaxMind MMDB 和 V2Ray GeoIP `.dat`/JSON 文件路径。
- **多文件支持**：`geosite_data_paths` 支持多个 GeoSite 数据文件。
- **GeoIP 匹配器**：支持 `geoip_country` 和 `geoip_private`。
- **GeoSite 匹配器**：支持 `geosite` 和 `geosite_not`，以及响应阶段的请求域名 GeoSite 匹配器。
- **调用语法**：界面识别 `geosite:cn`、`geoip:CN` 和 `geoip:CN,US`，并将其写入服务端字段。

编辑器中的 `geoip_auto_convert`、`geoip_filter_countries` 和顶层 `background_refresh_rule` 会被界面维护或输出，但当前运行引擎不会读取它们。GeoIP 转换时的国家过滤请使用主程序命令：

~~~bash
kixdns convert-geo-ip --input geoip.dat --output GeoIP.mmdb --filter CN,US,JP
~~~

编辑器提供：

- settings 全局配置表单；
- pipeline_select、Pipeline、规则、请求匹配器、响应匹配器和动作编辑；
- JSON 导入、右侧 JSON 预览和 JSON 下载；
- Pipeline/规则的 Mermaid 流程图；
- ECS、缓存后台刷新、Serve Stale、DoH 入站、GeoIP/GeoSite、DoH/DoT/DoQ 上游和 TXT 动作字段。

直接在浏览器打开：

~~~text
tools/config_editor.html
~~~

编辑器下载的文件可用以下命令加载：

~~~bash
kixdns run -c /path/to/pipeline.json
~~~

编辑器的界面字段会转换为服务端配置使用的 snake_case JSON。例如 ECS 会输出嵌套对象：

~~~json
{
  "id": "ecs-pipeline",
  "ecs": {
    "mode": "from_client_ip",
    "prefix_v4": 24,
    "prefix_v6": 56
  },
  "rules": [
    {
      "name": "forward",
      "matchers": [ { "type": "any" } ],
      "actions": [
        {
          "type": "forward",
          "upstream": "8.8.8.8:53",
          "ecs": {
            "mode": "from_client_ip",
            "prefix_v4": 24,
            "prefix_v6": 56
          }
        }
      ]
    }
  ]
}
~~~

### 服务端配置字段注意事项

编辑器只是静态前端，不会启动 KixDNS，也不会检查证书、数据文件、CIDR、正则或上游连通性。下载后应以 KixDNS 启动时的解析和校验结果为准。

当前 Rust 配置类型对 geoip_country 和 response_answer_ip_geoip_country 的 country_codes 要求字符串数组，例如：

~~~json
{ "type": "geoip_country", "country_codes": ["CN", "US"] }
~~~

如果手动编辑右侧 JSON，请保持这个数组格式。编辑器界面中的国家代码输入是逗号分隔文本；生成文件后应检查 JSON 中是否为数组。

以下字段目前虽然会被编辑器显示或输出，但不会改变运行引擎行为：

- settings.geoip_auto_convert；
- settings.geoip_filter_countries；
- 顶层 background_refresh_rule；
- 编辑器内部仅用于界面状态的字段会在下载时被移除。

GeoIP 转换时的国家过滤使用主程序命令：

~~~bash
kixdns convert-geo-ip \
  --input geoip.dat \
  --output GeoIP.mmdb \
  --filter CN,US,JP
~~~

### 匹配器

Pipeline selector 支持：

- any
- listener_label
- client_ip
- domain_suffix
- domain_regex
- qclass
- edns_present
- geosite
- geosite_not
- geoip_country
- geoip_private
- qtype

请求规则支持上面除 listener_label 外的类型。响应规则支持：

- upstream_equals
- request_domain_suffix
- request_domain_regex
- response_type
- response_rcode
- response_qclass
- response_edns_present
- response_upstream_ip
- response_answer_ip
- response_answer_ip_geoip_country
- response_answer_ip_geoip_private
- response_request_domain_geosite
- response_request_domain_geosite_not
- response_txt_content

GeoSite 和 GeoIP 的输入值在编辑器中可以使用普通字段。编辑器还会识别 geosite:tag 和 geoip:COUNTRY 形式并将参数写入对应字段；服务端最终仍按 Rust 配置枚举解析。

### 动作

编辑器提供以下动作：

- log
- static_response
- static_ip_response
- static_txt_response
- jump_to_pipeline
- allow
- deny
- forward
- continue
- replace_txt_response

TXT 动作的 text 可以是字符串或字符串数组。static_txt_response 还支持 ttl，默认值为 300。replace_txt_response 用于响应阶段；在请求阶段不会产生 TXT 响应。

### 上游传输

Forward 的 transport 值为 udp、tcp、tcp_udp、doh、dot、doq。upstream 支持逗号分隔的多个上游；带协议前缀时可以省略 transport：

~~~json
{
  "type": "forward",
  "upstream": [
    "udp://1.1.1.1:53",
    "tcp://8.8.8.8:53",
    "doh://dns.google/dns-query",
    "dot://1.1.1.1:853?sni=cloudflare-dns.com",
    "doq://dns.adguard.com:853"
  ]
}
~~~

支持的前缀为 udp://、tcp://、tcp+udp://、udp+tcp://、doh://、https://、dot://、tls://、doq:// 和 quic://。DoQ 使用 IP 地址时必须设置 sni；单个 DoQ 上游还可以通过 0rtt=true/false 覆盖全局设置。

### DoQ 0-RTT

- `doq_enable_0rtt` 控制全局默认值，默认启用。
- DoQ upstream 可以使用 `0rtt=true` 或 `0rtt=false` 覆盖全局设置。
- 服务器拒绝或请求超时后，该上游在本次进程生命周期内会禁用 0-RTT，重启后重新尝试。
- `sni` 或 `servername` 用于设置 TLS 名称；DoQ 使用 IP literal 时必须显式设置 SNI。

### RFC 8767 过期缓存

配置编辑器包含 `serve_stale`、`serve_stale_ttl`、`serve_stale_expire_ttl`、`serve_stale_ttl_reset` 和 `serve_stale_client_timeout_ms`。

- `serve_stale` 默认关闭。
- `serve_stale_client_timeout_ms=0` 时立即返回过期缓存；正值会先尝试上游指定的毫秒数。
- 过期响应使用 `serve_stale_ttl`，并受 `serve_stale_expire_ttl` 限制。

### 缓存后台刷新

编辑器包含 `cache_background_refresh`、`cache_refresh_threshold_percent` 和 `cache_refresh_min_ttl`。后台刷新失败不会替换现有缓存条目。

### 缓存相关设置

编辑器包含以下服务端缓存字段：

- cache_capacity
- cache_max_ttl
- min_ttl
- cache_background_refresh
- cache_refresh_threshold_percent
- cache_refresh_min_ttl
- serve_stale
- serve_stale_ttl
- serve_stale_expire_ttl
- serve_stale_ttl_reset
- serve_stale_client_timeout_ms

这些字段的默认值和运行语义以根目录 README 与 src/config.rs 为准。

### ECS（RFC 7871）

ECS 有两层配置：

| 层级 | JSON 位置 | 作用 |
|---|---|---|
| Pipeline 级 | `pipeline.ecs` | 将客户端子网加入缓存键，隔离不同子网的响应 |
| Action 级 | `forward.ecs` | 改写发往上游的 DNS 请求 |

> ⚠ **约束**：同一 Pipeline 内的 Forward action 与 Pipeline 级 ECS 模式应保持一致；需要不同 ECS 行为时请拆分 Pipeline。

可用模式为 `clear`、`from_client_ip` 和 `static`。`from_client_ip` 默认使用 IPv4 `/24`、IPv6 `/56`；`static` 需要配置 IP 和前缀。

~~~json
{
  "id": "ecs-pipeline",
  "ecs": { "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 },
  "rules": [{
    "name": "forward",
    "matchers": [{ "type": "any" }],
    "actions": [{
      "type": "forward",
      "upstream": "8.8.8.8:53",
      "ecs": { "mode": "from_client_ip", "prefix_v4": 24, "prefix_v6": 56 }
    }]
  }]
}
~~~

## diagnose.html

tools/diagnose.html 是一个简单的浏览器 smoke-check 页面，测试 Vue 挂载、响应式数据、TXT action 和响应 TXT 匹配器。它不连接 DNS 服务器，不提供 WebSocket API。

直接打开：

~~~text
tools/diagnose.html
~~~

## test_vue.html

tools/test_vue.html 是一个更小的 Vue/TXT action 页面，用于检查 Vue CDN 和基础 TXT action 绑定。

## check_geosite_tags.rs

tools/check_geosite_tags.rs 是独立 Rust 源码，用于扫描 V2Ray GeoSite .dat 文件并输出标签统计。当前 Cargo.toml 没有将它声明为 bin 或 example，因此不能按 cargo run --bin check_geosite_tags 直接运行。若要使用，需要先把它接入项目的 Cargo target，或自行提供依赖和编译环境。
