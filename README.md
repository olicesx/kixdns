# KixDNS

**注意：本项目完全由 AI 构建（内容、文档与初始实现均由 AI 生成）。**

KixDNS 是用 Rust 开发的高性能、可扩展 DNS 服务器，面向低延迟、高并发以及复杂路由场景。

## 主要特性

### 高性能
- 零拷贝网络：使用 `BytesMut` 实现 UDP 收包的零拷贝处理，尽量减少内存复制。
- 延迟解析：实现了“延迟请求解析”，普通转发场景避免对包进行完整反序列化，降低开销。
- 轻量化响应解析：在不需要完整解析时快速扫描上游响应以提取 `RCODE` 与最小 TTL（零分配）。
- 快速哈希：内部数据结构采用 `FxHash`（rustc-hash）以获得更快的哈希性能。
- 高并发：基于 `tokio` 异步 IO，使用 `DashMap` / `moka` 等并发数据结构进行状态管理。

### 灵活架构
- 管道化处理：可为不同监听器配置独立的处理 `pipeline`。
- 高级路由：支持基于域名（精确、通配、正则）、客户端 IP、查询类型等进行路由匹配。
- 响应动作：可在响应上执行重写 TTL、返回静态响应、拒绝、或继续跳转等动作。
- 上游负载与容错：支持多个上游解析器的负载均衡与故障切换策略。

### 缓存与去重
- 内存缓存：集成高性能缓存（`moka`）。
- 智能 TTL：遵循上游 TTL，同步支持可配置的最小 TTL。
- 去重（Singleflight）：合并相同请求的并发上游调用以防止缓存击穿。

## 安装

### 预编译二进制文件

从 [Releases 页面](https://github.com/olicesx/kixdns/releases) 下载适合你平台的预编译二进制文件：

- Linux (x86_64, ARM64)
- FreeBSD (x86_64, ARM64)

```bash
# 下载并解压
tar xzf kixdns-linux-x86_64.tar.gz

# 验证 SHA256 校验和
sha256sum -c kixdns-linux-x86_64.tar.gz.sha256
```

### 从源码构建

确保已安装 Rust（stable 通道），然后在项目根目录运行：

```bash
cargo build --release
```

构建产物位于：`target/release/kixdns`。

## 附带工具

项目包含一个基于浏览器的配置编辑器，用于生成和管理 `pipeline` 的 JSON 配置文件：

- 位置：`tools/config_editor.html`
- 使用方法：在现代浏览器中打开该 HTML 文件并按页面说明导出配置。

## 配置示例

配置采用 JSON 格式，可参考 `config/pipeline_local.json`。下面是一个最小示例：

```json
{
  "listeners": [
    {
      "protocol": "udp",
      "addr": "0.0.0.0:53",
      "pipeline": "main"
    }
  ],
  "pipelines": [
    {
      "id": "main",
      "rules": [
        {
          "name": "block_ads",
          "matcher": { "domain": ["*.doubleclick.net"] },
          "action": { "type": "static", "rcode": "NXDOMAIN" }
        },
        {
          "name": "forward_google",
          "matcher": { "domain": ["*"] },
          "action": { "type": "forward", "upstream": "8.8.8.8:53" }
        }
      ]
    }
  ]
}
```

## 启动示例

下面给出常用的构建与运行示例，适用于发布后的快速上手。

- 本地构建（Release）：

```bash
cargo build --release
```

- 直接运行（指定配置文件）：

```bash
# 在项目根目录运行，假设配置文件为 config/pipeline_local.json
./target/release/kixdns --config config/pipeline_local.json
```

- 作为 systemd 服务（示例 unit 文件 `/etc/systemd/system/kixdns.service`）：

```ini
[Unit]
Description=KixDNS
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kixdns --config /etc/kixdns/pipeline_local.json
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

部署步骤（简要）：

```bash
# 安装二进制到 /usr/local/bin
sudo install -m 0755 target/release/kixdns /usr/local/bin/kixdns
sudo mkdir -p /etc/kixdns
sudo cp config/pipeline_local.json /etc/kixdns/
sudo systemctl daemon-reload
sudo systemctl enable --now kixdns
```

- Docker 运行示例（最小）：

```bash
# 假设已有可执行文件或使用官方构建步骤在镜像中构建
docker run --rm -p 53:53/udp -v $(pwd)/config/pipeline_local.json:/etc/kixdns/pipeline_local.json your-image/kixdns:latest --config /etc/kixdns/pipeline_local.json
```

这些示例覆盖了常见的本地测试、systemd 部署与容器化场景。根据实际环境调整可执行路径与配置文件位置。

## 许可证

本项目采用 GNU 通用公共许可证 v3.0（GPL-3.0）发布，详见 `LICENSE` 文件。
