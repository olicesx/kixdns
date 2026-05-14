# KixDNS

**[English](./README.md)** | **[简体中文](./README.zh-CN.md)**

A high-performance, non-recursive DNS forwarding server written in Rust, designed for low-latency, high-concurrency environments with flexible pipeline-based routing rules and hot-reloadable configuration.

## Features

### Performance
- **Zero-copy UDP processing** — `BytesMut`-based packet handling minimizes memory copies
- **Lazy request parsing** — transparent forwarding without full deserialization when possible
- **Lightweight response scanning** — zero-alloc extraction of RCODE and minimum TTL from upstream responses
- **Fast hashing** — `rustc-hash` (FxHash) for all internal data structures
- **Async I/O** — built on `tokio` with `DashMap` / `moka` concurrent state management
- **Adaptive flow control** — `PermitManager` dynamically adjusts concurrency based on upstream latency
- **SO_REUSEPORT** — multi-worker port sharing on Unix for full multi-core utilization
- **Dual-socket architecture** — separate IPv4/IPv6 sockets for OpenBSD compatibility

### Flexible Routing
- **Pipeline selection rules** — route by listener label, client IP, domain, QCLASS, EDNS, GeoSite, and more
- **Logical matcher operators** — AND, OR, AND_NOT, OR_NOT, NOT for complex rule composition
- **Two-phase processing** — request matching + response matching with secondary decisions
- **Listener labels** — serve different pipelines from the same instance
- **Multiple upstream transports** — UDP / TCP / DoH (RFC 8484) / DoT / DoQ (RFC 9250)
- **URL protocol prefixes** — `udp://`, `tcp://`, `doh://`, `dot://`, `doq://` auto-detection

### Cache & Reliability
- **In-memory cache** — high-performance `moka` cache with configurable capacity and max TTL
- **Smart TTL handling** — honors upstream TTL with configurable minimum floor
- **Singleflight deduplication** — `tokio::watch`-based zero-alloc concurrent request deduplication
- **Background refresh** — automatic stale-while-revalidate with hybrid bloom filter + DashSet dedup
- **Serve Stale (RFC 8767)** — return expired cache when upstream is unavailable

### GeoIP & GeoSite
- **MaxMind GeoIP integration** — MMDB format support with country code matching
- **Private IP detection** — automatic private/internal network identification
- **V2Ray GeoSite support** — domain category routing (cn, google, category-ads, etc.)
- **Hot-reloadable databases** — automatic reload on file change, lazy loading

### DNS-over-QUIC (DoQ)
- **0-RTT auto-detection** — tries 0-RTT first, auto-disables on server rejection
- **Zero-overhead caching** — `AtomicBool`-based detection result cache
- **RFC 9250 compliant** — forced message-id=0 with client transaction ID restoration

### DNS Pollution Filtering
- **Response-stage IP matching** — detect polluted answers via `response_answer_ip` matcher
- **Automatic upstream failover** — switch to backup upstream on pollution detection
- **Flexible fallback strategies** — TCP fallback, multi-level upstream chaining

### Operations
- **Hot configuration reload** — lock-free `ArcSwap`-based reload via `notify` file watching
- **Structured logging** — `tracing`-based JSON log output
- **Configurable flow control** — tune permit ranges and latency thresholds per deployment

## Quick Start

### Build

```bash
cargo build --release
```

### Run

```bash
# Default config: config/pipeline.json
./target/release/kixdns

# Custom config
./target/release/kixdns --config /etc/kixdns/pipeline.json

# With listener label
./target/release/kixdns --listener-label edge-internal

# Debug logging
./target/release/kixdns --debug
```

### Command Line Options

```
kixdns [OPTIONS]

OPTIONS:
  -c, --config <FILE>          Configuration file path [default: config/pipeline.json]
      --listener-label <LABEL> Listener label for pipeline selection [default: default]
      --debug                  Enable debug logging
      --udp-workers <NUM>      Number of UDP workers [default: CPU core count]
  -h, --help                   Show help
  -V, --version                Show version
```

### Service Management (Cross-Platform)

KixDNS includes built-in service management that supports all major init systems.
The `service` subcommand works on Windows, Linux, and FreeBSD.

#### Quick Commands

```bash
# Install as a system service (auto-detects init system)
sudo ./target/release/kixdns service install

# Install with custom config
sudo ./target/release/kixdns service install \
    --config /etc/kixdns/pipeline.json \
    --listener-label edge-internal

# Uninstall the service
sudo ./target/release/kixdns service uninstall

# Run as service (used by init system internally)
kixdns service run
```

> **Note**: `service install` and `service uninstall` require root/Administrator
> privileges. `service run` is called automatically by the init system.

#### Auto-Detection Logic

The init system is auto-detected in the following order:

| Condition | Detected System |
|-----------|----------------|
| `#[cfg(target_os = "windows")]` | Windows SCM |
| `/sbin/procd` exists | Procd (OpenWrt) |
| `/usr/lib/systemd/systemd` or `/lib/systemd/systemd` exists | systemd |
| `/sbin/openrc-run` exists | OpenRC |
| `#[cfg(target_os = "freebsd")]` | BSD rc.d |
| Nothing matched | Unknown (manual setup required) |

#### Service Scripts

<details>
<summary><b>systemd</b> (Linux — most distributions)</summary>

Installed to: `/etc/systemd/system/kixdns.service`

```ini
[Unit]
Description=KixDNS DNS Server
Documentation=https://github.com/kixdns/kixdns
After=network.target
Wants=nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/local/bin/kixdns run \
    --config /etc/kixdns/pipeline.json \
    --listener-label default
Restart=on-failure
RestartSec=5
User=nobody
Group=nogroup
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=65536
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
# Manual commands
systemctl daemon-reload
systemctl enable --now kixdns
systemctl status kixdns
journalctl -u kixdns -f
```
</details>

<details>
<summary><b>OpenRC</b> (Gentoo, Alpine Linux)</summary>

Installed to: `/etc/init.d/kixdns`

```sh
#!/sbin/openrc-run

name="KixDNS DNS Server"
description="High-performance async DNS server"
command="/usr/local/bin/kixdns"
command_args="run --config /etc/kixdns/pipeline.json --listener-label default"
command_user="nobody:nogroup"
pidfile="/run/${RC_SVCNAME}.pid"
command_background=false

depend() {
    need net
    use dns logger
}
```

```bash
# Manual commands
rc-update add kixdns default
rc-service kixdns start
rc-service kixdns status
```
</details>

<details>
<summary><b>Procd</b> (OpenWrt)</summary>

Installed to: `/etc/init.d/kixdns`

```sh
#!/bin/sh /etc/rc.common

USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command "/usr/local/bin/kixdns"
    procd_append_param command run --config /etc/kixdns/pipeline.json --listener-label default
    procd_set_param user nobody
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}

service_triggers() {
    procd_add_reload_trigger "kixdns"
}
```

```bash
# Manual commands
/etc/init.d/kixdns enable
/etc/init.d/kixdns start
/etc/init.d/kixdns status
```
</details>

<details>
<summary><b>BSD rc.d</b> (FreeBSD)</summary>

Installed to: `/usr/local/etc/rc.d/kixdns`

```sh
#!/bin/sh
#
# PROVIDE: kixdns
# REQUIRE: NETWORKING SERVERS
# KEYWORD: shutdown

. /etc/rc.subr

name="kixdns"
rcvar="kixdns_enable"

load_rc_config $name

: ${kixdns_enable:="NO"}
: ${kixdns_config:="/usr/local/etc/kixdns/pipeline.json"}
: ${kixdns_listener_label:="default"}
: ${kixdns_user:="nobody"}

command="/usr/local/bin/kixdns"
command_args="run --config ${kixdns_config} --listener-label ${kixdns_listener_label}"
command_user="${kixdns_user}"
pidfile="/var/run/kixdns.pid"

run_rc_command "$1"
```

```bash
# Manual commands
echo 'kixdns_enable="YES"' >> /etc/rc.conf
service kixdns start
service kixdns status
```
</details>

<details>
<summary><b>Windows</b> (SCM — Service Control Manager)</summary>

```bash
# Install (Administrator PowerShell)
kixdns.exe service install --config config/pipeline.json

# Start
sc start KixDNS

# Query status
sc query KixDNS

# Stop
sc stop KixDNS

# Uninstall (Administrator PowerShell)
kixdns.exe service uninstall
```
</details>

## Configuration

Configuration uses JSON format with the following top-level structure:

```json
{
  "version": "1.0",
  "settings": { ... },
  "pipeline_select": [ ... ],
  "pipelines": [ ... ]
}
```

### Global Settings

- `min_ttl` — Minimum TTL in seconds (default: 0)
- `bind_udp` — UDP listen address (default: `0.0.0.0:5353`)
- `bind_tcp` — TCP listen address (default: `0.0.0.0:5353`)
- `cache_capacity` — Max cache entries (default: 10000)
- `cache_max_ttl` — Max cache TTL in seconds (default: 86400)
- `default_upstream` — Default upstream DNS (default: `1.1.1.1:53`)
- `upstream_timeout_ms` — Upstream timeout (default: 2000)
- `response_jump_limit` — Max pipeline jumps in response phase (default: 10)
- `udp_pool_size` — UDP upstream pool size (default: 64)
- `tcp_pool_size` — TCP upstream pool size (default: 64)
- `doh_pool_size` — DoH max idle connections per upstream (default: 8)
- `dot_pool_size` — DoT pool size (default: 64)
- `doq_pool_size` — DoQ pool size (default: 16)
- `doq_connection_idle_timeout_seconds` — DoQ idle timeout (default: 60)
- `doq_keepalive_interval_ms` — DoQ keepalive interval (default: 15000)
- `doq_enable_0rtt` — Enable DoQ 0-RTT with auto-detection (default: true)
- `flow_control_initial_permits` — Initial flow control permits (default: 500)
- `flow_control_min_permits` — Minimum permits (default: 100)
- `flow_control_max_permits` — Maximum permits (default: 800)
- `flow_control_latency_threshold_ms` — Latency alarm threshold (default: 100)
- `flow_control_adjustment_interval_secs` — Adjustment interval (default: 5)
- `cache_background_refresh` — Enable background cache refresh (default: false)
- `cache_refresh_threshold_percent` — Refresh threshold as % of remaining TTL (default: 10)
- `cache_refresh_min_ttl` — Minimum TTL for background refresh (default: 5)
- `serve_stale` — Enable RFC 8767 stale cache (default: false)
- `serve_stale_ttl` — TTL for stale responses (default: 30)
- `serve_stale_expire_ttl` — Max stale window in seconds (default: 86400)
- `serve_stale_ttl_reset` — Reset stale timer on each serve (default: true)
- `serve_stale_client_timeout_ms` — Try upstream before serving stale (default: 0)
- `geoip_db_path` — Path to GeoIP MMDB database
- `geoip_cache_capacity` — GeoIP lookup cache capacity (default: 10000)
- `geoip_cache_ttl` — GeoIP cache TTL in seconds (default: 3600)
- `geosite_data_paths` — Array of V2Ray GeoSite data file paths

### Matcher Types

#### Pipeline Select Matchers

| Type | Parameter | Description |
|------|-----------|-------------|
| `listener_label` | `value` | Match listener label |
| `client_ip` | `cidr` | Match client IP CIDR |
| `domain_suffix` | `value` | Match domain suffix |
| `domain_regex` | `value` | Match domain regex |
| `qclass` | `value` | Match QCLASS (IN/CH/HS) |
| `edns_present` | `expect` | Check EDNS presence (true/false) |
| `geosite` | `value` | Match GeoSite category |
| `geosite_not` | `value` | Negative GeoSite match |
| `any` | — | Match anything |

#### Request Matchers

Same as Pipeline Select, plus:

| Type | Parameter | Description |
|------|-----------|-------------|
| `geoip_country` | `country_codes` | Match client IP country (CN, US, etc.) |
| `geoip_private` | `expect` | Match private/internal IPs |

#### Response Matchers

| Type | Parameter | Description |
|------|-----------|-------------|
| `upstream_equals` | `value` | Exact upstream string match |
| `request_domain_suffix` | `value` | Request domain suffix match |
| `request_domain_regex` | `value` | Request domain regex match |
| `response_upstream_ip` | `cidr` | Upstream IP CIDR match |
| `response_answer_ip` | `cidr` | Answer section IP CIDR match |
| `response_type` | `value` | Record type match (A/AAAA/CNAME) |
| `response_rcode` | `value` | RCODE match (NOERROR/NXDOMAIN) |
| `response_qclass` | `value` | QCLASS match |
| `response_edns_present` | `expect` | EDNS presence check |

### Action Types

| Type | Parameters | Description |
|------|------------|-------------|
| `log` | `level`, `message` | Log message |
| `static_response` | `rcode` | Return static RCODE |
| `static_ip_response` | `rcode`, `ips` | Return static IP response |
| `jump_to_pipeline` | `pipeline` | Jump to another pipeline |
| `allow` | — | Accept current response |
| `deny` | — | Return REFUSED |
| `forward` | `upstream`, `transport` | Forward to upstream |
| `continue` | — | Continue to next rule |

**Transport options**: `udp`, `tcp`, `tcp_udp`, `doh`, `dot`, `doq` (can be omitted when upstream URL has protocol prefix)

**URL prefixes**: `udp://`, `tcp://`, `tcp+udp://`, `doh://`, `https://`, `dot://`, `tls://`, `doq://`, `quic://`

### Logical Operators

Matchers support logical composition:

| Operator | Description |
|----------|-------------|
| `and` | Logical AND (default) |
| `or` | Logical OR |
| `and_not` | AND NOT |
| `or_not` | OR NOT |
| `not` | NOT |

## Examples

### Basic GeoIP Routing

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

### GeoSite Domain Routing

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

### DNS Pollution Filtering

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

### DoQ with 0-RTT

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

## Tech Stack

- **tokio** — async runtime
- **hickory-proto** — DNS protocol
- **moka** — high-performance cache
- **dashmap** — concurrent hashmap
- **rustc-hash** — fast hashing (FxHash)
- **quinn** — QUIC/DoQ transport
- **reqwest** — HTTP/DoH client
- **tokio-rustls** — TLS for DoT/DoQ
- **maxminddb** — GeoIP MMDB lookups
- **arc-swap** — lock-free config hot-reload
- **notify** — filesystem change detection
- **clap** — CLI argument parsing
- **tracing** — structured logging

## Tools

- `tools/config_editor.html` — Browser-based pipeline configuration editor
- `tools/diagnose.html` — WebSocket-based DNS query diagnostic tool

## Building from Source

**Requirements**: Rust 1.82+ (edition 2024)

```bash
git clone https://github.com/olicesx/kixdns.git
cd kixdns
cargo build --release
```

Release profile uses `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, and `strip = true` for maximum performance.

## License

[GPL-3.0](LICENSE)
