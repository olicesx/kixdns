# Changelog

All notable changes to KixDNS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-12-18

### Added
- Initial release of KixDNS - High-performance DNS server written in Rust
- Zero-copy network processing using `BytesMut` for UDP packet handling
- Lazy request parsing to avoid full deserialization in forwarding scenarios
- Lightweight response parsing for fast RCODE and minimum TTL extraction
- Fast hashing with `FxHash` (rustc-hash) for internal data structures
- High concurrency with `tokio` async IO, `DashMap`, and `moka` for state management
- Pipeline processing architecture with independent processing pipelines per listener
- Advanced routing based on domain (exact, wildcard, regex), client IP, and query type
- Response actions: TTL rewriting, static responses, rejection, forwarding
- Upstream load balancing and failover strategies
- High-performance memory cache with `moka`
- Smart TTL handling respecting upstream TTL with configurable minimum TTL
- Request deduplication (singleflight) to prevent cache stampede
- Configuration via JSON files with hot-reload support
- Support for UDP and TCP listeners
- Multiple platform support:
  - Linux (x86_64, ARM64)
  - FreeBSD (x86_64, ARM64)
- Built-in configuration editor tool (`tools/config_editor.html`)
- Comprehensive logging with tracing and JSON output support
- Signal handling for graceful shutdown and configuration reload

### Performance Features
- Quick-parse EDNS support for minimal overhead
- Zero-allocation cache hit path
- Safe UDP receive buffer handling
- Optimized logging for high-throughput scenarios
- Fast-path response handling for UDP workers

### Documentation
- Comprehensive README with feature descriptions
- Build and deployment instructions
- Configuration examples
- systemd service example
- Docker deployment example

[0.1.0]: https://github.com/olicesx/kixdns/releases/tag/v0.1.0
