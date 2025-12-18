# KixDNS v0.1.0 Release Notes

## Overview

We are excited to announce the first official release of **KixDNS v0.1.0** - a high-performance, extensible DNS server written in Rust!

KixDNS is designed for low-latency, high-concurrency scenarios with complex routing requirements. Built entirely with AI assistance, this project showcases modern DNS server capabilities with a focus on performance and flexibility.

## Key Features

### 🚀 High Performance
- **Zero-copy networking**: UDP packet handling with `BytesMut` minimizes memory copying
- **Lazy request parsing**: Avoids full deserialization in simple forwarding scenarios
- **Fast hashing**: Uses `FxHash` (rustc-hash) for optimal hash performance
- **High concurrency**: Built on `tokio` async runtime with concurrent data structures

### 🎯 Flexible Architecture
- **Pipeline processing**: Independent processing pipelines for different listeners
- **Advanced routing**: Match on domain (exact/wildcard/regex), client IP, query type
- **Response actions**: Rewrite TTL, return static responses, reject, or forward
- **Load balancing**: Multiple upstream resolvers with failover support

### 💾 Caching & Deduplication
- **Memory cache**: High-performance caching with `moka`
- **Smart TTL**: Respects upstream TTL with configurable minimums
- **Singleflight**: Deduplicates concurrent identical requests

### 🔧 Configuration & Operations
- **JSON configuration**: Easy-to-understand configuration format
- **Hot reload**: Reload configuration without restart (SIGHUP)
- **Visual editor**: Browser-based configuration editor included
- **Comprehensive logging**: JSON and text output with tracing support

## Platform Support

Pre-built binaries are available for:
- **Linux**: x86_64, ARM64
- **FreeBSD**: x86_64, ARM64

## Download

Download the appropriate binary for your platform from the [releases page](https://github.com/olicesx/kixdns/releases/tag/v0.1.0).

### Verification

Each release includes SHA256 checksums. Verify your download:

```bash
sha256sum -c kixdns-linux-x86_64.tar.gz.sha256
```

## Quick Start

```bash
# Extract the archive
tar xzf kixdns-linux-x86_64.tar.gz

# Run with a configuration file
./kixdns --config config/pipeline_local.json
```

## What's Next

This is our initial release, and we're excited to continue improving KixDNS. Future enhancements may include:
- Additional protocol support (DoH, DoT)
- More advanced caching strategies
- Enhanced metrics and monitoring
- Additional routing capabilities

## Documentation

Full documentation is available in the [README.md](https://github.com/olicesx/kixdns/blob/main/README.md).

## Contributing

We welcome contributions! Please feel free to submit issues and pull requests.

## License

KixDNS is licensed under the GNU General Public License v3.0 (GPL-3.0). See the [LICENSE](https://github.com/olicesx/kixdns/blob/main/LICENSE) file for details.

---

**Note**: This project was entirely built by AI, including content, documentation, and initial implementation.
