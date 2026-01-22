# Commit Messages Translation Document

This document provides English translations for commits that originally contained Chinese text.

## Overview

This document serves as a reference for understanding the work done in commits with non-English messages. All future commits should use English-only messages following conventional commit format.

## Commits Documented

### 1. SERVFAIL/REFUSED Rejection in Concurrent Forwarding (b8ed0e2)

**Problem:** Previous concurrent forward implementation returned on network success regardless of DNS response code.

**Solution:** Check DNS response code, reject SERVFAIL and REFUSED, continue waiting for other upstreams.

**Key Changes:**
- Response code handling strategy in src/engine.rs:2012-2026
- NOERROR: Accept immediately
- SERVFAIL/REFUSED: Reject, continue waiting
- NXDOMAIN: Accept immediately (authoritative result)

**Design Rationale:**
- SERVFAIL indicates temporary failures (server config, backend unavailable, network issues)
- REFUSED indicates temporary rejections (server overload, rate limiting, ACL limits)
- NXDOMAIN is definitive, all authoritative DNS return same result

**Files:** tests/test_rcode_handling.rs, tests/test_concurrent_cancellation.rs

---

### 2. Concurrent Request Cancellation Documentation (e387313)

**Improvements:**
1. Explicit cancellation logging in src/engine.rs:2011-2022
2. Test framework in tests/test_concurrent_cancellation.rs

**Technical Details:**
- Cancellation flow: return res -> tasks dropped -> JoinHandles dropped -> tokio::task::abort() -> task stops
- Can be cancelled: waiting responses, unstarted operations, async block logic
- Cannot be cancelled: sent packets, established TCP connections, sent UDP requests

---

### 3. Multiple Forward Actions Merge with Transport Deduplication (aa51b79)

**Problem Fixes:**
1. Multiple forward action merge logic refactoring
2. Support protocol prefixes (tcp://, udp://)
3. Decision::Forward.transport type changed to Option<Transport>

**Key Changes:**
- Merge by transport type (TCP/UDP) separately with auto-deduplication
- Merged upstreams retain protocol prefixes
- Each upstream can decide transport via protocol prefix

**Files:** src/engine.rs (lines 1700-1783, 1929-1940)

---

### 4. GeoSite Matching, Cache Refresh, and Concurrent Forwarding Optimization (11228f0)

**GeoSite Suffix Matching Optimization:**
- Fix suffix matching to allow .github.com to match github.com
- Remove leading dot before matching
- File: src/geosite.rs

**Cache Background Refresh Fixes:**
- CacheEntry adds upstream field
- Background refresh uses original upstream
- Static DNS responses don't trigger background refresh
- Share Singleflight mechanism with user requests

**Concurrent Forward Optimization:**
- Pre-split upstream strings at config load time
- Enhanced concurrent logging

**Files:** src/cache.rs, src/engine.rs, src/config.rs, tests/regression_integration_test.rs

---

### 5. Upstream Splitting Optimization with Arc (7a1e9f0)

**Optimization:** Use Arc shared pre-split lists to eliminate runtime string splitting overhead.

**Main Changes:**
- Action::Forward and Decision::Forward add pre_split_upstreams field
- Pre-split at config load time, wrap with Arc for sharing
- forward_upstream() prioritizes pre-split data

**Performance:**
- One-time split at config load vs per-query splitting
- Arc zero-cost sharing
- Eliminates ~5% performance degradation

**Files:** src/config.rs, src/engine.rs, src/matcher.rs

---

### 6. Upstream Parsing Optimization (96543ad)

**Problem:** Every call to forward_upstream executes string splitting and Vec allocation, causing ~5% performance degradation.

**Optimization:**
- Check upstream.contains(',') for fast detection
- Single upstream: forward directly, no splitting
- Multiple upstream: only split when needed

**Performance:**
- Single upstream: near-zero overhead
- Multiple upstream: same as before

---

### 7. GeoSite/GeoIP Loading Optimization and Concurrent Forwarding (0997c82)

**Major Improvements:**
1. GeoSite/GeoIP selective loading
2. GeoIP loading logic optimization
3. True concurrent forwarding with FuturesUnordered
4. Web config tool updates

**Memory Savings:**
- ~58MB when not used
- ~35MB with selective loading

**Technical Details:**
- Use FuturesUnordered for true concurrency
- Support protocol prefixes and multiple upstreams
- Modified files: Cargo.toml, src/engine.rs, src/geosite.rs, tools/config_editor.html

---

### 8. Helper Functions Extraction and Send Trait Fixes (8515a90)

**Refactoring:**
- Matcher helpers module (match_geoip_country, match_geosite, collect_ips_from_message, any_ip_matches_nets)
- Engine helpers module (build_servfail_response, build_refused_response)
- Eliminated ~200 lines of duplicate code

**Concurrency Fixes:**
- Fix Send trait violations from MutexGuard spanning await points
- Use scoped blocks to ensure locks released immediately

**Test Enhancements:**
- 9 matcher helper unit tests
- 3 engine helper unit tests
- 4 integration tests
- Total: 69 tests passing

**API Changes:**
- RuntimeResponseMatcher::from_config made public
- engine_helpers module made public

---

### 9. GeoIP/GeoSite Cache Optimization and Pipeline Select (15bb43b)

**Cache Optimization:**
- Remove cache_capacity and cache_ttl parameters
- Auto-adjust cache size based on loaded entries
- GeoIP: entry_count × 2 (min 10k, max 1M)
- GeoSite: domain_count × 2 (min 10k, max 1M)

**Pipeline Selector Enhancement:**
- Add GeoIP/GeoIP matcher support
- Add GeoipCountry and GeoipPrivate matchers
- Enable client IP-based pipeline selection

**Performance Tests:**
- Latency: < 1μs per query
- Throughput: > 1.5M qps (concurrent)
- Cache hit rate: > 99%
- GeoIP: 0.30μs/query, 3.3M qps
- GeoSite: 0.16μs/query, 6.3M qps

---

## Guidelines for Future Commits

1. **Use English only** for all commit messages
2. **Follow conventional commit format:** type(scope): description
3. **Keep titles short** (< 72 characters)
4. **Separate title from body** with blank line
5. **Use imperative mood** ("fix" not "fixed", "add" not "added")
6. **Reference issues** in footer: "Fixes #123"
7. **Co-authorship** for AI assistance: "Co-Authored-By: ..."

## Commit Types

- **feat:** New feature
- **fix:** Bug fix
- **perf:** Performance improvement
- **refactor:** Code refactoring
- **docs:** Documentation only
- **test:** Test additions or changes
- **chore:** Maintenance tasks

## Example Good Commit

```
feat: implement concurrent upstream forwarding with SERVFAIL rejection

Add concurrent forwarding for multiple upstreams with intelligent
response code handling. Reject SERVFAIL and REFUSED responses to
automatically failover to healthy upstreams.

Key changes:
- Use FuturesUnordered for true concurrency
- Check response codes before accepting
- Reject SERVFAIL/REFUSED, continue waiting
- Accept NOERROR/NXDOMAIN immediately

Performance: 20-50ms latency reduction (P99)
Tests: 4 new integration tests passing

Fixes #123
Co-Authored-By: Assistant <assistant@example.com>
```

---

*This document was created to provide English translations for historical commits with non-English messages.*
