use std::sync::Arc;
use std::net::IpAddr;
use hickory_proto::rr::DNSClass;
use hickory_proto::rr::RecordType;
use tracing;

use crate::lock::RwLock;
use crate::matcher::RuntimeMatcher;
use crate::matcher::geoip::GeoIpManager;
use crate::matcher::geosite::GeoSiteManager;

/// Context for matcher evaluation
/// Groups related parameters to reduce function argument count
pub struct MatcherContext<'a> {
    pub qname: &'a str,
    pub qclass: DNSClass,
    pub client_ip: IpAddr,
    pub edns_present: bool,
    pub qtype: RecordType,
    pub geoip_manager: Option<&'a Arc<RwLock<GeoIpManager>>>,
    pub geosite_manager: Option<&'a Arc<RwLock<GeoSiteManager>>>,
}

pub fn matcher_matches(matcher: &RuntimeMatcher, ctx: &MatcherContext<'_>) -> bool {
    // 直接传递 Arc<RwLock<T>>，让 matches_with_qtype 内部按需获取锁
    // Pass Arc<RwLock<T>> directly, let matches_with_qtype acquire locks on-demand
    matcher.matches_with_qtype(
        ctx.qname,
        ctx.qclass,
        ctx.client_ip,
        ctx.edns_present,
        ctx.qtype,
        ctx.geoip_manager,
        ctx.geosite_manager,
    )
}

pub fn log_match(level: Option<&str>, rule_name: &str, qname: &str, client_ip: IpAddr) {
    match level.unwrap_or("info") {
        "trace" => {
            tracing::trace!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "trace")
        }
        "debug" => {
            tracing::debug!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "debug")
        }
        "warn" => {
            tracing::warn!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "warn")
        }
        "error" => {
            tracing::error!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "error")
        }
        _ => {
            tracing::info!(event = "matcher_log", rule = %rule_name, qname = %qname, client_ip = %client_ip, level = "info")
        }
    }
}
