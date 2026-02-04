// Error handling utilities for better error propagation
// 错误处理工具，提供更好的错误传播

/// Helper macro for safe parsing with context
/// 用于带上下文的安全解析的辅助宏
///
/// # Usage
/// ```rust
/// let ip = safe_parse!("8.8.8.8", IpAddr);
/// let net = safe_parse!("1.2.3.0/24", IpNet);
/// ```
#[macro_export]
macro_rules! safe_parse {
    ($expr:expr, $type:ty) => {
        $expr
            .parse::<$type>()
            .with_context(|| format!("Failed to parse '{}' as {}", $expr, stringify!($type)))
    };
    ($expr:expr, $type:ty, $context:expr) => {
        $expr.parse::<$type>().with_context(|| {
            format!(
                "{}: failed to parse '{}' as {}",
                $context,
                $expr,
                stringify!($type)
            )
        })
    };
}

/// Helper macro for safe IP parsing with default fallback
/// 用于带默认回退的安全 IP 解析的辅助宏
///
/// # Usage
/// ```rust
/// let ip = safe_parse_ip!("8.8.8.8", IpAddr::V4(Ipv4Addr::UNSPECIFIED));
/// ```
#[macro_export]
macro_rules! safe_parse_ip {
    ($expr:expr, $default:expr) => {
        $expr.parse::<std::net::IpAddr>().unwrap_or($default)
    };
}

/// Helper for Result type with logging instead of panic
/// 用于 Result 类型的辅助，使用日志而不是 panic
///
/// # Usage
/// ```rust
/// let result = safe_unwrap!(some_operation(), "Failed to do something");
/// ```
#[macro_export]
macro_rules! safe_unwrap {
    ($expr:expr, $context:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("{}: {:?}", $context, e);
                return Err(e.into());
            }
        }
    };
}

/// Helper for Option type with custom error
/// 用于 Option 类型的辅助，使用自定义错误
///
/// # Usage
/// ```rust
/// let value = safe_some!(some_option, "Missing required value");
/// ```
#[macro_export]
macro_rules! safe_some {
    ($expr:expr, $context:expr) => {
        $expr.ok_or_else(|| anyhow::anyhow!($context))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn test_safe_parse() {
        let result = safe_parse!("8.8.8.8", std::net::IpAddr);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "8.8.8.8".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn test_safe_parse_with_context() {
        let result = safe_parse!("invalid", std::net::IpAddr, "Invalid IP address");
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_parse_ip() {
        let ip = safe_parse_ip!(
            "8.8.8.8",
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(ip, "8.8.8.8".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn test_safe_parse_ip_invalid() {
        let ip = safe_parse_ip!(
            "invalid",
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }
}
