// Socket utility functions with safe wrappers for FFI calls
// Socket 工具函数，为 FFI 调用提供安全封装

#[cfg(unix)]
use socket2::Socket;
use std::io;

#[cfg(unix)]
use std::os::fd::AsRawFd;

/// Safely set IPV6_V6ONLY option on a socket
/// 安全地设置 socket 的 IPV6_V6ONLY 选项
///
/// # Arguments
/// * `socket` - The socket to configure
/// * `enabled` - Whether to enable IPV6_V6ONLY (true = IPv6 only, false = dual-stack)
///
/// # Returns
/// * `Ok(())` - Option set successfully
/// * `Err(io::Error)` - Failed to set option (non-fatal, logged as warning)
#[cfg(unix)]
#[inline]
pub fn set_ipv6_v6only(socket: &Socket, enabled: bool) -> io::Result<()> {
    use libc::{c_int, setsockopt, socklen_t, IPPROTO_IPV6, IPV6_V6ONLY};

    let val: c_int = if enabled { 1 } else { 0 };
    let fd = socket.as_raw_fd();

    let ret = unsafe {
        setsockopt(
            fd,
            IPPROTO_IPV6,
            IPV6_V6ONLY,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Safely set SO_REUSEPORT option on a socket
/// 安全地设置 socket 的 SO_REUSEPORT 选项
///
/// # Arguments
/// * `socket` - The socket to configure
/// * `enabled` - Whether to enable SO_REUSEPORT
///
/// # Returns
/// * `Ok(())` - Option set successfully
/// * `Err(io::Error)` - Failed to set option or not supported
#[cfg(unix)]
#[inline]
pub fn set_reuseport(socket: &Socket, enabled: bool) -> io::Result<()> {
    use libc::{c_int, setsockopt, socklen_t, SOL_SOCKET, SO_REUSEPORT};

    let val: c_int = if enabled { 1 } else { 0 };
    let fd = socket.as_raw_fd();

    let ret = unsafe {
        setsockopt(
            fd,
            SOL_SOCKET,
            SO_REUSEPORT,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as socklen_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Non-Unix stub implementations (Windows and other platforms)
/// 非 Unix 系统的存根实现（Windows 和其他平台）
#[cfg(not(unix))]
#[allow(dead_code)] // Stub implementations for cross-platform compatibility
#[inline]
pub fn set_ipv6_v6only(_socket: &socket2::Socket, _enabled: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "IPV6_V6ONLY not supported on this platform",
    ))
}

#[cfg(not(unix))]
#[allow(dead_code)] // Stub implementation for cross-platform compatibility
#[inline]
pub fn set_reuseport(_socket: &socket2::Socket, _enabled: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT not supported on this platform",
    ))
}
