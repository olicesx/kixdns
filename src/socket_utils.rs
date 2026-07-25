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
    use libc::{IPPROTO_IPV6, IPV6_V6ONLY, c_int, setsockopt, socklen_t};

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
    use libc::{SO_REUSEPORT, SOL_SOCKET, c_int, setsockopt, socklen_t};

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

/// Set SO_REUSEPORT with kernel-level load balancing for multi-worker UDP.
/// 为多 worker UDP 设置带内核级负载均衡的 SO_REUSEPORT。
///
/// On FreeBSD, `SO_REUSEPORT` allows multiple sockets to bind to the same port
/// but does NOT distribute incoming packets — all traffic goes to one socket.
/// `SO_REUSEPORT_LB` (0x00010000) is FreeBSD's separate option that enables
/// hash-based packet distribution across sockets in the reuseport group.
/// 为多 worker UDP 设置带内核级负载均衡的 SO_REUSEPORT。
///
/// On Linux, `SO_REUSEPORT` already includes hash-based distribution, so we
/// use it directly.
/// 在 Linux 上，`SO_REUSEPORT` 已包含哈希分发功能，直接使用即可。
///
/// # Arguments
/// * `socket` - The socket to configure
///
/// # Returns
/// * `Ok(())` - Option set successfully
/// * `Err(io::Error)` - Failed to set option or not supported
#[cfg(unix)]
#[inline]
pub fn set_reuseport_lb(socket: &Socket) -> io::Result<()> {
    use libc::{SOL_SOCKET, c_int, setsockopt, socklen_t};
    use std::os::fd::AsRawFd;

    let val: c_int = 1;
    let fd = socket.as_raw_fd();

    // FreeBSD: SO_REUSEPORT_LB (0x00010000) enables hash-based load balancing
    // FreeBSD: SO_REUSEPORT_LB (0x00010000) 启用基于哈希的负载均衡
    #[cfg(target_os = "freebsd")]
    {
        const SO_REUSEPORT_LB: c_int = 0x00010000;
        let ret = unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_REUSEPORT_LB,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as socklen_t,
            )
        };
        if ret == 0 {
            return Ok(());
        }
        // Fall back to plain SO_REUSEPORT if LB variant fails
        // 如果 LB 变体失败，回退到普通 SO_REUSEPORT
    }

    // Linux and fallback: plain SO_REUSEPORT already does load balancing on Linux
    // Linux 和回退：普通 SO_REUSEPORT 在 Linux 上已自带负载均衡
    use libc::SO_REUSEPORT;
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

#[cfg(not(unix))]
#[inline]
pub fn set_reuseport_lb(_socket: &socket2::Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "SO_REUSEPORT_LB not supported on this platform",
    ))
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
