//! Cross-platform service management for KixDNS
//!
//! Provides the ability to install, uninstall, and run KixDNS as a system service
//! on Windows (SCM), Linux (systemd, OpenRC, Procd), and FreeBSD (BSD rc.d).
//!
//! 跨平台服务管理：支持在 Windows (SCM)、Linux (systemd/OpenRC/Procd)
//! 和 FreeBSD (BSD rc.d) 上安装、卸载和运行服务。

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(not(target_os = "windows"))]
pub mod unix;

// ============================================================================
// Common types
// ============================================================================

/// Detected init system on the current platform.
/// 检测到的当前平台的 init 系统。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    /// Windows Service Control Manager / Windows 服务控制管理器
    #[cfg(target_os = "windows")]
    Scm,
    /// systemd (most modern Linux distributions)
    Systemd,
    /// OpenRC (Gentoo, Alpine, etc.)
    OpenRc,
    /// Procd (OpenWrt)
    Procd,
    /// BSD rc.d (FreeBSD, etc.)
    BsdRc,
    /// Unknown — cannot auto-detect
    Unknown,
}

impl InitSystem {
    /// Human-readable description of this init system.
    pub fn description(&self) -> &'static str {
        match self {
            #[cfg(target_os = "windows")]
            InitSystem::Scm => "Windows Service Control Manager",
            InitSystem::Systemd => "systemd (Linux)",
            InitSystem::OpenRc => "OpenRC (Gentoo/Alpine Linux)",
            InitSystem::Procd => "Procd (OpenWrt)",
            InitSystem::BsdRc => "BSD rc.d (FreeBSD)",
            InitSystem::Unknown => "Unknown init system",
        }
    }
}

/// Detect the init system on the current machine.
///
/// Detection order:
/// 1. Windows → SCM
/// 2. procd (/sbin/procd) → OpenWrt
/// 3. systemd (/usr/lib/systemd/systemd) → systemd
/// 4. openrc-run (/sbin/openrc-run) → OpenRC
/// 5. target_os = "freebsd" → BSD rc.d
/// 6. Otherwise → Unknown
///
/// 检测当前机器上的 init 系统。
pub fn detect_init_system() -> InitSystem {
    #[cfg(target_os = "windows")]
    {
        return InitSystem::Scm;
    }

    #[cfg(not(target_os = "windows"))]
    {
        // Procd (OpenWrt)
        if std::path::Path::new("/sbin/procd").exists() {
            return InitSystem::Procd;
        }
        // systemd
        if std::path::Path::new("/usr/lib/systemd/systemd").exists()
            || std::path::Path::new("/lib/systemd/systemd").exists()
        {
            return InitSystem::Systemd;
        }
        // OpenRC
        if std::path::Path::new("/sbin/openrc-run").exists() {
            return InitSystem::OpenRc;
        }
        // FreeBSD
        #[cfg(target_os = "freebsd")]
        {
            return InitSystem::BsdRc;
        }
        InitSystem::Unknown
    }
}

// ============================================================================
// Top-level API (delegates to platform-specific modules)
// ============================================================================

/// Install KixDNS as a system service.
///
/// On Windows: registers with SCM.
/// On Unix: auto-detects the init system and installs the appropriate service file.
///
/// 安装 KixDNS 为系统服务。
pub fn install_service(config: &std::path::PathBuf, listener_label: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::install_service(config, listener_label)
    }

    #[cfg(not(target_os = "windows"))]
    {
        unix::install_service(config, listener_label)
    }
}

/// Uninstall KixDNS system service.
///
/// On Windows: removes from SCM database.
/// On Unix: auto-detects the init system and removes the appropriate service file.
///
/// 卸载 KixDNS 系统服务。
pub fn uninstall_service() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::uninstall_service()
    }

    #[cfg(not(target_os = "windows"))]
    {
        unix::uninstall_service()
    }
}

/// Run KixDNS as a service (platform-specific).
///
/// On Windows: dispatches via SCM with proper event handling.
/// On Unix: runs the DNS server with a signal-based shutdown handler.
///
/// 以服务方式运行 KixDNS（平台相关）。
pub fn run_service(config: std::path::PathBuf, listener_label: String) -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows::run_service_dispatcher(config, listener_label)
    }

    #[cfg(not(target_os = "windows"))]
    {
        unix::run_service(config, listener_label)
    }
}
