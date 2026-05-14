use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing::error;

// ============================================================================
// CLI argument definitions
// ============================================================================

#[derive(Parser, Debug)]
#[command(author, version, about = "KixDNS async DNS with hot-reload pipelines", long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run DNS server / 运行 DNS 服务器
    Run {
        /// 配置文件路径（JSON） / Config file path (JSON)
        #[arg(short = 'c', long = "config", default_value = "config/pipeline.json")]
        config: PathBuf,
        /// 监听实例标签，用于 pipeline 选择（可选）。 / Listener instance label for pipeline selection (optional)
        #[arg(long = "listener-label", default_value = "default")]
        listener_label: String,
        /// 启用调试日志 / Enable debug logging
        #[arg(long = "debug", default_value_t = false)]
        debug: bool,
        /// UDP worker 数量（默认 CPU 核心数） / Number of UDP workers (defaults to CPU core count)
        #[arg(long = "udp-workers", default_value_t = 0)]
        udp_workers_count: usize,
    },
    /// Convert GeoIP .dat to MMDB format / 转换 GeoIP .dat 为 MMDB 格式
    ConvertGeoIp {
        /// 输入 .dat 文件路径 / Input .dat file path
        #[arg(short = 'i', long = "input")]
        input: PathBuf,
        /// 输出 MMDB 文件路径 / Output MMDB file path
        #[arg(short = 'o', long = "output")]
        output: PathBuf,
        /// 过滤国家代码（逗号分隔，如 CN,US,JP）/ Filter country codes (comma-separated, e.g., CN,US,JP)
        #[arg(short = 'f', long = "filter")]
        filter: Option<String>,
    },
    /// Manage system service (install/uninstall/run) / 系统服务管理（安装/卸载/运行）
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand, Debug)]
enum ServiceAction {
    /// Install KixDNS as a system service / 安装为系统服务
    Install {
        /// 配置文件路径（JSON） / Config file path (JSON)
        #[arg(short = 'c', long = "config", default_value = "config/pipeline.json")]
        config: PathBuf,
        /// 监听实例标签 / Listener instance label
        #[arg(long = "listener-label", default_value = "default")]
        listener_label: String,
    },
    /// Uninstall KixDNS system service / 卸载系统服务
    Uninstall,
    /// Run as system service (used by init system, not for direct use) / 以服务方式运行（供 init 系统内部使用）
    Run {
        /// 配置文件路径（JSON） / Config file path (JSON)
        #[arg(short = 'c', long = "config", default_value = "config/pipeline.json")]
        config: PathBuf,
        /// 监听实例标签 / Listener instance label
        #[arg(long = "listener-label", default_value = "default")]
        listener_label: String,
    },
}

// ============================================================================
// Entry point
// ============================================================================
//
// We do NOT use #[tokio::main] here because the Windows service path must call
// `service_dispatcher::start` from the main thread (it blocks forever). We
// manually create the tokio runtime only when running in console mode.
//
// 我们在此处不使用 #[tokio::main]，因为 Windows 服务路径须在主线程调用
// `service_dispatcher::start`（它会永久阻塞）。仅在控制台模式下才手动创建 tokio 运行时。
// ============================================================================
fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    match args.command {
        // ---- System service management ----
        Some(Commands::Service { action }) => match action {
            ServiceAction::Install {
                config,
                listener_label,
            } => kixdns::service::install_service(&config, &listener_label),
            ServiceAction::Uninstall => kixdns::service::uninstall_service(),
            ServiceAction::Run {
                config,
                listener_label,
            } => {
                // Blocks on Windows (SCM dispatcher), sets up signal handlers on Unix.
                // Windows：阻塞主线程（SCM 分发）；
                // Unix：设置信号处理。
                kixdns::service::run_service(config, listener_label)
            }
        },

        // ---- Convert GeoIP ----
        Some(Commands::ConvertGeoIp {
            input,
            output,
            filter,
        }) => convert_geoip(input, output, filter),

        // ---- Run DNS server (console mode) ----
        Some(Commands::Run {
            config,
            listener_label,
            debug,
            udp_workers_count,
        }) => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to build tokio runtime")?;
            rt.block_on(kixdns::run_dns_server(
                config,
                listener_label,
                debug,
                udp_workers_count,
            ))
        }

        // ---- Default: no subcommand → run DNS server ----
        None => {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("failed to build tokio runtime")?;
            rt.block_on(kixdns::run_dns_server(
                PathBuf::from("config/pipeline.json"),
                "default".to_string(),
                false,
                0,
            ))
        }
    }
}

// ============================================================================
// GeoIP conversion (synchronous helper)
// ============================================================================
fn convert_geoip(input: PathBuf, output: PathBuf, filter: Option<String>) -> anyhow::Result<()> {
    let filter_countries: Option<Vec<String>> =
        filter.map(|f| f.split(',').map(|s| s.trim().to_uppercase()).collect());
    let filter_slice = filter_countries.as_deref();

    match kixdns::matcher::geoip::GeoIpManager::convert_dat_to_mmdb(&input, &output, filter_slice) {
        Ok(stats) => {
            println!("Conversion completed successfully:\n{}", stats);
            Ok(())
        }
        Err(e) => {
            error!("Conversion failed: {}", e);
            Err(e)
        }
    }
}
