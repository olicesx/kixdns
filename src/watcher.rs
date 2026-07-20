use std::path::{Path, PathBuf};
use std::thread;

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{error, info, warn};

use crate::config;
use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

pub fn spawn(path: PathBuf, engine: Engine) {
    // 使用阻塞线程持有watcher，避免异步生命周期问题。 / Use blocking thread to hold watcher, avoiding async lifetime issues.
    thread::spawn(move || {
        if let Err(err) = run_watcher(path, engine) {
            error!(target = "watcher", error = %err, "config watcher exited with error");
        }
    });
}

fn run_watcher(path: PathBuf, engine: Engine) -> notify::Result<()> {
    // Watch the parent directory instead of the file itself,
    // so that atomic replacement (mv newfile config.yml) is properly detected.
    // Linux inotify watches inodes, not paths; watching the parent directory
    // captures IN_MOVED_TO/IN_CREATE events for the target filename.
    let parent_dir = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let target_file_name = path
        .file_name()
        .map(|s| s.to_os_string())
        .unwrap_or_default();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default())?;
    watcher.watch(&parent_dir, RecursiveMode::NonRecursive)?;

    info!(target = "watcher", path = %parent_dir.display(), filename = ?target_file_name, "config watcher started (watching parent directory for atomic replacement support)");

    for res in rx {
        match res {
            Ok(event) => {
                // Check if the event is for the file we care about
                let is_target_file = event
                    .paths
                    .iter()
                    .any(|p| p.file_name() == Some(&target_file_name));
                if !is_target_file {
                    continue;
                }

                // Only reload on data changes / 仅在数据更改时重载
                if !event.kind.is_modify() && !event.kind.is_create() {
                    continue;
                }

                // Simple retry mechanism to handle file write races (e.g. truncate+write) / 简单的重试机制来处理文件写入竞争（如截断+写入）
                let mut retries = 5;
                while retries > 0 {
                    match config::load_config(&path).and_then(RuntimePipelineConfig::from_config) {
                        Ok(new_cfg) => {
                            engine.reload(new_cfg);
                            info!(target = "watcher", path = %path.display(), "config reloaded");
                            break;
                        }
                        Err(err) => {
                            retries -= 1;
                            if retries == 0 {
                                warn!(target = "watcher", path = %path.display(), error = %err, "config reload failed, keeping old config");
                            } else {
                                // Wait a bit and retry / 稍等后重试
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                        }
                    }
                }
            }
            Err(err) => {
                warn!(target = "watcher", error = %err, "watcher event error");
            }
        }
    }
    Ok(())
}
