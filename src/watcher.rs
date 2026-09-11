use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{error, info, warn};

use crate::config;
use crate::engine::Engine;
use crate::matcher::RuntimePipelineConfig;

/// Reload attempts before giving up, and the delay between attempts —
/// rides out non-atomic writes (e.g. truncate+write) observed mid-way.
const RELOAD_RETRIES: u32 = 5;
const RELOAD_RETRY_DELAY: Duration = Duration::from_millis(100);

pub fn spawn(path: PathBuf, engine: Engine) {
    // 使用阻塞线程持有watcher，避免异步生命周期问题。 / Use blocking thread to hold watcher, avoiding async lifetime issues.
    thread::spawn(move || {
        let result = run_files_watcher(std::slice::from_ref(&path), || {
            if let Some(new_cfg) = load_with_retry("config", || {
                config::load_config(&path).and_then(RuntimePipelineConfig::from_config)
            }) {
                engine.reload(new_cfg);
                info!(target = "watcher", path = %path.display(), "config reloaded");
            }
        });
        if let Err(err) = result {
            error!(target = "watcher", error = %err, "config watcher exited with error");
        }
    });
}

/// Watch the given files and invoke `on_change` whenever any of them is created
/// or its data modified. Each file is watched through its parent directory so
/// atomic replacement (write tmp + rename over target) is detected: Linux
/// inotify watches inodes, not paths, and the parent directory captures
/// IN_MOVED_TO/IN_CREATE for the target filename.
///
/// Blocking — pumps events until the internal channel closes; run it on a
/// dedicated thread. Used for both config hot-reload and DoH TLS certificate
/// reload; the reload action itself belongs to the `on_change` callback.
pub(crate) fn run_files_watcher(
    paths: &[PathBuf],
    mut on_change: impl FnMut(),
) -> notify::Result<()> {
    // (parent directory, watched filename) per target path
    let targets: Vec<(PathBuf, std::ffi::OsString)> = paths
        .iter()
        .map(|p| {
            (
                p.parent().unwrap_or_else(|| Path::new(".")).to_path_buf(),
                p.file_name().map(|s| s.to_os_string()).unwrap_or_default(),
            )
        })
        .collect();

    let (tx, rx) = std::sync::mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Config::default())?;
    let mut watched_parents: HashSet<PathBuf> = HashSet::new();
    for (parent, _) in &targets {
        // cert and key often live in the same directory; watch it once
        if watched_parents.insert(parent.clone()) {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
        }
    }

    info!(target = "watcher", files = ?paths, "file watcher started (watching parent directories for atomic replacement support)");

    for res in rx {
        match res {
            Ok(event) => {
                // Only reload on data changes / 仅在数据更改时触发回调
                if !event.kind.is_modify() && !event.kind.is_create() {
                    continue;
                }

                let is_target_file = event
                    .paths
                    .iter()
                    .any(|p| targets.iter().any(|(_, name)| p.file_name() == Some(name)));
                if is_target_file {
                    on_change();
                }
            }
            Err(err) => {
                warn!(target = "watcher", error = %err, "watcher event error");
            }
        }
    }
    Ok(())
}

/// Retry `load` on failure so partially-written files are not mistaken for
/// broken content. Returns `None` (and logs) once all attempts fail, letting
/// the caller keep its current state instead of adopting a broken file.
pub(crate) fn load_with_retry<T>(
    what: &str,
    mut load: impl FnMut() -> anyhow::Result<T>,
) -> Option<T> {
    let mut retries = RELOAD_RETRIES;
    loop {
        match load() {
            Ok(value) => return Some(value),
            Err(err) => {
                retries -= 1;
                if retries == 0 {
                    warn!(target = "watcher", what = %what, error = %err, "reload failed, keeping current state");
                    return None;
                }
                thread::sleep(RELOAD_RETRY_DELAY);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The watcher fires `on_change` when a watched file is atomically replaced
    /// (write sibling tmp + rename over target) and reports it exactly per event.
    #[test]
    fn run_files_watcher_detects_atomic_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = std::sync::mpsc::channel();
        let watched = target.clone();
        let signal = tx.clone();
        // The watcher pumps events until the process exits by design, so the
        // thread is never joined here — assert via the channel instead.
        thread::spawn(move || {
            let _ = run_files_watcher(std::slice::from_ref(&watched), || {
                let _ = signal.send(());
            });
        });

        // The watcher thread may not have registered its watch() yet when the
        // first swap lands, so re-swap until the resulting event is observed.
        let mut fired = false;
        for _ in 0..20 {
            let tmp = dir.path().join("target.renew.tmp");
            std::fs::write(&tmp, "v2").expect("write tmp");
            std::fs::rename(&tmp, &target).expect("atomic rename");
            if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
                fired = true;
                break;
            }
        }
        assert!(fired, "on_change must fire on atomic replacement");
    }

    /// Events for sibling files (e.g. the tmp side of an atomic replace) must
    /// not trigger `on_change`.
    #[test]
    fn run_files_watcher_ignores_unrelated_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.file");
        std::fs::write(&target, "v1").expect("seed file");

        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let watched = target.clone();
        let signal = tx.clone();
        let _handle = thread::spawn(move || {
            let _ = run_files_watcher(std::slice::from_ref(&watched), || {
                signal.send(()).ok();
            });
        });

        thread::sleep(Duration::from_millis(300));
        // Only the sibling changes; the watched file stays untouched.
        std::fs::write(dir.path().join("target.renew.tmp"), "other").expect("write sibling");

        let fired = rx.recv_timeout(Duration::from_secs(2));
        assert!(
            fired.is_err(),
            "on_change must not fire for unrelated files"
        );
    }

    /// A load closure that always fails is retried, then reported as None so
    /// the caller keeps its current state.
    #[test]
    fn load_with_retry_gives_up_after_bounded_attempts() {
        let mut attempts = 0u32;
        let result: Option<()> = load_with_retry("unit-test", || {
            attempts += 1;
            Err(anyhow::anyhow!("persistent failure"))
        });
        assert!(result.is_none(), "persistent failure must return None");
        assert_eq!(
            attempts, RELOAD_RETRIES,
            "must attempt exactly RELOAD_RETRIES times"
        );
    }
}
