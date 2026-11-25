//! Shared helpers for `os-native` integration tests.

use os_native::{ExecOutput, NativeBootConfig, NativeOsHost};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

static BUNDLE_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Locate a verified signed Release v2 bundle for tests (checks `OS_NATIVE_TEST_BUNDLE`,
/// then `/tmp/os-native-test-bundle`).
pub fn test_bundle_dir() -> PathBuf {
    BUNDLE_PATH
        .get_or_init(|| {
            if let Ok(env_dir) = std::env::var("OS_NATIVE_TEST_BUNDLE") {
                let p = PathBuf::from(env_dir);
                if p.join("release.json").is_file() {
                    return p;
                }
            }
            let tmp = PathBuf::from("/tmp/os-native-test-bundle");
            if tmp.join("release.json").is_file() && tmp.join("publisher.json").is_file() {
                return tmp;
            }
            panic!(
                "signed Release v2 bundle not found: set OS_NATIVE_TEST_BUNDLE or assemble /tmp/os-native-test-bundle via `cargo xtask boot` + `cargo xtask sign`"
            );
        })
        .clone()
}

/// RAII temporary directory automatically deleted when dropped.
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let mut raw = [0u8; 8];
        let _ = os_native::dev_backend::fill_os_random(&mut raw);
        let hex = os_image::hex(&raw);
        let path = std::env::temp_dir().join(format!("os-native-test-{prefix}-{hex}"));
        std::fs::create_dir_all(&path).expect("create temp test dir");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Boot a fresh `NativeOsHost` against the signed Release v2 bundle in `state_dir`.
pub fn boot_host(state_dir: &Path, spawn_console_shell: bool) -> NativeOsHost {
    let mut cfg = NativeBootConfig::new(test_bundle_dir(), state_dir.to_path_buf());
    cfg.spawn_console_shell = spawn_console_shell;
    cfg.boot_timeout = Duration::from_secs(30);
    NativeOsHost::boot(cfg).expect("boot NativeOsHost")
}

/// Execute `/bin/sh -c <script>` as `uid` inside `host` with a 15-second timeout.
#[allow(dead_code)]
pub fn exec_sh(host: &NativeOsHost, uid: u32, script: &str) -> ExecOutput {
    host.exec_command_blocking(
        uid,
        vec!["/bin/sh".into(), "-c".into(), script.into()],
        Vec::new(),
        Some("/".into()),
        &[],
        Duration::from_secs(30),
    )
    .expect("exec_sh failed")
}
