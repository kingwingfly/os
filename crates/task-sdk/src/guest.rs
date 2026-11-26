//! Pure-`std` guest pod helpers (compiles cleanly to `wasm32-wasip1` and native tests).
//!
//! Strictly confines all reads to `/input` and all writes to `/output`, rejecting `..`,
//! absolute paths, NUL bytes, and symlink escapes.
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf};

/// Default mountpoint for read-only task inputs inside a sandbox.
pub const DEFAULT_INPUT_DIR: &str = "/input";
/// Default mountpoint for the fresh writable `cowfs` output volume inside a sandbox.
pub const DEFAULT_OUTPUT_DIR: &str = "/output";
/// Conventional file inside `/output` read by `kubelet` into `ResultRecord.summary`.
pub const SUMMARY_REL_PATH: &str = ".os-task-summary.txt";
/// Maximum summary bytes persisted to `ResultRecord.summary`.
pub const MAX_SUMMARY_BYTES: usize = 1024;

/// Runtime metadata injected into every task sandbox via environment variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskEnv {
    pub workload_id: String,
    pub attempt_generation: u64,
    pub node_id: String,
    pub node_generation: u64,
    pub sdk_version: u32,
    pub input_dir: PathBuf,
    pub output_dir: PathBuf,
}

impl TaskEnv {
    /// Load task identity and I/O directories from process environment variables.
    pub fn from_env() -> Self {
        Self {
            workload_id: std::env::var("OS_TASK_WORKLOAD_ID").unwrap_or_default(),
            attempt_generation: std::env::var("OS_TASK_ATTEMPT_GEN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            node_id: std::env::var("OS_TASK_NODE_ID").unwrap_or_default(),
            node_generation: std::env::var("OS_TASK_NODE_GEN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            sdk_version: std::env::var("OS_TASK_SDK_VERSION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(crate::TASK_SDK_VERSION),
            input_dir: PathBuf::from(
                std::env::var("OS_TASK_INPUT_DIR").unwrap_or_else(|_| DEFAULT_INPUT_DIR.into()),
            ),
            output_dir: PathBuf::from(
                std::env::var("OS_TASK_OUTPUT_DIR").unwrap_or_else(|_| DEFAULT_OUTPUT_DIR.into()),
            ),
        }
    }

    pub fn with_dirs(input_dir: impl Into<PathBuf>, output_dir: impl Into<PathBuf>) -> Self {
        Self {
            workload_id: String::new(),
            attempt_generation: 0,
            node_id: String::new(),
            node_generation: 0,
            sdk_version: crate::TASK_SDK_VERSION,
            input_dir: input_dir.into(),
            output_dir: output_dir.into(),
        }
    }

    pub fn read_input_bytes(&self, rel: &str) -> io::Result<Vec<u8>> {
        let path = confined_path(&self.input_dir, rel, false)?;
        fs::read(path)
    }

    pub fn read_input_json<T: DeserializeOwned>(&self, rel: &str) -> io::Result<T> {
        let bytes = self.read_input_bytes(rel)?;
        serde_json::from_slice(&bytes).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
    }

    pub fn list_inputs(&self, rel_dir: &str) -> io::Result<Vec<String>> {
        let dir = if rel_dir.is_empty() || rel_dir == "." {
            self.input_dir.clone()
        } else {
            confined_path(&self.input_dir, rel_dir, false)?
        };
        let mut names = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    pub fn write_output_bytes(&self, rel: &str, data: &[u8]) -> io::Result<()> {
        let path = confined_path(&self.output_dir, rel, true)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, data)
    }

    pub fn write_output_json<T: Serialize>(&self, rel: &str, value: &T) -> io::Result<()> {
        let bytes =
            serde_json::to_vec(value).map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
        self.write_output_bytes(rel, &bytes)
    }

    pub fn write_summary(&self, summary: &str) -> io::Result<()> {
        if summary.len() > MAX_SUMMARY_BYTES {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("summary exceeds {MAX_SUMMARY_BYTES} bytes"),
            ));
        }
        self.write_output_bytes(SUMMARY_REL_PATH, summary.as_bytes())
    }
}

/// Strictly confine `rel` beneath `base`, rejecting empty/absolute paths, `..`, NUL bytes,
/// and existing symlink components along the traversal.
pub fn confined_path(base: &Path, rel: &str, allow_missing_leaf: bool) -> io::Result<PathBuf> {
    if rel.is_empty() || rel.starts_with('/') || rel.contains('\0') {
        return Err(io::Error::new(
            ErrorKind::PermissionDenied,
            "path must be relative and confined to task directory",
        ));
    }
    let mut cur = base.to_path_buf();
    let comps: Vec<Component<'_>> = Path::new(rel).components().collect();
    if comps.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidInput, "empty path"));
    }
    for (idx, comp) in comps.iter().enumerate() {
        match comp {
            Component::Normal(seg) => {
                cur.push(seg);
                let is_last = idx + 1 == comps.len();
                match fs::symlink_metadata(&cur) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(io::Error::new(
                                ErrorKind::PermissionDenied,
                                "symlink traversal denied inside confined task directory",
                            ));
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::NotFound && allow_missing_leaf => {
                        let _ = is_last;
                    }
                    Err(e) if e.kind() == ErrorKind::NotFound => return Err(e),
                    Err(e) => return Err(e),
                }
            }
            _ => {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "path traversal outside confined task directory denied",
                ));
            }
        }
    }
    Ok(cur)
}

pub fn read_input_bytes(rel: &str) -> io::Result<Vec<u8>> {
    TaskEnv::from_env().read_input_bytes(rel)
}

pub fn read_input_json<T: DeserializeOwned>(rel: &str) -> io::Result<T> {
    TaskEnv::from_env().read_input_json(rel)
}

pub fn list_inputs(rel_dir: &str) -> io::Result<Vec<String>> {
    TaskEnv::from_env().list_inputs(rel_dir)
}

pub fn write_output_bytes(rel: &str, data: &[u8]) -> io::Result<()> {
    TaskEnv::from_env().write_output_bytes(rel, data)
}

pub fn write_output_json<T: Serialize>(rel: &str, value: &T) -> io::Result<()> {
    TaskEnv::from_env().write_output_json(rel, value)
}

pub fn write_summary(summary: &str) -> io::Result<()> {
    TaskEnv::from_env().write_summary(summary)
}
