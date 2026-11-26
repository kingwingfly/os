//! OCI Runtime Specification `config.json` parser & strict path/security validator.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::{Component, Path, PathBuf};

/// Maximum allowed size of `<bundle>/config.json` (1 MiB).
pub const MAX_CONFIG_JSON_BYTES: usize = 1024 * 1024;

/// Parsed OCI runtime `config.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciSpec {
    #[serde(default)]
    pub oci_version: String,
    #[serde(default)]
    pub process: Option<OciProcess>,
    #[serde(default)]
    pub root: Option<OciRoot>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub mounts: Vec<OciMount>,
    #[serde(default)]
    pub linux: Option<OciLinux>,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciProcess {
    #[serde(default)]
    pub terminal: bool,
    #[serde(default)]
    pub user: Option<OciUser>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub cwd: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciUser {
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub gid: u32,
    #[serde(default)]
    pub umask: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciRoot {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciMount {
    pub destination: String,
    #[serde(rename = "type", default)]
    pub mount_type: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciLinux {
    #[serde(default)]
    pub resources: Option<OciResources>,
    #[serde(default)]
    pub devices: Vec<OciLinuxDevice>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciResources {
    #[serde(default)]
    pub memory: Option<OciMemory>,
    #[serde(default)]
    pub pids: Option<OciPids>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciMemory {
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciPids {
    #[serde(default)]
    pub limit: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OciLinuxDevice {
    pub path: String,
    #[serde(rename = "type", default)]
    pub dev_type: String,
    #[serde(default)]
    pub major: i64,
    #[serde(default)]
    pub minor: i64,
}

impl OciSpec {
    /// Load and validate `<bundle>/config.json` using `O_NOFOLLOW` and a strict 1 MiB size bound.
    pub fn load_from_bundle(bundle: &Path) -> Result<Self, String> {
        let cfg_path = bundle.join("config.json");
        let mut cur = PathBuf::new();
        for comp in cfg_path.components() {
            if matches!(comp, Component::ParentDir) {
                return Err(format!(
                    "config path must not contain '..': {}",
                    cfg_path.display()
                ));
            }
            cur.push(comp);
            if matches!(comp, Component::RootDir) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&cur)
                .map_err(|e| format!("stat {}: {e}", cur.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "refusing symlink component in config path: {}",
                    cur.display()
                ));
            }
        }
        let cpath = CString::new(cfg_path.as_os_str().as_bytes())
            .map_err(|_| "NUL byte in config.json path".to_string())?;
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open {}: {}",
                cfg_path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(format!(
                "fstat {}: {}",
                cfg_path.display(),
                std::io::Error::last_os_error()
            ));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(format!("{} is not a regular file", cfg_path.display()));
        }
        if st.st_size < 0 || (st.st_size as u64) > (MAX_CONFIG_JSON_BYTES as u64) {
            return Err(format!(
                "{} exceeds {} byte cap",
                cfg_path.display(),
                MAX_CONFIG_JSON_BYTES
            ));
        }
        let mut bytes = Vec::new();
        file.take((MAX_CONFIG_JSON_BYTES as u64) + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("read {}: {e}", cfg_path.display()))?;
        if bytes.len() > MAX_CONFIG_JSON_BYTES {
            return Err(format!(
                "{} exceeds {} byte cap",
                cfg_path.display(),
                MAX_CONFIG_JSON_BYTES
            ));
        }
        let spec: Self = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse {}: {e}", cfg_path.display()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(root) = &self.root {
            validate_no_parent_traversal(&root.path, "root.path")?;
        }
        if let Some(proc) = &self.process
            && !proc.cwd.is_empty()
        {
            validate_container_path(&proc.cwd, "process.cwd")?;
        }
        for m in &self.mounts {
            validate_container_path(&m.destination, "mount.destination")?;
            if !m.source.is_empty() {
                validate_no_parent_traversal(&m.source, "mount.source")?;
            }
        }
        Ok(())
    }

    /// Returns `true` if CRI annotations declare this container as a Kubernetes PodSandbox.
    pub fn is_cri_sandbox(&self) -> bool {
        self.annotations
            .get("io.kubernetes.cri.container-type")
            .or_else(|| self.annotations.get("io.kubernetes.docker.type"))
            .is_some_and(|v| v == "sandbox" || v == "podsandbox")
    }

    pub fn cri_sandbox_id(&self) -> Option<&str> {
        self.annotations
            .get("io.kubernetes.cri.sandbox-id")
            .map(String::as_str)
    }

    pub fn csi_node_state_dir(&self) -> Option<PathBuf> {
        self.annotations
            .get("os.csi/node-state")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    }

    /// Resolve `root.path` relative to `bundle_dir` (defaulting to `<bundle>/rootfs`).
    pub fn resolve_rootfs(&self, bundle_dir: &Path) -> Result<PathBuf, String> {
        let raw = self
            .root
            .as_ref()
            .map(|r| r.path.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("rootfs");
        validate_no_parent_traversal(raw, "root.path")?;
        let p = Path::new(raw);
        Ok(if p.is_absolute() {
            p.to_path_buf()
        } else {
            bundle_dir.join(p)
        })
    }

    pub fn memory_limit_bytes(&self) -> u64 {
        self.linux
            .as_ref()
            .and_then(|l| l.resources.as_ref())
            .and_then(|r| r.memory.as_ref())
            .and_then(|m| m.limit)
            .filter(|&v| v > 0)
            .map(|v| v as u64)
            .unwrap_or(256 * 1024 * 1024)
    }

    pub fn pids_limit(&self) -> u32 {
        self.linux
            .as_ref()
            .and_then(|l| l.resources.as_ref())
            .and_then(|r| r.pids.as_ref())
            .map(|p| p.limit)
            .filter(|&v| v > 0)
            .map(|v| (v as u64).min(u32::MAX as u64) as u32)
            .unwrap_or(64)
    }
}

pub fn validate_no_parent_traversal(raw: &str, label: &str) -> Result<(), String> {
    if raw.contains('\0') {
        return Err(format!("{label} contains NUL byte"));
    }
    for comp in Path::new(raw).components() {
        if matches!(comp, Component::ParentDir) {
            return Err(format!("{label} must not contain '..': {raw}"));
        }
    }
    Ok(())
}

pub fn validate_container_path(raw: &str, label: &str) -> Result<(), String> {
    if raw.is_empty() || !raw.starts_with('/') {
        return Err(format!("{label} must be an absolute container path: {raw}"));
    }
    validate_no_parent_traversal(raw, label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oci_spec_validates_paths_and_cri_annotations() {
        let raw = r#"{
            "ociVersion": "1.1.0",
            "root": { "path": "rootfs", "readonly": false },
            "process": {
                "args": ["/app.wasm", "--flag"],
                "env": ["PATH=/usr/bin:/bin"],
                "cwd": "/",
                "user": { "uid": 0, "gid": 0 }
            },
            "mounts": [
                { "destination": "/data", "type": "bind", "source": "/var/lib/csi/vol1", "options": ["rbind", "rw"] }
            ],
            "linux": {
                "resources": {
                    "memory": { "limit": 67108864 },
                    "pids": { "limit": 16 }
                }
            },
            "annotations": {
                "io.kubernetes.cri.container-type": "container",
                "io.kubernetes.cri.sandbox-id": "pod-123"
            }
        }"#;
        let spec: OciSpec = serde_json::from_str(raw).unwrap();
        spec.validate().unwrap();
        assert!(!spec.is_cri_sandbox());
        assert_eq!(spec.cri_sandbox_id(), Some("pod-123"));
        assert_eq!(spec.memory_limit_bytes(), 64 * 1024 * 1024);
        assert_eq!(spec.pids_limit(), 16);

        let mut bad = spec.clone();
        bad.mounts[0].destination = "../escape".into();
        assert!(bad.validate().is_err());

        let mut bad_src = spec;
        bad_src.mounts[0].source = "/var/lib/../etc/shadow".into();
        assert!(bad_src.validate().is_err());
    }
}
