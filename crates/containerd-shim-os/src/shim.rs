//! Containerd shim v2/v3 TTRPC service (`OsShimService`) bridging OCI bundles + CSI volumes
//! into isolated `os-native` Wasm/WASIX containers.

use crate::SHIM_VERSION;
use crate::oci_spec::{OciProcess, OciSpec, validate_no_parent_traversal};
use crate::task_proto::{
    CloseIORequest, ConnectRequest, ConnectResponse, CreateTaskRequest, CreateTaskResponse,
    DeleteRequest, DeleteResponse, ExecProcessRequest, KillRequest, PidsRequest, PidsResponse,
    ProcessInfo, ResizePtyRequest, ShutdownRequest, StartRequest, StartResponse, StateRequest,
    StateResponse, TASK_V2_SERVICE, TASK_V3_SERVICE, TaskStatus, Timestamp, WaitRequest,
    WaitResponse,
};
use crate::ttrpc::{RpcCode, RpcStatus, TtrpcHandler, TtrpcRequest};
use abi::Errno;
use os_csi::fencing::CsiVolumeKind;
use os_csi::node::{PublishedVolumeDescriptor, load_published_descriptor};
use os_native::oci_runtime::{
    OciBundleRunSpec, OciContainerHandle, OciContainerState, OciCsiFenceCheck, OciExecHandle,
    OciExecSpec, OciVolumeMount, validate_stdio_path,
};
use os_native::overlay::{NativeCniAttachment, NativeOverlaySwitch};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::future::Future;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::FromRawFd;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

static WORK_DIR_SEQ: AtomicU64 = AtomicU64::new(1);

/// Configuration for [`OsShimService`].
#[derive(Clone, Debug)]
pub struct ShimConfig {
    pub namespace: String,
    pub csi_node_state_dir: Option<PathBuf>,
    pub cni_state_dir: Option<PathBuf>,
    pub work_root: PathBuf,
}

struct ManagedExec {
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    handle: Arc<OciExecHandle>,
}

struct ManagedContainer {
    id: String,
    bundle: String,
    stdin: String,
    stdout: String,
    stderr: String,
    terminal: bool,
    work_store_dir: PathBuf,
    handle: Arc<OciContainerHandle>,
    execs: Mutex<HashMap<String, ManagedExec>>,
    creating_execs: Mutex<HashSet<String>>,
}

struct CreatingGuard<'a> {
    creating: &'a Mutex<HashSet<String>>,
    id: String,
}

impl Drop for CreatingGuard<'_> {
    fn drop(&mut self) {
        self.creating.lock().unwrap().remove(&self.id);
    }
}

/// Containerd TTRPC `Task` (v2 & v3) service managing isolated `os-native` Wasm/WASIX containers.
pub struct OsShimService {
    cfg: ShimConfig,
    containers: Mutex<HashMap<String, Arc<ManagedContainer>>>,
    creating: Mutex<HashSet<String>>,
    overlay_switch: Arc<NativeOverlaySwitch>,
    shutdown_tx: watch::Sender<bool>,
}

impl OsShimService {
    pub fn new(cfg: ShimConfig, shutdown_tx: watch::Sender<bool>) -> Self {
        Self {
            cfg,
            containers: Mutex::new(HashMap::new()),
            creating: Mutex::new(HashSet::new()),
            overlay_switch: NativeOverlaySwitch::new(),
            shutdown_tx,
        }
    }

    fn get_container(&self, id: &str) -> Result<Arc<ManagedContainer>, RpcStatus> {
        self.containers
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| RpcStatus::err(RpcCode::NotFound, format!("container {id} not found")))
    }

    fn errno_to_status(errno: Errno, ctx: &str) -> RpcStatus {
        match errno {
            Errno::ENOEXEC => RpcStatus::err(
                RpcCode::InvalidArgument,
                format!(
                    "ENOEXEC ({ctx}): only WebAssembly (\\0asm) binaries are supported; Linux ELF executables are rejected"
                ),
            ),
            Errno::ESTALE => RpcStatus::err(
                RpcCode::FailedPrecondition,
                format!("ESTALE ({ctx}): CSI volume fenced by competing writer"),
            ),
            Errno::EBUSY => RpcStatus::err(
                RpcCode::FailedPrecondition,
                format!(
                    "EBUSY ({ctx}): CSI volume already exclusively attached by another container"
                ),
            ),
            Errno::ENOENT => RpcStatus::err(RpcCode::NotFound, format!("ENOENT ({ctx})")),
            Errno::EEXIST => RpcStatus::err(RpcCode::AlreadyExists, format!("EEXIST ({ctx})")),
            Errno::EPERM | Errno::EACCES | Errno::EROFS => {
                RpcStatus::err(RpcCode::PermissionDenied, format!("{errno:?} ({ctx})"))
            }
            Errno::EINVAL => RpcStatus::err(RpcCode::InvalidArgument, format!("EINVAL ({ctx})")),
            other => RpcStatus::err(RpcCode::Internal, format!("{other:?} ({ctx})")),
        }
    }

    fn map_state(s: OciContainerState) -> TaskStatus {
        match s {
            OciContainerState::Created => TaskStatus::Created,
            OciContainerState::Running => TaskStatus::Running,
            OciContainerState::Stopped => TaskStatus::Stopped,
        }
    }

    fn resolve_volumes(&self, spec: &OciSpec) -> Result<Vec<OciVolumeMount>, RpcStatus> {
        // Trusted shim configuration (`-csi-state` or `OS_CSI_NODE_STATE`) strictly takes
        // precedence over untrusted OCI annotations (`os.csi/node-state`).
        let trusted_csi_state = self
            .cfg
            .csi_node_state_dir
            .clone()
            .or_else(|| std::env::var_os("OS_CSI_NODE_STATE").map(PathBuf::from));
        let csi_state = if let Some(ref trusted) = trusted_csi_state {
            validate_host_path_no_symlinks(trusted, "csi_node_state_dir", true)?;
            Some(trusted.clone())
        } else if let Some(ann) = spec.csi_node_state_dir() {
            validate_host_path_no_symlinks(&ann, "os.csi/node-state", true)?;
            Some(ann)
        } else {
            None
        };

        let mut mounts = Vec::new();
        let mut used_vdevs: HashSet<String> = HashSet::new();

        for m in &spec.mounts {
            let dest = m.destination.trim();
            // Skip standard virtual mounts that os-native provides natively in its isolated kernel.
            if matches!(
                dest,
                "/proc"
                    | "/dev"
                    | "/dev/pts"
                    | "/dev/shm"
                    | "/dev/mqueue"
                    | "/sys"
                    | "/sys/fs/cgroup"
            ) || (dest == "/tmp" && m.mount_type == "tmpfs")
                || matches!(
                    m.mount_type.as_str(),
                    "proc" | "sysfs" | "devpts" | "cgroup" | "cgroup2" | "mqueue"
                )
            {
                continue;
            }

            let opt_ro = m.options.iter().any(|o| o == "ro" || o == "readonly");

            // 1. Resolve CSI published descriptor strictly from trusted `$CSI_STATE/published/`.
            //    Direct block binding files are ONLY allowed when no trusted CSI state root is
            //    configured and still undergo strict `O_NOFOLLOW` + symlink validation.
            let desc = if !m.source.is_empty() {
                let src_path = Path::new(&m.source);
                if let Some(st) = csi_state.as_deref() {
                    load_published_descriptor(st, src_path)
                } else {
                    try_load_block_binding_file(src_path)
                }
            } else {
                None
            };

            if let Some(desc) = desc {
                validate_published_descriptor(&desc)?;
                let readonly = desc.readonly || opt_ro;
                let csi_fence = desc.fence_file.map(|fence_file| OciCsiFenceCheck {
                    fence_file,
                    expected_epoch: desc.fence_epoch,
                    expected_lease_id: desc.lease_id,
                });
                match desc.volume_kind {
                    CsiVolumeKind::Cowfs => {
                        mounts.push(OciVolumeMount::CowFsVolume {
                            store_dir: desc.store_dir,
                            volume_id: desc.volume_id,
                            container_path: dest.to_string(),
                            readonly,
                            fence_flag: None,
                            lock_file: desc.lock_file,
                            handoff_socket: desc.handoff_socket,
                            csi_fence,
                        });
                    }
                    CsiVolumeKind::Block => {
                        let dev_name = derive_vdev_name(dest, &mut used_vdevs)?;
                        if let Some(nbd_socket) = desc.nbd_socket {
                            mounts.push(OciVolumeMount::NbdBlockDevice {
                                nbd_socket,
                                export_name: desc.volume_id,
                                dev_name,
                                readonly,
                                lock_file: desc.lock_file,
                                csi_fence,
                            });
                        } else {
                            mounts.push(OciVolumeMount::RawBlockDevice {
                                store_dir: desc.store_dir,
                                volume_id: desc.volume_id,
                                dev_name,
                                readonly,
                                fence_flag: None,
                                lock_file: desc.lock_file,
                                csi_fence,
                            });
                        }
                    }
                }
                continue;
            }

            // 2. Explicit `os-csi-*` mount options are strictly rejected when a trusted CSI node
            //    state root is configured (preventing untrusted OCI specs from opening arbitrary
            //    host SQLite stores).
            let opt_store = m
                .options
                .iter()
                .find_map(|o| o.strip_prefix("os-csi-store="));
            let opt_vol = m.options.iter().find_map(|o| o.strip_prefix("os-csi-vol="));
            let opt_kind = m
                .options
                .iter()
                .find_map(|o| o.strip_prefix("os-csi-kind="))
                .unwrap_or("cowfs");
            if let (Some(store), Some(vol)) = (opt_store, opt_vol) {
                if trusted_csi_state.is_some() {
                    return Err(RpcStatus::err(
                        RpcCode::PermissionDenied,
                        "os-csi-store mount option is forbidden when trusted CSI node state is configured",
                    ));
                }
                let store_path = PathBuf::from(store);
                validate_host_path_no_symlinks(&store_path, "os-csi-store", true)?;
                if opt_kind == "block" {
                    let dev_name = derive_vdev_name(dest, &mut used_vdevs)?;
                    mounts.push(OciVolumeMount::RawBlockDevice {
                        store_dir: store_path,
                        volume_id: vol.to_string(),
                        dev_name,
                        readonly: opt_ro,
                        fence_flag: None,
                        lock_file: None,
                        csi_fence: None,
                    });
                } else {
                    mounts.push(OciVolumeMount::CowFsVolume {
                        store_dir: store_path,
                        volume_id: vol.to_string(),
                        container_path: dest.to_string(),
                        readonly: opt_ro,
                        fence_flag: None,
                        lock_file: None,
                        handoff_socket: None,
                        csi_fence: None,
                    });
                }
                continue;
            }

            // 3. Read-only host directory bind mount (e.g. ConfigMap/Secret projection).
            if !m.source.is_empty() && opt_ro {
                let src = PathBuf::from(&m.source);
                validate_host_path_no_symlinks(&src, "mount.source", true)?;
                if src.is_dir() {
                    mounts.push(OciVolumeMount::ReadOnlyHostDir {
                        host_path: src,
                        container_path: dest.to_string(),
                    });
                }
            }
        }

        Ok(mounts)
    }

    async fn handle_create(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = CreateTaskRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        if req.id.is_empty() || req.bundle.is_empty() {
            return Err(RpcStatus::err(
                RpcCode::InvalidArgument,
                "Create requires non-empty id and bundle",
            ));
        }
        if req.id.contains(['/', '\0']) || req.id == "." || req.id == ".." {
            return Err(RpcStatus::err(
                RpcCode::InvalidArgument,
                "invalid container id",
            ));
        }
        validate_no_parent_traversal(&req.bundle, "bundle")
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;

        let stdin_path = validate_opt_stdio(&req.stdin, true, "Create stdin")?;
        let stdout_path = validate_opt_stdio(&req.stdout, false, "Create stdout")?;
        let stderr_path = validate_opt_stdio(&req.stderr, false, "Create stderr")?;

        // Atomically reserve container ID before blocking work so concurrent `Create` calls
        // with the same ID cannot race and double-spawn.
        {
            let ctrs = self.containers.lock().unwrap();
            let mut creating = self.creating.lock().unwrap();
            if ctrs.contains_key(&req.id) || creating.contains(&req.id) {
                return Err(RpcStatus::err(
                    RpcCode::AlreadyExists,
                    format!("container {} already exists", req.id),
                ));
            }
            creating.insert(req.id.clone());
        }
        let _creating_guard = CreatingGuard {
            creating: &self.creating,
            id: req.id.clone(),
        };

        let bundle_dir = PathBuf::from(&req.bundle);
        let spec = OciSpec::load_from_bundle(&bundle_dir)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        let mut rootfs_dir = spec
            .resolve_rootfs(&bundle_dir)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        if !rootfs_dir.exists() {
            for rm in &req.rootfs {
                if !rm.source.is_empty()
                    && validate_no_parent_traversal(&rm.source, "rootfs").is_ok()
                {
                    let cand = PathBuf::from(&rm.source);
                    if cand.is_dir() {
                        rootfs_dir = cand;
                        break;
                    }
                }
            }
        }

        let volumes = self.resolve_volumes(&spec)?;
        let proc_spec = spec.process.clone().unwrap_or_default();
        let is_sandbox = spec.is_cri_sandbox();
        let user = proc_spec.user.unwrap_or_default();
        let work_store_dir = self.cfg.work_root.join(format!(
            "ctr-{}-{}-{}",
            sanitize_id(&req.id),
            std::process::id(),
            WORK_DIR_SEQ.fetch_add(1, Ordering::Relaxed)
        ));

        let cni_state_dir = self
            .cfg
            .cni_state_dir
            .clone()
            .or_else(|| std::env::var_os("OS_CNI_STATE").map(PathBuf::from));
        let cni_attachment = match cni_state_dir {
            Some(ref dir) => NativeCniAttachment::load_nofollow(dir, &req.id)
                .map_err(|errno| Self::errno_to_status(errno, "CNI attachment"))?,
            None => None,
        };
        let overlay_switch = cni_attachment
            .as_ref()
            .map(|_| Arc::clone(&self.overlay_switch));

        let run_spec = OciBundleRunSpec {
            container_id: req.id.clone(),
            bundle_dir: bundle_dir.clone(),
            rootfs_dir,
            work_store_dir: work_store_dir.clone(),
            argv: proc_spec.args,
            env: proc_spec.env,
            cwd: if proc_spec.cwd.is_empty() {
                "/".to_string()
            } else {
                proc_spec.cwd
            },
            uid: user.uid,
            gid: user.gid,
            umask: user.umask.map(|u| (u & 0o777) as u16).unwrap_or(0o022),
            memory_max_bytes: spec.memory_limit_bytes(),
            pids_max: spec.pids_limit(),
            stdin_path,
            stdout_path,
            stderr_path,
            terminal: req.terminal || proc_spec.terminal,
            is_sandbox,
            volumes,
            cni_attachment,
            overlay_switch,
        };

        let handle = tokio::task::spawn_blocking(move || OciContainerHandle::create(run_spec))
            .await
            .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("create join: {e}")))?
            .map_err(|errno| Self::errno_to_status(errno, "Create"))?;

        let pid = handle.state().pid;
        let managed = Arc::new(ManagedContainer {
            id: req.id.clone(),
            bundle: req.bundle,
            stdin: req.stdin,
            stdout: req.stdout,
            stderr: req.stderr,
            terminal: req.terminal,
            work_store_dir,
            handle: Arc::new(handle),
            execs: Mutex::new(HashMap::new()),
            creating_execs: Mutex::new(HashSet::new()),
        });
        self.containers.lock().unwrap().insert(req.id, managed);

        Ok(CreateTaskResponse { pid }.encode())
    }

    async fn handle_start(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = StartRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        let ctr = self.get_container(&req.id)?;
        let pid = if req.exec_id.is_empty() {
            let h = Arc::clone(&ctr.handle);
            tokio::task::spawn_blocking(move || h.start())
                .await
                .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("start join: {e}")))?
                .map_err(|errno| Self::errno_to_status(errno, "Start"))?
        } else {
            let exec_h = {
                let g = ctr.execs.lock().unwrap();
                g.get(&req.exec_id)
                    .map(|e| Arc::clone(&e.handle))
                    .ok_or_else(|| {
                        RpcStatus::err(RpcCode::NotFound, format!("exec {} not found", req.exec_id))
                    })?
            };
            tokio::task::spawn_blocking(move || exec_h.start())
                .await
                .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("exec start join: {e}")))?
                .map_err(|errno| Self::errno_to_status(errno, "ExecStart"))?
        };
        Ok(StartResponse { pid }.encode())
    }

    async fn handle_state(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = StateRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        let ctr = self.get_container(&req.id)?;
        let resp = if req.exec_id.is_empty() {
            let snap = ctr.handle.state();
            StateResponse {
                id: ctr.id.clone(),
                bundle: ctr.bundle.clone(),
                pid: snap.pid,
                status: Self::map_state(snap.state),
                stdin: ctr.stdin.clone(),
                stdout: ctr.stdout.clone(),
                stderr: ctr.stderr.clone(),
                terminal: ctr.terminal,
                exit_status: snap
                    .exit_status
                    .as_ref()
                    .map(|s| s.exit_code as u32)
                    .unwrap_or(0),
                exited_at: snap
                    .exit_status
                    .as_ref()
                    .map(|s| Timestamp::from_unix_nanos(s.exited_at_ns)),
                exec_id: String::new(),
            }
        } else {
            let g = ctr.execs.lock().unwrap();
            let ex = g.get(&req.exec_id).ok_or_else(|| {
                RpcStatus::err(RpcCode::NotFound, format!("exec {} not found", req.exec_id))
            })?;
            let snap = ex.handle.state();
            StateResponse {
                id: ctr.id.clone(),
                bundle: ctr.bundle.clone(),
                pid: snap.pid,
                status: Self::map_state(snap.state),
                stdin: ex.stdin.clone(),
                stdout: ex.stdout.clone(),
                stderr: ex.stderr.clone(),
                terminal: ex.terminal,
                exit_status: snap
                    .exit_status
                    .as_ref()
                    .map(|s| s.exit_code as u32)
                    .unwrap_or(0),
                exited_at: snap
                    .exit_status
                    .as_ref()
                    .map(|s| Timestamp::from_unix_nanos(s.exited_at_ns)),
                exec_id: req.exec_id,
            }
        };
        Ok(resp.encode())
    }

    async fn handle_kill(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = KillRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        let ctr = self.get_container(&req.id)?;
        let sig = u8::try_from(req.signal)
            .map_err(|_| RpcStatus::err(RpcCode::InvalidArgument, "signal out of range"))?;
        if req.exec_id.is_empty() {
            let h = Arc::clone(&ctr.handle);
            let all = req.all;
            tokio::task::spawn_blocking(move || h.kill(sig, all))
                .await
                .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("kill join: {e}")))?
                .map_err(|errno| Self::errno_to_status(errno, "Kill"))?;
        } else {
            let exec_h = {
                let g = ctr.execs.lock().unwrap();
                g.get(&req.exec_id)
                    .map(|e| Arc::clone(&e.handle))
                    .ok_or_else(|| {
                        RpcStatus::err(RpcCode::NotFound, format!("exec {} not found", req.exec_id))
                    })?
            };
            tokio::task::spawn_blocking(move || exec_h.kill(sig))
                .await
                .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("exec kill join: {e}")))?
                .map_err(|errno| Self::errno_to_status(errno, "ExecKill"))?;
        }
        Ok(Vec::new())
    }

    async fn handle_wait(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = WaitRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        let ctr = self.get_container(&req.id)?;
        let status = if req.exec_id.is_empty() {
            let h = Arc::clone(&ctr.handle);
            tokio::task::spawn_blocking(move || h.wait())
                .await
                .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("wait join: {e}")))?
        } else {
            let exec_h = {
                let g = ctr.execs.lock().unwrap();
                g.get(&req.exec_id)
                    .map(|e| Arc::clone(&e.handle))
                    .ok_or_else(|| {
                        RpcStatus::err(RpcCode::NotFound, format!("exec {} not found", req.exec_id))
                    })?
            };
            tokio::task::spawn_blocking(move || exec_h.wait())
                .await
                .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("exec wait join: {e}")))?
        };
        Ok(WaitResponse {
            exit_status: status.exit_code as u32,
            exited_at: Some(Timestamp::from_unix_nanos(status.exited_at_ns)),
        }
        .encode())
    }

    async fn handle_exec(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = ExecProcessRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        if req.exec_id.is_empty() {
            return Err(RpcStatus::err(
                RpcCode::InvalidArgument,
                "Exec requires non-empty exec_id",
            ));
        }
        let stdin_path = validate_opt_stdio(&req.stdin, true, "Exec stdin")?;
        let stdout_path = validate_opt_stdio(&req.stdout, false, "Exec stdout")?;
        let stderr_path = validate_opt_stdio(&req.stderr, false, "Exec stderr")?;

        let ctr = self.get_container(&req.id)?;
        {
            let exs = ctr.execs.lock().unwrap();
            let mut creating_exs = ctr.creating_execs.lock().unwrap();
            if exs.contains_key(&req.exec_id) || creating_exs.contains(&req.exec_id) {
                return Err(RpcStatus::err(
                    RpcCode::AlreadyExists,
                    format!("exec {} already exists", req.exec_id),
                ));
            }
            creating_exs.insert(req.exec_id.clone());
        }
        let _exec_creating_guard = CreatingGuard {
            creating: &ctr.creating_execs,
            id: req.exec_id.clone(),
        };
        let proc_bytes = req
            .spec
            .as_ref()
            .map(|a| a.value.as_slice())
            .ok_or_else(|| RpcStatus::err(RpcCode::InvalidArgument, "Exec missing process spec"))?;
        let proc_spec: OciProcess = serde_json::from_slice(proc_bytes).map_err(|e| {
            RpcStatus::err(RpcCode::InvalidArgument, format!("parse exec spec: {e}"))
        })?;
        if proc_spec.args.is_empty() {
            return Err(RpcStatus::err(
                RpcCode::InvalidArgument,
                "Exec process.args must be non-empty",
            ));
        }

        let exec_spec = OciExecSpec {
            exec_id: req.exec_id.clone(),
            argv: proc_spec.args,
            env: proc_spec.env,
            cwd: if proc_spec.cwd.is_empty() {
                "/".to_string()
            } else {
                proc_spec.cwd
            },
            uid: proc_spec.user.map(|u| u.uid),
            stdin_path,
            stdout_path,
            stderr_path,
        };

        let h = Arc::clone(&ctr.handle);
        let exec_handle = tokio::task::spawn_blocking(move || h.exec(exec_spec))
            .await
            .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("exec join: {e}")))?
            .map_err(|errno| Self::errno_to_status(errno, "Exec"))?;

        ctr.execs.lock().unwrap().insert(
            req.exec_id,
            ManagedExec {
                stdin: req.stdin,
                stdout: req.stdout,
                stderr: req.stderr,
                terminal: req.terminal,
                handle: exec_handle,
            },
        );
        Ok(Vec::new())
    }

    async fn handle_delete(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = DeleteRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        if !req.exec_id.is_empty() {
            let ctr = self.get_container(&req.id)?;
            let ex = ctr
                .execs
                .lock()
                .unwrap()
                .remove(&req.exec_id)
                .ok_or_else(|| {
                    RpcStatus::err(RpcCode::NotFound, format!("exec {} not found", req.exec_id))
                })?;
            let pid = ex.handle.state().pid;
            let status = tokio::task::spawn_blocking(move || ex.handle.delete())
                .await
                .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("exec delete join: {e}")))?
                .map_err(|errno| Self::errno_to_status(errno, "ExecDelete"))?;
            return Ok(DeleteResponse {
                pid,
                exit_status: status.exit_code as u32,
                exited_at: Some(Timestamp::from_unix_nanos(status.exited_at_ns)),
            }
            .encode());
        }

        let ctr = self
            .containers
            .lock()
            .unwrap()
            .remove(&req.id)
            .ok_or_else(|| {
                RpcStatus::err(RpcCode::NotFound, format!("container {} not found", req.id))
            })?;
        // Drain and clean up any leftover exec processes before tearing down the container.
        let leftover_execs: Vec<Arc<OciExecHandle>> = ctr
            .execs
            .lock()
            .unwrap()
            .drain()
            .map(|(_, e)| e.handle)
            .collect();
        for ex_h in leftover_execs {
            let _ = tokio::task::spawn_blocking(move || ex_h.delete()).await;
        }

        let pid = ctr.handle.state().pid;
        let h = Arc::clone(&ctr.handle);
        let del_res = tokio::task::spawn_blocking(move || h.delete())
            .await
            .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("delete join: {e}")))?;
        let _ = std::fs::remove_dir_all(&ctr.work_store_dir);

        let status = del_res.map_err(|errno| Self::errno_to_status(errno, "Delete"))?;
        Ok(DeleteResponse {
            pid,
            exit_status: status.exit_code as u32,
            exited_at: Some(Timestamp::from_unix_nanos(status.exited_at_ns)),
        }
        .encode())
    }

    async fn handle_pids(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = PidsRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        let ctr = self.get_container(&req.id)?;
        let h = Arc::clone(&ctr.handle);
        let pids = tokio::task::spawn_blocking(move || h.pids())
            .await
            .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("pids join: {e}")))?;
        Ok(PidsResponse {
            processes: pids.into_iter().map(|pid| ProcessInfo { pid }).collect(),
        }
        .encode())
    }

    async fn handle_connect(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let req = ConnectRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        let task_pid = self
            .containers
            .lock()
            .unwrap()
            .get(&req.id)
            .map(|c| c.handle.state().pid)
            .unwrap_or(0);
        Ok(ConnectResponse {
            shim_pid: std::process::id(),
            task_pid,
            version: SHIM_VERSION.to_string(),
        }
        .encode())
    }

    async fn handle_shutdown(&self, payload: &[u8]) -> Result<Vec<u8>, RpcStatus> {
        let _req = ShutdownRequest::decode(payload)
            .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
        // Clean up any remaining containers & execs gracefully before terminating the shim loop.
        let leftover: Vec<Arc<ManagedContainer>> = self
            .containers
            .lock()
            .unwrap()
            .drain()
            .map(|(_, c)| c)
            .collect();
        for ctr in leftover {
            let leftover_execs: Vec<Arc<OciExecHandle>> = ctr
                .execs
                .lock()
                .unwrap()
                .drain()
                .map(|(_, e)| e.handle)
                .collect();
            for ex_h in leftover_execs {
                let _ = tokio::task::spawn_blocking(move || ex_h.delete()).await;
            }
            let h = Arc::clone(&ctr.handle);
            let _ = tokio::task::spawn_blocking(move || h.delete()).await;
            let _ = std::fs::remove_dir_all(&ctr.work_store_dir);
        }
        let _ = self.shutdown_tx.send(true);
        Ok(Vec::new())
    }
}

impl TtrpcHandler for OsShimService {
    fn handle<'a>(
        &'a self,
        req: TtrpcRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, RpcStatus>> + 'a>> {
        Box::pin(async move {
            if req.service != TASK_V2_SERVICE && req.service != TASK_V3_SERVICE {
                return Err(RpcStatus::err(
                    RpcCode::Unimplemented,
                    format!("unsupported TTRPC service: {}", req.service),
                ));
            }
            match req.method.as_str() {
                "Create" => self.handle_create(&req.payload).await,
                "Start" => self.handle_start(&req.payload).await,
                "State" => self.handle_state(&req.payload).await,
                "Kill" => self.handle_kill(&req.payload).await,
                "Wait" => self.handle_wait(&req.payload).await,
                "Exec" => self.handle_exec(&req.payload).await,
                "Delete" => self.handle_delete(&req.payload).await,
                "Pids" => self.handle_pids(&req.payload).await,
                "Connect" => self.handle_connect(&req.payload).await,
                "Shutdown" => self.handle_shutdown(&req.payload).await,
                "CloseIO" => {
                    let _ = CloseIORequest::decode(&req.payload)
                        .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
                    Ok(Vec::new())
                }
                "ResizePty" => {
                    let _ = ResizePtyRequest::decode(&req.payload)
                        .map_err(|e| RpcStatus::err(RpcCode::InvalidArgument, e))?;
                    Ok(Vec::new())
                }
                other => Err(RpcStatus::err(
                    RpcCode::Unimplemented,
                    format!("unsupported Task method: {other}"),
                )),
            }
        })
    }
}

fn validate_opt_stdio(
    raw: &str,
    is_input: bool,
    label: &str,
) -> Result<Option<PathBuf>, RpcStatus> {
    if raw.is_empty() {
        return Ok(None);
    }
    let path = PathBuf::from(raw);
    validate_stdio_path(&path, is_input).map_err(|e| OsShimService::errno_to_status(e, label))?;
    Ok(Some(path))
}

fn validate_host_path_no_symlinks(
    path: &Path,
    label: &str,
    must_exist: bool,
) -> Result<(), RpcStatus> {
    if path.as_os_str().is_empty() || path.as_os_str().as_bytes().contains(&0) {
        return Err(RpcStatus::err(
            RpcCode::InvalidArgument,
            format!("{label} is empty or contains NUL"),
        ));
    }
    if !path.is_absolute() {
        return Err(RpcStatus::err(
            RpcCode::InvalidArgument,
            format!("{label} must be absolute: {}", path.display()),
        ));
    }
    let mut cur = PathBuf::new();
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(RpcStatus::err(
                RpcCode::PermissionDenied,
                format!("{label} must not contain '..': {}", path.display()),
            ));
        }
        cur.push(comp);
        if matches!(comp, Component::RootDir) {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(RpcStatus::err(
                        RpcCode::PermissionDenied,
                        format!("refusing symlink component in {label}: {}", cur.display()),
                    ));
                }
            }
            Err(_) if !must_exist && cur == path => {}
            Err(_) => {
                return Err(RpcStatus::err(
                    RpcCode::NotFound,
                    format!("{label} path not found: {}", cur.display()),
                ));
            }
        }
    }
    Ok(())
}

fn validate_published_descriptor(desc: &PublishedVolumeDescriptor) -> Result<(), RpcStatus> {
    validate_host_path_no_symlinks(&desc.store_dir, "csi.store_dir", true)?;
    if let Some(ref sock) = desc.nbd_socket {
        validate_host_path_no_symlinks(sock, "csi.nbd_socket", true)?;
    }
    if let Some(ref f) = desc.fence_file {
        validate_host_path_no_symlinks(f, "csi.fence_file", false)?;
    }
    if let Some(ref h) = desc.handoff_socket {
        validate_host_path_no_symlinks(h, "csi.handoff_socket", true)?;
    }
    if let Some(ref l) = desc.lock_file {
        validate_host_path_no_symlinks(l, "csi.lock_file", false)?;
    }
    Ok(())
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .take(32)
        .collect()
}

fn try_load_block_binding_file(path: &Path) -> Option<PublishedVolumeDescriptor> {
    validate_host_path_no_symlinks(path, "block_binding", true).ok()?;
    let cpath = CString::new(path.as_os_str().as_bytes()).ok()?;
    let fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0
        || (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_size < 0
        || (st.st_size as u64) > 64 * 1024
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(64 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() > 64 * 1024 {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn derive_vdev_name(dest: &str, used: &mut HashSet<String>) -> Result<String, RpcStatus> {
    if let Some(rest) = dest.strip_prefix("/dev/")
        && rest.starts_with("vd")
        && rest.len() >= 3
        && rest[2..].bytes().all(|b| b.is_ascii_digit())
    {
        if !used.insert(rest.to_string()) {
            return Err(RpcStatus::err(
                RpcCode::InvalidArgument,
                format!("duplicate block device target /dev/{rest}"),
            ));
        }
        return Ok(rest.to_string());
    }
    for i in 0..64 {
        let cand = format!("vd{i}");
        if used.insert(cand.clone()) {
            return Ok(cand);
        }
    }
    Err(RpcStatus::err(
        RpcCode::InvalidArgument,
        "too many raw block devices attached to container",
    ))
}
