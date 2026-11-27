//! `containerd-shim-os-v1` CLI implementing containerd's shim v2 bootstrap (`start` / `delete` /
//! `-version` / `-info`) and TTRPC `Task` v2/v3 server daemon.

use containerd_shim_os::shim::{OsShimService, ShimConfig};
use containerd_shim_os::task_proto::{DeleteResponse, Timestamp};
use containerd_shim_os::ttrpc::{
    ensure_private_shim_runtime_dir, serve_ttrpc_unix, validate_safe_socket_path,
};
use containerd_shim_os::{RUNTIME_NAME, SHIM_VERSION};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;

struct CliArgs {
    namespace: String,
    id: String,
    bundle: Option<PathBuf>,
    socket: Option<PathBuf>,
    csi_state: Option<PathBuf>,
    serve: bool,
    version: bool,
    info: bool,
    subcommand: Option<String>,
}

fn parse_args_from<I: IntoIterator<Item = String>>(iter: I) -> Result<CliArgs, String> {
    let mut args = CliArgs {
        namespace: "default".to_string(),
        id: String::new(),
        bundle: None,
        socket: None,
        csi_state: std::env::var_os("OS_CSI_NODE_STATE").map(PathBuf::from),
        serve: false,
        version: false,
        info: false,
        subcommand: None,
    };
    let mut it = iter.into_iter();
    while let Some(arg) = it.next() {
        // Support Go-style `-flag=value` and `--flag=value` tokens as passed by containerd.
        let (flag, inline_val) = if arg.starts_with('-') {
            match arg.split_once('=') {
                Some((f, v)) => (f, Some(v.to_string())),
                None => (arg.as_str(), None),
            }
        } else {
            (arg.as_str(), None)
        };
        let mut take_val = |name: &str| -> Result<String, String> {
            if let Some(v) = inline_val.clone() {
                Ok(v)
            } else {
                it.next().ok_or_else(|| format!("missing {name} value"))
            }
        };
        match flag {
            "-namespace" | "--namespace" => {
                args.namespace = take_val("-namespace")?;
            }
            "-id" | "--id" => {
                args.id = take_val("-id")?;
            }
            "-address" | "--address" | "-publish-binary" | "--publish-binary" => {
                if inline_val.is_none() {
                    let _ = it.next();
                }
            }
            "-bundle" | "--bundle" => {
                args.bundle = Some(PathBuf::from(take_val("-bundle")?));
            }
            "-socket" | "--socket" => {
                let raw = take_val("-socket")?;
                let stripped = raw.strip_prefix("unix://").unwrap_or(&raw);
                args.socket = Some(PathBuf::from(stripped));
            }
            "-csi-state" | "--csi-state" => {
                args.csi_state = Some(PathBuf::from(take_val("-csi-state")?));
            }
            "-debug" | "--debug" => {}
            "-serve" | "--serve" => args.serve = true,
            "-version" | "--version" | "-v" => args.version = true,
            "-info" | "--info" => args.info = true,
            s if s.starts_with('-') => {
                // Ignore unknown optional containerd flags with `=val` or standalone.
            }
            other => {
                if args.subcommand.is_none() {
                    args.subcommand = Some(other.to_string());
                }
            }
        }
    }
    Ok(args)
}

fn parse_args() -> Result<CliArgs, String> {
    parse_args_from(std::env::args().skip(1))
}

fn shim_instance_hash(namespace: &str, id: &str, bundle: Option<&Path>) -> String {
    let mut h = Sha256::new();
    h.update(namespace.as_bytes());
    h.update(b"/");
    h.update(id.as_bytes());
    if let Some(b) = bundle {
        h.update(b"/");
        h.update(b.to_string_lossy().as_bytes());
    }
    let digest = h.finalize();
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn derive_socket_path(namespace: &str, id: &str, bundle: Option<&Path>) -> Result<PathBuf, String> {
    let hex = shim_instance_hash(namespace, id, bundle);
    if let Some(b) = bundle {
        let cand = b.join("shim.sock");
        // Leave room for the private staging subdirectory `.ttrpc-<pid>-<seq>/s` within SUN_LEN.
        if cand.as_os_str().len() < 76 {
            return Ok(cand);
        }
    }
    let rt_dir = ensure_private_shim_runtime_dir()
        .map_err(|e| format!("create private shim runtime dir: {e}"))?;
    Ok(rt_dir.join(format!("os-shim-{hex}.sock")))
}

fn derive_work_root(
    namespace: &str,
    id: &str,
    bundle: Option<&Path>,
    socket: &Path,
) -> Result<PathBuf, String> {
    let hex = shim_instance_hash(namespace, id, bundle);
    let leaf = format!(".os-shim-work-{hex}");
    if let Some(b) = bundle {
        Ok(b.join(leaf))
    } else if let Some(p) = socket.parent()
        && !p.as_os_str().is_empty()
    {
        Ok(p.join(leaf))
    } else {
        let rt_dir = ensure_private_shim_runtime_dir()
            .map_err(|e| format!("create private shim runtime dir: {e}"))?;
        Ok(rt_dir.join(leaf))
    }
}

fn validate_socket_path_syntax(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
        return Err("empty or NUL socket path".into());
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "socket path must not contain '..': {}",
            path.display()
        ));
    }
    Ok(())
}

fn run_start(args: &CliArgs) -> Result<(), String> {
    let sock_path = match &args.socket {
        Some(p) => p.clone(),
        None => derive_socket_path(&args.namespace, &args.id, args.bundle.as_deref())?,
    };
    validate_socket_path_syntax(&sock_path)?;
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create socket parent {}: {e}", parent.display()))?;
    }
    validate_safe_socket_path(&sock_path)
        .map_err(|e| format!("invalid socket path {}: {e}", sock_path.display()))?;
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut cmd = Command::new(exe);
    cmd.arg("-serve")
        .arg("-namespace")
        .arg(&args.namespace)
        .arg("-socket")
        .arg(&sock_path);
    if !args.id.is_empty() {
        cmd.arg("-id").arg(&args.id);
    }
    if let Some(b) = &args.bundle {
        cmd.arg("-bundle").arg(b);
    }
    if let Some(st) = &args.csi_state {
        cmd.arg("-csi-state").arg(st);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let mut child = cmd.spawn().map_err(|e| format!("spawn shim daemon: {e}"))?;

    // Wait until the daemon binds and accepts on the 0600 Unix socket.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("shim daemon exited prematurely with {status}"));
        }
        if std::os::unix::net::UnixStream::connect(&sock_path).is_ok() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "timed out waiting for shim TTRPC socket {}",
                sock_path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Standard containerd shim v2 bootstrap output on stdout.
    print!("unix://{}", sock_path.display());
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn run_delete(args: &CliArgs) -> Result<(), String> {
    let sock_path = match &args.socket {
        Some(p) => p.clone(),
        None => derive_socket_path(&args.namespace, &args.id, args.bundle.as_deref())?,
    };
    validate_safe_socket_path(&sock_path)
        .map_err(|e| format!("refusing unsafe socket path {}: {e}", sock_path.display()))?;
    if let Ok(meta) = std::fs::symlink_metadata(&sock_path)
        && meta.file_type().is_socket()
    {
        let _ = std::fs::remove_file(&sock_path);
    }
    let work_root = derive_work_root(
        &args.namespace,
        &args.id,
        args.bundle.as_deref(),
        &sock_path,
    )?;
    if let Ok(meta) = std::fs::symlink_metadata(&work_root)
        && !meta.file_type().is_symlink()
        && meta.file_type().is_dir()
    {
        let _ = std::fs::remove_dir_all(&work_root);
    }

    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let resp = DeleteResponse {
        pid: 0,
        exit_status: 0,
        exited_at: Some(Timestamp::from_unix_nanos(now_ns)),
    };
    let encoded = resp.encode();
    std::io::stdout()
        .write_all(&encoded)
        .map_err(|e| e.to_string())?;
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    Ok(())
}

fn run_serve(args: &CliArgs) -> Result<(), String> {
    let sock_path = match &args.socket {
        Some(p) => p.clone(),
        None => derive_socket_path(&args.namespace, &args.id, args.bundle.as_deref())?,
    };
    validate_socket_path_syntax(&sock_path)?;
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create socket parent {}: {e}", parent.display()))?;
    }
    let work_root = derive_work_root(
        &args.namespace,
        &args.id,
        args.bundle.as_deref(),
        &sock_path,
    )?;
    std::fs::create_dir_all(&work_root)
        .map_err(|e| format!("create work root {}: {e}", work_root.display()))?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;
    let local = tokio::task::LocalSet::new();
    let res = local.block_on(&rt, async move {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let sig_tx = shutdown_tx.clone();
        tokio::task::spawn_local(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = sig_tx.send(true);
        });
        let svc = Arc::new(OsShimService::new(
            ShimConfig {
                namespace: args.namespace.clone(),
                csi_node_state_dir: args.csi_state.clone(),
                cni_state_dir: std::env::var_os("OS_CNI_STATE").map(PathBuf::from),
                work_root: work_root.clone(),
            },
            shutdown_tx,
        ));
        let serve_res = serve_ttrpc_unix(sock_path, svc, shutdown_rx).await;
        let _ = std::fs::remove_dir_all(&work_root);
        serve_res
    });
    res.map_err(|e| format!("ttrpc server: {e}"))
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("containerd-shim-os-v1: {e}");
            std::process::exit(2);
        }
    };
    if args.version {
        println!("containerd-shim-os-v1 {SHIM_VERSION}");
        return;
    }
    if args.info {
        println!("{RUNTIME_NAME} {SHIM_VERSION}");
        return;
    }

    let res = if args.serve {
        run_serve(&args)
    } else {
        match args.subcommand.as_deref() {
            Some("start") => run_start(&args),
            Some("delete") => run_delete(&args),
            _ => run_serve(&args),
        }
    };

    if let Err(e) = res {
        eprintln!("containerd-shim-os-v1: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_args_supports_go_equals_syntax() {
        let parsed = parse_args_from([
            "-namespace=k8s.io".to_string(),
            "--id=pod-42".to_string(),
            "-bundle=/var/run/bundle".to_string(),
            "--socket=unix:///tmp/test.sock".to_string(),
            "-csi-state=/var/lib/csi".to_string(),
            "-address=/run/containerd/containerd.sock".to_string(),
            "start".to_string(),
        ])
        .unwrap();
        assert_eq!(parsed.namespace, "k8s.io");
        assert_eq!(parsed.id, "pod-42");
        assert_eq!(parsed.bundle, Some(PathBuf::from("/var/run/bundle")));
        assert_eq!(parsed.socket, Some(PathBuf::from("/tmp/test.sock")));
        assert_eq!(parsed.csi_state, Some(PathBuf::from("/var/lib/csi")));
        assert_eq!(parsed.subcommand.as_deref(), Some("start"));
    }
}
