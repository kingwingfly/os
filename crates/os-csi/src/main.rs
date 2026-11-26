//! Standalone `os-csi` daemon CLI (`--endpoint unix://... --mode controller|node|all --node-id ... --state ...`).

use abi::auth_v2::RemoteScope;
use os_cluster_state::ClusterGrant;
use os_cluster_state::memory::MemoryClusterStore;
use os_csi::controller::{CsiControllerConfig, OsCsiController};
use os_csi::grpc_unix::{CsiGrpcServerHandle, CsiServiceRouter};
use os_csi::node::{CsiNodeConfig, OsCsiNode, StageMode};
use std::path::PathBuf;
use std::sync::Arc;

struct CliArgs {
    endpoint: String,
    mode: String,
    node_id: String,
    state_dir: PathBuf,
    tenant: String,
    stage_mode: StageMode,
}

fn parse_args() -> Result<CliArgs, String> {
    let mut endpoint = String::from("unix:///run/os-csi/csi.sock");
    let mut mode = String::from("all");
    let mut node_id = String::from("node-0");
    let mut state_dir = PathBuf::from("/var/lib/os-csi");
    let mut tenant = String::from("u0");
    let mut stage_mode = StageMode::Auto;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--endpoint" => endpoint = args.next().ok_or("missing --endpoint value")?,
            "--mode" => mode = args.next().ok_or("missing --mode value")?,
            "--node-id" => node_id = args.next().ok_or("missing --node-id value")?,
            "--state" => state_dir = PathBuf::from(args.next().ok_or("missing --state value")?),
            "--tenant" => tenant = args.next().ok_or("missing --tenant value")?,
            "--stage-mode" => {
                let raw = args.next().ok_or("missing --stage-mode value")?;
                stage_mode =
                    StageMode::parse(&raw).ok_or_else(|| format!("invalid --stage-mode: {raw}"))?;
            }
            "--help" | "-h" => {
                println!(
                    "os-csi --endpoint unix://<path> --mode controller|node|all --node-id <id> --state <dir> [--tenant u0] [--stage-mode auto|fuse|host-subvol]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if !matches!(mode.as_str(), "controller" | "node" | "all") {
        return Err(format!(
            "invalid --mode '{mode}' (expected controller|node|all)"
        ));
    }
    Ok(CliArgs {
        endpoint,
        mode,
        node_id,
        state_dir,
        tenant,
        stage_mode,
    })
}

fn main() {
    let cli = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("os-csi: {e}");
            std::process::exit(2);
        }
    };
    let sock_str = cli
        .endpoint
        .strip_prefix("unix://")
        .unwrap_or(&cli.endpoint);
    if sock_str.is_empty()
        || sock_str.contains('\0')
        || std::path::Path::new(sock_str)
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        eprintln!("os-csi: invalid socket endpoint path: {}", cli.endpoint);
        std::process::exit(2);
    }
    let sock_path = PathBuf::from(sock_str);
    if let Some(parent) = sock_path.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        eprintln!("os-csi: create socket parent {}: {e}", parent.display());
        std::process::exit(1);
    }

    let store_dir = cli.state_dir.join("store");
    let node_state = cli.state_dir.join("node");
    let grant = ClusterGrant {
        tenant: cli.tenant.clone(),
        owner: format!("csi:{}", cli.node_id),
        admin: true,
        scope: RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_watch: true,
            cluster_lease: true,
            ..RemoteScope::default()
        },
    };

    let cluster = Arc::new(MemoryClusterStore::new("default"));
    let ctrl = Arc::new(OsCsiController::new(
        Arc::clone(&cluster),
        CsiControllerConfig::new(cli.tenant.clone(), grant.clone(), store_dir.clone()),
    ));
    let mut node_cfg = CsiNodeConfig::new(
        cli.node_id.clone(),
        cli.tenant.clone(),
        grant,
        node_state,
        store_dir,
    );
    node_cfg.stage_mode = cli.stage_mode;
    let node = Arc::new(OsCsiNode::new(Arc::clone(&cluster), node_cfg));

    let router = match cli.mode.as_str() {
        "controller" => CsiServiceRouter::new(ctrl.clone(), Some(ctrl), None),
        "node" => CsiServiceRouter::new(node.clone(), None, Some(node)),
        _ => CsiServiceRouter::new(ctrl.clone(), Some(ctrl), Some(node)),
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current_thread runtime");
    rt.block_on(async move {
        let mut server = match CsiGrpcServerHandle::bind_and_spawn(sock_path.clone(), router) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("os-csi: bind {}: {e}", sock_path.display());
                std::process::exit(1);
            }
        };
        eprintln!(
            "os-csi listening on unix://{} (mode={}, node={})",
            sock_path.display(),
            cli.mode,
            cli.node_id
        );
        let _ = tokio::signal::ctrl_c().await;
        server.shutdown().await;
    });
}
