//! Standalone CNI v1.0.0 plugin binary (`os-cni`).
//!
//! Invoked per CNI specification with `CNI_COMMAND=VERSION|ADD|CHECK|DEL`, `CNI_CONTAINERID`,
//! `CNI_NETNS`, `CNI_IFNAME`, `CNI_ARGS`, and JSON network config on stdin.

use abi::auth_v2::RemoteScope;
use os_cluster_state::ClusterGrant;
use os_cni::OsCniPlugin;
use os_cni::http::HttpClusterStore;
use os_cni::spec::{
    CNI_ERR_INVALID_CONFIG, CNI_ERR_IO_FAILURE, CNI_STDIN_MAX_BYTES, CniCommand, CniEnv, CniError,
    CniNetConfig, CniVersionResult,
};
use std::io::Read;
use std::sync::Arc;

fn emit_error_and_exit(err: &CniError) -> ! {
    match serde_json::to_string(err) {
        Ok(json) => println!("{json}"),
        Err(_) => {
            println!("{{\"cniVersion\":\"1.0.0\",\"code\":100,\"msg\":\"serialization error\"}}")
        }
    }
    std::process::exit(1);
}

fn read_bounded_stdin() -> Result<Vec<u8>, CniError> {
    let mut buf = Vec::new();
    std::io::stdin()
        .take((CNI_STDIN_MAX_BYTES as u64) + 1)
        .read_to_end(&mut buf)
        .map_err(|e| CniError::new(CNI_ERR_IO_FAILURE, "failed to read stdin", e.to_string()))?;
    if buf.len() > CNI_STDIN_MAX_BYTES {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            "stdin config too large",
            format!("exceeded {CNI_STDIN_MAX_BYTES} bytes"),
        ));
    }
    Ok(buf)
}

fn main() {
    let env = CniEnv::from_process_env();
    let cmd = match env.validate() {
        Ok(c) => c,
        Err(e) => emit_error_and_exit(&e),
    };
    if cmd == CniCommand::Version {
        let out = serde_json::to_string(&CniVersionResult::default()).unwrap();
        println!("{out}");
        return;
    }

    let stdin_bytes = match read_bounded_stdin() {
        Ok(b) => b,
        Err(e) => emit_error_and_exit(&e),
    };
    let cfg = match CniNetConfig::parse_json(&stdin_bytes) {
        Ok(c) => c,
        Err(e) => emit_error_and_exit(&e),
    };

    let endpoint_url = match cfg.endpoint_url.clone() {
        Some(u) if !u.trim().is_empty() => u,
        _ => emit_error_and_exit(&CniError::new(
            CNI_ERR_INVALID_CONFIG,
            "missing endpointUrl",
            "os-cni CLI requires endpointUrl pointing at the ClusterState /api/cluster/rpc endpoint",
        )),
    };
    let token = match cfg.resolve_token() {
        Ok(t) => t,
        Err(e) => emit_error_and_exit(&e),
    };

    let store = Arc::new(HttpClusterStore::new(
        endpoint_url,
        cfg.cluster.clone(),
        cfg.tenant.clone(),
        token,
        cfg.instance_id.clone(),
    ));
    let grant = ClusterGrant {
        tenant: cfg.tenant.clone(),
        owner: format!("cni:{}", cfg.node_id),
        admin: false,
        scope: RemoteScope::node_ceiling(&cfg.node_id),
    };
    let plugin = OsCniPlugin::new(store, grant);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(plugin.execute(&env, &stdin_bytes)) {
        Ok(Some(out)) => println!("{out}"),
        Ok(None) => {}
        Err(e) => emit_error_and_exit(&e),
    }
}
