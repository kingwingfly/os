//! OV-03: CNI Spec v1.0.0 conformance tests for `os-cni` (library + compiled CLI binary).

use abi::auth_v2::RemoteScope;
use abi::cluster_state::{ClusterCall, ClusterReply, ClusterRpcRequest, RangeEnd};
use abi::overlay::{overlay_endpoint_key, overlay_ipam_v4_key};
use os_cluster_state::memory::MemoryClusterStore;
use os_cluster_state::{ClusterGrant, ClusterStore};
use os_cni::OsCniPlugin;
use os_cni::spec::{
    CNI_ERR_INCOMPATIBLE_VERSION, CNI_ERR_INVALID_CONFIG, CNI_ERR_INVALID_ENV,
    CNI_ERR_TRY_AGAIN_LATER, CNI_SPEC_VERSION, CniEnv, CniError, CniResult, CniVersionResult,
    load_cni_attachment,
};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

fn unique_temp_dir(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("os-cni-test-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn node_grant(tenant: &str, node_id: &str) -> ClusterGrant {
    ClusterGrant {
        tenant: tenant.to_string(),
        owner: format!("node:{node_id}"),
        admin: false,
        scope: RemoteScope::node_ceiling(node_id),
    }
}

fn base_config_json(state_dir: &std::path::Path, extra: &str) -> Vec<u8> {
    let dir = state_dir.to_string_lossy();
    let comma = if extra.trim().is_empty() { "" } else { "," };
    format!(
        r#"{{"cniVersion":"1.0.0","name":"default","type":"os-cni","tenant":"u1000","cluster":"default","nodeId":"node-a","stateDir":"{dir}","driver":"userspace","mtu":1420,"leaseTtlSecs":30{comma}{extra}}}"#
    )
    .into_bytes()
}

fn cni_env(cmd: &str, cid: &str, ifname: &str, netns: &str) -> CniEnv {
    CniEnv {
        command: cmd.to_string(),
        container_id: cid.to_string(),
        netns: netns.to_string(),
        ifname: ifname.to_string(),
        args: String::new(),
        path: String::new(),
    }
}

#[tokio::test]
async fn ov03_version_validation_and_hygiene() {
    let dir = unique_temp_dir("hygiene");
    let store = Arc::new(MemoryClusterStore::new("default"));
    let plugin = OsCniPlugin::new(store, node_grant("u1000", "node-a"));

    // VERSION
    let ver_json = plugin
        .execute(&cni_env("VERSION", "", "", ""), b"")
        .await
        .expect("VERSION succeeds")
        .expect("VERSION prints JSON");
    let ver: CniVersionResult = serde_json::from_str(&ver_json).unwrap();
    assert_eq!(ver.cni_version, CNI_SPEC_VERSION);
    assert_eq!(ver.supported_versions, vec!["1.0.0".to_string()]);

    // Incompatible cniVersion -> code 1
    let bad_ver = br#"{"cniVersion":"0.4.0","name":"default","type":"os-cni"}"#;
    let err = plugin
        .execute(&cni_env("ADD", "pod-1", "eth0", "/run/netns/p1"), bad_ver)
        .await
        .unwrap_err();
    assert_eq!(err.code, CNI_ERR_INCOMPATIBLE_VERSION);

    // Invalid CNI_COMMAND / container id / ifname -> code 4
    let cfg = base_config_json(&dir, "");
    let err = plugin
        .execute(&cni_env("BOGUS", "pod-1", "eth0", "/run/netns/p1"), &cfg)
        .await
        .unwrap_err();
    assert_eq!(err.code, CNI_ERR_INVALID_ENV);

    let err = plugin
        .execute(&cni_env("ADD", "../escape", "eth0", "/run/netns/p1"), &cfg)
        .await
        .unwrap_err();
    assert_eq!(err.code, CNI_ERR_INVALID_ENV);

    let err = plugin
        .execute(&cni_env("ADD", "pod-1", "bad/name", "/run/netns/p1"), &cfg)
        .await
        .unwrap_err();
    assert_eq!(err.code, CNI_ERR_INVALID_ENV);

    // Path traversal in netns and stateDir rejected
    let err = plugin
        .execute(&cni_env("ADD", "pod-1", "eth0", "/run/netns/../etc"), &cfg)
        .await
        .unwrap_err();
    assert_eq!(err.code, CNI_ERR_INVALID_CONFIG);

    let bad_state = format!(
        r#"{{"cniVersion":"1.0.0","name":"default","type":"os-cni","stateDir":"{}/../escape"}}"#,
        dir.display()
    );
    let err = plugin
        .execute(
            &cni_env("ADD", "pod-1", "eth0", "/run/netns/p1"),
            bad_state.as_bytes(),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, CNI_ERR_INVALID_CONFIG);

    // Symlink stateDir rejected (O_NOFOLLOW)
    let real_target = dir.join("real");
    let link_path = dir.join("sym-state");
    std::fs::create_dir_all(&real_target).unwrap();
    std::os::unix::fs::symlink(&real_target, &link_path).unwrap();
    let sym_cfg = base_config_json(&link_path, "");
    let err = plugin
        .execute(&cni_env("ADD", "pod-1", "eth0", "/run/netns/p1"), &sym_cfg)
        .await
        .unwrap_err();
    assert_eq!(err.code, CNI_ERR_INVALID_CONFIG);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn ov03_ipam_add_check_del_exhaustion_and_host_loss_cas() {
    let dir = unique_temp_dir("hostloss");
    let now = Arc::new(AtomicU64::new(1_700_000_000));
    let now_clone = Arc::clone(&now);
    let store = Arc::new(MemoryClusterStore::new("default"));
    let grant = node_grant("u1000", "node-a");
    let plugin = OsCniPlugin::new(Arc::clone(&store), grant.clone())
        .with_clock(Arc::new(move || now_clone.load(Ordering::SeqCst)));

    // Use a /29 inside 10.64.0.0/10 -> 10.65.0.0/29: .0 net, .1 gw, .2..=.6 hosts (5 total), .7 bcast.
    let cfg = base_config_json(&dir, r#""cidr":"10.65.0.0/29""#);

    // 1. ADD pod-1
    let res1_json = plugin
        .execute(&cni_env("ADD", "pod-1", "eth0", "/run/netns/pod1"), &cfg)
        .await
        .expect("ADD pod-1")
        .expect("ADD result");
    let res1: CniResult = serde_json::from_str(&res1_json).unwrap();
    assert_eq!(res1.cni_version, "1.0.0");
    assert_eq!(res1.ips.len(), 1);
    assert_eq!(res1.ips[0].address, "10.65.0.2/29");
    assert_eq!(res1.ips[0].gateway.as_deref(), Some("10.65.0.1"));

    // Idempotent retry for same pod-1 returns same IP & lease.
    let res1_retry_json = plugin
        .execute(&cni_env("ADD", "pod-1", "eth0", "/run/netns/pod1"), &cfg)
        .await
        .expect("ADD pod-1 retry")
        .expect("retry result");
    let res1_retry: CniResult = serde_json::from_str(&res1_retry_json).unwrap();
    assert_eq!(res1_retry.ips[0].address, "10.65.0.2/29");

    // CHECK succeeds while lease is live.
    assert!(
        plugin
            .execute(&cni_env("CHECK", "pod-1", "eth0", "/run/netns/pod1"), &cfg)
            .await
            .is_ok()
    );

    // 2. Static IP allocation for pod-2 (.5) and fill remaining hosts (.3, .4, .6) -> 6th fails.
    let static_cfg = base_config_json(&dir, r#""cidr":"10.65.0.0/29","staticIp":"10.65.0.5""#);
    let res2_json = plugin
        .execute(
            &cni_env("ADD", "pod-2", "eth0", "/run/netns/pod2"),
            &static_cfg,
        )
        .await
        .unwrap()
        .unwrap();
    let res2: CniResult = serde_json::from_str(&res2_json).unwrap();
    assert_eq!(res2.ips[0].address, "10.65.0.5/29");

    // Static IP conflict fails cleanly.
    let conflict = plugin
        .execute(
            &cni_env("ADD", "pod-dup", "eth0", "/run/netns/dup"),
            &static_cfg,
        )
        .await
        .unwrap_err();
    assert_eq!(conflict.code, CNI_ERR_TRY_AGAIN_LATER);

    for cid in ["pod-3", "pod-4", "pod-5"] {
        plugin
            .execute(
                &cni_env("ADD", cid, "eth0", &format!("/run/netns/{cid}")),
                &cfg,
            )
            .await
            .expect("allocate remaining host");
    }
    // Subnet exhausted (5 of 5 host IPs allocated).
    let full_err = plugin
        .execute(&cni_env("ADD", "pod-6", "eth0", "/run/netns/pod6"), &cfg)
        .await
        .unwrap_err();
    assert_eq!(full_err.code, CNI_ERR_TRY_AGAIN_LATER);

    // 3. Normal DEL + idempotent double-DEL on pod-5.
    assert!(
        plugin
            .execute(&cni_env("DEL", "pod-5", "eth0", "/run/netns/pod5"), &cfg)
            .await
            .is_ok()
    );
    assert!(load_cni_attachment(&dir, "pod-5").unwrap().is_none());
    assert!(
        plugin
            .execute(&cni_env("DEL", "pod-5", "eth0", "/run/netns/pod5"), &cfg)
            .await
            .is_ok()
    );

    // 4. Simulated host loss while lease is STILL active: wipe pod-4's local state, then DEL!
    let pod4_desc = load_cni_attachment(&dir, "pod-4").unwrap().unwrap();
    let pod4_ip: Ipv4Addr = pod4_desc.ip.parse().unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&dir).unwrap();
    assert!(
        plugin
            .execute(&cni_env("DEL", "pod-4", "eth0", ""), &cfg)
            .await
            .is_ok()
    );
    // ClusterState IP key for pod-4 must have been recovered and freed.
    let check_pod4 = store
        .rpc(
            &grant,
            ClusterCall::Range {
                key: overlay_ipam_v4_key("u1000", pod4_ip),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
            now.load(Ordering::SeqCst),
        )
        .await
        .unwrap();
    match check_pod4 {
        ClusterReply::Range { kvs, .. } => assert!(kvs.is_empty(), "pod-4 IP should be released"),
        _ => panic!("expected Range"),
    }

    // 5. Simulated host loss + lease expiry + IP reallocation + delayed DEL CAS guard!
    // Advance clock past 30s TTL so pod-1, pod-2, pod-3 leases expire.
    now.fetch_add(60, Ordering::SeqCst);
    // Re-create pod-1's local file just to verify CHECK detects lease expiry too.
    // First confirm pod-new allocates 10.65.0.2 (which previously belonged to pod-1!).
    let res_new_json = plugin
        .execute(
            &cni_env("ADD", "pod-new", "eth0", "/run/netns/podnew"),
            &cfg,
        )
        .await
        .expect("ADD pod-new after lease expiry")
        .expect("result");
    let res_new: CniResult = serde_json::from_str(&res_new_json).unwrap();
    assert_eq!(res_new.ips[0].address, "10.65.0.2/29");

    // Now simulate delayed DEL for pod-1 (even if pod-1's stale local file still pointed at 10.65.0.2!).
    // Persist a stale descriptor for pod-1 pointing to 10.65.0.2 with old lease_id.
    let stale_desc = os_cni::spec::CniAttachmentDescriptor {
        version: 1,
        container_id: "pod-1".into(),
        ifname: "eth0".into(),
        netns: "/run/netns/pod1".into(),
        tenant: "u1000".into(),
        cluster: "default".into(),
        network: "default".into(),
        node_id: "node-a".into(),
        ip: "10.65.0.2".into(),
        prefix_len: 29,
        gateway: "10.65.0.1".into(),
        cidr: "10.65.0.0/29".into(),
        ipv6: None,
        mtu: 1420,
        lease_id: 1, // old expired lease
        fence_epoch: 1,
        driver: "userspace".into(),
        created_at: 1_700_000_000,
    };
    os_cni::spec::save_cni_attachment(&dir, &stale_desc).unwrap();

    // CHECK on stale pod-1 MUST fail!
    assert!(
        plugin
            .execute(&cni_env("CHECK", "pod-1", "eth0", "/run/netns/pod1"), &cfg)
            .await
            .is_err()
    );

    // Delayed DEL on pod-1 MUST exit cleanly AND MUST NOT clobber pod-new's 10.65.0.2!
    assert!(
        plugin
            .execute(&cni_env("DEL", "pod-1", "eth0", "/run/netns/pod1"), &cfg)
            .await
            .is_ok()
    );
    // pod-new's CHECK MUST still pass and 10.65.0.2 MUST still belong to pod-new!
    assert!(
        plugin
            .execute(
                &cni_env("CHECK", "pod-new", "eth0", "/run/netns/podnew"),
                &cfg
            )
            .await
            .is_ok(),
        "delayed DEL for pod-1 MUST NOT clobber pod-new's reallocated IP!"
    );

    let ep_new = store
        .rpc(
            &grant,
            ClusterCall::Range {
                key: overlay_endpoint_key("u1000", "pod-new"),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
            now.load(Ordering::SeqCst),
        )
        .await
        .unwrap();
    match ep_new {
        ClusterReply::Range { kvs, .. } => assert_eq!(kvs.len(), 1),
        _ => panic!("expected Range"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn ov03_cli_binary_over_http_cluster_rpc() {
    let dir = unique_temp_dir("cli");
    let store = Arc::new(MemoryClusterStore::new("default"));
    let grant = node_grant("u1000", "node-cli");

    // Start tiny HTTP/1.1 mock server for POST /api/cluster/rpc backed by MemoryClusterStore.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let srv_store = Arc::clone(&store);
    let srv_grant = grant.clone();
    let srv = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let st = Arc::clone(&srv_store);
            let gr = srv_grant.clone();
            tokio::spawn(async move {
                let mut reader = BufReader::new(stream);
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).await.unwrap_or(0) == 0 {
                    return;
                }
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        break;
                    }
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = trimmed.split_once(':')
                        && k.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_len = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_len];
                if reader.read_exact(&mut body).await.is_err() {
                    return;
                }
                let rpc_req: ClusterRpcRequest = serde_json::from_slice(&body).unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let (status, resp_body) = match st.rpc(&gr, rpc_req.call, now).await {
                    Ok(reply) => (200, serde_json::to_vec(&reply).unwrap()),
                    Err(err) => (400, serde_json::to_vec(&err).unwrap()),
                };
                let mut stream = reader.into_inner();
                let hdr = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    resp_body.len()
                );
                let _ = stream.write_all(hdr.as_bytes()).await;
                let _ = stream.write_all(&resp_body).await;
                let _ = stream.flush().await;
            });
        }
    });

    let bin = env!("CARGO_BIN_EXE_os-cni");
    let run_cli = move |cmd: &str, cid: &str, ifname: &str, netns: &str, stdin_bytes: &[u8]| {
        let mut child = Command::new(bin)
            .env("CNI_COMMAND", cmd)
            .env("CNI_CONTAINERID", cid)
            .env("CNI_IFNAME", ifname)
            .env("CNI_NETNS", netns)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn os-cni");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin_bytes)
            .unwrap();
        child.wait_with_output().unwrap()
    };

    // VERSION via CLI binary
    let ver_out = run_cli("VERSION", "", "", "", b"");
    assert!(ver_out.status.success());
    let ver: CniVersionResult = serde_json::from_slice(&ver_out.stdout).unwrap();
    assert_eq!(ver.cni_version, "1.0.0");

    // ADD -> CHECK -> DEL -> DEL via CLI binary
    let cfg = format!(
        r#"{{"cniVersion":"1.0.0","name":"default","type":"os-cni","tenant":"u1000","cluster":"default","nodeId":"node-cli","endpointUrl":"http://{addr}","stateDir":"{}","driver":"userspace"}}"#,
        dir.display()
    );
    let add_out = tokio::task::spawn_blocking({
        let cfg = cfg.clone();
        move || {
            run_cli(
                "ADD",
                "cli-pod-1",
                "eth0",
                "/run/netns/cli1",
                cfg.as_bytes(),
            )
        }
    })
    .await
    .unwrap();
    assert!(
        add_out.status.success(),
        "ADD failed: stdout={} stderr={}",
        String::from_utf8_lossy(&add_out.stdout),
        String::from_utf8_lossy(&add_out.stderr)
    );
    let add_res: CniResult = serde_json::from_slice(&add_out.stdout).unwrap();
    assert_eq!(add_res.ips.len(), 1);
    assert!(add_res.ips[0].address.starts_with("10."));

    let check_out = tokio::task::spawn_blocking({
        let cfg = cfg.clone();
        move || {
            run_cli(
                "CHECK",
                "cli-pod-1",
                "eth0",
                "/run/netns/cli1",
                cfg.as_bytes(),
            )
        }
    })
    .await
    .unwrap();
    assert!(check_out.status.success());
    assert!(check_out.stdout.is_empty());

    // Incompatible version via CLI binary returns exit 1 with CNI error JSON code 1.
    let bad_out = tokio::task::spawn_blocking(move || {
        run_cli(
            "ADD",
            "cli-bad",
            "eth0",
            "/run/netns/bad",
            br#"{"cniVersion":"0.3.1","name":"default","type":"os-cni"}"#,
        )
    })
    .await
    .unwrap();
    assert!(!bad_out.status.success());
    let bad_err: CniError = serde_json::from_slice(&bad_out.stdout).unwrap();
    assert_eq!(bad_err.code, CNI_ERR_INCOMPATIBLE_VERSION);

    for _ in 0..2 {
        let del_out = tokio::task::spawn_blocking({
            let cfg = cfg.clone();
            move || {
                run_cli(
                    "DEL",
                    "cli-pod-1",
                    "eth0",
                    "/run/netns/cli1",
                    cfg.as_bytes(),
                )
            }
        })
        .await
        .unwrap();
        assert!(del_out.status.success());
    }

    srv.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
