use abi::Errno;
use abi::auth_v2::RemoteScope;
use os_cluster_state::ClusterGrant;
use os_cluster_state::memory::MemoryClusterStore;
use os_csi::controller::{CsiControllerConfig, OsCsiController};
use os_csi::grpc_unix::{CsiGrpcClient, CsiGrpcServerHandle, CsiServiceRouter};
use os_csi::node::{CsiNodeConfig, OsCsiNode, StageMode, load_published_descriptor};
use os_csi::spec::*;
use os_nbd::{NBD_EIO, NBD_EPERM, NbdClient, NbdClientError};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn unique_test_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .filter(|p| p.as_os_str().len() <= 55)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = base.join(format!(
        "os-csi-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn csi_grant(tenant: &str) -> ClusterGrant {
    ClusterGrant {
        tenant: tenant.to_string(),
        owner: "csi-test".into(),
        admin: true,
        scope: RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_watch: true,
            cluster_lease: true,
            ..RemoteScope::default()
        },
    }
}

#[test]
fn csi_grpc_unix_fs_and_block_lifecycle_snapshots_ro_and_fencing() {
    let dir = unique_test_dir("full");
    let store_dir = dir.join("store");
    let node1_state = dir.join("node1");
    let node2_state = dir.join("node2");
    let mounts_root = dir.join("mounts");
    std::fs::create_dir_all(&mounts_root).unwrap();
    let sock_n1 = dir.join("csi-node1.sock");
    let sock_n2 = dir.join("csi-node2.sock");

    let clock_secs = Arc::new(AtomicU64::new(1_700_000_000));
    let clk = Arc::clone(&clock_secs);
    let clock_fn: os_csi::controller::ClockFn = Arc::new(move || clk.load(Ordering::SeqCst));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let cluster = Arc::new(MemoryClusterStore::new("default"));
        let grant = csi_grant("u0");

        let mut ctrl_cfg = CsiControllerConfig::new("u0", grant.clone(), store_dir.clone());
        ctrl_cfg.lease_ttl_secs = 5;
        ctrl_cfg.clock = Arc::clone(&clock_fn);
        let ctrl = Arc::new(OsCsiController::new(Arc::clone(&cluster), ctrl_cfg));

        let mut n1_cfg = CsiNodeConfig::new(
            "node-1",
            "u0",
            grant.clone(),
            node1_state.clone(),
            store_dir.clone(),
        );
        n1_cfg.allowed_mount_root = Some(mounts_root.clone());
        n1_cfg.stage_mode = StageMode::HostSubvol;
        n1_cfg.clock = Arc::clone(&clock_fn);
        n1_cfg.keepalive_interval_override = Some(Duration::from_secs(60));
        let node1 = Arc::new(OsCsiNode::new(Arc::clone(&cluster), n1_cfg));

        let mut n2_cfg = CsiNodeConfig::new(
            "node-2",
            "u0",
            grant.clone(),
            node2_state.clone(),
            store_dir.clone(),
        );
        n2_cfg.allowed_mount_root = Some(mounts_root.clone());
        n2_cfg.stage_mode = StageMode::HostSubvol;
        n2_cfg.clock = Arc::clone(&clock_fn);
        n2_cfg.keepalive_interval_override = Some(Duration::from_secs(60));
        let node2 = Arc::new(OsCsiNode::new(Arc::clone(&cluster), n2_cfg));

        let mut srv1 = CsiGrpcServerHandle::bind_and_spawn(
            sock_n1.clone(),
            CsiServiceRouter::new(ctrl.clone(), Some(ctrl.clone()), Some(node1.clone())),
        )
        .unwrap();
        let mut srv2 = CsiGrpcServerHandle::bind_and_spawn(
            sock_n2.clone(),
            CsiServiceRouter::new(ctrl.clone(), Some(ctrl.clone()), Some(node2.clone())),
        )
        .unwrap();

        assert_eq!(
            std::fs::metadata(&sock_n1).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut c1 = CsiGrpcClient::connect_unix(&sock_n1).await.unwrap();
        let mut c2 = CsiGrpcClient::connect_unix(&sock_n2).await.unwrap();

        // 1. Identity Probe + GetPluginInfo + NodeGetInfo
        let info = c1.get_plugin_info().await.unwrap();
        assert_eq!(info.name, os_csi::CSI_DRIVER_NAME);
        assert_eq!(c1.probe().await.unwrap().ready, Some(true));
        assert_eq!(c1.node_get_info().await.unwrap().node_id, "node-1");

        // 2. MULTI_NODE_MULTI_WRITER refused on CreateVolume & ControllerPublishVolume!
        let bad_create = c1
            .create_volume(&CreateVolumeRequest {
                name: "bad-rwx".into(),
                volume_capabilities: vec![VolumeCapability::mount(
                    "cowfs",
                    AccessMode::MultiNodeMultiWriter,
                )],
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(bad_create.code, CsiStatusCode::InvalidArgument);

        // 3. Create cowfs FS volume (idempotent) -> Publish -> Stage -> Publish -> Write -> Snapshot -> O(1) Restore!
        let fs_cap = VolumeCapability::mount("cowfs", AccessMode::SingleNodeWriter);
        let v_fs = c1
            .create_volume(&CreateVolumeRequest {
                name: "app-data".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 16 * 1024 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![fs_cap.clone()],
                ..Default::default()
            })
            .await
            .unwrap()
            .volume;
        // Idempotent repeat returns same volume_id.
        let v_fs_again = c1
            .create_volume(&CreateVolumeRequest {
                name: "app-data".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 16 * 1024 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![fs_cap.clone()],
                ..Default::default()
            })
            .await
            .unwrap()
            .volume;
        assert_eq!(v_fs.volume_id, v_fs_again.volume_id);

        let pub1 = c1
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_fs.volume_id.clone(),
                node_id: "node-1".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(pub1.publish_context["os.csi/fence_epoch"], "1");

        // DeleteVolume MUST refuse while published!
        let del_busy = c1
            .delete_volume(&DeleteVolumeRequest {
                volume_id: v_fs.volume_id.clone(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(del_busy.code, CsiStatusCode::FailedPrecondition);

        // Second node RW publish MUST be refused while node-1 lease is live!
        let rw_conflict = c2
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_fs.volume_id.clone(),
                node_id: "node-2".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(rw_conflict.code, CsiStatusCode::FailedPrecondition);

        // Traversal path rejected by NodeStageVolume!
        let bad_stage = c1
            .node_stage_volume(&NodeStageVolumeRequest {
                volume_id: v_fs.volume_id.clone(),
                publish_context: pub1.publish_context.clone(),
                staging_target_path: format!("{}/../escape", mounts_root.display()),
                volume_capability: Some(fs_cap.clone()),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(bad_stage.code, CsiStatusCode::InvalidArgument);

        let stage1 = mounts_root.join("stage-fs-1");
        let target1 = mounts_root.join("pub-fs-1");
        c1.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_fs.volume_id.clone(),
            publish_context: pub1.publish_context.clone(),
            staging_target_path: stage1.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        c1.node_publish_volume(&NodePublishVolumeRequest {
            volume_id: v_fs.volume_id.clone(),
            publish_context: pub1.publish_context.clone(),
            staging_target_path: stage1.to_string_lossy().into_owned(),
            target_path: target1.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            readonly: false,
            ..Default::default()
        })
        .await
        .unwrap();

        // Published descriptor stored strictly in $NODE_STATE/published/ (NOT inside target dir!).
        assert!(load_published_descriptor(&node1_state, &target1).is_some());
        assert_eq!(std::fs::read_dir(&target1).unwrap().count(), 0);

        // Write file through live fenced CowFs actor + commit.
        node1
            .write_staged_file(&v_fs.volume_id, "state/msg.txt", b"hello-csi-cowfs", true)
            .await
            .unwrap();
        assert_eq!(
            node1
                .read_staged_file(&v_fs.volume_id, "state/msg.txt")
                .await
                .unwrap(),
            b"hello-csi-cowfs"
        );

        // Create O(1) snapshot and restore into a brand-new volume!
        let snap = c1
            .create_snapshot(&CreateSnapshotRequest {
                source_volume_id: v_fs.volume_id.clone(),
                name: "snap-app-1".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .snapshot;
        assert!(snap.ready_to_use);

        let restored = c1
            .create_volume(&CreateVolumeRequest {
                name: "app-data-restored".into(),
                volume_capabilities: vec![fs_cap.clone()],
                volume_content_source: Some(VolumeContentSource::Snapshot {
                    snapshot_id: snap.snapshot_id.clone(),
                }),
                ..Default::default()
            })
            .await
            .unwrap()
            .volume;

        let pub_r = c2
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: restored.volume_id.clone(),
                node_id: "node-2".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        let stage_r = mounts_root.join("stage-fs-restored");
        c2.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: restored.volume_id.clone(),
            publish_context: pub_r.publish_context.clone(),
            staging_target_path: stage_r.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(
            node2
                .read_staged_file(&restored.volume_id, "state/msg.txt")
                .await
                .unwrap(),
            b"hello-csi-cowfs"
        );

        // 4. Lease expiry -> node-2 takeover -> stale node-1 FS write fails closed with ESTALE!
        clock_secs.fetch_add(10, Ordering::SeqCst); // expire 5s lease!
        let pub_takeover = c2
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_fs.volume_id.clone(),
                node_id: "node-2".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(pub_takeover.publish_context["os.csi/fence_epoch"], "2");
        let stage2 = mounts_root.join("stage-fs-2");
        c2.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_fs.volume_id.clone(),
            publish_context: pub_takeover.publish_context.clone(),
            staging_target_path: stage2.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        node2
            .write_staged_file(&v_fs.volume_id, "state/msg.txt", b"node2-wins", true)
            .await
            .unwrap();

        // Stale node-1 fails closed with ESTALE BOTH on CowFs commit CAS AND on fence check!
        assert_eq!(
            node1
                .write_staged_file(&v_fs.volume_id, "state/msg.txt", b"node1-stale", true)
                .await,
            Err(Errno::ESTALE)
        );
        assert!(node1.is_volume_fenced(&v_fs.volume_id));
        assert_eq!(
            node1.check_and_enforce_fence(&v_fs.volume_id).await,
            Err(Errno::ESTALE)
        );

        // 5. Raw Block volume -> NBD Unix socket export -> write/read -> snapshot -> restore -> competing takeover fencing!
        let blk_cap = VolumeCapability::block(AccessMode::SingleNodeWriter);
        let mut blk_params = BTreeMap::new();
        blk_params.insert("block_size".into(), "4096".into());
        let v_blk = c1
            .create_volume(&CreateVolumeRequest {
                name: "raw-disk-0".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 128 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![blk_cap.clone()],
                parameters: blk_params,
                ..Default::default()
            })
            .await
            .unwrap()
            .volume;
        let pub_b1 = c1
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_blk.volume_id.clone(),
                node_id: "node-1".into(),
                volume_capability: Some(blk_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        let stage_b1 = mounts_root.join("stage-blk-1");
        let target_b1 = mounts_root.join("pub-blk-1.bind");
        c1.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_blk.volume_id.clone(),
            publish_context: pub_b1.publish_context.clone(),
            staging_target_path: stage_b1.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        c1.node_publish_volume(&NodePublishVolumeRequest {
            volume_id: v_blk.volume_id.clone(),
            publish_context: pub_b1.publish_context.clone(),
            staging_target_path: stage_b1.to_string_lossy().into_owned(),
            target_path: target_b1.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            readonly: false,
            ..Default::default()
        })
        .await
        .unwrap();

        let nbd1_sock = node1.nbd_socket_for_volume(&v_blk.volume_id).unwrap();
        let mut nbd1 = NbdClient::connect_unix(&nbd1_sock).await.unwrap();
        let exp = nbd1.go(&v_blk.volume_id).await.unwrap();
        assert_eq!(exp.size_bytes, 128 * 1024);
        nbd1.write(4096, b"CSI-RAW-BLOCK-V1", true).await.unwrap();
        assert_eq!(&nbd1.read(4096, 16).await.unwrap(), b"CSI-RAW-BLOCK-V1");

        // Snapshot raw block volume & O(1) restore!
        let bsnap = c1
            .create_snapshot(&CreateSnapshotRequest {
                source_volume_id: v_blk.volume_id.clone(),
                name: "raw-snap-1".into(),
                ..Default::default()
            })
            .await
            .unwrap()
            .snapshot;
        let v_blk_clone = c1
            .create_volume(&CreateVolumeRequest {
                name: "raw-disk-clone".into(),
                volume_capabilities: vec![VolumeCapability::block(AccessMode::MultiNodeReaderOnly)],
                volume_content_source: Some(VolumeContentSource::Snapshot {
                    snapshot_id: bsnap.snapshot_id.clone(),
                }),
                ..Default::default()
            })
            .await
            .unwrap()
            .volume;

        // Concurrent RO publish on BOTH node-1 and node-2!
        let ro_cap = VolumeCapability::block(AccessMode::MultiNodeReaderOnly);
        let pub_ro1 = c1
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_blk_clone.volume_id.clone(),
                node_id: "node-1".into(),
                volume_capability: Some(ro_cap.clone()),
                readonly: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let pub_ro2 = c2
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_blk_clone.volume_id.clone(),
                node_id: "node-2".into(),
                volume_capability: Some(ro_cap.clone()),
                readonly: true,
                ..Default::default()
            })
            .await
            .unwrap();
        c1.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_blk_clone.volume_id.clone(),
            publish_context: pub_ro1.publish_context.clone(),
            staging_target_path: mounts_root
                .join("stage-ro-1")
                .to_string_lossy()
                .into_owned(),
            volume_capability: Some(ro_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        c2.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_blk_clone.volume_id.clone(),
            publish_context: pub_ro2.publish_context.clone(),
            staging_target_path: mounts_root
                .join("stage-ro-2")
                .to_string_lossy()
                .into_owned(),
            volume_capability: Some(ro_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        let mut nbd_ro2 =
            NbdClient::connect_unix(&node2.nbd_socket_for_volume(&v_blk_clone.volume_id).unwrap())
                .await
                .unwrap();
        nbd_ro2.go(&v_blk_clone.volume_id).await.unwrap();
        assert_eq!(&nbd_ro2.read(4096, 16).await.unwrap(), b"CSI-RAW-BLOCK-V1");
        assert!(matches!(
            nbd_ro2.write(0, b"ro-deny", false).await,
            Err(NbdClientError::ServerError(NBD_EPERM))
        ));
        nbd_ro2.disconnect().await.unwrap();

        // Lease expiry -> node-2 takes over raw block volume -> stale node-1 NBD FUA write fails closed with NBD_EIO!
        clock_secs.fetch_add(10, Ordering::SeqCst);
        let pub_b2 = c2
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_blk.volume_id.clone(),
                node_id: "node-2".into(),
                volume_capability: Some(blk_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(pub_b2.publish_context["os.csi/fence_epoch"], "2");
        c2.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_blk.volume_id.clone(),
            publish_context: pub_b2.publish_context.clone(),
            staging_target_path: mounts_root
                .join("stage-blk-2")
                .to_string_lossy()
                .into_owned(),
            volume_capability: Some(blk_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        let mut nbd2 =
            NbdClient::connect_unix(&node2.nbd_socket_for_volume(&v_blk.volume_id).unwrap())
                .await
                .unwrap();
        nbd2.go(&v_blk.volume_id).await.unwrap();
        nbd2.write(4096, b"NODE2-BLK-WINNER", true).await.unwrap();

        // Stale node-1 NBD client MUST fail closed with NBD_EIO, flip `node1.is_volume_fenced`
        // to `true` (P1-3), AND propagate `ESTALE` from `NodeUnstageVolume` (P1-1b)!
        assert!(matches!(
            nbd1.write(4096, b"NODE1-BLK-STALE!", true).await,
            Err(NbdClientError::ServerError(NBD_EIO))
        ));
        assert!(
            node1.is_volume_fenced(&v_blk.volume_id),
            "NBD CAS ESTALE must flip node1's external fence_flag to true"
        );
        assert_eq!(&nbd2.read(4096, 16).await.unwrap(), b"NODE2-BLK-WINNER");

        nbd1.disconnect().await.unwrap();
        let unstage_stale_err = c1
            .node_unstage_volume(&NodeUnstageVolumeRequest {
                volume_id: v_blk.volume_id.clone(),
                staging_target_path: stage_b1.to_string_lossy().into_owned(),
            })
            .await
            .expect_err("NodeUnstageVolume on fenced NBD volume must propagate ESTALE");
        assert_eq!(unstage_stale_err.code, CsiStatusCode::FailedPrecondition);
        assert!(
            unstage_stale_err.message.contains("ESTALE"),
            "unexpected unstage error: {unstage_stale_err}"
        );
        nbd2.disconnect().await.unwrap();

        // 6. P1-1(a) & P1-6 regressions:
        //    (a) Non-FUA buffered NBD write persists across `NodeUnstageVolume` + re-stage;
        //    (b) Re-staging a volume with a newer `fence_epoch` without unstaging first stops the
        //        old stage BEFORE creating the new NBD socket so the new socket stays live!
        let v_blk_nf = c1
            .create_volume(&CreateVolumeRequest {
                name: "raw-nonfua-restage".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 64 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![blk_cap.clone()],
                ..Default::default()
            })
            .await
            .unwrap()
            .volume;
        let pub_nf1 = c1
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_blk_nf.volume_id.clone(),
                node_id: "node-1".into(),
                volume_capability: Some(blk_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        let stage_nf = mounts_root.join("stage-nonfua");
        c1.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_blk_nf.volume_id.clone(),
            publish_context: pub_nf1.publish_context.clone(),
            staging_target_path: stage_nf.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        {
            let sock_nf = node1.nbd_socket_for_volume(&v_blk_nf.volume_id).unwrap();
            let mut nbd_nf = NbdClient::connect_unix(&sock_nf).await.unwrap();
            nbd_nf.go(&v_blk_nf.volume_id).await.unwrap();
            // Intentionally non-FUA write with NO flush before disconnect + NodeUnstageVolume!
            nbd_nf.write(0, b"NON-FUA-BUFFERED", false).await.unwrap();
            nbd_nf.disconnect().await.unwrap();
        }
        c1.node_unstage_volume(&NodeUnstageVolumeRequest {
            volume_id: v_blk_nf.volume_id.clone(),
            staging_target_path: stage_nf.to_string_lossy().into_owned(),
        })
        .await
        .unwrap();
        // Re-stage with same lease and verify the non-FUA buffered write persisted on unstage!
        c1.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_blk_nf.volume_id.clone(),
            publish_context: pub_nf1.publish_context.clone(),
            staging_target_path: stage_nf.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        {
            let sock_nf = node1.nbd_socket_for_volume(&v_blk_nf.volume_id).unwrap();
            let mut nbd_nf = NbdClient::connect_unix(&sock_nf).await.unwrap();
            nbd_nf.go(&v_blk_nf.volume_id).await.unwrap();
            assert_eq!(
                &nbd_nf.read(0, 16).await.unwrap(),
                b"NON-FUA-BUFFERED",
                "non-FUA buffered NBD write must flush cleanly on NodeUnstageVolume"
            );
            nbd_nf.disconnect().await.unwrap();
        }

        // Now expire lease and re-publish on node-1 with newer `fence_epoch` (2), then re-stage
        // directly over the existing staged entry (P1-6): the new NBD socket must stay live!
        clock_secs.fetch_add(10, Ordering::SeqCst);
        let pub_nf2 = c1
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: v_blk_nf.volume_id.clone(),
                node_id: "node-1".into(),
                volume_capability: Some(blk_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(pub_nf2.publish_context["os.csi/fence_epoch"], "2");
        c1.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: v_blk_nf.volume_id.clone(),
            publish_context: pub_nf2.publish_context.clone(),
            staging_target_path: stage_nf.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        {
            let sock_nf2 = node1.nbd_socket_for_volume(&v_blk_nf.volume_id).unwrap();
            assert!(
                sock_nf2.exists(),
                "re-staged NBD socket must not be unlinked by old stage teardown"
            );
            let mut nbd_nf2 = NbdClient::connect_unix(&sock_nf2).await.unwrap();
            nbd_nf2.go(&v_blk_nf.volume_id).await.unwrap();
            assert_eq!(&nbd_nf2.read(0, 16).await.unwrap(), b"NON-FUA-BUFFERED");
            nbd_nf2.write(512, b"RESTAGE-EPOCH-2!", true).await.unwrap();
            assert_eq!(&nbd_nf2.read(512, 16).await.unwrap(), b"RESTAGE-EPOCH-2!");
            nbd_nf2.disconnect().await.unwrap();
        }

        // ListVolumes + ListSnapshots over gRPC-h2c
        let vols = c1
            .list_volumes(&ListVolumesRequest::default())
            .await
            .unwrap();
        assert!(vols.entries.len() >= 5);
        let snaps = c1
            .list_snapshots(&ListSnapshotsRequest::default())
            .await
            .unwrap();
        assert_eq!(snaps.entries.len(), 2);

        srv1.shutdown().await;
        srv2.shutdown().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}
