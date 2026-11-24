//! RV-03/04/07/09. These mount the production CowFs and HTTP-backed stores with a
//! deterministic transport clock and a peer that can lose the acknowledgement after publication.
#[path = "support/remote_transport.rs"]
mod remote_transport;
use abi::{
    Errno,
    contract::cowfs_ioctl as ioctl,
    volume::{CowfsFsckResp, CowfsInfoResp},
};
use cowtree::{PackBuilder, WriterMode};
use os_cowfs::{CowFsOpenMode, PackStore, cowfs_ioctl_mounted};
use remote_transport::{Mount, Peer};
use std::rc::Rc;
use vfs::{Cred, Filesystem, OpenOptions, WriteAt, now_or_never};

async fn contents(fs: &Mount, name: &str, len: usize) -> Vec<u8> {
    let cred = Cred::root();
    let h = fs.lookup(&cred, &fs.root(), name).await.unwrap().handle;
    let fd = fs
        .open(&cred, &h, OpenOptions::new().read(true))
        .await
        .unwrap();
    let mut out = vec![0; len];
    let mut offset = 0;
    while offset < len {
        let n = fs
            .read_at(&fd, &mut out[offset..], offset as u64)
            .await
            .unwrap();
        assert!(n > 0);
        offset += n;
    }
    fs.release(&fd).await.unwrap();
    out
}
#[test]
fn epoch_conflict_preserves_dirty_data_and_allows_retry() {
    now_or_never(async {
        let peer = Rc::new(Peer::default());
        let fs = peer
            .mount(
                "retry",
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                true,
            )
            .await;
        let cred = Cred::root();
        fs.mkdir(&cred, &fs.root(), "retained", 0o755)
            .await
            .unwrap();
        peer.retry_epoch.set(true);
        assert_eq!(fs.sync_fs(&cred).await, Err(Errno::EAGAIN));
        fs.sync_fs(&cred).await.unwrap();
        let reader = peer.mount("retry", CowFsOpenMode::ReadOnly, false).await;
        reader
            .lookup(&cred, &reader.root(), "retained")
            .await
            .unwrap();
        reader.close_clean().await.unwrap();
        fs.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn delta_commit_lost_reply_pinned_reader_and_snapshot_fork() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let root = Cred::root();
        let fs = p
            .mount(
                "work",
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                true,
            )
            .await;
        let mut bytes = (0..2 * 1024 * 1024usize)
            .map(|i| ((i / 65536) ^ (i % 251)) as u8)
            .collect::<Vec<_>>();
        let opts = *OpenOptions::new().read(true).write(true).create_new(true);
        let (_, fd) = fs
            .create(&root, &fs.root(), "big", 0o644, &opts)
            .await
            .unwrap();
        fs.write_at(&fd, &bytes, WriteAt::Offset(0)).await.unwrap();
        fs.sync_all(&fd).await.unwrap();
        assert_eq!(fs.current_head().epoch, 1);
        let ro = p.mount("work", CowFsOpenMode::ReadOnly, false).await;
        ro.renew_ro_pin().await.unwrap();
        cowfs_ioctl_mounted(
            &fs,
            &root,
            ioctl::COWFS_IOC_SNAPSHOT,
            br#"{"name":"first"}"#,
        )
        .await
        .unwrap();
        let root_before = fs.current_head().root;
        p.packs.reset_counters();
        p.lost.set(true);
        fs.write_at(&fd, &[77; 128], WriteAt::Offset(66666))
            .await
            .unwrap();
        fs.sync_data(&fd).await.unwrap();
        assert_eq!(p.queries.get(), 1);
        assert_eq!(fs.current_head().epoch, 2);
        assert_eq!(p.packs.pack_writes(), 1);
        assert!(p.packs.bytes_written() < 128 * 1024);
        assert_eq!(contents(&ro, "big", bytes.len()).await, bytes);
        bytes[66666..66794].fill(77);
        ro.refresh_ro().await.unwrap();
        assert_eq!(contents(&ro, "big", bytes.len()).await, bytes);
        let cold = p.mount("work", CowFsOpenMode::ReadOnly, false).await;
        assert_eq!(contents(&cold, "big", bytes.len()).await, bytes);
        let (_, cloned) = fs
            .create(&root, &fs.root(), "clone", 0o644, &opts)
            .await
            .unwrap();
        fs.reflink(&root, &fd, &cloned).await.unwrap();
        fs.sync_all(&cloned).await.unwrap();
        assert_eq!(p.packs.pack_writes(), 1);
        let source = fs.clone_source(&fd).await.unwrap();
        fs.reflink_range(
            &source,
            &cloned,
            abi::volume::FileCloneRangeReq {
                src_fd: 0,
                src_offset: 65002,
                src_length: 131072,
                dest_offset: 17,
            },
        )
        .await
        .unwrap();
        let cloned_bytes = contents(&fs, "clone", bytes.len()).await;
        assert_eq!(&cloned_bytes[17..131089], &bytes[65002..196074]);
        drop(source);
        let writes_before_fork = p.packs.pack_writes();
        cowfs_ioctl_mounted(
            &fs,
            &root,
            ioctl::COWFS_IOC_FORK,
            br#"{"snapshot":"first","new_volume":"fork"}"#,
        )
        .await
        .unwrap();
        let fork = p.mount("fork", CowFsOpenMode::ReadOnly, false).await;
        assert_eq!(fork.current_head().root, root_before);
        assert_eq!(p.packs.pack_writes(), writes_before_fork);
        let report: CowfsFsckResp = serde_json::from_slice(
            &cowfs_ioctl_mounted(&fs, &root, ioctl::COWFS_IOC_FSCK, b"{}")
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(report.ok, "{report:?}");
        let info: CowfsInfoResp = serde_json::from_slice(
            &cowfs_ioctl_mounted(&fs, &root, ioctl::COWFS_IOC_INFO, b"")
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(info.writer_model, abi::contract::WriterModel::Fenced);
        fs.release(&fd).await.unwrap();
        fs.release(&cloned).await.unwrap();
        for view in [fork, cold, ro, fs] {
            view.close_clean().await.unwrap();
        }
    })
    .unwrap();
}
#[test]
fn self_fence_is_relative_to_renewal_send_and_prevents_every_put() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = p
            .mount(
                "clock",
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                true,
            )
            .await;
        p.time.set(20);
        fs.renew_lease().await.unwrap();
        let mut builder = PackBuilder::new();
        let bytes = vec![42u8; 65536];
        builder.push(cowtree::sha256(&bytes), &bytes).unwrap();
        let pack = builder.finish().unwrap().pop().unwrap();
        p.time.set(69);
        fs.pack_store_rc()
            .write_pack(&pack.pack_id, &pack.bytes)
            .await
            .unwrap();
        p.time.set(70);
        assert_eq!(
            fs.pack_store_rc()
                .write_pack(&pack.pack_id, &pack.bytes)
                .await,
            Err(Errno::ESTALE)
        );
        assert_eq!(fs.sync_fs(&Cred::root()).await, Err(Errno::ESTALE));
        assert_eq!(
            fs.mkdir(&Cred::root(), &fs.root(), "stale", 0o700)
                .await
                .err(),
            Some(Errno::ESTALE)
        );
        assert_eq!(p.puts.get(), 1);
    })
    .unwrap();
}

async fn writer(p: &Rc<Peer>, volume: &str) -> Rc<Mount> {
    p.mount(
        volume,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        true,
    )
    .await
}

#[test]
fn a_slow_pack_upload_allows_multiple_renewals() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "slow").await;
        let cred = Cred::root();
        let opts = *OpenOptions::new().read(true).write(true).create_new(true);
        let (_, fd) = fs
            .create(&cred, &fs.root(), "file", 0o644, &opts)
            .await
            .unwrap();
        fs.write_at(&fd, &[42; 65536], WriteAt::Offset(0))
            .await
            .unwrap();
        p.hold_upload.set(true);
        let mut sync = fs.sync_all(&fd);
        assert!(now_or_never(&mut sync).is_none());
        for t in [20, 40, 60, 80] {
            p.time.set(t);
            fs.renew_lease().await.unwrap();
        }
        p.hold_upload.set(false);
        sync.await.unwrap();
        assert_eq!(fs.current_head().epoch, 1);
        fs.release(&fd).await.unwrap();
        fs.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn uncertain_receipt_reconciles_after_takeover_and_aborted_eio_restages() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "receipts").await;
        let cred = Cred::root();
        fs.mkdir(&cred, &fs.root(), "dirty", 0o755).await.unwrap();
        p.abort_io.set(true);
        assert_eq!(fs.sync_fs(&cred).await, Err(Errno::EIO));
        fs.sync_fs(&cred).await.unwrap();
        fs.mkdir(&cred, &fs.root(), "also-dirty", 0o755)
            .await
            .unwrap();
        p.lost.set(true);
        p.status_offline.set(true);
        assert_eq!(fs.sync_fs(&cred).await, Err(Errno::EIO));
        assert_eq!(fs.current_head().epoch, 1);
        let successor = p
            .mount(
                "receipts",
                CowFsOpenMode::ReadWrite(WriterMode::ForceTakeover),
                false,
            )
            .await;
        assert_eq!(fs.renew_lease().await, Err(Errno::ESTALE));
        assert!(!fs.lease_status().held);
        p.status_offline.set(false);
        fs.sync_fs(&cred).await.unwrap();
        assert_eq!(fs.current_head().root, successor.current_head().root);
        assert_eq!(fs.current_head().epoch, 2);
        fs.close_clean().await.unwrap();
        successor.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn pending_commit_stays_uncertain_until_authority_confirms_expiry() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "pending").await;
        let cred = Cred::root();
        fs.mkdir(&cred, &fs.root(), "retained", 0o755)
            .await
            .unwrap();
        p.drop_before_publish.set(true);
        assert_eq!(fs.sync_fs(&cred).await, Err(Errno::EIO));
        p.time.set(51);
        assert_eq!(fs.sync_fs(&cred).await, Err(Errno::EIO));
        p.time.set(61);
        assert_eq!(fs.sync_fs(&cred).await, Err(Errno::ESTALE));
        fs.fork_volume(None, cowtree::VolumeId("rescued".into()), false)
            .await
            .unwrap();
        let ro = p.mount("rescued", CowFsOpenMode::ReadOnly, false).await;
        ro.lookup(&cred, &ro.root(), "retained").await.unwrap();
        ro.close_clean().await.unwrap();
        fs.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn metadata_larger_than_control_body_stages_in_bounded_requests() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "metadata").await;
        let cred = Cred::root();
        let root = fs.root();
        let data = vec![211; 2048];
        for i in 0..1100 {
            let dir = fs
                .mkdir(&cred, &root, &format!("dir{i:04}"), 0o755)
                .await
                .unwrap();
            fs.setxattr(
                &cred,
                &dir.handle,
                "user.data",
                &data,
                abi::fs::XattrFlags::CREATE,
            )
            .await
            .unwrap();
        }
        fs.sync_fs(&cred).await.unwrap();
        assert!(p.staged_bytes.get() > abi::remote_volume::CONTROL_BODY_MAX);
        assert!(p.stage_batches.get() > 4);
        let ro = p.mount("metadata", CowFsOpenMode::ReadOnly, false).await;
        let dir = ro.lookup(&cred, &ro.root(), "dir1099").await.unwrap();
        assert_eq!(
            ro.getxattr(&cred, &dir.handle, "user.data").await.unwrap(),
            data
        );
        ro.close_clean().await.unwrap();
        fs.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn fenced_dirty_overlay_can_be_rescued_on_a_fork() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "source").await;
        let cred = Cred::root();
        let opts = *OpenOptions::new().read(true).write(true).create_new(true);
        let (_, fd) = fs
            .create(&cred, &fs.root(), "rescue", 0o644, &opts)
            .await
            .unwrap();
        let bytes = vec![198; 65536];
        fs.write_at(&fd, &bytes, WriteAt::Offset(0)).await.unwrap();
        let successor = p
            .mount(
                "source",
                CowFsOpenMode::ReadWrite(WriterMode::ForceTakeover),
                false,
            )
            .await;
        assert_eq!(fs.renew_lease().await, Err(Errno::ESTALE));
        assert_eq!(fs.close_clean().await, Err(Errno::ESTALE));
        fs.fork_volume(None, cowtree::VolumeId("recovered".into()), false)
            .await
            .unwrap();
        let view = p.mount("recovered", CowFsOpenMode::ReadOnly, false).await;
        assert_eq!(contents(&view, "rescue", bytes.len()).await, bytes);
        assert!(
            successor
                .lookup(&cred, &successor.root(), "rescue")
                .await
                .is_err()
        );
        view.close_clean().await.unwrap();
        fs.close_clean().await.unwrap();
        successor.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn receive_uses_isolated_writer_for_new_and_existing_destinations() {
    use os_cowfs::{CowFsVolumeDevice, SliceSource, VecSink};
    use vfs::vblk::VolumeDevice;
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "source").await;
        let existing = writer(&p, "existing").await;
        existing.close_clean().await.unwrap();
        let cred = Cred::root();
        fs.mkdir(&cred, &fs.root(), "export", 0o755).await.unwrap();
        fs.sync_fs(&cred).await.unwrap();
        let source = fs.current_head();
        let dev = CowFsVolumeDevice::from_mounted(fs.clone());
        let mut stream = VecSink::default();
        os_cowfs::send_snapshot(
            &*fs.head_store_rc(),
            &*fs.pack_store_rc(),
            &source.volume,
            None,
            "@",
            None,
            false,
            &mut stream,
        )
        .await
        .unwrap();
        for volume in ["new", "existing"] {
            let request = abi::volume::CowfsReceiveReq {
                target_volume: Some(volume.into()),
                snapshot_name: Some("imported".into()),
                stream_fd: 0,
            };
            let mut input = SliceSource::new(&stream.0);
            let mut importing = dev.cowfs_receive(&request, &mut input);
            p.hold_nodes.set(true);
            assert!(now_or_never(&mut importing).is_none());
            for _ in 0..4 {
                p.tick(20).await;
                fs.renew_lease().await.unwrap();
            }
            p.hold_nodes.set(false);
            importing.await.unwrap();
            let view = p
                .mount(volume, CowFsOpenMode::Snapshot("imported".into()), false)
                .await;
            view.lookup(&cred, &view.root(), "export").await.unwrap();
            view.close_clean().await.unwrap();
            fs.renew_lease().await.unwrap();
            assert_eq!(fs.current_head().fence, source.fence);
            fs.mkdir(&cred, &fs.root(), volume, 0o755).await.unwrap();
            fs.sync_fs(&cred).await.unwrap();
        }
        fs.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn durable_close_preserves_dirty_mount_for_retry() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "shutdown").await;
        let cred = Cred::root();
        fs.mkdir(&cred, &fs.root(), "persist", 0o755).await.unwrap();
        p.abort_io.set(true);
        assert_eq!(fs.close_clean().await, Err(Errno::EIO));
        assert!(!fs.is_closed());
        fs.renew_lease().await.unwrap();
        fs.close_clean().await.unwrap();
        assert!(fs.is_closed());
        let next = p
            .mount(
                "shutdown",
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                false,
            )
            .await;
        next.lookup(&cred, &next.root(), "persist").await.unwrap();
        next.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn incremental_send_and_fsck_keep_deleted_snapshots_alive_through_gc() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "pinning").await;
        let cred = Cred::root();
        let root = fs.root();
        let opts = *OpenOptions::new().read(true).write(true).create_new(true);
        let (_, fd) = fs.create(&cred, &root, "file", 0o644, &opts).await.unwrap();
        fs.write_at(&fd, &[1; 65536], WriteAt::Offset(0))
            .await
            .unwrap();
        let parent = fs.create_snapshot("parent").await.unwrap();
        fs.write_at(&fd, &[2; 65536], WriteAt::Offset(0))
            .await
            .unwrap();
        let target = fs.create_snapshot("target").await.unwrap();
        fs.write_at(&fd, &[3; 65536], WriteAt::Offset(0))
            .await
            .unwrap();
        fs.sync_all(&fd).await.unwrap();
        fs.release(&fd).await.unwrap();

        let heads = fs.head_store_rc();
        let packs = fs.pack_store_rc();
        let volume = fs.volume_id();
        let mut stream = os_cowfs::VecSink::default();
        let mut send = Box::pin(os_cowfs::send_snapshot(
            &*heads,
            &*packs,
            volume,
            None,
            "target",
            Some("parent"),
            false,
            &mut stream,
        ));
        let mut check = Box::pin(cowfs_ioctl_mounted(
            &fs,
            &cred,
            ioctl::COWFS_IOC_FSCK,
            br#"{"snapshot":"target"}"#,
        ));
        p.hold_nodes.set(true);
        assert!(now_or_never(&mut send).is_none());
        assert!(now_or_never(&mut check).is_none());
        assert_eq!(p.pin_count(), 3);
        fs.delete_snapshot("parent").await.unwrap();
        fs.delete_snapshot("target").await.unwrap();
        for _ in 0..8 {
            p.tick(20).await;
            fs.renew_lease().await.unwrap();
        }
        assert_eq!(p.pin_count(), 3);
        os_cowfs::collect_garbage(
            &p.heads,
            &p.packs,
            vfs::Timespec {
                sec: 10000,
                nsec: 0,
            },
        )
        .await
        .unwrap();
        p.hold_nodes.set(false);
        let sent = send.await.unwrap();
        assert_eq!(sent.parent_root, Some(cowtree::digest_to_hex(&parent.root)));
        assert_eq!(sent.root, cowtree::digest_to_hex(&target.root));
        assert!(sent.blocks_sent > 0);
        let checked: CowfsFsckResp = serde_json::from_slice(&check.await.unwrap()).unwrap();
        assert!(checked.ok && checked.packs_verified > 0);
        assert_eq!(checked.root, sent.root);
        assert_eq!(p.pin_count(), 0);
        fs.close_clean().await.unwrap();
    })
    .unwrap();
}

#[test]
fn expired_reader_repins_only_its_original_root() {
    now_or_never(async {
        let p = Rc::new(Peer::default());
        let fs = writer(&p, "reader").await;
        let ro = p.mount("reader", CowFsOpenMode::ReadOnly, false).await;
        let cred = Cred::root();
        use vfs::vblk::VolumeDevice;
        let device = os_cowfs::CowFsVolumeDevice::from_mounted(ro.clone());
        assert!(device.blk_lease().await.unwrap().held);
        p.tick(121).await;
        let expired = device.blk_lease().await.unwrap();
        assert!(!expired.held && expired.expired);
        assert_eq!(expired.lease_expires_at, Some(120));
        ro.renew_ro_pin().await.unwrap();
        assert!(device.blk_lease().await.unwrap().held);
        assert_eq!(p.pin_count(), 1);
        let next = p
            .mount(
                "reader",
                CowFsOpenMode::ReadWrite(WriterMode::ForceTakeover),
                false,
            )
            .await;
        next.mkdir(&cred, &next.root(), "new", 0o755).await.unwrap();
        next.sync_fs(&cred).await.unwrap();
        next.close_clean().await.unwrap();
        p.tick(121).await;
        assert_eq!(ro.renew_ro_pin().await, Err(Errno::ESTALE));
        let lost = device.blk_lease().await.unwrap();
        assert!(!lost.held && lost.fenced && lost.expired);
        assert_eq!(
            ro.lookup(&cred, &ro.root(), "new").await.err(),
            Some(Errno::ESTALE)
        );
        ro.close_clean().await.unwrap();
        fs.close_clean().await.unwrap();
    })
    .unwrap();
}
