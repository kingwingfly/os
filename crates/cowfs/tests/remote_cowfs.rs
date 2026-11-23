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
