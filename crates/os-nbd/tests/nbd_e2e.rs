use abi::fs::Timespec;
use cowtree::{VolumeId, WriterMode};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::raw_lba::{RawBlockConfig, RawBlockOpenMode, RawBlockVolume};
use os_nbd::{
    MAX_NBD_IO_BYTES, NBD_CMD_WRITE, NBD_EIO, NBD_EOVERFLOW, NBD_EPERM, NBD_FLAG_READ_ONLY,
    NBD_OPT_LIST, NBD_REP_ERR_INVALID, NbdClient, NbdClientError, NbdExportConfig, NbdServerHandle,
    serve_unix_on_local_set,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_test_dir(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let base = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .filter(|p| p.as_os_str().len() <= 60)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let dir = base.join(format!(
        "os-nbd-{tag}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixed_clock() -> os_cowfs::CowFsClock {
    Rc::new(|| Timespec {
        sec: 1_700_000_000,
        nsec: 0,
    })
}

#[test]
fn nbd_full_ops_ro_rejection_oversize_and_competing_writer_fencing() {
    let dir = unique_test_dir("full");
    let store_dir = dir.join("store");
    std::fs::create_dir_all(&store_dir).unwrap();
    let sock_rw = dir.join("vol-rw.sock");
    let sock_ro = dir.join("vol-ro.sock");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let hs = Rc::new(NativeSqliteHeadStore::open(&store_dir).unwrap());
        let ps = Rc::new(NativePackStore::open(&store_dir).unwrap());
        let vol_id = VolumeId("nbd-vol-1".into());
        RawBlockVolume::format(
            &*hs,
            &*ps,
            vol_id.clone(),
            64 * 1024,
            4096,
            0,
            (fixed_clock())(),
        )
        .await
        .unwrap();

        let vol_rw = Rc::new(
            RawBlockVolume::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                vol_id.clone(),
                RawBlockOpenMode::ReadWrite(WriterMode::Exclusive),
                RawBlockConfig::remote_fenced(fixed_clock()),
            )
            .await
            .unwrap(),
        );
        let mut srv = serve_unix_on_local_set(
            sock_rw.clone(),
            NbdExportConfig::new("data0"),
            Rc::clone(&vol_rw),
        )
        .unwrap();

        // Socket permissions strictly 0600.
        let mode = std::fs::metadata(&sock_rw).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // LIST + INFO + ABORT client.
        let mut c0 = NbdClient::connect_unix(&sock_rw).await.unwrap();
        assert_eq!(c0.list_exports().await.unwrap(), vec!["data0".to_string()]);
        let info = c0.info("data0").await.unwrap();
        assert_eq!(info.size_bytes, 64 * 1024);
        assert_eq!(info.min_block_size, Some(4096));
        assert_eq!(info.max_block_size, Some(MAX_NBD_IO_BYTES));
        assert_eq!(info.transmission_flags & NBD_FLAG_READ_ONLY, 0);
        c0.abort().await.unwrap();

        // GO + WRITE + FUA + READ + TRIM + WRITE_ZEROES + FLUSH + DISC.
        let mut c = NbdClient::connect_unix(&sock_rw).await.unwrap();
        let go_info = c.go("data0").await.unwrap();
        assert_eq!(go_info.size_bytes, 64 * 1024);

        // Unaligned write + FUA durable flush.
        c.write(100, b"hello-nbd-raw-volume!", true).await.unwrap();
        let got = c.read(96, 32).await.unwrap();
        assert_eq!(&got[..4], &[0u8; 4]);
        assert_eq!(&got[4..25], b"hello-nbd-raw-volume!");
        assert_eq!(&got[25..], &[0u8; 7]);

        // Multi-sector write (16 KiB) then interior TRIM + WRITE_ZEROES.
        let pattern = vec![0x5a; 16 * 1024];
        c.write(4096, &pattern, false).await.unwrap();
        c.flush().await.unwrap();
        c.trim(8192, 4096, true).await.unwrap();
        assert_eq!(c.read(4096, 4096).await.unwrap(), vec![0x5a; 4096]);
        assert_eq!(c.read(8192, 4096).await.unwrap(), vec![0u8; 4096]);
        assert_eq!(c.read(12288, 4096).await.unwrap(), vec![0x5a; 4096]);

        c.write_zeroes(4100, 16, true).await.unwrap();
        let zcheck = c.read(4096, 24).await.unwrap();
        assert_eq!(&zcheck[..4], &[0x5a; 4]);
        assert_eq!(&zcheck[4..20], &[0u8; 16]);
        assert_eq!(&zcheck[20..24], &[0x5a; 4]);

        // Oversize READ (> 4 MiB) rejected with NBD_EOVERFLOW cleanly without dropping connection.
        assert!(matches!(
            c.read(0, MAX_NBD_IO_BYTES + 4096).await,
            Err(NbdClientError::ServerError(NBD_EOVERFLOW))
        ));

        // Oversize WRITE header rejected with NBD_EOVERFLOW.
        let mut c_big = NbdClient::connect_unix(&sock_rw).await.unwrap();
        c_big.go("data0").await.unwrap();
        let err_code = c_big
            .send_raw_header_and_read_reply(NBD_CMD_WRITE, 0, 0, MAX_NBD_IO_BYTES + 4096)
            .await
            .unwrap();
        assert_eq!(err_code, NBD_EOVERFLOW);

        // Oversize handshake option rejected with NBD_REP_ERR_INVALID.
        {
            let mut raw = tokio::net::UnixStream::connect(&sock_rw).await.unwrap();
            let _ = os_nbd::proto::read_newstyle_greeting(&mut raw)
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::write_all(
                &mut raw,
                &(os_nbd::NBD_FLAG_C_FIXED_NEWSTYLE | os_nbd::NBD_FLAG_C_NO_ZEROES).to_be_bytes(),
            )
            .await
            .unwrap();
            let mut hdr = [0u8; 16];
            hdr[0..8].copy_from_slice(&os_nbd::IHAVEOPT.to_be_bytes());
            hdr[8..12].copy_from_slice(&NBD_OPT_LIST.to_be_bytes());
            hdr[12..16].copy_from_slice(&(os_nbd::MAX_OPTION_LEN + 1).to_be_bytes());
            tokio::io::AsyncWriteExt::write_all(&mut raw, &hdr)
                .await
                .unwrap();
            let rep = os_nbd::proto::read_option_reply(&mut raw).await.unwrap();
            assert_eq!(rep.reply_type, NBD_REP_ERR_INVALID);
        }

        // Open competing RO NBD server on the same volume and verify RO writes/trim/zeroes -> NBD_EPERM.
        let vol_ro = Rc::new(
            RawBlockVolume::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                vol_id.clone(),
                RawBlockOpenMode::ReadOnly,
                RawBlockConfig::local_native(fixed_clock()),
            )
            .await
            .unwrap(),
        );
        let mut srv_ro = serve_unix_on_local_set(
            sock_ro.clone(),
            NbdExportConfig::new("ro0"),
            Rc::clone(&vol_ro),
        )
        .unwrap();
        let mut c_ro = NbdClient::connect_unix(&sock_ro).await.unwrap();
        let ro_info = c_ro.go("ro0").await.unwrap();
        assert_ne!(ro_info.transmission_flags & NBD_FLAG_READ_ONLY, 0);
        assert_eq!(&c_ro.read(100, 21).await.unwrap(), b"hello-nbd-raw-volume!");
        assert!(matches!(
            c_ro.write(0, b"nope", false).await,
            Err(NbdClientError::ServerError(NBD_EPERM))
        ));
        assert!(matches!(
            c_ro.trim(0, 4096, false).await,
            Err(NbdClientError::ServerError(NBD_EPERM))
        ));
        assert!(matches!(
            c_ro.write_zeroes(0, 4096, false).await,
            Err(NbdClientError::ServerError(NBD_EPERM))
        ));
        c_ro.disconnect().await.unwrap();
        srv_ro.shutdown().await.unwrap();
        assert!(!sock_ro.exists());

        // Competing native writer steals lease via ForceTakeover and commits a newer epoch!
        let hs2 = Rc::new(NativeSqliteHeadStore::open(&store_dir).unwrap());
        let ps2 = Rc::new(NativePackStore::open(&store_dir).unwrap());
        let winner = RawBlockVolume::open(
            Rc::clone(&hs2),
            Rc::clone(&ps2),
            vol_id.clone(),
            RawBlockOpenMode::ReadWrite(WriterMode::ForceTakeover),
            RawBlockConfig::remote_fenced(fixed_clock()),
        )
        .await
        .unwrap();
        winner.write_at(0, b"WINNER-DATA").await.unwrap();
        winner.flush().await.unwrap();
        winner.close_clean().await.unwrap();

        // Stale NBD server MUST fail closed on FUA write / FLUSH with NBD_EIO and set sticky fence!
        let stale_res = c.write(0, b"STALE-WRITE", true).await;
        assert!(
            matches!(stale_res, Err(NbdClientError::ServerError(NBD_EIO))),
            "expected NBD_EIO on stale fenced FUA write, got {stale_res:?}"
        );
        assert!(srv.is_fenced());
        // All subsequent writes/flushes also fail closed (sticky fence).
        assert!(matches!(
            c.write(0, b"STALE-AGAIN", false).await,
            Err(NbdClientError::ServerError(NBD_EIO))
        ));
        assert!(matches!(
            c.flush().await,
            Err(NbdClientError::ServerError(NBD_EIO))
        ));

        c.disconnect().await.unwrap();
        // P0-5: Shutting down a fenced NBD server with dirty buffered writes MUST propagate ESTALE
        // while still cleanly unlinking the Unix socket!
        assert_eq!(srv.shutdown().await, Err(abi::Errno::ESTALE));
        assert!(!sock_rw.exists());

        // Verify winner's bytes are completely uncorrupted!
        let verify = RawBlockVolume::open(
            Rc::clone(&hs2),
            Rc::clone(&ps2),
            vol_id.clone(),
            RawBlockOpenMode::ReadOnly,
            RawBlockConfig::local_native(fixed_clock()),
        )
        .await
        .unwrap();
        let mut check = [0u8; 11];
        verify.read_at(0, &mut check).await.unwrap();
        assert_eq!(&check, b"WINNER-DATA");
        verify.close_clean().await.unwrap();
    });

    // Also test dedicated-thread `NbdServerHandle::start_unix_native` + drop cleanup.
    let sock_native = dir.join("native.sock");
    let handle = NbdServerHandle::start_unix_native(
        sock_native.clone(),
        store_dir.clone(),
        VolumeId("nbd-vol-1".into()),
        NbdExportConfig::new("native0"),
        RawBlockOpenMode::ReadOnly,
        None,
    )
    .unwrap();
    rt.block_on(async {
        let mut c = NbdClient::connect_unix(&sock_native).await.unwrap();
        c.go("native0").await.unwrap();
        assert_eq!(&c.read(0, 11).await.unwrap(), b"WINNER-DATA");
        c.disconnect().await.unwrap();
    });
    drop(handle);
    assert!(!sock_native.exists());

    let _ = std::fs::remove_dir_all(&dir);
}
