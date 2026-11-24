//! Conformance tests for OCI-06 (bounded streaming tar/tar+gzip importer & security boundaries)
//! and OCI-07 (reproducible tar/tar+gzip exporter & lossless round-trip) (`contract.md` §2.15; #81).

use abi::Errno;
use abi::fs::{OpenOptions, Timespec, WriteAt};
use cowtree::WriterMode;
use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
use flate2::read::MultiGzDecoder;
use flate2::{Compression, GzBuilder};
use os_cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, OciTarExportOptions, OciTarImportOptions, OciTarLayerInput,
    SetuidPolicy, SymlinkPolicy, VolumeId, build_oci_image_config, build_oci_image_manifest,
    digest_to_hex, export_cowfs_oci_tar_layer, import_oci_tar_layers, sha256, verify_volume_strict,
};
use std::io::{Cursor, Read, Write};
use std::rc::Rc;
use vfs::{Cred, Filesystem, now_or_never};

fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    now_or_never(f).expect("sync future")
}

fn test_clock() -> os_cowfs::CowFsClock {
    Rc::new(|| Timespec {
        sec: 1_700_000_000,
        nsec: 0,
    })
}

fn root_cred() -> Cred {
    let mut c = Cred::root();
    c.umask = 0;
    c
}

fn build_tar_gz(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> (Vec<u8>, String) {
    let mut builder = tar::Builder::new(Vec::new());
    build(&mut builder);
    let raw_tar = builder.into_inner().unwrap();
    let diff_id = format!("sha256:{}", digest_to_hex(&sha256(&raw_tar)));
    let mut gz = GzBuilder::new()
        .mtime(0)
        .operating_system(3)
        .write(Vec::new(), Compression::default());
    gz.write_all(&raw_tar).unwrap();
    (gz.finish().unwrap(), diff_id)
}

fn append_dir(b: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32) {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Directory);
    h.set_size(0);
    h.set_mode(mode);
    h.set_cksum();
    b.append_data(&mut h, path, Cursor::new(&[][..])).unwrap();
}

fn append_file(b: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32, data: &[u8]) {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_size(data.len() as u64);
    h.set_mode(mode);
    h.set_cksum();
    b.append_data(&mut h, path, Cursor::new(data)).unwrap();
}

fn append_raw_path_file(b: &mut tar::Builder<Vec<u8>>, raw_path: &[u8], mode: u32, data: &[u8]) {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_size(data.len() as u64);
    h.set_mode(mode);
    let bytes = h.as_mut_bytes();
    bytes[..raw_path.len()].copy_from_slice(raw_path);
    h.set_cksum();
    b.append(&h, Cursor::new(data)).unwrap();
}

fn append_hardlink(b: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Link);
    h.set_size(0);
    h.set_mode(0o644);
    h.set_cksum();
    b.append_link(&mut h, path, target).unwrap();
}

fn append_symlink(b: &mut tar::Builder<Vec<u8>>, path: &str, target: &str) {
    let mut h = tar::Header::new_gnu();
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_size(0);
    h.set_mode(0o777);
    let raw_name = path.as_bytes();
    let raw_link = target.as_bytes();
    let hdr = h.as_mut_bytes();
    hdr[..raw_name.len()].copy_from_slice(raw_name);
    hdr[157..157 + raw_link.len()].copy_from_slice(raw_link);
    h.set_cksum();
    b.append(&h, Cursor::new(&[][..])).unwrap();
}

async fn read_file_by_path(
    fs: &CowFs<MemoryHeadStore, MemoryPackStore>,
    path: &str,
) -> vfs::Result<Vec<u8>> {
    let cred = root_cred();
    let mut cur = fs.root();
    for comp in path
        .trim_start_matches('/')
        .split('/')
        .filter(|c| !c.is_empty())
    {
        cur = fs.lookup(&cred, &cur, comp).await?.handle;
    }
    let meta = fs.metadata(&cred, &cur).await?;
    let mut ro = OpenOptions::new();
    ro.read(true);
    let open = fs.open(&cred, &cur, &ro).await?;
    let mut buf = vec![0u8; meta.size as usize];
    let mut off = 0usize;
    while off < buf.len() {
        let n = fs.read_at(&open, &mut buf[off..], off as u64).await?;
        if n == 0 {
            break;
        }
        off += n;
    }
    fs.release(&open).await?;
    buf.truncate(off);
    Ok(buf)
}

async fn lookup_meta_by_path(
    fs: &CowFs<MemoryHeadStore, MemoryPackStore>,
    path: &str,
) -> vfs::Result<abi::fs::Entry> {
    let cred = root_cred();
    let mut cur = fs.root();
    let mut last = None;
    for comp in path
        .trim_start_matches('/')
        .split('/')
        .filter(|c| !c.is_empty())
    {
        let e = fs.lookup(&cred, &cur, comp).await?;
        cur = e.handle.clone();
        last = Some(e);
    }
    last.ok_or(Errno::ENOENT)
}

#[test]
fn oci_06_multi_layer_overlay_whiteouts_opaque_both_orderings_hardlinks_and_symlinks() {
    run(async {
        // Layer 1: base files, directories, opaque dirs, hard link, confined relative symlink.
        let (layer1, diff1) = build_tar_gz(|b| {
            append_dir(b, "etc", 0o755);
            append_file(b, "etc/app.conf", 0o644, b"v1");
            append_file(b, "etc/remove-me", 0o644, b"gone-soon");
            append_symlink(b, "etc/current", "app.conf");

            append_dir(b, "opt/victim", 0o755);
            append_file(b, "opt/victim/nested.txt", 0o644, b"nested");

            // Opaque dir A: .wh..wh..opq will appear BEFORE new file in layer 2.
            append_dir(b, "opt/opq_before", 0o755);
            append_file(b, "opt/opq_before/old.txt", 0o644, b"old-a");

            // Opaque dir B: new file will appear BEFORE .wh..wh..opq in layer 2.
            append_dir(b, "opt/opq_after", 0o755);
            append_file(b, "opt/opq_after/old.txt", 0o644, b"old-b");

            append_dir(b, "bin", 0o755);
            append_file(b, "bin/hello", 0o755, b"#!/bin/sh\necho hi\n");
            append_hardlink(b, "bin/hello-link", "bin/hello");
        });

        // Layer 2: overwrite, file whiteout, recursive dir whiteout, opaque dirs in BOTH orderings.
        let (layer2, diff2) = build_tar_gz(|b| {
            append_file(b, "etc/app.conf", 0o640, b"v2-updated");
            append_file(b, "etc/.wh.remove-me", 0o644, b"");
            append_file(b, "opt/.wh.victim", 0o644, b"");

            // Ordering A: marker BEFORE new entry.
            append_file(b, "opt/opq_before/.wh..wh..opq", 0o644, b"");
            append_file(b, "opt/opq_before/new.txt", 0o644, b"fresh-a");

            // Ordering B: new entry BEFORE marker.
            append_file(b, "opt/opq_after/new.txt", 0o644, b"fresh-b");
            append_file(b, "opt/opq_after/.wh..wh..opq", 0o644, b"");
        });

        let head = Rc::new(MemoryHeadStore::new());
        let packs = Rc::new(MemoryPackStore::new());
        let vol = VolumeId("oci-06-overlay".into());
        let cfg = CowFsConfig::local_native(test_clock());

        let report = import_oci_tar_layers(
            Rc::clone(&head),
            Rc::clone(&packs),
            vol.clone(),
            &[
                OciTarLayerInput {
                    bytes: &layer1,
                    expected_diff_id: Some(&diff1),
                },
                OciTarLayerInput {
                    bytes: &layer2,
                    expected_diff_id: Some(&diff2),
                },
            ],
            &OciTarImportOptions::default(),
            Some("v2"),
            cfg.clone(),
        )
        .await
        .expect("overlay import succeeds");

        assert_eq!(report.diff_ids, vec![diff1, diff2]);
        assert_eq!(report.snapshot.as_deref(), Some("v2"));

        let fs = CowFs::open(
            Rc::clone(&head),
            Rc::clone(&packs),
            vol,
            CowFsOpenMode::ReadOnly,
            cfg,
        )
        .await
        .unwrap();
        let cred = root_cred();

        assert_eq!(
            read_file_by_path(&fs, "/etc/app.conf").await.unwrap(),
            b"v2-updated"
        );
        assert_eq!(
            lookup_meta_by_path(&fs, "/etc/app.conf")
                .await
                .unwrap()
                .metadata
                .mode
                & 0o777,
            0o640
        );
        // Whiteouts deleted targets and NEVER created `.wh.*` entries.
        assert_eq!(
            lookup_meta_by_path(&fs, "/etc/remove-me")
                .await
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            lookup_meta_by_path(&fs, "/etc/.wh.remove-me")
                .await
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            lookup_meta_by_path(&fs, "/opt/victim").await.unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            lookup_meta_by_path(&fs, "/opt/.wh.victim")
                .await
                .unwrap_err(),
            Errno::ENOENT
        );

        // Both opaque dir orderings removed lower-layer files and kept current-layer files!
        assert_eq!(
            lookup_meta_by_path(&fs, "/opt/opq_before/old.txt")
                .await
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            lookup_meta_by_path(&fs, "/opt/opq_before/.wh..wh..opq")
                .await
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            read_file_by_path(&fs, "/opt/opq_before/new.txt")
                .await
                .unwrap(),
            b"fresh-a"
        );

        assert_eq!(
            lookup_meta_by_path(&fs, "/opt/opq_after/old.txt")
                .await
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            lookup_meta_by_path(&fs, "/opt/opq_after/.wh..wh..opq")
                .await
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            read_file_by_path(&fs, "/opt/opq_after/new.txt")
                .await
                .unwrap(),
            b"fresh-b"
        );

        // Hard link shares inode and has nlink == 2.
        let orig = lookup_meta_by_path(&fs, "/bin/hello").await.unwrap();
        let link = lookup_meta_by_path(&fs, "/bin/hello-link").await.unwrap();
        assert_eq!(orig.handle.node.ino, link.handle.node.ino);
        assert_eq!(orig.metadata.nlink, 2);
        assert_eq!(
            read_file_by_path(&fs, "/bin/hello-link").await.unwrap(),
            b"#!/bin/sh\necho hi\n"
        );

        // Confined relative symlink preserved.
        let sym = lookup_meta_by_path(&fs, "/etc/current").await.unwrap();
        assert_eq!(fs.read_link(&cred, &sym.handle).await.unwrap(), "app.conf");
    });
}

#[test]
fn oci_06_rejects_escapes_symlinks_devices_setuid_bombs_caps_and_bad_diff_id() {
    run(async {
        let run_import = |layers: Vec<Vec<u8>>,
                          expected_diff: Option<String>,
                          opts: OciTarImportOptions| async move {
            let head = Rc::new(MemoryHeadStore::new());
            let packs = Rc::new(MemoryPackStore::new());
            let inputs: Vec<OciTarLayerInput<'_>> = layers
                .iter()
                .enumerate()
                .map(|(i, b)| OciTarLayerInput {
                    bytes: b.as_slice(),
                    expected_diff_id: if i == 0 {
                        expected_diff.as_deref()
                    } else {
                        None
                    },
                })
                .collect();
            import_oci_tar_layers(
                head,
                packs,
                VolumeId("sec-test".into()),
                &inputs,
                &opts,
                None,
                CowFsConfig::local_native(test_clock()),
            )
            .await
        };

        // 1. Path traversal with `..` component.
        let (dotdot, _) = build_tar_gz(|b| {
            append_raw_path_file(b, b"a/../../etc/passwd", 0o644, b"pwn");
        });
        assert!(matches!(
            run_import(vec![dotdot], None, OciTarImportOptions::default()).await,
            Err(Errno::EINVAL | Errno::EACCES)
        ));

        // 2. Multi-hop symlink escape (`a/l1 -> ..`, `a/l2 -> l1/../../etc/passwd`).
        let (multihop, _) = build_tar_gz(|b| {
            append_dir(b, "a", 0o755);
            append_symlink(b, "a/l1", "..");
            append_symlink(b, "a/l2", "l1/../../etc/passwd");
        });
        assert!(matches!(
            run_import(vec![multihop], None, OciTarImportOptions::default()).await,
            Err(Errno::EACCES | Errno::ELOOP)
        ));

        // 3. Symlink loop (`l1 -> l2`, `l2 -> l1`).
        let (symloop, _) = build_tar_gz(|b| {
            append_symlink(b, "l1", "l2");
            append_symlink(b, "l2", "l1");
        });
        assert_eq!(
            run_import(vec![symloop], None, OciTarImportOptions::default())
                .await
                .unwrap_err(),
            Errno::ELOOP
        );

        // 4. Symlink-parent overwrite attack across layers.
        let (sym_l1, _) = build_tar_gz(|b| {
            append_dir(b, "real", 0o755);
            append_symlink(b, "sub", "real");
        });
        let (sym_l2, _) = build_tar_gz(|b| {
            append_file(b, "sub/pwned", 0o644, b"escaped");
        });
        assert!(matches!(
            run_import(vec![sym_l1, sym_l2], None, OciTarImportOptions::default()).await,
            Err(Errno::ENOTDIR | Errno::EACCES)
        ));

        // 5. Absolute symlink targets (`/etc/shadow`, `/../etc/passwd`) rejected under StrictConfined.
        for bad_target in [
            "/etc/shadow",
            "/../etc/passwd",
            "//host/share",
            r"\\host\share",
        ] {
            let (bad_sym, _) = build_tar_gz(|b| {
                append_symlink(b, "bad", bad_target);
            });
            assert!(
                matches!(
                    run_import(vec![bad_sym], None, OciTarImportOptions::default()).await,
                    Err(Errno::EACCES | Errno::EINVAL)
                ),
                "expected rejection for symlink target {bad_target:?}"
            );
        }

        // 5b. RootedAbsolute allows clean `/etc/app.conf` but STILL rejects `/../etc/passwd` and `//host/share`.
        let (abs_ok, _) = build_tar_gz(|b| {
            append_symlink(b, "ok", "/etc/app.conf");
        });
        let rooted_opts = OciTarImportOptions {
            symlink_policy: SymlinkPolicy::RootedAbsolute,
            ..Default::default()
        };
        assert!(
            run_import(vec![abs_ok], None, rooted_opts.clone())
                .await
                .is_ok()
        );
        for bad_rooted in ["/../etc/passwd", "//host/share", r"\\host\share"] {
            let (bad_sym, _) = build_tar_gz(|b| {
                append_symlink(b, "bad", bad_rooted);
            });
            assert!(
                matches!(
                    run_import(vec![bad_sym], None, rooted_opts.clone()).await,
                    Err(Errno::EACCES | Errno::EINVAL)
                ),
                "expected RootedAbsolute rejection for {bad_rooted:?}"
            );
        }

        // 6. Device (Char, Block) and FIFO entries rejected with EPERM.
        for etype in [
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
        ] {
            let (dev_tar, _) = build_tar_gz(|b| {
                let mut h = tar::Header::new_gnu();
                h.set_entry_type(etype);
                h.set_size(0);
                h.set_mode(0o600);
                h.set_cksum();
                b.append_data(&mut h, "devnode", Cursor::new(&[][..]))
                    .unwrap();
            });
            assert_eq!(
                run_import(vec![dev_tar], None, OciTarImportOptions::default())
                    .await
                    .unwrap_err(),
                Errno::EPERM
            );
        }

        // 7. Setuid (0o4755) and setgid (0o2755): EPERM by default, stripped to 0o0755 under Strip.
        for suid_mode in [0o4755u32, 0o2755u32] {
            let (suid_tar, _) = build_tar_gz(|b| {
                append_file(b, "bin/suid", suid_mode, b"binary");
            });
            assert_eq!(
                run_import(vec![suid_tar.clone()], None, OciTarImportOptions::default())
                    .await
                    .unwrap_err(),
                Errno::EPERM
            );
            let head = Rc::new(MemoryHeadStore::new());
            let packs = Rc::new(MemoryPackStore::new());
            let vol = VolumeId("suid-strip".into());
            let cfg = CowFsConfig::local_native(test_clock());
            import_oci_tar_layers(
                Rc::clone(&head),
                Rc::clone(&packs),
                vol.clone(),
                &[OciTarLayerInput {
                    bytes: &suid_tar,
                    expected_diff_id: None,
                }],
                &OciTarImportOptions {
                    setuid_policy: SetuidPolicy::Strip,
                    ..Default::default()
                },
                None,
                cfg.clone(),
            )
            .await
            .expect("strip succeeds");
            let fs = CowFs::open(head, packs, vol, CowFsOpenMode::ReadOnly, cfg)
                .await
                .unwrap();
            let entry = lookup_meta_by_path(&fs, "/bin/suid").await.unwrap();
            assert_eq!(entry.metadata.mode & 0o7777, 0o0755);
        }

        // 8. Gzip bomb exceeds max_layer_uncompressed_bytes -> EFBIG.
        let (bomb, _) = build_tar_gz(|b| {
            let zeros = vec![0u8; 512 * 1024];
            append_file(b, "big.bin", 0o644, &zeros);
        });
        assert!(bomb.len() < 4096, "gzip bomb should compress tiny");
        assert_eq!(
            run_import(
                vec![bomb],
                None,
                OciTarImportOptions {
                    max_layer_uncompressed_bytes: 64 * 1024,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err(),
            Errno::EFBIG
        );

        // 9. Entry cap exceeded -> EFBIG.
        let (many, _) = build_tar_gz(|b| {
            for i in 0..10 {
                append_file(b, &format!("f{i}.txt"), 0o644, b"x");
            }
        });
        assert_eq!(
            run_import(
                vec![many],
                None,
                OciTarImportOptions {
                    max_entries: 5,
                    ..Default::default()
                },
            )
            .await
            .unwrap_err(),
            Errno::EFBIG
        );

        // 10. DiffID mismatch -> EIO.
        let (valid_layer, _) = build_tar_gz(|b| {
            append_file(b, "hello.txt", 0o644, b"world");
        });
        assert_eq!(
            run_import(
                vec![valid_layer],
                Some(format!("sha256:{}", "0".repeat(64))),
                OciTarImportOptions::default(),
            )
            .await
            .unwrap_err(),
            Errno::EIO
        );
    });
}

#[test]
fn oci_07_reproducible_exporter_digests_and_lossless_round_trip() {
    run(async {
        let head = Rc::new(MemoryHeadStore::new());
        let packs = Rc::new(MemoryPackStore::new());
        let vol = VolumeId("oci-07-src".into());
        let cfg = CowFsConfig::local_native(test_clock());
        CowFs::format_volume(&*head, &*packs, vol.clone(), 0, 0, 0o755, (test_clock())())
            .await
            .unwrap();
        let fs = CowFs::open(
            Rc::clone(&head),
            Rc::clone(&packs),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            cfg.clone(),
        )
        .await
        .unwrap();
        let cred = root_cred();

        // Populate inline small file, multi-extent large file, hard link, symlink, nested dirs.
        let mut rw = OpenOptions::new();
        rw.read(true).write(true).create_new(true);
        let dir_etc = fs.mkdir(&cred, &fs.root(), "etc", 0o755).await.unwrap();
        let (small, open_s) = fs
            .create(&cred, &dir_etc.handle, "small.txt", 0o600, &rw)
            .await
            .unwrap();
        fs.write_at(&open_s, b"inline-small-content", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&open_s).await.unwrap();

        let dir_var = fs.mkdir(&cred, &fs.root(), "var", 0o755).await.unwrap();
        let (_big, open_b) = fs
            .create(&cred, &dir_var.handle, "multi-extent.bin", 0o644, &rw)
            .await
            .unwrap();
        let mut expected_big = vec![0u8; 160 * 1024];
        for (i, byte) in expected_big.iter_mut().enumerate() {
            *byte = ((i * 31 + 17) & 0xff) as u8;
        }
        // Write in chunks across separate transaction commits to guarantee multiple extents/packs.
        fs.write_at(&open_b, &expected_big[..64 * 1024], WriteAt::Offset(0))
            .await
            .unwrap();
        fs.commit_tx_group().await.unwrap();
        fs.write_at(
            &open_b,
            &expected_big[64 * 1024..],
            WriteAt::Offset((64 * 1024) as u64),
        )
        .await
        .unwrap();
        fs.release(&open_b).await.unwrap();

        // Hard link to small.txt and confined relative symlink to multi-extent.bin.
        fs.link(&cred, &small.handle, &dir_etc.handle, "small-hardlink.txt")
            .await
            .unwrap();
        fs.symlink(&cred, &dir_etc.handle, "big-sym", "../var/multi-extent.bin")
            .await
            .unwrap();
        fs.commit_tx_group().await.unwrap();

        // Export twice and verify byte-for-byte reproducibility.
        let exp1 = export_cowfs_oci_tar_layer(&fs, &OciTarExportOptions::default())
            .await
            .unwrap();
        let exp2 = export_cowfs_oci_tar_layer(&fs, &OciTarExportOptions::default())
            .await
            .unwrap();
        assert_eq!(
            exp1.bytes, exp2.bytes,
            "tar+gzip export must be byte-for-byte deterministic"
        );
        assert_eq!(exp1.diff_id, exp2.diff_id);
        assert_eq!(exp1.blob_digest, exp2.blob_digest);

        // Build OCI config + manifest and independently verify compressed and uncompressed digests.
        let (oci_cfg, _cfg_bytes, cfg_desc) =
            build_oci_image_config(vec![exp1.diff_id.clone()], "amd64", "linux", None).unwrap();
        let layer_desc = abi::registry::OciDescriptor {
            media_type: exp1.media_type.clone(),
            digest: exp1.blob_digest.clone(),
            size: exp1.blob_size,
            urls: None,
            annotations: None,
            artifact_type: None,
            platform: None,
            data: None,
        };
        let (manifest, _, _) = build_oci_image_manifest(cfg_desc, vec![layer_desc], None).unwrap();

        let actual_compressed = format!("sha256:{}", digest_to_hex(&sha256(&exp1.bytes)));
        assert_eq!(actual_compressed, manifest.layers[0].digest);
        assert_eq!(exp1.bytes.len() as u64, manifest.layers[0].size);

        let mut gunzipped = Vec::new();
        MultiGzDecoder::new(Cursor::new(&exp1.bytes))
            .read_to_end(&mut gunzipped)
            .unwrap();
        let actual_diff_id = format!("sha256:{}", digest_to_hex(&sha256(&gunzipped)));
        assert_eq!(actual_diff_id, oci_cfg.rootfs.diff_ids[0]);
        assert_eq!(gunzipped.len() as u64, exp1.uncompressed_size);

        // Lossless round-trip re-import into a fresh cowfs volume.
        let dst_head = Rc::new(MemoryHeadStore::new());
        let dst_packs = Rc::new(MemoryPackStore::new());
        let dst_vol = VolumeId("oci-07-dst".into());
        import_oci_tar_layers(
            Rc::clone(&dst_head),
            Rc::clone(&dst_packs),
            dst_vol.clone(),
            &[OciTarLayerInput {
                bytes: &exp1.bytes,
                expected_diff_id: Some(&oci_cfg.rootfs.diff_ids[0]),
            }],
            &OciTarImportOptions::default(),
            Some("roundtrip"),
            cfg.clone(),
        )
        .await
        .expect("round-trip re-import succeeds");

        let fsck = verify_volume_strict(&*dst_head, &*dst_packs, &dst_vol)
            .await
            .unwrap();
        assert!(fsck.ok, "fsck errors: {:?}", fsck.errors);

        let dst_fs = CowFs::open(dst_head, dst_packs, dst_vol, CowFsOpenMode::ReadOnly, cfg)
            .await
            .unwrap();
        assert_eq!(
            read_file_by_path(&dst_fs, "/etc/small.txt").await.unwrap(),
            b"inline-small-content"
        );
        assert_eq!(
            read_file_by_path(&dst_fs, "/var/multi-extent.bin")
                .await
                .unwrap(),
            expected_big
        );
        let e1 = lookup_meta_by_path(&dst_fs, "/etc/small.txt")
            .await
            .unwrap();
        let e2 = lookup_meta_by_path(&dst_fs, "/etc/small-hardlink.txt")
            .await
            .unwrap();
        assert_eq!(e1.handle.node.ino, e2.handle.node.ino);
        assert_eq!(e1.metadata.nlink, 2);
        assert_eq!(e1.metadata.mode & 0o777, 0o600);
        let sym = lookup_meta_by_path(&dst_fs, "/etc/big-sym").await.unwrap();
        assert_eq!(
            dst_fs.read_link(&cred, &sym.handle).await.unwrap(),
            "../var/multi-extent.bin"
        );
    });
}
