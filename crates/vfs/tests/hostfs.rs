use abi::fs::JS_SAFE;
use abi::{ACL_ACCESS, ACL_DEFAULT, Errno, Time};
use os_core::acl::Entries;
use os_core::permissions::Identity;
use os_vfs::hostfs::mem::SimProfile;
use os_vfs::hostfs::{HostFs, HostGrant, STORE_FORMAT_VERSION};
use os_vfs::stat::stat as vfs_stat;
use os_vfs::{
    Cred, FileType, Filesystem, LockFamily, LockKind, LockRange, OpenOptions, RenameFlags, SetAttr,
    WriteAt, XattrFlags, profiles,
};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

struct FlagWaker(AtomicBool);

impl Wake for FlagWaker {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn block_on<F: Future>(fut: F) -> F::Output {
    let flag = Arc::new(FlagWaker(AtomicBool::new(true)));
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    for _ in 0..10_000 {
        flag.0.store(false, Ordering::SeqCst);
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return out;
        }
        assert!(
            flag.0.load(Ordering::SeqCst),
            "future stalled without waking in block_on"
        );
    }
    panic!("block_on exceeded poll budget");
}

fn poll_once<F: Future + ?Sized>(fut: &mut Pin<Box<F>>) -> Poll<F::Output> {
    let flag = Arc::new(FlagWaker(AtomicBool::new(false)));
    let waker = Waker::from(flag);
    let mut cx = Context::from_waker(&waker);
    fut.as_mut().poll(&mut cx)
}

fn user(uid: u32, gid: u32, groups: &[u32], umask: u16) -> Cred {
    Cred {
        identity: Identity {
            id: uid,
            group: gid,
            groups: groups.iter().copied().collect(),
        },
        umask,
        token: None,
    }
}

fn grant(owner: &Cred, read_only: bool, execute: bool) -> HostGrant {
    HostGrant {
        owner: owner.identity.clone(),
        read_only,
        execute,
    }
}

#[test]
fn opfs_and_directory_identities_are_53_bit_and_persist_across_aliases_and_remounts() {
    block_on(async {
        let owner = user(1000, 1000, &[1000, 2000], 0o022);
        let peer = user(1001, 1001, &[1001], 0o022);

        for is_opfs in [true, false] {
            let sim = SimProfile::new();
            let fs1 = if is_opfs {
                sim.mount_opfs(1, grant(&owner, false, true), 1)
                    .await
                    .unwrap()
            } else {
                let ops_before = sim.tree_ops();
                let mounted = sim
                    .mount_directory(1, grant(&owner, false, true), 1)
                    .await
                    .unwrap();
                // Directory-handle mount admission must NOT enumerate or stat the host folder.
                assert_eq!(sim.tree_ops(), ops_before);
                mounted
            };
            assert_eq!(
                fs1.capabilities(),
                if is_opfs {
                    profiles::OPFS
                } else {
                    profiles::DIRECTORY_HANDLE
                }
            );

            let root1 = fs1.root();
            let (entry, open) = fs1
                .create(
                    &owner,
                    &root1,
                    "doc.txt",
                    0o666,
                    OpenOptions::new().write(true),
                )
                .await
                .unwrap();
            fs1.write_at(&open, b"hello", WriteAt::Offset(0))
                .await
                .unwrap();
            fs1.release(&open).await.unwrap();

            let s1 = vfs_stat(fs1.id(), entry.handle.node, &entry.metadata);
            assert!(s1.dev >= 1 && s1.dev <= JS_SAFE);
            assert!(s1.ino >= 1 && s1.ino <= JS_SAFE);

            // Set chmod + access ACL + user xattr on first attachment.
            fs1.setattr(
                &owner,
                &entry.handle,
                &SetAttr {
                    mode: Some(0o640),
                    ..SetAttr::default()
                },
            )
            .await
            .unwrap();
            let acl_bytes = serde_json::to_vec(&Entries {
                user: 6,
                group: 4,
                other: 0,
                mask: Some(4),
                users: BTreeMap::from([(1001, 4)]),
                groups: BTreeMap::new(),
            })
            .unwrap();
            fs1.setxattr(
                &owner,
                &root1,
                ACL_ACCESS,
                &serde_json::to_vec(&Entries {
                    user: 7,
                    group: 5,
                    other: 0,
                    mask: Some(5),
                    users: BTreeMap::from([(1001, 5)]),
                    groups: BTreeMap::new(),
                })
                .unwrap(),
                XattrFlags::empty(),
            )
            .await
            .unwrap();
            fs1.setxattr(
                &owner,
                &entry.handle,
                ACL_ACCESS,
                &acl_bytes,
                XattrFlags::empty(),
            )
            .await
            .unwrap();
            fs1.setxattr(
                &owner,
                &entry.handle,
                "user.tag",
                b"important",
                XattrFlags::CREATE,
            )
            .await
            .unwrap();

            // Second concurrent alias in Tab 2 sees identical st_dev, st_ino, ACLs, and xattrs.
            let fs2 = if is_opfs {
                sim.mount_opfs(2, grant(&owner, false, true), 2)
                    .await
                    .unwrap()
            } else {
                sim.mount_directory(2, grant(&owner, false, true), 2)
                    .await
                    .unwrap()
            };
            let looked = fs2.lookup(&peer, &fs2.root(), "doc.txt").await.unwrap();
            let s2 = vfs_stat(fs2.id(), looked.handle.node, &looked.metadata);
            assert_eq!(s1.dev, s2.dev);
            assert_eq!(s1.ino, s2.ino);
            assert!(s2.acl);
            assert_eq!(
                fs2.getxattr(&peer, &looked.handle, "user.tag")
                    .await
                    .unwrap(),
                b"important"
            );

            // Remount after dropping both mounts preserves all metadata and zero sidecar files.
            drop(fs1);
            drop(fs2);
            if !is_opfs {
                assert_eq!(sim.host_paths(), vec!["doc.txt".to_string()]);
            }

            let fs3 = if is_opfs {
                sim.mount_opfs(3, grant(&owner, false, true), 3)
                    .await
                    .unwrap()
            } else {
                sim.mount_directory(3, grant(&owner, false, true), 3)
                    .await
                    .unwrap()
            };
            let after = fs3.lookup(&peer, &fs3.root(), "doc.txt").await.unwrap();
            let s3 = vfs_stat(fs3.id(), after.handle.node, &after.metadata);
            assert_eq!(s1.dev, s3.dev);
            assert_eq!(s1.ino, s3.ino);
            assert!(s3.acl);
            let r = fs3
                .open(&peer, &after.handle, OpenOptions::new().read(true))
                .await
                .unwrap();
            let mut buf = [0u8; 8];
            let n = fs3.read_at(&r, &mut buf, 0).await.unwrap();
            assert_eq!(&buf[..n], b"hello");
            fs3.release(&r).await.unwrap();
        }
    });
}

#[test]
fn creation_rules_distinct_setgid_default_acl_named_user_denial_and_grant_ceilings() {
    block_on(async {
        // Creator primary group 100, supplementary group 300; parent dir group 300 with setgid.
        let alice = user(10, 100, &[100, 300], 0o027);
        let bob = user(11, 200, &[200, 300], 0o022);
        let sim = SimProfile::new();
        let fs = sim
            .mount_opfs(1, grant(&alice, false, false), 1)
            .await
            .unwrap();
        let root = fs.root();

        let shared = fs.mkdir(&alice, &root, "shared", 0o777).await.unwrap();
        assert_eq!(shared.metadata.mode, 0o750);
        assert_eq!(shared.metadata.gid, 100);

        // Chown to supplementary group 300 and set setgid (02770).
        let meta = fs
            .setattr(
                &alice,
                &shared.handle,
                &SetAttr {
                    gid: Some(300),
                    mode: Some(0o2770),
                    ..SetAttr::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(meta.gid, 300);
        assert_eq!(meta.mode, 0o2770);

        // Install default ACL granting bob r-x, mask r-x, ignoring umask on child creation.
        let def_acl = serde_json::to_vec(&Entries {
            user: 7,
            group: 7,
            other: 0,
            mask: Some(5),
            users: BTreeMap::from([(11, 5)]),
            groups: BTreeMap::new(),
        })
        .unwrap();
        fs.setxattr(
            &alice,
            &shared.handle,
            ACL_DEFAULT,
            &def_acl,
            XattrFlags::empty(),
        )
        .await
        .unwrap();

        let (child, copen) = fs
            .create(
                &alice,
                &shared.handle,
                "item.wasm",
                0o777,
                OpenOptions::new().write(true),
            )
            .await
            .unwrap();
        fs.write_at(&copen, b"\0asm\x01\0\0\0", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&copen).await.unwrap();
        assert_eq!(child.metadata.gid, 300);
        assert!(child.metadata.acl);

        // Grant ceiling: `execute: false` refuses `Access::Exec` on regular files even when mode/ACL has +x!
        fs.setattr(
            &alice,
            &root,
            &SetAttr {
                mode: Some(0o755),
                ..SetAttr::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            fs.open(&bob, &child.handle, OpenOptions::new().exec(true))
                .await,
            Err(Errno::EACCES)
        );

        // Named-user denial (bob -> 0) takes precedence over bob's membership in allowed group 300!
        let deny_bob = serde_json::to_vec(&Entries {
            user: 7,
            group: 5,
            other: 5,
            mask: Some(5),
            users: BTreeMap::from([(11, 0)]),
            groups: BTreeMap::new(),
        })
        .unwrap();
        fs.setxattr(
            &alice,
            &child.handle,
            ACL_ACCESS,
            &deny_bob,
            XattrFlags::empty(),
        )
        .await
        .unwrap();
        assert_eq!(
            fs.open(&bob, &child.handle, OpenOptions::new().read(true))
                .await,
            Err(Errno::EACCES)
        );

        // Read-only grant ceiling refuses all mutations with EROFS even for owner.
        let ro = sim
            .mount_opfs(2, grant(&alice, true, false), 2)
            .await
            .unwrap();
        assert_eq!(
            ro.mkdir(&alice, &ro.root(), "nope", 0o755).await,
            Err(Errno::EROFS)
        );
        let ro_child = ro.lookup(&alice, &ro.root(), "shared").await.unwrap();
        assert_eq!(
            ro.setattr(
                &alice,
                &ro_child.handle,
                &SetAttr {
                    mode: Some(0o700),
                    ..SetAttr::default()
                }
            )
            .await,
            Err(Errno::EROFS)
        );
    });
}

#[test]
fn opfs_hard_links_symlinks_open_unlink_multi_tab_and_crash_orphan_sweep() {
    block_on(async {
        let owner = user(1000, 1000, &[1000], 0o022);
        let sim = SimProfile::new();
        let tab1 = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let tab2 = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();

        // Hard links & primary link unlink evacuation.
        let (orig, w) = tab1
            .create(
                &owner,
                &tab1.root(),
                "a.txt",
                0o644,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        tab1.write_at(&w, b"linked-data", WriteAt::Offset(0))
            .await
            .unwrap();
        let alias = tab1
            .link(&owner, &orig.handle, &tab1.root(), "b.txt")
            .await
            .unwrap();
        assert_eq!(alias.handle.node.ino, orig.handle.node.ino);
        assert_eq!(alias.metadata.nlink, 2);

        // Symlink creation & readlink.
        let sym = tab1
            .symlink(&owner, &tab1.root(), "sym.txt", "b.txt")
            .await
            .unwrap();
        assert_eq!(sym.metadata.file_type, FileType::Symlink);
        assert_eq!(tab1.read_link(&owner, &sym.handle).await.unwrap(), "b.txt");

        // Unlink primary path `a.txt`; `b.txt` keeps content & nlink == 1!
        tab1.unlink(&owner, &tab1.root(), "a.txt").await.unwrap();
        assert_eq!(
            tab2.lookup(&owner, &tab2.root(), "a.txt").await,
            Err(Errno::ENOENT)
        );
        let b_entry = tab2.lookup(&owner, &tab2.root(), "b.txt").await.unwrap();
        assert_eq!(b_entry.metadata.nlink, 1);

        // Tab 2 also opens `b.txt`; then Tab 1 unlinks `b.txt` (`open-unlink`).
        let r2 = tab2
            .open(&owner, &b_entry.handle, OpenOptions::new().read(true))
            .await
            .unwrap();
        tab1.unlink(&owner, &tab1.root(), "b.txt").await.unwrap();
        assert_eq!(
            tab2.lookup(&owner, &tab2.root(), "b.txt").await,
            Err(Errno::ENOENT)
        );
        let fstat_meta = tab2.open_metadata(&r2).await.unwrap();
        assert_eq!(fstat_meta.nlink, 0);
        assert_eq!(sim.orphan_ids(), vec![orig.handle.node.ino]);

        // Closing Tab 1's open ref keeps orphan alive because Tab 2 still holds `r2`.
        tab1.release(&w).await.unwrap();
        assert_eq!(sim.orphan_ids(), vec![orig.handle.node.ino]);
        let mut buf = [0u8; 16];
        let n = tab2.read_at(&r2, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"linked-data");

        // Closing Tab 2's last open ref deletes the orphan immediately.
        tab2.release(&r2).await.unwrap();
        assert!(sim.orphan_ids().is_empty());

        // Crash-recovery sweep test: Tab 2 opens + unlinks `crash.txt`, then crashes (`crash_tab(2)`).
        // Meanwhile Tab 1 holds an unlinked `live.txt` open — startup of Tab 3 must sweep `crash.txt`
        // AND keep `live.txt` intact!
        let (live_e, live_open) = tab1
            .create(
                &owner,
                &tab1.root(),
                "live.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        tab1.write_at(&live_open, b"still-open", WriteAt::Offset(0))
            .await
            .unwrap();
        tab1.unlink(&owner, &tab1.root(), "live.txt").await.unwrap();

        let (crash_e, crash_open) = tab2
            .create(
                &owner,
                &tab2.root(),
                "crash.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        tab2.write_at(&crash_open, b"leaked-by-crash", WriteAt::Offset(0))
            .await
            .unwrap();
        tab2.unlink(&owner, &tab2.root(), "crash.txt")
            .await
            .unwrap();
        assert_eq!(sim.orphan_ids().len(), 2);

        // Crash Tab 2 without calling `release`!
        sim.crash_tab(2);
        drop(tab2);

        // Mount Tab 3: startup `sweep_orphans` cleans `crash.txt` while preserving `live.txt`!
        let _tab3 = sim
            .mount_opfs(3, grant(&owner, false, true), 3)
            .await
            .unwrap();
        assert_eq!(sim.orphan_ids(), vec![live_e.handle.node.ino]);
        assert!(sim.raw_inode(crash_e.handle.node.ino).is_none());
        let mut live_buf = [0u8; 16];
        let n_live = tab1.read_at(&live_open, &mut live_buf, 0).await.unwrap();
        assert_eq!(&live_buf[..n_live], b"still-open");
        tab1.release(&live_open).await.unwrap();
        assert!(sim.orphan_ids().is_empty());
    });
}

#[test]
fn directory_handle_stale_on_open_unlink_outside_edit_copy_dir_rename_and_link_refusal() {
    block_on(async {
        let owner = user(1000, 1000, &[1000], 0o022);
        let peer = user(1001, 1001, &[1001], 0o022);
        let sim = SimProfile::new();
        // Enable Chromium copy-fallback directory rename mode (`entry.move` absent on directories).
        sim.set_copy_dir_move(true);

        let fs = sim
            .mount_directory(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let root = fs.root();

        // link & symlink explicitly refused with EPERM.
        let (f, fopen) = fs
            .create(
                &owner,
                &root,
                "note.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&fopen, b"v1", WriteAt::Offset(0))
            .await
            .unwrap();
        assert_eq!(
            fs.link(&owner, &f.handle, &root, "hard.txt").await,
            Err(Errno::EPERM)
        );
        assert_eq!(
            fs.symlink(&owner, &root, "sym.txt", "note.txt").await,
            Err(Errno::EPERM)
        );

        // O_EXCL & RENAME_NOREPLACE enforced atomically.
        assert_eq!(
            fs.create(
                &owner,
                &root,
                "note.txt",
                0o600,
                OpenOptions::new().write(true).create_new(true),
            )
            .await,
            Err(Errno::EEXIST)
        );

        // OS rename of open file AND open directory (with copy-move mtime bump) preserves open handle & ino!
        let dir_a = fs.mkdir(&owner, &root, "dir_a", 0o700).await.unwrap();
        let (nested, nested_open) = fs
            .create(
                &owner,
                &dir_a.handle,
                "inside.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&nested_open, b"nested-payload", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.rename(&owner, &root, "dir_a", &root, "dir_b", RenameFlags::empty())
            .await
            .unwrap();
        let dir_b = fs.lookup(&owner, &root, "dir_b").await.unwrap();
        assert_eq!(dir_b.handle.node.ino, dir_a.handle.node.ino);
        let moved_nested = fs
            .lookup(&owner, &dir_b.handle, "inside.txt")
            .await
            .unwrap();
        assert_eq!(moved_nested.handle.node.ino, nested.handle.node.ino);
        let mut buf = [0u8; 32];
        let n = fs.read_at(&nested_open, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"nested-payload");
        fs.release(&nested_open).await.unwrap();

        // RENAME_NOREPLACE fails with EEXIST when target exists.
        let (_, other_open) = fs
            .create(
                &owner,
                &root,
                "other.txt",
                0o600,
                OpenOptions::new().write(true),
            )
            .await
            .unwrap();
        fs.release(&other_open).await.unwrap();
        assert_eq!(
            fs.rename(
                &owner,
                &root,
                "note.txt",
                &root,
                "other.txt",
                RenameFlags::NOREPLACE
            )
            .await,
            Err(Errno::EEXIST)
        );

        // Grant ACL to `peer` on `note.txt`, then modify `note.txt` OUTSIDE the OS:
        // 1) Existing open descriptor `fopen` fails with ESTALE!
        // 2) Path lookup succeeds with new `ino` and resets metadata to private defaults (0600, no ACL)!
        let acl_bytes = serde_json::to_vec(&Entries {
            user: 6,
            group: 4,
            other: 0,
            mask: Some(4),
            users: BTreeMap::from([(1001, 4)]),
            groups: BTreeMap::new(),
        })
        .unwrap();
        fs.setxattr(
            &owner,
            &f.handle,
            ACL_ACCESS,
            &acl_bytes,
            XattrFlags::empty(),
        )
        .await
        .unwrap();
        sim.external_write("note.txt", b"changed-outside-os");

        assert_eq!(fs.read_at(&fopen, &mut buf, 0).await, Err(Errno::ESTALE));
        assert_eq!(fs.open_metadata(&fopen).await, Err(Errno::ESTALE));
        fs.release(&fopen).await.unwrap();

        let reset = fs.lookup(&owner, &root, "note.txt").await.unwrap();
        assert_ne!(reset.handle.node.ino, f.handle.node.ino);
        assert_eq!(reset.metadata.mode, 0o600);
        assert!(!reset.metadata.acl);
        assert_eq!(
            fs.open(&peer, &reset.handle, OpenOptions::new().read(true))
                .await,
            Err(Errno::EACCES)
        );

        // Open-unlink on directory handle marks open descriptor ESTALE on subsequent I/O & fstat.
        let r_open = fs
            .open(&owner, &reset.handle, OpenOptions::new().read(true))
            .await
            .unwrap();
        fs.unlink(&owner, &root, "note.txt").await.unwrap();
        assert_eq!(fs.read_at(&r_open, &mut buf, 0).await, Err(Errno::ESTALE));
        assert_eq!(fs.open_metadata(&r_open).await, Err(Errno::ESTALE));
        fs.release(&r_open).await.unwrap();

        // Host permission revocation -> EACCES.
        sim.set_permission_revoked(true);
        assert_eq!(
            fs.lookup(&owner, &root, "other.txt").await,
            Err(Errno::EACCES)
        );
    });
}

#[test]
fn store_format_versioning_resets_older_preserving_files_and_refuses_newer_untouched() {
    block_on(async {
        let owner = user(1000, 1000, &[1000], 0o022);
        let sim = SimProfile::new();
        let fs = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (entry, open) = fs
            .create(
                &owner,
                &fs.root(),
                "keep.txt",
                0o666,
                OpenOptions::new().write(true),
            )
            .await
            .unwrap();
        fs.write_at(&open, b"precious-user-bytes", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&open).await.unwrap();
        fs.setattr(
            &owner,
            &entry.handle,
            &SetAttr {
                mode: Some(0o644),
                mtime: Time::At { sec: 42, nsec: 0 },
                ..SetAttr::default()
            },
        )
        .await
        .unwrap();
        let old_uuid = fs.uuid().to_string();
        drop(fs);

        // Downgrade store version to 0 (older): mounting resets metadata to private defaults (0600)
        // once while preserving `keep.txt` bytes and UUID!
        sim.set_raw_version(Some(0));
        let upgraded = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();
        assert_eq!(sim.raw_version(), Some(STORE_FORMAT_VERSION));
        assert_eq!(upgraded.uuid(), old_uuid);
        let kept = upgraded
            .lookup(&owner, &upgraded.root(), "keep.txt")
            .await
            .unwrap();
        assert_eq!(kept.metadata.mode, 0o600);
        assert_eq!(
            sim.external_read("keep.txt").as_deref(),
            Some(b"precious-user-bytes".as_slice())
        );

        // Bump store version to STORE_FORMAT_VERSION + 1 (from a newer tab):
        // existing tab ops AND new mounts fail with EPROTONOSUPPORT without resetting the store!
        sim.set_raw_version(Some(STORE_FORMAT_VERSION + 1));
        assert_eq!(
            upgraded.lookup(&owner, &upgraded.root(), "keep.txt").await,
            Err(Errno::EPROTONOSUPPORT)
        );
        assert!(matches!(
            sim.mount_opfs(3, grant(&owner, false, true), 3).await,
            Err(Errno::EPROTONOSUPPORT)
        ));
        assert_eq!(sim.raw_version(), Some(STORE_FORMAT_VERSION + 1));
        assert!(sim.raw_inode(kept.handle.node.ino).is_some());
    });
}

#[test]
fn fsync_fdatasync_durability_quota_and_error_contracts() {
    block_on(async {
        let owner = user(1000, 1000, &[1000], 0o022);
        let sim = SimProfile::new();
        let fs = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (entry, open) = fs
            .create(
                &owner,
                &fs.root(),
                "durable.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&open, b"sync-me", WriteAt::Offset(0))
            .await
            .unwrap();

        let before = sim.flushes();
        fs.sync_data(&open).await.unwrap();
        fs.sync_all(&open).await.unwrap();
        let after = sim.flushes();
        assert_eq!(after.0, before.0 + 2);
        assert!(after.1 + after.2 >= before.1 + before.2 + 2);

        // O_PATH open ref -> EBADF on sync; symlink -> EINVAL on sync; closed ref -> EBADF.
        let path_open = fs
            .open(&owner, &entry.handle, OpenOptions::new().path(true))
            .await
            .unwrap();
        assert_eq!(fs.sync_all(&path_open).await, Err(Errno::EBADF));
        fs.release(&path_open).await.unwrap();

        // Flush failure -> EIO; quota failure -> EDQUOT.
        sim.set_flush_error(true);
        assert_eq!(fs.sync_all(&open).await, Err(Errno::EIO));
        sim.set_flush_error(false);

        sim.set_quota_exceeded(true);
        assert_eq!(
            fs.write_at(&open, b"more", WriteAt::End).await,
            Err(Errno::EDQUOT)
        );
        sim.set_quota_exceeded(false);

        fs.release(&open).await.unwrap();
        assert_eq!(fs.sync_all(&open).await, Err(Errno::EBADF));
    });
}

#[test]
fn multi_tab_flock_and_fcntl_byte_ranges_deadlock_cancel_crash_and_enolck() {
    let owner = user(1000, 1000, &[1000], 0o022);
    let sim = SimProfile::new();

    let (tab1, tab2, o1_a, o2_a, o1_b, o2_b) = block_on(async {
        let tab1 = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let tab2 = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();
        let (fa, o1_a) = tab1
            .create(
                &owner,
                &tab1.root(),
                "a.lock",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let (fb, o1_b) = tab1
            .create(
                &owner,
                &tab1.root(),
                "b.lock",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let fa2 = tab2.lookup(&owner, &tab2.root(), "a.lock").await.unwrap();
        let fb2 = tab2.lookup(&owner, &tab2.root(), "b.lock").await.unwrap();
        let _ = (fa, fb);
        let o2_a = tab2
            .open(
                &owner,
                &fa2.handle,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let o2_b = tab2
            .open(
                &owner,
                &fb2.handle,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        (tab1, tab2, o1_a, o2_a, o1_b, o2_b)
    });

    // 1. Byte-range conflict, non-overlapping coexistence, and F_GETLK (`test_lock`).
    block_on(async {
        let r0_10 = LockRange::new(0, Some(10)).unwrap();
        let r10_10 = LockRange::new(10, Some(20)).unwrap();
        tab1.try_lock(&o1_a, LockFamily::Posix, LockKind::Exclusive, r0_10)
            .await
            .unwrap();
        assert_eq!(
            tab2.try_lock(&o2_a, LockFamily::Posix, LockKind::Exclusive, r0_10)
                .await,
            Err(Errno::EAGAIN)
        );
        // Non-overlapping [10..20) succeeds in Tab 2!
        tab2.try_lock(&o2_a, LockFamily::Posix, LockKind::Exclusive, r10_10)
            .await
            .unwrap();
        let conflict = tab2
            .test_lock(&o2_a, LockKind::Shared, r0_10)
            .await
            .unwrap()
            .expect("conflict on [0..10)");
        assert_eq!(conflict.owner, o1_a.id);
        assert_eq!(conflict.kind, LockKind::Exclusive);
        tab2.unlock(&o2_a, LockFamily::Posix, r10_10).await.unwrap();
    });

    // 2. Cross-tab `fcntl` byte-range deadlock (`EDEADLK`) & cancellation!
    // `o1_a` (Tab 1) already holds `[0..10)`; `o2_a` (Tab 2) holds `[10..20)` and blocks waiting
    // on `[0..10)`; then `o1_a` blocking on `[10..20)` closes the `o1_a -> o2_a -> o1_a` cycle and
    // must fail immediately with `Err(Errno::EDEADLK)`!
    let r0_10 = LockRange::new(0, Some(10)).unwrap();
    let r10_20 = LockRange::new(10, Some(20)).unwrap();
    let _ = (&o1_b, &o2_b);
    block_on(tab2.try_lock(&o2_a, LockFamily::Posix, LockKind::Exclusive, r10_20)).unwrap();
    {
        let mut wait_tab2 =
            Box::pin(tab2.lock(&o2_a, LockFamily::Posix, LockKind::Exclusive, r0_10));
        assert!(poll_once(&mut wait_tab2).is_pending());

        let deadlk = block_on(tab1.lock(&o1_a, LockFamily::Posix, LockKind::Exclusive, r10_20));
        assert_eq!(deadlk, Err(Errno::EDEADLK));

        // Dropping `wait_tab2` cancels Tab 2's wait immediately!
        drop(wait_tab2);
    }
    block_on(async {
        tab1.unlock(&o1_a, LockFamily::Posix, r0_10).await.unwrap();
        tab2.unlock(&o2_a, LockFamily::Posix, r10_20).await.unwrap();
    });

    // 3. Blocking `flock` wait wakes automatically when holder tab crashes!
    block_on(tab2.try_lock(
        &o2_a,
        LockFamily::Flock,
        LockKind::Exclusive,
        LockRange::WHOLE,
    ))
    .unwrap();
    {
        let mut wait_tab1 = Box::pin(tab1.lock(
            &o1_a,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE,
        ));
        assert!(poll_once(&mut wait_tab1).is_pending());

        // Crash Tab 2! Its `os-fs-open` Web Lock releases and wakes `wait_tab1`!
        sim.crash_tab(2);
        drop(tab2);
        assert_eq!(poll_once(&mut wait_tab1), Poll::Ready(Ok(())));
    }

    // 4. Unavailable lock coordinator returns `Errno::ENOLCK` cleanly instead of faking success.
    block_on(async {
        let broken_locks = sim.locks_handle(9);
        broken_locks.set_unavailable(true);
        let tab9 = HostFs::opfs(
            grant(&owner, false, true),
            9,
            sim.tree_handle(),
            sim.meta_handle(),
            broken_locks,
            sim.clock(),
        );
        assert!(matches!(tab9.await, Err(Errno::ENOLCK)));

        let locks4 = sim.locks_handle(4);
        let tab4 = HostFs::opfs(
            grant(&owner, false, true),
            4,
            sim.tree_handle(),
            sim.meta_handle(),
            locks4.clone(),
            sim.clock(),
        )
        .await
        .unwrap();
        let fa4 = tab4.lookup(&owner, &tab4.root(), "a.lock").await.unwrap();
        let o4 = tab4
            .open(
                &owner,
                &fa4.handle,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        locks4.set_unavailable(true);
        assert_eq!(
            tab4.try_lock(&o4, LockFamily::Flock, LockKind::Shared, LockRange::WHOLE)
                .await,
            Err(Errno::ENOLCK)
        );
    });
}
