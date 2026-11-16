use abi::fs::JS_SAFE;
use abi::{ACL_ACCESS, ACL_DEFAULT, Errno, Time};
use os_core::acl::Entries;
use os_core::permissions::Identity;
use os_vfs::hostfs::mem::SimProfile;
use os_vfs::hostfs::{
    Backing, HostFs, HostGrant, PendingRename, PendingTruncate, STORE_FORMAT_VERSION,
};
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

#[test]
fn failed_replacement_rename_preserves_destination_and_unlinked_orphan() {
    let owner = user(1, 1, &[1], 0o022);

    // 1. OPFS: ordinary replacement rename failure (`EDQUOT`) keeps destination content intact, and
    // an open unlinked target is rolled back out of orphans when `move_entry` fails.
    block_on(async {
        let sim = SimProfile::new();
        let fs = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (src, o_src) = fs
            .create(
                &owner,
                &fs.root(),
                "src",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let (dst, o_dst) = fs
            .create(
                &owner,
                &fs.root(),
                "dst",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&o_src, b"NEW", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.write_at(&o_dst, b"OLD", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&o_src).await.unwrap();
        let _ = src;

        // With `dst` still open, trigger `EDQUOT` inside `move_entry`: target must be restored!
        sim.set_quota_exceeded(true);
        let err = fs
            .rename(
                &owner,
                &fs.root(),
                "src",
                &fs.root(),
                "dst",
                RenameFlags::empty(),
            )
            .await
            .unwrap_err();
        assert_eq!(err, Errno::EDQUOT);
        sim.set_quota_exceeded(false);

        assert!(sim.orphan_ids().is_empty());
        assert_eq!(sim.external_read("src").as_deref(), Some(b"NEW".as_slice()));
        assert_eq!(sim.external_read("dst").as_deref(), Some(b"OLD".as_slice()));

        // Open descriptor on `dst` still resolves cleanly after rollback, and fresh lookup works.
        let mut buf = [0u8; 8];
        let n = fs.read_at(&o_dst, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"OLD");
        let dst_now = fs.lookup(&owner, &fs.root(), "dst").await.unwrap();
        assert_eq!(dst_now.handle.node.ino, dst.handle.node.ino);
        fs.release(&o_dst).await.unwrap();

        // Also test closed destination on `EDQUOT`.
        sim.set_quota_exceeded(true);
        assert_eq!(
            fs.rename(
                &owner,
                &fs.root(),
                "src",
                &fs.root(),
                "dst",
                RenameFlags::empty()
            )
            .await
            .unwrap_err(),
            Errno::EDQUOT
        );
        sim.set_quota_exceeded(false);
        assert_eq!(sim.external_read("dst").as_deref(), Some(b"OLD".as_slice()));
    });

    // 2. Host Directory: failed replacement rename preserves destination in both tree and metadata.
    block_on(async {
        let sim = SimProfile::new();
        sim.external_write("src", b"SRC");
        sim.external_write("dst", b"KEEP");
        let fs = sim
            .mount_directory(1, grant(&owner, false, false), 1)
            .await
            .unwrap();
        sim.set_quota_exceeded(true);
        assert_eq!(
            fs.rename(
                &owner,
                &fs.root(),
                "src",
                &fs.root(),
                "dst",
                RenameFlags::empty()
            )
            .await
            .unwrap_err(),
            Errno::EDQUOT
        );
        sim.set_quota_exceeded(false);
        let dst_e = fs.lookup(&owner, &fs.root(), "dst").await.unwrap();
        let ro = fs
            .open(&owner, &dst_e.handle, OpenOptions::new().read(true))
            .await
            .unwrap();
        let mut buf = [0u8; 8];
        let n = fs.read_at(&ro, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"KEEP");
        fs.release(&ro).await.unwrap();
    });
}

#[test]
fn read_only_directory_attachment_does_not_strip_persistent_owner_write_bit() {
    let owner = user(10, 10, &[10], 0o022);
    let sim = SimProfile::new();
    sim.external_write("notes.txt", b"hello");

    block_on(async {
        let ro_fs = sim
            .mount_directory(1, grant(&owner, true, false), 1)
            .await
            .unwrap();
        let ro_entry = ro_fs
            .lookup(&owner, &ro_fs.root(), "notes.txt")
            .await
            .unwrap();
        assert_eq!(ro_entry.metadata.mode, 0o600);
        assert_eq!(
            ro_fs
                .open(&owner, &ro_entry.handle, OpenOptions::new().write(true))
                .await,
            Err(Errno::EROFS)
        );
        drop(ro_fs);

        let rw_fs = sim
            .mount_directory(2, grant(&owner, false, false), 2)
            .await
            .unwrap();
        let rw_entry = rw_fs
            .lookup(&owner, &rw_fs.root(), "notes.txt")
            .await
            .unwrap();
        assert_eq!(rw_entry.metadata.mode, 0o600);
        let w = rw_fs
            .open(&owner, &rw_entry.handle, OpenOptions::new().write(true))
            .await
            .unwrap();
        rw_fs
            .write_at(&w, b"world", WriteAt::Offset(0))
            .await
            .unwrap();
        rw_fs.release(&w).await.unwrap();
    });
}

#[test]
fn multiple_blocked_waiters_do_not_churn_lock_notifications() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    let (tab1, tab2, tab3, o1, o2, o3) = block_on(async {
        let tab1 = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let tab2 = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();
        let tab3 = sim
            .mount_opfs(3, grant(&owner, false, true), 3)
            .await
            .unwrap();
        let (f, o1) = tab1
            .create(
                &owner,
                &tab1.root(),
                "lock",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let _ = f;
        let f2 = tab2.lookup(&owner, &tab2.root(), "lock").await.unwrap();
        let f3 = tab3.lookup(&owner, &tab3.root(), "lock").await.unwrap();
        let o2 = tab2
            .open(
                &owner,
                &f2.handle,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let o3 = tab3
            .open(
                &owner,
                &f3.handle,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        (tab1, tab2, tab3, o1, o2, o3)
    });

    block_on(tab1.try_lock(
        &o1,
        LockFamily::Flock,
        LockKind::Exclusive,
        LockRange::WHOLE,
    ))
    .unwrap();

    let mut wait2 = Box::pin(tab2.lock(
        &o2,
        LockFamily::Flock,
        LockKind::Exclusive,
        LockRange::WHOLE,
    ));
    let mut wait3 = Box::pin(tab3.lock(
        &o3,
        LockFamily::Flock,
        LockKind::Exclusive,
        LockRange::WHOLE,
    ));
    assert!(poll_once(&mut wait2).is_pending());
    assert!(poll_once(&mut wait3).is_pending());

    let epoch_after_join = sim.lock_notifications();
    // Re-polling while lock stays held must NOT emit broadcast churn!
    assert!(poll_once(&mut wait2).is_pending());
    assert!(poll_once(&mut wait3).is_pending());
    assert_eq!(sim.lock_notifications(), epoch_after_join);

    block_on(tab1.unlock(&o1, LockFamily::Flock, LockRange::WHOLE)).unwrap();
    assert!(sim.lock_notifications() > epoch_after_join);
    assert_eq!(poll_once(&mut wait2), Poll::Ready(Ok(())));
    drop(wait2);
    block_on(tab2.unlock(&o2, LockFamily::Flock, LockRange::WHOLE)).unwrap();
    assert_eq!(poll_once(&mut wait3), Poll::Ready(Ok(())));
    drop(wait3);
    let _ = tab3;
}

#[test]
fn directory_io_rejects_external_replacement_between_validate_and_io() {
    let owner = user(10, 10, &[10], 0o022);
    let sim = SimProfile::new();

    block_on(async {
        let fs = sim
            .mount_directory(1, grant(&owner, false, false), 1)
            .await
            .unwrap();
        let (secret, rd) = fs
            .create(
                &owner,
                &fs.root(),
                "secret.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&rd, b"original-data", WriteAt::Offset(0))
            .await
            .unwrap();
        let _ = secret;

        // Simulate external host replacement occurring after `validate_inode_by_id` and right
        // before `HostTree::read_file`: must return `ESTALE`, never leak replacement bytes, and
        // mark the old inode stale.
        sim.schedule_external_replace("secret.txt", b"REPLACED_SECRET_BYTES");
        let mut buf = [0u8; 32];
        assert_eq!(fs.read_at(&rd, &mut buf, 0).await, Err(Errno::ESTALE));
        assert_eq!(fs.read_at(&rd, &mut buf, 0).await, Err(Errno::ESTALE));
        fs.release(&rd).await.unwrap();

        // Now verify `write_at` and `set_len` refuse to overwrite a replacement host file too.
        let (_, wr) = fs
            .create(
                &owner,
                &fs.root(),
                "target.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&wr, b"old-body", WriteAt::Offset(0))
            .await
            .unwrap();

        sim.schedule_external_replace("target.txt", b"REPLACED_KEEP_INTACT");
        assert_eq!(
            fs.write_at(&wr, b"STALE_CLOBBER", WriteAt::Offset(0)).await,
            Err(Errno::ESTALE)
        );
        assert_eq!(
            sim.external_read("target.txt").as_deref(),
            Some(b"REPLACED_KEEP_INTACT".as_slice())
        );
        fs.release(&wr).await.unwrap();

        let (trunc_entry, tr) = fs
            .create(
                &owner,
                &fs.root(),
                "trunc.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let _ = trunc_entry;
        fs.write_at(&tr, b"keep-trunc-orig", WriteAt::Offset(0))
            .await
            .unwrap();
        sim.schedule_external_replace("trunc.txt", b"REPLACED_BEFORE_TRUNC");
        assert_eq!(fs.set_len(&tr, 0).await, Err(Errno::ESTALE));
        assert_eq!(
            sim.external_read("trunc.txt").as_deref(),
            Some(b"REPLACED_BEFORE_TRUNC".as_slice())
        );
        fs.release(&tr).await.unwrap();
    });
}

#[test]
fn directory_external_replacement_invalidates_handle_and_resets_descendants_across_remount() {
    let owner = user(10, 10, &[10], 0o022);
    let sim = SimProfile::new();

    let (shared_entry, sub_entry, child_entry, shared2_ino) = block_on(async {
        let fs = sim
            .mount_directory(1, grant(&owner, false, false), 1)
            .await
            .unwrap();
        let shared = fs.mkdir(&owner, &fs.root(), "shared", 0o755).await.unwrap();
        fs.setxattr(
            &owner,
            &shared.handle,
            "user.dir",
            b"secret-dir-tag",
            XattrFlags::empty(),
        )
        .await
        .unwrap();
        let sub = fs
            .mkdir(&owner, &shared.handle, "sub", 0o755)
            .await
            .unwrap();
        let (child, child_open) = fs
            .create(
                &owner,
                &sub.handle,
                "child.txt",
                0o644,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&child_open, b"hello", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&child_open).await.unwrap();

        let shared2 = fs
            .mkdir(&owner, &fs.root(), "shared2", 0o755)
            .await
            .unwrap();
        fs.setxattr(
            &owner,
            &shared2.handle,
            "user.dir2",
            b"secret-dir2-tag",
            XattrFlags::empty(),
        )
        .await
        .unwrap();
        (shared, sub, child, shared2.handle.node.ino)
    });

    // Replace both directories externally on the host OS.
    sim.external_remove("shared/sub/child.txt");
    sim.external_remove("shared/sub");
    sim.external_remove("shared");
    sim.external_mkdir("shared");
    sim.external_mkdir("shared/sub");
    sim.external_write("shared/sub/child.txt", b"replacement-child");

    sim.external_remove("shared2");
    sim.external_mkdir("shared2");

    block_on(async {
        // Tab 1 observes ESTALE on the replaced directory and cached descendants.
        let tab1 = sim
            .mount_directory(1, grant(&owner, false, false), 2)
            .await
            .unwrap();
        assert_eq!(
            tab1.metadata(&owner, &shared_entry.handle).await,
            Err(Errno::ESTALE)
        );
        assert_eq!(
            tab1.metadata(&owner, &sub_entry.handle).await,
            Err(Errno::ESTALE)
        );
        assert_eq!(
            tab1.metadata(&owner, &child_entry.handle).await,
            Err(Errno::ESTALE)
        );

        // Fresh remount resets replaced `shared2` cleanly even without checking it before unmount.
        let tab2 = sim
            .mount_directory(2, grant(&owner, false, false), 3)
            .await
            .unwrap();
        let fresh_shared2 = tab2.lookup(&owner, &tab2.root(), "shared2").await.unwrap();
        assert_ne!(fresh_shared2.handle.node.ino, shared2_ino);
        assert_eq!(fresh_shared2.metadata.mode, 0o700);
        assert!(!fresh_shared2.metadata.acl);
        assert_eq!(
            tab2.getxattr(&owner, &fresh_shared2.handle, "user.dir2")
                .await,
            Err(Errno::ENODATA)
        );
    });
}

#[test]
fn commit_failure_rolls_back_open_guard_created_files_and_truncations() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    block_on(async {
        let fs = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (f, o) = fs
            .create(
                &owner,
                &fs.root(),
                "keep.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&o, b"KEEP_ME", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&o).await.unwrap();

        // 1. Existing-file `open(O_TRUNC)` commit failure restores bytes, releases lock, and allows reopen!
        sim.set_commit_error(Some(Errno::EDQUOT));
        assert_eq!(
            fs.open(
                &owner,
                &f.handle,
                OpenOptions::new().read(true).write(true).truncate(true),
            )
            .await,
            Err(Errno::EDQUOT)
        );
        sim.set_commit_error(None);
        assert_eq!(sim.held_lock_count("os-fs-open:"), 0);
        assert_eq!(
            sim.external_read("keep.txt").as_deref(),
            Some(b"KEEP_ME".as_slice())
        );

        let reopened = fs
            .open(&owner, &f.handle, OpenOptions::new().read(true).write(true))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = fs.read_at(&reopened, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"KEEP_ME");
        fs.release(&reopened).await.unwrap();

        // 2. Existing-file `create(O_TRUNC)` commit failure also restores bytes and leaks no lock!
        sim.set_commit_error(Some(Errno::EDQUOT));
        assert_eq!(
            fs.create(
                &owner,
                &fs.root(),
                "keep.txt",
                0o600,
                OpenOptions::new().read(true).write(true).truncate(true),
            )
            .await
            .map(|_| ()),
            Err(Errno::EDQUOT)
        );
        sim.set_commit_error(None);
        assert_eq!(sim.held_lock_count("os-fs-open:"), 0);
        assert_eq!(
            sim.external_read("keep.txt").as_deref(),
            Some(b"KEEP_ME".as_slice())
        );

        // 3. New-file `create` commit failure removes stray disk file and leaks no Web Lock!
        sim.set_commit_error(Some(Errno::EDQUOT));
        assert_eq!(
            fs.create(
                &owner,
                &fs.root(),
                "stray.txt",
                0o600,
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .create_new(true),
            )
            .await
            .map(|_| ()),
            Err(Errno::EDQUOT)
        );
        sim.set_commit_error(None);
        assert_eq!(sim.held_lock_count("os-fs-open:"), 0);
        assert_eq!(sim.external_read("stray.txt"), None);

        let (_, o_retry) = fs
            .create(
                &owner,
                &fs.root(),
                "stray.txt",
                0o600,
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .create_new(true),
            )
            .await
            .unwrap();
        fs.release(&o_retry).await.unwrap();

        // 4. `mkdir` commit failure removes stray directory!
        sim.set_commit_error(Some(Errno::EDQUOT));
        assert_eq!(
            fs.mkdir(&owner, &fs.root(), "straydir", 0o755).await,
            Err(Errno::EDQUOT)
        );
        sim.set_commit_error(None);
        assert!(!sim.host_paths().contains(&"straydir".to_string()));
    });
}

#[test]
fn do_lock_arms_wakeup_before_releasing_lock_mutex_and_unblocks_without_fd_close() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    let (tab1, tab2, o1, o2) = block_on(async {
        let tab1 = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let tab2 = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();
        let (_, o1) = tab1
            .create(
                &owner,
                &tab1.root(),
                "wake",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let f2 = tab2.lookup(&owner, &tab2.root(), "wake").await.unwrap();
        let o2 = tab2
            .open(
                &owner,
                &f2.handle,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        (tab1, tab2, o1, o2)
    });

    block_on(tab1.try_lock(
        &o1,
        LockFamily::Flock,
        LockKind::Exclusive,
        LockRange::WHOLE,
    ))
    .unwrap();

    let mut wait2 = Box::pin(tab2.lock(
        &o2,
        LockFamily::Flock,
        LockKind::Exclusive,
        LockRange::WHOLE,
    ));
    assert!(poll_once(&mut wait2).is_pending());
    // Waiter has armed wakeup AND released `os-fs-lock` before suspending!
    assert_eq!(sim.held_lock_count("os-fs-lock:"), 0);

    // Unlock WITHOUT closing `o1` (`o1`'s `os-fs-open` lock remains held): `wait2` must wake!
    block_on(tab1.unlock(&o1, LockFamily::Flock, LockRange::WHOLE)).unwrap();
    assert_eq!(poll_once(&mut wait2), Poll::Ready(Ok(())));
    drop(wait2);
    let _ = tab2;
}

#[test]
fn opfs_replacement_rename_crash_and_rollback_preserve_open_destination() {
    let owner = user(1, 1, &[1], 0o022);

    // 1. Mid-rename final commit failure rolls back BOTH source move and open destination orphan!
    {
        let sim = SimProfile::new();
        let (fs, dst_ino, o_dst) = block_on(async {
            let fs = sim
                .mount_opfs(1, grant(&owner, false, true), 1)
                .await
                .unwrap();
            let (_, o_src) = fs
                .create(
                    &owner,
                    &fs.root(),
                    "src",
                    0o600,
                    OpenOptions::new().read(true).write(true),
                )
                .await
                .unwrap();
            let (dst, o_dst) = fs
                .create(
                    &owner,
                    &fs.root(),
                    "dst",
                    0o600,
                    OpenOptions::new().read(true).write(true),
                )
                .await
                .unwrap();
            fs.write_at(&o_src, b"NEW_SRC", WriteAt::Offset(0))
                .await
                .unwrap();
            fs.write_at(&o_dst, b"PRECIOUS_DST", WriteAt::Offset(0))
                .await
                .unwrap();
            fs.release(&o_src).await.unwrap();
            (fs, dst.handle.node.ino, o_dst)
        });

        // Commit 0 = `pending_rename` succeeds; commit 1 = final rename batch fails `EDQUOT`!
        sim.set_fail_commit_after(Some(1), Errno::EDQUOT);
        assert_eq!(
            block_on(fs.rename(
                &owner,
                &fs.root(),
                "src",
                &fs.root(),
                "dst",
                RenameFlags::empty(),
            )),
            Err(Errno::EDQUOT)
        );
        assert!(sim.orphan_ids().is_empty());
        assert_eq!(
            sim.external_read("src").as_deref(),
            Some(b"NEW_SRC".as_slice())
        );
        assert_eq!(
            sim.external_read("dst").as_deref(),
            Some(b"PRECIOUS_DST".as_slice())
        );
        assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
        let mut buf = [0u8; 16];
        let n = block_on(fs.read_at(&o_dst, &mut buf, 0)).unwrap();
        assert_eq!(&buf[..n], b"PRECIOUS_DST");
        assert_eq!(sim.raw_inode(dst_ino).unwrap().nlink, 1);
    }

    // 2. `restore_orphan` failure on rollback propagates error and keeps durable `pending_rename`
    // so the next mount's `sweep_orphans()` repairs `dst` without deleting `/os-orphans`!
    {
        let sim = SimProfile::new();
        let (fs, o_dst) = block_on(async {
            let fs = sim
                .mount_opfs(1, grant(&owner, false, true), 1)
                .await
                .unwrap();
            let (_, o_src) = fs
                .create(
                    &owner,
                    &fs.root(),
                    "src",
                    0o600,
                    OpenOptions::new().read(true).write(true),
                )
                .await
                .unwrap();
            let (_, o_dst) = fs
                .create(
                    &owner,
                    &fs.root(),
                    "dst",
                    0o600,
                    OpenOptions::new().read(true).write(true),
                )
                .await
                .unwrap();
            fs.write_at(&o_src, b"NEW_SRC", WriteAt::Offset(0))
                .await
                .unwrap();
            fs.write_at(&o_dst, b"PRECIOUS_DST", WriteAt::Offset(0))
                .await
                .unwrap();
            fs.release(&o_src).await.unwrap();
            (fs, o_dst)
        });

        sim.set_quota_exceeded(true);
        sim.set_restore_orphan_error(Some(Errno::EIO));
        assert_eq!(
            block_on(fs.rename(
                &owner,
                &fs.root(),
                "src",
                &fs.root(),
                "dst",
                RenameFlags::empty(),
            )),
            Err(Errno::EIO)
        );
        sim.set_quota_exceeded(false);
        sim.set_restore_orphan_error(None);
        drop(o_dst);
        drop(fs);
        sim.crash_tab(1);

        // Next mount sweeps and restores `dst` instead of deleting the orphan!
        let recovered = block_on(sim.mount_opfs(2, grant(&owner, false, true), 2)).unwrap();
        assert!(sim.orphan_ids().is_empty());
        assert_eq!(
            sim.external_read("dst").as_deref(),
            Some(b"PRECIOUS_DST".as_slice())
        );
        assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
        let dst_e = block_on(recovered.lookup(&owner, &recovered.root(), "dst")).unwrap();
        let o2 =
            block_on(recovered.open(&owner, &dst_e.handle, OpenOptions::new().read(true))).unwrap();
        let mut buf = [0u8; 16];
        let n = block_on(recovered.read_at(&o2, &mut buf, 0)).unwrap();
        assert_eq!(&buf[..n], b"PRECIOUS_DST");
    }

    // 3. Even WITHOUT `pending_rename`, an orphan file whose inode record still shows `nlink > 0`
    // is never deleted by `sweep_orphans()`.
    {
        let sim = SimProfile::new();
        let dst_ino = block_on(async {
            let fs = sim
                .mount_opfs(1, grant(&owner, false, true), 1)
                .await
                .unwrap();
            let (dst, o_dst) = fs
                .create(
                    &owner,
                    &fs.root(),
                    "live",
                    0o600,
                    OpenOptions::new().read(true).write(true),
                )
                .await
                .unwrap();
            fs.write_at(&o_dst, b"KEEP_LIVE", WriteAt::Offset(0))
                .await
                .unwrap();
            fs.release(&o_dst).await.unwrap();
            dst.handle.node.ino
        });
        sim.put_external_orphan(dst_ino, b"STAGED_COPY");
        let _remount = block_on(sim.mount_opfs(2, grant(&owner, false, true), 2)).unwrap();
        assert_eq!(sim.orphan_ids(), vec![dst_ino]);
    }
}

#[test]
fn same_inode_rename_checks_rofs_and_may_delete_before_noop() {
    let owner = user(1, 1, &[1], 0o022);
    let bob = user(2, 2, &[2], 0o022);
    let sim = SimProfile::new();

    block_on(async {
        let rw = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let d = rw.mkdir(&owner, &rw.root(), "d", 0o755).await.unwrap();
        let (a, o) = rw
            .create(
                &owner,
                &d.handle,
                "a",
                0o644,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        rw.release(&o).await.unwrap();
        rw.link(&owner, &a.handle, &d.handle, "b").await.unwrap();

        // Non-owner (`bob`) lacks write on `d` (0o755) -> EACCES on same-name AND hardlink rename!
        assert_eq!(
            rw.rename(&bob, &d.handle, "a", &d.handle, "a", RenameFlags::empty())
                .await,
            Err(Errno::EACCES)
        );
        assert_eq!(
            rw.rename(&bob, &d.handle, "a", &d.handle, "b", RenameFlags::empty())
                .await,
            Err(Errno::EACCES)
        );
        // Owner can no-op rename("a", "a") and gets EEXIST for RENAME_NOREPLACE on hardlink "b".
        rw.rename(&owner, &d.handle, "a", &d.handle, "a", RenameFlags::empty())
            .await
            .unwrap();
        assert_eq!(
            rw.rename(
                &owner,
                &d.handle,
                "a",
                &d.handle,
                "b",
                RenameFlags::NOREPLACE
            )
            .await,
            Err(Errno::EEXIST)
        );

        // Read-only grant fails closed with EROFS on same-name and hardlink rename!
        let ro = sim
            .mount_opfs(2, grant(&owner, true, false), 2)
            .await
            .unwrap();
        let ro_d = ro.lookup(&owner, &ro.root(), "d").await.unwrap();
        assert_eq!(
            ro.rename(
                &owner,
                &ro_d.handle,
                "a",
                &ro_d.handle,
                "a",
                RenameFlags::empty(),
            )
            .await,
            Err(Errno::EROFS)
        );
        assert_eq!(
            ro.rename(
                &owner,
                &ro_d.handle,
                "a",
                &ro_d.handle,
                "b",
                RenameFlags::empty(),
            )
            .await,
            Err(Errno::EROFS)
        );
    });
}

#[test]
fn hostfs_fails_closed_on_enolck_and_does_not_delete_open_backing() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    block_on(async {
        let locks1 = sim.locks_handle(1);
        let locks2 = sim.locks_handle(2);
        let tab1 = HostFs::opfs(
            grant(&owner, false, true),
            1,
            sim.tree_handle(),
            sim.meta_handle(),
            locks1.clone(),
            sim.clock(),
        )
        .await
        .unwrap();
        let tab2 = HostFs::opfs(
            grant(&owner, false, true),
            2,
            sim.tree_handle(),
            sim.meta_handle(),
            locks2.clone(),
            sim.clock(),
        )
        .await
        .unwrap();

        let (_, o1) = tab1
            .create(
                &owner,
                &tab1.root(),
                "protected.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        tab1.write_at(&o1, b"MUST_SURVIVE", WriteAt::Offset(0))
            .await
            .unwrap();

        // Losing Web Locks mid-session must fail namespace mutations & opens with ENOLCK,
        // NOT bypass mutual exclusion or delete open backing data!
        locks2.set_unavailable(true);
        assert_eq!(
            tab2.create(
                &owner,
                &tab2.root(),
                "excl.txt",
                0o600,
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .create_new(true),
            )
            .await
            .map(|_| ()),
            Err(Errno::ENOLCK)
        );
        assert_eq!(
            tab2.unlink(&owner, &tab2.root(), "protected.txt").await,
            Err(Errno::ENOLCK)
        );
        assert_eq!(
            sim.external_read("protected.txt").as_deref(),
            Some(b"MUST_SURVIVE".as_slice())
        );

        let mut buf = [0u8; 16];
        let n = tab1.read_at(&o1, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"MUST_SURVIVE");

        locks1.set_unavailable(true);
        assert_eq!(tab1.release(&o1).await, Err(Errno::ENOLCK));
        // Even on ENOLCK release, the local open guard was still retired cleanly.
        assert_eq!(sim.held_lock_count("os-fs-open:"), 0);
    });
}

#[test]
fn codex1_pending_rename_recovery_preserves_intact_destination_across_partial_or_repeated_recovery()
{
    let owner = user(1, 1, &[1], 0o022);

    // 1. Crash after committing `pending_rename` BEFORE `move_to_orphan` / `move_entry`,
    // or repeated recovery after `restore_orphan` already deleted the orphan:
    // `to_path` has no backup elsewhere and must NEVER be deleted!
    {
        let sim = SimProfile::new();
        let dst_ino = block_on(async {
            let fs = sim
                .mount_opfs(1, grant(&owner, false, true), 1)
                .await
                .unwrap();
            let (_, o_src) = fs
                .create(
                    &owner,
                    &fs.root(),
                    "src",
                    0o600,
                    OpenOptions::new().read(true).write(true),
                )
                .await
                .unwrap();
            let (dst, o_dst) = fs
                .create(
                    &owner,
                    &fs.root(),
                    "dst",
                    0o600,
                    OpenOptions::new().read(true).write(true),
                )
                .await
                .unwrap();
            fs.write_at(&o_src, b"NEW_SRC", WriteAt::Offset(0))
                .await
                .unwrap();
            fs.write_at(&o_dst, b"PRECIOUS_DST", WriteAt::Offset(0))
                .await
                .unwrap();
            fs.release(&o_src).await.unwrap();
            fs.release(&o_dst).await.unwrap();
            dst.handle.node.ino
        });

        let mut header = sim.raw_header().unwrap();
        header.pending_rename = Some(PendingRename {
            from_path: "src".into(),
            to_path: "dst".into(),
            is_dir: false,
            source_has_path: true,
            staged_target_ino: Some(dst_ino),
            staged_other_path: None,
            removed_empty_dir: false,
        });
        sim.set_raw_header(header);
        sim.crash_tab(1);

        let tab2 = block_on(sim.mount_opfs(2, grant(&owner, false, true), 2)).unwrap();
        assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
        assert_eq!(
            sim.external_read("src").as_deref(),
            Some(b"NEW_SRC".as_slice())
        );
        assert_eq!(
            sim.external_read("dst").as_deref(),
            Some(b"PRECIOUS_DST".as_slice())
        );
        let dst_e = block_on(tab2.lookup(&owner, &tab2.root(), "dst")).unwrap();
        let o2 = block_on(tab2.open(&owner, &dst_e.handle, OpenOptions::new().read(true))).unwrap();
        let mut buf = [0u8; 16];
        let n = block_on(tab2.read_at(&o2, &mut buf, 0)).unwrap();
        assert_eq!(&buf[..n], b"PRECIOUS_DST");
        block_on(tab2.release(&o2)).unwrap();

        // Also test non-backing source (`source_has_path: false`) where orphan was already restored
        // before `pending_rename` cleared: `dst` must survive untouched.
        let mut h2 = sim.raw_header().unwrap();
        h2.pending_rename = Some(PendingRename {
            from_path: "h2".into(),
            to_path: "dst".into(),
            is_dir: false,
            source_has_path: false,
            staged_target_ino: Some(dst_ino),
            staged_other_path: None,
            removed_empty_dir: false,
        });
        sim.set_raw_header(h2);
        drop(tab2);
        sim.crash_tab(2);

        let _tab3 = block_on(sim.mount_opfs(3, grant(&owner, false, true), 3)).unwrap();
        assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
        assert_eq!(
            sim.external_read("dst").as_deref(),
            Some(b"PRECIOUS_DST".as_slice())
        );
    }
}

#[test]
fn codex2_and_3_closed_dst_and_non_backing_source_preserve_dst_on_commit_failure() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    block_on(async {
        let fs = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (_, o_src) = fs
            .create(
                &owner,
                &fs.root(),
                "src",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let (_, o_dst) = fs
            .create(
                &owner,
                &fs.root(),
                "dst",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&o_src, b"NEW_SRC", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.write_at(&o_dst, b"PRECIOUS_DST", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&o_src).await.unwrap();
        fs.release(&o_dst).await.unwrap();

        // Codex #2: Closed single-link `dst` is staged in `/os-orphans` and restored on commit failure.
        sim.set_fail_commit_after(Some(1), Errno::EDQUOT);
        assert_eq!(
            fs.rename(
                &owner,
                &fs.root(),
                "src",
                &fs.root(),
                "dst",
                RenameFlags::empty(),
            )
            .await,
            Err(Errno::EDQUOT)
        );
        assert!(sim.orphan_ids().is_empty());
        assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
        assert_eq!(
            sim.external_read("src").as_deref(),
            Some(b"NEW_SRC".as_slice())
        );
        assert_eq!(
            sim.external_read("dst").as_deref(),
            Some(b"PRECIOUS_DST".as_slice())
        );

        // Codex #3a: Non-backing 2nd hardlink `h2` (`!source_has_path`) replacing closed `dst`.
        let (h1, o_h1) = fs
            .create(
                &owner,
                &fs.root(),
                "h1",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&o_h1, b"LINK_DATA", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&o_h1).await.unwrap();
        fs.link(&owner, &h1.handle, &fs.root(), "h2").await.unwrap();

        sim.set_fail_commit_after(Some(1), Errno::EDQUOT);
        assert_eq!(
            fs.rename(
                &owner,
                &fs.root(),
                "h2",
                &fs.root(),
                "dst",
                RenameFlags::empty(),
            )
            .await,
            Err(Errno::EDQUOT)
        );
        assert!(sim.orphan_ids().is_empty());
        assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
        assert_eq!(
            sim.external_read("dst").as_deref(),
            Some(b"PRECIOUS_DST".as_slice())
        );
        let dst_e = fs.lookup(&owner, &fs.root(), "dst").await.unwrap();
        let o2 = fs
            .open(&owner, &dst_e.handle, OpenOptions::new().read(true))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = fs.read_at(&o2, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"PRECIOUS_DST");
        fs.release(&o2).await.unwrap();
        assert_eq!(
            fs.lookup(&owner, &fs.root(), "h2")
                .await
                .unwrap()
                .handle
                .node
                .ino,
            h1.handle.node.ino
        );

        // Codex #3b: Non-backing symlink `sym` replacing closed `dst`.
        fs.symlink(&owner, &fs.root(), "sym", "h1").await.unwrap();
        sim.set_fail_commit_after(Some(1), Errno::EDQUOT);
        assert_eq!(
            fs.rename(
                &owner,
                &fs.root(),
                "sym",
                &fs.root(),
                "dst",
                RenameFlags::empty(),
            )
            .await,
            Err(Errno::EDQUOT)
        );
        assert!(sim.orphan_ids().is_empty());
        assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
        assert_eq!(
            sim.external_read("dst").as_deref(),
            Some(b"PRECIOUS_DST".as_slice())
        );
        let sym_e = fs.lookup(&owner, &fs.root(), "sym").await.unwrap();
        assert_eq!(sym_e.metadata.file_type, FileType::Symlink);
        assert_eq!(fs.read_link(&owner, &sym_e.handle).await.unwrap(), "h1");
    });
}

#[test]
fn codex4_already_mounted_surviving_tab_recovers_pending_rename_before_ops() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    let (tab1, tab2) = block_on(async {
        let tab1 = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let tab2 = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();
        let (_, o_src) = tab1
            .create(
                &owner,
                &tab1.root(),
                "src",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        let (_, o_dst) = tab1
            .create(
                &owner,
                &tab1.root(),
                "dst",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        tab1.write_at(&o_src, b"NEW_SRC", WriteAt::Offset(0))
            .await
            .unwrap();
        tab1.write_at(&o_dst, b"PRECIOUS_DST", WriteAt::Offset(0))
            .await
            .unwrap();
        tab1.release(&o_src).await.unwrap();
        tab1.release(&o_dst).await.unwrap();
        (tab1, tab2)
    });

    // Fail `tab1`'s final commit AND rollback `restore_orphan`, leaving `pending_rename` active
    // while `dst` sits orphaned and `tab2` is already mounted.
    sim.set_fail_commit_after(Some(1), Errno::EDQUOT);
    sim.set_restore_orphan_error(Some(Errno::EIO));
    assert_eq!(
        block_on(tab1.rename(
            &owner,
            &tab1.root(),
            "src",
            &tab1.root(),
            "dst",
            RenameFlags::empty(),
        )),
        Err(Errno::EIO)
    );
    drop(tab1);
    sim.crash_tab(1);
    sim.set_restore_orphan_error(None);
    assert!(sim.raw_header().and_then(|h| h.pending_rename).is_some());
    assert_eq!(sim.external_read("dst"), None);

    // Surviving `tab2` executes an ordinary op without remounting -> `ns_lock` recovers first!
    block_on(async {
        let dst_e = tab2.lookup(&owner, &tab2.root(), "dst").await.unwrap();
        let o2 = tab2
            .open(&owner, &dst_e.handle, OpenOptions::new().read(true))
            .await
            .unwrap();
        let mut buf = [0u8; 16];
        let n = tab2.read_at(&o2, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"PRECIOUS_DST");
        tab2.release(&o2).await.unwrap();
    });
    assert!(sim.orphan_ids().is_empty());
    assert!(sim.raw_header().and_then(|h| h.pending_rename).is_none());
    assert_eq!(
        sim.external_read("src").as_deref(),
        Some(b"NEW_SRC".as_slice())
    );
    assert_eq!(
        sim.external_read("dst").as_deref(),
        Some(b"PRECIOUS_DST".as_slice())
    );
}

#[test]
fn codex5_large_17mib_otrunc_commit_failure_does_not_truncate_host_bytes() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();
    let offset_17m = 17 * 1024 * 1024u64;

    block_on(async {
        let fs = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (big, o) = fs
            .create(
                &owner,
                &fs.root(),
                "big.bin",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&o, b"BIG_HEADER_17M", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.write_at(&o, b"BIG_TAIL", WriteAt::Offset(offset_17m))
            .await
            .unwrap();
        fs.release(&o).await.unwrap();

        sim.set_commit_error(Some(Errno::EDQUOT));
        assert_eq!(
            fs.open(
                &owner,
                &big.handle,
                OpenOptions::new().read(true).write(true).truncate(true),
            )
            .await,
            Err(Errno::EDQUOT)
        );
        assert_eq!(
            fs.create(
                &owner,
                &fs.root(),
                "big.bin",
                0o600,
                OpenOptions::new()
                    .create(true)
                    .read(true)
                    .write(true)
                    .truncate(true),
            )
            .await
            .map(|_| ()),
            Err(Errno::EDQUOT)
        );
        sim.set_commit_error(None);
        assert_eq!(sim.held_lock_count("os-fs-open:"), 0);

        let bytes = sim.external_read("big.bin").unwrap();
        assert_eq!(bytes.len(), offset_17m as usize + 8);
        assert_eq!(&bytes[..14], b"BIG_HEADER_17M");
        assert_eq!(&bytes[offset_17m as usize..], b"BIG_TAIL");
    });
}

#[test]
fn codex7_directory_otrunc_second_commit_failure_restores_bytes_and_keeps_fp_live() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    block_on(async {
        let fs = sim
            .mount_directory(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (doc, o_init) = fs
            .create(
                &owner,
                &fs.root(),
                "doc.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&o_init, b"ORIGINAL_BYTES", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&o_init).await.unwrap();
        fs.setxattr(
            &owner,
            &doc.handle,
            "user.tag",
            b"keep",
            XattrFlags::empty(),
        )
        .await
        .unwrap();

        let o_keep = fs
            .open(&owner, &doc.handle, OpenOptions::new().read(true))
            .await
            .unwrap();

        // Commit 0 = pre-truncate metadata + open_id; Commit 1 = post-truncate fingerprint commit -> fail!
        sim.set_fail_commit_after(Some(1), Errno::EDQUOT);
        assert_eq!(
            fs.open(
                &owner,
                &doc.handle,
                OpenOptions::new().read(true).write(true).truncate(true),
            )
            .await,
            Err(Errno::EDQUOT)
        );

        assert_eq!(
            sim.external_read("doc.txt").as_deref(),
            Some(b"ORIGINAL_BYTES".as_slice())
        );
        // Existing handle & xattrs must remain live (updated fingerprint recorded during rollback, NOT ESTALE).
        let mut buf = [0u8; 32];
        let n = fs.read_at(&o_keep, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"ORIGINAL_BYTES");
        assert_eq!(
            fs.getxattr(&owner, &doc.handle, "user.tag").await.unwrap(),
            b"keep"
        );
        fs.release(&o_keep).await.unwrap();
        assert_eq!(sim.held_lock_count("os-fs-open:"), 0);
    });
}

#[test]
fn pending_truncate_recovery_reconciles_size_and_appends_cleanly() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    let ino = block_on(async {
        let fs = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let (f, o) = fs
            .create(
                &owner,
                &fs.root(),
                "trunc.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        fs.write_at(&o, b"OLD_SECRET_BYTES", WriteAt::Offset(0))
            .await
            .unwrap();
        fs.release(&o).await.unwrap();
        f.handle.node.ino
    });

    // Simulate crash right after Commit 0 recorded `pending_truncate` before `set_file_len(0)`:
    let mut header = sim.raw_header().unwrap();
    header.pending_truncate = Some(PendingTruncate {
        ino,
        backing: Backing::Path("trunc.txt".into()),
        target_mode: sim.raw_inode(ino).unwrap().meta.mode,
    });
    sim.set_raw_header(header);
    sim.crash_tab(1);

    block_on(async {
        let tab2 = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();
        // O_APPEND after crash recovery must see size 0 (NOT append past stale bytes!).
        let f2 = tab2
            .lookup(&owner, &tab2.root(), "trunc.txt")
            .await
            .unwrap();
        assert_eq!(f2.metadata.size, 0);
        assert_eq!(
            sim.external_read("trunc.txt").as_deref(),
            Some(b"".as_slice())
        );
        assert!(sim.raw_header().and_then(|h| h.pending_truncate).is_none());

        let o_app = tab2
            .open(
                &owner,
                &f2.handle,
                OpenOptions::new().read(true).write(true).append(true),
            )
            .await
            .unwrap();
        tab2.write_at(&o_app, b"NEW", WriteAt::End).await.unwrap();
        let mut buf = [0u8; 32];
        let n = tab2.read_at(&o_app, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"NEW");
        tab2.release(&o_app).await.unwrap();
    });
}

#[test]
fn interrupted_opfs_open_unlink_repairs_live_backing_despite_surviving_open_fd() {
    let owner = user(1, 1, &[1], 0o022);
    let sim = SimProfile::new();

    let (tab2, o2, live_ino) = block_on(async {
        let tab1 = sim
            .mount_opfs(1, grant(&owner, false, true), 1)
            .await
            .unwrap();
        let tab2 = sim
            .mount_opfs(2, grant(&owner, false, true), 2)
            .await
            .unwrap();
        let (f, o1) = tab1
            .create(
                &owner,
                &tab1.root(),
                "live.txt",
                0o600,
                OpenOptions::new().read(true).write(true),
            )
            .await
            .unwrap();
        tab1.write_at(&o1, b"IMPORTANT_DATA", WriteAt::Offset(0))
            .await
            .unwrap();
        tab1.release(&o1).await.unwrap();
        let f2 = tab2.lookup(&owner, &tab2.root(), "live.txt").await.unwrap();
        let o2 = tab2
            .open(&owner, &f2.handle, OpenOptions::new().read(true))
            .await
            .unwrap();

        // 1. Synchronous unlink commit failure rolls back the orphan back to `live.txt`.
        sim.set_commit_error(Some(Errno::EDQUOT));
        assert_eq!(
            tab1.unlink(&owner, &tab1.root(), "live.txt").await,
            Err(Errno::EDQUOT)
        );
        sim.set_commit_error(None);
        assert_eq!(
            sim.external_read("live.txt").as_deref(),
            Some(b"IMPORTANT_DATA".as_slice())
        );
        assert!(sim.orphan_ids().is_empty());

        (tab2, o2, f.handle.node.ino)
    });

    // 2. Crash leaving `live.txt` evacuated into `/os-orphans` while metadata still shows nlink==1
    // AND `tab2` still holds open descriptor `o2`: both `resolve_child` AND `sweep_orphans` must
    // restore `live.txt` (never delete the live inode or lose data)!
    sim.external_remove("live.txt");
    sim.put_external_orphan(live_ino, b"IMPORTANT_DATA");
    sim.crash_tab(1);

    block_on(async {
        // `tab2.lookup` repairs via `resolve_child` instead of pruning `live.txt`:
        let repaired = tab2.lookup(&owner, &tab2.root(), "live.txt").await.unwrap();
        assert_eq!(repaired.handle.node.ino, live_ino);
        assert_eq!(
            sim.external_read("live.txt").as_deref(),
            Some(b"IMPORTANT_DATA".as_slice())
        );

        // Now repeat crash state and verify `sweep_orphans` on Tab 3 ALSO restores despite `o2`:
        sim.external_remove("live.txt");
        sim.put_external_orphan(live_ino, b"IMPORTANT_DATA");
        let tab3 = sim
            .mount_opfs(3, grant(&owner, false, true), 3)
            .await
            .unwrap();
        assert_eq!(
            sim.external_read("live.txt").as_deref(),
            Some(b"IMPORTANT_DATA".as_slice())
        );
        assert!(sim.orphan_ids().is_empty());

        let mut buf = [0u8; 32];
        let n = tab2.read_at(&o2, &mut buf, 0).await.unwrap();
        assert_eq!(&buf[..n], b"IMPORTANT_DATA");
        tab2.release(&o2).await.unwrap();
        let _ = tab3;
    });
}
