use super::fs::HelperEngine;
use super::open_root_dir;
use super::store::{STATE_FORMAT_VERSION, StateStore, validate_state_dir_outside_root};
use abi::contract::{Boundary, Hello};
use abi::fs::{
    Conflict, DirEntry, Entry, FileType, Handle, JS_SAFE, LockFamily, LockKind, LockRange,
    Metadata, OpenOptions, OpenRef, RenameFlags, SetAttr, Walked, WriteAt, XattrFlags,
};
use abi::local_helper::{
    AttachReply, Call, HelloReply, HelperGrant, LEASE_SECONDS, LockOutcome, ReadReply, RenewReply,
    Request, VERSION, WireCred,
};
use abi::{ACL_ACCESS, ACL_DEFAULT, Errno};
use os_core::acl::Entries as AclEntries;
use os_core::permissions::SETGID;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions as StdOpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(1);

fn ticket() -> String {
    format!("unit-ticket-{}", TEMP_SEQ.fetch_add(1, Ordering::Relaxed))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "os-local-helper-test-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn opts_read() -> OpenOptions {
    *OpenOptions::new().read(true)
}

fn opts_exec() -> OpenOptions {
    *OpenOptions::new().exec(true)
}

fn opts_path() -> OpenOptions {
    *OpenOptions::new().path(true)
}

fn opts_create_w_excl() -> OpenOptions {
    *OpenOptions::new().write(true).create(true).create_new(true)
}

fn opts_create_rw_excl() -> OpenOptions {
    *OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .create_new(true)
}

fn opts_rw() -> OpenOptions {
    *OpenOptions::new().read(true).write(true)
}

fn opts_w() -> OpenOptions {
    *OpenOptions::new().write(true)
}

fn cred(id: u32, group: u32, groups: Vec<u32>, umask: u16) -> WireCred {
    WireCred {
        id,
        group,
        groups,
        umask,
    }
}

fn open_engine(root: &Path, state: &Path, write: bool, execute: bool) -> HelperEngine {
    let root_fd = open_root_dir(root).unwrap();
    HelperEngine::open(root, state, root_fd, write, execute).unwrap()
}

fn attach(
    engine: &mut HelperEngine,
    client_id: &str,
    who: &WireCred,
    write: bool,
    execute: bool,
) -> AttachReply {
    let hello: HelloReply = serde_json::from_value(
        engine
            .handle_request(Request::Hello(Hello {
                boundary: Boundary::LocalHelper,
                versions: vec![VERSION],
            }))
            .unwrap(),
    )
    .unwrap();
    let raw = engine
        .handle_request(Request::Attach {
            version: VERSION,
            client_id: client_id.to_owned(),
            handshake: hello.handshake,
            cred: who.clone(),
            grant: HelperGrant { write, execute },
        })
        .unwrap();
    serde_json::from_value(raw).unwrap()
}

fn call<T: DeserializeOwned>(
    engine: &mut HelperEngine,
    session: &str,
    who: &WireCred,
    call: Call,
) -> Result<T, Errno> {
    let val = engine.handle_request(Request::Call {
        version: VERSION,
        session: session.to_owned(),
        cred: who.clone(),
        call,
    })?;
    Ok(serde_json::from_value(val).unwrap())
}

fn call_unit(
    engine: &mut HelperEngine,
    session: &str,
    who: &WireCred,
    req: Call,
) -> Result<(), Errno> {
    let _val = engine.handle_request(Request::Call {
        version: VERSION,
        session: session.to_owned(),
        cred: who.clone(),
        call: req,
    })?;
    Ok(())
}

#[test]
fn state_dir_confinement_and_no_sidecar_in_root() {
    let tmp = TempDir::new("confinement");
    let root = tmp.path().join("root");
    let nested = root.join("nested-state");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&nested).unwrap();

    let canonical_root = fs::canonicalize(&root).unwrap();
    assert!(validate_state_dir_outside_root(&canonical_root, &root).is_err());
    assert!(validate_state_dir_outside_root(&canonical_root, &nested).is_err());

    let symlink_state = tmp.path().join("link-into-root");
    std::os::unix::fs::symlink(&nested, &symlink_state).unwrap();
    assert!(validate_state_dir_outside_root(&canonical_root, &symlink_state).is_err());

    let empty_root = tmp.path().join("empty-root");
    fs::create_dir_all(&empty_root).unwrap();
    let _engine = open_engine(&empty_root, &state, true, true);
    assert_eq!(fs::read_dir(&empty_root).unwrap().count(), 0);
    assert!(state.join("folders").exists());
}

#[test]
fn persistent_uuid_ino_metadata_across_remount() {
    let tmp = TempDir::new("remount");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    let owner = cred(1000, 1000, vec![1000], 0o022);

    let (fs_id, root_handle, file_handle, file_ino);
    {
        let mut engine = open_engine(&root, &state, true, true);
        let att = attach(&mut engine, "tab-1", &owner, true, true);
        fs_id = att.fs;
        assert!(fs_id.0.starts_with("helperfs:"));
        assert!(fs_id.dev() <= JS_SAFE);
        root_handle = att.root;

        let (entry, open): (Entry, OpenRef) = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Create {
                ticket: ticket(),
                dir: root_handle.clone(),
                name: "secret.txt".into(),
                mode: 0o640,
                options: opts_create_w_excl(),
            },
        )
        .unwrap();
        file_handle = entry.handle.clone();
        file_ino = file_handle.node.ino;
        assert!(file_ino <= JS_SAFE);
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::WriteAt {
                open: open.clone(),
                data: abi::Bytes(b"persistent".to_vec()),
                at: WriteAt::Offset(0),
            },
        )
        .unwrap();
        call_unit(&mut engine, &att.session, &owner, Call::Release { open }).unwrap();

        let mut users = BTreeMap::new();
        users.insert(2002, 4);
        let acl = AclEntries {
            user: 6,
            group: 0,
            other: 0,
            mask: Some(4),
            users,
            groups: BTreeMap::new(),
        };
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Setxattr {
                handle: file_handle.clone(),
                name: ACL_ACCESS.into(),
                value: abi::Bytes(serde_json::to_vec(&acl).unwrap()),
                flags: XattrFlags::empty(),
            },
        )
        .unwrap();
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Setxattr {
                handle: file_handle.clone(),
                name: "user.note".into(),
                value: abi::Bytes(b"kept".to_vec()),
                flags: XattrFlags::CREATE,
            },
        )
        .unwrap();
    }

    // Reopen fresh helper instance pointing at same root + state dir.
    let mut engine2 = open_engine(&root, &state, true, true);
    let att2 = attach(&mut engine2, "tab-2", &owner, true, true);
    assert_eq!(att2.fs, fs_id);
    assert_eq!(att2.root, root_handle);

    let looked: Entry = call(
        &mut engine2,
        &att2.session,
        &owner,
        Call::Lookup {
            dir: att2.root.clone(),
            name: "secret.txt".into(),
        },
    )
    .unwrap();
    assert_eq!(looked.handle.node.ino, file_ino);
    assert_eq!(looked.handle, file_handle);

    let meta: Metadata = call(
        &mut engine2,
        &att2.session,
        &owner,
        Call::Metadata {
            handle: looked.handle.clone(),
        },
    )
    .unwrap();
    assert!(meta.acl);
    assert_eq!(meta.uid, 1000);
    assert_eq!(meta.size, 10);

    let reader_allowed = cred(2002, 2002, vec![2002], 0o022);
    let att_acl = attach(&mut engine2, "tab-acl", &reader_allowed, false, false);
    let open_acl: OpenRef = call(
        &mut engine2,
        &att_acl.session,
        &reader_allowed,
        Call::Open {
            ticket: ticket(),
            handle: looked.handle.clone(),
            options: opts_read(),
        },
    )
    .unwrap();
    let read_back: ReadReply = call(
        &mut engine2,
        &att_acl.session,
        &reader_allowed,
        Call::ReadAt {
            open: open_acl,
            offset: 0,
            count: 64,
        },
    )
    .unwrap();
    assert_eq!(read_back.data.0, b"persistent");

    let note: abi::Bytes = call(
        &mut engine2,
        &att2.session,
        &owner,
        Call::Getxattr {
            handle: looked.handle,
            name: "user.note".into(),
        },
    )
    .unwrap();
    assert_eq!(note.0, b"kept");
}

#[test]
fn state_format_version_enforced_without_migration() {
    let tmp = TempDir::new("format-ver");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("host-file.txt"), b"untouched host bytes").unwrap();

    let state_file = {
        let engine = open_engine(&root, &state, true, true);
        engine.state_file_path().to_path_buf()
    };

    // Older format_version (1): resets metadata once without touching host files.
    let mut raw: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    let old_uuid = raw["folder_uuid"].as_str().unwrap().to_owned();
    raw["format_version"] = serde_json::json!(STATE_FORMAT_VERSION - 1);
    fs::write(&state_file, serde_json::to_vec_pretty(&raw).unwrap()).unwrap();

    {
        let engine = open_engine(&root, &state, true, true);
        assert_ne!(engine.fs_id().0, format!("helperfs:{old_uuid}"));
        assert_eq!(
            fs::read(root.join("host-file.txt")).unwrap(),
            b"untouched host bytes"
        );
    }

    // Newer format_version: refused with EPROTONOSUPPORT.
    let mut newer: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
    newer["format_version"] = serde_json::json!(STATE_FORMAT_VERSION + 1);
    fs::write(&state_file, serde_json::to_vec_pretty(&newer).unwrap()).unwrap();

    let root_fd = open_root_dir(&root).unwrap();
    let err = HelperEngine::open(&root, &state, root_fd, true, true)
        .err()
        .unwrap();
    assert_eq!(err, Errno::EPROTONOSUPPORT);
}

#[test]
fn external_file_replacement_resets_metadata_and_generation() {
    let tmp = TempDir::new("external-replace");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let owner = cred(1000, 1000, vec![1000], 0o022);
    let other = cred(3000, 3000, vec![3000], 0o022);

    let mut engine = open_engine(&root, &state, true, true);
    let att_owner = attach(&mut engine, "tab-owner", &owner, true, true);
    let att_other = attach(&mut engine, "tab-other", &other, true, true);
    call_unit(
        &mut engine,
        &att_owner.session,
        &owner,
        Call::Setattr {
            handle: att_owner.root.clone(),
            attr: SetAttr {
                mode: Some(0o755),
                ..Default::default()
            },
        },
    )
    .unwrap();

    let (entry1, open1): (Entry, OpenRef) = call(
        &mut engine,
        &att_owner.session,
        &owner,
        Call::Create {
            ticket: ticket(),
            dir: att_owner.root.clone(),
            name: "swap.txt".into(),
            mode: 0o644,
            options: opts_create_w_excl(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att_owner.session,
        &owner,
        Call::Release { open: open1 },
    )
    .unwrap();

    // Grant xattr so we prove external replacement wipes stale grants too.
    call_unit(
        &mut engine,
        &att_owner.session,
        &owner,
        Call::Setxattr {
            handle: entry1.handle.clone(),
            name: "user.grant".into(),
            value: abi::Bytes(b"sensitive".to_vec()),
            flags: XattrFlags::CREATE,
        },
    )
    .unwrap();

    // Replace file externally outside OS.
    fs::remove_file(root.join("swap.txt")).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    fs::write(root.join("swap.txt"), b"external data").unwrap();

    // Stale handle minted before replacement must fail with ESTALE.
    let stale_err = call::<Metadata>(
        &mut engine,
        &att_owner.session,
        &owner,
        Call::Metadata {
            handle: entry1.handle.clone(),
        },
    )
    .unwrap_err();
    assert_eq!(stale_err, Errno::ESTALE);

    // Re-lookup discovers new identity, attaches current session account owner with private 0600,
    // no ACL, and no stale xattrs.
    let entry2: Entry = call(
        &mut engine,
        &att_other.session,
        &other,
        Call::Lookup {
            dir: att_other.root.clone(),
            name: "swap.txt".into(),
        },
    )
    .unwrap();
    assert_ne!(entry2.handle, entry1.handle);
    let meta2: Metadata = call(
        &mut engine,
        &att_other.session,
        &other,
        Call::Metadata {
            handle: entry2.handle.clone(),
        },
    )
    .unwrap();
    assert_eq!(meta2.uid, 3000);
    assert_eq!(meta2.mode, 0o600);
    assert!(!meta2.acl);
    let xerr = call::<abi::Bytes>(
        &mut engine,
        &att_other.session,
        &other,
        Call::Getxattr {
            handle: entry2.handle,
            name: "user.grant".into(),
        },
    )
    .unwrap_err();
    assert_eq!(xerr, Errno::ENODATA);
}

#[test]
fn subfs_relpath_distinguishes_subfilesystem_boundaries() {
    use super::store::HostInodeKey;
    use super::sys::{HostGen, HostKind};
    use os_core::permissions::Node;

    let tmp = TempDir::new("subfs");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let root_fd = open_root_dir(&root).unwrap();
    let root_stx = super::sys::statx_fd(std::os::fd::AsFd::as_fd(&root_fd)).unwrap();
    let root_key = HostInodeKey::from_root(std::os::fd::AsFd::as_fd(&root_fd), &root_stx).unwrap();

    let key_a = HostInodeKey {
        subfs_relpath: String::new(),
        subvol: None,
        subfs_fsuuid: None,
        host_ino: 4242,
        host_gen: HostGen::IocVersion(7),
        kind: HostKind::File,
    };
    let key_b = HostInodeKey {
        subfs_relpath: "snapshot-1".into(),
        subvol: None,
        subfs_fsuuid: None,
        host_ino: 4242,
        host_gen: HostGen::IocVersion(7),
        kind: HostKind::File,
    };

    let (ino_a, ino_b) = {
        let mut store = StateStore::open(&root, &state, root_key.clone()).unwrap();
        let a = store
            .insert_created(
                "a",
                key_a.clone(),
                Node::file(1000, 1000, 0o600, String::new(), 0),
                &|_| false,
            )
            .unwrap();
        let b = store
            .insert_created(
                "snapshot-1/a",
                key_b.clone(),
                Node::file(1000, 1000, 0o640, String::new(), 0),
                &|_| false,
            )
            .unwrap();
        store.flush().unwrap();
        (a, b)
    };
    assert_ne!(ino_a, ino_b);

    let mut store2 = StateStore::open(&root, &state, root_key).unwrap();
    let (found_a, dirty_a) = store2
        .discover_or_reset("a", key_a.clone(), 1000, 1000, &|_| false)
        .unwrap();
    let (found_b, dirty_b) = store2
        .discover_or_reset("snapshot-1/a", key_b.clone(), 1000, 1000, &|_| false)
        .unwrap();
    assert_eq!(found_a, ino_a);
    assert_eq!(found_b, ino_b);
    assert!(!dirty_a && !dirty_b);
}

#[test]
fn creator_cred_umask_setgid_and_default_acl() {
    let tmp = TempDir::new("setgid-acl");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let alice = cred(1000, 1000, vec![1000, 2000], 0o022);
    let bob = cred(1001, 1001, vec![1001, 2000], 0o027);

    let mut engine = open_engine(&root, &state, true, true);
    let att_alice = attach(&mut engine, "alice", &alice, true, true);

    let plain_dir: Entry = call(
        &mut engine,
        &att_alice.session,
        &alice,
        Call::Mkdir {
            dir: att_alice.root.clone(),
            name: "plain".into(),
            mode: 0o777,
        },
    )
    .unwrap();
    let plain_meta: Metadata = call(
        &mut engine,
        &att_alice.session,
        &alice,
        Call::Metadata {
            handle: plain_dir.handle,
        },
    )
    .unwrap();
    assert_eq!(plain_meta.mode, 0o755);

    // Create shared setgid dir with group 2000 and default ACL.
    let shared: Entry = call(
        &mut engine,
        &att_alice.session,
        &alice,
        Call::Mkdir {
            dir: att_alice.root,
            name: "shared".into(),
            mode: 0o775,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att_alice.session,
        &alice,
        Call::Setattr {
            handle: shared.handle.clone(),
            attr: SetAttr {
                gid: Some(2000),
                mode: Some(SETGID | 0o775),
                ..Default::default()
            },
        },
    )
    .unwrap();

    // Set default ACL (`user::rwx`, `group::rx`, `other::---`).
    let default_acl = AclEntries {
        user: 7,
        group: 5,
        other: 0,
        mask: None,
        users: BTreeMap::new(),
        groups: BTreeMap::new(),
    };
    call_unit(
        &mut engine,
        &att_alice.session,
        &alice,
        Call::Setxattr {
            handle: shared.handle.clone(),
            name: ACL_DEFAULT.into(),
            value: abi::Bytes(serde_json::to_vec(&default_acl).unwrap()),
            flags: XattrFlags::empty(),
        },
    )
    .unwrap();

    let att_bob = attach(&mut engine, "bob", &bob, true, true);
    let (child_file, open_child): (Entry, OpenRef) = call(
        &mut engine,
        &att_bob.session,
        &bob,
        Call::Create {
            ticket: ticket(),
            dir: shared.handle.clone(),
            name: "note.txt".into(),
            mode: 0o666,
            options: opts_create_w_excl(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att_bob.session,
        &bob,
        Call::Release { open: open_child },
    )
    .unwrap();
    let child_meta: Metadata = call(
        &mut engine,
        &att_bob.session,
        &bob,
        Call::Metadata {
            handle: child_file.handle,
        },
    )
    .unwrap();
    assert_eq!(child_meta.uid, 1001);
    assert_eq!(child_meta.gid, 2000);
    // Default ACL masked 0o666 -> owner rw, group r (from GroupObj rx), other 0 => 0o640!
    assert_eq!(child_meta.mode, 0o640);

    let sub: Entry = call(
        &mut engine,
        &att_bob.session,
        &bob,
        Call::Mkdir {
            dir: shared.handle,
            name: "sub".into(),
            mode: 0o777,
        },
    )
    .unwrap();
    let sub_meta: Metadata = call(
        &mut engine,
        &att_bob.session,
        &bob,
        Call::Metadata { handle: sub.handle },
    )
    .unwrap();
    assert_eq!(sub_meta.gid, 2000);
    assert_ne!(sub_meta.mode & SETGID, 0);
    assert_eq!(sub_meta.mode & 0o777, 0o750);
}

#[test]
fn host_grant_ceilings_write_and_execute() {
    let tmp = TempDir::new("ceilings");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let su = cred(0, 0, vec![0], 0o022);
    // First populate a 0o755 script while writable+executable.
    let file_handle = {
        let mut engine = open_engine(&root, &state, true, true);
        let att = attach(&mut engine, "setup", &su, true, true);
        let dir: Entry = call(
            &mut engine,
            &att.session,
            &su,
            Call::Mkdir {
                dir: att.root,
                name: "bin".into(),
                mode: 0o755,
            },
        )
        .unwrap();
        let (entry, open): (Entry, OpenRef) = call(
            &mut engine,
            &att.session,
            &su,
            Call::Create {
                ticket: ticket(),
                dir: dir.handle,
                name: "run.sh".into(),
                mode: 0o755,
                options: opts_create_w_excl(),
            },
        )
        .unwrap();
        call_unit(
            &mut engine,
            &att.session,
            &su,
            Call::WriteAt {
                open: open.clone(),
                data: abi::Bytes(b"#!/bin/sh\n".to_vec()),
                at: WriteAt::Offset(0),
            },
        )
        .unwrap();
        call_unit(&mut engine, &att.session, &su, Call::Release { open }).unwrap();
        entry.handle
    };

    // Read-only helper (`write: false`, `execute: false`) blocks mutations with EROFS even for root,
    // blocks Access::Exec on non-dirs with EACCES, and still allows directory search + file read!
    let mut ro_engine = open_engine(&root, &state, false, false);
    let att_ro = attach(&mut ro_engine, "ro-tab", &su, true, true);
    assert!(!att_ro.grant.write);
    assert!(!att_ro.grant.execute);

    let walked: Walked = call(
        &mut ro_engine,
        &att_ro.session,
        &su,
        Call::Walk {
            dir: att_ro.root.clone(),
            names: vec!["bin".into(), "run.sh".into()],
        },
    )
    .unwrap();
    assert_eq!(walked.stop, None);
    assert_eq!(walked.entries.len(), 2);

    let ro_open: OpenRef = call(
        &mut ro_engine,
        &att_ro.session,
        &su,
        Call::Open {
            ticket: ticket(),
            handle: file_handle.clone(),
            options: opts_read(),
        },
    )
    .unwrap();
    call_unit(
        &mut ro_engine,
        &att_ro.session,
        &su,
        Call::Release { open: ro_open },
    )
    .unwrap();

    let exec_err = call::<OpenRef>(
        &mut ro_engine,
        &att_ro.session,
        &su,
        Call::Open {
            ticket: ticket(),
            handle: file_handle,
            options: opts_exec(),
        },
    )
    .unwrap_err();
    assert_eq!(exec_err, Errno::EACCES);

    let mkdir_err = call::<Entry>(
        &mut ro_engine,
        &att_ro.session,
        &su,
        Call::Mkdir {
            dir: att_ro.root,
            name: "blocked".into(),
            mode: 0o755,
        },
    )
    .unwrap_err();
    assert_eq!(mkdir_err, Errno::EROFS);
}

#[test]
fn open_unlink_open_rename_o_excl_noreplace_and_append() {
    let tmp = TempDir::new("unlink-rename");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let user = cred(1000, 1000, vec![1000], 0o022);
    let mut engine = open_engine(&root, &state, true, true);
    let att = attach(&mut engine, "tab", &user, true, true);

    let (e1, o1): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &user,
        Call::Create {
            ticket: ticket(),
            dir: att.root.clone(),
            name: "alpha".into(),
            mode: 0o644,
            options: opts_create_rw_excl(),
        },
    )
    .unwrap();

    // O_EXCL rejects creating existing file.
    let excl_err = call::<(Entry, OpenRef)>(
        &mut engine,
        &att.session,
        &user,
        Call::Create {
            ticket: ticket(),
            dir: att.root.clone(),
            name: "alpha".into(),
            mode: 0o644,
            options: opts_create_w_excl(),
        },
    )
    .unwrap_err();
    assert_eq!(excl_err, Errno::EEXIST);

    // Write + atomic append across two open handles.
    let o2: OpenRef = call(
        &mut engine,
        &att.session,
        &user,
        Call::Open {
            ticket: ticket(),
            handle: e1.handle.clone(),
            options: opts_w(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::WriteAt {
            open: o1.clone(),
            data: abi::Bytes(b"one-".to_vec()),
            at: WriteAt::End,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::WriteAt {
            open: o2.clone(),
            data: abi::Bytes(b"two".to_vec()),
            at: WriteAt::End,
        },
    )
    .unwrap();
    call_unit(&mut engine, &att.session, &user, Call::Release { open: o2 }).unwrap();

    // Create target "beta" and prove RENAME_NOREPLACE returns EEXIST.
    let (_e2, o_beta): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &user,
        Call::Create {
            ticket: ticket(),
            dir: att.root.clone(),
            name: "beta".into(),
            mode: 0o644,
            options: opts_create_w_excl(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Release { open: o_beta },
    )
    .unwrap();

    let noreplace_err = call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Rename {
            from_dir: att.root.clone(),
            from: "alpha".into(),
            to_dir: att.root.clone(),
            to: "beta".into(),
            flags: RenameFlags::NOREPLACE,
        },
    )
    .unwrap_err();
    assert_eq!(noreplace_err, Errno::EEXIST);

    // Rename open file to "gamma".
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Rename {
            from_dir: att.root.clone(),
            from: "alpha".into(),
            to_dir: att.root.clone(),
            to: "gamma".into(),
            flags: RenameFlags::empty(),
        },
    )
    .unwrap();
    let gamma: Entry = call(
        &mut engine,
        &att.session,
        &user,
        Call::Lookup {
            dir: att.root.clone(),
            name: "gamma".into(),
        },
    )
    .unwrap();
    assert_eq!(gamma.handle.node.ino, e1.handle.node.ino);

    // Unlink while still open: nlink becomes 0 on open_metadata, I/O still works!
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Unlink {
            dir: att.root.clone(),
            name: "gamma".into(),
        },
    )
    .unwrap();
    let open_meta: Metadata = call(
        &mut engine,
        &att.session,
        &user,
        Call::OpenMetadata { open: o1.clone() },
    )
    .unwrap();
    assert_eq!(open_meta.nlink, 0);

    let read_back: ReadReply = call(
        &mut engine,
        &att.session,
        &user,
        Call::ReadAt {
            open: o1.clone(),
            offset: 0,
            count: 64,
        },
    )
    .unwrap();
    assert_eq!(read_back.data.0, b"one-two");

    call_unit(&mut engine, &att.session, &user, Call::Release { open: o1 }).unwrap();

    let list: Vec<DirEntry> = call(
        &mut engine,
        &att.session,
        &user,
        Call::ReadDir { dir: att.root },
    )
    .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "beta");
}

#[test]
fn symlink_hardlink_confinement_and_forged_handle() {
    let tmp = TempDir::new("links");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    let outside = tmp.path().join("outside.txt");
    fs::create_dir_all(&root).unwrap();
    fs::write(&outside, b"outside secret").unwrap();

    let user = cred(1000, 1000, vec![1000], 0o022);
    let mut engine = open_engine(&root, &state, true, true);
    let att = attach(&mut engine, "tab", &user, true, true);

    let link_entry: Entry = call(
        &mut engine,
        &att.session,
        &user,
        Call::Symlink {
            dir: att.root.clone(),
            name: "escape".into(),
            target: "../outside.txt".into(),
        },
    )
    .unwrap();
    assert_eq!(link_entry.metadata.file_type, FileType::Symlink);

    let target: String = call(
        &mut engine,
        &att.session,
        &user,
        Call::ReadLink {
            link: link_entry.handle.clone(),
        },
    )
    .unwrap();
    assert_eq!(target, "../outside.txt");

    // Helper must refuse to open symlinks directly (O_NOFOLLOW -> ELOOP) rather than following out.
    let open_err = call::<OpenRef>(
        &mut engine,
        &att.session,
        &user,
        Call::Open {
            ticket: ticket(),
            handle: link_entry.handle,
            options: opts_read(),
        },
    )
    .unwrap_err();
    assert_eq!(open_err, Errno::ELOOP);

    // Hard link a regular file and verify nlink increments cleanly.
    let (file_entry, open_file): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &user,
        Call::Create {
            ticket: ticket(),
            dir: att.root.clone(),
            name: "real.txt".into(),
            mode: 0o644,
            options: opts_create_w_excl(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Release { open: open_file },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Link {
            target: file_entry.handle.clone(),
            dir: att.root.clone(),
            name: "hard.txt".into(),
        },
    )
    .unwrap();
    let hard_meta: Metadata = call(
        &mut engine,
        &att.session,
        &user,
        Call::Metadata {
            handle: file_entry.handle.clone(),
        },
    )
    .unwrap();
    assert_eq!(hard_meta.nlink, 2);

    // Forged handle HMAC proof must be rejected with EACCES.
    let forged = Handle {
        fs: file_entry.handle.fs,
        node: file_entry.handle.node,
        proof: "forged-hmac-proof".into(),
    };
    let forge_err = call::<Metadata>(
        &mut engine,
        &att.session,
        &user,
        Call::Metadata { handle: forged },
    )
    .unwrap_err();
    assert_eq!(forge_err, Errno::EACCES);

    // Host component traversal escapes (`..` or `/`) rejected with EINVAL.
    let dotdot_err = call::<Entry>(
        &mut engine,
        &att.session,
        &user,
        Call::Lookup {
            dir: att.root,
            name: "..".into(),
        },
    )
    .unwrap_err();
    assert_eq!(dotdot_err, Errno::EINVAL);
}

#[test]
fn fsync_and_fdatasync_on_open_descriptors() {
    let tmp = TempDir::new("fsync");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let user = cred(1000, 1000, vec![1000], 0o022);
    let mut engine = open_engine(&root, &state, true, true);
    let att = attach(&mut engine, "tab", &user, true, true);

    let (entry, open_w): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &user,
        Call::Create {
            ticket: ticket(),
            dir: att.root.clone(),
            name: "durable.txt".into(),
            mode: 0o644,
            options: opts_create_w_excl(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::WriteAt {
            open: open_w.clone(),
            data: abi::Bytes(b"sync-me".to_vec()),
            at: WriteAt::Offset(0),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Sync {
            open: open_w.clone(),
            data_only: false,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Sync {
            open: open_w.clone(),
            data_only: true,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Release { open: open_w },
    )
    .unwrap();

    // Directory fsync works, while O_PATH returns EBADF.
    let dir_open: OpenRef = call(
        &mut engine,
        &att.session,
        &user,
        Call::Open {
            ticket: ticket(),
            handle: att.root,
            options: opts_read(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Sync {
            open: dir_open.clone(),
            data_only: false,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Release { open: dir_open },
    )
    .unwrap();

    let path_open: OpenRef = call(
        &mut engine,
        &att.session,
        &user,
        Call::Open {
            ticket: ticket(),
            handle: entry.handle,
            options: opts_path(),
        },
    )
    .unwrap();
    let sync_path_err = call_unit(
        &mut engine,
        &att.session,
        &user,
        Call::Sync {
            open: path_open,
            data_only: false,
        },
    )
    .unwrap_err();
    assert_eq!(sync_path_err, Errno::EBADF);
}

#[test]
fn real_host_flock_and_ofd_locks_deadlock_and_teardown() {
    let tmp = TempDir::new("locks");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let user = cred(1000, 1000, vec![1000], 0o022);
    let mut engine = open_engine(&root, &state, true, true);
    let att_a = attach(&mut engine, "tab-a", &user, true, true);
    let att_b = attach(&mut engine, "tab-b", &user, true, true);

    let (e1, o1): (Entry, OpenRef) = call(
        &mut engine,
        &att_a.session,
        &user,
        Call::Create {
            ticket: ticket(),
            dir: att_a.root.clone(),
            name: "f1".into(),
            mode: 0o644,
            options: opts_create_rw_excl(),
        },
    )
    .unwrap();
    let (e2, o2): (Entry, OpenRef) = call(
        &mut engine,
        &att_a.session,
        &user,
        Call::Create {
            ticket: ticket(),
            dir: att_a.root,
            name: "f2".into(),
            mode: 0o644,
            options: opts_create_rw_excl(),
        },
    )
    .unwrap();

    for o in [&o1, &o2] {
        call_unit(
            &mut engine,
            &att_a.session,
            &user,
            Call::WriteAt {
                open: o.clone(),
                data: abi::Bytes(vec![b'x'; 64]),
                at: WriteAt::Offset(0),
            },
        )
        .unwrap();
    }

    let b1: OpenRef = call(
        &mut engine,
        &att_b.session,
        &user,
        Call::Open {
            ticket: ticket(),
            handle: e1.handle,
            options: opts_rw(),
        },
    )
    .unwrap();
    let b2: OpenRef = call(
        &mut engine,
        &att_b.session,
        &user,
        Call::Open {
            ticket: ticket(),
            handle: e2.handle,
            options: opts_rw(),
        },
    )
    .unwrap();

    // 1) Real host flock visibility & exclusion across helper & external host fd.
    call_unit(
        &mut engine,
        &att_a.session,
        &user,
        Call::TryLock {
            open: o1.clone(),
            family: LockFamily::Flock,
            kind: LockKind::Exclusive,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();

    let ext_file = StdOpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("f1"))
        .unwrap();
    let ext_rc = unsafe { libc::flock(ext_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(ext_rc, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EWOULDBLOCK)
    );

    let try_err = call_unit(
        &mut engine,
        &att_b.session,
        &user,
        Call::TryLock {
            open: b1.clone(),
            family: LockFamily::Flock,
            kind: LockKind::Exclusive,
            range: LockRange::WHOLE,
        },
    )
    .unwrap_err();
    assert_eq!(try_err, Errno::EAGAIN);

    call_unit(
        &mut engine,
        &att_a.session,
        &user,
        Call::Unlock {
            open: o1.clone(),
            family: LockFamily::Flock,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();
    assert_eq!(
        unsafe { libc::flock(ext_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert_eq!(
        unsafe { libc::flock(ext_file.as_raw_fd(), libc::LOCK_UN) },
        0
    );

    // 2) Real host F_OFD byte-range lock + F_OFD_GETLK + queued blocking ticket + EDEADLK!
    let range_0_10 = LockRange::new(0, Some(10)).unwrap();
    let range_10_20 = LockRange::new(10, Some(20)).unwrap();
    call_unit(
        &mut engine,
        &att_a.session,
        &user,
        Call::TryLock {
            open: o1.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: range_0_10,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att_b.session,
        &user,
        Call::TryLock {
            open: b1.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: range_10_20,
        },
    )
    .unwrap();
    let _ = b2;
    let _ = o2;

    // External host F_OFD_GETLK sees helper's lock on [0..10).
    let mut fl = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 10,
        l_pid: 0,
    };
    assert_eq!(
        unsafe { libc::fcntl(ext_file.as_raw_fd(), libc::F_OFD_GETLK, &mut fl) },
        0
    );
    assert_eq!(fl.l_type, libc::F_WRLCK as libc::c_short);
    assert_eq!(fl.l_start, 0);
    assert_eq!(fl.l_len, 10);

    let conflict: Option<Conflict> = call(
        &mut engine,
        &att_b.session,
        &user,
        Call::TestLock {
            open: b1.clone(),
            kind: LockKind::Exclusive,
            range: range_0_10,
        },
    )
    .unwrap();
    assert!(conflict.is_some());

    // B (holding [10..20) on f1) waits for [0..10) on f1 (held by A) -> Pending ticket!
    let outcome: LockOutcome = call(
        &mut engine,
        &att_b.session,
        &user,
        Call::Lock {
            open: b1.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: range_0_10,
            ticket: "wait-b1".into(),
        },
    )
    .unwrap();
    assert_eq!(outcome, LockOutcome::Pending);

    // A (holding [0..10) on f1) now requests [10..20) on f1 (held by B) -> EDEADLK!
    let deadlk = call::<LockOutcome>(
        &mut engine,
        &att_a.session,
        &user,
        Call::Lock {
            open: o1,
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: range_10_20,
            ticket: "wait-o1".into(),
        },
    )
    .unwrap_err();
    assert_eq!(deadlk, Errno::EDEADLK);

    // Release session A by simulating lease timeout + sweep_expired -> B acquires ticket!
    engine.force_session_idle(&att_a.session, Duration::from_secs(LEASE_SECONDS + 5));
    engine.sweep_expired();

    let outcome2: LockOutcome = call(
        &mut engine,
        &att_b.session,
        &user,
        Call::Lock {
            open: b1,
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: range_0_10,
            ticket: "wait-b1".into(),
        },
    )
    .unwrap();
    assert_eq!(outcome2, LockOutcome::Acquired);

    // Detach releases b1 and its host lock.
    engine
        .handle_request(Request::Detach {
            version: VERSION,
            session: att_b.session,
        })
        .unwrap();

    let mut fl_after = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 10,
        l_pid: 0,
    };
    assert_eq!(
        unsafe { libc::fcntl(ext_file.as_raw_fd(), libc::F_OFD_GETLK, &mut fl_after) },
        0
    );
    assert_eq!(fl_after.l_type, libc::F_UNLCK as libc::c_short);
}

#[test]
fn boundary_hello_and_legacy_rejection() {
    let tmp = TempDir::new("hello");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let mut engine = open_engine(&root, &state, false, true);
    let reply_raw = engine
        .handle_request(Request::Hello(Hello {
            boundary: Boundary::LocalHelper,
            versions: vec![1],
        }))
        .unwrap();
    let reply: HelloReply = serde_json::from_value(reply_raw).unwrap();
    assert_eq!(reply.boundary, Boundary::LocalHelper);
    assert_eq!(reply.version, 1);
    assert!(!reply.write);
    assert!(reply.execute);

    // Boundary mismatch -> EPROTONOSUPPORT.
    assert_eq!(
        engine
            .handle_request(Request::Hello(Hello {
                boundary: Boundary::RemoteFilesystem,
                versions: vec![1],
            }))
            .unwrap_err(),
        Errno::EPROTONOSUPPORT
    );

    // Unsupported versions -> EPROTONOSUPPORT.
    assert_eq!(
        engine
            .handle_request(Request::Hello(Hello {
                boundary: Boundary::LocalHelper,
                versions: vec![99],
            }))
            .unwrap_err(),
        Errno::EPROTONOSUPPORT
    );

    // Renew with wrong version -> EPROTONOSUPPORT.
    assert_eq!(
        engine
            .handle_request(Request::Renew {
                version: 2,
                session: "x".into(),
            })
            .unwrap_err(),
        Errno::EPROTONOSUPPORT
    );
    let _check: RenewReply = RenewReply { lease_seconds: 60 };
}

#[test]
fn handshake_token_single_use_and_cancel_open_lifecycle() {
    let tmp = TempDir::new("handshake-cancel-open");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    let mut engine = open_engine(&root, &state, true, true);
    let owner = cred(1000, 1000, vec![1000], 0o022);

    // Unknown handshake fails.
    assert_eq!(
        engine
            .handle_request(Request::Attach {
                version: VERSION,
                client_id: "c1".into(),
                handshake: "forged-handshake".into(),
                cred: owner.clone(),
                grant: HelperGrant {
                    write: true,
                    execute: true,
                },
            })
            .unwrap_err(),
        Errno::EPROTONOSUPPORT
    );

    // Consuming a valid handshake once succeeds, and replaying it fails.
    let hello: HelloReply = serde_json::from_value(
        engine
            .handle_request(Request::Hello(Hello {
                boundary: Boundary::LocalHelper,
                versions: vec![VERSION],
            }))
            .unwrap(),
    )
    .unwrap();
    let att: AttachReply = serde_json::from_value(
        engine
            .handle_request(Request::Attach {
                version: VERSION,
                client_id: "c1".into(),
                handshake: hello.handshake.clone(),
                cred: owner.clone(),
                grant: HelperGrant {
                    write: true,
                    execute: true,
                },
            })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        engine
            .handle_request(Request::Attach {
                version: VERSION,
                client_id: "c2".into(),
                handshake: hello.handshake,
                cred: owner.clone(),
                grant: HelperGrant {
                    write: true,
                    execute: true,
                },
            })
            .unwrap_err(),
        Errno::EPROTONOSUPPORT
    );

    // Same Create ticket is idempotent, and CancelOpen closes the allocated host descriptor.
    let (entry, open1): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Create {
            ticket: "dup-create".into(),
            dir: att.root.clone(),
            name: "f.txt".into(),
            mode: 0o644,
            options: opts_create_rw_excl(),
        },
    )
    .unwrap();
    let (_entry2, open1_again): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Create {
            ticket: "dup-create".into(),
            dir: att.root.clone(),
            name: "f.txt".into(),
            mode: 0o644,
            options: opts_create_rw_excl(),
        },
    )
    .unwrap();
    assert_eq!(open1, open1_again);

    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::CancelOpen {
            ticket: "dup-create".into(),
        },
    )
    .unwrap();
    assert_eq!(
        call::<Metadata>(
            &mut engine,
            &att.session,
            &owner,
            Call::OpenMetadata { open: open1 },
        )
        .unwrap_err(),
        Errno::EBADF
    );

    // Pre-cancelled ticket rejects a late arriving Open with ECANCELED without allocating an fd.
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::CancelOpen {
            ticket: "late-open".into(),
        },
    )
    .unwrap();
    assert_eq!(
        call::<OpenRef>(
            &mut engine,
            &att.session,
            &owner,
            Call::Open {
                ticket: "late-open".into(),
                handle: entry.handle,
                options: opts_read(),
            },
        )
        .unwrap_err(),
        Errno::ECANCELED
    );
}

#[test]
fn store_locking_symlink_escape_root_reservation_and_ino_exhaustion() {
    use super::store::{HostInodeKey, ROOT_INO};
    use super::sys::{HostGen, HostKind, openat_nofollow, statx_fd};
    use os_core::permissions::Node;
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new("store-hardening");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&state).unwrap();

    let root_fd = open_root_dir(&root).unwrap();
    let root_stx = statx_fd(root_fd.as_fd()).unwrap();
    let root_key = HostInodeKey::from_root(root_fd.as_fd(), &root_stx).unwrap();

    // Concurrent StateStore open on the same (root, state_dir) must fail with EBUSY.
    {
        let mut store1 = StateStore::open(&root, &state, root_key.clone()).unwrap();
        let err = StateStore::open(&root, &state, root_key.clone())
            .err()
            .unwrap();
        assert_eq!(err, Errno::EBUSY);

        // ROOT_INO is reserved; allocating up to JS_SAFE succeeds and overflowing returns ENOSPC.
        let r_handle = store1.ensure_root_node(&root_key, 1000, 1000).unwrap();
        assert_eq!(r_handle.node.ino, ROOT_INO);
        *store1.next_ino_mut() = JS_SAFE;
        let last_key = HostInodeKey {
            subfs_relpath: String::new(),
            subvol: None,
            subfs_fsuuid: None,
            host_ino: 999_001,
            host_gen: HostGen::IocVersion(1),
            kind: HostKind::File,
        };
        let last_ino = store1
            .insert_created(
                "last",
                last_key,
                Node::file(1000, 1000, 0o600, String::new(), 0),
                &|_| false,
            )
            .unwrap();
        assert_eq!(last_ino, JS_SAFE);
        let overflow_key = HostInodeKey {
            subfs_relpath: String::new(),
            subvol: None,
            subfs_fsuuid: None,
            host_ino: 999_002,
            host_gen: HostGen::IocVersion(1),
            kind: HostKind::File,
        };
        assert_eq!(
            store1
                .insert_created(
                    "overflow",
                    overflow_key,
                    Node::file(1000, 1000, 0o600, String::new(), 0),
                    &|_| false,
                )
                .unwrap_err(),
            Errno::ENOSPC
        );
    }

    // Reopening after dropping lock succeeds cleanly without wrapping to ROOT_INO.
    let store2 = StateStore::open(&root, &state, root_key.clone()).unwrap();
    assert!(store2.get(ROOT_INO).is_some());
    drop(store2);

    // Symlinking state/folders into the mounted root must fail without writing inside root.
    let sym_state = tmp.path().join("sym-state");
    fs::create_dir_all(&sym_state).unwrap();
    let trap = root.join("trap");
    fs::create_dir_all(&trap).unwrap();
    symlink(&trap, sym_state.join("folders")).unwrap();
    let err = StateStore::open(&root, &sym_state, root_key).err().unwrap();
    assert!(matches!(err, Errno::ELOOP | Errno::ENOTDIR));
    assert_eq!(fs::read_dir(&trap).unwrap().count(), 0);
    let _ = openat_nofollow(root_fd.as_fd(), "trap", libc::O_PATH, 0).unwrap();
}

#[test]
fn boundary_crossed_subfs_rules_and_directory_vs_overlayfs() {
    use super::sys::{HostKind, HostStat, boundary_crossed};

    let stat =
        |mnt_id: Option<u64>, subvol: Option<u64>, dev: (u32, u32), kind: HostKind| HostStat {
            mnt_id,
            subvol,
            dev,
            ino: 1,
            kind,
            nlink: 1,
            size: 0,
            atime: (0, 0),
            mtime: (0, 0),
            ctime: (0, 0),
            btime: None,
        };

    // Different mount IDs trigger boundary even when device numbers match (bind mount).
    assert!(boundary_crossed(
        &stat(Some(10), None, (0, 50), HostKind::Dir),
        &stat(Some(11), None, (0, 50), HostKind::Dir),
    ));
    // Different st_dev on a child directory within same mount triggers boundary (btrfs subvolume).
    assert!(boundary_crossed(
        &stat(Some(10), None, (0, 50), HostKind::Dir),
        &stat(Some(10), None, (0, 51), HostKind::Dir),
    ));
    // Different stx_subvol on a child directory triggers boundary even if dev/mnt_id matched.
    assert!(boundary_crossed(
        &stat(Some(10), Some(256), (0, 50), HostKind::Dir),
        &stat(Some(10), Some(257), (0, 50), HostKind::Dir),
    ));
    // Non-directory child with different st_dev on same mount does NOT split overlayfs files.
    assert!(!boundary_crossed(
        &stat(Some(10), None, (0, 50), HostKind::Dir),
        &stat(Some(10), None, (0, 51), HostKind::File),
    ));
}

#[test]
fn external_dir_escape_and_create_parent_exec_and_o_trunc_and_fifo_safety() {
    let tmp = TempDir::new("confinement-trunc-fifo");
    let root = tmp.path().join("root");
    let outside = tmp.path().join("outside");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();

    let mut engine = open_engine(&root, &state, true, true);
    let owner = cred(1000, 1000, vec![1000], 0o022);
    let att = attach(&mut engine, "c1", &owner, true, true);

    let sub: Entry = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Mkdir {
            dir: att.root.clone(),
            name: "sub".into(),
            mode: 0o700,
        },
    )
    .unwrap();
    let (file_e, file_o): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Create {
            ticket: ticket(),
            dir: sub.handle.clone(),
            name: "data.txt".into(),
            mode: 0o644,
            options: opts_create_rw_excl(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Release { open: file_o },
    )
    .unwrap();

    // Opening existing file via Call::Create enforces parent EXEC permission.
    call::<Metadata>(
        &mut engine,
        &att.session,
        &owner,
        Call::Setattr {
            handle: sub.handle.clone(),
            attr: SetAttr {
                mode: Some(0o600),
                ..Default::default()
            },
        },
    )
    .unwrap();
    assert_eq!(
        call::<(Entry, OpenRef)>(
            &mut engine,
            &att.session,
            &owner,
            Call::Create {
                ticket: ticket(),
                dir: sub.handle.clone(),
                name: "data.txt".into(),
                mode: 0o644,
                options: *OpenOptions::new().write(true).create(true),
            },
        )
        .unwrap_err(),
        Errno::EACCES
    );
    call::<Metadata>(
        &mut engine,
        &att.session,
        &owner,
        Call::Setattr {
            handle: sub.handle.clone(),
            attr: SetAttr {
                mode: Some(0o700),
                ..Default::default()
            },
        },
    )
    .unwrap();

    // External replacement + O_TRUNC on stale handle must fail with ESTALE without truncating!
    fs::rename(root.join("sub/data.txt"), root.join("sub/old.txt")).unwrap();
    fs::write(root.join("sub/data.txt"), b"DO-NOT-TRUNCATE").unwrap();
    assert_eq!(
        call::<OpenRef>(
            &mut engine,
            &att.session,
            &owner,
            Call::Open {
                ticket: ticket(),
                handle: file_e.handle.clone(),
                options: *OpenOptions::new().write(true).truncate(true),
            },
        )
        .unwrap_err(),
        Errno::ESTALE
    );
    assert_eq!(
        fs::read(root.join("sub/data.txt")).unwrap(),
        b"DO-NOT-TRUNCATE"
    );

    // Replacing target with a host FIFO must never block on O_WRONLY|O_TRUNC open and returns ESTALE.
    fs::remove_file(root.join("sub/data.txt")).unwrap();
    let fifo_c = std::ffi::CString::new(root.join("sub/data.txt").to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    assert_eq!(
        call::<OpenRef>(
            &mut engine,
            &att.session,
            &owner,
            Call::Open {
                ticket: ticket(),
                handle: file_e.handle,
                options: *OpenOptions::new().write(true).truncate(true),
            },
        )
        .unwrap_err(),
        Errno::ESTALE
    );

    // Moving sub outside root externally prevents mutating it via its retained handle.
    fs::rename(root.join("sub"), outside.join("escaped")).unwrap();
    assert!(
        call::<Entry>(
            &mut engine,
            &att.session,
            &owner,
            Call::Mkdir {
                dir: sub.handle,
                name: "child".into(),
                mode: 0o755,
            },
        )
        .is_err()
    );
    assert!(!outside.join("escaped/child").exists());
}

#[test]
fn atomic_append_unknown_rename_flags_dead_dir_and_hardlink_unlinked_gc() {
    let tmp = TempDir::new("append-rename-dead-gc");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let owner = cred(1000, 1000, vec![1000], 0o022);
    let (e_handle, engine) = {
        let mut engine = open_engine(&root, &state, true, true);
        let att = attach(&mut engine, "c1", &owner, true, true);

        // Two distinct open descriptions append atomically to shared file via RWF_APPEND.
        let (fe, o1): (Entry, OpenRef) = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Create {
                ticket: ticket(),
                dir: att.root.clone(),
                name: "log.txt".into(),
                mode: 0o644,
                options: *OpenOptions::new()
                    .read(true)
                    .write(true)
                    .append(true)
                    .create(true)
                    .create_new(true),
            },
        )
        .unwrap();
        let o2: OpenRef = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Open {
                ticket: ticket(),
                handle: fe.handle.clone(),
                options: *OpenOptions::new().read(true).write(true).append(true),
            },
        )
        .unwrap();

        let w1: abi::fs::Written = call(
            &mut engine,
            &att.session,
            &owner,
            Call::WriteAt {
                open: o1.clone(),
                data: abi::Bytes(b"first-".to_vec()),
                at: WriteAt::End,
            },
        )
        .unwrap();
        let w2: abi::fs::Written = call(
            &mut engine,
            &att.session,
            &owner,
            Call::WriteAt {
                open: o2.clone(),
                data: abi::Bytes(b"second".to_vec()),
                at: WriteAt::End,
            },
        )
        .unwrap();
        assert_eq!(w1.offset, 0);
        assert_eq!(w2.offset, 6);
        assert_eq!(fs::read(root.join("log.txt")).unwrap(), b"first-second");
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Release { open: o1 },
        )
        .unwrap();
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Release { open: o2 },
        )
        .unwrap();

        // Unknown rename flags bit returns EINVAL and preserves both entries.
        let (other_e, other_o): (Entry, OpenRef) = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Create {
                ticket: ticket(),
                dir: att.root.clone(),
                name: "keep.txt".into(),
                mode: 0o644,
                options: opts_create_w_excl(),
            },
        )
        .unwrap();
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Release { open: other_o },
        )
        .unwrap();
        assert_eq!(
            call_unit(
                &mut engine,
                &att.session,
                &owner,
                Call::Rename {
                    from_dir: att.root.clone(),
                    from: "log.txt".into(),
                    to_dir: att.root.clone(),
                    to: "keep.txt".into(),
                    flags: RenameFlags::from_bits_retain(0x2),
                },
            )
            .unwrap_err(),
            Errno::EINVAL
        );
        assert!(root.join("log.txt").exists() && root.join("keep.txt").exists());
        let _ = other_e;

        // Hard-link removal preserves OS metadata/xattrs until the last link is unlinked & closed.
        let link_e: Entry = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Link {
                target: fe.handle.clone(),
                dir: att.root.clone(),
                name: "log-link.txt".into(),
            },
        )
        .unwrap();
        assert_eq!(link_e.handle.node.ino, fe.handle.node.ino);
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Setxattr {
                handle: fe.handle.clone(),
                name: "user.tag".into(),
                value: abi::Bytes(b"v1".to_vec()),
                flags: XattrFlags::empty(),
            },
        )
        .unwrap();
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Unlink {
                dir: att.root.clone(),
                name: "log.txt".into(),
            },
        )
        .unwrap();
        let remaining = call::<abi::Bytes>(
            &mut engine,
            &att.session,
            &owner,
            Call::Getxattr {
                handle: fe.handle.clone(),
                name: "user.tag".into(),
            },
        )
        .unwrap();
        assert_eq!(remaining.0, b"v1");

        // Rmdir an open directory rejects subsequent Mkdir on its dead handle with ENOENT.
        let dir_e: Entry = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Mkdir {
                dir: att.root.clone(),
                name: "ephem".into(),
                mode: 0o755,
            },
        )
        .unwrap();
        let dir_open: OpenRef = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Open {
                ticket: ticket(),
                handle: dir_e.handle.clone(),
                options: opts_read(),
            },
        )
        .unwrap();
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Rmdir {
                dir: att.root.clone(),
                name: "ephem".into(),
            },
        )
        .unwrap();
        assert_eq!(
            call::<Entry>(
                &mut engine,
                &att.session,
                &owner,
                Call::Mkdir {
                    dir: dir_e.handle,
                    name: "inside".into(),
                    mode: 0o755,
                },
            )
            .unwrap_err(),
            Errno::ENOENT
        );
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Release { open: dir_open },
        )
        .unwrap();

        // Unlink last link while open, then drop engine without releasing to test startup GC!
        let o_unlinked: OpenRef = call(
            &mut engine,
            &att.session,
            &owner,
            Call::Open {
                ticket: ticket(),
                handle: fe.handle.clone(),
                options: opts_rw(),
            },
        )
        .unwrap();
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::Unlink {
                dir: att.root,
                name: "log-link.txt".into(),
            },
        )
        .unwrap();
        let unlinked_meta: Metadata = call(
            &mut engine,
            &att.session,
            &owner,
            Call::OpenMetadata { open: o_unlinked },
        )
        .unwrap();
        assert_eq!(unlinked_meta.nlink, 0);
        (fe.handle, engine)
    };
    drop(engine);

    // Reopening engine sweeps persisted unlinked record when no open descriptors exist!
    let mut engine2 = open_engine(&root, &state, true, true);
    let att2 = attach(&mut engine2, "c2", &owner, true, true);
    assert_eq!(
        call::<Metadata>(
            &mut engine2,
            &att2.session,
            &owner,
            Call::Metadata { handle: e_handle },
        )
        .unwrap_err(),
        Errno::ESTALE
    );
}

#[test]
fn flock_conversion_cancel_restore_and_posix_deadlock_three_way_and_partial_cancel() {
    let tmp = TempDir::new("lock-edge-cases");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let mut engine = open_engine(&root, &state, true, true);
    let owner = cred(1000, 1000, vec![1000], 0o022);
    let att = attach(&mut engine, "c1", &owner, true, true);

    let (fe, o1): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Create {
            ticket: ticket(),
            dir: att.root.clone(),
            name: "lockfile".into(),
            mode: 0o644,
            options: opts_create_rw_excl(),
        },
    )
    .unwrap();
    let o2: OpenRef = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Open {
            ticket: ticket(),
            handle: fe.handle.clone(),
            options: opts_rw(),
        },
    )
    .unwrap();
    let o3: OpenRef = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Open {
            ticket: ticket(),
            handle: fe.handle,
            options: opts_rw(),
        },
    )
    .unwrap();

    // 1. Flock shared on o1+o2, try_lock(Exclusive) on o1 -> EAGAIN AND o1 retains shared lock!
    assert_eq!(
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::TryLock {
                open: o1.clone(),
                family: LockFamily::Flock,
                kind: LockKind::Shared,
                range: LockRange::WHOLE,
            },
        ),
        Ok(())
    );
    assert_eq!(
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::TryLock {
                open: o2.clone(),
                family: LockFamily::Flock,
                kind: LockKind::Shared,
                range: LockRange::WHOLE,
            },
        ),
        Ok(())
    );
    assert_eq!(
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::TryLock {
                open: o1.clone(),
                family: LockFamily::Flock,
                kind: LockKind::Exclusive,
                range: LockRange::WHOLE,
            },
        ),
        Err(Errno::EAGAIN)
    );
    // Failed try_lock conversion follows Linux flock(2) semantics (drops o1's LOCK_SH and reconciles
    // shadow state cleanly, so o2 can immediately upgrade to Exclusive).
    assert_eq!(
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::TryLock {
                open: o2.clone(),
                family: LockFamily::Flock,
                kind: LockKind::Exclusive,
                range: LockRange::WHOLE,
            },
        ),
        Ok(())
    );
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Unlock {
            open: o2.clone(),
            family: LockFamily::Flock,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::TryLock {
            open: o1.clone(),
            family: LockFamily::Flock,
            kind: LockKind::Shared,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::TryLock {
            open: o2.clone(),
            family: LockFamily::Flock,
            kind: LockKind::Shared,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();

    // Pending flock upgrade cancelled restores LOCK_SH so o2 still cannot take Exclusive!
    let upgrade_out: LockOutcome = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Lock {
            open: o1.clone(),
            family: LockFamily::Flock,
            kind: LockKind::Exclusive,
            range: LockRange::WHOLE,
            ticket: "flock-up".into(),
        },
    )
    .unwrap();
    assert_eq!(upgrade_out, LockOutcome::Pending);
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::CancelLock {
            open: o1.clone(),
            ticket: "flock-up".into(),
        },
    )
    .unwrap();
    assert_eq!(
        call_unit(
            &mut engine,
            &att.session,
            &owner,
            Call::TryLock {
                open: o2.clone(),
                family: LockFamily::Flock,
                kind: LockKind::Exclusive,
                range: LockRange::WHOLE,
            },
        ),
        Err(Errno::EAGAIN)
    );
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Unlock {
            open: o1.clone(),
            family: LockFamily::Flock,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::TryLock {
            open: o2.clone(),
            family: LockFamily::Flock,
            kind: LockKind::Exclusive,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Unlock {
            open: o2.clone(),
            family: LockFamily::Flock,
            range: LockRange::WHOLE,
        },
    )
    .unwrap();

    // 2. Partial POSIX cancel preserves unrelated ranges on the same owner, and 3-way EDEADLK!
    let r_0_4 = LockRange::new(0, Some(4)).unwrap();
    let r_4_8 = LockRange::new(4, Some(8)).unwrap();
    let r_8_12 = LockRange::new(8, Some(12)).unwrap();
    let r_12_16 = LockRange::new(12, Some(16)).unwrap();
    let r_0_16 = LockRange::new(0, Some(16)).unwrap();

    // Owner o1 holds [0..4] and [12..16] Exclusive, waits on [4..8] held by o2 -> CancelLock keeps [0..4] & [12..16].
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::TryLock {
            open: o1.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: r_0_4,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::TryLock {
            open: o1.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: r_12_16,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::TryLock {
            open: o2.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: r_4_8,
        },
    )
    .unwrap();
    let p_wait: LockOutcome = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Lock {
            open: o1.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: r_4_8,
            ticket: "wait-mid".into(),
        },
    )
    .unwrap();
    assert_eq!(p_wait, LockOutcome::Pending);
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::CancelLock {
            open: o1.clone(),
            ticket: "wait-mid".into(),
        },
    )
    .unwrap();
    let c0: Option<Conflict> = call(
        &mut engine,
        &att.session,
        &owner,
        Call::TestLock {
            open: o2.clone(),
            kind: LockKind::Exclusive,
            range: r_0_4,
        },
    )
    .unwrap();
    let c12: Option<Conflict> = call(
        &mut engine,
        &att.session,
        &owner,
        Call::TestLock {
            open: o2.clone(),
            kind: LockKind::Exclusive,
            range: r_12_16,
        },
    )
    .unwrap();
    assert!(c0.is_some() && c12.is_some());

    // 3-way POSIX cycle: o1 holds [0..4] waits [4..8]; o2 holds [4..8] waits [8..12]; o3 holds [8..12] waits [0..4] -> EDEADLK.
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Unlock {
            open: o1.clone(),
            family: LockFamily::Posix,
            range: r_12_16,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::TryLock {
            open: o3.clone(),
            family: LockFamily::Posix,
            kind: LockKind::Exclusive,
            range: r_8_12,
        },
    )
    .unwrap();
    assert_eq!(
        call::<LockOutcome>(
            &mut engine,
            &att.session,
            &owner,
            Call::Lock {
                open: o1.clone(),
                family: LockFamily::Posix,
                kind: LockKind::Exclusive,
                range: r_4_8,
                ticket: "cycle-1".into(),
            },
        )
        .unwrap(),
        LockOutcome::Pending
    );
    assert_eq!(
        call::<LockOutcome>(
            &mut engine,
            &att.session,
            &owner,
            Call::Lock {
                open: o2.clone(),
                family: LockFamily::Posix,
                kind: LockKind::Exclusive,
                range: r_8_12,
                ticket: "cycle-2".into(),
            },
        )
        .unwrap(),
        LockOutcome::Pending
    );
    assert_eq!(
        call::<LockOutcome>(
            &mut engine,
            &att.session,
            &owner,
            Call::Lock {
                open: o3.clone(),
                family: LockFamily::Posix,
                kind: LockKind::Exclusive,
                range: r_0_4,
                ticket: "cycle-3".into(),
            },
        )
        .unwrap_err(),
        Errno::EDEADLK
    );
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Unlock {
            open: o1,
            family: LockFamily::Posix,
            range: r_0_16,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Unlock {
            open: o2,
            family: LockFamily::Posix,
            range: r_0_16,
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Unlock {
            open: o3,
            family: LockFamily::Posix,
            range: r_0_16,
        },
    )
    .unwrap();
}

#[test]
fn discovery_and_external_reset_use_attaching_account_not_caller() {
    let tmp = TempDir::new("owner-discovery");
    let root = tmp.path.join("root");
    let state = tmp.path.join("state");
    fs::create_dir_all(root.join("shared")).unwrap();
    fs::write(root.join("shared/host_secret.txt"), b"top-secret").unwrap();

    let owner = cred(1000, 1000, vec![1000], 0o022);
    let other = cred(2000, 2000, vec![2000], 0o022);

    let root_fd = super::open_root_dir(&root).unwrap();
    let mut engine = HelperEngine::open(&root, &state, root_fd, true, true).unwrap();
    let att = attach(&mut engine, "tab", &owner, true, true);

    let shared: Entry = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Lookup {
            dir: att.root.clone(),
            name: "shared".into(),
        },
    )
    .unwrap();
    let _: Metadata = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Setattr {
            handle: shared.handle.clone(),
            attr: SetAttr {
                mode: Some(0o755),
                ..Default::default()
            },
        },
    )
    .unwrap();

    // Another OS user with directory traversal discovers the host file: it MUST belong to
    // the attaching account (1000:1000, 0600), NEVER the lookup caller (2000:2000)!
    let discovered: Entry = call(
        &mut engine,
        &att.session,
        &other,
        Call::Lookup {
            dir: shared.handle.clone(),
            name: "host_secret.txt".into(),
        },
    )
    .unwrap();
    assert_eq!(discovered.metadata.uid, 1000);
    assert_eq!(discovered.metadata.gid, 1000);
    assert_eq!(discovered.metadata.mode, 0o600);
    assert_eq!(
        call::<OpenRef>(
            &mut engine,
            &att.session,
            &other,
            Call::Open {
                handle: discovered.handle.clone(),
                options: *OpenOptions::new().read(true),
                ticket: "other-read-secret".into(),
            },
        )
        .unwrap_err(),
        Errno::EACCES
    );
}

#[test]
fn externally_renamed_open_dir_resolves_children_and_creates_in_renamed_dir() {
    let tmp = TempDir::new("renamed-open-dir");
    let root = tmp.path.join("root");
    let state = tmp.path.join("state");
    fs::create_dir_all(root.join("a")).unwrap();
    fs::write(root.join("a/inside.txt"), b"from-a").unwrap();
    fs::write(root.join("inside.txt"), b"from-root").unwrap();

    let owner = cred(1000, 1000, vec![1000], 0o022);
    let root_fd = super::open_root_dir(&root).unwrap();
    let mut engine = HelperEngine::open(&root, &state, root_fd, true, true).unwrap();
    let att = attach(&mut engine, "tab", &owner, true, true);

    let dir_a: Entry = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Lookup {
            dir: att.root.clone(),
            name: "a".into(),
        },
    )
    .unwrap();
    let open_dir_a: OpenRef = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Open {
            handle: dir_a.handle.clone(),
            options: opts_read(),
            ticket: "open-a".into(),
        },
    )
    .unwrap();

    // Externally rename root/a -> root/b while directory descriptor stays open!
    fs::rename(root.join("a"), root.join("b")).unwrap();

    // Lookup and Create through dir_a MUST operate on root/b, NEVER redirect to root!
    let found_inside: Entry = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Lookup {
            dir: dir_a.handle.clone(),
            name: "inside.txt".into(),
        },
    )
    .unwrap();
    assert_eq!(found_inside.metadata.size, b"from-a".len() as u64);

    let (_created_entry, created_open): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Create {
            dir: dir_a.handle.clone(),
            name: "created.txt".into(),
            mode: 0o600,
            options: *OpenOptions::new().write(true).create(true).create_new(true),
            ticket: "create-in-b".into(),
        },
    )
    .unwrap();
    assert!(root.join("b/created.txt").exists());
    assert!(!root.join("created.txt").exists());

    let parent: Option<(Entry, String)> = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Parent {
            dir: dir_a.handle.clone(),
        },
    )
    .unwrap();
    assert_eq!(parent.unwrap().1, "b");

    // Moving dir_a outside root makes operations fail confinement instead of falling back to root.
    fs::rename(root.join("b"), tmp.path.join("escaped")).unwrap();
    let outside_err = call::<Entry>(
        &mut engine,
        &att.session,
        &owner,
        Call::Lookup {
            dir: dir_a.handle,
            name: "inside.txt".into(),
        },
    )
    .unwrap_err();
    assert_eq!(outside_err, Errno::EACCES);

    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Release { open: created_open },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Release { open: open_dir_a },
    )
    .unwrap();
}

#[test]
fn mountinfo_overlap_rejects_bind_mounted_root_descendant_and_alias() {
    let sample = "\
28 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
51 28 8:1 /tmp/work/root/private /tmp/outside_bind rw,relatime - ext4 /dev/sda1 rw\n\
52 28 8:1 /tmp/outside_state /tmp/work/root/alias rw,relatime - ext4 /dev/sda1 rw\n";
    let mounts = super::sys::parse_mountinfo(sample);

    // Bind mount of root/private at external --state-dir MUST be rejected!
    assert_eq!(
        super::sys::check_mountinfo_overlap(
            &mounts,
            Path::new("/tmp/work/root"),
            Some(28),
            Path::new("/tmp/outside_bind"),
            Some(51),
            Path::new("/tmp/outside_bind/folders"),
            Some(51),
        ),
        Err(Errno::EINVAL)
    );

    // Bind mount of external --state-dir into root/alias MUST be rejected!
    assert_eq!(
        super::sys::check_mountinfo_overlap(
            &mounts,
            Path::new("/tmp/work/root"),
            Some(28),
            Path::new("/tmp/outside_state"),
            Some(28),
            Path::new("/tmp/outside_state/folders"),
            Some(28),
        ),
        Err(Errno::EINVAL)
    );

    // Disjoint sibling state directory /tmp/work with folders at /tmp/work/folders MUST succeed!
    assert_eq!(
        super::sys::check_mountinfo_overlap(
            &mounts,
            Path::new("/tmp/work/root"),
            Some(28),
            Path::new("/tmp/work"),
            Some(28),
            Path::new("/tmp/work/folders"),
            Some(28),
        ),
        Ok(())
    );
}

#[test]
fn stalled_http_body_times_out_promptly_with_etimedout() {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, _rx) = mpsc::sync_channel(1);
    let server_handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        super::serve_http_connection(
            stream,
            "http://127.0.0.1:8787",
            "secret-tok",
            &tx,
            Duration::from_millis(120),
        );
    });

    let start = std::time::Instant::now();
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .write_all(
            b"POST / HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Origin: http://127.0.0.1:8787\r\n\
              Authorization: Bearer secret-tok\r\n\
              Content-Type: application/json\r\n\
              Content-Length: 65536\r\n\r\n\
              partial",
        )
        .unwrap();
    client.flush().unwrap();

    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    server_handle.join().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "stalled body took too long: {:?}",
        start.elapsed()
    );
    assert!(
        response.starts_with("HTTP/1.1 408 Request Timeout"),
        "{response}"
    );
    assert!(response.contains("ETIMEDOUT"), "{response}");
}

#[test]
fn surviving_hardlink_retains_metadata_when_open_dentry_unlinked() {
    let tmp = TempDir::new("hardlink-survive");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let owner = cred(1000, 1000, vec![1000], 0o022);
    let mut engine = open_engine(&root, &state, true, true);
    let att = attach(&mut engine, "tab-1", &owner, true, true);

    let (a_entry, a_open): (Entry, OpenRef) = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Create {
            ticket: ticket(),
            dir: att.root.clone(),
            name: "a.txt".into(),
            mode: 0o640,
            options: *OpenOptions::new().read(true).write(true).create_new(true),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Setxattr {
            handle: a_entry.handle.clone(),
            name: "user.keep".into(),
            value: abi::Bytes(b"yes".to_vec()),
            flags: XattrFlags::empty(),
        },
    )
    .unwrap();

    // Create an undiscovered host hard link `b.txt`, then remove `a.txt` externally while `a_open`
    // stays open so `/proc/self/fd/<fd>` reads `(deleted)` even though `stx.nlink == 1`.
    fs::hard_link(root.join("a.txt"), root.join("b.txt")).unwrap();
    fs::remove_file(root.join("a.txt")).unwrap();

    // Resolving `a_entry.handle` (to hit the `clone_open_fd` / `fd_relpath_inside_root == ENOENT`
    // path) and `OpenMetadata` must observe `nlink == 1` and NOT mark the inode unlinked.
    let meta: Metadata = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Metadata {
            handle: a_entry.handle.clone(),
        },
    )
    .unwrap();
    assert_eq!(meta.nlink, 1);

    // Closing `a_open` must NOT GC the surviving inode; lookup via `b.txt` keeps its ino/mode/xattr.
    call_unit(
        &mut engine,
        &att.session,
        &owner,
        Call::Release { open: a_open },
    )
    .unwrap();

    let b_entry: Entry = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Lookup {
            dir: att.root.clone(),
            name: "b.txt".into(),
        },
    )
    .unwrap();
    assert_eq!(b_entry.handle.node.ino, a_entry.handle.node.ino);
    assert_eq!(b_entry.metadata.mode, 0o640);
    let xval: abi::Bytes = call(
        &mut engine,
        &att.session,
        &owner,
        Call::Getxattr {
            handle: b_entry.handle,
            name: "user.keep".into(),
        },
    )
    .unwrap();
    assert_eq!(xval.0, b"yes");
}

#[test]
fn snapshot_subvol_and_fsuuid_distinguish_replaced_subfilesystems() {
    use super::store::HostInodeKey;
    use super::sys::{HostGen, HostKind};
    use os_core::permissions::Node;

    let tmp = TempDir::new("subvol-replace");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let root_fd = open_root_dir(&root).unwrap();
    let root_stx = super::sys::statx_fd(std::os::fd::AsFd::as_fd(&root_fd)).unwrap();
    let root_key = HostInodeKey::from_root(std::os::fd::AsFd::as_fd(&root_fd), &root_stx).unwrap();

    let mut store = StateStore::open(&root, &state, root_key).unwrap();
    let snap1_file = HostInodeKey {
        subfs_relpath: "snap".into(),
        subvol: Some(265),
        subfs_fsuuid: None,
        host_ino: 257,
        host_gen: HostGen::Btime {
            sec: 1_700_000_000,
            nsec: 123,
        },
        kind: HostKind::File,
    };
    let snap2_file = HostInodeKey {
        subvol: Some(266),
        ..snap1_file.clone()
    };
    let ino1 = store
        .insert_created(
            "snap/file.txt",
            snap1_file.clone(),
            Node::file(1000, 1000, 0o755, String::new(), 0),
            &|_| false,
        )
        .unwrap();
    let (ino2, dirty) = store
        .discover_or_reset("snap/file.txt", snap2_file, 2000, 2000, &|_| false)
        .unwrap();
    assert!(dirty);
    assert_ne!(ino1, ino2);
    assert_eq!(store.get(ino2).unwrap().node.mode, 0o600);
    assert_eq!(store.get(ino2).unwrap().node.owner, 2000);

    // Distinct backing filesystem UUIDs at identical `(subfs_relpath, ino, gen)` also reset cleanly.
    let mnt1_file = HostInodeKey {
        subfs_relpath: "mnt".into(),
        subvol: None,
        subfs_fsuuid: Some([1u8; 16]),
        host_ino: 12,
        host_gen: HostGen::Btime { sec: 55, nsec: 0 },
        kind: HostKind::File,
    };
    let mnt2_file = HostInodeKey {
        subfs_fsuuid: Some([2u8; 16]),
        ..mnt1_file.clone()
    };
    let mino1 = store
        .insert_created(
            "mnt/data",
            mnt1_file,
            Node::file(1000, 1000, 0o755, String::new(), 0),
            &|_| false,
        )
        .unwrap();
    let (mino2, m_dirty) = store
        .discover_or_reset("mnt/data", mnt2_file, 2000, 2000, &|_| false)
        .unwrap();
    assert!(m_dirty);
    assert_ne!(mino1, mino2);
    assert_eq!(store.get(mino2).unwrap().node.mode, 0o600);
}

#[test]
fn cross_parent_directory_rename_requires_source_write_permission() {
    let tmp = TempDir::new("dir-rename-write");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();

    let mut engine = open_engine(&root, &state, true, false);
    let root_user = cred(0, 0, vec![0], 0o022);
    let nonroot = cred(1000, 1000, vec![1000], 0o022);
    let att_user = attach(&mut engine, "c-user", &nonroot, true, false);
    let att_root = attach(&mut engine, "c-root", &root_user, true, false);

    let src_dir: Entry = call(
        &mut engine,
        &att_user.session,
        &nonroot,
        Call::Mkdir {
            dir: att_user.root.clone(),
            name: "src".into(),
            mode: 0o755,
        },
    )
    .unwrap();
    let dst_dir: Entry = call(
        &mut engine,
        &att_user.session,
        &nonroot,
        Call::Mkdir {
            dir: att_user.root.clone(),
            name: "dst".into(),
            mode: 0o755,
        },
    )
    .unwrap();
    let locked_dir: Entry = call(
        &mut engine,
        &att_user.session,
        &nonroot,
        Call::Mkdir {
            dir: src_dir.handle.clone(),
            name: "box".into(),
            mode: 0o555,
        },
    )
    .unwrap();
    let _ = locked_dir;

    // Cross-parent rename by non-root of a 0o555 directory fails with EACCES.
    assert_eq!(
        call_unit(
            &mut engine,
            &att_user.session,
            &nonroot,
            Call::Rename {
                from_dir: src_dir.handle.clone(),
                from: "box".into(),
                to_dir: dst_dir.handle.clone(),
                to: "box".into(),
                flags: RenameFlags::empty(),
            },
        ),
        Err(Errno::EACCES)
    );

    // Same-parent rename does not modify `..` and succeeds.
    call_unit(
        &mut engine,
        &att_user.session,
        &nonroot,
        Call::Rename {
            from_dir: src_dir.handle.clone(),
            from: "box".into(),
            to_dir: src_dir.handle.clone(),
            to: "box-same".into(),
            flags: RenameFlags::empty(),
        },
    )
    .unwrap();

    // Root bypasses source directory WRITE check cleanly across parents.
    let src_root: Entry = call(
        &mut engine,
        &att_root.session,
        &root_user,
        Call::Lookup {
            dir: att_root.root.clone(),
            name: "src".into(),
        },
    )
    .unwrap();
    let dst_root: Entry = call(
        &mut engine,
        &att_root.session,
        &root_user,
        Call::Lookup {
            dir: att_root.root.clone(),
            name: "dst".into(),
        },
    )
    .unwrap();
    call_unit(
        &mut engine,
        &att_root.session,
        &root_user,
        Call::Rename {
            from_dir: src_root.handle,
            from: "box-same".into(),
            to_dir: dst_root.handle,
            to: "box-moved".into(),
            flags: RenameFlags::empty(),
        },
    )
    .unwrap();
}

#[test]
fn discovered_wasm_binary_gets_owner_exec_while_text_gets_rw_only() {
    let tmp = TempDir::new("wasm-exec-discover");
    let root = tmp.path().join("root");
    let state = tmp.path().join("state");
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("prog.wasm"),
        [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x42],
    )
    .unwrap();
    fs::write(root.join("notes.txt"), b"plain text file").unwrap();

    let mut engine = open_engine(&root, &state, true, true);
    let user = cred(1000, 1000, vec![1000], 0o022);
    let att = attach(&mut engine, "c-wasm", &user, true, true);

    let prog: Entry = call(
        &mut engine,
        &att.session,
        &user,
        Call::Lookup {
            dir: att.root.clone(),
            name: "prog.wasm".into(),
        },
    )
    .unwrap();
    let notes: Entry = call(
        &mut engine,
        &att.session,
        &user,
        Call::Lookup {
            dir: att.root,
            name: "notes.txt".into(),
        },
    )
    .unwrap();
    assert_eq!(prog.metadata.mode, 0o700);
    assert_eq!(notes.metadata.mode, 0o600);
}
