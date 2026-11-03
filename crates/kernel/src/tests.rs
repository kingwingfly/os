use super::*;
use abi::{ACL_ACCESS, ACL_DEFAULT, O_DIRECTORY, O_TRUNC, O_WRONLY, XATTR_CREATE};
use std::collections::BTreeSet;
use terminal_worker_core::acl::Entries;

fn user(id: u32, groups: &[u32]) -> Identity {
    Identity {
        id,
        group: id,
        groups: groups.iter().copied().chain([id]).collect::<BTreeSet<_>>(),
    }
}
fn root() -> Process {
    Process {
        cred: Identity::root(),
        umask: 0o022,
    }
}
fn process(cred: &Identity) -> Process {
    Process {
        cred: cred.clone(),
        umask: 0o022,
    }
}
fn fs() -> MemStore {
    MemStore::new(User {
        id: 0,
        group: 0,
        groups: BTreeSet::new(),
        home: "/root".into(),
        locked: false,
        salt: String::new(),
        hash: String::new(),
    })
}
fn errno<T: std::fmt::Debug>(result: Result<T>) -> Errno {
    result.expect_err("should fail").errno
}
/// A directory `path`, root's, with `mode`, owned by `owner`.
fn dir(fs: &mut MemStore, path: &str, owner: u32, mode: u16) {
    mkdir(fs, &root(), path, 0o777).unwrap();
    chown(fs, &Identity::root(), path, Some(owner), Some(owner), true).unwrap();
    chmod(fs, &Identity::root(), path, mode).unwrap();
}
fn file(fs: &mut MemStore, path: &str, owner: u32, mode: u16) {
    mknod(fs, &root(), path, 0o666).unwrap();
    chown(fs, &Identity::root(), path, Some(owner), Some(owner), true).unwrap();
    chmod(fs, &Identity::root(), path, mode).unwrap();
}

#[test]
fn paths_resolve_part_by_part_with_each_directory_searched() {
    let mut fs = fs();
    let ann = user(1000, &[]);
    dir(&mut fs, "/a", 0, 0o755);
    dir(&mut fs, "/a/closed", 0, 0o700);
    file(&mut fs, "/a/closed/inside", 0, 0o644);
    file(&mut fs, "/a/f", 0, 0o644);
    assert_eq!(
        errno(stat(&fs, &ann, "/a/closed/inside", true)),
        Errno::EACCES
    );
    assert_eq!(errno(stat(&fs, &ann, "/a/missing/x", true)), Errno::ENOENT);
    assert_eq!(errno(stat(&fs, &ann, "/a/f/x", true)), Errno::ENOTDIR);
    assert_eq!(errno(stat(&fs, &ann, "/a/f/", true)), Errno::ENOTDIR);
    assert_eq!(errno(stat(&fs, &ann, "relative", true)), Errno::EINVAL);
    let long = format!("/{}", "x".repeat(256));
    assert_eq!(errno(stat(&fs, &ann, &long, true)), Errno::ENAMETOOLONG);
    assert!(stat(&fs, &ann, "/a/./f", true).unwrap().is_file());
}

#[test]
fn links_are_followed_on_the_way_and_at_the_end_if_asked_and_dotdot_is_physical() {
    let mut fs = fs();
    let cred = Identity::root();
    dir(&mut fs, "/real", 0, 0o755);
    dir(&mut fs, "/real/deep", 0, 0o755);
    dir(&mut fs, "/other", 0, 0o755);
    file(&mut fs, "/real/target", 0, 0o644);
    symlink(&mut fs, &cred, "/real/deep", "/other/link").unwrap();
    symlink(&mut fs, &cred, "target", "/real/rel").unwrap();
    // `..` after a link is the parent of where it led, as on Linux.
    assert!(
        stat(&fs, &cred, "/other/link/../target", true)
            .unwrap()
            .is_file()
    );
    assert!(stat(&fs, &cred, "/real/rel", true).unwrap().is_file());
    let link = stat(&fs, &cred, "/real/rel", false).unwrap();
    assert!(link.is_link());
    assert_eq!(link.link.as_deref(), Some("target"));
    assert_eq!(readlink(&fs, &cred, "/real/rel").unwrap(), "target");
    assert_eq!(errno(readlink(&fs, &cred, "/real/target")), Errno::EINVAL);
    symlink(&mut fs, &cred, "/loop2", "/loop1").unwrap();
    symlink(&mut fs, &cred, "/loop1", "/loop2").unwrap();
    assert_eq!(errno(stat(&fs, &cred, "/loop1", true)), Errno::ELOOP);
    assert!(stat(&fs, &cred, "/loop1", false).is_ok());
    symlink(&mut fs, &cred, "/nowhere", "/dangling").unwrap();
    assert_eq!(errno(stat(&fs, &cred, "/dangling", true)), Errno::ENOENT);
}

#[test]
fn a_link_in_a_shared_sticky_directory_is_followed_only_as_its_owner_or_the_directorys() {
    let mut fs = fs();
    let (ann, bob) = (user(1000, &[]), user(1001, &[]));
    dir(&mut fs, "/tmp", 0, 0o1777);
    file(&mut fs, "/tmp/secret", 1001, 0o644);
    symlink(&mut fs, &ann, "/tmp/secret", "/tmp/trap").unwrap();
    assert_eq!(errno(stat(&fs, &bob, "/tmp/trap", true)), Errno::EACCES);
    assert!(stat(&fs, &ann, "/tmp/trap", true).is_ok());
    assert!(stat(&fs, &Identity::root(), "/tmp/trap", true).is_ok());
}

#[test]
fn what_is_made_takes_the_umask_the_setgid_group_and_a_default_acl() {
    let mut fs = fs();
    let ann = user(1000, &[50]);
    dir(&mut fs, "/shared", 1000, 0o2775);
    chown(&mut fs, &Identity::root(), "/shared", None, Some(50), true).unwrap();
    mkdir(&mut fs, &process(&ann), "/shared/sub", 0o777).unwrap();
    let sub = stat(&fs, &ann, "/shared/sub", true).unwrap();
    assert_eq!((sub.gid, sub.perm()), (50, 0o2755));
    mknod(&mut fs, &process(&ann), "/shared/file", 0o666).unwrap();
    assert_eq!(stat(&fs, &ann, "/shared/file", true).unwrap().perm(), 0o644);
    assert_eq!(
        errno(mkdir(&mut fs, &process(&ann), "/shared/sub", 0o777)),
        Errno::EEXIST
    );
    assert_eq!(
        errno(mkdir(&mut fs, &process(&ann), "/shared/..", 0o777)),
        Errno::EEXIST
    );
    // A default ACL bounds what is made by it, and the umask is not taken off.
    let default = Entries {
        user: 7,
        group: 7,
        other: 0,
        mask: Some(7),
        users: [(1001, 5)].into(),
        ..Entries::default()
    };
    let value = serde_json::to_vec(&default).unwrap();
    xattr::set(&mut fs, &ann, "/shared/sub", ACL_DEFAULT, &value, 0, true).unwrap();
    mknod(&mut fs, &process(&ann), "/shared/sub/made", 0o640).unwrap();
    let made = fs.node("/shared/sub/made").unwrap();
    assert_eq!(made.mode & 0o777, 0o640);
    assert!(permission(&user(1001, &[]), &made, READ));
    assert!(!permission(&user(1001, &[]), &made, WRITE));
}

#[test]
fn a_home_not_made_yet_is_its_accounts_to_make() {
    let mut fs = fs();
    dir(&mut fs, "/guest", 0, 0o1777);
    let ann = User {
        id: 1000,
        group: 1000,
        groups: BTreeSet::new(),
        home: "/guest/ann".into(),
        locked: false,
        salt: String::new(),
        hash: String::new(),
    };
    fs.set_user("ann", &ann);
    let error = mkdir(&mut fs, &process(&user(1001, &[])), "/guest/ann", 0o700).unwrap_err();
    assert_eq!(error.errno, Errno::EACCES);
    assert_eq!(error.to_string(), "/guest/ann is another account's home");
    mkdir(&mut fs, &process(&user(1000, &[])), "/guest/ann", 0o700).unwrap();
}

#[test]
fn rmdir_and_unlink_take_one_name_as_linux_does() {
    let mut fs = fs();
    let (ann, bob) = (user(1000, &[]), user(1001, &[]));
    dir(&mut fs, "/tmp", 0, 0o1777);
    dir(&mut fs, "/tmp/full", 1000, 0o755);
    file(&mut fs, "/tmp/full/f", 1000, 0o644);
    file(&mut fs, "/tmp/ann", 1000, 0o666);
    assert_eq!(errno(rmdir(&mut fs, &ann, "/tmp/full")), Errno::ENOTEMPTY);
    assert_eq!(errno(rmdir(&mut fs, &ann, "/tmp/ann")), Errno::ENOTDIR);
    assert_eq!(errno(rmdir(&mut fs, &ann, "/")), Errno::EBUSY);
    assert_eq!(errno(rmdir(&mut fs, &ann, "/tmp/full/.")), Errno::EINVAL);
    // The directory a `..` is in is found first, as Linux does.
    assert_eq!(
        errno(rmdir(&mut fs, &ann, "/tmp/missing/..")),
        Errno::ENOENT
    );
    assert_eq!(
        errno(rmdir(&mut fs, &ann, "/tmp/full/..")),
        Errno::ENOTEMPTY
    );
    assert_eq!(errno(unlink(&mut fs, &ann, "/tmp/full")), Errno::EISDIR);
    // In a sticky directory, another's file stays, even if it may be written.
    assert_eq!(errno(unlink(&mut fs, &bob, "/tmp/ann")), Errno::EPERM);
    // Whether the name may go is asked before what it names, as may_delete does.
    assert_eq!(errno(rmdir(&mut fs, &bob, "/tmp")), Errno::EACCES);
    assert_eq!(errno(rmdir(&mut fs, &bob, "/tmp/full")), Errno::EPERM);
    assert_eq!(errno(unlink(&mut fs, &bob, "/tmp")), Errno::EACCES);
    unlink(&mut fs, &ann, "/tmp/full/f").unwrap();
    rmdir(&mut fs, &ann, "/tmp/full").unwrap();
    assert_eq!(errno(stat(&fs, &ann, "/tmp/full", true)), Errno::ENOENT);
}

#[test]
fn open_follows_a_link_to_what_it_names_and_checks_as_linux_does() {
    let mut fs = fs();
    let (ann, bob) = (process(&user(1000, &[])), process(&user(1001, &[])));
    dir(&mut fs, "/d", 1000, 0o755);
    file(&mut fs, "/d/r", 0, 0o644);
    symlink(&mut fs, &Identity::root(), "/d/new", "/d/dangling").unwrap();
    assert!(matches!(
        open(&fs, &ann, "/d/r", O_RDONLY, 0),
        Ok(Opening::Existing { .. })
    ));
    assert_eq!(
        errno(open(&fs, &ann, "/d/r", O_WRONLY | O_TRUNC, 0)),
        Errno::EACCES
    );
    let excl = O_WRONLY | O_CREAT | O_EXCL;
    assert_eq!(errno(open(&fs, &ann, "/d/r", excl, 0o666)), Errno::EEXIST);
    // A directory opens to read, as Linux's does, and only to read; O_DIRECTORY opens nothing
    // else.
    assert!(matches!(
        open(&fs, &ann, "/d", O_RDONLY, 0),
        Ok(Opening::Existing { .. })
    ));
    assert_eq!(errno(open(&fs, &ann, "/d", O_WRONLY, 0)), Errno::EISDIR);
    assert_eq!(
        errno(open(&fs, &ann, "/d/missing", O_DIRECTORY, 0)),
        Errno::ENOENT
    );
    assert_eq!(
        errno(open(&fs, &ann, "/d/none", O_WRONLY, 0)),
        Errno::ENOENT
    );
    // A link leading nowhere makes what it names, unless O_EXCL, which takes it as there.
    let Ok(Opening::New { path, node }) = open(&fs, &ann, "/d/dangling", O_WRONLY | O_CREAT, 0o666)
    else {
        panic!("a dangling link makes its target");
    };
    assert_eq!(
        (path.as_str(), node.owner, node.mode & 0o777),
        ("/d/new", 1000, 0o644)
    );
    assert_eq!(
        errno(open(&fs, &ann, "/d/dangling", excl, 0o666)),
        Errno::EEXIST
    );
    assert_eq!(
        errno(open(&fs, &bob, "/d/x", O_WRONLY | O_CREAT, 0o666)),
        Errno::EACCES
    );
}

#[test]
fn rename_replaces_as_linux_does_and_never_moves_a_directory_into_itself() {
    let mut fs = fs();
    let ann = user(1000, &[]);
    dir(&mut fs, "/w", 1000, 0o755);
    dir(&mut fs, "/w/d", 1000, 0o755);
    dir(&mut fs, "/w/empty", 1000, 0o755);
    dir(&mut fs, "/w/full", 1000, 0o755);
    file(&mut fs, "/w/full/x", 1000, 0o644);
    file(&mut fs, "/w/a", 1000, 0o644);
    file(&mut fs, "/w/b", 1000, 0o644);
    file(&mut fs, "/w/d/inside", 1000, 0o644);
    assert_eq!(
        errno(rename(&mut fs, &ann, "/w/a", "/w/b", true)),
        Errno::EEXIST
    );
    rename(&mut fs, &ann, "/w/a", "/w/b", false).unwrap();
    assert_eq!(errno(stat(&fs, &ann, "/w/a", true)), Errno::ENOENT);
    assert_eq!(
        errno(rename(&mut fs, &ann, "/w/d", "/w/d/x", false)),
        Errno::EINVAL
    );
    assert_eq!(
        errno(rename(&mut fs, &ann, "/w/d", "/w/d/inside/x", false)),
        Errno::ENOTDIR
    );
    assert_eq!(
        errno(rename(&mut fs, &ann, "/w/d", "/w/b", false)),
        Errno::ENOTDIR
    );
    assert_eq!(
        errno(rename(&mut fs, &ann, "/w/b", "/w/d", false)),
        Errno::EISDIR
    );
    assert_eq!(
        errno(rename(&mut fs, &ann, "/w/d", "/w/full", false)),
        Errno::ENOTEMPTY
    );
    rename(&mut fs, &ann, "/w/d", "/w/empty", false).unwrap();
    assert!(stat(&fs, &ann, "/w/empty/inside", true).unwrap().is_file());
    // A directory moving to another directory needs w on itself.
    dir(&mut fs, "/w/locked", 1000, 0o555);
    dir(&mut fs, "/w/to", 1000, 0o755);
    let mut cred = ann.clone();
    cred.id = 1001;
    chmod(&mut fs, &Identity::root(), "/w", 0o777).unwrap();
    chmod(&mut fs, &Identity::root(), "/w/to", 0o777).unwrap();
    assert_eq!(
        errno(rename(&mut fs, &cred, "/w/locked", "/w/to/locked", false)),
        Errno::EACCES
    );
}

#[test]
fn a_device_is_neither_renamed_nor_linked() {
    let mut fs = fs();
    dir(&mut fs, "/dev", 0, 0o755);
    fs.set_node("/dev/x", &Node::device(0, 0, 0o644, "present"));
    let stat = stat(&fs, &Identity::root(), "/dev/x", true).unwrap();
    assert_eq!(
        (stat.kind(), stat.rdev.as_deref()),
        (abi::S_IFCHR, Some("present"))
    );
    assert_eq!(
        errno(rename(&mut fs, &Identity::root(), "/dev/x", "/y", false)),
        Errno::EPERM
    );
    assert_eq!(
        errno(link(&mut fs, &Identity::root(), "/dev/x", "/y", false)),
        Errno::EPERM
    );
}

#[test]
fn hard_links_of_anothers_file_need_it_to_be_safe_to_link() {
    let mut fs = fs();
    let ann = user(1000, &[]);
    dir(&mut fs, "/w", 1000, 0o777);
    file(&mut fs, "/w/mine", 1000, 0o644);
    file(&mut fs, "/w/theirs", 1001, 0o644);
    file(&mut fs, "/w/open", 1001, 0o666);
    link(&mut fs, &ann, "/w/mine", "/w/mine2", false).unwrap();
    assert_eq!(stat(&fs, &ann, "/w/mine", true).unwrap().nlink, 2);
    assert_eq!(
        errno(link(&mut fs, &ann, "/w/theirs", "/w/t2", false)),
        Errno::EPERM
    );
    link(&mut fs, &ann, "/w/open", "/w/o2", false).unwrap();
    assert_eq!(
        errno(link(&mut fs, &ann, "/w", "/w/self", false)),
        Errno::EPERM
    );
    assert_eq!(
        errno(link(&mut fs, &ann, "/w/mine", "/w/mine2", false)),
        Errno::EEXIST
    );
}

#[test]
fn modes_and_owners_change_as_their_owner_or_root_may() {
    let mut fs = fs();
    let (ann, bob) = (user(1000, &[50]), user(1001, &[]));
    dir(&mut fs, "/w", 0, 0o777);
    file(&mut fs, "/w/f", 1000, 0o644);
    assert_eq!(errno(chmod(&mut fs, &bob, "/w/f", 0o777)), Errno::EPERM);
    chmod(&mut fs, &ann, "/w/f", 0o2755).unwrap();
    assert_eq!(stat(&fs, &ann, "/w/f", true).unwrap().perm(), 0o2755);
    chown(&mut fs, &Identity::root(), "/w/f", None, Some(60), true).unwrap();
    chmod(&mut fs, &ann, "/w/f", 0o2755).unwrap();
    // setgid needs the file's group to be one of the caller's: cleared otherwise.
    assert_eq!(stat(&fs, &ann, "/w/f", true).unwrap().perm(), 0o755);
    assert_eq!(
        errno(chown(&mut fs, &ann, "/w/f", Some(1001), None, true)),
        Errno::EPERM
    );
    assert_eq!(
        errno(chown(&mut fs, &ann, "/w/f", None, Some(60), true)),
        Errno::EPERM
    );
    chown(&mut fs, &ann, "/w/f", None, Some(50), true).unwrap();
    chmod(&mut fs, &ann, "/w/f", 0o4755).unwrap();
    chown(&mut fs, &Identity::root(), "/w/f", Some(1001), None, true).unwrap();
    assert_eq!(stat(&fs, &ann, "/w/f", true).unwrap().perm(), 0o755);
    // Root executes only what someone may.
    let plain = Node::file(0, 0, 0o644, "x".into(), 0);
    assert!(!permission(&Identity::root(), &plain, EXEC));
    assert!(permission(&Identity::root(), &plain, READ | WRITE));
    // Its times are its owner's, root's, or a writer's to set to now; a time given, its owner's
    // or root's only.
    let now =
        |fs: &mut MemStore, who: &Identity| utimens(fs, who, "/w/f", Time::Now, Time::Now, true);
    assert_eq!(errno(now(&mut fs, &user(1002, &[]))), Errno::EACCES);
    now(&mut fs, &bob).unwrap();
    let given = Time::At { sec: 1, nsec: 0 };
    assert_eq!(
        errno(utimens(&mut fs, &ann, "/w/f", given, Time::Omit, true)),
        Errno::EPERM
    );
    utimens(&mut fs, &bob, "/w/f", Time::Omit, given, true).unwrap();
    // Leaving both is nothing to ask.
    utimens(
        &mut fs,
        &user(1002, &[]),
        "/w/f",
        Time::Omit,
        Time::Omit,
        true,
    )
    .unwrap();
}

#[test]
fn a_directory_read_but_not_searched_lists_names_without_what_they_are() {
    let mut fs = fs();
    let ann = user(1000, &[]);
    dir(&mut fs, "/r", 0, 0o744);
    file(&mut fs, "/r/f", 0, 0o644);
    let entries = getdents(&fs, &ann, "/r").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (entries[0].name.as_str(), entries[0].stat.is_none()),
        ("f", true)
    );
    chmod(&mut fs, &Identity::root(), "/r", 0o711).unwrap();
    assert_eq!(errno(getdents(&fs, &ann, "/r")), Errno::EACCES);
    assert_eq!(errno(getdents(&fs, &ann, "/r/f")), Errno::ENOTDIR);
    chmod(&mut fs, &Identity::root(), "/r", 0o755).unwrap();
    assert!(
        getdents(&fs, &ann, "/r").unwrap()[0]
            .stat
            .as_ref()
            .unwrap()
            .is_file()
    );
}

#[test]
fn extended_attributes_and_acls_follow_linuxs_rules() {
    let mut fs = fs();
    let (ann, bob) = (user(1000, &[]), user(1001, &[]));
    dir(&mut fs, "/w", 0, 0o777);
    file(&mut fs, "/w/f", 1000, 0o644);
    symlink(&mut fs, &ann, "/w/f", "/w/l").unwrap();
    xattr::set(
        &mut fs,
        &ann,
        "/w/f",
        "user.note",
        b"hi",
        XATTR_CREATE,
        true,
    )
    .unwrap();
    assert_eq!(
        errno(xattr::set(
            &mut fs,
            &ann,
            "/w/f",
            "user.note",
            b"x",
            XATTR_CREATE,
            true
        )),
        Errno::EEXIST
    );
    assert_eq!(
        xattr::get(&fs, &bob, "/w/f", "user.note", true).unwrap(),
        b"hi"
    );
    assert_eq!(
        errno(xattr::set(
            &mut fs,
            &bob,
            "/w/f",
            "user.note",
            b"x",
            0,
            true
        )),
        Errno::EACCES
    );
    assert_eq!(
        errno(xattr::set(
            &mut fs,
            &ann,
            "/w/l",
            "user.note",
            b"x",
            0,
            false
        )),
        Errno::EPERM
    );
    assert_eq!(
        errno(xattr::set(
            &mut fs,
            &ann,
            "/w/f",
            "trusted.x",
            b"x",
            0,
            true
        )),
        Errno::EPERM
    );
    assert_eq!(
        errno(xattr::set(
            &mut fs,
            &ann,
            "/w/f",
            "security.x",
            b"x",
            0,
            true
        )),
        Errno::EOPNOTSUPP
    );
    xattr::set(
        &mut fs,
        &Identity::root(),
        "/w/f",
        "trusted.x",
        b"t",
        0,
        true,
    )
    .unwrap();
    assert_eq!(xattr::list(&fs, &ann, "/w/f", true).unwrap(), ["user.note"]);
    assert_eq!(
        errno(xattr::get(&fs, &ann, "/w/f", "trusted.x", true)),
        Errno::ENODATA
    );
    // An ACL is set by its owner, and decides as one set by setfacl does.
    let mut entries = fs.node("/w/f").unwrap().entries();
    entries.users.insert(1001, 6);
    entries.mask = Some(6);
    let value = serde_json::to_vec(&entries).unwrap();
    assert_eq!(
        errno(xattr::set(
            &mut fs, &bob, "/w/f", ACL_ACCESS, &value, 0, true
        )),
        Errno::EPERM
    );
    xattr::set(&mut fs, &ann, "/w/f", ACL_ACCESS, &value, 0, true).unwrap();
    assert!(permission(&bob, &fs.node("/w/f").unwrap(), READ | WRITE));
    assert!(stat(&fs, &ann, "/w/f", true).unwrap().acl);
    let read: Entries =
        serde_json::from_slice(&xattr::get(&fs, &bob, "/w/f", ACL_ACCESS, true).unwrap()).unwrap();
    assert_eq!(read.users.get(&1001), Some(&6));
    assert_eq!(
        errno(xattr::set(
            &mut fs,
            &ann,
            "/w/f",
            ACL_DEFAULT,
            &value,
            0,
            true
        )),
        Errno::EACCES
    );
    xattr::remove(&mut fs, &ann, "/w/f", ACL_ACCESS, true).unwrap();
    assert!(!permission(&bob, &fs.node("/w/f").unwrap(), WRITE));
    assert_eq!(
        errno(xattr::remove(&mut fs, &ann, "/w/f", ACL_ACCESS, true)),
        Errno::ENODATA
    );
    // Named entries need a mask.
    let mut maskless = fs.node("/w/f").unwrap().entries();
    maskless.users.insert(1001, 6);
    let value = serde_json::to_vec(&maskless).unwrap();
    assert_eq!(
        errno(xattr::set(
            &mut fs, &ann, "/w/f", ACL_ACCESS, &value, 0, true
        )),
        Errno::EINVAL
    );
}

#[test]
fn calls_dispatch_with_their_values_and_errors() {
    let mut fs = fs();
    let made = call(
        &mut fs,
        &root(),
        Call::Mkdir {
            path: "/d".into(),
            mode: 0o777,
        },
    );
    assert_eq!(made, Ok(Value::Null));
    let stat: Stat =
        serde_json::from_value(call(&mut fs, &root(), Call::Stat { path: "/d".into() }).unwrap())
            .unwrap();
    assert_eq!(stat.perm(), 0o755);
    assert!(stat.is_dir());
    let failed = call(
        &mut fs,
        &root(),
        Call::Rmdir {
            path: "/nothing".into(),
        },
    );
    assert_eq!(failed.unwrap_err().errno, Errno::ENOENT);
}
