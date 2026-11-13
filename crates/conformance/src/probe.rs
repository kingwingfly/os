//! One program, native Linux and ordinary OS WASI/WASIX execution. Each observation
//! is a call result, not an assertion about what a provider ought to implement.
use crate::platform;
use platform::{Result, io};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

struct Probe {
    root: PathBuf,
    alias: PathBuf,
    cross: PathBuf,
    uid: u64,
    gid: u64,
}
fn emit(case: &str, step: &str, call: &str, result: Result<Value>) {
    let mut row = json!({"case":case,"step":step,"call":call});
    match result {
        Ok(v) => row["ok"] = v,
        Err(e) => row["errno"] = json!(e),
    }
    println!("{row}");
}
fn unit(case: &str, step: &str, call: &str, result: Result<()>) {
    emit(case, step, call, result.map(|_| json!(null)));
}
fn skipped(case: &str, reason: &str) {
    skip_step(case, "unavailable", case, reason);
}
fn skip_step(case: &str, step: &str, call: &str, reason: &str) {
    println!(
        "{}",
        json!({"case":case,"step":step,"call":call,"skipped":reason})
    );
}
fn acl_step(case: &str, step: &str, call: &str, operation: impl FnOnce() -> Result<Value>) {
    if platform::named_acl_available() {
        emit(case, step, call, operation());
    } else {
        skip_step(
            case,
            step,
            call,
            "named ACL group 65534 is not mapped in this user namespace",
        );
    }
}
fn write(path: &Path, text: &[u8]) -> Result<()> {
    io(fs::write(path, text))
}
fn read(f: &mut File) -> Result<Value> {
    io(f.seek(SeekFrom::Start(0)))?;
    let mut s = String::new();
    io(f.read_to_string(&mut s))?;
    Ok(json!(s))
}
fn rw(path: &Path) -> Result<File> {
    io(OpenOptions::new().read(true).write(true).open(path))
}
impl Probe {
    fn stat(&self, path: &Path) -> Result<Value> {
        let mut v = platform::stat(path)?;
        v["owner_is_caller"] = json!(v["uid"] == self.uid);
        v["group_is_caller"] = json!(v["gid"] == self.gid);
        match platform::stat(path.parent().unwrap()) {
            Ok(parent) => {
                v["group_is_parent"] = json!(v["gid"] == parent["gid"]);
                v["owner_is_parent"] = json!(v["uid"] == parent["uid"]);
            }
            Err(errno) => {
                v["group_is_parent"] = json!({"errno": errno});
                v["owner_is_parent"] = json!({"errno": errno});
            }
        }
        v.as_object_mut().unwrap().remove("uid");
        v.as_object_mut().unwrap().remove("gid");
        Ok(v)
    }
    fn same(&self, a: &Path, b: &Path) -> Result<Value> {
        let a = platform::identity(a)?;
        let b = platform::identity(b)?;
        Ok(platform::identity_relation(a, b))
    }
    fn with_mounts(&self, available: bool, cases: &[&str], measure: impl FnOnce()) {
        if available {
            measure();
        } else {
            for case in cases {
                skipped(
                    case,
                    "rootless mount namespace unavailable; see linux-evidence.json",
                );
            }
        }
    }
    fn basic(&self, mounts: bool, cloud: bool) {
        let p = |s: &str| self.root.join(s);
        self.with_mounts(mounts, &["alias"], || {
            if cloud {
                skipped(
                    "alias",
                    "not implemented: cloud tree has no second attachment API",
                );
                return;
            }
            unit(
                "alias",
                "create",
                "write(file, 'hello')",
                write(&p("alias-file"), b"hello"),
            );
            emit(
                "alias",
                "identity",
                "stat(primary); stat(alias)",
                self.same(&p("alias-file"), &self.alias.join("alias-file")),
            );
            unit(
                "alias",
                "chmod",
                "chmod(primary, 0640)",
                platform::chmod(&p("alias-file"), 0o640),
            );
            emit(
                "alias",
                "mode",
                "stat(alias)",
                self.stat(&self.alias.join("alias-file")),
            );
            acl_step("alias", "setfacl", "setfacl(primary, named group)", || {
                platform::setacl(&p("alias-file"), false).map(|_| json!(null))
            });
            acl_step("alias", "acl", "getfacl(alias)", || {
                platform::acl(&self.alias.join("alias-file"))
            });
        });
        for (case, unlink) in [("open-rename", false), ("open-unlink", true)] {
            let path = p(case);
            unit(
                case,
                "create",
                "write(file, 'hello')",
                write(&path, b"hello"),
            );
            match rw(&path) {
                Err(e) => emit(case, "open", "open(O_RDWR)", Err(e)),
                Ok(mut f) => {
                    emit(case, "open", "open(O_RDWR)", Ok(json!(null)));
                    let before = platform::fdidentity(&f);
                    unit(
                        case,
                        "identity-before",
                        "fstat(fd) identity before change",
                        before.clone().map(|_| ()),
                    );
                    unit(
                        case,
                        "change",
                        if unlink {
                            "unlink(file)"
                        } else {
                            "rename(file, moved)"
                        },
                        io(if unlink {
                            fs::remove_file(&path)
                        } else {
                            fs::rename(&path, p("renamed"))
                        }),
                    );
                    emit(case, "read", "pread(fd, 0)", read(&mut f));
                    unit(
                        case,
                        "write",
                        "pwrite(fd, 0, 'HELLO')",
                        io(f.seek(SeekFrom::Start(0))).and_then(|_| io(f.write_all(b"HELLO"))),
                    );
                    emit(case, "fstat", "fstat(fd)", platform::fdstat(&f));
                    let after = platform::fdidentity(&f);
                    unit(
                        case,
                        "identity-after",
                        "fstat(fd) identity after change",
                        after.clone().map(|_| ()),
                    );
                    match (before, after) {
                        (Ok(before), Ok(after)) => emit(
                            case,
                            "identity",
                            "fstat(fd) identity before/after",
                            Ok(platform::identity_relation(before, after)),
                        ),
                        _ => skip_step(
                            case,
                            "identity",
                            "fstat(fd) identity before/after",
                            "identity comparison requires successful before and after fstat; see phase results",
                        ),
                    }
                    emit(case, "reread", "pread(fd, 0)", read(&mut f));
                }
            }
        }
        let path = p("flush");
        unit(
            "flush",
            "create",
            "write(file, 'hello')",
            write(&path, b"hello"),
        );
        match rw(&path) {
            Ok(f) => {
                unit("flush", "fsync", "fsync(fd)", io(f.sync_all()));
                unit("flush", "fdatasync", "fdatasync(fd)", io(f.sync_data()));
            }
            Err(e) => emit("flush", "open", "open(O_RDWR)", Err(e)),
        }
        unit(
            "flush",
            "invalid-sync",
            "fsync(-1)",
            platform::invalid_sync(false),
        );
        unit(
            "flush",
            "invalid-datasync",
            "fdatasync(-1)",
            platform::invalid_sync(true),
        );
        // Success alone is not a durability guarantee.
        unit(
            "exclusive",
            "create",
            "write(existing, 'old')",
            write(&p("exclusive"), b"old"),
        );
        emit(
            "exclusive",
            "open",
            "open(existing, O_CREAT|O_EXCL|O_WRONLY)",
            io(OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(p("exclusive")))
            .map(|_| json!(null)),
        );
        unit(
            "append",
            "create",
            "write(file, 'old')",
            write(&p("append"), b"old"),
        );
        unit(
            "append",
            "append",
            "open(O_APPEND); seek(0); write('new')",
            io(OpenOptions::new().append(true).open(p("append"))).and_then(|mut f| {
                io(f.seek(SeekFrom::Start(0)))?;
                io(f.write_all(b"new"))
            }),
        );
        emit(
            "append",
            "read",
            "read(file)",
            io(fs::read_to_string(p("append"))).map(|s| json!(s)),
        );
        unit(
            "noreplace",
            "source",
            "write(source)",
            write(&p("nr-a"), b"a"),
        );
        unit(
            "noreplace",
            "destination",
            "write(destination)",
            write(&p("nr-b"), b"b"),
        );
        unit(
            "noreplace",
            "rename",
            "renameat2(RENAME_NOREPLACE)",
            platform::noreplace(&p("nr-a"), &p("nr-b")),
        );
        emit(
            "noreplace",
            "contents",
            "read(destination)",
            io(fs::read_to_string(p("nr-b"))).map(|s| json!(s)),
        );
        unit(
            "hard-link",
            "create",
            "write(source)",
            write(&p("hard-a"), b"hello"),
        );
        unit(
            "hard-link",
            "link",
            "link(source, destination)",
            io(fs::hard_link(p("hard-a"), p("hard-b"))),
        );
        emit("hard-link", "stat", "stat(source)", self.stat(&p("hard-a")));
        emit(
            "hard-link",
            "identity",
            "stat(source); stat(destination)",
            self.same(&p("hard-a"), &p("hard-b")),
        );
        unit(
            "symlink",
            "create",
            "symlink('hard-a', link)",
            platform::symlink(Path::new("hard-a"), &p("relative-link")),
        );
        emit(
            "symlink",
            "read",
            "read(link)",
            io(fs::read_to_string(p("relative-link"))).map(|s| json!(s)),
        );
        self.with_mounts(mounts, &["cross-rename"], || {
            unit(
                "cross-rename",
                "create",
                "write(source)",
                write(&p("cross"), b"hello"),
            );
            unit(
                "cross-rename",
                "rename",
                "rename(source, other-mount/destination)",
                io(fs::rename(p("cross"), self.cross.join("cross-destination"))),
            );
        });
        self.with_mounts(mounts, &["mount-parent"], || {
            if cloud {
                skipped(
                    "mount-parent",
                    "account home is a subdirectory; no cloud mount-root attachment API",
                );
                return;
            }
            emit(
                "mount-parent",
                "stat",
                "stat(mount/..) is parent",
                self.same(&p(".."), self.root.parent().unwrap()),
            );
        });
        unit(
            "link-dotdot",
            "mkdir-a",
            "mkdir(a)",
            io(fs::create_dir(p("a"))),
        );
        unit(
            "link-dotdot",
            "mkdir-b",
            "mkdir(a/b)",
            io(fs::create_dir(p("a/b"))),
        );
        unit(
            "link-dotdot",
            "link",
            "symlink('a/b', link)",
            platform::symlink(Path::new("a/b"), &p("dir-link")),
        );
        unit(
            "link-dotdot",
            "chdir",
            "chdir(link/..)",
            platform::cd(&p("dir-link/..")),
        );
        emit(
            "link-dotdot",
            "getcwd",
            "getcwd() equals a",
            platform::cwd().map(|s| json!(s == p("a").to_string_lossy())),
        );
        unit(
            "link-dotdot",
            "restore",
            "chdir(root)",
            platform::cd(&self.root),
        );
        self.with_mounts(mounts, &["absolute-symlink"], || {
            unit(
                "absolute-symlink",
                "link",
                "symlink(absolute other-mount/file, link)",
                platform::symlink(&self.cross.join("target"), &p("absolute-link")),
            );
            emit(
                "absolute-symlink",
                "read",
                "read(absolute-link)",
                io(fs::read_to_string(p("absolute-link"))).map(|s| json!(s)),
            );
        });
        for (case, removed) in [("cwd-rename", false), ("cwd-remove", true)] {
            let path = p(case);
            unit(case, "mkdir", "mkdir(directory)", io(fs::create_dir(&path)));
            unit(case, "chdir", "chdir(directory)", platform::cd(&path));
            unit(
                case,
                "change",
                if removed {
                    "rmdir(cwd)"
                } else {
                    "rename(cwd, moved)"
                },
                io(if removed {
                    fs::remove_dir(&path)
                } else {
                    fs::rename(&path, p("cwd-moved"))
                }),
            );
            emit(
                case,
                "getcwd",
                "getcwd()",
                platform::cwd().map(|s| json!(s.replace(self.root.to_str().unwrap(), "$ROOT"))),
            );
            unit(case, "restore", "chdir(root)", platform::cd(&self.root));
        }
        unit(
            "creation",
            "mkdir",
            "mkdir(shared)",
            io(fs::create_dir(p("creation"))),
        );
        unit(
            "creation",
            "setgid",
            "chmod(shared, 02770)",
            platform::chmod(&p("creation"), 0o2770),
        );
        self.directory_facts("creation", "directory", &p("creation"));
        acl_step(
            "creation",
            "default-acl",
            "setfacl(default, shared)",
            || platform::setacl(&p("creation"), true).map(|_| json!(null)),
        );
        platform::umask(0o027);
        acl_step(
            "creation",
            "create",
            "umask(027); open(O_CREAT, 0666)",
            || write(&p("creation/file"), b"hello").map(|_| json!(null)),
        );
        acl_step("creation", "stat", "stat(created)", || {
            self.stat(&p("creation/file"))
        });
        acl_step("creation", "acl", "getfacl(created)", || {
            platform::acl(&p("creation/file"))
        });
        self.inheritance(
            "creation",
            "inheritance",
            &p("creation"),
            &p("creation/file"),
        );
        platform::umask(0o022);
    }
    fn remount(&self, prepare: bool) {
        let path = self.root.join("remount");
        if prepare {
            unit("remount", "create", "write(file)", write(&path, b"hello"));
            unit(
                "remount",
                "chmod",
                "chmod(file, 0640)",
                platform::chmod(&path, 0o640),
            );
            acl_step("remount", "setfacl", "setfacl(file, named group)", || {
                platform::setacl(&path, false).map(|_| json!(null))
            });
        } else {
            acl_step("remount", "stat", "stat(file) after detach/attach", || {
                self.stat(&path)
            });
            acl_step(
                "remount",
                "acl",
                "getfacl(file) after detach/attach",
                || platform::acl(&path),
            );
        }
    }
    fn hold(&self, cwd: bool) -> bool {
        let case = if cwd { "unmount-cwd" } else { "unmount-open" };
        let path = self.root.join(case);
        unit(case, "create", "write(file)", write(&path, b"hello"));
        let mut file = if cwd {
            None
        } else {
            match rw(&path) {
                Ok(f) => Some(f),
                Err(e) => {
                    emit(case, "open", "open(O_RDWR)", Err(e));
                    return false;
                }
            }
        };
        if cwd {
            let result = platform::cd(&self.root);
            let failed = result.is_err();
            unit(case, "chdir", "chdir(mount)", result);
            if failed {
                return false;
            }
        }
        #[cfg(target_os = "wasi")]
        {
            // Runner detaches only after observing this barrier, then releases stdin.
            println!("{}", json!({"barrier":case}));
            std::io::stdout().flush().unwrap();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line).unwrap();
        }
        #[cfg(target_os = "linux")]
        let detached = {
            let plain = platform::unmount(&self.root);
            let plain_detached = plain.is_ok();
            unit(case, "unmount", "umount(mount)", plain);
            let result = platform::detach(&self.root);
            let detached = plain_detached || result.is_ok();
            unit(case, "detach", "umount2(mount, MNT_DETACH)", result);
            detached
        };
        #[cfg(target_os = "wasi")]
        let detached = false; // The runner records the actual attachment outcome.
        if let Some(f) = file.as_mut() {
            emit(case, "read", "pread(fd) after detach", read(f));
            emit(case, "fstat", "fstat(fd) after detach", platform::fdstat(f));
        }
        if cwd {
            emit(
                case,
                "getcwd",
                "getcwd() after detach",
                platform::cwd().map(|s| json!(s.replace(self.root.to_str().unwrap(), "$ROOT"))),
            );
            unit(
                case,
                "restore",
                "chdir(parent)",
                platform::cd(self.root.parent().unwrap()),
            );
        }
        detached
    }
    fn directory_facts(&self, case: &str, step: &str, dir: &Path) {
        emit(
            case,
            step,
            "stat(shared directory)",
            platform::stat(dir)
                .map(|v| json!({"mode":v["mode"], "group_is_caller":v["gid"] == self.gid})),
        );
    }
    fn inheritance(&self, case: &str, step: &str, dir: &Path, file: &Path) {
        match platform::stat(dir) {
            Ok(v) if v["gid"] == self.gid => skip_step(
                case,
                step,
                "compare creator, directory and file groups",
                "creator primary group equals directory group; setgid inheritance is not distinguishable",
            ),
            Ok(_) => acl_step(
                case,
                step,
                "compare creator, directory and file groups",
                || {
                    self.stat(file).map(|v| json!({"group_is_parent":v["group_is_parent"], "group_is_caller":v["group_is_caller"]}))
                },
            ),
            Err(e) => emit(
                case,
                step,
                "compare creator, directory and file groups",
                Err(e),
            ),
        }
    }
    fn creator(&self, name: &str) {
        self.directory_facts("two-accounts", &format!("{name}-directory"), &self.root);
        emit(
            "two-accounts",
            &format!("{name}-groups"),
            "inspect supplementary groups excluding primary",
            platform::supplementary_groups_empty(self.gid).map(|empty| json!({"empty":empty})),
        );

        platform::umask(0o027);
        let file = self.root.join(name);
        unit(
            "two-accounts",
            &format!("{name}-create"),
            "umask(027); create(shared/file, 0666)",
            write(&file, b"hello"),
        );
        emit(
            "two-accounts",
            &format!("{name}-stat"),
            "stat(created)",
            self.stat(&file),
        );
        emit(
            "two-accounts",
            &format!("{name}-acl"),
            "getfacl(created)",
            platform::acl(&file),
        );
        self.inheritance(
            "two-accounts",
            &format!("{name}-inheritance"),
            &self.root,
            &file,
        );
    }
    fn latency(&self, op: &str) -> Result<()> {
        match op {
            "prepare" => {
                let deep = self.root.join("1/2/3/4/5/6/7");
                io(fs::create_dir_all(&deep))?;
                write(&deep.join("file"), b"x")?;
                write(&self.root.join("mib"), &vec![b'x'; 1 << 20])
            }
            "stat" => {
                platform::stat(&self.root.join("1/2/3/4/5/6/7/file"))?;
                Ok(())
            }
            "read" => {
                let bytes = io(fs::read(self.root.join("mib")))?;
                if bytes.len() != 1 << 20 {
                    return Err("short read".into());
                }
                Ok(())
            }
            "write" => write(&self.root.join("mib"), &vec![b'x'; 1 << 20]),
            _ => Err("unknown timing operation".into()),
        }
    }
}
fn valid_args(args: &[String]) -> bool {
    if args.len() < 7 || args[5].parse::<u32>().is_err() || args[6].parse::<u32>().is_err() {
        return false;
    }
    match args[1].as_str() {
        "creator" => args.len() == 8 && matches!(args[7].as_str(), "a" | "b"),
        "latency" => {
            args.len() == 8 && matches!(args[7].as_str(), "prepare" | "stat" | "read" | "write")
        }
        "basic" | "basic-cloud" | "no-mounts" | "cloud-link" | "remount-prepare"
        | "remount-observe" | "hold-open" | "hold-cwd" | "namespace" | "two-linux"
        | "unsupported" => args.len() == 7,
        _ => false,
    }
}
pub fn run() {
    #[cfg(target_os = "wasi")]
    os_posix::init_preopens().unwrap();
    let args: Vec<_> = std::env::args().collect();
    if !valid_args(&args) {
        eprintln!("os-conformance MODE ROOT ALIAS CROSS UID GID [OP]");
        std::process::exit(2);
    }
    let p = Probe {
        root: (&args[2]).into(),
        alias: (&args[3]).into(),
        cross: (&args[4]).into(),
        uid: args[5].parse().unwrap(),
        gid: args[6].parse().unwrap(),
    };
    platform::umask(0o022);
    match args[1].as_str() {
        "basic" => p.basic(true, false),
        "basic-cloud" => {
            p.basic(true, true);
            for case in ["remount", "unmount-open", "unmount-cwd"] {
                skipped(
                    case,
                    "not implemented: cloud root cannot be detached through the current mount API",
                );
            }
        }
        "no-mounts" => {
            p.basic(false, false);
            p.with_mounts(
                false,
                &[
                    "remount",
                    "unmount-open",
                    "unmount-cwd",
                    "mount-api",
                    "umount-api",
                    "chroot-api",
                    "cloud-to-provider",
                ],
                || unreachable!(),
            );
        }
        "cloud-link" => {
            unit(
                "cloud-to-provider",
                "link",
                "symlink(provider/target, cloud/link)",
                platform::symlink(&p.cross.join("target"), &p.root.join("cloud-link")),
            );
            emit(
                "cloud-to-provider",
                "read",
                "read(cloud/link)",
                io(fs::read_to_string(p.root.join("cloud-link"))).map(|s| json!(s)),
            );
        }
        "remount-prepare" => p.remount(true),
        "remount-observe" => p.remount(false),
        "hold-open" => {
            p.hold(false);
        }
        "hold-cwd" => {
            p.hold(true);
        }
        "latency" => unit("latency", &args[7], &args[7], p.latency(&args[7])),
        "namespace" => {
            #[cfg(target_os = "linux")]
            {
                for name in ["tree", "root", "alias", "cross"] {
                    fs::create_dir(p.root.join(name)).unwrap();
                }
                let q = Probe {
                    root: p.root.join("root"),
                    alias: p.root.join("alias"),
                    cross: p.root.join("cross"),
                    uid: p.uid,
                    gid: p.gid,
                };
                platform::mount(&p.root.join("tree"), &q.root, false).unwrap();
                platform::mount(&p.root.join("tree"), &q.alias, false).unwrap();
                platform::mount(Path::new("tmpfs"), &q.cross, true).unwrap();
                write(&q.cross.join("target"), b"target").unwrap();
                q.basic(true, false);
                write(&q.root.join("target"), b"target").unwrap();
                unit(
                    "cloud-to-provider",
                    "link",
                    "symlink(provider/target, cloud/link)",
                    platform::symlink(&q.root.join("target"), &p.root.join("cloud-link")),
                );
                emit(
                    "cloud-to-provider",
                    "read",
                    "read(cloud/link)",
                    io(fs::read_to_string(p.root.join("cloud-link"))).map(|s| json!(s)),
                );
                platform::cd(&p.root).unwrap();
                q.remount(true);
                unit(
                    "remount",
                    "detach",
                    "umount(mount)",
                    platform::unmount(&q.root),
                );
                unit(
                    "remount",
                    "attach",
                    "mount(source, mount)",
                    platform::mount(&p.root.join("tree"), &q.root, false),
                );
                q.remount(false);
                for cwd in [false, true] {
                    if q.hold(cwd) {
                        let case = if cwd { "unmount-cwd" } else { "unmount-open" };
                        let result = platform::mount(&p.root.join("tree"), &q.root, false);
                        unit(case, "attach", "mount(source, mount)", result.clone());
                        result.expect("held-case re-attach failed");
                    }
                }
                unit(
                    "mount-api",
                    "mount",
                    "mount(source, mount)",
                    platform::mount(&p.root.join("tree"), &q.root, false),
                );
                unit(
                    "umount-api",
                    "umount",
                    "umount(mount)",
                    platform::unmount(&q.root),
                );
                unit(
                    "chroot-api",
                    "chroot",
                    "chroot(root)",
                    platform::chroot(&q.root),
                );
            }
            #[cfg(target_os = "wasi")]
            for case in ["mount-api", "umount-api", "chroot-api"] {
                skipped(case, "not implemented: absent from abi::Call");
            }
        }
        "two-linux" => {
            #[cfg(target_os = "linux")]
            {
                use std::ffi::CString;
                if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
                    skipped(
                        "two-accounts",
                        "cannot clear inherited supplementary groups in this user namespace",
                    );
                    return;
                }
                assert_eq!(unsafe { libc::getgroups(0, std::ptr::null_mut()) }, 0);
                if !platform::named_acl_available() {
                    skipped(
                        "two-accounts",
                        "named ACL group 65534 is not mapped in this user namespace",
                    );
                    return;
                }
                // Match the OS fixture: one explicit neutral supplementary group.
                assert_eq!(unsafe { libc::setgroups(1, [3].as_ptr()) }, 0);
                platform::mount(Path::new("tmpfs"), &p.root, true).unwrap();
                platform::chmod(&p.root, 0o777).unwrap();
                // Enter while privileged. Dropped children must not traverse
                // unrelated private ancestors of the caller's TMPDIR.
                std::env::set_current_dir(&p.root).unwrap();
                let path = PathBuf::from("shared");
                fs::create_dir(&path).unwrap();
                let c = CString::new(path.to_str().unwrap()).unwrap();
                assert_eq!(unsafe { libc::chown(c.as_ptr(), 1, 3) }, 0);
                platform::chmod(&path, 0o2777).unwrap();
                platform::setacl(&path, true).unwrap();
                for (uid, name) in [(1, "a"), (2, "b")] {
                    let child = unsafe { libc::fork() };
                    assert!(child >= 0);
                    if child == 0 {
                        assert_eq!(unsafe { libc::setgid(uid) }, 0);
                        assert_eq!(unsafe { libc::setuid(uid) }, 0);
                        let mut groups = [0];
                        assert_eq!(unsafe { libc::getgroups(1, groups.as_mut_ptr()) }, 1);
                        assert_eq!(groups, [3]);
                        assert_eq!(unsafe { libc::getuid() }, uid);
                        assert_eq!(unsafe { libc::getgid() }, uid);
                        let q = Probe {
                            root: path.clone(),
                            alias: path.clone(),
                            cross: path.clone(),
                            uid: uid as u64,
                            gid: uid as u64,
                        };
                        q.creator(name);
                        std::process::exit(0);
                    }
                    let mut status = 0;
                    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                    assert_eq!(status, 0);
                }
            }
        }
        "unsupported" => {
            for case in ["mount-api", "umount-api", "chroot-api"] {
                skipped(case, "not implemented: absent from abi::Call");
            }
        }
        "creator" => p.creator(&args[7]),
        _ => {
            eprintln!("unknown mode");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mode_specific_usage() {
        for mode in ["creator", "latency", "unknown"] {
            assert!(!valid_args(
                &format!("probe {mode} / / / 1 1")
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            ));
        }
        for args in [
            "probe latency / / / 1 1 read",
            "probe creator / / / 1 2 a",
            "probe basic / / / 1 1",
        ] {
            assert!(valid_args(
                &args
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            ));
        }
        assert!(!valid_args(
            &"probe basic / / / invalid 1"
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        ));
    }
}
