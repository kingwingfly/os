//! The programs, run over the kernel in memory: what they print and how they fail.
use crate::{Io, Sys, View, run};
use abi::{Call, Closed, Errno, Error, FICLONE, O_ACCMODE, Opened};
use kernel::{Fs, Opening, Process, call};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::{Pin, pin};
use std::task::{Context, Poll, Waker};
use terminal_worker_core::permissions::*;

/// A process over the kernel in memory, as an account, with descriptors as the host keeps
/// them: here, of whole files, whose content is an id that copies share.
struct Mem {
    fs: RefCell<MemStore>,
    cred: RefCell<Identity>,
    fds: RefCell<BTreeMap<u32, MemFd>>,
}
struct MemFd {
    path: String,
    file: Option<String>,
    size: u64,
    write: bool,
    created: bool,
}
impl Mem {
    fn descriptor(&self, process: &Process, call: Call) -> Result<Value, Error> {
        let mut fs = self.fs.borrow_mut();
        let mut fds = self.fds.borrow_mut();
        match call {
            Call::Open {
                path, flags, mode, ..
            } => {
                let fd = (3..).find(|n| !fds.contains_key(n)).expect("a free fd");
                let write = flags & O_ACCMODE != 0;
                let opened = match kernel::open(&*fs, process, &path, flags, mode)? {
                    Opening::Existing { path, node } => MemFd {
                        path,
                        file: node.file,
                        size: node.size,
                        write,
                        created: false,
                    },
                    Opening::New { path, mut node } => {
                        node.file = Some(fs.empty(process.cred.id, &path));
                        fs.set_node(&path, &node);
                        MemFd {
                            path,
                            file: node.file,
                            size: 0,
                            write,
                            created: true,
                        }
                    }
                };
                let created = opened.created;
                fds.insert(fd, opened);
                Ok(json!(Opened {
                    fd,
                    created,
                    ..Opened::default()
                }))
            }
            Call::Ioctl {
                fd,
                request: FICLONE,
                arg,
            } => {
                let source = fds
                    .get(&(arg.as_u64().unwrap_or(u64::MAX) as u32))
                    .ok_or(Errno::EBADF)?;
                let (file, size) = (source.file.clone(), source.size);
                let target = fds
                    .get(&fd.number())
                    .filter(|f| f.write)
                    .ok_or(Errno::EBADF)?;
                let node = fs.node(&target.path).ok_or(Errno::ENOENT)?;
                fs.set_node(&target.path, &Node { file, size, ..node });
                Ok(Value::Null)
            }
            Call::Close { fd } => {
                let closed = fds.remove(&fd.number()).ok_or(Errno::EBADF)?;
                Ok(json!(Closed {
                    path: closed.path,
                    created: closed.created,
                    ..Closed::default()
                }))
            }
            _ => Err(Errno::ENOSYS.into()),
        }
    }
}
impl Sys for Mem {
    async fn batch(&self, calls: Vec<Call>) -> Vec<Result<Value, Error>> {
        let process = Process {
            cred: self.cred.borrow().clone(),
            umask: 0o022,
        };
        calls
            .into_iter()
            .map(|c| match c {
                Call::Open { .. } | Call::Ioctl { .. } | Call::Close { .. } => {
                    self.descriptor(&process, c)
                }
                c => call(&mut *self.fs.borrow_mut(), &process, c),
            })
            .collect()
    }
    async fn read(&self, path: &str) -> Result<Vec<u8>, Error> {
        let fs = self.fs.borrow();
        let text = match path {
            "/etc/passwd" => fs
                .users()
                .into_iter()
                .map(|(name, user)| {
                    format!(
                        "{name}:x:{}:{}::{}:/bin/sh\n",
                        user.id, user.group, user.home
                    )
                })
                .collect::<String>(),
            "/etc/group" => fs
                .groups()
                .into_iter()
                .map(|(name, id)| format!("{name}:x:{id}:\n"))
                .collect(),
            _ => return Err(abi::Errno::ENOENT.into()),
        };
        Ok(text.into_bytes())
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut context = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
    }
}

fn mem() -> Mem {
    let mut fs = MemStore::new(User {
        id: 0,
        group: 0,
        groups: BTreeSet::new(),
        home: "/root".into(),
        locked: false,
        salt: String::new(),
        hash: String::new(),
    });
    for (name, id) in [("ann", 1000), ("bob", 1001)] {
        fs.set_user(
            name,
            &User {
                id,
                group: id,
                groups: BTreeSet::new(),
                home: format!("/home/{name}"),
                locked: false,
                salt: String::new(),
                hash: String::new(),
            },
        );
        fs.set_group(name, id);
    }
    Mem {
        fs: RefCell::new(fs),
        cred: RefCell::new(Identity::root()),
        fds: RefCell::new(BTreeMap::new()),
    }
}
impl Mem {
    fn as_user(&self, id: u32) {
        *self.cred.borrow_mut() = if id == 0 {
            Identity::root()
        } else {
            Identity {
                id,
                group: id,
                groups: BTreeSet::from([id]),
            }
        };
    }
}

/// What running `line` in `cwd` gave: its status, its output, its errors, and its view.
struct Ran {
    status: i32,
    out: String,
    err: Vec<String>,
    view: Option<View>,
}
fn sh(mem: &Mem, cwd: &str, line: &str) -> Ran {
    sh_answering(mem, cwd, line, "n")
}
fn sh_answering(mem: &Mem, cwd: &str, line: &str, answer: &'static str) -> Ran {
    let cancelled = || false;
    let ask = move |_: String| -> Pin<Box<dyn Future<Output = Option<String>>>> {
        Box::pin(async move { Some(answer.to_string()) })
    };
    let mut io = Io {
        args: line.split_whitespace().map(String::from).collect(),
        cwd: cwd.into(),
        home: "/home/ann".into(),
        now: 1_793_291_641,
        stdin: None,
        out: String::new(),
        err: Vec::new(),
        view: None,
        found: Vec::new(),
        cancelled: &cancelled,
        ask: &ask,
    };
    let status = block_on(run(mem, &mut io)).expect("a program of user space");
    Ran {
        status,
        out: io.out,
        err: io.err,
        view: io.view,
    }
}
fn names(ran: &Ran) -> Vec<String> {
    match &ran.view {
        Some(View::Listing { entries, .. }) => entries.iter().map(|e| e.name.clone()).collect(),
        None => Vec::new(),
    }
}

#[test]
fn programs_work_through_system_calls_as_gnus_do() {
    let mem = mem();
    assert_eq!(sh(&mem, "/", "mkdir -p /w/a/b").status, 0);
    assert_eq!(sh(&mem, "/w", "touch a/one .hidden two").status, 0);
    // ls: directories first, hidden ones with -a only.
    assert_eq!(names(&sh(&mem, "/w", "ls")), ["a", "two"]);
    assert_eq!(names(&sh(&mem, "/w", "ls -a")), ["a", ".hidden", "two"]);
    let missing = sh(&mem, "/w", "ls nothing");
    assert_eq!(
        (missing.status, missing.err.clone()),
        (
            2,
            vec!["ls: cannot access 'nothing': No such file or directory".to_string()]
        )
    );
    // mkdir without -p, of what is there.
    assert_eq!(
        sh(&mem, "/w", "mkdir a").err,
        ["mkdir: cannot create directory 'a': File exists"]
    );
    assert_eq!(
        sh(&mem, "/w", "mkdir -p two/x").err,
        ["mkdir: cannot create directory 'two/x': Not a directory"]
    );
    // mv, ln, readlink, realpath.
    assert_eq!(
        sh(&mem, "/w", "mv -v two a").out,
        "renamed 'two' -> 'a/two'\n"
    );
    assert_eq!(sh(&mem, "/w", "ln -s a/two link").status, 0);
    assert_eq!(sh(&mem, "/w", "readlink link").out, "a/two\n");
    assert_eq!(sh(&mem, "/w", "readlink -f link").out, "/w/a/two\n");
    assert_eq!(sh(&mem, "/w", "realpath a/b/../two").out, "/w/a/two\n");
    assert_eq!(
        sh(&mem, "/w", "realpath -e nope").err,
        ["realpath: nope: No such file or directory"]
    );
    assert_eq!(
        sh(&mem, "/w", "ln -s a/one link").err,
        ["ln: failed to create symbolic link 'link': File exists"]
    );
    assert_eq!(sh(&mem, "/w", "ln -sf a/one link").status, 0);
    assert_eq!(sh(&mem, "/w", "readlink link").out, "a/one\n");
    // rm: a directory needs -r; . and .. never go.
    assert_eq!(
        sh(&mem, "/w", "rm a").err,
        ["rm: cannot remove 'a': Is a directory"]
    );
    assert_eq!(
        sh(&mem, "/w", "rm -r .").err,
        ["rm: refusing to remove '.' or '..' directory: skipping '.'"]
    );
    assert_eq!(sh(&mem, "/w", "rm -f nothing").status, 0);
    assert_eq!(sh(&mem, "/w", "rm -r a link .hidden").status, 0);
    assert!(names(&sh(&mem, "/w", "ls -a")).is_empty());
    assert_eq!(sh(&mem, "/w", "rmdir /w").status, 0);
}

#[test]
fn rm_r_removes_what_it_may_and_says_what_it_may_not() {
    let mem = mem();
    sh(&mem, "/", "mkdir -p /t/keep/inner /t/go");
    sh(&mem, "/", "touch /t/keep/inner/f /t/go/f /t/top");
    sh(&mem, "/", "chmod 777 /t /t/go");
    sh(&mem, "/", "chmod 555 /t/keep/inner");
    sh(&mem, "/", "chown -R ann /t");
    sh(&mem, "/", "chmod 555 /t/keep");
    mem.as_user(1000);
    let ran = sh(&mem, "/", "rm -r /t");
    assert_eq!(ran.status, 1);
    assert_eq!(
        ran.err,
        ["rm: cannot remove '/t/keep/inner/f': Permission denied"]
    );
    // What could go went, as on Linux; what holds what could not, stayed.
    mem.as_user(0);
    assert_eq!(names(&sh(&mem, "/", "ls /t")), ["keep"]);
}

#[test]
fn mv_n_and_i_leave_what_is_there_unless_answered_yes() {
    let mem = mem();
    sh(&mem, "/", "mkdir /m");
    sh(&mem, "/m", "touch a b c");
    assert_eq!(sh(&mem, "/m", "mv -n a b").status, 0);
    assert_eq!(names(&sh(&mem, "/m", "ls")), ["a", "b", "c"]);
    assert_eq!(sh_answering(&mem, "/m", "mv -i a b", "n").status, 0);
    assert_eq!(names(&sh(&mem, "/m", "ls")), ["a", "b", "c"]);
    assert_eq!(sh_answering(&mem, "/m", "mv -i a b", "y").status, 0);
    assert_eq!(names(&sh(&mem, "/m", "ls")), ["b", "c"]);
    assert_eq!(
        sh(&mem, "/m", "mv b c d").err,
        ["mv: target 'd' is not a directory"]
    );
    assert_eq!(
        sh(&mem, "/m", "mv nothing d").err,
        ["mv: cannot stat 'nothing': No such file or directory"]
    );
    // The working directory, and what holds it, stay where they are.
    sh(&mem, "/", "mkdir -p /m/in/deep");
    assert_eq!(
        sh(&mem, "/m/in/deep", "mv /m/in /m/out").err,
        ["mv: cannot move '/m/in': it holds the working directory; cd elsewhere first"]
    );
    assert_eq!(sh(&mem, "/m/in", "mv . /m/out").status, 1);
    assert_eq!(sh(&mem, "/m", "mv in out").status, 0);
}

#[test]
fn modes_owners_and_acls_change_as_their_programs_say() {
    let mem = mem();
    sh(&mem, "/", "mkdir -p /p/d");
    sh(&mem, "/p", "touch d/f g");
    assert_eq!(sh(&mem, "/p", "chmod -R go-rwx d").status, 0);
    let long = sh(&mem, "/p", "ls -l d");
    match long.view {
        Some(View::Listing {
            entries,
            long: true,
        }) => assert_eq!(entries[0].mode, 0o600),
        _ => panic!("a long listing"),
    }
    assert_eq!(
        sh(&mem, "/p", "chmod u+q g").err,
        ["chmod: invalid mode: 'u+q'"]
    );
    assert_eq!(sh(&mem, "/p", "chown ann:bob g").status, 0);
    assert_eq!(
        sh(&mem, "/p", "chown nobody g").err,
        ["chown: invalid user: 'nobody'"]
    );
    mem.as_user(1001);
    assert_eq!(
        sh(&mem, "/p", "chmod 600 g").err,
        ["chmod: changing permissions of 'g': Operation not permitted"]
    );
    mem.as_user(1000);
    assert_eq!(sh(&mem, "/p", "setfacl -m u:bob:rw g").status, 0);
    let acl = sh(&mem, "/p", "getfacl g").out;
    assert_eq!(
        acl,
        "# file: p/g\n# owner: ann\n# group: bob\nuser::rw-\nuser:bob:rw-\ngroup::r--\nmask::rw-\nother::r--\n"
    );
    mem.as_user(1001);
    assert_eq!(
        sh(&mem, "/p", "setfacl -m u:bob:rwx g").err,
        ["setfacl: g: Operation not permitted"]
    );
    assert_eq!(sh(&mem, "/p", "setfattr -n user.note -v hi g").status, 0);
    assert_eq!(
        sh(&mem, "/p", "getfattr -d g").out,
        "# file: p/g\nuser.note=\"hi\"\n"
    );
    assert_eq!(
        sh(&mem, "/p", "setfattr -x user.none g").err,
        ["setfattr: g: No such attribute"]
    );
    mem.as_user(1000);
    assert_eq!(sh(&mem, "/p", "setfacl -b g").status, 0);
    assert!(!sh(&mem, "/p", "getfacl -c g").out.contains("bob:"));
}

#[test]
fn fd_finds_below_its_roots_and_stat_says_what_a_file_is() {
    let mem = mem();
    sh(&mem, "/", "mkdir -p /f/x/y /f/.hid");
    sh(&mem, "/f", "touch x/a.md x/y/b.md x/c.txt .hid/d.md");
    let found = sh(&mem, "/f", "fd -e md");
    assert_eq!(found.out, "x/a.md\nx/y/b.md\n");
    assert_eq!(found.status, 0);
    assert_eq!(sh(&mem, "/f", "fd -H -e md").out.lines().count(), 3);
    let stat = sh(&mem, "/f", "stat x/a.md").out;
    assert!(stat.starts_with("  File: 'x/a.md'\n  Size: 0"), "{stat}");
    assert!(
        stat.contains("regular empty file") && stat.contains("Access: (0644/-rw-r--r--)"),
        "{stat}"
    );
    assert_eq!(
        sh(&mem, "/f", "stat nope").err,
        ["stat: cannot statx 'nope': No such file or directory"]
    );
}

/// The content id of the file at `path`.
fn content(mem: &Mem, path: &str) -> Option<String> {
    mem.fs.borrow().node(path).and_then(|node| node.file)
}

#[test]
fn cp_shares_content_copies_trees_and_says_what_it_will_not() {
    let mem = mem();
    sh(&mem, "/", "mkdir -p /w/src/deep");
    sh(&mem, "/w", "touch src/a src/deep/b");
    {
        let mut fs = mem.fs.borrow_mut();
        let node = fs.node("/w/src/a").unwrap();
        fs.set_node(
            "/w/src/a",
            &Node {
                file: Some("alpha".into()),
                size: 5,
                mode: (node.mode & !0o777) | 0o600,
                ..node
            },
        );
    }
    // A copy shares its source's content; its mode is the source's, less the umask.
    assert_eq!(sh(&mem, "/w", "cp src/a copy").status, 0);
    assert_eq!(content(&mem, "/w/copy").as_deref(), Some("alpha"));
    assert_eq!(mem.fs.borrow().node("/w/copy").unwrap().mode & 0o777, 0o600);
    assert_eq!(
        sh(&mem, "/w", "cp src dir").err,
        ["cp: -r not specified; omitting directory 'src'"]
    );
    // A tree, a level at a time, said in the order it is walked.
    assert_eq!(
        sh(&mem, "/w", "cp -rv src tree").out,
        "'src' -> 'tree'\n'src/a' -> 'tree/a'\n'src/deep' -> 'tree/deep'\n'src/deep/b' -> 'tree/deep/b'\n"
    );
    assert_eq!(content(&mem, "/w/tree/a").as_deref(), Some("alpha"));
    assert_eq!(
        sh(&mem, "/w", "cp -r src src/deep").err,
        ["cp: cannot copy a directory, 'src', into itself, 'src/deep/src'"]
    );
    assert_eq!(
        sh(&mem, "/w", "cp src/a src/a").err,
        ["cp: 'src/a' and 'src/a' are the same file"]
    );
    // -i asks of the name as given; no leaves what is there.
    sh(&mem, "/w", "touch other");
    assert_eq!(sh(&mem, "/w", "cp -i src/a other").status, 0);
    assert_ne!(content(&mem, "/w/other").as_deref(), Some("alpha"));
    // Links are copied as links with -r, and followed when named without it.
    sh(&mem, "/w", "ln -s a src/l");
    sh(&mem, "/w", "cp -r src again");
    assert_eq!(sh(&mem, "/w", "readlink again/l").out, "a\n");
    sh(&mem, "/w", "cp src/l followed");
    assert_eq!(content(&mem, "/w/followed").as_deref(), Some("alpha"));
    // -a keeps a file's names one file, and a link's target as written; -L follows links.
    sh(&mem, "/w", "ln src/a src/deep/a-too");
    assert_eq!(sh(&mem, "/w", "cp -a src kept").err, Vec::<String>::new());
    let ino = |path: &str| mem.fs.borrow().node(path).unwrap().ino;
    assert_eq!(ino("/w/kept/a"), ino("/w/kept/deep/a-too"));
    assert_ne!(ino("/w/kept/a"), ino("/w/src/a"));
    assert_eq!(
        sh(&mem, "/w", "readlink kept/l").out,
        "a
"
    );
    sh(&mem, "/w", "cp -rL src deref");
    assert_eq!(content(&mem, "/w/deref/l").as_deref(), Some("alpha"));
    // A file is written through a link to one, not through one leading nowhere.
    sh(&mem, "/w", "touch target");
    sh(&mem, "/w", "ln -s target via");
    sh(&mem, "/w", "cp src/a via");
    assert_eq!(content(&mem, "/w/target").as_deref(), Some("alpha"));
    sh(&mem, "/w", "ln -s nowhere dangling");
    assert_eq!(
        sh(&mem, "/w", "cp src/a dangling").err,
        ["cp: not writing through dangling symlink 'dangling'"]
    );
    // A file still uploading is copied once whole, and nothing of a tree holding one before.
    mem.fs.borrow_mut().incomplete.insert("alpha".into());
    assert_eq!(
        sh(&mem, "/w", "cp -r src late").err,
        ["cp: cannot copy 'src/a': still uploading; copy it once it completes"]
    );
    assert!(mem.fs.borrow().node("/w/late").is_none());
    mem.fs.borrow_mut().incomplete.clear();
    // -p keeps the owner only for root; -f replaces a file that cannot be written.
    sh(&mem, "/w", "chown 1000 src/deep/b");
    sh(&mem, "/w", "cp -p src/deep/b owned");
    assert_eq!(mem.fs.borrow().node("/w/owned").unwrap().owner, 1000);
    sh(&mem, "/w", "chmod 777 /w");
    mem.as_user(1001);
    sh(&mem, "/w", "cp -p src/deep/b bobs");
    assert_eq!(mem.fs.borrow().node("/w/bobs").unwrap().owner, 1001);
    mem.as_user(1000);
    sh(&mem, "/w", "touch /w/locked");
    sh(&mem, "/w", "chmod 444 /w/locked");
    assert_eq!(
        sh(&mem, "/w", "cp src/deep/b locked").err,
        ["cp: cannot create regular file 'locked': Permission denied"]
    );
    assert_eq!(
        sh(&mem, "/w", "cp -f src/deep/b locked").err,
        Vec::<String>::new()
    );
    assert_eq!(content(&mem, "/w/locked"), content(&mem, "/w/src/deep/b"));
    sh(&mem, "/w", "chmod 755 /w");
    mem.as_user(0);
    sh(&mem, "/w", "chmod 755 /w");
    // Where the account may not write, nothing is made.
    mem.as_user(1000);
    assert_eq!(
        sh(&mem, "/w", "cp src/deep/b x").err,
        ["cp: cannot create regular file 'x': Permission denied"]
    );
    assert_eq!(
        sh(&mem, "/w", "cp src/deep/b /nowhere/x /w").err,
        [
            "cp: cannot create regular file '/w/b': Permission denied",
            "cp: cannot stat '/nowhere/x': No such file or directory"
        ]
    );
}
