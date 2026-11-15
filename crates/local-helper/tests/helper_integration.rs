#![cfg(target_os = "linux")]

use abi::contract::Boundary;
use abi::fs::{
    Access, Entry, LockFamily, LockKind, LockRange, OpenOptions, RenameFlags, SetAttr, WriteAt,
    XattrFlags,
};
use abi::local_helper::{HelloReply, HelperGrant, Request, VERSION};
use abi::{ACL_DEFAULT, Errno};
use os_core::acl::Entries as AclEntries;
use os_core::permissions::SETGID;
use os_vfs::{
    BoxFuture, Cred, Filesystem, Identity,
    helperfs::{HelperFs, HelperHttpHost, HttpHelperTransport, HttpReply},
    now_or_never,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions as StdOpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEQ: AtomicU64 = AtomicU64::new(1);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "os-local-helper-int-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct SpawnedHelper {
    child: Child,
    url: String,
    token: String,
    fs: String,
}

impl SpawnedHelper {
    fn spawn(root: &Path, state_dir: &Path, origin: &str, write: bool, execute: bool) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_os-local-helper"));
        cmd.arg("--root")
            .arg(root)
            .arg("--origin")
            .arg(origin)
            .arg("--port")
            .arg("0")
            .arg("--state-dir")
            .arg(state_dir);
        if write {
            cmd.arg("--write");
        }
        if execute {
            cmd.arg("--execute");
        }
        cmd.stdout(Stdio::piped()).stderr(Stdio::inherit());
        let mut child = cmd.spawn().expect("spawn os-local-helper");
        let stdout = child.stdout.take().expect("stdout pipe");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read helper json line");
        let info: Value = serde_json::from_str(&line).expect("parse helper startup json");
        Self {
            child,
            url: info["url"].as_str().unwrap().to_owned(),
            token: info["token"].as_str().unwrap().to_owned(),
            fs: info["fs"].as_str().unwrap().to_owned(),
        }
    }
}

impl Drop for SpawnedHelper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn raw_http_request(
    url: &str,
    method: &str,
    origin: Option<&str>,
    token: Option<&str>,
    body: &[u8],
) -> Result<(u16, String, Vec<u8>), std::io::Error> {
    let addr = url.strip_prefix("http://").expect("http url");
    let mut stream = TcpStream::connect(addr)?;
    let mut head = format!("{method} / HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(orig) = origin {
        head.push_str(&format!("Origin: {orig}\r\n"));
    }
    if let Some(tok) = token {
        head.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    if method == "POST" {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    if method == "POST" {
        stream.write_all(body)?;
    }
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("http header separator");
    let headers_str = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status_line = headers_str.lines().next().unwrap();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let resp_body = raw[split + 4..].to_vec();
    Ok((status, headers_str, resp_body))
}

#[derive(Clone)]
struct TcpHelperHost {
    url: String,
    origin: String,
    token: String,
    ticket_seq: std::sync::Arc<AtomicU64>,
}

impl TcpHelperHost {
    fn new(url: String, origin: String, token: String) -> Self {
        Self {
            url,
            origin,
            token,
            ticket_seq: std::sync::Arc::new(AtomicU64::new(1)),
        }
    }
}

impl HelperHttpHost for TcpHelperHost {
    fn post<'a>(&'a self, body: Vec<u8>) -> BoxFuture<'a, HttpReply> {
        Box::pin(async move {
            match raw_http_request(
                &self.url,
                "POST",
                Some(&self.origin),
                Some(&self.token),
                &body,
            ) {
                Ok((status, _headers, resp_body)) => Ok(HttpReply {
                    status,
                    body: resp_body,
                }),
                Err(err) if err.kind() == std::io::ErrorKind::TimedOut => Err(Errno::ETIMEDOUT),
                Err(_) => Err(Errno::ENOTCONN),
            }
        })
    }

    fn sleep(&self, millis: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(millis)));
            Ok(())
        })
    }

    fn ticket(&self) -> String {
        let id = self.ticket_seq.fetch_add(1, Ordering::Relaxed);
        format!("http-ticket-{id}")
    }
}

fn make_cred(id: u32, group: u32, groups: &[u32], umask: u16) -> Cred {
    let mut set = BTreeMap::<u32, ()>::new();
    for g in groups {
        set.insert(*g, ());
    }
    Cred {
        identity: Identity {
            id,
            group,
            groups: set.into_keys().collect(),
        },
        umask,
        token: None,
    }
}

#[test]
fn http_security_cors_legacy_rejection_and_vfs_e2e_over_real_binary() {
    let tmp = TempDir::new("e2e");
    let root = tmp.path.join("root");
    let state = tmp.path.join("state");
    fs::create_dir_all(&root).unwrap();
    let origin = "https://os.example.test";

    let helper = SpawnedHelper::spawn(&root, &state, origin, true, true);
    assert!(helper.fs.starts_with("helperfs:"));

    // 1) Security checks: origin mismatch (403), forged token (401), OPTIONS CORS, legacy JSON.
    let hello_body = serde_json::to_vec(&Request::Hello(abi::contract::Hello {
        boundary: Boundary::LocalHelper,
        versions: vec![VERSION],
    }))
    .unwrap();
    let (status, _, body) = raw_http_request(
        &helper.url,
        "POST",
        Some("https://evil.example"),
        Some(&helper.token),
        &hello_body,
    )
    .unwrap();
    assert_eq!(status, 403);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["errno"],
        json!("EACCES")
    );

    let (status, _, body) = raw_http_request(
        &helper.url,
        "POST",
        Some(origin),
        Some("forged-token"),
        &hello_body,
    )
    .unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["errno"],
        json!("EACCES")
    );

    let (status, headers, _) =
        raw_http_request(&helper.url, "OPTIONS", Some(origin), None, b"").unwrap();
    assert_eq!(status, 204);
    assert!(headers.contains("Access-Control-Allow-Private-Network: true"));

    let (status, _, body) = raw_http_request(
        &helper.url,
        "POST",
        Some(origin),
        Some(&helper.token),
        br#"{"op":"stat","path":"/"}"#,
    )
    .unwrap();
    assert_eq!(status, 400);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap()["errno"],
        json!("EPROTONOSUPPORT")
    );

    let (status, _, body) = raw_http_request(
        &helper.url,
        "POST",
        Some(origin),
        Some(&helper.token),
        &hello_body,
    )
    .unwrap();
    assert_eq!(status, 200);
    let reply: HelloReply = serde_json::from_slice(&body).unwrap();
    assert_eq!(reply.version, VERSION);
    assert!(reply.write && reply.execute);

    // 2) Drive os_vfs::helperfs::HelperFs over real TCP HTTP against the spawned binary!
    let owner = make_cred(1000, 1000, &[1000, 2000], 0o022);
    let writer = make_cred(1001, 1001, &[1001, 2000], 0o027);
    let fs = now_or_never(HelperFs::connect(
        HttpHelperTransport(TcpHelperHost::new(
            helper.url.clone(),
            origin.into(),
            helper.token.clone(),
        )),
        "browser-tab-1",
        &owner,
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();

    // Open-unlink, open-rename, RENAME_NOREPLACE, fsync, and fdatasync.
    let (file_e, file_o) = now_or_never(
        fs.create(
            &owner,
            &fs.root(),
            "data.bin",
            0o644,
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .create_new(true),
        ),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        now_or_never(fs.write_at(&file_o, b"abc", WriteAt::End))
            .unwrap()
            .unwrap()
            .len,
        3
    );
    now_or_never(fs.sync_all(&file_o)).unwrap().unwrap();
    now_or_never(fs.sync_data(&file_o)).unwrap().unwrap();

    // Real host flock + F_OFD lock visible from outside this helper!
    now_or_never(fs.try_lock(
        &file_o,
        LockFamily::Flock,
        LockKind::Exclusive,
        LockRange::WHOLE,
    ))
    .unwrap()
    .unwrap();
    let range_lock = LockRange::new(0, Some(16)).unwrap();
    now_or_never(fs.try_lock(&file_o, LockFamily::Posix, LockKind::Exclusive, range_lock))
        .unwrap()
        .unwrap();

    let host_file = StdOpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join("data.bin"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(host_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
    let mut fl = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 0,
        l_len: 16,
        l_pid: 0,
    };
    assert_eq!(
        unsafe { libc::fcntl(host_file.as_raw_fd(), libc::F_OFD_GETLK, &mut fl) },
        0
    );
    assert_eq!(fl.l_type, libc::F_WRLCK as libc::c_short);

    // Second session's try_lock sees ordinary EAGAIN lock contention (never masked as ENOLCK).
    let fs_peer = now_or_never(HelperFs::connect(
        HttpHelperTransport(TcpHelperHost::new(
            helper.url.clone(),
            origin.into(),
            helper.token.clone(),
        )),
        "browser-tab-peer",
        &owner,
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();
    let peer_e = now_or_never(fs_peer.lookup(&owner, &fs_peer.root(), "data.bin"))
        .unwrap()
        .unwrap();
    let peer_o = now_or_never(fs_peer.open(
        &owner,
        &peer_e.handle,
        OpenOptions::new().read(true).write(true),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(
        now_or_never(fs_peer.try_lock(
            &peer_o,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE
        ))
        .unwrap()
        .unwrap_err(),
        Errno::EAGAIN
    );
    assert_eq!(
        now_or_never(fs_peer.try_lock(&peer_o, LockFamily::Posix, LockKind::Exclusive, range_lock))
            .unwrap()
            .unwrap_err(),
        Errno::EAGAIN
    );
    now_or_never(fs_peer.release(&peer_o)).unwrap().unwrap();
    now_or_never(fs_peer.detach()).unwrap().unwrap();

    // Rename while open + unlink while open -> nlink becomes 0 and bytes still readable!
    now_or_never(fs.rename(
        &owner,
        &fs.root(),
        "data.bin",
        &fs.root(),
        "renamed.bin",
        RenameFlags::NOREPLACE,
    ))
    .unwrap()
    .unwrap();
    now_or_never(fs.unlink(&owner, &fs.root(), "renamed.bin"))
        .unwrap()
        .unwrap();
    assert_eq!(
        now_or_never(fs.open_metadata(&file_o))
            .unwrap()
            .unwrap()
            .nlink,
        0
    );
    let mut buf = [0u8; 8];
    let n = now_or_never(fs.read_at(&file_o, &mut buf, 0))
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"abc");

    // Setgid dir + default ACL across creator creds, plus a persisted script.
    let dir_e: Entry = now_or_never(fs.mkdir(&owner, &fs.root(), "proj", 0o775))
        .unwrap()
        .unwrap();
    now_or_never(fs.setattr(
        &owner,
        &dir_e.handle,
        &SetAttr {
            gid: Some(2000),
            mode: Some(SETGID | 0o775),
            ..Default::default()
        },
    ))
    .unwrap()
    .unwrap();
    let dacl = AclEntries {
        user: 7,
        group: 5,
        other: 0,
        mask: None,
        users: BTreeMap::new(),
        groups: BTreeMap::new(),
    };
    now_or_never(fs.setxattr(
        &owner,
        &dir_e.handle,
        ACL_DEFAULT,
        &serde_json::to_vec(&dacl).unwrap(),
        XattrFlags::empty(),
    ))
    .unwrap()
    .unwrap();
    let (script_e, script_o) = now_or_never(fs.create(
        &writer,
        &dir_e.handle,
        "tool.sh",
        0o777,
        OpenOptions::new().write(true).create(true).create_new(true),
    ))
    .unwrap()
    .unwrap();
    now_or_never(fs.release(&script_o)).unwrap().unwrap();
    assert_eq!(script_e.metadata.uid, 1001);
    assert_eq!(script_e.metadata.gid, 2000);
    assert_eq!(script_e.metadata.mode, 0o750);

    // Explicitly detach cleans up held fds + host locks immediately.
    now_or_never(fs.detach()).unwrap().unwrap();
    assert_eq!(
        unsafe { libc::flock(host_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert_eq!(
        unsafe { libc::flock(host_file.as_raw_fd(), libc::LOCK_UN) },
        0
    );
    drop(file_e);
    drop(helper);

    // 3) Restart helper without `--execute`: same FsId & inodes persist, exec denied EACCES!
    let helper2 = SpawnedHelper::spawn(&root, &state, origin, true, false);
    assert_eq!(helper2.fs, fs.id().0);
    let fs2 = now_or_never(HelperFs::connect(
        HttpHelperTransport(TcpHelperHost::new(
            helper2.url.clone(),
            origin.into(),
            helper2.token.clone(),
        )),
        "browser-tab-2",
        &owner,
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();
    assert!(!fs2.grant().execute);

    let walked = now_or_never(fs2.walk(&owner, &fs2.root(), &["proj".into(), "tool.sh".into()]))
        .unwrap()
        .unwrap();
    assert_eq!(walked.entries[1].handle, script_e.handle);
    assert_eq!(
        now_or_never(fs2.open(&owner, &script_e.handle, OpenOptions::new().exec(true)))
            .unwrap()
            .unwrap_err(),
        Errno::EACCES
    );
    // Reading still succeeds with execute=false ceiling!
    let r = now_or_never(fs2.open(&owner, &script_e.handle, OpenOptions::new().read(true)))
        .unwrap()
        .unwrap();
    assert_eq!(r.access, Access::Read);
    now_or_never(fs2.release(&r)).unwrap().unwrap();

    // Kill helper2 and check unreachable helper maps lock calls to ENOLCK and reads to ENOTCONN!
    drop(helper2);
    assert_eq!(
        now_or_never(fs2.try_lock(&r, LockFamily::Flock, LockKind::Shared, LockRange::WHOLE))
            .unwrap()
            .unwrap_err(),
        Errno::EBADF
    );
    // Re-test with an un-released open handle after helper killed:
    let helper3 = SpawnedHelper::spawn(&root, &state, origin, true, false);
    let fs3 = now_or_never(HelperFs::connect(
        HttpHelperTransport(TcpHelperHost::new(
            helper3.url.clone(),
            origin.into(),
            helper3.token.clone(),
        )),
        "browser-tab-3",
        &owner,
        HelperGrant {
            write: true,
            execute: false,
        },
    ))
    .unwrap()
    .unwrap();
    let live_o = now_or_never(fs3.open(&owner, &script_e.handle, OpenOptions::new().read(true)))
        .unwrap()
        .unwrap();
    drop(helper3);
    assert_eq!(
        now_or_never(fs3.try_lock(
            &live_o,
            LockFamily::Flock,
            LockKind::Shared,
            LockRange::WHOLE
        ))
        .unwrap()
        .unwrap_err(),
        Errno::ENOLCK
    );
    assert_eq!(
        now_or_never(fs3.lookup(&owner, &fs3.root(), "proj"))
            .unwrap()
            .unwrap_err(),
        Errno::ENOTCONN
    );
}

#[test]
fn slow_stalled_http_client_does_not_block_other_requests() {
    let tmp = TempDir::new("slow-http");
    let root = tmp.path.join("root");
    let state = tmp.path.join("state");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("hello.txt"), b"ok").unwrap();

    let origin = "http://127.0.0.1:8787";
    let helper = SpawnedHelper::spawn(&root, &state, origin, true, true);

    // Open a slow HTTP client that advertises Content-Length: 100, sends 5 bytes, and stalls.
    let addr = helper.url.strip_prefix("http://").unwrap();
    let mut slow = TcpStream::connect(addr).unwrap();
    let head = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nOrigin: {origin}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\nhello",
        helper.token
    );
    slow.write_all(head.as_bytes()).unwrap();
    slow.flush().unwrap();

    // A second client must complete full Hello/Attach/Statfs promptly without waiting for the stalled socket.
    let start = std::time::Instant::now();
    let owner = Cred::new(Identity {
        id: 1000,
        group: 1000,
        groups: [1000].into(),
    });
    let fs = now_or_never(HelperFs::connect(
        HttpHelperTransport(TcpHelperHost::new(
            helper.url.clone(),
            origin.into(),
            helper.token.clone(),
        )),
        "fast-tab",
        &owner,
        HelperGrant {
            write: true,
            execute: true,
        },
    ))
    .unwrap()
    .unwrap();
    let entry = now_or_never(fs.lookup(&owner, &fs.root(), "hello.txt"))
        .unwrap()
        .unwrap();
    assert_eq!(entry.metadata.size, 2);
    assert!(
        start.elapsed() < std::time::Duration::from_secs(2),
        "healthy client blocked on stalled socket: {:?}",
        start.elapsed()
    );
    drop(slow);
}
