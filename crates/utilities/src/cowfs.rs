//! `cowfs` volume, subvolume, snapshot, fork, Merkle delta stream (`send`/`receive`), and GC
//! administrative CLI (`docs/architecture/contract.md` §2.15, §2.16, §5; Blueprint §3.1).

use abi::Errno;
use abi::contract::cowfs_ioctl;
use abi::volume::{
    CowfsForkReq, CowfsForkResp, CowfsGcReq, CowfsGcResp, CowfsInfoResp, CowfsReceiveReq,
    CowfsReceiveResp, CowfsSendReq, CowfsSendResp, CowfsSnapDeleteReq, CowfsSnapListResp,
    CowfsSnapshotReq, CowfsSnapshotResp, CowfsSubvolReq, CowfsSubvolResp,
};
use std::io;
#[cfg(unix)]
use std::os::fd::{FromRawFd, IntoRawFd};
#[cfg(target_os = "wasi")]
use std::os::wasi::io::{FromRawFd, IntoRawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const USAGE: &str = "Usage: cowfs <command> [options] ...\n\n\
Commands:\n\
  info [--json] [TARGET]                                   Show volume metadata\n\
  subvol list [--json] [TARGET]                            List subvolumes\n\
  subvol create [--json] [TARGET] <NAME>                   Create subvolume\n\
  subvol delete [--json] [TARGET] <NAME>                   Delete subvolume (refuses @)\n\
  snapshot list [--json] [TARGET]                          List named snapshots\n\
  snapshot create [--json] [TARGET] <NAME>                 Create O(1) snapshot\n\
  snapshot delete [TARGET] <NAME>                          Delete named snapshot\n\
  fork [--snapshot SNAP] [--ephemeral] [--json] [TARGET] <NEW_VOLUME>\n\
                                                           Create O(1) volume fork\n\
  send [--parent SNAP] [--archive] [-o FILE] [-v] [TARGET] [SNAP]\n\
                                                           Emit OSCOWS1 stream or .cowpack archive\n\
  receive [--snapshot|--name NAME] [--volume VOL] [-i FILE] [--json] [TARGET]\n\
                                                           Verify and atomically receive OSCOWS1 stream\n\
  gc [--grace SECS] [--json] [TARGET]                      Run reachability mark-and-sweep GC\n";

const MAX_VBLK_SCAN: u32 = 16;
static OUTPUT_SEQ: AtomicU64 = AtomicU64::new(1);

fn errno_io(errno: Errno, detail: &str) -> io::Error {
    let kind = match errno {
        Errno::EPERM | Errno::EACCES => io::ErrorKind::PermissionDenied,
        Errno::ENOENT => io::ErrorKind::NotFound,
        Errno::EEXIST => io::ErrorKind::AlreadyExists,
        Errno::EINVAL => io::ErrorKind::InvalidInput,
        Errno::EPIPE => io::ErrorKind::BrokenPipe,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(
        kind,
        os_posix::OsCallError(abi::Error::because(errno, detail)),
    )
}

fn call_one(call: abi::Call) -> io::Result<serde_json::Value> {
    let mut reply = os_posix::batch(&[call])?;
    reply
        .results
        .remove(0)
        .into_result()
        .map_err(|e| errno_io(e.errno, e.detail.as_deref().unwrap_or("")))
}

fn open_fd(path: &str, flags: u32, mode: u16) -> io::Result<u32> {
    let val = call_one(abi::Call::Open {
        path: path.to_string(),
        flags,
        mode,
        size: None,
        sha256: None,
        version: None,
    })?;
    val["fd"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| errno_io(Errno::EIO, "open returned invalid descriptor"))
}

fn close_fd(fd: u32) {
    let _ = os_posix::batch(&[abi::Call::Close { fd: fd.into() }]);
}

fn current_uid() -> io::Result<u32> {
    let val = call_one(abi::Call::Getcreds)?;
    let creds: abi::Creds =
        serde_json::from_value(val).map_err(|e| errno_io(Errno::EIO, &e.to_string()))?;
    Ok(creds.uid)
}

fn send_ioctl_on_fd(
    fd: u32,
    request: u32,
    arg: serde_json::Value,
) -> io::Result<serde_json::Value> {
    call_one(abi::Call::Ioctl {
        fd: fd.into(),
        request,
        arg,
    })
}

fn find_vblk_for_volume(uuid: &str) -> io::Result<Option<String>> {
    for idx in 0..MAX_VBLK_SCAN {
        let path = format!("/dev/vd{idx}");
        let Ok(st) = os_posix::stat(Path::new(&path), false) else {
            continue;
        };
        if !st.is_device() || !st.rdev.as_deref().is_some_and(|r| r.starts_with("vblk:")) {
            continue;
        }
        if let Ok(fd) = open_fd(&path, abi::O_RDONLY, 0) {
            let info_res =
                send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_INFO, serde_json::Value::Null);
            close_fd(fd);
            if let Ok(val) = info_res
                && let Ok(info) = serde_json::from_value::<CowfsInfoResp>(val)
                && info.volume == uuid
            {
                return Ok(Some(path));
            }
        }
    }
    Ok(None)
}

fn find_any_vblk() -> Option<String> {
    for idx in 0..MAX_VBLK_SCAN {
        let path = format!("/dev/vd{idx}");
        if let Ok(st) = os_posix::stat(Path::new(&path), false)
            && st.is_device()
            && st.rdev.as_deref().is_some_and(|r| r.starts_with("vblk:"))
        {
            return Some(path);
        }
    }
    None
}

/// Resolve a `TARGET` (`None` -> `/` falling back to `/dev/vd0`, `/dev/vdN`, mounted cowfs dir,
/// or `volume:<uuid>`) and open an `O_RDONLY` fd on it. Returns `(fd, explicit_volume_override)`.
///
/// When `allow_unattached` is `false`, an unattached `volume:<uuid>` fails closed with `ENODEV`
/// instead of silently targeting `/dev/vd0`. Only `cowfs receive` passes `allow_unattached = true`
/// because `COWFS_IOC_RECEIVE` explicitly carries `target_volume` to create/update volumes in the
/// store.
fn open_target(target: Option<&str>, allow_unattached: bool) -> io::Result<(u32, Option<String>)> {
    match target {
        None => {
            if let Ok(fd) = open_fd("/", abi::O_RDONLY | abi::O_DIRECTORY, 0) {
                if send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_INFO, serde_json::Value::Null)
                    .is_ok()
                {
                    return Ok((fd, None));
                }
                close_fd(fd);
            }
            let dev = find_any_vblk()
                .ok_or_else(|| errno_io(Errno::ENODEV, "no mounted cowfs or /dev/vdN target"))?;
            Ok((open_fd(&dev, abi::O_RDONLY, 0)?, None))
        }
        Some(t) => {
            if let Some(vol) = t.strip_prefix("volume:") {
                if vol.is_empty() || vol.contains(['/', '\0']) {
                    return Err(errno_io(Errno::EINVAL, "invalid volume identifier"));
                }
                if let Some(dev) = find_vblk_for_volume(vol)? {
                    return Ok((open_fd(&dev, abi::O_RDONLY, 0)?, None));
                }
                if !allow_unattached {
                    return Err(errno_io(
                        Errno::ENODEV,
                        &format!("volume:{vol} is not attached to any /dev/vdN device"),
                    ));
                }
                let dev = find_any_vblk().ok_or_else(|| {
                    errno_io(Errno::ENODEV, "no /dev/vdN device available for volume")
                })?;
                return Ok((open_fd(&dev, abi::O_RDONLY, 0)?, Some(vol.to_string())));
            }
            let fd = open_fd(t, abi::O_RDONLY, 0)?;
            Ok((fd, None))
        }
    }
}

fn looks_like_target(s: &str) -> bool {
    s == "."
        || s == ".."
        || s.starts_with('/')
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with("volume:")
}

fn current_pid_hint() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        if let Ok(reply) = os_posix::batch(&[abi::Call::Getpid])
            && let Some(Ok(val)) = reply.results.into_iter().next().map(|r| r.into_result())
            && let Some(pid) = val
                .as_u64()
                .or_else(|| val.get("pid").and_then(|p| p.as_u64()))
        {
            return pid;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        u64::from(std::process::id())
    }
}

/// Replace a regular backup only after the stream, fsync and close all succeed.
fn send_to_file(
    path: &Path,
    send: impl FnOnce(u32) -> io::Result<CowfsSendResp>,
) -> io::Result<CowfsSendResp> {
    let mut output = path.to_owned();
    let mut links = 0;
    let existing = loop {
        match os_posix::stat(&output, false) {
            Ok(st) if st.kind() == abi::S_IFLNK => {
                if links == 40 {
                    return Err(errno_io(Errno::ELOOP, "too many output symlinks"));
                }
                let target = os_posix::readlinkat(None, &output)?;
                output = output.with_file_name(target);
                links += 1;
            }
            entry => break entry,
        }
    };
    let path = output.as_path();
    let parent = path.parent().unwrap_or(Path::new("."));
    let mode = match existing {
        Ok(st) if st.is_file() => {
            let fd = open_fd(
                path.to_str()
                    .ok_or_else(|| errno_io(Errno::EINVAL, "invalid output path"))?,
                abi::O_WRONLY | abi::O_NOFOLLOW,
                0,
            )?;
            call_one(abi::Call::Close { fd: fd.into() })?;
            Some((st.mode & 0o777) as u16)
        }
        Ok(st) if st.is_device() => {
            let fd = open_fd(
                path.to_str()
                    .ok_or_else(|| errno_io(Errno::EINVAL, "invalid path"))?,
                abi::O_WRONLY | abi::O_NOFOLLOW,
                0,
            )?;
            let result = send(fd);
            let closed = call_one(abi::Call::Close { fd: fd.into() });
            let resp = result?;
            closed?;
            return Ok(resp);
        }
        Ok(_) => return Err(errno_io(Errno::EINVAL, "invalid output file")),
        Err(err) if os_posix::errno_of(&err) == Some(Errno::ENOENT) => None,
        Err(err) => return Err(err),
    };
    let pid = current_pid_hint();
    let (tmp, fd) = loop {
        let seq = OUTPUT_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = parent.join(format!(".cowfs-send-{pid}-{seq}"));
        let name = tmp
            .to_str()
            .ok_or_else(|| errno_io(Errno::EINVAL, "invalid output path"))?;
        match open_fd(
            name,
            abi::O_CREAT | abi::O_EXCL | abi::O_WRONLY,
            mode.map_or(0o644, |_| 0o600),
        ) {
            Ok(fd) => break (tmp, fd),
            Err(err) if os_posix::errno_of(&err) == Some(Errno::EEXIST) => continue,
            Err(err) => return Err(err),
        }
    };
    let result = (|| {
        // SAFETY: Open returned a new, owned descriptor in the process's WASI fd table.
        let file = unsafe { std::fs::File::from_raw_fd(fd as _) };
        let written = send(fd).and_then(|resp| {
            if let Some(mode) = mode {
                os_posix::fchmod(fd, u32::from(mode))?;
            }
            file.sync_all()?;
            Ok(resp)
        });
        let closed = call_one(abi::Call::Close {
            fd: (file.into_raw_fd() as u32).into(),
        });
        let resp = written?;
        closed?;
        os_posix::renameat(None, &tmp, None, path, false)?;
        Ok(resp)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

fn format_err(cmd: &str, err: &io::Error) -> String {
    if let Some(errno) = os_posix::errno_of(err) {
        format!("cowfs {cmd}: {errno:?}: {err}")
    } else {
        format!("cowfs {cmd}: {err}")
    }
}

fn run_info(args: &[String]) -> i32 {
    let mut json_out = false;
    let mut target: Option<String> = None;
    for a in args {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--json" => json_out = true,
            s if s.starts_with('-') => {
                eprintln!("cowfs info: unsupported option '{s}'");
                return 2;
            }
            t => {
                if target.is_some() {
                    eprintln!("cowfs info: expected at most one TARGET");
                    return 2;
                }
                target = Some(t.to_string());
            }
        }
    }
    let (fd, _) = match open_target(target.as_deref(), false) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{}", format_err("info", &e));
            return 1;
        }
    };
    let res = send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_INFO, serde_json::Value::Null);
    close_fd(fd);
    let info: CowfsInfoResp = match res
        .and_then(|v| serde_json::from_value(v).map_err(|e| errno_io(Errno::EIO, &e.to_string())))
    {
        Ok(i) => i,
        Err(e) => {
            eprintln!("{}", format_err("info", &e));
            return 1;
        }
    };
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&info).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("volume:         {}", info.volume);
        println!("format_version: {}", info.format_version);
        println!("root:           {}", info.root);
        println!(
            "lease:          incarnation={} fence={} epoch={}",
            info.incarnation, info.fence, info.epoch
        );
        println!("read_only:      {}", info.read_only);
        if let Some(parent) = info.parent_volume {
            println!("parent_volume:  {parent}");
        }
    }
    0
}

fn parse_target_and_name(pos: &[String]) -> Result<(Option<String>, String), String> {
    match pos {
        [only] => Ok((None, only.clone())),
        [a, b] => {
            if looks_like_target(a) {
                Ok((Some(a.clone()), b.clone()))
            } else if looks_like_target(b) {
                Ok((Some(b.clone()), a.clone()))
            } else {
                Ok((Some(a.clone()), b.clone()))
            }
        }
        _ => Err("expected [TARGET] <NAME>".to_string()),
    }
}

fn run_subvol(args: &[String]) -> i32 {
    let Some((sub, rest)) = args.split_first() else {
        eprintln!("cowfs subvol: expected list|create|delete");
        return 2;
    };
    let mut json_out = false;
    let mut pos: Vec<String> = Vec::new();
    for a in rest {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--json" => json_out = true,
            s if s.starts_with('-') => {
                eprintln!("cowfs subvol {sub}: unsupported option '{s}'");
                return 2;
            }
            v => pos.push(v.to_string()),
        }
    }
    let (target, req) = match sub.as_str() {
        "list" | "ls" => {
            if pos.len() > 1 {
                eprintln!("cowfs subvol list: expected at most one TARGET");
                return 2;
            }
            (pos.into_iter().next(), CowfsSubvolReq::List {})
        }
        "create" => match parse_target_and_name(&pos) {
            Ok((t, name)) => (t, CowfsSubvolReq::Create { name }),
            Err(m) => {
                eprintln!("cowfs subvol create: {m}");
                return 2;
            }
        },
        "delete" | "rm" => match parse_target_and_name(&pos) {
            Ok((t, name)) => (t, CowfsSubvolReq::Delete { name }),
            Err(m) => {
                eprintln!("cowfs subvol delete: {m}");
                return 2;
            }
        },
        "-h" | "--help" => {
            print!("{USAGE}");
            return 0;
        }
        other => {
            eprintln!("cowfs subvol: unknown subcommand '{other}'");
            return 2;
        }
    };
    if !matches!(req, CowfsSubvolReq::List {})
        && let Ok(uid) = current_uid()
        && uid != 0
    {
        eprintln!(
            "{}",
            format_err("subvol", &errno_io(Errno::EPERM, "Operation not permitted"))
        );
        return 1;
    }

    let (fd, _) = match open_target(target.as_deref(), false) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{}", format_err("subvol", &e));
            return 1;
        }
    };
    let arg = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
    let res = send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_SUBVOL, arg);
    close_fd(fd);
    let resp: CowfsSubvolResp = match res
        .and_then(|v| serde_json::from_value(v).map_err(|e| errno_io(Errno::EIO, &e.to_string())))
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", format_err("subvol", &e));
            return 1;
        }
    };
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        for sv in &resp.subvols {
            println!("{}\t{}", sv.name, &sv.root[..sv.root.len().min(12)]);
        }
    }
    0
}

fn run_snapshot(args: &[String]) -> i32 {
    let Some((sub, rest)) = args.split_first() else {
        eprintln!("cowfs snapshot: expected list|create|delete");
        return 2;
    };
    let mut json_out = false;
    let mut ro = false;
    let mut pos: Vec<String> = Vec::new();
    for a in rest {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--json" => json_out = true,
            "-r" | "--ro" => ro = true,
            s if s.starts_with('-') => {
                eprintln!("cowfs snapshot {sub}: unsupported option '{s}'");
                return 2;
            }
            v => pos.push(v.to_string()),
        }
    }
    match sub.as_str() {
        "list" | "ls" => {
            if pos.len() > 1 {
                eprintln!("cowfs snapshot list: expected at most one TARGET");
                return 2;
            }
            let target = pos.into_iter().next();
            let (fd, _) = match open_target(target.as_deref(), false) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("{}", format_err("snapshot", &e));
                    return 1;
                }
            };
            let res = send_ioctl_on_fd(
                fd,
                cowfs_ioctl::COWFS_IOC_SNAP_LIST,
                serde_json::Value::Null,
            );
            close_fd(fd);
            let resp: CowfsSnapListResp = match res.and_then(|v| {
                serde_json::from_value(v).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
            }) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{}", format_err("snapshot", &e));
                    return 1;
                }
            };
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
                );
            } else {
                for sn in &resp.snapshots {
                    println!(
                        "{}\tepoch={}\t{}",
                        sn.name,
                        sn.epoch,
                        &sn.root[..sn.root.len().min(12)]
                    );
                }
            }
            0
        }
        "create" => {
            let (target, name) = match parse_target_and_name(&pos) {
                Ok(pair) => pair,
                Err(m) => {
                    eprintln!("cowfs snapshot create: {m}");
                    return 2;
                }
            };
            if let Ok(uid) = current_uid()
                && uid != 0
            {
                eprintln!(
                    "{}",
                    format_err(
                        "snapshot",
                        &errno_io(Errno::EPERM, "Operation not permitted")
                    )
                );
                return 1;
            }
            let (fd, _) = match open_target(target.as_deref(), false) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("{}", format_err("snapshot", &e));
                    return 1;
                }
            };
            let req = CowfsSnapshotReq { name, ro };
            let arg = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let res = send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_SNAPSHOT, arg);
            close_fd(fd);
            let resp: CowfsSnapshotResp = match res.and_then(|v| {
                serde_json::from_value(v).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
            }) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("{}", format_err("snapshot", &e));
                    return 1;
                }
            };
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!(
                    "created snapshot {} on {} (epoch {}, root {})",
                    resp.name,
                    resp.volume,
                    resp.epoch,
                    &resp.root[..resp.root.len().min(12)]
                );
            }
            0
        }
        "delete" | "rm" => {
            let (target, name) = match parse_target_and_name(&pos) {
                Ok(pair) => pair,
                Err(m) => {
                    eprintln!("cowfs snapshot delete: {m}");
                    return 2;
                }
            };
            if let Ok(uid) = current_uid()
                && uid != 0
            {
                eprintln!(
                    "{}",
                    format_err(
                        "snapshot",
                        &errno_io(Errno::EPERM, "Operation not permitted")
                    )
                );
                return 1;
            }
            let (fd, _) = match open_target(target.as_deref(), false) {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("{}", format_err("snapshot", &e));
                    return 1;
                }
            };
            let req = CowfsSnapDeleteReq { name: name.clone() };
            let arg = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
            let res = send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_SNAP_DELETE, arg);
            close_fd(fd);
            if let Err(e) = res {
                eprintln!("{}", format_err("snapshot", &e));
                return 1;
            }
            if json_out {
                println!("{}", serde_json::json!({ "deleted": name }));
            }
            0
        }
        "-h" | "--help" => {
            print!("{USAGE}");
            0
        }
        other => {
            eprintln!("cowfs snapshot: unknown subcommand '{other}'");
            2
        }
    }
}

fn run_fork(args: &[String]) -> i32 {
    let mut json_out = false;
    let mut ephemeral = false;
    let mut snapshot: Option<String> = None;
    let mut pos: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--json" => json_out = true,
            "--ephemeral" => ephemeral = true,
            "--snapshot" | "-s" => {
                let Some(v) = iter.next() else {
                    eprintln!("cowfs fork: --snapshot requires an argument");
                    return 2;
                };
                snapshot = Some(v.clone());
            }
            s if s.starts_with("--snapshot=") => {
                snapshot = Some(s["--snapshot=".len()..].to_string());
            }
            s if s.starts_with('-') => {
                eprintln!("cowfs fork: unsupported option '{s}'");
                return 2;
            }
            v => pos.push(v.to_string()),
        }
    }
    let (target, new_volume) = match parse_target_and_name(&pos) {
        Ok(pair) => pair,
        Err(m) => {
            eprintln!("cowfs fork: {m}");
            return 2;
        }
    };
    if let Ok(uid) = current_uid()
        && uid != 0
    {
        eprintln!(
            "{}",
            format_err("fork", &errno_io(Errno::EPERM, "Operation not permitted"))
        );
        return 1;
    }
    let (fd, _) = match open_target(target.as_deref(), false) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{}", format_err("fork", &e));
            return 1;
        }
    };
    let req = CowfsForkReq {
        snapshot,
        new_volume,
        ephemeral_if_unmodified: ephemeral,
    };
    let arg = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
    let res = send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_FORK, arg);
    close_fd(fd);
    let resp: CowfsForkResp = match res
        .and_then(|v| serde_json::from_value(v).map_err(|e| errno_io(Errno::EIO, &e.to_string())))
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", format_err("fork", &e));
            return 1;
        }
    };
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!(
            "forked volume {} from {} (root {})",
            resp.volume,
            resp.parent_volume,
            &resp.root[..resp.root.len().min(12)]
        );
    }
    0
}

fn run_send(args: &[String]) -> i32 {
    let mut parent: Option<String> = None;
    let mut archive = false;
    let mut output: Option<String> = None;
    let mut json_stderr = false;
    let mut verbose = false;
    let mut pos: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--archive" => archive = true,
            "--json" => json_stderr = true,
            "-v" | "--verbose" => verbose = true,
            "-p" | "--parent" => {
                let Some(v) = iter.next() else {
                    eprintln!("cowfs send: --parent requires a snapshot name");
                    return 2;
                };
                parent = Some(v.clone());
            }
            s if s.starts_with("--parent=") => {
                parent = Some(s["--parent=".len()..].to_string());
            }
            "-o" | "--output" => {
                let Some(v) = iter.next() else {
                    eprintln!("cowfs send: --output requires a file path");
                    return 2;
                };
                output = Some(v.clone());
            }
            s if s.starts_with("--output=") => {
                output = Some(s["--output=".len()..].to_string());
            }
            s if s.starts_with('-') => {
                eprintln!("cowfs send: unsupported option '{s}'");
                return 2;
            }
            v => pos.push(v.to_string()),
        }
    }

    let (target, snapshot) = match pos.as_slice() {
        [] => (None, "@".to_string()),
        [only] => {
            if looks_like_target(only) {
                (Some(only.clone()), "@".to_string())
            } else {
                (None, only.clone())
            }
        }
        [a, b] => {
            if looks_like_target(a) {
                (Some(a.clone()), b.clone())
            } else if looks_like_target(b) {
                (Some(b.clone()), a.clone())
            } else {
                (Some(a.clone()), b.clone())
            }
        }
        _ => {
            eprintln!("cowfs send: expected [TARGET] [SNAPSHOT]");
            return 2;
        }
    };

    if archive && parent.is_some() {
        eprintln!("cowfs send: --archive and --parent cannot be combined");
        return 2;
    }
    let (dev_fd, _) = match open_target(target.as_deref(), false) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{}", format_err("send", &e));
            return 1;
        }
    };

    let send = |stream_fd| {
        let req = CowfsSendReq {
            snapshot,
            parent,
            stream_fd,
            archive,
        };
        let arg = serde_json::to_value(req)?;
        let value = send_ioctl_on_fd(dev_fd, cowfs_ioctl::COWFS_IOC_SEND, arg)?;
        serde_json::from_value(value).map_err(Into::into)
    };
    let resp_res = match output.as_deref() {
        Some(path) if path != "-" => send_to_file(Path::new(path), send),
        _ => send(1),
    };
    close_fd(dev_fd);

    match resp_res {
        Ok(resp) => {
            if json_stderr {
                eprintln!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
                );
            } else if verbose {
                eprintln!(
                    "sent {}@{}: {} bytes ({} nodes, {} blocks, {} subtrees skipped)",
                    resp.volume,
                    resp.snapshot,
                    resp.bytes_written,
                    resp.nodes_sent,
                    resp.blocks_sent,
                    resp.subtrees_skipped
                );
            }
            0
        }
        Err(e) => {
            eprintln!("{}", format_err("send", &e));
            1
        }
    }
}

fn run_receive(args: &[String]) -> i32 {
    let mut snapshot_name: Option<String> = None;
    let mut target_volume: Option<String> = None;
    let mut input: Option<String> = None;
    let mut json_out = false;
    let mut target: Option<String> = None;
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--json" => json_out = true,
            "-s" | "--snapshot" | "--name" => {
                let Some(v) = iter.next() else {
                    eprintln!("cowfs receive: {a} requires a name");
                    return 2;
                };
                snapshot_name = Some(v.clone());
            }
            s if s.starts_with("--snapshot=") => {
                snapshot_name = Some(s["--snapshot=".len()..].to_string());
            }
            s if s.starts_with("--name=") => {
                snapshot_name = Some(s["--name=".len()..].to_string());
            }
            "--volume" => {
                let Some(v) = iter.next() else {
                    eprintln!("cowfs receive: --volume requires a volume UUID");
                    return 2;
                };
                target_volume = Some(v.clone());
            }
            s if s.starts_with("--volume=") => {
                target_volume = Some(s["--volume=".len()..].to_string());
            }
            "-i" | "--input" => {
                let Some(v) = iter.next() else {
                    eprintln!("cowfs receive: --input requires a file path");
                    return 2;
                };
                input = Some(v.clone());
            }
            s if s.starts_with("--input=") => {
                input = Some(s["--input=".len()..].to_string());
            }
            s if s.starts_with('-') => {
                eprintln!("cowfs receive: unsupported option '{s}'");
                return 2;
            }
            v => {
                if target.is_some() {
                    eprintln!("cowfs receive: expected at most one TARGET");
                    return 2;
                }
                target = Some(v.to_string());
            }
        }
    }

    if let Ok(uid) = current_uid()
        && uid != 0
    {
        eprintln!(
            "{}",
            format_err(
                "receive",
                &errno_io(Errno::EPERM, "Operation not permitted")
            )
        );
        return 1;
    }

    let (dev_fd, vol_from_target) = match open_target(target.as_deref(), true) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{}", format_err("receive", &e));
            return 1;
        }
    };
    let effective_target_vol = target_volume.or(vol_from_target);

    let resp_res: io::Result<CowfsReceiveResp> = if let Some(ref in_path) = input
        && in_path != "-"
    {
        let in_fd = match open_fd(in_path, abi::O_RDONLY, 0) {
            Ok(f) => f,
            Err(e) => {
                close_fd(dev_fd);
                eprintln!("{}", format_err("receive", &e));
                return 1;
            }
        };
        let req = CowfsReceiveReq {
            stream_fd: in_fd,
            snapshot_name,
            target_volume: effective_target_vol,
        };
        let arg = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
        let r = send_ioctl_on_fd(dev_fd, cowfs_ioctl::COWFS_IOC_RECEIVE, arg).and_then(|v| {
            serde_json::from_value(v).map_err(|e| errno_io(Errno::EIO, &e.to_string()))
        });
        close_fd(in_fd);
        r
    } else {
        // Direct kernel fd 0 streaming (zero-copy when stdin is redirected from a file!).
        let req = CowfsReceiveReq {
            stream_fd: 0,
            snapshot_name: snapshot_name.clone(),
            target_volume: effective_target_vol.clone(),
        };
        let arg = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
        send_ioctl_on_fd(dev_fd, cowfs_ioctl::COWFS_IOC_RECEIVE, arg)
            .and_then(|value| serde_json::from_value(value).map_err(Into::into))
    };
    close_fd(dev_fd);

    match resp_res {
        Ok(resp) => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
                );
            } else {
                println!(
                    "received volume {} epoch {} root {} ({} nodes, {} blocks, {} bytes)",
                    resp.volume,
                    resp.epoch,
                    &resp.root[..resp.root.len().min(12)],
                    resp.nodes_received,
                    resp.blocks_received,
                    resp.bytes_read
                );
            }
            0
        }
        Err(e) => {
            eprintln!("{}", format_err("receive", &e));
            1
        }
    }
}

fn run_gc(args: &[String]) -> i32 {
    let mut json_out = false;
    let mut grace_window_secs: Option<u64> = None;
    let mut target: Option<String> = None;
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                return 0;
            }
            "--json" => json_out = true,
            "--grace" => {
                let Some(v) = iter.next() else {
                    eprintln!("cowfs gc: --grace requires seconds");
                    return 2;
                };
                match v.parse::<u64>() {
                    Ok(n) => grace_window_secs = Some(n),
                    Err(_) => {
                        eprintln!("cowfs gc: invalid --grace value '{v}'");
                        return 2;
                    }
                }
            }
            s if s.starts_with("--grace=") => {
                let v = &s["--grace=".len()..];
                match v.parse::<u64>() {
                    Ok(n) => grace_window_secs = Some(n),
                    Err(_) => {
                        eprintln!("cowfs gc: invalid --grace value '{v}'");
                        return 2;
                    }
                }
            }
            s if s.starts_with('-') => {
                eprintln!("cowfs gc: unsupported option '{s}'");
                return 2;
            }
            v => {
                if target.is_some() {
                    eprintln!("cowfs gc: expected at most one TARGET");
                    return 2;
                }
                target = Some(v.to_string());
            }
        }
    }
    if let Ok(uid) = current_uid()
        && uid != 0
    {
        eprintln!(
            "{}",
            format_err("gc", &errno_io(Errno::EPERM, "Operation not permitted"))
        );
        return 1;
    }
    let (fd, _) = match open_target(target.as_deref(), false) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{}", format_err("gc", &e));
            return 1;
        }
    };
    let req = CowfsGcReq { grace_window_secs };
    let arg = serde_json::to_value(&req).unwrap_or(serde_json::Value::Null);
    let res = send_ioctl_on_fd(fd, cowfs_ioctl::COWFS_IOC_GC, arg);
    close_fd(fd);
    let resp: CowfsGcResp = match res
        .and_then(|v| serde_json::from_value(v).map_err(|e| errno_io(Errno::EIO, &e.to_string())))
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", format_err("gc", &e));
            return 1;
        }
    };
    if json_out {
        println!(
            "{}",
            serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!(
            "gc: live_roots={} live_nodes={} live_blocks={} live_packs={} swept_packs={}",
            resp.live_roots,
            resp.live_nodes,
            resp.live_blocks,
            resp.live_packs,
            resp.swept_packs.len()
        );
    }
    0
}

pub fn run(args: &[String]) -> i32 {
    let Some((cmd, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return 2;
    };
    match cmd.as_str() {
        "-h" | "--help" => {
            print!("{USAGE}");
            0
        }
        "info" => run_info(rest),
        "subvol" | "subvolume" => run_subvol(rest),
        "snapshot" | "snap" => run_snapshot(rest),
        "fork" => run_fork(rest),
        "send" => run_send(rest),
        "receive" | "recv" => run_receive(rest),
        "gc" => run_gc(rest),
        other => {
            eprintln!("cowfs: unknown command '{other}'\n{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn parse_target_and_name_handles_both_orders() {
        assert_eq!(
            parse_target_and_name(&s(&["@data"])).unwrap(),
            (None, "@data".to_string())
        );
        assert_eq!(
            parse_target_and_name(&s(&["/mnt/v", "@data"])).unwrap(),
            (Some("/mnt/v".to_string()), "@data".to_string())
        );
        assert_eq!(
            parse_target_and_name(&s(&["@data", "/dev/vd1"])).unwrap(),
            (Some("/dev/vd1".to_string()), "@data".to_string())
        );
        assert!(parse_target_and_name(&s(&[])).is_err());
    }

    #[test]
    fn usage_documents_ephemeral_name_and_verbose_flags() {
        assert!(USAGE.contains("--ephemeral"));
        assert!(USAGE.contains("--name"));
        assert!(USAGE.contains("-v"));
    }

    #[test]
    fn cli_help_exits_zero_for_all_subcommands() {
        for cmd in [
            vec!["--help"],
            vec!["info", "--help"],
            vec!["subvol", "--help"],
            vec!["snapshot", "--help"],
            vec!["fork", "--ephemeral", "--help"],
            vec!["send", "-v", "--help"],
            vec!["receive", "--name", "s1", "--help"],
            vec!["gc", "--help"],
        ] {
            assert_eq!(run(&s(&cmd)), 0, "failed help for {cmd:?}");
        }
    }
}
