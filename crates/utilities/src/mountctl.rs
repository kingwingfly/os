//! mountctl and the shared mountd client for mount, umount, and findmnt.
use abi::mount_ctl::*;
use abi::socket::{MSG_NOSIGNAL, SHUT_WR};
use abi::{Call, Creds, Errno, Error};
use os_posix::socket::UnixStream;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

const USAGE: &str = "mountctl [--json] sources|filesystems|attachments|all|busy [TARGET]\nmountctl [--json] attach [-t TYPE] [-o OPTIONS] SOURCE TARGET\nmountctl [--json] detach [-l] [-f] TARGET | remount -o OPTIONS TARGET\nmountctl [--json] activate SOURCE_ID NAME [--exec] | forget SOURCE_ID";

pub fn current_uid() -> Result<u32, Error> {
    let reply = os_posix::batch(&[Call::Getcreds])
        .map_err(|e| Error::because(Errno::EIO, e.to_string()))?;
    let cred: Creds = serde_json::from_value(
        reply
            .results
            .into_iter()
            .next()
            .ok_or(Errno::EIO)?
            .into_result()?,
    )
    .map_err(|e| Error::because(Errno::EIO, e.to_string()))?;
    Ok(cred.uid)
}

pub fn request(uid: u32, req: &MountRequest) -> Result<MountResponse, Error> {
    let frame = encode_frame(req)?;
    // Only retry connection establishment. A lost reply can follow a committed mutation.
    let start = Instant::now();
    let user_socket = user_mount_sock(uid);
    let (stream, server_uid) = loop {
        match UnixStream::connect(&user_socket) {
            Ok(s) => break (s, uid),
            Err(Errno::ENOENT | Errno::ECONNREFUSED) => (),
            Err(e) => return Err(e.into()),
        }
        match UnixStream::connect(SYSTEM_MOUNT_SOCK) {
            Ok(s) => break (s, 0),
            Err(Errno::ENOENT | Errno::ECONNREFUSED)
                if start.elapsed() < Duration::from_secs(5) =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e.into()),
        }
    };
    if stream.peer_cred()?.uid != server_uid {
        return Err(Errno::EACCES.into());
    }
    write_frame(&frame, |s| stream.send(s, MSG_NOSIGNAL))?;
    stream.shutdown(SHUT_WR)?;
    decode_frame(&read_frame(|buf| stream.recv(buf, 0))?)
}

fn process_list(processes: &[BusyProcess]) -> String {
    processes
        .iter()
        .map(|p| format!("pid {} {} [{}]", p.pid, p.comm, p.reasons.join(", ")))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn diagnostic(errno: Errno, kind: &MountErrorKind, message: &str) -> String {
    if let MountErrorKind::Busy { processes } = kind {
        let pids = process_list(processes);
        let prefix = if pids.is_empty() {
            String::new()
        } else {
            format!("{pids}; ")
        };
        return format!("target is busy ({prefix}use 'umount -l' for lazy detach)");
    }
    format!("{message} ({errno:?})")
}

pub fn mutate(uid: u32, req: &MountRequest) -> io::Result<()> {
    match request(uid, req).map_err(io::Error::other)? {
        MountResponse::Ok {} => Ok(()),
        MountResponse::Error {
            errno,
            error,
            message,
        } => Err(io::Error::other(diagnostic(errno, &error, &message))),
        _ => Err(io::Error::other("unexpected mountd reply")),
    }
}

pub fn absolute(target: &str) -> String {
    let path = Path::new(target);
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let target = path.to_string_lossy();
    if target == "/" {
        "/".into()
    } else {
        target.trim_end_matches('/').into()
    }
}

fn parse(args: &[String]) -> Result<MountRequest, String> {
    let (verb, rest) = args.split_first().ok_or(USAGE)?;
    let mut operands = vec![];
    let (mut kind, mut opts, mut lazy, mut force, mut exec) = (None, vec![], false, false, false);
    let mut iter = rest.iter();
    while let Some(arg) = iter.next() {
        match (verb.as_str(), arg.as_str()) {
            ("attach", "-t" | "--types") => {
                kind = Some(iter.next().ok_or("missing filesystem type")?.clone())
            }
            ("remount" | "attach", "-o" | "--options") => {
                opts.push(iter.next().ok_or("missing mount options")?.clone())
            }
            ("detach", "-l" | "--lazy") => lazy = true,
            ("detach", "-f" | "--force") => force = true,
            ("detach", "-lf" | "-fl") => {
                lazy = true;
                force = true;
            }
            ("activate", "--exec") => exec = true,
            (_, "--") => {
                operands.extend(iter.map(String::as_str));
                break;
            }
            (_, s) if !s.starts_with('-') => operands.push(s),
            _ => return Err(format!("unknown option {arg}")),
        }
    }
    let (flags, data) = crate::mount::parse_mount_options(&opts);
    let options = (!data.is_empty()).then_some(data);
    match (verb.as_str(), operands.as_slice()) {
        ("sources", []) => Ok(MountRequest::ListSources),
        ("filesystems", []) => Ok(MountRequest::ListFilesystems),
        ("attachments", []) => Ok(MountRequest::ListAttachments { include_busy: true }),
        ("all", []) => Ok(MountRequest::ListAll { include_busy: true }),
        ("busy", []) => Ok(MountRequest::ListAttachments { include_busy: true }),
        ("busy", [target]) => Ok(MountRequest::BusyProcesses {
            target: absolute(target),
        }),
        ("attach", [source, target]) => {
            let fstype = kind.unwrap_or_else(|| {
                if source.starts_with("src:") {
                    String::new()
                } else if source.starts_with("volume:")
                    || source.starts_with("snapshot:")
                    || source.starts_with("/dev/loop")
                {
                    "cowfs".into()
                } else {
                    source.split(':').next().unwrap_or(source).to_string()
                }
            });
            Ok(MountRequest::Attach {
                source_id: source.starts_with("src:").then(|| source.to_string()),
                source: source.to_string(),
                target: absolute(target),
                fstype,
                flags,
                options,
                target_pid: None,
            })
        }
        ("detach", [target]) => Ok(MountRequest::Detach {
            target: absolute(target),
            lazy,
            force,
            target_pid: None,
        }),
        ("remount", [target]) if !opts.is_empty() => {
            let target = absolute(target);
            let text =
                std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?;
            let seed = crate::findmnt::parse_mountinfo(&text)
                .into_iter()
                .rev()
                .find(|r| r.target == target)
                .map(|r| crate::mount::parse_mount_options(&[r.mount_opts]).0)
                .unwrap_or(0);
            let flags = crate::mount::parse_mount_options_with_base(seed, &opts).0
                | abi::mount_flags::MS_REMOUNT;
            Ok(MountRequest::Remount {
                target,
                flags,
                options,
            })
        }
        ("activate", [source, name]) => Ok(MountRequest::ActivatePrivate {
            source_id: source.to_string(),
            name: name.to_string(),
            execute: exec,
            additional_sources: Vec::new(),
        }),
        ("forget", [id]) => Ok(MountRequest::ForgetSource {
            source_id: id.to_string(),
        }),
        _ => Err(USAGE.into()),
    }
}

fn display(reply: &MountResponse) {
    match reply {
        MountResponse::Sources { sources } => {
            for s in sources {
                println!("{}\t{}\t{}\t{:?}", s.id, s.kind.fstype(), s.label, s.state);
            }
        }
        MountResponse::Filesystems { filesystems } => {
            for f in filesystems {
                println!(
                    "{}\t{}\t{}\t{} blocks",
                    f.fs_id, f.fstype, f.source, f.blocks
                );
            }
        }
        MountResponse::Attachments { attachments } => {
            for a in attachments {
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    a.target,
                    a.fstype,
                    a.source_label,
                    a.options.join(","),
                    process_list(&a.busy_pids)
                );
            }
        }
        MountResponse::Busy { processes } => {
            for p in processes {
                println!("{}", process_list(std::slice::from_ref(p)));
            }
        }
        MountResponse::All { .. } => println!("{}", serde_json::to_string_pretty(reply).unwrap()),
        MountResponse::Error {
            errno,
            error,
            message,
        } => eprintln!("{}", diagnostic(*errno, error, message)),
        MountResponse::Ok {} => (),
    }
}

pub fn run(args: &[String]) -> i32 {
    if args.iter().any(|a| matches!(a.as_str(), "-h" | "--help")) {
        println!("{USAGE}");
        return 0;
    }
    let json = args.iter().any(|a| a == "--json");
    let args = args
        .iter()
        .filter(|a| a.as_str() != "--json")
        .cloned()
        .collect::<Vec<_>>();
    let req = match parse(&args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mountctl: {e}");
            return 2;
        }
    };
    let mut reply = match current_uid().and_then(|uid| request(uid, &req)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mountctl: {e}");
            return 1;
        }
    };
    if args.first().is_some_and(|verb| verb == "busy")
        && let MountResponse::Attachments { attachments } = &mut reply
    {
        attachments.retain(|a| !a.busy_pids.is_empty());
    }
    if json {
        println!("{}", serde_json::to_string(&reply).unwrap());
    } else {
        display(&reply);
    }
    i32::from(matches!(reply, MountResponse::Error { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_mutations_without_losing_grant_or_options() {
        let parse = |s: &str| {
            super::parse(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>()).unwrap()
        };
        assert!(
            matches!(parse("attach -t cowfs -o subvol=test,ro,excl /dev/loop2 /mnt/x"),
            MountRequest::Attach { fstype, flags: 1, options: Some(options), .. } if fstype=="cowfs" && options=="subvol=test,excl")
        );
        assert!(
            matches!(parse("attach src:a /mnt/local/p -t hostfs"), MountRequest::Attach { source_id:Some(id), .. } if id=="src:a")
        );
        assert!(matches!(
            parse("detach -lf /tmp"),
            MountRequest::Detach {
                lazy: true,
                force: true,
                ..
            }
        ));
        assert!(matches!(
            parse("activate src:a pkg --exec"),
            MountRequest::ActivatePrivate { execute: true, .. }
        ));
    }
}
