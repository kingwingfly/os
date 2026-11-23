//! AF_UNIX client for the userspace export service. Publication conveys an
//! already-open directory. Its display path is never a service-side lookup.
use abi::export_ctl::*;
use abi::{Call, Errno};
use os_posix::socket::{MSG_NOSIGNAL, UnixStream};
use serde::de::DeserializeOwned;
use std::fs::File;
#[cfg(not(target_os = "wasi"))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd};
use std::time::{Duration, Instant};

const USAGE:&str="Usage: exportctl publish [--name NAME] [--rw] [--exec] [--seconds N] [--password PASS] [--ipc-only] [--json] PATH
       exportctl list [--json]
       exportctl revoke ID
       exportctl status|clients [--json] ID";
fn parse(args: &[String]) -> Result<(ExportRequest, bool), Errno> {
    let (command, rest) = args.split_first().ok_or(Errno::EINVAL)?;
    let publish = command == "publish";
    let (mut writable, mut execute, mut json) = (false, false, false);
    let (mut name, mut password, mut operand) = (None, None, None);
    let mut transports = vec![];
    let mut seconds = default_lease_secs();
    let mut words = rest.iter();
    let mut options = true;
    while let Some(word) = words.next() {
        let flag = if options { word.as_str() } else { "" };
        match flag {
            "--" => options = false,
            "--json" => json = true,
            "--name" if publish => name = Some(words.next().ok_or(Errno::EINVAL)?.clone()),
            "--password" if publish => password = Some(words.next().ok_or(Errno::EINVAL)?.clone()),
            "--seconds" if publish => {
                seconds = words
                    .next()
                    .ok_or(Errno::EINVAL)?
                    .parse()
                    .map_err(|_| Errno::EINVAL)?
            }
            "--rw" if publish => writable = true,
            "--exec" if publish => execute = true,
            "--ipc-only" if publish => transports = vec![TransportKind::Ipc],
            s if s.starts_with('-') => return Err(Errno::EINVAL),
            _ => {
                if operand.replace(word.clone()).is_some() {
                    return Err(Errno::EINVAL);
                }
            }
        }
    }
    let req = match (command.as_str(), operand) {
        ("publish", Some(path)) => {
            let name = name.unwrap_or_else(|| {
                std::path::Path::new(&path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("share")
                    .to_owned()
            });
            ExportRequest::Publish {
                name,
                source_path: path,
                writable,
                execute,
                seconds,
                password,
                transports,
            }
        }
        ("list", None) => ExportRequest::List {},
        (op, Some(id)) => {
            let id = id.strip_prefix("osfs:").unwrap_or(&id).to_owned();
            match op {
                "revoke" => ExportRequest::Revoke { id },
                "status" => ExportRequest::Status { id },
                "clients" => ExportRequest::ListClients { id },
                _ => return Err(Errno::EINVAL),
            }
        }
        _ => return Err(Errno::EINVAL),
    };
    Ok((req, json))
}
fn sys<T: DeserializeOwned>(call: Call) -> Result<T, Errno> {
    let value = os_posix::batch(&[call])
        .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::EIO))?
        .results
        .pop()
        .ok_or(Errno::EIO)?
        .into_result()
        .map_err(|e| e.errno)?;
    serde_json::from_value(value).map_err(|_| Errno::EIO)
}
fn rpc(req: &ExportRequest) -> Result<ExportResponse, Errno> {
    let uid = sys::<abi::Creds>(Call::Getcreds)?.uid;
    let startup = Instant::now() + Duration::from_secs(1);
    let user = loop {
        if uid == 0 {
            break None;
        }
        match UnixStream::connect(&user_export_sock(uid)) {
            Ok(stream) if stream.peer_cred()?.uid == uid => break Some(stream),
            Ok(_) => return Err(Errno::EACCES),
            Err(Errno::ENOENT | Errno::ECONNREFUSED) => {
                if !matches!(req, ExportRequest::Publish { .. }) || Instant::now() >= startup {
                    break None;
                }
                // The session manager binds its socket asynchronously during login.
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e),
        }
    };
    let Some(stream) = user else {
        return exchange(UnixStream::connect(SYSTEM_EXPORT_SOCK)?, req);
    };
    let first = exchange(stream, req)?;
    let needs_lookup = matches!(
        req,
        ExportRequest::Status { .. }
            | ExportRequest::ListClients { .. }
            | ExportRequest::Revoke { .. }
    ) && matches!(
        first,
        ExportResponse::Error {
            errno: Errno::EACCES
        }
    );
    if !needs_lookup && !matches!(first, ExportResponse::Exports { .. }) {
        return Ok(first);
    }
    // A grant published through the system socket remains there when the user service starts.
    let system = match UnixStream::connect(SYSTEM_EXPORT_SOCK) {
        Ok(stream) => exchange(stream, req)?,
        Err(Errno::ENOENT | Errno::ECONNREFUSED) => return Ok(first),
        Err(e) => return Err(e),
    };
    match (first, system) {
        (ExportResponse::Exports { mut exports }, ExportResponse::Exports { exports: others }) => {
            exports.extend(others);
            Ok(ExportResponse::Exports { exports })
        }
        (_, reply) => Ok(reply),
    }
}

fn exchange(stream: UnixStream, req: &ExportRequest) -> Result<ExportResponse, Errno> {
    let root = if let ExportRequest::Publish { source_path, .. } = req {
        let opened: abi::Opened = sys(Call::OpenAt {
            dirfd: (abi::OS_FD_CWD as u32).into(),
            path: source_path.clone(),
            flags: abi::O_RDONLY | abi::O_DIRECTORY | abi::O_NOFOLLOW,
            mode: 0,
        })?;
        // SAFETY: OpenAt returned a newly owned guest descriptor.
        Some(unsafe { File::from_raw_fd(opened.fd as _) })
    } else {
        None
    };
    let frame = encode_control(req)?;
    let fds: Vec<_> = root.iter().map(|f| f.as_raw_fd() as u32).collect();
    let mut sent = 0;
    while sent < frame.len() {
        match stream.send_with_fds(
            &frame[sent..],
            if sent == 0 { &fds } else { &[] },
            MSG_NOSIGNAL,
        ) {
            Ok(0) => return Err(Errno::EPIPE),
            Ok(n) => sent += n,
            Err(Errno::EINTR) => {}
            Err(e) => return Err(e),
        }
    }
    let mut received = Vec::new();
    let mut buf = [0; 4096];
    loop {
        let n = match stream.recv(&mut buf, 0) {
            Err(Errno::EINTR) => continue,
            other => other?,
        };
        if n == 0 {
            return Err(Errno::ENOTCONN);
        }
        if received.len() + n > CONTROL_MAX {
            return Err(Errno::E2BIG);
        }
        received.extend_from_slice(&buf[..n]);
        if buf[..n].contains(&b'\n') {
            return decode_control(&received);
        }
    }
}
fn render(entry: &ExportEntry) {
    let transports = entry
        .transports
        .iter()
        .map(|t| match t {
            TransportKind::Ipc => "ipc",
            TransportKind::P2p => "p2p",
            TransportKind::Relay => "relay",
        })
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "osfs:{}\t{}\t{}\t{}",
        entry.id, entry.name, entry.source_path, transports
    );
}
pub fn run(args: &[String]) -> i32 {
    if matches!(args,[s] if s=="--help"||s=="-h") {
        println!("{USAGE}");
        return 0;
    }
    let (req, json) = match parse(args) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    let resp = rpc(&req).unwrap_or_else(|errno| ExportResponse::Error { errno });
    if json {
        println!("{}", serde_json::to_string(&resp).expect("export response"));
    }
    if let ExportResponse::Error { errno } = resp {
        if !json {
            eprintln!("exportctl: {errno:?} ({})", errno.text());
        }
        return 1;
    }
    if !json {
        match resp {
            ExportResponse::Published { export } | ExportResponse::Entry { export } => {
                render(&export)
            }
            ExportResponse::Exports { exports } => exports.iter().for_each(render),
            ExportResponse::Clients { clients } => {
                for c in clients {
                    println!("{}\t{}\t{:?}", c.id, c.peer_uid, c.transport);
                }
            }
            _ => {}
        }
    }
    0
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_publish_and_operands() {
        let args = [
            "publish",
            "--rw",
            "--exec",
            "--ipc-only",
            "--seconds",
            "33",
            "--json",
            "--",
            "-dir",
        ]
        .map(str::to_owned);
        let (req, json) = parse(&args).unwrap();
        assert!(json);
        assert!(
            matches!(req,ExportRequest::Publish{writable:true,execute:true,seconds:33,transports,name,..} if transports==[TransportKind::Ipc] && name=="-dir")
        );
        for args in [
            vec!["list", "extra"],
            vec!["publish", "--seconds"],
            vec!["revoke"],
            vec!["status", "--rw", "42"],
        ] {
            assert!(parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err());
        }
    }
}
