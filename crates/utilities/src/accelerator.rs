//! Executable archive/media clients. Parsing, terminal interaction and exit status belong
//! here; the driver sees typed operations over authorized resource handles.
use abi::accelerator as protocol;
use os_core::archive::{self, Job};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};

fn call(call: abi::Call) -> Result<Value, String> {
    os_posix::batch(&[call])
        .map_err(|e| e.to_string())?
        .results
        .remove(0)
        .into_result()
        .map_err(|e| e.to_string())
}

pub(crate) fn anchor(
    base: &str,
    typed: &str,
    allow_dir_self: bool,
) -> Result<(String, String), String> {
    if typed.is_empty() || typed.contains('\0') || base.contains('\0') {
        return Err("invalid path".into());
    }
    let joined = if typed.starts_with('/') || base.is_empty() || base == "." {
        typed.to_string()
    } else if base == "/" {
        format!("/{typed}")
    } else {
        format!("{}/{}", base.trim_end_matches('/'), typed)
    };
    let trimmed = joined.trim_end_matches('/');
    if trimmed.is_empty() {
        return if allow_dir_self {
            Ok(("/".into(), ".".into()))
        } else {
            Err("invalid path".into())
        };
    }
    let (raw_parent, leaf) = match trimmed.rsplit_once('/') {
        Some((parent, leaf)) => {
            let dir = if parent.bytes().all(|b| b == b'/') {
                "/"
            } else {
                parent
            };
            (dir, leaf)
        }
        None => (".", trimmed),
    };
    if leaf == "." || leaf == ".." {
        return if allow_dir_self {
            Ok((trimmed.to_string(), ".".into()))
        } else {
            Err("invalid path".into())
        };
    }
    if leaf.is_empty() {
        return Err("invalid path".into());
    }
    if leaf.len() > abi::NAME_MAX {
        return Err("Filename is too long".into());
    }
    Ok((raw_parent.to_string(), leaf.to_string()))
}

#[derive(Default)]
struct Handles {
    directories: HashMap<String, u32>,
    all: Vec<u32>,
}
impl Handles {
    fn open(&mut self, path: &str, flags: u32) -> Result<u32, String> {
        let open = if path.starts_with('/') {
            abi::Call::Open {
                path: path.into(),
                flags,
                mode: 0,
                size: None,
                sha256: None,
                version: None,
            }
        } else {
            abi::Call::OpenAt {
                dirfd: (abi::OS_FD_CWD as u32).into(),
                path: path.into(),
                flags,
                mode: 0,
            }
        };
        let opened = call(open)?;
        let fd = opened["fd"].as_u64().ok_or("open returned no descriptor")? as u32;
        self.all.push(fd);
        Ok(fd)
    }
    fn resolve_with(
        &mut self,
        base: &str,
        typed: &str,
        allow_dir_self: bool,
    ) -> Result<protocol::PathAt, String> {
        let (directory, name) = anchor(base, typed, allow_dir_self)?;
        let fd = match self.directories.get(&directory) {
            Some(fd) => *fd,
            None => {
                let fd = self.open(&directory, abi::O_PATH | abi::O_DIRECTORY)?;
                self.directories.insert(directory, fd);
                fd
            }
        };
        Ok(protocol::PathAt {
            directory: fd,
            name,
            open: None,
        })
    }
    fn resource(&mut self, base: &str, typed: &str) -> Result<protocol::PathAt, String> {
        self.resolve_with(base, typed, false)
    }
    fn dir_or_entry(&mut self, base: &str, typed: &str) -> Result<protocol::PathAt, String> {
        self.resolve_with(base, typed, true)
    }
}
impl Drop for Handles {
    fn drop(&mut self) {
        for fd in self.all.drain(..).rev() {
            let _ = call(abi::Call::Close { fd: fd.into() });
        }
    }
}

fn ioctl(fd: u32, request: u32, arg: impl serde::Serialize) -> Result<Value, String> {
    call(abi::Call::Ioctl {
        fd: fd.into(),
        request,
        arg: serde_json::to_value(arg).map_err(|e| e.to_string())?,
    })
}

fn operation(handles: &mut Handles, job: Job) -> Result<protocol::Operation, String> {
    use protocol::{Format, Operation as Op};
    Ok(match job {
        Job::Create {
            format,
            archive,
            paths,
            recursive,
            verbose,
            directory,
            links,
        } => {
            let base = directory.as_deref().unwrap_or(".");
            let output = handles.resource(".", &archive)?;
            let mut inputs = Vec::new();
            for path in paths {
                inputs.push(protocol::Input {
                    source: handles.dir_or_entry(base, &path)?,
                    name: archive::stored_name(&path),
                });
            }
            Op::Create {
                format,
                output,
                inputs,
                recursive,
                links,
                verbose,
            }
        }
        Job::Extract {
            zip,
            archive,
            directory,
            existing,
            members,
            verbose,
        } => {
            let source = handles.resource(".", &archive)?;
            let destination = directory.as_deref().unwrap_or(".");
            if zip {
                // Creating the destination is an ordinary user-space filesystem operation.
                std::fs::metadata(&archive).map_err(|e| e.to_string())?;
                std::fs::create_dir_all(destination).map_err(|e| e.to_string())?;
            }
            Op::Extract {
                format: if zip { Format::Zip } else { Format::Tar },
                source,
                destination: handles.dir_or_entry(".", destination)?,
                existing,
                members,
                verbose,
            }
        }
        Job::List {
            zip,
            archive,
            verbose,
        } => Op::List {
            format: if zip { Format::Zip } else { Format::Tar },
            source: handles.resource(".", &archive)?,
            verbose,
        },
        Job::Faststart { file } => Op::Faststart {
            file: handles.resource(".", &file)?,
        },
    })
}

fn decide(paths: Vec<String>) -> Result<BTreeMap<String, bool>, String> {
    let mut decisions = BTreeMap::new();
    let mut all = None;
    for path in paths {
        let replace = if let Some(answer) = all {
            answer
        } else {
            eprint!("replace {path}? [y]es, [n]o, [A]ll, [N]one: ");
            io::stderr().flush().map_err(|e| e.to_string())?;
            let mut answer = String::new();
            if io::stdin()
                .read_line(&mut answer)
                .map_err(|e| e.to_string())?
                == 0
            {
                return Err("end of input while waiting for an answer".into());
            }
            match answer.trim() {
                "A" | "All" => {
                    all = Some(true);
                    true
                }
                "N" | "None" => {
                    all = Some(false);
                    false
                }
                a => a.to_lowercase().starts_with('y'),
            }
        };
        decisions.insert(path, replace);
    }
    Ok(decisions)
}

pub fn run(name: &str, args: &[String]) -> Result<i32, String> {
    let parsed = match name {
        "zip" => archive::zip_args(args),
        "unzip" => archive::unzip_args(args),
        "tar" => archive::tar_args(args),
        "faststart" => archive::faststart_args(args),
        _ => return Err("unsupported client".into()),
    }?;
    let mut handles = Handles::default();
    let operation = operation(&mut handles, parsed)?;
    let device = handles.open(operation.device(), abi::O_RDWR)?;
    let info = ioctl(device, protocol::INFO, Value::Null)?;
    if info["version"] != protocol::VERSION {
        return Err("unsupported accelerator protocol".into());
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let request = format!("{}-{nonce}", call(abi::Call::Getpid)?["pid"]);
    let submitted = ioctl(
        device,
        protocol::SUBMIT,
        protocol::Submit {
            version: protocol::VERSION,
            request: request.clone(),
            operation,
        },
    )?;
    let id = submitted["id"]
        .as_str()
        .ok_or("submission returned no request handle")?
        .to_string();
    let mut after = 0;
    loop {
        let result = ioctl(
            device,
            protocol::POLL,
            protocol::Poll {
                version: protocol::VERSION,
                id: id.clone(),
                after,
                limit: protocol::MAX_EVENTS as u32,
            },
        )?;
        let result: protocol::Completion =
            serde_json::from_value(result).map_err(|e| e.to_string())?;
        if result.version != protocol::VERSION || result.id != id || result.request != request {
            return Err("invalid accelerator completion".into());
        }
        for event in result.events {
            match event {
                protocol::Event::Output {
                    sequence,
                    stderr,
                    text,
                } => {
                    if stderr {
                        writeln!(io::stderr(), "{text}")
                    } else {
                        writeln!(io::stdout(), "{text}")
                    }
                    .map_err(|e| e.to_string())?;
                    after = sequence;
                }
                protocol::Event::Conflict { sequence, paths } => {
                    ioctl(
                        device,
                        protocol::ANSWER,
                        protocol::Answer {
                            version: protocol::VERSION,
                            id: id.clone(),
                            sequence,
                            decisions: decide(paths)?,
                        },
                    )?;
                }
            }
        }
        io::stdout().flush().map_err(|e| e.to_string())?;
        if result.more {
            continue;
        }
        if let Some(status) = result.status {
            return Ok(status.into());
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::anchor;

    #[test]
    fn anchor_preserves_symlink_dotdot_and_posix_name_max() {
        // Must NOT collapse `symlink_to_deep_dir/..` lexically before kernel O_PATH open.
        assert_eq!(
            anchor(".", "symlink_to_deep_dir/../archive.tar", false).unwrap(),
            ("symlink_to_deep_dir/..".into(), "archive.tar".into())
        );
        assert_eq!(
            anchor("sub/link/..", "nested/../bundle.tgz", false).unwrap(),
            ("sub/link/../nested/..".into(), "bundle.tgz".into())
        );
        assert_eq!(
            anchor(".", "plain.zip", false).unwrap(),
            (".".into(), "plain.zip".into())
        );
        assert_eq!(
            anchor(".", "/top.tar", false).unwrap(),
            ("/".into(), "top.tar".into())
        );
        assert_eq!(
            anchor(".", "///top.tar", false).unwrap(),
            ("/".into(), "top.tar".into())
        );

        // 255-byte POSIX NAME_MAX and `.directory` are permitted on local/VFS mounts.
        let max_leaf = "x".repeat(abi::NAME_MAX);
        assert_eq!(
            anchor("/mnt/local/proj", &max_leaf, false).unwrap(),
            ("/mnt/local/proj".into(), max_leaf)
        );
        assert_eq!(
            anchor("/mnt/local/proj", ".directory", false).unwrap(),
            ("/mnt/local/proj".into(), ".directory".into())
        );

        // > 255-byte leaf fails.
        let too_long = "x".repeat(abi::NAME_MAX + 1);
        assert!(anchor("/mnt/local/proj", &too_long, false).is_err());

        // Leaf-only resources reject `.` / `..` / `/` / NUL.
        for bad in ["", "/", "///", ".", "..", "a/.", "a/..", "a\0b"] {
            assert!(
                anchor(".", bad, false).is_err(),
                "expected error for {bad:?}"
            );
        }

        // Directory destinations / archive inputs permit `.`, `/`, and `link/..` via `(raw_dir, ".")`.
        assert_eq!(anchor(".", ".", true).unwrap(), (".".into(), ".".into()));
        assert_eq!(anchor(".", "/", true).unwrap(), ("/".into(), ".".into()));
        assert_eq!(
            anchor(".", "link/..", true).unwrap(),
            ("link/..".into(), ".".into())
        );
    }
}
