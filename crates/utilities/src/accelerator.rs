//! Executable archive/media clients. Parsing, terminal interaction and exit status belong
//! here; the driver sees typed operations over authorized resource handles.
use abi::accelerator as protocol;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use terminal_worker_core::archive::{self, Job};

fn call(call: abi::Call) -> Result<Value, String> {
    terminal_worker_posix::batch(&[call])
        .map_err(|e| e.to_string())?
        .results
        .remove(0)
        .into_result()
        .map_err(|e| e.to_string())
}

#[derive(Default)]
struct Handles {
    directories: HashMap<String, u32>,
    all: Vec<u32>,
}
impl Handles {
    fn open(&mut self, path: &str, flags: u32) -> Result<u32, String> {
        let opened = call(abi::Call::Open {
            path: path.into(),
            flags,
            mode: 0,
            size: None,
            sha256: None,
            version: None,
        })?;
        let fd = opened["fd"].as_u64().ok_or("open returned no descriptor")? as u32;
        self.all.push(fd);
        Ok(fd)
    }
    fn resource(&mut self, base: &str, typed: &str) -> Result<protocol::PathAt, String> {
        let path = terminal_worker_core::resolve(base, typed)?;
        let (directory, name) = if path == "/" {
            ("/", ".")
        } else {
            let (parent, name) = path.rsplit_once('/').ok_or("invalid path")?;
            (if parent.is_empty() { "/" } else { parent }, name)
        };
        let fd = match self.directories.get(directory) {
            Some(fd) => *fd,
            None => {
                let fd = self.open(directory, abi::O_PATH | abi::O_DIRECTORY)?;
                self.directories.insert(directory.into(), fd);
                fd
            }
        };
        Ok(protocol::PathAt {
            directory: fd,
            name: name.into(),
        })
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

fn operation(handles: &mut Handles, cwd: &str, job: Job) -> Result<protocol::Operation, String> {
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
            let base = terminal_worker_core::resolve(cwd, directory.as_deref().unwrap_or("."))?;
            let output = handles.resource(cwd, &archive)?;
            let mut inputs = Vec::new();
            for path in paths {
                inputs.push(protocol::Input {
                    source: handles.resource(&base, &path)?,
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
            let source = handles.resource(cwd, &archive)?;
            let destination =
                terminal_worker_core::resolve(cwd, directory.as_deref().unwrap_or("."))?;
            if zip {
                // Creating the destination is an ordinary user-space filesystem operation.
                std::fs::metadata(terminal_worker_core::resolve(cwd, &archive)?)
                    .map_err(|e| e.to_string())?;
                std::fs::create_dir_all(&destination).map_err(|e| e.to_string())?;
            }
            Op::Extract {
                format: if zip { Format::Zip } else { Format::Tar },
                source,
                destination: handles.resource(cwd, &destination)?,
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
            source: handles.resource(cwd, &archive)?,
            verbose,
        },
        Job::Faststart { file } => Op::Faststart {
            file: handles.resource(cwd, &file)?,
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
    let cwd = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .to_string_lossy()
        .into_owned();
    let operation = operation(&mut handles, &cwd, parsed)?;
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
