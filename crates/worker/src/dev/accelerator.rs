//! Archive/media drivers. CLI parsing is in executable user space; this boundary accepts
//! only typed operations and directory handles belonging to the submitting process.
use abi::accelerator as protocol;
use abi::{Errno, Error};
use kernel::Process;
use os_core::archive::Job as Operation;
use os_core::permissions::Store;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::Request;
use crate::db::{Db, DeviceTask};

type Result<T> = std::result::Result<T, Error>;

fn decode<T: DeserializeOwned>(value: Value) -> Result<T> {
    if value.to_string().len() > protocol::MAX_REQUEST_BYTES {
        return Err(Errno::E2BIG.into());
    }
    if value["version"].as_u64() != Some(u64::from(protocol::VERSION)) {
        return Err(Errno::EOPNOTSUPP.into());
    }
    serde_json::from_value(value).map_err(|e| Error::because(Errno::EINVAL, e.to_string()))
}

fn path(db: &Db, request: &Request, resource: &protocol::PathAt) -> Result<String> {
    if !resource.valid() {
        return Err(Errno::EINVAL.into());
    }
    let control = db.fd(&request.sid, request.fd).ok_or(Errno::EBADF)?;
    crate::fds::yours(
        db,
        &request.sid,
        resource.directory,
        control.proc.as_deref(),
    )?;
    let directory = db
        .fd(&request.sid, resource.directory)
        .ok_or(Errno::EBADF)?;
    let name = directory
        .ino
        .and_then(|ino| {
            db.name_of(ino).or_else(|| {
                // Immutable image directories have synthetic inodes and no mutable SQLite name.
                (crate::usr::is(&directory.path)
                    && db
                        .node(&directory.path)
                        .is_some_and(|node| node.ino == ino && node.directory))
                .then(|| directory.path.clone())
            })
        })
        .ok_or(Errno::ESTALE)?;
    if !db.node(&name).is_some_and(|node| node.directory) {
        return Err(Errno::ENOTDIR.into());
    }
    Ok(if resource.name == "." {
        name
    } else {
        format!("{}/{}", name.trim_end_matches('/'), resource.name)
    })
}

/// Resolve authorized directory handles before snapshotting immutable inputs. The driver
/// derives its label from the operation, never by interpreting an executable name or argv.
fn operation(
    db: &Db,
    request: &Request,
    op: protocol::Operation,
) -> Result<(&'static str, Operation, Vec<String>)> {
    use protocol::{Format, Operation as Op};
    Ok(match op {
        Op::Create {
            format,
            output,
            inputs,
            recursive,
            links,
            verbose,
        } => {
            if inputs.is_empty() || inputs.len() > os_core::archive::ENTRIES_MAX {
                return Err(Errno::E2BIG.into());
            }
            let mut paths = Vec::new();
            let mut names = Vec::new();
            for input in inputs {
                // Names stored in the archive are data, but cannot name a parent or root.
                if input.name.starts_with('/')
                    || input.name.split('/').any(|p| p == "..")
                    || input.name.contains('\0')
                    || input.name.len() > 4096
                {
                    return Err(Errno::EINVAL.into());
                }
                paths.push(path(db, request, &input.source)?);
                names.push(input.name);
            }
            (
                if format == Format::Zip { "zip" } else { "tar" },
                Operation::Create {
                    format,
                    archive: path(db, request, &output)?,
                    paths,
                    recursive,
                    verbose,
                    directory: None,
                    links,
                },
                names,
            )
        }
        Op::Extract {
            format,
            source,
            destination,
            existing,
            members,
            verbose,
        } => (
            if format == Format::Zip {
                "unzip"
            } else {
                "tar"
            },
            Operation::Extract {
                zip: format == Format::Zip,
                archive: path(db, request, &source)?,
                directory: Some(path(db, request, &destination)?),
                existing,
                members,
                verbose,
            },
            Vec::new(),
        ),
        Op::List {
            format,
            source,
            verbose,
        } => (
            if format == Format::Zip {
                "unzip"
            } else {
                "tar"
            },
            Operation::List {
                zip: format == Format::Zip,
                archive: path(db, request, &source)?,
                verbose,
            },
            Vec::new(),
        ),
        Op::Faststart { file } => (
            "faststart",
            Operation::Faststart {
                file: path(db, request, &file)?,
            },
            Vec::new(),
        ),
    })
}

fn task(db: &Db, request: &Request, id: &str) -> Result<DeviceTask> {
    let task = db.device_task(id).ok_or(Errno::ENOENT)?;
    if task.sid != request.sid || task.fd != request.fd || task.device != request.device.name {
        return Err(Errno::EPERM.into());
    }
    Ok(task)
}

pub fn ioctl(
    db: &mut Db,
    process: &Process,
    request: Request,
    op: u32,
    arg: Value,
) -> Result<Value> {
    if !request.writes() {
        return Err(Errno::EBADF.into());
    }
    match op {
        protocol::INFO => Ok(json!({"version": protocol::VERSION,
            "device": request.device.name, "max_active": protocol::MAX_ACTIVE,
            "max_events": protocol::MAX_EVENTS, "max_request_bytes": protocol::MAX_REQUEST_BYTES,
            "max_output_bytes": protocol::MAX_OUTPUT_BYTES})),
        protocol::SUBMIT => {
            let submit: protocol::Submit = decode(arg)?;
            submit.validate()?;
            if submit.operation.device() != request.device.name {
                return Err(Errno::ENOTTY.into());
            }
            let fd = db.fd(&request.sid, request.fd).ok_or(Errno::EBADF)?;
            let controller = fd
                .proc
                .as_deref()
                .and_then(|line| db.controller(line))
                .or_else(|| db.session(&request.sid).map(|s| s.user))
                .unwrap_or(process.cred.id);
            let lineage = fd.proc.unwrap_or_else(|| request.sid.clone());
            let digest = crate::auth::token_hash(&serde_json::to_string(&submit).unwrap());
            if let Some(previous) = db.device_retry(&lineage, &submit.request) {
                if previous.digest != digest || previous.device != request.device.name {
                    return Err(Errno::EEXIST.into());
                }
                return Ok(
                    json!({"version": protocol::VERSION, "id": previous.id, "request": previous.request}),
                );
            }
            if db.active_tasks(controller) >= protocol::MAX_ACTIVE {
                return Err(Errno::EAGAIN.into());
            }
            let (label, operation, names) = operation(db, &request, submit.operation)?;
            let started =
                crate::jobs::start(db, &process.cred, controller, label, operation, &names)
                    .map_err(|why| {
                        Error::because(
                            if crate::commands::is_permission_error(&why) {
                                Errno::EACCES
                            } else {
                                Errno::EINVAL
                            },
                            why,
                        )
                    })?;
            let id = started["job"].as_str().ok_or(Errno::EIO)?.to_string();
            let token = crate::auth::random_token();
            let now = crate::auth::now();
            db.job_credential(
                &id,
                &crate::auth::token_hash(&token),
                &process.cred,
                process.umask,
                now,
            );
            if let Ok(source) =
                serde_json::from_value::<crate::jobs::Source>(started["source"].clone())
            {
                let owner = crate::creds::job_owner(&id);
                let source_fd = db.add_fd(
                    &owner,
                    Some(&source.file),
                    &source.path,
                    abi::O_RDONLY,
                    false,
                    now,
                );
                db.set_fd_proc(&owner, source_fd, &owner);
            }
            let spec =
                crate::jobs::Spec::of(&db.job(&id).ok_or(Errno::EIO)?).map_err(|_| Errno::EIO)?;
            let mut grants = Vec::new();
            if let Some(directory) = spec.directory {
                let inode = db.node(&directory).ok_or(Errno::ENOENT)?.ino;
                grants.push(crate::executor::WriteGrant {
                    directory,
                    inode,
                    name: None,
                });
            }
            if let Some(output) = spec.output {
                let directory = os_core::parent(&output).to_string();
                let inode = db.node(&directory).ok_or(Errno::ENOENT)?.ino;
                let name = output.rsplit('/').next().map(str::to_string);
                grants.push(crate::executor::WriteGrant {
                    directory,
                    inode,
                    name,
                });
            }
            db.set_expiry("device_task", &id, now + crate::jobs::WAITING);
            db.bind_device_task(&DeviceTask {
                id: id.clone(),
                lineage,
                request: submit.request.clone(),
                device: request.device.name,
                digest,
                sid: request.sid,
                fd: request.fd,
                owner: controller,
                detached: 0,
                grants: serde_json::to_string(&grants).unwrap(),
            });
            // sys.rs consumes this private launch envelope before serializing the reply.
            Ok(
                json!({"version": protocol::VERSION, "id": id, "request": submit.request,
                "_launch": {"job": id, "token": token}}),
            )
        }
        protocol::POLL => {
            let poll: protocol::Poll = decode(arg)?;
            let task = task(db, &request, &poll.id)?;
            if poll.limit == 0 || poll.limit as usize > protocol::MAX_EVENTS {
                return Err(Errno::EINVAL.into());
            }
            let job = db.job(&task.id).ok_or(Errno::ENOENT)?;
            let mut lines = db.lines(&job.id, poll.after, poll.limit + 1);
            let mut more = lines.len() > poll.limit as usize;
            lines.truncate(poll.limit as usize);
            let mut events = Vec::new();
            let mut bytes = 0;
            for (sequence, stderr, text) in lines {
                let event = protocol::Event::Output {
                    sequence,
                    stderr,
                    text,
                };
                let size = serde_json::to_vec(&event).map_err(|_| Errno::EIO)?.len();
                if bytes + size > protocol::MAX_REQUEST_BYTES - 8192 {
                    if events.is_empty() {
                        return Err(Errno::E2BIG.into());
                    }
                    more = true;
                    break;
                }
                bytes += size;
                events.push(event);
            }
            if !more && job.state == "question" {
                let question: Value = job
                    .question
                    .as_deref()
                    .and_then(|q| serde_json::from_str(q).ok())
                    .ok_or(Errno::EIO)?;
                let paths =
                    serde_json::from_value(question["replace"].clone()).map_err(|_| Errno::EIO)?;
                let event = protocol::Event::Conflict {
                    sequence: conflict_sequence(&job),
                    paths,
                };
                let size = serde_json::to_vec(&event).map_err(|_| Errno::EIO)?.len();
                if bytes + size > protocol::MAX_REQUEST_BYTES - 8192
                    || events.len() == poll.limit as usize
                {
                    if events.is_empty() {
                        return Err(Errno::E2BIG.into());
                    }
                    more = true;
                } else {
                    events.push(event);
                }
            }
            let progress: Value = serde_json::from_str(&job.progress).unwrap_or_default();
            let errors = progress["errors"].as_u64().unwrap_or(0);
            let reply = json!(protocol::Completion {
                version: protocol::VERSION,
                id: task.id,
                request: task.request,
                state: job.state.clone(),
                events,
                more,
                completed: progress["done"].as_u64().unwrap_or(0),
                total: progress["total"].as_u64().unwrap_or(0),
                errors,
                error: if job.state == "cancelled" {
                    Some(Errno::ECANCELED)
                } else if job.state == "failed" || errors > 0 {
                    Some(serde_json::from_value(progress["errno"].clone()).unwrap_or(Errno::EIO))
                } else {
                    None
                },
                status: job
                    .finished()
                    .then_some(if job.state == "done" && errors == 0 {
                        0
                    } else {
                        1
                    }),
            });
            if reply.to_string().len() > protocol::MAX_REQUEST_BYTES {
                return Err(Errno::E2BIG.into());
            }
            Ok(reply)
        }
        protocol::ANSWER => {
            let answer: protocol::Answer = decode(arg)?;
            let task = task(db, &request, &answer.id)?;
            let job = db.job(&task.id).ok_or(Errno::ENOENT)?;
            if job.state != "question" || conflict_sequence(&job) != answer.sequence {
                return Err(Errno::EAGAIN.into());
            }
            let question: Value = job
                .question
                .as_deref()
                .and_then(|q| serde_json::from_str(q).ok())
                .ok_or(Errno::EIO)?;
            let expected: std::collections::BTreeSet<String> =
                serde_json::from_value(question["replace"].clone()).map_err(|_| Errno::EIO)?;
            if answer.decisions.len() != expected.len()
                || expected.iter().any(|p| !answer.decisions.contains_key(p))
            {
                return Err(Errno::EINVAL.into());
            }
            crate::jobs::answer(db, &task.id, answer.decisions)?;
            Ok(json!({"_launch": {"job": task.id}, "id": task.id}))
        }
        protocol::CANCEL | protocol::DETACH | protocol::ATTACH => {
            let control: protocol::Control = decode(arg)?;
            let task = if op == protocol::ATTACH {
                let task = db.device_task(&control.id).ok_or(Errno::ENOENT)?;
                if task.device != request.device.name
                    || (task.owner != process.cred.id && process.cred.id != 0)
                {
                    return Err(Errno::EPERM.into());
                }
                if task.detached == 0
                    && (task.sid != request.sid || task.fd != request.fd)
                    && db.fd(&task.sid, task.fd).is_some()
                {
                    return Err(Errno::EBUSY.into());
                }
                task
            } else {
                task(db, &request, &control.id)?
            };
            if op == protocol::CANCEL {
                if db.job(&task.id).is_some_and(|job| !job.finished()) {
                    crate::executor::finish(db, &task.id, "cancelled");
                }
                Ok(json!({"id": task.id, "_launch": {"job": task.id}}))
            } else {
                db.attach_device_task(&task.id, &request.sid, request.fd, op == protocol::DETACH);
                Ok(json!({"id": task.id}))
            }
        }
        _ => Err(super::not_for(op)),
    }
}

fn conflict_sequence(job: &crate::db::Job) -> u64 {
    // A deterministic, JSON-safe revision of the immutable conflict list.
    let hash = crate::auth::token_hash(job.question.as_deref().unwrap_or_default());
    u64::from_str_radix(&hash[..12], 16).unwrap_or(0)
}

pub fn closed(db: &mut Db, sid: &str, fd: u32) {
    for task in db.tasks_on(sid, fd) {
        if db.job(&task.id).is_some_and(|job| !job.finished()) {
            crate::executor::finish(db, &task.id, "cancelled");
        }
    }
}
