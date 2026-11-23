//! Local mount policy. The listener supplies SO_PEERCRED and the backend binds every
//! operation to that connection. Client JSON never supplies the acting credentials.
use abi::Errno;
use abi::contract::FsType;
use abi::mount_ctl::*;
use abi::mount_flags::*;
use abi::socket::PeerCred;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub use abi::mount_ctl::MAX_FRAME_BYTES;
const USER_LOCK: u64 = MS_NOSUID | MS_NODEV;

pub trait MountBackend {
    /// `target_pid` is a namespace selector. The kernel checks the live target again when
    /// applying an operation. The accepted peer socket remains the authority.
    fn call(&mut self, request: MountBackendRequest) -> Result<Value, Errno>;
}

#[derive(Debug)]
struct Failure(Errno, MountErrorKind, String);
type Result<T, E = Failure> = std::result::Result<T, E>;

impl From<Errno> for Failure {
    fn from(errno: Errno) -> Self {
        let kind = match errno {
            Errno::EACCES | Errno::EPERM | Errno::EROFS => MountErrorKind::Denied,
            Errno::ENOTCONN => MountErrorKind::Offline,
            Errno::ESTALE => MountErrorKind::Revoked,
            Errno::ENOENT | Errno::ESRCH => MountErrorKind::NotFound,
            Errno::ENODEV | Errno::ENOSYS | Errno::EOPNOTSUPP => MountErrorKind::Unsupported,
            Errno::EBUSY => MountErrorKind::Busy { processes: vec![] },
            Errno::ECANCELED => MountErrorKind::Cancelled,
            _ => MountErrorKind::InvalidArgument,
        };
        Self(errno, kind, errno.text().into())
    }
}

fn query<T: DeserializeOwned>(
    backend: &mut impl MountBackend,
    pid: Option<u32>,
    op: MountBackendOp,
) -> Result<T> {
    let reply = backend.call(MountBackendRequest {
        target_pid: pid,
        op,
    })?;
    serde_json::from_value(reply).map_err(|_| Errno::EIO.into())
}

fn grant_required() -> Failure {
    let hint = "Choose a folder in Mounts and use its source ID.".to_string();
    Failure(
        Errno::EACCES,
        MountErrorKind::HostGrantRequired { hint: hint.clone() },
        hint,
    )
}

fn visible(uid: u32, owner: Option<u32>) -> bool {
    owner.is_none_or(|id| id == uid)
}
fn sources(backend: &mut impl MountBackend, uid: u32, pid: Option<u32>) -> Result<Vec<SourceInfo>> {
    let rows: Vec<SourceInfo> = query(backend, pid, MountBackendOp::Sources {})?;
    Ok(rows
        .into_iter()
        .filter(|s| visible(uid, s.owner_uid))
        .collect())
}

fn attachments(
    backend: &mut impl MountBackend,
    uid: u32,
    pid: Option<u32>,
    include_busy: bool,
) -> Result<Vec<AttachmentInfo>> {
    let mut rows: Vec<AttachmentInfo> =
        query(backend, pid, MountBackendOp::Attachments { include_busy })?;
    rows.retain(|a| visible(uid, a.owner_uid));
    for row in &mut rows {
        row.busy_pids
            .retain(|p| include_busy && (uid == 0 || p.uid == uid));
    }
    Ok(rows)
}

fn attachment(
    backend: &mut impl MountBackend,
    uid: u32,
    pid: Option<u32>,
    target: &str,
    busy: bool,
) -> Result<AttachmentInfo> {
    attachments(backend, uid, pid, busy)?
        .into_iter()
        .rev()
        .find(|a| a.target == target)
        .ok_or_else(|| Errno::EACCES.into())
}

fn source(
    backend: &mut impl MountBackend,
    uid: u32,
    pid: Option<u32>,
    id: &str,
) -> Result<SourceInfo> {
    sources(backend, uid, pid)?
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| Errno::EACCES.into())
}

fn granted(s: &SourceInfo) -> Result<()> {
    match s.state {
        SourceState::Granted => Ok(()),
        SourceState::NeedsRenewal => {
            let hint = "Renew permission for this source in Mounts.".to_owned();
            Err(Failure(
                Errno::EACCES,
                MountErrorKind::NeedsRenewal {
                    source_id: s.id.clone(),
                    hint: hint.clone(),
                },
                hint,
            ))
        }
        SourceState::Revoked => Err(Failure(
            Errno::EACCES,
            MountErrorKind::Revoked,
            "Source grant revoked".into(),
        )),
        SourceState::Offline => Err(Errno::ENOTCONN.into()),
        SourceState::Unavailable => Err(Errno::ENODEV.into()),
    }
}

fn clean_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn target_uid(b: &mut impl MountBackend, peer: PeerCred, pid: Option<u32>) -> Result<u32> {
    match pid {
        Some(pid) if pid != peer.pid => {
            if peer.uid != 0 {
                return Err(Errno::EPERM.into());
            }
            query(b, Some(pid), MountBackendOp::Peer {})
        }
        _ => Ok(peer.uid),
    }
}

fn apply(b: &mut impl MountBackend, pid: Option<u32>, op: MountBackendOp) -> Result<MountResponse> {
    query::<()>(b, pid, op)?;
    Ok(MountResponse::Ok {})
}

fn flags_from_attachment(row: &AttachmentInfo) -> u64 {
    row.options
        .iter()
        .map(|s| match s.as_str() {
            "ro" => MS_RDONLY,
            "nosuid" => MS_NOSUID,
            "nodev" => MS_NODEV,
            "noexec" => MS_NOEXEC,
            "sync" => MS_SYNCHRONOUS,
            "dirsync" => MS_DIRSYNC,
            "nosymfollow" => MS_NOSYMFOLLOW,
            "noatime" => MS_NOATIME,
            "relatime" => MS_RELATIME,
            "strictatime" => MS_STRICTATIME,
            "nodiratime" => MS_NODIRATIME,
            "lazytime" => MS_LAZYTIME,
            _ => 0,
        })
        .fold(0, |a, b| a | b)
}

fn dispatch(
    b: &mut impl MountBackend,
    peer: PeerCred,
    request: MountRequest,
) -> Result<MountResponse> {
    let uid = peer.uid;
    match request {
        MountRequest::ListSources => Ok(MountResponse::Sources {
            sources: sources(b, uid, None)?,
        }),
        MountRequest::ListFilesystems => Ok(MountResponse::Filesystems {
            filesystems: query(b, None, MountBackendOp::Filesystems {})?,
        }),
        MountRequest::ListAttachments { include_busy } => Ok(MountResponse::Attachments {
            attachments: attachments(b, uid, None, include_busy)?,
        }),
        MountRequest::ListAll { include_busy } => {
            let mut exports: Vec<ExportSummary> = match query(b, None, MountBackendOp::Exports {}) {
                Err(Failure(Errno::ENOENT | Errno::ECONNREFUSED | Errno::ENOTCONN, ..)) => {
                    Vec::new()
                }
                other => other?,
            };
            exports.retain(|e| e.owner_uid == uid);
            Ok(MountResponse::All {
                sources: sources(b, uid, None)?,
                filesystems: query(b, None, MountBackendOp::Filesystems {})?,
                attachments: attachments(b, uid, None, include_busy)?,
                exports,
            })
        }
        MountRequest::BusyProcesses { target } => Ok(MountResponse::Busy {
            processes: attachment(b, uid, None, &target, true)?.busy_pids,
        }),
        MountRequest::Attach {
            source_id,
            source: raw,
            target,
            fstype,
            flags,
            options,
            target_pid,
        } => {
            let acting = target_uid(b, peer, target_pid)?;
            let mut flags = accepted(flags)?;
            if flags & MS_REMOUNT != 0 {
                return Err(Errno::EINVAL.into());
            }
            let topology = flags & (MS_BIND | MS_MOVE | MS_PRIVATE) != 0;
            if acting != 0 && topology {
                return Err(Errno::EPERM.into());
            }
            let id = source_id
                .as_deref()
                .or_else(|| raw.starts_with("src:").then_some(raw.as_str()));
            let grant = id.map(|id| source(b, acting, target_pid, id)).transpose()?;
            let fstype = if fstype.is_empty()
                && let Some(s) = &grant
            {
                s.kind.fstype().to_owned()
            } else {
                fstype
            };
            let kind = if topology {
                None
            } else {
                Some(FsType::parse(&fstype)?)
            };
            if acting != 0 && !kind.is_some_and(FsType::is_user_mountable) {
                return Err(Errno::EPERM.into());
            }
            let mut owner_uid = (acting != 0).then_some(acting);
            let name = if let Some(s) = grant {
                granted(&s)?;
                if kind == Some(FsType::Image) && s.owner_uid == Some(acting) {
                    let name = target
                        .strip_prefix("/opt/private/")
                        .filter(|n| clean_name(n))
                        .ok_or(Errno::EPERM)?;
                    let execute = s.execute && flags & MS_NOEXEC == 0;
                    return apply(
                        b,
                        target_pid,
                        MountBackendOp::Activate {
                            additional_sources: vec![],
                            source_id: s.id,
                            name: name.into(),
                            execute,
                        },
                    );
                }
                if topology || s.kind.fstype() != fstype {
                    return Err(Errno::EINVAL.into());
                }
                if !s.writable {
                    flags |= MS_RDONLY;
                }
                if !s.execute {
                    flags |= MS_NOEXEC;
                }
                owner_uid = owner_uid.or(s.owner_uid);
                s.id
            } else {
                if matches!(kind, Some(FsType::HostFs | FsType::HelperFs)) {
                    return Err(grant_required());
                }
                // Implicit browser storage is local to the authenticated session.
                let implicit = kind == Some(FsType::Opfs)
                    || (kind == Some(FsType::ShareFs)
                        && raw.strip_prefix("osfs:").is_some_and(|id| !id.is_empty()));
                if acting != 0 && kind.is_some_and(FsType::is_user_mountable) && !implicit {
                    return Err(grant_required());
                }
                raw
            };
            if owner_uid.is_some() {
                let path = target.strip_prefix('/').ok_or(Errno::EPERM)?;
                if path
                    .split('/')
                    .any(|name| abi::fs::check_component(name).is_err())
                {
                    return Err(Errno::EPERM.into());
                }
                flags |= USER_LOCK;
            }
            apply(
                b,
                target_pid,
                MountBackendOp::Attach {
                    source: name,
                    target,
                    fstype,
                    flags,
                    options,
                    owner_uid,
                },
            )
        }
        MountRequest::Detach {
            target,
            lazy,
            force,
            target_pid,
        } => {
            let acting = target_uid(b, peer, target_pid)?;
            if acting != 0 && force {
                return Err(Errno::EPERM.into());
            }
            let a = attachment(b, acting, target_pid, &target, false)?;
            if a.owner_uid != Some(acting) && acting != 0 {
                return Err(Errno::EPERM.into());
            }
            if uid != acting && a.owner_uid.is_some() {
                return Err(Errno::EACCES.into());
            }
            let op = MountBackendOp::Detach {
                target: target.clone(),
                mount_id: a.mount_id,
                lazy,
                force,
            };
            match apply(b, target_pid, op) {
                Err(Failure(Errno::EBUSY, ..)) => {
                    let processes = attachment(b, acting, target_pid, &target, true)?.busy_pids;
                    Err(Failure(
                        Errno::EBUSY,
                        MountErrorKind::Busy { processes },
                        "target is busy".into(),
                    ))
                }
                other => other,
            }
        }
        MountRequest::Remount {
            target,
            flags,
            options,
        } => {
            let flags = accepted(flags)? | MS_REMOUNT;
            let a = attachment(b, uid, None, &target, false)?;
            if uid != 0 {
                let locked = flags_from_attachment(&a) & !(MS_RDONLY | MS_NOEXEC);
                if a.owner_uid != Some(uid)
                    || flags & USER_LOCK != USER_LOCK
                    || flags & !(MS_RDONLY | MS_NOEXEC | MS_REMOUNT) != locked
                    || options.as_ref().is_some_and(|s| !s.is_empty())
                {
                    return Err(Errno::EPERM.into());
                }
            }
            apply(
                b,
                None,
                MountBackendOp::Remount {
                    target,
                    mount_id: a.mount_id,
                    flags,
                    options,
                },
            )
        }
        MountRequest::ActivatePrivate {
            additional_sources,
            source_id,
            name,
            execute,
        } => {
            if !clean_name(&name) {
                return Err(Errno::EINVAL.into());
            }
            let s = source(b, uid, None, &source_id)?;
            granted(&s)?;
            if execute && !s.execute && s.kind != SourceKind::SelectedFiles {
                return Err(Errno::EACCES.into());
            }
            if additional_sources.len() >= 16 {
                return Err(Errno::E2BIG.into());
            }
            for id in &additional_sources {
                let grant = source(b, uid, None, id)?;
                granted(&grant)?;
                if execute && !grant.execute && grant.kind != SourceKind::SelectedFiles {
                    return Err(Errno::EACCES.into());
                }
            }
            apply(
                b,
                None,
                MountBackendOp::Activate {
                    additional_sources,
                    source_id,
                    name,
                    execute,
                },
            )
        }
        MountRequest::ForgetSource { source_id } => {
            if source(b, uid, None, &source_id)?.owner_uid != Some(uid) {
                return Err(Errno::EACCES.into());
            }
            apply(b, None, MountBackendOp::Forget { source_id })
        }
    }
}

pub fn handle_request(
    backend: &mut impl MountBackend,
    user_socket: Option<u32>,
    peer: PeerCred,
    request: MountRequest,
) -> MountResponse {
    let result = if user_socket.is_some_and(|uid| uid != peer.uid) {
        Err(Errno::EACCES.into())
    } else {
        dispatch(backend, peer, request)
    };
    result.unwrap_or_else(|Failure(errno, error, message)| MountResponse::Error {
        errno,
        error,
        message,
    })
}

pub fn error_response(error: abi::Error) -> MountResponse {
    let Failure(errno, kind, message) = error.errno.into();
    MountResponse::Error {
        errno,
        error: kind,
        message: error.detail.unwrap_or(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MemoryBackend {
        sources: Vec<SourceInfo>,
        mounts: Vec<AttachmentInfo>,
        export_error: Option<Errno>,
        last: Option<MountBackendOp>,
        users: BTreeMap<u32, u32>,
    }
    impl MountBackend for MemoryBackend {
        fn call(&mut self, req: MountBackendRequest) -> Result<Value, Errno> {
            match req.op {
                MountBackendOp::Sources {} => Ok(json!(self.sources)),
                MountBackendOp::Attachments { .. } => Ok(json!(self.mounts)),
                MountBackendOp::Filesystems {} => Ok(json!([])),
                MountBackendOp::Exports {} => self.export_error.map_or_else(|| Ok(json!([])), Err),
                MountBackendOp::Peer {} => self
                    .users
                    .get(&req.target_pid.unwrap())
                    .map(|u| json!(u))
                    .ok_or(Errno::ESRCH),
                MountBackendOp::Attach { ref fstype, .. } if fstype == "cloud" => {
                    Err(Errno::ENOTCONN)
                }
                MountBackendOp::Detach {
                    ref target, lazy, ..
                } => {
                    if self
                        .mounts
                        .iter()
                        .any(|a| a.target == *target && !a.busy_pids.is_empty())
                        && !lazy
                    {
                        return Err(Errno::EBUSY);
                    }
                    self.mounts.retain(|a| a.target != *target);
                    self.last = Some(req.op);
                    Ok(Value::Null)
                }
                other => {
                    self.last = Some(other);
                    Ok(Value::Null)
                }
            }
        }
    }
    fn peer(uid: u32) -> PeerCred {
        PeerCred {
            uid,
            gid: uid,
            pid: uid + 10,
        }
    }
    fn grant(uid: u32) -> SourceInfo {
        SourceInfo {
            id: format!("src:{uid}"),
            kind: SourceKind::Hostfs,
            label: "work".into(),
            location: "work".into(),
            state: SourceState::Granted,
            writable: true,
            execute: true,
            saved: true,
            owner_uid: Some(uid),
        }
    }
    fn mount(uid: Option<u32>, target: &str) -> AttachmentInfo {
        AttachmentInfo {
            ns_id: 1,
            fs_id: 1,
            mount_id: 5,
            parent_id: 1,
            source_id: uid.map(|u| format!("src:{u}")),
            target: target.into(),
            source_label: "test".into(),
            fstype: "hostfs".into(),
            options: vec!["rw".into(), "nosuid".into(), "nodev".into()],
            read_only: false,
            nosuid: true,
            nodev: true,
            noexec: false,
            owner_uid: uid,
            user_mount: uid.is_some(),
            health: "connected".into(),
            uncertain_writes: false,
            busy_pids: vec![],
        }
    }
    fn request(b: &mut MemoryBackend, uid: u32, v: Value) -> MountResponse {
        handle_request(b, None, peer(uid), serde_json::from_value(v).unwrap())
    }
    fn assert_errno(reply: MountResponse, expected: Errno) {
        assert!(
            matches!(reply, MountResponse::Error { errno,.. } if errno == expected),
            "{reply:?}"
        );
    }
    fn attach(id: &str) -> Value {
        json!({"op":"attach","fstype":"hostfs","source_id":id,"source":"label","target":"/mnt/local/x"})
    }

    #[test]
    fn per_user_socket_checks_peer_before_any_verb_and_system_lists_four_objects() {
        let mut b = MemoryBackend {
            sources: vec![grant(1000), grant(1001)],
            mounts: vec![
                mount(None, "/"),
                mount(Some(1000), "/x"),
                mount(Some(1001), "/y"),
            ],
            ..Default::default()
        };
        for uid in [0, 1001] {
            assert_errno(
                handle_request(&mut b, Some(1000), peer(uid), MountRequest::ListSources),
                Errno::EACCES,
            );
        }
        for (uid, count) in [(0, 1), (1000, 2)] {
            let MountResponse::All {
                sources,
                attachments,
                filesystems,
                exports,
            } = request(&mut b, uid, json!({"op":"list_all"}))
            else {
                panic!()
            };
            assert_eq!(attachments.len(), count);
            assert_eq!(sources.len(), count - 1);
            assert!(filesystems.is_empty() && exports.is_empty());
        }
    }

    #[test]
    fn attach_fences_targets_types_source_ownership_and_locks_user_flags() {
        let mut b = MemoryBackend {
            sources: vec![grant(1000)],
            ..Default::default()
        };
        assert!(matches!(
            request(&mut b, 1000, attach("src:1000")),
            MountResponse::Ok {}
        ));
        assert!(matches!(
            b.last,
            Some(MountBackendOp::Attach {
                flags: USER_LOCK,
                owner_uid: Some(1000),
                ..
            })
        ));
        for uid in [0, 1001] {
            assert_errno(request(&mut b, uid, attach("src:1000")), Errno::EACCES);
        }
        for target in ["/tmp/a", "/mnt/local/a/b"] {
            let mut v = attach("src:1000");
            v["target"] = json!(target);
            assert!(matches!(request(&mut b, 1000, v), MountResponse::Ok {}));
        }
        for target in ["/", "/mnt/local/..", "/mnt/local/a/../b"] {
            let mut v = attach("src:1000");
            v["target"] = json!(target);
            assert_errno(request(&mut b, 1000, v), Errno::EPERM);
        }
        for flag in [MS_BIND, MS_BIND | MS_REC, MS_MOVE] {
            let mut v = attach("src:1000");
            v["flags"] = json!(flag);
            assert_errno(request(&mut b, 1000, v), Errno::EPERM);
        }
        let mut targeted = attach("src:1000");
        targeted["target_pid"] = json!(77);
        assert_errno(request(&mut b, 1000, targeted.clone()), Errno::EPERM);
        b.users.insert(77, 1000);
        assert!(matches!(request(&mut b, 0, targeted), MountResponse::Ok {}));
        assert!(matches!(
            b.last,
            Some(MountBackendOp::Attach {
                flags: USER_LOCK,
                owner_uid: Some(1000),
                ..
            })
        ));
    }

    #[test]
    fn only_owner_can_remount_and_only_ro_noexec_can_change() {
        let mut b = MemoryBackend {
            mounts: vec![mount(Some(1000), "/mnt/local/x")],
            ..Default::default()
        };
        for flags in [MS_NOSUID, MS_NODEV, USER_LOCK | MS_DIRSYNC] {
            assert_errno(
                request(
                    &mut b,
                    1000,
                    json!({"op":"remount","target":"/mnt/local/x","flags":flags}),
                ),
                Errno::EPERM,
            );
        }
        for uid in [1001, 0] {
            assert_errno(
                request(
                    &mut b,
                    uid,
                    json!({"op":"remount","target":"/mnt/local/x","flags":0}),
                ),
                Errno::EACCES,
            );
        }
        let req =
            json!({"op":"remount","target":"/mnt/local/x","flags":USER_LOCK|MS_RDONLY|MS_NOEXEC});
        assert!(matches!(request(&mut b, 1000, req), MountResponse::Ok {}));
    }

    #[test]
    fn busy_pid_visibility_and_ordinary_force_lazy_detach() {
        let mut a = mount(Some(1000), "/mnt/local/x");
        for uid in [1000, 1001] {
            a.busy_pids.push(BusyProcess {
                pid: uid + 1,
                uid,
                comm: "sh".into(),
                reasons: vec!["cwd".into(), "fd".into()],
            });
        }
        let mut b = MemoryBackend {
            mounts: vec![a, mount(None, "/")],
            ..Default::default()
        };
        let target = "/mnt/local/x";
        assert_errno(
            request(&mut b, 1000, json!({"op":"detach","target":"/"})),
            Errno::EPERM,
        );
        assert_errno(
            request(
                &mut b,
                1000,
                json!({"op":"detach","target":target,"force":true}),
            ),
            Errno::EPERM,
        );
        assert_errno(
            request(
                &mut b,
                1001,
                json!({"op":"detach","target":target,"lazy":true}),
            ),
            Errno::EACCES,
        );
        let r = request(&mut b, 1000, json!({"op":"detach","target":target}));
        assert!(
            matches!(r,MountResponse::Error{errno:Errno::EBUSY,error:MountErrorKind::Busy{processes},..} if processes.len()==1 && processes[0].uid==1000)
        );
        assert!(matches!(
            request(
                &mut b,
                1000,
                json!({"op":"detach","target":target,"lazy":true})
            ),
            MountResponse::Ok {}
        ));
        assert_eq!(b.mounts.len(), 1);
    }

    #[test]
    fn missing_revoked_and_unrenewed_grants_are_distinct_and_never_mutate() {
        let mut b = MemoryBackend {
            sources: vec![grant(1000)],
            ..Default::default()
        };
        let r = request(
            &mut b,
            1000,
            json!({"op":"attach","fstype":"hostfs","source":"","target":"/mnt/local/x"}),
        );
        assert!(matches!(
            r,
            MountResponse::Error {
                errno: Errno::EACCES,
                error: MountErrorKind::HostGrantRequired { .. },
                ..
            }
        ));
        b.sources[0].state = SourceState::NeedsRenewal;
        let r = request(&mut b, 1000, attach("src:1000"));
        assert!(matches!(
            r,
            MountResponse::Error {
                errno: Errno::EACCES,
                error: MountErrorKind::NeedsRenewal { .. },
                ..
            }
        ));
        b.sources[0].state = SourceState::Revoked;
        assert!(matches!(
            request(&mut b, 1000, attach("src:1000")),
            MountResponse::Error {
                error: MountErrorKind::Revoked,
                ..
            }
        ));
        assert!(b.last.is_none());
    }

    #[test]
    fn activate_and_forget_require_owned_grants_and_obey_execute_ceiling() {
        let mut b = MemoryBackend {
            sources: vec![grant(1000)],
            ..Default::default()
        };
        let activate =
            json!({"op":"activate_private","source_id":"src:1000","name":"pkg","execute":true});
        let image = json!({"op":"attach","fstype":"image","source_id":"src:1000","source":"","target":"/opt/private/pkg","flags":MS_NOEXEC});
        assert!(matches!(request(&mut b, 1000, image), MountResponse::Ok {}));
        assert!(matches!(
            b.last,
            Some(MountBackendOp::Activate { execute: false, .. })
        ));
        assert_errno(request(&mut b, 0, activate.clone()), Errno::EACCES);
        b.sources[0].execute = false;
        assert_errno(request(&mut b, 1000, activate), Errno::EACCES);
        let forget = json!({"op":"forget_source","source_id":"src:1000"});
        assert_errno(request(&mut b, 1001, forget.clone()), Errno::EACCES);
        assert!(matches!(
            request(&mut b, 1000, forget),
            MountResponse::Ok {}
        ));
    }

    #[test]
    fn local_drivers_and_offline_cloud_report_kernel_results() {
        let mut b = MemoryBackend {
            export_error: Some(Errno::ECONNREFUSED),
            ..Default::default()
        };
        assert!(
            matches!(request(&mut b,1000,json!({"op":"list_all"})), MountResponse::All { exports,.. } if exports.is_empty())
        );
        for kind in [
            "cowfs", "tmpfs", "proc", "devpts", "devtmpfs", "image", "opfs", "sharefs",
        ] {
            let r = request(
                &mut b,
                0,
                json!({"op":"attach","fstype":kind,"source":"/dev/loop2","target":"/mnt","options":"subvol=x,excl"}),
            );
            assert!(matches!(r, MountResponse::Ok {}), "{kind}: {r:?}");
        }
        for fstype in ["tmpfs", "cowfs", "proc", "devtmpfs", "cloud"] {
            assert_errno(
                request(
                    &mut b,
                    1000,
                    json!({"op":"attach","fstype":fstype,"source":"test","target":"/mnt/local/x"}),
                ),
                Errno::EPERM,
            );
        }
        assert_errno(
            request(
                &mut b,
                0,
                json!({"op":"attach","fstype":"sysfs","source":"","target":"/sys"}),
            ),
            Errno::ENODEV,
        );
        assert!(matches!(
            request(
                &mut b,
                0,
                json!({"op":"attach","fstype":"cloud","source":"cloud","target":"/mnt/cloud"})
            ),
            MountResponse::Error {
                errno: Errno::ENOTCONN,
                error: MountErrorKind::Offline,
                ..
            }
        ));
    }
}
