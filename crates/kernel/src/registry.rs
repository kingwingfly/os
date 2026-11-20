//! Instance-local process & cgroup policy rules: who may invoke which local process/cgroup
//! syscall, and who may create/write/attach cgroups or manage processes.
//!
//! Retired server-side `Machine` DO process routes (`ProcInit`, `Seats`, `Gone`, `Pids`,
//! `Execve`, `Fork`, `Exit`, `MachineInit`, `LoginSession`, `ProcSession`, `ProcPoll`,
//! `ProcKeep`, `ProcTty`, `Resource`) have been removed cleanly (Contract §2.12).
use abi::{Call, Errno, Error};
use os_core::permissions::Identity;

/// Who an instance-local process/cgroup call comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    /// The local host adapter / client kernel itself.
    Registry,
    /// A browser page / UI batch acting as the session's account.
    Page,
    /// A running WASI process (invoking `os.sys` locally).
    Process,
}

/// As whom a permitted local call acts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acting {
    /// As an account (the page's account or the process's credential snapshot).
    Account,
    /// As the calling process itself.
    Itself,
}

/// PID 1's init reaper grants only orphan reaping (`getpid`, `waitpid`), never arbitrary root calls.
pub fn permit_reaper(call: &Call) -> Result<(), Error> {
    match call {
        Call::Getpid | Call::Waitpid { .. } => Ok(()),
        _ => Err(Errno::EPERM.into()),
    }
}

/// Whether `caller` may make the local process/cgroup call `call`, and as whom it acts:
/// `EPERM` for a call reserved for another caller, `ENOSYS` for non-process calls.
pub fn permit(caller: Caller, call: &Call) -> Result<Acting, Error> {
    use Caller::{Page, Process, Registry};
    if !call.is_registry() {
        return Err(Error::because(
            Errno::ENOSYS,
            "not a local process/cgroup call",
        ));
    }
    match call {
        Call::Wait { token, .. } => match caller {
            Registry if token.is_none() => Ok(Acting::Account),
            Registry | Process => Ok(Acting::Itself),
            Page => Err(Errno::EPERM.into()),
        },
        Call::Getpid
        | Call::Getpgid { .. }
        | Call::Getsid { .. }
        | Call::Setpgid { .. }
        | Call::Setsid
        | Call::ProcStopped { .. }
        | Call::Prctl { .. }
        | Call::Waitpid { .. } => match caller {
            Process => Ok(Acting::Itself),
            Registry | Page => Err(Error::because(Errno::EPERM, "a process's call")),
        },
        Call::Kill { .. }
        | Call::CgroupCreate { .. }
        | Call::CgroupRemove { .. }
        | Call::CgroupSet { .. }
        | Call::CgroupAttach { .. }
        | Call::CgroupStat { .. }
        | Call::CgroupList { .. } => Ok(Acting::Account),
        // Any future registry call without an explicit rule fails closed.
        _ => Err(Error::because(Errno::EPERM, "no rule says who may make it")),
    }
}

/// The cgroup every account may make cgroups in, as systemd delegates a user's slice: what is
/// made there is its maker's, which it may write, attach its own processes to, and remove.
pub const DELEGATED: &str = "/user";
/// The most `devices.allow` and `devices.deny` rules a cgroup keeps.
pub const DEVICE_RULES_MAX: usize = 64;
/// The controllers a cgroup may enable for its subtree (`cgroup.subtree_control`).
pub const CONTROLLERS: [&str; 5] = ["cpu", "io", "memory", "pids", "devices"];

/// Component-aware subtree membership; similarly prefixed siblings never match.
pub fn in_subtree(path: &str, root: &str) -> bool {
    root == "/"
        || path == root
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}

/// Whether `cred` may make a cgroup in the cgroup `parent`, owned by `owner`: root anywhere,
/// an account in a cgroup of its own, or in the delegated one.
pub fn may_create(cred: &Identity, parent: &str, owner: u32) -> bool {
    cred.id == 0 || owner == cred.id || parent == DELEGATED
}

/// Whether `cred` may write the control files of, or remove, a cgroup owned by `owner`.
pub fn may_write(cred: &Identity, owner: u32) -> bool {
    cred.id == 0 || owner == cred.id
}

/// Process cleanup obeys the same ownership boundary as kill, regardless of its route.
pub fn may_manage_process(cred: &Identity, owner: u32) -> bool {
    cred.id == 0 || owner == cred.id
}

/// Whether `cred` may move a process of the account `uid` into the cgroup `path`, owned by
/// `owner`: its own processes, into a cgroup of its own or the delegated one; root any.
pub fn may_attach(cred: &Identity, uid: u32, path: &str, owner: u32) -> bool {
    cred.id == 0 || (uid == cred.id && (owner == cred.id || path == DELEGATED))
}

/// The controllers `spec` enables, as `cgroup.subtree_control` takes them (`+cpu +memory`, or
/// `cpu memory`), each once, in a fixed order: EINVAL for one cgroup v2 does not have here.
pub fn controllers(spec: &str) -> Result<String, Error> {
    let mut enabled = Vec::new();
    for word in spec.split_whitespace() {
        let name = word.strip_prefix('+').unwrap_or(word);
        if !CONTROLLERS.contains(&name) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("{name} is not a controller (cpu, io, memory, pids, devices)"),
            ));
        }
        if !enabled.contains(&name) {
            enabled.push(name);
        }
    }
    enabled.sort_by_key(|name| CONTROLLERS.iter().position(|known| known == name));
    Ok(enabled.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn kill() -> Call {
        Call::Kill {
            pid: "7".into(),
            signal: None,
        }
    }

    #[test]
    fn process_only_calls_require_a_process_caller() {
        for call in [
            Call::Getpid,
            Call::Getpgid { pid: 0 },
            Call::Getsid { pid: 0 },
            Call::Setpgid { pid: 0, pgid: 0 },
            Call::Setsid,
            Call::ProcStopped { signal: 20 },
            Call::Prctl {
                option: 36,
                value: 1,
            },
            Call::Waitpid {
                pid: -1,
                options: 1,
            },
        ] {
            assert_eq!(permit(Caller::Process, &call), Ok(Acting::Itself));
            assert_eq!(permit(Caller::Page, &call).unwrap_err().errno, Errno::EPERM);
            assert_eq!(
                permit(Caller::Registry, &call).unwrap_err().errno,
                Errno::EPERM
            );
        }
    }

    #[test]
    fn reaper_only_permits_getpid_and_waitpid() {
        assert!(permit_reaper(&Call::Getpid).is_ok());
        assert!(
            permit_reaper(&Call::Waitpid {
                pid: -1,
                options: 1
            })
            .is_ok()
        );
        assert_eq!(permit_reaper(&kill()).unwrap_err().errno, Errno::EPERM);
        assert_eq!(
            permit_reaper(&Call::CgroupCreate {
                path: "/system/x".into(),
                controllers: None,
                lifetime: None,
            })
            .unwrap_err()
            .errno,
            Errno::EPERM
        );
    }

    #[test]
    fn non_registry_calls_return_enosys() {
        assert_eq!(
            permit(Caller::Page, &Call::Getcreds).unwrap_err().errno,
            Errno::ENOSYS
        );
        assert_eq!(
            permit(
                Caller::Process,
                &Call::Kill {
                    pid: "deadbeef".into(),
                    signal: Some(15)
                }
            )
            .unwrap_err()
            .errno,
            Errno::ENOSYS
        );
    }

    #[test]
    fn cgroup_and_process_management_boundaries() {
        let root = Identity::root();
        let ann = Identity {
            id: 1000,
            group: 1000,
            groups: BTreeSet::from([1000]),
        };
        let bob = Identity {
            id: 1001,
            group: 1001,
            groups: BTreeSet::from([1001]),
        };
        assert!(may_create(&root, "/system", 0));
        assert!(may_create(&ann, "/user", 0));
        assert!(!may_create(&ann, "/system", 0));
        assert!(may_write(&ann, 1000));
        assert!(!may_write(&bob, 1000));
        assert!(may_manage_process(&root, 1000));
        assert!(may_manage_process(&ann, 1000));
        assert!(!may_manage_process(&bob, 1000));
        assert!(may_attach(&ann, 1000, "/user", 0));
        assert!(!may_attach(&ann, 1001, "/user", 0));
        assert!(in_subtree("/user/a/b", "/user/a"));
        assert!(!in_subtree("/user/ab", "/user/a"));
        assert_eq!(
            controllers("+pids +memory +cpu").unwrap(),
            "cpu memory pids"
        );
        assert_eq!(controllers("bogus").unwrap_err().errno, Errno::EINVAL);
    }
}
