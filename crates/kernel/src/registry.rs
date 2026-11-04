//! The process registry's rules (each browser's machine, crates/worker/src/machine.rs): who may
//! make which of its calls, and as whom each acts; and who may change a cgroup. The registry
//! keeps its record in SQLite (crates/worker/src/procs.rs); what it decides is here, as plain
//! rules that can be tested without it. Every registry call is in `permit`'s table: a call
//! added to the ABI without a rule is refused.
use abi::{Call, Errno, Error};
use terminal_worker_core::permissions::Identity;

/// Who a registry call comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Caller {
    /// The browser's client kernel, by its own route (a batch marked `X-Registry`, with no
    /// process's token): it hosts the processes, and tells of their forks, exits and waits.
    Kernel,
    /// A page's batch, which the authority forwards with no process's token: user space, as
    /// the page's account.
    Page,
    /// A process: any batch carrying a process's token, whatever route it took. Uploaded wasm
    /// reaches the registry this way (terminal.sys), so it is given nothing of the kernel's.
    Process,
}

/// As whom a call the caller may make acts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acting {
    /// As the kernel itself: its bookkeeping (the namespace, pids lent, tabs and kernels gone,
    /// the processes it names by their tokens), and init's waits.
    Kernel,
    /// As an account: the page's, for the kernel's and the page's calls, or the process's
    /// snapshot, for a process's.
    Account,
    /// As the calling process, on itself (its fork, its exit, getpid) or its children (wait).
    Itself,
}

/// Whether `caller` may make the registry call `call`, and as whom it acts: EPERM for a call
/// that is another caller's, ENOSYS for one that is not the registry's.
pub fn permit(caller: Caller, call: &Call) -> Result<Acting, Error> {
    use Caller::{Kernel, Page, Process};
    if !call.is_registry() {
        return Err(Error::because(
            Errno::ENOSYS,
            "not the process registry's call: the filesystem's go to the authority",
        ));
    }
    match call {
        Call::ProcInit { .. } | Call::Pids { .. } | Call::Seats | Call::Gone { .. } => match caller
        {
            Kernel => Ok(Acting::Kernel),
            Page | Process => Err(Error::because(Errno::EPERM, "the client kernel's call")),
        },
        Call::Execve { .. } => match caller {
            Kernel | Page => Ok(Acting::Account),
            Process => Err(Error::because(
                Errno::EPERM,
                "a process replaces itself through its kernel, which holds its token",
            )),
        },
        Call::Fork { .. } | Call::Exit { .. } | Call::Wait { .. } => match caller {
            Kernel => Ok(Acting::Kernel),
            Process => Ok(Acting::Itself),
            Page => Err(Error::because(
                Errno::EPERM,
                "the client kernel tells of forks, exits and waits",
            )),
        },
        Call::Getpid => match caller {
            Process => Ok(Acting::Itself),
            Kernel | Page => Err(Error::because(Errno::EPERM, "a process's call")),
        },
        Call::ProcPoll { .. }
        | Call::Kill { .. }
        | Call::CgroupCreate { .. }
        | Call::CgroupRemove { .. }
        | Call::CgroupSet { .. }
        | Call::CgroupAttach { .. }
        | Call::CgroupStat { .. }
        | Call::CgroupList { .. } => Ok(Acting::Account),
        // A registry call with no rule yet is nobody's.
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

/// Whether `cred` may make a cgroup in the cgroup `parent`, owned by `owner`: root anywhere,
/// an account in a cgroup of its own, or in the delegated one.
pub fn may_create(cred: &Identity, parent: &str, owner: u32) -> bool {
    cred.id == 0 || owner == cred.id || parent == DELEGATED
}

/// Whether `cred` may write the control files of, or remove, a cgroup owned by `owner`.
pub fn may_write(cred: &Identity, owner: u32) -> bool {
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
    fn the_kernels_calls_are_its_own() {
        for call in [
            Call::ProcInit { boot: None },
            Call::Pids {
                count: 8,
                kernel: None,
            },
            Call::Seats,
            Call::Gone {
                seat: Some("tab".into()),
                kernel: None,
            },
        ] {
            assert_eq!(permit(Caller::Kernel, &call), Ok(Acting::Kernel));
            // Neither a page nor a process (uploaded wasm, through terminal.sys) may begin a
            // namespace, drain its pids, or end another tab's processes.
            for caller in [Caller::Page, Caller::Process] {
                assert_eq!(permit(caller, &call).unwrap_err().errno, Errno::EPERM);
            }
        }
    }

    #[test]
    fn lifecycle_calls_are_the_kernels_or_the_process_own() {
        let exit = Call::Exit {
            status: 0,
            signal: None,
            pid: None,
            token: None,
        };
        let wait = Call::Wait {
            pid: "3".into(),
            since: 0,
        };
        for call in [exit, wait] {
            assert_eq!(permit(Caller::Kernel, &call), Ok(Acting::Kernel));
            assert_eq!(permit(Caller::Process, &call), Ok(Acting::Itself));
            assert_eq!(permit(Caller::Page, &call).unwrap_err().errno, Errno::EPERM);
        }
        assert_eq!(permit(Caller::Process, &Call::Getpid), Ok(Acting::Itself));
        assert_eq!(
            permit(Caller::Kernel, &Call::Getpid).unwrap_err().errno,
            Errno::EPERM
        );
        let execve = Call::Execve {
            pid: None,
            token: None,
            path: "/usr/bin/coreutils".into(),
            argv: vec![],
            env: vec![],
            cwd: "/".into(),
            cgroup: None,
            seat: None,
        };
        assert_eq!(permit(Caller::Page, &execve), Ok(Acting::Account));
        assert_eq!(
            permit(Caller::Process, &execve).unwrap_err().errno,
            Errno::EPERM
        );
    }

    #[test]
    fn signals_polls_and_cgroups_act_as_the_account() {
        for caller in [Caller::Kernel, Caller::Page, Caller::Process] {
            assert_eq!(permit(caller, &kill()), Ok(Acting::Account));
            let set = Call::CgroupSet {
                path: "/user/x".into(),
                key: "cpu.weight".into(),
                value: "10".into(),
            };
            assert_eq!(permit(caller, &set), Ok(Acting::Account));
        }
        // Not the registry's: the filesystem's, or a job's.
        assert_eq!(
            permit(Caller::Kernel, &Call::Getcreds).unwrap_err().errno,
            Errno::ENOSYS
        );
        let job = Call::Kill {
            pid: "a1b2".into(),
            signal: None,
        };
        assert_eq!(permit(Caller::Page, &job).unwrap_err().errno, Errno::ENOSYS);
    }

    #[test]
    fn cgroups_are_their_makers_and_roots() {
        let ann = Identity {
            id: 1000,
            group: 1000,
            groups: BTreeSet::from([1000]),
        };
        let root = Identity::root();
        // Anyone makes cgroups in the delegated one; in another, its owner or root.
        assert!(may_create(&ann, DELEGATED, 0));
        assert!(!may_create(&ann, "/system", 0));
        assert!(may_create(&ann, "/user/ann", 1000));
        assert!(!may_create(&ann, "/user/bob", 1001));
        assert!(may_create(&root, "/system", 0));
        // Root's cgroups are root's to write.
        assert!(!may_write(&ann, 0));
        assert!(may_write(&ann, 1000));
        assert!(may_write(&root, 1000));
        // An account moves its own processes, into its own cgroups or the delegated one.
        assert!(may_attach(&ann, 1000, "/user/ann", 1000));
        assert!(may_attach(&ann, 1000, DELEGATED, 0));
        assert!(!may_attach(&ann, 1001, "/user/ann", 1000));
        assert!(!may_attach(&ann, 1000, "/init", 0));
        assert!(may_attach(&root, 1001, "/init", 0));
    }

    #[test]
    fn controllers_are_cgroup_v2s() {
        assert_eq!(controllers("+memory +cpu memory").unwrap(), "cpu memory");
        assert_eq!(controllers("").unwrap(), "");
        assert_eq!(controllers("+rdma").unwrap_err().errno, Errno::EINVAL);
    }
}
