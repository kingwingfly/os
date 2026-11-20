//! Portable, zero-DOM, zero-`wasm-bindgen` instance-local process table (`LocalProcessTable`).
//!
//! Each OS instance (browser tab/client-kernel or `os-native` process) owns its own PID namespace,
//! process groups, sessions, controlling terminal metadata, signals, waitpid/reaping, subreapers,
//! local cgroup v2 policies, and local login-scope fences (`docs/architecture/contract.md` §2.1,
//! §2.3, §2.4, §7).
//!
//! Remote credentials (`RemoteCredRef`) are explicit, optional, and monotonically attenuated:
//! - Booting PID 1, `fork`, `exit`, `waitpid`, `kill`, `setsid`, `setpgid`, `prctl`, `cgroup_*`,
//!   and `/proc/*` rendering require **zero** outbound network RPCs.
//! - Dropping local privilege via `set_cred` clears any ambient `RemoteCredRef` unless an explicit
//!   lower-identity remote credential is passed, returning any token whose last live local holder
//!   just dropped it so the host revokes it immediately over `ServiceAuth v2`.
use crate::local_cgroups::{
    CgroupSetEffect, CgroupTable, align_memory, normalize_cgroup_path, runtime_enforces_memory,
};
use crate::registry::{in_subtree, may_manage_process};
use abi::auth_v2::RemoteScope;
use abi::contract::InstanceIdentity;
use abi::{
    CgroupLifetime, Errno, Error, PendingSignal, Placement, Proc, ProcState, SIGCHLD, SIGCONT,
    SIGHUP, SIGKILL, SIGSTOP, SIGTSTP, Target, exit_status, signal_status,
};
use os_core::permissions::Identity;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const SIGTTIN: u8 = 21;
const SIGTTOU: u8 = 22;

/// Maximum concurrent processes (loading + running + stopped + zombies) in one instance.
pub const PROC_MAX: usize = abi::PROC_MAX;

/// Maximum dynamic PID before wrap-around (PID 1 is reserved for init).
pub const PID_MAX: u32 = 32_768;

/// Maximum combined argv bytes per exec.
pub const ARG_MAX: usize = 65_536;

/// Maximum combined environment bytes per exec.
pub const ENV_MAX: usize = 65_536;

/// `waitpid` option bits (Linux ABI).
pub const WNOHANG: u32 = 1;
pub const WUNTRACED: u32 = 2;
pub const WCONTINUED: u32 = 8;

/// `prctl` option numbers (Linux ABI).
pub const PR_SET_CHILD_SUBREAPER: u32 = 36;
pub const PR_GET_CHILD_SUBREAPER: u32 = 37;

/// Optional remote cloud-service credential bound to a local process.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCredRef {
    pub token: String,
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub instance_id: String,
    pub lineage: String,
    pub cloud_access: bool,
    pub scope: RemoteScope,
}

/// Complete local + optional remote credential snapshot of a process.
#[derive(Clone, Debug)]
pub struct LocalCred {
    pub identity: Identity,
    pub umask: u16,
    pub remote: Option<RemoteCredRef>,
    pub cloud_access: bool,
}

impl LocalCred {
    pub fn local_only(identity: Identity, umask: u16) -> Self {
        Self {
            identity,
            umask: umask & 0o777,
            remote: None,
            cloud_access: false,
        }
    }

    pub fn with_remote(identity: Identity, umask: u16, remote: RemoteCredRef) -> Self {
        let cloud_access = remote.cloud_access;
        Self {
            identity,
            umask: umask & 0o777,
            remote: Some(remote),
            cloud_access,
        }
    }
}

/// Unconsumed POSIX `waitpid` state change for a child process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WaitEvent {
    Exited { status: i32, signal: Option<u8> },
    Stopped { signal: u8 },
    Continued,
}

/// One process entry inside `LocalProcessTable`.
#[derive(Clone, Debug)]
pub struct LocalProc {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub state: ProcState,
    pub cred: LocalCred,
    pub path: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub cgroup: String,
    pub ctty: Option<u32>,
    pub tty_fds: Vec<u32>,
    pub owner_host: String,
    pub login_scope: Option<String>,
    pub subreaper: bool,
    pub execed: bool,
    pub loading: bool,
    pub memory_bytes: u64,
    pub runtime_tracked: bool,
    pub exit_status: Option<i32>,
    pub exit_signal: Option<u8>,
    pub wait_event: Option<WaitEvent>,
    pub pending_signals: Vec<PendingSignal>,
    pub started: u64,
    pub ended: u64,
}

impl LocalProc {
    pub fn comm(&self) -> String {
        self.argv
            .first()
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.path)
            .rsplit('/')
            .next()
            .unwrap_or("proc")
            .to_string()
    }

    pub fn to_abi_proc(&self) -> Proc {
        let wait_status = match (self.exit_signal, self.exit_status) {
            (Some(sig), _) => signal_status(sig),
            (None, Some(code)) => exit_status(code),
            (None, None) => 0,
        };
        Proc {
            pending_signals: self.pending_signals.clone(),
            pid: self.pid,
            ppid: self.ppid,
            pgid: self.pgid,
            sid: self.sid,
            state: self.state,
            status: wait_status,
            signal: self.exit_signal,
            uid: self.cred.identity.id,
            gid: self.cred.identity.group,
            cgroup: self.cgroup.clone(),
            path: self.path.clone(),
            argv: self.argv.clone(),
            started: self.started,
            ended: self.ended,
            seat: Some(self.owner_host.clone()),
            placement: Placement {
                cluster: "local".into(),
                executor: self.owner_host.clone(),
                cgroup: self.cgroup.clone(),
            },
        }
    }

    pub fn to_snapshot(&self) -> ProcSnapshot {
        ProcSnapshot {
            pid: self.pid,
            ppid: self.ppid,
            pgid: self.pgid,
            sid: self.sid,
            uid: self.cred.identity.id,
            gid: self.cred.identity.group,
            state: self.state,
            cgroup: self.cgroup.clone(),
            comm: self.comm(),
            path: self.path.clone(),
            argv: self.argv.clone(),
            started: self.started,
            tty: self.ctty,
            tty_fds: self.tty_fds.clone(),
            login_scope: self.login_scope.clone(),
        }
    }
}

/// Input specification for spawning a new process locally.
#[derive(Clone, Debug)]
pub struct SpawnSpec {
    pub path: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub cred: LocalCred,
    pub cgroup: Option<String>,
    pub owner_host: String,
    pub login_scope: Option<String>,
    pub runtime: Option<String>,
    pub ppid: Option<u32>,
    pub pgid: Option<u32>,
    pub sid: Option<u32>,
    pub initial_state: ProcState,
}

impl SpawnSpec {
    pub fn new(path: impl Into<String>, cred: LocalCred, owner_host: impl Into<String>) -> Self {
        let path = path.into();
        Self {
            argv: vec![path.clone()],
            path,
            env: Vec::new(),
            cwd: "/".into(),
            cred,
            cgroup: None,
            owner_host: owner_host.into(),
            login_scope: None,
            runtime: Some(crate::local_cgroups::RESOURCE_CONTRACT.into()),
            ppid: None,
            pgid: None,
            sid: None,
            initial_state: ProcState::Running,
        }
    }
}

/// Input specification for replacing a process image (`execve`).
#[derive(Clone, Debug)]
pub struct ReexecSpec {
    pub path: String,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<String>,
    pub runtime: Option<String>,
    pub cloud_access: bool,
    pub new_remote: Option<RemoteCredRef>,
}

/// Record of a signal queued or applied to a local process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalDelivery {
    pub pid: u32,
    pub owner_host: String,
    pub signal: u8,
    pub sequence: u64,
    pub killed: bool,
}

/// Result of `LocalProcessTable::exit`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExitOutcome {
    pub pid: u32,
    pub ppid: u32,
    pub reaped: bool,
    pub signals: Vec<SignalDelivery>,
    /// Remote service tokens whose last live local holder just exited; host MUST revoke via `ServiceAuth v2`.
    pub revoked_tokens: Vec<String>,
    /// Any additional processes terminated immediately (e.g., `CgroupLifetime::Process` subtree).
    pub killed_pids: Vec<u32>,
}

/// Result of `LocalProcessTable::waitpid`.
#[derive(Clone, Debug, PartialEq)]
pub enum WaitOutcome {
    Reaped(Box<Proc>),
    Event { pid: u32, status: i32 },
    Pending,
}

/// Read-only snapshot consumed by local `/proc` rendering (`ProcBridge`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcSnapshot {
    pub pid: u32,
    pub ppid: u32,
    pub pgid: u32,
    pub sid: u32,
    pub uid: u32,
    pub gid: u32,
    pub state: ProcState,
    pub cgroup: String,
    pub comm: String,
    pub path: String,
    pub argv: Vec<String>,
    pub started: u64,
    pub tty: Option<u32>,
    pub tty_fds: Vec<u32>,
    pub login_scope: Option<String>,
}

/// Portable, instance-owned process table.
#[derive(Clone, Debug)]
pub struct LocalProcessTable {
    identity: InstanceIdentity,
    booted_at: u64,
    next_pid: u32,
    next_signal_seq: u64,
    procs: BTreeMap<u32, LocalProc>,
    cgroups: CgroupTable,
    closed_scopes: BTreeSet<String>,
}

fn validate_exec_vectors(path: &str, argv: &[String], env: &[String]) -> Result<(), Error> {
    if path.is_empty() || path.len() > 4096 || path.contains('\0') {
        return Err(Errno::EINVAL.into());
    }
    let mut arg_bytes = 0usize;
    for a in argv {
        if a.contains('\0') {
            return Err(Errno::EINVAL.into());
        }
        arg_bytes = arg_bytes.saturating_add(a.len() + 1);
        if arg_bytes > ARG_MAX {
            return Err(Errno::E2BIG.into());
        }
    }
    let mut env_bytes = 0usize;
    for e in env {
        if e.contains('\0') {
            return Err(Errno::EINVAL.into());
        }
        env_bytes = env_bytes.saturating_add(e.len() + 1);
        if env_bytes > ENV_MAX {
            return Err(Errno::E2BIG.into());
        }
    }
    Ok(())
}

fn is_stop_signal(sig: u8) -> bool {
    matches!(sig, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

impl LocalProcessTable {
    pub fn new(identity: InstanceIdentity, now: u64) -> Self {
        Self {
            identity,
            booted_at: now,
            next_pid: 2,
            next_signal_seq: 0,
            procs: BTreeMap::new(),
            cgroups: CgroupTable::new(),
            closed_scopes: BTreeSet::new(),
        }
    }

    pub fn identity(&self) -> &InstanceIdentity {
        &self.identity
    }

    pub fn booted_at(&self) -> u64 {
        self.booted_at
    }

    pub fn cgroups(&self) -> &CgroupTable {
        &self.cgroups
    }

    pub fn proc(&self, pid: u32) -> Option<&LocalProc> {
        self.procs.get(&pid)
    }

    /// Close a local login scope so no new launches (`spawn`) can enter it (`EBUSY`), while
    /// existing processes in the scope (and their shutdown-handler forks) retain their scope.
    pub fn close_login_scope(&mut self, scope: &str) {
        self.closed_scopes.insert(scope.to_string());
    }

    pub fn reopen_login_scope(&mut self, scope: &str) {
        self.closed_scopes.remove(scope);
    }

    pub fn is_login_scope_closed(&self, scope: &str) -> bool {
        self.closed_scopes.contains(scope)
    }

    /// All non-zombie PIDs belonging to `scope`.
    pub fn login_scope_pids(&self, scope: &str) -> Vec<u32> {
        self.procs
            .values()
            .filter(|p| {
                p.pid != 1
                    && p.state != ProcState::Zombie
                    && p.login_scope.as_deref() == Some(scope)
            })
            .map(|p| p.pid)
            .collect()
    }

    /// All non-zombie PIDs (excluding PID 1) in this instance.
    pub fn live_user_pids(&self) -> Vec<u32> {
        self.procs
            .values()
            .filter(|p| p.pid != 1 && p.state != ProcState::Zombie)
            .map(|p| p.pid)
            .collect()
    }

    /// All active remote service tokens currently held by live local processes.
    pub fn active_remote_tokens(&self) -> Vec<String> {
        let mut set = BTreeSet::new();
        for p in self.procs.values() {
            if p.state != ProcState::Zombie
                && let Some(rem) = &p.cred.remote
            {
                set.insert(rem.token.clone());
            }
        }
        set.into_iter().collect()
    }

    /// Clear a revoked remote token from any local process still referencing it (e.g. after
    /// server reported it revoked due to account lock/delete/password-change).
    pub fn drop_revoked_remote_token(&mut self, token: &str) {
        for p in self.procs.values_mut() {
            if p.cred.remote.as_ref().is_some_and(|r| r.token == token) {
                p.cred.remote = None;
                p.cred.cloud_access = false;
            }
        }
    }

    fn alloc_pid(&mut self) -> Result<u32, Error> {
        if self.procs.len() >= PROC_MAX {
            return Err(Errno::EAGAIN.into());
        }
        let start = self.next_pid.clamp(2, PID_MAX);
        let mut candidate = start;
        loop {
            if !self.procs.contains_key(&candidate) {
                self.next_pid = if candidate >= PID_MAX {
                    2
                } else {
                    candidate + 1
                };
                return Ok(candidate);
            }
            candidate = if candidate >= PID_MAX {
                2
            } else {
                candidate + 1
            };
            if candidate == start {
                return Err(Errno::EAGAIN.into());
            }
        }
    }

    fn subtree_proc_count(&self, root: &str) -> usize {
        self.procs
            .values()
            .filter(|p| in_subtree(&p.cgroup, root))
            .count()
    }

    fn subtree_memory_bytes(&self, root: &str) -> u64 {
        self.procs
            .values()
            .filter(|p| p.state != ProcState::Zombie && in_subtree(&p.cgroup, root))
            .fold(0u64, |acc, p| acc.saturating_add(p.memory_bytes))
    }

    fn token_has_live_holder(&self, token: &str) -> bool {
        self.procs.values().any(|p| {
            p.state != ProcState::Zombie && p.cred.remote.as_ref().is_some_and(|r| r.token == token)
        })
    }

    fn queue_signal(&mut self, pid: u32, signal: u8) -> Option<SignalDelivery> {
        let proc = self.procs.get_mut(&pid)?;
        if proc.state == ProcState::Zombie {
            return None;
        }
        let owner_host = proc.owner_host.clone();
        if let Some(existing) = proc.pending_signals.iter().find(|s| s.signal == signal) {
            return Some(SignalDelivery {
                pid,
                owner_host,
                signal,
                sequence: existing.sequence,
                killed: false,
            });
        }
        self.next_signal_seq = self.next_signal_seq.saturating_add(1);
        let seq = self.next_signal_seq;
        proc.pending_signals.push(PendingSignal {
            sequence: seq,
            signal,
        });
        Some(SignalDelivery {
            pid,
            owner_host,
            signal,
            sequence: seq,
            killed: false,
        })
    }

    fn verify_owner(&self, caller_host: &str, pid: u32) -> Result<&LocalProc, Error> {
        let proc = self.procs.get(&pid).ok_or(Errno::ESRCH)?;
        if proc.owner_host != caller_host {
            return Err(Errno::ESRCH.into());
        }
        Ok(proc)
    }

    /// Start PID 1 (init) locally with zero remote RPCs.
    pub fn boot_init(&mut self, host: &str, now: u64) -> Result<&LocalProc, Error> {
        if host.is_empty() {
            return Err(Errno::EINVAL.into());
        }
        if let Some(existing) = self.procs.get_mut(&1) {
            existing.owner_host = host.to_string();
            existing.state = ProcState::Running;
            return Ok(self.procs.get(&1).unwrap());
        }
        let init = LocalProc {
            pid: 1,
            ppid: 0,
            pgid: 1,
            sid: 1,
            state: ProcState::Running,
            cred: LocalCred::local_only(Identity::root(), 0o022),
            path: "/usr/bin/init".into(),
            argv: vec!["init".into()],
            env: Vec::new(),
            cwd: "/".into(),
            cgroup: "/init".into(),
            ctty: None,
            tty_fds: Vec::new(),
            owner_host: host.to_string(),
            login_scope: None,
            subreaper: true,
            execed: true,
            loading: false,
            memory_bytes: 0,
            runtime_tracked: true,
            exit_status: None,
            exit_signal: None,
            wait_event: None,
            pending_signals: Vec::new(),
            started: now,
            ended: 0,
        };
        self.procs.insert(1, init);
        Ok(self.procs.get(&1).unwrap())
    }

    /// Admit & spawn a new top-level process locally (zero network calls).
    pub fn spawn(&mut self, spec: SpawnSpec, now: u64) -> Result<LocalProc, Error> {
        if spec.owner_host.is_empty() {
            return Err(Errno::EINVAL.into());
        }
        validate_exec_vectors(&spec.path, &spec.argv, &spec.env)?;
        if let Some(scope) = &spec.login_scope
            && self.closed_scopes.contains(scope)
        {
            return Err(Error::because(
                Errno::EBUSY,
                "login session is shutting down",
            ));
        }
        let target_cg = match &spec.cgroup {
            Some(raw) => {
                self.cgroups
                    .authorize_attach(&spec.cred.identity, spec.cred.identity.id, raw)?
            }
            None => "/user".to_string(),
        };
        let runtime_tracked = runtime_enforces_memory(spec.runtime.as_deref());
        // Count loading + running + stopped + zombies against `pids.max` BEFORE admitting guest code.
        self.cgroups
            .check_pids_admit(None, &target_cg, 1, |root| self.subtree_proc_count(root))?;
        self.cgroups
            .check_memory_admit(None, &target_cg, 0, runtime_tracked, |root| {
                self.subtree_memory_bytes(root)
            })?;
        let pid = self.alloc_pid()?;
        let ppid = spec.ppid.unwrap_or(1);
        let pgid = spec.pgid.unwrap_or(pid);
        let sid = spec.sid.unwrap_or(pid);
        let proc = LocalProc {
            pid,
            ppid,
            pgid,
            sid,
            state: spec.initial_state,
            cred: spec.cred,
            path: spec.path,
            argv: spec.argv,
            env: spec.env,
            cwd: if spec.cwd.is_empty() {
                "/".into()
            } else {
                spec.cwd
            },
            cgroup: target_cg,
            ctty: None,
            tty_fds: Vec::new(),
            owner_host: spec.owner_host,
            login_scope: spec.login_scope,
            subreaper: false,
            execed: true,
            loading: false,
            memory_bytes: 0,
            runtime_tracked,
            exit_status: None,
            exit_signal: None,
            wait_event: None,
            pending_signals: Vec::new(),
            started: now,
            ended: 0,
        };
        self.procs.insert(pid, proc.clone());
        Ok(proc)
    }

    /// Transition a loading process to running.
    pub fn mark_running(&mut self, caller_host: &str, pid: u32) -> Result<(), Error> {
        let proc = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        if proc.owner_host != caller_host {
            return Err(Errno::ESRCH.into());
        }
        proc.loading = false;
        if proc.state == ProcState::Sleeping {
            proc.state = ProcState::Running;
        }
        Ok(())
    }

    /// Replace image of `pid` (must be owned by `caller_host`; preserves `pid`/`ppid`/`pgid`/`sid`/
    /// `cgroup`/`login_scope`, sets `execed = true`, attenuates `cloud_access` monotonically).
    pub fn reexec(
        &mut self,
        caller_host: &str,
        pid: u32,
        spec: ReexecSpec,
        _now: u64,
    ) -> Result<LocalProc, Error> {
        validate_exec_vectors(&spec.path, &spec.argv, &spec.env)?;
        let (cg, prev_mem, runtime_tracked) = {
            let proc = self.verify_owner(caller_host, pid)?;
            if proc.state == ProcState::Zombie {
                return Err(Errno::ESRCH.into());
            }
            let rt = spec
                .runtime
                .as_deref()
                .map_or(proc.runtime_tracked, |r| runtime_enforces_memory(Some(r)));
            (proc.cgroup.clone(), proc.memory_bytes, rt)
        };
        if !runtime_tracked && self.cgroups.has_memory_limit(&cg) {
            return Err(Error::because(
                Errno::EOPNOTSUPP,
                "memory.max requires resources-v1 runtime enforcement",
            ));
        }
        let _ = prev_mem;
        let proc = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        proc.path = spec.path;
        proc.argv = spec.argv;
        proc.env = spec.env;
        if let Some(cwd) = spec.cwd
            && !cwd.is_empty()
        {
            proc.cwd = cwd;
        }
        // Monotonic cloud_access attenuation: reexec can NEVER escalate `false -> true`, and
        // attenuating to `false` without an explicit replacement clears any ambient remote cred.
        let next_cloud = proc.cred.cloud_access && spec.cloud_access;
        proc.cred.cloud_access = next_cloud;
        if let Some(mut new_remote) = spec.new_remote {
            new_remote.cloud_access &= next_cloud;
            proc.cred.remote = Some(new_remote);
        } else if !next_cloud {
            proc.cred.remote = None;
        } else if let Some(rem) = &mut proc.cred.remote {
            rem.cloud_access &= next_cloud;
        }
        proc.execed = true;
        proc.loading = false;
        proc.runtime_tracked = runtime_tracked;
        proc.memory_bytes = 0;
        if proc.state == ProcState::Sleeping {
            proc.state = ProcState::Running;
        }
        Ok(proc.clone())
    }

    /// Local fork (ZERO network calls): checks `PROC_MAX`, hierarchical `pids.max`, `memory.max`;
    /// clones `cred` (inheriting `remote` ref), `pgid`, `sid`, `ctty`, `cgroup`, `login_scope`;
    /// sets `execed = false`; clears child's `pending_signals`.
    pub fn fork(
        &mut self,
        caller_host: &str,
        parent_pid: u32,
        empty_memory: bool,
        now: u64,
    ) -> Result<LocalProc, Error> {
        let parent = self.verify_owner(caller_host, parent_pid)?.clone();
        if parent.state == ProcState::Zombie {
            return Err(Errno::ESRCH.into());
        }
        let child_mem = if empty_memory { 0 } else { parent.memory_bytes };
        self.cgroups
            .check_pids_admit(None, &parent.cgroup, 1, |root| {
                self.subtree_proc_count(root)
            })?;
        self.cgroups.check_memory_admit(
            None,
            &parent.cgroup,
            child_mem,
            parent.runtime_tracked,
            |root| self.subtree_memory_bytes(root),
        )?;
        let child_pid = self.alloc_pid()?;
        let child = LocalProc {
            pid: child_pid,
            ppid: parent.pid,
            pgid: parent.pgid,
            sid: parent.sid,
            state: ProcState::Running,
            cred: parent.cred,
            path: parent.path,
            argv: parent.argv,
            env: parent.env,
            cwd: parent.cwd,
            cgroup: parent.cgroup,
            ctty: parent.ctty,
            tty_fds: parent.tty_fds,
            owner_host: parent.owner_host,
            // Retain original login scope so shutdown cleanup handlers may still fork!
            login_scope: parent.login_scope,
            subreaper: false,
            execed: false,
            loading: empty_memory,
            memory_bytes: child_mem,
            runtime_tracked: parent.runtime_tracked,
            exit_status: None,
            exit_signal: None,
            wait_event: None,
            pending_signals: Vec::new(),
            started: now,
            ended: 0,
        };
        self.procs.insert(child_pid, child.clone());
        Ok(child)
    }

    /// Process exit -> zombie, subreaper/init orphan reparenting, orphaned stopped-group SIGHUP+SIGCONT,
    /// process-lifetime cgroup retirement, and remote-credential last-holder revocation check.
    pub fn exit(
        &mut self,
        caller_host: &str,
        pid: u32,
        status: i32,
        signal: Option<u8>,
        now: u64,
    ) -> Result<ExitOutcome, Error> {
        self.verify_owner(caller_host, pid)?;
        if pid == 1 {
            return Err(Errno::EPERM.into());
        }
        self.terminate_process(pid, status, signal, now)
    }

    /// Internal termination helper used by both `exit` and `SIGKILL` (including process-lifetime
    /// cgroup teardown).
    fn terminate_process(
        &mut self,
        pid: u32,
        status: i32,
        signal: Option<u8>,
        now: u64,
    ) -> Result<ExitOutcome, Error> {
        let mut outcome = ExitOutcome {
            pid,
            ..ExitOutcome::default()
        };
        let mut queue = vec![(pid, status, signal)];
        let mut dropped_tokens: BTreeSet<String> = BTreeSet::new();

        while let Some((cur_pid, cur_status, cur_sig)) = queue.pop() {
            let Some(cur) = self.procs.get_mut(&cur_pid) else {
                continue;
            };
            if cur.state == ProcState::Zombie {
                if cur_pid == pid {
                    outcome.ppid = cur.ppid;
                }
                continue;
            }
            let cur_ppid = cur.ppid;
            let cur_sid = cur.sid;
            if cur_pid == pid {
                outcome.ppid = cur_ppid;
            } else {
                outcome.killed_pids.push(cur_pid);
            }
            if let Some(rem) = &cur.cred.remote {
                dropped_tokens.insert(rem.token.clone());
            }
            cur.state = ProcState::Zombie;
            cur.loading = false;
            cur.memory_bytes = 0;
            cur.pending_signals.clear();
            cur.exit_status = Some(cur_status);
            cur.exit_signal = cur_sig;
            cur.ended = now;
            cur.wait_event = Some(WaitEvent::Exited {
                status: cur_status,
                signal: cur_sig,
            });

            // 1. Reparent any children of `cur_pid` to the nearest living subreaper ancestor, else PID 1.
            let new_parent = self.nearest_reaper(cur_ppid);
            let child_pids: Vec<u32> = self
                .procs
                .values()
                .filter(|p| p.ppid == cur_pid)
                .map(|p| p.pid)
                .collect();
            let mut affected_pgroups = BTreeSet::new();
            let mut reparented_zombie = false;
            for cpid in child_pids {
                if let Some(child) = self.procs.get_mut(&cpid) {
                    child.ppid = new_parent;
                    if child.sid == cur_sid {
                        affected_pgroups.insert((child.sid, child.pgid));
                    }
                    if child.state == ProcState::Zombie {
                        reparented_zombie = true;
                    }
                }
            }
            // Notify new parent if it inherited an already-zombified child.
            if reparented_zombie
                && new_parent != 0
                && let Some(sig) = self.queue_signal(new_parent, SIGCHLD)
            {
                outcome.signals.push(sig);
            }
            // Notify `cur_pid`'s own parent with `SIGCHLD`.
            if cur_ppid != 0
                && let Some(sig) = self.queue_signal(cur_ppid, SIGCHLD)
            {
                outcome.signals.push(sig);
            }

            // 2. Check for orphaned stopped process groups (POSIX §2.2.2.52).
            for (sid, pgid) in affected_pgroups {
                if self.is_orphaned_stopped_pgroup(sid, pgid) {
                    let members: Vec<u32> = self
                        .procs
                        .values()
                        .filter(|p| p.sid == sid && p.pgid == pgid && p.state != ProcState::Zombie)
                        .map(|p| p.pid)
                        .collect();
                    for mpid in members {
                        if let Some(p) = self.procs.get_mut(&mpid) {
                            if p.state == ProcState::Stopped {
                                p.state = ProcState::Running;
                                p.wait_event = Some(WaitEvent::Continued);
                            }
                            p.pending_signals.retain(|s| !is_stop_signal(s.signal));
                        }
                        if let Some(s) = self.queue_signal(mpid, SIGHUP) {
                            outcome.signals.push(s);
                        }
                        if let Some(s) = self.queue_signal(mpid, SIGCONT) {
                            outcome.signals.push(s);
                        }
                    }
                }
            }

            // 3. Retire any `CgroupLifetime::Process` cgroups owned by `cur_pid` & SIGKILL their subtrees.
            let retired_roots = self.cgroups.retire_owned_by(cur_pid);
            if !retired_roots.is_empty() {
                let victims: Vec<(u32, String)> = self
                    .procs
                    .values()
                    .filter(|p| {
                        p.pid != 1
                            && p.pid != cur_pid
                            && p.state != ProcState::Zombie
                            && retired_roots.iter().any(|r| in_subtree(&p.cgroup, r))
                    })
                    .map(|p| (p.pid, p.owner_host.clone()))
                    .collect();
                for (vpid, vhost) in victims {
                    self.next_signal_seq = self.next_signal_seq.saturating_add(1);
                    outcome.signals.push(SignalDelivery {
                        pid: vpid,
                        owner_host: vhost,
                        signal: SIGKILL,
                        sequence: self.next_signal_seq,
                        killed: true,
                    });
                    queue.push((vpid, 0, Some(SIGKILL)));
                }
            }
        }

        // 4. Prune any retired cgroups that are now empty.
        let proc_cgroups: Vec<String> = self.procs.values().map(|p| p.cgroup.clone()).collect();
        self.cgroups
            .prune_retired(|root| proc_cgroups.iter().any(|cg| in_subtree(cg, root)));

        // 5. Compute remote tokens that now have ZERO live local holders.
        for tok in dropped_tokens {
            if !self.token_has_live_holder(&tok) {
                outcome.revoked_tokens.push(tok);
            }
        }

        let _ = now;
        Ok(outcome)
    }

    fn nearest_reaper(&self, mut pid: u32) -> u32 {
        let mut hops = 0usize;
        while pid != 0 && hops < PROC_MAX {
            hops += 1;
            let Some(p) = self.procs.get(&pid) else {
                break;
            };
            if p.state != ProcState::Zombie && (p.subreaper || p.pid == 1) {
                return p.pid;
            }
            pid = p.ppid;
        }
        if self.procs.contains_key(&1) { 1 } else { 0 }
    }

    fn is_orphaned_stopped_pgroup(&self, sid: u32, pgid: u32) -> bool {
        let mut has_stopped = false;
        for p in self.procs.values() {
            if p.sid != sid || p.pgid != pgid || p.state == ProcState::Zombie {
                continue;
            }
            if p.state == ProcState::Stopped {
                has_stopped = true;
            }
            // A process group is NOT orphaned if any member has a parent in a different
            // process group within the same session.
            if let Some(parent) = self.procs.get(&p.ppid)
                && parent.state != ProcState::Zombie
                && parent.sid == sid
                && parent.pgid != pgid
            {
                return false;
            }
        }
        has_stopped
    }

    /// POSIX `waitpid(selector, options)` (`WNOHANG=1`, `WUNTRACED=2`, `WCONTINUED=8`).
    /// Frees the child's PID & cgroup `pids.current` slot on reap.
    pub fn waitpid(
        &mut self,
        caller_host: &str,
        caller_pid: u32,
        selector: i32,
        options: u32,
    ) -> Result<WaitOutcome, Error> {
        if options & !(WNOHANG | WUNTRACED | WCONTINUED) != 0 {
            return Err(Errno::EINVAL.into());
        }
        let caller_pgid = self.verify_owner(caller_host, caller_pid)?.pgid;
        let matching: Vec<u32> = self
            .procs
            .values()
            .filter(|p| {
                p.ppid == caller_pid
                    && match selector {
                        s if s > 0 => p.pid == s as u32,
                        0 => p.pgid == caller_pgid,
                        -1 => true,
                        s => p.pgid == s.unsigned_abs(),
                    }
            })
            .map(|p| p.pid)
            .collect();
        if matching.is_empty() {
            return Err(Errno::ECHILD.into());
        }
        for cpid in &matching {
            if let Some(child) = self.procs.get(cpid)
                && child.state == ProcState::Zombie
            {
                let reaped = self.procs.remove(cpid).unwrap();
                let proc_cgroups: Vec<String> =
                    self.procs.values().map(|p| p.cgroup.clone()).collect();
                self.cgroups
                    .prune_retired(|root| proc_cgroups.iter().any(|cg| in_subtree(cg, root)));
                return Ok(WaitOutcome::Reaped(Box::new(reaped.to_abi_proc())));
            }
        }
        for cpid in &matching {
            if let Some(child) = self.procs.get_mut(cpid) {
                if (options & WUNTRACED) != 0
                    && let Some(WaitEvent::Stopped { signal }) = child.wait_event
                {
                    child.wait_event = None;
                    return Ok(WaitOutcome::Event {
                        pid: *cpid,
                        status: ((signal as i32) << 8) | 0x7f,
                    });
                }
                if (options & WCONTINUED) != 0
                    && matches!(child.wait_event, Some(WaitEvent::Continued))
                {
                    child.wait_event = None;
                    return Ok(WaitOutcome::Event {
                        pid: *cpid,
                        status: 0xffff,
                    });
                }
            }
        }
        Ok(WaitOutcome::Pending)
    }

    /// Host reap for direct PID 1 children (`EPERM` if non-owner, `ECHILD` if `ppid != 1`).
    pub fn reap_init_child(
        &mut self,
        caller_host: &str,
        caller_cred: &Identity,
        pid: u32,
    ) -> Result<Proc, Error> {
        let target = self.procs.get(&pid).ok_or(Errno::ECHILD)?;
        if target.ppid != 1 {
            return Err(Errno::ECHILD.into());
        }
        if target.owner_host != caller_host
            && !may_manage_process(caller_cred, target.cred.identity.id)
        {
            return Err(Errno::EPERM.into());
        }
        if target.state != ProcState::Zombie {
            return Err(Errno::EAGAIN.into());
        }
        let reaped = self.procs.remove(&pid).unwrap();
        let proc_cgroups: Vec<String> = self.procs.values().map(|p| p.cgroup.clone()).collect();
        self.cgroups
            .prune_retired(|root| proc_cgroups.iter().any(|cg| in_subtree(cg, root)));
        Ok(reaped.to_abi_proc())
    }

    /// Signal delivery (`signal` in `0..=31`, `EINVAL` > 31; `EPERM` unless `may_manage_process`
    /// or `SIGCONT` in same session; `SIGKILL` ends immediately; `SIGSTOP`/`SIGTSTP`/`SIGCONT`
    /// update `state` and `wait_event`; standard signals coalesce with monotonic `sequence`).
    ///
    /// Also returns any remote tokens revoked as a result of `SIGKILL` via `kill_with_revocations`.
    pub fn kill(
        &mut self,
        caller_cred: &Identity,
        caller_pid: Option<u32>,
        target: Target<'_>,
        signal: u8,
        now: u64,
    ) -> Result<Vec<SignalDelivery>, Error> {
        let (deliveries, _) =
            self.kill_with_revocations(caller_cred, caller_pid, target, signal, now)?;
        Ok(deliveries)
    }

    /// Same as `kill`, additionally returning any remote tokens whose last live local holder
    /// was immediately terminated by `SIGKILL`.
    pub fn kill_with_revocations(
        &mut self,
        caller_cred: &Identity,
        caller_pid: Option<u32>,
        target: Target<'_>,
        signal: u8,
        now: u64,
    ) -> Result<(Vec<SignalDelivery>, Vec<String>), Error> {
        if signal > 31 {
            return Err(Errno::EINVAL.into());
        }
        let caller_sid = caller_pid.and_then(|p| self.procs.get(&p).map(|pr| pr.sid));
        let candidates: Vec<u32> = match target {
            Target::Job(_) => return Err(Errno::EINVAL.into()),
            Target::Pid(0) => {
                let cpid = caller_pid.ok_or(Errno::ESRCH)?;
                let pgid = self.procs.get(&cpid).ok_or(Errno::ESRCH)?.pgid;
                self.procs
                    .values()
                    .filter(|p| p.pgid == pgid && p.state != ProcState::Zombie)
                    .map(|p| p.pid)
                    .collect()
            }
            Target::Pid(pid) => {
                if !self.procs.contains_key(&pid) {
                    return Err(Errno::ESRCH.into());
                }
                vec![pid]
            }
            Target::Group(pgid) => {
                let list: Vec<u32> = self
                    .procs
                    .values()
                    .filter(|p| p.pgid == pgid && p.state != ProcState::Zombie)
                    .map(|p| p.pid)
                    .collect();
                if list.is_empty() {
                    return Err(Errno::ESRCH.into());
                }
                list
            }
            Target::All => {
                let list: Vec<u32> = self
                    .procs
                    .values()
                    .filter(|p| {
                        p.pid != 1 && Some(p.pid) != caller_pid && p.state != ProcState::Zombie
                    })
                    .map(|p| p.pid)
                    .collect();
                if list.is_empty() {
                    return Err(Errno::ESRCH.into());
                }
                list
            }
        };

        let mut permitted = Vec::new();
        for pid in &candidates {
            let Some(p) = self.procs.get(pid) else {
                continue;
            };
            if p.pid == 1 && (signal == SIGKILL || signal == SIGSTOP) {
                if matches!(target, Target::Pid(1)) {
                    return Err(Errno::EPERM.into());
                }
                continue;
            }
            let allowed = may_manage_process(caller_cred, p.cred.identity.id)
                || (signal == SIGCONT && caller_sid == Some(p.sid));
            if allowed {
                permitted.push(*pid);
            }
        }
        if permitted.is_empty() {
            return Err(Errno::EPERM.into());
        }
        if signal == 0 {
            return Ok((Vec::new(), Vec::new()));
        }

        let mut deliveries = Vec::new();
        let mut revoked_tokens = Vec::new();
        for pid in permitted {
            let Some(p) = self.procs.get(&pid) else {
                continue;
            };
            if p.state == ProcState::Zombie {
                continue;
            }
            if signal == SIGKILL {
                let host = p.owner_host.clone();
                self.next_signal_seq = self.next_signal_seq.saturating_add(1);
                deliveries.push(SignalDelivery {
                    pid,
                    owner_host: host,
                    signal: SIGKILL,
                    sequence: self.next_signal_seq,
                    killed: true,
                });
                let out = self.terminate_process(pid, 0, Some(SIGKILL), now)?;
                deliveries.extend(out.signals);
                revoked_tokens.extend(out.revoked_tokens);
                continue;
            }
            if signal == SIGSTOP {
                let ppid = p.ppid;
                if let Some(p_mut) = self.procs.get_mut(&pid) {
                    p_mut.pending_signals.retain(|s| s.signal != SIGCONT);
                    if p_mut.state != ProcState::Stopped {
                        p_mut.state = ProcState::Stopped;
                        p_mut.wait_event = Some(WaitEvent::Stopped { signal: SIGSTOP });
                    }
                }
                if let Some(d) = self.queue_signal(pid, SIGSTOP) {
                    deliveries.push(d);
                }
                if ppid != 0
                    && let Some(d) = self.queue_signal(ppid, SIGCHLD)
                {
                    deliveries.push(d);
                }
                continue;
            }
            if signal == SIGCONT {
                let ppid = p.ppid;
                let was_stopped = p.state == ProcState::Stopped;
                if let Some(p_mut) = self.procs.get_mut(&pid) {
                    p_mut.pending_signals.retain(|s| !is_stop_signal(s.signal));
                    if was_stopped {
                        p_mut.state = ProcState::Running;
                        p_mut.wait_event = Some(WaitEvent::Continued);
                    }
                }
                if let Some(d) = self.queue_signal(pid, SIGCONT) {
                    deliveries.push(d);
                }
                if was_stopped
                    && ppid != 0
                    && let Some(d) = self.queue_signal(ppid, SIGCHLD)
                {
                    deliveries.push(d);
                }
                continue;
            }
            if is_stop_signal(signal)
                && let Some(p_mut) = self.procs.get_mut(&pid)
            {
                p_mut.pending_signals.retain(|s| s.signal != SIGCONT);
            }
            if let Some(d) = self.queue_signal(pid, signal) {
                deliveries.push(d);
            }
        }
        Ok((deliveries, revoked_tokens))
    }

    /// Acknowledge delivered signals (`owner_host` verified; stale sequences never clear newer ones).
    pub fn ack_signals(
        &mut self,
        caller_host: &str,
        pid: u32,
        sequences: &[u64],
    ) -> Result<Vec<PendingSignal>, Error> {
        let proc = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        if proc.owner_host != caller_host {
            return Err(Errno::ESRCH.into());
        }
        if !sequences.is_empty() {
            proc.pending_signals
                .retain(|s| !sequences.contains(&s.sequence));
        }
        Ok(proc.pending_signals.clone())
    }

    pub fn report_stopped(&mut self, caller_host: &str, pid: u32, signal: u8) -> Result<(), Error> {
        if !is_stop_signal(signal) {
            return Err(Errno::EINVAL.into());
        }
        let ppid = {
            let proc = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
            if proc.owner_host != caller_host {
                return Err(Errno::ESRCH.into());
            }
            if proc.state == ProcState::Zombie {
                return Err(Errno::ESRCH.into());
            }
            proc.state = ProcState::Stopped;
            proc.wait_event = Some(WaitEvent::Stopped { signal });
            proc.ppid
        };
        if ppid != 0 {
            let _ = self.queue_signal(ppid, SIGCHLD);
        }
        Ok(())
    }

    pub fn getpgid(
        &self,
        caller_host: &str,
        caller_pid: u32,
        target_pid: i32,
    ) -> Result<u32, Error> {
        let caller = self.verify_owner(caller_host, caller_pid)?;
        if target_pid < 0 {
            return Err(Errno::EINVAL.into());
        }
        if target_pid == 0 {
            return Ok(caller.pgid);
        }
        let target = self.procs.get(&(target_pid as u32)).ok_or(Errno::ESRCH)?;
        if caller.cred.identity.id != 0 && target.sid != caller.sid {
            return Err(Errno::EPERM.into());
        }
        Ok(target.pgid)
    }

    pub fn getsid(
        &self,
        caller_host: &str,
        caller_pid: u32,
        target_pid: i32,
    ) -> Result<u32, Error> {
        let caller = self.verify_owner(caller_host, caller_pid)?;
        if target_pid < 0 {
            return Err(Errno::EINVAL.into());
        }
        if target_pid == 0 {
            return Ok(caller.sid);
        }
        let target = self.procs.get(&(target_pid as u32)).ok_or(Errno::ESRCH)?;
        if caller.cred.identity.id != 0 && target.sid != caller.sid {
            return Err(Errno::EPERM.into());
        }
        Ok(target.sid)
    }

    pub fn setpgid(
        &mut self,
        caller_host: &str,
        caller_pid: u32,
        pid: i32,
        pgid: i32,
    ) -> Result<(), Error> {
        if pid < 0 || pgid < 0 {
            return Err(Errno::EINVAL.into());
        }
        let caller = self.verify_owner(caller_host, caller_pid)?.clone();
        let target_pid = if pid == 0 { caller_pid } else { pid as u32 };
        let new_pgid = if pgid == 0 { target_pid } else { pgid as u32 };
        let target = self.procs.get(&target_pid).ok_or(Errno::ESRCH)?.clone();
        if target.state == ProcState::Zombie {
            return Err(Errno::ESRCH.into());
        }
        if target_pid != caller_pid {
            if target.ppid != caller_pid {
                return Err(Errno::ESRCH.into());
            }
            if target.sid != caller.sid {
                return Err(Errno::EPERM.into());
            }
            if target.execed {
                return Err(Errno::EACCES.into());
            }
        }
        // A session leader cannot change its process group.
        if target.pid == target.sid {
            return Err(Errno::EPERM.into());
        }
        // Target pgid must either be `target_pid` itself or an existing group in the same session.
        if new_pgid != target_pid {
            let group_exists = self
                .procs
                .values()
                .any(|p| p.state != ProcState::Zombie && p.pgid == new_pgid && p.sid == caller.sid);
            if !group_exists {
                return Err(Errno::EPERM.into());
            }
        }
        self.procs.get_mut(&target_pid).unwrap().pgid = new_pgid;
        Ok(())
    }

    pub fn setsid(&mut self, caller_host: &str, caller_pid: u32) -> Result<u32, Error> {
        let caller = self.verify_owner(caller_host, caller_pid)?.clone();
        if caller.state == ProcState::Zombie {
            return Err(Errno::ESRCH.into());
        }
        // Fail with EPERM if any process already has pgid == caller_pid.
        let is_group_leader = self
            .procs
            .values()
            .any(|p| p.state != ProcState::Zombie && p.pgid == caller_pid);
        if is_group_leader {
            return Err(Errno::EPERM.into());
        }
        let proc = self.procs.get_mut(&caller_pid).unwrap();
        proc.sid = caller_pid;
        proc.pgid = caller_pid;
        proc.ctty = None;
        Ok(caller_pid)
    }

    /// Bootstrap a fresh pipeline's shared session & process group (`leader = pids[0]`).
    pub fn bootstrap_session(&mut self, caller_host: &str, pids: &[u32]) -> Result<u32, Error> {
        if pids.is_empty() {
            return Err(Errno::EINVAL.into());
        }
        let leader = pids[0];
        let mut seen = BTreeSet::new();
        let mut expected_uid = None;
        for &pid in pids {
            if !seen.insert(pid) {
                return Err(Errno::EINVAL.into());
            }
            let p = self.verify_owner(caller_host, pid)?;
            if p.ppid != 1 || p.state == ProcState::Zombie {
                return Err(Errno::EPERM.into());
            }
            match expected_uid {
                None => expected_uid = Some(p.cred.identity.id),
                Some(uid) if uid != p.cred.identity.id => return Err(Errno::EPERM.into()),
                _ => {}
            }
        }
        for &pid in pids {
            if let Some(p) = self.procs.get_mut(&pid) {
                p.sid = leader;
                p.pgid = leader;
            }
        }
        Ok(leader)
    }

    pub fn set_tty(
        &mut self,
        caller_host: &str,
        pid: u32,
        tty: u32,
        fds: Vec<u32>,
    ) -> Result<(), Error> {
        let proc = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        if proc.owner_host != caller_host {
            return Err(Errno::ESRCH.into());
        }
        if proc.state == ProcState::Zombie {
            return Err(Errno::ESRCH.into());
        }
        proc.ctty = Some(tty);
        proc.tty_fds = fds;
        Ok(())
    }

    pub fn prctl(
        &mut self,
        caller_host: &str,
        pid: u32,
        option: u32,
        value: u32,
    ) -> Result<u32, Error> {
        let proc = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        if proc.owner_host != caller_host {
            return Err(Errno::ESRCH.into());
        }
        match option {
            PR_SET_CHILD_SUBREAPER => {
                proc.subreaper = value != 0;
                Ok(u32::from(proc.subreaper))
            }
            PR_GET_CHILD_SUBREAPER => Ok(u32::from(proc.subreaper)),
            _ => Err(Errno::EINVAL.into()),
        }
    }

    /// Local credential update (Contract §2.4): privilege drop clears ambient `remote` unless
    /// `explicit_remote` is passed. Returns any remote token whose last live local holder just
    /// dropped it so the host revokes it immediately via `ServiceAuth v2`.
    pub fn set_cred(
        &mut self,
        caller_host: &str,
        pid: u32,
        identity: Identity,
        explicit_remote: Option<RemoteCredRef>,
    ) -> Result<Vec<String>, Error> {
        let dropped_token = {
            let proc = self.procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
            if proc.owner_host != caller_host {
                return Err(Errno::ESRCH.into());
            }
            if proc.state == ProcState::Zombie {
                return Err(Errno::ESRCH.into());
            }
            let prev_uid = proc.cred.identity.id;
            let prev_gid = proc.cred.identity.group;
            let prev_groups = proc.cred.identity.groups.clone();
            let old_token = proc.cred.remote.as_ref().map(|r| r.token.clone());
            let identity_changed = identity.id != prev_uid
                || identity.group != prev_gid
                || identity.groups != prev_groups;

            proc.cred.identity = identity;
            match explicit_remote {
                Some(rem) => {
                    proc.cred.cloud_access = rem.cloud_access;
                    proc.cred.remote = Some(rem);
                }
                None if identity_changed => {
                    // Contract §2.4: privilege drop MUST clear ambient remote credential.
                    proc.cred.remote = None;
                    proc.cred.cloud_access = false;
                }
                None => {}
            }
            old_token.filter(|old| {
                proc.cred.remote.as_ref().map(|r| r.token.as_str()) != Some(old.as_str())
            })
        };

        let mut revoked = Vec::new();
        if let Some(tok) = dropped_token
            && !self.token_has_live_holder(&tok)
        {
            revoked.push(tok);
        }
        Ok(revoked)
    }

    /// Local `memory.max` linear-memory reservation (`resources-v1`, 64 KiB aligned).
    pub fn reserve_memory(&mut self, caller_host: &str, pid: u32, bytes: u64) -> Result<(), Error> {
        let aligned = align_memory(bytes)?;
        let (cg, current_mem, runtime_tracked) = {
            let proc = self.verify_owner(caller_host, pid)?;
            if proc.state == ProcState::Zombie {
                return Err(Errno::ESRCH.into());
            }
            (proc.cgroup.clone(), proc.memory_bytes, proc.runtime_tracked)
        };
        if aligned > current_mem {
            let delta = aligned - current_mem;
            self.cgroups
                .check_memory_admit(None, &cg, delta, runtime_tracked, |root| {
                    self.subtree_memory_bytes(root)
                })?;
        }
        self.procs.get_mut(&pid).unwrap().memory_bytes = aligned;
        Ok(())
    }

    // Local cgroup v2 policy (`pids.max`, `memory.max`, `io.max`, `devices.*`, `cgroup.kill`).
    pub fn cgroup_create(
        &mut self,
        cred: &Identity,
        owner_pid: Option<u32>,
        path: &str,
        controllers: Option<&str>,
        lifetime: Option<CgroupLifetime>,
    ) -> Result<(), Error> {
        self.cgroups
            .create(cred, owner_pid, path, controllers, lifetime)
    }

    pub fn cgroup_remove(&mut self, cred: &Identity, path: &str) -> Result<(), Error> {
        let proc_cgroups: Vec<String> = self.procs.values().map(|p| p.cgroup.clone()).collect();
        self.cgroups.remove(cred, path, |root| {
            proc_cgroups.iter().any(|cg| in_subtree(cg, root))
        })
    }

    pub fn cgroup_set(
        &mut self,
        cred: &Identity,
        path: &str,
        key: &str,
        value: &str,
        now: u64,
    ) -> Result<Vec<SignalDelivery>, Error> {
        let (deliveries, _) = self.cgroup_set_with_revocations(cred, path, key, value, now)?;
        Ok(deliveries)
    }

    /// Same as `cgroup_set`, also returning revoked remote tokens if `cgroup.kill` terminated
    /// the last holder of a remote credential.
    pub fn cgroup_set_with_revocations(
        &mut self,
        cred: &Identity,
        path: &str,
        key: &str,
        value: &str,
        now: u64,
    ) -> Result<(Vec<SignalDelivery>, Vec<String>), Error> {
        let effect = self.cgroups.set(cred, path, key, value)?;
        let mut deliveries = Vec::new();
        let mut revoked = Vec::new();
        if let CgroupSetEffect::KillSubtree(root) = effect {
            let victims: Vec<u32> = self
                .procs
                .values()
                .filter(|p| {
                    p.pid != 1 && p.state != ProcState::Zombie && in_subtree(&p.cgroup, &root)
                })
                .map(|p| p.pid)
                .collect();
            for vpid in victims {
                if let Some(p) = self.procs.get(&vpid) {
                    if p.state == ProcState::Zombie {
                        continue;
                    }
                    let host = p.owner_host.clone();
                    self.next_signal_seq = self.next_signal_seq.saturating_add(1);
                    deliveries.push(SignalDelivery {
                        pid: vpid,
                        owner_host: host,
                        signal: SIGKILL,
                        sequence: self.next_signal_seq,
                        killed: true,
                    });
                    let out = self.terminate_process(vpid, 0, Some(SIGKILL), now)?;
                    deliveries.extend(out.signals);
                    revoked.extend(out.revoked_tokens);
                }
            }
        }
        Ok((deliveries, revoked))
    }

    pub fn cgroup_attach(&mut self, cred: &Identity, pid: u32, path: &str) -> Result<(), Error> {
        if pid == 1 {
            return Err(Errno::EPERM.into());
        }
        let target_proc = self.procs.get(&pid).ok_or(Errno::ESRCH)?.clone();
        if target_proc.state == ProcState::Zombie {
            return Err(Errno::ESRCH.into());
        }
        let dest = self
            .cgroups
            .authorize_attach(cred, target_proc.cred.identity.id, path)?;
        if dest == target_proc.cgroup {
            return Ok(());
        }
        // Atomic hierarchical `pids.max` and `memory.max` admission on migration.
        self.cgroups
            .check_pids_admit(Some(&target_proc.cgroup), &dest, 1, |root| {
                self.subtree_proc_count(root)
            })?;
        self.cgroups.check_memory_admit(
            Some(&target_proc.cgroup),
            &dest,
            target_proc.memory_bytes,
            target_proc.runtime_tracked,
            |root| self.subtree_memory_bytes(root),
        )?;
        self.procs.get_mut(&pid).unwrap().cgroup = dest;
        let proc_cgroups: Vec<String> = self.procs.values().map(|p| p.cgroup.clone()).collect();
        self.cgroups
            .prune_retired(|root| proc_cgroups.iter().any(|cg| in_subtree(cg, root)));
        Ok(())
    }

    pub fn cgroup_stat(&self, path: &str) -> Result<Value, Error> {
        let norm = normalize_cgroup_path(path)?;
        let direct: Vec<u32> = self
            .procs
            .values()
            .filter(|p| p.cgroup == norm)
            .map(|p| p.pid)
            .collect();
        let subtree: Vec<u32> = self
            .procs
            .values()
            .filter(|p| in_subtree(&p.cgroup, &norm))
            .map(|p| p.pid)
            .collect();
        let mem = self.subtree_memory_bytes(&norm);
        let untracked = self
            .procs
            .values()
            .filter(|p| {
                p.state != ProcState::Zombie && !p.runtime_tracked && in_subtree(&p.cgroup, &norm)
            })
            .count();
        self.cgroups.stat(&norm, direct, subtree, mem, untracked)
    }

    pub fn cgroup_list(&self, path: &str) -> Vec<String> {
        self.cgroups.list(path)
    }

    /// `hidepid=invisible`: root sees all; non-root sees own uid + PID 1.
    pub fn poll(&self, cred: &Identity, pids: &[u32]) -> Vec<Proc> {
        let visible = |p: &LocalProc| cred.id == 0 || p.cred.identity.id == cred.id || p.pid == 1;
        if pids.is_empty() {
            self.procs
                .values()
                .filter(|p| visible(p))
                .map(LocalProc::to_abi_proc)
                .collect()
        } else {
            pids.iter()
                .filter_map(|pid| self.procs.get(pid))
                .filter(|p| visible(p))
                .map(LocalProc::to_abi_proc)
                .collect()
        }
    }

    pub fn proc_snapshot(&self, pid: u32) -> Option<ProcSnapshot> {
        self.procs.get(&pid).map(LocalProc::to_snapshot)
    }

    pub fn all_pids(&self) -> Vec<u32> {
        self.procs.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abi::{SIGINT, SIGTERM};

    fn id(uid: u32) -> Identity {
        Identity {
            id: uid,
            group: uid,
            groups: BTreeSet::from([uid]),
        }
    }

    fn remote(token: &str, uid: u32, cloud_access: bool) -> RemoteCredRef {
        RemoteCredRef {
            token: token.into(),
            uid,
            gid: uid,
            groups: vec![uid],
            instance_id: "inst-1".into(),
            lineage: format!("lin-{token}"),
            cloud_access,
            scope: if cloud_access {
                RemoteScope::cloud_only()
            } else {
                RemoteScope::default()
            },
        }
    }

    fn table_with_init() -> LocalProcessTable {
        let mut t = LocalProcessTable::new(
            InstanceIdentity {
                instance: "inst-1".into(),
                host: "browser".into(),
            },
            100,
        );
        t.boot_init("host-a", 100).unwrap();
        t
    }

    #[test]
    fn boot_fork_exit_waitpid_and_subreaper_work_locally() {
        let mut t = table_with_init();
        let parent = t
            .spawn(
                SpawnSpec::new(
                    "/usr/bin/sh",
                    LocalCred::local_only(id(1000), 0o022),
                    "host-a",
                ),
                101,
            )
            .unwrap();
        assert_eq!(parent.pid, 2);
        assert_eq!(parent.ppid, 1);

        // Set parent as subreaper.
        assert_eq!(
            t.prctl("host-a", parent.pid, PR_SET_CHILD_SUBREAPER, 1)
                .unwrap(),
            1
        );
        let child = t.fork("host-a", parent.pid, false, 102).unwrap();
        let grandchild = t.fork("host-a", child.pid, false, 103).unwrap();
        assert_eq!(grandchild.ppid, child.pid);

        // Child exits -> grandchild reparented to subreaper `parent`.
        t.exit("host-a", child.pid, 0, None, 104).unwrap();
        assert_eq!(t.proc(grandchild.pid).unwrap().ppid, parent.pid);

        // Reap child.
        match t
            .waitpid("host-a", parent.pid, child.pid as i32, 0)
            .unwrap()
        {
            WaitOutcome::Reaped(p) => assert_eq!(p.pid, child.pid),
            other => panic!("expected Reaped, got {other:?}"),
        }
        assert!(t.proc(child.pid).is_none());

        // Grandchild exits -> subreaper receives SIGCHLD and reaps it.
        let out = t.exit("host-a", grandchild.pid, 7, None, 105).unwrap();
        assert!(
            out.signals
                .iter()
                .any(|s| s.pid == parent.pid && s.signal == SIGCHLD)
        );
        match t.waitpid("host-a", parent.pid, -1, WNOHANG).unwrap() {
            WaitOutcome::Reaped(p) => {
                assert_eq!(p.pid, grandchild.pid);
                assert_eq!(p.status, exit_status(7));
            }
            other => panic!("expected Reaped, got {other:?}"),
        }
    }

    #[test]
    fn signals_coalesce_monotonic_sequence_and_enforce_permissions_and_sigkill_revokes() {
        let mut t = table_with_init();
        let ann = id(1000);
        let bob = id(1001);
        let p = t
            .spawn(
                SpawnSpec::new(
                    "/usr/bin/sleep",
                    LocalCred::with_remote(ann.clone(), 0o022, remote("tok-ann", 1000, true)),
                    "host-a",
                ),
                101,
            )
            .unwrap();

        // Invalid signal > 31 -> EINVAL.
        assert_eq!(
            t.kill(&ann, None, Target::Pid(p.pid), 32, 102)
                .unwrap_err()
                .errno,
            Errno::EINVAL
        );
        // Cross-uid kill -> EPERM.
        assert_eq!(
            t.kill(&bob, None, Target::Pid(p.pid), SIGTERM, 102)
                .unwrap_err()
                .errno,
            Errno::EPERM
        );
        // Wrong owner host cannot ack signals -> ESRCH.
        assert_eq!(
            t.ack_signals("host-b", p.pid, &[]).unwrap_err().errno,
            Errno::ESRCH
        );

        // Coalescing & monotonic sequence acks.
        let d1 = t.kill(&ann, None, Target::Pid(p.pid), SIGINT, 102).unwrap();
        let d2 = t.kill(&ann, None, Target::Pid(p.pid), SIGINT, 103).unwrap();
        assert_eq!(d1[0].sequence, d2[0].sequence);
        let rem = t.ack_signals("host-a", p.pid, &[d1[0].sequence]).unwrap();
        assert!(rem.is_empty());
        let d3 = t.kill(&ann, None, Target::Pid(p.pid), SIGINT, 104).unwrap();
        assert!(d3[0].sequence > d1[0].sequence);
        // Stale sequence ack must NOT clear newer delivery!
        let still = t.ack_signals("host-a", p.pid, &[d1[0].sequence]).unwrap();
        assert_eq!(still.len(), 1);
        assert_eq!(still[0].sequence, d3[0].sequence);

        // Fork shares remote token; SIGKILLing one does NOT revoke until last holder dies.
        let child = t.fork("host-a", p.pid, false, 105).unwrap();
        let (_, rev1) = t
            .kill_with_revocations(&ann, None, Target::Pid(child.pid), SIGKILL, 106)
            .unwrap();
        assert!(rev1.is_empty());
        let (_, rev2) = t
            .kill_with_revocations(&ann, None, Target::Pid(p.pid), SIGKILL, 107)
            .unwrap();
        assert_eq!(rev2, vec!["tok-ann".to_string()]);
    }

    #[test]
    fn privilege_drop_clears_ambient_remote_cred_and_revokes_last_holder() {
        let mut t = table_with_init();
        let p = t
            .spawn(
                SpawnSpec::new(
                    "/usr/bin/sh",
                    LocalCred::with_remote(Identity::root(), 0o022, remote("tok-root", 0, true)),
                    "host-a",
                ),
                101,
            )
            .unwrap();
        // Drop from uid 0 -> uid 1000 without explicit remote cred.
        let revoked = t.set_cred("host-a", p.pid, id(1000), None).unwrap();
        assert_eq!(revoked, vec!["tok-root".to_string()]);
        let after = t.proc(p.pid).unwrap();
        assert_eq!(after.cred.identity.id, 1000);
        assert!(after.cred.remote.is_none());
        assert!(!after.cred.cloud_access);

        // Passing explicit lower-identity remote cred binds it cleanly.
        let revoked2 = t
            .set_cred(
                "host-a",
                p.pid,
                id(1000),
                Some(remote("tok-ann", 1000, true)),
            )
            .unwrap();
        assert!(revoked2.is_empty());
        assert_eq!(
            t.proc(p.pid).unwrap().cred.remote.as_ref().unwrap().token,
            "tok-ann"
        );
    }

    #[test]
    fn monotonic_cloud_access_attenuation_on_reexec_and_fork() {
        let mut t = table_with_init();
        let p = t
            .spawn(
                SpawnSpec::new(
                    "/mnt/local/tool",
                    LocalCred::with_remote(id(1000), 0o022, remote("tok-no-cloud", 1000, false)),
                    "host-a",
                ),
                101,
            )
            .unwrap();
        assert!(!p.cred.cloud_access);
        // Reexec requesting cloud_access = true MUST remain false!
        let replaced = t
            .reexec(
                "host-a",
                p.pid,
                ReexecSpec {
                    path: "/usr/bin/cat".into(),
                    argv: vec!["cat".into()],
                    env: vec![],
                    cwd: None,
                    runtime: None,
                    cloud_access: true,
                    new_remote: None,
                },
                102,
            )
            .unwrap();
        assert!(!replaced.cred.cloud_access);
        let child = t.fork("host-a", p.pid, false, 103).unwrap();
        assert!(!child.cred.cloud_access);
    }

    #[test]
    fn pids_max_counts_zombies_and_loading_until_reaped_and_memory_max_enforces() {
        let mut t = table_with_init();
        let ann = id(1000);
        t.cgroup_create(&ann, None, "/user/limited", None, None)
            .unwrap();
        t.cgroup_set(&ann, "/user/limited", "pids.max", "1", 101)
            .unwrap();
        t.cgroup_set(&ann, "/user/limited", "memory.max", "131072", 101)
            .unwrap();

        let mut spec = SpawnSpec::new(
            "/usr/bin/sh",
            LocalCred::local_only(ann.clone(), 0o022),
            "host-a",
        );
        spec.cgroup = Some("/user/limited".into());
        let p1 = t.spawn(spec.clone(), 102).unwrap();

        // Second spawn or fork fails with EAGAIN.
        assert_eq!(t.spawn(spec.clone(), 103).unwrap_err().errno, Errno::EAGAIN);
        assert_eq!(
            t.fork("host-a", p1.pid, true, 103).unwrap_err().errno,
            Errno::EAGAIN
        );

        // Memory reservation up to 128 KiB succeeds, beyond fails EAGAIN.
        t.reserve_memory("host-a", p1.pid, 65_536).unwrap();
        t.reserve_memory("host-a", p1.pid, 131_072).unwrap();
        assert_eq!(
            t.reserve_memory("host-a", p1.pid, 131_073)
                .unwrap_err()
                .errno,
            Errno::EAGAIN
        );

        // Zombie still occupies slot until reaped!
        t.exit("host-a", p1.pid, 0, None, 104).unwrap();
        assert_eq!(t.spawn(spec.clone(), 105).unwrap_err().errno, Errno::EAGAIN);

        // Reaping frees slot immediately.
        t.reap_init_child("host-a", &ann, p1.pid).unwrap();
        let p2 = t.spawn(spec, 106).unwrap();
        assert_ne!(p2.pid, 0);
    }

    #[test]
    fn hidepid_invisible_and_login_scope_shutdown_fencing() {
        let mut t = table_with_init();
        let ann = id(1000);
        let bob = id(1001);
        let mut s_ann = SpawnSpec::new(
            "/usr/bin/sh",
            LocalCred::local_only(ann.clone(), 0o022),
            "host-a",
        );
        s_ann.login_scope = Some("scope-ann".into());
        let p_ann = t.spawn(s_ann.clone(), 101).unwrap();
        let p_bob = t
            .spawn(
                SpawnSpec::new(
                    "/usr/bin/sh",
                    LocalCred::local_only(bob.clone(), 0o022),
                    "host-a",
                ),
                102,
            )
            .unwrap();

        // Ann sees PID 1 + own PID, never Bob's PID.
        let ann_view: Vec<u32> = t.poll(&ann, &[]).into_iter().map(|p| p.pid).collect();
        assert_eq!(ann_view, vec![1, p_ann.pid]);
        // Root sees all.
        let root_view: Vec<u32> = t
            .poll(&Identity::root(), &[])
            .into_iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(root_view, vec![1, p_ann.pid, p_bob.pid]);

        // Closing login scope blocks new spawns (`EBUSY`), while existing process's cleanup fork
        // succeeds and retains original scope.
        t.close_login_scope("scope-ann");
        assert_eq!(t.spawn(s_ann, 103).unwrap_err().errno, Errno::EBUSY);
        let cleanup = t.fork("host-a", p_ann.pid, false, 104).unwrap();
        assert_eq!(cleanup.login_scope.as_deref(), Some("scope-ann"));
    }

    #[test]
    fn process_lifetime_cgroup_kills_subtree_and_orphaned_stopped_group_receives_hup_cont() {
        let mut t = table_with_init();
        let ann = id(1000);
        let sup = t
            .spawn(
                SpawnSpec::new(
                    "/usr/bin/supervise",
                    LocalCred::local_only(ann.clone(), 0o022),
                    "host-a",
                ),
                101,
            )
            .unwrap();
        t.cgroup_create(
            &ann,
            Some(sup.pid),
            "/user/sup-unit",
            None,
            Some(CgroupLifetime::Process),
        )
        .unwrap();
        let worker = t.fork("host-a", sup.pid, false, 102).unwrap();
        t.cgroup_attach(&ann, worker.pid, "/user/sup-unit").unwrap();

        // Supervisor exits -> worker in process-lifetime cgroup is SIGKILLed automatically.
        let out = t.exit("host-a", sup.pid, 0, None, 103).unwrap();
        assert!(out.killed_pids.contains(&worker.pid));
        assert_eq!(t.proc(worker.pid).unwrap().state, ProcState::Zombie);

        // Orphaned stopped process group receives SIGHUP + SIGCONT when parent exits.
        let leader = t
            .spawn(
                SpawnSpec::new(
                    "/usr/bin/sh",
                    LocalCred::local_only(ann.clone(), 0o022),
                    "host-a",
                ),
                110,
            )
            .unwrap();
        let sub = t.fork("host-a", leader.pid, false, 111).unwrap();
        t.setpgid("host-a", leader.pid, sub.pid as i32, sub.pid as i32)
            .unwrap();
        t.kill(&ann, Some(leader.pid), Target::Pid(sub.pid), SIGSTOP, 112)
            .unwrap();
        assert_eq!(t.proc(sub.pid).unwrap().state, ProcState::Stopped);
        let exit_leader = t.exit("host-a", leader.pid, 0, None, 113).unwrap();
        assert!(
            exit_leader
                .signals
                .iter()
                .any(|s| s.pid == sub.pid && s.signal == SIGHUP)
        );
        assert!(
            exit_leader
                .signals
                .iter()
                .any(|s| s.pid == sub.pid && s.signal == SIGCONT)
        );
        assert_eq!(t.proc(sub.pid).unwrap().state, ProcState::Running);
    }

    #[test]
    fn reexec_cloud_false_clears_remote_cred_and_blocks_escalation() {
        let mut t = table_with_init();
        let ann = id(1000);
        let cred = LocalCred::with_remote(ann.clone(), 0o022, remote("tok-parent", 1000, true));
        let p = t
            .spawn(SpawnSpec::new("/usr/bin/sh", cred, "host-a"), 100)
            .unwrap();
        assert_eq!(t.active_remote_tokens(), vec!["tok-parent".to_string()]);

        // Fork a child so parent still holds `tok-parent`; then child reexecs with cloud_access=false.
        let child = t.fork("host-a", p.pid, false, 101).unwrap();
        assert!(child.cred.remote.is_some());
        let attenuated = t
            .reexec(
                "host-a",
                child.pid,
                ReexecSpec {
                    path: "/mnt/local/tool.wasm".into(),
                    argv: vec!["tool".into()],
                    env: Vec::new(),
                    cwd: None,
                    runtime: Some("resources-v1".into()),
                    cloud_access: false,
                    new_remote: None,
                },
                102,
            )
            .unwrap();
        assert!(!attenuated.cred.cloud_access);
        assert!(
            attenuated.cred.remote.is_none(),
            "cloud_access=false reexec must clear inherited remote cred"
        );
        // Subsequent reexec requesting cloud_access=true cannot escalate back.
        let again = t
            .reexec(
                "host-a",
                child.pid,
                ReexecSpec {
                    path: "/usr/bin/true".into(),
                    argv: vec!["true".into()],
                    env: Vec::new(),
                    cwd: None,
                    runtime: Some("resources-v1".into()),
                    cloud_access: true,
                    new_remote: None,
                },
                103,
            )
            .unwrap();
        assert!(!again.cred.cloud_access);
        assert!(again.cred.remote.is_none());

        // Now parent also reexecs with cloud_access=false -> no live holders remain.
        let parent_att = t
            .reexec(
                "host-a",
                p.pid,
                ReexecSpec {
                    path: "/mnt/local/tool.wasm".into(),
                    argv: vec!["tool".into()],
                    env: Vec::new(),
                    cwd: None,
                    runtime: Some("resources-v1".into()),
                    cloud_access: false,
                    new_remote: None,
                },
                104,
            )
            .unwrap();
        assert!(parent_att.cred.remote.is_none());
        assert!(t.active_remote_tokens().is_empty());
    }

    #[test]
    fn stop_signals_discard_pending_sigcont_and_sigcont_discards_pending_stops() {
        let mut t = table_with_init();
        let ann = id(1000);
        let p = t
            .spawn(
                SpawnSpec::new(
                    "/usr/bin/sleep",
                    LocalCred::local_only(ann.clone(), 0o022),
                    "host-a",
                ),
                100,
            )
            .unwrap();

        for stop_sig in [SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU] {
            t.kill(&ann, None, Target::Pid(p.pid), SIGCONT, 101)
                .unwrap();
            assert!(
                t.proc(p.pid)
                    .unwrap()
                    .pending_signals
                    .iter()
                    .any(|s| s.signal == SIGCONT)
            );
            t.kill(&ann, None, Target::Pid(p.pid), stop_sig, 102)
                .unwrap();
            let pending = &t.proc(p.pid).unwrap().pending_signals;
            assert!(
                !pending.iter().any(|s| s.signal == SIGCONT),
                "stop signal {stop_sig} must clear pending SIGCONT"
            );
            assert!(pending.iter().any(|s| s.signal == stop_sig));
            // SIGCONT clears all pending stop signals.
            t.kill(&ann, None, Target::Pid(p.pid), SIGCONT, 103)
                .unwrap();
            let after = &t.proc(p.pid).unwrap().pending_signals;
            assert!(!after.iter().any(|s| is_stop_signal(s.signal)));
            assert!(after.iter().any(|s| s.signal == SIGCONT));
        }
    }
}
