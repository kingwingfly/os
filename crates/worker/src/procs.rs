//! The process registry (owner's plan, 2026-11-01): each browser is a namespace with PID 1,
//! and every process is a row here: who it runs as, its cgroup, its image, its state, and the
//! token its calls carry. The client kernel in the browser owns the wasm state; this registry
//! owns the decisions. Fork, exec, wait and signals are registry operations; a process's exit
//! makes it a zombie until its parent waits for it.
use crate::db::{Db, int, text};
use crate::usr;
use abi::{
    ARG_MAX, ENV_MAX, EXEC_MAX, Error, Exec, Forked, PROC_MAX, Proc, ProcState, SIGCONT, SIGHUP,
    SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSTOP, SIGTERM, SIGTSTP,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use terminal_worker_core::permissions::Identity;
use worker::SqlStorageValue;

/// The namespace's init, the first process of every browser.
pub const INIT: u32 = 1;
/// The cgroups every namespace starts with.
pub const ROOT_CGROUPS: [&str; 4] = ["/init", "/user", "/system", "/cluster"];

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize)]
pub struct Row {
    pub ns: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub groups: String,
    pub umask: u16,
    pub cgroup: String,
    pub path: String,
    pub argv: String,
    pub env: String,
    pub cwd: String,
    pub state: String,
    pub status: i64,
    pub signal: Option<i64>,
    pub started: u64,
    pub ended: u64,
    pub seat: Option<String>,
}
impl Row {
    pub fn proc(&self) -> Proc {
        Proc {
            pid: self.pid,
            ppid: self.ppid,
            state: state_of(&self.state),
            status: self.status as i32,
            signal: self.signal.and_then(|signal| u8::try_from(signal).ok()),
            uid: self.uid,
            gid: self.gid,
            cgroup: self.cgroup.clone(),
            path: self.path.clone(),
            argv: serde_json::from_str(&self.argv).unwrap_or_default(),
            started: self.started,
            ended: self.ended,
            seat: self.seat.clone(),
        }
    }
    pub fn identity(&self) -> Identity {
        Identity {
            id: self.uid,
            group: self.gid,
            groups: serde_json::from_str(&self.groups)
                .unwrap_or_else(|_| BTreeSet::from([self.gid])),
        }
    }
    pub fn zombie(&self) -> bool {
        self.state == "zombie"
    }
}

fn state_of(state: &str) -> ProcState {
    match state {
        "zombie" => ProcState::Zombie,
        "stopped" => ProcState::Stopped,
        "sleeping" => ProcState::Sleeping,
        _ => ProcState::Running,
    }
}

const COLUMNS: &str = "ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, started, ended, seat";

impl Db {
    /// The process `pid` of namespace `ns`.
    pub fn process(&self, ns: &str, pid: u32) -> Option<Row> {
        self.rows::<Row>(
            &format!("SELECT {COLUMNS} FROM processes WHERE ns = ? AND pid = ?"),
            vec![text(ns), int(pid)],
        )
        .into_iter()
        .next()
    }
    /// The live process whose token is `token`, in namespace `ns`, which must be the `pid` it
    /// says. Tokens are stored hashed, so a copy of the store is not a set of capabilities; a
    /// zombie's token is dead with the process.
    pub fn process_token(&self, token: &str, pid: Option<u32>, ns: &str) -> Option<Row> {
        let row = self
            .rows::<Row>(
                &format!(
                    "SELECT {COLUMNS} FROM processes WHERE token = ? AND ns = ? AND state != 'zombie'"
                ),
                vec![text(&crate::auth::token_hash(token)), text(ns)],
            )
            .into_iter()
            .next()?;
        (pid.is_none() || pid == Some(row.pid)).then_some(row)
    }
    /// The namespace a request is of: the browser's guest, or, with no guest cookie, its
    /// signed-in session (or the anonymous namespace of a request with neither).
    pub fn namespace(key: Option<&str>, guest: Option<&str>) -> String {
        guest
            .map(str::to_string)
            .or_else(|| key.map(|key| format!("session.{key}")))
            .unwrap_or_else(|| "anonymous".into())
    }
    /// Begin (or continue) a namespace, as init does: a new boot reaps what the old one left
    /// running, the init process exists, and the root cgroups are there.
    pub fn proc_init(&mut self, ns: &str, boot: Option<&str>, cred: &Identity, now: u64) -> Value {
        let existing = self.namespace_boot(ns);
        if let Some(boot) = boot
            && existing.as_deref() != Some(boot)
        {
            // Nothing of the old boot's processes can be waited for or signalled any more: its
            // pages are gone. The new boot starts with init alone.
            self.run("DELETE FROM processes WHERE ns = ?", vec![text(ns)]);
            self.close_ns_proc_fds(ns);
        }
        self.run(
            "INSERT INTO namespaces(id, guest, boot, next_pid, created, last_seen) VALUES(?, ?, ?, 2, ?, ?) ON CONFLICT(id) DO UPDATE SET boot = excluded.boot, last_seen = excluded.last_seen",
            vec![text(ns), text(ns), boot.map(text).unwrap_or(SqlStorageValue::Null), int(now), int(now)],
        );
        if self.process(ns, INIT).is_none() {
            self.insert_process(
                ns,
                INIT,
                0,
                cred,
                0o022,
                "/init",
                "/init",
                &[INIT.to_string()],
                &[],
                "/",
                now,
            );
        }
        self.ensure_cgroup(ns, "/", now);
        for path in ROOT_CGROUPS {
            self.ensure_cgroup(ns, path, now);
        }
        json!({
            "namespace": ns,
            "pid": INIT,
            "boot": self.namespace_boot(ns),
            "pids": self.processes(ns).iter().map(|row| row.pid).collect::<Vec<_>>(),
        })
    }
    /// A namespace that is there, without a boot's reap: its row, init, and root cgroups.
    fn ensure_namespace(&mut self, ns: &str, cred: &Identity, now: u64) {
        self.run(
            "INSERT INTO namespaces(id, guest, boot, next_pid, created, last_seen) VALUES(?, ?, NULL, 2, ?, ?) ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen",
            vec![text(ns), text(ns), int(now), int(now)],
        );
        if self.process(ns, INIT).is_none() {
            self.insert_process(
                ns,
                INIT,
                0,
                cred,
                0o022,
                "/init",
                "/init",
                &[INIT.to_string()],
                &[],
                "/",
                now,
            );
        }
        self.ensure_cgroup(ns, "/", now);
        for path in ROOT_CGROUPS {
            self.ensure_cgroup(ns, path, now);
        }
    }
    /// A process row with a fresh token, for init or a child before its exec.
    #[allow(clippy::too_many_arguments)]
    fn insert_process(
        &mut self,
        ns: &str,
        pid: u32,
        ppid: u32,
        cred: &Identity,
        umask: u16,
        path: &str,
        cgroup: &str,
        argv: &[String],
        env: &[String],
        cwd: &str,
        now: u64,
    ) {
        self.run(
            "INSERT INTO processes(ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, token, started, ended) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 0, NULL, ?, ?, 0)",
            vec![
                text(ns),
                int(pid),
                int(ppid),
                int(cred.id),
                int(cred.group),
                text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
                int(umask),
                text(cgroup),
                text(path),
                text(&serde_json::to_string(argv).unwrap_or_default()),
                text(&serde_json::to_string(env).unwrap_or_default()),
                text(cwd),
                text(&crate::auth::token_hash(&crate::auth::random_token())),
                int(now),
            ],
        );
    }
    fn namespace_boot(&self, ns: &str) -> Option<String> {
        #[derive(Deserialize)]
        struct Boot {
            boot: Option<String>,
        }
        self.rows::<Boot>("SELECT boot FROM namespaces WHERE id = ?", vec![text(ns)])
            .into_iter()
            .next()
            .and_then(|row| row.boot)
    }
    /// Every process of `ns`, by pid.
    pub fn processes(&self, ns: &str) -> Vec<Row> {
        self.rows::<Row>(
            &format!("SELECT {COLUMNS} FROM processes WHERE ns = ? ORDER BY pid"),
            vec![text(ns)],
        )
    }
    /// Start (or replace) the process `pid` with the image and credentials given, returning the
    /// token its calls carry. `sid` is the browser session the image's descriptor belongs to.
    #[allow(clippy::too_many_arguments)]
    pub fn execve(
        &mut self,
        ns: &str,
        sid: Option<&str>,
        cred: &Identity,
        pid: Option<u32>,
        path: &str,
        argv: &[String],
        env: &[String],
        cwd: &str,
        cgroup: Option<&str>,
        seat: Option<&str>,
        umask: u16,
        now: u64,
    ) -> Result<Exec> {
        if argv.iter().map(|arg| arg.len() + 1).sum::<usize>() > ARG_MAX {
            return Err(Error::because(
                abi::Errno::E2BIG,
                "the argument vector is too long",
            ));
        }
        self.ensure_namespace(ns, cred, now);
        if env.iter().map(|entry| entry.len() + 1).sum::<usize>() > ENV_MAX {
            return Err(Error::because(
                abi::Errno::E2BIG,
                "the environment is too long",
            ));
        }
        let path = if path.starts_with('/') {
            path.to_string()
        } else if cwd == "/" {
            format!("/{path}")
        } else {
            format!("{}/{}", cwd.trim_end_matches('/'), path)
        };
        let executable = kernel::executable(&*self, cred, &path)?;
        if executable.node.size > EXEC_MAX {
            return Err(Error::because(
                abi::Errno::E2BIG,
                format!("{} is larger than an executable may be", executable.path),
            ));
        }
        // The image: a binary of /usr, or any file whose content is one (a FICLONE copy or a
        // hard link of /usr/bin/coreutils), is the build's asset; anything else is uploaded,
        // and the loader reads it by a token of the process's own descriptor, revalidated with
        // the X rule.
        let asset = usr::asset(&executable.content);
        if usr::is(&executable.path) && asset.is_none() {
            return Err(Error::because(
                abi::Errno::ENOEXEC,
                format!("{} is not an executable image", executable.path),
            ));
        }
        let uploaded = asset.is_none();
        let sid = if uploaded {
            Some(sid.ok_or_else(|| {
                Error::because(abi::Errno::EBADF, "no session to keep descriptors")
            })?)
        } else {
            None
        };
        let cgroup = cgroup.unwrap_or("/user");
        if self.cgroup(ns, cgroup).is_none() {
            return Err(Error::because(
                abi::Errno::ENOENT,
                format!("{cgroup} is not a cgroup of this namespace"),
            ));
        }
        // A process replaces itself, or a child just forked; otherwise a child of init starts.
        let pid = match pid {
            Some(pid) => {
                let existing = self.process(ns, pid).ok_or(abi::Errno::ESRCH)?;
                if existing.zombie() {
                    return Err(abi::Errno::ESRCH.into());
                }
                // Only one's own process may be replaced (root's any but init): another
                // account's, or init, is not the caller's to take over.
                if pid == INIT || (cred.id != 0 && existing.uid != cred.id) {
                    return Err(abi::Errno::EPERM.into());
                }
                pid
            }
            None => self.new_pid(ns)?,
        };
        let token = crate::auth::random_token();
        if self.process(ns, pid).is_some() {
            // The image the process ran before is replaced: its descriptor and read token die
            // with the exec, not only when the process ends.
            self.close_proc_fds(ns, pid);
            self.run(
                "UPDATE processes SET uid = ?, gid = ?, groups = ?, umask = ?, cgroup = ?, path = ?, argv = ?, env = ?, cwd = ?, state = 'running', status = 0, signal = NULL, token = ?, started = ?, ended = 0, seat = COALESCE(?, seat) WHERE ns = ? AND pid = ?",
                vec![
                    int(cred.id),
                    int(cred.group),
                    text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
                    int(umask),
                    text(cgroup),
                    text(&executable.path),
                    text(&serde_json::to_string(argv).unwrap_or_default()),
                    text(&serde_json::to_string(env).unwrap_or_default()),
                    text(cwd),
                    text(&crate::auth::token_hash(&token)),
                    int(now),
                    seat.map_or(SqlStorageValue::Null, text),
                    text(ns),
                    int(pid),
                ],
            );
        } else {
            let ppid = INIT;
            self.run(
                "INSERT INTO processes(ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, token, started, ended, seat) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 0, NULL, ?, ?, 0, ?)",
                vec![
                    text(ns),
                    int(pid),
                    int(ppid),
                    int(cred.id),
                    int(cred.group),
                    text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
                    int(umask),
                    text(cgroup),
                    text(&executable.path),
                    text(&serde_json::to_string(argv).unwrap_or_default()),
                    text(&serde_json::to_string(env).unwrap_or_default()),
                    text(cwd),
                    text(&crate::auth::token_hash(&token)),
                    int(now),
                    seat.map_or(SqlStorageValue::Null, text),
                ],
            );
        }
        let (fd, asset, token_read, size) = if uploaded {
            let sid = sid.expect("an uploaded image needs a session");
            let read = crate::auth::random_token();
            let fd = self.add_exec_fd(
                sid,
                &executable.content,
                &executable.path,
                &format!("{ns} {pid}"),
                &crate::auth::token_hash(&read),
                now,
            );
            self.set_expiry("fd", &crate::db::fd_key(sid, fd), now + crate::fds::IDLE);
            (Some(fd), None, Some(read), executable.node.size)
        } else {
            (
                None,
                asset.map(str::to_string),
                None,
                asset.map_or(executable.node.size, usr::size),
            )
        };
        Ok(Exec {
            pid,
            token,
            fd,
            asset,
            path: Some(executable.path.clone()),
            size,
            token_read,
            version: Some(executable.content.clone()),
            cgroup: cgroup.to_string(),
        })
    }
    fn new_pid(&mut self, ns: &str) -> Result<u32> {
        #[derive(Deserialize)]
        struct Alive {
            n: usize,
        }
        let alive = self
            .rows::<Alive>(
                "SELECT COUNT(*) AS n FROM processes WHERE ns = ? AND state != 'zombie'",
                vec![text(ns)],
            )
            .first()
            .map_or(0, |row| row.n);
        if alive >= PROC_MAX {
            return Err(abi::Errno::EAGAIN.into());
        }
        #[derive(Deserialize)]
        struct Next {
            next_pid: u32,
        }
        let mut next = self
            .rows::<Next>(
                "SELECT next_pid FROM namespaces WHERE id = ?",
                vec![text(ns)],
            )
            .into_iter()
            .next()
            .map_or(2, |row| row.next_pid);
        while self.process(ns, next).is_some() {
            if next == u32::MAX {
                return Err(abi::Errno::EAGAIN.into());
            }
            next += 1;
        }
        self.run(
            "UPDATE namespaces SET next_pid = ? WHERE id = ?",
            vec![int(next.saturating_add(1)), text(ns)],
        );
        Ok(next)
    }
    /// fork(2)'s registry half: a child of `parent`, with its credentials, cgroup, image and
    /// environment copied.
    pub fn fork(&mut self, parent: &Row, now: u64) -> Result<Forked> {
        let pid = self.new_pid(&parent.ns)?;
        let token = crate::auth::random_token();
        self.run(
            "INSERT INTO processes(ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, token, started, ended) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 0, NULL, ?, ?, 0)",
            vec![
                text(&parent.ns),
                int(pid),
                int(parent.pid),
                int(parent.uid),
                int(parent.gid),
                text(&parent.groups),
                int(parent.umask),
                text(&parent.cgroup),
                text(&parent.path),
                text(&parent.argv),
                text(&parent.env),
                text(&parent.cwd),
                text(&crate::auth::token_hash(&token)),
                int(now),
            ],
        );
        Ok(Forked { pid, token })
    }
    /// exit(2): the process ends, by `status` or `signal`, and waits as a zombie for its parent.
    pub fn exit(&mut self, row: &Row, status: i32, signal: Option<u8>, now: u64) -> Result<()> {
        if row.zombie() {
            return Err(abi::Errno::ESRCH.into());
        }
        let wait = match signal {
            Some(signal) => abi::signal_status(signal),
            None => abi::exit_status(status),
        };
        self.run(
            "UPDATE processes SET state = 'zombie', status = ?, signal = ?, ended = ? WHERE ns = ? AND pid = ?",
            vec![
                int(wait),
                match signal {
                    Some(signal) => int(signal),
                    None => SqlStorageValue::Null,
                },
                int(now),
                text(&row.ns),
                int(row.pid),
            ],
        );
        self.close_proc_fds(&row.ns, row.pid);
        Ok(())
    }
    /// waitpid(2): the zombie `pid`, now reaped, or EAGAIN while it runs, or ECHILD when it is
    /// no child of `parent` (none: the client kernel, which waits for its namespace).
    pub fn wait(&mut self, ns: &str, parent: Option<u32>, pid: u32) -> Result<Proc> {
        let row = self.process(ns, pid).ok_or(abi::Errno::ECHILD)?;
        if let Some(parent) = parent
            && row.ppid != parent
        {
            return Err(abi::Errno::ECHILD.into());
        }
        if !row.zombie() {
            return Err(abi::Errno::EAGAIN.into());
        }
        self.run(
            "DELETE FROM processes WHERE ns = ? AND pid = ?",
            vec![text(ns), int(pid)],
        );
        self.close_proc_fds(ns, pid);
        Ok(row.proc())
    }
    /// kill(2) in the namespace, by each signal's default action (a process here installs no
    /// handlers): SIGHUP, SIGINT, SIGQUIT, SIGKILL, SIGPIPE and SIGTERM end the process;
    /// SIGSTOP and SIGTSTP stop it; SIGCONT resumes it. A signal from another account needs root.
    pub fn kill(
        &mut self,
        ns: &str,
        cred: &Identity,
        pid: u32,
        signal: u8,
        now: u64,
    ) -> Result<()> {
        let row = self.process(ns, pid).ok_or(abi::Errno::ESRCH)?;
        if cred.id != 0 && cred.id != row.uid {
            return Err(abi::Errno::EPERM.into());
        }
        if row.zombie() {
            return Err(abi::Errno::ESRCH.into());
        }
        match signal {
            SIGHUP | SIGINT | SIGQUIT | SIGKILL | SIGPIPE | SIGTERM => {
                let wait = abi::signal_status(signal);
                self.run(
                    "UPDATE processes SET state = 'zombie', status = ?, signal = ?, ended = ? WHERE ns = ? AND pid = ?",
                    vec![
                        int(wait),
                        int(signal),
                        int(now),
                        text(ns),
                        int(pid),
                    ],
                );
                self.close_proc_fds(ns, pid);
                Ok(())
            }
            SIGSTOP | SIGTSTP => {
                self.run(
                    "UPDATE processes SET state = 'stopped' WHERE ns = ? AND pid = ?",
                    vec![text(ns), int(pid)],
                );
                Ok(())
            }
            SIGCONT => {
                self.run(
                    "UPDATE processes SET state = 'running' WHERE ns = ? AND pid = ? AND state = 'stopped'",
                    vec![text(ns), int(pid)],
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }
    /// What the processes `pids` (all of `ns` if none) are now, as /proc shows them. A process
    /// sees its own account's; the client kernel sees the namespace's.
    pub fn poll(&self, ns: &str, pids: &[u32], cred: &Identity) -> Vec<Proc> {
        let rows = if pids.is_empty() {
            self.processes(ns)
        } else {
            pids.iter()
                .filter_map(|pid| self.process(ns, *pid))
                .collect()
        };
        rows.into_iter()
            .filter(|row| cred.id == 0 || row.uid == cred.id)
            .map(|row| row.proc())
            .collect()
    }

    // ---- cgroups ----

    fn cgroup(&self, ns: &str, path: &str) -> Option<Cgroup> {
        self.rows::<Cgroup>(
            "SELECT ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices FROM cgroups WHERE ns = ? AND path = ?",
            vec![text(ns), text(path)],
        )
        .into_iter()
        .next()
    }
    fn ensure_cgroup(&mut self, ns: &str, path: &str, now: u64) {
        // The root's parent is the empty string, so that it is nobody's child, its own included
        // (a listing of "/" would otherwise name "/" among its children).
        let parent = if path == "/" {
            ""
        } else {
            terminal_worker_core::parent(path)
        };
        if self.cgroup(ns, path).is_none() {
            self.run(
                "INSERT INTO cgroups(ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices) VALUES(?, ?, ?, '', NULL, 100, NULL, NULL, NULL, 0, '')",
                vec![text(ns), text(path), text(parent)],
            );
        }
        let _ = now;
    }
    pub fn cgroup_create(&mut self, ns: &str, path: &str) -> Result<()> {
        let path = cgroup_path(path);
        let parent = terminal_worker_core::parent(&path);
        if self.cgroup(ns, parent).is_none() {
            return Err(abi::Errno::ENOENT.into());
        }
        if self.cgroup(ns, &path).is_some() {
            return Err(abi::Errno::EEXIST.into());
        }
        self.ensure_cgroup(ns, &path, crate::auth::now());
        Ok(())
    }
    pub fn cgroup_remove(&mut self, ns: &str, path: &str) -> Result<()> {
        let path = cgroup_path(path);
        if ROOT_CGROUPS.contains(&path.as_str()) || path == "/" {
            return Err(abi::Errno::EBUSY.into());
        }
        if self.cgroup(ns, &path).is_none() {
            return Err(abi::Errno::ENOENT.into());
        }
        if self.processes(ns).iter().any(|row| row.cgroup == path) {
            return Err(abi::Errno::EBUSY.into());
        }
        if self
            .rows::<Cgroup>(
                "SELECT ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices FROM cgroups WHERE ns = ? AND parent = ?",
                vec![text(ns), text(&path)],
            )
            .into_iter()
            .next()
            .is_some()
        {
            return Err(abi::Errno::ENOTEMPTY.into());
        }
        self.run(
            "DELETE FROM cgroups WHERE ns = ? AND path = ?",
            vec![text(ns), text(&path)],
        );
        Ok(())
    }
    pub fn cgroup_set(&mut self, ns: &str, path: &str, key: &str, value: &str) -> Result<()> {
        let path = cgroup_path(path);
        let cgroup = self.cgroup(ns, &path).ok_or(abi::Errno::ENOENT)?;
        let mut updated = cgroup.clone();
        match key {
            "cpu.max" => {
                let value = value.trim();
                // cgroup v2's "$MAX [$PERIOD]": a quota or "max", and a period, if given.
                let parts: Vec<&str> = value.split_whitespace().collect();
                let quota = parts
                    .first()
                    .is_some_and(|quota| *quota == "max" || quota.parse::<u64>().is_ok());
                let period = parts
                    .get(1)
                    .is_none_or(|period| period.parse::<u64>().is_ok());
                if !quota || !period || parts.len() > 2 {
                    return Err(abi::Errno::EINVAL.into());
                }
                updated.cpu_max = Some(value.to_string());
            }
            "cpu.weight" => {
                let weight: u32 = value.trim().parse().map_err(|_| abi::Errno::EINVAL)?;
                if !(1..=10000).contains(&weight) {
                    return Err(abi::Errno::EINVAL.into());
                }
                updated.cpu_weight = weight;
            }
            "memory.max" => {
                let value = value.trim();
                if value != "max" && value.parse::<u64>().is_err() {
                    return Err(abi::Errno::EINVAL.into());
                }
                updated.memory_max = Some(value.to_string());
            }
            "pids.max" => {
                let value = value.trim();
                if value == "max" {
                    updated.pids_max = None;
                } else {
                    updated.pids_max = Some(value.parse().map_err(|_| abi::Errno::EINVAL)?);
                }
            }
            "io.max" => updated.io_max = Some(value.trim().to_string()),
            "cgroup.freeze" => {
                updated.freeze = match value.trim() {
                    "0" => 0,
                    "1" => 1,
                    _ => return Err(abi::Errno::EINVAL.into()),
                };
            }
            "devices.allow" | "devices.deny" => {
                updated.devices.push_str(key);
                updated.devices.push(' ');
                updated.devices.push_str(value.trim());
                updated.devices.push('\n');
            }
            _ => return Err(abi::Errno::EINVAL.into()),
        }
        self.run(
            "UPDATE cgroups SET cpu_max = ?, cpu_weight = ?, memory_max = ?, pids_max = ?, io_max = ?, freeze = ?, devices = ? WHERE ns = ? AND path = ?",
            vec![
                updated.cpu_max.clone().map_or(SqlStorageValue::Null, |v| text(&v)),
                int(updated.cpu_weight),
                updated.memory_max.clone().map_or(SqlStorageValue::Null, |v| text(&v)),
                updated.pids_max.map_or(SqlStorageValue::Null, int),
                updated.io_max.clone().map_or(SqlStorageValue::Null, |v| text(&v)),
                int(updated.freeze),
                text(&updated.devices),
                text(ns),
                text(&path),
            ],
        );
        Ok(())
    }
    pub fn cgroup_attach(&mut self, ns: &str, pid: u32, path: &str) -> Result<()> {
        let path = cgroup_path(path);
        if self.cgroup(ns, &path).is_none() {
            return Err(abi::Errno::ENOENT.into());
        }
        let row = self.process(ns, pid).ok_or(abi::Errno::ESRCH)?;
        if row.zombie() {
            return Err(abi::Errno::ESRCH.into());
        }
        self.run(
            "UPDATE processes SET cgroup = ? WHERE ns = ? AND pid = ?",
            vec![text(&path), text(ns), int(pid)],
        );
        Ok(())
    }
    pub fn cgroup_stat(&self, ns: &str, path: &str) -> Result<Value> {
        let path = cgroup_path(path);
        let cgroup = self.cgroup(ns, &path).ok_or(abi::Errno::ENOENT)?;
        let processes: Vec<u32> = self
            .processes(ns)
            .iter()
            .filter(|row| row.cgroup == path)
            .map(|row| row.pid)
            .collect();
        let children: Vec<String> = self
            .rows::<Cgroup>(
                "SELECT ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices FROM cgroups WHERE ns = ? AND parent = ? ORDER BY path",
                vec![text(ns), text(&path)],
            )
            .into_iter()
            .map(|child| child.path)
            .collect();
        Ok(json!({
            "path": cgroup.path,
            "parent": cgroup.parent,
            "controllers": cgroup.controllers,
            "cpu.max": cgroup.cpu_max,
            "cpu.weight": cgroup.cpu_weight,
            "memory.max": cgroup.memory_max,
            "pids.max": cgroup.pids_max,
            "io.max": cgroup.io_max,
            "cgroup.freeze": if cgroup.freeze != 0 { "1" } else { "0" },
            "devices": cgroup.devices,
            "cgroup.procs": processes,
            "children": children,
        }))
    }
    pub fn cgroup_list(&self, ns: &str, path: &str) -> Vec<String> {
        let path = cgroup_path(path);
        self.rows::<Cgroup>(
            "SELECT ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices FROM cgroups WHERE ns = ? AND parent = ? ORDER BY path",
            vec![text(ns), text(&path)],
        )
        .into_iter()
        .map(|child| child.path)
        .collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
struct Cgroup {
    ns: String,
    path: String,
    parent: String,
    controllers: String,
    cpu_max: Option<String>,
    cpu_weight: u32,
    memory_max: Option<String>,
    pids_max: Option<u32>,
    io_max: Option<String>,
    freeze: i64,
    devices: String,
}

/// A cgroup path as cgroup v2 writes one: absolute, its subtree's name relative to it.
fn cgroup_path(path: &str) -> String {
    if path == "/" {
        return "/".into();
    }
    if path.starts_with('/') {
        path.trim_end_matches('/').to_string()
    } else {
        format!("/{}", path.trim_end_matches('/'))
    }
}
