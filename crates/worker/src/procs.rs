//! The process registry (owner's plan, 2026-11-01; moved out of the authority 2026-11-03): each
//! browser is a namespace with PID 1, kept by a Durable Object of its own (machine.rs), and
//! every process is a row here: who it runs as, its cgroup, its image, its state, and the hash
//! of the token its calls carry. The client kernel in the browser owns the wasm state and tells
//! of forks, exits and waits as they happen, in batches; this registry keeps the record and the
//! decisions. A process's exit makes it a zombie until its parent waits for it; init reaps
//! orphans.
//!
//! The authority (the filesystem's Durable Object) keeps only each exec's credentials
//! (creds.rs): a token whose process is gone, and that no process forked from it still holds,
//! is revoked there in a batch (`revoked`, flushed with the next execve or by the alarm).
use crate::db::{Db, int, text};
use abi::{
    ARG_MAX, ENV_MAX, Error, Forked, PIDS_MAX, PROC_MAX, Proc, ProcState, SIGCONT, SIGHUP, SIGINT,
    SIGKILL, SIGPIPE, SIGQUIT, SIGSTOP, SIGTERM, SIGTSTP,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use terminal_worker_core::permissions::Identity;
use worker::{SqlStorage, SqlStorageValue};

/// The namespace's init, the first process of every browser.
pub const INIT: u32 = 1;
/// The cgroups every namespace starts with.
pub const ROOT_CGROUPS: [&str; 4] = ["/init", "/user", "/system", "/cluster"];

type Result<T> = std::result::Result<T, Error>;

/// The registry's tables, in its namespace's own Durable Object.
const SCHEMA: [&str; 6] = [
    // The namespace, one small machine: the browser it is (its guest, or session, key), the
    // boot it is of (a reload resets stale processes), and the next pid.
    "CREATE TABLE IF NOT EXISTS namespaces(id TEXT PRIMARY KEY, guest TEXT NOT NULL, boot TEXT, next_pid INTEGER NOT NULL, created INTEGER NOT NULL, last_seen INTEGER NOT NULL)",
    // Processes: their parent and credentials, cgroup, image, argument vector and environment,
    // state, the hash of the token their calls carry (a forked child's is its parent's, as its
    // credentials are), and the tab that runs them.
    "CREATE TABLE IF NOT EXISTS processes(ns TEXT NOT NULL, pid INTEGER NOT NULL, ppid INTEGER NOT NULL, uid INTEGER NOT NULL, gid INTEGER NOT NULL, groups TEXT NOT NULL, umask INTEGER NOT NULL, cgroup TEXT NOT NULL, path TEXT NOT NULL, argv TEXT NOT NULL, env TEXT NOT NULL, cwd TEXT NOT NULL, state TEXT NOT NULL, status INTEGER NOT NULL DEFAULT 0, signal INTEGER, token TEXT NOT NULL, started INTEGER NOT NULL, ended INTEGER NOT NULL DEFAULT 0, seat TEXT, PRIMARY KEY(ns, pid))",
    // cgroup v2's hierarchy: its subtree, controllers, and control files.
    "CREATE TABLE IF NOT EXISTS cgroups(ns TEXT NOT NULL, path TEXT NOT NULL, parent TEXT NOT NULL, controllers TEXT NOT NULL, cpu_max TEXT, cpu_weight INTEGER NOT NULL DEFAULT 100, memory_max TEXT, pids_max INTEGER, io_max TEXT, freeze INTEGER NOT NULL DEFAULT 0, devices TEXT NOT NULL DEFAULT '', PRIMARY KEY(ns, path))",
    // Pids lent to a client kernel, which its forks take at once and tell of after.
    "CREATE TABLE IF NOT EXISTS spare(pid INTEGER PRIMARY KEY)",
    // Tokens no process holds any more, which the authority is still to revoke.
    "CREATE TABLE IF NOT EXISTS revoked(token TEXT PRIMARY KEY)",
    "CREATE INDEX IF NOT EXISTS processes_token ON processes(token)",
];

/// Create the registry's tables, if they are not there yet.
pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    for statement in SCHEMA {
        sql.exec(statement, None)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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

/// What an execve asks of the registry, once its arguments are checked: the pid it runs as,
/// and, replacing a process, whose that was and the token it held (`Begun`); then, once the
/// authority has checked the image and snapshotted the caller, the row (`Db::exec_end`).
#[derive(Clone, Debug)]
pub struct Begun {
    pub pid: u32,
    /// The account of the process it replaces, if it replaces one.
    pub replacing: Option<u32>,
    /// The token hash the replaced image held, which dies with it: none while a process forked
    /// from it (or that forked it) still holds it.
    pub old: Option<String>,
    /// The token hash the replaced process proved itself with: the credentials the new image
    /// keeps, and the descriptors it keeps open.
    pub current: Option<String>,
    /// The cgroup the replaced process is in, which it stays in.
    pub cgroup: Option<String>,
}

/// The credentials an execve snapshotted (the authority's answer).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Snapshot {
    pub uid: u32,
    pub gid: u32,
    pub groups: BTreeSet<u32>,
    pub umask: u16,
}

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
    /// The live process `pid` of `ns`, if `token` is its token. Tokens are stored hashed, so a
    /// copy of the store is not a set of capabilities; a zombie's token is dead with the
    /// process. A forked child holds its parent's token, as it holds its credentials, so a
    /// token alone does not say which process calls: its pid does.
    pub fn process_token(&self, token: &str, pid: Option<u32>, ns: &str) -> Option<Row> {
        let pid = pid?;
        self.rows::<Row>(
            &format!(
                "SELECT {COLUMNS} FROM processes WHERE ns = ? AND pid = ? AND token = ? AND state != 'zombie'"
            ),
            vec![text(ns), int(pid), text(&crate::auth::token_hash(token))],
        )
        .into_iter()
        .next()
    }
    /// The namespace a request is of: the browser's guest, or, with no guest cookie, its
    /// signed-in session (or the anonymous namespace of a request with neither).
    pub fn namespace(key: Option<&str>, guest: Option<&str>) -> String {
        guest
            .map(str::to_string)
            .or_else(|| key.map(|key| format!("session.{key}")))
            .unwrap_or_else(|| "anonymous".into())
    }
    /// The namespace this registry keeps, once anything began it.
    pub fn namespace_id(&self) -> Option<String> {
        #[derive(Deserialize)]
        struct Id {
            id: String,
        }
        self.rows::<Id>("SELECT id FROM namespaces LIMIT 1", vec![])
            .into_iter()
            .next()
            .map(|row| row.id)
    }
    /// Begin (or continue) a namespace, as init does: a new boot reaps what the old one left
    /// running, the init process exists, and the root cgroups are there. Init is root's, as
    /// Linux's is.
    pub fn proc_init(&mut self, ns: &str, boot: Option<&str>, now: u64) -> Value {
        let existing = self.namespace_boot(ns);
        if let Some(boot) = boot
            && existing.as_deref() != Some(boot)
        {
            // Nothing of the old boot's processes can be waited for or signalled any more: its
            // pages are gone. The new boot starts with init alone.
            for row in self.processes(ns) {
                if row.pid != INIT {
                    self.remove(&row);
                }
            }
        }
        self.run(
            "INSERT INTO namespaces(id, guest, boot, next_pid, created, last_seen) VALUES(?, ?, ?, 2, ?, ?) ON CONFLICT(id) DO UPDATE SET boot = excluded.boot, last_seen = excluded.last_seen",
            vec![text(ns), text(ns), boot.map(text).unwrap_or(SqlStorageValue::Null), int(now), int(now)],
        );
        self.ensure_init(ns, now);
        json!({
            "namespace": ns,
            "pid": INIT,
            "boot": self.namespace_boot(ns),
            "pids": self.processes(ns).iter().map(|row| row.pid).collect::<Vec<_>>(),
        })
    }
    /// A namespace that is there, without a boot's reap: its row, init, and root cgroups.
    fn ensure_namespace(&mut self, ns: &str, now: u64) {
        self.run(
            "INSERT INTO namespaces(id, guest, boot, next_pid, created, last_seen) VALUES(?, ?, NULL, 2, ?, ?) ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen",
            vec![text(ns), text(ns), int(now), int(now)],
        );
        self.ensure_init(ns, now);
    }
    fn ensure_init(&mut self, ns: &str, now: u64) {
        if self.process(ns, INIT).is_none() {
            self.run(
                "INSERT INTO processes(ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, token, started, ended) VALUES(?, 1, 0, 0, 0, '[0]', 18, '/init', '/init', '[\"init\"]', '[]', '/', 'running', 0, NULL, ?, ?, 0)",
                vec![
                    text(ns),
                    // Init makes no calls of its own: nobody holds its token.
                    text(&crate::auth::token_hash(&crate::auth::random_token())),
                    int(now),
                ],
            );
        }
        self.ensure_cgroup(ns, "/");
        for path in ROOT_CGROUPS {
            self.ensure_cgroup(ns, path);
        }
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
    /// execve(2)'s first half, before the authority checks the image: its arguments' sizes,
    /// its cgroup, and its pid, a new one or the process it replaces, which proves itself by
    /// its token (`token`): only a process replaces itself, as only it can call execve.
    #[allow(clippy::too_many_arguments)]
    pub fn exec_begin(
        &mut self,
        ns: &str,
        pid: Option<u32>,
        token: Option<&str>,
        argv: &[String],
        env: &[String],
        cgroup: Option<&str>,
        now: u64,
    ) -> Result<Begun> {
        if argv.iter().map(|arg| arg.len() + 1).sum::<usize>() > ARG_MAX {
            return Err(Error::because(
                abi::Errno::E2BIG,
                "the argument vector is too long",
            ));
        }
        if env.iter().map(|entry| entry.len() + 1).sum::<usize>() > ENV_MAX {
            return Err(Error::because(
                abi::Errno::E2BIG,
                "the environment is too long",
            ));
        }
        self.ensure_namespace(ns, now);
        let cgroup = cgroup.unwrap_or("/user");
        if self.cgroup(ns, cgroup).is_none() {
            return Err(Error::because(
                abi::Errno::ENOENT,
                format!("{cgroup} is not a cgroup of this namespace"),
            ));
        }
        match pid {
            Some(pid) => {
                // Init is not the caller's to take over.
                if pid == INIT {
                    return Err(abi::Errno::EPERM.into());
                }
                self.process(ns, pid)
                    .filter(|existing| !existing.zombie())
                    .ok_or(abi::Errno::ESRCH)?;
                let existing = token
                    .and_then(|token| self.process_token(token, Some(pid), ns))
                    .ok_or_else(|| {
                        Error::because(abi::Errno::EPERM, "only a process replaces its own image")
                    })?;
                // The token the image held dies with it, unless a process forked from it, or
                // forked it, holds it still.
                let token = self.token_of(ns, pid).unwrap_or_default();
                let shared = self.processes(ns).iter().any(|row| {
                    row.pid != pid && self.token_of(ns, row.pid).as_ref() == Some(&token)
                });
                Ok(Begun {
                    pid,
                    replacing: Some(existing.uid),
                    old: (!shared).then(|| token.clone()),
                    current: Some(token),
                    cgroup: Some(existing.cgroup),
                })
            }
            None => Ok(Begun {
                pid: self.new_pid(ns)?,
                replacing: None,
                old: None,
                current: None,
                cgroup: None,
            }),
        }
    }
    /// execve(2)'s second half: the process, with the credentials the authority snapshotted
    /// and its new token's hash, runs the image.
    #[allow(clippy::too_many_arguments)]
    pub fn exec_end(
        &mut self,
        ns: &str,
        begun: &Begun,
        cred: &Snapshot,
        token_hash: &str,
        path: &str,
        argv: &[String],
        env: &[String],
        cwd: &str,
        cgroup: &str,
        seat: Option<&str>,
        now: u64,
    ) {
        let groups = serde_json::to_string(&cred.groups).unwrap_or_default();
        let argv = serde_json::to_string(argv).unwrap_or_default();
        let env = serde_json::to_string(env).unwrap_or_default();
        let seat = seat.map_or(SqlStorageValue::Null, text);
        if begun.replacing.is_some() {
            self.run(
                "UPDATE processes SET uid = ?, gid = ?, groups = ?, umask = ?, cgroup = ?, path = ?, argv = ?, env = ?, cwd = ?, state = 'running', status = 0, signal = NULL, token = ?, started = ?, ended = 0, seat = COALESCE(?, seat) WHERE ns = ? AND pid = ?",
                vec![
                    int(cred.uid),
                    int(cred.gid),
                    text(&groups),
                    int(cred.umask),
                    text(cgroup),
                    text(path),
                    text(&argv),
                    text(&env),
                    text(cwd),
                    text(token_hash),
                    int(now),
                    seat,
                    text(ns),
                    int(begun.pid),
                ],
            );
            // The image it ran before died with the exec at the authority (`Begun::old`).
        } else {
            self.run(
                "INSERT INTO processes(ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, token, started, ended, seat) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 0, NULL, ?, ?, 0, ?)",
                vec![
                    text(ns),
                    int(begun.pid),
                    int(INIT),
                    int(cred.uid),
                    int(cred.gid),
                    text(&groups),
                    int(cred.umask),
                    text(cgroup),
                    text(path),
                    text(&argv),
                    text(&env),
                    text(cwd),
                    text(token_hash),
                    int(now),
                    seat,
                ],
            );
        }
    }
    /// Whether any process still holds the token `hash` (a fork shares its parent's).
    pub fn token_held(&self, ns: &str, hash: &str) -> bool {
        #[derive(Deserialize)]
        struct One {
            #[allow(dead_code)]
            pid: u32,
        }
        !self
            .rows::<One>(
                "SELECT pid FROM processes WHERE ns = ? AND token = ? LIMIT 1",
                vec![text(ns), text(hash)],
            )
            .is_empty()
    }
    fn token_of(&self, ns: &str, pid: u32) -> Option<String> {
        #[derive(Deserialize)]
        struct Token {
            token: String,
        }
        self.rows::<Token>(
            "SELECT token FROM processes WHERE ns = ? AND pid = ?",
            vec![text(ns), int(pid)],
        )
        .into_iter()
        .next()
        .map(|row| row.token)
    }
    /// Revoke the token `hash` at the authority, unless a process still holds it.
    pub fn revoke_unheld(&mut self, ns: &str, hash: &str) {
        if !hash.is_empty() && !self.token_held(ns, hash) {
            self.run(
                "INSERT OR IGNORE INTO revoked(token) VALUES(?)",
                vec![text(hash)],
            );
        }
    }
    /// The tokens waiting to be revoked at the authority.
    pub fn revoking(&self) -> Vec<String> {
        #[derive(Deserialize)]
        struct Token {
            token: String,
        }
        self.rows::<Token>("SELECT token FROM revoked LIMIT 256", vec![])
            .into_iter()
            .map(|row| row.token)
            .collect()
    }
    /// The tokens the authority revoked.
    pub fn revoked(&mut self, tokens: &[String]) {
        for token in tokens {
            self.run("DELETE FROM revoked WHERE token = ?", vec![text(token)]);
        }
    }
    /// How many processes of `ns` are alive.
    fn alive(&self, ns: &str) -> usize {
        #[derive(Deserialize)]
        struct Alive {
            n: usize,
        }
        self.rows::<Alive>(
            "SELECT COUNT(*) AS n FROM processes WHERE ns = ? AND state != 'zombie'",
            vec![text(ns)],
        )
        .first()
        .map_or(0, |row| row.n)
    }
    fn new_pid(&mut self, ns: &str) -> Result<u32> {
        if self.alive(ns) >= PROC_MAX {
            return Err(abi::Errno::EAGAIN.into());
        }
        self.next_pids(ns, 1).pop().ok_or(abi::Errno::EAGAIN.into())
    }
    /// The next `count` pids no process has, taken.
    fn next_pids(&mut self, ns: &str, count: usize) -> Vec<u32> {
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
        let mut pids = Vec::with_capacity(count);
        while pids.len() < count && next < u32::MAX {
            if self.process(ns, next).is_none() && !self.spare(next) {
                pids.push(next);
            }
            next += 1;
        }
        self.run(
            "UPDATE namespaces SET next_pid = ? WHERE id = ?",
            vec![int(next), text(ns)],
        );
        pids
    }
    fn spare(&self, pid: u32) -> bool {
        #[derive(Deserialize)]
        struct One {
            #[allow(dead_code)]
            pid: u32,
        }
        !self
            .rows::<One>("SELECT pid FROM spare WHERE pid = ?", vec![int(pid)])
            .is_empty()
    }
    /// Lend the client kernel up to `count` pids, as many as the namespace has room for, which
    /// its forks take without asking. None when it has no room: EAGAIN, as fork(2) says.
    pub fn lend(&mut self, ns: &str, count: u32, now: u64) -> Result<Vec<u32>> {
        self.ensure_namespace(ns, now);
        #[derive(Deserialize)]
        struct Lent {
            n: usize,
        }
        let lent = self
            .rows::<Lent>("SELECT COUNT(*) AS n FROM spare", vec![])
            .first()
            .map_or(0, |row| row.n);
        let room = PROC_MAX.saturating_sub(self.alive(ns) + lent);
        let count = (count.min(PIDS_MAX) as usize).min(room);
        if count == 0 {
            return Err(abi::Errno::EAGAIN.into());
        }
        let pids = self.next_pids(ns, count);
        for pid in &pids {
            self.run("INSERT INTO spare(pid) VALUES(?)", vec![int(*pid)]);
        }
        Ok(pids)
    }
    /// fork(2)'s registry half: a child of `parent`, with its credentials, cgroup, image,
    /// environment and token copied (a child acts as its parent was executed, and shares its
    /// descriptors). Its pid is `child`, one lent to the kernel that forked, or a new one.
    pub fn fork(&mut self, parent: &Row, child: Option<u32>, now: u64) -> Result<Forked> {
        let pid = match child {
            Some(child) => {
                if !self.spare(child) {
                    return Err(Error::because(
                        abi::Errno::EINVAL,
                        format!("{child} is no pid lent to this kernel"),
                    ));
                }
                self.run("DELETE FROM spare WHERE pid = ?", vec![int(child)]);
                child
            }
            None => self.new_pid(&parent.ns)?,
        };
        self.run(
            "INSERT INTO processes(ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, token, started, ended, seat) SELECT ns, ?, pid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, 'running', 0, NULL, token, ?, 0, seat FROM processes WHERE ns = ? AND pid = ?",
            vec![int(pid), int(now), text(&parent.ns), int(parent.pid)],
        );
        Ok(Forked {
            pid,
            // The child's calls carry its parent's token, with its own pid.
            token: String::new(),
        })
    }
    /// exit(2): the process ends, by `status` or `signal`, and waits as a zombie for its
    /// parent. Its children are init's from now on, and those that ended already, init reaps.
    pub fn exit(&mut self, row: &Row, status: i32, signal: Option<u8>, now: u64) -> Result<()> {
        if row.zombie() {
            return Err(abi::Errno::ESRCH.into());
        }
        let wait = match signal {
            Some(signal) => abi::signal_status(signal),
            None => abi::exit_status(status),
        };
        self.end(row, wait, signal, now);
        Ok(())
    }
    /// The process `row` ends with the wait status `wait`: a zombie, its children init's, and
    /// its token revoked unless a fork of it still runs.
    fn end(&mut self, row: &Row, wait: i32, signal: Option<u8>, now: u64) {
        let token = self.token_of(&row.ns, row.pid).unwrap_or_default();
        self.run(
            "UPDATE processes SET state = 'zombie', status = ?, signal = ?, ended = ? WHERE ns = ? AND pid = ?",
            vec![
                int(wait),
                signal.map_or(SqlStorageValue::Null, int),
                int(now),
                text(&row.ns),
                int(row.pid),
            ],
        );
        self.orphan(&row.ns, row.pid);
        // A zombie's token is dead with it, though its row keeps the hash until it is reaped.
        if !self.token_live(&row.ns, &token) {
            self.run(
                "INSERT OR IGNORE INTO revoked(token) VALUES(?)",
                vec![text(&token)],
            );
        }
    }
    /// Whether a live process holds the token `hash`.
    fn token_live(&self, ns: &str, hash: &str) -> bool {
        #[derive(Deserialize)]
        struct One {
            #[allow(dead_code)]
            pid: u32,
        }
        !self
            .rows::<One>(
                "SELECT pid FROM processes WHERE ns = ? AND token = ? AND state != 'zombie' LIMIT 1",
                vec![text(ns), text(hash)],
            )
            .is_empty()
    }
    /// The children of `pid`, whose parent ended: init's now, as Linux reparents orphans, and,
    /// those that are zombies, reaped by it at once.
    fn orphan(&mut self, ns: &str, pid: u32) {
        let children = self.rows::<Row>(
            &format!("SELECT {COLUMNS} FROM processes WHERE ns = ? AND ppid = ?"),
            vec![text(ns), int(pid)],
        );
        for child in children {
            if child.zombie() {
                self.remove(&child);
            } else {
                self.run(
                    "UPDATE processes SET ppid = ? WHERE ns = ? AND pid = ?",
                    vec![int(INIT), text(ns), int(child.pid)],
                );
            }
        }
    }
    /// The process `row` is gone from the table, its token revoked unless another holds it.
    fn remove(&mut self, row: &Row) {
        let token = self.token_of(&row.ns, row.pid).unwrap_or_default();
        self.run(
            "DELETE FROM processes WHERE ns = ? AND pid = ?",
            vec![text(&row.ns), int(row.pid)],
        );
        self.revoke_unheld(&row.ns, &token);
    }
    /// waitpid(2): the zombie `pid`, now reaped, or EAGAIN while it runs, or ECHILD when it is
    /// no child of `parent` (none: the client kernel, which waits as init).
    pub fn wait(&mut self, ns: &str, parent: Option<u32>, pid: u32) -> Result<Proc> {
        let row = self.process(ns, pid).ok_or(abi::Errno::ECHILD)?;
        if pid == INIT || parent.is_some_and(|parent| row.ppid != parent) {
            return Err(abi::Errno::ECHILD.into());
        }
        if !row.zombie() {
            return Err(abi::Errno::EAGAIN.into());
        }
        self.remove(&row);
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
        // Init ignores the signals it installed no handler for, SIGKILL too, as Linux's does.
        if pid == INIT {
            return Ok(());
        }
        match signal {
            SIGHUP | SIGINT | SIGQUIT | SIGKILL | SIGPIPE | SIGTERM => {
                self.end(&row, abi::signal_status(signal), Some(signal), now);
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
    /// The tab `seat` is gone: what it ran ended with it, as by SIGKILL, and is reaped (it was
    /// init's, or is now). What it forked that another tab runs goes on, init's.
    pub fn gone(&mut self, ns: &str, seat: &str, now: u64) -> Vec<u32> {
        let rows = self.rows::<Row>(
            &format!("SELECT {COLUMNS} FROM processes WHERE ns = ? AND seat = ? AND pid != 1"),
            vec![text(ns), text(seat)],
        );
        let mut reaped = Vec::new();
        for row in &rows {
            if !row.zombie() {
                self.end(row, abi::signal_status(SIGKILL), Some(SIGKILL), now);
            }
        }
        for row in rows {
            // Its parent may be gone with it, which made it init's.
            if let Some(now) = self.process(ns, row.pid)
                && now.ppid == INIT
            {
                self.remove(&now);
                reaped.push(row.pid);
            }
        }
        reaped
    }
    /// The tabs whose processes still run.
    pub fn seats(&self, ns: &str) -> Vec<String> {
        #[derive(Deserialize)]
        struct Seat {
            seat: String,
        }
        self.rows::<Seat>(
            "SELECT DISTINCT seat FROM processes WHERE ns = ? AND seat IS NOT NULL AND state != 'zombie' ORDER BY seat",
            vec![text(ns)],
        )
        .into_iter()
        .map(|row| row.seat)
        .collect()
    }
    /// What the processes `pids` (all of `ns` if none) are now, as /proc shows them. A process
    /// sees its own account's; root sees the namespace's.
    pub fn poll(&self, ns: &str, pids: &[u32], cred: &Identity) -> Vec<Proc> {
        let rows = if pids.is_empty() {
            self.processes(ns)
        } else {
            pids.iter()
                .filter_map(|pid| self.process(ns, *pid))
                .collect()
        };
        rows.into_iter()
            .filter(|row| cred.id == 0 || row.uid == cred.id || row.pid == INIT)
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
    fn ensure_cgroup(&mut self, ns: &str, path: &str) {
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
    }
    pub fn cgroup_create(&mut self, ns: &str, path: &str) -> Result<()> {
        self.ensure_namespace(ns, crate::auth::now());
        let path = cgroup_path(path);
        let parent = terminal_worker_core::parent(&path);
        if self.cgroup(ns, parent).is_none() {
            return Err(abi::Errno::ENOENT.into());
        }
        if self.cgroup(ns, &path).is_some() {
            return Err(abi::Errno::EEXIST.into());
        }
        self.ensure_cgroup(ns, &path);
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
        if !self.cgroup_list(ns, &path).is_empty() {
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
            "children": self.cgroup_list(ns, &path),
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
