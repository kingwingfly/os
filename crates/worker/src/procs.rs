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
    ARG_MAX, ENV_MAX, Errno, Error, Forked, PIDS_MAX, PROC_MAX, Proc, ProcState, SIGCONT, SIGHUP,
    SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSTOP, SIGTERM, SIGTSTP,
};
use kernel::registry;
use os_core::permissions::Identity;
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use worker::{SqlStorage, SqlStorageValue};

/// The namespace's init, the first process of every browser.
pub const INIT: u32 = 1;
/// The cgroups every namespace starts with.
pub const ROOT_CGROUPS: [&str; 4] = ["/init", "/user", "/system", "/cluster"];

type Result<T> = std::result::Result<T, Error>;

/// The registry's tables, in its namespace's own Durable Object.
const SCHEMA: [&str; 12] = [
    // The namespace, one small machine: the browser it is (its guest, or session, key), the
    // boot it is of (a reload resets stale processes), and the next pid.
    "CREATE TABLE IF NOT EXISTS namespaces(id TEXT PRIMARY KEY, guest TEXT NOT NULL, boot TEXT, next_pid INTEGER NOT NULL, created INTEGER NOT NULL, last_seen INTEGER NOT NULL)",
    // Processes: their parent and credentials, cgroup, image, argument vector and environment,
    // state, the hash of the token their calls carry (a forked child's is its parent's, as its
    // credentials are), and the tab that runs them.
    "CREATE TABLE IF NOT EXISTS processes(ns TEXT NOT NULL, pid INTEGER NOT NULL, ppid INTEGER NOT NULL, uid INTEGER NOT NULL, gid INTEGER NOT NULL, groups TEXT NOT NULL, umask INTEGER NOT NULL, cgroup TEXT NOT NULL, path TEXT NOT NULL, argv TEXT NOT NULL, env TEXT NOT NULL, cwd TEXT NOT NULL, state TEXT NOT NULL, status INTEGER NOT NULL DEFAULT 0, signal INTEGER, token TEXT NOT NULL, started INTEGER NOT NULL, ended INTEGER NOT NULL DEFAULT 0, seat TEXT, PRIMARY KEY(ns, pid))",
    // cgroup v2's hierarchy: its subtree, controllers, control files, and the account that
    // made it (root's for the namespace's own), which may write it.
    "CREATE TABLE IF NOT EXISTS cgroups(ns TEXT NOT NULL, path TEXT NOT NULL, parent TEXT NOT NULL, controllers TEXT NOT NULL, cpu_max TEXT, cpu_weight INTEGER NOT NULL DEFAULT 100, memory_max TEXT, pids_max INTEGER, io_max TEXT, freeze INTEGER NOT NULL DEFAULT 0, devices TEXT NOT NULL DEFAULT '', owner INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(ns, path))",
    // Pids lent to a client kernel (its id), which its forks take at once and tell of after;
    // what a kernel that is gone did not take goes back.
    "CREATE TABLE IF NOT EXISTS spare(pid INTEGER PRIMARY KEY, kernel TEXT, owner INTEGER NOT NULL DEFAULT 0, token TEXT)",
    // Boot ids describe only an account's processes; another account cannot reset them.
    "CREATE TABLE IF NOT EXISTS account_boots(ns TEXT NOT NULL, owner INTEGER NOT NULL, boot TEXT NOT NULL, PRIMARY KEY(ns, owner))",
    // Tokens no process holds any more, which the authority is still to revoke.
    "CREATE TABLE IF NOT EXISTS revoked(token TEXT PRIMARY KEY)",
    "CREATE INDEX IF NOT EXISTS processes_token ON processes(token)",
    "CREATE TABLE IF NOT EXISTS leases(pid INTEGER PRIMARY KEY, expires INTEGER NOT NULL, renewed INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS renewals(token TEXT PRIMARY KEY)",
    "CREATE TABLE IF NOT EXISTS terminals(pid INTEGER PRIMARY KEY, tty INTEGER NOT NULL, fds TEXT NOT NULL)",
    "CREATE TRIGGER IF NOT EXISTS terminals_remove AFTER DELETE ON processes BEGIN DELETE FROM terminals WHERE pid = old.pid; END",
    "CREATE TABLE IF NOT EXISTS observations(name TEXT PRIMARY KEY, value INTEGER NOT NULL)",
];

/// Create the registry's tables, if they are not there yet.
pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    for statement in SCHEMA {
        sql.exec(statement, None)?;
    }
    sql.exec(&format!("INSERT OR IGNORE INTO leases(pid, expires, renewed) SELECT pid, started + {}, started FROM processes WHERE pid != 1", abi::PROCESS_LEASE), None)?;
    // Pids lent before a kernel said who it was are no kernel's, and cgroups made before they
    // had an owner are root's.
    if sql.exec("SELECT kernel FROM spare LIMIT 0", None).is_err() {
        sql.exec("ALTER TABLE spare ADD COLUMN kernel TEXT", None)?;
    }
    if sql.exec("SELECT owner FROM cgroups LIMIT 0", None).is_err() {
        sql.exec(
            "ALTER TABLE cgroups ADD COLUMN owner INTEGER NOT NULL DEFAULT 0",
            None,
        )?;
    }
    if sql.exec("SELECT owner FROM spare LIMIT 0", None).is_err() {
        sql.exec(
            "ALTER TABLE spare ADD COLUMN owner INTEGER NOT NULL DEFAULT 0",
            None,
        )?;
    }
    if sql.exec("SELECT token FROM spare LIMIT 0", None).is_err() {
        sql.exec("ALTER TABLE spare ADD COLUMN token TEXT", None)?;
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
    #[serde(default)]
    pub tty: Option<u32>,
    #[serde(default)]
    pub tty_fds: String,
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
            placement: crate::placement::browser(
                &self.ns,
                self.uid,
                self.seat.as_deref(),
                &self.cgroup,
            ),
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

const COLUMNS: &str = "ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, started, ended, seat, (SELECT tty FROM terminals WHERE terminals.pid = processes.pid) AS tty, COALESCE((SELECT fds FROM terminals WHERE terminals.pid = processes.pid), '[]') AS tty_fds";

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
    /// The executor seat retained when execve does not supply a new one.
    pub seat: Option<String>,
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
    fn lease(&mut self, pid: u32, now: u64) {
        self.run(
            "INSERT OR REPLACE INTO leases(pid, expires, renewed) VALUES(?, ?, ?)",
            vec![int(pid), int(now + abi::PROCESS_LEASE), int(now)],
        );
    }
    /// A host that disappears cannot leave executable credentials or process rows forever.
    /// Web Locks clean up promptly; this deadline also works when every browser tab is gone.
    pub fn expire_processes(&mut self, now: u64) {
        let rows = self.rows::<Row>(&format!("SELECT {COLUMNS} FROM processes WHERE pid != 1 AND pid IN (SELECT pid FROM leases WHERE expires <= ?)"), vec![int(now)]);
        for row in rows {
            if row.zombie() && row.ppid != INIT {
                // A live parent's lease preserves the status until wait, even for a child
                // that exited hours ago. Once the parent disappears it is reaped as usual.
                #[derive(Deserialize)]
                struct Deadline {
                    expires: u64,
                }
                if let Some(deadline) = self
                    .rows::<Deadline>(
                        "SELECT expires FROM leases WHERE pid = ? AND expires > ?",
                        vec![int(row.ppid), int(now)],
                    )
                    .first()
                {
                    self.run(
                        "UPDATE leases SET expires = ? WHERE pid = ?",
                        vec![int(deadline.expires), int(row.pid)],
                    );
                    continue;
                }
            }
            self.observe("processes_expired", 1);
            if !row.zombie() {
                let _ = self.exit(&row, 128 + i32::from(SIGKILL), Some(SIGKILL), now);
            }
            self.remove(&row);
        }
    }
    pub fn lease_deadline(&self) -> Option<u64> {
        #[derive(Deserialize)]
        struct Deadline {
            expires: Option<u64>,
        }
        self.rows::<Deadline>("SELECT MIN(expires) AS expires FROM leases", vec![])
            .into_iter()
            .next()
            .and_then(|row| row.expires)
    }
    pub fn renewing(&self) -> Vec<String> {
        #[derive(Deserialize)]
        struct Token {
            token: String,
        }
        self.rows::<Token>("SELECT token FROM renewals", vec![])
            .into_iter()
            .map(|row| row.token)
            .collect()
    }
    pub fn renewed(&mut self, tokens: &[String]) {
        for token in tokens {
            self.run("DELETE FROM renewals WHERE token = ?", vec![text(token)]);
        }
    }
    /// A host may inspect even a zombie by its token, without gaining access to another
    /// account's processes after a session change. Missing or invalid proofs reveal no row.
    pub fn keep_processes(
        &mut self,
        ns: &str,
        proofs: &[abi::ProcessProof],
        now: u64,
    ) -> Vec<Proc> {
        proofs
            .iter()
            .filter_map(|proof| {
                if self.token_of(ns, proof.pid).as_deref()
                    != Some(crate::auth::token_hash(&proof.token).as_str())
                {
                    return None;
                }
                let row = self.process(ns, proof.pid)?;
                if !row.zombie() {
                    let hash = crate::auth::token_hash(&proof.token);
                    if self.any(
                        "SELECT pid FROM leases WHERE pid = ? AND renewed <= ?",
                        vec![int(proof.pid), int(now.saturating_sub(600))],
                    ) {
                        self.run(
                            "INSERT OR IGNORE INTO renewals(token) VALUES(?)",
                            vec![text(&hash)],
                        );
                        self.run(
                            "UPDATE leases SET renewed = ? WHERE pid = ?",
                            vec![int(now), int(proof.pid)],
                        );
                    }
                    self.run(
                        "UPDATE leases SET expires = ? WHERE pid = ?",
                        vec![int(now + abi::PROCESS_LEASE), int(proof.pid)],
                    );
                }
                Some(row.proc())
            })
            .collect()
    }
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
    /// Begin (or continue) a namespace. A new boot reaps only this account's old processes
    /// and lends; a caller-supplied boot id proves nothing about other accounts' lifetimes.
    pub fn proc_init(&mut self, ns: &str, cred: &Identity, boot: Option<&str>, now: u64) -> Value {
        let existing = self.account_boot(ns, cred.id);
        if let Some(boot) = boot
            && existing.as_deref() != Some(boot)
        {
            for row in self.processes(ns) {
                if row.pid != INIT && row.uid == cred.id {
                    self.orphan(ns, row.pid);
                    self.remove(&row);
                }
            }
            self.run("DELETE FROM spare WHERE owner = ?", vec![int(cred.id)]);
            self.run(
                "INSERT INTO account_boots(ns, owner, boot) VALUES(?, ?, ?) ON CONFLICT(ns, owner) DO UPDATE SET boot = excluded.boot",
                vec![text(ns), int(cred.id), text(boot)],
            );
        }
        self.ensure_namespace(ns, now);
        json!({
            "namespace": ns,
            "pid": INIT,
            "boot": self.account_boot(ns, cred.id),
            "features": abi::Features { wasix: true, cgroups: true, cluster: false, completion_queue: false },
            "lease_seconds": abi::PROCESS_LEASE,
            "counters": self.observations(),
            "pids": self.poll(ns, &[], cred).iter().map(|row| row.pid).collect::<Vec<_>>(),
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
    /// Whether `query` finds a row.
    fn any(&self, query: &str, args: Vec<SqlStorageValue>) -> bool {
        !self.rows::<IgnoredAny>(query, args).is_empty()
    }
    /// The count `query` selects, as `n`.
    fn count(&self, query: &str, args: Vec<SqlStorageValue>) -> usize {
        #[derive(Deserialize)]
        struct Count {
            n: usize,
        }
        self.rows::<Count>(query, args)
            .first()
            .map_or(0, |row| row.n)
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
        self.ensure_cgroup(ns, "/", 0);
        for path in ROOT_CGROUPS {
            self.ensure_cgroup(ns, path, 0);
        }
    }
    fn account_boot(&self, ns: &str, owner: u32) -> Option<String> {
        #[derive(Deserialize)]
        struct Boot {
            boot: Option<String>,
        }
        self.rows::<Boot>(
            "SELECT boot FROM account_boots WHERE ns = ? AND owner = ?",
            vec![text(ns), int(owner)],
        )
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
    /// its token (`token`): only a process replaces itself, as only it can call execve. A new
    /// pid counts against the namespace's processes with the `reserved` ones other execs were
    /// given and have not started yet.
    #[allow(clippy::too_many_arguments)]
    pub fn exec_begin(
        &mut self,
        ns: &str,
        pid: Option<u32>,
        token: Option<&str>,
        argv: &[String],
        env: &[String],
        cgroup: Option<&str>,
        reserved: usize,
        now: u64,
    ) -> Result<Begun> {
        if argv.iter().map(|arg| arg.len() + 1).sum::<usize>() > ARG_MAX {
            return Err(Error::because(
                Errno::E2BIG,
                "the argument vector is too long",
            ));
        }
        if env.iter().map(|entry| entry.len() + 1).sum::<usize>() > ENV_MAX {
            return Err(Error::because(Errno::E2BIG, "the environment is too long"));
        }
        self.ensure_namespace(ns, now);
        let cgroup = cgroup.unwrap_or("/user");
        if self.cgroup(ns, cgroup).is_none() {
            return Err(Error::because(
                Errno::ENOENT,
                format!("{cgroup} is not a cgroup of this namespace"),
            ));
        }
        match pid {
            Some(pid) => {
                // Init is not the caller's to take over.
                if pid == INIT {
                    return Err(Errno::EPERM.into());
                }
                self.process(ns, pid)
                    .filter(|existing| !existing.zombie())
                    .ok_or(Errno::ESRCH)?;
                let existing = token
                    .and_then(|token| self.process_token(token, Some(pid), ns))
                    .ok_or_else(|| {
                        Error::because(Errno::EPERM, "only a process replaces its own image")
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
                    seat: existing.seat,
                })
            }
            None => Ok(Begun {
                pid: self.new_pid(ns, reserved)?,
                replacing: None,
                old: None,
                current: None,
                cgroup: None,
                seat: None,
            }),
        }
    }
    pub fn terminal(
        &mut self,
        ns: &str,
        pid: u32,
        token: &str,
        tty: u32,
        fds: &[u32],
    ) -> Result<()> {
        self.process_token(token, Some(pid), ns)
            .ok_or(Errno::ESRCH)?;
        if fds.len() > 256 || fds.iter().any(|fd| *fd > 65535) || tty < 2 {
            return Err(Errno::EINVAL.into());
        }
        self.run("INSERT INTO terminals(pid, tty, fds) VALUES(?, ?, ?) ON CONFLICT(pid) DO UPDATE SET tty=excluded.tty, fds=excluded.fds",
            vec![int(pid), int(tty), text(&serde_json::to_string(fds).unwrap_or_default())]);
        Ok(())
    }

    /// execve(2)'s second half: the process, with the credentials the authority snapshotted
    /// and its new token's hash, runs the image. A process replacing its image does so only if
    /// it still holds the token it proved itself with, alive: one that ended, or that another
    /// execve replaced first, meanwhile, does not, and the new token is revoked on error. The
    /// token it held goes once no process holds it, as a fork may still.
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
    ) -> Result<()> {
        // The authority has now verified the executable and the caller's snapshot. Check
        // placement with that identity, including changes made while exec awaited it.
        if begun.replacing.is_none() {
            let allowed = self
                .cgroup(ns, cgroup)
                .ok_or(Errno::ENOENT)
                .and_then(|group| {
                    let identity = os_core::permissions::Identity {
                        id: cred.uid,
                        group: cred.gid,
                        groups: cred.groups.clone(),
                    };
                    registry::may_attach(&identity, cred.uid, cgroup, group.owner)
                        .then_some(())
                        .ok_or(Errno::EACCES)
                });
            if let Err(error) = allowed {
                self.run(
                    "INSERT OR IGNORE INTO revoked(token) VALUES(?)",
                    vec![text(token_hash)],
                );
                return Err(error.into());
            }
        }
        let groups = serde_json::to_string(&cred.groups).unwrap_or_default();
        let argv = serde_json::to_string(argv).unwrap_or_default();
        let env = serde_json::to_string(env).unwrap_or_default();
        let seat = seat.map_or(SqlStorageValue::Null, text);
        if begun.replacing.is_some() {
            let current = begun.current.clone().unwrap_or_default();
            let replaced = self.any(
                "UPDATE processes SET uid = ?, gid = ?, groups = ?, umask = ?, cgroup = ?, path = ?, argv = ?, env = ?, cwd = ?, state = 'running', status = 0, signal = NULL, token = ?, started = ?, ended = 0, seat = COALESCE(?, seat) WHERE ns = ? AND pid = ? AND token = ? AND state != 'zombie' RETURNING pid",
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
                    text(&current),
                ],
            );
            if !replaced {
                self.run(
                    "INSERT OR IGNORE INTO revoked(token) VALUES(?)",
                    vec![text(token_hash)],
                );
                return Err(Error::because(
                    Errno::ESRCH,
                    "the process ended, or replaced its image, as it executed",
                ));
            }
            // The image it ran before died with the exec at the authority (`Begun::old`), or,
            // shared then, dies once no fork of it holds it.
            if begun.old.is_none() {
                self.revoke_unheld(ns, &current);
            }
            self.lease(begun.pid, now);
            Ok(())
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
            self.lease(begun.pid, now);
            Ok(())
        }
    }
    /// Whether any process still holds the token `hash` (a fork shares its parent's).
    pub fn token_held(&self, ns: &str, hash: &str) -> bool {
        self.any(
            "SELECT pid FROM processes WHERE ns = ? AND token = ? LIMIT 1",
            vec![text(ns), text(hash)],
        )
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
            self.run("DELETE FROM spare WHERE token = ?", vec![text(hash)]);
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
    /// How many processes `ns` has, or is to have: those alive, the pids lent to its kernels
    /// and not taken yet, and `reserved`, execs begun and not ended.
    fn taken(&self, ns: &str, reserved: usize) -> usize {
        let alive = self.count(
            "SELECT COUNT(*) AS n FROM processes WHERE ns = ? AND state != 'zombie'",
            vec![text(ns)],
        );
        alive + self.count("SELECT COUNT(*) AS n FROM spare", vec![]) + reserved
    }
    /// A new pid, if the namespace has room for one more process (`reserved` others are to
    /// start): EAGAIN, as fork(2) and execve's new process say, if not.
    fn new_pid(&mut self, ns: &str, reserved: usize) -> Result<u32> {
        if self.taken(ns, reserved) >= PROC_MAX {
            return Err(Errno::EAGAIN.into());
        }
        self.next_pids(ns, 1).pop().ok_or(Errno::EAGAIN.into())
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
        self.any("SELECT pid FROM spare WHERE pid = ?", vec![int(pid)])
    }
    /// Lend the client kernel `kernel` up to `count` pids, as many as the namespace has room
    /// for (`reserved` execs are to start), which its forks take without asking. None when it
    /// has no room: EAGAIN, as fork(2) says.
    #[allow(clippy::too_many_arguments)]
    pub fn lend(
        &mut self,
        ns: &str,
        cred: &Identity,
        token: Option<&str>,
        count: u32,
        kernel: Option<&str>,
        reserved: usize,
        now: u64,
    ) -> Result<Vec<u32>> {
        self.ensure_namespace(ns, now);
        let room = PROC_MAX.saturating_sub(self.taken(ns, reserved));
        let count = (count.min(PIDS_MAX) as usize).min(room);
        if count == 0 {
            return Err(Errno::EAGAIN.into());
        }
        let pids = self.next_pids(ns, count);
        let kernel = kernel.map_or(SqlStorageValue::Null, text);
        for pid in &pids {
            self.run(
                "INSERT INTO spare(pid, kernel, owner, token) VALUES(?, ?, ?, ?)",
                vec![
                    int(*pid),
                    kernel.clone(),
                    int(cred.id),
                    token
                        .map(|token| text(&crate::auth::token_hash(token)))
                        .unwrap_or(SqlStorageValue::Null),
                ],
            );
        }
        Ok(pids)
    }
    /// The kernel `kernel` is gone (its Web Lock is free): what it was lent and did not take
    /// goes back. A kernel that never said who it was is "".
    pub fn reclaim(&mut self, kernel: &str, cred: &Identity) -> Result<usize> {
        if cred.id != 0
            && self.any(
                "SELECT pid FROM spare WHERE COALESCE(kernel, '') = ? AND owner != ? LIMIT 1",
                vec![text(kernel), int(cred.id)],
            )
        {
            return Err(Errno::EPERM.into());
        }
        Ok(self
            .rows::<IgnoredAny>(
                "DELETE FROM spare WHERE COALESCE(kernel, '') = ? RETURNING pid",
                vec![text(kernel)],
            )
            .len())
    }
    /// fork(2)'s registry half: a child of `parent`, with its credentials, cgroup, image,
    /// environment and token copied (a child acts as its parent was executed, and shares its
    /// descriptors). Its pid is `child`, one lent to the kernel that forked, or a new one.
    pub fn fork(
        &mut self,
        parent: &Row,
        child: Option<u32>,
        reserved: usize,
        now: u64,
    ) -> Result<Forked> {
        let pid = match child {
            Some(child) => {
                if !self.any(
                    "SELECT pid FROM spare WHERE pid = ? AND owner = ? AND (token IS NULL OR token = ?)",
                    vec![int(child), int(parent.uid), text(&self.token_of(&parent.ns, parent.pid).unwrap_or_default())],
                ) {
                    return Err(Error::because(
                        Errno::EINVAL,
                        format!("{child} is no pid lent to this kernel"),
                    ));
                }
                self.run("DELETE FROM spare WHERE pid = ?", vec![int(child)]);
                child
            }
            None => self.new_pid(&parent.ns, reserved)?,
        };
        self.run(
            "INSERT INTO processes(ns, pid, ppid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, state, status, signal, token, started, ended, seat) SELECT ns, ?, pid, uid, gid, groups, umask, cgroup, path, argv, env, cwd, 'running', 0, NULL, token, ?, 0, seat FROM processes WHERE ns = ? AND pid = ?",
            vec![int(pid), int(now), text(&parent.ns), int(parent.pid)],
        );
        self.run(
            "INSERT INTO terminals(pid, tty, fds) SELECT ?, tty, fds FROM terminals WHERE pid = ?",
            vec![int(pid), int(parent.pid)],
        );
        self.lease(pid, now);
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
            return Err(Errno::ESRCH.into());
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
            self.run("DELETE FROM spare WHERE token = ?", vec![text(&token)]);
            self.run(
                "INSERT OR IGNORE INTO revoked(token) VALUES(?)",
                vec![text(&token)],
            );
        }
    }
    /// Whether a live process holds the token `hash`.
    fn token_live(&self, ns: &str, hash: &str) -> bool {
        self.any(
            "SELECT pid FROM processes WHERE ns = ? AND token = ? AND state != 'zombie' LIMIT 1",
            vec![text(ns), text(hash)],
        )
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
        self.run("DELETE FROM leases WHERE pid = ?", vec![int(row.pid)]);
        self.revoke_unheld(&row.ns, &token);
    }
    /// waitpid(2): the zombie `pid`, now reaped, or EAGAIN while it runs, or ECHILD when it is
    /// no child of `parent` (none: the client kernel, which waits as init).
    pub fn wait(&mut self, ns: &str, parent: Option<u32>, pid: u32) -> Result<Proc> {
        let row = self.process(ns, pid).ok_or(Errno::ECHILD)?;
        if pid == INIT || parent.is_some_and(|parent| row.ppid != parent) {
            return Err(Errno::ECHILD.into());
        }
        if !row.zombie() {
            return Err(Errno::EAGAIN.into());
        }
        self.remove(&row);
        Ok(row.proc())
    }
    /// A host's wait: prove possession of this zombie's token, or act as its account/root.
    /// Without a token the caller waits only for init's children, never another parent's.
    pub fn reap(
        &mut self,
        ns: &str,
        cred: Option<&Identity>,
        pid: u32,
        token: Option<&str>,
    ) -> Result<Proc> {
        let row = self.process(ns, pid).ok_or(Errno::ECHILD)?;
        if let Some(token) = token {
            if self.token_of(ns, pid).as_deref() != Some(crate::auth::token_hash(token).as_str()) {
                return Err(Errno::EPERM.into());
            }
        } else {
            let cred = cred.ok_or(Errno::EPERM)?;
            if !registry::may_manage_process(cred, row.uid) {
                return Err(Errno::EPERM.into());
            }
            if row.ppid != INIT {
                return Err(Errno::ECHILD.into());
            }
        }
        self.wait(ns, None, pid)
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
        let row = self.process(ns, pid).ok_or(Errno::ESRCH)?;
        if cred.id != 0 && cred.id != row.uid {
            return Err(Errno::EPERM.into());
        }
        if row.zombie() {
            return Err(Errno::ESRCH.into());
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
    pub fn gone(&mut self, ns: &str, cred: &Identity, seat: &str, now: u64) -> Result<Vec<u32>> {
        let rows = self.rows::<Row>(
            &format!("SELECT {COLUMNS} FROM processes WHERE ns = ? AND seat = ? AND pid != 1"),
            vec![text(ns), text(seat)],
        );
        // Check the entire seat before changing anything: a tab may hold multiple accounts'
        // processes after login/logout, and its public lock name confers no authority.
        if rows
            .iter()
            .any(|row| !registry::may_manage_process(cred, row.uid))
        {
            return Err(Errno::EPERM.into());
        }
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
        Ok(reaped)
    }
    /// The tabs whose processes still run, and the kernels that hold pids they were lent.
    pub fn seats(&self, ns: &str, cred: &Identity) -> Value {
        #[derive(Deserialize)]
        struct Seat {
            seat: String,
        }
        #[derive(Deserialize)]
        struct Kernel {
            kernel: String,
        }
        let seats: Vec<String> = self
            .rows::<Seat>(
                "SELECT DISTINCT seat FROM processes WHERE ns = ? AND seat IS NOT NULL AND state != 'zombie' AND (uid = ? OR ? = 0) ORDER BY seat",
                vec![text(ns), int(cred.id), int(cred.id)],
            )
            .into_iter()
            .map(|row| row.seat)
            .collect();
        let kernels: Vec<String> = self
            .rows::<Kernel>(
                "SELECT DISTINCT COALESCE(kernel, '') AS kernel FROM spare WHERE owner = ? OR ? = 0 ORDER BY kernel",
                vec![int(cred.id), int(cred.id)],
            )
            .into_iter()
            .map(|row| row.kernel)
            .collect();
        json!({ "seats": seats, "kernels": kernels })
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
            "SELECT ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices, owner FROM cgroups WHERE ns = ? AND path = ?",
            vec![text(ns), text(path)],
        )
        .into_iter()
        .next()
    }
    fn ensure_cgroup(&mut self, ns: &str, path: &str, owner: u32) {
        // The root's parent is the empty string, so that it is nobody's child, its own included
        // (a listing of "/" would otherwise name "/" among its children).
        let parent = if path == "/" {
            ""
        } else {
            os_core::parent(path)
        };
        if self.cgroup(ns, path).is_none() {
            self.run(
                "INSERT INTO cgroups(ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices, owner) VALUES(?, ?, ?, '', NULL, 100, NULL, NULL, NULL, 0, '', ?)",
                vec![text(ns), text(path), text(parent), int(owner)],
            );
        }
    }
    /// mkdir(2) of a cgroup, as `cred`, enabling `controllers` for its subtree: it is its
    /// maker's (`registry::may_create`).
    pub fn cgroup_create(
        &mut self,
        ns: &str,
        cred: &Identity,
        path: &str,
        controllers: Option<&str>,
    ) -> Result<()> {
        self.ensure_namespace(ns, crate::auth::now());
        let path = cgroup_path(path);
        let parent = os_core::parent(&path);
        let Some(above) = self.cgroup(ns, parent) else {
            return Err(Errno::ENOENT.into());
        };
        if self.cgroup(ns, &path).is_some() {
            return Err(Errno::EEXIST.into());
        }
        if !registry::may_create(cred, parent, above.owner) {
            return Err(Errno::EACCES.into());
        }
        let controllers = registry::controllers(controllers.unwrap_or_default())?;
        self.ensure_cgroup(ns, &path, cred.id);
        self.run(
            "UPDATE cgroups SET controllers = ? WHERE ns = ? AND path = ?",
            vec![text(&controllers), text(ns), text(&path)],
        );
        Ok(())
    }
    /// rmdir(2) of a cgroup: its maker's or root's, once nothing is in it.
    pub fn cgroup_remove(&mut self, ns: &str, cred: &Identity, path: &str) -> Result<()> {
        let path = cgroup_path(path);
        if ROOT_CGROUPS.contains(&path.as_str()) || path == "/" {
            return Err(Errno::EBUSY.into());
        }
        let cgroup = self.cgroup(ns, &path).ok_or(Errno::ENOENT)?;
        if !registry::may_write(cred, cgroup.owner) {
            return Err(Errno::EACCES.into());
        }
        if self.processes(ns).iter().any(|row| row.cgroup == path) {
            return Err(Errno::EBUSY.into());
        }
        if !self.cgroup_list(ns, &path).is_empty() {
            return Err(Errno::ENOTEMPTY.into());
        }
        self.run(
            "DELETE FROM cgroups WHERE ns = ? AND path = ?",
            vec![text(ns), text(&path)],
        );
        Ok(())
    }
    /// A write of one of a cgroup's control files: its maker's or root's.
    pub fn cgroup_set(
        &mut self,
        ns: &str,
        cred: &Identity,
        path: &str,
        key: &str,
        value: &str,
    ) -> Result<()> {
        let path = cgroup_path(path);
        let cgroup = self.cgroup(ns, &path).ok_or(Errno::ENOENT)?;
        if !registry::may_write(cred, cgroup.owner) {
            return Err(Errno::EACCES.into());
        }
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
                    return Err(Errno::EINVAL.into());
                }
                updated.cpu_max = Some(value.to_string());
            }
            "cpu.weight" => {
                let weight: u32 = value.trim().parse().map_err(|_| Errno::EINVAL)?;
                if !(1..=10000).contains(&weight) {
                    return Err(Errno::EINVAL.into());
                }
                updated.cpu_weight = weight;
            }
            "memory.max" => {
                let value = value.trim();
                if value != "max" && value.parse::<u64>().is_err() {
                    return Err(Errno::EINVAL.into());
                }
                updated.memory_max = Some(value.to_string());
            }
            "pids.max" => {
                let value = value.trim();
                if value == "max" {
                    updated.pids_max = None;
                } else {
                    updated.pids_max = Some(value.parse().map_err(|_| Errno::EINVAL)?);
                }
            }
            "io.max" => updated.io_max = Some(value.trim().to_string()),
            "cgroup.freeze" => {
                updated.freeze = match value.trim() {
                    "0" => 0,
                    "1" => 1,
                    _ => return Err(Errno::EINVAL.into()),
                };
            }
            "devices.allow" | "devices.deny" => {
                if updated.devices.lines().count() >= registry::DEVICE_RULES_MAX {
                    return Err(Error::because(
                        Errno::ENOSPC,
                        format!(
                            "a cgroup keeps at most {} device rules",
                            registry::DEVICE_RULES_MAX
                        ),
                    ));
                }
                updated.devices.push_str(key);
                updated.devices.push(' ');
                updated.devices.push_str(value.trim());
                updated.devices.push('\n');
            }
            _ => return Err(Errno::EINVAL.into()),
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
    /// A write of the process `pid` to the cgroup's `cgroup.procs`: as `registry::may_attach`.
    pub fn cgroup_attach(&mut self, ns: &str, cred: &Identity, pid: u32, path: &str) -> Result<()> {
        let path = cgroup_path(path);
        let cgroup = self.cgroup(ns, &path).ok_or(Errno::ENOENT)?;
        let row = self.process(ns, pid).ok_or(Errno::ESRCH)?;
        if row.zombie() {
            return Err(Errno::ESRCH.into());
        }
        if !registry::may_attach(cred, row.uid, &path, cgroup.owner) {
            return Err(Errno::EACCES.into());
        }
        self.run(
            "UPDATE processes SET cgroup = ? WHERE ns = ? AND pid = ?",
            vec![text(&path), text(ns), int(pid)],
        );
        Ok(())
    }
    pub fn cgroup_stat(&self, ns: &str, path: &str) -> Result<Value> {
        let path = cgroup_path(path);
        let cgroup = self.cgroup(ns, &path).ok_or(Errno::ENOENT)?;
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
            "owner": cgroup.owner,
            "cgroup.procs": processes,
            "children": self.cgroup_list(ns, &path),
        }))
    }
    pub fn cgroup_list(&self, ns: &str, path: &str) -> Vec<String> {
        let path = cgroup_path(path);
        self.rows::<Cgroup>(
            "SELECT ns, path, parent, controllers, cpu_max, cpu_weight, memory_max, pids_max, io_max, freeze, devices, owner FROM cgroups WHERE ns = ? AND parent = ? ORDER BY path",
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
    owner: u32,
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
