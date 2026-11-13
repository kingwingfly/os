//! What the authority keeps of processes (owner's plan, 2026-11-02): only each exec's
//! credentials. The process table is each browser's own Durable Object (machine.rs, procs.rs);
//! of all a process's life, only execve needs the filesystem's authority, which checks the
//! image (X, not R), snapshots the caller (root under sudo), and records the snapshot by the
//! hash of the token the process's calls carry from then on. Its forks carry the same token,
//! as they keep its credentials and share its descriptors; the registry revokes it, in
//! batches, once no process holds it.
//!
//! The registry asks here by internal requests, which the Worker never routes from a browser
//! (it routes /api/* alone): `/internal/exec`, `/internal/identity`, `/internal/revoke` and
//! `/internal/tell`. Each carries the browser's cookies, as the request it serves did.
use crate::api::Reply;
use crate::auth;
use crate::db::{Db, int, text, transact};
use abi::{EXEC_MAX, Errno, Error, Return};
use os_core::permissions::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use worker::*;

/// An exec's credentials, as its process (and what it forked) acts.
#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
    /// The hash of the token its calls carry.
    pub token: String,
    pub ns: String,
    /// The process that executed.
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub groups: String,
    pub umask: u16,
    pub generation: Option<String>,
    pub cloud_access: u8,
    /// The key its process's descriptors are owned by: its own exec's (`owner`), or, for an
    /// image a process replaced its own with, the one that process had, as execve keeps a
    /// process's open files.
    #[serde(rename = "owner")]
    lineage: String,
}

/// A credential's descriptors' owner, in SQL: an exec made before credentials named it owns
/// them by its own key (`owner`).
const OWNER: &str = "COALESCE(owner, ns || ' ' || pid || ' ' || substr(token, 1, 16))";
/// The columns a `Credential` is read from.
fn columns() -> String {
    format!("token, ns, pid, uid, gid, groups, umask, generation, cloud_access, {OWNER} AS owner")
}
impl Credential {
    pub fn cloud(&self) -> std::result::Result<(), abi::Error> {
        if self.cloud_access == 0 {
            Err(abi::Error::because(
                Errno::EACCES,
                "cloud filesystem access was not delegated to this process",
            ))
        } else {
            Ok(())
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
    /// The key its descriptors are owned by (fds.rs): its process's and its forks', and those
    /// of the images they replace their own with, which keep them open. A process whose image
    /// another of the line replaced, while a fork kept this one, shares them: they hold the
    /// same credentials, which an execve does not change.
    pub fn owner(&self) -> String {
        self.lineage.clone()
    }
    /// The key of what this exec alone owns: its image's descriptor, which closes with it.
    pub fn image(&self) -> String {
        owner(&self.ns, self.pid, &self.token)
    }
}

/// The namespace jobs' credentials are in (Phase 4): a job is no browser's process, and its
/// token never leaves the server, as its runner alone holds it (runner.rs).
pub const JOBS: &str = "jobs";
/// The namespace of a request with no browser's cookies (procs.rs `Db::namespace`).
const ANONYMOUS: &str = "anonymous";

/// The key the descriptors of the job `id` are owned by, and the session they are kept in.
pub fn job_owner(id: &str) -> String {
    format!("job {id}")
}

impl Credential {
    /// The session its descriptors are kept in: its line's own, whatever the browser's page is
    /// signed in as meanwhile, as a process's open files outlive any change to its user's
    /// login session (a job's is the job's own).
    pub fn session(&self) -> String {
        session_of(&self.ns, &self.lineage)
    }
    /// The job these credentials are, if they are a job's.
    pub fn job(&self) -> Option<String> {
        (self.ns == JOBS)
            .then(|| self.lineage.strip_prefix("job ").map(str::to_string))
            .flatten()
    }
}

/// The session the descriptors of a request are kept in: its process's line's, or else the
/// browser's (the cookies' session).
pub fn sid_of(
    db: &Db,
    key: Option<&str>,
    guest: Option<&str>,
    caller: Option<&Credential>,
) -> Option<String> {
    caller
        .map(Credential::session)
        .or_else(|| auth::sid(db, key, guest))
}

/// The session of the descriptors the line of credentials `lineage` of `ns` owns: a job's is
/// its owner key; a browser's process's, its line's.
fn session_of(ns: &str, lineage: &str) -> String {
    if ns == JOBS {
        lineage.to_string()
    } else {
        format!("proc {lineage}")
    }
}

/// The key the descriptors of the credentials of token hash `token`, executed as `pid` of
/// `ns`, are owned by.
fn owner(ns: &str, pid: u32, token: &str) -> String {
    format!("{ns} {pid} {}", token.get(..16).unwrap_or(token))
}

impl Db {
    /// The credentials the token `token` carries, in namespace `ns`, while it is not revoked:
    /// a browser's process's, or a job's, whose token only its runner has.
    pub fn credential(&self, token: &str, ns: &str) -> Option<Credential> {
        let hash = auth::token_hash(token);
        // A job's token comes from its runner alone, whose requests carry no browser's cookies
        // (the anonymous namespace): a browser's request never finds a job's.
        self.credential_of(&hash, ns)
            .or_else(|| (ns == ANONYMOUS).then(|| self.credential_of(&hash, JOBS))?)
    }
    /// The credentials of the job `id`, as `cred` spawned it with `umask`, by its token's hash
    /// `hash`: they are the job's for its life, whatever becomes of the account.
    pub fn job_credential(&mut self, id: &str, hash: &str, cred: &Identity, umask: u16, now: u64) {
        // Enforce the same absolute deadline on byte streams and syscall batches,
        // even if the durable cleanup alarm is delivered late.
        let expires = self.provider_deadline(id).unwrap_or(now + 7 * 24 * 3600);
        self.run(
            "INSERT OR REPLACE INTO credentials(token, ns, pid, uid, gid, groups, umask, started, owner, expires) VALUES(?, ?, 0, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(hash),
                text(JOBS),
                int(cred.id),
                int(cred.group),
                text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
                int(umask & 0o777),
                int(now),
                text(&job_owner(id)),
                int(expires),
            ],
        );
        self.run(
            "UPDATE credentials SET generation = ? WHERE token = ?",
            vec![
                self.image.as_ref().map(|v| v.id.as_str()).into(),
                text(hash),
            ],
        );
        self.set_expiry("credential", hash, expires);
        let placement = crate::placement::container(cred.id, id);
        self.run(
            "UPDATE credentials SET placement = ? WHERE token = ?",
            vec![
                text(&serde_json::to_string(&placement).unwrap_or_default()),
                text(hash),
            ],
        );
    }
    /// The job `id` ended: its credentials are revoked, and what it had open closes.
    pub fn revoke_job(&mut self, id: &str) {
        for row in self.rows::<Credential>(
            &format!(
                "SELECT {} FROM credentials WHERE ns = ? AND owner = ?",
                columns()
            ),
            vec![text(JOBS), text(&job_owner(id))],
        ) {
            self.clear_expiry("credential", &row.token);
        }
        self.run(
            "DELETE FROM credentials WHERE ns = ? AND owner = ?",
            vec![text(JOBS), text(&job_owner(id))],
        );
        self.end_line(JOBS, &job_owner(id));
    }
    /// The line of credentials `lineage` of `ns` has none left: what its processes opened
    /// closes, and its session of descriptors goes, numbers and all.
    fn end_line(&mut self, ns: &str, lineage: &str) {
        self.close_proc_fds(lineage);
        let session = session_of(ns, lineage);
        for fd in self.fds_of(&session) {
            crate::fds::release(self, &session, fd.fd);
        }
        self.forget_fd_numbers(&session);
        self.forget_controller(lineage);
    }
    /// Keep the descriptors of every process line of the namespace `ns` (its pages were heard
    /// from, which host its processes).
    pub fn renew_lines(&mut self, ns: &str, now: u64) {
        #[derive(Deserialize)]
        struct Line {
            owner: String,
        }
        let lines = self.rows::<Line>(
            &format!("SELECT DISTINCT {OWNER} AS owner FROM credentials WHERE ns = ?"),
            vec![text(ns)],
        );
        for line in lines {
            crate::fds::renew(self, &session_of(ns, &line.owner), now);
        }
    }
    /// The credentials whose token's hash is `hash`, in `ns`.
    fn credential_of(&self, hash: &str, ns: &str) -> Option<Credential> {
        self.rows::<Credential>(
            &format!(
                "SELECT {} FROM credentials WHERE token = ? AND ns = ? AND expires > ?",
                columns()
            ),
            vec![text(hash), text(ns), int(auth::now())],
        )
        .into_iter()
        .next()
    }
    pub fn expire_credential(&mut self, hash: &str, now: u64) {
        let expired = self.rows::<Credential>(
            &format!(
                "SELECT {} FROM credentials WHERE token = ? AND expires <= ?",
                columns()
            ),
            vec![text(hash), int(now)],
        );
        for row in expired {
            self.revoke(&row.ns, hash);
        }
        self.clear_expiry("credential", hash);
    }
    /// Revoke the credentials whose token's hash is `hash`: its image's descriptor closes, and
    /// what its processes opened, once no image of theirs holds the credentials still.
    pub fn revoke(&mut self, ns: &str, hash: &str) {
        self.clear_expiry("credential", hash);
        let found = self.rows::<Credential>(
            &format!(
                "DELETE FROM credentials WHERE token = ? AND ns = ? RETURNING {}",
                columns()
            ),
            vec![text(hash), text(ns)],
        );
        for credential in found {
            self.close_exec_fds(&credential.image());
            let held = !self
                .rows::<Credential>(
                    &format!(
                        "SELECT {} FROM credentials WHERE ns = ? AND {OWNER} = ? LIMIT 1",
                        columns()
                    ),
                    vec![text(ns), text(&credential.owner())],
                )
                .is_empty();
            if !held {
                self.end_line(ns, &credential.owner());
            }
        }
    }
}

/// One execve the registry asks the authority about.
#[derive(Deserialize)]
struct Asked {
    #[serde(default)]
    local: Option<abi::LocalExecutable>,
    pid: u32,
    /// The hash of the token its process will carry.
    token: String,
    path: String,
    cwd: String,
    #[serde(default)]
    seat: Option<String>,
    #[serde(default)]
    cgroup: Option<String>,
    #[serde(default)]
    generation: Option<String>,
    /// The account of the process it replaces, if any: only that account, or root, may.
    #[serde(default)]
    replacing: Option<u32>,
    /// The hash of the token the replaced image held, which dies with it.
    #[serde(default)]
    old: Option<String>,
    /// The hash of the token the replacing process proved itself with (the registry checked
    /// it): the credentials the new image keeps, and the descriptors it keeps open.
    #[serde(default)]
    current: Option<String>,
}

#[derive(Deserialize)]
struct Execs {
    ns: String,
    #[serde(default)]
    sudo: bool,
    #[serde(default = "umask")]
    umask: u16,
    execs: Vec<Asked>,
    /// Tokens whose processes are gone, which the registry was still to revoke.
    #[serde(default)]
    revoke: Vec<String>,
}
fn umask() -> u16 {
    0o022
}

/// What an execve gives: the credentials snapshotted, and how the loader reads the image.
#[derive(Serialize)]
struct Image {
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<abi::LocalExecutable>,
    login: Option<crate::login::Context>,
    uid: u32,
    gid: u32,
    groups: BTreeSet<u32>,
    umask: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    fd: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asset: Option<String>,
    path: String,
    size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_read: Option<String>,
    version: String,
}

/// The internal requests the registry makes, as the Worker's routes are: `None` when
/// `endpoint` is none of them.
pub async fn internal(req: &mut Request, state: &State, endpoint: &str) -> Result<Option<Reply>> {
    let key = auth::token_key(req);
    let guest = auth::guest_key(req);
    Ok(Some(match endpoint {
        "/internal/exec" => {
            let Ok(asked) = req.json::<Execs>().await else {
                return Ok(Some(Reply::error("Invalid execve request", 400)));
            };
            let now = auth::now();
            let ns = asked.ns.clone();
            let revoke = asked.revoke;
            transact(state, move |db| {
                for hash in &revoke {
                    db.revoke(&ns, hash);
                }
                ((), true)
            })?;
            let mut results = Vec::with_capacity(asked.execs.len());
            for one in asked.execs {
                let (key, guest, ns) = (key.clone(), guest.clone(), asked.ns.clone());
                let (sudo, umask) = (asked.sudo, asked.umask & 0o777);
                let result = transact(state, move |db| {
                    let result = exec(
                        db,
                        key.as_deref(),
                        guest.as_deref(),
                        &ns,
                        sudo,
                        umask,
                        one,
                        now,
                    );
                    let commit = result.is_ok();
                    (
                        match result {
                            Ok(value) => Return::Ok(value),
                            Err(error) => Return::Err(error),
                        },
                        commit,
                    )
                })?;
                results.push(result);
            }
            Reply::ok(json!({ "results": results }))
        }
        // The caller's credentials, as a page's batch acts (root under sudo, if it may).
        "/internal/identity" => {
            #[derive(Deserialize)]
            struct Asked {
                #[serde(default)]
                sudo: bool,
            }
            let sudo = req
                .json::<Asked>()
                .await
                .map(|asked| asked.sudo)
                .unwrap_or(false);
            transact(state, move |db| {
                let reply = match crate::sys::caller(db, key.as_deref(), guest.as_deref(), sudo) {
                    Ok(cred) => Reply::ok(json!(cred)),
                    Err(error) => crate::api::errno_reply(&error),
                };
                (reply, true)
            })?
        }
        "/internal/login" => transact(state, move |db| {
            let context = login_context(db, key.as_deref(), guest.as_deref());
            let reply = match context {
                Some(context) => Reply::ok(json!(context)),
                None => crate::api::errno_reply(&Errno::EACCES.into()),
            };
            (reply, true)
        })?,
        "/internal/revoke" => {
            #[derive(Deserialize)]
            struct Asked {
                ns: String,
                tokens: Vec<String>,
                #[serde(default)]
                renew: Vec<String>,
            }
            let Ok(asked) = req.json::<Asked>().await else {
                return Ok(Some(Reply::error("Invalid revocation", 400)));
            };
            transact(state, move |db| {
                for hash in &asked.renew {
                    // Expiry and revocation are final: a late heartbeat cannot revive a token.
                    if db.credential_of(hash, &asked.ns).is_some() {
                        let deadline = auth::now() + abi::PROCESS_TOKEN_TTL;
                        db.run(
                            "UPDATE credentials SET expires = ? WHERE ns = ? AND token = ?",
                            vec![int(deadline), text(&asked.ns), text(hash)],
                        );
                        db.set_expiry("credential", hash, deadline);
                    }
                }
                for hash in &asked.tokens {
                    db.revoke(&asked.ns, hash);
                }
                (Reply::ok(Value::Null), true)
            })?
        }
        // What the pages of a browser are to hear: a signal to a process one of its tabs runs.
        "/internal/tell" => {
            #[derive(Deserialize)]
            struct Asked {
                ns: String,
                value: Value,
            }
            let Ok(asked) = req.json::<Asked>().await else {
                return Ok(Some(Reply::error("Invalid message", 400)));
            };
            transact(state, move |db| {
                db.tell(crate::db::Told::Namespace(asked.ns), asked.value);
                (Reply::ok(Value::Null), true)
            })?
        }
        _ => return Ok(None),
    }))
}

/// execve(2), as the authority decides it: the caller (root under sudo, if it may) for a new
/// process, the process's own credentials for one replacing its image; the image (a regular,
/// whole file it may execute: X, not R); how the loader reads it (the build's asset for /usr, a
/// descriptor of the process's own for an uploaded one); and the credentials its process
/// carries from now on.
#[allow(clippy::too_many_arguments)]
fn exec(
    db: &mut Db,
    key: Option<&str>,
    guest: Option<&str>,
    ns: &str,
    sudo: bool,
    umask: u16,
    asked: Asked,
    now: u64,
) -> std::result::Result<Value, Error> {
    // A process replacing its image keeps its credentials, as execve keeps them (there is no
    // setuid), and its open descriptors; a new process is the caller's.
    let current = match &asked.current {
        Some(hash) => Some(db.credential_of(hash, ns).ok_or(Errno::ESRCH)?),
        None => None,
    };
    let (cred, umask) = match &current {
        Some(current) => (current.identity(), current.umask),
        None => (crate::sys::caller(db, key, guest, sudo)?, umask),
    };
    // Only one's own process may be replaced (root's any).
    if current.is_none()
        && asked
            .replacing
            .is_some_and(|uid| cred.id != 0 && uid != cred.id)
    {
        return Err(Errno::EPERM.into());
    }
    let generation = current
        .as_ref()
        .map(|c| c.generation.clone())
        .unwrap_or(asked.generation)
        .filter(|g| g != "legacy");
    crate::system::select(db, generation.as_deref())?;
    let cwd = asked.cwd;
    let path = if asked.path.starts_with('/') {
        asked.path
    } else if cwd == "/" {
        format!("/{}", asked.path)
    } else {
        format!("{}/{}", cwd.trim_end_matches('/'), asked.path)
    };
    let mut local = asked.local;
    if let Some(image) = &mut local {
        if !image.valid() || !path.starts_with('/') || path.len() > 4096 || path.contains('\0') {
            return Err(Errno::EINVAL.into());
        }
        if sudo && current.is_none() {
            return Err(Errno::EPERM.into());
        }
        // Exec may attenuate an existing delegation, never enlarge it.
        image.cloud &= current.as_ref().is_none_or(|c| c.cloud_access != 0);
    } else if let Some(current) = &current {
        current.cloud()?;
    }
    let executable = if local.is_some() {
        None
    } else {
        Some(kernel::executable(&*db, &cred, &path)?)
    };
    if executable.as_ref().is_some_and(|e| e.node.size > EXEC_MAX) {
        return Err(Error::because(
            Errno::E2BIG,
            format!("{path} is larger than an executable may be"),
        ));
    }
    // The image: a binary of /usr, or any file whose content is one (a FICLONE copy or a hard
    // link of /usr/bin/coreutils), is the build's asset; anything else is uploaded, and the
    // loader reads it by a token of the process's own descriptor, revalidated with the X rule.
    let asset = executable
        .as_ref()
        .and_then(|e| crate::system::asset(&e.content));
    if executable
        .as_ref()
        .is_some_and(|e| crate::system::owns(db, &e.path))
        && asset.is_none()
    {
        return Err(Error::because(
            Errno::ENOEXEC,
            format!("{path} is not an executable image"),
        ));
    }
    let lineage = current
        .as_ref()
        .map_or_else(|| owner(ns, asked.pid, &asked.token), Credential::owner);
    let controller = match &current {
        Some(c) => db.controller(&c.owner()).unwrap_or(c.uid),
        None => auth::identity_of(db, key, guest).id,
    };
    db.set_controller(&lineage, controller);
    // The image's descriptor is kept in its process's line's session, as what it opens is.
    let sid = session_of(ns, &lineage);
    db.run(
        "INSERT OR REPLACE INTO credentials(token, ns, pid, uid, gid, groups, umask, started, owner, expires) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            text(&asked.token),
            text(ns),
            int(asked.pid),
            int(cred.id),
            int(cred.group),
            text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
            int(umask),
            int(now),
            text(&lineage),
            int(now + abi::PROCESS_TOKEN_TTL),
        ],
    );
    db.run(
        "UPDATE credentials SET generation = ?, cloud_access = ? WHERE token = ?",
        vec![
            generation.as_deref().into(),
            int(u8::from(local.as_ref().is_none_or(|l| l.cloud))),
            text(&asked.token),
        ],
    );
    db.set_expiry("credential", &asked.token, now + abi::PROCESS_TOKEN_TTL);
    let placement = crate::placement::browser(
        ns,
        cred.id,
        asked.seat.as_deref(),
        asked.cgroup.as_deref().unwrap_or("/user"),
    );
    db.run(
        "UPDATE credentials SET placement = ? WHERE token = ?",
        vec![
            text(&serde_json::to_string(&placement).unwrap_or_default()),
            text(&asked.token),
        ],
    );
    // The image the process ran before is replaced: its token and its image's descriptor die
    // with the exec, not only when the process ends; what it opened stays open for the new one.
    if let Some(old) = &asked.old {
        db.revoke(ns, old);
    }
    // The new image's own descriptor is its exec's alone.
    let owner = owner(ns, asked.pid, &asked.token);
    let (fd, token_read, size, version, path) = match executable {
        Some(executable) if asset.is_none() => {
            let read = auth::random_token();
            let fd = db.add_exec_fd(
                &sid,
                &executable.content,
                &executable.path,
                &owner,
                &auth::token_hash(&read),
                now,
            );
            (
                Some(fd),
                Some(read),
                executable.node.size,
                executable.content,
                executable.path,
            )
        }
        // A binary of /usr is as large as the build's (`usr::size` takes its content id).
        Some(executable) => (
            None,
            None,
            crate::system::size(&executable.content),
            executable.content,
            executable.path,
        ),
        None => {
            let image = local.as_ref().ok_or(Errno::EINVAL)?;
            (
                None,
                None,
                image.size,
                format!("local:{}", image.digest),
                path,
            )
        }
    };
    Ok(json!(Image {
        local,
        login: if current.is_none() {
            login_context(db, key, guest)
        } else {
            None
        },
        uid: cred.id,
        gid: cred.group,
        groups: cred.groups.clone(),
        umask,
        fd,
        asset,
        path,
        size,
        token_read,
        version,
    }))
}

// Authenticated login provenance is internal registry metadata, never supplied by a page.
fn login_context(
    db: &mut Db,
    key: Option<&str>,
    guest: Option<&str>,
) -> Option<crate::login::Context> {
    use os_core::permissions::Store;
    let uid = auth::identity_of(db, key, guest).id;
    auth::sid(db, key, guest).map(|binding| {
        let expires = key
            .and_then(|key| db.session(key))
            .filter(|session| session.user == uid && session.expires > auth::now())
            .map_or(auth::now() + 24 * 60 * 60, |session| session.expires);
        crate::login::Context {
            binding,
            uid,
            expires,
        }
    })
}
