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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use terminal_worker_core::permissions::Identity;
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
}
impl Credential {
    pub fn identity(&self) -> Identity {
        Identity {
            id: self.uid,
            group: self.gid,
            groups: serde_json::from_str(&self.groups)
                .unwrap_or_else(|_| BTreeSet::from([self.gid])),
        }
    }
    /// The key its descriptors are owned by (fds.rs): its process's, and its forks', but not
    /// those of another image the process executed later while a fork kept this one.
    pub fn owner(&self) -> String {
        owner(&self.ns, self.pid, &self.token)
    }
}

/// The key the descriptors of the credentials of token hash `token`, executed as `pid` of
/// `ns`, are owned by.
fn owner(ns: &str, pid: u32, token: &str) -> String {
    format!("{ns} {pid} {}", token.get(..16).unwrap_or(token))
}

impl Db {
    /// The credentials the token `token` carries, in namespace `ns`, while it is not revoked.
    pub fn credential(&self, token: &str, ns: &str) -> Option<Credential> {
        self.rows::<Credential>(
            "SELECT token, ns, pid, uid, gid, groups, umask FROM credentials WHERE token = ? AND ns = ?",
            vec![text(&auth::token_hash(token)), text(ns)],
        )
        .into_iter()
        .next()
    }
    /// Revoke the credentials whose token's hash is `hash`: what its processes opened closes.
    pub fn revoke(&mut self, ns: &str, hash: &str) {
        let found = self.rows::<Credential>(
            "DELETE FROM credentials WHERE token = ? AND ns = ? RETURNING token, ns, pid, uid, gid, groups, umask",
            vec![text(hash), text(ns)],
        );
        for credential in found {
            self.close_proc_fds(&credential.owner());
        }
    }
}

/// One execve the registry asks the authority about.
#[derive(Deserialize)]
struct Asked {
    pid: u32,
    /// The hash of the token its process will carry.
    token: String,
    path: String,
    cwd: String,
    /// The account of the process it replaces, if any: only that account, or root, may.
    #[serde(default)]
    replacing: Option<u32>,
    /// The hash of the token the replaced image held, which dies with it.
    #[serde(default)]
    old: Option<String>,
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
        "/internal/revoke" => {
            #[derive(Deserialize)]
            struct Asked {
                ns: String,
                tokens: Vec<String>,
            }
            let Ok(asked) = req.json::<Asked>().await else {
                return Ok(Some(Reply::error("Invalid revocation", 400)));
            };
            transact(state, move |db| {
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

/// execve(2), as the authority decides it: the caller (root under sudo, if it may), the image
/// (a regular, whole file it may execute: X, not R), how the loader reads it (the build's asset
/// for /usr, a descriptor of the process's own for an uploaded one), and the credentials its
/// process carries from now on.
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
    let cred = crate::sys::caller(db, key, guest, sudo)?;
    // Only one's own process may be replaced (root's any).
    if asked
        .replacing
        .is_some_and(|uid| cred.id != 0 && uid != cred.id)
    {
        return Err(Errno::EPERM.into());
    }
    let cwd = asked.cwd;
    let path = if asked.path.starts_with('/') {
        asked.path
    } else if cwd == "/" {
        format!("/{}", asked.path)
    } else {
        format!("{}/{}", cwd.trim_end_matches('/'), asked.path)
    };
    let executable = kernel::executable(&*db, &cred, &path)?;
    if executable.node.size > EXEC_MAX {
        return Err(Error::because(
            Errno::E2BIG,
            format!("{} is larger than an executable may be", executable.path),
        ));
    }
    // The image: a binary of /usr, or any file whose content is one (a FICLONE copy or a hard
    // link of /usr/bin/coreutils), is the build's asset; anything else is uploaded, and the
    // loader reads it by a token of the process's own descriptor, revalidated with the X rule.
    let asset = crate::usr::asset(&executable.content);
    if crate::usr::is(&executable.path) && asset.is_none() {
        return Err(Error::because(
            Errno::ENOEXEC,
            format!("{} is not an executable image", executable.path),
        ));
    }
    let sid = auth::sid(db, key, guest);
    if asset.is_none() && sid.is_none() {
        return Err(Error::because(
            Errno::EBADF,
            "no session to keep descriptors",
        ));
    }
    // The image the process ran before is replaced: its credentials, descriptor and read token
    // die with the exec, not only when the process ends.
    if let Some(old) = &asked.old {
        db.revoke(ns, old);
    }
    db.run(
        "INSERT OR REPLACE INTO credentials(token, ns, pid, uid, gid, groups, umask, started) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            text(&asked.token),
            text(ns),
            int(asked.pid),
            int(cred.id),
            int(cred.group),
            text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
            int(umask),
            int(now),
        ],
    );
    let owner = owner(ns, asked.pid, &asked.token);
    let (fd, token_read, size) = match (asset, sid) {
        (None, Some(sid)) => {
            let read = auth::random_token();
            let fd = db.add_exec_fd(
                &sid,
                &executable.content,
                &executable.path,
                &owner,
                &auth::token_hash(&read),
                now,
            );
            db.set_expiry("fd", &crate::db::fd_key(&sid, fd), now + crate::fds::IDLE);
            (Some(fd), Some(read), executable.node.size)
        }
        _ => (
            None,
            None,
            asset.map_or(executable.node.size, crate::usr::size),
        ),
    };
    Ok(json!(Image {
        uid: cred.id,
        gid: cred.group,
        groups: cred.groups.clone(),
        umask,
        fd,
        asset: asset.map(str::to_string),
        path: executable.path.clone(),
        size,
        token_read,
        version: executable.content.clone(),
    }))
}
