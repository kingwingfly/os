//! The system-call entry (owner's design, 2026-10-29): `POST /api/sys` takes a batch of calls
//! (abi::Batch) from user space, the page, and runs each as its session's account (root under
//! sudo), in order, in a transaction of its own, as separate system calls are: one that fails
//! changes nothing and stops nothing. What the calls do is the kernel's (crates/kernel), over
//! the authority's SQLite.
use crate::api::Reply;
use crate::auth;
use crate::creds::Credential;
use crate::db::{Db, transact};
use abi::{BATCH_MAX, Batch, Call, Creds, Data, Errno, Error, FdRef, INLINE_MAX, Results, Return};
use kernel::Process;
use os_core::permissions::*;
use serde_json::json;
use std::rc::Rc;
use worker::*;

pub async fn handle(
    req: &mut Request,
    env: &Env,
    state: &State,
    key: Option<String>,
) -> Result<Reply> {
    let content = req.headers().get("Content-Length")?;
    if content
        .and_then(|length| length.parse::<u64>().ok())
        .is_none_or(|length| length > abi::BATCH_BYTES)
    {
        return Ok(Reply::error(
            "A batch says its length, and is at most 4 MB",
            400,
        ));
    }
    let Ok(batch) = req.json::<Batch>().await else {
        return Ok(Reply::error("Invalid system call batch", 400));
    };
    let https = req.url()?.scheme() == "https";
    // The session's cookie, as a login, logout or password change made it anew.
    let mut cookie = None;
    if batch.calls.len() > BATCH_MAX {
        return Ok(Reply::error(
            &format!("A batch takes at most {BATCH_MAX} calls"),
            400,
        ));
    }
    let guest = auth::guest_key(req);
    // As whom each call is made: the page's session, or the process the batch names.
    let session = Rc::new(Session {
        key: key.clone(),
        guest: guest.clone(),
        sudo: batch.sudo,
        umask: batch.umask.map(|mask| mask & 0o777),
        pid: batch.pid,
        token: batch.process.clone(),
        release: req.headers().get("X-OS-Release")?,
    });
    // The session was heard from: its descriptors are kept (a process's, its line's), and a
    // page's keeps those of the processes its tabs run, whatever account they run as.
    let renewing = session.clone();
    let count = batch.calls.len() as u64;
    transact(state, move |db| {
        db.observe("syscalls", count);
        let Ok(acting) = renewing.of(db) else {
            return ((), false);
        };
        let Some(sid) = acting.sid.filter(|sid| heard(sid)) else {
            return ((), false);
        };
        let now = auth::now();
        crate::fds::renew(db, &sid, now);
        if acting.credential.is_none() {
            db.renew_lines(&renewing.namespace(), now);
        }
        ((), true)
    })?;
    let mut results = Vec::with_capacity(batch.calls.len());
    let mut calls = batch.calls.into_iter().peekable();
    while let Some(mut call) = calls.next() {
        // The process registry's calls are the browser's machine's (machine.rs): those in a row
        // go there at once, with the caller found here.
        if call.is_registry() && session.token.is_some() {
            let checking = session.clone();
            let remote = transact(state, move |db| {
                (
                    checking
                        .of(db)
                        .ok()
                        .and_then(|a| a.credential)
                        .and_then(|c| c.job())
                        .is_some(),
                    false,
                )
            })?;
            if remote {
                results.push(Return::Err(Errno::EPERM.into()));
                continue;
            }
        }
        if call.is_registry() {
            let mut registry = vec![call];
            while calls.peek().is_some_and(Call::is_registry) {
                registry.extend(calls.next());
            }
            let cookie = req.headers().get("Cookie")?;
            results.extend(crate::machine::forward(env, state, &session, cookie, registry).await?);
            continue;
        }
        if let Err(error) = resolve(&mut call, &results) {
            results.push(Return::Err(error));
            continue;
        }
        // Bytes that go with the call move to or from R2 outside a transaction.
        if matches!(call, Call::Pread { .. } | Call::Pwrite { .. }) {
            results.push(match bytes(env, state, session.clone(), call).await {
                Ok(value) => Return::Ok(value),
                Err(error) => Return::Err(error),
            });
            continue;
        }
        // What takes a password (its KDF, and a rate limit) waits outside a transaction too,
        // and may give the session a new cookie. A process token cannot touch the session.
        if let Some(asked) = passworded(&call, session.sudo) {
            if session.token.is_some() {
                results.push(Return::Err(Error::because(
                    Errno::EPERM,
                    "a process cannot sign the browser in or out",
                )));
                continue;
            }
            let reply = asked.run(req, env, state, key.clone(), https).await?;
            if let Some(made) = &reply.cookie {
                cookie = Some(made.clone());
            }
            results.push(returned(reply));
            continue;
        }
        if let Call::Ioctl { fd, request, arg } = &call
            && *request == crate::system::CONTROL
            && arg["op"] == "stage"
        {
            results.push(
                match crate::system::stage(env, state, session.clone(), fd.number(), arg.clone())
                    .await
                {
                    Ok(value) => Return::Ok(value),
                    Err(error) => Return::Err(error),
                },
            );
            continue;
        }
        // A driver's request that asks Realtime waits for the network outside a transaction.
        if let Call::Ioctl { fd, request, arg } = &call
            && crate::dev::networked(*request)
        {
            let asked = Asked {
                session: session.clone(),
                fd: fd.number(),
                op: *request,
                arg: arg.clone(),
            };
            results.push(match networked(req, env, state, asked).await {
                Ok(value) => Return::Ok(value),
                Err(error) => Return::Err(error),
            });
            continue;
        }
        let logout = matches!(call, Call::Logout);
        // A remote task signalled: its runner wakes. A numeric pid is a registry process's,
        // which has no runner.
        let wakes = match &call {
            Call::Kill { pid, .. } if matches!(abi::Target::of(pid), abi::Target::Job(_)) => {
                Some(pid.clone())
            }
            _ => None,
        };
        // A listing or file of /proc tells of the browser's processes, as its machine has them.
        let procs = if lists_processes(&mut call) {
            crate::machine::list(env, &session.namespace()).await?
        } else {
            Vec::new()
        };
        let asking = session.clone();
        let result = transact(state, move |db| {
            // A descriptor call stands as it ends, failed or not: a close that fails closes.
            let descriptors = matches!(
                call,
                Call::Open { .. } | Call::Close { .. } | Call::Discard { .. } | Call::Ioctl { .. }
            );
            let result = asking
                .of(db)
                .and_then(|acting| run(db, &asking, &acting, &procs, call));
            let commit = result.is_ok() || descriptors;
            let result = match result {
                Ok(value) => Return::Ok(value),
                Err(error) => Return::Err(error),
            };
            (result, commit)
        })?;
        if logout && matches!(result, Return::Ok(_)) {
            cookie = Some(auth::cookie(https, "", 0));
        }
        let mut result = result;
        // A driver's private executor envelope never crosses the public syscall boundary.
        if let Return::Ok(value) = &mut result
            && let Some(launch) = value
                .as_object_mut()
                .and_then(|value| value.remove("_launch"))
        {
            let spawned = launch["token"].as_str().is_some();
            if !crate::api::kick(env, &launch).await && spawned {
                let id = launch["job"].as_str().unwrap_or_default().to_string();
                transact(state, move |db| {
                    db.add_lines(&id, &[(true, "The executor could not be started".into())]);
                    crate::executor::finish(db, &id, "failed");
                    ((), true)
                })?;
            }
        }
        if let (Some(pid), Return::Ok(value)) = (wakes, &mut result) {
            let pid = value["pid"].as_str().map(str::to_string).unwrap_or(pid);
            crate::api::kick(env, &json!({ "job": pid })).await;
        }
        results.push(result);
    }
    let reply = Reply::ok(json!(Results { results }));
    Ok(match cookie {
        Some(cookie) => reply.cookie(cookie),
        None => reply,
    })
}

thread_local! {
    /// When each session's descriptors were last kept, by this instance.
    static HEARD: std::cell::RefCell<std::collections::HashMap<String, u64>> = Default::default();
}
/// Whether the session `sid`'s descriptors are to be kept now: at most every few seconds, as a
/// page that holds some says something every few.
fn heard(sid: &str) -> bool {
    const EVERY: u64 = 5;
    let now = auth::now();
    HEARD.with(|heard| {
        let mut heard = heard.borrow_mut();
        if heard.get(sid).is_some_and(|at| now < at + EVERY) {
            return false;
        }
        if heard.len() > 4096 {
            heard.retain(|_, at| now < *at + EVERY);
        }
        heard.insert(sid.to_string(), now);
        true
    })
}

/// Make the descriptors `call` names by reference (`{"ref": i}`) those the calls before it
/// opened: a reference to one that failed fails as it did.
fn resolve(call: &mut Call, results: &[Return]) -> std::result::Result<(), Error> {
    let fd = match call {
        Call::Close { fd }
        | Call::Discard { fd }
        | Call::Fchmod { fd, .. }
        | Call::Ioctl { fd, .. }
        | Call::Pwrite { fd, .. }
        | Call::Pread { fd: Some(fd), .. } => fd,
        _ => return Ok(()),
    };
    if let FdRef::Ref { call: index } = *fd {
        let opened = match results.get(index) {
            Some(Return::Ok(value)) => value["fd"]
                .as_u64()
                .and_then(|fd| u32::try_from(fd).ok())
                .ok_or(Errno::EBADF)?,
            Some(Return::Err(error)) => return Err(error.clone()),
            None => {
                return Err(Error::because(
                    Errno::EINVAL,
                    "a call refers only to those before it",
                ));
            }
        };
        *fd = FdRef::Fd(opened);
    }
    Ok(())
}

/// The process a batch runs as, before a transaction finds its account.
pub struct Session {
    pub key: Option<String>,
    pub guest: Option<String>,
    pub sudo: bool,
    pub umask: Option<u16>,
    pub pid: Option<u32>,
    pub token: Option<String>,
    pub release: Option<String>,
}

/// As whom a call acts, once a transaction found it: its process (credentials and umask), the
/// session its descriptors are in, and, a process calling, its exec's credentials.
pub struct Acting {
    pub process: Process,
    pub sid: Option<String>,
    pub credential: Option<Credential>,
}
impl Acting {
    /// The key a process's own descriptors answer to (fds::owned): its line's; none for a page.
    pub fn owner(&self) -> Option<String> {
        self.credential.as_ref().map(Credential::owner)
    }
}

impl Session {
    /// The browser's process namespace.
    pub fn namespace(&self) -> String {
        Db::namespace(self.key.as_deref(), self.guest.as_deref())
    }
    /// As whom its calls act, as the store `db` knows it: a process token runs as the
    /// process's snapshot, never as the page signed in later; a page's batch as the session's
    /// account (root under sudo, if it may). A token that names no process is EPERM, never
    /// taken for the page's.
    pub(crate) fn of(&self, db: &mut Db) -> std::result::Result<Acting, Error> {
        let (process, credential) = match self.token.as_deref() {
            Some(token) => {
                let credential = db
                    .credential(token, &self.namespace())
                    .ok_or_else(|| Error::because(Errno::EPERM, "not this process's token"))?;
                (
                    Process {
                        cred: credential.identity(),
                        // The runtime owns its mutable creation mask. Identity still comes
                        // only from the authenticated credential snapshot. Omitted masks
                        // retain that snapshot (including archive runner requests).
                        umask: self.umask.unwrap_or(credential.umask),
                    },
                    Some(credential),
                )
            }
            None => (
                process(
                    db,
                    self.key.as_deref(),
                    self.guest.as_deref(),
                    self.sudo,
                    self.umask.unwrap_or(0o022),
                )?,
                None,
            ),
        };
        let release = credential
            .as_ref()
            .map(|c| c.generation.as_deref())
            .unwrap_or(self.release.as_deref());
        crate::system::select(db, release)?;
        let sid = crate::creds::sid_of(
            db,
            self.key.as_deref(),
            self.guest.as_deref(),
            credential.as_ref(),
        );
        Ok(Acting {
            process,
            sid,
            credential,
        })
    }
}

/// pread and pwrite of bytes a batch carries: decided in a transaction, moved to or from R2
/// outside one, and, written, recorded in another.
/// `length` bytes of the build's asset `asset` from `offset` (a binary of /usr), as the assets
/// give them: the range, or all of it, cut to the range.
async fn asset_range(env: &Env, asset: &str, offset: u64, length: u64) -> Sys<Vec<u8>> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let io = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
    let headers = Headers::new();
    headers
        .set("Range", &format!("bytes={offset}-{}", offset + length - 1))
        .map_err(io)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let request = Request::new_with_init(&format!("https://assets{asset}"), &init).map_err(io)?;
    let mut response = if asset.starts_with("/boot/blobs/") {
        crate::system::checked_asset(request, env)
            .await
            .map_err(io)?
    } else {
        env.assets("ASSETS")
            .map_err(io)?
            .fetch_request(request)
            .await
            .map_err(io)?
    };
    if !matches!(response.status_code(), 200 | 206) {
        return Err(Errno::EIO.into());
    }
    let body = response.bytes().await.map_err(io)?;
    if response.status_code() == 206 {
        return Ok(body);
    }
    let start = usize::try_from(offset).map_or(body.len(), |offset| offset.min(body.len()));
    let end = start
        .saturating_add(usize::try_from(length).unwrap_or(usize::MAX))
        .min(body.len());
    Ok(body[start..end].to_vec())
}

async fn bytes(
    env: &Env,
    state: &State,
    session: Rc<Session>,
    call: Call,
) -> Sys<serde_json::Value> {
    let io = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
    let too_many = || {
        Error::because(
            Errno::EINVAL,
            format!("a batch carries at most {INLINE_MAX} bytes a call"),
        )
    };
    let requested = match &call {
        Call::Pread { count, .. } => ("read_bytes_requested", *count),
        Call::Pwrite { data, .. } => ("write_base64_bytes_requested", data.len() as u64),
        _ => ("bytes", 0),
    };
    transact(state, move |db| {
        db.observe(requested.0, requested.1);
        ((), true)
    })
    .map_err(io)?;
    match call {
        Call::Pread {
            fd,
            path,
            offset,
            count,
        } => {
            if count > INLINE_MAX {
                return Err(too_many());
            }
            // A file of /proc that tells of processes is read again with its machine's list.
            let mut procs: Option<Rc<Vec<crate::procs::Row>>> = None;
            let read = loop {
                let (asking, path, listed) = (session.clone(), path.clone(), procs.clone());
                let read = transact(state, move |db| {
                    let read = asking.of(db).and_then(|acting| {
                        if acting.credential.as_ref().and_then(|c| c.job()).is_some() {
                            return Err(Errno::EPERM.into());
                        }
                        crate::fds::pread(
                            db,
                            acting.sid.as_deref(),
                            listed.as_deref().map(Vec::as_slice),
                            &acting.process,
                            fd.map(FdRef::number),
                            path.as_deref(),
                            offset,
                            count,
                            acting.owner().as_deref(),
                        )
                    });
                    (read, false)
                })
                .map_err(io)??;
                if !matches!(read, crate::fds::Read::Processes) || procs.is_some() {
                    break read;
                }
                procs = Some(Rc::new(
                    crate::machine::list(env, &session.namespace())
                        .await
                        .map_err(io)?,
                ));
            };
            let (data, size) = match read {
                crate::fds::Read::Bytes(data, size) => (data, size),
                crate::fds::Read::Chunks(parts, size) => {
                    crate::resources::session_io(
                        env,
                        state,
                        session.clone(),
                        false,
                        parts.iter().map(|(_, _, length)| *length).sum(),
                    )
                    .await?;
                    let bucket = env.bucket("FILES").map_err(io)?;
                    let mut data = Vec::new();
                    for (key, offset, length) in parts {
                        let object = bucket
                            .get(&key)
                            .range(Range::OffsetWithLength { offset, length })
                            .execute()
                            .await
                            .map_err(io)?
                            .ok_or(Errno::EIO)?;
                        let body = object.body().ok_or(Errno::EIO)?;
                        data.extend(body.bytes().await.map_err(io)?);
                    }
                    (data, size)
                }
                crate::fds::Read::Asset(asset, offset, length, size) => {
                    crate::resources::session_io(env, state, session.clone(), false, length)
                        .await?;
                    (asset_range(env, &asset, offset, length).await?, size)
                }
                crate::fds::Read::Processes => return Err(Errno::EIO.into()),
            };
            Ok(json!(Data {
                data: data.into(),
                size
            }))
        }
        Call::Pwrite { fd, index, data } => {
            let length = data.len() as u64;
            if length > INLINE_MAX {
                return Err(too_many());
            }
            let fd = fd.number();
            let asking = session.clone();
            let target = transact(state, move |db| {
                let target = asking.of(db).and_then(|acting| {
                    let sid = acting.sid.as_deref().ok_or(Errno::EBADF)?;
                    crate::fds::pwrite(
                        db,
                        sid,
                        &acting.process.cred,
                        fd,
                        index,
                        length,
                        acting.owner().as_deref(),
                    )
                });
                let commit = target.is_ok();
                (target, commit)
            })
            .map_err(io)??;
            let Some((object, mime)) = target else {
                return Ok(json!({ "written": length }));
            };
            crate::resources::session_io(env, state, session.clone(), true, length).await?;
            env.bucket("FILES")
                .map_err(io)?
                .put(&object, data.0)
                .http_metadata(HttpMetadata {
                    content_type: Some(mime),
                    ..Default::default()
                })
                .execute()
                .await
                .map_err(io)?;
            transact(state, move |db| {
                let written = session.of(db).and_then(|acting| {
                    let sid = acting.sid.clone().ok_or(Errno::EBADF)?;
                    crate::fds::written(
                        db,
                        &sid,
                        &acting.process.cred,
                        fd,
                        index,
                        &object,
                        None,
                        length,
                        acting.owner().as_deref(),
                    )
                });
                (written, true)
            })
            .map_err(io)?
        }
        _ => Err(Errno::ENOSYS.into()),
    }
}

/// A call that takes a password, as the kernel's handlers of them take it (api.rs).
enum Passworded {
    Login(serde_json::Value),
    Sudo(serde_json::Value),
    Passwd(serde_json::Value),
    Register(serde_json::Value),
    Unregister(serde_json::Value),
}
fn passworded(call: &Call, sudo: bool) -> Option<Passworded> {
    Some(match call {
        // sudo -u, root's, and root's own switch need no password.
        Call::Login { username, password } => Passworded::Login(
            json!({ "username": username, "password": password, "sudo": sudo, "switch": true }),
        ),
        Call::Sudo { password, revoke } => {
            Passworded::Sudo(json!({ "password": password, "revoke": revoke }))
        }
        Call::Passwd {
            username,
            password,
            current_password,
            force,
        } => Passworded::Passwd(json!({
            "username": username, "password": password,
            "current_password": current_password.clone().unwrap_or_default(),
            "sudo": sudo, "force": force,
        })),
        Call::Useradd {
            name,
            create_home,
            password: Some(password),
            short_password,
            ..
        } => Passworded::Register(json!({
            "username": name, "password": password, "short_password": short_password,
            "create_home": create_home,
        })),
        Call::Userdel {
            remove,
            password: Some(password),
            ..
        } => Passworded::Unregister(json!({ "password": password, "remove": remove })),
        _ => return None,
    })
}
impl Passworded {
    async fn run(
        self,
        req: &Request,
        env: &Env,
        state: &State,
        key: Option<String>,
        https: bool,
    ) -> Result<Reply> {
        use crate::api;
        match self {
            Self::Login(body) => api::login(req, env, state, key, https, body).await,
            Self::Sudo(body) => api::sudo(req, env, state, key, body).await,
            Self::Passwd(body) => api::passwd(req, env, state, key, https, body).await,
            Self::Register(body) => api::register(req, env, state, key, https, body).await,
            Self::Unregister(body) => api::unregister(req, env, state, key, https, body).await,
        }
    }
}

/// A handler's reply, as a call's result: its value, or an errno its status says, with its
/// words.
fn returned(reply: Reply) -> Return {
    if reply.status < 300 {
        return Return::Ok(reply.body);
    }
    let errno = match reply.status {
        401 => Errno::EACCES,
        403 => Errno::EPERM,
        404 => Errno::ENOENT,
        409 => Errno::EEXIST,
        412 => Errno::ESTALE,
        413 => Errno::EFBIG,
        429 => Errno::EAGAIN,
        500.. => Errno::EIO,
        _ => Errno::EINVAL,
    };
    let detail = reply.body["error"]
        .as_str()
        .unwrap_or(errno.text())
        .to_string();
    Return::Err(Error::because(errno, detail))
}

/// The process a page's session runs as: its account, root under sudo if it may. A signed-out
/// browser is its own guest account.
fn process(
    db: &mut Db,
    key: Option<&str>,
    guest: Option<&str>,
    sudo: bool,
    umask: u16,
) -> std::result::Result<Process, Error> {
    Ok(Process {
        cred: caller(db, key, guest, sudo)?,
        umask,
    })
}

/// A page's session's account, root under sudo if it may: as whom its batch acts, and whose
/// credentials an execve snapshots (creds.rs).
pub fn caller(
    db: &mut Db,
    key: Option<&str>,
    guest: Option<&str>,
    sudo: bool,
) -> std::result::Result<Identity, Error> {
    auth::elevated_of(db, key, guest, sudo).map_err(|why| {
        // Not a wheel member: never. One that has not authenticated lately: not yet. (A guest
        // is never a wheel member, so the session's own account is enough to tell.)
        let errno = if db.can_sudo(&auth::identity(db, key)) {
            Errno::EACCES
        } else {
            Errno::EPERM
        };
        Error::because(errno, why)
    })
}

/// Whose a job is: the calling process's snapshot, or the page's account without sudo (its own
/// guest account, signed out), as the tab that follows the job asks without sudo.
fn owner(
    db: &mut Db,
    key: Option<&str>,
    guest: Option<&str>,
    by_process: bool,
    process: &Process,
) -> u32 {
    if by_process {
        process.cred.id
    } else {
        auth::identity_of(db, key, guest).id
    }
}

/// The call `call`, as `acting` found it: a process's own snapshot, or the session's account
/// (signed in or not, under sudo if it asked). `procs` are the browser's processes, as its
/// machine listed them, for a call on /proc.
fn run(
    db: &mut Db,
    session: &Session,
    acting: &Acting,
    procs: &[crate::procs::Row],
    call: Call,
) -> std::result::Result<serde_json::Value, Error> {
    let (key, guest) = (session.key.as_deref(), session.guest.as_deref());
    let (process, sid, caller) = (&acting.process, acting.sid.as_deref(), &acting.credential);
    if let Some(credential) = caller {
        crate::executor::authorize(db, credential, &call)?;
    }
    // A process acts as itself: it cannot sign the browser in or out, or mint sudo.
    if caller.is_some() && matches!(call, Call::Logout) {
        return Err(Error::because(
            Errno::EPERM,
            "a process cannot change its browser's session",
        ));
    }
    // /proc/self/fd/N names what the descriptor has open; /proc is procfs's.
    let mut call = call;
    let mut proc = false;
    let writing_image = changes(&call);
    let original_view = db.image.clone();
    for (path, follow) in paths(&mut call) {
        db.image = original_view.clone();
        *path = crate::procfs::follow(db, sid, path, follow)?;
        proc |= crate::procfs::is(path);
        if writing_image
            && let Ok(name) = kernel::namei(db, &process.cred, path, follow)
            && crate::system::owns(db, &name.path)
        {
            return Err(Errno::EROFS.into());
        }
    }
    if proc {
        let opening = matches!(call, Call::Open { .. });
        let value = crate::procfs::call(db, sid, procs, &process.cred, call)?;
        // A process's open of /proc is its own descriptor, as any open of its is (fds.rs).
        if opening
            && let (Some(sid), Some(credential), Some(fd)) = (sid, &caller, value["fd"].as_u64())
        {
            db.set_fd_proc(sid, fd as u32, &credential.owner());
        }
        return Ok(value);
    }
    match call {
        Call::Statfs { path } => {
            kernel::stat(db, &process.cred, &path, true)?;
            let real = kernel::namei(db, &process.cred, &path, true)?.path;
            if crate::system::owns(db, &real) {
                return Ok(json!(crate::usr::statfs()));
            }
            Ok(json!(statfs(db)))
        }
        Call::InotifyAddWatch { path, mask } => {
            let sid = sid.ok_or(Errno::EBADF)?;
            let stat = kernel::stat(db, &process.cred, &path, true)?;
            if !stat.is_dir() {
                return Err(Error::because(
                    Errno::ENOTDIR,
                    "only a directory's changes are told",
                ));
            }
            kernel::access(db, &process.cred, &path, abi::R_OK | abi::X_OK)?;
            // The directory itself, wherever links on the way led.
            let real = kernel::namei(db, &process.cred, &path, true)?.path;
            db.add_watch(sid, &real, mask)
                .map(|wd| json!(wd))
                .ok_or_else(|| Errno::ENOSPC.into())
        }
        Call::InotifyRmWatch { wd } => {
            let sid = sid.ok_or(Errno::EBADF)?;
            if db.rm_watch(sid, wd) {
                Ok(serde_json::Value::Null)
            } else {
                Err(Errno::EINVAL.into())
            }
        }
        Call::Mknod {
            path,
            mode,
            rdev: Some(rdev),
        } => crate::dev::mknod(db, process, &path, mode, &rdev).map(|()| serde_json::Value::Null),
        Call::Logout => {
            if let Some(key) = key {
                db.delete_session(key);
            }
            Ok(json!({ "username": "guest", "home": "/" }))
        }
        call @ (Call::Useradd { .. }
        | Call::Usermod { .. }
        | Call::Userdel { .. }
        | Call::Groupadd { .. }
        | Call::Groupmod { .. }
        | Call::Groupdel { .. }) => account(db, &process.cred, call),
        Call::Getcreds => Ok(json!(creds(db, key, &process.cred))),
        call @ (Call::Kill { .. } | Call::Wait { .. }) => {
            // A job is its account's, not root's under sudo: the tab follows it, answers it and
            // cancels it without sudo, and `~` is the account's home.
            let owner = owner(db, key, guest, caller.is_some(), process);
            crate::executor::call(db, owner, process, call)
        }
        call @ (Call::Open { .. }
        | Call::Close { .. }
        | Call::Discard { .. }
        | Call::Fchmod { .. }
        | Call::Ioctl { .. }) => {
            crate::fds::call(db, sid, process, acting.owner().as_deref(), call)
        }
        call => kernel::call(db, process, call),
    }
}

/// Whether `call` names /proc's processes (not only /proc/self's descriptors).
fn lists_processes(call: &mut Call) -> bool {
    paths(call)
        .iter()
        .any(|(path, _)| crate::procfs::of_processes(path))
}

/// Whether `call` would change what it names.
fn changes(call: &Call) -> bool {
    match call {
        Call::Open { flags, .. } => {
            flags & abi::O_ACCMODE != abi::O_RDONLY || flags & abi::O_CREAT != 0
        }
        Call::Mkdir { .. }
        | Call::Mknod { .. }
        | Call::Rmdir { .. }
        | Call::Unlink { .. }
        | Call::Rename { .. }
        | Call::Link { .. }
        | Call::Symlink { .. }
        | Call::Chmod { .. }
        | Call::Chown { .. }
        | Call::Utimens { .. }
        | Call::Setxattr { .. }
        | Call::Removexattr { .. } => true,
        _ => false,
    }
}

/// The paths `call` names, each with whether it follows a link at its end.
fn paths(call: &mut Call) -> Vec<(&mut String, bool)> {
    match call {
        Call::Stat { path }
        | Call::Getdents { path, .. }
        | Call::Access { path, .. }
        | Call::Chmod { path, .. }
        | Call::Open { path, .. }
        | Call::Statfs { path }
        | Call::Pread {
            path: Some(path), ..
        } => vec![(path, true)],
        Call::Lstat { path }
        | Call::Readlink { path }
        | Call::Mkdir { path, .. }
        | Call::Mknod { path, .. }
        | Call::Rmdir { path }
        | Call::Unlink { path }
        | Call::Symlink { path, .. } => vec![(path, false)],
        Call::Rename { from, to, .. } => vec![(from, false), (to, false)],
        Call::Link { from, to, follow } => {
            let follow = *follow;
            vec![(from, follow), (to, false)]
        }
        Call::Chown { path, nofollow, .. }
        | Call::Utimens { path, nofollow, .. }
        | Call::Getxattr { path, nofollow, .. }
        | Call::Setxattr { path, nofollow, .. }
        | Call::Listxattr { path, nofollow }
        | Call::Removexattr { path, nofollow, .. } => {
            let follow = !*nofollow;
            vec![(path, follow)]
        }
        _ => Vec::new(),
    }
}

/// What statfs(2) tells of the store: blocks of 4 KiB, as many used as its files take, and, as
/// R2 holds as much as it is given, a petabyte free.
fn statfs(db: &Db) -> abi::StatFs {
    const BLOCK: u64 = 4096;
    const FREE: u64 = (1 << 50) / BLOCK;
    let (used, inodes) = db.usage();
    abi::StatFs {
        bsize: BLOCK,
        blocks: used.div_ceil(BLOCK) + FREE,
        bfree: FREE,
        bavail: FREE,
        files: inodes + FREE,
        ffree: FREE,
        namelen: abi::NAME_MAX as u64,
    }
}

/// The files the kernel writes as they are read, as /proc's are: /etc/passwd and /etc/group,
/// what libc's getpwnam and getgrnam read, which user space's programs do to name accounts.
pub fn generated(db: &Db, path: &str) -> Option<String> {
    // Every read of a path asks this: the accounts are looked up only for the two files made
    // of them, and the guests for /etc/passwd alone.
    if !matches!(path, "/etc/passwd" | "/etc/group") {
        return None;
    }
    let mut users = db.users();
    users.sort_by_key(|(_, user)| user.id);
    match path {
        "/etc/passwd" => {
            let mut text: String = users
                .iter()
                .map(|(name, user)| {
                    format!(
                        "{name}:x:{}:{}::{}:/bin/sh\n",
                        user.id, user.group, user.home
                    )
                })
                .collect();
            for guest in db.guests() {
                text.push_str(&format!(
                    "{}:x:{}:{}::/guest:/bin/sh\n",
                    guest.name(),
                    guest.uid,
                    guest.gid
                ));
            }
            Some(text)
        }
        "/etc/group" => {
            let mut groups = db.groups();
            groups.sort_by_key(|(_, id)| *id);
            Some(
                groups
                    .iter()
                    .map(|(name, id)| {
                        let members: Vec<&str> = users
                            .iter()
                            .filter(|(_, user)| user.groups.contains(id))
                            .map(|(name, _)| name.as_str())
                            .collect();
                        format!("{name}:x:{id}:{}\n", members.join(","))
                    })
                    .collect(),
            )
        }
        _ => None,
    }
}

/// Make /etc and the files the kernel writes in it, root's, where they are not; /proc, where
/// procfs answers; and the rest of Arch's / that is the store's.
pub fn ensure(db: &mut Db) {
    if db.node("/etc").is_none() {
        db.set_node("/etc", &Node::directory(0, 0, 0o755));
    }
    if db.node("/proc").is_none() {
        db.set_node("/proc", &Node::directory(0, 0, 0o555));
    }
    // The rest of Arch's /, the store's: /tmp shared and sticky, as /guest is.
    for (path, mode) in [
        ("/boot", 0o755),
        ("/mnt", 0o755),
        ("/opt", 0o755),
        ("/run", 0o755),
        ("/srv", 0o755),
        ("/tmp", 0o1777),
        ("/var", 0o755),
    ] {
        if db.node(path).is_none() {
            db.set_node(path, &Node::directory(0, 0, mode));
        }
    }
    for path in ["/etc/passwd", "/etc/group"] {
        if db.node(path).is_none() {
            let file = kernel::Fs::empty(db, 0, path);
            db.set_node(path, &Node::file(0, 0, 0o644, file, 0));
        }
    }
}

/// Who the process is.
fn creds(db: &Db, key: Option<&str>, cred: &Identity) -> Creds {
    let view = auth::session_view(db, key);
    let home = db
        .user_by_id(cred.id)
        .map(|(_, user)| user.home)
        .unwrap_or_else(|| "/".into());
    Creds {
        uid: cred.id,
        gid: cred.group,
        groups: cred.groups.iter().copied().collect(),
        user: db.username(cred.id),
        group: db.groupname(cred.group),
        group_names: cred.groups.iter().map(|id| db.groupname(*id)).collect(),
        home,
        signed_in: auth::signed_in(db, key),
        can_sudo: db.can_sudo(cred),
        sudo_active: view["sudo_active"].as_bool().unwrap_or(false),
    }
}

/// A driver's request that asks Realtime, as the session asks it.
struct Asked {
    /// Who asks: a page's session, or a process by its token, which acts as its snapshot.
    session: Rc<Session>,
    fd: u32,
    op: u32,
    arg: serde_json::Value,
}

/// What a networked request was decided to be, before Realtime is asked.
enum Plan {
    /// Send the sound a descriptor writes, or a listener's voice: the voice's name.
    Publish {
        voice: Option<String>,
    },
    /// Hear a sound: its speaker's session and track, and what it is.
    Listen {
        speaker: String,
        track: String,
        version: String,
        /// The session listening, which alone answers.
        sid: String,
    },
    Answer {
        session: String,
    },
}

type Sys<T> = std::result::Result<T, Error>;

/// A page's session description, from `arg`: what it offers or answers, within bounds.
fn sdp(arg: &serde_json::Value) -> Sys<String> {
    arg["sdp"]
        .as_str()
        .filter(|sdp| !sdp.is_empty() && sdp.len() <= crate::dev::realtime::SDP_MAX)
        .map(str::to_string)
        .ok_or_else(|| Error::because(Errno::EINVAL, "a session description is needed"))
}

/// A driver's request that asks Realtime (dev::networked): decided in one transaction, asked
/// outside any, and recorded in another, as what it makes may not wait on the network inside
/// one. Rate-limited, as each makes a Realtime session.
async fn networked(
    req: &Request,
    env: &Env,
    state: &State,
    asked: Asked,
) -> Sys<serde_json::Value> {
    use crate::dev::{self, realtime};
    let io = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
    realtime::app(env).map_err(|why| Error::because(Errno::ENODEV, why))?;
    let limited = match asked.op {
        abi::SND_LISTEN => auth::limited_by(req, env, "LISTEN_LIMIT", "listen").await,
        abi::SND_ANSWER => Ok(false),
        _ => auth::limited(req, env, "speak").await,
    };
    if limited.map_err(io)? {
        return Err(Error::because(
            Errno::EAGAIN,
            "Too many attempts; please try again later",
        ));
    }
    let Asked {
        session: asker,
        fd,
        op,
        arg,
    } = asked;
    let decided = {
        let (asker, arg) = (asker.clone(), arg.clone());
        transact(state, move |db| {
            let plan = (|| {
                let acting = asker.of(db)?;
                let process = &acting.process;
                let sid = acting.sid.clone().ok_or(Errno::EBADF)?;
                crate::fds::yours(db, &sid, fd, acting.owner().as_deref())?;
                let request = dev::request(db, &sid, fd)?.ok_or(Errno::ENOTTY)?;
                let rdev = request.node.rdev.clone().unwrap_or_default();
                Ok(match (op, rdev.as_str()) {
                    (abi::SND_PUBLISH, "snd") => {
                        dev::snd::may_publish(&request)?;
                        Plan::Publish { voice: None }
                    }
                    (abi::PRESENT_SPEAK, "present") => Plan::Publish {
                        voice: Some(dev::present::voice_name(db, &process.cred, &request)?),
                    },
                    (abi::SND_LISTEN, "snd") => {
                        if request.flags & abi::O_ACCMODE == abi::O_WRONLY {
                            return Err(Errno::EBADF.into());
                        }
                        let (speaker, track) = dev::snd::heard(&request.device)?;
                        Plan::Listen {
                            speaker,
                            track,
                            version: dev::version(&request.device),
                            sid: sid.clone(),
                        }
                    }
                    // Only the session that listened answers its pull.
                    (abi::SND_ANSWER, "snd") => {
                        let session = arg["session"].as_str().unwrap_or_default().to_string();
                        let listener = realtime::listener(&sid, &session);
                        let fresh = db
                            .expiry(realtime::LISTENER, &listener)
                            .is_some_and(|due| auth::now() <= due);
                        db.clear_expiry(realtime::LISTENER, &listener);
                        if !fresh {
                            return Err(Error::because(
                                Errno::ENOENT,
                                "No such sound session; listen again",
                            ));
                        }
                        Plan::Answer { session }
                    }
                    _ => return Err(dev::not_for(op)),
                })
            })();
            let commit = plan.is_ok();
            (plan, commit)
        })
        .map_err(io)?
    }?;
    let unreached = |why: String| Error::because(Errno::EIO, why);
    match decided {
        Plan::Publish { voice } => {
            let mid = arg["mid"].as_str().unwrap_or_default().to_string();
            let ask = arg["ask"]
                .as_str()
                .filter(|ask| ask.len() <= 32 && ask.bytes().all(|b| b.is_ascii_alphanumeric()))
                .map(str::to_string);
            let (session, answer) = realtime::publish(env, &sdp(&arg)?, &mid)
                .await
                .map_err(unreached)?;
            let made = transact(state, move |db| {
                let made = (|| {
                    let acting = asker.of(db)?;
                    let process = &acting.process;
                    let sid = acting.sid.clone().ok_or(Errno::EBADF)?;
                    let request = dev::request(db, &sid, fd)?.ok_or(Errno::ENOTTY)?;
                    match &voice {
                        Some(voice) => dev::present::spoken(
                            db,
                            &process.cred,
                            &request,
                            voice,
                            &session,
                            ask.as_deref(),
                        ),
                        None => dev::snd::published(db, &request, &session),
                    }
                })();
                let commit = made.is_ok();
                (made, commit)
            })
            .map_err(io)??;
            let mut made = made;
            made["sdp"] = json!(answer);
            Ok(made)
        }
        Plan::Listen {
            speaker,
            track,
            version,
            sid,
        } => {
            let (session, offer) = realtime::pull(env, &speaker, &track)
                .await
                .map_err(unreached)?;
            let kept = realtime::listener(&sid, &session);
            transact(state, move |db| {
                db.set_expiry(
                    realtime::LISTENER,
                    &kept,
                    auth::now() + realtime::ANSWER_TTL,
                );
                ((), true)
            })
            .map_err(io)?;
            Ok(json!({ "session": session, "sdp": offer, "version": version }))
        }
        Plan::Answer { session } => {
            realtime::answer(env, &session, &sdp(&arg)?)
                .await
                .map_err(unreached)?;
            Ok(json!({ "session": session }))
        }
    }
}

/// The account calls of root (or one under sudo), as their options say (commands/accounts.rs):
/// what was done, said as the programs say it.
fn account(
    db: &mut Db,
    who: &Identity,
    call: Call,
) -> std::result::Result<serde_json::Value, Error> {
    use crate::commands::accounts;
    use os_core::cli::accounts as args;
    let done = match call {
        Call::Useradd {
            name,
            create_home,
            home,
            group,
            groups,
            short_password,
            ..
        } => accounts::useradd(
            db,
            who,
            args::Useradd {
                short_password,
                create_home,
                no_create_home: !create_home,
                home,
                group,
                groups,
                name,
            },
        ),
        Call::Usermod {
            name,
            append,
            groups,
            group,
            home,
            move_home,
            rename,
            lock,
            unlock,
        } => accounts::usermod(
            db,
            who,
            args::Usermod {
                append,
                groups,
                group,
                home,
                move_home,
                rename,
                lock,
                unlock,
                user: name,
            },
        ),
        Call::Userdel { name, remove, .. } => {
            accounts::userdel(db, who, args::Userdel { remove, user: name })
        }
        Call::Groupadd { name } => accounts::groupadd(db, who, args::Groupadd { group: name }),
        Call::Groupmod { name, new_name } => accounts::groupmod(
            db,
            who,
            args::Groupmod {
                new: new_name,
                old: name,
            },
        ),
        Call::Groupdel { name } => accounts::groupdel(db, who, args::Groupdel { group: name }),
        _ => return Err(Errno::ENOSYS.into()),
    };
    done.map(|message| json!({ "message": message }))
        .map_err(|why| {
            let errno = if crate::commands::is_permission_error(&why)
                || why.starts_with("Root permission")
            {
                Errno::EPERM
            } else if why.contains("does not exist") {
                Errno::ENOENT
            } else if why.contains("already exists") {
                Errno::EEXIST
            } else {
                Errno::EINVAL
            };
            Error::because(errno, why)
        })
}
