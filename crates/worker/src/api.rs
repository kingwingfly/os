//! The authority's requests: each decides and writes in one synchronous transaction, after any
//! awaiting (reading the body, hashing a password) is done. It never touches file bytes; the
//! Worker asks it whether it may, and tells it what it wrote.
use crate::db::{Db, File, transact};
use crate::{auth, commands, jobs};
use serde::Deserialize;
use serde_json::{Value, json};
use terminal_worker_core::{mime, permissions::*, resolve};
use worker::*;

/// How long an upload may go without a new chunk before it is cancelled, in seconds.
pub const UPLOAD_TTL: u64 = 24 * 60 * 60;
/// The chunks of a recording (`stream`): small, as each is sent once it is whole, and lost if
/// its page goes first (about half a minute of speech at 64 kbit/s); not too small, as reading a
/// file takes an R2 request a chunk, of the Worker's subrequests (1000 a request).
pub const RECORDING_CHUNK: u64 = 256 * 1024;
/// The most a recording may be: as many chunks as one read can take, with room for what else it
/// asks (240 MiB, about eight hours at 64 kbit/s).
pub const RECORDING_MAX: u64 = RECORDING_CHUNK * 960;
/// How long a recording's page may go unheard (chunks, its lease) before the recording is
/// completed with what arrived, in seconds.
pub const RECORDING_IDLE: u64 = 10 * 60;

pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub cookie: Option<String>,
    /// Whether the transaction's writes stand: by default, only when the reply is a success.
    pub commit: bool,
}
impl Reply {
    pub fn ok(body: Value) -> Self {
        Self {
            status: 200,
            body,
            cookie: None,
            commit: true,
        }
    }
    pub fn error(message: &str, status: u16) -> Self {
        Self {
            status,
            body: json!({"error":message}),
            cookie: None,
            commit: false,
        }
    }
    fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }
    pub fn cookie(mut self, cookie: String) -> Self {
        self.cookie = Some(cookie);
        self
    }
    /// Keep the writes of an error reply, such as a cleanup.
    fn keep(mut self) -> Self {
        self.commit = true;
        self
    }
    pub fn response(self) -> Result<Response> {
        let mut response = Response::from_json(&self.body)?.with_status(self.status);
        if let Some(cookie) = self.cookie {
            response.headers_mut().set("Set-Cookie", &cookie)?;
        }
        Ok(response)
    }
}

/// An error reply whose status follows the message: guests are asked to sign in.
/// A failed system call as HTTP: its errno and words, with a status that says as much.
pub fn errno_reply(error: &abi::Error) -> Reply {
    use abi::Errno::*;
    let status = match error.errno {
        EACCES | EPERM => 403,
        ENOENT => 404,
        EBADF | EBUSY | EEXIST => 409,
        ESTALE => 412,
        EFBIG => 413,
        _ => 400,
    };
    let mut reply = Reply::error(&error.to_string(), status);
    reply.body["errno"] = json!(error.errno);
    reply
}

/// The credentials a request's `X-Process-Token` carries, in the request's own namespace. A
/// token that does not resolve (or is another browser's process's) is refused, never treated
/// as no header: a process request must act as its snapshot, not as the page signed in later.
fn process_caller(
    db: &Db,
    token: Option<&str>,
    key: Option<&str>,
    guest: Option<&str>,
) -> std::result::Result<Option<crate::creds::Credential>, abi::Error> {
    let Some(token) = token else {
        return Ok(None);
    };
    let ns = Db::namespace(key, guest);
    db.credential(token, &ns)
        .map(Some)
        .ok_or_else(|| abi::Error::because(abi::Errno::EPERM, "not this browser's process"))
}
pub fn denied(message: &str, who: &Identity) -> Reply {
    let status = if commands::is_permission_error(message) {
        if is_guest_id(who.id) { 401 } else { 403 }
    } else if message.contains("does not exist") {
        404
    } else if message.contains("already exists")
        || message.contains("with this name")
        || message.contains("This is a directory")
        || message.contains("File exists")
        || message.contains("Device or resource busy")
    {
        409
    } else {
        400
    };
    Reply::error(message, status)
}

pub fn run(state: &State, work: impl FnOnce(&mut Db) -> Reply + 'static) -> Result<Reply> {
    transact(state, move |db| {
        let reply = work(db);
        let commit = reply.commit;
        (reply, commit)
    })
}
fn read<T: 'static>(state: &State, work: impl FnOnce(&mut Db) -> T + 'static) -> Result<T> {
    transact(state, move |db| (work(db), false))
}

macro_rules! acl {
    ($result:expr, $who:expr) => {
        match $result {
            Ok(value) => value,
            Err(message) => return denied(&message, $who),
        }
    };
}
/// `path` physically for `who`, a link at its end followed if `follow`, or the error reply.
macro_rules! real {
    ($db:expr, $who:expr, $path:expr, $follow:expr) => {
        acl!($db.physical($who, $path, $follow), $who)
    };
}

pub async fn handle(req: &mut Request, env: &Env, state: &State) -> Result<Reply> {
    let url = req.url()?;
    let endpoint = url.path().to_string();
    let method = req.method();
    let key = auth::token_key(req);
    let raw_path = url
        .query_pairs()
        .find(|(k, _)| k == "path")
        .map(|(_, v)| v.into_owned())
        .unwrap_or_else(|| "/".into());
    let path = match resolve("/", &raw_path) {
        Ok(p) => p,
        Err(e) => return Ok(Reply::error(&e, 400)),
    };
    let param = |name: &str| {
        url.query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    };
    match (method.clone(), endpoint.as_str()) {
        // System calls (sys.rs): what user space, the page, asks of the kernel.
        (Method::Post, "/api/sys") => crate::sys::handle(req, env, state, key).await,
        // What each browser's machine asks of the authority (creds.rs): never a browser's.
        (
            Method::Post,
            "/internal/exec" | "/internal/identity" | "/internal/revoke" | "/internal/tell",
        ) => Ok(crate::creds::internal(req, state, &endpoint)
            .await?
            .unwrap_or_else(|| Reply::error("Not found", 404))),
        (Method::Get, "/internal/read") => {
            let guest = auth::guest_key(req);
            let proc_token = req.headers().get("X-Process-Token")?;
            // /proc's files tell of the browser's processes, as its machine has them.
            let procs = if crate::procfs::of_processes(&path) {
                let ns = Db::namespace(key.as_deref(), guest.as_deref());
                crate::machine::list(env, &ns).await?
            } else {
                Vec::new()
            };
            run(state, move |db| {
                // A process's byte request carries its token: it reads as its snapshot, never
                // as the page signed in later.
                let row = match process_caller(
                    db,
                    proc_token.as_deref(),
                    key.as_deref(),
                    guest.as_deref(),
                ) {
                    Ok(row) => row,
                    Err(error) => return errno_reply(&error).keep(),
                };
                let who = row.as_ref().map_or_else(
                    || auth::identity_of(db, key.as_deref(), guest.as_deref()),
                    |row| row.identity(),
                );
                // /proc's files are written as they are read; /proc/self/fd/N names what the
                // descriptor has open.
                let sid = crate::creds::sid_of(db, key.as_deref(), guest.as_deref(), row.as_ref());
                let path = match crate::procfs::follow(db, sid.as_deref(), &path, true) {
                    Ok(path) => path,
                    Err(error) => return errno_reply(&error),
                };
                if crate::procfs::is(&path) {
                    return match crate::procfs::read(db, sid.as_deref(), &procs, &who, &path) {
                        Ok(text) => Reply::ok(json!({ "generated": text })),
                        Err(error) => errno_reply(&error),
                    };
                }
                let real = real!(db, &who, &path, true);
                let node = acl!(db.access(&who, &real, READ), &who);
                // /etc/passwd and /etc/group are the kernel's to write as they are read; a device's
                // content is its driver's state.
                if let Some(text) = crate::sys::generated(db, &real) {
                    return Reply::ok(json!({ "generated": text }));
                }
                if node.is_device() {
                    return match crate::dev::read(db, &who, sid.as_deref(), &real) {
                        Some(state) => Reply::ok(json!({ "device": state })),
                        None => Reply::error("No such device or address", 404),
                    };
                }
                let Some(id) = node.file else {
                    return Reply::error("This is a directory", 400);
                };
                // /usr's binaries are the build's, in the Worker's assets.
                if let Some(asset) = crate::usr::asset(&id) {
                    return Reply::ok(json!({ "asset": asset, "size": node.size }));
                }
                let Some(file) = db.file(&id) else {
                    return Reply::error("File content does not exist", 404);
                };
                let chunks: Vec<_> = db
                    .chunks(&id)
                    .into_iter()
                    .map(|c| json!([c.idx, c.key]))
                    .collect();
                Reply::ok(json!({
                    "file": id, "size": file.size, "chunk_size": file.chunk_size,
                    "state": file.state, "etag": file.etag(), "mime": mime(&real), "chunks": chunks,
                    "readable": db.readable(&file),
                }))
            })
        }
        // A read token (fds.rs by_token): what the Worker reads it by, the kernel asked again.
        (Method::Get, "/internal/token") => {
            let token = param("token");
            let guest = auth::guest_key(req);
            let proc_token = req.headers().get("X-Process-Token")?;
            run(state, move |db| {
                let row = match process_caller(
                    db,
                    proc_token.as_deref(),
                    key.as_deref(),
                    guest.as_deref(),
                ) {
                    Ok(row) => row,
                    Err(error) => return errno_reply(&error).keep(),
                };
                let who = row.as_ref().map_or_else(
                    || auth::identity_of(db, key.as_deref(), guest.as_deref()),
                    |row| row.identity(),
                );
                let sid = crate::creds::sid_of(db, key.as_deref(), guest.as_deref(), row.as_ref());
                match crate::fds::by_token(db, sid.as_deref(), &who, &token, row.as_ref()) {
                    Ok((file, exec)) => {
                        let chunks: Vec<_> = db
                            .chunks(&file.id)
                            .into_iter()
                            .map(|c| json!([c.idx, c.key]))
                            .collect();
                        let path = db.showing(&file.id).pop().unwrap_or(file.target.clone());
                        let content_type = if exec {
                            "application/wasm"
                        } else {
                            mime(&path)
                        };
                        Reply::ok(json!({
                            "file": file.id, "size": file.size, "chunk_size": file.chunk_size,
                            "state": file.state, "etag": file.etag(), "mime": content_type, "chunks": chunks,
                            "readable": file.size, "exec": exec,
                        }))
                    }
                    Err(error) => errno_reply(&error).keep(),
                }
            })
        }
        // pwrite(2) through a descriptor, as the Worker streams its bytes to R2 (files.rs):
        // where the chunk goes, then that it is there.
        (Method::Get, "/internal/pwrite") => {
            let fd = param("fd").parse::<u32>().unwrap_or(u32::MAX);
            let index = param("index").parse::<u64>().unwrap_or(u64::MAX);
            let length = param("length").parse::<u64>().unwrap_or(0);
            let guest = auth::guest_key(req);
            let proc_token = req.headers().get("X-Process-Token")?;
            run(state, move |db| {
                let row = match process_caller(
                    db,
                    proc_token.as_deref(),
                    key.as_deref(),
                    guest.as_deref(),
                ) {
                    Ok(row) => row,
                    Err(error) => return errno_reply(&error).keep(),
                };
                let who = row.as_ref().map_or_else(
                    || auth::identity_of(db, key.as_deref(), guest.as_deref()),
                    |row| row.identity(),
                );
                let sid = crate::creds::sid_of(db, key.as_deref(), guest.as_deref(), row.as_ref())
                    .unwrap_or_default();
                let caller = row.map(|row| row.owner());
                match crate::fds::pwrite(db, &sid, &who, fd, index, length, caller.as_deref()) {
                    Ok((key, mime)) => Reply::ok(json!({"key": key, "mime": mime})),
                    Err(error) => errno_reply(&error).keep(),
                }
            })
        }
        (Method::Post, "/internal/pwrite/commit") => {
            #[derive(Deserialize)]
            struct Written {
                fd: u32,
                index: u64,
                key: String,
                sha256: Option<String>,
                length: u64,
            }
            let Ok(chunk) = req.json::<Written>().await else {
                return Ok(Reply::error("Invalid write", 400));
            };
            let guest = auth::guest_key(req);
            let proc_token = req.headers().get("X-Process-Token")?;
            run(state, move |db| {
                let row = match process_caller(
                    db,
                    proc_token.as_deref(),
                    key.as_deref(),
                    guest.as_deref(),
                ) {
                    Ok(row) => row,
                    Err(error) => return errno_reply(&error).keep(),
                };
                let who = row.as_ref().map_or_else(
                    || auth::identity_of(db, key.as_deref(), guest.as_deref()),
                    |row| row.identity(),
                );
                let sid = crate::creds::sid_of(db, key.as_deref(), guest.as_deref(), row.as_ref())
                    .unwrap_or_default();
                let caller = row.map(|row| row.owner());
                let written = crate::fds::written(
                    db,
                    &sid,
                    &who,
                    chunk.fd,
                    chunk.index,
                    &chunk.key,
                    chunk.sha256.as_deref(),
                    chunk.length,
                    caller.as_deref(),
                );
                match written {
                    Ok(value) => Reply::ok(value),
                    Err(error) => errno_reply(&error).keep(),
                }
            })
        }
        (_, endpoint) if endpoint.starts_with("/internal/job") => {
            let token = req.headers().get("X-Process-Token")?.unwrap_or_default();
            let body: Value = if matches!(method, Method::Post) {
                req.json().await.unwrap_or_default()
            } else {
                Value::Null
            };
            run(state, {
                let endpoint = endpoint.to_string();
                let method = method.clone();
                let file = param("file");
                move |db| job_reply(db, &method, &endpoint, &token, &file, body)
            })
        }
        _ => Ok(Reply::error(
            "Unknown endpoint or unsupported request method",
            404,
        )),
    }
}

/// What a job's runner asks of the job itself, by the job's token (its credentials, creds.rs):
/// the job, its output and progress, its end, and the contents it pinned as it started (the
/// archive it reads, the files it archives), as exec hands a process its image. Its file calls
/// are the system calls, made with the same token, checked as any process's are.
fn job_reply(
    db: &mut Db,
    method: &Method,
    endpoint: &str,
    token: &str,
    file: &str,
    body: Value,
) -> Reply {
    use crate::db::JobColumn;
    let Some(id) = db
        .credential(token, crate::creds::JOBS)
        .and_then(|credential| credential.job())
    else {
        return Reply::error("not a job's token, or its job has ended", 403);
    };
    let id = id.as_str();
    let Some(job) = db.job(id) else {
        return Reply::error("Job does not exist", 404);
    };
    match (method, endpoint) {
        (Method::Get, "/internal/job") => Reply::ok(json!(job)),
        (Method::Post, "/internal/job/update") => {
            if let Some(lines) = body["lines"].as_array() {
                let lines: Vec<(bool, String)> = lines
                    .iter()
                    .filter_map(|l| Some((l[0].as_bool()?, l[1].as_str()?.to_string())))
                    .collect();
                db.add_lines(id, &lines);
            }
            if let Some(progress) = body.get("progress") {
                db.set_job(id, JobColumn::Progress, Some(&progress.to_string()));
            }
            if let Some(question) = body.get("question") {
                db.set_job(
                    id,
                    JobColumn::Question,
                    (!question.is_null())
                        .then(|| question.to_string())
                        .as_deref(),
                );
            }
            // A job being cancelled stays so; the runner finishes it.
            if let Some(state) = body["state"].as_str()
                && !job.finished()
                && job.state != "cancelling"
            {
                db.set_job(id, JobColumn::State, Some(state));
                if state == "question" {
                    db.set_expiry("job", id, auth::now() + jobs::UNANSWERED);
                }
            }
            Reply::ok(json!({"state": db.job(id).map(|j| j.state)}))
        }
        (Method::Post, "/internal/job/finish") => {
            let state = body["state"].as_str().unwrap_or("done");
            jobs::finish(
                db,
                id,
                if job.state == "cancelling" {
                    "cancelled"
                } else {
                    state
                },
            );
            Reply::ok(json!({"finished": true}))
        }
        (Method::Get, "/internal/job/file") => {
            if !db.pinned(id, file) {
                return Reply::error("The job does not read that file", 403);
            }
            let Some(f) = db.file(file) else {
                return Reply::error("File content does not exist", 404);
            };
            let chunks: Vec<Value> = db
                .chunks(file)
                .into_iter()
                .map(|c| json!([c.idx, c.key]))
                .collect();
            Reply::ok(json!({"size": f.size, "chunk_size": f.chunk_size, "chunks": chunks}))
        }
        _ => Reply::error("Unknown endpoint or unsupported request method", 404),
    }
}

/// Run one command as the session `key`, elevated if it asks for sudo.
/// Wake the runner of the job a reply started or changed, if any.
pub async fn kick(env: &Env, reply: &Value) {
    let Some(job) = reply["job"].as_str() else {
        return;
    };
    // A job just spawned hands its runner its token, which the runner keeps; one woken again
    // (an answer, a signal) has it already.
    let woken = async {
        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        init.with_body(Some(
            json!({"job": job, "token": reply["token"]})
                .to_string()
                .into(),
        ));
        env.durable_object("JOBS")?
            .id_from_name(job)?
            .get_stub()?
            .fetch_with_request(Request::new_with_init("https://runner/start", &init)?)
            .await
    }
    .await;
    if let Err(e) = woken {
        console_error!("cannot start the runner of job {}: {}", job, e);
    }
}

/// A new R2 object for chunk `index` of `file`. Each write has its own, so a chunk sent again,
/// or late, never overwrites one already committed, which readers and copies may be reading.
pub fn chunk_key(file: &str, index: u64) -> String {
    format!("chunks/{file}/{index}-{}", &auth::random_token()[..16])
}
/// Whether `key` is an object `chunk_key` named for chunk `index` of `file`.
pub fn chunk_of(key: &str, file: &str, index: u64) -> bool {
    key.strip_prefix(&format!("chunks/{file}/{index}-"))
        .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A recording whose page went away: it is complete with what arrived, in order; one with
/// nothing is abandoned. Its live sound ends.
pub fn finish_recording(db: &mut Db, file: &File) {
    if let Some(path) = db.showing(&file.id).pop() {
        end_live(db, file, &path);
    }
    // A recording takes only its next chunk, so what arrived is all there, in order.
    if file.size == 0 {
        return cancel(db, file);
    }
    db.finish_file(&file.id);
}

/// End the live sound of the recording `file`, which shows at `path`: a recording that ended is
/// live no more.
fn end_live(db: &mut Db, file: &File, path: &str) {
    for device in db.presenting(file.uploader, path) {
        crate::dev::hangup(db, &device.name, true);
    }
}

/// Abandon an upload: a new file disappears, an overwritten one keeps its old content.
pub fn cancel(db: &mut Db, file: &File) {
    if file.base.is_none() {
        for path in db.showing(&file.id) {
            db.delete_node(&path);
        }
    }
    // Deleting the last node showing it may have freed it already.
    if db.file(&file.id).is_some() {
        db.drop_file(&file.id);
    }
}

pub async fn login(
    req: &Request,
    env: &Env,
    state: &State,
    key: Option<String>,
    https: bool,
    body: Value,
) -> Result<Reply> {
    if auth::limited(req, env, "login").await? {
        return Ok(Reply::error(
            "Too many attempts; please try again later",
            429,
        ));
    }
    #[derive(Deserialize)]
    struct Login {
        #[serde(default = "root_user")]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        switch: bool,
        #[serde(default)]
        sudo: bool,
    }
    fn root_user() -> String {
        "root".into()
    }
    let Ok(login) = serde_json::from_value::<Login>(body) else {
        return Ok(Reply::error("Invalid login request", 400));
    };
    let (who, user, root, sudo) = read(state, {
        let key = key.clone();
        let name = login.username.clone();
        let sudo = login.sudo;
        move |db| {
            let sudo = if sudo {
                auth::elevated(db, key.as_deref(), true).map(|_| ())
            } else {
                Ok(())
            };
            (
                auth::identity(db, key.as_deref()),
                db.user(&name),
                db.user("root"),
                sudo,
            )
        }
    })?;
    // Explicit sudo -u switches only after the caller has authorized sudo.
    if let Err(message) = sudo {
        return Ok(denied(&message, &who));
    }
    // Run the same KDF for nonexistent users to avoid a username timing oracle.
    let verified = if login.sudo || login.switch && who.id == 0 {
        true
    } else {
        let Some(account) = user.as_ref().or(root.as_ref()) else {
            return Ok(Reply::error("Root account is missing", 500));
        };
        auth::verify(&login.password, account, env).await?
    };
    let Some(user) = user.filter(|u| (!u.locked || who.id == 0 && login.switch) && verified) else {
        return Ok(Reply::error(
            "Incorrect username or password, or the account is locked",
            401,
        ));
    };
    if user.locked {
        return Ok(Reply::error(
            "Account is locked; use usermod -U to unlock it first",
            403,
        ));
    }
    run(state, move |db| {
        // The password verified above must still be the account's, and the account unlocked:
        // a session issued after a lock would come back when the account is unlocked.
        if db
            .user_by_id(user.id)
            .is_none_or(|(_, u)| u.hash != user.hash || u.locked)
        {
            return Reply::error("Account changed during sign-in; please try again", 409);
        }
        let (body, token) = auth::issue(db, key.as_deref(), user.id);
        Reply::ok(body).cookie(auth::cookie(https, &token, auth::TTL))
    })
}

pub async fn sudo(
    req: &Request,
    env: &Env,
    state: &State,
    key: Option<String>,
    body: Value,
) -> Result<Reply> {
    let (who, can_sudo, account) = read(state, {
        let key = key.clone();
        move |db| {
            let who = auth::identity(db, key.as_deref());
            let can_sudo = db.can_sudo(&who);
            let account = db.user_by_id(who.id).map(|(_, u)| u);
            (who, can_sudo, account)
        }
    })?;
    if is_guest_id(who.id) {
        return Ok(Reply::error("Sign in first", 401));
    }
    if !can_sudo {
        return Ok(Reply::error(
            "Current account is not in the wheel group",
            403,
        ));
    }
    let value = body;
    let revoke = value["revoke"] == true;
    if !revoke && who.id != 0 {
        if auth::limited(req, env, "sudo").await? {
            return Ok(Reply::error(
                "Too many attempts; please try again later",
                429,
            ));
        }
        let Some(account) = &account else {
            return Ok(Reply::error("Sign in first", 401));
        };
        if !auth::verify(value["password"].as_str().unwrap_or(""), account, env).await? {
            return Ok(Reply::error("Incorrect account password", 401));
        }
    }
    run(state, move |db| {
        if let Some(key) = &key
            && let Some(mut session) = db.session(key)
        {
            session.sudo_until = if revoke { 0 } else { auth::now() + 300 };
            db.set_session(key, &session);
        }
        Reply::ok(json!({"sudo_active":!revoke}))
    })
}

pub async fn passwd(
    req: &Request,
    env: &Env,
    state: &State,
    key: Option<String>,
    https: bool,
    body: Value,
) -> Result<Reply> {
    let who = read(state, {
        let key = key.clone();
        move |db| auth::identity(db, key.as_deref())
    })?;
    if is_guest_id(who.id) {
        return Ok(Reply::error("Sign in first", 401));
    }
    if auth::limited(req, env, "passwd").await? {
        return Ok(Reply::error(
            "Too many attempts; please try again later",
            429,
        ));
    }
    #[derive(Deserialize)]
    struct Password {
        #[serde(default)]
        username: Option<String>,
        password: String,
        #[serde(default)]
        current_password: String,
        #[serde(default)]
        sudo: bool,
        #[serde(default)]
        force: bool,
    }
    let Ok(value) = serde_json::from_value::<Password>(body) else {
        return Ok(Reply::error("Invalid password request", 400));
    };
    let checked = read(state, {
        let key = key.clone();
        let name = value.username.clone();
        let sudo = value.sudo;
        let who = who.clone();
        move |db| {
            let actor = auth::elevated(db, key.as_deref(), sudo)?;
            let name = name.unwrap_or_else(|| db.username(who.id));
            let target = db.user(&name).ok_or("User does not exist")?;
            Ok::<_, String>((actor, name, target))
        }
    })?;
    let (actor, name, target) = match checked {
        Ok(checked) => checked,
        Err(message) => return Ok(denied(&message, &who)),
    };
    if is_guest_id(target.id) {
        return Ok(Reply::error(
            "guest has no password: it is who is signed out",
            400,
        ));
    }
    if actor.id != 0 && target.id != who.id {
        return Ok(Reply::error(
            "Only root can change another account's password",
            403,
        ));
    }
    if actor.id != 0 && !auth::verify(&value.current_password, &target, env).await? {
        return Ok(Reply::error("Incorrect current password", 401));
    }
    if value.password.is_empty() || value.password.len() > 512 {
        return Ok(Reply::error(
            "The new password cannot be empty and must not exceed 512 bytes",
            400,
        ));
    }
    if !value.force && !auth::password_valid(&value.password) {
        return Ok(Reply::error(
            "Use at least 12 characters; explicitly use passwd --force to allow a short password",
            400,
        ));
    }
    let salt = auth::random_token();
    let hash = auth::hash(&value.password, &salt, env).await?;
    let sudo = value.sudo;
    run(state, move |db| {
        let Some(mut account) = db.user(&name).filter(|u| u.id == target.id) else {
            return Reply::error("User does not exist", 404);
        };
        // What was checked before hashing must still hold: the same signed-in account, acting as
        // it did, and, without root, the current password verified still the account's, which
        // is not locked meanwhile.
        let now = auth::identity(db, key.as_deref());
        let still = auth::elevated(db, key.as_deref(), sudo).is_ok_and(|a| a.id == actor.id);
        if now.id != who.id
            || !still
            || actor.id != 0 && (account.hash != target.hash || account.locked)
        {
            return Reply::error(
                "Account changed during the password change; please try again",
                409,
            );
        }
        account.salt = salt;
        account.hash = hash;
        account.locked = false;
        db.set_user(&name, &account);
        db.delete_sessions(account.id);
        if account.id == who.id {
            let (body, token) = auth::issue(db, key.as_deref(), account.id);
            return Reply::ok(body).cookie(auth::cookie(https, &token, auth::TTL));
        }
        Reply::ok(
            json!({"output":format!("Password updated for {name}; previous sessions revoked")}),
        )
    })
}

/// The most accounts guests may make, all told.
const REGISTERED_MAX: usize = 1000;

/// An account of group guest's deleting itself (userdel NAME, signed in as NAME), as its
/// password confirms, and with `remove` its home: its sessions end, this one too.
pub async fn unregister(
    req: &Request,
    env: &Env,
    state: &State,
    key: Option<String>,
    https: bool,
    body: Value,
) -> Result<Reply> {
    let who = read(state, {
        let key = key.clone();
        move |db| auth::identity(db, key.as_deref())
    })?;
    if is_guest_id(who.id) {
        return Ok(Reply::error("Sign in first", 401));
    }
    if who.id == 0 || !who.groups.contains(&GUEST) {
        return Ok(Reply::error(
            "Permission denied: an account deletes itself only if it is in group guest; root deletes others with sudo userdel",
            403,
        ));
    }
    if auth::limited(req, env, "unregister").await? {
        return Ok(Reply::error(
            "Too many attempts; please try again later",
            429,
        ));
    }
    #[derive(Deserialize)]
    struct Unregister {
        password: String,
        #[serde(default)]
        remove: bool,
    }
    let Ok(wanted) = serde_json::from_value::<Unregister>(body) else {
        return Ok(Reply::error("Invalid account request", 400));
    };
    let (name, user) = read(state, {
        let id = who.id;
        move |db| {
            let name = db.username(id);
            let user = db.user(&name);
            (name, user)
        }
    })?;
    let Some(user) = user.filter(|user| user.id == who.id) else {
        return Ok(Reply::error("User does not exist", 404));
    };
    if !auth::verify(&wanted.password, &user, env).await? {
        return Ok(Reply::error("Incorrect password", 401));
    }
    run(state, move |db| {
        if auth::identity(db, key.as_deref()).id != who.id {
            return Reply::error("Signed out meanwhile; please try again", 409);
        }
        let kept = match commands::accounts::delete_account(db, &name, wanted.remove) {
            Ok(kept) => kept,
            Err(message) => return denied(&message, &who),
        };
        Reply::ok(json!({ "username": "guest", "deleted": name, "home": "/", "kept": kept }))
            .cookie(auth::cookie(https, "", 0))
    })
}

/// useradd NAME, signed out: an account of one's own, in its own group and in guest's, its home
/// /guest/NAME (made, only it may enter, with -m), and the password given; signed in as it at
/// once.
pub async fn register(
    req: &Request,
    env: &Env,
    state: &State,
    key: Option<String>,
    https: bool,
    body: Value,
) -> Result<Reply> {
    let who = read(state, {
        let key = key.clone();
        move |db| auth::identity(db, key.as_deref())
    })?;
    if !is_guest_id(who.id) {
        return Ok(Reply::error(
            "useradd NAME makes an account for one who is signed out; signed in, use sudo useradd",
            409,
        ));
    }
    if auth::limited(req, env, "register").await? {
        return Ok(Reply::error(
            "Too many attempts; please try again later",
            429,
        ));
    }
    #[derive(Deserialize)]
    struct Register {
        username: String,
        password: String,
        /// One shorter than 12 characters is meant (useradd --short-password).
        #[serde(default)]
        short_password: bool,
        /// Its home, /guest/NAME, is made too (useradd -m).
        #[serde(default)]
        create_home: bool,
    }
    let Ok(wanted) = serde_json::from_value::<Register>(body) else {
        return Ok(Reply::error("Invalid account request", 400));
    };
    let name = wanted.username;
    if !valid_name(&name) {
        return Ok(Reply::error(
            "Username is invalid (start with a lowercase letter; up to 32 lowercase letters, digits, underscores, or hyphens)",
            400,
        ));
    }
    if wanted.password.is_empty() || wanted.password.len() > 512 {
        return Ok(Reply::error(
            "The password cannot be empty and must not exceed 512 bytes",
            400,
        ));
    }
    if !wanted.short_password && !auth::password_valid(&wanted.password) {
        return Ok(Reply::error(
            "Use at least 12 characters; useradd --short-password allows a short password",
            400,
        ));
    }
    let create_home = wanted.create_home;
    // Refused before the slow hash, and again in the transaction that makes it.
    let taken = |db: &Db, name: &str| {
        if db.user(name).is_some() || db.group(name).is_some() {
            Some(Reply::error("Username already exists", 409))
        } else if db.node(GUEST_HOME).is_none_or(|n| !n.directory) {
            Some(Reply::error(
                "There is no /guest for homes; ask root to make it",
                503,
            ))
        } else if db
            .users()
            .iter()
            .filter(|(_, u)| u.home.starts_with(&format!("{GUEST_HOME}/")))
            .count()
            >= REGISTERED_MAX
        {
            Some(Reply::error(
                "Guests have made as many accounts as they may",
                503,
            ))
        } else {
            db.node(&format!("{GUEST_HOME}/{name}"))
                .map(|_| Reply::error("Something with that name is already in /guest", 409))
        }
    };
    if let Some(reply) = read(state, {
        let name = name.clone();
        move |db| taken(db, &name)
    })? {
        return Ok(reply);
    }
    let salt = auth::random_token();
    let hash = auth::hash(&wanted.password, &salt, env).await?;
    run(state, move |db| {
        if !is_guest_id(auth::identity(db, key.as_deref()).id) {
            return Reply::error("Signed in meanwhile; please try again", 409);
        }
        if let Some(reply) = taken(db, &name) {
            return reply;
        }
        let home = format!("{GUEST_HOME}/{name}");
        let gid = db.next_id(Id::Group);
        db.set_group(&name, gid);
        let uid = db.next_id(Id::User);
        db.set_user(
            &name,
            &User {
                id: uid,
                group: gid,
                groups: [GUEST].into(),
                home: home.clone(),
                locked: false,
                salt,
                hash,
            },
        );
        // Its home is /guest/NAME, made as useradd -m makes one, or not at all.
        if create_home {
            db.set_node(&home, &Node::directory(uid, gid, 0o700));
        }
        let (mut body, token) = auth::issue(db, key.as_deref(), uid);
        body["home"] = json!(home);
        body["created_home"] = json!(create_home);
        Reply::ok(body)
            .status(201)
            .cookie(auth::cookie(https, &token, auth::TTL))
    })
}
