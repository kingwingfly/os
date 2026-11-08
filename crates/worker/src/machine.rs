//! Each browser's machine (owner's plan, 2026-11-02): a Durable Object per process namespace,
//! by its name (`Db::namespace`), which keeps the process registry (procs.rs) apart from the
//! filesystem's one authority. Its calls are the registry's (`Call::is_registry`); the client
//! kernel sends them straight here (the Worker routes a batch marked `X-Registry` by its
//! browser's cookies), and the authority forwards those a page's batch carries
//! (`/internal/sys`), with the caller it found.
//!
//! Execve asks the authority for the image and credentials (`/internal/exec`); tokenless
//! account operations resolve the browser identity there once per batch (`/internal/identity`). A pipeline's stages are one such request. What else a
//! process does, fork, exit, wait, signals, cgroups, stays here, told of in batches by the
//! kernel that hosts it. A batch that ended processes revokes their tokens at the authority
//! once, as it answers, so that what they opened closes as they end, as on Linux; one that
//! cannot is tried again by the alarm.
//!
//! Who may make which call, and as whom it acts, is `kernel::registry`'s table: the
//! registry route and the page both act as the authenticated account; the routing header
//! grants no privilege. A process acts by its token and snapshot (including terminal.sys).
use crate::db::{Db, transact};
use crate::procs::{Begun, Snapshot};
use crate::{auth, procs};
use abi::{BATCH_MAX, Batch, Call, Errno, Error, Exec, Forked, Return};
use kernel::registry::{self, Acting};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use terminal_worker_core::permissions::Identity;
use worker::*;

/// How long a revocation that failed waits to be tried again, in milliseconds.
const REVOKE_AFTER: i64 = 10_000;

#[durable_object]
pub struct Machine {
    state: State,
    env: Env,
    ready: Cell<bool>,
    /// New processes execs were given pids for and have not started yet, as they wait on the
    /// authority: they count against the namespace's room (`PROC_MAX`) with those running.
    reserved: Cell<usize>,
}

/// Pids an exec reserved, given back as it ends, however it ends.
struct Reservation<'a> {
    reserved: &'a Cell<usize>,
    count: usize,
}
impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.reserved
            .set(self.reserved.get().saturating_sub(self.count));
    }
}

impl DurableObject for Machine {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ready: Cell::new(false),
            reserved: Cell::new(0),
        }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if !self.ready.get() {
            procs::create(&self.state.storage().sql())?;
            self.ready.set(true);
        }
        transact(&self.state, |db| {
            db.expire_processes(auth::now());
            ((), true)
        })?;
        let path = req.path();
        let reply = match (req.method(), path.as_str()) {
            // A directly routed batch. Any page can set the header; account/token checks
            // below are the authority for every operation.
            (Method::Post, "/api/sys") => {
                if req
                    .headers()
                    .get("Content-Length")?
                    .and_then(|length| length.parse::<u64>().ok())
                    .is_none_or(|length| length > abi::BATCH_BYTES)
                {
                    return Response::error("A batch says its length, and is at most 4 MB", 400);
                }
                let Ok(batch) = req.json::<Batch>().await else {
                    return Response::error("Invalid system call batch", 400);
                };
                let ns = Db::namespace(
                    auth::token_key(&req).as_deref(),
                    auth::guest_key(&req).as_deref(),
                );
                let caller = Caller {
                    class: if batch.process.is_some() {
                        registry::Caller::Process
                    } else {
                        registry::Caller::Registry
                    },
                    ns,
                    cookie: req.headers().get("Cookie")?,
                    sudo: batch.sudo,
                    umask: batch.umask.unwrap_or(0o022) & 0o777,
                    pid: batch.pid,
                    token: batch.process.clone(),
                    identity: RefCell::new(None),
                };
                self.batch(&caller, batch.calls).await?
            }
            // A page's registry calls, as the authority forwards them, with the caller it found.
            (Method::Post, "/internal/sys") => {
                let Ok(forwarded) = req.json::<Forwarded>().await else {
                    return Response::error("Invalid forwarded calls", 400);
                };
                let caller = Caller {
                    class: if forwarded.token.is_some() {
                        registry::Caller::Process
                    } else {
                        registry::Caller::Page
                    },
                    ns: forwarded.ns,
                    cookie: forwarded.cookie,
                    sudo: forwarded.sudo,
                    umask: forwarded.umask & 0o777,
                    pid: forwarded.pid,
                    token: forwarded.token,
                    identity: RefCell::new(forwarded.identity.map(Ok)),
                };
                self.batch(&caller, forwarded.calls).await?
            }
            // The namespace's processes, as /proc lists them at the authority.
            (Method::Get, "/internal/list") => {
                let ns = req
                    .url()?
                    .query_pairs()
                    .find(|(name, _)| name == "ns")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default();
                let rows = transact(&self.state, move |db| (db.processes(&ns), false))?;
                return Response::from_json(&rows);
            }
            _ => return Response::error("Not found", 404),
        };
        // What the batch ended closes at the authority before it answers. Its calls stand
        // whether or not that can be done now: what cannot, the alarm does.
        self.settle().await;
        Response::from_json(&json!(abi::Results { results: reply }))
    }
    async fn alarm(&self) -> Result<Response> {
        if !self.ready.get() {
            procs::create(&self.state.storage().sql())?;
            self.ready.set(true);
        }
        transact(&self.state, |db| {
            db.expire_processes(auth::now());
            ((), true)
        })?;
        self.settle().await;
        Response::ok("")
    }
}

/// Registry calls a page's batch carried, as the authority forwards them.
#[derive(Deserialize)]
pub struct Forwarded {
    pub ns: String,
    #[serde(default)]
    pub cookie: Option<String>,
    #[serde(default)]
    pub sudo: bool,
    #[serde(default = "umask")]
    pub umask: u16,
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default, rename = "proc")]
    pub token: Option<String>,
    /// The page's caller, as the authority found it (root under sudo, if it may).
    #[serde(default)]
    pub identity: Option<Identity>,
    pub calls: Vec<Call>,
}
fn umask() -> u16 {
    0o022
}

/// Who a batch's calls are from: a browser (its namespace and cookies), as its client kernel,
/// a page or, with a token, one of its processes; the page's account, once asked of the
/// authority.
struct Caller {
    class: registry::Caller,
    ns: String,
    cookie: Option<String>,
    sudo: bool,
    umask: u16,
    pid: Option<u32>,
    token: Option<String>,
    identity: RefCell<Option<std::result::Result<Identity, Error>>>,
}

impl Machine {
    /// The calls of a batch, in order, each in a transaction of its own. Consecutive execve
    /// calls, a pipeline's stages, are asked of the authority at once.
    async fn batch(&self, caller: &Caller, calls: Vec<Call>) -> Result<Vec<Return>> {
        if calls.len() > BATCH_MAX {
            return Ok(vec![Return::Err(Error::because(
                Errno::E2BIG,
                format!("A batch takes at most {BATCH_MAX} calls"),
            ))]);
        }
        let count = calls.len() as u64;
        transact(&self.state, move |db| {
            db.observe("syscalls", count);
            ((), true)
        })?;
        let mut results = Vec::with_capacity(calls.len());
        let mut calls = calls.into_iter().peekable();
        while let Some(call) = calls.next() {
            if let Call::Execve { .. } = call {
                let mut execs = vec![call];
                while matches!(calls.peek(), Some(Call::Execve { .. })) {
                    execs.extend(calls.next());
                }
                results.extend(self.execve(caller, execs).await?);
                continue;
            }
            results.push(match self.call(caller, call).await? {
                Ok(value) => Return::Ok(value),
                Err(error) => Return::Err(error),
            });
        }
        Ok(results)
    }

    /// The page's account, as the authority finds it, once a batch asks.
    async fn identity(&self, caller: &Caller) -> Result<std::result::Result<Identity, Error>> {
        if let Some(found) = caller.identity.borrow().as_ref() {
            return Ok(found.clone());
        }
        let answer = self
            .authority(
                "/internal/identity",
                caller.cookie.as_deref(),
                &json!({ "sudo": caller.sudo }),
            )
            .await?;
        let found = match answer {
            Ok(value) => serde_json::from_value::<Identity>(value)
                .map_err(|error| Error::because(Errno::EIO, error.to_string())),
            Err(error) => Err(error),
        };
        *caller.identity.borrow_mut() = Some(found.clone());
        Ok(found)
    }

    /// One call that is not an execve.
    async fn call(&self, caller: &Caller, call: Call) -> Result<std::result::Result<Value, Error>> {
        let acting = match registry::permit(caller.class, &call) {
            Ok(acting) => acting,
            Err(error) => return Ok(Err(error)),
        };
        // What acts as an account acts as the page's, unless a process's token says whose.
        let identity = match acting {
            Acting::Account if caller.token.is_none() => match self.identity(caller).await? {
                Ok(identity) => Some(identity),
                Err(error) => return Ok(Err(error)),
            },
            _ => None,
        };
        let (ns, pid, token) = (caller.ns.clone(), caller.pid, caller.token.clone());
        let reserved = self.reserved.get();
        let told = call.clone();
        let result = transact(&self.state, move |db| {
            let asked = Asked {
                ns: &ns,
                pid,
                token: token.as_deref(),
                identity: identity.as_ref(),
                reserved,
            };
            let result = run(db, &asked, call);
            let commit = result.is_ok();
            (result, commit)
        })?;
        // A signal is told to the tab that runs the process, on its browser's events line.
        if let (Ok(_), Call::Kill { pid, signal }) = (&result, told)
            && let abi::Target::Pid(pid) = abi::Target::of(&pid)
        {
            let told = json!({ "ns": caller.ns, "value": { "signal": {
                "pid": pid,
                "signal": signal.unwrap_or(abi::SIGTERM),
            } } });
            let _ = self.authority("/internal/tell", None, &told).await;
        }
        Ok(result)
    }

    /// execve of each of `calls`, a pipeline's stages: the registry gives each a pid, the
    /// authority checks each image and snapshots the caller in one request, and each process
    /// starts.
    async fn execve(&self, caller: &Caller, calls: Vec<Call>) -> Result<Vec<Return>> {
        if let Some(Err(error)) = calls
            .first()
            .map(|call| registry::permit(caller.class, call))
        {
            return Ok(calls.iter().map(|_| Return::Err(error.clone())).collect());
        }
        let now = auth::now();
        let ns = caller.ns.clone();
        let asked: Vec<Call> = calls.clone();
        let reserved = self.reserved.get();
        // First, each stage's pid; what fails here is not asked further. A new process's pid
        // counts against the namespace's room until it starts, with those other execs hold.
        let begun: Vec<std::result::Result<Begun, Error>> = transact(&self.state, move |db| {
            let mut new = 0;
            let begun: Vec<_> = asked
                .iter()
                .map(|call| match call {
                    Call::Execve {
                        pid,
                        token,
                        argv,
                        env,
                        cgroup,
                        ..
                    } => {
                        let begun = db.exec_begin(
                            &ns,
                            *pid,
                            token.as_deref(),
                            argv,
                            env,
                            cgroup.as_deref(),
                            reserved + new,
                            now,
                        );
                        if matches!(&begun, Ok(begun) if begun.replacing.is_none()) {
                            new += 1;
                        }
                        begun
                    }
                    _ => Err(Errno::EINVAL.into()),
                })
                .collect();
            (begun, true)
        })?;
        let count = begun
            .iter()
            .filter(|begun| matches!(begun, Ok(begun) if begun.replacing.is_none()))
            .count();
        self.reserved.set(self.reserved.get() + count);
        let _reservation = Reservation {
            reserved: &self.reserved,
            count,
        };
        let tokens: Vec<String> = calls.iter().map(|_| auth::random_token()).collect();
        let execs: Vec<Value> = calls
            .iter()
            .zip(&begun)
            .zip(&tokens)
            .filter_map(|((call, begun), token)| {
                let (
                    Call::Execve {
                        path,
                        cwd,
                        seat,
                        cgroup,
                        ..
                    },
                    Ok(begun),
                ) = (call, begun)
                else {
                    return None;
                };
                Some(json!({
                    "pid": begun.pid,
                    "token": auth::token_hash(token),
                    "path": path,
                    "cwd": cwd,
                    "seat": seat.as_ref().or(begun.seat.as_ref()),
                    "cgroup": begun.cgroup.as_ref().or(cgroup.as_ref()),
                    "replacing": begun.replacing,
                    "old": begun.old,
                    "current": begun.current,
                }))
            })
            .collect();
        let revoke = transact(&self.state, |db| (db.revoking(), false))?;
        let answered = if execs.is_empty() {
            Ok(Value::Null)
        } else {
            self.authority(
                "/internal/exec",
                caller.cookie.as_deref(),
                &json!({
                    "ns": caller.ns,
                    "sudo": caller.sudo,
                    "umask": caller.umask,
                    "execs": execs,
                    "revoke": revoke,
                }),
            )
            .await?
        };
        // The revocations it took went with an answer, not a refusal: only then are they done.
        let mut images: Vec<Return> = match answered {
            Ok(value) => {
                let images = serde_json::from_value(value["results"].clone()).unwrap_or_default();
                let revoked = revoke.clone();
                transact(&self.state, move |db| {
                    db.revoked(&revoked);
                    ((), true)
                })?;
                images
            }
            Err(error) => execs.iter().map(|_| Return::Err(error.clone())).collect(),
        };
        images.reverse();
        let mut results = Vec::with_capacity(calls.len());
        for ((call, begun), token) in calls.into_iter().zip(begun).zip(tokens) {
            let begun = match begun {
                Ok(begun) => begun,
                Err(error) => {
                    results.push(Return::Err(error));
                    continue;
                }
            };
            let image = match images.pop() {
                Some(Return::Ok(image)) => image,
                Some(Return::Err(error)) => {
                    results.push(Return::Err(error));
                    continue;
                }
                None => {
                    results.push(Return::Err(Error::because(
                        Errno::EIO,
                        "the authority answered no image",
                    )));
                    continue;
                }
            };
            let Call::Execve {
                argv,
                env,
                cwd,
                cgroup,
                seat,
                ..
            } = call
            else {
                continue;
            };
            let snapshot: Snapshot = match serde_json::from_value(image.clone()) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    results.push(Return::Err(Error::because(Errno::EIO, error.to_string())));
                    continue;
                }
            };
            // A replaced process stays in its cgroup.
            let cgroup = begun
                .cgroup
                .clone()
                .or(cgroup)
                .unwrap_or_else(|| "/user".into());
            let seat = seat.or_else(|| begun.seat.clone());
            let path = image["path"].as_str().unwrap_or_default().to_string();
            let (ns, hash) = (caller.ns.clone(), auth::token_hash(&token));
            let row = (begun.clone(), path.clone(), cgroup.clone());
            let placement =
                crate::placement::browser(&caller.ns, snapshot.uid, seat.as_deref(), &cgroup);
            let started = transact(&self.state, move |db| {
                let (begun, path, cgroup) = row;
                let started = db.exec_end(
                    &ns,
                    &begun,
                    &snapshot,
                    &hash,
                    &path,
                    &argv,
                    &env,
                    &cwd,
                    &cgroup,
                    seat.as_deref(),
                    now,
                );
                if started.is_ok() {
                    db.observe("execs", 1);
                }
                (started, true)
            })?;
            if let Err(error) = started {
                results.push(Return::Err(error));
                continue;
            }
            results.push(Return::Ok(json!(Exec {
                pid: begun.pid,
                token,
                fd: image["fd"].as_u64().map(|fd| fd as u32),
                asset: image["asset"].as_str().map(str::to_string),
                path: Some(path),
                size: image["size"].as_u64().unwrap_or(0),
                token_read: image["token_read"].as_str().map(str::to_string),
                version: image["version"].as_str().map(str::to_string),
                cgroup,
                placement,
            })));
        }
        Ok(results)
    }

    /// Ask the authority `endpoint`, with the browser's cookies: its value, or its errno.
    async fn authority(
        &self,
        endpoint: &str,
        cookie: Option<&str>,
        body: &Value,
    ) -> Result<std::result::Result<Value, Error>> {
        let headers = Headers::new();
        headers.set("Content-Type", "application/json")?;
        if let Some(cookie) = cookie {
            headers.set("Cookie", cookie)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.to_string().into()));
        let req = Request::new_with_init(&format!("https://authority{endpoint}"), &init)?;
        let mut response = self
            .env
            .durable_object("AUTHORITY")?
            .id_from_name("filesystem")?
            .get_stub()?
            .fetch_with_request(req)
            .await?;
        let status = response.status_code();
        let value: Value = response.json().await.unwrap_or(Value::Null);
        if status == 200 {
            return Ok(Ok(value));
        }
        let errno = serde_json::from_value(value["errno"].clone()).unwrap_or(Errno::EIO);
        let detail = value["error"]
            .as_str()
            .unwrap_or("the authority refused")
            .to_string();
        Ok(Err(Error::because(errno, detail)))
    }

    /// Revoke what waits to be revoked, and wake to try again if any of it is left: a failure
    /// is logged, not answered, as the calls that ended the processes stand.
    async fn settle(&self) {
        if let Err(error) = self.flush().await {
            console_error!("revocation failed: {error}");
        }
        if let Err(error) = self.schedule().await {
            console_error!("the revocation alarm could not be set: {error}");
        }
    }

    /// Revoke at the authority the tokens no process holds any more.
    async fn flush(&self) -> Result<()> {
        let (ns, tokens, renew) = transact(&self.state, |db| {
            ((db.namespace_id(), db.revoking(), db.renewing()), false)
        })?;
        let Some(ns) = ns else { return Ok(()) };
        if tokens.is_empty() && renew.is_empty() {
            return Ok(());
        }
        if self
            .authority(
                "/internal/revoke",
                None,
                &json!({ "ns": ns, "tokens": tokens, "renew": renew }),
            )
            .await?
            .is_ok()
        {
            transact(&self.state, move |db| {
                db.revoked(&tokens);
                db.renewed(&renew);
                ((), true)
            })?;
        }
        Ok(())
    }

    /// Wake to revoke what waits, if anything does and no alarm is set.
    async fn schedule(&self) -> Result<()> {
        let deadline = transact(&self.state, |db| {
            let retry = (!db.revoking().is_empty() || !db.renewing().is_empty())
                .then_some(auth::now() + REVOKE_AFTER as u64 / 1000);
            let next = [retry, db.lease_deadline()].into_iter().flatten().min();
            (next, false)
        })?;
        if let Some(deadline) = deadline {
            let storage = self.state.storage();
            let when = deadline as f64 * 1000.0;
            if storage
                .get_alarm()
                .await?
                .is_none_or(|alarm| alarm as f64 > when)
            {
                storage
                    .set_alarm(((deadline.saturating_sub(auth::now()) * 1000) as i64).max(1))
                    .await?;
            }
        }
        Ok(())
    }
}

/// The machine of the namespace `ns`.
fn stub(env: &Env, ns: &str) -> Result<Stub> {
    env.durable_object("MACHINE")?.id_from_name(ns)?.get_stub()
}

/// The registry calls a page's batch carried, asked of its browser's machine with the caller
/// the authority finds (root under sudo, if it may; none, and the machine asks again for the
/// error, if not).
pub async fn forward(
    env: &Env,
    state: &State,
    session: &crate::sys::Session,
    cookie: Option<String>,
    calls: Vec<Call>,
) -> Result<Vec<Return>> {
    let (key, guest, sudo) = (session.key.clone(), session.guest.clone(), session.sudo);
    let identity = transact(state, move |db| {
        (
            crate::sys::caller(db, key.as_deref(), guest.as_deref(), sudo).ok(),
            true,
        )
    })?;
    let ns = Db::namespace(session.key.as_deref(), session.guest.as_deref());
    let count = calls.len();
    let body = json!({
        "ns": ns,
        "cookie": cookie,
        "sudo": session.sudo,
        "umask": session.umask.unwrap_or(0o022),
        "pid": session.pid,
        "proc": session.token,
        "identity": identity,
        "calls": calls,
    });
    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));
    let req = Request::new_with_init("https://machine/internal/sys", &init)?;
    let mut response = stub(env, &ns)?.fetch_with_request(req).await?;
    let results = match response.json::<abi::Results>().await {
        Ok(results) if response.status_code() == 200 => results.results,
        _ => (0..count)
            .map(|_| {
                Return::Err(Error::because(
                    Errno::EIO,
                    "the browser's machine did not answer",
                ))
            })
            .collect(),
    };
    Ok(results)
}

/// The processes of the namespace `ns`, as its machine has them, for /proc.
pub async fn list(env: &Env, ns: &str) -> Result<Vec<procs::Row>> {
    let url = format!(
        "https://machine/internal/list?ns={}",
        js_sys::encode_uri_component(ns)
    );
    let mut response = stub(env, ns)?.fetch_with_str(&url).await?;
    Ok(response.json().await.unwrap_or_default())
}

/// Who a registry call is from, as the machine found it: its namespace, the process's pid and
/// token (a process's call), the account it acts as (the page's, for the kernel's and the
/// page's calls that act as one), and the pids reserved by execs still asking the authority.
struct Asked<'a> {
    ns: &'a str,
    pid: Option<u32>,
    token: Option<&'a str>,
    identity: Option<&'a Identity>,
    reserved: usize,
}

/// A registry call that is not an execve, which `registry::permit` let its caller make.
fn run(db: &mut Db, asked: &Asked, call: Call) -> std::result::Result<Value, Error> {
    let ns = asked.ns;
    let caller = match asked.token {
        Some(token) => Some(
            db.process_token(token, asked.pid, ns)
                .ok_or_else(|| Error::because(Errno::EPERM, "not this process's token"))?,
        ),
        None => None,
    };
    let now = auth::now();
    let process = || {
        caller
            .as_ref()
            .ok_or_else(|| Error::because(Errno::EPERM, "a process's call"))
    };
    // The account a call acts as: the process's snapshot, or the page's.
    let account = || {
        caller
            .as_ref()
            .map(procs::Row::identity)
            .or_else(|| asked.identity.cloned())
            .ok_or(Error::from(Errno::EPERM))
    };
    match call {
        Call::ProcInit { boot } => Ok(db.proc_init(ns, &account()?, boot.as_deref(), now)),
        Call::Fork {
            pid,
            child,
            token: named,
        } => {
            // The parent itself, or the parent its kernel names by its token.
            let (row, token) = match named {
                Some(named) => (
                    db.process_token(&named, Some(pid), ns).ok_or_else(|| {
                        Error::because(Errno::ESRCH, "no such process, or not its token")
                    })?,
                    named,
                ),
                None => (
                    process()?.clone(),
                    asked.token.unwrap_or_default().to_string(),
                ),
            };
            if pid != row.pid {
                return Err(Error::because(
                    Errno::EINVAL,
                    "fork is called by its parent",
                ));
            }
            let forked = db.fork(&row, child, asked.reserved, now)?;
            db.observe("forks", 1);
            Ok(json!(Forked {
                pid: forked.pid,
                // The child carries its parent's token, as it keeps its credentials.
                token,
            }))
        }
        Call::Exit {
            status,
            signal,
            pid: named,
            token: named_token,
        } => {
            // The process itself, or one its kernel names by pid and token.
            let row = match (named, named_token) {
                (Some(named), Some(named_token)) => db
                    .process_token(&named_token, Some(named), ns)
                    .ok_or_else(|| {
                        Error::because(Errno::ESRCH, "no such process, or not its token")
                    })?,
                _ => process()?.clone(),
            };
            db.exit(&row, status, signal, now)?;
            Ok(Value::Null)
        }
        Call::Pids { count, kernel } => Ok(json!(db.lend(
            ns,
            &account()?,
            asked.token,
            count,
            kernel.as_deref(),
            asked.reserved,
            now
        )?)),
        Call::Seats => Ok(db.seats(ns, &account()?)),
        Call::Gone { seat, kernel } => {
            let cred = account()?;
            let reaped = seat
                .map(|seat| db.gone(ns, &cred, &seat, now))
                .transpose()?
                .unwrap_or_default();
            if let Some(kernel) = kernel {
                db.reclaim(&kernel, &cred)?;
            }
            Ok(json!(reaped))
        }
        Call::Getpid => {
            let row = process()?;
            Ok(json!({ "pid": row.pid, "ppid": row.ppid }))
        }
        Call::ProcPoll { pids } => {
            if pids.len() > abi::PROC_POLL_MAX {
                return Err(Error::because(
                    Errno::E2BIG,
                    format!("at most {} processes at a time", abi::PROC_POLL_MAX),
                ));
            }
            Ok(json!(db.poll(ns, &pids, &account()?)))
        }
        Call::ProcTty {
            pid,
            token,
            tty,
            fds,
        } => {
            db.terminal(ns, pid, &token, tty, &fds)?;
            Ok(Value::Null)
        }
        Call::ProcKeep { processes } => {
            if processes.len() > abi::PROC_POLL_MAX {
                return Err(Errno::E2BIG.into());
            }
            Ok(json!(db.keep_processes(ns, &processes, now)))
        }
        Call::Kill {
            pid: target,
            signal,
        } => {
            let abi::Target::Pid(target) = abi::Target::of(&target) else {
                return Err(Errno::ESRCH.into());
            };
            db.kill(ns, &account()?, target, signal.unwrap_or(abi::SIGTERM), now)?;
            Ok(Value::Null)
        }
        Call::Wait {
            pid: target, token, ..
        } => {
            let abi::Target::Pid(want) = abi::Target::of(&target) else {
                return Err(Errno::ECHILD.into());
            };
            let waited = match caller.as_ref() {
                Some(row) => db.wait(ns, Some(row.pid), want),
                None => db.reap(ns, asked.identity, want, token.as_deref()),
            }?;
            Ok(json!(waited))
        }
        Call::CgroupCreate { path, controllers } => db
            .cgroup_create(ns, &account()?, &path, controllers.as_deref())
            .map(|()| Value::Null),
        Call::CgroupRemove { path } => db
            .cgroup_remove(ns, &account()?, &path)
            .map(|()| Value::Null),
        Call::CgroupSet { path, key, value } => db
            .cgroup_set(ns, &account()?, &path, &key, &value)
            .map(|()| Value::Null),
        Call::CgroupAttach { pid, path } => db
            .cgroup_attach(ns, &account()?, pid, &path)
            .map(|()| Value::Null),
        Call::CgroupStat { path } => db.cgroup_stat(ns, &path),
        Call::CgroupList { path } => Ok(json!(db.cgroup_list(ns, &path))),
        _ => Err(Errno::ENOSYS.into()),
    }
}
