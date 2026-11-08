//! The JobRunner: one Durable Object, with its container (crates/jobs), a job. Its
//! alarm does the work in steps, keeping its plan in its own storage, so that a restart, of it
//! or of the container, resumes rather than starts over:
//!
//! - extracting: send the archive, list it, plan where each member goes (asking, through the
//!   job, about files that exist), then write member by member, a chunk at a time;
//! - listing: send the archive and write its members' names;
//! - creating: send the inputs, build the archive, and store it a chunk at a time. Building is
//!   deterministic, so after an interruption the chunks already stored are checked against
//!   the new build's, and the upload starts over only if one differs.
//!
//! Bytes go between R2 and the container as streams. The job is a process (Phase 4): its spawn
//! handed this runner the job's token, the one key to its credentials, and every file the job
//! looks at or writes goes through the system calls with it (`sys`, and pwrite's two halves for
//! a chunk), checked as any process's are, as who started it was then.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::time::Duration;

use abi::{Call, Errno, O_CREAT, O_EXCL, O_TRUNC, O_WRONLY, Return};
use serde::Deserialize;
use serde_json::{Value, json};
use terminal_worker_core::CHUNK_SIZE;
use terminal_worker_core::archive::{Existing, Job as Command, member_path};
use terminal_worker_core::permissions::{mode_text, type_mode_text};
use wasm_bindgen::JsValue;
use worker::*;

use crate::db::Job;
use crate::files::decode_hex;
use crate::jobs::Spec;
use crate::streams;

/// The job server's port in its container.
const PORT: u16 = 8080;
/// How long one alarm works before handing over to the next.
const BUDGET: f64 = 20_000.0;
/// How many failed steps in a row end a job.
const ATTEMPTS: u32 = 5;

#[durable_object]
pub struct JobRunner {
    state: State,
    env: Env,
    /// The directories a step made or found, which it does not make again.
    made: RefCell<std::collections::BTreeSet<String>>,
}

/// What a step leaves to do.
enum Step {
    /// More work: the next alarm continues.
    More,
    /// Nothing until someone answers the job's question.
    Wait,
    Done,
}

/// A file the job writes: its descriptor, its path, whether the job made it (or writes over
/// one there), the member it is (extraction), how many of its chunks are recorded, and their
/// SHA-256 (a new archive's), so that a rebuild after a restart goes on only if it is the same.
#[derive(serde::Serialize, Deserialize)]
struct Writing {
    fd: u32,
    path: String,
    created: bool,
    index: Option<u64>,
    written: u64,
    #[serde(default)]
    hashes: Vec<Option<String>>,
}

/// Lines a step writes to its job: to standard output, or with `err`, to standard error.
#[derive(Default)]
struct Lines(Vec<(bool, String)>);
impl Lines {
    fn out(&mut self, line: impl Into<String>) {
        self.0.push((false, line.into()));
    }
    fn err(&mut self, line: impl Into<String>) {
        self.0.push((true, line.into()));
    }
}

#[derive(Deserialize)]
struct Row {
    idx: u64,
    name: String,
    size: u64,
    /// The member's permission bits, if the archive keeps them: a zip made elsewhere may not.
    mode: Option<u32>,
    /// file, directory, symlink or hardlink.
    kind: String,
    target: String,
    action: String,
    /// A symbolic link's target, as written, or the path a hard link names.
    link: Option<String>,
}
/// A plan's columns, as a [`Row`].
const ROW: &str = "idx, name, size, mode, kind, target, action, link";

/// The permission bits a member gets, as each tool gives them: unzip those archived, as tar
/// does for root, setuid, setgid and sticky too; tar for others less the umask (022). Without
/// any, 644 for a file and 755 for a directory.
fn extracted_mode(cmd: &str, root: bool, mode: Option<u32>, directory: bool) -> u32 {
    match mode {
        Some(mode) if cmd == "tar" && root => mode & 0o7777,
        Some(mode) if cmd == "tar" => mode & 0o777 & !0o022,
        Some(mode) => mode & 0o777,
        None if directory => 0o755,
        None => 0o644,
    }
}

impl DurableObject for JobRunner {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            made: RefCell::default(),
        }
    }
    /// `{job, token}`: the job to work on, and, as it spawned, its token, kept here alone.
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        #[derive(Deserialize)]
        struct Start {
            job: String,
            #[serde(default)]
            token: Option<String>,
        }
        let url = req.url()?;
        let Ok(start) = req.json::<Start>().await else {
            return Response::error("Unknown runner request", 404);
        };
        if url.path() != "/start" || start.job.is_empty() {
            return Response::error("Unknown runner request", 404);
        }
        let storage = self.state.storage();
        if let Some(token) = start.token {
            storage.put("token", &token).await?;
        } else if storage.get::<String>("token").await?.is_none() {
            // Woken with no token, and given none before: its job ended (a runner that finished
            // forgets it), or never reached it. There is nothing to do.
            return Response::ok("idle");
        }
        storage.put("job", &start.job).await?;
        storage.set_alarm(1).await?;
        Response::ok("started")
    }
    async fn alarm(&self) -> Result<Response> {
        let storage = self.state.storage();
        let Some(job) = storage.get::<String>("job").await? else {
            return Response::ok("idle");
        };
        match self.work(&job).await {
            Ok(Step::More) => {
                storage.put("failures", 0u32).await?;
                storage.set_alarm(1).await?;
            }
            Ok(Step::Wait) => {
                storage.put("failures", 0u32).await?;
                // Revocation/last-close must also reach an idle executor with no page left
                // to wake it. This lease check releases its container after cancellation.
                storage.set_alarm(5000).await?;
            }
            Ok(Step::Done) => self.close().await,
            Err(e) => {
                let failures = storage.get::<u32>("failures").await?.unwrap_or(0) + 1;
                console_error!(
                    "job {} step failed ({} of {}): {}",
                    job,
                    failures,
                    ATTEMPTS,
                    e
                );
                if failures >= ATTEMPTS {
                    let _ = self
                        .call(
                            Method::Post,
                            "/internal/job/update",
                            Some(json!({"lines": [[true, format!("The job failed: {e}")]]})),
                        )
                        .await;
                    let _ = self.abort_upload().await;
                    let _ = self
                        .call(
                            Method::Post,
                            "/internal/job/finish",
                            Some(json!({"state": "failed"})),
                        )
                        .await;
                    self.close().await;
                } else {
                    // Said in the job too, which would otherwise seem to hang.
                    let _ = self
                        .call(
                            Method::Post,
                            "/internal/job/update",
                            Some(json!({"lines": [[true, format!(
                                "Attempt {failures} of {ATTEMPTS} failed, trying again: {e}"
                            )]]})),
                        )
                        .await;
                    storage.put("failures", failures).await?;
                    storage.set_alarm(i64::from(2000 * failures)).await?;
                }
            }
        }
        Response::ok("")
    }
}

impl JobRunner {
    /// The job's token, which its spawn handed over.
    async fn token(&self) -> Result<String> {
        self.state
            .storage()
            .get::<String>("token")
            .await?
            .ok_or_else(|| Error::RustError("the job was given no token".into()))
    }
    /// Ask the authority, as the job: its token goes with the request.
    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let headers = Headers::new();
        headers.set("X-Process-Token", &self.token().await?)?;
        let mut init = RequestInit::new();
        init.with_method(method);
        if let Some(body) = body {
            headers.set("Content-Type", "application/json")?;
            init.with_body(Some(body.to_string().into()));
        }
        init.with_headers(headers);
        let mut response = self
            .env
            .durable_object("AUTHORITY")?
            .id_from_name("filesystem")?
            .get_stub()?
            .fetch_with_request(Request::new_with_init(
                &format!("https://authority{path}"),
                &init,
            )?)
            .await?;
        let status = response.status_code();
        Ok((status, response.json().await.unwrap_or_default()))
    }
    /// Ask the authority, failing the step on an error reply.
    async fn ask(&self, method: Method, path: &str, body: Option<Value>) -> Result<Value> {
        let (status, value) = self.call(method, path, body).await?;
        if status >= 400 {
            return Err(Error::RustError(
                value["error"]
                    .as_str()
                    .unwrap_or("The authority refused")
                    .to_string(),
            ));
        }
        Ok(value)
    }
    async fn update(&self, lines: Lines, progress: Option<Value>) -> Result<String> {
        let mut body =
            json!({"lines": lines.0.iter().map(|(e, l)| json!([e, l])).collect::<Vec<_>>()});
        if let Some(progress) = progress {
            body["progress"] = progress;
        }
        let value = self
            .ask(Method::Post, "/internal/job/update", Some(body))
            .await?;
        Ok(value["state"].as_str().unwrap_or_default().to_string())
    }
    async fn close(&self) {
        if let Some(container) = self.state.container()
            && container.running()
        {
            let _ = container.destroy(None).await;
        }
        let _ = self.state.storage().delete_all().await;
    }
    /// Let go of the file being written, if any: its descriptor closes, and the unfinished file
    /// with it (`Discard`): one the job made goes, one it wrote over keeps its old content.
    async fn abort_upload(&self) -> Result<()> {
        if let Some(writing) = self.writing().await? {
            // The kernel lets go of the file by its content, not its name: what is at the name
            // now may be another's.
            self.one(Call::Discard {
                fd: writing.fd.into(),
            })
            .await?
            .ok();
            self.state.storage().delete("writing").await?;
        }
        Ok(())
    }

    // ---- The job's system calls ----

    /// `calls`, as the job makes them (its token), a batch at a time: each one's result.
    async fn sys(&self, calls: Vec<Call>) -> Result<Vec<std::result::Result<Value, abi::Error>>> {
        let token = self.token().await?;
        let mut results = Vec::with_capacity(calls.len());
        for batch in calls.chunks(abi::BATCH_MAX) {
            let body = json!({"calls": batch, "proc": token}).to_string();
            let headers = Headers::new();
            headers.set("Content-Type", "application/json")?;
            // A batch says its length (sys.rs), as a browser's request does.
            headers.set("Content-Length", &body.len().to_string())?;
            let mut init = RequestInit::new();
            init.with_method(Method::Post);
            init.with_headers(headers);
            init.with_body(Some(body.into()));
            let mut response = self
                .env
                .durable_object("AUTHORITY")?
                .id_from_name("filesystem")?
                .get_stub()?
                .fetch_with_request(Request::new_with_init("https://authority/api/sys", &init)?)
                .await?;
            if response.status_code() != 200 {
                return Err(Error::RustError(format!(
                    "the kernel refused the job's calls ({})",
                    response.status_code()
                )));
            }
            let answered: abi::Results = response.json().await?;
            results.extend(answered.results.into_iter().map(Return::into_result));
        }
        Ok(results)
    }
    /// One call, as the job makes it.
    async fn one(&self, call: Call) -> Result<std::result::Result<Value, abi::Error>> {
        Ok(self
            .sys(vec![call])
            .await?
            .pop()
            .unwrap_or_else(|| Err(Errno::EIO.into())))
    }
    /// lstat(2) of each of `paths`: the mode of those there where the job may look. What lies
    /// where it may not is not told, not even whether it is there: writing it fails, as for a
    /// path that is not.
    async fn modes(&self, paths: &[&String]) -> Result<BTreeMap<String, u32>> {
        let calls = paths
            .iter()
            .map(|path| Call::Lstat {
                path: path.to_string(),
            })
            .collect();
        Ok(paths
            .iter()
            .zip(self.sys(calls).await?)
            .filter_map(|(path, found)| {
                Some((path.to_string(), found.ok()?["mode"].as_u64()? as u32))
            })
            .collect())
    }
    /// mkdir -p of `path`, below `base`, which is there: each directory on the way that is not
    /// there yet, made with the job's umask.
    /// Those this step made or found already are not asked again.
    async fn mkdirs(&self, base: &str, path: &str) -> Result<std::result::Result<(), String>> {
        let mut at = base.trim_end_matches('/').to_string();
        let mut wanted = Vec::new();
        for part in path
            .strip_prefix(base)
            .unwrap_or(path)
            .split('/')
            .filter(|part| !part.is_empty())
        {
            at = format!("{at}/{part}");
            if !self.made.borrow().contains(&at) {
                wanted.push(at.clone());
            }
        }
        if wanted.is_empty() {
            return Ok(Ok(()));
        }
        let calls = wanted
            .iter()
            .map(|path| Call::Mkdir {
                path: path.clone(),
                mode: 0o777,
            })
            .collect();
        for (path, made) in wanted.into_iter().zip(self.sys(calls).await?) {
            match made {
                Err(error) if error.errno != Errno::EEXIST => return Ok(Err(error.to_string())),
                _ => {
                    self.made.borrow_mut().insert(path);
                }
            }
        }
        Ok(Ok(()))
    }
    /// Open `path` to write `size` bytes, as open(2) with O_CREAT: a new file with `mode`, as an
    /// archive gives it (the umask takes nothing from it, and root's keeps setuid, setgid and
    /// sticky), or, with `replace`, over the one there: removed first if `unlink` (extraction,
    /// so that it is the extractor's and other names keep the old one) or a link, written over
    /// in place otherwise (a new archive, faststart). Its descriptor, or none if one is there
    /// and is kept.
    async fn open_write(
        &self,
        path: &str,
        size: u64,
        replace: bool,
        unlink: bool,
        mode: Option<u32>,
    ) -> Result<std::result::Result<Option<Writing>, String>> {
        let there = self.modes(&[&path.to_string()]).await?.remove(path);
        let mut overwrite = false;
        if let Some(had) = there {
            if had & 0o170000 == 0o040000 {
                return Ok(Err("a directory with this name already exists".into()));
            }
            if !replace {
                return Ok(Ok(None));
            }
            if unlink || had & 0o170000 == 0o120000 {
                if let Err(error) = self.one(Call::Unlink { path: path.into() }).await? {
                    return Ok(Err(error.to_string()));
                }
            } else {
                overwrite = true;
            }
        }
        let mut calls = vec![Call::Open {
            path: path.into(),
            flags: O_WRONLY | O_CREAT | if overwrite { O_TRUNC } else { O_EXCL },
            mode: mode.map_or(0o666, |mode| (mode & 0o777) as u16),
            size: Some(size),
            sha256: None,
            version: None,
        }];
        // Through the descriptor the open made, in the same batch, as fchmod(2): nothing is
        // changed if the open failed, and no name is followed to another file.
        if let (false, Some(mode)) = (overwrite, mode) {
            calls.push(Call::Fchmod {
                fd: abi::FdRef::Ref { call: 0 },
                mode: (mode & 0o7777) as u16,
            });
        }
        let mut results = self.sys(calls).await?.into_iter();
        let opened = match results.next() {
            Some(Ok(opened)) => opened,
            Some(Err(error)) => return Ok(Err(error.to_string())),
            None => return Ok(Err("cannot be written".into())),
        };
        Ok(Ok(Some(Writing {
            fd: opened["fd"].as_u64().unwrap_or(u64::from(u32::MAX)) as u32,
            path: path.into(),
            created: !overwrite,
            index: None,
            written: 0,
            hashes: Vec::new(),
        })))
    }
    /// pwrite(2) of chunk `index` of what `writing` writes: `length` bytes the container serves
    /// at `url`, stored where the kernel says, then recorded, as a process's pwrite is.
    async fn pwrite(
        &self,
        fetcher: &Fetcher,
        writing: &Writing,
        index: u64,
        url: &str,
        length: u64,
        sha256: Option<&str>,
    ) -> Result<()> {
        let grant = self
            .ask(
                Method::Get,
                &format!(
                    "/internal/pwrite?fd={}&index={index}&length={length}",
                    writing.fd
                ),
                None,
            )
            .await?;
        let key = grant["key"].as_str().unwrap_or_default().to_string();
        self.store(fetcher, url, &key, length, sha256).await?;
        self.ask(
            Method::Post,
            "/internal/pwrite/commit",
            Some(json!({
                "fd": writing.fd, "index": index, "key": key, "sha256": sha256, "length": length,
            })),
        )
        .await?;
        Ok(())
    }
    /// close(2) of what `writing` writes, which completes it.
    /// What is being written is forgotten only once the kernel answered the close: a close
    /// that did not arrive is sent again by the next step.
    async fn close_write(&self, writing: &Writing) -> Result<std::result::Result<(), String>> {
        let closed = self
            .one(Call::Close {
                fd: writing.fd.into(),
            })
            .await?;
        self.state.storage().delete("writing").await?;
        Ok(closed.map(|_| ()).map_err(|error| error.to_string()))
    }
    /// Whether the descriptor `writing` writes through is still open (a descriptor not used for
    /// an hour, or whose file another took over, is not). Asking keeps the job's descriptors.
    async fn open_still(&self, writing: &Writing) -> Result<bool> {
        Ok(self
            .one(Call::Readlink {
                path: format!("/proc/self/fd/{}", writing.fd),
            })
            .await?
            .is_ok())
    }
    /// The file being written, if a step after a restart may go on with it on its descriptor:
    /// else, what it made is let go of (by its descriptor, or, the descriptor gone, by its name,
    /// for a file the job made), and the file is written again.
    async fn resumable(&self, writing: Writing, same: bool) -> Result<Option<Writing>> {
        let open = self.open_still(&writing).await?;
        if open && same {
            return Ok(Some(writing));
        }
        if open {
            self.abort_upload().await?;
        } else {
            if writing.created {
                self.one(Call::Unlink {
                    path: writing.path.clone(),
                })
                .await?
                .ok();
            }
            self.state.storage().delete("writing").await?;
        }
        Ok(None)
    }
    /// The file being written, kept so that a step after a restart goes on with it.
    async fn writing(&self) -> Result<Option<Writing>> {
        Ok(self
            .state
            .storage()
            .get::<String>("writing")
            .await?
            .and_then(|text| serde_json::from_str(&text).ok()))
    }
    async fn keep_writing(&self, writing: &Writing) -> Result<()> {
        self.state
            .storage()
            .put(
                "writing",
                serde_json::to_string(writing).unwrap_or_default(),
            )
            .await
    }

    /// The container's server, started if need be.
    async fn container(&self) -> Result<Fetcher> {
        let container = self.state.container().ok_or_else(|| {
            Error::RustError(
                "Containers are not available; see the README's archive section".into(),
            )
        })?;
        // A container that cannot start says so only to its monitor: keep why, so as to stop
        // waiting for it at once.
        let ended = Rc::new(RefCell::new(None::<String>));
        if !container.running() {
            container.start(None)?;
            if let Some(watched) = self.state.container() {
                let ended = ended.clone();
                wasm_bindgen_futures::spawn_local(async move {
                    let why = match watched.wait_for_exit().await {
                        Ok(()) => "it exited".to_string(),
                        Err(e) => e.to_string(),
                    };
                    *ended.borrow_mut() = Some(why);
                });
            }
        }
        let fetcher = container.get_tcp_port(PORT)?;
        for _ in 0..120 {
            if let Some(why) = ended.borrow_mut().take() {
                return Err(Error::RustError(format!(
                    "The job container did not start: {why}"
                )));
            }
            if let Ok(response) = fetcher.fetch("http://jobs/status", None).await
                && response.status_code() == 200
            {
                return Ok(fetcher);
            }
            Delay::from(Duration::from_millis(500)).await;
        }
        Err(Error::RustError("The job container did not start".into()))
    }
    async fn status(&self, fetcher: &Fetcher, job: &str) -> Result<Value> {
        let mut response = fetcher.fetch("http://jobs/status", None).await?;
        let status: Value = response.json().await?;
        // Another job's files, or none: start again from nothing.
        Ok(if status["job"].as_str() == Some(job) {
            status
        } else {
            json!({})
        })
    }
    /// Send the file the job pins, `file`, to the container at `url`.
    async fn send(&self, fetcher: &Fetcher, file: &str, url: &str) -> Result<()> {
        let grant = self
            .ask(
                Method::Get,
                &format!("/internal/job/file?file={file}"),
                None,
            )
            .await?;
        let size = grant["size"].as_u64().unwrap_or(0);
        // A binary of /usr streams from the Worker's assets, as its reads are served.
        if let Some(asset) = grant["asset"].as_str() {
            let response = self
                .env
                .assets("ASSETS")?
                .fetch(format!("https://assets{asset}"), None)
                .await?;
            let (200, ResponseBody::Stream(stream)) = (response.status_code(), response.body())
            else {
                return Err(Error::RustError(format!(
                    "the asset {asset} has no content"
                )));
            };
            let mut init = RequestInit::new();
            init.with_method(Method::Put);
            init.with_body(Some(streams::fixed_length(stream, size as f64).into()));
            let answer = fetcher
                .fetch(format!("http://jobs{url}"), Some(init))
                .await?;
            if answer.status_code() != 200 {
                return Err(Error::RustError(format!("the job container refused {url}")));
            }
            return Ok(());
        }
        let chunk_size = grant["chunk_size"].as_u64().unwrap_or(1).max(1);
        let mut parts: Vec<(u64, String)> = grant["chunks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| Some((c[0].as_u64()?, c[1].as_str()?.to_string())))
            .collect();
        parts.sort();
        let parts = parts
            .into_iter()
            .map(|(index, key)| (key, chunk_size.min(size - index * chunk_size)))
            .collect();
        let mut init = RequestInit::new();
        init.with_method(Method::Put);
        init.with_body(Some(if size == 0 {
            JsValue::from_str("")
        } else {
            streams::objects(self.env.bucket("FILES")?, parts).into()
        }));
        let response = fetcher
            .fetch(format!("http://jobs{url}"), Some(init))
            .await?;
        if response.status_code() != 200 {
            return Err(Error::RustError(format!("the job container refused {url}")));
        }
        Ok(())
    }
    /// Store `length` bytes the container serves at `url` as the R2 object `key`.
    async fn store(
        &self,
        fetcher: &Fetcher,
        url: &str,
        key: &str,
        length: u64,
        sha256: Option<&str>,
    ) -> Result<()> {
        let mut response = fetcher.fetch(format!("http://jobs{url}"), None).await?;
        if response.status_code() != 200 {
            let error: Value = response.json().await.unwrap_or_default();
            return Err(Error::RustError(
                error["error"]
                    .as_str()
                    .unwrap_or("the job container failed")
                    .to_string(),
            ));
        }
        let ResponseBody::Stream(stream) = response.body() else {
            return Err(Error::RustError("the job container sent no content".into()));
        };
        let data = Data::ReadableStream(streams::fixed_length(stream, length as f64));
        let bucket = self.env.bucket("FILES")?;
        let mut put = bucket.put(key, data);
        if let Some(bytes) = sha256.and_then(decode_hex) {
            put = put.sha256(bytes);
        }
        put.execute().await?;
        Ok(())
    }

    async fn work(&self, id: &str) -> Result<Step> {
        // A runner given no token has nothing it may do.
        if self.state.storage().get::<String>("token").await?.is_none() {
            return Ok(Step::Done);
        }
        // What a step made or found of directories, the next one asks again.
        self.made.borrow_mut().clear();
        // A job that ended (done, failed, cancelled) has no credentials any more: its token
        // opens nothing.
        let (status, job) = self.call(Method::Get, "/internal/job", None).await?;
        if status == 403 {
            return Ok(Step::Done);
        }
        if status >= 400 {
            return Err(Error::RustError(
                job["error"]
                    .as_str()
                    .unwrap_or("the job cannot be read")
                    .into(),
            ));
        }
        let job: Job = serde_json::from_value(job).map_err(|e| Error::RustError(e.to_string()))?;
        // The token it was handed is its job's: a runner works on no other.
        if job.id != id {
            return Err(Error::RustError(format!(
                "the job's token is job {}'s, not {id}'s",
                job.id
            )));
        }
        match job.state.as_str() {
            "question" => return Ok(Step::Wait),
            "cancelling" => {
                self.abort_upload().await?;
                self.ask(
                    Method::Post,
                    "/internal/job/finish",
                    Some(json!({"state": "cancelled"})),
                )
                .await?;
                return Ok(Step::Done);
            }
            _ => {}
        }
        if job.state == "queued" {
            self.ask(
                Method::Post,
                "/internal/job/update",
                Some(json!({"state": "running"})),
            )
            .await?;
        }
        let spec = Spec::of(&job).map_err(Error::RustError)?;
        let deadline = Date::now().as_millis() as f64 + BUDGET;
        let step = match &spec.command {
            Command::Extract { .. } => self.extract(&job, &spec, deadline).await?,
            Command::List { .. } => self.list(&job, &spec).await?,
            Command::Create { .. } | Command::Faststart { .. } => {
                self.create(&job, &spec, deadline).await?
            }
        };
        if matches!(step, Step::Done) {
            self.ask(
                Method::Post,
                "/internal/job/finish",
                Some(json!({"state": "done"})),
            )
            .await?;
        }
        Ok(step)
    }

    /// Make sure the container has the job's archive, and has listed it, unpacked if `unpack`.
    async fn prepare(
        &self,
        fetcher: &Fetcher,
        job: &str,
        spec: &Spec,
        unpack: bool,
    ) -> Result<Value> {
        let status = self.status(fetcher, job).await?;
        let source = spec
            .source
            .as_ref()
            .ok_or_else(|| Error::RustError("the job has no archive".into()))?;
        if status["archive"] != true {
            self.send(fetcher, &source.file, &format!("/archive?job={job}"))
                .await?;
        }
        let mut response = fetcher
            .fetch(
                format!(
                    "http://jobs/list?job={job}{}",
                    if unpack { "&unpack=1" } else { "" }
                ),
                Some({
                    let mut init = RequestInit::new();
                    init.with_method(Method::Post);
                    init
                }),
            )
            .await?;
        let status = response.status_code();
        let value: Value = response.json().await?;
        if status != 200 {
            return Err(Error::RustError(format!(
                "{}: {}",
                source.path,
                value["error"].as_str().unwrap_or("cannot be read")
            )));
        }
        Ok(value)
    }

    async fn list(&self, job: &Job, spec: &Spec) -> Result<Step> {
        let Command::List { zip, verbose, .. } = &spec.command else {
            return Ok(Step::Done);
        };
        let fetcher = self.container().await?;
        let listing = self.prepare(&fetcher, &job.id, spec, false).await?;
        let mut lines = Lines::default();
        let members = listing["members"].as_array().cloned().unwrap_or_default();
        let source = spec
            .source
            .as_ref()
            .map(|s| s.path.as_str())
            .unwrap_or_default();
        if *zip {
            lines.out(format!("Archive:  {source}"));
            lines.out("  Length  Name");
            lines.out("---------  ----");
            let mut total = 0;
            for m in &members {
                let size = m["size"].as_u64().unwrap_or(0);
                total += size;
                lines.out(format!(
                    "{size:>9}  {}",
                    m["name"].as_str().unwrap_or_default()
                ));
            }
            lines.out("---------  -------");
            lines.out(format!(
                "{total:>9}  {} file{}",
                members.len(),
                if members.len() == 1 { "" } else { "s" }
            ));
        } else {
            for m in &members {
                let name = m["name"].as_str().unwrap_or_default();
                if *verbose {
                    let kind = match m["kind"].as_str() {
                        Some("directory") => 'd',
                        Some("symlink") => 'l',
                        Some("hardlink") => 'h',
                        _ => '-',
                    };
                    let link = m["link"].as_str().unwrap_or_default();
                    lines.out(format!(
                        "{} {:>9} {name}{}",
                        type_mode_text(m["mode"].as_u64().unwrap_or(0) as u16 & 0o7777, kind),
                        m["size"].as_u64().unwrap_or(0),
                        match kind {
                            'l' => format!(" -> {link}"),
                            'h' => format!(" link to {link}"),
                            _ => String::new(),
                        }
                    ));
                } else {
                    lines.out(name);
                }
            }
        }
        self.update(
            lines,
            Some(json!({"done": members.len(), "total": members.len()})),
        )
        .await?;
        Ok(Step::Done)
    }

    fn sql(&self) -> SqlStorage {
        self.state.storage().sql()
    }
    fn rows(&self, query: &str, args: Vec<SqlStorageValue>) -> Result<Vec<Row>> {
        self.sql().exec(query, args)?.to_array()
    }
    /// How many members of the plan match `condition`.
    fn count(&self, condition: &str) -> Result<usize> {
        #[derive(Deserialize)]
        struct Count {
            n: usize,
        }
        let counted: Count = self
            .sql()
            .exec(
                &format!("SELECT COUNT(*) AS n FROM plan WHERE {condition}"),
                None,
            )?
            .one()?;
        Ok(counted.n)
    }

    async fn extract(&self, job: &Job, spec: &Spec, deadline: f64) -> Result<Step> {
        let Command::Extract {
            zip,
            existing,
            members: wanted,
            verbose,
            ..
        } = &spec.command
        else {
            return Ok(Step::Done);
        };
        let cmd = if *zip { "unzip" } else { "tar" };
        let id = job.id.as_str();
        let directory = spec.directory.clone().unwrap_or_else(|| "/".into());
        let fetcher = self.container().await?;
        let sql = self.sql();
        sql.exec(
            "CREATE TABLE IF NOT EXISTS plan(idx INTEGER PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, mode INTEGER, kind TEXT NOT NULL, target TEXT NOT NULL, action TEXT NOT NULL, link TEXT, done INTEGER NOT NULL)",
            None,
        )?;
        // Said once the plan is made, which may have no members at all.
        let planned = self.state.storage().get::<bool>("planned").await? == Some(true);
        let status = self.status(&fetcher, id).await?;
        if !planned || status["listed"] != true {
            // The container lost its files, or never had them: send and unpack again.
            let listing = self.prepare(&fetcher, id, spec, true).await?;
            if !planned {
                return self
                    .plan(cmd, spec, &directory, *existing, wanted, *verbose, &listing)
                    .await;
            }
        }
        if spec.decisions.is_none() {
            let asking: Vec<String> = self
                .rows(
                    &format!("SELECT {ROW} FROM plan WHERE action = 'ask' ORDER BY idx"),
                    vec![],
                )?
                .into_iter()
                .map(|row| row.target)
                .collect();
            if !asking.is_empty() {
                // A job waiting for its answer does not come here: the step that planned failed
                // before its question reached the job, so ask it now.
                self.ask(
                    Method::Post,
                    "/internal/job/update",
                    Some(json!({"question": {"replace": asking}, "state": "question"})),
                )
                .await?;
                return Ok(Step::Wait);
            }
        }
        let decisions = spec.decisions.clone().unwrap_or_default();
        let total = self.count("1")?;
        let mut done = self.count("done = 1")?;
        // A member that a restart interrupted goes on (`write`), on the descriptor it had.
        let mut lines = Lines::default();
        // Those of the steps before, planning's included, go on counting.
        let mut errors = serde_json::from_str::<Value>(&job.progress).unwrap_or_default()["errors"]
            .as_u64()
            .unwrap_or(0);
        // Members go in order, so the next one is past the last, found through the key; symbolic
        // links after all the rest, as GNU tar makes them, so that nothing this archive holds
        // is written through one it makes.
        let mut after = -1;
        let mut links = false;
        loop {
            let Some(row) = self
                .rows(
                    &format!("SELECT {ROW} FROM plan WHERE done = 0 AND (kind = 'symlink') = ? AND idx > ? ORDER BY idx LIMIT 1"),
                    vec![SqlStorageValue::Integer(links as i64), SqlStorageValue::Integer(after)],
                )?
                .pop()
            else {
                if links {
                    break;
                }
                links = true;
                after = -1;
                continue;
            };
            after = row.idx as i64;
            let replace = match row.action.as_str() {
                "replace" => true,
                "ask" => decisions.get(&row.target).copied().unwrap_or(false),
                _ => false,
            };
            match row.action.as_str() {
                "mkdir" => {
                    if let Err(message) = self.mkdirs(&directory, &row.target).await? {
                        errors += 1;
                        lines.err(format!("{cmd}: {}: {message}", row.target));
                    } else if *verbose {
                        lines.out(if *zip {
                            format!("   creating: {}/", row.target)
                        } else {
                            row.name.clone()
                        });
                    }
                }
                "write" | "replace" | "ask"
                    if row.action != "ask" || decisions.contains_key(&row.target) =>
                {
                    let written = if row.kind == "file" {
                        // A file is made anew, with its mode from the start.
                        let mode = extracted_mode(cmd, job.actor == 0, row.mode, false);
                        self.write(&fetcher, id, &row, &directory, replace, mode)
                            .await?
                            .map(|made| made.is_some())
                    } else {
                        self.link(&row, &directory, replace).await?
                    };
                    match written {
                        Ok(true) => {
                            if *verbose {
                                lines.out(match (*zip, row.kind.as_str()) {
                                    (true, "symlink") => format!(
                                        "    linking: {}  -> {}",
                                        row.target,
                                        row.link.as_deref().unwrap_or_default()
                                    ),
                                    (true, _) => format!("  inflating: {}", row.target),
                                    (false, _) => row.name.clone(),
                                });
                            }
                        }
                        Ok(false) => {}
                        Err(message) => {
                            errors += 1;
                            lines.err(format!("{cmd}: {}: {message}", row.target));
                        }
                    }
                }
                _ => {}
            }
            sql.exec(
                "UPDATE plan SET done = 1 WHERE idx = ?",
                vec![SqlStorageValue::Integer(row.idx as i64)],
            )?;
            done += 1;
            let state = self
                .update(
                    std::mem::take(&mut lines),
                    Some(json!({"done": done, "total": total, "errors": errors})),
                )
                .await?;
            if state == "cancelling" {
                return Ok(Step::More);
            }
            if Date::now().as_millis() as f64 > deadline {
                return Ok(Step::More);
            }
        }
        // Directories get their modes last, deepest first, so that none stops its own filling:
        // those that were there before too, whatever mode they had. One that is not there, or
        // not where the job may look, failed to be made, and said so.
        let directories = self.rows(
            &format!("SELECT {ROW} FROM plan WHERE action = 'mkdir' ORDER BY length(target) DESC"),
            vec![],
        )?;
        let paths: Vec<&String> = directories.iter().map(|row| &row.target).collect();
        let found = self.modes(&paths).await?;
        for row in &directories {
            let mode = extracted_mode(cmd, job.actor == 0, row.mode, true);
            let Some(had) = found.get(&row.target) else {
                continue;
            };
            if had & 0o7777 == mode {
                continue;
            }
            if let Err(error) = self
                .one(Call::Chmod {
                    path: row.target.clone(),
                    mode: mode as u16,
                })
                .await?
            {
                errors += 1;
                lines.err(format!(
                    "{cmd}: {}: Cannot change mode to {}: {error}",
                    row.target,
                    &mode_text(mode as u16, true)[1..],
                ));
            }
        }
        if !lines.0.is_empty() {
            self.update(
                lines,
                Some(json!({"done": done, "total": total, "errors": errors})),
            )
            .await?;
        }
        Ok(Step::Done)
    }

    /// Decide where each member goes, skipping those that cannot go anywhere safe, and ask,
    /// through the job, about files that exist when unzip has no -o or -n.
    #[allow(clippy::too_many_arguments)]
    async fn plan(
        &self,
        cmd: &str,
        spec: &Spec,
        directory: &str,
        existing: Existing,
        wanted: &[String],
        verbose: bool,
        listing: &Value,
    ) -> Result<Step> {
        let mut lines = Lines::default();
        if cmd == "unzip" && verbose {
            lines.out(format!(
                "Archive:  {}",
                spec.source
                    .as_ref()
                    .map(|s| s.path.as_str())
                    .unwrap_or_default()
            ));
        }
        #[allow(clippy::type_complexity)]
        let mut rows: Vec<(
            u64,
            String,
            u64,
            Option<u32>,
            String,
            String,
            String,
            Option<String>,
        )> = Vec::new();
        let mut targets = BTreeMap::new();
        let mut stripped_noted = false;
        let members = listing["members"].as_array().cloned().unwrap_or_default();
        // The members asked for, and whether any of the archive's is each.
        let mut matched = vec![false; wanted.len()];
        for (index, member) in members.iter().enumerate() {
            let name = member["name"].as_str().unwrap_or_default().to_string();
            let trimmed = name.trim_end_matches('/');
            if !wanted.is_empty() {
                let mut any = false;
                for (w, seen) in wanted.iter().zip(&mut matched) {
                    let w = w.trim_end_matches('/');
                    if trimmed == w || trimmed.starts_with(&format!("{w}/")) {
                        *seen = true;
                        any = true;
                    }
                }
                if !any {
                    continue;
                }
            }
            let kind = member["kind"].as_str().unwrap_or("other").to_string();
            let mut link = member["link"].as_str().map(String::from);
            match kind.as_str() {
                "other" => {
                    lines.err(format!(
                        "{cmd}: skipping {name}: not a regular file, directory or link"
                    ));
                    continue;
                }
                "symlink" if link.as_deref().is_none_or(str::is_empty) => {
                    lines.err(format!("{cmd}: skipping {name}: the link has no target"));
                    continue;
                }
                // A hard link names a member, which must be one it may write as safely.
                "hardlink" => match member_path(directory, link.as_deref().unwrap_or_default()) {
                    Ok((path, _)) => link = Some(path),
                    Err(reason) => {
                        lines.err(format!(
                            "{cmd}: skipping {name}: what it links to: {reason}"
                        ));
                        continue;
                    }
                },
                _ => {}
            }
            let (target, stripped) = match member_path(directory, &name) {
                Ok(found) => found,
                Err(reason) => {
                    lines.err(format!("{cmd}: skipping {name}: {reason}"));
                    continue;
                }
            };
            if stripped && !stripped_noted {
                stripped_noted = true;
                lines.err(if cmd == "tar" {
                    "tar: Removing leading `/' from member names".to_string()
                } else {
                    format!("warning: stripped absolute path spec from {name}")
                });
            }
            if targets.insert(target.clone(), kind.clone()).is_some() {
                lines.err(format!(
                    "{cmd}: skipping {name}: another member has the same name"
                ));
                continue;
            }
            let action = if kind == "directory" {
                "mkdir"
            } else {
                "write"
            };
            rows.push((
                index as u64,
                name,
                member["size"].as_u64().unwrap_or(0),
                member["mode"].as_u64().map(|m| m as u32),
                kind,
                target,
                action.to_string(),
                link,
            ));
        }
        let paths: Vec<&String> = rows.iter().map(|r| &r.5).collect();
        let found = self.modes(&paths).await?;
        let mut conflicts = Vec::new();
        for row in &mut rows {
            let Some(had) = found.get(&row.5) else {
                continue;
            };
            let there = if had & 0o170000 == 0o040000 {
                "directory"
            } else {
                "file"
            };
            match (row.4.as_str(), there) {
                ("directory", "directory") => {}
                ("directory", _) | (_, "directory") => {
                    lines.err(format!(
                        "{cmd}: {}: cannot replace a {there} with a {}",
                        row.5,
                        if row.4 == "directory" {
                            "directory"
                        } else {
                            "file"
                        }
                    ));
                    row.6 = "skip".into();
                }
                _ => match existing {
                    Existing::Replace => row.6 = "replace".into(),
                    Existing::Skip => row.6 = "skip".into(),
                    Existing::Keep => {
                        lines.err(format!("{cmd}: {}: Cannot open: File exists", row.5));
                        row.6 = "skip".into();
                    }
                    Existing::Ask => {
                        row.6 = "ask".into();
                        conflicts.push(row.5.clone());
                    }
                },
            }
        }
        let sql = self.sql();
        for row in &rows {
            sql.exec(
                "INSERT OR REPLACE INTO plan(idx, name, size, mode, kind, target, action, link, done) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 0)",
                vec![
                    SqlStorageValue::Integer(row.0 as i64),
                    row.1.as_str().into(),
                    SqlStorageValue::Integer(row.2 as i64),
                    row.3.map(i64::from).into(),
                    row.4.as_str().into(),
                    row.5.as_str().into(),
                    row.6.as_str().into(),
                    row.7.as_deref().into(),
                ],
            )?;
        }
        // As Info-ZIP and GNU tar say of what was asked for and is not there, a failure each.
        let mut errors = 0;
        for (w, _) in wanted.iter().zip(&matched).filter(|(_, seen)| !**seen) {
            errors += 1;
            lines.err(if cmd == "tar" {
                format!("tar: {w}: Not found in archive")
            } else {
                format!("caution: filename not matched:  {w}")
            });
        }
        if members.is_empty() && cmd == "unzip" {
            errors += 1;
            lines.err(format!(
                "warning [{}]:  zipfile is empty",
                spec.source
                    .as_ref()
                    .map(|s| s.path.as_str())
                    .unwrap_or_default()
            ));
        }
        let mut body = json!({
            "lines": lines.0.iter().map(|(e, l)| json!([e, l])).collect::<Vec<_>>(),
            "progress": {"done": 0, "total": rows.len(), "errors": errors},
        });
        let asking = !conflicts.is_empty() && spec.decisions.is_none();
        if asking {
            body["question"] = json!({"replace": conflicts});
            body["state"] = json!("question");
        }
        self.ask(Method::Post, "/internal/job/update", Some(body))
            .await?;
        self.state.storage().put("planned", true).await?;
        Ok(if asking {
            Step::Wait
        } else if rows.is_empty() {
            // Nothing to write: the job ends now, rather than plan again.
            Step::Done
        } else {
            Step::More
        })
    }

    /// Write one member, a new file with `mode`, through a descriptor of the job's own: Ok with
    /// the mode it has if written, Ok(None) if left as it was, Err with a message if refused.
    /// What a restart interrupted of it goes on, on the descriptor it had.
    async fn write(
        &self,
        fetcher: &Fetcher,
        id: &str,
        row: &Row,
        directory: &str,
        replace: bool,
        mode: u32,
    ) -> Result<std::result::Result<Option<u32>, String>> {
        let member = row.idx;
        let mut writing = match self.writing().await? {
            Some(writing) => {
                let same = writing.index == Some(member);
                self.resumable(writing, same).await?
            }
            None => None,
        };
        if writing.is_none() {
            let parent = terminal_worker_core::parent(&row.target);
            if parent != directory
                && let Err(message) = self.mkdirs(directory, parent).await?
            {
                return Ok(Err(message));
            }
            match self
                .open_write(&row.target, row.size, replace, true, Some(mode))
                .await?
            {
                Err(message) => return Ok(Err(message)),
                Ok(None) => return Ok(Ok(None)),
                Ok(Some(mut opened)) => {
                    opened.index = Some(member);
                    self.keep_writing(&opened).await?;
                    writing = Some(opened);
                }
            }
        }
        let Some(mut writing) = writing else {
            return Ok(Ok(None));
        };
        let count = row.size.div_ceil(CHUNK_SIZE);
        for index in writing.written..count {
            let offset = index * CHUNK_SIZE;
            let length = CHUNK_SIZE.min(row.size - offset);
            self.pwrite(
                fetcher,
                &writing,
                index,
                &format!(
                    "/entry?job={id}&index={}&offset={offset}&length={length}",
                    row.idx
                ),
                length,
                None,
            )
            .await?;
            writing.written = index + 1;
            self.keep_writing(&writing).await?;
        }
        Ok(self.close_write(&writing).await?.map(|()| Some(mode)))
    }

    /// Make the symbolic or hard link `row` is: Ok(true) if made, Ok(false) if left as it was,
    /// Err with a message if refused. One that replaces what is there is made beside it and
    /// renamed over it, so that what was there gives way only once the link is made.
    async fn link(
        &self,
        row: &Row,
        directory: &str,
        replace: bool,
    ) -> Result<std::result::Result<bool, String>> {
        let parent = terminal_worker_core::parent(&row.target);
        if parent != directory
            && let Err(message) = self.mkdirs(directory, parent).await?
        {
            return Ok(Err(message));
        }
        let there = self.modes(&[&row.target]).await?.remove(&row.target);
        if let Some(had) = there {
            if had & 0o170000 == 0o040000 {
                return Ok(Err("a directory with this name already exists".into()));
            }
            if !replace {
                return Ok(Ok(false));
            }
        }
        let made = match there {
            Some(_) => format!(
                "{}/.{}.{}",
                parent.trim_end_matches('/'),
                row.target.rsplit('/').next().unwrap_or_default(),
                &crate::auth::random_token()[..8]
            ),
            None => row.target.clone(),
        };
        let link = row.link.clone().unwrap_or_default();
        let call = if row.kind == "symlink" {
            Call::Symlink {
                target: link,
                path: made.clone(),
            }
        } else {
            Call::Link {
                from: link,
                to: made.clone(),
                follow: false,
            }
        };
        if let Err(error) = self.one(call).await? {
            return Ok(Err(error.to_string()));
        }
        if made != row.target {
            // The name beside goes either way: rename(2) of a name onto another of the same
            // inode (a hard link made again) does nothing, and leaves both.
            let mut results = self
                .sys(vec![
                    Call::Rename {
                        from: made.clone(),
                        to: row.target.clone(),
                        noreplace: false,
                    },
                    Call::Unlink { path: made },
                ])
                .await?
                .into_iter();
            if let Some(Err(error)) = results.next() {
                return Ok(Err(error.to_string()));
            }
        }
        Ok(Ok(true))
    }

    async fn create(&self, job: &Job, spec: &Spec, deadline: f64) -> Result<Step> {
        // A new archive, or, without a format, a video made faststart in its place.
        let (format, verbose) = match &spec.command {
            Command::Create {
                format, verbose, ..
            } => (Some(*format), *verbose),
            Command::Faststart { .. } => (None, false),
            _ => return Ok(Step::Done),
        };
        let output = spec.output.clone().unwrap_or_default();
        let id = job.id.as_str();
        let storage = self.state.storage();
        let fetcher = self.container().await?;
        let status = self.status(&fetcher, id).await?;
        let present: Vec<String> =
            serde_json::from_value(status["inputs"].clone()).unwrap_or_default();
        for (index, input) in spec.inputs.iter().enumerate() {
            if let Some(file) = &input.file
                && !present.contains(&index.to_string())
            {
                self.send(&fetcher, file, &format!("/input?job={id}&index={index}"))
                    .await?;
                if Date::now().as_millis() as f64 > deadline {
                    return Ok(Step::More);
                }
            }
        }
        let inputs: Vec<Value> = spec
            .inputs
            .iter()
            .enumerate()
            .map(|(index, i)| {
                json!({
                    "name": i.name, "file": i.file.as_ref().map(|_| index.to_string()), "mode": i.mode,
                    "owner": i.owner, "group": i.group, "uid": i.uid, "gid": i.gid, "store": i.store,
                    "symlink": i.symlink, "hardlink": i.hardlink,
                })
            })
            .collect();
        // Built once: a later step stores what the container built for it, unless the container
        // lost it, rather than building it all again, and storing a chunk, each step.
        let cached = storage
            .get::<String>("built")
            .await?
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .filter(|built| {
                status["output"]
                    .as_u64()
                    .is_some_and(|size| built["size"].as_u64() == Some(size))
            });
        let built = match cached {
            Some(built) => built,
            None => {
                let (url, body) = match format {
                    Some(format) => (
                        format!("http://jobs/build?job={id}"),
                        json!({"format": format, "mtime": spec.mtime, "chunk_size": CHUNK_SIZE, "inputs": inputs}),
                    ),
                    None => (
                        format!("http://jobs/faststart?job={id}"),
                        json!({"chunk_size": CHUNK_SIZE}),
                    ),
                };
                let mut init = RequestInit::new();
                init.with_method(Method::Post);
                init.with_body(Some(body.to_string().into()));
                let mut response = fetcher.fetch(url, Some(init)).await?;
                let built: Value = response.json().await?;
                let error = built["error"]
                    .as_str()
                    .unwrap_or("the archive could not be built");
                // A file that cannot be made faststart is so whenever it is tried: say so, once.
                if format.is_none() && response.status_code() == 422 {
                    let mut lines = Lines::default();
                    lines.err(format!("faststart: {output}: {error}"));
                    self.update(lines, Some(json!({"done": 0, "total": 0, "errors": 1})))
                        .await?;
                    return Ok(Step::Done);
                }
                if response.status_code() != 200 {
                    return Err(Error::RustError(error.into()));
                }
                storage.put("built", built.to_string()).await?;
                built
            }
        };
        if built["already"] == true {
            let mut lines = Lines::default();
            lines.out(format!(
                "faststart: {output} is already faststart; left as it was"
            ));
            self.update(lines, Some(json!({"done": 0, "total": 0})))
                .await?;
            return Ok(Step::Done);
        }
        let size = built["size"].as_u64().unwrap_or(0);
        let hashes: Vec<String> =
            serde_json::from_value(built["chunks"].clone()).unwrap_or_default();
        if storage.get::<bool>("announced").await? != Some(true) {
            let mut lines = Lines::default();
            if verbose {
                for input in &spec.inputs {
                    lines.out(
                        if format == Some(terminal_worker_core::archive::Format::Zip) {
                            format!("  adding: {}", input.name)
                        } else {
                            input.name.clone()
                        },
                    );
                }
            }
            self.update(lines, Some(json!({"done": 0, "total": hashes.len()})))
                .await?;
            storage.put("announced", true).await?;
        }
        // Go on with the archive begun before, on its descriptor, if it is this one (the build
        // is deterministic: its size says); else begin it.
        // The same archive is the same size, and its chunks stored so far are the new build's,
        // SHA-256 by SHA-256 (a container image that changed builds other bytes).
        let resumed = match self.writing().await? {
            Some(writing) => {
                let same = storage.get::<u64>("upload_size").await? == Some(size)
                    && writing.hashes.len() as u64 == writing.written
                    && writing
                        .hashes
                        .iter()
                        .enumerate()
                        .all(|(index, sha)| hashes.get(index) == sha.as_ref());
                self.resumable(writing, same).await?
            }
            None => None,
        };
        let mut writing = match resumed {
            Some(writing) => writing,
            None => match self
                .open_write(&output, size, spec.replace, false, None)
                .await?
            {
                Ok(Some(opened)) => {
                    self.keep_writing(&opened).await?;
                    storage.put("upload_size", size).await?;
                    opened
                }
                Ok(None) => {
                    return Err(Error::RustError(format!(
                        "{output} appeared while the archive was made"
                    )));
                }
                Err(message) => return Err(Error::RustError(format!("{output}: {message}"))),
            },
        };
        let count = size.div_ceil(CHUNK_SIZE);
        for index in writing.written..count {
            let offset = index * CHUNK_SIZE;
            let length = CHUNK_SIZE.min(size - offset);
            let sha = hashes.get(index as usize).cloned();
            self.pwrite(
                &fetcher,
                &writing,
                index,
                &format!("/output?job={id}&offset={offset}&length={length}"),
                length,
                sha.as_deref(),
            )
            .await?;
            writing.written = index + 1;
            writing.hashes.truncate(index as usize);
            writing.hashes.push(sha);
            self.keep_writing(&writing).await?;
            let state = self
                .update(
                    Lines::default(),
                    Some(json!({"done": index + 1, "total": count})),
                )
                .await?;
            if state == "cancelling" || Date::now().as_millis() as f64 > deadline {
                return Ok(Step::More);
            }
        }
        if let Err(message) = self.close_write(&writing).await? {
            return Err(Error::RustError(format!("{output}: {message}")));
        }
        storage.delete("upload_size").await?;
        if format.is_none() {
            let mut lines = Lines::default();
            lines.out(format!(
                "faststart: {output}: its index ({} bytes) now comes before its media; it plays as it downloads",
                built["moov"].as_u64().unwrap_or(0)
            ));
            self.update(lines, None).await?;
        }
        Ok(Step::Done)
    }
}
