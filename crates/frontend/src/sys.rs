//! System calls from the page (owner's design, 2026-10-29: the page is user space): the batch
//! endpoint (`POST /api/sys`), and file bytes, read as pread reads them (`GET /api/file`). The
//! programs of user space (crates/userland) run over this.
//!
//! What only looks (stat, lstat, getdents, access, readlink) is answered from a cache, as an NFS
//! client answers from its attribute cache, while the directory it is in is watched (inotify):
//! the kernel tells this page's socket what changes in a directory it watches, before it
//! answers the request that changed it, and that directory's answers go. So do all of them
//! when this page changes anything, when its account changes, when its socket opens again
//! after dropping (what it missed is unknown), and after `FRESH_MS` whatever happens: a path
//! through a link elsewhere is told of by the directory it is named in, not the one it leads to.
//! Under sudo, nothing is cached.
use abi::{BATCH_MAX, Batch, Call, Errno, Error, IN_IGNORED, IN_MODIFY, Results, Return};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;

/// How long an answer is trusted, its directory's watch silent.
const FRESH_MS: f64 = 15_000.0;
/// The most directories watched at once; past it, the least lately used goes.
const WATCHED_MAX: usize = 64;

/// An answer kept: what the call gave, when, what it named, and the directory that tells of it.
struct Answer {
    value: Value,
    at: f64,
    path: String,
    dir: String,
}
#[derive(Default)]
struct Cache {
    answers: HashMap<String, Answer>,
    /// The directories watched, by path as this page names them, and their watches' numbers;
    /// the least lately used first.
    watches: Vec<(String, u32)>,
    /// Watches let go of, to remove with the next batch.
    unwatched: Vec<u32>,
}
thread_local! {
    static CACHE: RefCell<Cache> = RefCell::default();
}
impl Cache {
    fn watched(&self, dir: &str) -> bool {
        self.watches.iter().any(|(path, _)| path == dir)
    }
    fn watch(&mut self, dir: &str, wd: u32) {
        self.watches.retain(|(path, _)| path != dir);
        self.watches.push((dir.to_string(), wd));
        while self.watches.len() > WATCHED_MAX {
            let (path, wd) = self.watches.remove(0);
            self.unwatched.push(wd);
            self.forget(&path);
        }
    }
    /// Its directory used now, as the least lately used goes first.
    fn used(&mut self, dir: &str) {
        if let Some(at) = self.watches.iter().position(|(path, _)| path == dir) {
            let watch = self.watches.remove(at);
            self.watches.push(watch);
        }
    }
    /// Forget what was answered of `dir`, of what is in it, and of `dir` itself.
    fn forget(&mut self, dir: &str) {
        let below = format!("{}/", dir.trim_end_matches('/'));
        self.answers.retain(|_, answer| {
            answer.dir != dir && answer.path != dir && !answer.path.starts_with(&below)
        });
    }
}

/// The key and directory of a call that only looks and may be answered from the cache: what it
/// names must be an absolute path without a trailing or doubled slash. Watches are of the
/// directories the kernel resolves (`.`, `..` and links followed), so any spelling of one hears
/// what changes in it.
fn cacheable(call: &Call) -> Option<(String, String, String)> {
    let (path, dir) = match call {
        Call::Getdents {
            path,
            cookie: 0,
            count: None,
        } => (path, path.clone()),
        Call::Stat { path }
        | Call::Lstat { path }
        | Call::Readlink { path }
        | Call::Access { path, .. } => (path, terminal_worker_core::parent(path).to_string()),
        _ => return None,
    };
    let plain = path.starts_with('/')
        && (path == "/" || !path.ends_with('/'))
        && !path.contains("//")
        && !path.starts_with("/proc");
    plain.then(|| {
        (
            serde_json::to_string(call).unwrap_or_default(),
            path.clone(),
            dir,
        )
    })
}

/// Whether `call` only looks, changing nothing.
fn looks(call: &Call) -> bool {
    matches!(
        call,
        Call::Getcreds
            | Call::Stat { .. }
            | Call::Lstat { .. }
            | Call::Getdents { .. }
            | Call::Access { .. }
            | Call::Readlink { .. }
            | Call::Getxattr { .. }
            | Call::Listxattr { .. }
            | Call::Statfs { .. }
            | Call::Pread { .. }
            | Call::Wait { .. }
            | Call::InotifyAddWatch { .. }
            | Call::InotifyRmWatch { .. }
    )
}

/// Forget every answer: this page's socket opened again, or its account changed (with
/// `watches`, the watches too, a new session's to make).
pub fn forget(watches: bool) {
    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        cache.answers.clear();
        if watches {
            cache.watches.clear();
            cache.unwatched.clear();
        }
    });
}

/// What the kernel told of the watches `events` (`{wd, mask}`): their directories' answers go,
/// and a watch it ended goes too. The directories, as this page names them.
pub fn heard(events: &[Value]) -> Vec<String> {
    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let mut dirs = Vec::new();
        for event in events {
            let wd = event["wd"].as_u64().unwrap_or(0) as u32;
            let mask = event["mask"].as_u64().unwrap_or(u64::from(IN_MODIFY)) as u32;
            let named: Vec<String> = cache
                .watches
                .iter()
                .filter(|(_, watch)| *watch == wd)
                .map(|(path, _)| path.clone())
                .collect();
            for dir in named {
                cache.forget(&dir);
                if mask & IN_IGNORED != 0 {
                    cache.watches.retain(|(path, _)| *path != dir);
                }
                dirs.push(dir);
            }
        }
        dirs
    })
}

/// A process of this page: under sudo or not, with its umask.
#[derive(Clone, Copy, Debug)]
pub struct HttpSys {
    pub sudo: bool,
    pub umask: u16,
}
impl Default for HttpSys {
    fn default() -> Self {
        Self {
            sudo: false,
            umask: 0o022,
        }
    }
}

/// What failed to reach the kernel, as each call of the batch hears it.
fn unreached(why: String) -> Error {
    Error::because(Errno::EIO, why)
}

impl userland::Sys for HttpSys {
    async fn batch(&self, calls: Vec<Call>) -> Vec<Result<Value, Error>> {
        if self.sudo {
            let results = self.send(calls).await;
            forget(false);
            return results;
        }
        let now = js_sys::Date::now();
        let count = calls.len();
        let mut answered: Vec<Option<Result<Value, Error>>> = (0..count).map(|_| None).collect();
        // What goes to the kernel: the calls the cache cannot answer, and, after them, watches
        // of the directories they look in, and the watches let go of.
        let mut sending: Vec<(usize, Call)> = Vec::new();
        let mut watching: Vec<String> = Vec::new();
        let mut changing = false;
        let mut unwatched = Vec::new();
        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            unwatched = std::mem::take(&mut cache.unwatched);
            for (index, call) in calls.into_iter().enumerate() {
                // After a change in the batch, what follows sees it: nothing is answered here.
                if !changing && let Some((key, _, dir)) = cacheable(&call) {
                    let fresh = cache
                        .answers
                        .get(&key)
                        .filter(|answer| now - answer.at < FRESH_MS)
                        .map(|answer| answer.value.clone());
                    if let Some(value) = fresh.filter(|_| cache.watched(&dir)) {
                        cache.used(&dir);
                        answered[index] = Some(Ok(value));
                        continue;
                    }
                    if !cache.watched(&dir) && !watching.contains(&dir) {
                        watching.push(dir);
                    }
                }
                changing |= !looks(&call);
                sending.push((index, call));
            }
        });
        // Watches to drop and to add go along with the calls, as many as the batch has room
        // for; the drops left wait for the next.
        let room = BATCH_MAX.saturating_sub(sending.len());
        if unwatched.len() > room {
            let rest = unwatched.split_off(room);
            CACHE.with(|cache| cache.borrow_mut().unwatched.extend(rest));
        }
        watching.truncate(room.saturating_sub(unwatched.len()));
        let mut outgoing: Vec<Call> = sending.iter().map(|(_, call)| call.clone()).collect();
        outgoing.extend(watching.iter().map(|dir| Call::InotifyAddWatch {
            path: dir.clone(),
            mask: IN_MODIFY,
        }));
        outgoing.extend(unwatched.iter().map(|wd| Call::InotifyRmWatch { wd: *wd }));
        let signing = sending
            .iter()
            .any(|(_, call)| matches!(call, Call::Login { .. } | Call::Logout));
        let mut results = if outgoing.is_empty() {
            Vec::new()
        } else {
            self.send(outgoing).await
        };
        let mut watched: Vec<Result<Value, Error>> = results.drain(sending.len()..).collect();
        let dropped = watched.split_off(watching.len().min(watched.len()));
        CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            for (dir, watch) in watching.iter().zip(watched) {
                if let Some(wd) = watch.ok().and_then(|wd| wd.as_u64()) {
                    cache.watch(dir, wd as u32);
                }
            }
            // A drop the batch could not carry is made with the next.
            for (wd, result) in unwatched.iter().zip(dropped) {
                if result.is_err_and(|error| error.errno == Errno::EIO) {
                    cache.unwatched.push(*wd);
                }
            }
            for ((index, call), result) in sending.into_iter().zip(results) {
                if !changing
                    && let (Ok(value), Some((key, path, dir))) = (&result, cacheable(&call))
                    && cache.watched(&dir)
                {
                    cache.answers.insert(
                        key,
                        Answer {
                            value: value.clone(),
                            at: now,
                            path,
                            dir,
                        },
                    );
                }
                answered[index] = Some(result);
            }
        });
        // What this page changed, it reads anew; a new account watches anew.
        if changing {
            forget(signing);
        }
        answered
            .into_iter()
            .map(|answer| answer.unwrap_or_else(|| Err(Errno::EIO.into())))
            .collect()
    }
    async fn read(&self, path: &str) -> Result<Vec<u8>, Error> {
        self.read_bytes(path).await
    }
}

impl HttpSys {
    /// Send `calls`, one batch, to the kernel: each one's answer.
    async fn send(&self, calls: Vec<Call>) -> Vec<Result<Value, Error>> {
        let count = calls.len();
        let batch = Batch {
            calls,
            umask: self.umask,
            sudo: self.sudo,
        };
        let sent = async {
            let response = gloo_net::http::Request::post("/api/sys")
                .json(&batch)
                .map_err(|e| e.to_string())?
                .send()
                .await
                .map_err(|e| e.to_string())?;
            if !response.ok() {
                let why = response
                    .json::<Value>()
                    .await
                    .ok()
                    .and_then(|value| value["error"].as_str().map(String::from))
                    .unwrap_or_else(|| format!("Request failed ({})", response.status()));
                return Err(why);
            }
            response.json::<Results>().await.map_err(|e| e.to_string())
        }
        .await;
        match sent {
            Ok(results) => results
                .results
                .into_iter()
                .map(Return::into_result)
                .collect(),
            Err(why) => (0..count).map(|_| Err(unreached(why.clone()))).collect(),
        }
    }
    async fn read_bytes(&self, path: &str) -> Result<Vec<u8>, Error> {
        let url = format!("/api/file?path={}", js_sys::encode_uri_component(path));
        let response = gloo_net::http::Request::get(&url)
            .header("Accept-Encoding", "identity")
            .send()
            .await
            .map_err(|e| unreached(e.to_string()))?;
        if response.ok() {
            return response
                .binary()
                .await
                .map_err(|e| unreached(e.to_string()));
        }
        let errno = match response.status() {
            404 => Errno::ENOENT,
            401 | 403 => Errno::EACCES,
            400 => Errno::EISDIR,
            _ => Errno::EIO,
        };
        Err(errno.into())
    }
}
