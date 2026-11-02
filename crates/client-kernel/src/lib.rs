//! The client kernel (owner's plan, 2026-11-01): the browser's half of the kernel, in Rust→wasm
//! inside a SharedWorker. It owns the browser's process table mirror and the tokens processes
//! make their calls with; every decision remains the worker kernel's, through `/api/sys`.
//!
//! It holds no policy: `exec` asks for an image, the worker kernel checks the path, the execute
//! bit and the credentials, and answers the token; `fork`, `wait`, `exit`, `kill` and `poll` are
//! the same calls as a page makes. The page and the process hosts are untrusted user space; the
//! tokens this kernel keeps are capabilities handed to the hosts that run the processes.
use abi::{Batch, Call, Errno, Error, Exec, Forked, PROC_POLL_MAX, Proc, Return, SIGTERM};
use std::cell::RefCell;
use std::collections::HashMap;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// The transport the SharedWorker's script installs (`self.kernelSys(body)`): POST /api/sys,
/// answering `{status, text}` as JSON. Fetch and cookies are the browser's; the Rust kernel
/// holds the calls and the tokens.
async fn kernel_sys(body: &str) -> Result<JsValue, JsValue> {
    let global = js_sys::global();
    let function = js_sys::Reflect::get(&global, &JsValue::from_str("kernelSys"))?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| JsValue::from_str("the client kernel's transport is not installed"))?;
    let answer = function.call1(&global, &JsValue::from_str(body))?;
    let promise = answer
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| JsValue::from_str("the client kernel's transport did not answer a promise"))?;
    JsFuture::from(promise).await
}

/// The kernel's own protocol version, which the page checks at start.
pub const VERSION: &str = "1";

struct State {
    namespace: String,
    boot: String,
    /// The token each running (or forked, not yet exited) process makes its calls with.
    tokens: HashMap<u32, String>,
}

#[wasm_bindgen]
pub struct Kernel {
    state: RefCell<State>,
}

#[wasm_bindgen]
impl Kernel {
    /// A kernel for one browser boot. The page gives the boot id; the SharedWorker keeps it
    /// across that boot's tabs. An empty one reaps nothing by boot: where tabs hold Web Locks,
    /// what a gone tab left is reaped by its seat (client.js), and a kernel of one tab alone
    /// must not reap the processes of the browser's other tabs.
    #[wasm_bindgen(constructor)]
    pub fn new(boot: &str) -> Kernel {
        Kernel {
            state: RefCell::new(State {
                namespace: String::new(),
                boot: boot.to_string(),
                tokens: HashMap::new(),
            }),
        }
    }

    /// The protocol version, so a page built another way does not talk past this kernel.
    pub fn version(&self) -> String {
        VERSION.into()
    }

    /// The namespace this kernel is of.
    pub fn namespace(&self) -> String {
        self.state.borrow().namespace.clone()
    }

    /// proc_init: begin (or continue) this browser's namespace, as init does.
    pub async fn init(&self) -> Result<String, JsValue> {
        let boot = self.state.borrow().boot.clone();
        let boot = (!boot.is_empty()).then_some(boot);
        let value = one(vec![Call::ProcInit { boot }], None, None).await?;
        let namespace = value["namespace"].as_str().unwrap_or_default().to_string();
        self.state.borrow_mut().namespace = namespace;
        Ok(value.to_string())
    }

    /// execve: ask the worker kernel for the image at `path`, run as this browser's account.
    /// `argv`, `env` and `pids` are JSON arrays; `cgroup` is empty for the default; `sudo`
    /// snapshots root for the new process, once the page has authenticated it; `seat` is the
    /// tab that runs it, empty if none said.
    #[allow(clippy::too_many_arguments)]
    pub async fn exec(
        &self,
        path: &str,
        argv: &str,
        env: &str,
        cwd: &str,
        cgroup: &str,
        sudo: bool,
        seat: &str,
    ) -> Result<String, JsValue> {
        let argv: Vec<String> = parse(argv, "argv")?;
        let env: Vec<String> = parse(env, "env")?;
        let value = one_as(
            vec![Call::Execve {
                pid: None,
                path: path.into(),
                argv,
                env,
                cwd: cwd.into(),
                cgroup: (!cgroup.is_empty()).then(|| cgroup.to_string()),
                seat: (!seat.is_empty()).then(|| seat.to_string()),
            }],
            None,
            None,
            sudo,
        )
        .await?;
        let exec: Exec = from_value(value, "execve")?;
        self.state
            .borrow_mut()
            .tokens
            .insert(exec.pid, exec.token.clone());
        to_json(&exec)
    }

    /// fork: a child of `pid`, with its registry state copied; the page clones the wasm state.
    pub async fn fork(&self, pid: u32) -> Result<String, JsValue> {
        let token = self.token(pid)?;
        let value = one(vec![Call::Fork { pid }], Some(pid), Some(&token)).await?;
        let forked: Forked = from_value(value, "fork")?;
        self.state
            .borrow_mut()
            .tokens
            .insert(forked.pid, forked.token.clone());
        to_json(&forked)
    }

    /// exit: the process `pid` ends with `status`, or by `signal`.
    pub async fn exit(&self, pid: u32, status: i32, signal: Option<u8>) -> Result<String, JsValue> {
        let token = self.token(pid)?;
        one(vec![Call::Exit { status, signal }], Some(pid), Some(&token)).await?;
        self.state.borrow_mut().tokens.remove(&pid);
        Ok("null".into())
    }

    /// waitpid: the zombie `pid`, now reaped; EAGAIN while it runs.
    pub async fn wait(&self, pid: u32) -> Result<String, JsValue> {
        let value = one(
            vec![Call::Wait {
                pid: pid.to_string(),
                since: 0,
            }],
            None,
            None,
        )
        .await?;
        let reaped: Proc = from_value(value, "wait")?;
        self.state.borrow_mut().tokens.remove(&pid);
        to_json(&reaped)
    }

    /// kill: send `signal` (SIGTERM by default) to `pid`.
    pub async fn kill(&self, pid: u32, signal: Option<u8>) -> Result<String, JsValue> {
        one(
            vec![Call::Kill {
                pid: pid.to_string(),
                signal: Some(signal.unwrap_or(SIGTERM)),
            }],
            None,
            None,
        )
        .await?;
        Ok("null".into())
    }

    /// What those processes (JSON array of pids; none for all) are now.
    pub async fn poll(&self, pids: &str) -> Result<String, JsValue> {
        let pids: Vec<u32> = parse(pids, "pids")?;
        if pids.len() > PROC_POLL_MAX {
            return Err(fail(Error::because(
                Errno::E2BIG,
                format!("at most {PROC_POLL_MAX} processes at a time"),
            )));
        }
        let value = one(vec![Call::ProcPoll { pids }], None, None).await?;
        Ok(value.to_string())
    }

    /// getpid: what the process `pid` is, by its token.
    pub async fn getpid(&self, pid: u32) -> Result<String, JsValue> {
        let token = self.token(pid)?;
        let value = one(vec![Call::Getpid], Some(pid), Some(&token)).await?;
        Ok(value.to_string())
    }

    /// cgroup_create, cgroup_set, cgroup_attach, cgroup_remove and cgroup_stat, as the page
    /// asks them for this namespace.
    pub async fn cgroup_create(&self, path: &str) -> Result<String, JsValue> {
        one(
            vec![Call::CgroupCreate {
                path: path.into(),
                controllers: None,
            }],
            None,
            None,
        )
        .await?;
        Ok("null".into())
    }
    pub async fn cgroup_set(&self, path: &str, key: &str, value: &str) -> Result<String, JsValue> {
        one(
            vec![Call::CgroupSet {
                path: path.into(),
                key: key.into(),
                value: value.into(),
            }],
            None,
            None,
        )
        .await?;
        Ok("null".into())
    }
    pub async fn cgroup_attach(&self, pid: u32, path: &str) -> Result<String, JsValue> {
        one(
            vec![Call::CgroupAttach {
                pid,
                path: path.into(),
            }],
            None,
            None,
        )
        .await?;
        Ok("null".into())
    }
    pub async fn cgroup_remove(&self, path: &str) -> Result<String, JsValue> {
        one(vec![Call::CgroupRemove { path: path.into() }], None, None).await?;
        Ok("null".into())
    }
    pub async fn cgroup_stat(&self, path: &str) -> Result<String, JsValue> {
        let value = one(vec![Call::CgroupStat { path: path.into() }], None, None).await?;
        Ok(value.to_string())
    }
    pub async fn cgroup_list(&self, path: &str) -> Result<String, JsValue> {
        let value = one(vec![Call::CgroupList { path: path.into() }], None, None).await?;
        Ok(value.to_string())
    }

    fn token(&self, pid: u32) -> std::result::Result<String, JsValue> {
        self.state
            .borrow()
            .tokens
            .get(&pid)
            .cloned()
            .ok_or_else(|| fail(Error::because(Errno::ESRCH, format!("no process {pid}"))))
    }
}

async fn one(
    calls: Vec<Call>,
    pid: Option<u32>,
    token: Option<&str>,
) -> Result<serde_json::Value, JsValue> {
    one_as(calls, pid, token, false).await
}

async fn one_as(
    calls: Vec<Call>,
    pid: Option<u32>,
    token: Option<&str>,
    sudo: bool,
) -> Result<serde_json::Value, JsValue> {
    let results = sys(calls, pid, token, sudo).await.map_err(fail)?;
    match results.into_iter().next() {
        Some(Return::Ok(value)) => Ok(value),
        Some(Return::Err(error)) => Err(fail(error)),
        None => Err(fail(Error::because(
            Errno::EIO,
            "the kernel answered no call",
        ))),
    }
}

async fn sys(
    calls: Vec<Call>,
    pid: Option<u32>,
    token: Option<&str>,
    sudo: bool,
) -> std::result::Result<Vec<Return>, Error> {
    let batch = Batch {
        calls,
        umask: 0o022,
        sudo,
        pid,
        process: token.map(str::to_string),
    };
    let body = serde_json::to_string(&batch)
        .map_err(|error| Error::because(Errno::EIO, error.to_string()))?;
    let raw = kernel_sys(&body)
        .await
        .map_err(|error| Error::because(Errno::EIO, format!("{error:?}")))?;
    let raw = raw
        .as_string()
        .ok_or_else(|| Error::because(Errno::EIO, "the kernel's reply is not text"))?;
    let reply: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|error| Error::because(Errno::EIO, error.to_string()))?;
    let status = reply["status"].as_u64().unwrap_or(0);
    if status != 200 {
        let detail = reply["text"].as_str().unwrap_or("system call failed");
        return Err(Error::because(Errno::EIO, detail.to_string()));
    }
    let text = reply["text"]
        .as_str()
        .ok_or_else(|| Error::because(Errno::EIO, "the kernel's reply is not text"))?;
    let results: abi::Results = serde_json::from_str(text)
        .map_err(|error| Error::because(Errno::EIO, error.to_string()))?;
    Ok(results.results)
}

fn parse<T: serde::de::DeserializeOwned>(
    text: &str,
    what: &str,
) -> std::result::Result<T, JsValue> {
    serde_json::from_str(text)
        .map_err(|error| fail(Error::because(Errno::EINVAL, format!("{what}: {error}"))))
}

fn from_value<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
    what: &str,
) -> std::result::Result<T, JsValue> {
    serde_json::from_value(value)
        .map_err(|error| fail(Error::because(Errno::EIO, format!("{what}: {error}"))))
}

fn to_json<T: serde::Serialize>(value: &T) -> std::result::Result<String, JsValue> {
    serde_json::to_string(value)
        .map_err(|error| fail(Error::because(Errno::EIO, error.to_string())))
}

/// An error as the page reads it: its errno, and what it says.
fn fail(error: Error) -> JsValue {
    JsValue::from_str(
        &serde_json::json!({
            "errno": error.errno,
            "detail": error.detail,
        })
        .to_string(),
    )
}
