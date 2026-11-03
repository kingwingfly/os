//! The client kernel (owner's plan, 2026-11-01): the browser's half of the kernel, in Rust→wasm
//! inside a SharedWorker (or one tab's dedicated Worker). It keeps the processes its tabs host,
//! and the tokens they make their calls with; every decision on files remains the worker
//! kernel's, and the process record is the browser's machine's (a Durable Object of its own,
//! reached by a batch marked `X-Registry`).
//!
//! Only execve asks the worker kernel anything, and a pipeline's stages ask at once. A fork, an
//! exit and a wait happen here, as they happen in a Linux kernel: a fork takes a pid the
//! machine lent ahead of time, and each is told to the machine after, in a batch with the
//! others (`flush`), or with the next request that goes there anyway. A wait answers here; its
//! host replies once the machine heard (`queued`, `reported`), so that /proc no longer names
//! what was reaped.
//!
//! It holds no policy. The page and the process hosts are untrusted user space; the tokens this
//! kernel keeps are capabilities handed to the hosts that run the processes.
use abi::{Batch, Call, Errno, Error, Exec, PROC_POLL_MAX, Return, SIGTERM};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::HashMap;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// The transport the worker's script installs (`self.kernelSys(body)`): POST /api/sys, marked
/// for the browser's machine, answering `{status, text}` as JSON. Fetch and cookies are the
/// browser's; the Rust kernel holds the calls and the tokens.
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
/// How many pids the kernel asks to be lent at a time, for its forks.
const LEND: u32 = 8;
/// Linux's init.
const INIT: u32 = 1;

/// How a process ended: its exit status, or the signal that ended it.
type Ended = (i32, Option<u8>);

/// A process this kernel hosts: its parent, the token its calls carry (a fork's is its
/// parent's), and, once it ended, its wait status until its parent waits.
struct Local {
    ppid: u32,
    token: String,
    ended: Option<Ended>,
}

struct State {
    namespace: String,
    boot: String,
    processes: HashMap<u32, Local>,
    /// Pids the machine lent, which forks take.
    spare: Vec<u32>,
    /// What happened here that the machine is still to hear: forks, exits, waits, in order.
    reports: Vec<Call>,
    /// How many reports were made, and how many the machine heard, since the kernel started.
    queued: u64,
    reported: u64,
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
                processes: HashMap::new(),
                spare: Vec::new(),
                reports: Vec::new(),
                queued: 0,
                reported: 0,
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
        let value = self.one(Call::ProcInit { boot }, false).await?;
        let namespace = value["namespace"].as_str().unwrap_or_default().to_string();
        self.state.borrow_mut().namespace = namespace;
        Ok(value.to_string())
    }

    /// execve: ask for the image at `path`, run as this browser's account. `argv`, `env` and
    /// `pids` are JSON arrays; `cgroup` is empty for the default; `sudo` snapshots root for the
    /// new process, once the page has authenticated it; `seat` is the tab that runs it, empty
    /// if none said.
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
        let stage = json!({ "path": path, "argv": parse::<Value>(argv, "argv")?, "env": parse::<Value>(env, "env")?, "cwd": cwd, "cgroup": cgroup });
        let mut results = self.execs_of(vec![stage], sudo, seat).await?;
        match results.pop() {
            Some(Ok(exec)) => to_json(&exec),
            Some(Err(error)) => Err(fail(error)),
            None => Err(fail(Error::because(Errno::EIO, "no process was made"))),
        }
    }

    /// execve of each stage of a pipeline at once (a JSON array of `{path, argv, env, cwd,
    /// cgroup}`): one request, each stage's process or its errno, in order.
    pub async fn execs(&self, stages: &str, sudo: bool, seat: &str) -> Result<String, JsValue> {
        let stages: Vec<Value> = parse(stages, "stages")?;
        let results = self.execs_of(stages, sudo, seat).await?;
        let results: Vec<Value> = results
            .into_iter()
            .map(|result| match result {
                Ok(exec) => json!({ "ok": exec }),
                Err(error) => json!({ "err": { "errno": error.errno, "detail": error.detail } }),
            })
            .collect();
        Ok(Value::Array(results).to_string())
    }

    /// execve of the process `pid` itself, as its own image calls it: the image at `path`
    /// replaces its own, with its pid, its credentials and its open descriptors; the process
    /// carries a new token from now on (its forks keep the old one). `argv` and `env` are JSON
    /// arrays.
    pub async fn reexec(
        &self,
        pid: u32,
        path: &str,
        argv: &str,
        env: &str,
        cwd: &str,
        seat: &str,
    ) -> Result<String, JsValue> {
        let token = self.token(pid)?;
        let call = Call::Execve {
            pid: Some(pid),
            token: Some(token),
            path: path.into(),
            argv: parse(argv, "argv")?,
            env: parse(env, "env")?,
            cwd: cwd.into(),
            cgroup: None,
            seat: (!seat.is_empty()).then(|| seat.to_string()),
        };
        let value = self.one(call, false).await?;
        let exec: Exec = from_value(value, "execve")?;
        if let Some(local) = self.state.borrow_mut().processes.get_mut(&pid) {
            local.token = exec.token.clone();
        }
        to_json(&exec)
    }

    /// fork: a child of `pid`, at once, with a pid lent ahead (one request when none is left);
    /// the machine hears of it after. The page clones the wasm state.
    pub async fn fork(&self, pid: u32) -> Result<String, JsValue> {
        let token = self.token(pid)?;
        if self.state.borrow().spare.is_empty() {
            let lent = self.one(Call::Pids { count: LEND }, false).await?;
            let lent: Vec<u32> = from_value(lent, "pids")?;
            self.state.borrow_mut().spare.extend(lent);
        }
        let mut state = self.state.borrow_mut();
        // A fork taken while the lending was asked may have left none.
        let child = state
            .spare
            .pop()
            .ok_or_else(|| fail(Errno::EAGAIN.into()))?;
        state.processes.insert(
            child,
            Local {
                ppid: pid,
                token: token.clone(),
                ended: None,
            },
        );
        state.report(Call::Fork {
            pid,
            child: Some(child),
            token: Some(token.clone()),
        });
        to_json(&json!({ "pid": child, "token": token }))
    }

    /// exit: the process `pid` ends with `status`, or by `signal`: a zombie until its parent
    /// waits; its children are init's, and those that ended, init reaps. Its parent, which is
    /// to wait for it: init's are their host's to reap, as init would.
    pub async fn exit(&self, pid: u32, status: i32, signal: Option<u8>) -> Result<String, JsValue> {
        let mut state = self.state.borrow_mut();
        let local = state
            .processes
            .get_mut(&pid)
            .ok_or_else(|| fail(Error::because(Errno::ESRCH, format!("no process {pid}"))))?;
        if local.ended.is_some() {
            return Err(fail(Errno::ESRCH.into()));
        }
        local.ended = Some((status, signal));
        let (token, ppid) = (local.token.clone(), local.ppid);
        let orphans: Vec<u32> = state
            .processes
            .iter()
            .filter(|(_, child)| child.ppid == pid)
            .map(|(child, _)| *child)
            .collect();
        for orphan in orphans {
            if state.processes[&orphan].ended.is_some() {
                state.processes.remove(&orphan);
            } else if let Some(child) = state.processes.get_mut(&orphan) {
                child.ppid = INIT;
            }
        }
        state.report(Call::Exit {
            status,
            signal,
            pid: Some(pid),
            token: Some(token),
        });
        Ok(json!({ "ppid": ppid }).to_string())
    }

    /// waitpid: the zombie `pid`, now reaped, told to the machine with the next batch; EAGAIN
    /// while it runs. One this kernel does not host is the machine's to answer.
    pub async fn wait(&self, pid: u32) -> Result<String, JsValue> {
        let ended = self
            .state
            .borrow()
            .processes
            .get(&pid)
            .map(|local| (local.ppid, local.ended));
        let value = match ended {
            Some((_, None)) => return Err(fail(Errno::EAGAIN.into())),
            Some((ppid, Some((status, signal)))) => {
                let mut state = self.state.borrow_mut();
                state.processes.remove(&pid);
                state.report(Call::Wait {
                    pid: pid.to_string(),
                    since: 0,
                });
                let wait = match signal {
                    Some(signal) => abi::signal_status(signal),
                    None => abi::exit_status(status),
                };
                json!({ "pid": pid, "ppid": ppid, "state": "zombie", "status": wait, "signal": signal })
            }
            None => {
                self.one(
                    Call::Wait {
                        pid: pid.to_string(),
                        since: 0,
                    },
                    false,
                )
                .await?
            }
        };
        Ok(value.to_string())
    }

    /// wait4(2), as the process `ppid` asks it: its child `pid`, or any of its children with
    /// none, once ended, reaped now (told to the machine with the next batch), with its exit
    /// status (`code`) or the signal that ended it; EAGAIN while those it may wait for run;
    /// ECHILD when it has none of them.
    pub async fn waitchild(&self, ppid: u32, pid: Option<u32>) -> Result<String, JsValue> {
        let found = {
            let state = self.state.borrow();
            let mut children: Vec<(u32, Option<Ended>)> = state
                .processes
                .iter()
                .filter(|(child, local)| local.ppid == ppid && pid.is_none_or(|pid| **child == pid))
                .map(|(child, local)| (*child, local.ended))
                .collect();
            if children.is_empty() {
                return Err(fail(Errno::ECHILD.into()));
            }
            children.sort_unstable_by_key(|(child, _)| *child);
            children
                .into_iter()
                .find_map(|(child, ended)| ended.map(|ended| (child, ended)))
        };
        let Some((child, (code, signal))) = found else {
            return Err(fail(Errno::EAGAIN.into()));
        };
        let mut state = self.state.borrow_mut();
        state.processes.remove(&child);
        state.report(Call::Wait {
            pid: child.to_string(),
            since: 0,
        });
        let wait = match signal {
            Some(signal) => abi::signal_status(signal),
            None => abi::exit_status(code),
        };
        Ok(
            json!({ "pid": child, "ppid": ppid, "status": wait, "code": code, "signal": signal })
                .to_string(),
        )
    }

    /// kill: send `signal` (SIGTERM by default) to `pid`, as the page's account.
    pub async fn kill(&self, pid: u32, signal: Option<u8>) -> Result<String, JsValue> {
        self.one(
            Call::Kill {
                pid: pid.to_string(),
                signal: Some(signal.unwrap_or(SIGTERM)),
            },
            false,
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
        let value = self.one(Call::ProcPoll { pids }, false).await?;
        Ok(value.to_string())
    }

    /// getpid: what the process `pid`, hosted here, is.
    pub async fn getpid(&self, pid: u32) -> Result<String, JsValue> {
        let state = self.state.borrow();
        let local = state
            .processes
            .get(&pid)
            .filter(|local| local.ended.is_none())
            .ok_or_else(|| fail(Error::because(Errno::ESRCH, format!("no process {pid}"))))?;
        Ok(json!({ "pid": pid, "ppid": local.ppid }).to_string())
    }

    /// The tabs whose processes still run, by the machine's record.
    pub async fn seats(&self) -> Result<String, JsValue> {
        Ok(self.one(Call::Seats, false).await?.to_string())
    }

    /// The tab `seat` is gone: what it ran ended with it.
    pub async fn gone(&self, seat: &str) -> Result<String, JsValue> {
        let value = self.one(Call::Gone { seat: seat.into() }, false).await?;
        // What it ran that this kernel kept goes too.
        let reaped: Vec<u32> = serde_json::from_value(value.clone()).unwrap_or_default();
        let mut state = self.state.borrow_mut();
        for pid in reaped {
            state.processes.remove(&pid);
        }
        Ok(value.to_string())
    }

    /// Whether the machine is still to hear of something.
    pub fn pending(&self) -> bool {
        !self.state.borrow().reports.is_empty()
    }

    /// How many reports were made since the kernel started: the machine heard the one made
    /// last once `reported` is as many.
    pub fn queued(&self) -> f64 {
        self.state.borrow().queued as f64
    }

    /// How many reports the machine heard since the kernel started.
    pub fn reported(&self) -> f64 {
        self.state.borrow().reported as f64
    }

    /// Tell the machine what happened here since it last heard: one request, if anything did.
    pub async fn flush(&self) -> Result<(), JsValue> {
        if self.pending() {
            self.send(Vec::new(), false).await.map_err(fail)?;
        }
        Ok(())
    }

    /// cgroup_create, cgroup_set, cgroup_attach, cgroup_remove and cgroup_stat, as the page
    /// asks them for this namespace.
    pub async fn cgroup_create(&self, path: &str) -> Result<String, JsValue> {
        self.one(
            Call::CgroupCreate {
                path: path.into(),
                controllers: None,
            },
            false,
        )
        .await?;
        Ok("null".into())
    }
    pub async fn cgroup_set(&self, path: &str, key: &str, value: &str) -> Result<String, JsValue> {
        self.one(
            Call::CgroupSet {
                path: path.into(),
                key: key.into(),
                value: value.into(),
            },
            false,
        )
        .await?;
        Ok("null".into())
    }
    pub async fn cgroup_attach(&self, pid: u32, path: &str) -> Result<String, JsValue> {
        self.one(
            Call::CgroupAttach {
                pid,
                path: path.into(),
            },
            false,
        )
        .await?;
        Ok("null".into())
    }
    pub async fn cgroup_remove(&self, path: &str) -> Result<String, JsValue> {
        self.one(Call::CgroupRemove { path: path.into() }, false)
            .await?;
        Ok("null".into())
    }
    pub async fn cgroup_stat(&self, path: &str) -> Result<String, JsValue> {
        let value = self
            .one(Call::CgroupStat { path: path.into() }, false)
            .await?;
        Ok(value.to_string())
    }
    pub async fn cgroup_list(&self, path: &str) -> Result<String, JsValue> {
        let value = self
            .one(Call::CgroupList { path: path.into() }, false)
            .await?;
        Ok(value.to_string())
    }
}

impl Kernel {
    fn token(&self, pid: u32) -> std::result::Result<String, JsValue> {
        self.state
            .borrow()
            .processes
            .get(&pid)
            .filter(|local| local.ended.is_none())
            .map(|local| local.token.clone())
            .ok_or_else(|| fail(Error::because(Errno::ESRCH, format!("no process {pid}"))))
    }

    /// execve of `stages`, in one request: each stage's process, kept here, or its error.
    async fn execs_of(
        &self,
        stages: Vec<Value>,
        sudo: bool,
        seat: &str,
    ) -> std::result::Result<Vec<std::result::Result<Exec, Error>>, JsValue> {
        let calls = stages
            .iter()
            .map(|stage| {
                let cgroup = stage["cgroup"].as_str().unwrap_or_default();
                Ok(Call::Execve {
                    pid: None,
                    token: None,
                    path: stage["path"].as_str().unwrap_or_default().into(),
                    argv: from_value(stage["argv"].clone(), "argv")?,
                    env: from_value(stage["env"].clone(), "env")?,
                    cwd: stage["cwd"].as_str().unwrap_or("/").into(),
                    cgroup: (!cgroup.is_empty()).then(|| cgroup.to_string()),
                    seat: (!seat.is_empty()).then(|| seat.to_string()),
                })
            })
            .collect::<std::result::Result<Vec<_>, JsValue>>()?;
        let results = self.send(calls, sudo).await.map_err(fail)?;
        let mut state = self.state.borrow_mut();
        Ok(results
            .into_iter()
            .map(|result| {
                let exec: Exec = serde_json::from_value(result.into_result()?)
                    .map_err(|error| Error::because(Errno::EIO, error.to_string()))?;
                state.processes.insert(
                    exec.pid,
                    Local {
                        ppid: INIT,
                        token: exec.token.clone(),
                        ended: None,
                    },
                );
                Ok(exec)
            })
            .collect())
    }

    /// One call to the machine, its value.
    async fn one(&self, call: Call, sudo: bool) -> Result<Value, JsValue> {
        let results = self.send(vec![call], sudo).await.map_err(fail)?;
        match results.into_iter().next() {
            Some(Return::Ok(value)) => Ok(value),
            Some(Return::Err(error)) => Err(fail(error)),
            None => Err(fail(Error::because(
                Errno::EIO,
                "the kernel answered no call",
            ))),
        }
    }

    /// `calls`, after what the machine is still to hear, in one batch: the calls' results. What
    /// it was to hear goes again with the next batch if this one does not arrive.
    async fn send(&self, calls: Vec<Call>, sudo: bool) -> std::result::Result<Vec<Return>, Error> {
        let reports = std::mem::take(&mut self.state.borrow_mut().reports);
        let told = reports.len();
        let mut batch = reports.clone();
        batch.extend(calls);
        match sys(batch, sudo).await {
            Ok(mut results) => {
                self.state.borrow_mut().reported += told as u64;
                Ok(results.split_off(told.min(results.len())))
            }
            Err(error) => {
                let mut state = self.state.borrow_mut();
                let later = std::mem::take(&mut state.reports);
                state.reports = reports;
                state.reports.extend(later);
                Err(error)
            }
        }
    }
}

impl State {
    /// Something the machine is to hear.
    fn report(&mut self, call: Call) {
        self.reports.push(call);
        self.queued += 1;
    }
}

async fn sys(calls: Vec<Call>, sudo: bool) -> std::result::Result<Vec<Return>, Error> {
    let batch = Batch {
        calls,
        umask: 0o022,
        sudo,
        pid: None,
        process: None,
    };
    let body = serde_json::to_string(&batch)
        .map_err(|error| Error::because(Errno::EIO, error.to_string()))?;
    let raw = kernel_sys(&body)
        .await
        .map_err(|error| Error::because(Errno::EIO, format!("{error:?}")))?;
    let raw = raw
        .as_string()
        .ok_or_else(|| Error::because(Errno::EIO, "the kernel's reply is not text"))?;
    let reply: Value = serde_json::from_str(&raw)
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
    value: Value,
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
        &json!({
            "errno": error.errno,
            "detail": error.detail,
        })
        .to_string(),
    )
}
