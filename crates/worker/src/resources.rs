//! Registered WASM linear-memory accounting. The conforming runtime reserves before
//! allocation; this is not browser RSS accounting or attestation of a modified client.
use crate::{
    db::{Db, int, text},
    procs::Row,
};
use abi::{Errno, Error};
use kernel::registry;
use serde::{Deserialize, Serialize};
use worker::SqlStorage;
type Result<T> = std::result::Result<T, Error>;
pub const RUNTIME: &str = "resources-v1";
const MAX_MEMORY: u64 = 1 << 40;

pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    sql.exec("CREATE TABLE IF NOT EXISTS process_resources(pid INTEGER PRIMARY KEY, runtime TEXT NOT NULL, memory INTEGER NOT NULL DEFAULT 0)", None)?;
    sql.exec("CREATE TRIGGER IF NOT EXISTS resources_remove AFTER DELETE ON processes BEGIN DELETE FROM process_resources WHERE pid=old.pid; END", None)?;
    sql.exec("CREATE TABLE IF NOT EXISTS cgroup_io(ns TEXT NOT NULL,path TEXT NOT NULL,read_end INTEGER NOT NULL DEFAULT 0,write_end INTEGER NOT NULL DEFAULT 0,read_bytes INTEGER NOT NULL DEFAULT 0,write_bytes INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(ns,path))", None)?;
    sql.exec("CREATE TRIGGER IF NOT EXISTS cgroup_io_remove AFTER DELETE ON cgroups BEGIN DELETE FROM cgroup_io WHERE ns=old.ns AND path=old.path; END", None)?;
    Ok(())
}
#[derive(Deserialize)]
pub struct Usage {
    pub memory: u64,
    pub runtime: String,
}
#[derive(Deserialize)]
struct Limit {
    path: String,
    memory_max: String,
}
#[derive(Deserialize, Serialize)]
pub struct IoRequest {
    pub ns: String,
    pub token: String,
    pub pid: Option<u32>,
    pub write: bool,
    pub bytes: u64,
}
#[derive(Deserialize)]
struct IoPolicy {
    path: String,
    io_max: String,
}
#[derive(Default, Deserialize, Serialize)]
pub struct IoUsage {
    read_end: u64,
    write_end: u64,
    read_bytes: u64,
    write_bytes: u64,
}

impl Db {
    pub fn io_usage(&self, ns: &str, path: &str) -> IoUsage {
        self.rows(
            "SELECT read_end,write_end,read_bytes,write_bytes FROM cgroup_io WHERE ns=? AND path=?",
            vec![text(ns), text(path)],
        )
        .pop()
        .unwrap_or_default()
    }
    pub fn resource_io(&mut self, ask: &IoRequest, now: u64) -> Result<u64> {
        let policies = self.rows::<IoPolicy>(
            "SELECT path,io_max FROM cgroups WHERE ns=? AND io_max IS NOT NULL",
            vec![text(&ask.ns)],
        );
        let row = if let Some(pid) = ask.pid {
            self.process_token(&ask.token, Some(pid), &ask.ns)
                .ok_or(Errno::EPERM)?
        } else {
            // Older hosts did not send their PID on byte routes. A shared lineage's
            // token cannot choose one descendant's possibly cheaper cgroup.
            let hash = crate::auth::token_hash(&ask.token);
            let rows: Vec<_> = self
                .processes(&ask.ns)
                .into_iter()
                .filter(|p| !p.zombie() && self.token_of(&ask.ns, p.pid).as_deref() == Some(&hash))
                .collect();
            if rows.is_empty() {
                return Err(Errno::EPERM.into());
            }
            if rows.iter().any(|p| {
                policies.iter().any(|g| {
                    registry::in_subtree(&p.cgroup, &g.path)
                        && kernel::resource::IoLimit::parse(&g.io_max)
                            .map_or(true, |limit| limit != Default::default())
                })
            }) {
                return Err(Error::because(
                    Errno::EOPNOTSUPP,
                    "limited byte I/O requires an authenticated process PID",
                ));
            }
            return Ok(0);
        };
        let mut updates = Vec::new();
        let mut deadline = now;
        for policy in policies
            .into_iter()
            .filter(|p| registry::in_subtree(&row.cgroup, &p.path))
        {
            let limit = kernel::resource::IoLimit::parse(&policy.io_max)?;
            let usage = self.io_usage(&ask.ns, &policy.path);
            let end = kernel::resource::io_deadline(
                now,
                if ask.write {
                    usage.write_end
                } else {
                    usage.read_end
                },
                if ask.write { limit.write } else { limit.read },
                ask.bytes,
            )?;
            deadline = deadline.max(end);
            updates.push((policy.path, end));
        }
        for (path, end) in updates {
            self.run(
                "INSERT OR IGNORE INTO cgroup_io(ns,path) VALUES(?,?)",
                vec![text(&ask.ns), text(&path)],
            );
            let (clock, total) = if ask.write {
                ("write_end", "write_bytes")
            } else {
                ("read_end", "read_bytes")
            };
            self.run(
                &format!("UPDATE cgroup_io SET {clock}=?,{total}={total}+? WHERE ns=? AND path=?"),
                vec![int(end), int(ask.bytes), text(&ask.ns), text(&path)],
            );
        }
        Ok(deadline.saturating_sub(now))
    }
    pub fn resource_usage(&self, pid: u32) -> Option<Usage> {
        self.rows(
            "SELECT memory,runtime FROM process_resources WHERE pid=?",
            vec![int(pid)],
        )
        .pop()
    }
    pub fn memory_current(&self, ns: &str, path: &str) -> u64 {
        self.processes(ns)
            .iter()
            .filter(|p| !p.zombie() && registry::in_subtree(&p.cgroup, path))
            .filter_map(|p| self.resource_usage(p.pid))
            .map(|u| u.memory)
            .sum()
    }
    pub fn memory_untracked(&self, ns: &str, path: &str) -> usize {
        self.processes(ns)
            .iter()
            .filter(|p| {
                !p.zombie()
                    && registry::in_subtree(&p.cgroup, path)
                    && self.resource_usage(p.pid).is_none()
            })
            .count()
    }
    pub fn resource_admit(
        &self,
        ns: &str,
        path: &str,
        runtime: Option<&str>,
        bytes: u64,
        from: Option<&str>,
    ) -> Result<()> {
        if runtime.is_some_and(|r| r != RUNTIME) {
            return Err(Errno::EOPNOTSUPP.into());
        }
        let limits = self.rows::<Limit>("SELECT path,memory_max FROM cgroups WHERE ns=? AND memory_max IS NOT NULL AND memory_max!='max'", vec![text(ns)]);
        for limit in limits {
            if !registry::in_subtree(path, &limit.path) {
                continue;
            }
            if runtime != Some(RUNTIME) {
                return Err(Error::because(
                    Errno::EOPNOTSUPP,
                    "memory.max requires the resources-v1 runtime",
                ));
            }
            if from.is_some_and(|old| registry::in_subtree(old, &limit.path)) {
                continue;
            }
            let max = limit.memory_max.parse::<u64>().map_err(|_| Errno::EINVAL)?;
            if bytes > 0 && self.memory_current(ns, &limit.path).saturating_add(bytes) > max {
                return Err(Error::because(
                    Errno::EAGAIN,
                    format!("memory.max reached at {}", limit.path),
                ));
            }
        }
        Ok(())
    }
    pub fn resource_exec(&mut self, pid: u32, runtime: Option<&str>) {
        if let Some(runtime) = runtime {
            // Preserve the replaced image's charge until its runtime reserves the new
            // instance. The old execution token can no longer change this accounting.
            self.run("INSERT INTO process_resources(pid,runtime) VALUES(?,?) ON CONFLICT(pid) DO UPDATE SET runtime=excluded.runtime", vec![int(pid),text(runtime)]);
        } else {
            self.run("DELETE FROM process_resources WHERE pid=?", vec![int(pid)]);
        }
    }
    pub fn resource_fork(&mut self, parent: u32, child: u32, empty_memory: bool) {
        self.run("INSERT INTO process_resources(pid,runtime,memory) SELECT ?,runtime,CASE WHEN ? THEN 0 ELSE memory END FROM process_resources WHERE pid=?", vec![int(child),int(u8::from(empty_memory)),int(parent)]);
    }
    pub fn resource_memory(&mut self, row: &Row, bytes: u64) -> Result<()> {
        if bytes > MAX_MEMORY || !bytes.is_multiple_of(65536) {
            return Err(Errno::EINVAL.into());
        }
        let current = self.resource_usage(row.pid).ok_or(Errno::EOPNOTSUPP)?;
        self.resource_admit(
            &row.ns,
            &row.cgroup,
            Some(&current.runtime),
            bytes.saturating_sub(current.memory),
            None,
        )?;
        self.run(
            "UPDATE process_resources SET memory=? WHERE pid=?",
            vec![int(bytes), int(row.pid)],
        );
        Ok(())
    }
}

pub async fn io(
    env: &worker::Env,
    ns: String,
    token: Option<String>,
    pid: Option<u32>,
    write: bool,
    bytes: u64,
) -> Result<()> {
    use worker::*;
    let Some(token) = token else {
        return Ok(());
    };
    if bytes == 0 {
        return Ok(());
    }
    let map = |e: worker::Error| abi::Error::because(Errno::EIO, e.to_string());
    let request = IoRequest {
        ns,
        token,
        pid,
        write,
        bytes,
    };
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(
        serde_json::to_string(&request)
            .map_err(|_| Errno::EIO)?
            .into(),
    ));
    let mut reply = env
        .durable_object("MACHINE")
        .map_err(map)?
        .id_from_name(&request.ns)
        .map_err(map)?
        .get_stub()
        .map_err(map)?
        .fetch_with_request(
            Request::new_with_init("https://machine/internal/io", &init).map_err(map)?,
        )
        .await
        .map_err(map)?;
    let result: abi::Return = reply.json().await.map_err(map)?;
    let value = result.into_result()?;
    let delay = value["delay_ms"].as_u64().ok_or(Errno::EIO)?;
    if delay != 0 {
        Delay::from(std::time::Duration::from_millis(delay)).await;
    }
    Ok(())
}
pub async fn request_io(
    env: &worker::Env,
    req: &worker::Request,
    write: bool,
    bytes: u64,
) -> Result<()> {
    let map = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
    let ns = Db::namespace(
        crate::auth::token_key(req).as_deref(),
        crate::auth::guest_key(req).as_deref(),
    );
    let token = req.headers().get("X-Process-Token").map_err(map)?;
    let pid = req
        .headers()
        .get("X-Process-Pid")
        .map_err(map)?
        .map(|p| p.parse::<u32>().map_err(|_| Errno::EINVAL))
        .transpose()?;
    io(env, ns, token, pid, write, bytes).await
}
pub async fn session_io(
    env: &worker::Env,
    state: &worker::State,
    session: std::rc::Rc<crate::sys::Session>,
    write: bool,
    bytes: u64,
) -> Result<()> {
    if session.token.is_none() || bytes == 0 {
        return Ok(());
    }
    let asking = session.clone();
    let browser = crate::db::transact(state, move |db| {
        (
            asking
                .of(db)
                .map(|a| a.credential.is_some_and(|c| c.job().is_none())),
            false,
        )
    })
    .map_err(|e| Error::because(Errno::EIO, e.to_string()))??;
    if browser {
        io(
            env,
            session.namespace(),
            session.token.clone(),
            session.pid,
            write,
            bytes,
        )
        .await?;
    }
    Ok(())
}
pub fn refused(error: abi::Error) -> worker::Result<worker::Response> {
    worker::Response::from_json(&serde_json::json!({"errno":error.errno,"error":error.to_string()}))
        .map(|response| {
            response.with_status(if error.errno == Errno::EAGAIN {
                429
            } else {
                400
            })
        })
}
