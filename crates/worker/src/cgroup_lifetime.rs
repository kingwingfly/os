//! Generic process-owned cgroup lifetimes. No executable or service names are interpreted.
use crate::{
    db::{Db, int, text},
    procs::Row,
};
use abi::{Errno, Error};
use kernel::registry::in_subtree;
use serde::Deserialize;
use serde_json::{Value, json};
use worker::SqlStorage;

#[derive(Deserialize)]
struct Lifetime {
    path: String,
    pid: u32,
    retiring: u32,
}

pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    sql.exec("CREATE TABLE IF NOT EXISTS cgroup_lifetimes(ns TEXT NOT NULL, path TEXT NOT NULL, pid INTEGER NOT NULL, retiring INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(ns, path))", None)?;
    sql.exec("CREATE TRIGGER IF NOT EXISTS cgroup_lifetime_remove AFTER DELETE ON cgroups BEGIN DELETE FROM cgroup_lifetimes WHERE ns = old.ns AND path = old.path; END", None)?;
    Ok(())
}
impl Db {
    fn lifetimes(&self, ns: &str) -> Vec<Lifetime> {
        self.rows(
            "SELECT path, pid, retiring FROM cgroup_lifetimes WHERE ns = ?",
            vec![text(ns)],
        )
    }
    pub(crate) fn check_cgroup_lifetime(&self, owner: &Row, path: &str) -> Result<(), Error> {
        let entries = self.lifetimes(&owner.ns);
        if owner.pid == 1 || owner.zombie() || in_subtree(&owner.cgroup, path) {
            return Err(Errno::EPERM.into());
        }
        if entries.len() >= 128
            || entries
                .iter()
                .filter(|entry| entry.pid == owner.pid)
                .count()
                >= 32
        {
            return Err(Errno::ENOSPC.into());
        }
        Ok(())
    }
    pub(crate) fn bind_cgroup(&mut self, owner: &Row, path: &str) {
        self.run(
            "INSERT INTO cgroup_lifetimes(ns, path, pid) VALUES(?, ?, ?)",
            vec![text(&owner.ns), text(path), int(owner.pid)],
        );
    }
    pub(crate) fn cgroup_lifetime(&self, ns: &str, path: &str) -> Value {
        self.lifetimes(ns)
            .into_iter()
            .find(|l| l.path == path)
            .map(|l| json!({"pid": l.pid, "retiring": l.retiring != 0}))
            .unwrap_or(Value::Null)
    }
    pub(crate) fn cgroup_available(&self, ns: &str, path: &str) -> Result<(), Error> {
        if self
            .lifetimes(ns)
            .iter()
            .any(|l| l.retiring != 0 && in_subtree(path, &l.path))
        {
            return Err(Error::because(Errno::ESTALE, "cgroup owner ended"));
        }
        Ok(())
    }
    /// A transaction serializes this recursive SIGKILL with fork and migration.
    pub(crate) fn kill_cgroup(&mut self, ns: &str, path: &str, now: u64) {
        let pids: Vec<_> = self
            .processes(ns)
            .iter()
            .filter(|p| p.pid != 1 && !p.zombie() && in_subtree(&p.cgroup, path))
            .map(|p| p.pid)
            .collect();
        for pid in pids {
            // Nested owner cleanup may already have ended this row.
            if let Some(row) = self.process(ns, pid).filter(|p| !p.zombie()) {
                let _ = self.kill(ns, &row.identity(), pid, abi::SIGKILL, now);
            }
        }
    }
    pub(crate) fn retire_cgroups(&mut self, ns: &str, now: u64) {
        let ended: Vec<_> = self
            .lifetimes(ns)
            .into_iter()
            .filter(|l| l.retiring == 0 && self.process(ns, l.pid).is_none_or(|p| p.zombie()))
            .collect();
        // Mark every dead owner's subtree first, before recursively ending members.
        for l in &ended {
            self.run(
                "UPDATE cgroup_lifetimes SET retiring = 1 WHERE ns = ? AND path = ?",
                vec![text(ns), text(&l.path)],
            );
        }
        for l in ended {
            self.kill_cgroup(ns, &l.path, now);
        }
        self.prune_cgroups(ns);
    }
    pub(crate) fn prune_cgroups(&mut self, ns: &str) {
        #[derive(Deserialize)]
        struct Path {
            path: String,
        }
        let processes = self.processes(ns);
        for l in self.lifetimes(ns).into_iter().filter(|l| l.retiring != 0) {
            if processes.iter().any(|p| in_subtree(&p.cgroup, &l.path)) {
                continue;
            }
            let groups = self.rows::<Path>("SELECT path FROM cgroups WHERE ns = ?", vec![text(ns)]);
            for group in groups.into_iter().filter(|g| in_subtree(&g.path, &l.path)) {
                self.run(
                    "DELETE FROM cgroups WHERE ns = ? AND path = ?",
                    vec![text(ns), text(&group.path)],
                );
            }
        }
    }
}
