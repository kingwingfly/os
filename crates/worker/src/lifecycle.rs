//! Explicit shutdown scopes survive fork, exec, setsid and cgroup changes.
use crate::{
    db::{Db, int, text},
    procs::Row,
};

impl Db {
    fn scoped_processes(&self, ns: &str, scope: Option<&str>) -> Vec<Row> {
        self.processes(ns)
            .into_iter()
            .filter(|p| {
                p.pid != 1
                    && !p.zombie()
                    && scope.is_none_or(|scope| p.login_scope.as_deref() == Some(scope))
            })
            .collect()
    }
    pub(crate) fn stop_scope(&mut self, ns: &str, scope: Option<&str>, now: u64) {
        let rows = self.scoped_processes(ns, scope);
        // Let each top-level executable implement its own graceful child ordering.
        // Orphans are roots too; escaped descendants remain in the durable scope.
        for row in &rows {
            if rows.iter().any(|p| p.pid == row.ppid) {
                continue;
            }
            let signal = if row.tty.is_some() { 1 } else { abi::SIGTERM };
            let _ = self.kill(ns, &row.identity(), row.pid, signal, now);
            let _ = self.kill(ns, &row.identity(), row.pid, abi::SIGCONT, now);
        }
    }
    pub(crate) fn drain_scope(
        &mut self,
        ns: &str,
        scope: Option<&str>,
        force: bool,
        now: u64,
    ) -> bool {
        let rows = self.scoped_processes(ns, scope);
        if force {
            for row in rows {
                let _ = self.kill(ns, &row.identity(), row.pid, abi::SIGKILL, now);
            }
        }
        self.scoped_processes(ns, scope).is_empty()
    }
    pub(crate) fn finish_reboot(&mut self, ns: &str, now: u64) {
        // Monotonic PIDs prevent stale client caches, waits or grants aliasing a new run.
        // Revoke ordinary credentials through the existing durable settlement queue.
        self.run("INSERT OR IGNORE INTO revoked(token) SELECT token FROM processes WHERE ns = ? AND pid != 1", vec![text(ns)]);
        self.run(
            "DELETE FROM leases WHERE pid IN (SELECT pid FROM processes WHERE ns = ? AND pid != 1)",
            vec![text(ns)],
        );
        self.run(
            "DELETE FROM processes WHERE ns = ? AND pid != 1",
            vec![text(ns)],
        );
        self.retire_cgroups(ns, now);
        self.run("DELETE FROM spare", vec![]);
        self.run("DELETE FROM pending_signals", vec![]);
        self.run("DELETE FROM login_sessions WHERE ns = ?", vec![text(ns)]);
        self.run("UPDATE processes SET path = '[init]', argv = '[]', started = ? WHERE ns = ? AND pid = 1", vec![int(now), text(ns)]);
    }
}
