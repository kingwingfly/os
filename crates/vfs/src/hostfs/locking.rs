use super::{HostFs, HostTree, LockGuard, MetaBatch, MetaStore, ProfileLocks};
use crate::locks::{self, Held, Locks};
use crate::{Conflict, LockFamily, LockKind, LockRange, OpenRef, Result};
use std::collections::{BTreeMap, BTreeSet, HashSet};

struct CancelWaitGuard<'a, L: ProfileLocks> {
    locks: &'a L,
    guard: Option<Box<dyn LockGuard>>,
    armed: bool,
}

impl<L: ProfileLocks> Drop for CancelWaitGuard<'_, L> {
    fn drop(&mut self) {
        // Release the per-ticket Web Lock first so any peer querying `held_locks()` immediately
        // observes the dropped ticket.
        drop(self.guard.take());
        if self.armed {
            self.locks.notify_locks();
        }
    }
}

fn is_empty_table(table: &Locks) -> bool {
    table.held.is_empty()
        && table.waits.is_empty()
        && table.displaced.is_empty()
        && table.acknowledged.is_empty()
        && table.cancelled.is_empty()
}

impl<T: HostTree, M: MetaStore, L: ProfileLocks> HostFs<T, M, L> {
    async fn lock_mutex(&self) -> Result<Box<dyn LockGuard>> {
        let name = format!("os-fs-lock:{}", self.uuid);
        self.locks.acquire(&name, LockKind::Exclusive).await
    }

    /// Prune locks and queued waits belonging to crashed tabs (whose `os-fs-open` Web Lock is
    /// gone) or dropped `LockWait` futures (whose `os-fs-wait` Web Lock is gone).
    fn prune_tables(
        &self,
        tables: &mut BTreeMap<u64, Locks>,
        held_locks: &HashSet<String>,
    ) -> BTreeSet<u64> {
        let mut dirty = BTreeSet::new();
        for (&ino, table) in tables.iter_mut() {
            let mut owners = BTreeSet::new();
            for h in &table.held {
                owners.insert(h.owner);
            }
            for w in &table.waits {
                owners.insert(w.lock.owner);
            }
            for d in &table.displaced {
                owners.insert(d.lock.owner);
            }
            for owner in owners {
                let open_lock = format!("os-fs-open:{}:{ino}:{owner}", self.uuid);
                if !held_locks.contains(&open_lock) {
                    table.release(owner);
                    dirty.insert(ino);
                }
            }

            let dropped_waits: Vec<(u64, String)> = table
                .waits
                .iter()
                .filter_map(|w| {
                    let wait_lock = format!(
                        "os-fs-wait:{}:{ino}:{}:{}",
                        self.uuid, w.lock.owner, w.ticket
                    );
                    (!held_locks.contains(&wait_lock)).then(|| (w.lock.owner, w.ticket.clone()))
                })
                .collect();
            for (owner, ticket) in dropped_waits {
                table.cancel(owner, &ticket);
                dirty.insert(ino);
            }
        }
        dirty
    }

    async fn load_and_prune_tables(&self) -> Result<(BTreeMap<u64, Locks>, BTreeSet<u64>)> {
        let held_locks = self.locks.held_locks().await?;
        let mut tables: BTreeMap<u64, Locks> =
            self.meta.list_all_locks().await?.into_iter().collect();
        let dirty = self.prune_tables(&mut tables, &held_locks);
        Ok((tables, dirty))
    }

    async fn flush_dirty_tables(
        &self,
        tables: &BTreeMap<u64, Locks>,
        dirty: BTreeSet<u64>,
    ) -> Result<()> {
        if dirty.is_empty() {
            return Ok(());
        }
        let mut batch = MetaBatch::default();
        for ino in dirty {
            match tables.get(&ino) {
                Some(table) if !is_empty_table(table) => {
                    batch.put_locks.push((ino, table.clone()));
                }
                _ => batch.delete_locks.push(ino),
            }
        }
        self.meta.commit(batch, false).await
    }

    pub(super) async fn release_open_locks(&self, ino: u64, owner: u64) -> Result<()> {
        let Ok(_guard) = self.lock_mutex().await else {
            return Ok(());
        };
        let mut table = self.meta.get_locks(ino).await?;
        let had_any = table.held.iter().any(|h| h.owner == owner)
            || table.waits.iter().any(|w| w.lock.owner == owner)
            || table.displaced.iter().any(|d| d.lock.owner == owner)
            || table.acknowledged.iter().any(|(o, _)| *o == owner)
            || table.cancelled.iter().any(|(o, _)| *o == owner);
        if !had_any {
            return Ok(());
        }
        table.release(owner);
        let mut batch = MetaBatch::default();
        if is_empty_table(&table) {
            batch.delete_locks.push(ino);
        } else {
            batch.put_locks.push((ino, table));
        }
        self.meta.commit(batch, false).await?;
        self.locks.notify_locks();
        Ok(())
    }

    pub(super) async fn do_try_lock(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Result<()> {
        self.ensure_version().await?;
        let (ino, access, _) = self.get_open_info(open)?;
        locks::validate(access, family, Some(kind), range)?;
        {
            let _ns = self.ns_lock(LockKind::Shared).await?;
            self.validate_inode_by_id(ino).await?;
        }

        let _guard = self.lock_mutex().await?;
        let (mut tables, mut dirty) = self.load_and_prune_tables().await?;
        let mut target = tables.remove(&ino).unwrap_or_default();
        let others: Vec<Locks> = tables.values().cloned().collect();
        let res = target.acquire(
            Held {
                owner: open.id,
                family,
                kind,
                range,
                ticket: None,
            },
            None,
            &others,
        );
        // Even on EAGAIN, a flock conversion may have released the old lock before failing.
        dirty.insert(ino);
        tables.insert(ino, target);
        self.flush_dirty_tables(&tables, dirty).await?;
        self.locks.notify_locks();
        res.map(|_| ())
    }

    pub(super) async fn do_lock(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Result<()> {
        self.ensure_version().await?;
        let (ino, access, _) = self.get_open_info(open)?;
        locks::validate(access, family, Some(kind), range)?;
        {
            let _ns = self.ns_lock(LockKind::Shared).await?;
            self.validate_inode_by_id(ino).await?;
        }

        let ticket = self.locks.new_ticket();
        let wait_lock_name = format!("os-fs-wait:{}:{ino}:{}:{ticket}", self.uuid, open.id);
        let wait_guard = self
            .locks
            .acquire(&wait_lock_name, LockKind::Exclusive)
            .await?;
        let mut cancel_guard = CancelWaitGuard {
            locks: &self.locks,
            guard: Some(wait_guard),
            armed: true,
        };

        loop {
            self.ensure_version().await?;
            let _ = self.get_open_info(open)?;
            {
                let _ns = self.ns_lock(LockKind::Shared).await?;
                self.validate_inode_by_id(ino).await?;
            }

            let blocking_locks = {
                let _guard = self.lock_mutex().await?;
                let (mut tables, mut dirty) = self.load_and_prune_tables().await?;
                let mut target = tables.remove(&ino).unwrap_or_default();
                let others: Vec<Locks> = tables.values().cloned().collect();
                let res = target.acquire(
                    Held {
                        owner: open.id,
                        family,
                        kind,
                        range,
                        ticket: None,
                    },
                    Some(&ticket),
                    &others,
                );
                match res {
                    Ok(true) => {
                        target.acknowledge(open.id, &ticket);
                        target.wake();
                        dirty.insert(ino);
                        tables.insert(ino, target);
                        self.flush_dirty_tables(&tables, dirty).await?;
                        cancel_guard.armed = false;
                        self.locks.notify_locks();
                        return Ok(());
                    }
                    Ok(false) => {
                        let mut blockers = BTreeSet::new();
                        for h in &target.held {
                            if h.owner != open.id {
                                blockers
                                    .insert(format!("os-fs-open:{}:{ino}:{}", self.uuid, h.owner));
                            }
                        }
                        for w in &target.waits {
                            if w.lock.owner != open.id {
                                blockers.insert(format!(
                                    "os-fs-open:{}:{ino}:{}",
                                    self.uuid, w.lock.owner
                                ));
                            }
                        }
                        dirty.insert(ino);
                        tables.insert(ino, target);
                        self.flush_dirty_tables(&tables, dirty).await?;
                        self.locks.notify_locks();
                        blockers.into_iter().collect::<Vec<_>>()
                    }
                    Err(err) => {
                        dirty.insert(ino);
                        tables.insert(ino, target);
                        self.flush_dirty_tables(&tables, dirty).await?;
                        cancel_guard.armed = false;
                        return Err(err);
                    }
                }
            };

            self.locks.wait_for_change(&blocking_locks).await?;
        }
    }

    pub(super) async fn do_unlock(
        &self,
        open: &OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> Result<()> {
        self.ensure_version().await?;
        let (ino, access, _) = self.get_open_info(open)?;
        locks::validate(access, family, None, range)?;
        {
            let _ns = self.ns_lock(LockKind::Shared).await?;
            self.validate_inode_by_id(ino).await?;
        }

        let _guard = self.lock_mutex().await?;
        let (mut tables, mut dirty) = self.load_and_prune_tables().await?;
        if let Some(target) = tables.get_mut(&ino) {
            target.carve(open.id, family, range);
            target.wake();
            dirty.insert(ino);
        }
        self.flush_dirty_tables(&tables, dirty).await?;
        self.locks.notify_locks();
        Ok(())
    }

    pub(super) async fn do_test_lock(
        &self,
        open: &OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> Result<Option<Conflict>> {
        self.ensure_version().await?;
        let (ino, access, _) = self.get_open_info(open)?;
        locks::validate(access, LockFamily::Posix, None, range)?;
        {
            let _ns = self.ns_lock(LockKind::Shared).await?;
            self.validate_inode_by_id(ino).await?;
        }

        let _guard = self.lock_mutex().await?;
        let (tables, dirty) = self.load_and_prune_tables().await?;
        let conflict = tables.get(&ino).and_then(|target| {
            target.conflict(&Held {
                owner: open.id,
                family: LockFamily::Posix,
                kind,
                range,
                ticket: None,
            })
        });
        self.flush_dirty_tables(&tables, dirty).await?;
        Ok(conflict)
    }
}
