//! Durable advisory lock state. The service stores one table per inode and passes the
//! queued waits across all inodes for POSIX deadlock detection.
use crate::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Held {
    pub owner: u64,
    pub family: LockFamily,
    pub kind: LockKind,
    pub range: LockRange,
    pub ticket: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wait {
    pub lock: Held,
    pub ticket: String,
    pub granted: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Locks {
    #[serde(default)]
    pub cancelled: Vec<(u64, String)>,
    pub held: Vec<Held>,
    pub waits: Vec<Wait>,
}
impl Held {
    fn same_lock(&self, other: &Self) -> bool {
        self.owner == other.owner && self.family == other.family && self.kind == other.kind
    }
    pub fn conflicts(&self, other: &Self) -> bool {
        self.owner != other.owner
            && self.family == other.family
            && self.range.overlaps(other.range)
            && (self.kind == LockKind::Exclusive || other.kind == LockKind::Exclusive)
    }
}
impl Locks {
    pub fn conflict(&self, lock: &Held) -> Option<Conflict> {
        let first = self.held.iter().find(|l| l.conflicts(lock))?;
        // Cancellation tickets can partition one logical POSIX lock. F_GETLK reports the
        // entire contiguous range, regardless of which request contributed each piece.
        let mut ranges: Vec<_> = self
            .held
            .iter()
            .filter(|l| l.same_lock(first))
            .map(|l| l.range)
            .collect();
        ranges.sort_unstable_by_key(|r| r.start());
        let mut range = ranges[0];
        for next in ranges.into_iter().skip(1) {
            if range.touches(next) {
                range = range.union(next);
            } else if range.overlaps(first.range) {
                break;
            } else {
                range = next;
            }
        }
        Some(Conflict {
            owner: first.owner,
            kind: first.kind,
            range,
        })
    }
    fn blocked(&self, lock: &Held, ticket: Option<&str>) -> bool {
        self.held.iter().any(|held| held.conflicts(lock))
            || self
                .waits
                .iter()
                .take_while(|w| Some(w.ticket.as_str()) != ticket)
                .any(|w| !w.granted && self.queue_blocks(&w.lock, lock))
    }
    fn queue_blocks(&self, earlier: &Held, lock: &Held) -> bool {
        // A waiter that needs this owner's existing locks must not prevent that owner from
        // updating them. Otherwise a reapply/downgrade creates a false wait cycle. Actual
        // held conflicts still block, and new contenders keep their queue order.
        earlier.conflicts(lock)
            && !self
                .held
                .iter()
                .any(|held| held.owner == lock.owner && held.conflicts(earlier))
    }
    pub fn carve(&mut self, owner: u64, family: LockFamily, range: LockRange) {
        self.held = std::mem::take(&mut self.held)
            .into_iter()
            .flat_map(|l| {
                if l.owner == owner && l.family == family {
                    l.range
                        .minus(range)
                        .into_iter()
                        .flatten()
                        .map(|range| Held { range, ..l.clone() })
                        .collect()
                } else {
                    vec![l]
                }
            })
            .collect();
    }
    fn grant(&mut self, mut lock: Held) {
        self.carve(lock.owner, lock.family, lock.range);
        // Merge only pieces with the same cancellation ownership. A late cancellation
        // must remove that request's surviving pieces without unlocking its neighbors.
        loop {
            let before = self.held.len();
            self.held.retain(|held| {
                if held.same_lock(&lock)
                    && held.ticket == lock.ticket
                    && held.range.touches(lock.range)
                {
                    lock.range = lock.range.union(held.range);
                    false
                } else {
                    true
                }
            });
            if before == self.held.len() {
                break;
            }
        }
        self.held.push(lock);
    }
    pub fn wake(&mut self) {
        for index in 0..self.waits.len() {
            let w = self.waits[index].clone();
            if !w.granted && !self.blocked(&w.lock, Some(&w.ticket)) {
                self.grant(w.lock);
                self.waits[index].granted = true;
            }
        }
    }
    pub fn acquire(&mut self, mut lock: Held, ticket: Option<&str>, all: &[Locks]) -> Result<bool> {
        if let Some(ticket) = ticket {
            if self
                .cancelled
                .iter()
                .any(|(owner, t)| *owner == lock.owner && t == ticket)
            {
                return Err(Errno::ECANCELED);
            }
            if ticket.is_empty() || ticket.len() > 128 {
                return Err(Errno::EINVAL);
            }
            if let Some(w) = self.waits.iter().find(|w| w.ticket == ticket) {
                if w.lock.owner != lock.owner
                    || w.lock.family != lock.family
                    || w.lock.kind != lock.kind
                    || w.lock.range != lock.range
                {
                    return Err(Errno::EINVAL);
                }
                return Ok(w.granted);
            }
            lock.ticket = Some(ticket.into());
        }
        // flock conversion releases the old lock before waiting, as Linux documents.
        if lock.family == LockFamily::Flock
            && self.held.iter().any(|held| {
                held.owner == lock.owner && held.family == lock.family && held.kind != lock.kind
            })
        {
            self.carve(lock.owner, lock.family, LockRange::WHOLE);
            self.wake();
        }
        let blocked = self.blocked(&lock, None);
        if blocked && ticket.is_none() {
            return Err(Errno::EAGAIN);
        }
        if blocked && lock.family == LockFamily::Posix {
            let mut reachable: BTreeSet<_> = self
                .held
                .iter()
                .filter(|l| l.conflicts(&lock))
                .map(|l| l.owner)
                .collect();
            reachable.extend(
                self.waits
                    .iter()
                    .filter(|w| !w.granted && self.queue_blocks(&w.lock, &lock))
                    .map(|w| w.lock.owner),
            );
            loop {
                if reachable.contains(&lock.owner) {
                    return Err(Errno::EDEADLK);
                }
                let before = reachable.len();
                for table in all.iter().chain(std::iter::once(&*self)) {
                    for (i, w) in table
                        .waits
                        .iter()
                        .enumerate()
                        .filter(|(_, w)| !w.granted && w.lock.family == LockFamily::Posix)
                    {
                        if reachable.contains(&w.lock.owner) {
                            reachable.extend(
                                table
                                    .held
                                    .iter()
                                    .filter(|l| l.conflicts(&w.lock))
                                    .map(|l| l.owner),
                            );
                            reachable.extend(
                                table.waits[..i]
                                    .iter()
                                    .filter(|p| !p.granted && table.queue_blocks(&p.lock, &w.lock))
                                    .map(|p| p.lock.owner),
                            );
                        }
                    }
                }
                if reachable.len() == before {
                    break;
                }
            }
        }
        if let Some(ticket) = ticket {
            if self.waits.len() >= 4096 {
                return Err(Errno::ENOSPC);
            }
            self.waits.push(Wait {
                lock: lock.clone(),
                ticket: ticket.into(),
                granted: !blocked,
            });
        }
        if !blocked {
            self.grant(lock);
            self.wake();
        }
        Ok(!blocked)
    }
    pub fn acknowledge(&mut self, owner: u64, ticket: &str) {
        self.waits
            .retain(|w| w.lock.owner != owner || w.ticket != ticket || !w.granted);
    }
    pub fn cancel(&mut self, owner: u64, ticket: &str) {
        if !self
            .cancelled
            .iter()
            .any(|(o, t)| *o == owner && t == ticket)
        {
            self.cancelled.push((owner, ticket.into()));
        }
        self.waits
            .retain(|w| w.lock.owner != owner || w.ticket != ticket);
        self.held
            .retain(|l| l.owner != owner || l.ticket.as_deref() != Some(ticket));
        self.wake();
    }
    pub fn release(&mut self, owner: u64) {
        self.cancelled.retain(|(o, _)| *o != owner);
        self.waits.retain(|w| w.lock.owner != owner);
        self.held.retain(|l| l.owner != owner);
        self.wake();
    }
}
pub fn validate(
    access: Access,
    family: LockFamily,
    kind: Option<LockKind>,
    range: LockRange,
) -> Result<()> {
    if access == Access::Path {
        return Err(Errno::EBADF);
    }
    if range.start() > FILE_MAX
        || range
            .end()
            .is_some_and(|end| end <= range.start() || end > FILE_MAX + 1)
        || family == LockFamily::Flock && range != LockRange::WHOLE
    {
        return Err(Errno::EINVAL);
    }
    if family == LockFamily::Posix
        && kind.is_some_and(|kind| match kind {
            LockKind::Shared => !access.reads(),
            LockKind::Exclusive => !access.writes(),
        })
    {
        return Err(Errno::EBADF);
    }
    Ok(())
}
