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
/// A piece of its owner's own lock that a ticketed grant replaced (an upgrade, downgrade or
/// reapplication). A late cancellation of that ticket puts it back instead of unlocking it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Displaced {
    pub ticket: String,
    pub lock: Held,
}
/// How many acknowledged tickets an owner keeps rollback history for before committing the
/// oldest; sequential driver calls drain deferred cancellations before acquiring again.
pub const ACKNOWLEDGED_MAX: usize = 1024;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Locks {
    #[serde(default)]
    pub cancelled: BTreeSet<(u64, String)>,
    pub held: Vec<Held>,
    pub waits: Vec<Wait>,
    #[serde(default)]
    pub displaced: Vec<Displaced>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub acknowledged: Vec<(u64, String)>,
}
/// What `piece` keeps of an owner and family's locks once `range` is taken out of them.
fn cut(piece: &Held, owner: u64, family: LockFamily, range: LockRange) -> Vec<LockRange> {
    if piece.owner == owner && piece.family == family {
        piece.range.minus(range).into_iter().flatten().collect()
    } else {
        vec![piece.range]
    }
}
/// The bytes both ranges cover, if any.
fn intersection(a: LockRange, b: LockRange) -> Option<LockRange> {
    if !a.overlaps(b) {
        return None;
    }
    let end = match (a.end(), b.end()) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) | (None, x) => x,
    };
    LockRange::new(a.start().max(b.start()), end)
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
                .take_while(|w| ticket.is_none_or(|t| w.lock.owner != lock.owner || w.ticket != t))
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
    fn cut_held(&mut self, owner: u64, family: LockFamily, range: LockRange) {
        self.held = std::mem::take(&mut self.held)
            .into_iter()
            .flat_map(|l| {
                cut(&l, owner, family, range)
                    .into_iter()
                    .map(move |range| Held { range, ..l.clone() })
            })
            .collect();
    }
    pub fn carve(&mut self, owner: u64, family: LockFamily, range: LockRange) {
        self.cut_held(owner, family, range);
        // Non-cancellable replacements (try_lock, unlock, flock conversion) permanently
        // supersede whatever an earlier ticketed request would have restored on these bytes.
        self.displaced = std::mem::take(&mut self.displaced)
            .into_iter()
            .flat_map(|d| {
                cut(&d.lock, owner, family, range)
                    .into_iter()
                    .map(move |range| Displaced {
                        ticket: d.ticket.clone(),
                        lock: Held {
                            range,
                            ..d.lock.clone()
                        },
                    })
            })
            .collect();
        self.prune_acknowledged(owner);
    }
    fn insert_held(&mut self, mut lock: Held) {
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
    fn grant(&mut self, lock: Held) {
        if let Some(ticket) = &lock.ticket {
            let replaced: Vec<Held> = self
                .held
                .iter()
                .filter(|l| l.owner == lock.owner && l.family == lock.family)
                .filter_map(|l| {
                    intersection(l.range, lock.range).map(|range| Held { range, ..l.clone() })
                })
                .collect();
            self.cut_held(lock.owner, lock.family, lock.range);
            self.displaced
                .extend(replaced.into_iter().map(|lock| Displaced {
                    ticket: ticket.clone(),
                    lock,
                }));
        } else {
            self.carve(lock.owner, lock.family, lock.range);
        }
        self.insert_held(lock);
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
            if ticket.is_empty() || ticket.len() > 128 {
                return Err(Errno::EINVAL);
            }
            if self.cancelled.contains(&(lock.owner, ticket.into())) {
                return Err(Errno::ECANCELED);
            }
            if let Some(w) = self
                .waits
                .iter()
                .find(|w| w.lock.owner == lock.owner && w.ticket == ticket)
            {
                if w.lock.family != lock.family
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
    fn commit_ticket(&mut self, owner: u64, ticket: &str) {
        self.displaced
            .retain(|d| d.lock.owner != owner || d.ticket != ticket);
        for d in &mut self.displaced {
            if d.lock.owner == owner && d.lock.ticket.as_deref() == Some(ticket) {
                d.lock.ticket = None;
            }
        }
        let (committed, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|l| l.owner == owner && l.ticket.as_deref() == Some(ticket));
        self.held = keep;
        for mut lock in committed {
            lock.ticket = None;
            self.insert_held(lock);
        }
    }
    fn is_tracked(&self, owner: u64, ticket: &str) -> bool {
        self.held
            .iter()
            .any(|l| l.owner == owner && l.ticket.as_deref() == Some(ticket))
            || self.displaced.iter().any(|d| {
                d.lock.owner == owner
                    && (d.ticket == ticket || d.lock.ticket.as_deref() == Some(ticket))
            })
    }
    fn prune_acknowledged(&mut self, owner: u64) {
        let stale: BTreeSet<String> = self
            .acknowledged
            .iter()
            .filter(|(o, t)| *o == owner && !self.is_tracked(owner, t))
            .map(|(_, t)| t.clone())
            .collect();
        if !stale.is_empty() {
            self.acknowledged
                .retain(|(o, t)| *o != owner || !stale.contains(t));
        }
    }
    pub fn acknowledge(&mut self, owner: u64, ticket: &str) {
        self.waits
            .retain(|w| w.lock.owner != owner || w.ticket != ticket || !w.granted);
        if self.is_tracked(owner, ticket)
            && !self
                .acknowledged
                .iter()
                .any(|(o, t)| *o == owner && t == ticket)
        {
            self.acknowledged.push((owner, ticket.into()));
            while self
                .acknowledged
                .iter()
                .filter(|(o, _)| *o == owner)
                .count()
                > ACKNOWLEDGED_MAX
            {
                let pos = self
                    .acknowledged
                    .iter()
                    .position(|(o, _)| *o == owner)
                    .expect("counted above");
                let (_, oldest) = self.acknowledged.remove(pos);
                self.commit_ticket(owner, &oldest);
            }
        }
    }
    pub fn cancel(&mut self, owner: u64, ticket: &str) {
        if ticket.is_empty() || ticket.len() > 128 {
            return;
        }
        self.cancelled.insert((owner, ticket.into()));
        self.acknowledged
            .retain(|(o, t)| *o != owner || t != ticket);
        self.waits
            .retain(|w| w.lock.owner != owner || w.ticket != ticket);
        let (active, keep_held): (Vec<_>, Vec<_>) = std::mem::take(&mut self.held)
            .into_iter()
            .partition(|l| l.owner == owner && l.ticket.as_deref() == Some(ticket));
        self.held = keep_held;
        let (own_displaced, other_displaced): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.displaced)
                .into_iter()
                .partition(|d| d.lock.owner == owner && d.ticket == ticket);
        // If a later ticketed lock overlapped this one and is cancelled after it, splice this
        // cancelled grant out of that later ticket's displaced chain so it restores what was
        // held before this grant (or nothing), never this cancelled grant itself.
        self.displaced = other_displaced
            .into_iter()
            .flat_map(|d| {
                if d.lock.owner == owner && d.lock.ticket.as_deref() == Some(ticket) {
                    own_displaced
                        .iter()
                        .filter(|p| p.lock.family == d.lock.family)
                        .filter_map(|p| {
                            intersection(p.lock.range, d.lock.range).map(|range| Displaced {
                                ticket: d.ticket.clone(),
                                lock: Held {
                                    range,
                                    ..p.lock.clone()
                                },
                            })
                        })
                        .collect::<Vec<_>>()
                } else {
                    vec![d]
                }
            })
            .collect();
        // Undo what the cancelled grant replaced on the bytes it still owned, splitting at
        // any subrange where another owner has since taken a lock the downgrade allowed.
        for granted in active {
            for prior in own_displaced
                .iter()
                .filter(|p| p.lock.family == granted.family)
            {
                let Some(overlap) = intersection(prior.lock.range, granted.range) else {
                    continue;
                };
                let candidate = Held {
                    range: overlap,
                    ..prior.lock.clone()
                };
                let mut uncontested = vec![overlap];
                for other in &self.held {
                    if other.conflicts(&candidate) {
                        uncontested = uncontested
                            .into_iter()
                            .flat_map(|seg| seg.minus(other.range).into_iter().flatten())
                            .collect();
                    }
                }
                let mut contested = vec![overlap];
                for seg in &uncontested {
                    contested = contested
                        .into_iter()
                        .flat_map(|c| c.minus(*seg).into_iter().flatten())
                        .collect();
                }
                for range in uncontested {
                    self.insert_held(Held {
                        range,
                        ..prior.lock.clone()
                    });
                }
                for range in contested {
                    self.insert_held(Held {
                        range,
                        ticket: prior.lock.ticket.clone(),
                        ..granted.clone()
                    });
                }
            }
        }
        self.wake();
    }
    pub fn release(&mut self, owner: u64) {
        self.displaced.retain(|d| d.lock.owner != owner);
        self.cancelled.retain(|(o, _)| *o != owner);
        self.acknowledged.retain(|(o, _)| *o != owner);
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
