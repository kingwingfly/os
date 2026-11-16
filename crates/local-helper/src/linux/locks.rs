//! Host kernel `flock(2)` and Linux Open File Description (`F_OFD_*`) byte-range locks with
//! queued blocking tickets, helper-wide deadlock detection (`EDEADLK`), cancellation rollback, and
//! teardown on descriptor close or session loss.

use super::sys;
use abi::Errno;
use abi::fs::{Access, Conflict, LockFamily, LockKind, LockRange};
use abi::local_helper::LockOutcome;
use os_vfs::locks::{ACKNOWLEDGED_MAX, Displaced, Held, validate};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::os::fd::BorrowedFd;

#[derive(Clone, Debug)]
struct WaitEntry {
    lock: Held,
    ticket: String,
}

#[derive(Clone, Debug)]
struct GrantedTicket {
    owner: u64,
    ticket: String,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
}

#[derive(Default)]
struct InodeLocks {
    held: Vec<Held>,
    waits: Vec<WaitEntry>,
    displaced: Vec<Displaced>,
    granted: VecDeque<GrantedTicket>,
}

#[derive(Default)]
pub struct LockManager {
    inodes: HashMap<u64, InodeLocks>,
    cancelled: BTreeSet<(u64, String)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockSpec {
    pub family: LockFamily,
    pub kind: LockKind,
    pub range: LockRange,
}

fn same_lock(a: &Held, b: &Held) -> bool {
    a.owner == b.owner && a.family == b.family && a.kind == b.kind
}

fn cut(piece: &Held, owner: u64, family: LockFamily, range: LockRange) -> Vec<LockRange> {
    if piece.owner == owner && piece.family == family {
        piece.range.minus(range).into_iter().flatten().collect()
    } else {
        vec![piece.range]
    }
}

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

fn subtract_ranges(source: &[LockRange], remove: &[LockRange]) -> Vec<LockRange> {
    let mut out = source.to_vec();
    for &r in remove {
        out = out
            .into_iter()
            .flat_map(|seg| seg.minus(r).into_iter().flatten())
            .collect();
    }
    out
}

fn owner_family_locks(held: &[Held], owner: u64, family: LockFamily) -> Vec<(LockKind, LockRange)> {
    let mut own: Vec<(LockKind, LockRange)> = held
        .iter()
        .filter(|h| h.owner == owner && h.family == family)
        .map(|h| (h.kind, h.range))
        .collect();
    own.sort_unstable_by_key(|(k, r)| (r.start(), *k == LockKind::Exclusive));
    let mut merged: Vec<(LockKind, LockRange)> = Vec::with_capacity(own.len());
    for (k, r) in own {
        if let Some((last_k, last_r)) = merged.last_mut()
            && *last_k == k
            && last_r.touches(r)
        {
            *last_r = last_r.union(r);
        } else {
            merged.push((k, r));
        }
    }
    merged
}

impl InodeLocks {
    fn queue_blocks(&self, earlier: &Held, lock: &Held) -> bool {
        earlier.conflicts(lock)
            && !self
                .held
                .iter()
                .any(|held| held.owner == lock.owner && held.conflicts(earlier))
    }

    fn blocked_for(&self, wait_limit: usize, lock: &Held) -> bool {
        self.held.iter().any(|held| held.conflicts(lock))
            || self.waits[..wait_limit]
                .iter()
                .any(|earlier| self.queue_blocks(&earlier.lock, lock))
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

    fn is_tracked(&self, owner: u64, ticket: &str) -> bool {
        self.held
            .iter()
            .any(|l| l.owner == owner && l.ticket.as_deref() == Some(ticket))
            || self.displaced.iter().any(|d| {
                d.lock.owner == owner
                    && (d.ticket == ticket || d.lock.ticket.as_deref() == Some(ticket))
            })
    }

    fn prune_granted(&mut self, owner: u64) {
        let stale: BTreeSet<String> = self
            .granted
            .iter()
            .filter(|g| g.owner == owner && !self.is_tracked(owner, &g.ticket))
            .map(|g| g.ticket.clone())
            .collect();
        if !stale.is_empty() {
            self.granted
                .retain(|g| g.owner != owner || !stale.contains(&g.ticket));
        }
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

    fn carve(&mut self, owner: u64, family: LockFamily, range: LockRange) {
        self.cut_held(owner, family, range);
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
        self.prune_granted(owner);
    }

    fn insert_held(&mut self, mut lock: Held) {
        loop {
            let before = self.held.len();
            self.held.retain(|held| {
                if same_lock(held, &lock)
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

    fn grant_ticketed(&mut self, lock: Held) {
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

    fn record_granted(&mut self, lock: &Held) {
        let Some(ticket) = lock.ticket.as_ref() else {
            return;
        };
        if !self.is_tracked(lock.owner, ticket) {
            return;
        }
        if !self
            .granted
            .iter()
            .any(|g| g.owner == lock.owner && g.ticket == *ticket)
        {
            self.granted.push_back(GrantedTicket {
                owner: lock.owner,
                ticket: ticket.clone(),
                family: lock.family,
                kind: lock.kind,
                range: lock.range,
            });
            while self
                .granted
                .iter()
                .filter(|g| g.owner == lock.owner)
                .count()
                > ACKNOWLEDGED_MAX
            {
                let pos = self
                    .granted
                    .iter()
                    .position(|g| g.owner == lock.owner)
                    .expect("counted above");
                let oldest = self.granted.remove(pos).expect("index valid");
                self.commit_ticket(lock.owner, &oldest.ticket);
            }
        }
    }

    fn clear_ticket_displaced(&mut self, owner: u64, ticket: &str) {
        self.displaced
            .retain(|d| !(d.lock.owner == owner && d.ticket == ticket));
    }

    fn keep_prior_kind_on_overlap(&mut self, owner: u64, overlap: LockRange, prior_kind: LockKind) {
        let mut split = Vec::with_capacity(self.held.len() + 2);
        for piece in self.held.drain(..) {
            if piece.owner == owner
                && piece.family == LockFamily::Posix
                && let Some(hit) = intersection(piece.range, overlap)
            {
                for rem in piece.range.minus(hit).into_iter().flatten() {
                    split.push(Held {
                        range: rem,
                        ..piece.clone()
                    });
                }
                split.push(Held {
                    kind: prior_kind,
                    range: hit,
                    ..piece
                });
            } else {
                split.push(piece);
            }
        }
        for piece in split {
            self.insert_held(piece);
        }
    }

    fn conflict(&self, lock: &Held) -> Option<Conflict> {
        let first = self.held.iter().find(|l| l.conflicts(lock))?;
        let mut ranges: Vec<_> = self
            .held
            .iter()
            .filter(|l| same_lock(l, first))
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
}

impl LockManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_lock(
        &mut self,
        ino: u64,
        open_id: u64,
        access: Access,
        fd: BorrowedFd<'_>,
        spec: LockSpec,
    ) -> Result<(), Errno> {
        let LockSpec {
            family,
            kind,
            range,
        } = spec;
        validate(access, family, Some(kind), range)?;
        let req = Held {
            owner: open_id,
            family,
            kind,
            range,
            ticket: None,
        };

        // Linux flock(2) drops the descriptor's old flock BEFORE checking conflicts or converting
        // (even on EAGAIN with LOCK_NB). Drop and carve before checking queue eligibility.
        if family == LockFamily::Flock
            && self.inodes.get(&ino).is_some_and(|il| {
                il.held
                    .iter()
                    .any(|h| h.owner == open_id && h.family == LockFamily::Flock && h.kind != kind)
            })
        {
            let _ = sys::flock_fd(fd, libc::LOCK_UN);
            if let Some(il) = self.inodes.get_mut(&ino) {
                il.carve(open_id, LockFamily::Flock, LockRange::WHOLE);
            }
        }

        if self
            .inodes
            .get(&ino)
            .is_some_and(|il| il.blocked_for(il.waits.len(), &req))
        {
            self.cleanup_empty_inode(ino);
            return Err(Errno::EAGAIN);
        }

        if let Err(err) = host_try_lock(fd, family, kind, range) {
            self.cleanup_empty_inode(ino);
            return Err(err);
        }

        let il = self.inodes.entry(ino).or_default();
        il.carve(open_id, family, range);
        il.insert_held(req);
        Ok(())
    }

    pub fn lock(
        &mut self,
        ino: u64,
        open_id: u64,
        access: Access,
        fd: BorrowedFd<'_>,
        spec: LockSpec,
        ticket: &str,
    ) -> Result<LockOutcome, Errno> {
        let LockSpec {
            family,
            kind,
            range,
        } = spec;
        validate(access, family, Some(kind), range)?;
        if ticket.is_empty() || ticket.len() > 128 {
            return Err(Errno::EINVAL);
        }
        let key = (open_id, ticket.to_owned());
        if self.cancelled.contains(&key) {
            return Err(Errno::ECANCELED);
        }

        // Idempotent retry if this ticket already acquired and has not been cancelled.
        if let Some(prev) = self.inodes.get(&ino).and_then(|il| {
            il.granted
                .iter()
                .find(|g| g.owner == open_id && g.ticket == ticket)
        }) {
            if (prev.family, prev.kind, prev.range) != (family, kind, range) {
                return Err(Errno::EINVAL);
            }
            return Ok(LockOutcome::Acquired);
        }

        // Existing waiter polling?
        if let Some(pos) = self.inodes.get(&ino).and_then(|il| {
            il.waits
                .iter()
                .position(|w| w.lock.owner == open_id && w.ticket == ticket)
        }) {
            let existing = &self.inodes[&ino].waits[pos].lock;
            if existing.family != family || existing.kind != kind || existing.range != range {
                return Err(Errno::EINVAL);
            }
            let can_try = self
                .inodes
                .get(&ino)
                .is_some_and(|il| !il.blocked_for(pos, &il.waits[pos].lock));
            if can_try {
                match host_try_lock(fd, family, kind, range) {
                    Ok(()) => {
                        let il = self.inodes.get_mut(&ino).expect("inode");
                        let wait = il.waits.remove(pos);
                        il.grant_ticketed(wait.lock.clone());
                        il.record_granted(&wait.lock);
                        self.cleanup_empty_inode(ino);
                        return Ok(LockOutcome::Acquired);
                    }
                    Err(Errno::EAGAIN) => {}
                    Err(other) => {
                        let il = self.inodes.get_mut(&ino).expect("inode");
                        il.waits.remove(pos);
                        il.clear_ticket_displaced(open_id, ticket);
                        self.cleanup_empty_inode(ino);
                        return Err(other);
                    }
                }
            }
            if family == LockFamily::Posix && self.has_cycle(open_id) {
                let il = self.inodes.get_mut(&ino).expect("inode");
                il.waits.remove(pos);
                il.clear_ticket_displaced(open_id, ticket);
                self.cleanup_empty_inode(ino);
                return Err(Errno::EDEADLK);
            }
            return Ok(LockOutcome::Pending);
        }

        // First call for `(open_id, ticket)`.
        let req = Held {
            owner: open_id,
            family,
            kind,
            range,
            ticket: Some(ticket.to_owned()),
        };

        let mut dropped_flock_conversion = false;
        if family == LockFamily::Flock
            && let Some(prior) = self.inodes.get(&ino).and_then(|il| {
                il.held
                    .iter()
                    .find(|h| h.owner == open_id && h.family == LockFamily::Flock && h.kind != kind)
                    .cloned()
            })
        {
            let _ = sys::flock_fd(fd, libc::LOCK_UN);
            let il = self.inodes.get_mut(&ino).expect("inode");
            il.cut_held(open_id, LockFamily::Flock, LockRange::WHOLE);
            il.displaced.push(Displaced {
                ticket: ticket.to_owned(),
                lock: prior,
            });
            dropped_flock_conversion = true;
        }

        let blocked = self
            .inodes
            .get(&ino)
            .is_some_and(|il| il.blocked_for(il.waits.len(), &req));

        if !blocked {
            match host_try_lock(fd, family, kind, range) {
                Ok(()) => {
                    let il = self.inodes.entry(ino).or_default();
                    il.grant_ticketed(req.clone());
                    il.record_granted(&req);
                    return Ok(LockOutcome::Acquired);
                }
                Err(Errno::EAGAIN) => {}
                Err(other) => {
                    if dropped_flock_conversion && let Some(il) = self.inodes.get_mut(&ino) {
                        il.clear_ticket_displaced(open_id, ticket);
                    }
                    self.cleanup_empty_inode(ino);
                    return Err(other);
                }
            }
        }

        let il = self.inodes.entry(ino).or_default();
        if il.waits.len() >= 4096 {
            if dropped_flock_conversion {
                il.clear_ticket_displaced(open_id, ticket);
            }
            self.cleanup_empty_inode(ino);
            return Err(Errno::ENOSPC);
        }
        il.waits.push(WaitEntry {
            lock: req,
            ticket: ticket.to_owned(),
        });

        if family == LockFamily::Posix && self.has_cycle(open_id) {
            if let Some(il) = self.inodes.get_mut(&ino) {
                il.waits
                    .retain(|w| !(w.lock.owner == open_id && w.ticket == ticket));
                il.clear_ticket_displaced(open_id, ticket);
            }
            self.cleanup_empty_inode(ino);
            return Err(Errno::EDEADLK);
        }

        Ok(LockOutcome::Pending)
    }

    pub fn unlock(
        &mut self,
        ino: u64,
        open_id: u64,
        access: Access,
        fd: BorrowedFd<'_>,
        family: LockFamily,
        range: LockRange,
    ) -> Result<(), Errno> {
        validate(access, family, None, range)?;
        host_unlock(fd, family, range)?;
        if let Some(il) = self.inodes.get_mut(&ino) {
            il.carve(open_id, family, range);
        }
        self.cleanup_empty_inode(ino);
        Ok(())
    }

    pub fn test_lock(
        &mut self,
        ino: u64,
        open_id: u64,
        access: Access,
        fd: BorrowedFd<'_>,
        kind: LockKind,
        range: LockRange,
    ) -> Result<Option<Conflict>, Errno> {
        validate(access, LockFamily::Posix, None, range)?;
        let Some((ckind, crange, lpid)) = sys::ofd_getlk(fd, kind, range)? else {
            return Ok(None);
        };
        let probe = Held {
            owner: open_id,
            family: LockFamily::Posix,
            kind,
            range: crange,
            ticket: None,
        };
        if lpid > 0 {
            return Ok(Some(Conflict {
                kind: ckind,
                range: crange,
                owner: lpid as u64,
            }));
        }
        let owner = self
            .inodes
            .get(&ino)
            .and_then(|il| il.conflict(&probe))
            .map(|c| c.owner)
            .unwrap_or(0);
        Ok(Some(Conflict {
            kind: ckind,
            range: crange,
            owner,
        }))
    }

    /// Cancel an in-flight or uncertainly completed lock ticket; if the ticket already displaced or
    /// replaced an earlier lock (including a pending `flock` conversion), restore the prior state
    /// via minimal host lock adjustments without dropping uninvolved ranges.
    pub fn cancel_lock(
        &mut self,
        open_id: u64,
        fd: Option<BorrowedFd<'_>>,
        ticket: &str,
    ) -> Result<(), Errno> {
        if ticket.is_empty() || ticket.len() > 128 {
            return Err(Errno::EINVAL);
        }
        let key = (open_id, ticket.to_owned());
        self.cancelled.insert(key);

        let target_inos: Vec<u64> = self
            .inodes
            .iter()
            .filter_map(|(&ino, il)| {
                let touched = il
                    .waits
                    .iter()
                    .any(|w| w.lock.owner == open_id && w.ticket == ticket)
                    || il
                        .held
                        .iter()
                        .any(|h| h.owner == open_id && h.ticket.as_deref() == Some(ticket))
                    || il
                        .displaced
                        .iter()
                        .any(|d| d.lock.owner == open_id && d.ticket == ticket)
                    || il
                        .granted
                        .iter()
                        .any(|g| g.owner == open_id && g.ticket == ticket);
                touched.then_some(ino)
            })
            .collect();

        for ino in target_inos {
            let Some(il) = self.inodes.get_mut(&ino) else {
                continue;
            };
            il.granted
                .retain(|g| !(g.owner == open_id && g.ticket == ticket));
            let wait_pos = il
                .waits
                .iter()
                .position(|w| w.lock.owner == open_id && w.ticket == ticket);
            let wait_family = wait_pos.map(|pos| il.waits.remove(pos).lock.family);

            let active_family = il
                .held
                .iter()
                .find(|h| h.owner == open_id && h.ticket.as_deref() == Some(ticket))
                .map(|h| h.family);
            let displaced_family = il
                .displaced
                .iter()
                .find(|d| d.lock.owner == open_id && d.ticket == ticket)
                .map(|d| d.lock.family);
            let Some(family) = active_family.or(displaced_family).or(wait_family) else {
                self.cleanup_empty_inode(ino);
                continue;
            };

            let before = owner_family_locks(&il.held, open_id, family);

            let (active, keep_held): (Vec<_>, Vec<_>) = std::mem::take(&mut il.held)
                .into_iter()
                .partition(|l| l.owner == open_id && l.ticket.as_deref() == Some(ticket));
            il.held = keep_held;

            let (own_displaced, other_displaced): (Vec<_>, Vec<_>) =
                std::mem::take(&mut il.displaced)
                    .into_iter()
                    .partition(|d| d.lock.owner == open_id && d.ticket == ticket);

            // Splice this cancelled ticket out of any later ticket's displacement chain so
            // cancelling tickets in any order converges cleanly.
            il.displaced = other_displaced
                .into_iter()
                .flat_map(|d| {
                    if d.lock.owner == open_id && d.lock.ticket.as_deref() == Some(ticket) {
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

            if !active.is_empty() {
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
                        for other in &il.held {
                            if other.conflicts(&candidate) {
                                uncontested = uncontested
                                    .into_iter()
                                    .flat_map(|seg| seg.minus(other.range).into_iter().flatten())
                                    .collect();
                            }
                        }
                        let contested = subtract_ranges(&[overlap], &uncontested);
                        for range in uncontested {
                            il.insert_held(Held {
                                range,
                                ..prior.lock.clone()
                            });
                        }
                        for range in contested {
                            il.insert_held(Held {
                                range,
                                ticket: prior.lock.ticket.clone(),
                                ..granted.clone()
                            });
                        }
                    }
                }
            } else if family == LockFamily::Flock
                && wait_family == Some(LockFamily::Flock)
                && !il
                    .held
                    .iter()
                    .any(|h| h.owner == open_id && h.family == LockFamily::Flock)
            {
                // A pending `flock(2)` conversion dropped the descriptor's prior flock before
                // waiting; cancelling it restores the displaced flock if uncontended.
                for prior in &own_displaced {
                    if !il.held.iter().any(|h| h.conflicts(&prior.lock)) {
                        il.insert_held(prior.lock.clone());
                    }
                }
            }

            if let Some(fd) = fd {
                sync_host_diff(fd, il, open_id, family, &before)?;
            }
            self.cleanup_empty_inode(ino);
        }
        Ok(())
    }

    /// Remove all lock state held or queued by `open_id` when its host descriptor closes.
    pub fn release_open(&mut self, open_id: u64) {
        self.cancelled.retain(|(o, _)| *o != open_id);
        let empty_inos: Vec<u64> = self
            .inodes
            .iter_mut()
            .filter_map(|(&ino, il)| {
                il.displaced.retain(|d| d.lock.owner != open_id);
                il.granted.retain(|g| g.owner != open_id);
                il.waits.retain(|w| w.lock.owner != open_id);
                il.held.retain(|h| h.owner != open_id);
                (il.held.is_empty() && il.waits.is_empty() && il.displaced.is_empty())
                    .then_some(ino)
            })
            .collect();
        for ino in empty_inos {
            self.inodes.remove(&ino);
        }
    }

    fn cleanup_empty_inode(&mut self, ino: u64) {
        if let Some(il) = self.inodes.get(&ino)
            && il.held.is_empty()
            && il.waits.is_empty()
            && il.displaced.is_empty()
        {
            self.inodes.remove(&ino);
        }
    }

    fn has_cycle(&self, start_owner: u64) -> bool {
        let mut adj: HashMap<u64, Vec<u64>> = HashMap::new();
        for il in self.inodes.values() {
            for (idx, w) in il.waits.iter().enumerate() {
                if w.lock.family != LockFamily::Posix {
                    continue;
                }
                let deps = adj.entry(w.lock.owner).or_default();
                for h in &il.held {
                    if h.conflicts(&w.lock) {
                        deps.push(h.owner);
                    }
                }
                for earlier in &il.waits[..idx] {
                    if il.queue_blocks(&earlier.lock, &w.lock) {
                        deps.push(earlier.lock.owner);
                    }
                }
            }
        }
        let mut visited = HashSet::new();
        let mut stack = adj.get(&start_owner).cloned().unwrap_or_default();
        while let Some(node) = stack.pop() {
            if node == start_owner {
                return true;
            }
            if visited.insert(node)
                && let Some(next) = adj.get(&node)
            {
                stack.extend(next.iter().copied());
            }
        }
        false
    }
}

fn sync_host_diff(
    fd: BorrowedFd<'_>,
    il: &mut InodeLocks,
    open_id: u64,
    family: LockFamily,
    before: &[(LockKind, LockRange)],
) -> Result<(), Errno> {
    let after = owner_family_locks(&il.held, open_id, family);
    match family {
        LockFamily::Flock => {
            let before_kind = before.first().map(|(k, _)| *k);
            let after_kind = after.first().map(|(k, _)| *k);
            if before_kind == after_kind {
                return Ok(());
            }
            let Some(target) = after_kind else {
                return sys::flock_fd(fd, libc::LOCK_UN);
            };
            match sys::flock_fd(fd, flock_op(target) | libc::LOCK_NB) {
                Ok(()) => Ok(()),
                Err(Errno::EAGAIN) => {
                    // Linux flock drops any existing flock on the open description before checking
                    // LOCK_NB; if restoring an Exclusive lock over a Shared downgrade hits an
                    // external reader, re-acquire Shared rather than dropping all protection.
                    il.held
                        .retain(|h| !(h.owner == open_id && h.family == LockFamily::Flock));
                    if before_kind == Some(LockKind::Shared)
                        && target == LockKind::Exclusive
                        && sys::flock_fd(fd, libc::LOCK_SH | libc::LOCK_NB).is_ok()
                    {
                        il.insert_held(Held {
                            owner: open_id,
                            family: LockFamily::Flock,
                            kind: LockKind::Shared,
                            range: LockRange::WHOLE,
                            ticket: None,
                        });
                    }
                    Ok(())
                }
                Err(other) => Err(other),
            }
        }
        LockFamily::Posix => {
            let before_ranges: Vec<LockRange> = before.iter().map(|(_, r)| *r).collect();
            let after_ranges: Vec<LockRange> = after.iter().map(|(_, r)| *r).collect();

            for unlock_seg in subtract_ranges(&before_ranges, &after_ranges) {
                sys::ofd_setlk(fd, None, unlock_seg)?;
            }

            for (ak, ar) in &after {
                let already_same: Vec<LockRange> = before
                    .iter()
                    .filter(|(bk, _)| bk == ak)
                    .map(|(_, br)| *br)
                    .collect();
                for seg in subtract_ranges(&[*ar], &already_same) {
                    apply_posix_segment_checked(fd, il, open_id, before, *ak, seg, 0)?;
                }
            }
            Ok(())
        }
    }
}

fn apply_posix_segment_checked(
    fd: BorrowedFd<'_>,
    il: &mut InodeLocks,
    open_id: u64,
    before: &[(LockKind, LockRange)],
    target_kind: LockKind,
    seg: LockRange,
    depth: usize,
) -> Result<(), Errno> {
    match sys::ofd_setlk(fd, Some(target_kind), seg) {
        Ok(()) => Ok(()),
        Err(Errno::EAGAIN) if depth < 64 => {
            match sys::ofd_getlk(fd, target_kind, seg)? {
                None => match sys::ofd_setlk(fd, Some(target_kind), seg) {
                    Ok(()) => Ok(()),
                    Err(Errno::EAGAIN) => {
                        reconcile_posix_conflict_to_before(il, open_id, before, seg);
                        Ok(())
                    }
                    Err(other) => Err(other),
                },
                Some((_ckind, crange, _lpid)) => {
                    let Some(hit) = intersection(seg, crange) else {
                        reconcile_posix_conflict_to_before(il, open_id, before, seg);
                        return Ok(());
                    };
                    for rem in seg.minus(hit).into_iter().flatten() {
                        apply_posix_segment_checked(
                            fd,
                            il,
                            open_id,
                            before,
                            target_kind,
                            rem,
                            depth + 1,
                        )?;
                    }
                    // Linux F_OFD_SETLK preserves the prior lock atomically on conflict; reflect
                    // the unupgraded `before` state on `hit` rather than claiming `target_kind`.
                    reconcile_posix_conflict_to_before(il, open_id, before, hit);
                    Ok(())
                }
            }
        }
        Err(Errno::EAGAIN) => {
            reconcile_posix_conflict_to_before(il, open_id, before, seg);
            Ok(())
        }
        Err(other) => Err(other),
    }
}

fn reconcile_posix_conflict_to_before(
    il: &mut InodeLocks,
    open_id: u64,
    before: &[(LockKind, LockRange)],
    seg: LockRange,
) {
    for &(bk, br) in before {
        if let Some(hit) = intersection(seg, br) {
            il.keep_prior_kind_on_overlap(open_id, hit, bk);
        }
    }
}

fn flock_op(kind: LockKind) -> libc::c_int {
    match kind {
        LockKind::Shared => libc::LOCK_SH,
        LockKind::Exclusive => libc::LOCK_EX,
    }
}

fn host_try_lock(
    fd: BorrowedFd<'_>,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
) -> Result<(), Errno> {
    match family {
        LockFamily::Flock => sys::flock_fd(fd, flock_op(kind) | libc::LOCK_NB),
        LockFamily::Posix => sys::ofd_setlk(fd, Some(kind), range),
    }
}

fn host_unlock(fd: BorrowedFd<'_>, family: LockFamily, range: LockRange) -> Result<(), Errno> {
    match family {
        LockFamily::Flock => sys::flock_fd(fd, libc::LOCK_UN),
        LockFamily::Posix => sys::ofd_setlk(fd, None, range),
    }
}
