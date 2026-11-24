//! Per-process POSIX standard signal state (`1..=31`), matching `web/wasi/signals.mjs`.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const SA_RESTART: u32 = 0x1000_0000;
pub const SA_NODEFER: u32 = 0x4000_0000;
pub const SA_RESETHAND: u32 = 0x8000_0000;

pub const SIG_DFL: i32 = 0;
pub const SIG_IGN: i32 = 1;
pub const SIG_CATCH: i32 = 2;

pub const UNMASKABLE: u32 = bit(9) | bit(19); // SIGKILL, SIGSTOP

pub const fn bit(sig: u8) -> u32 {
    if sig == 0 || sig >= 32 {
        0
    } else {
        1u32 << (sig - 1)
    }
}

pub const fn is_valid_signal(sig: u32) -> bool {
    sig >= 1 && sig < 32
}

pub const fn is_ignored_by_default(sig: u8) -> bool {
    matches!(sig, 17 | 23 | 28) // SIGCHLD, SIGURG, SIGWINCH
}

pub const fn is_stopped_by_default(sig: u8) -> bool {
    matches!(sig, 19..=22) // SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigAction {
    pub kind: i32,
    pub mask: u32,
    pub flags: u32,
}

#[derive(Clone, Debug)]
pub struct SignalSnapshot {
    pub actions: [SigAction; 32],
    pub mask: u32,
    pub callback: Option<String>,
}

/// Shared signal control block between Kernel Actor (delivery) and Guest Thread (execution).
pub struct SignalControl {
    /// Bit 0x100 => force killed (`killed_sig = word & 0xff`).
    /// Value 1 => stopped by job-control signal (`SIGSTOP`/`SIGTSTP`/`SIGTTIN`/`SIGTTOU`).
    /// Value 0 => running.
    pub state: AtomicU32,
    pub stop_cause: AtomicU32,
    pub pending: AtomicU32,
    pub mask: AtomicU32,
    pub ignored: AtomicU32,
    pub caught: AtomicU32,
    lock: Mutex<u64>,
    cv: Condvar,
}

pub const CTRL_STOPPED: u32 = 1;
pub const CTRL_KILLED: u32 = 0x100;

impl SignalControl {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicU32::new(0),
            stop_cause: AtomicU32::new(19),
            pending: AtomicU32::new(0),
            mask: AtomicU32::new(0),
            ignored: AtomicU32::new(0),
            caught: AtomicU32::new(0),
            lock: Mutex::new(0),
            cv: Condvar::new(),
        })
    }

    pub fn wake(&self) {
        let mut g = self.lock.lock().unwrap();
        *g = g.wrapping_add(1);
        self.cv.notify_all();
    }

    pub fn wait_timeout(&self, dur: Duration) {
        let g = self.lock.lock().unwrap();
        let _ = self.cv.wait_timeout(g, dur);
    }

    /// Deliver a signal from the kernel to this process.
    pub fn deliver(&self, sig: u8) {
        if sig == 0 || sig >= 32 {
            return;
        }
        let b = bit(sig);
        match sig {
            9 => {
                // SIGKILL terminates immediately regardless of mask/stop state.
                self.state
                    .store(CTRL_KILLED | u32::from(sig), Ordering::SeqCst);
                self.wake();
            }
            19 => {
                // SIGSTOP unconditionally stops unless already killed.
                let cur = self.state.load(Ordering::SeqCst);
                if (cur & CTRL_KILLED) == 0 {
                    self.stop_cause.store(19, Ordering::SeqCst);
                    self.state.store(CTRL_STOPPED, Ordering::SeqCst);
                }
                self.wake();
            }
            18 => {
                // SIGCONT resumes stopped process and discards pending stop signals.
                let stop_bits = bit(19) | bit(20) | bit(21) | bit(22);
                self.pending.fetch_and(!stop_bits, Ordering::SeqCst);
                let _ = self.state.compare_exchange(
                    CTRL_STOPPED,
                    0,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                if (self.ignored.load(Ordering::SeqCst) & b) == 0 {
                    self.pending.fetch_or(b, Ordering::SeqCst);
                }
                self.wake();
            }
            _ => {
                if (self.ignored.load(Ordering::SeqCst) & b) == 0 {
                    self.pending.fetch_or(b, Ordering::SeqCst);
                    self.wake();
                }
            }
        }
    }

    pub fn killed_signal(&self) -> Option<u8> {
        let w = self.state.load(Ordering::SeqCst);
        if (w & CTRL_KILLED) != 0 {
            Some((w & 0xff) as u8)
        } else {
            None
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.state.load(Ordering::SeqCst) == CTRL_STOPPED
    }
}

/// Thread-owned signal table coupled to the shared `SignalControl`.
pub struct ProcessSignals {
    pub ctrl: Arc<SignalControl>,
    pub actions: [SigAction; 32],
    pub callback: Option<String>,
    pub delivered_count: u64,
}

impl ProcessSignals {
    pub fn new(ctrl: Arc<SignalControl>, snapshot: Option<SignalSnapshot>, is_exec: bool) -> Self {
        let mut this = Self {
            ctrl,
            actions: [SigAction::default(); 32],
            callback: None,
            delivered_count: 0,
        };
        if let Some(snap) = snapshot {
            this.actions = snap.actions;
            this.callback = snap.callback;
            this.set_mask(snap.mask);
            if is_exec {
                this.on_exec();
            }
        }
        this.publish();
        this
    }

    pub fn publish(&self) {
        let mut ignored = 0u32;
        let mut caught = 0u32;
        for n in 1u8..32 {
            match self.actions[n as usize].kind {
                SIG_IGN => ignored |= bit(n),
                SIG_CATCH => caught |= bit(n),
                _ => {}
            }
        }
        self.ctrl.ignored.store(ignored, Ordering::SeqCst);
        self.ctrl.caught.store(caught, Ordering::SeqCst);
    }

    pub fn mask(&self) -> u32 {
        self.ctrl.mask.load(Ordering::SeqCst)
    }

    pub fn set_mask(&self, value: u32) {
        self.ctrl
            .mask
            .store(value & 0x7fff_ffff & !UNMASKABLE, Ordering::SeqCst);
    }

    pub fn pending_blocked(&self) -> u32 {
        self.ctrl.pending.load(Ordering::SeqCst) & self.mask()
    }

    pub fn action(&mut self, n: u32, kind: i32, mask: u32, flags: u32) -> i32 {
        if !is_valid_signal(n) || !(-1..=2).contains(&kind) {
            return -(crate::errno::WASI_EINVAL as i32);
        }
        if kind == -1 {
            return self.actions[n as usize].kind;
        }
        let b = bit(n as u8);
        if (UNMASKABLE & b) != 0 || (flags & !(SA_RESTART | SA_NODEFER | SA_RESETHAND)) != 0 {
            return -(crate::errno::WASI_EINVAL as i32);
        }
        self.actions[n as usize] = SigAction {
            kind,
            mask: mask & !UNMASKABLE,
            flags,
        };
        if kind == SIG_IGN {
            self.ctrl.pending.fetch_and(!b, Ordering::SeqCst);
        }
        self.publish();
        0
    }

    pub fn queue(&self, n: u32) -> u32 {
        if !is_valid_signal(n) {
            return crate::errno::WASI_EINVAL;
        }
        self.ctrl.deliver(n as u8);
        0
    }

    pub fn take(&self) -> Option<(u8, SigAction)> {
        loop {
            let pend = self.ctrl.pending.load(Ordering::SeqCst);
            let ready = pend & !self.mask();
            if ready == 0 {
                return None;
            }
            let lowest_bit = ready.isolate_lowest_one();
            let sig = (lowest_bit.trailing_zeros() + 1) as u8;
            let prev = self.ctrl.pending.fetch_and(!lowest_bit, Ordering::SeqCst);
            if (prev & lowest_bit) != 0 {
                return Some((sig, self.actions[sig as usize]));
            }
        }
    }

    pub fn snapshot(&self) -> SignalSnapshot {
        SignalSnapshot {
            actions: self.actions,
            mask: self.mask(),
            callback: self.callback.clone(),
        }
    }

    pub fn on_exec(&mut self) {
        self.callback = None;
        for action in &mut self.actions {
            if action.kind != SIG_IGN {
                *action = SigAction::default();
            }
        }
        self.publish();
    }

    pub fn is_suppressed(&self, sig: u8) -> bool {
        if sig == 0 || sig >= 32 {
            return false;
        }
        self.actions[sig as usize].kind == SIG_IGN || (self.mask() & bit(sig)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_mask_and_unmaskable_sigkill() {
        let ctrl = SignalControl::new();
        let mut sigs = ProcessSignals::new(Arc::clone(&ctrl), None, true);
        sigs.action(10, SIG_CATCH, 0, 0); // SIGUSR1
        sigs.set_mask(bit(10) | bit(9)); // SIGKILL bit must be stripped
        assert_eq!(sigs.mask() & bit(9), 0, "SIGKILL cannot be masked");
        ctrl.deliver(10);
        assert!(sigs.take().is_none(), "masked SIGUSR1 must remain pending");
        sigs.set_mask(0);
        let (sig, act) = sigs.take().expect("unmasked SIGUSR1 must be delivered");
        assert_eq!(sig, 10);
        assert_eq!(act.kind, SIG_CATCH);
        ctrl.deliver(9);
        assert_eq!(ctrl.killed_signal(), Some(9));
    }
}
