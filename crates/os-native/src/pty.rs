//! Pure-Rust POSIX PTY subsystem (`Send + Sync`), porting `web/kernel/pty.js` + adding
//! 64 KiB output scrollback and multi-client remote seat/PTY fan-out (`HostAdapter v2`).

use crate::pipes::PipeBuf;
use abi::Errno;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub mod ioctl {
    pub const TCGETS: u32 = 0x5401;
    pub const TCSETS: u32 = 0x5402;
    pub const TCSETSW: u32 = 0x5403;
    pub const TCSETSF: u32 = 0x5404;
    pub const TIOCSCTTY: u32 = 0x540e;
    pub const TIOCGPGRP: u32 = 0x540f;
    pub const TIOCSPGRP: u32 = 0x5410;
    pub const TIOCGWINSZ: u32 = 0x5413;
    pub const TIOCSWINSZ: u32 = 0x5414;
    pub const TIOCNOTTY: u32 = 0x5422;
    pub const TIOCGSID: u32 = 0x5429;
    pub const TIOCGPTN: u32 = 0x8004_5430;
    pub const TIOCSPTLCK: u32 = 0x4004_5431;
    pub const TIOCGPTLCK: u32 = 0x8004_5439;
}

pub mod iflag {
    pub const INLCR: u32 = 64;
    pub const IGNCR: u32 = 128;
    pub const ICRNL: u32 = 256;
    pub const SUPPORTED: u32 = INLCR | IGNCR | ICRNL;
}

pub mod oflag {
    pub const OPOST: u32 = 1;
    pub const ONLCR: u32 = 4;
    pub const SUPPORTED: u32 = OPOST | ONLCR;
}

pub mod lflag {
    pub const ISIG: u32 = 1;
    pub const ICANON: u32 = 2;
    pub const ECHO: u32 = 8;
    pub const ECHOE: u32 = 16;
    pub const ECHOK: u32 = 32;
    pub const ECHONL: u32 = 64;
    pub const NOFLSH: u32 = 128;
    pub const TOSTOP: u32 = 256;
    pub const ECHOCTL: u32 = 512;
    pub const SUPPORTED: u32 =
        ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL | NOFLSH | TOSTOP | ECHOCTL;
}

pub mod cc {
    pub const VINTR: usize = 0;
    pub const VQUIT: usize = 1;
    pub const VERASE: usize = 2;
    pub const VKILL: usize = 3;
    pub const VEOF: usize = 4;
    pub const VTIME: usize = 5;
    pub const VMIN: usize = 6;
    pub const VSUSP: usize = 10;
}

pub const SCROLLBACK_MAX: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub cc: Vec<u8>,
}

impl Default for Termios {
    fn default() -> Self {
        let mut cc_arr = vec![0u8; 32];
        cc_arr[cc::VINTR] = 3;
        cc_arr[cc::VQUIT] = 28;
        cc_arr[cc::VERASE] = 127;
        cc_arr[cc::VKILL] = 21;
        cc_arr[cc::VEOF] = 4;
        cc_arr[cc::VMIN] = 1;
        cc_arr[cc::VSUSP] = 26;
        Self {
            iflag: iflag::ICRNL,
            oflag: oflag::OPOST | oflag::ONLCR,
            cflag: 0xb0,
            lflag: lflag::ISIG
                | lflag::ICANON
                | lflag::ECHO
                | lflag::ECHOE
                | lflag::ECHOK
                | lflag::ECHOCTL,
            cc: cc_arr,
        }
    }
}

impl Termios {
    pub fn validate(&self) -> Result<(), Errno> {
        if self.cc.len() != 32 {
            return Err(Errno::EINVAL);
        }
        if self.cflag != 0xb0
            || (self.iflag & !iflag::SUPPORTED) != 0
            || (self.oflag & !oflag::SUPPORTED) != 0
            || (self.lflag & !lflag::SUPPORTED) != 0
        {
            return Err(Errno::EOPNOTSUPP);
        }
        Ok(())
    }

    pub fn canonical(&self) -> bool {
        (self.lflag & lflag::ICANON) != 0
    }

    pub fn echo(&self) -> bool {
        (self.lflag & lflag::ECHO) != 0
    }

    pub fn matches(&self, index: usize, byte: u8) -> bool {
        let v = self.cc.get(index).copied().unwrap_or(0);
        v != 0 && v == byte
    }

    pub fn transform_output(&self, data: &[u8]) -> Vec<u8> {
        if (self.oflag & (oflag::OPOST | oflag::ONLCR)) != (oflag::OPOST | oflag::ONLCR) {
            return data.to_vec();
        }
        let extra = data.iter().filter(|&&b| b == b'\n').count();
        if extra == 0 {
            return data.to_vec();
        }
        let mut out = Vec::with_capacity(data.len() + extra);
        for &b in data {
            if b == b'\n' {
                out.push(b'\r');
            }
            out.push(b);
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinSize {
    pub columns: u16,
    pub rows: u16,
    #[serde(default)]
    pub width: u16,
    #[serde(default)]
    pub height: u16,
}

impl Default for WinSize {
    fn default() -> Self {
        Self {
            columns: 80,
            rows: 24,
            width: 0,
            height: 0,
        }
    }
}

impl WinSize {
    pub fn validate(&self) -> Result<(), Errno> {
        if self.columns == 0 || self.rows == 0 {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }
}

/// Callback invoked by a PTY when `ISIG` or resize requires signalling the foreground pgrp.
pub type PtySignalHook = Arc<dyn Fn(u32, u8) + Send + Sync>;
/// Callback invoked when the last master handle of a PTY drops: `(pty_number, pgrp, sid)`.
pub type PtyHangupHook = Arc<dyn Fn(u32, u32, u32) + Send + Sync>;

struct PtyInner {
    owner_uid: u32,
    owner_gid: u32,
    termios: Termios,
    winsize: WinSize,
    pgrp: u32,
    session: u32,
    locked: bool,
    hungup: bool,
    master_refs: usize,
    slave_refs: usize,
    line_buf: Vec<u8>,
    scrollback: VecDeque<u8>,
    subscribers: HashMap<u64, mpsc::UnboundedSender<Vec<u8>>>,
}

/// One live PTY pair (`/dev/ptmx` master <-> `/dev/pts/<number>` slave).
pub struct PtyInstance {
    pub number: u32,
    /// Master -> Slave input queue (read by slave processes).
    pub slave_in: Arc<PipeBuf>,
    /// Slave -> Master output queue (read by master fd holders).
    pub master_in: Arc<PipeBuf>,
    inner: Mutex<PtyInner>,
    next_sub: AtomicU64,
    signal_hook: PtySignalHook,
    hangup_hook: PtyHangupHook,
}

impl PtyInstance {
    pub fn new(
        number: u32,
        owner_uid: u32,
        owner_gid: u32,
        locked: bool,
        signal_hook: PtySignalHook,
        hangup_hook: PtyHangupHook,
    ) -> Arc<Self> {
        // Master holds a reader+writer reference on `slave_in` so buffered input survives
        // between slave processes; master holds reader on `master_in` and slave writes to it.
        let slave_in = PipeBuf::new(1, 1);
        let master_in = PipeBuf::new(1, 1);
        Arc::new(Self {
            number,
            slave_in,
            master_in,
            inner: Mutex::new(PtyInner {
                owner_uid,
                owner_gid,
                termios: Termios::default(),
                winsize: WinSize::default(),
                pgrp: 0,
                session: 0,
                locked,
                hungup: false,
                master_refs: 0,
                slave_refs: 0,
                line_buf: Vec::new(),
                scrollback: VecDeque::with_capacity(4096),
                subscribers: HashMap::new(),
            }),
            next_sub: AtomicU64::new(1),
            signal_hook,
            hangup_hook,
        })
    }

    pub fn owner(&self) -> (u32, u32) {
        let g = self.inner.lock().unwrap();
        (g.owner_uid, g.owner_gid)
    }

    pub fn set_owner(&self, uid: u32, gid: u32) {
        let mut g = self.inner.lock().unwrap();
        g.owner_uid = uid;
        g.owner_gid = gid;
    }

    pub fn add_master_ref(&self) {
        self.inner.lock().unwrap().master_refs += 1;
    }

    pub fn drop_master_ref(&self) -> Option<(u32, u32)> {
        let mut g = self.inner.lock().unwrap();
        g.master_refs = g.master_refs.saturating_sub(1);
        if g.master_refs == 0 && !g.hungup {
            g.hungup = true;
            g.line_buf.clear();
            let pgrp = g.pgrp;
            let sid = g.session;
            drop(g);
            self.slave_in.drop_writer();
            self.master_in.drop_reader();
            return Some((pgrp, sid));
        }
        None
    }

    pub fn add_slave_ref(&self) {
        let mut g = self.inner.lock().unwrap();
        g.slave_refs += 1;
    }

    pub fn drop_slave_ref(&self) {
        let mut g = self.inner.lock().unwrap();
        g.slave_refs = g.slave_refs.saturating_sub(1);
    }

    pub fn master_refs(&self) -> usize {
        self.inner.lock().unwrap().master_refs
    }

    pub fn slave_refs(&self) -> usize {
        self.inner.lock().unwrap().slave_refs
    }

    pub fn is_locked(&self) -> bool {
        self.inner.lock().unwrap().locked
    }

    pub fn set_locked(&self, locked: bool) {
        self.inner.lock().unwrap().locked = locked;
    }

    pub fn is_hungup(&self) -> bool {
        self.inner.lock().unwrap().hungup
    }

    pub fn termios(&self) -> Termios {
        self.inner.lock().unwrap().termios.clone()
    }

    pub fn set_termios(&self, termios: Termios, flush: bool) -> Result<(), Errno> {
        termios.validate()?;
        let mut to_flush = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            let was_canon = g.termios.canonical();
            g.termios = termios;
            if flush {
                g.line_buf.clear();
            } else if was_canon && !g.termios.canonical() && !g.line_buf.is_empty() {
                to_flush = std::mem::take(&mut g.line_buf);
            }
        }
        if flush {
            self.slave_in.discard();
        } else if !to_flush.is_empty() {
            let _ = self.slave_in.try_put(&to_flush);
        }
        Ok(())
    }

    pub fn winsize(&self) -> WinSize {
        self.inner.lock().unwrap().winsize
    }

    pub fn set_winsize(&self, ws: WinSize) -> Result<(), Errno> {
        ws.validate()?;
        let pgrp = {
            let mut g = self.inner.lock().unwrap();
            let changed = g.winsize.columns != ws.columns || g.winsize.rows != ws.rows;
            g.winsize = ws;
            if changed { g.pgrp } else { 0 }
        };
        if pgrp != 0 {
            (self.signal_hook)(pgrp, 28); // SIGWINCH
        }
        Ok(())
    }

    pub fn pgrp(&self) -> u32 {
        self.inner.lock().unwrap().pgrp
    }

    pub fn set_pgrp(&self, pgrp: u32) {
        self.inner.lock().unwrap().pgrp = pgrp;
    }

    pub fn session(&self) -> u32 {
        self.inner.lock().unwrap().session
    }

    pub fn set_session(&self, sid: u32, pgrp: u32) {
        let mut g = self.inner.lock().unwrap();
        g.session = sid;
        if pgrp != 0 {
            g.pgrp = pgrp;
        }
    }

    /// Subscribe a remote seat/client to live slave output. Returns `(sub_id, scrollback_snapshot, rx)`.
    pub fn subscribe(&self) -> (u64, Vec<u8>, mpsc::UnboundedReceiver<Vec<u8>>) {
        let id = self.next_sub.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        let mut g = self.inner.lock().unwrap();
        let snap: Vec<u8> = g.scrollback.iter().copied().collect();
        g.subscribers.insert(id, tx);
        (id, snap, rx)
    }

    pub fn unsubscribe(&self, sub_id: u64) {
        self.inner.lock().unwrap().subscribers.remove(&sub_id);
    }

    fn emit_output_raw(&self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let _ = self.master_in.try_put(bytes);
        let mut g = self.inner.lock().unwrap();
        for &b in bytes {
            if g.scrollback.len() >= SCROLLBACK_MAX {
                g.scrollback.pop_front();
            }
            g.scrollback.push_back(b);
        }
        g.subscribers
            .retain(|_, tx| tx.send(bytes.to_vec()).is_ok());
    }

    /// Write bytes from a slave process to the PTY (applies `OPOST|ONLCR`, pushes to master & subscribers).
    pub fn write_from_slave(&self, data: &[u8]) -> Result<usize, Errno> {
        let transformed = {
            let g = self.inner.lock().unwrap();
            if g.hungup {
                return Err(Errno::EIO);
            }
            g.termios.transform_output(data)
        };
        self.emit_output_raw(&transformed);
        Ok(data.len())
    }

    /// Write input bytes from the master / remote seat into the PTY line discipline.
    pub fn write_from_master(&self, data: &[u8]) -> Result<usize, Errno> {
        let mut echo_out = Vec::new();
        let mut to_slave: Vec<Option<Vec<u8>>> = Vec::new();
        let mut signals_to_send: Vec<(u32, u8)> = Vec::new();
        let mut discard_input = false;

        {
            let mut g = self.inner.lock().unwrap();
            if g.hungup {
                return Err(Errno::EIO);
            }
            for &raw_byte in data {
                let mut byte = raw_byte;
                let inp = g.termios.iflag;
                let loc = g.termios.lflag;
                if byte == 13 {
                    if (inp & iflag::IGNCR) != 0 {
                        continue;
                    }
                    if (inp & iflag::ICRNL) != 0 {
                        byte = 10;
                    }
                } else if byte == 10 && (inp & iflag::INLCR) != 0 {
                    byte = 13;
                }

                if (loc & lflag::ISIG) != 0 {
                    let sig = if g.termios.matches(cc::VINTR, byte) {
                        Some(2u8)
                    } else if g.termios.matches(cc::VQUIT, byte) {
                        Some(3u8)
                    } else if g.termios.matches(cc::VSUSP, byte) {
                        Some(20u8)
                    } else {
                        None
                    };
                    if let Some(sig) = sig {
                        if (loc & lflag::NOFLSH) == 0 {
                            g.line_buf.clear();
                            to_slave.clear();
                            discard_input = true;
                        }
                        if (loc & lflag::ECHO) != 0 {
                            echo_out.push(b'^');
                            echo_out.push(byte.wrapping_add(64));
                            echo_out.extend_from_slice(b"\r\n");
                        }
                        if g.pgrp != 0 {
                            signals_to_send.push((g.pgrp, sig));
                        }
                        continue;
                    }
                }

                if g.termios.canonical() {
                    if g.termios.matches(cc::VERASE, byte) || byte == 8 {
                        if !g.line_buf.is_empty() {
                            let mut at = g.line_buf.len() - 1;
                            while at > 0 && (g.line_buf[at] & 0xc0) == 0x80 {
                                at -= 1;
                            }
                            let first = g.line_buf[at];
                            g.line_buf.truncate(at);
                            if (loc & lflag::ECHO) != 0 && (loc & lflag::ECHOE) != 0 {
                                if first < 32 {
                                    echo_out.extend_from_slice(b"\x08 \x08\x08 \x08");
                                } else {
                                    echo_out.extend_from_slice(b"\x08 \x08");
                                }
                            }
                        }
                        continue;
                    }
                    if g.termios.matches(cc::VKILL, byte) {
                        while let Some(last) = g.line_buf.pop() {
                            if (loc & lflag::ECHO) != 0 && (loc & lflag::ECHOE) != 0 {
                                if last < 32 {
                                    echo_out.extend_from_slice(b"\x08 \x08\x08 \x08");
                                } else {
                                    echo_out.extend_from_slice(b"\x08 \x08");
                                }
                            }
                        }
                        continue;
                    }
                    if g.termios.matches(cc::VEOF, byte) {
                        if !g.line_buf.is_empty() {
                            to_slave.push(Some(std::mem::take(&mut g.line_buf)));
                        } else {
                            to_slave.push(None);
                        }
                        continue;
                    }
                    if g.line_buf.len() >= 4095 && byte != 10 {
                        continue;
                    }
                    g.line_buf.push(byte);
                } else {
                    to_slave.push(Some(vec![byte]));
                }

                if (loc & lflag::ECHO) != 0 || (byte == 10 && (loc & lflag::ECHONL) != 0) {
                    if byte == 10 {
                        echo_out.extend_from_slice(b"\r\n");
                    } else if byte < 32 && byte != 9 && (loc & lflag::ECHOCTL) != 0 {
                        echo_out.push(b'^');
                        echo_out.push(byte + 64);
                    } else {
                        echo_out.push(byte);
                    }
                }
                if g.termios.canonical() && byte == 10 {
                    to_slave.push(Some(std::mem::take(&mut g.line_buf)));
                }
            }
        }

        if discard_input {
            self.slave_in.discard();
        }
        if !echo_out.is_empty() {
            self.emit_output_raw(&echo_out);
        }
        for chunk in to_slave {
            match chunk {
                Some(bytes) => {
                    let _ = self.slave_in.try_put(&bytes);
                }
                None => self.slave_in.push_eof(),
            }
        }
        for (pgrp, sig) in signals_to_send {
            (self.signal_hook)(pgrp, sig);
        }
        Ok(data.len())
    }

    pub fn scrollback_snapshot(&self) -> Vec<u8> {
        self.inner
            .lock()
            .unwrap()
            .scrollback
            .iter()
            .copied()
            .collect()
    }
}

/// RAII handle for a PTY master descriptor (symmetrically ref-counted across `Clone`/`Drop`).
pub struct PtyMasterHandle {
    pub pty: Arc<PtyInstance>,
}

impl PtyMasterHandle {
    pub fn new(pty: Arc<PtyInstance>) -> Self {
        pty.add_master_ref();
        Self { pty }
    }
}

impl Clone for PtyMasterHandle {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.pty))
    }
}

impl Drop for PtyMasterHandle {
    fn drop(&mut self) {
        if let Some((pgrp, sid)) = self.pty.drop_master_ref() {
            (self.pty.hangup_hook)(self.pty.number, pgrp, sid);
        }
    }
}

impl std::ops::Deref for PtyMasterHandle {
    type Target = PtyInstance;
    fn deref(&self) -> &Self::Target {
        &self.pty
    }
}

/// RAII handle for a PTY slave descriptor (symmetrically ref-counted across `Clone`/`Drop`).
pub struct PtySlaveHandle {
    pub pty: Arc<PtyInstance>,
}

impl PtySlaveHandle {
    pub fn new(pty: Arc<PtyInstance>) -> Self {
        pty.add_slave_ref();
        Self { pty }
    }
}

impl Clone for PtySlaveHandle {
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.pty))
    }
}

impl Drop for PtySlaveHandle {
    fn drop(&mut self) {
        self.pty.drop_slave_ref();
    }
}

impl std::ops::Deref for PtySlaveHandle {
    type Target = PtyInstance;
    fn deref(&self) -> &Self::Target {
        &self.pty
    }
}

/// Registry of all live PTYs in the native OS instance.
pub struct PtyTable {
    ptys: Mutex<BTreeMap<u32, Arc<PtyInstance>>>,
    next_num: AtomicU32,
    signal_hook: PtySignalHook,
    hangup_hook: PtyHangupHook,
}

impl PtyTable {
    pub fn new(signal_hook: PtySignalHook, hangup_hook: PtyHangupHook) -> Arc<Self> {
        Arc::new(Self {
            ptys: Mutex::new(BTreeMap::new()),
            next_num: AtomicU32::new(0),
            signal_hook,
            hangup_hook,
        })
    }

    /// Allocate a new PTY pair owned by `(uid, gid)` and return its RAII master handle.
    pub fn allocate_owned(&self, uid: u32, gid: u32, locked: bool) -> PtyMasterHandle {
        let mut map = self.ptys.lock().unwrap();
        let mut num = self.next_num.fetch_add(1, Ordering::Relaxed);
        while map.contains_key(&num) {
            num = self.next_num.fetch_add(1, Ordering::Relaxed);
        }
        let pty = PtyInstance::new(
            num,
            uid,
            gid,
            locked,
            Arc::clone(&self.signal_hook),
            Arc::clone(&self.hangup_hook),
        );
        map.insert(num, Arc::clone(&pty));
        PtyMasterHandle::new(pty)
    }

    /// Allocate a PTY at an exact seat number (used by scoped `Attach { seat, spawn_if_missing }`).
    pub fn allocate_specific(
        &self,
        num: u32,
        uid: u32,
        gid: u32,
        locked: bool,
    ) -> Result<PtyMasterHandle, Errno> {
        let mut map = self.ptys.lock().unwrap();
        if map.contains_key(&num) {
            return Err(Errno::EEXIST);
        }
        let pty = PtyInstance::new(
            num,
            uid,
            gid,
            locked,
            Arc::clone(&self.signal_hook),
            Arc::clone(&self.hangup_hook),
        );
        map.insert(num, Arc::clone(&pty));
        let cur_next = self.next_num.load(Ordering::Relaxed);
        if cur_next <= num {
            let _ = self.next_num.compare_exchange(
                cur_next,
                num.saturating_add(1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
        Ok(PtyMasterHandle::new(pty))
    }

    pub fn get(&self, num: u32) -> Option<Arc<PtyInstance>> {
        self.ptys.lock().unwrap().get(&num).cloned()
    }

    pub fn list_numbers(&self) -> Vec<u32> {
        self.ptys.lock().unwrap().keys().copied().collect()
    }

    pub fn remove(&self, num: u32) {
        self.ptys.lock().unwrap().remove(&num);
    }
}
