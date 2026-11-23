//! Native SQLite (`WAL` + `synchronous=FULL`) [`HeadStore`], atomic `fsync(2)` + `pread(2)`
//! [`PackStore`], and OS `flock(2)` writer/GC exclusion (`contract.md` §2.15, #77).
//!
//! Uses direct FFI against system `libsqlite3` (`#[link(name = "sqlite3")]`) with zero extra
//! third-party Cargo dependencies.

use abi::Errno;
use abi::fs::Timespec;
use cowtree::pack::{
    PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer, decode_pack_trailer_bytes,
};
use cowtree::{
    BlockLoc, COWFS_FORMAT_VERSION, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot,
    HeadStore, PACK_MAX_BYTES, PackId, PackMeta, PackStore, PackTrailer, ReceiveCommitRequest,
    RoPinGuard, SnapshotRecord, VolumeHead, VolumeId, WriterLease, WriterLockGuard, WriterMode,
    digest_to_hex, sha256,
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use vfs::{BoxFuture, Result};

// -----------------------------------------------------------------------------
// Minimal libsqlite3 C ABI bindings
// -----------------------------------------------------------------------------

#[repr(C)]
struct Sqlite3 {
    _private: [u8; 0],
}

#[repr(C)]
struct Sqlite3Stmt {
    _private: [u8; 0],
}

const SQLITE_OK: c_int = 0;
const SQLITE_FULL: c_int = 13;
const SQLITE_BUSY: c_int = 5;
const SQLITE_LOCKED: c_int = 6;
const SQLITE_CONSTRAINT: c_int = 19;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const SQLITE_NULL: c_int = 5;

const SQLITE_OPEN_READWRITE: c_int = 0x0000_0002;
const SQLITE_OPEN_CREATE: c_int = 0x0000_0004;

// SQLITE_TRANSIENT = (void(*)(void*))-1
const SQLITE_TRANSIENT: isize = -1;

#[link(name = "sqlite3")]
unsafe extern "C" {
    fn sqlite3_open_v2(
        filename: *const c_char,
        pp_db: *mut *mut Sqlite3,
        flags: c_int,
        z_vfs: *const c_char,
    ) -> c_int;
    fn sqlite3_close_v2(db: *mut Sqlite3) -> c_int;
    fn sqlite3_busy_timeout(db: *mut Sqlite3, ms: c_int) -> c_int;
    fn sqlite3_exec(
        db: *mut Sqlite3,
        sql: *const c_char,
        callback: Option<
            unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int,
        >,
        arg: *mut c_void,
        errmsg: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_free(ptr: *mut c_void);
    fn sqlite3_prepare_v2(
        db: *mut Sqlite3,
        z_sql: *const c_char,
        n_byte: c_int,
        pp_stmt: *mut *mut Sqlite3Stmt,
        pz_tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_finalize(stmt: *mut Sqlite3Stmt) -> c_int;
    fn sqlite3_step(stmt: *mut Sqlite3Stmt) -> c_int;
    fn sqlite3_bind_int64(stmt: *mut Sqlite3Stmt, idx: c_int, val: i64) -> c_int;
    fn sqlite3_bind_text(
        stmt: *mut Sqlite3Stmt,
        idx: c_int,
        val: *const c_char,
        n: c_int,
        destructor: isize,
    ) -> c_int;
    fn sqlite3_bind_blob(
        stmt: *mut Sqlite3Stmt,
        idx: c_int,
        val: *const c_void,
        n: c_int,
        destructor: isize,
    ) -> c_int;
    fn sqlite3_bind_null(stmt: *mut Sqlite3Stmt, idx: c_int) -> c_int;
    fn sqlite3_column_type(stmt: *mut Sqlite3Stmt, col: c_int) -> c_int;
    fn sqlite3_column_int64(stmt: *mut Sqlite3Stmt, col: c_int) -> i64;
    fn sqlite3_column_text(stmt: *mut Sqlite3Stmt, col: c_int) -> *const u8;
    fn sqlite3_column_blob(stmt: *mut Sqlite3Stmt, col: c_int) -> *const c_void;
    fn sqlite3_column_bytes(stmt: *mut Sqlite3Stmt, col: c_int) -> c_int;
}

fn map_sqlite_rc(rc: c_int) -> Errno {
    match rc & 0xff {
        SQLITE_FULL => Errno::ENOSPC,
        SQLITE_BUSY | SQLITE_LOCKED => Errno::EBUSY,
        SQLITE_CONSTRAINT => Errno::EEXIST,
        _ => Errno::EIO,
    }
}

struct Db {
    raw: *mut Sqlite3,
}

impl Drop for Db {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                sqlite3_close_v2(self.raw);
            }
        }
    }
}

struct Stmt {
    raw: *mut Sqlite3Stmt,
}

impl Drop for Stmt {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                sqlite3_finalize(self.raw);
            }
        }
    }
}

impl Db {
    fn open(path: &Path) -> Result<Self> {
        let c_path = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| Errno::EINVAL)?;
        let mut raw: *mut Sqlite3 = ptr::null_mut();
        let rc = unsafe {
            sqlite3_open_v2(
                c_path.as_ptr(),
                &mut raw,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                ptr::null(),
            )
        };
        if rc != SQLITE_OK || raw.is_null() {
            if !raw.is_null() {
                unsafe {
                    sqlite3_close_v2(raw);
                }
            }
            return Err(map_sqlite_rc(rc));
        }
        let db = Self { raw };
        unsafe {
            sqlite3_busy_timeout(db.raw, 5000);
        }
        Ok(db)
    }

    fn exec(&self, sql: &str) -> Result<()> {
        let c_sql = CString::new(sql).map_err(|_| Errno::EINVAL)?;
        let mut err_msg: *mut c_char = ptr::null_mut();
        let rc = unsafe {
            sqlite3_exec(
                self.raw,
                c_sql.as_ptr(),
                None,
                ptr::null_mut(),
                &mut err_msg,
            )
        };
        if !err_msg.is_null() {
            unsafe {
                sqlite3_free(err_msg.cast());
            }
        }
        if rc != SQLITE_OK {
            return Err(map_sqlite_rc(rc));
        }
        Ok(())
    }

    fn prepare(&self, sql: &str) -> Result<Stmt> {
        let mut raw: *mut Sqlite3Stmt = ptr::null_mut();
        let rc = unsafe {
            sqlite3_prepare_v2(
                self.raw,
                sql.as_ptr().cast(),
                sql.len() as c_int,
                &mut raw,
                ptr::null_mut(),
            )
        };
        if rc != SQLITE_OK || raw.is_null() {
            return Err(map_sqlite_rc(rc));
        }
        Ok(Stmt { raw })
    }
}

impl Stmt {
    fn bind_i64(&self, idx: c_int, val: i64) -> Result<()> {
        let rc = unsafe { sqlite3_bind_int64(self.raw, idx, val) };
        if rc != SQLITE_OK {
            return Err(map_sqlite_rc(rc));
        }
        Ok(())
    }

    fn bind_u64(&self, idx: c_int, val: u64) -> Result<()> {
        self.bind_i64(idx, val as i64)
    }

    fn bind_str(&self, idx: c_int, val: &str) -> Result<()> {
        let rc = unsafe {
            sqlite3_bind_text(
                self.raw,
                idx,
                val.as_ptr().cast(),
                val.len() as c_int,
                SQLITE_TRANSIENT,
            )
        };
        if rc != SQLITE_OK {
            return Err(map_sqlite_rc(rc));
        }
        Ok(())
    }

    fn bind_opt_str(&self, idx: c_int, val: Option<&str>) -> Result<()> {
        match val {
            Some(s) => self.bind_str(idx, s),
            None => {
                let rc = unsafe { sqlite3_bind_null(self.raw, idx) };
                if rc != SQLITE_OK {
                    return Err(map_sqlite_rc(rc));
                }
                Ok(())
            }
        }
    }

    fn bind_blob(&self, idx: c_int, bytes: &[u8]) -> Result<()> {
        let ptr = if bytes.is_empty() {
            ptr::null()
        } else {
            bytes.as_ptr().cast()
        };
        let rc = unsafe {
            sqlite3_bind_blob(self.raw, idx, ptr, bytes.len() as c_int, SQLITE_TRANSIENT)
        };
        if rc != SQLITE_OK {
            return Err(map_sqlite_rc(rc));
        }
        Ok(())
    }

    fn step_row(&self) -> Result<bool> {
        let rc = unsafe { sqlite3_step(self.raw) };
        match rc {
            SQLITE_ROW => Ok(true),
            SQLITE_DONE => Ok(false),
            _ => Err(map_sqlite_rc(rc)),
        }
    }

    fn step_done(&self) -> Result<()> {
        let rc = unsafe { sqlite3_step(self.raw) };
        if rc == SQLITE_DONE || rc == SQLITE_ROW {
            Ok(())
        } else {
            Err(map_sqlite_rc(rc))
        }
    }

    fn col_u64(&self, col: c_int) -> u64 {
        unsafe { sqlite3_column_int64(self.raw, col) as u64 }
    }

    fn col_u32(&self, col: c_int) -> u32 {
        unsafe { sqlite3_column_int64(self.raw, col) as u32 }
    }

    fn col_str(&self, col: c_int) -> Result<String> {
        let ptr = unsafe { sqlite3_column_text(self.raw, col) };
        if ptr.is_null() {
            return Ok(String::new());
        }
        let len = unsafe { sqlite3_column_bytes(self.raw, col) as usize };
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        std::str::from_utf8(slice)
            .map(str::to_owned)
            .map_err(|_| Errno::EIO)
    }

    fn col_opt_str(&self, col: c_int) -> Result<Option<String>> {
        if unsafe { sqlite3_column_type(self.raw, col) } == SQLITE_NULL {
            return Ok(None);
        }
        self.col_str(col).map(Some)
    }

    fn col_blob(&self, col: c_int) -> Vec<u8> {
        let len = unsafe { sqlite3_column_bytes(self.raw, col) as usize };
        if len == 0 {
            return Vec::new();
        }
        let ptr = unsafe { sqlite3_column_blob(self.raw, col) as *const u8 };
        if ptr.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }

    fn col_digest(&self, col: c_int) -> Result<Digest> {
        let blob = self.col_blob(col);
        if blob.len() != 32 {
            return Err(Errno::EIO);
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&blob);
        Ok(d)
    }
}

// -----------------------------------------------------------------------------
// Native flock guards & CSPRNG helpers
// -----------------------------------------------------------------------------

fn ts_expired(created_at: Timespec, now: Timespec, grace_window_secs: u64) -> bool {
    let exp_sec = created_at.sec.saturating_add(grace_window_secs);
    exp_sec < now.sec || (exp_sec == now.sec && created_at.nsec <= now.nsec)
}

fn random_hex_16() -> String {
    let mut bytes = [0u8; 16];
    let ok = File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok();
    if !ok {
        let seq = FORK_SEQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let mut seed = Vec::with_capacity(28);
        seed.extend_from_slice(&pid.to_be_bytes());
        seed.extend_from_slice(&seq.to_be_bytes());
        seed.extend_from_slice(&nanos.to_be_bytes());
        let h = sha256(&seed);
        bytes.copy_from_slice(&h[..16]);
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

struct FlockWriterGuard {
    _file: File,
}

impl WriterLockGuard for FlockWriterGuard {}

struct FlockGcGuard {
    _file: File,
}

impl GcLockGuard for FlockGcGuard {}

struct FlockRoPinGuard {
    db: Rc<Db>,
    pin_id: String,
    lock_path: PathBuf,
    _file: File,
}

impl RoPinGuard for FlockRoPinGuard {}

impl Drop for FlockRoPinGuard {
    fn drop(&mut self) {
        if let Ok(stmt) = self.db.prepare("DELETE FROM ro_pins WHERE pin_id = ?1") {
            let _ = stmt.bind_str(1, &self.pin_id);
            let _ = stmt.step_done();
        }
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn sanitize_name(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
                b as char
            } else {
                '_'
            }
        })
        .collect()
}

fn try_flock_exclusive(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(map_io_err)?;
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(file);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            return Err(Errno::EBUSY);
        }
        return Err(map_io_err(err));
    }
}

fn acquire_flock_gc(path: &Path, exclusive: bool) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(map_io_err)?;
    // Writers (`exclusive == false`) block on `LOCK_SH` while GC finishes instead of aborting
    // live commits with `EBUSY`; GC (`exclusive == true`) stays non-blocking (`LOCK_EX | LOCK_NB`).
    let op = if exclusive {
        libc::LOCK_EX | libc::LOCK_NB
    } else {
        libc::LOCK_SH
    };
    loop {
        let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
        if rc == 0 {
            return Ok(file);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) || err.raw_os_error() == Some(libc::EAGAIN)
        {
            return Err(Errno::EBUSY);
        }
        return Err(map_io_err(err));
    }
}

fn map_io_err(err: std::io::Error) -> Errno {
    match err.raw_os_error() {
        Some(libc::ENOENT) => Errno::ENOENT,
        Some(libc::EACCES) => Errno::EACCES,
        Some(libc::EPERM) => Errno::EPERM,
        Some(libc::ENOSPC) => Errno::ENOSPC,
        Some(libc::EDQUOT) => Errno::EDQUOT,
        Some(libc::EEXIST) => Errno::EEXIST,
        Some(libc::EBUSY | libc::EWOULDBLOCK) => Errno::EBUSY,
        Some(libc::EROFS) => Errno::EROFS,
        _ => Errno::EIO,
    }
}

fn sync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir).map_err(map_io_err)?;
    f.sync_all().map_err(map_io_err)
}

// -----------------------------------------------------------------------------
// NativeSqliteHeadStore
// -----------------------------------------------------------------------------

static FORK_SEQ: AtomicU64 = AtomicU64::new(1);

/// Native SQLite (`WAL` + `synchronous=FULL`) + `flock` implementation of [`HeadStore`].
pub struct NativeSqliteHeadStore {
    state_dir: PathBuf,
    locks_dir: PathBuf,
    db: Rc<Db>,
    fail_next_commit: Cell<Option<Errno>>,
    grace_window_secs: Cell<u64>,
}

const INIT_SCHEMA_SQL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS heads (
    volume TEXT PRIMARY KEY,
    format_version INTEGER NOT NULL,
    incarnation INTEGER NOT NULL,
    fence INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    root BLOB NOT NULL,
    parent_volume TEXT,
    ephemeral_if_unmodified INTEGER NOT NULL,
    modified INTEGER NOT NULL,
    updated_sec INTEGER NOT NULL,
    updated_nsec INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    digest BLOB PRIMARY KEY,
    data BLOB NOT NULL,
    created_sec INTEGER NOT NULL,
    created_nsec INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS packs (
    pack_id TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    created_sec INTEGER NOT NULL,
    created_nsec INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
    digest BLOB PRIMARY KEY,
    pack_id TEXT NOT NULL,
    offset INTEGER NOT NULL,
    len INTEGER NOT NULL,
    raw_len INTEGER NOT NULL,
    flags INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    volume TEXT NOT NULL,
    name TEXT NOT NULL,
    root BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    created_sec INTEGER NOT NULL,
    created_nsec INTEGER NOT NULL,
    PRIMARY KEY (volume, name)
);

CREATE TABLE IF NOT EXISTS receipts (
    op_id BLOB PRIMARY KEY,
    volume TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    root BLOB NOT NULL,
    head_json TEXT NOT NULL,
    created_sec INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS grace_pins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    volume TEXT NOT NULL,
    root BLOB NOT NULL,
    pinned_until_sec INTEGER NOT NULL,
    pinned_until_nsec INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ro_pins (
    pin_id TEXT PRIMARY KEY,
    volume TEXT NOT NULL,
    root BLOB NOT NULL
);
"#;

impl NativeSqliteHeadStore {
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        let locks_dir = state_dir.join("locks");
        fs::create_dir_all(&locks_dir).map_err(map_io_err)?;
        let db_path = state_dir.join("cowfs.sqlite");
        let db = Rc::new(Db::open(&db_path)?);
        db.exec(INIT_SCHEMA_SQL)?;
        Ok(Self {
            state_dir,
            locks_dir,
            db,
            fail_next_commit: Cell::new(None),
            grace_window_secs: Cell::new(600),
        })
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn set_grace_window_secs(&self, secs: u64) {
        self.grace_window_secs.set(secs);
    }

    /// Inject a one-shot error on the next `commit_head` (for crash / `ENOSPC` fault tests).
    pub fn fail_next_commit(&self, err: Errno) {
        self.fail_next_commit.set(Some(err));
    }

    /// Overwrite stored `format_version` metadata (for version-mismatch refusal tests).
    pub fn set_stored_format_version(&self, version: u32) -> Result<()> {
        let stmt = self
            .db
            .prepare("INSERT OR REPLACE INTO meta (key, value) VALUES ('format_version', ?1)")?;
        stmt.bind_str(1, &version.to_string())?;
        stmt.step_done()
    }

    /// Bit-flip one byte in a stored B+tree node inside SQLite (for corruption `EIO` tests).
    pub fn corrupt_node_byte(&self, digest: &Digest, offset: usize) -> Result<bool> {
        let sel = self
            .db
            .prepare("SELECT data FROM nodes WHERE digest = ?1")?;
        sel.bind_blob(1, digest)?;
        if !sel.step_row()? {
            return Ok(false);
        }
        let mut data = sel.col_blob(0);
        drop(sel);
        if offset >= data.len() {
            return Ok(false);
        }
        data[offset] ^= 0x01;
        let upd = self
            .db
            .prepare("UPDATE nodes SET data = ?1 WHERE digest = ?2")?;
        upd.bind_blob(1, &data)?;
        upd.bind_blob(2, digest)?;
        upd.step_done()?;
        Ok(true)
    }

    fn read_stored_format_version(&self) -> Result<Option<u32>> {
        let stmt = self
            .db
            .prepare("SELECT value FROM meta WHERE key = 'format_version'")?;
        if !stmt.step_row()? {
            return Ok(None);
        }
        let s = stmt.col_str(0)?;
        s.parse::<u32>().map(Some).map_err(|_| Errno::EIO)
    }

    fn ensure_format_compatible(&self) -> Result<()> {
        if let Some(v) = self.read_stored_format_version()?
            && v != COWFS_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }
        Ok(())
    }

    fn lock_path(&self, volume: &VolumeId, incarnation: u64, fence: u64) -> PathBuf {
        let vol_hash = digest_to_hex(&sha256(volume.0.as_bytes()));
        self.locks_dir.join(format!(
            "vol-{}-{}-i{incarnation}-f{fence}.lock",
            sanitize_name(&volume.0),
            &vol_hash[..12],
        ))
    }

    fn ro_pin_lock_path(&self, pin_id: &str) -> PathBuf {
        self.locks_dir.join(format!("ro-{pin_id}.lock"))
    }

    fn gc_lock_path(&self) -> PathBuf {
        self.locks_dir.join("gc.lock")
    }

    fn acquire_current_volume_lock(&self, volume: &VolumeId) -> Result<(VolumeHead, File)> {
        for _ in 0..16 {
            let cur = self.read_head_sync(volume)?;
            if cur.format_version != COWFS_FORMAT_VERSION {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let file = try_flock_exclusive(&self.lock_path(volume, cur.incarnation, cur.fence))?;
            let latest = self.read_head_sync(volume)?;
            if latest.incarnation == cur.incarnation && latest.fence == cur.fence {
                return Ok((latest, file));
            }
            // Fence or incarnation rotated while acquiring the old lock; drop & retry on new lock.
            drop(file);
        }
        Err(Errno::EBUSY)
    }

    fn delete_volume_rows_in_txn(&self, volume: &VolumeId) -> Result<()> {
        let d_snap = self.db.prepare("DELETE FROM snapshots WHERE volume = ?1")?;
        d_snap.bind_str(1, &volume.0)?;
        d_snap.step_done()?;

        let d_rec = self.db.prepare("DELETE FROM receipts WHERE volume = ?1")?;
        d_rec.bind_str(1, &volume.0)?;
        d_rec.step_done()?;

        let d_head = self.db.prepare("DELETE FROM heads WHERE volume = ?1")?;
        d_head.bind_str(1, &volume.0)?;
        d_head.step_done()?;
        Ok(())
    }

    fn read_head_sync(&self, volume: &VolumeId) -> Result<VolumeHead> {
        self.ensure_format_compatible()?;
        let stmt = self.db.prepare(
            "SELECT format_version, incarnation, fence, epoch, root, parent_volume, \
             ephemeral_if_unmodified, modified, updated_sec, updated_nsec \
             FROM heads WHERE volume = ?1",
        )?;
        stmt.bind_str(1, &volume.0)?;
        if !stmt.step_row()? {
            return Err(Errno::ENOENT);
        }
        Ok(VolumeHead {
            format_version: stmt.col_u32(0),
            volume: volume.clone(),
            incarnation: stmt.col_u64(1),
            fence: stmt.col_u64(2),
            epoch: stmt.col_u64(3),
            root: stmt.col_digest(4)?,
            parent_volume: stmt.col_opt_str(5)?.map(VolumeId),
            ephemeral_if_unmodified: stmt.col_u64(6) != 0,
            modified: stmt.col_u64(7) != 0,
            updated_at: Timespec {
                sec: stmt.col_u64(8),
                nsec: stmt.col_u32(9),
            },
        })
    }

    fn with_txn<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        self.db.exec("BEGIN IMMEDIATE")?;
        match f() {
            Ok(v) => {
                self.db.exec("COMMIT")?;
                Ok(v)
            }
            Err(e) => {
                let _ = self.db.exec("ROLLBACK");
                Err(e)
            }
        }
    }
}

impl HeadStore for NativeSqliteHeadStore {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move { self.read_stored_format_version() })
    }

    fn grace_window_secs(&self) -> u64 {
        self.grace_window_secs.get()
    }

    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            self.ensure_format_compatible()?;
            self.with_txn(|| {
                let meta_stmt = self.db.prepare(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('format_version', ?1)",
                )?;
                meta_stmt.bind_str(1, &COWFS_FORMAT_VERSION.to_string())?;
                meta_stmt.step_done()?;

                for (digest, bytes) in initial_nodes {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO nodes (digest, data, created_sec, created_nsec) \
                         VALUES (?1, ?2, ?3, ?4)",
                    )?;
                    s.bind_blob(1, digest)?;
                    s.bind_blob(2, bytes)?;
                    s.bind_u64(3, head.updated_at.sec)?;
                    s.bind_u64(4, u64::from(head.updated_at.nsec))?;
                    s.step_done()?;
                }

                let ins = self.db.prepare(
                    "INSERT INTO heads (volume, format_version, incarnation, fence, epoch, root, \
                     parent_volume, ephemeral_if_unmodified, modified, updated_sec, updated_nsec) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )?;
                ins.bind_str(1, &head.volume.0)?;
                ins.bind_u64(2, u64::from(head.format_version))?;
                ins.bind_u64(3, head.incarnation)?;
                ins.bind_u64(4, head.fence)?;
                ins.bind_u64(5, head.epoch)?;
                ins.bind_blob(6, &head.root)?;
                ins.bind_opt_str(7, head.parent_volume.as_ref().map(|v| v.0.as_str()))?;
                ins.bind_i64(8, i64::from(head.ephemeral_if_unmodified))?;
                ins.bind_i64(9, i64::from(head.modified))?;
                ins.bind_u64(10, head.updated_at.sec)?;
                ins.bind_u64(11, u64::from(head.updated_at.nsec))?;
                ins.step_done()?;
                Ok(head.clone())
            })
        })
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move { self.read_head_sync(volume) })
    }

    fn list_volumes(&self) -> BoxFuture<'_, Vec<VolumeHead>> {
        Box::pin(async move {
            self.ensure_format_compatible()?;
            let stmt = self.db.prepare(
                "SELECT volume, format_version, incarnation, fence, epoch, root, parent_volume, \
                 ephemeral_if_unmodified, modified, updated_sec, updated_nsec \
                 FROM heads ORDER BY volume ASC",
            )?;
            let mut out = Vec::new();
            while stmt.step_row()? {
                out.push(VolumeHead {
                    volume: VolumeId(stmt.col_str(0)?),
                    format_version: stmt.col_u32(1),
                    incarnation: stmt.col_u64(2),
                    fence: stmt.col_u64(3),
                    epoch: stmt.col_u64(4),
                    root: stmt.col_digest(5)?,
                    parent_volume: stmt.col_opt_str(6)?.map(VolumeId),
                    ephemeral_if_unmodified: stmt.col_u64(7) != 0,
                    modified: stmt.col_u64(8) != 0,
                    updated_at: Timespec {
                        sec: stmt.col_u64(9),
                        nsec: stmt.col_u32(10),
                    },
                });
            }
            Ok(out)
        })
    }

    fn commit_received_root<'a>(
        &'a self,
        req: &'a ReceiveCommitRequest,
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            if let Some(ref snap) = req.snapshot_name
                && (snap.is_empty() || snap.contains(['/', '\0']))
            {
                return Err(Errno::EINVAL);
            }
            self.ensure_format_compatible()?;
            self.with_txn(|| {
                let meta_stmt = self.db.prepare(
                    "INSERT OR IGNORE INTO meta (key, value) VALUES ('format_version', ?1)",
                )?;
                meta_stmt.bind_str(1, &COWFS_FORMAT_VERSION.to_string())?;
                meta_stmt.step_done()?;

                let rec = self
                    .db
                    .prepare("SELECT root, head_json FROM receipts WHERE op_id = ?1")?;
                rec.bind_blob(1, &req.op_id)?;
                if rec.step_row()? {
                    let rec_root = rec.col_digest(0)?;
                    if rec_root != req.new_root {
                        return Err(Errno::EINVAL);
                    }
                    let json = rec.col_str(1)?;
                    let head: VolumeHead =
                        serde_json::from_str(&json).map_err(|_| Errno::EIO)?;
                    return Ok(head);
                }
                drop(rec);

                let next_head = match req.expected_lease {
                    Some((exp_inc, exp_fence, exp_epoch)) => {
                        let cur = self.read_head_sync(&req.volume)?;
                        if cur.incarnation != exp_inc
                            || cur.fence != exp_fence
                            || cur.epoch != exp_epoch
                        {
                            return Err(Errno::ESTALE);
                        }
                        if let Some(ref snap) = req.snapshot_name {
                            let check = self.db.prepare(
                                "SELECT 1 FROM snapshots WHERE volume = ?1 AND name = ?2",
                            )?;
                            check.bind_str(1, &req.volume.0)?;
                            check.bind_str(2, snap)?;
                            if check.step_row()? {
                                return Err(Errno::EEXIST);
                            }
                        }
                        let grace = self.grace_window_secs.get();
                        if grace > 0 {
                            let pin = self.db.prepare(
                                "INSERT INTO grace_pins (volume, root, pinned_until_sec, pinned_until_nsec) \
                                 VALUES (?1, ?2, ?3, ?4)",
                            )?;
                            pin.bind_str(1, &req.volume.0)?;
                            pin.bind_blob(2, &cur.root)?;
                            pin.bind_u64(3, req.committed_at.sec.saturating_add(grace))?;
                            pin.bind_u64(4, u64::from(req.committed_at.nsec))?;
                            pin.step_done()?;
                        }
                        VolumeHead {
                            format_version: COWFS_FORMAT_VERSION,
                            volume: req.volume.clone(),
                            incarnation: cur.incarnation,
                            fence: cur.fence,
                            epoch: cur.epoch.saturating_add(1),
                            root: req.new_root,
                            parent_volume: cur.parent_volume,
                            ephemeral_if_unmodified: cur.ephemeral_if_unmodified,
                            modified: true,
                            updated_at: req.committed_at,
                        }
                    }
                    None => {
                        if self.read_head_sync(&req.volume).is_ok() {
                            return Err(Errno::EEXIST);
                        }
                        VolumeHead {
                            format_version: COWFS_FORMAT_VERSION,
                            volume: req.volume.clone(),
                            incarnation: 1,
                            fence: 1,
                            epoch: 0,
                            root: req.new_root,
                            parent_volume: None,
                            ephemeral_if_unmodified: false,
                            modified: true,
                            updated_at: req.committed_at,
                        }
                    }
                };

                for (digest, bytes) in &req.put_nodes {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO nodes (digest, data, created_sec, created_nsec) \
                         VALUES (?1, ?2, ?3, ?4)",
                    )?;
                    s.bind_blob(1, digest)?;
                    s.bind_blob(2, bytes)?;
                    s.bind_u64(3, req.committed_at.sec)?;
                    s.bind_u64(4, u64::from(req.committed_at.nsec))?;
                    s.step_done()?;
                }
                for pm in &req.put_packs {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO packs (pack_id, size, entry_count, created_sec, created_nsec) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                    )?;
                    s.bind_str(1, &pm.pack_id.0)?;
                    s.bind_u64(2, u64::from(pm.size))?;
                    s.bind_u64(3, u64::from(pm.entry_count))?;
                    s.bind_u64(4, req.committed_at.sec)?;
                    s.bind_u64(5, u64::from(req.committed_at.nsec))?;
                    s.step_done()?;
                }
                for (digest, loc) in &req.put_blocks {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO blocks (digest, pack_id, offset, len, raw_len, flags) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )?;
                    s.bind_blob(1, digest)?;
                    s.bind_str(2, &loc.pack_id.0)?;
                    s.bind_u64(3, u64::from(loc.offset))?;
                    s.bind_u64(4, u64::from(loc.len))?;
                    s.bind_u64(5, u64::from(loc.raw_len))?;
                    s.bind_u64(6, u64::from(loc.flags))?;
                    s.step_done()?;
                }

                if req.expected_lease.is_some() {
                    let upd = self.db.prepare(
                        "UPDATE heads SET epoch = ?1, root = ?2, modified = 1, \
                         updated_sec = ?3, updated_nsec = ?4 WHERE volume = ?5",
                    )?;
                    upd.bind_u64(1, next_head.epoch)?;
                    upd.bind_blob(2, &next_head.root)?;
                    upd.bind_u64(3, next_head.updated_at.sec)?;
                    upd.bind_u64(4, u64::from(next_head.updated_at.nsec))?;
                    upd.bind_str(5, &req.volume.0)?;
                    upd.step_done()?;
                } else {
                    let ins = self.db.prepare(
                        "INSERT INTO heads (volume, format_version, incarnation, fence, epoch, root, \
                         parent_volume, ephemeral_if_unmodified, modified, updated_sec, updated_nsec) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, 0, 1, ?7, ?8)",
                    )?;
                    ins.bind_str(1, &next_head.volume.0)?;
                    ins.bind_u64(2, u64::from(next_head.format_version))?;
                    ins.bind_u64(3, next_head.incarnation)?;
                    ins.bind_u64(4, next_head.fence)?;
                    ins.bind_u64(5, next_head.epoch)?;
                    ins.bind_blob(6, &next_head.root)?;
                    ins.bind_u64(7, next_head.updated_at.sec)?;
                    ins.bind_u64(8, u64::from(next_head.updated_at.nsec))?;
                    ins.step_done()?;
                }

                if let Some(ref snap) = req.snapshot_name {
                    let s = self.db.prepare(
                        "INSERT INTO snapshots (volume, name, root, epoch, created_sec, created_nsec) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )?;
                    s.bind_str(1, &req.volume.0)?;
                    s.bind_str(2, snap)?;
                    s.bind_blob(3, &next_head.root)?;
                    s.bind_u64(4, next_head.epoch)?;
                    s.bind_u64(5, req.committed_at.sec)?;
                    s.bind_u64(6, u64::from(req.committed_at.nsec))?;
                    s.step_done()?;
                }

                let head_json = serde_json::to_string(&next_head).map_err(|_| Errno::EIO)?;
                let rec_ins = self.db.prepare(
                    "INSERT INTO receipts (op_id, volume, epoch, root, head_json, created_sec) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )?;
                rec_ins.bind_blob(1, &req.op_id)?;
                rec_ins.bind_str(2, &req.volume.0)?;
                rec_ins.bind_u64(3, next_head.epoch)?;
                rec_ins.bind_blob(4, &next_head.root)?;
                rec_ins.bind_str(5, &head_json)?;
                rec_ins.bind_u64(6, req.committed_at.sec)?;
                rec_ins.step_done()?;

                Ok(next_head)
            })
        })
    }

    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async move {
            self.ensure_format_compatible()?;
            let _gc = acquire_flock_gc(&self.gc_lock_path(), false)?;
            let pin_id = random_hex_16();
            let lock_path = self.ro_pin_lock_path(&pin_id);
            let pin_lock = try_flock_exclusive(&lock_path)?;
            let pinned_head = self.with_txn(|| {
                let mut head = self.read_head_sync(volume)?;
                if head.format_version != COWFS_FORMAT_VERSION {
                    return Err(Errno::EPROTONOSUPPORT);
                }
                if let Some(snap_name) = snapshot {
                    let s = self.db.prepare(
                        "SELECT root, epoch, created_sec, created_nsec FROM snapshots \
                         WHERE volume = ?1 AND name = ?2",
                    )?;
                    s.bind_str(1, &volume.0)?;
                    s.bind_str(2, snap_name)?;
                    if !s.step_row()? {
                        return Err(Errno::ENOENT);
                    }
                    head.root = s.col_digest(0)?;
                    head.epoch = s.col_u64(1);
                    head.updated_at = Timespec {
                        sec: s.col_u64(2),
                        nsec: s.col_u32(3),
                    };
                }
                let check = self.db.prepare("SELECT 1 FROM nodes WHERE digest = ?1")?;
                check.bind_blob(1, &head.root)?;
                if !check.step_row()? {
                    return Err(Errno::ENOENT);
                }
                drop(check);
                let ins = self
                    .db
                    .prepare("INSERT INTO ro_pins (pin_id, volume, root) VALUES (?1, ?2, ?3)")?;
                ins.bind_str(1, &pin_id)?;
                ins.bind_str(2, &volume.0)?;
                ins.bind_blob(3, &head.root)?;
                ins.step_done()?;
                Ok(head)
            });
            match pinned_head {
                Ok(head) => Ok((
                    head,
                    Box::new(FlockRoPinGuard {
                        db: Rc::clone(&self.db),
                        pin_id,
                        lock_path,
                        _file: pin_lock,
                    }) as Box<dyn RoPinGuard>,
                )),
                Err(e) => {
                    drop(pin_lock);
                    let _ = fs::remove_file(&lock_path);
                    Err(e)
                }
            }
        })
    }

    fn unpin_ro_root<'a>(&'a self, pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            drop(pin);
            Ok(())
        })
    }

    fn acquire_writer<'a>(
        &'a self,
        volume: &'a VolumeId,
        mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async move {
            self.ensure_format_compatible()?;
            let head = self.read_head_sync(volume)?;
            if head.format_version != COWFS_FORMAT_VERSION {
                return Err(Errno::EPROTONOSUPPORT);
            }
            match mode {
                WriterMode::Exclusive => {
                    let (latest, file) = self.acquire_current_volume_lock(volume)?;
                    Ok(WriterLease {
                        volume: volume.clone(),
                        incarnation: latest.incarnation,
                        fence: latest.fence,
                        epoch: latest.epoch,
                        head: latest,
                        forked_from: None,
                        expires_at: None,
                        guard: Box::new(FlockWriterGuard { _file: file }),
                    })
                }
                WriterMode::ForkOnBusy => match self.acquire_current_volume_lock(volume) {
                    Ok((latest, file)) => Ok(WriterLease {
                        volume: volume.clone(),
                        incarnation: latest.incarnation,
                        fence: latest.fence,
                        epoch: latest.epoch,
                        head: latest,
                        forked_from: None,
                        expires_at: None,
                        guard: Box::new(FlockWriterGuard { _file: file }),
                    }),
                    Err(Errno::EBUSY) => {
                        // Hold shared GC lock from root selection through fork head publication.
                        let _gc = acquire_flock_gc(&self.gc_lock_path(), false)?;
                        for _ in 0..16 {
                            let fork_vol =
                                VolumeId(format!("{}-fork-{}", volume.0, random_hex_16()));
                            let fork_lock =
                                match try_flock_exclusive(&self.lock_path(&fork_vol, 1, 1)) {
                                    Ok(f) => f,
                                    Err(Errno::EBUSY) => continue,
                                    Err(e) => return Err(e),
                                };
                            let inserted = self.with_txn(|| {
                                let latest = self.read_head_sync(volume)?;
                                let check =
                                    self.db.prepare("SELECT 1 FROM nodes WHERE digest = ?1")?;
                                check.bind_blob(1, &latest.root)?;
                                if !check.step_row()? {
                                    return Err(Errno::ENOENT);
                                }
                                drop(check);
                                let fh = VolumeHead {
                                    format_version: COWFS_FORMAT_VERSION,
                                    volume: fork_vol.clone(),
                                    incarnation: 1,
                                    fence: 1,
                                    epoch: 0,
                                    root: latest.root,
                                    parent_volume: Some(volume.clone()),
                                    ephemeral_if_unmodified: true,
                                    modified: false,
                                    updated_at: latest.updated_at,
                                };
                                let ins = self.db.prepare(
                                    "INSERT INTO heads (volume, format_version, incarnation, fence, epoch, \
                                     root, parent_volume, ephemeral_if_unmodified, modified, updated_sec, updated_nsec) \
                                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, 0, ?8, ?9)",
                                )?;
                                ins.bind_str(1, &fh.volume.0)?;
                                ins.bind_u64(2, u64::from(fh.format_version))?;
                                ins.bind_u64(3, fh.incarnation)?;
                                ins.bind_u64(4, fh.fence)?;
                                ins.bind_u64(5, fh.epoch)?;
                                ins.bind_blob(6, &fh.root)?;
                                ins.bind_str(7, &volume.0)?;
                                ins.bind_u64(8, fh.updated_at.sec)?;
                                ins.bind_u64(9, u64::from(fh.updated_at.nsec))?;
                                ins.step_done()?;
                                Ok(fh)
                            });
                            match inserted {
                                Ok(fork_head) => {
                                    return Ok(WriterLease {
                                        volume: fork_vol,
                                        incarnation: fork_head.incarnation,
                                        fence: fork_head.fence,
                                        epoch: fork_head.epoch,
                                        head: fork_head,
                                        forked_from: Some(volume.clone()),
                                        expires_at: None,
                                        guard: Box::new(FlockWriterGuard { _file: fork_lock }),
                                    });
                                }
                                Err(Errno::EEXIST) => {
                                    drop(fork_lock);
                                    continue;
                                }
                                Err(e) => {
                                    drop(fork_lock);
                                    return Err(e);
                                }
                            }
                        }
                        Err(Errno::EEXIST)
                    }
                    Err(e) => Err(e),
                },
                WriterMode::ForceTakeover => {
                    // Atomically allocate `next_fence` and acquire its exclusive OS `flock`
                    // BEFORE committing the fence bump, so a takeover writer ALWAYS holds an
                    // enforceable OS exclusion lock even after the prior holder exits.
                    let (taken, file) = self.with_txn(|| {
                        let cur = self.read_head_sync(volume)?;
                        let next_fence = cur.fence.saturating_add(1);
                        let lock_file = self.lock_path(volume, cur.incarnation, next_fence);
                        let file = try_flock_exclusive(&lock_file)?;
                        let upd = self
                            .db
                            .prepare("UPDATE heads SET fence = ?1 WHERE volume = ?2")?;
                        upd.bind_u64(1, next_fence)?;
                        upd.bind_str(2, &volume.0)?;
                        upd.step_done()?;
                        Ok((
                            VolumeHead {
                                fence: next_fence,
                                ..cur
                            },
                            file,
                        ))
                    })?;
                    Ok(WriterLease {
                        volume: volume.clone(),
                        incarnation: taken.incarnation,
                        fence: taken.fence,
                        epoch: taken.epoch,
                        head: taken,
                        forked_from: None,
                        expires_at: None,
                        guard: Box::new(FlockWriterGuard { _file: file }),
                    })
                }
            }
        })
    }

    fn renew_writer<'a>(&'a self, lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let head = self.read_head_sync(&lease.volume)?;
            if head.incarnation != lease.incarnation || head.fence != lease.fence {
                return Err(Errno::ESTALE);
            }
            Ok(())
        })
    }

    fn release_writer<'a>(&'a self, lease: WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            drop(lease);
            Ok(())
        })
    }

    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let stmt = self
                .db
                .prepare("SELECT data FROM nodes WHERE digest = ?1")?;
            stmt.bind_blob(1, digest)?;
            if !stmt.step_row()? {
                return Err(Errno::ENOENT);
            }
            Ok(stmt.col_blob(0))
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move {
            let stmt = self.db.prepare(
                "SELECT pack_id, offset, len, raw_len, flags FROM blocks WHERE digest = ?1",
            )?;
            stmt.bind_blob(1, digest)?;
            if !stmt.step_row()? {
                return Ok(None);
            }
            Ok(Some(BlockLoc {
                pack_id: PackId(stmt.col_str(0)?),
                offset: stmt.col_u32(1),
                len: stmt.col_u32(2),
                raw_len: stmt.col_u32(3),
                flags: stmt.col_u32(4) as u16,
            }))
        })
    }

    fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            if let Some(err) = self.fail_next_commit.take() {
                return Err(err);
            }
            self.ensure_format_compatible()?;
            self.with_txn(|| {
                // 1. Check idempotency receipt.
                let rec = self
                    .db
                    .prepare("SELECT root, head_json FROM receipts WHERE op_id = ?1")?;
                rec.bind_blob(1, &req.op_id)?;
                if rec.step_row()? {
                    let rec_root = rec.col_digest(0)?;
                    if rec_root != req.new_root {
                        return Err(Errno::EINVAL);
                    }
                    let json = rec.col_str(1)?;
                    let head: VolumeHead =
                        serde_json::from_str(&json).map_err(|_| Errno::EIO)?;
                    return Ok(head);
                }
                drop(rec);

                // 2. Verify (incarnation, fence, epoch) match.
                let cur = self.read_head_sync(&req.volume)?;
                if cur.incarnation != req.expected_incarnation
                    || cur.fence != req.expected_fence
                    || cur.epoch != req.expected_epoch
                {
                    return Err(Errno::ESTALE);
                }

                // 3. Insert put_nodes, put_packs, put_blocks.
                for (digest, bytes) in &req.put_nodes {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO nodes (digest, data, created_sec, created_nsec) \
                         VALUES (?1, ?2, ?3, ?4)",
                    )?;
                    s.bind_blob(1, digest)?;
                    s.bind_blob(2, bytes)?;
                    s.bind_u64(3, req.committed_at.sec)?;
                    s.bind_u64(4, u64::from(req.committed_at.nsec))?;
                    s.step_done()?;
                }
                for pm in &req.put_packs {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO packs (pack_id, size, entry_count, created_sec, created_nsec) \
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                    )?;
                    s.bind_str(1, &pm.pack_id.0)?;
                    s.bind_u64(2, u64::from(pm.size))?;
                    s.bind_u64(3, u64::from(pm.entry_count))?;
                    s.bind_u64(4, req.committed_at.sec)?;
                    s.bind_u64(5, u64::from(req.committed_at.nsec))?;
                    s.step_done()?;
                }
                for (digest, loc) in &req.put_blocks {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO blocks (digest, pack_id, offset, len, raw_len, flags) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )?;
                    s.bind_blob(1, digest)?;
                    s.bind_str(2, &loc.pack_id.0)?;
                    s.bind_u64(3, u64::from(loc.offset))?;
                    s.bind_u64(4, u64::from(loc.len))?;
                    s.bind_u64(5, u64::from(loc.raw_len))?;
                    s.bind_u64(6, u64::from(loc.flags))?;
                    s.step_done()?;
                }

                // Record superseded root in grace_pins.
                let grace = self.grace_window_secs.get();
                if grace > 0 {
                    let pin = self.db.prepare(
                        "INSERT INTO grace_pins (volume, root, pinned_until_sec, pinned_until_nsec) \
                         VALUES (?1, ?2, ?3, ?4)",
                    )?;
                    pin.bind_str(1, &req.volume.0)?;
                    pin.bind_blob(2, &cur.root)?;
                    pin.bind_u64(3, req.committed_at.sec.saturating_add(grace))?;
                    pin.bind_u64(4, u64::from(req.committed_at.nsec))?;
                    pin.step_done()?;
                }

                // 4. Advance head atomically.
                let next_head = VolumeHead {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: req.volume.clone(),
                    incarnation: cur.incarnation,
                    fence: cur.fence,
                    epoch: cur.epoch.saturating_add(1),
                    root: req.new_root,
                    parent_volume: cur.parent_volume,
                    ephemeral_if_unmodified: cur.ephemeral_if_unmodified,
                    modified: true,
                    updated_at: req.committed_at,
                };
                let upd = self.db.prepare(
                    "UPDATE heads SET epoch = ?1, root = ?2, modified = 1, \
                     updated_sec = ?3, updated_nsec = ?4 WHERE volume = ?5",
                )?;
                upd.bind_u64(1, next_head.epoch)?;
                upd.bind_blob(2, &next_head.root)?;
                upd.bind_u64(3, next_head.updated_at.sec)?;
                upd.bind_u64(4, u64::from(next_head.updated_at.nsec))?;
                upd.bind_str(5, &req.volume.0)?;
                upd.step_done()?;

                let head_json = serde_json::to_string(&next_head).map_err(|_| Errno::EIO)?;
                let rec_ins = self.db.prepare(
                    "INSERT INTO receipts (op_id, volume, epoch, root, head_json, created_sec) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )?;
                rec_ins.bind_blob(1, &req.op_id)?;
                rec_ins.bind_str(2, &req.volume.0)?;
                rec_ins.bind_u64(3, next_head.epoch)?;
                rec_ins.bind_blob(4, &next_head.root)?;
                rec_ins.bind_str(5, &head_json)?;
                rec_ins.bind_u64(6, req.committed_at.sec)?;
                rec_ins.step_done()?;

                Ok(next_head)
            })
        })
    }

    fn create_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
        head: &'a VolumeHead,
        now: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            if name.is_empty() || name.contains(['/', '\0']) {
                return Err(Errno::EINVAL);
            }
            self.with_txn(|| {
                let s = self.db.prepare(
                    "INSERT INTO snapshots (volume, name, root, epoch, created_sec, created_nsec) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )?;
                s.bind_str(1, &volume.0)?;
                s.bind_str(2, name)?;
                s.bind_blob(3, &head.root)?;
                s.bind_u64(4, head.epoch)?;
                s.bind_u64(5, now.sec)?;
                s.bind_u64(6, u64::from(now.nsec))?;
                s.step_done()?;
                Ok(SnapshotRecord {
                    volume: volume.clone(),
                    name: name.to_string(),
                    root: head.root,
                    epoch: head.epoch,
                    created_at: now,
                })
            })
        })
    }

    fn get_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            let s = self.db.prepare(
                "SELECT root, epoch, created_sec, created_nsec FROM snapshots \
                 WHERE volume = ?1 AND name = ?2",
            )?;
            s.bind_str(1, &volume.0)?;
            s.bind_str(2, name)?;
            if !s.step_row()? {
                return Err(Errno::ENOENT);
            }
            Ok(SnapshotRecord {
                volume: volume.clone(),
                name: name.to_string(),
                root: s.col_digest(0)?,
                epoch: s.col_u64(1),
                created_at: Timespec {
                    sec: s.col_u64(2),
                    nsec: s.col_u32(3),
                },
            })
        })
    }

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        Box::pin(async move {
            let s = self.db.prepare(
                "SELECT name, root, epoch, created_sec, created_nsec FROM snapshots \
                 WHERE volume = ?1 ORDER BY name ASC",
            )?;
            s.bind_str(1, &volume.0)?;
            let mut out = Vec::new();
            while s.step_row()? {
                out.push(SnapshotRecord {
                    volume: volume.clone(),
                    name: s.col_str(0)?,
                    root: s.col_digest(1)?,
                    epoch: s.col_u64(2),
                    created_at: Timespec {
                        sec: s.col_u64(3),
                        nsec: s.col_u32(4),
                    },
                });
            }
            Ok(out)
        })
    }

    fn delete_snapshot<'a>(&'a self, volume: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.with_txn(|| {
                let check = self
                    .db
                    .prepare("SELECT 1 FROM snapshots WHERE volume = ?1 AND name = ?2")?;
                check.bind_str(1, &volume.0)?;
                check.bind_str(2, name)?;
                if !check.step_row()? {
                    return Err(Errno::ENOENT);
                }
                drop(check);
                let del = self
                    .db
                    .prepare("DELETE FROM snapshots WHERE volume = ?1 AND name = ?2")?;
                del.bind_str(1, &volume.0)?;
                del.bind_str(2, name)?;
                del.step_done()
            })
        })
    }

    fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            self.ensure_format_compatible()?;
            self.with_txn(|| {
                let check = self.db.prepare("SELECT 1 FROM nodes WHERE digest = ?1")?;
                check.bind_blob(1, &req.source_root)?;
                if !check.step_row()? {
                    return Err(Errno::ENOENT);
                }
                drop(check);
                let head = VolumeHead {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: req.new_volume.clone(),
                    incarnation: 1,
                    fence: 1,
                    epoch: 0,
                    root: req.source_root,
                    parent_volume: Some(req.source_volume.clone()),
                    ephemeral_if_unmodified: req.ephemeral_if_unmodified,
                    modified: false,
                    updated_at: req.created_at,
                };
                let ins = self.db.prepare(
                    "INSERT INTO heads (volume, format_version, incarnation, fence, epoch, root, \
                     parent_volume, ephemeral_if_unmodified, modified, updated_sec, updated_nsec) \
                     VALUES (?1, ?2, 1, 1, 0, ?3, ?4, ?5, 0, ?6, ?7)",
                )?;
                ins.bind_str(1, &head.volume.0)?;
                ins.bind_u64(2, u64::from(head.format_version))?;
                ins.bind_blob(3, &head.root)?;
                ins.bind_str(4, &req.source_volume.0)?;
                ins.bind_i64(5, i64::from(head.ephemeral_if_unmodified))?;
                ins.bind_u64(6, head.updated_at.sec)?;
                ins.bind_u64(7, u64::from(head.updated_at.nsec))?;
                ins.step_done()?;
                Ok(head)
            })
        })
    }

    fn delete_volume<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (locked_head, _lock) = self.acquire_current_volume_lock(volume)?;
            self.with_txn(|| {
                let cur = self.read_head_sync(volume)?;
                if cur.incarnation != locked_head.incarnation || cur.fence != locked_head.fence {
                    return Err(Errno::EBUSY);
                }
                self.delete_volume_rows_in_txn(volume)
            })
        })
    }

    fn delete_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let res = self.with_txn(|| {
                let cur = self.read_head_sync(&lease.volume)?;
                if cur.incarnation != lease.incarnation
                    || cur.fence != lease.fence
                    || cur.epoch != lease.epoch
                {
                    return Err(Errno::ESTALE);
                }
                if only_if_unmodified_ephemeral && (!cur.ephemeral_if_unmodified || cur.modified) {
                    return Ok(false);
                }
                self.delete_volume_rows_in_txn(&lease.volume)?;
                Ok(true)
            });
            drop(lease);
            res
        })
    }

    fn reformat_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        new_head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            self.ensure_format_compatible()?;
            let res = self.with_txn(|| {
                let cur = self.read_head_sync(&lease.volume)?;
                if cur.incarnation != lease.incarnation
                    || cur.fence != lease.fence
                    || cur.epoch != lease.epoch
                {
                    return Err(Errno::ESTALE);
                }
                let mut stale_pins = Vec::new();
                {
                    let s_pin = self
                        .db
                        .prepare("SELECT pin_id FROM ro_pins WHERE volume = ?1")?;
                    s_pin.bind_str(1, &lease.volume.0)?;
                    while s_pin.step_row()? {
                        let pin_id = s_pin.col_str(0)?;
                        let lpath = self.ro_pin_lock_path(&pin_id);
                        match try_flock_exclusive(&lpath) {
                            Err(Errno::EBUSY) => return Err(Errno::EBUSY),
                            Ok(f) => {
                                drop(f);
                                let _ = fs::remove_file(&lpath);
                                stale_pins.push(pin_id);
                            }
                            Err(_) => return Err(Errno::EBUSY),
                        }
                    }
                }
                for pin_id in stale_pins {
                    let d_pin = self.db.prepare("DELETE FROM ro_pins WHERE pin_id = ?1")?;
                    d_pin.bind_str(1, &pin_id)?;
                    d_pin.step_done()?;
                }
                let d_snap = self.db.prepare("DELETE FROM snapshots WHERE volume = ?1")?;
                d_snap.bind_str(1, &lease.volume.0)?;
                d_snap.step_done()?;

                let d_rec = self.db.prepare("DELETE FROM receipts WHERE volume = ?1")?;
                d_rec.bind_str(1, &lease.volume.0)?;
                d_rec.step_done()?;

                for (digest, bytes) in initial_nodes {
                    let s = self.db.prepare(
                        "INSERT OR IGNORE INTO nodes (digest, data, created_sec, created_nsec) \
                         VALUES (?1, ?2, ?3, ?4)",
                    )?;
                    s.bind_blob(1, digest)?;
                    s.bind_blob(2, bytes)?;
                    s.bind_u64(3, new_head.updated_at.sec)?;
                    s.bind_u64(4, u64::from(new_head.updated_at.nsec))?;
                    s.step_done()?;
                }

                let next_incarnation = cur.incarnation.saturating_add(1);
                let replaced = VolumeHead {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: lease.volume.clone(),
                    incarnation: next_incarnation,
                    fence: 1,
                    epoch: 0,
                    root: new_head.root,
                    parent_volume: None,
                    ephemeral_if_unmodified: false,
                    modified: false,
                    updated_at: new_head.updated_at,
                };
                let upd = self.db.prepare(
                    "UPDATE heads SET format_version = ?1, incarnation = ?2, fence = 1, \
                     epoch = 0, root = ?3, parent_volume = NULL, ephemeral_if_unmodified = 0, \
                     modified = 0, updated_sec = ?4, updated_nsec = ?5 WHERE volume = ?6",
                )?;
                upd.bind_u64(1, u64::from(replaced.format_version))?;
                upd.bind_u64(2, replaced.incarnation)?;
                upd.bind_blob(3, &replaced.root)?;
                upd.bind_u64(4, replaced.updated_at.sec)?;
                upd.bind_u64(5, u64::from(replaced.updated_at.nsec))?;
                upd.bind_str(6, &replaced.volume.0)?;
                upd.step_done()?;
                Ok(replaced)
            });
            drop(lease);
            res
        })
    }

    fn acquire_gc_lock(&self, exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async move {
            let file = acquire_flock_gc(&self.gc_lock_path(), exclusive)?;
            Ok(Box::new(FlockGcGuard { _file: file }) as Box<dyn GcLockGuard>)
        })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async move {
            let mut out = Vec::new();
            let s1 = self.db.prepare("SELECT volume, root FROM heads")?;
            while s1.step_row()? {
                out.push(GcRoot {
                    volume: VolumeId(s1.col_str(0)?),
                    root: s1.col_digest(1)?,
                    pinned_until: None,
                });
            }
            let s2 = self.db.prepare("SELECT volume, root FROM snapshots")?;
            while s2.step_row()? {
                out.push(GcRoot {
                    volume: VolumeId(s2.col_str(0)?),
                    root: s2.col_digest(1)?,
                    pinned_until: None,
                });
            }
            let s3 = self.db.prepare(
                "SELECT volume, root, pinned_until_sec, pinned_until_nsec FROM grace_pins",
            )?;
            while s3.step_row()? {
                out.push(GcRoot {
                    volume: VolumeId(s3.col_str(0)?),
                    root: s3.col_digest(1)?,
                    pinned_until: Some(Timespec {
                        sec: s3.col_u64(2),
                        nsec: s3.col_u32(3),
                    }),
                });
            }
            let mut stale_ro_pins = Vec::new();
            let s4 = self
                .db
                .prepare("SELECT pin_id, volume, root FROM ro_pins")?;
            while s4.step_row()? {
                let pin_id = s4.col_str(0)?;
                let vol = VolumeId(s4.col_str(1)?);
                let root = s4.col_digest(2)?;
                let lpath = self.ro_pin_lock_path(&pin_id);
                match try_flock_exclusive(&lpath) {
                    Err(Errno::EBUSY) => {
                        // Reader process is alive and holding its RO pin lock.
                        out.push(GcRoot {
                            volume: vol,
                            root,
                            pinned_until: None,
                        });
                    }
                    Ok(f) => {
                        drop(f);
                        stale_ro_pins.push((pin_id, lpath));
                    }
                    Err(_) => {
                        // Fail safe: preserve root if lock check returned a transient error.
                        out.push(GcRoot {
                            volume: vol,
                            root,
                            pinned_until: None,
                        });
                    }
                }
            }
            drop(s4);
            for (pin_id, lpath) in stale_ro_pins {
                if let Ok(del) = self.db.prepare("DELETE FROM ro_pins WHERE pin_id = ?1") {
                    let _ = del.bind_str(1, &pin_id);
                    let _ = del.step_done();
                }
                let _ = fs::remove_file(&lpath);
            }
            Ok(out)
        })
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move {
            let mut out = HashSet::new();
            let s1 = self.db.prepare("SELECT pack_id FROM packs")?;
            while s1.step_row()? {
                out.insert(PackId(s1.col_str(0)?));
            }
            let s2 = self.db.prepare("SELECT DISTINCT pack_id FROM blocks")?;
            while s2.step_row()? {
                out.insert(PackId(s2.col_str(0)?));
            }
            Ok(out)
        })
    }

    fn prune_abandoned_ephemeral_forks(
        &self,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'_, usize> {
        Box::pin(async move {
            let mut candidates = Vec::new();
            let s = self.db.prepare(
                "SELECT volume, incarnation, fence, updated_sec, updated_nsec FROM heads \
                 WHERE ephemeral_if_unmodified = 1 AND modified = 0",
            )?;
            while s.step_row()? {
                let vol = VolumeId(s.col_str(0)?);
                let inc = s.col_u64(1);
                let fence = s.col_u64(2);
                let updated = Timespec {
                    sec: s.col_u64(3),
                    nsec: s.col_u32(4),
                };
                if ts_expired(updated, now, grace_window_secs) {
                    candidates.push((vol, inc, fence));
                }
            }
            drop(s);

            let mut pruned = 0usize;
            for (vol, inc, fence) in candidates {
                let Ok(_lock) = try_flock_exclusive(&self.lock_path(&vol, inc, fence)) else {
                    continue;
                };
                let deleted = self.with_txn(|| {
                    let cur = match self.read_head_sync(&vol) {
                        Ok(h) => h,
                        Err(Errno::ENOENT) => return Ok(false),
                        Err(e) => return Err(e),
                    };
                    if cur.ephemeral_if_unmodified
                        && !cur.modified
                        && cur.incarnation == inc
                        && cur.fence == fence
                        && ts_expired(cur.updated_at, now, grace_window_secs)
                    {
                        self.delete_volume_rows_in_txn(&vol)?;
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                })?;
                if deleted {
                    pruned += 1;
                }
            }
            Ok(pruned)
        })
    }

    fn sweep_metadata<'a>(
        &'a self,
        keep_nodes: &'a HashSet<Digest>,
        keep_packs: &'a HashSet<PackId>,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async move {
            self.with_txn(|| {
                // Expire grace pins when `pinned_until <= now`.
                let del_pins = self.db.prepare(
                    "DELETE FROM grace_pins WHERE pinned_until_sec < ?1 \
                     OR (pinned_until_sec = ?1 AND pinned_until_nsec <= ?2)",
                )?;
                del_pins.bind_u64(1, now.sec)?;
                del_pins.bind_u64(2, u64::from(now.nsec))?;
                del_pins.step_done()?;

                let mut dead_nodes = Vec::new();
                let sn = self
                    .db
                    .prepare("SELECT digest, created_sec, created_nsec FROM nodes")?;
                while sn.step_row()? {
                    let d = sn.col_digest(0)?;
                    let ts = Timespec {
                        sec: sn.col_u64(1),
                        nsec: sn.col_u32(2),
                    };
                    if !keep_nodes.contains(&d) && ts_expired(ts, now, grace_window_secs) {
                        dead_nodes.push(d);
                    }
                }
                drop(sn);
                for d in &dead_nodes {
                    let del = self.db.prepare("DELETE FROM nodes WHERE digest = ?1")?;
                    del.bind_blob(1, d)?;
                    del.step_done()?;
                }

                let mut dead_packs = Vec::new();
                let sp = self
                    .db
                    .prepare("SELECT pack_id, created_sec, created_nsec FROM packs")?;
                while sp.step_row()? {
                    let pid = PackId(sp.col_str(0)?);
                    let ts = Timespec {
                        sec: sp.col_u64(1),
                        nsec: sp.col_u32(2),
                    };
                    if !keep_packs.contains(&pid) && ts_expired(ts, now, grace_window_secs) {
                        dead_packs.push(pid);
                    }
                }
                drop(sp);
                for pid in &dead_packs {
                    let db1 = self.db.prepare("DELETE FROM blocks WHERE pack_id = ?1")?;
                    db1.bind_str(1, &pid.0)?;
                    db1.step_done()?;
                    let dp = self.db.prepare("DELETE FROM packs WHERE pack_id = ?1")?;
                    dp.bind_str(1, &pid.0)?;
                    dp.step_done()?;
                }

                // Prune aged receipts whose epoch is no longer a live head's current epoch.
                let mut live_epochs: HashMap<String, u64> = HashMap::new();
                let sh = self.db.prepare("SELECT volume, epoch FROM heads")?;
                while sh.step_row()? {
                    live_epochs.insert(sh.col_str(0)?, sh.col_u64(1));
                }
                drop(sh);
                let mut dead_receipts: Vec<Vec<u8>> = Vec::new();
                let sr = self
                    .db
                    .prepare("SELECT op_id, volume, epoch, created_sec FROM receipts")?;
                while sr.step_row()? {
                    let op_id = sr.col_blob(0);
                    let vol = sr.col_str(1)?;
                    let ep = sr.col_u64(2);
                    let created = Timespec {
                        sec: sr.col_u64(3),
                        nsec: 0,
                    };
                    if live_epochs.get(&vol) != Some(&ep)
                        && ts_expired(created, now, grace_window_secs)
                    {
                        dead_receipts.push(op_id);
                    }
                }
                drop(sr);
                for op_id in &dead_receipts {
                    let dr = self.db.prepare("DELETE FROM receipts WHERE op_id = ?1")?;
                    dr.bind_blob(1, op_id)?;
                    dr.step_done()?;
                }

                Ok(dead_packs)
            })
        })
    }
}

// -----------------------------------------------------------------------------
// NativePackStore
// -----------------------------------------------------------------------------

static TMP_SEQ: AtomicU64 = AtomicU64::new(1);

/// Native immutable pack-file [`PackStore`] (`$STATE/packs/<pack_id>.pack`).
/// Writes via temp file + `sync_all()` + atomic `rename` + directory `fsync`; reads via lock-free
/// `pread(2)`.
pub struct NativePackStore {
    packs_dir: PathBuf,
    bytes_written: Cell<u64>,
    pack_writes: Cell<u64>,
    quota_bytes: Cell<Option<u64>>,
    fail_next_write: Cell<Option<Errno>>,
}

impl NativePackStore {
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let packs_dir = state_dir.as_ref().join("packs");
        fs::create_dir_all(&packs_dir).map_err(map_io_err)?;
        Ok(Self {
            packs_dir,
            bytes_written: Cell::new(0),
            pack_writes: Cell::new(0),
            quota_bytes: Cell::new(None),
            fail_next_write: Cell::new(None),
        })
    }

    pub fn packs_dir(&self) -> &Path {
        &self.packs_dir
    }

    pub fn pack_path(&self, pack_id: &PackId) -> PathBuf {
        self.packs_dir.join(format!("{}.pack", pack_id.0))
    }

    pub fn set_quota_bytes(&self, quota: Option<u64>) {
        self.quota_bytes.set(quota);
    }

    pub fn fail_next_write(&self, err: Errno) {
        self.fail_next_write.set(Some(err));
    }

    pub fn reset_counters(&self) {
        self.bytes_written.set(0);
        self.pack_writes.set(0);
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.get()
    }

    pub fn pack_writes(&self) -> u64 {
        self.pack_writes.get()
    }

    /// Bit-flip one byte on disk in a pack file (for corruption `EIO` tests).
    pub fn corrupt_pack_byte(&self, pack_id: &PackId, offset: u64) -> Result<bool> {
        let path = self.pack_path(pack_id);
        let mut data = fs::read(&path).map_err(map_io_err)?;
        let idx = offset as usize;
        if idx >= data.len() {
            return Ok(false);
        }
        data[idx] ^= 0x01;
        fs::write(&path, &data).map_err(map_io_err)?;
        Ok(true)
    }

    fn total_stored_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        for entry in fs::read_dir(&self.packs_dir).map_err(map_io_err)? {
            let entry = entry.map_err(map_io_err)?;
            let name = entry.file_name();
            if name.to_string_lossy().ends_with(".pack")
                && let Ok(meta) = entry.metadata()
            {
                total = total.saturating_add(meta.len());
            }
        }
        Ok(total)
    }
}

impl PackStore for NativePackStore {
    fn write_pack<'a>(&'a self, pack_id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async move {
            if bytes.len() > PACK_MAX_BYTES {
                return Err(Errno::EFBIG);
            }
            if let Some(err) = self.fail_next_write.take() {
                return Err(err);
            }
            if digest_to_hex(&sha256(bytes)) != pack_id.0 {
                return Err(Errno::EINVAL);
            }
            let trailer = decode_pack_trailer(bytes)?;
            let final_path = self.pack_path(pack_id);
            let meta = PackMeta {
                pack_id: pack_id.clone(),
                size: bytes.len() as u32,
                entry_count: trailer.entries.len() as u32,
                created_at: Timespec { sec: 0, nsec: 0 },
            };
            // Verify full length + SHA-256 before reusing an existing file on disk so a corrupt or
            // truncated file is atomically replaced rather than indexed.
            if let Ok(existing) = fs::read(&final_path)
                && existing.len() == bytes.len()
                && digest_to_hex(&sha256(&existing)) == pack_id.0
            {
                return Ok(meta);
            }
            if let Some(quota) = self.quota_bytes.get()
                && self.total_stored_bytes()? + bytes.len() as u64 > quota
            {
                return Err(Errno::ENOSPC);
            }
            let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp_path = self.packs_dir.join(format!(
                ".{}.{}.{seq}.tmp",
                sanitize_name(&pack_id.0),
                std::process::id()
            ));
            let write_res = (|| -> Result<()> {
                let mut f = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&tmp_path)
                    .map_err(map_io_err)?;
                f.write_all(bytes).map_err(map_io_err)?;
                f.sync_all().map_err(map_io_err)?;
                drop(f);
                fs::rename(&tmp_path, &final_path).map_err(map_io_err)?;
                sync_dir(&self.packs_dir)?;
                Ok(())
            })();
            if let Err(e) = write_res {
                let _ = fs::remove_file(&tmp_path);
                return Err(e);
            }
            self.bytes_written
                .set(self.bytes_written.get() + bytes.len() as u64);
            self.pack_writes.set(self.pack_writes.get() + 1);
            Ok(meta)
        })
    }

    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let file = File::open(self.pack_path(pack_id)).map_err(map_io_err)?;
            let mut buf = vec![0u8; len as usize];
            let mut done = 0usize;
            while done < buf.len() {
                let n = file
                    .read_at(&mut buf[done..], u64::from(offset) + done as u64)
                    .map_err(map_io_err)?;
                if n == 0 {
                    return Err(Errno::EIO);
                }
                done += n;
            }
            Ok(buf)
        })
    }

    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let file = File::open(self.pack_path(pack_id)).map_err(map_io_err)?;
            let file_len = file.metadata().map_err(map_io_err)?.len();
            if file_len < PACK_FOOTER_BYTES as u64 || file_len > PACK_MAX_BYTES as u64 {
                return Err(Errno::EIO);
            }
            let mut footer = [0u8; PACK_FOOTER_BYTES];
            file.read_exact_at(&mut footer, file_len - PACK_FOOTER_BYTES as u64)
                .map_err(map_io_err)?;
            let (trailer_len, trailer_sha) = decode_pack_footer(&footer)?;
            let trailer_start = file_len
                .checked_sub(PACK_FOOTER_BYTES as u64 + u64::from(trailer_len))
                .ok_or(Errno::EIO)?;
            let mut trailer_bytes = vec![0u8; trailer_len as usize];
            file.read_exact_at(&mut trailer_bytes, trailer_start)
                .map_err(map_io_err)?;
            decode_pack_trailer_bytes(&trailer_bytes, trailer_sha, trailer_start as u32)
        })
    }

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move {
            match fs::metadata(self.pack_path(pack_id)) {
                Ok(m) => Ok(Some(m.len())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(map_io_err(e)),
            }
        })
    }

    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move {
            let mut out = Vec::new();
            for entry in fs::read_dir(&self.packs_dir).map_err(map_io_err)? {
                let entry = entry.map_err(map_io_err)?;
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if let Some(stem) = s.strip_suffix(".pack")
                    && !stem.starts_with('.')
                {
                    out.push(PackId(stem.to_string()));
                }
            }
            out.sort();
            Ok(out)
        })
    }

    fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match fs::remove_file(self.pack_path(pack_id)) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(map_io_err(e)),
            }
        })
    }
}

#[allow(dead_code)]
fn _cstr_unused(_: &CStr) {}
