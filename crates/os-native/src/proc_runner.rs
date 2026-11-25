//! Per-process OS thread Wasmtime 51 executor with asyncify (`proc_fork`, `stack_checkpoint`,
//! `stack_restore`), `execve` in-place replacement, POSIX signals, and cgroup `memory.max` limits.

use crate::errno::FD_MAX;
use crate::kernel_rpc::{
    GuestFdEntry, GuestFdKind, KernelClient, KernelCmd, LoadedImage, SpawnProcessReq,
};
use crate::signals::{
    CTRL_STOPPED, ProcessSignals, SA_NODEFER, SA_RESETHAND, SA_RESTART, SIG_CATCH, SIG_DFL,
    SIG_IGN, SignalControl, SignalSnapshot, bit, is_ignored_by_default, is_stopped_by_default,
};
use abi::Errno;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use wasmtime::{
    AsContext, AsContextMut, Config, Engine, Extern, ExternType, Global, Instance, Linker, Memory,
    MemoryType, Module, Mutability, Ref, ResourceLimiter, SharedMemory, Store, Table, TypedFunc,
    Val,
};

pub const WASM_PAGE_BYTES: usize = 65_536;
pub const ASYNCIFY_BUFFER_PAGES: u32 = 4;

/// Shared Wasmtime 51 engine + compiled module cache across all guest OS processes.
pub struct WasmRuntime {
    pub engine: Engine,
    modules: Mutex<HashMap<String, Module>>,
}

impl WasmRuntime {
    /// Return a process-wide shared `WasmRuntime` caching immutable compiled `Module`s by SHA-256.
    pub fn shared() -> Result<Arc<Self>, String> {
        static SHARED: OnceLock<Arc<WasmRuntime>> = OnceLock::new();
        if let Some(rt) = SHARED.get() {
            return Ok(Arc::clone(rt));
        }
        let created = Self::new()?;
        let _ = SHARED.set(Arc::clone(&created));
        Ok(SHARED.get().map(Arc::clone).unwrap_or(created))
    }

    pub fn new() -> Result<Arc<Self>, String> {
        let mut cfg = Config::new();
        cfg.wasm_threads(true);
        cfg.shared_memory(true);
        cfg.wasm_multi_memory(true);
        cfg.wasm_bulk_memory(true);
        #[cfg(debug_assertions)]
        cfg.cranelift_opt_level(wasmtime::OptLevel::None);
        #[cfg(not(debug_assertions))]
        cfg.cranelift_opt_level(wasmtime::OptLevel::Speed);
        let engine = Engine::new(&cfg).map_err(|e| format!("wasmtime Engine::new: {e}"))?;
        Ok(Arc::new(Self {
            engine,
            modules: Mutex::new(HashMap::new()),
        }))
    }

    pub fn compile_cached(&self, key: &str, bytes: &[u8]) -> Result<Module, String> {
        if let Some(m) = self.modules.lock().unwrap().get(key) {
            return Ok(m.clone());
        }
        let module =
            Module::new(&self.engine, bytes).map_err(|e| format!("wasm compile {key}: {e}"))?;
        let mut cache = self.modules.lock().unwrap();
        Ok(cache.entry(key.to_string()).or_insert(module).clone())
    }
}

/// Unified linear memory handle supporting both standard `Memory` and WASIX `SharedMemory`.
#[derive(Clone)]
pub enum GuestMem {
    Regular(Memory),
    Shared(SharedMemory),
}

impl GuestMem {
    pub fn byte_len(&self, store: impl AsContext) -> usize {
        match self {
            Self::Regular(m) => m.data_size(store),
            Self::Shared(m) => m.data_size(),
        }
    }

    pub fn read_bytes(&self, store: impl AsContext, ptr: u32, len: u32) -> Result<Vec<u8>, Errno> {
        let start = ptr as usize;
        let end = start.checked_add(len as usize).ok_or(Errno::EINVAL)?;
        match self {
            Self::Regular(m) => {
                let data = m.data(&store);
                if end > data.len() {
                    return Err(Errno::EINVAL);
                }
                Ok(data[start..end].to_vec())
            }
            Self::Shared(m) => {
                let cells = m.data();
                if end > cells.len() {
                    return Err(Errno::EINVAL);
                }
                let mut out = vec![0u8; len as usize];
                for (dst, cell) in out.iter_mut().zip(&cells[start..end]) {
                    // SAFETY: single guest thread owns this process's Wasm store; shared memory is
                    // used strictly to satisfy WASIX `dash.wasm` imported memory type.
                    *dst = unsafe { *cell.get() };
                }
                Ok(out)
            }
        }
    }

    pub fn write_bytes(
        &self,
        mut store: impl AsContextMut,
        ptr: u32,
        src: &[u8],
    ) -> Result<(), Errno> {
        let start = ptr as usize;
        let end = start.checked_add(src.len()).ok_or(Errno::EINVAL)?;
        match self {
            Self::Regular(m) => {
                let data = m.data_mut(&mut store);
                if end > data.len() {
                    return Err(Errno::EINVAL);
                }
                data[start..end].copy_from_slice(src);
                Ok(())
            }
            Self::Shared(m) => {
                let cells = m.data();
                if end > cells.len() {
                    return Err(Errno::EINVAL);
                }
                for (cell, &byte) in cells[start..end].iter().zip(src.iter()) {
                    // SAFETY: see `read_bytes`.
                    unsafe { *cell.get() = byte };
                }
                Ok(())
            }
        }
    }

    pub fn read_str(&self, store: impl AsContext, ptr: u32, len: u32) -> Result<String, Errno> {
        let bytes = self.read_bytes(store, ptr, len)?;
        String::from_utf8(bytes).map_err(|_| Errno::EINVAL)
    }

    pub fn read_u32(&self, store: impl AsContext, ptr: u32) -> Result<u32, Errno> {
        let b = self.read_bytes(store, ptr, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn write_u32(&self, store: impl AsContextMut, ptr: u32, val: u32) -> Result<(), Errno> {
        self.write_bytes(store, ptr, &val.to_le_bytes())
    }

    pub fn read_i32(&self, store: impl AsContext, ptr: u32) -> Result<i32, Errno> {
        Ok(self.read_u32(store, ptr)? as i32)
    }

    pub fn write_i32(&self, store: impl AsContextMut, ptr: u32, val: i32) -> Result<(), Errno> {
        self.write_bytes(store, ptr, &val.to_le_bytes())
    }

    pub fn read_u16(&self, store: impl AsContext, ptr: u32) -> Result<u16, Errno> {
        let b = self.read_bytes(store, ptr, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn write_u16(&self, store: impl AsContextMut, ptr: u32, val: u16) -> Result<(), Errno> {
        self.write_bytes(store, ptr, &val.to_le_bytes())
    }

    pub fn read_u8(&self, store: impl AsContext, ptr: u32) -> Result<u8, Errno> {
        let b = self.read_bytes(store, ptr, 1)?;
        Ok(b[0])
    }

    pub fn write_u8(&self, store: impl AsContextMut, ptr: u32, val: u8) -> Result<(), Errno> {
        self.write_bytes(store, ptr, &[val])
    }

    pub fn read_u64(&self, store: impl AsContext, ptr: u32) -> Result<u64, Errno> {
        let b = self.read_bytes(store, ptr, 8)?;
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    pub fn write_u64(&self, store: impl AsContextMut, ptr: u32, val: u64) -> Result<(), Errno> {
        self.write_bytes(store, ptr, &val.to_le_bytes())
    }

    pub fn read_i64(&self, store: impl AsContext, ptr: u32) -> Result<i64, Errno> {
        Ok(self.read_u64(store, ptr)? as i64)
    }

    pub fn snapshot_all(&self, store: impl AsContext) -> Vec<u8> {
        let len = self.byte_len(&store);
        self.read_bytes(&store, 0, len as u32).unwrap_or_default()
    }

    pub fn restore_all(&self, mut store: impl AsContextMut, bytes: &[u8]) -> Result<(), String> {
        let cur = self.byte_len(&store);
        if bytes.len() > cur {
            let need_pages = (bytes.len() - cur).div_ceil(WASM_PAGE_BYTES) as u64;
            match self {
                Self::Regular(m) => {
                    m.grow(&mut store, need_pages)
                        .map_err(|e| format!("grow regular mem: {e}"))?;
                }
                Self::Shared(m) => {
                    m.grow(need_pages)
                        .map_err(|e| format!("grow shared mem: {e}"))?;
                }
            }
        }
        self.write_bytes(&mut store, 0, bytes)
            .map_err(|e| format!("restore mem bytes: {e:?}"))
    }
}

/// Cgroup `memory.max` + linear memory reservation limiter wired to Wasmtime `Store::limiter`.
pub struct StoreMemoryLimiter {
    pub limit_bytes: Option<usize>,
    pub linear_bytes: u64,
    pub grow_reserved: u64,
}

impl ResourceLimiter for StoreMemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if let Some(max) = maximum
            && desired > max
        {
            return Ok(false);
        }
        if let Some(lim) = self.limit_bytes
            && desired > lim
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if let Some(max) = maximum
            && desired > max
        {
            return Ok(false);
        }
        Ok(desired <= 1_000_000)
    }
}

/// Host trap error used to unwind Wasm execution on `proc_exit`, fatal signal, `execve`, or `SignalJump`.
#[derive(Debug)]
pub enum GuestControlFlow {
    Exit { code: i32, signal: Option<u8> },
    ExecReplaced(Box<LoadedImage>),
    SignalJump { snapshot_ptr: u32, value: u64 },
}

impl std::fmt::Display for GuestControlFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exit { code, signal } => write!(f, "exit(code={code}, signal={signal:?})"),
            Self::ExecReplaced(img) => write!(f, "exec({})", img.resolved_path),
            Self::SignalJump { .. } => write!(f, "signal_jump"),
        }
    }
}

impl std::error::Error for GuestControlFlow {}

#[derive(Clone, Debug)]
pub enum AsyncifyPending {
    Fork,
    Checkpoint { snapshot_ptr: u32, sp: Option<i32> },
    Restore { snapshot_ptr: u32, value: u64 },
}

#[derive(Clone, Debug)]
pub enum AsyncifyAnswer {
    Fork { pid: u32, errno: u32 },
    Value(u64),
}

#[derive(Clone, Debug)]
pub struct SavedStack {
    pub id: u64,
    pub stack: Vec<u8>,
    pub sp: Option<i32>,
}

#[derive(Clone, Debug)]
pub enum SavedGlobal {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
}

/// Complete Wasm instance snapshot captured on `proc_fork` (matches `web/wasi/fork.js`).
#[derive(Clone)]
pub struct ForkSnapshot {
    pub main_memory: Vec<u8>,
    pub extra_memories: HashMap<String, Vec<u8>>,
    pub globals: HashMap<String, SavedGlobal>,
    pub tables: HashMap<String, Vec<i32>>,
    pub region_end: u32,
    pub stack_top: Option<i32>,
    pub initializing: bool,
    pub snapshots: HashMap<u32, SavedStack>,
    pub next_snapshot_id: u64,
    pub signals: SignalSnapshot,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub umask: u16,
    pub image: LoadedImage,
}

#[derive(Default)]
pub struct AsyncifyState {
    pub able: bool,
    pub region_at: u32,
    pub region_end: u32,
    pub stack_top: Option<i32>,
    pub pending: Option<AsyncifyPending>,
    pub answer: Option<AsyncifyAnswer>,
    pub initializing: bool,
    pub start_unwind: Option<TypedFunc<i32, ()>>,
    pub stop_unwind: Option<TypedFunc<(), ()>>,
    pub start_rewind: Option<TypedFunc<i32, ()>>,
    pub stop_rewind: Option<TypedFunc<(), ()>>,
    pub get_state: Option<TypedFunc<(), i32>>,
    pub stack_ptr_global: Option<Global>,
    pub scratch_mem: Option<Memory>,
}

/// Per-process Wasmtime `Store` host state.
pub struct ProcessHost {
    pub pid: u32,
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub umask: u16,
    pub fds: BTreeMap<u32, GuestFdEntry>,
    pub signals: ProcessSignals,
    pub sys_reply: Vec<u8>,
    pub main_mem: Option<GuestMem>,
    pub asyncify: AsyncifyState,
    pub snapshots: HashMap<u32, SavedStack>,
    pub next_snapshot_id: u64,
    pub kernel: KernelClient,
    pub runtime: Arc<WasmRuntime>,
    pub limiter: StoreMemoryLimiter,
    pub boot_instant: Instant,
    pub in_signal_dispatch: bool,
    pub sig_callback_fn: Option<TypedFunc<u32, ()>>,
    pub instance_exports: Option<Instance>,
}

impl ProcessHost {
    pub fn lowest_fd(&self, min: u32) -> Result<u32, Errno> {
        for fd in min..FD_MAX {
            if !self.fds.contains_key(&fd) {
                return Ok(fd);
            }
        }
        Err(Errno::EMFILE)
    }

    pub fn lowest_fd_pair(&self) -> Result<(u32, u32), Errno> {
        let a = self.lowest_fd(0)?;
        let b = self.lowest_fd(a + 1)?;
        Ok((a, b))
    }

    pub fn mem(&self) -> Result<GuestMem, Errno> {
        self.main_mem.clone().ok_or(Errno::EIO)
    }

    pub fn close_guest_fd(&mut self, fd: u32) -> Result<(), Errno> {
        let entry = self.fds.remove(&fd).ok_or(Errno::EBADF)?;
        self.drop_fd_kind(entry.kind);
        Ok(())
    }

    pub fn drop_fd_kind(&self, kind: GuestFdKind) {
        match kind {
            GuestFdKind::Kfd { kfd, .. } => {
                let _ = self.kernel.try_call_sync(|reply| KernelCmd::CloseKfd {
                    pid: self.pid,
                    kfd,
                    reply,
                });
            }
            GuestFdKind::UnixSock { sock_id, .. } => {
                let _ = self.kernel.try_call_sync(|reply| KernelCmd::SockClose {
                    pid: self.pid,
                    sock_id,
                    reply,
                });
            }
            GuestFdKind::PtyMaster { .. }
            | GuestFdKind::PtySlave { .. }
            | GuestFdKind::Pipe { .. }
            | GuestFdKind::Preopen
            | GuestFdKind::NullIn
            | GuestFdKind::HostLog { .. } => {}
        }
    }

    pub fn close_all_fds(&mut self) {
        let all: Vec<u32> = self.fds.keys().copied().collect();
        for fd in all {
            let _ = self.close_guest_fd(fd);
        }
    }

    pub fn duplicate_fd_kind(
        &self,
        kind: &GuestFdKind,
        cloexec: bool,
    ) -> Result<GuestFdKind, Errno> {
        match kind {
            GuestFdKind::Kfd {
                kfd,
                is_dir,
                path_only,
                readable,
                writable,
                append,
                nonblock,
                device,
            } => {
                let new_kfd = self.kernel.call_sync(|reply| KernelCmd::DupKfd {
                    pid: self.pid,
                    kfd: *kfd,
                    cloexec,
                    reply,
                })?;
                Ok(GuestFdKind::Kfd {
                    kfd: new_kfd,
                    is_dir: *is_dir,
                    path_only: *path_only,
                    readable: *readable,
                    writable: *writable,
                    append: *append,
                    nonblock: *nonblock,
                    device: device.clone(),
                })
            }
            GuestFdKind::UnixSock {
                sock_id,
                sock_type,
                nonblock,
            } => {
                self.kernel.call_sync(|reply| KernelCmd::SockHold {
                    pid: self.pid,
                    sock_id: *sock_id,
                    reply,
                })?;
                Ok(GuestFdKind::UnixSock {
                    sock_id: *sock_id,
                    sock_type: *sock_type,
                    nonblock: *nonblock,
                })
            }
            GuestFdKind::Pipe { handle, nonblock } => Ok(GuestFdKind::Pipe {
                handle: handle.clone(),
                nonblock: *nonblock,
            }),
            GuestFdKind::PtyMaster { pty, nonblock } => Ok(GuestFdKind::PtyMaster {
                pty: pty.clone(),
                nonblock: *nonblock,
            }),
            GuestFdKind::PtySlave {
                pty,
                readable,
                writable,
                nonblock,
            } => Ok(GuestFdKind::PtySlave {
                pty: pty.clone(),
                readable: *readable,
                writable: *writable,
                nonblock: *nonblock,
            }),
            GuestFdKind::Preopen => Ok(GuestFdKind::Preopen),
            GuestFdKind::NullIn => Ok(GuestFdKind::NullIn),
            GuestFdKind::HostLog { fd } => Ok(GuestFdKind::HostLog { fd: *fd }),
        }
    }

    pub fn guest_fd_map(&self) -> BTreeMap<u32, GuestFdKind> {
        self.fds
            .iter()
            .map(|(&fd, e)| (fd, e.kind.clone()))
            .collect()
    }
}

/// Check termination, stop (`SIGSTOP`/`SIGTSTP`), and deliver pending caught/default signals.
/// Returns `Ok(true)` if a caught signal interrupted a syscall without `SA_RESTART`.
pub fn pause_and_dispatch(
    store: &mut Store<ProcessHost>,
    interruptible: bool,
) -> Result<bool, wasmtime::Error> {
    // 1. Check SIGKILL immediately.
    if let Some(sig) = store.data().signals.ctrl.killed_signal() {
        return Err(wasmtime::Error::new(GuestControlFlow::Exit {
            code: 128 + i32::from(sig),
            signal: Some(sig),
        }));
    }

    // 2. Check SIGSTOP/SIGTSTP stop latch.
    if store.data().signals.ctrl.is_stopped() {
        let cause = store
            .data()
            .signals
            .ctrl
            .stop_cause
            .load(std::sync::atomic::Ordering::SeqCst) as u8;
        let pid = store.data().pid;
        store
            .data()
            .kernel
            .send_fire_and_forget(KernelCmd::ReportStopped { pid, signal: cause });
        while store.data().signals.ctrl.is_stopped() {
            if let Some(sig) = store.data().signals.ctrl.killed_signal() {
                return Err(wasmtime::Error::new(GuestControlFlow::Exit {
                    code: 128 + i32::from(sig),
                    signal: Some(sig),
                }));
            }
            store
                .data()
                .signals
                .ctrl
                .wait_timeout(Duration::from_millis(25));
        }
    }

    // 3. Do not dispatch signals while rewinding asyncify or already inside a signal handler.
    if store.data().in_signal_dispatch {
        return Ok(false);
    }
    if is_asyncify_rewinding(store) {
        return Ok(false);
    }

    let mut interrupted = false;
    while let Some((sig, action)) = store.data().signals.take() {
        if action.kind == SIG_IGN || (action.kind == SIG_DFL && is_ignored_by_default(sig)) {
            continue;
        }
        if action.kind == SIG_DFL {
            if sig == 18 {
                continue;
            }
            if is_stopped_by_default(sig) {
                store
                    .data()
                    .signals
                    .ctrl
                    .stop_cause
                    .store(u32::from(sig), std::sync::atomic::Ordering::SeqCst);
                store
                    .data()
                    .signals
                    .ctrl
                    .state
                    .store(CTRL_STOPPED, std::sync::atomic::Ordering::SeqCst);
                return pause_and_dispatch(store, interruptible);
            }
            return Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code: 128 + i32::from(sig),
                signal: Some(sig),
            }));
        }
        if action.kind == SIG_CATCH {
            let cb_name = store.data().signals.callback.clone();
            let cb_fn = cb_name.and_then(|name| {
                let inst = store.data().instance_exports?;
                inst.get_typed_func::<u32, ()>(&mut *store, &name).ok()
            });
            let Some(cb) = cb_fn else {
                continue;
            };
            let saved_mask = store.data().signals.mask();
            if (action.flags & SA_RESETHAND) != 0 {
                store.data_mut().signals.action(u32::from(sig), 0, 0, 0);
            }
            let next_mask = saved_mask
                | action.mask
                | if (action.flags & SA_NODEFER) != 0 {
                    0
                } else {
                    bit(sig)
                };
            store.data_mut().signals.set_mask(next_mask);
            store.data_mut().in_signal_dispatch = true;
            let call_res = cb.call(&mut *store, u32::from(sig));
            store.data_mut().in_signal_dispatch = false;
            store.data_mut().signals.set_mask(saved_mask);

            call_res?;
            if let Some(pending) = check_asyncify_unwound(store) {
                match pending {
                    AsyncifyPending::Restore {
                        snapshot_ptr,
                        value,
                    } => {
                        return Err(wasmtime::Error::new(GuestControlFlow::SignalJump {
                            snapshot_ptr,
                            value,
                        }));
                    }
                    _ => {
                        return Err(wasmtime::Error::msg(
                            "unsupported asyncify op inside signal handler",
                        ));
                    }
                }
            }
            store.data_mut().signals.delivered_count += 1;
            if (action.flags & SA_RESTART) == 0 {
                interrupted = true;
            }
        }
    }
    Ok(interruptible && interrupted)
}

pub fn is_asyncify_rewinding(store: &mut Store<ProcessHost>) -> bool {
    let Some(get_state) = store.data().asyncify.get_state.clone() else {
        return false;
    };
    get_state.call(&mut *store, ()).unwrap_or(0) == 2
}

pub fn asyncify_start_unwind(
    store: &mut Store<ProcessHost>,
    pending: AsyncifyPending,
) -> Result<(), Errno> {
    if !store.data().asyncify.able {
        return Err(Errno::ENOSYS);
    }
    let at = store.data().asyncify.region_at;
    let end = store.data().asyncify.region_end;
    let scratch = store.data().asyncify.scratch_mem.ok_or(Errno::ENOSYS)?;
    {
        let data = scratch.data_mut(&mut *store);
        let a = at as usize;
        if a + 8 > data.len() {
            return Err(Errno::ENOSPC);
        }
        data[a..a + 4].copy_from_slice(&(at + 8).to_le_bytes());
        data[a + 4..a + 8].copy_from_slice(&end.to_le_bytes());
    }
    store.data_mut().asyncify.pending = Some(pending);
    let start_fn = store
        .data()
        .asyncify
        .start_unwind
        .clone()
        .ok_or(Errno::ENOSYS)?;
    start_fn
        .call(&mut *store, at as i32)
        .map_err(|_| Errno::EIO)?;
    Ok(())
}

pub fn asyncify_resume(store: &mut Store<ProcessHost>) -> Option<AsyncifyAnswer> {
    if let Some(stop) = store.data().asyncify.stop_rewind.clone() {
        let _ = stop.call(&mut *store, ());
    }
    store.data_mut().asyncify.answer.take()
}

fn check_asyncify_unwound(store: &mut Store<ProcessHost>) -> Option<AsyncifyPending> {
    let get_state = store.data().asyncify.get_state.clone()?;
    let state = get_state.call(&mut *store, ()).unwrap_or(0);
    if state != 1 {
        return None;
    }
    if let Some(stop) = store.data().asyncify.stop_unwind.clone() {
        let _ = stop.call(&mut *store, ());
    }
    store.data_mut().asyncify.pending.take()
}

fn asyncify_read_saved_stack(store: &Store<ProcessHost>) -> Vec<u8> {
    let Some(scratch) = store.data().asyncify.scratch_mem else {
        return Vec::new();
    };
    let at = store.data().asyncify.region_at as usize;
    let data = scratch.data(store);
    if at + 8 > data.len() {
        return Vec::new();
    }
    let cur_end = u32::from_le_bytes(data[at..at + 4].try_into().unwrap()) as usize;
    let start = at + 8;
    if cur_end <= start || cur_end > data.len() {
        return Vec::new();
    }
    data[start..cur_end].to_vec()
}

fn asyncify_start_rewind(
    store: &mut Store<ProcessHost>,
    answer: AsyncifyAnswer,
    saved_stack: Option<&[u8]>,
) -> Result<(), String> {
    let at = store.data().asyncify.region_at;
    let end = store.data().asyncify.region_end;
    let scratch = store
        .data()
        .asyncify
        .scratch_mem
        .ok_or("missing asyncify scratch memory")?;
    {
        let data = scratch.data_mut(&mut *store);
        let a = at as usize;
        if let Some(stack) = saved_stack {
            let start = a + 8;
            let stop = start + stack.len();
            if stop > data.len() {
                return Err("asyncify saved stack exceeds scratch memory".into());
            }
            data[start..stop].copy_from_slice(stack);
            data[a..a + 4].copy_from_slice(&(stop as u32).to_le_bytes());
        }
        data[a + 4..a + 8].copy_from_slice(&end.to_le_bytes());
    }
    store.data_mut().asyncify.answer = Some(answer);
    let rewind = store
        .data()
        .asyncify
        .start_rewind
        .clone()
        .ok_or("missing asyncify_start_rewind")?;
    rewind
        .call(&mut *store, at as i32)
        .map_err(|e| format!("asyncify_start_rewind: {e}"))
}

fn capture_fork_snapshot(
    store: &mut Store<ProcessHost>,
    instance: &Instance,
    image: &LoadedImage,
) -> Result<ForkSnapshot, String> {
    let main_mem = store.data().mem().map_err(|e| format!("no mem: {e:?}"))?;
    let main_bytes = main_mem.snapshot_all(&*store);

    // Collect all exported names & externs first.
    let export_names: Vec<String> = instance
        .exports(&mut *store)
        .map(|e| e.name().to_string())
        .collect();

    let mut extra_memories = HashMap::new();
    let mut globals = HashMap::new();
    let mut tables = HashMap::new();

    // Build function -> index map from `__tw_functions` table if present.
    let mut func_to_idx: HashMap<usize, i32> = HashMap::new();
    if let Some(Extern::Table(ftbl)) = instance.get_export(&mut *store, "__tw_functions") {
        let len = ftbl.size(&*store);
        for i in 0..len {
            if let Some(Ref::Func(Some(f))) = ftbl.get(&mut *store, i) {
                let raw = f.to_raw(&mut *store) as usize;
                func_to_idx.insert(raw, i as i32);
            }
        }
    }

    for name in export_names {
        let Some(ext) = instance.get_export(&mut *store, &name) else {
            continue;
        };
        match ext {
            Extern::Memory(m) => {
                if name != "memory" {
                    let bytes = m.data(&*store).to_vec();
                    extra_memories.insert(name, bytes);
                }
            }
            Extern::Global(g) => {
                if g.ty(&*store).mutability() == Mutability::Var {
                    let val = g.get(&mut *store);
                    let saved = match val {
                        Val::I32(v) => Some(SavedGlobal::I32(v)),
                        Val::I64(v) => Some(SavedGlobal::I64(v)),
                        Val::F32(v) => Some(SavedGlobal::F32(v)),
                        Val::F64(v) => Some(SavedGlobal::F64(v)),
                        _ => None,
                    };
                    if let Some(s) = saved {
                        globals.insert(name, s);
                    }
                }
            }
            Extern::Table(t) if name != "__tw_functions" => {
                let len = t.size(&*store);
                let mut entries = Vec::with_capacity(len as usize);
                for i in 0..len {
                    let idx = match t.get(&mut *store, i) {
                        Some(Ref::Func(None)) | None => -1,
                        Some(Ref::Func(Some(f))) => {
                            let raw = f.to_raw(&mut *store) as usize;
                            *func_to_idx.get(&raw).unwrap_or(&-2)
                        }
                        _ => -2,
                    };
                    entries.push(idx);
                }
                tables.insert(name, entries);
            }
            _ => {}
        }
    }

    Ok(ForkSnapshot {
        main_memory: main_bytes,
        extra_memories,
        globals,
        tables,
        region_end: store.data().asyncify.region_end,
        stack_top: store.data().asyncify.stack_top,
        initializing: store.data().asyncify.initializing,
        snapshots: store.data().snapshots.clone(),
        next_snapshot_id: store.data().next_snapshot_id,
        signals: store.data().signals.snapshot(),
        argv: store.data().argv.clone(),
        env: store.data().env.clone(),
        umask: store.data().umask,
        image: image.clone(),
    })
}

fn restore_fork_snapshot(
    store: &mut Store<ProcessHost>,
    instance: &Instance,
    snap: &ForkSnapshot,
) -> Result<(), String> {
    let main_mem = store.data().mem().map_err(|e| format!("no mem: {e:?}"))?;
    main_mem.restore_all(&mut *store, &snap.main_memory)?;

    for (name, bytes) in &snap.extra_memories {
        if let Some(Extern::Memory(m)) = instance.get_export(&mut *store, name) {
            let cur = m.data_size(&*store);
            if bytes.len() > cur {
                let pages = (bytes.len() - cur).div_ceil(WASM_PAGE_BYTES) as u64;
                m.grow(&mut *store, pages)
                    .map_err(|e| format!("grow extra mem {name}: {e}"))?;
            }
            m.data_mut(&mut *store)[..bytes.len()].copy_from_slice(bytes);
        }
    }

    for (name, saved) in &snap.globals {
        if let Some(Extern::Global(g)) = instance.get_export(&mut *store, name)
            && g.ty(&*store).mutability() == Mutability::Var
        {
            let v = match *saved {
                SavedGlobal::I32(x) => Val::I32(x),
                SavedGlobal::I64(x) => Val::I64(x),
                SavedGlobal::F32(x) => Val::F32(x),
                SavedGlobal::F64(x) => Val::F64(x),
            };
            let _ = g.set(&mut *store, v);
        }
    }

    let funcs_table: Option<Table> = match instance.get_export(&mut *store, "__tw_functions") {
        Some(Extern::Table(t)) => Some(t),
        _ => None,
    };
    if let Some(ftbl) = funcs_table {
        for (name, entries) in &snap.tables {
            if let Some(Extern::Table(t)) = instance.get_export(&mut *store, name) {
                let cur = t.size(&*store) as usize;
                if entries.len() > cur {
                    let _ = t.grow(&mut *store, (entries.len() - cur) as u64, Ref::Func(None));
                }
                for (i, &fn_idx) in entries.iter().enumerate() {
                    if fn_idx == -2 {
                        continue;
                    }
                    let val = if fn_idx == -1 {
                        Ref::Func(None)
                    } else {
                        ftbl.get(&mut *store, fn_idx as u64)
                            .unwrap_or(Ref::Func(None))
                    };
                    let _ = t.set(&mut *store, i as u64, val);
                }
            }
        }
    }

    store.data_mut().asyncify.region_at = 0;
    store.data_mut().asyncify.region_end = snap.region_end;
    store.data_mut().asyncify.stack_top = snap.stack_top;
    store.data_mut().asyncify.initializing = snap.initializing;
    store.data_mut().snapshots = snap.snapshots.clone();
    store.data_mut().next_snapshot_id = snap.next_snapshot_id;
    Ok(())
}

/// Instantiate `image` into `store`, satisfying `env::memory` (shared or regular) when imported.
fn instantiate_image(
    store: &mut Store<ProcessHost>,
    runtime: &WasmRuntime,
    image: &LoadedImage,
    fork_snap: Option<&ForkSnapshot>,
) -> Result<Instance, String> {
    let cache_key = if image.is_rv1 {
        format!("{}:rv1", image.raw_sha256)
    } else {
        image.raw_sha256.clone()
    };
    let module = runtime.compile_cached(&cache_key, &image.wasm_bytes)?;

    let mut linker: Linker<ProcessHost> = Linker::new(&runtime.engine);
    linker.allow_shadowing(true);
    crate::wasi_host::register_all(&mut linker)
        .map_err(|e| format!("register host imports: {e}"))?;

    // Check if the module imports `env::memory` (e.g. WASIX `dash.wasm.rv1`).
    let mut imported_mem: Option<GuestMem> = None;
    for imp in module.imports() {
        if imp.module() == "env"
            && imp.name() == "memory"
            && let ExternType::Memory(mut mem_ty) = imp.ty()
        {
            if let Some(snap) = fork_snap {
                let min_pages = (snap.main_memory.len() / WASM_PAGE_BYTES) as u64;
                if min_pages > mem_ty.minimum() {
                    mem_ty = if mem_ty.is_shared() {
                        MemoryType::shared(
                            min_pages as u32,
                            mem_ty.maximum().unwrap_or(65536) as u32,
                        )
                        .map_err(|e| format!("MemoryType::shared: {e}"))?
                    } else {
                        MemoryType::new(min_pages as u32, mem_ty.maximum().map(|m| m as u32))
                            .map_err(|e| format!("MemoryType::new: {e}"))?
                    };
                }
            }
            if mem_ty.is_shared() {
                let sm = SharedMemory::new(&runtime.engine, mem_ty)
                    .map_err(|e| format!("SharedMemory::new: {e}"))?;
                linker
                    .define(&*store, "env", "memory", sm.clone())
                    .map_err(|e| format!("define env::memory: {e}"))?;
                imported_mem = Some(GuestMem::Shared(sm));
            } else {
                let m =
                    Memory::new(&mut *store, mem_ty).map_err(|e| format!("Memory::new: {e}"))?;
                linker
                    .define(&*store, "env", "memory", m)
                    .map_err(|e| format!("define env::memory: {e}"))?;
                imported_mem = Some(GuestMem::Regular(m));
            }
        }
    }

    let instance = linker
        .instantiate(&mut *store, &module)
        .map_err(|e| format!("instantiate {}: {e}", image.resolved_path))?;

    let main_mem = if let Some(m) = imported_mem {
        m
    } else if let Some(m) = instance.get_memory(&mut *store, "memory") {
        GuestMem::Regular(m)
    } else {
        return Err(format!("{} exports no memory", image.resolved_path));
    };

    // Reserve initial linear memory against cgroup `memory.max`.
    let initial_bytes = main_mem.byte_len(&*store) as u64;
    let pid = store.data().pid;
    if let Some(Err(e)) = store
        .data()
        .kernel
        .try_call_sync(|reply| KernelCmd::ReserveMemory {
            pid,
            bytes: initial_bytes,
            reply,
        })
    {
        return Err(format!(
            "cgroup memory.max exceeded on {} ({initial_bytes} bytes): {e:?}",
            image.resolved_path
        ));
    }
    store.data_mut().limiter.linear_bytes = initial_bytes;
    store.data_mut().main_mem = Some(main_mem);
    store.data_mut().instance_exports = Some(instance);

    // Wire asyncify exports if present (`.rv1` transformed modules like `dash.wasm.rv1`).
    let start_unwind = instance
        .get_typed_func::<i32, ()>(&mut *store, "asyncify_start_unwind")
        .ok();
    let stop_unwind = instance
        .get_typed_func::<(), ()>(&mut *store, "asyncify_stop_unwind")
        .ok();
    let start_rewind = instance
        .get_typed_func::<i32, ()>(&mut *store, "asyncify_start_rewind")
        .ok();
    let stop_rewind = instance
        .get_typed_func::<(), ()>(&mut *store, "asyncify_stop_rewind")
        .ok();
    let get_state = instance
        .get_typed_func::<(), i32>(&mut *store, "asyncify_get_state")
        .ok();
    let scratch_mem = instance.get_memory(&mut *store, "__tw_asyncify_memory");
    let stack_ptr_global = instance
        .get_global(&mut *store, "__stack_pointer")
        .or_else(|| instance.get_global(&mut *store, "__tw_stack_pointer"));
    let stack_top = stack_ptr_global.and_then(|g| g.get(&mut *store).i32());
    let has_tw_init = instance
        .get_typed_func::<(), ()>(&mut *store, "__tw_initialize")
        .is_ok();

    let able = start_unwind.is_some()
        && stop_unwind.is_some()
        && start_rewind.is_some()
        && stop_rewind.is_some()
        && get_state.is_some()
        && scratch_mem.is_some();

    store.data_mut().asyncify = AsyncifyState {
        able,
        region_at: 0,
        region_end: ASYNCIFY_BUFFER_PAGES * (WASM_PAGE_BYTES as u32),
        stack_top,
        pending: None,
        answer: None,
        initializing: has_tw_init,
        start_unwind,
        stop_unwind,
        start_rewind,
        stop_rewind,
        get_state,
        stack_ptr_global,
        scratch_mem,
    };

    if let Some(snap) = fork_snap {
        restore_fork_snapshot(store, &instance, snap)?;
    }

    Ok(instance)
}

/// Spawn a new OS thread running a freshly spawned Wasm process (or PID 1).
#[allow(clippy::too_many_arguments)]
pub fn spawn_process_thread(
    pid: u32,
    sig_ctrl: Arc<SignalControl>,
    fds: BTreeMap<u32, GuestFdEntry>,
    image: LoadedImage,
    umask: u16,
    sig_snap: Option<SignalSnapshot>,
    kernel: KernelClient,
    runtime: Arc<WasmRuntime>,
) {
    let name = format!("os-pid-{pid}");
    let _ = std::thread::Builder::new()
        .name(name)
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            run_process_thread(
                pid, sig_ctrl, fds, image, umask, sig_snap, None, kernel, runtime,
            );
        });
}

/// Spawn a new OS thread running a forked child Wasm process from `ForkSnapshot`.
pub fn spawn_forked_child_thread(
    pid: u32,
    sig_ctrl: Arc<SignalControl>,
    fds: BTreeMap<u32, GuestFdEntry>,
    snapshot: ForkSnapshot,
    kernel: KernelClient,
    runtime: Arc<WasmRuntime>,
) {
    let image = snapshot.image.clone();
    let umask = snapshot.umask;
    let sig_snap = Some(snapshot.signals.clone());
    let name = format!("os-pid-{pid}");
    let _ = std::thread::Builder::new()
        .name(name)
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            run_process_thread(
                pid,
                sig_ctrl,
                fds,
                image,
                umask,
                sig_snap,
                Some(snapshot),
                kernel,
                runtime,
            );
        });
}

/// Helper used by host/tests/seat server to spawn a process via `KernelCmd::PrepareSpawn` + thread.
pub fn spawn_and_launch(
    kernel: &KernelClient,
    runtime: &Arc<WasmRuntime>,
    req: SpawnProcessReq,
) -> Result<u32, Errno> {
    let umask = req.umask;
    let sig_snap = req.signals.clone();
    let (pid, ctrl, fds, image) = kernel.call_sync(|reply| KernelCmd::PrepareSpawn {
        req: Box::new(req),
        reply,
    })?;
    spawn_process_thread(
        pid,
        ctrl,
        fds,
        image,
        umask,
        sig_snap,
        kernel.clone(),
        Arc::clone(runtime),
    );
    Ok(pid)
}

#[allow(clippy::too_many_arguments)]
fn run_process_thread(
    pid: u32,
    sig_ctrl: Arc<SignalControl>,
    mut fds: BTreeMap<u32, GuestFdEntry>,
    mut image: LoadedImage,
    umask: u16,
    sig_snap: Option<SignalSnapshot>,
    mut fork_snap: Option<ForkSnapshot>,
    kernel: KernelClient,
    runtime: Arc<WasmRuntime>,
) {
    // Ensure a preopen root fd (fd 3) exists if not already populated (matches `web/wasi/process.js`).
    if fork_snap.is_none() && !fds.values().any(|e| matches!(e.kind, GuestFdKind::Preopen)) {
        for cand in 3..FD_MAX {
            if let std::collections::btree_map::Entry::Vacant(e) = fds.entry(cand) {
                e.insert(GuestFdEntry {
                    kind: GuestFdKind::Preopen,
                    cloexec: false,
                });
                break;
            }
        }
    }

    let is_fork = fork_snap.is_some();
    let signals = ProcessSignals::new(sig_ctrl, sig_snap, !is_fork);

    let host = ProcessHost {
        pid,
        argv: image.argv.clone(),
        env: image.env.clone(),
        umask,
        fds,
        signals,
        sys_reply: Vec::new(),
        main_mem: None,
        asyncify: AsyncifyState::default(),
        snapshots: HashMap::new(),
        next_snapshot_id: 1,
        kernel: kernel.clone(),
        runtime: Arc::clone(&runtime),
        limiter: StoreMemoryLimiter {
            limit_bytes: image.memory_limit_bytes.map(|b| b as usize),
            linear_bytes: 0,
            grow_reserved: 0,
        },
        boot_instant: Instant::now(),
        in_signal_dispatch: false,
        sig_callback_fn: None,
        instance_exports: None,
    };

    let mut store = Store::new(&runtime.engine, host);
    store.limiter(|h| &mut h.limiter);

    let (exit_code, exit_sig) = 'exec_loop: loop {
        let instance = match instantiate_image(&mut store, &runtime, &image, fork_snap.as_ref()) {
            Ok(inst) => inst,
            Err(err) => {
                write_stderr_diag(&store, &format!("{}: {err}\n", image.resolved_path));
                break 'exec_loop (126, None);
            }
        };

        if fork_snap.take().is_some()
            && let Err(err) =
                asyncify_start_rewind(&mut store, AsyncifyAnswer::Fork { pid: 0, errno: 0 }, None)
        {
            write_stderr_diag(&store, &format!("fork child rewind failed: {err}\n"));
            break 'exec_loop (128 + 6, Some(6));
        }

        // Main asyncify execution loop (mirrors `web/wasi/process.js:run()`).
        loop {
            let entry_name = if store.data().asyncify.initializing {
                "__tw_initialize"
            } else {
                "_start"
            };
            let entry_fn = match instance.get_typed_func::<(), ()>(&mut store, entry_name) {
                Ok(f) => f,
                Err(_) => break 'exec_loop (0, None),
            };

            let call_res = entry_fn.call(&mut store, ());
            let pending = match call_res {
                Ok(()) => check_asyncify_unwound(&mut store),
                Err(err) => {
                    if let Some(cf) = err.downcast_ref::<GuestControlFlow>() {
                        match cf {
                            GuestControlFlow::Exit { code, signal } => {
                                break 'exec_loop (*code, *signal);
                            }
                            GuestControlFlow::ExecReplaced(next_img) => {
                                // Apply CLOEXEC on guest fds, reset signal handlers, reload image!
                                let cloexec_fds: Vec<u32> = store
                                    .data()
                                    .fds
                                    .iter()
                                    .filter_map(|(&fd, e)| e.cloexec.then_some(fd))
                                    .collect();
                                for fd in cloexec_fds {
                                    // Note: kernel kfds were already closed by `vfs.exec_preserve`.
                                    if let Some(entry) = store.data_mut().fds.remove(&fd)
                                        && !matches!(entry.kind, GuestFdKind::Kfd { .. })
                                    {
                                        store.data().drop_fd_kind(entry.kind);
                                    }
                                }
                                store.data_mut().argv = next_img.argv.clone();
                                store.data_mut().env = next_img.env.clone();
                                store.data_mut().snapshots.clear();
                                store.data_mut().sys_reply.clear();
                                store.data_mut().signals.on_exec();
                                store.data_mut().limiter.limit_bytes =
                                    next_img.memory_limit_bytes.map(|b| b as usize);
                                image = (**next_img).clone();
                                continue 'exec_loop;
                            }
                            GuestControlFlow::SignalJump {
                                snapshot_ptr,
                                value,
                            } => Some(AsyncifyPending::Restore {
                                snapshot_ptr: *snapshot_ptr,
                                value: *value,
                            }),
                        }
                    } else {
                        write_stderr_diag(
                            &store,
                            &format!("{}: trap: {err}\n", image.resolved_path),
                        );
                        break 'exec_loop (128 + 6, Some(6));
                    }
                }
            };

            let Some(pending) = pending else {
                if store.data().asyncify.initializing {
                    store.data_mut().asyncify.initializing = false;
                    let sp = store
                        .data()
                        .asyncify
                        .stack_ptr_global
                        .and_then(|g| g.get(&mut store).i32());
                    store.data_mut().asyncify.stack_top = sp;
                    continue;
                }
                break 'exec_loop (0, None);
            };

            match pending {
                AsyncifyPending::Fork => {
                    let snap = match capture_fork_snapshot(&mut store, &instance, &image) {
                        Ok(s) => s,
                        Err(_) => {
                            let _ = asyncify_start_rewind(
                                &mut store,
                                AsyncifyAnswer::Fork {
                                    pid: 0,
                                    errno: crate::errno::WASI_ENOMEM,
                                },
                                None,
                            );
                            continue;
                        }
                    };
                    let parent_fds = store.data().fds.clone();
                    match store
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::PrepareFork {
                            parent_pid: pid,
                            fds: parent_fds,
                            reply,
                        }) {
                        Ok((child_pid, child_ctrl, child_fds)) => {
                            spawn_forked_child_thread(
                                child_pid,
                                child_ctrl,
                                child_fds,
                                snap,
                                kernel.clone(),
                                Arc::clone(&runtime),
                            );
                            if asyncify_start_rewind(
                                &mut store,
                                AsyncifyAnswer::Fork {
                                    pid: child_pid,
                                    errno: 0,
                                },
                                None,
                            )
                            .is_err()
                            {
                                break 'exec_loop (128 + 6, Some(6));
                            }
                        }
                        Err(e) => {
                            if asyncify_start_rewind(
                                &mut store,
                                AsyncifyAnswer::Fork {
                                    pid: 0,
                                    errno: crate::errno::abi_to_wasi(e),
                                },
                                None,
                            )
                            .is_err()
                            {
                                break 'exec_loop (128 + 6, Some(6));
                            }
                        }
                    }
                }
                AsyncifyPending::Checkpoint { snapshot_ptr, sp } => {
                    let stack = asyncify_read_saved_stack(&store);
                    let id = store.data().next_snapshot_id;
                    store.data_mut().next_snapshot_id += 1;
                    store
                        .data_mut()
                        .snapshots
                        .insert(snapshot_ptr, SavedStack { id, stack, sp });
                    if let Ok(mem) = store.data().mem() {
                        let _ = mem.write_u64(&mut store, snapshot_ptr, id);
                        let _ = mem.write_bytes(&mut store, snapshot_ptr + 8, &[0u8; 16]);
                    }
                    if asyncify_start_rewind(&mut store, AsyncifyAnswer::Value(0), None).is_err() {
                        break 'exec_loop (128 + 6, Some(6));
                    }
                }
                AsyncifyPending::Restore {
                    snapshot_ptr,
                    value,
                } => {
                    let saved = store.data().snapshots.get(&snapshot_ptr).cloned();
                    let Some(saved) = saved else {
                        break 'exec_loop (128 + 6, Some(6));
                    };
                    if let Some(sp) = saved.sp
                        && let Some(g) = store.data().asyncify.stack_ptr_global
                    {
                        let _ = g.set(&mut store, Val::I32(sp));
                    }
                    if asyncify_start_rewind(
                        &mut store,
                        AsyncifyAnswer::Value(value),
                        Some(&saved.stack),
                    )
                    .is_err()
                    {
                        break 'exec_loop (128 + 6, Some(6));
                    }
                }
            }
        }
    };

    // Cleanly release all guest descriptors and notify Kernel Actor of exit.
    store.data_mut().close_all_fds();
    let _ = kernel.try_call_sync(|reply| KernelCmd::ProcessExited {
        pid,
        code: exit_code,
        signal: exit_sig,
        reply,
    });
}

fn write_stderr_diag(store: &Store<ProcessHost>, msg: &str) {
    if let Some(entry) = store.data().fds.get(&2) {
        match &entry.kind {
            GuestFdKind::PtySlave { pty, .. } => {
                let _ = pty.write_from_slave(msg.as_bytes());
            }
            GuestFdKind::Pipe { handle, .. } if handle.is_writer => {
                let _ = handle.buf.write(msg.as_bytes(), true, || Ok(()));
            }
            GuestFdKind::HostLog { .. } => {
                eprint!("{msg}");
            }
            _ => {}
        }
    }
}
