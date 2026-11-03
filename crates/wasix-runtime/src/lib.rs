//! The WASIX runtime host, in Rust. The browser engine instantiates the guest; this crate owns
//! the syscall state, the fd table, the merge of `wasix_32v1` into the kernel's calls, and (in
//! progress) the asyncify checkpoint/restore/fork engine. The JS bridge (`web/kernel/host.js`)
//! only creates Workers/instances and moves bytes; it holds no policy.
use std::collections::BTreeMap;

use wasm_bindgen::prelude::*;

/// WASI/WASIX errno values used by the Phase 0 subset.
const SUCCESS: u16 = 0;
const BADF: u16 = 8;
const FAULT: u16 = 21;
const INVAL: u16 = 28;
const NOENT: u16 = 44;
const NOSYS: u16 = 52;
const SPIPE: u16 = 70;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["globalThis", "wasixGuest"], js_name = read)]
    fn guest_read(pid: u32, ptr: u32, len: u32) -> js_sys::Uint8Array;
    #[wasm_bindgen(js_namespace = ["globalThis", "wasixGuest"], js_name = write)]
    fn guest_write(pid: u32, ptr: u32, data: &[u8]);
    #[wasm_bindgen(js_namespace = ["globalThis", "wasixGuest"], js_name = output)]
    fn guest_output(fd: u32, data: &[u8]);
    #[wasm_bindgen(js_namespace = ["globalThis", "wasixGuest"], js_name = stackPointer)]
    fn guest_stack_pointer(pid: u32) -> u32;
    #[wasm_bindgen(js_namespace = ["globalThis", "wasixGuest"], js_name = asyncify)]
    fn guest_asyncify(pid: u32, action: &str, data: u32);
    #[wasm_bindgen(js_namespace = ["globalThis", "wasixGuest"], js_name = clone)]
    fn guest_clone(parent: u32, child: u32, stack_pointer: u32) -> u32;
}

#[derive(Debug)]
enum Outcome {
    Ready(u16),
    Exit(i32),
    Unwind,
    Resume,
    Fork(u32),
}
impl Outcome {
    fn ready(errno: u16) -> Self {
        Self::Ready(errno)
    }
    fn json(&self) -> String {
        match self {
            Self::Ready(errno) => serde_json::json!({"kind":"ready","errno":errno}).to_string(),
            Self::Exit(code) => serde_json::json!({"kind":"exit","code":code}).to_string(),
            Self::Unwind => serde_json::json!({"kind":"unwind"}).to_string(),
            Self::Resume => serde_json::json!({"kind":"resume"}).to_string(),
            Self::Fork(child) => serde_json::json!({"kind":"fork","child":child}).to_string(),
        }
    }
}

#[derive(Clone, Debug)]
enum Fd {
    Stdin,
    Stdout,
    Stderr,
    File { data: Vec<u8>, offset: usize },
    Dir,
}

#[derive(Clone)]
struct Process {
    pid: u32,
    ppid: u32,
    argv: Vec<String>,
    env: Vec<String>,
    cwd: String,
    fds: BTreeMap<u32, Fd>,
    next_fd: u32,
    stack_lower: u32,
    stack_upper: u32,
}

#[derive(Clone, Debug)]
struct Snapshot {
    unwind_stack: Vec<u8>,
}

enum Pending {
    Checkpoint { snapshot_ptr: u32 },
    Restore { snapshot: u64, value: u64 },
    Fork { stack_pointer: u32 },
}

#[wasm_bindgen]
pub struct Runtime {
    procs: BTreeMap<u32, Process>,
    files: BTreeMap<String, Vec<u8>>,
    snapshots: BTreeMap<u64, Snapshot>,
    next_snapshot: u64,
    pending: BTreeMap<u32, Pending>,
    rewind_values: BTreeMap<u32, u32>,
    next_pid: u32,
}

#[wasm_bindgen]
impl Runtime {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            procs: BTreeMap::new(),
            files: BTreeMap::new(),
            snapshots: BTreeMap::new(),
            next_snapshot: 1,
            pending: BTreeMap::new(),
            rewind_values: BTreeMap::new(),
            next_pid: 2,
        }
    }

    /// Register a process before its guest starts. Args and env arrive as JSON arrays.
    pub fn register(&mut self, pid: u32, ppid: u32, argv_json: &str, env_json: &str, cwd: &str) {
        let argv: Vec<String> = serde_json::from_str(argv_json).unwrap_or_default();
        let env: Vec<String> = serde_json::from_str(env_json).unwrap_or_default();
        let mut fds = BTreeMap::new();
        fds.insert(0, Fd::Stdin);
        fds.insert(1, Fd::Stdout);
        fds.insert(2, Fd::Stderr);
        fds.insert(3, Fd::Dir);
        self.procs.insert(
            pid,
            Process {
                pid,
                ppid,
                argv,
                env,
                cwd: cwd.to_string(),
                fds,
                next_fd: 4,
                stack_lower: 0,
                stack_upper: 0,
            },
        );
    }

    /// The guest's stack bounds, read from `__data_end` and the initial `__stack_pointer`.
    pub fn set_layout(&mut self, pid: u32, stack_lower: u32, stack_upper: u32) {
        if let Some(proc) = self.procs.get_mut(&pid) {
            proc.stack_lower = stack_lower;
            proc.stack_upper = stack_upper;
        }
    }

    /// Add a file the Phase 0 probe may open (the executable and empty profile files).
    pub fn add_file(&mut self, path: &str, bytes: &[u8]) {
        self.files.insert(clean(path), bytes.to_vec());
    }

    /// Called by the JS bridge after `_start` returns from an asyncify unwind. Captures the
    /// unwind stack, then either rewinds the same stack (checkpoint), restores a saved one, or
    /// forks. Returns the next action for the bridge.
    pub fn unwind_done(&mut self, pid: u32) -> String {
        let Some(pending) = self.pending.remove(&pid) else {
            return serde_json::json!({"kind":"none"}).to_string();
        };
        let Some((lower, upper)) = self.layout(pid) else {
            return Outcome::Exit(134).json();
        };
        let unwind_start = read_u32(pid, lower);
        let unwind_len = unwind_start.saturating_sub(lower + 8);
        let unwind_stack = mem_read(pid, lower + 8, unwind_len);
        guest_asyncify(pid, "stop_unwind", 0);
        let _ = upper;
        match pending {
            Pending::Checkpoint { snapshot_ptr } => {
                let snapshot = Snapshot {
                    unwind_stack: unwind_stack.clone(),
                };
                let id = self.next_snapshot;
                self.next_snapshot += 1;
                self.snapshots.insert(id, snapshot);
                write_bytes(pid, snapshot_ptr, &[0u8; 32]);
                write_u64(pid, snapshot_ptr, id);
                self.rewind(pid, &unwind_stack);
                self.rewind_values.insert(pid, 0);
                Outcome::Resume.json()
            }
            Pending::Restore { snapshot, value } => {
                let Some(saved) = self.snapshots.get(&snapshot).cloned() else {
                    return Outcome::Exit(0).json();
                };
                self.rewind(pid, &saved.unwind_stack);
                self.rewind_values.insert(pid, value as u32);
                Outcome::Resume.json()
            }
            Pending::Fork { stack_pointer } => {
                let child_pid = self.next_pid;
                self.next_pid += 1;
                let Some(parent) = self.procs.get(&pid).cloned() else {
                    return Outcome::Exit(134).json();
                };
                let mut child = parent;
                child.pid = child_pid;
                child.ppid = pid;
                self.procs.insert(child_pid, child);
                let child_lower = guest_clone(pid, child_pid, stack_pointer);
                if let Some(child) = self.procs.get_mut(&child_pid) {
                    child.stack_lower = child_lower;
                    child.stack_upper = stack_pointer;
                }
                self.rewind(pid, &unwind_stack);
                self.rewind_values.insert(pid, child_pid);
                self.rewind(child_pid, &unwind_stack);
                self.rewind_values.insert(child_pid, 0);
                Outcome::Fork(child_pid).json()
            }
        }
    }

    /// One `wasix_32v1` import call. The JS bridge calls this from the guest's import function and
    /// returns the resulting errno, throws on `exit`, or starts asyncify on `unwind`.
    pub fn syscall(&mut self, pid: u32, name: &str, args: &[u32]) -> String {
        let outcome = self.dispatch(pid, name, args);
        outcome.json()
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

impl Runtime {
    fn layout(&self, pid: u32) -> Option<(u32, u32)> {
        let proc = self.procs.get(&pid)?;
        (proc.stack_lower != 0 && proc.stack_upper > proc.stack_lower)
            .then_some((proc.stack_lower, proc.stack_upper))
    }

    /// The used stack, from the current `__stack_pointer` to the stack upper bound.
    fn memory_stack(&self, pid: u32) -> Option<Vec<u8>> {
        let (_, upper) = self.layout(pid)?;
        let stack_pointer = guest_stack_pointer(pid);
        if stack_pointer > upper || stack_pointer < self.procs.get(&pid)?.stack_lower {
            return None;
        }
        Some(mem_read(pid, stack_pointer, upper - stack_pointer))
    }

    fn start_unwind(&mut self, pid: u32, memory_len: u32) -> bool {
        let Some((lower, upper)) = self.layout(pid) else {
            return false;
        };
        let start = lower + 8;
        let Some(end) = upper.checked_sub(memory_len) else {
            return false;
        };
        if end < start {
            return false;
        }
        write_u32(pid, lower, start);
        write_u32(pid, lower + 4, end);
        guest_asyncify(pid, "start_unwind", lower);
        true
    }

    fn rewind(&mut self, pid: u32, unwind_stack: &[u8]) {
        let Some((lower, upper)) = self.layout(pid) else {
            return;
        };
        let start = lower + 8 + unwind_stack.len() as u32;
        if start > upper {
            return;
        }
        write_u32(pid, lower, start);
        write_u32(pid, lower + 4, upper);
        write_bytes(pid, lower + 8, unwind_stack);
        guest_asyncify(pid, "start_rewind", lower);
    }

    fn proc_fork(&mut self, pid: u32, args: &[u32]) -> Outcome {
        if let Some(value) = self.rewind_values.remove(&pid) {
            write_u32(pid, args.get(1).copied().unwrap_or(0), value);
            guest_asyncify(pid, "stop_rewind", 0);
            return Outcome::ready(SUCCESS);
        }
        let Some(memory_stack) = self.memory_stack(pid) else {
            return Outcome::ready(BADF);
        };
        let len = memory_stack.len() as u32;
        let stack_pointer = guest_stack_pointer(pid);
        self.pending.insert(pid, Pending::Fork { stack_pointer });
        if !self.start_unwind(pid, len) {
            self.pending.remove(&pid);
            return Outcome::ready(NOSYS);
        }
        Outcome::Unwind
    }

    fn stack_checkpoint(&mut self, pid: u32, args: &[u32]) -> Outcome {
        if let Some(value) = self.rewind_values.remove(&pid) {
            write_u64(pid, args.get(1).copied().unwrap_or(0), value as u64);
            guest_asyncify(pid, "stop_rewind", 0);
            return Outcome::ready(SUCCESS);
        }
        let Some(memory_stack) = self.memory_stack(pid) else {
            return Outcome::ready(BADF);
        };
        let len = memory_stack.len() as u32;
        let snapshot_ptr = args.first().copied().unwrap_or(0);
        self.pending
            .insert(pid, Pending::Checkpoint { snapshot_ptr });
        if !self.start_unwind(pid, len) {
            self.pending.remove(&pid);
            return Outcome::ready(NOSYS);
        }
        Outcome::Unwind
    }

    fn stack_restore(&mut self, pid: u32, args: &[u32]) -> Outcome {
        if self.rewind_values.remove(&pid).is_some() {
            guest_asyncify(pid, "stop_rewind", 0);
            return Outcome::ready(SUCCESS);
        }
        let snapshot_ptr = args.first().copied().unwrap_or(0);
        let snapshot = read_u64(pid, snapshot_ptr);
        if snapshot == 0 || !self.snapshots.contains_key(&snapshot) {
            // A longjmp to a zero/unknown snapshot: end the process cleanly for the probe.
            return Outcome::Exit(0);
        }
        let Some(memory_stack) = self.memory_stack(pid) else {
            return Outcome::ready(BADF);
        };
        let len = memory_stack.len() as u32;
        let value = args.get(1).copied().unwrap_or(0) as u64;
        self.pending
            .insert(pid, Pending::Restore { snapshot, value });
        if !self.start_unwind(pid, len) {
            self.pending.remove(&pid);
            return Outcome::ready(NOSYS);
        }
        Outcome::Unwind
    }

    fn dispatch(&mut self, pid: u32, name: &str, args: &[u32]) -> Outcome {
        match name {
            "stack_checkpoint" => return self.stack_checkpoint(pid, args),
            "stack_restore" => return self.stack_restore(pid, args),
            "proc_fork" => return self.proc_fork(pid, args),
            _ => {}
        }
        let files = &self.files;
        let Some(proc) = self.procs.get_mut(&pid) else {
            return Outcome::ready(BADF);
        };
        let arg = |i: usize| args.get(i).copied().unwrap_or(0);
        match name {
            "args_sizes_get" => {
                let size = strings_size(&proc.argv);
                write_u32(pid, arg(0), proc.argv.len() as u32);
                write_u32(pid, arg(1), size);
                Outcome::ready(SUCCESS)
            }
            "args_get" => put_strings(pid, arg(0), arg(1), &proc.argv)
                .map_or(Outcome::ready(FAULT), |_| Outcome::ready(SUCCESS)),
            "environ_sizes_get" => {
                let size = strings_size(&proc.env);
                write_u32(pid, arg(0), proc.env.len() as u32);
                write_u32(pid, arg(1), size);
                Outcome::ready(SUCCESS)
            }
            "environ_get" => put_strings(pid, arg(0), arg(1), &proc.env)
                .map_or(Outcome::ready(FAULT), |_| Outcome::ready(SUCCESS)),
            "fd_write" => {
                let (fd, iovs, iovs_len, nwritten) = (arg(0), arg(1), arg(2), arg(3));
                let iovs_vec = match read_iovs(pid, iovs, iovs_len) {
                    Ok(parts) => parts,
                    Err(errno) => return Outcome::ready(errno),
                };
                let data = gather(pid, &iovs_vec);
                match proc.fds.get_mut(&fd) {
                    Some(Fd::Stdout) | Some(Fd::Stderr) => {
                        guest_output(fd, &data);
                        write_u32(pid, nwritten, data.len() as u32);
                        Outcome::ready(SUCCESS)
                    }
                    Some(Fd::File { data: file, offset }) => {
                        let at = (*offset).min(file.len());
                        let end = (at + data.len()).min(file.len());
                        file[at..end].copy_from_slice(&data[..end - at]);
                        *offset = end;
                        write_u32(pid, nwritten, (end - at) as u32);
                        Outcome::ready(SUCCESS)
                    }
                    Some(_) => Outcome::ready(BADF),
                    None => Outcome::ready(BADF),
                }
            }
            "fd_read" => {
                let (fd, iovs, iovs_len, nread) = (arg(0), arg(1), arg(2), arg(3));
                let iovs_vec = match read_iovs(pid, iovs, iovs_len) {
                    Ok(parts) => parts,
                    Err(errno) => return Outcome::ready(errno),
                };
                let wanted: usize = iovs_vec.iter().map(|(_, len)| *len as usize).sum();
                let bytes = match proc.fds.get_mut(&fd) {
                    Some(Fd::File { data, offset }) => {
                        let at = (*offset).min(data.len());
                        let end = (at + wanted).min(data.len());
                        let bytes = data[at..end].to_vec();
                        *offset = end;
                        bytes
                    }
                    Some(Fd::Stdin) | Some(Fd::Stdout) | Some(Fd::Stderr) => Vec::new(),
                    Some(Fd::Dir) => return Outcome::ready(BADF),
                    None => return Outcome::ready(BADF),
                };
                let written = write_iovs(pid, &iovs_vec, &bytes);
                write_u32(pid, nread, written as u32);
                Outcome::ready(SUCCESS)
            }
            "fd_close" => {
                proc.fds.remove(&arg(0));
                Outcome::ready(SUCCESS)
            }
            "fd_fdstat_get" => {
                let fd = arg(0);
                let filetype = filetype(proc, fd);
                let mut stat = [0u8; 24];
                stat[0] = filetype;
                stat[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
                write_bytes(pid, arg(1), &stat);
                Outcome::ready(SUCCESS)
            }
            "fd_fdstat_set_flags" => Outcome::ready(SUCCESS),
            "fd_filestat_get" => {
                let fd = arg(0);
                let size = match proc.fds.get(&fd) {
                    Some(Fd::File { data, .. }) => data.len() as u64,
                    Some(_) => 0,
                    None => return Outcome::ready(BADF),
                };
                write_filestat(pid, arg(1), filetype(proc, fd), size);
                Outcome::ready(SUCCESS)
            }
            "fd_prestat_get" => {
                if arg(0) != 3 {
                    return Outcome::ready(BADF);
                }
                let mut prestat = [0u8; 8];
                prestat[4..8].copy_from_slice(&1u32.to_le_bytes());
                write_bytes(pid, arg(1), &prestat);
                Outcome::ready(SUCCESS)
            }
            "fd_prestat_dir_name" => {
                if arg(0) != 3 {
                    return Outcome::ready(BADF);
                }
                if arg(2) < 1 {
                    return Outcome::ready(INVAL);
                }
                write_bytes(pid, arg(1), b"/");
                Outcome::ready(SUCCESS)
            }
            "fd_readdir" => {
                write_u32(pid, arg(4), 0);
                Outcome::ready(SUCCESS)
            }
            "fd_seek" => {
                let fd = arg(0);
                // The host passes an i64 as its low 32 bits: the offset is signed (SEEK_CUR -1).
                let offset = i64::from(arg(1) as i32);
                match proc.fds.get_mut(&fd) {
                    Some(Fd::File { data, offset: at }) => {
                        // WASI's whence: from the start, from where it is, from the end.
                        let base = match arg(2) {
                            0 => 0,
                            1 => *at as i64,
                            2 => data.len() as i64,
                            _ => return Outcome::ready(INVAL),
                        };
                        let Some(to) = base.checked_add(offset).filter(|to| *to >= 0) else {
                            return Outcome::ready(INVAL);
                        };
                        // Past the end is allowed, as lseek(2) allows it; a read there reads
                        // nothing.
                        *at = to as usize;
                        write_u64(pid, arg(3), *at as u64);
                        Outcome::ready(SUCCESS)
                    }
                    // A pipe or a terminal does not seek.
                    Some(_) => Outcome::ready(SPIPE),
                    None => Outcome::ready(BADF),
                }
            }
            "fd_dup" => {
                let fd = arg(0);
                let copy = match proc.fds.get(&fd) {
                    Some(Fd::File { data, offset }) => Fd::File {
                        data: data.clone(),
                        offset: *offset,
                    },
                    Some(Fd::Dir) => Fd::Dir,
                    Some(Fd::Stdin) => Fd::Stdin,
                    Some(Fd::Stdout) => Fd::Stdout,
                    Some(Fd::Stderr) => Fd::Stderr,
                    None => return Outcome::ready(BADF),
                };
                let new_fd = proc.next_fd;
                proc.next_fd += 1;
                proc.fds.insert(new_fd, copy);
                write_u32(pid, arg(1), new_fd);
                Outcome::ready(SUCCESS)
            }
            "fd_renumber" => Outcome::ready(SUCCESS),
            "fd_pipe" => Outcome::ready(NOSYS),
            "path_open" => {
                let (path_ptr, path_len, opened_ptr) = (arg(2), arg(3), arg(8));
                let path = read_string(pid, path_ptr, path_len);
                match resolve(files, &path) {
                    Some(Node::File(data)) => {
                        let new_fd = proc.next_fd;
                        proc.next_fd += 1;
                        proc.fds.insert(new_fd, Fd::File { data, offset: 0 });
                        write_u32(pid, opened_ptr, new_fd);
                        Outcome::ready(SUCCESS)
                    }
                    Some(Node::Dir) => {
                        write_u32(pid, opened_ptr, 3);
                        Outcome::ready(SUCCESS)
                    }
                    None => Outcome::ready(NOENT),
                }
            }
            "path_filestat_get" => {
                let (path_ptr, path_len, out) = (arg(2), arg(3), arg(4));
                let path = read_string(pid, path_ptr, path_len);
                match resolve(files, &path) {
                    Some(Node::File(data)) => {
                        write_filestat(pid, out, 4, data.len() as u64);
                        Outcome::ready(SUCCESS)
                    }
                    Some(Node::Dir) => {
                        write_filestat(pid, out, 3, 0);
                        Outcome::ready(SUCCESS)
                    }
                    None => Outcome::ready(NOENT),
                }
            }
            "getcwd" => {
                let cwd = proc.cwd.clone();
                if arg(1) < cwd.len() as u32 + 1 {
                    return Outcome::ready(INVAL);
                }
                write_bytes(pid, arg(0), cwd.as_bytes());
                write_bytes(pid, arg(0) + cwd.len() as u32, &[0]);
                Outcome::ready(SUCCESS)
            }
            "chdir" => {
                let path = read_string(pid, arg(0), arg(1));
                match resolve(files, &path) {
                    Some(Node::Dir) => {
                        proc.cwd = if path.trim().is_empty() || path == "/" {
                            "/".into()
                        } else {
                            path
                        };
                        Outcome::ready(SUCCESS)
                    }
                    _ => Outcome::ready(NOENT),
                }
            }
            "clock_time_get" => {
                write_u64(pid, arg(2), (js_sys::Date::now() * 1_000_000.0) as u64);
                Outcome::ready(SUCCESS)
            }
            "proc_id" => {
                write_u32(pid, arg(0), proc.pid);
                Outcome::ready(SUCCESS)
            }
            "proc_parent" => {
                write_u32(pid, arg(1), proc.ppid);
                Outcome::ready(SUCCESS)
            }
            "proc_exit" => Outcome::Exit(arg(0) as i32),
            "proc_join" | "proc_exec" | "proc_signal" => Outcome::ready(NOSYS),
            "callback_signal" => Outcome::ready(SUCCESS),
            "thread_id" => {
                write_u32(pid, arg(0), proc.pid);
                Outcome::ready(SUCCESS)
            }
            "thread_signal" => Outcome::ready(SUCCESS),
            "thread_exit" => Outcome::Exit(arg(0) as i32),
            "futex_wait" | "futex_wake" | "futex_wake_all" => Outcome::ready(NOSYS),
            "sched_yield" => Outcome::ready(SUCCESS),
            _ => Outcome::ready(NOSYS),
        }
    }
}

enum Node {
    File(Vec<u8>),
    Dir,
}

fn clean(path: &str) -> String {
    let clean = path.trim().trim_start_matches('/').trim_end_matches('/');
    if clean == "." || clean == ".." {
        String::new()
    } else {
        clean.to_string()
    }
}

fn resolve(files: &BTreeMap<String, Vec<u8>>, path: &str) -> Option<Node> {
    let name = clean(path);
    if name.is_empty() || name == "etc" {
        return Some(Node::Dir);
    }
    files.get(&name).cloned().map(Node::File)
}

fn filetype(proc: &Process, fd: u32) -> u8 {
    match proc.fds.get(&fd) {
        Some(Fd::Dir) => 3,
        Some(Fd::File { .. }) => 4,
        Some(_) => 2,
        None => 0,
    }
}

fn strings_size(list: &[String]) -> u32 {
    list.iter().map(|s| s.len() as u32 + 1).sum()
}

fn put_strings(pid: u32, ptrs: u32, buf: u32, list: &[String]) -> Result<(), u16> {
    let mut at = buf;
    for (index, text) in list.iter().enumerate() {
        write_u32(pid, ptrs + index as u32 * 4, at);
        write_bytes(pid, at, text.as_bytes());
        write_bytes(pid, at + text.len() as u32, &[0]);
        at += text.len() as u32 + 1;
    }
    Ok(())
}

fn read_string(pid: u32, ptr: u32, len: u32) -> String {
    String::from_utf8_lossy(&mem_read(pid, ptr, len)).into_owned()
}

fn read_iovs(pid: u32, iovs: u32, len: u32) -> Result<Vec<(u32, u32)>, u16> {
    if len > 1024 {
        return Err(FAULT);
    }
    let mut parts = Vec::new();
    for index in 0..len {
        let ptr = read_u32(pid, iovs + index * 8);
        let size = read_u32(pid, iovs + index * 8 + 4);
        parts.push((ptr, size));
    }
    Ok(parts)
}

fn gather(pid: u32, iovs: &[(u32, u32)]) -> Vec<u8> {
    let mut data = Vec::new();
    for (ptr, size) in iovs {
        data.extend_from_slice(&mem_read(pid, *ptr, *size));
    }
    data
}

fn write_iovs(pid: u32, iovs: &[(u32, u32)], data: &[u8]) -> usize {
    let mut written = 0;
    for (ptr, size) in iovs {
        if written >= data.len() {
            break;
        }
        let take = (*size as usize).min(data.len() - written);
        write_bytes(pid, *ptr, &data[written..written + take]);
        written += take;
    }
    written
}

fn write_filestat(pid: u32, out: u32, filetype: u8, size: u64) {
    let mut stat = [0u8; 64];
    stat[16] = filetype;
    stat[24..32].copy_from_slice(&1u64.to_le_bytes());
    stat[32..40].copy_from_slice(&size.to_le_bytes());
    write_bytes(pid, out, &stat);
}

fn mem_read(pid: u32, ptr: u32, len: u32) -> Vec<u8> {
    guest_read(pid, ptr, len).to_vec()
}

fn write_bytes(pid: u32, ptr: u32, data: &[u8]) {
    guest_write(pid, ptr, data);
}

fn read_u32(pid: u32, ptr: u32) -> u32 {
    let bytes = mem_read(pid, ptr, 4);
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(pid: u32, ptr: u32) -> u64 {
    let bytes = mem_read(pid, ptr, 8);
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn write_u32(pid: u32, ptr: u32, value: u32) {
    write_bytes(pid, ptr, &value.to_le_bytes());
}

fn write_u64(pid: u32, ptr: u32, value: u64) {
    write_bytes(pid, ptr, &value.to_le_bytes());
}
