//! The WASIX runtime host, in Rust. The browser engine instantiates the guest; this crate owns
//! the syscall state, the fd table, the merge of `wasix_32v1` into the kernel's calls, and (in
//! progress) the asyncify checkpoint/restore/fork engine. The JS bridge (`web/kernel/host.js`)
//! only creates Workers/instances and moves bytes; it holds no policy.
use std::collections::BTreeMap;

use wasm_bindgen::prelude::*;

/// WASI/WASIX errno values used by the runtime subset.
const SUCCESS: u16 = 0;
const BADF: u16 = 8;
const FAULT: u16 = 21;
const INVAL: u16 = 28;
const NOENT: u16 = 44;
const NOSYS: u16 = 52;
const NOTDIR: u16 = 54;
const RANGE: u16 = 68;
const SPIPE: u16 = 70;

/// Reserved host pseudo-descriptors matching `abi::OS_FD_ROOT` / `abi::OS_FD_CWD`.
pub const OS_FD_ROOT: u32 = 0x7fff_fffd;
pub const OS_FD_CWD: u32 = 0x7fff_fffe;

#[wasm_bindgen]
extern "C" {
    #[cfg_attr(test, allow(dead_code))]
    #[wasm_bindgen(js_namespace = ["globalThis", "wasixGuest"], js_name = read)]
    fn guest_read(pid: u32, ptr: u32, len: u32) -> js_sys::Uint8Array;
    #[cfg_attr(test, allow(dead_code))]
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

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Ready(i32),
    Exit(i32),
    Unwind,
    Resume,
    Fork(u32),
}
impl Outcome {
    fn ready(errno: u16) -> Self {
        Self::Ready(i32::from(errno))
    }
    fn os_value(value: i32) -> Self {
        Self::Ready(value)
    }
    fn os_errno(errno: u16) -> Self {
        if errno == SUCCESS {
            Self::Ready(0)
        } else {
            Self::Ready(-i32::from(errno))
        }
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
    Dir { path: String },
}

#[derive(Clone)]
struct Process {
    pid: u32,
    ppid: u32,
    argv: Vec<String>,
    env: Vec<String>,
    cwd: String,
    root: String,
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
        fds.insert(3, Fd::Dir { path: "/".into() });
        self.procs.insert(
            pid,
            Process {
                pid,
                ppid,
                argv,
                env,
                cwd: normalize_abs(cwd, "/"),
                root: "/".into(),
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
        let canon = normalize_abs(path, "/");
        let key = canon.trim_start_matches('/').to_string();
        if !key.is_empty() {
            self.files.insert(key, bytes.to_vec());
        }
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

    /// One `wasix_32v1` / `os` import call. Accepts bare `wasix_32v1` symbol names (`"getcwd"`)
    /// or module-qualified `"<module>::<name>"` / `"<module>.<name>"` names (`"os::getcwd"`).
    pub fn syscall(&mut self, pid: u32, name: &str, args: &[u32]) -> String {
        let (module, bare) = split_qualified_syscall(name);
        let outcome = self.dispatch(pid, module, bare, args);
        outcome.json()
    }

    /// Module-qualified import call (`module` = `"os"`, `"wasix_32v1"`, or `"wasi_snapshot_preview1"`).
    pub fn syscall_module(&mut self, pid: u32, module: &str, name: &str, args: &[u32]) -> String {
        let outcome = self.dispatch(pid, module, name, args);
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

    fn dispatch(&mut self, pid: u32, module: &str, name: &str, args: &[u32]) -> Outcome {
        if module != "os" {
            match name {
                "stack_checkpoint" => return self.stack_checkpoint(pid, args),
                "stack_restore" => return self.stack_restore(pid, args),
                "proc_fork" => return self.proc_fork(pid, args),
                _ => {}
            }
        }
        let files = &self.files;
        let Some(proc) = self.procs.get_mut(&pid) else {
            return if module == "os" {
                Outcome::os_errno(BADF)
            } else {
                Outcome::ready(BADF)
            };
        };
        let arg = |i: usize| args.get(i).copied().unwrap_or(0);
        if module == "os" {
            return match name {
                "getcwd" => {
                    let (buf_ptr, cap) = (arg(0), arg(1) as usize);
                    if buf_ptr == 0 && cap != 0 {
                        return Outcome::os_errno(FAULT);
                    }
                    match proc_getcwd(proc, cap) {
                        Ok(cwd) => {
                            write_bytes(pid, buf_ptr, cwd.as_bytes());
                            write_bytes(pid, buf_ptr + cwd.len() as u32, &[0]);
                            Outcome::os_value((cwd.len() + 1) as i32)
                        }
                        Err(errno) => Outcome::os_errno(errno),
                    }
                }
                "chdir" => {
                    let path = read_string(pid, arg(0), arg(1));
                    Outcome::os_errno(proc_chdir(files, proc, &path))
                }
                "fchdir" => Outcome::os_errno(proc_fchdir(proc, arg(0))),
                "chroot" => {
                    let path = read_string(pid, arg(0), arg(1));
                    Outcome::os_errno(proc_chroot(files, proc, &path))
                }
                _ => Outcome::os_errno(NOSYS),
            };
        }
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
                    Some(_) | None => Outcome::ready(BADF),
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
                    Some(Fd::Dir { .. }) | None => return Outcome::ready(BADF),
                };
                let written = write_iovs(pid, &iovs_vec, &bytes);
                write_u32(pid, nread, written as u32);
                Outcome::ready(SUCCESS)
            }
            "fd_close" => {
                let fd = arg(0);
                if fd == OS_FD_ROOT || fd == OS_FD_CWD {
                    return Outcome::ready(BADF);
                }
                proc.fds.remove(&fd);
                Outcome::ready(SUCCESS)
            }
            "fd_fdstat_get" => {
                let fd = arg(0);
                let Some(ft) = filetype(proc, fd) else {
                    return Outcome::ready(BADF);
                };
                let mut stat = [0u8; 24];
                stat[0] = ft;
                stat[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
                write_bytes(pid, arg(1), &stat);
                Outcome::ready(SUCCESS)
            }
            "fd_fdstat_set_flags" => Outcome::ready(SUCCESS),
            "fd_filestat_get" => {
                let fd = arg(0);
                let (ft, size) = if fd == OS_FD_ROOT || fd == OS_FD_CWD {
                    (3, 0)
                } else {
                    match proc.fds.get(&fd) {
                        Some(Fd::File { data, .. }) => (4, data.len() as u64),
                        Some(Fd::Dir { .. }) => (3, 0),
                        Some(_) => (2, 0),
                        None => return Outcome::ready(BADF),
                    }
                };
                write_filestat(pid, arg(1), ft, size);
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
                    Some(Fd::Dir { path }) => Fd::Dir { path: path.clone() },
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
                let (dirfd, path_ptr, path_len, opened_ptr) = (arg(0), arg(2), arg(3), arg(8));
                let path = read_string(pid, path_ptr, path_len);
                match proc_open(files, proc, dirfd, &path) {
                    Ok(opened) => {
                        write_u32(pid, opened_ptr, opened);
                        Outcome::ready(SUCCESS)
                    }
                    Err(errno) => Outcome::ready(errno),
                }
            }
            "path_filestat_get" => {
                let (dirfd, path_ptr, path_len, out) = (arg(0), arg(2), arg(3), arg(4));
                let path = read_string(pid, path_ptr, path_len);
                match resolve_at(files, proc, dirfd, &path) {
                    Ok((_, Node::File(data))) => {
                        write_filestat(pid, out, 4, data.len() as u64);
                        Outcome::ready(SUCCESS)
                    }
                    Ok((_, Node::Dir)) => {
                        write_filestat(pid, out, 3, 0);
                        Outcome::ready(SUCCESS)
                    }
                    Err(errno) => Outcome::ready(errno),
                }
            }
            "getcwd" => {
                let (buf_ptr, len_ptr) = (arg(0), arg(1));
                if len_ptr == 0 {
                    return Outcome::ready(FAULT);
                }
                let cap = read_u32(pid, len_ptr) as usize;
                let Some(cwd) = rebase_under_root(&proc.cwd, &proc.root) else {
                    return Outcome::ready(NOENT);
                };
                let needed = cwd.len() + 1;
                if cap < needed {
                    write_u32(pid, len_ptr, needed as u32);
                    Outcome::ready(RANGE)
                } else if buf_ptr == 0 {
                    Outcome::ready(FAULT)
                } else {
                    write_bytes(pid, buf_ptr, cwd.as_bytes());
                    write_bytes(pid, buf_ptr + cwd.len() as u32, &[0]);
                    write_u32(pid, len_ptr, cwd.len() as u32);
                    Outcome::ready(SUCCESS)
                }
            }
            "chdir" => {
                let path = read_string(pid, arg(0), arg(1));
                Outcome::ready(proc_chdir(files, proc, &path))
            }
            "fchdir" => Outcome::ready(proc_fchdir(proc, arg(0))),
            "chroot" => {
                let path = read_string(pid, arg(0), arg(1));
                Outcome::ready(proc_chroot(files, proc, &path))
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

#[derive(Debug, PartialEq, Eq)]
enum Node {
    File(Vec<u8>),
    Dir,
}

fn normalize_abs(path: &str, root: &str) -> String {
    let mut stack: Vec<&str> = root
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    let root_depth = stack.len();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if stack.len() > root_depth {
                    stack.pop();
                }
            }
            seg => stack.push(seg),
        }
    }
    if stack.is_empty() {
        "/".into()
    } else {
        format!("/{}", stack.join("/"))
    }
}

fn rebase_under_root(cwd: &str, root: &str) -> Option<String> {
    if root == "/" {
        return Some(cwd.to_string());
    }
    if cwd == root {
        return Some("/".into());
    }
    cwd.strip_prefix(root)
        .filter(|rest| rest.starts_with('/'))
        .map(ToOwned::to_owned)
}

fn lookup_node(files: &BTreeMap<String, Vec<u8>>, canon: &str) -> Option<Node> {
    let key = canon.trim_start_matches('/');
    if key.is_empty() || key == "etc" {
        return Some(Node::Dir);
    }
    if let Some(data) = files.get(key) {
        return Some(Node::File(data.clone()));
    }
    let prefix = format!("{key}/");
    if files.keys().any(|entry| entry.starts_with(&prefix)) {
        return Some(Node::Dir);
    }
    None
}

fn resolve_at(
    files: &BTreeMap<String, Vec<u8>>,
    proc: &Process,
    dirfd: u32,
    raw: &str,
) -> Result<(String, Node), u16> {
    let path = raw.trim();
    if path.is_empty() {
        return Err(NOENT);
    }
    let start = if path.starts_with('/') || dirfd == OS_FD_ROOT {
        proc.root.as_str()
    } else if dirfd == OS_FD_CWD {
        proc.cwd.as_str()
    } else {
        match proc.fds.get(&dirfd) {
            Some(Fd::Dir { path: dir }) => {
                if dirfd == 3 && dir == "/" {
                    proc.root.as_str()
                } else {
                    dir.as_str()
                }
            }
            Some(_) => return Err(NOTDIR),
            None => return Err(BADF),
        }
    };

    let trailing_slash = path.len() > 1 && path.ends_with('/');
    let mut parts: Vec<&str> = start.split('/').filter(|seg| !seg.is_empty()).collect();
    let segments: Vec<&str> = path.split('/').filter(|seg| !seg.is_empty()).collect();

    for (idx, seg) in segments.iter().enumerate() {
        match *seg {
            "." => {}
            ".." => {
                let current = if parts.is_empty() {
                    "/".to_string()
                } else {
                    format!("/{}", parts.join("/"))
                };
                if current != proc.root {
                    parts.pop();
                }
            }
            name => {
                parts.push(name);
                let step = format!("/{}", parts.join("/"));
                let is_last = idx + 1 == segments.len();
                if !is_last {
                    match lookup_node(files, &step) {
                        Some(Node::Dir) => {}
                        Some(Node::File(_)) => return Err(NOTDIR),
                        None => return Err(NOENT),
                    }
                }
            }
        }
    }

    let canon = if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    };
    match lookup_node(files, &canon) {
        Some(Node::File(_)) if trailing_slash => Err(NOTDIR),
        Some(node) => Ok((canon, node)),
        None => Err(NOENT),
    }
}

fn proc_open(
    files: &BTreeMap<String, Vec<u8>>,
    proc: &mut Process,
    dirfd: u32,
    path: &str,
) -> Result<u32, u16> {
    match resolve_at(files, proc, dirfd, path)? {
        (_, Node::File(data)) => {
            let new_fd = proc.next_fd;
            proc.next_fd += 1;
            proc.fds.insert(new_fd, Fd::File { data, offset: 0 });
            Ok(new_fd)
        }
        (canon, Node::Dir) => {
            let new_fd = proc.next_fd;
            proc.next_fd += 1;
            proc.fds.insert(new_fd, Fd::Dir { path: canon });
            Ok(new_fd)
        }
    }
}

fn proc_chdir(files: &BTreeMap<String, Vec<u8>>, proc: &mut Process, path: &str) -> u16 {
    let dirfd = if path.starts_with('/') {
        OS_FD_ROOT
    } else {
        OS_FD_CWD
    };
    match resolve_at(files, proc, dirfd, path) {
        Ok((canon, Node::Dir)) => {
            proc.cwd = canon;
            SUCCESS
        }
        Ok((_, Node::File(_))) => NOTDIR,
        Err(errno) => errno,
    }
}

fn proc_fchdir(proc: &mut Process, fd: u32) -> u16 {
    if fd == OS_FD_ROOT {
        proc.cwd = proc.root.clone();
        return SUCCESS;
    }
    if fd == OS_FD_CWD {
        return SUCCESS;
    }
    match proc.fds.get(&fd) {
        Some(Fd::Dir { path }) => {
            proc.cwd = path.clone();
            SUCCESS
        }
        Some(_) => NOTDIR,
        None => BADF,
    }
}

fn proc_chroot(files: &BTreeMap<String, Vec<u8>>, proc: &mut Process, path: &str) -> u16 {
    let dirfd = if path.starts_with('/') {
        OS_FD_ROOT
    } else {
        OS_FD_CWD
    };
    match resolve_at(files, proc, dirfd, path) {
        Ok((canon, Node::Dir)) => {
            proc.root = canon;
            SUCCESS
        }
        Ok((_, Node::File(_))) => NOTDIR,
        Err(errno) => errno,
    }
}

fn proc_getcwd(proc: &Process, cap: usize) -> Result<String, u16> {
    if cap == 0 {
        return Err(INVAL);
    }
    let Some(cwd) = rebase_under_root(&proc.cwd, &proc.root) else {
        return Err(NOENT);
    };
    if cap < cwd.len() + 1 {
        return Err(RANGE);
    }
    Ok(cwd)
}

fn filetype(proc: &Process, fd: u32) -> Option<u8> {
    if fd == OS_FD_ROOT || fd == OS_FD_CWD {
        return Some(3);
    }
    match proc.fds.get(&fd) {
        Some(Fd::Dir { .. }) => Some(3),
        Some(Fd::File { .. }) => Some(4),
        Some(_) => Some(2),
        None => None,
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

fn split_qualified_syscall(name: &str) -> (&str, &str) {
    if let Some((module, bare)) = name.split_once("::") {
        return (module, bare);
    }
    if let Some((module, bare)) = name.split_once('.') {
        return (module, bare);
    }
    ("wasix_32v1", name)
}

#[cfg(test)]
thread_local! {
    static TEST_GUEST_MEM: std::cell::RefCell<BTreeMap<u32, Vec<u8>>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
}

fn mem_read(pid: u32, ptr: u32, len: u32) -> Vec<u8> {
    #[cfg(test)]
    {
        TEST_GUEST_MEM.with(|mem| {
            let map = mem.borrow();
            let Some(buf) = map.get(&pid) else {
                return vec![0; len as usize];
            };
            let start = (ptr as usize).min(buf.len());
            let end = (start + len as usize).min(buf.len());
            let mut out = vec![0; len as usize];
            out[..end - start].copy_from_slice(&buf[start..end]);
            out
        })
    }
    #[cfg(not(test))]
    {
        guest_read(pid, ptr, len).to_vec()
    }
}

fn write_bytes(pid: u32, ptr: u32, data: &[u8]) {
    #[cfg(test)]
    {
        TEST_GUEST_MEM.with(|mem| {
            let mut map = mem.borrow_mut();
            let buf = map.entry(pid).or_insert_with(|| vec![0; 65536]);
            let end = ptr as usize + data.len();
            if buf.len() < end {
                buf.resize(end, 0);
            }
            buf[ptr as usize..end].copy_from_slice(data);
        });
    }
    #[cfg(not(test))]
    {
        guest_write(pid, ptr, data);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime() -> Runtime {
        let mut rt = Runtime::new();
        rt.add_file("/dash", b"elf");
        rt.add_file("/etc/profile", b"# profile\n");
        rt.add_file("/jail/bin/sh", b"#!/bin/sh\n");
        rt.add_file("/jail/etc/motd", b"jailed\n");
        rt.register(1, 0, "[\"dash\"]", "[]", "/");
        rt
    }

    #[test]
    fn resolves_os_fd_root_and_cwd_with_uncollapsed_dotdot() {
        let mut rt = test_runtime();
        let files = rt.files.clone();
        let proc = rt.procs.get_mut(&1).expect("proc 1");

        assert_eq!(proc_chdir(&files, proc, "jail/bin"), SUCCESS);
        assert_eq!(proc_getcwd(proc, 64), Ok("/jail/bin".to_string()));
        assert_eq!(proc_getcwd(proc, 0), Err(INVAL));
        assert_eq!(proc_getcwd(proc, 4), Err(RANGE));

        let (canon, node) =
            resolve_at(&files, proc, OS_FD_CWD, "../etc/motd").expect("relative ..");
        assert_eq!(canon, "/jail/etc/motd");
        assert_eq!(node, Node::File(b"jailed\n".to_vec()));

        let (root_canon, root_node) =
            resolve_at(&files, proc, OS_FD_ROOT, "etc/profile").expect("root anchor");
        assert_eq!(root_canon, "/etc/profile");
        assert_eq!(root_node, Node::File(b"# profile\n".to_vec()));
    }

    #[test]
    fn chroot_clamps_dotdot_and_rebases_getcwd() {
        let mut rt = test_runtime();
        let files = rt.files.clone();
        let proc = rt.procs.get_mut(&1).expect("proc 1");

        // chroot without chdir leaves cwd outside root -> getcwd returns ENOENT.
        assert_eq!(proc_chroot(&files, proc, "/jail"), SUCCESS);
        assert_eq!(proc_getcwd(proc, 64), Err(NOENT));

        // chdir("/") enters the new root; `..` cannot escape `/jail`.
        assert_eq!(proc_chdir(&files, proc, "/"), SUCCESS);
        assert_eq!(proc_getcwd(proc, 64), Ok("/".to_string()));
        assert_eq!(proc_chdir(&files, proc, "../../.."), SUCCESS);
        assert_eq!(proc_getcwd(proc, 64), Ok("/".to_string()));
        assert_eq!(resolve_at(&files, proc, OS_FD_ROOT, "dash"), Err(NOENT));

        assert_eq!(proc_chdir(&files, proc, "/bin"), SUCCESS);
        assert_eq!(proc_getcwd(proc, 64), Ok("/bin".to_string()));
    }

    #[test]
    fn fchdir_switches_to_opened_directory_fd() {
        let mut rt = test_runtime();
        let files = rt.files.clone();
        let proc = rt.procs.get_mut(&1).expect("proc 1");

        let dir_fd = proc_open(&files, proc, OS_FD_ROOT, "jail/etc").expect("open dir");
        let file_fd = proc_open(&files, proc, OS_FD_ROOT, "dash").expect("open file");
        assert_eq!(proc_fchdir(proc, file_fd), NOTDIR);
        assert_eq!(proc_fchdir(proc, 999), BADF);
        assert_eq!(proc_fchdir(proc, dir_fd), SUCCESS);
        assert_eq!(proc_getcwd(proc, 64), Ok("/jail/etc".to_string()));
    }

    #[test]
    fn os_getcwd_returns_len_plus_one_and_negative_wasi_errno_while_wasix_uses_len_ptr() {
        TEST_GUEST_MEM.with(|mem| mem.borrow_mut().insert(1, vec![0xaa; 4096]));
        let mut rt = test_runtime();

        // Write "jail/bin" at ptr 256 and chdir via `os::chdir`.
        write_bytes(1, 256, b"jail/bin");
        let chdir_reply: serde_json::Value =
            serde_json::from_str(&rt.syscall_module(1, "os", "chdir", &[256, 8])).unwrap();
        assert_eq!(chdir_reply["errno"], 0);

        // `os::getcwd` with cap == 0 -> -EINVAL (-28).
        let zero_cap: serde_json::Value =
            serde_json::from_str(&rt.syscall_module(1, "os", "getcwd", &[512, 0])).unwrap();
        assert_eq!(zero_cap["errno"], -i32::from(INVAL));

        // `os::getcwd` with cap too small (4 < "/jail/bin\0".len() == 10) -> -ERANGE (-68),
        // and guest buffer at 512 remains untouched (`0xaa`).
        let small_cap: serde_json::Value =
            serde_json::from_str(&rt.syscall(1, "os::getcwd", &[512, 4])).unwrap();
        assert_eq!(small_cap["errno"], -i32::from(RANGE));
        assert_eq!(mem_read(1, 512, 4), vec![0xaa; 4]);

        // `os::getcwd` with sufficient capacity -> returns `len + 1` (10) and writes NUL-terminated path.
        let ok_reply: serde_json::Value =
            serde_json::from_str(&rt.syscall_module(1, "os", "getcwd", &[512, 64])).unwrap();
        assert_eq!(ok_reply["errno"], 10);
        assert_eq!(mem_read(1, 512, 10), b"/jail/bin\0");

        // `wasix_32v1::getcwd` uses `(buf_ptr, len_ptr) -> 0 / +ERANGE (68)`.
        write_u32(1, 1024, 4);
        let wasix_small: serde_json::Value =
            serde_json::from_str(&rt.syscall(1, "getcwd", &[1200, 1024])).unwrap();
        assert_eq!(wasix_small["errno"], i32::from(RANGE));
        assert_eq!(read_u32(1, 1024), 10);

        write_u32(1, 1024, 64);
        let wasix_ok: serde_json::Value =
            serde_json::from_str(&rt.syscall(1, "getcwd", &[1200, 1024])).unwrap();
        assert_eq!(wasix_ok["errno"], i32::from(SUCCESS));
        assert_eq!(read_u32(1, 1024), 9);
        assert_eq!(mem_read(1, 1200, 10), b"/jail/bin\0");

        // `os::chroot` leaving cwd outside root -> `os::getcwd` returns -ENOENT (-44).
        write_bytes(1, 256, b"/etc");
        let chroot_reply: serde_json::Value =
            serde_json::from_str(&rt.syscall_module(1, "os", "chroot", &[256, 4])).unwrap();
        assert_eq!(chroot_reply["errno"], 0);
        let unreachable: serde_json::Value =
            serde_json::from_str(&rt.syscall_module(1, "os", "getcwd", &[512, 64])).unwrap();
        assert_eq!(unreachable["errno"], -i32::from(NOENT));
    }

    #[test]
    fn resolve_at_accepts_all_slash_root_path_inside_and_outside_chroot() {
        let mut rt = test_runtime();
        let files = rt.files.clone();
        let proc = rt.procs.get_mut(&1).expect("proc 1");
        assert_eq!(
            resolve_at(&files, proc, OS_FD_ROOT, "/"),
            Ok(("/".to_string(), Node::Dir))
        );
        assert_eq!(proc_chroot(&files, proc, "/jail"), SUCCESS);
        assert_eq!(
            resolve_at(&files, proc, OS_FD_ROOT, "/"),
            Ok(("/jail".to_string(), Node::Dir))
        );
    }
}
