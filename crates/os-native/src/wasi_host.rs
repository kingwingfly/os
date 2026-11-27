//! Complete Wasmtime 51 host import surface for `os-native`:
//! - `os_runtime` (`memory_grow_pre`, `memory_grow_post`)
//! - `wasi_snapshot_preview1` (all 37 active & stub functions)
//! - `wasix_32v1` (all 35 active & stub functions including `proc_fork`, `stack_checkpoint`/`restore`)
//! - `os` (all 39 functions: L2 mounts/namespaces/chroot/cwd, `execve`, `posix_spawn`, `waitpid*`,
//!   signals, credentials, `sys`/`reply` batch, all 13 `AF_UNIX` `sock_*`, and `gui_*` stubs)
//! - `terminal` (alias of `os` for legacy coreutils)

use crate::dev_backend::fill_os_random;
use crate::errno::*;
use crate::kernel_rpc::{
    GuestFdEntry, GuestFdKind, KAnchor, KernelCmd, RightsFd, ServiceGrantSpec, SpawnProcessReq,
};
use crate::pipes::PipeHandle;
use crate::proc_runner::{
    AsyncifyAnswer, AsyncifyPending, GuestControlFlow, ProcessHost, spawn_and_launch,
};
use crate::pty::{PtySlaveHandle, Termios, iflag, lflag};
use abi::socket::{MSG_CMSG_CLOEXEC, MSG_CTRUNC, MSG_DONTWAIT, MSG_NOSIGNAL, PeerCred};
use abi::{Call, Errno, OS_FD_CWD, OS_FD_ROOT, RawStatFs, Stat, Time};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use wasmtime::{Caller, Linker};

type HostRes<T> = Result<T, wasmtime::Error>;

/// Signal / stop / kill check directly usable from any `Caller<'_, ProcessHost>` host function.
fn check_signals_caller(
    caller: &mut Caller<'_, ProcessHost>,
    interruptible: bool,
) -> Result<bool, wasmtime::Error> {
    if let Some(sig) = caller.data().signals.ctrl.killed_signal() {
        return Err(wasmtime::Error::new(GuestControlFlow::Exit {
            code: 128 + i32::from(sig),
            signal: Some(sig),
        }));
    }
    if caller.data().signals.ctrl.is_stopped() {
        let cause = caller
            .data()
            .signals
            .ctrl
            .stop_cause
            .load(std::sync::atomic::Ordering::SeqCst) as u8;
        let pid = caller.data().pid;
        caller
            .data()
            .kernel
            .send_fire_and_forget(KernelCmd::ReportStopped { pid, signal: cause });
        while caller.data().signals.ctrl.is_stopped() {
            if let Some(sig) = caller.data().signals.ctrl.killed_signal() {
                return Err(wasmtime::Error::new(GuestControlFlow::Exit {
                    code: 128 + i32::from(sig),
                    signal: Some(sig),
                }));
            }
            caller
                .data()
                .signals
                .ctrl
                .wait_timeout(Duration::from_millis(25));
        }
    }
    if caller.data().in_signal_dispatch {
        return Ok(false);
    }
    if let Some(get_state) = caller.data().asyncify.get_state.clone()
        && get_state.call(&mut *caller, ()).unwrap_or(0) == 2
    {
        return Ok(false);
    }

    let mut interrupted = false;
    while let Some((sig, action)) = caller.data().signals.take() {
        if action.kind == crate::signals::SIG_IGN
            || (action.kind == crate::signals::SIG_DFL
                && crate::signals::is_ignored_by_default(sig))
        {
            continue;
        }
        if action.kind == crate::signals::SIG_DFL {
            if sig == 18 {
                continue;
            }
            if crate::signals::is_stopped_by_default(sig) {
                caller
                    .data()
                    .signals
                    .ctrl
                    .stop_cause
                    .store(u32::from(sig), std::sync::atomic::Ordering::SeqCst);
                caller.data().signals.ctrl.state.store(
                    crate::signals::CTRL_STOPPED,
                    std::sync::atomic::Ordering::SeqCst,
                );
                return check_signals_caller(caller, interruptible);
            }
            return Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code: 128 + i32::from(sig),
                signal: Some(sig),
            }));
        }
        if action.kind == crate::signals::SIG_CATCH {
            let cb_name = caller.data().signals.callback.clone();
            let cb_fn = cb_name.and_then(|name| {
                let inst = caller.data().instance_exports?;
                inst.get_typed_func::<u32, ()>(&mut *caller, &name).ok()
            });
            let Some(cb) = cb_fn else {
                continue;
            };
            let saved_mask = caller.data().signals.mask();
            if (action.flags & crate::signals::SA_RESETHAND) != 0 {
                caller.data_mut().signals.action(u32::from(sig), 0, 0, 0);
            }
            let next_mask = saved_mask
                | action.mask
                | if (action.flags & crate::signals::SA_NODEFER) != 0 {
                    0
                } else {
                    crate::signals::bit(sig)
                };
            caller.data_mut().signals.set_mask(next_mask);
            caller.data_mut().in_signal_dispatch = true;
            let res = cb.call(&mut *caller, u32::from(sig));
            caller.data_mut().in_signal_dispatch = false;
            caller.data_mut().signals.set_mask(saved_mask);
            res?;
            // Check if signal handler called `stack_restore` (longjmp).
            if let Some(get_state) = caller.data().asyncify.get_state.clone()
                && get_state.call(&mut *caller, ()).unwrap_or(0) == 1
            {
                if let Some(stop) = caller.data().asyncify.stop_unwind.clone() {
                    let _ = stop.call(&mut *caller, ());
                }
                if let Some(AsyncifyPending::Restore {
                    snapshot_ptr,
                    value,
                }) = caller.data_mut().asyncify.pending.take()
                {
                    return Err(wasmtime::Error::new(GuestControlFlow::SignalJump {
                        snapshot_ptr,
                        value,
                    }));
                }
            }
            caller.data_mut().signals.delivered_count += 1;
            if (action.flags & crate::signals::SA_RESTART) == 0 {
                interrupted = true;
            }
        }
    }
    Ok(interruptible && interrupted)
}

fn resolve_anchor(
    caller: &Caller<'_, ProcessHost>,
    fd: u32,
    raw_path: &str,
) -> Result<KAnchor, Errno> {
    if raw_path.starts_with('/') {
        return Ok(KAnchor::Root);
    }
    if fd == OS_FD_ROOT as u32 {
        return Ok(KAnchor::Root);
    }
    if fd == OS_FD_CWD as u32 {
        return Ok(KAnchor::Cwd);
    }
    let entry = caller.data().fds.get(&fd).ok_or(Errno::EBADF)?;
    match &entry.kind {
        GuestFdKind::Preopen => Ok(KAnchor::Root),
        GuestFdKind::Kfd { kfd, .. } => Ok(KAnchor::Kfd(*kfd)),
        _ => Err(Errno::ENOTDIR),
    }
}

fn write_filestat(caller: &mut Caller<'_, ProcessHost>, ptr: u32, st: &Stat) -> Result<(), Errno> {
    let mem = caller.data().mem()?;
    let mut buf = [0u8; 64];
    buf[0..8].copy_from_slice(&st.dev.to_le_bytes());
    buf[8..16].copy_from_slice(&st.ino.to_le_bytes());
    buf[16] = wasi_filetype_from_mode(st.mode);
    buf[24..32].copy_from_slice(&u64::from(st.nlink.max(1)).to_le_bytes());
    buf[32..40].copy_from_slice(&st.size.to_le_bytes());
    let atim = st
        .atime
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(st.atime_nsec));
    let mtim = st
        .mtime
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(st.mtime_nsec));
    let ctim = st
        .ctime
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::from(st.ctime_nsec));
    buf[40..48].copy_from_slice(&atim.to_le_bytes());
    buf[48..56].copy_from_slice(&mtim.to_le_bytes());
    buf[56..64].copy_from_slice(&ctim.to_le_bytes());
    mem.write_bytes(caller, ptr, &buf)
}

fn write_raw_statfs(
    caller: &mut Caller<'_, ProcessHost>,
    ptr: u32,
    raw: &RawStatFs,
) -> Result<(), Errno> {
    let mem = caller.data().mem()?;
    let mut buf = [0u8; 80];
    buf[0..8].copy_from_slice(&raw.f_type.to_le_bytes());
    buf[8..16].copy_from_slice(&raw.f_bsize.to_le_bytes());
    buf[16..24].copy_from_slice(&raw.f_frsize.to_le_bytes());
    buf[24..32].copy_from_slice(&raw.f_blocks.to_le_bytes());
    buf[32..40].copy_from_slice(&raw.f_bfree.to_le_bytes());
    buf[40..48].copy_from_slice(&raw.f_bavail.to_le_bytes());
    buf[48..56].copy_from_slice(&raw.f_files.to_le_bytes());
    buf[56..64].copy_from_slice(&raw.f_ffree.to_le_bytes());
    buf[64..72].copy_from_slice(&raw.f_namelen.to_le_bytes());
    buf[72..80].copy_from_slice(&raw.f_flags.to_le_bytes());
    mem.write_bytes(caller, ptr, &buf)
}

fn write_peercred(
    caller: &mut Caller<'_, ProcessHost>,
    ptr: u32,
    cred: PeerCred,
) -> Result<(), Errno> {
    if ptr == 0 {
        return Ok(());
    }
    let mem = caller.data().mem()?;
    let mut buf = [0u8; 12];
    buf[0..4].copy_from_slice(&cred.pid.to_le_bytes());
    buf[4..8].copy_from_slice(&cred.uid.to_le_bytes());
    buf[8..12].copy_from_slice(&cred.gid.to_le_bytes());
    mem.write_bytes(caller, ptr, &buf)
}

const MAX_IOV_COUNT: u32 = 1024;
const MAX_IO_BYTES: usize = 16 * 1024 * 1024;

fn should_interrupt_blocking(ctrl: &crate::signals::SignalControl) -> Result<(), Errno> {
    if ctrl.killed_signal().is_some()
        || ctrl.is_stopped()
        || (ctrl.pending.load(std::sync::atomic::Ordering::SeqCst)
            & !ctrl.mask.load(std::sync::atomic::Ordering::SeqCst))
            != 0
    {
        return Err(Errno::EINTR);
    }
    Ok(())
}

fn read_iovecs(
    caller: &Caller<'_, ProcessHost>,
    iovs: u32,
    count: u32,
) -> Result<Vec<(u32, u32)>, Errno> {
    if count > MAX_IOV_COUNT {
        return Err(Errno::EINVAL);
    }
    let mem = caller.data().mem()?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let base = iovs
            .checked_add(i.checked_mul(8).ok_or(Errno::EINVAL)?)
            .ok_or(Errno::EINVAL)?;
        let ptr = mem.read_u32(caller, base)?;
        let len = mem.read_u32(caller, base + 4)?;
        out.push((ptr, len));
    }
    Ok(out)
}

fn decode_wasi_time(val: u64, set_bit: u32, now_bit: u32, fstflags: u32) -> Time {
    if (fstflags & now_bit) != 0 {
        Time::Now
    } else if (fstflags & set_bit) != 0 {
        Time::At {
            sec: val / 1_000_000_000,
            nsec: (val % 1_000_000_000) as u32,
        }
    } else {
        Time::Omit
    }
}

#[allow(clippy::too_many_arguments)]
fn open_path_at(
    caller: &mut Caller<'_, ProcessHost>,
    dirfd: u32,
    raw: &str,
    dirflags: u32,
    oflags: u32,
    rights: u64,
    fdflags: u32,
    noctty: bool,
    mode: u16,
    extra: u32,
) -> Result<u32, Errno> {
    let anchor = resolve_anchor(caller, dirfd, raw)?;
    let path_only = (extra & O_PATH) != 0;
    let cloexec = (extra & O_CLOEXEC) != 0;
    let nonblock = (fdflags & u32::from(WASI_FDFLAG_NONBLOCK)) != 0;
    let append = (fdflags & u32::from(WASI_FDFLAG_APPEND)) != 0;
    let want_read = (rights & WASI_RIGHT_READ) != 0;
    let want_write = (rights & WASI_RIGHT_WRITE) != 0;

    let mut linux_flags = if path_only {
        O_PATH
    } else if want_read && want_write {
        O_RDWR
    } else if want_write {
        O_WRONLY
    } else {
        O_RDONLY
    };
    if (oflags & WASI_OFLAG_CREAT) != 0 {
        linux_flags |= O_CREAT;
    }
    if (oflags & WASI_OFLAG_EXCL) != 0 {
        linux_flags |= O_EXCL;
    }
    if (oflags & WASI_OFLAG_TRUNC) != 0 {
        linux_flags |= O_TRUNC;
    }
    if (oflags & WASI_OFLAG_DIRECTORY) != 0 {
        linux_flags |= O_DIRECTORY;
    }
    if append {
        linux_flags |= O_APPEND;
    }
    if (dirflags & WASI_LOOKUP_SYMLINK_FOLLOW) == 0 {
        linux_flags |= O_NOFOLLOW;
    }

    // Always resolve through the kernel VFS first so chroot jails, mount namespaces,
    // `O_NOFOLLOW`, and DAC permissions (`0620` on `/dev/pts/<N>`) are strictly enforced.
    let pid = caller.data().pid;
    let opened = caller.data().kernel.call_sync(|reply| KernelCmd::OpenAt {
        pid,
        anchor,
        path: raw.to_string(),
        flags: linux_flags,
        mode,
        cloexec,
        reply,
    })?;
    let close_opened_kfd = |caller: &Caller<'_, ProcessHost>| {
        let _ = caller.data().kernel.call_sync(|reply| KernelCmd::CloseKfd {
            pid,
            kfd: opened.kfd,
            reply,
        });
    };
    let fd = match caller.data().lowest_fd(0) {
        Ok(f) => f,
        Err(e) => {
            close_opened_kfd(caller);
            return Err(e);
        }
    };

    if !path_only {
        match opened.device.as_deref() {
            Some("ptmx") => {
                close_opened_kfd(caller);
                let master = caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::AllocPty {
                        pid,
                        locked: true,
                        reply,
                    })?;
                caller.data_mut().fds.insert(
                    fd,
                    GuestFdEntry {
                        kind: GuestFdKind::PtyMaster {
                            pty: master,
                            nonblock,
                        },
                        cloexec,
                    },
                );
                return Ok(fd);
            }
            Some("tty") => {
                close_opened_kfd(caller);
                let (_uid, _gid, ctty) = caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::GetProcCredAndCtty { pid, reply })?;
                let num = ctty.ok_or(Errno::ENXIO)?;
                let pty = caller.data().kernel.ptys.get(num).ok_or(Errno::ENXIO)?;
                if pty.is_hungup() {
                    return Err(Errno::ENXIO);
                }
                caller.data_mut().fds.insert(
                    fd,
                    GuestFdEntry {
                        kind: GuestFdKind::PtySlave {
                            pty: PtySlaveHandle::new(pty),
                            readable: want_read || !want_write,
                            writable: want_write,
                            nonblock,
                        },
                        cloexec,
                    },
                );
                return Ok(fd);
            }
            Some(dev) if dev.starts_with("pts:") => {
                close_opened_kfd(caller);
                let num: u32 = dev
                    .strip_prefix("pts:")
                    .and_then(|s| s.parse::<u32>().ok())
                    .ok_or(Errno::ENOENT)?;
                let pty = caller.data().kernel.ptys.get(num).ok_or(Errno::ENOENT)?;
                if pty.is_locked() || pty.is_hungup() {
                    return Err(Errno::EIO);
                }
                let (uid, gid, _ctty) = caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::GetProcCredAndCtty { pid, reply })?;
                let (owner_uid, owner_gid) = pty.owner();
                let allowed =
                    uid == 0 || uid == owner_uid || (gid == owner_gid && !want_read && want_write);
                if !allowed {
                    return Err(Errno::EACCES);
                }
                if !noctty {
                    let (pgid, sid, ctty) = caller
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::GetProcTtyInfo { pid, reply });
                    if sid == pid && ctty.is_none() && pty.session() == 0 {
                        pty.set_session(sid, pgid);
                        caller.data().kernel.call_sync(|reply| KernelCmd::SetTty {
                            pid,
                            tty: Some(num),
                            tty_fds: vec![0, 1, 2],
                            reply,
                        });
                    }
                }
                caller.data_mut().fds.insert(
                    fd,
                    GuestFdEntry {
                        kind: GuestFdKind::PtySlave {
                            pty: PtySlaveHandle::new(pty),
                            readable: want_read || !want_write,
                            writable: want_write,
                            nonblock,
                        },
                        cloexec,
                    },
                );
                return Ok(fd);
            }
            _ => {}
        }
    }

    caller.data_mut().fds.insert(
        fd,
        GuestFdEntry {
            kind: GuestFdKind::Kfd {
                kfd: opened.kfd,
                is_dir: opened.is_dir,
                path_only: opened.path_only,
                readable: !path_only && (want_read || !want_write),
                writable: !path_only && want_write,
                append,
                nonblock,
                device: opened.device,
            },
            cloexec,
        },
    );
    Ok(fd)
}

fn do_execve(
    caller: &mut Caller<'_, ProcessHost>,
    file: String,
    argv: Vec<String>,
    env: Vec<String>,
    search: bool,
) -> Result<Result<(), Errno>, wasmtime::Error> {
    let pid = caller.data().pid;
    match caller
        .data()
        .kernel
        .call_sync(|reply| KernelCmd::PrepareExec {
            pid,
            file,
            argv,
            env,
            search,
            reply,
        }) {
        Ok(loaded) => Err(wasmtime::Error::new(GuestControlFlow::ExecReplaced(
            Box::new(loaded),
        ))),
        Err(e) => Ok(Err(e)),
    }
}

fn do_waitpid(
    caller: &mut Caller<'_, ProcessHost>,
    target: i32,
    options: u32,
) -> Result<Result<crate::kernel_rpc::WaitResult, Errno>, wasmtime::Error> {
    let nohang = (options & 1) != 0;
    loop {
        if check_signals_caller(caller, true)? {
            return Ok(Err(Errno::EINTR));
        }
        let seen = caller.data().kernel.wake.current();
        let pid = caller.data().pid;
        match caller.data().kernel.call_sync(|reply| KernelCmd::Waitpid {
            pid,
            target,
            options: options | 1,
            host_reap: false,
            reply,
        }) {
            Ok(w) if !w.nothing || nohang => return Ok(Ok(w)),
            Ok(_) => {
                caller
                    .data()
                    .kernel
                    .wake
                    .wait_since(seen, Duration::from_millis(25));
            }
            Err(e) => return Ok(Err(e)),
        }
    }
}

fn do_fd_read(
    caller: &mut Caller<'_, ProcessHost>,
    fd: u32,
    iovs: u32,
    count: u32,
    nread_ptr: u32,
) -> HostRes<u32> {
    if check_signals_caller(caller, true)? {
        return Ok(WASI_EINTR);
    }
    let vectors = match read_iovecs(caller, iovs, count) {
        Ok(v) => v,
        Err(e) => return Ok(abi_to_wasi(e)),
    };
    let kind = match caller.data().fds.get(&fd) {
        Some(e) => e.kind.clone(),
        None => return Ok(WASI_EBADF),
    };
    let mem = match caller.data().mem() {
        Ok(m) => m,
        Err(e) => return Ok(abi_to_wasi(e)),
    };
    let mem_len = mem.byte_len(&*caller);
    for &(ptr, len) in &vectors {
        if (ptr as usize)
            .checked_add(len as usize)
            .is_none_or(|end| end > mem_len)
        {
            return Ok(WASI_EINVAL);
        }
    }
    let total_want: usize = vectors
        .iter()
        .fold(0usize, |acc, &(_, l)| acc.saturating_add(l as usize))
        .min(MAX_IO_BYTES);
    let mut total_read = 0usize;

    match kind {
        GuestFdKind::Kfd {
            kfd,
            readable,
            nonblock,
            device,
            ..
        } if device.as_deref() == Some(abi::overlay::TUN_RDEV) => {
            if !readable {
                return Ok(WASI_EBADF);
            }
            let want = total_want.min(65_536);
            let pid = caller.data().pid;
            loop {
                if check_signals_caller(caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                match caller.data().kernel.call_sync(|reply| KernelCmd::ReadKfd {
                    pid,
                    kfd,
                    offset: None,
                    len: want,
                    reply,
                }) {
                    Ok(bytes) => {
                        let mut off = 0usize;
                        for &(ptr, len) in &vectors {
                            if off >= bytes.len() {
                                break;
                            }
                            let take = (len as usize).min(bytes.len() - off);
                            if take > 0 {
                                if let Err(e) =
                                    mem.write_bytes(&mut *caller, ptr, &bytes[off..off + take])
                                {
                                    return Ok(abi_to_wasi(e));
                                }
                                off += take;
                            }
                        }
                        total_read = off;
                        break;
                    }
                    Err(Errno::EAGAIN) if !nonblock => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
        }
        GuestFdKind::Kfd { kfd, readable, .. } => {
            if !readable {
                return Ok(WASI_EBADF);
            }
            let pid = caller.data().pid;
            for (ptr, len) in vectors {
                if len == 0 {
                    continue;
                }
                let rem = MAX_IO_BYTES.saturating_sub(total_read);
                if rem == 0 {
                    break;
                }
                let req_len = (len as usize).min(rem);
                match caller.data().kernel.call_sync(|reply| KernelCmd::ReadKfd {
                    pid,
                    kfd,
                    offset: None,
                    len: req_len,
                    reply,
                }) {
                    Ok(bytes) => {
                        let got = bytes.len();
                        if let Err(e) = mem.write_bytes(&mut *caller, ptr, &bytes) {
                            return Ok(abi_to_wasi(e));
                        }
                        total_read += got;
                        if got < req_len {
                            break;
                        }
                    }
                    Err(e) => {
                        if total_read > 0 {
                            break;
                        }
                        return Ok(abi_to_wasi(e));
                    }
                }
            }
        }
        GuestFdKind::UnixSock {
            sock_id, nonblock, ..
        } => {
            if total_want > 0 {
                let pid = caller.data().pid;
                loop {
                    if check_signals_caller(caller, true)? {
                        return Ok(WASI_EINTR);
                    }
                    let seen = caller.data().kernel.wake.current();
                    match caller
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::SockRecvMsg {
                            pid,
                            sock_id,
                            max_bytes: total_want,
                            max_fds: 0,
                            flags: 0,
                            reply,
                        }) {
                        Ok(res) => {
                            let mut off = 0usize;
                            for (ptr, len) in &vectors {
                                if off >= res.data.len() {
                                    break;
                                }
                                let take = (*len as usize).min(res.data.len() - off);
                                if let Err(e) =
                                    mem.write_bytes(&mut *caller, *ptr, &res.data[off..off + take])
                                {
                                    return Ok(abi_to_wasi(e));
                                }
                                off += take;
                            }
                            total_read = off;
                            break;
                        }
                        Err(Errno::EAGAIN) if !nonblock => {
                            caller
                                .data()
                                .kernel
                                .wake
                                .wait_since(seen, Duration::from_millis(20));
                        }
                        Err(e) => return Ok(abi_to_wasi(e)),
                    }
                }
            }
        }
        GuestFdKind::InetSock { .. } => return Ok(abi_to_wasi(Errno::ENOTCONN)),
        GuestFdKind::Pipe { handle, nonblock } => {
            if handle.is_writer {
                return Ok(WASI_EBADF);
            }
            if total_want > 0 {
                let mut tmp = vec![0u8; total_want.min(65_536)];
                let got = loop {
                    let ctrl = Arc::clone(&caller.data().signals.ctrl);
                    match handle
                        .buf
                        .read(&mut tmp, nonblock, || should_interrupt_blocking(&ctrl))
                    {
                        Ok(n) => break n,
                        Err(Errno::EINTR) => {
                            if check_signals_caller(caller, true)? {
                                return Ok(WASI_EINTR);
                            }
                        }
                        Err(e) => return Ok(abi_to_wasi(e)),
                    }
                };
                let mut off = 0usize;
                for (ptr, len) in &vectors {
                    if off >= got {
                        break;
                    }
                    let take = (*len as usize).min(got - off);
                    if let Err(e) = mem.write_bytes(&mut *caller, *ptr, &tmp[off..off + take]) {
                        return Ok(abi_to_wasi(e));
                    }
                    off += take;
                }
                total_read = off;
            }
        }
        GuestFdKind::PtyMaster { pty, nonblock } => {
            if total_want > 0 {
                let mut tmp = vec![0u8; total_want.min(65_536)];
                let got = loop {
                    let ctrl = Arc::clone(&caller.data().signals.ctrl);
                    match pty
                        .master_in
                        .read(&mut tmp, nonblock, || should_interrupt_blocking(&ctrl))
                    {
                        Ok(n) => break n,
                        Err(Errno::EINTR) => {
                            if check_signals_caller(caller, true)? {
                                return Ok(WASI_EINTR);
                            }
                        }
                        Err(e) => return Ok(abi_to_wasi(e)),
                    }
                };
                let mut off = 0usize;
                for (ptr, len) in &vectors {
                    if off >= got {
                        break;
                    }
                    let take = (*len as usize).min(got - off);
                    if let Err(e) = mem.write_bytes(&mut *caller, *ptr, &tmp[off..off + take]) {
                        return Ok(abi_to_wasi(e));
                    }
                    off += take;
                }
                total_read = off;
            }
        }
        GuestFdKind::PtySlave {
            pty,
            readable,
            nonblock,
            ..
        } => {
            if !readable {
                return Ok(WASI_EBADF);
            }
            if total_want > 0 {
                let mut tmp = vec![0u8; total_want.min(65_536)];
                let got = loop {
                    let ctrl = Arc::clone(&caller.data().signals.ctrl);
                    match pty
                        .slave_in
                        .read(&mut tmp, nonblock, || should_interrupt_blocking(&ctrl))
                    {
                        Ok(n) => break n,
                        Err(Errno::EINTR) => {
                            if check_signals_caller(caller, true)? {
                                return Ok(WASI_EINTR);
                            }
                        }
                        Err(e) => return Ok(abi_to_wasi(e)),
                    }
                };
                let mut off = 0usize;
                for (ptr, len) in &vectors {
                    if off >= got {
                        break;
                    }
                    let take = (*len as usize).min(got - off);
                    if let Err(e) = mem.write_bytes(&mut *caller, *ptr, &tmp[off..off + take]) {
                        return Ok(abi_to_wasi(e));
                    }
                    off += take;
                }
                total_read = off;
            }
        }
        GuestFdKind::NullIn => {
            total_read = 0;
        }
        GuestFdKind::Preopen | GuestFdKind::HostLog { .. } => return Ok(WASI_EBADF),
    }

    if let Err(e) = caller
        .data()
        .mem()
        .and_then(|m| m.write_u32(&mut *caller, nread_ptr, total_read as u32))
    {
        return Ok(abi_to_wasi(e));
    }
    Ok(0)
}

fn do_fd_write(
    caller: &mut Caller<'_, ProcessHost>,
    fd: u32,
    iovs: u32,
    count: u32,
    nwritten_ptr: u32,
) -> HostRes<u32> {
    if check_signals_caller(caller, true)? {
        return Ok(WASI_EINTR);
    }
    let vectors = match read_iovecs(caller, iovs, count) {
        Ok(v) => v,
        Err(e) => return Ok(abi_to_wasi(e)),
    };
    let kind = match caller.data().fds.get(&fd) {
        Some(e) => e.kind.clone(),
        None => return Ok(WASI_EBADF),
    };
    let mem = match caller.data().mem() {
        Ok(m) => m,
        Err(e) => return Ok(abi_to_wasi(e)),
    };
    let mem_len = mem.byte_len(&*caller);
    for &(ptr, len) in &vectors {
        if (ptr as usize)
            .checked_add(len as usize)
            .is_none_or(|end| end > mem_len)
        {
            return Ok(WASI_EINVAL);
        }
    }
    let raw_total: usize = vectors
        .iter()
        .fold(0usize, |acc, &(_, l)| acc.saturating_add(l as usize));
    let capped_total: usize = raw_total.min(MAX_IO_BYTES);
    let mut payload = Vec::with_capacity(capped_total);
    for &(ptr, len) in &vectors {
        if len == 0 {
            continue;
        }
        let rem = MAX_IO_BYTES.saturating_sub(payload.len());
        if rem == 0 {
            break;
        }
        let take = (len as usize).min(rem) as u32;
        match mem.read_bytes(&*caller, ptr, take) {
            Ok(b) => payload.extend_from_slice(&b),
            Err(e) => return Ok(abi_to_wasi(e)),
        }
    }

    let wrote = match kind {
        GuestFdKind::Kfd {
            kfd,
            writable,
            nonblock,
            device,
            ..
        } if device.as_deref() == Some(abi::overlay::TUN_RDEV) => {
            if !writable {
                return Ok(WASI_EBADF);
            }
            if raw_total > 65_536 {
                return Ok(abi_to_wasi(Errno::EMSGSIZE));
            }
            let pid = caller.data().pid;
            loop {
                if check_signals_caller(caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                match caller.data().kernel.call_sync(|reply| KernelCmd::WriteKfd {
                    pid,
                    kfd,
                    offset: None,
                    data: payload.clone(),
                    reply,
                }) {
                    Ok(n) => break n,
                    Err(Errno::EAGAIN) if !nonblock => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
        }
        GuestFdKind::Kfd { kfd, writable, .. } => {
            if !writable {
                return Ok(WASI_EBADF);
            }
            let pid = caller.data().pid;
            match caller.data().kernel.call_sync(|reply| KernelCmd::WriteKfd {
                pid,
                kfd,
                offset: None,
                data: payload,
                reply,
            }) {
                Ok(n) => n,
                Err(e) => return Ok(abi_to_wasi(e)),
            }
        }
        GuestFdKind::UnixSock {
            sock_id, nonblock, ..
        } => {
            let pid = caller.data().pid;
            loop {
                if check_signals_caller(caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockSendMsg {
                        pid,
                        sock_id,
                        data: payload.clone(),
                        fds: Vec::new(),
                        addr: None,
                        flags: 0,
                        reply,
                    }) {
                    Ok(n) => break n,
                    Err(Errno::EAGAIN) if !nonblock => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(Errno::EPIPE) => {
                        caller.data().signals.queue(13); // SIGPIPE
                        let _ = check_signals_caller(caller, false)?;
                        return Ok(WASI_EPIPE);
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
        }
        GuestFdKind::InetSock { .. } => return Ok(abi_to_wasi(Errno::ENOTCONN)),
        GuestFdKind::Pipe { handle, nonblock } => {
            if !handle.is_writer {
                return Ok(WASI_EBADF);
            }
            loop {
                let ctrl = Arc::clone(&caller.data().signals.ctrl);
                match handle
                    .buf
                    .write(&payload, nonblock, || should_interrupt_blocking(&ctrl))
                {
                    Ok(n) => break n,
                    Err(Errno::EPIPE) => {
                        caller.data().signals.queue(13);
                        let _ = check_signals_caller(caller, false)?;
                        return Ok(WASI_EPIPE);
                    }
                    Err(Errno::EINTR) => {
                        if check_signals_caller(caller, true)? {
                            return Ok(WASI_EINTR);
                        }
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
        }
        GuestFdKind::PtyMaster { pty, .. } => match pty.write_from_master(&payload) {
            Ok(n) => n,
            Err(e) => return Ok(abi_to_wasi(e)),
        },
        GuestFdKind::PtySlave { pty, writable, .. } => {
            if !writable {
                return Ok(WASI_EBADF);
            }
            match pty.write_from_slave(&payload) {
                Ok(n) => n,
                Err(e) => return Ok(abi_to_wasi(e)),
            }
        }
        GuestFdKind::HostLog { fd: log_fd } => {
            if log_fd == 2 {
                eprint!("{}", String::from_utf8_lossy(&payload));
            } else {
                print!("{}", String::from_utf8_lossy(&payload));
            }
            payload.len()
        }
        GuestFdKind::Preopen | GuestFdKind::NullIn => return Ok(WASI_EBADF),
    };

    if let Err(e) = caller
        .data()
        .mem()
        .and_then(|m| m.write_u32(&mut *caller, nwritten_ptr, wrote as u32))
    {
        return Ok(abi_to_wasi(e));
    }
    Ok(0)
}

/// Register every Wasm host import namespace (`os_runtime`, `wasi_snapshot_preview1`, `wasix_32v1`,
/// `os`) onto `linker`.
pub fn register_all(linker: &mut Linker<ProcessHost>) -> wasmtime::Result<()> {
    register_os_runtime(linker)?;
    register_wasi_preview1(linker, "wasi_snapshot_preview1")?;
    register_wasi_preview1(linker, "wasix_32v1")?;
    register_wasix_extensions(linker)?;
    register_os_module(linker, "os")?;
    Ok(())
}

fn register_os_runtime(linker: &mut Linker<ProcessHost>) -> wasmtime::Result<()> {
    linker.func_wrap(
        "os_runtime",
        "memory_grow_pre",
        |mut caller: Caller<'_, ProcessHost>, _mem_idx: i32, delta: i32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let pages = delta as u32;
            let bytes = u64::from(pages).saturating_mul(65_536);
            if bytes == 0 {
                return Ok(delta);
            }
            let desired = caller.data().limiter.linear_bytes.saturating_add(bytes);
            if let Some(lim) = caller.data().limiter.limit_bytes
                && desired > lim as u64
            {
                return Ok(-1);
            }
            let pid = caller.data().pid;
            match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::ReserveMemory {
                    pid,
                    bytes: desired,
                    reply,
                }) {
                Ok(()) => {
                    caller.data_mut().limiter.linear_bytes = desired;
                    caller.data_mut().limiter.grow_reserved = bytes;
                    Ok(delta)
                }
                Err(_) => Ok(-1),
            }
        },
    )?;
    linker.func_wrap(
        "os_runtime",
        "memory_grow_post",
        |mut caller: Caller<'_, ProcessHost>, _mem_idx: i32, result: i32| -> i32 {
            let reserved = caller.data().limiter.grow_reserved;
            if result == -1 && reserved > 0 {
                let next = caller.data().limiter.linear_bytes.saturating_sub(reserved);
                caller.data_mut().limiter.linear_bytes = next;
                let pid = caller.data().pid;
                let _ = caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::ReserveMemory {
                        pid,
                        bytes: next,
                        reply,
                    });
            }
            caller.data_mut().limiter.grow_reserved = 0;
            result
        },
    )?;
    Ok(())
}

fn register_wasi_preview1(linker: &mut Linker<ProcessHost>, module: &str) -> wasmtime::Result<()> {
    linker.func_wrap(
        module,
        "args_sizes_get",
        |mut caller: Caller<'_, ProcessHost>, count_ptr: u32, size_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let count = caller.data().argv.len() as u32;
            let size: u32 = caller
                .data()
                .argv
                .iter()
                .map(|s| (s.len() + 1) as u32)
                .sum();
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if let Err(e) = mem.write_u32(&mut caller, count_ptr, count) {
                return Ok(abi_to_wasi(e));
            }
            if let Err(e) = mem.write_u32(&mut caller, size_ptr, size) {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "args_get",
        |mut caller: Caller<'_, ProcessHost>, argv_ptr: u32, mut buf_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let argv = caller.data().argv.clone();
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            for (i, arg) in argv.iter().enumerate() {
                if let Err(e) = mem.write_u32(&mut caller, argv_ptr + (i as u32) * 4, buf_ptr) {
                    return Ok(abi_to_wasi(e));
                }
                if let Err(e) = mem.write_bytes(&mut caller, buf_ptr, arg.as_bytes()) {
                    return Ok(abi_to_wasi(e));
                }
                if let Err(e) = mem.write_u8(&mut caller, buf_ptr + arg.len() as u32, 0) {
                    return Ok(abi_to_wasi(e));
                }
                buf_ptr += (arg.len() + 1) as u32;
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "environ_sizes_get",
        |mut caller: Caller<'_, ProcessHost>, count_ptr: u32, size_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let count = caller.data().env.len() as u32;
            let size: u32 = caller.data().env.iter().map(|s| (s.len() + 1) as u32).sum();
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if let Err(e) = mem.write_u32(&mut caller, count_ptr, count) {
                return Ok(abi_to_wasi(e));
            }
            if let Err(e) = mem.write_u32(&mut caller, size_ptr, size) {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "environ_get",
        |mut caller: Caller<'_, ProcessHost>, env_ptr: u32, mut buf_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let env = caller.data().env.clone();
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            for (i, item) in env.iter().enumerate() {
                if let Err(e) = mem.write_u32(&mut caller, env_ptr + (i as u32) * 4, buf_ptr) {
                    return Ok(abi_to_wasi(e));
                }
                if let Err(e) = mem.write_bytes(&mut caller, buf_ptr, item.as_bytes()) {
                    return Ok(abi_to_wasi(e));
                }
                if let Err(e) = mem.write_u8(&mut caller, buf_ptr + item.len() as u32, 0) {
                    return Ok(abi_to_wasi(e));
                }
                buf_ptr += (item.len() + 1) as u32;
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "clock_res_get",
        |mut caller: Caller<'_, ProcessHost>, _id: u32, ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            match caller
                .data()
                .mem()
                .and_then(|m| m.write_u64(&mut caller, ptr, 1_000))
            {
                Ok(()) => Ok(0),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "clock_time_get",
        |mut caller: Caller<'_, ProcessHost>, id: u32, _precision: u64, ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let ns: u64 = if id == 0 {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0)
            } else {
                caller.data().boot_instant.elapsed().as_nanos() as u64
            };
            match caller
                .data()
                .mem()
                .and_then(|m| m.write_u64(&mut caller, ptr, ns))
            {
                Ok(()) => Ok(0),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "fd_advise",
        |_: Caller<'_, ProcessHost>, _: u32, _: u64, _: u64, _: u32| -> u32 { 0 },
    )?;
    linker.func_wrap(
        module,
        "fd_allocate",
        |_: Caller<'_, ProcessHost>, _: u32, _: u64, _: u64| -> u32 { 0 },
    )?;
    linker.func_wrap(
        module,
        "fd_close",
        |mut caller: Caller<'_, ProcessHost>, fd: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            match caller.data_mut().close_guest_fd(fd) {
                Ok(()) => Ok(0),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "fd_datasync",
        |mut caller: Caller<'_, ProcessHost>, fd: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let kind = match caller.data().fds.get(&fd) {
                Some(e) => e.kind.clone(),
                None => return Ok(WASI_EBADF),
            };
            if let GuestFdKind::Kfd { kfd, .. } = kind {
                let pid = caller.data().pid;
                return Ok(
                    match caller.data().kernel.call_sync(|reply| KernelCmd::FsyncKfd {
                        pid,
                        kfd,
                        data_only: true,
                        reply,
                    }) {
                        Ok(()) => 0,
                        Err(e) => abi_to_wasi(e),
                    },
                );
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_sync",
        |mut caller: Caller<'_, ProcessHost>, fd: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let kind = match caller.data().fds.get(&fd) {
                Some(e) => e.kind.clone(),
                None => return Ok(WASI_EBADF),
            };
            if let GuestFdKind::Kfd { kfd, .. } = kind {
                let pid = caller.data().pid;
                return Ok(
                    match caller.data().kernel.call_sync(|reply| KernelCmd::FsyncKfd {
                        pid,
                        kfd,
                        data_only: false,
                        reply,
                    }) {
                        Ok(()) => 0,
                        Err(e) => abi_to_wasi(e),
                    },
                );
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_fdstat_get",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let mut buf = [0u8; 24];
            if fd == OS_FD_ROOT as u32 || fd == OS_FD_CWD as u32 {
                buf[0] = WASI_FILETYPE_DIRECTORY;
                buf[8..16].copy_from_slice(&WASI_ALL_RIGHTS.to_le_bytes());
                buf[16..24].copy_from_slice(&WASI_ALL_RIGHTS.to_le_bytes());
            } else {
                let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                    return Ok(WASI_EBADF);
                };
                let (ft, flags, rights) = match &entry.kind {
                    GuestFdKind::Preopen => (WASI_FILETYPE_DIRECTORY, 0u16, WASI_ALL_RIGHTS),
                    GuestFdKind::Kfd {
                        kfd,
                        is_dir,
                        path_only,
                        append,
                        nonblock,
                        device,
                        ..
                    } => {
                        let pid = caller.data().pid;
                        let app = if !*is_dir && !*path_only {
                            caller
                                .data()
                                .kernel
                                .call_sync(|reply| KernelCmd::IsKfdAppend {
                                    pid,
                                    kfd: *kfd,
                                    reply,
                                })
                                .unwrap_or(*append)
                        } else {
                            *append
                        };
                        let ft = if *is_dir {
                            WASI_FILETYPE_DIRECTORY
                        } else if device.is_some() {
                            WASI_FILETYPE_CHARACTER_DEVICE
                        } else {
                            WASI_FILETYPE_REGULAR_FILE
                        };
                        let mut f = 0u16;
                        if app {
                            f |= WASI_FDFLAG_APPEND;
                        }
                        if *nonblock {
                            f |= WASI_FDFLAG_NONBLOCK;
                        }
                        let rights = if device.as_deref() == Some(abi::overlay::TUN_RDEV) {
                            WASI_ALL_RIGHTS & !(WASI_RIGHT_SEEK | WASI_RIGHT_TELL)
                        } else {
                            WASI_ALL_RIGHTS
                        };
                        (ft, f, rights)
                    }
                    GuestFdKind::UnixSock {
                        sock_type,
                        nonblock,
                        ..
                    } => {
                        let ft = if *sock_type == abi::socket::SOCK_DGRAM {
                            WASI_FILETYPE_SOCKET_DGRAM
                        } else {
                            WASI_FILETYPE_SOCKET_STREAM
                        };
                        let f = if *nonblock { WASI_FDFLAG_NONBLOCK } else { 0 };
                        (
                            ft,
                            f,
                            WASI_ALL_RIGHTS & !(WASI_RIGHT_SEEK | WASI_RIGHT_TELL),
                        )
                    }
                    GuestFdKind::InetSock { nonblock, .. } => {
                        let f = if *nonblock { WASI_FDFLAG_NONBLOCK } else { 0 };
                        (
                            WASI_FILETYPE_SOCKET_STREAM,
                            f,
                            WASI_ALL_RIGHTS & !(WASI_RIGHT_SEEK | WASI_RIGHT_TELL),
                        )
                    }
                    GuestFdKind::Pipe { nonblock, .. } => {
                        let f = if *nonblock { WASI_FDFLAG_NONBLOCK } else { 0 };
                        (
                            WASI_FILETYPE_UNKNOWN,
                            f,
                            WASI_ALL_RIGHTS & !(WASI_RIGHT_SEEK | WASI_RIGHT_TELL),
                        )
                    }
                    GuestFdKind::PtyMaster { nonblock, .. } => {
                        let f = if *nonblock { WASI_FDFLAG_NONBLOCK } else { 0 };
                        (
                            WASI_FILETYPE_CHARACTER_DEVICE,
                            f,
                            WASI_ALL_RIGHTS & !(WASI_RIGHT_SEEK | WASI_RIGHT_TELL),
                        )
                    }
                    GuestFdKind::PtySlave {
                        readable,
                        writable,
                        nonblock,
                        ..
                    } => {
                        let f = if *nonblock { WASI_FDFLAG_NONBLOCK } else { 0 };
                        let mut r = WASI_ALL_RIGHTS & !(WASI_RIGHT_SEEK | WASI_RIGHT_TELL);
                        if !*readable {
                            r &= !WASI_RIGHT_READ;
                        }
                        if !*writable {
                            r &= !WASI_RIGHT_WRITE;
                        }
                        (WASI_FILETYPE_CHARACTER_DEVICE, f, r)
                    }
                    GuestFdKind::NullIn | GuestFdKind::HostLog { .. } => (
                        WASI_FILETYPE_CHARACTER_DEVICE,
                        0,
                        WASI_ALL_RIGHTS & !(WASI_RIGHT_SEEK | WASI_RIGHT_TELL),
                    ),
                };
                buf[0] = ft;
                buf[2..4].copy_from_slice(&flags.to_le_bytes());
                buf[8..16].copy_from_slice(&rights.to_le_bytes());
                buf[16..24].copy_from_slice(&WASI_ALL_RIGHTS.to_le_bytes());
            }
            match caller
                .data()
                .mem()
                .and_then(|m| m.write_bytes(&mut caller, ptr, &buf))
            {
                Ok(()) => Ok(0),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "fd_fdstat_set_flags",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, flags: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let f16 = flags as u16;
            if (f16 & !(WASI_FDFLAG_APPEND | WASI_FDFLAG_NONBLOCK)) != 0 {
                return Ok(WASI_EOPNOTSUPP);
            }
            let nb = (f16 & WASI_FDFLAG_NONBLOCK) != 0;
            let app = (f16 & WASI_FDFLAG_APPEND) != 0;
            let pid = caller.data().pid;
            let Some(entry) = caller.data_mut().fds.get_mut(&fd) else {
                return Ok(WASI_EBADF);
            };
            match &mut entry.kind {
                GuestFdKind::Kfd {
                    kfd,
                    append,
                    nonblock,
                    ..
                } => {
                    let k = *kfd;
                    *append = app;
                    *nonblock = nb;
                    let _ = caller
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::SetKfdAppend {
                            pid,
                            kfd: k,
                            append: app,
                            reply,
                        });
                }
                GuestFdKind::UnixSock {
                    sock_id, nonblock, ..
                } => {
                    let sid = *sock_id;
                    *nonblock = nb;
                    let _ = caller
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::SockSetNonblock {
                            pid,
                            sock_id: sid,
                            nonblock: nb,
                            reply,
                        });
                }
                GuestFdKind::Pipe { nonblock, .. }
                | GuestFdKind::InetSock { nonblock, .. }
                | GuestFdKind::PtyMaster { nonblock, .. }
                | GuestFdKind::PtySlave { nonblock, .. } => {
                    *nonblock = nb;
                }
                _ => {}
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_fdstat_set_rights",
        |_: Caller<'_, ProcessHost>, _: u32, _: u64, _: u64| -> u32 { 0 },
    )?;
    linker.func_wrap(
        module,
        "fd_filestat_get",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let pid = caller.data().pid;
            if fd == OS_FD_ROOT as u32 || fd == OS_FD_CWD as u32 {
                let anchor = if fd == OS_FD_ROOT as u32 {
                    KAnchor::Root
                } else {
                    KAnchor::Cwd
                };
                return Ok(
                    match caller.data().kernel.call_sync(|reply| KernelCmd::StatAt {
                        pid,
                        anchor,
                        path: ".".into(),
                        follow: true,
                        reply,
                    }) {
                        Ok(st) => write_filestat(&mut caller, ptr, &st)
                            .err()
                            .map_or(0, abi_to_wasi),
                        Err(e) => abi_to_wasi(e),
                    },
                );
            }
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let st = match entry.kind {
                GuestFdKind::Preopen => {
                    match caller.data().kernel.call_sync(|reply| KernelCmd::StatAt {
                        pid,
                        anchor: KAnchor::Root,
                        path: "/".into(),
                        follow: true,
                        reply,
                    }) {
                        Ok(s) => s,
                        Err(e) => return Ok(abi_to_wasi(e)),
                    }
                }
                GuestFdKind::Kfd { kfd, .. } => match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::FstatKfd { pid, kfd, reply })
                {
                    Ok(s) => s,
                    Err(e) => return Ok(abi_to_wasi(e)),
                },
                GuestFdKind::PtyMaster { pty, .. } => Stat {
                    ino: u64::from(pty.number) + 1,
                    mode: abi::S_IFCHR | 0o620,
                    nlink: 1,
                    ..Stat::default()
                },
                GuestFdKind::PtySlave { pty, .. } => Stat {
                    ino: u64::from(pty.number) + 1,
                    mode: abi::S_IFCHR | 0o620,
                    nlink: 1,
                    ..Stat::default()
                },
                GuestFdKind::UnixSock { sock_id, .. } => Stat {
                    ino: sock_id,
                    mode: abi::S_IFSOCK | 0o777,
                    nlink: 1,
                    ..Stat::default()
                },
                GuestFdKind::InetSock { .. } => Stat {
                    ino: 0,
                    mode: abi::S_IFSOCK | 0o777,
                    nlink: 1,
                    ..Stat::default()
                },
                _ => Stat {
                    mode: abi::S_IFCHR | 0o666,
                    nlink: 1,
                    ..Stat::default()
                },
            };
            Ok(write_filestat(&mut caller, ptr, &st)
                .err()
                .map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        module,
        "fd_filestat_set_size",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, size: u64| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let Some(GuestFdKind::Kfd { kfd, .. }) =
                caller.data().fds.get(&fd).map(|e| &e.kind).cloned()
            else {
                return Ok(WASI_EINVAL);
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::FtruncateKfd {
                        pid,
                        kfd,
                        size,
                        reply,
                    }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "fd_filestat_set_times",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         atim: u64,
         mtim: u64,
         fstflags: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let atime = decode_wasi_time(atim, 1, 2, fstflags);
            let mtime = decode_wasi_time(mtim, 4, 8, fstflags);
            let pid = caller.data().pid;
            if fd == OS_FD_ROOT as u32 || fd == OS_FD_CWD as u32 {
                let anchor = if fd == OS_FD_ROOT as u32 {
                    KAnchor::Root
                } else {
                    KAnchor::Cwd
                };
                return Ok(
                    match caller
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::UtimensAt {
                            pid,
                            anchor,
                            path: ".".into(),
                            atime,
                            mtime,
                            follow: false,
                            reply,
                        }) {
                        Ok(()) => 0,
                        Err(e) => abi_to_wasi(e),
                    },
                );
            }
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            match entry.kind {
                GuestFdKind::Kfd { kfd, .. } => Ok(
                    match caller
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::FutimensKfd {
                            pid,
                            kfd,
                            atime,
                            mtime,
                            reply,
                        }) {
                        Ok(()) => 0,
                        Err(e) => abi_to_wasi(e),
                    },
                ),
                _ => Ok(WASI_EINVAL),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "fd_pread",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         iovs: u32,
         count: u32,
         offset: u64,
         nread_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let vectors = match read_iovecs(&caller, iovs, count) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let Some(GuestFdKind::Kfd { kfd, device, .. }) =
                caller.data().fds.get(&fd).map(|e| e.kind.clone())
            else {
                return Ok(WASI_ESPIPE);
            };
            if device.as_deref() == Some(abi::overlay::TUN_RDEV) {
                return Ok(WASI_ESPIPE);
            }
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mem_len = mem.byte_len(&caller);
            for &(ptr, len) in &vectors {
                if (ptr as usize)
                    .checked_add(len as usize)
                    .is_none_or(|end| end > mem_len)
                {
                    return Ok(WASI_EINVAL);
                }
            }
            let pid = caller.data().pid;
            let mut at = offset;
            let mut total = 0usize;
            for (ptr, len) in vectors {
                if len == 0 {
                    continue;
                }
                let rem = MAX_IO_BYTES.saturating_sub(total);
                if rem == 0 {
                    break;
                }
                let req_len = (len as usize).min(rem);
                match caller.data().kernel.call_sync(|reply| KernelCmd::ReadKfd {
                    pid,
                    kfd,
                    offset: Some(at),
                    len: req_len,
                    reply,
                }) {
                    Ok(bytes) => {
                        let got = bytes.len();
                        if let Err(e) = mem.write_bytes(&mut caller, ptr, &bytes) {
                            return Ok(abi_to_wasi(e));
                        }
                        total += got;
                        at += got as u64;
                        if got < req_len {
                            break;
                        }
                    }
                    Err(e) => {
                        if total > 0 {
                            break;
                        }
                        return Ok(abi_to_wasi(e));
                    }
                }
            }
            if let Err(e) = caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, nread_ptr, total as u32))
            {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_prestat_get",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32| -> HostRes<u32> {
            let is_pre = caller
                .data()
                .fds
                .get(&fd)
                .is_some_and(|e| matches!(e.kind, GuestFdKind::Preopen));
            if !is_pre {
                return Ok(WASI_EBADF);
            }
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let _ = mem.write_u8(&mut caller, ptr, 0);
            let _ = mem.write_u32(&mut caller, ptr + 4, 1);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_prestat_dir_name",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32, len: u32| -> HostRes<u32> {
            let is_pre = caller
                .data()
                .fds
                .get(&fd)
                .is_some_and(|e| matches!(e.kind, GuestFdKind::Preopen));
            if !is_pre {
                return Ok(WASI_EBADF);
            }
            if len >= 1
                && let Err(e) = caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_bytes(&mut caller, ptr, b"/"))
            {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_pwrite",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         iovs: u32,
         count: u32,
         offset: u64,
         nwritten_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let vectors = match read_iovecs(&caller, iovs, count) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let Some(GuestFdKind::Kfd { kfd, device, .. }) =
                caller.data().fds.get(&fd).map(|e| e.kind.clone())
            else {
                return Ok(WASI_ESPIPE);
            };
            if device.as_deref() == Some(abi::overlay::TUN_RDEV) {
                return Ok(WASI_ESPIPE);
            }
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mem_len = mem.byte_len(&caller);
            for &(ptr, len) in &vectors {
                if (ptr as usize)
                    .checked_add(len as usize)
                    .is_none_or(|end| end > mem_len)
                {
                    return Ok(WASI_EINVAL);
                }
            }
            let pid = caller.data().pid;
            let mut at = offset;
            let mut total = 0usize;
            for (ptr, len) in vectors {
                if len == 0 {
                    continue;
                }
                let rem = MAX_IO_BYTES.saturating_sub(total);
                if rem == 0 {
                    break;
                }
                let take = (len as usize).min(rem) as u32;
                let bytes = match mem.read_bytes(&caller, ptr, take) {
                    Ok(b) => b,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                match caller.data().kernel.call_sync(|reply| KernelCmd::WriteKfd {
                    pid,
                    kfd,
                    offset: Some(at),
                    data: bytes,
                    reply,
                }) {
                    Ok(n) => {
                        total += n;
                        at += n as u64;
                        if n < take as usize {
                            break;
                        }
                    }
                    Err(e) => {
                        if total > 0 {
                            break;
                        }
                        return Ok(abi_to_wasi(e));
                    }
                }
            }
            if let Err(e) = caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, nwritten_ptr, total as u32))
            {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_read",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         iovs: u32,
         count: u32,
         nread_ptr: u32|
         -> HostRes<u32> { do_fd_read(&mut caller, fd, iovs, count, nread_ptr) },
    )?;
    linker.func_wrap(
        module,
        "fd_readdir",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         buf_ptr: u32,
         buf_len: u32,
         cookie: u64,
         used_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let pid = caller.data().pid;
            let entries = if fd == OS_FD_ROOT as u32
                || fd == OS_FD_CWD as u32
                || caller
                    .data()
                    .fds
                    .get(&fd)
                    .is_some_and(|e| matches!(e.kind, GuestFdKind::Preopen))
            {
                let anchor = if fd == OS_FD_CWD as u32 {
                    KAnchor::Cwd
                } else {
                    KAnchor::Root
                };
                let opened = match caller.data().kernel.call_sync(|reply| KernelCmd::OpenAt {
                    pid,
                    anchor,
                    path: ".".into(),
                    flags: O_RDONLY | O_DIRECTORY,
                    mode: 0,
                    cloexec: true,
                    reply,
                }) {
                    Ok(o) => o,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let res = caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::ReaddirKfd {
                        pid,
                        kfd: opened.kfd,
                        reply,
                    });
                let _ = caller.data().kernel.call_sync(|reply| KernelCmd::CloseKfd {
                    pid,
                    kfd: opened.kfd,
                    reply,
                });
                match res {
                    Ok(e) => e,
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            } else {
                let Some(GuestFdKind::Kfd { kfd, is_dir, .. }) =
                    caller.data().fds.get(&fd).map(|e| e.kind.clone())
                else {
                    return Ok(WASI_ENOTDIR);
                };
                if !is_dir {
                    return Ok(WASI_ENOTDIR);
                }
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::ReaddirKfd { pid, kfd, reply })
                {
                    Ok(e) => e,
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            };

            let mut all = Vec::with_capacity(entries.len() + 2);
            all.push((0u64, WASI_FILETYPE_DIRECTORY, ".".to_string()));
            all.push((0u64, WASI_FILETYPE_DIRECTORY, "..".to_string()));
            for e in entries {
                all.push((e.ino, e.filetype, e.name));
            }

            let mut out = Vec::new();
            let cap = buf_len as usize;
            let start = cookie as usize;
            for (idx, (ino, ft, name)) in all.into_iter().enumerate().skip(start) {
                if out.len() >= cap {
                    break;
                }
                let nb = name.as_bytes();
                let mut rec = Vec::with_capacity(24 + nb.len());
                rec.extend_from_slice(&((idx + 1) as u64).to_le_bytes());
                rec.extend_from_slice(&ino.to_le_bytes());
                rec.extend_from_slice(&(nb.len() as u32).to_le_bytes());
                rec.push(ft);
                rec.extend_from_slice(&[0, 0, 0]);
                rec.extend_from_slice(nb);
                let take = rec.len().min(cap - out.len());
                out.extend_from_slice(&rec[..take]);
            }

            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if let Err(e) = mem.write_bytes(&mut caller, buf_ptr, &out) {
                return Ok(abi_to_wasi(e));
            }
            if let Err(e) = mem.write_u32(&mut caller, used_ptr, out.len() as u32) {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_renumber",
        |mut caller: Caller<'_, ProcessHost>, from: u32, to: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if to >= FD_MAX {
                return Ok(WASI_EBADF);
            }
            if from == to {
                return Ok(if caller.data().fds.contains_key(&from) {
                    0
                } else {
                    WASI_EBADF
                });
            }
            let Some(src) = caller.data().fds.get(&from).cloned() else {
                return Ok(WASI_EBADF);
            };
            // In `wasix_32v1`, `fd_renumber` acts like `dup2` (keeps `from` open); in preview1
            // it moves `from` -> `to`. Since `wasix_32v1` overrides `fd_renumber` below, here we
            // implement standard preview1 move semantics.
            if caller.data().fds.contains_key(&to) {
                let _ = caller.data_mut().close_guest_fd(to);
            }
            caller.data_mut().fds.remove(&from);
            caller.data_mut().fds.insert(to, src);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "fd_seek",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         offset: i64,
         whence: u32,
         out_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let Some(GuestFdKind::Kfd {
                kfd,
                is_dir,
                path_only,
                device,
                ..
            }) = caller.data().fds.get(&fd).map(|e| e.kind.clone())
            else {
                return Ok(WASI_ESPIPE);
            };
            if is_dir || path_only {
                return Ok(WASI_EBADF);
            }
            if device.as_deref() == Some(abi::overlay::TUN_RDEV) {
                return Ok(WASI_ESPIPE);
            }
            let pid = caller.data().pid;
            match caller.data().kernel.call_sync(|reply| KernelCmd::SeekKfd {
                pid,
                kfd,
                offset,
                whence: whence as u8,
                reply,
            }) {
                Ok(pos) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u64(&mut caller, out_ptr, pos))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "fd_tell",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, out_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let Some(GuestFdKind::Kfd {
                kfd,
                is_dir,
                path_only,
                device,
                ..
            }) = caller.data().fds.get(&fd).map(|e| e.kind.clone())
            else {
                return Ok(WASI_ESPIPE);
            };
            if is_dir || path_only {
                return Ok(WASI_EBADF);
            }
            if device.as_deref() == Some(abi::overlay::TUN_RDEV) {
                return Ok(WASI_ESPIPE);
            }
            let pid = caller.data().pid;
            match caller.data().kernel.call_sync(|reply| KernelCmd::SeekKfd {
                pid,
                kfd,
                offset: 0,
                whence: 1,
                reply,
            }) {
                Ok(pos) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u64(&mut caller, out_ptr, pos))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "fd_write",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         iovs: u32,
         count: u32,
         nwritten_ptr: u32|
         -> HostRes<u32> { do_fd_write(&mut caller, fd, iovs, count, nwritten_ptr) },
    )?;
    linker.func_wrap(
        module,
        "path_create_directory",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32, len: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, fd, &raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::MkdirAt {
                    pid,
                    anchor,
                    path: raw,
                    mode: 0o777,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "path_filestat_get",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         flags: u32,
         ptr: u32,
         len: u32,
         out_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, fd, &raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::StatAt {
                    pid,
                    anchor,
                    path: raw,
                    follow: (flags & WASI_LOOKUP_SYMLINK_FOLLOW) != 0,
                    reply,
                }) {
                    Ok(st) => write_filestat(&mut caller, out_ptr, &st)
                        .err()
                        .map_or(0, abi_to_wasi),
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "path_filestat_set_times",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         flags: u32,
         ptr: u32,
         len: u32,
         atim: u64,
         mtim: u64,
         fstflags: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, fd, &raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            let atime = decode_wasi_time(atim, 1, 2, fstflags);
            let mtime = decode_wasi_time(mtim, 4, 8, fstflags);
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::UtimensAt {
                        pid,
                        anchor,
                        path: raw,
                        atime,
                        mtime,
                        follow: (flags & WASI_LOOKUP_SYMLINK_FOLLOW) != 0,
                        reply,
                    }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "path_link",
        |mut caller: Caller<'_, ProcessHost>,
         fd1: u32,
         flags: u32,
         p1: u32,
         l1: u32,
         fd2: u32,
         p2: u32,
         l2: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let oldpath = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, p1, l1))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let newpath = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, p2, l2))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let a1 = match resolve_anchor(&caller, fd1, &oldpath) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let a2 = match resolve_anchor(&caller, fd2, &newpath) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::LinkAt {
                    pid,
                    from_anchor: a1,
                    from: oldpath,
                    to_anchor: a2,
                    to: newpath,
                    follow: (flags & WASI_LOOKUP_SYMLINK_FOLLOW) != 0,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "path_open",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         dirflags: u32,
         ptr: u32,
         len: u32,
         oflags: u32,
         base: u64,
         _inheriting: u64,
         fdflags: u32,
         out_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            match open_path_at(
                &mut caller,
                fd,
                &raw,
                dirflags,
                oflags,
                base,
                fdflags,
                false,
                0o666,
                0,
            ) {
                Ok(new_fd) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u32(&mut caller, out_ptr, new_fd))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "path_readlink",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         ptr: u32,
         len: u32,
         buf_ptr: u32,
         buf_len: u32,
         used_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, fd, &raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            let target = match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::ReadlinkAt {
                    pid,
                    anchor,
                    path: raw,
                    reply,
                }) {
                Ok(t) => t,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let tb = target.as_bytes();
            let take = tb.len().min(buf_len as usize);
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if let Err(e) = mem.write_bytes(&mut caller, buf_ptr, &tb[..take]) {
                return Ok(abi_to_wasi(e));
            }
            if let Err(e) = mem.write_u32(&mut caller, used_ptr, take as u32) {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "path_remove_directory",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32, len: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, fd, &raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::UnlinkAt {
                    pid,
                    anchor,
                    path: raw,
                    rmdir: true,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "path_rename",
        |mut caller: Caller<'_, ProcessHost>,
         fd1: u32,
         p1: u32,
         l1: u32,
         fd2: u32,
         p2: u32,
         l2: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let oldpath = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, p1, l1))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let newpath = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, p2, l2))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let a1 = match resolve_anchor(&caller, fd1, &oldpath) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let a2 = match resolve_anchor(&caller, fd2, &newpath) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::RenameAt {
                    pid,
                    from_anchor: a1,
                    from: oldpath,
                    to_anchor: a2,
                    to: newpath,
                    noreplace: false,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "path_symlink",
        |mut caller: Caller<'_, ProcessHost>,
         tp: u32,
         tl: u32,
         fd: u32,
         lp: u32,
         ll: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let target = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, tp, tl))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let linkpath = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, lp, ll))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, fd, &linkpath) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SymlinkAt {
                        pid,
                        target,
                        anchor,
                        path: linkpath,
                        reply,
                    }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "path_unlink_file",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32, len: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, fd, &raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::UnlinkAt {
                    pid,
                    anchor,
                    path: raw,
                    rmdir: false,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "poll_oneoff",
        |mut caller: Caller<'_, ProcessHost>,
         input: u32,
         output: u32,
         count: u32,
         events_ptr: u32|
         -> HostRes<u32> {
            if count == 0 || count > 1024 {
                return Ok(WASI_EINVAL);
            }
            struct Sub {
                userdata: u64,
                kind: u8,
                fd: u32,
                deadline: Option<Instant>,
            }
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let now = Instant::now();
            let mut subs = Vec::with_capacity(count as usize);
            for i in 0..count {
                let at = input + i * 48;
                let userdata = match mem.read_u64(&caller, at) {
                    Ok(v) => v,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let kind = match mem.read_u8(&caller, at + 8) {
                    Ok(v) => v,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let fd = match mem.read_u32(&caller, at + 16) {
                    Ok(v) => v,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let deadline = if kind == 0 {
                    let clock_id = fd;
                    let timeout_ns = mem.read_u64(&caller, at + 24).unwrap_or(0);
                    let flags = mem.read_u16(&caller, at + 40).unwrap_or(0);
                    if (flags & 1) != 0 {
                        // Absolute timestamp.
                        let cur_ns = if clock_id == 0 {
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_nanos() as u64)
                                .unwrap_or(0)
                        } else {
                            caller.data().boot_instant.elapsed().as_nanos() as u64
                        };
                        let rem = timeout_ns.saturating_sub(cur_ns);
                        Some(now + Duration::from_nanos(rem))
                    } else {
                        Some(now + Duration::from_nanos(timeout_ns))
                    }
                } else {
                    None
                };
                subs.push(Sub {
                    userdata,
                    kind,
                    fd,
                    deadline,
                });
            }

            let pid = caller.data().pid;
            loop {
                if check_signals_caller(&mut caller, true)? {
                    if subs.iter().all(|s| s.kind == 0) {
                        // `wasi-libc` `clock_nanosleep` converts any non-zero `poll_oneoff` error
                        // (including `EINTR`) into `ENOTSUP`, which panics Rust `std::thread::sleep`.
                        // Complete the clock sleep cleanly after dispatching the signal handler.
                        let mut ev = [0u8; 32];
                        ev[0..8].copy_from_slice(&subs[0].userdata.to_le_bytes());
                        if let Err(e) = mem.write_bytes(&mut caller, output, &ev) {
                            return Ok(abi_to_wasi(e));
                        }
                        if let Err(e) = mem.write_u32(&mut caller, events_ptr, 1) {
                            return Ok(abi_to_wasi(e));
                        }
                        return Ok(0);
                    }
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                let mut ready = 0u32;
                let check_now = Instant::now();
                let mut earliest: Option<Instant> = None;

                for sub in &subs {
                    let mut err = 0u16;
                    let mut nbytes = 0u64;
                    let mut hangup = false;
                    if sub.kind == 0 {
                        if let Some(dl) = sub.deadline
                            && check_now < dl
                        {
                            earliest = Some(earliest.map_or(dl, |e| e.min(dl)));
                            continue;
                        }
                    } else if sub.kind != 1 && sub.kind != 2 {
                        err = WASI_EINVAL as u16;
                    } else if let Some(entry) = caller.data().fds.get(&sub.fd).cloned() {
                        let writing = sub.kind == 2;
                        match entry.kind {
                            GuestFdKind::UnixSock { sock_id, .. } => {
                                match caller.data().kernel.call_sync(|reply| KernelCmd::SockPoll {
                                    pid,
                                    sock_id,
                                    writing,
                                    reply,
                                }) {
                                    Ok(st) => {
                                        if !st.ready {
                                            continue;
                                        }
                                        nbytes = st.nbytes as u64;
                                        hangup = st.hangup;
                                    }
                                    Err(e) => err = abi_to_wasi(e) as u16,
                                }
                            }
                            GuestFdKind::InetSock { .. } => {
                                err = abi_to_wasi(Errno::ENOTCONN) as u16;
                            }
                            GuestFdKind::Pipe { handle, .. } => {
                                if (!writing && handle.is_writer) || (writing && !handle.is_writer)
                                {
                                    err = WASI_EBADF as u16;
                                } else {
                                    let (ok, nb, hu) = handle.buf.poll(writing);
                                    if !ok {
                                        continue;
                                    }
                                    nbytes = nb as u64;
                                    hangup = hu;
                                }
                            }
                            GuestFdKind::PtyMaster { pty, .. } => {
                                if writing {
                                    nbytes = 4096;
                                    hangup = pty.is_hungup();
                                } else {
                                    let (ok, nb, hu) = pty.master_in.poll(false);
                                    if !ok && !pty.is_hungup() {
                                        continue;
                                    }
                                    nbytes = nb as u64;
                                    hangup = hu || pty.is_hungup();
                                }
                            }
                            GuestFdKind::PtySlave { pty, .. } => {
                                if writing {
                                    nbytes = 4096;
                                    hangup = pty.is_hungup();
                                } else {
                                    let (ok, nb, hu) = pty.slave_in.poll(false);
                                    if !ok && !pty.is_hungup() {
                                        continue;
                                    }
                                    nbytes = nb as u64;
                                    hangup = hu || pty.is_hungup();
                                }
                            }
                            GuestFdKind::Kfd { kfd, device, .. }
                                if device.as_deref() == Some(abi::overlay::TUN_RDEV) =>
                            {
                                match caller.data().kernel.call_sync(|reply| KernelCmd::TunPoll {
                                    pid,
                                    kfd,
                                    writing,
                                    reply,
                                }) {
                                    Ok(st) => {
                                        if !st.ready && !st.hangup {
                                            continue;
                                        }
                                        nbytes = st.nbytes as u64;
                                        hangup = st.hangup;
                                    }
                                    Err(e) => err = abi_to_wasi(e) as u16,
                                }
                            }
                            GuestFdKind::Kfd { kfd, device, .. }
                                if device.as_deref().is_some_and(|d| d.starts_with("gui:")) =>
                            {
                                match caller.data().kernel.call_sync(|reply| KernelCmd::GuiPoll {
                                    pid,
                                    kfd,
                                    writing,
                                    reply,
                                }) {
                                    Ok(0) => continue,
                                    Ok(n) => nbytes = n as u64,
                                    Err(e) => err = abi_to_wasi(e) as u16,
                                }
                            }
                            _ => {
                                nbytes = 1;
                            }
                        }
                    } else {
                        err = WASI_EBADF as u16;
                    }

                    let at = output + ready * 32;
                    let mut ev = [0u8; 32];
                    ev[0..8].copy_from_slice(&sub.userdata.to_le_bytes());
                    ev[8..10].copy_from_slice(&err.to_le_bytes());
                    ev[10] = sub.kind;
                    ev[16..24].copy_from_slice(&nbytes.to_le_bytes());
                    ev[24..26].copy_from_slice(&(if hangup { 1u16 } else { 0u16 }).to_le_bytes());
                    if let Err(e) = mem.write_bytes(&mut caller, at, &ev) {
                        return Ok(abi_to_wasi(e));
                    }
                    ready += 1;
                }

                if ready > 0 {
                    if let Err(e) = mem.write_u32(&mut caller, events_ptr, ready) {
                        return Ok(abi_to_wasi(e));
                    }
                    return Ok(0);
                }
                let wait = match earliest {
                    Some(dl) => dl
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(15)),
                    None => Duration::from_millis(15),
                };
                if wait > Duration::ZERO {
                    caller.data().kernel.wake.wait_since(seen, wait);
                }
            }
        },
    )?;
    linker.func_wrap(
        module,
        "proc_exit",
        |_: Caller<'_, ProcessHost>, code: i32| -> HostRes<()> {
            Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code,
                signal: None,
            }))
        },
    )?;
    linker.func_wrap(
        module,
        "proc_raise",
        |mut caller: Caller<'_, ProcessHost>, sig: u32| -> HostRes<u32> {
            let err = caller.data().signals.queue(sig);
            let _ = check_signals_caller(&mut caller, false)?;
            Ok(err)
        },
    )?;
    linker.func_wrap(
        module,
        "random_get",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32, len: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mem_len = mem.byte_len(&caller);
            if (ptr as usize)
                .checked_add(len as usize)
                .is_none_or(|end| end > mem_len)
            {
                return Ok(WASI_EINVAL);
            }
            let mut chunk = [0u8; 65_536];
            let mut off = 0usize;
            let total = len as usize;
            while off < total {
                let take = (total - off).min(chunk.len());
                if let Err(e) = fill_os_random(&mut chunk[..take]) {
                    return Ok(abi_to_wasi(e));
                }
                if let Err(e) = mem.write_bytes(&mut caller, ptr + off as u32, &chunk[..take]) {
                    return Ok(abi_to_wasi(e));
                }
                off += take;
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sched_yield",
        |mut caller: Caller<'_, ProcessHost>| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            std::thread::yield_now();
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sock_accept",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, fdflags: u32, ro_fd: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            match entry.kind {
                GuestFdKind::InetSock { .. } => Ok(WASI_EOPNOTSUPP),
                GuestFdKind::UnixSock {
                    sock_id,
                    sock_type,
                    nonblock,
                } => {
                    let nb_new = (fdflags as u16 & WASI_FDFLAG_NONBLOCK) != 0;
                    let pid = caller.data().pid;
                    loop {
                        if check_signals_caller(&mut caller, true)? {
                            return Ok(WASI_EINTR);
                        }
                        let seen = caller.data().kernel.wake.current();
                        match caller
                            .data()
                            .kernel
                            .call_sync(|reply| KernelCmd::SockAccept {
                                pid,
                                sock_id,
                                nonblock_new: nb_new,
                                reply,
                            }) {
                            Ok(Some((new_sock_id, _peer))) => {
                                let new_fd = match caller.data_mut().alloc_fd(
                                    0,
                                    GuestFdEntry {
                                        kind: GuestFdKind::UnixSock {
                                            sock_id: new_sock_id,
                                            sock_type,
                                            nonblock: nb_new,
                                        },
                                        cloexec: false,
                                    },
                                ) {
                                    Ok(f) => f,
                                    Err(e) => {
                                        let _ = caller.data().kernel.try_call_sync(|reply| {
                                            KernelCmd::SockClose {
                                                pid,
                                                sock_id: new_sock_id,
                                                reply,
                                            }
                                        });
                                        return Ok(abi_to_wasi(e));
                                    }
                                };
                                let write_res = caller
                                    .data()
                                    .mem()
                                    .and_then(|m| m.write_u32(&mut caller, ro_fd, new_fd));
                                if let Err(e) = write_res {
                                    if let Some(removed) = caller.data_mut().fds.remove(&new_fd) {
                                        caller.data().drop_fd_kind(removed.kind);
                                    }
                                    return Ok(abi_to_wasi(e));
                                }
                                return Ok(0);
                            }
                            Ok(None) if nonblock => return Ok(WASI_EAGAIN),
                            Ok(None) => {
                                caller
                                    .data()
                                    .kernel
                                    .wake
                                    .wait_since(seen, Duration::from_millis(20));
                            }
                            Err(e) => return Ok(abi_to_wasi(e)),
                        }
                    }
                }
                _ => Ok(abi_to_wasi(Errno::ENOTSOCK)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "sock_recv",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         ri_data: u32,
         ri_data_len: u32,
         ri_flags: u32,
         ro_datalen: u32,
         ro_flags: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let ri_f = ri_flags as u16;
            if (ri_f & !3) != 0 {
                return Ok(WASI_EINVAL);
            }
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let (sock_id, nonblock) = match entry.kind {
                GuestFdKind::UnixSock {
                    sock_id, nonblock, ..
                } => (sock_id, nonblock),
                GuestFdKind::InetSock { .. } => return Ok(abi_to_wasi(Errno::ENOTCONN)),
                _ => return Ok(abi_to_wasi(Errno::ENOTSOCK)),
            };
            let vectors = match read_iovecs(&caller, ri_data, ri_data_len) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let total_want: usize = vectors
                .iter()
                .map(|&(_, l)| l as usize)
                .sum::<usize>()
                .min(MAX_IO_BYTES);
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let peek = (ri_f & 1) != 0;
            let waitall = (ri_f & 2) != 0 && !peek;
            let recv_flags = if peek { abi::socket::MSG_PEEK } else { 0 };
            let pid = caller.data().pid;
            let mut gathered = Vec::new();
            if total_want > 0 {
                loop {
                    if check_signals_caller(&mut caller, true)? {
                        if !gathered.is_empty() {
                            break;
                        }
                        return Ok(WASI_EINTR);
                    }
                    let want_now = total_want.saturating_sub(gathered.len());
                    if want_now == 0 {
                        break;
                    }
                    let seen = caller.data().kernel.wake.current();
                    match caller
                        .data()
                        .kernel
                        .call_sync(|reply| KernelCmd::SockRecvMsg {
                            pid,
                            sock_id,
                            max_bytes: want_now,
                            max_fds: 0,
                            flags: recv_flags,
                            reply,
                        }) {
                        Ok(res) => {
                            if res.data.is_empty() {
                                break;
                            }
                            gathered.extend_from_slice(&res.data);
                            if !waitall || gathered.len() >= total_want {
                                break;
                            }
                        }
                        Err(Errno::EAGAIN) if !nonblock => {
                            if !gathered.is_empty() && !waitall {
                                break;
                            }
                            caller
                                .data()
                                .kernel
                                .wake
                                .wait_since(seen, Duration::from_millis(20));
                        }
                        Err(e) => {
                            if !gathered.is_empty() {
                                break;
                            }
                            return Ok(abi_to_wasi(e));
                        }
                    }
                }
            }
            let mut off = 0usize;
            for (ptr, len) in &vectors {
                if off >= gathered.len() {
                    break;
                }
                let take = (*len as usize).min(gathered.len() - off);
                if let Err(e) = mem.write_bytes(&mut caller, *ptr, &gathered[off..off + take]) {
                    return Ok(abi_to_wasi(e));
                }
                off += take;
            }
            if let Err(e) = mem.write_u32(&mut caller, ro_datalen, off as u32) {
                return Ok(abi_to_wasi(e));
            }
            if let Err(e) = mem.write_u16(&mut caller, ro_flags, 0) {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sock_send",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         si_data: u32,
         si_data_len: u32,
         si_flags: u32,
         ro_datalen: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if si_flags != 0 {
                return Ok(WASI_EINVAL);
            }
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let (sock_id, nonblock) = match entry.kind {
                GuestFdKind::UnixSock {
                    sock_id, nonblock, ..
                } => (sock_id, nonblock),
                GuestFdKind::InetSock { .. } => return Ok(abi_to_wasi(Errno::ENOTCONN)),
                _ => return Ok(abi_to_wasi(Errno::ENOTSOCK)),
            };
            let vectors = match read_iovecs(&caller, si_data, si_data_len) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mut payload = Vec::new();
            for (ptr, len) in &vectors {
                if payload.len().saturating_add(*len as usize) > MAX_IO_BYTES {
                    return Ok(WASI_EINVAL);
                }
                match mem.read_bytes(&caller, *ptr, *len) {
                    Ok(chunk) => payload.extend_from_slice(&chunk),
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
            let pid = caller.data().pid;
            let sent = loop {
                if check_signals_caller(&mut caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockSendMsg {
                        pid,
                        sock_id,
                        data: payload.clone(),
                        fds: Vec::new(),
                        addr: None,
                        flags: MSG_NOSIGNAL,
                        reply,
                    }) {
                    Ok(n) => break n,
                    Err(Errno::EAGAIN) if !nonblock => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            };
            if let Err(e) = mem.write_u32(&mut caller, ro_datalen, sent as u32) {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sock_shutdown",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, how: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let posix_how = match how as u8 {
                1 => abi::socket::SHUT_RD,
                2 => abi::socket::SHUT_WR,
                3 => abi::socket::SHUT_RDWR,
                _ => return Ok(WASI_EINVAL),
            };
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let sock_id = match entry.kind {
                GuestFdKind::UnixSock { sock_id, .. } => sock_id,
                GuestFdKind::InetSock { .. } => return Ok(abi_to_wasi(Errno::ENOTCONN)),
                _ => return Ok(abi_to_wasi(Errno::ENOTSOCK)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockShutdown {
                        pid,
                        sock_id,
                        how: posix_how,
                        reply,
                    }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    Ok(())
}

fn read_wasix_lines(
    caller: &Caller<'_, ProcessHost>,
    ptr: u32,
    len: u32,
) -> Result<Vec<String>, Errno> {
    let text = caller.data().mem()?.read_str(caller, ptr, len)?;
    Ok(text
        .split(['\n', '\r'])
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

fn read_wasix_pointer_strings(
    caller: &Caller<'_, ProcessHost>,
    ptr: u32,
    len: u32,
) -> Result<Vec<String>, Errno> {
    let mem = caller.data().mem()?;
    let mut out = Vec::new();
    for i in 0..len {
        let s_ptr = mem.read_u32(caller, ptr + i * 4)?;
        if s_ptr == 0 {
            break;
        }
        // Read NUL-terminated C string.
        let mut bytes = Vec::new();
        let mut cur = s_ptr;
        loop {
            let b = mem.read_u8(caller, cur)?;
            if b == 0 {
                break;
            }
            bytes.push(b);
            cur += 1;
            if bytes.len() > 128 * 1024 {
                return Err(Errno::E2BIG);
            }
        }
        out.push(String::from_utf8(bytes).map_err(|_| Errno::EINVAL)?);
    }
    Ok(out)
}

fn register_wasix_extensions(linker: &mut Linker<ProcessHost>) -> wasmtime::Result<()> {
    const M: &str = "wasix_32v1";

    linker.func_wrap(
        M,
        "proc_exit2",
        |_: Caller<'_, ProcessHost>, code: i32| -> HostRes<()> {
            Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code,
                signal: None,
            }))
        },
    )?;
    linker.func_wrap(
        M,
        "proc_id",
        |mut caller: Caller<'_, ProcessHost>, out_ptr: u32| -> HostRes<u32> {
            let pid = caller.data().pid;
            Ok(caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, out_ptr, pid))
                .err()
                .map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        M,
        "proc_parent",
        |mut caller: Caller<'_, ProcessHost>, target: u32, out_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let pid = caller.data().pid;
            match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::GetProcParent { pid, target, reply })
            {
                Ok(ppid) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u32(&mut caller, out_ptr, ppid))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "proc_signal",
        |mut caller: Caller<'_, ProcessHost>, target: u32, sig: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let pid = caller.data().pid;
            let res = caller.data().kernel.call_sync(|reply| KernelCmd::Kill {
                pid,
                target: (target as i32).to_string(),
                signal: sig as u8,
                reply,
            });
            let _ = check_signals_caller(&mut caller, false)?;
            Ok(res.err().map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        M,
        "proc_signals_sizes_get",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32| -> u32 {
            caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, ptr, 0))
                .err()
                .map_or(0, abi_to_wasi)
        },
    )?;
    linker.func_wrap(
        M,
        "proc_signals_get",
        |_: Caller<'_, ProcessHost>, _: u32, _: u32| -> u32 { 0 },
    )?;
    linker.func_wrap(
        M,
        "proc_fork",
        |mut caller: Caller<'_, ProcessHost>, _copy: u32, pid_ptr: u32| -> HostRes<u32> {
            // Rewinding path: return child pid (in parent) or 0 (in child).
            if let Some(get_state) = caller.data().asyncify.get_state.clone()
                && get_state.call(&mut caller, ()).unwrap_or(0) == 2
            {
                if let Some(stop) = caller.data().asyncify.stop_rewind.clone() {
                    let _ = stop.call(&mut caller, ());
                }
                if let Some(AsyncifyAnswer::Fork { pid, errno }) =
                    caller.data_mut().asyncify.answer.take()
                {
                    if errno != 0 {
                        return Ok(errno);
                    }
                    return Ok(caller
                        .data()
                        .mem()
                        .and_then(|m| m.write_u32(&mut caller, pid_ptr, pid))
                        .err()
                        .map_or(0, abi_to_wasi));
                }
                return Ok(WASI_EIO);
            }
            if !caller.data().asyncify.able {
                return Ok(WASI_ENOSYS);
            }
            let at = caller.data().asyncify.region_at;
            let end = caller.data().asyncify.region_end;
            let Some(scratch) = caller.data().asyncify.scratch_mem else {
                return Ok(WASI_ENOSYS);
            };
            {
                let data = scratch.data_mut(&mut caller);
                let a = at as usize;
                data[a..a + 4].copy_from_slice(&(at + 8).to_le_bytes());
                data[a + 4..a + 8].copy_from_slice(&end.to_le_bytes());
            }
            caller.data_mut().asyncify.pending = Some(AsyncifyPending::Fork);
            if let Some(start) = caller.data().asyncify.start_unwind.clone() {
                let _ = start.call(&mut caller, at as i32);
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "proc_exec",
        |mut caller: Caller<'_, ProcessHost>, np: u32, nl: u32, ap: u32, al: u32| -> HostRes<()> {
            let name = caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, np, nl))
                .unwrap_or_default();
            let argv = read_wasix_lines(&caller, ap, al).unwrap_or_default();
            let env = caller.data().env.clone();
            let search = !name.contains('/');
            let _ = do_execve(&mut caller, name, argv, env, search)?;
            Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code: 127,
                signal: None,
            }))
        },
    )?;
    linker.func_wrap(
        M,
        "proc_exec2",
        |mut caller: Caller<'_, ProcessHost>,
         np: u32,
         nl: u32,
         ap: u32,
         al: u32,
         ep: u32,
         el: u32|
         -> HostRes<()> {
            let name = caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, np, nl))
                .unwrap_or_default();
            let argv = read_wasix_lines(&caller, ap, al).unwrap_or_default();
            let env = read_wasix_lines(&caller, ep, el).unwrap_or_default();
            let search = !name.contains('/');
            let _ = do_execve(&mut caller, name, argv, env, search)?;
            Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code: 127,
                signal: None,
            }))
        },
    )?;
    linker.func_wrap(
        M,
        "proc_exec3",
        |mut caller: Caller<'_, ProcessHost>,
         np: u32,
         nl: u32,
         ap: u32,
         al: u32,
         ep: u32,
         el: u32,
         search: u32,
         pp: u32,
         pl: u32|
         -> HostRes<u32> {
            let name = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, np, nl))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let argv = match read_wasix_lines(&caller, ap, al) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mut env = match read_wasix_lines(&caller, ep, el) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let path_val = caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, pp, pl))
                .unwrap_or_default();
            if search != 0 && !path_val.is_empty() {
                env.retain(|e| !e.starts_with("PATH="));
                env.push(format!("PATH={path_val}"));
            }
            let do_search = search != 0 && !name.contains('/');
            match do_execve(&mut caller, name, argv, env, do_search)? {
                Ok(()) => Ok(0),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "proc_exec4",
        |mut caller: Caller<'_, ProcessHost>,
         np: u32,
         nl: u32,
         ap: u32,
         al: u32,
         ep: u32,
         el: u32,
         search: u32,
         pp: u32,
         pl: u32|
         -> HostRes<u32> {
            let name = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, np, nl))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let argv = match read_wasix_pointer_strings(&caller, ap, al) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mut env = match read_wasix_pointer_strings(&caller, ep, el) {
                Ok(v) => v,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let path_val = caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, pp, pl))
                .unwrap_or_default();
            if search != 0 && !path_val.is_empty() {
                env.retain(|e| !e.starts_with("PATH="));
                env.push(format!("PATH={path_val}"));
            }
            let do_search = search != 0 && !name.contains('/');
            match do_execve(&mut caller, name, argv, env, do_search)? {
                Ok(()) => Ok(0),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "proc_join",
        |mut caller: Caller<'_, ProcessHost>,
         pid_ptr: u32,
         flags: u32,
         status_ptr: u32|
         -> HostRes<u32> {
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let tag = match mem.read_u8(&caller, pid_ptr) {
                Ok(t) => t,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if tag > 1 {
                return Ok(WASI_EINVAL);
            }
            let target = if tag == 1 {
                mem.read_i32(&caller, pid_ptr + 4).unwrap_or(-1)
            } else {
                -1
            };
            let res = match do_waitpid(&mut caller, target, flags & 3)? {
                Ok(w) => w,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let _ = mem.write_bytes(&mut caller, status_ptr, &[0u8; 6]);
            if res.nothing {
                let _ = mem.write_u8(&mut caller, pid_ptr, 0);
                let _ = mem.write_u32(&mut caller, pid_ptr + 4, 0);
                return Ok(0);
            }
            let _ = mem.write_u8(&mut caller, pid_ptr, 1);
            let _ = mem.write_u32(&mut caller, pid_ptr + 4, res.pid);
            if res.stopped {
                let _ = mem.write_u8(&mut caller, status_ptr, 3);
                let _ = mem.write_u8(
                    &mut caller,
                    status_ptr + 4,
                    ((res.status >> 8) & 0xff) as u8,
                );
            } else if let Some(sig) = res.signal {
                let _ = mem.write_u8(&mut caller, status_ptr, 2);
                let _ = mem.write_u8(&mut caller, status_ptr + 4, sig);
            } else {
                let code = ((res.status >> 8) & 0xff) as u16;
                let _ = mem.write_u8(&mut caller, status_ptr, 1);
                let _ = mem.write_u16(&mut caller, status_ptr + 2, code);
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "callback_signal",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32, len: u32| {
            if let Ok(name) = caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                caller.data_mut().signals.callback = Some(name);
            }
        },
    )?;
    linker.func_wrap(
        M,
        "fd_renumber",
        |mut caller: Caller<'_, ProcessHost>, from: u32, to: u32| -> HostRes<u32> {
            // WASIX `fd_renumber` has dup2 semantics (duplicates `from` to `to`, keeping `from`).
            let _ = check_signals_caller(&mut caller, false)?;
            if to >= FD_MAX {
                return Ok(WASI_EBADF);
            }
            let Some(src) = caller.data().fds.get(&from).cloned() else {
                return Ok(WASI_EBADF);
            };
            if from == to {
                return Ok(0);
            }
            let duped = match caller.data().duplicate_fd_kind(&src.kind, false) {
                Ok(k) => k,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if caller.data().fds.contains_key(&to) {
                let _ = caller.data_mut().close_guest_fd(to);
            }
            caller.data_mut().fds.insert(
                to,
                GuestFdEntry {
                    kind: duped,
                    cloexec: false,
                },
            );
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "fd_dup",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, out_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let Some(src) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let new_fd = match caller.data().lowest_fd(0) {
                Ok(f) => f,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let duped = match caller.data().duplicate_fd_kind(&src.kind, false) {
                Ok(k) => k,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            caller.data_mut().fds.insert(
                new_fd,
                GuestFdEntry {
                    kind: duped,
                    cloexec: false,
                },
            );
            Ok(caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, out_ptr, new_fd))
                .err()
                .map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        M,
        "fd_dup2",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         min: u32,
         cloexec: u32,
         out_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let Some(src) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let new_fd = match caller.data().lowest_fd(min) {
                Ok(f) => f,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let ce = cloexec != 0;
            let duped = match caller.data().duplicate_fd_kind(&src.kind, ce) {
                Ok(k) => k,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            caller.data_mut().fds.insert(
                new_fd,
                GuestFdEntry {
                    kind: duped,
                    cloexec: ce,
                },
            );
            Ok(caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, out_ptr, new_fd))
                .err()
                .map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        M,
        "fd_pipe",
        |mut caller: Caller<'_, ProcessHost>, r_ptr: u32, w_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let (rfd, wfd) = match caller.data().lowest_fd_pair() {
                Ok(p) => p,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let (rh, wh) = PipeHandle::pair();
            caller.data_mut().fds.insert(
                rfd,
                GuestFdEntry {
                    kind: GuestFdKind::Pipe {
                        handle: rh,
                        nonblock: false,
                    },
                    cloexec: false,
                },
            );
            caller.data_mut().fds.insert(
                wfd,
                GuestFdEntry {
                    kind: GuestFdKind::Pipe {
                        handle: wh,
                        nonblock: false,
                    },
                    cloexec: false,
                },
            );
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let _ = mem.write_u32(&mut caller, r_ptr, rfd);
            let _ = mem.write_u32(&mut caller, w_ptr, wfd);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "fd_fdflags_get",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, ptr: u32| -> HostRes<u32> {
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let ce = if let GuestFdKind::Kfd { kfd, .. } = entry.kind {
                let pid = caller.data().pid;
                caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::GetKfdCloexec { pid, kfd, reply })
                    .unwrap_or(entry.cloexec)
            } else {
                entry.cloexec
            };
            Ok(caller
                .data()
                .mem()
                .and_then(|m| m.write_u16(&mut caller, ptr, if ce { 1 } else { 0 }))
                .err()
                .map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        M,
        "fd_fdflags_set",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, flags: u32| -> HostRes<u32> {
            if (flags & !1) != 0 {
                return Ok(WASI_EINVAL);
            }
            let ce = (flags & 1) != 0;
            let pid = caller.data().pid;
            let Some(entry) = caller.data_mut().fds.get_mut(&fd) else {
                return Ok(WASI_EBADF);
            };
            entry.cloexec = ce;
            if let GuestFdKind::Kfd { kfd, .. } = entry.kind {
                let _ = caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SetKfdCloexec {
                        pid,
                        kfd,
                        cloexec: ce,
                        reply,
                    });
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "path_open2",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         dirflags: u32,
         ptr: u32,
         len: u32,
         oflags: u32,
         base: u64,
         _inheriting: u64,
         fdflags: u32,
         extra: u32,
         out_ptr: u32|
         -> HostRes<u32> {
            if (extra & !1) != 0 {
                return Ok(WASI_EINVAL);
            }
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let ext = if (extra & 1) != 0 { O_CLOEXEC } else { 0 };
            match open_path_at(
                &mut caller,
                fd,
                &raw,
                dirflags,
                oflags,
                base,
                fdflags,
                false,
                0o666,
                ext,
            ) {
                Ok(new_fd) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u32(&mut caller, out_ptr, new_fd))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "getcwd",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32, len_ptr: u32| -> HostRes<u32> {
            let pid = caller.data().pid;
            let cwd = match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::Getcwd { pid, reply })
            {
                Ok(c) => c,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let room = match mem.read_u32(&caller, len_ptr) {
                Ok(r) => r,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let need = (cwd.len() + 1) as u32;
            let _ = mem.write_u32(&mut caller, len_ptr, need);
            if need > room {
                return Ok(WASI_ERANGE);
            }
            if let Err(e) = mem.write_bytes(&mut caller, ptr, cwd.as_bytes()) {
                return Ok(abi_to_wasi(e));
            }
            let _ = mem.write_u8(&mut caller, ptr + cwd.len() as u32, 0);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "chdir",
        |caller: Caller<'_, ProcessHost>, ptr: u32, len: u32| -> HostRes<u32> {
            let path = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::Chdir { pid, path, reply })
                {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        M,
        "tty_get",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32| -> HostRes<u32> {
            let pty = caller.data().fds.get(&0).and_then(|e| match &e.kind {
                GuestFdKind::PtySlave { pty, .. } => Some(Arc::clone(&pty.pty)),
                _ => None,
            });
            let Some(pty) = pty else {
                return Ok(WASI_ENOTTY);
            };
            let ws = pty.winsize();
            let t = pty.termios();
            let mut buf = [0u8; 24];
            buf[0..4].copy_from_slice(&u32::from(ws.columns).to_le_bytes());
            buf[4..8].copy_from_slice(&u32::from(ws.rows).to_le_bytes());
            buf[8..12].copy_from_slice(&u32::from(ws.width).to_le_bytes());
            buf[12..16].copy_from_slice(&u32::from(ws.height).to_le_bytes());
            for i in 0u32..3 {
                let is_tty = caller
                    .data()
                    .fds
                    .get(&i)
                    .is_some_and(|e| matches!(e.kind, GuestFdKind::PtySlave { .. }));
                buf[16 + i as usize] = u8::from(is_tty);
            }
            buf[19] = u8::from(t.echo());
            buf[20] = u8::from(t.canonical());
            buf[21] = u8::from((t.iflag & iflag::IGNCR) != 0);
            Ok(caller
                .data()
                .mem()
                .and_then(|m| m.write_bytes(&mut caller, ptr, &buf))
                .err()
                .map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        M,
        "tty_set",
        |caller: Caller<'_, ProcessHost>, ptr: u32| -> HostRes<u32> {
            let pty = caller.data().fds.get(&0).and_then(|e| match &e.kind {
                GuestFdKind::PtySlave { pty, .. } => Some(Arc::clone(&pty.pty)),
                _ => None,
            });
            let Some(pty) = pty else {
                return Ok(WASI_ENOTTY);
            };
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let echo = mem.read_u8(&caller, ptr + 19).unwrap_or(0) != 0;
            let canon = mem.read_u8(&caller, ptr + 20).unwrap_or(0) != 0;
            let igncr = mem.read_u8(&caller, ptr + 21).unwrap_or(0) != 0;
            let mut t: Termios = pty.termios();
            if echo {
                t.lflag |= lflag::ECHO;
            } else {
                t.lflag &= !lflag::ECHO;
            }
            if canon {
                t.lflag |= lflag::ICANON;
            } else {
                t.lflag &= !lflag::ICANON;
            }
            if igncr {
                t.iflag |= iflag::IGNCR;
            } else {
                t.iflag &= !iflag::IGNCR;
            }
            Ok(pty.set_termios(t, false).err().map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        M,
        "stack_checkpoint",
        |mut caller: Caller<'_, ProcessHost>, snapshot_ptr: u32, result_ptr: u32| -> HostRes<u32> {
            if let Some(get_state) = caller.data().asyncify.get_state.clone()
                && get_state.call(&mut caller, ()).unwrap_or(0) == 2
            {
                if let Some(stop) = caller.data().asyncify.stop_rewind.clone() {
                    let _ = stop.call(&mut caller, ());
                }
                let val = match caller.data_mut().asyncify.answer.take() {
                    Some(AsyncifyAnswer::Value(v)) => v,
                    _ => 0,
                };
                return Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u64(&mut caller, result_ptr, val))
                    .err()
                    .map_or(0, abi_to_wasi));
            }
            if !caller.data().asyncify.able {
                return Ok(WASI_ENOSYS);
            }
            let sp = caller
                .data()
                .asyncify
                .stack_ptr_global
                .and_then(|g| g.get(&mut caller).i32());
            let at = caller.data().asyncify.region_at;
            let end = caller.data().asyncify.region_end;
            let Some(scratch) = caller.data().asyncify.scratch_mem else {
                return Ok(WASI_ENOSYS);
            };
            {
                let data = scratch.data_mut(&mut caller);
                let a = at as usize;
                data[a..a + 4].copy_from_slice(&(at + 8).to_le_bytes());
                data[a + 4..a + 8].copy_from_slice(&end.to_le_bytes());
            }
            caller.data_mut().asyncify.pending =
                Some(AsyncifyPending::Checkpoint { snapshot_ptr, sp });
            if let Some(start) = caller.data().asyncify.start_unwind.clone() {
                let _ = start.call(&mut caller, at as i32);
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "stack_restore",
        |mut caller: Caller<'_, ProcessHost>, snapshot_ptr: u32, value: u64| -> HostRes<()> {
            let mem = caller
                .data()
                .mem()
                .map_err(|e| wasmtime::Error::msg(format!("{e:?}")))?;
            let id = mem.read_u64(&caller, snapshot_ptr).unwrap_or(0);
            let valid = caller
                .data()
                .snapshots
                .get(&snapshot_ptr)
                .is_some_and(|s| s.id == id);
            if !caller.data().asyncify.able || !valid {
                return Err(wasmtime::Error::new(GuestControlFlow::Exit {
                    code: 128 + 6,
                    signal: Some(6),
                }));
            }
            let at = caller.data().asyncify.region_at;
            let end = caller.data().asyncify.region_end;
            let Some(scratch) = caller.data().asyncify.scratch_mem else {
                return Err(wasmtime::Error::new(GuestControlFlow::Exit {
                    code: 128 + 6,
                    signal: Some(6),
                }));
            };
            {
                let data = scratch.data_mut(&mut caller);
                let a = at as usize;
                data[a..a + 4].copy_from_slice(&(at + 8).to_le_bytes());
                data[a + 4..a + 8].copy_from_slice(&end.to_le_bytes());
            }
            caller.data_mut().asyncify.pending = Some(AsyncifyPending::Restore {
                snapshot_ptr,
                value: if value == 0 { 1 } else { value },
            });
            if let Some(start) = caller.data().asyncify.start_unwind.clone() {
                let _ = start.call(&mut caller, at as i32);
            }
            Ok(())
        },
    )?;
    linker.func_wrap(
        M,
        "thread_id",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32| -> u32 {
            caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, ptr, 1))
                .err()
                .map_or(0, abi_to_wasi)
        },
    )?;
    linker.func_wrap(
        M,
        "thread_signal",
        |mut caller: Caller<'_, ProcessHost>, tid: u32, sig: u32| -> HostRes<u32> {
            if tid != 1 {
                return Ok(WASI_ESRCH);
            }
            let err = caller.data().signals.queue(sig);
            let _ = check_signals_caller(&mut caller, false)?;
            Ok(err)
        },
    )?;
    linker.func_wrap(
        M,
        "thread_exit",
        |_: Caller<'_, ProcessHost>, code: i32| -> HostRes<()> {
            Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code,
                signal: None,
            }))
        },
    )?;
    linker.func_wrap(
        M,
        "thread_parallelism",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32| -> u32 {
            caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, ptr, 1))
                .err()
                .map_or(0, abi_to_wasi)
        },
    )?;
    linker.func_wrap(
        M,
        "futex_wait",
        |mut caller: Caller<'_, ProcessHost>,
         _addr: u32,
         _expected: u32,
         _timeout: u32,
         woken: u32|
         -> u32 {
            let _ = caller
                .data()
                .mem()
                .and_then(|m| m.write_u8(&mut caller, woken, 0));
            0
        },
    )?;
    linker.func_wrap(
        M,
        "futex_wake",
        |mut caller: Caller<'_, ProcessHost>, _addr: u32, woken: u32| -> u32 {
            let _ = caller
                .data()
                .mem()
                .and_then(|m| m.write_u8(&mut caller, woken, 0));
            0
        },
    )?;
    linker.func_wrap(
        M,
        "sock_open",
        |mut caller: Caller<'_, ProcessHost>,
         af: u32,
         ty: u32,
         pt: u32,
         ro_fd: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let af_u8 = af as u8;
            let ty_u8 = ty as u8;
            if af_u8 == abi::net_ctl::WASIX_AF_INET4 || af_u8 == abi::net_ctl::WASIX_AF_INET6 {
                if matches!(
                    ty_u8,
                    abi::net_ctl::WASIX_SOCK_DGRAM | abi::net_ctl::WASIX_SOCK_RAW
                ) || matches!(pt, 1 | 17 | 58)
                {
                    return Ok(abi_to_wasi(Errno::EPROTONOSUPPORT));
                }
                if ty_u8 != abi::net_ctl::WASIX_SOCK_STREAM {
                    return Ok(abi_to_wasi(Errno::EPROTOTYPE));
                }
                if pt != 0 && pt != abi::socket::IPPROTO_TCP {
                    return Ok(abi_to_wasi(Errno::EPROTONOSUPPORT));
                }
                let new_fd = match caller.data_mut().alloc_fd(
                    0,
                    GuestFdEntry {
                        kind: GuestFdKind::InetSock {
                            af: af_u8,
                            sock_type: ty_u8,
                            nonblock: false,
                        },
                        cloexec: false,
                    },
                ) {
                    Ok(f) => f,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let write_res = caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u32(&mut caller, ro_fd, new_fd));
                if let Err(e) = write_res {
                    if let Some(removed) = caller.data_mut().fds.remove(&new_fd) {
                        caller.data().drop_fd_kind(removed.kind);
                    }
                    return Ok(abi_to_wasi(e));
                }
                return Ok(0);
            }
            if af_u8 == abi::net_ctl::WASIX_AF_UNIX {
                if pt != 0 {
                    return Ok(abi_to_wasi(Errno::EPROTONOSUPPORT));
                }
                let unix_ty = match ty_u8 {
                    abi::net_ctl::WASIX_SOCK_STREAM => abi::socket::SOCK_STREAM,
                    abi::net_ctl::WASIX_SOCK_DGRAM => abi::socket::SOCK_DGRAM,
                    abi::net_ctl::WASIX_SOCK_SEQPACKET => abi::socket::SOCK_SEQPACKET,
                    _ => return Ok(abi_to_wasi(Errno::EPROTOTYPE)),
                };
                let pid = caller.data().pid;
                let sock_id = match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockCreate {
                        pid,
                        sock_type: unix_ty,
                        nonblock: false,
                        reply,
                    }) {
                    Ok(id) => id,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let new_fd = match caller.data_mut().alloc_fd(
                    0,
                    GuestFdEntry {
                        kind: GuestFdKind::UnixSock {
                            sock_id,
                            sock_type: unix_ty,
                            nonblock: false,
                        },
                        cloexec: false,
                    },
                ) {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = caller
                            .data()
                            .kernel
                            .try_call_sync(|reply| KernelCmd::SockClose {
                                pid,
                                sock_id,
                                reply,
                            });
                        return Ok(abi_to_wasi(e));
                    }
                };
                let write_res = caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u32(&mut caller, ro_fd, new_fd));
                if let Err(e) = write_res {
                    if let Some(removed) = caller.data_mut().fds.remove(&new_fd) {
                        caller.data().drop_fd_kind(removed.kind);
                    }
                    return Ok(abi_to_wasi(e));
                }
                return Ok(0);
            }
            Ok(abi_to_wasi(Errno::EAFNOSUPPORT))
        },
    )?;
    linker.func_wrap(
        M,
        "sock_connect",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, addr_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let Some(entry) = caller.data().fds.get(&fd).cloned() else {
                return Ok(WASI_EBADF);
            };
            let (af, nonblock) = match entry.kind {
                GuestFdKind::InetSock { af, nonblock, .. } => (af, nonblock),
                GuestFdKind::UnixSock { .. } => return Ok(abi_to_wasi(Errno::EISCONN)),
                _ => return Ok(abi_to_wasi(Errno::ENOTSOCK)),
            };
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let raw = match mem.read_bytes(&caller, addr_ptr, 20) {
                Ok(b) => b,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let sock_addr = match abi::net_ctl::decode_wasix_addr_port(&raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let expected_af = match sock_addr {
                std::net::SocketAddr::V4(_) => abi::net_ctl::WASIX_AF_INET4,
                std::net::SocketAddr::V6(_) => abi::net_ctl::WASIX_AF_INET6,
            };
            if expected_af != af {
                return Ok(abi_to_wasi(Errno::EAFNOSUPPORT));
            }
            let host = sock_addr.ip().to_string();
            let port = sock_addr.port();
            match netd_connect_over_unix(&mut caller, &host, port, nonblock)? {
                Ok(sock_id) => {
                    if let Some(slot) = caller.data_mut().fds.get_mut(&fd) {
                        slot.kind = GuestFdKind::UnixSock {
                            sock_id,
                            sock_type: abi::socket::SOCK_STREAM,
                            nonblock,
                        };
                    } else {
                        let pid = caller.data().pid;
                        let _ = caller
                            .data()
                            .kernel
                            .try_call_sync(|reply| KernelCmd::SockClose {
                                pid,
                                sock_id,
                                reply,
                            });
                        return Ok(WASI_EBADF);
                    }
                    Ok(0)
                }
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "sock_bind",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, _addr_ptr: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::InetSock { .. } | GuestFdKind::UnixSock { .. }) => {
                    Ok(WASI_EOPNOTSUPP)
                }
                Some(_) => Ok(abi_to_wasi(Errno::ENOTSOCK)),
                None => Ok(WASI_EBADF),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "sock_listen",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, _backlog: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::InetSock { .. } | GuestFdKind::UnixSock { .. }) => {
                    Ok(WASI_EOPNOTSUPP)
                }
                Some(_) => Ok(abi_to_wasi(Errno::ENOTSOCK)),
                None => Ok(WASI_EBADF),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "sock_send_to",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         _: u32,
         _: u32,
         _: u32,
         _: u32,
         _: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::InetSock { .. } | GuestFdKind::UnixSock { .. }) => {
                    Ok(abi_to_wasi(Errno::EPROTONOSUPPORT))
                }
                Some(_) => Ok(abi_to_wasi(Errno::ENOTSOCK)),
                None => Ok(WASI_EBADF),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "sock_recv_from",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         _: u32,
         _: u32,
         _: u32,
         _: u32,
         _: u32,
         _: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::InetSock { .. } | GuestFdKind::UnixSock { .. }) => {
                    Ok(abi_to_wasi(Errno::EPROTONOSUPPORT))
                }
                Some(_) => Ok(abi_to_wasi(Errno::ENOTSOCK)),
                None => Ok(WASI_EBADF),
            }
        },
    )?;
    linker.func_wrap(
        M,
        "sock_addr_resolve",
        |mut caller: Caller<'_, ProcessHost>,
         host_ptr: u32,
         host_len: u32,
         port: u32,
         _hints_ptr: u32,
         results_ptr: u32,
         results_len: u32,
         out_count: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let host = match mem.read_str(&caller, host_ptr, host_len) {
                Ok(h) => h,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let ips: Vec<std::net::IpAddr> = if let Ok(ip) = host.trim().parse::<std::net::IpAddr>()
            {
                vec![ip]
            } else {
                match netd_resolve_over_unix(&mut caller, &host, port as u16)? {
                    Ok(addrs) => addrs
                        .into_iter()
                        .filter_map(|s| s.parse::<std::net::IpAddr>().ok())
                        .collect(),
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            };
            let cap = results_len as usize;
            let count = ips.len().min(cap);
            for (idx, ip) in ips.into_iter().take(count).enumerate() {
                let mut rec = [0u8; 18];
                match ip {
                    std::net::IpAddr::V4(v4) => {
                        rec[0] = abi::net_ctl::WASIX_ADDR_INET4;
                        rec[2..6].copy_from_slice(&v4.octets());
                    }
                    std::net::IpAddr::V6(v6) => {
                        rec[0] = abi::net_ctl::WASIX_ADDR_INET6;
                        for (j, seg) in v6.segments().into_iter().enumerate() {
                            rec[2 + j * 2..4 + j * 2].copy_from_slice(&seg.to_le_bytes());
                        }
                    }
                }
                let off = results_ptr.saturating_add((idx * 18) as u32);
                if let Err(e) = mem.write_bytes(&mut caller, off, &rec) {
                    return Ok(abi_to_wasi(e));
                }
            }
            if let Err(e) = mem.write_u32(&mut caller, out_count, count as u32) {
                return Ok(abi_to_wasi(e));
            }
            Ok(0)
        },
    )?;
    linker.func_wrap(
        M,
        "futex_wake_all",
        |mut caller: Caller<'_, ProcessHost>, _addr: u32, woken: u32| -> u32 {
            let _ = caller
                .data()
                .mem()
                .and_then(|m| m.write_u8(&mut caller, woken, 0));
            0
        },
    )?;
    Ok(())
}

fn register_os_module(linker: &mut Linker<ProcessHost>, module: &str) -> wasmtime::Result<()> {
    linker.func_wrap(
        module,
        "gui_dispatch",
        |_: Caller<'_, ProcessHost>| -> HostRes<()> {
            Err(wasmtime::Error::new(GuestControlFlow::Exit {
                code: 0,
                signal: None,
            }))
        },
    )?;
    linker.func_wrap(
        module,
        "gui_paint",
        |_: Caller<'_, ProcessHost>, _: i64, _: u32, _: u32| {},
    )?;
    linker.func_wrap(
        module,
        "gui_resize",
        |_: Caller<'_, ProcessHost>, _: i64, _: u32, _: u32| {},
    )?;

    linker.func_wrap(
        module,
        "open",
        |mut caller: Caller<'_, ProcessHost>,
         ptr: u32,
         len: u32,
         flags: u32,
         mode: u32|
         -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let allowed = 3
                | O_CREAT
                | O_EXCL
                | O_NOCTTY
                | O_TRUNC
                | O_APPEND
                | O_NONBLOCK
                | O_DIRECTORY
                | O_NOFOLLOW
                | O_CLOEXEC
                | O_PATH;
            if (flags & !allowed) != 0 || ((flags & O_PATH) == 0 && (flags & 3) == 3) {
                return Ok(-(WASI_EINVAL as i32));
            }
            let oflags = if (flags & O_CREAT) != 0 {
                WASI_OFLAG_CREAT
            } else {
                0
            } | if (flags & O_EXCL) != 0 {
                WASI_OFLAG_EXCL
            } else {
                0
            } | if (flags & O_TRUNC) != 0 {
                WASI_OFLAG_TRUNC
            } else {
                0
            } | if (flags & O_DIRECTORY) != 0 {
                WASI_OFLAG_DIRECTORY
            } else {
                0
            };
            let rights = match flags & 3 {
                O_RDONLY => WASI_RIGHT_READ,
                O_WRONLY => WASI_RIGHT_WRITE,
                _ => WASI_RIGHT_READ | WASI_RIGHT_WRITE,
            };
            let fdflags = if (flags & O_APPEND) != 0 {
                u32::from(WASI_FDFLAG_APPEND)
            } else {
                0
            } | if (flags & O_NONBLOCK) != 0 {
                u32::from(WASI_FDFLAG_NONBLOCK)
            } else {
                0
            };
            let dirflags = if (flags & O_NOFOLLOW) != 0 {
                0
            } else {
                WASI_LOOKUP_SYMLINK_FOLLOW
            };
            let extra = (flags & O_CLOEXEC) | (flags & O_PATH);
            match open_path_at(
                &mut caller,
                OS_FD_CWD as u32,
                &raw,
                dirflags,
                oflags,
                rights,
                fdflags,
                (flags & O_NOCTTY) != 0,
                (mode & 0o7777) as u16,
                extra,
            ) {
                Ok(fd) => Ok(fd as i32),
                Err(e) => Ok(abi_to_neg_wasi(e)),
            }
        },
    )?;

    // ---- L2 VFS / Mount / Namespace Imports (return 0 | -wasi_errno) ----
    linker.func_wrap(
        module,
        "chdir",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32, len: u32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let path = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => return Ok(abi_to_neg_wasi(Errno::ENOENT)),
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::Chdir { pid, path, reply })
                {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "fchdir",
        |mut caller: Caller<'_, ProcessHost>, fd: i32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if fd < 0 {
                return Ok(abi_to_neg_wasi(Errno::EBADF));
            }
            let kfd = match caller.data().fds.get(&(fd as u32)).map(|e| &e.kind) {
                Some(GuestFdKind::Preopen) => OS_FD_ROOT as u32,
                Some(GuestFdKind::Kfd { kfd, .. }) => *kfd,
                Some(_) => return Ok(abi_to_neg_wasi(Errno::ENOTDIR)),
                None => return Ok(abi_to_neg_wasi(Errno::EBADF)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::Fchdir { pid, kfd, reply })
                {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "getcwd",
        |mut caller: Caller<'_, ProcessHost>, buf_ptr: u32, buf_cap: u32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if buf_cap == 0 {
                return Ok(abi_to_neg_wasi(Errno::EINVAL));
            }
            let pid = caller.data().pid;
            let cwd = match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::Getcwd { pid, reply })
            {
                Ok(c) => c,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let need = cwd.len() + 1;
            if need > buf_cap as usize {
                return Ok(abi_to_neg_wasi(Errno::ERANGE));
            }
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            if let Err(e) = mem.write_bytes(&mut caller, buf_ptr, cwd.as_bytes()) {
                return Ok(abi_to_neg_wasi(e));
            }
            if let Err(e) = mem.write_u8(&mut caller, buf_ptr + cwd.len() as u32, 0) {
                return Ok(abi_to_neg_wasi(e));
            }
            Ok(need as i32)
        },
    )?;
    linker.func_wrap(
        module,
        "chroot",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32, len: u32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let path = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => return Ok(abi_to_neg_wasi(Errno::ENOENT)),
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::Chroot { pid, path, reply })
                {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "mount",
        |mut caller: Caller<'_, ProcessHost>,
         src_ptr: u32,
         src_len: u32,
         tgt_ptr: u32,
         tgt_len: u32,
         fs_ptr: u32,
         fs_len: u32,
         flags: u64,
         data_ptr: u32,
         data_len: u32|
         -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let opt_s = |p: u32, l: u32| -> Result<Option<String>, Errno> {
                if p == 0 && l == 0 {
                    Ok(None)
                } else {
                    Ok(Some(mem.read_str(&caller, p, l)?))
                }
            };
            let source = match opt_s(src_ptr, src_len) {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let target = match mem.read_str(&caller, tgt_ptr, tgt_len) {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => return Ok(abi_to_neg_wasi(Errno::ENOENT)),
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let fstype = match opt_s(fs_ptr, fs_len) {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let data = match opt_s(data_ptr, data_len) {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::Mount {
                    pid,
                    source,
                    target,
                    fstype,
                    flags,
                    data,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "umount2",
        |mut caller: Caller<'_, ProcessHost>,
         tgt_ptr: u32,
         tgt_len: u32,
         flags: u32|
         -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let target = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, tgt_ptr, tgt_len))
            {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => return Ok(abi_to_neg_wasi(Errno::ENOENT)),
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::Umount2 {
                    pid,
                    target,
                    flags,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "statfs",
        |mut caller: Caller<'_, ProcessHost>,
         path_ptr: u32,
         path_len: u32,
         out_ptr: u32|
         -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, path_ptr, path_len))
            {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => return Ok(abi_to_neg_wasi(Errno::ENOENT)),
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let anchor = match resolve_anchor(&caller, OS_FD_CWD as u32, &raw) {
                Ok(a) => a,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            let pid = caller.data().pid;
            match caller.data().kernel.call_sync(|reply| KernelCmd::Statfs {
                pid,
                anchor,
                path: raw,
                reply,
            }) {
                Ok(sfs) => Ok(write_raw_statfs(&mut caller, out_ptr, &sfs.to_raw())
                    .err()
                    .map_or(0, abi_to_neg_wasi)),
                Err(e) => Ok(abi_to_neg_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "fstatfs",
        |mut caller: Caller<'_, ProcessHost>, fd: i32, out_ptr: u32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if fd < 0 {
                return Ok(abi_to_neg_wasi(Errno::EBADF));
            }
            let Some(entry) = caller.data().fds.get(&(fd as u32)).cloned() else {
                return Ok(abi_to_neg_wasi(Errno::EBADF));
            };
            let pid = caller.data().pid;
            let raw = match entry.kind {
                GuestFdKind::Preopen => {
                    match caller.data().kernel.call_sync(|reply| KernelCmd::Statfs {
                        pid,
                        anchor: KAnchor::Root,
                        path: "/".into(),
                        reply,
                    }) {
                        Ok(s) => s.to_raw(),
                        Err(e) => return Ok(abi_to_neg_wasi(e)),
                    }
                }
                GuestFdKind::Kfd { kfd, .. } => match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::Fstatfs { pid, kfd, reply })
                {
                    Ok(s) => s.to_raw(),
                    Err(e) => return Ok(abi_to_neg_wasi(e)),
                },
                GuestFdKind::PtyMaster { .. } | GuestFdKind::PtySlave { .. } => RawStatFs {
                    f_type: abi::fs_magic::DEVPTS_SUPER_MAGIC,
                    f_bsize: 4096,
                    f_frsize: 4096,
                    f_namelen: 255,
                    f_flags: 6,
                    ..RawStatFs::default()
                },
                GuestFdKind::UnixSock { .. } | GuestFdKind::InetSock { .. } => RawStatFs {
                    f_type: 0x534f_434b,
                    f_bsize: 4096,
                    f_frsize: 4096,
                    f_namelen: 255,
                    ..RawStatFs::default()
                },
                GuestFdKind::Pipe { .. } => RawStatFs {
                    f_type: 0x5049_5045,
                    f_bsize: 4096,
                    f_frsize: 4096,
                    f_namelen: 255,
                    ..RawStatFs::default()
                },
                _ => return Ok(abi_to_neg_wasi(Errno::ENOSYS)),
            };
            Ok(write_raw_statfs(&mut caller, out_ptr, &raw)
                .err()
                .map_or(0, abi_to_neg_wasi))
        },
    )?;
    linker.func_wrap(
        module,
        "unshare",
        |mut caller: Caller<'_, ProcessHost>, flags: u32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::Unshare {
                    pid,
                    flags,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "setns",
        |mut caller: Caller<'_, ProcessHost>, fd: i32, nstype: u32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if fd < 0 {
                return Ok(abi_to_neg_wasi(Errno::EBADF));
            }
            let Some(GuestFdKind::Kfd { kfd, .. }) =
                caller.data().fds.get(&(fd as u32)).map(|e| e.kind.clone())
            else {
                return Ok(abi_to_neg_wasi(Errno::EINVAL));
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::Setns {
                    pid,
                    kfd,
                    nstype,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "execve",
        |mut caller: Caller<'_, ProcessHost>, req_ptr: u32, req_len: u32| -> HostRes<i32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if req_len > (1 << 20) {
                return Ok(abi_to_neg_wasi(Errno::E2BIG));
            }
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, req_ptr, req_len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_neg_wasi(e)),
            };
            #[derive(serde::Deserialize)]
            struct ExecReq {
                file: String,
                argv: Vec<String>,
                env: Vec<String>,
                #[serde(default)]
                search: bool,
            }
            let parsed: ExecReq = match serde_json::from_str::<ExecReq>(&raw) {
                Ok(v) if !v.file.is_empty() && !v.argv.is_empty() => v,
                _ => return Ok(abi_to_neg_wasi(Errno::EINVAL)),
            };
            match do_execve(
                &mut caller,
                parsed.file,
                parsed.argv,
                parsed.env,
                parsed.search,
            )? {
                Ok(()) => Ok(abi_to_neg_wasi(Errno::ENOEXEC)),
                Err(e) => Ok(abi_to_neg_wasi(e)),
            }
        },
    )?;

    // ---- Process Groups / Sessions / TTY / Wait / Credentials / Signals ----
    linker.func_wrap(
        module,
        "getpgid",
        |caller: Caller<'_, ProcessHost>, target: i32| -> HostRes<i32> {
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::GetPgid {
                    pid,
                    target,
                    reply,
                }) {
                    Ok(pg) => pg as i32,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "getsid",
        |caller: Caller<'_, ProcessHost>, target: i32| -> HostRes<i32> {
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::GetSid {
                    pid,
                    target,
                    reply,
                }) {
                    Ok(s) => s as i32,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "setpgid",
        |caller: Caller<'_, ProcessHost>, target: i32, pgid: i32| -> HostRes<i32> {
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::SetPgid {
                    pid,
                    target,
                    pgid,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "setsid",
        |caller: Caller<'_, ProcessHost>| -> HostRes<i32> {
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SetSid { pid, reply })
                {
                    Ok(sid) => sid as i32,
                    Err(e) => abi_to_neg_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "tcgetpgrp",
        |caller: Caller<'_, ProcessHost>, fd: u32| -> i32 {
            match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::PtySlave { pty, .. }) => pty.pgrp() as i32,
                Some(GuestFdKind::PtyMaster { pty, .. }) => pty.pgrp() as i32,
                Some(_) => abi_to_neg_wasi(Errno::ENOTTY),
                None => abi_to_neg_wasi(Errno::EBADF),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "tcsetpgrp",
        |caller: Caller<'_, ProcessHost>, fd: u32, pgid: i32| -> i32 {
            if pgid <= 0 {
                return abi_to_neg_wasi(Errno::EINVAL);
            }
            match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::PtySlave { pty, .. }) => {
                    pty.set_pgrp(pgid as u32);
                    0
                }
                Some(GuestFdKind::PtyMaster { pty, .. }) => {
                    pty.set_pgrp(pgid as u32);
                    0
                }
                Some(_) => abi_to_neg_wasi(Errno::ENOTTY),
                None => abi_to_neg_wasi(Errno::EBADF),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "waitpid2",
        |mut caller: Caller<'_, ProcessHost>,
         target: i32,
         status_ptr: u32,
         options: u32|
         -> HostRes<i32> {
            if (options & !11) != 0 {
                return Ok(abi_to_neg_wasi(Errno::EINVAL));
            }
            match do_waitpid(&mut caller, target, options)? {
                Ok(w) => {
                    if w.nothing {
                        return Ok(0);
                    }
                    if status_ptr != 0
                        && let Err(e) = caller
                            .data()
                            .mem()
                            .and_then(|m| m.write_i32(&mut caller, status_ptr, w.status))
                    {
                        return Ok(abi_to_neg_wasi(e));
                    }
                    Ok(w.pid as i32)
                }
                Err(e) => Ok(abi_to_neg_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "waitpid",
        |mut caller: Caller<'_, ProcessHost>, target: u32, status_ptr: u32| -> HostRes<u32> {
            match do_waitpid(&mut caller, target as i32, 0)? {
                Ok(w) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_i32(&mut caller, status_ptr, w.status))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(module, "getuid", |caller: Caller<'_, ProcessHost>| -> u32 {
        let pid = caller.data().pid;
        caller
            .data()
            .kernel
            .call_sync(|reply| KernelCmd::GetCreds { pid, reply })
            .map(|c| c.uid)
            .unwrap_or(0)
    })?;
    linker.func_wrap(module, "getgid", |caller: Caller<'_, ProcessHost>| -> u32 {
        let pid = caller.data().pid;
        caller
            .data()
            .kernel
            .call_sync(|reply| KernelCmd::GetCreds { pid, reply })
            .map(|c| c.gid)
            .unwrap_or(0)
    })?;
    linker.func_wrap(
        module,
        "getgroups",
        |mut caller: Caller<'_, ProcessHost>, count: i32, ptr: u32| -> i32 {
            if count < 0 {
                return abi_to_neg_wasi(Errno::EINVAL);
            }
            let pid = caller.data().pid;
            let groups = caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::GetCreds { pid, reply })
                .map(|c| c.groups)
                .unwrap_or_else(|_| vec![0]);
            if count != 0 && (count as usize) < groups.len() {
                return abi_to_neg_wasi(Errno::EINVAL);
            }
            if count != 0 {
                let mem = match caller.data().mem() {
                    Ok(m) => m,
                    Err(e) => return abi_to_neg_wasi(e),
                };
                for (i, &g) in groups.iter().enumerate() {
                    if let Err(e) = mem.write_u32(&mut caller, ptr + (i as u32) * 4, g) {
                        return abi_to_neg_wasi(e);
                    }
                }
            }
            groups.len() as i32
        },
    )?;
    linker.func_wrap(
        module,
        "sigaction",
        |mut caller: Caller<'_, ProcessHost>, n: u32, kind: i32, mask: u32, flags: u32| -> i32 {
            caller.data_mut().signals.action(n, kind, mask, flags)
        },
    )?;
    linker.func_wrap(
        module,
        "sigmask",
        |mut caller: Caller<'_, ProcessHost>, how: i32, mask: u32| -> u32 {
            let prev = caller.data().signals.mask();
            match how {
                0 => caller.data_mut().signals.set_mask(prev | mask),
                1 => caller.data_mut().signals.set_mask(prev & !mask),
                2 => caller.data_mut().signals.set_mask(mask),
                _ => {}
            }
            prev
        },
    )?;
    linker.func_wrap(
        module,
        "sigpoll",
        |mut caller: Caller<'_, ProcessHost>| -> HostRes<()> {
            let _ = check_signals_caller(&mut caller, false)?;
            Ok(())
        },
    )?;
    linker.func_wrap(
        module,
        "sigpending",
        |caller: Caller<'_, ProcessHost>| -> u32 { caller.data().signals.pending_blocked() },
    )?;
    linker.func_wrap(
        module,
        "sigsuspend",
        |mut caller: Caller<'_, ProcessHost>, mask: u32| -> HostRes<u32> {
            let prev = caller.data().signals.mask();
            caller.data_mut().signals.set_mask(mask);
            let res = loop {
                let before = caller.data().signals.delivered_count;
                let interrupted = check_signals_caller(&mut caller, true)?;
                if interrupted || caller.data().signals.delivered_count != before {
                    break WASI_EINTR;
                }
                caller
                    .data()
                    .signals
                    .ctrl
                    .wait_timeout(Duration::from_millis(50));
            };
            caller.data_mut().signals.set_mask(prev);
            Ok(res)
        },
    )?;
    linker.func_wrap(
        module,
        "posix_spawn",
        |mut caller: Caller<'_, ProcessHost>,
         req_ptr: u32,
         req_len: u32,
         out_pid_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if req_len > (1 << 20) {
                return Ok(WASI_E2BIG);
            }
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, req_ptr, req_len))
            {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            #[derive(serde::Deserialize)]
            struct SpawnJson {
                argv: Vec<String>,
                cwd: String,
                env: Vec<String>,
                #[serde(default)]
                pgroup: Option<u32>,
                #[serde(default)]
                cgroup: Option<String>,
                #[serde(default)]
                dup2: Vec<[u32; 2]>,
                #[serde(default)]
                stdin: String,
                #[serde(rename = "serviceGrant", default)]
                service_grant: Option<ServiceGrantSpec>,
                #[serde(default)]
                setsid: bool,
                #[serde(default)]
                ctty_fd: Option<u32>,
            }
            let req: SpawnJson = match serde_json::from_str::<SpawnJson>(&raw) {
                Ok(r) if !r.argv.is_empty() && !r.argv[0].is_empty() => r,
                _ => return Ok(WASI_EINVAL),
            };

            // Build inherited descriptor table with `dup2`, `stdin`, and `FD_CLOEXEC` filtering.
            let mut inherited = caller.data().fds.clone();
            let mut dup_kfds_map: std::collections::BTreeMap<u32, (u32, bool)> =
                std::collections::BTreeMap::new();
            let mut clear_cloexec_kfds: Vec<u32> = Vec::new();
            let mut overwritten_kfds: Vec<u32> = Vec::new();
            let input_action = req.dup2.iter().any(|&[_, to]| to == 0);
            for &[from, to] in &req.dup2 {
                let Some(src) = caller.data().fds.get(&from).cloned() else {
                    return Ok(WASI_EBADF);
                };
                if from != to {
                    if !dup_kfds_map.contains_key(&to)
                        && let Some(prev) = inherited.get(&to)
                        && !prev.cloexec
                        && let GuestFdKind::Kfd { kfd, .. } = prev.kind
                    {
                        overwritten_kfds.push(kfd);
                    }
                    dup_kfds_map.remove(&to);
                    if let GuestFdKind::Kfd { kfd, .. } = src.kind {
                        dup_kfds_map.insert(to, (kfd, false));
                    }
                    inherited.insert(
                        to,
                        GuestFdEntry {
                            kind: src.kind,
                            cloexec: false,
                        },
                    );
                } else if let Some(e) = inherited.get_mut(&to) {
                    e.cloexec = false;
                    if let GuestFdKind::Kfd { kfd, .. } = e.kind {
                        clear_cloexec_kfds.push(kfd);
                    }
                }
            }
            inherited.retain(|_, e| !e.cloexec);
            if !input_action && req.stdin == "null" {
                if !dup_kfds_map.contains_key(&0)
                    && let Some(prev) = inherited.get(&0)
                    && let GuestFdKind::Kfd { kfd, .. } = prev.kind
                {
                    overwritten_kfds.push(kfd);
                }
                dup_kfds_map.remove(&0);
                inherited.insert(
                    0,
                    GuestFdEntry {
                        kind: GuestFdKind::NullIn,
                        cloexec: false,
                    },
                );
            }
            let still_used_kfds: std::collections::HashSet<u32> = inherited
                .iter()
                .filter(|(gfd, _)| !dup_kfds_map.contains_key(gfd))
                .filter_map(|(_, e)| match e.kind {
                    GuestFdKind::Kfd { kfd, .. } => Some(kfd),
                    _ => None,
                })
                .collect();
            let mut close_kfds: Vec<u32> = Vec::new();
            for kfd in overwritten_kfds {
                if !still_used_kfds.contains(&kfd) && !close_kfds.contains(&kfd) {
                    close_kfds.push(kfd);
                }
            }
            let dup_kfds: Vec<(u32, u32, bool)> = dup_kfds_map
                .into_iter()
                .map(|(to, (src_kfd, cloexec))| (to, src_kfd, cloexec))
                .collect();

            let ctty = req.ctty_fd.and_then(|cfd| {
                inherited.get(&cfd).and_then(|e| match &e.kind {
                    GuestFdKind::PtySlave { pty, .. } => Some(pty.number),
                    _ => None,
                })
            });

            let spawn_req = SpawnProcessReq {
                parent_pid: caller.data().pid,
                argv: req.argv,
                env: req.env,
                cwd: req.cwd,
                pgroup: req.pgroup,
                cgroup: req.cgroup,
                service_grant: req.service_grant,
                umask: caller.data().umask,
                fds: inherited,
                dup_kfds,
                close_kfds,
                clear_cloexec_kfds,
                signals: Some(caller.data().signals.snapshot()),
                ctty,
                setsid: req.setsid,
                host_owned: false,
                host_uid: None,
            };
            let kernel = caller.data().kernel.clone();
            let runtime = Arc::clone(&caller.data().runtime);
            match spawn_and_launch(&kernel, &runtime, spawn_req) {
                Ok(child_pid) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_u32(&mut caller, out_pid_ptr, child_pid))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "umask",
        |mut caller: Caller<'_, ProcessHost>, mask: u32| -> u32 {
            let next = (mask & 0o777) as u16;
            let pid = caller.data().pid;
            let prev = caller.data().kernel.call_sync(|reply| KernelCmd::SetUmask {
                pid,
                umask: next,
                reply,
            });
            caller.data_mut().umask = next;
            u32::from(prev)
        },
    )?;
    linker.func_wrap(
        module,
        "sys",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32, len: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let raw = match caller
                .data()
                .mem()
                .and_then(|m| m.read_str(&caller, ptr, len))
            {
                Ok(s) => s,
                Err(_) => {
                    caller.data_mut().sys_reply = b"{\"results\":[]}".to_vec();
                    return Ok(caller.data().sys_reply.len() as u32);
                }
            };
            let calls: Vec<Call> = serde_json::from_str(&raw).unwrap_or_default();
            let pid = caller.data().pid;
            let umask = caller.data().umask;
            let guest_fds = caller.data().guest_fd_map();
            let results = caller.data().kernel.call_sync(|reply| KernelCmd::SysBatch {
                pid,
                umask,
                calls,
                guest_fds,
                reply,
            });
            let encoded = serde_json::to_vec(&abi::Results { results })
                .unwrap_or_else(|_| b"{\"results\":[]}".to_vec());
            let n = encoded.len() as u32;
            caller.data_mut().sys_reply = encoded;
            Ok(n)
        },
    )?;
    linker.func_wrap(
        module,
        "reply",
        |mut caller: Caller<'_, ProcessHost>, ptr: u32| {
            let data = caller.data().sys_reply.clone();
            let _ = caller
                .data()
                .mem()
                .and_then(|m| m.write_bytes(&mut caller, ptr, &data));
        },
    )?;

    // ---- All 13 AF_UNIX / SCM_RIGHTS / SO_PEERCRED Imports ----
    linker.func_wrap(
        module,
        "sock_socket",
        |mut caller: Caller<'_, ProcessHost>,
         domain: u32,
         sock_type: u32,
         protocol: u32,
         out_fd_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if domain != abi::socket::AF_UNIX {
                return Ok(WASI_EAFNOSUPPORT);
            }
            if protocol != 0 {
                return Ok(WASI_EPROTONOSUPPORT);
            }
            let type_mask = 0xfu32;
            if (sock_type & !(type_mask | abi::socket::SOCK_NONBLOCK | abi::socket::SOCK_CLOEXEC))
                != 0
            {
                return Ok(WASI_EINVAL);
            }
            let base = sock_type & type_mask;
            let nonblock = (sock_type & abi::socket::SOCK_NONBLOCK) != 0;
            let cloexec = (sock_type & abi::socket::SOCK_CLOEXEC) != 0;
            let fd = match caller.data().lowest_fd(0) {
                Ok(f) => f,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            let sock_id = match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::SockCreate {
                    pid,
                    sock_type: base,
                    nonblock,
                    reply,
                }) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            caller.data_mut().fds.insert(
                fd,
                GuestFdEntry {
                    kind: GuestFdKind::UnixSock {
                        sock_id,
                        sock_type: base,
                        nonblock,
                    },
                    cloexec,
                },
            );
            Ok(caller
                .data()
                .mem()
                .and_then(|m| m.write_u32(&mut caller, out_fd_ptr, fd))
                .err()
                .map_or(0, abi_to_wasi))
        },
    )?;
    linker.func_wrap(
        module,
        "sock_socketpair",
        |mut caller: Caller<'_, ProcessHost>,
         domain: u32,
         sock_type: u32,
         protocol: u32,
         out_fds_ptr: u32|
         -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            if domain != abi::socket::AF_UNIX {
                return Ok(WASI_EAFNOSUPPORT);
            }
            if protocol != 0 {
                return Ok(WASI_EPROTONOSUPPORT);
            }
            let type_mask = 0xfu32;
            let base = sock_type & type_mask;
            let nonblock = (sock_type & abi::socket::SOCK_NONBLOCK) != 0;
            let cloexec = (sock_type & abi::socket::SOCK_CLOEXEC) != 0;
            let (fd_a, fd_b) = match caller.data().lowest_fd_pair() {
                Ok(p) => p,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            let (sock_a, sock_b) =
                match caller.data().kernel.call_sync(|reply| KernelCmd::SockPair {
                    pid,
                    sock_type: base,
                    nonblock,
                    reply,
                }) {
                    Ok(p) => p,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
            caller.data_mut().fds.insert(
                fd_a,
                GuestFdEntry {
                    kind: GuestFdKind::UnixSock {
                        sock_id: sock_a,
                        sock_type: base,
                        nonblock,
                    },
                    cloexec,
                },
            );
            caller.data_mut().fds.insert(
                fd_b,
                GuestFdEntry {
                    kind: GuestFdKind::UnixSock {
                        sock_id: sock_b,
                        sock_type: base,
                        nonblock,
                    },
                    cloexec,
                },
            );
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let _ = mem.write_u32(&mut caller, out_fds_ptr, fd_a);
            let _ = mem.write_u32(&mut caller, out_fds_ptr + 4, fd_b);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sock_bind",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, p: u32, l: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let path = match caller.data().mem().and_then(|m| m.read_str(&caller, p, l)) {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller.data().kernel.call_sync(|reply| KernelCmd::SockBind {
                    pid,
                    sock_id,
                    path,
                    reply,
                }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "sock_listen",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, backlog: u32| -> HostRes<u32> {
            let _ = check_signals_caller(&mut caller, false)?;
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockListen {
                        pid,
                        sock_id,
                        backlog,
                        reply,
                    }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "sock_accept",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         flags: u32,
         out_fd_ptr: u32|
         -> HostRes<u32> {
            if (flags & !(abi::socket::SOCK_NONBLOCK | abi::socket::SOCK_CLOEXEC)) != 0 {
                return Ok(WASI_EINVAL);
            }
            let (sock_id, sock_type, nonblock) = match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::UnixSock {
                    sock_id,
                    sock_type,
                    nonblock,
                }) => (*sock_id, *sock_type, *nonblock),
                Some(_) => return Ok(WASI_ENOTSOCK),
                None => return Ok(WASI_EBADF),
            };
            let nonblock_new = (flags & abi::socket::SOCK_NONBLOCK) != 0;
            let cloexec_new = (flags & abi::socket::SOCK_CLOEXEC) != 0;
            let pid = caller.data().pid;

            loop {
                if check_signals_caller(&mut caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let target_fd = match caller.data().lowest_fd(0) {
                    Ok(f) => f,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let seen = caller.data().kernel.wake.current();
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockAccept {
                        pid,
                        sock_id,
                        nonblock_new,
                        reply,
                    }) {
                    Ok(Some((new_sock_id, _peer))) => {
                        caller.data_mut().fds.insert(
                            target_fd,
                            GuestFdEntry {
                                kind: GuestFdKind::UnixSock {
                                    sock_id: new_sock_id,
                                    sock_type,
                                    nonblock: nonblock_new,
                                },
                                cloexec: cloexec_new,
                            },
                        );
                        return Ok(caller
                            .data()
                            .mem()
                            .and_then(|m| m.write_u32(&mut caller, out_fd_ptr, target_fd))
                            .err()
                            .map_or(0, abi_to_wasi));
                    }
                    Ok(None) if nonblock => return Ok(WASI_EAGAIN),
                    Ok(None) => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
        },
    )?;
    linker.func_wrap(
        module,
        "sock_connect",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, p: u32, l: u32| -> HostRes<u32> {
            let (sock_id, nonblock) = match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::UnixSock {
                    sock_id, nonblock, ..
                }) => (*sock_id, *nonblock),
                Some(_) => return Ok(WASI_ENOTSOCK),
                None => return Ok(WASI_EBADF),
            };
            let path = match caller.data().mem().and_then(|m| m.read_str(&caller, p, l)) {
                Ok(s) => s,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            loop {
                if check_signals_caller(&mut caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockConnect {
                        pid,
                        sock_id,
                        path: path.clone(),
                        reply,
                    }) {
                    Ok(_) => return Ok(0),
                    Err(Errno::EAGAIN) if !nonblock => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
        },
    )?;
    linker.func_wrap(
        module,
        "sock_shutdown",
        |caller: Caller<'_, ProcessHost>, fd: u32, how: u32| -> HostRes<u32> {
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockShutdown {
                        pid,
                        sock_id,
                        how,
                        reply,
                    }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;
    linker.func_wrap(
        module,
        "sock_sendmsg",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         data_ptr: u32,
         data_len: u32,
         fds_ptr: u32,
         fds_len: u32,
         addr_ptr: u32,
         addr_len: u32,
         flags: u32,
         out_sent_ptr: u32|
         -> HostRes<u32> {
            let (sock_id, nonblock) = match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::UnixSock {
                    sock_id, nonblock, ..
                }) => (*sock_id, *nonblock),
                Some(_) => return Ok(WASI_ENOTSOCK),
                None => return Ok(WASI_EBADF),
            };
            if fds_len as usize > abi::socket::SCM_MAX_FD {
                return Ok(WASI_EINVAL);
            }
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let data = if data_len > 0 {
                match mem.read_bytes(&caller, data_ptr, data_len) {
                    Ok(b) => b,
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            } else {
                Vec::new()
            };
            let addr = if addr_len > 0 {
                match mem.read_str(&caller, addr_ptr, addr_len) {
                    Ok(s) => Some(s),
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            } else {
                None
            };
            let mut rights = Vec::with_capacity(fds_len as usize);
            for i in 0..fds_len {
                let gfd = match mem.read_u32(&caller, fds_ptr + i * 4) {
                    Ok(n) => n,
                    Err(e) => return Ok(abi_to_wasi(e)),
                };
                let Some(entry) = caller.data().fds.get(&gfd) else {
                    return Ok(WASI_EBADF);
                };
                let rfd = match &entry.kind {
                    GuestFdKind::Kfd {
                        kfd,
                        is_dir,
                        path_only,
                        readable,
                        writable,
                        append,
                        nonblock,
                        device,
                    } => RightsFd::Kfd {
                        kfd: *kfd,
                        is_dir: *is_dir,
                        path_only: *path_only,
                        readable: *readable,
                        writable: *writable,
                        append: *append,
                        nonblock: *nonblock,
                        device: device.clone(),
                    },
                    GuestFdKind::UnixSock {
                        sock_id, sock_type, ..
                    } => RightsFd::UnixSock {
                        sock_id: *sock_id,
                        sock_type: *sock_type,
                    },
                    GuestFdKind::Pipe { handle, .. } => RightsFd::Pipe {
                        handle: handle.clone(),
                    },
                    GuestFdKind::PtyMaster { pty, .. } => RightsFd::PtyMaster { pty: pty.clone() },
                    GuestFdKind::PtySlave {
                        pty,
                        readable,
                        writable,
                        ..
                    } => RightsFd::PtySlave {
                        pty: pty.clone(),
                        readable: *readable,
                        writable: *writable,
                    },
                    _ => return Ok(WASI_EBADF),
                };
                rights.push(rfd);
            }
            let dontwait = nonblock || (flags & MSG_DONTWAIT) != 0;
            let pid = caller.data().pid;
            loop {
                if check_signals_caller(&mut caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockSendMsg {
                        pid,
                        sock_id,
                        data: data.clone(),
                        fds: rights.clone(),
                        addr: addr.clone(),
                        flags,
                        reply,
                    }) {
                    Ok(sent) => {
                        return Ok(mem
                            .write_u32(&mut caller, out_sent_ptr, sent as u32)
                            .err()
                            .map_or(0, abi_to_wasi));
                    }
                    Err(Errno::EAGAIN) if !dontwait => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(Errno::EPIPE) => {
                        if (flags & MSG_NOSIGNAL) == 0 {
                            caller.data().signals.queue(13);
                            let _ = check_signals_caller(&mut caller, false)?;
                        }
                        return Ok(WASI_EPIPE);
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            }
        },
    )?;
    linker.func_wrap(
        module,
        "sock_recvmsg",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         buf_ptr: u32,
         buf_len: u32,
         fds_ptr: u32,
         fds_cap: u32,
         out_fds_len_ptr: u32,
         out_peer_ptr: u32,
         flags: u32,
         out_recv_ptr: u32,
         out_flags_ptr: u32|
         -> HostRes<u32> {
            let (sock_id, nonblock) = match caller.data().fds.get(&fd).map(|e| &e.kind) {
                Some(GuestFdKind::UnixSock {
                    sock_id, nonblock, ..
                }) => (*sock_id, *nonblock),
                Some(_) => return Ok(WASI_ENOTSOCK),
                None => return Ok(WASI_EBADF),
            };
            let dontwait = nonblock || (flags & MSG_DONTWAIT) != 0;
            let cmsg_cloexec = (flags & MSG_CMSG_CLOEXEC) != 0;
            let avail = (FD_MAX as usize).saturating_sub(caller.data().fds.len());
            let max_fds = (fds_cap as usize).min(avail);
            let pid = caller.data().pid;

            let res = loop {
                if check_signals_caller(&mut caller, true)? {
                    return Ok(WASI_EINTR);
                }
                let seen = caller.data().kernel.wake.current();
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockRecvMsg {
                        pid,
                        sock_id,
                        max_bytes: buf_len as usize,
                        max_fds,
                        flags,
                        reply,
                    }) {
                    Ok(r) => break r,
                    Err(Errno::EAGAIN) if !dontwait => {
                        caller
                            .data()
                            .kernel
                            .wake
                            .wait_since(seen, Duration::from_millis(20));
                    }
                    Err(e) => return Ok(abi_to_wasi(e)),
                }
            };

            let mut installed = Vec::with_capacity(res.fds.len());
            let mut out_flags = res.out_flags;
            for rfd in res.fds {
                let kind = match rfd {
                    RightsFd::Kfd {
                        kfd,
                        is_dir,
                        path_only,
                        readable,
                        writable,
                        append,
                        nonblock,
                        device,
                    } => GuestFdKind::Kfd {
                        kfd,
                        is_dir,
                        path_only,
                        readable,
                        writable,
                        append,
                        nonblock,
                        device,
                    },
                    RightsFd::UnixSock { sock_id, sock_type } => GuestFdKind::UnixSock {
                        sock_id,
                        sock_type,
                        nonblock: false,
                    },
                    RightsFd::Pipe { handle } => GuestFdKind::Pipe {
                        handle,
                        nonblock: false,
                    },
                    RightsFd::PtyMaster { pty } => GuestFdKind::PtyMaster {
                        pty,
                        nonblock: false,
                    },
                    RightsFd::PtySlave {
                        pty,
                        readable,
                        writable,
                    } => GuestFdKind::PtySlave {
                        pty,
                        readable,
                        writable,
                        nonblock: false,
                    },
                };
                match caller.data().lowest_fd(0) {
                    Ok(gfd) => {
                        caller.data_mut().fds.insert(
                            gfd,
                            GuestFdEntry {
                                kind,
                                cloexec: cmsg_cloexec,
                            },
                        );
                        installed.push(gfd);
                    }
                    Err(_) => {
                        caller.data().drop_fd_kind(kind);
                        out_flags |= MSG_CTRUNC;
                    }
                }
            }

            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let take = res.data.len().min(buf_len as usize);
            if take > 0
                && let Err(e) = mem.write_bytes(&mut caller, buf_ptr, &res.data[..take])
            {
                return Ok(abi_to_wasi(e));
            }
            for (i, &gfd) in installed.iter().enumerate() {
                let _ = mem.write_u32(&mut caller, fds_ptr + (i as u32) * 4, gfd);
            }
            let _ = mem.write_u32(&mut caller, out_fds_len_ptr, installed.len() as u32);
            let _ = write_peercred(&mut caller, out_peer_ptr, res.peer_cred);
            let _ = mem.write_u32(&mut caller, out_recv_ptr, res.reported_len as u32);
            let _ = mem.write_u32(&mut caller, out_flags_ptr, out_flags);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sock_peercred",
        |mut caller: Caller<'_, ProcessHost>, fd: u32, out_cred_ptr: u32| -> HostRes<u32> {
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::SockPeerCred {
                    pid,
                    sock_id,
                    reply,
                }) {
                Ok(cred) => Ok(write_peercred(&mut caller, out_cred_ptr, cred)
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "sock_getsockname",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         buf_ptr: u32,
         buf_len: u32,
         out_len_ptr: u32|
         -> HostRes<u32> {
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            let path = match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::SockGetsockname {
                    pid,
                    sock_id,
                    reply,
                }) {
                Ok(p) => p,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pb = path.as_bytes();
            let take = pb.len().min(buf_len as usize);
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if take > 0 {
                let _ = mem.write_bytes(&mut caller, buf_ptr, &pb[..take]);
            }
            let _ = mem.write_u32(&mut caller, out_len_ptr, pb.len() as u32);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sock_getpeername",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         buf_ptr: u32,
         buf_len: u32,
         out_len_ptr: u32|
         -> HostRes<u32> {
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            let path = match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::SockGetpeername {
                    pid,
                    sock_id,
                    reply,
                }) {
                Ok(p) => p,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pb = path.as_bytes();
            let take = pb.len().min(buf_len as usize);
            let mem = match caller.data().mem() {
                Ok(m) => m,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            if take > 0 {
                let _ = mem.write_bytes(&mut caller, buf_ptr, &pb[..take]);
            }
            let _ = mem.write_u32(&mut caller, out_len_ptr, pb.len() as u32);
            Ok(0)
        },
    )?;
    linker.func_wrap(
        module,
        "sock_getsockopt",
        |mut caller: Caller<'_, ProcessHost>,
         fd: u32,
         level: u32,
         optname: u32,
         out_val_ptr: u32|
         -> HostRes<u32> {
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            match caller
                .data()
                .kernel
                .call_sync(|reply| KernelCmd::SockGetsockopt {
                    pid,
                    sock_id,
                    level,
                    optname,
                    reply,
                }) {
                Ok(val) => Ok(caller
                    .data()
                    .mem()
                    .and_then(|m| m.write_i32(&mut caller, out_val_ptr, val))
                    .err()
                    .map_or(0, abi_to_wasi)),
                Err(e) => Ok(abi_to_wasi(e)),
            }
        },
    )?;
    linker.func_wrap(
        module,
        "sock_setsockopt",
        |caller: Caller<'_, ProcessHost>,
         fd: u32,
         level: u32,
         optname: u32,
         val: i32|
         -> HostRes<u32> {
            let sock_id = match sock_id_of(&caller, fd) {
                Ok(id) => id,
                Err(e) => return Ok(abi_to_wasi(e)),
            };
            let pid = caller.data().pid;
            Ok(
                match caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockSetsockopt {
                        pid,
                        sock_id,
                        level,
                        optname,
                        val,
                        reply,
                    }) {
                    Ok(()) => 0,
                    Err(e) => abi_to_wasi(e),
                },
            )
        },
    )?;

    Ok(())
}

fn sock_id_of(caller: &Caller<'_, ProcessHost>, fd: u32) -> Result<u64, Errno> {
    match caller.data().fds.get(&fd).map(|e| &e.kind) {
        Some(GuestFdKind::UnixSock { sock_id, .. }) => Ok(*sock_id),
        Some(_) => Err(Errno::ENOTSOCK),
        None => Err(Errno::EBADF),
    }
}

fn netd_sock_send_all(
    caller: &mut Caller<'_, ProcessHost>,
    sock_id: u64,
    mut bytes: &[u8],
) -> HostRes<Result<(), Errno>> {
    let pid = caller.data().pid;
    while !bytes.is_empty() {
        if check_signals_caller(caller, true)? {
            return Ok(Err(Errno::EINTR));
        }
        let seen = caller.data().kernel.wake.current();
        match caller
            .data()
            .kernel
            .call_sync(|reply| KernelCmd::SockSendMsg {
                pid,
                sock_id,
                data: bytes.to_vec(),
                fds: Vec::new(),
                addr: None,
                flags: MSG_NOSIGNAL,
                reply,
            }) {
            Ok(0) => return Ok(Err(Errno::EPIPE)),
            Ok(n) => bytes = &bytes[n..],
            Err(Errno::EAGAIN) => {
                caller
                    .data()
                    .kernel
                    .wake
                    .wait_since(seen, Duration::from_millis(20));
            }
            Err(e) => return Ok(Err(e)),
        }
    }
    Ok(Ok(()))
}

fn netd_sock_recv_exact(
    caller: &mut Caller<'_, ProcessHost>,
    sock_id: u64,
    len: usize,
) -> HostRes<Result<Vec<u8>, Errno>> {
    let pid = caller.data().pid;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        if check_signals_caller(caller, true)? {
            return Ok(Err(Errno::EINTR));
        }
        let want = len - out.len();
        let seen = caller.data().kernel.wake.current();
        match caller
            .data()
            .kernel
            .call_sync(|reply| KernelCmd::SockRecvMsg {
                pid,
                sock_id,
                max_bytes: want,
                max_fds: 0,
                flags: 0,
                reply,
            }) {
            Ok(res) if res.data.is_empty() => return Ok(Err(Errno::ECONNRESET)),
            Ok(res) => out.extend_from_slice(&res.data),
            Err(Errno::EAGAIN) => {
                caller
                    .data()
                    .kernel
                    .wake
                    .wait_since(seen, Duration::from_millis(20));
            }
            Err(e) => return Ok(Err(e)),
        }
    }
    Ok(Ok(out))
}

fn netd_recv_control_resp(
    caller: &mut Caller<'_, ProcessHost>,
    sock_id: u64,
) -> HostRes<Result<abi::net_ctl::NetdResp, Errno>> {
    let hdr = match netd_sock_recv_exact(caller, sock_id, 4)? {
        Ok(b) => b,
        Err(e) => return Ok(Err(e)),
    };
    let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    if len == 0 || len > abi::net_ctl::NET_CONTROL_MAX_BYTES {
        return Ok(Err(Errno::EIO));
    }
    let body = match netd_sock_recv_exact(caller, sock_id, len)? {
        Ok(b) => b,
        Err(e) => return Ok(Err(e)),
    };
    match serde_json::from_slice::<abi::net_ctl::NetdResp>(&body) {
        Ok(resp) => Ok(Ok(resp)),
        Err(_) => Ok(Err(Errno::EIO)),
    }
}

fn netd_open_and_hello(caller: &mut Caller<'_, ProcessHost>) -> HostRes<Result<u64, Errno>> {
    let pid = caller.data().pid;
    let sock_id = match caller
        .data()
        .kernel
        .call_sync(|reply| KernelCmd::SockCreate {
            pid,
            sock_type: abi::socket::SOCK_STREAM,
            nonblock: false,
            reply,
        }) {
        Ok(id) => id,
        Err(e) => return Ok(Err(e)),
    };
    let close_sock = |c: &Caller<'_, ProcessHost>, sid: u64| {
        let _ = c.data().kernel.try_call_sync(|reply| KernelCmd::SockClose {
            pid,
            sock_id: sid,
            reply,
        });
    };
    loop {
        if check_signals_caller(caller, true)? {
            close_sock(caller, sock_id);
            return Ok(Err(Errno::EINTR));
        }
        let seen = caller.data().kernel.wake.current();
        match caller
            .data()
            .kernel
            .call_sync(|reply| KernelCmd::SockConnect {
                pid,
                sock_id,
                path: abi::net_ctl::NETD_SOCK.to_string(),
                reply,
            }) {
            Ok(_) => break,
            Err(Errno::EAGAIN) => {
                caller
                    .data()
                    .kernel
                    .wake
                    .wait_since(seen, Duration::from_millis(20));
            }
            Err(e) => {
                close_sock(caller, sock_id);
                return Ok(Err(e));
            }
        }
    }
    let hello = match abi::net_ctl::encode_control_frame(&abi::net_ctl::NetdReq::Hello {
        versions: vec![abi::net_ctl::NETD_VERSION],
    }) {
        Ok(b) => b,
        Err(_) => {
            close_sock(caller, sock_id);
            return Ok(Err(Errno::EINVAL));
        }
    };
    if let Err(e) = netd_sock_send_all(caller, sock_id, &hello)? {
        close_sock(caller, sock_id);
        return Ok(Err(e));
    }
    match netd_recv_control_resp(caller, sock_id)? {
        Ok(abi::net_ctl::NetdResp::Welcome { .. }) => Ok(Ok(sock_id)),
        Ok(abi::net_ctl::NetdResp::Error { errno, .. }) => {
            close_sock(caller, sock_id);
            Ok(Err(errno))
        }
        Ok(_) => {
            close_sock(caller, sock_id);
            Ok(Err(Errno::EPROTONOSUPPORT))
        }
        Err(e) => {
            close_sock(caller, sock_id);
            Ok(Err(e))
        }
    }
}

fn netd_connect_over_unix(
    caller: &mut Caller<'_, ProcessHost>,
    host: &str,
    port: u16,
    nonblock: bool,
) -> HostRes<Result<u64, Errno>> {
    let pid = caller.data().pid;
    let sock_id = match netd_open_and_hello(caller)? {
        Ok(id) => id,
        Err(e) => return Ok(Err(e)),
    };
    let close_sock = |c: &Caller<'_, ProcessHost>, sid: u64| {
        let _ = c.data().kernel.try_call_sync(|reply| KernelCmd::SockClose {
            pid,
            sock_id: sid,
            reply,
        });
    };
    let req = match abi::net_ctl::encode_control_frame(&abi::net_ctl::NetdReq::Connect {
        host: host.to_string(),
        port,
        tls: abi::net_ctl::TlsMode::Off,
        mode: abi::net_ctl::StreamMode::Raw,
        timeout_ms: None,
    }) {
        Ok(b) => b,
        Err(_) => {
            close_sock(caller, sock_id);
            return Ok(Err(Errno::EINVAL));
        }
    };
    if let Err(e) = netd_sock_send_all(caller, sock_id, &req)? {
        close_sock(caller, sock_id);
        return Ok(Err(e));
    }
    match netd_recv_control_resp(caller, sock_id)? {
        Ok(abi::net_ctl::NetdResp::Connected { .. }) => {
            if nonblock {
                let _ = caller
                    .data()
                    .kernel
                    .call_sync(|reply| KernelCmd::SockSetNonblock {
                        pid,
                        sock_id,
                        nonblock: true,
                        reply,
                    });
            }
            Ok(Ok(sock_id))
        }
        Ok(abi::net_ctl::NetdResp::Error { errno, .. }) => {
            close_sock(caller, sock_id);
            Ok(Err(errno))
        }
        Ok(_) => {
            close_sock(caller, sock_id);
            Ok(Err(Errno::EIO))
        }
        Err(e) => {
            close_sock(caller, sock_id);
            Ok(Err(e))
        }
    }
}

fn netd_resolve_over_unix(
    caller: &mut Caller<'_, ProcessHost>,
    host: &str,
    port: u16,
) -> HostRes<Result<Vec<String>, Errno>> {
    let pid = caller.data().pid;
    let sock_id = match netd_open_and_hello(caller)? {
        Ok(id) => id,
        Err(e) => return Ok(Err(e)),
    };
    let close_sock = |c: &Caller<'_, ProcessHost>, sid: u64| {
        let _ = c.data().kernel.try_call_sync(|reply| KernelCmd::SockClose {
            pid,
            sock_id: sid,
            reply,
        });
    };
    let req = match abi::net_ctl::encode_control_frame(&abi::net_ctl::NetdReq::Resolve {
        host: host.to_string(),
        port,
    }) {
        Ok(b) => b,
        Err(_) => {
            close_sock(caller, sock_id);
            return Ok(Err(Errno::EINVAL));
        }
    };
    let res = match netd_sock_send_all(caller, sock_id, &req)? {
        Ok(()) => match netd_recv_control_resp(caller, sock_id)? {
            Ok(abi::net_ctl::NetdResp::Resolved { addrs }) => Ok(addrs),
            Ok(abi::net_ctl::NetdResp::Error { errno, .. }) => Err(errno),
            Ok(_) => Err(Errno::EIO),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    close_sock(caller, sock_id);
    Ok(res)
}
