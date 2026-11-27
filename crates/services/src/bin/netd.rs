//! Userspace `netd` outbound stream socket gateway daemon (`/usr/bin/netd`, Phase 10a `#86`).
//!
//! - Binds `/run/netd.sock` (`0666`) and notifies PID 1 (`READY=1\n` on `NOTIFY_SOCKET`)
//!   with ZERO network requests on boot.
//! - Authenticates every local client via kernel `SO_PEERCRED` and passes the accepted
//!   client socket fd via `SCM_RIGHTS` over `/run/net/host.sock` (`peer_cred().uid == 0`).
//! - Uses WASI `poll_oneoff` for low-latency, non-busy-spinning multiplexing of up to 16
//!   concurrent credit-windowed bidirectional streams.
//!
//! WASM32-WASIP1 SAFETY:
//! - NEVER calls `std::process::id()`.
//! - Ignores `SIGPIPE` (`SIG_IGN`) and installs `SA_RESTART` on `SIGHUP`/`SIGINT`/`SIGTERM`.

#[cfg(target_os = "wasi")]
mod runtime {
    use abi::net_ctl::{NET_HOST_SOCK, NETD_SOCK};
    use abi::socket::{SOCK_CLOEXEC, SOCK_NONBLOCK};
    use abi::{Call, Creds, Errno, Error};
    use os_posix::socket::{UnixDatagram, UnixListener, UnixStream};
    use os_services::netd::{ClientSession, HostConnector, MAX_CLIENTS, NetdIo};
    use std::path::Path;
    use std::sync::atomic::{AtomicU32, Ordering};

    const SA_RESTART: u32 = 0x1000_0000;
    const POLL_TIMEOUT_NS: u64 = 15_000_000; // 15 ms

    static STOP: AtomicU32 = AtomicU32::new(0);

    #[unsafe(no_mangle)]
    pub extern "C" fn __os_netd_signal(signal: u32) {
        if matches!(signal, 1 | 2 | 15) {
            let _ = STOP.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
        }
    }

    #[link(wasm_import_module = "wasix_32v1")]
    unsafe extern "C" {
        fn callback_signal(name: *const u8, len: usize);
    }

    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        fn sigaction(signal: u32, kind: u32, mask: u32, flags: u32) -> i32;
    }

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        fn poll_oneoff(
            in_ptr: *const u8,
            out_ptr: *mut u8,
            nsubscriptions: u32,
            nevents: *mut u32,
        ) -> u32;
    }

    fn install_signals() -> Result<(), Error> {
        let name = b"__os_netd_signal";
        // SAFETY: valid exported callback name and scalar signal dispositions.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            let _ = sigaction(13, 1, 0, 0); // SIGPIPE -> SIG_IGN
            for sig in [1, 2, 15] {
                if sigaction(sig, 2, 0, SA_RESTART) < 0 {
                    return Err(Error::because(
                        Errno::EIO,
                        format!("sigaction({sig}) failed"),
                    ));
                }
            }
        }
        Ok(())
    }

    struct WasiUnixStream(UnixStream);

    impl NetdIo for WasiUnixStream {
        fn raw_fd(&self) -> u32 {
            self.0.as_raw_fd()
        }
        fn recv(&self, buf: &mut [u8], flags: u32) -> Result<usize, Errno> {
            self.0.recv(buf, flags)
        }
        fn send(&self, data: &[u8], flags: u32) -> Result<usize, Errno> {
            self.0.send(data, flags)
        }
        fn send_with_fds(&self, data: &[u8], fds: &[u32], flags: u32) -> Result<usize, Errno> {
            self.0.send_with_fds(data, fds, flags)
        }
        fn shutdown(&self, how: u32) -> Result<(), Errno> {
            self.0.shutdown(how)
        }
    }

    struct WasiHostConnector;

    impl HostConnector<WasiUnixStream> for WasiHostConnector {
        fn connect_host(&mut self) -> Result<WasiUnixStream, Errno> {
            let stream = UnixStream::connect(NET_HOST_SOCK)?;
            let peer = stream.peer_cred()?;
            if peer.uid != 0 {
                return Err(Errno::EACCES);
            }
            stream.set_nonblocking(true)?;
            Ok(WasiUnixStream(stream))
        }
    }

    fn io_errno(e: std::io::Error) -> Error {
        Error::because(os_posix::errno_of(&e).unwrap_or(Errno::EIO), e.to_string())
    }

    fn push_clock_sub(subs: &mut Vec<u8>, userdata: u64, timeout_ns: u64) {
        let mut entry = [0u8; 48];
        entry[0..8].copy_from_slice(&userdata.to_le_bytes());
        entry[8] = 0; // CLOCK
        entry[16..20].copy_from_slice(&1u32.to_le_bytes()); // MONOTONIC
        entry[24..32].copy_from_slice(&timeout_ns.to_le_bytes());
        entry[32..40].copy_from_slice(&1_000_000u64.to_le_bytes());
        subs.extend_from_slice(&entry);
    }

    fn push_fd_sub(subs: &mut Vec<u8>, userdata: u64, tag: u8, fd: u32) {
        let mut entry = [0u8; 48];
        entry[0..8].copy_from_slice(&userdata.to_le_bytes());
        entry[8] = tag; // 1 = FD_READ, 2 = FD_WRITE
        entry[16..20].copy_from_slice(&fd.to_le_bytes());
        subs.extend_from_slice(&entry);
    }

    fn poll_wait(listener_fd: u32, accept_room: bool, sessions: &[ClientSession<WasiUnixStream>]) {
        let mut subs = Vec::with_capacity(48 * (2 + sessions.len() * 4));
        let mut count = 0u32;
        push_clock_sub(&mut subs, 0, POLL_TIMEOUT_NS);
        count += 1;
        if accept_room {
            push_fd_sub(&mut subs, 1, 1, listener_fd);
            count += 1;
        }
        for (idx, sess) in sessions.iter().enumerate() {
            let interest = sess.poll_interest();
            let base = (idx as u64 + 1) << 8;
            if interest.client_read {
                push_fd_sub(&mut subs, base | 1, 1, interest.client_fd);
                count += 1;
            }
            if interest.client_write {
                push_fd_sub(&mut subs, base | 2, 2, interest.client_fd);
                count += 1;
            }
            if let Some(hfd) = interest.host_fd {
                if interest.host_read {
                    push_fd_sub(&mut subs, base | 3, 1, hfd);
                    count += 1;
                }
                if interest.host_write {
                    push_fd_sub(&mut subs, base | 4, 2, hfd);
                    count += 1;
                }
            }
        }
        let mut events = vec![0u8; 32 * (count as usize)];
        let mut nevents = 0u32;
        // SAFETY: `subs` has `count * 48` valid bytes and `events` has `count * 32` writable bytes.
        let _ = unsafe { poll_oneoff(subs.as_ptr(), events.as_mut_ptr(), count, &mut nevents) };
    }

    pub fn run() -> Result<(), Error> {
        os_posix::init_preopens().map_err(io_errno)?;
        install_signals()?;
        let creds: Creds = serde_json::from_value(
            os_posix::batch(&[Call::Getcreds])
                .map_err(io_errno)?
                .results
                .remove(0)
                .into_result()?,
        )
        .map_err(|_| Errno::EIO)?;
        if creds.uid != 0 {
            return Err(Error::because(Errno::EPERM, "netd requires uid 0"));
        }

        let dir = Path::new(NETD_SOCK).parent().unwrap();
        match os_posix::mkdir(dir, 0o755) {
            Ok(()) => (),
            Err(e) if os_posix::errno_of(&e) == Some(Errno::EEXIST) => (),
            Err(e) => return Err(io_errno(e)),
        }
        if let Ok(stat) = os_posix::stat(Path::new(NETD_SOCK), false) {
            if stat.mode & abi::S_IFMT != abi::S_IFSOCK || stat.uid != 0 {
                return Err(Errno::EADDRINUSE.into());
            }
            match UnixStream::connect(NETD_SOCK) {
                Err(Errno::ECONNREFUSED) => std::fs::remove_file(NETD_SOCK).map_err(io_errno)?,
                _ => return Err(Errno::EADDRINUSE.into()),
            }
        }

        let listener = UnixListener::bind_with_mode(NETD_SOCK, 0o666)?;
        os_posix::chmod(Path::new(NETD_SOCK), 0o666).map_err(io_errno)?;
        listener.set_nonblocking(true)?;

        // Notify PID 1 readiness with ZERO network calls on boot.
        if let Ok(notify) = std::env::var("NOTIFY_SOCKET")
            && !notify.is_empty()
            && let Ok(dgram) = UnixDatagram::unbound()
        {
            let _ = dgram.send_to(b"READY=1\nSTATUS=netd ready\n", &notify);
        }

        let mut connector = WasiHostConnector;
        let mut sessions: Vec<ClientSession<WasiUnixStream>> = Vec::new();

        while STOP.load(Ordering::SeqCst) == 0 {
            while sessions.len() < MAX_CLIENTS {
                match listener.accept_flags(SOCK_NONBLOCK | SOCK_CLOEXEC) {
                    Ok((socket, peer)) => {
                        sessions.push(ClientSession::new(WasiUnixStream(socket), peer));
                    }
                    Err(Errno::EAGAIN | Errno::EINTR) => break,
                    Err(e) => return Err(e.into()),
                }
            }

            let active = sessions.iter().filter(|s| s.is_active_stream()).count() as u32;
            sessions.retain_mut(|sess| sess.step(&mut connector, active));

            if STOP.load(Ordering::SeqCst) != 0 {
                break;
            }
            poll_wait(
                listener.as_raw_fd(),
                sessions.len() < MAX_CLIENTS,
                &sessions,
            );
        }

        let _ = std::fs::remove_file(NETD_SOCK);
        Ok(())
    }
}

fn main() {
    #[cfg(target_os = "wasi")]
    let result = runtime::run();
    #[cfg(not(target_os = "wasi"))]
    let result: Result<(), abi::Error> = Err(abi::Error::because(
        abi::Errno::ENOSYS,
        "netd service requires the OS WASI runtime",
    ));
    if let Err(err) = result {
        eprintln!("netd: {err}");
        std::process::exit(1);
    }
}
