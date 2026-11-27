//! `netctl` — Phase 10a (`#86`) CLI for querying `netd` status, resolving permitted hostnames,
//! and opening outbound TCP/TLS streams bridged to stdin/stdout.
//!
//! Usage:
//!   netctl status [--json]
//!   netctl resolve [--port <PORT>] [--json] <HOST>
//!   netctl connect [--tls] [--framed] [--timeout-ms <MS>] <HOST> <PORT>

use abi::Errno;
use abi::net_ctl::{DataFrame, NET_DATA_CHUNK_MAX, StreamMode, TlsMode, encode_unix_data_frame};
use os_posix::net::{NetError, NetStream};
use std::collections::VecDeque;
use std::io::{self, Read, Write};

fn usage() -> &'static str {
    "Usage:\n  \
       netctl status [--json]\n  \
       netctl resolve [--port <PORT>] [--json] <HOST>\n  \
       netctl connect [--tls] [--framed] [--timeout-ms <MS>] <HOST> <PORT>\n"
}

pub fn run(args: &[String]) -> i32 {
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print!("{}", usage());
        return 0;
    }
    match args[0].as_str() {
        "status" => cmd_status(&args[1..]),
        "resolve" => cmd_resolve(&args[1..]),
        "connect" => cmd_connect(&args[1..]),
        other => {
            eprintln!("netctl: unknown subcommand '{other}'\n{}", usage());
            2
        }
    }
}

fn cmd_status(args: &[String]) -> i32 {
    let mut as_json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => as_json = true,
            "-h" | "--help" => {
                print!("{}", usage());
                return 0;
            }
            other => {
                eprintln!("netctl status: unknown flag '{other}'");
                return 2;
            }
        }
    }
    match NetStream::status() {
        Ok(st) => {
            if as_json {
                println!(
                    "{}",
                    serde_json::json!({
                        "version": st.version,
                        "host_kind": st.host_kind,
                        "active_streams": st.active_streams,
                        "ready": st.ready,
                    })
                );
            } else {
                println!(
                    "netd version={} host_kind={} active_streams={} ready={}",
                    st.version, st.host_kind, st.active_streams, st.ready
                );
            }
            0
        }
        Err(e) => report_net_error("status", e),
    }
}

fn cmd_resolve(args: &[String]) -> i32 {
    let mut port = 80u16;
    let mut as_json = false;
    let mut host: Option<String> = None;
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => as_json = true,
            "--port" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("netctl resolve: missing value for --port");
                    return 2;
                };
                match val.parse::<u16>() {
                    Ok(p) if p > 0 => port = p,
                    _ => {
                        eprintln!("netctl resolve: invalid port '{val}'");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                print!("{}", usage());
                return 0;
            }
            other if !other.starts_with('-') && host.is_none() => {
                host = Some(other.to_string());
            }
            other => {
                eprintln!("netctl resolve: unexpected argument '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    let Some(host) = host else {
        eprintln!("netctl resolve: missing <HOST>");
        return 2;
    };
    match NetStream::resolve(&host, port) {
        Ok(addrs) => {
            if as_json {
                println!("{}", serde_json::json!({ "host": host, "addrs": addrs }));
            } else {
                for a in addrs {
                    println!("{a}");
                }
            }
            0
        }
        Err(e) => report_net_error("resolve", e),
    }
}

fn cmd_connect(args: &[String]) -> i32 {
    let mut tls = TlsMode::Off;
    let mut mode = StreamMode::Raw;
    let mut timeout_ms: Option<u64> = None;
    let mut pos: Vec<String> = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--tls" => tls = TlsMode::On,
            "--framed" => mode = StreamMode::Framed,
            "--timeout-ms" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    eprintln!("netctl connect: missing value for --timeout-ms");
                    return 2;
                };
                match val.parse::<u64>() {
                    Ok(ms) if ms > 0 => timeout_ms = Some(ms),
                    _ => {
                        eprintln!("netctl connect: invalid --timeout-ms '{val}'");
                        return 2;
                    }
                }
            }
            "-h" | "--help" => {
                print!("{}", usage());
                return 0;
            }
            other if !other.starts_with('-') => pos.push(other.to_string()),
            other => {
                eprintln!("netctl connect: unknown flag '{other}'");
                return 2;
            }
        }
        i += 1;
    }
    if pos.len() != 2 {
        eprintln!("netctl connect: expected <HOST> <PORT>");
        return 2;
    }
    let host = &pos[0];
    let port: u16 = match pos[1].parse::<u16>() {
        Ok(p) if p > 0 => p,
        _ => {
            eprintln!("netctl connect: invalid port '{}'", pos[1]);
            return 2;
        }
    };

    let stream = match mode {
        StreamMode::Raw => NetStream::connect_raw(host, port, tls, timeout_ms),
        StreamMode::Framed => NetStream::connect_framed(host, port, tls, timeout_ms),
    };
    let mut stream = match stream {
        Ok(s) => s,
        Err(e) => return report_net_error("connect", e),
    };

    match mode {
        StreamMode::Raw => pump_raw(&mut stream),
        StreamMode::Framed => pump_framed(&mut stream),
    }
}

fn report_net_error(op: &str, err: NetError) -> i32 {
    eprintln!("netctl {op}: {err}");
    match err.errno {
        Errno::EACCES | Errno::EPERM => 13,
        Errno::EDQUOT => 122,
        Errno::ETIMEDOUT => 110,
        Errno::ECONNREFUSED => 111,
        Errno::EOPNOTSUPP | Errno::EPROTONOSUPPORT => 95,
        _ => 1,
    }
}

#[cfg(target_arch = "wasm32")]
mod poll_wasi {
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Subscription {
        pub userdata: u64,
        pub tag: u8,
        pub _pad: [u8; 7],
        pub payload: [u64; 5],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Event {
        pub userdata: u64,
        pub error: u16,
        pub kind: u8,
        pub _pad: [u8; 5],
        pub nbytes: u64,
        pub flags: u16,
        pub _pad2: [u8; 6],
    }

    pub fn sub_fd_read(userdata: u64, fd: u32) -> Subscription {
        let mut s = Subscription {
            userdata,
            tag: 1,
            _pad: [0; 7],
            payload: [0; 5],
        };
        s.payload[0] = fd as u64;
        s
    }

    pub fn sub_fd_write(userdata: u64, fd: u32) -> Subscription {
        let mut s = Subscription {
            userdata,
            tag: 2,
            _pad: [0; 7],
            payload: [0; 5],
        };
        s.payload[0] = fd as u64;
        s
    }

    pub fn sub_clock(userdata: u64, timeout_ns: u64) -> Subscription {
        let mut s = Subscription {
            userdata,
            tag: 0,
            _pad: [0; 7],
            payload: [0; 5],
        };
        s.payload[0] = 1; // monotonic
        s.payload[1] = timeout_ns;
        s.payload[2] = 1_000_000;
        s.payload[3] = 0; // relative
        s
    }

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        pub fn poll_oneoff(
            in_ptr: *const Subscription,
            out_ptr: *mut Event,
            nsubscriptions: usize,
            nevents: *mut usize,
        ) -> u32;
    }

    pub fn poll(subs: &[Subscription], out: &mut [Event]) -> usize {
        let mut nevents = 0usize;
        // SAFETY: slice pointers and length match stack arrays.
        let rc = unsafe { poll_oneoff(subs.as_ptr(), out.as_mut_ptr(), subs.len(), &mut nevents) };
        if rc != 0 { 0 } else { nevents.min(out.len()) }
    }
}

fn pump_raw(stream: &mut NetStream) -> i32 {
    let mut stdout = io::stdout();
    let mut stdin = io::stdin();
    let mut buf = vec![0u8; NET_DATA_CHUNK_MAX];

    // Drain any bytes buffered during control handshake first.
    while stream.has_buffered_rx() {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err() {
                    return 1;
                }
            }
            Err(_) => break,
        }
    }

    #[cfg(target_arch = "wasm32")]
    {
        let _ = stream.set_nonblocking(true);
        let sock_fd = stream.as_raw_fd();
        let mut stdin_eof = false;
        let mut shut_wr_sent = false;
        let mut sock_eof = false;
        let mut pending_tx: Vec<u8> = Vec::new();
        let mut pending_tx_pos = 0usize;
        let mut subs = Vec::with_capacity(4);
        let mut events = [poll_wasi::Event::default(); 4];

        while !sock_eof {
            let has_tx = pending_tx_pos < pending_tx.len();
            subs.clear();
            subs.push(poll_wasi::sub_fd_read(1, sock_fd));
            if has_tx {
                subs.push(poll_wasi::sub_fd_write(4, sock_fd));
            }
            if !stdin_eof && !has_tx {
                subs.push(poll_wasi::sub_fd_read(2, 0));
            }
            subs.push(poll_wasi::sub_clock(3, 250_000_000));
            let n_ev = poll_wasi::poll(&subs, &mut events);

            let mut sock_read_ready = false;
            let mut sock_write_ready = false;
            let mut stdin_ready = false;
            for ev in &events[..n_ev] {
                match ev.userdata {
                    1 => sock_read_ready = true,
                    2 => stdin_ready = true,
                    4 => sock_write_ready = true,
                    _ => {}
                }
            }

            if stdin_ready && !stdin_eof && pending_tx_pos >= pending_tx.len() {
                match stdin.read(&mut buf) {
                    Ok(0) => {
                        stdin_eof = true;
                        if !shut_wr_sent {
                            shut_wr_sent = true;
                            let _ = stream.shutdown_write();
                        }
                    }
                    Ok(n) => {
                        pending_tx.clear();
                        pending_tx.extend_from_slice(&buf[..n]);
                        pending_tx_pos = 0;
                        sock_write_ready = true;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        stdin_eof = true;
                        if !shut_wr_sent {
                            shut_wr_sent = true;
                            let _ = stream.shutdown_write();
                        }
                    }
                }
            }

            if sock_write_ready && pending_tx_pos < pending_tx.len() {
                while pending_tx_pos < pending_tx.len() {
                    match stream.write(&pending_tx[pending_tx_pos..]) {
                        Ok(0) => {
                            eprintln!("netctl connect: write error: EPIPE");
                            return 1;
                        }
                        Ok(n) => pending_tx_pos += n,
                        Err(Errno::EAGAIN) => break,
                        Err(Errno::EINTR) => continue,
                        Err(e) => {
                            eprintln!("netctl connect: write error: {e:?}");
                            return 1;
                        }
                    }
                }
                if pending_tx_pos >= pending_tx.len() {
                    pending_tx.clear();
                    pending_tx_pos = 0;
                    if stdin_eof && !shut_wr_sent {
                        shut_wr_sent = true;
                        let _ = stream.shutdown_write();
                    }
                }
            }

            if sock_read_ready {
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => {
                            sock_eof = true;
                            break;
                        }
                        Ok(n) => {
                            if stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err() {
                                return 1;
                            }
                        }
                        Err(Errno::EAGAIN) => break,
                        Err(Errno::EINTR) => continue,
                        Err(e) => {
                            eprintln!("netctl connect: read error: {e:?}");
                            return 1;
                        }
                    }
                }
            }
        }
        0
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        // Non-wasm32 fallback: pump stdin to stream, half-close, then drain stream to stdout.
        loop {
            match stdin.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = stream.write_all(&buf[..n]) {
                        eprintln!("netctl connect: write error: {e:?}");
                        return 1;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stream.shutdown_write();
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err() {
                        return 1;
                    }
                }
                Err(Errno::EINTR) => continue,
                Err(e) => {
                    eprintln!("netctl connect: read error: {e:?}");
                    return 1;
                }
            }
        }
        0
    }
}

fn pump_framed(stream: &mut NetStream) -> i32 {
    let mut stdout = io::stdout();
    let mut stdin = io::stdin();
    let mut buf = vec![0u8; NET_DATA_CHUNK_MAX];
    let mut send_credit: u32 = stream.initial_window();

    // Interleave credit-gated stdin TX frames and socket RX frames non-blockingly via `poll_oneoff`
    // so bulk framed uploads (>64 KiB) wait for `DataFrame::Credit` instead of overflowing `netd`.
    #[cfg(target_arch = "wasm32")]
    {
        let _ = stream.set_nonblocking(true);
        let sock_fd = stream.as_raw_fd();
        let mut stdin_eof = false;
        let mut pending_tx: VecDeque<u8> = VecDeque::new();
        let mut subs = Vec::with_capacity(4);
        let mut events = [poll_wasi::Event::default(); 4];

        let enqueue_frame = |q: &mut VecDeque<u8>, f: &DataFrame| -> Result<(), Errno> {
            let encoded = encode_unix_data_frame(f).map_err(|e| e.errno)?;
            q.extend(encoded);
            Ok(())
        };

        let flush_tx = |s: &NetStream, q: &mut VecDeque<u8>| -> Result<(), Errno> {
            while !q.is_empty() {
                let (front, _) = q.as_slices();
                if front.is_empty() {
                    q.make_contiguous();
                    continue;
                }
                match s.write(front) {
                    Ok(0) => return Err(Errno::EPIPE),
                    Ok(n) => {
                        q.drain(..n);
                    }
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        };

        loop {
            if let Err(e) = flush_tx(stream, &mut pending_tx) {
                eprintln!("netctl connect: send frame error: {e:?}");
                return 1;
            }

            // Drain any complete RX frames already buffered before polling.
            while stream.has_buffered_rx() {
                match stream.recv_frame() {
                    Ok(Some(DataFrame::Data(bytes))) => {
                        let len = bytes.len() as u32;
                        if stdout.write_all(&bytes).is_err() || stdout.flush().is_err() {
                            return 1;
                        }
                        if len > 0 {
                            let _ = enqueue_frame(&mut pending_tx, &DataFrame::Credit(len));
                            if let Err(e) = flush_tx(stream, &mut pending_tx) {
                                eprintln!("netctl connect: send credit error: {e:?}");
                                return 1;
                            }
                        }
                    }
                    Ok(Some(DataFrame::Credit(c))) => {
                        send_credit = send_credit.saturating_add(c);
                    }
                    Ok(Some(DataFrame::HalfClose)) | Ok(None) => return 0,
                    Ok(Some(DataFrame::Closed(cl))) => {
                        if let Some(errno) = cl.errno {
                            eprintln!(
                                "netctl connect: closed ({errno:?}): {}",
                                cl.message.as_deref().unwrap_or("")
                            );
                            return 1;
                        }
                        return 0;
                    }
                    Ok(Some(DataFrame::Cancel)) => return 1,
                    Err(Errno::EAGAIN) => break,
                    Err(e) => {
                        eprintln!("netctl connect: recv error: {e:?}");
                        return 1;
                    }
                }
            }

            subs.clear();
            subs.push(poll_wasi::sub_fd_read(1, sock_fd));
            if !pending_tx.is_empty() {
                subs.push(poll_wasi::sub_fd_write(4, sock_fd));
            }
            if !stdin_eof && send_credit > 0 && pending_tx.len() < NET_DATA_CHUNK_MAX {
                subs.push(poll_wasi::sub_fd_read(2, 0));
            }
            subs.push(poll_wasi::sub_clock(3, 250_000_000));
            let n_ev = poll_wasi::poll(&subs, &mut events);

            let mut sock_read_ready = false;
            let mut sock_write_ready = false;
            let mut stdin_ready = false;
            for ev in &events[..n_ev] {
                match ev.userdata {
                    1 => sock_read_ready = true,
                    2 => stdin_ready = true,
                    4 => sock_write_ready = true,
                    _ => {}
                }
            }

            if sock_write_ready && let Err(e) = flush_tx(stream, &mut pending_tx) {
                eprintln!("netctl connect: send frame error: {e:?}");
                return 1;
            }

            if stdin_ready && !stdin_eof && send_credit > 0 && pending_tx.len() < NET_DATA_CHUNK_MAX
            {
                let max_read = (send_credit as usize).min(NET_DATA_CHUNK_MAX);
                match stdin.read(&mut buf[..max_read]) {
                    Ok(0) => {
                        stdin_eof = true;
                        let _ = enqueue_frame(&mut pending_tx, &DataFrame::HalfClose);
                    }
                    Ok(n) => {
                        send_credit -= n as u32;
                        if let Err(e) =
                            enqueue_frame(&mut pending_tx, &DataFrame::Data(buf[..n].to_vec()))
                        {
                            eprintln!("netctl connect: send frame error: {e:?}");
                            return 1;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        stdin_eof = true;
                        let _ = enqueue_frame(&mut pending_tx, &DataFrame::HalfClose);
                    }
                }
                if let Err(e) = flush_tx(stream, &mut pending_tx) {
                    eprintln!("netctl connect: send frame error: {e:?}");
                    return 1;
                }
            }

            if sock_read_ready {
                loop {
                    match stream.recv_frame() {
                        Ok(Some(DataFrame::Data(bytes))) => {
                            let len = bytes.len() as u32;
                            if stdout.write_all(&bytes).is_err() || stdout.flush().is_err() {
                                return 1;
                            }
                            if len > 0 {
                                let _ = enqueue_frame(&mut pending_tx, &DataFrame::Credit(len));
                            }
                        }
                        Ok(Some(DataFrame::Credit(c))) => {
                            send_credit = send_credit.saturating_add(c);
                        }
                        Ok(Some(DataFrame::HalfClose)) | Ok(None) => return 0,
                        Ok(Some(DataFrame::Closed(cl))) => {
                            if let Some(errno) = cl.errno {
                                eprintln!(
                                    "netctl connect: closed ({errno:?}): {}",
                                    cl.message.as_deref().unwrap_or("")
                                );
                                return 1;
                            }
                            return 0;
                        }
                        Ok(Some(DataFrame::Cancel)) => return 1,
                        Err(Errno::EAGAIN) => break,
                        Err(e) => {
                            eprintln!("netctl connect: recv error: {e:?}");
                            return 1;
                        }
                    }
                }
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (
            &mut send_credit,
            &encode_unix_data_frame,
            VecDeque::<u8>::new,
        );
        loop {
            while send_credit == 0 {
                match stream.recv_frame() {
                    Ok(Some(DataFrame::Credit(c))) => {
                        send_credit = send_credit.saturating_add(c);
                    }
                    Ok(Some(DataFrame::Data(bytes))) => {
                        let len = bytes.len() as u32;
                        if stdout.write_all(&bytes).is_err() || stdout.flush().is_err() {
                            return 1;
                        }
                        let _ = stream.send_framed_credit(len);
                    }
                    Ok(Some(DataFrame::HalfClose)) | Ok(None) => return 0,
                    Ok(Some(DataFrame::Closed(cl))) => {
                        if let Some(errno) = cl.errno {
                            eprintln!(
                                "netctl connect: closed ({errno:?}): {}",
                                cl.message.as_deref().unwrap_or("")
                            );
                            return 1;
                        }
                        return 0;
                    }
                    Ok(Some(DataFrame::Cancel)) => return 1,
                    Err(e) => {
                        eprintln!("netctl connect: recv error: {e:?}");
                        return 1;
                    }
                }
            }
            let max_read = (send_credit as usize).min(NET_DATA_CHUNK_MAX);
            match stdin.read(&mut buf[..max_read]) {
                Ok(0) => break,
                Ok(n) => {
                    send_credit -= n as u32;
                    if let Err(e) = stream.send_framed_data(&buf[..n]) {
                        eprintln!("netctl connect: send frame error: {e:?}");
                        return 1;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = stream.send_framed_half_close();
        loop {
            match stream.recv_frame() {
                Ok(Some(DataFrame::Data(bytes))) => {
                    let len = bytes.len() as u32;
                    if stdout.write_all(&bytes).is_err() || stdout.flush().is_err() {
                        return 1;
                    }
                    let _ = stream.send_framed_credit(len);
                }
                Ok(Some(DataFrame::HalfClose)) | Ok(None) => return 0,
                Ok(Some(DataFrame::Closed(cl))) => {
                    if let Some(errno) = cl.errno {
                        eprintln!(
                            "netctl connect: closed ({errno:?}): {}",
                            cl.message.as_deref().unwrap_or("")
                        );
                        return 1;
                    }
                    return 0;
                }
                Ok(Some(DataFrame::Credit(_) | DataFrame::Cancel)) => {}
                Err(e) => {
                    eprintln!("netctl connect: recv error: {e:?}");
                    return 1;
                }
            }
        }
    }
}
