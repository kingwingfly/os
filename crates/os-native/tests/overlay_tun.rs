//! Phase 10b (`#87`) `os-native` `/dev/net/tun` & Tenant L3 Overlay Conformance Suite (`OV-04`, `OV-05`, `OV-06`).
//!
//! Exercises:
//! - **OV-04**: Pod-to-pod L3 ICMP Echo + UDP-in-IPv4 roundtrip between two isolated
//!   `OciContainerHandle` Wasmtime 51 pods wired via CNI attachment descriptors
//!   (`NativeCniAttachment::load_nofollow`) and a shared `Arc<NativeOverlaySwitch>`, including
//!   `os::sys(Call::Ioctl { TUNSETIFF })`, `fd_seek` -> `WASI_ESPIPE`, `poll_oneoff(FD_READ)`,
//!   single-packet `fd_read`/`fd_write`, and small-buffer packet truncation.
//! - **OV-05**: Triple-layer L3 firewall enforcement on shared `NativeOverlaySwitch`:
//!   - Spoofed source-IP drop (`tx_dropped_spoofed_src == 1`, peer receives 0 packets).
//!   - Cross-tenant denial (`u1000` -> `u1001`, `tx_dropped_cross_tenant >= 1`, Tenant B receives 0 packets).
//!   - Oversized packet (`> mtu`) -> `WASI_EMSGSIZE`.
//!   - `1 MiB` RX queue flood drops tail (`rx_dropped_queue_full > 0`) without OOM.
//!   - `SIGKILL` closes TUN descriptor and unregisters switch port cleanly (`active_port_count == 0`).
//! - **OV-06**: Zero boot network invariant (`NativeOverlayConfig::default()` has zero uplink URLs)
//!   and unprivileged container/sandbox without CNI attachment has no `/dev/net/tun` (`WASI_ENOENT`).

use abi::Errno;
use abi::overlay::{
    DropReason, IpCidr, TUN_DEFAULT_MTU, TUN_QUEUE_MAX_BYTES, TunStats, build_ipv4_packet,
    derive_tenant_v4_cidr, derive_tenant_v6_cidr, internet_checksum, tun_ioctl,
};
use os_native::kernel_rpc::WakeBus;
use os_native::oci_runtime::{OciBundleRunSpec, OciContainerHandle};
use os_native::overlay::{
    ForwardOutcome, NativeCniAttachment, NativeOverlayConfig, NativeOverlaySwitch,
    OverlayActorEvent,
};
use std::cell::Cell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
use vfs::tundev::{TunBinding, TunDeviceBackend, TunHostSink, TunPolicy, TunRegistry};
use vfs::{Cred, Filesystem, FsId, OpenOptions, now_or_never};

const WASI_EMSGSIZE: u32 = 35;
const WASI_ENOENT: u32 = 44;
const WASI_ESPIPE: u32 = 70;

// ---- Minimal L3 ICMP/UDP packet builders & parsers ----

fn build_icmp_echo_request(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut icmp = Vec::with_capacity(8 + payload.len());
    icmp.push(8); // Echo Request
    icmp.push(0); // Code 0
    icmp.extend_from_slice(&[0, 0]); // Checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let csum = internet_checksum(&icmp);
    icmp[2..4].copy_from_slice(&csum.to_be_bytes());
    build_ipv4_packet(src, dst, 1, 64, &icmp)
}

fn build_udp_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = Vec::with_capacity(udp_len as usize);
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // RFC 768 optional IPv4 UDP checksum = 0
    udp.extend_from_slice(payload);
    build_ipv4_packet(src, dst, 17, 64, &udp)
}

// ---- Deterministic inline WebAssembly WASI guest builders ----

fn encode_u32_leb(mut val: u32, out: &mut Vec<u8>) {
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if val == 0 {
            break;
        }
    }
}

fn encode_i64_sleb(mut v: i64, b: &mut Vec<u8>) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && (byte & 0x40) == 0) || (v == -1 && (byte & 0x40) != 0);
        if !done {
            byte |= 0x80;
        }
        b.push(byte);
        if done {
            break;
        }
    }
}

fn push_section(wasm: &mut Vec<u8>, id: u8, body: &[u8]) {
    wasm.push(id);
    encode_u32_leb(body.len() as u32, wasm);
    wasm.extend_from_slice(body);
}

fn encode_str(s: &str, out: &mut Vec<u8>) {
    encode_u32_leb(s.len() as u32, out);
    out.extend_from_slice(s.as_bytes());
}

fn i32c(v: u32, b: &mut Vec<u8>) {
    b.push(0x41);
    encode_i64_sleb(i64::from(v as i32), b);
}

fn i64c(v: u64, b: &mut Vec<u8>) {
    b.push(0x42);
    encode_i64_sleb(v as i64, b);
}

/// Build a WASI module importing:
///   0: wasi::proc_exit(i32) -> ()
///   1: wasi::path_open(9 args) -> i32
///   2: wasi::fd_read(4 args) -> i32
///   3: wasi::fd_write(4 args) -> i32
///   4: wasi::fd_seek(i32, i64, i32, i32) -> i32
///   5: wasi::poll_oneoff(4 args) -> i32
///   6: wasi::fd_close(i32) -> i32
///   7: os::sys(i32, i32) -> i32
///   8: os::reply(i32) -> ()
/// Func 9 = `_start() -> ()`. Memory = 2 pages (128 KiB).
fn assemble_wasi_tun_module(code_body: &[u8], data_segs: &[(u32, &[u8])]) -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    let mut types = vec![8];
    // 0: (i32) -> ()
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]);
    // 1: path_open(5xi32, 2xi64, 2xi32) -> i32
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]);
    // 2: (4xi32) -> i32
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]);
    // 3: fd_seek(i32, i64, i32, i32) -> i32
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7e, 0x7f, 0x7f, 1, 0x7f]);
    // 4: (i32) -> i32
    types.extend_from_slice(&[0x60, 1, 0x7f, 1, 0x7f]);
    // 5: (i32, i32) -> i32
    types.extend_from_slice(&[0x60, 2, 0x7f, 0x7f, 1, 0x7f]);
    // 6: () -> ()
    types.extend_from_slice(&[0x60, 0, 0]);
    // 7: unused placeholder? no, we have 7 types (0..6):
    types[0] = 7;
    push_section(&mut wasm, 1, &types);

    let mut imp = vec![9];
    for (module, name, ty) in [
        ("wasi_snapshot_preview1", "proc_exit", 0u8),
        ("wasi_snapshot_preview1", "path_open", 1),
        ("wasi_snapshot_preview1", "fd_read", 2),
        ("wasi_snapshot_preview1", "fd_write", 2),
        ("wasi_snapshot_preview1", "fd_seek", 3),
        ("wasi_snapshot_preview1", "poll_oneoff", 2),
        ("wasi_snapshot_preview1", "fd_close", 4),
        ("os", "sys", 5),
        ("os", "reply", 0),
    ] {
        encode_str(module, &mut imp);
        encode_str(name, &mut imp);
        imp.extend_from_slice(&[0x00, ty]);
    }
    push_section(&mut wasm, 2, &imp);
    // Function section: func 9 -> type 6 (() -> ())
    push_section(&mut wasm, 3, &[1, 6]);
    // Memory section: 2 pages (128 KiB)
    push_section(&mut wasm, 5, &[1, 0x00, 2]);
    // Export section
    let mut exp = vec![2];
    encode_str("memory", &mut exp);
    exp.extend_from_slice(&[0x02, 0]);
    encode_str("_start", &mut exp);
    exp.extend_from_slice(&[0x00, 9]);
    push_section(&mut wasm, 7, &exp);

    // Code section
    let mut code = vec![1];
    encode_u32_leb(code_body.len() as u32, &mut code);
    code.extend_from_slice(code_body);
    push_section(&mut wasm, 10, &code);

    // Data section
    if !data_segs.is_empty() {
        let mut data = Vec::new();
        encode_u32_leb(data_segs.len() as u32, &mut data);
        for (off, bytes) in data_segs {
            data.push(0x00); // memory 0
            i32c(*off, &mut data);
            data.push(0x0b);
            encode_u32_leb(bytes.len() as u32, &mut data);
            data.extend_from_slice(bytes);
        }
        push_section(&mut wasm, 11, &data);
    }
    wasm
}

// Emit helpers referencing our fixed import indices (0..8).
const FN_EXIT: u8 = 0;
const FN_PATH_OPEN: u8 = 1;
const FN_FD_READ: u8 = 2;
const FN_FD_WRITE: u8 = 3;
const FN_FD_SEEK: u8 = 4;
const FN_POLL: u8 = 5;
const FN_FD_CLOSE: u8 = 6;
const FN_OS_SYS: u8 = 7;
const FN_OS_REPLY: u8 = 8;

fn emit_expect_eq(expected: u32, fail_code: u32, b: &mut Vec<u8>) {
    i32c(expected, b);
    b.extend_from_slice(&[0x47, 0x04, 0x40]); // i32.ne; if
    i32c(fail_code, b);
    b.extend_from_slice(&[0x10, FN_EXIT, 0x0b]);
}

/// Emit `path_open(3, 1, path_ptr, path_len, 0, READ|WRITE=66, 0, 0, out_fd_ptr)`
fn emit_open_tun(path_ptr: u32, path_len: u32, out_fd_ptr: u32, b: &mut Vec<u8>) {
    i32c(3, b);
    i32c(1, b);
    i32c(path_ptr, b);
    i32c(path_len, b);
    i32c(0, b);
    i64c(2 | 64, b); // FD_READ | FD_WRITE
    i64c(0, b);
    i32c(0, b);
    i32c(out_fd_ptr, b);
    b.extend_from_slice(&[0x10, FN_PATH_OPEN]);
}

/// Emit `os::sys(req_ptr, req_len) -> len`, store len in `local_len`, call `os::reply(resp_ptr)`.
fn emit_os_sys(req_ptr: u32, req_len: u32, resp_ptr: u32, local_len: u8, b: &mut Vec<u8>) {
    i32c(req_ptr, b);
    i32c(req_len, b);
    b.extend_from_slice(&[0x10, FN_OS_SYS]);
    b.extend_from_slice(&[0x21, local_len]); // local.set local_len
    i32c(resp_ptr, b);
    b.extend_from_slice(&[0x10, FN_OS_REPLY]);
}

/// Emit `fd_write(fd_expr, buf_ptr, buf_len)` using scratch iovec at `0x410` and nwritten at `0x420`.
/// Leaves WASI errno on stack.
fn emit_fd_write_const(
    fd_local: Option<u8>,
    const_fd: u32,
    buf_ptr: u32,
    buf_len_local: Option<u8>,
    const_len: u32,
    b: &mut Vec<u8>,
) {
    i32c(0x410, b);
    i32c(buf_ptr, b);
    b.extend_from_slice(&[0x36, 0x02, 0x00]); // mem[0x410] = buf_ptr
    i32c(0x414, b);
    if let Some(l) = buf_len_local {
        b.extend_from_slice(&[0x20, l]);
    } else {
        i32c(const_len, b);
    }
    b.extend_from_slice(&[0x36, 0x02, 0x00]); // mem[0x414] = buf_len
    if let Some(l) = fd_local {
        b.extend_from_slice(&[0x20, l]);
    } else {
        i32c(const_fd, b);
    }
    i32c(0x410, b);
    i32c(1, b);
    i32c(0x420, b);
    b.extend_from_slice(&[0x10, FN_FD_WRITE]);
}

/// Emit `poll_oneoff` with 2 subscriptions at `0x600`:
///   sub 0: FD_READ on `fd_local` (userdata = 1)
///   sub 1: CLOCK_MONOTONIC relative timeout `timeout_ns` (userdata = 2)
/// Events written to `0x700`, nevents at `0x780`. Leaves WASI errno on stack.
fn emit_poll_fd_read_with_timeout(fd_local: u8, timeout_ns: u64, b: &mut Vec<u8>) {
    // sub 0 @ 0x600: userdata = 1, tag = 1 (FD_READ), fd = fd_local
    i32c(0x600, b);
    i64c(1, b);
    b.extend_from_slice(&[0x37, 0x03, 0x00]); // i64.store
    i32c(0x608, b);
    i32c(1, b); // tag = FD_READ
    b.extend_from_slice(&[0x3a, 0x00, 0x00]); // i32.store8
    i32c(0x610, b);
    b.extend_from_slice(&[0x20, fd_local, 0x36, 0x02, 0x00]); // fd

    // sub 1 @ 0x630 (0x600 + 48): userdata = 2, tag = 0 (CLOCK), clock_id = 1, timeout_ns
    i32c(0x630, b);
    i64c(2, b);
    b.extend_from_slice(&[0x37, 0x03, 0x00]);
    i32c(0x638, b);
    i32c(0, b); // tag = CLOCK
    b.extend_from_slice(&[0x3a, 0x00, 0x00]);
    i32c(0x640, b);
    i32c(1, b); // CLOCK_MONOTONIC
    b.extend_from_slice(&[0x36, 0x02, 0x00]);
    i32c(0x648, b);
    i64c(timeout_ns, b);
    b.extend_from_slice(&[0x37, 0x03, 0x00]);
    i32c(0x650, b);
    i64c(1_000_000, b); // precision 1ms
    b.extend_from_slice(&[0x37, 0x03, 0x00]);
    i32c(0x658, b);
    i32c(0, b); // relative
    b.extend_from_slice(&[0x3b, 0x01, 0x00]); // i32.store16

    i32c(0x600, b);
    i32c(0x700, b);
    i32c(2, b);
    i32c(0x780, b);
    b.extend_from_slice(&[0x10, FN_POLL]);
}

/// Emit `fd_read(fd_local, buf_ptr, buf_cap)` -> stores nread at `0x420`. Leaves errno on stack.
fn emit_fd_read(fd_local: u8, buf_ptr: u32, buf_cap: u32, b: &mut Vec<u8>) {
    i32c(0x410, b);
    i32c(buf_ptr, b);
    b.extend_from_slice(&[0x36, 0x02, 0x00]);
    i32c(0x414, b);
    i32c(buf_cap, b);
    b.extend_from_slice(&[0x36, 0x02, 0x00]);
    b.extend_from_slice(&[0x20, fd_local]);
    i32c(0x410, b);
    i32c(1, b);
    i32c(0x420, b);
    b.extend_from_slice(&[0x10, FN_FD_READ]);
}

/// WASI guest for Pod B (echo responder):
/// 1. Opens `/dev/net/tun` (expects fd == 4) and calls `TUNSETIFF` (`"tun0"`, `IFF_TUN | IFF_NO_PI`).
/// 2. Writes `"READY\n"` to stdout (fd 1).
/// 3. Loops `count` times:
///    - Waits on `poll_oneoff(FD_READ, 8s)` -> expects userdata 1 (FD_READ, not timeout).
///    - Reads 1 L3 IPv4 packet into `0x2000` (cap 2048).
///    - Swaps IPv4 src (`0x200c`) and dst (`0x2010`) (IPv4 header checksum unchanged!).
///    - If `proto == 1` (ICMP): sets type (`0x2014`) = 0 and updates big-endian ICMP checksum (`0x2016`) by +0x0800 (1's complement).
///    - If `proto == 17` (UDP): swaps 2-byte ports (`0x2014`, `0x2016`) and zeros UDP checksum (`0x201a`).
///    - Writes reply packet back to TUN `fd`!
/// 4. Closes TUN and exits 0.
fn wasm_tun_echo_responder(count: u32) -> Vec<u8> {
    let tun_path = b"dev/net/tun";
    let set_iff_json = format!(
        r#"[{{"ioctl":{{"fd":4,"request":{},"arg":{{"name":"tun0","flags":{}}}}}}}]"#,
        tun_ioctl::TUNSETIFF,
        tun_ioctl::IFF_REQUIRED,
    );
    let ready_msg = b"READY\n";

    // Locals: 0=fd, 1=reply_len, 2=iter, 3=nread, 4=tmp1, 5=tmp2
    let mut b = vec![1, 6, 0x7f];

    // Open /dev/net/tun
    emit_open_tun(0x100, tun_path.len() as u32, 0x400, &mut b);
    emit_expect_eq(0, 10, &mut b);
    i32c(0x400, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]); // local.0 = fd
    // Assert fd == 4 (so our static TUNSETIFF JSON fd=4 matches!)
    b.extend_from_slice(&[0x20, 0x00]);
    emit_expect_eq(4, 11, &mut b);

    // TUNSETIFF
    emit_os_sys(0x120, set_iff_json.len() as u32, 0x3000, 1, &mut b);

    // Write "READY\n" to stdout (fd 1)
    emit_fd_write_const(None, 1, 0x280, None, ready_msg.len() as u32, &mut b);
    emit_expect_eq(0, 12, &mut b);

    // Loop `count` times
    i32c(0, &mut b);
    b.extend_from_slice(&[0x21, 0x02]); // local.2 = 0
    b.extend_from_slice(&[0x02, 0x40, 0x03, 0x40]); // block { loop {
    // if iter >= count -> br 1 (break)
    b.extend_from_slice(&[0x20, 0x02]);
    i32c(count, &mut b);
    b.extend_from_slice(&[0x4f, 0x0d, 0x01]); // i32.ge_u; br_if 1

    // poll_oneoff(FD_READ, 8s)
    emit_poll_fd_read_with_timeout(0, 8_000_000_000, &mut b);
    emit_expect_eq(0, 13, &mut b);
    // Verify event 0 is FD_READ (type == 1 at 0x70a)
    i32c(0x70a, &mut b);
    b.extend_from_slice(&[0x2d, 0x00, 0x00]); // i32.load8_u
    emit_expect_eq(1, 14, &mut b);

    // fd_read(fd, 0x2000, 2048)
    emit_fd_read(0, 0x2000, 2048, &mut b);
    emit_expect_eq(0, 15, &mut b);
    i32c(0x420, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x03]); // local.3 = nread

    // Swap IPv4 src (0x200c) and dst (0x2010)
    i32c(0x200c, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x04]); // tmp1 = src
    i32c(0x2010, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x05]); // tmp2 = dst
    i32c(0x200c, &mut b);
    b.extend_from_slice(&[0x20, 0x05, 0x36, 0x02, 0x00]); // mem[0x200c] = dst
    i32c(0x2010, &mut b);
    b.extend_from_slice(&[0x20, 0x04, 0x36, 0x02, 0x00]); // mem[0x2010] = src

    // Check proto = mem8[0x2009]
    i32c(0x2009, &mut b);
    b.extend_from_slice(&[0x2d, 0x00, 0x00]);
    i32c(1, &mut b);
    b.extend_from_slice(&[0x46, 0x04, 0x40]); // if proto == 1 (ICMP)
    // Set ICMP type (0x2014) = 0 (Echo Reply)
    i32c(0x2014, &mut b);
    i32c(0, &mut b);
    b.extend_from_slice(&[0x3a, 0x00, 0x00]);
    // Update big-endian ICMP checksum at 0x2016: ck = (hi<<8 | lo) + 0x0800; fold carry
    i32c(0x2016, &mut b);
    b.extend_from_slice(&[0x2d, 0x00, 0x00]); // hi
    i32c(8, &mut b);
    b.push(0x74); // shl 8
    i32c(0x2017, &mut b);
    b.extend_from_slice(&[0x2d, 0x00, 0x00, 0x72]); // or lo
    i32c(0x0800, &mut b);
    b.extend_from_slice(&[0x6a, 0x22, 0x04]); // add 0x0800; local.tee 4
    // fold: tmp1 = (tmp1 & 0xffff) + (tmp1 >> 16)
    i32c(0xffff, &mut b);
    b.push(0x71); // and
    b.extend_from_slice(&[0x20, 0x04]);
    i32c(16, &mut b);
    b.extend_from_slice(&[0x76, 0x6a, 0x21, 0x04]); // shr_u 16; add; local.set 4
    // store hi = tmp1 >> 8 at 0x2016, lo = tmp1 & 0xff at 0x2017
    i32c(0x2016, &mut b);
    b.extend_from_slice(&[0x20, 0x04]);
    i32c(8, &mut b);
    b.extend_from_slice(&[0x76, 0x3a, 0x00, 0x00]);
    i32c(0x2017, &mut b);
    b.extend_from_slice(&[0x20, 0x04, 0x3a, 0x00, 0x00]);
    b.push(0x05); // else (assume UDP proto == 17)
    // Swap 2-byte UDP src port (0x2014) and dst port (0x2016)
    i32c(0x2014, &mut b);
    b.extend_from_slice(&[0x2f, 0x01, 0x00, 0x21, 0x04]); // tmp1 = u16[0x2014]
    i32c(0x2016, &mut b);
    b.extend_from_slice(&[0x2f, 0x01, 0x00, 0x21, 0x05]); // tmp2 = u16[0x2016]
    i32c(0x2014, &mut b);
    b.extend_from_slice(&[0x20, 0x05, 0x3b, 0x01, 0x00]);
    i32c(0x2016, &mut b);
    b.extend_from_slice(&[0x20, 0x04, 0x3b, 0x01, 0x00]);
    // Zero UDP checksum at 0x201a
    i32c(0x201a, &mut b);
    i32c(0, &mut b);
    b.extend_from_slice(&[0x3b, 0x01, 0x00]);
    b.push(0x0b); // end if

    // fd_write(fd, 0x2000, nread)
    emit_fd_write_const(Some(0), 0, 0x2000, Some(3), 0, &mut b);
    emit_expect_eq(0, 16, &mut b);

    // iter += 1; br 0
    b.extend_from_slice(&[0x20, 0x02]);
    i32c(1, &mut b);
    b.extend_from_slice(&[0x6a, 0x21, 0x02, 0x0c, 0x00]);
    b.extend_from_slice(&[0x0b, 0x0b]); // end loop; end block

    // fd_close(fd); proc_exit(0)
    b.extend_from_slice(&[0x20, 0x00, 0x10, FN_FD_CLOSE, 0x1a]);
    i32c(0, &mut b);
    b.extend_from_slice(&[0x10, FN_EXIT, 0x0b]);

    assemble_wasi_tun_module(
        &b,
        &[
            (0x100, tun_path),
            (0x120, set_iff_json.as_bytes()),
            (0x280, ready_msg),
        ],
    )
}

/// WASI guest for Pod A (OV-04 probe):
/// 1. Opens `/dev/net/tun` (fd 4) + `TUNSETIFF`.
/// 2. Calls `fd_seek(4, 0, 0, ...)` -> asserts `WASI_ESPIPE` (`70`)!
/// 3. Sends `pkt1` (ICMP Echo Request), polls `FD_READ`, reads reply, writes `[u16_le len][pkt]` to stdout!
/// 4. Sends `pkt2` (UDP-in-IPv4), polls `FD_READ`, reads reply, writes `[u16_le len][pkt]` to stdout!
/// 5. Exits 0.
fn wasm_tun_dual_probe(pkt1: &[u8], pkt2: &[u8]) -> Vec<u8> {
    let tun_path = b"dev/net/tun";
    let set_iff_json = format!(
        r#"[{{"ioctl":{{"fd":4,"request":{},"arg":{{"name":"tun0","flags":{}}}}}}}]"#,
        tun_ioctl::TUNSETIFF,
        tun_ioctl::IFF_REQUIRED,
    );
    // Locals: 0=fd, 1=reply_len, 2=nread
    let mut b = vec![1, 3, 0x7f];

    emit_open_tun(0x100, tun_path.len() as u32, 0x400, &mut b);
    emit_expect_eq(0, 20, &mut b);
    i32c(0x400, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    b.extend_from_slice(&[0x20, 0x00]);
    emit_expect_eq(4, 21, &mut b);

    emit_os_sys(0x120, set_iff_json.len() as u32, 0x3000, 1, &mut b);

    // Check fd_seek(4, 0, 0, 0x430) == WASI_ESPIPE (70)
    b.extend_from_slice(&[0x20, 0x00]);
    i64c(0, &mut b);
    i32c(0, &mut b);
    i32c(0x430, &mut b);
    b.extend_from_slice(&[0x10, FN_FD_SEEK]);
    emit_expect_eq(WASI_ESPIPE, 22, &mut b);

    for (idx, (pkt_off, pkt_len)) in [
        (0x4000u32, pkt1.len() as u32),
        (0x5000u32, pkt2.len() as u32),
    ]
    .into_iter()
    .enumerate()
    {
        let base_err = 30 + (idx as u32) * 10;
        // Write packet to TUN
        emit_fd_write_const(Some(0), 0, pkt_off, None, pkt_len, &mut b);
        emit_expect_eq(0, base_err, &mut b);
        // Poll for reply
        emit_poll_fd_read_with_timeout(0, 8_000_000_000, &mut b);
        emit_expect_eq(0, base_err + 1, &mut b);
        i32c(0x70a, &mut b);
        b.extend_from_slice(&[0x2d, 0x00, 0x00]);
        emit_expect_eq(1, base_err + 2, &mut b);
        // Read reply into 0x2002 (leave 2 bytes at 0x2000 for u16_le length header!)
        emit_fd_read(0, 0x2002, 2048, &mut b);
        emit_expect_eq(0, base_err + 3, &mut b);
        i32c(0x420, &mut b);
        b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x02]); // local.2 = nread
        // Store u16_le nread at 0x2000
        i32c(0x2000, &mut b);
        b.extend_from_slice(&[0x20, 0x02, 0x3b, 0x01, 0x00]);
        // local.2 += 2
        b.extend_from_slice(&[0x20, 0x02]);
        i32c(2, &mut b);
        b.extend_from_slice(&[0x6a, 0x21, 0x02]);
        // Write [u16_le len][pkt] to stdout (fd 1)
        emit_fd_write_const(None, 1, 0x2000, Some(2), 0, &mut b);
        emit_expect_eq(0, base_err + 4, &mut b);
    }

    b.extend_from_slice(&[0x20, 0x00, 0x10, FN_FD_CLOSE, 0x1a]);
    i32c(0, &mut b);
    b.extend_from_slice(&[0x10, FN_EXIT, 0x0b]);

    assemble_wasi_tun_module(
        &b,
        &[
            (0x100, tun_path),
            (0x120, set_iff_json.as_bytes()),
            (0x4000, pkt1),
            (0x5000, pkt2),
        ],
    )
}

/// WASI guest that opens `/dev/net/tun`, attaches `TUNSETIFF`, writes `"READY\n"`, then polls
/// `FD_READ` for `wait_ms` milliseconds and exits `0` ONLY if ZERO packets arrived (timeout event),
/// or exits `99` if any unauthorized packet leaked through!
fn wasm_tun_expect_silence(wait_ms: u64) -> Vec<u8> {
    let tun_path = b"dev/net/tun";
    let set_iff_json = format!(
        r#"[{{"ioctl":{{"fd":4,"request":{},"arg":{{"name":"tun0","flags":{}}}}}}}]"#,
        tun_ioctl::TUNSETIFF,
        tun_ioctl::IFF_REQUIRED,
    );
    let ready_msg = b"READY\n";
    let mut b = vec![1, 2, 0x7f]; // local 0 = fd, local 1 = reply_len

    emit_open_tun(0x100, tun_path.len() as u32, 0x400, &mut b);
    emit_expect_eq(0, 40, &mut b);
    i32c(0x400, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    emit_os_sys(0x120, set_iff_json.len() as u32, 0x3000, 1, &mut b);
    emit_fd_write_const(None, 1, 0x280, None, ready_msg.len() as u32, &mut b);
    emit_expect_eq(0, 41, &mut b);

    emit_poll_fd_read_with_timeout(0, wait_ms * 1_000_000, &mut b);
    emit_expect_eq(0, 42, &mut b);
    // Expect event 0 type == 0 (CLOCK timeout, NOT FD_READ!)
    i32c(0x70a, &mut b);
    b.extend_from_slice(&[0x2d, 0x00, 0x00]);
    emit_expect_eq(0, 99, &mut b);

    b.extend_from_slice(&[0x20, 0x00, 0x10, FN_FD_CLOSE, 0x1a]);
    i32c(0, &mut b);
    b.extend_from_slice(&[0x10, FN_EXIT, 0x0b]);

    assemble_wasi_tun_module(
        &b,
        &[
            (0x100, tun_path),
            (0x120, set_iff_json.as_bytes()),
            (0x280, ready_msg),
        ],
    )
}

/// WASI guest for OV-05 attacker Pod A:
/// 1. Opens `/dev/net/tun` + `TUNSETIFF`.
/// 2. Writes `spoof_pkt` (dropped silently by anti-spoofing firewall -> fd_write returns 0).
/// 3. Writes `cross_tenant_pkt` (dropped silently by cross-tenant firewall -> fd_write returns 0).
/// 4. Writes `oversized_pkt` (`> mtu`) -> asserts `fd_write` returns `WASI_EMSGSIZE` (`35`)!
/// 5. Queries `TUN_IOC_STATS` via `os::sys` and prints the JSON reply to stdout (fd 1).
fn wasm_tun_firewall_attacker(spoof_pkt: &[u8], cross_pkt: &[u8], oversized_pkt: &[u8]) -> Vec<u8> {
    let tun_path = b"dev/net/tun";
    let set_iff_json = format!(
        r#"[{{"ioctl":{{"fd":4,"request":{},"arg":{{"name":"tun0","flags":{}}}}}}}]"#,
        tun_ioctl::TUNSETIFF,
        tun_ioctl::IFF_REQUIRED,
    );
    let stats_json = format!(
        r#"[{{"ioctl":{{"fd":4,"request":{},"arg":null}}}}]"#,
        tun_ioctl::TUN_IOC_STATS,
    );
    let mut b = vec![1, 2, 0x7f]; // 0=fd, 1=reply_len

    emit_open_tun(0x100, tun_path.len() as u32, 0x400, &mut b);
    emit_expect_eq(0, 50, &mut b);
    i32c(0x400, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    emit_os_sys(0x120, set_iff_json.len() as u32, 0x3000, 1, &mut b);

    // 1. Spoofed source IP write
    emit_fd_write_const(Some(0), 0, 0x4000, None, spoof_pkt.len() as u32, &mut b);
    emit_expect_eq(0, 51, &mut b);

    // 2. Cross-tenant write
    emit_fd_write_const(Some(0), 0, 0x5000, None, cross_pkt.len() as u32, &mut b);
    emit_expect_eq(0, 52, &mut b);

    // 3. Oversized (> MTU) write -> MUST fail with WASI_EMSGSIZE!
    emit_fd_write_const(Some(0), 0, 0x6000, None, oversized_pkt.len() as u32, &mut b);
    emit_expect_eq(WASI_EMSGSIZE, 53, &mut b);

    // 4. Query TUN_IOC_STATS and dump JSON to stdout
    emit_os_sys(0x200, stats_json.len() as u32, 0x3000, 1, &mut b);
    emit_fd_write_const(None, 1, 0x3000, Some(1), 0, &mut b);
    emit_expect_eq(0, 54, &mut b);

    b.extend_from_slice(&[0x20, 0x00, 0x10, FN_FD_CLOSE, 0x1a]);
    i32c(0, &mut b);
    b.extend_from_slice(&[0x10, FN_EXIT, 0x0b]);

    assemble_wasi_tun_module(
        &b,
        &[
            (0x100, tun_path),
            (0x120, set_iff_json.as_bytes()),
            (0x200, stats_json.as_bytes()),
            (0x4000, spoof_pkt),
            (0x5000, cross_pkt),
            (0x6000, oversized_pkt),
        ],
    )
}

/// WASI guest that opens `/dev/net/tun`, attaches `TUNSETIFF`, writes `"READY\n"`, and spins in
/// `poll_oneoff` until terminated by `SIGKILL`.
fn wasm_tun_hold_forever() -> Vec<u8> {
    let tun_path = b"dev/net/tun";
    let set_iff_json = format!(
        r#"[{{"ioctl":{{"fd":4,"request":{},"arg":{{"name":"tun0","flags":{}}}}}}}]"#,
        tun_ioctl::TUNSETIFF,
        tun_ioctl::IFF_REQUIRED,
    );
    let ready_msg = b"READY\n";
    let mut b = vec![1, 2, 0x7f];

    emit_open_tun(0x100, tun_path.len() as u32, 0x400, &mut b);
    emit_expect_eq(0, 60, &mut b);
    i32c(0x400, &mut b);
    b.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    emit_os_sys(0x120, set_iff_json.len() as u32, 0x3000, 1, &mut b);
    emit_fd_write_const(None, 1, 0x280, None, ready_msg.len() as u32, &mut b);
    emit_expect_eq(0, 61, &mut b);

    b.extend_from_slice(&[0x03, 0x40]); // loop
    emit_poll_fd_read_with_timeout(0, 50_000_000, &mut b); // 50ms slices
    b.push(0x1a); // drop errno
    b.extend_from_slice(&[0x0c, 0x00, 0x0b]); // br 0; end loop
    b.push(0x0b); // end func

    assemble_wasi_tun_module(
        &b,
        &[
            (0x100, tun_path),
            (0x120, set_iff_json.as_bytes()),
            (0x280, ready_msg),
        ],
    )
}

/// WASI guest for OV-06: attempts `path_open("dev/net/tun")` and exits 0 ONLY if `WASI_ENOENT`!
fn wasm_expect_no_tun() -> Vec<u8> {
    let tun_path = b"dev/net/tun";
    let mut b = vec![0]; // 0 locals
    emit_open_tun(0x100, tun_path.len() as u32, 0x400, &mut b);
    emit_expect_eq(WASI_ENOENT, 70, &mut b);
    i32c(0, &mut b);
    b.extend_from_slice(&[0x10, FN_EXIT, 0x0b]);
    assemble_wasi_tun_module(&b, &[(0x100, tun_path)])
}

// ---- Test fixture helpers ----

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "os-ov-test-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        Self(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_cni_attachment(
    cni_state_dir: &Path,
    container_id: &str,
    tenant: &str,
    ip: Ipv4Addr,
    lease_id: u64,
) -> NativeCniAttachment {
    let cidr = derive_tenant_v4_cidr(tenant);
    let att = NativeCniAttachment {
        version: 1,
        container_id: container_id.to_string(),
        ifname: "tun0".to_string(),
        netns: format!("/run/netns/{container_id}"),
        tenant: tenant.to_string(),
        cluster: "default".to_string(),
        network: "default".to_string(),
        node_id: "node-ov-test".to_string(),
        ip: ip.to_string(),
        prefix_len: cidr.prefix_len,
        gateway: cidr.gateway_addr().unwrap().to_string(),
        cidr: cidr.to_string(),
        ipv6: None,
        mtu: TUN_DEFAULT_MTU,
        lease_id,
        fence_epoch: 1,
        driver: "userspace".to_string(),
        created_at: 1_700_000_000,
    };
    let attach_dir = cni_state_dir.join("attachments");
    std::fs::create_dir_all(&attach_dir).expect("mkdir attachments");
    std::fs::write(
        attach_dir.join(format!("{container_id}.json")),
        serde_json::to_vec_pretty(&att).unwrap(),
    )
    .expect("write CNI attachment JSON");
    NativeCniAttachment::load_nofollow(cni_state_dir, container_id)
        .expect("load_nofollow must succeed")
        .expect("attachment must exist")
}

fn make_pod_spec(
    base: &Path,
    id: &str,
    wasm_bytes: &[u8],
    cni_attachment: Option<NativeCniAttachment>,
    overlay_switch: Option<Arc<NativeOverlaySwitch>>,
) -> (OciBundleRunSpec, PathBuf) {
    let bundle_dir = base.join(format!("bundle-{id}"));
    let rootfs_dir = bundle_dir.join("rootfs");
    let bin_dir = rootfs_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("mkdir rootfs/bin");
    let wasm_path = bin_dir.join("app.wasm");
    std::fs::write(&wasm_path, wasm_bytes).expect("write app.wasm");
    std::fs::set_permissions(&wasm_path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod +x app.wasm");
    let stdout_path = bundle_dir.join("stdout.bin");
    std::fs::write(&stdout_path, b"").expect("create stdout file");
    let work_store_dir = base.join(format!("store-{id}"));
    std::fs::create_dir_all(&work_store_dir).expect("mkdir work_store_dir");
    let spec = OciBundleRunSpec {
        container_id: id.to_string(),
        bundle_dir,
        rootfs_dir,
        work_store_dir,
        argv: vec!["/bin/app.wasm".to_string()],
        env: vec!["PATH=/bin".to_string()],
        cwd: "/".to_string(),
        uid: 0,
        gid: 0,
        umask: 0o022,
        memory_max_bytes: 32 * 1024 * 1024,
        pids_max: 16,
        stdin_path: None,
        stdout_path: Some(stdout_path.clone()),
        stderr_path: None,
        terminal: false,
        is_sandbox: false,
        volumes: Vec::new(),
        cni_attachment,
        overlay_switch,
    };
    (spec, stdout_path)
}

fn wait_for_file_contains(path: &Path, needle: &[u8], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(path)
            && bytes.windows(needle.len()).any(|w| w == needle)
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for {:?} in {}",
        String::from_utf8_lossy(needle),
        path.display()
    );
}

#[test]
fn ov04_pod_to_pod_l3_icmp_and_udp_roundtrip_via_cni_and_switch() {
    let tmp = TempDirGuard::new("ov04");
    let cni_dir = tmp.path().join("cni-state");

    let cidr_a = derive_tenant_v4_cidr("u1000");
    let ip_a = cidr_a.host_ip(0).unwrap();
    let ip_b = cidr_a.host_ip(1).unwrap();

    let att_a = write_cni_attachment(&cni_dir, "pod-a", "u1000", ip_a, 101);
    let att_b = write_cni_attachment(&cni_dir, "pod-b", "u1000", ip_b, 102);

    // Path traversal & symlink rejection on NativeCniAttachment::load_nofollow:
    assert_eq!(
        NativeCniAttachment::load_nofollow(&cni_dir, "../escape"),
        Err(Errno::EINVAL)
    );
    let symlink_target = cni_dir.join("attachments/pod-a.json");
    let symlink_path = cni_dir.join("attachments/pod-evil.json");
    std::os::unix::fs::symlink(&symlink_target, &symlink_path).expect("create test symlink");
    assert_eq!(
        NativeCniAttachment::load_nofollow(&cni_dir, "pod-evil"),
        Err(Errno::EACCES)
    );

    let switch = NativeOverlaySwitch::new();

    // Start Pod B (echo responder expecting 2 packets: 1 ICMP + 1 UDP).
    let (spec_b, stdout_b) = make_pod_spec(
        tmp.path(),
        "pod-b",
        &wasm_tun_echo_responder(2),
        Some(att_b),
        Some(Arc::clone(&switch)),
    );
    let pod_b = OciContainerHandle::create(spec_b).expect("create pod-b");
    pod_b.start().expect("start pod-b");
    wait_for_file_contains(&stdout_b, b"READY\n", Duration::from_secs(5));

    // Build real L3 ICMP Echo Request and UDP-in-IPv4 packets from Pod A -> Pod B.
    let icmp_req = build_icmp_echo_request(ip_a, ip_b, 0x1234, 7, b"ov04-icmp-ping");
    let udp_req = build_udp_ipv4_packet(ip_a, ip_b, 41234, 9000, b"ov04-udp-hello");

    let (spec_a, stdout_a) = make_pod_spec(
        tmp.path(),
        "pod-a",
        &wasm_tun_dual_probe(&icmp_req, &udp_req),
        Some(att_a),
        Some(Arc::clone(&switch)),
    );
    let pod_a = OciContainerHandle::create(spec_a).expect("create pod-a");
    pod_a.start().expect("start pod-a");

    let exit_a = pod_a.wait();
    assert_eq!(exit_a.exit_code, 0, "pod-a failed: {exit_a:?}");

    let exit_b = pod_b.wait();
    assert_eq!(exit_b.exit_code, 0, "pod-b failed: {exit_b:?}");

    // Parse the two length-prefixed L3 reply packets emitted by pod-a.
    let raw = std::fs::read(&stdout_a).expect("read pod-a stdout");
    assert!(raw.len() > 4, "stdout too short: {} bytes", raw.len());
    let len1 = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    let reply1 = &raw[2..2 + len1];
    let off2 = 2 + len1;
    let len2 = u16::from_le_bytes([raw[off2], raw[off2 + 1]]) as usize;
    let reply2 = &raw[off2 + 2..off2 + 2 + len2];

    // Verify ICMP Echo Reply
    assert_eq!(reply1[9], 1, "expected ICMP proto=1");
    assert_eq!(
        Ipv4Addr::new(reply1[12], reply1[13], reply1[14], reply1[15]),
        ip_b
    );
    assert_eq!(
        Ipv4Addr::new(reply1[16], reply1[17], reply1[18], reply1[19]),
        ip_a
    );
    assert_eq!(reply1[20], 0, "expected ICMP Echo Reply type=0");
    assert_eq!(
        internet_checksum(&reply1[20..]),
        0,
        "ICMP reply checksum must verify to 0"
    );
    assert_eq!(&reply1[28..], b"ov04-icmp-ping");

    // Verify UDP Reply
    assert_eq!(reply2[9], 17, "expected UDP proto=17");
    assert_eq!(
        Ipv4Addr::new(reply2[12], reply2[13], reply2[14], reply2[15]),
        ip_b
    );
    assert_eq!(
        Ipv4Addr::new(reply2[16], reply2[17], reply2[18], reply2[19]),
        ip_a
    );
    assert_eq!(u16::from_be_bytes([reply2[20], reply2[21]]), 9000);
    assert_eq!(u16::from_be_bytes([reply2[22], reply2[23]]), 41234);
    assert_eq!(&reply2[28..], b"ov04-udp-hello");

    let c = switch.counters();
    assert!(
        c.forwarded_local >= 4,
        "expected >=4 local forwards, got {c:?}"
    );
    assert_eq!(c.dropped_spoofed_src, 0);
    assert_eq!(c.dropped_cross_tenant, 0);

    pod_a.delete().expect("delete pod-a");
    pod_b.delete().expect("delete pod-b");
    assert_eq!(switch.active_port_count(), 0);
}

#[test]
fn ov05_anti_spoofing_cross_tenant_mtu_flood_and_sigkill_teardown() {
    let tmp = TempDirGuard::new("ov05");
    let cni_dir = tmp.path().join("cni-state");

    let cidr_t1 = derive_tenant_v4_cidr("u1000");
    let cidr_t2 = derive_tenant_v4_cidr("u1001");
    assert_ne!(
        cidr_t1, cidr_t2,
        "distinct tenants must receive disjoint /24 subnets"
    );

    let ip_a = cidr_t1.host_ip(0).unwrap();
    let ip_b = cidr_t1.host_ip(1).unwrap();
    let forged_src = cidr_t1.host_ip(50).unwrap();
    let ip_c = cidr_t2.host_ip(0).unwrap();

    let att_a = write_cni_attachment(&cni_dir, "pod-a-ov05", "u1000", ip_a, 201);
    let att_b = write_cni_attachment(&cni_dir, "pod-b-ov05", "u1000", ip_b, 202);
    let att_c = write_cni_attachment(&cni_dir, "pod-c-ov05", "u1001", ip_c, 203);

    let switch = NativeOverlaySwitch::new();

    // Start Pod B (same tenant u1000) and Pod C (other tenant u1001), both asserting silence!
    let (spec_b, stdout_b) = make_pod_spec(
        tmp.path(),
        "pod-b-ov05",
        &wasm_tun_expect_silence(400),
        Some(att_b),
        Some(Arc::clone(&switch)),
    );
    let (spec_c, stdout_c) = make_pod_spec(
        tmp.path(),
        "pod-c-ov05",
        &wasm_tun_expect_silence(400),
        Some(att_c),
        Some(Arc::clone(&switch)),
    );
    let pod_b = OciContainerHandle::create(spec_b).expect("create pod-b");
    let pod_c = OciContainerHandle::create(spec_c).expect("create pod-c");
    pod_b.start().expect("start pod-b");
    pod_c.start().expect("start pod-c");
    wait_for_file_contains(&stdout_b, b"READY\n", Duration::from_secs(5));
    wait_for_file_contains(&stdout_c, b"READY\n", Duration::from_secs(5));

    // Launch attacker Pod A sending:
    // 1. Spoofed source IP (`forged_src -> ip_b`)
    // 2. Cross-tenant packet (`ip_a -> ip_c`)
    // 3. Oversized (> MTU) packet (asserts WASI_EMSGSIZE)
    let spoof_pkt = build_icmp_echo_request(forged_src, ip_b, 1, 1, b"spoof");
    let cross_pkt = build_icmp_echo_request(ip_a, ip_c, 1, 2, b"cross");
    let oversized_pkt = build_icmp_echo_request(
        ip_a,
        ip_b,
        1,
        3,
        &vec![0xAB; usize::from(TUN_DEFAULT_MTU) + 64],
    );
    let (spec_a, stdout_a) = make_pod_spec(
        tmp.path(),
        "pod-a-ov05",
        &wasm_tun_firewall_attacker(&spoof_pkt, &cross_pkt, &oversized_pkt),
        Some(att_a),
        Some(Arc::clone(&switch)),
    );
    let pod_a = OciContainerHandle::create(spec_a).expect("create pod-a");
    pod_a.start().expect("start pod-a");

    let exit_a = pod_a.wait();
    assert_eq!(exit_a.exit_code, 0, "attacker pod-a failed: {exit_a:?}");

    // Parse TUN_IOC_STATS JSON printed by Pod A
    let stats_raw = std::fs::read_to_string(&stdout_a).expect("read pod-a stats");
    let results: abi::Results = serde_json::from_str(&stats_raw)
        .unwrap_or_else(|e| panic!("bad abi::Results JSON '{stats_raw}': {e}"));
    let stats_val = results.results[0]
        .clone()
        .into_result()
        .expect("TUN_IOC_STATS must succeed");
    let stats: TunStats = serde_json::from_value(stats_val).expect("parse TunStats");
    assert_eq!(
        stats.tx_dropped_spoofed_src, 1,
        "expected 1 spoofed-src drop: {stats:?}"
    );
    assert!(
        stats.tx_dropped_cross_tenant >= 1,
        "expected >=1 cross-tenant drop: {stats:?}"
    );

    // Neither Pod B nor Pod C may have received ANY packet!
    let exit_b = pod_b.wait();
    assert_eq!(
        exit_b.exit_code, 0,
        "Pod B unexpectedly received spoofed packet: {exit_b:?}"
    );
    let exit_c = pod_c.wait();
    assert_eq!(
        exit_c.exit_code, 0,
        "Pod C unexpectedly received cross-tenant packet: {exit_c:?}"
    );

    pod_a.delete().expect("delete pod-a");
    pod_b.delete().expect("delete pod-b");
    pod_c.delete().expect("delete pod-c");

    // 1 MiB RX queue flood without OOM:
    struct NoopSink;
    impl TunHostSink for NoopSink {}
    let reg = Rc::new(TunRegistry::with_policy(
        Rc::new(NoopSink),
        Rc::new(Cell::new(Some(1))),
        TunPolicy {
            allow_root_open: true,
        },
    ));
    let dev = DevTmpFs::new(
        FsId("devtmpfs-ov05".into()),
        1,
        Box::new(|| (1_700_000_000, 0)),
        TunDeviceBackend::new(DefaultDeviceBackend, Rc::clone(&reg)),
    );
    dev.register_tun_device().expect("register_tun_device");
    let net_dir = now_or_never(dev.lookup(&Cred::root(), &dev.root(), "net"))
        .expect("ready")
        .expect("lookup net");
    let tun_ent = now_or_never(dev.lookup(&Cred::root(), &net_dir.handle, "tun"))
        .expect("ready")
        .expect("lookup tun");
    let mut rw = OpenOptions::new();
    rw.read(true).write(true);
    let open = now_or_never(dev.open(&Cred::root(), &tun_ent.handle, &rw))
        .expect("ready")
        .expect("open tun");
    let (tun_id, _resp) = reg
        .commit_set_iff(
            &open,
            "tun0".to_string(),
            TunBinding {
                tenant: "u1000".to_string(),
                network: "default".to_string(),
                endpoint_id: "flood-ep".to_string(),
                ip: ip_b,
                prefix_len: cidr_t1.prefix_len,
                gateway: cidr_t1.gateway_addr().unwrap(),
                cidr_v4: cidr_t1,
                ipv6: None,
                cidr_v6: None,
                mtu: TUN_DEFAULT_MTU,
                max_mtu: TUN_DEFAULT_MTU,
                lease_id: 1,
                allowed_peer_cidrs: vec![IpCidr::V4(cidr_t1)],
            },
        )
        .expect("commit_set_iff");
    let big_pkt = build_icmp_echo_request(ip_a, ip_b, 1, 1, &[0x55; 1300]);
    assert!(big_pkt.len() <= usize::from(TUN_DEFAULT_MTU));
    for _ in 0..900 {
        let _ = reg.inject_rx(tun_id, &big_pkt);
    }
    let flood_info = reg.info_by_tun_id(tun_id).expect("flood info");
    let flood_stats = reg.stats_by_tun_id(tun_id).expect("flood stats");
    assert!(
        flood_info.rx_queued_bytes <= TUN_QUEUE_MAX_BYTES,
        "RX queue exceeded 1 MiB: {:?}",
        flood_info
    );
    assert!(
        flood_stats.rx_dropped_queue_full > 0,
        "expected drop-tail on 1 MiB flood: {:?}",
        flood_stats
    );

    // SIGKILL teardown test: hold TUN open, kill(9), verify clean switch port unregister!
    let att_d = write_cni_attachment(
        &cni_dir,
        "pod-d-kill",
        "u1000",
        cidr_t1.host_ip(3).unwrap(),
        204,
    );
    let (spec_d, stdout_d) = make_pod_spec(
        tmp.path(),
        "pod-d-kill",
        &wasm_tun_hold_forever(),
        Some(att_d),
        Some(Arc::clone(&switch)),
    );
    let pod_d = OciContainerHandle::create(spec_d).expect("create pod-d");
    pod_d.start().expect("start pod-d");
    wait_for_file_contains(&stdout_d, b"READY\n", Duration::from_secs(5));
    assert_eq!(
        switch.active_port_count(),
        1,
        "active TUN port must be registered"
    );

    pod_d.kill(9, true).expect("SIGKILL pod-d");
    let exit_d = pod_d.wait();
    assert_eq!(exit_d.signal, Some(9), "expected SIGKILL exit: {exit_d:?}");
    pod_d.delete().expect("delete pod-d");
    assert_eq!(
        switch.active_port_count(),
        0,
        "SIGKILL + teardown must unregister switch port cleanly"
    );
}

#[test]
fn ov06_zero_boot_network_and_unprivileged_sandbox_no_tun() {
    // Default NativeOverlayConfig has ZERO remote uplink URLs or attachments (zero boot network).
    let cfg = NativeOverlayConfig::default();
    assert!(cfg.overlay_url.is_none());
    assert!(cfg.cni_attachment.is_none());
    assert!(cfg.shared_switch.is_none());

    // An OCI container without CNI attachment MUST NOT have `/dev/net/tun` (`WASI_ENOENT`).
    let tmp = TempDirGuard::new("ov06");
    let (spec, _stdout) = make_pod_spec(
        tmp.path(),
        "pod-unpriv-no-tun",
        &wasm_expect_no_tun(),
        None,
        None,
    );
    let pod = OciContainerHandle::create(spec).expect("create unprivileged pod");
    pod.start().expect("start unprivileged pod");
    let exit = pod.wait();
    assert_eq!(
        exit.exit_code, 0,
        "unprivileged container without CNI must observe ENOENT for /dev/net/tun: {exit:?}"
    );
    pod.delete().expect("delete pod");
}

fn build_ipv6_udp_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 40 + payload.len()];
    pkt[0] = 0x60; // IPv6 version 6
    pkt[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    pkt[6] = 17; // Next Header = UDP
    pkt[7] = 64; // Hop Limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..].copy_from_slice(payload);
    pkt
}

#[test]
fn ov05_layer2_native_switch_firewall_and_dual_stack_ipv6() {
    let switch = NativeOverlaySwitch::new();
    let wake = Arc::new(WakeBus::new());

    let cidr_t1 = derive_tenant_v4_cidr("u1000");
    let cidr_t2 = derive_tenant_v4_cidr("u1001");
    let cidr6_t1 = derive_tenant_v6_cidr("u1000");
    let cidr6_t2 = derive_tenant_v6_cidr("u1001");

    let ip_a = cidr_t1.host_ip(0).unwrap();
    let ip_b = cidr_t1.host_ip(1).unwrap();
    let ip_a_new = cidr_t1.host_ip(2).unwrap();
    let forged_v4 = cidr_t1.host_ip(40).unwrap();
    let ip_c = cidr_t2.host_ip(0).unwrap();

    let ip6_a = cidr6_t1.host_ip(2).unwrap();
    let ip6_b = cidr6_t1.host_ip(3).unwrap();
    let forged_v6 = cidr6_t1.host_ip(40).unwrap();
    let ip6_c = cidr6_t2.host_ip(2).unwrap();

    let (tx_a, _rx_a) = tokio::sync::mpsc::channel(32);
    let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(32);
    let (tx_c, mut rx_c) = tokio::sync::mpsc::channel(32);

    switch
        .register_port(
            "ep-a".to_string(),
            "u1000".to_string(),
            "default".to_string(),
            ip_a,
            cidr_t1,
            Some(ip6_a),
            Some(cidr6_t1),
            TUN_DEFAULT_MTU,
            Vec::new(),
            1,
            tx_a.clone(),
            Arc::clone(&wake),
            None,
            None,
        )
        .expect("register ep-a");
    switch
        .register_port(
            "ep-b".to_string(),
            "u1000".to_string(),
            "default".to_string(),
            ip_b,
            cidr_t1,
            Some(ip6_b),
            Some(cidr6_t1),
            TUN_DEFAULT_MTU,
            Vec::new(),
            2,
            tx_b,
            Arc::clone(&wake),
            None,
            None,
        )
        .expect("register ep-b");
    switch
        .register_port(
            "ep-c".to_string(),
            "u1001".to_string(),
            "default".to_string(),
            ip_c,
            cidr_t2,
            Some(ip6_c),
            Some(cidr6_t2),
            TUN_DEFAULT_MTU,
            Vec::new(),
            3,
            tx_c,
            Arc::clone(&wake),
            None,
            None,
        )
        .expect("register ep-c");

    assert_eq!(switch.active_port_count(), 3);

    // 1. Direct layer-2 spoofed IPv4 source -> dropped & counted on switch (bypassing os-vfs).
    let spoof_v4 = build_icmp_echo_request(forged_v4, ip_b, 1, 1, b"l2-spoof-v4");
    assert_eq!(
        switch.forward_from_port("ep-a", &spoof_v4),
        Err(DropReason::SpoofedSource)
    );
    assert!(rx_b.try_recv().is_err());

    // 2. Direct layer-2 cross-tenant IPv4 -> dropped & counted on switch; Tenant u1001 gets 0!
    let cross_v4 = build_icmp_echo_request(ip_a, ip_c, 1, 2, b"l2-cross-v4");
    assert_eq!(
        switch.forward_from_port("ep-a", &cross_v4),
        Err(DropReason::CrossTenant)
    );
    assert!(rx_c.try_recv().is_err());

    // 3. Valid intra-tenant IPv4 -> forwarded locally to ep-b.
    let ok_v4 = build_icmp_echo_request(ip_a, ip_b, 1, 3, b"l2-ok-v4");
    assert_eq!(
        switch.forward_from_port("ep-a", &ok_v4),
        Ok(ForwardOutcome::DeliveredLocal)
    );
    match rx_b.try_recv().expect("ep-b should receive IPv4 packet") {
        OverlayActorEvent::RxPacket { tun_id, pkt } => {
            assert_eq!(tun_id, 2);
            assert_eq!(pkt, ok_v4);
        }
        _ => panic!("expected RxPacket"),
    }

    // 4. Dual-stack IPv6 intra-tenant forwarding + IPv6 anti-spoofing + IPv6 cross-tenant denial!
    let ok_v6 = build_ipv6_udp_packet(ip6_a, ip6_b, b"l2-ok-v6");
    assert_eq!(
        switch.forward_from_port("ep-a", &ok_v6),
        Ok(ForwardOutcome::DeliveredLocal)
    );
    match rx_b.try_recv().expect("ep-b should receive IPv6 packet") {
        OverlayActorEvent::RxPacket { tun_id, pkt } => {
            assert_eq!(tun_id, 2);
            assert_eq!(pkt, ok_v6);
        }
        _ => panic!("expected RxPacket"),
    }

    let spoof_v6 = build_ipv6_udp_packet(forged_v6, ip6_b, b"l2-spoof-v6");
    assert_eq!(
        switch.forward_from_port("ep-a", &spoof_v6),
        Err(DropReason::SpoofedSource)
    );
    assert!(rx_b.try_recv().is_err());

    let cross_v6 = build_ipv6_udp_packet(ip6_a, ip6_c, b"l2-cross-v6");
    assert_eq!(
        switch.forward_from_port("ep-a", &cross_v6),
        Err(DropReason::CrossTenant)
    );
    assert!(rx_c.try_recv().is_err());

    let c = switch.counters();
    assert_eq!(
        c.forwarded_local, 2,
        "expected 2 local forwards (v4 + v6): {c:?}"
    );
    assert_eq!(
        c.dropped_spoofed_src, 2,
        "expected 2 spoofed_src drops (v4 + v6): {c:?}"
    );
    assert_eq!(
        c.dropped_cross_tenant, 2,
        "expected 2 cross_tenant drops (v4 + v6): {c:?}"
    );

    // 5. Re-registering `ep-a` with a new IP cleans up its old IP key from `ports`.
    switch
        .register_port(
            "ep-a".to_string(),
            "u1000".to_string(),
            "default".to_string(),
            ip_a_new,
            cidr_t1,
            None,
            None,
            TUN_DEFAULT_MTU,
            Vec::new(),
            1,
            tx_a,
            Arc::clone(&wake),
            None,
            None,
        )
        .expect("re-register ep-a with new IP");
    assert_eq!(switch.active_port_count(), 3);
    assert_eq!(
        switch.alloc_local_ip("u1000", "default", cidr_t1),
        Ok(ip_a),
        "old IP must have been freed from ports map on re-registration"
    );

    switch.unregister_endpoint("ep-a");
    switch.unregister_endpoint("ep-b");
    switch.unregister_endpoint("ep-c");
    assert_eq!(switch.active_port_count(), 0);
}
