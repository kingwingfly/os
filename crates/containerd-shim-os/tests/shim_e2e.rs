//! Full cross-component Phase 9.5 E2E test:
//! Real compiled `containerd-shim-os-v1` binary (TTRPC v2/v3 over `0600` Unix socket)
//! + Real `os-csi` Controller & Node plugins (gRPC-h2c over `0600` Unix socket + `ClusterState` leases)
//! + Real `os-nbd` Fixed Newstyle block export (`0600` Unix socket)
//! + Isolated `os-native` Wasmtime 51 OCI containers.
//!
//! Exercises:
//! 1. CRI PodSandbox lifecycle (`Create` -> `Start` -> `State` -> `Connect` -> `Pids`)
//! 2. CSI FS volume creation, seeding, O(1) snapshot + O(1) snapshot restore, publish/stage
//! 3. CSI raw block volume creation, publish/stage -> `os-nbd` `NbdClient` seed block 0
//! 4. WASI preview1 OCI container reading/writing BOTH CSI `cowfs` `/data` and CSI raw `/dev/vd0`
//!    with host Linux FIFO stdout capture, verifying persistence across `os-cowfs` & `os-nbd`
//! 5. Explicit rejection of Linux `\x7fELF` executables with `ENOEXEC`
//! 6. Wasmtime 51 epoch preemption `< 200 ms` on `Kill(SIGKILL)` of an infinite-loop Wasm module
//! 7. Competing native `ForceTakeover` writer fencing causing `Delete` to fail closed with `ESTALE`
//! 8. Clean TTRPC `Shutdown` terminating the shim daemon and unlinking its Unix socket.

use abi::auth_v2::RemoteScope;
use abi::fs::{OpenOptions, Timespec, WriteAt};
use containerd_shim_os::task_proto::{
    ConnectRequest, ConnectResponse, CreateTaskRequest, CreateTaskResponse, DeleteRequest,
    DeleteResponse, ExecProcessRequest, KillRequest, PidsRequest, PidsResponse, ProtoAny,
    ShutdownRequest, StartRequest, StartResponse, StateRequest, StateResponse, TASK_V2_SERVICE,
    TASK_V3_SERVICE, TaskStatus, WaitRequest, WaitResponse,
};
use containerd_shim_os::ttrpc::{MultiplexedTtrpcClient, RpcCode, TtrpcClient};
use cowtree::{VolumeId, WriterMode};
use os_cluster_state::ClusterGrant;
use os_cluster_state::memory::MemoryClusterStore;
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{CowFs, CowFsConfig, CowFsOpenMode};
use os_csi::controller::{CsiControllerConfig, OsCsiController};
use os_csi::grpc_unix::{CsiGrpcClient, CsiGrpcServerHandle, CsiServiceRouter};
use os_csi::node::{CsiNodeConfig, OsCsiNode, StageMode};
use os_csi::spec::{
    AccessMode, CapacityRange, ControllerPublishVolumeRequest, ControllerUnpublishVolumeRequest,
    CreateSnapshotRequest, CreateVolumeRequest, NodePublishVolumeRequest, NodeStageVolumeRequest,
    NodeUnpublishVolumeRequest, NodeUnstageVolumeRequest, VolumeCapability, VolumeContentSource,
};
use os_nbd::NbdClient;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use vfs::{Cred, Filesystem};

// ---------------------------------------------------------------------------
// Minimal self-contained WebAssembly 1.0 + WASI preview1 binary builders
// ---------------------------------------------------------------------------

fn push_uleb(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn push_sleb(out: &mut Vec<u8>, mut v: i64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0);
        out.push(if done { b } else { b | 0x80 });
        if done {
            break;
        }
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    push_uleb(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn push_section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
    out.push(id);
    push_uleb(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

fn i32_const(code: &mut Vec<u8>, v: i32) {
    code.push(0x41);
    push_sleb(code, i64::from(v));
}

fn i64_const(code: &mut Vec<u8>, v: i64) {
    code.push(0x42);
    push_sleb(code, v);
}

fn local_get(code: &mut Vec<u8>, idx: u32) {
    code.push(0x20);
    push_uleb(code, u64::from(idx));
}

fn local_set(code: &mut Vec<u8>, idx: u32) {
    code.push(0x21);
    push_uleb(code, u64::from(idx));
}

fn i32_load(code: &mut Vec<u8>, off: u32) {
    code.push(0x28);
    code.push(0x02);
    push_uleb(code, u64::from(off));
}

fn i32_store(code: &mut Vec<u8>, off: u32) {
    code.push(0x36);
    code.push(0x02);
    push_uleb(code, u64::from(off));
}

fn call_fn(code: &mut Vec<u8>, idx: u32) {
    code.push(0x10);
    push_uleb(code, u64::from(idx));
}

/// Emit `if (rc != 0) proc_exit(rc)` where `proc_exit` is function index `exit_fn`.
fn check_rc(code: &mut Vec<u8>, rc_local: u32, exit_fn: u32) {
    local_set(code, rc_local);
    local_get(code, rc_local);
    code.push(0x04); // if
    code.push(0x40); // void
    local_get(code, rc_local);
    call_fn(code, exit_fn);
    code.push(0x0b); // end
}

/// Build a tiny WASI preview1 `.wasm` module that prints `"EXEC-OK"` to stdout and exits 0.
fn build_exec_hello_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    let mut types = vec![3];
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]); // 0: fd_write
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]); // 1: proc_exit
    types.extend_from_slice(&[0x60, 0, 0]); // 2: _start
    push_section(&mut wasm, 1, &types);

    let mut imp = vec![2];
    push_str(&mut imp, "wasi_snapshot_preview1");
    push_str(&mut imp, "fd_write");
    imp.extend_from_slice(&[0x00, 0]);
    push_str(&mut imp, "wasi_snapshot_preview1");
    push_str(&mut imp, "proc_exit");
    imp.extend_from_slice(&[0x00, 1]);
    push_section(&mut wasm, 2, &imp);

    push_section(&mut wasm, 3, &[1, 2]); // fn 2 = _start
    push_section(&mut wasm, 5, &[1, 0, 1]);
    let mut exp = vec![2];
    push_str(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0]);
    push_str(&mut exp, "_start");
    exp.extend_from_slice(&[0x00, 2]);
    push_section(&mut wasm, 7, &exp);

    let mut body = vec![0];
    i32_const(&mut body, 0x200);
    i32_const(&mut body, 0x100);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x204);
    i32_const(&mut body, 7);
    i32_store(&mut body, 0);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x200);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x208);
    call_fn(&mut body, 0);
    body.push(0x1a);
    i32_const(&mut body, 0);
    call_fn(&mut body, 1);
    body.push(0x0b);

    let mut code_sec = vec![1];
    push_uleb(&mut code_sec, body.len() as u64);
    code_sec.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code_sec);

    let mut data_sec = vec![1, 0x00];
    i32_const(&mut data_sec, 0x100);
    data_sec.push(0x0b);
    push_uleb(&mut data_sec, 7);
    data_sec.extend_from_slice(b"EXEC-OK");
    push_section(&mut wasm, 11, &data_sec);
    wasm
}

/// Build a valid WASI preview1 `.wasm` module that spins in `(loop (br 0))` forever until preempted.
fn build_spin_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    // Type 0: () -> ()
    push_section(&mut wasm, 1, &[1, 0x60, 0, 0]);
    // Func 0: type 0
    push_section(&mut wasm, 3, &[1, 0]);
    // Memory 0: 1 page
    push_section(&mut wasm, 5, &[1, 0, 1]);
    // Exports: memory + _start
    let mut exp = vec![2];
    push_str(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0]);
    push_str(&mut exp, "_start");
    exp.extend_from_slice(&[0x00, 0]);
    push_section(&mut wasm, 7, &exp);
    // Code: loop { br 0 } end
    let body = vec![0, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b];
    let mut code_sec = vec![1];
    push_uleb(&mut code_sec, body.len() as u64);
    code_sec.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code_sec);
    wasm
}

/// Build a valid WASI preview1 `.wasm` module that:
/// 1. Reads `data/seed.txt` (via preopen fd 3)
/// 2. Creates & writes `data/from-container.txt` with `"CONTAINER-FS:"` + seed bytes + `fd_sync`
/// 3. Opens `dev/vd0` RW, `fd_pread` 16 bytes at offset 0, `fd_pwrite` `"CONTAINER-RAW-OK"` at offset 512, `fd_sync`
/// 4. Writes `"OK:"` + seed bytes + `"|BLK:"` + 16 bytes from `/dev/vd0` offset 0 to stdout (fd 1)
/// 5. Exits 0 (or non-zero WASI errno on any error).
fn build_storage_worker_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();

    // Types:
    // 0: path_open (i32, i32, i32, i32, i32, i64, i64, i32, i32) -> i32
    // 1: fd_read / fd_write (i32, i32, i32, i32) -> i32
    // 2: fd_pread / fd_pwrite (i32, i32, i32, i64, i32) -> i32
    // 3: fd_sync / fd_close (i32) -> i32
    // 4: proc_exit (i32) -> ()
    // 5: _start () -> ()
    let mut types = vec![6];
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]);
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 5, 0x7f, 0x7f, 0x7f, 0x7e, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 1, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]);
    types.extend_from_slice(&[0x60, 0, 0]);
    push_section(&mut wasm, 1, &types);

    // Imports (fn 0..7):
    // 0: path_open (t0)
    // 1: fd_read (t1)
    // 2: fd_write (t1)
    // 3: fd_pread (t2)
    // 4: fd_pwrite (t2)
    // 5: fd_sync (t3)
    // 6: fd_close (t3)
    // 7: proc_exit (t4)
    let imports = [
        ("path_open", 0u8),
        ("fd_read", 1),
        ("fd_write", 1),
        ("fd_pread", 2),
        ("fd_pwrite", 2),
        ("fd_sync", 3),
        ("fd_close", 3),
        ("proc_exit", 4),
    ];
    let mut imp_sec = vec![imports.len() as u8];
    for (name, ty) in imports {
        push_str(&mut imp_sec, "wasi_snapshot_preview1");
        push_str(&mut imp_sec, name);
        imp_sec.push(0x00);
        imp_sec.push(ty);
    }
    push_section(&mut wasm, 2, &imp_sec);

    // Func 8 = _start (type 5)
    push_section(&mut wasm, 3, &[1, 5]);
    // Memory 0: 1 page
    push_section(&mut wasm, 5, &[1, 0, 1]);
    // Exports
    let mut exp = vec![2];
    push_str(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0]);
    push_str(&mut exp, "_start");
    exp.extend_from_slice(&[0x00, 8]);
    push_section(&mut wasm, 7, &exp);

    // Static data layout in linear memory:
    // 0x100: "data/seed.txt" (13)
    // 0x120: "data/from-container.txt" (23)
    // 0x150: "dev/vd0" (7)
    // 0x170: "CONTAINER-FS:" (13)
    // 0x190: "CONTAINER-RAW-OK" (16)
    // 0x1b0: "OK:" (3)
    // 0x1c0: "|BLK:" (5)
    // Scratch addresses:
    // 0x300: opened_fd (u32)
    // 0x304: nbytes (u32)
    // 0x310: iov0..iov3 (each 8 bytes: ptr, len)
    // 0x400: seed_buf (64 bytes)
    // 0x500: blk_buf (16 bytes)

    // Locals: 0=rc, 1=fd, 2=seed_len
    let mut body = vec![1, 3, 0x7f]; // 1 local decl of 3 i32s

    // Step 1: path_open(3, 0, 0x100, 13, 0, 2, 2, 0, 0x300)
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x100);
    i32_const(&mut body, 13);
    i32_const(&mut body, 0);
    i64_const(&mut body, 2); // FD_READ
    i64_const(&mut body, 2);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    check_rc(&mut body, 0, 7);

    // fd = load(0x300)
    i32_const(&mut body, 0x300);
    i32_load(&mut body, 0);
    local_set(&mut body, 1);

    // iov0 = (0x400, 64)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x400);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 64);
    i32_store(&mut body, 0);

    // fd_read(fd, 0x310, 1, 0x304)
    local_get(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 1);
    check_rc(&mut body, 0, 7);

    // seed_len = load(0x304)
    i32_const(&mut body, 0x304);
    i32_load(&mut body, 0);
    local_set(&mut body, 2);

    // fd_close(fd)
    local_get(&mut body, 1);
    call_fn(&mut body, 6);
    check_rc(&mut body, 0, 7);

    // Step 2: path_open(3, 0, 0x120, 23, 9 /*CREAT|TRUNC*/, 82 /*R|W|SYNC*/, 82, 0, 0x300)
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x120);
    i32_const(&mut body, 23);
    i32_const(&mut body, 9);
    i64_const(&mut body, 82);
    i64_const(&mut body, 82);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    check_rc(&mut body, 0, 7);

    i32_const(&mut body, 0x300);
    i32_load(&mut body, 0);
    local_set(&mut body, 1);

    // iov0 = ("CONTAINER-FS:", 13), iov1 = (0x400, seed_len)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x170);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 13);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x318);
    i32_const(&mut body, 0x400);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x31c);
    local_get(&mut body, 2);
    i32_store(&mut body, 0);

    // fd_write(fd, 0x310, 2, 0x304)
    local_get(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 2);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 2);
    check_rc(&mut body, 0, 7);

    // fd_sync(fd) + fd_close(fd)
    local_get(&mut body, 1);
    call_fn(&mut body, 5);
    check_rc(&mut body, 0, 7);
    local_get(&mut body, 1);
    call_fn(&mut body, 6);
    check_rc(&mut body, 0, 7);

    // Step 3: path_open(3, 0, 0x150, 7, 0, 82, 82, 0, 0x300) for "dev/vd0"
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x150);
    i32_const(&mut body, 7);
    i32_const(&mut body, 0);
    i64_const(&mut body, 82);
    i64_const(&mut body, 82);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    check_rc(&mut body, 0, 7);

    i32_const(&mut body, 0x300);
    i32_load(&mut body, 0);
    local_set(&mut body, 1);

    // fd_pread(fd, iov=(0x500, 16), 1, offset=0, 0x304)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x500);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 16);
    i32_store(&mut body, 0);

    local_get(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i64_const(&mut body, 0);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 3);
    check_rc(&mut body, 0, 7);

    // fd_pwrite(fd, iov=(0x190 "CONTAINER-RAW-OK", 16), 1, offset=512, 0x304)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x190);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 16);
    i32_store(&mut body, 0);

    local_get(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i64_const(&mut body, 512);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 4);
    check_rc(&mut body, 0, 7);

    // fd_sync(fd) + fd_close(fd)
    local_get(&mut body, 1);
    call_fn(&mut body, 5);
    check_rc(&mut body, 0, 7);
    local_get(&mut body, 1);
    call_fn(&mut body, 6);
    check_rc(&mut body, 0, 7);

    // Step 4: write "OK:" + seed_buf + "|BLK:" + blk_buf to stdout (fd 1)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x1b0);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 3);
    i32_store(&mut body, 0);

    i32_const(&mut body, 0x318);
    i32_const(&mut body, 0x400);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x31c);
    local_get(&mut body, 2);
    i32_store(&mut body, 0);

    i32_const(&mut body, 0x320);
    i32_const(&mut body, 0x1c0);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x324);
    i32_const(&mut body, 5);
    i32_store(&mut body, 0);

    i32_const(&mut body, 0x328);
    i32_const(&mut body, 0x500);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x32c);
    i32_const(&mut body, 16);
    i32_store(&mut body, 0);

    i32_const(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 4);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 2);
    check_rc(&mut body, 0, 7);

    // proc_exit(0)
    i32_const(&mut body, 0);
    call_fn(&mut body, 7);
    body.push(0x0b); // end

    let mut code_sec = vec![1];
    push_uleb(&mut code_sec, body.len() as u64);
    code_sec.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code_sec);

    // Data segments
    let segs: &[(i32, &[u8])] = &[
        (0x100, b"data/seed.txt"),
        (0x120, b"data/from-container.txt"),
        (0x150, b"dev/vd0"),
        (0x170, b"CONTAINER-FS:"),
        (0x190, b"CONTAINER-RAW-OK"),
        (0x1b0, b"OK:"),
        (0x1c0, b"|BLK:"),
    ];
    let mut data_sec = vec![segs.len() as u8];
    for &(off, bytes) in segs {
        data_sec.push(0x00); // mem 0
        i32_const(&mut data_sec, off);
        data_sec.push(0x0b);
        push_uleb(&mut data_sec, bytes.len() as u64);
        data_sec.extend_from_slice(bytes);
    }
    push_section(&mut wasm, 11, &data_sec);
    wasm
}

/// Build a valid WASI preview1 `.wasm` module for deterministic competing-writer fencing tests:
/// 1. Opens `data/fenced.txt` (`CREAT|TRUNC|RDWR`), writes `"STALE-DATA"`, closes fd (dirty uncommitted)
/// 2. Writes `"READY"` to stdout (fd 1)
/// 3. Blocks on `fd_read(0, ...)` until host closes/writes stdin FIFO
/// 4. Exits 0 (so `Delete` attempts fenced commit -> `ESTALE`!).
fn build_fenced_writer_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    let mut types = vec![5];
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]); // 0: path_open
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]); // 1: fd_read/write
    types.extend_from_slice(&[0x60, 1, 0x7f, 1, 0x7f]); // 2: fd_close
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]); // 3: proc_exit
    types.extend_from_slice(&[0x60, 0, 0]); // 4: _start
    push_section(&mut wasm, 1, &types);

    // 0: path_open, 1: fd_read, 2: fd_write, 3: fd_close, 4: proc_exit
    let imports = [
        ("path_open", 0u8),
        ("fd_read", 1),
        ("fd_write", 1),
        ("fd_close", 2),
        ("proc_exit", 3),
    ];
    let mut imp_sec = vec![imports.len() as u8];
    for (name, ty) in imports {
        push_str(&mut imp_sec, "wasi_snapshot_preview1");
        push_str(&mut imp_sec, name);
        imp_sec.push(0x00);
        imp_sec.push(ty);
    }
    push_section(&mut wasm, 2, &imp_sec);
    push_section(&mut wasm, 3, &[1, 4]); // fn 5 = _start
    push_section(&mut wasm, 5, &[1, 0, 1]);
    let mut exp = vec![2];
    push_str(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0]);
    push_str(&mut exp, "_start");
    exp.extend_from_slice(&[0x00, 5]);
    push_section(&mut wasm, 7, &exp);

    let mut body = vec![1, 2, 0x7f]; // locals 0=rc, 1=fd
    // Open data/fenced.txt
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x100);
    i32_const(&mut body, 15);
    i32_const(&mut body, 9);
    i64_const(&mut body, 66);
    i64_const(&mut body, 66);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    check_rc(&mut body, 0, 4);

    i32_const(&mut body, 0x300);
    i32_load(&mut body, 0);
    local_set(&mut body, 1);

    // Write "STALE-DATA" (10 bytes at 0x120)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x120);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 10);
    i32_store(&mut body, 0);
    local_get(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 2);
    check_rc(&mut body, 0, 4);

    local_get(&mut body, 1);
    call_fn(&mut body, 3);
    check_rc(&mut body, 0, 4);

    // Write "READY" (5 bytes at 0x140) to stdout (fd 1)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x140);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 5);
    i32_store(&mut body, 0);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 2);
    check_rc(&mut body, 0, 4);

    // Block on stdin fd 0 read (16 bytes into 0x400) until host releases us
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x400);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 16);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 1);
    body.push(0x1a); // drop rc

    i32_const(&mut body, 0);
    call_fn(&mut body, 4);
    body.push(0x0b);

    let mut code_sec = vec![1];
    push_uleb(&mut code_sec, body.len() as u64);
    code_sec.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code_sec);

    let segs: &[(i32, &[u8])] = &[
        (0x100, b"data/fenced.txt"),
        (0x120, b"STALE-DATA"),
        (0x140, b"READY"),
    ];
    let mut data_sec = vec![segs.len() as u8];
    for &(off, bytes) in segs {
        data_sec.push(0x00);
        i32_const(&mut data_sec, off);
        data_sec.push(0x0b);
        push_uleb(&mut data_sec, bytes.len() as u64);
        data_sec.extend_from_slice(bytes);
    }
    push_section(&mut wasm, 11, &data_sec);
    wasm
}

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn temp_test_dir(tag: &str) -> PathBuf {
    let base = match std::env::var_os("TMPDIR") {
        Some(t) if t.len() <= 50 => PathBuf::from(t),
        _ => PathBuf::from("/tmp"),
    };
    let dir = base.join(format!(
        "os-shim-{tag}-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn mkfifo(path: &Path) {
    let c = CString::new(path.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(rc, 0, "mkfifo {} failed", path.display());
}

fn write_bundle_config(bundle: &Path, config: &serde_json::Value) {
    std::fs::create_dir_all(bundle.join("rootfs")).unwrap();
    std::fs::write(
        bundle.join("config.json"),
        serde_json::to_vec_pretty(config).unwrap(),
    )
    .unwrap();
}

async fn read_cowfs_file(store_dir: &Path, vol_id: &str, name: &str) -> Vec<u8> {
    let hs = Rc::new(NativeSqliteHeadStore::open(store_dir).unwrap());
    let ps = Rc::new(NativePackStore::open(store_dir).unwrap());
    let clock: os_cowfs::CowFsClock = Rc::new(|| Timespec {
        sec: 1_700_000_000,
        nsec: 0,
    });
    let fs = CowFs::open(
        hs,
        ps,
        VolumeId(vol_id.to_string()),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_native(clock),
    )
    .await
    .unwrap();
    let cred = Cred::root();
    let root = fs.root();
    let ent = fs.lookup(&cred, &root, name).await.unwrap();
    let mut opts = OpenOptions::new();
    opts.read(true);
    let r = fs.open(&cred, &ent.handle, &opts).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = fs.read_at(&r, &mut buf, 0).await.unwrap();
    let _ = fs.release(&r).await;
    let _ = fs.close_clean().await;
    buf.truncate(n);
    buf
}

#[test]
fn shim_csi_nbd_full_e2e_lifecycle_preemption_elf_rejection_and_fencing() {
    let dir = temp_test_dir("e2e");
    let store_dir = dir.join("store");
    let node_state = dir.join("node-state");
    let mounts_root = dir.join("mnt");
    let bundles_root = dir.join("bundles");
    std::fs::create_dir_all(&store_dir).unwrap();
    std::fs::create_dir_all(&node_state).unwrap();
    std::fs::create_dir_all(&mounts_root).unwrap();
    std::fs::create_dir_all(&bundles_root).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async {
        // ------------------------------------------------------------------
        // 1. Start real `os-csi` Controller + Node over gRPC-h2c `AF_UNIX`
        // ------------------------------------------------------------------
        let cluster = Arc::new(MemoryClusterStore::new("default"));
        let grant = ClusterGrant {
            tenant: "u0".into(),
            owner: "csi-e2e".into(),
            admin: true,
            scope: RemoteScope {
                cluster_read: true,
                cluster_write: true,
                cluster_watch: true,
                cluster_lease: true,
                ..RemoteScope::default()
            },
        };
        let ctrl_cfg = CsiControllerConfig::new("u0", grant.clone(), store_dir.clone());
        let controller = Arc::new(OsCsiController::new(Arc::clone(&cluster), ctrl_cfg));
        let mut node_cfg = CsiNodeConfig::new(
            "node-e2e",
            "u0",
            grant,
            node_state.clone(),
            store_dir.clone(),
        );
        node_cfg.allowed_mount_root = Some(mounts_root.clone());
        node_cfg.stage_mode = StageMode::HostSubvol;
        let node = Arc::new(OsCsiNode::new(Arc::clone(&cluster), node_cfg));

        let csi_sock = dir.join("csi.sock");
        let mut csi_srv = CsiGrpcServerHandle::bind_and_spawn(
            csi_sock.clone(),
            CsiServiceRouter::new(
                controller.clone(),
                Some(controller.clone()),
                Some(node.clone()),
            ),
        )
        .unwrap();
        let mut csi = CsiGrpcClient::connect_unix(&csi_sock).await.unwrap();

        let fs_cap = VolumeCapability::mount("cowfs", AccessMode::SingleNodeWriter);
        let blk_cap = VolumeCapability::block(AccessMode::SingleNodeWriter);

        // Create FS volume, seed `seed.txt`, snapshot O(1), restore O(1) into a new CSI volume!
        let base_fs_vol = csi
            .create_volume(&CreateVolumeRequest {
                name: "base-fs-vol".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 16 * 1024 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![fs_cap.clone()],
                parameters: BTreeMap::new(),
                secrets: BTreeMap::new(),
                volume_content_source: None,
            })
            .await
            .unwrap()
            .volume
            .volume_id;

        // Publish & stage base FS volume to write seed.txt
        let pub_base = csi
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: base_fs_vol.clone(),
                node_id: "node-e2e".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                secrets: BTreeMap::new(),
                volume_context: BTreeMap::new(),
            })
            .await
            .unwrap();
        let base_stage = mounts_root.join("stage-base");
        csi.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: base_fs_vol.clone(),
            publish_context: pub_base.publish_context,
            staging_target_path: base_stage.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();
        node.write_staged_file(&base_fs_vol, "seed.txt", b"SNAP-SEED-V1", true)
            .await
            .unwrap();

        // Create O(1) snapshot & restore into `restored-fs-vol`
        let snap = csi
            .create_snapshot(&CreateSnapshotRequest {
                source_volume_id: base_fs_vol.clone(),
                name: "snap-seed".into(),
                parameters: BTreeMap::new(),
                secrets: BTreeMap::new(),
            })
            .await
            .unwrap()
            .snapshot;
        assert!(snap.ready_to_use);

        let restored_fs_vol = csi
            .create_volume(&CreateVolumeRequest {
                name: "restored-fs-vol".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 16 * 1024 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![fs_cap.clone()],
                parameters: BTreeMap::new(),
                secrets: BTreeMap::new(),
                volume_content_source: Some(VolumeContentSource::Snapshot {
                    snapshot_id: snap.snapshot_id.clone(),
                }),
            })
            .await
            .unwrap()
            .volume
            .volume_id;

        let pub_fs = csi
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: restored_fs_vol.clone(),
                node_id: "node-e2e".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                secrets: BTreeMap::new(),
                volume_context: BTreeMap::new(),
            })
            .await
            .unwrap();
        let fs_stage = mounts_root.join("stage-restored");
        let fs_target = mounts_root.join("pod-data");
        csi.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: restored_fs_vol.clone(),
            publish_context: pub_fs.publish_context.clone(),
            staging_target_path: fs_stage.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();
        csi.node_publish_volume(&NodePublishVolumeRequest {
            volume_id: restored_fs_vol.clone(),
            publish_context: pub_fs.publish_context,
            staging_target_path: fs_stage.to_string_lossy().into_owned(),
            target_path: fs_target.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            readonly: false,
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();

        // Create CSI raw block volume, stage (`os-nbd`), seed block 0 via `NbdClient`!
        let mut blk_params = BTreeMap::new();
        blk_params.insert("volumeMode".into(), "Block".into());
        blk_params.insert("blockSize".into(), "4096".into());
        let blk_vol = csi
            .create_volume(&CreateVolumeRequest {
                name: "pod-raw-blk".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 2 * 1024 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![blk_cap.clone()],
                parameters: blk_params,
                secrets: BTreeMap::new(),
                volume_content_source: None,
            })
            .await
            .unwrap()
            .volume
            .volume_id;
        let pub_blk = csi
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: blk_vol.clone(),
                node_id: "node-e2e".into(),
                volume_capability: Some(blk_cap.clone()),
                readonly: false,
                secrets: BTreeMap::new(),
                volume_context: BTreeMap::new(),
            })
            .await
            .unwrap();
        let blk_stage = mounts_root.join("stage-blk");
        let blk_target = mounts_root.join("pod-raw.blk");
        csi.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: blk_vol.clone(),
            publish_context: pub_blk.publish_context.clone(),
            staging_target_path: blk_stage.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();
        csi.node_publish_volume(&NodePublishVolumeRequest {
            volume_id: blk_vol.clone(),
            publish_context: pub_blk.publish_context.clone(),
            staging_target_path: blk_stage.to_string_lossy().into_owned(),
            target_path: blk_target.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            readonly: false,
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();

        // Seed block 0 via `os-nbd` `NbdClient`!
        let nbd_sock = node.nbd_socket_for_volume(&blk_vol).unwrap();
        let mut nbd = NbdClient::connect_unix(&nbd_sock).await.unwrap();
        let _ = nbd.go(&blk_vol).await.unwrap();
        nbd.write(0, b"NBD-SEED-BLOCK0!", true).await.unwrap();
        nbd.flush().await.unwrap();
        nbd.disconnect().await.unwrap();

        // ------------------------------------------------------------------
        // 2. Spawn REAL compiled `containerd-shim-os-v1` binary via `start`!
        // ------------------------------------------------------------------
        let shim_bin = env!("CARGO_BIN_EXE_containerd-shim-os-v1");
        let sandbox_bundle = bundles_root.join("sandbox");
        write_bundle_config(
            &sandbox_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/pause"], "cwd": "/" },
                "annotations": {
                    "io.kubernetes.cri.container-type": "sandbox",
                    "io.kubernetes.cri.sandbox-id": "pod-e2e-1",
                    "os.csi/node-state": node_state.to_string_lossy()
                }
            }),
        );

        let start_out = Command::new(shim_bin)
            .arg("-namespace")
            .arg("k8s.io")
            .arg("-id")
            .arg("pod-e2e-1")
            .arg("-bundle")
            .arg(&sandbox_bundle)
            .arg("-csi-state")
            .arg(&node_state)
            .arg("start")
            .output()
            .expect("spawn containerd-shim-os-v1 start");
        assert!(
            start_out.status.success(),
            "shim start failed: stderr={}",
            String::from_utf8_lossy(&start_out.stderr)
        );
        let addr = String::from_utf8(start_out.stdout).unwrap();
        let shim_sock = PathBuf::from(
            addr.trim()
                .strip_prefix("unix://")
                .expect("shim start must print unix://<path>"),
        );
        let sock_mode = std::fs::symlink_metadata(&shim_sock)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(sock_mode, 0o600, "shim TTRPC socket must be 0600");

        let mut client = TtrpcClient::connect(&shim_sock).await.unwrap();

        // ------------------------------------------------------------------
        // 3. CRI PodSandbox lifecycle over `containerd.task.v2.Task`
        // ------------------------------------------------------------------
        let c_resp = CreateTaskResponse::decode(
            &client
                .call(
                    TASK_V2_SERVICE,
                    "Create",
                    CreateTaskRequest {
                        id: "pod-e2e-1".into(),
                        bundle: sandbox_bundle.to_string_lossy().into_owned(),
                        ..Default::default()
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(c_resp.pid, 1);

        let st0 = StateResponse::decode(
            &client
                .call(
                    TASK_V2_SERVICE,
                    "State",
                    StateRequest {
                        id: "pod-e2e-1".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(st0.status, TaskStatus::Created);

        let s_resp = StartResponse::decode(
            &client
                .call(
                    TASK_V2_SERVICE,
                    "Start",
                    StartRequest {
                        id: "pod-e2e-1".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(s_resp.pid, 1);

        let conn = ConnectResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Connect",
                    ConnectRequest {
                        id: "pod-e2e-1".into(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(conn.shim_pid > 0);
        assert_eq!(conn.task_pid, 1);

        let pids = PidsResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Pids",
                    PidsRequest {
                        id: "pod-e2e-1".into(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!pids.processes.is_empty());

        // ------------------------------------------------------------------
        // 4. WASI container reading/writing BOTH CSI cowfs `/data` & raw `/dev/vd0`
        //    with host Linux FIFO stdout capture!
        // ------------------------------------------------------------------
        let app_bundle = bundles_root.join("app-worker");
        write_bundle_config(
            &app_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": {
                    "args": ["/worker.wasm"],
                    "env": ["PATH=/usr/bin:/bin"],
                    "cwd": "/"
                },
                "mounts": [
                    {
                        "destination": "/data",
                        "type": "bind",
                        "source": fs_target.to_string_lossy(),
                        "options": ["rbind", "rw"]
                    },
                    {
                        "destination": "/dev/vd0",
                        "type": "bind",
                        "source": blk_target.to_string_lossy(),
                        "options": ["rw"]
                    }
                ],
                "linux": {
                    "resources": {
                        "memory": { "limit": 67108864 },
                        "pids": { "limit": 16 }
                    }
                },
                "annotations": {
                    "io.kubernetes.cri.container-type": "container",
                    "io.kubernetes.cri.sandbox-id": "pod-e2e-1",
                    "os.csi/node-state": node_state.to_string_lossy()
                }
            }),
        );
        let worker_path = app_bundle.join("rootfs").join("worker.wasm");
        std::fs::write(&worker_path, build_storage_worker_wasm()).unwrap();
        std::fs::set_permissions(&worker_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let stdout_fifo = dir.join("worker.stdout.fifo");
        mkfifo(&stdout_fifo);
        let fifo_read_path = stdout_fifo.clone();
        let fifo_reader = std::thread::spawn(move || {
            let mut f = std::fs::File::open(&fifo_read_path).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            buf
        });

        let _ = client
            .call(
                TASK_V3_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "app-worker".into(),
                    bundle: app_bundle.to_string_lossy().into_owned(),
                    stdout: stdout_fifo.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();

        let _ = client
            .call(
                TASK_V3_SERVICE,
                "Start",
                StartRequest {
                    id: "app-worker".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();

        let w_resp = WaitResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Wait",
                    WaitRequest {
                        id: "app-worker".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(w_resp.exit_status, 0, "worker.wasm must exit 0");

        let d_resp = DeleteResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Delete",
                    DeleteRequest {
                        id: "app-worker".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(d_resp.exit_status, 0);

        let captured = fifo_reader.join().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&captured),
            "OK:SNAP-SEED-V1|BLK:NBD-SEED-BLOCK0!",
            "worker stdout must confirm both CSI FS snapshot seed and NBD raw block seed"
        );

        // Verify CSI cowfs persistence directly on committed volume!
        let persisted_fs =
            read_cowfs_file(&store_dir, &restored_fs_vol, "from-container.txt").await;
        assert_eq!(persisted_fs, b"CONTAINER-FS:SNAP-SEED-V1");

        // Verify CSI raw block persistence IMMEDIATELY through `OsCsiNode`'s EXISTING `nbd_sock`
        // WITHOUT unstaging/restaging — proving container `/dev/vd0` routed through `os-nbd` with
        // ZERO self-fencing! (P0-5)
        {
            let mut nbd_live = NbdClient::connect_unix(&nbd_sock).await.unwrap();
            let _ = nbd_live.go(&blk_vol).await.unwrap();
            assert_eq!(nbd_live.read(0, 16).await.unwrap(), b"NBD-SEED-BLOCK0!");
            assert_eq!(nbd_live.read(512, 16).await.unwrap(), b"CONTAINER-RAW-OK");
            nbd_live.disconnect().await.unwrap();
        }

        // Also verify durability across CSI Unpublish/Unstage -> Re-stage -> `os-nbd` `NbdClient`!
        csi.node_unpublish_volume(&NodeUnpublishVolumeRequest {
            volume_id: blk_vol.clone(),
            target_path: blk_target.to_string_lossy().into_owned(),
        })
        .await
        .unwrap();
        csi.node_unstage_volume(&NodeUnstageVolumeRequest {
            volume_id: blk_vol.clone(),
            staging_target_path: blk_stage.to_string_lossy().into_owned(),
        })
        .await
        .unwrap();
        csi.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: blk_vol.clone(),
            publish_context: pub_blk.publish_context,
            staging_target_path: blk_stage.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();
        let nbd_sock2 = node.nbd_socket_for_volume(&blk_vol).unwrap();
        let mut nbd2 = NbdClient::connect_unix(&nbd_sock2).await.unwrap();
        let _ = nbd2.go(&blk_vol).await.unwrap();
        assert_eq!(nbd2.read(0, 16).await.unwrap(), b"NBD-SEED-BLOCK0!");
        assert_eq!(nbd2.read(512, 16).await.unwrap(), b"CONTAINER-RAW-OK");
        nbd2.disconnect().await.unwrap();

        // ------------------------------------------------------------------
        // 5. Explicit `\x7fELF` rejection with `ENOEXEC`
        // ------------------------------------------------------------------
        let elf_bundle = bundles_root.join("elf-reject");
        write_bundle_config(
            &elf_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/bin/linux-elf"], "cwd": "/" }
            }),
        );
        std::fs::create_dir_all(elf_bundle.join("rootfs/bin")).unwrap();
        let elf_path = elf_bundle.join("rootfs/bin/linux-elf");
        std::fs::write(&elf_path, b"\x7fELF\x02\x01\x01\x00dummy-linux-binary").unwrap();
        std::fs::set_permissions(&elf_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let elf_err = client
            .call(
                TASK_V2_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "elf-reject".into(),
                    bundle: elf_bundle.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .expect_err("Linux ELF binary must be rejected with ENOEXEC");
        assert_eq!(elf_err.code, RpcCode::InvalidArgument as i32);
        assert!(
            elf_err.message.contains("ENOEXEC"),
            "unexpected ELF error: {elf_err}"
        );

        // ------------------------------------------------------------------
        // 5b. Setuid rootfs file rejection (`PermissionDenied`)
        // ------------------------------------------------------------------
        let suid_bundle = bundles_root.join("suid-reject");
        write_bundle_config(
            &suid_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/hello.wasm"], "cwd": "/" }
            }),
        );
        let suid_path = suid_bundle.join("rootfs/hello.wasm");
        std::fs::write(&suid_path, build_exec_hello_wasm()).unwrap();
        std::fs::set_permissions(&suid_path, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let suid_err = client
            .call(
                TASK_V2_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "suid-reject".into(),
                    bundle: suid_bundle.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .expect_err("setuid file in OCI rootfs must be rejected");
        assert_eq!(suid_err.code, RpcCode::PermissionDenied as i32);

        // ------------------------------------------------------------------
        // 5b2. P0-3: Symlinked host stdio path MUST be rejected (`PermissionDenied`)
        //      and symlink target file MUST remain untouched!
        // ------------------------------------------------------------------
        let secret_host_file = dir.join("host-secret.txt");
        std::fs::write(&secret_host_file, b"DO-NOT-OVERWRITE").unwrap();
        let symlink_stdout = dir.join("evil-stdout-link");
        std::os::unix::fs::symlink(&secret_host_file, &symlink_stdout).unwrap();
        let sym_bundle = bundles_root.join("sym-stdio");
        write_bundle_config(
            &sym_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/hello.wasm"], "cwd": "/" }
            }),
        );
        let sym_wasm = sym_bundle.join("rootfs/hello.wasm");
        std::fs::write(&sym_wasm, build_exec_hello_wasm()).unwrap();
        std::fs::set_permissions(&sym_wasm, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sym_err = client
            .call(
                TASK_V2_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "sym-stdio".into(),
                    bundle: sym_bundle.to_string_lossy().into_owned(),
                    stdout: symlink_stdout.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .expect_err("symlinked stdout path must be rejected");
        assert_eq!(sym_err.code, RpcCode::PermissionDenied as i32);
        assert_eq!(
            std::fs::read(&secret_host_file).unwrap(),
            b"DO-NOT-OVERWRITE",
            "symlink target must never be truncated or modified"
        );

        // ------------------------------------------------------------------
        // 5c. `Exec` RPC on running container (WASI exec succeeds; ELF exec fails ENOEXEC)
        // ------------------------------------------------------------------
        let spin_bundle = bundles_root.join("spin-ctr");
        write_bundle_config(
            &spin_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/spin.wasm"], "cwd": "/" }
            }),
        );
        let spin_path = spin_bundle.join("rootfs/spin.wasm");
        std::fs::write(&spin_path, build_spin_wasm()).unwrap();
        std::fs::set_permissions(&spin_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exec_wasm_path = spin_bundle.join("rootfs/exec-hello.wasm");
        std::fs::write(&exec_wasm_path, build_exec_hello_wasm()).unwrap();
        std::fs::set_permissions(&exec_wasm_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let exec_elf_path = spin_bundle.join("rootfs/bad-elf");
        std::fs::write(&exec_elf_path, b"\x7fELF\x02\x01\x01\x00").unwrap();
        std::fs::set_permissions(&exec_elf_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "spin-ctr".into(),
                    bundle: spin_bundle.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Start",
                StartRequest {
                    id: "spin-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();

        let exec_out_file = dir.join("exec.stdout.log");
        let exec_spec_json = serde_json::to_vec(&serde_json::json!({
            "args": ["/exec-hello.wasm"],
            "env": ["PATH=/usr/bin:/bin"],
            "cwd": "/"
        }))
        .unwrap();
        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Exec",
                ExecProcessRequest {
                    id: "spin-ctr".into(),
                    exec_id: "exec-1".into(),
                    stdout: exec_out_file.to_string_lossy().into_owned(),
                    spec: Some(ProtoAny {
                        type_url: "types.containerd.io/opencontainers/runtime-spec/1/Process"
                            .into(),
                        value: exec_spec_json,
                    }),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        let ex_start = StartResponse::decode(
            &client
                .call(
                    TASK_V2_SERVICE,
                    "Start",
                    StartRequest {
                        id: "spin-ctr".into(),
                        exec_id: "exec-1".into(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(ex_start.pid > 1);
        let ex_wait = WaitResponse::decode(
            &client
                .call(
                    TASK_V2_SERVICE,
                    "Wait",
                    WaitRequest {
                        id: "spin-ctr".into(),
                        exec_id: "exec-1".into(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(ex_wait.exit_status, 0);
        assert_eq!(std::fs::read(&exec_out_file).unwrap(), b"EXEC-OK");
        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "spin-ctr".into(),
                    exec_id: "exec-1".into(),
                }
                .encode(),
            )
            .await
            .unwrap();

        let elf_exec_err = client
            .call(
                TASK_V2_SERVICE,
                "Exec",
                ExecProcessRequest {
                    id: "spin-ctr".into(),
                    exec_id: "exec-elf".into(),
                    spec: Some(ProtoAny {
                        type_url: "types.containerd.io/opencontainers/runtime-spec/1/Process"
                            .into(),
                        value: serde_json::to_vec(&serde_json::json!({
                            "args": ["/bad-elf"],
                            "cwd": "/"
                        }))
                        .unwrap(),
                    }),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .expect_err("Exec of Linux ELF must fail with ENOEXEC");
        assert!(elf_exec_err.message.contains("ENOEXEC"));

        // 5d. P1-2 regression: prepare an `Exec` and `Delete` it WITHOUT calling `Start` —
        //     must complete promptly with zero stdio-pipe teardown deadlock!
        let unstarted_out = dir.join("exec-unstarted.stdout.log");
        client
            .call(
                TASK_V2_SERVICE,
                "Exec",
                ExecProcessRequest {
                    id: "spin-ctr".into(),
                    exec_id: "exec-unstarted".into(),
                    stdout: unstarted_out.to_string_lossy().into_owned(),
                    spec: Some(ProtoAny {
                        type_url: "types.containerd.io/opencontainers/runtime-spec/1/Process"
                            .into(),
                        value: serde_json::to_vec(&serde_json::json!({
                            "args": ["/exec-hello.wasm"],
                            "cwd": "/"
                        }))
                        .unwrap(),
                    }),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        let del_unstarted = tokio::time::timeout(
            Duration::from_secs(2),
            client.call(
                TASK_V2_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "spin-ctr".into(),
                    exec_id: "exec-unstarted".into(),
                }
                .encode(),
            ),
        )
        .await
        .expect("Delete on unstarted Exec must not deadlock")
        .unwrap();
        let del_unstarted = DeleteResponse::decode(&del_unstarted).unwrap();
        assert_eq!(del_unstarted.exit_status, 0);

        // ------------------------------------------------------------------
        // 6. P0-2 + Wasmtime 51 epoch preemption `< 200 ms`:
        //    Issue blocking `Wait` AND `Kill(SIGKILL)` CONCURRENTLY over the EXACT SAME
        //    persistent TTRPC Unix connection (`MultiplexedTtrpcClient`) — proving zero
        //    per-connection head-of-line deadlock!
        // ------------------------------------------------------------------
        let mux_client = MultiplexedTtrpcClient::connect(&shim_sock).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let wait_fut = mux_client.call(
            TASK_V2_SERVICE,
            "Wait",
            WaitRequest {
                id: "spin-ctr".into(),
                exec_id: String::new(),
            }
            .encode(),
        );
        let kill_and_time_fut = async {
            // Ensure `Wait` is already in-flight on the server before sending `Kill` on the same socket.
            tokio::time::sleep(Duration::from_millis(25)).await;
            let t0 = Instant::now();
            mux_client
                .call(
                    TASK_V2_SERVICE,
                    "Kill",
                    KillRequest {
                        id: "spin-ctr".into(),
                        exec_id: String::new(),
                        signal: 9,
                        all: true,
                    }
                    .encode(),
                )
                .await
                .expect("Kill must not stall behind Wait on the same TTRPC connection");
            t0
        };
        let (wait_res, t0) = tokio::join!(wait_fut, kill_and_time_fut);
        let elapsed = t0.elapsed();
        let spin_wait = WaitResponse::decode(&wait_res.unwrap()).unwrap();
        drop(mux_client);
        assert_eq!(
            spin_wait.exit_status, 137,
            "SIGKILL exit status must be 137"
        );
        assert!(
            elapsed < Duration::from_millis(200),
            "Wasmtime epoch preemption took {:?} (>= 200 ms)",
            elapsed
        );
        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "spin-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();

        // ------------------------------------------------------------------
        // 7. Competing native `ForceTakeover` writer fences container (`ESTALE`)
        // ------------------------------------------------------------------
        let fence_bundle = bundles_root.join("fence-ctr");
        write_bundle_config(
            &fence_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/fenced.wasm"], "cwd": "/" },
                "mounts": [
                    {
                        "destination": "/data",
                        "type": "bind",
                        "source": fs_target.to_string_lossy(),
                        "options": ["rbind", "rw"]
                    }
                ],
                "annotations": {
                    "os.csi/node-state": node_state.to_string_lossy()
                }
            }),
        );
        let fenced_path = fence_bundle.join("rootfs/fenced.wasm");
        std::fs::write(&fenced_path, build_fenced_writer_wasm()).unwrap();
        std::fs::set_permissions(&fenced_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let fence_in = dir.join("fence.stdin.fifo");
        let fence_out = dir.join("fence.stdout.fifo");
        mkfifo(&fence_in);
        mkfifo(&fence_out);

        // Open stdout reader & stdin writer (O_RDWR so open never blocks before container opens)
        let out_p = fence_out.clone();
        let ready_reader = std::thread::spawn(move || {
            let mut f = std::fs::File::open(&out_p).unwrap();
            let mut buf = [0u8; 5];
            f.read_exact(&mut buf).unwrap();
            buf
        });
        let c_in = CString::new(fence_in.as_os_str().as_bytes()).unwrap();
        let stdin_writer_fd = unsafe { libc::open(c_in.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(stdin_writer_fd >= 0);

        let _ = client
            .call(
                TASK_V3_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "fence-ctr".into(),
                    bundle: fence_bundle.to_string_lossy().into_owned(),
                    stdin: fence_in.to_string_lossy().into_owned(),
                    stdout: fence_out.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        let _ = client
            .call(
                TASK_V3_SERVICE,
                "Start",
                StartRequest {
                    id: "fence-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();

        let ready = ready_reader.join().unwrap();
        assert_eq!(&ready, b"READY");

        // 7a. P0-5: Second container attempting to mount the SAME RW CSI volume while `fence-ctr`
        //     holds exclusive ownership MUST fail with `EBUSY` (`FailedPrecondition`), never steal!
        let dup_bundle = bundles_root.join("dup-writer");
        write_bundle_config(
            &dup_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/hello.wasm"], "cwd": "/" },
                "mounts": [
                    {
                        "destination": "/data",
                        "type": "bind",
                        "source": fs_target.to_string_lossy(),
                        "options": ["rbind", "rw"]
                    }
                ]
            }),
        );
        let dup_wasm = dup_bundle.join("rootfs/hello.wasm");
        std::fs::write(&dup_wasm, build_exec_hello_wasm()).unwrap();
        std::fs::set_permissions(&dup_wasm, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dup_err = client
            .call(
                TASK_V3_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "dup-writer".into(),
                    bundle: dup_bundle.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .expect_err("second RW container on same CSI volume must fail with EBUSY");
        assert_eq!(dup_err.code, RpcCode::FailedPrecondition as i32);
        assert!(
            dup_err.message.contains("EBUSY"),
            "expected EBUSY on duplicate RW CSI volume attach, got: {dup_err}"
        );

        // Competing native writer executes `ForceTakeover` on `restored_fs_vol` and commits `"WINNER"`!
        {
            let hs = Rc::new(NativeSqliteHeadStore::open(&store_dir).unwrap());
            let ps = Rc::new(NativePackStore::open(&store_dir).unwrap());
            let clock: os_cowfs::CowFsClock = Rc::new(|| Timespec {
                sec: 1_700_000_010,
                nsec: 0,
            });
            let winner = CowFs::open(
                hs,
                ps,
                VolumeId(restored_fs_vol.clone()),
                CowFsOpenMode::ReadWrite(WriterMode::ForceTakeover),
                CowFsConfig::local_native(clock),
            )
            .await
            .unwrap();
            let cred = Cred::root();
            let root = winner.root();
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let (_, wref) = winner
                .create(&cred, &root, "winner.txt", 0o644, &opts)
                .await
                .unwrap();
            winner
                .write_at(&wref, b"WINNER", WriteAt::Offset(0))
                .await
                .unwrap();
            winner.release(&wref).await.unwrap();
            winner.commit_tx_group().await.unwrap();
            winner.close_clean().await.unwrap();
        }

        // Unblock container stdin so it exits cleanly, then call `Delete` -> MUST fail with ESTALE!
        let go = b"GO\n";
        unsafe {
            let _ = libc::write(stdin_writer_fd, go.as_ptr().cast(), go.len());
            libc::close(stdin_writer_fd);
        }
        let f_wait = WaitResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Wait",
                    WaitRequest {
                        id: "fence-ctr".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(f_wait.exit_status, 0);

        let fence_del_err = client
            .call(
                TASK_V3_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "fence-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .expect_err("fenced container Delete MUST fail closed with ESTALE");
        assert_eq!(fence_del_err.code, RpcCode::FailedPrecondition as i32);
        assert!(
            fence_del_err.message.contains("ESTALE"),
            "expected ESTALE error on fenced Delete, got: {fence_del_err}"
        );

        // Verify winner's file is intact and stale container's dirty file was never committed!
        assert_eq!(
            read_cowfs_file(&store_dir, &restored_fs_vol, "winner.txt").await,
            b"WINNER"
        );
        {
            let hs = Rc::new(NativeSqliteHeadStore::open(&store_dir).unwrap());
            let ps = Rc::new(NativePackStore::open(&store_dir).unwrap());
            let clock: os_cowfs::CowFsClock = Rc::new(|| Timespec {
                sec: 1_700_000_020,
                nsec: 0,
            });
            let ro = CowFs::open(
                hs,
                ps,
                VolumeId(restored_fs_vol.clone()),
                CowFsOpenMode::ReadOnly,
                CowFsConfig::local_native(clock),
            )
            .await
            .unwrap();
            let cred = Cred::root();
            let root = ro.root();
            assert!(
                ro.lookup(&cred, &root, "fenced.txt").await.is_err(),
                "stale container's uncommitted fenced.txt must NOT exist"
            );
            let _ = ro.close_clean().await;
        }

        // ------------------------------------------------------------------
        // 8. Stop sandbox & clean `Shutdown` terminating shim binary + unlinking socket
        // ------------------------------------------------------------------
        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Kill",
                KillRequest {
                    id: "pod-e2e-1".into(),
                    exec_id: String::new(),
                    signal: 15,
                    all: true,
                }
                .encode(),
            )
            .await
            .unwrap();
        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "pod-e2e-1".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();
        let _ = client
            .call(
                TASK_V2_SERVICE,
                "Shutdown",
                ShutdownRequest {
                    id: "pod-e2e-1".into(),
                    now: true,
                }
                .encode(),
            )
            .await
            .unwrap();
        drop(client);

        for _ in 0..50 {
            if !shim_sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            !shim_sock.exists(),
            "shim TTRPC Unix socket must be unlinked on Shutdown"
        );

        csi_srv.shutdown().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}

/// Build a tiny WASI preview1 `.wasm` module verifying non-root OCI `process.user` enforcement:
/// 1. `path_open("secret-root.txt")` (`0o600` owned by uid=0) MUST fail with WASI `EACCES` (2);
///    otherwise `proc_exit(99)` (if it wrongly succeeded) or `proc_exit(rc)` (if wrong errno).
/// 2. `path_open("public.txt")` (`0o644` owned by uid=0) MUST succeed (0) and close cleanly.
/// 3. Writes `"UID-OK"` to stdout (fd 1) and exits 0.
fn build_uid_enforcement_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    let mut types = vec![5];
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]); // 0: path_open
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]); // 1: fd_write
    types.extend_from_slice(&[0x60, 1, 0x7f, 1, 0x7f]); // 2: fd_close
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]); // 3: proc_exit
    types.extend_from_slice(&[0x60, 0, 0]); // 4: _start
    push_section(&mut wasm, 1, &types);

    // 0: path_open, 1: fd_write, 2: fd_close, 3: proc_exit
    let imports = [
        ("path_open", 0u8),
        ("fd_write", 1),
        ("fd_close", 2),
        ("proc_exit", 3),
    ];
    let mut imp_sec = vec![imports.len() as u8];
    for (name, ty) in imports {
        push_str(&mut imp_sec, "wasi_snapshot_preview1");
        push_str(&mut imp_sec, name);
        imp_sec.push(0x00);
        imp_sec.push(ty);
    }
    push_section(&mut wasm, 2, &imp_sec);
    push_section(&mut wasm, 3, &[1, 4]); // fn 4 = _start
    push_section(&mut wasm, 5, &[1, 0, 1]);
    let mut exp = vec![2];
    push_str(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0]);
    push_str(&mut exp, "_start");
    exp.extend_from_slice(&[0x00, 4]);
    push_section(&mut wasm, 7, &exp);

    // Local 0 = rc, Local 1 = fd
    let mut body = vec![1, 2, 0x7f];

    // 1. Try opening "secret-root.txt" (15 bytes at 0x100) for read -> expect rc == 2 (WASI EACCES).
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x100);
    i32_const(&mut body, 15);
    i32_const(&mut body, 0);
    i64_const(&mut body, 2); // FD_READ
    i64_const(&mut body, 2);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    local_set(&mut body, 0);

    // if rc == 0 -> proc_exit(99)
    local_get(&mut body, 0);
    body.push(0x45); // i32.eqz
    body.push(0x04);
    body.push(0x40);
    i32_const(&mut body, 99);
    call_fn(&mut body, 3);
    body.push(0x0b);

    // if rc != 2 (EACCES) -> proc_exit(rc)
    local_get(&mut body, 0);
    i32_const(&mut body, 2);
    body.push(0x47); // i32.ne
    body.push(0x04);
    body.push(0x40);
    local_get(&mut body, 0);
    call_fn(&mut body, 3);
    body.push(0x0b);

    // 2. Open "public.txt" (10 bytes at 0x120) for read -> must succeed (rc == 0)
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x120);
    i32_const(&mut body, 10);
    i32_const(&mut body, 0);
    i64_const(&mut body, 2);
    i64_const(&mut body, 2);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    check_rc(&mut body, 0, 3);

    i32_const(&mut body, 0x300);
    i32_load(&mut body, 0);
    local_set(&mut body, 1);
    local_get(&mut body, 1);
    call_fn(&mut body, 2);
    check_rc(&mut body, 0, 3);

    // 3. Write "UID-OK" (6 bytes at 0x140) to stdout
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x140);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 6);
    i32_store(&mut body, 0);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 1);
    check_rc(&mut body, 0, 3);

    i32_const(&mut body, 0);
    call_fn(&mut body, 3);
    body.push(0x0b);

    let mut code_sec = vec![1];
    push_uleb(&mut code_sec, body.len() as u64);
    code_sec.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code_sec);

    let segs: &[(i32, &[u8])] = &[
        (0x100, b"secret-root.txt"),
        (0x120, b"public.txt"),
        (0x140, b"UID-OK"),
    ];
    let mut data_sec = vec![segs.len() as u8];
    for &(off, bytes) in segs {
        data_sec.push(0x00);
        i32_const(&mut data_sec, off);
        data_sec.push(0x0b);
        push_uleb(&mut data_sec, bytes.len() as u64);
        data_sec.extend_from_slice(bytes);
    }
    push_section(&mut wasm, 11, &data_sec);
    wasm
}

#[test]
fn shim_csi_lease_fencing_and_non_root_oci_user_e2e() {
    let dir = temp_test_dir("lease-uid");
    let store_dir = dir.join("store");
    let node_state = dir.join("node-state");
    let mounts_root = dir.join("mnt");
    let bundles_root = dir.join("bundles");
    std::fs::create_dir_all(&store_dir).unwrap();
    std::fs::create_dir_all(&node_state).unwrap();
    std::fs::create_dir_all(&mounts_root).unwrap();
    std::fs::create_dir_all(&bundles_root).unwrap();

    // 1. Direct `OciContainerHandle::process_uid_gid()` verification for P1-3 (non-root uid/gid).
    {
        let direct_bundle = bundles_root.join("uid-direct");
        std::fs::create_dir_all(direct_bundle.join("rootfs")).unwrap();
        let w = direct_bundle.join("rootfs/uid.wasm");
        std::fs::write(&w, build_uid_enforcement_wasm()).unwrap();
        std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o755)).unwrap();
        let sec = direct_bundle.join("rootfs/secret-root.txt");
        std::fs::write(&sec, b"ROOT-ONLY").unwrap();
        std::fs::set_permissions(&sec, std::fs::Permissions::from_mode(0o600)).unwrap();
        let pubf = direct_bundle.join("rootfs/public.txt");
        std::fs::write(&pubf, b"WORLD-OK").unwrap();
        std::fs::set_permissions(&pubf, std::fs::Permissions::from_mode(0o644)).unwrap();

        let h = os_native::oci_runtime::OciContainerHandle::create(
            os_native::oci_runtime::OciBundleRunSpec {
                container_id: "uid-direct".into(),
                bundle_dir: direct_bundle.clone(),
                rootfs_dir: direct_bundle.join("rootfs"),
                work_store_dir: dir.join("work-uid-direct"),
                argv: vec!["/uid.wasm".into()],
                env: vec![],
                cwd: "/".into(),
                uid: 1000,
                gid: 1000,
                umask: 0o022,
                memory_max_bytes: 64 * 1024 * 1024,
                pids_max: 16,
                stdin_path: None,
                stdout_path: None,
                stderr_path: None,
                terminal: false,
                is_sandbox: false,
                volumes: vec![],
                cni_attachment: None,
                overlay_switch: None,
            },
        )
        .unwrap();
        assert_eq!(h.process_uid_gid().unwrap(), (1000, 1000));
        h.start().unwrap();
        let st = h.wait();
        assert_eq!(
            st.exit_code, 0,
            "uid=1000 container must get EACCES on 0600 root file and open 0644 public file"
        );
        h.delete().unwrap();
    }

    // 2. Full shim E2E for P0-5 (live CSI ClusterState lease revocation propagates to container)
    //    and P1-3 (non-root OCI `process.user` via `containerd-shim-os-v1` TTRPC).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async {
        let cluster = Arc::new(MemoryClusterStore::new("default"));
        let grant = ClusterGrant {
            tenant: "u0".into(),
            owner: "csi-lease-e2e".into(),
            admin: true,
            scope: RemoteScope {
                cluster_read: true,
                cluster_write: true,
                cluster_watch: true,
                cluster_lease: true,
                ..RemoteScope::default()
            },
        };
        let controller = Arc::new(OsCsiController::new(
            Arc::clone(&cluster),
            CsiControllerConfig::new("u0", grant.clone(), store_dir.clone()),
        ));
        let mut node_cfg = CsiNodeConfig::new(
            "node-lease",
            "u0",
            grant,
            node_state.clone(),
            store_dir.clone(),
        );
        node_cfg.allowed_mount_root = Some(mounts_root.clone());
        node_cfg.stage_mode = StageMode::HostSubvol;
        let node = Arc::new(OsCsiNode::new(Arc::clone(&cluster), node_cfg));

        let csi_sock = dir.join("csi-lease.sock");
        let mut csi_srv = CsiGrpcServerHandle::bind_and_spawn(
            csi_sock.clone(),
            CsiServiceRouter::new(
                controller.clone(),
                Some(controller.clone()),
                Some(node.clone()),
            ),
        )
        .unwrap();
        let mut csi = CsiGrpcClient::connect_unix(&csi_sock).await.unwrap();

        let fs_cap = VolumeCapability::mount("cowfs", AccessMode::SingleNodeWriter);
        let vol_id = csi
            .create_volume(&CreateVolumeRequest {
                name: "lease-fence-vol".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 8 * 1024 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![fs_cap.clone()],
                parameters: BTreeMap::new(),
                secrets: BTreeMap::new(),
                volume_content_source: None,
            })
            .await
            .unwrap()
            .volume
            .volume_id;

        let pub_res = csi
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: vol_id.clone(),
                node_id: "node-lease".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                secrets: BTreeMap::new(),
                volume_context: BTreeMap::new(),
            })
            .await
            .unwrap();
        let stage_path = mounts_root.join("stage-lease");
        let target_path = mounts_root.join("target-lease");
        csi.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: vol_id.clone(),
            publish_context: pub_res.publish_context.clone(),
            staging_target_path: stage_path.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();
        csi.node_publish_volume(&NodePublishVolumeRequest {
            volume_id: vol_id.clone(),
            publish_context: pub_res.publish_context,
            staging_target_path: stage_path.to_string_lossy().into_owned(),
            target_path: target_path.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap),
            readonly: false,
            secrets: BTreeMap::new(),
            volume_context: BTreeMap::new(),
        })
        .await
        .unwrap();

        // Spawn real shim binary using Go-style `-flag=value` tokens too (P2-3)!
        let shim_bin = env!("CARGO_BIN_EXE_containerd-shim-os-v1");
        let lease_bundle = bundles_root.join("lease-ctr");
        write_bundle_config(
            &lease_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/fenced.wasm"], "cwd": "/" },
                "mounts": [
                    {
                        "destination": "/data",
                        "type": "bind",
                        "source": target_path.to_string_lossy(),
                        "options": ["rbind", "rw"]
                    }
                ]
            }),
        );
        let fw_path = lease_bundle.join("rootfs/fenced.wasm");
        std::fs::write(&fw_path, build_fenced_writer_wasm()).unwrap();
        std::fs::set_permissions(&fw_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        let start_out = Command::new(shim_bin)
            .arg("-namespace=k8s.io")
            .arg("-id=lease-ctr")
            .arg(format!("-bundle={}", lease_bundle.display()))
            .arg(format!("-csi-state={}", node_state.display()))
            .arg("start")
            .output()
            .expect("spawn shim");
        assert!(
            start_out.status.success(),
            "shim start failed: {}",
            String::from_utf8_lossy(&start_out.stderr)
        );
        let shim_sock = PathBuf::from(
            String::from_utf8(start_out.stdout)
                .unwrap()
                .trim()
                .strip_prefix("unix://")
                .unwrap(),
        );
        let mut client = TtrpcClient::connect(&shim_sock).await.unwrap();

        // Launch non-root OCI user container through shim and verify stdout == "UID-OK"
        let uid_bundle = bundles_root.join("uid-ctr");
        write_bundle_config(
            &uid_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": {
                    "args": ["/uid.wasm"],
                    "cwd": "/",
                    "user": { "uid": 1000, "gid": 1000 }
                }
            }),
        );
        let uid_wasm = uid_bundle.join("rootfs/uid.wasm");
        std::fs::write(&uid_wasm, build_uid_enforcement_wasm()).unwrap();
        std::fs::set_permissions(&uid_wasm, std::fs::Permissions::from_mode(0o755)).unwrap();
        let uid_sec = uid_bundle.join("rootfs/secret-root.txt");
        std::fs::write(&uid_sec, b"ROOT-ONLY").unwrap();
        std::fs::set_permissions(&uid_sec, std::fs::Permissions::from_mode(0o600)).unwrap();
        let uid_pub = uid_bundle.join("rootfs/public.txt");
        std::fs::write(&uid_pub, b"WORLD-OK").unwrap();
        std::fs::set_permissions(&uid_pub, std::fs::Permissions::from_mode(0o644)).unwrap();
        let uid_out = dir.join("uid.stdout.log");

        client
            .call(
                TASK_V3_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "uid-ctr".into(),
                    bundle: uid_bundle.to_string_lossy().into_owned(),
                    stdout: uid_out.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        client
            .call(
                TASK_V3_SERVICE,
                "Start",
                StartRequest {
                    id: "uid-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();
        let uid_wait = WaitResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Wait",
                    WaitRequest {
                        id: "uid-ctr".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(uid_wait.exit_status, 0);
        client
            .call(
                TASK_V3_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "uid-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read(&uid_out).unwrap(), b"UID-OK");

        // Launch container holding CSI volume RW, wait for READY, then revoke CSI publish lease!
        let f_in = dir.join("lease.stdin.fifo");
        let f_out = dir.join("lease.stdout.fifo");
        mkfifo(&f_in);
        mkfifo(&f_out);
        let f_out_p = f_out.clone();
        let ready_th = std::thread::spawn(move || {
            let mut f = std::fs::File::open(&f_out_p).unwrap();
            let mut buf = [0u8; 5];
            f.read_exact(&mut buf).unwrap();
            buf
        });
        let c_in = CString::new(f_in.as_os_str().as_bytes()).unwrap();
        let in_fd = unsafe { libc::open(c_in.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(in_fd >= 0);

        client
            .call(
                TASK_V3_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "lease-ctr".into(),
                    bundle: lease_bundle.to_string_lossy().into_owned(),
                    stdin: f_in.to_string_lossy().into_owned(),
                    stdout: f_out.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        client
            .call(
                TASK_V3_SERVICE,
                "Start",
                StartRequest {
                    id: "lease-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(&ready_th.join().unwrap(), b"READY");

        // Revoke the CSI publish lease in `ClusterState` (simulating failover/expiry) and run
        // the node's fence enforcement check — NO native ForceTakeover performed!
        csi.controller_unpublish_volume(&ControllerUnpublishVolumeRequest {
            volume_id: vol_id.clone(),
            node_id: "node-lease".into(),
            secrets: BTreeMap::new(),
        })
        .await
        .unwrap();
        assert!(
            node.check_and_enforce_fence(&vol_id).await.is_err(),
            "node must detect revoked ClusterState publish lease and trip FenceStateFile"
        );

        // Unblock container stdin so it exits cleanly; `Delete` MUST fail closed with ESTALE!
        unsafe {
            let _ = libc::write(in_fd, b"GO\n".as_ptr().cast(), 3);
            libc::close(in_fd);
        }
        let w = WaitResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Wait",
                    WaitRequest {
                        id: "lease-ctr".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(w.exit_status, 0);

        let del_err = client
            .call(
                TASK_V3_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "lease-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .expect_err("CSI lease revocation MUST propagate ESTALE to container Delete");
        assert_eq!(del_err.code, RpcCode::FailedPrecondition as i32);
        assert!(
            del_err.message.contains("ESTALE"),
            "expected ESTALE after CSI lease revocation, got: {del_err}"
        );

        let _ = client
            .call(
                TASK_V3_SERVICE,
                "Shutdown",
                ShutdownRequest {
                    id: "lease-ctr".into(),
                    now: true,
                }
                .encode(),
            )
            .await
            .unwrap();
        drop(client);
        csi_srv.shutdown().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}

/// Build a WASI preview1 `.wasm` module for P1-3 (CSI NBD block ForceTakeover fencing):
/// 1. Opens `dev/vd0` RW, pwrites `"STALE-BLK"` at offset 0 (unflushed)
/// 2. Prints `"READY"` to stdout, blocks on stdin until host unblocks
/// 3. Calls `fd_sync(dev_fd)` and exits with `rc` (expected `72` = `WASI_ESTALE` when fenced!).
fn build_fenced_blk_writer_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    let mut types = vec![6];
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]); // 0: path_open
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]); // 1: fd_read/fd_write
    types.extend_from_slice(&[0x60, 5, 0x7f, 0x7f, 0x7f, 0x7e, 0x7f, 1, 0x7f]); // 2: fd_pwrite
    types.extend_from_slice(&[0x60, 1, 0x7f, 1, 0x7f]); // 3: fd_sync/fd_close
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]); // 4: proc_exit
    types.extend_from_slice(&[0x60, 0, 0]); // 5: _start
    push_section(&mut wasm, 1, &types);

    // 0: path_open, 1: fd_read, 2: fd_write, 3: fd_pwrite, 4: fd_sync, 5: proc_exit
    let imports = [
        ("path_open", 0u8),
        ("fd_read", 1),
        ("fd_write", 1),
        ("fd_pwrite", 2),
        ("fd_sync", 3),
        ("proc_exit", 4),
    ];
    let mut imp_sec = vec![imports.len() as u8];
    for (name, ty) in imports {
        push_str(&mut imp_sec, "wasi_snapshot_preview1");
        push_str(&mut imp_sec, name);
        imp_sec.push(0x00);
        imp_sec.push(ty);
    }
    push_section(&mut wasm, 2, &imp_sec);
    push_section(&mut wasm, 3, &[1, 5]); // fn 6 = _start
    push_section(&mut wasm, 5, &[1, 0, 1]);
    let mut exp = vec![2];
    push_str(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0]);
    push_str(&mut exp, "_start");
    exp.extend_from_slice(&[0x00, 6]);
    push_section(&mut wasm, 7, &exp);

    let mut body = vec![1, 2, 0x7f]; // locals 0=rc, 1=dev_fd
    // Open "dev/vd0" (7 bytes at 0x100)
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x100);
    i32_const(&mut body, 7);
    i32_const(&mut body, 0);
    i64_const(&mut body, 82);
    i64_const(&mut body, 82);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    check_rc(&mut body, 0, 5);

    i32_const(&mut body, 0x300);
    i32_load(&mut body, 0);
    local_set(&mut body, 1);

    // fd_pwrite(dev_fd, "STALE-BLK" (9 bytes at 0x120), offset=0)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x120);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 9);
    i32_store(&mut body, 0);
    local_get(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i64_const(&mut body, 0);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 3);
    check_rc(&mut body, 0, 5);

    // Write "READY" (5 bytes at 0x140) to stdout
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x140);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 5);
    i32_store(&mut body, 0);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 2);
    check_rc(&mut body, 0, 5);

    // Block on stdin fd 0
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x400);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 16);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 1);
    body.push(0x1a);

    // Call fd_sync(dev_fd) and exit with its WASI errno (72 = WASI_ESTALE)!
    local_get(&mut body, 1);
    call_fn(&mut body, 4);
    call_fn(&mut body, 5);
    body.push(0x0b);

    let mut code_sec = vec![1];
    push_uleb(&mut code_sec, body.len() as u64);
    code_sec.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code_sec);

    let segs: &[(i32, &[u8])] = &[
        (0x100, b"dev/vd0"),
        (0x120, b"STALE-BLK"),
        (0x140, b"READY"),
    ];
    let mut data_sec = vec![segs.len() as u8];
    for &(off, bytes) in segs {
        data_sec.push(0x00);
        i32_const(&mut data_sec, off);
        data_sec.push(0x0b);
        push_uleb(&mut data_sec, bytes.len() as u64);
        data_sec.extend_from_slice(bytes);
    }
    push_section(&mut wasm, 11, &data_sec);
    wasm
}

/// Build a WASI preview1 `.wasm` module for P1-4 (mid-run `CowFs` fencing via `FenceStateFile`):
/// 1. Opens `data/midrun.txt` (`CREAT|TRUNC|RDWR`) BEFORE fence trips
/// 2. Prints `"READY"` to stdout and blocks on stdin
/// 3. Attempts `fd_write` on the already-open fd AFTER `FenceStateFile` trips -> exits with WASI
///    errno (`72` = `WASI_ESTALE`), or `99` if the write wrongly succeeded!
fn build_midrun_cowfs_fence_wasm() -> Vec<u8> {
    let mut wasm = b"\0asm\x01\0\0\0".to_vec();
    let mut types = vec![4];
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]); // 0: path_open
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]); // 1: fd_read/fd_write
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]); // 2: proc_exit
    types.extend_from_slice(&[0x60, 0, 0]); // 3: _start
    push_section(&mut wasm, 1, &types);

    // 0: path_open, 1: fd_read, 2: fd_write, 3: proc_exit
    let imports = [
        ("path_open", 0u8),
        ("fd_read", 1),
        ("fd_write", 1),
        ("proc_exit", 2),
    ];
    let mut imp_sec = vec![imports.len() as u8];
    for (name, ty) in imports {
        push_str(&mut imp_sec, "wasi_snapshot_preview1");
        push_str(&mut imp_sec, name);
        imp_sec.push(0x00);
        imp_sec.push(ty);
    }
    push_section(&mut wasm, 2, &imp_sec);
    push_section(&mut wasm, 3, &[1, 3]); // fn 4 = _start
    push_section(&mut wasm, 5, &[1, 0, 1]);
    let mut exp = vec![2];
    push_str(&mut exp, "memory");
    exp.extend_from_slice(&[0x02, 0]);
    push_str(&mut exp, "_start");
    exp.extend_from_slice(&[0x00, 4]);
    push_section(&mut wasm, 7, &exp);

    let mut body = vec![1, 2, 0x7f]; // locals 0=rc, 1=fd
    // Open "data/midrun.txt" (15 bytes at 0x100)
    i32_const(&mut body, 3);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x100);
    i32_const(&mut body, 15);
    i32_const(&mut body, 9); // CREAT|TRUNC
    i64_const(&mut body, 82);
    i64_const(&mut body, 82);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x300);
    call_fn(&mut body, 0);
    check_rc(&mut body, 0, 3);

    i32_const(&mut body, 0x300);
    i32_load(&mut body, 0);
    local_set(&mut body, 1);

    // Print "READY" (5 bytes at 0x140)
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x140);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 5);
    i32_store(&mut body, 0);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 2);
    check_rc(&mut body, 0, 3);

    // Block on stdin fd 0
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x400);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 16);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 1);
    body.push(0x1a);

    // Now attempt mid-run write to already-open fd -> MUST immediately fail with WASI_ESTALE (72)!
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 0x120);
    i32_store(&mut body, 0);
    i32_const(&mut body, 0x314);
    i32_const(&mut body, 10);
    i32_store(&mut body, 0);
    local_get(&mut body, 1);
    i32_const(&mut body, 0x310);
    i32_const(&mut body, 1);
    i32_const(&mut body, 0x304);
    call_fn(&mut body, 2);
    local_set(&mut body, 0);

    // If rc == 0 (wrongly succeeded), exit 99; otherwise exit rc (72 = WASI_ESTALE).
    local_get(&mut body, 0);
    body.push(0x45);
    body.push(0x04);
    body.push(0x40);
    i32_const(&mut body, 99);
    call_fn(&mut body, 3);
    body.push(0x0b);

    local_get(&mut body, 0);
    call_fn(&mut body, 3);
    body.push(0x0b);

    let mut code_sec = vec![1];
    push_uleb(&mut code_sec, body.len() as u64);
    code_sec.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code_sec);

    let segs: &[(i32, &[u8])] = &[
        (0x100, b"data/midrun.txt"),
        (0x120, b"MIDRUN-BAD"),
        (0x140, b"READY"),
    ];
    let mut data_sec = vec![segs.len() as u8];
    for &(off, bytes) in segs {
        data_sec.push(0x00);
        i32_const(&mut data_sec, off);
        data_sec.push(0x0b);
        push_uleb(&mut data_sec, bytes.len() as u64);
        data_sec.extend_from_slice(bytes);
    }
    push_section(&mut wasm, 11, &data_sec);
    wasm
}

#[test]
fn shim_nbd_force_takeover_and_midrun_cowfs_fencing_e2e() {
    let dir = temp_test_dir("p1-3-4");
    let store_dir = dir.join("store");
    let node_state = dir.join("node-state");
    let mounts_root = dir.join("mnt");
    let bundles_root = dir.join("bundles");
    std::fs::create_dir_all(&store_dir).unwrap();
    std::fs::create_dir_all(&node_state).unwrap();
    std::fs::create_dir_all(&mounts_root).unwrap();
    std::fs::create_dir_all(&bundles_root).unwrap();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, async {
        let cluster = Arc::new(MemoryClusterStore::new("default"));
        let grant = ClusterGrant {
            tenant: "u0".into(),
            owner: "csi-p134".into(),
            admin: true,
            scope: RemoteScope {
                cluster_read: true,
                cluster_write: true,
                cluster_watch: true,
                cluster_lease: true,
                ..RemoteScope::default()
            },
        };
        let controller = Arc::new(OsCsiController::new(
            Arc::clone(&cluster),
            CsiControllerConfig::new("u0", grant.clone(), store_dir.clone()),
        ));
        let mut node_cfg = CsiNodeConfig::new(
            "node-p134",
            "u0",
            grant,
            node_state.clone(),
            store_dir.clone(),
        );
        node_cfg.allowed_mount_root = Some(mounts_root.clone());
        node_cfg.stage_mode = StageMode::HostSubvol;
        let node = Arc::new(OsCsiNode::new(Arc::clone(&cluster), node_cfg));

        let csi_sock = dir.join("csi-p134.sock");
        let mut csi_srv = CsiGrpcServerHandle::bind_and_spawn(
            csi_sock.clone(),
            CsiServiceRouter::new(
                controller.clone(),
                Some(controller.clone()),
                Some(node.clone()),
            ),
        )
        .unwrap();
        let mut csi = CsiGrpcClient::connect_unix(&csi_sock).await.unwrap();

        // Provision & publish BOTH a CSI raw block volume (for P1-3) and a CSI cowfs volume (for P1-4).
        let blk_cap = VolumeCapability::block(AccessMode::SingleNodeWriter);
        let blk_vol = csi
            .create_volume(&CreateVolumeRequest {
                name: "p13-nbd-vol".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 128 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![blk_cap.clone()],
                ..Default::default()
            })
            .await
            .unwrap()
            .volume
            .volume_id;
        let pub_blk = csi
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: blk_vol.clone(),
                node_id: "node-p134".into(),
                volume_capability: Some(blk_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        let blk_stage = mounts_root.join("stage-blk");
        let blk_target = mounts_root.join("target-blk.bind");
        csi.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: blk_vol.clone(),
            publish_context: pub_blk.publish_context.clone(),
            staging_target_path: blk_stage.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        csi.node_publish_volume(&NodePublishVolumeRequest {
            volume_id: blk_vol.clone(),
            publish_context: pub_blk.publish_context,
            staging_target_path: blk_stage.to_string_lossy().into_owned(),
            target_path: blk_target.to_string_lossy().into_owned(),
            volume_capability: Some(blk_cap),
            readonly: false,
            ..Default::default()
        })
        .await
        .unwrap();

        let fs_cap = VolumeCapability::mount("cowfs", AccessMode::SingleNodeWriter);
        let fs_vol = csi
            .create_volume(&CreateVolumeRequest {
                name: "p14-fs-vol".into(),
                capacity_range: Some(CapacityRange {
                    required_bytes: 8 * 1024 * 1024,
                    limit_bytes: 0,
                }),
                volume_capabilities: vec![fs_cap.clone()],
                ..Default::default()
            })
            .await
            .unwrap()
            .volume
            .volume_id;
        let pub_fs = csi
            .controller_publish_volume(&ControllerPublishVolumeRequest {
                volume_id: fs_vol.clone(),
                node_id: "node-p134".into(),
                volume_capability: Some(fs_cap.clone()),
                readonly: false,
                ..Default::default()
            })
            .await
            .unwrap();
        let fs_stage = mounts_root.join("stage-fs");
        let fs_target = mounts_root.join("target-fs");
        csi.node_stage_volume(&NodeStageVolumeRequest {
            volume_id: fs_vol.clone(),
            publish_context: pub_fs.publish_context.clone(),
            staging_target_path: fs_stage.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap.clone()),
            ..Default::default()
        })
        .await
        .unwrap();
        csi.node_publish_volume(&NodePublishVolumeRequest {
            volume_id: fs_vol.clone(),
            publish_context: pub_fs.publish_context,
            staging_target_path: fs_stage.to_string_lossy().into_owned(),
            target_path: fs_target.to_string_lossy().into_owned(),
            volume_capability: Some(fs_cap),
            readonly: false,
            ..Default::default()
        })
        .await
        .unwrap();

        let shim_bin = env!("CARGO_BIN_EXE_containerd-shim-os-v1");
        let blk_bundle = bundles_root.join("blk-fence");
        write_bundle_config(
            &blk_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/blk-fence.wasm"], "cwd": "/" },
                "mounts": [
                    {
                        "destination": "/dev/vd0",
                        "type": "bind",
                        "source": blk_target.to_string_lossy(),
                        "options": ["rw"]
                    }
                ]
            }),
        );
        let blk_wasm = blk_bundle.join("rootfs/blk-fence.wasm");
        std::fs::write(&blk_wasm, build_fenced_blk_writer_wasm()).unwrap();
        std::fs::set_permissions(&blk_wasm, std::fs::Permissions::from_mode(0o755)).unwrap();

        let start_out = Command::new(shim_bin)
            .arg("-namespace=k8s.io")
            .arg("-id=p134-shim")
            .arg(format!("-bundle={}", blk_bundle.display()))
            .arg(format!("-csi-state={}", node_state.display()))
            .arg("start")
            .output()
            .unwrap();
        assert!(start_out.status.success());
        let shim_sock = PathBuf::from(
            String::from_utf8(start_out.stdout)
                .unwrap()
                .trim()
                .strip_prefix("unix://")
                .unwrap(),
        );
        let mut client = TtrpcClient::connect(&shim_sock).await.unwrap();

        // ------------------------------------------------------------------
        // P1-3: Competing ForceTakeover on CSI NBD block volume -> `/dev/vd0` fsync returns
        // WASI_ESTALE (72), `node.is_volume_fenced(&blk_vol) == true`, and `Delete` fails ESTALE!
        // ------------------------------------------------------------------
        let blk_in = dir.join("blk.stdin.fifo");
        let blk_out = dir.join("blk.stdout.fifo");
        mkfifo(&blk_in);
        mkfifo(&blk_out);
        let blk_out_p = blk_out.clone();
        let blk_ready = std::thread::spawn(move || {
            let mut f = std::fs::File::open(&blk_out_p).unwrap();
            let mut buf = [0u8; 5];
            f.read_exact(&mut buf).unwrap();
            buf
        });
        let c_blk_in = CString::new(blk_in.as_os_str().as_bytes()).unwrap();
        let blk_in_fd = unsafe { libc::open(c_blk_in.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(blk_in_fd >= 0);

        client
            .call(
                TASK_V3_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "blk-fence-ctr".into(),
                    bundle: blk_bundle.to_string_lossy().into_owned(),
                    stdin: blk_in.to_string_lossy().into_owned(),
                    stdout: blk_out.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        client
            .call(
                TASK_V3_SERVICE,
                "Start",
                StartRequest {
                    id: "blk-fence-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(&blk_ready.join().unwrap(), b"READY");

        // Competing native ForceTakeover on `blk_vol`!
        {
            let hs = Rc::new(NativeSqliteHeadStore::open(&store_dir).unwrap());
            let ps = Rc::new(NativePackStore::open(&store_dir).unwrap());
            let clock: os_cowfs::CowFsClock = Rc::new(|| Timespec {
                sec: 1_700_000_050,
                nsec: 0,
            });
            let winner = os_cowfs::RawBlockVolume::open(
                hs,
                ps,
                VolumeId(blk_vol.clone()),
                os_cowfs::RawBlockOpenMode::ReadWrite(WriterMode::ForceTakeover),
                os_cowfs::RawBlockConfig::remote_fenced(clock),
            )
            .await
            .unwrap();
            winner.write_at(0, b"WINNER-BLK").await.unwrap();
            winner.flush().await.unwrap();
            winner.close_clean().await.unwrap();
        }

        // Unblock container -> `/dev/vd0` fd_sync MUST fail with WASI_ESTALE (72)!
        unsafe {
            let _ = libc::write(blk_in_fd, b"GO\n".as_ptr().cast(), 3);
            libc::close(blk_in_fd);
        }
        let blk_wait = WaitResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Wait",
                    WaitRequest {
                        id: "blk-fence-ctr".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            blk_wait.exit_status, 72,
            "fenced /dev/vd0 fd_sync must return WASI_ESTALE (72)"
        );
        assert!(
            node.is_volume_fenced(&blk_vol),
            "competing ForceTakeover on CSI NBD block must flip node.is_volume_fenced to true"
        );
        let blk_del_err = client
            .call(
                TASK_V3_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "blk-fence-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .expect_err("fenced NBD container Delete must fail closed with ESTALE");
        assert_eq!(blk_del_err.code, RpcCode::FailedPrecondition as i32);
        assert!(
            blk_del_err.message.contains("ESTALE"),
            "expected ESTALE on NBD Delete, got: {blk_del_err}"
        );

        // Verify winner's block data is intact!
        {
            let hs = Rc::new(NativeSqliteHeadStore::open(&store_dir).unwrap());
            let ps = Rc::new(NativePackStore::open(&store_dir).unwrap());
            let clock: os_cowfs::CowFsClock = Rc::new(|| Timespec {
                sec: 1_700_000_060,
                nsec: 0,
            });
            let ro = os_cowfs::RawBlockVolume::open(
                hs,
                ps,
                VolumeId(blk_vol.clone()),
                os_cowfs::RawBlockOpenMode::ReadOnly,
                os_cowfs::RawBlockConfig::local_native(clock),
            )
            .await
            .unwrap();
            let mut buf = [0u8; 10];
            ro.read_at(0, &mut buf).await.unwrap();
            assert_eq!(&buf, b"WINNER-BLK");
            ro.close_clean().await.unwrap();
        }

        // ------------------------------------------------------------------
        // P1-4: Mid-run `CowFs` write fails IMMEDIATELY with WASI_ESTALE (72) after
        // `FenceStateFile` trips (before container exits)!
        // ------------------------------------------------------------------
        let fs_bundle = bundles_root.join("midrun-fs");
        write_bundle_config(
            &fs_bundle,
            &serde_json::json!({
                "ociVersion": "1.1.0",
                "root": { "path": "rootfs" },
                "process": { "args": ["/midrun.wasm"], "cwd": "/" },
                "mounts": [
                    {
                        "destination": "/data",
                        "type": "bind",
                        "source": fs_target.to_string_lossy(),
                        "options": ["rbind", "rw"]
                    }
                ]
            }),
        );
        let mr_wasm = fs_bundle.join("rootfs/midrun.wasm");
        std::fs::write(&mr_wasm, build_midrun_cowfs_fence_wasm()).unwrap();
        std::fs::set_permissions(&mr_wasm, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mr_in = dir.join("mr.stdin.fifo");
        let mr_out = dir.join("mr.stdout.fifo");
        mkfifo(&mr_in);
        mkfifo(&mr_out);
        let mr_out_p = mr_out.clone();
        let mr_ready = std::thread::spawn(move || {
            let mut f = std::fs::File::open(&mr_out_p).unwrap();
            let mut buf = [0u8; 5];
            f.read_exact(&mut buf).unwrap();
            buf
        });
        let c_mr_in = CString::new(mr_in.as_os_str().as_bytes()).unwrap();
        let mr_in_fd = unsafe { libc::open(c_mr_in.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        assert!(mr_in_fd >= 0);

        client
            .call(
                TASK_V3_SERVICE,
                "Create",
                CreateTaskRequest {
                    id: "midrun-fs-ctr".into(),
                    bundle: fs_bundle.to_string_lossy().into_owned(),
                    stdin: mr_in.to_string_lossy().into_owned(),
                    stdout: mr_out.to_string_lossy().into_owned(),
                    ..Default::default()
                }
                .encode(),
            )
            .await
            .unwrap();
        client
            .call(
                TASK_V3_SERVICE,
                "Start",
                StartRequest {
                    id: "midrun-fs-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .unwrap();
        assert_eq!(&mr_ready.join().unwrap(), b"READY");

        // Revoke CSI publish lease -> flips FenceStateFile to `fenced: true` while container is live!
        csi.controller_unpublish_volume(&ControllerUnpublishVolumeRequest {
            volume_id: fs_vol.clone(),
            node_id: "node-p134".into(),
            secrets: BTreeMap::new(),
        })
        .await
        .unwrap();
        assert!(node.check_and_enforce_fence(&fs_vol).await.is_err());

        // Unblock container -> mid-run `fd_write` MUST fail immediately with WASI_ESTALE (72)!
        unsafe {
            let _ = libc::write(mr_in_fd, b"GO\n".as_ptr().cast(), 3);
            libc::close(mr_in_fd);
        }
        let mr_wait = WaitResponse::decode(
            &client
                .call(
                    TASK_V3_SERVICE,
                    "Wait",
                    WaitRequest {
                        id: "midrun-fs-ctr".into(),
                        exec_id: String::new(),
                    }
                    .encode(),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            mr_wait.exit_status, 72,
            "mid-run CowFs write after FenceStateFile trip must fail immediately with WASI_ESTALE (72)"
        );

        let mr_del_err = client
            .call(
                TASK_V3_SERVICE,
                "Delete",
                DeleteRequest {
                    id: "midrun-fs-ctr".into(),
                    exec_id: String::new(),
                }
                .encode(),
            )
            .await
            .expect_err("fenced mid-run CowFs container Delete must fail closed with ESTALE");
        assert_eq!(mr_del_err.code, RpcCode::FailedPrecondition as i32);
        assert!(mr_del_err.message.contains("ESTALE"));

        let _ = client
            .call(
                TASK_V3_SERVICE,
                "Shutdown",
                ShutdownRequest {
                    id: "midrun-fs-ctr".into(),
                    now: true,
                }
                .encode(),
            )
            .await
            .unwrap();
        drop(client);
        csi_srv.shutdown().await;
    });

    let _ = std::fs::remove_dir_all(&dir);
}
