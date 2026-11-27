//! Conformance suite `KB-02`: `os-native` ephemeral `SandboxInstance` execution,
//! `/input` -> `/output` `cowfs` snapshot, host isolation (PID 1 `/proc`, zero `/etc/shadow`,
//! zero `/dev/vd0`), `memory.max` enforcement, ELF (`\x7fELF`) -> `Errno::ENOEXEC`, and
//! `< 200 ms` Wasmtime 51 epoch preemption on infinite loops.

use abi::Errno;
use cowtree::{HeadStore, VolumeId, WriterMode};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{CowFs, CowFsConfig, CowFsOpenMode};
use os_native::kernel_actor::now_timespec;
use os_native::sandbox::{SandboxRunSpec, delete_kubelet_volume, run_sandbox_attempt_blocking};
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use vfs::{Cred, Filesystem, OpenOptions, WriteAt};

// ---- Minimal deterministic WebAssembly binary builders (zero external tools required!) ----

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

fn push_section(wasm: &mut Vec<u8>, id: u8, body: &[u8]) {
    wasm.push(id);
    encode_u32_leb(body.len() as u32, wasm);
    wasm.extend_from_slice(body);
}

fn encode_str(s: &str, out: &mut Vec<u8>) {
    encode_u32_leb(s.len() as u32, out);
    out.extend_from_slice(s.as_bytes());
}

/// Minimal valid Wasm module whose `_start` spins forever in `loop { br 0 }`.
fn wasm_infinite_loop() -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // Type section: type 0 = () -> ()
    push_section(&mut wasm, 1, &[1, 0x60, 0, 0]);
    // Function section: func 0 -> type 0
    push_section(&mut wasm, 3, &[1, 0]);
    // Memory section: 1 page min (64 KiB)
    push_section(&mut wasm, 5, &[1, 0x00, 1]);
    // Export section: "memory" (mem 0) and "_start" (func 0)
    let mut exp = vec![2];
    encode_str("memory", &mut exp);
    exp.extend_from_slice(&[0x02, 0]);
    encode_str("_start", &mut exp);
    exp.extend_from_slice(&[0x00, 0]);
    push_section(&mut wasm, 7, &exp);
    // Code section: 1 body: 0 locals, loop (0x03 0x40), br 0 (0x0c 0x00), end, end
    let body = [0x00, 0x03, 0x40, 0x0c, 0x00, 0x0b, 0x0b];
    let mut code = vec![1];
    encode_u32_leb(body.len() as u32, &mut code);
    code.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code);
    wasm
}

/// Valid WASI module that tries `memory.grow(grow_pages)` and calls `proc_exit(0)` if growth was
/// DENIED (`-1`), or `proc_exit(42)` if growth unexpectedly succeeded!
fn wasm_memory_grow_probe(grow_pages: u32) -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // Type section: type 0 = (i32) -> (), type 1 = () -> ()
    push_section(&mut wasm, 1, &[2, 0x60, 1, 0x7f, 0, 0x60, 0, 0]);
    // Import section: wasi_snapshot_preview1::proc_exit (func 0, type 0)
    let mut imp = vec![1];
    encode_str("wasi_snapshot_preview1", &mut imp);
    encode_str("proc_exit", &mut imp);
    imp.extend_from_slice(&[0x00, 0]);
    push_section(&mut wasm, 2, &imp);
    // Function section: func 1 (_start) -> type 1
    push_section(&mut wasm, 3, &[1, 1]);
    // Memory section: 1 page min
    push_section(&mut wasm, 5, &[1, 0x00, 1]);
    // Export section: "memory" (mem 0), "_start" (func 1)
    let mut exp = vec![2];
    encode_str("memory", &mut exp);
    exp.extend_from_slice(&[0x02, 0]);
    encode_str("_start", &mut exp);
    exp.extend_from_slice(&[0x00, 1]);
    push_section(&mut wasm, 7, &exp);
    // Code section for _start:
    //   i32.const grow_pages
    //   memory.grow 0
    //   i32.const -1 (0x7f)
    //   i32.eq
    //   if (empty) -> proc_exit(0) else -> proc_exit(42) end
    let mut body = vec![0x00]; // 0 locals
    body.push(0x41); // i32.const
    encode_u32_leb(grow_pages, &mut body);
    body.extend_from_slice(&[
        0x40, 0x00, // memory.grow 0
        0x41, 0x7f, // i32.const -1
        0x46, // i32.eq
        0x04, 0x40, // if ()
        0x41, 0x00, // i32.const 0
        0x10, 0x00, // call proc_exit
        0x05, // else
        0x41, 42, // i32.const 42
        0x10, 0x00, // call proc_exit
        0x0b, // end if
        0x0b, // end func
    ]);
    let mut code = vec![1];
    encode_u32_leb(body.len() as u32, &mut code);
    code.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code);
    wasm
}

/// Real WASI module exercising `path_open`, `fd_read`, `fd_write`, `fd_close`, `proc_exit`:
/// 1. Reads `/input/in.txt` via preopen fd 3 -> writes `/output/out.txt` + `/output/.os-task-summary.txt`
/// 2. Asserts `/etc/shadow` fails `path_open` (non-zero errno -> host isolation!)
/// 3. Asserts `/dev/vd0` fails `path_open` (non-zero errno -> minimal `/dev`!)
/// 4. Asserts `/dev/null` succeeds `path_open`
/// 5. Asserts `/proc/1/stat` succeeds `path_open` and `/proc/2/stat` fails (PID 1 isolation!)
/// 6. Asserts opening `/input/escape.txt` with `O_CREAT` fails (read-only `/input`!)
///
/// Exits 0 if ALL checks pass, else exits with distinct error code 10..99!
fn wasm_full_sandbox_probe() -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    // Types:
    // 0: proc_exit(i32) -> ()
    // 1: path_open(i32, i32, i32, i32, i32, i64, i64, i32, i32) -> i32
    // 2: fd_read(i32, i32, i32, i32) -> i32
    // 3: fd_write(i32, i32, i32, i32) -> i32
    // 4: fd_close(i32) -> i32
    // 5: _start() -> ()
    let mut types = vec![6];
    types.extend_from_slice(&[0x60, 1, 0x7f, 0]);
    types.extend_from_slice(&[
        0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    ]);
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 1, 0x7f, 1, 0x7f]);
    types.extend_from_slice(&[0x60, 0, 0]);
    push_section(&mut wasm, 1, &types);

    // Imports (func indices 0..5):
    let mut imp = vec![5];
    for (name, ty) in [
        ("proc_exit", 0u8),
        ("path_open", 1),
        ("fd_read", 2),
        ("fd_write", 3),
        ("fd_close", 4),
    ] {
        encode_str("wasi_snapshot_preview1", &mut imp);
        encode_str(name, &mut imp);
        imp.extend_from_slice(&[0x00, ty]);
    }
    push_section(&mut wasm, 2, &imp);

    // Function section: func 5 (_start) -> type 5
    push_section(&mut wasm, 3, &[1, 5]);
    // Memory section: 1 page min
    push_section(&mut wasm, 5, &[1, 0x00, 1]);
    // Export section: memory + _start
    let mut exp = vec![2];
    encode_str("memory", &mut exp);
    exp.extend_from_slice(&[0x02, 0]);
    encode_str("_start", &mut exp);
    exp.extend_from_slice(&[0x00, 5]);
    push_section(&mut wasm, 7, &exp);

    // Data layout in linear memory starting at offset 0x100:
    // strings + scratch buffers:
    let strings: &[(&str, u32)] = &[
        ("input/in.txt", 0x100),
        ("output/out.txt", 0x120),
        ("output/.os-task-summary.txt", 0x140),
        ("etc/shadow", 0x180),
        ("dev/vd0", 0x1A0),
        ("dev/null", 0x1C0),
        ("proc/1/stat", 0x1E0),
        ("proc/2/stat", 0x200),
        ("input/escape.txt", 0x220),
        ("kb02-ok", 0x240),
    ];
    // Scratch slots:
    // 0x400: opened_fd (u32)
    // 0x410: iovec { ptr: u32, len: u32 }
    // 0x420: nread / nwritten (u32)
    // 0x500: data buffer (256 bytes)
    let mut code_body = Vec::new();
    // 2 locals: local 0 = fd (i32), local 1 = nread (i32)
    code_body.extend_from_slice(&[1, 2, 0x7f]);

    let encode_i64_sleb = |mut v: i64, b: &mut Vec<u8>| loop {
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
    };
    let emit_const = |v: u32, b: &mut Vec<u8>| {
        b.push(0x41);
        encode_i64_sleb(i64::from(v as i32), b);
    };
    let emit_path_open =
        |path_ptr: u32, path_len: u32, oflags: u32, rights: u64, b: &mut Vec<u8>| {
            emit_const(3, b); // preopen root fd 3
            emit_const(1, b); // lookupflags: SYMLINK_FOLLOW
            emit_const(path_ptr, b);
            emit_const(path_len, b);
            emit_const(oflags, b);
            b.push(0x42); // i64.const rights_base
            encode_i64_sleb(rights as i64, b);
            b.extend_from_slice(&[0x42, 0x00]); // rights_inheriting = 0
            emit_const(0, b); // fdflags
            emit_const(0x400, b); // out_fd ptr
            b.extend_from_slice(&[0x10, 0x01]); // call path_open
        };
    let emit_expect_ok = |fail_code: u32, b: &mut Vec<u8>| {
        // stack top: errno; if != 0 -> proc_exit(fail_code)
        b.extend_from_slice(&[0x04, 0x40]); // if (non-zero)
        emit_const(fail_code, b);
        b.extend_from_slice(&[0x10, 0x00, 0x0b]); // call proc_exit; end
    };
    let emit_expect_err = |fail_code: u32, b: &mut Vec<u8>| {
        // stack top: errno; if == 0 -> proc_exit(fail_code)
        b.extend_from_slice(&[0x45, 0x04, 0x40]); // i32.eqz; if
        emit_const(fail_code, b);
        b.extend_from_slice(&[0x10, 0x00, 0x0b]); // call proc_exit; end
    };

    // 1. Open /input/in.txt RO (rights=READ=2), read into 0x500, close.
    emit_path_open(0x100, "input/in.txt".len() as u32, 0, 2, &mut code_body);
    emit_expect_ok(10, &mut code_body);
    // local.0 = i32.load(0x400)
    emit_const(0x400, &mut code_body);
    code_body.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    // iovec at 0x410 = { 0x500, 256 }
    emit_const(0x410, &mut code_body);
    emit_const(0x500, &mut code_body);
    code_body.extend_from_slice(&[0x36, 0x02, 0x00]);
    emit_const(0x414, &mut code_body);
    emit_const(256, &mut code_body);
    code_body.extend_from_slice(&[0x36, 0x02, 0x00]);
    // fd_read(local.0, 0x410, 1, 0x420)
    code_body.extend_from_slice(&[0x20, 0x00]);
    emit_const(0x410, &mut code_body);
    emit_const(1, &mut code_body);
    emit_const(0x420, &mut code_body);
    code_body.extend_from_slice(&[0x10, 0x02]);
    emit_expect_ok(11, &mut code_body);
    // local.1 = nread = i32.load(0x420)
    emit_const(0x420, &mut code_body);
    code_body.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x01]);
    // fd_close(local.0)
    code_body.extend_from_slice(&[0x20, 0x00, 0x10, 0x04, 0x1a]);

    // 2. Open /output/out.txt (O_CREAT|O_TRUNC = 1|8 = 9, rights=WRITE=64), write read bytes, close.
    emit_path_open(0x120, "output/out.txt".len() as u32, 9, 64, &mut code_body);
    emit_expect_ok(12, &mut code_body);
    emit_const(0x400, &mut code_body);
    code_body.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    // iovec at 0x410 = { 0x500, local.1 }
    emit_const(0x410, &mut code_body);
    emit_const(0x500, &mut code_body);
    code_body.extend_from_slice(&[0x36, 0x02, 0x00]);
    emit_const(0x414, &mut code_body);
    code_body.extend_from_slice(&[0x20, 0x01, 0x36, 0x02, 0x00]);
    // fd_write(local.0, 0x410, 1, 0x420)
    code_body.extend_from_slice(&[0x20, 0x00]);
    emit_const(0x410, &mut code_body);
    emit_const(1, &mut code_body);
    emit_const(0x420, &mut code_body);
    code_body.extend_from_slice(&[0x10, 0x03]);
    emit_expect_ok(13, &mut code_body);
    code_body.extend_from_slice(&[0x20, 0x00, 0x10, 0x04, 0x1a]);

    // 3. Write /output/.os-task-summary.txt = "kb02-ok"
    emit_path_open(
        0x140,
        "output/.os-task-summary.txt".len() as u32,
        9,
        64,
        &mut code_body,
    );
    emit_expect_ok(14, &mut code_body);
    emit_const(0x400, &mut code_body);
    code_body.extend_from_slice(&[0x28, 0x02, 0x00, 0x21, 0x00]);
    emit_const(0x410, &mut code_body);
    emit_const(0x240, &mut code_body);
    code_body.extend_from_slice(&[0x36, 0x02, 0x00]);
    emit_const(0x414, &mut code_body);
    emit_const("kb02-ok".len() as u32, &mut code_body);
    code_body.extend_from_slice(&[0x36, 0x02, 0x00]);
    code_body.extend_from_slice(&[0x20, 0x00]);
    emit_const(0x410, &mut code_body);
    emit_const(1, &mut code_body);
    emit_const(0x420, &mut code_body);
    code_body.extend_from_slice(&[0x10, 0x03]);
    emit_expect_ok(15, &mut code_body);
    code_body.extend_from_slice(&[0x20, 0x00, 0x10, 0x04, 0x1a]);

    // 4. Host isolation probes:
    // /etc/shadow MUST fail
    emit_path_open(0x180, "etc/shadow".len() as u32, 0, 2, &mut code_body);
    emit_expect_err(20, &mut code_body);
    // /dev/vd0 MUST fail
    emit_path_open(0x1A0, "dev/vd0".len() as u32, 0, 2, &mut code_body);
    emit_expect_err(21, &mut code_body);
    // /dev/null MUST succeed
    emit_path_open(0x1C0, "dev/null".len() as u32, 0, 2, &mut code_body);
    emit_expect_ok(22, &mut code_body);
    emit_const(0x400, &mut code_body);
    code_body.extend_from_slice(&[0x28, 0x02, 0x00, 0x10, 0x04, 0x1a]);
    // /proc/1/stat MUST succeed
    emit_path_open(0x1E0, "proc/1/stat".len() as u32, 0, 2, &mut code_body);
    emit_expect_ok(23, &mut code_body);
    emit_const(0x400, &mut code_body);
    code_body.extend_from_slice(&[0x28, 0x02, 0x00, 0x10, 0x04, 0x1a]);
    // /proc/2/stat MUST fail (only PID 1 exists in sandbox!)
    emit_path_open(0x200, "proc/2/stat".len() as u32, 0, 2, &mut code_body);
    emit_expect_err(24, &mut code_body);
    // Writing /input/escape.txt MUST fail (EROFS!)
    emit_path_open(
        0x220,
        "input/escape.txt".len() as u32,
        9,
        64,
        &mut code_body,
    );
    emit_expect_err(25, &mut code_body);

    // All checks passed -> proc_exit(0)!
    emit_const(0, &mut code_body);
    code_body.extend_from_slice(&[0x10, 0x00, 0x0b]);

    let mut code = vec![1];
    encode_u32_leb(code_body.len() as u32, &mut code);
    code.extend_from_slice(&code_body);
    push_section(&mut wasm, 10, &code);

    // Data section
    let mut data = Vec::new();
    encode_u32_leb(strings.len() as u32, &mut data);
    for (s, off) in strings {
        data.push(0x00); // mem 0 active
        data.push(0x41); // i32.const off
        encode_u32_leb(*off, &mut data);
        data.push(0x0b); // end expr
        encode_u32_leb(s.len() as u32, &mut data);
        data.extend_from_slice(s.as_bytes());
    }
    push_section(&mut wasm, 11, &data);
    wasm
}

fn seed_local_volume(
    store_dir: &Path,
    vol_id: &str,
    snap_name: &str,
    files: &[(&str, &[u8], u16)],
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let hs = Rc::new(NativeSqliteHeadStore::open(store_dir).unwrap());
        let ps = Rc::new(NativePackStore::open(store_dir).unwrap());
        let vid = VolumeId(vol_id.to_string());
        let now = now_timespec();
        CowFs::format_volume(&*hs, &*ps, vid.clone(), 0, 0, 0o755, now)
            .await
            .unwrap();
        let fs = CowFs::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            vid.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(Rc::new(now_timespec)),
        )
        .await
        .unwrap();
        let mut cred = Cred::root();
        cred.umask = 0;
        for (path, bytes, mode) in files {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            let mut parent = fs.root();
            for dir in &parts[..parts.len() - 1] {
                parent = match fs.lookup(&cred, &parent, dir).await {
                    Ok(e) => e.handle,
                    Err(_) => fs.mkdir(&cred, &parent, dir, 0o755).await.unwrap().handle,
                };
            }
            let name = parts[parts.len() - 1];
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let (_ent, open) = fs.create(&cred, &parent, name, *mode, &opts).await.unwrap();
            if !bytes.is_empty() {
                fs.write_at(&open, bytes, WriteAt::Offset(0)).await.unwrap();
            }
            fs.release(&open).await.unwrap();
        }
        fs.commit_tx_group().await.unwrap();
        let head = fs.current_head();
        hs.create_snapshot(&vid, snap_name, &head, now_timespec())
            .await
            .unwrap();
        fs.close_clean().await.unwrap();
    });
}

fn read_local_volume_file(store_dir: &Path, vol_id: &str, name: &str) -> Vec<u8> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let hs = Rc::new(NativeSqliteHeadStore::open(store_dir).unwrap());
        let ps = Rc::new(NativePackStore::open(store_dir).unwrap());
        let fs = CowFs::open(
            hs,
            ps,
            VolumeId(vol_id.to_string()),
            CowFsOpenMode::ReadOnly,
            CowFsConfig::local_native(Rc::new(now_timespec)),
        )
        .await
        .unwrap();
        let cred = Cred::root();
        let root = fs.root();
        let entry = fs.lookup(&cred, &root, name).await.unwrap();
        let mut opts = OpenOptions::new();
        opts.read(true);
        let open = fs.open(&cred, &entry.handle, &opts).await.unwrap();
        let mut buf = vec![0u8; entry.metadata.size as usize];
        let n = fs.read_at(&open, &mut buf, 0).await.unwrap();
        buf.truncate(n);
        fs.release(&open).await.unwrap();
        fs.close_clean().await.unwrap();
        buf
    })
}

fn list_local_volumes(store_dir: &Path) -> Vec<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let hs = NativeSqliteHeadStore::open(store_dir).unwrap();
        hs.list_volumes()
            .await
            .unwrap()
            .into_iter()
            .map(|h| h.volume.0)
            .collect()
    })
}

#[test]
fn kb02_sandbox_io_isolation_limits_elf_rejection_and_epoch_preemption() {
    let tmp = std::env::temp_dir().join(format!("os-native-kb02-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let probe_wasm = wasm_full_sandbox_probe();
    let mem_wasm = wasm_memory_grow_probe(512); // requests 32 MiB growth (> 4 MiB limit!)
    let loop_wasm = wasm_infinite_loop();
    let fake_elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    seed_local_volume(
        &tmp,
        "img-test",
        "base",
        &[
            ("/usr/bin/probe.wasm", &probe_wasm, 0o755),
            ("/usr/bin/mem.wasm", &mem_wasm, 0o755),
            ("/usr/bin/loop.wasm", &loop_wasm, 0o755),
            ("/usr/bin/elf-pod", fake_elf, 0o755),
        ],
    );
    seed_local_volume(
        &tmp,
        "in-test",
        "v1",
        &[("/in.txt", b"hello-from-kb02-input", 0o444)],
    );

    // 1. Full `/input` -> `/output` cowfs snapshot + host isolation + PID 1 + RO `/input` probe!
    let res = run_sandbox_attempt_blocking(SandboxRunSpec {
        kubelet_store_dir: tmp.clone(),
        workload_id: "wl-probe".into(),
        attempt_generation: 1,
        node_generation: 1,
        node_id: "node-a".into(),
        image_ref: "local:snapshot:img-test@base".into(),
        entrypoint: "/usr/bin/probe.wasm".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_ref: Some("local:snapshot:in-test@v1".into()),
        extra_inputs: BTreeMap::new(),
        remote_auth: None,
        memory_max_bytes: 16 * 1024 * 1024,
        pids_max: 4,
        timeout: Duration::from_secs(10),
        cancel_flag: Arc::new(AtomicBool::new(false)),
        cni_attachment: None,
        overlay_switch: None,
    })
    .expect("probe sandbox runs cleanly");
    assert_eq!(res.exit_code, 0, "probe failed: {res:?}");
    assert_eq!(
        res.summary.as_deref(),
        Some("kb02-ok"),
        "unexpected summary; res={res:?}, stderr={}",
        String::from_utf8_lossy(&res.stderr)
    );
    let out_vol = res
        .output_volume
        .expect("output volume preserved on exit 0");
    assert_eq!(
        read_local_volume_file(&tmp, &out_vol, "out.txt"),
        b"hello-from-kb02-input"
    );
    delete_kubelet_volume(&tmp, &out_vol);
    // Ephemeral `sb-root-*` MUST already be deleted!
    let remaining = list_local_volumes(&tmp);
    assert!(
        !remaining.iter().any(|v| v.starts_with("sb-root-")),
        "ephemeral root volume leaked: {remaining:?}"
    );

    // 2. Cgroup `memory.max` enforcement: 32 MiB `memory.grow` denied under 4 MiB cap!
    let mem_res = run_sandbox_attempt_blocking(SandboxRunSpec {
        kubelet_store_dir: tmp.clone(),
        workload_id: "wl-mem".into(),
        attempt_generation: 1,
        node_generation: 1,
        node_id: "node-a".into(),
        image_ref: "local:snapshot:img-test@base".into(),
        entrypoint: "/usr/bin/mem.wasm".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_ref: None,
        extra_inputs: BTreeMap::new(),
        remote_auth: None,
        memory_max_bytes: 4 * 1024 * 1024,
        pids_max: 2,
        timeout: Duration::from_secs(10),
        cancel_flag: Arc::new(AtomicBool::new(false)),
        cni_attachment: None,
        overlay_switch: None,
    })
    .expect("memory probe runs");
    assert_eq!(
        mem_res.exit_code, 0,
        "memory.grow(512) MUST be denied under 4 MiB memory.max (exit=42 means growth succeeded!)"
    );
    if let Some(ov) = mem_res.output_volume {
        delete_kubelet_volume(&tmp, &ov);
    }

    // 3. ELF (`\x7fELF`) binary MUST be rejected with `Errno::ENOEXEC`!
    let elf_err = run_sandbox_attempt_blocking(SandboxRunSpec {
        kubelet_store_dir: tmp.clone(),
        workload_id: "wl-elf".into(),
        attempt_generation: 1,
        node_generation: 1,
        node_id: "node-a".into(),
        image_ref: "local:snapshot:img-test@base".into(),
        entrypoint: "/usr/bin/elf-pod".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_ref: None,
        extra_inputs: BTreeMap::new(),
        remote_auth: None,
        memory_max_bytes: 16 * 1024 * 1024,
        pids_max: 2,
        timeout: Duration::from_secs(10),
        cancel_flag: Arc::new(AtomicBool::new(false)),
        cni_attachment: None,
        overlay_switch: None,
    })
    .unwrap_err();
    assert_eq!(elf_err, Errno::ENOEXEC);

    // 4. Infinite-loop Wasm module preempted via Wasmtime 51 epoch interruption in < 200 ms!
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_trigger = Arc::clone(&cancel);
    let cancel_at = Arc::new(std::sync::Mutex::new(None::<Instant>));
    let cancel_at_clone = Arc::clone(&cancel_at);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(60));
        *cancel_at_clone.lock().unwrap() = Some(Instant::now());
        cancel_trigger.store(true, Ordering::SeqCst);
    });
    let loop_res = run_sandbox_attempt_blocking(SandboxRunSpec {
        kubelet_store_dir: tmp.clone(),
        workload_id: "wl-loop".into(),
        attempt_generation: 1,
        node_generation: 1,
        node_id: "node-a".into(),
        image_ref: "local:snapshot:img-test@base".into(),
        entrypoint: "/usr/bin/loop.wasm".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_ref: None,
        extra_inputs: BTreeMap::new(),
        remote_auth: None,
        memory_max_bytes: 16 * 1024 * 1024,
        pids_max: 2,
        timeout: Duration::from_secs(30),
        cancel_flag: cancel,
        cni_attachment: None,
        overlay_switch: None,
    })
    .expect("loop sandbox exits on cancel");
    let preempt_elapsed = cancel_at.lock().unwrap().expect("cancel fired").elapsed();
    assert!(
        loop_res.canceled,
        "expected canceled=true, got {loop_res:?}"
    );
    assert!(
        loop_res.output_volume.is_none(),
        "no output volume on cancel"
    );
    assert!(
        preempt_elapsed < Duration::from_millis(200),
        "epoch preemption took {preempt_elapsed:?}, expected < 200ms"
    );

    // Verify zero ephemeral sandbox volumes leaked!
    let final_vols = list_local_volumes(&tmp);
    assert!(
        !final_vols.iter().any(|v| v.starts_with("sb-")),
        "ephemeral sandbox volumes leaked: {final_vols:?}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
