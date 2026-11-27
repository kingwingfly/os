//! L6d (`#65`, Contract §2.12): verify `os-native` accepts the `"os"` WASM import
//! namespace and rejects the retired `"terminal"` import namespace.

use cowtree::{VolumeId, WriterMode};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{CowFs, CowFsConfig, CowFsOpenMode};
use os_native::kernel_actor::now_timespec;
use os_native::sandbox::{SandboxRunSpec, delete_kubelet_volume, run_sandbox_attempt_blocking};
use std::collections::BTreeMap;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use vfs::{Cred, Filesystem, OpenOptions, WriteAt};

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

/// Minimal valid WASI module importing `<ns>::umask(i32) -> i32` and calling `proc_exit(0)`.
fn wasm_umask_probe(ns: &str) -> Vec<u8> {
    let mut wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    // Type section:
    //   type 0 = (i32) -> (i32)  [umask]
    //   type 1 = (i32) -> ()     [proc_exit]
    //   type 2 = () -> ()        [_start]
    push_section(
        &mut wasm,
        1,
        &[3, 0x60, 1, 0x7f, 1, 0x7f, 0x60, 1, 0x7f, 0, 0x60, 0, 0],
    );
    // Import section:
    //   func 0: <ns>::umask (type 0)
    //   func 1: wasi_snapshot_preview1::proc_exit (type 1)
    let mut imp = vec![2];
    encode_str(ns, &mut imp);
    encode_str("umask", &mut imp);
    imp.extend_from_slice(&[0x00, 0]);
    encode_str("wasi_snapshot_preview1", &mut imp);
    encode_str("proc_exit", &mut imp);
    imp.extend_from_slice(&[0x00, 1]);
    push_section(&mut wasm, 2, &imp);
    // Function section: func 2 (_start) -> type 2
    push_section(&mut wasm, 3, &[1, 2]);
    // Memory section: 1 page min
    push_section(&mut wasm, 5, &[1, 0x00, 1]);
    // Export section: "memory" (mem 0), "_start" (func 2)
    let mut exp = vec![2];
    encode_str("memory", &mut exp);
    exp.extend_from_slice(&[0x02, 0]);
    encode_str("_start", &mut exp);
    exp.extend_from_slice(&[0x00, 2]);
    push_section(&mut wasm, 7, &exp);
    // Code section for _start:
    //   i32.const 18; call 0 (umask); drop; i32.const 0; call 1 (proc_exit); end
    let body = [0x00, 0x41, 18, 0x10, 0, 0x1a, 0x41, 0, 0x10, 1, 0x0b];
    let mut code = vec![1];
    encode_u32_leb(body.len() as u32, &mut code);
    code.extend_from_slice(&body);
    push_section(&mut wasm, 10, &code);
    wasm
}

fn seed_volume(store_dir: &Path, vol_id: &str, snap_name: &str, files: &[(&str, &[u8], u16)]) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let hs = Rc::new(NativeSqliteHeadStore::open(store_dir).unwrap());
        let ps = Rc::new(NativePackStore::open(store_dir).unwrap());
        let vid = VolumeId(vol_id.to_string());
        CowFs::format_volume(&*hs, &*ps, vid.clone(), 0, 0, 0o755, now_timespec())
            .await
            .unwrap();
        let fs = CowFs::open(
            hs.clone(),
            ps.clone(),
            vid.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(Rc::new(now_timespec)),
        )
        .await
        .unwrap();
        let cred = Cred::root();
        let root = fs.root();
        for (path, data, mode) in files {
            let trimmed = path.trim_start_matches('/');
            let parts: Vec<&str> = trimmed.split('/').collect();
            let mut dir = root.clone();
            for p in &parts[..parts.len().saturating_sub(1)] {
                dir = match fs.lookup(&cred, &dir, p).await {
                    Ok(e) => e.handle,
                    Err(_) => fs.mkdir(&cred, &dir, p, 0o755).await.unwrap().handle,
                };
            }
            let name = parts.last().unwrap();
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            let (_, open) = fs.create(&cred, &dir, name, *mode, &opts).await.unwrap();
            fs.write_at(&open, data, WriteAt::Offset(0)).await.unwrap();
            fs.release(&open).await.unwrap();
        }
        fs.create_snapshot(snap_name).await.unwrap();
        fs.close_clean().await.unwrap();
    });
}

#[test]
fn l6d_rejects_retired_terminal_wasm_import_namespace_and_accepts_os() {
    let tmp = std::env::temp_dir().join(format!("os-native-l6d-ns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let os_wasm = wasm_umask_probe("os");
    let terminal_wasm = wasm_umask_probe("terminal");

    seed_volume(
        &tmp,
        "img-l6d-ns",
        "base",
        &[
            ("/usr/bin/ok-os.wasm", &os_wasm, 0o755),
            ("/usr/bin/retired-terminal.wasm", &terminal_wasm, 0o755),
        ],
    );

    let ok_res = run_sandbox_attempt_blocking(SandboxRunSpec {
        kubelet_store_dir: tmp.clone(),
        workload_id: "wl-ns-os".into(),
        attempt_generation: 1,
        node_generation: 1,
        node_id: "node-l6d".into(),
        image_ref: "local:snapshot:img-l6d-ns@base".into(),
        entrypoint: "/usr/bin/ok-os.wasm".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_ref: None,
        extra_inputs: BTreeMap::new(),
        remote_auth: None,
        memory_max_bytes: 16 * 1024 * 1024,
        pids_max: 2,
        timeout: Duration::from_secs(10),
        cancel_flag: Arc::new(AtomicBool::new(false)),
    })
    .expect("os namespace probe should execute");
    assert_eq!(
        ok_res.exit_code,
        0,
        "os namespace probe failed: stderr={}",
        String::from_utf8_lossy(&ok_res.stderr)
    );
    if let Some(ov) = ok_res.output_volume {
        delete_kubelet_volume(&tmp, &ov);
    }

    let term_res = run_sandbox_attempt_blocking(SandboxRunSpec {
        kubelet_store_dir: tmp.clone(),
        workload_id: "wl-ns-terminal".into(),
        attempt_generation: 1,
        node_generation: 1,
        node_id: "node-l6d".into(),
        image_ref: "local:snapshot:img-l6d-ns@base".into(),
        entrypoint: "/usr/bin/retired-terminal.wasm".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_ref: None,
        extra_inputs: BTreeMap::new(),
        remote_auth: None,
        memory_max_bytes: 16 * 1024 * 1024,
        pids_max: 2,
        timeout: Duration::from_secs(10),
        cancel_flag: Arc::new(AtomicBool::new(false)),
    })
    .expect("terminal namespace rejection settles cleanly");
    assert_eq!(
        term_res.exit_code, 126,
        "retired terminal import namespace MUST be rejected (expected exit 126, got {term_res:?})"
    );
    let stderr = String::from_utf8_lossy(&term_res.stderr);
    assert!(
        stderr.contains("terminal") && stderr.contains("umask"),
        "expected unknown import diagnostic for terminal::umask, got stderr={stderr:?}"
    );
    if let Some(ov) = term_res.output_volume {
        delete_kubelet_volume(&tmp, &ov);
    }

    let _ = std::fs::remove_dir_all(&tmp);
}
