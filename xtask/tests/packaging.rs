use std::{
    fs,
    path::Path,
    process::Command,
    sync::atomic::{AtomicU32, Ordering},
};

static NEXT: AtomicU32 = AtomicU32::new(0);
struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "os-packaging-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn run(root: &Path, args: &[&str], success: bool) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn assets(root: &Path) {
    fs::create_dir_all(root.join("dist/usr/bin")).unwrap();
    let mut files = std::collections::BTreeMap::new();
    // Make one binary larger than CHUNK_SIZE_DEFAULT (256 KiB) to exercise multi-chunk digests!
    let mut large_wasm = vec![0x61u8; os_image::CHUNK_SIZE_DEFAULT as usize + 1024];
    large_wasm[..8].copy_from_slice(b"\0asm\x01\0\0\0");
    for bin in [
        "coreutils",
        "utilities",
        "dash",
        "supervise",
        "init",
        "early_init",
        "mountd",
        "exportd",
        "kubelet",
        "compositor",
        "desktop-shell",
        "greeter",
        "gui-sample-doc",
        "gui-sample-pixel",
        "osh",
        "terminal",
        "files",
        "mounts",
    ] {
        let bytes: &[u8] = if bin == "utilities" {
            &large_wasm
        } else if bin == "early_init" {
            b"\0asm\x01\0\0\0early-init"
        } else {
            b"\0asm\x01\0\0\0"
        };
        fs::write(root.join(format!("dist/usr/bin/{bin}.wasm")), bytes).unwrap();
        files.insert(format!("usr/bin/{bin}.wasm"), os_image::digest(bytes));
    }
    let bytes = br#"{"html":"","css":"","js":""}"#;
    for doc in [
        "usr/share/gui/samples/doc-view.json",
        "usr/share/gui/terminal/terminal.json",
        "usr/share/gui/files/files.json",
        "usr/share/gui/mounts/mounts.json",
    ] {
        let full = root.join("dist").join(doc);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, bytes).unwrap();
        files.insert(doc.into(), os_image::digest(bytes));
    }
    let html = b"<html>OS</html>";
    let kernel_js = b"// client-kernel";
    let kernel_wasm = b"\0asm\x01\0\0\0";
    fs::write(root.join("dist/index.html"), html).unwrap();
    fs::write(root.join("dist/client-kernel.js"), kernel_js).unwrap();
    fs::write(root.join("dist/client_kernel_bg.wasm"), kernel_wasm).unwrap();
    files.insert("index.html".into(), os_image::digest(html));
    files.insert("client-kernel.js".into(), os_image::digest(kernel_js));
    files.insert(
        "client_kernel_bg.wasm".into(),
        os_image::digest(kernel_wasm),
    );
    fs::write(
        root.join("dist/build-provenance.json"),
        serde_json::to_vec(&serde_json::json!({
            "format": "os.build",
            "version": 1,
            "inputs": { "fixture": "synthetic test bytes" },
            "files": files
        }))
        .unwrap(),
    )
    .unwrap();
}

#[test]
fn assembly_refuses_missing_or_stale_build_provenance() {
    let temp = Directory::new();
    let root = &temp.0;
    assets(root);
    fs::write(root.join("dist/index.html"), "changed after build").unwrap();
    run(
        root,
        &["boot", "--assets", "dist", "--out", "bundle"],
        false,
    );
    assert!(!root.join("bundle/release.json").exists());
    fs::remove_file(root.join("dist/build-provenance.json")).unwrap();
    run(
        root,
        &["boot", "--assets", "dist", "--out", "bundle"],
        false,
    );
}

#[test]
fn assembly_is_deterministic_v2_and_signed_bytes_and_chunks_are_checked() {
    let temp = Directory::new();
    let root = &temp.0;
    assets(root);
    let one = run(root, &["boot", "--assets", "dist", "--out", "one"], true);
    let two = run(root, &["boot", "--assets", "dist", "--out", "two"], true);
    assert_eq!(one, two);
    let release_bytes = fs::read(root.join("one/release.json")).unwrap();
    assert_eq!(
        release_bytes,
        fs::read(root.join("two/release.json")).unwrap()
    );

    // Verify Release v2 structure: version 2, loader, boot, initramfs, root_template, base, chunks.
    let release = os_image::ReleaseV2::parse(&release_bytes).unwrap();
    assert_eq!(release.version, 2);
    assert_eq!(release.protocol.min, 2);
    assert_eq!(release.protocol.max, 2);
    assert_eq!(release.schema.min, 10);
    assert_eq!(release.schema.max, 10);
    let base = fs::read(root.join(format!("one/images/{}.json", release.base))).unwrap();
    let base = os_image::Image::parse(&base).unwrap();
    for bin in [
        "compositor",
        "desktop-shell",
        "greeter",
        "gui-sample-doc",
        "gui-sample-pixel",
        "osh",
        "terminal",
        "files",
        "mounts",
    ] {
        let path = format!("/usr/bin/{bin}");
        assert!(
            base.entries
                .iter()
                .any(|e| e.path == path && e.mode & 0o111 != 0)
        );
    }
    for bundle in [
        "/usr/share/gui/samples/doc-view.json",
        "/usr/share/gui/terminal/terminal.json",
        "/usr/share/gui/files/files.json",
        "/usr/share/gui/mounts/mounts.json",
    ] {
        let doc = base.entries.iter().find(|e| e.path == bundle).unwrap();
        assert_eq!((doc.uid, doc.gid, doc.mode), (0, 0, 0o444));
    }

    let initramfs_bytes =
        fs::read(root.join(format!("one/images/{}.json", release.initramfs))).unwrap();
    let initramfs = os_image::Image::parse(&initramfs_bytes).unwrap();
    assert_eq!(initramfs.kind, os_image::Kind::Initramfs);
    let initramfs_comp = os_image::Composition::standalone(&initramfs).unwrap();
    for bin in os_image::ReleaseV2::REQUIRED_INITRAMFS_BINS {
        assert!(initramfs_comp.resolve(bin).is_ok(), "missing {bin}");
    }
    // Verify `/init` in initramfs came from `early_init.wasm` and NOT Stage 2 `init.wasm` (#34).
    let init_entry = initramfs
        .entries
        .iter()
        .find(|e| e.path == "/init")
        .unwrap();
    match &init_entry.node {
        os_image::Node::File { sha256, .. } => {
            assert_eq!(sha256, &os_image::digest(b"\0asm\x01\0\0\0early-init"));
        }
        other => panic!("unexpected /init node: {other:?}"),
    }
    // Verify multi-chunk digest list on `/bin/utilities` (> 256 KiB -> 2 chunks).
    let util_entry = initramfs
        .entries
        .iter()
        .find(|e| e.path == "/bin/utilities")
        .unwrap();
    match &util_entry.node {
        os_image::Node::File {
            chunk_size, chunks, ..
        } => {
            assert_eq!(*chunk_size, os_image::CHUNK_SIZE_DEFAULT);
            assert_eq!(chunks.len(), 2);
        }
        other => panic!("unexpected node: {other:?}"),
    }

    let root_tpl_bytes =
        fs::read(root.join(format!("one/images/{}.json", release.root_template))).unwrap();
    let root_tpl = os_image::Image::parse(&root_tpl_bytes).unwrap();
    assert_eq!(root_tpl.kind, os_image::Kind::RootTemplate);
    assert!(root_tpl.entries.iter().any(|e| e.path == "/etc/passwd"));
    assert!(root_tpl.entries.iter().any(|e| e.path == "/etc/sudoers"));

    // Test-only seed; real signing always requires an explicitly supplied external file.
    fs::write(root.join("test-seed"), [17; 32]).unwrap();
    run(
        root,
        &["sign", "--bundle", "one", "--key-file", "test-seed"],
        true,
    );
    // Offline verification with public trust succeeds twice cleanly.
    run(
        root,
        &["verify", "--bundle", "one", "--trust", "one/publisher.json"],
        true,
    );
    let id = one.trim();
    // Tampering a boot asset fails offline verification.
    fs::write(
        root.join(format!("one/releases/{id}/assets/index.html")),
        b"tampered",
    )
    .unwrap();
    run(
        root,
        &["verify", "--bundle", "one", "--trust", "one/publisher.json"],
        false,
    );
    // Tampering a single byte in the second chunk of a multi-chunk blob fails verification.
    if let os_image::Node::File { sha256, .. } = &util_entry.node {
        let blob_path = root.join(format!("two/blobs/{sha256}"));
        let mut blob_bytes = fs::read(&blob_path).unwrap();
        let last = blob_bytes.len() - 1;
        blob_bytes[last] ^= 0x01;
        fs::write(&blob_path, &blob_bytes).unwrap();
        run(
            root,
            &["verify", "--bundle", "two", "--unsigned-development"],
            false,
        );
        // Restore and confirm unsigned verification passes again.
        blob_bytes[last] ^= 0x01;
        fs::write(&blob_path, &blob_bytes).unwrap();
    }
    run(root, &["verify", "--bundle", "two"], false);
    run(
        root,
        &["verify", "--bundle", "two", "--unsigned-development"],
        true,
    );
}

#[test]
fn extension_composition_preserves_configuration_and_rejects_collisions() {
    let temp = Directory::new();
    let root = &temp.0;
    assets(root);
    fs::create_dir_all(root.join("config/etc/example")).unwrap();
    fs::write(
        root.join("config/etc/example/options.json"),
        b"{\"enabled\":true}",
    )
    .unwrap();
    run(
        root,
        &[
            "image",
            "--root",
            "config",
            "--kind",
            "confext",
            "--out",
            "config-package",
        ],
        true,
    );
    run(
        root,
        &[
            "boot",
            "--assets",
            "dist",
            "--out",
            "bundle",
            "--confext",
            "config-package",
        ],
        true,
    );
    run(
        root,
        &["verify", "--bundle", "bundle", "--unsigned-development"],
        true,
    );
    fs::write(root.join("config/etc/passwd"), b"root::0:0::/:/bin/sh").unwrap();
    run(
        root,
        &[
            "image",
            "--root",
            "config",
            "--kind",
            "confext",
            "--out",
            "bad-config",
        ],
        false,
    );
    fs::create_dir_all(root.join("extra/usr/bin")).unwrap();
    fs::write(root.join("extra/usr/bin/init"), b"conflict").unwrap();
    run(
        root,
        &[
            "image",
            "--root",
            "extra",
            "--kind",
            "sysext",
            "--out",
            "extra-package",
        ],
        true,
    );
    run(
        root,
        &[
            "boot",
            "--assets",
            "dist",
            "--out",
            "bad-bundle",
            "--sysext",
            "extra-package",
        ],
        false,
    );
}

#[test]
fn failed_update_does_not_replace_current_release() {
    let temp = Directory::new();
    let root = &temp.0;
    assets(root);
    let id = run(root, &["boot", "--assets", "dist", "--out", "bundle"], true);
    let before = fs::read(root.join("bundle/release.json")).unwrap();
    fs::remove_file(root.join("dist/usr/bin/init.wasm")).unwrap();
    run(
        root,
        &["boot", "--assets", "dist", "--out", "bundle"],
        false,
    );
    assert_eq!(before, fs::read(root.join("bundle/release.json")).unwrap());
    assert!(
        root.join(format!("bundle/releases/{}/assets/index.html", id.trim()))
            .exists()
    );
    run(
        root,
        &["verify", "--bundle", "bundle", "--unsigned-development"],
        true,
    );
}

#[test]
fn verifier_rejects_v1_manifests_and_incomplete_initramfs() {
    let temp = Directory::new();
    let root = &temp.0;
    assets(root);
    run(root, &["boot", "--assets", "dist", "--out", "bundle"], true);

    // Replace release.json with a v1 manifest -> rejected.
    let mut v1: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("bundle/release.json")).unwrap()).unwrap();
    v1["version"] = serde_json::json!(1);
    fs::write(
        root.join("bundle/release.json"),
        serde_json::to_vec(&v1).unwrap(),
    )
    .unwrap();
    run(
        root,
        &["verify", "--bundle", "bundle", "--unsigned-development"],
        false,
    );

    // Build an incomplete initramfs missing /bin/cowfsck -> rejected by xtask image.
    fs::create_dir_all(root.join("bad-initramfs/bin")).unwrap();
    fs::write(root.join("bad-initramfs/init"), b"\0asm\x01\0\0\0").unwrap();
    fs::write(root.join("bad-initramfs/bin/sh"), b"\0asm\x01\0\0\0").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            root.join("bad-initramfs/init"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(
            root.join("bad-initramfs/bin/sh"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    run(
        root,
        &[
            "image",
            "--root",
            "bad-initramfs",
            "--kind",
            "initramfs",
            "--out",
            "bad-initramfs-out",
        ],
        false,
    );
}

#[cfg(unix)]
#[test]
fn host_modes_are_normalized_deterministically_across_umask_and_sgid() {
    use std::os::unix::fs::PermissionsExt;

    let temp = Directory::new();
    let root = &temp.0;

    // Tree 1: standard 0o755 dirs, 0o644 regular file, 0o755 executable.
    fs::create_dir_all(root.join("t1/opt/tool/bin")).unwrap();
    fs::write(root.join("t1/opt/tool/data.txt"), b"hello").unwrap();
    fs::write(root.join("t1/opt/tool/bin/run"), b"\0asm\x01\0\0\0").unwrap();
    fs::set_permissions(root.join("t1/opt"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(root.join("t1/opt/tool"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        root.join("t1/opt/tool/bin"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        root.join("t1/opt/tool/data.txt"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    fs::set_permissions(
        root.join("t1/opt/tool/bin/run"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // Tree 2: identical bytes, but host umask 0002 / SGID dir (0o2775) / group-writable (0o664) / setuid exec (0o4755).
    fs::create_dir_all(root.join("t2/opt/tool/bin")).unwrap();
    fs::write(root.join("t2/opt/tool/data.txt"), b"hello").unwrap();
    fs::write(root.join("t2/opt/tool/bin/run"), b"\0asm\x01\0\0\0").unwrap();
    fs::set_permissions(root.join("t2/opt"), fs::Permissions::from_mode(0o2755)).unwrap();
    fs::set_permissions(root.join("t2/opt/tool"), fs::Permissions::from_mode(0o2775)).unwrap();
    fs::set_permissions(
        root.join("t2/opt/tool/bin"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    fs::set_permissions(
        root.join("t2/opt/tool/data.txt"),
        fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    fs::set_permissions(
        root.join("t2/opt/tool/bin/run"),
        fs::Permissions::from_mode(0o4755),
    )
    .unwrap();

    let id1 = run(
        root,
        &[
            "image", "--root", "t1", "--kind", "sysext", "--out", "out1", "--name", "det",
        ],
        true,
    );
    let id2 = run(
        root,
        &[
            "image", "--root", "t2", "--kind", "sysext", "--out", "out2", "--name", "det",
        ],
        true,
    );
    assert_eq!(
        id1, id2,
        "manifest digests must be deterministic across host umask/SGID/SUID"
    );

    let manifest =
        os_image::Image::parse(&fs::read(root.join("out2/manifest.json")).unwrap()).unwrap();
    let mode_of = |p: &str| manifest.entries.iter().find(|e| e.path == p).unwrap().mode;
    assert_eq!(mode_of("/opt"), 0o755);
    assert_eq!(mode_of("/opt/tool"), 0o755);
    assert_eq!(mode_of("/opt/tool/bin"), 0o755);
    assert_eq!(mode_of("/opt/tool/data.txt"), 0o644);
    assert_eq!(mode_of("/opt/tool/bin/run"), 0o755);
}

#[test]
fn boot_packaging_fails_closed_when_early_init_wasm_is_absent() {
    let temp = Directory::new();
    let root = &temp.0;
    fs::create_dir_all(root.join("dist/usr/bin")).unwrap();
    let mut files = std::collections::BTreeMap::new();
    for bin in ["coreutils", "utilities", "dash", "supervise", "init"] {
        let bytes = b"\0asm\x01\0\0\0stage2";
        fs::write(root.join(format!("dist/usr/bin/{bin}.wasm")), bytes).unwrap();
        files.insert(format!("usr/bin/{bin}.wasm"), os_image::digest(bytes));
    }
    for (name, bytes) in [
        ("index.html", b"<html>OS</html>".as_slice()),
        ("client-kernel.js", b"// client-kernel".as_slice()),
        ("client_kernel_bg.wasm", b"\0asm\x01\0\0\0".as_slice()),
    ] {
        fs::write(root.join("dist").join(name), bytes).unwrap();
        files.insert(name.into(), os_image::digest(bytes));
    }
    fs::write(
        root.join("dist/build-provenance.json"),
        serde_json::to_vec(&serde_json::json!({
            "format": "os.build",
            "version": 1,
            "inputs": { "fixture": "missing early_init" },
            "files": files
        }))
        .unwrap(),
    )
    .unwrap();

    run(
        root,
        &["boot", "--assets", "dist", "--out", "bundle"],
        false,
    );
    assert!(!root.join("bundle/release.json").exists());
}
