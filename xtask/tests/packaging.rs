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
    for bin in ["coreutils", "utilities", "dash", "supervise", "init"] {
        fs::write(
            root.join(format!("dist/usr/bin/{bin}.wasm")),
            b"\0asm\x01\0\0\0",
        )
        .unwrap();
    }
    fs::write(root.join("dist/index.html"), b"<html>OS</html>").unwrap();
    let mut files = std::collections::BTreeMap::new();
    for bin in ["coreutils", "utilities", "dash", "supervise", "init"] {
        files.insert(
            format!("usr/bin/{bin}.wasm"),
            os_image::digest(b"\0asm\x01\0\0\0"),
        );
    }
    files.insert("index.html".into(), os_image::digest(b"<html>OS</html>"));
    fs::write(root.join("dist/build-provenance.json"), serde_json::to_vec(&serde_json::json!({
        "format":"os.build", "version":1, "inputs":{"fixture":"synthetic test bytes"}, "files":files
    })).unwrap()).unwrap();
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
fn assembly_is_deterministic_and_signed_bytes_are_checked() {
    let temp = Directory::new();
    let root = &temp.0;
    assets(root);
    let one = run(root, &["boot", "--assets", "dist", "--out", "one"], true);
    let two = run(root, &["boot", "--assets", "dist", "--out", "two"], true);
    assert_eq!(one, two);
    assert_eq!(
        fs::read(root.join("one/release.json")).unwrap(),
        fs::read(root.join("two/release.json")).unwrap()
    );
    // Test-only seed; real signing always requires an explicitly supplied external file.
    fs::write(root.join("test-seed"), [17; 32]).unwrap();
    run(
        root,
        &["sign", "--bundle", "one", "--key-file", "test-seed"],
        true,
    );
    run(
        root,
        &["verify", "--bundle", "one", "--trust", "one/publisher.json"],
        true,
    );
    let id = one.trim();
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
