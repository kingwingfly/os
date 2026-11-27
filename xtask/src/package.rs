use crate::Result;
use os_image::{
    ABI, CHUNK_SIZE_DEFAULT, Composition, Entry, HOST_ADAPTER, IMAGE_VERSION, Image, Kind, LEVEL,
    LoaderMeta, Node, PROTOCOL, RELEASE_VERSION, Range, ReleaseV2, SCHEMA, SIGNING_DOMAIN_IMAGE_V2,
    SIGNING_DOMAIN_RELEASE_V2, Trust, chunk_digests, digest, hex,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("missing parent")?;
    fs::create_dir_all(parent)?;
    let pid = std::process::id();
    let (tmp, mut file) = loop {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(".xtask-{pid}-{seq}"));
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => break (candidate, file),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    };
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
fn immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if read_regular(path)? != bytes {
            return Err("immutable artifact collision".into());
        }
        return Ok(());
    }
    replace(path, bytes)
}
fn read_regular(path: &Path) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err("artifact must be a regular file".into());
    }
    Ok(fs::read(path)?)
}
fn no_overlap(input: &Path, output: &Path) -> Result<()> {
    let input = fs::canonicalize(input)?;
    fs::create_dir_all(output)?;
    let output = fs::canonicalize(output)?;
    if input.starts_with(&output) || output.starts_with(input) {
        return Err("input and output trees must not overlap".into());
    }
    Ok(())
}
fn directory(path: &str) -> Entry {
    directory_mode(path, 0, 0, 0o755)
}
fn directory_mode(path: &str, uid: u32, gid: u32, mode: u16) -> Entry {
    Entry {
        path: path.into(),
        uid,
        gid,
        mode,
        node: Node::Directory,
    }
}
fn image(kind: Kind, name: &str, revision: &str, entries: Vec<Entry>) -> Image {
    Image {
        format: "os.image".into(),
        version: IMAGE_VERSION,
        kind,
        name: name.into(),
        revision: revision.into(),
        abi: ABI,
        features: vec![],
        level: LEVEL,
        provenance: BTreeMap::new(),
        entries,
    }
}
fn blob(out: &Path, bytes: &[u8]) -> Result<Node> {
    let sha256 = digest(bytes);
    let chunks = chunk_digests(bytes, CHUNK_SIZE_DEFAULT)?;
    immutable(&out.join("blobs").join(&sha256), bytes)?;
    Ok(Node::File {
        sha256,
        size: bytes.len() as u64,
        chunk_size: CHUNK_SIZE_DEFAULT,
        chunks,
    })
}
fn walk(root: &Path, at: &Path, out: &Path, entries: &mut Vec<Entry>, boot: bool) -> Result<()> {
    let mut names = fs::read_dir(at)?
        .map(|v| v.map(|e| e.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    for path in names {
        if boot
            && at == root
            && matches!(
                path.file_name().and_then(|n| n.to_str()),
                Some("boot" | "_headers" | "_redirects" | ".assetsignore")
            )
        {
            continue;
        }
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .ok_or("non-UTF8 image path")?;
        let virtual_path = format!("/{relative}");
        let meta = fs::symlink_metadata(&path)?;
        // Normalize modes deterministically across host umasks and SGID/SUID directories.
        let mode: u16 = if meta.is_dir() {
            0o755
        } else if meta.is_symlink() {
            0o777
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if (meta.permissions().mode() & 0o111) != 0 {
                    0o755
                } else {
                    0o644
                }
            }
            #[cfg(not(unix))]
            {
                0o644
            }
        };
        let node = if meta.is_dir() {
            Node::Directory
        } else if meta.is_symlink() {
            Node::Symlink {
                target: fs::read_link(&path)?
                    .to_str()
                    .ok_or("non-UTF8 symlink")?
                    .into(),
            }
        } else if meta.is_file() {
            blob(out, &read_regular(&path)?)?
        } else {
            return Err("device/socket/special image entries are unsupported".into());
        };
        entries.push(Entry {
            path: virtual_path,
            uid: 0,
            gid: 0,
            mode,
            node,
        });
        if entries.len() > os_image::ENTRIES_MAX {
            return Err("too many image entries".into());
        }
        if meta.is_dir() {
            walk(root, &path, out, entries, boot)?;
        }
    }
    Ok(())
}
fn write_image(out: &Path, image: &Image) -> Result<String> {
    image.validate()?;
    let bytes = serde_json::to_vec(image)?;
    Image::parse(&bytes)?;
    let id = digest(&bytes);
    immutable(&out.join(format!("images/{id}.json")), &bytes)?;
    Ok(id)
}
pub fn tree(root: &Path, kind: Kind, name: &str, revision: &str, out: &Path) -> Result<String> {
    no_overlap(root, out)?;
    let mut entries = vec![directory("/")];
    walk(root, root, out, &mut entries, false)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = image(kind, name, revision, entries);
    let id = write_image(out, &manifest)?;
    replace(&out.join("manifest.json"), &serde_json::to_vec(&manifest)?)?;
    Ok(id)
}
/// Resolve the Stage 1 `early_init` Wasm binary for `Initramfs`'s `/init`.
///
/// Strictly requires `assets/usr/bin/early_init.wasm` in the verified build inputs and fails
/// closed when it is absent (never reads external Cargo target directories or substitutes
/// Stage 2 `init.wasm`).
fn resolve_early_init_wasm(assets: &Path) -> Result<Vec<u8>> {
    let explicit = assets.join("usr/bin/early_init.wasm");
    read_regular(&explicit).map_err(|err| {
        format!(
            "missing required Stage 1 init binary {}: {err}",
            explicit.display()
        )
        .into()
    })
}

/// Stage 1 `Initramfs` image: `/init` (`early_init.wasm`), `/bin/mount`, `/bin/switch_root`,
/// `/bin/cowfsck`, `/bin/sh` backed by built WASI applet bundles.
fn initramfs(assets: &Path, out: &Path, name: &str) -> Result<Image> {
    let mut entries = vec![
        directory("/"),
        directory("/bin"),
        directory("/dev"),
        directory_mode("/proc", 0, 0, 0o555),
        directory("/run"),
        directory("/sysroot"),
        directory_mode("/tmp", 0, 0, 0o1777),
        directory("/usr"),
        Entry {
            path: "/init".into(),
            uid: 0,
            gid: 0,
            mode: 0o755,
            node: blob(out, &resolve_early_init_wasm(assets)?)?,
        },
        Entry {
            path: "/bin/utilities".into(),
            uid: 0,
            gid: 0,
            mode: 0o755,
            node: blob(out, &read_regular(&assets.join("usr/bin/utilities.wasm"))?)?,
        },
        Entry {
            path: "/bin/dash".into(),
            uid: 0,
            gid: 0,
            mode: 0o755,
            node: blob(out, &read_regular(&assets.join("usr/bin/dash.wasm"))?)?,
        },
    ];
    for (path, target) in [
        ("/bin/mount", "utilities"),
        ("/bin/switch_root", "utilities"),
        ("/bin/cowfsck", "utilities"),
        ("/bin/sh", "dash"),
    ] {
        entries.push(Entry {
            path: path.into(),
            uid: 0,
            gid: 0,
            mode: 0o777,
            node: Node::Symlink {
                target: target.into(),
            },
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = image(Kind::Initramfs, name, "1", entries);
    manifest.validate()?;
    Ok(manifest)
}
/// Stage 1 first-boot `RootTemplate` image: deterministic `/etc`, `/var`, `/root`, `/home`
/// defaults (including default local user `uid 1000` in `wheel` with passwordless `sudo`,
/// Contract §2.1 & §2.15). Never overwrites an existing root volume.
fn root_template(out: &Path, name: &str) -> Result<Image> {
    let mut entries = vec![
        directory("/"),
        directory("/boot"),
        directory("/dev"),
        directory("/dev/pts"),
        directory("/etc"),
        directory("/home"),
        directory_mode("/home/user", 1000, 1000, 0o750),
        directory("/mnt"),
        directory("/mnt/cloud"),
        directory("/mnt/local"),
        directory("/mnt/shared"),
        directory("/opt"),
        directory("/opt/private"),
        directory_mode("/proc", 0, 0, 0o555),
        directory_mode("/root", 0, 0, 0o700),
        directory("/run"),
        directory("/srv"),
        directory_mode("/sys", 0, 0, 0o555),
        directory_mode("/tmp", 0, 0, 0o1777),
        directory("/usr"),
        directory("/var"),
        directory("/var/cache"),
        directory("/var/lib"),
        directory("/var/log"),
        directory_mode("/var/tmp", 0, 0, 0o1777),
    ];
    let defaults: &[(&str, u16, &[u8])] = &[
        (
            "/etc/passwd",
            0o644,
            b"root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:Local User:/home/user:/bin/sh\nexportd:x:998:998:Export service:/nonexistent:/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n",
        ),
        (
            "/etc/group",
            0o644,
            b"root:x:0:\nwheel:x:10:root,user\nuser:x:1000:\nexportd:x:998:\nnogroup:x:65534:\n",
        ),
        (
            "/etc/shadow",
            0o600,
            b"root:!:0:0:99999:7:::\nuser:!:0:0:99999:7:::\nexportd:*:0:0:99999:7:::\nnobody:!:0:0:99999:7:::\n",
        ),
        (
            "/etc/sudoers",
            0o440,
            b"root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) NOPASSWD: ALL\n",
        ),
        ("/etc/hostname", 0o644, b"os\n"),
        (
            "/etc/os-release",
            0o644,
            b"NAME=\"OS\"\nID=os\nVERSION_ID=\"2\"\nPRETTY_NAME=\"OS Release v2\"\n",
        ),
    ];
    for &(path, mode, content) in defaults {
        entries.push(Entry {
            path: path.into(),
            uid: 0,
            gid: 0,
            mode,
            node: blob(out, content)?,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest = image(Kind::RootTemplate, name, "1", entries);
    manifest.validate()?;
    Ok(manifest)
}
fn installed(assets: &Path, out: &Path, name: &str) -> Result<Image> {
    let mut entries: Vec<Entry> = [
        "/",
        "/etc",
        "/opt",
        "/sys",
        "/usr",
        "/usr/bin",
        "/usr/include",
        "/usr/lib",
        "/usr/lib/os",
        "/usr/lib/os/units",
        "/usr/libexec",
        "/usr/local",
        "/usr/share",
        "/usr/share/desktop",
        "/usr/share/os",
        "/usr/share/gui",
        "/usr/share/gui/samples",
        "/usr/share/gui/terminal",
        "/usr/share/gui/files",
        "/usr/share/gui/mounts",
        "/usr/share/gui/editor",
        "/usr/share/gui/preview",
        "/usr/src",
    ]
    .into_iter()
    .map(directory)
    .collect();
    for bin in [
        "coreutils",
        "utilities",
        "dash",
        "supervise",
        "init",
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
        "editor",
        "preview",
    ] {
        entries.push(Entry {
            path: format!("/usr/bin/{bin}"),
            uid: 0,
            gid: 0,
            mode: 0o755,
            node: blob(
                out,
                &read_regular(&assets.join(format!("usr/bin/{bin}.wasm")))?,
            )?,
        });
    }
    for doc in [
        "/usr/share/gui/samples/doc-view.json",
        "/usr/share/gui/terminal/terminal.json",
        "/usr/share/gui/files/files.json",
        "/usr/share/gui/mounts/mounts.json",
        "/usr/share/gui/editor/editor.json",
        "/usr/share/gui/preview/preview.json",
        "/usr/share/os/config.json",
        "/usr/share/desktop/associations.json",
    ] {
        entries.push(Entry {
            path: doc.into(),
            uid: 0,
            gid: 0,
            mode: 0o444,
            node: blob(out, &read_regular(&assets.join(&doc[1..]))?)?,
        });
    }
    let mut links = vec![
        ("/bin".into(), "usr/bin"),
        ("/sbin".into(), "usr/bin"),
        ("/lib".into(), "usr/lib"),
        ("/lib64".into(), "usr/lib"),
        ("/usr/sbin".into(), "bin"),
        ("/usr/lib64".into(), "lib"),
        ("/usr/bin/sh".into(), "dash"),
    ];
    for (names, target) in [
        (os_core::bin::PROGRAMS, "coreutils"),
        (os_core::bin::UTILITIES, "utilities"),
    ] {
        links.extend(names.iter().map(|n| (format!("/usr/bin/{n}"), target)));
    }
    for (path, target) in links {
        entries.push(Entry {
            path,
            uid: 0,
            gid: 0,
            mode: 0o777,
            node: Node::Symlink {
                target: target.into(),
            },
        });
    }
    for spec in os_services::graph::default_system_units() {
        let raw = serde_json::to_vec_pretty(&spec)?;
        entries.push(Entry {
            path: format!("/usr/lib/os/units/{}.json", spec.name),
            uid: 0,
            gid: 0,
            mode: 0o644,
            node: blob(out, &raw)?,
        });
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(image(Kind::Base, name, "1", entries))
}
pub fn provenance() -> Result<BTreeMap<String, String>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("workspace root missing")?;
    let mut p = BTreeMap::new();
    for path in [
        "Cargo.lock",
        "crates/coreutils/Cargo.lock",
        "package-lock.json",
        "packages/dash/lock.json",
    ] {
        p.insert(path.into(), digest(&fs::read(root.join(path))?));
    }
    for (tool, args) in [
        ("rustc", vec!["-Vv"]),
        ("node", vec!["--version"]),
        ("wasm-bindgen", vec!["--version"]),
    ] {
        let result = Command::new(tool).args(args).output()?;
        if !result.status.success() {
            return Err(format!("cannot identify {tool}").into());
        }
        p.insert(tool.into(), String::from_utf8(result.stdout)?.trim().into());
    }
    // Include uncommitted/untracked implementation bytes, not only git HEAD. Explicit
    // source roots exclude private state, build artifacts and sibling worktrees.
    let mut source = Sha256::new();
    fn hash_tree(root: &Path, path: &Path, hash: &mut Sha256) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.is_symlink() {
            return Err("source provenance cannot follow symlinks".into());
        }
        if metadata.is_dir() {
            let mut paths = fs::read_dir(path)?
                .map(|v| v.map(|e| e.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
            paths.sort();
            for child in paths {
                if child
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with('.'))
                {
                    continue;
                }
                if matches!(
                    child.file_name().and_then(|n| n.to_str()),
                    Some("target" | "build" | "node_modules" | ".tmp")
                ) {
                    continue;
                }
                hash_tree(root, &child, hash)?;
            }
        } else {
            hash.update(
                path.strip_prefix(root)?
                    .to_str()
                    .ok_or("non-UTF8 source")?
                    .as_bytes(),
            );
            hash.update([0]);
            hash.update(metadata.len().to_le_bytes());
            let mut file = fs::File::open(path)?;
            let mut buffer = [0; 65536];
            loop {
                let count = file.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hash.update(&buffer[..count]);
            }
        }
        Ok(())
    }
    for path in [
        "Cargo.toml",
        "package.json",
        ".cargo/config.toml",
        ".dockerignore",
        "crates",
        "xtask",
        "web",
        "scripts",
        "packages",
        "containers",
    ] {
        hash_tree(root, &root.join(path), &mut source)?;
    }
    p.insert("source.sha256".into(), hex(&source.finalize()));
    Ok(p)
}
fn import(package: &Path, out: &Path, kind: Kind) -> Result<(String, Image)> {
    let bytes = read_regular(&package.join("manifest.json"))?;
    let image = Image::parse(&bytes)?;
    if image.kind != kind {
        return Err("extension package kind mismatch".into());
    }
    check_contents(package, &image)?;
    for e in &image.entries {
        if let Node::File { sha256, .. } = &e.node {
            immutable(
                &out.join("blobs").join(sha256),
                &read_regular(&package.join("blobs").join(sha256))?,
            )?;
        }
    }
    let id = digest(&bytes);
    immutable(&out.join(format!("images/{id}.json")), &bytes)?;
    Ok((id, image))
}
pub fn boot(
    assets: &Path,
    out: &Path,
    name: &str,
    sysext: &[PathBuf],
    confext: &[PathBuf],
) -> Result<String> {
    no_overlap(assets, out)?;
    let mut entries = vec![directory("/")];
    walk(assets, assets, out, &mut entries, true)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let p = crate::build::verify(assets)?;
    let mut boot = image(Kind::Boot, name, "1", entries);
    boot.provenance = p.clone();
    let client_kernel_sha256 = boot
        .entries
        .iter()
        .find_map(|entry| {
            if entry.path == "/client_kernel_bg.wasm"
                && let Node::File { sha256, .. } = &entry.node
            {
                return Some(sha256.clone());
            }
            None
        })
        .ok_or("boot assets missing required /client_kernel_bg.wasm")?;
    let mut initramfs_img = initramfs(assets, out, name)?;
    initramfs_img.provenance = p.clone();
    let mut root_template_img = root_template(out, name)?;
    root_template_img.provenance = p.clone();
    let mut base = installed(assets, out, name)?;
    base.provenance = p.clone();
    let mut release = ReleaseV2 {
        format: "os.release".into(),
        version: RELEASE_VERSION,
        name: name.into(),
        loader: LoaderMeta {
            entry: "/index.html".into(),
            client_kernel_js: "/client-kernel.js".into(),
            client_kernel_wasm: "/client_kernel_bg.wasm".into(),
            client_kernel_sha256,
            host_adapter: Range {
                min: HOST_ADAPTER,
                max: HOST_ADAPTER,
            },
        },
        boot: write_image(out, &boot)?,
        initramfs: write_image(out, &initramfs_img)?,
        root_template: write_image(out, &root_template_img)?,
        base: write_image(out, &base)?,
        sysext: vec![],
        confext: vec![],
        protocol: Range {
            min: PROTOCOL,
            max: PROTOCOL,
        },
        schema: Range {
            min: SCHEMA,
            max: SCHEMA,
        },
        release_seq: None,
        provenance: p,
    };
    let mut extensions = Vec::new();
    for (paths, kind) in [(sysext, Kind::Sysext), (confext, Kind::Confext)] {
        for path in paths {
            let (id, image) = import(path, out, kind)?;
            extensions.push(image);
            if kind == Kind::Sysext {
                release.sysext.push(id);
            } else {
                release.confext.push(id);
            }
        }
    }
    release.verify_boot_loader(&boot)?;
    Composition::standalone(&initramfs_img)?;
    Composition::standalone(&root_template_img)?;
    Composition::new(&base, &extensions)?;
    release.validate()?;
    let bytes = serde_json::to_vec(&release)?;
    let id = digest(&bytes);
    for entry in &boot.entries {
        match &entry.node {
            Node::Directory => {}
            Node::File { sha256, .. } => immutable(
                &out.join(format!("releases/{id}/assets{}", entry.path)),
                &read_regular(&out.join("blobs").join(sha256))?,
            )?,
            Node::Symlink { .. } => return Err("boot assets cannot contain symlinks".into()),
        }
    }
    immutable(&out.join(format!("releases/{id}/manifest.json")), &bytes)?;
    replace(&out.join("release.json"), &bytes)?;
    // No activation here. The authority must independently verify and approve this release.
    verify(out, None)?;
    Ok(id)
}
fn check_file_chunks(
    path: &Path,
    expected_sha256: &str,
    expected_size: u64,
    chunk_size: u32,
    expected_chunks: &[String],
    label: &str,
) -> Result<()> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(format!("artifact is not a regular file: {label}").into());
    }
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut chunk_hash = Sha256::new();
    let mut chunk_filled = 0usize;
    let mut chunk_index = 0usize;
    let cs = chunk_size as usize;
    let mut length = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        length += n as u64;
        if length > expected_size {
            return Err(format!("content length mismatch: {label}").into());
        }
        let mut slice = &buffer[..n];
        while !slice.is_empty() {
            let take = slice.len().min(cs - chunk_filled);
            chunk_hash.update(&slice[..take]);
            chunk_filled += take;
            slice = &slice[take..];
            if chunk_filled == cs {
                let expected = expected_chunks
                    .get(chunk_index)
                    .ok_or_else(|| format!("chunk index out of range: {label}"))?;
                if hex(&chunk_hash.finalize_reset()) != *expected {
                    return Err(format!("chunk {chunk_index} digest mismatch: {label}").into());
                }
                chunk_filled = 0;
                chunk_index += 1;
            }
        }
    }
    if chunk_filled > 0 {
        let expected = expected_chunks
            .get(chunk_index)
            .ok_or_else(|| format!("chunk index out of range: {label}"))?;
        if hex(&chunk_hash.finalize()) != *expected {
            return Err(format!("chunk {chunk_index} digest mismatch: {label}").into());
        }
        chunk_index += 1;
    }
    if length != expected_size
        || chunk_index != expected_chunks.len()
        || hex(&hash.finalize()) != expected_sha256
    {
        return Err(format!("content digest/length mismatch: {label}").into());
    }
    Ok(())
}
fn check_contents(root: &Path, image: &Image) -> Result<()> {
    for entry in &image.entries {
        if let Node::File {
            sha256,
            size,
            chunk_size,
            chunks,
        } = &entry.node
        {
            check_file_chunks(
                &root.join("blobs").join(sha256),
                sha256,
                *size,
                *chunk_size,
                chunks,
                &entry.path,
            )?;
        }
    }
    Ok(())
}
pub fn verify(bundle: &Path, trust: Option<&Trust>) -> Result<String> {
    let bytes = read_regular(&bundle.join("release.json"))?;
    let release = ReleaseV2::parse(&bytes)?;
    let id = digest(&bytes);
    if read_regular(&bundle.join(format!("releases/{id}/manifest.json")))? != bytes {
        return Err("release projection mismatch".into());
    }
    if let Some(trust) = trust {
        trust.verify(
            SIGNING_DOMAIN_RELEASE_V2,
            &bytes,
            &read_regular(&bundle.join(format!("releases/{id}/signature.json")))?,
        )?;
    }
    let mut images = Vec::new();
    for hash in release.images() {
        let bytes = read_regular(&bundle.join(format!("images/{hash}.json")))?;
        if digest(&bytes) != hash {
            return Err("image digest mismatch".into());
        }
        if let Some(trust) = trust {
            trust.verify(
                SIGNING_DOMAIN_IMAGE_V2,
                &bytes,
                &read_regular(&bundle.join(format!("images/{hash}.sig")))?,
            )?;
        }
        let image = Image::parse(&bytes)?;
        check_contents(bundle, &image)?;
        images.push(image);
    }
    if images.len() < 4
        || images[0].kind != Kind::Boot
        || images[1].kind != Kind::Initramfs
        || images[2].kind != Kind::RootTemplate
        || images[3].kind != Kind::Base
    {
        return Err("release boot/initramfs/root_template/base kind mismatch".into());
    }
    for (i, image) in images[4..].iter().enumerate() {
        if image.kind
            != if i < release.sysext.len() {
                Kind::Sysext
            } else {
                Kind::Confext
            }
        {
            return Err("release extension kind mismatch".into());
        }
    }
    release.verify_boot_loader(&images[0])?;
    Composition::standalone(&images[1])?;
    Composition::standalone(&images[2])?;
    Composition::new(&images[3], &images[4..])?;
    for entry in &images[0].entries {
        if let Node::File {
            sha256,
            size,
            chunk_size,
            chunks,
        } = &entry.node
        {
            check_file_chunks(
                &bundle.join(format!("releases/{id}/assets{}", entry.path)),
                sha256,
                *size,
                *chunk_size,
                chunks,
                &entry.path,
            )?;
        } else if matches!(entry.node, Node::Symlink { .. }) {
            return Err("boot assets cannot contain symlinks".into());
        }
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::replace;
    use std::{fs, sync::Arc, thread};

    #[test]
    fn concurrent_replace_uses_unique_temp_paths_without_collision() {
        let dir = std::env::temp_dir().join(format!(
            "os-xtask-replace-concurrent-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let dir = Arc::new(dir);

        let handles: Vec<_> = (0..8)
            .map(|t| {
                let dir = Arc::clone(&dir);
                thread::spawn(move || {
                    for iter in 0..25 {
                        let target = dir.join(format!("file-{t}-{iter}.bin"));
                        let payload = format!("thread-{t}-iter-{iter}");
                        replace(&target, payload.as_bytes()).unwrap();
                        assert_eq!(fs::read(&target).unwrap(), payload.as_bytes());
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let _ = fs::remove_dir_all(dir.as_ref());
    }

    #[test]
    fn initramfs_packs_early_init_and_root_template_enforces_exact_account_modes() {
        let dir = std::env::temp_dir().join(format!("os-xtask-stage1-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let assets = dir.join("assets");
        let out = dir.join("out");
        fs::create_dir_all(assets.join("usr/bin")).unwrap();
        let early_bytes = b"\0asm\x01\0\0\0early-init-stage1";
        let main_init_bytes = b"\0asm\x01\0\0\0main-init-stage2";
        fs::write(assets.join("usr/bin/early_init.wasm"), early_bytes).unwrap();
        fs::write(assets.join("usr/bin/init.wasm"), main_init_bytes).unwrap();
        fs::write(
            assets.join("usr/bin/utilities.wasm"),
            b"\0asm\x01\0\0\0utils",
        )
        .unwrap();
        fs::write(assets.join("usr/bin/dash.wasm"), b"\0asm\x01\0\0\0dash").unwrap();

        let initramfs_img = super::initramfs(&assets, &out, "stage1-test").unwrap();
        let init_entry = initramfs_img
            .entries
            .iter()
            .find(|e| e.path == "/init")
            .expect("/init entry");
        assert_eq!(init_entry.mode, 0o755);
        match &init_entry.node {
            os_image::Node::File { sha256, .. } => {
                assert_eq!(sha256, &os_image::digest(early_bytes));
            }
            other => panic!("expected file node for /init, got {other:?}"),
        }

        let tpl = super::root_template(&out, "stage1-test").unwrap();
        let find = |p: &str| tpl.entries.iter().find(|e| e.path == p).expect(p);

        let passwd = find("/etc/passwd");
        assert_eq!((passwd.uid, passwd.gid, passwd.mode), (0, 0, 0o644));
        let group = find("/etc/group");
        assert_eq!((group.uid, group.gid, group.mode), (0, 0, 0o644));
        let shadow = find("/etc/shadow");
        assert_eq!((shadow.uid, shadow.gid, shadow.mode), (0, 0, 0o600));
        let sudoers = find("/etc/sudoers");
        assert_eq!((sudoers.uid, sudoers.gid, sudoers.mode), (0, 0, 0o440));
        if let os_image::Node::File { sha256, .. } = &sudoers.node {
            let text = fs::read_to_string(out.join("blobs").join(sha256)).unwrap();
            assert!(text.contains("%wheel ALL=(ALL:ALL) NOPASSWD: ALL"));
        } else {
            panic!("expected file node for /etc/sudoers");
        }
        let home_user = find("/home/user");
        assert_eq!(
            (home_user.uid, home_user.gid, home_user.mode),
            (1000, 1000, 0o750)
        );
        let root_dir = find("/root");
        assert_eq!((root_dir.uid, root_dir.gid, root_dir.mode), (0, 0, 0o700));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn initramfs_fails_closed_when_early_init_wasm_is_missing() {
        let dir = std::env::temp_dir().join(format!(
            "os-xtask-missing-early-init-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let assets = dir.join("assets");
        let out = dir.join("out");
        fs::create_dir_all(assets.join("usr/bin")).unwrap();
        // Deliberately omit `usr/bin/early_init.wasm` while providing Stage 2 `init.wasm`.
        fs::write(
            assets.join("usr/bin/init.wasm"),
            b"\0asm\x01\0\0\0stage2-init-must-not-be-substituted",
        )
        .unwrap();
        fs::write(
            assets.join("usr/bin/utilities.wasm"),
            b"\0asm\x01\0\0\0utils",
        )
        .unwrap();
        fs::write(assets.join("usr/bin/dash.wasm"), b"\0asm\x01\0\0\0dash").unwrap();

        let err = super::initramfs(&assets, &out, "missing-early-init").unwrap_err();
        assert!(
            err.to_string().contains("early_init.wasm"),
            "expected missing early_init.wasm error, got: {err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
