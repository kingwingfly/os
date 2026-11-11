use crate::Result;
use os_image::{
    ABI, Composition, Entry, Image, Kind, LEVEL, Node, PROTOCOL, Range, Release, SCHEMA, Trust,
    digest, hex,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Command,
};

pub fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or("missing parent")?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".xtask-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
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
    Entry {
        path: path.into(),
        uid: 0,
        gid: 0,
        mode: 0o755,
        node: Node::Directory,
    }
}
fn image(kind: Kind, name: &str, revision: &str, entries: Vec<Entry>) -> Image {
    Image {
        format: "os.image".into(),
        version: 1,
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
    immutable(&out.join("blobs").join(&sha256), bytes)?;
    Ok(Node::File {
        sha256,
        size: bytes.len() as u64,
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
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            (meta.permissions().mode() & 0o7777) as u16
        };
        #[cfg(not(unix))]
        let mode = if meta.is_dir() { 0o755 } else { 0o644 };
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
        "/usr/libexec",
        "/usr/local",
        "/usr/share",
        "/usr/src",
    ]
    .into_iter()
    .map(directory)
    .collect();
    for bin in ["coreutils", "utilities", "dash", "supervise", "init"] {
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
    let mut base = installed(assets, out, name)?;
    base.provenance = p.clone();
    let mut release = Release {
        format: "os.release".into(),
        version: 1,
        name: name.into(),
        boot: write_image(out, &boot)?,
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
fn check_contents(root: &Path, image: &Image) -> Result<()> {
    for entry in &image.entries {
        if let Node::File { sha256, size } = &entry.node {
            let path = root.join("blobs").join(sha256);
            if !fs::symlink_metadata(&path)?.is_file() {
                return Err("blob is not a regular file".into());
            }
            let mut file = fs::File::open(path)?;
            let mut hash = Sha256::new();
            let mut length = 0u64;
            let mut buffer = [0; 65536];
            loop {
                let n = file.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                hash.update(&buffer[..n]);
                length += n as u64;
            }
            if length != *size || hex(&hash.finalize()) != *sha256 {
                return Err(format!("content digest/length mismatch: {}", entry.path).into());
            }
        }
    }
    Ok(())
}
pub fn verify(bundle: &Path, trust: Option<&Trust>) -> Result<String> {
    let bytes = read_regular(&bundle.join("release.json"))?;
    let release = Release::parse(&bytes)?;
    let id = digest(&bytes);
    if read_regular(&bundle.join(format!("releases/{id}/manifest.json")))? != bytes {
        return Err("release projection mismatch".into());
    }
    if let Some(trust) = trust {
        trust.verify(
            "os.release.v1",
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
                "os.image.v1",
                &bytes,
                &read_regular(&bundle.join(format!("images/{hash}.sig")))?,
            )?;
        }
        let image = Image::parse(&bytes)?;
        check_contents(bundle, &image)?;
        images.push(image);
    }
    if images[0].kind != Kind::Boot || images[1].kind != Kind::Base {
        return Err("release boot/base kind mismatch".into());
    }
    for (i, image) in images[2..].iter().enumerate() {
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
    Composition::new(&images[1], &images[2..])?;
    for entry in &images[0].entries {
        if let Node::File { sha256, size } = &entry.node {
            let bytes = read_regular(&bundle.join(format!("releases/{id}/assets{}", entry.path)))?;
            if bytes.len() as u64 != *size || digest(&bytes) != *sha256 {
                return Err(format!("boot asset mismatch: {}", entry.path).into());
            }
        } else if matches!(entry.node, Node::Symlink { .. }) {
            return Err("boot assets cannot contain symlinks".into());
        }
    }
    Ok(id)
}
