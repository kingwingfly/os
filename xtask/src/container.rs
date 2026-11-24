//! Assemble a minimal, 100% offline `FROM scratch` OCI container build context for `os-native`
//! (`cargo xtask container --bundle <BUNDLE> --out <STAGE_DIR> [--bin <BIN>] [--tag <TAG>] [--build]`).

use crate::{Result, package};
use os_image::{ReleaseV2, Trust};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CONTAINER_HELP: &str = "Usage: cargo xtask container --bundle BUNDLE --out STAGE_DIR [OPTIONS]\n\
  --bundle DIR             Verified Release v2 bundle directory (required)\n\
  --out DIR                Output build-context directory (required)\n\
  --bin PATH               Prebuilt os-native binary (default: cargo build --release --locked --offline -p os-native)\n\
  --trust FILE             Public trust JSON to verify bundle (default: <BUNDLE>/publisher.json)\n\
  --unsigned-development   Allow unsigned development bundle verification\n\
  --tag NAME               OCI image tag when invoking --build (default: localhost/os-native:dev)\n\
  --build                  Build the FROM scratch image offline via `podman build --network=none`\n\
  --podman-root DIR        Optional isolated podman --root directory\n\
  --podman-runroot DIR     Optional isolated podman --runroot directory\n";

pub fn run(args: Vec<String>) -> Result<()> {
    if args.is_empty() || args.iter().any(|a| matches!(a.as_str(), "-h" | "--help")) {
        println!("{CONTAINER_HELP}");
        return Ok(());
    }

    let mut bundle_dir: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut bin_path: Option<PathBuf> = None;
    let mut trust_path: Option<PathBuf> = None;
    let mut unsigned_dev = false;
    let mut do_build = false;
    let mut tag = "localhost/os-native:dev".to_string();
    let mut podman_root: Option<PathBuf> = None;
    let mut podman_runroot: Option<PathBuf> = None;

    let mut i = 0usize;
    while i < args.len() {
        let flag = args[i].as_str();
        let next = |idx: &mut usize| -> Result<String> {
            *idx += 1;
            args.get(*idx)
                .cloned()
                .ok_or_else(|| format!("missing value for {flag}").into())
        };
        match flag {
            "--bundle" => bundle_dir = Some(PathBuf::from(next(&mut i)?)),
            "--out" => out_dir = Some(PathBuf::from(next(&mut i)?)),
            "--bin" => bin_path = Some(PathBuf::from(next(&mut i)?)),
            "--trust" => trust_path = Some(PathBuf::from(next(&mut i)?)),
            "--unsigned-development" => unsigned_dev = true,
            "--build" => do_build = true,
            "--tag" => tag = next(&mut i)?,
            "--podman-root" => podman_root = Some(PathBuf::from(next(&mut i)?)),
            "--podman-runroot" => podman_runroot = Some(PathBuf::from(next(&mut i)?)),
            other => return Err(format!("unknown option {other}\n{CONTAINER_HELP}").into()),
        }
        i += 1;
    }

    let bundle_dir = bundle_dir.ok_or("missing required --bundle")?;
    let out_dir = out_dir.ok_or("missing required --out")?;
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("missing workspace root")?
        .to_path_buf();

    // 1. Verify the Release v2 bundle BEFORE staging anything into the container context.
    let trust: Option<Trust> = if unsigned_dev {
        None
    } else {
        let tp = trust_path.unwrap_or_else(|| bundle_dir.join("publisher.json"));
        let bytes = fs::read(&tp).map_err(|e| {
            format!(
                "read trust {}: {e} (or pass --unsigned-development)",
                tp.display()
            )
        })?;
        Some(os_image::parse(&bytes)?)
    };
    let release_id = package::verify(&bundle_dir, trust.as_ref())?;
    let release_bytes = fs::read(bundle_dir.join("release.json"))?;
    let release = ReleaseV2::parse(&release_bytes)?;

    // 2. Locate or build the release `os-native` binary.
    let binary = match bin_path {
        Some(p) => p,
        None => {
            let status = Command::new("cargo")
                .current_dir(&repo_root)
                .args([
                    "build",
                    "--release",
                    "--locked",
                    "--offline",
                    "-p",
                    "os-native",
                    "--bin",
                    "os-native",
                ])
                .status()?;
            if !status.success() {
                return Err("failed to build release os-native binary".into());
            }
            let target_dir = std::env::var_os("CARGO_TARGET_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| repo_root.join("target"));
            target_dir.join("release/os-native")
        }
    };
    if !binary.is_file() {
        return Err(format!("os-native binary not found at {}", binary.display()).into());
    }

    // 3. Stage clean `FROM scratch` build context (`Containerfile`, `rootfs/`, `bundle/`).
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)?;
    }
    let rootfs = out_dir.join("rootfs");
    let stage_bundle = out_dir.join("bundle");
    fs::create_dir_all(rootfs.join("usr/local/bin"))?;
    fs::create_dir_all(rootfs.join("state"))?;
    fs::create_dir_all(rootfs.join("tmp"))?;
    fs::set_permissions(rootfs.join("tmp"), fs::Permissions::from_mode(0o1777))?;

    let dst_bin = rootfs.join("usr/local/bin/os-native");
    fs::copy(&binary, &dst_bin)?;
    fs::set_permissions(&dst_bin, fs::Permissions::from_mode(0o755))?;

    // Discover and copy exact `ldd` ELF shared library closure (preserving symlink chains).
    let libs = discover_ldd_closure(&binary)?;
    for lib_path in &libs {
        stage_host_lib(&rootfs, lib_path)?;
    }

    // Copy minimal verified Release v2 bundle (omitting browser `releases/<id>/assets/` duplicates).
    stage_minimal_bundle(&bundle_dir, &stage_bundle, &release_id, &release)?;

    let containerfile_src = repo_root.join("containers/os-native/Containerfile");
    fs::copy(&containerfile_src, out_dir.join("Containerfile"))?;

    println!(
        "staged os-native container context at {} (release={}, libs={})",
        out_dir.display(),
        release_id,
        libs.len()
    );

    if do_build {
        let mut cmd = Command::new("podman");
        if let Some(ref r) = podman_root {
            cmd.arg("--root").arg(r);
        }
        if let Some(ref rr) = podman_runroot {
            cmd.arg("--runroot").arg(rr);
        }
        cmd.args(["build", "--network=none", "-f"])
            .arg(out_dir.join("Containerfile"))
            .arg("-t")
            .arg(&tag)
            .arg(&out_dir);
        let status = cmd.status()?;
        if !status.success() {
            return Err(format!("podman build failed with status {status}").into());
        }
        println!("built offline OCI image {tag}");
    }

    Ok(())
}

fn discover_ldd_closure(binary: &Path) -> Result<BTreeSet<PathBuf>> {
    let out = Command::new("ldd").arg(binary).output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Statically linked binary returns exit 1 with "not a dynamic executable".
        if stderr.contains("not a dynamic executable") || stderr.contains("statically linked") {
            return Ok(BTreeSet::new());
        }
        return Err(format!("ldd {} failed: {stderr}", binary.display()).into());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut paths = BTreeSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains("not found") {
            return Err(format!("unresolved shared library in ldd output: {trimmed}").into());
        }
        if let Some((lhs, rhs)) = trimmed.split_once("=>") {
            if let Some(p) = lhs.split_whitespace().next()
                && p.starts_with('/')
            {
                paths.insert(PathBuf::from(p));
            }
            if let Some(p) = rhs.split_whitespace().next()
                && p.starts_with('/')
            {
                paths.insert(PathBuf::from(p));
            }
        } else if let Some(p) = trimmed.split_whitespace().next()
            && p.starts_with('/')
        {
            paths.insert(PathBuf::from(p));
        }
    }
    Ok(paths)
}

/// Copy a host library path (and any symlink target chain it points to) into `rootfs` at its
/// exact absolute path so the Linux dynamic loader resolves every library identically in `scratch`.
fn stage_host_lib(rootfs: &Path, abs_path: &Path) -> Result<()> {
    let mut current = abs_path.to_path_buf();
    for _ in 0..16 {
        let rel = current
            .strip_prefix("/")
            .map_err(|_| format!("expected absolute library path: {}", current.display()))?;
        let dst = rootfs.join(rel);
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        let meta = fs::symlink_metadata(&current)?;
        if meta.file_type().is_symlink() {
            let link_target = fs::read_link(&current)?;
            if !dst.exists() && fs::symlink_metadata(&dst).is_err() {
                std::os::unix::fs::symlink(&link_target, &dst)?;
            }
            current = if link_target.is_absolute() {
                link_target
            } else {
                current
                    .parent()
                    .unwrap_or_else(|| Path::new("/"))
                    .join(link_target)
            };
        } else {
            if !dst.exists() {
                fs::copy(&current, &dst)?;
                let mode = meta.permissions().mode() & 0o755;
                let _ = fs::set_permissions(&dst, fs::Permissions::from_mode(mode.max(0o644)));
            }
            break;
        }
    }
    Ok(())
}

fn stage_minimal_bundle(
    src: &Path,
    dst: &Path,
    release_id: &str,
    release: &ReleaseV2,
) -> Result<()> {
    fs::create_dir_all(dst.join("images"))?;
    fs::create_dir_all(dst.join("blobs"))?;
    fs::create_dir_all(dst.join(format!("releases/{release_id}")))?;

    fs::copy(src.join("release.json"), dst.join("release.json"))?;
    if src.join("publisher.json").is_file() {
        fs::copy(src.join("publisher.json"), dst.join("publisher.json"))?;
    }
    let rel_manifest = format!("releases/{release_id}/manifest.json");
    if src.join(&rel_manifest).is_file() {
        fs::copy(src.join(&rel_manifest), dst.join(&rel_manifest))?;
    }
    let rel_sig = format!("releases/{release_id}/signature.json");
    if src.join(&rel_sig).is_file() {
        fs::copy(src.join(&rel_sig), dst.join(&rel_sig))?;
    }

    let mut needed_blobs: BTreeSet<String> = BTreeSet::new();
    for img_id in release.images() {
        let json_rel = format!("images/{img_id}.json");
        let raw = fs::read(src.join(&json_rel))?;
        fs::write(dst.join(&json_rel), &raw)?;
        let sig_rel = format!("images/{img_id}.sig");
        if src.join(&sig_rel).is_file() {
            fs::copy(src.join(&sig_rel), dst.join(&sig_rel))?;
        }
        let img = os_image::Image::parse(&raw)?;
        for entry in img.entries {
            if let os_image::Node::File { sha256, .. } = entry.node {
                needed_blobs.insert(sha256);
            }
        }
    }

    for blob_id in needed_blobs {
        let rel = format!("blobs/{blob_id}");
        fs::copy(src.join(&rel), dst.join(&rel))?;
    }
    Ok(())
}
