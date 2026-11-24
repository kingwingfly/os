//! Stage 0 verified Release v2 offline bundle loader and zero-whole-blob-buffering
//! `LocalFileBlobStore` (`pread(2)` + per-chunk SHA-256 verification before exposing any byte).

use abi::Errno;
use os_image::{
    Composition, Image, Kind, Node, ReleaseV2, SIGNING_DOMAIN_IMAGE_V2, SIGNING_DOMAIN_RELEASE_V2,
    Trust,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use vfs::BoxFuture;
use vfs::imagefs::{BlobStore, ChunkManifest, ImageEntry, ImageNodeKind};

/// On-disk Release v2 blob store backed by `pread(2)` with per-chunk SHA-256 verification.
#[derive(Clone, Debug)]
pub struct LocalFileBlobStore {
    blobs_dir: PathBuf,
}

impl LocalFileBlobStore {
    pub fn new(bundle_dir: impl AsRef<Path>) -> Self {
        Self {
            blobs_dir: bundle_dir.as_ref().join("blobs"),
        }
    }

    pub fn blob_path(&self, sha256: &str) -> Result<PathBuf, Errno> {
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Errno::EINVAL);
        }
        Ok(self.blobs_dir.join(sha256))
    }

    /// Synchronously read and chunk-verify a complete blob from disk against its manifest.
    pub fn read_verified_whole(
        &self,
        sha256: &str,
        size: u64,
        chunk_size: u32,
        chunks: &[String],
    ) -> Result<Vec<u8>, Errno> {
        if size == 0 {
            if sha256 != os_image::EMPTY_SHA256 || !chunks.is_empty() {
                return Err(Errno::EIO);
            }
            return Ok(Vec::new());
        }
        let manifest = ChunkManifest {
            sha256: sha256.to_string(),
            size,
            chunk_size,
            chunks: chunks.to_vec(),
        };
        let mut out = vec![0u8; usize::try_from(size).map_err(|_| Errno::EFBIG)?];
        let got = self.read_verified_sync(sha256, &manifest, 0, &mut out)?;
        if got != out.len() {
            return Err(Errno::EIO);
        }
        Ok(out)
    }

    fn read_verified_sync(
        &self,
        blob_id: &str,
        manifest: &ChunkManifest,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        if buf.is_empty() || offset >= manifest.size {
            return Ok(0);
        }
        let cs = u64::from(manifest.chunk_size);
        if cs == 0
            || !manifest.chunk_size.is_power_of_two()
            || !(os_image::CHUNK_SIZE_MIN..=os_image::CHUNK_SIZE_MAX).contains(&manifest.chunk_size)
        {
            return Err(Errno::EINVAL);
        }
        let path = self.blob_path(blob_id)?;
        let file = File::open(&path).map_err(|e| crate::errno::io_err_to_abi(&e))?;
        let total_want =
            usize::try_from(manifest.size - offset).map_or(buf.len(), |rem| rem.min(buf.len()));
        let end_off = offset.checked_add(total_want as u64).ok_or(Errno::EINVAL)?;
        let first_chunk = usize::try_from(offset / cs).map_err(|_| Errno::EINVAL)?;
        let last_chunk = usize::try_from((end_off - 1) / cs).map_err(|_| Errno::EINVAL)?;
        if last_chunk >= manifest.chunks.len() {
            return Err(Errno::EINVAL);
        }

        let mut dst = 0usize;
        let mut chunk_buf = Vec::new();
        for idx in first_chunk..=last_chunk {
            let c_start = (idx as u64).checked_mul(cs).ok_or(Errno::EINVAL)?;
            let expected_len = usize::try_from(manifest.size.saturating_sub(c_start).min(cs))
                .map_err(|_| Errno::EINVAL)?;
            chunk_buf.resize(expected_len, 0);
            if let Err(err) = file.read_exact_at(&mut chunk_buf, c_start) {
                buf[..dst].fill(0);
                return Err(crate::errno::io_err_to_abi(&err));
            }
            let actual = os_image::hex(&Sha256::digest(&chunk_buf));
            if actual != manifest.chunks[idx] {
                buf[..dst].fill(0);
                return Err(Errno::EIO);
            }
            let copy_start = offset.saturating_sub(c_start) as usize;
            let copy_end = (end_off - c_start).min(expected_len as u64) as usize;
            let take = copy_end - copy_start;
            buf[dst..dst + take].copy_from_slice(&chunk_buf[copy_start..copy_end]);
            dst += take;
        }
        Ok(dst)
    }
}

impl BlobStore for LocalFileBlobStore {
    fn read_at<'a>(
        &'a self,
        blob_id: &'a str,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, usize> {
        self.read_verified_at(blob_id, None, offset, buf)
    }

    fn read_verified_at<'a>(
        &'a self,
        blob_id: &'a str,
        manifest: Option<&'a ChunkManifest>,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let Some(m) = manifest else {
                // Fail closed: Release v2 reads MUST always carry a verified ChunkManifest.
                return Err(Errno::EIO);
            };
            self.read_verified_sync(blob_id, m, offset, buf)
        })
    }
}

/// Verified `.rv1` sidecar manifest entry indexed by raw `.wasm` SHA-256 digest.
#[derive(Clone, Debug)]
pub struct VerifiedSidecar {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub chunk_size: u32,
    pub chunks: Vec<String>,
}

/// Cryptographically verified Release v2 offline bundle ready for Stage 0 -> Stage 1 -> Stage 2.
#[derive(Clone, Debug)]
pub struct VerifiedReleaseBundle {
    pub release_id: String,
    pub signer_key: Option<String>,
    pub release: ReleaseV2,
    pub boot: Image,
    pub initramfs: Image,
    pub root_template: Image,
    pub base: Image,
    pub extensions: Vec<Image>,
    pub blobs: LocalFileBlobStore,
    /// Map from raw `.wasm` SHA-256 -> verified `.wasm.rv1` sidecar entry in `Kind::Boot`.
    pub rv1_by_raw_sha256: HashMap<String, VerifiedSidecar>,
}

fn read_regular(path: &Path) -> Result<Vec<u8>, String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!("expected regular file: {}", path.display()));
    }
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

impl VerifiedReleaseBundle {
    /// Load and cryptographically verify a local Release v2 bundle directory completely offline.
    ///
    /// When `trust` is `Some`, Ed25519 signatures over `SIGNING_DOMAIN_RELEASE_V2` and
    /// `SIGNING_DOMAIN_IMAGE_V2` are strictly verified. When `trust` is `None` AND
    /// `allow_unsigned_dev` is `false`, loads `<bundle>/publisher.json` and requires valid
    /// signatures (failing closed if absent!).
    pub fn load(
        bundle_dir: impl AsRef<Path>,
        trust_override: Option<&Trust>,
        allow_unsigned_dev: bool,
    ) -> Result<Self, String> {
        let dir = bundle_dir.as_ref();
        let trust_owned: Option<Trust> = if let Some(t) = trust_override {
            Some(t.clone())
        } else if !allow_unsigned_dev {
            let pub_bytes = read_regular(&dir.join("publisher.json")).map_err(|e| {
                format!("missing publisher trust bundle (use --trust or --allow-unsigned-dev): {e}")
            })?;
            let parsed: Trust = os_image::parse(&pub_bytes)
                .map_err(|e| format!("invalid publisher.json trust bundle: {e}"))?;
            if parsed.keys.is_empty() {
                return Err("publisher.json contains no trusted keys".into());
            }
            Some(parsed)
        } else {
            None
        };

        let release_bytes = read_regular(&dir.join("release.json"))?;
        let release_id = os_image::digest(&release_bytes);
        let manifest_path = dir.join(format!("releases/{release_id}/manifest.json"));
        if manifest_path.exists() && read_regular(&manifest_path)? != release_bytes {
            return Err("release.json does not match releases/<id>/manifest.json".into());
        }

        let signer_key = if let Some(ref trust) = trust_owned {
            let sig_bytes =
                read_regular(&dir.join(format!("releases/{release_id}/signature.json")))?;
            let signer = trust
                .verify(SIGNING_DOMAIN_RELEASE_V2, &release_bytes, &sig_bytes)
                .map_err(|e| format!("release signature verification failed: {e}"))?;
            Some(signer)
        } else {
            None
        };

        let release = ReleaseV2::parse(&release_bytes)
            .map_err(|e| format!("invalid Release v2 manifest: {e}"))?;

        let expected_ids: Vec<&str> = release.images().collect();
        let mut parsed_images = Vec::with_capacity(expected_ids.len());
        for (idx, expected_id) in expected_ids.iter().enumerate() {
            let img_bytes = read_regular(&dir.join(format!("images/{expected_id}.json")))?;
            if os_image::digest(&img_bytes) != *expected_id {
                return Err(format!("image digest mismatch for {expected_id}"));
            }
            if let Some(ref trust) = trust_owned {
                let img_sig = read_regular(&dir.join(format!("images/{expected_id}.sig")))?;
                trust
                    .verify(SIGNING_DOMAIN_IMAGE_V2, &img_bytes, &img_sig)
                    .map_err(|e| {
                        format!("image signature verification failed ({expected_id}): {e}")
                    })?;
            }
            let img = Image::parse(&img_bytes)
                .map_err(|e| format!("invalid image {expected_id}: {e}"))?;
            let expected_kind = match idx {
                0 => Kind::Boot,
                1 => Kind::Initramfs,
                2 => Kind::RootTemplate,
                3 => Kind::Base,
                n if n < 4 + release.sysext.len() => Kind::Sysext,
                _ => Kind::Confext,
            };
            if img.kind != expected_kind {
                return Err(format!(
                    "image {expected_id} kind mismatch: expected {expected_kind:?}, got {:?}",
                    img.kind
                ));
            }
            parsed_images.push(img);
        }

        let mut iter = parsed_images.into_iter();
        let boot = iter.next().ok_or("missing boot image")?;
        let initramfs = iter.next().ok_or("missing initramfs image")?;
        let root_template = iter.next().ok_or("missing root_template image")?;
        let base = iter.next().ok_or("missing base image")?;
        let extensions: Vec<Image> = iter.collect();

        release
            .verify_boot_loader(&boot)
            .map_err(|e| format!("boot loader verification failed: {e}"))?;
        Composition::standalone(&initramfs)
            .map_err(|e| format!("initramfs composition invalid: {e}"))?;
        Composition::standalone(&root_template)
            .map_err(|e| format!("root_template composition invalid: {e}"))?;
        Composition::new(&base, &extensions)
            .map_err(|e| format!("base + extensions composition invalid: {e}"))?;

        let blobs = LocalFileBlobStore::new(dir);

        // Index verified `.wasm.rv1` sidecars shipped in `Kind::Boot` by the raw `.wasm` SHA-256.
        let mut boot_files: HashMap<&str, (&str, u64, u32, &[String])> = HashMap::new();
        for entry in &boot.entries {
            if let Node::File {
                sha256,
                size,
                chunk_size,
                chunks,
            } = &entry.node
            {
                boot_files.insert(
                    entry.path.as_str(),
                    (sha256.as_str(), *size, *chunk_size, chunks.as_slice()),
                );
            }
        }
        let mut rv1_by_raw_sha256 = HashMap::new();
        for (&path, &(raw_sha, _, _, _)) in &boot_files {
            if path.ends_with(".wasm") {
                let rv1_path = format!("{path}.rv1");
                if let Some(&(rv1_sha, rv1_size, rv1_cs, rv1_chunks)) =
                    boot_files.get(rv1_path.as_str())
                {
                    rv1_by_raw_sha256.insert(
                        raw_sha.to_string(),
                        VerifiedSidecar {
                            path: rv1_path,
                            sha256: rv1_sha.to_string(),
                            size: rv1_size,
                            chunk_size: rv1_cs,
                            chunks: rv1_chunks.to_vec(),
                        },
                    );
                }
            }
        }

        Ok(Self {
            release_id,
            signer_key,
            release,
            boot,
            initramfs,
            root_template,
            base,
            extensions,
            blobs,
            rv1_by_raw_sha256,
        })
    }

    pub fn load_rv1_for_raw_sha256(&self, raw_sha256: &str) -> Result<Option<Vec<u8>>, Errno> {
        let Some(sc) = self.rv1_by_raw_sha256.get(raw_sha256) else {
            return Ok(None);
        };
        let bytes =
            self.blobs
                .read_verified_whole(&sc.sha256, sc.size, sc.chunk_size, &sc.chunks)?;
        Ok(Some(bytes))
    }
}

/// Convert a verified `os_image::Image` into `os_vfs::imagefs::ImageEntry` records.
pub fn image_to_vfs_entries(img: &Image) -> Vec<ImageEntry> {
    img.entries
        .iter()
        .map(|entry| {
            let node = match &entry.node {
                Node::Directory => ImageNodeKind::Directory,
                Node::File {
                    sha256,
                    size,
                    chunk_size,
                    chunks,
                } => ImageNodeKind::File {
                    blob_id: sha256.clone(),
                    size: *size,
                    chunk_size: Some(*chunk_size),
                    chunks: chunks.clone(),
                },
                Node::Symlink { target } => ImageNodeKind::Symlink {
                    target: target.clone(),
                },
            };
            ImageEntry {
                path: entry.path.clone(),
                uid: entry.uid,
                gid: entry.gid,
                mode: entry.mode,
                node,
            }
        })
        .collect()
}

/// Compose `Kind::Base` + `Kind::Sysext`/`Kind::Confext` into `os_vfs::imagefs::ImageEntry` records.
pub fn compose_system_image_entries(
    base: &Image,
    extensions: &[Image],
) -> Result<Vec<ImageEntry>, String> {
    let comp = Composition::new(base, extensions).map_err(|e| e.to_string())?;
    let entries = comp
        .entries
        .into_values()
        .map(|entry| {
            let node = match entry.node {
                Node::Directory => ImageNodeKind::Directory,
                Node::File {
                    sha256,
                    size,
                    chunk_size,
                    chunks,
                } => ImageNodeKind::File {
                    blob_id: sha256,
                    size,
                    chunk_size: Some(chunk_size),
                    chunks,
                },
                Node::Symlink { target } => ImageNodeKind::Symlink { target },
            };
            ImageEntry {
                path: entry.path,
                uid: entry.uid,
                gid: entry.gid,
                mode: entry.mode,
                node,
            }
        })
        .collect();
    Ok(entries)
}
