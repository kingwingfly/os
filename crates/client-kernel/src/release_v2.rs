//! Release v2 chunk-verified [`BlobStore`] and offline Stage 0 / Stage 1 verification bindings
//! (`#78` L2.5b, Blueprint §2.4).
//!
//! `VerifiedAssetBlobStore` never buffers whole image blobs in `wasm32` linear memory: every read
//! passes the file's [`ChunkManifest`] directly to `self.imageBlobRead(blobId, offset, len, manifest)`
//! (backed by `web/kernel/image-pager.js`: OPFS-first local read with zero network when installed,
//! or bounded `<= 1 MiB` streaming range fetch with `Range` + strong `If-Range`, max 4 concurrent
//! fetches, in-flight coalescing, and per-chunk SHA-256 verification before exposing any byte).

use crate::cloudfs::installed;
use abi::Errno;
use image::{
    Composition, Image, Kind, Node, ReleaseV2, SIGNING_DOMAIN_IMAGE_V2, SIGNING_DOMAIN_RELEASE_V2,
    Trust,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use vfs::imagefs::{BlobStore, ChunkManifest, ImageEntry, ImageFs, ImageNodeKind};
use vfs::{BoxFuture, Cred, Filesystem, FsId, OpenOptions, Timespec};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const WASM_HEADER_STUB: [u8; 8] = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];

fn errno_from_js(err: &JsValue) -> Errno {
    let code = js_sys::Reflect::get(err, &"errno".into())
        .ok()
        .and_then(|v| v.as_string())
        .or_else(|| {
            js_sys::Reflect::get(err, &"code".into())
                .ok()
                .and_then(|v| v.as_string())
        });
    match code.as_deref() {
        Some("ENOENT") => Errno::ENOENT,
        Some("EINVAL") => Errno::EINVAL,
        Some("EACCES") => Errno::EACCES,
        Some("EPERM") => Errno::EPERM,
        Some("ENOTCONN") => Errno::ENOTCONN,
        Some("EPROTONOSUPPORT") => Errno::EPROTONOSUPPORT,
        Some("ENOSPC") => Errno::ENOSPC,
        Some("EFBIG") => Errno::EFBIG,
        Some("ESTALE") => Errno::ESTALE,
        _ => Errno::EIO,
    }
}

fn manifest_to_js(manifest: &ChunkManifest) -> vfs::Result<JsValue> {
    let obj = js_sys::Object::new();
    let chunks = js_sys::Array::new_with_length(manifest.chunks.len() as u32);
    for (i, c) in manifest.chunks.iter().enumerate() {
        chunks.set(i as u32, JsValue::from_str(c));
    }
    js_sys::Reflect::set(&obj, &"sha256".into(), &JsValue::from_str(&manifest.sha256))
        .map_err(|_| Errno::EIO)?;
    js_sys::Reflect::set(
        &obj,
        &"size".into(),
        &JsValue::from_f64(manifest.size as f64),
    )
    .map_err(|_| Errno::EIO)?;
    js_sys::Reflect::set(
        &obj,
        &"chunk_size".into(),
        &JsValue::from_f64(f64::from(manifest.chunk_size)),
    )
    .map_err(|_| Errno::EIO)?;
    js_sys::Reflect::set(&obj, &"chunks".into(), &chunks).map_err(|_| Errno::EIO)?;
    Ok(obj.into())
}

fn is_lower_hex_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Reads the covering aligned chunks for `[offset, offset + buf.len())`, verifies every
/// chunk's exact length and SHA-256 digest in Rust before exposing any bytes, and copies
/// the requested sub-range into `buf`. Zeroes `buf` and returns `Err(Errno::EIO)` on any
/// short read, zero-byte premature EOF, or digest mismatch.
async fn read_verified_chunks<F>(
    manifest: &ChunkManifest,
    offset: u64,
    buf: &mut [u8],
    mut fetch_chunk: F,
) -> vfs::Result<usize>
where
    F: FnMut(u64, usize) -> BoxFuture<'static, Vec<u8>>,
{
    if buf.is_empty() || offset >= manifest.size {
        return Ok(0);
    }
    let cs = u64::from(manifest.chunk_size);
    if cs == 0
        || !manifest.chunk_size.is_power_of_two()
        || !(image::CHUNK_SIZE_MIN..=image::CHUNK_SIZE_MAX).contains(&manifest.chunk_size)
    {
        return Err(Errno::EINVAL);
    }
    let total_want =
        usize::try_from(manifest.size - offset).map_or(buf.len(), |rem| rem.min(buf.len()));
    let end_off = offset.checked_add(total_want as u64).ok_or(Errno::EINVAL)?;
    let first_chunk = usize::try_from(offset / cs).map_err(|_| Errno::EINVAL)?;
    let last_chunk = usize::try_from((end_off - 1) / cs).map_err(|_| Errno::EINVAL)?;
    if last_chunk >= manifest.chunks.len() {
        return Err(Errno::EINVAL);
    }
    let mut dst = 0usize;
    for idx in first_chunk..=last_chunk {
        let c_start = (idx as u64).checked_mul(cs).ok_or(Errno::EINVAL)?;
        let expected_len = usize::try_from(manifest.size.saturating_sub(c_start).min(cs))
            .map_err(|_| Errno::EINVAL)?;
        let chunk_bytes = match fetch_chunk(c_start, expected_len).await {
            Ok(bytes) => bytes,
            Err(err) => {
                buf[..dst].fill(0);
                return Err(err);
            }
        };
        if chunk_bytes.len() != expected_len {
            buf[..dst].fill(0);
            return Err(Errno::EIO);
        }
        if let Err(err) = verify_chunk_bytes(manifest, idx, &chunk_bytes) {
            buf[..dst].fill(0);
            return Err(err);
        }
        let copy_start = offset.saturating_sub(c_start) as usize;
        let copy_end = (end_off - c_start).min(expected_len as u64) as usize;
        let take = copy_end - copy_start;
        buf[dst..dst + take].copy_from_slice(&chunk_bytes[copy_start..copy_end]);
        dst += take;
    }
    Ok(dst)
}

/// Chunk-verified, zero-whole-blob-buffering [`BlobStore`] backed by `self.imageBlobRead`.
#[derive(Clone, Default)]
pub(crate) struct VerifiedAssetBlobStore;

impl BlobStore for VerifiedAssetBlobStore {
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
            if buf.is_empty() {
                return Ok(0);
            }
            if let Some(m) = manifest
                && offset >= m.size
            {
                return Ok(0);
            }
            if let Ok((global, reader)) = installed("imageBlobRead") {
                if let Some(m) = manifest {
                    let effective_id = if is_lower_hex_sha256(blob_id) {
                        format!("sha256:{blob_id}")
                    } else {
                        blob_id.to_string()
                    };
                    let manifest_js = manifest_to_js(m)?;
                    return read_verified_chunks(m, offset, buf, |c_start, expected_len| {
                        let global = global.clone();
                        let reader = reader.clone();
                        let effective_id = effective_id.clone();
                        let manifest_js = manifest_js.clone();
                        Box::pin(async move {
                            let args = js_sys::Array::new_with_length(4);
                            args.set(0, JsValue::from_str(&effective_id));
                            args.set(1, JsValue::from_f64(c_start as f64));
                            args.set(2, JsValue::from_f64(expected_len as f64));
                            args.set(3, manifest_js);
                            let answer = reader
                                .apply(&global, &args)
                                .map_err(|e| errno_from_js(&e))?;
                            let promise = answer
                                .dyn_into::<js_sys::Promise>()
                                .map_err(|_| Errno::EIO)?;
                            let val = JsFuture::from(promise)
                                .await
                                .map_err(|e| errno_from_js(&e))?;
                            let bytes = js_sys::Uint8Array::new(&val);
                            let len = bytes.length() as usize;
                            if len != expected_len {
                                return Err(Errno::EIO);
                            }
                            let mut out = vec![0u8; len];
                            bytes.copy_to(&mut out);
                            Ok(out)
                        })
                    })
                    .await;
                }
                let args = js_sys::Array::new_with_length(4);
                args.set(0, JsValue::from_str(blob_id));
                args.set(1, JsValue::from_f64(offset as f64));
                args.set(2, JsValue::from_f64(buf.len() as f64));
                args.set(3, JsValue::UNDEFINED);
                let answer = reader
                    .apply(&global, &args)
                    .map_err(|e| errno_from_js(&e))?;
                let promise = answer
                    .dyn_into::<js_sys::Promise>()
                    .map_err(|_| Errno::EIO)?;
                let val = JsFuture::from(promise)
                    .await
                    .map_err(|e| errno_from_js(&e))?;
                let bytes = js_sys::Uint8Array::new(&val);
                let len = bytes.length() as usize;
                // Fail closed if host returns more bytes than requested.
                if len > buf.len() {
                    return Err(Errno::EIO);
                }
                bytes.copy_to(&mut buf[..len]);
                return Ok(len);
            }
            // Headless unit test fallback for unsigned local build assets only.
            // Verified Release v2 reads MUST fail closed if no pager is installed.
            if manifest.is_some() {
                return Err(Errno::EIO);
            }
            if offset >= WASM_HEADER_STUB.len() as u64 {
                return Ok(0);
            }
            let start = offset as usize;
            let n = (WASM_HEADER_STUB.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&WASM_HEADER_STUB[start..start + n]);
            Ok(n)
        })
    }
}

/// Pure-Rust chunk verifier used by both native tests and defense-in-depth checks.
pub fn verify_chunk_bytes(
    manifest: &ChunkManifest,
    chunk_index: usize,
    bytes: &[u8],
) -> vfs::Result<()> {
    let cs = u64::from(manifest.chunk_size);
    let expected_digest = manifest.chunks.get(chunk_index).ok_or(Errno::EINVAL)?;
    let start = (chunk_index as u64).checked_mul(cs).ok_or(Errno::EINVAL)?;
    if start >= manifest.size {
        return Err(Errno::EINVAL);
    }
    let expected_len = manifest.size.saturating_sub(start).min(cs) as usize;
    if bytes.len() != expected_len {
        return Err(Errno::EIO);
    }
    let actual = image::hex(&Sha256::digest(bytes));
    if actual != *expected_digest {
        return Err(Errno::EIO);
    }
    Ok(())
}

fn verify_bundle_core(
    release_bytes: &[u8],
    release_sig: &[u8],
    trust_bytes: &[u8],
    images: &[(Vec<u8>, Vec<u8>)],
) -> std::result::Result<serde_json::Value, image::Error> {
    let trust: Trust = image::parse(trust_bytes)?;
    let release_id = image::digest(release_bytes);
    let signer = trust.verify(SIGNING_DOMAIN_RELEASE_V2, release_bytes, release_sig)?;
    let release = ReleaseV2::parse(release_bytes)?;
    let expected_ids: Vec<&str> = release.images().collect();
    if images.len() != expected_ids.len() {
        return Err(image::Error("release image count mismatch".into()));
    }
    let mut parsed_images = Vec::with_capacity(images.len());
    for (idx, ((img_bytes, img_sig), expected_id)) in
        images.iter().zip(expected_ids.iter()).enumerate()
    {
        if image::digest(img_bytes) != *expected_id {
            return Err(image::Error("image manifest digest mismatch".into()));
        }
        trust.verify(SIGNING_DOMAIN_IMAGE_V2, img_bytes, img_sig)?;
        let img = Image::parse(img_bytes)?;
        let expected_kind = match idx {
            0 => Kind::Boot,
            1 => Kind::Initramfs,
            2 => Kind::RootTemplate,
            3 => Kind::Base,
            n if n < 4 + release.sysext.len() => Kind::Sysext,
            _ => Kind::Confext,
        };
        if img.kind != expected_kind {
            return Err(image::Error("release image kind mismatch".into()));
        }
        parsed_images.push(img);
    }
    release.verify_boot_loader(&parsed_images[0])?;
    let initramfs_comp = Composition::standalone(&parsed_images[1])?;
    let _root_template_comp = Composition::standalone(&parsed_images[2])?;
    let sys_comp = Composition::new(&parsed_images[3], &parsed_images[4..])?;

    let mut initramfs_bins = Vec::new();
    for required in ReleaseV2::REQUIRED_INITRAMFS_BINS {
        let resolved = initramfs_comp.resolve(required)?;
        initramfs_bins.push(json!({ "path": required, "resolved": resolved }));
    }
    Ok(json!({
        "id": release_id,
        "name": release.name,
        "version": release.version,
        "signer": signer,
        "boot": release.boot,
        "initramfs": release.initramfs,
        "root_template": release.root_template,
        "base": release.base,
        "sysext": release.sysext,
        "confext": release.confext,
        "initramfs_bins": initramfs_bins,
        "composition_entries": sys_comp.entries.len(),
    }))
}

fn js_err(msg: impl Into<String>) -> JsValue {
    js_sys::Error::new(&msg.into()).into()
}

fn read_string_array(val: &JsValue, label: &str) -> std::result::Result<Vec<Vec<u8>>, JsValue> {
    let arr = js_sys::Array::from(val);
    let mut out = Vec::with_capacity(arr.length() as usize);
    for i in 0..arr.length() {
        let item = arr.get(i);
        if let Some(s) = item.as_string() {
            out.push(s.into_bytes());
        } else if item.is_instance_of::<js_sys::Uint8Array>() {
            out.push(js_sys::Uint8Array::new(&item).to_vec());
        } else {
            return Err(js_err(format!("{label}[{i}] must be string or Uint8Array")));
        }
    }
    Ok(out)
}

/// Offline Stage 0 Release v2 cryptographic & structural verifier executed inside `client_kernel_bg.wasm`.
#[wasm_bindgen]
pub fn verify_release_v2_bundle(
    release_json: &str,
    release_sig: &str,
    trust_json: &str,
    images_json: JsValue,
    images_sig: JsValue,
) -> std::result::Result<JsValue, JsValue> {
    let imgs = read_string_array(&images_json, "images_json")?;
    let sigs = read_string_array(&images_sig, "images_sig")?;
    if imgs.len() != sigs.len() {
        return Err(js_err("images_json and images_sig length mismatch"));
    }
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = imgs.into_iter().zip(sigs).collect();
    let summary = verify_bundle_core(
        release_json.as_bytes(),
        release_sig.as_bytes(),
        trust_json.as_bytes(),
        &pairs,
    )
    .map_err(|e| js_err(e.to_string()))?;
    let text = serde_json::to_string(&summary).map_err(|e| js_err(e.to_string()))?;
    js_sys::JSON::parse(&text)
}

/// Convert a verified `os_image::Image` into `os_vfs::imagefs::ImageEntry` records.
pub fn image_to_vfs_entries(img: &Image) -> Vec<ImageEntry> {
    img.entries
        .iter()
        .map(|e| ImageEntry {
            path: e.path.clone(),
            uid: e.uid,
            gid: e.gid,
            mode: e.mode,
            node: match &e.node {
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
            },
        })
        .collect()
}

/// Compose a verified `Kind::Base` image with optional `Kind::Sysext` / `Kind::Confext` layers
/// and return the merged `ImageEntry` list for mounting `/sysroot/usr` in Stage 2.
pub fn compose_system_image_entries(
    base: &Image,
    extensions: &[Image],
) -> std::result::Result<Vec<ImageEntry>, image::Error> {
    let comp = Composition::new(base, extensions)?;
    Ok(comp
        .entries
        .values()
        .map(|e| ImageEntry {
            path: e.path.clone(),
            uid: e.uid,
            gid: e.gid,
            mode: e.mode,
            node: match &e.node {
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
            },
        })
        .collect())
}

/// Read an entire verified file from `blobs` using chunk-verified streaming (`<= 1 MiB` per chunk)
/// and verify its exact total byte length before returning.
pub async fn read_verified_image_file<B: BlobStore>(
    blobs: &B,
    sha256: &str,
    size: u64,
    chunk_size: u32,
    chunks: &[String],
) -> vfs::Result<Vec<u8>> {
    let manifest = ChunkManifest {
        sha256: sha256.to_string(),
        size,
        chunk_size,
        chunks: chunks.to_vec(),
    };
    let total = usize::try_from(size).map_err(|_| Errno::EFBIG)?;
    if total == 0 {
        return Ok(Vec::new());
    }
    let mut out = vec![0u8; total];
    let mut offset = 0usize;
    while offset < total {
        let step = (total - offset).min(chunk_size as usize);
        let n = blobs
            .read_verified_at(
                sha256,
                Some(&manifest),
                offset as u64,
                &mut out[offset..offset + step],
            )
            .await?;
        if n == 0 {
            return Err(Errno::EIO);
        }
        offset += n;
    }
    Ok(out)
}

/// Mounts a verified Stage 1 `Kind::Initramfs` image into `os_vfs::ImageFs<VerifiedAssetBlobStore>`
/// and verifies reading every required Stage 1 binary (`/init`, `/bin/mount`, `/bin/switch_root`,
/// `/bin/cowfsck`, `/bin/sh`) through `VerifiedAssetBlobStore::read_verified_at` -> `self.imageBlobRead`.
#[wasm_bindgen]
pub async fn boot_stage1_initramfs(
    initramfs_json: String,
) -> std::result::Result<JsValue, JsValue> {
    let img = Image::parse(initramfs_json.as_bytes()).map_err(|e| js_err(e.to_string()))?;
    if img.kind != Kind::Initramfs {
        return Err(js_err("expected initramfs image"));
    }
    let comp = Composition::standalone(&img).map_err(|e| js_err(e.to_string()))?;
    let entries = image_to_vfs_entries(&img);
    let fs = ImageFs::new(
        FsId("image:initramfs".into()),
        true,
        Timespec::default(),
        entries,
        VerifiedAssetBlobStore,
    )
    .map_err(|e| js_err(format!("initramfs mount failed: {e:?}")))?;
    let cred = Cred::root();
    let mut verified_bins = Vec::new();
    for required in ReleaseV2::REQUIRED_INITRAMFS_BINS {
        let resolved = comp
            .resolve(required)
            .map_err(|e| js_err(format!("resolve {required}: {e}")))?;
        let handle = fs
            .handle_at(&resolved)
            .ok_or_else(|| js_err(format!("missing initramfs handle: {resolved}")))?;
        let manifest = fs
            .chunk_manifest_at(&resolved)
            .cloned()
            .ok_or_else(|| js_err(format!("missing chunk manifest: {resolved}")))?;
        let mut read_opts = OpenOptions::new();
        read_opts.read(true);
        let open = fs
            .open(&cred, &handle, &read_opts)
            .await
            .map_err(|e| js_err(format!("open {resolved}: {e:?}")))?;
        let mut header = [0u8; 8];
        let n = fs
            .read_at(&open, &mut header, 0)
            .await
            .map_err(|e| js_err(format!("read {resolved}: {e:?}")))?;
        let _ = fs.release(&open).await;
        if n < 8 || header != WASM_HEADER_STUB {
            return Err(js_err(format!(
                "invalid Wasm magic for Stage 1 binary {required} ({resolved})"
            )));
        }
        verified_bins.push(json!({
            "path": required,
            "resolved": resolved,
            "size": manifest.size,
            "sha256": manifest.sha256,
            "chunk_size": manifest.chunk_size,
            "chunks": manifest.chunks.len(),
            "wasm": true,
        }));
    }
    let summary = json!({
        "stage": 1,
        "kind": "initramfs",
        "binaries": verified_bins,
    });
    let text = serde_json::to_string(&summary).map_err(|e| js_err(e.to_string()))?;
    js_sys::JSON::parse(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{CHUNK_SIZE_MIN, chunk_digests, digest};

    #[test]
    fn verify_chunk_bytes_accepts_valid_and_rejects_tampered_or_truncated() {
        let mut payload = vec![0u8; CHUNK_SIZE_MIN as usize + 512];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let manifest = ChunkManifest {
            sha256: digest(&payload),
            size: payload.len() as u64,
            chunk_size: CHUNK_SIZE_MIN,
            chunks: chunk_digests(&payload, CHUNK_SIZE_MIN).unwrap(),
        };
        assert_eq!(
            verify_chunk_bytes(&manifest, 0, &payload[..CHUNK_SIZE_MIN as usize]),
            Ok(())
        );
        assert_eq!(
            verify_chunk_bytes(&manifest, 1, &payload[CHUNK_SIZE_MIN as usize..]),
            Ok(())
        );
        // Flip 1 byte -> EIO
        let mut flipped = payload[CHUNK_SIZE_MIN as usize..].to_vec();
        flipped[17] ^= 0x01;
        assert_eq!(verify_chunk_bytes(&manifest, 1, &flipped), Err(Errno::EIO));
        // Truncated -> EIO
        assert_eq!(
            verify_chunk_bytes(
                &manifest,
                1,
                &payload[CHUNK_SIZE_MIN as usize..payload.len() - 1]
            ),
            Err(Errno::EIO)
        );
        // Out of range chunk index -> EINVAL
        assert_eq!(verify_chunk_bytes(&manifest, 2, &[]), Err(Errno::EINVAL));
    }

    #[test]
    fn read_verified_chunks_verifies_subchunk_and_rejects_short_or_tampered_reads() {
        let mut payload = vec![0u8; CHUNK_SIZE_MIN as usize + 512];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = ((i * 19 + 3) & 0xff) as u8;
        }
        let manifest = ChunkManifest {
            sha256: digest(&payload),
            size: payload.len() as u64,
            chunk_size: CHUNK_SIZE_MIN,
            chunks: chunk_digests(&payload, CHUNK_SIZE_MIN).unwrap(),
        };

        // 1. Sub-chunk 8-byte probe at offset 0 verifies the ENTIRE chunk 0.
        let mut header = [0u8; 8];
        let n = vfs::now_or_never(read_verified_chunks(
            &manifest,
            0,
            &mut header,
            |c_start, len| {
                let slice = payload[c_start as usize..c_start as usize + len].to_vec();
                Box::pin(async move { Ok(slice) })
            },
        ))
        .unwrap()
        .unwrap();
        assert_eq!(n, 8);
        assert_eq!(&header, &payload[..8]);

        // 2. Flipping a byte in the tail of chunk 0 (outside the 8-byte slice) fails EIO!
        let mut tampered = payload.clone();
        tampered[CHUNK_SIZE_MIN as usize - 1] ^= 0x01;
        let mut probe = [0xCCu8; 8];
        let res = vfs::now_or_never(read_verified_chunks(
            &manifest,
            0,
            &mut probe,
            |c_start, len| {
                let slice = tampered[c_start as usize..c_start as usize + len].to_vec();
                Box::pin(async move { Ok(slice) })
            },
        ))
        .unwrap();
        assert_eq!(res, Err(Errno::EIO));

        // 3. Cross-chunk read splices accurately; corrupted chunk 1 zeroes prefix and fails EIO.
        let mut cross = [0u8; 32];
        let n_cross = vfs::now_or_never(read_verified_chunks(
            &manifest,
            u64::from(CHUNK_SIZE_MIN) - 16,
            &mut cross,
            |c_start, len| {
                let slice = payload[c_start as usize..c_start as usize + len].to_vec();
                Box::pin(async move { Ok(slice) })
            },
        ))
        .unwrap()
        .unwrap();
        assert_eq!(n_cross, 32);
        assert_eq!(
            &cross,
            &payload[CHUNK_SIZE_MIN as usize - 16..CHUNK_SIZE_MIN as usize + 16]
        );

        let mut bad_c1 = payload.clone();
        bad_c1[CHUNK_SIZE_MIN as usize + 100] ^= 0x40;
        let mut cross_bad = [0xEEu8; 32];
        let res_bad = vfs::now_or_never(read_verified_chunks(
            &manifest,
            u64::from(CHUNK_SIZE_MIN) - 16,
            &mut cross_bad,
            |c_start, len| {
                let slice = bad_c1[c_start as usize..c_start as usize + len].to_vec();
                Box::pin(async move { Ok(slice) })
            },
        ))
        .unwrap();
        assert_eq!(res_bad, Err(Errno::EIO));
        assert!(cross_bad[..16].iter().all(|&b| b == 0));

        // 4. Short read or 0-byte read when offset < manifest.size returns Err(Errno::EIO), NEVER Ok(0).
        let mut short_buf = [0u8; 16];
        let res_zero = vfs::now_or_never(read_verified_chunks(
            &manifest,
            0,
            &mut short_buf,
            |_c_start, _len| Box::pin(async move { Ok(Vec::new()) }),
        ))
        .unwrap();
        assert_eq!(res_zero, Err(Errno::EIO));

        let res_short = vfs::now_or_never(read_verified_chunks(
            &manifest,
            0,
            &mut short_buf,
            |c_start, len| {
                let slice = payload[c_start as usize..c_start as usize + len - 1].to_vec();
                Box::pin(async move { Ok(slice) })
            },
        ))
        .unwrap();
        assert_eq!(res_short, Err(Errno::EIO));
    }
}
