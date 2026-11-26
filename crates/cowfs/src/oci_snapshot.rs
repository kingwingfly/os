//! Native `cowfs` Snapshot Artifact v1 (`application/vnd.os.cowfs.snapshot.v1`) over the shared
//! immutable `COWP` pack store (`docs/architecture/contract.md` §2.15; #81).
//!
//! - Zero byte-format conversion: `COWP` packs are pushed and pulled verbatim as OCI blobs whose
//!   digest `sha256:<pack_id>` equals their `cowfs` `PackId`.
//! - Deterministic binary `NodePack` (`COWNP1\0\0`) and `BlockDir` (`COWBD1\0\0`) enable lazy
//!   read-only mounting with **zero `COWP` data packs fetched at mount** and bounded `<= 1 MiB`
//!   SHA-256-verified HTTP `Range` reads.
//! - Large volumes shard automatically into an OCI Image Index (`application/vnd.oci.image.index.v1+json`)
//!   of self-contained shard manifests with zero origin hostnames or external URLs.

use crate::fs::{AsyncMutex, CowFs, CowFsConfig, CowFsOpenMode};
use crate::inode::ExtentDataValue;
use crate::oci_client::{OciClient, OciTransport, verify_ed25519_referrers};
use abi::Errno;
use abi::contract::{Durability, WriterModel};
use abi::fs::Timespec;
use abi::registry::{
    COWFS_BLOCKDIR_LAYER_MEDIA_TYPE, COWFS_NODEPACK_LAYER_MEDIA_TYPE, COWFS_PACK_LAYER_MEDIA_TYPE,
    COWFS_SNAPSHOT_ARTIFACT_TYPE, COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE,
    COWFS_SNAPSHOT_SHARD_ARTIFACT_TYPE, CowfsOciPullResp, CowfsOciPushResp, CowfsSnapshotConfig,
    OCI_IMAGE_INDEX_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE, OciDescriptor, OciImageIndex,
    OciImageManifest, parse_sha256_digest,
};
use cowtree::pack::{
    PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer, decode_pack_trailer_bytes,
    verify_block_digest,
};
use cowtree::{
    BlockLoc, COWFS_FORMAT_VERSION, CommitRequest, Digest, EXTENT_MAX_BYTES, ForkRequest,
    GcLockGuard, GcRoot, HeadStore, KIND_EXTENT_DATA, NODE_MAX_BYTES, Node, PACK_MAX_BYTES, PackId,
    PackMeta, PackStore, PackTrailer, ReceiveCommitRequest, RoPinGuard, RootObject, SnapshotRecord,
    VolumeHead, VolumeId, WriterLease, WriterMode, digest_from_hex, digest_to_hex, sha256,
};
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use vfs::{BoxFuture, Result};

/// Magic header for `NodePack` blobs (`application/vnd.os.cowfs.nodepack.v1`).
pub const NODEPACK_MAGIC: [u8; 8] = *b"COWNP1\0\0";
/// Magic header for `BlockDir` blobs (`application/vnd.os.cowfs.blockdir.v1`).
pub const BLOCKDIR_MAGIC: [u8; 8] = *b"COWBD1\0\0";
pub const SNAPSHOT_ARTIFACT_FORMAT: &str = "os.cowfs.snapshot";
pub const SNAPSHOT_ARTIFACT_VERSION: u32 = 1;
const NODEPACK_MAX_SHARD_BYTES: usize = 4 * 1024 * 1024;
const BLOCKDIR_MAX_SHARD_BYTES: usize = 4 * 1024 * 1024;

/// Configuration for [`push_cowfs_snapshot`].
#[derive(Clone, Debug)]
pub struct OciPushOptions {
    /// Maximum `COWP` pack layers per shard manifest (default `128`).
    pub max_layers_per_shard: usize,
    /// Emit an OCI Image Index even if all packs fit in a single shard.
    pub force_index: bool,
    /// Optional extra annotations merged into the top-level manifest/index so staged kubelet
    /// attempts receive an attempt-unique manifest digest while `COWP` packs stay deduplicated.
    pub extra_annotations: BTreeMap<String, String>,
}

impl Default for OciPushOptions {
    fn default() -> Self {
        Self {
            max_layers_per_shard: 128,
            force_index: false,
            extra_annotations: BTreeMap::new(),
        }
    }
}

/// Encode `(digest, raw_node_bytes)` pairs into one or more deterministic `<= 4 MiB` `COWNP1\0\0`
/// `NodePack` shards with entries sorted strictly ascending by digest.
pub fn encode_nodepacks(mut nodes: Vec<(Digest, Vec<u8>)>) -> Result<Vec<Vec<u8>>> {
    nodes.sort_by_key(|a| a.0);
    nodes.dedup_by(|a, b| a.0 == b.0);
    let mut shards: Vec<Vec<u8>> = Vec::new();
    let mut batch: Vec<(Digest, Vec<u8>)> = Vec::new();
    let mut cur_len = 8 + 2 + 4;
    for (digest, bytes) in nodes {
        if bytes.len() > NODE_MAX_BYTES {
            return Err(Errno::EFBIG);
        }
        let entry_len = 32 + 4 + bytes.len();
        if !batch.is_empty() && cur_len + entry_len > NODEPACK_MAX_SHARD_BYTES {
            shards.push(encode_single_nodepack(&batch)?);
            batch.clear();
            cur_len = 8 + 2 + 4;
        }
        batch.push((digest, bytes));
        cur_len += entry_len;
    }
    if !batch.is_empty() || shards.is_empty() {
        shards.push(encode_single_nodepack(&batch)?);
    }
    Ok(shards)
}

fn encode_single_nodepack(entries: &[(Digest, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&NODEPACK_MAGIC);
    out.extend_from_slice(&1u16.to_be_bytes());
    let count = u32::try_from(entries.len()).map_err(|_| Errno::EFBIG)?;
    out.extend_from_slice(&count.to_be_bytes());
    for (digest, bytes) in entries {
        let len = u32::try_from(bytes.len()).map_err(|_| Errno::EFBIG)?;
        out.extend_from_slice(digest);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

/// Decode and SHA-256-verify a `COWNP1\0\0` `NodePack` blob.
pub fn decode_nodepack(bytes: &[u8]) -> Result<Vec<(Digest, Vec<u8>)>> {
    if bytes.len() < 14 || bytes[0..8] != NODEPACK_MAGIC {
        return Err(Errno::EIO);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != 1 {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let count = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let mut cursor = 14usize;
    let mut out = Vec::with_capacity(count.min(4096));
    let mut prev: Option<Digest> = None;
    for _ in 0..count {
        let entry_hdr_end = cursor.checked_add(36).ok_or(Errno::EIO)?;
        if entry_hdr_end > bytes.len() {
            return Err(Errno::EIO);
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        if let Some(p) = prev
            && digest <= p
        {
            return Err(Errno::EIO);
        }
        prev = Some(digest);
        let len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let data_end = cursor.checked_add(len).ok_or(Errno::EIO)?;
        if len > NODE_MAX_BYTES || data_end > bytes.len() {
            return Err(Errno::EIO);
        }
        let raw = bytes[cursor..data_end].to_vec();
        cursor = data_end;
        if sha256(&raw) != digest {
            return Err(Errno::EIO);
        }
        out.push((digest, raw));
    }
    if cursor != bytes.len() {
        return Err(Errno::EIO);
    }
    Ok(out)
}

/// Encode `(block_digest, BlockLoc)` entries into one or more deterministic `<= 4 MiB` `COWBD1\0\0`
/// `BlockDir` shards with entries sorted strictly ascending by `block_digest`.
pub fn encode_blockdirs(
    pack_ids: &[Digest],
    mut entries: Vec<(Digest, u32, u32, u32)>,
) -> Result<Vec<Vec<u8>>> {
    entries.sort_by_key(|a| a.0);
    entries.dedup_by(|a, b| a.0 == b.0);
    let header_len = 8 + 2 + 4 + pack_ids.len() * 32 + 4;
    if header_len >= BLOCKDIR_MAX_SHARD_BYTES {
        return Err(Errno::EFBIG);
    }
    let max_entries_per_shard = ((BLOCKDIR_MAX_SHARD_BYTES - header_len) / 44).max(1);
    if entries.is_empty() {
        return Ok(vec![encode_single_blockdir(pack_ids, &[])?]);
    }
    let mut shards = Vec::new();
    for chunk in entries.chunks(max_entries_per_shard) {
        shards.push(encode_single_blockdir(pack_ids, chunk)?);
    }
    Ok(shards)
}

fn encode_single_blockdir(
    pack_ids: &[Digest],
    entries: &[(Digest, u32, u32, u32)],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(18 + pack_ids.len() * 32 + entries.len() * 44);
    out.extend_from_slice(&BLOCKDIR_MAGIC);
    out.extend_from_slice(&1u16.to_be_bytes());
    let pcount = u32::try_from(pack_ids.len()).map_err(|_| Errno::EFBIG)?;
    out.extend_from_slice(&pcount.to_be_bytes());
    for pid in pack_ids {
        out.extend_from_slice(pid);
    }
    let ecount = u32::try_from(entries.len()).map_err(|_| Errno::EFBIG)?;
    out.extend_from_slice(&ecount.to_be_bytes());
    for (bdig, pack_idx, offset, len) in entries {
        out.extend_from_slice(bdig);
        out.extend_from_slice(&pack_idx.to_be_bytes());
        out.extend_from_slice(&offset.to_be_bytes());
        out.extend_from_slice(&len.to_be_bytes());
    }
    Ok(out)
}

/// Decode a `COWBD1\0\0` `BlockDir` blob into `(block_digest, BlockLoc)` mappings.
pub fn decode_blockdir(bytes: &[u8]) -> Result<Vec<(Digest, BlockLoc)>> {
    if bytes.len() < 18 || bytes[0..8] != BLOCKDIR_MAGIC {
        return Err(Errno::EIO);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != 1 {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let pack_count = u32::from_be_bytes([bytes[10], bytes[11], bytes[12], bytes[13]]) as usize;
    let mut cursor = 14usize;
    let packs_bytes = pack_count.checked_mul(32).ok_or(Errno::EIO)?;
    let packs_end = cursor
        .checked_add(packs_bytes)
        .and_then(|v| v.checked_add(4))
        .ok_or(Errno::EIO)?;
    if packs_end > bytes.len() {
        return Err(Errno::EIO);
    }
    let mut pack_ids = Vec::with_capacity(pack_count);
    for _ in 0..pack_count {
        let mut d = [0u8; 32];
        d.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        pack_ids.push(PackId(digest_to_hex(&d)));
    }
    let entry_count = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
    cursor += 4;
    let entries_bytes = entry_count.checked_mul(44).ok_or(Errno::EIO)?;
    if cursor.checked_add(entries_bytes) != Some(bytes.len()) {
        return Err(Errno::EIO);
    }
    let mut out = Vec::with_capacity(entry_count.min(4096));
    let mut prev: Option<Digest> = None;
    for _ in 0..entry_count {
        let mut bdig = [0u8; 32];
        bdig.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;
        if let Some(p) = prev
            && bdig <= p
        {
            return Err(Errno::EIO);
        }
        prev = Some(bdig);
        let pack_idx = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        let offset = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let len = u32::from_be_bytes(bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let pack_id = pack_ids.get(pack_idx).ok_or(Errno::EIO)?.clone();
        let loc = BlockLoc {
            pack_id,
            offset,
            len,
            raw_len: len,
            flags: 0,
        };
        loc.validate_v1()?;
        out.push((bdig, loc));
    }
    Ok(out)
}

async fn upload_blob_if_missing<T: OciTransport>(
    client: &OciClient<T>,
    repo: &str,
    bytes: &[u8],
) -> Result<(String, u64, bool)> {
    let digest = format!("sha256:{}", digest_to_hex(&sha256(bytes)));
    let size = bytes.len() as u64;
    if client.head_blob(repo, &digest).await?.is_some() {
        return Ok((digest, size, false));
    }
    client.put_blob_monolithic(repo, &digest, bytes).await?;
    Ok((digest, size, true))
}

/// Push a pinned `cowfs` volume head or named snapshot to an OCI Distribution v1.1 registry
/// as a zero-conversion `application/vnd.os.cowfs.snapshot.v1` artifact (single manifest or
/// sharded OCI Image Index).
#[allow(clippy::too_many_arguments)]
pub async fn push_cowfs_snapshot<H: HeadStore, P: PackStore, T: OciTransport>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
    snapshot: Option<&str>,
    client: &OciClient<T>,
    repo: &str,
    reference: &str,
    opts: OciPushOptions,
) -> Result<CowfsOciPushResp> {
    push_cowfs_snapshot_pinned(
        head_store, pack_store, volume, None, snapshot, client, repo, reference, opts,
    )
    .await
}

/// Push a `cowfs` volume or snapshot with an optional pinned read-only [`VolumeHead`].
#[allow(clippy::too_many_arguments)]
pub async fn push_cowfs_snapshot_pinned<H: HeadStore, P: PackStore, T: OciTransport>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
    exact_head: Option<&VolumeHead>,
    snapshot: Option<&str>,
    client: &OciClient<T>,
    repo: &str,
    reference: &str,
    opts: OciPushOptions,
) -> Result<CowfsOciPushResp> {
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let _gc = head_store.acquire_gc_lock(false).await?;
    let (head, pin) = head_store.pin_view(volume, snapshot, exact_head).await?;
    let res = push_pinned_snapshot(
        head_store, pack_store, volume, head.root, client, repo, reference, opts,
    )
    .await;
    if let Some(p) = pin {
        let _ = head_store.unpin_ro_root(p).await;
    }
    res
}

#[allow(clippy::too_many_arguments)]
async fn push_pinned_snapshot<H: HeadStore, P: PackStore, T: OciTransport>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
    root_digest: Digest,
    client: &OciClient<T>,
    repo: &str,
    reference: &str,
    opts: OciPushOptions,
) -> Result<CowfsOciPushResp> {
    let raw_root = head_store.get_node(&root_digest).await?;
    let root_obj = RootObject::decode_verified(&root_digest, &raw_root)?;

    let mut visited: HashSet<Digest> = HashSet::new();
    let mut nodes: Vec<(Digest, Vec<u8>)> = Vec::new();
    let mut blocks_by_pack: BTreeMap<PackId, Vec<(Digest, BlockLoc)>> = BTreeMap::new();
    let mut seen_blocks: HashSet<Digest> = HashSet::new();

    visited.insert(root_digest);
    nodes.push((root_digest, raw_root));

    for sv_root in root_obj.subvols.values() {
        let mut stack = vec![*sv_root];
        while let Some(d) = stack.pop() {
            if !visited.insert(d) {
                continue;
            }
            let raw = head_store.get_node(&d).await?;
            let node = Node::decode_verified(&d, &raw)?;
            nodes.push((d, raw));
            match node {
                Node::Internal { entries, .. } => {
                    for e in entries.into_iter().rev() {
                        if !visited.contains(&e.child) {
                            stack.push(e.child);
                        }
                    }
                }
                Node::Leaf { entries } => {
                    for e in entries {
                        if e.key.kind != KIND_EXTENT_DATA {
                            continue;
                        }
                        if let ExtentDataValue::Extent { digest: bdig, .. } =
                            ExtentDataValue::decode(&e.value)?
                            && seen_blocks.insert(bdig)
                        {
                            let loc = head_store.lookup_block(&bdig).await?.ok_or(Errno::EIO)?;
                            loc.validate_v1()?;
                            blocks_by_pack
                                .entry(loc.pack_id.clone())
                                .or_default()
                                .push((bdig, loc));
                        }
                    }
                }
            }
        }
    }

    let node_count = nodes.len() as u64;
    let nodepack_blobs = encode_nodepacks(nodes)?;
    let all_pack_ids: Vec<PackId> = blocks_by_pack.keys().cloned().collect();
    let max_packs = opts.max_layers_per_shard.max(1);

    let subvols_map: BTreeMap<String, String> = root_obj
        .subvols
        .iter()
        .map(|(k, v)| (k.clone(), digest_to_hex(v)))
        .collect();

    // Partition packs into shards (each shard has <= `max_packs` raw COWP pack layers).
    let pack_chunks: Vec<&[PackId]> = if all_pack_ids.is_empty() {
        vec![&[]]
    } else {
        all_pack_ids.chunks(max_packs).collect()
    };
    let use_index = opts.force_index || pack_chunks.len() > 1;
    let shard_count = pack_chunks.len() as u32;

    let mut packs_pushed = 0u64;
    let mut bytes_pushed = 0u64;
    let mut shard_descriptors: Vec<OciDescriptor> = Vec::with_capacity(pack_chunks.len());
    let mut single_manifest_bytes: Option<Vec<u8>> = None;

    for (idx, chunk) in pack_chunks.iter().enumerate() {
        let mut layers: Vec<OciDescriptor> = Vec::new();
        let mut shard_bytes = 0u64;

        // Shard 0 carries all NodePack layers (tree nodes + RootObject).
        if idx == 0 {
            for np in &nodepack_blobs {
                let (digest, size, uploaded) = upload_blob_if_missing(client, repo, np).await?;
                if uploaded {
                    bytes_pushed = bytes_pushed.saturating_add(size);
                }
                shard_bytes = shard_bytes.saturating_add(size);
                layers.push(OciDescriptor {
                    media_type: COWFS_NODEPACK_LAYER_MEDIA_TYPE.into(),
                    digest,
                    size,
                    urls: None,
                    annotations: None,
                    artifact_type: None,
                    platform: None,
                    data: None,
                });
            }
        }

        // Build BlockDir covering this shard's packs.
        let mut shard_pack_digests: Vec<Digest> = Vec::with_capacity(chunk.len());
        let mut shard_block_entries: Vec<(Digest, u32, u32, u32)> = Vec::new();
        for (pi, pid) in chunk.iter().enumerate() {
            let p_dig = digest_from_hex(&pid.0)?;
            shard_pack_digests.push(p_dig);
            if let Some(blks) = blocks_by_pack.get(pid) {
                for (bdig, loc) in blks {
                    shard_block_entries.push((*bdig, pi as u32, loc.offset, loc.len));
                }
            }
        }
        let blockdir_blobs = encode_blockdirs(&shard_pack_digests, shard_block_entries)?;
        for bd in &blockdir_blobs {
            let (digest, size, uploaded) = upload_blob_if_missing(client, repo, bd).await?;
            if uploaded {
                bytes_pushed = bytes_pushed.saturating_add(size);
            }
            shard_bytes = shard_bytes.saturating_add(size);
            layers.push(OciDescriptor {
                media_type: COWFS_BLOCKDIR_LAYER_MEDIA_TYPE.into(),
                digest,
                size,
                urls: None,
                annotations: None,
                artifact_type: None,
                platform: None,
                data: None,
            });
        }

        // Push raw immutable COWP packs directly (ZERO byte-format conversion!).
        for pid in *chunk {
            let expected_digest = format!("sha256:{}", pid.0);
            let pack_len = pack_store.stat_pack(pid).await?.ok_or(Errno::EIO)?;
            if pack_len > PACK_MAX_BYTES as u64 {
                return Err(Errno::EFBIG);
            }
            let size = if let Some(remote_len) = client.head_blob(repo, &expected_digest).await? {
                if remote_len != pack_len {
                    return Err(Errno::EIO);
                }
                remote_len
            } else {
                let raw_pack = pack_store.read_pack_range(pid, 0, pack_len as u32).await?;
                if digest_to_hex(&sha256(&raw_pack)) != pid.0 {
                    return Err(Errno::EIO);
                }
                let _ = decode_pack_trailer(&raw_pack)?;
                client
                    .put_blob_monolithic(repo, &expected_digest, &raw_pack)
                    .await?;
                packs_pushed = packs_pushed.saturating_add(1);
                bytes_pushed = bytes_pushed.saturating_add(raw_pack.len() as u64);
                raw_pack.len() as u64
            };
            shard_bytes = shard_bytes.saturating_add(size);
            layers.push(OciDescriptor {
                media_type: COWFS_PACK_LAYER_MEDIA_TYPE.into(),
                digest: expected_digest,
                size,
                urls: None,
                annotations: None,
                artifact_type: None,
                platform: None,
                data: None,
            });
        }

        let cfg = CowfsSnapshotConfig {
            format: SNAPSHOT_ARTIFACT_FORMAT.into(),
            version: SNAPSHOT_ARTIFACT_VERSION,
            cowfs_format_version: COWFS_FORMAT_VERSION,
            volume_uuid: volume.0.clone(),
            root_digest: digest_to_hex(&root_digest),
            subvols: subvols_map.clone(),
            shard_index: idx as u32,
            shard_count,
            node_count: if idx == 0 { node_count } else { 0 },
            pack_count: chunk.len() as u64,
            total_bytes: shard_bytes,
        };
        let cfg_bytes = serde_json::to_vec(&cfg).map_err(|_| Errno::EIO)?;
        let (cfg_digest, cfg_size, cfg_uploaded) =
            upload_blob_if_missing(client, repo, &cfg_bytes).await?;
        if cfg_uploaded {
            bytes_pushed = bytes_pushed.saturating_add(cfg_size);
        }

        let manifest = OciImageManifest {
            schema_version: 2,
            media_type: Some(OCI_IMAGE_MANIFEST_MEDIA_TYPE.into()),
            artifact_type: Some(if use_index {
                COWFS_SNAPSHOT_SHARD_ARTIFACT_TYPE.into()
            } else {
                COWFS_SNAPSHOT_ARTIFACT_TYPE.into()
            }),
            config: OciDescriptor {
                media_type: COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE.into(),
                digest: cfg_digest,
                size: cfg_size,
                urls: None,
                annotations: None,
                artifact_type: None,
                platform: None,
                data: None,
            },
            layers,
            subject: None,
            annotations: if !use_index && !opts.extra_annotations.is_empty() {
                Some(opts.extra_annotations.clone())
            } else {
                None
            },
        };
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| Errno::EIO)?;
        if use_index {
            let shard_digest = format!("sha256:{}", digest_to_hex(&sha256(&manifest_bytes)));
            let (pushed, _) = client
                .put_manifest(
                    repo,
                    &shard_digest,
                    OCI_IMAGE_MANIFEST_MEDIA_TYPE,
                    &manifest_bytes,
                )
                .await?;
            let mut ann = BTreeMap::new();
            ann.insert("org.os.cowfs.shard.index".into(), idx.to_string());
            ann.insert("org.os.cowfs.shard.count".into(), shard_count.to_string());
            shard_descriptors.push(OciDescriptor {
                media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.into(),
                digest: pushed,
                size: manifest_bytes.len() as u64,
                urls: None,
                annotations: Some(ann),
                artifact_type: Some(COWFS_SNAPSHOT_SHARD_ARTIFACT_TYPE.into()),
                platform: None,
                data: None,
            });
        } else {
            single_manifest_bytes = Some(manifest_bytes);
        }
    }

    if use_index {
        let mut ann = BTreeMap::new();
        ann.insert("org.os.cowfs.root".into(), digest_to_hex(&root_digest));
        ann.insert("org.os.cowfs.volume".into(), volume.0.clone());
        for (k, v) in &opts.extra_annotations {
            ann.insert(k.clone(), v.clone());
        }
        let index = OciImageIndex {
            schema_version: 2,
            media_type: Some(OCI_IMAGE_INDEX_MEDIA_TYPE.into()),
            artifact_type: Some(COWFS_SNAPSHOT_ARTIFACT_TYPE.into()),
            manifests: shard_descriptors,
            subject: None,
            annotations: Some(ann),
        };
        let index_bytes = serde_json::to_vec(&index).map_err(|_| Errno::EIO)?;
        let (digest, _) = client
            .put_manifest(repo, reference, OCI_IMAGE_INDEX_MEDIA_TYPE, &index_bytes)
            .await?;
        Ok(CowfsOciPushResp {
            repo: repo.into(),
            reference: reference.into(),
            manifest_digest: digest,
            media_type: OCI_IMAGE_INDEX_MEDIA_TYPE.into(),
            shards: shard_count,
            packs_pushed,
            bytes_pushed,
        })
    } else {
        let raw = single_manifest_bytes.ok_or(Errno::EIO)?;
        let (digest, _) = client
            .put_manifest(repo, reference, OCI_IMAGE_MANIFEST_MEDIA_TYPE, &raw)
            .await?;
        Ok(CowfsOciPushResp {
            repo: repo.into(),
            reference: reference.into(),
            manifest_digest: digest,
            media_type: OCI_IMAGE_MANIFEST_MEDIA_TYPE.into(),
            shards: 1,
            packs_pushed,
            bytes_pushed,
        })
    }
}

struct ResolvedSnapshot {
    manifest_digest: String,
    root_digest: Digest,
    volume_uuid: String,
    nodes: HashMap<Digest, Vec<u8>>,
    blocks: HashMap<Digest, BlockLoc>,
    pack_sizes: HashMap<PackId, u64>,
}

async fn resolve_snapshot_metadata<T: OciTransport>(
    client: &OciClient<T>,
    repo: &str,
    reference: &str,
) -> Result<ResolvedSnapshot> {
    let (top_digest, _top_mt, top_bytes) = client.get_manifest(repo, reference).await?;
    let val: serde_json::Value = os_image::parse(&top_bytes).map_err(|_| Errno::EIO)?;
    let obj = val.as_object().ok_or(Errno::EIO)?;

    let mut shard_manifests: Vec<OciImageManifest> = Vec::new();
    if obj.contains_key("manifests") {
        let index: OciImageIndex = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
        if index.artifact_type.as_deref() != Some(COWFS_SNAPSHOT_ARTIFACT_TYPE) {
            return Err(Errno::EINVAL);
        }
        if index.manifests.is_empty() {
            return Err(Errno::EIO);
        }
        for desc in &index.manifests {
            let (_d, _mt, raw) = client.get_manifest(repo, &desc.digest).await?;
            let m: OciImageManifest = os_image::parse(&raw).map_err(|_| Errno::EIO)?;
            shard_manifests.push(m);
        }
    } else if obj.contains_key("config") && obj.contains_key("layers") {
        let m: OciImageManifest = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
        if m.effective_artifact_type() != Some(COWFS_SNAPSHOT_ARTIFACT_TYPE)
            && m.config.media_type != COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE
        {
            return Err(Errno::EINVAL);
        }
        shard_manifests.push(m);
    } else {
        return Err(Errno::EINVAL);
    }

    let mut root_digest: Option<Digest> = None;
    let mut volume_uuid: Option<String> = None;
    let mut nodes: HashMap<Digest, Vec<u8>> = HashMap::new();
    let mut blocks: HashMap<Digest, BlockLoc> = HashMap::new();
    let mut pack_sizes: HashMap<PackId, u64> = HashMap::new();

    for manifest in &shard_manifests {
        if manifest.config.media_type != COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE {
            return Err(Errno::EINVAL);
        }
        let cfg_bytes = client.get_blob(repo, &manifest.config.digest).await?;
        let cfg: CowfsSnapshotConfig = os_image::parse(&cfg_bytes).map_err(|_| Errno::EIO)?;
        if cfg.format != SNAPSHOT_ARTIFACT_FORMAT || cfg.version != SNAPSHOT_ARTIFACT_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        if cfg.cowfs_format_version != COWFS_FORMAT_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let rd = digest_from_hex(&cfg.root_digest)?;
        if let Some(prev) = root_digest {
            if prev != rd {
                return Err(Errno::EIO);
            }
        } else {
            root_digest = Some(rd);
            volume_uuid = Some(cfg.volume_uuid);
        }

        for layer in &manifest.layers {
            match layer.media_type.as_str() {
                COWFS_NODEPACK_LAYER_MEDIA_TYPE => {
                    let raw = client.get_blob(repo, &layer.digest).await?;
                    for (d, node_bytes) in decode_nodepack(&raw)? {
                        nodes.insert(d, node_bytes);
                    }
                }
                COWFS_BLOCKDIR_LAYER_MEDIA_TYPE => {
                    let raw = client.get_blob(repo, &layer.digest).await?;
                    for (bdig, loc) in decode_blockdir(&raw)? {
                        blocks.insert(bdig, loc);
                    }
                }
                COWFS_PACK_LAYER_MEDIA_TYPE => {
                    // Metadata only! ZERO COWP data packs downloaded here!
                    let hex = parse_sha256_digest(&layer.digest).ok_or(Errno::EIO)?;
                    if layer.size > PACK_MAX_BYTES as u64 {
                        return Err(Errno::EFBIG);
                    }
                    pack_sizes.insert(PackId(hex.to_string()), layer.size);
                }
                _ => {}
            }
        }
    }

    let root_digest = root_digest.ok_or(Errno::EIO)?;
    let root_raw = nodes.get(&root_digest).ok_or(Errno::EIO)?;
    let _root_obj = RootObject::decode_verified(&root_digest, root_raw)?;
    // Verify every block location references a pack declared in the artifact.
    for loc in blocks.values() {
        let Some(&psize) = pack_sizes.get(&loc.pack_id) else {
            return Err(Errno::EIO);
        };
        if u64::from(loc.offset).saturating_add(u64::from(loc.len)) > psize {
            return Err(Errno::EIO);
        }
    }

    Ok(ResolvedSnapshot {
        manifest_digest: top_digest,
        root_digest,
        volume_uuid: volume_uuid.unwrap_or_else(|| format!("oci-{repo}")),
        nodes,
        blocks,
        pack_sizes,
    })
}

/// Pull a `cowfs` snapshot artifact from an OCI registry into a destination local or remote
/// `HeadStore`/`PackStore` with zero byte-format conversion, full Merkle verification, and
/// atomic head/snapshot publication.
#[allow(clippy::too_many_arguments)]
pub async fn pull_cowfs_snapshot<T: OciTransport, H: HeadStore, P: PackStore>(
    client: &OciClient<T>,
    repo: &str,
    reference: &str,
    dest_head_store: &H,
    dest_pack_store: &P,
    dest_volume: &VolumeId,
    snapshot_name: Option<&str>,
    now: Timespec,
    trust: Option<&os_image::Trust>,
) -> Result<CowfsOciPullResp> {
    if let Some(ver) = dest_head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let (pinned_ref, verified_key) = if let Some(t) = trust {
        let (digest, key_id) = verify_ed25519_referrers(client, repo, reference, t).await?;
        (digest, Some(key_id))
    } else {
        (reference.to_string(), None)
    };

    let resolved = resolve_snapshot_metadata(client, repo, &pinned_ref).await?;
    let _gc = dest_head_store.acquire_gc_lock(false).await?;

    let acquired_lease: Option<WriterLease>;
    let expected_lease = match dest_head_store.read_head(dest_volume).await {
        Ok(_) => {
            let lease = dest_head_store
                .acquire_writer(dest_volume, WriterMode::Exclusive)
                .await?;
            let triple = (lease.incarnation, lease.fence, lease.epoch);
            acquired_lease = Some(lease);
            Some(triple)
        }
        Err(Errno::ENOENT) => {
            acquired_lease = dest_head_store.reserve_receive(dest_volume).await?;
            acquired_lease
                .as_ref()
                .map(|l| (l.incarnation, l.fence, l.epoch))
        }
        Err(e) => return Err(e),
    };

    let res = async {
        let mut packs_pulled = 0u64;
        let mut put_packs: Vec<PackMeta> = Vec::new();
        let mut put_blocks: Vec<(Digest, BlockLoc)> = Vec::new();

        for (pack_id, expected_size) in &resolved.pack_sizes {
            if dest_pack_store.stat_pack(pack_id).await?.is_none() {
                let blob_digest = format!("sha256:{}", pack_id.0);
                let raw_pack = client.get_blob(repo, &blob_digest).await?;
                if raw_pack.len() as u64 != *expected_size {
                    return Err(Errno::EIO);
                }
                let trailer = decode_pack_trailer(&raw_pack)?;
                // Verify every block digest inside the COWP pack before writing.
                for e in &trailer.entries {
                    let start = e.offset as usize;
                    let end = start.checked_add(e.len as usize).ok_or(Errno::EIO)?;
                    if end > raw_pack.len() {
                        return Err(Errno::EIO);
                    }
                    verify_block_digest(&e.digest, &raw_pack[start..end])?;
                }
                let mut meta = dest_pack_store.write_pack(pack_id, &raw_pack).await?;
                meta.created_at = now;
                let locs: Vec<(Digest, BlockLoc)> = trailer
                    .entries
                    .iter()
                    .map(|e| {
                        (
                            e.digest,
                            BlockLoc {
                                pack_id: pack_id.clone(),
                                offset: e.offset,
                                len: e.len,
                                raw_len: e.raw_len,
                                flags: e.flags,
                            },
                        )
                    })
                    .collect();
                dest_head_store
                    .stage_objects(&[], std::slice::from_ref(&meta), &locs, now)
                    .await?;
                put_packs.push(meta);
                put_blocks.extend(locs);
                packs_pulled = packs_pulled.saturating_add(1);
            } else {
                // Pack already exists locally; verify its length and derive canonical BlockLocs
                // directly from its verified local trailer (never trusting raw BlockDir offsets).
                let existing_len = dest_pack_store
                    .stat_pack(pack_id)
                    .await?
                    .ok_or(Errno::EIO)?;
                if existing_len != *expected_size {
                    return Err(Errno::EIO);
                }
                let trailer = dest_pack_store.read_pack_trailer(pack_id).await?;
                let locs: Vec<(Digest, BlockLoc)> = trailer
                    .entries
                    .iter()
                    .map(|e| {
                        (
                            e.digest,
                            BlockLoc {
                                pack_id: pack_id.clone(),
                                offset: e.offset,
                                len: e.len,
                                raw_len: e.raw_len,
                                flags: e.flags,
                            },
                        )
                    })
                    .collect();
                dest_head_store.stage_objects(&[], &[], &locs, now).await?;
                put_blocks.extend(locs);
            }
        }

        let put_nodes: Vec<(Digest, Vec<u8>)> = resolved.nodes.into_iter().collect();
        let nodes_pulled = put_nodes.len() as u64;
        dest_head_store
            .stage_objects(&put_nodes, &[], &[], now)
            .await?;

        let verify_epoch = expected_lease.map_or(0, |(_, _, ep)| ep.saturating_add(1));
        let report = crate::fsck::verify_root_reachable(
            dest_head_store,
            dest_pack_store,
            &dest_volume.0,
            verify_epoch,
            resolved.root_digest,
        )
        .await?;
        if !report.ok {
            return Err(Errno::EIO);
        }

        let mut op_seed = Vec::with_capacity(96);
        op_seed.extend_from_slice(&resolved.root_digest);
        op_seed.extend_from_slice(dest_volume.0.as_bytes());
        op_seed.push(0);
        if let Some((inc, fence, ep)) = expected_lease {
            op_seed.extend_from_slice(&inc.to_be_bytes());
            op_seed.extend_from_slice(&fence.to_be_bytes());
            op_seed.extend_from_slice(&ep.to_be_bytes());
        }
        if let Some(snap) = snapshot_name {
            op_seed.extend_from_slice(snap.as_bytes());
        }
        op_seed.extend_from_slice(&now.sec.to_be_bytes());
        op_seed.extend_from_slice(&now.nsec.to_be_bytes());
        let op_hash = sha256(&op_seed);
        let mut op_id = [0u8; 16];
        op_id.copy_from_slice(&op_hash[..16]);
        let req = ReceiveCommitRequest {
            op_id,
            volume: dest_volume.clone(),
            expected_lease,
            new_root: resolved.root_digest,
            put_nodes,
            put_packs,
            put_blocks,
            snapshot_name: snapshot_name.map(str::to_owned),
            committed_at: now,
        };
        let head = dest_head_store.commit_received_root(&req).await?;
        Ok(CowfsOciPullResp {
            volume: head.volume.0,
            root: digest_to_hex(&head.root),
            epoch: head.epoch,
            manifest_digest: resolved.manifest_digest,
            snapshot: snapshot_name.map(str::to_owned),
            verified_key,
            packs_pulled,
            nodes_pulled,
        })
    }
    .await;

    if let Some(lease) = acquired_lease {
        let _ = dest_head_store.release_writer(lease).await;
    }
    res
}

struct OciRoPin;
impl RoPinGuard for OciRoPin {}

struct OciGcGuard;
impl GcLockGuard for OciGcGuard {}

/// Lazy read-only [`HeadStore`] backed by verified `NodePack`s and `BlockDir`s from an OCI
/// `cowfs` snapshot artifact. Zero `COWP` data packs are fetched at mount time.
pub struct OciSnapshotHeadStore<T: OciTransport> {
    volume: VolumeId,
    repo: String,
    manifest_digest: String,
    root_digest: Digest,
    nodes: HashMap<Digest, Vec<u8>>,
    blocks: HashMap<Digest, BlockLoc>,
    pack_ids: HashSet<PackId>,
    _marker: std::marker::PhantomData<T>,
}

/// Lazy read-only [`PackStore`] fetching `COWP` byte ranges on demand via bounded `<= 1 MiB`
/// HTTP `Range` requests (max 4 concurrent via `[AsyncMutex; 4]`) against the configured registry.
pub struct OciSnapshotPackStore<T: OciTransport> {
    client: OciClient<T>,
    repo: String,
    pack_sizes: HashMap<PackId, u64>,
    reads: [AsyncMutex; 4],
    next_read: Cell<usize>,
}

impl<T: OciTransport> OciSnapshotHeadStore<T> {
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn repo(&self) -> &str {
        &self.repo
    }

    pub fn synthetic_head(&self) -> VolumeHead {
        VolumeHead {
            format_version: COWFS_FORMAT_VERSION,
            volume: self.volume.clone(),
            incarnation: 1,
            fence: 1,
            epoch: 0,
            root: self.root_digest,
            parent_volume: None,
            ephemeral_if_unmodified: false,
            modified: false,
            updated_at: Timespec { sec: 0, nsec: 0 },
        }
    }
}

impl<T: OciTransport> HeadStore for OciSnapshotHeadStore<T> {
    fn filesystem_identity(&self, _v: &VolumeId) -> String {
        format!("cowfs:oci/{}@{}", self.repo, self.manifest_digest)
    }

    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async { Ok(Some(COWFS_FORMAT_VERSION)) })
    }

    fn grace_window_secs(&self) -> u64 {
        0
    }

    fn create_volume<'a>(
        &'a self,
        _head: &'a VolumeHead,
        _initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            if volume == &self.volume {
                Ok(self.synthetic_head())
            } else {
                Err(Errno::ENOENT)
            }
        })
    }

    fn list_volumes(&self) -> BoxFuture<'_, Vec<VolumeHead>> {
        Box::pin(async move { Ok(vec![self.synthetic_head()]) })
    }

    fn commit_received_root<'a>(
        &'a self,
        _req: &'a ReceiveCommitRequest,
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async move {
            if volume != &self.volume || snapshot.is_some() {
                return Err(Errno::ENOENT);
            }
            Ok((
                self.synthetic_head(),
                Box::new(OciRoPin) as Box<dyn RoPinGuard>,
            ))
        })
    }

    fn unpin_ro_root<'a>(&'a self, _pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn acquire_writer<'a>(
        &'a self,
        _volume: &'a VolumeId,
        _mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn renew_writer<'a>(&'a self, _lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn release_writer<'a>(&'a self, _lease: WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let raw = self.nodes.get(digest).ok_or(Errno::ENOENT)?;
            if sha256(raw) != *digest {
                return Err(Errno::EIO);
            }
            Ok(raw.clone())
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move { Ok(self.blocks.get(digest).cloned()) })
    }

    fn commit_head<'a>(&'a self, _req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn create_snapshot<'a>(
        &'a self,
        _volume: &'a VolumeId,
        _name: &'a str,
        _head: &'a VolumeHead,
        _now: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn get_snapshot<'a>(
        &'a self,
        _volume: &'a VolumeId,
        _name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async { Err(Errno::ENOENT) })
    }

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        Box::pin(async move {
            if volume == &self.volume {
                Ok(Vec::new())
            } else {
                Err(Errno::ENOENT)
            }
        })
    }

    fn delete_snapshot<'a>(&'a self, _volume: &'a VolumeId, _name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn fork_volume<'a>(&'a self, _req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn delete_volume<'a>(&'a self, _volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn delete_volume_with_lease<'a>(
        &'a self,
        _lease: WriterLease,
        _only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn reformat_volume_with_lease<'a>(
        &'a self,
        _lease: WriterLease,
        _new_head: &'a VolumeHead,
        _initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn acquire_gc_lock(&self, exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async move {
            if exclusive {
                Err(Errno::EROFS)
            } else {
                Ok(Box::new(OciGcGuard) as Box<dyn GcLockGuard>)
            }
        })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async move {
            Ok(vec![GcRoot {
                volume: self.volume.clone(),
                root: self.root_digest,
                pinned_until: None,
            }])
        })
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move { Ok(self.pack_ids.clone()) })
    }

    fn prune_abandoned_ephemeral_forks(
        &self,
        _now: Timespec,
        _grace_window_secs: u64,
    ) -> BoxFuture<'_, usize> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn sweep_metadata<'a>(
        &'a self,
        _keep_nodes: &'a HashSet<Digest>,
        _keep_packs: &'a HashSet<PackId>,
        _now: Timespec,
        _grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async { Err(Errno::EROFS) })
    }
}

impl<T: OciTransport> PackStore for OciSnapshotPackStore<T> {
    fn write_pack<'a>(&'a self, _pack_id: &'a PackId, _bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async { Err(Errno::EROFS) })
    }

    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if len > EXTENT_MAX_BYTES {
                return Err(Errno::EFBIG);
            }
            let &pack_size = self.pack_sizes.get(pack_id).ok_or(Errno::ENOENT)?;
            let end = u64::from(offset)
                .checked_add(u64::from(len))
                .ok_or(Errno::EIO)?;
            if end > pack_size {
                return Err(Errno::EIO);
            }
            let slot = self.next_read.get() % self.reads.len();
            self.next_read.set(slot.wrapping_add(1));
            let _guard = self.reads[slot].lock().await;
            let blob_digest = format!("sha256:{}", pack_id.0);
            self.client
                .get_blob_range(&self.repo, &blob_digest, u64::from(offset), u64::from(len))
                .await
        })
    }

    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let &pack_size = self.pack_sizes.get(pack_id).ok_or(Errno::ENOENT)?;
            let pack_len = u32::try_from(pack_size).map_err(|_| Errno::EIO)?;
            if (pack_len as usize) < PACK_FOOTER_BYTES || (pack_len as usize) > PACK_MAX_BYTES {
                return Err(Errno::EIO);
            }
            let footer_off = pack_len - PACK_FOOTER_BYTES as u32;
            let footer = self
                .read_pack_range(pack_id, footer_off, PACK_FOOTER_BYTES as u32)
                .await?;
            let (trailer_len, trailer_sha) = decode_pack_footer(&footer)?;
            let trailer_off = footer_off.checked_sub(trailer_len).ok_or(Errno::EIO)?;
            let trailer_bytes = self
                .read_pack_range(pack_id, trailer_off, trailer_len)
                .await?;
            decode_pack_trailer_bytes(&trailer_bytes, trailer_sha, trailer_off)
        })
    }

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move { Ok(self.pack_sizes.get(pack_id).copied()) })
    }

    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move {
            let mut ids: Vec<PackId> = self.pack_sizes.keys().cloned().collect();
            ids.sort();
            Ok(ids)
        })
    }

    fn delete_pack<'a>(&'a self, _pack_id: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }
}

/// Mount an OCI `cowfs` snapshot artifact lazily read-only (`WriterModel::Immutable`).
/// Downloads ONLY manifest(s) + config + `NodePack`(s) + `BlockDir`(s) at mount time (**ZERO `COWP`
/// data packs fetched at mount**); file data is fetched lazily via bounded `<= 1 MiB` HTTP `Range`
/// requests and SHA-256 verified against Merkle extent digests on every read.
pub async fn open_oci_snapshot_cowfs<T: OciTransport>(
    client: OciClient<T>,
    repo: &str,
    reference: &str,
    mut config: CowFsConfig,
) -> Result<CowFs<OciSnapshotHeadStore<T>, OciSnapshotPackStore<T>>> {
    let resolved = resolve_snapshot_metadata(&client, repo, reference).await?;
    let volume = VolumeId(resolved.volume_uuid);
    let pack_ids: HashSet<PackId> = resolved.pack_sizes.keys().cloned().collect();

    let head_store = Rc::new(OciSnapshotHeadStore {
        volume: volume.clone(),
        repo: repo.to_string(),
        manifest_digest: resolved.manifest_digest,
        root_digest: resolved.root_digest,
        nodes: resolved.nodes,
        blocks: resolved.blocks,
        pack_ids,
        _marker: std::marker::PhantomData,
    });
    let pack_store = Rc::new(OciSnapshotPackStore {
        client,
        repo: repo.to_string(),
        pack_sizes: resolved.pack_sizes,
        reads: Default::default(),
        next_read: Cell::new(0),
    });

    config.capabilities.writer_model = WriterModel::Immutable;
    config.capabilities.durability = Durability::FencedCommit;
    CowFs::open(
        head_store,
        pack_store,
        volume,
        CowFsOpenMode::ReadOnly,
        config,
    )
    .await
}
