//! Synchronous SQLite metadata engine for `Boundary::Registry` (OCI Distribution v1.1)
//! running inside the per-tenant `StorageVolume` Durable Object (`storage_do.rs`, schema v2).

use crate::{
    auth,
    db::{Db, int, text},
    storage_do::{Grant, VResult, manifest_key, number, string, strings, used_quota_bytes},
};
use abi::{
    Errno,
    registry::{REGISTRY_TAGS_MAX_N, REGISTRY_UPLOAD_TTL_SECS, valid_repo_name, valid_tag},
    sha256::ResumableSha256,
    volume::CowfsGcResp,
};
use cowtree::digest_from_hex;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct RegistryCommand {
    pub grant: Grant,
    pub action: RegistryAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct UploadChunkMeta {
    pub part_idx: u32,
    pub offset: u64,
    pub len: u64,
    pub r2_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ReferrerMeta {
    pub digest: String,
    pub media_type: String,
    pub artifact_type: Option<String>,
    pub size: u64,
    pub annotations_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum RegistryAction {
    StatBlob {
        repo: String,
        digest: String,
    },
    DeleteBlob {
        repo: String,
        digest: String,
    },
    MountBlob {
        repo: String,
        from_repo: String,
        digest: String,
    },
    BeginMonolithic {
        repo: String,
        digest: String,
        size: u64,
    },
    SealBlob {
        repo: String,
        digest: String,
        size: u64,
        etag: String,
    },
    StartUpload {
        repo: String,
    },
    GetUpload {
        repo: String,
        upload_id: String,
    },
    AppendUploadChunks {
        repo: String,
        upload_id: String,
        expected_received: u64,
        new_sha_state_b64: String,
        chunks: Vec<UploadChunkMeta>,
    },
    PrepareFinalizeUpload {
        repo: String,
        upload_id: String,
        digest: String,
        expected_received: u64,
        extra_chunks: Vec<UploadChunkMeta>,
    },
    CompleteFinalizeUpload {
        repo: String,
        upload_id: String,
        digest: String,
        total_size: u64,
        etag: String,
    },
    AbortUpload {
        repo: String,
        upload_id: String,
    },
    CheckManifestRefs {
        repo: String,
        manifest_digest: String,
        refs: Vec<(String, String)>,
    },
    PutManifest {
        repo: String,
        digest: String,
        tag: Option<String>,
        media_type: String,
        artifact_type: Option<String>,
        subject_digest: Option<String>,
        size: u64,
        annotations_json: String,
        refs: Vec<(String, String)>,
    },
    GetManifest {
        repo: String,
        reference: String,
        is_digest: bool,
    },
    DeleteManifest {
        repo: String,
        reference: String,
        is_digest: bool,
    },
    ListTags {
        repo: String,
        n: usize,
        last: Option<String>,
    },
    ListReferrers {
        repo: String,
        subject_digest: String,
        artifact_type: Option<String>,
    },
    RunGc {},
}

impl RegistryAction {
    pub(crate) fn writes_checkpoint(&self) -> bool {
        matches!(
            self,
            Self::SealBlob { .. }
                | Self::MountBlob { .. }
                | Self::DeleteBlob { .. }
                | Self::CompleteFinalizeUpload { .. }
                | Self::PutManifest { .. }
                | Self::DeleteManifest { .. }
                | Self::RunGc {}
        )
    }

    pub(crate) fn auth_context(&self) -> (Option<&str>, bool, Option<&str>) {
        match self {
            Self::StatBlob { repo, .. }
            | Self::GetManifest { repo, .. }
            | Self::ListTags { repo, .. }
            | Self::ListReferrers { repo, .. } => (Some(repo.as_str()), false, None),
            Self::MountBlob {
                repo, from_repo, ..
            } => (Some(repo.as_str()), true, Some(from_repo.as_str())),
            Self::DeleteBlob { repo, .. }
            | Self::BeginMonolithic { repo, .. }
            | Self::SealBlob { repo, .. }
            | Self::StartUpload { repo }
            | Self::GetUpload { repo, .. }
            | Self::AppendUploadChunks { repo, .. }
            | Self::PrepareFinalizeUpload { repo, .. }
            | Self::CompleteFinalizeUpload { repo, .. }
            | Self::AbortUpload { repo, .. }
            | Self::CheckManifestRefs { repo, .. }
            | Self::PutManifest { repo, .. }
            | Self::DeleteManifest { repo, .. } => (Some(repo.as_str()), true, None),
            Self::RunGc {} => (None, true, None),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum RegistryReply {
    Done,
    BlobStat {
        size: u64,
        etag: String,
    },
    Mounted {
        mounted: bool,
        upload_id: Option<String>,
    },
    MonolithicReady {
        already_sealed: bool,
        etag: Option<String>,
    },
    Upload {
        upload_id: String,
        received_bytes: u64,
        part_count: u32,
        sha_state_b64: String,
    },
    FinalizePlan {
        already_sealed: bool,
        etag: Option<String>,
        total_size: u64,
        parts: Vec<(String, u64)>,
    },
    CleanedKeys(Vec<String>),
    ManifestMeta {
        digest: String,
        media_type: String,
        size: u64,
        artifact_type: Option<String>,
        subject_digest: Option<String>,
    },
    Tags {
        tags: Vec<String>,
        has_more: bool,
    },
    Referrers(Vec<ReferrerMeta>),
    Gc(CowfsGcResp),
}

#[derive(Deserialize)]
struct UploadRow {
    upload_id: String,
    repo: String,
    owner: String,
    #[serde(deserialize_with = "crate::db::exact_u64")]
    received_bytes: u64,
    part_count: u32,
    sha_state_b64: String,
    #[serde(deserialize_with = "crate::db::exact_u64")]
    expires: u64,
}

#[derive(Deserialize)]
struct BlobMetaRow {
    #[serde(deserialize_with = "crate::db::exact_u64")]
    size: u64,
    etag: String,
}

#[derive(Deserialize)]
struct ChunkPartRow {
    r2_key: String,
    #[serde(deserialize_with = "crate::db::exact_u64")]
    len: u64,
}

#[derive(Deserialize)]
struct ManifestRow {
    digest: String,
    media_type: String,
    artifact_type: Option<String>,
    subject_digest: Option<String>,
    #[serde(deserialize_with = "crate::db::exact_u64")]
    size: u64,
    annotations_json: String,
}

fn find_sealed_blob(db: &Db, digest: &str) -> Option<BlobMetaRow> {
    if let Some(row) = db
        .rows::<BlobMetaRow>(
            "SELECT CAST(size AS TEXT) size, etag FROM registry_blobs WHERE digest=? AND status='sealed'",
            vec![text(digest)],
        )
        .pop()
    {
        return Some(row);
    }
    db.rows::<BlobMetaRow>(
        "SELECT CAST(size AS TEXT) size, etag FROM packs WHERE pack_id=? AND status='sealed' AND etag IS NOT NULL AND etag != ''",
        vec![text(digest)],
    )
    .pop()
}

fn load_upload(db: &Db, repo: &str, upload_id: &str, owner: &str) -> VResult<UploadRow> {
    let row = db
        .rows::<UploadRow>(
            "SELECT upload_id, repo, owner, CAST(received_bytes AS TEXT) received_bytes, part_count, sha_state_b64, CAST(expires AS TEXT) expires FROM registry_uploads WHERE upload_id=?",
            vec![text(upload_id)],
        )
        .pop()
        .ok_or(Errno::ENOENT)?;
    if row.repo != repo || row.expires <= auth::now() {
        return Err(Errno::ENOENT);
    }
    if row.owner != owner {
        return Err(Errno::EACCES);
    }
    Ok(row)
}

fn create_upload_session(db: &mut Db, repo: &str, owner: &str) -> RegistryReply {
    let now = auth::now();
    let upload_id = auth::random_token()[..32].to_string();
    let sha_state_b64 = ResumableSha256::new().to_base64();
    db.run(
        "INSERT INTO registry_uploads(upload_id, repo, owner, received_bytes, part_count, sha_state_b64, created_at, expires) VALUES(?,?,?,0,0,?,?,?)",
        vec![
            text(&upload_id),
            text(repo),
            text(owner),
            text(&sha_state_b64),
            int(now),
            int(now.saturating_add(REGISTRY_UPLOAD_TTL_SECS)),
        ],
    );
    RegistryReply::Upload {
        upload_id,
        received_bytes: 0,
        part_count: 0,
        sha_state_b64,
    }
}

fn verify_manifest_refs(db: &Db, repo: &str, refs: &[(String, String)]) -> VResult<()> {
    for (kind, digest) in refs {
        digest_from_hex(digest)?;
        match kind.as_str() {
            "blob" => {
                let exists = number(
                    db,
                    "SELECT 1 n FROM registry_repo_blobs rb JOIN registry_blobs b ON b.digest=rb.digest WHERE rb.repo=? AND rb.digest=? AND b.status='sealed'",
                    vec![text(repo), text(digest)],
                )
                .is_some();
                if !exists {
                    return Err(Errno::ENOENT);
                }
            }
            "manifest" => {
                let exists = number(
                    db,
                    "SELECT 1 n FROM registry_manifests WHERE repo=? AND digest=?",
                    vec![text(repo), text(digest)],
                )
                .is_some();
                if !exists {
                    return Err(Errno::ENOENT);
                }
            }
            _ => return Err(Errno::EINVAL),
        }
    }
    Ok(())
}

pub(crate) fn dispatch(
    db: &mut Db,
    cmd: RegistryCommand,
    quota: u64,
    retain: u64,
) -> VResult<RegistryReply> {
    let RegistryCommand { grant: g, action } = cmd;
    let (repo_opt, push, from_repo_opt) = action.auth_context();
    if let Some(repo) = repo_opt {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        if !g.scope.allows_registry(repo, push) {
            return Err(Errno::EACCES);
        }
    }
    if let Some(from_repo) = from_repo_opt {
        if !valid_repo_name(from_repo) {
            return Err(Errno::EINVAL);
        }
        if !g.scope.allows_registry(from_repo, false) {
            return Err(Errno::EACCES);
        }
    }

    match action {
        RegistryAction::StatBlob { repo, digest } => {
            digest_from_hex(&digest)?;
            let row = db
                .rows::<BlobMetaRow>(
                    "SELECT CAST(b.size AS TEXT) size, b.etag FROM registry_repo_blobs rb JOIN registry_blobs b ON b.digest=rb.digest WHERE rb.repo=? AND rb.digest=? AND b.status='sealed'",
                    vec![text(&repo), text(&digest)],
                )
                .pop()
                .ok_or(Errno::ENOENT)?;
            Ok(RegistryReply::BlobStat {
                size: row.size,
                etag: row.etag,
            })
        }
        RegistryAction::DeleteBlob { repo, digest } => {
            digest_from_hex(&digest)?;
            let exists = number(
                db,
                "SELECT 1 n FROM registry_repo_blobs WHERE repo=? AND digest=?",
                vec![text(&repo), text(&digest)],
            )
            .is_some();
            if !exists {
                return Err(Errno::ENOENT);
            }
            let referenced = number(
                db,
                "SELECT 1 n FROM registry_manifest_refs WHERE repo=? AND ref_kind='blob' AND ref_digest=? LIMIT 1",
                vec![text(&repo), text(&digest)],
            )
            .is_some();
            if referenced {
                return Err(Errno::EBUSY);
            }
            db.run(
                "DELETE FROM registry_repo_blobs WHERE repo=? AND digest=?",
                vec![text(&repo), text(&digest)],
            );
            Ok(RegistryReply::Done)
        }
        RegistryAction::MountBlob {
            repo,
            from_repo,
            digest,
        } => {
            digest_from_hex(&digest)?;
            let exists_in_src = number(
                db,
                "SELECT 1 n FROM registry_repo_blobs rb JOIN registry_blobs b ON b.digest=rb.digest WHERE rb.repo=? AND rb.digest=? AND b.status='sealed'",
                vec![text(&from_repo), text(&digest)],
            )
            .is_some();
            if exists_in_src {
                db.run(
                    "INSERT OR REPLACE INTO registry_repo_blobs(repo, digest, created_at) VALUES(?,?,?)",
                    vec![text(&repo), text(&digest), int(auth::now())],
                );
                Ok(RegistryReply::Mounted {
                    mounted: true,
                    upload_id: None,
                })
            } else {
                let RegistryReply::Upload { upload_id, .. } =
                    create_upload_session(db, &repo, &g.owner)
                else {
                    unreachable!()
                };
                Ok(RegistryReply::Mounted {
                    mounted: false,
                    upload_id: Some(upload_id),
                })
            }
        }
        RegistryAction::BeginMonolithic {
            repo: _,
            digest,
            size,
        } => {
            digest_from_hex(&digest)?;
            if number(
                db,
                "SELECT in_flight n FROM gc_pending_deletes WHERE pack_id=?",
                vec![text(&digest)],
            ) == Some(1)
            {
                return Err(Errno::EAGAIN);
            }
            if let Some(existing) = find_sealed_blob(db, &digest) {
                if existing.size == size {
                    return Ok(RegistryReply::MonolithicReady {
                        already_sealed: true,
                        etag: Some(existing.etag),
                    });
                }
                // Do not reveal cross-repo/volume existence or size via 500 EIO.
                // Enforce quota normally and let the edge stream-verify and return 400 DIGEST_INVALID
                // without overwriting the existing R2 object.
                let used = used_quota_bytes(db)?;
                if used.saturating_add(size) > quota {
                    return Err(Errno::EDQUOT);
                }
                return Ok(RegistryReply::MonolithicReady {
                    already_sealed: true,
                    etag: None,
                });
            }
            let used = used_quota_bytes(db)?;
            if used.saturating_add(size) > quota {
                return Err(Errno::EDQUOT);
            }
            db.run(
                "DELETE FROM gc_pending_deletes WHERE pack_id=? AND in_flight=0",
                vec![text(&digest)],
            );
            Ok(RegistryReply::MonolithicReady {
                already_sealed: false,
                etag: None,
            })
        }
        RegistryAction::SealBlob {
            repo,
            digest,
            size,
            etag,
        } => {
            digest_from_hex(&digest)?;
            if number(
                db,
                "SELECT in_flight n FROM gc_pending_deletes WHERE pack_id=?",
                vec![text(&digest)],
            ) == Some(1)
            {
                return Err(Errno::EAGAIN);
            }
            let now = auth::now();
            let already_counted = number(
                db,
                "SELECT 1 n FROM (SELECT pack_id id FROM packs WHERE pack_id=?1 AND status!='deleting' UNION SELECT digest FROM registry_blobs WHERE digest=?1 AND status!='deleting')",
                vec![text(&digest)],
            )
            .is_some();
            if !already_counted && used_quota_bytes(db)?.saturating_add(size) > quota {
                return Err(Errno::EDQUOT);
            }
            db.run(
                "DELETE FROM gc_pending_deletes WHERE pack_id=? AND in_flight=0",
                vec![text(&digest)],
            );
            db.run(
                "INSERT INTO registry_blobs(digest, size, etag, status, created_at, retain_until) VALUES(?,?,?,'sealed',?,0)
                 ON CONFLICT(digest) DO UPDATE SET size=excluded.size, etag=excluded.etag, status='sealed', created_at=excluded.created_at",
                vec![text(&digest), int(size), text(&etag), int(now)],
            );
            db.run(
                "INSERT OR REPLACE INTO registry_repo_blobs(repo, digest, created_at) VALUES(?,?,?)",
                vec![text(&repo), text(&digest), int(now)],
            );
            Ok(RegistryReply::Done)
        }
        RegistryAction::StartUpload { repo } => Ok(create_upload_session(db, &repo, &g.owner)),
        RegistryAction::GetUpload { repo, upload_id } => {
            let row = load_upload(db, &repo, &upload_id, &g.owner)?;
            Ok(RegistryReply::Upload {
                upload_id: row.upload_id,
                received_bytes: row.received_bytes,
                part_count: row.part_count,
                sha_state_b64: row.sha_state_b64,
            })
        }
        RegistryAction::AppendUploadChunks {
            repo,
            upload_id,
            expected_received,
            new_sha_state_b64,
            chunks,
        } => {
            let row = load_upload(db, &repo, &upload_id, &g.owner)?;
            if row.received_bytes != expected_received {
                return Err(Errno::ERANGE);
            }
            let added: u64 = chunks
                .iter()
                .try_fold(0u64, |acc, c| acc.checked_add(c.len).ok_or(Errno::EFBIG))?;
            let used = used_quota_bytes(db)?;
            if used.saturating_add(added) > quota {
                return Err(Errno::EDQUOT);
            }
            let mut next_off = row.received_bytes;
            let mut next_part = row.part_count;
            for chunk in &chunks {
                if chunk.part_idx != next_part || chunk.offset != next_off {
                    return Err(Errno::ERANGE);
                }
                db.run(
                    "INSERT INTO registry_upload_chunks(upload_id, part_idx, offset, len, r2_key) VALUES(?,?,?,?,?)",
                    vec![
                        text(&upload_id),
                        int(chunk.part_idx),
                        int(chunk.offset),
                        int(chunk.len),
                        text(&chunk.r2_key),
                    ],
                );
                next_off = next_off.checked_add(chunk.len).ok_or(Errno::EFBIG)?;
                next_part = next_part.checked_add(1).ok_or(Errno::EFBIG)?;
            }
            let now = auth::now();
            db.run(
                "UPDATE registry_uploads SET received_bytes=?, part_count=?, sha_state_b64=?, expires=? WHERE upload_id=?",
                vec![
                    int(next_off),
                    int(next_part),
                    text(&new_sha_state_b64),
                    int(now.saturating_add(REGISTRY_UPLOAD_TTL_SECS)),
                    text(&upload_id),
                ],
            );
            Ok(RegistryReply::Upload {
                upload_id,
                received_bytes: next_off,
                part_count: next_part,
                sha_state_b64: new_sha_state_b64,
            })
        }
        RegistryAction::PrepareFinalizeUpload {
            repo,
            upload_id,
            digest,
            expected_received,
            extra_chunks,
        } => {
            digest_from_hex(&digest)?;
            let row = load_upload(db, &repo, &upload_id, &g.owner)?;
            if row.received_bytes != expected_received {
                return Err(Errno::ERANGE);
            }
            if number(
                db,
                "SELECT in_flight n FROM gc_pending_deletes WHERE pack_id=?",
                vec![text(&digest)],
            ) == Some(1)
            {
                return Err(Errno::EAGAIN);
            }
            let extra_bytes: u64 = extra_chunks
                .iter()
                .try_fold(0u64, |acc, c| acc.checked_add(c.len).ok_or(Errno::EFBIG))?;
            let total_size = row
                .received_bytes
                .checked_add(extra_bytes)
                .ok_or(Errno::EFBIG)?;
            let existing = find_sealed_blob(db, &digest);
            if let Some(ref ex) = existing
                && ex.size != total_size
            {
                return Err(Errno::EIO);
            }
            if existing.is_none() && used_quota_bytes(db)?.saturating_add(extra_bytes) > quota {
                return Err(Errno::EDQUOT);
            }
            let mut next_off = row.received_bytes;
            let mut next_part = row.part_count;
            for chunk in &extra_chunks {
                if chunk.part_idx != next_part || chunk.offset != next_off {
                    return Err(Errno::ERANGE);
                }
                db.run(
                    "INSERT INTO registry_upload_chunks(upload_id, part_idx, offset, len, r2_key) VALUES(?,?,?,?,?)",
                    vec![
                        text(&upload_id),
                        int(chunk.part_idx),
                        int(chunk.offset),
                        int(chunk.len),
                        text(&chunk.r2_key),
                    ],
                );
                next_off = next_off.checked_add(chunk.len).ok_or(Errno::EFBIG)?;
                next_part = next_part.checked_add(1).ok_or(Errno::EFBIG)?;
            }
            if !extra_chunks.is_empty() {
                db.run(
                    "UPDATE registry_uploads SET received_bytes=?, part_count=?, expires=? WHERE upload_id=?",
                    vec![
                        int(next_off),
                        int(next_part),
                        int(auth::now().saturating_add(REGISTRY_UPLOAD_TTL_SECS)),
                        text(&upload_id),
                    ],
                );
            }
            let parts = db
                .rows::<ChunkPartRow>(
                    "SELECT r2_key, CAST(len AS TEXT) len FROM registry_upload_chunks WHERE upload_id=? ORDER BY part_idx ASC",
                    vec![text(&upload_id)],
                )
                .into_iter()
                .map(|r| (r.r2_key, r.len))
                .collect();
            db.run(
                "DELETE FROM gc_pending_deletes WHERE pack_id=? AND in_flight=0",
                vec![text(&digest)],
            );
            Ok(RegistryReply::FinalizePlan {
                already_sealed: existing.is_some(),
                etag: existing.map(|e| e.etag),
                total_size,
                parts,
            })
        }
        RegistryAction::CompleteFinalizeUpload {
            repo,
            upload_id,
            digest,
            total_size,
            etag,
        } => {
            digest_from_hex(&digest)?;
            let _row = load_upload(db, &repo, &upload_id, &g.owner)?;
            if number(
                db,
                "SELECT in_flight n FROM gc_pending_deletes WHERE pack_id=?",
                vec![text(&digest)],
            ) == Some(1)
            {
                return Err(Errno::EAGAIN);
            }
            let now = auth::now();
            let staged_keys = strings(
                db,
                "SELECT r2_key v FROM registry_upload_chunks WHERE upload_id=? ORDER BY part_idx ASC",
                vec![text(&upload_id)],
            );
            db.run(
                "DELETE FROM gc_pending_deletes WHERE pack_id=? AND in_flight=0",
                vec![text(&digest)],
            );
            db.run(
                "INSERT INTO registry_blobs(digest, size, etag, status, created_at, retain_until) VALUES(?,?,?,'sealed',?,0)
                 ON CONFLICT(digest) DO UPDATE SET size=excluded.size, etag=excluded.etag, status='sealed', created_at=excluded.created_at",
                vec![text(&digest), int(total_size), text(&etag), int(now)],
            );
            db.run(
                "INSERT OR REPLACE INTO registry_repo_blobs(repo, digest, created_at) VALUES(?,?,?)",
                vec![text(&repo), text(&digest), int(now)],
            );
            for k in &staged_keys {
                db.run(
                    "INSERT OR IGNORE INTO registry_pending_deletes(r2_key, in_flight, delete_after) VALUES(?, 0, ?)",
                    vec![text(k), int(now)],
                );
            }
            db.run(
                "DELETE FROM registry_upload_chunks WHERE upload_id=?",
                vec![text(&upload_id)],
            );
            db.run(
                "DELETE FROM registry_uploads WHERE upload_id=?",
                vec![text(&upload_id)],
            );
            Ok(RegistryReply::CleanedKeys(staged_keys))
        }
        RegistryAction::AbortUpload { repo, upload_id } => {
            let _row = load_upload(db, &repo, &upload_id, &g.owner)?;
            let now = auth::now();
            let staged_keys = strings(
                db,
                "SELECT r2_key v FROM registry_upload_chunks WHERE upload_id=? ORDER BY part_idx ASC",
                vec![text(&upload_id)],
            );
            for k in &staged_keys {
                db.run(
                    "INSERT OR IGNORE INTO registry_pending_deletes(r2_key, in_flight, delete_after) VALUES(?, 0, ?)",
                    vec![text(k), int(now)],
                );
            }
            db.run(
                "DELETE FROM registry_upload_chunks WHERE upload_id=?",
                vec![text(&upload_id)],
            );
            db.run(
                "DELETE FROM registry_uploads WHERE upload_id=?",
                vec![text(&upload_id)],
            );
            Ok(RegistryReply::CleanedKeys(staged_keys))
        }
        RegistryAction::CheckManifestRefs {
            repo,
            manifest_digest,
            refs,
        } => {
            digest_from_hex(&manifest_digest)?;
            let mkey = manifest_key(&g.tenant, &manifest_digest);
            if number(
                db,
                "SELECT in_flight n FROM registry_pending_deletes WHERE r2_key=?",
                vec![text(&mkey)],
            ) == Some(1)
            {
                return Err(Errno::EAGAIN);
            }
            verify_manifest_refs(db, &repo, &refs)?;
            Ok(RegistryReply::Done)
        }
        RegistryAction::PutManifest {
            repo,
            digest,
            tag,
            media_type,
            artifact_type,
            subject_digest,
            size,
            annotations_json,
            refs,
        } => {
            digest_from_hex(&digest)?;
            if let Some(ref t) = tag
                && !valid_tag(t)
            {
                return Err(Errno::EINVAL);
            }
            if let Some(ref s) = subject_digest {
                digest_from_hex(s)?;
            }
            verify_manifest_refs(db, &repo, &refs)?;
            let now = auth::now();
            let mkey = manifest_key(&g.tenant, &digest);
            if number(
                db,
                "SELECT in_flight n FROM registry_pending_deletes WHERE r2_key=?",
                vec![text(&mkey)],
            ) == Some(1)
            {
                return Err(Errno::EAGAIN);
            }
            db.run(
                "DELETE FROM registry_pending_deletes WHERE r2_key=? AND in_flight=0",
                vec![text(&mkey)],
            );
            db.run(
                "INSERT OR REPLACE INTO registry_manifests(repo, digest, media_type, artifact_type, subject_digest, size, annotations_json, created_at) VALUES(?,?,?,?,?,?,?,?)",
                vec![
                    text(&repo),
                    text(&digest),
                    text(&media_type),
                    artifact_type.as_deref().into(),
                    subject_digest.as_deref().into(),
                    int(size),
                    text(&annotations_json),
                    int(now),
                ],
            );
            db.run(
                "DELETE FROM registry_manifest_refs WHERE repo=? AND manifest_digest=?",
                vec![text(&repo), text(&digest)],
            );
            for (kind, ref_digest) in &refs {
                db.run(
                    "INSERT OR IGNORE INTO registry_manifest_refs(repo, manifest_digest, ref_kind, ref_digest) VALUES(?,?,?,?)",
                    vec![text(&repo), text(&digest), text(kind), text(ref_digest)],
                );
            }
            if let Some(tag_name) = tag {
                db.run(
                    "INSERT OR REPLACE INTO registry_tags(repo, tag, digest, updated_at) VALUES(?,?,?,?)",
                    vec![text(&repo), text(&tag_name), text(&digest), int(now)],
                );
            }
            Ok(RegistryReply::Done)
        }
        RegistryAction::GetManifest {
            repo,
            reference,
            is_digest,
        } => {
            let digest = if is_digest {
                digest_from_hex(&reference)?;
                reference
            } else {
                if !valid_tag(&reference) {
                    return Err(Errno::EINVAL);
                }
                string(
                    db,
                    "SELECT digest v FROM registry_tags WHERE repo=? AND tag=?",
                    vec![text(&repo), text(&reference)],
                )
                .ok_or(Errno::ENOENT)?
            };
            let row = db
                .rows::<ManifestRow>(
                    "SELECT digest, media_type, artifact_type, subject_digest, CAST(size AS TEXT) size, annotations_json FROM registry_manifests WHERE repo=? AND digest=?",
                    vec![text(&repo), text(&digest)],
                )
                .pop()
                .ok_or(Errno::ENOENT)?;
            Ok(RegistryReply::ManifestMeta {
                digest: row.digest,
                media_type: row.media_type,
                size: row.size,
                artifact_type: row.artifact_type,
                subject_digest: row.subject_digest,
            })
        }
        RegistryAction::DeleteManifest {
            repo,
            reference,
            is_digest,
        } => {
            if !is_digest {
                if !valid_tag(&reference) {
                    return Err(Errno::EINVAL);
                }
                let deleted = number(
                    db,
                    "DELETE FROM registry_tags WHERE repo=? AND tag=? RETURNING 1 n",
                    vec![text(&repo), text(&reference)],
                );
                if deleted.is_none() {
                    return Err(Errno::ENOENT);
                }
                return Ok(RegistryReply::Done);
            }
            digest_from_hex(&reference)?;
            let deleted = number(
                db,
                "DELETE FROM registry_manifests WHERE repo=? AND digest=? RETURNING 1 n",
                vec![text(&repo), text(&reference)],
            );
            if deleted.is_none() {
                return Err(Errno::ENOENT);
            }
            db.run(
                "DELETE FROM registry_manifest_refs WHERE repo=? AND manifest_digest=?",
                vec![text(&repo), text(&reference)],
            );
            db.run(
                "DELETE FROM registry_tags WHERE repo=? AND digest=?",
                vec![text(&repo), text(&reference)],
            );
            let still_used = number(
                db,
                "SELECT 1 n FROM registry_manifests WHERE digest=? LIMIT 1",
                vec![text(&reference)],
            )
            .is_some();
            if !still_used {
                let mkey = manifest_key(&g.tenant, &reference);
                db.run(
                    "INSERT OR IGNORE INTO registry_pending_deletes(r2_key, in_flight, delete_after) VALUES(?, 0, ?)",
                    vec![text(&mkey), int(auth::now().saturating_add(retain))],
                );
            }
            Ok(RegistryReply::Done)
        }
        RegistryAction::ListTags { repo, n, last } => {
            let cap = n.min(REGISTRY_TAGS_MAX_N);
            let fetch = cap.saturating_add(1);
            let mut tags = if let Some(last_tag) = last {
                strings(
                    db,
                    "SELECT tag v FROM registry_tags WHERE repo=? AND tag > ? ORDER BY tag ASC LIMIT ?",
                    vec![text(&repo), text(&last_tag), int(fetch)],
                )
            } else {
                strings(
                    db,
                    "SELECT tag v FROM registry_tags WHERE repo=? ORDER BY tag ASC LIMIT ?",
                    vec![text(&repo), int(fetch)],
                )
            };
            let has_more = tags.len() > cap;
            if has_more {
                tags.truncate(cap);
            }
            Ok(RegistryReply::Tags { tags, has_more })
        }
        RegistryAction::ListReferrers {
            repo,
            subject_digest,
            artifact_type,
        } => {
            digest_from_hex(&subject_digest)?;
            let rows = if let Some(filter) = artifact_type.filter(|s| !s.is_empty()) {
                db.rows::<ManifestRow>(
                    "SELECT digest, media_type, artifact_type, subject_digest, CAST(size AS TEXT) size, annotations_json FROM registry_manifests WHERE repo=? AND subject_digest=? AND artifact_type=? ORDER BY digest ASC",
                    vec![text(&repo), text(&subject_digest), text(&filter)],
                )
            } else {
                db.rows::<ManifestRow>(
                    "SELECT digest, media_type, artifact_type, subject_digest, CAST(size AS TEXT) size, annotations_json FROM registry_manifests WHERE repo=? AND subject_digest=? ORDER BY digest ASC",
                    vec![text(&repo), text(&subject_digest)],
                )
            };
            Ok(RegistryReply::Referrers(
                rows.into_iter()
                    .map(|r| ReferrerMeta {
                        digest: r.digest,
                        media_type: r.media_type,
                        artifact_type: r.artifact_type,
                        size: r.size,
                        annotations_json: r.annotations_json,
                    })
                    .collect(),
            ))
        }
        RegistryAction::RunGc {} => {
            if !g.scope.registry_repos.is_empty() {
                return Err(Errno::EACCES);
            }
            Ok(RegistryReply::Gc(crate::storage_do::collect(db, retain)?))
        }
    }
}
