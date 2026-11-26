//! Conformance tests for OCI-03 (Ed25519 signature referrers), OCI-05 (sharded `cowfs` snapshot
//! artifact v1, zero byte-format conversion, generic mirror to an independent registry, offline
//! origin shutdown + lazy RO range-verified mount + corruption detection + pull/fork/mutate), and
//! OCI-08 (zero new `abi::Call` variants; `COWFS_IOC_OCI_*` ioctl round-trip) (`contract.md` §2.15; #81).

use abi::Errno;
use abi::contract::{Durability, WriterModel, cowfs_ioctl};
use abi::fs::{OpenOptions, Timespec, WriteAt};
use abi::registry::{
    COWFS_PACK_LAYER_MEDIA_TYPE, CowfsOciExportReq, CowfsOciExportResp, CowfsOciImportReq,
    CowfsOciImportResp, CowfsOciPullReq, CowfsOciPullResp, CowfsOciPushReq, CowfsOciPushResp,
    OCI_IMAGE_INDEX_MEDIA_TYPE, OciDescriptor, OciImageIndex, OciImageManifest, OciTokenResponse,
    parse_sha256_digest,
};
use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
use cowtree::{PackId, WriterMode};
use ed25519_dalek::{Signer, SigningKey};
use os_cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, CowFsVolumeDevice, OciClient, OciHttpReply, OciPushOptions,
    OciTransport, PackStore, VolumeId, attach_ed25519_signature, digest_to_hex,
    mirror_oci_artifact, open_oci_snapshot_cowfs, pull_cowfs_snapshot, push_cowfs_snapshot, sha256,
    verify_ed25519_referrers, verify_volume, verify_volume_strict,
};
use os_image::{Detached, SIGNING_DOMAIN_OCI_ARTIFACT_V1, Trust, digest, hex, signing_message};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use vfs::vblk::{StreamSink, StreamSource, VblkRegistry};
use vfs::{BoxFuture, Cred, Filesystem, now_or_never};

fn run<T>(f: impl std::future::Future<Output = T>) -> T {
    now_or_never(f).expect("sync future")
}

fn test_clock() -> os_cowfs::CowFsClock {
    Rc::new(|| Timespec {
        sec: 1_700_000_000,
        nsec: 0,
    })
}

fn root_cred() -> Cred {
    let mut c = Cred::root();
    c.umask = 0;
    c
}

#[derive(Clone)]
struct StoredManifest {
    media_type: String,
    artifact_type: Option<String>,
    subject_digest: Option<String>,
    annotations: Option<BTreeMap<String, String>>,
    bytes: Vec<u8>,
}

fn reply(status: u16, headers: Vec<(&str, String)>, body: Vec<u8>) -> OciHttpReply {
    OciHttpReply {
        status,
        headers: headers
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        body,
    }
}

struct MockRegistry {
    inner: RefCell<MockRegistryData>,
    offline: Cell<bool>,
    corrupt_next_range: Cell<bool>,
    blob_gets: RefCell<Vec<(String, Option<String>)>>,
    max_range_len: Cell<u64>,
}

#[derive(Default)]
struct MockRegistryData {
    blobs: HashMap<String, Vec<u8>>,
    repo_blobs: HashSet<(String, String)>,
    manifests: HashMap<(String, String), StoredManifest>,
    tags: HashMap<(String, String), String>,
}

impl MockRegistry {
    fn new() -> Rc<Self> {
        Rc::new(Self {
            inner: RefCell::new(MockRegistryData::default()),
            offline: Cell::new(false),
            corrupt_next_range: Cell::new(false),
            blob_gets: RefCell::new(Vec::new()),
            max_range_len: Cell::new(0),
        })
    }

    fn client(self: &Rc<Self>, host: &str) -> OciClient<RegTransport> {
        let base = format!("http://{host}.invalid");
        OciClient::new(
            base.clone(),
            Rc::new(RegTransport {
                reg: Rc::clone(self),
                base,
            }),
        )
    }

    fn transport(self: &Rc<Self>, host: &str) -> Rc<dyn OciTransport> {
        Rc::new(RegTransport {
            reg: Rc::clone(self),
            base: format!("http://{host}.invalid"),
        })
    }
}

#[derive(Clone)]
struct RegTransport {
    reg: Rc<MockRegistry>,
    base: String,
}

fn parse_query_param(query: &str, key: &str) -> Option<String> {
    for kv in query.split('&') {
        if let Some((k, v)) = kv.split_once('=')
            && k == key
        {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(val) = u8::from_str_radix(hex_str, 16)
        {
            out.push(val);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

impl OciTransport for RegTransport {
    fn request<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> BoxFuture<'a, OciHttpReply> {
        Box::pin(async move {
            if self.reg.offline.get() {
                return Err(Errno::ENOTCONN);
            }
            let path_and_q = url.strip_prefix(&self.base).unwrap_or(url);
            let (path, query) = path_and_q.split_once('?').unwrap_or((path_and_q, ""));

            if path == "/v2/token" {
                let tok = OciTokenResponse {
                    token: "mock-jwt".into(),
                    access_token: "mock-jwt".into(),
                    expires_in: 300,
                    issued_at: "2026-01-01T00:00:00Z".into(),
                };
                return Ok(reply(
                    200,
                    vec![("Content-Type", "application/json".into())],
                    serde_json::to_vec(&tok).unwrap(),
                ));
            }

            let auth = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.as_str());
            if auth != Some("Bearer mock-jwt") {
                return Ok(reply(
                    401,
                    vec![
                        ("Docker-Distribution-API-Version", "registry/2.0".into()),
                        (
                            "WWW-Authenticate",
                            format!("Bearer realm=\"{}/v2/token\",service=\"mock\"", self.base),
                        ),
                    ],
                    b"{}".to_vec(),
                ));
            }

            if path == "/v2" || path == "/v2/" {
                return Ok(reply(
                    200,
                    vec![("Docker-Distribution-API-Version", "registry/2.0".into())],
                    b"{}".to_vec(),
                ));
            }

            let rest = path.strip_prefix("/v2/").ok_or(Errno::ENOENT)?;

            // Blob upload POST /v2/<repo>/blobs/uploads/?digest=<d>
            if let Some(repo) = rest
                .strip_suffix("/blobs/uploads/")
                .or_else(|| rest.strip_suffix("/blobs/uploads"))
                && method == "POST"
            {
                let expected = parse_query_param(query, "digest").ok_or(Errno::EINVAL)?;
                let actual = format!("sha256:{}", digest_to_hex(&sha256(body)));
                if actual != expected {
                    return Ok(reply(400, vec![], b"digest mismatch".to_vec()));
                }
                let mut data = self.reg.inner.borrow_mut();
                data.blobs.insert(expected.clone(), body.to_vec());
                data.repo_blobs.insert((repo.to_string(), expected.clone()));
                return Ok(reply(
                    201,
                    vec![
                        ("Location", format!("/v2/{repo}/blobs/{expected}")),
                        ("Docker-Content-Digest", expected),
                    ],
                    Vec::new(),
                ));
            }

            // Blobs HEAD/GET /v2/<repo>/blobs/<digest>
            if let Some((repo, digest)) = rest.rsplit_once("/blobs/") {
                let data = self.reg.inner.borrow();
                if !data
                    .repo_blobs
                    .contains(&(repo.to_string(), digest.to_string()))
                {
                    return Ok(reply(404, vec![], b"{}".to_vec()));
                }
                let Some(blob) = data.blobs.get(digest) else {
                    return Ok(reply(404, vec![], b"{}".to_vec()));
                };
                if method == "HEAD" {
                    return Ok(reply(
                        200,
                        vec![
                            ("Content-Length", blob.len().to_string()),
                            ("Docker-Content-Digest", digest.to_string()),
                            ("Accept-Ranges", "bytes".into()),
                        ],
                        Vec::new(),
                    ));
                }
                if method == "GET" {
                    let range_hdr = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("range"))
                        .map(|(_, v)| v.clone());
                    self.reg
                        .blob_gets
                        .borrow_mut()
                        .push((digest.to_string(), range_hdr.clone()));
                    if let Some(r) = range_hdr {
                        let spec = r.strip_prefix("bytes=").ok_or(Errno::EINVAL)?;
                        let (s, e) = spec.split_once('-').ok_or(Errno::EINVAL)?;
                        let start: usize = s.parse().map_err(|_| Errno::EINVAL)?;
                        let end: usize = e.parse().map_err(|_| Errno::EINVAL)?;
                        if end >= blob.len() || start > end {
                            return Ok(reply(416, vec![], Vec::new()));
                        }
                        let mut slice = blob[start..=end].to_vec();
                        let rlen = slice.len() as u64;
                        if rlen > self.reg.max_range_len.get() {
                            self.reg.max_range_len.set(rlen);
                        }
                        if self.reg.corrupt_next_range.replace(false) && !slice.is_empty() {
                            slice[0] ^= 0x5a;
                        }
                        return Ok(reply(
                            206,
                            vec![
                                ("Content-Length", slice.len().to_string()),
                                (
                                    "Content-Range",
                                    format!("bytes {start}-{end}/{}", blob.len()),
                                ),
                                ("Docker-Content-Digest", digest.to_string()),
                            ],
                            slice,
                        ));
                    }
                    return Ok(reply(
                        200,
                        vec![
                            ("Content-Length", blob.len().to_string()),
                            ("Docker-Content-Digest", digest.to_string()),
                        ],
                        blob.clone(),
                    ));
                }
            }

            // Referrers GET /v2/<repo>/referrers/<digest>?artifactType=...
            if let Some((repo, subject_digest)) = rest.rsplit_once("/referrers/")
                && method == "GET"
            {
                let filter_at = parse_query_param(query, "artifactType");
                let data = self.reg.inner.borrow();
                let mut descs: Vec<OciDescriptor> = Vec::new();
                let mut keys: Vec<_> = data
                    .manifests
                    .iter()
                    .filter(|((r, _), m)| {
                        r == repo && m.subject_digest.as_deref() == Some(subject_digest)
                    })
                    .collect();
                keys.sort_by(|a, b| a.0.1.cmp(&b.0.1));
                for ((_, d), m) in keys {
                    if let Some(ref want) = filter_at
                        && m.artifact_type.as_deref() != Some(want.as_str())
                    {
                        continue;
                    }
                    descs.push(OciDescriptor {
                        media_type: m.media_type.clone(),
                        digest: d.clone(),
                        size: m.bytes.len() as u64,
                        urls: None,
                        annotations: m.annotations.clone(),
                        artifact_type: m.artifact_type.clone(),
                        platform: None,
                        data: None,
                    });
                }
                let index = OciImageIndex {
                    schema_version: 2,
                    media_type: Some(OCI_IMAGE_INDEX_MEDIA_TYPE.into()),
                    artifact_type: None,
                    manifests: descs,
                    subject: None,
                    annotations: None,
                };
                let mut hdrs = vec![("Content-Type", OCI_IMAGE_INDEX_MEDIA_TYPE.into())];
                if filter_at.is_some() {
                    hdrs.push(("OCI-Filters-Applied", "artifactType".into()));
                }
                return Ok(reply(200, hdrs, serde_json::to_vec(&index).unwrap()));
            }

            // Manifests HEAD/GET/PUT /v2/<repo>/manifests/<ref>
            if let Some((repo, reference)) = rest.rsplit_once("/manifests/") {
                if method == "PUT" {
                    let digest = format!("sha256:{}", digest_to_hex(&sha256(body)));
                    if reference.starts_with("sha256:") && reference != digest {
                        return Ok(reply(400, vec![], b"digest mismatch".to_vec()));
                    }
                    let mt = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| "application/vnd.oci.image.manifest.v1+json".into());
                    let val: serde_json::Value =
                        os_image::parse(body).map_err(|_| Errno::EINVAL)?;
                    let (artifact_type, subject_digest, annotations) =
                        if val.get("manifests").is_some() {
                            let idx: OciImageIndex =
                                serde_json::from_value(val).map_err(|_| Errno::EINVAL)?;
                            (
                                idx.artifact_type,
                                idx.subject.map(|s| s.digest),
                                idx.annotations,
                            )
                        } else {
                            let m: OciImageManifest =
                                serde_json::from_value(val).map_err(|_| Errno::EINVAL)?;
                            (
                                m.effective_artifact_type().map(str::to_owned),
                                m.subject.map(|s| s.digest),
                                m.annotations,
                            )
                        };
                    let mut data = self.reg.inner.borrow_mut();
                    data.manifests.insert(
                        (repo.to_string(), digest.clone()),
                        StoredManifest {
                            media_type: mt,
                            artifact_type,
                            subject_digest: subject_digest.clone(),
                            annotations,
                            bytes: body.to_vec(),
                        },
                    );
                    if !reference.starts_with("sha256:") {
                        data.tags
                            .insert((repo.to_string(), reference.to_string()), digest.clone());
                    }
                    let mut hdrs = vec![
                        ("Location", format!("/v2/{repo}/manifests/{digest}")),
                        ("Docker-Content-Digest", digest),
                    ];
                    if let Some(sub) = subject_digest {
                        hdrs.push(("OCI-Subject", sub));
                    }
                    return Ok(reply(201, hdrs, Vec::new()));
                }

                let data = self.reg.inner.borrow();
                let resolved_digest = if parse_sha256_digest(reference).is_some() {
                    reference.to_string()
                } else {
                    match data.tags.get(&(repo.to_string(), reference.to_string())) {
                        Some(d) => d.clone(),
                        None => return Ok(reply(404, vec![], b"{}".to_vec())),
                    }
                };
                let Some(m) = data
                    .manifests
                    .get(&(repo.to_string(), resolved_digest.clone()))
                else {
                    return Ok(reply(404, vec![], b"{}".to_vec()));
                };
                let hdrs = vec![
                    ("Content-Type", m.media_type.clone()),
                    ("Content-Length", m.bytes.len().to_string()),
                    ("Docker-Content-Digest", resolved_digest),
                ];
                if method == "HEAD" {
                    return Ok(reply(200, hdrs, Vec::new()));
                }
                if method == "GET" {
                    return Ok(reply(200, hdrs, m.bytes.clone()));
                }
            }

            Ok(reply(404, vec![], b"{}".to_vec()))
        })
    }
}

fn sign_bytes(key: &SigningKey, subject_bytes: &[u8]) -> (Vec<u8>, Trust, String) {
    let key_id = digest(key.verifying_key().as_bytes());
    let sig_json = serde_json::to_vec(&Detached {
        format: "os.signature".into(),
        version: 1,
        key: key_id.clone(),
        signature: hex(&key
            .sign(&signing_message(SIGNING_DOMAIN_OCI_ARTIFACT_V1, subject_bytes).unwrap())
            .to_bytes()),
    })
    .unwrap();
    let mut trust = Trust::default();
    trust
        .keys
        .insert(key_id.clone(), hex(key.verifying_key().as_bytes()));
    (sig_json, trust, key_id)
}

async fn read_file_from_fs<H: cowtree::HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    name: &str,
) -> vfs::Result<Vec<u8>> {
    let cred = root_cred();
    let entry = fs.lookup(&cred, &fs.root(), name).await?;
    let meta = fs.metadata(&cred, &entry.handle).await?;
    let mut ro = OpenOptions::new();
    ro.read(true);
    let open = fs.open(&cred, &entry.handle, &ro).await?;
    let mut out = vec![0u8; meta.size as usize];
    let mut off = 0usize;
    while off < out.len() {
        let n = fs.read_at(&open, &mut out[off..], off as u64).await?;
        if n == 0 {
            break;
        }
        off += n;
    }
    fs.release(&open).await?;
    out.truncate(off);
    Ok(out)
}

async fn write_new_file<H: cowtree::HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    name: &str,
    data: &[u8],
) {
    let cred = root_cred();
    let mut rw = OpenOptions::new();
    rw.read(true).write(true).create_new(true);
    let (_, open) = fs
        .create(&cred, &fs.root(), name, 0o644, &rw)
        .await
        .unwrap();
    fs.write_at(&open, data, WriteAt::Offset(0)).await.unwrap();
    fs.release(&open).await.unwrap();
}

#[test]
fn oci_03_ed25519_referrer_sign_verify_tamper_and_revoke() {
    run(async {
        let reg = MockRegistry::new();
        let client = reg.client("origin");
        let head = Rc::new(MemoryHeadStore::new());
        let packs = Rc::new(MemoryPackStore::new());
        let vol = VolumeId("signed-vol".into());
        CowFs::format_volume(&*head, &*packs, vol.clone(), 0, 0, 0o755, (test_clock())())
            .await
            .unwrap();
        let fs = CowFs::open(
            Rc::clone(&head),
            Rc::clone(&packs),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(test_clock()),
        )
        .await
        .unwrap();
        write_new_file(&fs, "hello.txt", b"signed-payload-v1").await;
        fs.commit_tx_group().await.unwrap();
        fs.close_clean().await.unwrap();

        let pushed = push_cowfs_snapshot(
            &*head,
            &*packs,
            &vol,
            None,
            &client,
            "org/app",
            "v1",
            OciPushOptions::default(),
        )
        .await
        .unwrap();

        let (sub_dig, sub_mt, sub_bytes) = client.get_manifest("org/app", "v1").await.unwrap();
        assert_eq!(sub_dig, pushed.manifest_digest);

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (sig_json, mut trust, key_id) = sign_bytes(&key, &sub_bytes);
        attach_ed25519_signature(
            &client,
            "org/app",
            &sub_dig,
            &sub_mt,
            sub_bytes.len() as u64,
            &sig_json,
        )
        .await
        .unwrap();

        // Trusted verification succeeds.
        let (verified_digest, verified_key) =
            verify_ed25519_referrers(&client, "org/app", "v1", &trust)
                .await
                .unwrap();
        assert_eq!(verified_digest, sub_dig);
        assert_eq!(verified_key, key_id);

        // Untrusted key set fails closed.
        let other_key = SigningKey::from_bytes(&[9u8; 32]);
        let (_, other_trust, _) = sign_bytes(&other_key, &sub_bytes);
        assert!(
            verify_ed25519_referrers(&client, "org/app", "v1", &other_trust)
                .await
                .is_err()
        );

        // Revoked key fails closed.
        trust.revoked.insert(key_id.clone());
        assert!(
            verify_ed25519_referrers(&client, "org/app", "v1", &trust)
                .await
                .is_err()
        );

        // Tampered signature fails closed.
        let reg_tampered = MockRegistry::new();
        let client_t = reg_tampered.client("tamper");
        push_cowfs_snapshot(
            &*head,
            &*packs,
            &vol,
            None,
            &client_t,
            "org/app",
            "v1",
            OciPushOptions::default(),
        )
        .await
        .unwrap();
        let (bad_sig, clean_trust, _) = sign_bytes(&key, b"different-manifest-bytes");
        attach_ed25519_signature(
            &client_t,
            "org/app",
            &sub_dig,
            &sub_mt,
            sub_bytes.len() as u64,
            &bad_sig,
        )
        .await
        .unwrap();
        assert!(
            verify_ed25519_referrers(&client_t, "org/app", "v1", &clean_trust)
                .await
                .is_err()
        );
    });
}

#[test]
fn oci_05_sharded_cowfs_snapshot_mirror_offline_lazy_mount_corruption_and_fork() {
    run(async {
        let head = Rc::new(MemoryHeadStore::new());
        let packs = Rc::new(MemoryPackStore::new());
        let vol = VolumeId("multi-pack-vol".into());
        CowFs::format_volume(&*head, &*packs, vol.clone(), 0, 0, 0o755, (test_clock())())
            .await
            .unwrap();
        let fs = CowFs::open(
            Rc::clone(&head),
            Rc::clone(&packs),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(test_clock()),
        )
        .await
        .unwrap();
        let cred = root_cred();

        // Create 5 files across 5 separate tx-group commits so we produce >= 5 distinct COWP packs!
        let mut expected_files: Vec<(String, Vec<u8>)> = Vec::new();
        for idx in 0..5u8 {
            let name = format!("shard_file_{idx}.bin");
            let mut payload = vec![0u8; 32 * 1024];
            for (i, b) in payload.iter_mut().enumerate() {
                *b = ((i * 13 + usize::from(idx) * 41) & 0xff) as u8;
            }
            write_new_file(&fs, &name, &payload).await;
            fs.commit_tx_group().await.unwrap();
            expected_files.push((name, payload));
        }
        let local_packs = packs.list_packs().await.unwrap();
        assert!(
            local_packs.len() >= 5,
            "expected >= 5 distinct COWP packs, got {}",
            local_packs.len()
        );
        fs.close_clean().await.unwrap();

        // Push to Origin Registry A with max_layers_per_shard = 2 -> sharded OCI Image Index!
        let reg_a = MockRegistry::new();
        let client_a = reg_a.client("origin-a");
        let pushed = push_cowfs_snapshot(
            &*head,
            &*packs,
            &vol,
            None,
            &client_a,
            "team/snap",
            "v1",
            OciPushOptions {
                max_layers_per_shard: 2,
                ..OciPushOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(pushed.media_type, OCI_IMAGE_INDEX_MEDIA_TYPE);
        assert!(
            pushed.shards >= 3,
            "expected >= 3 shards, got {}",
            pushed.shards
        );

        // Verify ZERO byte-format conversion: pack blobs stored in Registry A equal exact raw COWP packs!
        let sample_pid: &PackId = &local_packs[0];
        let local_pack_len = packs.stat_pack(sample_pid).await.unwrap().unwrap();
        let local_pack_bytes = packs
            .read_pack_range(sample_pid, 0, local_pack_len as u32)
            .await
            .unwrap();
        let remote_pack_bytes = client_a
            .get_blob("team/snap", &format!("sha256:{}", sample_pid.0))
            .await
            .unwrap();
        assert_eq!(
            remote_pack_bytes, local_pack_bytes,
            "COWP packs must be stored verbatim"
        );

        // Sign the sharded OCI Image Index on Origin A.
        let (idx_dig, idx_mt, idx_bytes) = client_a.get_manifest("team/snap", "v1").await.unwrap();
        let key = SigningKey::from_bytes(&[42u8; 32]);
        let (sig_json, trust, key_id) = sign_bytes(&key, &idx_bytes);
        attach_ed25519_signature(
            &client_a,
            "team/snap",
            &idx_dig,
            &idx_mt,
            idx_bytes.len() as u64,
            &sig_json,
        )
        .await
        .unwrap();

        // Generically mirror Origin A -> Independent Registry B (with referrers).
        let reg_b = MockRegistry::new();
        let client_b = reg_b.client("mirror-b");
        let mirrored_digest = mirror_oci_artifact(
            &client_a,
            "team/snap",
            "v1",
            &client_b,
            "mirror/snap",
            "mirrored",
            true,
        )
        .await
        .unwrap();
        assert_eq!(mirrored_digest, idx_dig);

        // SHUT DOWN Origin Registry A completely! Any call to A now fails with ENOTCONN.
        reg_a.offline.set(true);
        assert_eq!(
            client_a.get_manifest("team/snap", "v1").await.unwrap_err(),
            Errno::ENOTCONN
        );

        // Verify Ed25519 referrer signature directly on Mirror B while Origin A is offline!
        let (ver_dig, ver_key) =
            verify_ed25519_referrers(&client_b, "mirror/snap", "mirrored", &trust)
                .await
                .unwrap();
        assert_eq!(ver_dig, idx_dig);
        assert_eq!(ver_key, key_id);

        // Reset Mirror B blob-get telemetry and open lazy RO mount from Mirror B ONLY.
        reg_b.blob_gets.borrow_mut().clear();
        let pack_digest_set: HashSet<String> = local_packs
            .iter()
            .map(|p| format!("sha256:{}", p.0))
            .collect();

        let mounted = open_oci_snapshot_cowfs(
            reg_b.client("mirror-b"),
            "mirror/snap",
            "mirrored",
            CowFsConfig::local_native(test_clock()),
        )
        .await
        .expect("lazy mount from independent mirror succeeds while origin is offline");

        // ZERO COWP data packs downloaded at mount time!
        let pack_fetches_at_mount = reg_b
            .blob_gets
            .borrow()
            .iter()
            .filter(|(d, _)| pack_digest_set.contains(d))
            .count();
        assert_eq!(
            pack_fetches_at_mount, 0,
            "0 COWP packs may be fetched at mount"
        );

        // Immutable RO enforcement.
        assert_eq!(mounted.capabilities().writer_model, WriterModel::Immutable);
        assert_eq!(
            mounted
                .mkdir(&cred, &mounted.root(), "nope", 0o755)
                .await
                .unwrap_err(),
            Errno::EROFS
        );

        // Read files across multiple shards via bounded Range reads!
        for (name, expected) in &expected_files[..4] {
            let got = read_file_from_fs(&mounted, name).await.unwrap();
            assert_eq!(&got, expected, "mismatch reading {name}");
        }
        let range_fetches: Vec<_> = reg_b
            .blob_gets
            .borrow()
            .iter()
            .filter(|(d, r)| pack_digest_set.contains(d) && r.is_some())
            .cloned()
            .collect();
        assert!(
            !range_fetches.is_empty(),
            "expected lazy Range fetches for COWP packs"
        );
        assert!(
            reg_b.max_range_len.get() <= 1024 * 1024,
            "every Range fetch must be <= 1 MiB"
        );

        // Corruption detection: flip 1 bit in Mirror B's next Range response for uncached file #4 -> EIO!
        reg_b.corrupt_next_range.set(true);
        assert_eq!(
            read_file_from_fs(&mounted, &expected_files[4].0)
                .await
                .unwrap_err(),
            Errno::EIO
        );
        // Clean retry succeeds!
        assert_eq!(
            read_file_from_fs(&mounted, &expected_files[4].0)
                .await
                .unwrap(),
            expected_files[4].1
        );

        // cowfsck passes on the lazily mounted mirror snapshot.
        let hs = mounted.head_store_rc();
        let ps = mounted.pack_store_rc();
        let fsck = verify_volume(&*hs, &*ps, mounted.volume_id())
            .await
            .unwrap();
        assert!(fsck.ok, "fsck errors: {:?}", fsck.errors);

        // Pull into a fresh local cowfs store with Ed25519 trust verification -> O(1) fork -> mutate!
        let local_head = Rc::new(MemoryHeadStore::new());
        let local_packs_store = Rc::new(MemoryPackStore::new());
        let pulled_vol = VolumeId("pulled-local".into());
        let pull_resp = pull_cowfs_snapshot(
            &client_b,
            "mirror/snap",
            "mirrored",
            &*local_head,
            &*local_packs_store,
            &pulled_vol,
            Some("base"),
            (test_clock())(),
            Some(&trust),
        )
        .await
        .expect("verified pull from mirror succeeds");
        assert_eq!(pull_resp.verified_key.as_deref(), Some(key_id.as_str()));
        assert!(
            verify_volume_strict(&*local_head, &*local_packs_store, &pulled_vol)
                .await
                .unwrap()
                .ok
        );

        // O(1) fork and mutate!
        let pulled_fs = CowFs::open(
            Rc::clone(&local_head),
            Rc::clone(&local_packs_store),
            pulled_vol.clone(),
            CowFsOpenMode::ReadOnly,
            CowFsConfig::local_native(test_clock()),
        )
        .await
        .unwrap();
        let forked_vol = VolumeId("forked-rw".into());
        pulled_fs
            .fork_volume(Some("base"), forked_vol.clone(), false)
            .await
            .unwrap();
        pulled_fs.close_clean().await.unwrap();

        let fork_fs = CowFs::open(
            Rc::clone(&local_head),
            Rc::clone(&local_packs_store),
            forked_vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(test_clock()),
        )
        .await
        .unwrap();
        write_new_file(&fork_fs, "mutated.txt", b"forked-change").await;
        fork_fs.commit_tx_group().await.unwrap();
        assert_eq!(
            read_file_from_fs(&fork_fs, "mutated.txt").await.unwrap(),
            b"forked-change"
        );
        assert_eq!(
            read_file_from_fs(&fork_fs, &expected_files[0].0)
                .await
                .unwrap(),
            expected_files[0].1
        );
        fork_fs.close_clean().await.unwrap();
        assert!(
            verify_volume_strict(&*local_head, &*local_packs_store, &forked_vol)
                .await
                .unwrap()
                .ok
        );

        // Also check the shard manifest layer media type uses COWFS_PACK_LAYER_MEDIA_TYPE.
        let index: OciImageIndex = os_image::parse(&idx_bytes).unwrap();
        let (_sd, _smt, shard0_bytes) = client_b
            .get_manifest("mirror/snap", &index.manifests[0].digest)
            .await
            .unwrap();
        let shard0: OciImageManifest = os_image::parse(&shard0_bytes).unwrap();
        assert!(
            shard0
                .layers
                .iter()
                .any(|l| l.media_type == COWFS_PACK_LAYER_MEDIA_TYPE)
        );
    });
}

struct VecStream(Vec<u8>, usize);
impl StreamSink for VecStream {
    fn write_chunk<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        })
    }
}
impl StreamSource for VecStream {
    fn read_chunk<'a>(&'a mut self, bytes: &'a mut [u8]) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let rem = self.0.len().saturating_sub(self.1);
            let n = rem.min(bytes.len());
            bytes[..n].copy_from_slice(&self.0[self.1..self.1 + n]);
            self.1 += n;
            Ok(n)
        })
    }
}

#[test]
fn oci_08_volume_device_ioctls_work_without_new_syscalls_and_reject_unknown_fields() {
    run(async {
        // Verify strict deny_unknown_fields on all 4 ioctl request structs.
        assert!(
            serde_json::from_str::<CowfsOciPushReq>(r#"{"reference":"a/b:v1","extra":1}"#).is_err()
        );
        assert!(
            serde_json::from_str::<CowfsOciPullReq>(r#"{"reference":"a/b:v1","extra":1}"#).is_err()
        );
        assert!(serde_json::from_str::<CowfsOciImportReq>(r#"{"stream_fd":0,"extra":1}"#).is_err());
        assert!(serde_json::from_str::<CowfsOciExportReq>(r#"{"stream_fd":1,"extra":1}"#).is_err());

        // Exercise COWFS_IOC_OCI_EXPORT -> COWFS_IOC_OCI_IMPORT -> COWFS_IOC_OCI_PUSH -> COWFS_IOC_OCI_PULL
        // via VolumeDevice (exact ioctl path used by in-OS `cowfs` CLI!).
        let head = Rc::new(MemoryHeadStore::new());
        let packs = Rc::new(MemoryPackStore::new());
        let vol = VolumeId("ioctl-src".into());
        CowFs::format_volume(&*head, &*packs, vol.clone(), 0, 0, 0o755, (test_clock())())
            .await
            .unwrap();
        let fs = Rc::new(
            CowFs::open(
                Rc::clone(&head),
                Rc::clone(&packs),
                vol.clone(),
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                CowFsConfig::local_native(test_clock()),
            )
            .await
            .unwrap(),
        );
        write_new_file(&fs, "note.txt", b"via-ioctl").await;
        fs.commit_tx_group().await.unwrap();

        let dev = CowFsVolumeDevice::from_mounted(Rc::clone(&fs));
        assert!(vfs::vblk::is_cowfs_or_blk_ioctl(
            cowfs_ioctl::COWFS_IOC_OCI_PUSH
        ));
        assert!(vfs::vblk::is_cowfs_or_blk_ioctl(
            cowfs_ioctl::COWFS_IOC_OCI_PULL
        ));
        assert!(vfs::vblk::is_cowfs_or_blk_ioctl(
            cowfs_ioctl::COWFS_IOC_OCI_IMPORT
        ));
        assert!(vfs::vblk::is_cowfs_or_blk_ioctl(
            cowfs_ioctl::COWFS_IOC_OCI_EXPORT
        ));

        // 1. Export tar+gzip via VolumeDevice::cowfs_oci_export
        let mut sink = VecStream(Vec::new(), 0);
        let exp_req = CowfsOciExportReq {
            stream_fd: 1,
            snapshot: None,
            uncompressed: false,
        };
        let exp_resp: CowfsOciExportResp =
            vfs::vblk::VolumeDevice::cowfs_oci_export(&dev, &exp_req, &mut sink)
                .await
                .unwrap();
        assert!(!sink.0.is_empty());

        // 2. Import into a fresh volume via VolumeDevice::cowfs_oci_import
        let imp_dev = CowFsVolumeDevice::unmounted(
            VolumeId("ioctl-imp".into()),
            Rc::new(MemoryHeadStore::new()),
            Rc::new(MemoryPackStore::new()),
            WriterModel::Local,
            Durability::TreeCommit,
            test_clock(),
        );
        let imp_req = CowfsOciImportReq {
            stream_fd: 0,
            snapshot_name: Some("imported".into()),
            target_volume: None,
            strip_setuid: false,
            expected_diff_id: Some(exp_resp.diff_id.clone()),
        };
        let mut src_stream = VecStream(sink.0, 0);
        let imp_resp: CowfsOciImportResp =
            vfs::vblk::VolumeDevice::cowfs_oci_import(&imp_dev, &imp_req, &mut src_stream)
                .await
                .unwrap();
        assert_eq!(imp_resp.diff_id, exp_resp.diff_id);
        assert_eq!(imp_resp.snapshot.as_deref(), Some("imported"));

        // 3. Push via VolumeDevice::cowfs_oci_push and pull via VolumeDevice::cowfs_oci_pull
        let reg = MockRegistry::new();
        let push_req = CowfsOciPushReq {
            reference: "ioctl/test:v1".into(),
            snapshot: None,
            tar: false,
            max_layers_per_shard: None,
        };
        let push_resp: CowfsOciPushResp =
            vfs::vblk::VolumeDevice::cowfs_oci_push(&dev, &push_req, reg.transport("reg"))
                .await
                .unwrap();
        assert_eq!(push_resp.repo, "ioctl/test");

        let pull_head = Rc::new(MemoryHeadStore::new());
        let pull_packs = Rc::new(MemoryPackStore::new());
        let pull_dev = CowFsVolumeDevice::unmounted(
            VolumeId("ioctl-pulled".into()),
            Rc::clone(&pull_head),
            Rc::clone(&pull_packs),
            WriterModel::Local,
            Durability::TreeCommit,
            test_clock(),
        );
        let pull_req = CowfsOciPullReq {
            reference: "ioctl/test:v1".into(),
            snapshot_name: Some("pulled".into()),
            target_volume: None,
            trust_json: None,
        };
        let pull_resp: CowfsOciPullResp =
            vfs::vblk::VolumeDevice::cowfs_oci_pull(&pull_dev, &pull_req, reg.transport("reg"))
                .await
                .unwrap();
        assert_eq!(pull_resp.manifest_digest, push_resp.manifest_digest);
        let pulled_fs = CowFs::open(
            pull_head,
            pull_packs,
            VolumeId("ioctl-pulled".into()),
            CowFsOpenMode::ReadOnly,
            CowFsConfig::local_native(test_clock()),
        )
        .await
        .unwrap();
        assert_eq!(
            read_file_from_fs(&pulled_fs, "note.txt").await.unwrap(),
            b"via-ioctl"
        );

        // Ensure VblkRegistry::dispatch_volume_ioctl rejects unprivileged pull/import with EPERM!
        let mut non_root = Cred::root();
        non_root.identity.id = 1000;
        let err = VblkRegistry::dispatch_volume_ioctl(
            &pull_dev,
            Some("vd0"),
            None,
            &non_root,
            true,
            false,
            cowfs_ioctl::COWFS_IOC_OCI_PULL,
            &serde_json::to_vec(&pull_req).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(err, Errno::EPERM);
    });
}
