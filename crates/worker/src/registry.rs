//! OCI Distribution v1.1 Edge Router (`Boundary::Registry`, version 1) over the shared
//! per-tenant R2 pack store (`t/{tenant}/packs/{sha256}`) and `StorageVolume` DO SQLite v2.

use crate::{
    auth,
    pack_gateway::{charge_slices, paced_stream_io},
    registry_do::{RegistryAction, RegistryCommand, RegistryReply, UploadChunkMeta},
    resources::{self, IoRequest},
    storage_do::{Grant, manifest_key, pack_key, upload_chunk_key},
    streams,
};
use abi::{
    Errno,
    auth_v2::RemoteScope,
    registry::{
        OCI_IMAGE_INDEX_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE, OciAccessEntry, OciDescriptor,
        OciErrorBody, OciErrorEntry, OciImageIndex, OciImageManifest, OciTagsList,
        OciTokenResponse, REGISTRY_DEFAULT_MAX_BLOB_BYTES, REGISTRY_MANIFEST_MAX_BYTES,
        REGISTRY_TAGS_DEFAULT_N, REGISTRY_TAGS_MAX_N, REGISTRY_TOKEN_TTL_SECS, parse_sha256_digest,
        valid_repo_name, valid_tag,
    },
    sha256::ResumableSha256,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cowtree::{PackId, digest_from_hex, digest_to_hex, sha256};
use futures_util::{StreamExt, TryStreamExt};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::{cell::RefCell, rc::Rc};
use worker::*;

/// Maximum buffered sub-part size flushed to R2 during streaming/chunked uploads (4 MiB).
const UPLOAD_PART_MAX_BYTES: usize = 4 * 1024 * 1024;
const JWT_ISSUER: &str = "os-registry";
const JWT_HEADER_B64: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RegistryJwtClaims {
    iss: String,
    sub: String,
    aud: String,
    uid: u32,
    iat: u64,
    exp: u64,
    jti: String,
    access: Vec<OciAccessEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cred_hash: Option<String>,
}

#[derive(Clone, Debug)]
struct LiveBearer {
    claims: RegistryJwtClaims,
    grant: Grant,
}

impl LiveBearer {
    fn io_req(&self, write: bool, bytes: u64) -> Option<IoRequest> {
        let ns = self.claims.ns.as_ref().filter(|s| !s.is_empty())?;
        let hash = self.claims.cred_hash.as_ref().filter(|s| !s.is_empty())?;
        Some(IoRequest {
            ns: ns.clone(),
            token: hash.clone(),
            token_is_hash: true,
            pid: None,
            write,
            bytes,
        })
    }
}

#[derive(Debug)]
enum RegErr {
    Unauthorized {
        scope: Option<String>,
    },
    Denied,
    Oci {
        status: u16,
        code: &'static str,
        message: String,
    },
    Errno(Errno),
}

type RResult<T> = std::result::Result<T, RegErr>;

fn io_err(_: worker::Error) -> RegErr {
    RegErr::Oci {
        status: 500,
        code: "UNKNOWN",
        message: "internal storage error".into(),
    }
}

fn oci_err(status: u16, code: &'static str, msg: impl Into<String>) -> RegErr {
    RegErr::Oci {
        status,
        code,
        message: msg.into(),
    }
}

fn header(req: &Request, name: &str) -> RResult<Option<String>> {
    req.headers().get(name).map_err(io_err)
}

fn req_host(url: &Url) -> String {
    let host = url.host_str().unwrap_or("localhost");
    match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    }
}

fn jwt_signing_key(env: &Env) -> RResult<[u8; 32]> {
    let secret = env.secret("SESSION_SECRET").map_err(io_err)?.to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| oci_err(500, "UNKNOWN", "invalid signing key"))?;
    mac.update(b"os.registry.bearer.v1");
    let out: [u8; 32] = mac.finalize().into_bytes().into();
    Ok(out)
}

fn sign_jwt(env: &Env, claims: &RegistryJwtClaims) -> RResult<String> {
    let key = jwt_signing_key(env)?;
    let payload_json = serde_json::to_vec(claims).map_err(|_| oci_err(500, "UNKNOWN", "encode"))?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
    let signing_input = format!("{JWT_HEADER_B64}.{payload_b64}");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|_| oci_err(500, "UNKNOWN", "hmac init"))?;
    mac.update(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

fn verify_jwt(env: &Env, token: &str) -> RResult<RegistryJwtClaims> {
    let mut parts = token.split('.');
    let (Some(hdr), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(RegErr::Unauthorized { scope: None });
    };
    if hdr != JWT_HEADER_B64 {
        return Err(RegErr::Unauthorized { scope: None });
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| RegErr::Unauthorized { scope: None })?;
    let key = jwt_signing_key(env)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|_| oci_err(500, "UNKNOWN", "hmac init"))?;
    mac.update(hdr.as_bytes());
    mac.update(b".");
    mac.update(payload.as_bytes());
    mac.verify_slice(&sig_bytes)
        .map_err(|_| RegErr::Unauthorized { scope: None })?;
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| RegErr::Unauthorized { scope: None })?;
    let claims: RegistryJwtClaims =
        serde_json::from_slice(&payload_bytes).map_err(|_| RegErr::Unauthorized { scope: None })?;
    let now = auth::now();
    if claims.iss != JWT_ISSUER || claims.exp <= now || claims.iat > now.saturating_add(30) {
        return Err(RegErr::Unauthorized { scope: None });
    }
    Ok(claims)
}

fn extract_bearer(req: &Request) -> RResult<Option<String>> {
    let Some(raw) = header(req, "Authorization")? else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.len() > 7 && trimmed[..7].eq_ignore_ascii_case("bearer ") {
        let tok = trimmed[7..].trim();
        if !tok.is_empty() {
            return Ok(Some(tok.to_string()));
        }
    }
    Ok(None)
}

fn jwt_grants_action(claims: &RegistryJwtClaims, repo: &str, push: bool) -> bool {
    let needed = if push { "push" } else { "pull" };
    claims.access.iter().any(|entry| {
        entry.kind == "repository"
            && entry.name == repo
            && entry
                .actions
                .iter()
                .any(|a| a == needed || a == "*" || (push && a == "delete"))
    })
}

async fn verify_bearer_live(
    req: &Request,
    env: &Env,
    repo: Option<&str>,
    push: bool,
    from_repo: Option<&str>,
) -> RResult<LiveBearer> {
    let scope_hint = repo.map(|r| {
        let actions = if push { "pull,push" } else { "pull" };
        format!("repository:{r}:{actions}")
    });
    let Some(tok) = extract_bearer(req)? else {
        return Err(RegErr::Unauthorized { scope: scope_hint });
    };
    let claims = verify_jwt(env, &tok).map_err(|_| RegErr::Unauthorized {
        scope: scope_hint.clone(),
    })?;
    let body = json!({
        "uid": claims.uid,
        "tenant": claims.sub,
        "ns": claims.ns,
        "cred_hash": claims.cred_hash,
        "repo": repo,
        "push": push,
        "from_repo": from_repo,
    });
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(io_err)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));
    let sub = Request::new_with_init(
        "https://authority/internal/service-auth/verify-registry-bearer",
        &init,
    )
    .map_err(io_err)?;
    let mut resp = env
        .durable_object("AUTHORITY")
        .map_err(io_err)?
        .get_by_name("filesystem")
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)?;
    match resp.status_code() {
        200 => {}
        401 => {
            return Err(RegErr::Unauthorized { scope: scope_hint });
        }
        403 => return Err(RegErr::Denied),
        _ => return Err(oci_err(500, "UNKNOWN", "authority verification failed")),
    }
    let grant: Grant = resp.json().await.map_err(io_err)?;
    if let (Some(ns), Some(hash)) = (&claims.ns, &claims.cred_hash)
        && !ns.is_empty()
        && !hash.is_empty()
    {
        resources::checked_io(
            env,
            IoRequest {
                ns: ns.clone(),
                token: hash.clone(),
                token_is_hash: true,
                pid: None,
                write: false,
                bytes: 0,
            },
        )
        .await
        .map_err(|_| RegErr::Unauthorized {
            scope: scope_hint.clone(),
        })?;
    }
    // Check JWT's own access[] claims for the requested repo & cross-repo mount source.
    if let Some(r) = repo
        && !jwt_grants_action(&claims, r, push)
    {
        return Err(RegErr::Denied);
    }
    if let Some(src) = from_repo
        && !jwt_grants_action(&claims, src, false)
    {
        return Err(RegErr::Denied);
    }
    Ok(LiveBearer { claims, grant })
}

/// Re-verify the bearer token inside `StorageVolume` DO right before committing SQLite metadata
/// (eliminating TOCTOU across cold-start / async `ensure_ready`).
pub(crate) async fn revalidate_internal_bearer(
    req: &Request,
    env: &Env,
    cmd: &RegistryCommand,
) -> crate::storage_do::VResult<Grant> {
    let (repo, push, from_repo) = cmd.action.auth_context();
    let live = verify_bearer_live(req, env, repo, push, from_repo)
        .await
        .map_err(|e| match e {
            RegErr::Unauthorized { .. } | RegErr::Denied => Errno::EACCES,
            RegErr::Errno(er) => er,
            RegErr::Oci { .. } => Errno::EIO,
        })?;
    if live.grant.tenant != cmd.grant.tenant || live.grant.owner != cmd.grant.owner {
        return Err(Errno::EACCES);
    }
    Ok(live.grant)
}

async fn storage_call(
    req: &Request,
    env: &Env,
    grant: &Grant,
    action: RegistryAction,
) -> RResult<RegistryReply> {
    let cmd = RegistryCommand {
        grant: grant.clone(),
        action,
    };
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(io_err)?;
    if let Some(auth_hdr) = header(req, "Authorization")? {
        headers.set("Authorization", &auth_hdr).map_err(io_err)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(
            serde_json::to_string(&cmd)
                .map_err(|_| oci_err(500, "UNKNOWN", "encode"))?
                .into(),
        ));
    let sub = Request::new_with_init("https://storage/internal/registry", &init).map_err(io_err)?;
    let mut resp = env
        .durable_object("STORAGE")
        .map_err(io_err)?
        .get_by_name(&format!("tenant:{}", grant.tenant))
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)?;
    if resp.status_code() >= 400 {
        let errno = resp
            .json::<abi::remote_volume::VolumeError>()
            .await
            .map(|e| e.errno)
            .unwrap_or(Errno::EIO);
        return Err(RegErr::Errno(errno));
    }
    resp.json().await.map_err(io_err)
}

fn max_blob_bytes(env: &Env) -> u64 {
    env.var("REGISTRY_MAX_BLOB_BYTES")
        .ok()
        .and_then(|v| v.to_string().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(REGISTRY_DEFAULT_MAX_BLOB_BYTES)
}

fn format_rfc3339(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    let sec = rem % 60;
    // Howard Hinnant's civil-from-days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[derive(Debug, PartialEq, Eq)]
enum V2Route {
    Base,
    Token,
    TagsList { repo: String },
    BlobUploadsStart { repo: String },
    BlobUpload { repo: String, uuid: String },
    Blob { repo: String, digest: String },
    Manifest { repo: String, reference: String },
    Referrers { repo: String, digest: String },
}

fn parse_v2_route(path: &str) -> RResult<V2Route> {
    if path == "/v2" || path == "/v2/" {
        return Ok(V2Route::Base);
    }
    if path == "/v2/token" {
        return Ok(V2Route::Token);
    }
    let Some(rest) = path.strip_prefix("/v2/") else {
        return Err(oci_err(404, "NAME_UNKNOWN", "unknown registry route"));
    };
    let check_repo = |repo: &str| -> RResult<String> {
        if valid_repo_name(repo) {
            Ok(repo.to_string())
        } else {
            Err(oci_err(400, "NAME_INVALID", "invalid repository name"))
        }
    };
    if let Some(repo) = rest.strip_suffix("/tags/list") {
        return Ok(V2Route::TagsList {
            repo: check_repo(repo)?,
        });
    }
    if let Some(repo) = rest
        .strip_suffix("/blobs/uploads/")
        .or_else(|| rest.strip_suffix("/blobs/uploads"))
    {
        return Ok(V2Route::BlobUploadsStart {
            repo: check_repo(repo)?,
        });
    }
    if let Some((repo, uuid)) = rest.rsplit_once("/blobs/uploads/")
        && !uuid.is_empty()
        && !uuid.contains('/')
    {
        return Ok(V2Route::BlobUpload {
            repo: check_repo(repo)?,
            uuid: uuid.to_string(),
        });
    }
    if let Some((repo, digest)) = rest.rsplit_once("/blobs/")
        && !digest.is_empty()
        && !digest.contains('/')
    {
        return Ok(V2Route::Blob {
            repo: check_repo(repo)?,
            digest: digest.to_string(),
        });
    }
    if let Some((repo, reference)) = rest.rsplit_once("/manifests/")
        && !reference.is_empty()
        && !reference.contains('/')
    {
        return Ok(V2Route::Manifest {
            repo: check_repo(repo)?,
            reference: reference.to_string(),
        });
    }
    if let Some((repo, digest)) = rest.rsplit_once("/referrers/")
        && !digest.is_empty()
        && !digest.contains('/')
    {
        return Ok(V2Route::Referrers {
            repo: check_repo(repo)?,
            digest: digest.to_string(),
        });
    }
    Err(oci_err(404, "NAME_UNKNOWN", "unsupported registry path"))
}

fn with_v2_headers(mut resp: Response) -> Result<Response> {
    let headers = Headers::new();
    for (k, v) in resp.headers().entries() {
        headers.append(&k, &v)?;
    }
    headers.set("Docker-Distribution-API-Version", "registry/2.0")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    resp = resp.with_headers(headers);
    Ok(resp)
}

fn error_to_response(err: RegErr, url: &Url) -> Result<Response> {
    match err {
        RegErr::Unauthorized { scope } => {
            let origin = url.origin().ascii_serialization();
            let host = req_host(url);
            let mut challenge = format!("Bearer realm=\"{origin}/v2/token\",service=\"{host}\"");
            if let Some(s) = scope {
                challenge.push_str(&format!(",scope=\"{s}\""));
            }
            let body = OciErrorBody {
                errors: vec![OciErrorEntry {
                    code: "UNAUTHORIZED".into(),
                    message: "authentication required".into(),
                    detail: None,
                }],
            };
            let mut resp = Response::from_json(&body)?.with_status(401);
            resp.headers_mut().set("WWW-Authenticate", &challenge)?;
            with_v2_headers(resp)
        }
        RegErr::Denied => {
            let body = OciErrorBody {
                errors: vec![OciErrorEntry {
                    code: "DENIED".into(),
                    message: "requested access to the resource is denied".into(),
                    detail: None,
                }],
            };
            with_v2_headers(Response::from_json(&body)?.with_status(403))
        }
        RegErr::Oci {
            status,
            code,
            message,
        } => {
            let body = OciErrorBody {
                errors: vec![OciErrorEntry {
                    code: code.into(),
                    message,
                    detail: None,
                }],
            };
            with_v2_headers(Response::from_json(&body)?.with_status(status))
        }
        RegErr::Errno(errno) => {
            let (status, code) = match errno {
                Errno::EACCES | Errno::EPERM => (403, "DENIED"),
                Errno::ENOENT => (404, "BLOB_UNKNOWN"),
                Errno::EBUSY => (409, "DENIED"),
                Errno::EFBIG => (413, "SIZE_INVALID"),
                Errno::ERANGE => (416, "RANGE_INVALID"),
                Errno::EDQUOT => (507, "DENIED"),
                Errno::EAGAIN => (429, "TOOMANYREQUESTS"),
                Errno::EPROTONOSUPPORT => (503, "UNSUPPORTED"),
                Errno::EINVAL => (400, "UNSUPPORTED"),
                _ => (500, "UNKNOWN"),
            };
            let body = OciErrorBody {
                errors: vec![OciErrorEntry {
                    code: code.into(),
                    message: errno.text().into(),
                    detail: Some(json!({ "errno": errno })),
                }],
            };
            let mut resp = Response::from_json(&body)?.with_status(status);
            resp.headers_mut()
                .set("X-OS-Errno", &format!("{errno:?}"))?;
            with_v2_headers(resp)
        }
    }
}

pub async fn gateway(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    match route(&mut req, &url, env).await {
        Ok(resp) => with_v2_headers(resp),
        Err(err) => error_to_response(err, &url),
    }
}

async fn route(req: &mut Request, url: &Url, env: &Env) -> RResult<Response> {
    let route = parse_v2_route(url.path())?;
    let method = req.method();
    match (method, route) {
        (Method::Get, V2Route::Token) => handle_token(req, url, env).await,
        (Method::Get | Method::Head, V2Route::Base) => {
            let _live = verify_bearer_live(req, env, None, false, None).await?;
            let resp = if req.method() == Method::Head {
                Response::empty().map_err(io_err)?
            } else {
                Response::from_json(&json!({})).map_err(io_err)?
            };
            Ok(resp.with_status(200))
        }
        (Method::Head | Method::Get, V2Route::Blob { repo, digest }) => {
            handle_blob_get(req, env, &repo, &digest).await
        }
        (Method::Delete, V2Route::Blob { repo, digest }) => {
            handle_blob_delete(req, env, &repo, &digest).await
        }
        (Method::Post, V2Route::BlobUploadsStart { repo }) => {
            handle_upload_start(req, url, env, &repo).await
        }
        (Method::Get, V2Route::BlobUpload { repo, uuid }) => {
            handle_upload_status(req, env, &repo, &uuid).await
        }
        (Method::Patch, V2Route::BlobUpload { repo, uuid }) => {
            handle_upload_patch(req, env, &repo, &uuid).await
        }
        (Method::Put, V2Route::BlobUpload { repo, uuid }) => {
            handle_upload_finalize(req, url, env, &repo, &uuid).await
        }
        (Method::Delete, V2Route::BlobUpload { repo, uuid }) => {
            handle_upload_delete(req, env, &repo, &uuid).await
        }
        (Method::Head | Method::Get, V2Route::Manifest { repo, reference }) => {
            handle_manifest_get(req, env, &repo, &reference).await
        }
        (Method::Put, V2Route::Manifest { repo, reference }) => {
            handle_manifest_put(req, env, &repo, &reference).await
        }
        (Method::Delete, V2Route::Manifest { repo, reference }) => {
            handle_manifest_delete(req, env, &repo, &reference).await
        }
        (Method::Get, V2Route::TagsList { repo }) => handle_tags_list(req, url, env, &repo).await,
        (Method::Get, V2Route::Referrers { repo, digest }) => {
            handle_referrers(req, url, env, &repo, &digest).await
        }
        _ => Err(oci_err(405, "UNSUPPORTED", "method not allowed")),
    }
}

async fn handle_token(req: &Request, url: &Url, env: &Env) -> RResult<Response> {
    let service = url
        .query_pairs()
        .find(|(k, _)| k == "service")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| req_host(url));

    let mut raw_scopes: Vec<String> = Vec::new();
    for (k, v) in url.query_pairs() {
        if k == "scope" {
            for part in v.split_whitespace() {
                if !part.is_empty() {
                    raw_scopes.push(part.to_string());
                }
            }
        }
    }

    #[derive(Deserialize)]
    struct AuthGrantReply {
        tenant: String,
        #[serde(default)]
        ns: Option<String>,
        uid: u32,
        #[serde(default)]
        cred_hash: Option<String>,
        scope: RemoteScope,
    }

    let auth_hdr = header(req, "Authorization")?;
    let proc_tok = header(req, "X-Process-Token")?;
    let grant: AuthGrantReply = if let Some(ref raw_auth) = auth_hdr
        && raw_auth.len() > 6
        && raw_auth[..6].eq_ignore_ascii_case("basic ")
    {
        // Rate-limit HTTP Basic logins whenever `LOGIN_LIMIT` is bound.
        if let Ok(limiter) = env.rate_limiter("LOGIN_LIMIT") {
            let ip = header(req, "CF-Connecting-IP")?.unwrap_or_else(|| "local".into());
            let allowed = limiter
                .limit(format!("login:{ip}"))
                .await
                .map_err(io_err)?
                .success;
            if !allowed {
                return Err(oci_err(
                    429,
                    "TOOMANYREQUESTS",
                    "too many authentication attempts",
                ));
            }
        }
        let decoded = STANDARD
            .decode(raw_auth[6..].trim())
            .map_err(|_| RegErr::Unauthorized { scope: None })?;
        let text = String::from_utf8(decoded).map_err(|_| RegErr::Unauthorized { scope: None })?;
        let Some((username, password)) = text.split_once(':') else {
            return Err(RegErr::Unauthorized { scope: None });
        };
        let asked_tenant = header(req, "X-OS-Tenant")?;
        let body = json!({
            "username": username,
            "password": password,
            "tenant": asked_tenant,
        });
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(io_err)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.to_string().into()));
        let sub = Request::new_with_init(
            "https://authority/internal/service-auth/verify-registry-basic",
            &init,
        )
        .map_err(io_err)?;
        let mut resp = env
            .durable_object("AUTHORITY")
            .map_err(io_err)?
            .get_by_name("filesystem")
            .map_err(io_err)?
            .fetch_with_request(sub)
            .await
            .map_err(io_err)?;
        match resp.status_code() {
            200 => resp.json().await.map_err(io_err)?,
            403 => return Err(RegErr::Denied),
            _ => return Err(RegErr::Unauthorized { scope: None }),
        }
    } else if let Some(raw_token) = proc_tok.filter(|s| !s.is_empty()) {
        let headers = Headers::new();
        for name in ["Cookie", "X-Process-Token", "X-OS-Instance", "X-OS-Tenant"] {
            if let Some(v) = header(req, name)? {
                headers.set(name, &v).map_err(io_err)?;
            }
        }
        headers
            .set("Content-Type", "application/json")
            .map_err(io_err)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post).with_headers(headers);
        let sub = Request::new_with_init(
            "https://authority/internal/service-auth/verify-registry",
            &init,
        )
        .map_err(io_err)?;
        let mut resp = env
            .durable_object("AUTHORITY")
            .map_err(io_err)?
            .get_by_name("filesystem")
            .map_err(io_err)?
            .fetch_with_request(sub)
            .await
            .map_err(io_err)?;
        if resp.status_code() != 200 {
            return Err(RegErr::Unauthorized { scope: None });
        }
        let g: AuthGrantReply = resp.json().await.map_err(io_err)?;
        let ns = g.ns.clone().ok_or(RegErr::Unauthorized { scope: None })?;
        resources::checked_io(
            env,
            IoRequest {
                ns,
                token: raw_token,
                token_is_hash: false,
                pid: None,
                write: false,
                bytes: 0,
            },
        )
        .await
        .map_err(|_| RegErr::Unauthorized { scope: None })?;
        g
    } else {
        // NEVER mint a registry token from bare browser cookies alone (CSRF protection).
        return Err(RegErr::Unauthorized { scope: None });
    };

    // Intersect requested repository scopes with the live `RemoteScope`.
    let mut granted_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for raw_scope in &raw_scopes {
        let mut parts = raw_scope.splitn(3, ':');
        let (Some(kind), Some(repo), Some(actions_csv)) =
            (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        if kind != "repository" || !valid_repo_name(repo) {
            continue;
        }
        let entry = granted_map.entry(repo.to_string()).or_default();
        for action in actions_csv.split(',') {
            match action.trim() {
                "pull" => {
                    if grant.scope.allows_registry(repo, false)
                        && !entry.iter().any(|a| a == "pull")
                    {
                        entry.push("pull".into());
                    }
                }
                "push" => {
                    if grant.scope.allows_registry(repo, true) && !entry.iter().any(|a| a == "push")
                    {
                        entry.push("push".into());
                    }
                }
                "delete" => {
                    if grant.scope.allows_registry(repo, true) {
                        if !entry.iter().any(|a| a == "push") {
                            entry.push("push".into());
                        }
                        if !entry.iter().any(|a| a == "delete") {
                            entry.push("delete".into());
                        }
                    }
                }
                "*" => {
                    if grant.scope.allows_registry(repo, false)
                        && !entry.iter().any(|a| a == "pull")
                    {
                        entry.push("pull".into());
                    }
                    if grant.scope.allows_registry(repo, true) && !entry.iter().any(|a| a == "push")
                    {
                        entry.push("push".into());
                    }
                }
                _ => {}
            }
        }
    }
    let access: Vec<OciAccessEntry> = granted_map
        .into_iter()
        .filter(|(_, actions)| !actions.is_empty())
        .map(|(name, actions)| OciAccessEntry {
            kind: "repository".into(),
            name,
            actions,
        })
        .collect();

    let now = auth::now();
    let claims = RegistryJwtClaims {
        iss: JWT_ISSUER.into(),
        sub: grant.tenant,
        aud: service,
        uid: grant.uid,
        iat: now,
        exp: now.saturating_add(REGISTRY_TOKEN_TTL_SECS),
        jti: auth::random_token()[..32].to_string(),
        access,
        ns: grant.ns,
        cred_hash: grant.cred_hash,
    };
    let jwt = sign_jwt(env, &claims)?;
    let reply = OciTokenResponse {
        token: jwt.clone(),
        access_token: jwt,
        expires_in: REGISTRY_TOKEN_TTL_SECS,
        issued_at: format_rfc3339(now),
    };
    let mut resp = Response::from_json(&reply).map_err(io_err)?;
    resp.headers_mut()
        .set("Cache-Control", "private, no-store")
        .map_err(io_err)?;
    Ok(resp)
}

async fn handle_blob_get(req: &Request, env: &Env, repo: &str, digest: &str) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), false, None).await?;
    let Some(hex) = parse_sha256_digest(digest) else {
        return Err(oci_err(400, "DIGEST_INVALID", "invalid sha256 digest"));
    };
    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::StatBlob {
            repo: repo.into(),
            digest: hex.into(),
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "BLOB_UNKNOWN", "blob unknown to registry"),
        other => other,
    })?;
    let RegistryReply::BlobStat { size, .. } = reply else {
        return Err(oci_err(500, "UNKNOWN", "unexpected stat reply"));
    };
    let canon_digest = format!("sha256:{hex}");
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(io_err)?;
    headers
        .set("Docker-Content-Digest", &canon_digest)
        .map_err(io_err)?;
    headers.set("Accept-Ranges", "bytes").map_err(io_err)?;
    headers
        .set("ETag", &format!("\"{canon_digest}\""))
        .map_err(io_err)?;

    let range_hdr = header(req, "Range")?;
    let (start, len, status) = if let Some(ref raw_range) = range_hdr {
        let Some((a, b)) = os_core::byte_range(raw_range, size) else {
            headers
                .set("Content-Range", &format!("bytes */{size}"))
                .map_err(io_err)?;
            return Ok(Response::empty()
                .map_err(io_err)?
                .with_headers(headers)
                .with_status(416));
        };
        headers
            .set("Content-Range", &format!("bytes {a}-{b}/{size}"))
            .map_err(io_err)?;
        (a, b - a + 1, 206)
    } else {
        (0, size, 200)
    };
    headers
        .set("Content-Length", &len.to_string())
        .map_err(io_err)?;

    if req.method() == Method::Head {
        return Ok(Response::empty()
            .map_err(io_err)?
            .with_status(status)
            .with_headers(headers));
    }
    if len == 0 {
        return Ok(Response::empty()
            .map_err(io_err)?
            .with_status(status)
            .with_headers(headers));
    }

    let bucket = env.bucket("FILES").map_err(io_err)?;
    let key = pack_key(&live.grant.tenant, &PackId(hex.to_string()));
    let obj = bucket
        .get(&key)
        .range(Range::OffsetWithLength {
            offset: start,
            length: len,
        })
        .execute()
        .await
        .map_err(io_err)?
        .ok_or_else(|| oci_err(404, "BLOB_UNKNOWN", "blob object missing"))?;
    let stream = obj
        .body()
        .ok_or_else(|| oci_err(500, "UNKNOWN", "missing R2 body"))?
        .stream()
        .map_err(io_err)?;
    let resp = if let Some(io_req) = live.io_req(false, 0) {
        let paced = paced_stream_io(env, io_req, stream, len)
            .await
            .map_err(RegErr::Errno)?;
        Response::from_stream(paced).map_err(io_err)?
    } else {
        Response::from_stream(stream).map_err(io_err)?
    };
    Ok(resp.with_status(status).with_headers(headers))
}

async fn handle_blob_delete(
    req: &Request,
    env: &Env,
    repo: &str,
    digest: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;
    let Some(hex) = parse_sha256_digest(digest) else {
        return Err(oci_err(400, "DIGEST_INVALID", "invalid sha256 digest"));
    };
    storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::DeleteBlob {
            repo: repo.into(),
            digest: hex.into(),
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "BLOB_UNKNOWN", "blob unknown to registry"),
        RegErr::Errno(Errno::EBUSY) => oci_err(409, "DENIED", "blob is referenced by a manifest"),
        other => other,
    })?;
    Ok(Response::empty().map_err(io_err)?.with_status(202))
}

async fn handle_upload_start(
    req: &mut Request,
    url: &Url,
    env: &Env,
    repo: &str,
) -> RResult<Response> {
    let mount_digest = url
        .query_pairs()
        .find(|(k, _)| k == "mount")
        .map(|(_, v)| v.into_owned());
    let from_repo = url
        .query_pairs()
        .find(|(k, _)| k == "from")
        .map(|(_, v)| v.into_owned());
    let mono_digest = url
        .query_pairs()
        .find(|(k, _)| k == "digest")
        .map(|(_, v)| v.into_owned());

    // 1. Cross-repo blob mount (`?mount=<digest>&from=<src_repo>`).
    if let (Some(md), Some(src_repo)) = (mount_digest, from_repo) {
        if !valid_repo_name(&src_repo) {
            return Err(oci_err(
                400,
                "NAME_INVALID",
                "invalid source repository name",
            ));
        }
        // Strict cross-repo authorization: requires BOTH `<repo>:push` AND `<src_repo>:pull`!
        let live = verify_bearer_live(req, env, Some(repo), true, Some(&src_repo)).await?;
        let Some(hex) = parse_sha256_digest(&md) else {
            return Err(oci_err(400, "DIGEST_INVALID", "invalid mount digest"));
        };
        let reply = storage_call(
            req,
            env,
            &live.grant,
            RegistryAction::MountBlob {
                repo: repo.into(),
                from_repo: src_repo,
                digest: hex.into(),
            },
        )
        .await?;
        match reply {
            RegistryReply::Mounted { mounted: true, .. } => {
                let canon = format!("sha256:{hex}");
                let headers = Headers::new();
                headers
                    .set("Location", &format!("/v2/{repo}/blobs/{canon}"))
                    .map_err(io_err)?;
                headers
                    .set("Docker-Content-Digest", &canon)
                    .map_err(io_err)?;
                headers.set("Content-Length", "0").map_err(io_err)?;
                return Ok(Response::empty()
                    .map_err(io_err)?
                    .with_status(201)
                    .with_headers(headers));
            }
            RegistryReply::Mounted {
                mounted: false,
                upload_id: Some(uid),
            } => {
                return upload_accepted_response(repo, &uid, 0);
            }
            _ => return Err(oci_err(500, "UNKNOWN", "unexpected mount reply")),
        }
    }

    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;

    // 2. Monolithic blob upload (`POST /v2/<name>/blobs/uploads/?digest=<d>`).
    if let Some(expected_digest) = mono_digest {
        return handle_monolithic_upload(req, env, &live, repo, &expected_digest).await;
    }

    // 3. Start chunked upload session.
    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::StartUpload { repo: repo.into() },
    )
    .await?;
    let RegistryReply::Upload { upload_id, .. } = reply else {
        return Err(oci_err(500, "UNKNOWN", "unexpected start upload reply"));
    };
    upload_accepted_response(repo, &upload_id, 0)
}

fn upload_accepted_response(repo: &str, upload_id: &str, received_bytes: u64) -> RResult<Response> {
    let end = received_bytes.saturating_sub(1);
    let headers = Headers::new();
    headers
        .set("Location", &format!("/v2/{repo}/blobs/uploads/{upload_id}"))
        .map_err(io_err)?;
    headers
        .set("Docker-Upload-UUID", upload_id)
        .map_err(io_err)?;
    headers.set("Range", &format!("0-{end}")).map_err(io_err)?;
    headers.set("OCI-Chunk-Min-Length", "1").map_err(io_err)?;
    headers.set("Content-Length", "0").map_err(io_err)?;
    Ok(Response::empty()
        .map_err(io_err)?
        .with_status(202)
        .with_headers(headers))
}

async fn handle_monolithic_upload(
    req: &mut Request,
    env: &Env,
    live: &LiveBearer,
    repo: &str,
    expected_digest: &str,
) -> RResult<Response> {
    let Some(hex) = parse_sha256_digest(expected_digest) else {
        return Err(oci_err(400, "DIGEST_INVALID", "invalid sha256 digest"));
    };
    let expected = digest_from_hex(hex).map_err(|_| oci_err(400, "DIGEST_INVALID", "bad hex"))?;
    let max_blob = max_blob_bytes(env);
    let content_len = header(req, "Content-Length")?
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| oci_err(400, "SIZE_INVALID", "invalid Content-Length"))
        })
        .transpose()?;
    if let Some(len) = content_len
        && len > max_blob
    {
        return Err(oci_err(413, "SIZE_INVALID", "blob exceeds maximum size"));
    }

    let bucket = env.bucket("FILES").map_err(io_err)?;
    let key = pack_key(&live.grant.tenant, &PackId(hex.to_string()));

    // Fast streaming path when Content-Length is known.
    if let Some(size) = content_len {
        let ready = storage_call(
            req,
            env,
            &live.grant,
            RegistryAction::BeginMonolithic {
                repo: repo.into(),
                digest: hex.into(),
                size,
            },
        )
        .await?;
        let RegistryReply::MonolithicReady {
            already_sealed,
            etag: existing_etag,
        } = ready
        else {
            return Err(oci_err(500, "UNKNOWN", "unexpected begin reply"));
        };
        let hash = Rc::new(RefCell::new(Sha256::new()));
        let etag = if size == 0 {
            let actual: [u8; 32] = Sha256::new().finalize().into();
            if actual != expected {
                return Err(oci_err(400, "DIGEST_INVALID", "digest mismatch"));
            }
            if let Some(et) = existing_etag.filter(|_| already_sealed) {
                et
            } else {
                bucket
                    .put(&key, Vec::<u8>::new())
                    .sha256(expected.to_vec())
                    .execute()
                    .await
                    .map_err(io_err)?
                    .ok_or_else(|| oci_err(500, "UNKNOWN", "R2 put returned none"))?
                    .etag()
            }
        } else if already_sealed && let Some(et) = existing_etag {
            // Still stream & verify caller bytes so corrupt upload with existing digest fails 400.
            let mut stream = req.stream().map_err(io_err)?;
            let mut total = 0u64;
            while let Some(chunk) = stream.next().await {
                let bytes = chunk.map_err(io_err)?;
                total = total.saturating_add(bytes.len() as u64);
                if total > size {
                    return Err(oci_err(400, "SIZE_INVALID", "body exceeded Content-Length"));
                }
                if let Some(io_req) = live.io_req(true, 0) {
                    charge_slices(env, &io_req, bytes.len() as u64)
                        .await
                        .map_err(RegErr::Errno)?;
                }
                hash.borrow_mut().update(&bytes);
            }
            if total != size {
                return Err(oci_err(400, "SIZE_INVALID", "truncated body"));
            }
            let actual: [u8; 32] = hash.take().finalize().into();
            if actual != expected {
                return Err(oci_err(400, "DIGEST_INVALID", "digest mismatch"));
            }
            et
        } else {
            let update = hash.clone();
            let input = req.stream().map_err(io_err)?;
            let put_res = if let Some(io_req) = live.io_req(true, 0) {
                let paced = paced_stream_io(env, io_req, input, size)
                    .await
                    .map_err(RegErr::Errno)?
                    .inspect_ok(move |chunk| update.borrow_mut().update(chunk));
                bucket
                    .put(&key, FixedLengthStream::wrap(paced, size))
                    .sha256(expected.to_vec())
                    .execute()
                    .await
            } else {
                let counted = input.inspect_ok(move |chunk| update.borrow_mut().update(chunk));
                bucket
                    .put(&key, FixedLengthStream::wrap(counted, size))
                    .sha256(expected.to_vec())
                    .execute()
                    .await
            };
            let actual: [u8; 32] = hash.take().finalize().into();
            if actual != expected {
                return Err(oci_err(400, "DIGEST_INVALID", "digest mismatch"));
            }
            put_res
                .map_err(io_err)?
                .ok_or_else(|| oci_err(500, "UNKNOWN", "R2 put returned none"))?
                .etag()
        };

        storage_call(
            req,
            env,
            &live.grant,
            RegistryAction::SealBlob {
                repo: repo.into(),
                digest: hex.into(),
                size,
                etag,
            },
        )
        .await?;
        return blob_created_response(repo, hex);
    }

    // Streaming Transfer-Encoding: chunked monolithic upload (no Content-Length).
    let tmp_id = auth::random_token()[..32].to_string();
    let mut sha = ResumableSha256::new();
    let streamed =
        stream_body_to_parts(req, env, live, &bucket, &tmp_id, 0, 0, max_blob, &mut sha).await;
    let (parts, added) = match streamed {
        Ok(v) => v,
        Err((e, partial_keys)) => {
            if !partial_keys.is_empty() {
                let _ = bucket.delete_multiple(partial_keys).await;
            }
            return Err(e);
        }
    };
    let part_keys: Vec<String> = parts.iter().map(|p| p.r2_key.clone()).collect();
    let actual_hex = sha.finalize_hex();
    if actual_hex != hex {
        if !part_keys.is_empty() {
            let _ = bucket.delete_multiple(part_keys).await;
        }
        return Err(oci_err(400, "DIGEST_INVALID", "digest mismatch"));
    }
    let ready = match storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::BeginMonolithic {
            repo: repo.into(),
            digest: hex.into(),
            size: added,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            if !part_keys.is_empty() {
                let _ = bucket.delete_multiple(part_keys).await;
            }
            return Err(e);
        }
    };
    let RegistryReply::MonolithicReady {
        already_sealed,
        etag: existing_etag,
    } = ready
    else {
        if !part_keys.is_empty() {
            let _ = bucket.delete_multiple(part_keys).await;
        }
        return Err(oci_err(500, "UNKNOWN", "unexpected begin reply"));
    };
    let etag = if let Some(et) = existing_etag.filter(|_| already_sealed) {
        et
    } else if added == 0 {
        bucket
            .put(&key, Vec::<u8>::new())
            .sha256(expected.to_vec())
            .execute()
            .await
            .map_err(io_err)?
            .ok_or_else(|| oci_err(500, "UNKNOWN", "R2 put returned none"))?
            .etag()
    } else {
        let obj_parts: Vec<(String, u64)> =
            parts.iter().map(|p| (p.r2_key.clone(), p.len)).collect();
        let concat_stream = streams::objects(env.bucket("FILES").map_err(io_err)?, obj_parts);
        let put_res = bucket
            .put(&key, Data::ReadableStream(concat_stream))
            .sha256(expected.to_vec())
            .execute()
            .await;
        match put_res {
            Ok(Some(o)) => o.etag(),
            _ => {
                if !part_keys.is_empty() {
                    let _ = bucket.delete_multiple(part_keys).await;
                }
                return Err(oci_err(500, "UNKNOWN", "R2 concatenation failed"));
            }
        }
    };
    if !part_keys.is_empty() {
        let _ = bucket.delete_multiple(part_keys).await;
    }
    storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::SealBlob {
            repo: repo.into(),
            digest: hex.into(),
            size: added,
            etag,
        },
    )
    .await?;
    blob_created_response(repo, hex)
}

fn blob_created_response(repo: &str, hex: &str) -> RResult<Response> {
    let canon = format!("sha256:{hex}");
    let headers = Headers::new();
    headers
        .set("Location", &format!("/v2/{repo}/blobs/{canon}"))
        .map_err(io_err)?;
    headers
        .set("Docker-Content-Digest", &canon)
        .map_err(io_err)?;
    headers.set("Content-Length", "0").map_err(io_err)?;
    Ok(Response::empty()
        .map_err(io_err)?
        .with_status(201)
        .with_headers(headers))
}

/// Stream a request body (fixed `Content-Length` OR `Transfer-Encoding: chunked`) into bounded
/// `<= 4 MiB` staged R2 parts while incrementally updating `sha` and charging `checked_io`.
#[allow(clippy::too_many_arguments)]
async fn stream_body_to_parts(
    req: &mut Request,
    env: &Env,
    live: &LiveBearer,
    bucket: &Bucket,
    upload_id: &str,
    start_offset: u64,
    start_part_idx: u32,
    max_total_bytes: u64,
    sha: &mut ResumableSha256,
) -> std::result::Result<(Vec<UploadChunkMeta>, u64), (RegErr, Vec<String>)> {
    let mut parts: Vec<UploadChunkMeta> = Vec::new();
    let mut created_keys: Vec<String> = Vec::new();
    let mut total_added = 0u64;
    let mut next_offset = start_offset;
    let mut next_part = start_part_idx;
    let mut buf: Vec<u8> = Vec::new();

    let mut stream = match req.stream() {
        Ok(s) => s,
        Err(_) => return Ok((parts, 0)),
    };

    while let Some(item) = stream.next().await {
        let chunk = match item {
            Ok(b) => b,
            Err(e) => return Err((io_err(e), created_keys)),
        };
        if chunk.is_empty() {
            continue;
        }
        let n = chunk.len() as u64;
        let new_total = match start_offset
            .checked_add(total_added)
            .and_then(|v| v.checked_add(n))
        {
            Some(v) if v <= max_total_bytes => v,
            _ => {
                return Err((
                    oci_err(413, "SIZE_INVALID", "blob exceeds maximum size"),
                    created_keys,
                ));
            }
        };
        let _ = new_total;
        if let Some(io_req) = live.io_req(true, 0)
            && let Err(e) = charge_slices(env, &io_req, n).await
        {
            return Err((RegErr::Errno(e), created_keys));
        }
        sha.update(&chunk);
        total_added += n;

        let mut slice = chunk.as_slice();
        while !slice.is_empty() {
            let space = UPLOAD_PART_MAX_BYTES - buf.len();
            let take = slice.len().min(space);
            buf.extend_from_slice(&slice[..take]);
            slice = &slice[take..];
            if buf.len() == UPLOAD_PART_MAX_BYTES {
                let flushed = std::mem::take(&mut buf);
                let len = flushed.len() as u64;
                let r2_key = upload_chunk_key(&live.grant.tenant, upload_id, next_part);
                if let Err(e) = bucket.put(&r2_key, flushed).execute().await {
                    return Err((io_err(e), created_keys));
                }
                created_keys.push(r2_key.clone());
                parts.push(UploadChunkMeta {
                    part_idx: next_part,
                    offset: next_offset,
                    len,
                    r2_key,
                });
                next_offset += len;
                next_part = next_part.saturating_add(1);
            }
        }
    }
    if !buf.is_empty() {
        let len = buf.len() as u64;
        let r2_key = upload_chunk_key(&live.grant.tenant, upload_id, next_part);
        if let Err(e) = bucket.put(&r2_key, buf).execute().await {
            return Err((io_err(e), created_keys));
        }
        created_keys.push(r2_key.clone());
        parts.push(UploadChunkMeta {
            part_idx: next_part,
            offset: next_offset,
            len,
            r2_key,
        });
    }
    Ok((parts, total_added))
}

fn parse_upload_content_range(raw: &str) -> Option<(u64, u64)> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("bytes ").unwrap_or(trimmed).trim();
    let (a, b) = trimmed.split_once('-')?;
    let start = a.parse::<u64>().ok()?;
    let end = b.parse::<u64>().ok()?;
    (start <= end).then_some((start, end))
}

async fn handle_upload_status(
    req: &Request,
    env: &Env,
    repo: &str,
    uuid: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;
    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::GetUpload {
            repo: repo.into(),
            upload_id: uuid.into(),
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "BLOB_UPLOAD_UNKNOWN", "blob upload unknown"),
        other => other,
    })?;
    let RegistryReply::Upload { received_bytes, .. } = reply else {
        return Err(oci_err(500, "UNKNOWN", "unexpected upload status"));
    };
    let end = received_bytes.saturating_sub(1);
    let headers = Headers::new();
    headers
        .set("Location", &format!("/v2/{repo}/blobs/uploads/{uuid}"))
        .map_err(io_err)?;
    headers.set("Docker-Upload-UUID", uuid).map_err(io_err)?;
    headers.set("Range", &format!("0-{end}")).map_err(io_err)?;
    Ok(Response::empty()
        .map_err(io_err)?
        .with_status(204)
        .with_headers(headers))
}

async fn handle_upload_patch(
    req: &mut Request,
    env: &Env,
    repo: &str,
    uuid: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;
    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::GetUpload {
            repo: repo.into(),
            upload_id: uuid.into(),
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "BLOB_UPLOAD_UNKNOWN", "blob upload unknown"),
        other => other,
    })?;
    let RegistryReply::Upload {
        received_bytes,
        part_count,
        sha_state_b64,
        ..
    } = reply
    else {
        return Err(oci_err(500, "UNKNOWN", "unexpected upload status"));
    };

    let expected_range_len = if let Some(cr) = header(req, "Content-Range")? {
        let Some((start, end)) = parse_upload_content_range(&cr) else {
            return Err(oci_err(416, "RANGE_INVALID", "invalid Content-Range"));
        };
        if start != received_bytes {
            return Err(oci_err(
                416,
                "RANGE_INVALID",
                "chunk start does not match current upload offset",
            ));
        }
        let range_len = end
            .checked_sub(start)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| oci_err(416, "RANGE_INVALID", "invalid Content-Range span"))?;
        if let Some(cl_hdr) = header(req, "Content-Length")?
            && let Ok(cl) = cl_hdr.parse::<u64>()
            && cl != range_len
        {
            return Err(oci_err(
                416,
                "RANGE_INVALID",
                "Content-Length does not match Content-Range",
            ));
        }
        Some(range_len)
    } else {
        None
    };

    let mut sha = ResumableSha256::from_base64(&sha_state_b64)
        .ok_or_else(|| oci_err(500, "UNKNOWN", "corrupt upload hash state"))?;
    let max_blob = max_blob_bytes(env);
    let bucket = env.bucket("FILES").map_err(io_err)?;
    let (parts, added) = match stream_body_to_parts(
        req,
        env,
        &live,
        &bucket,
        uuid,
        received_bytes,
        part_count,
        max_blob,
        &mut sha,
    )
    .await
    {
        Ok(v) => v,
        Err((e, keys)) => {
            if !keys.is_empty() {
                let _ = bucket.delete_multiple(keys).await;
            }
            return Err(e);
        }
    };
    let created_keys: Vec<String> = parts.iter().map(|p| p.r2_key.clone()).collect();
    if let Some(exp_len) = expected_range_len
        && added != exp_len
    {
        if !created_keys.is_empty() {
            let _ = bucket.delete_multiple(created_keys).await;
        }
        return Err(oci_err(
            416,
            "RANGE_INVALID",
            "received bytes did not match Content-Range",
        ));
    }

    let updated = match storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::AppendUploadChunks {
            repo: repo.into(),
            upload_id: uuid.into(),
            expected_received: received_bytes,
            new_sha_state_b64: sha.to_base64(),
            chunks: parts,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            if !created_keys.is_empty() {
                let _ = bucket.delete_multiple(created_keys).await;
            }
            return Err(match e {
                RegErr::Errno(Errno::ENOENT) => {
                    oci_err(404, "BLOB_UPLOAD_UNKNOWN", "blob upload unknown")
                }
                other => other,
            });
        }
    };
    let RegistryReply::Upload {
        received_bytes: new_received,
        ..
    } = updated
    else {
        return Err(oci_err(500, "UNKNOWN", "unexpected append reply"));
    };
    upload_accepted_response(repo, uuid, new_received)
}

async fn handle_upload_finalize(
    req: &mut Request,
    url: &Url,
    env: &Env,
    repo: &str,
    uuid: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;
    let Some(digest_param) = url
        .query_pairs()
        .find(|(k, _)| k == "digest")
        .map(|(_, v)| v.into_owned())
    else {
        return Err(oci_err(400, "DIGEST_INVALID", "missing digest query param"));
    };
    let Some(hex) = parse_sha256_digest(&digest_param) else {
        return Err(oci_err(400, "DIGEST_INVALID", "invalid sha256 digest"));
    };
    let expected = digest_from_hex(hex).map_err(|_| oci_err(400, "DIGEST_INVALID", "bad hex"))?;

    let status_reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::GetUpload {
            repo: repo.into(),
            upload_id: uuid.into(),
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "BLOB_UPLOAD_UNKNOWN", "blob upload unknown"),
        other => other,
    })?;
    let RegistryReply::Upload {
        received_bytes,
        part_count,
        sha_state_b64,
        ..
    } = status_reply
    else {
        return Err(oci_err(500, "UNKNOWN", "unexpected upload status"));
    };

    if let Some(cr) = header(req, "Content-Range")? {
        let Some((start, _end)) = parse_upload_content_range(&cr) else {
            return Err(oci_err(416, "RANGE_INVALID", "invalid Content-Range"));
        };
        if start != received_bytes {
            return Err(oci_err(
                416,
                "RANGE_INVALID",
                "final chunk start does not match current upload offset",
            ));
        }
    }

    let mut sha = ResumableSha256::from_base64(&sha_state_b64)
        .ok_or_else(|| oci_err(500, "UNKNOWN", "corrupt upload hash state"))?;
    let max_blob = max_blob_bytes(env);
    let bucket = env.bucket("FILES").map_err(io_err)?;
    let (extra_parts, _added) = match stream_body_to_parts(
        req,
        env,
        &live,
        &bucket,
        uuid,
        received_bytes,
        part_count,
        max_blob,
        &mut sha,
    )
    .await
    {
        Ok(v) => v,
        Err((e, keys)) => {
            if !keys.is_empty() {
                let _ = bucket.delete_multiple(keys).await;
            }
            return Err(e);
        }
    };
    let extra_keys: Vec<String> = extra_parts.iter().map(|p| p.r2_key.clone()).collect();
    let actual_hex = sha.finalize_hex();
    if actual_hex != hex {
        if !extra_keys.is_empty() {
            let _ = bucket.delete_multiple(extra_keys).await;
        }
        if let Ok(RegistryReply::CleanedKeys(keys)) = storage_call(
            req,
            env,
            &live.grant,
            RegistryAction::AbortUpload {
                repo: repo.into(),
                upload_id: uuid.into(),
            },
        )
        .await
            && !keys.is_empty()
        {
            let _ = bucket.delete_multiple(keys).await;
        }
        return Err(oci_err(400, "DIGEST_INVALID", "blob digest mismatch"));
    }

    let plan = match storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::PrepareFinalizeUpload {
            repo: repo.into(),
            upload_id: uuid.into(),
            digest: hex.into(),
            expected_received: received_bytes,
            extra_chunks: extra_parts,
        },
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            if !extra_keys.is_empty() {
                let _ = bucket.delete_multiple(extra_keys).await;
            }
            return Err(e);
        }
    };
    let RegistryReply::FinalizePlan {
        already_sealed,
        etag: existing_etag,
        total_size,
        parts,
    } = plan
    else {
        return Err(oci_err(500, "UNKNOWN", "unexpected finalize plan"));
    };

    let key = pack_key(&live.grant.tenant, &PackId(hex.to_string()));
    let etag = if let Some(et) = existing_etag.filter(|_| already_sealed) {
        et
    } else if total_size == 0 {
        bucket
            .put(&key, Vec::<u8>::new())
            .sha256(expected.to_vec())
            .execute()
            .await
            .map_err(io_err)?
            .ok_or_else(|| oci_err(500, "UNKNOWN", "R2 put returned none"))?
            .etag()
    } else {
        let concat_stream = streams::objects(env.bucket("FILES").map_err(io_err)?, parts);
        bucket
            .put(&key, Data::ReadableStream(concat_stream))
            .sha256(expected.to_vec())
            .execute()
            .await
            .map_err(io_err)?
            .ok_or_else(|| oci_err(500, "UNKNOWN", "R2 put returned none"))?
            .etag()
    };

    let done = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::CompleteFinalizeUpload {
            repo: repo.into(),
            upload_id: uuid.into(),
            digest: hex.into(),
            total_size,
            etag,
        },
    )
    .await?;
    if let RegistryReply::CleanedKeys(keys) = done
        && !keys.is_empty()
    {
        let _ = bucket.delete_multiple(keys).await;
    }
    blob_created_response(repo, hex)
}

async fn handle_upload_delete(
    req: &Request,
    env: &Env,
    repo: &str,
    uuid: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;
    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::AbortUpload {
            repo: repo.into(),
            upload_id: uuid.into(),
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "BLOB_UPLOAD_UNKNOWN", "blob upload unknown"),
        other => other,
    })?;
    if let RegistryReply::CleanedKeys(keys) = reply
        && !keys.is_empty()
    {
        let _ = env
            .bucket("FILES")
            .map_err(io_err)?
            .delete_multiple(keys)
            .await;
    }
    Ok(Response::empty().map_err(io_err)?.with_status(204))
}

async fn handle_manifest_get(
    req: &Request,
    env: &Env,
    repo: &str,
    reference: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), false, None).await?;
    let (lookup_ref, is_digest) = if let Some(hex) = parse_sha256_digest(reference) {
        (hex.to_string(), true)
    } else if valid_tag(reference) {
        (reference.to_string(), false)
    } else {
        return Err(oci_err(400, "NAME_INVALID", "invalid manifest reference"));
    };
    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::GetManifest {
            repo: repo.into(),
            reference: lookup_ref,
            is_digest,
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "MANIFEST_UNKNOWN", "manifest unknown"),
        other => other,
    })?;
    let RegistryReply::ManifestMeta {
        digest,
        media_type,
        size,
        ..
    } = reply
    else {
        return Err(oci_err(500, "UNKNOWN", "unexpected manifest reply"));
    };
    let canon = format!("sha256:{digest}");
    let headers = Headers::new();
    headers.set("Content-Type", &media_type).map_err(io_err)?;
    headers
        .set("Content-Length", &size.to_string())
        .map_err(io_err)?;
    headers
        .set("Docker-Content-Digest", &canon)
        .map_err(io_err)?;
    headers
        .set("ETag", &format!("\"{canon}\""))
        .map_err(io_err)?;

    if req.method() == Method::Head {
        return Ok(Response::empty()
            .map_err(io_err)?
            .with_status(200)
            .with_headers(headers));
    }

    let bucket = env.bucket("FILES").map_err(io_err)?;
    let key = manifest_key(&live.grant.tenant, &digest);
    let obj = bucket
        .get(&key)
        .execute()
        .await
        .map_err(io_err)?
        .ok_or_else(|| oci_err(404, "MANIFEST_UNKNOWN", "manifest body missing"))?;
    let bytes = obj
        .body()
        .ok_or_else(|| oci_err(500, "UNKNOWN", "missing manifest body"))?
        .bytes()
        .await
        .map_err(io_err)?;
    if let Some(io_req) = live.io_req(false, 0) {
        charge_slices(env, &io_req, bytes.len() as u64)
            .await
            .map_err(RegErr::Errno)?;
    }
    Ok(Response::from_bytes(bytes)
        .map_err(io_err)?
        .with_status(200)
        .with_headers(headers))
}

async fn handle_manifest_put(
    req: &mut Request,
    env: &Env,
    repo: &str,
    reference: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;
    let (expected_digest, tag_name) = if let Some(hex) = parse_sha256_digest(reference) {
        (Some(hex.to_string()), None)
    } else if valid_tag(reference) {
        (None, Some(reference.to_string()))
    } else {
        return Err(oci_err(
            400,
            "MANIFEST_INVALID",
            "invalid manifest reference",
        ));
    };

    if let Some(cl) = header(req, "Content-Length")?.and_then(|s| s.parse::<usize>().ok())
        && cl > REGISTRY_MANIFEST_MAX_BYTES
    {
        return Err(oci_err(413, "SIZE_INVALID", "manifest exceeds 4 MiB"));
    }

    let mut body = Vec::new();
    let mut stream = req
        .stream()
        .map_err(|_| oci_err(400, "MANIFEST_INVALID", "missing manifest body"))?;
    while let Some(chunk) = stream.next().await {
        let bytes = chunk.map_err(io_err)?;
        if body.len().saturating_add(bytes.len()) > REGISTRY_MANIFEST_MAX_BYTES {
            return Err(oci_err(413, "SIZE_INVALID", "manifest exceeds 4 MiB"));
        }
        body.extend_from_slice(&bytes);
    }
    if body.is_empty() {
        return Err(oci_err(400, "MANIFEST_INVALID", "empty manifest"));
    }
    if let Some(io_req) = live.io_req(true, 0) {
        charge_slices(env, &io_req, body.len() as u64)
            .await
            .map_err(RegErr::Errno)?;
    }

    let actual_digest_bytes = sha256(&body);
    let actual_hex = digest_to_hex(&actual_digest_bytes);
    if let Some(ref exp) = expected_digest
        && exp != &actual_hex
    {
        return Err(oci_err(400, "DIGEST_INVALID", "manifest digest mismatch"));
    }

    // Strict JSON parsing rejecting duplicate keys (`os_image::parse`).
    let val: Value = os_image::parse(&body).map_err(|e| {
        oci_err(
            400,
            "MANIFEST_INVALID",
            format!("invalid manifest JSON: {e}"),
        )
    })?;
    let obj = val
        .as_object()
        .ok_or_else(|| oci_err(400, "MANIFEST_INVALID", "manifest must be a JSON object"))?;
    let header_ct = header(req, "Content-Type")?
        .map(|s| s.split(';').next().unwrap_or(&s).trim().to_string())
        .filter(|s| !s.is_empty());

    let (media_type, artifact_type, subject_hex, annotations_json, refs) =
        if obj.contains_key("manifests") {
            let index: OciImageIndex = serde_json::from_value(val)
                .map_err(|e| oci_err(400, "MANIFEST_INVALID", format!("invalid OCI index: {e}")))?;
            if index.schema_version != 2 {
                return Err(oci_err(400, "MANIFEST_INVALID", "schemaVersion must be 2"));
            }
            let mt = index
                .media_type
                .clone()
                .or(header_ct)
                .unwrap_or_else(|| OCI_IMAGE_INDEX_MEDIA_TYPE.into());
            let mut refs = Vec::with_capacity(index.manifests.len());
            for child in &index.manifests {
                let Some(hex) = parse_sha256_digest(&child.digest) else {
                    return Err(oci_err(
                        400,
                        "MANIFEST_INVALID",
                        "invalid child manifest digest",
                    ));
                };
                refs.push(("manifest".into(), hex.to_string()));
            }
            let subject_hex = match &index.subject {
                Some(sub) => Some(
                    parse_sha256_digest(&sub.digest)
                        .ok_or_else(|| oci_err(400, "MANIFEST_INVALID", "invalid subject digest"))?
                        .to_string(),
                ),
                None => None,
            };
            let ann = serde_json::to_string(&index.annotations.unwrap_or_default())
                .unwrap_or_else(|_| "{}".into());
            (mt, index.artifact_type, subject_hex, ann, refs)
        } else if obj.contains_key("config") && obj.contains_key("layers") {
            let manifest: OciImageManifest = serde_json::from_value(val).map_err(|e| {
                oci_err(
                    400,
                    "MANIFEST_INVALID",
                    format!("invalid OCI manifest: {e}"),
                )
            })?;
            if manifest.schema_version != 2 {
                return Err(oci_err(400, "MANIFEST_INVALID", "schemaVersion must be 2"));
            }
            let mt = manifest
                .media_type
                .clone()
                .or(header_ct)
                .unwrap_or_else(|| OCI_IMAGE_MANIFEST_MEDIA_TYPE.into());
            let mut refs = Vec::with_capacity(1 + manifest.layers.len());
            let Some(cfg_hex) = parse_sha256_digest(&manifest.config.digest) else {
                return Err(oci_err(400, "MANIFEST_INVALID", "invalid config digest"));
            };
            refs.push(("blob".into(), cfg_hex.to_string()));
            for layer in &manifest.layers {
                let Some(lhex) = parse_sha256_digest(&layer.digest) else {
                    return Err(oci_err(400, "MANIFEST_INVALID", "invalid layer digest"));
                };
                refs.push(("blob".into(), lhex.to_string()));
            }
            let subject_hex = match &manifest.subject {
                Some(sub) => Some(
                    parse_sha256_digest(&sub.digest)
                        .ok_or_else(|| oci_err(400, "MANIFEST_INVALID", "invalid subject digest"))?
                        .to_string(),
                ),
                None => None,
            };
            let eff_at = manifest.effective_artifact_type().map(str::to_owned);
            let ann = serde_json::to_string(&manifest.annotations.unwrap_or_default())
                .unwrap_or_else(|_| "{}".into());
            (mt, eff_at, subject_hex, ann, refs)
        } else {
            return Err(oci_err(
                400,
                "MANIFEST_INVALID",
                "manifest must contain either config+layers or manifests",
            ));
        };

    // Pre-check all referenced blobs & child manifests exist in this repo BEFORE writing R2.
    storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::CheckManifestRefs {
            repo: repo.into(),
            refs: refs.clone(),
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(
            400,
            "MANIFEST_BLOB_UNKNOWN",
            "one or more referenced blobs or child manifests are unknown",
        ),
        other => other,
    })?;

    let size = body.len() as u64;
    let bucket = env.bucket("FILES").map_err(io_err)?;
    let mkey = manifest_key(&live.grant.tenant, &actual_hex);
    bucket
        .put(&mkey, body)
        .sha256(actual_digest_bytes.to_vec())
        .execute()
        .await
        .map_err(io_err)?;

    storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::PutManifest {
            repo: repo.into(),
            digest: actual_hex.clone(),
            tag: tag_name,
            media_type,
            artifact_type,
            subject_digest: subject_hex.clone(),
            size,
            annotations_json,
            refs,
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(
            400,
            "MANIFEST_BLOB_UNKNOWN",
            "one or more referenced blobs or child manifests are unknown",
        ),
        other => other,
    })?;

    let canon = format!("sha256:{actual_hex}");
    let headers = Headers::new();
    headers
        .set("Location", &format!("/v2/{repo}/manifests/{canon}"))
        .map_err(io_err)?;
    headers
        .set("Docker-Content-Digest", &canon)
        .map_err(io_err)?;
    if let Some(sub) = subject_hex {
        headers
            .set("OCI-Subject", &format!("sha256:{sub}"))
            .map_err(io_err)?;
    }
    headers.set("Content-Length", "0").map_err(io_err)?;
    Ok(Response::empty()
        .map_err(io_err)?
        .with_status(201)
        .with_headers(headers))
}

async fn handle_manifest_delete(
    req: &Request,
    env: &Env,
    repo: &str,
    reference: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), true, None).await?;
    let (lookup_ref, is_digest) = if let Some(hex) = parse_sha256_digest(reference) {
        (hex.to_string(), true)
    } else if valid_tag(reference) {
        (reference.to_string(), false)
    } else {
        return Err(oci_err(400, "NAME_INVALID", "invalid manifest reference"));
    };
    storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::DeleteManifest {
            repo: repo.into(),
            reference: lookup_ref,
            is_digest,
        },
    )
    .await
    .map_err(|e| match e {
        RegErr::Errno(Errno::ENOENT) => oci_err(404, "MANIFEST_UNKNOWN", "manifest or tag unknown"),
        other => other,
    })?;
    Ok(Response::empty().map_err(io_err)?.with_status(202))
}

async fn handle_tags_list(req: &Request, url: &Url, env: &Env, repo: &str) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), false, None).await?;
    let n = url
        .query_pairs()
        .find(|(k, _)| k == "n")
        .map(|(_, v)| {
            v.parse::<usize>()
                .map_err(|_| oci_err(400, "UNSUPPORTED", "invalid n query parameter"))
        })
        .transpose()?
        .unwrap_or(REGISTRY_TAGS_DEFAULT_N)
        .min(REGISTRY_TAGS_MAX_N);
    let last = url
        .query_pairs()
        .find(|(k, _)| k == "last")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty());

    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::ListTags {
            repo: repo.into(),
            n,
            last,
        },
    )
    .await?;
    let RegistryReply::Tags { tags, has_more } = reply else {
        return Err(oci_err(500, "UNKNOWN", "unexpected tags reply"));
    };
    let last_returned = tags.last().cloned();
    let body = OciTagsList {
        name: repo.into(),
        tags,
    };
    let mut resp = Response::from_json(&body).map_err(io_err)?;
    if has_more && let Some(cursor) = last_returned {
        resp.headers_mut()
            .set(
                "Link",
                &format!("</v2/{repo}/tags/list?n={n}&last={cursor}>; rel=\"next\""),
            )
            .map_err(io_err)?;
    }
    Ok(resp)
}

async fn handle_referrers(
    req: &Request,
    url: &Url,
    env: &Env,
    repo: &str,
    digest: &str,
) -> RResult<Response> {
    let live = verify_bearer_live(req, env, Some(repo), false, None).await?;
    let Some(hex) = parse_sha256_digest(digest) else {
        return Err(oci_err(400, "DIGEST_INVALID", "invalid sha256 digest"));
    };
    let artifact_type_filter = url
        .query_pairs()
        .find(|(k, _)| k == "artifactType")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty());

    let reply = storage_call(
        req,
        env,
        &live.grant,
        RegistryAction::ListReferrers {
            repo: repo.into(),
            subject_digest: hex.into(),
            artifact_type: artifact_type_filter.clone(),
        },
    )
    .await?;
    let RegistryReply::Referrers(rows) = reply else {
        return Err(oci_err(500, "UNKNOWN", "unexpected referrers reply"));
    };
    let manifests: Vec<OciDescriptor> = rows
        .into_iter()
        .map(|r| {
            let annotations: BTreeMap<String, String> =
                serde_json::from_str(&r.annotations_json).unwrap_or_default();
            OciDescriptor {
                media_type: r.media_type,
                digest: format!("sha256:{}", r.digest),
                size: r.size,
                urls: None,
                annotations: (!annotations.is_empty()).then_some(annotations),
                artifact_type: r.artifact_type,
                platform: None,
                data: None,
            }
        })
        .collect();
    let index = OciImageIndex {
        schema_version: 2,
        media_type: Some(OCI_IMAGE_INDEX_MEDIA_TYPE.into()),
        artifact_type: None,
        manifests,
        subject: None,
        annotations: None,
    };
    let bytes = serde_json::to_vec(&index).map_err(|_| oci_err(500, "UNKNOWN", "encode"))?;
    let headers = Headers::new();
    headers
        .set("Content-Type", OCI_IMAGE_INDEX_MEDIA_TYPE)
        .map_err(io_err)?;
    headers
        .set("Content-Length", &bytes.len().to_string())
        .map_err(io_err)?;
    if artifact_type_filter.is_some() {
        headers
            .set("OCI-Filters-Applied", "artifactType")
            .map_err(io_err)?;
    }
    Ok(Response::from_bytes(bytes)
        .map_err(io_err)?
        .with_status(200)
        .with_headers(headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_parser_handles_multi_segment_repos_from_right() {
        assert_eq!(parse_v2_route("/v2").unwrap(), V2Route::Base);
        assert_eq!(parse_v2_route("/v2/").unwrap(), V2Route::Base);
        assert_eq!(parse_v2_route("/v2/token").unwrap(), V2Route::Token);
        assert_eq!(
            parse_v2_route("/v2/org/team/app/tags/list").unwrap(),
            V2Route::TagsList {
                repo: "org/team/app".into()
            }
        );
        assert_eq!(
            parse_v2_route("/v2/org/team/app/blobs/uploads/").unwrap(),
            V2Route::BlobUploadsStart {
                repo: "org/team/app".into()
            }
        );
        assert_eq!(
            parse_v2_route("/v2/org/team/app/blobs/uploads/deadbeef").unwrap(),
            V2Route::BlobUpload {
                repo: "org/team/app".into(),
                uuid: "deadbeef".into()
            }
        );
        assert_eq!(
            parse_v2_route("/v2/org/team/app/blobs/sha256:abc").unwrap(),
            V2Route::Blob {
                repo: "org/team/app".into(),
                digest: "sha256:abc".into()
            }
        );
        assert_eq!(
            parse_v2_route("/v2/org/team/app/manifests/v1.0").unwrap(),
            V2Route::Manifest {
                repo: "org/team/app".into(),
                reference: "v1.0".into()
            }
        );
        assert_eq!(
            parse_v2_route("/v2/org/team/app/referrers/sha256:abc").unwrap(),
            V2Route::Referrers {
                repo: "org/team/app".into(),
                digest: "sha256:abc".into()
            }
        );
        assert!(parse_v2_route("/v2/BadRepo/manifests/v1").is_err());
    }

    #[test]
    fn rfc3339_formatting_matches_known_timestamps() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}
