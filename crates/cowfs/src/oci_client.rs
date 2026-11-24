//! Portable OCI Distribution v1.1 HTTP client, generic recursive artifact mirror, and
//! Ed25519 detached signature referrer publisher/verifier (`docs/architecture/contract.md` §2.15,
//! §6; #81).
//!
//! Zero DOM, `web-sys`, or `wasm-bindgen` types: runs identically in browser kernel Workers,
//! `xtask` host tooling, `os-native`, and headless Rust conformance tests.

use abi::Errno;
use abi::registry::{
    OCI_EMPTY_CONFIG_MEDIA_TYPE, OCI_EMPTY_JSON_BYTES, OCI_EMPTY_JSON_DIGEST,
    OCI_IMAGE_INDEX_MEDIA_TYPE, OCI_IMAGE_MANIFEST_MEDIA_TYPE, OS_SIGNATURE_ARTIFACT_TYPE,
    OciDescriptor, OciImageIndex, OciImageManifest, OciTagsList, OciTokenResponse,
    parse_sha256_digest, valid_repo_name,
};
use cowtree::{digest_from_hex, digest_to_hex, sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
pub use vfs::vblk::{OciHttpReply, OciTransport};
use vfs::{BoxFuture, Result};

/// Parsed `WWW-Authenticate: Bearer realm="...",service="...",scope="..."` challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BearerChallenge {
    pub realm: String,
    pub service: Option<String>,
    pub scope: Option<String>,
}

pub fn parse_www_authenticate(header: &str) -> Option<BearerChallenge> {
    let trimmed = header.trim();
    if trimmed.len() <= 7 || !trimmed[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let mut rest = trimmed[7..].trim();
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    while !rest.is_empty() {
        let eq = rest.find('=')?;
        let key = rest[..eq].trim().to_ascii_lowercase();
        rest = rest[eq + 1..].trim_start();
        let val = if let Some(after_quote) = rest.strip_prefix('"') {
            let mut out = String::new();
            let mut chars = after_quote.char_indices();
            let mut end_idx = None;
            while let Some((i, ch)) = chars.next() {
                if ch == '\\' {
                    if let Some((_, next_ch)) = chars.next() {
                        out.push(next_ch);
                    }
                } else if ch == '"' {
                    end_idx = Some(i);
                    break;
                } else {
                    out.push(ch);
                }
            }
            let close = end_idx?;
            rest = after_quote[close + 1..].trim_start();
            if let Some(after_comma) = rest.strip_prefix(',') {
                rest = after_comma.trim_start();
            }
            out
        } else {
            let comma = rest.find(',').unwrap_or(rest.len());
            let v = rest[..comma].trim().to_string();
            rest = if comma < rest.len() {
                rest[comma + 1..].trim_start()
            } else {
                ""
            };
            v
        };
        match key.as_str() {
            "realm" => realm = Some(val),
            "service" => service = Some(val),
            "scope" => scope = Some(val),
            _ => {}
        }
    }
    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

fn percent_encode_query(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn map_http_status(status: u16) -> Errno {
    match status {
        401 | 403 => Errno::EACCES,
        404 => Errno::ENOENT,
        409 => Errno::EBUSY,
        413 => Errno::EFBIG,
        416 => Errno::ERANGE,
        429 => Errno::EAGAIN,
        503 => Errno::EPROTONOSUPPORT,
        507 => Errno::EDQUOT,
        400 => Errno::EINVAL,
        _ => Errno::EIO,
    }
}

/// Portable OCI Distribution v1.1 client with automatic Bearer token negotiation & caching.
pub struct OciClient<T: OciTransport> {
    transport: Rc<T>,
    base_url: String,
    tokens: RefCell<HashMap<String, String>>,
}

impl<T: OciTransport> Clone for OciClient<T> {
    fn clone(&self) -> Self {
        Self {
            transport: Rc::clone(&self.transport),
            base_url: self.base_url.clone(),
            tokens: RefCell::new(self.tokens.borrow().clone()),
        }
    }
}

impl<T: OciTransport> OciClient<T> {
    pub fn new(base_url: impl Into<String>, transport: Rc<T>) -> Self {
        let base = base_url.into().trim_end_matches('/').to_string();
        Self {
            transport,
            base_url: base,
            tokens: RefCell::new(HashMap::new()),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn transport(&self) -> &Rc<T> {
        &self.transport
    }

    fn resolve_url(&self, path_or_url: &str) -> String {
        if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
            path_or_url.to_string()
        } else if path_or_url.starts_with('/') {
            format!("{}{}", self.base_url, path_or_url)
        } else {
            format!("{}/{}", self.base_url, path_or_url)
        }
    }

    fn realm_same_origin(&self, realm_url: &str) -> bool {
        fn origin_of(u: &str) -> Option<&str> {
            let scheme_end = u.find("://")?;
            let after_scheme = &u[scheme_end + 3..];
            let authority_end = after_scheme.find('/').unwrap_or(after_scheme.len());
            Some(&u[..scheme_end + 3 + authority_end])
        }
        if realm_url.starts_with('/') {
            return true;
        }
        if self.base_url.is_empty() {
            // Transport owns the origin (e.g. BrowserOciTransport -> self.ociRegistryFetch checks
            // `resolved.origin === self.location.origin`); still require http(s) + `/v2` path.
            let Some(origin) = origin_of(realm_url) else {
                return false;
            };
            let rest = &realm_url[origin.len()..];
            return (origin.starts_with("http://") || origin.starts_with("https://"))
                && (rest == "/v2" || rest.starts_with("/v2/"));
        }
        match (origin_of(&self.base_url), origin_of(realm_url)) {
            (Some(base_o), Some(realm_o)) => base_o.eq_ignore_ascii_case(realm_o),
            _ => false,
        }
    }

    async fn fetch_bearer_token(
        &self,
        challenge: &BearerChallenge,
        explicit_scopes: &[String],
    ) -> Result<String> {
        let mut url = self.resolve_url(&challenge.realm);
        if !self.realm_same_origin(&url) {
            return Err(Errno::EACCES);
        }
        let mut sep = if url.contains('?') { '&' } else { '?' };
        if let Some(ref svc) = challenge.service {
            url.push(sep);
            url.push_str("service=");
            url.push_str(&percent_encode_query(svc));
            sep = '&';
        }
        if !explicit_scopes.is_empty() {
            for s in explicit_scopes {
                url.push(sep);
                url.push_str("scope=");
                url.push_str(&percent_encode_query(s));
                sep = '&';
            }
        } else if let Some(ref s) = challenge.scope {
            url.push(sep);
            url.push_str("scope=");
            url.push_str(&percent_encode_query(s));
        }
        let auth_hdrs = self.transport.token_auth_headers();
        let reply = self.transport.request("GET", &url, &auth_hdrs, &[]).await?;
        if reply.status != 200 {
            return Err(map_http_status(reply.status));
        }
        let parsed: OciTokenResponse =
            serde_json::from_slice(&reply.body).map_err(|_| Errno::EIO)?;
        if !parsed.token.is_empty() {
            Ok(parsed.token)
        } else if !parsed.access_token.is_empty() {
            Ok(parsed.access_token)
        } else {
            Err(Errno::EACCES)
        }
    }

    async fn send_authed(
        &self,
        method: &str,
        path_or_url: &str,
        extra_headers: &[(String, String)],
        body: &[u8],
        scopes: &[String],
    ) -> Result<OciHttpReply> {
        let url = self.resolve_url(path_or_url);
        let cache_key = scopes.join(" ");
        let cached = self.tokens.borrow().get(&cache_key).cloned();

        let mut hdrs = extra_headers.to_vec();
        if let Some(tok) = cached {
            hdrs.push(("Authorization".into(), format!("Bearer {tok}")));
        }
        let reply = self.transport.request(method, &url, &hdrs, body).await?;
        if reply.status != 401 {
            return Ok(reply);
        }
        let Some(www_auth) = reply.header("WWW-Authenticate") else {
            return Ok(reply);
        };
        let Some(challenge) = parse_www_authenticate(www_auth) else {
            return Ok(reply);
        };
        let tok = self.fetch_bearer_token(&challenge, scopes).await?;
        self.tokens.borrow_mut().insert(cache_key, tok.clone());

        let mut retry_hdrs = extra_headers.to_vec();
        retry_hdrs.push(("Authorization".into(), format!("Bearer {tok}")));
        self.transport
            .request(method, &url, &retry_hdrs, body)
            .await
    }

    pub async fn ping(&self) -> Result<()> {
        let reply = self.send_authed("GET", "/v2/", &[], &[], &[]).await?;
        if reply.status == 200 {
            Ok(())
        } else {
            Err(map_http_status(reply.status))
        }
    }

    pub async fn head_blob(&self, repo: &str, digest: &str) -> Result<Option<u64>> {
        if !valid_repo_name(repo) || parse_sha256_digest(digest).is_none() {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull")];
        let reply = self
            .send_authed(
                "HEAD",
                &format!("/v2/{repo}/blobs/{digest}"),
                &[],
                &[],
                &scopes,
            )
            .await?;
        match reply.status {
            200 => {
                let len = reply
                    .header("Content-Length")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                Ok(Some(len))
            }
            404 => Ok(None),
            other => Err(map_http_status(other)),
        }
    }

    pub async fn get_blob(&self, repo: &str, digest: &str) -> Result<Vec<u8>> {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let expected_hex = parse_sha256_digest(digest).ok_or(Errno::EINVAL)?;
        let expected = digest_from_hex(expected_hex)?;
        let scopes = vec![format!("repository:{repo}:pull")];
        let reply = self
            .send_authed(
                "GET",
                &format!("/v2/{repo}/blobs/{digest}"),
                &[],
                &[],
                &scopes,
            )
            .await?;
        if reply.status != 200 {
            return Err(map_http_status(reply.status));
        }
        if sha256(&reply.body) != expected {
            return Err(Errno::EIO);
        }
        Ok(reply.body)
    }

    pub async fn get_blob_range(
        &self,
        repo: &str,
        digest: &str,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        if !valid_repo_name(repo) || parse_sha256_digest(digest).is_none() {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Ok(Vec::new());
        }
        let end = offset
            .checked_add(len)
            .and_then(|v| v.checked_sub(1))
            .ok_or(Errno::EINVAL)?;
        let scopes = vec![format!("repository:{repo}:pull")];
        let hdrs = vec![("Range".into(), format!("bytes={offset}-{end}"))];
        let reply = self
            .send_authed(
                "GET",
                &format!("/v2/{repo}/blobs/{digest}"),
                &hdrs,
                &[],
                &scopes,
            )
            .await?;
        match reply.status {
            206 => {
                if reply.body.len() as u64 != len {
                    return Err(Errno::EIO);
                }
                Ok(reply.body)
            }
            200 => {
                let start = usize::try_from(offset).map_err(|_| Errno::EIO)?;
                let count = usize::try_from(len).map_err(|_| Errno::EIO)?;
                let stop = start.checked_add(count).ok_or(Errno::EIO)?;
                if stop > reply.body.len() {
                    return Err(Errno::EIO);
                }
                Ok(reply.body[start..stop].to_vec())
            }
            other => Err(map_http_status(other)),
        }
    }

    pub async fn put_blob_monolithic(&self, repo: &str, digest: &str, bytes: &[u8]) -> Result<()> {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let expected_hex = parse_sha256_digest(digest).ok_or(Errno::EINVAL)?;
        if digest_to_hex(&sha256(bytes)) != expected_hex {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull,push")];
        let hdrs = vec![("Content-Type".into(), "application/octet-stream".into())];
        let reply = self
            .send_authed(
                "POST",
                &format!("/v2/{repo}/blobs/uploads/?digest={digest}"),
                &hdrs,
                bytes,
                &scopes,
            )
            .await?;
        if reply.status == 201 {
            return Ok(());
        }
        // Fallback to chunked upload if a registry returns 202 for monolithic POST.
        if reply.status == 202
            && let Some(loc) = reply.header("Location")
        {
            let sep = if loc.contains('?') { '&' } else { '?' };
            let fin = self
                .send_authed(
                    "PUT",
                    &format!("{loc}{sep}digest={digest}"),
                    &hdrs,
                    bytes,
                    &scopes,
                )
                .await?;
            if fin.status == 201 {
                return Ok(());
            }
            return Err(map_http_status(fin.status));
        }
        Err(map_http_status(reply.status))
    }

    pub async fn put_blob_chunked(
        &self,
        repo: &str,
        digest: &str,
        bytes: &[u8],
        chunk_size: usize,
    ) -> Result<()> {
        if !valid_repo_name(repo) || chunk_size == 0 {
            return Err(Errno::EINVAL);
        }
        let expected_hex = parse_sha256_digest(digest).ok_or(Errno::EINVAL)?;
        if digest_to_hex(&sha256(bytes)) != expected_hex {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull,push")];
        let start = self
            .send_authed(
                "POST",
                &format!("/v2/{repo}/blobs/uploads/"),
                &[],
                &[],
                &scopes,
            )
            .await?;
        if start.status != 202 {
            return Err(map_http_status(start.status));
        }
        let mut loc = start.header("Location").ok_or(Errno::EIO)?.to_string();
        let mut offset = 0usize;
        for chunk in bytes.chunks(chunk_size) {
            let end = offset + chunk.len() - 1;
            let hdrs = vec![
                ("Content-Type".into(), "application/octet-stream".into()),
                ("Content-Range".into(), format!("{offset}-{end}")),
            ];
            let patch = self
                .send_authed("PATCH", &loc, &hdrs, chunk, &scopes)
                .await?;
            if patch.status != 202 {
                return Err(map_http_status(patch.status));
            }
            if let Some(next_loc) = patch.header("Location") {
                loc = next_loc.to_string();
            }
            offset += chunk.len();
        }
        let sep = if loc.contains('?') { '&' } else { '?' };
        let fin = self
            .send_authed(
                "PUT",
                &format!("{loc}{sep}digest={digest}"),
                &[("Content-Type".into(), "application/octet-stream".into())],
                &[],
                &scopes,
            )
            .await?;
        if fin.status == 201 {
            Ok(())
        } else {
            Err(map_http_status(fin.status))
        }
    }

    pub async fn mount_blob(&self, repo: &str, from_repo: &str, digest: &str) -> Result<bool> {
        if !valid_repo_name(repo)
            || !valid_repo_name(from_repo)
            || parse_sha256_digest(digest).is_none()
        {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![
            format!("repository:{repo}:pull,push"),
            format!("repository:{from_repo}:pull"),
        ];
        let reply = self
            .send_authed(
                "POST",
                &format!(
                    "/v2/{repo}/blobs/uploads/?mount={}&from={}",
                    percent_encode_query(digest),
                    percent_encode_query(from_repo)
                ),
                &[],
                &[],
                &scopes,
            )
            .await?;
        match reply.status {
            201 => Ok(true),
            202 => Ok(false),
            other => Err(map_http_status(other)),
        }
    }

    pub async fn head_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> Result<Option<(String, String, u64)>> {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull")];
        let hdrs = vec![(
            "Accept".into(),
            format!("{OCI_IMAGE_MANIFEST_MEDIA_TYPE}, {OCI_IMAGE_INDEX_MEDIA_TYPE}"),
        )];
        let reply = self
            .send_authed(
                "HEAD",
                &format!("/v2/{repo}/manifests/{reference}"),
                &hdrs,
                &[],
                &scopes,
            )
            .await?;
        match reply.status {
            200 => {
                let digest = reply
                    .header("Docker-Content-Digest")
                    .ok_or(Errno::EIO)?
                    .to_string();
                let media_type = reply
                    .header("Content-Type")
                    .unwrap_or(OCI_IMAGE_MANIFEST_MEDIA_TYPE)
                    .to_string();
                let size = reply
                    .header("Content-Length")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                Ok(Some((digest, media_type, size)))
            }
            404 => Ok(None),
            other => Err(map_http_status(other)),
        }
    }

    pub async fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> Result<(String, String, Vec<u8>)> {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull")];
        let hdrs = vec![(
            "Accept".into(),
            format!("{OCI_IMAGE_MANIFEST_MEDIA_TYPE}, {OCI_IMAGE_INDEX_MEDIA_TYPE}"),
        )];
        let reply = self
            .send_authed(
                "GET",
                &format!("/v2/{repo}/manifests/{reference}"),
                &hdrs,
                &[],
                &scopes,
            )
            .await?;
        if reply.status != 200 {
            return Err(map_http_status(reply.status));
        }
        let actual = format!("sha256:{}", digest_to_hex(&sha256(&reply.body)));
        if parse_sha256_digest(reference).is_some() && actual != reference {
            return Err(Errno::EIO);
        }
        if let Some(hdr_digest) = reply.header("Docker-Content-Digest")
            && hdr_digest != actual
        {
            return Err(Errno::EIO);
        }
        let media_type = reply
            .header("Content-Type")
            .unwrap_or(OCI_IMAGE_MANIFEST_MEDIA_TYPE)
            .to_string();
        Ok((actual, media_type, reply.body))
    }

    pub async fn put_manifest(
        &self,
        repo: &str,
        reference: &str,
        media_type: &str,
        body: &[u8],
    ) -> Result<(String, Option<String>)> {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull,push")];
        let hdrs = vec![("Content-Type".into(), media_type.to_string())];
        let reply = self
            .send_authed(
                "PUT",
                &format!("/v2/{repo}/manifests/{reference}"),
                &hdrs,
                body,
                &scopes,
            )
            .await?;
        if reply.status != 201 {
            return Err(map_http_status(reply.status));
        }
        let actual = format!("sha256:{}", digest_to_hex(&sha256(body)));
        let digest = reply
            .header("Docker-Content-Digest")
            .map(str::to_string)
            .unwrap_or(actual);
        let subject = reply.header("OCI-Subject").map(str::to_string);
        Ok((digest, subject))
    }

    pub async fn delete_manifest(&self, repo: &str, reference: &str) -> Result<()> {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull,push")];
        let reply = self
            .send_authed(
                "DELETE",
                &format!("/v2/{repo}/manifests/{reference}"),
                &[],
                &[],
                &scopes,
            )
            .await?;
        if matches!(reply.status, 200 | 202) {
            Ok(())
        } else {
            Err(map_http_status(reply.status))
        }
    }

    pub async fn delete_blob(&self, repo: &str, digest: &str) -> Result<()> {
        if !valid_repo_name(repo) || parse_sha256_digest(digest).is_none() {
            return Err(Errno::EINVAL);
        }
        let scopes = vec![format!("repository:{repo}:pull,push")];
        let reply = self
            .send_authed(
                "DELETE",
                &format!("/v2/{repo}/blobs/{digest}"),
                &[],
                &[],
                &scopes,
            )
            .await?;
        if matches!(reply.status, 200 | 202) {
            Ok(())
        } else {
            Err(map_http_status(reply.status))
        }
    }

    pub async fn list_tags(
        &self,
        repo: &str,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<(Vec<String>, Option<String>)> {
        if !valid_repo_name(repo) {
            return Err(Errno::EINVAL);
        }
        let mut path = format!("/v2/{repo}/tags/list");
        let mut sep = '?';
        if let Some(limit) = n {
            path.push(sep);
            path.push_str(&format!("n={limit}"));
            sep = '&';
        }
        if let Some(cursor) = last {
            path.push(sep);
            path.push_str("last=");
            path.push_str(&percent_encode_query(cursor));
        }
        let scopes = vec![format!("repository:{repo}:pull")];
        let reply = self.send_authed("GET", &path, &[], &[], &scopes).await?;
        if reply.status != 200 {
            return Err(map_http_status(reply.status));
        }
        let list: OciTagsList = serde_json::from_slice(&reply.body).map_err(|_| Errno::EIO)?;
        let link = reply.header("Link").map(str::to_string);
        Ok((list.tags, link))
    }

    pub async fn list_referrers(
        &self,
        repo: &str,
        digest: &str,
        artifact_type: Option<&str>,
    ) -> Result<(OciImageIndex, bool)> {
        if !valid_repo_name(repo) || parse_sha256_digest(digest).is_none() {
            return Err(Errno::EINVAL);
        }
        let mut path = format!("/v2/{repo}/referrers/{digest}");
        if let Some(at) = artifact_type.filter(|s| !s.is_empty()) {
            path.push_str("?artifactType=");
            path.push_str(&percent_encode_query(at));
        }
        let scopes = vec![format!("repository:{repo}:pull")];
        let reply = self.send_authed("GET", &path, &[], &[], &scopes).await?;
        if reply.status != 200 {
            return Err(map_http_status(reply.status));
        }
        let index: OciImageIndex = serde_json::from_slice(&reply.body).map_err(|_| Errno::EIO)?;
        let filtered = reply
            .header("OCI-Filters-Applied")
            .is_some_and(|v| v.contains("artifactType"));
        Ok((index, filtered))
    }
}

/// Generic OCI recursive artifact mirror (`oras cp -r` semantics).
/// Copies an OCI Image Manifest or OCI Image Index (including all child manifests, config & layer
/// blobs, and optionally OCI 1.1 referrers) from `src` to an independent registry `dst`.
pub async fn mirror_oci_artifact<S: OciTransport, D: OciTransport>(
    src: &OciClient<S>,
    src_repo: &str,
    src_ref: &str,
    dst: &OciClient<D>,
    dst_repo: &str,
    dst_ref: &str,
    include_referrers: bool,
) -> Result<String> {
    let mut copied_blobs: HashSet<String> = HashSet::new();
    let mut copied_manifests: HashSet<String> = HashSet::new();
    mirror_manifest_recursive(
        src,
        src_repo,
        src_ref,
        dst,
        dst_repo,
        dst_ref,
        include_referrers,
        0,
        &mut copied_blobs,
        &mut copied_manifests,
    )
    .await
}

const MAX_MIRROR_DEPTH: usize = 8;

#[allow(clippy::too_many_arguments)]
fn mirror_manifest_recursive<'a, S: OciTransport, D: OciTransport>(
    src: &'a OciClient<S>,
    src_repo: &'a str,
    src_ref: &'a str,
    dst: &'a OciClient<D>,
    dst_repo: &'a str,
    dst_ref: &'a str,
    include_referrers: bool,
    depth: usize,
    copied_blobs: &'a mut HashSet<String>,
    copied_manifests: &'a mut HashSet<String>,
) -> BoxFuture<'a, String> {
    Box::pin(async move {
        if depth >= MAX_MIRROR_DEPTH {
            return Err(Errno::ELOOP);
        }
        let (digest, media_type, raw_bytes) = src.get_manifest(src_repo, src_ref).await?;
        let val: serde_json::Value = serde_json::from_slice(&raw_bytes).map_err(|_| Errno::EIO)?;
        let obj = val.as_object().ok_or(Errno::EIO)?;

        if obj.contains_key("manifests") {
            let index: OciImageIndex = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            for child in &index.manifests {
                if !copied_manifests.contains(&child.digest) {
                    mirror_manifest_recursive(
                        src,
                        src_repo,
                        &child.digest,
                        dst,
                        dst_repo,
                        &child.digest,
                        include_referrers,
                        depth + 1,
                        copied_blobs,
                        copied_manifests,
                    )
                    .await?;
                }
            }
        } else if obj.contains_key("config") && obj.contains_key("layers") {
            let manifest: OciImageManifest = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            let mut blob_digests = Vec::with_capacity(1 + manifest.layers.len());
            blob_digests.push(manifest.config.digest);
            for l in manifest.layers {
                blob_digests.push(l.digest);
            }
            for bd in blob_digests {
                if copied_blobs.insert(bd.clone()) && dst.head_blob(dst_repo, &bd).await?.is_none()
                {
                    let bytes = src.get_blob(src_repo, &bd).await?;
                    dst.put_blob_monolithic(dst_repo, &bd, &bytes).await?;
                }
            }
        } else {
            return Err(Errno::EIO);
        }

        let (pushed_digest, _) = dst
            .put_manifest(dst_repo, dst_ref, &media_type, &raw_bytes)
            .await?;
        if pushed_digest != digest {
            return Err(Errno::EIO);
        }
        copied_manifests.insert(digest.clone());

        if include_referrers {
            let (ref_index, _) = src.list_referrers(src_repo, &digest, None).await?;
            for r in ref_index.manifests {
                if !copied_manifests.contains(&r.digest) {
                    mirror_manifest_recursive(
                        src,
                        src_repo,
                        &r.digest,
                        dst,
                        dst_repo,
                        &r.digest,
                        false,
                        depth + 1,
                        copied_blobs,
                        copied_manifests,
                    )
                    .await?;
                }
            }
        }

        Ok(digest)
    })
}

/// Publish a detached Ed25519 signature (`os_image::Detached` JSON bytes signed over
/// `os_image::SIGNING_DOMAIN_OCI_ARTIFACT_V1`) as an OCI 1.1 referrer manifest targeting
/// `subject_digest`.
pub async fn attach_ed25519_signature<T: OciTransport>(
    client: &OciClient<T>,
    repo: &str,
    subject_digest: &str,
    subject_media_type: &str,
    subject_size: u64,
    detached_signature_json: &[u8],
) -> Result<(String, Option<String>)> {
    let parsed: os_image::Detached =
        os_image::parse(detached_signature_json).map_err(|_| Errno::EINVAL)?;
    if parsed.format != "os.signature" || parsed.version != 1 {
        return Err(Errno::EINVAL);
    }
    if parse_sha256_digest(subject_digest).is_none() {
        return Err(Errno::EINVAL);
    }

    if client
        .head_blob(repo, OCI_EMPTY_JSON_DIGEST)
        .await?
        .is_none()
    {
        client
            .put_blob_monolithic(repo, OCI_EMPTY_JSON_DIGEST, OCI_EMPTY_JSON_BYTES)
            .await?;
    }
    let sig_digest = format!("sha256:{}", digest_to_hex(&sha256(detached_signature_json)));
    if client.head_blob(repo, &sig_digest).await?.is_none() {
        client
            .put_blob_monolithic(repo, &sig_digest, detached_signature_json)
            .await?;
    }

    let mut annotations = BTreeMap::new();
    annotations.insert("org.os.signature.key".into(), parsed.key);
    let referrer_manifest = OciImageManifest {
        schema_version: 2,
        media_type: Some(OCI_IMAGE_MANIFEST_MEDIA_TYPE.into()),
        artifact_type: Some(OS_SIGNATURE_ARTIFACT_TYPE.into()),
        config: OciDescriptor {
            media_type: OCI_EMPTY_CONFIG_MEDIA_TYPE.into(),
            digest: OCI_EMPTY_JSON_DIGEST.into(),
            size: OCI_EMPTY_JSON_BYTES.len() as u64,
            urls: None,
            annotations: None,
            artifact_type: None,
            platform: None,
            data: None,
        },
        layers: vec![OciDescriptor {
            media_type: OS_SIGNATURE_ARTIFACT_TYPE.into(),
            digest: sig_digest,
            size: detached_signature_json.len() as u64,
            urls: None,
            annotations: None,
            artifact_type: None,
            platform: None,
            data: None,
        }],
        subject: Some(OciDescriptor {
            media_type: subject_media_type.into(),
            digest: subject_digest.into(),
            size: subject_size,
            urls: None,
            annotations: None,
            artifact_type: None,
            platform: None,
            data: None,
        }),
        annotations: Some(annotations),
    };
    let manifest_bytes = serde_json::to_vec(&referrer_manifest).map_err(|_| Errno::EIO)?;
    let manifest_digest = format!("sha256:{}", digest_to_hex(&sha256(&manifest_bytes)));
    client
        .put_manifest(
            repo,
            &manifest_digest,
            OCI_IMAGE_MANIFEST_MEDIA_TYPE,
            &manifest_bytes,
        )
        .await
}

/// Verify at least one trusted, non-revoked Ed25519 referrer signature (`os.oci.artifact.v1`)
/// for the exact subject manifest bytes resolved at `repo`/`reference`. Fails closed (`EACCES`)
/// if no valid signature exists or all signatures are tampered/untrusted/revoked.
pub async fn verify_ed25519_referrers<T: OciTransport>(
    client: &OciClient<T>,
    repo: &str,
    reference: &str,
    trust: &os_image::Trust,
) -> Result<(String, String)> {
    let (subject_digest, _subject_mt, subject_bytes) = client.get_manifest(repo, reference).await?;
    let (ref_index, _) = client
        .list_referrers(repo, &subject_digest, Some(OS_SIGNATURE_ARTIFACT_TYPE))
        .await?;
    for desc in ref_index.manifests {
        let Ok((_ref_digest, _ref_mt, ref_bytes)) = client.get_manifest(repo, &desc.digest).await
        else {
            continue;
        };
        let Ok(manifest) = serde_json::from_slice::<OciImageManifest>(&ref_bytes) else {
            continue;
        };
        if manifest.subject.as_ref().map(|s| s.digest.as_str()) != Some(subject_digest.as_str()) {
            continue;
        }
        for layer in manifest.layers {
            if layer.media_type != OS_SIGNATURE_ARTIFACT_TYPE {
                continue;
            }
            let Ok(sig_bytes) = client.get_blob(repo, &layer.digest).await else {
                continue;
            };
            if let Ok(key_id) = trust.verify(
                os_image::SIGNING_DOMAIN_OCI_ARTIFACT_V1,
                &subject_bytes,
                &sig_bytes,
            ) {
                return Ok((subject_digest, key_id));
            }
        }
    }
    Err(Errno::EACCES)
}
