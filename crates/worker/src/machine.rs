//! Narrowed `Machine` Durable Object (`ServiceAuth v2` + per-credential remote `io.max` +
//! bounded host-loss lease cleanup & durable token revocation).
//!
//! Retired process, PID, signal, seat, init-owner, and login-session tables & routes have been
//! removed cleanly (`docs/architecture/contract.md` §2.1, §2.3, §2.10, §2.12).
use crate::db::{Db, transact};
use crate::{auth, procs};
use abi::auth_v2::{
    self, AttachResult, INSTANCE_LEASE_SECONDS, RenewResult, Request as AuthRequest,
    Response as AuthResponse, ServiceCredIssued, TOKENS_MAX, VERSION, negotiate_hello, valid_id,
};
use abi::{Errno, Error, Return};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeMap;
use worker::*;

/// Retry interval (ms) when flushing durable revocations to `OsAuthority` fails transiently.
const REVOKE_RETRY_MS: i64 = 10_000;

#[durable_object]
pub struct Machine {
    state: State,
    env: Env,
    ready: Cell<bool>,
}

impl DurableObject for Machine {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ready: Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        self.ensure_schema()?;
        let now = auth::now();
        transact(&self.state, move |db| {
            db.expire_machine_leases(now);
            ((), true)
        })?;
        let path = req.path();
        let response = match (req.method(), path.as_str()) {
            (Method::Post, "/api/service-auth") => self.handle_service_auth(&mut req).await?,
            (Method::Post, "/internal/io") => self.handle_internal_io(&mut req).await?,
            // All retired server process registry routes fail closed.
            (Method::Post, "/api/sys" | "/internal/sys") => {
                return auth_error_response(&Error::because(
                    Errno::ENOSYS,
                    "server process registry has been removed; processes are instance-local",
                ));
            }
            _ => return Response::error("Not found", 404),
        };
        self.settle().await;
        Ok(response)
    }

    async fn alarm(&self) -> Result<Response> {
        self.ensure_schema()?;
        let now = auth::now();
        transact(&self.state, move |db| {
            db.expire_machine_leases(now);
            ((), true)
        })?;
        self.settle().await;
        Response::ok("")
    }
}

impl Machine {
    fn ensure_schema(&self) -> Result<()> {
        if !self.ready.get() {
            procs::create(&self.state.storage().sql())?;
            self.ready.set(true);
        }
        Ok(())
    }

    async fn handle_internal_io(&self, req: &mut Request) -> Result<Response> {
        let ask: crate::resources::IoRequest = match req.json().await {
            Ok(ask) => ask,
            Err(_) => {
                return Response::from_json(&Return::Err(Error::new(Errno::EINVAL)));
            }
        };
        let now_secs = auth::now();
        let now_ms = js_sys::Date::now() as u64;
        let result = transact(&self.state, move |db| {
            let res = db
                .charge_remote_io(&ask.ns, &ask.token, ask.write, ask.bytes, now_secs, now_ms)
                .map(|delay_ms| json!({ "delay_ms": delay_ms }));
            let commit = res.is_ok();
            (res, commit)
        })?;
        Response::from_json(&match result {
            Ok(v) => Return::Ok(v),
            Err(e) => Return::Err(e),
        })
    }

    async fn handle_service_auth(&self, req: &mut Request) -> Result<Response> {
        if req
            .headers()
            .get("Content-Length")?
            .and_then(|v| v.parse::<u64>().ok())
            .is_none_or(|len| len > abi::BATCH_BYTES)
        {
            return auth_error_response(&Errno::E2BIG.into());
        }
        let body = req.text().await?;
        let Ok(raw_val) = serde_json::from_str::<Value>(&body) else {
            return auth_error_response(&Error::because(Errno::EINVAL, "invalid ServiceAuth JSON"));
        };
        // Check explicit top-level `version` field if present on non-hello messages.
        if let Some(ver) = raw_val.get("version").and_then(Value::as_u64)
            && ver != u64::from(VERSION)
        {
            return auth_error_response(&Error::because(
                Errno::EPROTONOSUPPORT,
                format!("ServiceAuth v{VERSION} required"),
            ));
        }
        let Ok(parsed) = serde_json::from_value::<AuthRequest>(raw_val) else {
            return auth_error_response(&Error::because(
                Errno::EINVAL,
                "invalid ServiceAuth v2 request",
            ));
        };
        let ns = Db::namespace(
            auth::token_key(req).as_deref(),
            auth::guest_key(req).as_deref(),
        );
        let cookie = req.headers().get("Cookie")?;
        let release = req.headers().get("X-OS-Release")?;
        let now = auth::now();

        match parsed {
            AuthRequest::Hello(hello) => match negotiate_hello(&hello) {
                Ok(welcome) => Response::from_json(&AuthResponse::Welcome(welcome)),
                Err(err) => auth_error_response(&err),
            },
            AuthRequest::AttachInstance(attach) => {
                if !valid_id(&attach.instance.instance)
                    || !valid_id(&attach.instance.host)
                    || !valid_id(&attach.host_proof)
                {
                    return auth_error_response(&Errno::EINVAL.into());
                }
                let ns_c = ns.clone();
                let res = transact(&self.state, move |db| {
                    let r = db.attach_instance(
                        &ns_c,
                        &attach.instance.instance,
                        &attach.instance.host,
                        &attach.host_proof,
                        now,
                    );
                    let commit = r.is_ok();
                    (r, commit)
                })?;
                match res {
                    Ok(row) => Response::from_json(&AuthResponse::Attached(AttachResult {
                        version: VERSION,
                        instance_id: row.instance_id,
                        lease_seconds: INSTANCE_LEASE_SECONDS,
                        host_epoch: row.host_epoch,
                    })),
                    Err(err) => auth_error_response(&err),
                }
            }
            AuthRequest::MintServiceCred(mint) => {
                if !valid_id(&mint.instance_id) || !valid_id(&mint.host_proof) {
                    return auth_error_response(&Errno::EINVAL.into());
                }
                let ns_v = ns.clone();
                let inst_v = mint.instance_id.clone();
                let proof_v = mint.host_proof.clone();
                let verified = transact(&self.state, move |db| {
                    let r = db
                        .verify_instance(&ns_v, &inst_v, &proof_v, now)
                        .and_then(|_| {
                            if db.active_service_token_count(&ns_v, now)
                                >= procs::SERVICE_TOKENS_MAX
                            {
                                Err(Errno::ENOSPC.into())
                            } else {
                                Ok(())
                            }
                        });
                    (r, false)
                })?;
                if let Err(err) = verified {
                    return auth_error_response(&err);
                }
                let raw_token = auth::random_token();
                let token_hash = auth::token_hash(&raw_token);
                let cgroup = mint.cgroup.clone().unwrap_or_else(|| "/user".into());
                let generation = mint.generation.clone().or_else(|| release.clone());
                let authority_body = json!({
                    "ns": ns,
                    "instance_id": mint.instance_id,
                    "token_hash": token_hash,
                    "scope": mint.scope,
                    "cloud_access": mint.cloud_access,
                    "umask": mint.umask & 0o777,
                    "cgroup": cgroup,
                    "generation": generation,
                    "sudo": mint.sudo,
                });
                let auth_resp = self
                    .call_authority(
                        "/internal/service-auth/mint",
                        cookie.as_deref(),
                        release.as_deref(),
                        authority_body,
                    )
                    .await;
                let minted = match auth_resp {
                    Ok(val) => val,
                    Err(err) => return auth_error_response(&err),
                };
                let uid = minted["uid"].as_u64().unwrap_or(65534) as u32;
                let gid = minted["gid"].as_u64().unwrap_or(65534) as u32;
                let groups: Vec<u32> =
                    serde_json::from_value(minted["groups"].clone()).unwrap_or_else(|_| vec![gid]);
                let umask = minted["umask"].as_u64().unwrap_or(0o022) as u16;
                let cloud_access = minted["cloud_access"].as_bool().unwrap_or(false);
                let scope: auth_v2::RemoteScope =
                    serde_json::from_value(minted["scope"].clone()).unwrap_or_default();
                let expires = minted["expires"]
                    .as_u64()
                    .unwrap_or_else(|| now.saturating_add(abi::PROCESS_TOKEN_TTL));
                let lineage = minted["lineage"].as_str().unwrap_or_default().to_string();

                let ns_r = ns.clone();
                let inst_r = mint.instance_id.clone();
                let proof_r = mint.host_proof.clone();
                let tok_r = raw_token.clone();
                let hash_r = token_hash.clone();
                let lin_r = lineage.clone();
                let cg_r = cgroup.clone();
                let scope_r = scope.clone();
                let rbps = mint.rbps;
                let wbps = mint.wbps;
                let post_now = auth::now();
                let rec = transact(&self.state, move |db| {
                    let r = db
                        .verify_instance(&ns_r, &inst_r, &proof_r, post_now)
                        .and_then(|_| {
                            db.record_service_token(
                                &ns_r,
                                &inst_r,
                                &tok_r,
                                uid,
                                gid,
                                &lin_r,
                                &cg_r,
                                &scope_r,
                                cloud_access,
                                expires,
                                rbps,
                                wbps,
                                post_now,
                            )
                        });
                    if r.is_err() {
                        // Queue orphan authority credential for immediate revocation in `settle()`.
                        db.queue_orphan_revocation(&ns_r, &hash_r, post_now);
                    }
                    (r, true)
                })?;
                if let Err(err) = rec {
                    return auth_error_response(&err);
                }
                Response::from_json(&AuthResponse::Cred(ServiceCredIssued {
                    version: VERSION,
                    token: raw_token,
                    uid,
                    gid,
                    groups,
                    umask,
                    cloud_access,
                    scope,
                    expires,
                    instance_id: mint.instance_id,
                    lineage,
                }))
            }
            AuthRequest::DeriveServiceCred(derive) => {
                if !valid_id(&derive.instance_id)
                    || !valid_id(&derive.host_proof)
                    || derive.parent_token.is_empty()
                {
                    return auth_error_response(&Errno::EINVAL.into());
                }
                let ns_v = ns.clone();
                let inst_v = derive.instance_id.clone();
                let proof_v = derive.host_proof.clone();
                let ptok_v = derive.parent_token.clone();
                let revoke_parent_v = derive.revoke_parent;
                let parent_row = transact(&self.state, move |db| {
                    let r = db
                        .verify_instance(&ns_v, &inst_v, &proof_v, now)
                        .and_then(|_| {
                            let count = db.active_service_token_count(&ns_v, now);
                            if !revoke_parent_v && count >= procs::SERVICE_TOKENS_MAX {
                                return Err(Errno::ENOSPC.into());
                            }
                            db.service_token_for_instance(&ns_v, &inst_v, &ptok_v, now)
                                .ok_or_else(|| {
                                    Error::because(
                                        Errno::EACCES,
                                        "parent token not owned by instance",
                                    )
                                })
                        });
                    (r, false)
                })?;
                let parent_row = match parent_row {
                    Ok(r) => r,
                    Err(err) => return auth_error_response(&err),
                };
                let parent_scope: auth_v2::RemoteScope =
                    serde_json::from_str(&parent_row.scope).unwrap_or_default();
                let requested_scope = parent_scope.attenuate(&derive.scope);
                let requested_cloud = (parent_row.cloud_access != 0)
                    && derive.cloud_access
                    && requested_scope.cloud_fs;
                let new_raw = auth::random_token();
                let new_hash = auth::token_hash(&new_raw);
                let cgroup = derive.cgroup.clone().unwrap_or(parent_row.cgroup.clone());
                let body = json!({
                    "ns": ns,
                    "instance_id": derive.instance_id,
                    "parent_hash": parent_row.token_hash,
                    "new_hash": new_hash,
                    "scope": requested_scope,
                    "cloud_access": requested_cloud,
                    "umask": derive.umask.map(|m| m & 0o777),
                    "cgroup": cgroup,
                    "revoke_parent": derive.revoke_parent,
                });
                let derived = match self
                    .call_authority(
                        "/internal/service-auth/derive",
                        cookie.as_deref(),
                        release.as_deref(),
                        body,
                    )
                    .await
                {
                    Ok(v) => v,
                    Err(err) => return auth_error_response(&err),
                };
                let uid = derived["uid"].as_u64().unwrap_or(u64::from(parent_row.uid)) as u32;
                let gid = derived["gid"].as_u64().unwrap_or(u64::from(parent_row.gid)) as u32;
                let groups: Vec<u32> =
                    serde_json::from_value(derived["groups"].clone()).unwrap_or_else(|_| vec![gid]);
                let umask = derived["umask"].as_u64().unwrap_or(0o022) as u16;
                let auth_scope: auth_v2::RemoteScope =
                    serde_json::from_value(derived["scope"].clone()).unwrap_or_default();
                let auth_cloud =
                    derived["cloud_access"].as_bool().unwrap_or(false) && auth_scope.cloud_fs;
                let expires = derived["expires"]
                    .as_u64()
                    .unwrap_or_else(|| now.saturating_add(abi::PROCESS_TOKEN_TTL));
                let lineage = derived["lineage"]
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or(parent_row.lineage);
                let ns_r = ns.clone();
                let inst_r = derive.instance_id.clone();
                let proof_r = derive.host_proof.clone();
                let ptok_r = derive.parent_token.clone();
                let raw_r = new_raw.clone();
                let new_hash_r = new_hash.clone();
                let lin_r = lineage.clone();
                let cg_r = cgroup.clone();
                let sc_r = auth_scope.clone();
                let ph_r = parent_row.token_hash.clone();
                let revoke_parent = derive.revoke_parent;
                let rbps = derive.rbps;
                let wbps = derive.wbps;
                let post_now = auth::now();
                let rec = transact(&self.state, move |db| {
                    let r = db
                        .verify_instance(&ns_r, &inst_r, &proof_r, post_now)
                        .and_then(|_| {
                            if db
                                .service_token_for_instance(&ns_r, &inst_r, &ptok_r, post_now)
                                .is_none()
                            {
                                return Err(Error::because(
                                    Errno::ESTALE,
                                    "parent token was revoked concurrently",
                                ));
                            }
                            let parent_quota = db.io_quota_of(&ns_r, &ph_r);
                            if revoke_parent {
                                db.drop_service_token_hash(&ns_r, &ph_r);
                            }
                            let res = db.record_service_token(
                                &ns_r, &inst_r, &raw_r, uid, gid, &lin_r, &cg_r, &sc_r, auth_cloud,
                                expires, rbps, wbps, post_now,
                            );
                            if res.is_ok() {
                                db.inherit_remote_io_quota_from(
                                    &ns_r,
                                    &inst_r,
                                    parent_quota.as_ref(),
                                    &raw_r,
                                    &cg_r,
                                    rbps,
                                    wbps,
                                );
                            }
                            res
                        });
                    if r.is_err() {
                        db.queue_orphan_revocation(&ns_r, &new_hash_r, post_now);
                    }
                    (r, true)
                })?;
                if let Err(err) = rec {
                    return auth_error_response(&err);
                }
                Response::from_json(&AuthResponse::Cred(ServiceCredIssued {
                    version: VERSION,
                    token: new_raw,
                    uid,
                    gid,
                    groups,
                    umask,
                    cloud_access: auth_cloud,
                    scope: auth_scope,
                    expires,
                    instance_id: derive.instance_id,
                    lineage,
                }))
            }
            AuthRequest::RenewInstance(renew) => {
                if !valid_id(&renew.instance_id)
                    || !valid_id(&renew.host_proof)
                    || renew.active_tokens.len() > TOKENS_MAX
                {
                    return auth_error_response(&Errno::EINVAL.into());
                }
                let ns_r = ns.clone();
                let inst_r = renew.instance_id.clone();
                let proof_r = renew.host_proof.clone();
                let active_r = renew.active_tokens.clone();
                let owned = transact(&self.state, move |db| {
                    let r = db.collect_owned_tokens(&ns_r, &inst_r, &proof_r, &active_r, now);
                    (r, false)
                })?;
                let owned = match owned {
                    Ok(v) => v,
                    Err(err) => return auth_error_response(&err),
                };
                let mut revoked_raw = Vec::new();
                // Any active token NOT owned by this instance is reported revoked immediately.
                for raw in &renew.active_tokens {
                    if !owned.iter().any(|(r, _)| r == raw) {
                        revoked_raw.push(raw.clone());
                    }
                }
                let mut dead_hashes = Vec::new();
                if !owned.is_empty() {
                    let hashes: Vec<String> = owned.iter().map(|(_, h)| h.clone()).collect();
                    let val = match self
                        .call_authority(
                            "/internal/service-auth/renew",
                            cookie.as_deref(),
                            release.as_deref(),
                            json!({ "ns": ns, "hashes": hashes }),
                        )
                        .await
                    {
                        Ok(v) => v,
                        Err(err) => return auth_error_response(&err),
                    };
                    dead_hashes =
                        serde_json::from_value(val["revoked"].clone()).unwrap_or_default();
                    for (raw, hash) in &owned {
                        if dead_hashes.contains(hash) {
                            revoked_raw.push(raw.clone());
                        }
                    }
                }
                let live_hashes: Vec<String> = owned
                    .iter()
                    .filter(|(_, h)| !dead_hashes.contains(h))
                    .map(|(_, h)| h.clone())
                    .collect();
                let ns_c = ns.clone();
                let inst_c = renew.instance_id.clone();
                let proof_c = renew.host_proof.clone();
                let post_now = auth::now();
                let commit_res = transact(&self.state, move |db| {
                    let r = db.commit_instance_renewal(
                        &ns_c,
                        &inst_c,
                        &proof_c,
                        &live_hashes,
                        &dead_hashes,
                        post_now,
                    );
                    let commit = r.is_ok();
                    (r, commit)
                })?;
                if let Err(err) = commit_res {
                    return auth_error_response(&err);
                }
                Response::from_json(&AuthResponse::Renewed(RenewResult {
                    version: VERSION,
                    lease_seconds: INSTANCE_LEASE_SECONDS,
                    revoked: revoked_raw,
                }))
            }
            AuthRequest::RevokeTokens(rev) => {
                if !valid_id(&rev.instance_id)
                    || !valid_id(&rev.host_proof)
                    || rev.tokens.len() > TOKENS_MAX
                {
                    return auth_error_response(&Errno::EINVAL.into());
                }
                let ns_r = ns.clone();
                let inst_r = rev.instance_id.clone();
                let proof_r = rev.host_proof.clone();
                let toks_r = rev.tokens.clone();
                let res = transact(&self.state, move |db| {
                    let r = db
                        .verify_instance(&ns_r, &inst_r, &proof_r, now)
                        .map(|_| db.queue_token_revocations(&ns_r, &inst_r, &toks_r, now));
                    let commit = r.is_ok();
                    (r, commit)
                })?;
                match res {
                    Ok(count) => Response::from_json(&AuthResponse::Revoked { count }),
                    Err(err) => auth_error_response(&err),
                }
            }
            AuthRequest::DetachInstance(det) => {
                if !valid_id(&det.instance_id) || !valid_id(&det.host_proof) {
                    return auth_error_response(&Errno::EINVAL.into());
                }
                let ns_d = ns.clone();
                let inst_d = det.instance_id.clone();
                let proof_d = det.host_proof.clone();
                let res = transact(&self.state, move |db| {
                    let r = db.detach_instance(&ns_d, &inst_d, &proof_d, now);
                    let commit = r.is_ok();
                    (r, commit)
                })?;
                match res {
                    Ok(revoked) => Response::from_json(&AuthResponse::Detached { revoked }),
                    Err(err) => auth_error_response(&err),
                }
            }
            AuthRequest::SetRemoteIoQuota(quota) => {
                if !valid_id(&quota.instance_id)
                    || !valid_id(&quota.host_proof)
                    || quota.token.is_empty()
                    || quota.cgroup.is_empty()
                    || quota.cgroup.len() > 256
                {
                    return auth_error_response(&Errno::EINVAL.into());
                }
                let ns_q = ns.clone();
                let res = transact(&self.state, move |db| {
                    let r = db.set_remote_io_quota(
                        &ns_q,
                        &quota.instance_id,
                        &quota.host_proof,
                        &quota.token,
                        &quota.cgroup,
                        quota.rbps,
                        quota.wbps,
                        now,
                    );
                    let commit = r.is_ok();
                    (r, commit)
                })?;
                match res {
                    Ok(()) => Response::from_json(&AuthResponse::QuotaSet),
                    Err(err) => auth_error_response(&err),
                }
            }
        }
    }

    async fn call_authority(
        &self,
        endpoint: &str,
        cookie: Option<&str>,
        release: Option<&str>,
        body: Value,
    ) -> std::result::Result<Value, Error> {
        let map = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
        let headers = Headers::new();
        headers
            .set("Content-Type", "application/json")
            .map_err(map)?;
        if let Some(cookie) = cookie {
            headers.set("Cookie", cookie).map_err(map)?;
        }
        if let Some(release) = release {
            headers.set("X-OS-Release", release).map_err(map)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.to_string().into()));
        let req =
            Request::new_with_init(&format!("https://authority{endpoint}"), &init).map_err(map)?;
        let mut resp = self
            .env
            .durable_object("AUTHORITY")
            .map_err(map)?
            .id_from_name("filesystem")
            .map_err(map)?
            .get_stub()
            .map_err(map)?
            .fetch_with_request(req)
            .await
            .map_err(map)?;
        let status = resp.status_code();
        let val: Value = resp.json().await.map_err(map)?;
        if status >= 400 {
            let errno = val
                .get("errno")
                .and_then(|v| serde_json::from_value::<Errno>(v.clone()).ok())
                .unwrap_or(match status {
                    401 | 403 => Errno::EACCES,
                    404 => Errno::ENOENT,
                    409 => Errno::EBUSY,
                    412 => Errno::ESTALE,
                    _ => Errno::EIO,
                });
            let detail = val["error"]
                .as_str()
                .unwrap_or_else(|| errno.text())
                .to_string();
            return Err(Error::because(errno, detail));
        }
        Ok(val)
    }

    /// Flush all queued token revocations to `OsAuthority` `/internal/revoke` and schedule the
    /// next DO alarm for host-loss expiration or durable revocation retry.
    async fn settle(&self) {
        let pending = match transact(&self.state, |db| (db.pending_revocations(), false)) {
            Ok(list) => list,
            Err(_) => return,
        };
        let mut by_ns: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for item in pending {
            by_ns.entry(item.ns).or_default().push(item.token_hash);
        }
        let mut retry_needed = false;
        for (ns, hashes) in by_ns {
            let body = json!({ "ns": ns, "tokens": hashes, "renew": [] });
            match self
                .call_authority("/internal/revoke", None, None, body)
                .await
            {
                Ok(_) => {
                    let ns_c = ns.clone();
                    let hashes_c = hashes.clone();
                    let _ = transact(&self.state, move |db| {
                        db.clear_revocations(&ns_c, &hashes_c);
                        ((), true)
                    });
                }
                Err(_) => {
                    retry_needed = true;
                }
            }
        }
        let next_exp = transact(&self.state, |db| (db.next_machine_expiry(), false))
            .ok()
            .flatten();
        let now_ms = js_sys::Date::now() as i64;
        let next_ms = match (retry_needed, next_exp) {
            (true, Some(exp)) => Some((now_ms + REVOKE_RETRY_MS).min((exp as i64) * 1000)),
            (true, None) => Some(now_ms + REVOKE_RETRY_MS),
            (false, Some(exp)) => Some(((exp as i64) * 1000).max(now_ms + 1000)),
            (false, None) => None,
        };
        if let Some(at) = next_ms {
            let _ = self.state.storage().set_alarm(at).await;
        }
    }
}

fn auth_error_response(err: &Error) -> Result<Response> {
    let status = match err.errno {
        Errno::EACCES | Errno::EPERM => 403,
        Errno::ENOENT => 404,
        Errno::EBUSY | Errno::EEXIST => 409,
        Errno::ESTALE => 412,
        Errno::E2BIG => 413,
        Errno::EAGAIN => 429,
        Errno::ENOSYS => 501,
        _ => 400,
    };
    Ok(Response::from_json(&json!({
        "errno": err.errno,
        "error": err.to_string(),
    }))?
    .with_status(status))
}
