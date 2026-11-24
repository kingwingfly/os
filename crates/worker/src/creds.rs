//! Remote service credentials stored in `OsAuthority` (`credentials` table, `SCHEMA_VERSION = "10"`).
//!
//! Under `#54` (`L3a`), processes live locally in each instance's `LocalProcessTable`.
//! `OsAuthority` stores ONLY explicit remote service credentials minted/derived/renewed/revoked
//! through `ServiceAuth v2` (`Machine` DO -> `/internal/service-auth/{mint,derive,renew}` and
//! `/internal/revoke`), plus server-hosted container job credentials (`JOBS`).
use crate::api::Reply;
use crate::auth;
use crate::db::{Db, int, text, transact};
use abi::auth_v2::RemoteScope;
use abi::{Errno, Error};
use os_core::permissions::{Identity, Store};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use worker::*;

/// Hard absolute maximum lifetime for any browser `ServiceAuth v2` credential lineage (24h).
/// Repeated renewals or derivations can NEVER extend a credential past `started + MAX_CREDENTIAL_LIFETIME`.
pub const MAX_CREDENTIAL_LIFETIME: u64 = 24 * 3600;

/// A remote service credential (or remote container job credential).
#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
    /// The SHA-256 hash of the token carried in requests.
    pub token: String,
    pub ns: String,
    /// Legacy/job numeric pid field (0 for ServiceAuth v2 instance-scoped credentials).
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub groups: String,
    pub umask: u16,
    #[serde(default)]
    pub started: u64,
    pub generation: Option<String>,
    pub cloud_access: u8,
    /// JSON metadata holding `instance_id`, `cgroup`, and `scope` (`RemoteScope`) without
    /// altering `OsAuthority`'s `SCHEMA_VERSION = "10"`.
    #[serde(default)]
    pub placement: String,
    /// Descriptor lineage owner key.
    #[serde(rename = "owner")]
    lineage: String,
}

pub(crate) const OWNER: &str = "COALESCE(owner, ns || ' ' || pid || ' ' || substr(token, 1, 16))";

pub(crate) fn columns() -> String {
    format!(
        "token, ns, pid, uid, gid, groups, umask, started, generation, cloud_access, placement, {OWNER} AS owner"
    )
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PlacementMeta {
    #[serde(default)]
    instance_id: Option<String>,
    #[serde(default)]
    scope: Option<RemoteScope>,
}

impl Credential {
    fn placement_meta(&self) -> PlacementMeta {
        serde_json::from_str(&self.placement).unwrap_or_default()
    }

    pub fn instance_id(&self) -> Option<String> {
        self.placement_meta().instance_id
    }

    pub fn scope(&self) -> Option<RemoteScope> {
        self.placement_meta().scope
    }

    /// Reject requests missing or presenting a mismatched `X-OS-Instance` header against this
    /// credential's bound `instance_id` (`EACCES`).
    pub fn check_instance(&self, presented: Option<&str>) -> std::result::Result<(), Error> {
        if let Some(bound) = self.instance_id() {
            match presented.filter(|s| !s.is_empty()) {
                Some(got) if got == bound => {}
                _ => {
                    return Err(Error::because(
                        Errno::EACCES,
                        "missing or mismatched instance_id for service credential",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Enforce explicit `RemoteScope` device attachment authorization (`archive`, `media`,
    /// `present`, `snd`).
    pub fn check_device(&self, driver: &str) -> std::result::Result<(), Error> {
        if let Some(scope) = self.scope() {
            if !scope.allows_device(driver) {
                return Err(Error::because(
                    Errno::EACCES,
                    format!(
                        "remote device driver '{driver}' is not granted to this service credential"
                    ),
                ));
            }
            return Ok(());
        }
        self.cloud()
    }

    /// Map a remote device path to its driver name (`archive`, `media`, `present`, `snd`).
    pub fn remote_device_driver(path: &str) -> Option<&'static str> {
        if path == abi::accelerator::ARCHIVE {
            Some("archive")
        } else if path == abi::accelerator::MEDIA {
            Some("media")
        } else if path == crate::dev::PRESENT
            || path.starts_with(&format!("{}/", crate::dev::PRESENT))
        {
            Some("present")
        } else if path == crate::dev::SOUND || path.starts_with(&format!("{}/", crate::dev::SOUND))
        {
            Some("snd")
        } else {
            None
        }
    }

    pub fn cloud(&self) -> std::result::Result<(), abi::Error> {
        if self.cloud_access == 0 || self.scope().is_some_and(|s| !s.cloud_fs) {
            Err(abi::Error::because(
                Errno::EACCES,
                "cloud filesystem access was not delegated to this process",
            ))
        } else {
            Ok(())
        }
    }

    /// Enforce `RemoteScope.containers` for server-hosted container jobs (`Call::Kill { Job }`,
    /// `Call::Wait { Job }`, and accelerator job submission/control ioctls).
    pub fn check_containers(&self) -> std::result::Result<(), Error> {
        if let Some(scope) = self.scope() {
            if !scope.containers {
                return Err(Error::because(
                    Errno::EACCES,
                    "remote container job access is not granted to this service credential",
                ));
            }
            return Ok(());
        }
        self.cloud()
    }

    /// Enforce `RemoteScope.relay` for shared-mount relay operations.
    pub fn check_relay(&self) -> std::result::Result<(), Error> {
        if self.instance_id().is_some() && self.scope().is_some_and(|s| s.relay) {
            Ok(())
        } else {
            Err(Error::because(
                Errno::EACCES,
                "credential has no relay grant",
            ))
        }
    }

    /// Absolute hard expiration ceiling for this credential lineage (`started + 24h`).
    pub fn max_expires(&self) -> Option<u64> {
        (self.started > 0).then(|| self.started.saturating_add(MAX_CREDENTIAL_LIFETIME))
    }

    pub fn identity(&self) -> Identity {
        Identity {
            id: self.uid,
            group: self.gid,
            groups: serde_json::from_str(&self.groups)
                .unwrap_or_else(|_| BTreeSet::from([self.gid])),
        }
    }

    pub fn owner(&self) -> String {
        self.lineage.clone()
    }

    pub fn image(&self) -> String {
        owner(&self.ns, self.pid, &self.token)
    }
}

pub const JOBS: &str = "jobs";
const ANONYMOUS: &str = "anonymous";

pub fn job_owner(id: &str) -> String {
    format!("job {id}")
}

impl Credential {
    pub fn session(&self) -> String {
        session_of(&self.ns, &self.lineage)
    }

    pub fn job(&self) -> Option<String> {
        (self.ns == JOBS)
            .then(|| self.lineage.strip_prefix("job ").map(str::to_string))
            .flatten()
    }
}

pub fn sid_of(
    db: &Db,
    key: Option<&str>,
    guest: Option<&str>,
    caller: Option<&Credential>,
) -> Option<String> {
    caller
        .map(Credential::session)
        .or_else(|| auth::sid(db, key, guest))
}

fn session_of(ns: &str, lineage: &str) -> String {
    if ns == JOBS {
        lineage.to_string()
    } else {
        format!("proc {lineage}")
    }
}

fn owner(ns: &str, pid: u32, token: &str) -> String {
    format!("{ns} {pid} {}", token.get(..16).unwrap_or(token))
}

impl Db {
    pub fn credential(&self, token: &str, ns: &str) -> Option<Credential> {
        let hash = auth::token_hash(token);
        self.credential_of(&hash, ns)
            .or_else(|| (ns == ANONYMOUS).then(|| self.credential_of(&hash, JOBS))?)
    }

    pub fn job_credential(&mut self, id: &str, hash: &str, cred: &Identity, umask: u16, now: u64) {
        let expires = self.provider_deadline(id).unwrap_or(now + 7 * 24 * 3600);
        self.run(
            "INSERT OR REPLACE INTO credentials(token, ns, pid, uid, gid, groups, umask, started, owner, expires) VALUES(?, ?, 0, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(hash),
                text(JOBS),
                int(cred.id),
                int(cred.group),
                text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
                int(umask & 0o777),
                int(now),
                text(&job_owner(id)),
                int(expires),
            ],
        );
        self.run(
            "UPDATE credentials SET generation = ? WHERE token = ?",
            vec![
                self.image.as_ref().map(|v| v.id.as_str()).into(),
                text(hash),
            ],
        );
        self.set_expiry("credential", hash, expires);
        let placement = crate::placement::container(cred.id, id);
        self.run(
            "UPDATE credentials SET placement = ? WHERE token = ?",
            vec![
                text(&serde_json::to_string(&placement).unwrap_or_default()),
                text(hash),
            ],
        );
    }

    pub fn revoke_job(&mut self, id: &str) {
        for row in self.rows::<Credential>(
            &format!(
                "SELECT {} FROM credentials WHERE ns = ? AND owner = ?",
                columns()
            ),
            vec![text(JOBS), text(&job_owner(id))],
        ) {
            self.revoke_cloud_opens(&row.token);
            self.clear_expiry("credential", &row.token);
        }
        self.run(
            "DELETE FROM credentials WHERE ns = ? AND owner = ?",
            vec![text(JOBS), text(&job_owner(id))],
        );
        self.end_line(JOBS, &job_owner(id));
    }

    fn end_line(&mut self, ns: &str, lineage: &str) {
        self.close_proc_fds(lineage);
        let session = session_of(ns, lineage);
        for fd in self.fds_of(&session) {
            crate::fds::release(self, &session, fd.fd);
        }
        self.forget_fd_numbers(&session);
        self.forget_controller(lineage);
    }

    pub fn renew_lines(&mut self, ns: &str, now: u64) {
        #[derive(Deserialize)]
        struct Line {
            owner: String,
        }
        let lines = self.rows::<Line>(
            &format!("SELECT DISTINCT {OWNER} AS owner FROM credentials WHERE ns = ?"),
            vec![text(ns)],
        );
        for line in lines {
            crate::fds::renew(self, &session_of(ns, &line.owner), now);
        }
    }

    pub(crate) fn credential_of(&self, hash: &str, ns: &str) -> Option<Credential> {
        let cred = self
            .rows::<Credential>(
                &format!(
                    "SELECT {} FROM credentials WHERE token = ? AND ns = ? AND expires > ?",
                    columns()
                ),
                vec![text(hash), text(ns), int(auth::now())],
            )
            .into_iter()
            .next()?;
        // Fail closed immediately if a non-guest, non-job account (or the controlling account
        // that minted a sudo-elevated credential) was locked/deleted, or if the lineage exceeded
        // its absolute hard lifetime cap (`started + MAX_CREDENTIAL_LIFETIME`).
        if cred.ns != JOBS {
            if cred.max_expires().is_some_and(|cap| auth::now() >= cap) {
                return None;
            }
            if !os_core::permissions::is_guest_id(cred.uid) {
                let (_, user) = self.user_by_id(cred.uid)?;
                if user.locked {
                    return None;
                }
            }
            if let Some(ctrl_uid) = self.controller(&cred.owner())
                && ctrl_uid != cred.uid
                && !os_core::permissions::is_guest_id(ctrl_uid)
            {
                let (_, ctrl) = self.user_by_id(ctrl_uid)?;
                if ctrl.locked {
                    return None;
                }
            }
        }
        Some(cred)
    }

    pub fn expire_credential(&mut self, hash: &str, now: u64) {
        let expired = self.rows::<Credential>(
            &format!(
                "SELECT {} FROM credentials WHERE token = ? AND expires <= ?",
                columns()
            ),
            vec![text(hash), int(now)],
        );
        for row in expired {
            self.revoke(&row.ns, hash);
        }
        self.clear_expiry("credential", hash);
    }

    pub fn revoke(&mut self, ns: &str, hash: &str) {
        let found = self.rows::<Credential>(
            &format!(
                "DELETE FROM credentials WHERE token = ? AND ns = ? RETURNING {}",
                columns()
            ),
            vec![text(hash), text(ns)],
        );
        for credential in found {
            self.revoke_cloud_opens(hash);
            self.clear_expiry("credential", hash);
            self.close_exec_fds(&credential.image());
            let held = !self
                .rows::<Credential>(
                    &format!(
                        "SELECT {} FROM credentials WHERE ns = ? AND {OWNER} = ? LIMIT 1",
                        columns()
                    ),
                    vec![text(ns), text(&credential.owner())],
                )
                .is_empty();
            if !held {
                self.end_line(ns, &credential.owner());
            }
        }
    }
}

fn valid_tenant_name(tenant: &str) -> bool {
    tenant
        .strip_prefix('u')
        .and_then(|id| id.parse::<u32>().ok())
        .is_some_and(|id| tenant == format!("u{id}"))
}

/// Internal credential endpoints for trusted service bindings. The volume/registry gateways also
/// verify the returned grant against the live Machine instance before use.
pub async fn internal(
    req: &mut Request,
    env: &Env,
    state: &State,
    endpoint: &str,
) -> Result<Option<Reply>> {
    let key = auth::token_key(req);
    let guest = auth::guest_key(req);
    Ok(Some(match endpoint {
        "/internal/service-auth/verify-registry" => {
            let token = req.headers().get("X-Process-Token")?.unwrap_or_default();
            let instance = req.headers().get("X-OS-Instance")?;
            let asked_tenant = req.headers().get("X-OS-Tenant")?;
            let ns = Db::namespace(key.as_deref(), guest.as_deref());
            crate::api::run(state, move |db| {
                let grant = db
                    .credential_of(&auth::token_hash(&token), &ns)
                    .and_then(|cred| {
                        let scope = cred.scope()?;
                        if (!scope.registry_pull && !scope.registry_push)
                            || cred.job().is_some()
                            || cred.instance_id().is_none()
                            || os_core::permissions::is_guest_id(cred.uid)
                            || cred.check_instance(instance.as_deref()).is_err()
                        {
                            return None;
                        }
                        let own = format!("u{}", cred.uid);
                        let tenant = asked_tenant.unwrap_or_else(|| own.clone());
                        if tenant != own
                            && (cred.uid != 0
                                || !scope.registry_pull
                                || !scope.registry_push
                                || !scope.registry_repos.is_empty()
                                || !valid_tenant_name(&tenant))
                        {
                            return None;
                        }
                        Some(json!({
                            "tenant": tenant,
                            "ns": cred.ns,
                            "uid": cred.uid,
                            "cred_hash": cred.token,
                            "scope": scope,
                            "admin": cred.uid == 0,
                        }))
                    });
                match grant {
                    Some(g) => Reply::ok(g),
                    None => crate::api::errno_reply(&Errno::EACCES.into()),
                }
            })?
        }
        "/internal/service-auth/verify-registry-basic" => {
            #[derive(Deserialize)]
            struct BasicAsked {
                username: String,
                password: String,
                #[serde(default)]
                tenant: Option<String>,
            }
            let Ok(asked) = req.json::<BasicAsked>().await else {
                return Ok(Some(Reply::error("Invalid basic auth request", 400)));
            };
            let uname = asked.username.clone();
            let (user, root) =
                transact(state, move |db| ((db.user(&uname), db.user("root")), false))?;
            let verified = if let Some(account) = user.as_ref().or(root.as_ref()) {
                auth::verify(&asked.password, account, env).await?
            } else {
                false
            };
            let uname2 = asked.username;
            let asked_tenant = asked.tenant;
            transact(state, move |db| {
                let Some(u) = db.user(&uname2) else {
                    return (Reply::error("unauthorized", 401), false);
                };
                if !verified || u.locked || os_core::permissions::is_guest_id(u.id) {
                    return (Reply::error("unauthorized", 401), false);
                }
                let own = format!("u{}", u.id);
                let tenant = asked_tenant.unwrap_or_else(|| own.clone());
                if tenant != own && (u.id != 0 || !valid_tenant_name(&tenant)) {
                    return (Reply::error("denied", 403), false);
                }
                let scope = RemoteScope {
                    registry_pull: true,
                    registry_push: true,
                    ..Default::default()
                };
                (
                    Reply::ok(json!({
                        "tenant": tenant,
                        "uid": u.id,
                        "scope": scope,
                        "admin": u.id == 0,
                    })),
                    false,
                )
            })?
        }
        "/internal/service-auth/verify-registry-bearer" => {
            #[derive(Deserialize)]
            struct BearerAsked {
                uid: u32,
                tenant: String,
                #[serde(default)]
                ns: Option<String>,
                #[serde(default)]
                cred_hash: Option<String>,
                #[serde(default)]
                repo: Option<String>,
                #[serde(default)]
                push: bool,
                #[serde(default)]
                from_repo: Option<String>,
            }
            let Ok(asked) = req.json::<BearerAsked>().await else {
                return Ok(Some(Reply::error("Invalid bearer verify request", 400)));
            };
            transact(state, move |db| {
                let reply = match (asked.ns, asked.cred_hash) {
                    (Some(ns), Some(cred_hash)) => {
                        let Some(cred) = db.credential_of(&cred_hash, &ns) else {
                            return (Reply::error("unauthorized", 401), false);
                        };
                        if cred.uid != asked.uid
                            || cred.job().is_some()
                            || cred.instance_id().is_none()
                            || os_core::permissions::is_guest_id(cred.uid)
                        {
                            return (Reply::error("unauthorized", 401), false);
                        }
                        let Some(scope) = cred.scope() else {
                            return (Reply::error("unauthorized", 401), false);
                        };
                        let own = format!("u{}", cred.uid);
                        if asked.tenant != own
                            && (cred.uid != 0
                                || !scope.registry_pull
                                || !scope.registry_push
                                || !scope.registry_repos.is_empty()
                                || !valid_tenant_name(&asked.tenant))
                        {
                            return (Reply::error("denied", 403), false);
                        }
                        let allowed = match asked.repo.as_deref() {
                            Some(repo) => scope.allows_registry(repo, asked.push),
                            None => scope.registry_pull || scope.registry_push,
                        };
                        if !allowed {
                            return (Reply::error("denied", 403), false);
                        }
                        if let Some(src_repo) = asked.from_repo.as_deref()
                            && !scope.allows_registry(src_repo, false)
                        {
                            return (Reply::error("denied", 403), false);
                        }
                        Reply::ok(json!(crate::storage_do::Grant {
                            tenant: asked.tenant,
                            ns: cred.ns,
                            owner: cred.token,
                            scope,
                            admin: cred.uid == 0,
                        }))
                    }
                    (None, None) => {
                        let Some((_, u)) = db.user_by_id(asked.uid) else {
                            return (Reply::error("unauthorized", 401), false);
                        };
                        if u.locked || os_core::permissions::is_guest_id(u.id) {
                            return (Reply::error("unauthorized", 401), false);
                        }
                        let own = format!("u{}", u.id);
                        if asked.tenant != own && (u.id != 0 || !valid_tenant_name(&asked.tenant)) {
                            return (Reply::error("denied", 403), false);
                        }
                        let scope = RemoteScope {
                            registry_pull: true,
                            registry_push: true,
                            ..Default::default()
                        };
                        Reply::ok(json!(crate::storage_do::Grant {
                            tenant: asked.tenant,
                            ns: String::new(),
                            owner: format!("basic:u{}", u.id),
                            scope,
                            admin: u.id == 0,
                        }))
                    }
                    _ => Reply::error("unauthorized", 401),
                };
                (reply, false)
            })?
        }
        "/internal/service-auth/verify-volume" => {
            let token = req.headers().get("X-Process-Token")?.unwrap_or_default();
            let instance = req.headers().get("X-OS-Instance")?;
            let asked_tenant = req.headers().get("X-OS-Tenant")?;
            let ns = Db::namespace(key.as_deref(), guest.as_deref());
            crate::api::run(state, move |db| {
                let grant = db
                    .credential_of(&auth::token_hash(&token), &ns)
                    .and_then(|cred| {
                        let scope = cred.scope()?;
                        if !scope.volumes
                            || cred.job().is_some()
                            || cred.instance_id().is_none()
                            || os_core::permissions::is_guest_id(cred.uid)
                            || cred.check_instance(instance.as_deref()).is_err()
                        {
                            return None;
                        }
                        let own = format!("u{}", cred.uid);
                        let tenant = asked_tenant.unwrap_or_else(|| own.clone());
                        if tenant != own
                            && (cred.uid != 0
                                || scope.volumes_ro
                                || !scope.volume_ids.is_empty()
                                || !tenant
                                    .strip_prefix('u')
                                    .and_then(|id| id.parse::<u32>().ok())
                                    .is_some_and(|id| tenant == format!("u{id}")))
                        {
                            return None;
                        }
                        Some(crate::storage_do::Grant {
                            tenant,
                            ns: cred.ns,
                            owner: cred.token,
                            scope,
                            admin: cred.uid == 0,
                        })
                    });
                match grant {
                    Some(g) => Reply::ok(json!(g)),
                    None => crate::api::errno_reply(&Errno::EACCES.into()),
                }
            })?
        }
        "/internal/relay-identity" => {
            #[derive(Deserialize)]
            struct Namespace {
                ns: String,
            }
            let token = req.headers().get("X-Process-Token")?.unwrap_or_default();
            let instance = req.headers().get("X-OS-Instance")?;
            crate::api::run(state, move |db| {
                let hash = auth::token_hash(&token);
                let cred = db
                    .rows::<Namespace>(
                        "SELECT ns FROM credentials WHERE token = ?",
                        vec![text(&hash)],
                    )
                    .first()
                    .and_then(|row| db.credential_of(&hash, &row.ns));
                match cred {
                    Some(c)
                        if c.check_relay().is_ok()
                            && c.check_instance(instance.as_deref()).is_ok() =>
                    {
                        Reply::ok(json!({"uid": c.uid}))
                    }
                    _ => crate::api::errno_reply(&Error::because(
                        Errno::EACCES,
                        "relay credential required",
                    )),
                }
            })?
        }
        "/internal/service-auth/mint" => {
            #[derive(Deserialize)]
            struct MintAsked {
                ns: String,
                instance_id: String,
                token_hash: String,
                #[serde(default)]
                scope: RemoteScope,
                #[serde(default = "default_true")]
                cloud_access: bool,
                #[serde(default = "default_umask")]
                umask: u16,
                #[serde(default)]
                cgroup: Option<String>,
                #[serde(default)]
                generation: Option<String>,
                #[serde(default)]
                sudo: bool,
            }
            let header_release = req.headers().get("X-OS-Release").ok().flatten();
            let Ok(asked) = req.json::<MintAsked>().await else {
                return Ok(Some(Reply::error("Invalid mint request", 400)));
            };
            let now = auth::now();
            transact(state, move |db| {
                let cred =
                    match crate::sys::caller(db, key.as_deref(), guest.as_deref(), asked.sudo) {
                        Ok(c) => c,
                        Err(e) => return (crate::api::errno_reply(&e), false),
                    };
                let generation = asked
                    .generation
                    .or(header_release)
                    .filter(|g| g != "legacy");
                if let Err(e) = crate::system::select(db, generation.as_deref()) {
                    return (crate::api::errno_reply(&e), false);
                }
                let effective_cloud = asked.cloud_access && asked.scope.cloud_fs;
                let expires = now.saturating_add(abi::PROCESS_TOKEN_TTL);
                let lineage = format!(
                    "inst:{}:{}",
                    asked.instance_id,
                    asked.token_hash.get(..16).unwrap_or(&asked.token_hash)
                );
                let controller = auth::identity_of(db, key.as_deref(), guest.as_deref()).id;
                db.set_controller(&lineage, controller);
                let groups_vec: Vec<u32> = cred.groups.iter().copied().collect();
                let placement = json!({
                    "instance_id": asked.instance_id,
                    "cgroup": asked.cgroup.unwrap_or_else(|| "/user".into()),
                    "scope": asked.scope,
                });
                db.run(
                    "INSERT OR REPLACE INTO credentials(token, ns, pid, uid, gid, groups, umask, started, owner, expires, placement, generation, cloud_access) VALUES(?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    vec![
                        text(&asked.token_hash),
                        text(&asked.ns),
                        int(cred.id),
                        int(cred.group),
                        text(&serde_json::to_string(&cred.groups).unwrap_or_default()),
                        int(asked.umask & 0o777),
                        int(now),
                        text(&lineage),
                        int(expires),
                        text(&placement.to_string()),
                        generation.as_deref().into(),
                        int(u8::from(effective_cloud)),
                    ],
                );
                db.set_expiry("credential", &asked.token_hash, expires);
                (
                    Reply::ok(json!({
                        "uid": cred.id,
                        "gid": cred.group,
                        "groups": groups_vec,
                        "umask": asked.umask & 0o777,
                        "cloud_access": effective_cloud,
                        "scope": asked.scope,
                        "expires": expires,
                        "lineage": lineage,
                    })),
                    true,
                )
            })?
        }
        "/internal/service-auth/derive" => {
            #[derive(Deserialize)]
            struct DeriveAsked {
                ns: String,
                instance_id: String,
                parent_hash: String,
                new_hash: String,
                #[serde(default)]
                scope: RemoteScope,
                #[serde(default = "default_true")]
                cloud_access: bool,
                #[serde(default)]
                umask: Option<u16>,
                #[serde(default)]
                cgroup: Option<String>,
                #[serde(default)]
                revoke_parent: bool,
            }
            let Ok(asked) = req.json::<DeriveAsked>().await else {
                return Ok(Some(Reply::error("Invalid derive request", 400)));
            };
            let now = auth::now();
            transact(state, move |db| {
                let Some(parent) = db.credential_of(&asked.parent_hash, &asked.ns) else {
                    return (
                        crate::api::errno_reply(&Error::because(
                            Errno::EACCES,
                            "parent service credential expired or revoked",
                        )),
                        false,
                    );
                };
                if parent.instance_id().as_deref() != Some(asked.instance_id.as_str()) {
                    return (
                        crate::api::errno_reply(&Error::because(
                            Errno::EACCES,
                            "parent credential belongs to another instance",
                        )),
                        false,
                    );
                }
                let origin_started = if parent.started > 0 {
                    parent.started
                } else {
                    now
                };
                let max_exp = origin_started.saturating_add(MAX_CREDENTIAL_LIFETIME);
                if now >= max_exp {
                    db.revoke(&asked.ns, &asked.parent_hash);
                    return (
                        crate::api::errno_reply(&Error::because(
                            Errno::EACCES,
                            "service credential exceeded maximum lifetime",
                        )),
                        true,
                    );
                }
                let parent_scope = parent.scope().unwrap_or_else(RemoteScope::full);
                let new_scope = parent_scope.attenuate(&asked.scope);
                let new_cloud =
                    (parent.cloud_access != 0) && asked.cloud_access && new_scope.cloud_fs;
                let umask = asked.umask.unwrap_or(parent.umask) & 0o777;
                let expires = now.saturating_add(abi::PROCESS_TOKEN_TTL).min(max_exp);
                let lineage = parent.owner();
                let placement = json!({
                    "instance_id": asked.instance_id,
                    "cgroup": asked.cgroup.unwrap_or_else(|| "/user".into()),
                    "scope": new_scope,
                });
                db.run(
                    "INSERT OR REPLACE INTO credentials(token, ns, pid, uid, gid, groups, umask, started, owner, expires, placement, generation, cloud_access) VALUES(?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    vec![
                        text(&asked.new_hash),
                        text(&asked.ns),
                        int(parent.uid),
                        int(parent.gid),
                        text(&parent.groups),
                        int(umask),
                        int(origin_started),
                        text(&lineage),
                        int(expires),
                        text(&placement.to_string()),
                        parent.generation.as_deref().into(),
                        int(u8::from(new_cloud)),
                    ],
                );
                db.set_expiry("credential", &asked.new_hash, expires);
                if new_cloud {
                    db.inherit_cloud_opens(&asked.ns, &asked.parent_hash, &asked.new_hash);
                }
                if asked.revoke_parent {
                    db.revoke(&asked.ns, &asked.parent_hash);
                }
                let groups_vec: Vec<u32> = parent.identity().groups.into_iter().collect();
                (
                    Reply::ok(json!({
                        "uid": parent.uid,
                        "gid": parent.gid,
                        "groups": groups_vec,
                        "umask": umask,
                        "cloud_access": new_cloud,
                        "scope": new_scope,
                        "expires": expires,
                        "lineage": lineage,
                    })),
                    true,
                )
            })?
        }
        "/internal/service-auth/renew" => {
            #[derive(Deserialize)]
            struct RenewAsked {
                ns: String,
                hashes: Vec<String>,
            }
            let Ok(asked) = req.json::<RenewAsked>().await else {
                return Ok(Some(Reply::error("Invalid renew request", 400)));
            };
            let now = auth::now();
            transact(state, move |db| {
                let mut revoked = Vec::new();
                for hash in &asked.hashes {
                    if let Some(cred) = db.credential_of(hash, &asked.ns) {
                        let max_exp = cred.max_expires().unwrap_or(u64::MAX);
                        if now >= max_exp {
                            db.revoke(&asked.ns, hash);
                            revoked.push(hash.clone());
                            continue;
                        }
                        let deadline = now.saturating_add(abi::PROCESS_TOKEN_TTL).min(max_exp);
                        db.run(
                            "UPDATE credentials SET expires = ? WHERE ns = ? AND token = ?",
                            vec![int(deadline), text(&asked.ns), text(hash)],
                        );
                        db.set_expiry("credential", hash, deadline);
                        crate::fds::renew(self_db_ref(db), &cred.session(), now);
                    } else {
                        revoked.push(hash.clone());
                    }
                }
                (Reply::ok(json!({ "revoked": revoked })), true)
            })?
        }
        "/internal/identity" => {
            #[derive(Deserialize)]
            struct Asked {
                #[serde(default)]
                sudo: bool,
            }
            let sudo = req
                .json::<Asked>()
                .await
                .map(|asked| asked.sudo)
                .unwrap_or(false);
            transact(state, move |db| {
                let reply = match crate::sys::caller(db, key.as_deref(), guest.as_deref(), sudo) {
                    Ok(cred) => Reply::ok(json!(cred)),
                    Err(error) => crate::api::errno_reply(&error),
                };
                (reply, true)
            })?
        }
        "/internal/revoke" => {
            #[derive(Deserialize)]
            struct Asked {
                ns: String,
                tokens: Vec<String>,
                #[serde(default)]
                renew: Vec<String>,
            }
            let Ok(asked) = req.json::<Asked>().await else {
                return Ok(Some(Reply::error("Invalid revocation", 400)));
            };
            transact(state, move |db| {
                for hash in &asked.renew {
                    if db.credential_of(hash, &asked.ns).is_some() {
                        let deadline = auth::now() + abi::PROCESS_TOKEN_TTL;
                        db.run(
                            "UPDATE credentials SET expires = ? WHERE ns = ? AND token = ?",
                            vec![int(deadline), text(&asked.ns), text(hash)],
                        );
                        db.set_expiry("credential", hash, deadline);
                    }
                }
                for hash in &asked.tokens {
                    db.revoke(&asked.ns, hash);
                }
                (Reply::ok(Value::Null), true)
            })?
        }
        "/internal/tell" => {
            #[derive(Deserialize)]
            struct Asked {
                ns: String,
                value: Value,
            }
            let Ok(asked) = req.json::<Asked>().await else {
                return Ok(Some(Reply::error("Invalid message", 400)));
            };
            transact(state, move |db| {
                db.tell(crate::db::Told::Namespace(asked.ns), asked.value);
                (Reply::ok(Value::Null), true)
            })?
        }
        _ => return Ok(None),
    }))
}

fn self_db_ref(db: &mut Db) -> &mut Db {
    db
}

fn default_true() -> bool {
    true
}

fn default_umask() -> u16 {
    0o022
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred_with_scope(scope: RemoteScope, cloud_access: u8, started: u64) -> Credential {
        Credential {
            token: "hash-1".into(),
            ns: "guest.abc".into(),
            pid: 0,
            uid: 1000,
            gid: 1000,
            groups: "[1000]".into(),
            umask: 0o022,
            started,
            generation: None,
            cloud_access,
            placement: json!({
                "instance_id": "inst-1",
                "cgroup": "/user",
                "scope": scope,
            })
            .to_string(),
            lineage: "inst:inst-1:hash".into(),
        }
    }

    #[test]
    fn remote_scope_enforces_containers_relay_devices_and_max_lifetime() {
        let cloud_only = cred_with_scope(RemoteScope::cloud_only(), 1, 1000);
        assert!(cloud_only.cloud().is_ok());
        assert_eq!(
            cloud_only.check_containers().unwrap_err().errno,
            Errno::EACCES
        );
        assert_eq!(cloud_only.check_relay().unwrap_err().errno, Errno::EACCES);
        assert_eq!(
            cloud_only.check_device("archive").unwrap_err().errno,
            Errno::EACCES
        );
        assert_eq!(
            cloud_only.max_expires(),
            Some(1000 + MAX_CREDENTIAL_LIFETIME)
        );

        let full = cred_with_scope(RemoteScope::full(), 1, 2000);
        assert!(full.cloud().is_ok());
        assert!(full.check_containers().is_ok());
        assert!(full.check_relay().is_ok());
        assert!(full.check_device("archive").is_ok());
        assert!(full.check_device("present").is_ok());

        let containers_only = cred_with_scope(
            RemoteScope {
                cloud_fs: false,
                devices: vec!["archive".into()],
                containers: true,
                relay: false,
                ..Default::default()
            },
            0,
            3000,
        );
        assert_eq!(containers_only.cloud().unwrap_err().errno, Errno::EACCES);
        assert!(containers_only.check_containers().is_ok());
        assert!(containers_only.check_device("archive").is_ok());
        assert_eq!(
            containers_only.check_device("media").unwrap_err().errno,
            Errno::EACCES
        );
        assert_eq!(
            containers_only.check_relay().unwrap_err().errno,
            Errno::EACCES
        );
    }
}
