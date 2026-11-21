//! The client kernel (`#54` L3a, `docs/architecture/contract.md` §2.1, §2.3, §2.4, §2.7, §2.10):
//! the browser's instance-local kernel in Rust→wasm inside a dedicated Worker.
//!
//! Each OS instance owns its own:
//! - PID namespace, process table, process groups, sessions, signals, waitpid/reaping, subreapers,
//!   and local cgroup v2 policies (`kernel::proc_table::LocalProcessTable`, zero network RPCs)
//! - Local `/proc` rendering (`os_vfs::ProcFs` wired via `ProcBridge` hooks, zero network RPCs)
//! - Local `/run`, `/tmp` (`01777`), `/dev` (local-only devices at boot; remote devices require
//!   explicit credentialed attachment)
//! - Local `Init` reaper and `Login` session scope coordinators
//!
//! Remote cloud services (`CloudFs`, remote `/dev/{archive,media,present,snd}`, containers, relay)
//! attach lazily on first remote use through `ServiceAuth v2` (`POST /api/service-auth`), fencing
//! `(instance_id, host_proof)` and immediately revoking remote credentials on exit, `SIGKILL`,
//! privilege drop, or login-scope end.
pub mod boot_stage;
mod cloudfs;
mod cowfs_bridge;
mod helper;
mod hostfs;
mod mounts;
mod release_v2;
mod share_bridge;
pub mod unix_sock_bridge;
mod vfs_engine;

use abi::auth_v2::{
    self, AttachInstance, DeriveServiceCred, DetachInstance, MintServiceCred, RemoteIoQuota,
    RemoteScope, RenewInstance, RevokeTokens,
};
use abi::contract::{Boundary, Hello, InstanceIdentity};
use abi::{
    Call, Errno, Error, Exec, InitAction, InitOwner, LocalExecutable, LoginAction, PROC_POLL_MAX,
    Placement, ProcState, SIGCONT, SIGHUP, SIGKILL, SIGTERM, SharingMode, Target,
};
use kernel::init::Init;
use kernel::local_cgroups::normalize_cgroup_path;
use kernel::login::Session as LoginSession;
use kernel::proc_table::{
    LocalCred, LocalProcessTable, ReexecSpec, RemoteCredRef, SpawnSpec, WaitOutcome,
};
use kernel::registry::in_subtree;
use kernel::startup::{Profile as StartupProfile, Startup};
use os_core::permissions::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// The client kernel's `HostAdapter` protocol version (`abi::contract::HOST_ADAPTER_VERSION`).
pub const VERSION: &str = "2";
/// Linux's init PID.
pub(crate) const INIT: u32 = 1;

/// Monotonic wall clock in whole seconds (works on both `wasm32` and native host tests).
pub(crate) fn now_secs() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        let ms = js_sys::Date::now();
        if ms.is_finite() && ms > 0.0 {
            (ms / 1000.0).floor() as u64
        } else {
            0
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000)
    }
}

/// Generate a 32-byte (64-hex-char) high-entropy local secret (e.g. `host_proof` or random id).
pub(crate) fn random_hex(bytes_len: usize) -> String {
    let mut buf = vec![0u8; bytes_len];
    #[cfg(target_arch = "wasm32")]
    {
        let mut filled = false;
        let global = js_sys::global();
        if let Ok(crypto) = js_sys::Reflect::get(&global, &"crypto".into())
            && let Ok(func) = js_sys::Reflect::get(&crypto, &"getRandomValues".into())
                .and_then(|v| v.dyn_into::<js_sys::Function>())
        {
            let arr = js_sys::Uint8Array::new_with_length(bytes_len as u32);
            if func.call1(&crypto, &arr).is_ok() {
                arr.copy_to(&mut buf);
                filled = true;
            }
        }
        if !filled {
            for b in &mut buf {
                *b = (js_sys::Math::random() * 256.0) as u8;
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let mut seed = now_secs()
            .wrapping_mul(0x9e37_79b9_7f4a_7c15)
            .wrapping_add(CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
        for chunk in buf.chunks_mut(8) {
            seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let raw = z.to_le_bytes();
            chunk.copy_from_slice(&raw[..chunk.len()]);
        }
    }
    let mut out = String::with_capacity(bytes_len * 2);
    for b in buf {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn sha256_hex(input: &str) -> String {
    image::digest(input.as_bytes())
}

/// Notify the page of a `ServiceAuth` / `HostAdapter` protocol version mismatch without
/// auto-reloading (`docs/architecture/contract.md` §2.10).
pub(crate) fn emit_protocol_mismatch(boundary: &str, detail: &str) {
    if let Ok((global, cb)) = cloudfs::installed("onProtocolMismatch") {
        let payload = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&payload, &"boundary".into(), &JsValue::from_str(boundary));
        let _ = js_sys::Reflect::set(
            &payload,
            &"errno".into(),
            &JsValue::from_str("EPROTONOSUPPORT"),
        );
        let _ = js_sys::Reflect::set(&payload, &"detail".into(), &JsValue::from_str(detail));
        let _ = cb.call1(&global, &payload);
    }
}

/// Transport for `POST /api/service-auth` installed as `self.serviceAuthPost(bodyJson)`.
pub(crate) async fn service_auth_request(
    req: &auth_v2::Request,
) -> std::result::Result<auth_v2::Response, Error> {
    let Ok((global, post)) = cloudfs::installed("serviceAuthPost") else {
        return Err(Error::because(
            Errno::ENOTCONN,
            "service auth transport is not installed",
        ));
    };
    let body = serde_json::to_string(req)
        .map_err(|error| Error::because(Errno::EIO, error.to_string()))?;
    let answer = post
        .call1(&global, &JsValue::from_str(&body))
        .map_err(|_| Error::because(Errno::EIO, "serviceAuthPost invocation failed"))?;
    let promise = answer
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| Error::because(Errno::EIO, "serviceAuthPost did not return a Promise"))?;
    let raw = JsFuture::from(promise)
        .await
        .map_err(|_| Error::because(Errno::ENOTCONN, "service auth request failed"))?;
    let raw_text = raw
        .as_string()
        .ok_or_else(|| Error::because(Errno::EIO, "serviceAuthPost reply is not text"))?;
    let reply: Value = serde_json::from_str(&raw_text)
        .map_err(|error| Error::because(Errno::EIO, error.to_string()))?;
    let status = reply["status"].as_u64().unwrap_or(0);
    let text = reply["text"].as_str().unwrap_or("");
    if status != 200 {
        let parsed_err = serde_json::from_str::<Value>(text).ok();
        let detail = parsed_err
            .as_ref()
            .and_then(|v| v["detail"].as_str().or_else(|| v["error"].as_str()))
            .unwrap_or(if text.is_empty() {
                "service auth failed"
            } else {
                text
            })
            .to_string();
        let errno = parsed_err
            .as_ref()
            .and_then(|v| v["errno"].as_str())
            .and_then(|code| serde_json::from_value::<Errno>(Value::String(code.into())).ok())
            .unwrap_or(match status {
                400 => Errno::EINVAL,
                401 | 403 => Errno::EACCES,
                409 => Errno::ESTALE,
                426 | 505 => Errno::EPROTONOSUPPORT,
                429 => Errno::EAGAIN,
                _ => Errno::EIO,
            });
        if errno == Errno::EPROTONOSUPPORT {
            emit_protocol_mismatch("service-auth", &detail);
        }
        return Err(Error::because(errno, detail));
    }
    serde_json::from_str::<auth_v2::Response>(text)
        .map_err(|error| Error::because(Errno::EIO, error.to_string()))
}

/// Ensure this instance is attached to `ServiceAuth v2` (lazy on first remote use).
pub(crate) async fn ensure_remote_attached_state(
    state: &Rc<RefCell<State>>,
) -> std::result::Result<(String, String), Error> {
    let (already, instance_id, host_proof) = {
        let s = state.borrow();
        (
            s.remote_attached,
            s.instance_id.clone(),
            s.host_proof.clone(),
        )
    };
    if already {
        return Ok((instance_id, host_proof));
    }
    let req = auth_v2::Request::AttachInstance(AttachInstance {
        instance: InstanceIdentity {
            instance: instance_id.clone(),
            host: "browser".into(),
        },
        host_proof: host_proof.clone(),
    });
    match service_auth_request(&req).await? {
        auth_v2::Response::Attached(res) => {
            let mut s = state.borrow_mut();
            s.remote_attached = true;
            s.host_epoch = res.host_epoch;
            Ok((instance_id, host_proof))
        }
        _ => Err(Error::because(Errno::EIO, "unexpected attach reply")),
    }
}

/// Decide whether a lazily minted `ServiceAuth v2` credential with `issued_uid` may bind to a
/// local process running as `proc_uid`.
///
/// A local uninitialized guest (`uid == GUEST`, `65534`) may only bind to a per-session guest uid
/// (`is_guest_id(issued_uid)`) while `!signed_in && !account_changed` — NEVER to `root` (`0`) or
/// any named account. All other processes require an exact `issued_uid == proc_uid` match.
pub(crate) fn lazy_mint_uid_permitted(
    proc_uid: u32,
    issued_uid: u32,
    signed_in: bool,
    account_changed: bool,
) -> bool {
    if issued_uid == proc_uid {
        return true;
    }
    proc_uid == os_core::permissions::GUEST
        && os_core::permissions::is_guest_id(issued_uid)
        && !signed_in
        && !account_changed
}

/// Lazily mint and bind a `ServiceAuth v2` remote credential for an already-running local process
/// `pid` on its first cloud/remote access. Refuses with `EACCES` (0 network calls) if `pid` was
/// started with `cloud_access == false` or dropped local privilege via `set_cred`.
pub(crate) async fn lazy_mint_remote_cred(
    state: &Rc<RefCell<State>>,
    pid: u32,
) -> std::result::Result<RemoteCredRef, Error> {
    let (existing, cloud_allowed, cgroup, io_at_mint, proc_uid, proc_epoch, signed_in, cur_epoch) = {
        let s = state.borrow();
        let proc = s
            .table
            .proc(pid)
            .filter(|p| p.state != ProcState::Zombie)
            .ok_or_else(|| Error::from(Errno::ESRCH))?;
        let io = s.table.cgroups().effective_io_limit(&proc.cgroup);
        (
            proc.cred.remote.clone(),
            proc.cred.cloud_access,
            proc.cgroup.clone(),
            io,
            proc.cred.identity.id,
            s.proc_account_epoch.get(&pid).copied().unwrap_or(0),
            s.account.signed_in,
            s.account_epoch,
        )
    };
    if let Some(rem) = existing {
        if !rem.cloud_access {
            return Err(Errno::EACCES.into());
        }
        return Ok(rem);
    }
    if !cloud_allowed {
        return Err(Errno::EACCES.into());
    }
    let (instance_id, host_proof) = ensure_remote_attached_state(state).await?;
    let resp = service_auth_request(&auth_v2::Request::MintServiceCred(MintServiceCred {
        instance_id: instance_id.clone(),
        host_proof: host_proof.clone(),
        scope: RemoteScope::full(),
        cloud_access: true,
        umask: 0o022,
        cgroup: Some(cgroup.clone()),
        generation: None,
        sudo: false,
        rbps: io_at_mint.read,
        wbps: io_at_mint.write,
    }))
    .await?;
    let issued = match resp {
        auth_v2::Response::Cred(c) => c,
        _ => return Err(Error::because(Errno::EIO, "unexpected service cred reply")),
    };
    // Prevent a guest or stale process from hijacking a signed-in/root account cookie!
    let account_changed = proc_epoch != cur_epoch;
    if !lazy_mint_uid_permitted(proc_uid, issued.uid, signed_in, account_changed) {
        revoke_remote_tokens_state(state, vec![issued.token]).await;
        return Err(Error::because(
            Errno::EACCES,
            "process identity does not match current remote account",
        ));
    }
    let rem = RemoteCredRef {
        token: issued.token.clone(),
        uid: issued.uid,
        gid: issued.gid,
        groups: issued.groups.clone(),
        instance_id: issued.instance_id.clone(),
        lineage: issued.lineage.clone(),
        cloud_access: issued.cloud_access,
        scope: issued.scope.clone(),
    };
    // Re-check process state after awaiting `MintServiceCred` so a concurrent privilege drop,
    // `cloud_access=false` attenuation, or process exit mid-await can never be overwritten.
    let rebind_result = {
        let mut s = state.borrow_mut();
        let current_proc = s
            .table
            .proc(pid)
            .filter(|p| p.state != ProcState::Zombie)
            .map(|p| {
                (
                    p.owner_host.clone(),
                    p.cred.cloud_access,
                    p.cred.identity.clone(),
                    p.cgroup.clone(),
                )
            });
        match current_proc {
            None => Err(Errno::ESRCH),
            Some((_, cloud_now, cur_id, _)) if !cloud_now || cur_id.id != proc_uid => {
                Err(Errno::EACCES)
            }
            Some((host, _, cur_id, cur_cg)) => {
                let hydrate = proc_uid == os_core::permissions::GUEST
                    && os_core::permissions::is_guest_id(rem.uid);
                let res = if hydrate {
                    let hydrated = Identity {
                        id: rem.uid,
                        group: rem.gid,
                        groups: rem.groups.iter().copied().collect(),
                    };
                    s.table
                        .hydrate_guest_identity(&host, pid, hydrated, Some(rem.clone()))
                } else {
                    s.table.set_cred(&host, pid, cur_id, Some(rem.clone()))
                };
                match res {
                    Ok(_) => {
                        if hydrate {
                            let _ = s.hydrate_guest_account_if_uninitialized(
                                rem.uid,
                                rem.gid,
                                &rem.groups,
                            );
                        }
                        Ok((
                            cur_cg.clone(),
                            s.table.cgroups().effective_io_limit(&cur_cg),
                        ))
                    }
                    Err(e) => Err(e.errno),
                }
            }
        }
    };
    let (active_cgroup, io_limit) = match rebind_result {
        Ok(pair) => pair,
        Err(errno) => {
            revoke_remote_tokens_state(state, vec![rem.token]).await;
            return Err(errno.into());
        }
    };
    if active_cgroup != cgroup || io_limit != io_at_mint {
        let _ = service_auth_request(&auth_v2::Request::SetRemoteIoQuota(RemoteIoQuota {
            instance_id,
            host_proof,
            token: rem.token.clone(),
            cgroup: active_cgroup,
            rbps: io_limit.read,
            wbps: io_limit.write,
        }))
        .await;
    }
    Ok(rem)
}

/// Revoke one or more remote service tokens over `ServiceAuth v2` (chunked at `TOKENS_MAX`),
/// queueing any transient failures into `state.pending_revocations` for durable retry.
pub(crate) async fn revoke_remote_tokens_state(state: &Rc<RefCell<State>>, tokens: Vec<String>) {
    if tokens.is_empty() {
        return;
    }
    let (attached, instance_id, host_proof) = {
        let s = state.borrow();
        (
            s.remote_attached,
            s.instance_id.clone(),
            s.host_proof.clone(),
        )
    };
    if !attached || cloudfs::installed("serviceAuthPost").is_err() {
        return;
    }
    for chunk in tokens.chunks(auth_v2::TOKENS_MAX) {
        let req = auth_v2::Request::RevokeTokens(RevokeTokens {
            instance_id: instance_id.clone(),
            host_proof: host_proof.clone(),
            tokens: chunk.to_vec(),
        });
        if service_auth_request(&req).await.is_err() {
            let mut s = state.borrow_mut();
            for tok in chunk {
                if !s.pending_revocations.contains(tok) {
                    s.pending_revocations.push(tok.clone());
                }
            }
        }
    }
}

/// Local account identity for this browser instance (starts as local guest with zero RPCs;
/// updated on explicit login/logout or cloud sync).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LocalAccount {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub user: String,
    pub group: String,
    pub home: String,
    pub shell: String,
    pub signed_in: bool,
}

impl Default for LocalAccount {
    fn default() -> Self {
        Self {
            uid: 65534,
            gid: 65534,
            groups: vec![65534],
            user: "guest".into(),
            group: "guest".into(),
            home: "/tmp".into(),
            shell: "/usr/bin/dash".into(),
            signed_in: false,
        }
    }
}

impl LocalAccount {
    pub(crate) fn identity(&self) -> Identity {
        let mut groups: BTreeSet<u32> = self.groups.iter().copied().collect();
        groups.insert(self.gid);
        Identity {
            id: self.uid,
            group: self.gid,
            groups,
        }
    }

    pub(crate) fn to_creds_json(&self) -> Value {
        json!({
            "uid": self.uid,
            "gid": self.gid,
            "groups": self.groups,
            "user": self.user,
            "group": self.group,
            "home": self.home,
            "shell": self.shell,
            "signed_in": self.signed_in,
        })
    }
}

pub(crate) struct State {
    pub(crate) instance_id: String,
    pub(crate) host_proof: String,
    pub(crate) boot: String,
    pub(crate) namespace: String,
    pub(crate) table: LocalProcessTable,
    pub(crate) account: LocalAccount,
    pub(crate) account_epoch: u64,
    pub(crate) proc_account_epoch: HashMap<u32, u64>,
    pub(crate) remote_attached: bool,
    pub(crate) host_epoch: u64,
    pub(crate) pending_revocations: Vec<String>,
    pub(crate) attached_devices: BTreeMap<String, String>,
    pub(crate) init_state: Init,
    pub(crate) login_session: LoginSession,
    pub(crate) login_profiles: BTreeMap<u32, StartupProfile>,
    pub(crate) seat_policies: BTreeMap<u32, (String, u64)>,
    pub(crate) boot_seq: u64,
    pub(crate) session_seq: u64,
}

impl State {
    pub(crate) fn seat_policy(&self) -> (String, u64) {
        self.seat_policies
            .get(&self.account.uid)
            .cloned()
            .unwrap_or_else(|| ("control".into(), 0))
    }

    pub(crate) fn set_seat_policy(&mut self, uid: u32, sharing: String, revision: u64) {
        self.seat_policies.insert(uid, (sharing, revision));
    }

    pub(crate) fn sync_account(&mut self, account: LocalAccount) -> Vec<u32> {
        let prev_uid = self.account.uid;
        let initial_guest_hydration = prev_uid == os_core::permissions::GUEST
            && !self.account.signed_in
            && os_core::permissions::is_guest_id(account.uid)
            && !account.signed_in;
        let uid_changed = prev_uid != account.uid
            || self.account.signed_in != account.signed_in
            || self.account.user != account.user;
        self.account = account;
        let mut hydrated_pids = Vec::new();
        if initial_guest_hydration {
            // Hydrating the boot fallback guest (65534) to this browser's own unauthenticated
            // guest cookie UID keeps the same login scope and account epoch so in-flight local
            // guest processes are not falsely rejected as cross-account.
            self.login_session.uid = self.account.uid;
            if let Some(prof) = self.login_profiles.remove(&prev_uid) {
                self.login_profiles.entry(self.account.uid).or_insert(prof);
            }
            if let Some(pol) = self.seat_policies.remove(&prev_uid) {
                self.seat_policies.entry(self.account.uid).or_insert(pol);
            }
            let cur_epoch = self.account_epoch;
            let hydrated_id = self.account.identity();
            let candidates: Vec<(u32, String)> = self
                .table
                .all_pids()
                .into_iter()
                .filter_map(|pid| {
                    let p = self.table.proc(pid)?;
                    if p.pid != 1
                        && p.state != ProcState::Zombie
                        && p.cred.identity.id == os_core::permissions::GUEST
                        && p.cred.remote.is_none()
                        && self.proc_account_epoch.get(&pid).copied().unwrap_or(0) == cur_epoch
                    {
                        Some((pid, p.owner_host.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            for (pid, host) in candidates {
                if self
                    .table
                    .hydrate_guest_identity(&host, pid, hydrated_id.clone(), None)
                    .is_ok()
                {
                    hydrated_pids.push(pid);
                }
            }
        } else if uid_changed {
            self.account_epoch = self.account_epoch.saturating_add(1);
            let now = now_secs();
            self.session_seq = self.session_seq.saturating_add(1);
            let sid = format!("{}:s{}", self.instance_id, self.session_seq);
            let mut next = LoginSession::new(sid, self.account.uid, now + 86_400, now);
            if let Some(profile) = self.login_profiles.get(&self.account.uid) {
                next.startup = Some(Startup::new(profile.clone()));
            }
            self.login_session = next;
        }
        hydrated_pids
    }

    pub(crate) fn hydrate_guest_account_if_uninitialized(
        &mut self,
        uid: u32,
        gid: u32,
        groups: &[u32],
    ) -> Vec<u32> {
        if self.account.uid == os_core::permissions::GUEST
            && !self.account.signed_in
            && os_core::permissions::is_guest_id(uid)
        {
            let mut next = self.account.clone();
            next.uid = uid;
            next.gid = gid;
            next.groups = if groups.is_empty() {
                vec![gid]
            } else {
                groups.to_vec()
            };
            return self.sync_account(next);
        }
        Vec::new()
    }

    pub(crate) fn login_view(&self) -> Value {
        let mut view = self.login_session.view();
        let (sharing, revision) = self.seat_policy();
        if let Some(obj) = view.as_object_mut() {
            obj.insert(
                "seat_policy".into(),
                json!({
                    "sharing": sharing,
                    "revision": revision,
                }),
            );
        }
        view
    }

    pub(crate) fn refresh_login_shutdown(&mut self, now: u64) -> Vec<String> {
        let mut revoked = Vec::new();
        let sid = self.login_session.id.clone();
        if let Some(shutdown) = &mut self.login_session.shutdown
            && !shutdown.complete
        {
            let live = self.table.login_scope_pids(&sid);
            if live.is_empty() {
                shutdown.complete = true;
            } else if shutdown.due(now) {
                for pid in live {
                    if let Ok((_, rev)) = self.table.kill_with_revocations(
                        &Identity::root(),
                        None,
                        Target::Pid(pid),
                        SIGKILL,
                        now,
                    ) {
                        revoked.extend(rev);
                    }
                }
                if self.table.login_scope_pids(&sid).is_empty() {
                    shutdown.complete = true;
                }
            }
        }
        revoked
    }
}

fn is_supervisor_image(exec: &Exec) -> bool {
    exec.asset.is_some()
        && exec.local.is_none()
        && exec.path.as_deref() == Some("/usr/bin/supervise")
}

/// Paths that live purely inside this local instance (never require cloud attachment).
fn is_local_only_path(path: &str) -> bool {
    if path.is_empty() || path == "/" {
        return true;
    }
    matches!(
        path,
        "/usr"
            | "/bin"
            | "/sbin"
            | "/lib"
            | "/lib64"
            | "/proc"
            | "/dev"
            | "/run"
            | "/tmp"
            | "/mnt"
            | "/mnt/local"
            | "/mnt/shared"
            | "/opt"
            | "/opt/private"
    ) || path.starts_with("/usr/")
        || path.starts_with("/bin/")
        || path.starts_with("/sbin/")
        || path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || path.starts_with("/proc/")
        || path.starts_with("/dev/")
        || path.starts_with("/run/")
        || path.starts_with("/tmp/")
        || path.starts_with("/mnt/")
        || path.starts_with("/opt/private/")
}

fn system_usr_asset(path: &str) -> Option<String> {
    match path {
        "/usr/bin/init" => Some("/usr/bin/init.wasm".into()),
        "/usr/bin/supervise" => Some("/usr/bin/supervise.wasm".into()),
        "/usr/bin/dash" | "/usr/bin/sh" | "/bin/sh" => Some("/usr/bin/dash.wasm".into()),
        "/usr/bin/coreutils" => Some("/usr/bin/coreutils.wasm".into()),
        "/usr/bin/utilities" => Some("/usr/bin/utilities.wasm".into()),
        _ => None,
    }
}

fn validate_local_exec(local: &LocalExecutable) -> std::result::Result<(), Error> {
    if local.size == 0 || local.size > abi::EXEC_MAX {
        return Err(Error::because(
            Errno::EINVAL,
            "invalid local executable size",
        ));
    }
    if local.digest.len() != 64 || !local.digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::because(
            Errno::EINVAL,
            "invalid local executable digest",
        ));
    }
    Ok(())
}

#[wasm_bindgen]
pub struct Kernel {
    state: Rc<RefCell<State>>,
    /// The process a cloud call acts for now (cloudfs.rs), read before the driver awaits.
    current: Rc<RefCell<cloudfs::Actor>>,
    /// The instance's cloud filesystem session (cloudfs.rs).
    cloud: cloudfs::Connector,
    /// Unified `os_vfs::Vfs` mount/namespace/descriptor engine (vfs_engine.rs).
    vfs_rt: RefCell<vfs_engine::VfsRuntime>,
}

#[wasm_bindgen]
impl Kernel {
    /// Create a fresh isolated client kernel instance (ZERO network RPCs).
    #[wasm_bindgen(constructor)]
    pub fn new(boot: &str, id: &str) -> Kernel {
        let now = now_secs();
        let instance_id = if !id.is_empty() && auth_v2::valid_id(id) {
            id.to_string()
        } else if !boot.is_empty() && auth_v2::valid_id(boot) {
            boot.to_string()
        } else {
            format!("inst-{}", random_hex(12))
        };
        let host_proof = random_hex(32);
        let boot_id = if !boot.is_empty() {
            boot.to_string()
        } else {
            format!("{instance_id}:b1")
        };
        let identity = InstanceIdentity {
            instance: instance_id.clone(),
            host: "browser".into(),
        };
        let mut table = LocalProcessTable::new(identity, now);
        let _ = table.boot_init("boot", now);
        let init_state = Init::new(boot_id.clone(), now);
        let account = LocalAccount::default();
        let login_session =
            LoginSession::new(format!("{instance_id}:s1"), account.uid, now + 86_400, now);

        let current = Rc::default();
        let state = Rc::new(RefCell::new(State {
            instance_id: instance_id.clone(),
            host_proof,
            boot: boot_id,
            namespace: instance_id.clone(),
            table,
            account,
            account_epoch: 1,
            proc_account_epoch: HashMap::new(),
            remote_attached: false,
            host_epoch: 0,
            pending_revocations: Vec::new(),
            attached_devices: BTreeMap::new(),
            init_state,
            login_session,
            login_profiles: BTreeMap::new(),
            seat_policies: BTreeMap::new(),
            boot_seq: 1,
            session_seq: 1,
        }));
        let connector = cloudfs::Connector::default();
        let root_cloud = Rc::new(cloudfs::RootCloudDriver::new(
            Rc::clone(&state),
            Rc::clone(&current),
            connector.clone(),
        ));
        let vfs_rt = RefCell::new(vfs_engine::VfsRuntime::new_sync(
            &instance_id,
            root_cloud,
            Rc::clone(&state),
        ));
        Kernel {
            current,
            cloud: connector,
            state,
            vfs_rt,
        }
    }

    /// The `HostAdapter` protocol version (`"2"`).
    pub fn version(&self) -> String {
        VERSION.into()
    }

    /// This instance's globally unique identifier.
    pub fn instance_id(&self) -> String {
        self.state.borrow().instance_id.clone()
    }

    /// The namespace/instance identifier.
    pub fn namespace(&self) -> String {
        self.state.borrow().namespace.clone()
    }

    /// Instance-local account credentials for workspace binding (ZERO network RPCs).
    pub fn workspace_credentials(&self) -> String {
        self.state.borrow().account.to_creds_json().to_string()
    }

    /// Update the instance-local account snapshot (ZERO network RPCs).
    pub fn sync_account(&self, account_json: &str) -> Result<String, JsValue> {
        let val: Value = parse(account_json, "account")?;
        let account = parse_account_from_value(&val)?;
        self.apply_account_update(account);
        Ok(self.state.borrow().account.to_creds_json().to_string())
    }

    /// Restore a persisted per-UID seat sharing policy from profile storage (ZERO network RPCs).
    pub fn restore_seat_policy(
        &self,
        uid: u32,
        sharing: &str,
        revision: u64,
    ) -> Result<String, JsValue> {
        if !matches!(sharing, "none" | "view" | "control") {
            return Err(fail(Errno::EINVAL.into()));
        }
        let mut state = self.state.borrow_mut();
        state.set_seat_policy(uid, sharing.to_string(), revision);
        Ok(state.login_view().to_string())
    }

    /// Refresh the instance-local account snapshot from the browser's current session cookie
    /// (called explicitly on `os:login-changed`, NEVER at cold boot).
    pub async fn sync_account_from_server(&self) -> Result<String, JsValue> {
        let mut results = cloudfs::page_sys_batch(abi::Batch {
            calls: vec![Call::Getcreds],
            umask: None,
            sudo: false,
            pid: None,
            process: None,
        })
        .await
        .map_err(|e| fail(Error::from(e)))?;
        let val = results
            .pop()
            .ok_or_else(|| fail(Errno::EIO.into()))?
            .into_result()
            .map_err(fail)?;
        let account = parse_account_from_value(&val)?;
        self.apply_account_update(account);
        Ok(self.state.borrow().account.to_creds_json().to_string())
    }

    /// Boot/initialize this local instance (ZERO network RPCs).
    pub async fn init(&self) -> Result<String, JsValue> {
        let (instance_id, boot, namespace) = {
            let mut state = self.state.borrow_mut();
            let now = now_secs();
            let _ = state.table.boot_init("boot", now);
            (
                state.instance_id.clone(),
                state.boot.clone(),
                state.namespace.clone(),
            )
        };
        Ok(json!({
            "namespace": namespace,
            "instance_id": instance_id,
            "boot": boot,
            "version": abi::contract::HOST_ADAPTER_VERSION,
            "local": true,
        })
        .to_string())
    }

    /// Local `MachineInit` state-machine action (`inspect`, `claim`, `renew`, `release`, `reboot`).
    /// Runs 100% locally (ZERO network RPCs; `reboot` revokes remote tokens if any are live).
    pub async fn machine_init_action(
        &self,
        action_json: &str,
        _host: &str,
    ) -> Result<String, JsValue> {
        let action: InitAction = parse(action_json, "machine_init action")?;
        let now = now_secs();
        let proof_hash = match &action {
            InitAction::Claim { owner }
            | InitAction::Renew { owner }
            | InitAction::Release { owner }
            | InitAction::Start { owner, .. } => {
                if owner.proof.len() != 64 || !owner.proof.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err(fail(Errno::EINVAL.into()));
                }
                if let InitAction::Start { token, .. } = &action
                    && (token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()))
                {
                    return Err(fail(Errno::EINVAL.into()));
                }
                sha256_hex(&owner.proof)
            }
            InitAction::Inspect | InitAction::Reboot { .. } => String::new(),
        };

        let (view, revoked, cleared_pids, is_reboot) = {
            let mut state = self.state.borrow_mut();
            if let InitAction::Reboot { .. } = &action
                && state.account.uid != 0
            {
                return Err(fail(Error::because(
                    Errno::EPERM,
                    "only root may reboot the instance",
                )));
            }
            state
                .init_state
                .apply(&action, &proof_hash, now)
                .map_err(fail)?;
            if let InitAction::Start { token, .. } = &action {
                state.init_state.start(&sha256_hex(token)).map_err(fail)?;
            }

            let mut revoked = Vec::new();
            let mut cleared_pids = Vec::new();
            let is_reboot = matches!(action, InitAction::Reboot { .. });
            if is_reboot {
                let victims = state.table.live_user_pids();
                // Revoke all remote credentials from this boot immediately while signalling
                // user processes gracefully with SIGHUP + SIGTERM + SIGCONT so trap handlers run.
                for &vpid in &victims {
                    revoked.extend(state.table.clear_remote_access(vpid));
                    if let Some(p) = state.table.proc(vpid) {
                        cleared_pids.push((vpid, p.cred.identity.clone()));
                    }
                }
                let active_tokens = state.table.active_remote_tokens();
                for tok in &active_tokens {
                    state.table.drop_revoked_remote_token(tok);
                }
                revoked.extend(active_tokens);
                for vpid in victims {
                    for sig in [SIGHUP, SIGTERM, SIGCONT] {
                        let _ = state.table.kill_with_revocations(
                            &Identity::root(),
                            None,
                            Target::Pid(vpid),
                            sig,
                            now,
                        );
                    }
                }
                // Advance to a fresh boot generation and login scope, preserving startup profile.
                state.boot_seq = state.boot_seq.saturating_add(1);
                let next_boot = format!("{}:b{}", state.instance_id, state.boot_seq);
                state.boot = next_boot.clone();
                state.init_state = Init::new(next_boot, now);
                state.session_seq = state.session_seq.saturating_add(1);
                let next_sid = format!("{}:s{}", state.instance_id, state.session_seq);
                let mut next_login =
                    LoginSession::new(next_sid, state.account.uid, now + 86_400, now);
                if let Some(profile) = state.login_profiles.get(&state.account.uid) {
                    next_login.startup = Some(Startup::new(profile.clone()));
                }
                state.login_session = next_login;
            }
            (state.init_state.view(), revoked, cleared_pids, is_reboot)
        };
        for (pid, id) in cleared_pids {
            let _ = self.proc_revoke_remote_creds(
                pid,
                id.id,
                id.group,
                id.groups.into_iter().collect(),
            );
        }
        if is_reboot {
            self.detach_all_remote_devices();
        }
        revoke_remote_tokens_state(&self.state, revoked).await;
        Ok(view.to_string())
    }

    /// Local `LoginSession` state-machine action (`inspect`, `join`, `keep`, `claim`, `renew`,
    /// `leave`, `configure`, `begin`, `attach`, `finish`, `signal`, `end`, `restart`, `seat_policy`).
    /// Runs 100% locally (ZERO network RPCs; `end`/`restart` revoke remote tokens of ended procs).
    pub async fn login_session_action(
        &self,
        action_json: &str,
        host: &str,
    ) -> Result<String, JsValue> {
        let raw: Value = parse(action_json, "login_session action")?;
        let now = now_secs();
        // Support `seat_policy` action directly in addition to `abi::LoginAction`.
        if raw.get("op").and_then(Value::as_str) == Some("seat_policy") {
            let sharing = raw["sharing"]
                .as_str()
                .ok_or_else(|| fail(Errno::EINVAL.into()))?;
            if !matches!(sharing, "none" | "view" | "control") {
                return Err(fail(Errno::EINVAL.into()));
            }
            let expected_session = raw["session"].as_str();
            let expected_rev = raw["expected"].as_u64();
            let mut state = self.state.borrow_mut();
            state.login_session.expire(now);
            if let Some(sid) = expected_session
                && sid != state.login_session.id
            {
                return Err(fail(Errno::ESTALE.into()));
            }
            let (_, cur_rev) = state.seat_policy();
            if let Some(rev) = expected_rev
                && rev != cur_rev
            {
                return Err(fail(Errno::ESTALE.into()));
            }
            let uid = state.account.uid;
            state.set_seat_policy(uid, sharing.to_string(), cur_rev.saturating_add(1));
            return Ok(state.login_view().to_string());
        }

        let action: LoginAction = from_value(raw, "login_session action")?;
        let mut revoked = Vec::new();
        let mut killed_pids = Vec::new();
        let mut cleared_pids = Vec::new();

        let view = {
            let mut state = self.state.borrow_mut();
            state.login_session.expire(now);
            revoked.extend(state.refresh_login_shutdown(now));
            match action {
                LoginAction::Inspect => state.login_view(),
                LoginAction::SeatPolicy {
                    session,
                    expected,
                    sharing,
                } => {
                    let (_, cur_rev) = state.seat_policy();
                    if session != state.login_session.id || expected != cur_rev {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let next_sharing = match sharing {
                        SharingMode::None => "none",
                        SharingMode::View => "view",
                        SharingMode::Control => "control",
                    }
                    .to_string();
                    let uid = state.account.uid;
                    state.set_seat_policy(uid, next_sharing, cur_rev.saturating_add(1));
                    state.login_view()
                }
                LoginAction::Join { host: h, proof } => {
                    let hash = sha256_hex(&proof);
                    state.login_session.join(&h, &hash).map_err(fail)?;
                    state.login_view()
                }
                LoginAction::Keep { member } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let hash = sha256_hex(&member.proof);
                    state
                        .login_session
                        .keep(&member.host, &hash)
                        .map_err(fail)?;
                    state.login_view()
                }
                LoginAction::Claim { member, generation } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let hash = sha256_hex(&member.proof);
                    state
                        .login_session
                        .claim(&member.host, &hash, generation)
                        .map_err(fail)?;
                    state.login_view()
                }
                LoginAction::Renew { member, generation } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let hash = sha256_hex(&member.proof);
                    state
                        .login_session
                        .renew(&member.host, &hash, generation)
                        .map_err(fail)?;
                    state.login_view()
                }
                LoginAction::Leave { member } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let hash = sha256_hex(&member.proof);
                    state
                        .login_session
                        .leave(&member.host, &hash)
                        .map_err(fail)?;
                    state.login_view()
                }
                LoginAction::Configure {
                    member,
                    generation,
                    file,
                } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let hash = sha256_hex(&member.proof);
                    state
                        .login_session
                        .authorize(&member.host, &hash, generation)
                        .map_err(fail)?;
                    let uid = state.account.uid;
                    match file {
                        Some(path) => {
                            if state.login_session.managed.is_some()
                                || state
                                    .login_session
                                    .startup
                                    .as_ref()
                                    .is_some_and(|s| s.reserved())
                            {
                                return Err(fail(Errno::EBUSY.into()));
                            }
                            let rev = random_hex(8);
                            let profile = StartupProfile::new(rev, path).map_err(fail)?;
                            state.login_profiles.insert(uid, profile.clone());
                            state.login_session.startup = Some(Startup::new(profile));
                        }
                        None => {
                            state.login_profiles.remove(&uid);
                            if let Some(startup) = &mut state.login_session.startup {
                                startup.disable();
                            }
                        }
                    }
                    state.login_view()
                }
                LoginAction::Begin {
                    member,
                    generation,
                    launch,
                } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let hash = sha256_hex(&member.proof);
                    state
                        .login_session
                        .authorize(&member.host, &hash, generation)
                        .map_err(fail)?;
                    let lhash = sha256_hex(&launch.proof);
                    state
                        .login_session
                        .startup
                        .as_mut()
                        .ok_or_else(|| fail(Errno::ESTALE.into()))?
                        .begin(&member.host, generation, &launch.revision, &lhash)
                        .map_err(fail)?;
                    state.login_view()
                }
                LoginAction::Attach {
                    member,
                    generation,
                    launch,
                    process,
                } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let proc = state
                        .table
                        .proc(process.pid)
                        .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                        .ok_or_else(|| fail(Errno::ESRCH.into()))?;
                    if proc.login_scope.as_deref() != Some(state.login_session.id.as_str()) {
                        return Err(fail(Error::because(
                            Errno::EPERM,
                            "process does not belong to this login scope",
                        )));
                    }
                    if proc.pid != proc.sid {
                        return Err(fail(Error::because(
                            Errno::EPERM,
                            "managed process must lead its own session",
                        )));
                    }
                    let hash = sha256_hex(&member.proof);
                    if let Some(launch) = launch {
                        let lhash = sha256_hex(&launch.proof);
                        state
                            .login_session
                            .attach_startup(
                                &member.host,
                                &hash,
                                generation,
                                process.pid,
                                &launch.revision,
                                &lhash,
                            )
                            .map_err(fail)?;
                    } else {
                        state
                            .login_session
                            .attach(&member.host, &hash, generation, process.pid)
                            .map_err(fail)?;
                    }
                    state.login_view()
                }
                LoginAction::Finish {
                    session,
                    launch,
                    status,
                    error,
                } => {
                    if session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let lhash = sha256_hex(&launch.proof);
                    let is_managed = state.login_session.managed.is_some();
                    let Some(startup) = &mut state.login_session.startup else {
                        return Err(fail(Errno::ESTALE.into()));
                    };
                    startup
                        .authorize_finish(&launch.revision, &lhash)
                        .map_err(fail)?;
                    if is_managed {
                        return Err(fail(Errno::EBUSY.into()));
                    }
                    startup
                        .finish(&launch.revision, &lhash, status, error)
                        .map_err(fail)?;
                    state.login_view()
                }
                LoginAction::Signal {
                    member,
                    generation,
                    pid,
                    signal,
                } => {
                    if member.session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let hash = sha256_hex(&member.proof);
                    state
                        .login_session
                        .signal(&member.host, &hash, generation, pid)
                        .map_err(fail)?;
                    let cred = state.account.identity();
                    let (deliveries, rev) = state
                        .table
                        .kill_with_revocations(&cred, None, Target::Pid(pid), signal, now)
                        .map_err(fail)?;
                    for d in deliveries {
                        if d.killed {
                            killed_pids.push(d.pid);
                        }
                    }
                    revoked.extend(rev);
                    if signal == SIGTERM
                        && let Ok((_, rev2)) = state.table.kill_with_revocations(
                            &cred,
                            None,
                            Target::Pid(pid),
                            SIGCONT,
                            now,
                        )
                    {
                        revoked.extend(rev2);
                    }
                    if killed_pids.contains(&pid)
                        && state
                            .login_session
                            .managed
                            .as_ref()
                            .is_some_and(|m| m.pid == pid)
                    {
                        state.login_session.managed = None;
                        if let Some(startup) = &mut state.login_session.startup
                            && startup.pid == Some(pid)
                        {
                            startup.observed_exit();
                        }
                    }
                    state.login_view()
                }
                LoginAction::End { session } => {
                    let newly_ended = state.login_session.end(&session).map_err(fail)?;
                    let sid = state.login_session.id.clone();
                    state.table.close_login_scope(&sid);
                    if newly_ended {
                        let live = state.table.login_scope_pids(&sid);
                        let cred = Identity::root();
                        for pid in live {
                            if let Ok((_, rev)) = state.table.kill_with_revocations(
                                &cred,
                                None,
                                Target::Pid(pid),
                                SIGTERM,
                                now,
                            ) {
                                revoked.extend(rev);
                            }
                            // F3-03: Immediately clear cloud_access AND drop remote tokens on ALL
                            // processes in the ending login scope so none can lazily mint tokens.
                            revoked.extend(state.table.clear_remote_access(pid));
                            if let Some(p) = state.table.proc(pid) {
                                cleared_pids.push((pid, p.cred.identity.clone()));
                            }
                        }
                    }
                    revoked.extend(state.refresh_login_shutdown(now));
                    state.login_view()
                }
                LoginAction::Restart { session } => {
                    if session != state.login_session.id {
                        return Err(fail(Errno::ESTALE.into()));
                    }
                    let complete = state
                        .login_session
                        .shutdown
                        .as_ref()
                        .is_some_and(|s| s.complete);
                    if !complete && state.account.uid != 0 {
                        return Err(fail(Error::because(
                            Errno::EPERM,
                            "only root may restart an active login session",
                        )));
                    }
                    let old_sid = state.login_session.id.clone();
                    state.table.close_login_scope(&old_sid);
                    for pid in state.table.login_scope_pids(&old_sid) {
                        if let Ok((deliveries, rev)) = state.table.kill_with_revocations(
                            &Identity::root(),
                            None,
                            Target::Pid(pid),
                            SIGKILL,
                            now,
                        ) {
                            for d in deliveries {
                                if d.killed {
                                    killed_pids.push(d.pid);
                                }
                            }
                            revoked.extend(rev);
                        }
                    }
                    state.session_seq = state.session_seq.saturating_add(1);
                    let next_sid = format!("{}:s{}", state.instance_id, state.session_seq);
                    let mut next =
                        LoginSession::new(next_sid, state.account.uid, now + 86_400, now);
                    if let Some(profile) = state.login_profiles.get(&state.account.uid) {
                        next.startup = Some(Startup::new(profile.clone()));
                    }
                    state.login_session = next;
                    state.login_view()
                }
            }
        };

        for (pid, id) in cleared_pids {
            let _ = self.proc_revoke_remote_creds(
                pid,
                id.id,
                id.group,
                id.groups.into_iter().collect(),
            );
        }
        for kpid in killed_pids {
            self.cloud_exited(kpid, None).await;
        }
        revoke_remote_tokens_state(&self.state, revoked).await;
        Ok(view.to_string())
    }

    /// Bind a hosted process to the local login coordinator before guest code starts (0 RPCs).
    pub async fn login_attach(
        &self,
        pid: u32,
        member: &str,
        generation: u64,
        launch: Option<String>,
        host: &str,
    ) -> Result<String, JsValue> {
        let member_val: Value = parse(member, "login member")?;
        let launch_val: Option<Value> = launch
            .as_deref()
            .map(|value| parse(value, "login launch"))
            .transpose()?;
        let action = json!({
            "op": "attach",
            "member": member_val,
            "generation": generation,
            "launch": launch_val,
            "process": { "pid": pid, "proc": "", "signals": [] },
        });
        self.login_session_action(&action.to_string(), host).await
    }

    /// execve: spawn one local process (ZERO network RPCs for local paths & non-sudo).
    #[allow(clippy::too_many_arguments)]
    pub async fn exec(
        &self,
        path: &str,
        argv: &str,
        env: &str,
        cwd: &str,
        cgroup: &str,
        sudo: bool,
        seat: &str,
        host: &str,
    ) -> Result<String, JsValue> {
        let stage = json!({
            "path": path,
            "argv": parse::<Value>(argv, "argv")?,
            "env": parse::<Value>(env, "env")?,
            "cwd": cwd,
            "cgroup": cgroup,
        });
        let mut results = self.execs_of(vec![stage], sudo, seat, host).await?;
        match results.pop() {
            Some(Ok(exec)) => to_json(&exec),
            Some(Err(error)) => Err(fail(error)),
            None => Err(fail(Error::because(Errno::EIO, "no process was made"))),
        }
    }

    /// execve of each stage of a pipeline at once.
    pub async fn execs(
        &self,
        stages: &str,
        sudo: bool,
        seat: &str,
        host: &str,
    ) -> Result<String, JsValue> {
        let stages: Vec<Value> = parse(stages, "stages")?;
        let results = self.execs_of(stages, sudo, seat, host).await?;
        let results: Vec<Value> = results
            .into_iter()
            .map(|result| match result {
                Ok(exec) => json!({ "ok": exec }),
                Err(error) => json!({ "err": { "errno": error.errno, "detail": error.detail } }),
            })
            .collect();
        Ok(Value::Array(results).to_string())
    }

    /// Replace image of `pid` (`execve(2)`): 100% local unless rotating an attached `RemoteCredRef`.
    #[allow(clippy::too_many_arguments)]
    pub async fn reexec(
        &self,
        pid: u32,
        local: &str,
        path: &str,
        argv: &str,
        env: &str,
        cwd: &str,
        _seat: &str,
        host: &str,
    ) -> Result<String, JsValue> {
        let local_exec: Option<LocalExecutable> = parse(local, "local executable")?;
        if let Some(le) = &local_exec {
            validate_local_exec(le).map_err(fail)?;
        }
        let argv_vec: Vec<String> = parse(argv, "argv")?;
        let env_vec: Vec<String> = parse(env, "env")?;
        let cloud_req = local_exec.as_ref().is_none_or(|l| l.cloud);

        let (prev_remote, prev_cloud, cgroup, io_at_derive) = {
            let state = self.state.borrow();
            let proc = state
                .table
                .proc(pid)
                .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                .ok_or_else(|| fail(Error::because(Errno::ESRCH, format!("no process {pid}"))))?;
            let io = state.table.cgroups().effective_io_limit(&proc.cgroup);
            (
                proc.cred.remote.clone(),
                proc.cred.cloud_access,
                proc.cgroup.clone(),
                io,
            )
        };

        let next_cloud = prev_cloud && cloud_req;
        // F3-03: Derive with `revoke_parent: false`, then let `LocalProcessTable::reexec`
        // atomically determine which old tokens now have zero live holders (revoking either
        // dropped old tokens on success OR the newly derived token on failure).
        let mut derived_remote: Option<RemoteCredRef> = None;
        if let Some(old_rem) = &prev_remote
            && next_cloud
            && cloudfs::installed("serviceAuthPost").is_ok()
        {
            let (instance_id, host_proof) = ensure_remote_attached_state(&self.state)
                .await
                .map_err(fail)?;
            let resp =
                service_auth_request(&auth_v2::Request::DeriveServiceCred(DeriveServiceCred {
                    instance_id,
                    host_proof,
                    parent_token: old_rem.token.clone(),
                    scope: old_rem.scope.clone(),
                    cloud_access: next_cloud,
                    umask: None,
                    cgroup: Some(cgroup.clone()),
                    revoke_parent: false,
                    rbps: io_at_derive.read,
                    wbps: io_at_derive.write,
                }))
                .await
                .map_err(fail)?;
            if let auth_v2::Response::Cred(issued) = resp {
                derived_remote = Some(RemoteCredRef {
                    token: issued.token,
                    uid: issued.uid,
                    gid: issued.gid,
                    groups: issued.groups,
                    instance_id: issued.instance_id,
                    lineage: issued.lineage,
                    cloud_access: issued.cloud_access,
                    scope: issued.scope,
                });
            }
        }

        let reexec_res = {
            let mut state = self.state.borrow_mut();
            state
                .table
                .reexec(
                    host,
                    pid,
                    ReexecSpec {
                        path: path.into(),
                        argv: argv_vec,
                        env: env_vec,
                        cwd: (!cwd.is_empty()).then(|| cwd.to_string()),
                        runtime: Some(kernel::local_cgroups::RESOURCE_CONTRACT.into()),
                        cloud_access: next_cloud,
                        new_remote: derived_remote.clone(),
                    },
                    now_secs(),
                )
                .map(|(proc, dropped)| {
                    let updated = state.table.proc(pid).cloned().unwrap_or(proc);
                    (updated, dropped)
                })
        };
        let (updated_proc, dropped_tokens) = match reexec_res {
            Ok(pair) => pair,
            Err(err) => {
                if let Some(d) = derived_remote {
                    revoke_remote_tokens_state(&self.state, vec![d.token]).await;
                }
                return Err(fail(err));
            }
        };
        revoke_remote_tokens_state(&self.state, dropped_tokens).await;
        if let Some(ref rem) = updated_proc.cred.remote {
            self.sync_remote_io_quota_for_token(&rem.token, &updated_proc.cgroup)
                .await;
        }

        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            meta.supervisor = false;
        }
        let new_token = updated_proc.cred.remote.as_ref().map(|r| r.token.clone());
        let id = updated_proc.cred.identity.clone();
        let setup = async {
            self.proc_exec_preserve(pid).await?;
            self.proc_set_creds(
                pid,
                id.id,
                id.group,
                id.groups.into_iter().collect(),
                new_token.clone(),
                updated_proc.cred.cloud_access,
            )
        }
        .await;
        if let Err(error) = setup {
            let _ = self.exit(pid, 126, None, host).await;
            let error = error
                .as_string()
                .and_then(|s| js_sys::JSON::parse(&s).ok())
                .unwrap_or(error);
            let _ = js_sys::Reflect::set(&error, &"execCommitted".into(), &JsValue::TRUE);
            return Err(error);
        }

        let boot_id = self.state.borrow().boot.clone();
        let exec = Exec {
            pid,
            boot: Some(boot_id),
            login_scope: updated_proc.login_scope.clone(),
            token: new_token.unwrap_or_default(),
            local: local_exec.as_ref().map(|l| LocalExecutable {
                digest: l.digest.clone(),
                size: l.size,
                cloud: updated_proc.cred.cloud_access,
            }),
            fd: None,
            asset: if local_exec.is_some() {
                None
            } else {
                system_usr_asset(&updated_proc.path)
            },
            path: Some(updated_proc.path.clone()),
            size: local_exec.as_ref().map_or(0, |l| l.size),
            token_read: None,
            version: None,
            cgroup: updated_proc.cgroup.clone(),
            placement: Placement {
                cluster: "local".into(),
                executor: "browser".into(),
                cgroup: updated_proc.cgroup.clone(),
            },
        };
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            meta.supervisor = is_supervisor_image(&exec);
        }
        to_json(&exec)
    }

    /// Fork locally in `LocalProcessTable` (ZERO network RPCs).
    pub async fn fork(&self, pid: u32, host: &str, empty_memory: bool) -> Result<String, JsValue> {
        let child = {
            let mut state = self.state.borrow_mut();
            let child = state
                .table
                .fork(host, pid, empty_memory, now_secs())
                .map_err(fail)?;
            if let Some(ep) = state.proc_account_epoch.get(&pid).copied() {
                state.proc_account_epoch.insert(child.pid, ep);
            }
            child
        };
        if let Err(err) = self.proc_fork(pid, child.pid, 0) {
            let mut state = self.state.borrow_mut();
            let _ = state.table.exit(host, child.pid, 126, None, now_secs());
            let _ = state.table.waitpid(host, pid, child.pid as i32, 1);
            return Err(err);
        }
        let token = child
            .cred
            .remote
            .as_ref()
            .map(|r| r.token.clone())
            .unwrap_or_default();
        to_json(&json!({ "pid": child.pid, "token": token }))
    }

    /// Process exit: zombie + subreaper/init orphan reparenting + immediate remote token revoke
    /// only when the exiting process was the last live holder of a remote credential.
    pub async fn exit(
        &self,
        pid: u32,
        status: i32,
        signal: Option<u8>,
        host: &str,
    ) -> Result<String, JsValue> {
        let (has_live, token_before) = {
            let state = self.state.borrow();
            let proc = state
                .table
                .proc(pid)
                .filter(|p| p.owner_host == host)
                .ok_or_else(|| fail(Error::because(Errno::ESRCH, format!("no process {pid}"))))?;
            (
                proc.state != ProcState::Zombie,
                proc.cred.remote.as_ref().map(|r| r.token.clone()),
            )
        };
        if !has_live {
            return Err(fail(Errno::ESRCH.into()));
        }
        self.close_process_server_fds(pid).await;
        let outcome = {
            let mut state = self.state.borrow_mut();
            let out = state
                .table
                .exit(host, pid, status, signal, now_secs())
                .map_err(fail)?;
            if state
                .login_session
                .managed
                .as_ref()
                .is_some_and(|m| m.pid == pid)
            {
                state.login_session.managed = None;
                if let Some(startup) = &mut state.login_session.startup
                    && startup.pid == Some(pid)
                {
                    startup.observed_exit();
                }
            }
            out
        };
        self.cloud_exited(pid, token_before).await;
        for kpid in outcome.killed_pids {
            if kpid != pid {
                self.cloud_exited(kpid, None).await;
            }
        }
        revoke_remote_tokens_state(&self.state, outcome.revoked_tokens).await;
        Ok(json!({ "ppid": outcome.ppid }).to_string())
    }

    /// Reap an ended direct child of PID 1 (ZERO network RPCs).
    pub async fn wait(&self, pid: u32, host: &str) -> Result<String, JsValue> {
        let mut state = self.state.borrow_mut();
        let cred = state.account.identity();
        let reaped = state
            .table
            .reap_init_child(host, &cred, pid)
            .map_err(fail)?;
        state.proc_account_epoch.remove(&pid);
        let _ = state.refresh_login_shutdown(now_secs());
        to_json(&reaped)
    }

    /// `wait4(2)` of parent `ppid` for child `pid` (or any child) (ZERO network RPCs).
    pub async fn waitchild(
        &self,
        ppid: u32,
        pid: Option<u32>,
        host: &str,
    ) -> Result<String, JsValue> {
        let selector = pid.map_or(-1, |p| p as i32);
        let mut state = self.state.borrow_mut();
        match state
            .table
            .waitpid(host, ppid, selector, kernel::proc_table::WNOHANG)
            .map_err(fail)?
        {
            WaitOutcome::Reaped(proc) => {
                state.proc_account_epoch.remove(&proc.pid);
                let code = if proc.signal.is_some() {
                    128 + i32::from(proc.signal.unwrap_or(0))
                } else {
                    (proc.status >> 8) & 0xff
                };
                Ok(json!({
                    "pid": proc.pid,
                    "ppid": ppid,
                    "status": proc.status,
                    "code": code,
                    "signal": proc.signal,
                })
                .to_string())
            }
            WaitOutcome::Event { pid, status } => Ok(json!({
                "pid": pid,
                "ppid": ppid,
                "status": status,
            })
            .to_string()),
            WaitOutcome::Pending => Err(fail(Errno::EAGAIN.into())),
        }
    }

    /// `kill(2)`: 100% local in `LocalProcessTable` (revokes remote token only if `SIGKILL` ended
    /// the last live holder of a remote credential).
    pub async fn kill(
        &self,
        pid: i32,
        signal: Option<u8>,
        from: Option<u32>,
        host: &str,
    ) -> Result<String, JsValue> {
        let sig = signal.unwrap_or(SIGTERM);
        let target_str = pid.to_string();
        let target = Target::of(&target_str);
        let (deliveries, revoked) = {
            let mut state = self.state.borrow_mut();
            let caller_cred = if let Some(from_pid) = from {
                state
                    .table
                    .proc(from_pid)
                    .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                    .ok_or_else(|| {
                        fail(Error::because(
                            Errno::ESRCH,
                            format!("no process {from_pid}"),
                        ))
                    })?
                    .cred
                    .identity
                    .clone()
            } else {
                state.account.identity()
            };
            state
                .table
                .kill_with_revocations(&caller_cred, from, target, sig, now_secs())
                .map_err(fail)?
        };
        for d in deliveries {
            if d.killed {
                {
                    let mut state = self.state.borrow_mut();
                    let was_managed = state
                        .login_session
                        .managed
                        .as_ref()
                        .is_some_and(|m| m.pid == d.pid);
                    if was_managed {
                        state.login_session.managed = None;
                        if let Some(startup) = state.login_session.startup.as_mut() {
                            startup.observed_exit();
                        }
                    }
                }
                self.cloud_exited(d.pid, None).await;
            }
        }
        revoke_remote_tokens_state(&self.state, revoked).await;
        Ok("null".into())
    }

    /// Invoke a process lifecycle operation locally in `LocalProcessTable` (ZERO network RPCs).
    pub async fn process_call(&self, pid: u32, call: &str, host: &str) -> Result<String, JsValue> {
        let call: Call = parse(call, "process call")?;
        let val = self
            .eval_local_process_call(pid, host, call)
            .await
            .map_err(fail)?;
        Ok(val.to_string())
    }

    /// Bootstrap a pipeline's session/pgid locally before guest code starts (ZERO network RPCs).
    pub async fn session(&self, pids: &str, host: &str) -> Result<String, JsValue> {
        let pids: Vec<u32> = parse(pids, "session processes")?;
        let mut state = self.state.borrow_mut();
        let _sid = state.table.bootstrap_session(host, &pids).map_err(fail)?;
        let mut rows = Vec::with_capacity(pids.len());
        for pid in pids {
            if let Some(p) = state.table.proc(pid) {
                rows.push(json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "pgid": p.pgid,
                    "sid": p.sid,
                    "uid": p.cred.identity.id,
                    "ctty": p.ctty.unwrap_or(0),
                }));
            }
        }
        Ok(Value::Array(rows).to_string())
    }

    /// Poll visible local processes (`hidepid=invisible`, ZERO network RPCs).
    pub async fn poll(&self, pids: &str) -> Result<String, JsValue> {
        let pids: Vec<u32> = parse(pids, "pids")?;
        if pids.len() > PROC_POLL_MAX {
            return Err(fail(Error::because(
                Errno::E2BIG,
                format!("at most {PROC_POLL_MAX} processes at a time"),
            )));
        }
        let state = self.state.borrow();
        let cred = state.account.identity();
        let procs = state.table.poll(&cred, &pids);
        to_json(&procs)
    }

    /// Record controlling terminal & tty fds for a local process (ZERO network RPCs).
    pub fn terminal(&self, pid: u32, tty: u32, fds: &str, host: &str) -> Result<(), JsValue> {
        let fds: Vec<u32> = parse(fds, "terminal descriptors")?;
        if fds.len() > 256 {
            return Err(fail(Errno::E2BIG.into()));
        }
        self.state
            .borrow_mut()
            .table
            .set_tty(host, pid, tty, fds)
            .map_err(fail)
    }

    /// Start local PID 1 (`init`) under local `InitOwner` fence (ZERO network RPCs).
    pub async fn boot_init(&self, owner: &str, token: &str, host: &str) -> Result<String, JsValue> {
        let owner: InitOwner = parse(owner, "init owner")?;
        if owner.proof.len() != 64
            || !owner.proof.bytes().all(|c| c.is_ascii_hexdigit())
            || token.len() != 64
            || !token.bytes().all(|c| c.is_ascii_hexdigit())
        {
            return Err(fail(Errno::EINVAL.into()));
        }
        let now = now_secs();
        let proof_hash = sha256_hex(&owner.proof);
        let token_hash = sha256_hex(token);
        {
            let mut state = self.state.borrow_mut();
            state
                .init_state
                .apply(
                    &InitAction::Start {
                        owner,
                        token: token.into(),
                    },
                    &proof_hash,
                    now,
                )
                .map_err(fail)?;
            state.init_state.start(&token_hash).map_err(fail)?;
            let _ = state.table.boot_init(host, now);
            // Update PID 1's owner_host to this host so `init` Worker can call waitpid/sync.
            let _ = state.table.set_tty(host, INIT, 0, Vec::new());
        }
        let _ = self.proc_set_creds(INIT, 0, 0, vec![0], None, false);
        Ok(json!({
            "pid": INIT,
            "ppid": 0,
            "token": "",
            "asset": "/usr/bin/init.wasm",
            "path": "/usr/bin/init",
            "membership": { "pid": INIT, "ppid": 0, "pgid": INIT, "sid": INIT, "uid": 0, "ctty": 0 }
        })
        .to_string())
    }

    /// Reconcile local processes owned by `host` and acknowledge delivered signals (ZERO network RPCs).
    pub async fn sync(&self, host: &str, acknowledgements: &str) -> Result<String, JsValue> {
        let acknowledgements: BTreeMap<u32, Vec<u64>> = serde_json::from_str(acknowledgements)
            .map_err(|error| JsValue::from_str(&error.to_string()))?;
        let mut state = self.state.borrow_mut();
        let host_pids: Vec<u32> = state
            .table
            .all_pids()
            .into_iter()
            .filter(|&pid| state.table.proc(pid).is_some_and(|p| p.owner_host == host))
            .collect();
        let mut rows = Vec::with_capacity(host_pids.len());
        for pid in host_pids {
            if let Some(seqs) = acknowledgements.get(&pid)
                && !seqs.is_empty()
            {
                let _ = state.table.ack_signals(host, pid, seqs);
            }
            if let Some(p) = state.table.proc(pid) {
                rows.push(p.to_abi_proc());
            }
        }
        to_json(&rows)
    }

    /// Authoritative local `(pid, ppid)` (ZERO network RPCs).
    pub async fn getpid(&self, pid: u32) -> Result<String, JsValue> {
        let state = self.state.borrow();
        let proc = state
            .table
            .proc(pid)
            .ok_or_else(|| fail(Error::from(Errno::ESRCH)))?;
        Ok(json!({ "pid": proc.pid, "ppid": proc.ppid }).to_string())
    }

    /// Return a hosted process's local credential snapshot (ZERO network RPCs).
    pub fn getcreds_proc(&self, pid: u32, host: &str) -> Result<String, JsValue> {
        let state = self.state.borrow();
        let proc = state
            .table
            .proc(pid)
            .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
            .ok_or_else(|| fail(Errno::ESRCH.into()))?;
        let rt = self.vfs_rt.borrow();
        let uid = proc.cred.identity.id;
        let gid = proc.cred.identity.group;
        let user = rt
            .uid_names
            .get(&uid)
            .cloned()
            .or_else(|| rt.root_cloud.cached_uid_name(uid))
            .unwrap_or_else(|| {
                if uid == 0 {
                    "root".into()
                } else if uid == 65534 {
                    "guest".into()
                } else {
                    uid.to_string()
                }
            });
        let group = rt
            .gid_names
            .get(&gid)
            .cloned()
            .or_else(|| rt.root_cloud.cached_gid_name(gid))
            .unwrap_or_else(|| {
                if gid == 0 {
                    "root".into()
                } else if gid == 65534 {
                    "guest".into()
                } else {
                    gid.to_string()
                }
            });
        let groups: Vec<u32> = proc.cred.identity.groups.iter().copied().collect();
        let group_names: Vec<String> = groups
            .iter()
            .map(|&g| {
                rt.gid_names
                    .get(&g)
                    .cloned()
                    .or_else(|| rt.root_cloud.cached_gid_name(g))
                    .unwrap_or_else(|| {
                        if g == 0 {
                            "root".into()
                        } else if g == 65534 {
                            "guest".into()
                        } else {
                            g.to_string()
                        }
                    })
            })
            .collect();
        let can_sudo = uid == 0 || groups.contains(&0) || group_names.iter().any(|n| n == "wheel");
        Ok(json!({
            "uid": uid,
            "gid": gid,
            "groups": groups,
            "user": user,
            "group": group,
            "group_names": group_names,
            "home": if uid == 0 { "/root" } else { state.account.home.as_str() },
            "shell": state.account.shell,
            "signed_in": state.account.signed_in,
            "can_sudo": can_sudo,
            "sudo_active": uid == 0,
            "cloud_access": proc.cred.cloud_access,
            "has_remote": proc.cred.remote.is_some(),
        })
        .to_string())
    }

    /// Local linear-memory reservation (`resources-v1`, ZERO network RPCs).
    pub fn reserve_memory(&self, pid: u32, bytes: u64, host: &str) -> Result<(), JsValue> {
        self.state
            .borrow_mut()
            .table
            .reserve_memory(host, pid, bytes)
            .map_err(fail)
    }

    /// Local credential update / privilege drop (`docs/architecture/contract.md` §2.4).
    /// Dropping local privilege clears any ambient remote credential unless an explicit lower
    /// remote credential is supplied, immediately revoking any dropped token via `ServiceAuth v2`.
    pub async fn set_proc_cred(
        &self,
        pid: u32,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
        explicit_remote_json: Option<String>,
        host: &str,
    ) -> Result<String, JsValue> {
        let explicit_remote: Option<RemoteCredRef> = explicit_remote_json
            .as_deref()
            .filter(|s| !s.is_empty() && *s != "null")
            .map(|s| parse(s, "explicit remote cred"))
            .transpose()?;
        let mut gset: BTreeSet<u32> = groups.iter().copied().collect();
        gset.insert(gid);
        let identity = Identity {
            id: uid,
            group: gid,
            groups: gset,
        };
        let (revoked, next_token, next_cloud) = {
            let mut state = self.state.borrow_mut();
            // F3-01: Untrusted HostAdapter `set_proc_cred` can NEVER escalate a non-root process
            // to uid 0, forge a remote credential with `cloud_access: true`, or bind remote uid 0.
            let prev = state
                .table
                .proc(pid)
                .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                .ok_or_else(|| fail(Errno::ESRCH.into()))?;
            let prev_uid = prev.cred.identity.id;
            if prev_uid != 0 && uid == 0 {
                return Err(fail(Error::because(
                    Errno::EPERM,
                    "unprivileged process cannot elevate to uid 0",
                )));
            }
            if let Some(ref rem) = explicit_remote
                && (rem.cloud_access || (prev_uid != 0 && rem.uid == 0))
            {
                return Err(fail(Error::because(
                    Errno::EPERM,
                    "set_proc_cred cannot supply remote cloud_access or root credentials",
                )));
            }
            let rev = state
                .table
                .set_cred(host, pid, identity.clone(), explicit_remote)
                .map_err(fail)?;
            let proc = state
                .table
                .proc(pid)
                .ok_or_else(|| fail(Errno::ESRCH.into()))?;
            (
                rev,
                proc.cred.remote.as_ref().map(|r| r.token.clone()),
                proc.cred.cloud_access,
            )
        };
        let _ = self.proc_set_creds(
            pid,
            uid,
            gid,
            identity.groups.into_iter().collect(),
            next_token.clone(),
            next_cloud,
        );
        revoke_remote_tokens_state(&self.state, revoked).await;
        Ok(json!({
            "pid": pid,
            "uid": uid,
            "gid": gid,
            "cloud_access": next_cloud,
            "has_remote": next_token.is_some(),
        })
        .to_string())
    }

    /// Legacy batching hooks retained as no-ops (all process state is synchronous & local).
    pub fn pending(&self) -> bool {
        false
    }
    pub fn queued(&self) -> f64 {
        0.0
    }
    pub fn reported(&self) -> f64 {
        0.0
    }
    pub async fn flush(&self) -> Result<(), JsValue> {
        Ok(())
    }

    /// Local cgroup v2 policy operations (ZERO network RPCs except `io.max` push when remote
    /// attached or `cgroup.kill` revoking remote tokens).
    pub async fn cgroup_create(&self, path: &str) -> Result<String, JsValue> {
        let mut state = self.state.borrow_mut();
        let cred = state.account.identity();
        state
            .table
            .cgroup_create(&cred, None, path, None, None)
            .map_err(fail)?;
        Ok("null".into())
    }

    pub async fn cgroup_set(&self, path: &str, key: &str, value: &str) -> Result<String, JsValue> {
        let (deliveries, revoked, norm) = {
            let mut state = self.state.borrow_mut();
            let cred = state.account.identity();
            let (d, r) = state
                .table
                .cgroup_set_with_revocations(&cred, path, key, value, now_secs())
                .map_err(fail)?;
            let norm = normalize_cgroup_path(path).unwrap_or_else(|_| path.to_string());
            (d, r, norm)
        };
        for d in deliveries {
            if d.killed {
                {
                    let mut state = self.state.borrow_mut();
                    let was_managed = state
                        .login_session
                        .managed
                        .as_ref()
                        .is_some_and(|m| m.pid == d.pid);
                    if was_managed {
                        state.login_session.managed = None;
                        if let Some(startup) = state.login_session.startup.as_mut() {
                            startup.observed_exit();
                        }
                    }
                }
                self.cloud_exited(d.pid, None).await;
            }
        }
        revoke_remote_tokens_state(&self.state, revoked).await;
        if key == "io.max" {
            self.sync_remote_io_quota_subtree(&norm).await;
        }
        Ok("null".into())
    }

    pub async fn cgroup_attach(&self, pid: u32, path: &str) -> Result<String, JsValue> {
        let (norm, remote_tok) = {
            let mut state = self.state.borrow_mut();
            let cred = state.account.identity();
            state.table.cgroup_attach(&cred, pid, path).map_err(fail)?;
            let norm = normalize_cgroup_path(path).unwrap_or_else(|_| path.to_string());
            let tok = state
                .table
                .proc(pid)
                .and_then(|p| p.cred.remote.as_ref().map(|r| r.token.clone()));
            (norm, tok)
        };
        if let Some(token) = remote_tok {
            self.sync_remote_io_quota_for_token(&token, &norm).await;
        }
        Ok("null".into())
    }

    pub async fn cgroup_remove(&self, path: &str) -> Result<String, JsValue> {
        let mut state = self.state.borrow_mut();
        let cred = state.account.identity();
        state.table.cgroup_remove(&cred, path).map_err(fail)?;
        Ok("null".into())
    }

    pub async fn cgroup_stat(&self, path: &str) -> Result<String, JsValue> {
        let state = self.state.borrow();
        let val = state.table.cgroup_stat(path).map_err(fail)?;
        Ok(val.to_string())
    }

    pub async fn cgroup_list(&self, path: &str) -> Result<String, JsValue> {
        let state = self.state.borrow();
        let list = state.table.cgroup_list(path);
        to_json(&list)
    }

    /// Negotiate `ServiceAuth` protocol version (`Hello` -> `Welcome` or `EPROTONOSUPPORT` without
    /// auto-reload, Contract §2.10).
    pub async fn service_auth_hello(
        &self,
        versions_json: Option<String>,
    ) -> Result<String, JsValue> {
        let versions: Vec<u32> = match versions_json.as_deref() {
            Some(s) if !s.is_empty() => parse(s, "versions")?,
            _ => vec![auth_v2::VERSION],
        };
        let resp = service_auth_request(&auth_v2::Request::Hello(Hello {
            boundary: Boundary::ServiceAuth,
            versions,
        }))
        .await
        .map_err(fail)?;
        to_json(&resp)
    }

    /// Explicitly attach this instance to `ServiceAuth v2`.
    pub async fn service_auth_attach(&self) -> Result<String, JsValue> {
        let (instance_id, _) = ensure_remote_attached_state(&self.state)
            .await
            .map_err(fail)?;
        let epoch = self.state.borrow().host_epoch;
        Ok(json!({
            "version": auth_v2::VERSION,
            "instance_id": instance_id,
            "host_epoch": epoch,
        })
        .to_string())
    }

    /// Explicitly mint and bind a `ServiceAuth v2` remote credential to local process `pid`.
    pub async fn mint_remote_cred(
        &self,
        pid: u32,
        scope_json: Option<String>,
        sudo: bool,
        host: &str,
    ) -> Result<String, JsValue> {
        let scope: RemoteScope = match scope_json.as_deref() {
            Some(s) if !s.is_empty() && s != "null" => parse(s, "remote scope")?,
            _ => RemoteScope::full(),
        };
        let (cgroup, io_at_mint, proc_uid, proc_epoch, signed_in, cur_epoch) = {
            let state = self.state.borrow();
            let proc = state
                .table
                .proc(pid)
                .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                .ok_or_else(|| fail(Errno::ESRCH.into()))?;
            if !proc.cred.cloud_access {
                return Err(fail(Error::because(
                    Errno::EACCES,
                    "process has no cloud access",
                )));
            }
            let io = state.table.cgroups().effective_io_limit(&proc.cgroup);
            (
                proc.cgroup.clone(),
                io,
                proc.cred.identity.id,
                state.proc_account_epoch.get(&pid).copied().unwrap_or(0),
                state.account.signed_in,
                state.account_epoch,
            )
        };
        let account_changed = proc_epoch != cur_epoch;
        if sudo && (proc_uid != 0 || account_changed) {
            return Err(fail(Error::because(
                Errno::EPERM,
                "sudo remote mint requires an active root process in the current account epoch",
            )));
        }
        let (instance_id, host_proof) = ensure_remote_attached_state(&self.state)
            .await
            .map_err(fail)?;
        let resp = service_auth_request(&auth_v2::Request::MintServiceCred(MintServiceCred {
            instance_id: instance_id.clone(),
            host_proof: host_proof.clone(),
            scope: scope.clone(),
            cloud_access: scope.cloud_fs,
            umask: 0o022,
            cgroup: Some(cgroup.clone()),
            generation: None,
            sudo,
            rbps: io_at_mint.read,
            wbps: io_at_mint.write,
        }))
        .await
        .map_err(fail)?;
        let issued = match resp {
            auth_v2::Response::Cred(c) => c,
            _ => return Err(fail(Error::because(Errno::EIO, "unexpected cred reply"))),
        };
        // F3-01: Prevent a guest or stale process from hijacking a signed-in/root account cookie,
        // and never let `sudo: true` bind a root remote token onto a non-root or stale process.
        if !lazy_mint_uid_permitted(proc_uid, issued.uid, signed_in, account_changed) {
            revoke_remote_tokens_state(&self.state, vec![issued.token]).await;
            return Err(fail(Error::because(
                Errno::EACCES,
                "process identity does not match current remote account",
            )));
        }
        let rem = RemoteCredRef {
            token: issued.token.clone(),
            uid: issued.uid,
            gid: issued.gid,
            groups: issued.groups.clone(),
            instance_id: issued.instance_id.clone(),
            lineage: issued.lineage.clone(),
            cloud_access: issued.cloud_access,
            scope: issued.scope.clone(),
        };
        // Re-check process state after awaiting `MintServiceCred` so a concurrent privilege drop,
        // `cloud_access=false` attenuation, or process exit mid-await can never be overwritten.
        let bind_res = {
            let mut state = self.state.borrow_mut();
            let current_proc = state
                .table
                .proc(pid)
                .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                .map(|p| {
                    (
                        p.cred.cloud_access,
                        p.cred.identity.clone(),
                        p.cgroup.clone(),
                    )
                });
            match current_proc {
                None => Err(Error::from(Errno::ESRCH)),
                Some((cloud_now, cur_id, _)) if !cloud_now || cur_id.id != proc_uid => {
                    Err(Error::because(
                        Errno::EACCES,
                        "process credentials changed during remote credential mint",
                    ))
                }
                Some((_, cur_id, cur_cg)) => {
                    let hydrate = !sudo
                        && proc_uid == os_core::permissions::GUEST
                        && os_core::permissions::is_guest_id(rem.uid)
                        && !signed_in
                        && !account_changed;
                    let next_local_id = if hydrate {
                        Identity {
                            id: rem.uid,
                            group: rem.gid,
                            groups: rem.groups.iter().copied().collect(),
                        }
                    } else {
                        cur_id
                    };
                    let set_res = if hydrate {
                        state.table.hydrate_guest_identity(
                            host,
                            pid,
                            next_local_id.clone(),
                            Some(rem.clone()),
                        )
                    } else {
                        state
                            .table
                            .set_cred(host, pid, next_local_id.clone(), Some(rem.clone()))
                    };
                    set_res.map(|rev| {
                        let hydrated_pids = if hydrate {
                            state.hydrate_guest_account_if_uninitialized(
                                rem.uid,
                                rem.gid,
                                &rem.groups,
                            )
                        } else {
                            Vec::new()
                        };
                        let actual_cloud =
                            state.table.proc(pid).is_some_and(|p| p.cred.cloud_access);
                        (rev, next_local_id, cur_cg, actual_cloud, hydrated_pids)
                    })
                }
            }
        };
        let (revoked, local_id, active_cg, actual_cloud, hydrated_pids) = match bind_res {
            Ok(tuple) => tuple,
            Err(err) => {
                revoke_remote_tokens_state(&self.state, vec![rem.token]).await;
                return Err(fail(err));
            }
        };
        let _ = self.proc_set_creds(
            pid,
            local_id.id,
            local_id.group,
            local_id.groups.into_iter().collect(),
            Some(rem.token.clone()),
            actual_cloud,
        );
        for hpid in hydrated_pids {
            if hpid != pid {
                self.sync_vfs_proc_creds(hpid);
            }
        }
        revoke_remote_tokens_state(&self.state, revoked).await;
        if active_cg != cgroup {
            self.sync_remote_io_quota_for_token(&rem.token, &active_cg)
                .await;
        }
        Ok(json!({
            "uid": rem.uid,
            "gid": rem.gid,
            "groups": rem.groups,
            "instance_id": rem.instance_id,
            "lineage": rem.lineage,
            "cloud_access": actual_cloud,
            "scope": rem.scope,
        })
        .to_string())
    }

    /// Explicitly attach a remote device driver (`archive`, `media`, `present`, `snd`) into `/dev`
    /// only after authenticating a `ServiceAuth v2` credential whose scope authorizes `driver`
    /// (`docs/architecture/contract.md` §2.7).
    pub async fn attach_remote_device(
        &self,
        driver: &str,
        pid: Option<u32>,
        host: &str,
    ) -> Result<String, JsValue> {
        if !vfs::devfs::REMOTE_DEVICE_DRIVERS.contains(&driver) {
            return Err(fail(Errno::ENODEV.into()));
        }
        let scope_label = if let Some(p) = pid {
            let existing = {
                let state = self.state.borrow();
                let proc = state
                    .table
                    .proc(p)
                    .filter(|pr| pr.state != ProcState::Zombie && pr.owner_host == host)
                    .ok_or_else(|| fail(Errno::ESRCH.into()))?;
                proc.cred.remote.clone()
            };
            let rem = existing.ok_or_else(|| {
                fail(Error::because(
                    Errno::EACCES,
                    "remote device attachment requires a verified remote credential",
                ))
            })?;
            if !rem.scope.allows_device(driver) {
                return Err(fail(Error::because(
                    Errno::EACCES,
                    format!("remote credential scope does not permit /dev/{driver}"),
                )));
            }
            format!("service-auth-v2:{}:{driver}", rem.instance_id)
        } else {
            let (instance_id, host_proof) = ensure_remote_attached_state(&self.state)
                .await
                .map_err(fail)?;
            let req = auth_v2::Request::MintServiceCred(MintServiceCred {
                instance_id: instance_id.clone(),
                host_proof: host_proof.clone(),
                scope: RemoteScope {
                    cloud_fs: false,
                    devices: vec![driver.to_string()],
                    containers: false,
                    relay: false,
                },
                cloud_access: false,
                umask: 0o022,
                cgroup: None,
                generation: None,
                sudo: false,
                rbps: None,
                wbps: None,
            });
            let resp = service_auth_request(&req).await.map_err(fail)?;
            let issued = match resp {
                auth_v2::Response::Cred(c) => c,
                _ => return Err(fail(Errno::EIO.into())),
            };
            if !issued.scope.allows_device(driver) {
                revoke_remote_tokens_state(&self.state, vec![issued.token]).await;
                return Err(fail(Errno::EACCES.into()));
            }
            revoke_remote_tokens_state(&self.state, vec![issued.token]).await;
            format!("service-auth-v2:{instance_id}:{driver}")
        };

        let mode = match driver {
            "archive" | "media" => 0o666,
            _ => 0o755,
        };
        let dev_fs = Rc::clone(&self.vfs_rt.borrow().dev_fs);
        dev_fs
            .attach_remote(driver, mode, &scope_label)
            .map_err(|e| fail(Error::from(e)))?;
        if matches!(driver, "present" | "snd") {
            self.mount_remote_cloud_dev(driver).await;
        }
        self.state
            .borrow_mut()
            .attached_devices
            .insert(driver.to_string(), scope_label.clone());
        Ok(json!({ "driver": driver, "attached": true, "scope": scope_label }).to_string())
    }

    /// Detach a previously attached remote device driver from `/dev`.
    pub fn detach_remote_device(&self, driver: &str) -> Result<(), JsValue> {
        self.unmount_remote_cloud_dev(driver);
        let dev_fs = Rc::clone(&self.vfs_rt.borrow().dev_fs);
        dev_fs
            .detach_remote(driver)
            .map_err(|e| fail(Error::from(e)))?;
        self.state.borrow_mut().attached_devices.remove(driver);
        Ok(())
    }

    /// Cleanly detach this instance from `ServiceAuth v2`, revoking all remote credentials and
    /// releasing its host fence immediately.
    pub async fn detach_instance(&self) -> Result<String, JsValue> {
        let (attached, instance_id, host_proof) = {
            let s = self.state.borrow();
            (
                s.remote_attached,
                s.instance_id.clone(),
                s.host_proof.clone(),
            )
        };
        if !attached {
            self.detach_all_remote_devices();
            return Ok(json!({ "detached": 0 }).to_string());
        }
        let resp = service_auth_request(&auth_v2::Request::DetachInstance(DetachInstance {
            instance_id,
            host_proof,
        }))
        .await
        .map_err(fail)?;
        let affected: Vec<(u32, Identity)> = {
            let mut s = self.state.borrow_mut();
            s.remote_attached = false;
            s.pending_revocations.clear();
            let mut list = Vec::new();
            for pid in s.table.all_pids() {
                if let Some(p) = s.table.proc(pid)
                    && p.state != ProcState::Zombie
                    && (p.cred.remote.is_some() || p.cred.cloud_access)
                {
                    list.push((pid, p.cred.identity.clone()));
                }
            }
            let tokens = s.table.active_remote_tokens();
            for tok in tokens {
                s.table.drop_revoked_remote_token(&tok);
            }
            for &(pid, _) in &list {
                let _ = s.table.clear_remote_access(pid);
            }
            list
        };
        for (pid, id) in affected {
            let _ = self.proc_set_creds(
                pid,
                id.id,
                id.group,
                id.groups.into_iter().collect(),
                None,
                false,
            );
        }
        self.detach_all_remote_devices();
        to_json(&resp)
    }

    /// Renew this instance's remote lease and active tokens via `ServiceAuth v2` (chunked at
    /// `TOKENS_MAX`; no-op with 0 network requests when `!remote_attached`).
    pub async fn renew_instance(&self) -> Result<String, JsValue> {
        let (attached, instance_id, host_proof, active_tokens, pending) = {
            let mut s = self.state.borrow_mut();
            if !s.remote_attached {
                return Ok(json!({ "attached": false }).to_string());
            }
            let pending = std::mem::take(&mut s.pending_revocations);
            (
                true,
                s.instance_id.clone(),
                s.host_proof.clone(),
                s.table.active_remote_tokens(),
                pending,
            )
        };
        if !attached {
            return Ok(json!({ "attached": false }).to_string());
        }
        if !pending.is_empty() {
            revoke_remote_tokens_state(&self.state, pending).await;
        }
        let mut all_revoked: Vec<String> = Vec::new();
        let mut last_lease = auth_v2::INSTANCE_LEASE_SECONDS;
        let chunks: Vec<Vec<String>> = if active_tokens.is_empty() {
            vec![Vec::new()]
        } else {
            active_tokens
                .chunks(auth_v2::TOKENS_MAX)
                .map(|c| c.to_vec())
                .collect()
        };
        for batch in chunks {
            let resp = service_auth_request(&auth_v2::Request::RenewInstance(RenewInstance {
                instance_id: instance_id.clone(),
                host_proof: host_proof.clone(),
                active_tokens: batch,
            }))
            .await
            .map_err(fail)?;
            if let auth_v2::Response::Renewed(res) = resp {
                last_lease = res.lease_seconds;
                all_revoked.extend(res.revoked);
            }
        }
        if !all_revoked.is_empty() {
            let affected: Vec<(u32, Identity)> = {
                let mut state = self.state.borrow_mut();
                let mut out = Vec::new();
                for tok in &all_revoked {
                    for pid in state.table.all_pids() {
                        if let Some(p) = state.table.proc(pid)
                            && p.cred.remote.as_ref().map(|r| r.token.as_str())
                                == Some(tok.as_str())
                        {
                            out.push((pid, p.cred.identity.clone()));
                        }
                    }
                    state.table.drop_revoked_remote_token(tok);
                }
                out
            };
            for (pid, id) in affected {
                let _ = self.proc_set_creds(
                    pid,
                    id.id,
                    id.group,
                    id.groups.into_iter().collect(),
                    None,
                    false,
                );
            }
        }
        to_json(&auth_v2::Response::Renewed(auth_v2::RenewResult {
            version: auth_v2::VERSION,
            lease_seconds: last_lease,
            revoked: all_revoked,
        }))
    }
}

impl Kernel {
    pub(crate) fn detach_all_remote_devices(&self) {
        let drivers: Vec<String> = self
            .state
            .borrow_mut()
            .attached_devices
            .keys()
            .cloned()
            .collect();
        self.state.borrow_mut().attached_devices.clear();
        let dev_fs = Rc::clone(&self.vfs_rt.borrow().dev_fs);
        for driver in drivers {
            self.unmount_remote_cloud_dev(&driver);
            let _ = dev_fs.detach_remote(&driver);
        }
    }

    pub(crate) fn sync_vfs_proc_creds(&self, pid: u32) {
        let info = {
            let state = self.state.borrow();
            state.table.proc(pid).map(|p| {
                (
                    p.cred.identity.clone(),
                    p.cred.remote.as_ref().map(|r| r.token.clone()),
                    p.cred.cloud_access,
                )
            })
        };
        if let Some((id, tok, cloud)) = info {
            let _ = self.proc_set_creds(
                pid,
                id.id,
                id.group,
                id.groups.into_iter().collect(),
                tok,
                cloud,
            );
        }
    }
    pub(crate) fn apply_account_update(&self, account: LocalAccount) {
        let uid = account.uid;
        let gid = account.gid;
        let user = account.user.clone();
        let group = account.group.clone();
        let hydrated_pids = self.state.borrow_mut().sync_account(account);
        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.root_cloud.clear_cached_account_names();
            if !user.is_empty() {
                rt.uid_names.insert(uid, user);
            }
            if !group.is_empty() {
                rt.gid_names.insert(gid, group);
            }
        }
        for pid in hydrated_pids {
            self.sync_vfs_proc_creds(pid);
        }
    }

    pub(crate) async fn eval_local_process_call(
        &self,
        pid: u32,
        host: &str,
        call: Call,
    ) -> std::result::Result<Value, Error> {
        match call {
            Call::Getpid => {
                let state = self.state.borrow();
                let proc = state
                    .table
                    .proc(pid)
                    .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                    .ok_or(Errno::ESRCH)?;
                Ok(json!({ "pid": proc.pid, "ppid": proc.ppid }))
            }
            Call::Getpgid { pid: target } => {
                let state = self.state.borrow();
                let _pgid = state.table.getpgid(host, pid, target)?;
                let target_pid = if target == 0 { pid } else { target as u32 };
                let p = state.table.proc(target_pid).ok_or(Errno::ESRCH)?;
                Ok(json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "pgid": p.pgid,
                    "sid": p.sid,
                }))
            }
            Call::Getsid { pid: target } => {
                let state = self.state.borrow();
                let _sid = state.table.getsid(host, pid, target)?;
                let target_pid = if target == 0 { pid } else { target as u32 };
                let p = state.table.proc(target_pid).ok_or(Errno::ESRCH)?;
                Ok(json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "pgid": p.pgid,
                    "sid": p.sid,
                }))
            }
            Call::Setpgid { pid: target, pgid } => {
                let mut state = self.state.borrow_mut();
                state.table.setpgid(host, pid, target, pgid)?;
                let target_pid = if target == 0 { pid } else { target as u32 };
                let p = state.table.proc(target_pid).ok_or(Errno::ESRCH)?;
                Ok(json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "pgid": p.pgid,
                    "sid": p.sid,
                }))
            }
            Call::Setsid => {
                let mut state = self.state.borrow_mut();
                let sid = state.table.setsid(host, pid)?;
                let p = state.table.proc(pid).ok_or(Errno::ESRCH)?;
                Ok(json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "pgid": p.pgid,
                    "sid": sid,
                }))
            }
            Call::Prctl { option, value } => {
                let res = self
                    .state
                    .borrow_mut()
                    .table
                    .prctl(host, pid, option, value)?;
                Ok(json!(res))
            }
            Call::ProcStopped { signal } => {
                self.state
                    .borrow_mut()
                    .table
                    .report_stopped(host, pid, signal)?;
                Ok(Value::Null)
            }
            Call::Waitpid {
                pid: selector,
                options,
            } => {
                let mut state = self.state.borrow_mut();
                match state.table.waitpid(host, pid, selector, options)? {
                    WaitOutcome::Reaped(proc) => {
                        state.proc_account_epoch.remove(&proc.pid);
                        if pid == INIT {
                            state.init_state.reaped();
                        }
                        let code = if proc.signal.is_some() {
                            128 + i32::from(proc.signal.unwrap_or(0))
                        } else {
                            (proc.status >> 8) & 0xff
                        };
                        Ok(json!({
                            "pid": proc.pid,
                            "ppid": pid,
                            "status": proc.status,
                            "code": code,
                            "signal": proc.signal,
                        }))
                    }
                    WaitOutcome::Event { pid: cpid, status } => Ok(json!({
                        "pid": cpid,
                        "ppid": pid,
                        "status": status,
                        "stopped": status != 0xffff,
                        "continued": status == 0xffff,
                    })),
                    WaitOutcome::Pending => {
                        if options & kernel::proc_table::WNOHANG != 0 {
                            Ok(json!({ "nothing": true }))
                        } else {
                            Err(Errno::EAGAIN.into())
                        }
                    }
                }
            }
            Call::CgroupCreate {
                path,
                controllers,
                lifetime,
            } => {
                let mut state = self.state.borrow_mut();
                let cred = state
                    .table
                    .proc(pid)
                    .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                    .ok_or(Errno::ESRCH)?
                    .cred
                    .identity
                    .clone();
                state.table.cgroup_create(
                    &cred,
                    Some(pid),
                    &path,
                    controllers.as_deref(),
                    lifetime,
                )?;
                Ok(Value::Null)
            }
            Call::CgroupRemove { path } => {
                let mut state = self.state.borrow_mut();
                let cred = state
                    .table
                    .proc(pid)
                    .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                    .ok_or(Errno::ESRCH)?
                    .cred
                    .identity
                    .clone();
                state.table.cgroup_remove(&cred, &path)?;
                Ok(Value::Null)
            }
            Call::CgroupSet { path, key, value } => {
                let (deliveries, revoked, norm) = {
                    let mut state = self.state.borrow_mut();
                    let cred = state
                        .table
                        .proc(pid)
                        .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                        .ok_or(Errno::ESRCH)?
                        .cred
                        .identity
                        .clone();
                    let (d, r) = state.table.cgroup_set_with_revocations(
                        &cred,
                        &path,
                        &key,
                        &value,
                        now_secs(),
                    )?;
                    let norm = normalize_cgroup_path(&path).unwrap_or(path);
                    (d, r, norm)
                };
                for d in deliveries {
                    if d.killed {
                        self.cloud_exited(d.pid, None).await;
                    }
                }
                revoke_remote_tokens_state(&self.state, revoked).await;
                if key == "io.max" {
                    self.sync_remote_io_quota_subtree(&norm).await;
                }
                Ok(Value::Null)
            }
            Call::CgroupAttach {
                pid: target_pid,
                path,
            } => {
                let (norm, remote_tok) = {
                    let mut state = self.state.borrow_mut();
                    let cred = state
                        .table
                        .proc(pid)
                        .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                        .ok_or(Errno::ESRCH)?
                        .cred
                        .identity
                        .clone();
                    state.table.cgroup_attach(&cred, target_pid, &path)?;
                    let norm = normalize_cgroup_path(&path).unwrap_or(path);
                    let tok = state
                        .table
                        .proc(target_pid)
                        .and_then(|p| p.cred.remote.as_ref().map(|r| r.token.clone()));
                    (norm, tok)
                };
                if let Some(token) = remote_tok {
                    self.sync_remote_io_quota_for_token(&token, &norm).await;
                }
                Ok(Value::Null)
            }
            Call::CgroupStat { path } => self.state.borrow().table.cgroup_stat(&path),
            Call::CgroupList { path } => {
                let list = self.state.borrow().table.cgroup_list(&path);
                Ok(json!(list))
            }
            _ => Err(Errno::EPERM.into()),
        }
    }

    /// Compute the strictest (minimum finite `rbps`/`wbps`) `io.max` policy across ALL live
    /// processes holding `token` (F3-04: prevents moving one holder to `/user` from clearing a
    /// shared token's active limit).
    fn effective_token_io_quota(
        &self,
        token: &str,
        fallback_cg: &str,
    ) -> (String, kernel::resource::IoLimit) {
        let s = self.state.borrow();
        let mut found_any = false;
        let mut min_read: Option<u64> = None;
        let mut min_write: Option<u64> = None;
        let mut best_cg: Option<String> = None;
        let mut best_restricted = false;

        for pid in s.table.all_pids() {
            let Some(p) = s.table.proc(pid) else {
                continue;
            };
            if p.state == ProcState::Zombie {
                continue;
            }
            if p.cred.remote.as_ref().map(|r| r.token.as_str()) != Some(token) {
                continue;
            }
            found_any = true;
            let lim = s.table.cgroups().effective_io_limit(&p.cgroup);
            if let Some(r) = lim.read {
                min_read = Some(min_read.map_or(r, |cur| cur.min(r)));
            }
            if let Some(w) = lim.write {
                min_write = Some(min_write.map_or(w, |cur| cur.min(w)));
            }
            let is_restricted = lim.read.is_some() || lim.write.is_some();
            let replace = match &best_cg {
                None => true,
                Some(prev) => {
                    (is_restricted && !best_restricted)
                        || (is_restricted == best_restricted && p.cgroup.len() > prev.len())
                }
            };
            if replace {
                best_cg = Some(p.cgroup.clone());
                best_restricted = is_restricted;
            }
        }
        if !found_any {
            let lim = s.table.cgroups().effective_io_limit(fallback_cg);
            return (fallback_cg.to_string(), lim);
        }
        (
            best_cg.unwrap_or_else(|| fallback_cg.to_string()),
            kernel::resource::IoLimit {
                read: min_read,
                write: min_write,
            },
        )
    }

    async fn sync_remote_io_quota_for_token(&self, token: &str, cgroup: &str) {
        let (attached, instance_id, host_proof) = {
            let s = self.state.borrow();
            (
                s.remote_attached,
                s.instance_id.clone(),
                s.host_proof.clone(),
            )
        };
        if !attached || cloudfs::installed("serviceAuthPost").is_err() {
            return;
        }
        let (effective_cg, io) = self.effective_token_io_quota(token, cgroup);
        let _ = service_auth_request(&auth_v2::Request::SetRemoteIoQuota(RemoteIoQuota {
            instance_id,
            host_proof,
            token: token.to_string(),
            cgroup: effective_cg,
            rbps: io.read,
            wbps: io.write,
        }))
        .await;
    }

    async fn sync_remote_io_quota_subtree(&self, cgroup: &str) {
        let targets: Vec<(String, String)> = {
            let s = self.state.borrow();
            if !s.remote_attached {
                return;
            }
            let mut seen = BTreeSet::new();
            let mut out = Vec::new();
            for pid in s.table.all_pids() {
                if let Some(p) = s.table.proc(pid)
                    && p.state != ProcState::Zombie
                    && in_subtree(&p.cgroup, cgroup)
                    && let Some(rem) = &p.cred.remote
                    && seen.insert(rem.token.clone())
                {
                    out.push((rem.token.clone(), p.cgroup.clone()));
                }
            }
            out
        };
        for (token, cg) in targets {
            self.sync_remote_io_quota_for_token(&token, &cg).await;
        }
    }

    /// Local multi-stage `execve` admission + lazy `ServiceAuth v2` credential minting.
    async fn execs_of(
        &self,
        stages: Vec<Value>,
        sudo: bool,
        _seat: &str,
        host: &str,
    ) -> std::result::Result<Vec<std::result::Result<Exec, Error>>, JsValue> {
        let mut admitted: Vec<(std::result::Result<Exec, Error>, Value)> =
            Vec::with_capacity(stages.len());

        for stage in stages {
            let path = stage["path"].as_str().unwrap_or_default().to_string();
            let argv: Vec<String> = match serde_json::from_value(stage["argv"].clone()) {
                Ok(v) => v,
                Err(e) => {
                    admitted.push((
                        Err(Error::because(Errno::EINVAL, format!("argv: {e}"))),
                        stage,
                    ));
                    continue;
                }
            };
            let env: Vec<String> = match serde_json::from_value(stage["env"].clone()) {
                Ok(v) => v,
                Err(e) => {
                    admitted.push((
                        Err(Error::because(Errno::EINVAL, format!("env: {e}"))),
                        stage,
                    ));
                    continue;
                }
            };
            let cwd = stage["cwd"].as_str().unwrap_or("/").to_string();
            let cgroup = stage["cgroup"]
                .as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let runtime = stage["runtime"]
                .as_str()
                .map(str::to_string)
                .or_else(|| Some(kernel::local_cgroups::RESOURCE_CONTRACT.into()));
            let parent_pid = stage["parentPid"].as_u64().map(|p| p as u32);
            let local_exec: Option<LocalExecutable> =
                match serde_json::from_value(stage["local"].clone()) {
                    Ok(v) => v,
                    Err(e) => {
                        admitted.push((
                            Err(Error::because(
                                Errno::EINVAL,
                                format!("local executable: {e}"),
                            )),
                            stage,
                        ));
                        continue;
                    }
                };
            if let Some(le) = &local_exec
                && let Err(err) = validate_local_exec(le)
            {
                admitted.push((Err(err), stage));
                continue;
            }

            let explicit_remote_val = stage.get("remote");
            let remote_explicit_false = explicit_remote_val == Some(&Value::Bool(false));
            let explicit_scope: Option<RemoteScope> = match explicit_remote_val {
                Some(Value::Bool(true)) => Some(RemoteScope::full()),
                Some(Value::Object(_)) => {
                    match serde_json::from_value::<RemoteScope>(
                        explicit_remote_val.unwrap().clone(),
                    ) {
                        Ok(sc) => Some(sc),
                        Err(e) => {
                            admitted.push((
                                Err(Error::because(Errno::EINVAL, format!("remote scope: {e}"))),
                                stage,
                            ));
                            continue;
                        }
                    }
                }
                _ => None,
            };

            let mut cloud_allowed =
                local_exec.as_ref().is_none_or(|l| l.cloud) && !remote_explicit_false;
            let (parent_cred, default_identity, active_login_scope, account_epoch) = {
                let s = self.state.borrow();
                let pcred = parent_pid.and_then(|pp| {
                    s.table
                        .proc(pp)
                        .filter(|p| p.state != ProcState::Zombie && p.owner_host == host)
                        .map(|p| p.cred.clone())
                });
                let sid = stage["sessionId"]
                    .as_str()
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .or_else(|| Some(s.login_session.id.clone()));
                (pcred, s.account.identity(), sid, s.account_epoch)
            };
            if let Some(pp) = parent_pid
                && parent_cred.is_none()
            {
                admitted.push((
                    Err(Error::because(Errno::ESRCH, format!("no process {pp}"))),
                    stage,
                ));
                continue;
            }
            if let Some(pc) = &parent_cred {
                cloud_allowed &= pc.cloud_access;
            }

            let is_cloud_target = (local_exec.as_ref().is_none_or(|l| l.cloud)
                && !is_local_only_path(&path))
                || !is_local_only_path(&cwd);
            let should_mint_remote = cloud_allowed
                && cloudfs::installed("serviceAuthPost").is_ok()
                && (sudo || explicit_scope.is_some() || is_cloud_target);

            let cred_result: std::result::Result<LocalCred, Error> = if let Some(pc) = parent_cred {
                let mut c = pc;
                c.cloud_access &= cloud_allowed;
                if !c.cloud_access {
                    c.remote = None;
                } else if let Some(rem) = &mut c.remote {
                    rem.cloud_access &= cloud_allowed;
                }
                Ok(c)
            } else if should_mint_remote {
                let (signed_in, io_at_mint) = {
                    let s = self.state.borrow();
                    let target_cg = cgroup.as_deref().unwrap_or("/user");
                    (
                        s.account.signed_in,
                        s.table.cgroups().effective_io_limit(target_cg),
                    )
                };
                match ensure_remote_attached_state(&self.state).await {
                    Ok((instance_id, host_proof)) => {
                        let scope = explicit_scope.unwrap_or_else(RemoteScope::full);
                        let req_cloud = cloud_allowed && scope.cloud_fs;
                        match service_auth_request(&auth_v2::Request::MintServiceCred(
                            MintServiceCred {
                                instance_id,
                                host_proof,
                                scope,
                                cloud_access: req_cloud,
                                umask: 0o022,
                                cgroup: cgroup.clone(),
                                generation: None,
                                sudo,
                                rbps: io_at_mint.read,
                                wbps: io_at_mint.write,
                            },
                        ))
                        .await
                        {
                            Ok(auth_v2::Response::Cred(issued)) => {
                                // F3-01: On `!sudo`, NEVER overwrite local `Identity` OR attach a
                                // higher-privilege remote token when remote and local UIDs diverge
                                // (except initial 65534 -> guest hydration, or signed-out guest ->
                                // guest cookie rotation). Keep `sudo: true` remote root identity
                                // for #54 Gate 3b.
                                let guest_cookie_rotated = !signed_in
                                    && os_core::permissions::is_guest_id(default_identity.id)
                                    && os_core::permissions::is_guest_id(issued.uid);
                                if !sudo
                                    && !guest_cookie_rotated
                                    && !lazy_mint_uid_permitted(
                                        default_identity.id,
                                        issued.uid,
                                        signed_in,
                                        false,
                                    )
                                {
                                    revoke_remote_tokens_state(&self.state, vec![issued.token])
                                        .await;
                                    Err(Error::because(
                                        Errno::EACCES,
                                        "remote account identity does not match local account",
                                    ))
                                } else {
                                    let hydrated_pids = if !sudo
                                        && default_identity.id == os_core::permissions::GUEST
                                        && !signed_in
                                        && os_core::permissions::is_guest_id(issued.uid)
                                    {
                                        self.state
                                            .borrow_mut()
                                            .hydrate_guest_account_if_uninitialized(
                                                issued.uid,
                                                issued.gid,
                                                &issued.groups,
                                            )
                                    } else {
                                        Vec::new()
                                    };
                                    for hpid in hydrated_pids {
                                        self.sync_vfs_proc_creds(hpid);
                                    }
                                    let identity = Identity {
                                        id: issued.uid,
                                        group: issued.gid,
                                        groups: issued.groups.iter().copied().collect(),
                                    };
                                    let rem = RemoteCredRef {
                                        token: issued.token,
                                        uid: issued.uid,
                                        gid: issued.gid,
                                        groups: issued.groups,
                                        instance_id: issued.instance_id,
                                        lineage: issued.lineage,
                                        cloud_access: issued.cloud_access && req_cloud,
                                        scope: issued.scope,
                                    };
                                    Ok(LocalCred::with_remote(identity, issued.umask, rem))
                                }
                            }
                            Ok(_) => Err(Error::because(Errno::EIO, "unexpected cred reply")),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => Err(e),
                }
            } else if sudo && cloudfs::installed("serviceAuthPost").is_ok() {
                // `sudo: true` when `!cloud_allowed` still cannot synthesize root locally.
                Err(Error::because(
                    Errno::EPERM,
                    "sudo requires authenticated elevation",
                ))
            } else {
                Ok(LocalCred {
                    identity: default_identity,
                    umask: 0o022,
                    remote: None,
                    cloud_access: cloud_allowed,
                })
            };

            let local_cred = match cred_result {
                Ok(c) => c,
                Err(err) => {
                    admitted.push((Err(err), stage));
                    continue;
                }
            };
            let minted_token = local_cred.remote.as_ref().map(|r| r.token.clone());

            let spawn_res = {
                let mut state = self.state.borrow_mut();
                let spec = SpawnSpec {
                    path: path.clone(),
                    argv,
                    env,
                    cwd: cwd.clone(),
                    cred: local_cred,
                    cgroup: cgroup.clone(),
                    owner_host: host.to_string(),
                    login_scope: active_login_scope,
                    runtime,
                    ppid: parent_pid,
                    pgid: None,
                    sid: None,
                    initial_state: ProcState::Running,
                };
                let res = state.table.spawn(spec, now_secs());
                if let Ok(ref p) = res {
                    state.proc_account_epoch.insert(p.pid, account_epoch);
                }
                res
            };

            match spawn_res {
                Ok(proc) => {
                    let boot_id = self.state.borrow().boot.clone();
                    if let Some(ref rem) = proc.cred.remote {
                        let io = self
                            .state
                            .borrow()
                            .table
                            .cgroups()
                            .effective_io_limit(&proc.cgroup);
                        if io.read.is_some() || io.write.is_some() {
                            self.sync_remote_io_quota_for_token(&rem.token, &proc.cgroup)
                                .await;
                        }
                    }
                    let exec = Exec {
                        pid: proc.pid,
                        boot: Some(boot_id),
                        login_scope: proc.login_scope.clone(),
                        token: proc
                            .cred
                            .remote
                            .as_ref()
                            .map(|r| r.token.clone())
                            .unwrap_or_default(),
                        local: local_exec.as_ref().map(|l| LocalExecutable {
                            digest: l.digest.clone(),
                            size: l.size,
                            cloud: proc.cred.cloud_access,
                        }),
                        fd: None,
                        asset: if local_exec.is_some() {
                            None
                        } else {
                            system_usr_asset(&proc.path)
                        },
                        path: Some(proc.path.clone()),
                        size: local_exec.as_ref().map_or(0, |l| l.size),
                        token_read: None,
                        version: None,
                        cgroup: proc.cgroup.clone(),
                        placement: Placement {
                            cluster: "local".into(),
                            executor: "browser".into(),
                            cgroup: proc.cgroup.clone(),
                        },
                    };
                    admitted.push((Ok(exec), stage));
                }
                Err(err) => {
                    // Failed local admission must never leak a minted remote token.
                    if let Some(tok) = minted_token {
                        revoke_remote_tokens_state(&self.state, vec![tok]).await;
                    }
                    admitted.push((Err(err), stage));
                }
            }
        }

        // Register all admitted stages in `Vfs` locally (ZERO network RPCs).
        let registered: Result<(), JsValue> = async {
            for (res, stage) in &admitted {
                if let Ok(exec) = res {
                    let cwd = stage["cwd"].as_str().unwrap_or("/");
                    let sid = stage["sessionId"].as_str();
                    let (identity, token, cloud_allowed) = {
                        let state = self.state.borrow();
                        let p = state
                            .table
                            .proc(exec.pid)
                            .ok_or_else(|| fail(Errno::ESRCH.into()))?;
                        (
                            p.cred.identity.clone(),
                            p.cred.remote.as_ref().map(|r| r.token.clone()),
                            p.cred.cloud_access,
                        )
                    };
                    if let Some(parent_pid) = stage["parentPid"].as_u64().map(|p| p as u32) {
                        self.proc_fork(parent_pid, exec.pid, 0)?;
                        self.proc_exec_preserve(exec.pid).await?;
                        self.proc_set_creds(
                            exec.pid,
                            identity.id,
                            identity.group,
                            identity.groups.into_iter().collect(),
                            token,
                            cloud_allowed,
                        )?;
                        if !cwd.is_empty() {
                            self.sys_chdir(exec.pid, cwd.to_string()).await?;
                        }
                    } else {
                        let grant_json = stage
                            .get("serviceGrant")
                            .filter(|v| !v.is_null())
                            .map(Value::to_string);
                        self.register_local_exec_in_vfs(
                            exec.pid,
                            INIT,
                            identity,
                            token,
                            cwd,
                            sid,
                            cloud_allowed,
                            grant_json.as_deref(),
                        )
                        .await?;
                    }
                    if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&exec.pid) {
                        meta.supervisor = is_supervisor_image(exec);
                    }
                }
            }
            Ok(())
        }
        .await;

        if let Err(error) = registered {
            for (exec, _) in &admitted {
                if let Ok(exec) = exec {
                    let _ = self.exit(exec.pid, 126, None, host).await;
                    let _ = self.wait(exec.pid, host).await;
                }
            }
            return Err(error);
        }

        Ok(admitted.into_iter().map(|(res, _)| res).collect())
    }
}

fn parse_account_from_value(val: &Value) -> std::result::Result<LocalAccount, JsValue> {
    let uid = val["uid"]
        .as_u64()
        .ok_or_else(|| fail(Error::because(Errno::EINVAL, "account uid required")))?
        as u32;
    let gid = val["gid"].as_u64().unwrap_or(u64::from(uid)) as u32;
    let mut groups: Vec<u32> = val["groups"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u32))
                .collect()
        })
        .unwrap_or_default();
    if !groups.contains(&gid) {
        groups.push(gid);
    }
    let user = val["user"].as_str().map(str::to_string).unwrap_or_else(|| {
        if uid == 0 {
            "root".into()
        } else if uid == 65534 {
            "guest".into()
        } else {
            uid.to_string()
        }
    });
    let group = val["group"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| user.clone());
    let home = val["home"].as_str().map(str::to_string).unwrap_or_else(|| {
        if uid == 0 {
            "/root".into()
        } else {
            "/tmp".into()
        }
    });
    let shell = val["shell"]
        .as_str()
        .map(str::to_string)
        .unwrap_or_else(|| "/usr/bin/dash".into());
    let signed_in = val["signed_in"].as_bool().unwrap_or(uid != 65534);
    Ok(LocalAccount {
        uid,
        gid,
        groups,
        user,
        group,
        home,
        shell,
        signed_in,
    })
}

fn parse<T: serde::de::DeserializeOwned>(
    text: &str,
    what: &str,
) -> std::result::Result<T, JsValue> {
    serde_json::from_str(text)
        .map_err(|error| fail(Error::because(Errno::EINVAL, format!("{what}: {error}"))))
}

fn from_value<T: serde::de::DeserializeOwned>(
    value: Value,
    what: &str,
) -> std::result::Result<T, JsValue> {
    serde_json::from_value(value)
        .map_err(|error| fail(Error::because(Errno::EIO, format!("{what}: {error}"))))
}

fn to_json<T: serde::Serialize>(value: &T) -> std::result::Result<String, JsValue> {
    serde_json::to_string(value)
        .map_err(|error| fail(Error::because(Errno::EIO, error.to_string())))
}

/// An error as the page reads it: its errno, and what it says.
pub(crate) fn fail(error: Error) -> JsValue {
    JsValue::from_str(
        &json!({
            "errno": error.errno,
            "detail": error.detail,
        })
        .to_string(),
    )
}

#[cfg(test)]
mod tests {
    /// All three Contract v2 boundaries (`HostAdapter v2`, `ServiceAuth v2`, `Release v2`) match
    /// `abi::contract` across `#54` (L3a), `#77` (L2.5a), and `#78` (L2.5b).
    #[test]
    fn versions_match_the_contract() {
        assert_eq!(
            super::VERSION,
            abi::contract::HOST_ADAPTER_VERSION.to_string()
        );
        assert_eq!(abi::contract::HOST_ADAPTER_VERSION, 2);
        assert_eq!(abi::auth_v2::VERSION, abi::contract::SERVICE_AUTH_VERSION);
        assert_eq!(image::PROTOCOL, abi::contract::RELEASE_VERSION);
        assert_eq!(image::PROTOCOL, 2);
        assert_eq!(image::HOST_ADAPTER, abi::contract::HOST_ADAPTER_VERSION);
    }

    #[test]
    fn lazy_mint_refuses_guest_to_root_or_user_escalation() {
        let guest = os_core::permissions::GUEST;
        let session_guest = os_core::permissions::GUEST_UID_MIN + 7;
        // Exact match always allowed.
        assert!(super::lazy_mint_uid_permitted(0, 0, true, false));
        assert!(super::lazy_mint_uid_permitted(1000, 1000, true, false));
        assert!(super::lazy_mint_uid_permitted(guest, guest, false, false));
        // Uninitialized local guest may bind to a per-session guest uid while unsigned-in.
        assert!(super::lazy_mint_uid_permitted(
            guest,
            session_guest,
            false,
            false
        ));
        // Guest MUST NEVER rebind to root (0) or a real user (1000), even if !signed_in.
        assert!(!super::lazy_mint_uid_permitted(guest, 0, false, false));
        assert!(!super::lazy_mint_uid_permitted(guest, 1000, false, false));
        assert!(!super::lazy_mint_uid_permitted(guest, 0, true, false));
        assert!(!super::lazy_mint_uid_permitted(
            guest,
            session_guest,
            true,
            false
        ));
        assert!(!super::lazy_mint_uid_permitted(
            guest,
            session_guest,
            false,
            true
        ));
        // Cross-uid mismatch between real accounts or guest->root is always refused.
        assert!(!super::lazy_mint_uid_permitted(1000, 0, true, false));
        assert!(!super::lazy_mint_uid_permitted(
            session_guest,
            0,
            false,
            false
        ));
    }

    #[test]
    fn guest_account_hydration_updates_account_login_session_and_inflight_procs() {
        let mut table = super::LocalProcessTable::new(
            super::InstanceIdentity {
                instance: "inst-test".into(),
                host: "browser".into(),
            },
            100,
        );
        let host = "host-local";
        let _ = table.boot_init(host, 100);
        let p = table
            .spawn(
                super::SpawnSpec::new(
                    "/usr/bin/sh",
                    super::LocalCred::local_only(super::LocalAccount::default().identity(), 0o022),
                    host,
                ),
                101,
            )
            .expect("spawn local guest");
        let mut proc_epochs = std::collections::HashMap::new();
        proc_epochs.insert(p.pid, 1);
        let mut state = super::State {
            instance_id: "inst-test".into(),
            namespace: "ns-test".into(),
            host_proof: String::new(),
            boot: "boot-1".into(),
            table,
            account: super::LocalAccount::default(),
            account_epoch: 1,
            proc_account_epoch: proc_epochs,
            remote_attached: false,
            host_epoch: 0,
            pending_revocations: Vec::new(),
            attached_devices: std::collections::BTreeMap::new(),
            init_state: super::Init::new("boot-1".into(), 100),
            login_session: super::LoginSession::new(
                "inst-test:s1".into(),
                os_core::permissions::GUEST,
                86_500,
                100,
            ),
            login_profiles: std::collections::BTreeMap::new(),
            seat_policies: std::collections::BTreeMap::new(),
            boot_seq: 1,
            session_seq: 1,
        };
        let session_guest = os_core::permissions::GUEST_UID_MIN + 42;
        // Must ignore root/non-guest UIDs.
        assert!(
            state
                .hydrate_guest_account_if_uninitialized(0, 0, &[0])
                .is_empty()
        );
        assert_eq!(state.account.uid, os_core::permissions::GUEST);
        // Hydrating 65534 -> session guest updates account, login_session, and in-flight proc
        // without bumping account_epoch, allowing reap_init_child to succeed!
        let hydrated = state.hydrate_guest_account_if_uninitialized(
            session_guest,
            session_guest,
            &[session_guest],
        );
        assert_eq!(hydrated, vec![p.pid]);
        assert_eq!(state.account.uid, session_guest);
        assert_eq!(state.login_session.uid, session_guest);
        assert_eq!(state.account_epoch, 1);
        assert_eq!(
            state.table.proc(p.pid).unwrap().cred.identity.id,
            session_guest
        );
        state.table.exit(host, p.pid, 0, None, 102).unwrap();
        let caller = state.account.identity();
        assert!(state.table.reap_init_child(host, &caller, p.pid).is_ok());
    }
}
