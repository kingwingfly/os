use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use os_core::permissions::{Identity, Session, Store, User, is_guest_id};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use worker::*;
pub const COOKIE: &str = "os_session";
/// A browser signed out, each its own session, all acting as guest: what keeps its descriptors.
pub const GUEST_COOKIE: &str = "os_guest";
pub const TTL: u64 = 8 * 60 * 60;
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inline_js = "
export function randomToken() { const bytes=crypto.getRandomValues(new Uint8Array(32)); return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''); }
")]
extern "C" {
    #[wasm_bindgen(js_name=randomToken)]
    fn random_token_js() -> String;
}
#[wasm_bindgen(inline_js = "
export async function passwordKdf(password,salt) { const e=new TextEncoder(); const key=await crypto.subtle.importKey('raw',e.encode(password),'PBKDF2',false,['deriveBits']); const hash=await crypto.subtle.deriveBits({name:'PBKDF2',salt:e.encode(salt),iterations:100000,hash:'SHA-256'},key,256); return Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join(''); }
")]
extern "C" {
    #[wasm_bindgen(catch,js_name=passwordKdf)]
    async fn password_kdf(password: &str, salt: &str) -> std::result::Result<JsValue, JsValue>;
}
pub fn random_token() -> String {
    #[cfg(target_arch = "wasm32")]
    {
        random_token_js()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut h = Sha256::new();
        h.update(n.to_le_bytes());
        h.update(now_ns.to_le_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }
}
pub fn now() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        Date::now().as_millis() / 1000
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000)
    }
}
/// Seconds since 1970 and nanoseconds past them, to the millisecond the clock gives.
pub fn clock() -> (u64, u32) {
    #[cfg(target_arch = "wasm32")]
    {
        let ms = Date::now().as_millis();
        (ms / 1000, (ms % 1000) as u32 * 1_000_000)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let dur = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        (dur.as_secs(), dur.subsec_nanos())
    }
}
/// The token of the cookie `name` the request carries, if it is one (64 hexadecimal digits).
fn raw_cookie(req: &Request, name: &str) -> Option<String> {
    let cookies = req.headers().get("Cookie").ok()??;
    let token = cookies
        .split(';')
        .map(str::trim)
        .find_map(|s| s.strip_prefix(&format!("{name}=")))?;
    Some(token.to_string())
}
fn valid_token(token: String) -> Option<String> {
    (token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())).then_some(token)
}
pub fn cookie_token(req: &Request, name: &str) -> Option<String> {
    raw_cookie(req, name).and_then(valid_token)
}
/// The stored key of the request's session token: its hash, so stored keys cannot sign in.
pub fn token_key(req: &Request) -> Option<String> {
    cookie_token(req, COOKIE).map(|token| token_hash(&token))
}
/// A token as stored: its SHA-256, so a store's contents cannot be replayed as a capability.
pub fn token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}
/// The key of the request's signed-out browser (`GUEST_COOKIE`), which no session's key can be.
pub fn guest_key(req: &Request) -> Option<String> {
    cookie_token(req, GUEST_COOKIE).map(|token| {
        format!(
            "guest.{}",
            URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
        )
    })
}
/// The session a request is of, as its descriptors are kept: the signed-in one, `key`, or,
/// signed out, the browser's own, `guest`.
pub fn sid(c: &impl Store, key: Option<&str>, guest: Option<&str>) -> Option<String> {
    match live_session(c, key) {
        Some(_) => key.map(str::to_string),
        None => guest.map(str::to_string),
    }
}
/// The cookie that makes a signed-out browser a session of its own.
pub fn guest_cookie(https: bool, token: &str) -> String {
    format!(
        "{GUEST_COOKIE}={token}; Path=/api; HttpOnly; SameSite=Strict; Max-Age={}{}",
        400 * 24 * 60 * 60,
        if https { "; Secure" } else { "" }
    )
}
fn live_session(c: &impl Store, key: Option<&str>) -> Option<Session> {
    key.and_then(|k| c.session(k)).filter(|s| s.expires > now())
}
pub fn identity(c: &impl Store, key: Option<&str>) -> Identity {
    live_session(c, key)
        .and_then(|s| c.user_by_id(s.user))
        .filter(|(_, u)| !u.locked)
        .map(|(_, u)| Identity::of(&u))
        .unwrap_or_else(Identity::guest)
}
/// Who the request is: its signed-in account, or, signed out, the browser's own guest account
/// (`guest-<uuid>`), made if this browser has not been here. A locked account is nobody's.
pub fn identity_of(c: &mut crate::db::Db, key: Option<&str>, guest: Option<&str>) -> Identity {
    let who = identity(c, key);
    if !is_guest_id(who.id) {
        return who;
    }
    guest
        .map(|guest| c.guest_identity(guest, now()))
        .unwrap_or_else(Identity::guest)
}
/// The same, under sudo when `requested` and the account may (a signed-in wheel member's
/// timestamp). A guest is no wheel member: its sudo is refused, never run as another identity.
pub fn elevated_of(
    c: &mut crate::db::Db,
    key: Option<&str>,
    guest: Option<&str>,
    requested: bool,
) -> std::result::Result<Identity, String> {
    if !requested {
        return Ok(identity_of(c, key, guest));
    }
    elevated(c, key, true)
}
/// Whether the request's session is signed in (not a signed-out browser's guest).
pub fn signed_in(c: &impl Store, key: Option<&str>) -> bool {
    live_session(c, key).is_some()
}
pub fn elevated(
    c: &impl Store,
    key: Option<&str>,
    requested: bool,
) -> std::result::Result<Identity, String> {
    let who = identity(c, key);
    if !requested || who.id == 0 {
        return Ok(who);
    }
    if !c.can_sudo(&who) {
        return Err("Current account is not in the wheel group".into());
    }
    if !live_session(c, key).is_some_and(|s| s.sudo_until > now()) {
        return Err("sudo requires reauthentication with your own password".into());
    }
    Ok(Identity::root())
}
pub fn cookie(https: bool, token: &str, age: u64) -> String {
    format!(
        "{COOKIE}={token}; Path=/api; HttpOnly; SameSite=Strict; Max-Age={age}{}",
        if https { "; Secure" } else { "" }
    )
}
pub fn session_view(c: &impl Store, key: Option<&str>) -> Value {
    let who = identity(c, key);
    let home = c
        .user_by_id(who.id)
        .map(|(_, u)| u.home)
        .unwrap_or_else(|| "/".into());
    json!({"writable":signed_in(c,key),"authenticated":signed_in(c,key),"username":c.username(who.id),"uid":who.id,"group":c.groupname(who.group),"groups":who.groups.iter().map(|g|c.groupname(*g)).collect::<Vec<_>>(),"home":home,"can_sudo":c.can_sudo(&who),"sudo_active":who.id==0||live_session(c,key).is_some_and(|s|s.sudo_until>now())})
}
fn session_reply_body(c: &impl Store, uid: u32) -> Value {
    let (who, home) = match c.user_by_id(uid) {
        Some((_, u)) => (Identity::of(&u), u.home),
        None => (
            Identity {
                id: uid,
                group: uid,
                groups: [uid].into(),
            },
            String::new(),
        ),
    };
    let groups: Vec<u32> = who.groups.iter().copied().collect();
    json!({
        "writable": true,
        "username": c.username(uid),
        "uid": uid,
        "gid": who.group,
        "groups": groups,
        "home": home,
    })
}
/// Replace the request's session with a new one for `uid`, returning the reply and the new
/// token for the cookie.
pub fn issue(c: &mut impl Store, key: Option<&str>, uid: u32) -> (Value, String) {
    if let Some(key) = key {
        c.delete_session(key);
    }
    c.delete_expired_sessions(now());
    let token = random_token();
    let key = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    c.set_session(
        &key,
        &Session {
            user: uid,
            expires: now() + TTL,
            sudo_until: 0,
        },
    );
    (session_reply_body(c, uid), token)
}
/// Renew an already-live session for the exact same `uid` (preserving the shared browser cookie
/// and its `Machine`/`vfs_sessions` namespace when a second tab signs into Cloud as the same
/// account after re-verifying credentials), or issue a brand-new session when signed out,
/// expired, or switching accounts.
pub fn renew_or_issue(
    c: &mut impl Store,
    existing_token: Option<&str>,
    key: Option<&str>,
    uid: u32,
) -> (Value, String) {
    if let (Some(token), Some(key)) = (existing_token, key)
        && token_hash(token) == key
        && live_session(c, Some(key)).is_some_and(|s| s.user == uid)
    {
        c.delete_expired_sessions(now());
        c.set_session(
            key,
            &Session {
                user: uid,
                expires: now() + TTL,
                sudo_until: 0,
            },
        );
        return (session_reply_body(c, uid), token.to_string());
    }
    issue(c, key, uid)
}
pub fn password_valid(password: &str) -> bool {
    password.chars().count() >= 12 && password.len() <= 512
}
pub async fn hash(password: &str, salt: &str, env: &Env) -> Result<String> {
    // A server-side pepper is independent of per-user salts and never stored in the catalog.
    let pepper = env.secret("SESSION_SECRET")?.to_string();
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper.as_bytes()).unwrap();
    mac.update(password.as_bytes());
    let input = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    password_kdf(&input, salt)
        .await
        .map_err(Error::from)?
        .as_string()
        .ok_or_else(|| Error::RustError("KDF returned no string".into()))
}
pub async fn verify(password: &str, user: &User, env: &Env) -> Result<bool> {
    if password.len() > 512 {
        return Ok(false);
    }
    let actual = hash(password, &user.salt, env).await?;
    Ok(!user.hash.is_empty()
        && actual.len() == user.hash.len()
        && actual
            .bytes()
            .zip(user.hash.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0)
}
pub async fn limited(req: &Request, env: &Env, action: &str) -> Result<bool> {
    limited_by(req, env, "LOGIN_LIMIT", action).await
}
/// Whether the client of `req` did `action` too often, as the rate limiter `binding` counts.
pub async fn limited_by(req: &Request, env: &Env, binding: &str, action: &str) -> Result<bool> {
    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "local".into());
    Ok(!env
        .rate_limiter(binding)?
        .limit(format!("{action}:{ip}"))
        .await?
        .success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use os_core::permissions::{Id, Node};
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Default)]
    struct MockStore {
        users: BTreeMap<String, User>,
        groups: BTreeMap<String, u32>,
        sessions: BTreeMap<String, Session>,
        next_uid: u32,
        next_gid: u32,
    }

    impl Store for MockStore {
        fn node(&self, _path: &str) -> Option<Node> {
            None
        }
        fn children(&self, _path: &str) -> Vec<(String, Node)> {
            Vec::new()
        }
        fn subtree(&self, _path: &str) -> Vec<(String, Node)> {
            Vec::new()
        }
        fn set_node(&mut self, _path: &str, _node: &Node) {}
        fn delete_node(&mut self, _path: &str) {}
        fn xattrs(&self, _ino: u64) -> BTreeMap<String, Vec<u8>> {
            BTreeMap::new()
        }
        fn set_xattrs(&mut self, _ino: u64, _attrs: &BTreeMap<String, Vec<u8>>) {}
        fn user(&self, name: &str) -> Option<User> {
            self.users.get(name).cloned()
        }
        fn user_by_id(&self, id: u32) -> Option<(String, User)> {
            self.users
                .iter()
                .find(|(_, u)| u.id == id)
                .map(|(n, u)| (n.clone(), u.clone()))
        }
        fn users(&self) -> Vec<(String, User)> {
            self.users
                .iter()
                .map(|(n, u)| (n.clone(), u.clone()))
                .collect()
        }
        fn set_user(&mut self, name: &str, user: &User) {
            self.users.insert(name.to_owned(), user.clone());
        }
        fn delete_user(&mut self, name: &str) {
            self.users.remove(name);
        }
        fn group(&self, name: &str) -> Option<u32> {
            self.groups.get(name).copied()
        }
        fn group_name(&self, id: u32) -> Option<String> {
            self.groups
                .iter()
                .find(|(_, g)| **g == id)
                .map(|(n, _)| n.clone())
        }
        fn groups(&self) -> Vec<(String, u32)> {
            self.groups.iter().map(|(n, g)| (n.clone(), *g)).collect()
        }
        fn set_group(&mut self, name: &str, id: u32) {
            self.groups.insert(name.to_owned(), id);
        }
        fn delete_group(&mut self, name: &str) {
            self.groups.remove(name);
        }
        fn session(&self, key: &str) -> Option<Session> {
            self.sessions.get(key).cloned()
        }
        fn set_session(&mut self, key: &str, session: &Session) {
            self.sessions.insert(key.to_owned(), session.clone());
        }
        fn delete_session(&mut self, key: &str) {
            self.sessions.remove(key);
        }
        fn delete_sessions(&mut self, user: u32) {
            self.sessions.retain(|_, s| s.user != user);
        }
        fn delete_expired_sessions(&mut self, ts: u64) {
            self.sessions.retain(|_, s| s.expires > ts);
        }
        fn next_id(&mut self, kind: Id) -> u32 {
            match kind {
                Id::User => {
                    self.next_uid += 1;
                    self.next_uid
                }
                Id::Group => {
                    self.next_gid += 1;
                    self.next_gid
                }
            }
        }
    }

    #[test]
    fn issue_includes_numeric_uid_gid_and_groups_and_replaces_session() {
        let mut store = MockStore::default();
        store.set_group("alice", 1005);
        store.set_group("wheel", 10);
        store.set_group("devs", 2000);
        store.set_user(
            "alice",
            &User {
                id: 1005,
                group: 1005,
                groups: BTreeSet::from([10, 2000]),
                home: "/home/alice".into(),
                locked: false,
                salt: "salt".into(),
                hash: "hash".into(),
            },
        );
        store.set_session(
            "old-key",
            &Session {
                user: 999,
                expires: now() + 3600,
                sudo_until: 0,
            },
        );

        let (body, token) = issue(&mut store, Some("old-key"), 1005);
        assert_eq!(token.len(), 64);
        assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(body["writable"], json!(true));
        assert_eq!(body["username"], json!("alice"));
        assert_eq!(body["uid"], json!(1005));
        assert_eq!(body["gid"], json!(1005));
        assert_eq!(body["groups"], json!([10, 1005, 2000]));
        assert_eq!(body["home"], json!("/home/alice"));

        assert!(store.session("old-key").is_none());
        let stored = store.session(&token_hash(&token)).expect("new session");
        assert_eq!(stored.user, 1005);
        assert_eq!(stored.sudo_until, 0);
        assert!(stored.expires > now());
    }

    #[test]
    fn renew_or_issue_preserves_live_same_user_and_rotates_on_expired_cross_user_or_mismatch() {
        let mut store = MockStore::default();
        for (name, uid) in [("alice", 1005u32), ("bob", 1006u32)] {
            store.set_group(name, uid);
            store.set_user(
                name,
                &User {
                    id: uid,
                    group: uid,
                    groups: BTreeSet::new(),
                    home: format!("/home/{name}"),
                    locked: false,
                    salt: "salt".into(),
                    hash: "hash".into(),
                },
            );
        }

        // 1. Live same-user session preserves token, extends expires, and resets sudo_until to 0.
        let tok_a = "a".repeat(64);
        let key_a = token_hash(&tok_a);
        let initial_exp = now() + 60;
        store.set_session(
            &key_a,
            &Session {
                user: 1005,
                expires: initial_exp,
                sudo_until: now() + 300,
            },
        );
        let (body, returned) = renew_or_issue(&mut store, Some(&tok_a), Some(&key_a), 1005);
        assert_eq!(returned, tok_a);
        assert_eq!(body["uid"], json!(1005));
        let renewed = store.session(&key_a).expect("renewed session");
        assert_eq!(renewed.user, 1005);
        assert_eq!(renewed.sudo_until, 0);
        assert!(renewed.expires > initial_exp);

        // 2. Mismatched token/key falls back to issuing a fresh session.
        let (_, mismatch_tok) =
            renew_or_issue(&mut store, Some(&"b".repeat(64)), Some(&key_a), 1005);
        assert_ne!(mismatch_tok, tok_a);
        assert!(store.session(&key_a).is_none());

        // 3. Cross-user login deletes the old session and issues a new token.
        let key_m = token_hash(&mismatch_tok);
        let (_, bob_tok) = renew_or_issue(&mut store, Some(&mismatch_tok), Some(&key_m), 1006);
        assert_ne!(bob_tok, mismatch_tok);
        assert!(store.session(&key_m).is_none());
        assert_eq!(store.session(&token_hash(&bob_tok)).unwrap().user, 1006);

        // 4. Expired same-user session rotates to a fresh token.
        let tok_exp = "c".repeat(64);
        let key_exp = token_hash(&tok_exp);
        store.set_session(
            &key_exp,
            &Session {
                user: 1006,
                expires: now().saturating_sub(10),
                sudo_until: 0,
            },
        );
        let (_, rotated_tok) = renew_or_issue(&mut store, Some(&tok_exp), Some(&key_exp), 1006);
        assert_ne!(rotated_tok, tok_exp);
        assert!(store.session(&key_exp).is_none());
        assert_eq!(store.session(&token_hash(&rotated_tok)).unwrap().user, 1006);
    }
}
