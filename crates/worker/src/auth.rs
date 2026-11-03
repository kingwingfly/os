use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use terminal_worker_core::permissions::{GUEST, Identity, Session, Store, User};
use wasm_bindgen::prelude::*;
use worker::*;
pub const COOKIE: &str = "terminal_session";
/// A browser signed out, each its own session, all acting as guest: what keeps its descriptors.
pub const GUEST_COOKIE: &str = "terminal_guest";
pub const TTL: u64 = 8 * 60 * 60;
#[wasm_bindgen(inline_js = "
export function randomToken() { const bytes=crypto.getRandomValues(new Uint8Array(32)); return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join(''); }
export async function passwordKdf(password,salt) { const e=new TextEncoder(); const key=await crypto.subtle.importKey('raw',e.encode(password),'PBKDF2',false,['deriveBits']); const hash=await crypto.subtle.deriveBits({name:'PBKDF2',salt:e.encode(salt),iterations:100000,hash:'SHA-256'},key,256); return Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join(''); }
")]
extern "C" {
    #[wasm_bindgen(js_name=randomToken)]
    pub fn random_token() -> String;
    #[wasm_bindgen(catch,js_name=passwordKdf)]
    async fn password_kdf(password: &str, salt: &str) -> std::result::Result<JsValue, JsValue>;
}
pub fn now() -> u64 {
    Date::now().as_millis() / 1000
}
/// Seconds since 1970 and nanoseconds past them, to the millisecond the clock gives.
pub fn clock() -> (u64, u32) {
    let ms = Date::now().as_millis();
    (ms / 1000, (ms % 1000) as u32 * 1_000_000)
}
/// The token of the cookie `name` the request carries, if it is one (64 hexadecimal digits).
pub fn cookie_token(req: &Request, name: &str) -> Option<String> {
    let cookies = req.headers().get("Cookie").ok()??;
    let token = cookies
        .split(';')
        .map(str::trim)
        .find_map(|s| s.strip_prefix(&format!("{name}=")))?;
    (token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())).then(|| token.to_string())
}
/// The stored key of the request's session token: its hash, so stored keys cannot sign in.
pub fn token_key(req: &Request) -> Option<String> {
    cookie_token(req, COOKIE).map(|token| URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())))
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
    json!({"writable":who.id!=GUEST,"authenticated":who.id!=GUEST,"username":c.username(who.id),"uid":who.id,"group":c.groupname(who.group),"groups":who.groups.iter().map(|g|c.groupname(*g)).collect::<Vec<_>>(),"home":home,"can_sudo":c.can_sudo(&who),"sudo_active":who.id==0||live_session(c,key).is_some_and(|s|s.sudo_until>now())})
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
    let home = c.user_by_id(uid).map(|(_, u)| u.home).unwrap_or_default();
    (
        json!({"writable":true,"username":c.username(uid),"home":home}),
        token,
    )
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
