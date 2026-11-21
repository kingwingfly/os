//! 100% local OS account, group, shadow password, and sudoers policy engine (`#57` `L3d`,
//! Contract v2 §1, §2.4).
//!
//! OS identity lives exclusively in `/etc/passwd`, `/etc/group`, `/etc/shadow`, and `/etc/sudoers`
//! inside the instance's local `os-cowfs` root volume. There is NO OS-level `issuer`, NO
//! `/etc/os/principals`, and NO cross-instance `(issuer, subject)` UID federation.
//!
//! All mutations write to a uniquely named temporary file under `/etc` with exact ownership and
//! mode (`0644` for `passwd`/`group`, `0600` for `shadow`, `0440` for `sudoers`) before atomically
//! `rename()`ing over the target so crashes never corrupt `/etc/*`.

use abi::{Creds, Errno, Error};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use os_core::permissions::Identity;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

pub const PASSWD_PATH: &str = "/etc/passwd";
pub const GROUP_PATH: &str = "/etc/group";
pub const SHADOW_PATH: &str = "/etc/shadow";
pub const SUDOERS_PATH: &str = "/etc/sudoers";

pub const PASSWD_MODE: u16 = 0o644;
pub const GROUP_MODE: u16 = 0o644;
pub const SHADOW_MODE: u16 = 0o600;
pub const SUDOERS_MODE: u16 = 0o440;

/// Local `sudo` credential timestamp grace window (5 minutes).
pub const SUDO_TIMESTAMP_TTL_SECS: u64 = 300;

/// RFC 2898 PBKDF2-HMAC-SHA256 iteration count for newly hashed passwords.
pub const PBKDF2_ITERATIONS: u32 = 100_000;
/// Upper bound accepted during verification to prevent CPU DoS on crafted shadow files.
pub const PBKDF2_MAX_ITERATIONS: u32 = 2_000_000;
/// Derived key length in bytes (256 bits).
pub const PBKDF2_DK_LEN: usize = 32;

/// Minimum character length for ordinary passwords unless `force` / `short_password` is set.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Maximum password length in bytes.
pub const MAX_PASSWORD_BYTES: usize = 512;

/// First dynamically allocated local user/group ID.
pub const MIN_LOCAL_ID: u32 = 1000;
/// Default primary group ID for `wheel`.
pub const WHEEL_GID: u32 = 10;

/// Default initial `/etc/passwd` contents for a freshly seeded local `os-cowfs` root.
pub const DEFAULT_PASSWD: &str = "\
root:x:0:0:root:/root:/bin/sh
user:x:1000:1000:Local User:/home/user:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
";

/// Default initial `/etc/group` contents (`user` in `wheel` for local `sudo`).
pub const DEFAULT_GROUP: &str = "\
root:x:0:
wheel:x:10:user
user:x:1000:
nogroup:x:65534:
";

/// Default initial `/etc/shadow` contents (`!` = password locked; auto-login and `wheel NOPASSWD`
/// continue to work until the user sets a password with `passwd`).
pub const DEFAULT_SHADOW: &str = "\
root:!:0:0:99999:7:::
user:!:0:0:99999:7:::
nobody:*:0:0:99999:7:::
";

/// Default initial `/etc/sudoers` contents.
pub const DEFAULT_SUDOERS: &str = "\
root ALL=(ALL:ALL) ALL
%wheel ALL=(ALL:ALL) NOPASSWD: ALL
";

const RESERVED_GROUPS: &[&str] = &["root", "wheel", "nogroup"];
const RESERVED_USERS: &[&str] = &["root", "nobody"];

static TMP_COUNTER: AtomicU64 = AtomicU64::new(1);

type Result<T> = std::result::Result<T, Error>;

/// Abstract portable filesystem backend over which `LocalAccountStore` operates.
/// Implemented directly on `os_vfs::Vfs` in `client-kernel` / `os-native` and in-memory for tests.
pub trait AccountFs {
    fn read_file(&self, path: &str) -> Result<Vec<u8>>;
    fn write_file(&mut self, path: &str, data: &[u8], mode: u16, uid: u32, gid: u32) -> Result<()>;
    fn rename(&mut self, from: &str, to: &str) -> Result<()>;
    fn remove_file(&mut self, path: &str) -> Result<()>;
    fn exists(&self, path: &str) -> bool;
    fn mkdir_p(&mut self, path: &str, mode: u16, uid: u32, gid: u32) -> Result<()>;
    fn remove_dir_all(&mut self, path: &str) -> Result<()>;
}

/// Seed the default local `/etc/{passwd,group,shadow,sudoers}` files and standard home directories
/// using exact Contract v2 modes (`0644`, `0644`, `0600`, `0440`).
pub fn seed_default_etc(fs: &mut dyn AccountFs) -> Result<()> {
    fs.mkdir_p("/etc", 0o755, 0, 0)?;
    fs.mkdir_p("/root", 0o700, 0, 0)?;
    fs.mkdir_p("/home/user", 0o750, 1000, 1000)?;
    atomic_write_etc(fs, PASSWD_PATH, DEFAULT_PASSWD.as_bytes(), PASSWD_MODE)?;
    atomic_write_etc(fs, GROUP_PATH, DEFAULT_GROUP.as_bytes(), GROUP_MODE)?;
    atomic_write_etc(fs, SHADOW_PATH, DEFAULT_SHADOW.as_bytes(), SHADOW_MODE)?;
    atomic_write_etc(fs, SUDOERS_PATH, DEFAULT_SUDOERS.as_bytes(), SUDOERS_MODE)?;
    Ok(())
}

/// Constant-time byte-slice equality comparison.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Pure-Rust RFC 2898 PBKDF2-HMAC-SHA256 key derivation (`out.len() > 0`, `iterations > 0`).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(iterations > 0, "PBKDF2 iteration count must be >= 1");
    let base_mac = Hmac::<Sha256>::new_from_slice(password)
        .expect("HMAC-SHA256 accepts keys of arbitrary length");
    for (chunk_idx, chunk) in out.chunks_mut(PBKDF2_DK_LEN).enumerate() {
        let block_num = (chunk_idx as u32)
            .checked_add(1)
            .expect("PBKDF2 output length overflow");
        let mut mac = base_mac.clone();
        mac.update(salt);
        mac.update(&block_num.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut t = u;
        for _ in 1..iterations {
            let mut next = base_mac.clone();
            next.update(&u);
            u = next.finalize().into_bytes();
            for (acc, byte) in t.iter_mut().zip(u.iter()) {
                *acc ^= *byte;
            }
        }
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
}

/// Hash a password using RFC 2898 PBKDF2-HMAC-SHA256 with `PBKDF2_ITERATIONS` (`100_000`) rounds:
/// `$pbkdf2-sha256$i=100000$<b64-salt>$<b64-dk>`.
pub fn hash_password(password: &str, salt: [u8; 16]) -> String {
    hash_password_with_iterations(password, &salt, PBKDF2_ITERATIONS)
}

/// Hash a password with an explicit iteration count (helper for testing / future tuning).
pub fn hash_password_with_iterations(password: &str, salt: &[u8], iterations: u32) -> String {
    let mut dk = [0u8; PBKDF2_DK_LEN];
    pbkdf2_hmac_sha256(password.as_bytes(), salt, iterations, &mut dk);
    format!(
        "$pbkdf2-sha256$i={iterations}${}${}",
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(dk)
    )
}

/// Whether a `/etc/shadow` password field denotes a locked or non-password-authenticating account.
pub fn is_locked_hash(encoded_hash: &str) -> bool {
    encoded_hash.is_empty() || encoded_hash.starts_with('!') || encoded_hash.starts_with('*')
}

fn decode_b64_flexible(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return None;
    }
    STANDARD_NO_PAD
        .decode(input)
        .or_else(|_| STANDARD.decode(input))
        .ok()
}

/// Verify `password` against an encoded `/etc/shadow` password field in constant time.
/// Locked accounts (`"!"`, `"*"`, or `"!<hash>"`) and malformed hashes always return `false`.
pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES || is_locked_hash(encoded_hash) {
        return false;
    }
    let Some(rest) = encoded_hash.strip_prefix("$pbkdf2-sha256$") else {
        return false;
    };
    let mut parts = rest.split('$');
    let (Some(iter_part), Some(salt_part), Some(dk_part), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let Some(iter_str) = iter_part.strip_prefix("i=") else {
        return false;
    };
    let Ok(iterations) = iter_str.parse::<u32>() else {
        return false;
    };
    if iterations == 0 || iterations > PBKDF2_MAX_ITERATIONS {
        return false;
    }
    let Some(salt) = decode_b64_flexible(salt_part) else {
        return false;
    };
    let Some(expected_dk) = decode_b64_flexible(dk_part) else {
        return false;
    };
    if salt.is_empty() || expected_dk.len() != PBKDF2_DK_LEN {
        return false;
    }
    let mut actual_dk = [0u8; PBKDF2_DK_LEN];
    pbkdf2_hmac_sha256(password.as_bytes(), &salt, iterations, &mut actual_dk);
    constant_time_eq(&actual_dk, &expected_dk)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
    pub home: String,
    pub shell: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEntry {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowEntry {
    pub name: String,
    pub password_hash: String,
    pub locked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SudoCheck {
    AllowedNoPassword,
    RequiresPassword,
    Denied,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UseraddReq {
    pub name: String,
    pub uid: Option<u32>,
    pub group: Option<String>,
    pub groups: Vec<String>,
    pub gecos: Option<String>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub create_home: bool,
    pub password: Option<String>,
    pub short_password: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsermodReq {
    pub name: String,
    pub rename: Option<String>,
    pub group: Option<String>,
    pub groups: Option<Vec<String>>,
    pub append: bool,
    pub gecos: Option<String>,
    pub home: Option<String>,
    pub move_home: bool,
    pub shell: Option<String>,
    pub lock: bool,
    pub unlock: bool,
}

/// Validate a POSIX local account or group name (rejecting colons, newlines, NULs, whitespace,
/// uppercase, and reserved synthetic prefixes).
pub fn valid_account_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && name != "guest"
        && !name.starts_with("guest-")
}

/// Reject control/delimiter characters that could corrupt colon-delimited `/etc/*` records.
pub fn valid_etc_field(value: &str) -> bool {
    !value
        .bytes()
        .any(|b| matches!(b, b':' | b'\n' | b'\r' | b'\0'))
}

fn validate_abs_path(path: &str, label: &str) -> Result<String> {
    if !valid_etc_field(path) || !path.starts_with('/') || path.len() > abi::PATH_MAX {
        return Err(Error::because(
            Errno::EINVAL,
            format!("invalid {label} path"),
        ));
    }
    if path != "/" {
        if path.ends_with('/') {
            return Err(Error::because(
                Errno::EINVAL,
                format!("{label} path must not end with '/'"),
            ));
        }
        for seg in path[1..].split('/') {
            if seg.is_empty() || seg == "." || seg == ".." || seg.len() > abi::NAME_MAX {
                return Err(Error::because(
                    Errno::EINVAL,
                    format!("invalid {label} path component"),
                ));
            }
        }
    }
    Ok(path.to_owned())
}

fn validate_password(password: &str, allow_short: bool) -> Result<()> {
    if password.is_empty() {
        return Err(Error::because(Errno::EINVAL, "password cannot be empty"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Error::because(
            Errno::EINVAL,
            format!("password exceeds {MAX_PASSWORD_BYTES} bytes"),
        ));
    }
    if password.bytes().any(|b| matches!(b, b'\0' | b'\n' | b'\r')) {
        return Err(Error::because(
            Errno::EINVAL,
            "password contains disallowed control characters",
        ));
    }
    if !allow_short && password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(Error::because(
            Errno::EINVAL,
            format!(
                "password must be at least {MIN_PASSWORD_CHARS} characters (pass --force to override)"
            ),
        ));
    }
    Ok(())
}

/// Parse `/etc/passwd` text into structured entries.
pub fn parse_passwd(text: &str) -> Result<Vec<PasswdEntry>> {
    let mut entries = Vec::new();
    let mut seen_names = BTreeSet::new();
    let mut seen_uids = BTreeSet::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/passwd line {}: expected 7 fields", idx + 1),
            ));
        }
        let name = fields[0].to_owned();
        if name.is_empty() || !valid_etc_field(&name) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/passwd line {}: invalid username", idx + 1),
            ));
        }
        let uid: u32 = fields[2].parse().map_err(|_| {
            Error::because(
                Errno::EINVAL,
                format!("/etc/passwd line {}: invalid uid", idx + 1),
            )
        })?;
        let gid: u32 = fields[3].parse().map_err(|_| {
            Error::because(
                Errno::EINVAL,
                format!("/etc/passwd line {}: invalid gid", idx + 1),
            )
        })?;
        if !seen_names.insert(name.clone()) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/passwd: duplicate username '{name}'"),
            ));
        }
        if !seen_uids.insert(uid) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/passwd: duplicate uid {uid}"),
            ));
        }
        entries.push(PasswdEntry {
            name,
            uid,
            gid,
            gecos: fields[4].to_owned(),
            home: fields[5].to_owned(),
            shell: fields[6].to_owned(),
        });
    }
    Ok(entries)
}

/// Format entries as canonical `/etc/passwd`.
pub fn format_passwd(entries: &[PasswdEntry]) -> Result<String> {
    let mut out = String::new();
    for entry in entries {
        if !valid_etc_field(&entry.name)
            || !valid_etc_field(&entry.gecos)
            || !valid_etc_field(&entry.home)
            || !valid_etc_field(&entry.shell)
        {
            return Err(Error::because(
                Errno::EINVAL,
                "passwd field contains forbidden delimiter or control byte",
            ));
        }
        out.push_str(&format!(
            "{}:x:{}:{}:{}:{}:{}\n",
            entry.name, entry.uid, entry.gid, entry.gecos, entry.home, entry.shell
        ));
    }
    Ok(out)
}

/// Parse `/etc/group` text into structured entries.
pub fn parse_group(text: &str) -> Result<Vec<GroupEntry>> {
    let mut entries = Vec::new();
    let mut seen_names = BTreeSet::new();
    let mut seen_gids = BTreeSet::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() != 4 {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/group line {}: expected 4 fields", idx + 1),
            ));
        }
        let name = fields[0].to_owned();
        if name.is_empty() || !valid_etc_field(&name) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/group line {}: invalid group name", idx + 1),
            ));
        }
        let gid: u32 = fields[2].parse().map_err(|_| {
            Error::because(
                Errno::EINVAL,
                format!("/etc/group line {}: invalid gid", idx + 1),
            )
        })?;
        if !seen_names.insert(name.clone()) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/group: duplicate group '{name}'"),
            ));
        }
        if !seen_gids.insert(gid) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/group: duplicate gid {gid}"),
            ));
        }
        let mut members: Vec<String> = fields[3]
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .collect();
        let mut uniq = BTreeSet::new();
        members.retain(|m| uniq.insert(m.clone()));
        entries.push(GroupEntry { name, gid, members });
    }
    Ok(entries)
}

/// Format entries as canonical `/etc/group`.
pub fn format_group(entries: &[GroupEntry]) -> Result<String> {
    let mut out = String::new();
    for entry in entries {
        if !valid_etc_field(&entry.name)
            || entry
                .members
                .iter()
                .any(|m| !valid_etc_field(m) || m.contains(','))
        {
            return Err(Error::because(
                Errno::EINVAL,
                "group field contains forbidden delimiter or control byte",
            ));
        }
        out.push_str(&format!(
            "{}:x:{}:{}\n",
            entry.name,
            entry.gid,
            entry.members.join(",")
        ));
    }
    Ok(out)
}

/// Parse `/etc/shadow` text into structured entries.
pub fn parse_shadow(text: &str) -> Result<Vec<ShadowEntry>> {
    let mut entries = Vec::new();
    let mut seen_names = BTreeSet::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 2 {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/shadow line {}: expected at least 2 fields", idx + 1),
            ));
        }
        let name = fields[0].to_owned();
        if name.is_empty() || !valid_etc_field(&name) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/shadow line {}: invalid username", idx + 1),
            ));
        }
        if !seen_names.insert(name.clone()) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("/etc/shadow: duplicate username '{name}'"),
            ));
        }
        let password_hash = fields[1].to_owned();
        let locked = is_locked_hash(&password_hash);
        entries.push(ShadowEntry {
            name,
            password_hash,
            locked,
        });
    }
    Ok(entries)
}

/// Format entries as canonical 9-field `/etc/shadow`.
pub fn format_shadow(entries: &[ShadowEntry]) -> Result<String> {
    let mut out = String::new();
    for entry in entries {
        if !valid_etc_field(&entry.name) || !valid_etc_field(&entry.password_hash) {
            return Err(Error::because(
                Errno::EINVAL,
                "shadow field contains forbidden delimiter or control byte",
            ));
        }
        out.push_str(&format!(
            "{}:{}:0:0:99999:7:::\n",
            entry.name, entry.password_hash
        ));
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SudoSubject {
    User(String),
    Group(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SudoRule {
    subject: SudoSubject,
    nopasswd: bool,
}

fn parse_sudoers(text: &str) -> Vec<SudoRule> {
    let mut rules = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 3 {
            continue;
        }
        let subject_tok = tokens[0];
        if subject_tok.eq_ignore_ascii_case("Defaults") {
            continue;
        }
        let subject = if let Some(group) = subject_tok.strip_prefix('%') {
            if group.is_empty() {
                continue;
            }
            SudoSubject::Group(group.to_owned())
        } else {
            SudoSubject::User(subject_tok.to_owned())
        };
        // Expect `ALL=(ALL:ALL)` or `ALL=(ALL)` followed by optional `NOPASSWD:` / `PASSWD:` and `ALL`.
        let host_runas = tokens[1];
        if !host_runas.starts_with("ALL=") {
            continue;
        }
        let tail = &tokens[2..];
        let mut nopasswd = false;
        let mut grants_all = false;
        for &tok in tail {
            if tok == "NOPASSWD:" {
                nopasswd = true;
            } else if tok == "PASSWD:" {
                nopasswd = false;
            } else if let Some(cmd) = tok.strip_prefix("NOPASSWD:") {
                nopasswd = true;
                if cmd == "ALL" {
                    grants_all = true;
                }
            } else if let Some(cmd) = tok.strip_prefix("PASSWD:") {
                nopasswd = false;
                if cmd == "ALL" {
                    grants_all = true;
                }
            } else if tok == "ALL" {
                grants_all = true;
            }
        }
        if grants_all {
            rules.push(SudoRule { subject, nopasswd });
        }
    }
    rules
}

fn read_text(fs: &dyn AccountFs, path: &str) -> Result<String> {
    let bytes = fs.read_file(path)?;
    String::from_utf8(bytes)
        .map_err(|_| Error::because(Errno::EINVAL, format!("{path} is not valid UTF-8")))
}

fn atomic_write_etc(fs: &mut dyn AccountFs, target: &str, data: &[u8], mode: u16) -> Result<()> {
    let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = format!("{target}.tmp.{seq:016x}");
    fs.write_file(&tmp, data, mode, 0, 0)?;
    if let Err(err) = fs.rename(&tmp, target) {
        let _ = fs.remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}

fn next_free_id(used: &BTreeSet<u32>) -> Result<u32> {
    let mut candidate = MIN_LOCAL_ID;
    while used.contains(&candidate) {
        candidate = candidate
            .checked_add(1)
            .ok_or_else(|| Error::because(Errno::ENOSPC, "no free local IDs available"))?;
        if candidate >= os_core::permissions::GUEST {
            return Err(Error::because(
                Errno::ENOSPC,
                "local ID range exhausted below 65534",
            ));
        }
    }
    Ok(candidate)
}

fn identity_for(entry: &PasswdEntry, groups: &[GroupEntry]) -> Identity {
    let mut gids = BTreeSet::from([entry.gid]);
    for group in groups {
        if group.members.iter().any(|m| m == &entry.name) {
            gids.insert(group.gid);
        }
    }
    Identity {
        id: entry.uid,
        group: entry.gid,
        groups: gids,
    }
}

/// 100% local OS account & sudo policy store operating on `/etc/{passwd,group,shadow,sudoers}`.
#[derive(Clone, Debug, Default)]
pub struct LocalAccountStore {
    /// Local sudo timestamp cache keyed by `(uid, sid) -> expiry_epoch_secs`.
    sudo_timestamps: BTreeMap<(u32, u32), u64>,
}

impl LocalAccountStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list_users(&self, fs: &dyn AccountFs) -> Result<Vec<PasswdEntry>> {
        parse_passwd(&read_text(fs, PASSWD_PATH)?)
    }

    pub fn list_groups(&self, fs: &dyn AccountFs) -> Result<Vec<GroupEntry>> {
        parse_group(&read_text(fs, GROUP_PATH)?)
    }

    /// Resolve a local username to its full `Identity` (uid, primary gid, all supplementary gids).
    pub fn resolve_user(&self, fs: &dyn AccountFs, username: &str) -> Result<Identity> {
        let users = self.list_users(fs)?;
        let entry = users
            .iter()
            .find(|u| u.name == username)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such user: {username}")))?;
        let groups = self.list_groups(fs)?;
        Ok(identity_for(entry, &groups))
    }

    /// Resolve a local numeric UID to its `/etc/passwd` record.
    pub fn resolve_uid(&self, fs: &dyn AccountFs, uid: u32) -> Result<PasswdEntry> {
        let users = self.list_users(fs)?;
        users
            .into_iter()
            .find(|u| u.uid == uid)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such uid: {uid}")))
    }

    /// Build an `abi::Creds` response for `Call::Getcreds` directly from local `/etc/*` with ZERO
    /// network RPCs.
    pub fn build_creds(&self, fs: &dyn AccountFs, uid: u32, sid: u32, now: u64) -> Result<Creds> {
        let entry = self.resolve_uid(fs, uid)?;
        let groups = self.list_groups(fs)?;
        let ident = identity_for(&entry, &groups);
        let group_ids: Vec<u32> = ident.groups.iter().copied().collect();
        let group_name = |gid: u32| {
            groups
                .iter()
                .find(|g| g.gid == gid)
                .map(|g| g.name.clone())
                .unwrap_or_else(|| gid.to_string())
        };
        let sudo = self.check_sudo(fs, uid, &group_ids, sid, now)?;
        let can_sudo = !matches!(sudo, SudoCheck::Denied);
        let sudo_active = matches!(sudo, SudoCheck::AllowedNoPassword);
        Ok(Creds {
            uid: entry.uid,
            gid: entry.gid,
            groups: group_ids.clone(),
            user: entry.name,
            group: group_name(entry.gid),
            group_names: group_ids.into_iter().map(group_name).collect(),
            home: entry.home,
            signed_in: true,
            can_sudo,
            sudo_active,
        })
    }

    /// Evaluate `/etc/sudoers` and the local `(uid, sid)` 5-minute timestamp cache.
    pub fn check_sudo(
        &self,
        fs: &dyn AccountFs,
        uid: u32,
        groups: &[u32],
        sid: u32,
        now: u64,
    ) -> Result<SudoCheck> {
        if uid == 0 {
            return Ok(SudoCheck::AllowedNoPassword);
        }
        let sudoers_text = match read_text(fs, SUDOERS_PATH) {
            Ok(text) => text,
            Err(err) if err.errno == Errno::ENOENT => return Ok(SudoCheck::Denied),
            Err(err) => return Err(err),
        };
        let rules = parse_sudoers(&sudoers_text);
        let user_entry = match self.resolve_uid(fs, uid) {
            Ok(u) => u,
            Err(err) if err.errno == Errno::ENOENT => return Ok(SudoCheck::Denied),
            Err(err) => return Err(err),
        };
        let group_table = self.list_groups(fs)?;
        let mut active_group_names = BTreeSet::new();
        for &gid in groups {
            if let Some(g) = group_table.iter().find(|g| g.gid == gid) {
                active_group_names.insert(g.name.as_str());
            }
        }
        // Standard sudoers semantics: last matching rule wins.
        let mut matched: Option<bool> = None;
        for rule in &rules {
            let matches_subject = match &rule.subject {
                SudoSubject::User(name) => name == &user_entry.name,
                SudoSubject::Group(group) => active_group_names.contains(group.as_str()),
            };
            if matches_subject {
                matched = Some(rule.nopasswd);
            }
        }
        match matched {
            None => Ok(SudoCheck::Denied),
            Some(true) => Ok(SudoCheck::AllowedNoPassword),
            Some(false) => {
                if self
                    .sudo_timestamps
                    .get(&(uid, sid))
                    .is_some_and(|&expiry| expiry > now)
                {
                    Ok(SudoCheck::AllowedNoPassword)
                } else {
                    Ok(SudoCheck::RequiresPassword)
                }
            }
        }
    }

    /// Authenticate `username` with `password` against local `/etc/shadow` (constant-time
    /// PBKDF2-HMAC-SHA256). Locked accounts (`"!"` / `"*"`) always fail with `EACCES`.
    pub fn authenticate(
        &self,
        fs: &dyn AccountFs,
        username: &str,
        password: &str,
    ) -> Result<Identity> {
        let users = self.list_users(fs)?;
        let Some(entry) = users.iter().find(|u| u.name == username) else {
            return Err(Error::because(Errno::EACCES, "authentication failed"));
        };
        let shadows = parse_shadow(&read_text(fs, SHADOW_PATH)?)?;
        let Some(shadow) = shadows.iter().find(|s| s.name == username) else {
            return Err(Error::because(Errno::EACCES, "authentication failed"));
        };
        if shadow.locked || !verify_password(password, &shadow.password_hash) {
            return Err(Error::because(Errno::EACCES, "authentication failed"));
        }
        let groups = self.list_groups(fs)?;
        Ok(identity_for(entry, &groups))
    }

    /// Authenticate a local `sudo` elevation request for `(caller, sid)`.
    /// Honors `NOPASSWD` rules (including locked default `user` in `wheel`), verifies local
    /// `/etc/shadow` password when required, and records a 5-minute `(uid, sid)` timestamp.
    pub fn sudo_authenticate(
        &mut self,
        fs: &dyn AccountFs,
        caller: &Identity,
        sid: u32,
        password: Option<&str>,
        now: u64,
    ) -> Result<()> {
        let group_ids: Vec<u32> = caller.groups.iter().copied().collect();
        match self.check_sudo(fs, caller.id, &group_ids, sid, now)? {
            SudoCheck::Denied => Err(Error::because(
                Errno::EPERM,
                "user is not authorized for sudo in /etc/sudoers",
            )),
            SudoCheck::AllowedNoPassword => {
                self.sudo_timestamps.insert(
                    (caller.id, sid),
                    now.saturating_add(SUDO_TIMESTAMP_TTL_SECS),
                );
                Ok(())
            }
            SudoCheck::RequiresPassword => {
                let pw = password.ok_or_else(|| {
                    Error::because(Errno::EACCES, "sudo requires a local password")
                })?;
                let user = self.resolve_uid(fs, caller.id)?;
                let shadows = parse_shadow(&read_text(fs, SHADOW_PATH)?)?;
                let Some(shadow) = shadows.iter().find(|s| s.name == user.name) else {
                    return Err(Error::because(Errno::EACCES, "authentication failed"));
                };
                if shadow.locked || !verify_password(pw, &shadow.password_hash) {
                    return Err(Error::because(Errno::EACCES, "authentication failed"));
                }
                self.sudo_timestamps.insert(
                    (caller.id, sid),
                    now.saturating_add(SUDO_TIMESTAMP_TTL_SECS),
                );
                Ok(())
            }
        }
    }

    /// Revoke the cached `sudo` timestamp for `(uid, sid)` (`sudo -k`).
    pub fn sudo_revoke(&mut self, uid: u32, sid: u32) {
        self.sudo_timestamps.remove(&(uid, sid));
    }

    /// Revoke every cached `sudo` timestamp for `uid` (e.g., on password change, lock, or delete).
    pub fn sudo_revoke_all_for_uid(&mut self, uid: u32) {
        self.sudo_timestamps.retain(|&(u, _), _| u != uid);
    }

    /// Set a local account's password in `/etc/shadow` (mode `0600`, atomic temp-file + rename).
    #[allow(clippy::too_many_arguments)]
    pub fn passwd(
        &mut self,
        fs: &mut dyn AccountFs,
        caller: &Identity,
        target: Option<&str>,
        old: Option<&str>,
        new: &str,
        force: bool,
        salt: [u8; 16],
    ) -> Result<()> {
        validate_password(new, force)?;
        let users = self.list_users(fs)?;
        let caller_entry = users
            .iter()
            .find(|u| u.uid == caller.id)
            .ok_or_else(|| Error::because(Errno::ENOENT, "caller account not found"))?;
        let target_name = target.unwrap_or(&caller_entry.name);
        let target_entry = users
            .iter()
            .find(|u| u.name == target_name)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such user: {target_name}")))?;

        let changing_other = target_entry.uid != caller.id;
        if changing_other && caller.id != 0 {
            return Err(Error::because(
                Errno::EPERM,
                "only root may change another user's password",
            ));
        }

        let mut shadows = parse_shadow(&read_text(fs, SHADOW_PATH)?)?;
        if caller.id != 0 {
            let current =
                old.ok_or_else(|| Error::because(Errno::EACCES, "current password is required"))?;
            let existing = shadows
                .iter()
                .find(|s| s.name == target_name)
                .ok_or_else(|| Error::because(Errno::EACCES, "authentication failed"))?;
            if existing.locked || !verify_password(current, &existing.password_hash) {
                return Err(Error::because(
                    Errno::EACCES,
                    "current password is incorrect",
                ));
            }
        }

        let new_hash = hash_password(new, salt);
        if let Some(entry) = shadows.iter_mut().find(|s| s.name == target_name) {
            entry.password_hash = new_hash;
            entry.locked = false;
        } else {
            shadows.push(ShadowEntry {
                name: target_name.to_owned(),
                password_hash: new_hash,
                locked: false,
            });
        }
        let encoded = format_shadow(&shadows)?;
        atomic_write_etc(fs, SHADOW_PATH, encoded.as_bytes(), SHADOW_MODE)?;
        self.sudo_revoke_all_for_uid(target_entry.uid);
        Ok(())
    }

    /// Create a local user in `/etc/{passwd,group,shadow}` (root only).
    pub fn useradd(
        &self,
        fs: &mut dyn AccountFs,
        caller: &Identity,
        req: UseraddReq,
        salt: [u8; 16],
    ) -> Result<PasswdEntry> {
        if caller.id != 0 {
            return Err(Error::because(Errno::EPERM, "only root may add accounts"));
        }
        if !valid_account_name(&req.name) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("invalid username '{}'", req.name),
            ));
        }
        let gecos = req.gecos.unwrap_or_else(|| req.name.clone());
        if !valid_etc_field(&gecos) {
            return Err(Error::because(Errno::EINVAL, "invalid gecos field"));
        }
        let home = match req.home {
            Some(path) => validate_abs_path(&path, "home")?,
            None => format!("/home/{}", req.name),
        };
        let shell = match req.shell {
            Some(path) => validate_abs_path(&path, "shell")?,
            None => "/bin/sh".to_owned(),
        };
        let password_hash = match &req.password {
            Some(pw) => {
                validate_password(pw, req.short_password)?;
                hash_password(pw, salt)
            }
            None => "!".to_owned(),
        };

        let mut users = self.list_users(fs)?;
        let mut groups = self.list_groups(fs)?;
        let mut shadows = parse_shadow(&read_text(fs, SHADOW_PATH)?)?;

        if users.iter().any(|u| u.name == req.name) {
            return Err(Error::because(
                Errno::EEXIST,
                format!("user '{}' already exists", req.name),
            ));
        }

        let used_uids: BTreeSet<u32> = users.iter().map(|u| u.uid).collect();
        let uid = match req.uid {
            Some(explicit) => {
                if used_uids.contains(&explicit) {
                    return Err(Error::because(
                        Errno::EEXIST,
                        format!("uid {explicit} is already in use"),
                    ));
                }
                explicit
            }
            None => next_free_id(&used_uids)?,
        };

        let mut group_changed = false;
        let primary_gid = if let Some(group_spec) = &req.group {
            if let Ok(gid_num) = group_spec.parse::<u32>() {
                groups
                    .iter()
                    .find(|g| g.gid == gid_num)
                    .map(|g| g.gid)
                    .ok_or_else(|| {
                        Error::because(Errno::ENOENT, format!("no such group gid {gid_num}"))
                    })?
            } else {
                groups
                    .iter()
                    .find(|g| g.name == *group_spec)
                    .map(|g| g.gid)
                    .ok_or_else(|| {
                        Error::because(Errno::ENOENT, format!("no such group '{group_spec}'"))
                    })?
            }
        } else {
            if groups.iter().any(|g| g.name == req.name) {
                return Err(Error::because(
                    Errno::EEXIST,
                    format!(
                        "group '{}' already exists; pass -g to select primary group",
                        req.name
                    ),
                ));
            }
            let used_gids: BTreeSet<u32> = groups.iter().map(|g| g.gid).collect();
            let gid = if !used_gids.contains(&uid) {
                uid
            } else {
                next_free_id(&used_gids)?
            };
            groups.push(GroupEntry {
                name: req.name.clone(),
                gid,
                members: Vec::new(),
            });
            group_changed = true;
            gid
        };

        for supp in &req.groups {
            let group = groups
                .iter_mut()
                .find(|g| g.name == *supp)
                .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such group '{supp}'")))?;
            if !group.members.iter().any(|m| m == &req.name) {
                group.members.push(req.name.clone());
                group_changed = true;
            }
        }

        let new_entry = PasswdEntry {
            name: req.name.clone(),
            uid,
            gid: primary_gid,
            gecos,
            home: home.clone(),
            shell,
        };
        users.push(new_entry.clone());
        shadows.retain(|s| s.name != req.name);
        shadows.push(ShadowEntry {
            name: req.name.clone(),
            locked: is_locked_hash(&password_hash),
            password_hash,
        });

        let group_text = if group_changed {
            Some(format_group(&groups)?)
        } else {
            None
        };
        let passwd_text = format_passwd(&users)?;
        let shadow_text = format_shadow(&shadows)?;

        if let Some(gt) = group_text {
            atomic_write_etc(fs, GROUP_PATH, gt.as_bytes(), GROUP_MODE)?;
        }
        atomic_write_etc(fs, PASSWD_PATH, passwd_text.as_bytes(), PASSWD_MODE)?;
        atomic_write_etc(fs, SHADOW_PATH, shadow_text.as_bytes(), SHADOW_MODE)?;

        if req.create_home {
            fs.mkdir_p(&home, 0o750, uid, primary_gid)?;
        }
        Ok(new_entry)
    }

    /// Modify an existing local user in `/etc/{passwd,group,shadow}` (root only).
    pub fn usermod(
        &mut self,
        fs: &mut dyn AccountFs,
        caller: &Identity,
        req: UsermodReq,
    ) -> Result<PasswdEntry> {
        if caller.id != 0 {
            return Err(Error::because(
                Errno::EPERM,
                "only root may modify accounts",
            ));
        }
        if req.lock && req.unlock {
            return Err(Error::because(
                Errno::EINVAL,
                "cannot specify both --lock and --unlock",
            ));
        }
        if req.move_home && req.home.is_none() {
            return Err(Error::because(Errno::EINVAL, "--move-home requires --home"));
        }
        if req.append && req.groups.is_none() {
            return Err(Error::because(Errno::EINVAL, "--append requires --groups"));
        }

        let mut users = self.list_users(fs)?;
        let mut groups = self.list_groups(fs)?;
        let mut shadows = parse_shadow(&read_text(fs, SHADOW_PATH)?)?;

        let idx = users
            .iter()
            .position(|u| u.name == req.name)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such user: {}", req.name)))?;

        let old_name = users[idx].name.clone();
        let old_home = users[idx].home.clone();
        let target_uid = users[idx].uid;

        let new_name = match &req.rename {
            Some(renamed) => {
                if RESERVED_USERS.contains(&old_name.as_str()) {
                    return Err(Error::because(
                        Errno::EPERM,
                        format!("cannot rename system account '{old_name}'"),
                    ));
                }
                if !valid_account_name(renamed) {
                    return Err(Error::because(
                        Errno::EINVAL,
                        format!("invalid username '{renamed}'"),
                    ));
                }
                if renamed != &old_name && users.iter().any(|u| u.name == *renamed) {
                    return Err(Error::because(
                        Errno::EEXIST,
                        format!("user '{renamed}' already exists"),
                    ));
                }
                renamed.clone()
            }
            None => old_name.clone(),
        };

        if let Some(gecos) = &req.gecos {
            if !valid_etc_field(gecos) {
                return Err(Error::because(Errno::EINVAL, "invalid gecos field"));
            }
            users[idx].gecos = gecos.clone();
        }
        if let Some(shell) = &req.shell {
            users[idx].shell = validate_abs_path(shell, "shell")?;
        }

        let new_home = match &req.home {
            Some(home) => Some(validate_abs_path(home, "home")?),
            None => None,
        };

        if let Some(group_spec) = &req.group {
            let gid = if let Ok(gid_num) = group_spec.parse::<u32>() {
                groups
                    .iter()
                    .find(|g| g.gid == gid_num)
                    .map(|g| g.gid)
                    .ok_or_else(|| {
                        Error::because(Errno::ENOENT, format!("no such group gid {gid_num}"))
                    })?
            } else {
                groups
                    .iter()
                    .find(|g| g.name == *group_spec)
                    .map(|g| g.gid)
                    .ok_or_else(|| {
                        Error::because(Errno::ENOENT, format!("no such group '{group_spec}'"))
                    })?
            };
            users[idx].gid = gid;
        }

        // Rename user references in `/etc/group`.
        if new_name != old_name {
            for group in &mut groups {
                for member in &mut group.members {
                    if member == &old_name {
                        *member = new_name.clone();
                    }
                }
            }
        }

        if let Some(supp_list) = &req.groups {
            for name in supp_list {
                if !groups.iter().any(|g| g.name == *name) {
                    return Err(Error::because(
                        Errno::ENOENT,
                        format!("no such group '{name}'"),
                    ));
                }
            }
            if !req.append {
                for group in &mut groups {
                    group.members.retain(|m| m != &new_name);
                }
            }
            for name in supp_list {
                if let Some(group) = groups.iter_mut().find(|g| g.name == *name)
                    && !group.members.iter().any(|m| m == &new_name)
                {
                    group.members.push(new_name.clone());
                }
            }
        }

        // Update `/etc/shadow` for rename/lock/unlock.
        let mut shadow_changed = false;
        if let Some(shadow) = shadows.iter_mut().find(|s| s.name == old_name) {
            if new_name != old_name {
                shadow.name = new_name.clone();
                shadow_changed = true;
            }
            if req.lock {
                if !shadow.password_hash.starts_with('!') && !shadow.password_hash.starts_with('*')
                {
                    shadow.password_hash = format!("!{}", shadow.password_hash);
                } else if shadow.password_hash.is_empty() {
                    shadow.password_hash = "!".to_owned();
                }
                shadow.locked = true;
                shadow_changed = true;
            } else if req.unlock {
                let stripped = shadow.password_hash.trim_start_matches('!');
                if stripped.is_empty() || stripped == "*" {
                    return Err(Error::because(
                        Errno::EINVAL,
                        "cannot unlock account without a password hash; run passwd first",
                    ));
                }
                shadow.password_hash = stripped.to_owned();
                shadow.locked = false;
                shadow_changed = true;
            }
        } else if req.lock || req.unlock {
            return Err(Error::because(
                Errno::ENOENT,
                format!("no shadow record for '{old_name}'"),
            ));
        }

        if let Some(ref dest_home) = new_home {
            if req.move_home && dest_home != &old_home {
                if fs.exists(dest_home) {
                    return Err(Error::because(
                        Errno::EEXIST,
                        format!("destination home '{dest_home}' already exists"),
                    ));
                }
                if fs.exists(&old_home) {
                    fs.rename(&old_home, dest_home)?;
                }
            }
            users[idx].home = dest_home.clone();
        }
        users[idx].name = new_name;

        let updated = users[idx].clone();
        let passwd_text = format_passwd(&users)?;
        let group_text = format_group(&groups)?;
        let shadow_text = if shadow_changed {
            Some(format_shadow(&shadows)?)
        } else {
            None
        };

        atomic_write_etc(fs, GROUP_PATH, group_text.as_bytes(), GROUP_MODE)?;
        atomic_write_etc(fs, PASSWD_PATH, passwd_text.as_bytes(), PASSWD_MODE)?;
        if let Some(st) = shadow_text {
            atomic_write_etc(fs, SHADOW_PATH, st.as_bytes(), SHADOW_MODE)?;
        }
        if req.lock {
            self.sudo_revoke_all_for_uid(target_uid);
        }
        Ok(updated)
    }

    /// Delete a local user from `/etc/{passwd,group,shadow}` (root only).
    pub fn userdel(
        &mut self,
        fs: &mut dyn AccountFs,
        caller: &Identity,
        name: &str,
        remove_home: bool,
    ) -> Result<()> {
        if caller.id != 0 {
            return Err(Error::because(
                Errno::EPERM,
                "only root may delete accounts",
            ));
        }
        if RESERVED_USERS.contains(&name) {
            return Err(Error::because(
                Errno::EPERM,
                format!("cannot delete system account '{name}'"),
            ));
        }
        let mut users = self.list_users(fs)?;
        let idx = users
            .iter()
            .position(|u| u.name == name)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such user: {name}")))?;
        let removed = users.remove(idx);

        let mut groups = self.list_groups(fs)?;
        for group in &mut groups {
            group.members.retain(|m| m != name);
        }
        // Remove the user's private primary group if it matches the username, is not reserved, has
        // no remaining members, and is no longer any other user's primary group.
        if !RESERVED_GROUPS.contains(&name)
            && let Some(g_idx) = groups.iter().position(|g| g.name == name)
        {
            let gid = groups[g_idx].gid;
            let still_primary = users.iter().any(|u| u.gid == gid);
            if !still_primary && groups[g_idx].members.is_empty() {
                groups.remove(g_idx);
            }
        }

        let mut shadows = parse_shadow(&read_text(fs, SHADOW_PATH)?)?;
        shadows.retain(|s| s.name != name);

        let passwd_text = format_passwd(&users)?;
        let group_text = format_group(&groups)?;
        let shadow_text = format_shadow(&shadows)?;

        atomic_write_etc(fs, PASSWD_PATH, passwd_text.as_bytes(), PASSWD_MODE)?;
        atomic_write_etc(fs, SHADOW_PATH, shadow_text.as_bytes(), SHADOW_MODE)?;
        atomic_write_etc(fs, GROUP_PATH, group_text.as_bytes(), GROUP_MODE)?;
        self.sudo_revoke_all_for_uid(removed.uid);

        if remove_home
            && removed.home != "/"
            && removed.home != "/home"
            && removed.home != "/root"
            && fs.exists(&removed.home)
        {
            fs.remove_dir_all(&removed.home)?;
        }
        Ok(())
    }

    /// Create a local group in `/etc/group` (root only).
    pub fn groupadd(
        &self,
        fs: &mut dyn AccountFs,
        caller: &Identity,
        name: &str,
    ) -> Result<GroupEntry> {
        self.groupadd_with_gid(fs, caller, name, None)
    }

    /// Create a local group with an optional explicit GID (root only).
    pub fn groupadd_with_gid(
        &self,
        fs: &mut dyn AccountFs,
        caller: &Identity,
        name: &str,
        explicit_gid: Option<u32>,
    ) -> Result<GroupEntry> {
        if caller.id != 0 {
            return Err(Error::because(Errno::EPERM, "only root may add groups"));
        }
        if !valid_account_name(name) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("invalid group name '{name}'"),
            ));
        }
        let mut groups = self.list_groups(fs)?;
        if groups.iter().any(|g| g.name == name) {
            return Err(Error::because(
                Errno::EEXIST,
                format!("group '{name}' already exists"),
            ));
        }
        let used_gids: BTreeSet<u32> = groups.iter().map(|g| g.gid).collect();
        let gid = match explicit_gid {
            Some(g) => {
                if used_gids.contains(&g) {
                    return Err(Error::because(
                        Errno::EEXIST,
                        format!("gid {g} is already in use"),
                    ));
                }
                g
            }
            None => next_free_id(&used_gids)?,
        };
        let entry = GroupEntry {
            name: name.to_owned(),
            gid,
            members: Vec::new(),
        };
        groups.push(entry.clone());
        let encoded = format_group(&groups)?;
        atomic_write_etc(fs, GROUP_PATH, encoded.as_bytes(), GROUP_MODE)?;
        Ok(entry)
    }

    /// Rename a local group in `/etc/group` (root only).
    pub fn groupmod(
        &self,
        fs: &mut dyn AccountFs,
        caller: &Identity,
        name: &str,
        new_name: &str,
    ) -> Result<GroupEntry> {
        if caller.id != 0 {
            return Err(Error::because(Errno::EPERM, "only root may modify groups"));
        }
        if RESERVED_GROUPS.contains(&name) {
            return Err(Error::because(
                Errno::EPERM,
                format!("cannot rename system group '{name}'"),
            ));
        }
        if !valid_account_name(new_name) {
            return Err(Error::because(
                Errno::EINVAL,
                format!("invalid group name '{new_name}'"),
            ));
        }
        let mut groups = self.list_groups(fs)?;
        let idx = groups
            .iter()
            .position(|g| g.name == name)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such group: {name}")))?;
        if new_name != name && groups.iter().any(|g| g.name == new_name) {
            return Err(Error::because(
                Errno::EEXIST,
                format!("group '{new_name}' already exists"),
            ));
        }
        groups[idx].name = new_name.to_owned();
        let updated = groups[idx].clone();
        let encoded = format_group(&groups)?;
        atomic_write_etc(fs, GROUP_PATH, encoded.as_bytes(), GROUP_MODE)?;
        Ok(updated)
    }

    /// Delete a local group from `/etc/group` (root only; refuses if primary group of any user).
    pub fn groupdel(&self, fs: &mut dyn AccountFs, caller: &Identity, name: &str) -> Result<()> {
        if caller.id != 0 {
            return Err(Error::because(Errno::EPERM, "only root may delete groups"));
        }
        if RESERVED_GROUPS.contains(&name) {
            return Err(Error::because(
                Errno::EPERM,
                format!("cannot delete system group '{name}'"),
            ));
        }
        let mut groups = self.list_groups(fs)?;
        let idx = groups
            .iter()
            .position(|g| g.name == name)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("no such group: {name}")))?;
        let gid = groups[idx].gid;
        let users = self.list_users(fs)?;
        if let Some(owner) = users.iter().find(|u| u.gid == gid) {
            return Err(Error::because(
                Errno::EBUSY,
                format!(
                    "cannot remove primary group '{name}' of user '{}'",
                    owner.name
                ),
            ));
        }
        groups.remove(idx);
        let encoded = format_group(&groups)?;
        atomic_write_etc(fs, GROUP_PATH, encoded.as_bytes(), GROUP_MODE)?;
        Ok(())
    }
}

/// Metadata recorded per file in [`MemoryAccountFs`] (for portable unit tests and verification).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryFile {
    pub data: Vec<u8>,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}

/// Portable in-memory implementation of [`AccountFs`] with optional fault injection to test
/// crash-atomic temp-file + `rename()` behavior.
#[derive(Clone, Debug, Default)]
pub struct MemoryAccountFs {
    pub files: BTreeMap<String, MemoryFile>,
    pub dirs: BTreeMap<String, (u16, u32, u32)>,
    pub fail_next_rename: bool,
    pub fail_next_write: bool,
    pub write_log: Vec<(String, u16, u32, u32)>,
    pub rename_log: Vec<(String, String)>,
}

impl MemoryAccountFs {
    pub fn seeded() -> Self {
        let mut fs = Self::default();
        seed_default_etc(&mut fs).expect("default /etc seed");
        fs.write_log.clear();
        fs.rename_log.clear();
        fs
    }
}

impl AccountFs for MemoryAccountFs {
    fn read_file(&self, path: &str) -> Result<Vec<u8>> {
        self.files
            .get(path)
            .map(|f| f.data.clone())
            .ok_or_else(|| Error::new(Errno::ENOENT))
    }

    fn write_file(&mut self, path: &str, data: &[u8], mode: u16, uid: u32, gid: u32) -> Result<()> {
        if self.fail_next_write {
            self.fail_next_write = false;
            return Err(Error::because(Errno::EIO, "injected write failure"));
        }
        self.write_log.push((path.to_owned(), mode, uid, gid));
        self.files.insert(
            path.to_owned(),
            MemoryFile {
                data: data.to_vec(),
                mode,
                uid,
                gid,
            },
        );
        Ok(())
    }

    fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        if self.fail_next_rename {
            self.fail_next_rename = false;
            return Err(Error::because(Errno::EIO, "injected rename failure"));
        }
        self.rename_log.push((from.to_owned(), to.to_owned()));
        if let Some(file) = self.files.remove(from) {
            self.files.insert(to.to_owned(), file);
            return Ok(());
        }
        if let Some(dir_meta) = self.dirs.remove(from) {
            self.dirs.insert(to.to_owned(), dir_meta);
            let prefix = format!("{from}/");
            let child_files: Vec<String> = self
                .files
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for old_key in child_files {
                if let Some(f) = self.files.remove(&old_key) {
                    self.files
                        .insert(format!("{to}{}", &old_key[from.len()..]), f);
                }
            }
            let child_dirs: Vec<String> = self
                .dirs
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for old_key in child_dirs {
                if let Some(d) = self.dirs.remove(&old_key) {
                    self.dirs
                        .insert(format!("{to}{}", &old_key[from.len()..]), d);
                }
            }
            return Ok(());
        }
        Err(Error::new(Errno::ENOENT))
    }

    fn remove_file(&mut self, path: &str) -> Result<()> {
        self.files
            .remove(path)
            .map(|_| ())
            .ok_or_else(|| Error::new(Errno::ENOENT))
    }

    fn exists(&self, path: &str) -> bool {
        self.files.contains_key(path) || self.dirs.contains_key(path)
    }

    fn mkdir_p(&mut self, path: &str, mode: u16, uid: u32, gid: u32) -> Result<()> {
        let mut cur = String::new();
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        for (i, part) in parts.iter().enumerate() {
            cur.push('/');
            cur.push_str(part);
            let is_leaf = i + 1 == parts.len();
            if is_leaf {
                self.dirs.insert(cur.clone(), (mode, uid, gid));
            } else {
                self.dirs.entry(cur.clone()).or_insert((0o755, 0, 0));
            }
        }
        Ok(())
    }

    fn remove_dir_all(&mut self, path: &str) -> Result<()> {
        let prefix = format!("{path}/");
        self.files.retain(|k, _| !k.starts_with(&prefix));
        self.dirs
            .retain(|k, _| k != path && !k.starts_with(&prefix));
        Ok(())
    }
}
