//! Authenticated `HostAdapter v2` remote seat/PTY wire protocol, `$STATE/seat-tokens.json`
//! (`0600`) constant-time SHA-256 token store, and `$STATE/host-ctl.sock` (`0600`) control frames.

use crate::dev_backend::random_hex;
use crate::kernel_actor::now_secs;
use crate::kernel_rpc::HostInspect;
use abi::Errno;
use abi::contract::{Boundary, HOST_ADAPTER_VERSION, Hello, negotiate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const TOKEN_PREFIX: &str = "osnt_";

/// The server's `HostAdapter v2` handshake banner.
pub fn server_hello() -> Hello {
    Hello {
        boundary: Boundary::HostAdapter,
        versions: vec![HOST_ADAPTER_VERSION],
    }
}

/// Negotiate `HostAdapter v2` against a peer's `Hello`, returning `EPROTONOSUPPORT` on mismatch.
pub fn negotiate_host_adapter(peer: &Hello) -> Result<u32, Errno> {
    negotiate(&server_hello(), peer).ok_or(Errno::EPROTONOSUPPORT)
}

/// Client -> Server frames over Unix socket, TCP, or RFC-6455 WebSocket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientFrame {
    Hello {
        boundary: Boundary,
        versions: Vec<u32>,
    },
    Auth {
        token: String,
    },
    ListSeats,
    Inspect,
    Attach {
        #[serde(default)]
        seat: Option<u32>,
        #[serde(default)]
        spawn_if_missing: bool,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    Input {
        data_b64: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Detach,
    Exec {
        argv: Vec<String>,
        #[serde(default)]
        env: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        stdin_b64: Option<String>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
}

/// Server -> Client frames over Unix socket, TCP, or RFC-6455 WebSocket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerFrame {
    HelloOk {
        boundary: Boundary,
        version: u32,
        instance_id: String,
        release_id: String,
    },
    AuthOk {
        token_id: String,
        uid: u32,
        allowed_seats: Vec<u32>,
        can_exec: bool,
    },
    Seats {
        seats: Vec<u32>,
    },
    Inspect(HostInspect),
    Attached {
        seat: u32,
        cols: u16,
        rows: u16,
        scrollback_b64: String,
    },
    Output {
        seat: u32,
        data_b64: String,
    },
    Detached {
        seat: u32,
    },
    ExecResult {
        exit_code: i32,
        signal: Option<u8>,
        stdout_b64: String,
        stderr_b64: String,
    },
    Error {
        errno: String,
        code: i32,
        message: String,
    },
}

impl ServerFrame {
    pub fn err(errno: Errno, message: impl Into<String>) -> Self {
        Self::Error {
            errno: format!("{errno:?}"),
            code: errno as i32,
            message: message.into(),
        }
    }
}

/// Persisted token record stored in `$STATE/seat-tokens.json` (never stores the raw secret!).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub label: String,
    pub token_sha256: String,
    pub uid: u32,
    /// Empty means all seats permitted; otherwise explicit list of PTY seat numbers.
    #[serde(default)]
    pub allowed_seats: Vec<u32>,
    #[serde(default = "default_true")]
    pub can_exec: bool,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_at: Option<u64>,
}

fn default_true() -> bool {
    true
}

impl TokenRecord {
    pub fn permits_seat(&self, seat: u32) -> bool {
        self.allowed_seats.is_empty() || self.allowed_seats.contains(&seat)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct TokenFile {
    version: u32,
    tokens: Vec<TokenRecord>,
}

/// Constant-time 32-byte digest comparison (no early exit).
fn ct_eq_hex(a_hex: &str, b_bytes: &[u8; 32]) -> bool {
    if a_hex.len() != 64 {
        return false;
    }
    let mut a = [0u8; 32];
    for i in 0..32 {
        let Ok(byte) = u8::from_str_radix(&a_hex[i * 2..i * 2 + 2], 16) else {
            return false;
        };
        a[i] = byte;
    }
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b_bytes[i];
    }
    diff == 0
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Thread-safe, `0600` file-backed seat token store at `$STATE/seat-tokens.json`.
pub struct TokenStore {
    path: PathBuf,
    lock: Mutex<()>,
}

impl TokenStore {
    pub fn new(state_dir: impl AsRef<Path>) -> Self {
        Self {
            path: state_dir.as_ref().join("seat-tokens.json"),
            lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn load_unlocked(&self) -> Result<TokenFile, String> {
        if !self.path.exists() {
            return Ok(TokenFile {
                version: 1,
                tokens: Vec::new(),
            });
        }
        let raw = fs::read(&self.path).map_err(|e| format!("read {}: {e}", self.path.display()))?;
        let parsed: TokenFile = serde_json::from_slice(&raw)
            .map_err(|e| format!("parse {}: {e}", self.path.display()))?;
        Ok(parsed)
    }

    fn save_unlocked(&self, file: &TokenFile) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create dir {}: {e}", parent.display()))?;
        }
        let bytes =
            serde_json::to_vec_pretty(file).map_err(|e| format!("serialize tokens: {e}"))?;
        let tmp = self
            .path
            .with_extension(format!("json.tmp.{}", random_hex(6)));
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp)
                .map_err(|e| format!("create {}: {e}", tmp.display()))?;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
            f.write_all(&bytes)
                .map_err(|e| format!("write {}: {e}", tmp.display()))?;
            let _ = f.sync_all();
        }
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        fs::rename(&tmp, &self.path)
            .map_err(|e| format!("rename {} -> {}: {e}", tmp.display(), self.path.display()))?;
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        Ok(())
    }

    /// Create a new scoped seat token. Returns `(record, plaintext_secret)`.
    pub fn create_token(
        &self,
        uid: u32,
        label: String,
        allowed_seats: Vec<u32>,
        can_exec: bool,
        ttl_secs: Option<u64>,
    ) -> Result<(TokenRecord, String), String> {
        let _g = self.lock.lock().unwrap();
        let mut file = self.load_unlocked()?;
        let now = now_secs();
        let id = format!("tok_{}", random_hex(8));
        let secret = format!("{TOKEN_PREFIX}{}", random_hex(32));
        let digest = sha256_bytes(secret.as_bytes());
        let record = TokenRecord {
            id,
            label,
            token_sha256: os_image::hex(&digest),
            uid,
            allowed_seats,
            can_exec,
            created_at: now,
            expires_at: ttl_secs.map(|t| now.saturating_add(t)),
            revoked: false,
            revoked_at: None,
        };
        file.version = 1;
        file.tokens.push(record.clone());
        self.save_unlocked(&file)?;
        Ok((record, secret))
    }

    /// List all persisted tokens (metadata only; hashes stay private unless inspected).
    pub fn list_tokens(&self) -> Result<Vec<TokenRecord>, String> {
        let _g = self.lock.lock().unwrap();
        Ok(self.load_unlocked()?.tokens)
    }

    /// Revoke all tokens whose `id` equals or starts with `id_or_prefix`.
    /// Returns the list of newly/already revoked token IDs.
    pub fn revoke_token(&self, id_or_prefix: &str) -> Result<Vec<String>, String> {
        if id_or_prefix.is_empty() {
            return Err("token id/prefix must not be empty".into());
        }
        let _g = self.lock.lock().unwrap();
        let mut file = self.load_unlocked()?;
        let now = now_secs();
        let mut matched = Vec::new();
        for tok in &mut file.tokens {
            if tok.id == id_or_prefix || tok.id.starts_with(id_or_prefix) {
                tok.revoked = true;
                if tok.revoked_at.is_none() {
                    tok.revoked_at = Some(now);
                }
                matched.push(tok.id.clone());
            }
        }
        if matched.is_empty() {
            return Err(format!("no token matching '{id_or_prefix}'"));
        }
        self.save_unlocked(&file)?;
        Ok(matched)
    }

    /// Constant-time authenticate a presented bearer token against `$STATE/seat-tokens.json`.
    pub fn authenticate(&self, presented: &str) -> Result<TokenRecord, Errno> {
        if !presented.starts_with(TOKEN_PREFIX) || presented.len() < TOKEN_PREFIX.len() + 32 {
            return Err(Errno::EACCES);
        }
        let _g = self.lock.lock().unwrap();
        let file = self.load_unlocked().map_err(|_| Errno::EACCES)?;
        let presented_digest = sha256_bytes(presented.as_bytes());
        let now = now_secs();

        let mut matched: Option<TokenRecord> = None;
        for rec in &file.tokens {
            if ct_eq_hex(&rec.token_sha256, &presented_digest) {
                matched = Some(rec.clone());
            }
        }
        let Some(rec) = matched else {
            return Err(Errno::EACCES);
        };
        if rec.revoked || rec.is_expired(now) {
            return Err(Errno::EACCES);
        }
        Ok(rec)
    }
}

/// Control request sent over `$STATE/host-ctl.sock` (`0600`) by `os-native token|inspect`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    CreateToken {
        uid: u32,
        label: String,
        #[serde(default)]
        allowed_seats: Vec<u32>,
        #[serde(default = "default_true")]
        can_exec: bool,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    ListTokens,
    RevokeToken {
        id_or_prefix: String,
    },
    Inspect,
}

/// Control reply sent over `$STATE/host-ctl.sock`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ControlReply {
    TokenCreated {
        record: TokenRecord,
        token: String,
    },
    Tokens {
        tokens: Vec<TokenRecord>,
    },
    Revoked {
        token_ids: Vec<String>,
        disconnected_clients: usize,
    },
    Inspect(HostInspect),
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn host_adapter_v2_negotiation_and_rejection() {
        let ok_hello = Hello {
            boundary: Boundary::HostAdapter,
            versions: vec![HOST_ADAPTER_VERSION],
        };
        assert_eq!(negotiate_host_adapter(&ok_hello), Ok(HOST_ADAPTER_VERSION));

        let bad_ver = Hello {
            boundary: Boundary::HostAdapter,
            versions: vec![1],
        };
        assert_eq!(
            negotiate_host_adapter(&bad_ver).unwrap_err(),
            Errno::EPROTONOSUPPORT
        );

        let bad_boundary = Hello {
            boundary: Boundary::ServiceAuth,
            versions: vec![HOST_ADAPTER_VERSION],
        };
        assert_eq!(
            negotiate_host_adapter(&bad_boundary).unwrap_err(),
            Errno::EPROTONOSUPPORT
        );
    }

    #[test]
    fn token_store_0600_auth_and_revocation() {
        let dir = std::env::temp_dir().join(format!("os-native-tok-unit-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let store = TokenStore::new(&dir);
        let (rec, secret) = store
            .create_token(1000, "unit".into(), vec![0], true, None)
            .unwrap();
        let mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "seat-tokens.json must be 0600");

        let authed = store.authenticate(&secret).expect("valid token must auth");
        assert_eq!(authed.id, rec.id);
        assert_eq!(authed.uid, 1000);
        assert!(authed.permits_seat(0));
        assert!(!authed.permits_seat(1));

        assert_eq!(store.authenticate("osnt_bad").unwrap_err(), Errno::EACCES);

        let revoked = store.revoke_token(&rec.id).unwrap();
        assert_eq!(revoked, vec![rec.id]);
        assert_eq!(store.authenticate(&secret).unwrap_err(), Errno::EACCES);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
