//! Portable Files app state machine, formatting, config persistence, and wire types
//! for `/usr/bin/files` (`#63` `L6b-1`).
//!
//! All directory sorting, permission/ACL refusal formatting, path resolution (`~`, relative,
//! `..`), MP4 faststart inspection, `~/.config/os/files.json` atomic persistence, and
//! Document UI / control-socket wire messages live here so they are unit-tested on host
//! without requiring a WASI runtime.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use abi::Errno;
use os_core::{Entry, completion::runnable, parent, resolve};
use serde::{Deserialize, Serialize};

/// Relative path under `$HOME` where `/usr/bin/files` persists its last directory.
pub const CONFIG_REL_PATH: &str = ".config/os/files.json";

/// Current schema version for `~/.config/os/files.json`.
pub const CONFIG_VERSION: u32 = 1;

/// Notice shown when an upload is requested while another upload is already active.
pub const BUSY_NOTICE: &str = "An upload is going on in this page; wait for it, or cancel it";

/// Maximum length of a window title accepted by the GUI v1 compositor.
const MAX_TITLE_CHARS: usize = 128;

/// Rendered view of one directory entry sent to the sealed Files Document iframe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesEntryView {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub directory: bool,
    pub runnable: bool,
    #[serde(default)]
    pub link: Option<String>,
    pub denied: bool,
    #[serde(default)]
    pub refusal: Option<String>,
    pub size_label: String,
    pub title: String,
}

/// Wire message sent by the sealed Files Document iframe to `/usr/bin/files`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum FilesUiMsg {
    Ready {},
    Nav { path: String },
    Up {},
    Refresh {},
    Open { name: String },
    Upload {},
    CancelUpload {},
    DismissProgress {},
    OpenMounts {},
}

/// Wire message sent by `/usr/bin/files` to the sealed Files Document iframe
/// (chunked automatically via `gui_doc::chunk_document_message` when `> 4096` bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum FilesHostMsg {
    State {
        cwd: String,
        can_up: bool,
        entries: Vec<FilesEntryView>,
        error: String,
        notice: String,
        keep_scroll: bool,
    },
    Notice {
        text: String,
    },
    Progress {
        text: String,
        uploading: bool,
    },
    Focus {},
}

/// Wire request accepted on `/run/user/<uid>/files.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum FilesControlReq {
    OpenDir { path: String },
    Refresh {},
    TriggerUpload {},
    Focus {},
}

/// Wire reply returned on `/run/user/<uid>/files.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesControlReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Persisted `~/.config/os/files.json` document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesConfig {
    pub version: u32,
    pub cwd: String,
}

/// Outcome of loading `~/.config/os/files.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigLoadOutcome {
    Loaded(String),
    Missing,
    /// File has `version > CONFIG_VERSION`; preserve it untouched (do not overwrite).
    NewerVersion {
        version: u32,
    },
    Invalid,
}

/// Load `~/.config/os/files.json` safely, gating unknown future versions without overwriting.
pub fn load_config_file(path: &Path) -> ConfigLoadOutcome {
    let raw = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return ConfigLoadOutcome::Missing,
        Err(_) => return ConfigLoadOutcome::Invalid,
    };
    if raw.len() > 16 * 1024 {
        return ConfigLoadOutcome::Invalid;
    }
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(&raw) else {
        return ConfigLoadOutcome::Invalid;
    };
    if let Some(v) = val.get("version").and_then(|v| v.as_u64())
        && v > u64::from(CONFIG_VERSION)
    {
        return ConfigLoadOutcome::NewerVersion {
            version: v.min(u64::from(u32::MAX)) as u32,
        };
    }
    match serde_json::from_value::<FilesConfig>(val) {
        Ok(cfg)
            if cfg.version == CONFIG_VERSION
                && cfg.cwd.starts_with('/')
                && !cfg.cwd.contains('\0') =>
        {
            ConfigLoadOutcome::Loaded(cfg.cwd)
        }
        _ => ConfigLoadOutcome::Invalid,
    }
}

/// Atomically persist `~/.config/os/files.json` (mode `0600`, parent dir `0700`).
pub fn save_config_file_atomic(path: &Path, cwd: &str) -> io::Result<()> {
    if !cwd.starts_with('/') || cwd.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid cwd path",
        ));
    }
    if let Some(parent_dir) = path.parent() {
        std::fs::create_dir_all(parent_dir)?;
        let _ = os_posix::chmod(parent_dir, 0o700);
    }
    let payload = serde_json::to_vec(&FilesConfig {
        version: CONFIG_VERSION,
        cwd: cwd.to_owned(),
    })
    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(&payload)?;
        f.flush()?;
    }
    let _ = os_posix::chmod(&tmp, 0o600);
    std::fs::rename(&tmp, path)?;
    let _ = os_posix::chmod(path, 0o600);
    Ok(())
}

/// Sort directory entries identically to the retired Files view: directories first,
/// then lexicographically by name.
pub fn sort_entries(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        b.directory
            .cmp(&a.directory)
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// How much of an in-flight upload or recording has arrived, shown in place of file size.
pub fn upload_progress_label(entry: &Entry) -> Option<String> {
    let uploaded = entry.uploaded?;
    if entry.recording {
        return Some("● recording".into());
    }
    Some(format!(
        "↑ {}%",
        (uploaded * 100).checked_div(entry.size).unwrap_or(100)
    ))
}

/// Convert an `os_core::Entry` into the exact view model expected by the Files Document UI.
pub fn entry_view(entry: &Entry) -> FilesEntryView {
    let linked = entry.link.is_some();
    let is_runnable = runnable(entry);
    // What the account may not open shows dimmed, and says why when clicked.
    // Executables (`.wasm` or execute bit) remain clickable so Terminal can launch or report errno.
    let denied = entry.denied && !is_runnable;
    let refusal = denied.then(|| {
        format!(
            "Permission denied: {} is {} {}:{}",
            entry.name,
            entry.mode_line().trim_end(),
            entry.owner,
            entry.group
        )
    });
    let base_title = format!(
        "{} {}:{}{}",
        entry.mode_line(),
        entry.owner,
        entry.group,
        entry
            .link
            .as_ref()
            .map(|t| format!(" -> {t}"))
            .unwrap_or_default()
    );
    let title = if denied {
        format!("{base_title} · permission denied")
    } else {
        base_title
    };
    let size_label = if linked {
        "→".to_owned()
    } else if entry.directory {
        String::new()
    } else {
        upload_progress_label(entry)
            .unwrap_or_else(|| format!("{:.1} KB", entry.size as f64 / 1000.0))
    };
    let kind = if entry.directory {
        "directory".to_owned()
    } else {
        entry.kind.clone()
    };
    FilesEntryView {
        name: entry.name.clone(),
        path: entry.path.clone(),
        kind,
        directory: entry.directory,
        runnable: is_runnable,
        link: entry.link.clone(),
        denied,
        refusal,
        size_label,
        title,
    }
}

/// Resolve a user-typed location against `cwd` and `home` (`~` / `~/...`, relative, `..`).
pub fn resolve_location(cwd: &str, home: &str, typed: &str) -> Result<String, String> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Ok(cwd.to_owned());
    }
    let expanded = if typed == "~" {
        home.to_owned()
    } else if let Some(rest) = typed.strip_prefix("~/") {
        format!("{}/{rest}", home.trim_end_matches('/'))
    } else {
        typed.to_owned()
    };
    resolve(cwd, &expanded)
}

/// Format the window title `Files — <cwd>`, clamping cleanly to compositor limits.
pub fn window_title(cwd: &str) -> String {
    let full = format!("Files — {cwd}");
    if full.chars().count() <= MAX_TITLE_CHARS {
        full
    } else {
        full.chars().take(MAX_TITLE_CHARS).collect()
    }
}

/// Join a directory and sanitized filename into a clean absolute path.
pub fn join_child(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", dir.trim_end_matches('/'))
    }
}

/// Validate an uploaded filename before creating a file in `cwd`.
pub fn sanitize_upload_name(raw: &str) -> Result<&str, &'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
        || trimmed.len() > abi::NAME_MAX
    {
        return Err("Invalid filename");
    }
    Ok(trimmed)
}

/// Map POSIX `openat(O_WRONLY | O_CREAT | O_EXCL)` errors to exact user-facing upload notices.
pub fn upload_open_error_message(errno: Errno) -> String {
    match errno {
        Errno::EEXIST => "File already exists; rename it before uploading".into(),
        Errno::EISDIR => "A directory with this name already exists".into(),
        Errno::EACCES | Errno::EPERM | Errno::EROFS => "Permission denied".into(),
        other => other.text().to_owned(),
    }
}

/// Whether `name` has an MP4-family extension that warrants faststart inspection.
pub fn is_mp4_family(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".mp4")
        || lower.ends_with(".m4v")
        || lower.ends_with(".mov")
        || lower.ends_with(".m4a")
}

/// Read only top-level ISO BMFF box headers to determine whether `moov` precedes `mdat`.
pub fn inspect_faststart_reader<R: Read + Seek>(
    reader: &mut R,
    file_size: u64,
) -> Result<bool, String> {
    let mut offset: u64 = 0;
    let mut moov: Option<u64> = None;
    let mut mdat: Option<u64> = None;
    let mut count: u32 = 0;
    let mut header_buf = [0u8; 16];

    while offset < file_size {
        count += 1;
        if count > 10_000 {
            return Err("Too many MP4 boxes to inspect".into());
        }
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        let avail = (file_size - offset).min(16) as usize;
        if avail < 8 {
            return Err("Incomplete MP4 box header".into());
        }
        reader
            .read_exact(&mut header_buf[..avail])
            .map_err(|_| "Incomplete MP4 box header".to_owned())?;

        let raw_len = u32::from_be_bytes(header_buf[0..4].try_into().unwrap());
        let box_type = &header_buf[4..8];
        let (length, header_len): (u64, u64) = if raw_len == 1 {
            if avail < 16 {
                return Err("Incomplete extended MP4 box".into());
            }
            let big = u64::from_be_bytes(header_buf[8..16].try_into().unwrap());
            (big, 16)
        } else if raw_len == 0 {
            (file_size - offset, 8)
        } else {
            (u64::from(raw_len), 8)
        };
        if length < header_len || offset.checked_add(length).is_none_or(|end| end > file_size) {
            return Err("Invalid MP4 box length".into());
        }
        if box_type == b"moov" && moov.is_none() {
            moov = Some(offset);
        }
        if box_type == b"mdat" && mdat.is_none() {
            mdat = Some(offset);
        }
        offset += length;
    }

    match (moov, mdat) {
        (Some(moov_off), Some(mdat_off)) => Ok(moov_off < mdat_off),
        _ => Err("Complete moov / mdat boxes were not found; cannot verify faststart".into()),
    }
}

/// Build the user-facing faststart warning for an uploaded MP4-family file, or `None` if faststart.
pub fn faststart_warning_for_reader<R: Read + Seek>(
    name: &str,
    size: u64,
    reader: &mut R,
) -> Option<String> {
    let fix = format!(
        "to stream it, run faststart '{}' once it has uploaded",
        name.replace('\'', "'\\''")
    );
    match inspect_faststart_reader(reader, size) {
        Ok(true) => None,
        Ok(false) => Some(format!(
            "not faststart: its index (moov) is after its media, so it plays only once the end has downloaded, and not until its upload completes; {fix}"
        )),
        Err(msg) => Some(format!(
            "faststart could not be checked ({msg}); if it does not play while downloading, {fix}"
        )),
    }
}

/// Pure portable state machine for `/usr/bin/files`.
#[derive(Clone, Debug)]
pub struct FilesCore {
    pub cwd: String,
    pub home: String,
    pub entries: Vec<Entry>,
    pub error: String,
    pub notice: String,
    pub progress: String,
    pub uploading: bool,
    pub config_read_only: bool,
}

impl FilesCore {
    pub fn new(cwd: String, home: String, config_read_only: bool) -> Self {
        Self {
            cwd,
            home,
            entries: Vec::new(),
            error: String::new(),
            notice: String::new(),
            progress: String::new(),
            uploading: false,
            config_read_only,
        }
    }

    /// Parent directory of `self.cwd`.
    pub fn parent_dir(&self) -> String {
        parent(&self.cwd).to_owned()
    }

    /// Resolve a user-typed location relative to `self.cwd` and `self.home`.
    pub fn resolve_typed(&self, typed: &str) -> Result<String, String> {
        resolve_location(&self.cwd, &self.home, typed)
    }

    /// Update current listing state and return the corresponding `FilesHostMsg::State`.
    pub fn apply_listing(
        &mut self,
        path: String,
        listed: Result<Vec<Entry>, String>,
        keep_scroll: bool,
    ) -> FilesHostMsg {
        self.cwd = path;
        match listed {
            Ok(mut entries) => {
                sort_entries(&mut entries);
                self.entries = entries;
                self.error.clear();
            }
            Err(err) => {
                self.entries.clear();
                self.error = err;
            }
        }
        self.state_message(keep_scroll)
    }

    /// Snapshot the current directory state for transmission to the Document iframe.
    pub fn state_message(&self, keep_scroll: bool) -> FilesHostMsg {
        FilesHostMsg::State {
            cwd: self.cwd.clone(),
            can_up: self.cwd != "/",
            entries: self.entries.iter().map(entry_view).collect(),
            error: self.error.clone(),
            notice: self.notice.clone(),
            keep_scroll,
        }
    }

    /// Look up a listed entry by display name.
    pub fn find_entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// Update notice text and return a `FilesHostMsg::Notice`.
    pub fn set_notice(&mut self, text: impl Into<String>) -> FilesHostMsg {
        let text = text.into();
        self.notice = text.clone();
        FilesHostMsg::Notice { text }
    }

    /// Update upload progress banner and return a `FilesHostMsg::Progress`.
    pub fn set_progress(&mut self, text: impl Into<String>, uploading: bool) -> FilesHostMsg {
        let text = text.into();
        self.progress = text.clone();
        self.uploading = uploading;
        if !uploading && self.notice == BUSY_NOTICE {
            self.notice.clear();
        }
        FilesHostMsg::Progress { text, uploading }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_entry(name: &str, directory: bool, mode: u16, denied: bool) -> Entry {
        Entry {
            name: name.into(),
            path: format!("/home/user/{name}"),
            size: 1500,
            kind: if directory {
                "directory".into()
            } else {
                os_core::kind(name).into()
            },
            directory,
            mode,
            owner: "user".into(),
            group: "user".into(),
            link: None,
            acl: false,
            denied,
            uploaded: None,
            recording: false,
            ..Entry::default()
        }
    }

    #[test]
    fn sorts_directories_first_then_lexicographical() {
        let mut items = vec![
            sample_entry("zeta.txt", false, 0o644, false),
            sample_entry("docs", true, 0o755, false),
            sample_entry("alpha.txt", false, 0o644, false),
            sample_entry("bin", true, 0o755, false),
        ];
        sort_entries(&mut items);
        let names: Vec<&str> = items.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["bin", "docs", "alpha.txt", "zeta.txt"]);
    }

    #[test]
    fn resolves_tilde_relative_and_parent_locations() {
        assert_eq!(
            resolve_location("/tmp", "/home/alice", "~").unwrap(),
            "/home/alice"
        );
        assert_eq!(
            resolve_location("/tmp", "/home/alice", "~/docs/../notes").unwrap(),
            "/home/alice/notes"
        );
        assert_eq!(
            resolve_location("/home/alice/docs", "/home/alice", "..").unwrap(),
            "/home/alice"
        );
        assert_eq!(
            resolve_location("/home/alice", "/home/alice", "sub/dir/").unwrap(),
            "/home/alice/sub/dir"
        );
    }

    #[test]
    fn formats_denied_runnable_and_symlink_entry_views() {
        let mut secret = sample_entry("secret.txt", false, 0o600, true);
        secret.owner = "root".into();
        secret.group = "root".into();
        let v = entry_view(&secret);
        assert!(v.denied);
        assert_eq!(
            v.refusal.as_deref(),
            Some("Permission denied: secret.txt is -rw------- root:root")
        );
        assert!(v.title.ends_with(" · permission denied"));
        assert_eq!(v.size_label, "1.5 KB");

        // Execute-only .wasm file (`denied == true`, `runnable == true`) remains clickable!
        let exec_wasm = sample_entry("execute-only.wasm", false, 0o111, true);
        let v_wasm = entry_view(&exec_wasm);
        assert!(v_wasm.runnable);
        assert!(!v_wasm.denied);
        assert_eq!(v_wasm.refusal, None);

        // Symlink renders arrow in size column and target in title.
        let mut lnk = sample_entry("latest", false, 0o777, false);
        lnk.link = Some("docs/v2.md".into());
        let v_lnk = entry_view(&lnk);
        assert_eq!(v_lnk.size_label, "→");
        assert!(v_lnk.title.contains(" -> docs/v2.md"));
    }

    #[test]
    fn wire_messages_reject_unknown_fields() {
        let ui: FilesUiMsg = serde_json::from_str(r#"{"t":"nav","path":"/tmp"}"#).unwrap();
        assert_eq!(
            ui,
            FilesUiMsg::Nav {
                path: "/tmp".into()
            }
        );
        assert!(
            serde_json::from_str::<FilesUiMsg>(r#"{"t":"nav","path":"/tmp","extra":1}"#).is_err()
        );
        let ctrl: FilesControlReq =
            serde_json::from_str(r#"{"op":"open_dir","path":"/home/user"}"#).unwrap();
        assert_eq!(
            ctrl,
            FilesControlReq::OpenDir {
                path: "/home/user".into()
            }
        );
        assert!(serde_json::from_str::<FilesControlReq>(r#"{"op":"focus","rogue":true}"#).is_err());
    }

    #[test]
    fn config_persistence_roundtrips_and_preserves_future_versions() {
        let dir = std::env::temp_dir().join(format!(
            "files-cfg-test-{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("files.json");
        assert_eq!(load_config_file(&path), ConfigLoadOutcome::Missing);
        save_config_file_atomic(&path, "/home/user/docs").unwrap();
        assert_eq!(
            load_config_file(&path),
            ConfigLoadOutcome::Loaded("/home/user/docs".into())
        );

        std::fs::write(&path, r#"{"version":99,"cwd":"/future","new_key":true}"#).unwrap();
        assert_eq!(
            load_config_file(&path),
            ConfigLoadOutcome::NewerVersion { version: 99 }
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn faststart_inspector_detects_moov_before_and_after_mdat() {
        let make_box = |ty: &[u8; 4], payload_len: usize| -> Vec<u8> {
            let mut v = Vec::with_capacity(8 + payload_len);
            v.extend_from_slice(&((8 + payload_len) as u32).to_be_bytes());
            v.extend_from_slice(ty);
            v.resize(8 + payload_len, 0);
            v
        };
        let mut fast = Vec::new();
        fast.extend(make_box(b"ftyp", 8));
        fast.extend(make_box(b"moov", 16));
        fast.extend(make_box(b"mdat", 32));
        let mut cur = Cursor::new(&fast);
        assert_eq!(
            faststart_warning_for_reader("good.mp4", fast.len() as u64, &mut cur),
            None
        );

        let mut tail = Vec::new();
        tail.extend(make_box(b"ftyp", 8));
        tail.extend(make_box(b"mdat", 32));
        tail.extend(make_box(b"moov", 16));
        let mut cur = Cursor::new(&tail);
        let warn = faststart_warning_for_reader("tail-moov.mp4", tail.len() as u64, &mut cur)
            .expect("expected warning");
        assert!(warn.contains("not faststart: its index (moov) is after its media"));
        assert!(warn.contains("run faststart 'tail-moov.mp4' once it has uploaded"));
    }

    #[test]
    fn sanitizes_upload_names_and_maps_open_errnos() {
        assert_eq!(sanitize_upload_name("report.txt"), Ok("report.txt"));
        for bad in ["", ".", "..", "a/b", "a\\b", "bad\0name"] {
            assert!(
                sanitize_upload_name(bad).is_err(),
                "expected err for {bad:?}"
            );
        }
        assert_eq!(
            upload_open_error_message(Errno::EEXIST),
            "File already exists; rename it before uploading"
        );
        assert_eq!(
            upload_open_error_message(Errno::EISDIR),
            "A directory with this name already exists"
        );
        assert_eq!(
            upload_open_error_message(Errno::EACCES),
            "Permission denied"
        );
    }
}
