//! Portable Editor controller and atomic draft store (`#64` `L6c-1`).
//!
//! Keeps all file/draft policy, language detection, conflict messages, and Document wire types
//! independent of WASI/browser transport so they are thoroughly unit-tested natively.

use abi::Errno;
use abi::gui::sha256_hex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const MAX_EDIT_BYTES: usize = 2_000_000;
pub const MAX_EDITOR_ASSEMBLED_BYTES: usize = 2_600_000;
pub const MAX_EDITOR_CHUNKS: usize = 1024;
pub const DRAFT_VERSION: u32 = 1;
pub const DRAFTS_REL_DIR: &str = ".local/state/os/editor/drafts";
pub const MAX_DRAFTS: usize = 32;
const MAX_DRAFT_FILE_BYTES: usize = 2_600_000;

/// Conflict category surfaced by `/usr/bin/editor` when conditional save fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    ChangedElsewhere,
    CreatedElsewhere,
    DeletedElsewhere,
}

/// Messages sent from the sealed Editor Document iframe (`web/gui/editor/editor.mjs`) to `/usr/bin/editor`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum EditorUiMsg {
    Ready {},
    Dirty {
        dirty: bool,
    },
    DraftSync {
        content: String,
    },
    Save {
        content: String,
        #[serde(default)]
        force_overwrite: bool,
        #[serde(default)]
        save_as_copy: bool,
    },
    Close {
        #[serde(default)]
        force: bool,
        #[serde(default)]
        dirty: bool,
    },
    Download {
        content: String,
    },
    RestoreDraft {},
    DiscardDraft {},
    ReloadFromDisk {},
}

/// Messages sent from `/usr/bin/editor` to the sealed Editor Document iframe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum EditorHostMsg {
    Init {
        path: String,
        language: String,
        content: String,
        read_only: bool,
        existing: bool,
        dirty: bool,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        load_error: Option<String>,
        has_draft: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        conflict: Option<ConflictKind>,
    },
    Status {
        status: String,
        dirty: bool,
        saving: bool,
        read_only: bool,
        existing: bool,
        show_discard: bool,
        has_draft: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        conflict: Option<ConflictKind>,
        #[serde(skip_serializing_if = "Option::is_none")]
        saved_content_sha256: Option<String>,
    },
    ReplaceContent {
        content: String,
        dirty: bool,
        status: String,
        read_only: bool,
        existing: bool,
        show_discard: bool,
        has_draft: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        conflict: Option<ConflictKind>,
    },
    Focus {},
}

/// Persisted recovery draft record (Contract v2 §2.12 versioned JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftRecord {
    pub version: u32,
    pub path: String,
    #[serde(default)]
    pub base_rev: Option<String>,
    pub updated_at_ms: u64,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DraftLoadOutcome {
    Loaded(DraftRecord),
    Missing,
    ResetOlder(u32),
    RefusedNewer(u32),
}

/// Detect the CodeMirror language identifier from a file path (matching `web/editor.mjs`).
pub fn language_for_path(path: &str) -> &'static str {
    let base = path.rsplit('/').next().unwrap_or(path);
    let Some((_, ext)) = base.rsplit_once('.') else {
        return "plain";
    };
    match ext.to_ascii_lowercase().as_str() {
        "md" | "markdown" => "markdown",
        "js" | "mjs" | "cjs" => "js",
        "jsx" => "jsx",
        "ts" => "ts",
        "tsx" => "tsx",
        "rs" => "rust",
        "py" => "python",
        "json" | "game" => "json",
        "html" | "htm" => "html",
        "css" => "css",
        "c" | "h" | "cc" | "cpp" | "hpp" => "cpp",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        "sh" | "bash" | "zsh" => "shell",
        _ => "plain",
    }
}

/// Sanitize a file basename for `ClientReq::ExportFile`.
pub fn export_filename(path: &str) -> String {
    let raw = path.rsplit('/').next().unwrap_or("draft.txt");
    let cleaned: String = raw
        .chars()
        .filter(|&c| c != '/' && c != '\\' && c != '\0' && !c.is_control())
        .collect();
    let trimmed = cleaned.trim_start_matches('.');
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        "draft.txt".into()
    } else if trimmed.len() > 200 {
        trimmed.chars().take(200).collect()
    } else {
        trimmed.to_owned()
    }
}

/// Suggest a sibling conflict-copy path (e.g. `/home/user/main.rs` -> `/home/user/main.copy.rs`).
pub fn copy_path_for(path: &str, suffix_num: u32) -> String {
    let (dir, name) = match path.rsplit_once('/') {
        Some(("", n)) => ("", n),
        Some((d, n)) => (d, n),
        None => ("", path),
    };
    let tag = if suffix_num <= 1 {
        "copy".to_owned()
    } else {
        format!("copy-{suffix_num}")
    };
    let copy_name = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() && !ext.is_empty() => format!("{stem}.{tag}.{ext}"),
        _ => format!("{name}.{tag}"),
    };
    if dir.is_empty() {
        format!("/{copy_name}")
    } else {
        format!("{dir}/{copy_name}")
    }
}

/// Map conditional-open `Errno` into the exact user-facing conflict message and kind.
pub fn save_error_message(errno: Errno, detail: Option<&str>) -> (String, Option<ConflictKind>) {
    match errno {
        Errno::ESTALE => (
            "File changed in another session; reopen it or download your draft to avoid overwriting changes"
                .into(),
            Some(ConflictKind::ChangedElsewhere),
        ),
        Errno::EEXIST => (
            "File was created by another session; reopen it".into(),
            Some(ConflictKind::CreatedElsewhere),
        ),
        Errno::ENOENT => (
            "File was deleted or moved; save it as a new file".into(),
            Some(ConflictKind::DeletedElsewhere),
        ),
        Errno::EACCES => ("Permission denied".into(), None),
        Errno::EROFS => ("Read-only file system".into(), None),
        _ => (
            detail
                .filter(|d| !d.is_empty())
                .unwrap_or_else(|| errno.text())
                .to_owned(),
            None,
        ),
    }
}

/// Validate raw bytes loaded from disk for text editing.
pub fn decode_editable_text(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_EDIT_BYTES {
        return Err("File exceeds 2 MB; download it to edit locally".into());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "The file contains binary data and cannot be edited as text".to_owned())?;
    if text.contains('\0') {
        return Err("The file contains binary data and cannot be edited as text".into());
    }
    Ok(text.to_owned())
}

pub fn window_title(path: &str) -> String {
    format!("Editor — {path}")
}

pub fn draft_path_for(home: &str, canonical_path: &str) -> PathBuf {
    let key = sha256_hex(canonical_path.as_bytes());
    Path::new(home)
        .join(DRAFTS_REL_DIR)
        .join(format!("{key}.json"))
}

pub fn parse_draft_record(bytes: &[u8]) -> DraftLoadOutcome {
    if bytes.len() > MAX_DRAFT_FILE_BYTES {
        return DraftLoadOutcome::ResetOlder(0);
    }
    let Ok(raw) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return DraftLoadOutcome::ResetOlder(0);
    };
    let Some(version) = raw
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return DraftLoadOutcome::ResetOlder(0);
    };
    if version > DRAFT_VERSION {
        return DraftLoadOutcome::RefusedNewer(version);
    }
    if version < DRAFT_VERSION {
        return DraftLoadOutcome::ResetOlder(version);
    }
    match serde_json::from_slice::<DraftRecord>(bytes) {
        Ok(rec) if rec.content.len() <= MAX_EDIT_BYTES && !rec.content.contains('\0') => {
            DraftLoadOutcome::Loaded(rec)
        }
        _ => DraftLoadOutcome::ResetOlder(version),
    }
}

pub fn load_draft(home: &str, canonical_path: &str) -> DraftLoadOutcome {
    let path = draft_path_for(home, canonical_path);
    match fs::read(&path) {
        Ok(bytes) => parse_draft_record(&bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => DraftLoadOutcome::Missing,
        Err(_) => DraftLoadOutcome::ResetOlder(0),
    }
}

fn set_mode(path: &Path, mode: u16) {
    #[cfg(target_os = "wasi")]
    {
        let _ = os_posix::chmod(path, u32::from(mode));
    }
    #[cfg(all(unix, not(target_os = "wasi")))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(u32::from(mode)));
    }
    #[cfg(not(any(unix, target_os = "wasi")))]
    {
        let _ = (path, mode);
    }
}

fn ensure_private_dir_chain(home: &str) -> io::Result<PathBuf> {
    let dir = Path::new(home).join(DRAFTS_REL_DIR);
    fs::create_dir_all(&dir)?;
    for rel in [
        ".local",
        ".local/state",
        ".local/state/os",
        ".local/state/os/editor",
        DRAFTS_REL_DIR,
    ] {
        set_mode(&Path::new(home).join(rel), 0o700);
    }
    Ok(dir)
}

/// Atomically persist a recovery draft (`0600` temp + `fsync` + `rename`) and enforce the
/// `MAX_DRAFTS` LRU cap.
pub fn save_draft_atomic(home: &str, record: &DraftRecord) -> io::Result<()> {
    if record.content.len() > MAX_EDIT_BYTES || record.content.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "draft exceeds 2 MB or contains NUL bytes",
        ));
    }
    let dir = ensure_private_dir_chain(home)?;
    let target = draft_path_for(home, &record.path);
    let bytes =
        serde_json::to_vec(record).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_DRAFT_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "encoded draft exceeds size limit",
        ));
    }

    let tmp_seq = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(1);
        SEQ.fetch_add(1, Ordering::Relaxed)
    };
    let tmp_path = dir.join(format!(".draft.tmp.{:x}.{tmp_seq}", record.updated_at_ms));
    let res = (|| -> io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(all(unix, not(target_os = "wasi")))]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp_path)?;
        set_mode(&tmp_path, 0o600);
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp_path, &target)?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp_path);
        return res;
    }
    prune_old_drafts(&dir, MAX_DRAFTS);
    Ok(())
}

/// Remove the recovery draft for `canonical_path` if present.
pub fn remove_draft(home: &str, canonical_path: &str) {
    let path = draft_path_for(home, canonical_path);
    let _ = fs::remove_file(path);
}

fn prune_old_drafts(dir: &Path, limit: usize) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let stamp = fs::read(&p)
            .ok()
            .and_then(|b| match parse_draft_record(&b) {
                DraftLoadOutcome::Loaded(r) => Some(r.updated_at_ms),
                _ => None,
            })
            .unwrap_or(0);
        files.push((stamp, p));
    }
    if files.len() <= limit {
        return;
    }
    files.sort_by_key(|(stamp, _)| *stamp);
    let excess = files.len() - limit;
    for (_, path) in files.into_iter().take(excess) {
        let _ = fs::remove_file(path);
    }
}

/// Pure editor state machine driven by `/usr/bin/editor`.
#[derive(Clone, Debug)]
pub struct EditorCore {
    pub path: String,
    pub language: String,
    pub content: String,
    pub base_rev: Option<String>,
    pub existing: bool,
    pub read_only: bool,
    pub dirty: bool,
    pub saving: bool,
    pub show_discard: bool,
    pub status: String,
    pub load_error: Option<String>,
    pub conflict: Option<ConflictKind>,
    pub pending_draft: Option<DraftRecord>,
    pub draft_read_only: bool,
}

impl EditorCore {
    pub fn from_loaded(
        path: String,
        content: String,
        base_rev: Option<String>,
        existing: bool,
        read_only: bool,
        draft: DraftLoadOutcome,
    ) -> Self {
        let language = language_for_path(&path).to_owned();
        let (pending_draft, draft_read_only) = match draft {
            DraftLoadOutcome::Loaded(rec) if rec.content != content => (Some(rec), false),
            DraftLoadOutcome::RefusedNewer(_) => (None, true),
            _ => (None, false),
        };
        let status = if read_only {
            "Read-only: your account does not have write permission".to_owned()
        } else if pending_draft.is_some() {
            "Unsaved recovery draft found. Restore or discard it.".to_owned()
        } else if existing {
            "Ctrl / Cmd S to save; Esc to close".to_owned()
        } else {
            "New file: save to create it at this path".to_owned()
        };
        Self {
            path,
            language,
            content,
            base_rev,
            existing,
            read_only,
            dirty: !existing,
            saving: false,
            show_discard: false,
            status,
            load_error: None,
            conflict: None,
            pending_draft,
            draft_read_only,
        }
    }

    pub fn from_load_error(path: String, error: String) -> Self {
        let language = language_for_path(&path).to_owned();
        Self {
            path,
            language,
            content: String::new(),
            base_rev: None,
            existing: false,
            read_only: true,
            dirty: false,
            saving: false,
            show_discard: false,
            status: error.clone(),
            load_error: Some(error),
            conflict: None,
            pending_draft: None,
            draft_read_only: false,
        }
    }

    pub fn init_message(&self) -> EditorHostMsg {
        EditorHostMsg::Init {
            path: self.path.clone(),
            language: self.language.clone(),
            content: self.content.clone(),
            read_only: self.read_only,
            existing: self.existing,
            dirty: self.dirty,
            status: self.status.clone(),
            load_error: self.load_error.clone(),
            has_draft: self.pending_draft.is_some(),
            conflict: self.conflict,
        }
    }

    pub fn status_message(&self, saved_content_sha256: Option<String>) -> EditorHostMsg {
        EditorHostMsg::Status {
            status: self.status.clone(),
            dirty: self.dirty,
            saving: self.saving,
            read_only: self.read_only,
            existing: self.existing,
            show_discard: self.show_discard,
            has_draft: self.pending_draft.is_some(),
            conflict: self.conflict,
            saved_content_sha256,
        }
    }

    /// Evaluate a close request. Returns `true` if the editor should close immediately, or `false`
    /// if unsaved changes require explicit confirmation (setting `show_discard = true`).
    pub fn request_close(&mut self, force: bool, ui_dirty: bool) -> bool {
        if self.saving {
            return false;
        }
        if ui_dirty {
            self.dirty = true;
        }
        if self.dirty && !force && self.load_error.is_none() {
            self.status = "You have unsaved changes. Save or choose Discard changes.".to_owned();
            self.show_discard = true;
            return false;
        }
        true
    }

    pub fn apply_save_ok(&mut self, saved_text: String, new_rev: Option<String>) -> EditorHostMsg {
        let sha = sha256_hex(saved_text.as_bytes());
        self.content = saved_text;
        self.base_rev = new_rev;
        self.existing = true;
        self.saving = false;
        self.dirty = false;
        self.show_discard = false;
        self.conflict = None;
        self.pending_draft = None;
        self.status = "Saved".to_owned();
        self.status_message(Some(sha))
    }

    pub fn apply_save_err(&mut self, errno: Errno, detail: Option<&str>) -> EditorHostMsg {
        self.saving = false;
        let (msg, kind) = save_error_message(errno, detail);
        self.status = msg;
        self.conflict = kind;
        self.status_message(None)
    }

    pub fn restore_pending_draft(&mut self) -> Option<EditorHostMsg> {
        let rec = self.pending_draft.take()?;
        self.content = rec.content;
        self.dirty = true;
        self.show_discard = false;
        self.conflict = None;
        self.status = "Draft restored. Ctrl / Cmd S to save.".to_owned();
        Some(EditorHostMsg::ReplaceContent {
            content: self.content.clone(),
            dirty: self.dirty,
            status: self.status.clone(),
            read_only: self.read_only,
            existing: self.existing,
            show_discard: self.show_discard,
            has_draft: false,
            conflict: None,
        })
    }

    pub fn discard_pending_draft(&mut self) -> EditorHostMsg {
        self.pending_draft = None;
        self.status = if self.existing {
            "Draft discarded. Ctrl / Cmd S to save; Esc to close".to_owned()
        } else {
            "Draft discarded. New file: save to create it at this path".to_owned()
        };
        self.status_message(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui_doc::{DocChunkAssembler, chunk_document_message};

    #[test]
    fn language_and_filename_helpers() {
        assert_eq!(language_for_path("/home/user/main.rs"), "rust");
        assert_eq!(language_for_path("/home/user/app.tsx"), "tsx");
        assert_eq!(language_for_path("/home/user/demo.slides.md"), "markdown");
        assert_eq!(language_for_path("/home/user/chess.game"), "json");
        assert_eq!(language_for_path("/home/user/README"), "plain");

        assert_eq!(export_filename("/home/user/notes.md"), "notes.md");
        assert_eq!(export_filename("/home/user/.hidden"), "hidden");
        assert_eq!(export_filename("/home/user/.."), "draft.txt");

        assert_eq!(
            copy_path_for("/home/user/main.rs", 1),
            "/home/user/main.copy.rs"
        );
        assert_eq!(
            copy_path_for("/home/user/main.rs", 2),
            "/home/user/main.copy-2.rs"
        );
        assert_eq!(copy_path_for("/README", 1), "/README.copy");
    }

    #[test]
    fn binary_and_size_checks_and_conflict_messages() {
        assert!(decode_editable_text(b"hello world\n").is_ok());
        assert!(decode_editable_text(b"a\0b").is_err());
        assert!(decode_editable_text(&[0xff, 0xfe]).is_err());
        assert!(decode_editable_text(&vec![b'a'; MAX_EDIT_BYTES + 1]).is_err());

        let (m, k) = save_error_message(Errno::ESTALE, None);
        assert!(m.contains("changed in another session"));
        assert_eq!(k, Some(ConflictKind::ChangedElsewhere));

        let (m, k) = save_error_message(Errno::EEXIST, None);
        assert!(m.contains("created by another session"));
        assert_eq!(k, Some(ConflictKind::CreatedElsewhere));

        let (m, k) = save_error_message(Errno::ENOENT, None);
        assert!(m.contains("deleted or moved"));
        assert_eq!(k, Some(ConflictKind::DeletedElsewhere));
    }

    #[test]
    fn close_guard_and_conflict_state_machine() {
        let mut core = EditorCore::from_loaded(
            "/home/user/a.rs".into(),
            "fn a() {}".into(),
            Some("rev1".into()),
            true,
            false,
            DraftLoadOutcome::Missing,
        );
        assert!(!core.dirty);
        assert!(core.request_close(false, false));

        core.dirty = true;
        assert!(!core.request_close(false, true));
        assert!(core.show_discard);
        assert!(core.status.contains("Discard changes"));
        assert!(core.request_close(true, true));

        let err_msg = core.apply_save_err(Errno::ESTALE, None);
        assert!(matches!(
            err_msg,
            EditorHostMsg::Status {
                conflict: Some(ConflictKind::ChangedElsewhere),
                ..
            }
        ));
        let ok_msg = core.apply_save_ok("fn b() {}".into(), Some("rev2".into()));
        assert!(matches!(
            ok_msg,
            EditorHostMsg::Status {
                dirty: false,
                conflict: None,
                ..
            }
        ));
        assert_eq!(core.base_rev.as_deref(), Some("rev2"));
    }

    #[test]
    fn draft_persistence_atomic_versioning_and_lru_cap() {
        let tmp =
            std::env::temp_dir().join(format!("os-editor-drafts-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let home = tmp.to_str().unwrap();

        let rec = DraftRecord {
            version: DRAFT_VERSION,
            path: "/home/user/notes.md".into(),
            base_rev: Some("rev1".into()),
            updated_at_ms: 100,
            content: "draft body".into(),
        };
        save_draft_atomic(home, &rec).unwrap();
        assert_eq!(
            load_draft(home, "/home/user/notes.md"),
            DraftLoadOutcome::Loaded(rec.clone())
        );

        let newer = br#"{"version": 99, "path": "/a", "updated_at_ms": 1, "content": "x"}"#;
        assert_eq!(
            parse_draft_record(newer),
            DraftLoadOutcome::RefusedNewer(99)
        );

        // Exceed MAX_DRAFTS and confirm oldest drafts are pruned.
        for i in 0..(MAX_DRAFTS + 5) {
            save_draft_atomic(
                home,
                &DraftRecord {
                    version: DRAFT_VERSION,
                    path: format!("/home/user/file-{i}.txt"),
                    base_rev: None,
                    updated_at_ms: 200 + i as u64,
                    content: format!("body {i}"),
                },
            )
            .unwrap();
        }
        let dir = Path::new(home).join(DRAFTS_REL_DIR);
        let count = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .count();
        assert!(count <= MAX_DRAFTS);

        remove_draft(home, "/home/user/notes.md");
        assert_eq!(
            load_draft(home, "/home/user/notes.md"),
            DraftLoadOutcome::Missing
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn large_two_megabyte_document_chunks_and_reassembles() {
        let payload = serde_json::to_string(&EditorUiMsg::Save {
            content: "x".repeat(MAX_EDIT_BYTES),
            force_overwrite: false,
            save_as_copy: false,
        })
        .unwrap();
        let frames = chunk_document_message(1, &payload);
        assert!(frames.len() > 400 && frames.len() <= MAX_EDITOR_CHUNKS);
        let mut asm = DocChunkAssembler::with_limits(MAX_EDITOR_ASSEMBLED_BYTES, MAX_EDITOR_CHUNKS);
        let mut assembled = None;
        for f in &frames {
            assert!(f.len() <= abi::gui::MAX_DOCUMENT_MESSAGE);
            assembled = asm.feed(f);
        }
        assert_eq!(assembled.as_deref(), Some(payload.as_str()));
    }
}
