//! Config-driven file associations (`#64` `L6c`, Contract v2 §2.12).
//!
//! Files, `open`/`vim`, and the desktop launcher consult `/usr/share/desktop/associations.json`
//! merged with an optional per-user override at `~/.config/os/associations.json` instead of
//! hardcoding file-type routing in page JavaScript.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const ASSOCIATIONS_VERSION: u32 = 1;
pub const SYSTEM_ASSOCIATIONS_PATH: &str = "/usr/share/desktop/associations.json";
pub const USER_ASSOCIATIONS_REL_PATH: &str = ".config/os/associations.json";
const MAX_ASSOCIATIONS_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileAssociation {
    pub kind: String,
    pub open: String,
    #[serde(default)]
    pub edit: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssociationsConfig {
    pub version: u32,
    pub defaults: BTreeMap<String, String>,
    #[serde(default)]
    pub compound_extensions: BTreeMap<String, FileAssociation>,
    #[serde(default)]
    pub extensions: BTreeMap<String, FileAssociation>,
    #[serde(default)]
    pub filenames: BTreeMap<String, FileAssociation>,
    pub fallback: FileAssociation,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedAssociation {
    pub kind: String,
    pub open_app: String,
    pub open_bin: Option<String>,
    pub edit_app: Option<String>,
    pub edit_bin: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssociationsLoadOutcome {
    Loaded(AssociationsConfig),
    Missing,
    ResetOlder(u32),
    RefusedNewer(u32),
}

/// Built-in default system association table (also written to `/usr/share/desktop/associations.json`).
pub fn default_associations() -> AssociationsConfig {
    let mut defaults = BTreeMap::new();
    defaults.insert("preview".into(), "/usr/bin/preview".into());
    defaults.insert("editor".into(), "/usr/bin/editor".into());
    defaults.insert("files".into(), "/usr/bin/files".into());
    defaults.insert("terminal".into(), "/usr/bin/terminal".into());

    let assoc = |kind: &str, open: &str, edit: Option<&str>| FileAssociation {
        kind: kind.into(),
        open: open.into(),
        edit: edit.map(str::to_owned),
    };

    let mut compound_extensions = BTreeMap::new();
    compound_extensions.insert(
        ".slides.md".into(),
        assoc("slides", "preview", Some("editor")),
    );
    compound_extensions.insert(".tar.gz".into(), assoc("archive", "preview", None));

    let mut extensions = BTreeMap::new();
    for ext in ["md", "markdown"] {
        extensions.insert(ext.into(), assoc("markdown", "preview", Some("editor")));
    }
    extensions.insert("pdf".into(), assoc("pdf", "preview", None));
    extensions.insert("game".into(), assoc("game", "preview", Some("editor")));
    for ext in [
        "png", "jpg", "jpeg", "gif", "webp", "avif", "svg", "bmp", "ico",
    ] {
        extensions.insert(ext.into(), assoc("image", "preview", None));
    }
    for ext in ["mp4", "webm", "mov", "m4v", "ogv"] {
        extensions.insert(ext.into(), assoc("video", "preview", None));
    }
    for ext in ["mp3", "wav", "ogg", "m4a", "flac", "weba", "opus"] {
        extensions.insert(ext.into(), assoc("audio", "preview", None));
    }
    for ext in ["zip", "tar", "tgz"] {
        extensions.insert(ext.into(), assoc("archive", "preview", None));
    }
    for ext in [
        "txt", "log", "rs", "js", "mjs", "cjs", "jsx", "ts", "tsx", "py", "json", "html", "htm",
        "css", "c", "h", "cc", "cpp", "hpp", "yaml", "yml", "toml", "sh", "bash", "zsh", "csv",
        "tsv", "vcf", "ics", "diff", "patch", "xml", "sql", "ini", "cfg", "conf",
    ] {
        extensions.insert(ext.into(), assoc("text", "preview", Some("editor")));
    }

    let mut filenames = BTreeMap::new();
    for name in ["makefile", "dockerfile", "readme", "license", "changelog"] {
        filenames.insert(name.into(), assoc("text", "preview", Some("editor")));
    }

    AssociationsConfig {
        version: ASSOCIATIONS_VERSION,
        defaults,
        compound_extensions,
        extensions,
        filenames,
        fallback: assoc("text", "preview", Some("editor")),
    }
}

/// Inspect schema version before strict deserialization (Contract v2 §2.12).
pub fn parse_associations(bytes: &[u8]) -> AssociationsLoadOutcome {
    if bytes.len() > MAX_ASSOCIATIONS_BYTES {
        return AssociationsLoadOutcome::ResetOlder(0);
    }
    let Ok(raw) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return AssociationsLoadOutcome::ResetOlder(0);
    };
    let Some(version) = raw
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return AssociationsLoadOutcome::ResetOlder(0);
    };
    if version > ASSOCIATIONS_VERSION {
        return AssociationsLoadOutcome::RefusedNewer(version);
    }
    if version < ASSOCIATIONS_VERSION {
        return AssociationsLoadOutcome::ResetOlder(version);
    }
    match serde_json::from_slice::<AssociationsConfig>(bytes) {
        Ok(cfg) if cfg.validate() => AssociationsLoadOutcome::Loaded(cfg),
        _ => AssociationsLoadOutcome::ResetOlder(version),
    }
}

fn valid_app_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn valid_bin_path(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= abi::PATH_MAX
        && !s.contains('\0')
        && !s.split('/').any(|seg| seg == "..")
}

impl AssociationsConfig {
    pub fn validate(&self) -> bool {
        if self.version != ASSOCIATIONS_VERSION {
            return false;
        }
        if self.defaults.len() > 32
            || self
                .defaults
                .iter()
                .any(|(k, v)| !valid_app_name(k) || !valid_bin_path(v))
        {
            return false;
        }
        let check_assoc = |a: &FileAssociation| {
            !a.kind.is_empty()
                && a.kind.len() <= 32
                && valid_app_name(&a.open)
                && a.edit.as_deref().is_none_or(valid_app_name)
        };
        if !check_assoc(&self.fallback) {
            return false;
        }
        self.compound_extensions.values().all(check_assoc)
            && self.extensions.values().all(check_assoc)
            && self.filenames.values().all(check_assoc)
    }

    /// Merge a valid user override config on top of the system default table.
    pub fn merge_override(&self, user: &AssociationsConfig) -> AssociationsConfig {
        let mut out = self.clone();
        for (k, v) in &user.defaults {
            out.defaults.insert(k.clone(), v.clone());
        }
        for (k, v) in &user.compound_extensions {
            out.compound_extensions
                .insert(k.to_ascii_lowercase(), v.clone());
        }
        for (k, v) in &user.extensions {
            out.extensions.insert(k.to_ascii_lowercase(), v.clone());
        }
        for (k, v) in &user.filenames {
            out.filenames.insert(k.to_ascii_lowercase(), v.clone());
        }
        out.fallback = user.fallback.clone();
        out
    }

    /// Resolve a file path to its configured file kind and open/edit application handlers.
    pub fn resolve(&self, path: &str) -> ResolvedAssociation {
        let base = path.rsplit('/').next().unwrap_or(path);
        let lower = base.to_ascii_lowercase();

        // 1. Compound extensions (longest match first for determinism).
        let mut best_compound: Option<(&str, &FileAssociation)> = None;
        for (suffix, assoc) in &self.compound_extensions {
            let norm = suffix.to_ascii_lowercase();
            if lower.ends_with(&norm)
                && best_compound.is_none_or(|(prev, _)| suffix.len() > prev.len())
            {
                best_compound = Some((suffix.as_str(), assoc));
            }
        }
        let picked = if let Some((_, assoc)) = best_compound {
            assoc
        } else if let Some(assoc) = self.filenames.get(&lower) {
            assoc
        } else if let Some((_, ext)) = lower.rsplit_once('.')
            && !ext.is_empty()
            && let Some(assoc) = self.extensions.get(ext)
        {
            assoc
        } else {
            &self.fallback
        };

        ResolvedAssociation {
            kind: picked.kind.clone(),
            open_bin: self.defaults.get(&picked.open).cloned(),
            open_app: picked.open.clone(),
            edit_bin: picked
                .edit
                .as_ref()
                .and_then(|app| self.defaults.get(app).cloned()),
            edit_app: picked.edit.clone(),
        }
    }
}

/// Load the effective association config from `/usr/share/desktop/associations.json` (falling back
/// to `default_associations()`) plus an optional `~/.config/os/associations.json` override.
/// Returns `(config, read_only_user_config)` where `read_only_user_config` is `true` if the user
/// file had `version > ASSOCIATIONS_VERSION` (Contract v2 §2.12).
pub fn load_effective_associations(home: Option<&str>) -> (AssociationsConfig, bool) {
    let base = match fs::read(SYSTEM_ASSOCIATIONS_PATH) {
        Ok(bytes) => match parse_associations(&bytes) {
            AssociationsLoadOutcome::Loaded(cfg) => cfg,
            _ => default_associations(),
        },
        Err(_) => default_associations(),
    };
    let Some(home) = home.filter(|h| !h.is_empty()) else {
        return (base, false);
    };
    let user_path = Path::new(home).join(USER_ASSOCIATIONS_REL_PATH);
    match fs::read(&user_path) {
        Ok(bytes) => match parse_associations(&bytes) {
            AssociationsLoadOutcome::Loaded(user) => (base.merge_override(&user), false),
            AssociationsLoadOutcome::RefusedNewer(_) => (base, true),
            AssociationsLoadOutcome::Missing | AssociationsLoadOutcome::ResetOlder(_) => {
                (base, false)
            }
        },
        Err(_) => (base, false),
    }
}

/// Return `true` when `path` has a media/PDF extension that `/usr/bin/editor` refuses to open.
pub fn is_editor_blocked_media_path(path: &str) -> bool {
    let base = path.rsplit('/').next().unwrap_or(path);
    let Some((_, ext)) = base.rsplit_once('.') else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "pdf"
            | "png"
            | "jpg"
            | "jpeg"
            | "webp"
            | "gif"
            | "avif"
            | "bmp"
            | "ico"
            | "mp4"
            | "webm"
            | "mov"
            | "m4v"
            | "mp3"
            | "wav"
            | "ogg"
            | "m4a"
            | "flac"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_table_resolves_compound_extensions_filenames_and_fallback() {
        let cfg = default_associations();
        assert!(cfg.validate());

        let slides = cfg.resolve("/home/user/deck.slides.md");
        assert_eq!(slides.kind, "slides");
        assert_eq!(slides.open_app, "preview");
        assert_eq!(slides.edit_app.as_deref(), Some("editor"));

        let md = cfg.resolve("/home/user/NOTES.MD");
        assert_eq!(md.kind, "markdown");
        assert_eq!(md.open_app, "preview");
        assert_eq!(md.edit_bin.as_deref(), Some("/usr/bin/editor"));

        let tgz = cfg.resolve("/tmp/backup.tar.gz");
        assert_eq!(tgz.kind, "archive");
        assert_eq!(tgz.edit_app, None);

        let pdf = cfg.resolve("/docs/manual.pdf");
        assert_eq!(pdf.kind, "pdf");
        assert_eq!(pdf.edit_app, None);

        let mk = cfg.resolve("/src/Makefile");
        assert_eq!(mk.kind, "text");
        assert_eq!(mk.edit_app.as_deref(), Some("editor"));

        let unknown = cfg.resolve("/home/user/README");
        assert_eq!(unknown.kind, "text");
        assert_eq!(unknown.open_app, "preview");
        assert_eq!(unknown.edit_app.as_deref(), Some("editor"));
    }

    #[test]
    fn config_versioning_and_user_override_merge() {
        let newer =
            br#"{"version": 99, "defaults": {}, "fallback": {"kind": "text", "open": "preview"}}"#;
        assert_eq!(
            parse_associations(newer),
            AssociationsLoadOutcome::RefusedNewer(99)
        );

        let older =
            br#"{"version": 0, "defaults": {}, "fallback": {"kind": "text", "open": "preview"}}"#;
        assert_eq!(
            parse_associations(older),
            AssociationsLoadOutcome::ResetOlder(0)
        );

        let unknown_field = br#"{"version": 1, "defaults": {}, "fallback": {"kind": "text", "open": "preview"}, "extra": true}"#;
        assert_eq!(
            parse_associations(unknown_field),
            AssociationsLoadOutcome::ResetOlder(1)
        );

        let base = default_associations();
        let mut user = base.clone();
        user.extensions.insert(
            "notes".into(),
            FileAssociation {
                kind: "markdown".into(),
                open: "editor".into(),
                edit: Some("editor".into()),
            },
        );
        let merged = base.merge_override(&user);
        let resolved = merged.resolve("/home/user/scratch.notes");
        assert_eq!(resolved.kind, "markdown");
        assert_eq!(resolved.open_app, "editor");
        assert_eq!(resolved.open_bin.as_deref(), Some("/usr/bin/editor"));
    }

    #[test]
    fn blocked_media_extensions_match_legacy_editor() {
        assert!(is_editor_blocked_media_path("/docs/report.PDF"));
        assert!(is_editor_blocked_media_path("/pics/a.jpeg"));
        assert!(is_editor_blocked_media_path("/media/clip.mp4"));
        assert!(!is_editor_blocked_media_path("/pics/icon.svg"));
        assert!(!is_editor_blocked_media_path("/home/user/main.rs"));
        assert!(!is_editor_blocked_media_path("/home/user/README"));
    }
}
