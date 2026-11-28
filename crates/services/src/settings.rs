//! Portable state machine, wire protocol types, and `~/.config/os/settings.json` persistence
//! for `/usr/bin/settings` (GNOME/COSMIC-aligned Settings app over the unified GUI Portal IPC).
use abi::auth_v2::RemoteScope;
use abi::gui::{
    AccountPortalOutcome, CloudAccountSummary, DesktopPortalOutcome, LocalIdentitySummary,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const SETTINGS_VERSION: u32 = 1;
pub const SETTINGS_REL_PATH: &str = ".config/os/settings.json";

/// Persisted per-user desktop appearance & dock preferences (`~/.config/os/settings.json`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopSettingsFile {
    pub version: u32,
    pub theme: String,
    pub dock_autohide: bool,
}

impl Default for DesktopSettingsFile {
    fn default() -> Self {
        Self {
            version: SETTINGS_VERSION,
            theme: "light".into(),
            dock_autohide: false,
        }
    }
}

pub fn normalize_theme(raw: &str) -> String {
    if raw.trim().eq_ignore_ascii_case("dark") {
        "dark".into()
    } else {
        "light".into()
    }
}

pub fn load_settings_file(path: &Path) -> Option<DesktopSettingsFile> {
    let bytes = fs::read(path).ok()?;
    let parsed: DesktopSettingsFile = serde_json::from_slice(&bytes).ok()?;
    if parsed.version != SETTINGS_VERSION {
        return None;
    }
    Some(DesktopSettingsFile {
        version: SETTINGS_VERSION,
        theme: normalize_theme(&parsed.theme),
        dock_autohide: parsed.dock_autohide,
    })
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

/// Atomically persist `settings` to `path` with `0700` config dirs and `0600` file permissions.
pub fn save_settings_file_atomic(path: &Path, settings: &DesktopSettingsFile) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing settings parent dir"))?;
    fs::create_dir_all(parent)?;
    set_mode(parent, 0o700);
    if let Some(grandparent) = parent.parent()
        && grandparent.file_name().and_then(|n| n.to_str()) == Some(".config")
    {
        set_mode(grandparent, 0o700);
    }
    let normalized = DesktopSettingsFile {
        version: SETTINGS_VERSION,
        theme: normalize_theme(&settings.theme),
        dock_autohide: settings.dock_autohide,
    };
    let mut bytes = serde_json::to_vec_pretty(&normalized)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');

    let tmp_seq = {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(1);
        SEQ.fetch_add(1, Ordering::Relaxed)
    };
    let tmp_stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let tmp_name = format!(".settings.json.tmp.{tmp_stamp:x}.{tmp_seq}");
    let tmp_path: PathBuf = parent.join(tmp_name);
    let write_res = (|| -> io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)?;
        set_mode(&tmp_path, 0o600);
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)?;
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
        if let Ok(committed) = fs::File::open(path) {
            committed.sync_all()?;
        }
        Ok(())
    })();
    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

/// Active sidebar section inside the Settings GUI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsSection {
    Accounts,
    System,
    Appearance,
}

impl SettingsSection {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "system" | "users" | "local" => Self::System,
            "appearance" | "dock" | "display" => Self::Appearance,
            _ => Self::Accounts,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::System => "system",
            Self::Appearance => "appearance",
        }
    }
}

/// Wire message sent by the sealed Settings Document iframe to `/usr/bin/settings`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum SettingsUiMsg {
    Ready {},
    Refresh {},
    SelectSection {
        section: String,
    },
    CloudSignIn {
        username: String,
        password: String,
        scope: RemoteScope,
    },
    CloudSignOut {},
    SwitchLocalUser {},
    OpenMounts {
        #[serde(default)]
        tab: Option<String>,
    },
    SetPreferences {
        theme: String,
        dock_autohide: bool,
    },
    SetFullscreen {
        active: bool,
    },
}

/// Control request accepted on `/run/user/<uid>/settings.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SettingsControlReq {
    Focus {
        #[serde(default)]
        section: Option<String>,
    },
    Refresh {},
    SyncPreferences {
        theme: String,
        dock_autohide: bool,
        #[serde(default)]
        fullscreen: bool,
    },
    Status {},
}

/// Control reply emitted on `/run/user/<uid>/settings.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsControlReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Wire snapshot pushed from `/usr/bin/settings` to its sealed Document iframe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum SettingsHostMsg {
    Snapshot {
        section: String,
        local: LocalIdentitySummary,
        cloud: CloudAccountSummary,
        theme: String,
        dock_autohide: bool,
        fullscreen: bool,
        settings_path: String,
        busy: bool,
        error: Option<String>,
        notice: Option<String>,
        ready: bool,
    },
}

/// Pure portable state machine for `/usr/bin/settings`.
#[derive(Clone, Debug)]
pub struct SettingsCore {
    pub section: SettingsSection,
    pub local: LocalIdentitySummary,
    pub cloud: CloudAccountSummary,
    pub theme: String,
    pub dock_autohide: bool,
    pub fullscreen: bool,
    pub settings_path: String,
    pub busy: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub account_loaded: bool,
    pub prefs_loaded: bool,
    pub has_disk_prefs: bool,
}

impl SettingsCore {
    pub fn new(
        section: SettingsSection,
        settings_path: String,
        disk_prefs: Option<DesktopSettingsFile>,
    ) -> Self {
        let has_disk_prefs = disk_prefs.is_some();
        let prefs = disk_prefs.unwrap_or_default();
        Self {
            section,
            local: LocalIdentitySummary {
                username: "user".into(),
                uid: 1000,
                gid: 1000,
                home: "/home/user".into(),
                root_volume_uuid: None,
                forked_from: None,
                ephemeral_if_unmodified: false,
                can_sudo: false,
                root_fstype: "cowfs".into(),
            },
            cloud: CloudAccountSummary::default(),
            theme: prefs.theme,
            dock_autohide: prefs.dock_autohide,
            fullscreen: false,
            settings_path,
            busy: false,
            error: None,
            notice: None,
            account_loaded: false,
            prefs_loaded: has_disk_prefs,
            has_disk_prefs,
        }
    }

    pub fn disk_settings(&self) -> DesktopSettingsFile {
        DesktopSettingsFile {
            version: SETTINGS_VERSION,
            theme: normalize_theme(&self.theme),
            dock_autohide: self.dock_autohide,
        }
    }

    pub fn apply_account_outcome(&mut self, outcome: AccountPortalOutcome) {
        self.busy = false;
        match outcome {
            AccountPortalOutcome::State {
                local,
                cloud,
                notice,
            } => {
                self.account_loaded = true;
                self.local = local;
                self.cloud = cloud;
                self.error = None;
                if notice.is_some() {
                    self.notice = notice;
                }
            }
            AccountPortalOutcome::ActionDone { notice } => {
                self.error = None;
                if notice.is_some() {
                    self.notice = notice;
                }
            }
            AccountPortalOutcome::Canceled { .. } => {
                self.error = None;
                self.notice = Some("Cancelled.".into());
            }
            AccountPortalOutcome::Error { detail, .. } => {
                self.notice = None;
                self.error = Some(if detail.is_empty() {
                    "Account operation failed.".into()
                } else {
                    detail
                });
            }
        }
    }

    pub fn apply_desktop_outcome(&mut self, outcome: DesktopPortalOutcome) {
        self.busy = false;
        match outcome {
            DesktopPortalOutcome::Preferences {
                theme,
                dock_autohide,
                fullscreen,
            } => {
                self.prefs_loaded = true;
                self.theme = normalize_theme(&theme);
                self.dock_autohide = dock_autohide;
                self.fullscreen = fullscreen;
                self.error = None;
            }
            DesktopPortalOutcome::Canceled { .. } => {
                self.error = None;
            }
            DesktopPortalOutcome::Error { detail, .. } => {
                self.error = Some(if detail.is_empty() {
                    "Desktop preference update failed.".into()
                } else {
                    detail
                });
            }
        }
    }

    pub fn snapshot_msg(&self) -> SettingsHostMsg {
        SettingsHostMsg::Snapshot {
            section: self.section.as_str().into(),
            local: self.local.clone(),
            cloud: self.cloud.clone(),
            theme: self.theme.clone(),
            dock_autohide: self.dock_autohide,
            fullscreen: self.fullscreen,
            settings_path: self.settings_path.clone(),
            busy: self.busy,
            error: self.error.clone(),
            notice: self.notice.clone(),
            ready: self.account_loaded || self.prefs_loaded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_file_atomic_roundtrip_and_normalization() {
        let dir = std::env::temp_dir().join(format!("os-settings-test-{}", std::process::id()));
        let path = dir.join(".config/os/settings.json");
        let _ = fs::remove_dir_all(&dir);
        assert!(load_settings_file(&path).is_none());

        let file = DesktopSettingsFile {
            version: SETTINGS_VERSION,
            theme: "DARK".into(),
            dock_autohide: true,
        };
        save_settings_file_atomic(&path, &file).unwrap();
        let loaded = load_settings_file(&path).unwrap();
        assert_eq!(loaded.version, SETTINGS_VERSION);
        assert_eq!(loaded.theme, "dark");
        assert!(loaded.dock_autohide);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn settings_core_applies_account_and_desktop_portal_outcomes() {
        let mut core = SettingsCore::new(
            SettingsSection::parse("appearance"),
            "/home/user/.config/os/settings.json".into(),
            None,
        );
        assert_eq!(core.section, SettingsSection::Appearance);
        assert_eq!(core.theme, "light");

        core.busy = true;
        core.apply_account_outcome(AccountPortalOutcome::State {
            local: LocalIdentitySummary {
                username: "alice".into(),
                uid: 1001,
                gid: 1001,
                home: "/home/alice".into(),
                root_volume_uuid: Some("abcdef12-0000".into()),
                forked_from: Some("base-0001".into()),
                ephemeral_if_unmodified: true,
                can_sudo: true,
                root_fstype: "cowfs".into(),
            },
            cloud: CloudAccountSummary {
                signed_in: true,
                cloud_user: Some("alice@cloud".into()),
                scope: RemoteScope {
                    cloud_fs: true,
                    ..Default::default()
                },
                cloud_mount_active: true,
                attached_devices: vec!["archive".into()],
            },
            notice: Some("Cloud credentials active.".into()),
        });
        assert!(!core.busy);
        assert!(core.account_loaded);
        assert!(core.cloud.signed_in);
        assert_eq!(core.local.username, "alice");
        assert_eq!(core.notice.as_deref(), Some("Cloud credentials active."));

        core.apply_desktop_outcome(DesktopPortalOutcome::Preferences {
            theme: "dark".into(),
            dock_autohide: true,
            fullscreen: true,
        });
        assert_eq!(core.theme, "dark");
        assert!(core.dock_autohide);
        assert!(core.fullscreen);

        core.apply_account_outcome(AccountPortalOutcome::Error {
            errno: abi::Errno::EACCES,
            detail: "Invalid credentials".into(),
        });
        assert_eq!(core.error.as_deref(), Some("Invalid credentials"));
    }
}
