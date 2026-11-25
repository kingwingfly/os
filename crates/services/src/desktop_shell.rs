//! Desktop shell controller (`#61` `L5b`, Contract v2 §2.9, §2.12).
//!
//! Pure portable state machine and per-display layout persistence for `/usr/bin/desktop-shell`.
//! Manages `Background`/`Panel`/`Launcher` chrome state, pinned and dynamic dock entries,
//! launcher items, one-time conversion from legacy `localStorage['os-desktop']`, and atomic
//! `~/.config/os/desktop-layout.json` storage keyed by `seat_id`.
use abi::gui::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

pub const LAYOUT_VERSION: u32 = 1;
pub const LAYOUT_REL_PATH: &str = ".config/os/desktop-layout.json";

const PINNED_APPS: [(&str, &str); 2] = [("terminal", "Terminal"), ("files", "Files")];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutFile {
    pub version: u32,
    #[serde(default)]
    pub displays: BTreeMap<String, BTreeMap<String, SavedWindowFrame>>,
}

impl Default for LayoutFile {
    fn default() -> Self {
        Self {
            version: LAYOUT_VERSION,
            displays: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayoutLoadOutcome {
    Loaded(LayoutFile),
    Missing,
    ResetOlder(u32),
    RefusedNewer(u32),
}

/// Inspect schema version before strict deserialization (Contract v2 §2.12):
/// - `version > LAYOUT_VERSION`: refuse to silently misread AND refuse to overwrite.
/// - `version < LAYOUT_VERSION` or unreadable/corrupt: reset cleanly to v1.
pub fn parse_layout_file(bytes: &[u8]) -> LayoutLoadOutcome {
    let Ok(raw) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return LayoutLoadOutcome::ResetOlder(0);
    };
    let Some(version) = raw
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
    else {
        return LayoutLoadOutcome::ResetOlder(0);
    };
    if version > LAYOUT_VERSION {
        return LayoutLoadOutcome::RefusedNewer(version);
    }
    if version < LAYOUT_VERSION {
        return LayoutLoadOutcome::ResetOlder(version);
    }
    match serde_json::from_slice::<LayoutFile>(bytes) {
        Ok(file) => LayoutLoadOutcome::Loaded(file),
        Err(_) => LayoutLoadOutcome::ResetOlder(version),
    }
}

pub fn load_layout_file(path: &Path) -> LayoutLoadOutcome {
    match fs::read(path) {
        Ok(bytes) => parse_layout_file(&bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => LayoutLoadOutcome::Missing,
        Err(_) => LayoutLoadOutcome::ResetOlder(0),
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

/// Atomically persist `layout` to `path` with `0700` config dir and `0600` temp file + rename.
pub fn save_layout_file_atomic(path: &Path, layout: &LayoutFile) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing layout parent dir"))?;
    fs::create_dir_all(parent)?;
    set_mode(parent, 0o700);
    if let Some(grandparent) = parent.parent()
        && grandparent.file_name().and_then(|n| n.to_str()) == Some(".config")
    {
        set_mode(grandparent, 0o700);
    }
    let mut bytes = serde_json::to_vec_pretty(layout)
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
    let tmp_name = format!(
        ".{}.tmp.{tmp_stamp:x}.{tmp_seq}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("desktop-layout.json"),
    );
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
        // Commit the renamed directory entry durably before returning (POSIX + os-cowfs TreeCommit).
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

#[derive(Deserialize)]
struct LegacyFrame {
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    #[serde(default)]
    place: Option<String>,
    #[serde(default)]
    minimized: bool,
}

/// Convert legacy `localStorage['os-desktop']` JSON into v1 `SavedWindowFrame` entries.
pub fn convert_legacy_os_desktop(raw: &str) -> Option<BTreeMap<String, SavedWindowFrame>> {
    let parsed: BTreeMap<String, serde_json::Value> = serde_json::from_str(raw).ok()?;
    let mut frames = BTreeMap::new();
    for (app_id, value) in parsed {
        if !valid_app_id(&app_id) {
            continue;
        }
        let Ok(legacy) = serde_json::from_value::<LegacyFrame>(value) else {
            continue;
        };
        if !legacy.x.is_finite()
            || !legacy.y.is_finite()
            || !legacy.w.is_finite()
            || !legacy.h.is_finite()
            || legacy.w < 1.0
            || legacy.h < 1.0
        {
            continue;
        }
        let rect = Rect {
            x: legacy.x.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32,
            y: legacy.y.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32,
            width: legacy.w.round().clamp(1.0, u32::MAX as f64) as u32,
            height: legacy.h.round().clamp(1.0, u32::MAX as f64) as u32,
        };
        let state = if legacy.minimized {
            WindowState::Minimized
        } else {
            match legacy.place.as_deref() {
                Some("maximized") => WindowState::Maximized,
                Some("left") => WindowState::Left,
                Some("right") => WindowState::Right,
                _ => WindowState::Normal,
            }
        };
        frames.insert(
            app_id.clone(),
            SavedWindowFrame {
                rect,
                state,
                open: matches!(app_id.as_str(), "files" | "terminal"),
            },
        );
    }
    Some(frames)
}

fn valid_app_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn app_label<'a>(app_id: &str, fallback: &'a str) -> &'a str {
    match app_id {
        "files" => "Files",
        "terminal" => "Terminal",
        "viewer" => "Preview",
        "editor" => "Editor",
        "mounts" => "Mounts",
        _ => fallback,
    }
}

pub fn default_launcher_items() -> Vec<LauncherEntry> {
    vec![
        LauncherEntry {
            app_id: "terminal".into(),
            label: "Terminal".into(),
            description: "Interactive shell".into(),
        },
        LauncherEntry {
            app_id: "files".into(),
            label: "Files".into(),
            description: "Browse local and mounted files".into(),
        },
        LauncherEntry {
            app_id: "mounts".into(),
            label: "Mounts".into(),
            description: "Manage local and remote mounts".into(),
        },
        LauncherEntry {
            app_id: "manual".into(),
            label: "Manual".into(),
            description: "Read the system manual".into(),
        },
        LauncherEntry {
            app_id: "upload".into(),
            label: "Upload files".into(),
            description: "Upload files from this device".into(),
        },
    ]
}

pub struct DesktopShellCore {
    seat_id: String,
    layout: LayoutFile,
    save_blocked: bool,
    layout_dirty: bool,
    pending_legacy_migration: Option<String>,
    loaded_layout_for_seat: bool,
    launcher_open: bool,
    windows: Vec<WindowSummary>,
    compact: bool,
    fullscreen: bool,
}

impl DesktopShellCore {
    pub fn new(outcome: LayoutLoadOutcome) -> Self {
        let (layout, save_blocked) = match outcome {
            LayoutLoadOutcome::Loaded(file) => (file, false),
            LayoutLoadOutcome::Missing | LayoutLoadOutcome::ResetOlder(_) => {
                (LayoutFile::default(), false)
            }
            LayoutLoadOutcome::RefusedNewer(_) => (LayoutFile::default(), true),
        };
        Self {
            seat_id: "seat0".into(),
            layout,
            save_blocked,
            layout_dirty: false,
            pending_legacy_migration: None,
            loaded_layout_for_seat: false,
            launcher_open: false,
            windows: Vec::new(),
            compact: false,
            fullscreen: false,
        }
    }

    pub fn save_blocked(&self) -> bool {
        self.save_blocked
    }

    pub fn layout(&self) -> &LayoutFile {
        &self.layout
    }

    pub fn startup_requests(&self) -> Vec<ClientReq> {
        vec![
            ClientReq::CreateSurface {
                spec: SurfaceSpec {
                    role: SurfaceRole::Background,
                    kind: SurfaceKind::Host {
                        component: "background".into(),
                    },
                    title: "Desktop".into(),
                    rect: Rect {
                        x: 0,
                        y: 0,
                        width: 1024,
                        height: 720,
                    },
                    min_size: Size {
                        width: 1,
                        height: 1,
                    },
                    max_size: None,
                    resizable: false,
                    app_id: Some("desktop-background".into()),
                },
            },
            ClientReq::CreateSurface {
                spec: SurfaceSpec {
                    role: SurfaceRole::Panel,
                    kind: SurfaceKind::Host {
                        component: "panel".into(),
                    },
                    title: "Dock".into(),
                    rect: Rect {
                        x: 0,
                        y: 0,
                        width: 1024,
                        height: 44,
                    },
                    min_size: Size {
                        width: 1,
                        height: 1,
                    },
                    max_size: None,
                    resizable: false,
                    app_id: Some("desktop-panel".into()),
                },
            },
            ClientReq::SubscribeShell,
        ]
    }

    pub fn build_shell_state(&self) -> ShellStateView {
        let mut dock = Vec::new();
        for &(app_id, label) in &PINNED_APPS {
            if let Some(win) = self
                .windows
                .iter()
                .find(|w| w.app_id.as_deref() == Some(app_id))
            {
                dock.push(DockEntry {
                    app_id: app_id.into(),
                    label: label.into(),
                    surface_id: Some(win.surface_id),
                    open: true,
                    minimized: win.state == WindowState::Minimized,
                    focused: win.focused && win.visible,
                    pinned: true,
                });
            } else {
                dock.push(DockEntry {
                    app_id: app_id.into(),
                    label: label.into(),
                    surface_id: None,
                    open: false,
                    minimized: false,
                    focused: false,
                    pinned: true,
                });
            }
        }
        for win in &self.windows {
            if win.role != SurfaceRole::Window {
                continue;
            }
            if win
                .app_id
                .as_deref()
                .is_some_and(|id| PINNED_APPS.iter().any(|(pinned, _)| *pinned == id))
            {
                continue;
            }
            let app_id = win
                .app_id
                .clone()
                .unwrap_or_else(|| format!("surface-{}", win.surface_id));
            let label = app_label(&app_id, &win.title).to_owned();
            dock.push(DockEntry {
                app_id,
                label,
                surface_id: Some(win.surface_id),
                open: true,
                minimized: win.state == WindowState::Minimized,
                focused: win.focused && win.visible,
                pinned: false,
            });
        }
        let focused_title = self
            .windows
            .iter()
            .find(|w| w.focused && w.visible)
            .map(|w| w.title.clone());
        ShellStateView {
            dock,
            launcher_open: self.launcher_open,
            launcher_items: default_launcher_items(),
            compact: self.compact,
            fullscreen: self.fullscreen,
            focused_title,
            seat_id: self.seat_id.clone(),
        }
    }

    pub fn handle_event(&mut self, event: ClientEvent) -> Vec<ClientReq> {
        let mut reqs = Vec::new();
        match event {
            ClientEvent::SeatLayoutInit {
                seat_id,
                legacy_json,
            } => {
                if !seat_id.is_empty() && seat_id.len() <= 64 {
                    self.seat_id = seat_id.clone();
                }
                let already_has_display = self.layout.displays.contains_key(&self.seat_id);
                if let Some(raw) = legacy_json.as_deref()
                    && !self.save_blocked
                {
                    if !already_has_display {
                        if let Some(converted) = convert_legacy_os_desktop(raw) {
                            self.layout.displays.insert(self.seat_id.clone(), converted);
                            self.layout_dirty = true;
                            // Defer `LegacyLayoutMigrated` until after atomic disk save succeeds!
                            self.pending_legacy_migration = Some(self.seat_id.clone());
                        }
                    } else {
                        // Layout already persisted in `~/.config/os/desktop-layout.json`:
                        // ask the browser to clear any leftover legacy localStorage key.
                        reqs.push(ClientReq::LegacyLayoutMigrated {
                            seat_id: self.seat_id.clone(),
                        });
                    }
                }
                let frames = self
                    .layout
                    .displays
                    .get(&self.seat_id)
                    .cloned()
                    .unwrap_or_default();
                self.loaded_layout_for_seat = true;
                reqs.push(ClientReq::SetSavedLayout {
                    seat_id: self.seat_id.clone(),
                    frames,
                });
                reqs.push(ClientReq::PublishShellState {
                    state: self.build_shell_state(),
                });
            }
            ClientEvent::WindowList {
                windows,
                compact,
                fullscreen,
                seat_id,
                ..
            } => {
                self.windows = windows;
                self.compact = compact;
                self.fullscreen = fullscreen;
                if !seat_id.is_empty() && seat_id.len() <= 64 {
                    self.seat_id = seat_id;
                }
                if !self.save_blocked && self.loaded_layout_for_seat {
                    let entry = self
                        .layout
                        .displays
                        .entry(self.seat_id.clone())
                        .or_default();
                    let mut changed = false;
                    for win in &self.windows {
                        if win.role != SurfaceRole::Window {
                            continue;
                        }
                        let Some(app_id) = win.app_id.as_ref() else {
                            continue;
                        };
                        let next = SavedWindowFrame {
                            rect: win.normal,
                            state: win.state,
                            open: true,
                        };
                        if entry.get(app_id) != Some(&next) {
                            entry.insert(app_id.clone(), next);
                            changed = true;
                        }
                    }
                    if changed {
                        self.layout_dirty = true;
                    }
                }
                reqs.push(ClientReq::PublishShellState {
                    state: self.build_shell_state(),
                });
            }
            ClientEvent::ShellInput { action } => match action {
                ShellAction::ToggleLauncher {} => {
                    self.launcher_open = !self.launcher_open;
                    reqs.push(ClientReq::PublishShellState {
                        state: self.build_shell_state(),
                    });
                }
                ShellAction::CloseLauncher {} => {
                    if self.launcher_open {
                        self.launcher_open = false;
                        reqs.push(ClientReq::PublishShellState {
                            state: self.build_shell_state(),
                        });
                    }
                }
                ShellAction::Launch { app_id } => {
                    self.launcher_open = false;
                    if !matches!(app_id.as_str(), "manual" | "upload")
                        && let Some(win) = self
                            .windows
                            .iter()
                            .find(|w| w.app_id.as_deref() == Some(app_id.as_str()))
                    {
                        reqs.push(ClientReq::ShellCommand {
                            action: ShellAction::Focus {
                                surface_id: win.surface_id,
                            },
                        });
                    } else {
                        reqs.push(ClientReq::ShellCommand {
                            action: ShellAction::Launch { app_id },
                        });
                    }
                    reqs.push(ClientReq::PublishShellState {
                        state: self.build_shell_state(),
                    });
                }
                ShellAction::ToggleApp { app_id } => {
                    self.launcher_open = false;
                    if let Some(win) = self
                        .windows
                        .iter()
                        .find(|w| w.app_id.as_deref() == Some(app_id.as_str()))
                    {
                        if win.state == WindowState::Minimized {
                            reqs.push(ClientReq::ShellCommand {
                                action: ShellAction::Restore {
                                    surface_id: win.surface_id,
                                },
                            });
                        } else if win.focused {
                            reqs.push(ClientReq::ShellCommand {
                                action: ShellAction::Minimize {
                                    surface_id: win.surface_id,
                                },
                            });
                        } else {
                            reqs.push(ClientReq::ShellCommand {
                                action: ShellAction::Focus {
                                    surface_id: win.surface_id,
                                },
                            });
                        }
                    } else {
                        reqs.push(ClientReq::ShellCommand {
                            action: ShellAction::Launch { app_id },
                        });
                    }
                    reqs.push(ClientReq::PublishShellState {
                        state: self.build_shell_state(),
                    });
                }
                other @ (ShellAction::Focus { .. }
                | ShellAction::Minimize { .. }
                | ShellAction::Maximize { .. }
                | ShellAction::Restore { .. }
                | ShellAction::Close { .. }) => {
                    self.launcher_open = false;
                    reqs.push(ClientReq::ShellCommand { action: other });
                    reqs.push(ClientReq::PublishShellState {
                        state: self.build_shell_state(),
                    });
                }
            },
            _ => {}
        }
        reqs
    }

    /// Return a snapshot ready to persist if layout state is dirty and saving is allowed.
    pub fn take_dirty_layout(&mut self) -> Option<LayoutFile> {
        if self.save_blocked || !self.layout_dirty {
            return None;
        }
        self.layout_dirty = false;
        Some(self.layout.clone())
    }

    /// Take the seat id awaiting `LegacyLayoutMigrated` acknowledgement after durable disk save.
    pub fn take_pending_legacy_migration(&mut self) -> Option<String> {
        if self.save_blocked {
            self.pending_legacy_migration = None;
            return None;
        }
        self.pending_legacy_migration.take()
    }

    /// Re-mark layout dirty and preserve any pending legacy migration when a disk save fails.
    pub fn restore_pending_save(&mut self, pending_legacy: Option<String>) {
        if !self.save_blocked {
            self.layout_dirty = true;
            if self.pending_legacy_migration.is_none() {
                self.pending_legacy_migration = pending_legacy;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_reset_older_and_refuse_newer_without_overwrite() {
        let v1 = serde_json::to_vec(&LayoutFile::default()).unwrap();
        assert!(matches!(
            parse_layout_file(&v1),
            LayoutLoadOutcome::Loaded(_)
        ));

        let v0 = br#"{"version":0,"displays":{}}"#;
        assert_eq!(parse_layout_file(v0), LayoutLoadOutcome::ResetOlder(0));

        // Corrupt JSON resets cleanly.
        assert_eq!(
            parse_layout_file(b"not-json"),
            LayoutLoadOutcome::ResetOlder(0)
        );

        // Newer version (even with unknown future fields!) refuses AND blocks overwrites
        // and MUST NOT emit LegacyLayoutMigrated.
        let v2 = br#"{"version":2,"future_field":true,"displays":{}}"#;
        let outcome = parse_layout_file(v2);
        assert_eq!(outcome, LayoutLoadOutcome::RefusedNewer(2));
        let mut core = DesktopShellCore::new(outcome);
        assert!(core.save_blocked());
        let reqs = core.handle_event(ClientEvent::SeatLayoutInit {
            seat_id: "seat0".into(),
            legacy_json: Some(r#"{"terminal":{"x":12,"y":34,"w":500,"h":400}}"#.into()),
        });
        assert!(
            !reqs
                .iter()
                .any(|r| matches!(r, ClientReq::LegacyLayoutMigrated { .. }))
        );
        assert!(core.take_dirty_layout().is_none());
        assert!(core.take_pending_legacy_migration().is_none());
    }

    #[test]
    fn convert_legacy_os_desktop_and_atomic_multi_display_persistence() {
        let raw = r#"{
            "terminal": {"x": 440.4, "y": 10.2, "w": 800.0, "h": 580.0, "place": "free", "minimized": false},
            "files": {"x": 10, "y": 10, "w": 420, "h": 580, "place": "left", "minimized": false},
            "viewer": {"x": 120, "y": 40, "w": 700, "h": 500, "place": "maximized", "minimized": true},
            "bad": {"x": 0, "y": 0, "w": 0, "h": 100}
        }"#;
        let converted = convert_legacy_os_desktop(raw).unwrap();
        assert_eq!(converted.len(), 3);
        assert_eq!(
            converted["terminal"],
            SavedWindowFrame {
                rect: Rect {
                    x: 440,
                    y: 10,
                    width: 800,
                    height: 580,
                },
                state: WindowState::Normal,
                open: true,
            }
        );
        assert_eq!(converted["files"].state, WindowState::Left);
        assert_eq!(converted["viewer"].state, WindowState::Minimized);

        let dir = std::env::temp_dir().join(format!("os-l5b-layout-{}", std::process::id()));
        let path = dir.join(".config/os/desktop-layout.json");
        let _ = fs::remove_dir_all(&dir);

        let mut core = DesktopShellCore::new(load_layout_file(&path));
        let reqs = core.handle_event(ClientEvent::SeatLayoutInit {
            seat_id: "display-1280x720".into(),
            legacy_json: Some(raw.into()),
        });
        // LegacyLayoutMigrated is deferred until after durable atomic save succeeds.
        assert!(
            !reqs
                .iter()
                .any(|r| matches!(r, ClientReq::LegacyLayoutMigrated { .. }))
        );
        assert!(reqs.iter().any(|r| matches!(
            r,
            ClientReq::SetSavedLayout { seat_id, frames }
                if seat_id == "display-1280x720" && frames.contains_key("terminal")
        )));
        let to_save = core.take_dirty_layout().unwrap();
        let pending_seat = core.take_pending_legacy_migration();
        assert_eq!(pending_seat.as_deref(), Some("display-1280x720"));
        save_layout_file_atomic(&path, &to_save).unwrap();

        // Reload: now that display-1280x720 is already durably on disk, a leftover legacy key
        // immediately receives LegacyLayoutMigrated.
        let reloaded = load_layout_file(&path);
        let mut reloaded_core = DesktopShellCore::new(reloaded.clone());
        let follow = reloaded_core.handle_event(ClientEvent::SeatLayoutInit {
            seat_id: "display-1280x720".into(),
            legacy_json: Some(raw.into()),
        });
        assert!(follow.iter().any(|r| matches!(
            r,
            ClientReq::LegacyLayoutMigrated { seat_id } if seat_id == "display-1280x720"
        )));

        // Add a second independent display seat.
        let LayoutLoadOutcome::Loaded(mut file) = reloaded else {
            panic!("expected loaded v1 layout");
        };
        file.displays.insert(
            "display-412x915".into(),
            BTreeMap::from([(
                "terminal".into(),
                SavedWindowFrame {
                    rect: Rect {
                        x: 0,
                        y: 0,
                        width: 412,
                        height: 820,
                    },
                    state: WindowState::Normal,
                    open: true,
                },
            )]),
        );
        save_layout_file_atomic(&path, &file).unwrap();
        let LayoutLoadOutcome::Loaded(final_file) = load_layout_file(&path) else {
            panic!("expected reloaded multi-display file");
        };
        assert_eq!(
            final_file.displays["display-1280x720"]["terminal"].rect.x,
            440
        );
        assert_eq!(
            final_file.displays["display-412x915"]["terminal"]
                .rect
                .width,
            412
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dock_state_and_shell_actions_handle_toggle_launch_and_launcher() {
        let mut core = DesktopShellCore::new(LayoutLoadOutcome::Missing);
        let start = core.startup_requests();
        assert_eq!(start.len(), 3);
        assert!(matches!(start[2], ClientReq::SubscribeShell));

        let _ = core.handle_event(ClientEvent::SeatLayoutInit {
            seat_id: "seat0".into(),
            legacy_json: None,
        });
        let reqs = core.handle_event(ClientEvent::WindowList {
            windows: vec![
                WindowSummary {
                    surface_id: 1,
                    app_id: Some("files".into()),
                    title: "Files".into(),
                    role: SurfaceRole::Window,
                    rect: Rect {
                        x: 10,
                        y: 10,
                        width: 400,
                        height: 500,
                    },
                    normal: Rect {
                        x: 10,
                        y: 10,
                        width: 400,
                        height: 500,
                    },
                    state: WindowState::Normal,
                    focused: false,
                    visible: true,
                    z_index: 1,
                },
                WindowSummary {
                    surface_id: 2,
                    app_id: Some("terminal".into()),
                    title: "Terminal".into(),
                    role: SurfaceRole::Window,
                    rect: Rect {
                        x: 420,
                        y: 10,
                        width: 600,
                        height: 500,
                    },
                    normal: Rect {
                        x: 420,
                        y: 10,
                        width: 600,
                        height: 500,
                    },
                    state: WindowState::Normal,
                    focused: true,
                    visible: true,
                    z_index: 2,
                },
            ],
            bounds: Rect {
                x: 0,
                y: 0,
                width: 1024,
                height: 720,
            },
            compact: false,
            fullscreen: false,
            seat_id: "seat0".into(),
        });
        assert!(matches!(
            reqs.last(),
            Some(ClientReq::PublishShellState { state }) if state.dock.len() == 2 && state.dock[0].focused
        ));

        // Toggling focused terminal minimizes it; toggling unfocused files focuses it;
        // toggling closed viewer launches it.
        let r1 = core.handle_event(ClientEvent::ShellInput {
            action: ShellAction::ToggleApp {
                app_id: "terminal".into(),
            },
        });
        assert!(r1.contains(&ClientReq::ShellCommand {
            action: ShellAction::Minimize { surface_id: 2 }
        }));
        let r2 = core.handle_event(ClientEvent::ShellInput {
            action: ShellAction::ToggleApp {
                app_id: "files".into(),
            },
        });
        assert!(r2.contains(&ClientReq::ShellCommand {
            action: ShellAction::Focus { surface_id: 1 }
        }));
        let r3 = core.handle_event(ClientEvent::ShellInput {
            action: ShellAction::ToggleApp {
                app_id: "viewer".into(),
            },
        });
        assert!(r3.contains(&ClientReq::ShellCommand {
            action: ShellAction::Launch {
                app_id: "viewer".into()
            }
        }));
        let r4 = core.handle_event(ClientEvent::ShellInput {
            action: ShellAction::ToggleLauncher {},
        });
        assert!(matches!(
            r4.last(),
            Some(ClientReq::PublishShellState { state }) if state.launcher_open
        ));
        let r5 = core.handle_event(ClientEvent::ShellInput {
            action: ShellAction::CloseLauncher {},
        });
        assert!(matches!(
            r5.last(),
            Some(ClientReq::PublishShellState { state }) if !state.launcher_open
        ));
        let r6 = core.handle_event(ClientEvent::ShellInput {
            action: ShellAction::CloseLauncher {},
        });
        assert!(r6.is_empty());
    }
}
