//! Portable state machine and wire protocol types for `/usr/bin/mounts` (`#63` `L6b-2`).
//!
//! Keeps mount snapshot formatting, host-consent state transitions, error policy, and
//! control-socket parsing independent of WASI/OS I/O so they can be exhaustively unit tested.
use abi::Errno;
use abi::gui::{MountConsentAction, MountConsentOutcome};
use abi::mount_ctl::{
    AttachmentInfo, BusyProcess, ExportSummary, FilesystemInfo, SourceInfo, SourceState,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Normalized tab name inside the Mounts GUI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountsTab {
    Mounted,
    Add,
    Connect,
    Publish,
}

impl MountsTab {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "add" => Self::Add,
            "connect" => Self::Connect,
            "publish" | "sharing" => Self::Publish,
            _ => Self::Mounted,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mounted => "mounted",
            Self::Add => "add",
            Self::Connect => "connect",
            Self::Publish => "publish",
        }
    }
}

/// Wire message sent by the sealed Mounts Document iframe to `/usr/bin/mounts`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountsUiMsg {
    Ready {},
    Refresh {},
    SelectTab {
        tab: String,
    },
    SelectMount {
        target: Option<String>,
    },
    OpenInFiles {
        target: String,
    },
    Unmount {
        target: String,
        #[serde(default)]
        lazy: bool,
    },
    ActivatePackage {
        source_id: String,
        name: String,
    },
    ForgetSource {
        source_id: String,
    },
    MountExistingSource {
        source_id: String,
        kind: String,
        name: String,
        writable: bool,
        execute: bool,
    },
    RenewAndMount {
        source_id: String,
        kind: String,
        name: String,
        writable: bool,
        execute: bool,
    },
    PickHostFolder {
        name: String,
        writable: bool,
        execute: bool,
        cloud: bool,
        save: bool,
    },
    MountOpfs {
        name: String,
        writable: bool,
        execute: bool,
        cloud: bool,
    },
    MountHelper {
        name: String,
        url: String,
        token: String,
        writable: bool,
        execute: bool,
        cloud: bool,
    },
    ConnectShare {
        name: String,
        address: String,
        password: String,
        writable: bool,
        execute: bool,
    },
    PublishExport {
        source: String,
        #[serde(default)]
        subpath: String,
        name: String,
        seconds: u64,
        #[serde(default)]
        password: String,
    },
    RevokeExport {
        id: String,
    },
    CopyAddress {
        address: String,
    },
}

/// Control request accepted on `/run/user/<uid>/mounts.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountsControlReq {
    Focus {
        #[serde(default)]
        tab: Option<String>,
    },
    Refresh {
        #[serde(default)]
        reset: bool,
    },
    Status {},
}

/// Control reply emitted on `/run/user/<uid>/mounts.sock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountsControlReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tab: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// View row for a mounted attachment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRow {
    pub target: String,
    pub fstype: String,
    pub kind_label: String,
    pub source_id: Option<String>,
    pub source_label: String,
    pub options: Vec<String>,
    pub health: String,
    pub uncertain_writes: bool,
    pub user_mount: bool,
    pub can_unmount: bool,
    pub is_private_ext: bool,
    pub mode_str: String,
    pub busy_summary: String,
    pub can_activate_package: bool,
    pub publishable: bool,
}

/// View row for a registered source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRow {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub state: String,
    pub writable: bool,
    pub execute: bool,
    pub can_manage: bool,
    pub can_mount: bool,
    pub can_renew: bool,
}

/// View row for a mounted filesystem.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemRow {
    pub label: String,
    pub fstype: String,
    pub bfree: u64,
    pub blocks: u64,
}

/// View row for a published export.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRow {
    pub id: String,
    pub name: String,
    pub address: String,
    pub password_protected: bool,
    pub expires_at: u64,
    pub active_clients: u32,
}

/// Full Mounts UI snapshot payload (boxed inside `MountsHostMsg::Snapshot` to keep the enum small).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountsSnapshot {
    pub tab: String,
    pub uid: u32,
    pub selected: Option<String>,
    pub helper_mode: bool,
    pub helper_reason: String,
    pub origin: String,
    pub relay_ready: bool,
    pub submitting: bool,
    pub ready_for_consent: bool,
    pub notice: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clear_fields: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reset_forms: bool,
    pub attachments: Vec<AttachmentRow>,
    pub sources: Vec<SourceRow>,
    pub filesystems: Vec<FilesystemRow>,
    pub exports: Vec<ExportRow>,
}

/// Wire message sent by `/usr/bin/mounts` to the sealed Mounts Document iframe
/// (chunked via `gui_doc::chunk_document_message` when > 4096 UTF-8 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum MountsHostMsg {
    Snapshot(Box<MountsSnapshot>),
    Notice { text: String, submitting: bool },
    Focus {},
}

/// Pending mount attachment waiting for a host `MountConsent` outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingConsentAttach {
    pub fstype: String,
    pub name: String,
    pub writable: bool,
    pub execute: bool,
    pub clear_field: Option<&'static str>,
}

/// Follow-up command returned by `MountsCore::apply_consent_outcome`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsentFollowUp {
    None,
    Attach {
        source_id: String,
        fstype: String,
        target: String,
        flags: u64,
    },
}

/// Human-readable filesystem kind label matching legacy `web/mount-manager.js`.
pub fn kind_label(fstype: &str) -> &str {
    match fstype {
        "directory" | "hostfs" => "Host folder · browser",
        "native-directory" | "helperfs" => "Host folder · helper",
        "browser-storage" | "opfs" => "Browser storage",
        "snapshot" => "File image",
        "private-extension" => "Private extension",
        "shared" | "sharefs" => "Shared directory",
        "tmpfs" => "Memory filesystem · tmpfs",
        "image" => "Image filesystem",
        "cloud" => "Cloud filesystem",
        "proc" => "Process filesystem · proc",
        "devtmpfs" => "Device filesystem · devtmpfs",
        "devpts" => "Pseudo-terminals · devpts",
        "cowfs" => "CoW filesystem · cowfs",
        other => other,
    }
}

/// Format POSIX permission bits (`0o750` -> `"rwxr-x---"`).
pub fn format_mode(mode: u32) -> String {
    const BITS: [char; 9] = ['r', 'w', 'x', 'r', 'w', 'x', 'r', 'w', 'x'];
    let mut out = String::with_capacity(9);
    for (i, ch) in BITS.iter().enumerate() {
        if mode & (0o400 >> i) != 0 {
            out.push(*ch);
        } else {
            out.push('-');
        }
    }
    out
}

/// Format busy process list identically to legacy `web/mount-manager.js`.
pub fn format_busy_processes(processes: &[BusyProcess]) -> String {
    processes
        .iter()
        .map(|p| format!("pid {} {} [{}]", p.pid, p.comm, p.reasons.join(", ")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Translate writable/execute checkboxes to `mountd` attach flags (`MS_RDONLY=1`, `MS_NOEXEC=8`).
pub fn mount_flags_for(writable: bool, execute: bool) -> u64 {
    (if writable {
        0
    } else {
        abi::mount_flags::MS_RDONLY
    }) | (if execute {
        0
    } else {
        abi::mount_flags::MS_NOEXEC
    })
}

/// Validate a user mount name (`[a-zA-Z0-9_.-]{1,80}`, not `.` or `..`).
pub fn valid_mount_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 80
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// Build the target path for a local or shared mount.
pub fn mount_target_path(fstype: &str, name: &str) -> Result<String, &'static str> {
    if !valid_mount_name(name) {
        return Err("Invalid mount name.");
    }
    let prefix = if fstype == "sharefs" {
        "/mnt/shared/"
    } else {
        "/mnt/local/"
    };
    Ok(format!("{prefix}{name}"))
}

/// Format export path from selected mount root and optional relative subdirectory.
pub fn export_source_path(source: &str, subpath: &str) -> Result<String, &'static str> {
    let base = source.trim().trim_end_matches('/');
    if base.is_empty() || !base.starts_with('/') || base.contains('\0') {
        return Err("Select a mounted filesystem to publish.");
    }
    let sub = subpath.trim().trim_matches('/');
    if sub.is_empty() {
        return Ok(base.to_owned());
    }
    if sub.contains('\0')
        || sub
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err("Invalid subdirectory path.");
    }
    Ok(format!("{base}/{sub}"))
}

/// Map `exportd` errors to human-readable UI notices.
pub fn export_error_message(errno: Errno) -> String {
    match errno {
        Errno::EPROTONOSUPPORT => {
            "EPROTONOSUPPORT Update os-local-helper before sharing this folder.".into()
        }
        Errno::EACCES => "EACCES Permission denied. Check the export credentials or ACL.".into(),
        Errno::EAGAIN => "EAGAIN Too many password attempts. Try again in a minute.".into(),
        other => format!("{other:?} {}", other.text()),
    }
}

fn source_state_str(state: &SourceState) -> &'static str {
    match state {
        SourceState::Granted => "granted",
        SourceState::NeedsRenewal => "needs_renewal",
        SourceState::Revoked => "revoked",
        SourceState::Offline => "offline",
        SourceState::Unavailable => "unavailable",
    }
}

/// Pure portable state machine for `/usr/bin/mounts`.
pub struct MountsCore {
    pub uid: u32,
    pub tab: MountsTab,
    pub selected: Option<String>,
    pub helper_mode: bool,
    pub helper_reason: String,
    pub origin: String,
    pub relay_ready: bool,
    pub capabilities_loaded: bool,
    pub submitting: bool,
    pub notice: String,
    pub pending_attach: Option<PendingConsentAttach>,
    pub pending_clear_fields: Vec<String>,
    pub pending_reset_forms: bool,
    pub attachments: Vec<AttachmentRow>,
    pub sources: Vec<SourceRow>,
    pub filesystems: Vec<FilesystemRow>,
    pub exports: Vec<ExportRow>,
}

impl MountsCore {
    pub fn new(uid: u32, initial_tab: MountsTab) -> Self {
        Self {
            uid,
            tab: initial_tab,
            selected: None,
            helper_mode: false,
            helper_reason:
                "This browser does not expose the directory picker API that OS uses for direct host-folder mounts."
                    .into(),
            origin: String::new(),
            relay_ready: false,
            capabilities_loaded: false,
            submitting: false,
            notice: String::new(),
            pending_attach: None,
            pending_clear_fields: Vec::new(),
            pending_reset_forms: false,
            attachments: Vec::new(),
            sources: Vec::new(),
            filesystems: Vec::new(),
            exports: Vec::new(),
        }
    }

    pub fn set_tab(&mut self, tab: MountsTab) {
        self.tab = tab;
        self.notice.clear();
    }

    pub fn select_mount(&mut self, target: Option<String>) {
        self.selected = target.filter(|t| self.attachments.iter().any(|a| a.target == *t));
    }

    /// Clear transient form/selection state when the active login session changes.
    pub fn reset_for_session_change(&mut self) {
        self.selected = None;
        self.pending_reset_forms = true;
        self.notice = "Session changed. Refresh to view its mounts.".into();
    }

    /// Update the live snapshot from `mountd`'s `ListAll` reply + VFS stat/manifest probes.
    pub fn apply_list_all(
        &mut self,
        sources: Vec<SourceInfo>,
        filesystems: Vec<FilesystemInfo>,
        attachments: Vec<AttachmentInfo>,
        exports: Vec<ExportSummary>,
        modes: &BTreeMap<String, u32>,
        manifests: &BTreeMap<String, bool>,
    ) {
        let attached_source_ids: Vec<&str> = attachments
            .iter()
            .filter_map(|a| a.source_id.as_deref())
            .collect();

        self.sources = sources
            .into_iter()
            .map(|s| {
                let can_manage = s.owner_uid == Some(self.uid);
                let is_attached = attached_source_ids.iter().any(|id| *id == s.id);
                let can_mount = can_manage && s.state == SourceState::Granted && !is_attached;
                let can_renew = can_manage && s.state == SourceState::NeedsRenewal;
                SourceRow {
                    id: s.id,
                    kind: s.kind.fstype().to_owned(),
                    label: s.label,
                    state: source_state_str(&s.state).to_owned(),
                    writable: s.writable,
                    execute: s.execute,
                    can_manage,
                    can_mount,
                    can_renew,
                }
            })
            .collect();

        self.filesystems = filesystems
            .into_iter()
            .map(|f| FilesystemRow {
                label: f.label,
                fstype: f.fstype,
                bfree: f.bfree,
                blocks: f.blocks,
            })
            .collect();

        self.exports = exports
            .into_iter()
            .map(|e| ExportRow {
                id: e.id,
                name: e.name,
                address: e.address,
                password_protected: e.password_protected,
                expires_at: e.expires_at,
                active_clients: e.active_clients,
            })
            .collect();

        self.attachments = attachments
            .into_iter()
            .map(|a| {
                let is_private_ext = a.target.starts_with("/opt/private/");
                let can_unmount = a.owner_uid == Some(self.uid) || self.uid == 0;
                let mode_str = modes
                    .get(&a.target)
                    .map(|m| format_mode(*m))
                    .unwrap_or_else(|| "—".into());
                let busy_summary = format_busy_processes(&a.busy_pids);
                let has_manifest = manifests.get(&a.target).copied().unwrap_or(false);
                let can_activate_package = a.source_id.is_some()
                    && a.user_mount
                    && !is_private_ext
                    && (!a.noexec || a.source_label.starts_with("snapshot:"))
                    && has_manifest;
                let publishable = matches!(a.fstype.as_str(), "opfs" | "hostfs" | "helperfs");
                let kind_lbl = kind_label(&a.fstype).to_owned();
                AttachmentRow {
                    target: a.target,
                    fstype: a.fstype,
                    kind_label: kind_lbl,
                    source_id: a.source_id,
                    source_label: a.source_label,
                    options: a.options,
                    health: a.health,
                    uncertain_writes: a.uncertain_writes,
                    user_mount: a.user_mount,
                    can_unmount,
                    is_private_ext,
                    mode_str,
                    busy_summary,
                    can_activate_package,
                    publishable,
                }
            })
            .collect();

        // Keep selected mount if it still exists; otherwise pick the first user mount.
        if !self
            .selected
            .as_deref()
            .is_some_and(|sel| self.attachments.iter().any(|a| a.target == sel))
        {
            self.selected = self
                .attachments
                .iter()
                .find(|a| a.user_mount)
                .map(|a| a.target.clone());
        }
    }

    /// Prepare a host `MountConsentAction` from a mutating UI action.
    pub fn begin_consent(
        &mut self,
        action: MountConsentAction,
        attach: PendingConsentAttach,
    ) -> Result<MountConsentAction, String> {
        // Validate mount target before prompting the host.
        mount_target_path(&attach.fstype, &attach.name).map_err(str::to_owned)?;
        self.submitting = true;
        self.notice.clear();
        self.pending_attach = Some(attach);
        Ok(action)
    }

    /// Process a `MountConsentOutcome` from the compositor.
    ///
    /// Security invariant:
    /// - `Canceled` or `Error` NEVER flips `helper_mode = true`.
    /// - ONLY `Unsupported` flips `helper_mode = true` and populates `origin` + `helper_reason`.
    pub fn apply_consent_outcome(&mut self, outcome: MountConsentOutcome) -> ConsentFollowUp {
        match outcome {
            MountConsentOutcome::Capabilities {
                host_picker,
                origin,
                browser_label,
                relay_ready,
                ..
            } => {
                self.capabilities_loaded = true;
                self.origin = origin;
                self.relay_ready = relay_ready;
                if !host_picker {
                    self.helper_mode = true;
                    let label = if browser_label.is_empty() {
                        "This browser"
                    } else {
                        browser_label.as_str()
                    };
                    self.helper_reason = format!(
                        "{label} does not expose the directory picker API that OS uses for direct host-folder mounts."
                    );
                } else {
                    self.helper_mode = false;
                }
                ConsentFollowUp::None
            }
            MountConsentOutcome::Granted { source_id, .. }
            | MountConsentOutcome::Renewed { source_id } => {
                let Some(pending) = self.pending_attach.take() else {
                    self.submitting = false;
                    return ConsentFollowUp::None;
                };
                if let Some(field) = pending.clear_field {
                    self.pending_clear_fields.push(field.to_owned());
                }
                match mount_target_path(&pending.fstype, &pending.name) {
                    Ok(target) => ConsentFollowUp::Attach {
                        source_id,
                        fstype: pending.fstype,
                        target,
                        flags: mount_flags_for(pending.writable, pending.execute),
                    },
                    Err(msg) => {
                        self.submitting = false;
                        self.notice = msg.to_owned();
                        ConsentFollowUp::None
                    }
                }
            }
            MountConsentOutcome::Canceled { .. } => {
                let was_mutating = self.pending_attach.take().is_some();
                self.submitting = false;
                if was_mutating {
                    self.notice = "Cancelled.".into();
                }
                ConsentFollowUp::None
            }
            MountConsentOutcome::Unsupported { origin, detail } => {
                self.pending_attach = None;
                self.submitting = false;
                self.helper_mode = true;
                if !origin.is_empty() {
                    self.origin = origin;
                }
                self.helper_reason = if detail.is_empty() {
                    "This browser could not provide a usable directory handle to OS.".into()
                } else {
                    detail.clone()
                };
                self.notice = if detail.is_empty() {
                    self.helper_reason.clone()
                } else {
                    detail
                };
                ConsentFollowUp::None
            }
            MountConsentOutcome::Error { errno, detail } => {
                self.pending_attach = None;
                self.submitting = false;
                self.notice = if detail.is_empty() {
                    errno.text().to_owned()
                } else {
                    detail
                };
                ConsentFollowUp::None
            }
        }
    }

    /// Build the full snapshot message to transmit to the sealed iframe.
    pub fn snapshot_msg(&mut self) -> MountsHostMsg {
        let clear_fields = std::mem::take(&mut self.pending_clear_fields);
        let reset_forms = std::mem::take(&mut self.pending_reset_forms);
        MountsHostMsg::Snapshot(Box::new(MountsSnapshot {
            tab: self.tab.as_str().to_owned(),
            uid: self.uid,
            selected: self.selected.clone(),
            helper_mode: self.helper_mode,
            helper_reason: self.helper_reason.clone(),
            origin: self.origin.clone(),
            relay_ready: self.relay_ready,
            submitting: self.submitting,
            ready_for_consent: self.capabilities_loaded,
            notice: self.notice.clone(),
            clear_fields,
            reset_forms,
            attachments: self.attachments.clone(),
            sources: self.sources.clone(),
            filesystems: self.filesystems.clone(),
            exports: self.exports.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui_doc::{DocChunkAssembler, chunk_document_message};
    use abi::contract::{
        Durability, FsCapabilities, IdentityScope, LockScope, Support, WriterModel,
    };
    use abi::mount_ctl::SourceKind;

    fn sample_caps() -> FsCapabilities {
        FsCapabilities {
            identity: IdentityScope::ProfileLocal,
            open_survives_unlink: Support::Yes,
            open_survives_rename: Support::Yes,
            hard_links: Support::Refused(Errno::EOPNOTSUPP),
            symlinks: Support::Refused(Errno::EOPNOTSUPP),
            exclusive_create: Support::Yes,
            atomic_rename: Support::Yes,
            rename_noreplace: Support::Yes,
            snapshots: Support::Refused(Errno::EOPNOTSUPP),
            reflink: Support::Refused(Errno::EOPNOTSUPP),
            writer_model: WriterModel::MultiWriter,
            durability: Durability::WritableClose,
            locks: LockScope::Profile,
        }
    }

    fn sample_attachment(target: &str, fstype: &str, user_mount: bool) -> AttachmentInfo {
        AttachmentInfo {
            mount_id: 1,
            parent_id: 0,
            ns_id: 1,
            fs_id: 10,
            source_id: user_mount.then(|| "src:00000000-0000-0000-0000-000000000001".into()),
            target: target.into(),
            fstype: fstype.into(),
            source_label: "project".into(),
            options: vec!["rw".into(), "nosuid".into(), "nodev".into()],
            read_only: false,
            nosuid: true,
            nodev: true,
            noexec: false,
            owner_uid: user_mount.then_some(1000),
            user_mount,
            health: "connected".into(),
            uncertain_writes: false,
            busy_pids: vec![BusyProcess {
                pid: 42,
                uid: 1000,
                comm: "osh".into(),
                reasons: vec!["cwd".into(), "fd".into()],
            }],
        }
    }

    #[test]
    fn snapshot_maps_modes_busy_pids_and_package_activation() {
        let mut core = MountsCore::new(1000, MountsTab::Mounted);
        let sources = vec![
            SourceInfo {
                id: "src:00000000-0000-0000-0000-000000000001".into(),
                kind: SourceKind::Hostfs,
                label: "project".into(),
                location: "project".into(),
                state: SourceState::Granted,
                writable: true,
                execute: true,
                saved: false,
                owner_uid: Some(1000),
            },
            SourceInfo {
                id: "src:00000000-0000-0000-0000-000000000002".into(),
                kind: SourceKind::Hostfs,
                label: "saved".into(),
                location: "saved".into(),
                state: SourceState::NeedsRenewal,
                writable: false,
                execute: false,
                saved: true,
                owner_uid: Some(1000),
            },
        ];
        let filesystems = vec![FilesystemInfo {
            fs_id: 10,
            fstype: "hostfs".into(),
            source: "project".into(),
            label: "project".into(),
            blocks: 1000,
            bfree: 800,
            bavail: 800,
            bsize: 4096,
            files: 100,
            ffree: 90,
            capabilities: sample_caps(),
            cowfs: None,
        }];
        let attachments = vec![
            sample_attachment("/", "cowfs", false),
            sample_attachment("/mnt/local/project", "hostfs", true),
        ];
        let modes = BTreeMap::from([("/mnt/local/project".into(), 0o40750)]);
        let manifests = BTreeMap::from([("/mnt/local/project".into(), true)]);
        core.apply_list_all(
            sources,
            filesystems,
            attachments,
            vec![],
            &modes,
            &manifests,
        );

        assert_eq!(core.selected.as_deref(), Some("/mnt/local/project"));
        assert_eq!(core.attachments[1].mode_str, "rwxr-x---");
        assert_eq!(core.attachments[1].busy_summary, "pid 42 osh [cwd, fd]");
        assert!(core.attachments[1].can_activate_package);
        assert!(core.attachments[1].can_unmount);
        assert!(!core.attachments[0].can_unmount);
        assert!(!core.sources[0].can_mount); // already attached
        assert!(core.sources[1].can_renew);
    }

    #[test]
    fn canceled_and_error_never_flip_helper_mode_only_unsupported_does() {
        let mut core = MountsCore::new(1000, MountsTab::Add);
        assert_eq!(
            core.apply_consent_outcome(MountConsentOutcome::Capabilities {
                host_picker: true,
                origin: "http://127.0.0.1:8788".into(),
                browser_label: "Chrome".into(),
                relay_ready: false,
                account_user: "user".into(),
                signed_in: false,
            }),
            ConsentFollowUp::None
        );
        assert!(!core.helper_mode);

        // User cancel leaves helper_mode false.
        let _ = core
            .begin_consent(
                MountConsentAction::PickHostFolder {
                    writable: true,
                    execute: true,
                    cloud: false,
                    save: false,
                },
                PendingConsentAttach {
                    fstype: "hostfs".into(),
                    name: "project".into(),
                    writable: true,
                    execute: true,
                    clear_field: None,
                },
            )
            .unwrap();
        assert_eq!(
            core.apply_consent_outcome(MountConsentOutcome::Canceled {
                errno: Errno::ECANCELED
            }),
            ConsentFollowUp::None
        );
        assert!(!core.helper_mode);
        assert_eq!(core.notice, "Cancelled.");

        // EACCES / permission error leaves helper_mode false.
        assert_eq!(
            core.apply_consent_outcome(MountConsentOutcome::Error {
                errno: Errno::EACCES,
                detail: "The requested local directory permission was not granted.".into(),
            }),
            ConsentFollowUp::None
        );
        assert!(!core.helper_mode);
        assert!(core.notice.contains("local directory permission"));

        // ONLY Unsupported switches to helper mode.
        assert_eq!(
            core.apply_consent_outcome(MountConsentOutcome::Unsupported {
                origin: "http://127.0.0.1:8788".into(),
                detail: "This browser could not provide a usable directory handle to OS.".into(),
            }),
            ConsentFollowUp::None
        );
        assert!(core.helper_mode);
        assert_eq!(core.origin, "http://127.0.0.1:8788");
    }

    #[test]
    fn granted_consent_produces_attach_followup_with_exact_rwx_flags() {
        let mut core = MountsCore::new(1000, MountsTab::Add);
        let _ = core
            .begin_consent(
                MountConsentAction::RegisterHelper {
                    url: "http://127.0.0.1:9999/".into(),
                    token: "secret".into(),
                    writable: true,
                    execute: false,
                    cloud: false,
                },
                PendingConsentAttach {
                    fstype: "helperfs".into(),
                    name: "work".into(),
                    writable: true,
                    execute: false,
                    clear_field: Some("token"),
                },
            )
            .unwrap();
        let follow = core.apply_consent_outcome(MountConsentOutcome::Granted {
            source_id: "src:00000000-0000-0000-0000-000000000009".into(),
            label: "Local helper".into(),
            writable: true,
        });
        assert_eq!(
            follow,
            ConsentFollowUp::Attach {
                source_id: "src:00000000-0000-0000-0000-000000000009".into(),
                fstype: "helperfs".into(),
                target: "/mnt/local/work".into(),
                flags: abi::mount_flags::MS_NOEXEC,
            }
        );
        let snap = core.snapshot_msg();
        let MountsHostMsg::Snapshot(snap_body) = &snap else {
            panic!("expected snapshot");
        };
        assert_eq!(snap_body.clear_fields, vec!["token".to_owned()]);
        let wire: serde_json::Value = serde_json::to_value(&snap).unwrap();
        assert_eq!(wire["t"], "snapshot");
        assert_eq!(wire["clear_fields"][0], "token");
    }

    #[test]
    fn large_snapshot_chunks_and_reassembles_over_4096_byte_document_limit() {
        let mut core = MountsCore::new(1000, MountsTab::Mounted);
        let mut attachments = Vec::new();
        for i in 0..40 {
            attachments.push(sample_attachment(
                &format!("/mnt/local/project-{i:02}"),
                "hostfs",
                true,
            ));
        }
        core.apply_list_all(
            vec![],
            vec![],
            attachments,
            vec![],
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        let json = serde_json::to_string(&core.snapshot_msg()).unwrap();
        assert!(json.len() > abi::gui::MAX_DOCUMENT_MESSAGE);
        let chunks = chunk_document_message(7, &json);
        assert!(chunks.len() > 1);
        let mut asm = DocChunkAssembler::default();
        let mut reassembled = None;
        for c in chunks {
            assert!(c.len() <= abi::gui::MAX_DOCUMENT_MESSAGE);
            if let Some(full) = asm.feed(&c) {
                reassembled = Some(full);
            }
        }
        assert_eq!(reassembled.as_deref(), Some(json.as_str()));
    }

    #[test]
    fn control_requests_and_export_paths_validate_strictly() {
        assert_eq!(
            serde_json::from_str::<MountsControlReq>(r#"{"op":"focus","tab":"publish"}"#).unwrap(),
            MountsControlReq::Focus {
                tab: Some("publish".into())
            }
        );
        assert_eq!(
            serde_json::from_str::<MountsControlReq>(r#"{"op":"refresh","reset":true}"#).unwrap(),
            MountsControlReq::Refresh { reset: true }
        );
        assert_eq!(
            serde_json::from_str::<MountsControlReq>(r#"{"op":"refresh"}"#).unwrap(),
            MountsControlReq::Refresh { reset: false }
        );
        assert!(serde_json::from_str::<MountsControlReq>(r#"{"op":"focus","uid":0}"#).is_err());
        let mut core = MountsCore::new(1000, MountsTab::Add);
        core.selected = Some("/mnt/local/project".into());
        core.reset_for_session_change();
        assert_eq!(core.selected, None);
        let MountsHostMsg::Snapshot(snap) = core.snapshot_msg() else {
            panic!("expected snapshot");
        };
        assert!(snap.reset_forms);
        assert!(snap.notice.contains("Session changed"));
        let MountsHostMsg::Snapshot(snap2) = core.snapshot_msg() else {
            panic!("expected snapshot");
        };
        assert!(!snap2.reset_forms);
        assert_eq!(
            export_source_path("/mnt/local/project", "sub/dir"),
            Ok("/mnt/local/project/sub/dir".into())
        );
        assert!(export_source_path("/mnt/local/project", "../etc").is_err());
        assert_eq!(MountsTab::parse("sharing"), MountsTab::Publish);
    }
}
