//! Boundary::Gui v1. All coordinates are logical seat pixels. Local clients use
//! length-prefixed JSON on AF_UNIX streams. Credentials are out-of-band.
use crate::{Bytes, Errno, contract::GUI_VERSION};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;

pub use crate::sha256::sha256_hex;

pub const SOCKET: &str = "/run/gui/seat0.sock";
pub const SAMPLE_BUNDLE: &str = "/usr/share/gui/samples/doc-view.json";
pub const TERMINAL_BUNDLE: &str = "/usr/share/gui/terminal/terminal.json";
pub const FILES_BUNDLE: &str = "/usr/share/gui/files/files.json";
pub const MOUNTS_BUNDLE: &str = "/usr/share/gui/mounts/mounts.json";
pub const SETTINGS_BUNDLE: &str = "/usr/share/gui/settings/settings.json";
pub const EDITOR_BUNDLE: &str = "/usr/share/gui/editor/editor.json";
pub const PREVIEW_BUNDLE: &str = "/usr/share/gui/preview/preview.json";
pub const MAX_BUNDLE: usize = 2 << 20;
pub const MAX_DOCUMENT_MESSAGE: usize = 4096;
pub const MAX_CLIPBOARD: usize = 1 << 20;
pub const MAX_EXPORT_INLINE: usize = 2 << 20;
pub const MAX_EXPORT_FD: u64 = 128 << 20;
pub const MAX_STREAM_ASSET_BLOB: u64 = 64 << 20;
pub const MAX_STREAM_ASSET_RANGE: u64 = 1 << 30;
pub const MAX_STREAM_ASSETS_PER_SURFACE: usize = 32;
pub const MAX_PDF_BYTES: u64 = 100_000_000;
pub const MAX_ARCHIVE_BYTES: u64 = 50_000_000;
pub const MAX_FRAME: usize = 4 << 20;
pub const IDS_PER_SEAT: u64 = 1 << 20;
pub const MAX_SURFACES: usize = 64;
pub const CAPABILITIES: &[&str] = &[
    "document",
    "pixel",
    "pixel-input",
    "drag-lease",
    "clipboard",
    "dnd",
    "picker",
    "export",
    "fullscreen",
    "media-stream",
    "preview-compute",
    "game-embed",
    "live-media",
    "portal",
    "notify",
    "a11y",
];

pub mod gui_ioctl {
    pub const INFO: u32 = 0x4755_0001;
    pub const NEXT_EVENT: u32 = 0x4755_0002;
    pub const DISPLAY_CMD: u32 = 0x4755_0003;
    pub const BIND_SURFACE: u32 = 0x4755_0004;
    pub const SIMULATE_LOSS: u32 = 0x4755_0005;
    pub const READ_BUNDLE: u32 = 0x4755_0009;
    pub const ARM_PICK: u32 = 0x4755_0008;
    pub const CHECK_BUNDLE: u32 = 0x4755_0007;
    pub const POLL: u32 = 0x4755_0006;
    pub const WATCH_SHELL: u32 = 0x4755_000a;
    pub const TAKE_SHELL: u32 = 0x4755_000b;
    pub const PEER_ROLES: u32 = 0x4755_000c;
    pub const PIN_FD: u32 = 0x4755_000d;
    pub const UNPIN_SURFACE: u32 = 0x4755_000e;
}

pub fn negotiate(versions: &[u32], required: &[String]) -> Result<u32, Errno> {
    if !versions.contains(&GUI_VERSION) {
        return Err(Errno::EPROTONOSUPPORT);
    }
    if required.iter().any(|s| !CAPABILITIES.contains(&s.as_str())) {
        return Err(Errno::EOPNOTSUPP);
    }
    Ok(GUI_VERSION)
}

pub fn frame<T: Serialize>(value: &T) -> Result<Vec<u8>, Errno> {
    let payload = serde_json::to_vec(value).map_err(|_| Errno::EINVAL)?;
    if payload.len() > MAX_FRAME {
        return Err(Errno::E2BIG);
    }
    let mut bytes = (payload.len() as u32).to_le_bytes().to_vec();
    bytes.extend(payload);
    Ok(bytes)
}
pub fn take_frame<T: DeserializeOwned>(bytes: &mut Vec<u8>) -> Result<Option<T>, Errno> {
    let Some(header) = bytes.get(..4) else {
        return Ok(None);
    };
    let len = u32::from_le_bytes(header.try_into().unwrap()) as usize;
    if len > MAX_FRAME {
        return Err(Errno::E2BIG);
    }
    let Some(raw) = bytes.get(4..4 + len) else {
        return Ok(None);
    };
    let value = serde_json::from_slice(raw).map_err(|_| Errno::EINVAL)?;
    bytes.drain(..4 + len);
    Ok(Some(value))
}

pub type SurfaceId = u64;
pub type LeaseId = u64;

macro_rules! record {
    ($(#[$attr:meta])* $name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        $(#[$attr])*
        pub struct $name { $(pub $field: $ty),* }
    }
}
macro_rules! choices {
    ($name:ident { $($variant:ident),+ }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(rename_all="snake_case")]
        pub enum $name { $($variant),+ }
    }
}
choices!(SurfaceRole {
    Window,
    Panel,
    Background,
    Launcher,
    Lock,
    Greeter
});
impl SurfaceRole {
    pub fn modal(self) -> bool {
        matches!(self, Self::Lock | Self::Greeter)
    }
}
choices!(WindowState {
    Normal,
    Minimized,
    Maximized,
    Left,
    Right
});
choices!(ResizeEdge {
    N,
    S,
    E,
    W,
    Ne,
    Nw,
    Se,
    Sw
});
choices!(SnapZone { Top, Left, Right });
choices!(PixelBackend { WebGpu, Software2d });
choices!(DragMode {
    LocalLease,
    Roundtrip
});
choices!(Shortcut {
    Next,
    Previous,
    Left,
    Right,
    Maximize,
    Restore,
    Cancel,
    Close
});
record!(
    #[derive(Copy, Default)]
    Size {
        width: u32,
        height: u32
    }
);
record!(
    #[derive(Copy, Default)]
    Rect {
        x: i32,
        y: i32,
        width: u32,
        height: u32
    }
);
impl Rect {
    pub fn constrained(mut self, bounds: Rect, min: Size, max: Option<Size>) -> Rect {
        let max = max.unwrap_or(Size {
            width: u32::MAX,
            height: u32::MAX,
        });
        let fit = |value: u32, low: u32, high: u32, room: u32| {
            value.clamp(low.max(1).min(room), high.max(low).max(1).min(room))
        };
        self.width = fit(self.width, min.width, max.width, bounds.width);
        self.height = fit(self.height, min.height, max.height, bounds.height);
        self.x = self.x.clamp(
            bounds.x,
            bounds.x.saturating_add_unsigned(bounds.width - self.width),
        );
        self.y = self.y.clamp(
            bounds.y,
            bounds
                .y
                .saturating_add_unsigned(bounds.height - self.height),
        );
        self
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum InteractiveOp {
    Move,
    Resize { edge: ResizeEdge },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HitRegion {
    Content,
    Titlebar,
    Edge(ResizeEdge),
}
fn default_true() -> bool {
    true
}
fn default_window_state() -> WindowState {
    WindowState::Normal
}
record!(
    #[derive(Default)]
    PeerGrants {
        roles: Vec<SurfaceRole>,
        allow_host_kind: bool
    }
);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DragLease {
    pub lease_id: LeaseId,
    pub surface_id: SurfaceId,
    pub op: InteractiveOp,
    pub start_rect: Rect,
    #[serde(default)]
    pub restore_rect: Option<Rect>,
    pub pointer_id: u32,
    pub bounds: Rect,
    pub min_size: Size,
    pub max_size: Option<Size>,
    pub snap_zones: Vec<SnapZone>,
    pub expires_at_ms: u64,
}
choices!(PointerKind {
    Down,
    Move,
    Up,
    Cancel
});
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KeyInput {
    pub key: String,
    pub code: String,
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
    pub meta: bool,
    pub composing: bool,
}
record!(WindowChromeSpec {
    title: String,
    show_minimize: bool,
    show_maximize: bool,
    show_close: bool,
    resizable: bool,
    focused: bool,
    state: WindowState
});
record!(DocumentSource {
    bundle_path: String,
    expected_sha256: String
});
record!(DocumentBundle {
    html: String,
    css: String,
    js: String
});
record!(VerifiedDocument {
    content_sha256: String,
    script_sha256: String,
    style_sha256: String,
    bundle: DocumentBundle
});
pub fn verify_document(source: &DocumentSource, raw: &[u8]) -> Result<VerifiedDocument, Errno> {
    if raw.len() > MAX_BUNDLE {
        return Err(Errno::E2BIG);
    }
    let content_sha256 = sha256_hex(raw);
    if content_sha256 != source.expected_sha256 {
        return Err(Errno::EIO);
    }
    let bundle: DocumentBundle = serde_json::from_slice(raw).map_err(|_| Errno::EINVAL)?;
    Ok(VerifiedDocument {
        content_sha256,
        script_sha256: sha256_hex(bundle.js.as_bytes()),
        style_sha256: sha256_hex(bundle.css.as_bytes()),
        bundle,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SurfaceKind {
    Document(DocumentSource),
    Pixel,
    Host { component: String },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceSpec {
    pub role: SurfaceRole,
    pub kind: SurfaceKind,
    pub title: String,
    pub rect: Rect,
    pub min_size: Size,
    pub max_size: Option<Size>,
    pub resizable: bool,
    #[serde(default)]
    pub app_id: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedWindowFrame {
    pub rect: Rect,
    #[serde(default = "default_window_state")]
    pub state: WindowState,
    #[serde(default)]
    pub open: bool,
}
record!(WindowSummary {
    surface_id: SurfaceId,
    app_id: Option<String>,
    title: String,
    role: SurfaceRole,
    rect: Rect,
    normal: Rect,
    state: WindowState,
    focused: bool,
    visible: bool,
    z_index: u32
});
record!(DockEntry {
    app_id: String,
    label: String,
    surface_id: Option<SurfaceId>,
    open: bool,
    minimized: bool,
    focused: bool,
    pinned: bool
});
record!(LauncherEntry {
    app_id: String,
    label: String,
    description: String
});
record!(
    #[derive(Default)]
    ShellStateView {
        dock: Vec<DockEntry>,
        launcher_open: bool,
        launcher_items: Vec<LauncherEntry>,
        compact: bool,
        fullscreen: bool,
        focused_title: Option<String>,
        seat_id: String
    }
);
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ShellAction {
    Focus { surface_id: SurfaceId },
    ToggleApp { app_id: String },
    Minimize { surface_id: SurfaceId },
    Maximize { surface_id: SurfaceId },
    Restore { surface_id: SurfaceId },
    Close { surface_id: SurfaceId },
    Launch { app_id: String },
    ToggleLauncher {},
    CloseLauncher {},
}
record!(A11y {
    label: String,
    role_description: String,
    live_announcement: String
});
record!(TransferItem {
    mime: String,
    data: Bytes
});
record!(BindSurface {
    surface_id: SurfaceId,
    socket_fd: u32
});
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountConsentAction {
    Capabilities {},
    PickHostFolder {
        writable: bool,
        execute: bool,
        cloud: bool,
        save: bool,
    },
    RenewHostFolder {
        source_id: String,
        writable: bool,
    },
    RegisterOpfs {
        writable: bool,
        execute: bool,
        cloud: bool,
    },
    RegisterHelper {
        url: String,
        token: String,
        writable: bool,
        execute: bool,
        cloud: bool,
    },
    RegisterShare {
        address: String,
        password: String,
        writable: bool,
        execute: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum MountConsentOutcome {
    Capabilities {
        host_picker: bool,
        origin: String,
        browser_label: String,
        relay_ready: bool,
        account_user: String,
        signed_in: bool,
    },
    Granted {
        source_id: String,
        label: String,
        writable: bool,
    },
    Renewed {
        source_id: String,
    },
    Canceled {
        errno: Errno,
    },
    Unsupported {
        origin: String,
        detail: String,
    },
    Error {
        errno: Errno,
        detail: String,
    },
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalIdentitySummary {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    #[serde(default)]
    pub root_volume_uuid: Option<String>,
    #[serde(default)]
    pub forked_from: Option<String>,
    #[serde(default)]
    pub ephemeral_if_unmodified: bool,
    #[serde(default)]
    pub can_sudo: bool,
    #[serde(default)]
    pub root_fstype: String,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudAccountSummary {
    pub signed_in: bool,
    #[serde(default)]
    pub cloud_user: Option<String>,
    #[serde(default)]
    pub scope: crate::auth_v2::RemoteScope,
    #[serde(default)]
    pub cloud_mount_active: bool,
    #[serde(default)]
    pub attached_devices: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountPortalAction {
    Status {},
    CloudSignIn {
        username: String,
        password: String,
        scope: crate::auth_v2::RemoteScope,
    },
    CloudSignOut {},
    SwitchLocalUser {},
    OpenMounts {
        #[serde(default)]
        tab: Option<String>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountPortalOutcome {
    State {
        local: LocalIdentitySummary,
        cloud: CloudAccountSummary,
        #[serde(default)]
        notice: Option<String>,
    },
    ActionDone {
        #[serde(default)]
        notice: Option<String>,
    },
    Canceled {
        errno: Errno,
    },
    Error {
        errno: Errno,
        detail: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopPortalAction {
    GetPreferences {},
    ApplyPreferences {
        theme: String,
        dock_autohide: bool,
    },
    SetFullscreen {
        active: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum DesktopPortalOutcome {
    Preferences {
        theme: String,
        dock_autohide: bool,
        fullscreen: bool,
    },
    Canceled {
        errno: Errno,
    },
    Error {
        errno: Errno,
        detail: String,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PortalKind {
    Mounts,
    Account,
    Desktop,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "portal", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortalRequest {
    Mounts { action: MountConsentAction },
    Account { action: AccountPortalAction },
    Desktop { action: DesktopPortalAction },
}
impl PortalRequest {
    pub fn kind(&self) -> PortalKind {
        match self {
            Self::Mounts { .. } => PortalKind::Mounts,
            Self::Account { .. } => PortalKind::Account,
            Self::Desktop { .. } => PortalKind::Desktop,
        }
    }
    pub fn is_mutating(&self) -> bool {
        !matches!(
            self,
            Self::Mounts {
                action: MountConsentAction::Capabilities {}
            } | Self::Account {
                action: AccountPortalAction::Status {}
            } | Self::Desktop {
                action: DesktopPortalAction::GetPreferences {}
            }
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "portal", rename_all = "snake_case", deny_unknown_fields)]
pub enum PortalResponse {
    Mounts { outcome: MountConsentOutcome },
    Account { outcome: AccountPortalOutcome },
    Desktop { outcome: DesktopPortalOutcome },
}
impl PortalResponse {
    pub fn kind(&self) -> PortalKind {
        match self {
            Self::Mounts { .. } => PortalKind::Mounts,
            Self::Account { .. } => PortalKind::Account,
            Self::Desktop { .. } => PortalKind::Desktop,
        }
    }
    pub fn canceled(kind: PortalKind, errno: Errno) -> Self {
        match kind {
            PortalKind::Mounts => Self::Mounts {
                outcome: MountConsentOutcome::Canceled { errno },
            },
            PortalKind::Account => Self::Account {
                outcome: AccountPortalOutcome::Canceled { errno },
            },
            PortalKind::Desktop => Self::Desktop {
                outcome: DesktopPortalOutcome::Canceled { errno },
            },
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetStreamMode {
    Blob,
    RangePull,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreviewJobKind {
    PdfOpen {},
    PdfRender {
        doc_id: u32,
        page: u32,
        width: u32,
    },
    PdfClose {
        doc_id: u32,
    },
    ListArchive {},
    Diagram {
        source: String,
    },
    Highlight {
        language: String,
        group: String,
        text: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PdfPageSize {
    pub width_milli: u32,
    pub height_milli: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMember {
    pub path: String,
    pub size: u64,
    pub directory: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreviewJobOutput {
    PdfOpened {
        doc_id: u32,
        pages: Vec<PdfPageSize>,
    },
    PdfRendered {
        doc_id: u32,
        page: u32,
        width: u32,
        height: u32,
    },
    PdfClosed {},
    ArchiveListed {
        entries: Vec<ArchiveMember>,
        more: bool,
    },
    Text {
        text: String,
    },
    Error {
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum MediaControlOp {
    OpenSpeaker {
        path: String,
    },
    BroadcastPresent {
        path: String,
        column: u32,
        row: u32,
    },
    ListenSdp {
        stream_id: String,
        label: String,
        offer_sdp: String,
        #[serde(default)]
        is_voice: bool,
    },
    StopListen {
        #[serde(default)]
        stream_id: Option<String>,
    },
    CaptureMicOffer {
        stream_id: String,
    },
    CaptureMicAnswer {
        stream_id: String,
        answer_sdp: String,
    },
    StopCapture {
        stream_id: String,
    },
    GoLive {
        path: String,
        keep: bool,
    },
    FetchPresentState {
        device: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum MediaEventPayload {
    SpeakerOpened {
        request_id: u64,
        ok: bool,
    },
    PresentBroadcast {
        path: String,
        column: u32,
        row: u32,
    },
    PresentState {
        request_id: u64,
        device: String,
        #[serde(default)]
        body_json: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
    SdpAnswer {
        request_id: u64,
        stream_id: String,
        sdp: String,
    },
    MicOffer {
        request_id: u64,
        stream_id: String,
        sdp: String,
        mid: String,
    },
    MicConnected {
        request_id: u64,
        stream_id: String,
    },
    StreamState {
        stream_id: String,
        state: String,
    },
    LiveSoundState {
        #[serde(default)]
        device: Option<String>,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        recording: Option<String>,
        #[serde(default)]
        since_ms: u64,
        #[serde(default)]
        progress: String,
        #[serde(default)]
        note: Option<String>,
        active: bool,
    },
    Error {
        request_id: u64,
        #[serde(default)]
        stream_id: Option<String>,
        detail: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionEventOp {
    Subscribe {},
    Unsubscribe {},
    Send { payload_json: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientReq {
    Hello {
        versions: Vec<u32>,
        required: Vec<String>,
    },
    CreateSurface {
        spec: SurfaceSpec,
    },
    Destroy {
        surface_id: SurfaceId,
    },
    SetTitle {
        surface_id: SurfaceId,
        title: String,
    },
    SetSizeLimits {
        surface_id: SurfaceId,
        min_size: Size,
        max_size: Option<Size>,
    },
    RequestState {
        surface_id: SurfaceId,
        state: WindowState,
    },
    SetA11y {
        surface_id: SurfaceId,
        a11y: A11y,
    },
    ClipboardWrite {
        surface_id: SurfaceId,
        item: TransferItem,
    },
    ClipboardRead {
        surface_id: SurfaceId,
    },
    DndStart {
        surface_id: SurfaceId,
        items: Vec<TransferItem>,
    },
    PickFile {
        surface_id: SurfaceId,
        #[serde(default)]
        multiple: bool,
        #[serde(default)]
        cloud_dest: Option<String>,
    },
    CancelPick {
        request_id: u64,
    },
    SimulateLoss {
        surface_id: SurfaceId,
    },
    DocumentReply {
        surface_id: SurfaceId,
        text: String,
    },
    Notify {
        surface_id: SurfaceId,
        title: String,
        body: String,
    },
    DismissNotification {
        surface_id: SurfaceId,
        id: u64,
    },
    SubscribeShell,
    ShellCommand {
        action: ShellAction,
    },
    SetSavedLayout {
        seat_id: String,
        frames: BTreeMap<String, SavedWindowFrame>,
    },
    PublishShellState {
        state: ShellStateView,
    },
    LegacyLayoutMigrated {
        seat_id: String,
    },
    Portal {
        surface_id: SurfaceId,
        request: PortalRequest,
    },
    ExportFile {
        surface_id: SurfaceId,
        filename: String,
        mime: String,
        #[serde(default)]
        data: Option<Bytes>,
    },
    RequestFullscreen {
        surface_id: SurfaceId,
        active: bool,
    },
    StreamAsset {
        surface_id: SurfaceId,
        asset_id: u64,
        mime: String,
        mode: AssetStreamMode,
    },
    ReleaseAsset {
        surface_id: SurfaceId,
        #[serde(default)]
        asset_id: Option<u64>,
    },
    PreviewJob {
        surface_id: SurfaceId,
        job_id: u64,
        kind: PreviewJobKind,
    },
    MountGameEmbed {
        surface_id: SurfaceId,
        #[serde(default)]
        entry: Option<String>,
        #[serde(default)]
        title: String,
    },
    MediaControl {
        surface_id: SurfaceId,
        request_id: u64,
        control: MediaControlOp,
    },
    SessionEvents {
        surface_id: SurfaceId,
        control: SessionEventOp,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientEvent {
    Hello {
        version: u32,
    },
    Created {
        surface_id: SurfaceId,
    },
    Ok,
    Error {
        errno: Errno,
    },
    Configure {
        surface_id: SurfaceId,
        width: u32,
        height: u32,
        state: WindowState,
    },
    CloseRequested {
        surface_id: SurfaceId,
    },
    Focus {
        surface_id: SurfaceId,
        focused: bool,
    },
    DeviceLost {
        surface_id: SurfaceId,
        generation: u32,
    },
    SurfaceReady {
        surface_id: SurfaceId,
        generation: u32,
        backend: PixelBackend,
    },
    Pointer {
        surface_id: SurfaceId,
        kind: PointerKind,
        x: i32,
        y: i32,
        button: i16,
        pointer_id: u32,
    },
    Key {
        surface_id: SurfaceId,
        #[serde(flatten)]
        input: KeyInput,
    },
    PasteRequested {
        surface_id: SurfaceId,
    },
    Clipboard {
        item: TransferItem,
    },
    Picked {
        surface_id: SurfaceId,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        size: u64,
        #[serde(default)]
        index: u32,
        #[serde(default)]
        total: u32,
    },
    UploadProgress {
        request_id: u64,
        surface_id: SurfaceId,
        text: String,
        done: bool,
        #[serde(default)]
        error: Option<String>,
    },
    Notification {
        id: u64,
    },
    DndOffer {
        surface_id: SurfaceId,
        mimes: Vec<String>,
        x: i32,
        y: i32,
    },
    DndDrop {
        surface_id: SurfaceId,
        items: Vec<TransferItem>,
    },
    DocumentMessage {
        surface_id: SurfaceId,
        text: String,
    },
    WindowList {
        windows: Vec<WindowSummary>,
        bounds: Rect,
        compact: bool,
        fullscreen: bool,
        seat_id: String,
    },
    ShellInput {
        action: ShellAction,
    },
    SeatLayoutInit {
        seat_id: String,
        legacy_json: Option<String>,
    },
    PortalResult {
        surface_id: SurfaceId,
        response: PortalResponse,
    },
    FullscreenChanged {
        surface_id: SurfaceId,
        active: bool,
    },
    FullscreenError {
        surface_id: SurfaceId,
        detail: String,
    },
    PreviewJobResult {
        surface_id: SurfaceId,
        job_id: u64,
        output: PreviewJobOutput,
    },
    MediaEvent {
        surface_id: SurfaceId,
        payload: MediaEventPayload,
    },
    SessionEvent {
        surface_id: SurfaceId,
        event_json: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputEvent {
    Viewport {
        bounds: Rect,
        mode: DragMode,
    },
    SeatActive {
        active: bool,
    },
    HostFocus,
    FocusRequest {
        surface_id: SurfaceId,
    },
    PointerDown {
        surface_id: SurfaceId,
        hit_region: HitRegion,
        x: i32,
        y: i32,
        pointer_id: u32,
        timestamp_ms: u64,
        #[serde(default)]
        button: i16,
    },
    PointerMove {
        surface_id: SurfaceId,
        pointer_id: u32,
        x: i32,
        y: i32,
    },
    PointerUp {
        surface_id: SurfaceId,
        pointer_id: u32,
        button: i16,
        x: i32,
        y: i32,
        #[serde(default)]
        canceled: bool,
    },
    Key {
        surface_id: SurfaceId,
        paste: bool,
        #[serde(flatten)]
        input: KeyInput,
    },
    Paste {
        surface_id: SurfaceId,
        text: Option<String>,
    },
    Shortcut {
        surface_id: SurfaceId,
        key: Shortcut,
    },
    InteractiveOpProgress {
        #[serde(default)]
        serial: u32,
        lease_id: LeaseId,
        surface_id: SurfaceId,
        rect: Rect,
        snap_hint: Option<SnapZone>,
    },
    InteractiveOpEnd {
        lease_id: LeaseId,
        surface_id: SurfaceId,
        rect: Rect,
        snap_hint: Option<SnapZone>,
        canceled: bool,
    },
    ChromeAction {
        surface_id: SurfaceId,
        state: Option<WindowState>,
    },
    DndHover {
        pointer_id: u32,
        surface_id: SurfaceId,
        x: i32,
        y: i32,
    },
    DndDrop {
        pointer_id: u32,
        button: i16,
        surface_id: SurfaceId,
    },
    PickerResult {
        surface_id: SurfaceId,
        request_id: u64,
        chosen: bool,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        size: u64,
        #[serde(default)]
        index: u32,
        #[serde(default)]
        total: u32,
    },
    ExternalDrop {
        surface_id: SurfaceId,
        request_id: u64,
    },
    UploadProgress {
        request_id: u64,
        surface_id: SurfaceId,
        text: String,
        done: bool,
        #[serde(default)]
        error: Option<String>,
    },
    DocumentMessage {
        surface_id: SurfaceId,
        text: String,
    },
    TitlebarDoubleClick {
        surface_id: SurfaceId,
    },
    ShellInput {
        action: ShellAction,
    },
    SeatLayoutInit {
        seat_id: String,
        legacy_json: Option<String>,
    },
    FullscreenChanged {
        #[serde(default)]
        surface_id: Option<SurfaceId>,
        active: bool,
        #[serde(default)]
        error: Option<String>,
    },
    PortalResult {
        request_id: u64,
        surface_id: SurfaceId,
        response: PortalResponse,
    },
    PreviewJobResult {
        surface_id: SurfaceId,
        job_id: u64,
        output: PreviewJobOutput,
    },
    MediaEvent {
        #[serde(default)]
        surface_id: Option<SurfaceId>,
        payload: MediaEventPayload,
    },
    SessionEvent {
        #[serde(default)]
        surface_id: Option<SurfaceId>,
        event_json: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisplayEvent {
    SurfaceDeviceLost {
        surface_id: SurfaceId,
        generation: u32,
        reason: String,
        fallback: PixelBackend,
    },
    SurfaceReady {
        surface_id: SurfaceId,
        generation: u32,
        backend: PixelBackend,
        width: u32,
        height: u32,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SeatEvent {
    Input(InputEvent),
    Display(DisplayEvent),
    ClientGone { pid: u32 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisplayCmd {
    Map {
        surface_id: SurfaceId,
        owner_pid: u32,
        role: SurfaceRole,
        rect: Rect,
        document: Option<VerifiedDocument>,
        #[serde(default)]
        compat_app: Option<String>,
        #[serde(default)]
        app_id: Option<String>,
        generation: u32,
    },
    Unmap {
        surface_id: SurfaceId,
    },
    Geometry {
        surface_id: SurfaceId,
        rect: Rect,
        state: WindowState,
        #[serde(default = "default_true")]
        visible: bool,
        #[serde(default)]
        filled: bool,
        #[serde(default)]
        z_index: u32,
    },
    Focus {
        surface_id: Option<SurfaceId>,
        modal: bool,
    },
    UpdateSurfaceChrome {
        surface_id: SurfaceId,
        chrome: WindowChromeSpec,
    },
    SetA11y {
        surface_id: SurfaceId,
        a11y: A11y,
    },
    BeginInteractiveOp {
        lease: DragLease,
    },
    CancelInteractiveOp {
        lease_id: LeaseId,
    },
    DragFrame {
        serial: u32,
        surface_id: SurfaceId,
        lease_id: LeaseId,
        rect: Rect,
    },
    SetDragMode {
        mode: DragMode,
    },
    RecreatePixelCanvas {
        surface_id: SurfaceId,
        generation: u32,
        width: u32,
        height: u32,
        backend: PixelBackend,
    },
    DndTracking {
        active: bool,
        pointer_id: u32,
    },
    PickerDelivered {
        request_id: u64,
    },
    CancelPicker {
        request_id: u64,
    },
    ClipboardWrite {
        item: TransferItem,
    },
    PickFile {
        surface_id: SurfaceId,
        request_id: u64,
        #[serde(default)]
        owner_pid: u32,
        #[serde(default)]
        multiple: bool,
        #[serde(default)]
        cloud_dest: Option<String>,
    },
    DocumentReply {
        surface_id: SurfaceId,
        text: String,
    },
    Notify {
        id: u64,
        owner_pid: u32,
        title: String,
        body: String,
    },
    DismissNotification {
        id: u64,
    },
    ShellState {
        state: ShellStateView,
    },
    LaunchApp {
        app_id: String,
    },
    LegacyLayoutMigrated {
        seat_id: String,
    },
    LayoutReady {
        seat_id: String,
    },
    Portal {
        request_id: u64,
        surface_id: SurfaceId,
        owner_pid: u32,
        request: PortalRequest,
    },
    ExportFile {
        request_id: u64,
        surface_id: SurfaceId,
        owner_pid: u32,
        filename: String,
        mime: String,
        #[serde(default)]
        data: Option<Bytes>,
        #[serde(default)]
        pin_id: Option<u64>,
        #[serde(default)]
        size: u64,
    },
    SetFullscreen {
        surface_id: SurfaceId,
        active: bool,
    },
    StreamAsset {
        surface_id: SurfaceId,
        owner_pid: u32,
        asset_id: u64,
        mime: String,
        mode: AssetStreamMode,
        pin_id: u64,
        size: u64,
    },
    ReleaseAsset {
        surface_id: SurfaceId,
        #[serde(default)]
        asset_id: Option<u64>,
    },
    PreviewJob {
        surface_id: SurfaceId,
        owner_pid: u32,
        job_id: u64,
        kind: PreviewJobKind,
        #[serde(default)]
        pin_id: Option<u64>,
        #[serde(default)]
        size: u64,
    },
    SetGameEmbed {
        surface_id: SurfaceId,
        #[serde(default)]
        entry: Option<String>,
        #[serde(default)]
        title: String,
    },
    MediaControl {
        surface_id: SurfaceId,
        owner_pid: u32,
        request_id: u64,
        control: MediaControlOp,
    },
    SessionEvents {
        surface_id: SurfaceId,
        owner_pid: u32,
        control: SessionEventOp,
    },
    SeatReset,
}
pub trait GuiHostSink {
    fn display(&self, cmd: DisplayCmd);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_frames_and_negotiation() {
        let mut bytes = frame(&ClientReq::Hello {
            versions: vec![1],
            required: vec![],
        })
        .unwrap();
        let last = bytes.pop().unwrap();
        assert_eq!(take_frame::<ClientReq>(&mut bytes), Ok(None));
        bytes.push(last);
        assert!(matches!(
            take_frame(&mut bytes),
            Ok(Some(ClientReq::Hello { .. }))
        ));
        assert!(bytes.is_empty());
        assert_eq!(
            take_frame::<ClientReq>(&mut u32::MAX.to_le_bytes().to_vec()),
            Err(Errno::E2BIG)
        );
        assert!(
            serde_json::from_str::<ClientReq>(r#"{"op":"destroy","surface_id":1,"pid":1}"#)
                .is_err()
        );
        assert_eq!(negotiate(&[2], &[]), Err(Errno::EPROTONOSUPPORT));
        assert_eq!(negotiate(&[1], &["unknown".into()]), Err(Errno::EOPNOTSUPP));
    }
    #[test]
    fn bundle_limit_and_exact_bytes() {
        let raw = br#"{"html":"","css":"","js":""}"#;
        let source = DocumentSource {
            bundle_path: SAMPLE_BUNDLE.into(),
            expected_sha256: sha256_hex(raw),
        };
        assert_eq!(
            verify_document(&source, raw).unwrap().script_sha256,
            sha256_hex(b"")
        );
        assert_eq!(verify_document(&source, b"changed"), Err(Errno::EIO));
        assert_eq!(
            verify_document(&source, &vec![0; MAX_BUNDLE + 1]),
            Err(Errno::E2BIG)
        );
    }
    #[test]
    fn desktop_shell_wire_defaults_and_strict_fields() {
        let lease: DragLease = serde_json::from_str(
            r#"{"lease_id":1,"surface_id":2,"op":"move","start_rect":{"x":0,"y":0,"width":300,"height":200},"pointer_id":1,"bounds":{"x":0,"y":0,"width":1024,"height":720},"min_size":{"width":280,"height":180},"max_size":null,"snap_zones":[],"expires_at_ms":1000}"#,
        )
        .unwrap();
        assert_eq!(lease.restore_rect, None);

        let spec: SurfaceSpec = serde_json::from_str(
            r#"{"role":"window","kind":"pixel","title":"App","rect":{"x":0,"y":0,"width":300,"height":200},"min_size":{"width":100,"height":80},"max_size":null,"resizable":true}"#,
        )
        .unwrap();
        assert_eq!(spec.app_id, None);

        let host_spec = SurfaceSpec {
            role: SurfaceRole::Window,
            kind: SurfaceKind::Host {
                component: "terminal".into(),
            },
            title: "Terminal".into(),
            rect: Rect {
                x: 10,
                y: 20,
                width: 600,
                height: 400,
            },
            min_size: Size {
                width: 280,
                height: 180,
            },
            max_size: None,
            resizable: true,
            app_id: Some("terminal".into()),
        };
        let encoded = frame(&ClientReq::CreateSurface {
            spec: host_spec.clone(),
        })
        .unwrap();
        assert_eq!(
            take_frame::<ClientReq>(&mut encoded.clone()).unwrap(),
            Some(ClientReq::CreateSurface { spec: host_spec })
        );

        let geom: DisplayCmd = serde_json::from_str(
            r#"{"op":"geometry","surface_id":1,"rect":{"x":0,"y":0,"width":300,"height":200},"state":"normal"}"#,
        )
        .unwrap();
        assert_eq!(
            geom,
            DisplayCmd::Geometry {
                surface_id: 1,
                rect: Rect {
                    x: 0,
                    y: 0,
                    width: 300,
                    height: 200
                },
                state: WindowState::Normal,
                visible: true,
                filled: false,
                z_index: 0,
            }
        );

        let map: DisplayCmd = serde_json::from_str(
            r#"{"op":"map","surface_id":1,"owner_pid":5,"role":"window","rect":{"x":0,"y":0,"width":300,"height":200},"document":null,"generation":1}"#,
        )
        .unwrap();
        assert!(matches!(
            map,
            DisplayCmd::Map {
                compat_app: None,
                ..
            }
        ));

        let grants = PeerGrants {
            roles: vec![
                SurfaceRole::Panel,
                SurfaceRole::Background,
                SurfaceRole::Launcher,
            ],
            allow_host_kind: true,
        };
        let mut raw = frame(&grants).unwrap();
        assert_eq!(take_frame::<PeerGrants>(&mut raw).unwrap(), Some(grants));

        assert!(
            serde_json::from_str::<ClientReq>(
                r#"{"op":"shell_command","action":{"action":"toggle_launcher","extra":1}}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<PeerGrants>(
                r#"{"roles":[],"allow_host_kind":false,"rogue":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<InputEvent>(
                r#"{"op":"titlebar_double_click","surface_id":1,"extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn l6b_picker_drop_and_upload_progress_defaults_and_strict_fields() {
        let old_pick: ClientReq =
            serde_json::from_str(r#"{"op":"pick_file","surface_id":3}"#).unwrap();
        assert_eq!(
            old_pick,
            ClientReq::PickFile {
                surface_id: 3,
                multiple: false,
                cloud_dest: None,
            }
        );

        let cancel: ClientReq =
            serde_json::from_str(r#"{"op":"cancel_pick","request_id":9}"#).unwrap();
        assert_eq!(cancel, ClientReq::CancelPick { request_id: 9 });

        let old_picked: ClientEvent =
            serde_json::from_str(r#"{"op":"picked","surface_id":3}"#).unwrap();
        assert_eq!(
            old_picked,
            ClientEvent::Picked {
                surface_id: 3,
                name: None,
                size: 0,
                index: 0,
                total: 0,
            }
        );

        let old_result: InputEvent = serde_json::from_str(
            r#"{"op":"picker_result","surface_id":3,"request_id":9,"chosen":true}"#,
        )
        .unwrap();
        assert_eq!(
            old_result,
            InputEvent::PickerResult {
                surface_id: 3,
                request_id: 9,
                chosen: true,
                name: None,
                size: 0,
                index: 0,
                total: 0,
            }
        );

        let old_cmd: DisplayCmd =
            serde_json::from_str(r#"{"op":"pick_file","surface_id":3,"request_id":9}"#).unwrap();
        assert_eq!(
            old_cmd,
            DisplayCmd::PickFile {
                surface_id: 3,
                request_id: 9,
                owner_pid: 0,
                multiple: false,
                cloud_dest: None,
            }
        );

        let drop_ev: InputEvent =
            serde_json::from_str(r#"{"op":"external_drop","surface_id":3,"request_id":11}"#)
                .unwrap();
        assert_eq!(
            drop_ev,
            InputEvent::ExternalDrop {
                surface_id: 3,
                request_id: 11,
            }
        );

        let prog: InputEvent = serde_json::from_str(
            r#"{"op":"upload_progress","request_id":11,"surface_id":3,"text":"↑ a.txt · 50%","done":false}"#,
        )
        .unwrap();
        assert_eq!(
            prog,
            InputEvent::UploadProgress {
                request_id: 11,
                surface_id: 3,
                text: "↑ a.txt · 50%".into(),
                done: false,
                error: None,
            }
        );

        assert!(
            serde_json::from_str::<ClientReq>(r#"{"op":"pick_file","surface_id":3,"rogue":true}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<InputEvent>(
                r#"{"op":"external_drop","surface_id":3,"request_id":11,"rogue":1}"#
            )
            .is_err()
        );
    }

    #[test]
    fn unified_portal_wire_roundtrip_and_strict_fields() {
        let req = ClientReq::Portal {
            surface_id: 7,
            request: PortalRequest::Mounts {
                action: MountConsentAction::PickHostFolder {
                    writable: true,
                    execute: false,
                    cloud: true,
                    save: true,
                },
            },
        };
        assert_eq!(
            take_frame::<ClientReq>(&mut frame(&req).unwrap()).unwrap(),
            Some(req)
        );
        let caps_req = ClientReq::Portal {
            surface_id: 7,
            request: PortalRequest::Mounts {
                action: MountConsentAction::Capabilities {},
            },
        };
        assert_eq!(
            take_frame::<ClientReq>(&mut frame(&caps_req).unwrap()).unwrap(),
            Some(caps_req)
        );
        let acct_req = ClientReq::Portal {
            surface_id: 8,
            request: PortalRequest::Account {
                action: AccountPortalAction::CloudSignIn {
                    username: "alice".into(),
                    password: "secret".into(),
                    scope: crate::auth_v2::RemoteScope {
                        cloud_fs: true,
                        devices: vec!["archive".into()],
                        ..Default::default()
                    },
                },
            },
        };
        assert_eq!(
            take_frame::<ClientReq>(&mut frame(&acct_req).unwrap()).unwrap(),
            Some(acct_req)
        );
        let desk_req = ClientReq::Portal {
            surface_id: 8,
            request: PortalRequest::Desktop {
                action: DesktopPortalAction::ApplyPreferences {
                    theme: "dark".into(),
                    dock_autohide: true,
                },
            },
        };
        assert_eq!(
            take_frame::<ClientReq>(&mut frame(&desk_req).unwrap()).unwrap(),
            Some(desk_req)
        );
        let cmd = DisplayCmd::Portal {
            request_id: 42,
            surface_id: 7,
            owner_pid: 19,
            request: PortalRequest::Mounts {
                action: MountConsentAction::RenewHostFolder {
                    source_id: "src:00000000-0000-0000-0000-000000000001".into(),
                    writable: true,
                },
            },
        };
        assert_eq!(
            take_frame::<DisplayCmd>(&mut frame(&cmd).unwrap()).unwrap(),
            Some(cmd)
        );
        let ev = InputEvent::PortalResult {
            request_id: 42,
            surface_id: 7,
            response: PortalResponse::Mounts {
                outcome: MountConsentOutcome::Granted {
                    source_id: "src:00000000-0000-0000-0000-000000000001".into(),
                    label: "project".into(),
                    writable: true,
                },
            },
        };
        assert_eq!(
            take_frame::<InputEvent>(&mut frame(&ev).unwrap()).unwrap(),
            Some(ev)
        );
        let client_ev = ClientEvent::PortalResult {
            surface_id: 7,
            response: PortalResponse::Mounts {
                outcome: MountConsentOutcome::Unsupported {
                    origin: "http://127.0.0.1:8788".into(),
                    detail: "Picker unavailable".into(),
                },
            },
        };
        assert_eq!(
            take_frame::<ClientEvent>(&mut frame(&client_ev).unwrap()).unwrap(),
            Some(client_ev)
        );
        let acct_ev = ClientEvent::PortalResult {
            surface_id: 8,
            response: PortalResponse::Account {
                outcome: AccountPortalOutcome::State {
                    local: LocalIdentitySummary {
                        username: "user".into(),
                        uid: 1000,
                        gid: 1000,
                        home: "/home/user".into(),
                        root_volume_uuid: Some("12345678-aaaa".into()),
                        forked_from: None,
                        ephemeral_if_unmodified: false,
                        can_sudo: true,
                        root_fstype: "cowfs".into(),
                    },
                    cloud: CloudAccountSummary {
                        signed_in: false,
                        cloud_user: None,
                        scope: Default::default(),
                        cloud_mount_active: false,
                        attached_devices: vec![],
                    },
                    notice: None,
                },
            },
        };
        assert_eq!(
            take_frame::<ClientEvent>(&mut frame(&acct_ev).unwrap()).unwrap(),
            Some(acct_ev)
        );
        assert!(
            serde_json::from_str::<MountConsentAction>(r#"{"action":"capabilities","extra":1}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<MountConsentOutcome>(
                r#"{"status":"canceled","errno":"ECANCELED","rogue":true}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<AccountPortalAction>(r#"{"action":"status","extra":1}"#)
                .is_err()
        );
        assert!(
            serde_json::from_str::<DesktopPortalAction>(
                r#"{"action":"apply_preferences","theme":"light","dock_autohide":false,"x":1}"#
            )
            .is_err()
        );
    }

    #[test]
    fn l6c_export_file_wire_roundtrip_and_strict_fields() {
        let req = ClientReq::ExportFile {
            surface_id: 9,
            filename: "notes.md".into(),
            mime: "text/plain;charset=utf-8".into(),
            data: Some(Bytes(b"hello".to_vec())),
        };
        assert_eq!(
            take_frame::<ClientReq>(&mut frame(&req).unwrap()).unwrap(),
            Some(req)
        );
        let cmd = DisplayCmd::ExportFile {
            request_id: 12,
            surface_id: 9,
            owner_pid: 44,
            filename: "notes.md".into(),
            mime: "text/plain;charset=utf-8".into(),
            data: Some(Bytes(b"hello".to_vec())),
            pin_id: None,
            size: 5,
        };
        assert_eq!(
            take_frame::<DisplayCmd>(&mut frame(&cmd).unwrap()).unwrap(),
            Some(cmd)
        );
        assert!(
            serde_json::from_str::<ClientReq>(
                r#"{"op":"export_file","surface_id":9,"filename":"a.txt","mime":"text/plain","extra":1}"#
            )
            .is_err()
        );
    }

    #[test]
    fn l6c_preview_protocol_wire_roundtrip_and_strict_fields() {
        let reqs = [
            ClientReq::RequestFullscreen {
                surface_id: 4,
                active: true,
            },
            ClientReq::StreamAsset {
                surface_id: 4,
                asset_id: 7,
                mime: "image/png".into(),
                mode: AssetStreamMode::Blob,
            },
            ClientReq::ReleaseAsset {
                surface_id: 4,
                asset_id: Some(7),
            },
            ClientReq::PreviewJob {
                surface_id: 4,
                job_id: 2,
                kind: PreviewJobKind::PdfRender {
                    doc_id: 1,
                    page: 0,
                    width: 1200,
                },
            },
            ClientReq::MountGameEmbed {
                surface_id: 4,
                entry: Some("demo".into()),
                title: "Demo".into(),
            },
            ClientReq::MediaControl {
                surface_id: 4,
                request_id: 8,
                control: MediaControlOp::OpenSpeaker {
                    path: "/deck.slides.md".into(),
                },
            },
            ClientReq::SessionEvents {
                surface_id: 4,
                control: SessionEventOp::Subscribe {},
            },
        ];
        for req in reqs {
            assert_eq!(
                take_frame::<ClientReq>(&mut frame(&req).unwrap()).unwrap(),
                Some(req)
            );
        }
        let job_ev = ClientEvent::PreviewJobResult {
            surface_id: 4,
            job_id: 2,
            output: PreviewJobOutput::PdfOpened {
                doc_id: 1,
                pages: vec![PdfPageSize {
                    width_milli: 400_000,
                    height_milli: 300_000,
                }],
            },
        };
        assert_eq!(
            take_frame::<ClientEvent>(&mut frame(&job_ev).unwrap()).unwrap(),
            Some(job_ev)
        );
        let fs_ev: InputEvent =
            serde_json::from_str(r#"{"op":"fullscreen_changed","active":true}"#).unwrap();
        assert_eq!(
            fs_ev,
            InputEvent::FullscreenChanged {
                surface_id: None,
                active: true,
                error: None,
            }
        );
        assert!(
            serde_json::from_str::<PreviewJobKind>(r#"{"kind":"pdf_open","extra":true}"#).is_err()
        );
        assert!(
            serde_json::from_str::<MediaControlOp>(
                r#"{"action":"open_speaker","path":"/a","x":1}"#
            )
            .is_err()
        );
    }
}
