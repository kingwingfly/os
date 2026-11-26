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
pub const MAX_BUNDLE: usize = 2 << 20;
pub const MAX_DOCUMENT_MESSAGE: usize = 4096;
pub const MAX_CLIPBOARD: usize = 1 << 20;
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
        allow_host_kind: bool,
        allow_compat_apps: bool
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
        active: bool,
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
            allow_compat_apps: false,
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
                r#"{"roles":[],"allow_host_kind":false,"allow_compat_apps":false,"rogue":true}"#
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
}
