//! Seat policy is userspace. The socket listener supplies authenticated peers and
//! bundles. Only trusted host input can establish activation or a paste gesture.
use abi::{Errno, gui::*, socket::PeerCred};
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, Errno>;
pub const COMPACT_WIDTH: u32 = 650;
const MAX_APP_ID_LEN: usize = 64;
const MAX_SEAT_ID_LEN: usize = 64;
const MAX_LEGACY_JSON_LEN: usize = 65_536;
#[derive(Debug)]
pub enum Output {
    Display(DisplayCmd),
    Client(u32, ClientEvent),
}
struct Surface {
    owner: u32,
    spec: SurfaceSpec,
    rect: Rect,
    normal: Rect,
    state: WindowState,
    generation: u32,
    recovering: bool,
    fallback_failed: bool,
    user_touched: bool,
}
#[derive(Default)]
struct Notifications {
    tokens: u8,
    last: u64,
    active: BTreeSet<u64>,
}
pub struct CompositorCore {
    surfaces: BTreeMap<SurfaceId, Surface>,
    z: Vec<SurfaceId>,
    negotiated: BTreeMap<u32, bool>,
    shell: Option<u32>,
    role_grants: BTreeMap<u32, BTreeSet<SurfaceRole>>,
    host_kind_peers: BTreeSet<u32>,
    compat_peers: BTreeSet<u32>,
    shell_subscribers: BTreeSet<u32>,
    seat_id: String,
    saved_layout: BTreeMap<String, SavedWindowFrame>,
    pending_layout_init: Option<(String, Option<String>)>,
    fullscreen: bool,
    pre_drag_normal: Option<(LeaseId, Rect)>,
    bounds: Rect,
    active: bool,
    focus: Option<SurfaceId>,
    mode: DragMode,
    lease: Option<DragLease>,
    next: u64,
    limit: u64,
    activation: Option<(SurfaceId, u64)>,
    paste: Option<(SurfaceId, u64)>,
    pressed: Option<(SurfaceId, u32)>,
    clipboard: Option<TransferItem>,
    dnd: Option<(u32, Vec<TransferItem>)>,
    pick: Option<(SurfaceId, u64)>,
    notifications: BTreeMap<u32, Notifications>,
    pub output: Vec<Output>,
}
impl Default for CompositorCore {
    fn default() -> Self {
        Self::new(1)
    }
}
impl CompositorCore {
    pub fn new(first: u64) -> Self {
        Self {
            surfaces: BTreeMap::new(),
            z: vec![],
            negotiated: BTreeMap::new(),
            shell: None,
            role_grants: BTreeMap::new(),
            host_kind_peers: BTreeSet::new(),
            compat_peers: BTreeSet::new(),
            shell_subscribers: BTreeSet::new(),
            seat_id: "seat0".into(),
            saved_layout: BTreeMap::new(),
            pending_layout_init: None,
            fullscreen: false,
            pre_drag_normal: None,
            bounds: Rect {
                x: 0,
                y: 0,
                width: 1024,
                height: 720,
            },
            active: true,
            focus: None,
            mode: DragMode::LocalLease,
            lease: None,
            next: first,
            limit: first.saturating_add(IDS_PER_SEAT),
            activation: None,
            paste: None,
            pressed: None,
            clipboard: None,
            dnd: None,
            pick: None,
            notifications: BTreeMap::new(),
            output: vec![],
        }
    }
    pub fn grant_peer(&mut self, peer: PeerCred, grants: PeerGrants) -> Result<()> {
        if grants.roles.is_empty() {
            self.role_grants.remove(&peer.pid);
        } else {
            self.role_grants
                .insert(peer.pid, grants.roles.into_iter().collect());
        }
        if grants.allow_host_kind {
            self.host_kind_peers.insert(peer.pid);
        } else {
            self.host_kind_peers.remove(&peer.pid);
        }
        if grants.allow_compat_apps {
            self.compat_peers.insert(peer.pid);
        } else {
            self.compat_peers.remove(&peer.pid);
        }
        Ok(())
    }
    pub fn designate_shell(&mut self, peer: PeerCred) -> Result<()> {
        if peer.uid != 0 {
            return Err(Errno::EPERM);
        }
        self.shell = Some(peer.pid);
        self.role_grants.insert(
            peer.pid,
            [
                SurfaceRole::Panel,
                SurfaceRole::Background,
                SurfaceRole::Launcher,
                SurfaceRole::Lock,
                SurfaceRole::Greeter,
            ]
            .into_iter()
            .collect(),
        );
        Ok(())
    }
    fn has_role(&self, pid: u32, role: SurfaceRole) -> bool {
        role == SurfaceRole::Window
            || self
                .role_grants
                .get(&pid)
                .is_some_and(|roles| roles.contains(&role))
    }
    fn is_panel_peer(&self, pid: u32) -> bool {
        self.role_grants
            .get(&pid)
            .is_some_and(|roles| roles.contains(&SurfaceRole::Panel))
    }
    fn compact(&self) -> bool {
        self.bounds.width <= COMPACT_WIDTH
    }
    fn compact_active_window(&self) -> Option<SurfaceId> {
        if !self.compact() {
            return None;
        }
        if let Some(id) = self.focus
            && self.surfaces.get(&id).is_some_and(|s| {
                s.spec.role == SurfaceRole::Window && s.state != WindowState::Minimized
            })
        {
            return Some(id);
        }
        self.z.iter().rev().copied().find(|id| {
            self.surfaces.get(id).is_some_and(|s| {
                s.spec.role == SurfaceRole::Window && s.state != WindowState::Minimized
            })
        })
    }
    fn effective_geometry(&self, id: SurfaceId) -> Option<(Rect, WindowState, bool, bool, u32)> {
        let s = self.surfaces.get(&id)?;
        let z_index = self
            .z
            .iter()
            .position(|&x| x == id)
            .map_or(1, |i| i as u32 + 1);
        if s.spec.role != SurfaceRole::Window {
            return Some((s.rect, s.state, true, false, z_index));
        }
        if s.state == WindowState::Minimized {
            return Some((s.rect, s.state, false, false, z_index));
        }
        if self.compact() {
            if self.compact_active_window() == Some(id) {
                Some((self.bounds, s.state, true, true, z_index))
            } else {
                Some((s.rect, s.state, false, false, z_index))
            }
        } else {
            let filled = matches!(
                s.state,
                WindowState::Maximized | WindowState::Left | WindowState::Right
            );
            Some((s.rect, s.state, true, filled, z_index))
        }
    }
    fn emit_geometry(&mut self, id: SurfaceId) {
        if let Some((rect, state, visible, filled, z_index)) = self.effective_geometry(id) {
            self.display(DisplayCmd::Geometry {
                surface_id: id,
                rect,
                state,
                visible,
                filled,
                z_index,
            });
        }
    }
    fn emit_all_window_geometries(&mut self) {
        for id in self.z.clone() {
            if self
                .surfaces
                .get(&id)
                .is_some_and(|s| s.spec.role == SurfaceRole::Window)
            {
                self.emit_geometry(id);
            }
        }
    }
    fn window_list_event(&self) -> ClientEvent {
        let windows = self
            .surfaces
            .iter()
            .filter(|(_, s)| s.spec.role == SurfaceRole::Window)
            .map(|(&surface_id, s)| {
                let (rect, state, visible, _, z_index) = self
                    .effective_geometry(surface_id)
                    .unwrap_or((s.rect, s.state, false, false, 1));
                WindowSummary {
                    surface_id,
                    app_id: s.spec.app_id.clone(),
                    title: s.spec.title.clone(),
                    role: s.spec.role,
                    rect,
                    normal: s.normal,
                    state,
                    focused: self.focus == Some(surface_id),
                    visible,
                    z_index,
                }
            })
            .collect();
        ClientEvent::WindowList {
            windows,
            bounds: self.bounds,
            compact: self.compact(),
            fullscreen: self.fullscreen,
            seat_id: self.seat_id.clone(),
        }
    }
    fn broadcast_windows(&mut self) {
        if self.shell_subscribers.is_empty() {
            return;
        }
        let event = self.window_list_event();
        for pid in self.shell_subscribers.iter().copied().collect::<Vec<_>>() {
            self.output.push(Output::Client(pid, event.clone()));
        }
    }
    fn remember_app_frame(&mut self, id: SurfaceId, open: bool) {
        if let Some(s) = self.surfaces.get(&id)
            && s.spec.role == SurfaceRole::Window
            && let Some(app_id) = s.spec.app_id.as_ref()
        {
            self.saved_layout.insert(
                app_id.clone(),
                SavedWindowFrame {
                    rect: s.normal,
                    state: s.state,
                    open,
                },
            );
        }
    }
    fn id(&mut self) -> Result<u64> {
        if self.next >= self.limit {
            return Err(Errno::ENOSPC);
        }
        let id = self.next;
        self.next = id.checked_add(1).ok_or(Errno::ENOSPC)?;
        Ok(id)
    }
    fn display(&mut self, c: DisplayCmd) {
        self.output.push(Output::Display(c));
    }
    fn send(&mut self, id: SurfaceId, e: ClientEvent) {
        if let Some(s) = self.surfaces.get(&id) {
            self.output.push(Output::Client(s.owner, e));
        }
    }
    fn owner(&self, pid: u32, id: SurfaceId) -> Result<()> {
        if self.surfaces.get(&id).is_some_and(|s| s.owner == pid) {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }
    fn modal(&self) -> Option<SurfaceId> {
        self.z
            .iter()
            .rev()
            .copied()
            .find(|id| self.surfaces[id].spec.role.modal())
    }
    fn can_input(&self, id: SurfaceId) -> bool {
        self.active
            && self
                .surfaces
                .get(&id)
                .is_some_and(|s| s.state != WindowState::Minimized)
            && self.modal().is_none_or(|m| m == id)
    }
    fn gesture(&self, id: SurfaceId, now: u64) -> bool {
        self.can_input(id)
            && self.focus == Some(id)
            && self
                .activation
                .is_some_and(|(s, t)| s == id && now.saturating_sub(t) <= 5000)
    }
    fn chrome(&mut self, id: SurfaceId) {
        if let Some(s) = self.surfaces.get(&id)
            && s.spec.role == SurfaceRole::Window
        {
            self.display(DisplayCmd::UpdateSurfaceChrome {
                surface_id: id,
                chrome: WindowChromeSpec {
                    title: s.spec.title.clone(),
                    show_minimize: true,
                    show_maximize: s.spec.resizable,
                    show_close: true,
                    resizable: s.spec.resizable,
                    focused: self.focus == Some(id),
                    state: s.state,
                },
            });
        }
    }
    fn pixel_input(&self, id: SurfaceId) -> bool {
        self.surfaces.get(&id).is_some_and(|s| {
            matches!(s.spec.kind, SurfaceKind::Pixel)
                && self.negotiated.get(&s.owner) == Some(&true)
        })
    }
    fn cancel(&mut self) {
        self.finish_lease(true);
    }
    fn finish_lease(&mut self, rollback: bool) {
        self.pre_drag_normal = None;
        if let Some(l) = self.lease.take() {
            self.pressed = None;
            if rollback
                && matches!(l.op, InteractiveOp::Resize { .. })
                && let Some(s) = self.surfaces.get(&l.surface_id)
            {
                self.send(
                    l.surface_id,
                    ClientEvent::Configure {
                        surface_id: l.surface_id,
                        width: s.rect.width,
                        height: s.rect.height,
                        state: s.state,
                    },
                );
            }
            self.display(DisplayCmd::CancelInteractiveOp {
                lease_id: l.lease_id,
            });
        }
    }
    fn end_dnd(&mut self) {
        if let Some((pointer_id, _)) = self.dnd.take() {
            self.display(DisplayCmd::DndTracking {
                active: false,
                pointer_id,
            });
        }
    }
    fn clear_gestures(&mut self) {
        self.cancel();
        self.activation = None;
        self.paste = None;
        self.pressed = None;
        self.end_dnd();
        if let Some((id, request_id)) = self.pick.take() {
            self.display(DisplayCmd::CancelPicker { request_id });
            self.send(
                id,
                ClientEvent::Error {
                    errno: Errno::ECANCELED,
                },
            );
        }
    }
    fn focus(&mut self, id: Option<SurfaceId>) {
        if id.is_some_and(|i| !self.can_input(i)) {
            return;
        }
        let changed = self.focus != id;
        if changed {
            self.clear_gestures();
            let old = self.focus;
            self.focus = id;
            if let Some(i) = old {
                self.chrome(i);
                self.send(
                    i,
                    ClientEvent::Focus {
                        surface_id: i,
                        focused: false,
                    },
                );
            }
            if let Some(i) = id {
                self.z.retain(|&j| i != j);
                self.z.push(i);
                self.chrome(i);
                self.send(
                    i,
                    ClientEvent::Focus {
                        surface_id: i,
                        focused: true,
                    },
                );
            }
            self.emit_all_window_geometries();
            self.broadcast_windows();
        }
        self.display(DisplayCmd::Focus {
            surface_id: id,
            modal: self.modal().is_some(),
        });
    }
    fn restore_focus(&mut self) {
        let next = self.z.iter().rev().copied().find(|&i| self.can_input(i));
        self.focus(next);
    }
    fn remove(&mut self, id: SurfaceId) {
        let was_window = self
            .surfaces
            .get(&id)
            .is_some_and(|s| s.spec.role == SurfaceRole::Window);
        if was_window {
            self.remember_app_frame(id, false);
        }
        if self.focus == Some(id) {
            self.clear_gestures();
        }
        self.surfaces.remove(&id);
        self.z.retain(|&i| i != id);
        self.display(DisplayCmd::Unmap { surface_id: id });
        if self.focus == Some(id) {
            self.restore_focus();
        } else if was_window {
            self.emit_all_window_geometries();
            self.broadcast_windows();
        }
    }
    fn layout(&mut self, id: SurfaceId, state: WindowState, rect: Rect) -> Result<()> {
        self.layout_internal(id, state, rect, true)
    }
    fn layout_internal(
        &mut self,
        id: SurfaceId,
        state: WindowState,
        rect: Rect,
        user_action: bool,
    ) -> Result<()> {
        let s = self.surfaces.get(&id).ok_or(Errno::EACCES)?;
        if s.spec.role != SurfaceRole::Window {
            return Err(Errno::EPERM);
        }
        if matches!(
            state,
            WindowState::Maximized | WindowState::Left | WindowState::Right
        ) && !s.spec.resizable
        {
            return Err(Errno::EPERM);
        }
        let b = self.bounds;
        let target = match state {
            WindowState::Minimized => s.rect,
            other => state_rect(other, rect, b),
        };
        let rect = target.constrained(b, s.spec.min_size, s.spec.max_size);
        if self.lease.as_ref().is_some_and(|l| l.surface_id == id) {
            self.cancel();
        }
        let s = self.surfaces.get_mut(&id).unwrap();
        s.state = state;
        s.rect = rect;
        if state == WindowState::Normal {
            s.normal = rect;
        }
        if user_action {
            s.user_touched = true;
        }
        self.remember_app_frame(id, true);
        self.emit_geometry(id);
        self.chrome(id);
        let (eff_rect, _, _, _, _) = self
            .effective_geometry(id)
            .unwrap_or((rect, state, true, false, 1));
        self.send(
            id,
            ClientEvent::Configure {
                surface_id: id,
                width: eff_rect.width,
                height: eff_rect.height,
                state,
            },
        );
        if self.focus == Some(id) && state == WindowState::Minimized {
            self.restore_focus();
        } else {
            if self.compact() {
                self.emit_all_window_geometries();
            }
            self.broadcast_windows();
        }
        Ok(())
    }
    pub fn request(
        &mut self,
        peer: PeerCred,
        req: ClientReq,
        now: u64,
        load: impl FnOnce(&DocumentSource) -> Result<Vec<u8>>,
    ) -> Result<ClientEvent> {
        use ClientReq::*;
        let pid = peer.pid;
        if let Hello { versions, required } = req {
            if self.negotiated.contains_key(&pid) {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let version = negotiate(&versions, &required)?;
            self.negotiated
                .insert(pid, required.iter().any(|c| c == "pixel-input"));
            return Ok(ClientEvent::Hello { version });
        }
        if !self.negotiated.contains_key(&pid) {
            return Err(Errno::EPROTONOSUPPORT);
        }
        match req {
            SubscribeShell => {
                if !self.is_panel_peer(pid) {
                    return Err(Errno::EPERM);
                }
                self.shell_subscribers.insert(pid);
                let wl = self.window_list_event();
                self.output.push(Output::Client(pid, wl));
                if let Some((seat_id, legacy_json)) = self.pending_layout_init.clone() {
                    self.output.push(Output::Client(
                        pid,
                        ClientEvent::SeatLayoutInit {
                            seat_id,
                            legacy_json,
                        },
                    ));
                }
                Ok(ClientEvent::Ok)
            }
            ShellCommand { action } => {
                if !self.is_panel_peer(pid) {
                    return Err(Errno::EPERM);
                }
                if self.modal().is_some() || !self.active {
                    return Err(Errno::EACCES);
                }
                match action {
                    ShellAction::Focus { surface_id } => {
                        if let Some(s) = self.surfaces.get(&surface_id)
                            && s.spec.role == SurfaceRole::Window
                        {
                            if s.state == WindowState::Minimized {
                                let normal = s.normal;
                                self.layout(surface_id, WindowState::Normal, normal)?;
                            }
                            self.focus(Some(surface_id));
                        } else {
                            return Err(Errno::ENOENT);
                        }
                    }
                    ShellAction::Minimize { surface_id } => {
                        let normal = self.surfaces.get(&surface_id).ok_or(Errno::ENOENT)?.normal;
                        self.layout(surface_id, WindowState::Minimized, normal)?;
                    }
                    ShellAction::Maximize { surface_id } => {
                        let s = self.surfaces.get(&surface_id).ok_or(Errno::ENOENT)?;
                        let next = if s.state == WindowState::Maximized {
                            WindowState::Normal
                        } else {
                            WindowState::Maximized
                        };
                        let normal = s.normal;
                        self.layout(surface_id, next, normal)?;
                        self.focus(Some(surface_id));
                    }
                    ShellAction::Restore { surface_id } => {
                        let normal = self.surfaces.get(&surface_id).ok_or(Errno::ENOENT)?.normal;
                        self.layout(surface_id, WindowState::Normal, normal)?;
                        self.focus(Some(surface_id));
                    }
                    ShellAction::Close { surface_id } => {
                        if self
                            .surfaces
                            .get(&surface_id)
                            .is_some_and(|s| s.spec.role == SurfaceRole::Window)
                        {
                            self.send(surface_id, ClientEvent::CloseRequested { surface_id });
                        } else {
                            return Err(Errno::ENOENT);
                        }
                    }
                    ShellAction::Launch { app_id } => {
                        if !valid_identifier(&app_id, MAX_APP_ID_LEN) {
                            return Err(Errno::EINVAL);
                        }
                        self.display(DisplayCmd::LaunchApp { app_id });
                    }
                    ShellAction::ToggleApp { .. }
                    | ShellAction::ToggleLauncher {}
                    | ShellAction::CloseLauncher {} => {}
                }
                Ok(ClientEvent::Ok)
            }
            SetSavedLayout { seat_id, frames } => {
                if !self.is_panel_peer(pid) {
                    return Err(Errno::EPERM);
                }
                if !valid_identifier(&seat_id, MAX_SEAT_ID_LEN)
                    || frames.len() > MAX_SURFACES
                    || frames.keys().any(|k| !valid_identifier(k, MAX_APP_ID_LEN))
                {
                    return Err(Errno::EINVAL);
                }
                self.seat_id = seat_id.clone();
                self.saved_layout = frames;
                for id in self.z.clone() {
                    let Some(s) = self.surfaces.get(&id) else {
                        continue;
                    };
                    if s.spec.role != SurfaceRole::Window || s.user_touched {
                        continue;
                    }
                    let Some(app_id) = s.spec.app_id.as_deref() else {
                        continue;
                    };
                    let Some(saved) = self.saved_layout.get(app_id).cloned() else {
                        continue;
                    };
                    let target_state = if saved.state == WindowState::Minimized
                        || (!s.spec.resizable && saved.state != WindowState::Normal)
                    {
                        WindowState::Normal
                    } else {
                        saved.state
                    };
                    let constrained =
                        saved
                            .rect
                            .constrained(self.bounds, s.spec.min_size, s.spec.max_size);
                    if let Some(s) = self.surfaces.get_mut(&id) {
                        s.normal = constrained;
                    }
                    let _ = self.layout_internal(id, target_state, constrained, false);
                }
                self.display(DisplayCmd::LayoutReady { seat_id });
                self.broadcast_windows();
                Ok(ClientEvent::Ok)
            }
            PublishShellState { state } => {
                if !self.is_panel_peer(pid) {
                    return Err(Errno::EPERM);
                }
                if state.dock.len() > MAX_SURFACES
                    || state.launcher_items.len() > MAX_SURFACES
                    || state.seat_id.len() > MAX_SEAT_ID_LEN
                {
                    return Err(Errno::E2BIG);
                }
                self.display(DisplayCmd::ShellState { state });
                Ok(ClientEvent::Ok)
            }
            LegacyLayoutMigrated { seat_id } => {
                if !self.is_panel_peer(pid) {
                    return Err(Errno::EPERM);
                }
                if !valid_identifier(&seat_id, MAX_SEAT_ID_LEN) {
                    return Err(Errno::EINVAL);
                }
                self.pending_layout_init = Some((seat_id.clone(), None));
                self.display(DisplayCmd::LegacyLayoutMigrated { seat_id });
                Ok(ClientEvent::Ok)
            }
            CreateSurface { mut spec } => {
                if !self.has_role(pid, spec.role) {
                    return Err(Errno::EPERM);
                }
                if self.surfaces.len() >= MAX_SURFACES {
                    return Err(Errno::ENOSPC);
                }
                if let Some(ref app_id) = spec.app_id
                    && !valid_identifier(app_id, MAX_APP_ID_LEN)
                {
                    return Err(Errno::EINVAL);
                }
                spec.title = title(&spec.title)?;
                if spec.min_size.width == 0
                    || spec.min_size.height == 0
                    || spec.max_size.is_some_and(|m| {
                        m.width < spec.min_size.width || m.height < spec.min_size.height
                    })
                {
                    return Err(Errno::EINVAL);
                }
                let (document, compat_app) = match &spec.kind {
                    SurfaceKind::Document(source) => {
                        (Some(verify_document(source, &load(source)?)?), None)
                    }
                    SurfaceKind::Pixel => (None, None),
                    SurfaceKind::Host { component } => {
                        if spec.role == SurfaceRole::Window {
                            if !self.compat_peers.contains(&pid)
                                || !matches!(
                                    component.as_str(),
                                    "files" | "terminal" | "mounts" | "viewer" | "editor"
                                )
                            {
                                return Err(Errno::EPERM);
                            }
                            (None, Some(component.clone()))
                        } else {
                            let expected = match spec.role {
                                SurfaceRole::Panel => "panel",
                                SurfaceRole::Background => "background",
                                SurfaceRole::Launcher => "launcher",
                                SurfaceRole::Greeter => "greeter",
                                SurfaceRole::Lock => "lock",
                                SurfaceRole::Window => unreachable!(),
                            };
                            if !self.host_kind_peers.contains(&pid) || component != expected {
                                return Err(Errno::EPERM);
                            }
                            (None, Some(component.clone()))
                        }
                    }
                };
                let id = self.id()?;
                let role = spec.role;
                let (rect, normal, state) = if role == SurfaceRole::Window {
                    if let Some(saved) = spec
                        .app_id
                        .as_deref()
                        .and_then(|aid| self.saved_layout.get(aid))
                        .cloned()
                    {
                        let normal =
                            saved
                                .rect
                                .constrained(self.bounds, spec.min_size, spec.max_size);
                        let state = if saved.state == WindowState::Minimized
                            || (!spec.resizable && saved.state != WindowState::Normal)
                        {
                            WindowState::Normal
                        } else {
                            saved.state
                        };
                        let rect = state_rect(state, normal, self.bounds).constrained(
                            self.bounds,
                            spec.min_size,
                            spec.max_size,
                        );
                        (rect, normal, state)
                    } else {
                        let base = if spec.rect.width == 0 || spec.rect.height == 0 {
                            default_app_rect(spec.app_id.as_deref(), self.bounds)
                        } else {
                            spec.rect
                        };
                        let rect = base.constrained(self.bounds, spec.min_size, spec.max_size);
                        (rect, rect, WindowState::Normal)
                    }
                } else {
                    let rect = spec
                        .rect
                        .constrained(self.bounds, spec.min_size, spec.max_size);
                    (rect, rect, WindowState::Normal)
                };
                self.surfaces.insert(
                    id,
                    Surface {
                        owner: pid,
                        spec,
                        rect,
                        normal,
                        state,
                        generation: 1,
                        fallback_failed: false,
                        recovering: false,
                        user_touched: false,
                    },
                );
                self.z.push(id);
                let map_rect = if role == SurfaceRole::Window && self.compact() {
                    self.bounds
                } else {
                    rect
                };
                self.display(DisplayCmd::Map {
                    surface_id: id,
                    owner_pid: pid,
                    role,
                    rect: map_rect,
                    document,
                    compat_app,
                    generation: 1,
                });
                self.chrome(id);
                if role.modal() {
                    self.clear_gestures();
                    let ids: Vec<_> = self
                        .notifications
                        .values_mut()
                        .flat_map(|n| std::mem::take(&mut n.active))
                        .collect();
                    for id in ids {
                        self.display(DisplayCmd::DismissNotification { id });
                    }
                }
                if role == SurfaceRole::Window || role.modal() {
                    self.focus(Some(id));
                    if role == SurfaceRole::Window {
                        // Ensure geometry + window list broadcast even if a modal blocked focus.
                        if self.focus != Some(id) {
                            self.emit_geometry(id);
                            self.broadcast_windows();
                        }
                    }
                }
                Ok(ClientEvent::Created { surface_id: id })
            }
            req => {
                let id = match &req {
                    Destroy { surface_id }
                    | SetTitle { surface_id, .. }
                    | RequestState { surface_id, .. }
                    | SetA11y { surface_id, .. }
                    | ClipboardWrite { surface_id, .. }
                    | ClipboardRead { surface_id }
                    | SetSizeLimits { surface_id, .. }
                    | DndStart { surface_id, .. }
                    | PickFile { surface_id }
                    | Notify { surface_id, .. }
                    | DocumentReply { surface_id, .. }
                    | SimulateLoss { surface_id }
                    | DismissNotification { surface_id, .. } => *surface_id,
                    _ => unreachable!(),
                };
                self.owner(pid, id)?;
                match req {
                    Destroy { .. } => self.remove(id),
                    SetTitle { title: t, .. } => {
                        self.surfaces.get_mut(&id).unwrap().spec.title = title(&t)?;
                        self.chrome(id);
                        self.broadcast_windows();
                    }
                    SetSizeLimits {
                        min_size, max_size, ..
                    } => {
                        if min_size.width == 0
                            || min_size.height == 0
                            || max_size.is_some_and(|m| {
                                m.width < min_size.width || m.height < min_size.height
                            })
                        {
                            return Err(Errno::EINVAL);
                        }
                        let s = self.surfaces.get_mut(&id).unwrap();
                        if s.spec.role != SurfaceRole::Window {
                            return Err(Errno::EPERM);
                        }
                        s.spec.min_size = min_size;
                        s.spec.max_size = max_size;
                        let (state, rect) = (s.state, s.rect);
                        self.layout(id, state, rect)?;
                    }
                    RequestState { state, .. } => {
                        self.layout(id, state, self.surfaces[&id].normal)?
                    }
                    SetA11y { a11y, .. } => {
                        if a11y.label.len() > 512
                            || a11y.role_description.len() > 128
                            || a11y.live_announcement.len() > 1024
                        {
                            return Err(Errno::E2BIG);
                        }
                        self.display(DisplayCmd::SetA11y {
                            surface_id: id,
                            a11y,
                        });
                    }
                    ClipboardWrite { mut item, .. } => {
                        if !self.gesture(id, now) {
                            return Err(Errno::EACCES);
                        }
                        sanitize(&mut item)?;
                        self.clipboard = Some(item.clone());
                        self.display(DisplayCmd::ClipboardWrite { item });
                    }
                    ClipboardRead { .. } => {
                        if !self.gesture(id, now)
                            || !self
                                .paste
                                .take()
                                .is_some_and(|(s, t)| s == id && now.saturating_sub(t) <= 5000)
                        {
                            return Err(Errno::EACCES);
                        }
                        return self
                            .clipboard
                            .clone()
                            .map(|item| ClientEvent::Clipboard { item })
                            .ok_or(Errno::ENODATA);
                    }
                    DndStart { items, .. } => {
                        let Some((source, pointer_id)) = self.pressed else {
                            return Err(Errno::EPERM);
                        };
                        if source != id
                            || self.lease.is_some()
                            || self.focus != Some(id)
                            || !self.can_input(id)
                        {
                            return Err(Errno::EPERM);
                        }
                        if items.len() > 64
                            || items.iter().map(|i| i.data.len()).sum::<usize>() > MAX_CLIPBOARD
                        {
                            return Err(Errno::E2BIG);
                        }
                        if items.is_empty()
                            || items
                                .iter()
                                .any(|i| i.mime.is_empty() || i.mime.len() > 128)
                        {
                            return Err(Errno::EINVAL);
                        }
                        self.dnd = Some((pointer_id, items));
                        self.display(DisplayCmd::DndTracking {
                            active: true,
                            pointer_id,
                        });
                    }
                    PickFile { .. } => {
                        if !self.gesture(id, now) {
                            return Err(Errno::EACCES);
                        }
                        if self.pick.is_some() {
                            return Err(Errno::EBUSY);
                        }
                        let request_id = self.id()?;
                        self.activation = None;
                        self.pick = Some((id, request_id));
                        self.display(DisplayCmd::PickFile {
                            surface_id: id,
                            request_id,
                        });
                    }
                    Notify { title, body, .. } => {
                        if title.len() > 128 || body.len() > 512 {
                            return Err(Errno::E2BIG);
                        }
                        if self.modal().is_some() {
                            return Err(Errno::EACCES);
                        }
                        let n = self
                            .notifications
                            .entry(pid)
                            .or_insert_with(|| Notifications {
                                tokens: 3,
                                last: now,
                                ..Default::default()
                            });
                        let refill = now.saturating_sub(n.last) / 5000;
                        n.tokens = (u64::from(n.tokens) + refill).min(3) as u8;
                        n.last += refill * 5000;
                        if n.tokens == 0 || n.active.len() >= 32 {
                            return Err(Errno::EAGAIN);
                        }
                        let nid = self.id()?;
                        let n = self.notifications.get_mut(&pid).unwrap();
                        n.tokens -= 1;
                        n.active.insert(nid);
                        self.display(DisplayCmd::Notify {
                            id: nid,
                            owner_pid: pid,
                            title,
                            body,
                        });
                        return Ok(ClientEvent::Notification { id: nid });
                    }
                    SimulateLoss { .. } => {
                        if !matches!(self.surfaces[&id].spec.kind, SurfaceKind::Pixel) {
                            return Err(Errno::EINVAL);
                        }
                    }
                    DocumentReply { text, .. } => {
                        if text.len() > MAX_DOCUMENT_MESSAGE {
                            return Err(Errno::E2BIG);
                        }
                        self.display(DisplayCmd::DocumentReply {
                            surface_id: id,
                            text,
                        });
                    }
                    DismissNotification { id, .. } => {
                        if !self
                            .notifications
                            .get_mut(&pid)
                            .is_some_and(|n| n.active.remove(&id))
                        {
                            return Err(Errno::EACCES);
                        }
                        self.display(DisplayCmd::DismissNotification { id });
                    }
                    _ => unreachable!(),
                }
                Ok(ClientEvent::Ok)
            }
        }
    }

    pub fn expire(&mut self, now: u64) {
        if self.lease.as_ref().is_some_and(|l| now >= l.expires_at_ms) {
            self.cancel();
        }
    }
    pub fn input(&mut self, event: InputEvent, now: u64) -> Result<()> {
        use InputEvent::*;
        self.expire(now);
        match event {
            Viewport { bounds, mode } => {
                if bounds.width == 0 || bounds.height == 0 {
                    return Err(Errno::EINVAL);
                }
                self.cancel();
                self.bounds = bounds;
                self.mode = mode;
                self.display(DisplayCmd::SetDragMode { mode });
                for id in self.z.clone() {
                    let Some(s) = self.surfaces.get_mut(&id) else {
                        continue;
                    };
                    if s.spec.role != SurfaceRole::Window {
                        continue;
                    }
                    let target = match s.state {
                        WindowState::Minimized => s.rect,
                        other => state_rect(other, s.normal, bounds),
                    };
                    let rect = target.constrained(bounds, s.spec.min_size, s.spec.max_size);
                    let state = s.state;
                    s.rect = rect;
                    self.chrome(id);
                    let (eff_rect, _, _, _, _) = self
                        .effective_geometry(id)
                        .unwrap_or((rect, state, true, false, 1));
                    self.send(
                        id,
                        ClientEvent::Configure {
                            surface_id: id,
                            width: eff_rect.width,
                            height: eff_rect.height,
                            state,
                        },
                    );
                }
                self.emit_all_window_geometries();
                self.broadcast_windows();
            }
            SeatActive { active } => {
                self.active = active;
                if !active {
                    self.clear_gestures();
                } else {
                    self.restore_focus();
                }
            }
            HostFocus => {
                // A host chooser keeps its pending request while typing in it revokes gestures.
                self.activation = None;
                self.paste = None;
                self.pressed = None;
                self.cancel();
                self.end_dnd();
            }
            FocusRequest { surface_id } => {
                if !self.can_input(surface_id) {
                    return Err(Errno::EACCES);
                }
                self.focus(Some(surface_id));
            }
            PointerDown {
                surface_id: id,
                hit_region,
                pointer_id,
                button,
                x,
                y,
                ..
            } => {
                if !self.can_input(id)
                    || button != 0
                    || self.pressed.is_some_and(|(_, p)| p != pointer_id)
                {
                    return Err(Errno::EACCES);
                }
                self.focus(Some(id));
                self.activation = Some((id, now));
                self.pressed = Some((id, pointer_id));
                if hit_region == HitRegion::Content && self.pixel_input(id) {
                    self.send(
                        id,
                        ClientEvent::Pointer {
                            surface_id: id,
                            kind: PointerKind::Down,
                            x,
                            y,
                            button,
                            pointer_id,
                        },
                    );
                }
                let s = &self.surfaces[&id];
                if hit_region != HitRegion::Content && s.spec.role == SurfaceRole::Window {
                    if self.compact() {
                        return Ok(());
                    }
                    let op = match hit_region {
                        HitRegion::Titlebar => InteractiveOp::Move,
                        HitRegion::Edge(edge) if s.spec.resizable => InteractiveOp::Resize { edge },
                        _ => return Err(Errno::EPERM),
                    };
                    let (min_size, max_size) = (s.spec.min_size, s.spec.max_size);
                    let start_rect = s.rect;
                    let pre_normal = s.normal;
                    let restore_rect = (op == InteractiveOp::Move
                        && s.state != WindowState::Normal)
                        .then_some(s.normal);
                    let snap_zones = if op == InteractiveOp::Move && s.spec.resizable {
                        vec![SnapZone::Top, SnapZone::Left, SnapZone::Right]
                    } else {
                        vec![]
                    };
                    self.cancel();
                    self.pressed = Some((id, pointer_id));
                    let lease_id = self.id()?;
                    let lease = DragLease {
                        lease_id,
                        surface_id: id,
                        op,
                        pointer_id,
                        bounds: self.bounds,
                        min_size,
                        max_size,
                        snap_zones,
                        start_rect,
                        restore_rect,
                        expires_at_ms: now.saturating_add(30000),
                    };
                    self.pre_drag_normal = Some((lease_id, pre_normal));
                    self.lease = Some(lease.clone());
                    self.display(DisplayCmd::BeginInteractiveOp { lease });
                }
            }
            PointerMove {
                surface_id,
                pointer_id,
                x,
                y,
            } => {
                if self.can_input(surface_id)
                    && self.focus == Some(surface_id)
                    && self.pixel_input(surface_id)
                    && self.lease.is_none()
                    && self.dnd.is_none()
                    && self
                        .pressed
                        .is_none_or(|pair| pair == (surface_id, pointer_id))
                {
                    self.send(
                        surface_id,
                        ClientEvent::Pointer {
                            surface_id,
                            kind: PointerKind::Move,
                            x,
                            y,
                            button: -1,
                            pointer_id,
                        },
                    );
                }
            }
            PointerUp {
                surface_id,
                pointer_id,
                button,
                x,
                y,
                canceled,
            } => {
                if self.pressed == Some((surface_id, pointer_id)) && button == 0 {
                    if self.can_input(surface_id)
                        && self.focus == Some(surface_id)
                        && self.pixel_input(surface_id)
                        && self.lease.is_none()
                    {
                        self.send(
                            surface_id,
                            ClientEvent::Pointer {
                                surface_id,
                                kind: if canceled {
                                    PointerKind::Cancel
                                } else {
                                    PointerKind::Up
                                },
                                x,
                                y,
                                button,
                                pointer_id,
                            },
                        );
                    }
                    self.pressed = None;
                    self.end_dnd();
                    if canceled {
                        self.cancel();
                    }
                }
            }
            Key {
                surface_id,
                paste,
                input,
            } => {
                if self.focus != Some(surface_id) || !self.can_input(surface_id) {
                    return Err(Errno::EACCES);
                }
                if input.composing {
                    return Ok(());
                }
                if input.key.len() > 128 || input.code.len() > 64 {
                    return Err(Errno::E2BIG);
                }
                self.activation = Some((surface_id, now));
                if paste {
                    self.paste = Some((surface_id, now));
                }
                if self.pixel_input(surface_id) {
                    self.send(surface_id, ClientEvent::Key { surface_id, input });
                }
            }
            Paste { surface_id, text } => {
                if self.focus != Some(surface_id) || !self.can_input(surface_id) {
                    return Err(Errno::EACCES);
                }
                if let Some(text) = text {
                    if text.len() > MAX_CLIPBOARD {
                        return Err(Errno::E2BIG);
                    }
                    self.clipboard = Some(TransferItem {
                        mime: "text/plain".into(),
                        data: text.into_bytes().into(),
                    });
                }
                self.activation = Some((surface_id, now));
                self.paste = Some((surface_id, now));
                self.send(surface_id, ClientEvent::PasteRequested { surface_id });
            }
            Shortcut {
                surface_id: id,
                key,
            } => {
                if self.focus != Some(id) || !self.can_input(id) {
                    return Err(Errno::EACCES);
                }
                match key {
                    abi::gui::Shortcut::Next | abi::gui::Shortcut::Previous => {
                        let mut ids: Vec<_> = self
                            .surfaces
                            .keys()
                            .copied()
                            .filter(|&s| {
                                self.can_input(s)
                                    && self.surfaces[&s].spec.role == SurfaceRole::Window
                            })
                            .collect();
                        if key == abi::gui::Shortcut::Previous {
                            ids.reverse();
                        }
                        if let Some(i) = ids.iter().position(|s| *s == id) {
                            self.focus(Some(ids[(i + 1) % ids.len()]));
                        }
                    }
                    abi::gui::Shortcut::Cancel => self.cancel(),
                    abi::gui::Shortcut::Close => {
                        if self.surfaces[&id].spec.role == SurfaceRole::Window {
                            self.send(id, ClientEvent::CloseRequested { surface_id: id });
                        }
                    }
                    key => {
                        let cur = self.surfaces[&id].state;
                        let state = match key {
                            abi::gui::Shortcut::Left => {
                                if cur == WindowState::Left {
                                    WindowState::Normal
                                } else {
                                    WindowState::Left
                                }
                            }
                            abi::gui::Shortcut::Right => {
                                if cur == WindowState::Right {
                                    WindowState::Normal
                                } else {
                                    WindowState::Right
                                }
                            }
                            abi::gui::Shortcut::Maximize => {
                                if cur == WindowState::Maximized {
                                    WindowState::Normal
                                } else {
                                    WindowState::Maximized
                                }
                            }
                            abi::gui::Shortcut::Restore => {
                                if cur == WindowState::Normal {
                                    WindowState::Minimized
                                } else {
                                    WindowState::Normal
                                }
                            }
                            _ => WindowState::Normal,
                        };
                        self.layout(id, state, self.surfaces[&id].normal)?;
                    }
                }
            }
            ChromeAction {
                surface_id: id,
                state,
            } => {
                if !self.can_input(id) || self.surfaces[&id].spec.role != SurfaceRole::Window {
                    return Err(Errno::EACCES);
                }
                if let Some(state) = state {
                    let next = if state == WindowState::Maximized
                        && self.surfaces[&id].state == WindowState::Maximized
                    {
                        WindowState::Normal
                    } else {
                        state
                    };
                    self.layout(id, next, self.surfaces[&id].normal)?;
                } else {
                    self.send(id, ClientEvent::CloseRequested { surface_id: id });
                }
            }
            InteractiveOpProgress {
                lease_id,
                surface_id,
                rect,
                ..
            }
            | InteractiveOpEnd {
                lease_id,
                surface_id,
                rect,
                ..
            } => {
                let l = self
                    .lease
                    .as_mut()
                    .filter(|l| l.lease_id == lease_id && l.surface_id == surface_id)
                    .ok_or(Errno::ESTALE)?;
                let was_snapped = l.restore_rect.is_some();
                let start_rect = l.start_rect;
                let rect = lease_rect(l, rect);
                l.expires_at_ms = now.saturating_add(30000);
                match event {
                    InteractiveOpEnd {
                        canceled,
                        snap_hint,
                        ..
                    } => {
                        let snap_hint = snap_hint.filter(|hint| l.snap_zones.contains(hint));
                        let pre_normal = self
                            .pre_drag_normal
                            .take()
                            .filter(|(id, _)| *id == lease_id)
                            .map(|(_, r)| r);
                        self.finish_lease(canceled);
                        if !canceled {
                            if let Some(hint) = snap_hint {
                                let state = match hint {
                                    SnapZone::Left => WindowState::Left,
                                    SnapZone::Right => WindowState::Right,
                                    SnapZone::Top => WindowState::Maximized,
                                };
                                if let Some(normal) = pre_normal
                                    && let Some(s) = self.surfaces.get_mut(&surface_id)
                                {
                                    s.normal = normal;
                                }
                                let normal = self.surfaces[&surface_id].normal;
                                self.layout(surface_id, state, normal)?;
                            } else if was_snapped && rect == start_rect {
                                self.emit_geometry(surface_id);
                            } else {
                                self.layout(surface_id, WindowState::Normal, rect)?;
                            }
                        }
                    }
                    InteractiveOpProgress { serial, .. } if self.mode == DragMode::Roundtrip => {
                        self.display(DisplayCmd::DragFrame {
                            serial,
                            surface_id,
                            lease_id,
                            rect,
                        })
                    }
                    _ if matches!(l.op, InteractiveOp::Resize { .. }) => self.send(
                        surface_id,
                        ClientEvent::Configure {
                            surface_id,
                            width: rect.width,
                            height: rect.height,
                            state: WindowState::Normal,
                        },
                    ),
                    _ => {}
                }
            }
            DndHover {
                surface_id,
                x,
                y,
                pointer_id,
            } => {
                if !self.can_input(surface_id) {
                    return Err(Errno::EACCES);
                }
                let (_, items) = self
                    .dnd
                    .as_ref()
                    .filter(|(p, _)| *p == pointer_id)
                    .ok_or(Errno::EPERM)?;
                self.send(
                    surface_id,
                    ClientEvent::DndOffer {
                        surface_id,
                        mimes: items.iter().map(|i| i.mime.clone()).collect(),
                        x,
                        y,
                    },
                );
            }
            DndDrop {
                surface_id,
                pointer_id,
                button,
            } => {
                if !self.can_input(surface_id) {
                    return Err(Errno::EACCES);
                }
                if button != 0 || self.dnd.as_ref().is_none_or(|(p, _)| *p != pointer_id) {
                    return Err(Errno::EPERM);
                }
                let (_, items) = self.dnd.take().unwrap();
                self.display(DisplayCmd::DndTracking {
                    active: false,
                    pointer_id,
                });
                if let Some((source, pressed_pointer)) = self.pressed
                    && pressed_pointer == pointer_id
                    && self.pixel_input(source)
                {
                    // The drop consumes this press. Its target has no source-local coordinates.
                    self.send(
                        source,
                        ClientEvent::Pointer {
                            surface_id: source,
                            kind: PointerKind::Cancel,
                            x: 0,
                            y: 0,
                            button,
                            pointer_id,
                        },
                    );
                }
                self.pressed = None;
                self.send(surface_id, ClientEvent::DndDrop { surface_id, items });
            }
            PickerResult {
                surface_id,
                request_id,
                ..
            } => {
                if !self.finish_picker(surface_id, request_id) {
                    return Err(Errno::ESTALE);
                }
                self.send(
                    surface_id,
                    ClientEvent::Error {
                        errno: Errno::ECANCELED,
                    },
                );
            }
            DocumentMessage { surface_id, text } => {
                if !self.can_input(surface_id)
                    || !matches!(
                        self.surfaces[&surface_id].spec.kind,
                        SurfaceKind::Document(_)
                    )
                {
                    return Err(Errno::EACCES);
                }
                if text.len() > MAX_DOCUMENT_MESSAGE {
                    return Err(Errno::E2BIG);
                }
                self.send(
                    surface_id,
                    ClientEvent::DocumentMessage { surface_id, text },
                );
            }
            TitlebarDoubleClick { surface_id } => {
                if !self.can_input(surface_id)
                    || self.surfaces[&surface_id].spec.role != SurfaceRole::Window
                {
                    return Err(Errno::EACCES);
                }
                self.focus(Some(surface_id));
                let s = &self.surfaces[&surface_id];
                let next = if s.state == WindowState::Maximized {
                    WindowState::Normal
                } else {
                    WindowState::Maximized
                };
                let normal = s.normal;
                self.layout(surface_id, next, normal)?;
            }
            ShellInput { action } => {
                if !self.active || self.modal().is_some() {
                    return Err(Errno::EACCES);
                }
                for pid in self.shell_subscribers.iter().copied().collect::<Vec<_>>() {
                    self.output.push(Output::Client(
                        pid,
                        ClientEvent::ShellInput {
                            action: action.clone(),
                        },
                    ));
                }
            }
            SeatLayoutInit {
                seat_id,
                legacy_json,
            } => {
                if !valid_identifier(&seat_id, MAX_SEAT_ID_LEN)
                    || legacy_json
                        .as_ref()
                        .is_some_and(|s| s.len() > MAX_LEGACY_JSON_LEN)
                {
                    return Err(Errno::EINVAL);
                }
                self.seat_id = seat_id.clone();
                self.pending_layout_init = Some((seat_id.clone(), legacy_json.clone()));
                for pid in self.shell_subscribers.iter().copied().collect::<Vec<_>>() {
                    self.output.push(Output::Client(
                        pid,
                        ClientEvent::SeatLayoutInit {
                            seat_id: seat_id.clone(),
                            legacy_json: legacy_json.clone(),
                        },
                    ));
                }
            }
            FullscreenChanged { active } => {
                self.fullscreen = active;
                self.broadcast_windows();
            }
        }
        Ok(())
    }
    pub fn finish_picker(&mut self, id: SurfaceId, request_id: u64) -> bool {
        if self.pick == Some((id, request_id)) && self.can_input(id) && self.focus == Some(id) {
            self.pick = None;
            true
        } else {
            false
        }
    }
    pub fn device(&mut self, event: DisplayEvent) -> Result<()> {
        let (id, g) = match &event {
            DisplayEvent::SurfaceDeviceLost {
                surface_id,
                generation,
                ..
            }
            | DisplayEvent::SurfaceReady {
                surface_id,
                generation,
                ..
            } => (*surface_id, *generation),
        };
        let s = self.surfaces.get_mut(&id).ok_or(Errno::ESTALE)?;
        if !matches!(s.spec.kind, SurfaceKind::Pixel) || s.generation != g || s.fallback_failed {
            return Err(Errno::ESTALE);
        }
        match event {
            DisplayEvent::SurfaceDeviceLost { .. } => {
                if s.recovering {
                    s.fallback_failed = true;
                    self.send(id, ClientEvent::Error { errno: Errno::EIO });
                    return Ok(());
                }
                let generation = g.checked_add(1).ok_or(Errno::ENOSPC)?;
                s.generation = generation;
                s.recovering = true;
                let rect = s.rect;
                self.send(
                    id,
                    ClientEvent::DeviceLost {
                        surface_id: id,
                        generation: g,
                    },
                );
                self.display(DisplayCmd::RecreatePixelCanvas {
                    surface_id: id,
                    generation,
                    width: rect.width,
                    height: rect.height,
                    backend: PixelBackend::Software2d,
                });
            }
            DisplayEvent::SurfaceReady { backend, .. } => {
                s.recovering = false;
                self.send(
                    id,
                    ClientEvent::SurfaceReady {
                        surface_id: id,
                        generation: g,
                        backend,
                    },
                );
            }
        }
        Ok(())
    }
    pub fn client_gone(&mut self, pid: u32) {
        let ids: Vec<_> = self
            .z
            .iter()
            .copied()
            .filter(|id| self.surfaces[id].owner == pid)
            .collect();
        for id in ids {
            self.remove(id);
        }
        self.negotiated.remove(&pid);
        self.role_grants.remove(&pid);
        self.host_kind_peers.remove(&pid);
        self.compat_peers.remove(&pid);
        self.shell_subscribers.remove(&pid);
        if self.shell == Some(pid) {
            self.shell = None;
        }
        if let Some(n) = self.notifications.remove(&pid) {
            for id in n.active {
                self.display(DisplayCmd::DismissNotification { id });
            }
        }
    }
}
fn valid_identifier(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_len
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn state_rect(state: WindowState, normal: Rect, bounds: Rect) -> Rect {
    match state {
        WindowState::Maximized => bounds,
        WindowState::Left => Rect {
            width: bounds.width / 2,
            ..bounds
        },
        WindowState::Right => Rect {
            x: bounds.x.saturating_add_unsigned(bounds.width / 2),
            width: bounds.width - bounds.width / 2,
            ..bounds
        },
        WindowState::Normal | WindowState::Minimized => normal,
    }
}
fn default_app_rect(app_id: Option<&str>, b: Rect) -> Rect {
    let gap = 10u32;
    let files_w = ((b.width as f64) * 0.34).round().clamp(280.0, 420.0) as u32;
    let term_w = b.width.saturating_sub(files_w + gap * 3).max(280);
    let full_h = b.height.saturating_sub(gap * 2).max(180);
    let centered = |w: u32, h: u32| Rect {
        x: b.x.saturating_add_unsigned(b.width.saturating_sub(w) / 2),
        y: b.y.saturating_add_unsigned(b.height.saturating_sub(h) / 2),
        width: w,
        height: h,
    };
    match app_id {
        Some("files") => Rect {
            x: b.x.saturating_add_unsigned(gap),
            y: b.y.saturating_add_unsigned(gap),
            width: files_w,
            height: full_h,
        },
        Some("terminal") => Rect {
            x: b.x.saturating_add_unsigned(gap * 2 + files_w),
            y: b.y.saturating_add_unsigned(gap),
            width: term_w,
            height: full_h,
        },
        Some("viewer") => {
            let w = ((b.width as f64) * 0.72).round().clamp(320.0, 960.0) as u32;
            let max_h = b.height.saturating_sub(60).max(220) as f64;
            let h = ((b.height as f64) * 0.80).round().clamp(220.0, max_h) as u32;
            centered(w, h)
        }
        Some("editor") => {
            let w = ((b.width as f64) * 0.68).round().clamp(320.0, 900.0) as u32;
            let max_h = b.height.saturating_sub(60).max(220) as f64;
            let h = ((b.height as f64) * 0.78).round().clamp(220.0, max_h) as u32;
            centered(w, h)
        }
        Some("mounts") => {
            let w = ((b.width as f64) * 0.50).round().clamp(320.0, 620.0) as u32;
            let h = ((b.height as f64) * 0.62).round().clamp(220.0, 480.0) as u32;
            centered(w, h)
        }
        _ => centered(
            b.width.saturating_mul(2) / 3,
            b.height.saturating_mul(2) / 3,
        ),
    }
}
fn lease_rect(l: &DragLease, proposed: Rect) -> Rect {
    let base = l.start_rect;
    let InteractiveOp::Resize { edge } = l.op else {
        let (width, height) = if let Some(restore) = l.restore_rect {
            let moved = (proposed.x - l.start_rect.x).abs() + (proposed.y - l.start_rect.y).abs()
                >= 6
                || proposed.width != l.start_rect.width
                || proposed.height != l.start_rect.height;
            if moved {
                (restore.width, restore.height)
            } else {
                return l.start_rect;
            }
        } else {
            (base.width, base.height)
        };
        return Rect {
            x: proposed.x,
            y: proposed.y,
            width,
            height,
        }
        .constrained(l.bounds, l.min_size, l.max_size);
    };
    use ResizeEdge::*;
    // An inward-facing edge has only the space between its fixed edge and the viewport.
    let axis = |pos: i32,
                size: u32,
                want: u32,
                (low, high): (bool, bool),
                (origin, room): (i32, u32),
                (min, max): (u32, u32)| {
        if !low && !high {
            return (pos, size);
        }
        let offset = pos.abs_diff(origin);
        let available = if low {
            offset.saturating_add(size)
        } else {
            room.saturating_sub(offset)
        };
        let size_new = want.clamp(min.min(available), max.min(available));
        let pos_new = if low {
            (i64::from(pos) + i64::from(size) - i64::from(size_new))
                .clamp(i32::MIN.into(), i32::MAX.into()) as i32
        } else {
            pos
        };
        (pos_new, size_new)
    };
    let max = l.max_size.unwrap_or(Size {
        width: u32::MAX,
        height: u32::MAX,
    });
    let (x, width) = axis(
        base.x,
        base.width,
        proposed.width,
        (matches!(edge, W | Nw | Sw), matches!(edge, E | Ne | Se)),
        (l.bounds.x, l.bounds.width),
        (l.min_size.width, max.width),
    );
    let (y, height) = axis(
        base.y,
        base.height,
        proposed.height,
        (matches!(edge, N | Nw | Ne), matches!(edge, S | Sw | Se)),
        (l.bounds.y, l.bounds.height),
        (l.min_size.height, max.height),
    );
    Rect {
        x,
        y,
        width,
        height,
    }
}
fn title(s: &str) -> Result<String> {
    if s.chars().count() > 128 {
        return Err(Errno::E2BIG);
    }
    Ok(s.chars().filter(|c| !c.is_control()).collect())
}
fn sanitize(item: &mut TransferItem) -> Result<()> {
    if item.data.len() > MAX_CLIPBOARD {
        return Err(Errno::E2BIG);
    }
    match item.mime.as_str() {
        "text/html" => {
            let text = std::str::from_utf8(&item.data).map_err(|_| Errno::EINVAL)?;
            let safe = text
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;");
            if safe.len() > MAX_CLIPBOARD {
                return Err(Errno::E2BIG);
            }
            item.data = safe.into_bytes().into();
        }
        "text/plain" => {
            std::str::from_utf8(&item.data).map_err(|_| Errno::EINVAL)?;
        }
        "image/png" if item.data.starts_with(b"\x89PNG\r\n\x1a\n") => {}
        "image/png" => return Err(Errno::EINVAL),
        _ => return Err(Errno::EOPNOTSUPP),
    }
    Ok(())
}

// Both crates use this exact presentation implementation. The test build avoids
// introducing a dependency from userspace services to the kernel filesystem.
#[cfg(test)]
#[path = "../../vfs/src/gui_headless.rs"]
mod headless;
#[cfg(test)]
mod tests {
    use super::*;
    use headless::HeadlessHostAdapter;
    use std::time::Instant;
    struct Suite {
        core: CompositorCore,
        host: HeadlessHostAdapter,
        events: Vec<(u32, ClientEvent)>,
        now: u64,
        inputs: usize,
    }
    const RAW: &[u8] = br#"{"html":"<main>Note</main>","css":"","js":""}"#;
    fn peer(pid: u32) -> PeerCred {
        PeerCred {
            pid,
            uid: if pid == 1 { 0 } else { 1000 },
            gid: 1000,
        }
    }
    fn spec(doc: bool) -> SurfaceSpec {
        SurfaceSpec {
            role: SurfaceRole::Window,
            kind: if doc {
                SurfaceKind::Document(DocumentSource {
                    bundle_path: SAMPLE_BUNDLE.into(),
                    expected_sha256: sha256_hex(RAW),
                })
            } else {
                SurfaceKind::Pixel
            },
            title: "Sample".into(),
            rect: Rect {
                x: 10,
                y: 10,
                width: 300,
                height: 250,
            },
            min_size: Size {
                width: 100,
                height: 80,
            },
            max_size: None,
            resizable: true,
            app_id: None,
        }
    }
    impl Suite {
        fn new() -> Self {
            Self {
                core: Default::default(),
                host: Default::default(),
                events: vec![],
                now: 1000,
                inputs: 0,
            }
        }
        fn pump(&mut self) {
            for out in self.core.output.drain(..) {
                match out {
                    Output::Display(c) => self
                        .host
                        .display(take_frame(&mut frame(&c).unwrap()).unwrap().unwrap()),
                    Output::Client(p, e) => self.events.push((p, e)),
                }
            }
        }
        fn req(&mut self, pid: u32, req: ClientReq) -> Result<ClientEvent> {
            let req = take_frame(&mut frame(&req)?)?.unwrap();
            let r = self
                .core
                .request(peer(pid), req, self.now, |_| Ok(RAW.into()));
            self.pump();
            r
        }
        fn hello(&mut self, pid: u32) {
            assert_eq!(
                self.req(
                    pid,
                    ClientReq::Hello {
                        versions: vec![1],
                        required: vec!["pixel-input".into()]
                    }
                ),
                Ok(ClientEvent::Hello { version: 1 })
            );
        }
        fn create(&mut self, pid: u32, spec: SurfaceSpec) -> SurfaceId {
            if !self.core.negotiated.contains_key(&pid) {
                self.hello(pid);
            }
            let ClientEvent::Created { surface_id } =
                self.req(pid, ClientReq::CreateSurface { spec }).unwrap()
            else {
                panic!("missing surface")
            };
            surface_id
        }
        fn input(&mut self, event: InputEvent) -> Result<()> {
            self.inputs += 1;
            let event = take_frame(&mut frame(&event)?)?.unwrap();
            let r = self.core.input(event, self.now);
            self.pump();
            r
        }
        fn down(&mut self, id: SurfaceId, hit: HitRegion) {
            self.input(InputEvent::PointerDown {
                surface_id: id,
                hit_region: hit,
                x: 10,
                y: 10,
                pointer_id: 1,
                button: 0,
                timestamp_ms: self.now,
            })
            .unwrap();
        }
    }
    #[test]
    fn g02_negotiate_before_surface_and_probe() {
        let mut s = Suite::new();
        assert_eq!(
            s.req(2, ClientReq::CreateSurface { spec: spec(true) }),
            Err(Errno::EPROTONOSUPPORT)
        );
        assert_eq!(
            s.req(
                2,
                ClientReq::Hello {
                    versions: vec![0],
                    required: vec![]
                }
            ),
            Err(Errno::EPROTONOSUPPORT)
        );
        assert_eq!(
            s.req(
                2,
                ClientReq::Hello {
                    versions: vec![1],
                    required: vec!["rdma".into()]
                }
            ),
            Err(Errno::EOPNOTSUPP)
        );
    }
    #[test]
    fn g03_concurrent_owners_and_private_events() {
        let mut s = Suite::new();
        let doc = s.create(2, spec(true));
        let pixel = s.create(3, spec(false));
        assert_eq!(s.host.surfaces.borrow().len(), 2);
        for request in [
            ClientReq::Destroy { surface_id: doc },
            ClientReq::SetTitle {
                surface_id: doc,
                title: "mine".into(),
            },
            ClientReq::PickFile { surface_id: doc },
            ClientReq::ClipboardRead { surface_id: doc },
            ClientReq::SimulateLoss { surface_id: doc },
        ] {
            assert_eq!(s.req(3, request), Err(Errno::EACCES));
        }
        s.events.clear();
        s.input(InputEvent::DocumentMessage {
            surface_id: doc,
            text: "Hello".into(),
        })
        .unwrap();
        assert!(matches!(
            &s.events[..],
            [(2, ClientEvent::DocumentMessage { .. })]
        ));
        assert_eq!(s.host.surfaces.borrow()[&pixel].0, 3);
    }
    #[test]
    fn g04_privileged_roles_require_designation_and_authentic_root() {
        let mut s = Suite::new();
        s.hello(2);
        for role in [
            SurfaceRole::Panel,
            SurfaceRole::Background,
            SurfaceRole::Launcher,
            SurfaceRole::Lock,
            SurfaceRole::Greeter,
        ] {
            assert_eq!(
                s.req(
                    2,
                    ClientReq::CreateSurface {
                        spec: SurfaceSpec {
                            role,
                            ..spec(false)
                        }
                    }
                ),
                Err(Errno::EPERM)
            );
        }
        assert_eq!(s.core.designate_shell(peer(2)), Err(Errno::EPERM));
        s.core.designate_shell(peer(1)).unwrap();
        let id = s.create(
            1,
            SurfaceSpec {
                role: SurfaceRole::Lock,
                ..spec(true)
            },
        );
        assert!(!s.host.commands.borrow().iter().any(
            |c| matches!(c,DisplayCmd::UpdateSurfaceChrome{surface_id,..} if *surface_id==id)
        ));
    }
    #[test]
    fn g05_verify_bundle_before_mapping() {
        let mut s = Suite::new();
        s.hello(2);
        let mut spec = spec(true);
        if let SurfaceKind::Document(src) = &mut spec.kind {
            src.expected_sha256 = sha256_hex(b"other");
        }
        assert_eq!(s.req(2, ClientReq::CreateSurface { spec }), Err(Errno::EIO));
        assert!(s.host.surfaces.borrow().is_empty());
    }
    #[test]
    fn document_messages_count_utf8_bytes_in_both_directions() {
        let mut s = Suite::new();
        let id = s.create(2, spec(true));
        for (size, accepted) in [(1365, true), (1366, false)] {
            let text = "界".repeat(size);
            assert_eq!(
                s.input(InputEvent::DocumentMessage {
                    surface_id: id,
                    text: text.clone()
                })
                .is_ok(),
                accepted
            );
            assert_eq!(
                s.req(
                    2,
                    ClientReq::DocumentReply {
                        surface_id: id,
                        text
                    }
                )
                .is_ok(),
                accepted
            );
        }
    }
    #[test]
    fn g06_lease_clamps_consumes_and_expires() {
        let mut s = Suite::new();
        let id = s.create(2, spec(true));
        s.down(id, HitRegion::Edge(ResizeEdge::Se));
        let lease = s.host.lease.borrow().clone().unwrap();
        let end = InputEvent::InteractiveOpEnd {
            lease_id: lease.lease_id,
            surface_id: id,
            rect: Rect {
                x: i32::MAX,
                y: i32::MIN,
                width: 0,
                height: u32::MAX,
            },
            snap_hint: None,
            canceled: false,
        };
        s.input(end.clone()).unwrap();
        assert_eq!(
            s.host.surfaces.borrow()[&id].1,
            Rect {
                x: 10,
                y: 10,
                width: 100,
                height: 710
            }
        );
        assert_eq!(s.input(end), Err(Errno::ESTALE));
        s.down(id, HitRegion::Titlebar);
        s.now += 30001;
        s.core.expire(s.now);
        s.pump();
        assert!(s.host.lease.borrow().is_none());
    }
    #[test]
    fn headless_drag_frame_cannot_reapply_a_retired_lease() {
        let mut s = Suite::new();
        let id = s.create(2, spec(true));
        s.down(id, HitRegion::Titlebar);
        let lease = s.host.lease.borrow().clone().unwrap();
        let moved = Rect {
            x: 30,
            ..lease.start_rect
        };
        let frame = DisplayCmd::DragFrame {
            surface_id: id,
            lease_id: lease.lease_id,
            serial: 1,
            rect: moved,
        };
        s.host.display(frame.clone());
        assert_eq!(s.host.surfaces.borrow()[&id].1, moved);
        s.core.expire(lease.expires_at_ms + 1);
        s.pump();
        s.down(id, HitRegion::Titlebar);
        s.host.display(frame);
        assert_eq!(s.host.surfaces.borrow()[&id].1, lease.start_rect);
    }
    #[test]
    fn g07_focus_shortcuts_accessible_pixel() {
        let mut s = Suite::new();
        let a = s.create(2, spec(true));
        let b = s.create(3, spec(false));
        s.input(InputEvent::FocusRequest { surface_id: a }).unwrap();
        s.input(InputEvent::Shortcut {
            surface_id: a,
            key: Shortcut::Next,
        })
        .unwrap();
        assert_eq!(*s.host.focus.borrow(), Some(b));
        s.req(
            3,
            ClientReq::SetA11y {
                surface_id: b,
                a11y: A11y {
                    label: "Plot".into(),
                    role_description: "Graph".into(),
                    live_announcement: "Updated".into(),
                },
            },
        )
        .unwrap();
        assert!(
            matches!(s.host.commands.borrow().last(),Some(DisplayCmd::SetA11y{a11y,..}) if a11y.label=="Plot")
        );
    }
    #[test]
    fn g08_generation_fences_loss_and_recreation() {
        let mut s = Suite::new();
        let id = s.create(2, spec(false));
        let loss = DisplayEvent::SurfaceDeviceLost {
            surface_id: id,
            generation: 1,
            reason: "reset".into(),
            fallback: PixelBackend::Software2d,
        };
        s.core.device(loss.clone()).unwrap();
        s.pump();
        assert_eq!(s.host.surfaces.borrow()[&id].2, 2);
        assert_eq!(s.core.device(loss), Err(Errno::ESTALE));
        s.core
            .device(DisplayEvent::SurfaceReady {
                surface_id: id,
                generation: 2,
                backend: PixelBackend::Software2d,
                width: 300,
                height: 250,
            })
            .unwrap();
        s.pump();
        assert!(
            s.events
                .iter()
                .any(|(p, e)| *p == 2
                    && matches!(e, ClientEvent::SurfaceReady { generation: 2, .. }))
        );
    }
    #[test]
    fn failed_software_initialization_stops_recreation() {
        let mut s = Suite::new();
        let id = s.create(2, spec(false));
        let loss = |generation| DisplayEvent::SurfaceDeviceLost {
            surface_id: id,
            generation,
            reason: "no context".into(),
            fallback: PixelBackend::Software2d,
        };
        s.core.device(loss(1)).unwrap();
        s.pump();
        s.host.commands.borrow_mut().clear();
        s.core.device(loss(2)).unwrap();
        s.pump();
        assert!(s.host.commands.borrow().is_empty());
        assert!(
            s.events
                .contains(&(2, ClientEvent::Error { errno: Errno::EIO }))
        );
        assert_eq!(s.core.device(loss(2)), Err(Errno::ESTALE));
    }
    #[test]
    fn g09_gestures_paste_picker_notification_limits_and_lock() {
        let mut s = Suite::new();
        let a = s.create(2, spec(true));
        let b = s.create(3, spec(false));
        let write = ClientReq::ClipboardWrite {
            surface_id: a,
            item: TransferItem {
                mime: "text/html".into(),
                data: b"<test>".to_vec().into(),
            },
        };
        assert_eq!(s.req(2, write.clone()), Err(Errno::EACCES));
        s.input(InputEvent::FocusRequest { surface_id: a }).unwrap();
        assert_eq!(s.req(2, write.clone()), Err(Errno::EACCES));
        s.down(a, HitRegion::Content);
        s.req(2, write.clone()).unwrap();
        let read = ClientReq::ClipboardRead { surface_id: a };
        assert_eq!(s.req(2, read.clone()), Err(Errno::EACCES));
        s.input(InputEvent::Key {
            surface_id: a,
            paste: true,
            input: KeyInput::default(),
        })
        .unwrap();
        assert!(
            matches!(s.req(2,read.clone()),Ok(ClientEvent::Clipboard{item}) if item.data.0==b"&lt;test&gt;")
        );
        assert_eq!(s.req(2, read), Err(Errno::EACCES));
        s.req(2, ClientReq::PickFile { surface_id: a }).unwrap();
        let (_, request_id) = s.core.pick.unwrap();
        s.input(InputEvent::PickerResult {
            surface_id: a,
            request_id,
            chosen: false,
        })
        .unwrap();
        assert!(s.events.contains(&(
            2,
            ClientEvent::Error {
                errno: Errno::ECANCELED
            }
        )));
        s.now += 5001;
        assert_eq!(s.req(2, write), Err(Errno::EACCES));
        let notify = ClientReq::Notify {
            surface_id: b,
            title: "Hello".into(),
            body: "World".into(),
        };
        for _ in 0..3 {
            s.req(3, notify.clone()).unwrap();
        }
        let next_id = s.core.next;
        assert_eq!(s.req(3, notify.clone()), Err(Errno::EAGAIN));
        assert_eq!(s.core.next, next_id);
        s.now += 5000;
        s.req(3, notify.clone()).unwrap();
        s.down(a, HitRegion::Titlebar);
        s.core.designate_shell(peer(1)).unwrap();
        s.create(
            1,
            SurfaceSpec {
                role: SurfaceRole::Greeter,
                ..spec(true)
            },
        );
        assert_eq!(s.req(3, notify), Err(Errno::EACCES));
        assert!(s.host.lease.borrow().is_none());
        assert_eq!(
            s.input(InputEvent::FocusRequest { surface_id: a }),
            Err(Errno::EACCES)
        );
    }
    #[test]
    fn pixel_source_receives_one_terminal_pointer_on_drop() {
        let mut s = Suite::new();
        let source = s.create(2, spec(false));
        let target = s.create(3, spec(true));
        s.down(source, HitRegion::Content);
        s.req(
            2,
            ClientReq::DndStart {
                surface_id: source,
                items: vec![TransferItem {
                    mime: "text/plain".into(),
                    data: b"sample".to_vec().into(),
                }],
            },
        )
        .unwrap();
        s.events.clear();
        s.input(InputEvent::DndDrop {
            surface_id: target,
            pointer_id: 1,
            button: 0,
        })
        .unwrap();
        s.input(InputEvent::PointerUp {
            surface_id: source,
            pointer_id: 1,
            button: 0,
            x: 10,
            y: 10,
            canceled: false,
        })
        .unwrap();
        assert!(matches!(&s.events[..], [
            (2, ClientEvent::Pointer { surface_id, kind: PointerKind::Cancel, pointer_id: 1, .. }),
            (3, ClientEvent::DndDrop { surface_id: id, .. })
        ] if *surface_id == source && *id == target));
    }
    #[test]
    fn g09_dnd_discloses_only_types_until_drop() {
        let mut s = Suite::new();
        let a = s.create(2, spec(true));
        let b = s.create(3, spec(false));
        let items = vec![TransferItem {
            mime: "text/plain".into(),
            data: b"private".to_vec().into(),
        }];
        let req = ClientReq::DndStart {
            surface_id: a,
            items: items.clone(),
        };
        assert_eq!(s.req(2, req.clone()), Err(Errno::EPERM));
        s.down(a, HitRegion::Content);
        s.req(2, req).unwrap();
        s.events.clear();
        assert_eq!(
            s.input(InputEvent::DndDrop {
                surface_id: b,
                pointer_id: 2,
                button: 0
            }),
            Err(Errno::EPERM)
        );
        assert_eq!(
            s.input(InputEvent::DndDrop {
                surface_id: b,
                pointer_id: 1,
                button: 2
            }),
            Err(Errno::EPERM)
        );
        s.input(InputEvent::PointerUp {
            surface_id: a,
            pointer_id: 2,
            button: 0,
            x: 4,
            y: 5,
            canceled: false,
        })
        .unwrap();
        assert!(s.events.is_empty());
        s.input(InputEvent::DndHover {
            pointer_id: 1,
            surface_id: b,
            x: 4,
            y: 5,
        })
        .unwrap();
        assert!(
            matches!(&s.events[..],[(3,ClientEvent::DndOffer{mimes,..})] if mimes==&["text/plain"])
        );
        s.input(InputEvent::DndDrop {
            surface_id: b,
            pointer_id: 1,
            button: 0,
        })
        .unwrap();
        assert_eq!(
            s.events.last(),
            Some(&(
                3,
                ClientEvent::DndDrop {
                    surface_id: b,
                    items
                }
            ))
        );
    }
    #[test]
    fn modal_close_requires_shell_dismissal() {
        for role in [SurfaceRole::Lock, SurfaceRole::Greeter] {
            let mut s = Suite::new();
            let window = s.create(2, spec(false));
            s.core.designate_shell(peer(1)).unwrap();
            let modal = s.create(1, SurfaceSpec { role, ..spec(true) });
            s.events.clear();
            s.input(InputEvent::Shortcut {
                surface_id: modal,
                key: Shortcut::Close,
            })
            .unwrap();
            assert!(s.events.is_empty());
            assert!(s.host.surfaces.borrow().contains_key(&window));
            assert_eq!(
                s.input(InputEvent::FocusRequest { surface_id: window }),
                Err(Errno::EACCES)
            );
            assert_eq!(
                s.req(2, ClientReq::Destroy { surface_id: modal }),
                Err(Errno::EACCES)
            );
            s.req(1, ClientReq::Destroy { surface_id: modal }).unwrap();
            assert_eq!(*s.host.focus.borrow(), Some(window));
        }
    }
    #[test]
    fn pixel_input_follows_focus_modal_suspend_and_composition() {
        let mut s = Suite::new();
        let a = s.create(2, spec(false));
        let b = s.create(3, spec(false));
        let key = |surface_id, composing| InputEvent::Key {
            surface_id,
            paste: false,
            input: KeyInput {
                key: "x".into(),
                code: "KeyX".into(),
                composing,
                ..Default::default()
            },
        };
        s.events.clear();
        s.input(key(b, false)).unwrap();
        assert!(matches!(&s.events[..], [(3, ClientEvent::Key { .. })]));
        s.events.clear();
        s.input(key(b, true)).unwrap();
        assert!(s.events.is_empty());
        s.down(a, HitRegion::Content);
        assert!(s.events.iter().any(|e| matches!(
            e,
            (
                2,
                ClientEvent::Pointer {
                    kind: PointerKind::Down,
                    x: 10,
                    y: 10,
                    ..
                }
            )
        )));
        s.events.clear();
        assert_eq!(s.input(key(b, false)), Err(Errno::EACCES));
        s.input(key(a, false)).unwrap();
        assert!(matches!(&s.events[..], [(2, ClientEvent::Key { .. })]));
        s.input(InputEvent::SeatActive { active: false }).unwrap();
        assert_eq!(s.input(key(a, false)), Err(Errno::EACCES));
        s.input(InputEvent::SeatActive { active: true }).unwrap();
        s.core.designate_shell(peer(1)).unwrap();
        s.create(
            1,
            SurfaceSpec {
                role: SurfaceRole::Greeter,
                ..spec(true)
            },
        );
        assert_eq!(s.input(key(a, false)), Err(Errno::EACCES));
    }
    #[test]
    fn resize_rollback_and_delayed_cancel_are_surface_and_lease_scoped() {
        let mut s = Suite::new();
        let a = s.create(2, spec(false));
        let b = s.create(3, spec(true));
        s.down(a, HitRegion::Edge(ResizeEdge::Nw));
        let first = s.core.lease.clone().unwrap();
        assert!(first.snap_zones.is_empty());
        s.req(
            3,
            ClientReq::SetSizeLimits {
                surface_id: b,
                min_size: spec(true).min_size,
                max_size: None,
            },
        )
        .unwrap();
        assert_eq!(s.core.lease, Some(first.clone()));
        let rect = Rect {
            x: 500,
            y: 500,
            width: 150,
            height: 100,
        };
        s.input(InputEvent::InteractiveOpProgress {
            serial: 1,
            lease_id: first.lease_id,
            surface_id: a,
            rect,
            snap_hint: Some(SnapZone::Left),
        })
        .unwrap();
        s.events.clear();
        s.req(
            2,
            ClientReq::RequestState {
                surface_id: a,
                state: WindowState::Maximized,
            },
        )
        .unwrap();
        assert!(s.events.iter().any(|e| matches!(
            e,
            (
                2,
                ClientEvent::Configure {
                    width: 300,
                    height: 250,
                    ..
                }
            )
        )));
        s.down(a, HitRegion::Titlebar);
        let second = s.core.lease.clone().unwrap();
        s.host.display(DisplayCmd::CancelInteractiveOp {
            lease_id: first.lease_id,
        });
        assert_eq!(*s.host.lease.borrow(), Some(second));
    }
    #[test]
    fn g10_suspend_peer_exit_focus_and_reset() {
        let mut s = Suite::new();
        let a = s.create(2, spec(true));
        let b = s.create(3, spec(false));
        s.down(b, HitRegion::Titlebar);
        s.input(InputEvent::SeatActive { active: false }).unwrap();
        assert_eq!(s.host.surfaces.borrow().len(), 2);
        assert!(s.host.lease.borrow().is_none());
        assert_eq!(
            s.input(InputEvent::FocusRequest { surface_id: b }),
            Err(Errno::EACCES)
        );
        s.input(InputEvent::SeatActive { active: true }).unwrap();
        s.core.client_gone(3);
        s.pump();
        assert_eq!(*s.host.focus.borrow(), Some(a));
        assert!(!s.host.surfaces.borrow().contains_key(&b));
        s.host.display(DisplayCmd::SeatReset);
        assert!(s.host.surfaces.borrow().is_empty());
    }
    #[test]
    fn headless_drag_latency_120_steps() {
        for mode in [DragMode::LocalLease, DragMode::Roundtrip] {
            let mut s = Suite::new();
            let id = s.create(2, spec(true));
            s.input(InputEvent::Viewport {
                bounds: s.core.bounds,
                mode,
            })
            .unwrap();
            let before = s.inputs + s.host.commands.borrow().len();
            s.down(id, HitRegion::Titlebar);
            let lease = s.host.lease.borrow().clone().unwrap();
            let mut samples = vec![];
            let mut rect = s.host.surfaces.borrow()[&id].1;
            let mut last = 0;
            for i in 1..=120 {
                let now = i * 1000 / 60;
                let start = Instant::now();
                rect.x = i;
                if mode == DragMode::LocalLease {
                    s.host.local_frame(rect);
                }
                if mode == DragMode::Roundtrip || now - last >= 100 {
                    s.input(InputEvent::InteractiveOpProgress {
                        serial: i as u32,
                        lease_id: lease.lease_id,
                        surface_id: id,
                        rect,
                        snap_hint: None,
                    })
                    .unwrap();
                    last = now;
                }
                assert_eq!(s.host.surfaces.borrow()[&id].1.x, rect.x);
                samples.push(start.elapsed().as_secs_f64() * 1000.0);
            }
            s.input(InputEvent::InteractiveOpEnd {
                lease_id: lease.lease_id,
                surface_id: id,
                rect,
                snap_hint: None,
                canceled: false,
            })
            .unwrap();
            let messages = s.inputs + s.host.commands.borrow().len() - before;
            samples.sort_by(f64::total_cmp);
            println!(
                "{mode:?} samples=120 p50={:.6} p95={:.6} p99={:.6} max={:.6} ms dropped={} gesture_messages={} messages/s={:.1}",
                samples[59],
                samples[113],
                samples[118],
                samples[119],
                samples.iter().filter(|t| **t > 16.7).count(),
                messages,
                messages as f64 / 2.0
            );
        }
    }
    #[test]
    fn l5b_multi_client_role_and_host_kind_privilege_separation() {
        let mut s = Suite::new();
        let shell_pid = 10;
        let greeter_pid = 11;
        let compat_pid = 12;
        let ordinary_pid = 13;

        s.core
            .grant_peer(
                peer(shell_pid),
                PeerGrants {
                    roles: vec![
                        SurfaceRole::Panel,
                        SurfaceRole::Background,
                        SurfaceRole::Launcher,
                    ],
                    allow_host_kind: true,
                    allow_compat_apps: false,
                },
            )
            .unwrap();
        s.core
            .grant_peer(
                PeerCred {
                    pid: greeter_pid,
                    uid: 0,
                    gid: 0,
                },
                PeerGrants {
                    roles: vec![SurfaceRole::Lock, SurfaceRole::Greeter],
                    allow_host_kind: true,
                    allow_compat_apps: false,
                },
            )
            .unwrap();
        s.core
            .grant_peer(
                peer(compat_pid),
                PeerGrants {
                    roles: vec![],
                    allow_host_kind: false,
                    allow_compat_apps: true,
                },
            )
            .unwrap();

        for pid in [shell_pid, greeter_pid, compat_pid, ordinary_pid] {
            s.hello(pid);
        }

        let host_spec = |role, component: &str, app_id: Option<&str>| SurfaceSpec {
            role,
            kind: SurfaceKind::Host {
                component: component.into(),
            },
            title: component.into(),
            rect: Rect {
                x: 0,
                y: 0,
                width: 400,
                height: 300,
            },
            min_size: Size {
                width: 1,
                height: 1,
            },
            max_size: None,
            resizable: true,
            app_id: app_id.map(str::to_owned),
        };

        // desktop-shell gets Panel/Background/Launcher, NOT Lock/Greeter or compat windows.
        assert!(
            s.req(
                shell_pid,
                ClientReq::CreateSurface {
                    spec: host_spec(SurfaceRole::Panel, "panel", None)
                }
            )
            .is_ok()
        );
        assert_eq!(
            s.req(
                shell_pid,
                ClientReq::CreateSurface {
                    spec: host_spec(SurfaceRole::Lock, "lock", None)
                }
            ),
            Err(Errno::EPERM)
        );
        assert_eq!(
            s.req(
                shell_pid,
                ClientReq::CreateSurface {
                    spec: host_spec(SurfaceRole::Window, "terminal", Some("terminal"))
                }
            ),
            Err(Errno::EPERM)
        );

        // greeter gets Lock/Greeter, NOT Panel or shell RPCs.
        assert_eq!(
            s.req(
                greeter_pid,
                ClientReq::CreateSurface {
                    spec: host_spec(SurfaceRole::Panel, "panel", None)
                }
            ),
            Err(Errno::EPERM)
        );
        assert_eq!(
            s.req(greeter_pid, ClientReq::SubscribeShell),
            Err(Errno::EPERM)
        );
        let greeter_surf = s.create(
            greeter_pid,
            host_spec(SurfaceRole::Greeter, "greeter", None),
        );
        assert!(s.host.modal.get());
        s.req(
            greeter_pid,
            ClientReq::Destroy {
                surface_id: greeter_surf,
            },
        )
        .unwrap();
        assert!(!s.host.modal.get());

        // compat proxy gets Window compat apps ONLY, NOT privileged roles or shell RPCs.
        assert!(
            s.req(
                compat_pid,
                ClientReq::CreateSurface {
                    spec: host_spec(SurfaceRole::Window, "terminal", Some("terminal"))
                }
            )
            .is_ok()
        );
        assert_eq!(
            s.req(
                compat_pid,
                ClientReq::CreateSurface {
                    spec: host_spec(SurfaceRole::Panel, "panel", None)
                }
            ),
            Err(Errno::EPERM)
        );
        assert_eq!(
            s.req(compat_pid, ClientReq::SubscribeShell),
            Err(Errno::EPERM)
        );

        // ordinary app gets EPERM for SurfaceKind::Host and all privileged roles/RPCs.
        assert_eq!(
            s.req(
                ordinary_pid,
                ClientReq::CreateSurface {
                    spec: host_spec(SurfaceRole::Window, "terminal", Some("terminal"))
                }
            ),
            Err(Errno::EPERM)
        );
        assert_eq!(
            s.req(
                ordinary_pid,
                ClientReq::PublishShellState {
                    state: ShellStateView::default()
                }
            ),
            Err(Errno::EPERM)
        );
    }

    #[test]
    fn l5b_shell_restart_preserves_apps_and_reconnects_window_list() {
        let mut s = Suite::new();
        let shell1 = 10;
        let shell2 = 11;
        let app = 20;
        for sp in [shell1, shell2] {
            s.core
                .grant_peer(
                    peer(sp),
                    PeerGrants {
                        roles: vec![
                            SurfaceRole::Panel,
                            SurfaceRole::Background,
                            SurfaceRole::Launcher,
                        ],
                        allow_host_kind: true,
                        allow_compat_apps: false,
                    },
                )
                .unwrap();
        }
        s.hello(shell1);
        let panel_id = s.create(
            shell1,
            SurfaceSpec {
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
                app_id: None,
            },
        );
        s.req(shell1, ClientReq::SubscribeShell).unwrap();
        let win = s.create(
            app,
            SurfaceSpec {
                app_id: Some("terminal".into()),
                ..spec(false)
            },
        );

        // Killing desktop-shell removes ONLY panel_id; app window stays alive!
        s.core.client_gone(shell1);
        s.pump();
        assert!(!s.host.surfaces.borrow().contains_key(&panel_id));
        assert!(s.host.surfaces.borrow().contains_key(&win));

        // Respawned desktop-shell connects and immediately receives the surviving window.
        s.events.clear();
        s.hello(shell2);
        s.req(shell2, ClientReq::SubscribeShell).unwrap();
        assert!(s.events.iter().any(|(pid, ev)| {
            *pid == shell2
                && matches!(
                    ev,
                    ClientEvent::WindowList { windows, .. }
                        if windows.len() == 1 && windows[0].surface_id == win
                )
        }));
    }

    #[test]
    fn l5b_phone_compact_mode_tear_off_snap_back_and_shortcuts() {
        let mut s = Suite::new();
        let a = s.create(
            2,
            SurfaceSpec {
                app_id: Some("files".into()),
                rect: Rect {
                    x: 10,
                    y: 10,
                    width: 360,
                    height: 500,
                },
                ..spec(false)
            },
        );
        let b = s.create(
            3,
            SurfaceSpec {
                app_id: Some("terminal".into()),
                rect: Rect {
                    x: 400,
                    y: 10,
                    width: 500,
                    height: 500,
                },
                ..spec(false)
            },
        );

        // Drag terminal to top -> maximized; tear-off drag -> restores free size (500x500).
        s.down(b, HitRegion::Titlebar);
        let lease = s.host.lease.borrow().clone().unwrap();
        s.input(InputEvent::InteractiveOpEnd {
            lease_id: lease.lease_id,
            surface_id: b,
            rect: Rect {
                x: 400,
                y: 0,
                width: 500,
                height: 500,
            },
            snap_hint: Some(SnapZone::Top),
            canceled: false,
        })
        .unwrap();
        assert_eq!(s.host.surfaces.borrow()[&b].1, s.core.bounds);
        assert!(s.host.visibility.borrow()[&b].1);

        s.down(b, HitRegion::Titlebar);
        let tear = s.host.lease.borrow().clone().unwrap();
        assert_eq!(
            tear.restore_rect,
            Some(Rect {
                x: 400,
                y: 10,
                width: 500,
                height: 500,
            })
        );
        s.host.local_frame(Rect {
            x: 100,
            y: 120,
            width: tear.start_rect.width,
            height: tear.start_rect.height,
        });
        assert_eq!(s.host.surfaces.borrow()[&b].1.width, 500);
        s.input(InputEvent::InteractiveOpEnd {
            lease_id: tear.lease_id,
            surface_id: b,
            rect: Rect {
                x: 100,
                y: 120,
                width: 500,
                height: 500,
            },
            snap_hint: None,
            canceled: false,
        })
        .unwrap();
        let before = s.host.surfaces.borrow()[&b].1;
        assert_eq!((before.width, before.height), (500, 500));

        // Snap right, then double-click twice -> returns to `before`.
        s.down(b, HitRegion::Titlebar);
        let right_lease = s.host.lease.borrow().clone().unwrap();
        s.input(InputEvent::InteractiveOpEnd {
            lease_id: right_lease.lease_id,
            surface_id: b,
            rect: Rect {
                x: 900,
                y: 120,
                width: 500,
                height: 500,
            },
            snap_hint: Some(SnapZone::Right),
            canceled: false,
        })
        .unwrap();
        s.input(InputEvent::TitlebarDoubleClick { surface_id: b })
            .unwrap();
        assert_eq!(s.host.surfaces.borrow()[&b].1, s.core.bounds);
        s.input(InputEvent::TitlebarDoubleClick { surface_id: b })
            .unwrap();
        assert_eq!(s.host.surfaces.borrow()[&b].1, before);

        // Ctrl+Alt+ArrowDown: first frees snapped window, second minimizes & transfers focus to `a`.
        s.input(InputEvent::Shortcut {
            surface_id: b,
            key: Shortcut::Left,
        })
        .unwrap();
        assert!(s.host.visibility.borrow()[&b].1);
        s.input(InputEvent::Shortcut {
            surface_id: b,
            key: Shortcut::Restore,
        })
        .unwrap();
        assert!(!s.host.visibility.borrow()[&b].1);
        s.input(InputEvent::Shortcut {
            surface_id: b,
            key: Shortcut::Restore,
        })
        .unwrap();
        assert!(!s.host.visibility.borrow()[&b].0);
        assert_eq!(*s.host.focus.borrow(), Some(a));

        // Restore b and enter phone compact mode (412x780 <= 650).
        s.req(
            3,
            ClientReq::RequestState {
                surface_id: b,
                state: WindowState::Normal,
            },
        )
        .unwrap();
        let phone_bounds = Rect {
            x: 0,
            y: 0,
            width: 412,
            height: 780,
        };
        s.input(InputEvent::Viewport {
            bounds: phone_bounds,
            mode: DragMode::LocalLease,
        })
        .unwrap();
        // `a` is focused -> visible & filled; `b` is hidden.
        assert!(s.host.visibility.borrow()[&a].0);
        assert!(s.host.visibility.borrow()[&a].1);
        assert_eq!(s.host.surfaces.borrow()[&a].1, phone_bounds);
        assert!(!s.host.visibility.borrow()[&b].0);

        // Switching focus to `b` swaps visibility.
        s.input(InputEvent::FocusRequest { surface_id: b }).unwrap();
        assert!(s.host.visibility.borrow()[&b].0);
        assert!(!s.host.visibility.borrow()[&a].0);

        // Returning to desktop width restores free frames for both windows.
        s.input(InputEvent::Viewport {
            bounds: Rect {
                x: 0,
                y: 0,
                width: 1024,
                height: 720,
            },
            mode: DragMode::LocalLease,
        })
        .unwrap();
        assert!(s.host.visibility.borrow()[&a].0);
        assert!(s.host.visibility.borrow()[&b].0);
        assert_eq!(s.host.surfaces.borrow()[&b].1, before);
    }
}
