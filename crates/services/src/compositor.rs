//! Seat policy is userspace. The socket listener supplies authenticated peers and
//! bundles. Only trusted host input can establish activation or a paste gesture.
use abi::{Errno, gui::*, socket::PeerCred};
use std::collections::{BTreeMap, BTreeSet};

type Result<T> = std::result::Result<T, Errno>;
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
    pub fn designate_shell(&mut self, peer: PeerCred) -> Result<()> {
        if peer.uid != 0 {
            return Err(Errno::EPERM);
        }
        self.shell = Some(peer.pid);
        Ok(())
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
        if self.focus != id {
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
        if self.focus == Some(id) {
            self.clear_gestures();
        }
        self.surfaces.remove(&id);
        self.z.retain(|&i| i != id);
        self.display(DisplayCmd::Unmap { surface_id: id });
        if self.focus == Some(id) {
            self.restore_focus();
        }
    }
    fn layout(&mut self, id: SurfaceId, state: WindowState, rect: Rect) -> Result<()> {
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
            WindowState::Maximized => b,
            WindowState::Left => Rect {
                width: b.width / 2,
                ..b
            },
            WindowState::Right => Rect {
                x: b.x.saturating_add_unsigned(b.width / 2),
                width: b.width - b.width / 2,
                ..b
            },
            WindowState::Normal => rect,
            WindowState::Minimized => s.rect,
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
        self.display(DisplayCmd::Geometry {
            surface_id: id,
            rect,
            state,
        });
        self.chrome(id);
        self.send(
            id,
            ClientEvent::Configure {
                surface_id: id,
                width: rect.width,
                height: rect.height,
                state,
            },
        );
        if self.focus == Some(id) && state == WindowState::Minimized {
            self.restore_focus();
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
        if let CreateSurface { mut spec } = req {
            if spec.role != SurfaceRole::Window && (peer.uid != 0 || self.shell != Some(pid)) {
                return Err(Errno::EPERM);
            }
            if self.surfaces.len() >= MAX_SURFACES {
                return Err(Errno::ENOSPC);
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
            let document = match &spec.kind {
                SurfaceKind::Document(source) => Some(verify_document(source, &load(source)?)?),
                SurfaceKind::Pixel => None,
            };
            let id = self.id()?;
            let rect = spec
                .rect
                .constrained(self.bounds, spec.min_size, spec.max_size);
            let role = spec.role;
            self.surfaces.insert(
                id,
                Surface {
                    owner: pid,
                    spec,
                    rect,
                    normal: rect,
                    state: WindowState::Normal,
                    generation: 1,
                    fallback_failed: false,
                    recovering: false,
                },
            );
            self.z.push(id);
            self.display(DisplayCmd::Map {
                surface_id: id,
                owner_pid: pid,
                role,
                rect,
                document,
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
            }
            return Ok(ClientEvent::Created { surface_id: id });
        }
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
            }
            SetSizeLimits {
                min_size, max_size, ..
            } => {
                if min_size.width == 0
                    || min_size.height == 0
                    || max_size
                        .is_some_and(|m| m.width < min_size.width || m.height < min_size.height)
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
            RequestState { state, .. } => self.layout(id, state, self.surfaces[&id].normal)?,
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
            Hello { .. } | CreateSurface { .. } => unreachable!(),
        }
        Ok(ClientEvent::Ok)
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
                    let s = &self.surfaces[&id];
                    if s.spec.role == SurfaceRole::Window {
                        self.layout(id, s.state, s.normal)?;
                    }
                }
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
                    let op = match hit_region {
                        HitRegion::Titlebar => InteractiveOp::Move,
                        HitRegion::Edge(edge) if s.spec.resizable => InteractiveOp::Resize { edge },
                        _ => return Err(Errno::EPERM),
                    };
                    let (min_size, max_size) = (s.spec.min_size, s.spec.max_size);
                    let start_rect = s.rect;
                    let snap_zones = if op == InteractiveOp::Move && s.spec.resizable {
                        vec![SnapZone::Top, SnapZone::Left, SnapZone::Right]
                    } else {
                        vec![]
                    };
                    self.cancel();
                    self.pressed = Some((id, pointer_id));
                    let lease = DragLease {
                        lease_id: self.id()?,
                        surface_id: id,
                        op,
                        pointer_id,
                        bounds: self.bounds,
                        min_size,
                        max_size,
                        snap_zones,
                        start_rect,
                        expires_at_ms: now.saturating_add(30000),
                    };
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
                        let state = match key {
                            abi::gui::Shortcut::Left => WindowState::Left,
                            abi::gui::Shortcut::Right => WindowState::Right,
                            abi::gui::Shortcut::Maximize => WindowState::Maximized,
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
                    self.layout(id, state, self.surfaces[&id].normal)?;
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
                let rect = lease_rect(l, rect);
                l.expires_at_ms = now.saturating_add(30000);
                match event {
                    InteractiveOpEnd {
                        canceled,
                        snap_hint,
                        ..
                    } => {
                        let snap_hint = snap_hint.filter(|hint| l.snap_zones.contains(hint));
                        self.finish_lease(canceled);
                        if !canceled {
                            let state = match snap_hint {
                                Some(SnapZone::Left) => WindowState::Left,
                                Some(SnapZone::Right) => WindowState::Right,
                                Some(SnapZone::Top) => WindowState::Maximized,
                                None => WindowState::Normal,
                            };
                            self.layout(surface_id, state, rect)?;
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
fn lease_rect(l: &DragLease, proposed: Rect) -> Rect {
    let base = l.start_rect;
    let InteractiveOp::Resize { edge } = l.op else {
        return Rect {
            x: proposed.x,
            y: proposed.y,
            ..base
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
}
