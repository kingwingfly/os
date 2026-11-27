//! Presentation state for a host with no graphical system. The WASI compositor
//! and the headless tests consume the same wire commands and return seat events.
use abi::gui::*;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
};

#[derive(Default)]
pub struct HeadlessHostAdapter {
    pub surfaces: RefCell<BTreeMap<SurfaceId, (u32, Rect, u32)>>,
    pub visibility: RefCell<BTreeMap<SurfaceId, (bool, bool, u32)>>,
    pub focus: RefCell<Option<SurfaceId>>,
    pub modal: Cell<bool>,
    pub fullscreen: Cell<Option<SurfaceId>>,
    pub lease: RefCell<Option<DragLease>>,
    lease_origin: Cell<Option<Rect>>,
    pub shell_state: RefCell<Option<ShellStateView>>,
    pub launched: RefCell<Vec<String>>,
    pub migrated_seats: RefCell<Vec<String>>,
    pub ready_seats: RefCell<Vec<String>>,
    pub commands: RefCell<Vec<DisplayCmd>>,
}
impl GuiHostSink for HeadlessHostAdapter {
    fn display(&self, cmd: DisplayCmd) {
        match &cmd {
            DisplayCmd::Map {
                surface_id,
                owner_pid,
                rect,
                generation,
                ..
            } => {
                self.surfaces
                    .borrow_mut()
                    .insert(*surface_id, (*owner_pid, *rect, *generation));
                self.visibility
                    .borrow_mut()
                    .insert(*surface_id, (true, false, 0));
            }
            DisplayCmd::Unmap { surface_id } => {
                self.surfaces.borrow_mut().remove(surface_id);
                self.visibility.borrow_mut().remove(surface_id);
                if self.fullscreen.get() == Some(*surface_id) {
                    self.fullscreen.set(None);
                }
            }
            DisplayCmd::SetFullscreen { surface_id, active } => {
                if *active {
                    self.fullscreen.set(Some(*surface_id));
                } else if self.fullscreen.get() == Some(*surface_id) {
                    self.fullscreen.set(None);
                }
            }
            DisplayCmd::Focus { surface_id, modal } => {
                self.focus.replace(*surface_id);
                self.modal.set(*modal);
            }
            DisplayCmd::DragFrame {
                surface_id,
                lease_id,
                ..
            } if !self
                .lease
                .borrow()
                .as_ref()
                .is_some_and(|l| l.lease_id == *lease_id && l.surface_id == *surface_id) => {}
            DisplayCmd::Geometry {
                surface_id,
                rect,
                visible,
                filled,
                z_index,
                ..
            } => {
                if let Some(s) = self.surfaces.borrow_mut().get_mut(surface_id) {
                    s.1 = *rect;
                }
                self.visibility
                    .borrow_mut()
                    .insert(*surface_id, (*visible, *filled, *z_index));
            }
            DisplayCmd::DragFrame {
                surface_id, rect, ..
            } => {
                if let Some(s) = self.surfaces.borrow_mut().get_mut(surface_id) {
                    s.1 = *rect;
                }
            }
            DisplayCmd::RecreatePixelCanvas {
                surface_id,
                generation,
                ..
            } => {
                if let Some(s) = self.surfaces.borrow_mut().get_mut(surface_id) {
                    s.2 = *generation;
                }
            }
            DisplayCmd::BeginInteractiveOp { lease } => {
                self.lease_origin
                    .set(self.surfaces.borrow().get(&lease.surface_id).map(|s| s.1));
                self.lease.replace(Some(lease.clone()));
            }
            DisplayCmd::CancelInteractiveOp { lease_id }
                if self
                    .lease
                    .borrow()
                    .as_ref()
                    .is_some_and(|l| l.lease_id == *lease_id) =>
            {
                if let (Some(lease), Some(rect)) = (self.lease.take(), self.lease_origin.take())
                    && let Some(s) = self.surfaces.borrow_mut().get_mut(&lease.surface_id)
                {
                    s.1 = rect;
                }
            }
            DisplayCmd::ShellState { state } => {
                self.shell_state.replace(Some(state.clone()));
            }
            DisplayCmd::LaunchApp { app_id } => {
                self.launched.borrow_mut().push(app_id.clone());
            }
            DisplayCmd::LegacyLayoutMigrated { seat_id } => {
                self.migrated_seats.borrow_mut().push(seat_id.clone());
            }
            DisplayCmd::LayoutReady { seat_id } => {
                self.ready_seats.borrow_mut().push(seat_id.clone());
            }
            DisplayCmd::SeatReset => {
                self.surfaces.borrow_mut().clear();
                self.visibility.borrow_mut().clear();
                self.focus.take();
                self.modal.set(false);
                self.fullscreen.set(None);
                self.lease.take();
                self.lease_origin.take();
                self.shell_state.take();
                self.launched.borrow_mut().clear();
                self.migrated_seats.borrow_mut().clear();
                self.ready_seats.borrow_mut().clear();
            }
            _ => {}
        }
        self.commands.borrow_mut().push(cmd);
    }
}
impl HeadlessHostAdapter {
    pub fn local_frame(&self, rect: Rect) {
        if let Some(l) = self.lease.borrow().as_ref()
            && let Some(s) = self.surfaces.borrow_mut().get_mut(&l.surface_id)
        {
            let proposed = if l.op == InteractiveOp::Move
                && let Some(restore) = l.restore_rect
                && (rect.x - l.start_rect.x).abs() + (rect.y - l.start_rect.y).abs() >= 6
            {
                Rect {
                    x: rect.x,
                    y: rect.y,
                    width: restore.width,
                    height: restore.height,
                }
            } else {
                rect
            };
            s.1 = proposed.constrained(l.bounds, l.min_size, l.max_size);
        }
    }
}
