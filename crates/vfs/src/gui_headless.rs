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
    pub focus: RefCell<Option<SurfaceId>>,
    pub lease: RefCell<Option<DragLease>>,
    lease_origin: Cell<Option<Rect>>,
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
            }
            DisplayCmd::Unmap { surface_id } => {
                self.surfaces.borrow_mut().remove(surface_id);
            }
            DisplayCmd::Focus { surface_id, .. } => {
                self.focus.replace(*surface_id);
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
                surface_id, rect, ..
            }
            | DisplayCmd::DragFrame {
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
            DisplayCmd::SeatReset => {
                self.surfaces.borrow_mut().clear();
                self.focus.take();
                self.lease.take();
                self.lease_origin.take();
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
            s.1 = rect.constrained(l.bounds, l.min_size, l.max_size);
        }
    }
}
