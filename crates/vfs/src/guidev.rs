//! Instance-local seat 0. Exclusivity follows the open description through dup/close.
//! Only the host supplies input and only the process holding the display can present.
use crate::devfs::DeviceBackend;
use crate::{Access, BoxFuture, Cred, OpenRef, Result, WriteAt, Written};
pub use abi::gui::GuiHostSink;
use abi::{Errno, gui::*};
use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, VecDeque},
    rc::Rc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GuiDevice {
    Display,
    Input,
}
impl GuiDevice {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "gui:display" => Some(Self::Display),
            "gui:input" => Some(Self::Input),
            _ => None,
        }
    }
}
#[derive(Clone, Debug)]
pub struct SurfaceBinding {
    pub pid: u32,
    pub endpoint: u32,
    pub generation: u32,
    pub pixel: bool,
    pub mapped: bool,
}
#[derive(Default)]
struct Seat {
    opens: BTreeMap<GuiDevice, (u32, OpenRef)>,
    shell_nominee: Option<u32>,
    peers: BTreeSet<u32>,
    grants: BTreeMap<u32, Vec<String>>,
    bindings: BTreeMap<SurfaceId, SurfaceBinding>,
    events: VecDeque<SeatEvent>,
    read_buf: VecDeque<u8>,
    write_buf: Vec<u8>,
    epoch: u32,
}
pub struct GuiDeviceRegistry {
    seat: RefCell<Seat>,
    sink: Rc<dyn GuiHostSink>,
    pub caller: Rc<Cell<Option<u32>>>,
}
impl GuiDeviceRegistry {
    pub fn new(sink: Rc<dyn GuiHostSink>, caller: Rc<Cell<Option<u32>>>) -> Self {
        Self {
            seat: Default::default(),
            sink,
            caller,
        }
    }
    pub fn grant(&self, pid: u32, devices: &[String]) {
        self.seat.borrow_mut().grants.insert(pid, devices.to_vec());
    }
    pub fn epoch(&self) -> u32 {
        self.seat.borrow().epoch
    }
    pub fn claim(&self, dev: GuiDevice, uid: u32, open: &OpenRef) -> Result<()> {
        if open.access == Access::Path {
            return Ok(());
        }
        if uid != 0 {
            return Err(Errno::EACCES);
        }
        let pid = self.caller.get().ok_or(Errno::EPERM)?;
        let mut seat = self.seat.borrow_mut();
        let name = match dev {
            GuiDevice::Display => "display",
            GuiDevice::Input => "input",
        };
        if !seat
            .grants
            .get(&pid)
            .is_some_and(|d| d.iter().any(|x| x == name))
        {
            return Err(Errno::EPERM);
        }
        if (dev == GuiDevice::Display && !open.access.writes())
            || (dev == GuiDevice::Input && !open.access.reads())
        {
            return Err(Errno::EACCES);
        }
        if seat.opens.contains_key(&dev) || seat.opens.values().any(|(owner, _)| *owner != pid) {
            return Err(Errno::EBUSY);
        }
        if dev == GuiDevice::Display {
            seat.epoch = seat.epoch.checked_add(1).ok_or(Errno::ENOSPC)?;
        }
        seat.opens.insert(dev, (pid, open.clone()));
        Ok(())
    }
    pub fn check(&self, pid: u32, open: &OpenRef) -> Result<GuiDevice> {
        if open.access == Access::Path {
            return Err(Errno::EBADF);
        }
        self.seat
            .borrow()
            .opens
            .iter()
            .find_map(|(d, (owner, r))| (r == open && *owner == pid).then_some(*d))
            .ok_or(Errno::EACCES)
    }
    pub fn release(&self, open: &OpenRef) {
        let mut seat = self.seat.borrow_mut();
        let reset = seat
            .opens
            .get(&GuiDevice::Display)
            .is_some_and(|(_, r)| r == open);
        seat.opens.retain(|_, (_, r)| r != open);
        if reset {
            seat.shell_nominee = None;
            seat.peers.clear();
            seat.bindings.clear();
            seat.events.clear();
            seat.read_buf.clear();
            seat.write_buf.clear();
            drop(seat);
            self.sink.display(DisplayCmd::SeatReset);
        }
    }
    pub fn watch_shell(&self, pid: u32) {
        self.seat.borrow_mut().shell_nominee = Some(pid);
    }
    pub fn track_peer(&self, pid: u32) {
        self.seat.borrow_mut().peers.insert(pid);
    }
    pub fn take_shell(&self, pid: u32) -> bool {
        self.seat
            .borrow_mut()
            .shell_nominee
            .take_if(|p| *p == pid)
            .is_some()
    }
    pub fn process_exit(&self, pid: u32) {
        let mut seat = self.seat.borrow_mut();
        seat.grants.remove(&pid);
        let opens: Vec<_> = seat
            .opens
            .values()
            .filter(|(owner, _)| *owner == pid)
            .map(|(_, r)| r.clone())
            .collect();
        let owned = seat.bindings.values().any(|b| b.pid == pid);
        let nominated = seat.shell_nominee.take_if(|p| *p == pid).is_some();
        let tracked = seat.peers.remove(&pid);
        if owned || nominated || tracked {
            seat.bindings.retain(|_, b| b.pid != pid);
            seat.events.push_front(SeatEvent::ClientGone { pid });
        }
        drop(seat);
        for open in opens {
            self.release(&open);
        }
    }
    pub fn bind(&self, surface_id: SurfaceId, pid: u32, endpoint: u32) -> Result<()> {
        let mut seat = self.seat.borrow_mut();
        if seat.bindings.contains_key(&surface_id) {
            return Err(Errno::EBUSY);
        }
        if seat.bindings.len() >= MAX_SURFACES {
            return Err(Errno::ENOSPC);
        }
        seat.bindings.insert(
            surface_id,
            SurfaceBinding {
                pid,
                endpoint,
                generation: 0,
                pixel: false,
                mapped: false,
            },
        );
        Ok(())
    }
    pub fn binding(&self, id: SurfaceId) -> Result<SurfaceBinding> {
        self.seat
            .borrow()
            .bindings
            .get(&id)
            .filter(|b| b.mapped)
            .cloned()
            .ok_or(Errno::ESTALE)
    }
    pub fn present(&self, cmd: DisplayCmd) -> Result<()> {
        let mut seat = self.seat.borrow_mut();
        match &cmd {
            DisplayCmd::Map {
                surface_id,
                owner_pid,
                document,
                compat_app,
                generation,
                ..
            } => {
                let b = seat.bindings.get_mut(surface_id).ok_or(Errno::EACCES)?;
                if b.pid != *owner_pid || b.mapped || *generation != 1 {
                    return Err(Errno::EACCES);
                }
                b.mapped = true;
                b.pixel = document.is_none() && compat_app.is_none();
                b.generation = *generation;
            }
            DisplayCmd::RecreatePixelCanvas {
                surface_id,
                generation,
                ..
            } => {
                let b = seat.bindings.get_mut(surface_id).ok_or(Errno::ESTALE)?;
                if !b.pixel || b.generation.checked_add(1) != Some(*generation) {
                    return Err(Errno::ESTALE);
                }
                b.generation = *generation;
            }
            DisplayCmd::Unmap { surface_id } => {
                seat.bindings.remove(surface_id);
            }
            DisplayCmd::SeatReset => {
                seat.bindings.clear();
            }
            _ => {}
        }
        drop(seat);
        self.sink.display(cmd);
        Ok(())
    }
    pub fn enqueue(&self, event: SeatEvent) -> Result<()> {
        let mut seat = self.seat.borrow_mut();
        if !seat.opens.contains_key(&GuiDevice::Display) {
            return Err(Errno::ENODEV);
        }
        // Only coalesce within the current run of motion. A release, focus change
        // or other transition is an ordering barrier.
        if let Some(key) = motion(&event) {
            let pending = seat
                .events
                .iter()
                .rev()
                .take_while(|e| motion(e).is_some())
                .position(|e| motion(e) == Some(key));
            if let Some(back) = pending {
                let index = seat.events.len() - back - 1;
                seat.events.remove(index);
            }
            if seat.events.len() >= 448 {
                return Ok(());
            }
        }
        let mandatory = matches!(
            event,
            SeatEvent::Display(_)
                | SeatEvent::ClientGone { .. }
                | SeatEvent::Input(
                    InputEvent::SeatActive { .. }
                        | InputEvent::InteractiveOpEnd { .. }
                        | InputEvent::PointerUp { .. }
                        | InputEvent::DndDrop { .. }
                        | InputEvent::HostFocus
                        | InputEvent::PickerResult { .. }
                        | InputEvent::ExternalDrop { .. }
                        | InputEvent::UploadProgress { .. }
                        | InputEvent::MountConsentResult { .. }
                        | InputEvent::FullscreenChanged { .. }
                        | InputEvent::SeatLayoutInit { .. }
                )
        );
        if seat.events.len() >= if mandatory { 512 } else { 448 } {
            return Err(Errno::EAGAIN);
        }
        seat.events.push_back(event);
        Ok(())
    }
    pub fn next(&self) -> Result<SeatEvent> {
        self.seat
            .borrow_mut()
            .events
            .pop_front()
            .ok_or(Errno::EAGAIN)
    }
    pub fn ready(&self) -> usize {
        let s = self.seat.borrow();
        s.read_buf.len() + s.events.len()
    }
}
fn motion(e: &SeatEvent) -> Option<(u8, u64, u64)> {
    match e {
        SeatEvent::Input(InputEvent::InteractiveOpProgress {
            lease_id,
            surface_id,
            ..
        }) => Some((0, *surface_id, *lease_id)),
        SeatEvent::Input(InputEvent::DndHover {
            surface_id,
            pointer_id,
            ..
        }) => Some((1, *surface_id, (*pointer_id).into())),
        SeatEvent::Input(InputEvent::PointerMove {
            surface_id,
            pointer_id,
            ..
        }) => Some((2, *surface_id, (*pointer_id).into())),
        _ => None,
    }
}
pub struct GuiDeviceBackend<D> {
    pub registry: Rc<GuiDeviceRegistry>,
    inner: D,
}
impl<D> GuiDeviceBackend<D> {
    pub fn new(inner: D, registry: GuiDeviceRegistry) -> Self {
        Self {
            inner,
            registry: Rc::new(registry),
        }
    }
}
impl<D: DeviceBackend> DeviceBackend for GuiDeviceBackend<D> {
    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        self.inner.fill_random(buf)
    }
    fn open_device(&self, rdev: &str, cred: &Cred, open: &OpenRef) -> Result<()> {
        match GuiDevice::parse(rdev) {
            Some(d) => self.registry.claim(d, cred.identity.id, open),
            None => self.inner.open_device(rdev, cred, open),
        }
    }
    fn release_device(&self, open: &OpenRef) {
        self.registry.release(open);
        self.inner.release_device(open);
    }
    fn poll_device(&self, rdev: &str, open: &OpenRef, writing: bool) -> Result<Option<usize>> {
        let Some(dev) = GuiDevice::parse(rdev) else {
            return self.inner.poll_device(rdev, open, writing);
        };
        if self
            .registry
            .check(self.registry.caller.get().ok_or(Errno::EPERM)?, open)?
            != dev
        {
            return Err(Errno::EBADF);
        }
        Ok(Some(match (dev, writing) {
            (GuiDevice::Input, false) => self.registry.ready(),
            (GuiDevice::Display, true) => 1,
            _ => return Err(Errno::EBADF),
        }))
    }
    fn read_open_device<'a>(
        &'a self,
        rdev: &'a str,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        if rdev == "gui:input" {
            return self.read_device(rdev, buf, offset);
        }
        self.inner.read_open_device(rdev, open, buf, offset)
    }
    fn write_open_device<'a>(
        &'a self,
        rdev: &'a str,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        if rdev == "gui:display" {
            return self.write_device(rdev, buf, at);
        }
        self.inner.write_open_device(rdev, open, buf, at)
    }
    fn read_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        if rdev != "gui:input" {
            return self.inner.read_device(rdev, buf, offset);
        }
        Box::pin(async move {
            let mut s = self.registry.seat.borrow_mut();
            if s.read_buf.is_empty() {
                let event = s.events.pop_front().ok_or(Errno::EAGAIN)?;
                s.read_buf = frame(&event)?.into();
            }
            let n = buf.len().min(s.read_buf.len());
            for (b, value) in buf.iter_mut().zip(s.read_buf.drain(..n)) {
                *b = value;
            }
            Ok(n)
        })
    }
    fn write_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        if rdev != "gui:display" {
            return self.inner.write_device(rdev, buf, at);
        }
        Box::pin(async move {
            let mut s = self.registry.seat.borrow_mut();
            if s.write_buf.len() + buf.len() > MAX_FRAME + 4 {
                s.write_buf.clear();
                return Err(Errno::E2BIG);
            }
            s.write_buf.extend_from_slice(buf);
            loop {
                match take_frame(&mut s.write_buf) {
                    Ok(Some(cmd)) => {
                        drop(s);
                        self.registry.present(cmd)?;
                        s = self.registry.seat.borrow_mut();
                    }
                    Ok(None) => break,
                    Err(e) => {
                        s.write_buf.clear();
                        return Err(e);
                    }
                }
            }
            Ok(Written {
                offset: 0,
                len: buf.len(),
            })
        })
    }
    fn sync_device<'a>(&'a self, rdev: &'a str) -> BoxFuture<'a, ()> {
        if GuiDevice::parse(rdev).is_some() {
            return Box::pin(async { Err(Errno::EINVAL) });
        }
        self.inner.sync_device(rdev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Filesystem, FsId, OpenOptions,
        devfs::{DefaultDeviceBackend, DevTmpFs},
        gui_headless::HeadlessHostAdapter,
        now_or_never,
    };
    #[test]
    fn exiting_nominee_revokes_unused_nomination_and_notifies_the_seat() {
        let seat = GuiDeviceRegistry::new(
            Rc::new(HeadlessHostAdapter::default()),
            Rc::new(Cell::new(Some(20))),
        );
        seat.watch_shell(21);
        seat.process_exit(22);
        assert_eq!(seat.next(), Err(Errno::EAGAIN));
        seat.process_exit(21);
        assert_eq!(seat.next(), Ok(SeatEvent::ClientGone { pid: 21 }));
        assert!(!seat.take_shell(21));
    }
    #[test]
    fn tracked_peer_exit_and_compat_surface_pixel_flag() {
        let sink = Rc::new(HeadlessHostAdapter::default());
        let seat = GuiDeviceRegistry::new(sink, Rc::new(Cell::new(Some(20))));
        seat.track_peer(31);
        seat.process_exit(31);
        assert_eq!(seat.next(), Ok(SeatEvent::ClientGone { pid: 31 }));

        seat.bind(7, 32, 1).unwrap();
        seat.present(DisplayCmd::Map {
            surface_id: 7,
            owner_pid: 32,
            role: SurfaceRole::Window,
            rect: Rect {
                x: 0,
                y: 0,
                width: 320,
                height: 240,
            },
            document: None,
            compat_app: Some("files".into()),
            app_id: Some("files".into()),
            generation: 1,
        })
        .unwrap();
        assert!(!seat.binding(7).unwrap().pixel);
    }
    #[test]
    fn g01_seat_acl_grant_exclusion_path_and_last_close() {
        let sink = Rc::new(HeadlessHostAdapter::default());
        let caller = Rc::new(Cell::new(Some(20)));
        let dev = Rc::new(DevTmpFs::new(
            FsId("seat".into()),
            1,
            Box::new(|| (0, 0)),
            GuiDeviceBackend::new(
                DefaultDeviceBackend,
                GuiDeviceRegistry::new(sink.clone(), caller.clone()),
            ),
        ));
        dev.register_gui_devices().unwrap();
        let root = Cred::root();
        let mut user = root.clone();
        user.identity.id = 1000;
        let registry = &dev.backend().registry;
        for name in ["display", "input"] {
            let entry = now_or_never(dev.lookup(&root, &dev.root(), name))
                .unwrap()
                .unwrap();
            assert_eq!(
                (
                    entry.metadata.mode & 0o777,
                    entry.metadata.uid,
                    entry.metadata.gid
                ),
                (0o600, 0, 0)
            );
            let mut opts = OpenOptions::new();
            opts.read(true).write(true);
            let open =
                |cred, options| now_or_never(dev.open(cred, &entry.handle, options)).unwrap();
            let mut path_opts = OpenOptions::new();
            path_opts.path(true);
            let path = open(&user, &path_opts).unwrap();
            assert_eq!(registry.check(20, &path), Err(Errno::EBADF));
            registry.grant(20, &[]);
            assert_eq!(open(&root, &opts), Err(Errno::EPERM));
            assert_eq!(open(&user, &opts), Err(Errno::EACCES));
            registry.grant(20, &[name.into()]);
            let fd = open(&root, &opts).unwrap();
            assert_eq!(open(&root, &opts), Err(Errno::EBUSY));
            now_or_never(dev.release(&path)).unwrap().unwrap();
            caller.set(Some(21));
            registry.grant(21, &[name.into()]);
            assert_eq!(open(&root, &opts), Err(Errno::EBUSY));
            assert_eq!(registry.check(21, &fd), Err(Errno::EACCES));
            caller.set(Some(20));
            now_or_never(dev.release(&fd)).unwrap().unwrap();
            let again = open(&root, &opts).unwrap();
            registry.process_exit(20);
            assert_eq!(registry.check(20, &again), Err(Errno::EACCES));
            now_or_never(dev.release(&again)).unwrap().unwrap();
        }
        let registry = &dev.backend().registry;
        let releases = crate::ReleaseQueue::new();
        let mut table = crate::FdTable::new();
        let fd = |name: &str, write: bool| {
            let entry = now_or_never(dev.lookup(&root, &dev.root(), name)).unwrap()?;
            let mut opts = OpenOptions::new();
            opts.write(write).read(!write);
            let open = now_or_never(dev.open(&root, &entry.handle, &opts)).unwrap()?;
            Ok::<_, Errno>(crate::FileRef::new(
                dev.clone(),
                open,
                entry.handle,
                root.clone(),
                &opts,
                &releases,
            ))
        };
        registry.grant(20, &["display".into(), "input".into()]);
        registry.grant(21, &["display".into(), "input".into()]);
        assert!(matches!(fd("display", false), Err(Errno::EACCES)));
        assert!(matches!(fd("input", true), Err(Errno::EACCES)));
        let display = table.insert(fd("display", true).unwrap(), true).unwrap();
        let dup = table.dup(display, 0, true).unwrap();
        now_or_never(table.close(display)).unwrap().unwrap();
        caller.set(Some(21));
        assert!(matches!(fd("display", true), Err(Errno::EBUSY)));
        assert!(matches!(fd("input", false), Err(Errno::EBUSY)));
        now_or_never(table.close(dup)).unwrap().unwrap();
        table.insert(fd("display", true).unwrap(), true).unwrap();
        for serial in 0..1024 {
            registry
                .enqueue(SeatEvent::Input(InputEvent::InteractiveOpProgress {
                    serial,
                    surface_id: 1,
                    lease_id: 1,
                    rect: Rect::default(),
                    snap_hint: None,
                }))
                .unwrap();
        }
        assert_eq!(registry.ready(), 1);
        for _ in 0..447 {
            registry
                .enqueue(SeatEvent::Input(InputEvent::FocusRequest { surface_id: 1 }))
                .unwrap();
        }
        assert_eq!(
            registry.enqueue(SeatEvent::Input(InputEvent::FocusRequest { surface_id: 1 })),
            Err(Errno::EAGAIN)
        );
        registry
            .enqueue(SeatEvent::Input(InputEvent::SeatActive { active: false }))
            .unwrap();
        drop(table);
        now_or_never(releases.flush()).unwrap().unwrap();
        caller.set(Some(20));
        let input = fd("input", false).unwrap();
        now_or_never(input.close()).unwrap().unwrap();
        assert!(sink.commands.borrow().contains(&DisplayCmd::SeatReset));
    }
}
