//! The desktop (owner's design, 2026-10-30): a compositor in the page, in wasm, whose windows
//! are the browser's own elements, which it moves, sizes, stacks and focuses, and the browser
//! draws, as it draws everything else: text, input methods, video, PDF pages and iframes stay
//! the browser's. Its apps are the terminal, the files, the preview (the viewer) and the editor;
//! a dock shows and switches them, and a launcher starts them.
//!
//! A window is free, at its own place and size, or fills the desktop, or its left or right half;
//! it may be minimized to the dock. One moves by its title bar and resizes from its edges and
//! corners; dragged to the top it fills the desktop, to a side it takes that half, and a double
//! click fills or restores it. Ctrl+Alt+←/→/↑/↓ do the same from the keyboard, and Alt+` goes to
//! the next window. On a phone, the desktop shows one window at a time, filling it.
//!
//! The layout is the display's: each browser keeps its own (localStorage), as a monitor keeps
//! its arrangement, and lays every tab out by it. The preview and the editor are `<dialog>`s
//! that web/app.js opens with `show()`: the compositor takes them in among its windows, and
//! follows them as they open and close.
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use wasm_bindgen::{JsCast, closure::Closure};

/// The desktop's apps: their id, title, and the element that is their window.
pub const APPS: [(&str, &str, &str); 4] = [
    ("files", "Files", "window-files"),
    ("terminal", "Terminal", "window-terminal"),
    ("viewer", "Preview", "viewer"),
    ("editor", "Editor", "editor"),
];
/// The desktop is a phone's up to this width, as the CSS's: one window at a time.
const COMPACT: f64 = 650.0;
/// The smallest a window is made.
const MIN_W: f64 = 280.0;
const MIN_H: f64 = 180.0;
/// The gap the default layout leaves between windows and around them.
const GAP: f64 = 10.0;
/// Where the layout is kept.
const SAVED: &str = "terminal-desktop";

/// Where a window is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Place {
    #[default]
    Free,
    Maximized,
    Left,
    Right,
}

/// A window's frame: its place and size when free, where it is, and whether it is minimized.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    #[serde(default)]
    pub place: Place,
    #[serde(default)]
    pub minimized: bool,
}

/// A window of the desktop.
#[derive(Clone, Debug, PartialEq)]
pub struct Win {
    pub id: &'static str,
    pub title: &'static str,
    element: &'static str,
    pub open: bool,
    /// None until the desktop is measured, and a default layout made for it.
    frame: Option<Frame>,
    z: u32,
}
impl Win {
    pub fn shown(&self) -> bool {
        self.open && !self.frame.is_some_and(|f| f.minimized)
    }
}

/// The desktop's area, between its bar and its dock, as the viewport places it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Area {
    left: f64,
    top: f64,
    w: f64,
    h: f64,
}

/// What a pointer is doing to a window.
#[derive(Clone, Copy, Debug)]
enum Gesture {
    /// `free`: a filled window's frame as it was free, whose size a drag gives back.
    Move {
        id: &'static str,
        from: (f64, f64),
        start: Frame,
        free: Option<Frame>,
    },
    Resize {
        id: &'static str,
        edge: (i8, i8),
        from: (f64, f64),
        start: Frame,
    },
}

#[derive(Clone, Copy)]
pub struct Desktop {
    pub windows: RwSignal<Vec<Win>>,
    pub focused: RwSignal<Option<&'static str>>,
    area: RwSignal<Area>,
    gesture: StoredValue<Option<Gesture>>,
}

thread_local! {
    static DESKTOP: std::cell::Cell<Option<Desktop>> = const { std::cell::Cell::new(None) };
}

/// The desktop, once made.
pub fn desktop() -> Option<Desktop> {
    DESKTOP.with(std::cell::Cell::get)
}

fn document() -> Option<web_sys::Document> {
    web_sys::window()?.document()
}
fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

impl Desktop {
    /// The desktop, with the Terminal and the Files open, and the layout this display kept.
    pub fn new() -> Self {
        let saved: BTreeMap<String, Frame> = storage()
            .and_then(|s| s.get_item(SAVED).ok().flatten())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let windows = APPS
            .iter()
            .enumerate()
            .map(|(z, (id, title, element))| Win {
                id,
                title,
                element,
                open: matches!(*id, "files" | "terminal"),
                frame: saved.get(*id).copied(),
                z: z as u32,
            })
            .collect();
        let desktop = Self {
            windows: RwSignal::new(windows),
            focused: RwSignal::new(Some("terminal")),
            area: RwSignal::new(Area::default()),
            gesture: StoredValue::new(None),
        };
        DESKTOP.with(|d| d.set(Some(desktop)));
        desktop
    }

    /// Whether the desktop is a phone's.
    pub fn compact(self) -> bool {
        self.area.with(|a| a.w > 0.0 && a.w <= COMPACT)
    }

    fn update(self, id: &str, change: impl FnOnce(&mut Win)) {
        self.windows.update(|windows| {
            if let Some(win) = windows.iter_mut().find(|w| w.id == id) {
                change(win);
            }
        });
    }
    fn win(self, id: &str) -> Option<Win> {
        self.windows
            .with_untracked(|windows| windows.iter().find(|w| w.id == id).cloned())
    }

    /// Raise the window `id` above the others, and give it the focus.
    pub fn focus(self, id: &'static str) {
        let top = self
            .windows
            .with_untracked(|windows| windows.iter().map(|w| w.z).max().unwrap_or(0));
        let already =
            self.focused.get_untracked() == Some(id) && self.win(id).is_some_and(|w| w.z == top);
        if !already {
            // Stacked 1, 2, 3…: the order, without numbers that only grow.
            self.windows.update(|windows| {
                if let Some(win) = windows.iter_mut().find(|w| w.id == id) {
                    win.z = top + 1;
                }
                let mut order: Vec<usize> = (0..windows.len()).collect();
                order.sort_by_key(|&at| windows[at].z);
                for (z, at) in order.into_iter().enumerate() {
                    windows[at].z = z as u32 + 1;
                }
            });
            self.focused.set(Some(id));
        }
    }
    /// Open the window `id`, as it was, and focus it.
    pub fn show(self, id: &'static str) {
        self.update(id, |win| {
            win.open = true;
            if let Some(frame) = &mut win.frame {
                frame.minimized = false;
            }
        });
        self.focus(id);
        self.save();
    }
    /// What the dock does with the window `id`: shows it if it is not, minimizes it if it is the
    /// focused one, focuses it otherwise.
    pub fn toggle(self, id: &'static str) {
        let Some(win) = self.win(id) else { return };
        if !win.shown() {
            self.show(id);
            focus_into(id);
        } else if self.focused.get_untracked() == Some(id) {
            self.minimize(id);
        } else {
            self.focus(id);
            focus_into(id);
        }
    }
    pub fn minimize(self, id: &'static str) {
        self.update(id, |win| {
            if let Some(frame) = &mut win.frame {
                frame.minimized = true;
            }
        });
        self.focus_next(id);
        self.save();
    }
    /// Close the window `id`: the preview and the editor close as their own buttons do; the
    /// Terminal and the Files are hidden, and the dock opens them again.
    pub fn close(self, id: &'static str) {
        match id {
            "viewer" => click("close-viewer"),
            "editor" => click("editor-close"),
            _ => {
                self.update(id, |win| win.open = false);
                self.focus_next(id);
                self.save();
            }
        }
    }
    /// Put the window `id` at `place`, or free it if it is there already.
    pub fn place(self, id: &'static str, place: Place) {
        let area = self.area.get_untracked();
        self.update(id, |win| {
            let frame = win.frame.get_or_insert_with(|| default_frame(id, area));
            frame.place = if frame.place == place {
                Place::Free
            } else {
                place
            };
            frame.minimized = false;
        });
        self.focus(id);
        self.save();
    }
    /// The window `id` went: the one above the rest gets the focus.
    fn focus_next(self, id: &str) {
        if self.focused.get_untracked() != Some(id) {
            return;
        }
        let next = self.windows.with_untracked(|windows| {
            windows
                .iter()
                .filter(|w| w.id != id && w.shown())
                .max_by_key(|w| w.z)
                .map(|w| w.id)
        });
        self.focused.set(next);
        if let Some(next) = next {
            focus_into(next);
        }
    }
    /// Go to the next window shown, the lowest of them, as Alt+Tab does.
    pub fn cycle(self) {
        let next = self.windows.with_untracked(|windows| {
            windows
                .iter()
                .filter(|w| w.shown())
                .min_by_key(|w| w.z)
                .map(|w| w.id)
        });
        if let Some(next) = next {
            self.focus(next);
            focus_into(next);
        }
    }

    /// Keep the layout, for this display.
    fn save(self) {
        let frames: BTreeMap<&str, Frame> = self.windows.with_untracked(|windows| {
            windows
                .iter()
                .filter_map(|w| Some((w.id, w.frame?)))
                .collect()
        });
        if let (Some(storage), Ok(text)) = (storage(), serde_json::to_string(&frames)) {
            let _ = storage.set_item(SAVED, &text);
        }
    }

    /// Measure the desktop's area again, as the viewport, or the keyboard, changed it.
    pub fn measure(self) {
        let Some(area) = document()
            .and_then(|d| d.query_selector(".desktop-area").ok().flatten())
            .map(|e| e.get_bounding_client_rect())
        else {
            return;
        };
        let area = Area {
            left: area.left(),
            top: area.top(),
            w: area.width(),
            h: area.height(),
        };
        if area != self.area.get_untracked() {
            self.area.set(area);
        }
    }

    /// Lay every window out as it is now: where, how big, how high, whether shown.
    fn apply(self) {
        let area = self.area.get();
        if area.w <= 0.0 {
            return;
        }
        let compact = self.compact();
        let focused = self.focused.get();
        // A window first shown gets the default layout of this desktop's size.
        if self
            .windows
            .with_untracked(|w| w.iter().any(|w| w.frame.is_none()))
        {
            self.windows.update(|windows| {
                for win in windows.iter_mut() {
                    win.frame.get_or_insert_with(|| default_frame(win.id, area));
                }
            });
        }
        let Some(document) = document() else { return };
        self.windows.with(|windows| {
            for win in windows {
                let Some(element) = document.get_element_by_id(win.element) else {
                    continue;
                };
                let frame = win.frame.unwrap_or_default();
                // On a phone, the focused window alone shows, and fills the desktop.
                let shown = win.shown() && (!compact || focused == Some(win.id));
                let (x, y, w, h) = if compact || frame.place == Place::Maximized {
                    (0.0, 0.0, area.w, area.h)
                } else {
                    match frame.place {
                        Place::Left => (0.0, 0.0, (area.w / 2.0).floor(), area.h),
                        Place::Right => {
                            let half = (area.w / 2.0).floor();
                            (half, 0.0, area.w - half, area.h)
                        }
                        _ => clamped(frame, area),
                    }
                };
                // Within the desktop's area, which holds every window.
                let style = format!(
                    "left:{x}px;top:{y}px;width:{w}px;height:{h}px;z-index:{}",
                    20 + win.z
                );
                let _ = element.set_attribute("style", &style);
                let classes = element.class_list();
                // A closed dialog the browser hides itself; left unmarked, it shows the moment
                // web/app.js opens it, and can take the focus then.
                let dialog = element.tag_name() == "DIALOG";
                let _ = classes.toggle_with_force("window-hidden", !shown && (win.open || !dialog));
                let _ = classes.toggle_with_force("window-focused", focused == Some(win.id));
                let _ = classes
                    .toggle_with_force("window-filled", compact || frame.place != Place::Free);
            }
        });
    }
}

/// The default layout, for a desktop of `area`: the Files to the left, the Terminal beside
/// them; the preview and the editor over the middle.
fn default_frame(id: &str, area: Area) -> Frame {
    let files = (area.w * 0.28).clamp(MIN_W, 460.0);
    let (x, y, w, h) = match id {
        "files" => (GAP, GAP, files, area.h - 2.0 * GAP),
        "terminal" => (
            files + 2.0 * GAP,
            GAP,
            area.w - files - 3.0 * GAP,
            area.h - 2.0 * GAP,
        ),
        "viewer" => (area.w * 0.08, area.h * 0.04, area.w * 0.84, area.h * 0.92),
        _ => (area.w * 0.14, area.h * 0.05, area.w * 0.72, area.h * 0.9),
    };
    Frame {
        x,
        y,
        w: w.max(MIN_W),
        h: h.max(MIN_H),
        ..Frame::default()
    }
}

/// A free window's place within `area`: as large as it fits, with its title bar on the desktop.
fn clamped(frame: Frame, area: Area) -> (f64, f64, f64, f64) {
    let w = frame.w.clamp(MIN_W.min(area.w), area.w);
    let h = frame.h.clamp(MIN_H.min(area.h), area.h);
    let x = frame.x.clamp(80.0 - w, area.w - 80.0);
    let y = frame.y.clamp(0.0, (area.h - 40.0).max(0.0));
    (x, y, w, h)
}

/// Press the button `id`, as its window's own close does.
fn click(id: &str) {
    if let Some(button) = document()
        .and_then(|d| d.get_element_by_id(id))
        .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
    {
        button.click();
    }
}

/// Give the keyboard to the window `id`: the terminal's command line, or the window itself.
fn focus_into(id: &str) {
    if id == "terminal" {
        crate::focus_input();
        return;
    }
    let Some((_, _, element)) = APPS.iter().find(|(app, _, _)| *app == id) else {
        return;
    };
    if let Some(element) = document()
        .and_then(|d| d.get_element_by_id(element))
        .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
    {
        let _ = element.focus();
    }
}

/// The window an element is in, if it is in one.
fn window_of(target: &web_sys::EventTarget) -> Option<(&'static str, web_sys::Element)> {
    let element = target.dyn_ref::<web_sys::Element>()?;
    let window = element.closest(".window").ok().flatten()?;
    let id = window.get_attribute("data-window")?;
    let id = APPS.iter().find(|(app, _, _)| *app == id)?.0;
    Some((id, element.clone()))
}

/// The resize handles a window has at its edges and corners.
pub const EDGES: [(&str, i8, i8); 8] = [
    ("n", 0, -1),
    ("s", 0, 1),
    ("e", 1, 0),
    ("w", -1, 0),
    ("ne", 1, -1),
    ("nw", -1, -1),
    ("se", 1, 1),
    ("sw", -1, 1),
];

/// A window's resize handles, as markup.
pub fn handles() -> impl IntoView {
    EDGES
        .iter()
        .map(|(name, _, _)| {
            view! { <div class=format!("window-resize window-resize-{name}") data-edge=*name aria-hidden="true"></div> }
        })
        .collect_view()
}

/// A window's buttons: minimize, maximize, close.
pub fn controls(id: &'static str, title: &'static str) -> impl IntoView {
    view! {
        <span class="window-controls">
            <button type="button" data-window-action="minimize" aria-label=format!("Minimize {title}") title="Minimize">"–"</button>
            <button type="button" data-window-action="maximize" aria-label=format!("Maximize {title}") title="Fill the desktop · Ctrl+Alt+↑">"□"</button>
            <button type="button" data-window-action="close" aria-label=format!("Close {title}") title="Close" data-window-for=id>"×"</button>
        </span>
    }
}

/// Make a `<dialog>` that web/app.js shows, `id`, a window of the desktop: its bar moves it, it
/// has handles and buttons, and it is laid out as it opens and goes as it closes.
fn adopt(desktop: Desktop, app: &'static str, element: &str, bar: &str, close: &str) {
    let Some(document) = document() else { return };
    let Some(dialog) = document.get_element_by_id(element) else {
        return;
    };
    // Among the other windows, to stack with them.
    if let Some(area) = document.query_selector(".desktop-area").ok().flatten() {
        let _ = area.append_child(&dialog);
    }
    let _ = dialog.class_list().add_1("window");
    let _ = dialog.set_attribute("data-window", app);
    let _ = dialog.set_attribute("tabindex", "-1");
    for (name, _, _) in EDGES {
        if let Ok(handle) = document.create_element("div") {
            let _ = handle.set_attribute("class", &format!("window-resize window-resize-{name}"));
            let _ = handle.set_attribute("data-edge", name);
            let _ = handle.set_attribute("aria-hidden", "true");
            let _ = dialog.append_child(&handle);
        }
    }
    if let Some(bar) = dialog.query_selector(bar).ok().flatten() {
        let _ = bar.set_attribute("data-window-bar", "");
        let title = APPS.iter().find(|(a, _, _)| *a == app).map_or("", |a| a.1);
        for (action, label, text) in [("minimize", "Minimize", "–"), ("maximize", "Maximize", "□")]
        {
            if let Ok(button) = document.create_element("button") {
                let _ = button.set_attribute("type", "button");
                let _ = button.set_attribute("data-window-action", action);
                let _ = button.set_attribute("aria-label", &format!("{label} {title}"));
                let _ = button.set_attribute("class", "window-control");
                button.set_text_content(Some(text));
                // Before the window's own close.
                match bar.query_selector(close).ok().flatten() {
                    Some(own) => {
                        let _ = own
                            .parent_node()
                            .and_then(|parent| parent.insert_before(&button, Some(&own)).ok());
                    }
                    None => {
                        let _ = bar.append_child(&button);
                    }
                }
            }
        }
    }
    // Opened and closed by web/app.js: the desktop follows.
    let watched = dialog.clone();
    let observer = Closure::<dyn FnMut()>::new(move || {
        let open = watched.has_attribute("open");
        let was = desktop.win(app).is_some_and(|w| w.open);
        if open && !was {
            desktop.show(app);
        } else if !open && was {
            desktop.update(app, |win| win.open = false);
            desktop.focus_next(app);
        }
    });
    if let Ok(mutations) = web_sys::MutationObserver::new(observer.as_ref().unchecked_ref()) {
        let init = web_sys::MutationObserverInit::new();
        init.set_attributes(true);
        init.set_attribute_filter(&js_sys::Array::of1(&"open".into()));
        let _ = mutations.observe_with_options(&dialog, &init);
    }
    observer.forget();
}

/// Run the compositor: lay out as things change, and take the pointer's and the keyboard's
/// gestures on windows.
pub fn run(desktop: Desktop) {
    Effect::new(move || desktop.apply());
    adopt(desktop, "viewer", "viewer", ".viewer-bar", "#close-viewer");
    adopt(desktop, "editor", "editor", ".editor-bar", "#editor-close");
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(page) = window.document() else {
        return;
    };
    let listen = |target: &web_sys::EventTarget,
                  name: &str,
                  capture: bool,
                  f: Closure<dyn FnMut(web_sys::Event)>| {
        let _ = target.add_event_listener_with_callback_and_bool(
            name,
            f.as_ref().unchecked_ref(),
            capture,
        );
        f.forget();
    };
    // Measured as the area changes size, whatever changed it: the window, the on-screen keyboard
    // (app.js's --app-height), the bar hidden; first, once laid out.
    let measure = Closure::<dyn FnMut()>::new(move || desktop.measure());
    if let (Ok(observer), Some(area)) = (
        web_sys::ResizeObserver::new(measure.as_ref().unchecked_ref()),
        page.query_selector(".desktop-area").ok().flatten(),
    ) {
        observer.observe(&area);
    }
    measure.forget();
    let measure = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| desktop.measure());
    listen(&window, "resize", false, measure);
    // Pressed: the window comes up; on its bar it moves, on an edge it resizes.
    let down = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        let Some(pointer) = event.dyn_ref::<web_sys::PointerEvent>() else {
            return;
        };
        let Some(target) = event.target() else { return };
        let Some((id, element)) = window_of(&target) else {
            return;
        };
        desktop.focus(id);
        if pointer.button() != 0 || desktop.compact() {
            return;
        }
        // Where the area is now: a keyboard may have scrolled the page without resizing it.
        desktop.measure();
        if desktop.compact() {
            return;
        }
        let area = desktop.area.get_untracked();
        let from = (f64::from(pointer.client_x()), f64::from(pointer.client_y()));
        let current = |desktop: Desktop| {
            let win = desktop.win(id)?;
            let frame = win.frame?;
            // What it shows now, as a free window's frame.
            let (x, y, w, h) = match frame.place {
                Place::Free => clamped(frame, area),
                Place::Maximized => (0.0, 0.0, area.w, area.h),
                Place::Left => (0.0, 0.0, area.w / 2.0, area.h),
                Place::Right => (area.w / 2.0, 0.0, area.w / 2.0, area.h),
            };
            Some(Frame {
                x,
                y,
                w,
                h,
                place: Place::Free,
                minimized: false,
            })
        };
        let gesture = if let Some(edge) = element
            .closest(".window-resize")
            .ok()
            .flatten()
            .and_then(|handle| handle.get_attribute("data-edge"))
        {
            let (_, dx, dy) = *EDGES
                .iter()
                .find(|(name, _, _)| *name == edge)
                .unwrap_or(&EDGES[0]);
            current(desktop).map(|start| Gesture::Resize {
                id,
                edge: (dx, dy),
                from,
                start,
            })
        } else if element
            .closest("[data-window-bar]")
            .ok()
            .flatten()
            .is_some()
            && element
                .closest("button,a,input,select,textarea,[contenteditable='true'],[role='tab']")
                .ok()
                .flatten()
                .is_none()
        {
            let free = desktop
                .win(id)
                .and_then(|win| win.frame)
                .filter(|frame| frame.place != Place::Free);
            current(desktop).map(|start| Gesture::Move {
                id,
                from,
                start,
                free,
            })
        } else {
            None
        };
        if let Some(gesture) = gesture {
            event.prevent_default();
            desktop.gesture.set_value(Some(gesture));
            let _ = document()
                .and_then(|d| d.body())
                .map(|b| b.class_list().add_1("window-dragging"));
        }
    });
    listen(&page, "pointerdown", true, down);
    let moved = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        let (Some(pointer), Some(gesture)) = (
            event.dyn_ref::<web_sys::PointerEvent>(),
            desktop.gesture.get_value(),
        ) else {
            return;
        };
        let at = (f64::from(pointer.client_x()), f64::from(pointer.client_y()));
        match gesture {
            Gesture::Move {
                id,
                from,
                start,
                free,
            } => {
                let (dx, dy) = (at.0 - from.0, at.1 - from.1);
                // A filled window stays until it is clearly dragged; then it is free at its own
                // size again, held where the pointer held it.
                let start = match free {
                    Some(_) if dx.abs() + dy.abs() < 6.0 => return,
                    Some(Frame { w, h, .. }) => {
                        let held = from.0 - desktop.area.get_untracked().left;
                        Frame {
                            x: held - (held - start.x) * w / start.w,
                            w,
                            h,
                            ..start
                        }
                    }
                    None => start,
                };
                desktop.update(id, |win| {
                    win.frame = Some(Frame {
                        x: start.x + dx,
                        y: start.y + dy,
                        ..start
                    });
                });
            }
            Gesture::Resize {
                id,
                edge,
                from,
                start,
            } => desktop.update(id, |win| {
                let (dx, dy) = (at.0 - from.0, at.1 - from.1);
                let mut frame = start;
                if edge.0 > 0 {
                    frame.w = (start.w + dx).max(MIN_W);
                }
                if edge.0 < 0 {
                    frame.w = (start.w - dx).max(MIN_W);
                    frame.x = start.x + start.w - frame.w;
                }
                if edge.1 > 0 {
                    frame.h = (start.h + dy).max(MIN_H);
                }
                if edge.1 < 0 {
                    frame.h = (start.h - dy).max(MIN_H);
                    frame.y = start.y + start.h - frame.h;
                }
                win.frame = Some(frame);
            }),
        }
    });
    listen(&page, "pointermove", false, moved);
    let up = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        let Some(gesture) = desktop.gesture.get_value() else {
            return;
        };
        desktop.gesture.set_value(None);
        let _ = document()
            .and_then(|d| d.body())
            .map(|b| b.class_list().remove_1("window-dragging"));
        // A window dragged and let go at the top fills the desktop; at a side, that half.
        if let (
            Gesture::Move {
                id,
                from,
                start,
                free,
            },
            Some(pointer),
        ) = (gesture, event.dyn_ref::<web_sys::PointerEvent>())
        {
            let area = desktop.area.get_untracked();
            let (x, y) = (f64::from(pointer.client_x()), f64::from(pointer.client_y()));
            let place = if (x - from.0).abs() + (y - from.1).abs() < 6.0 {
                None
            } else if y <= area.top + 2.0 {
                Some(Place::Maximized)
            } else if x <= area.left + 2.0 {
                Some(Place::Left)
            } else if x >= area.left + area.w - 2.0 {
                Some(Place::Right)
            } else {
                None
            };
            // Freed again, it goes back where it was before this drag.
            if let Some(place) = place {
                let before = free.unwrap_or(start);
                desktop.update(id, |win| {
                    if let Some(frame) = &mut win.frame {
                        (frame.x, frame.y, frame.place) = (before.x, before.y, place);
                    }
                });
            }
        }
        desktop.save();
    });
    listen(&page, "pointerup", false, up);
    // The keyboard's focus in a window brings it up.
    let focused = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        if let Some((id, _)) = event.target().as_ref().and_then(window_of) {
            desktop.focus(id);
        }
    });
    listen(&page, "focusin", false, focused);
    // A double click on a bar fills or restores its window; its buttons do what they say.
    let double = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        let Some(target) = event.target() else { return };
        let Some((id, element)) = window_of(&target) else {
            return;
        };
        let on_bar = element
            .closest("[data-window-bar]")
            .ok()
            .flatten()
            .is_some();
        let on_control = element.closest("button,a,input").ok().flatten().is_some();
        if on_bar && !on_control {
            desktop.place(id, Place::Maximized);
        }
    });
    listen(&page, "dblclick", false, double);
    let clicked = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        let Some(target) = event.target() else { return };
        let Some((id, element)) = window_of(&target) else {
            return;
        };
        let Some(action) = element
            .closest("[data-window-action]")
            .ok()
            .flatten()
            .and_then(|button| button.get_attribute("data-window-action"))
        else {
            return;
        };
        match action.as_str() {
            "minimize" => desktop.minimize(id),
            "maximize" => desktop.place(id, Place::Maximized),
            "close" => desktop.close(id),
            _ => {}
        }
    });
    listen(&page, "click", false, clicked);
    // Ctrl+Alt+arrows place the focused window; Alt+` goes to the next.
    let keys = Closure::<dyn FnMut(web_sys::Event)>::new(move |event: web_sys::Event| {
        let Some(key) = event.dyn_ref::<web_sys::KeyboardEvent>() else {
            return;
        };
        if key.is_composing() || key.meta_key() {
            return;
        }
        if key.alt_key() && !key.ctrl_key() && key.code() == "Backquote" {
            event.prevent_default();
            desktop.cycle();
            return;
        }
        if !(key.alt_key() && key.ctrl_key()) {
            return;
        }
        let Some(id) = desktop.focused.get_untracked() else {
            return;
        };
        let place = match key.key().as_str() {
            "ArrowLeft" => Place::Left,
            "ArrowRight" => Place::Right,
            "ArrowUp" => Place::Maximized,
            "ArrowDown" => {
                event.prevent_default();
                let filled = desktop
                    .win(id)
                    .and_then(|w| w.frame)
                    .is_some_and(|f| f.place != Place::Free);
                if filled {
                    desktop.update(id, |win| {
                        if let Some(frame) = &mut win.frame {
                            frame.place = Place::Free;
                        }
                    });
                    desktop.save();
                } else {
                    desktop.minimize(id);
                }
                return;
            }
            _ => return,
        };
        event.prevent_default();
        desktop.place(id, place);
    });
    listen(&page, "keydown", false, keys);
}
