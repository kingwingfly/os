// COMPAT-BRIDGE (#61): remove in #65 once files/terminal/viewer/editor/mounts run as native GUI clients.
//! Thin DOM presentation bridge for the desktop. Window placement, focus, stacking, snap zones,
//! compact phone layout, dock state, launcher state, and layout persistence all live in the
//! supervised `compositor` and `desktop-shell` WASI processes over `/run/gui/seat0.sock`.
use abi::gui::{DockEntry, LauncherEntry, ShellAction, ShellStateView};
use leptos::prelude::*;
use wasm_bindgen::{JsCast, closure::Closure, prelude::*};
use wasm_bindgen_futures::{JsFuture, spawn_local};

/// The legacy page compat apps: their id, title, and DOM element id.
pub const APPS: [(&str, &str, &str); 5] = [
    ("files", "Files", "window-files"),
    ("terminal", "Terminal", "window-terminal"),
    ("viewer", "Preview", "viewer"),
    ("editor", "Editor", "editor"),
    ("mounts", "Mounts", "window-mounts"),
];

pub const EDGES: [&str; 8] = ["n", "s", "e", "w", "ne", "nw", "se", "sw"];

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = osDesktop, js_name = start)]
    fn bridge_start(callbacks: &JsValue);
    #[wasm_bindgen(js_namespace = osDesktop, js_name = show)]
    fn bridge_show(app_id: &str);
    #[wasm_bindgen(js_namespace = osDesktop, js_name = setCompatOpen)]
    fn bridge_set_compat_open(app_id: &str, open: bool);
    #[wasm_bindgen(js_namespace = osDesktop, js_name = shellInput)]
    fn bridge_shell_input(action: &JsValue);
    #[wasm_bindgen(js_namespace = osDesktop, js_name = restartGraphical)]
    fn bridge_restart_graphical() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osDesktop, js_name = stopGreeter)]
    fn bridge_stop_greeter() -> js_sys::Promise;
}

fn initial_shell_state() -> ShellStateView {
    ShellStateView {
        dock: vec![
            DockEntry {
                app_id: "terminal".into(),
                label: "Terminal".into(),
                surface_id: None,
                open: true,
                minimized: false,
                focused: true,
                pinned: true,
            },
            DockEntry {
                app_id: "files".into(),
                label: "Files".into(),
                surface_id: None,
                open: true,
                minimized: false,
                focused: false,
                pinned: true,
            },
        ],
        launcher_open: false,
        launcher_items: vec![
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
        ],
        compact: false,
        fullscreen: false,
        focused_title: Some("Terminal".into()),
        seat_id: "seat0".into(),
    }
}

#[derive(Clone, Copy)]
pub struct Desktop {
    pub shell_state: RwSignal<ShellStateView>,
    pub focused: RwSignal<Option<&'static str>>,
    pub graphical_ended: RwSignal<bool>,
    pub greeter_modal: RwSignal<bool>,
    pub restarting: RwSignal<bool>,
    on_launch: StoredValue<Option<Callback<String>>>,
}

thread_local! {
    static DESKTOP: std::cell::Cell<Option<Desktop>> = const { std::cell::Cell::new(None) };
}

pub fn desktop() -> Option<Desktop> {
    DESKTOP.with(std::cell::Cell::get)
}

fn document() -> Option<web_sys::Document> {
    web_sys::window()?.document()
}

fn static_app_id(id: &str) -> Option<&'static str> {
    APPS.iter()
        .find(|(app, _, _)| *app == id)
        .map(|(a, _, _)| *a)
}

impl Desktop {
    pub fn new() -> Self {
        let desktop = Self {
            shell_state: RwSignal::new(initial_shell_state()),
            focused: RwSignal::new(Some("terminal")),
            graphical_ended: RwSignal::new(false),
            greeter_modal: RwSignal::new(false),
            restarting: RwSignal::new(false),
            on_launch: StoredValue::new(None),
        };
        DESKTOP.with(|d| d.set(Some(desktop)));
        desktop
    }

    pub fn set_on_launch(self, cb: Callback<String>) {
        self.on_launch.set_value(Some(cb));
    }

    pub fn show(self, id: &str) {
        bridge_show(id);
    }

    pub fn send_action(self, action: ShellAction) {
        if let Ok(val) = serde_wasm_bindgen::to_value(&action) {
            bridge_shell_input(&val);
        }
    }

    pub fn toggle(self, id: &str) {
        self.send_action(ShellAction::ToggleApp {
            app_id: id.to_owned(),
        });
    }

    pub fn focus_surface(self, surface_id: u64) {
        self.send_action(ShellAction::Focus { surface_id });
    }

    pub fn toggle_launcher(self) {
        self.send_action(ShellAction::ToggleLauncher {});
    }

    pub fn close_launcher(self) {
        self.send_action(ShellAction::CloseLauncher {});
    }

    pub fn launch(self, id: &str) {
        self.send_action(ShellAction::Launch {
            app_id: id.to_owned(),
        });
    }

    pub fn restart_graphical(self) {
        if self.restarting.get_untracked() {
            return;
        }
        self.restarting.set(true);
        spawn_local(async move {
            let res = JsFuture::from(bridge_restart_graphical()).await;
            self.restarting.set(false);
            if res.is_ok() {
                self.graphical_ended.set(false);
            }
        });
    }

    pub fn dismiss_greeter(self) {
        spawn_local(async move {
            let _ = JsFuture::from(bridge_stop_greeter()).await;
            self.greeter_modal.set(false);
        });
    }
}

pub fn handles() -> impl IntoView {
    EDGES
        .iter()
        .map(|name| {
            view! { <div class=format!("window-resize window-resize-{name}") data-edge=*name aria-hidden="true"></div> }
        })
        .collect_view()
}

pub fn controls(id: &'static str, title: &'static str) -> impl IntoView {
    view! {
        <span class="window-controls">
            <button type="button" data-window-action="minimize" aria-label=format!("Minimize {title}") title="Minimize">"–"</button>
            <button type="button" data-window-action="maximize" aria-label=format!("Maximize {title}") title="Fill the desktop · Ctrl+Alt+↑">"□"</button>
            <button type="button" data-window-action="close" aria-label=format!("Close {title}") title="Close" data-window-for=id>"×"</button>
        </span>
    }
}

fn adopt(app: &'static str, element: &str, bar: &str, close: &str) {
    let Some(document) = document() else { return };
    let Some(dialog) = document.get_element_by_id(element) else {
        return;
    };
    if let Some(area) = document.query_selector(".desktop-area").ok().flatten() {
        let _ = area.append_child(&dialog);
    }
    let _ = dialog.class_list().add_1("window");
    let _ = dialog.set_attribute("data-window", app);
    let _ = dialog.set_attribute("tabindex", "-1");
    for name in EDGES {
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
    let watched = dialog.clone();
    let last_open = std::rc::Rc::new(std::cell::Cell::new(watched.has_attribute("open")));
    let observer = Closure::<dyn FnMut()>::new(move || {
        let open = watched.has_attribute("open");
        if open != last_open.get() {
            last_open.set(open);
            bridge_set_compat_open(app, open);
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

pub fn run(desktop: Desktop) {
    adopt("viewer", "viewer", ".viewer-bar", "#close-viewer");
    adopt("editor", "editor", ".editor-bar", "#editor-close");

    let cbs = js_sys::Object::new();

    let on_shell_state = Closure::<dyn FnMut(JsValue)>::new(move |val: JsValue| {
        if let Ok(state) = serde_wasm_bindgen::from_value::<ShellStateView>(val) {
            desktop.shell_state.set(state);
        }
    });
    let _ = js_sys::Reflect::set(
        &cbs,
        &"onShellState".into(),
        on_shell_state.as_ref().unchecked_ref(),
    );
    on_shell_state.forget();

    let on_focus = Closure::<dyn FnMut(JsValue)>::new(move |val: JsValue| {
        let focused = val.as_string().and_then(|s| static_app_id(&s));
        desktop.focused.set(focused);
    });
    let _ = js_sys::Reflect::set(&cbs, &"onFocus".into(), on_focus.as_ref().unchecked_ref());
    on_focus.forget();

    let on_launch_app = Closure::<dyn FnMut(JsValue)>::new(move |val: JsValue| {
        if let Some(app_id) = val.as_string()
            && let Some(cb) = desktop.on_launch.get_value()
        {
            cb.run(app_id);
        }
    });
    let _ = js_sys::Reflect::set(
        &cbs,
        &"onLaunchApp".into(),
        on_launch_app.as_ref().unchecked_ref(),
    );
    on_launch_app.forget();

    let on_graphical_ended = Closure::<dyn FnMut(bool)>::new(move |ended: bool| {
        desktop.graphical_ended.set(ended);
    });
    let _ = js_sys::Reflect::set(
        &cbs,
        &"onGraphicalEnded".into(),
        on_graphical_ended.as_ref().unchecked_ref(),
    );
    on_graphical_ended.forget();

    let on_greeter_modal = Closure::<dyn FnMut(bool)>::new(move |active: bool| {
        desktop.greeter_modal.set(active);
    });
    let _ = js_sys::Reflect::set(
        &cbs,
        &"onGreeterModal".into(),
        on_greeter_modal.as_ref().unchecked_ref(),
    );
    on_greeter_modal.forget();

    bridge_start(cbs.as_ref());
}
