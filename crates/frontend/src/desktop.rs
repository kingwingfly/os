//! Thin DOM presentation bridge for the desktop. Window placement, focus, stacking, snap zones,
//! compact phone layout, dock state, launcher state, and layout persistence all live in the
//! supervised `compositor` and `desktop-shell` WASI processes over `/run/gui/seat0.sock`.
//! All desktop applications (`terminal`, `files`, `mounts`, `editor`, `preview`) run as ordinary
//! unprivileged GUI client processes (`#64` `L6c`).
use abi::gui::{DockEntry, LauncherEntry, ShellAction, ShellStateView};
use leptos::prelude::*;
use wasm_bindgen::{JsCast, closure::Closure, prelude::*};
use wasm_bindgen_futures::{JsFuture, spawn_local};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = osDesktop, js_name = start)]
    fn bridge_start(callbacks: &JsValue);
    #[wasm_bindgen(js_namespace = osDesktop, js_name = shellInput)]
    fn bridge_shell_input(action: &JsValue);
    #[wasm_bindgen(js_namespace = osDesktop, js_name = restartGraphical)]
    fn bridge_restart_graphical() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osDesktop, js_name = greeterStatus)]
    pub fn bridge_greeter_status() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osDesktop, js_name = startGreeter)]
    fn bridge_start_greeter() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osDesktop, js_name = stopGreeter)]
    pub fn bridge_stop_greeter(password: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osDesktop, js_name = openTerminalTab)]
    fn bridge_open_terminal_tab(argv: &JsValue, cwd: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osDesktop, js_name = openSettings)]
    fn bridge_open_settings(section: &str) -> js_sys::Promise;
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
                app_id: "settings".into(),
                label: "Settings".into(),
                description: "Accounts, cloud credentials, and appearance".into(),
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
    pub loading_label: RwSignal<Option<String>>,
    pub launching_apps: RwSignal<Vec<String>>,
}

thread_local! {
    static DESKTOP: std::cell::Cell<Option<Desktop>> = const { std::cell::Cell::new(None) };
}

pub fn desktop() -> Option<Desktop> {
    DESKTOP.with(std::cell::Cell::get)
}

fn static_app_id(id: &str) -> Option<&'static str> {
    match id {
        "terminal" => Some("terminal"),
        "files" => Some("files"),
        "mounts" => Some("mounts"),
        "settings" => Some("settings"),
        "editor" => Some("editor"),
        "preview" => Some("preview"),
        _ => None,
    }
}

pub fn open_terminal_tab(argv: &[String], cwd: &str) {
    let js_argv = serde_wasm_bindgen::to_value(argv).unwrap_or(JsValue::NULL);
    let _ = bridge_open_terminal_tab(&js_argv, cwd);
}

pub fn open_settings(section: &str) {
    let _ = bridge_open_settings(section);
}

impl Desktop {
    pub fn new() -> Self {
        let desktop = Self {
            shell_state: RwSignal::new(initial_shell_state()),
            focused: RwSignal::new(Some("terminal")),
            graphical_ended: RwSignal::new(false),
            greeter_modal: RwSignal::new(false),
            restarting: RwSignal::new(false),
            loading_label: RwSignal::new(None),
            launching_apps: RwSignal::new(Vec::new()),
        };
        DESKTOP.with(|d| d.set(Some(desktop)));
        desktop
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

    pub fn lock_screen(self) {
        if self.greeter_modal.get_untracked() {
            return;
        }
        spawn_local(async move {
            let _ = JsFuture::from(bridge_start_greeter()).await;
        });
    }

    pub fn dismiss_greeter(self) {
        self.greeter_modal.set(false);
    }
}

pub fn run(desktop: Desktop) {
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

    let on_loading = Closure::<dyn FnMut(JsValue)>::new(move |val: JsValue| {
        if let Ok(parsed) = serde_wasm_bindgen::from_value::<serde_json::Value>(val) {
            let label = parsed
                .get("label")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let apps = parsed
                .get("launchingApps")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_str().map(str::to_owned))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            desktop.loading_label.set(label);
            desktop.launching_apps.set(apps);
        } else {
            desktop.loading_label.set(None);
            desktop.launching_apps.set(Vec::new());
        }
    });
    let _ = js_sys::Reflect::set(
        &cbs,
        &"onLoading".into(),
        on_loading.as_ref().unchecked_ref(),
    );
    on_loading.forget();

    bridge_start(cbs.as_ref());
}
