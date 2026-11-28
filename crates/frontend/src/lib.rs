pub mod cloud_panel;
mod console;
mod desktop;
mod greeter;
mod terminal;
mod uploads;

use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = os)]
    fn config() -> JsValue;
    #[wasm_bindgen(js_namespace = os, js_name = localMounts)]
    fn local_mounts() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = closeConsole)]
    fn close_console(id: &str);
    #[wasm_bindgen(js_namespace = os, js_name = bootStatus)]
    fn boot_status() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = cloudStatus)]
    fn cloud_status() -> js_sys::Promise;
}

pub(crate) fn js_message(error: JsValue) -> String {
    js_sys::Reflect::get(&error, &JsValue::from_str("message"))
        .ok()
        .and_then(|v| v.as_string())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "Operation failed".into())
}

async fn refresh_local_identity(local_identity: RwSignal<cloud_panel::LocalIdentityInfo>) {
    if let Ok(val) = JsFuture::from(boot_status()).await
        && let Ok(parsed) = serde_wasm_bindgen::from_value::<serde_json::Value>(val)
    {
        local_identity.update(|info| {
            if let Some(acc) = parsed.get("account") {
                if let Some(u) = acc.get("user").and_then(|v| v.as_str()) {
                    info.username = u.to_owned();
                }
                if let Some(uid) = acc.get("uid").and_then(|v| v.as_u64()) {
                    info.uid = uid as u32;
                }
                if let Some(gid) = acc.get("gid").and_then(|v| v.as_u64()) {
                    info.gid = gid as u32;
                }
                if let Some(h) = acc.get("home").and_then(|v| v.as_str()) {
                    info.home = h.to_owned();
                }
            }
            if let Some(root) = parsed.get("mounted_root") {
                if let Some(uuid) = root.get("volume_uuid").and_then(|v| v.as_str()) {
                    info.root_volume_uuid = Some(uuid.to_owned());
                }
                info.forked_from = root
                    .get("forked_from")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned);
                info.ephemeral_if_unmodified = root
                    .get("ephemeral_if_unmodified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
        });
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NotifItem {
    id: u64,
    pid: u32,
    title: String,
    body: String,
    time: String,
}

fn format_clock_parts() -> (String, String, String) {
    let d = js_sys::Date::new_0();
    const DAYS_SHORT: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const DAYS_LONG: [&str; 7] = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    const MONTHS_SHORT: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    const MONTHS_LONG: [&str; 12] = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let dow = (d.get_day() as usize).min(6);
    let mon = (d.get_month() as usize).min(11);
    let dom = d.get_date();
    let hour24 = d.get_hours();
    let min = d.get_minutes();
    let ampm = if hour24 >= 12 { "PM" } else { "AM" };
    let hour12 = match hour24 % 12 {
        0 => 12,
        h => h,
    };
    let time_str = format!("{hour12}:{min:02} {ampm}");
    let short = format!(
        "{} {} {}  {}",
        DAYS_SHORT[dow], MONTHS_SHORT[mon], dom, time_str
    );
    let long_date = format!("{}, {} {}", DAYS_LONG[dow], MONTHS_LONG[mon], dom);
    (short, long_date, time_str)
}

fn read_storage(key: &str) -> Option<String> {
    web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item(key).ok().flatten())
}

fn write_storage(key: &str, value: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(key, value);
    }
}

fn apply_theme_to_dom(mode: &str) {
    let resolved = if mode == "dark" { "dark" } else { "light" };
    if let Some(win) = web_sys::window() {
        if let Some(doc) = win.document()
            && let Some(root) = doc.document_element()
        {
            let _ = root.set_attribute("data-theme", resolved);
        }
        write_storage("os-theme", resolved);
        if let Ok(ev) = web_sys::Event::new("os:theme") {
            let _ = win.dispatch_event(&ev);
        }
    }
}

fn dispatch_chrome_preferences(theme: &str, dock_autohide: bool) {
    if let Some(win) = web_sys::window() {
        let detail = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &detail,
            &JsValue::from_str("theme"),
            &JsValue::from_str(if theme == "dark" { "dark" } else { "light" }),
        );
        let _ = js_sys::Reflect::set(
            &detail,
            &JsValue::from_str("dock_autohide"),
            &JsValue::from_bool(dock_autohide),
        );
        let _ = js_sys::Reflect::set(
            &detail,
            &JsValue::from_str("source"),
            &JsValue::from_str("chrome"),
        );
        let init = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&init, &JsValue::from_str("detail"), &detail);
        if let Ok(ctor) = js_sys::Reflect::get(&win, &JsValue::from_str("CustomEvent"))
            && let Some(ctor_fn) = ctor.dyn_ref::<js_sys::Function>()
        {
            let args = js_sys::Array::of2(&JsValue::from_str("os:preferences-changed"), &init);
            if let Ok(ev_val) = js_sys::Reflect::construct(ctor_fn, &args)
                && let Ok(ev) = ev_val.dyn_into::<web_sys::Event>()
            {
                let _ = win.dispatch_event(&ev);
            }
        }
    }
}

fn check_fullscreen() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|doc| js_sys::Reflect::get(&doc, &JsValue::from_str("fullscreenElement")).ok())
        .is_some_and(|v| !v.is_null() && !v.is_undefined())
}

fn toggle_desktop_fullscreen() {
    let Some(win) = web_sys::window() else { return };
    let Some(doc) = win.document() else { return };
    if check_fullscreen() {
        if let Ok(func) = js_sys::Reflect::get(&doc, &JsValue::from_str("exitFullscreen"))
            && let Some(f) = func.dyn_ref::<js_sys::Function>()
        {
            let _ = f.call0(&doc);
        }
    } else if let Some(target) = doc
        .query_selector(".desktop")
        .ok()
        .flatten()
        .or_else(|| doc.document_element())
        && let Ok(func) = js_sys::Reflect::get(&target, &JsValue::from_str("requestFullscreen"))
        && let Some(f) = func.dyn_ref::<js_sys::Function>()
    {
        let _ = f.call0(&target);
    }
}

fn dock_svg(id: &str) -> impl IntoView + use<> {
    let cls = match id {
        "terminal" => "dock-tile dock-tile-terminal",
        "files" => "dock-tile dock-tile-files",
        "mounts" => "dock-tile dock-tile-mounts",
        "settings" => "dock-tile dock-tile-settings",
        "preview" => "dock-tile dock-tile-preview",
        "editor" => "dock-tile dock-tile-editor",
        "manual" => "dock-tile dock-tile-manual",
        "upload" => "dock-tile dock-tile-upload",
        _ => "dock-tile dock-tile-default",
    };
    let icon = match id {
        "terminal" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <polyline points="5 8 10 12 5 16"/>
                <line x1="12" y1="16" x2="19" y2="16"/>
            </svg>
        }.into_any(),
        "files" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M3.5 7.5a2 2 0 0 1 2-2h4.2l2 2.2h6.8a2 2 0 0 1 2 2v7.8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2V7.5Z"/>
            </svg>
        }.into_any(),
        "mounts" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="5" width="18" height="6" rx="2"/>
                <rect x="3" y="13" width="18" height="6" rx="2"/>
                <circle cx="7.5" cy="8" r="1" fill="currentColor" stroke="none"/>
                <circle cx="7.5" cy="16" r="1" fill="currentColor" stroke="none"/>
            </svg>
        }.into_any(),
        "settings" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="3.2"/>
                <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.08a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.08a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.08a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>
            </svg>
        }.into_any(),
        "editor" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 20h9"/>
                <path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5Z"/>
            </svg>
        }.into_any(),
        "preview" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M2 12s3.8-6.5 10-6.5S22 12 22 12s-3.8 6.5-10 6.5S2 12 2 12Z"/>
                <circle cx="12" cy="12" r="2.8"/>
            </svg>
        }.into_any(),
        "manual" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v17H6.5A2.5 2.5 0 0 0 4 22V5.5Z"/>
                <path d="M4 18.5A2.5 2.5 0 0 1 6.5 16H20"/>
            </svg>
        }.into_any(),
        "upload" => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 16V5"/>
                <polyline points="7 10 12 5 17 10"/>
                <path d="M5 19h14"/>
            </svg>
        }.into_any(),
        _ => view! {
            <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <rect x="4" y="4" width="16" height="16" rx="4"/>
            </svg>
        }.into_any(),
    };
    view! { <span class=cls aria-hidden="true">{icon}</span> }
}

#[component]
fn App() -> impl IntoView {
    let branding: serde_json::Value =
        serde_wasm_bindgen::from_value(config()).expect("OS branding");
    let title = branding["name"].as_str().unwrap_or("OS").to_owned();
    let subtitle = branding["subtitle"].as_str().unwrap_or("").to_owned();
    let heading = branding["heading"].as_str().unwrap_or("").to_owned();
    let description = branding["description"].as_str().unwrap_or("").to_owned();
    // Supervised compositor & desktop-shell presentation bridge (`#64` L6c / `#65` L6d).
    let desktop = desktop::Desktop::new();
    let local_identity = RwSignal::new(cloud_panel::LocalIdentityInfo::default());
    let cloud_auth = RwSignal::new(cloud_panel::CloudAuthState::default());

    let initial_theme = read_storage("os-theme")
        .filter(|t| t == "dark" || t == "light")
        .unwrap_or_else(|| "light".to_owned());
    apply_theme_to_dom(&initial_theme);
    let theme = RwSignal::new(initial_theme);
    let dock_autohide_pref =
        RwSignal::new(read_storage("os-dock-autohide").as_deref() == Some("true"));
    let set_theme = move |next: &'static str| {
        theme.set(next.to_owned());
        apply_theme_to_dom(next);
        dispatch_chrome_preferences(next, dock_autohide_pref.get_untracked());
    };
    let is_fullscreen = RwSignal::new(check_fullscreen());
    let has_filled_window = RwSignal::new(false);
    let dock_hovered = RwSignal::new(false);
    let cc_open = RwSignal::new(false);
    let nc_open = RwSignal::new(false);
    let notifications = RwSignal::new(Vec::<NotifItem>::new());
    let unread_notifs = RwSignal::new(0usize);

    let (init_short, init_long, init_time) = format_clock_parts();
    let clock_short = RwSignal::new(init_short);
    let clock_long = RwSignal::new(init_long);
    let clock_time = RwSignal::new(init_time);

    spawn_local(async move {
        refresh_local_identity(local_identity).await;
        if let Ok(val) = JsFuture::from(cloud_status()).await
            && let Ok(parsed) = serde_wasm_bindgen::from_value::<serde_json::Value>(val)
        {
            apply_cloud_status_json(cloud_auth, &parsed, None);
        }
    });

    let window = web_sys::window().unwrap();

    // Refresh live clock every 15 seconds.
    let clock_cb = Closure::<dyn FnMut()>::new(move || {
        let (s, l, t) = format_clock_parts();
        clock_short.set(s);
        clock_long.set(l);
        clock_time.set(t);
    });
    let _ = window.set_interval_with_callback_and_timeout_and_arguments_0(
        clock_cb.as_ref().unchecked_ref(),
        15_000,
    );
    clock_cb.forget();

    // Track browser fullscreen transitions.
    if let Some(doc) = window.document() {
        let fs_cb = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
            is_fullscreen.set(check_fullscreen());
        });
        let _ = doc
            .add_event_listener_with_callback("fullscreenchange", fs_cb.as_ref().unchecked_ref());
        fs_cb.forget();
    }

    // Track maximized/filled windows for automatic Dock auto-hide.
    let filled_cb =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
            has_filled_window.set(e.detail().as_bool().unwrap_or(false));
        });
    let _ = window
        .add_event_listener_with_callback("os:window-filled", filled_cb.as_ref().unchecked_ref());
    filled_cb.forget();

    // Pointer bottom-edge sensor to reveal the auto-hidden Dock as cursor approaches.
    let dock_hide_timer: std::rc::Rc<std::cell::Cell<Option<i32>>> =
        std::rc::Rc::new(std::cell::Cell::new(None));
    let cancel_dock_hide = {
        let timer = dock_hide_timer.clone();
        move || {
            if let Some(id) = timer.take()
                && let Some(win) = web_sys::window()
            {
                win.clear_timeout_with_handle(id);
            }
        }
    };
    let schedule_dock_hide = {
        let timer = dock_hide_timer.clone();
        move || {
            if timer.get().is_some() {
                return;
            }
            let Some(win) = web_sys::window() else { return };
            let t_inner = timer.clone();
            let cb = Closure::once(move || {
                t_inner.set(None);
                dock_hovered.set(false);
            });
            if let Ok(id) = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                260,
            ) {
                timer.set(Some(id));
            }
            cb.forget();
        }
    };
    let cancel_for_move = cancel_dock_hide.clone();
    let schedule_for_move = schedule_dock_hide.clone();
    let pointer_cb =
        Closure::<dyn FnMut(web_sys::PointerEvent)>::new(move |e: web_sys::PointerEvent| {
            let Some(win) = web_sys::window() else { return };
            let h = win
                .inner_height()
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(900.0);
            let y = e.client_y() as f64;
            if y >= h - 18.0 {
                cancel_for_move();
                if !dock_hovered.get_untracked() {
                    dock_hovered.set(true);
                }
            } else if dock_hovered.get_untracked() && y < h - 96.0 {
                schedule_for_move();
            } else if y >= h - 96.0 {
                cancel_for_move();
            }
        });
    let _ =
        window.add_event_listener_with_callback("pointermove", pointer_cb.as_ref().unchecked_ref());
    pointer_cb.forget();

    // Capture compositor notifications into the Notification Center feed.
    let notify_cb =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
            if let Ok(v) = serde_wasm_bindgen::from_value::<serde_json::Value>(e.detail()) {
                let id = v.get("id").and_then(|x| x.as_u64()).unwrap_or(0);
                let pid = v.get("pid").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                let title = v
                    .get("title")
                    .and_then(|x| x.as_str())
                    .unwrap_or("Notification")
                    .to_owned();
                let body = v
                    .get("body")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_owned();
                let (_, _, time) = format_clock_parts();
                notifications.update(|list| {
                    list.insert(
                        0,
                        NotifItem {
                            id,
                            pid,
                            title,
                            body,
                            time,
                        },
                    );
                    if list.len() > 30 {
                        list.truncate(30);
                    }
                });
                if !nc_open.get_untracked() {
                    unread_notifs.update(|n| *n = n.saturating_add(1));
                }
            }
        });
    let _ =
        window.add_event_listener_with_callback("os:notify", notify_cb.as_ref().unchecked_ref());
    notify_cb.forget();

    let listener =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |_e: web_sys::CustomEvent| {
            spawn_local(async move {
                refresh_local_identity(local_identity).await;
            });
        });
    window
        .add_event_listener_with_callback("os:changed", listener.as_ref().unchecked_ref())
        .unwrap();
    listener.forget();

    let login_listener = Closure::<dyn FnMut(web_sys::Event)>::new(move |_e: web_sys::Event| {
        spawn_local(async move {
            refresh_local_identity(local_identity).await;
        });
    });
    window
        .add_event_listener_with_callback(
            "os:login-changed",
            login_listener.as_ref().unchecked_ref(),
        )
        .unwrap();
    login_listener.forget();

    let cloud_changed =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
            if let Ok(parsed) = serde_wasm_bindgen::from_value::<serde_json::Value>(e.detail()) {
                apply_cloud_status_json(cloud_auth, &parsed, None);
            }
        });
    window
        .add_event_listener_with_callback(
            "os:cloud-changed",
            cloud_changed.as_ref().unchecked_ref(),
        )
        .unwrap();
    cloud_changed.forget();

    let prefs_listener =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
            if let Ok(parsed) = serde_wasm_bindgen::from_value::<serde_json::Value>(e.detail()) {
                if parsed.get("source").and_then(|v| v.as_str()) == Some("chrome") {
                    return;
                }
                if let Some(t) = parsed.get("theme").and_then(|v| v.as_str()) {
                    let resolved = if t == "dark" { "dark" } else { "light" };
                    if theme.get_untracked() != resolved {
                        theme.set(resolved.to_owned());
                    }
                }
                if let Some(auto) = parsed.get("dock_autohide").and_then(|v| v.as_bool()) {
                    if dock_autohide_pref.get_untracked() != auto {
                        dock_autohide_pref.set(auto);
                    }
                }
            }
        });
    let _ = window.add_event_listener_with_callback(
        "os:preferences-changed",
        prefs_listener.as_ref().unchecked_ref(),
    );
    prefs_listener.forget();

    let dock_auto_active = move || {
        !desktop.shell_state.with(|s| s.compact)
            && (is_fullscreen.get() || has_filled_window.get() || dock_autohide_pref.get())
    };
    let dock_hidden = move || {
        if !dock_auto_active() {
            return false;
        }
        let launcher_open = desktop.shell_state.with(|s| s.launcher_open);
        !(launcher_open || dock_hovered.get())
    };
    let settings_pill_label = move || {
        let local_info = local_identity.get();
        let cloud_info = cloud_auth.get();
        let cloud_name = cloud_info
            .signed_in
            .then_some(cloud_info.cloud_user)
            .flatten();
        cloud_panel::format_pill_label(&local_info.username, cloud_name.as_deref())
    };
    let settings_open = move || {
        desktop.shell_state.with(|s| {
            s.dock
                .iter()
                .any(|d| d.app_id == "settings" && d.open)
        })
    };
    let settings_focused = move || {
        desktop.shell_state.with(|s| {
            s.dock
                .iter()
                .any(|d| d.app_id == "settings" && d.focused)
        })
    };
    let settings_launching = move || {
        desktop
            .launching_apps
            .with(|apps| apps.iter().any(|a| a == "settings"))
    };
    let desktop_busy = move || desktop.loading_label.with(|l| l.is_some());
    let active_app_name = move || {
        if let Some(app) = desktop.focused.get() {
            match app {
                "terminal" => "Terminal".to_owned(),
                "files" => "Files".to_owned(),
                "mounts" => "Mounts".to_owned(),
                "settings" => "Settings".to_owned(),
                "editor" => "Editor".to_owned(),
                "preview" => "Preview".to_owned(),
                _ => app.to_owned(),
            }
        } else {
            desktop
                .shell_state
                .with(|s| s.focused_title.clone().unwrap_or_else(|| "Desktop".into()))
        }
    };

    view! {
        <main
            class="desktop"
            class:is-fullscreen=move || is_fullscreen.get()
            class:dock-autohide-active=dock_auto_active
            class:desktop-busy=desktop_busy
        >
            <header class="topbar">
                <div class="topbar-left">
                    <div class="wordmark">
                        <span class="signal"></span>
                        <span class="brand-name">{title}</span>
                        <span class="subtitle">{subtitle}</span>
                    </div>
                    <span class="topbar-sep" aria-hidden="true"></span>
                    <span class="topbar-active-app">{active_app_name}</span>
                    <Show when=move || desktop.loading_label.with(|l| l.is_some())>
                        <span class="topbar-loading-pill" role="status" aria-live="polite">
                            <span class="loading-spinner" aria-hidden="true"></span>
                            <span class="topbar-loading-text">
                                {move || desktop.loading_label.get().unwrap_or_default()}
                            </span>
                        </span>
                    </Show>
                </div>

                <div class="topbar-center">
                    <div
                        class="topbar-menu-wrap"
                        on:keydown=move |e: web_sys::KeyboardEvent| {
                            if e.key() == "Escape" {
                                nc_open.set(false);
                            }
                        }
                        on:focusout=move |e: web_sys::FocusEvent| {
                            let inside = e
                                .current_target()
                                .and_then(|n| n.dyn_into::<web_sys::Node>().ok())
                                .zip(e.related_target().and_then(|n| n.dyn_into::<web_sys::Node>().ok()))
                                .is_some_and(|(wrap, target)| wrap.contains(Some(&target)));
                            if !inside {
                                nc_open.set(false);
                            }
                        }
                    >
                        <button
                            type="button"
                            class="topbar-btn topbar-clock-btn"
                            class:active=move || nc_open.get()
                            aria-label="Notification Center"
                            title="Notification Center"
                            aria-haspopup="dialog"
                            aria-expanded=move || nc_open.get().to_string()
                            on:click=move |_| {
                                let next = !nc_open.get_untracked();
                                cc_open.set(false);
                                nc_open.set(next);
                                if next {
                                    unread_notifs.set(0);
                                }
                            }
                        >
                            <Show when=move || { unread_notifs.get() > 0 }>
                                <span class="topbar-notif-dot" aria-hidden="true"></span>
                            </Show>
                            <span class="topbar-clock">{move || clock_short.get()}</span>
                        </button>

                        <Show when=move || nc_open.get()>
                            <section
                                class="nc-popover glass-surface"
                                role="dialog"
                                tabindex="-1"
                                aria-label="Notification Center"
                            >
                                <div class="nc-clock-hero">
                                    <div class="nc-time">{move || clock_time.get()}</div>
                                    <div class="nc-date">{move || clock_long.get()}</div>
                                </div>

                                <div class="nc-header">
                                    <strong>"Notifications"</strong>
                                    <Show when=move || !notifications.with(Vec::is_empty)>
                                        <button
                                            type="button"
                                            class="nc-clear-btn"
                                            on:click=move |_| {
                                                notifications.set(Vec::new());
                                                unread_notifs.set(0);
                                            }
                                        >
                                            "Clear all"
                                        </button>
                                    </Show>
                                </div>

                                <Show
                                    when=move || !notifications.with(Vec::is_empty)
                                    fallback=move || view! {
                                        <p class="nc-empty">"No notifications"</p>
                                    }
                                >
                                    <ul class="nc-list">
                                        {move || {
                                            notifications.get().into_iter().map(|item| {
                                                view! {
                                                    <li class="nc-item">
                                                        <div class="nc-item-head">
                                                            <strong>{item.title}</strong>
                                                            <span>{item.time}</span>
                                                        </div>
                                                        <p>{item.body}</p>
                                                    </li>
                                                }
                                            }).collect_view()
                                        }}
                                    </ul>
                                </Show>
                            </section>
                        </Show>
                    </div>
                </div>

                <div class="topbar-right">
                    <Show when=move || cloud_auth.get().signed_in>
                        <button
                            type="button"
                            class="topbar-cloud-badge"
                            title="Cloud connected — open Settings"
                            on:click=move |_| desktop::open_settings("accounts")
                        >
                            <span class="topbar-cloud-dot" aria-hidden="true"></span>
                            <span>{move || cloud_auth.get().cloud_user.unwrap_or_else(|| "Cloud".into())}</span>
                        </button>
                    </Show>

                    <button
                        type="button"
                        class="topbar-btn"
                        aria-label=move || if is_fullscreen.get() { "Exit fullscreen" } else { "Enter fullscreen" }
                        title=move || if is_fullscreen.get() { "Exit fullscreen" } else { "Enter fullscreen" }
                        aria-pressed=move || is_fullscreen.get().to_string()
                        on:click=move |_| toggle_desktop_fullscreen()
                    >
                        <svg class="topbar-svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">
                            {move || if is_fullscreen.get() {
                                view! {
                                    <path d="M8 3v5H3M12 3v5h5M8 17v-5H3M12 17v-5h5"/>
                                }.into_any()
                            } else {
                                view! {
                                    <path d="M3 8V3h5M17 8V3h-5M3 12v5h5M17 12v5h-5"/>
                                }.into_any()
                            }}
                        </svg>
                    </button>

                    <div
                        class="topbar-menu-wrap"
                        on:keydown=move |e: web_sys::KeyboardEvent| {
                            if e.key() == "Escape" {
                                cc_open.set(false);
                            }
                        }
                        on:focusout=move |e: web_sys::FocusEvent| {
                            let inside = e
                                .current_target()
                                .and_then(|n| n.dyn_into::<web_sys::Node>().ok())
                                .zip(e.related_target().and_then(|n| n.dyn_into::<web_sys::Node>().ok()))
                                .is_some_and(|(wrap, target)| wrap.contains(Some(&target)));
                            if !inside {
                                cc_open.set(false);
                            }
                        }
                    >
                        <button
                            type="button"
                            class="topbar-btn topbar-qs-btn"
                            class:active=move || cc_open.get()
                            aria-label="Control Center"
                            title="Quick Settings & Control Center"
                            aria-haspopup="dialog"
                            aria-expanded=move || cc_open.get().to_string()
                            on:click=move |_| {
                                let next = !cc_open.get_untracked();
                                nc_open.set(false);
                                cc_open.set(next);
                            }
                        >
                            <span class="topbar-theme-glyph" aria-hidden="true">
                                {move || if theme.get() == "dark" {
                                    view! {
                                        <svg class="topbar-svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
                                            <path d="M16.5 11.8A6.8 6.8 0 0 1 8.2 3.5a6.8 6.8 0 1 0 8.3 8.3Z"/>
                                        </svg>
                                    }.into_any()
                                } else {
                                    view! {
                                        <svg class="topbar-svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round">
                                            <circle cx="10" cy="10" r="3.4"/>
                                            <path d="M10 2.6v1.6M10 15.8v1.6M2.6 10h1.6M15.8 10h1.6M4.8 4.8l1.1 1.1M14.1 14.1l1.1 1.1M15.2 4.8l-1.1 1.1M5.9 14.1l-1.1 1.1"/>
                                        </svg>
                                    }.into_any()
                                }}
                            </span>
                            <svg class="topbar-svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
                                <rect x="2.5" y="4" width="15" height="5" rx="2.5"/>
                                <circle cx="14.5" cy="6.5" r="1.5" fill="currentColor" stroke="none"/>
                                <rect x="2.5" y="11" width="15" height="5" rx="2.5"/>
                                <circle cx="5.5" cy="13.5" r="1.5" fill="currentColor" stroke="none"/>
                            </svg>
                        </button>

                        <Show when=move || cc_open.get()>
                            <section
                                class="cc-popover glass-surface"
                                role="dialog"
                                tabindex="-1"
                                aria-label="Control Center"
                            >
                                <div class="cc-card">
                                    <span class="cc-label">"Appearance"</span>
                                    <div class="cc-segmented" role="group" aria-label="Theme">
                                        <button
                                            type="button"
                                            class="cc-seg-btn"
                                            class:active=move || theme.get() == "light"
                                            aria-pressed=move || (theme.get() == "light").to_string()
                                            on:click=move |_| set_theme("light")
                                        >
                                            <svg class="topbar-svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                                <circle cx="10" cy="10" r="3.4"/>
                                                <path d="M10 2.6v1.6M10 15.8v1.6M2.6 10h1.6M15.8 10h1.6M4.8 4.8l1.1 1.1M14.1 14.1l1.1 1.1M15.2 4.8l-1.1 1.1M5.9 14.1l-1.1 1.1"/>
                                            </svg>
                                            " Light"
                                        </button>
                                        <button
                                            type="button"
                                            class="cc-seg-btn"
                                            class:active=move || theme.get() == "dark"
                                            aria-pressed=move || (theme.get() == "dark").to_string()
                                            on:click=move |_| set_theme("dark")
                                        >
                                            <svg class="topbar-svg" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                                                <path d="M16.5 11.8A6.8 6.8 0 0 1 8.2 3.5a6.8 6.8 0 1 0 8.3 8.3Z"/>
                                            </svg>
                                            " Dark"
                                        </button>
                                    </div>
                                </div>

                                <div class="cc-grid">
                                    <button
                                        type="button"
                                        class="cc-tile"
                                        class:active=move || is_fullscreen.get()
                                        aria-pressed=move || is_fullscreen.get().to_string()
                                        on:click=move |_| toggle_desktop_fullscreen()
                                    >
                                        <span class="cc-tile-title">"Fullscreen"</span>
                                        <span class="cc-tile-sub">
                                            {move || if is_fullscreen.get() { "Active" } else { "Off" }}
                                        </span>
                                    </button>
                                    <button
                                        type="button"
                                        class="cc-tile"
                                        class:active=move || dock_autohide_pref.get()
                                        aria-pressed=move || dock_autohide_pref.get().to_string()
                                        on:click=move |_| {
                                            let next = !dock_autohide_pref.get_untracked();
                                            dock_autohide_pref.set(next);
                                            write_storage(
                                                "os-dock-autohide",
                                                if next { "true" } else { "false" },
                                            );
                                            dispatch_chrome_preferences(&theme.get_untracked(), next);
                                        }
                                    >
                                        <span class="cc-tile-title">"Auto-hide Dock"</span>
                                        <span class="cc-tile-sub">
                                            {move || if dock_autohide_pref.get() { "Always" } else { "Maximized" }}
                                        </span>
                                    </button>
                                </div>

                                <div class="cc-card cc-meta-card">
                                    <div class="cc-meta-row">
                                        <span class="cc-label">"Local user"</span>
                                        <span class="cc-val">
                                            {move || {
                                                let info = local_identity.get();
                                                format!("{} (uid {})", info.username, info.uid)
                                            }}
                                        </span>
                                    </div>
                                    <div class="cc-meta-row">
                                        <span class="cc-label">"Cloud"</span>
                                        <span class="cc-val">
                                            {move || {
                                                let c = cloud_auth.get();
                                                if c.signed_in {
                                                    c.cloud_user.unwrap_or_else(|| "Connected".into())
                                                } else {
                                                    "Signed out".into()
                                                }
                                            }}
                                        </span>
                                    </div>
                                    <div class="cc-quick-actions">
                                        <button
                                            type="button"
                                            class="cc-action-btn"
                                            on:click=move |_| {
                                                cc_open.set(false);
                                                desktop::open_settings("accounts");
                                            }
                                        >
                                            "Settings"
                                        </button>
                                        <button
                                            type="button"
                                            class="cc-action-btn"
                                            on:click=move |_| {
                                                cc_open.set(false);
                                                let _ = local_mounts();
                                            }
                                        >
                                            "Mounts"
                                        </button>
                                        <button
                                            type="button"
                                            class="cc-action-btn"
                                            on:click=move |_| {
                                                cc_open.set(false);
                                                let home = local_identity.with_untracked(|i| i.home.clone());
                                                desktop::open_terminal_tab(&["/usr/bin/su".into()], &home);
                                            }
                                        >
                                            "Switch user"
                                        </button>
                                    </div>
                                </div>
                            </section>
                        </Show>
                    </div>
                </div>
            </header>

            <Show when=move || desktop.graphical_ended.get()>
                <aside class="graphical-ended-banner" role="alert">
                    <span>"Graphical session ended. Background services and your terminal remain running."</span>
                    <div class="graphical-ended-actions">
                        <button type="button" disabled=move || desktop.restarting.get() on:click=move |_| desktop.restart_graphical()>
                            {move || if desktop.restarting.get() { "Restarting…" } else { "Restart graphical session" }}
                        </button>
                        <a href="/shell.html">"Open terminal shell"</a>
                    </div>
                </aside>
            </Show>

            <div class="desktop-area">
                // The wallpaper: luminous Liquid Glass backdrop with brand hero when clear.
                <section class="intro wallpaper">
                    <span class="eyebrow">"OS WORKSPACE"</span>
                    <h1>{heading}</h1>
                    <p>{description}</p>
                </section>
            </div>

            <div
                class="dock-edge-sensor"
                aria-hidden="true"
                class:active=dock_hidden
                on:pointerenter={
                    let cancel = cancel_dock_hide.clone();
                    move |_| {
                        cancel();
                        dock_hovered.set(true);
                    }
                }
                on:pointerleave={
                    let schedule = schedule_dock_hide.clone();
                    move |_| schedule()
                }
            >
                <span class="dock-edge-pill"></span>
            </div>

            <nav
                class="dock glass-surface"
                class:dock-hidden=dock_hidden
                aria-label="Dock"
                on:pointerenter={
                    let cancel = cancel_dock_hide.clone();
                    move |_| {
                        cancel();
                        dock_hovered.set(true);
                    }
                }
                on:pointerleave={
                    let schedule = schedule_dock_hide.clone();
                    move |_| schedule()
                }
            >
              <div class="dock-launcher-group"
                on:keydown=move |event: web_sys::KeyboardEvent| {
                    if event.key() == "Escape" { desktop.close_launcher(); }
                }
                on:focusout=move |event: web_sys::FocusEvent| {
                    let inside = event.current_target().and_then(|node| node.dyn_into::<web_sys::Node>().ok())
                        .zip(event.related_target().and_then(|node| node.dyn_into::<web_sys::Node>().ok()))
                        .is_some_and(|(group, target)| group.contains(Some(&target)));
                    if !inside { desktop.close_launcher(); }
                }>
                <button type="button" class="dock-item dock-launcher" aria-label="Applications" title="Applications"
                    aria-expanded=move || desktop.shell_state.with(|s| s.launcher_open).to_string()
                    on:click=move |_| desktop.toggle_launcher()>
                    <span class="dock-tile dock-tile-launcher" aria-hidden="true">
                        <svg class="dock-svg" viewBox="0 0 24 24" fill="currentColor">
                            <rect x="4" y="4" width="4" height="4" rx="1.2"/>
                            <rect x="10" y="4" width="4" height="4" rx="1.2"/>
                            <rect x="16" y="4" width="4" height="4" rx="1.2"/>
                            <rect x="4" y="10" width="4" height="4" rx="1.2"/>
                            <rect x="10" y="10" width="4" height="4" rx="1.2"/>
                            <rect x="16" y="10" width="4" height="4" rx="1.2"/>
                            <rect x="4" y="16" width="4" height="4" rx="1.2"/>
                            <rect x="10" y="16" width="4" height="4" rx="1.2"/>
                            <rect x="16" y="16" width="4" height="4" rx="1.2"/>
                        </svg>
                    </span>
                    <span class="dock-tooltip" aria-hidden="true">"Applications"</span>
                </button>
                <Show when=move || desktop.shell_state.with(|s| s.launcher_open)>
                    <div class="launcher glass-surface" role="menu" aria-label="Applications">
                        {move || {
                            desktop.shell_state.with(|s| s.launcher_items.clone()).into_iter().map(|item| {
                                let id = item.app_id.clone();
                                let icon_view = dock_svg(&id);
                                view! {
                                    <button type="button" role="menuitem" on:click=move |_| desktop.launch(&id)>
                                        {icon_view}
                                        <div class="launcher-text">
                                            <strong>{item.label}</strong>
                                            <small>{item.description}</small>
                                        </div>
                                    </button>
                                }
                            }).collect_view()
                        }}
                    </div>
                </Show>
              </div>

              <span class="dock-divider" aria-hidden="true"></span>

              {move || {
                  desktop.shell_state.with(|s| s.dock.clone()).into_iter().filter(|entry| entry.app_id != "settings").map(|entry| {
                      let app_id = entry.app_id.clone();
                      let label = entry.label.clone();
                      let aria_label = label.clone();
                      let title = label.clone();
                      let icon_view = dock_svg(&app_id);
                      let open = entry.open;
                      let focused = entry.focused;
                      let sid = entry.surface_id;
                      let is_known = entry.pinned
                          || matches!(app_id.as_str(), "files" | "terminal" | "mounts" | "settings" | "preview" | "editor");
                      let app_id_launch = app_id.clone();
                      let app_id_busy = app_id.clone();
                      let is_launching = move || {
                          desktop
                              .launching_apps
                              .with(|apps| apps.iter().any(|a| a == &app_id_launch))
                      };
                      let is_busy = move || {
                          desktop
                              .launching_apps
                              .with(|apps| apps.iter().any(|a| a == &app_id_busy))
                              .to_string()
                      };
                      view! {
                          <button type="button" class="dock-item" class:dock-open=open class:dock-focused=focused class:dock-launching=is_launching
                              aria-label=aria_label title=title aria-pressed=focused.to_string()
                              aria-busy=is_busy
                              on:click=move |_| {
                                  if is_known {
                                      desktop.toggle(&app_id);
                                  } else if let Some(surface_id) = sid {
                                      desktop.focus_surface(surface_id);
                                  }
                              }>
                              {icon_view}
                              <span class="dock-tooltip" aria-hidden="true">{label.clone()}</span>
                              <span class="dock-label sr-only">{label}</span>
                          </button>
                      }
                  }).collect_view()
              }}

              <span class="dock-divider" aria-hidden="true"></span>

              <button
                  type="button"
                  class="dock-item dock-app-settings cloud-panel-trigger"
                  class:cloud-connected=move || cloud_auth.get().signed_in
                  class:dock-open=settings_open
                  class:dock-focused=settings_focused
                  class:dock-launching=settings_launching
                  aria-label="Settings"
                  title=settings_pill_label
                  aria-pressed=move || settings_focused().to_string()
                  aria-busy=move || settings_launching().to_string()
                  on:click=move |_| {
                      cc_open.set(false);
                      nc_open.set(false);
                      desktop.toggle("settings");
                  }
              >
                  <span class="dock-tile dock-tile-settings" aria-hidden="true">
                      <svg class="dock-svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                          <circle cx="12" cy="12" r="3.2"/>
                          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.08a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.08a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.08a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>
                      </svg>
                      <span class="cloud-indicator" aria-hidden="true"></span>
                  </span>
                  <span class="dock-tooltip" aria-hidden="true">
                      {move || if cloud_auth.get().signed_in {
                          format!("Settings · {}", cloud_auth.get().cloud_user.unwrap_or_else(|| "Cloud".into()))
                      } else {
                          "Settings".into()
                      }}
                  </span>
                  <span class="sr-only cloud-pill-text">{settings_pill_label}</span>
              </button>
            </nav>

            <Show when=move || desktop.greeter_modal.get()>
                <div class="greeter-modal-overlay">
                    <greeter::Greeter in_session=true on_dismiss=Callback::new(move |()| desktop.dismiss_greeter())/>
                </div>
            </Show>
        </main>
    }
}

fn apply_cloud_status_json(
    signal: RwSignal<cloud_panel::CloudAuthState>,
    parsed: &serde_json::Value,
    notice: Option<String>,
) {
    let signed_in = parsed
        .get("signed_in")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cloud_user = parsed
        .get("cloud_user")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let cloud_mount_active = parsed
        .get("cloud_mounted")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let scope = parsed
        .get("scope")
        .and_then(|v| serde_json::from_value::<abi::auth_v2::RemoteScope>(v.clone()).ok())
        .unwrap_or_default();
    signal.set(cloud_panel::CloudAuthState {
        signed_in,
        cloud_user,
        scope,
        cloud_mount_active,
        busy: false,
        error: None,
        notice,
    });
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    let root = web_sys::window()
        .unwrap()
        .document()
        .unwrap()
        .get_element_by_id("app")
        .unwrap();
    if root.has_attribute("data-greeter") {
        root.set_text_content(None);
        leptos::mount::mount_to(root.unchecked_into(), || view! { <greeter::Greeter/> }).forget();
        return;
    }
    if root.has_attribute("data-shell-session") {
        root.set_text_content(None);
        leptos::mount::mount_to(
            root.unchecked_into(),
            || view! { <console::ConsoleWindow local=true/> },
        )
        .forget();
        return;
    }
    if root.has_attribute("data-attached-console") {
        root.set_text_content(None);
        leptos::mount::mount_to(
            root.unchecked_into(),
            || view! { <console::ConsoleWindow/> },
        )
        .forget();
        return;
    }
    uploads::register();
    let root = web_sys::window()
        .unwrap()
        .document()
        .unwrap()
        .get_element_by_id("app")
        .unwrap();
    root.set_text_content(None);
    leptos::mount::mount_to(root.unchecked_into(), App).forget();
    if let Some(desktop) = desktop::desktop() {
        desktop::run(desktop);
    }
}
