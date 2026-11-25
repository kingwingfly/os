pub mod cloud_panel;
mod console;
mod desktop;
mod files;
mod greeter;
mod manual;
mod preview;
mod search;
mod sys;
mod terminal;
mod uploads;
mod viewer;
mod workers;

use leptos::prelude::*;
use os_core::{Entry, resolve};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = os)]
    fn config() -> JsValue;
    #[wasm_bindgen(js_namespace = os, js_name = open)]
    pub(crate) fn open_file(path: &str, kind: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = accountCommand)]
    fn account_command(args: JsValue, cwd: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = chooseFiles)]
    fn choose_files() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = localMounts)]
    fn local_mounts() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = uploadFiles)]
    fn upload_files(files: &JsValue, path: &str, progress: &js_sys::Function) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = cancelUploads)]
    fn cancel_uploads() -> bool;
    #[wasm_bindgen(js_namespace = os, js_name = closeConsole)]
    fn close_console(id: &str);
    /// Whether an upload goes on in this page: one at a time.
    #[wasm_bindgen(js_namespace = os)]
    fn uploading() -> bool;
    #[wasm_bindgen(js_namespace = os, js_name = cancelChoosing)]
    fn cancel_choosing() -> bool;
    #[wasm_bindgen(js_namespace = os, js_name = bootStatus)]
    fn boot_status() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = cloudStatus)]
    fn cloud_status() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = cloudSignIn)]
    fn cloud_sign_in(username: &str, password: &str, scope: &JsValue) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = os, js_name = cloudSignOut)]
    fn cloud_sign_out() -> js_sys::Promise;
}

/// Active local OS account shared by the desktop UI.
#[derive(Clone, Copy)]
pub(crate) struct Account {
    pub writable: RwSignal<bool>,
    pub username: RwSignal<String>,
    pub home: RwSignal<String>,
}

/// Resolve a user-typed path from `cwd` with `~` / `~/` expanded against `home`.
pub(crate) fn located(cwd: &str, home: &str, typed: &str) -> Result<String, String> {
    let expanded = if typed == "~" {
        home.to_string()
    } else if let Some(rest) = typed.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        typed.into()
    };
    resolve(cwd, &expanded)
}

pub(crate) fn js_message(error: JsValue) -> String {
    js_sys::Reflect::get(&error, &JsValue::from_str("message"))
        .ok()
        .and_then(|v| v.as_string())
        .or_else(|| error.as_string())
        .unwrap_or_else(|| "Operation failed".into())
}

/// What stat(2) says of `path`, a link at its end followed.
async fn stat(path: &str) -> Result<abi::Stat, abi::Error> {
    userland::sys::stat(&sys::HttpSys::default(), path).await
}

/// Whether `path` is a directory the account may enter (search), as chdir(2) needs.
async fn enterable(path: &str) -> Result<(), abi::Error> {
    if !stat(path).await?.is_dir() {
        return Err(abi::Errno::ENOTDIR.into());
    }
    let access = abi::Call::Access {
        path: path.into(),
        mode: abi::X_OK,
    };
    userland::sys::done(&sys::HttpSys::default(), access).await
}

thread_local! {
    /// Directories the kernel said changed, which Files has yet to list again.
    static CHANGED: std::cell::RefCell<std::collections::BTreeSet<String>> = Default::default();
}

/// Structured directory entries for Files, read through system calls.
async fn listing(path: &str) -> Result<Vec<Entry>, String> {
    userland::entries(&sys::HttpSys::default(), path, path)
        .await
        .map_err(|error| error.to_string())
}

fn file_icon(kind: &str, directory: bool) -> impl IntoView + use<> {
    let (label, path) = if directory {
        ("directory", "M3 7V5h6l2 2h10v13H3Z")
    } else {
        match kind {
            "image" => ("Image", "M3 3h18v18H3ZM3 17l5-6 4 5 3-3 6 6M15 7h.01"),
            "video" => ("Video", "M3 5h14v14H3ZM17 9l4-3v12l-4-3M8 9l4 3-4 3Z"),
            "audio" => (
                "Audio",
                "M9 18V5l11-2v13M9 8l11-2M9 18a3 3 0 1 1-3-3h3M20 16a3 3 0 1 1-3-3h3",
            ),
            "game" => (
                "Game",
                "M6 7h12l3 11-3 1-4-4h-4l-4 4-3-1ZM6 11h6M9 8v6M16 10h.01M18 13h.01",
            ),
            "slides" => ("Slides", "M3 4h18v13H3ZM12 17v4M7 21h10M7 9h10M7 12h6"),
            "markdown" => (
                "Markdown",
                "M3 4h18v16H3ZM6 15V9l3 3 3-3v6M17 9v6l-2-2M17 15l2-2",
            ),
            "pdf" => ("PDF", "M5 3h10l4 4v14H5ZM14 3v5h5M8 12h8M8 16h6"),
            "archive" => (
                "Archive",
                "M4 4h16v4H4ZM5 8v12h14V8M10 12h4M12 3v1M12 9v2M12 13v2",
            ),
            _ => ("Text file", "M5 3h10l4 4v14H5ZM14 3v5h5M8 12h8M8 16h6"),
        }
    };
    view! { <svg class="file-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" role="img" aria-label=label><path d=path/></svg> }
}

/// How much of a file still uploading has arrived, as shown after its name.
fn upload_progress(entry: &Entry) -> Option<String> {
    let uploaded = entry.uploaded?;
    if entry.recording {
        return Some("● recording".into());
    }
    Some(format!(
        "↑ {}%",
        (uploaded * 100).checked_div(entry.size).unwrap_or(100)
    ))
}

pub(crate) fn session_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.session_storage().ok().flatten()
}

async fn refresh_account_state(account: Account) {
    if let Ok(value) = userland::sys::call(&sys::HttpSys::default(), abi::Call::Getcreds).await
        && let Ok(creds) = serde_json::from_value::<abi::Creds>(value)
    {
        account.writable.set(creds.signed_in);
        account.username.set(creds.user);
        account.home.set(creds.home);
    }
}

#[component]
fn App() -> impl IntoView {
    let branding: serde_json::Value =
        serde_wasm_bindgen::from_value(config()).expect("OS branding");
    let title = branding["name"].as_str().unwrap_or("OS").to_owned();
    let subtitle = branding["subtitle"].as_str().unwrap_or("").to_owned();
    let heading = branding["heading"].as_str().unwrap_or("").to_owned();
    let description = branding["description"].as_str().unwrap_or("").to_owned();
    // Supervised compositor & desktop-shell compat bridge (#61 L5b / #62 L6a).
    let desktop = desktop::Desktop::new();
    let account = Account {
        writable: RwSignal::new(true),
        username: RwSignal::new("user".into()),
        home: RwSignal::new("/home/user".into()),
    };
    let local_identity = RwSignal::new(cloud_panel::LocalIdentityInfo::default());
    let cloud_auth = RwSignal::new(cloud_panel::CloudAuthState::default());
    Effect::new(move || {
        let user = account.username.get();
        let home = account.home.get();
        local_identity.update(|info| {
            info.username = user;
            info.home = home;
        });
    });
    spawn_local(async move {
        refresh_account_state(account).await;
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
        if let Ok(val) = JsFuture::from(cloud_status()).await
            && let Ok(parsed) = serde_wasm_bindgen::from_value::<serde_json::Value>(val)
        {
            apply_cloud_status_json(cloud_auth, &parsed, None);
        }
    });

    // A runnable program clicked in Files launches in a Terminal tab via `/usr/bin/terminal`.
    let files = files::Files::new(
        account,
        "/".into(),
        Callback::new(move |path: String| {
            let cwd = Path::new(&path)
                .parent()
                .and_then(|p| p.to_str())
                .filter(|p| !p.is_empty())
                .unwrap_or("/")
                .to_owned();
            desktop::open_terminal_tab(&[path], &cwd);
            Ok(())
        }),
    );
    files.refresh();

    let listener =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |_e: web_sys::CustomEvent| {
            sys::forget(true);
            files.refresh();
            spawn_local(async move {
                refresh_account_state(account).await;
            });
        });
    let window = web_sys::window().unwrap();
    window
        .add_event_listener_with_callback("os:changed", listener.as_ref().unchecked_ref())
        .unwrap();
    listener.forget();

    let mounts_changed =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |_: web_sys::CustomEvent| {
            sys::forget(false);
            files.refresh();
        });
    window
        .add_event_listener_with_callback(
            "os:mounts-changed",
            mounts_changed.as_ref().unchecked_ref(),
        )
        .unwrap();
    mounts_changed.forget();

    let told = Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
        let events: Vec<serde_json::Value> =
            serde_wasm_bindgen::from_value(e.detail()).unwrap_or_default();
        let dirs = sys::heard(&events);
        CHANGED.with(|changed| changed.borrow_mut().extend(dirs));
    });
    window
        .add_event_listener_with_callback("os:inotify", told.as_ref().unchecked_ref())
        .unwrap();
    told.forget();

    let remote = Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |_: web_sys::CustomEvent| {
        let dirs = CHANGED.with(|changed| std::mem::take(&mut *changed.borrow_mut()));
        if dirs.contains(&files.cwd.get_untracked()) {
            files.refresh();
        }
    });
    window
        .add_event_listener_with_callback("os-remote", remote.as_ref().unchecked_ref())
        .unwrap();
    remote.forget();

    let dropped =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
            files.dropped(e.detail());
        });
    window
        .add_event_listener_with_callback("os-files", dropped.as_ref().unchecked_ref())
        .unwrap();
    dropped.forget();

    let dropped_on_files =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
            files.dropped(e.detail());
        });
    window
        .add_event_listener_with_callback(
            "files-dropped",
            dropped_on_files.as_ref().unchecked_ref(),
        )
        .unwrap();
    dropped_on_files.forget();

    // F5 refreshes the focused Files app.
    let keys =
        Closure::<dyn FnMut(web_sys::KeyboardEvent)>::new(move |e: web_sys::KeyboardEvent| {
            if e.key() != "F5"
                || e.alt_key()
                || e.ctrl_key()
                || e.meta_key()
                || e.is_composing()
                || e.default_prevented()
                || desktop.focused.get_untracked() != Some("files")
            {
                return;
            }
            let dialog = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.query_selector("dialog[open]:modal").ok().flatten());
            if dialog.is_some() {
                return;
            }
            e.prevent_default();
            files.reload();
        });
    window
        .add_event_listener_with_callback("keydown", keys.as_ref().unchecked_ref())
        .unwrap();
    keys.forget();

    desktop.set_on_launch(Callback::new(move |app_id: String| match app_id.as_str() {
        "manual" => {
            let args = serde_wasm_bindgen::to_value(&["man"]).unwrap_or(JsValue::NULL);
            let _ = account_command(args, "/");
        }
        "upload" => {
            desktop.show("files");
            files.choose();
        }
        "mounts" => {
            let _ = local_mounts();
        }
        _ => {}
    }));

    let app_icon = |id: &str| match id {
        "terminal" => ">_",
        "files" => "▤",
        "mounts" => "▱",
        "viewer" => "◫",
        "editor" => "✎",
        "manual" => "?",
        "upload" => "↑",
        _ => "□",
    };

    let show_mounts = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| desktop.show("mounts"));
    window
        .add_event_listener_with_callback("os-open-mounts", show_mounts.as_ref().unchecked_ref())
        .unwrap();
    show_mounts.forget();

    let browse =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |event: web_sys::CustomEvent| {
            if let Some(path) = event.detail().as_string() {
                files.go(path);
                desktop.show("files");
            }
        });
    window
        .add_event_listener_with_callback("os-open-directory", browse.as_ref().unchecked_ref())
        .unwrap();
    browse.forget();

    let cloud_changed =
        Closure::<dyn FnMut(web_sys::CustomEvent)>::new(move |e: web_sys::CustomEvent| {
            if let Ok(parsed) = serde_wasm_bindgen::from_value::<serde_json::Value>(e.detail()) {
                apply_cloud_status_json(cloud_auth, &parsed, None);
            }
            sys::forget(false);
            files.refresh();
        });
    window
        .add_event_listener_with_callback(
            "os:cloud-changed",
            cloud_changed.as_ref().unchecked_ref(),
        )
        .unwrap();
    cloud_changed.forget();

    let on_cloud_sign_in = Callback::new(move |req: cloud_panel::CloudSignInRequest| {
        cloud_auth.update(|c| {
            c.busy = true;
            c.error = None;
            c.notice = None;
        });
        spawn_local(async move {
            let scope_js = serde_wasm_bindgen::to_value(&req.scope).unwrap_or(JsValue::NULL);
            match JsFuture::from(cloud_sign_in(&req.username, &req.password, &scope_js)).await {
                Ok(val) => {
                    let parsed = serde_wasm_bindgen::from_value::<serde_json::Value>(val)
                        .unwrap_or_default();
                    apply_cloud_status_json(
                        cloud_auth,
                        &parsed,
                        Some("Cloud credentials active; local OS account unchanged.".into()),
                    );
                }
                Err(err) => {
                    cloud_auth.update(|c| {
                        c.busy = false;
                        c.error = Some(js_message(err));
                    });
                }
            }
        });
    });

    let on_cloud_sign_out = Callback::new(move |()| {
        cloud_auth.update(|c| {
            c.busy = true;
            c.error = None;
            c.notice = None;
        });
        spawn_local(async move {
            match JsFuture::from(cloud_sign_out()).await {
                Ok(val) => {
                    let parsed = serde_wasm_bindgen::from_value::<serde_json::Value>(val)
                        .unwrap_or_default();
                    apply_cloud_status_json(
                        cloud_auth,
                        &parsed,
                        Some("Signed out of Cloud; local processes unaffected.".into()),
                    );
                }
                Err(err) => {
                    cloud_auth.update(|c| {
                        c.busy = false;
                        c.error = Some(js_message(err));
                    });
                }
            }
        });
    });

    let on_switch_local_user = Callback::new(move |()| {
        let home = account.home.get_untracked();
        desktop::open_terminal_tab(&["/usr/bin/su".into()], &home);
    });
    let on_open_boot_profile = Callback::new(move |()| {
        let _ = local_mounts();
    });

    view! {
        <main class="desktop">
            <header class="topbar"><div class="wordmark"><span class="signal"></span>{title}<span class="subtitle">{subtitle}</span></div>
                <cloud_panel::CloudSignInPanel
                    local=local_identity.into()
                    cloud=cloud_auth.into()
                    on_sign_in=on_cloud_sign_in
                    on_sign_out=on_cloud_sign_out
                    on_switch_local_user=on_switch_local_user
                    on_open_boot_profile=on_open_boot_profile
                />
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
            // The wallpaper: what the site says of itself.
            <section class="intro wallpaper"><span class="eyebrow">"PUBLIC ARCHIVE / 001"</span><h1>{heading}</h1><p>{description}</p></section>
            <section class="window" id="window-files" data-window="files" aria-label="Files window" tabindex="-1">
                <div class="window-bar" data-window-bar><span class="window-title">{file_icon("directory", true)}"Files"</span>{desktop::controls("files", "Files")}</div>
                {files::view(files)}
                {desktop::handles()}
            </section>
            <section class="window window-hidden" id="window-mounts" data-window="mounts" aria-label="Mounts window" tabindex="-1">
                <div class="window-bar" data-window-bar><span class="window-title"><span class="window-glyph" aria-hidden="true">"▱"</span>"Mounts"</span>{desktop::controls("mounts", "Mounts")}</div>
                <div id="mount-manager"></div>
                {desktop::handles()}
            </section>
            </div>
            <nav class="dock" aria-label="Dock">
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
                    <span class="dock-icon" aria-hidden="true">"⋮⋮"</span>
                </button>
                <Show when=move || desktop.shell_state.with(|s| s.launcher_open)>
                    <div class="launcher" role="menu" aria-label="Applications">
                        {move || {
                            desktop.shell_state.with(|s| s.launcher_items.clone()).into_iter().map(|item| {
                                let id = item.app_id.clone();
                                let icon = app_icon(&id);
                                view! {
                                    <button type="button" role="menuitem" on:click=move |_| desktop.launch(&id)>
                                        <span aria-hidden="true">{icon}</span>{item.label}
                                    </button>
                                }
                            }).collect_view()
                        }}
                    </div>
                </Show>
              </div>
              {move || {
                  desktop.shell_state.with(|s| s.dock.clone()).into_iter().map(|entry| {
                      let app_id = entry.app_id.clone();
                      let label = entry.label.clone();
                      let aria_label = label.clone();
                      let title = label.clone();
                      let icon = app_icon(&app_id);
                      let open = entry.open;
                      let focused = entry.focused;
                      let sid = entry.surface_id;
                      let is_known = entry.pinned
                          || matches!(app_id.as_str(), "files" | "terminal" | "mounts" | "viewer" | "editor");
                      view! {
                          <button type="button" class="dock-item" class:dock-open=open class:dock-focused=focused
                              aria-label=aria_label title=title aria-pressed=focused.to_string()
                              on:click=move |_| {
                                  if is_known {
                                      desktop.toggle(&app_id);
                                  } else if let Some(surface_id) = sid {
                                      desktop.focus_surface(surface_id);
                                  }
                              }>
                              <span class="dock-icon" aria-hidden="true">{icon}</span><span class="dock-label">{label}</span>
                          </button>
                      }
                  }).collect_view()
              }}
            </nav>
            <Show when=move || desktop.greeter_modal.get()>
                <div class="greeter-modal-overlay">
                    <greeter::Greeter in_session=true on_dismiss=Callback::new(move |()| desktop.dismiss_greeter())/>
                </div>
            </Show>
        </main>
    }
}

use std::path::Path;

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
    viewer::register();
    uploads::register();
    manual::register();
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
