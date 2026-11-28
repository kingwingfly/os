//! Browser-hosted sign-in and session selection. The authority owns authentication.
use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::{JsCast, prelude::*};
use wasm_bindgen_futures::{JsFuture, spawn_local};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = osGreeter)]
    fn target() -> String;
    #[wasm_bindgen(js_namespace = osGreeter)]
    fn identity() -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osGreeter)]
    fn enter(mode: &str, target: &str, username: &str, password: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = osGreeter)]
    fn lifecycle(operation: &str) -> js_sys::Promise;
}
#[derive(Deserialize)]
struct Identity {
    user: String,
    signed_in: bool,
    can_end: bool,
    root: bool,
}

#[derive(Deserialize)]
struct LockStatus {
    username: String,
    #[allow(dead_code)]
    uid: u32,
    has_password: bool,
}

fn focus_lock_password_input() {
    if let Some(win) = web_sys::window() {
        let cb = wasm_bindgen::closure::Closure::once(move || {
            if let Some(el) = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| d.get_element_by_id("lock-password"))
                .and_then(|e| e.dyn_into::<web_sys::HtmlElement>().ok())
            {
                let _ = el.focus();
            }
        });
        let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
            cb.as_ref().unchecked_ref(),
            0,
        );
        cb.forget();
    }
}

#[component]
pub fn Greeter(
    #[prop(optional)] in_session: bool,
    #[prop(optional)] on_dismiss: Option<Callback<()>>,
    #[prop(optional)] clock_time: Option<RwSignal<String>>,
    #[prop(optional)] clock_date: Option<RwSignal<String>>,
    #[prop(optional)] fallback_user: Option<Signal<String>>,
) -> impl IntoView {
    if in_session {
        let initial_user = fallback_user
            .map(|sig| sig.get_untracked())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "user".into());
        let username = RwSignal::new(initial_user);
        let has_password = RwSignal::new(false);
        let ready = RwSignal::new(false);
        let password = RwSignal::new(String::new());
        let busy = RwSignal::new(false);
        let error = RwSignal::new(String::new());

        spawn_local(async move {
            if let Ok(val) = JsFuture::from(crate::desktop::bridge_greeter_status()).await
                && let Ok(status) = serde_wasm_bindgen::from_value::<LockStatus>(val)
            {
                if !status.username.is_empty() {
                    username.set(status.username);
                }
                has_password.set(status.has_password);
                if status.has_password {
                    focus_lock_password_input();
                }
            }
            ready.set(true);
        });

        let unlock = move || {
            if busy.get_untracked() {
                return;
            }
            busy.set(true);
            error.set(String::new());
            let secret = password.get_untracked();
            password.set(String::new());
            spawn_local(async move {
                match JsFuture::from(crate::desktop::bridge_stop_greeter(&secret)).await {
                    Ok(_) => {
                        if let Some(cb) = on_dismiss {
                            cb.run(());
                        }
                    }
                    Err(err) => {
                        let errno = js_sys::Reflect::get(&err, &JsValue::from_str("errno"))
                            .ok()
                            .and_then(|v| v.as_string());
                        if errno.as_deref() == Some("EACCES") {
                            error.set("Incorrect password. Please try again.".into());
                        } else {
                            let msg = crate::js_message(err);
                            if msg == "Operation failed" && has_password.get_untracked() {
                                error.set("Incorrect password. Please try again.".into());
                            } else {
                                error.set(msg);
                            }
                        }
                        if has_password.get_untracked() {
                            focus_lock_password_input();
                        }
                    }
                }
                busy.set(false);
            });
        };

        let avatar_initial = move || {
            username
                .get()
                .chars()
                .next()
                .map(|c| c.to_ascii_uppercase().to_string())
                .unwrap_or_else(|| "U".into())
        };
        let hero_time = move || clock_time.map(|s| s.get()).unwrap_or_default();
        let hero_date = move || clock_date.map(|s| s.get()).unwrap_or_default();

        return view! {
            <div class="greeter greeter-lock-shell">
                <Show when=move || !hero_time().is_empty()>
                    <div class="greeter-lock-hero" aria-hidden="true">
                        <div class="greeter-lock-date">{hero_date}</div>
                        <div class="greeter-lock-time">{hero_time}</div>
                    </div>
                </Show>
                <section
                    class="greeter-card greeter-lock-card"
                    role="dialog"
                    aria-modal="true"
                    data-role="greeter"
                    aria-labelledby="greeter-title"
                >
                    <div class="greeter-lock-avatar" aria-hidden="true">{avatar_initial}</div>
                    <h1 id="greeter-title" class="greeter-lock-user">{move || username.get()}</h1>
                    <p class="greeter-lock-subtitle">
                        <svg class="greeter-lock-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                            <rect x="3.5" y="7" width="9" height="6.5" rx="1.8"/>
                            <path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>
                        </svg>
                        <span>"Session Locked"</span>
                    </p>
                    <Show
                        when=move || has_password.get()
                        fallback=move || view! {
                            <button
                                type="button"
                                class="primary greeter-unlock-btn"
                                disabled=move || busy.get() || !ready.get()
                                on:click=move |_| unlock()
                            >
                                {move || if busy.get() { "Unlocking…" } else { "Unlock" }}
                            </button>
                            <Show when=move || ready.get()>
                                <p class="greeter-lock-hint">"No local password set. Run sudo passwd user in Terminal to require one."</p>
                            </Show>
                        }
                    >
                        <form class="greeter-lock-form" on:submit=move |event| {
                            event.prevent_default();
                            unlock();
                        }>
                            <label class="sr-only" for="lock-password">"Password"</label>
                            <input
                                id="lock-password"
                                name="password"
                                type="password"
                                autocomplete="current-password"
                                placeholder="Enter password"
                                required
                                disabled=move || busy.get()
                                prop:value=move || password.get()
                                on:input=move |event| password.set(event_target_value(&event))
                            />
                            <button type="submit" class="primary greeter-unlock-btn" disabled=move || busy.get()>
                                {move || if busy.get() { "Unlocking…" } else { "Unlock" }}
                            </button>
                        </form>
                    </Show>
                    <p class="greeter-error" role="alert">{move || error.get()}</p>
                    <div class="greeter-lock-footer">
                        <a href="/login.html">"Switch session…"</a>
                    </div>
                </section>
            </div>
        }.into_any();
    }
    let selected = RwSignal::new(target());
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let current = RwSignal::new(String::new());
    let signed_in = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let known = RwSignal::new(false);
    let can_end = RwSignal::new(false);
    let root = RwSignal::new(false);
    let notice = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let refresh = move || {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        spawn_local(async move {
            match JsFuture::from(identity()).await {
                Ok(value) => match serde_wasm_bindgen::from_value::<Identity>(value) {
                    Ok(who) => {
                        current.set(who.user);
                        signed_in.set(who.signed_in);
                        can_end.set(who.can_end);
                        root.set(who.root);
                        known.set(true);
                    }
                    Err(_) => error.set("The account response could not be read.".into()),
                },
                Err(value) => error.set(crate::js_message(value)),
            }
            busy.set(false);
        });
    };
    refresh();
    let stop = move |operation: &'static str| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        notice.set(
            if operation == "end" {
                "Ending this session…"
            } else {
                "Restarting this Machine…"
            }
            .into(),
        );
        spawn_local(async move {
            match JsFuture::from(lifecycle(operation)).await {
                Ok(_) => notice.set(
                    if operation == "end" {
                        "Session ended. Choose a session to start again."
                    } else {
                        "Machine restarted. Files and account settings are preserved."
                    }
                    .into(),
                ),
                Err(value) => {
                    notice.set(String::new());
                    error.set(crate::js_message(value));
                }
            }
            busy.set(false);
            // Keep failure feedback visible; refresh after successful completion only.
            if error.get_untracked().is_empty() {
                refresh();
            }
        });
    };
    let submit = move |mode: &'static str| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error.set(String::new());
        let secret = password.get_untracked();
        password.set(String::new());
        let promise = enter(
            mode,
            &selected.get_untracked(),
            &username.get_untracked(),
            &secret,
        );
        spawn_local(async move {
            if let Err(value) = JsFuture::from(promise).await {
                error.set(crate::js_message(value));
            }
            busy.set(false);
        });
    };
    view! {
        <main class="greeter">
            <section class="greeter-card" role="dialog" aria-modal="true" data-role="greeter" aria-labelledby="greeter-title">
                <h1 id="greeter-title">"OS"</h1>
                <p>"Choose your account and session."</p>
                <fieldset disabled=move || busy.get()>
                    <legend>"Session"</legend>
                    <label><input type="radio" name="session-target" value="desktop" prop:checked=move || selected.get() == "desktop" on:change=move |_| selected.set("desktop".into())/>"Desktop"</label>
                    <label><input type="radio" name="session-target" value="shell" prop:checked=move || selected.get() == "shell" on:change=move |_| selected.set("shell".into())/>"Shell"</label>
                </fieldset>
                <Show when=move || known.get()>
                    <p class="greeter-account">{move || if signed_in.get() { format!("Signed in as {}", current.get()) } else { "Guest session".into() }}</p>
                    <button type="button" disabled=move || busy.get() on:click=move |_| submit("current")>
                        {move || if signed_in.get() { format!("Continue as {}", current.get()) } else { "Continue as guest".into() }}
                    </button>
                    <Show when=move || signed_in.get()>
                        <button type="button" disabled=move || busy.get() on:click=move |_| submit("guest")>"Sign out and continue as guest"</button>
                    </Show>
                </Show>
                <Show when=move || !known.get() && !busy.get()>
                    <button type="button" on:click=move |_| refresh()>"Retry connection"</button>
                </Show>
                <form on:submit=move |event| { event.prevent_default(); submit("login"); }>
                    <h2>"Sign in"</h2>
                    <label for="login-user">"Username"</label>
                    <input id="login-user" name="username" autocomplete="username" required maxlength="64" disabled=move || busy.get()
                        prop:value=move || username.get() on:input=move |event| username.set(event_target_value(&event))/>
                    <label for="login-password">"Password"</label>
                    <input id="login-password" name="password" type="password" autocomplete="current-password" required disabled=move || busy.get()
                        prop:value=move || password.get() on:input=move |event| password.set(event_target_value(&event))/>
                    <button type="submit" class="primary" disabled=move || busy.get()>"Sign in and start"</button>
                </form>
                <p class="greeter-error" role="alert">{move || error.get()}</p>
                <p role="status">{move || notice.get()}</p>
                <Show when=move || can_end.get() || root.get()>
                    <details><summary>"Session controls"</summary>
                        <p>"End session stops its commands in every window. Restart Machine stops all browser workloads in this Machine. Files are preserved."</p>
                        <Show when=move || can_end.get()><button type="button" disabled=move || busy.get() on:click=move |_| stop("end")>"End session"</button></Show>
                        <Show when=move || root.get()><button type="button" disabled=move || busy.get() on:click=move |_| stop("reboot")>"Restart Machine"</button></Show>
                    </details>
                </Show>
                <Show when=move || known.get() && !error.get().is_empty()>
                    <button type="button" disabled=move || busy.get() on:click=move |_| refresh()>"Refresh account"</button>
                </Show>
            </section>
        </main>
    }
    .into_any()
}
