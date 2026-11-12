//! Browser-hosted sign-in and session selection. The authority owns authentication.
use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::prelude::*;
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

#[component]
pub fn Greeter() -> impl IntoView {
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
                Err(value) => error.set(crate::shell::js_message(value)),
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
                    error.set(crate::shell::js_message(value));
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
                error.set(crate::shell::js_message(value));
            }
            busy.set(false);
        });
    };
    view! {
        <main class="greeter">
            <section class="greeter-card" aria-labelledby="greeter-title">
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
}
