//! A PTY screen for attached commands and standalone installed-shell sessions.
use leptos::prelude::*;
use os_core::ansi::screen::Screen;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = osConsole)]
    fn listen(callback: &js_sys::Function);
    #[wasm_bindgen(js_namespace = osConsole)]
    fn send(operation: &str, text: &str);
    #[wasm_bindgen(js_namespace = osConsole)]
    fn detach();
    #[wasm_bindgen(js_namespace = osConsole)]
    fn restart();
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Event {
    Reset,
    Output {
        text: String,
    },
    Size {
        columns: usize,
        rows: usize,
    },
    Mode {
        echo: bool,
    },
    Status {
        text: String,
        live: bool,
        input: bool,
        #[serde(default)]
        stopped: bool,
        #[serde(default = "can_restart")]
        restartable: bool,
    },
}

fn can_restart() -> bool {
    true
}

#[component]
pub fn ConsoleWindow(#[prop(default = false)] local: bool) -> impl IntoView {
    let screen = RwSignal::new(Screen::default());
    let live = RwSignal::new(false);
    let enabled = RwSignal::new(false);
    let stopped = RwSignal::new(false);
    let restartable = RwSignal::new(true);
    let echo = RwSignal::new(true);
    let status = RwSignal::new(String::new());
    let input = NodeRef::<leptos::html::Input>::new();
    let transcript = NodeRef::<leptos::html::Div>::new();
    let following = RwSignal::new(true);
    let callback = Closure::<dyn Fn(JsValue)>::new(move |value| {
        let Ok(event) = serde_wasm_bindgen::from_value::<Event>(value) else {
            return;
        };
        match event {
            Event::Reset => {
                screen.set(Screen::default());
                following.set(true);
                echo.set(true);
            }
            Event::Output { text } => {
                let mut reply = String::new();
                screen.update(|screen| reply = screen.feed(&text));
                if enabled.get_untracked() && !reply.is_empty() {
                    send("reply", &reply);
                }
            }
            Event::Size { columns, rows } => screen.update(|screen| screen.resize(columns, rows)),
            Event::Mode { echo: value } => echo.set(value),
            Event::Status {
                text,
                live: value,
                input: accepts,
                stopped: paused,
                restartable: restart,
            } => {
                restartable.set(restart);
                stopped.set(paused);
                status.set(text);
                live.set(value);
                if enabled.get_untracked() != accepts {
                    enabled.set(accepts);
                }
            }
        }
    });
    // One callback lasts for this window's single component lifetime.
    let callback = StoredValue::new_local(callback);
    Effect::new(move || {
        if input.get().is_some() {
            callback.with_value(|callback| listen(callback.as_ref().unchecked_ref()));
        }
    });
    Effect::new(move || {
        let accepts = enabled.get();
        if let Some(element) = input.get() {
            let _ = element.set_attribute("autocorrect", "off");
            if accepts {
                // Wait for the reactive disabled attribute to clear before
                // giving native keyboard focus to the PTY input.
                request_animation_frame(move || {
                    if enabled.get_untracked()
                        && let Some(element) = input.get_untracked()
                    {
                        let _ = element.blur();
                        let _ = element.focus();
                    }
                });
            }
        }
    });
    Effect::new(move || {
        screen.track();
        if following.get_untracked() {
            request_animation_frame(move || {
                if following.get_untracked()
                    && let Some(element) = transcript.get_untracked()
                {
                    element.set_scroll_top(element.scroll_height());
                }
            });
        }
    });
    let focus = move || {
        if enabled.get_untracked()
            && let Some(element) = input.get_untracked()
        {
            let _ = element.focus();
        }
    };
    view! {
        <main class="console-window">
            <header><strong>{if local { "Shell" } else { "Attached terminal" }}</strong>
                <Show when=move || local>
                    <a href="/" target="_blank" rel="noopener">"Desktop"</a>
                    <a href="/login.html?target=shell" target="_blank" rel="noopener">"Sign in"</a>
                    <button type="button" on:click=move |_| restart() hidden=move || !restartable.get() || live.get()>"Start shell"</button>
                    <button type="button" on:click=move |_| send("resume", "") hidden=move || !stopped.get()>"Resume"</button>
                </Show>
                <button type="button" on:click=move |_| detach() disabled=move || !live.get()>{if local { "End shell" } else { "Disconnect" }}</button>
            </header>
            <p class="console-connection" role="status">{move || status.get()}</p>
            <Show when=move || !local><p class="console-note">"Live output starts here. Keep the original window open."</p></Show>
            <section class="terminal-panel" data-pty="true" data-terminal=local.then_some("session-shell") aria-label=if local { "Shell terminal" } else { "Attached terminal" }>
                <div class="transcript" role="log" aria-live="polite" node_ref=transcript
                    on:scroll=move |_| {
                        if let Some(element) = transcript.get_untracked() { following.set(element.scroll_height() - element.scroll_top() - element.client_height() < 48); }
                    }
                    on:click=move |_| {
                        if !web_sys::window().and_then(|w| w.get_selection().ok().flatten()).is_some_and(|s| !s.is_collapsed()) { focus(); }
                    }>
                    <div class="console-surface">
                        {crate::terminal::view(screen, live)}
                        <form class="command-line" on:submit=move |event| { event.prevent_default(); if enabled.get_untracked() { send("write", "\r"); } }
                            style=move || screen.with(|screen| { let (row, col) = screen.cursor_position(); format!("left:{col}ch;top:{}em", row as f64 * 1.7) })>
                            <input class="command-input" aria-label=if local { "Shell input" } else { "Attached terminal input" } autocomplete="off" autocapitalize="off" spellcheck="false" enterkeyhint="go"
                                type=move || if echo.get() { "text" } else { "password" } disabled=move || !enabled.get() node_ref=input
                                on:input=move |event| {
                                    if event.dyn_ref::<web_sys::InputEvent>().is_some_and(|event| event.is_composing()) { return; }
                                    if enabled.get_untracked() { send("write", &event_target_value(&event)); }
                                    if let Some(element) = input.get_untracked() { element.set_value(""); }
                                }
                                on:keydown=move |event| {
                                    if enabled.get_untracked() && let Some(text) = crate::terminal::key(&event, screen.with_untracked(|screen| screen.application_cursor)) {
                                        event.prevent_default(); send("write", &text);
                                    }
                                }
                                on:paste=move |event: web_sys::ClipboardEvent| {
                                    if enabled.get_untracked() && let Some(text) = event.clipboard_data().and_then(|data| data.get_data("text/plain").ok()) {
                                        event.prevent_default();
                                        let text = if screen.with_untracked(|screen| screen.bracketed_paste) { format!("\x1b[200~{text}\x1b[201~") } else { text };
                                        send("write", &text);
                                    }
                                }/>
                        </form>
                    </div>
                </div>
                <div class="touch-keys" aria-label="Terminal keys" on:pointerdown=move |event| event.prevent_default()>
                    <button type="button" disabled=move || !enabled.get() on:click=move |_| { focus(); send("write", "\t"); }>"Tab"</button>
                    <button type="button" disabled=move || !enabled.get() on:click=move |_| { focus(); send("write", "\x1b[A"); }>"↑"</button>
                    <button type="button" disabled=move || !enabled.get() on:click=move |_| { focus(); send("write", "\x1b[B"); }>"↓"</button>
                    <button type="button" disabled=move || !enabled.get() on:click=move |_| { focus(); send("write", "\x04"); }>"^D"</button>
                    <button type="button" disabled=move || !enabled.get() on:click=move |_| { focus(); send("write", "\x03"); }>"^C"</button>
                </div>
            </section>
        </main>
    }
}
