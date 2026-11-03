//! The Files app (owner's request, 2026-10-30: "the file explorer no longer follows terminal's
//! pwd, and file explorer operations no longer become a command in terminal"): a directory of
//! its own, which it lists, goes into and out of, and opens files of in the preview, and which
//! uploads go into, through system calls, as a file manager does, apart from any shell. Its
//! notices and uploads' progress show in it; the terminal hears nothing of it.
use std::cell::Cell;

use leptos::prelude::*;
use terminal_worker_core::{Entry, resolve};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};

use crate::shell::{Account, js_message};

/// Where its directory is kept, for this browser tab, across reloads.
const SAVED: &str = "terminal-files";

#[derive(Clone, Copy)]
pub struct Files {
    pub cwd: RwSignal<String>,
    pub entries: RwSignal<Vec<Entry>>,
    /// Why its directory cannot be listed, if it cannot.
    pub error: RwSignal<String>,
    /// What it says of the last thing done in it: a refusal, or an error.
    pub notice: RwSignal<String>,
    /// What an upload into it says as it goes, and when it is done.
    pub progress: RwSignal<String>,
    pub uploading: RwSignal<bool>,
    /// The location being typed, while it is.
    pub typed: RwSignal<Option<String>>,
    account: Account,
    /// Which listing was asked for last: one answered after it is old news.
    asked: StoredValue<u64>,
}

thread_local! {
    static FILES: Cell<Option<Files>> = const { Cell::new(None) };
}

/// The Files app, once made.
pub fn files() -> Option<Files> {
    FILES.with(Cell::get)
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.session_storage().ok().flatten()
}

impl Files {
    /// The Files app, in the directory it was in, or at `start`.
    pub fn new(account: Account, start: String) -> Self {
        let cwd = storage()
            .and_then(|s| s.get_item(SAVED).ok().flatten())
            .unwrap_or(start);
        let files = Self {
            cwd: RwSignal::new(cwd),
            entries: RwSignal::new(Vec::new()),
            error: RwSignal::new(String::new()),
            notice: RwSignal::new(String::new()),
            progress: RwSignal::new(String::new()),
            uploading: RwSignal::new(false),
            typed: RwSignal::new(None),
            account,
            asked: StoredValue::new(0),
        };
        FILES.with(|cell| cell.set(Some(files)));
        files
    }

    /// Go into the directory `path`, if the account may, and list it.
    pub fn go(self, path: String) {
        spawn_local(async move {
            if let Err(error) = crate::enterable(&path).await {
                self.notice.set(format!("{path}: {error}"));
                return;
            }
            self.notice.set(String::new());
            self.show(path).await;
        });
    }
    /// List its directory again, as it is now.
    pub fn refresh(self) {
        spawn_local(async move { self.show(self.cwd.get_untracked()).await });
    }
    /// Show the directory `path`, listed; a listing asked for later wins.
    async fn show(self, path: String) {
        let asked = self.asked.get_value() + 1;
        self.asked.set_value(asked);
        let listed = crate::listing(&path).await;
        if self.asked.get_value() != asked {
            return;
        }
        if let Some(storage) = storage() {
            let _ = storage.set_item(SAVED, &path);
        }
        self.cwd.set(path);
        match listed {
            Ok(entries) => {
                self.entries.set(entries);
                self.error.set(String::new());
            }
            Err(error) => {
                self.entries.set(Vec::new());
                self.error.set(error);
            }
        }
    }
    /// The directory above its own.
    pub fn up(self) {
        let cwd = self.cwd.get_untracked();
        self.go(terminal_worker_core::parent(&cwd).to_string());
    }
    /// Go to the location typed: a path, from its directory, or from the account's home (~).
    pub fn locate(self, typed: &str) {
        self.typed.set(None);
        let home = self.account.home.get_untracked();
        let expanded = match typed.trim() {
            "" => return,
            "~" => home,
            value => match value.strip_prefix("~/") {
                Some(rest) => format!("{home}/{rest}"),
                None => value.to_string(),
            },
        };
        match resolve(&self.cwd.get_untracked(), &expanded) {
            Ok(path) => self.go(path),
            Err(error) => self.notice.set(error),
        }
    }
    /// What a click on `entry` does: a directory opens in it, a file in the preview; a link,
    /// what it leads to, if anything.
    pub fn activate(self, entry: &Entry) {
        if entry.directory {
            return self.go(entry.path.clone());
        }
        let (path, name) = (entry.path.clone(), entry.name.clone());
        spawn_local(async move {
            match crate::stat(&path).await {
                Err(error) => return self.notice.set(format!("{name}: {error}")),
                Ok(stat) if stat.is_dir() => return self.go(path),
                Ok(_) => {}
            }
            let opened =
                JsFuture::from(crate::open_file(&path, terminal_worker_core::kind(&path))).await;
            match opened {
                Ok(_) => self.notice.set(String::new()),
                Err(error) => self.notice.set(js_message(error)),
            }
        });
    }

    /// Upload into its directory what the chooser gives, opened now, while the tap or click
    /// that asked is fresh (phones refuse it later).
    pub fn choose(self) {
        if self.busy() {
            return;
        }
        self.upload(crate::choose_files());
    }
    /// Upload `files`, dropped on it, into its directory.
    pub fn dropped(self, files: JsValue) {
        if self.busy() {
            return;
        }
        self.upload(js_sys::Promise::resolve(&files));
    }
    fn busy(self) -> bool {
        let busy = self.uploading.get_untracked();
        if busy {
            self.notice
                .set("An upload into Files is going on; wait for it, or cancel it".into());
        }
        busy
    }
    fn upload(self, chosen: js_sys::Promise) {
        let path = self.cwd.get_untracked();
        self.uploading.set(true);
        spawn_local(async move {
            let files = JsFuture::from(chosen).await.unwrap_or(JsValue::NULL);
            if js_sys::Array::from(&files).length() == 0 {
                self.uploading.set(false);
                return;
            }
            self.notice.set(String::new());
            self.progress.set("↑ starting".into());
            let progress =
                Closure::<dyn Fn(String)>::new(move |text: String| self.progress.set(text));
            let result = JsFuture::from(crate::upload_files(
                &files,
                &path,
                progress.as_ref().unchecked_ref(),
            ))
            .await;
            drop(progress);
            self.uploading.set(false);
            match result {
                Ok(results) => {
                    let lines: Vec<String> = results
                        .dyn_into::<js_sys::Array>()
                        .map(|a| a.iter().filter_map(|r| r.as_string()).collect())
                        .unwrap_or_default();
                    self.progress.set(lines.join("\n"));
                }
                Err(error) => self.progress.set(format!("✕ {}", js_message(error))),
            }
            self.refresh();
        });
    }
    /// Stop the upload going on, keeping nothing of what was not done.
    pub fn cancel(self) {
        let _ = crate::cancel_uploads();
    }
}

/// The Files app's window content: its location, its directory listed, what it says.
pub fn view(files: Files) -> impl IntoView {
    let location = move || files.typed.get().unwrap_or_else(|| files.cwd.get());
    view! {
        <section class="file-panel" aria-label="File manager">
        <div class="directory-bar">
            <input class="location" aria-label="Location" autocomplete="off" spellcheck="false" autocapitalize="off" enterkeyhint="go"
                prop:value=location
                on:input=move |e| files.typed.set(Some(event_target_value(&e)))
                on:keydown=move |e| match e.key().as_str() {
                    "Enter" => { e.prevent_default(); files.locate(&event_target_value(&e)); }
                    "Escape" => { e.prevent_default(); files.typed.set(None); }
                    _ => {}
                }
                on:blur=move |_| files.typed.set(None)/>
            <button on:click=move |_| files.choose() disabled=move || files.uploading.get()>"↑ Upload files"</button>
        </div>
        <p class="file-notice" role="status">{move || files.notice.get()}</p>
        <Show when=move || !files.progress.get().is_empty()>
            <div class="file-progress">
                <pre role="status" aria-label="Upload progress">{move || files.progress.get()}</pre>
                {move || if files.uploading.get() {
                    view! { <button type="button" on:click=move |_| files.cancel()>"Cancel"</button> }.into_any()
                } else {
                    view! { <button type="button" aria-label="Dismiss" on:click=move |_| files.progress.set(String::new())>"×"</button> }.into_any()
                }}
            </div>
        </Show>
        <div class="files" aria-label="Current directory">
            <Show when=move || files.cwd.get() != "/"><button class="file" on:click=move |_| files.up()><span class="file-kind">{crate::file_icon("directory", true)}</span><span>"../"</span></button></Show>
            {move || files.entries.get().into_iter().map(|entry| {
                let size = if entry.directory { String::new() } else { crate::upload_progress(&entry).unwrap_or_else(|| format!("{:.1} KB", entry.size as f64 / 1000.0)) };
                let title = format!("{} {}:{}{}", entry.mode_line(), entry.owner, entry.group, entry.link.as_ref().map(|t| format!(" -> {t}")).unwrap_or_default());
                let linked = entry.link.is_some();
                // What the account may not open shows dimmed, and says why when clicked.
                let denied = entry.denied;
                let refusal = denied.then(|| format!("Permission denied: {} is {} {}:{}", entry.name, entry.mode_line().trim_end(), entry.owner, entry.group));
                let title = if denied { format!("{title} · permission denied") } else { title };
                let kind = if entry.directory { "directory".to_string() } else { entry.kind.clone() };
                let icon = crate::file_icon(&entry.kind, entry.directory);
                let name = format!("{}{}", entry.name, if entry.directory { "/" } else { "" });
                let size = if linked { "→".to_string() } else { size };
                view! { <button class="file" class:link=linked class:denied=denied aria-disabled=denied.then_some("true") data-kind=kind title=title on:click=move |_| match &refusal { Some(refusal) => files.notice.set(refusal.clone()), None => files.activate(&entry) }><span class="file-kind">{icon}</span><span class="filename"><span class="filename-text">{name}</span></span><span class="file-size">{size}</span></button> }
            }).collect_view()}
            <p class="directory-error" role="status">{move || files.error.get()}</p>
            <Show when=move || files.entries.get().is_empty() && files.error.get().is_empty()><p class="empty">"This directory is empty. Drop files here, or upload some."</p></Show>
        </div>
        </section>
    }
}
