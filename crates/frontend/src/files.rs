//! The Files app (owner's request, 2026-10-30: "the file explorer no longer follows terminal's
//! pwd, and file explorer operations no longer become a command in terminal"): a directory of
//! its own, which it lists, goes into and out of, and opens files of in the preview, and which
//! uploads go into, through system calls, as a file manager does, apart from any shell. Its
//! notices and uploads' progress show in it; the terminal hears nothing of it.
use std::cell::Cell;
use std::collections::HashMap;

use leptos::prelude::*;
use os_core::Entry;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::{JsFuture, spawn_local};

use crate::session_storage as storage;
use crate::shell::{Account, js_message, located};

/// Where its directory is kept, for this browser tab, across reloads: a key of its own, as the
/// Files are no tab of the terminal's (whose state is `os-tabs`).
const SAVED: &str = "os-files";
/// Why an upload is not started: one goes on in this page, or the directory is still opening.
const BUSY: &str = "An upload is going on in this page; wait for it, or cancel it";
const OPENING: &str = "The directory is still opening; upload once it is open";

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
    /// Whether the chooser it opened is still open, which Cancel closes.
    choosing: StoredValue<bool>,
    /// Whether a navigation is going on: an upload waits for the directory it goes into.
    pub navigating: RwSignal<bool>,
    /// The location being typed, while it is.
    pub typed: RwSignal<Option<String>>,
    account: Account,
    /// Which listing was asked for last: one answered after it is old news.
    asked: StoredValue<u64>,
    /// The number of the latest navigation: a refresh that began before one, or while one was
    /// in flight, does not undo it.
    navs: StoredValue<u64>,
    launch: Callback<String, Result<(), String>>,
    scroller: NodeRef<leptos::html::Div>,
    positions: StoredValue<HashMap<String, (i32, i32)>>,
    /// An older animation frame must not restore over a newer listing.
    rendered: StoredValue<u64>,
}

thread_local! {
    static FILES: Cell<Option<Files>> = const { Cell::new(None) };
}

/// The Files app, once made.
pub fn files() -> Option<Files> {
    FILES.with(Cell::get)
}

impl Files {
    fn local_mounts(self) {
        let chosen = crate::local_mounts();
        spawn_local(async move {
            match JsFuture::from(chosen).await {
                Ok(path) => {
                    if let Some(path) = path.as_string() {
                        self.go(path);
                    }
                }
                Err(error) => self.notice.set(js_message(error)),
            }
        });
    }
    /// The Files app, in the directory it was in, or at `start`.
    pub fn new(
        account: Account,
        start: String,
        launch: Callback<String, Result<(), String>>,
    ) -> Self {
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
            choosing: StoredValue::new(false),
            navigating: RwSignal::new(false),
            typed: RwSignal::new(None),
            account,
            asked: StoredValue::new(0),
            navs: StoredValue::new(0),
            launch,
            scroller: NodeRef::new(),
            positions: StoredValue::new(HashMap::new()),
            rendered: StoredValue::new(0),
        };
        FILES.with(|cell| cell.set(Some(files)));
        files
    }

    /// Go into the directory `path`, if the account may, and list it.
    pub fn go(self, path: String) {
        // This navigation is newer than any refresh already in flight.
        let nav = self.navs.get_value() + 1;
        self.navs.set_value(nav);
        self.navigating.set(true);
        spawn_local(async move {
            let latest = move || self.navs.get_value() == nav;
            if let Err(error) = crate::enterable(&path).await {
                if latest() {
                    self.navigating.set(false);
                }
                self.notice.set(format!("{path}: {error}"));
                return;
            }
            self.notice.set(String::new());
            let listed = crate::listing(&path).await;
            // A later navigation wins; a refresh does not.
            if !latest() {
                return;
            }
            self.show(path, listed);
            self.navigating.set(false);
        });
    }
    /// List its directory again, as it is now: unless a navigation began meanwhile, which the
    /// refresh would undo.
    pub fn refresh(self) {
        let navs = self.navs.get_value();
        spawn_local(async move {
            let path = self.cwd.get_untracked();
            let asked = self.asked.get_value() + 1;
            self.asked.set_value(asked);
            let listed = crate::listing(&path).await;
            if self.asked.get_value() != asked
                || self.navs.get_value() != navs
                || self.cwd.get_untracked() != path
            {
                return;
            }
            self.show(path, listed);
        });
    }
    /// Explicit user refresh bypasses cached directory metadata without navigating.
    /// Both the view button and its keyboard shortcut use this controller action.
    pub fn reload(self) {
        if self.navigating.get_untracked() {
            return;
        }
        super::sys::forget(false);
        self.typed.set(None);
        self.notice.set(String::new());
        self.refresh();
    }
    /// Show the directory `path`, listed.
    fn show(self, path: String, listed: Result<Vec<Entry>, String>) {
        // Read the departing directory before replacing its rows. Refreshes save the current
        // position too, so an upload or an inotify update does not jump back to an old offset.
        if let Some(scroller) = self.scroller.get_untracked()
            && scroller.client_height() > 0
        {
            self.positions.update_value(|positions| {
                positions.insert(
                    self.cwd.get_untracked(),
                    (scroller.scroll_left(), scroller.scroll_top()),
                );
            });
        }
        let position = self
            .positions
            .with_value(|positions| positions.get(&path).copied())
            .unwrap_or_default();
        let rendered = self.rendered.get_value() + 1;
        self.rendered.set_value(rendered);
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
        // Leptos commits the new rows asynchronously. Restore only after they supply the
        // scroll height; restoring before then clamps the saved offset to the old directory.
        request_animation_frame(move || {
            if self.rendered.get_value() == rendered
                && let Some(scroller) = self.scroller.get_untracked()
            {
                scroller.set_scroll_left(position.0);
                scroller.set_scroll_top(position.1);
            }
        });
    }
    /// The directory above its own.
    pub fn up(self) {
        let cwd = self.cwd.get_untracked();
        self.go(os_core::parent(&cwd).to_string());
    }
    /// Go to the location typed: a path, from its directory, or from the account's home (~).
    pub fn locate(self, typed: &str) {
        self.typed.set(None);
        let typed = typed.trim();
        if typed.is_empty() {
            return;
        }
        let home = self.account.home.get_untracked();
        match located(&self.cwd.get_untracked(), &home, typed) {
            Ok(path) => self.go(path),
            Err(error) => self.notice.set(error),
        }
    }
    /// Directories open here, programs run in the terminal, and documents open in Preview.
    pub fn activate(self, entry: &Entry) {
        if entry.directory {
            return self.go(entry.path.clone());
        }
        // The listing says what a file is; only a link is asked what it leads to now, if to
        // anything: a dangling one says so, rather than open a preview of nothing.
        let (path, name, linked) = (entry.path.clone(), entry.name.clone(), entry.link.is_some());
        let mut runnable = os_core::completion::runnable(entry);
        spawn_local(async move {
            if linked {
                match crate::stat(&path).await {
                    Err(error) => return self.notice.set(format!("{name}: {error}")),
                    Ok(stat) if stat.is_dir() => return self.go(path),
                    Ok(stat) => runnable |= stat.mode & 0o111 != 0,
                }
            }
            if runnable {
                self.notice
                    .set(self.launch.run(path).err().unwrap_or_default());
                return;
            }
            let opened = JsFuture::from(crate::open_file(&path, os_core::kind(&path))).await;
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
        self.upload(crate::choose_files(), true);
    }
    /// Upload `files`, dropped on it, into its directory.
    pub fn dropped(self, files: JsValue) {
        if self.busy() {
            return;
        }
        self.upload(js_sys::Promise::resolve(&files), false);
    }
    /// Whether an upload cannot start now, saying why: one goes on in this page (the Files' or
    /// the terminal's: one at a time), or the directory it would go into is still opening.
    fn busy(self) -> bool {
        let why = if self.navigating.get_untracked() {
            Some(OPENING)
        } else if self.uploading.get_untracked() || crate::uploading() {
            Some(BUSY)
        } else {
            None
        };
        if let Some(why) = why {
            self.notice.set(why.into());
        }
        why.is_some()
    }
    /// Upload what `chosen` gives into its directory; a chooser that is still open (`choosing`)
    /// shows, so that Cancel can close it.
    fn upload(self, chosen: js_sys::Promise, choosing: bool) {
        let path = self.cwd.get_untracked();
        self.uploading.set(true);
        self.choosing.set_value(choosing);
        if choosing {
            self.progress.set("↑ choosing files".into());
        }
        spawn_local(async move {
            let files = JsFuture::from(chosen).await;
            self.choosing.set_value(false);
            let files = match files {
                Ok(files) if js_sys::Array::from(&files).length() > 0 => files,
                Ok(_) => {
                    self.progress.set(String::new());
                    return self.done();
                }
                Err(error) => {
                    self.progress.set(format!("✕ {}", js_message(error)));
                    return self.done();
                }
            };
            self.notice.set(String::new());
            self.progress.set("↑ starting".into());
            let result =
                crate::uploads::upload(&files, &path, move |text| self.progress.set(text)).await;
            self.done();
            match result {
                Ok(lines) => self.progress.set(lines.join("\n")),
                Err(error) => self.progress.set(format!("✕ {error}")),
            }
            self.refresh();
        });
    }
    /// An upload is over: another may start, and what said one went on is old news.
    fn done(self) {
        self.uploading.set(false);
        self.notice.update(|notice| {
            if notice == BUSY {
                notice.clear();
            }
        });
    }
    /// Stop what it uploads: a chooser still open closes with nothing; an upload under way
    /// stops, keeping nothing of what was not done. Only its own: while its chooser is open, no
    /// upload of the page is its to stop.
    pub fn cancel(self) {
        if self.choosing.get_value() {
            crate::cancel_choosing();
        } else {
            crate::cancel_uploads();
        }
    }
}

/// The Files app's window content: its location, its directory listed, what it says.
pub fn view(files: Files) -> impl IntoView {
    let location = move || files.typed.get().unwrap_or_else(|| files.cwd.get());
    // iOS corrects what is typed unless told not to, with an attribute Leptos does not name, as
    // the terminal's command line is told.
    let input = NodeRef::<leptos::html::Input>::new();
    Effect::new(move || {
        if let Some(input) = input.get() {
            let _ = input.set_attribute("autocorrect", "off");
        }
    });
    view! {
        <section class="file-panel" aria-label="File manager">
        <div class="directory-bar">
            <input class="location" aria-label="Location" autocomplete="off" spellcheck="false" autocapitalize="off" enterkeyhint="go"
                node_ref=input
                prop:value=location
                on:input=move |e| files.typed.set(Some(event_target_value(&e)))
                on:keydown=move |e| {
                    // What an input method is still composing is not the location yet.
                    if e.is_composing() { return; }
                    match e.key().as_str() {
                        "Enter" => { e.prevent_default(); files.locate(&event_target_value(&e)); }
                        "Escape" => { e.prevent_default(); files.typed.set(None); }
                        _ => {}
                    }
                }
                on:blur=move |_| files.typed.set(None)/>
            <div class="directory-actions" role="group" aria-label="Filesystem actions"><button type="button" class="files-refresh" title="Refresh (F5)" aria-label="Refresh" aria-keyshortcuts="F5" on:click=move |_| files.reload() disabled=move || files.navigating.get()><span aria-hidden="true">"↻"</span></button>
            <button class="files-upload" title="Upload" aria-label="Upload" on:click=move |_| files.choose() disabled=move || files.uploading.get() || files.navigating.get()><span aria-hidden="true">"↑"</span></button>
            <button type="button" class="files-mounts" aria-label="Mounts" title="Mount and manage filesystems" on:click=move |_| files.local_mounts()><span aria-hidden="true">"▱"</span></button></div>
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
        <div class="files" aria-label="Current directory" node_ref=files.scroller>
            <Show when=move || files.cwd.get() != "/"><button class="file" on:click=move |_| files.up()><span class="file-kind">{crate::file_icon("directory", true)}</span><span>"../"</span></button></Show>
            {move || files.entries.get().into_iter().map(|entry| {
                let size = if entry.directory { String::new() } else { crate::upload_progress(&entry).unwrap_or_else(|| format!("{:.1} KB", entry.size as f64 / 1000.0)) };
                let title = format!("{} {}:{}{}", entry.mode_line(), entry.owner, entry.group, entry.link.as_ref().map(|t| format!(" -> {t}")).unwrap_or_default());
                let linked = entry.link.is_some();
                // What the account may not open shows dimmed, and says why when clicked.
                let denied = entry.denied && !os_core::completion::runnable(&entry);
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
