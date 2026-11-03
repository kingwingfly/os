//! The previews in the viewer dialog. web/app.js opens the dialog, hands its content to [`show`]
//! through `window.terminalPreview.show(content, path, kind, version)`, and later calls what that
//! returns, to release the preview: its views, its workers' documents and its listeners. The
//! manual renders through `window.terminalPreview.markdown(text, path)`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gloo_net::http::{Method, RequestBuilder};
use leptos::{ev, html, mount::mount_to, prelude::*, task::spawn_local};
use terminal_worker_preview::language;
use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::{JsFuture, future_to_promise};
use web_sys::{
    Blob, BlobPropertyBag, CanvasRenderingContext2d, Element, HtmlCanvasElement, HtmlElement,
    ResizeObserver, ResizeObserverEntry, Url,
};

use crate::preview::{self, ARCHIVE_MAX, DiffLine, Kind, TEXT_MAX, file_path, file_url};
use crate::search::Searchable;
use crate::workers;

#[wasm_bindgen]
extern "C" {
    /// Open `path` in the viewer, from a link in the file it shows, which Back returns to.
    #[wasm_bindgen(js_namespace = terminal, js_name = follow)]
    fn follow_link(path: &str, kind: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = terminal, js_name = place)]
    fn saved_place(path: &str) -> JsValue;
    #[wasm_bindgen(js_namespace = terminal, js_name = setPlace)]
    fn save_place(path: &str, value: JsValue);
    /// Tell this browser's other windows, and the account's pages signed in elsewhere, that this
    /// page presents `column`, `row` of the file at `path`: a slide, or a PDF's page and 0.
    #[wasm_bindgen(js_namespace = terminal, js_name = present)]
    fn tell_presenting(path: &str, column: usize, row: usize);
    /// Ask where this page's account last showed the file at `path`, on any device: the answer
    /// comes as what another presents (`terminal:present`).
    #[wasm_bindgen(js_namespace = terminal, js_name = ask)]
    fn ask_where(path: &str);
    /// The last place this page heard of, or showed, in the file at `path`: `[column, row]`.
    #[wasm_bindgen(js_namespace = terminal, js_name = presented)]
    fn last_presented(path: &str) -> JsValue;
    /// The presentation of the file at `path` that this page follows, if it does
    /// (`open /dev/present/NAME`): `{device, owner, controller}`.
    #[wasm_bindgen(js_namespace = terminal, js_name = attending)]
    fn attending(path: &str) -> JsValue;
    /// The bar shows the file at `path` now: what it shows of it comes as `terminal:bar`.
    #[wasm_bindgen(js_namespace = terminal, js_name = barOf)]
    fn bar_of(path: &str);
    /// Present the file at `path` to others, as /dev/present/NAME, or stop presenting it.
    #[wasm_bindgen(js_namespace = terminal, js_name = togglePresenting)]
    fn toggle_presenting(path: &str);
    /// Go live, as stream does, and record too (`keep`) beside the file at `path`; or stop.
    #[wasm_bindgen(js_namespace = terminal, js_name = goLive)]
    fn go_live(path: &str, keep: bool);
    /// Ask to speak in the presentation followed, or withdraw the ask, or stop speaking.
    #[wasm_bindgen(js_namespace = terminal, js_name = askToSpeak)]
    fn ask_to_speak();
    /// Allow, or dismiss, a listener's ask to speak.
    #[wasm_bindgen(js_namespace = terminal, js_name = answerAsk)]
    fn answer_ask(id: &str, allow: bool);
    /// End a listener's voice, as its presenter.
    #[wasm_bindgen(js_namespace = terminal, js_name = endVoice)]
    fn end_voice(device: &str);
}

/// Where the preview of `path` was left, as web/app.js keeps it: `{"slide": [column, row]}`,
/// `{"page": n, "zoom": z}`, and so on; null if nowhere.
fn place(path: &str) -> serde_json::Value {
    js_sys::JSON::stringify(&saved_place(path))
        .ok()
        .and_then(|text| text.as_string())
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}
/// Keep `value`, merged with what is kept, as where the preview of `path` is.
pub(crate) fn set_place(path: &str, value: serde_json::Value) {
    if let Ok(value) = js_sys::JSON::parse(&value.to_string()) {
        save_place(path, value);
    }
}

/// The most bytes of a PDF opened, as many as an upload has.
const PDF_MAX: usize = 100_000_000;
/// The size slides are laid out at, as reveal.js laid them out before; they scale to the space
/// they have, in the dialog or full screen.
const SLIDE_SIZE: (f64, f64) = (1280.0, 720.0);

/// A JavaScript error as text.
pub fn js_error(error: JsValue) -> String {
    match error.dyn_ref::<js_sys::Error>() {
        Some(error) => String::from(error.message()),
        None => error.as_string().unwrap_or_else(|| format!("{error:?}")),
    }
}

/// Make [`show`] and [`preview::markdown`] web/app.js's `window.terminalPreview`.
pub fn register() {
    let show = Closure::<dyn Fn(HtmlElement, String, String, String) -> js_sys::Promise>::new(
        |content, path, kind, version| {
            future_to_promise(async move {
                show(content, path, kind, version)
                    .await
                    .map_err(|error| js_sys::Error::new(&error).into())
            })
        },
    );
    let markdown =
        Closure::<dyn Fn(String, String) -> String>::new(|text: String, path: String| {
            preview::markdown(&text, &path)
        });
    let api = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&api, &"show".into(), show.as_ref());
    let _ = js_sys::Reflect::set(&api, &"markdown".into(), markdown.as_ref());
    show.forget();
    markdown.forget();
    let _ = js_sys::Reflect::set(&window(), &"terminalPreview".into(), &api);
}

/// What a preview shows once its file is read.
enum Preview {
    /// An image, video or audio of the kind the terminal lists, which the browser streams.
    Media(String, String),
    Slides(String),
    File(Kind, Vec<u8>),
}

/// Show the file at `path`, which the terminal lists as `listed`, in `content`, unless the viewer
/// went on to another file while it was read, as `content`'s `data-version` then is no longer
/// `version`. Returns what releases it.
async fn show(
    content: HtmlElement,
    path: String,
    listed: String,
    version: String,
) -> Result<JsValue, String> {
    let url = file_url(&path);
    // A player asks for many ranges: it plays from a read descriptor's token, which the Worker
    // serves without asking the kernel each time; closing the preview closes it.
    let held = if matches!(listed.as_str(), "video" | "audio") {
        playing(&path).await
    } else {
        None
    };
    let size = if held.is_some() { 0 } else { head(&url).await? };
    let preview = match listed.as_str() {
        "image" | "video" | "audio" => Preview::Media(
            listed,
            held.as_ref().map_or(url, |(_, token)| {
                format!("/api/file?token={}", js_sys::encode_uri_component(token))
            }),
        ),
        _ => {
            let archive = [".zip", ".tar", ".tar.gz", ".tgz"]
                .iter()
                .any(|extension| path.to_lowercase().ends_with(extension));
            let limit = match listed.as_str() {
                "pdf" => PDF_MAX,
                _ if archive => ARCHIVE_MAX,
                _ => TEXT_MAX,
            };
            if size > limit {
                return Err(if limit == TEXT_MAX {
                    "Text exceeds 2 MB; use the download button in the top right.".into()
                } else {
                    "The file is too large to preview; use the download button in the top right."
                        .into()
                });
            }
            let data = get(&url).await?;
            match listed.as_str() {
                "slides" => Preview::Slides(String::from_utf8_lossy(&data).into_owned()),
                "pdf" => Preview::File(Kind::Pdf, data),
                _ => Preview::File(preview::kind(&path, &data), data),
            }
        }
    };
    let fd = held.map(|(fd, _)| fd);
    if content.get_attribute("data-version").as_deref() != Some(version.as_str()) {
        let _ = close(fd);
        return Ok(Closure::once_into_js(|| {}));
    }
    content.set_text_content(None);
    let handle = mount_to(content, move || render(preview, path));
    Ok(Closure::once_into_js(move || {
        drop(handle);
        let _ = close(fd);
    }))
}

/// A read descriptor of the file at `path`, and its token, if it has one.
async fn playing(path: &str) -> Option<(u32, String)> {
    let opened: abi::Opened = userland::sys::call(
        &crate::sys::HttpSys::default(),
        abi::Call::Open {
            path: path.to_string(),
            flags: abi::O_RDONLY,
            mode: 0o666,
            size: None,
            sha256: None,
            version: None,
        },
    )
    .await
    .ok()?;
    match opened.token {
        Some(token) => Some((opened.fd, token)),
        None => {
            let _ = close(Some(opened.fd));
            None
        }
    }
}

/// Let go of the descriptor `fd`, if there is one, in the background.
fn close(fd: Option<u32>) -> Option<()> {
    let fd = fd?;
    spawn_local(async move {
        let _ = userland::sys::calls::<serde_json::Value>(
            &crate::sys::HttpSys::default(),
            vec![abi::Call::Close { fd: fd.into() }],
        )
        .await;
    });
    Some(())
}

/// The size of the file at `url`, which the viewer may read.
async fn head(url: &str) -> Result<usize, String> {
    let response = respond(RequestBuilder::new(url).method(Method::HEAD)).await?;
    Ok(response
        .headers()
        .get("Content-Length")
        .and_then(|length| length.parse().ok())
        .unwrap_or(0))
}

/// The bytes of the file at `url`.
async fn get(url: &str) -> Result<Vec<u8>, String> {
    respond(RequestBuilder::new(url))
        .await?
        .binary()
        .await
        .map_err(|e| e.to_string())
}

/// The response to `request`, or the error the terminal gave.
async fn respond(request: RequestBuilder) -> Result<gloo_net::http::Response, String> {
    let response = request.send().await.map_err(|e| e.to_string())?;
    if response.ok() {
        return Ok(response);
    }
    let error = response
        .json::<serde_json::Value>()
        .await
        .ok()
        .and_then(|value| value["error"].as_str().map(String::from));
    Err(error.unwrap_or_else(|| format!("Request failed ({})", response.status())))
}

fn render(preview: Preview, path: String) -> AnyView {
    match preview {
        Preview::Media(kind, url) => media(&kind, url, &path),
        Preview::Slides(source) => view! { <Slides source path /> }.into_any(),
        Preview::File(kind, data) => match kind {
            Kind::Image(mime) => match image_url(&data, mime) {
                Some(url) => media("image", url, &path),
                None => no_preview(),
            },
            Kind::Video(mime) => match blob_url(&data, mime) {
                Some(url) => media("video", url, &path),
                None => no_preview(),
            },
            Kind::Audio(mime) => match blob_url(&data, mime) {
                Some(url) => media("audio", url, &path),
                None => no_preview(),
            },
            Kind::Pdf => view! { <PdfView data=Arc::new(data) path /> }.into_any(),
            Kind::Markdown { html, source } => {
                view! { <MarkdownView html source path /> }.into_any()
            }
            Kind::Code { text, language } => view! {
                <Searchable>
                    <Enhanced>
                        <pre class="text-preview"><code data-lang=language>{text}</code></pre>
                    </Enhanced>
                </Searchable>
            }
            .into_any(),
            Kind::Table(table) => table_view(table),
            Kind::Archive => view! { <ArchiveView data /> }.into_any(),
            Kind::Cards(cards) => cards_view(cards),
            Kind::Diff(lines) => {
                let diff = diff_view(lines);
                view! { <Searchable>{diff}</Searchable> }.into_any()
            }
            Kind::None => no_preview(),
        },
    }
}

fn no_preview() -> AnyView {
    view! {
        <div class="media-frame">
            <p class="no-preview">"No preview for this kind of file. Download it to open it."</p>
        </div>
    }
    .into_any()
}

/// An image, video or audio from `url`, the file at `path`.
fn media(kind: &str, url: String, path: &str) -> AnyView {
    let failed = RwSignal::new(false);
    let element = match kind {
        "image" => view! { <img src=url alt=path.to_string() on:error=move |_| failed.set(true) /> }
            .into_any(),
        "video" => view! {
            <video src=url controls preload="metadata" playsinline on:error=move |_| failed.set(true)></video>
        }
        .into_any(),
        _ => view! {
            <audio src=url controls preload="metadata" on:error=move |_| failed.set(true)></audio>
        }
        .into_any(),
    };
    view! {
        <div class="media-frame">
            {element}
            {move || {
                failed.get().then(|| view! { <p>"This browser cannot decode the media. Download it to open locally."</p> })
            }}
        </div>
    }
    .into_any()
}

/// A URL that shows the image `data`, of the MIME type `mime`: a blob URL of this origin, but for
/// SVG, which would open from one as a page of this origin, running its scripts; a `data:` URL
/// opens as no page, and as an image, it runs none.
fn image_url(data: &[u8], mime: &str) -> Option<String> {
    if mime == "image/svg+xml" {
        let text = String::from_utf8_lossy(data);
        Some(format!(
            "data:{mime};charset=utf-8,{}",
            js_sys::encode_uri_component(&text)
        ))
    } else {
        blob_url(data, mime)
    }
}

/// A blob URL of this origin for `data`, typed `mime`, revoked when the preview goes.
fn blob_url(data: &[u8], mime: &str) -> Option<String> {
    let parts = js_sys::Array::of1(&js_sys::Uint8Array::from(data));
    let options = BlobPropertyBag::new();
    options.set_type(mime);
    let url = Blob::new_with_u8_array_sequence_and_options(&parts, &options)
        .and_then(|blob| Url::create_object_url_with_blob(&blob))
        .ok()?;
    let revoked = url.clone();
    on_cleanup(move || {
        let _ = Url::revoke_object_url(&revoked);
    });
    Some(url)
}

/// What it shows, once shown, with its code blocks highlighted and its diagrams drawn; its links
/// to files open them in the viewer.
#[component]
fn Enhanced(children: Children) -> impl IntoView {
    let node = NodeRef::<html::Div>::new();
    Effect::new(move || {
        if let Some(element) = node.get() {
            enhance(&element);
        }
    });
    view! {
        <div class="enhanced" node_ref=node on:click=follow>
            {children()}
        </div>
    }
}

/// Open the file a clicked link names in the viewer, instead of leaving for it.
fn follow(event: ev::MouseEvent) {
    let Some(link) = event
        .target()
        .and_then(|target| target.dyn_into::<Element>().ok())
        .and_then(|target| target.closest("a[href]").ok().flatten())
    else {
        return;
    };
    let Some(path) = link.get_attribute("href").and_then(|href| file_path(&href)) else {
        return;
    };
    event.prevent_default();
    let kind = terminal_worker_core::kind(&path);
    spawn_local(async move {
        let _ = JsFuture::from(follow_link(&path, kind)).await;
    });
}

/// The elements in `element` that `selector` selects.
fn select(element: &Element, selector: &str) -> Vec<Element> {
    let Ok(nodes) = element.query_selector_all(selector) else {
        return Vec::new();
    };
    (0..nodes.length())
        .filter_map(|i| nodes.item(i)?.dyn_into().ok())
        .collect()
}

/// Make the web links in `element` open in a tab of their own; highlight its code blocks,
/// `pre > code[data-lang]`, and draw its Mermaid ones, as images. Blocks that fail stay as they
/// are, saying why in `data-error`.
fn enhance(element: &Element) {
    for link in select(element, "a[href^='http']") {
        let _ = link.set_attribute("target", "_blank");
    }
    for code in select(element, "pre > code[data-lang]") {
        spawn_local(async move {
            let info = code.get_attribute("data-lang").unwrap_or_default();
            let text = code.text_content().unwrap_or_default();
            let shown = if info.eq_ignore_ascii_case("mermaid") {
                workers::diagram(&text).await.and_then(|svg| {
                    // A data: URL, not a blob: one of this origin, which would open as a page.
                    let image = document().create_element("img").map_err(js_error)?;
                    image.set_class_name("diagram");
                    let src = format!(
                        "data:image/svg+xml;charset=utf-8,{}",
                        js_sys::encode_uri_component(&svg)
                    );
                    let _ = image.set_attribute("alt", "diagram");
                    let _ = image.set_attribute("src", &src);
                    if let Some(block) = code.parent_element() {
                        block.replace_with_with_node_1(&image).map_err(js_error)?;
                    }
                    Ok(())
                })
            } else if let Some(language) = language::of_block(&info) {
                workers::highlight(language, &text)
                    .await
                    .map(|html| code.set_inner_html(&html))
            } else {
                Ok(())
            };
            if let (Err(e), Some(block)) = (shown, code.parent_element()) {
                let _ = block.set_attribute("data-error", &e);
            }
        });
    }
}

/// A line icon, as the terminal's file icons are drawn.
fn icon(path: &'static str) -> impl IntoView {
    view! {
        <svg class="preview-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d=path />
        </svg>
    }
}

const PREVIOUS: &str = "M15 6l-6 6 6 6";
const NEXT: &str = "M9 6l6 6-6 6";
const UP: &str = "M6 15l6-6 6 6";
const DOWN: &str = "M6 9l6 6 6-6";
const AS_SLIDES: &str = "M3 4h18M4 4v11a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1V4M12 16v4M8 20h8";
const AS_DOCUMENT: &str =
    "M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h6";

/// A Markdown file, as a document, or as slides.
#[component]
fn MarkdownView(html: String, source: String, path: String) -> impl IntoView {
    let as_slides = RwSignal::new(place(&path)["slides"] == true || speaker_window(&path));
    let kept = path.clone();
    Effect::new(move || set_place(&kept, serde_json::json!({ "slides": as_slides.get() })));
    let label = move || {
        if as_slides.get() {
            "View as a document"
        } else {
            "View as slides"
        }
    };
    view! {
        <div class="preview-bar">
            <button
                class="preview-button"
                title=label
                aria-label=label
                on:click=move |_| as_slides.update(|slides| *slides = !*slides)
            >
                {move || icon(if as_slides.get() { AS_DOCUMENT } else { AS_SLIDES })}
            </button>
        </div>
        {move || {
            if as_slides.get() {
                view! { <Slides source=source.clone() path=path.clone() /> }.into_any()
            } else {
                let html = html.clone();
                view! {
                    <Searchable>
                        <Enhanced>
                            <article class="markdown" inner_html=html></article>
                        </Enhanced>
                    </Searchable>
                }
                .into_any()
            }
        }}
    }
}

/// The looks slides can take, for every deck: each a value of `.slides[data-theme]`, and its name.
const SLIDE_THEMES: [(&str, &str); 4] = [
    ("light", "Light"),
    ("dark", "Dark"),
    ("sepia", "Sepia"),
    ("night", "Night"),
];
const SLIDE_THEME: &str = "terminal-slide-theme";
/// The size of the speaker view's notes, in pixels, kept for every deck in this browser.
const NOTES_SIZE: &str = "terminal-notes-size";
const NOTES_SIZES: (u32, u32, u32) = (14, 24, 56);
/// How many slides either side of the one shown are drawn ahead of it.
const SLIDES_AHEAD: usize = 2;
/// How far, in pixels, a touch must move across to turn a slide or a page.
const SWIPE: i32 = 50;

/// What this browser keeps under `key`, if it can keep anything.
fn stored(key: &str) -> Option<String> {
    let storage = window().local_storage().ok().flatten()?;
    storage.get_item(key).ok().flatten()
}
fn store(key: &str, value: &str) {
    if let Some(storage) = window().local_storage().ok().flatten() {
        let _ = storage.set_item(key, value);
    }
}
/// The slide theme chosen last in this browser, or Light.
fn slide_theme() -> String {
    stored(SLIDE_THEME)
        .filter(|theme| SLIDE_THEMES.iter().any(|(value, _)| value == theme))
        .unwrap_or_else(|| "light".into())
}

/// Whether keys are the slides', rather than another dialog's or a text field's.
fn keys_for_slides() -> bool {
    let document = document();
    let typing = document.active_element().is_some_and(|element| {
        matches!(element.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT")
            || element.has_attribute("contenteditable")
    });
    let elsewhere = document
        .query_selector("dialog#auth[open], dialog#editor[open]")
        .ok()
        .flatten()
        .is_some();
    !typing && !elsewhere
}
/// Whether `key` would press what has the focus, rather than turn: Space a button, Enter a
/// button or a link, tabbed to (a click leaves the focus where it was: app.js).
fn pressing(key: &str) -> bool {
    let pressed: &[&str] = match key {
        " " => &["BUTTON", "SUMMARY"],
        "Enter" => &["BUTTON", "A", "SUMMARY"],
        _ => &[],
    };
    document()
        .active_element()
        .is_some_and(|element| pressed.contains(&element.tag_name().as_str()))
}
/// How far a key turns through slides, or a presented PDF's pages, in order: Space, N, Page Down
/// (what a presenter's remote sends) on; Shift+Space, P, Page Up back.
fn turn_key(event: &web_sys::KeyboardEvent) -> Option<isize> {
    match event.key().as_str() {
        " " if event.shift_key() => Some(-1),
        " " | "PageDown" | "n" | "N" => Some(1),
        "PageUp" | "p" | "P" => Some(-1),
        _ => None,
    }
}
/// Show the viewer full screen, or no longer, as its button does.
fn toggle_fullscreen() {
    if let Some(button) = document().get_element_by_id("fullscreen") {
        button.unchecked_into::<HtmlElement>().click();
    }
}

/// Where a touch on slides or a presented PDF began, to turn them as it ends: a swipe left goes
/// on, right back.
#[derive(Clone, Copy)]
struct Swipe(StoredValue<Option<(i32, i32)>>);
impl Swipe {
    fn new() -> Self {
        Self(StoredValue::new(None))
    }
    fn start(self, event: &web_sys::PointerEvent) {
        if event.pointer_type() != "mouse" {
            self.0.set_value(Some((event.client_x(), event.client_y())));
        }
    }
    fn cancel(self) {
        self.0.set_value(None);
    }
    /// How far the touch that `event` ends turns: 1 on, -1 back, 0 not at all.
    fn end(self, event: &web_sys::PointerEvent) -> isize {
        let Some(Some((x, y))) = self.0.try_update_value(Option::take) else {
            return 0;
        };
        let (across, down) = (event.client_x() - x, event.client_y() - y);
        if across.abs() > SWIPE && across.abs() > 2 * down.abs() {
            -across.signum() as isize
        } else {
            0
        }
    }
}

/// Call `resized` with the element `node` refers to and its content box's width and height,
/// once it is laid out and whenever that changes, for as long as the view lasts.
fn on_resize(node: NodeRef<html::Div>, resized: impl Fn(&HtmlElement, f64, f64) + 'static) {
    let call = Closure::<dyn FnMut(js_sys::Array)>::new(move |entries: js_sys::Array| {
        for entry in entries.iter() {
            let entry: ResizeObserverEntry = entry.unchecked_into();
            let size = entry.content_rect();
            resized(entry.target().unchecked_ref(), size.width(), size.height());
        }
    });
    let observer = StoredValue::new_local(ResizeObserver::new(call.as_ref().unchecked_ref()).ok());
    let call = StoredValue::new_local(Some(call));
    Effect::new(move || {
        if let (Some(element), Some(observer)) = (node.get(), observer.get_value()) {
            observer.observe(&element);
        }
    });
    on_cleanup(move || {
        if let Some(Some(observer)) = observer.try_get_value() {
            observer.disconnect();
        }
        let _ = call.try_update_value(Option::take);
    });
}

/// Follow, with `apply`, the place that another window of this browser, or a page of this account
/// signed in elsewhere, presents in the file at `path`, as app.js hears of it
/// (`terminal:present`), for as long as the view lasts.
fn follow_presenting(path: StoredValue<String>, apply: impl Fn(usize, usize) + Copy + 'static) {
    // What came while the file was read.
    let last = path.with_value(|path| last_presented(path));
    if let Some(last) = last.dyn_ref::<js_sys::Array>()
        && let (Some(column), Some(row)) = (last.get(0).as_f64(), last.get(1).as_f64())
    {
        apply(column as usize, row as usize);
    }
    let listener = window_event_listener_untyped("terminal:present", move |event| {
        let Some(detail) = event
            .dyn_ref::<web_sys::CustomEvent>()
            .map(|event| event.detail())
        else {
            return;
        };
        let get = |name: &str| js_sys::Reflect::get(&detail, &name.into()).ok();
        let Some(shown) = get("path").and_then(|path| path.as_string()) else {
            return;
        };
        let at = get("at")
            .and_then(|at| at.dyn_into::<js_sys::Array>().ok())
            .unwrap_or_default();
        let place = |index: u32| {
            at.get(index)
                .as_f64()
                .filter(|n| *n >= 0.0 && n.fract() == 0.0)
                .map(|n| n as usize)
        };
        if let (true, Some(column), Some(row)) =
            (path.with_value(|path| *path == shown), place(0), place(1))
        {
            apply(column, row);
        }
    });
    on_cleanup(move || listener.remove());
}

/// A page that follows another account's presentation of the file it shows (devices.rs), as a
/// listener: it shows each place the presenter turns to, until its reader turns elsewhere,
/// which pauses following until they follow again; and it says when the presentation ends.
/// The presenter's own account turns a presentation it follows, and is no audience.
#[derive(Clone, Copy)]
struct Audience {
    device: StoredValue<String>,
    owner: StoredValue<String>,
    paused: RwSignal<bool>,
    /// Where the presenter is, as last heard.
    latest: RwSignal<Option<(usize, usize)>>,
    ended: RwSignal<bool>,
}
impl Audience {
    /// What this page is of the file at `path`: an audience if it follows another account's
    /// presentation of it.
    fn of(path: &str) -> Option<Self> {
        let attended = attending(path);
        let get = |name: &str| js_sys::Reflect::get(&attended, &name.into()).ok();
        if get("controller").and_then(|controller| controller.as_bool()) != Some(false) {
            return None;
        }
        let audience = Self {
            device: StoredValue::new(get("device")?.as_string()?),
            owner: StoredValue::new(get("owner")?.as_string()?),
            paused: RwSignal::new(false),
            latest: RwSignal::new(None),
            ended: RwSignal::new(get("ended").is_some_and(|ended| ended.is_truthy())),
        };
        let listener = window_event_listener_untyped("terminal:device", move |event| {
            let Some(detail) = event.dyn_ref::<web_sys::CustomEvent>().map(|e| e.detail()) else {
                return;
            };
            let get = |name: &str| js_sys::Reflect::get(&detail, &name.into()).ok();
            let named = get("name").and_then(|name| name.as_string());
            if audience
                .device
                .with_value(|device| named.as_ref() == Some(device))
                && (get("ended").is_some_and(|ended| ended.is_truthy())
                    || get("error").is_some_and(|error| error.is_truthy()))
            {
                audience.ended.set(true);
            }
        });
        on_cleanup(move || listener.remove());
        Some(audience)
    }
    /// The presenter turned to `at`: whether to show it, as the page is not paused.
    fn heard(self, at: (usize, usize)) -> bool {
        self.latest.set(Some(at));
        !self.paused.get_untracked()
    }
    /// The reader turned to `at` themselves, which pauses following unless it is where the
    /// presenter is.
    fn turned(self, at: (usize, usize)) {
        self.paused.set(self.latest.get_untracked() != Some(at));
    }
    /// Follow again, from where the presenter is.
    fn resume(self) -> Option<(usize, usize)> {
        self.paused.set(false);
        self.latest.get_untracked()
    }
    /// What the bar says of it, a button that follows again.
    fn badge(self, resume: impl Fn() + Copy + 'static) -> impl IntoView {
        let label = move || {
            let owner = self.owner.get_value();
            if self.ended.get() {
                "The presentation ended".to_string()
            } else if self.paused.get() {
                format!("Follow {owner}")
            } else {
                format!("Following {owner}")
            }
        };
        let title = move || {
            self.device.with_value(|device| {
                if self.paused.get() {
                    format!("Back to where {device} is")
                } else {
                    format!("{device}: turn yourself to pause following")
                }
            })
        };
        view! {
            <button
                class="presentation-badge"
                class:paused=move || self.paused.get()
                title=title
                disabled=move || self.ended.get()
                on:click=move |_| resume()
            >
                {label}
            </button>
        }
    }
}

/// What the bar's live controls show (web/app.js `bar`): who is signed in, this account's
/// presentations of the file, the sound this page sends, listeners asking to speak and speaking,
/// and, following another's presentation, this page's ask; and a note, what failed or was saved.
#[derive(Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Bar {
    path: Option<String>,
    user: Option<String>,
    presented: Vec<String>,
    asks: Vec<Ask>,
    voices: Vec<Voice>,
    sound: Option<Sending>,
    asking: Option<Asking>,
    note: String,
}
#[derive(Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Ask {
    id: String,
    name: String,
}
#[derive(Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Voice {
    device: String,
    speaker: String,
}
#[derive(Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Sending {
    device: Option<String>,
    recording: Option<String>,
    since: f64,
    progress: String,
}
#[derive(Clone, Default, PartialEq, serde::Deserialize)]
#[serde(default)]
struct Asking {
    state: String,
    error: Option<String>,
}

const PRESENT_TO_OTHERS: &str = "M3 8V6a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-6M3 12a8 8 0 0 1 8 8M3 16a4 4 0 0 1 4 4M3 20h.01";
const MICROPHONE: &str =
    "M12 3a3 3 0 0 0-3 3v6a3 3 0 0 0 6 0V6a3 3 0 0 0-3-3zM5 11a7 7 0 0 0 14 0M12 18v3M8 21h8";
const RAISED_HAND: &str = "M8 13V5.5a1.5 1.5 0 0 1 3 0V11M11 10.5V4a1.5 1.5 0 0 1 3 0v6.5M14 10V5.5a1.5 1.5 0 0 1 3 0V13M17 9.5a1.5 1.5 0 0 1 3 0V15a7 7 0 0 1-7 7h-1a7 7 0 0 1-5.6-2.8l-3.1-3.6a1.5 1.5 0 0 1 2.3-1.9L8 16";

/// The bar's live controls of the file at `path` (owner's request, 2026-10-28). Signed in:
/// Present, which makes /dev/present/NAME for others to follow, or stops it; Go live, Live or
/// Live + record, as stream does; and the listeners asking to speak, whom the presenter allows
/// or not, and those speaking, whom it ends. Following another's presentation: Ask to speak.
#[component]
fn LiveControls(path: StoredValue<String>, audience: Option<Audience>) -> impl IntoView {
    let bar = RwSignal::new(Bar::default());
    // Which popover is open: the Go live choice, or the listeners.
    let menu = RwSignal::new(None::<&'static str>);
    let listener = window_event_listener_untyped("terminal:bar", move |event| {
        let Some(detail) = event.dyn_ref::<web_sys::CustomEvent>().map(|e| e.detail()) else {
            return;
        };
        let shown: Option<Bar> = js_sys::JSON::stringify(&detail)
            .ok()
            .and_then(|text| text.as_string())
            .and_then(|text| serde_json::from_str(&text).ok());
        if let Some(shown) = shown
            && path.with_value(|path| shown.path.as_ref() == Some(path))
        {
            bar.set(shown);
        }
    });
    on_cleanup(move || listener.remove());
    path.with_value(|path| bar_of(path));
    let note = move || {
        let note = bar.with(|bar| bar.note.clone());
        (!note.is_empty()).then(|| view! { <span class="live-note" role="status">{note}</span> })
    };
    if let Some(audience) = audience {
        let state = move || bar.with(|bar| bar.asking.as_ref().map(|asking| asking.state.clone()));
        let label = move || match state().as_deref() {
            Some("asking") => "Asking to speak · click to withdraw".to_string(),
            Some("connecting") => "Starting your microphone".to_string(),
            Some("speaking") => {
                "Speaking: everyone following hears you · click to stop".to_string()
            }
            Some("denied") => "Not now, says the presenter".to_string(),
            Some("error") => bar.with(|bar| {
                bar.asking
                    .as_ref()
                    .and_then(|asking| asking.error.clone())
                    .unwrap_or_default()
            }),
            _ => "Ask to speak".to_string(),
        };
        return view! {
            <span class="live-controls">
                <button
                    class="preview-button live-ask"
                    class:waiting=move || matches!(state().as_deref(), Some("asking" | "connecting"))
                    class:on=move || state().as_deref() == Some("speaking")
                    aria-label="Ask to speak"
                    aria-pressed=move || state().is_some_and(|state| matches!(state.as_str(), "asking" | "connecting" | "speaking")).to_string()
                    title=label
                    disabled=move || audience.ended.get()
                    on:click=move |_| ask_to_speak()
                >
                    {icon(RAISED_HAND)}
                </button>
                {move || (!matches!(state().as_deref(), None | Some("speaking"))).then(|| view! { <span class="live-note" role="status">{label}</span> })}
                {note}
            </span>
        }
        .into_any();
    }
    let presented = move || bar.with(|bar| bar.presented.first().cloned());
    let sending = move || bar.with(|bar| bar.sound.clone());
    let people = move || bar.with(|bar| (bar.asks.clone(), bar.voices.clone()));
    // A popover closes once it has nothing to choose: live already, or no one left; and on a
    // click elsewhere.
    Effect::new(move |_| {
        let live = sending().is_some();
        let alone = bar.with(|bar| bar.asks.is_empty() && bar.voices.is_empty());
        if (live && menu.get_untracked() == Some("live"))
            || (alone && menu.get_untracked() == Some("people"))
        {
            menu.set(None);
        }
    });
    let outside = window_event_listener(ev::pointerdown, move |event| {
        let inside = event
            .target()
            .and_then(|target| target.dyn_into::<Element>().ok())
            .and_then(|target| target.closest(".live-controls").ok().flatten());
        if inside.is_none() && menu.get_untracked().is_some() {
            menu.set(None);
        }
    });
    on_cleanup(move || outside.remove());
    let toggle = move |which: &'static str| {
        menu.update(|open| *open = (*open != Some(which)).then_some(which))
    };
    let live = move |keep: bool| {
        menu.set(None);
        path.with_value(|path| go_live(path, keep));
    };
    let clock = move |since: f64| {
        let seconds = ((js_sys::Date::now() - since) / 1000.0).max(0.0) as u64;
        format!("{:02}:{:02}", seconds / 60, seconds % 60)
    };
    view! {
        <span class="live-controls" class:signed-out=move || bar.with(|bar| bar.user.is_none())>
            <button
                class="preview-button"
                class:on=move || presented().is_some()
                aria-label="Present to others"
                aria-pressed=move || presented().is_some().to_string()
                title=move || match presented() {
                    Some(device) => format!("Presented as {device}: others follow it with open {device} · click to stop"),
                    None => "Present to others: they follow it with open /dev/present/NAME".to_string(),
                }
                on:click=move |_| path.with_value(|path| toggle_presenting(path))
            >
                {icon(PRESENT_TO_OTHERS)}
            </button>
            {move || match sending() {
                Some(sound) => {
                    let title = match (&sound.device, &sound.recording) {
                        (Some(device), Some(file)) => format!("Live as {device}, recording into {file} · click to stop"),
                        (Some(device), None) => format!("Live as {device} · click to stop"),
                        (None, Some(file)) => format!("Recording into {file} · click to stop"),
                        (None, None) => "Starting the microphone · click to stop".to_string(),
                    };
                    let title = if sound.progress.is_empty() { title } else { format!("{title}\n{}", sound.progress) };
                    view! {
                        <button class="live-on" aria-label="Stop the live sound" title=title on:click=move |_| live(false)>
                            {format!("● {}", clock(sound.since))}
                        </button>
                    }
                    .into_any()
                }
                None => view! {
                    <button
                        class="preview-button"
                        aria-label="Go live"
                        aria-haspopup="menu"
                        aria-expanded=move || (menu.get() == Some("live")).to_string()
                        title="Go live: send your microphone to those following"
                        on:click=move |_| toggle("live")
                    >
                        {icon(MICROPHONE)}
                    </button>
                }
                .into_any(),
            }}
            {move || (menu.get() == Some("live") && sending().is_none()).then(|| view! {
                <span class="live-menu" role="menu" aria-label="Go live">
                    <button role="menuitem" title="Live only: nothing is kept" on:click=move |_| live(false)>"Live"</button>
                    <button role="menuitem" title="Live, and recorded beside this file as NAME-DATE-TIME.weba" on:click=move |_| live(true)>"Live + record"</button>
                </span>
            })}
            {move || {
                let (asks, voices) = people();
                (!asks.is_empty() || !voices.is_empty()).then(|| view! {
                    <button
                        class="preview-button live-hands"
                        class:asked=!asks.is_empty()
                        aria-label=format!("Listeners: {} asking to speak, {} speaking", asks.len(), voices.len())
                        aria-haspopup="menu"
                        aria-expanded=move || (menu.get() == Some("people")).to_string()
                        on:click=move |_| toggle("people")
                    >
                        {icon(RAISED_HAND)}
                        {(!asks.is_empty()).then(|| view! { <span class="live-count">{asks.len()}</span> })}
                    </button>
                })
            }}
            {move || (menu.get() == Some("people")).then(|| {
                let (asks, voices) = people();
                view! {
                    <span class="live-menu live-people" role="menu" aria-label="Listeners">
                        {asks.into_iter().map(|ask| {
                            let (allow, dismiss) = (ask.id.clone(), ask.id.clone());
                            view! {
                                <span class="live-person">
                                    <span>{format!("{} asks to speak", ask.name)}</span>
                                    <button role="menuitem" on:click=move |_| answer_ask(&allow, true)>"Allow"</button>
                                    <button role="menuitem" on:click=move |_| answer_ask(&dismiss, false)>"Dismiss"</button>
                                </span>
                            }
                        }).collect_view()}
                        {voices.into_iter().map(|voice| {
                            let device = voice.device.clone();
                            view! {
                                <span class="live-person speaking">
                                    <span>{format!("{} speaking", voice.speaker)}</span>
                                    <button role="menuitem" on:click=move |_| end_voice(&device)>"End"</button>
                                </span>
                            }
                        }).collect_view()}
                    </span>
                }
            })}
            {note}
        </span>
    }
    .into_any()
}

thread_local! {
    /// The speaker view this page opened last, and the deck it was opened for, which S shows
    /// again rather than open another.
    static SPEAKER: std::cell::RefCell<Option<(web_sys::Window, String)>> = const { std::cell::RefCell::new(None) };
}
/// Whether this window is the speaker view of the deck at `path`, as S opened it: app.js opens
/// the deck its address names.
fn speaker_window(path: &str) -> bool {
    window()
        .location()
        .search()
        .ok()
        .and_then(|search| web_sys::UrlSearchParams::new_with_str(&search).ok())
        .and_then(|params| params.get("speaker"))
        .is_some_and(|deck| deck == path)
}
/// Open the speaker view of the deck at `path` in a window of its own, to keep on this screen
/// while the slides show on another; or show the one open already, taken to this deck if it
/// showed another. Whether there is one.
fn open_speaker(path: &str) -> bool {
    let url = format!("/?speaker={}", js_sys::encode_uri_component(path));
    let open = SPEAKER.with_borrow(|speaker| {
        speaker
            .clone()
            .filter(|(speaker, _)| !speaker.closed().unwrap_or(true))
    });
    if let Some((speaker, deck)) = open {
        if deck != path {
            if speaker.location().set_href(&url).is_err() {
                return false;
            }
            SPEAKER.set(Some((speaker.clone(), path.to_string())));
        }
        return speaker.focus().is_ok();
    }
    let opened = window()
        .open_with_url_and_target_and_features(&url, "_blank", "popup,width=1280,height=800")
        .ok()
        .flatten();
    let shown = opened.is_some();
    SPEAKER.set(opened.map(|speaker| (speaker, path.to_string())));
    shown
}

/// The slide of `deck` at `at`, one of the places in `order`, among the slides near it, in a stage
/// it scales to fit, as reveal.js scales slides. Each slide is drawn once it comes near and kept,
/// hidden, so that the next shows at once, its images loaded (files are served no-store: an
/// image drawn again is fetched again) and its code highlighted.
#[component]
fn Stage(
    deck: StoredValue<Vec<Vec<preview::Slide>>>,
    order: StoredValue<Vec<(usize, usize)>>,
    at: Signal<Option<(usize, usize)>>,
    class: &'static str,
) -> impl IntoView {
    let drawn = Memo::new(move |before: Option<&BTreeSet<(usize, usize)>>| {
        let mut drawn = before.cloned().unwrap_or_default();
        if let Some(at) = at.get() {
            order.with_value(|order| {
                let index = order.iter().position(|slot| *slot == at).unwrap_or(0);
                let end = (index + SLIDES_AHEAD + 1).min(order.len());
                drawn.extend(&order[index.saturating_sub(SLIDES_AHEAD)..end]);
            });
        }
        drawn
    });
    let node = NodeRef::<html::Div>::new();
    on_resize(node, |stage, width, height| {
        let scale = (width / SLIDE_SIZE.0).min(height / SLIDE_SIZE.1);
        let _ = stage
            .style()
            .set_property("--scale", &scale.max(0.05).to_string());
    });
    view! {
        <div class=format!("slides-stage {class}") node_ref=node>
            <For
                each=move || { drawn.get().into_iter().collect::<Vec<_>>() }
                key=|slot| *slot
                children=move |slot| {
                    let html = deck.with_value(|deck| deck[slot.0][slot.1].html.clone());
                    let class = if preview::image_slide(&html) {
                        "slide markdown slide-image"
                    } else {
                        "slide markdown"
                    };
                    view! {
                        <div class="slide-frame" hidden=move || at.get() != Some(slot)>
                            <Enhanced>
                                <div class=class inner_html=html></div>
                            </Enhanced>
                        </div>
                    }
                }
            />
        </div>
    }
}

const OVERVIEW: &str = "M4 4h6v6H4zM14 4h6v6h-6zM4 14h6v6H4zM14 14h6v6h-6z";
const SPEAKER_VIEW: &str = "M3 4h18v12H3zM7 20h10M12 16v4M7 8h6M7 11h10";

/// Slides, as reveal.js shows them, scaled to the space they have. The arrow keys go to the next
/// column, left and right, and to the next slide in it, up and down; Space, N and P, Page Down
/// and Up, and a swipe go through them all in order, Home and End to the first and the last. F
/// shows them full screen, O an overview, G goes to a slide by its number, and S opens the
/// speaker view, with the notes, the next slide and a clock, in a window of its own; the bar
/// shows it here too. A click on an image shows it large. Every window and device that shows
/// the deck shows one slide: this browser's other windows, and the account's pages signed in
/// elsewhere.
#[component]
fn Slides(source: String, path: String) -> impl IntoView {
    let deck = StoredValue::new(preview::slides(&source, &path));
    // Every slide's place, in order: column by column, down each.
    let order = StoredValue::new(deck.with_value(|deck| {
        deck.iter()
            .enumerate()
            .flat_map(|(column, rows)| (0..rows.len()).map(move |row| (column, row)))
            .collect::<Vec<_>>()
    }));
    let exists = move |(column, row): (usize, usize)| {
        deck.with_value(|deck| deck.get(column).is_some_and(|rows| row < rows.len()))
    };
    // The slide it was left at, if the deck still has it.
    let left = place(&path)["slide"]
        .as_array()
        .and_then(|at| {
            Some((
                at.first()?.as_u64()? as usize,
                at.get(1)?.as_u64()? as usize,
            ))
        })
        .filter(|&at| exists(at));
    let position = RwSignal::new(left.unwrap_or((0, 0)));
    let speaker = RwSignal::new(speaker_window(&path));
    let audience = Audience::of(&path);
    // Where the account showed it last, on any device, unless it shows another's presentation.
    if audience.is_none() {
        ask_where(&path);
    }
    let path = StoredValue::new(path);
    Effect::new(move || {
        let (column, row) = position.get();
        path.with_value(|path| set_place(path, serde_json::json!({ "slide": [column, row] })));
    });
    let theme = RwSignal::new(slide_theme());
    Effect::new(move || store(SLIDE_THEME, &theme.get()));
    let overview = RwSignal::new(false);
    let jumping = RwSignal::new(false);
    let enlarged = RwSignal::new(None::<String>);
    let notice = RwSignal::new(None::<&'static str>);
    // Shown by this page's keys, buttons and swipes: the other windows and devices follow, but
    // for a listener's, which pause following.
    let show = move |at: (usize, usize)| {
        if position.get_untracked() == at {
            return;
        }
        position.set(at);
        match audience {
            Some(audience) => audience.turned(at),
            None => path.with_value(|path| tell_presenting(path, at.0, at.1)),
        }
    };
    follow_presenting(path, move |column, row| {
        if exists((column, row)) && audience.is_none_or(|audience| audience.heard((column, row))) {
            position.set((column, row));
        }
    });
    // An image enlarged is the slide's it came from: turned, by whoever, it closes.
    Effect::new(move || {
        position.track();
        enlarged.set(None);
    });
    let resume = move || {
        if let Some(at) = audience.and_then(Audience::resume) {
            position.set(at);
        }
    };
    let index = move |at: (usize, usize)| {
        order.with_value(|order| order.iter().position(|slot| *slot == at).unwrap_or(0))
    };
    let go = move |right: isize, down: isize| {
        let (column, row) = position.get_untracked();
        let at = deck.with_value(|deck| {
            let last = |len: usize| len.saturating_sub(1) as isize;
            if right != 0 {
                let next = (column as isize + right).clamp(0, last(deck.len())) as usize;
                if next == column {
                    (column, row)
                } else {
                    (next, 0)
                }
            } else {
                let row = (row as isize + down).clamp(0, last(deck[column].len()));
                (column, row as usize)
            }
        });
        show(at);
    };
    // Through every slide, in order.
    let step = move |by: isize| {
        let next = index(position.get_untracked()) as isize + by;
        let at = order.with_value(|order| order[next.clamp(0, order.len() as isize - 1) as usize]);
        show(at);
    };
    let next = Memo::new(move |_| {
        let after = index(position.get()) + 1;
        order.with_value(|order| order.get(after).copied())
    });
    let say = move |text: &'static str| {
        notice.set(Some(text));
        set_timeout(
            move || {
                notice.try_set(None);
            },
            std::time::Duration::from_secs(4),
        );
    };
    let speak_elsewhere = move || {
        // The speaker view itself opens no other.
        if path.with_value(|path| speaker_window(path)) {
            return;
        }
        if !path.with_value(|path| open_speaker(path)) {
            say("Allow pop-ups for the speaker view");
        }
    };
    let keys = window_event_listener(ev::keydown, move |event| {
        if !keys_for_slides()
            || event.ctrl_key()
            || event.meta_key()
            || event.alt_key()
            || event.default_prevented()
        {
            return;
        }
        let key = event.key();
        if pressing(&key) {
            return;
        }
        match key.as_str() {
            "ArrowRight" => go(1, 0),
            "ArrowLeft" => go(-1, 0),
            "ArrowDown" => go(0, 1),
            "ArrowUp" => go(0, -1),
            "Home" => show((0, 0)),
            "End" => show(order.with_value(|order| *order.last().expect("a deck has a slide"))),
            "Enter" if overview.get_untracked() => overview.set(false),
            "o" | "O" => overview.update(|shown| *shown = !*shown),
            "g" | "G" => jumping.set(true),
            "s" | "S" => speak_elsewhere(),
            "f" | "F" => toggle_fullscreen(),
            _ => match turn_key(&event) {
                Some(by) => step(by),
                None => return,
            },
        }
        event.prevent_default();
    });
    // Escape closes an enlarged image or the overview before the viewer: it is taken before the
    // page's own handler (app.js), which closes the dialog.
    let escape =
        Closure::<dyn Fn(web_sys::KeyboardEvent)>::new(move |event: web_sys::KeyboardEvent| {
            if event.key() != "Escape" || event.default_prevented() {
                return;
            }
            if enlarged.with_untracked(Option::is_some) {
                enlarged.set(None);
            } else if overview.get_untracked() {
                overview.set(false);
            } else {
                return;
            }
            event.prevent_default();
        });
    let _ = window().add_event_listener_with_callback_and_bool(
        "keydown",
        escape.as_ref().unchecked_ref(),
        true,
    );
    let escape = StoredValue::new_local(Some(escape));
    on_cleanup(move || {
        keys.remove();
        if let Some(Some(escape)) = escape.try_update_value(Option::take) {
            let _ = window().remove_event_listener_with_callback_and_bool(
                "keydown",
                escape.as_ref().unchecked_ref(),
                true,
            );
        }
    });
    // The speaker view's clock: the time since the deck opened, which a click restarts, and the
    // time of day.
    let started = RwSignal::new(js_sys::Date::now());
    let now = RwSignal::new(js_sys::Date::now());
    let ticking = set_interval_with_handle(
        move || now.set(js_sys::Date::now()),
        std::time::Duration::from_secs(1),
    )
    .ok();
    on_cleanup(move || {
        if let Some(ticking) = ticking {
            ticking.clear();
        }
    });
    let elapsed = move || {
        let seconds = ((now.get() - started.get()) / 1000.0).max(0.0) as u64;
        let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
        if hours > 0 {
            format!("{hours}:{minutes:02}:{seconds:02}")
        } else {
            format!("{minutes:02}:{seconds:02}")
        }
    };
    let clock = move || {
        now.track();
        let date = js_sys::Date::new_0();
        format!("{:02}:{:02}", date.get_hours(), date.get_minutes())
    };
    let (smallest, usual, largest) = NOTES_SIZES;
    let notes_size = RwSignal::new(
        stored(NOTES_SIZE)
            .and_then(|size| size.parse::<u32>().ok())
            .unwrap_or(usual)
            .clamp(smallest, largest),
    );
    Effect::new(move || store(NOTES_SIZE, &notes_size.get().to_string()));
    let resize_notes = move |by: i32| {
        notes_size.update(|size| *size = size.saturating_add_signed(by).clamp(smallest, largest))
    };
    let notes = move || {
        let (column, row) = position.get();
        deck.with_value(|deck| deck[column][row].notes.clone())
    };
    let numbered = move |(column, row): (usize, usize)| {
        deck.with_value(|deck| match deck[column].len() {
            1 => (column + 1).to_string(),
            _ => format!("{}.{}", column + 1, row + 1),
        })
    };
    // The overview shows where the deck is, as it moves.
    let grid = NodeRef::<html::Div>::new();
    Effect::new(move || {
        position.track();
        if let (true, Some(grid)) = (overview.get(), grid.get()) {
            request_animation_frame(move || {
                if let Ok(Some(current)) = grid.query_selector(".slides-thumb.current") {
                    let options = web_sys::ScrollIntoViewOptions::new();
                    options.set_block(web_sys::ScrollLogicalPosition::Nearest);
                    current.scroll_into_view_with_scroll_into_view_options(&options);
                }
            });
        }
    });
    let jump = NodeRef::<html::Input>::new();
    Effect::new(move || {
        if let Some(input) = jump.get() {
            let _ = input.focus();
        }
    });
    let go_to = move |text: String| {
        jumping.set(false);
        match preview::slide_number(&text).filter(|&at| exists(at)) {
            Some(at) => show(at),
            None if text.trim().is_empty() => {}
            None => say("No such slide"),
        }
    };
    // An image clicked in the slide shown shows large, but for one a slide shows already whole
    // and one that is a link.
    let enlarge = move |event: ev::MouseEvent| {
        let Some(image) = event
            .target()
            .and_then(|target| target.dyn_into::<Element>().ok())
            .filter(|target| target.tag_name() == "IMG")
        else {
            return;
        };
        let elsewhere = image.closest(".slides-current").ok().flatten().is_none();
        if elsewhere || image.closest("a, .slide-image").ok().flatten().is_some() {
            return;
        }
        enlarged.set(image.get_attribute("src"));
    };
    let swipe = Swipe::new();
    // The keys are the slides' from the start, not the viewer bar's first button's, which the
    // dialog focused (Space would press it).
    let body = NodeRef::<html::Div>::new();
    Effect::new(move || {
        if let Some(body) = body.get() {
            let _ = body.focus();
        }
    });
    let can = move |right: isize, down: isize| {
        let (column, row) = position.get();
        deck.with_value(|deck| match (right, down) {
            (-1, _) => column > 0,
            (1, _) => column + 1 < deck.len(),
            (_, -1) => row > 0,
            _ => row + 1 < deck[column].len(),
        })
    };
    let counter = move || {
        if let Some(notice) = notice.get() {
            return notice.to_string();
        }
        let (column, row) = position.get();
        deck.with_value(|deck| match deck[column].len() {
            1 => format!("{} / {}", column + 1, deck.len()),
            rows => format!("{} / {} · {} / {rows}", column + 1, deck.len(), row + 1),
        })
    };
    let button = move |label: &'static str, path: &'static str, right: isize, down: isize| {
        // Phones have no room for up and down; a swipe goes through the slides below others.
        let class = if down == 0 {
            "preview-button"
        } else {
            "preview-button slides-vertical"
        };
        view! {
            <button
                class=class
                title=label
                aria-label=label
                disabled=move || !can(right, down)
                on:click=move |_| go(right, down)
            >
                {icon(path)}
            </button>
        }
    };
    // Up and down only for a deck with slides below others.
    let vertical = deck.with_value(|deck| deck.iter().any(|rows| rows.len() > 1));
    view! {
        <div class="slides" class:speaking=move || speaker.get() data-theme=move || theme.get()>
            <div
                class="slides-body"
                tabindex="-1"
                node_ref=body
                on:click=enlarge
                on:pointerdown=move |event| swipe.start(&event)
                on:pointercancel=move |_| swipe.cancel()
                on:pointerup=move |event| {
                    let by = swipe.end(&event);
                    if by != 0 && !overview.get_untracked() {
                        step(by);
                    }
                }
            >
                <Stage deck order at=Signal::derive(move || Some(position.get())) class="slides-current" />
                {move || {
                    speaker.get().then(|| view! {
                        <aside class="slides-speaker" aria-label="Speaker view">
                            <div class="slides-time">
                                <button class="slides-elapsed" title="Restart the timer" aria-label="Restart the timer" on:click=move |_| started.set(js_sys::Date::now())>
                                    {elapsed}
                                </button>
                                <span class="slides-clock">{clock}</span>
                            </div>
                            <div class="slides-upcoming" aria-label="Next slide">
                                <Stage deck order at=Signal::derive(move || next.get()) class="slides-next" />
                                {move || next.get().is_none().then(|| view! { <p class="slides-end">"End of the deck"</p> })}
                            </div>
                            <div class="slides-notes-bar">
                                <span>"Notes"</span>
                                <button class="preview-button" aria-label="Smaller notes" title="Smaller notes" on:click=move |_| resize_notes(-2)>"A−"</button>
                                <button class="preview-button" aria-label="Larger notes" title="Larger notes" on:click=move |_| resize_notes(2)>"A+"</button>
                            </div>
                            <div class="slides-notes" style=move || format!("font-size:{}px", notes_size.get())>
                                {move || {
                                    let html = notes();
                                    if html.is_empty() {
                                        view! { <p class="slides-no-notes">"No notes for this slide."</p> }.into_any()
                                    } else {
                                        view! { <Enhanced><div class="markdown" inner_html=html></div></Enhanced> }.into_any()
                                    }
                                }}
                            </div>
                        </aside>
                    })
                }}
                {move || {
                    overview.get().then(|| {
                        let thumbs = order
                            .get_value()
                            .into_iter()
                            .map(|at| {
                                let html = deck.with_value(|deck| deck[at.0][at.1].html.clone());
                                let class = if preview::image_slide(&html) {
                                    "slide markdown slide-image"
                                } else {
                                    "slide markdown"
                                };
                                let number = numbered(at);
                                view! {
                                    <button
                                        class="slides-thumb"
                                        class:current=move || position.get() == at
                                        aria-label=format!("Slide {number}")
                                        on:click=move |_| {
                                            show(at);
                                            overview.set(false);
                                        }
                                    >
                                        <div class=class inner_html=html></div>
                                        <span class="slides-number">{number.clone()}</span>
                                    </button>
                                }
                            })
                            .collect_view();
                        view! { <div class="slides-overview" node_ref=grid>{thumbs}</div> }
                    })
                }}
                {move || {
                    enlarged.get().map(|src| view! {
                        <div class="slides-enlarged" title="Close · Esc" on:click=move |_| enlarged.set(None)>
                            <img src=src alt="The image, enlarged" />
                        </div>
                    })
                }}
            </div>
            <div class="slides-bar">
                <div class="slides-tools">
                    <button class="preview-button" title="Overview · O" aria-label="Overview" aria-pressed=move || overview.get().to_string() on:click=move |_| overview.update(|shown| *shown = !*shown)>
                        {icon(OVERVIEW)}
                    </button>
                    <button class="preview-button" title="Speaker view; S opens it in a window" aria-label="Speaker view" aria-pressed=move || speaker.get().to_string() on:click=move |_| speaker.update(|shown| *shown = !*shown)>
                        {icon(SPEAKER_VIEW)}
                    </button>
                    {audience.map(|audience| audience.badge(resume))}
                    <LiveControls path=path audience=audience />
                </div>
                {button("Previous slide", PREVIOUS, -1, 0)}
                {vertical.then(|| button("Slide above", UP, 0, -1))}
                {move || {
                    if jumping.get() {
                        view! {
                            <input
                                class="slides-jump"
                                aria-label="Go to slide"
                                placeholder="3 or 3.2"
                                enterkeyhint="go"
                                node_ref=jump
                                on:keydown=move |event| match event.key().as_str() {
                                    "Enter" => {
                                        event.prevent_default();
                                        go_to(event_target_value(&event));
                                    }
                                    "Escape" => {
                                        event.prevent_default();
                                        jumping.set(false);
                                    }
                                    _ => {}
                                }
                                on:blur=move |_| jumping.set(false)
                            />
                        }
                        .into_any()
                    } else {
                        view! {
                            <button class="slides-counter" title="Go to slide · G" on:click=move |_| jumping.set(true)>
                                <span role="status">{counter}</span>
                            </button>
                        }
                        .into_any()
                    }
                }}
                {vertical.then(|| button("Slide below", DOWN, 0, 1))}
                {button("Next slide", NEXT, 1, 0)}
                <select class="slides-theme" aria-label="Slide theme" prop:value=move || theme.get() on:change=move |e| theme.set(event_target_value(&e))>
                    {SLIDE_THEMES.iter().map(|(value, label)| view! { <option value=*value>{*label}</option> }).collect_view()}
                </select>
            </div>
        </div>
    }
}

/// The most pixels wide a PDF page is drawn: past that, the memory pages take outgrows what is
/// seen of them.
const PDF_PIXELS: f64 = 2000.0;
/// The most pixels wide a page is drawn presented, alone on a screen, which may be a 4K one.
const PDF_PRESENT_PIXELS: f64 = 3840.0;
/// How far the view zooms out and in, from the stage's width.
const PDF_ZOOM: (f64, f64) = (0.5, 3.0);

/// A PDF as one document that scrolls. Every page has its place, at its size, from the start;
/// a worker draws the pages near the view, one at a time, and those far from it are let go,
/// so that a long document takes the memory of a few pages. The toolbar says which page is in
/// view, goes to the one before or after it, and zooms. Presented, a slide deck made a PDF, it
/// shows one page at a time, filling the view, turned as slides are, which the other windows
/// and devices showing it follow.
#[component]
fn PdfView(data: Arc<Vec<u8>>, path: String) -> impl IntoView {
    let pages = RwSignal::new(Vec::<(f64, f64)>::new());
    let failure = RwSignal::new(None::<String>);
    // Where it was left: its page and zoom, and whether it was presented.
    let left = place(&path);
    let audience = Audience::of(&path);
    let path = StoredValue::new(path);
    let presenting = RwSignal::new(left["present"] == true || audience.is_some());
    let current = RwSignal::new(0usize);
    // The page it starts at, once its pages are known: where it was left, or where it is
    // presented, as heard while it was read.
    let start = StoredValue::new(left["page"].as_u64().unwrap_or(0) as usize);
    let zoom = RwSignal::new(
        left["zoom"]
            .as_f64()
            .unwrap_or(1.0)
            .clamp(PDF_ZOOM.0, PDF_ZOOM.1),
    );
    let document = StoredValue::new(None::<workers::Pdf>);
    let stage = NodeRef::<html::Div>::new();
    // The pages near the view, and the width in pixels each one is drawn at.
    let near = StoredValue::new(BTreeSet::<usize>::new());
    let drawn = StoredValue::new(BTreeMap::<usize, u32>::new());
    let drawing = StoredValue::new(false);
    spawn_local(async move {
        match workers::open_pdf(&data).await {
            Ok((pdf, sizes)) => {
                if document.try_set_value(Some(pdf)).is_some() {
                    workers::close_pdf(pdf);
                    return;
                }
                pages.try_set(sizes);
            }
            Err(e) => {
                failure.try_set(Some(format!("Could not open PDF: {e}")));
            }
        }
    });
    let frame = move |index: usize| -> Option<HtmlElement> {
        stage
            .get_untracked()?
            .query_selector(&format!(".pdf-frame[data-index=\"{index}\"]"))
            .ok()
            .flatten()
            .map(JsCast::unchecked_into)
    };
    let canvas = move |index: usize| -> Option<HtmlCanvasElement> {
        frame(index)?
            .query_selector("canvas")
            .ok()
            .flatten()
            .map(JsCast::unchecked_into)
    };
    let release = move |index: usize| {
        if let Some(canvas) = canvas(index) {
            canvas.set_width(0);
            canvas.set_height(0);
        }
        drawn.update_value(|drawn| {
            drawn.remove(&index);
        });
    };
    // Draw what is near and not drawn at its width, nearest the page in view first, until
    // nothing is left; one drawing at a time, as the pages come and go meanwhile.
    let draw = move || {
        if drawing.get_value() {
            return;
        }
        drawing.set_value(true);
        spawn_local(async move {
            let ratio = window().device_pixel_ratio().min(2.0);
            while let Some(pdf) = document.try_get_value().flatten() {
                let wanted = near.with_value(|near| {
                    near.iter()
                        .filter_map(|&index| {
                            let width = frame(index)?.client_width();
                            let pixels = (f64::from(width) * ratio).min(PDF_PIXELS).round() as u32;
                            (pixels > 0 && drawn.with_value(|d| d.get(&index) != Some(&pixels)))
                                .then_some((index, pixels))
                        })
                        .min_by_key(|(index, _)| index.abs_diff(current.get_untracked()))
                });
                let Some((index, pixels)) = wanted else {
                    break;
                };
                let image = workers::render_pdf(pdf, index, pixels).await;
                if !near
                    .try_with_value(|near| near.contains(&index))
                    .unwrap_or(false)
                {
                    continue;
                }
                match image.and_then(|image| paint(canvas(index), &image)) {
                    Ok(()) => drawn.update_value(|drawn| {
                        drawn.insert(index, pixels);
                    }),
                    Err(e) => {
                        failure.set(Some(format!("PDF rendering failed: {e}")));
                        break;
                    }
                }
            }
            let _ = drawing.try_set_value(false);
        });
    };
    // Which pages are near the view, within a screen of it.
    let seen = Closure::<dyn FnMut(js_sys::Array)>::new(move |entries: js_sys::Array| {
        for entry in entries.iter() {
            let entry: web_sys::IntersectionObserverEntry = entry.unchecked_into();
            let Some(index) = entry
                .target()
                .get_attribute("data-index")
                .and_then(|index| index.parse::<usize>().ok())
            else {
                continue;
            };
            if entry.is_intersecting() {
                near.update_value(|near| {
                    near.insert(index);
                });
            } else {
                near.update_value(|near| {
                    near.remove(&index);
                });
                release(index);
            }
        }
        draw();
    });
    let seen = StoredValue::new_local(Some(seen));
    let observer = StoredValue::new_local(None::<web_sys::IntersectionObserver>);
    Effect::new(move || {
        let count = pages.with(Vec::len);
        let Some(stage) = stage.get() else {
            return;
        };
        if count == 0 || observer.with_value(Option::is_some) {
            return;
        }
        let options = web_sys::IntersectionObserverInit::new();
        options.set_root(Some(&stage));
        options.set_root_margin("100% 0px");
        let Some(Ok(watching)) = seen.with_value(|seen| {
            seen.as_ref().map(|seen| {
                web_sys::IntersectionObserver::new_with_options(
                    seen.as_ref().unchecked_ref(),
                    &options,
                )
            })
        }) else {
            return;
        };
        if let Ok(frames) = stage.query_selector_all(".pdf-frame") {
            for index in 0..frames.length() {
                if let Some(frame) = frames.item(index) {
                    watching.observe(frame.unchecked_ref());
                }
            }
        }
        observer.set_value(Some(watching));
        let _ = stage.focus();
        // Back to the page it was left at, once the pages are laid out.
        let page = start.get_value().min(count - 1);
        if page > 0 {
            request_animation_frame(move || {
                if let Some(frame) = frame(page) {
                    frame.scroll_into_view();
                    current.set(page);
                }
            });
        }
    });
    Effect::new(move || {
        let (page, level, presented) = (current.get(), zoom.get(), presenting.get());
        if pages.with(|pages| !pages.is_empty()) {
            let place = serde_json::json!({ "page": page, "zoom": level, "present": presented });
            path.with_value(|path| set_place(path, place));
        }
    });
    // A new zoom draws the pages in view at their new width, and keeps the page in view.
    Effect::new(move |previous: Option<f64>| {
        let level = zoom.get();
        if previous.is_some_and(|previous| previous != level) {
            if let Some(frame) = frame(current.get_untracked()) {
                frame.scroll_into_view();
            }
            draw();
        }
        level
    });
    on_cleanup(move || {
        if let Some(Some(observer)) = observer.try_get_value() {
            observer.disconnect();
        }
        let _ = seen.try_update_value(Option::take);
        if let Some(Some(pdf)) = document.try_get_value() {
            workers::close_pdf(pdf);
        }
    });
    // The page in view: the last one whose top is above a third of the stage.
    let scrolled = move |_| {
        let Some(stage) = stage.get_untracked() else {
            return;
        };
        let line = stage.scroll_top() + stage.client_height() / 3;
        let count = pages.with_untracked(Vec::len);
        let page = (0..count)
            .take_while(|&index| frame(index).is_some_and(|frame| frame.offset_top() <= line))
            .last()
            .unwrap_or(0);
        if current.get_untracked() != page {
            current.set(page);
        }
    };
    // Turned here, presenting: the other windows and devices follow, but for a listener's turns,
    // which pause following.
    let turn = move |page: usize| {
        let page = page.min(pages.with_untracked(Vec::len).saturating_sub(1));
        if current.get_untracked() == page {
            return;
        }
        current.set(page);
        match audience {
            Some(audience) => audience.turned((page, 0)),
            None => path.with_value(|path| tell_presenting(path, page, 0)),
        }
    };
    // Presented, it opens where the account showed it last, on any device.
    Effect::new(move |_| {
        if presenting.get() && audience.is_none() {
            path.with_value(|path| ask_where(path));
        }
    });
    let go = move |page: usize| {
        if presenting.get_untracked() {
            turn(page);
        } else if let Some(frame) = frame(page) {
            frame.scroll_into_view();
            current.set(page);
        }
    };
    follow_presenting(path, move |page, _| {
        if !presenting.get_untracked() || !audience.is_none_or(|audience| audience.heard((page, 0)))
        {
            return;
        }
        match pages.with_untracked(Vec::len) {
            0 => start.set_value(page),
            count if page < count => current.set(page),
            _ => {}
        }
    });
    let keys = window_event_listener(ev::keydown, move |event| {
        if !presenting.get_untracked()
            || !keys_for_slides()
            || event.ctrl_key()
            || event.meta_key()
            || event.alt_key()
            || event.default_prevented()
        {
            return;
        }
        let key = event.key();
        if pressing(&key) {
            return;
        }
        let page = current.get_untracked();
        match key.as_str() {
            "ArrowRight" | "ArrowDown" => turn(page + 1),
            "ArrowLeft" | "ArrowUp" => turn(page.saturating_sub(1)),
            "Home" => turn(0),
            "End" => turn(usize::MAX),
            "f" | "F" => toggle_fullscreen(),
            _ => match turn_key(&event) {
                Some(1) => turn(page + 1),
                Some(_) => turn(page.saturating_sub(1)),
                None => return,
            },
        }
        event.prevent_default();
    });
    on_cleanup(move || keys.remove());
    // Presented: the page shown, drawn as wide as it shows, and those either side, drawn ahead
    // to turn to at once.
    let screen = NodeRef::<html::Canvas>::new();
    let shown = NodeRef::<html::Div>::new();
    let room = RwSignal::new((0.0, 0.0));
    on_resize(shown, move |_, width, height| room.set((width, height)));
    let ready = StoredValue::new_local(BTreeMap::<usize, (u32, web_sys::ImageData)>::new());
    let readying = StoredValue::new(false);
    let present_width = move |index: usize| -> u32 {
        let (width, height) = room.get_untracked();
        let Some((page_width, page_height)) =
            pages.with_untracked(|pages| pages.get(index).copied())
        else {
            return 0;
        };
        let fit = width.min(height * page_width / page_height);
        let pixels = fit * window().device_pixel_ratio();
        pixels.clamp(0.0, PDF_PRESENT_PIXELS).round() as u32
    };
    let show_ready = move || {
        let page = current.get_untracked();
        if let Some(Some(image)) =
            ready.try_with_value(|ready| ready.get(&page).map(|(_, image)| image.clone()))
            && let Err(e) = paint(screen.get_untracked(), &image)
        {
            failure.set(Some(format!("PDF rendering failed: {e}")));
        }
    };
    let draw_ahead = move || {
        if readying.get_value() {
            return;
        }
        readying.set_value(true);
        spawn_local(async move {
            while let Some(pdf) = document.try_get_value().flatten() {
                if !presenting.get_untracked() {
                    break;
                }
                let page = current.get_untracked();
                let count = pages.with_untracked(Vec::len);
                // The page shown first, then the next, then the one before.
                let wanted = [Some(page), Some(page + 1), page.checked_sub(1)]
                    .into_iter()
                    .flatten()
                    .filter(|&index| index < count)
                    .map(|index| (index, present_width(index)))
                    .find(|&(index, pixels)| {
                        pixels > 0
                            && ready.with_value(|ready| {
                                ready.get(&index).map(|(drawn, _)| *drawn) != Some(pixels)
                            })
                    });
                let Some((index, pixels)) = wanted else {
                    break;
                };
                match workers::render_pdf(pdf, index, pixels).await {
                    Ok(image) => {
                        // The view may have closed while the page was drawn.
                        let Some(page) = current.try_get_untracked() else {
                            return;
                        };
                        let kept = ready.try_update_value(|ready| {
                            ready.insert(index, (pixels, image));
                            ready.retain(|&kept, _| kept.abs_diff(page) <= 1);
                        });
                        if kept.is_none() {
                            return;
                        }
                        if index == page {
                            show_ready();
                        }
                    }
                    Err(e) => {
                        failure.try_set(Some(format!("PDF rendering failed: {e}")));
                        break;
                    }
                }
            }
            let _ = readying.try_set_value(false);
        });
    };
    Effect::new(move || {
        let _ = (current.get(), room.get());
        if presenting.get() && pages.with(|pages| !pages.is_empty()) {
            show_ready();
            draw_ahead();
        }
    });
    // Back to scrolling, at the page it was presenting.
    Effect::new(move |before: Option<bool>| {
        let now = presenting.get();
        if before == Some(true) && !now {
            request_animation_frame(move || {
                if let Some(frame) = frame(current.get_untracked()) {
                    frame.scroll_into_view();
                }
                draw();
            });
        }
        now
    });
    let swipe = Swipe::new();
    let count = move || pages.with(Vec::len);
    let zoom_by = move |factor: f64| {
        zoom.update(|zoom| *zoom = (*zoom * factor).clamp(PDF_ZOOM.0, PDF_ZOOM.1));
    };
    let present_label = move || {
        if presenting.get() {
            "Scroll the pages"
        } else {
            "Present one page at a time"
        }
    };
    let resume = move || {
        if let Some((page, _)) = audience.and_then(Audience::resume) {
            current.set(page);
        }
    };
    view! {
        <div class="pdf-view" class:presenting=move || presenting.get()>
            <div class="pdf-toolbar">
                <div class="pdf-tools">
                    {audience.map(|audience| audience.badge(resume))}
                    <button
                        class="pdf-present-button"
                        title=present_label
                        aria-label=present_label
                        aria-pressed=move || presenting.get().to_string()
                        on:click=move |_| presenting.update(|presenting| *presenting = !*presenting)
                    >
                        {move || icon(if presenting.get() { AS_DOCUMENT } else { AS_SLIDES })}
                    </button>
                    <LiveControls path=path audience=audience />
                </div>
                <button
                    aria-label="Previous page"
                    disabled=move || current.get() == 0
                    on:click=move |_| go(current.get_untracked().saturating_sub(1))
                >
                    "↑"
                </button>
                <span role="status">
                    {move || {
                        failure
                            .get()
                            .unwrap_or_else(|| match count() {
                                0 => "Loading PDF...".into(),
                                count => format!("{} / {count}", current.get() + 1),
                            })
                    }}
                </span>
                <button
                    aria-label="Next page"
                    disabled=move || { current.get() + 1 >= count() }
                    on:click=move |_| go(current.get_untracked() + 1)
                >
                    "↓"
                </button>
                <span class="pdf-zoom" hidden=move || presenting.get()>
                    <button aria-label="Zoom out" disabled=move || { zoom.get() <= PDF_ZOOM.0 } on:click=move |_| zoom_by(1.0 / 1.25)>"−"</button>
                    <button aria-label="Fit width" on:click=move |_| zoom.set(1.0)>{move || format!("{:.0}%", zoom.get() * 100.0)}</button>
                    <button aria-label="Zoom in" disabled=move || { zoom.get() >= PDF_ZOOM.1 } on:click=move |_| zoom_by(1.25)>"+"</button>
                </span>
            </div>
            <div
                class="pdf-present"
                node_ref=shown
                hidden=move || !presenting.get()
                on:pointerdown=move |event| swipe.start(&event)
                on:pointercancel=move |_| swipe.cancel()
                on:pointerup=move |event| match swipe.end(&event) {
                    0 => {}
                    by => turn((current.get_untracked() as isize + by).max(0) as usize),
                }
            >
                <canvas class="pdf-slide" node_ref=screen aria-label=move || format!("Presented page {}", current.get() + 1)></canvas>
            </div>
            <div
                class="pdf-stage"
                tabindex="0"
                hidden=move || presenting.get()
                node_ref=stage
                style=move || format!("--pdf-zoom:{}", zoom.get())
                on:scroll=scrolled
            >
                {move || {
                    pages
                        .get()
                        .into_iter()
                        .enumerate()
                        .map(|(index, (width, height))| {
                            view! {
                                <div class="pdf-frame" data-index=index style=format!("aspect-ratio:{width}/{height}")>
                                    <canvas class="pdf-page" aria-label=format!("PDF page {}", index + 1)></canvas>
                                </div>
                            }
                        })
                        .collect_view()
                }}
            </div>
        </div>
    }
}

/// Paint `image`, a page as the worker drew it, into `canvas`, which the page's frame sizes.
fn paint(canvas: Option<HtmlCanvasElement>, image: &web_sys::ImageData) -> Result<(), String> {
    let canvas = canvas.ok_or("the page is gone")?;
    canvas.set_width(image.width());
    canvas.set_height(image.height());
    let context: CanvasRenderingContext2d = canvas
        .get_context("2d")
        .map_err(js_error)?
        .ok_or("no 2D context")?
        .unchecked_into();
    context.put_image_data(image, 0.0, 0.0).map_err(js_error)
}

/// `bytes`, in the largest unit they make at least one of.
pub(crate) fn size(bytes: u64) -> String {
    match bytes {
        0..1_000 => format!("{bytes} B"),
        1_000..1_000_000 => format!("{:.1} KB", bytes as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.1} MB", bytes as f64 / 1e6),
        _ => format!("{:.1} GB", bytes as f64 / 1e9),
    }
}

fn table_view(table: preview::Table) -> AnyView {
    let mut rows = table.rows.into_iter();
    let header = rows.next().unwrap_or_default();
    view! {
        <div class="table-preview">
            <table>
                <thead>
                    <tr>{header.into_iter().map(|cell| view! { <th>{cell}</th> }).collect_view()}</tr>
                </thead>
                <tbody>
                    {rows
                        .map(|row| {
                            view! {
                                <tr>{row.into_iter().map(|cell| view! { <td>{cell}</td> }).collect_view()}</tr>
                            }
                        })
                        .collect_view()}
                </tbody>
            </table>
            {table
                .more
                .then(|| {
                    view! {
                        <p class="preview-note">
                            {format!("Only the first {} rows show.", preview::ROWS_MAX)}
                        </p>
                    }
                })}
        </div>
    }
    .into_any()
}

/// The members of the archive `data`, as its worker lists them.
#[component]
fn ArchiveView(data: Vec<u8>) -> impl IntoView {
    let listed = RwSignal::new(None::<Result<(Vec<preview::Entry>, bool), String>>);
    spawn_local(async move {
        let result = workers::list_archive(&data).await;
        listed.try_set(Some(result));
    });
    move || match listed.get() {
        None => view! { <p class="preview-note">"Listing the archive..."</p> }.into_any(),
        Some(Ok((entries, more))) => archive_view(entries, more),
        Some(Err(e)) => view! {
            <div class="media-frame">
                <p class="no-preview">{format!("Could not list the archive: {e}")}</p>
            </div>
        }
        .into_any(),
    }
}

/// `entries`, and whether the archive has more, which do not show.
fn archive_view(entries: Vec<preview::Entry>, more: bool) -> AnyView {
    let files = entries.iter().filter(|entry| !entry.directory).count();
    let total: u64 = entries.iter().map(|entry| entry.size).sum();
    let first = if more { "The first " } else { "" };
    view! {
        <div class="archive">
            <p class="preview-note">{format!("{first}{files} files, {} unpacked", size(total))}</p>
            <ul>
                {entries
                    .into_iter()
                    .map(|entry| {
                        let length = if entry.directory { String::new() } else { size(entry.size) };
                        view! {
                            <li class:directory=entry.directory>
                                <span>{entry.path}</span>
                                <span>{length}</span>
                            </li>
                        }
                    })
                    .collect_view()}
            </ul>
        </div>
    }
    .into_any()
}

fn cards_view(cards: Vec<preview::Card>) -> AnyView {
    if cards.is_empty() {
        return no_preview();
    }
    view! {
        <div class="cards">
            {cards
                .into_iter()
                .map(|card| {
                    let title = if card.title.is_empty() { "Untitled".to_string() } else { card.title };
                    view! {
                        <section class="card">
                            <h3>{title}</h3>
                            <dl>
                                {card
                                    .fields
                                    .into_iter()
                                    .map(|(label, value)| view! { <dt>{label}</dt><dd>{value}</dd> })
                                    .collect_view()}
                            </dl>
                        </section>
                    }
                })
                .collect_view()}
        </div>
    }
    .into_any()
}

fn diff_view(lines: Vec<(DiffLine, String)>) -> AnyView {
    view! {
        <pre class="text-preview diff">
            {lines
                .into_iter()
                .map(|(kind, line)| {
                    let class = match kind {
                        DiffLine::File => "diff-file",
                        DiffLine::Hunk => "diff-hunk",
                        DiffLine::Added => "diff-added",
                        DiffLine::Removed => "diff-removed",
                        DiffLine::Context => "diff-context",
                    };
                    view! { <span class=class>{line}</span> }
                })
                .collect_view()}
        </pre>
    }
    .into_any()
}
