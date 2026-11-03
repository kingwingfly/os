//! What web/app.js's man needs from Rust, as `window.terminalManual`: the pages, made from the
//! commands' definitions in [`terminal_worker_core::cli`], as Markdown for the viewer.

use wasm_bindgen::{JsValue, closure::Closure};

/// Make `window.terminalManual`: `page(name)`, a command's page, or undefined for one there is
/// none of; `index()`, the index and how the terminal works; `bin(name)`, whether /bin has a
/// program of that name.
pub fn register() {
    let page = Closure::<dyn Fn(String) -> Option<String>>::new(|name: String| {
        terminal_worker_core::cli::page(&name)
    });
    let index = Closure::<dyn Fn() -> String>::new(terminal_worker_core::cli::index);
    let bin = Closure::<dyn Fn(String) -> bool>::new(|name: String| {
        terminal_worker_core::bin::program(&name).is_some()
    });
    let api = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&api, &"page".into(), &page.into_js_value());
    let _ = js_sys::Reflect::set(&api, &"index".into(), &index.into_js_value());
    let _ = js_sys::Reflect::set(&api, &"bin".into(), &bin.into_js_value());
    if let Some(window) = web_sys::window() {
        let _ = js_sys::Reflect::set(&window, &JsValue::from_str("terminalManual"), &api);
    }
}
