//! What `web/upload.mjs` and `web/gui/media-broker.js` need from Rust as `window.osUploads`:
//! the chunk size, max file size, and SHA-256 hashing of files read slice by slice.

use std::cell::RefCell;
use std::rc::Rc;

use sha2::{Digest, Sha256};
use wasm_bindgen::{JsValue, closure::Closure};

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// A hasher as a JavaScript object: `update(bytes)`, then `hex()`, which finishes it.
fn hasher() -> js_sys::Object {
    let state = Rc::new(RefCell::new(Some(Sha256::new())));
    let update = {
        let state = state.clone();
        Closure::<dyn Fn(js_sys::Uint8Array)>::new(move |bytes: js_sys::Uint8Array| {
            if let Some(hasher) = state.borrow_mut().as_mut() {
                hasher.update(bytes.to_vec());
            }
        })
    };
    let finish = Closure::<dyn Fn() -> String>::new(move || {
        state
            .borrow_mut()
            .take()
            .map(|hasher| hex(&hasher.finalize()))
            .unwrap_or_default()
    });
    let object = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&object, &"update".into(), &update.into_js_value());
    let _ = js_sys::Reflect::set(&object, &"hex".into(), &finish.into_js_value());
    object
}

/// Make `window.osUploads`.
pub fn register() {
    let digest =
        Closure::<dyn Fn(js_sys::Uint8Array) -> String>::new(|bytes: js_sys::Uint8Array| {
            hex(&Sha256::digest(bytes.to_vec()))
        });
    let new_hasher = Closure::<dyn Fn() -> js_sys::Object>::new(hasher);
    let api = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&api, &"sha256".into(), &digest.into_js_value());
    let _ = js_sys::Reflect::set(&api, &"hasher".into(), &new_hasher.into_js_value());
    let _ = js_sys::Reflect::set(
        &api,
        &"chunkSize".into(),
        &JsValue::from_f64(os_core::CHUNK_SIZE as f64),
    );
    let _ = js_sys::Reflect::set(
        &api,
        &"maxFile".into(),
        &JsValue::from_f64(os_core::MAX_FILE as f64),
    );
    if let Some(window) = web_sys::window() {
        let _ = js_sys::Reflect::set(&window, &JsValue::from_str("osUploads"), &api);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_lowercase_hex() {
        assert_eq!(
            hex(&Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
