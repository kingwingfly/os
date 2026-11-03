//! What web/upload.mjs and web/record.mjs need from Rust, as `window.terminalUploads`: the
//! chunk size, SHA-256 hashes of files read slice by slice, which resume uploads and let R2
//! check every chunk, and setfacl, for a recording made with ACL entries.

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

/// `setfacl -m entries path`, as user space runs it: None if done, or why not, for a recording
/// made with ACL entries (stream -m), which is not made without them.
fn setfacl(path: String, entries: String) -> js_sys::Promise {
    wasm_bindgen_futures::future_to_promise(async move {
        let cancelled = || false;
        let ask =
            |_: String| -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<String>>>> {
                Box::pin(async { None })
            };
        let mut io = userland::Io {
            args: vec!["setfacl".into(), "-m".into(), entries, path],
            cwd: "/".into(),
            home: "/".into(),
            now: (js_sys::Date::now() / 1000.0) as u64,
            stdin: None,
            out: String::new(),
            err: Vec::new(),
            view: None,
            found: Vec::new(),
            cancelled: &cancelled,
            ask: &ask,
        };
        let status = userland::run(&crate::sys::HttpSys::default(), &mut io)
            .await
            .unwrap_or(1);
        Ok(if status == 0 {
            JsValue::NULL
        } else {
            JsValue::from_str(&io.err.join("; "))
        })
    })
}

/// Make `window.terminalUploads`.
pub fn register() {
    let digest =
        Closure::<dyn Fn(js_sys::Uint8Array) -> String>::new(|bytes: js_sys::Uint8Array| {
            hex(&Sha256::digest(bytes.to_vec()))
        });
    let new_hasher = Closure::<dyn Fn() -> js_sys::Object>::new(hasher);
    let acl = Closure::<dyn Fn(String, String) -> js_sys::Promise>::new(setfacl);
    let api = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&api, &"sha256".into(), &digest.into_js_value());
    let _ = js_sys::Reflect::set(&api, &"hasher".into(), &new_hasher.into_js_value());
    let _ = js_sys::Reflect::set(&api, &"setfacl".into(), &acl.into_js_value());
    let _ = js_sys::Reflect::set(
        &api,
        &"chunkSize".into(),
        &JsValue::from_f64(terminal_worker_core::CHUNK_SIZE as f64),
    );
    let _ = js_sys::Reflect::set(
        &api,
        &"maxFile".into(),
        &JsValue::from_f64(terminal_worker_core::MAX_FILE as f64),
    );
    if let Some(window) = web_sys::window() {
        let _ = js_sys::Reflect::set(&window, &JsValue::from_str("terminalUploads"), &api);
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
