//! Streams of file bytes, piped by the runtime rather than copied through WebAssembly.
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use wasm_bindgen::prelude::*;
use worker::wasm_bindgen_futures::future_to_promise;
use worker::*;

#[wasm_bindgen(inline_js = "
export async function discardStream(body, length) {
  if (!body) { if (length) throw new Error('missing body'); return; }
  const reader = body.getReader();
  let received = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > length) throw new Error('body exceeds declared length');
    }
    if (received !== length) throw new Error('truncated body');
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally { reader.releaseLock(); }
}
")]
extern "C" {
    /// Consume an authorized null-device write with bounded memory, without R2 storage.
    #[wasm_bindgen(catch, js_name = discardStream)]
    pub async fn discard_stream(body: JsValue, length: f64) -> std::result::Result<(), JsValue>;
}

#[wasm_bindgen(inline_js = "
export function concatenate(next) {
  const { readable, writable } = new TransformStream();
  (async () => {
    try {
      for (;;) {
        const part = await next();
        if (!part) break;
        await part.pipeTo(writable, { preventClose: true });
      }
      await writable.close();
    } catch (error) {
      await writable.abort(error).catch(() => {});
    }
  })();
  return readable;
}
")]
extern "C" {
    /// One stream of the streams `next` resolves to, in order, until it resolves to null.
    pub fn concatenate(next: &js_sys::Function) -> web_sys::ReadableStream;
}

// A snippet of its own: wasm-bindgen 0.2.129 names a snippet in the Worker's imports once per
// function the module imports from it directly, which esbuild warns of as a duplicate key.
#[wasm_bindgen(inline_js = "
export function fixedLength(body, length) {
  const { readable, writable } = new FixedLengthStream(length);
  body.pipeTo(writable).catch(() => {});
  return readable;
}
")]
extern "C" {
    /// `body`, which must be exactly `length` bytes, as a stream R2 accepts.
    #[wasm_bindgen(js_name = fixedLength)]
    pub fn fixed_length(body: &web_sys::ReadableStream, length: f64) -> web_sys::ReadableStream;
}

/// `length` bytes of the R2 object `key`, from `offset`.
pub async fn object_range(
    bucket: &Bucket,
    key: &str,
    offset: u64,
    length: u64,
) -> std::result::Result<web_sys::ReadableStream, JsValue> {
    let object = bucket
        .get(key)
        .range(Range::OffsetWithLength { offset, length })
        .execute()
        .await
        .map_err(|e| JsValue::from_str(&e.to_string()))?
        .ok_or_else(|| JsValue::from_str("File content does not exist"))?;
    match object.body().map(|b| b.response_body()) {
        Some(Ok(ResponseBody::Stream(stream))) => Ok(stream),
        _ => Err(JsValue::from_str("File content is unavailable")),
    }
}

/// The R2 objects `parts`, each (key, length), one after another, as one stream of their
/// total length.
pub fn objects(bucket: Bucket, parts: Vec<(String, u64)>) -> web_sys::ReadableStream {
    let total: u64 = parts.iter().map(|(_, length)| length).sum();
    let parts = Rc::new(RefCell::new(VecDeque::from(parts)));
    let bucket = Rc::new(bucket);
    let next = Closure::<dyn FnMut() -> js_sys::Promise>::new(move || {
        let part = parts.borrow_mut().pop_front();
        let bucket = bucket.clone();
        future_to_promise(async move {
            let Some((key, length)) = part else {
                return Ok(JsValue::NULL);
            };
            object_range(&bucket, &key, 0, length).await.map(Into::into)
        })
    });
    let stream = concatenate(&next.into_js_value().into());
    fixed_length(&stream, total as f64)
}
