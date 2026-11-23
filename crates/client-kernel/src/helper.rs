//! Client-kernel glue for the Linux helper driver (`#49`/`#50`): bridges the JS `NativeMount`
//! loopback fetch transport into `os_vfs::helperfs::HelperFs`, negotiates `Boundary::LocalHelper`,
//! renews the helper session lease, and detaches cleanly on unmount.

use abi::Errno;
use abi::local_helper::{HelperGrant, RENEW_MILLIS};
use js_sys::{Function, Promise, Reflect};
use std::cell::Cell;
use std::rc::Rc;
use vfs::helperfs::{HelperFs, HelperHttpHost, HttpHelperTransport, HttpReply};
use vfs::{BoxFuture, Cred, Filesystem};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{JsFuture, spawn_local};

pub(crate) async fn sleep_ms(millis: u32) -> Result<(), JsValue> {
    let promise = Promise::new(&mut |resolve, _reject| {
        let global = js_sys::global();
        if let Ok(set_timeout) = Reflect::get(&global, &JsValue::from_str("setTimeout"))
            && let Ok(func) = set_timeout.dyn_into::<Function>()
        {
            if let Ok(timer) = func.call2(&global, &resolve, &JsValue::from_f64(f64::from(millis)))
                && timer.is_object()
                && let Ok(unref) = Reflect::get(&timer, &JsValue::from_str("unref"))
                && let Ok(unref_fn) = unref.dyn_into::<Function>()
            {
                let _ = unref_fn.call0(&timer);
            }
        } else {
            let _ = resolve.call0(&JsValue::UNDEFINED);
        }
    });
    JsFuture::from(promise).await.map(|_| ())
}

fn random_ticket(seq: &Cell<u64>) -> String {
    let global = js_sys::global();
    if let Ok(crypto) = Reflect::get(&global, &JsValue::from_str("crypto"))
        && let Ok(uuid_fn) = Reflect::get(&crypto, &JsValue::from_str("randomUUID"))
        && let Ok(func) = uuid_fn.dyn_into::<Function>()
        && let Ok(val) = func.call0(&crypto)
        && let Some(s) = val.as_string()
    {
        return s;
    }
    let next = seq.get().wrapping_add(1);
    seq.set(next);
    format!("helper-ticket-{next}")
}

fn read_client_id(transport: &JsValue, seq: &Cell<u64>) -> String {
    if let Ok(cid_fn) = Reflect::get(transport, &JsValue::from_str("clientId"))
        && let Ok(func) = cid_fn.dyn_into::<Function>()
        && let Ok(val) = func.call0(transport)
        && let Some(s) = val.as_string()
    {
        return s;
    }
    random_ticket(seq)
}

fn close_js_transport(transport: &JsValue) {
    if let Ok(close_fn) = Reflect::get(transport, &JsValue::from_str("close"))
        && let Ok(func) = close_fn.dyn_into::<Function>()
    {
        let _ = func.call0(transport);
    }
}

fn js_transport_errno(err: &JsValue) -> Errno {
    if let Ok(code) = Reflect::get(err, &JsValue::from_str("errno"))
        && let Some(text) = code.as_string()
    {
        return match text.as_str() {
            "ETIMEDOUT" => Errno::ETIMEDOUT,
            _ => Errno::ENOTCONN,
        };
    }
    Errno::ENOTCONN
}

struct JsHelperHost {
    transport: JsValue,
    ticket_seq: Cell<u64>,
}

impl HelperHttpHost for JsHelperHost {
    fn post<'a>(&'a self, body: Vec<u8>) -> BoxFuture<'a, HttpReply> {
        Box::pin(async move {
            let text = String::from_utf8(body).map_err(|_| Errno::EINVAL)?;
            let post_fn = Reflect::get(&self.transport, &JsValue::from_str("postRaw"))
                .ok()
                .and_then(|v| v.dyn_into::<Function>().ok())
                .ok_or(Errno::ENOTCONN)?;
            let answer = post_fn
                .call1(&self.transport, &JsValue::from_str(&text))
                .map_err(|_| Errno::ENOTCONN)?;
            let promise = answer.dyn_into::<Promise>().map_err(|_| Errno::ENOTCONN)?;
            let reply_val = JsFuture::from(promise)
                .await
                .map_err(|err| js_transport_errno(&err))?;
            let status_val =
                Reflect::get(&reply_val, &JsValue::from_str("status")).map_err(|_| Errno::EIO)?;
            let body_val =
                Reflect::get(&reply_val, &JsValue::from_str("body")).map_err(|_| Errno::EIO)?;
            let status = status_val
                .as_f64()
                .filter(|s| *s >= 100.0 && *s <= 599.0)
                .ok_or(Errno::EIO)? as u16;
            let resp_body = body_val.as_string().ok_or(Errno::EIO)?.into_bytes();
            Ok(HttpReply {
                status,
                body: resp_body,
            })
        })
    }

    fn sleep(&self, millis: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            sleep_ms(millis).await.map_err(|_| Errno::EIO)?;
            Ok(())
        })
    }

    fn ticket(&self) -> String {
        random_ticket(&self.ticket_seq)
    }
}

fn format_errno(errno: Errno) -> JsValue {
    let msg = format!("{errno:?}: {}", errno.text());
    let err = js_sys::Error::new(&msg);
    if let Ok(serde_json::Value::String(code)) = serde_json::to_value(errno) {
        let _ = Reflect::set(&err, &JsValue::from_str("errno"), &JsValue::from_str(&code));
    }
    err.into()
}

/// Connect an `os-local-helper` JS transport (`web/kernel/native-mount.js`) into the VFS
/// `LocalMount` registry using `HelperFs`.
#[wasm_bindgen]
pub async fn connect_helper_mount(
    transport: JsValue,
    grant_json: &str,
) -> Result<crate::mounts::LocalMount, JsValue> {
    let mut grant: crate::mounts::Grant = serde_json::from_str(grant_json)
        .map_err(|e| JsValue::from_str(&format!("EINVAL: invalid helper grant: {e}")))?;
    let cred = Cred::new(grant.owner.clone());
    let requested = HelperGrant {
        write: !grant.read_only,
        execute: grant.execute,
    };

    let host = JsHelperHost {
        transport: transport.clone(),
        ticket_seq: Cell::new(0),
    };
    let client_id = read_client_id(&transport, &host.ticket_seq);
    let fs = HelperFs::connect(HttpHelperTransport(host), client_id, &cred, requested)
        .await
        .map_err(format_errno)?;

    let effective = fs.grant();
    grant.read_only = !effective.write;
    grant.execute = effective.execute;

    let fs = Rc::new(fs);
    let alive = Rc::new(Cell::new(true));

    let fs_unmount = Rc::clone(&fs);
    let alive_unmount = Rc::clone(&alive);
    let transport_unmount = transport.clone();
    let on_unmount = move || {
        alive_unmount.set(false);
        let fs_detach = Rc::clone(&fs_unmount);
        let transport_close = transport_unmount.clone();
        spawn_local(async move {
            let _ = fs_detach.detach().await;
            close_js_transport(&transport_close);
        });
    };

    let dyn_fs: Rc<dyn Filesystem> = Rc::clone(&fs) as Rc<dyn Filesystem>;
    let mount = crate::mounts::from_fs_with_unmount(dyn_fs, grant, on_unmount);
    let on_revoke = mount.revoke_callback();
    let on_lose = mount.lose_callback();

    let fs_renew = Rc::clone(&fs);
    let alive_renew = Rc::clone(&alive);
    let transport_renew = transport;
    let lease_ms = fs_renew
        .lease_seconds()
        .saturating_mul(1000)
        .max(u64::from(RENEW_MILLIS));
    spawn_local(async move {
        let mut failed_ms: u64 = 0;
        let mut next_delay = RENEW_MILLIS;
        while alive_renew.get() {
            if sleep_ms(next_delay).await.is_err() || !alive_renew.get() {
                break;
            }
            match fs_renew.renew().await {
                Ok(_) => {
                    failed_ms = 0;
                    next_delay = RENEW_MILLIS;
                }
                Err(Errno::EACCES) => {
                    alive_renew.set(false);
                    on_revoke();
                    close_js_transport(&transport_renew);
                    break;
                }
                Err(Errno::ENODEV | Errno::EPROTONOSUPPORT) => {
                    alive_renew.set(false);
                    on_lose();
                    close_js_transport(&transport_renew);
                    break;
                }
                Err(_) => {
                    failed_ms = failed_ms.saturating_add(u64::from(next_delay));
                    if failed_ms >= lease_ms {
                        alive_renew.set(false);
                        on_lose();
                        close_js_transport(&transport_renew);
                        break;
                    }
                    next_delay = 5_000.min(RENEW_MILLIS);
                }
            }
        }
    });

    Ok(mount)
}
