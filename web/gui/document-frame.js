// These two functions are serialized into the hash-pinned opaque document.
export function reservedShortcut(e) {
  if (e.isComposing || e.keyCode === 229) return null;
  if (e.altKey && !e.ctrlKey && !e.metaKey && (e.code === 'Backquote' || e.key === '`')) return e.shiftKey ? 'previous' : 'next';
  if (e.altKey && e.ctrlKey) {
    switch (e.key) {
      case 'ArrowLeft': return 'left';
      case 'ArrowRight': return 'right';
      case 'ArrowUp': return 'maximize';
      case 'ArrowDown': return 'restore';
      default: return null;
    }
  }
  return e.altKey && e.key === 'F4' ? 'close' : null;
}
function bootstrap(nonce, shortcut) {
  if (window.origin !== 'null') return;
  const post = Function.prototype.call.bind(MessagePort.prototype.postMessage);
  const getter = (proto, name) => Function.prototype.call.bind(Object.getOwnPropertyDescriptor(proto, name).get);
  const getterButtons = getter(MouseEvent.prototype, 'buttons');
  const clientX = getter(MouseEvent.prototype, 'clientX'), clientY = getter(MouseEvent.prototype, 'clientY');
  const pointerId = getter(PointerEvent.prototype, 'pointerId'), button = getter(MouseEvent.prototype, 'button');
  const capture = Function.prototype.call.bind(Element.prototype.setPointerCapture);
  const targetOf = getter(Event.prototype, 'target');
  const timestamp = getter(Event.prototype, 'timeStamp'), timeOrigin = performance.timeOrigin;
  const typesOf = getter(DataTransfer.prototype, 'types');
  const includes = Function.prototype.call.bind(Array.prototype.includes);
  const keyOf = Object.fromEntries(['key', 'code', 'keyCode', 'altKey', 'ctrlKey', 'shiftKey', 'metaKey', 'isComposing']
    .map(k => [k, getter(KeyboardEvent.prototype, k)]));
  const messageData = getter(MessageEvent.prototype, 'data');
  const clipboard = getter(ClipboardEvent.prototype, 'clipboardData');
  const getData = Function.prototype.call.bind(DataTransfer.prototype.getData);
  const prevent = Function.prototype.call.bind(Event.prototype.preventDefault);
  const stop = Function.prototype.call.bind(Event.prototype.stopImmediatePropagation);
  const encode = TextEncoder.prototype.encode.bind(new TextEncoder());
  const byteLength = getter(Object.getPrototypeOf(Uint8Array.prototype), 'byteLength');
  const later = window.setTimeout.bind(window);
  const ready = event => {
    if (event.source !== parent || event.data?.type !== 'gui-frame-port' || event.data.bootNonce !== nonce || event.ports.length !== 2) return;
    stop(event);
    removeEventListener('message', ready, true);
    const [appPort, controlPort] = event.ports;
    let onmessage, onbinary, head, tail, pending = 0, serial = 0, acknowledged = 0, pasteChord = false;
    const control = data => post(controlPort, { serial: ++serial, data });
    // Application actions produced by a click wait until its trusted input has
    // reached the seat. Only strings or bounded range-read descriptors leave via the application port.
    Object.defineProperty(window, 'gui', { value: Object.freeze({
      send(text) {
        if (typeof text !== 'string') return 'EINVAL';
        if (byteLength(encode(text)) > 4096) return 'E2BIG';
        if (pending >= 128) return 'EAGAIN';
        if (serial === acknowledged) post(appPort, { type: 'message', text });
        else {
          const item = { serial, text, next: null };
          if (tail) tail.next = item; else head = item;
          tail = item; pending++;
        }
        return null;
      },
      requestAssetRange(reqId, assetId, offset, length) {
        if (!Number.isSafeInteger(reqId) || !Number.isSafeInteger(assetId)
          || !Number.isSafeInteger(offset) || offset < 0
          || !Number.isSafeInteger(length) || length <= 0 || length > 1048576) return 'EINVAL';
        post(appPort, { type: 'asset-read', req_id: reqId, asset_id: assetId, offset, length });
        return null;
      },
      set onmessage(fn) { onmessage = typeof fn === 'function' ? fn : null; },
      set onbinary(fn) { onbinary = typeof fn === 'function' ? fn : null; },
    }) });
    controlPort.onmessage = event => {
      acknowledged = messageData(event);
      while (head && head.serial <= acknowledged) {
        post(appPort, { type: 'message', text: head.text });
        head = head.next; pending--;
      }
      if (!head) tail = null;
    };
    appPort.onmessage = ({ data }) => {
      if (typeof data?.text === 'string') later(() => onmessage?.(data.text), 0);
      else if (data && typeof data.type === 'string') later(() => onbinary?.(data), 0);
    };
    addEventListener('focusin', e => { if (e.isTrusted) control({ op: 'focus_request' }); }, true);
    addEventListener('pointerdown', e => {
      if (!e.isTrusted || button(e) !== 0) return;
      const id = pointerId(e);
      try { capture(targetOf(e), id); } catch { /* pointer is already released */ }
      control({ op: 'pointer_down', pointer_id: id, button: 0, pressedAt: timeOrigin + timestamp(e) });
    }, true);
    addEventListener('pointermove', e => {
      if (e.isTrusted && getterButtons(e)) control({ op: 'pointer_move', pointer_id: pointerId(e), x: clientX(e), y: clientY(e) });
    }, true);
    for (const type of ['pointerup', 'pointercancel', 'lostpointercapture']) addEventListener(type, e => {
      if (e.isTrusted && (type !== 'pointerup' || button(e) === 0)) control({ op: 'pointer_up', pointer_id: pointerId(e), button: 0, x: clientX(e), y: clientY(e), canceled: type !== 'pointerup', lost: type === 'lostpointercapture' });
    }, true);
    for (const type of ['copy', 'cut', 'paste', 'dragover', 'drop']) {
      addEventListener(type, e => {
        prevent(e); stop(e);
        if (type === 'paste' && e.isTrusted) {
          pasteChord = false;
          const transfer = clipboard(e);
          const text = transfer && includes(typesOf(transfer), 'text/plain') ? getData(transfer, 'text/plain') : null;
          if (text === null || (text.length <= 1048576 && byteLength(encode(text)) <= 1048576)) control({ op: 'paste', text });
        }
      }, true);
    }
    addEventListener('keydown', e => {
      if (!e.isTrusted) return;
      const k = { key: keyOf.key(e), code: keyOf.code(e), keyCode: keyOf.keyCode(e), isComposing: keyOf.isComposing(e),
        ctrlKey: keyOf.ctrlKey(e), altKey: keyOf.altKey(e), shiftKey: keyOf.shiftKey(e), metaKey: keyOf.metaKey(e) };
      if (k.isComposing || k.keyCode === 229) return;
      const key = shortcut(k);
      if (key || k.key === 'Escape') {
        if (key) { prevent(e); stop(e); }
        control({ op: 'shortcut', key: key || 'cancel' });
      } else {
        pasteChord = (k.ctrlKey || k.metaKey) && (k.key === 'v' || k.key === 'V');
        control({ op: 'key', key: k.key, code: k.code, ctrl: k.ctrlKey, alt: k.altKey, shift: k.shiftKey, meta: k.metaKey, paste: false });
      }
    }, true);
    addEventListener('keyup', e => {
      if (e.isTrusted && pasteChord && (keyOf.key(e) === 'v' || keyOf.key(e) === 'V')) {
        pasteChord = false; control({ op: 'paste', text: null });
      }
    }, true);
    later(() => {
      const bundle = JSON.parse(document.getElementById('gui-application').textContent);
      const style = document.createElement('style');
      style.textContent = bundle.css; document.head.append(style);
      const content = document.createElement('template');
      content.innerHTML = bundle.html; document.body.append(content.content);
      const script = document.createElement('script');
      script.textContent = bundle.js;
      document.body.append(script);
    }, 0);
  };
  addEventListener('message', ready, true);
  parent.postMessage({ type: 'gui-frame-ready', bootNonce: nonce }, '*');
}
const utf8 = new TextEncoder();
async function hash(source) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', utf8.encode(source)));
}
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const base64 = bytes => btoa(String.fromCharCode(...bytes));
export async function documentSource(verified, nonce) {
  const { bundle, script_sha256, style_sha256 } = verified;
  const boot = '(' + bootstrap.toString() + ')(' + JSON.stringify(nonce) + ',' + reservedShortcut.toString() + ');';
  const [script, style, bootHash] = await Promise.all([hash(bundle.js), hash(bundle.css), hash(boot)]);
  if (hex(script) !== script_sha256 || hex(style) !== style_sha256) throw new Error('Invalid GUI document digest');
  const csp = "default-src 'none'; script-src 'sha256-" + base64(bootHash) + "' 'sha256-" + base64(script) +
    "'; style-src 'unsafe-inline'; img-src data: blob:; media-src blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-src 'none'";
  return '<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="' + csp +
    '"><script>' + boot + '</script><body><script type="application/json" id="gui-application">' + JSON.stringify(bundle).replaceAll('<', '\\u003c') + '</script></body>';
}
export async function documentFrame(verified, title, transport, signal) {
  const frame = document.createElement('iframe');
  frame.title = title;
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.setAttribute('allow', "clipboard-read 'none'; clipboard-write 'none'; camera 'none'; microphone 'none'; geolocation 'none'");
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.credentialless = true;
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const source = await documentSource(verified, nonce);
  let loaded = false, authenticated = false, revoked = false, app, control;
  function revoke() {
    if (revoked) return;
    revoked = true;
    window.removeEventListener('message', ready);
    control?.port1.close(); control?.port2.close(); app?.port2.close();
    if (app) transport.revoke();
  }
  async function connect() {
    if (!loaded || !authenticated || revoked || app) return;
    app = new MessageChannel(); control = new MessageChannel();
    try {
      await transport.port(app.port1);
      if (revoked) { await transport.revoke(); return; }
      let delivery = Promise.resolve();
      control.port1.onmessage = ({ data: { serial, data } }) => {
        const canDeliver = () => data?.op === 'pointer_down' ? transport.canPress(data.pressedAt)
          : ['pointer_move', 'pointer_up'].includes(data?.op) || document.activeElement === frame;
        const accepted = canDeliver();
        delivery = delivery.then(async () => {
          if (!revoked && accepted && canDeliver()) await transport.control(data);
          if (!revoked) control.port1.postMessage(serial);
        }).catch(transport.error);
      };
      frame.contentWindow.postMessage({ type: 'gui-frame-port', bootNonce: nonce }, '*', [app.port2, control.port2]);
    } catch (e) { revoke(); transport.error(e); }
  }
  function ready(event) {
    if (event.source !== frame.contentWindow || event.origin !== 'null' || event.data?.type !== 'gui-frame-ready' || event.data.bootNonce !== nonce) return;
    window.removeEventListener('message', ready);
    authenticated = true; void connect();
  }
  frame.addEventListener('load', () => { if (loaded) revoke(); else { loaded = true; void connect(); } }, { signal });
  signal.addEventListener('abort', revoke, { once: true });
  window.addEventListener('message', ready, { signal });
  frame.srcdoc = source;
  return frame;
}
