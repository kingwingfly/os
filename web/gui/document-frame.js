// These two functions are serialized into the hash-pinned opaque document.
export function reservedShortcut(e) {
  if (e.isComposing || e.keyCode === 229) return null;
  if (e.altKey && !e.ctrlKey && !e.metaKey && (e.code === 'Backquote' || e.key === '`')) return e.shiftKey ? 'previous' : 'next';
  if (e.altKey && e.ctrlKey) return ({ ArrowLeft: 'left', ArrowRight: 'right', ArrowUp: 'maximize', ArrowDown: 'restore' })[e.key] || null;
  return e.altKey && e.key === 'F4' ? 'close' : null;
}
function bootstrap(nonce, shortcut) {
  if (window.origin !== 'null') return;
  const ready = event => {
    if (event.source !== parent || event.data?.type !== 'gui-frame-port' || event.data.bootNonce !== nonce || event.ports.length !== 1) return;
    event.stopImmediatePropagation();
    removeEventListener('message', ready, true);
    const port = event.ports[0], send = port.postMessage.bind(port);
    let onmessage;
    Object.defineProperty(window, 'gui', { value: Object.freeze({
      send(text) { if (typeof text === 'string' && text.length <= 4096) send({ type: 'message', text }); },
      set onmessage(fn) { onmessage = fn; },
    }) });
    port.onmessage = ({ data }) => { if (typeof data?.text === 'string') onmessage?.(data.text); };
    addEventListener('focusin', e => { if (e.isTrusted) send({ type: 'surface_activate' }); }, true);
    addEventListener('pointerdown', e => { if (e.isTrusted) send({ type: 'pointerdown', pointer_id: e.pointerId }); }, true);
    addEventListener('pointerup', e => { if (e.isTrusted) send({ type: 'pointerup' }); }, true);
    // Native clipboard and drop events can carry bytes even when the async
    // Clipboard API is disabled. Only the compositor may deliver those bytes.
    for (const type of ['copy', 'cut', 'paste', 'dragover', 'drop']) {
      addEventListener(type, e => { e.preventDefault(); e.stopImmediatePropagation(); }, true);
    }
    addEventListener('keydown', e => {
      if (!e.isTrusted || e.isComposing || e.keyCode === 229) return;
      const key = shortcut(e);
      if (key) { e.preventDefault(); e.stopImmediatePropagation(); send({ type: 'shortcut', key }); }
      else send({ type: 'key', paste: (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'v' });
    }, true);
    const bundle = JSON.parse(document.getElementById('gui-application').textContent);
    const style = document.createElement('style');
    style.textContent = bundle.css; document.head.append(style);
    const content = document.createElement('template');
    content.innerHTML = bundle.html; document.body.append(content.content);
    const script = document.createElement('script');
    script.textContent = bundle.js;
    document.body.append(script);
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
    "'; style-src 'sha256-" + base64(style) + "' 'unsafe-inline'; img-src data: blob:; media-src blob:; font-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-src 'none'";
  return '<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="' + csp +
    '"><script>' + boot + '</script><body><script type="application/json" id="gui-application">' + JSON.stringify(bundle).replaceAll('<', '\\u003c') + '</script></body>';
}
export async function documentFrame(verified, title, handoff, signal) {
  const frame = document.createElement('iframe');
  frame.title = title;
  frame.setAttribute('sandbox', 'allow-scripts');
  frame.setAttribute('allow', "clipboard-read 'none'; clipboard-write 'none'; camera 'none'; microphone 'none'; geolocation 'none'");
  frame.setAttribute('referrerpolicy', 'no-referrer');
  frame.credentialless = true;
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const source = await documentSource(verified, nonce);
  function ready(event) {
    if (event.source !== frame.contentWindow || event.origin !== 'null' || event.data?.type !== 'gui-frame-ready' || event.data.bootNonce !== nonce) return;
    window.removeEventListener('message', ready);
    const { port1, port2 } = new MessageChannel();
    handoff(port1);
    frame.contentWindow.postMessage({ type: 'gui-frame-port', bootNonce: nonce }, '*', [port2]);
  }
  window.addEventListener('message', ready, { signal });
  frame.srcdoc = source;
  return frame;
}
