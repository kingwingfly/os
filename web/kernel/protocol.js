import { asset, entryPath, releaseId } from '../release.js';
// The page's side of the client kernel's HostAdapter v2 protocol: one envelope, versioned, with
// an id for each request and one reply. Version mismatches return `EPROTONOSUPPORT` and surface
// an `os:protocol-mismatch` event without auto-reloading (docs/architecture/contract.md §2.10).
export const VERSION = 2;

let connection;
const portHooks = new Set();
export function onKernelPort(fn) {
  portHooks.add(fn);
  if (connection) {
    try { fn(connection); } catch { /* ignore hook failure */ }
  }
  return () => portHooks.delete(fn);
}

// This tab, as the kernel knows it (local instance label; never shared cross-tab).
export const tab = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
const holding = globalThis.navigator?.locks
  ? new Promise(held => {
    globalThis.navigator.locks.request(`tw-tab-${tab}`, () => { held(); return new Promise(() => {}); }).catch(() => held());
  })
  : Promise.resolve();

function emitProtocolMismatch(detail) {
  if (typeof globalThis.dispatchEvent === 'function' && typeof CustomEvent === 'function') {
    globalThis.dispatchEvent(new CustomEvent('os:protocol-mismatch', { detail }));
  }
  // Surface a reload option without ever auto-reloading (docs/architecture/contract.md §2.10).
  if (typeof document !== 'undefined' && document.body && !document.querySelector('.protocol-mismatch-notice')) {
    const notice = document.createElement('aside');
    notice.className = 'protocol-mismatch-notice';
    notice.setAttribute('role', 'alert');
    const text = document.createElement('span');
    const boundary = detail?.boundary ?? 'protocol';
    const message = detail?.detail ?? 'Protocol version mismatch (EPROTONOSUPPORT). Local processes remain running; reload when ready.';
    text.textContent = `${boundary}: ${message} `;
    const reload = document.createElement('button');
    reload.type = 'button';
    reload.textContent = 'Reload';
    reload.addEventListener('click', () => globalThis.location?.reload());
    notice.append(text, reload);
    if (releaseId !== 'legacy' && globalThis.location) {
      const switchDefault = document.createElement('a');
      switchDefault.className = 'protocol-mismatch-default';
      const defaultPath = entryPath(globalThis.location.pathname) || '/';
      switchDefault.href = `${defaultPath}${globalThis.location.search}${globalThis.location.hash}`;
      switchDefault.textContent = ' Switch to default release';
      notice.append(' ', switchDefault);
    }
    (document.querySelector('.topbar') ?? document.body).after?.(notice);
    if (!notice.isConnected) document.body.prepend(notice);
  }
}

// The page's port to its dedicated client-kernel Worker.
export function kernelPort() {
  if (connection) return connection;
  const worker = new Worker(asset('/client-kernel.js'));
  const port = worker;
  const pending = new Map();
  const listeners = new Map();
  let next = 0;
  // A kernel whose script failed to load or run answers nothing: what waits fails (EIO) rather
  // than hang the command that asked, and the next call starts the worker again.
  worker.onerror = event => {
    if (connection?.port === port) connection = undefined;
    const error = Object.assign(new Error(event?.message || 'the client kernel failed'), { errno: 'EIO' });
    for (const waiting of pending.values()) waiting.reject(error);
    pending.clear();
  };
  port.onmessage = ({ data }) => {
    if (data?.v !== VERSION) {
      if (data?.err?.errno === 'EPROTONOSUPPORT') {
        emitProtocolMismatch({ boundary: 'host-adapter', ...data.err });
        if (data.id != null) {
          const waiting = pending.get(data.id);
          if (waiting) {
            pending.delete(data.id);
            waiting.reject(Object.assign(new Error(data.err.detail ?? data.err.errno), data.err));
          }
        }
      }
      return;
    }
    if (data.id != null) {
      const waiting = pending.get(data.id);
      if (!waiting) return;
      pending.delete(data.id);
      if (data.err) {
        if (data.err.errno === 'EPROTONOSUPPORT') {
          emitProtocolMismatch({ boundary: 'host-adapter', ...data.err });
        }
        waiting.reject(Object.assign(new Error(data.err.detail ?? data.err.errno), data.err));
      } else waiting.resolve(data.ok);
      return;
    }
    if (data.type === 'event') {
      if (data.event === 'protocol-mismatch') emitProtocolMismatch(data.value);
      for (const listener of listeners.get(data.event) ?? []) listener(data.value);
      for (const listener of listeners.get('*') ?? []) listener(data);
    }
  };
  // Each request says which tab asks, once the tab holds its lock.
  const request = (type, args = {}, transfer = []) => holding.then(() => new Promise((resolve, reject) => {
    const id = ++next;
    pending.set(id, { resolve, reject });
    try { port.postMessage({ v: VERSION, id, type, args, tab }, transfer); }
    catch (error) { pending.delete(id); reject(error); }
  }));
  const hello = (versions = [VERSION], boundary = 'host-adapter') => holding.then(() => new Promise((resolve, reject) => {
    const id = ++next;
    pending.set(id, { resolve, reject });
    try { port.postMessage({ v: VERSION, id, type: 'hello', boundary, versions, tab }); }
    catch (error) { pending.delete(id); reject(error); }
  }));
  const on = (event, listener) => {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event).add(listener);
    return () => listeners.get(event).delete(listener);
  };
  connection = { request, hello, on, port };
  for (const hook of portHooks) {
    try { hook(connection); } catch { /* ignore hook failure */ }
  }
  return connection;
}

export async function hostAdapterHello(versions = [VERSION], boundary = 'host-adapter') {
  return kernelPort().hello(versions, boundary);
}

// One call, its value: an error the kernel refused with is thrown with its errno.
export async function kernelCall(type, args, transfer) {
  return kernelPort().request(type, args, transfer);
}
