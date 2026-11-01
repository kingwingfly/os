// The page's side of the client kernel's protocol: one envelope, versioned, with an id for each
// request and one reply. Requests never carry functions; events (process state, a boot, a
// mount) are pushed as they happen. The SharedWorker (client.js) speaks this too; its classic
// script cannot import this module, so the version here is the one to change with it.
export const VERSION = 1;

let shared;

// The page's port to the browser's client kernel, one SharedWorker for every tab.
export function kernelPort() {
  if (shared) return shared;
  const worker = new SharedWorker('/client-kernel.js');
  const port = worker.port;
  const pending = new Map();
  const listeners = new Map();
  let next = 0;
  port.onmessage = ({ data }) => {
    if (data?.v !== VERSION) return;
    if (data.id != null) {
      const waiting = pending.get(data.id);
      if (!waiting) return;
      pending.delete(data.id);
      if (data.err) waiting.reject(Object.assign(new Error(data.err.detail ?? data.err.errno), data.err));
      else waiting.resolve(data.ok);
      return;
    }
    if (data.type === 'event') {
      for (const listener of listeners.get(data.event) ?? []) listener(data.value);
      for (const listener of listeners.get('*') ?? []) listener(data);
    }
  };
  port.start();
  const request = (type, args = {}) => new Promise((resolve, reject) => {
    const id = ++next;
    pending.set(id, { resolve, reject });
    port.postMessage({ v: VERSION, id, type, args });
  });
  const on = (event, listener) => {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event).add(listener);
    return () => listeners.get(event).delete(listener);
  };
  shared = { request, on, port };
  return shared;
}

// One call, its value: an error the kernel refused with is thrown with its errno.
export async function kernelCall(type, args) {
  return kernelPort().request(type, args);
}
