// The page's side of the client kernel's protocol: one envelope, versioned, with an id for each
// request and one reply. Requests never carry functions; events (process state, a boot, a
// mount) are pushed as they happen. The dedicated Worker (client.js) speaks this too; its classic
// script cannot import this module, so the version here is the one to change with it.
export const VERSION = 1;

let connection;

// This tab, as the kernel knows it (a process's seat): it holds the Web Lock `tw-tab-<tab>` for
// as long as it lives, taken before it asks anything, which the kernel waits on to reap what
// the tab ran once it is gone (client.js).
export const tab = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
const holding = globalThis.navigator?.locks
  ? new Promise(held => {
    globalThis.navigator.locks.request(`tw-tab-${tab}`, () => { held(); return new Promise(() => {}); }).catch(() => held());
  })
  : Promise.resolve();

// The page's port to its dedicated client-kernel Worker.
export function kernelPort() {
  if (connection) return connection;
  const worker = new Worker('/client-kernel.js');
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
  // Each request says which tab asks, once the tab holds its lock.
  const request = (type, args = {}) => holding.then(() => new Promise((resolve, reject) => {
    const id = ++next;
    pending.set(id, { resolve, reject });
    port.postMessage({ v: VERSION, id, type, args, tab });
  }));
  const on = (event, listener) => {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event).add(listener);
    return () => listeners.get(event).delete(listener);
  };
  connection = { request, on, port };
  return connection;
}

// One call, its value: an error the kernel refused with is thrown with its errno. What some
// answer:
// - `wait {pid}`: the reaped process's `{pid, ppid, status, signal}` (status as waitpid's),
//   and, for one the kernel does not host, the machine's whole record (abi::Proc), of which
//   those are a part; read only those.
// - `waitchild {ppid, pid?}`: `{pid, ppid, status, code, signal}`, wait4's.
// - `poll {pids}`: abi::Proc records, as /proc has them.
// - `kill {pid, signal, from?}`: null; `from` names a process this tab runs, which signals as
//   itself (its own credentials), not as the page's account.
export async function kernelCall(type, args) {
  return kernelPort().request(type, args);
}
