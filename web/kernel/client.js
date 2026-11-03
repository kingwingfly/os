// The client kernel: a classic worker, so it can importScripts the no-modules wasm-bindgen
// build, with the Rust kernel (crates/client-kernel) holding the process tokens. It runs as the
// browser's SharedWorker, one for every tab, or, where a browser has none (Chrome for Android
// before 148), as a dedicated Worker of one tab, which speaks through itself as its port. Every
// decision is the worker kernel's, reached by the Rust kernel through /api/sys.
//
// Each tab holds a Web Lock, `tw-tab-<tab>`, for as long as it lives (web/kernel/protocol.js),
// and each process says which tab runs it (its seat). A process whose seat's lock is free was
// left by a tab that closed, crashed or reloaded while it ran: the kernel reaps it, at once
// where it waits on that tab's lock, and at boot, or when the namespace has no room for another
// process, by asking which locks are held.
importScripts('/client_kernel.js');

const VERSION = 1;
const ports = new Set();
const sharing = typeof SharedWorkerGlobalScope === 'function' && self instanceof SharedWorkerGlobalScope;
const locks = self.navigator?.locks;
// The tabs waited on, by seat.
const watched = new Set();
let kernel;
let starting;

// The Rust kernel's transport: one POST, its status and text. Same-origin, so the browser's
// cookies go with it; the kernel never sees them.
self.kernelSys = async body => {
  const response = await fetch('/api/sys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

function boot() {
  starting ??= wasm_bindgen('/client_kernel_bg.wasm').then(async () => {
    // A boot id reaps what the browser's last boot left; only the browser's one shared kernel,
    // and only where tabs cannot say they are gone, may do so.
    const id = sharing && !locks ? self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}` : '';
    kernel = new wasm_bindgen.Kernel(id);
    const value = JSON.parse(await kernel.init());
    broadcast({ v: VERSION, type: 'event', event: 'started', value });
    void reapGone().catch(() => {});
    return value;
  }).catch(error => {
    // A boot that failed (offline, a 5xx) is tried again by the next request, not kept as
    // every tab's answer for as long as this worker lives.
    kernel = undefined;
    starting = undefined;
    throw error;
  });
  return starting;
}

function broadcast(message) {
  for (const port of ports) port.postMessage(message);
}

// The lock a tab holds while it lives.
const tabLock = seat => `tw-tab-${seat}`;
// End and reap the process `process`, as SIGKILL would end it, unless it ended already.
async function reap(process) {
  try { if (process.state !== 'zombie') await kernel.kill(process.pid, 9); } catch { /* gone already */ }
  try { await kernel.wait(process.pid); } catch { /* reaped already */ }
}
// Reap the processes whose tab is gone: those of `seat`, or of any seat whose lock is free.
async function reapGone(seat) {
  if (!locks || !kernel) return;
  const held = new Set(((await locks.query()).held ?? []).map(lock => lock.name));
  const processes = JSON.parse(await kernel.poll('[]'));
  for (const process of processes) {
    if (process.pid === 1 || !process.seat) continue;
    if (seat ? process.seat === seat : !held.has(tabLock(process.seat))) await reap(process);
  }
}
// Wait for the tab `seat` to go, and reap what it left: its lock is granted here once the tab
// lets it go, closed, crashed or reloaded.
function watch(seat) {
  if (!locks || !seat || watched.has(seat)) return;
  watched.add(seat);
  void locks.request(tabLock(seat), async () => {
    watched.delete(seat);
    await boot();
    await reapGone(seat);
  }).catch(() => watched.delete(seat));
}
// execve, as the tab `seat` asks it: where the namespace has no room (EAGAIN), what gone tabs
// left is reaped, and it is asked once more.
async function exec(args, seat) {
  const call = () => kernel.exec(
    args.path,
    JSON.stringify(args.argv ?? []),
    JSON.stringify(args.env ?? []),
    args.cwd ?? '/',
    args.cgroup ?? '',
    !!args.sudo,
    seat ?? '',
  );
  try {
    return JSON.parse(await call());
  } catch (error) {
    if (failure(error).errno !== 'EAGAIN' || !locks) throw error;
    await reapGone();
    return JSON.parse(await call());
  }
}

function failure(error) {
  if (typeof error === 'string') {
    try { return JSON.parse(error); } catch { /* not our envelope */ }
  }
  if (error && typeof error === 'object' && error.errno) return error;
  return { errno: 'EIO', detail: String(error?.message ?? error) };
}

async function dispatch(message) {
  const { type, args = {}, tab } = message;
  switch (type) {
    case 'init': return boot();
    case 'version': return kernel.version();
    case 'namespace': return kernel.namespace();
    case 'exec': return exec(args, tab);
    case 'fork': return JSON.parse(await kernel.fork(args.pid));
    case 'exit': return JSON.parse(await kernel.exit(args.pid, args.status ?? 0, args.signal ?? undefined));
    case 'wait': return JSON.parse(await kernel.wait(args.pid));
    case 'kill': return JSON.parse(await kernel.kill(args.pid, args.signal ?? undefined));
    case 'poll': return JSON.parse(await kernel.poll(JSON.stringify(args.pids ?? [])));
    case 'getpid': return JSON.parse(await kernel.getpid(args.pid));
    case 'cgroup_create': return JSON.parse(await kernel.cgroup_create(args.path));
    case 'cgroup_set': return JSON.parse(await kernel.cgroup_set(args.path, args.key, args.value));
    case 'cgroup_attach': return JSON.parse(await kernel.cgroup_attach(args.pid, args.path));
    case 'cgroup_remove': return JSON.parse(await kernel.cgroup_remove(args.path));
    case 'cgroup_stat': return JSON.parse(await kernel.cgroup_stat(args.path));
    case 'cgroup_list': return JSON.parse(await kernel.cgroup_list(args.path ?? '/'));
    default: throw { errno: 'ENOSYS', detail: `no client-kernel call ${type}` };
  }
}

async function handle(port, message) {
  if (message?.v !== VERSION) {
    port.postMessage({ v: VERSION, id: message?.id, err: { errno: 'EPROTO', detail: `client kernel speaks version ${VERSION}` } });
    return;
  }
  ports.add(port);
  // The browser's kernel outlives its tabs, and reaps what each leaves; a tab's own kernel goes
  // with its tab.
  if (sharing) watch(message.tab);
  try {
    await boot();
    const value = await dispatch(message);
    port.postMessage({ v: VERSION, id: message.id, ok: value });
  } catch (error) {
    port.postMessage({ v: VERSION, id: message.id, err: failure(error) });
  }
}

self.onconnect = event => {
  for (const port of event.ports) {
    ports.add(port);
    port.onmessage = ({ data }) => handle(port, data);
    port.start();
    // A tab that joins a kernel already booted hears what it is.
    if (kernel) port.postMessage({ v: VERSION, type: 'event', event: 'started', value: null });
  }
};
// A dedicated Worker: one tab's kernel, whose port is itself.
if (!sharing) self.onmessage = ({ data }) => handle(self, data);
