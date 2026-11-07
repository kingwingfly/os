// The client kernel: a classic worker, so it can importScripts the no-modules wasm-bindgen
// build, with the Rust kernel (crates/client-kernel) holding the processes its tabs host and
// their tokens. It runs as the browser's SharedWorker, one for every tab, or, where a browser
// has none (Chrome for Android before 148), as a dedicated Worker of one tab, which speaks
// through itself as its port. Its requests go to the browser's machine (a Durable Object of
// its own, by a batch marked X-Registry). The machine verifies account identity with the
// authority for tokenless batches; process-token calls use their stored snapshot.
// Forks, exits and waits happen in the Rust kernel and are told to the machine in batches:
// with its next request, or a moment after. Requests go one at a time, so that the machine
// hears of a fork before the exit of what it made.
//
// Each tab holds a Web Lock, `tw-tab-<tab>`, for as long as it lives (web/kernel/protocol.js),
// and each process says which tab runs it (its seat). A process whose seat's lock is free was
// left by a tab that closed, crashed or reloaded while it ran: the kernel reaps it, at once
// where it waits on that tab's lock, and at boot, or when the namespace has no room for another
// process, by asking which locks are held. Each kernel holds one too, `tw-kernel-<id>`: the pids
// a kernel that is gone was lent go back the same way.
//
// A process is its host's: the port that executed it, under an identity of the port's own (not
// the tab it said it was, whose lock any same-origin page can see). Only that port forks it,
// replaces its image, ends it, waits for its children, or signals as it; another tab's page
// learns nothing of its token.
importScripts('/client_kernel.js');

const VERSION = 1;
const ports = new Set();
const sharing = typeof SharedWorkerGlobalScope === 'function' && self instanceof SharedWorkerGlobalScope;
const locks = self.navigator?.locks;
// The tabs waited on, by seat.
const watched = new Set();
let kernel;
let starting;
// This kernel's id, and the lock it holds of it while it runs.
const kernelId = self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
const kernelLock = id => `tw-kernel-${id}`;
if (locks) void locks.request(kernelLock(kernelId), () => new Promise(() => {})).catch(() => {});
// Each port's host: an identity of its own, made here, and the tab it first said it was. A tab
// id is a Web Lock's name, which any same-origin page can read: it says whose lock ends the
// port's processes, never which port owns them.
const hosts = new WeakMap();
// What the kernel does, one thing at a time.
let queue = Promise.resolve();
const serially = task => {
  const done = queue.then(task);
  queue = done.catch(() => {});
  return done;
};
// What happened here goes to the machine a moment after, if nothing took it sooner: the
// exits and waits of a pipeline's stages, which end together, go together.
const REPORT_AFTER = 25;
let reporting = null;
function report() {
  if (!kernel?.pending()) return reporting ?? Promise.resolve();
  reporting ??= new Promise(resolve => setTimeout(resolve, REPORT_AFTER))
    .then(() => serially(() => kernel.flush()))
    .catch(() => {})
    .finally(() => { reporting = null; void report(); });
  return reporting;
}
// Once the machine heard what happened here so far (a few tries, if it cannot be reached).
async function heard() {
  const mine = kernel.queued();
  for (let tries = 0; kernel.reported() < mine && tries < 5; tries++) await report();
}

// The Rust kernel's transport: one POST to the browser's machine, its status and text.
// Same-origin, so the browser's cookies go with it; the kernel never sees them.
self.kernelSys = async body => {
  const response = await fetch('/api/sys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Registry': '1' },
    body,
  });
  return JSON.stringify({ status: response.status, text: await response.text() });
};

function boot() {
  starting ??= wasm_bindgen('/client_kernel_bg.wasm').then(async () => {
    // A boot id reaps what the current account's last boot left; only the browser's one shared kernel,
    // and only where tabs cannot say they are gone, may do so.
    const id = sharing && !locks ? self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}` : '';
    kernel = new wasm_bindgen.Kernel(id, locks ? kernelId : '');
    const value = JSON.parse(await kernel.init());
    broadcast({ v: VERSION, type: 'event', event: 'started', value });
    void serially(() => reapGone()).catch(() => {});
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
// Reap the processes whose tab is gone: those of `seat`, or of any seat whose lock is free.
// The machine ends them as SIGKILL would, and init reaps them. The pids lent to kernels whose
// lock is free go back.
async function reapGone(seat) {
  if (!locks || !kernel) return;
  if (seat) { await kernel.gone(seat); return; }
  const held = new Set(((await locks.query()).held ?? []).map(lock => lock.name));
  const { seats = [], kernels = [] } = JSON.parse(await kernel.seats());
  for (const running of seats) {
    if (!held.has(tabLock(running))) await kernel.gone(running);
  }
  for (const lender of kernels) {
    if (lender !== kernelId && !held.has(kernelLock(lender))) await kernel.reclaim(lender);
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
    await serially(() => reapGone(seat));
  }).catch(() => watched.delete(seat));
}
// execve of a pipeline's stages, in one request, as the tab `seat` asks it: each stage's
// process, or its error. Where the namespace has no room (EAGAIN), what gone tabs left is
// reaped, and it is asked once more.
async function execs(args, seat, host) {
  const stages = (args.stages ?? []).map(stage => ({
    path: stage.path, argv: stage.argv ?? [], env: stage.env ?? [], cwd: stage.cwd ?? '/', cgroup: stage.cgroup ?? '',
  }));
  const call = async () => JSON.parse(await kernel.execs(JSON.stringify(stages), !!args.sudo, seat ?? '', host));
  const results = await call();
  if (!locks || !results.some(result => result.err?.errno === 'EAGAIN')) return results;
  // The stages that were given processes give them back before the pipeline is asked again.
  for (const result of results) {
    if (!result.ok) continue;
    try { await kernel.exit(result.ok.pid, 126, undefined, host); await kernel.wait(result.ok.pid, host); } catch { /* gone already */ }
  }
  await reapGone();
  return call();
}
// execve of one image: a pipeline of one stage.
async function exec(args, seat, host) {
  const [result] = await execs({ stages: [args], sudo: args.sudo }, seat, host);
  if (result.err) throw result.err;
  return result.ok;
}

function failure(error) {
  if (typeof error === 'string') {
    try { return JSON.parse(error); } catch { /* not our envelope */ }
  }
  if (error && typeof error === 'object' && error.errno) return error;
  return { errno: 'EIO', detail: String(error?.message ?? error) };
}

async function dispatch(message, host, tab) {
  const { type, args = {} } = message;
  switch (type) {
    case 'init': return boot();
    case 'version': return kernel.version();
    case 'namespace': return kernel.namespace();
    case 'exec': return exec(args, tab, host);
    case 'execs': return execs(args, tab, host);
    // A process's own execve: its image replaced, its pid, credentials and descriptors kept.
    case 'reexec': return JSON.parse(await kernel.reexec(args.pid, args.path, JSON.stringify(args.argv ?? []), JSON.stringify(args.env ?? []), args.cwd ?? '/', tab ?? '', host));
    case 'fork': return JSON.parse(await kernel.fork(args.pid, host));
    case 'exit': return JSON.parse(await kernel.exit(args.pid, args.status ?? 0, args.signal ?? undefined, host));
    case 'wait': return JSON.parse(await kernel.wait(args.pid, host));
    // wait4 of a process for its children (`pid`, or any).
    case 'waitchild': return JSON.parse(await kernel.waitchild(args.ppid, args.pid ?? undefined, host));
    // kill(2): as the page's account, or `from` a process this port runs, as that process.
    case 'kill': return JSON.parse(await kernel.kill(args.pid, args.signal ?? undefined, args.from ?? undefined, host));
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
  // A port's authority is an identity of its own, not the tab it names: another port that says
  // the same tab is still another host. The tab it first said it was cannot change.
  if (!hosts.has(port)) hosts.set(port, {
    id: `port-${self.crypto?.randomUUID?.() ?? Math.random()}`,
    tab: message.tab,
  });
  const host = hosts.get(port);
  if (message.tab != null && message.tab !== host.tab) {
    port.postMessage({ v: VERSION, id: message.id, err: { errno: 'EPERM', detail: 'a port speaks for the tab it first said it was' } });
    return;
  }
  // The browser's kernel outlives its tabs, and reaps what each leaves; a tab's own kernel goes
  // with its tab.
  if (sharing) watch(host.tab);
  try {
    await boot();
    const value = await serially(() => dispatch(message, host.id, host.tab));
    // A wait answers once the machine heard of it, so that /proc agrees.
    if (message.type === 'wait' || message.type === 'waitchild') await heard();
    port.postMessage({ v: VERSION, id: message.id, ok: value });
  } catch (error) {
    port.postMessage({ v: VERSION, id: message.id, err: failure(error) });
  }
  void report();
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
