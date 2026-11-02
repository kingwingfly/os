// The client kernel's SharedWorker: a classic worker, so it can importScripts the no-modules
// wasm-bindgen build, with the Rust kernel (crates/client-kernel) holding the browser's process
// table and tokens. This file is transport only: it checks the envelope version, calls the Rust
// exports, and posts back their value or their errno. Every decision is the worker kernel's,
// reached by the Rust kernel through /api/sys.
importScripts('/client_kernel.js');

const VERSION = 1;
const ports = new Set();
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
    const id = self.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
    kernel = new wasm_bindgen.Kernel(id);
    const value = JSON.parse(await kernel.init());
    broadcast({ v: VERSION, type: 'event', event: 'started', value });
    return value;
  });
  return starting;
}

function broadcast(message) {
  for (const port of ports) port.postMessage(message);
}

function failure(error) {
  if (typeof error === 'string') {
    try { return JSON.parse(error); } catch { /* not our envelope */ }
  }
  if (error && typeof error === 'object' && error.errno) return error;
  return { errno: 'EIO', detail: String(error?.message ?? error) };
}

async function dispatch(message) {
  const { type, args = {} } = message;
  switch (type) {
    case 'init': return boot();
    case 'version': return kernel.version();
    case 'namespace': return kernel.namespace();
    case 'exec': return JSON.parse(await kernel.exec(
      args.path,
      JSON.stringify(args.argv ?? []),
      JSON.stringify(args.env ?? []),
      args.cwd ?? '/',
      args.cgroup ?? '',
      !!args.sudo,
    ));
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
