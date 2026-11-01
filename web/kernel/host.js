// Phase 0 browser bridge: a module Worker that instantiates the Rust wasix-runtime and a
// prebuilt WASIX guest, then drives the same asyncify/checkpoint/fork loop as the Node harness.
// It holds only engine/transport glue; the runtime state and policy are in the Rust wasm.
import init, { Runtime } from './wasix_runtime.js';

const guests = new Map();
let runtime;
const rootPid = 1;

class Exit extends Error {
  constructor(code) {
    super(`exit ${code}`);
    this.code = code;
  }
}

function post(type, value) {
  self.postMessage({ type, ...value });
}

globalThis.wasixGuest = {
  read(pid, ptr, len) {
    return new Uint8Array(guests.get(pid).memory.buffer, ptr, len).slice();
  },
  write(pid, ptr, data) {
    new Uint8Array(guests.get(pid).memory.buffer, ptr, data.length).set(data);
  },
  output(fd, data) {
    post('output', { fd, text: new TextDecoder().decode(data) });
  },
  stackPointer(pid) {
    return guests.get(pid).instance.exports.__stack_pointer.value;
  },
  asyncify(pid, action, data) {
    const exports = guests.get(pid).instance.exports;
    if (action === 'start_unwind') exports.asyncify_start_unwind(data);
    else if (action === 'stop_unwind') exports.asyncify_stop_unwind();
    else if (action === 'start_rewind') exports.asyncify_start_rewind(data);
    else if (action === 'stop_rewind') exports.asyncify_stop_rewind();
  },
  clone(parent, child, stackPointer) {
    const source = guests.get(parent);
    const pages = source.memory.buffer.byteLength / 65536;
    const memory = new WebAssembly.Memory({ initial: pages, maximum: 65536, shared: true });
    new Uint8Array(memory.buffer).set(new Uint8Array(source.memory.buffer));
    const instance = new WebAssembly.Instance(source.module, importsFor(child, memory));
    instance.exports.__stack_pointer.value = stackPointer;
    guests.set(child, { instance, memory, module: source.module });
    return instance.exports.__data_end.value;
  },
};

const names = [
  'args_get', 'args_sizes_get', 'environ_get', 'environ_sizes_get', 'clock_time_get',
  'fd_close', 'fd_fdstat_get', 'fd_fdstat_set_flags', 'fd_filestat_get', 'fd_prestat_get',
  'fd_prestat_dir_name', 'fd_read', 'fd_readdir', 'fd_renumber', 'fd_dup', 'fd_seek',
  'fd_write', 'fd_pipe', 'path_filestat_get', 'path_open', 'sched_yield', 'getcwd', 'chdir',
  'callback_signal', 'thread_id', 'thread_signal', 'futex_wait', 'futex_wake', 'futex_wake_all',
  'thread_exit', 'stack_checkpoint', 'stack_restore', 'proc_exit', 'proc_fork', 'proc_exec',
  'proc_id', 'proc_parent', 'proc_join', 'proc_signal',
];

function importsFor(pid, memory) {
  const wasix = {};
  for (const name of names) {
    wasix[name] = (...args) => {
      const numbers = Uint32Array.from(args.map(value => Number(value) >>> 0));
      const result = JSON.parse(runtime.syscall(pid, name, numbers));
      if (result.kind === 'exit') throw new Exit(result.code);
      if (result.kind === 'unwind') return 0;
      return result.errno;
    };
  }
  return { env: { memory }, wasix_32v1: wasix };
}

function run(pid) {
  const guest = guests.get(pid);
  try {
    guest.instance.exports._start();
  } catch (error) {
    if (error instanceof Exit) {
      post('exit', { pid, code: error.code });
      return;
    }
    throw error;
  }
  const next = JSON.parse(runtime.unwind_done(pid));
  if (next.kind === 'resume') return run(pid);
  if (next.kind === 'fork') {
    run(next.child);
    run(pid);
    return;
  }
  if (next.kind === 'exit') {
    post('exit', { pid, code: next.code });
    return;
  }
  if (next.kind === 'none') {
    post('exit', { pid, code: 0 });
    return;
  }
  throw new Error(`unsupported asyncify action: ${JSON.stringify(next)}`);
}

async function main({ dash, argv }) {
  await init();
  runtime = new Runtime();
  const bytes = await (await fetch(dash)).arrayBuffer();
  const command = argv ?? ['dash', '-c', 'echo one; (echo two); echo three'];
  const env = ['PWD=/', 'HOME=/', 'PATH=/usr/bin', 'TERM=xterm', 'LANG=C.UTF-8'];
  runtime.register(rootPid, 0, JSON.stringify(command), JSON.stringify(env), '/');
  runtime.add_file('/dash', new Uint8Array(bytes));
  for (const path of ['/etc/profile', '/.profile', '/profile']) {
    runtime.add_file(path, new Uint8Array(0));
  }
  const memory = new WebAssembly.Memory({ initial: 2, maximum: 65536, shared: true });
  const module = await WebAssembly.compile(bytes);
  const instance = new WebAssembly.Instance(module, importsFor(rootPid, memory));
  guests.set(rootPid, { instance, memory, module });
  runtime.set_layout(rootPid, instance.exports.__data_end.value, instance.exports.__stack_pointer.value);
  run(rootPid);
  post('done', {});
}

self.onmessage = async event => {
  if (event.data?.type !== 'start') return;
  try {
    await main(event.data);
  } catch (error) {
    post('error', { error: String(error?.stack ?? error) });
  }
};
