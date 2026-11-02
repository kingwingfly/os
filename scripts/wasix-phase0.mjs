// Phase 0: run a prebuilt WASIX binary through the Rust wasix-runtime in Node.
// Usage: WASIX_DASH=/path/to/dash node scripts/wasix-phase0.mjs [argv...]
// The fixture is not committed; the test skips when WASIX_DASH is absent.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dashPath = process.env.WASIX_DASH;
const watPath = process.env.WASIX_WAT;
if (!dashPath && !watPath) {
  console.error('Set WASIX_DASH to a WASIX binary, or WASIX_WAT to a WAT module to asyncify.');
  process.exit(2);
}
const argv = process.argv.slice(2);
if (!argv.length) argv.push(...(watPath ? ['wasix-fork'] : ['dash', '-c', 'echo one; (echo two); echo three']));

const target = JSON.parse(execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], { cwd: root, encoding: 'utf8' })).target_directory;
execFileSync('cargo', ['build', '-p', 'terminal-worker-wasix-runtime', '--target', 'wasm32-unknown-unknown', '--release'], { cwd: root, stdio: 'pipe' });
const bindings = join(target, 'wasix-node');
execFileSync('wasm-bindgen', [
  '--target', 'nodejs',
  '--out-dir', bindings,
  '--out-name', 'wasix_runtime',
  join(target, 'wasm32-unknown-unknown/release/terminal_worker_wasix_runtime.wasm'),
], { cwd: root, stdio: 'pipe' });

const require = createRequire(import.meta.url);
const { Runtime } = require(join(bindings, 'wasix_runtime.js'));
let bytes;
if (watPath) {
  const binaryen = (await import('binaryen')).default;
  const module = binaryen.parseText(readFileSync(watPath, 'utf8'));
  module.runPasses(['asyncify']);
  bytes = Buffer.from(module.emitBinary());
} else {
  bytes = readFileSync(dashPath);
}
const env = ['PWD=/', 'HOME=/', 'PATH=/usr/bin', 'TERM=xterm', 'LANG=C.UTF-8'];
const pid = 1;
const guests = new Map();
const runtime = new Runtime();
runtime.register(pid, 0, JSON.stringify(argv), JSON.stringify(env), '/');
if (dashPath) {
  runtime.add_file('/dash', new Uint8Array(bytes));
  for (const path of ['/etc/profile', '/.profile', '/profile']) runtime.add_file(path, new Uint8Array(0));
}

class Exit extends Error {
  constructor(code) {
    super(`exit ${code}`);
    this.code = code;
  }
}

globalThis.wasixGuest = {
  read(id, ptr, len) {
    return new Uint8Array(guests.get(id).memory.buffer, ptr, len).slice();
  },
  write(id, ptr, data) {
    new Uint8Array(guests.get(id).memory.buffer, ptr, data.length).set(data);
  },
  output(fd, data) {
    const out = Buffer.from(data);
    if (fd === 1) process.stdout.write(out);
    else if (fd === 2) process.stderr.write(out);
  },
  stackPointer(id) {
    return guests.get(id).instance.exports.__stack_pointer.value;
  },
  asyncify(id, action, data) {
    const exports = guests.get(id).instance.exports;
    if (action === 'start_unwind') exports.asyncify_start_unwind(data);
    else if (action === 'stop_unwind') exports.asyncify_stop_unwind();
    else if (action === 'start_rewind') exports.asyncify_start_rewind(data);
    else if (action === 'stop_rewind') exports.asyncify_stop_rewind();
  },
  clone(parent, child, stackPointer) {
    const source = guests.get(parent);
    let instance;
    let memory;
    if (source.importsMemory) {
      const pages = source.memory.buffer.byteLength / 65536;
      memory = new WebAssembly.Memory({ initial: pages, maximum: 65536, shared: source.shared });
      new Uint8Array(memory.buffer).set(new Uint8Array(source.memory.buffer));
      instance = new WebAssembly.Instance(source.module, importsFor(child, memory));
    } else {
      instance = new WebAssembly.Instance(source.module, importsFor(child));
      memory = instance.exports.memory;
      // The parent's memory may have grown past what a new instance starts with.
      const grown = (source.memory.buffer.byteLength - memory.buffer.byteLength) / 65536;
      if (grown > 0) memory.grow(grown);
      new Uint8Array(memory.buffer).set(new Uint8Array(source.memory.buffer));
    }
    instance.exports.__stack_pointer.value = stackPointer;
    guests.set(child, {
      instance,
      memory,
      module: source.module,
      shared: source.shared,
      importsMemory: source.importsMemory,
    });
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

function importsFor(id, memory) {
  const wasix = {};
  for (const name of names) {
    wasix[name] = (...args) => {
      const numbers = Uint32Array.from(args.map(value => Number(value) >>> 0));
      const result = JSON.parse(runtime.syscall(id, name, numbers));
      if (process.env.WASIX_LOG === '1') console.error(`syscall ${id} ${name}(${Array.from(numbers).join(',')}) -> ${JSON.stringify(result)}`);
      if (result.kind === 'exit') throw new Exit(result.code);
      if (result.kind === 'unwind') return 0;
      return result.errno;
    };
  }
  return { env: memory ? { memory } : {}, wasix_32v1: wasix };
}

function run(id) {
  const guest = guests.get(id);
  try {
    guest.instance.exports._start();
  } catch (error) {
    if (error instanceof Exit) {
      process.stdout.write(`\n[${id} exit ${error.code}]\n`);
      return;
    }
    throw error;
  }
  const next = JSON.parse(runtime.unwind_done(id));
  if (process.env.WASIX_LOG === '1') console.error(`unwind_done ${id} -> ${JSON.stringify(next)}`);
  if (next.kind === 'resume') return run(id);
  if (next.kind === 'fork') {
    run(next.child);
    run(id);
    return;
  }
  if (next.kind === 'exit') {
    process.stdout.write(`\n[${id} exit ${next.code}]\n`);
    return;
  }
  if (next.kind === 'none') {
    process.stdout.write(`\n[${id} exit 0]\n`);
    return;
  }
  throw new Error(`unsupported asyncify action: ${JSON.stringify(next)}`);
}

const memory = new WebAssembly.Memory({ initial: 2, maximum: 65536, shared: true });
const module = await WebAssembly.compile(bytes);
const importsMemory = WebAssembly.Module.imports(module).some(
  entry => entry.kind === 'memory' && entry.module === 'env' && entry.name === 'memory',
);
const shared = importsMemory;
const imported = importsMemory ? memory : undefined;
const instance = new WebAssembly.Instance(module, importsFor(pid, imported));
const guestMemory = instance.exports.memory ?? imported;
guests.set(pid, { instance, memory: guestMemory, module, shared, importsMemory });
runtime.set_layout(pid, instance.exports.__data_end.value, instance.exports.__stack_pointer.value);
if (process.env.WASIX_LAYOUT === '1') {
  console.error(JSON.stringify({
    stack_pointer: instance.exports.__stack_pointer.value,
    data_end: instance.exports.__data_end.value,
    memory_pages: guestMemory.buffer.byteLength / 65536,
    imports_memory: importsMemory,
  }));
}
run(pid);
