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
if (!dashPath) {
  console.error('WASIX_DASH is not set; point it at a WASIX dash binary.');
  process.exit(2);
}
const argv = process.argv.slice(2);
if (!argv.length) argv.push('dash', '-c', 'echo one; (echo two); echo three');

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
const bytes = readFileSync(dashPath);
const env = ['PWD=/', 'HOME=/', 'PATH=/usr/bin', 'TERM=xterm', 'LANG=C.UTF-8'];
const pid = 1;
const guests = new Map();
const runtime = new Runtime();
runtime.register(pid, 0, JSON.stringify(argv), JSON.stringify(env), '/');
runtime.add_file('/dash', new Uint8Array(bytes));
for (const path of ['/etc/profile', '/.profile', '/profile']) runtime.add_file(path, new Uint8Array(0));

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

function importsFor(id, memory) {
  const wasix = {};
  for (const name of names) {
    wasix[name] = (...args) => {
      const numbers = Uint32Array.from(args.map(value => Number(value) >>> 0));
      const result = JSON.parse(runtime.syscall(id, name, numbers));
      if (result.kind === 'exit') throw new Exit(result.code);
      if (result.kind === 'unwind') return 0;
      return result.errno;
    };
  }
  return { env: { memory }, wasix_32v1: wasix };
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
const instance = new WebAssembly.Instance(module, importsFor(pid, memory));
guests.set(pid, { instance, memory, module });
runtime.set_layout(pid, instance.exports.__data_end.value, instance.exports.__stack_pointer.value);
run(pid);
