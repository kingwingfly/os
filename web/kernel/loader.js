// The loader (owner's design, issue #20 phase 2): what an exec's image becomes. A module is
// compiled once per immutable content (the exec's `version`, the file's content id; an asset's
// path for /usr), concurrent compiles sharing one promise, and validated: only the imports the
// engine provides (WASI preview 1, terminal.sys, WASIX), a `_start`, and a memory. Anything
// else cannot execute, as Linux's loader says (ENOEXEC); what the kernel checked (the X rule)
// is not asked again: its exec token is the leave to read the image.

// How many modules stay compiled at once; the oldest goes past that (LRU).
const CACHE_MAX = 8;
// The import namespaces a process may ask for (web/wasi/process.js, the WASIX runtime): WASI
// preview 1 and the kernel's own terminal.sys; WASIX, stubbed until its runtime lands (its
// calls answer NOSYS); env's memory, which WASIX modules import.
const NAMESPACES = new Set(['wasi_snapshot_preview1', 'terminal', 'wasix_32v1']);
const ALLOWED = { env: ['memory'] };

const compiled = new Map();
// For the tests: how many modules were really compiled (a cache hit compiles none).
export const stats = { compiled: 0 };
globalThis.loaderStats = stats;

// The module the exec result `image` loads, compiling it once per content: an asset path for
// /usr, or an uploaded file read by its exec token with the process's token.
export function load(image) {
  const key = image.version ?? image.asset;
  if (compiled.has(key)) return compiled.get(key);
  const promise = compile(image);
  promise.catch(() => compiled.delete(key));
  compiled.set(key, promise);
  while (compiled.size > CACHE_MAX) compiled.delete(compiled.keys().next().value);
  return promise;
}

async function compile(image) {
  const response = image.asset
    ? await fetch(image.asset)
    : await fetch(`/api/file?token=${encodeURIComponent(image.token_read)}`, { headers: { 'X-Process-Token': image.token } });
  if (!response.ok) {
    const errno = response.status === 403 || response.status === 409 ? 'EACCES' : response.status === 404 ? 'ENOENT' : 'EIO';
    throw Object.assign(new Error(errno), { errno });
  }
  // compileStreaming compiles as the bytes arrive, when the type says wasm; bytes always work.
  // What is not a wasm module at all is ENOEXEC, as Linux's loader says.
  const module = await (response.headers.get('Content-Type') === 'application/wasm'
    ? WebAssembly.compileStreaming(response)
    : response.arrayBuffer().then(bytes => WebAssembly.compile(bytes))
  ).catch(() => {
    throw Object.assign(new Error('cannot execute binary file: Exec format error'), { errno: 'ENOEXEC' });
  });
  validate(module);
  stats.compiled++;
  return module;
}

// What may not run, said as the kernel would: ENOEXEC, with what was wrong. The caller names
// the file, as the shell says it.
function validate(module) {
  const fail = why => {
    throw Object.assign(new Error(`cannot execute binary file: Exec format error (${why})`), { errno: 'ENOEXEC' });
  };
  const imports = WebAssembly.Module.imports(module);
  for (const entry of imports) {
    if (!NAMESPACES.has(entry.module) && !(ALLOWED[entry.module] ?? []).includes(entry.name)) {
      fail(`unknown import ${entry.module}.${entry.name}`);
    }
  }
  const exports = WebAssembly.Module.exports(module);
  if (!exports.some(entry => entry.name === '_start' && entry.kind === 'function')) fail('no _start');
  if (!imports.some(entry => entry.kind === 'memory') && !exports.some(entry => entry.kind === 'memory')) fail('no memory');
}
