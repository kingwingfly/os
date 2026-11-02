// The loader (owner's design, issue #20 phase 2): what an exec's image becomes. A module is
// compiled once per immutable content (the exec's `version`, the file's content id; an asset's
// path for /usr), concurrent compiles sharing one promise, and validated: only the imports the
// engine provides (WASI preview 1, terminal.sys, WASIX), a `_start`, and a memory. Anything
// else cannot execute, as Linux's loader says (ENOEXEC); what the kernel checked (the X rule)
// is not asked again: its exec token is the leave to read the image.
//
// A load is what instantiation needs: the compiled module, and, for a module that imports its
// memory (WASIX's do, as env.memory), the memory's declared limits and shared flag, so every
// process creates one of exactly that type. A module of its own exports `memory`.

// How many modules stay compiled at once; the oldest goes past that (LRU).
const CACHE_MAX = 8;
// The import namespaces a process may ask for (web/wasi/process.js, the WASIX runtime): WASI
// preview 1 and the kernel's own terminal.sys; WASIX, stubbed until its runtime lands (its
// calls answer NOSYS). env's memory, which WASIX modules import.
const NAMESPACES = new Set(['wasi_snapshot_preview1', 'terminal', 'wasix_32v1']);
const MEMORY = { module: 'env', name: 'memory' };

const compiled = new Map();
// For the tests: how many modules were really compiled (a cache hit compiles none).
export const stats = { compiled: 0 };
globalThis.loaderStats = stats;

// The module the exec result `image` loads, compiling it once per content: an asset path for
// /usr, or an uploaded file read by its exec token with the process's token.
export function load(image) {
  const key = image.version ?? image.asset;
  const known = compiled.get(key);
  if (known) {
    // A cache hit is the newest: an image just run is not the one evicted next.
    compiled.delete(key);
    compiled.set(key, known);
    return known;
  }
  const promise = compile(image);
  // A failed compile leaves nothing behind, and takes only its own entry with it: a later load
  // of the same content may already have replaced this promise.
  promise.catch(() => {
    if (compiled.get(key) === promise) compiled.delete(key);
  });
  compiled.set(key, promise);
  while (compiled.size > CACHE_MAX) compiled.delete(compiled.keys().next().value);
  return promise;
}

async function compile(image) {
  const response = image.asset
    ? await fetch(image.asset)
    : await fetch(`/api/file?token=${encodeURIComponent(image.token_read)}`, { headers: { 'X-Process-Token': image.token } });
  if (!response.ok) throw await refusal(response);
  // compileStreaming compiles as the bytes arrive, when the type says wasm; bytes always work.
  // A module that imports its memory names its type before anything runs, so a copy of the
  // response serves that prefix while the compiler reads the original.
  const streamed = response.headers.get('Content-Type') === 'application/wasm';
  let module, prefix;
  if (streamed) {
    prefix = response.clone();
    module = await WebAssembly.compileStreaming(response).catch(error => { throw formatError(error); });
  } else {
    prefix = new Uint8Array(await response.arrayBuffer());
    module = await WebAssembly.compile(prefix).catch(error => { throw formatError(error); });
  }
  const imports = WebAssembly.Module.imports(module);
  const memoryImport = validateImports(imports);
  let memory;
  if (memoryImport) {
    memory = await importedMemory(prefix).catch(error => {
      throw formatError(error);
    });
    if (!memory) throw formatError(new Error('no env.memory type'));
    // Shared memory must declare its maximum: the engine cannot grow it past one.
    if (memory.shared && memory.maximum == null) {
      throw formatError(new Error('shared memory without a maximum'));
    }
  } else if (streamed) {
    prefix.body?.cancel().catch(() => { /* the compiler is done with it */ });
  }
  validateExports(module, memoryImport);
  stats.compiled++;
  return { module, memory };
}

// What may not run, said as the kernel would: ENOEXEC, with what was wrong. The caller names
// the file, as the shell says it.
function formatError(error) {
  return Object.assign(
    new Error(`cannot execute binary file: Exec format error (${error?.message ?? error})`),
    { errno: 'ENOEXEC' },
  );
}
const fail = why => {
  throw formatError(new Error(why));
};

// The imports a process may ask for, as their kinds too: WASI, terminal.sys and WASIX are
// functions; the only memory is WASIX's env.memory. Returns whether the image imports one.
function validateImports(imports) {
  let memory = false;
  for (const entry of imports) {
    if (entry.kind === 'function' && NAMESPACES.has(entry.module)) continue;
    if (entry.kind === 'memory' && entry.module === MEMORY.module && entry.name === MEMORY.name) {
      if (memory) fail(`duplicate import ${entry.module}.${entry.name}`);
      memory = true;
      continue;
    }
    fail(`unknown import ${entry.module}.${entry.name}`);
  }
  return memory;
}

function validateExports(module, memoryImport) {
  const exports = WebAssembly.Module.exports(module);
  if (!exports.some(entry => entry.name === '_start' && entry.kind === 'function')) fail('no _start');
  if (!memoryImport && !exports.some(entry => entry.name === 'memory' && entry.kind === 'memory')) {
    fail('no memory');
  }
}

// Why the kernel refused to serve the image, as it said it: its errno and words, not one made
// up from the HTTP status. A reply without them (a proxy's, a device's) still gets a status's.
async function refusal(response) {
  let body;
  try {
    body = await response.json();
  } catch {
    // Not the kernel's JSON: the status is all it said.
  }
  const errno = typeof body?.errno === 'string'
    ? body.errno
    : response.status === 409 ? 'EBADF' : response.status === 404 ? 'ENOENT' : response.status >= 400 && response.status < 500 ? 'EACCES' : 'EIO';
  const message = typeof body?.error === 'string' ? body.error : errno;
  throw Object.assign(new Error(message), { errno });
}

// The memory `env.memory` declares, as the image's import section says: {initial, maximum,
// shared}. Only that section's prefix is read, and only for images that import a memory.
async function importedMemory(prefix) {
  const { pull, close } = sourceOf(prefix);
  const cursor = new Cursor(pull);
  try {
    const magic = await cursor.bytes(4);
    if (magic[0] !== 0x00 || magic[1] !== 0x61 || magic[2] !== 0x73 || magic[3] !== 0x6d) {
      throw new Error('not a wasm module');
    }
    const version = await cursor.bytes(4);
    if (version[0] !== 1 || version[1] !== 0 || version[2] !== 0 || version[3] !== 0) {
      throw new Error('not wasm version 1');
    }
    for (;;) {
      let id;
      try {
        id = await cursor.u8();
      } catch {
        // The sections ended before an import section: there is none.
        return undefined;
      }
      // Sections ascend: types (1) precede imports (2), and nothing but custom sections (0)
      // may come before them. Past 2, there is no import section at all.
      if (id > 2) return undefined;
      const size = await cursor.u32();
      if (id !== 2) {
        await cursor.skip(size);
        continue;
      }
      const count = await cursor.u32();
      let memory;
      for (let index = 0; index < count; index++) {
        const module = await cursor.string();
        const name = await cursor.string();
        const kind = await cursor.u8();
        if (kind === 0) {
          await cursor.u32();
        } else if (kind === 1) {
          await cursor.u8();
          await limits(cursor);
        } else if (kind === 2) {
          const type = await limits(cursor);
          if (module === MEMORY.module && name === MEMORY.name) memory = type;
        } else if (kind === 3) {
          await cursor.u8();
          await cursor.u8();
        } else if (kind === 4) {
          await cursor.u8();
          await cursor.u32();
        } else {
          throw new Error(`unknown import kind ${kind}`);
        }
      }
      return memory;
    }
  } finally {
    close();
  }
}

// A memory's limits from the binary: flags (0x1 maximum, 0x2 shared), minimum, then maximum.
async function limits(cursor) {
  const flags = await cursor.u32();
  if (flags & ~3) throw new Error('unknown memory limits flags');
  const initial = await cursor.u32();
  const maximum = flags & 1 ? await cursor.u32() : undefined;
  return { initial, maximum, shared: (flags & 2) !== 0 };
}

// The prefix's bytes, chunk by chunk: a Response's stream, or bytes already read.
function sourceOf(prefix) {
  if (prefix instanceof Response) {
    const reader = prefix.body.getReader();
    return {
      pull: async () => {
        const { value, done } = await reader.read();
        return done ? null : value;
      },
      close: () => reader.cancel().catch(() => { /* the compiler is done with it */ }),
    };
  }
  let at = 0;
  return {
    pull: async () => {
      if (at >= prefix.length) return null;
      const chunk = prefix.subarray(at, at + 65536);
      at += chunk.length;
      return chunk;
    },
    close: () => {},
  };
}

// A cursor over a pull source, with the binary format's integers and strings.
class Cursor {
  constructor(pull) {
    this.pull = pull;
    this.buf = new Uint8Array(0);
    this.at = 0;
    this.ended = false;
  }

  async need(length) {
    while (this.buf.length - this.at < length) {
      if (this.ended) throw new Error('truncated wasm');
      const chunk = await this.pull();
      const rest = this.buf.subarray(this.at);
      if (!chunk) {
        this.ended = true;
        if (rest.length < length) throw new Error('truncated wasm');
      } else {
        const next = new Uint8Array(rest.length + chunk.length);
        next.set(rest);
        next.set(chunk, rest.length);
        this.buf = next;
        this.at = 0;
      }
    }
  }

  async bytes(length) {
    await this.need(length);
    const bytes = this.buf.subarray(this.at, this.at + length);
    this.at += length;
    return bytes;
  }

  async u8() {
    await this.need(1);
    return this.buf[this.at++];
  }

  async u32() {
    let value = 0;
    for (let shift = 0; ; shift += 7) {
      const byte = await this.u8();
      value += (byte & 0x7f) * 2 ** shift;
      if (!(byte & 0x80)) return value;
      if (shift >= 28) throw new Error('malformed wasm integer');
    }
  }

  async skip(length) {
    await this.need(length);
    this.at += length;
  }

  async string() {
    const length = await this.u32();
    return new TextDecoder().decode(await this.bytes(length));
  }
}
