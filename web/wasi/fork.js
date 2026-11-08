// The engine fork(2), setjmp and longjmp need in a process (web/wasi/process.js), as WASIX has
// them: binaryen's asyncify, which the loader adds to an image that imports them
// (web/kernel/loader.js). A call that forks, or saves or restores a stack, unwinds the image's
// stack into a buffer of its memory, back out of `_start`; the host then does what the call
// asked with nothing of the image's on the stack, and rewinds, re-entering the call, which
// returns. A fork's child is a copy of the memory, the mutable globals and the tables' entries
// in a new instance, rewound from the same buffer, in a Worker of its own: the parent's call
// returns the child's pid, the child's 0.
//
// The transform puts scratch in a separate memory, preserving the guest's declared limits
// and allocator layout. Mechanism only: who may fork,
// and the child's pid, are the client kernel's.

// asyncify's states, as asyncify_get_state answers.
export const NORMAL = 0, UNWINDING = 1, REWINDING = 2;
// The loader's table of every function of the image (web/kernel/asyncify.js).
const FUNCTIONS = '__tw_functions';
// The buffer an unwound stack is written to: its two words (where it is, where it ends), then
// the stack.
const BUFFER_PAGES = 4, PAGE = 65536;

export class Engine {
  // The engine of `instance`, whose memory `memory()` gives; `region`, the buffer a fork's
  // parent had already, which its child's memory holds.
  constructor(instance, memory, region = null) {
    this.exports = instance.exports;
    this.memory = memory;
    this.region = region;
    // What the unwinding call asked, and what the re-entered call is to answer.
    this.pending = null;
    this.answer = null;
    // The stack's top, as the image started: what a saved stack runs up to.
    this.top = region?.top ?? this.stackPointer();
  }
  // Whether the image was built for this (asyncify exports its controls).
  get able() { return typeof this.exports.asyncify_start_unwind === 'function'; }
  get state() { return this.able ? this.exports.asyncify_get_state() : NORMAL; }
  get rewinding() { return this.state === REWINDING; }
  // The shadow stack's pointer: the image's own global, or the loader's export of it.
  stackPointer() {
    const global = this.exports.__stack_pointer ?? this.exports.__tw_stack_pointer;
    return global instanceof WebAssembly.Global ? global.value : undefined;
  }
  setStackPointer(value) {
    const global = this.exports.__stack_pointer ?? this.exports.__tw_stack_pointer;
    if (global instanceof WebAssembly.Global) global.value = value;
  }
  stackMemory() { return this.exports.__tw_asyncify_memory ?? this.memory(); }
  words() { return new Int32Array(this.stackMemory().buffer); }
  // The separate scratch buffer: its two words at `at`, the stack after them.
  buffer() {
    if (!this.region) {
      if (!this.exports.__tw_asyncify_memory) throw new Error('image has no runtime scratch memory');
      const at = 0;
      this.region = { at, end: at + BUFFER_PAGES * PAGE, top: this.top };
    }
    return this.region;
  }
  // Unwind out of the image, for `pending`: the call returns, and so does each one below it.
  unwind(pending) {
    const { at, end } = this.buffer();
    const words = this.words();
    words[at >> 2] = at + 8;
    words[(at >> 2) + 1] = end;
    this.pending = pending;
    this.exports.asyncify_start_unwind(at);
  }
  // Once `_start` has returned: what the unwound call asked, if it unwound; the stack it left
  // is in the buffer.
  unwound() {
    if (this.state !== UNWINDING) return null;
    this.exports.asyncify_stop_unwind();
    const pending = this.pending;
    this.pending = null;
    return pending;
  }
  // The unwound stack, as bytes: what a setjmp keeps.
  saved() {
    const { at } = this.region, words = this.words();
    return new Uint8Array(this.stackMemory().buffer).slice(at + 8, words[at >> 2]);
  }
  // Rewind to the call that unwound (or, with `stack`, to the one a saved stack was unwound
  // from), which answers `answer`: run `_start` next.
  rewind(answer, stack) {
    const { at, end } = this.buffer();
    const words = this.words();
    if (stack) {
      new Uint8Array(this.stackMemory().buffer).set(stack, at + 8);
      words[at >> 2] = at + 8 + stack.length;
    }
    words[(at >> 2) + 1] = end;
    this.answer = answer;
    this.exports.asyncify_start_rewind(at);
  }
  // In the re-entered call: what it answers, the rewinding done.
  resume() {
    this.exports.asyncify_stop_rewind();
    const answer = this.answer;
    this.answer = null;
    return answer;
  }

  // ---- fork ----

  // What a child needs to be this image at this point: its memory, its mutable globals (the
  // shadow stack's pointer, thread-local storage's base, and the like), and what each of its
  // tables holds, by function (the loader's `__tw_functions` table numbers them), once unwound.
  snapshot() {
    const globals = {};
    for (const [name, value] of Object.entries(this.exports)) {
      if (!(value instanceof WebAssembly.Global)) continue;
      try {
        // Only a mutable global can be set again; reading one is how to find out.
        const now = value.value;
        value.value = now;
        globals[name] = typeof now === 'bigint' ? { bigint: String(now) } : now;
      } catch { /* immutable: the module's own */ }
    }
    const buffer = this.memory().buffer;
    const memories = {}, seen = new Set([this.memory()]);
    for (const [name, value] of Object.entries(this.exports)) {
      if (!(value instanceof WebAssembly.Memory) || seen.has(value)) continue;
      seen.add(value);
      memories[name] = new Uint8Array(value.buffer).slice();
    }
    return { memory: new Uint8Array(buffer).slice().buffer, memories, globals, tables: this.tables(), region: this.region };
  }
  // Each table's entries, as numbers of `__tw_functions`: -1 for none, -2 for what is not one
  // of the image's functions (kept as the child has it).
  tables() {
    const functions = this.exports[FUNCTIONS];
    if (!(functions instanceof WebAssembly.Table)) return {};
    const numbers = new Map();
    for (let index = 0; index < functions.length; index++) numbers.set(functions.get(index), index);
    const tables = {};
    for (const [name, table] of Object.entries(this.exports)) {
      if (!(table instanceof WebAssembly.Table) || table === functions) continue;
      const entries = new Int32Array(table.length);
      for (let index = 0; index < table.length; index++) {
        const entry = table.get(index);
        entries[index] = entry == null ? -1 : numbers.get(entry) ?? -2;
      }
      tables[name] = entries;
    }
    return tables;
  }
  // A child: this engine's image, with the memory and globals of the parent's `snapshot`.
  static child(instance, memory, snapshot) {
    const target = memory();
    const pages = snapshot.memory.byteLength / PAGE - target.buffer.byteLength / PAGE;
    if (pages > 0) target.grow(pages);
    new Uint8Array(target.buffer).set(new Uint8Array(snapshot.memory));
    for (const [name, bytes] of Object.entries(snapshot.memories ?? {})) {
      const memory = instance.exports[name];
      const pages = (bytes.length - memory.buffer.byteLength) / PAGE;
      if (pages > 0) memory.grow(pages);
      new Uint8Array(memory.buffer).set(bytes);
    }
    for (const [name, value] of Object.entries(snapshot.globals)) {
      const global = instance.exports[name];
      if (!(global instanceof WebAssembly.Global)) continue;
      try { global.value = typeof value === 'object' ? BigInt(value.bigint) : value; } catch { /* immutable here */ }
    }
    // Its tables hold what its parent's did: the same functions, this instance's own.
    const functions = instance.exports[FUNCTIONS];
    for (const [name, entries] of Object.entries(snapshot.tables ?? {})) {
      const table = instance.exports[name];
      if (!(table instanceof WebAssembly.Table) || !(functions instanceof WebAssembly.Table)) continue;
      if (table.length < entries.length) table.grow(entries.length - table.length);
      for (let index = 0; index < entries.length; index++) {
        if (entries[index] === -2) continue;
        table.set(index, entries[index] === -1 ? null : functions.get(entries[index]));
      }
    }
    return new Engine(instance, memory, snapshot.region);
  }
}
