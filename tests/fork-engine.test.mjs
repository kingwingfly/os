// Phase 3: the fork engine of the terminal's processes (web/wasi/fork.js), over the loader's
// asyncify (web/kernel/asyncify.js), as a process Worker drives it: an uninstrumented module
// that imports WASIX's proc_fork is transformed, unwound at the fork, copied into a child
// instance of its own memory, and both are rewound; the child's fork answers 0, the parent's
// the child's pid.
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';

const binaryen = (await import('binaryen')).default;
const { asyncify } = await import('../web/kernel/asyncify.js');
const { Engine } = await import('../web/wasi/fork.js');

class Exit { constructor(code) { this.code = code; } }

// One process: its instance, engine and what it wrote; `pid`, what its fork answers it.
async function process(module, out, snapshot) {
  const self = {};
  const memory = () => self.instance.exports.memory;
  const imports = { wasix_32v1: {
    proc_fork: (copy, pidPtr) => {
      if (self.engine.rewinding) {
        new DataView(memory().buffer).setUint32(pidPtr, self.engine.resume().pid, true);
        return 0;
      }
      self.engine.unwind({ kind: 'fork' });
      return 0;
    },
    fd_write: (fd, iovs, count, written) => {
      const view = new DataView(memory().buffer);
      const [ptr, len] = [view.getUint32(iovs, true), view.getUint32(iovs + 4, true)];
      out.push(new TextDecoder().decode(new Uint8Array(memory().buffer, ptr, len)));
      view.setUint32(written, len, true);
      return 0;
    },
    proc_exit: code => { throw new Exit(code); },
  } };
  self.instance = await WebAssembly.instantiate(module, imports);
  self.engine = snapshot ? Engine.child(self.instance, memory, snapshot) : new Engine(self.instance, memory);
  return self;
}
// Run it until it exits or forks: its exit status, or what it asked.
function run(self) {
  try { self.instance.exports._start(); } catch (error) { if (error instanceof Exit) return { exit: error.code }; throw error; }
  return self.engine.unwound() ?? { exit: 0 };
}

test('a module that imports proc_fork forks: each rewinds its own copy', async () => {
  const wat = readFileSync(new URL('./fixtures/wasix-fork.wat', import.meta.url), 'utf8');
  const bytes = asyncify(binaryen, binaryen.parseText(wat).emitBinary(), ['wasix_32v1.proc_fork']);
  const module = await WebAssembly.compile(bytes);
  assert.ok(WebAssembly.Module.exports(module).some(entry => entry.name === 'asyncify_start_unwind'));
  const out = [];
  const parent = await process(module, out);
  assert.deepEqual(run(parent), { kind: 'fork' });
  // The child: the parent's memory and globals, in an instance of its own.
  const child = await process(module, out, parent.engine.snapshot());
  child.engine.rewind({ pid: 0 });
  assert.deepEqual(run(child), { exit: 0 });
  parent.engine.rewind({ pid: 2 });
  assert.deepEqual(run(parent), { exit: 0 });
  assert.deepEqual(out, ['child\n', 'parent\n']);
});
