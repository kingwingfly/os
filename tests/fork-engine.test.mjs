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

// A table the image changes as it runs (issue #30): the child calls through what its parent's
// table held at the fork, not what the module began with. Rewinding skips the table.set, as it
// skips everything before the fork, so only the snapshot can give it.
const TABLE = `(module
  (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
  (import "wasix_32v1" "proc_exit" (func $exit (param i32)))
  (memory (export "memory") 1)
  (global $sp (mut i32) (i32.const 4096))
  (type $answer (func (result i32)))
  (table $calls 1 funcref)
  (elem (table $calls) (i32.const 0) func $one)
  (elem declare func $two)
  (func $one (result i32) (i32.const 1))
  (func $two (result i32) (i32.const 2))
  (func (export "_start")
    (table.set $calls (i32.const 0) (ref.func $two))
    (drop (call $fork (i32.const 0) (i32.const 16)))
    (call $exit (call_indirect $calls (type $answer) (i32.const 0)))))`;

test('a fork\'s child holds what its parent\'s tables held, as the image changed them', async () => {
  const bytes = asyncify(binaryen, binaryen.parseText(TABLE).emitBinary(), ['wasix_32v1.proc_fork']);
  const module = await WebAssembly.compile(bytes);
  // The tables are exported, and one of every function.
  const names = WebAssembly.Module.exports(module).filter(entry => entry.kind === 'table').map(entry => entry.name);
  assert.ok(names.includes('__tw_functions'));
  const out = [];
  const parent = await process(module, out);
  assert.deepEqual(run(parent), { kind: 'fork' });
  const child = await process(module, out, parent.engine.snapshot());
  child.engine.rewind({ pid: 0 });
  assert.deepEqual(run(child), { exit: 2 });
  parent.engine.rewind({ pid: 2 });
  assert.deepEqual(run(parent), { exit: 2 });
});

test('a line\'s open files are counted by holder: a killed process\'s go, and the last is told', async () => {
  const { Shares, Bytes } = await import('../web/wasi/shared.js');
  const shares = new Shares();
  // A parent (pid 5) holds one, and its fork's child (pid 6) two, as dup made them.
  const slot = shares.claim(5, 1, 0);
  const gen = shares.gen(slot);
  shares.add(slot, 6, 2);
  // The child is killed: the parent still holds the file, which stays open.
  assert.deepEqual(shares.release(6), []);
  // The parent is killed too: it held the last, which its host is to close.
  assert.deepEqual(shares.release(5), [{ slot, gen }]);
  // A slot used again is another description.
  const again = shares.claim(7, 1, 0);
  assert.equal(again, slot);
  assert.notEqual(shares.gen(again), gen);
  // A lock a killed process held goes with it.
  shares.lock(again, 7);
  shares.release(7);
  shares.lock(again, 8);
  shares.unlock(again);
  const bytes = Bytes.create(1024);
  bytes.lock(9);
  bytes.release(9);
  bytes.lock(10);
  bytes.unlock();
});
