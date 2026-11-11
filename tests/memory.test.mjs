import { test } from 'node:test';
import assert from 'node:assert/strict';
import binaryen from 'binaryen';
import { instrumentMemory } from '../web/kernel/memory.js';

test('the compiler wraps actual growth in every memory and preserves failure semantics', async () => {
  const original = binaryen.parseText(`(module
    (memory $a (export "memory") 1 3) (memory $b 1 2)
    (func (export "grow") (param i32) (result i32) (memory.grow $a (local.get 0)))
    (func (export "second") (result i32) (memory.grow $b (i32.const 1))))`);
  original.setFeatures(binaryen.Features.MultiMemory);
  const bytes = instrumentMemory(binaryen, original.emitBinary()); original.dispose();
  let used = 2, ceiling = 4, reserved = 0;
  const { instance } = await WebAssembly.instantiate(bytes, { os_runtime: {
    memory_grow_pre: (_, delta) => {
      reserved = 0;
      if (used + (delta >>> 0) > ceiling) return -1;
      used += delta; reserved = delta; return delta;
    },
    memory_grow_post: (_, result) => { if (result === -1) used -= reserved; return result; },
  } });
  assert.equal(instance.exports.grow(1), 1); assert.equal(used, 3);
  assert.equal(instance.exports.second(), 1); assert.equal(used, 4);
  assert.equal(instance.exports.grow(1), -1); assert.equal(used, 4);
  ceiling = 100;
  assert.equal(instance.exports.grow(10), -1); assert.equal(used, 4);
  assert.equal(instance.exports.memory.buffer.byteLength, 2 * 65536);
});
