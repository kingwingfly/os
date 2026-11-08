import test from 'node:test';
import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { once } from 'node:events';
import binaryen from 'binaryen';

test('server compiler transforms fixed-memory modules without running their initializer', async () => {
  const server = fork(new URL('../containers/compiler/server.mjs', import.meta.url), [], { env: { ...process.env, PORT: '0' }, stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
  try {
    const [{ port }] = await once(server, 'message');
    const module = binaryen.parseText(`(module
      (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
      (memory (export "memory") 1 1)
      (func $init unreachable) (start $init)
      (func (export "_start") (drop (call $fork (i32.const 1) (i32.const 0)))))`);
    let bytes; try { bytes = module.emitBinary(); } finally { module.dispose(); }
    const response = await fetch(`http://127.0.0.1:${port}/compile`, { method: 'POST', body: bytes });
    assert.equal(response.status, 200, await response.clone().text().then(text => text.slice(0, 200)));
    const compiled = await WebAssembly.compile(await response.arrayBuffer());
    const instance = await WebAssembly.instantiate(compiled, { wasix_32v1: { proc_fork: () => 0 } });
    assert.equal(instance.exports.memory.buffer.byteLength, 65536);
    assert.throws(() => instance.exports.memory.grow(1), RangeError);
    assert.ok(instance.exports.__tw_asyncify_memory instanceof WebAssembly.Memory);
    assert.throws(() => instance.exports.__tw_initialize(), WebAssembly.RuntimeError);
    const invalid = await fetch(`http://127.0.0.1:${port}/compile`, { method: 'POST', body: 'not wasm' });
    assert.equal(invalid.status, 422);
    assert.equal((await invalid.json()).errno, 'ENOEXEC');
    for (const namespace of ['os', 'terminal']) {
      const probe = binaryen.parseText(`(module
        (import "${namespace}" "umask" (func $mask (param i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "_start") (drop (call $mask (i32.const 18)))))`);
      try {
        const reply = await fetch(`http://127.0.0.1:${port}/compile`, { method: 'POST', body: probe.emitBinary() });
        assert.equal(reply.status, 200, namespace);
        const compiled = await WebAssembly.compile(await reply.arrayBuffer());
        let called = false;
        const running = await WebAssembly.instantiate(compiled, { [namespace]: { umask: mask => { called = true; return mask; } } });
        running.exports._start();
        assert.equal(called, true);
      } finally { probe.dispose(); }
    }
  } finally { server.kill(); await once(server, 'exit'); }
});
