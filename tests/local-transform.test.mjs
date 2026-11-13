import test from 'node:test';
import assert from 'node:assert/strict';
import { transformLocal } from '../web/kernel/local-transform.js';

// The real compiler is exercised in both browsers. Here inject worker startup/error/
// deadline races without waiting a minute or depending on browser OOM behavior.
test('local compiler bounds concurrency, terminates on success, and ignores late events', async () => {
  const previous = globalThis.Worker, workers = [];
  globalThis.Worker = class {
    constructor(url, options) { this.url = url; this.options = options; workers.push(this); }
    postMessage(bytes, transfer) { assert.equal(transfer[0], bytes.buffer); }
    terminate() { this.ended = true; }
  };
  try {
    const first = transformLocal(new Uint8Array([1]));
    await assert.rejects(transformLocal(new Uint8Array([2])), { errno: 'EAGAIN' });
    assert.equal(workers[0].url, '/local-compiler.js');
    assert.equal(workers[0].options.type, 'module');
    workers[0].onmessage({ data: { bytes: new Uint8Array([3]) } });
    assert.deepEqual(await first, new Uint8Array([3])); assert.ok(workers[0].ended);
    const next = transformLocal(new Uint8Array([4]));
    workers[0].onmessage({ data: { error: 'late event' } });
    await assert.rejects(transformLocal(new Uint8Array([5])), { errno: 'EAGAIN' });
    workers[1].onmessage({ data: { error: 'bad image' } });
    await assert.rejects(next, { errno: 'ENOEXEC' }); assert.ok(workers[1].ended);
  } finally { globalThis.Worker = previous; }
});

test('missing workers, startup failures and deadline expiry release the compiler slot', async () => {
  const previous = globalThis.Worker, timeout = globalThis.setTimeout, clear = globalThis.clearTimeout;
  let expire, terminated = 0;
  try {
    globalThis.Worker = undefined;
    await assert.rejects(transformLocal(new Uint8Array()), { errno: 'ENOTSUP' });
    globalThis.Worker = class { constructor() { throw new Error('cannot start'); } };
    await assert.rejects(transformLocal(new Uint8Array()), { errno: 'EIO' });
    globalThis.Worker = class { postMessage() {} terminate() { terminated++; } };
    globalThis.setTimeout = (callback, ms) => { assert.equal(ms, 60_000); expire = callback; return 42; };
    globalThis.clearTimeout = id => { if (id != null) assert.equal(id, 42); };
    const pending = transformLocal(new Uint8Array()); expire();
    await assert.rejects(pending, { errno: 'ETIMEDOUT' }); assert.equal(terminated, 1);
    const again = transformLocal(new Uint8Array()); expire();
    await assert.rejects(again, { errno: 'ETIMEDOUT' }); assert.equal(terminated, 2);
  } finally { globalThis.Worker = previous; globalThis.setTimeout = timeout; globalThis.clearTimeout = clear; }
});
