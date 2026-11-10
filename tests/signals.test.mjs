import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Signals, bit, CONTROL_WORDS } from '../web/wasi/signals.mjs';
import { Pipe, pipeBuffer } from '../web/wasi/pipe.js';
const fresh = state => new Signals(new Int32Array(new SharedArrayBuffer(4 * CONTROL_WORDS)), state);

test('standard signals coalesce while blocked and uncatchable signals remain unblocked', () => {
  const signals = fresh();
  signals.mask = bit(10) | bit(9) | bit(19);
  signals.queue(10); signals.queue(10);
  assert.equal(signals.take(), null);
  signals.queue(9);
  assert.equal(signals.take().n, 9);
  signals.mask = 0;
  assert.equal(signals.take().n, 10);
  assert.equal(signals.take(), null);
  assert.equal(signals.action(9, 1, 0, 0), -28);
  assert.equal(signals.action(19, 2, 0, 0), -28);
});

test('fork copies dispositions and mask but not pending signals; exec retains ignored dispositions', () => {
  const parent = fresh(); parent.callback = 'handler';
  parent.action(10, 2, bit(12), 0); parent.action(15, 1, 0, 0);
  parent.mask = bit(10); parent.queue(10);
  const child = fresh(parent.snapshot());
  assert.equal(child.mask, bit(10));
  assert.equal(child.take(), null);
  child.action(10, 0, 0, 0);
  assert.equal(parent.action(10, -1), 2);
  child.exec();
  assert.equal(child.callback, null);
  assert.equal(child.action(10, -1), 0);
  assert.equal(child.action(15, -1), 1);
  assert.equal(child.mask, bit(10));
});

test('ignoring a pending signal discards it without discarding other pending signals', () => {
  const signals = fresh(); signals.queue(10); signals.queue(12);
  signals.action(10, 1, 0, 0);
  assert.equal(signals.take().n, 12);
  assert.equal(signals.take(), null);
  assert.equal(signals.queue(32), 28);
  assert.equal(signals.action(0, 2, 0, 0), -28);
});

test('an interrupted pipe write reports bytes already transferred without duplicating them', () => {
  const pipe = new Pipe(pipeBuffer(64));
  const data = Uint8Array.from({ length: 8192 }, (_, index) => index % 251);
  const result = pipe.write(data, () => false);
  assert.deepEqual(result, { written: 64, broken: false });
  assert.deepEqual(pipe.read(64), data.slice(0, 64));
  pipe.closeReader();
  assert.deepEqual(pipe.write(data), { written: 0, broken: true });
});
