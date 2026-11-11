import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Consoles } from '../web/kernel/console.js';

const run = () => ({ displayed: new Map(), changes: [], group: {
  foreground(active) { this.active = active; }, hangup: async () => {},
} });

test('consoles allow one input owner and releasing a background lease preserves the foreground', () => {
  const consoles = new Consoles(), a = run(), b = run(), c = run();
  consoles.acquire('one', a); consoles.acquire('one', b); consoles.acquire('two', c);
  assert.equal(consoles.accepts(a), false); assert.equal(a.group.active, false);
  assert.equal(consoles.accepts(b), true); assert.equal(consoles.accepts(c), true);
  consoles.foreground(a, false); consoles.release(a);
  assert.equal(consoles.accepts(b), true);
  consoles.foreground(b, false); assert.equal(consoles.accepts(b), false);
  consoles.foreground(b, true); assert.equal(consoles.accepts(b), true);
});

test('active consoles survive cache pressure and exhaustion recovers from idle leases', () => {
  const consoles = new Consoles(2), a = run(), b = run(), c = run();
  consoles.acquire('a', a); consoles.acquire('b', b);
  assert.throws(() => consoles.acquire('c', c), e => e.errno === 'ENOSPC');
  const original = a.console;
  consoles.release(b); consoles.acquire('c', c);
  assert.equal(consoles.entries.get('a'), original); assert.equal(consoles.accepts(a), true);
  assert.equal(consoles.entries.has('b'), false);
});

test('console close wakes output, waits for hangup and rejects stale leases after ID reuse', async () => {
  const consoles = new Consoles(), a = run(), b = run();
  let resume, acknowledged = false, hungup = 0;
  a.group.hangup = () => { hungup++; return new Promise(resolve => { resume = resolve; }); };
  a.displayed.set(1, () => { acknowledged = true; });
  consoles.acquire('pane', a);
  const closing = consoles.close('pane');
  assert.equal(acknowledged, true); assert.equal(consoles.accepts(a), false);
  assert.throws(() => consoles.acquire('pane', b), e => e.errno === 'EPIPE');
  const duplicate = consoles.close('pane'); resume(); await closing; await duplicate;
  assert.equal(hungup, 1); consoles.acquire('pane', b);
  consoles.foreground(a, true); consoles.release(a);
  assert.equal(consoles.accepts(a), false); assert.equal(consoles.accepts(b), true);
});
