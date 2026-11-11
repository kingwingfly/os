import test from 'node:test';
import assert from 'node:assert/strict';
import { InitCoordinator } from '../web/kernel/init.js';

const view = (owner = 'host', generation = 1) => ({ boot: 'boot', pid: 1, now: 100,
  lease: 30, generation, owner, owner_expires: owner ? 130 : null });
const create = options => new InitCoordinator({ host: 'host', proof: 'private-proof', ...options });

test('only a proven lease reports ownership, with a monotonic deadline and no public proof', async () => {
  let time = 0; const calls = [];
  const c = create({ now: () => time, call: async action => {
    calls.push(action.op); return view();
  } });
  try {
    await c.tick(); assert.deepEqual(calls, ['inspect', 'renew']);
    assert.equal(c.current().coordinator, true);
    assert.ok(!JSON.stringify(c.current()).includes('private-proof'));
    time = 29_000; assert.equal(c.current().coordinator, false);
  } finally { await c.stop(); }
});

test('the public owner name alone cannot make a host a coordinator', async () => {
  const c = create({ call: async action => {
    if (action.op === 'renew') throw { errno: 'EACCES' };
    return view();
  } });
  try { await c.tick(); assert.equal(c.current().coordinator, false); }
  finally { await c.stop(); }
});

test('a lost claim race observes the winner without retrying indefinitely', async () => {
  const calls = [];
  const c = create({ call: async action => {
    calls.push(action.op);
    if (action.op === 'claim') throw { errno: 'ESTALE' };
    return calls.length === 1 ? view(null, 0) : view('other', 1);
  } });
  try {
    await c.tick(); assert.deepEqual(calls, ['inspect', 'claim', 'inspect']);
    assert.equal(c.current().coordinator, false); assert.equal(c.current().init.owner, 'other');
  } finally { await c.stop(); }
});

test('transport failure removes cached ownership and a lost success response can recover', async () => {
  let claimed = false, lost = false;
  const c = create({ call: async action => {
    if (action.op === 'claim') { claimed = true; throw { errno: 'EIO' }; }
    if (lost) throw { errno: 'EIO' };
    return claimed ? view() : view(null, 0);
  } });
  try {
    await c.tick(); assert.equal(c.current().connected, false);
    await c.tick(); assert.equal(c.current().coordinator, true);
    lost = true; await c.tick(); assert.equal(c.current().coordinator, false);
  } finally { await c.stop(); }
});

test('a stale renewal observes a successor and cannot release the successor on shutdown', async () => {
  let replaced = false; const calls = [];
  const c = create({ call: async action => {
    calls.push(action);
    if (replaced && action.op === 'renew') throw { errno: 'ESTALE' };
    return replaced ? view('other', 2) : view();
  } });
  await c.tick(); replaced = true; await c.tick();
  assert.equal(c.current().coordinator, false); assert.equal(c.current().init.generation, 2);
  await c.stop(); assert.ok(!calls.some(action => action.op === 'release'));
});

test('closing during a claim releases the late success without publishing it', async () => {
  let finish; const calls = [], seen = [];
  const c = create({ changed: value => seen.push(value), call: async action => {
    calls.push(action);
    if (action.op === 'claim') return new Promise(resolve => { finish = resolve; });
    return view(null, 0);
  } });
  const tick = c.tick();
  while (!finish) await Promise.resolve();
  const stopped = c.stop(); finish(view()); await tick; await stopped;
  assert.deepEqual(calls.map(action => action.op), ['inspect', 'claim', 'release']);
  assert.equal(calls[2].owner.generation, 1);
  assert.ok(!seen.some(value => value.coordinator));
});

test('resume after departure reacquires a new generation in the same boot', async () => {
  let current = view(null, 0);
  const c = create({ call: async action => {
    if (action.op === 'claim') current = view('host', current.generation + 1);
    if (action.op === 'release') current = view(null, current.generation);
    return current;
  } });
  try {
    await c.tick(); await c.stop(); await c.resume();
    assert.equal(c.current().coordinator, true); assert.equal(c.current().init.generation, 2);
    assert.equal(c.current().init.boot, 'boot');
  } finally { await c.stop(); }
});

const { InitReaper } = await import('../web/kernel/init.js');
const bootOwner = { boot: 'boot', generation: 1, host: 'host', proof: 'private' };
test('boot runs once per active execution and cancellation releases the captured generation', async () => {
  let finish, cancelled; const releases = [];
  const reaper = new InitReaper({ token: () => 'secret', release: async owner => releases.push(owner),
    start: async (owner, token, stopped, running) => {
      assert.equal(token, 'secret'); cancelled = stopped; running();
      await new Promise(resolve => { finish = resolve; });
    } });
  reaper.update({ coordinator: true }, bootOwner);
  const done = reaper.run.done;
  reaper.update({ coordinator: true }, bootOwner);
  assert.equal(reaper.attempts, 1); assert.equal(reaper.current().state, 'running');
  assert.ok(!JSON.stringify(reaper.current()).includes('secret'));
  reaper.update({ coordinator: true }, { ...bootOwner, generation: 2 });
  assert.equal(cancelled(), true); assert.equal(reaper.attempts, 1);
  finish(); await done;
  assert.equal(releases[0].generation, 1); assert.equal(reaper.current().state, 'stopped');
});

test('failed boot attempts are bounded and never start while ownership is absent', async () => {
  let starts = 0, exhausted = 0;
  const reaper = new InitReaper({ token: () => 'secret', release: async () => {}, exhausted: () => exhausted++,
    start: async () => { starts++; throw { errno: 'EIO', detail: 'cannot load init' }; } });
  reaper.update({ coordinator: false }, bootOwner); assert.equal(starts, 0);
  for (let generation = 1; generation <= 5; generation++) {
    reaper.update({ coordinator: true }, { ...bootOwner, generation });
    await reaper.run?.done;
  }
  assert.equal(starts, 3); assert.equal(exhausted, 1); assert.equal(reaper.current().state, 'failed');
  assert.equal(reaper.current().error, 'cannot load init');
});


test('a new durable Machine boot receives a fresh reaper failure budget', async () => {
  const reaper = new InitReaper({ token: () => 'secret', release: async () => {}, start: async () => { throw new Error('unavailable'); } });
  for (let generation = 1; generation <= 3; generation++) {
    reaper.update({ coordinator: true, init: { boot: 'first' } }, { boot: 'first', generation });
    await reaper.run.done;
  }
  assert.equal(reaper.failures, 3);
  reaper.update({ coordinator: true, init: { boot: 'second' } }, { boot: 'second', generation: 1 });
  assert.equal(reaper.attempts, 1); await reaper.run.done; assert.equal(reaper.failures, 1);
});
