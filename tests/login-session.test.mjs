import test from 'node:test';
import assert from 'node:assert/strict';
import { LoginCoordinator } from '../web/kernel/login.js';

const view = (id = 'session', owner = 'host', generation = 1) => ({ id, uid: 1000, now: 100,
  expires: 1000, generation, owner, owner_expires: owner ? 130 : null, hosts: [{ host: 'host', expires: 130 }] });
const create = options => new LoginCoordinator({ host: 'host', proof: 'private-proof', ...options });

test('cached ownership expires by monotonic time and public metadata never exposes the proof', async () => {
  let time = 0;
  const c = create({ now: () => time, call: async () => view() });
  try {
    await c.tick(); assert.equal(c.current().coordinator, true);
    assert.ok(!JSON.stringify(c.current()).includes('private-proof'));
    time = 29_000; assert.equal(c.current().coordinator, false); assert.equal(c.current().connected, false);
  } finally { await c.stop(); }
});

test('a login change fences an unfinished join and releases it before joining the new login', async () => {
  let finish, joined = 0; const actions = [], seen = [];
  const c = create({ changed: value => seen.push(value), call: async action => {
    actions.push(action);
    if (action.op === 'join') {
      if (++joined === 1) return new Promise(resolve => { finish = resolve; });
      return view('new');
    }
    return null;
  } });
  try {
    const tick = c.tick(); await Promise.resolve();
    const reset = c.reset(); finish(view('old')); await tick; await reset;
    assert.deepEqual(actions.map(action => action.op), ['join', 'leave', 'join']);
    assert.ok(!seen.some(value => value.session?.id === 'old' && value.coordinator));
    assert.equal(c.current().session.id, 'new');
  } finally { await c.stop(); }
});

test('an unavailable authority removes coordinator status and a stale lease rejoins as a follower', async () => {
  let mode = 'ready';
  const c = create({ call: async action => {
    if (mode === 'offline') throw { errno: 'EIO' };
    if (mode === 'replaced' && action.op === 'renew') throw { errno: 'ESTALE' };
    return view('session', mode === 'replaced' ? 'other' : 'host', mode === 'replaced' ? 2 : 1);
  } });
  try {
    await c.tick(); mode = 'offline'; await c.tick(); assert.equal(c.current().coordinator, false);
    mode = 'replaced'; await c.tick(); assert.equal(c.current().connected, true);
    assert.equal(c.current().coordinator, false); assert.equal(c.current().session.generation, 2);
  } finally { await c.stop(); }
});

test('losing a concurrent claim observes the winner without retrying a stale generation', async () => {
  const calls = [];
  const c = create({ call: async action => {
    calls.push(action.op);
    if (action.op === 'join') return view('session', null, 0);
    if (action.op === 'claim') throw { errno: 'ESTALE' };
    return view('session', 'other', 1);
  } });
  try { await c.tick(); assert.equal(c.current().coordinator, false); assert.deepEqual(calls, ['join', 'claim', 'keep']); }
  finally { await c.stop(); }
});

test('closing during startup releases the late membership without publishing ownership', async () => {
  let finish; const seen = [], calls = [];
  const c = create({ changed: value => seen.push(value), call: async action => {
    calls.push(action.op);
    if (action.op === 'join') return new Promise(resolve => { finish = resolve; });
    return null;
  } });
  const tick = c.tick(); await Promise.resolve(); const stopped = c.stop(); finish(view());
  await tick; await stopped;
  assert.deepEqual(calls, ['join', 'leave']); assert.ok(!seen.some(value => value.coordinator));
});

test('repeated revocation cannot create an unbounded rejoin loop', async () => {
  let joins = 0;
  const c = create({ call: async action => {
    if (action.op === 'join') { joins++; return view('session', null, 0); }
    throw { errno: 'ESTALE' };
  } });
  try { await c.tick(); assert.equal(joins, 2); assert.equal(c.current().connected, false); }
  finally { await c.stop(); }
});

test('managed controls require a current fence and do not extend cached ownership', async () => {
  let time = 0; const calls = [];
  const c = create({ now: () => time, call: async action => { calls.push(action); return view(); } });
  try {
    await c.tick();
    assert.throws(() => c.capture({ session: 'old', generation: 1 }), e => e.errno === 'ESTALE');
    await c.control('signal', { pid: 42, signal: 15 }, { session: 'session', generation: 1 });
    assert.equal(calls.at(-1).member.proof, 'private-proof');
    assert.ok(!JSON.stringify(c.current()).includes('private-proof'));
    time = 29_000;
    await assert.rejects(c.control('signal', { pid: 42, signal: 15 }, { session: 'session', generation: 1 }), e => e.errno === 'EACCES');
    assert.equal(calls.filter(a => a.op === 'signal').length, 1);
  } finally { await c.stop(); }
});

test('a late managed attachment reply cannot authorize startup after login retirement', async () => {
  const c = create({ call: async () => view() });
  try {
    await c.tick();
    const ticket = c.capture({ session: 'session', generation: 1 });
    c.retire();
    assert.throws(() => c.checked(ticket, view()), e => e.errno === 'EACCES');
    assert.equal(c.current().coordinator, false);
  } finally { await c.stop(); }
});
