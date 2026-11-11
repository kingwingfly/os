import test from 'node:test';
import assert from 'node:assert/strict';
import { enterSession, sessionTarget } from '../web/session-targets.js';
import { ShellSession } from '../web/shell-session-controller.js';
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };
const turns = async () => { for (let n = 0; n < 6; n++) await Promise.resolve(); };
const who = { user: 'alice', home: '/home/alice' };
function shell(options = {}) {
  const events = [], timers = new Map(); let id = 0;
  const session = new ShellSession({ identity: async () => who, close: () => {}, emit: v => events.push(v),
    setTimer: (fn, ms) => { timers.set(++id, { fn, ms }); return id; }, clearTimer: id => timers.delete(id), ...options });
  return { session, events, timers };
}

test('session targets are fixed routes and invalid selections cause no account mutation', async () => {
  assert.equal(sessionTarget('desktop'), '/'); assert.equal(sessionTarget('shell'), '/shell.html');
  let calls = 0;
  for (const target of ['https://example.test', '//example.test', '__proto__', 'constructor', '/shell.html']) {
    await assert.rejects(enterSession({ mode: 'login', target }, { call: () => calls++ }));
  }
  await assert.rejects(enterSession({ mode: 'bad', target: 'shell' }, { call: () => calls++ }));
  assert.equal(calls, 0);
});

test('authentication must finish before notification and navigation; failure stays on the greeter', async () => {
  const auth = deferred(), events = [];
  const deps = { call: async (name, args) => { events.push([name, args]); await auth.promise; return { uid: 42, signed_in: true }; },
    changed: (...args) => events.push(['changed', args]), navigate: path => events.push(['navigate', path]) };
  const done = enterSession({ mode: 'login', target: 'shell', username: 'alice', password: 'test-only' }, deps);
  assert.equal(events.length, 1); auth.resolve(); await done;
  assert.deepEqual(events.slice(1), [['changed', []], [{ login_session: { action: { op: 'inspect' } } }, undefined], ['navigate', '/shell.html']]);
  events.length = 0;
  await assert.rejects(enterSession({ mode: 'login', target: 'desktop' }, { ...deps, call: async () => { throw new Error('denied'); } }));
  assert.equal(events.length, 0);
  await enterSession({ mode: 'current', target: 'desktop', expected: { uid: 42, signed_in: true } }, deps);
  assert.deepEqual(events, [['getcreds', undefined], [{ login_session: { action: { op: 'inspect' } } }, undefined], ['navigate', '/']]);
  events.length = 0;
  await assert.rejects(enterSession({ mode: 'current', target: 'shell', expected: { uid: 43, signed_in: false } }, deps), /account changed/);
  assert.deepEqual(events, [['getcreds', undefined]]);
});

test('one shell uses ordinary identity, PTY I/O and argv; late callbacks cannot affect a replacement', async () => {
  const done = deferred(); let options, launches = 0;
  const { session: s, events } = shell({ execute: async (argv, given) => {
    launches++; assert.deepEqual(argv, [['/usr/bin/sh', '-i']]); options = given;
    assert.equal(given.cwd, who.home); assert.equal(given.tty, true); assert.equal(given.sudo, undefined);
    return done.promise;
  } });
  const first = s.start(); assert.equal(s.start(), first); await turns(); assert.equal(launches, 1);
  const input = []; options.onTty({ write: text => input.push(text), reply: text => input.push(text) });
  s.send('write', 'hello'); s.send('reply', '\x1b[1;1R'); s.send('write', 'x'.repeat(65537));
  assert.deepEqual(input, ['hello', '\x1b[1;1R']);
  done.resolve({ status: 7 }); await first; assert.equal(s.run, null); assert.equal(s.message, 'Shell exited (7)');
  const old = options, next = deferred(); s.execute = async (_args, given) => { options = given; return next.promise; };
  const second = s.start(); await turns(); const count = events.length;
  old.onOutput(1, 'old'); old.onTty({}); old.onState('stopped'); assert.equal(events.length, count);
  assert.equal(events.filter(v => v.type === 'reset').length, 2); next.resolve({ status: 0 }); await second;
});

test('ending during identity lookup prevents any executable launch', async () => {
  const lookup = deferred(); let executions = 0;
  const { session: s, timers } = shell({ identity: () => lookup.promise, execute: async () => { executions++; } });
  const done = s.start(); s.stop(); lookup.resolve(who); await done;
  assert.equal(executions, 0); assert.equal(timers.size, 0); assert.equal(s.run, null);
});

test('shutdown sends HUP and CONT, disables stale input, and bounds an unresponsive run with KILL', async () => {
  const done = deferred(), signals = [], inputs = []; let options;
  const { session: s, timers } = shell({ execute: async (_args, given) => {
    options = given; given.onJob({ signal: n => signals.push(n) }); given.onTty({ write: text => inputs.push(text) }); return done.promise;
  } });
  const running = s.start(); await turns(); options.onState('stopped'); s.send('resume', ''); assert.deepEqual(signals, [18]);
  signals.length = 0; s.stop(); s.stop(); s.send('write', 'late'); assert.deepEqual(signals, [1, 18]); assert.deepEqual(inputs, []);
  assert.equal(options.cancelled(), true); [...timers.values()][0].fn(); assert.deepEqual(signals, [1, 18, 9]);
  done.resolve({ status: 137 }); await running; assert.equal(timers.size, 0);
});

test('startup failure is visible, never loops automatically, and allows an explicit retry', async () => {
  let attempts = 0;
  const { session: s } = shell({ execute: async () => { attempts++; throw new Error('image unavailable'); } });
  await s.start(); await turns(); assert.equal(attempts, 1); assert.match(s.message, /image unavailable/);
  await s.start(); assert.equal(attempts, 2);
});


test('explicit entry restarts a completed session but refuses one still draining', async () => {
  const seen = [];
  const deps = { call: async action => { seen.push(action); return { id: 'ended', shutdown: { complete: true } }; },
    changed() {}, navigate: path => seen.push(path) };
  await enterSession({ mode: 'guest', target: 'shell' }, deps);
  assert.deepEqual(seen.slice(-2), [{ login_session: { action: { op: 'restart', session: 'ended' } } }, '/shell.html']);
  seen.length = 0;
  await assert.rejects(enterSession({ mode: 'guest', target: 'shell' }, { ...deps,
    call: async () => ({ id: 'ending', shutdown: { complete: false } }) }), /still shutting down/);
  assert.equal(seen.length, 0);
});
