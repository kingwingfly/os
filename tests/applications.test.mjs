import test from 'node:test';
import assert from 'node:assert/strict';
import { ApplicationSupervisor } from '../web/application-supervisor.js';
import { ApplicationPeer } from '../web/application-client.js';
import { validateExpectedSession, checkExpectedSession } from '../web/kernel/launch-context.js';
import { ShellSession } from '../web/shell-session-controller.js';
const scope = { session: 'login', boot: 'boot' }, nonce = 'a'.repeat(36);
const turns = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { resolve, promise }; };
function fixture(extra = {}) {
  let now = 0, ids = 0; const opened = [], connections = [], closed = [];
  const s = new ApplicationSupervisor({ now: () => now, token: () => String(++ids),
    open: path => { const w = { closed: false, path }; opened.push(w); return w; }, context: async () => scope,
    close: r => { r.window.closed = true; closed.push(r.id); },
    connect: (r, receive) => { const p = { messages: [], postMessage(v) { this.messages.push(v); }, close() { this.closed = true; } }; connections.push({ r, receive, p }); return p; }, ...extra });
  const launch = async () => { const id = s.launch('shell'); const r = s.records.get(id); s.hello(r.window, nonce); await turns(); return r; };
  return { s, opened, connections, closed, launch, time: n => { now = n; s.tick(); } };
}
test('only installed targets open and blocked popups create no records', () => {
  const f = fixture();
  for (const name of ['constructor', '__proto__', 'https://example.test', 'desktop']) assert.throws(() => f.s.launch(name));
  assert.equal(f.opened.length, 0);
  const blocked = fixture({ open: () => null }); assert.throws(() => blocked.s.launch('shell'), /pop-ups/); assert.equal(blocked.s.records.size, 0);
});
test('readiness needs the selected window, document and private channel after context capture', async () => {
  const lookup = deferred(), f = fixture({ context: () => lookup.promise });
  const id = f.s.launch('shell'), r = f.s.records.get(id);
  f.s.hello({}, nonce); f.s.hello(r.window, 'short'); assert.equal(r.nonce, undefined);
  f.s.hello(r.window, nonce); assert.equal(f.connections.length, 0);
  lookup.resolve(scope); await turns(); assert.equal(f.connections.length, 1); assert.equal(r.state, 'starting');
  f.connections[0].receive({ type: 'ready' }); assert.equal(r.state, 'ready');
  assert.deepEqual(Object.keys(f.s.snapshot()[0]).sort(), ['id', 'reason', 'state', 'target']);
});
test('stop during delayed context lookup cannot transfer a late port or revive a window', async () => {
  const lookup = deferred(), f = fixture({ context: () => lookup.promise });
  const id = f.s.launch('shell'), r = f.s.records.get(id); f.s.hello(r.window, nonce); f.s.stop(id);
  lookup.resolve(scope); await turns(); assert.equal(r.state, 'stopped'); assert.equal(f.connections.length, 0); assert.deepEqual(f.closed, [id]);
});
test('navigation fences the old document without closing its replacement', async () => {
  const f = fixture(), r = await f.launch(), connection = f.connections[0];
  f.s.hello(r.window, 'b'.repeat(36)); assert.equal(r.state, 'failed'); assert.equal(connection.p.closed, true);
  connection.receive({ type: 'ready' }); assert.equal(r.state, 'failed'); assert.deepEqual(f.closed, []);
});
test('startup and stop deadlines are bounded, idempotent and ignore late readiness', async () => {
  const f = fixture(), r = await f.launch(), connection = f.connections[0];
  f.time(30000); assert.equal(r.state, 'stopping'); assert.match(r.reason, /startup timed out/);
  f.time(35000); f.s.stop(r.id); connection.receive({ type: 'ready' }); assert.equal(r.state, 'stopping');
  f.time(38000); assert.equal(r.state, 'failed'); assert.deepEqual(f.closed, [r.id]); assert.equal(f.opened.length, 1);
});
test('ready applications survive startup deadlines but lost peers are stopped without automatic popup retries', async () => {
  const f = fixture(), r = await f.launch(); f.connections[0].receive({ type: 'ready' });
  f.time(30000); assert.equal(r.state, 'ready'); f.connections[0].receive({ type: 'pong' });
  f.time(104999); assert.equal(r.state, 'ready'); f.time(105000); assert.equal(r.state, 'stopping');
  f.time(113000); assert.equal(r.state, 'failed'); assert.equal(f.opened.length, 1);
});
test('confirmed login changes, shutdown and boot replacement stop only captured records; offline observations do not', async () => {
  for (const update of [s => s.login({ connected: true, session: { id: 'other' } }),
    s => s.login({ connected: true, session: { id: scope.session, shutdown: {} } }),
    s => s.boot({ connected: true, init: { boot: 'replacement' } }),
    s => s.boot({ connected: true, init: { boot: scope.boot, shutdown: {} } })]) {
    const f = fixture(), r = await f.launch(); f.connections[0].receive({ type: 'ready' });
    f.s.login({ connected: false }); f.s.boot({ connected: false }); assert.equal(r.state, 'ready');
    update(f.s); assert.equal(r.state, 'stopping');
    f.connections[0].receive({ type: 'exit', status: 143 }); assert.equal(r.state, 'stopped');
  }
});
test('capacity bounds active windows and terminal history without evicting active records', async () => {
  const f = fixture(); for (let i = 0; i < 8; i++) await f.launch(); assert.throws(() => f.s.launch('shell'), /Close an application/);
  const active = f.s.snapshot().slice(1).map(r => r.id);
  f.connections[0].receive({ type: 'exit', status: 1 });
  for (let i = 0; i < 20; i++) { await f.launch(); f.connections.at(-1).receive({ type: 'exit', status: 1 }); }
  assert.equal(f.s.records.size, 16); for (const id of active) assert.equal(f.s.records.get(id).state, 'starting');
});
test('natural completion does not close the output window or restart it', async () => {
  const f = fixture(), r = await f.launch(); f.connections[0].receive({ type: 'ready' }); f.connections[0].receive({ type: 'exit', status: 0 });
  f.time(999999); assert.equal(r.state, 'exited'); assert.equal(f.opened.length, 1); assert.deepEqual(f.closed, []);
});
test('peer loss waits for application cleanup and stop before adapter installation is retained', async () => {
  let now = 0, stopped = 0; const cleanup = deferred(), messages = [];
  const port = { postMessage: v => messages.push(v), close() {} };
  const peer = new ApplicationPeer(port, scope, { now: () => now });
  now = 75000; peer.tick(); peer.ready(); assert.equal(peer.stopping, true); assert.deepEqual(messages, [{ type: 'stopping' }]);
  peer.onStop(() => { stopped++; return cleanup.promise; }); await turns(); assert.equal(stopped, 1); assert.equal(messages.length, 1);
  peer.stop(); cleanup.resolve(); await turns(); assert.deepEqual(messages, [{ type: 'stopping' }, { type: 'exit', status: 0 }]);
});
test('execution expectations fail closed on old runtimes, foreign login scopes and replaced boots', () => {
  for (const value of [null, {}, { session: 'a', boot: '' }, { session: 3, boot: 'b' }]) assert.throws(() => validateExpectedSession(value));
  assert.deepEqual(validateExpectedSession({ ...scope, proof: 'ignored' }), scope);
  for (const image of [{}, { login_scope: 'other', boot: scope.boot }, { login_scope: scope.session, boot: 'other' }]) {
    assert.throws(() => checkExpectedSession(scope, image), { errno: 'ESTALE' });
  }
  checkExpectedSession(scope, { login_scope: scope.session, boot: scope.boot });
});
test('navigation retains a departure fence through delayed application cleanup', async () => {
  const cleanup = deferred(), messages = []; let closed = false;
  const peer = new ApplicationPeer({ postMessage: value => messages.push(value), close() {} }, scope);
  peer.onStop(() => cleanup.promise);
  peer.release = () => { if (!peer.departed) closed = true; };
  peer.left(); await turns(); assert.equal(peer.stopping, true); assert.equal(peer.departed, true);
  cleanup.resolve(); await turns(); assert.equal(closed, false); assert.equal(peer.ended, true);
  assert.equal(messages[0].type, 'left');
});
test('managed shell readiness waits for an actual read, carries expectations and awaits cleanup', async () => {
  const done = deferred(), events = []; let options;
  const s = new ShellSession({ expectedSession: scope, identity: async () => ({ home: '/', user: 'guest' }), close() {}, emit: e => events.push(e),
    execute: async (_, o) => { options = o; return done.promise; } });
  const running = s.start(); await turns(); assert.deepEqual(options.expectedSession, scope);
  options.onTty({ write() {} }); assert.equal(events.at(-1).input, false); assert.equal(events.at(-1).restartable, false);
  options.onReading(); assert.equal(events.at(-1).type, 'ready'); assert.equal(events.at(-2).input, true);
  const stopped = s.stop(); assert.equal(stopped, running); assert.equal(options.cancelled(), false);
  done.resolve({ status: 129 }); assert.equal((await stopped).status, 129);
});
