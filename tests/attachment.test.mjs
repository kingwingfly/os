import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ConsoleGrants, ConsolePeer, consoleInput } from '../web/kernel/attachment.js';
import { Consoles } from '../web/kernel/console.js';
import { sharingAllowed } from '../web/kernel/sharing-policy.js';

test('sharing preference restricts grants and tightening or expired authentication revokes existing ports', async t => {
  let status = { connected: true, session: { seat_policy: { sharing: 'control' } } };
  const { grants, connect, run } = setup(t, { allowed: access => sharingAllowed(status, access) });
  const control = await connect('control'), view = await connect('view');
  status.session.seat_policy.sharing = 'view'; grants.sweep();
  await until(() => control.peer.ended);
  assert.equal(view.peer.ended, undefined);
  const channel = new MessageChannel();
  assert.throws(() => grants.grant(run, channel.port1, 'control'), e => e.errno === 'EACCES');
  channel.port1.close(); channel.port2.close();
  status.connected = false; grants.sweep(); await until(() => view.peer.ended);
  status.connected = true; status.session.seat_policy.sharing = 'control'; grants.sweep();
  assert.equal(grants.records.size, 0);
  assert.equal(sharingAllowed({ connected: true, session: {} }, 'view'), false);
  status.session.shutdown = {}; assert.equal(sharingAllowed(status, 'view'), false);
});

const until = async check => {
  for (let n = 0; n < 1000; n++) { if (check()) return; await new Promise(resolve => setTimeout(resolve, 1)); }
  assert.fail('console message did not arrive');
};
function setup(t, settings = {}) {
  const consoles = new Consoles(), grants = new ConsoleGrants(settings), received = [], peers = [], calls = [];
  const run = { displayed: new Map(), input: { write: text => calls.push(['input', text]),
    enqueue: bytes => calls.push(['reply', [...bytes]]), eof: () => calls.push(['eof']), resize: size => calls.push(['resize', size]) },
  snapshot: () => [{ type: 'mode', raw: false, echo: true }, { type: 'foreground', active: true }, { type: 'tty', active: true }] };
  consoles.acquire('pane', run);
  run.remoteInput = (controller, operation, value) => {
    if (!consoles.accepts(run, controller)) throw { errno: 'EACCES' };
    consoleInput(run, operation, value);
  };
  run.detach = () => grants.end(run, 'console pane closed', false);
  const connect = async (access = 'view', acknowledge = true) => {
    const channel = new MessageChannel(), id = grants.grant(run, channel.port1, access);
    const peer = new ConsolePeer(channel.port2, { ...settings, event(event, sequence) {
      received.push(event); if (acknowledge) peer.ack(sequence);
    } });
    peers.push(peer); await peer.ready; return { id, peer };
  };
  t.after(() => { for (const peer of peers) peer.close(); for (const id of grants.records.keys()) grants.revoke(id); });
  return { consoles, grants, received, peers, calls, run, connect };
}

test('view grants expose only console events and deny every write operation', async t => {
  const { grants, run, connect, calls, received } = setup(t);
  const { peer } = await connect();
  for (const [operation, value] of [['input', 'secret'], ['eof'], ['resize', { columns: 80, rows: 24, width: 0, height: 0 }], ['exec', '/bin/sh']])
    await assert.rejects(peer.request(operation, value), e => e.errno === 'EACCES');
  grants.publish(run, { type: 'output', fd: 1, text: 'visible', token: 'must-not-cross', run: 'private' });
  grants.publish(run, { type: 'job', pids: [42], token: 'must-not-cross' });
  await until(() => received.length === 1);
  assert.deepEqual(received, [{ type: 'output', fd: 1, text: 'visible' }]);
  assert.deepEqual(calls, []);
});

test('large output frames preserve Unicode characters at chunk boundaries', async t => {
  const { grants, run, connect, received } = setup(t);
  await connect();
  const text = 'a'.repeat(8191) + '\u{1f680}tail';
  grants.publish(run, { type: 'output', fd: 1, text });
  await until(() => received.length === 2);
  assert.equal(received.map(event => event.text).join(''), text);
  for (const event of received) assert.equal(event.text.isWellFormed(), true);
});

test('control transfers input exclusively, remains bound to its run and revocation restores the owner', async t => {
  const { consoles, grants, run, calls, connect } = setup(t);
  const { peer, id } = await connect('control');
  assert.equal(consoles.accepts(run), false);
  await peer.request('input', 'first\n');
  assert.deepEqual(calls, [['input', 'first\n']]);
  await assert.rejects(peer.request('input', 'x'.repeat(8193)), e => e.errno === 'EINVAL');
  await assert.rejects(peer.request('resize', { columns: -1, rows: 24, width: 0, height: 0 }), e => e.errno === 'EINVAL');
  await assert.rejects(peer.request('exec', '/bin/sh'), e => e.errno === 'ENOSYS');
  const other = { displayed: new Map() }; consoles.acquire('pane', other);
  await assert.rejects(peer.request('input', 'must-not-reach-new-run'), e => e.errno === 'EACCES');
  consoles.foreground(run, true); await peer.request('eof');
  grants.revoke(id); assert.equal(consoles.accepts(run), true);
  await until(() => peer.ended);
  await assert.rejects(peer.request('input', 'after-revoke'), e => e.errno === 'EPIPE');
  assert.deepEqual(calls, [['input', 'first\n'], ['eof']]);
});

test('normal exit drains final output but a reused pane cannot inherit a grant', async t => {
  const { consoles, grants, run, connect, received } = setup(t);
  const { peer } = await connect('control', false);
  grants.publish(run, { type: 'output', fd: 1, text: 'last output' }); grants.end(run);
  await until(() => received.length === 1);
  assert.equal(peer.ended, undefined); assert.equal(run.controller, null);
  await assert.rejects(peer.request('input', 'after-exit'), e => e.errno === 'EPIPE');
  consoles.release(run); const next = { displayed: new Map() }; consoles.acquire('pane', next);
  grants.publish(next, { type: 'output', fd: 1, text: 'must-not-leak' });
  for (const sequence of peer.events) peer.ack(sequence);
  await until(() => peer.ended);
  assert.deepEqual(received, [{ type: 'output', fd: 1, text: 'last output' }]);
});

test('closing a pane revokes attachments immediately and duplicate control grants fail', async t => {
  const { consoles, grants, run, connect } = setup(t);
  const { peer } = await connect('control');
  const channel = new MessageChannel();
  assert.throws(() => grants.grant(run, channel.port1, 'control'), e => e.errno === 'EBUSY'); channel.port2.close();
  await consoles.close('pane');
  assert.equal(grants.records.size, 0); await until(() => peer.ended);
  assert.equal(consoles.accepts(run), false);
});

test('stalled output is bounded and detaches its consumer without blocking the console', async t => {
  const { grants, consoles, run, connect, received } = setup(t);
  const { peer } = await connect('control', false);
  for (let i = 0; i < 20; i++) grants.publish(run, { type: 'output', fd: 1, text: 'x'.repeat(8192) });
  assert.equal(grants.records.size, 0); assert.equal(consoles.accepts(run), true);
  await until(() => peer.ended);
  assert.ok(received.length <= 4);
});

test('leases reclaim unused grants, lost peers and pending requests', async t => {
  let now = 0;
  const { grants, run, connect, consoles } = setup(t, { now: () => now, lease: 100, limit: 1 });
  const unused = new MessageChannel(), extra = new MessageChannel();
  grants.grant(run, unused.port1);
  assert.throws(() => grants.grant(run, extra.port1), e => e.errno === 'ENOSPC'); extra.port2.close();
  now = 101; grants.sweep(); unused.port2.close(); assert.equal(grants.records.size, 0);
  const { peer } = await connect('control');
  now = 202; grants.sweep(); assert.equal(consoles.accepts(run), true); await until(() => peer.ended);
  const absent = new MessageChannel();
  const lost = new ConsolePeer(absent.port1, { now: () => now, lease: 100 });
  const rejected = assert.rejects(lost.ready, e => e.errno === 'ETIMEDOUT');
  now += 101; lost.sweep(); await rejected; absent.port2.close();
});

test('replaying a remote input request cannot inject it twice', async t => {
  const { grants, run, calls } = setup(t), channel = new MessageChannel(), messages = [];
  channel.port2.onmessage = ({ data }) => messages.push(data);
  t.after(() => channel.port2.close());
  grants.grant(run, channel.port1, 'control'); channel.port2.postMessage({ v: 1, type: 'connect' });
  await until(() => messages.length > 0);
  const message = { v: 1, type: 'request', id: 1, operation: 'input', value: 'once' };
  channel.port2.postMessage(message); channel.port2.postMessage(message);
  await until(() => messages.some(m => m.type === 'closed'));
  assert.deepEqual(calls, [['input', 'once']]); assert.equal(grants.records.size, 0);
});

test('the receiving host rejects malformed snapshots and bounds unacknowledged events', async () => {
  for (const snapshot of [[{ type: 'job', pids: [1] }], Array(1), []]) {
    const invalid = snapshot.length > 0;
    const channel = new MessageChannel();
    const peer = new ConsolePeer(channel.port1);
    const ready = invalid ? assert.rejects(peer.ready, e => e.errno === 'EPROTO') : peer.ready;
    channel.port2.postMessage({ v: 1, type: 'event', sequence: 1,
      event: { type: 'ready', access: 'view', snapshot } });
    await ready;
    if (!invalid) {
      for (let sequence = 2; sequence <= 6; sequence++) channel.port2.postMessage({ v: 1, type: 'event', sequence, event: { type: 'output', fd: 1, text: 'x' } });
      await until(() => peer.ended);
    }
    assert.equal(peer.ended, true); channel.port2.close();
  }
});

test('a peer that sends heartbeats cannot keep requests or an unfinished handshake alive forever', async () => {
  for (const connected of [false, true]) {
    let now = 0;
    const channel = new MessageChannel(), peer = new ConsolePeer(channel.port1, { now: () => now, lease: 100 });
    let rejected;
    if (connected) {
      channel.port2.postMessage({ v: 1, type: 'event', sequence: 1, event: { type: 'ready', access: 'control', snapshot: [] } });
      await peer.ready;
      rejected = assert.rejects(peer.request('input', 'waiting'), e => e.errno === 'ETIMEDOUT');
    } else rejected = assert.rejects(peer.ready, e => e.errno === 'ETIMEDOUT');
    now = 101;
    channel.port2.postMessage({ v: 1, type: 'pong' }); await until(() => peer.heard === 101);
    peer.sweep(); await rejected; assert.equal(peer.ended, true); channel.port2.close();
  }
});
