import test from 'node:test';
import assert from 'node:assert/strict';
import { attachMount } from '../web/kernel/mount-sharing.js';

async function remote(t, receive) {
  const channel = new MessageChannel(), workspace = { check() {}, identity: { uid: 1 } };
  t.mock.method(globalThis, 'fetch', async () => Response.json({ id: crypto.randomUUID(), session: crypto.randomUUID(), ticket: 'test', expires: Date.now() + 60000, uid: 1, write: true }));
  channel.port1.onmessage = ({ data }) => {
    if (data.type === 'connect') channel.port1.postMessage({ type: 'ready' });
    else if (data.type === 'send') receive(data.message, channel.port1);
  };
  const mount = await attachMount(workspace, { address: 'osfs:' + crypto.randomUUID(), port: channel.port2, writable: true });
  t.after(() => { mount.unmount(mount.grant); channel.port1.close(); });
  return mount;
}

test('a lost connection warns only requests with an unconfirmed file change', async t => {
  let received = 0;
  const mount = await remote(t, (_message, port) => { if (++received === 2) port.postMessage({ type: 'closed', errno: 'ENODEV' }); });
  const [read, write] = await Promise.allSettled([
    mount.read(mount.grant, 'file', 0, 4),
    mount.write(mount.grant, 'file', new Uint8Array([1])),
  ]);
  assert.equal(read.status, 'rejected'); assert.equal(write.status, 'rejected');
  assert.match(read.reason.message, /shared folder is disconnected/);
  assert.doesNotMatch(read.reason.message, /saved|file change|write/);
  assert.match(write.reason.message, /may already have been saved/);
});

test('an acknowledged change is not reported uncertain by a later disconnected read', async t => {
  const mount = await remote(t, (message, port) => {
    if (message.op === 'write') port.postMessage({ type: 'message', message: { type: 'reply', id: message.id, value: { written: 1 } } });
    else port.postMessage({ type: 'closed', errno: 'ENODEV' });
  });
  assert.equal((await mount.write(mount.grant, 'file', new Uint8Array([1]))).written, 1);
  await assert.rejects(mount.read(mount.grant, 'file', 0, 4), error => /disconnected/.test(error.message) && !/saved/.test(error.message));
});
