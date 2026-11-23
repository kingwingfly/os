import test from 'node:test';
import assert from 'node:assert/strict';
import { attachPortTransport } from '../web/mount-transport.js';

function remote(t, receive) {
  const { port1, port2 } = new MessageChannel();
  const transport = attachPortTransport(port2, 'relay');
  port1.onmessage = ({ data }) => {
    if (data.type !== 'frame') return;
    const length = new DataView(data.bytes).getUint32(0);
    assert.equal(length, data.bytes.byteLength - 4);
    receive(JSON.parse(new TextDecoder().decode(new Uint8Array(data.bytes, 4))), port1);
  };
  t.after(() => { transport.close(); port1.close(); });
  return transport;
}

const read = { op: 'read', handle: 1, offset: 0, len: 4 };
const write = { op: 'write', handle: 1, offset: 0, data: 'AQ==' };
function disconnected(error) {
  assert.equal(error.errno, 'ENOTCONN');
  assert.equal(error.uncertain_writes, false);
  assert.match(error.message, /shared folder is disconnected/);
  assert.doesNotMatch(error.message, /saved|file change|write/);
  return true;
}

test('a lost connection warns only requests with an unconfirmed file change', async t => {
  let received = 0;
  const mount = remote(t, (_frame, port) => { if (++received === 2) port.postMessage({ type: 'closed', errno: 'ENODEV' }); });
  await Promise.all([
    assert.rejects(mount.request(read), disconnected),
    assert.rejects(mount.request(write), error => {
      assert.equal(error.errno, 'EIO');
      assert.equal(error.uncertain_writes, true);
      assert.match(error.message, /may already have been saved/);
      return true;
    }),
  ]);
  assert.equal(mount.uncertain_writes, true);
});

test('an acknowledged change is not reported uncertain by a later disconnected read', async t => {
  const mount = remote(t, ({ request, request_id }, port) => {
    if (request.op === 'write') port.postMessage({ type: 'message', message: { type: 'reply', request_id, result: { Ok: { written: 1 } } } });
    else port.postMessage({ type: 'closed', errno: 'ENODEV' });
  });
  assert.equal((await mount.request(write)).written, 1);
  await assert.rejects(mount.request(read), disconnected);
  assert.equal(mount.uncertain_writes, false);
});
