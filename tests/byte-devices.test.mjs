import test from 'node:test';
import assert from 'node:assert/strict';
import { DEVICE_READ_MAX, readDevice } from '../web/wasi/devices.mjs';

test('device reads bound allocation and split cryptographic requests at the platform quota', () => {
  for (const name of ['random', 'urandom']) {
    const lengths = [];
    const entropy = { getRandomValues(bytes) { assert.ok(bytes.length <= 65536); lengths.push(bytes.length); bytes.fill(lengths.length); return bytes; } };
    const bytes = readDevice(name, 70001, entropy);
    assert.deepEqual(lengths, [65536, 4465]);
    assert.equal(bytes[65535], 1); assert.equal(bytes[65536], 2);
    assert.equal(readDevice(name, Number.MAX_SAFE_INTEGER, entropy).length, DEVICE_READ_MAX);
  }
});

test('entropy failure propagates without producing predictable fallback bytes', () => {
  const failed = { getRandomValues() { throw new Error('entropy unavailable'); } };
  for (const name of ['random', 'urandom']) {
    assert.throws(() => readDevice(name, 32, failed), /entropy unavailable/);
    assert.throws(() => readDevice(name, 32, null), TypeError);
    assert.equal(readDevice(name, 0, failed).length, 0);
  }
});

test('null ends immediately and zero/full produce bounded zero bytes without entropy', () => {
  const entropy = { getRandomValues() { assert.fail('not a random device'); } };
  assert.equal(readDevice('null', 70001, entropy).length, 0);
  for (const name of ['zero', 'full']) assert.deepEqual(readDevice(name, 70001, entropy), new Uint8Array(70001));
  for (const count of [-1, NaN, 0.5, Infinity]) assert.throws(() => readDevice('zero', count), RangeError);
  assert.throws(() => readDevice('unknown', 1), RangeError);
});
