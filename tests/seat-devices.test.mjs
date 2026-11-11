import test from 'node:test';
import assert from 'node:assert/strict';
import { SeatDevices } from '../web/kernel/seat.js';

test('pause and resume fence all earlier input handles without closing devices', () => {
  const seat = new SeatDevices(), device = seat.open('console'), old = seat.stamp(device);
  seat.check(device, old);
  const paused = seat.change(false, seat.current());
  assert.throws(() => seat.check(device, old), e => e.errno === 'ESTALE');
  const pausedStamp = seat.stamp(device);
  assert.throws(() => seat.check(device, pausedStamp), e => e.errno === 'EACCES');
  seat.change(true, paused);
  assert.equal(seat.current().devices.length, 1);
  for (const stamp of [old, pausedStamp]) assert.throws(() => seat.check(device, stamp), e => e.errno === 'ESTALE');
  seat.check(device, seat.stamp(device));
});

test('activation is local and compare-and-swap rejects another seat or stale requests', () => {
  const one = new SeatDevices(), two = new SeatDevices(), before = one.current();
  assert.throws(() => one.change(false, two.current()), e => e.errno === 'ESTALE');
  one.change(false, before);
  assert.throws(() => one.change(true, before), e => e.errno === 'ESTALE');
  assert.equal(one.active, false); assert.equal(two.active, true);
  const paused = one.current(); assert.deepEqual(one.change(false, paused), paused);
  assert.throws(() => one.change('true', paused), e => e.errno === 'EINVAL');
});

test('closed and replaced devices cannot be addressed by old stamps or copied records', () => {
  const seat = new SeatDevices(), first = seat.open('console'), stamp = seat.stamp(first);
  assert.throws(() => seat.check({ ...first }, stamp), e => e.errno === 'ENODEV');
  seat.close(undefined); seat.close({ ...first });
  seat.check(first, stamp);
  seat.close(first); const second = seat.open('console');
  assert.throws(() => seat.check(first, stamp), e => e.errno === 'ENODEV');
  assert.throws(() => seat.check(second, stamp), e => e.errno === 'ESTALE');
  assert.throws(() => seat.check(second, { ...seat.stamp(second), device: first.id }), e => e.errno === 'ESTALE');
  seat.check(second, seat.stamp(second));
});

test('capacity bounds all devices, including those opened while paused, and close releases capacity', () => {
  const seat = new SeatDevices({ limit: 2 });
  const first = seat.open('console'); seat.change(false, seat.current());
  const second = seat.open('attachment');
  assert.throws(() => seat.open('console'), e => e.errno === 'ENOSPC');
  assert.throws(() => seat.check(second, seat.stamp(second)), e => e.errno === 'EACCES');
  seat.close(first); assert.equal(seat.open('console').kind, 'console');
  assert.equal(seat.current().devices.length, 2);
});

test('generation exhaustion fails closed and snapshots cannot mutate device policy', () => {
  const seat = new SeatDevices(), device = seat.open('console');
  const snapshot = seat.current(); snapshot.active = false; snapshot.devices[0].id = 'forged';
  seat.check(device, seat.stamp(device));
  seat.generation = Number.MAX_SAFE_INTEGER;
  assert.throws(() => seat.change(false, seat.current()), e => e.errno === 'ENOSPC');
  assert.equal(seat.active, true);
});
