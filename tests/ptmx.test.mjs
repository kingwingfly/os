import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PtyDevices, PTY_MAX } from '../web/kernel/ptmx.js';
import { IOCTL, LF } from '../web/kernel/pty.js';

const process = { pid: 10, uid: 1000, ctty: 0 };
const bytes = text => new TextEncoder().encode(text);
const text = data => new TextDecoder().decode(data);
const error = errno => e => e.errno === errno;
function allocate(devices, options) {
  const master = devices.open(process, '/dev/ptmx', options);
  devices.ioctl(process.pid, master.handle, IOCTL.TIOCSPTLCK, 0);
  const slave = devices.open(process, `/dev/pts/${master.number}`, options);
  return { master, slave, pair: devices.get(process.pid, master.handle).pair };
}

test('allocated PTYs isolate canonical input, echo and output processing', async () => {
  const devices = new PtyDevices();
  try {
    const a = allocate(devices), b = allocate(devices);
    devices.write(10, a.master.handle, bytes('one\r'));
    assert.equal(text(devices.read(10, a.slave.handle, 100)), 'one\n');
    assert.equal(text(devices.read(10, a.master.handle, 100)), 'one\r\n');
    assert.deepEqual(devices.read(10, b.slave.handle, 100), { wait: true, nonblock: false });
    devices.write(10, a.slave.handle, bytes('reply\n'));
    assert.equal(text(devices.read(10, a.master.handle, 100)), 'reply\r\n');
  } finally { await devices.release(10); }
});

test('raw PTY transport preserves every byte and routes signal characters only with ISIG', async () => {
  const signals = [], devices = new PtyDevices({ signal: (tty, n) => signals.push([tty.number, n]) });
  try {
    const { master, slave, pair } = allocate(devices);
    const modes = pair.terminal.state.termios;
    modes.iflag = 0; modes.oflag = 0; modes.lflag = 0;
    pair.terminal.configure(modes);
    const data = Uint8Array.from({ length: 256 }, (_, n) => n);
    devices.write(10, master.handle, data);
    assert.deepEqual(devices.read(10, slave.handle, 256), data);
    devices.write(10, slave.handle, data);
    assert.deepEqual(devices.read(10, master.handle, 256), data);
    assert.deepEqual(signals, []);
    modes.lflag = LF.ISIG; pair.terminal.configure(modes);
    devices.write(10, master.handle, Uint8Array.of(3));
    assert.deepEqual(signals, [[master.number, 2]]);
  } finally { await devices.release(10); }
});

test('slave locks, creator identity and private handles constrain opening and use', async () => {
  const devices = new PtyDevices();
  try {
    const master = devices.open(process, '/dev/ptmx');
    const path = `/dev/pts/${master.number}`;
    assert.throws(() => devices.open(process, path), error('EIO'));
    devices.ioctl(10, master.handle, IOCTL.TIOCSPTLCK, 0);
    assert.throws(() => devices.open({ pid: 11, uid: 1001 }, path), error('EACCES'));
    assert.throws(() => devices.read(11, master.handle, 1), error('EBADF'));
    assert.throws(() => new PtyDevices().open(process, path), error('ENOENT'));
    const slave = devices.open(process, path, { readable: true, writable: false });
    assert.throws(() => devices.write(10, slave.handle, bytes('x')), error('EBADF'));
    assert.throws(() => devices.ioctl(10, slave.handle, IOCTL.TIOCSPTLCK, 1), error('ENOTTY'));
    devices.ioctl(10, master.handle, IOCTL.TIOCSPTLCK, 1);
    assert.throws(() => devices.open(process, path), error('EIO'));
  } finally { await devices.release(10); }
});

test('the last inherited master reference hangs up once, and surviving slaves reach EOF/EIO', async () => {
  const hung = [], devices = new PtyDevices({ hangup: async tty => hung.push(tty.number) });
  const { master, slave } = allocate(devices);
  devices.hold(10, 11, master.handle, 2);
  await devices.close(10, master.handle);
  await devices.close(11, master.handle);
  assert.deepEqual(hung, []);
  await devices.release(11);
  assert.deepEqual(hung, [master.number]);
  assert.equal(devices.read(10, slave.handle, 8).length, 0);
  assert.throws(() => devices.write(10, slave.handle, bytes('x')), error('EIO'));
  assert.throws(() => devices.open(process, `/dev/pts/${master.number}`), error('ENOENT'));
  await devices.release(10);
  assert.equal(devices.pairs.size, 0); assert.equal(devices.handles.size, 0);
});

test('the master drains output after last slave close and accepts a reopened slave', async () => {
  const devices = new PtyDevices();
  try {
    const { master, slave } = allocate(devices);
    devices.write(10, slave.handle, bytes('last'));
    await devices.close(10, slave.handle);
    assert.equal(text(devices.read(10, master.handle, 4)), 'last');
    assert.throws(() => devices.read(10, master.handle, 4), error('EIO'));
    assert.equal(devices.poll(10, master.handle, false).hangup, true);
    devices.open(process, `/dev/pts/${master.number}`);
    assert.deepEqual(devices.read(10, master.handle, 1), { wait: true, nonblock: false });
  } finally { await devices.release(10); }
});

test('PTY output backpressure and allocation exhaustion recover after drain and close', async () => {
  const devices = new PtyDevices();
  try {
    const { master, slave } = allocate(devices, { nonblock: true });
    const data = new Uint8Array(4096).fill(65);
    for (let n = 0; n < 256; n++) assert.equal(devices.write(10, slave.handle, data).count, data.length);
    assert.deepEqual(devices.write(10, slave.handle, data), { wait: true, nonblock: true });
    assert.equal(devices.poll(10, slave.handle, true).ready, false);
    assert.equal(devices.read(10, master.handle, 4096).length, 4096);
    assert.equal(devices.write(10, slave.handle, data).count, data.length);
    for (let n = 1; n < PTY_MAX; n++) devices.open(process, '/dev/ptmx');
    assert.throws(() => devices.open(process, '/dev/ptmx'), error('ENOSPC'));
    await devices.close(10, master.handle); await devices.close(10, slave.handle);
    assert.notEqual(devices.open(process, '/dev/ptmx').number, master.number);
  } finally { await devices.release(10); }
});
