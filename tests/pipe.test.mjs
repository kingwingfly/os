import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Pipe, pipeBuffer, PAGE } from '../web/wasi/pipe.js';

test('nonblocking pipe writes preserve PIPE_BUF atomicity and report partial larger writes', () => {
  const pipe = new Pipe(pipeBuffer()); pipe.hold(PAGE, 'r'); pipe.hold(PAGE, 'w');
  const input = new Uint8Array(65536).fill(7);
  assert.equal(pipe.tryWrite(input).written, input.length);
  assert.equal(pipe.tryWrite(Uint8Array.of(9)).written, 0);
  pipe.read(1000);
  assert.equal(pipe.tryWrite(new Uint8Array(4096)).written, 0);
  assert.equal(pipe.tryWrite(new Uint8Array(4097)).written, 1000);
  assert.equal(pipe.queued, 65536);
  pipe.release(PAGE);
  assert.equal(pipe.tryWrite(Uint8Array.of(9)).broken, true);
  assert.deepEqual(pipe.tryWrite(new Uint8Array()), { written: 0, broken: false });
});

test('nonblocking reads distinguish would-block from EOF and retain canonical line boundaries', () => {
  const pipe = new Pipe(pipeBuffer()); pipe.hold(PAGE, 'r'); pipe.hold(PAGE, 'w');
  assert.equal(pipe.read(100, undefined, true, true), null);
  pipe.tryWrite(new TextEncoder().encode('one\ntwo\n'));
  assert.equal(new TextDecoder().decode(pipe.read(100, undefined, true, true)), 'one\n');
  assert.equal(new TextDecoder().decode(pipe.read(100, undefined, true, true)), 'two\n');
  pipe.endOfFile(); assert.equal(pipe.read(100, undefined, true, true).length, 0);
  assert.equal(pipe.read(100, undefined, true, true), null);
  pipe.release(PAGE); assert.equal(pipe.read(100, undefined, true, true).length, 0);
});
