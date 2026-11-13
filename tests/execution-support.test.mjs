import test from 'node:test';
import assert from 'node:assert/strict';
import { executionSupport, requireExecutionSupport } from '../web/kernel/capabilities.js';

test('execution requires isolation and usable shared memory regardless of browser name', () => {
  const scope = { crossOriginIsolated: true, SharedArrayBuffer, Atomics };
  assert.equal(executionSupport(scope).supported, true);
  assert.doesNotThrow(() => requireExecutionSupport(scope));
  for (const missing of [{ crossOriginIsolated: false }, { SharedArrayBuffer: undefined }, { Atomics: {} }]) {
    assert.equal(executionSupport({ ...scope, ...missing }).supported, false);
    assert.throws(() => requireExecutionSupport({ ...scope, ...missing }), { errno: 'ENOTSUP' });
  }
});
