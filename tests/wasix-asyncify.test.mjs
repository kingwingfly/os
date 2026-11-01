// Phase 0: binaryen asyncify-at-load transforms an uninstrumented module, then the Rust
// runtime forks it. The WAT fixture imports wasix_32v1 directly and has no asyncify exports
// until the load-time pass adds them.
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';

test('asyncify-at-load forks an uninstrumented module', () => {
  const result = spawnSync(process.execPath, ['scripts/wasix-phase0.mjs'], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
    env: { ...process.env, WASIX_WAT: 'tests/fixtures/wasix-fork.wat', WASIX_DASH: '' },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /child/);
  assert.match(result.stdout, /parent/);
  assert.match(result.stdout, /\[2 exit 0\]/);
  assert.match(result.stdout, /\[1 exit 0\]/);
});
