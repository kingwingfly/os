// Phase 0 gate: the Rust WASIX runtime runs a prebuilt dash and forks a subshell.
// The fixture is third-party and not committed; skip unless WASIX_DASH names it.
import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';

const dash = process.env.WASIX_DASH;

test('the Rust WASIX runtime forks dash', { skip: dash ? false : 'set WASIX_DASH to a WASIX dash binary' }, () => {
  const result = spawnSync(
    process.execPath,
    ['scripts/wasix-phase0.mjs', 'dash', '-c', 'echo one; (echo two); echo three'],
    { cwd: new URL('..', import.meta.url), encoding: 'utf8', env: process.env },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /one/);
  assert.match(result.stdout, /two/);
  assert.match(result.stdout, /three/);
  assert.match(result.stdout, /\[2 exit 0\]/);
  assert.match(result.stdout, /\[1 exit 0\]/);
});
