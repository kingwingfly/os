// Contract v2 §2.12 clean-break verification for local PID 1 init ownership (#56 L3c + #57 L3d):
// Server-lease `web/kernel/init.js` (`InitCoordinator` / `InitReaper`) and `web/kernel/login-boot.js`
// (`LoginStartup`) are permanently deleted; PID 1 `/usr/bin/init` runs 100% locally inside each
// browser tab's isolated client-kernel Worker.
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');

test('retired server-lease InitCoordinator/InitReaper and LoginStartup modules are deleted', () => {
  assert.equal(existsSync(resolve(root, 'web/kernel/init.js')), false, 'web/kernel/init.js must be deleted');
  assert.equal(existsSync(resolve(root, 'web/kernel/login-boot.js')), false, 'web/kernel/login-boot.js must be deleted');
});

test('client-kernel Worker and build script no longer reference retired init-owner or login-boot bundles', () => {
  const clientJs = readFileSync(resolve(root, 'web/kernel/client.js'), 'utf8');
  assert.ok(!clientJs.includes('init-owner.js'), 'client.js must not import init-owner.js');
  assert.ok(!clientJs.includes('InitCoordinator'), 'client.js must not reference InitCoordinator');
  assert.ok(!clientJs.includes('InitReaper'), 'client.js must not reference InitReaper');
  assert.ok(!clientJs.includes('LoginStartup'), 'client.js must not reference LoginStartup');
  assert.ok(clientJs.includes('boot_cowfs_root'), 'client.js must boot local os-cowfs root');

  const loginJs = readFileSync(resolve(root, 'web/kernel/login.js'), 'utf8');
  assert.ok(!loginJs.includes('login-boot.js'), 'login.js must not re-export login-boot.js');

  const buildMjs = readFileSync(resolve(root, 'scripts/build.mjs'), 'utf8');
  assert.ok(!buildMjs.includes("'init-owner': 'web/kernel/init.js'"), 'build.mjs must not bundle init-owner.js');
});
