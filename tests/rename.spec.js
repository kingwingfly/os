import { test, expect, request as requests } from './test.js';
import binaryen from 'binaryen';
import { api, call, sys } from './sys.js';
import { execCmd, filesLocation, pageMkdirp, pagePut, pageRmrf, terminalSurface, waitForFilesReady, waitForTerminalReady } from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || 'test-admin-password-w4b';
const cookies = async request => (await request.storageState()).cookies;
const legacy = async (request, name, old) => {
  const cookie = (await cookies(request)).find(c => c.name === name);
  expect(cookie).toBeDefined();
  return requests.newContext({ baseURL: origin, storageState: {
    cookies: [{ ...cookie, name: old }], origins: [],
  } });
};

test('OS boots with window.os and ignores retired terminal-* storage keys without migrating them', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('terminal-slide-theme', 'light');
    localStorage.setItem('terminal-notes-size', '19');
    localStorage.setItem('terminal-desktop', '{"terminal":{"x":12}}');
    sessionStorage.setItem('terminal-files', '/tmp');
  });
  await page.goto('/');
  await expect(page).toHaveTitle('OS');
  await waitForTerminalReady(page);
  await waitForFilesReady(page);
  await expect(terminalSurface(page)).toBeVisible();
  expect(await page.evaluate(() => typeof window.os.exec)).toBe('function');
  // Fail-closed non-migration (Contract §2.12 / L6d #65): retired `terminal-*` keys are ignored.
  expect(await page.evaluate(() => [
    localStorage.getItem('os-slide-theme'),
    localStorage.getItem('os-notes-size'),
    localStorage.getItem('terminal-slide-theme'),
    localStorage.getItem('terminal-notes-size'),
    sessionStorage.getItem('terminal-files'),
  ])).toEqual([null, null, 'light', '19', '/tmp']);
  await expect(filesLocation(page)).not.toHaveValue('/tmp');
});

test('retired terminal_session and terminal_guest cookies are ignored and never revive identity', async ({ request }) => {
  expect((await api(request, 'login', { data: { password } })).ok()).toBe(true);
  const token = (await cookies(request)).find(c => c.name === 'os_session').value;
  const old = await legacy(request, 'os_session', 'terminal_session');
  try {
    const creds = await call(old, 'getcreds');
    expect(creds.signed_in).toBe(false);
    expect(creds.uid).not.toBe(0);
    expect((await cookies(old)).some(c => c.name === 'os_session')).toBe(false);
  } finally { await old.dispose(); }

  const bad = await requests.newContext({ baseURL: origin });
  try {
    const [res] = await sys(bad, ['getcreds'], {}, { Cookie: `os_session=invalid; terminal_session=${token}` });
    expect(res.ok.signed_in).toBe(false);
    expect(res.ok.uid).not.toBe(0);
  } finally { await bad.dispose(); }

  const guestCtx = await requests.newContext({ baseURL: origin });
  try {
    const before = await call(guestCtx, 'getcreds');
    const oldGuest = await legacy(guestCtx, 'os_guest', 'terminal_guest');
    try {
      const after = await call(oldGuest, 'getcreds');
      expect(after.signed_in).toBe(false);
      // Retired `terminal_guest` must NOT bind to the prior guest namespace.
      expect(after.uid).not.toBe(before.uid);
    } finally { await oldGuest.dispose(); }
  } finally { await guestCtx.dispose(); }
});

test('WASM loader accepts the os import namespace and rejects the retired terminal namespace with ENOEXEC', async ({ page }) => {
  const buildProbe = namespace => binaryen.parseText(`(module
    (import "${namespace}" "umask" (func $umask (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1) (data (i32.const 100) "import-ok\\0a")
    (func (export "_start")
      (if (i32.ne (call $umask (i32.const 18)) (i32.const 18)) (then unreachable))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 10))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);

  const base = '/home/user/rename-ns-' + Date.now().toString(36);
  const osMod = buildProbe('os');
  const termMod = buildProbe('terminal');
  await page.goto('/');
  await waitForTerminalReady(page);
  try {
    await pageMkdirp(page, base, 0o755);
    await pagePut(page, base + '/ok-os.wasm', Buffer.from(osMod.emitBinary()), { mode: 0o755 });
    await pagePut(page, base + '/retired-terminal.wasm', Buffer.from(termMod.emitBinary()), { mode: 0o755 });

    const okResult = await execCmd(page, [base + '/ok-os.wasm']);
    expect(okResult.status, okResult.stderr).toBe(0);
    expect(okResult.stdout.trim()).toBe('import-ok');

    const rejected = await page.evaluate(async path => {
      try {
        const res = await window.os.exec([[path]], { stdin: '' });
        return { thrown: false, status: res.status };
      } catch (err) {
        return { thrown: true, errno: err?.errno ?? null, message: String(err?.message ?? err) };
      }
    }, base + '/retired-terminal.wasm');
    expect(rejected.thrown).toBe(true);
    expect(rejected.errno).toBe('ENOEXEC');
    expect(rejected.message).toMatch(/Exec format error|unknown import terminal\.umask/i);
  } finally {
    osMod.dispose();
    termMod.dispose();
    await pageRmrf(page, base).catch(() => {});
  }
});
