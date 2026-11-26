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
test('OS boots with the renamed browser API and migrates saved preferences', async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('terminal-slide-theme', 'light');
    localStorage.setItem('terminal-notes-size', '19');
    sessionStorage.setItem('terminal-files', '/tmp');
  });
  await page.goto('/');
  await expect(page).toHaveTitle('OS');
  await waitForTerminalReady(page);
  await waitForFilesReady(page);
  await expect(terminalSurface(page)).toBeVisible();
  expect(await page.evaluate(() => typeof window.os.exec)).toBe('function');
  expect(await page.evaluate(() => [localStorage.getItem('os-slide-theme'),
    localStorage.getItem('os-notes-size'), localStorage.getItem('terminal-slide-theme')]))
    .toEqual(['light', '19', null]);
  await expect(filesLocation(page)).toHaveValue('/tmp');
  expect(await page.evaluate(() => sessionStorage.getItem('terminal-files'))).toBeNull();
});
test('old session cookies migrate without changing identity and logout cannot revive them', async ({ request }) => {
  expect((await api(request, 'login', { data: { password } })).ok()).toBe(true);
  const token = (await cookies(request)).find(c => c.name === 'os_session').value;
  const old = await legacy(request, 'os_session', 'terminal_session');
  try {
    expect((await call(old, 'getcreds')).uid).toBe(0);
    expect((await cookies(old)).find(c => c.name === 'os_session').value).toBe(token);
    expect((await cookies(old)).some(c => c.name === 'terminal_session')).toBe(false);
  } finally { await old.dispose(); }
  // Login on the very first legacy request must win over automatic cookie migration.
  const signing = await legacy(request, 'os_session', 'terminal_session');
  try {
    expect((await api(signing, 'login', { data: { password } })).ok()).toBe(true);
    expect((await cookies(signing)).find(c => c.name === 'os_session').value).not.toBe(token);
    expect((await cookies(signing)).some(c => c.name === 'terminal_session')).toBe(false);
    await api(signing, 'logout');
    expect((await call(signing, 'getcreds')).signed_in).toBe(false);
  } finally { await signing.dispose(); }
  const exiting = await legacy(request, 'os_session', 'terminal_session');
  try {
    await api(exiting, 'logout');
    expect((await call(exiting, 'getcreds')).signed_in).toBe(false);
    expect((await cookies(exiting)).some(c => c.name.includes('session'))).toBe(false);
  } finally { await exiting.dispose(); }
});
test('old guest cookies retain their namespace and an invalid new cookie cannot restore an old login', async ({ request }) => {
  const before = await call(request, 'getcreds');
  const old = await legacy(request, 'os_guest', 'terminal_guest');
  try {
    expect((await call(old, 'getcreds')).uid).toBe(before.uid);
    expect((await cookies(old)).some(c => c.name === 'os_guest')).toBe(true);
    expect((await cookies(old)).some(c => c.name === 'terminal_guest')).toBe(false);
  } finally { await old.dispose(); }
  await api(request, 'login', { data: { password } });
  const token = (await cookies(request)).find(c => c.name === 'os_session').value;
  const bad = await requests.newContext({ baseURL: origin });
  try {
    const [res] = await sys(bad, ['getcreds'], {}, { Cookie: `os_session=invalid; terminal_session=${token}` });
    expect(res.ok.signed_in).toBe(false);
  } finally { await bad.dispose(); }
});
for (const namespace of ['os', 'terminal']) {
  test(`uploaded programs can use the ${namespace} import namespace`, async ({ page }) => {
    const base = '/home/user/rename-' + namespace + '-' + Date.now().toString(36);
    const module = binaryen.parseText(`(module
      (import "${namespace}" "umask" (func $umask (param i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1) (data (i32.const 100) "import-ok\\0a")
      (func (export "_start")
        (if (i32.ne (call $umask (i32.const 18)) (i32.const 18)) (then unreachable))
        (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 10))
        (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
    await page.goto('/');
    await waitForTerminalReady(page);
    try {
      await pageMkdirp(page, base, 0o755);
      await pagePut(page, base + '/probe.wasm', Buffer.from(module.emitBinary()), { mode: 0o755 });
      const result = await execCmd(page, [base + '/probe.wasm']);
      expect(result.status).toBe(0);
      expect(result.stdout.trim()).toBe('import-ok');
    } finally {
      module.dispose();
      await pageRmrf(page, base).catch(() => {});
    }
  });
}
