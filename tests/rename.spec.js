import { test, expect, request as requests } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call, mkdirp, put, rmrf } from './sys.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
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
    sessionStorage.setItem('terminal-tabs', JSON.stringify({ active: 0, tabs: [
      { cwd: '/guest', history: ['echo previous-session'] },
    ] }));
    sessionStorage.setItem('terminal-files', '/media');
  });
  await page.goto('/');
  await expect(page).toHaveTitle('OS');
  await expect(page.locator('#command')).toBeVisible();
  expect(await page.evaluate(() => typeof window.os.exec)).toBe('function');
  expect(await page.evaluate(() => [localStorage.getItem('os-slide-theme'),
    localStorage.getItem('os-notes-size'), localStorage.getItem('terminal-slide-theme')]))
    .toEqual(['light', '19', null]);
  await expect(page.getByRole('textbox', { name: 'Location' })).toHaveValue('/media');
  await page.locator('#command').press('ArrowUp');
  await expect(page.locator('#command')).toHaveValue('echo previous-session');
  expect(await page.evaluate(() => [sessionStorage.getItem('terminal-tabs'),
    sessionStorage.getItem('terminal-files')])).toEqual([null, null]);
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
    expect((await call(bad, 'getcreds', { headers: { Cookie: `os_session=invalid; terminal_session=${token}` } })).signed_in).toBe(false);
  } finally { await bad.dispose(); }
});
for (const namespace of ['os', 'terminal']) {
  test(`uploaded programs can use the ${namespace} import namespace`, async ({ page, request }) => {
    await api(request, 'login', { data: { password } });
    const base = '/rename-' + namespace + '-' + Date.now().toString(36);
    await mkdirp(request, base);
    const module = binaryen.parseText(`(module
      (import "${namespace}" "umask" (func $umask (param i32) (result i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1) (data (i32.const 100) "import-ok\\0a")
      (func (export "_start")
        (if (i32.ne (call $umask (i32.const 18)) (i32.const 18)) (then unreachable))
        (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 10))
        (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
    try {
      expect((await put(request, '/api/file?path=' + encodeURIComponent(base + '/probe.wasm'),
        { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true);
      await call(request, { chmod: { path: base + '/probe.wasm', mode: 0o755 } });
      await page.goto('/');
      await page.locator('#command').fill(base + '/probe.wasm');
      await page.locator('#command').press('Enter');
      await expect(page.locator('.transcript:not([hidden]) pre').last()).toHaveText('import-ok');
    } finally { module.dispose(); await rmrf(request, base); }
  });
}
