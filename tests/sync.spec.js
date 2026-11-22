import { test, expect, request as playwrightRequest } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, program, put, rmrf, sys } from './sys.js';
import { browse, cloudSignIn, promptPath } from './ui.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
let sequence = 0;
// Another device, signed in as root through the API.
async function device() {
  const client = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'sync-' + Date.now() + '-' + (++sequence) } });
  expect((await api(client, 'login', { data: { password } })).ok()).toBe(true);
  return client;
}

test('a page shows what other devices change as it happens, and hears nothing of what it may not list', async ({ page, context, browser }) => {
  const other = await device(), base = '/sync-' + Date.now().toString(36);
  try {
    await mkdirp(other, base);
    await context.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'sync-page-' + Date.now() });
    await page.goto('/');
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
    await cloudSignIn(page, 'root', password);
    const cloudBase = '/mnt/cloud' + base;
    await browse(page, cloudBase);
    // Without anything done here, the Files follow the other device.
    const names = page.locator('.files .filename');
    expect((await put(other, file(base + '/hello.txt'), { data: 'hi' })).status()).toBe(201);
    await expect(names).toHaveText(['hello.txt']);
    await mkdirp(other, base + '/docs');
    await expect(names).toHaveText(['docs/', 'hello.txt']);
    expect((await program(other, ['mv', base + '/hello.txt', base + '/docs/'])).ok()).toBe(true);
    await expect(names).toHaveText(['docs/']);
    // A guest's server session watches a Cloud directory it may list, and hears nothing of /root.
    const guest = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': 'sync-guest-' + Date.now() } });
    const [dir, rootWatch] = await sys(guest.request, [{ inotify_add_watch: { path: base } }, { inotify_add_watch: { path: '/root' } }]);
    expect(rootWatch.err?.errno).toBe('EACCES');
    const listener = await guest.newPage(); await listener.goto(origin + '/login');
    await listener.evaluate(async url => {
      window.heard = []; const socket = new WebSocket(url.replace(/^http/, 'ws') + '/api/events');
      socket.onmessage = event => window.heard.push(...(JSON.parse(event.data).inotify ?? []));
      await new Promise(opened => { socket.onopen = opened; });
    }, origin);
    expect((await put(other, file('/root/sync-secret.txt') + '&overwrite=true', { data: 'x' })).status()).toBeLessThan(300);
    expect((await put(other, file(base + '/public.txt'), { data: 'x' })).status()).toBe(201);
    // What changed in it is told, as IN_MODIFY of its watch (the page's own watches are told on
    // this line too, as it is the same session's).
    await expect.poll(() => listener.evaluate(() => window.heard)).toContainEqual({ wd: dir.ok, mask: 2 });
    await guest.close();
    // Only this site may open the line, which carries the session cookie.
    expect((await other.get('/api/events', { headers: { Origin: 'https://elsewhere.example' } })).status()).toBe(403);
    expect((await other.get('/api/events')).status()).toBe(426);
  } finally {
    await rmrf(other, base); await rmrf(other, '/root/sync-secret.txt');
    await other.dispose();
  }
});

test('removing a file another device is uploading stops that upload, as rm does to a file being written', async ({ page, context }) => {
  const other = await device(), base = '/sync-upload-' + Date.now().toString(36);
  try {
    await mkdirp(other, base);
    await context.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'sync-uploader-' + Date.now() });
    await page.goto('/');
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
    await cloudSignIn(page, 'root', password);
    const cloudBase = '/mnt/cloud' + base;
    await input.fill('cd ' + cloudBase); await input.press('Enter');
    await expect(promptPath(page)).toHaveText(cloudBase);
    await browse(page, cloudBase);
    // Slow chunks leave the other device time to remove the file.
    // A chunk the stopped upload aborted meanwhile is handled already, and continues nowhere.
    await page.route('**/api/pwrite?**', async route => { await new Promise(r => setTimeout(r, 1500)); await route.continue().catch(() => {}); });
    const chooser = page.waitForEvent('filechooser');
    await input.fill('upload'); await input.press('Enter');
    await (await chooser).setFiles({ name: 'big.log', mimeType: 'application/octet-stream', buffer: Buffer.alloc(3 * 8 * 1024 * 1024 + 100, 7) });
    await expect(page.locator('.files .filename')).toContainText(['big.log'], { timeout: 20_000 });
    expect(await rmrf(other, base + '/big.log')).toBe(null);
    await expect(page.locator('.transcript')).toContainText('✕ big.log: stopped: the file was removed, or its upload cancelled, elsewhere', { timeout: 30_000 });
    await expect(page.locator('.files .filename')).toHaveCount(0);
  } finally {
    await page.unroute('**/api/pwrite?**');
    await rmrf(other, base);
    await other.dispose();
  }
});
