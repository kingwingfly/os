import { test, expect } from './test.js';
import { api, mkdirp, put, rmrf } from './sys.js';
import { browse, cloudSignIn } from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || 'test-admin-password-w4b';
const file = path => '/api/file?path=' + encodeURIComponent(path);

// The page answers what only looks from a cache while the kernel tells it nothing changed in the
// watched CloudFs directory (`/mnt/cloud/...`, inotify): listing again asks nothing; what another
// device changes, and what it changes itself, it lists anew.
test('Files reuses watched metadata until something in its directory changes', async ({ page, request }) => {
  const base = '/cache-' + Date.now().toString(36);
  const cloudBase = '/mnt/cloud' + base;
  const headers = { Origin: origin, 'CF-Connecting-IP': 'cache-' + base };
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, base);
  expect((await put(request, file(base + '/one.txt'), { headers, data: '1' })).status()).toBe(201);
  try {
    await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'cache-ui-' + base });
    const asked = [];
    page.context().on('request', r => {
      const path = new URL(r.url()).pathname;
      if (path === '/api/sys' || path === '/api/fs') asked.push(r.postData() || '');
    });
    await page.goto('/');
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    const busy = page.locator('#command').locator('xpath=ancestor::form');
    const run = async text => {
      await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
      await input.fill(text);
      await input.press('Enter');
      await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
    };
    const last = page.locator('.transcript pre').last();
    await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
    await cloudSignIn(page, 'root', password);
    await run('cd ' + cloudBase);
    await browse(page, cloudBase);
    const names = page.locator('.files .filename');
    const upload = page.getByRole('button', { name: 'Upload' });
    await expect(names).toHaveText(['one.txt']);
    await expect(upload).toBeEnabled();
    // Files uses its page metadata cache. External ls has its own process credentials and
    // filesystem calls, and must not rely on the browser reconstructing its output.
    const before = asked.length;
    await browse(page, cloudBase);
    await expect(upload).toBeEnabled();
    await expect(names).toHaveText(['one.txt']);
    expect(asked.slice(before).filter(body =>
      body.includes('getdents') || body.includes('"stat"') || body.includes('"readdir"') || body.includes('"getattr"')
    )).toEqual([]);
    // Another device adds a file on CloudFs: the server tells the page via inotify, which lists it anew.
    expect((await put(request, file(base + '/two.txt'), { headers, data: '2' })).status()).toBe(201);
    await expect(names).toHaveText(['one.txt', 'two.txt'], { timeout: 15_000 });
    await run('ls');
    await expect(last).toContainText('two.txt');
    // What the page changes itself, it lists anew too.
    await run('rm one.txt');
    await expect(names).toHaveText(['two.txt']);
    await run('ls');
    await expect(last).not.toContainText('one.txt');
    await expect(last).toContainText('two.txt');
  } finally {
    await rmrf(request, base);
  }
});
