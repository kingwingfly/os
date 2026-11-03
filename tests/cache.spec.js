import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, put, rmrf } from './sys.js';
// The Files go to `path` of their own: its location typed (files.rs).
async function browse(page, path) {
  const location = page.getByRole('textbox', { name: 'Location' });
  await location.fill(path); await location.press('Enter');
  await expect(location).toHaveValue(path);
}
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);

// The page answers what only looks from a cache while the kernel tells it nothing changed in the
// directory (inotify): listing again asks nothing; what others change, and what it changes itself,
// it lists anew.
test('a directory listed again asks the kernel nothing, until something in it changes', async ({ page, request }) => {
  const base = '/cache-' + Date.now().toString(36);
  const headers = { Origin: origin, 'CF-Connecting-IP': 'cache-' + base };
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, base);
  expect((await put(request, file(base + '/one.txt'), { headers, data: '1' })).status()).toBe(201);
  try {
    await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'cache-ui-' + base });
    const asked = [];
    page.on('request', r => { if (r.url().endsWith('/api/sys')) asked.push(r.postData() || ''); });
    await page.goto('/');
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    const busy = page.locator('#command').locator('xpath=ancestor::form').locator('.busy');
    const run = async text => { await expect(busy).toHaveText('↵'); await input.fill(text); await input.press('Enter'); await expect(busy).toHaveText('↵'); };
    const last = page.locator('.transcript pre').last();
    await expect(busy).toHaveText('↵'); await input.fill('su root'); await input.press('Enter');
    await page.getByLabel('Password', { exact: true }).fill(password); await page.locator('#auth button[type=submit]').click();
    await expect(page.locator('#auth')).not.toBeVisible();
    await run('cd ' + base);
    await browse(page, base);
    await run('ls -l');
    await expect(last).toContainText('one.txt');
    // Again: every answer is the cache's.
    const before = asked.length;
    await run('ls -l');
    await expect(last).toContainText('one.txt');
    expect(asked.slice(before).filter(body => body.includes('getdents') || body.includes('"stat"'))).toEqual([]);
    // Another device adds a file: the kernel tells the page, which lists it anew.
    expect((await put(request, file(base + '/two.txt'), { headers, data: '2' })).status()).toBe(201);
    await expect(page.locator('.files .filename')).toHaveText(['one.txt', 'two.txt']);
    await run('ls');
    await expect(last).toContainText('two.txt');
    // What the page changes itself, it lists anew too.
    await run('rm one.txt');
    await run('ls');
    await expect(last).not.toContainText('one.txt');
    await expect(last).toContainText('two.txt');
  } finally {
    await rmrf(request, base);
  }
});
