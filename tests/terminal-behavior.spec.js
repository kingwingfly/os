import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, entry, errno, mkdirp, put, rmrf } from './sys.js';
// The Files go to `path` of their own: its location typed (files.rs).
async function browse(page, path) {
  const location = page.getByRole('textbox', { name: 'Location' });
  await location.fill(path); await location.press('Enter');
  await expect(location).toHaveValue(path);
}
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const headers = { Origin: origin };
const url = (path, recursive = false) => '/api/file?path=' + encodeURIComponent(path) + '&recursive=' + recursive;
async function command(page, text) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await expect(page.locator('.busy')).toHaveText('↵');
  await input.fill(text); await input.press('Enter');
}

test('stdout and errors scroll after DOM updates; completion uses a separate pager', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('navigation', { name: 'Dock' })).toBeVisible();
  const log = page.locator('.transcript');
  await page.route('**/api/sys', async route => { if (route.request().postData()?.includes('getdents')) await new Promise(resolve => setTimeout(resolve, 120)); await route.continue(); });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 780 });
    for (let i = 0; i < 4; i++) { await command(page, 'help'); await expect(log.locator('pre').last()).toContainText('useradd NAME makes an account'); }
    expect(await log.evaluate(e => e.scrollHeight > e.clientHeight)).toBe(true);
    await log.evaluate(e => { e.scrollTop = 0; });
    await command(page, 'ls');
    await expect(log.locator('pre').last()).not.toContainText('visitor:');
    await expect.poll(() => log.evaluate(e => e.scrollHeight - e.clientHeight - e.scrollTop)).toBeLessThanOrEqual(2);
    await command(page, 'unknown-command');
    await expect(log.locator('pre').last()).toContainText('Unknown command');
    await expect.poll(() => log.evaluate(e => e.scrollHeight - e.clientHeight - e.scrollTop)).toBeLessThanOrEqual(2);
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    const transcript = await log.innerText();
    await input.fill(''); await input.press('Tab');
    await expect(page.getByRole('listbox', { name: 'Completions' })).toBeVisible();
    expect(await log.innerText()).toBe(transcript);
    await input.press('Escape');
  }
});

test('removal is the kernel\'s to allow, from this site only; removing a tree leaves its neighbours', async ({ request }) => {
  const base = '/rm-api-' + Date.now(), target = base + '/directory', sibling = base + '/Directory-kept';
  // A guest may not; nor a request from elsewhere; rmdir and unlink each take what they take.
  expect(await errno(request, { rmdir: { path: '/media' } })).toBe('EACCES');
  await api(request, 'login', { headers, data: { password } });
  try {
    for (const dir of [target + '/nested', sibling]) {
      await mkdirp(request, dir);
      expect((await put(request, url(dir + '/With spaces.txt'), { headers, data: 'keep or delete' })).status()).toBe(201);
    }
    expect((await request.post('/api/sys', { headers: { Origin: 'https://elsewhere.invalid' }, data: { calls: [{ rmdir: { path: target } }] } })).status()).toBe(403);
    expect(await errno(request, { rmdir: { path: '/a/..' } })).toBe('ENOENT');
    expect(await errno(request, { rmdir: { path: '/' } })).toBe('EBUSY');
    expect(await errno(request, { rmdir: { path: target } })).toBe('ENOTEMPTY');
    expect(await errno(request, { unlink: { path: target } })).toBe('EISDIR');
    expect(await errno(request, { unlink: { path: base + '/missing.txt' } })).toBe('ENOENT');
    expect(await rmrf(request, target)).toBe(null);
    expect(await entry(request, target)).toBe(null);
    expect((await request.get(url(target + '/nested/With spaces.txt'))).status()).toBe(404);
    expect((await request.get(url(sibling + '/With spaces.txt'))).ok()).toBe(true);
    expect(await errno(request, { unlink: { path: sibling + '/With spaces.txt' } })).toBe(null);
    expect((await request.head(url(sibling + '/With spaces.txt'))).status()).toBe(404);
    expect((await entry(request, sibling))?.directory).toBe(true);
  } finally { await rmrf(request, base); }
});

test('rm requires explicit login, handles quoted paths, refreshes lists and refuses cwd deletion', async ({ page, request }) => {
  const base = '/rm-ui-' + Date.now();
  await page.goto('/');
  await command(page, 'rm');
  await expect(page.locator('.transcript pre').last()).toContainText('rm: missing PATH');
  await command(page, 'su root');
  await expect(page.locator('#auth')).toBeVisible();
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('.busy')).toHaveText('↵');
  await command(page, 'mkdir ' + base);
  await expect.poll(async () => (await entry(request, base))?.directory).toBe(true);
  try {
    await command(page, 'cd ' + base);
    await browse(page, base);
    await command(page, 'mkdir "Delete this directory"');
    await expect(page.locator('.filename').filter({ hasText: 'Delete this directory' })).toBeVisible();
    await command(page, 'rm "Delete this directory"');
    await expect(page.locator('.transcript pre').last()).toContainText("rm: cannot remove 'Delete this directory': Is a directory");
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    await expect(page.locator('.busy')).toHaveText('↵');
    await input.fill('rm -r Dele'); await input.press('Tab');
    await expect(input).toHaveValue('rm -r "Delete this directory/"'); await input.press('Enter');
    await expect(page.locator('.filename').filter({ hasText: 'Delete this directory' })).toHaveCount(0);
    await command(page, 'rm -r .'); await expect(page.locator('.transcript pre').last()).toContainText("rm: refusing to remove '.' or '..' directory");
    await expect(page.locator('.busy')).toHaveText('↵');
    const chooser = page.waitForEvent('filechooser'); await page.getByRole('button', { name: '↑ Upload files' }).click();
    await (await chooser).setFiles({ name: 'Delete me.txt', mimeType: 'text/plain', buffer: Buffer.from('temporary') });
    await expect(page.locator('.filename').filter({ hasText: 'Delete me.txt' })).toBeVisible();
    await command(page, 'logout'); await expect(page.locator('.lock')).toContainText('guest');
    await command(page, 'rm "' + base + '/Delete me.txt"');
    await expect(page.locator('.transcript pre').last()).toContainText('Permission denied');
    await expect(page.locator('#auth')).not.toBeVisible();
    await expect(page.locator('.lock')).toContainText('guest');
    await command(page, 'su root'); await expect(page.locator('#auth')).toBeVisible();
    await page.getByLabel('Password', { exact: true }).fill(password); await page.locator('#auth button[type=submit]').click();
    await expect(page.locator('.busy')).toHaveText('↵');
    await command(page, 'rm "' + base + '/Delete me.txt"');
    await expect(page.locator('.filename').filter({ hasText: 'Delete me.txt' })).toHaveCount(0);
  } finally {
    await page.request.delete(url(base, true), { headers });
  }
});
