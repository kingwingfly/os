import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, listing, mkdirp, put, rmrf, sys } from './sys.js';
import { browse, promptPath } from './ui.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];

// The Files (crates/frontend/src/files.rs): a directory of their own, apart from the terminal's;
// what is done in them is not a command of the terminal.
const location = page => page.getByRole('textbox', { name: 'Location' });
const names = page => page.locator('.files .filename');
const cwd = promptPath;
const go = browse;
async function run(page, text) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  await input.fill(text); await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
}

let base;
test.beforeEach(async ({ context }) => {
  base = '/files-' + Date.now().toString(36);
  await context.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'files-' + base });
  expect((await api(context.request, 'login', { headers: { Origin: origin }, data: { password } })).ok()).toBe(true);
  await mkdirp(context.request, base + '/docs');
  expect((await put(context.request, '/api/file?path=' + encodeURIComponent(base + '/notes.md'), { headers: { Origin: origin }, data: '# Notes\n' })).status()).toBe(201);
});
test.afterEach(async ({ context }) => { await rmrf(context.request, base); });

test('the Files and the terminal each keep their own directory, and the Files run no commands', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('.lock')).toContainText('root');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  const transcript = await page.locator('.transcript').innerText();
  // Typed, a location goes there; a click goes into a directory, ../ out of it, and opens a file.
  await go(page, base);
  await expect(names(page)).toHaveText(['docs/', 'notes.md']);
  await page.locator('.files .file', { hasText: 'docs/' }).click();
  await expect(location(page)).toHaveValue(base + '/docs');
  await page.locator('.files .file', { hasText: '../' }).click();
  await expect(location(page)).toHaveValue(base);
  await page.locator('.files .file', { hasText: 'notes.md' }).click();
  await expect(page.locator('#viewer .markdown h1')).toHaveText('Notes');
  await page.getByRole('button', { name: 'Close preview' }).click();
  // None of it was the terminal's: no line, no directory of its.
  await expect(page.locator('.transcript')).toHaveText(transcript, { useInnerText: true });
  await expect(cwd(page)).toHaveText('/');
  // The terminal goes elsewhere; the Files stay.
  await run(page, 'cd /etc');
  await expect(cwd(page)).toHaveText('/etc');
  await expect(location(page)).toHaveValue(base);
  // A location that is not there says so, and the Files stay where they were.
  await location(page).fill(base + '/missing'); await location(page).press('Enter');
  await expect(page.locator('.file-notice')).toContainText('No such file or directory');
  await expect(location(page)).toHaveValue(base);
  // ~ is the account's home.
  await location(page).fill('~'); await location(page).press('Enter');
  await expect(location(page)).toHaveValue('/root');
  // A reload finds them where they were, the terminal where it was.
  await go(page, base + '/docs');
  await page.reload();
  await expect(location(page)).toHaveValue(base + '/docs');
  await expect(cwd(page)).toHaveText('/etc');
});

test('files dropped on the Files upload into their directory, which shows how it goes', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  await go(page, base + '/docs');
  const transfer = await page.evaluateHandle(() => {
    const dt = new DataTransfer(); dt.items.add(new File(['dropped'], 'dropped.txt', { type: 'text/plain' })); return dt;
  });
  await page.dispatchEvent('#window-files .files', 'drop', { dataTransfer: transfer });
  await expect(page.getByRole('status', { name: 'Upload progress' })).toContainText('✓ dropped.txt', { timeout: 20_000 });
  await expect(names(page)).toHaveText(['dropped.txt']);
  expect((await listing(page.request, base + '/docs')).map(entry => entry.name)).toEqual(['dropped.txt']);
  // The terminal heard nothing of it.
  await expect(page.locator('.transcript')).not.toContainText('dropped.txt');
  await page.getByRole('button', { name: 'Dismiss' }).click();
  await expect(page.getByRole('status', { name: 'Upload progress' })).toHaveCount(0);
});

test('returning to a directory restores its scroll position and refreshes keep it', async ({ page }) => {
  const request = page.request;
  const dirs = Array.from({ length: 80 }, (_, i) => `folder-${String(i).padStart(3, '0')}`);
  const child = base + '/folder-040';
  const made = await sys(request, [
    ...dirs.map(name => ({ mkdir: { path: base + '/' + name, mode: 0o755 } })),
    ...dirs.map(name => ({ mkdir: { path: child + '/' + name, mode: 0o755 } })),
  ]);
  expect(made.filter(result => result.err)).toEqual([]);
  await page.goto('/'); await go(page, base);
  const scroller = page.locator('.files');
  const position = () => scroller.evaluate(e => e.scrollTop);
  const openChild = scroller.locator('.file').filter({ has: page.locator('.filename-text', { hasText: /^folder-040\/$/ }) });
  await openChild.scrollIntoViewIfNeeded();
  const parentPosition = await position(); expect(parentPosition).toBeGreaterThan(500);
  await openChild.click(); await expect(location(page)).toHaveValue(child);
  await expect.poll(position).toBe(0);
  await scroller.evaluate(e => { e.scrollTop = 1200; });
  const childPosition = await position(); expect(childPosition).toBeGreaterThan(500);
  // Return through the location field, then through ../: each visited path has its own place.
  await go(page, base); await expect.poll(position).toBe(parentPosition);
  await openChild.click(); await expect(location(page)).toHaveValue(child);
  await expect.poll(position).toBe(childPosition);
  await scroller.locator('.file').filter({ hasText: '../' }).click();
  await expect(location(page)).toHaveValue(base);
  await expect.poll(position).toBe(parentPosition);
  // A live directory refresh replaces the rows but must preserve the current place.
  await mkdirp(request, base + '/zz-new');
  await expect(names(page).filter({ hasText: 'zz-new/' })).toHaveCount(1);
  await expect.poll(position).toBe(parentPosition);
  await go(page, base + '/docs'); await expect.poll(position).toBe(0);
  await go(page, base); await expect.poll(position).toBe(parentPosition);
});
