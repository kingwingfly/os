import { test, expect } from './test.js';
import { browse, pageListing, pageMkdirp, pagePut, pageRmrf, pageSys, promptPath } from './ui.js';

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
async function initBase(page) {
  base = '/home/user/files-' + Date.now().toString(36);
  await page.goto('/');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  await pageMkdirp(page, base + '/docs', 0o755);
  await pagePut(page, base + '/notes.md', '# Notes\n', { mode: 0o644 });
}
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base).catch(() => {});
});

test('the Files and the terminal each keep their own directory, and the Files run no commands', async ({ page }) => {
  await initBase(page);
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user');
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
  // ~ is the local account's home (/home/user).
  await location(page).fill('~'); await location(page).press('Enter');
  await expect(location(page)).toHaveValue('/home/user');
  // A reload finds them where they were, the terminal where it was.
  await go(page, base + '/docs');
  await page.reload();
  await expect(location(page)).toHaveValue(base + '/docs');
  await expect(cwd(page)).toHaveText('/etc');
});

test('files dropped on the Files upload into their directory, which shows how it goes', async ({ page }) => {
  await initBase(page);
  await go(page, base + '/docs');
  const transfer = await page.evaluateHandle(() => {
    const dt = new DataTransfer(); dt.items.add(new File(['dropped'], 'dropped.txt', { type: 'text/plain' })); return dt;
  });
  await page.dispatchEvent('#window-files .files', 'drop', { dataTransfer: transfer });
  await expect(page.getByRole('status', { name: 'Upload progress' })).toContainText('✓ dropped.txt', { timeout: 20_000 });
  await expect(names(page)).toHaveText(['dropped.txt']);
  expect((await pageListing(page, base + '/docs')).map(entry => entry.name)).toEqual(['dropped.txt']);
  // The terminal heard nothing of it.
  await expect(page.locator('.transcript')).not.toContainText('dropped.txt');
  await page.getByRole('button', { name: 'Dismiss' }).click();
  await expect(page.getByRole('status', { name: 'Upload progress' })).toHaveCount(0);
});

test('returning to a directory restores its scroll position and refreshes keep it', async ({ page }) => {
  await initBase(page);
  const dirs = Array.from({ length: 80 }, (_, i) => `folder-${String(i).padStart(3, '0')}`);
  const child = base + '/folder-040';
  const made = await pageSys(page, [
    ...dirs.map(name => ({ mkdir: { path: base + '/' + name, mode: 0o755 } })),
    ...dirs.map(name => ({ mkdir: { path: child + '/' + name, mode: 0o755 } })),
  ]);
  expect(made.filter(result => result.err)).toEqual([]);
  await go(page, base);
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
  // A directory refresh replaces the rows but must preserve the current place.
  await pageMkdirp(page, base + '/zz-new', 0o755);
  await page.locator('#window-files').getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(names(page).filter({ hasText: 'zz-new/' })).toHaveCount(1);
  await expect.poll(position).toBe(parentPosition);
  await go(page, base + '/docs'); await expect.poll(position).toBe(0);
  await go(page, base); await expect.poll(position).toBe(parentPosition);
});

test('Refresh and F5 bypass cached listings without navigation or losing scroll', async ({ page }) => {
  await page.addInitScript(() => window.addEventListener('os:inotify', event => event.stopImmediatePropagation()));
  await initBase(page);
  await pageSys(page, Array.from({ length: 60 }, (_, index) => ({ mkdir: { path: base + '/folder-' + String(index).padStart(3, '0'), mode: 0o755 } })));
  await go(page, base);
  const scroller = page.locator('.files');
  await expect(names(page)).toHaveCount(62);
  await scroller.evaluate(element => { element.scrollTop = 800; });
  const scroll = await scroller.evaluate(element => element.scrollTop);
  await page.evaluate(() => { window.refreshTestPage = true; });
  await pageMkdirp(page, base + '/zz-button', 0o755);
  await expect(names(page).filter({ hasText: 'zz-button/' })).toHaveCount(0);
  await page.locator('#window-files').getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(names(page).filter({ hasText: 'zz-button/' })).toHaveCount(1);
  await expect(location(page)).toHaveValue(base);
  await expect.poll(() => scroller.evaluate(element => element.scrollTop)).toBe(scroll);
  await pageMkdirp(page, base + '/zz-keyboard', 0o755);
  await location(page).press('F5');
  await expect(names(page).filter({ hasText: 'zz-keyboard/' })).toHaveCount(1);
  expect(await page.evaluate(() => window.refreshTestPage)).toBe(true);
  await expect(location(page)).toHaveValue(base);
  await expect.poll(() => scroller.evaluate(element => element.scrollTop)).toBe(scroll);
});
