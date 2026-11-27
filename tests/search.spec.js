import { test, expect } from './test.js';
import { closePreview, pageMkdirp, pagePut, pageRmrf, previewFrame, previewSurface, runTerminal, waitForTerminalReady } from './ui.js';

function minimalWav() {
  const samples = 4000;
  const buf = Buffer.alloc(44 + samples, 0x80);
  buf.write('RIFF', 0);
  buf.writeUInt32LE(36 + samples, 4);
  buf.write('WAVEfmt ', 8);
  buf.writeUInt32LE(16, 16);
  buf.writeUInt16LE(1, 20);
  buf.writeUInt16LE(1, 22);
  buf.writeUInt32LE(8000, 24);
  buf.writeUInt32LE(8000, 28);
  buf.writeUInt16LE(1, 32);
  buf.writeUInt16LE(8, 34);
  buf.write('data', 36);
  buf.writeUInt32LE(samples, 40);
  return buf;
}

let base;

test.beforeEach(async ({ page }) => {
  base = '/home/user/search-' + Date.now().toString(36);
  await page.goto('/');
  await waitForTerminalReady(page);
  await pageMkdirp(page, base, 0o755);
  const files = {
    'main.rs': 'fn main() {\n    let spéctrum = "γάμμα";\n    helper(spéctrum);\n}\n\nfn helper(x: &str) {}\nfn Other() {}\n',
    'notes.txt': 'a.b axb A.B\nsecond line\n',
    'guide.md': '# Guide\n\nSearch **this** text, and this `code`.\n',
  };
  for (const [name, text] of Object.entries(files)) await pagePut(page, `${base}/${name}`, text);
  await pagePut(page, `${base}/signal.wav`, minimalWav());
});
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base).catch(() => {});
});

async function open(page, name) {
  await runTerminal(page, `open ${base}/${name}`);
  await expect(previewSurface(page)).toBeVisible();
}
const highlighted = (page, name) => previewFrame(page).locator('body').evaluate((_, n) => CSS.highlights.get(n)?.size ?? 0, name);

test('a regular expression searches highlighted code, step by step, without changing it', async ({ page }) => {
  await open(page, 'main.rs');
  const pf = previewFrame(page);
  // Wait for syntax highlighting, which replaces the code's markup.
  await expect(pf.locator('.text-preview code span').first()).toBeVisible();
  const markup = await pf.locator('.text-preview code').innerHTML();
  await expect(pf.locator('#viewer-search')).toBeVisible();
  await page.keyboard.press('Control+f');
  const search = pf.getByRole('searchbox', { name: 'Search the preview' });
  await expect(search).toBeFocused();
  await search.fill('fn \\w+');
  const status = pf.locator('.search-status');
  await expect(status).toHaveText('1 of 3');
  expect(await highlighted(page, 'preview-search')).toBe(3);
  expect(await highlighted(page, 'preview-search-current')).toBe(1);
  await search.press('Enter'); await expect(status).toHaveText('2 of 3');
  await search.press('Shift+Enter'); await expect(status).toHaveText('1 of 3');
  await search.press('Shift+Enter'); await expect(status).toHaveText('3 of 3');
  await page.keyboard.press('F3'); await expect(status).toHaveText('1 of 3');
  // Highlights are ranges; the code's markup stays as it was.
  expect(await pf.locator('.text-preview code').innerHTML()).toBe(markup);
  // Case, Unicode and line anchors.
  await pf.getByRole('button', { name: 'Match case' }).click();
  await search.fill('fn [A-Z]\\w*'); await expect(status).toHaveText('1 of 1');
  await pf.getByRole('button', { name: 'Match case' }).click();
  await search.fill('SPÉC\\w+'); await expect(status).toHaveText('1 of 2');
  await search.fill('^fn'); await expect(status).toHaveText('1 of 3');
  await search.fill('nothing here'); await expect(status).toHaveText('No matches');
  expect(await highlighted(page, 'preview-search')).toBe(0);
  // A broken expression says why.
  await search.fill('(fn');
  await expect(status).toContainText('unclosed');
  await expect(search).toHaveAttribute('aria-invalid', 'true');
  // Esc closes the search, not the viewer.
  await search.fill('helper');
  await expect(status).toHaveText('1 of 2');
  await search.press('Escape');
  await expect(pf.locator('.preview-search')).toBeHidden();
  await expect(previewSurface(page)).toBeVisible();
  expect(await highlighted(page, 'preview-search')).toBe(0);
  // The search button opens it again, with the last query.
  await pf.locator('#viewer-search').click();
  await expect(search).toBeFocused(); await expect(status).toHaveText('1 of 2');
  await closePreview(page);
});

test('plain text matches literally without regular expressions; Markdown is searchable; media is not', async ({ page }) => {
  await open(page, 'notes.txt');
  const pf = previewFrame(page);
  await expect(pf.locator('#viewer-search')).toBeVisible();
  await page.keyboard.press('Control+f');
  const search = pf.getByRole('searchbox', { name: 'Search the preview' });
  const status = pf.locator('.search-status');
  await search.fill('a.b'); await expect(status).toHaveText('1 of 3');
  await pf.getByRole('button', { name: 'Regular expression' }).click();
  await expect(search).toHaveAttribute('placeholder', 'Text');
  await expect(status).toHaveText('1 of 2');
  await search.fill('(');
  await expect(status).toHaveText('No matches');
  await closePreview(page);
  await open(page, 'guide.md');
  await expect(pf.locator('#viewer-search')).toBeVisible();
  await page.keyboard.press('Control+f');
  await search.fill('this'); await expect(status).toHaveText('1 of 2');
  await closePreview(page);
  await open(page, 'signal.wav');
  await expect(pf.locator('audio')).toBeVisible();
  await expect(pf.locator('#viewer-search')).toBeHidden();
  await page.keyboard.press('Control+f');
  await expect(pf.locator('.preview-search')).toHaveCount(0);
});
