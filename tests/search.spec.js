import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, put, rmrf } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
let base, headers;

test.beforeEach(async ({ request, page }) => {
  base = '/search-' + Date.now().toString(36);
  headers = { Origin: origin, 'CF-Connecting-IP': 'search-' + base };
  await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'search-ui-' + base });
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, base);
  const files = {
    'main.rs': 'fn main() {\n    let spéctrum = "γάμμα";\n    helper(spéctrum);\n}\n\nfn helper(x: &str) {}\nfn Other() {}\n',
    'notes.txt': 'a.b axb A.B\nsecond line\n',
    'guide.md': '# Guide\n\nSearch **this** text, and this `code`.\n',
  };
  for (const [name, text] of Object.entries(files)) expect((await put(request, file(`${base}/${name}`), { headers, data: text })).status()).toBe(201);
});
test.afterEach(async ({ request }) => { await rmrf(request, base); });

async function open(page, name) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await expect(page.locator('#command').locator('xpath=ancestor::form').locator('.busy')).toHaveText('↵');
  await input.fill(`open ${base}/${name}`); await input.press('Enter');
  await expect(page.locator('#viewer')).toBeVisible();
}
const highlighted = (page, name) => page.evaluate(n => CSS.highlights.get(n)?.size ?? 0, name);

test('a regular expression searches highlighted code, step by step, without changing it', async ({ page }) => {
  await page.goto('/');
  await open(page, 'main.rs');
  // Wait for syntax highlighting, which replaces the code's markup.
  await expect(page.locator('.text-preview code span').first()).toBeVisible();
  const markup = await page.locator('.text-preview code').innerHTML();
  await expect(page.locator('#viewer-search')).toBeVisible();
  await page.keyboard.press('Control+f');
  const search = page.getByRole('searchbox', { name: 'Search the preview' });
  await expect(search).toBeFocused();
  await search.fill('fn \\w+');
  const status = page.locator('.search-status');
  await expect(status).toHaveText('1 of 3');
  expect(await highlighted(page, 'preview-search')).toBe(3);
  expect(await highlighted(page, 'preview-search-current')).toBe(1);
  await search.press('Enter'); await expect(status).toHaveText('2 of 3');
  await search.press('Shift+Enter'); await expect(status).toHaveText('1 of 3');
  await search.press('Shift+Enter'); await expect(status).toHaveText('3 of 3');
  await page.keyboard.press('F3'); await expect(status).toHaveText('1 of 3');
  // Highlights are ranges; the code's markup stays as it was.
  expect(await page.locator('.text-preview code').innerHTML()).toBe(markup);
  // Case, Unicode and line anchors.
  await page.getByRole('button', { name: 'Match case' }).click();
  await search.fill('fn [A-Z]\\w*'); await expect(status).toHaveText('1 of 1');
  await page.getByRole('button', { name: 'Match case' }).click();
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
  await expect(page.locator('.preview-search')).toBeHidden();
  await expect(page.locator('#viewer')).toBeVisible();
  expect(await highlighted(page, 'preview-search')).toBe(0);
  // The search button opens it again, with the last query.
  await page.locator('#viewer-search').click();
  await expect(search).toBeFocused(); await expect(status).toHaveText('1 of 2');
  await page.getByRole('button', { name: 'Close preview' }).click();
  await expect(page.locator('#viewer')).toBeHidden();
  expect(await highlighted(page, 'preview-search')).toBe(0);
});

test('plain text matches literally without regular expressions; Markdown is searchable; media is not', async ({ page }) => {
  await page.goto('/');
  await open(page, 'notes.txt');
  await expect(page.locator('#viewer-search')).toBeVisible();
  await page.keyboard.press('Control+f');
  const search = page.getByRole('searchbox', { name: 'Search the preview' });
  const status = page.locator('.search-status');
  await search.fill('a.b'); await expect(status).toHaveText('1 of 3');
  await page.getByRole('button', { name: 'Regular expression' }).click();
  await expect(search).toHaveAttribute('placeholder', 'Text');
  await expect(status).toHaveText('1 of 2');
  await search.fill('(');
  await expect(status).toHaveText('No matches');
  await page.getByRole('button', { name: 'Close preview' }).click();
  await open(page, 'guide.md');
  await expect(page.locator('#viewer-search')).toBeVisible();
  await page.keyboard.press('Control+f');
  await search.fill('this'); await expect(status).toHaveText('1 of 2');
  await page.getByRole('button', { name: 'Close preview' }).click();
  await open(page, '../media/signal.wav');
  await expect(page.locator('audio')).toBeVisible();
  await expect(page.locator('#viewer-search')).toBeHidden();
  await page.keyboard.press('Control+f');
  await expect(page.locator('.preview-search')).toHaveCount(0);
});
