import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, put, rmrf } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787', headers = { Origin: origin };
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const names = ['alpha.txt', 'alphabet.txt', 'z-alpha.txt', 'a_l_p_h_a.txt', 'GammaSpectrum.txt', 'γάμμα-spectrum.md', 'name "quote".txt'];
let base;
test.beforeEach(async ({ request, page }) => {
  base = '/completion-' + Date.now();
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  for (const path of [base + '/a-dir', base + '/b-dir']) await mkdirp(request, path);
  for (const name of [...names, 'a-dir/inside.txt']) expect((await put(request, '/api/file?path=' + encodeURIComponent(base + '/' + name), { headers, data: 'fixture' })).status()).toBe(201);
  await page.goto('/');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('cd ' + base); await input.press('Enter');
  await expect(page.locator('label[for=command] .prompt-path')).toHaveText(base);
});
test.afterEach(async ({ request }) => { await rmrf(request, base); });

test('lists the fuzzy matches first, to narrow them by typing, cycles them both ways, browses files on an empty line, and preserves stdout', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' }), options = page.getByRole('option');
  const transcript = await page.locator('.transcript').innerText();
  // The first Tab only lists them, so that more may be typed (owner's request, 2026-10-28).
  await input.fill('open alp'); await input.press('Tab');
  await expect(options).toHaveCount(4); await expect(input).toHaveValue('open alp');
  await expect(page.locator('.completion-hint')).toHaveText('4 matches · type to narrow · Tab pick · Esc close');
  await expect(page.locator('[role=option][aria-selected=true]')).toHaveCount(0);
  await expect(input).not.toHaveAttribute('aria-activedescendant');
  // Typed on, the line narrows them: one alone completes at once.
  await input.press('End'); await input.pressSequentially('b'); await expect(options).toHaveCount(0);
  await input.press('Tab'); await expect(input).toHaveValue('open "alphabet.txt"');
  // From the list, Tab picks the first, Shift+Tab the last.
  await input.fill('open alp'); await input.press('Tab'); await expect(options).toHaveCount(4);
  await input.press('Shift+Tab'); await expect(input).toHaveValue('open "a_l_p_h_a.txt"');
  await input.press('Escape'); await expect(input).toHaveValue('open alp');
  await input.press('Tab'); await expect(options).toHaveCount(4);
  await input.press('Tab'); await expect(input).toHaveValue('open "alpha.txt"');
  await expect(page.locator('.completion-hint')).toHaveText('1 / 4 · Tab next · Shift+Tab previous · → accept · Esc cancel');
  await input.press('Tab'); await expect(input).toHaveValue('open "alphabet.txt"');
  await input.press('Shift+Tab'); await expect(input).toHaveValue('open "alpha.txt"');
  await input.press('Shift+Tab'); await expect(input).toHaveValue('open "a_l_p_h_a.txt"');
  await input.press('Tab'); await expect(input).toHaveValue('open "alpha.txt"');
  await input.press('Escape'); await expect(input).toHaveValue('open alp'); await expect(options).toHaveCount(0);
  await input.fill(''); await input.press('Tab'); await expect(options).toHaveCount(names.length + 2);
  await input.press('Tab'); await expect(input).toHaveValue('cd "a-dir/"');
  for (let i = 0; i < names.length + 2; i++) await input.press('Tab');
  await expect(input).toHaveValue('cd "a-dir/"');
  await options.filter({ hasText: 'GammaSpectrum.txt' }).click(); await expect(input).toHaveValue('open "GammaSpectrum.txt"');
  await expect(options).toHaveCount(0);
  expect(await page.locator('.transcript').innerText()).toBe(transcript);
  await input.fill('cd '); await input.press('Tab'); await expect(options).toHaveCount(2);
  await input.press('Tab'); await expect(input).toHaveValue('cd "a-dir/"');
  await input.press('Tab'); await expect(input).toHaveValue('cd "b-dir/"');
  await input.fill('open '); await input.press('Tab'); await expect(options).toHaveCount(names.length + 2);
});

test('matches case-insensitive subsequences and quoted Unicode paths, then descends into a directory', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('open gMsP'); await input.press('Tab'); await expect(input).toHaveValue('open "GammaSpectrum.txt"');
  await input.fill('open "γα'); await input.press('Tab'); await expect(input).toHaveValue('open "γάμμα-spectrum.md"');
  await input.fill('open quo'); await input.press('Tab'); await expect(input).toHaveValue('open "name \\"quote\\".txt"');
  await input.press('Enter'); await expect(page.locator('.text-preview')).toHaveText('fixture'); await page.getByRole('button', { name: 'Close preview' }).click();
  await input.fill('open a-d'); await input.press('Tab'); await expect(input).toHaveValue('open "a-dir/"');
  await input.press('ArrowRight');
  await expect.poll(() => input.evaluate(e => e.selectionStart)).toBe('open "a-dir/'.length);
  await input.pressSequentially('in'); await input.press('Tab'); await expect(input).toHaveValue('open "a-dir/inside.txt"');
  await input.fill('rm -r -- b-d'); await input.press('Tab'); await expect(input).toHaveValue('rm -r -- "b-dir/"');
  await input.fill('zzzzzzzz'); await input.press('Tab'); await expect(page.locator('.completion-hint')).toHaveText('No matches'); await expect(input).toHaveValue('zzzzzzzz');
  await input.fill('op'); await input.press('Tab'); await expect(page.getByRole('option').first()).toContainText('open');
  await input.press('Tab'); await expect(input).toHaveValue('open '); await input.press('ArrowRight');
  await input.press('Tab'); await expect(page.getByRole('option')).toHaveCount(names.length + 2);
});

test('queues fast Tab presses and discards late listings after editing', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  let requests = 0;
  await page.route('**/api/sys', async route => { if (route.request().postData()?.includes('getdents')) { requests++; await new Promise(resolve => setTimeout(resolve, 500)); } await route.continue(); });
  // The first lists them; each one after picks the next.
  await input.fill('open alp'); await input.press('Tab'); await input.press('Tab'); await input.press('Tab');
  // At most one listing: none, as the panel's listing of the directory is the page's cache's.
  await expect(input).toHaveValue('open "alphabet.txt"'); expect(requests).toBeLessThanOrEqual(1);
  await input.fill('open a-dir/in');
  const response = page.waitForResponse(r => r.url().includes('/api/sys') && r.request().postData()?.includes('getdents'));
  await input.press('Tab'); await input.fill('pwd'); await response;
  // A rendering frame lets the discarded response finish all its callbacks.
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(input).toHaveValue('pwd'); await expect(page.getByRole('option')).toHaveCount(0);
});
