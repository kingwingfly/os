import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, mkdirp, put, rmrf } from './sys.js';
import { promptPath } from './ui.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787', headers = { Origin: origin };
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const names = ['alpha.txt', 'alphabet.txt', 'z-alpha.txt', 'a_l_p_h_a.txt', 'GammaSpectrum.txt', 'γάμμα-spectrum.md', 'name "quote".txt'];
let base;
test.beforeEach(async ({ request, page }) => {
  base = '/completion-' + Date.now();
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  for (const path of [base + '/a-dir', base + '/b-dir', base + '/space dir']) await mkdirp(request, path);
  for (const name of [...names, 'a-dir/inside.txt']) expect((await put(request, '/api/file?path=' + encodeURIComponent(base + '/' + name), { headers, data: 'fixture' })).status()).toBe(201);
  await page.goto('/');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('cd ' + base); await input.press('Enter');
  await expect(promptPath(page)).toHaveText(base);
});
test.afterEach(async ({ request }) => { await rmrf(request, base); });

test('expands the common prefix, cycles the pager, and restores the original token on Escape', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' }), options = page.getByRole('option');
  const transcript = await page.locator('.transcript').innerText();
  await input.fill('open alp'); await input.press('Tab');
  await expect(options).toHaveCount(2); await expect(input).toHaveValue('open alpha');
  await expect(page.locator('[role=option][aria-selected=true]')).toHaveCount(0);
  await input.pressSequentially('b'); await expect(options).toHaveCount(0);
  await input.press('Tab'); await expect(input).toHaveValue('open alphabet.txt ');
  await expect(options).toHaveCount(0);
  await input.fill('open alp'); await input.press('Tab');
  await expect(input).toHaveValue('open alpha');
  await input.press('Shift+Tab'); await expect(input).toHaveValue('open alphabet.txt ');
  await input.press('Tab'); await expect(input).toHaveValue('open alpha.txt ');
  await input.press('Tab'); await expect(input).toHaveValue('open alphabet.txt ');
  await input.press('Escape'); await expect(input).toHaveValue('open alp');
  await expect(options).toHaveCount(0);
  expect(await page.locator('.transcript').innerText()).toBe(transcript);
});

test('suggestions sit directly below the active command and stay there after scrolling and resizing', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const check = async () => {
    const geometry = await page.locator('.terminal-panel:not([hidden])').evaluate(panel => {
      const log = panel.querySelector('.transcript'), form = panel.querySelector('.command-line'), pager = panel.querySelector('.completion-pager');
      const l = log.getBoundingClientRect(), f = form.getBoundingClientRect(), p = pager.getBoundingClientRect();
      return { inline: pager.parentElement === log && form.nextElementSibling === pager, gap: p.top - f.bottom, visible: f.top >= l.top - 1 && p.bottom <= l.bottom + 1 };
    });
    expect(geometry.inline).toBe(true); expect(geometry.gap).toBeGreaterThanOrEqual(0); expect(geometry.gap).toBeLessThanOrEqual(8); expect(geometry.visible).toBe(true);
  };
  await input.fill('open alp'); await input.press('Tab'); await expect(page.getByRole('option')).toHaveCount(2); await check();
  await input.press('Escape');
  await input.fill('/usr/bin/seq 1 60'); await input.press('Enter');
  await expect(input.locator('xpath=..')).toHaveAttribute('data-state', 'idle', { timeout: 60000 });
  await input.fill('open alp'); await input.press('Tab'); await expect(page.getByRole('option')).toHaveCount(2);
  await expect.poll(async () => page.locator('.transcript').evaluate(log => log.scrollTop > 0)).toBe(true); await check();
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(async () => input.evaluate(e => { const r = e.getBoundingClientRect(), parent = e.closest('.transcript').getBoundingClientRect(); return r.top >= parent.top - 1; })).toBe(true);
  await check();
});

test('completes directories without inserting cd and enters them directly', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' }), options = page.getByRole('option');
  await input.fill(''); await input.press('Tab');
  await expect(options.filter({ hasText: 'a-dir/' })).toHaveCount(1);
  await options.filter({ hasText: 'a-dir/' }).click();
  await expect(input).toHaveValue('a-dir/'); await expect(options).toHaveCount(0);
  await input.press('Enter'); await expect(promptPath(page)).toHaveText(base + '/a-dir');
  await input.fill('..'); await input.press('Enter'); await expect(promptPath(page)).toHaveText(base);
  await input.fill('spa'); await input.press('Tab'); await expect(input).toHaveValue(String.raw`space\ dir/`);
  await input.press('Enter'); await expect(promptPath(page)).toHaveText(base + '/space dir');
  await input.fill('cd /'); await input.press('Enter'); await expect(promptPath(page)).toHaveText('/');
  await input.fill('gues'); await input.press('Tab'); await expect(input).toHaveValue('guest/');
  await input.press('Enter'); await expect(promptPath(page)).toHaveText('/guest');
});

test('keeps Unicode and shell escaping, and continues completion inside directories', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('open gMsP'); await input.press('Tab'); await expect(input).toHaveValue('open GammaSpectrum.txt ');
  await input.fill('open "γα'); await input.press('Tab'); await expect(input).toHaveValue('open "γάμμα-spectrum.md" ');
  await input.fill('open quo'); await input.press('Tab'); await expect(input).toHaveValue(String.raw`open name\ \"quote\".txt `);
  await input.press('Enter'); await expect(page.locator('.text-preview')).toHaveText('fixture'); await page.getByRole('button', { name: 'Close preview' }).click();
  await input.fill('open a-d'); await input.press('Tab'); await expect(input).toHaveValue('open a-dir/');
  await input.pressSequentially('in'); await input.press('Tab'); await expect(input).toHaveValue('open a-dir/inside.txt ');
  await input.fill('open "a-d'); await input.press('Tab'); await expect(input).toHaveValue('open "a-dir/"');
  await expect.poll(() => input.evaluate(e => e.selectionStart)).toBe('open "a-dir/'.length);
  await input.pressSequentially('in'); await input.press('Tab'); await expect(input).toHaveValue('open "a-dir/inside.txt" ');
  await input.fill('rm -r -- b-d'); await input.press('Tab'); await expect(input).toHaveValue('rm -r -- b-dir/');
  await input.fill('zzzzzzzz'); await input.press('Tab'); await expect(page.locator('.completion-hint')).toHaveText('No matches');
  await expect(input).toHaveValue('zzzzzzzz');
  await input.fill('op'); await input.press('Tab'); await expect(input).toHaveValue('open ');
  await input.press('Tab'); await expect(page.getByRole('option')).toHaveCount(names.length + 3);
});

test('completes the token at the cursor and preserves the rest of the command', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('cp   alp destination.txt');
  await input.evaluate(e => e.setSelectionRange(8, 8)); await input.press('Tab');
  await expect(input).toHaveValue('cp   alpha destination.txt');
  await input.press('Tab'); await expect(input).toHaveValue('cp   alpha.txt destination.txt');
  await input.press('Escape'); await expect(input).toHaveValue('cp   alp destination.txt');
  await input.fill('open "γάxxx"');
  const caret = 'open "γά'.length;
  await input.evaluate((e, n) => e.setSelectionRange(n, n), caret); await input.press('Tab');
  await expect(input).toHaveValue('open "γάμμα-spectrum.md" ');
});

test('queues fast Tab presses and discards late listings after editing or moving the caret', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  let requests = 0;
  await page.route('**/api/sys', async route => { if (route.request().postData()?.includes('getdents')) { requests++; await new Promise(resolve => setTimeout(resolve, 500)); } await route.continue(); });
  await input.fill('open alp'); await input.press('Tab'); await input.press('Tab'); await input.press('Tab');
  await expect(input).toHaveValue('open alphabet.txt '); expect(requests).toBeLessThanOrEqual(1);
  await input.fill('open a-dir/in');
  const response = page.waitForResponse(r => r.url().includes('/api/sys') && r.request().postData()?.includes('getdents'));
  await input.press('Tab'); await input.fill('pwd'); await response;
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(input).toHaveValue('pwd'); await expect(page.getByRole('option')).toHaveCount(0);
  await input.fill('open space\\ dir/');
  const moved = page.waitForResponse(r => r.url().includes('/api/sys') && r.request().postData()?.includes('getdents'));
  await input.press('Tab'); await input.press('Home'); await moved;
  await expect(input).toHaveValue('open space\\ dir/'); await expect(page.getByRole('option')).toHaveCount(0);
  await input.press('End'); await input.press('Tab'); await expect(page.locator('.completion-hint')).toHaveText('No matches');
});

test('a delayed completion cannot steal focus from another desktop app', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  let release, pending = false;
  const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/api/sys', async route => {
    if (route.request().postData()?.includes('getdents')) { pending = true; await gate; }
    await route.continue();
  });
  try {
    await input.fill('open a-dir/in'); await input.press('Tab'); await expect.poll(() => pending).toBe(true);
    await page.evaluate(() => window.os.localMounts());
    const app = page.locator('#window-mounts'); await app.getByRole('tab', { name: 'Add mount', exact: true }).click();
    await app.locator('[data-add-form] [name=name]').focus(); release();
    await expect(input).toHaveValue('open a-dir/inside.txt ');
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(app).toHaveClass(/window-focused/); await expect(app.locator('[data-add-form] [name=name]')).toBeFocused();
  } finally { release(); await page.unrouteAll({ behavior: 'wait' }); }
});

test('ls and explicit external programs complete files without a browser command definition', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  for (const command of ['ls', '/usr/bin/ls', 'sudo ls']) {
    await input.fill(command + ' '); await input.press('Tab');
    await expect(page.getByRole('option')).toHaveCount(names.length + 3);
    await input.press('Escape');
    await input.fill(command + ' a-d'); await input.press('Tab');
    await expect(input).toHaveValue(command + ' a-dir/');
  }
});

test('a wrapped guest prompt keeps the input beside its final symbol in narrow windows', async ({ page }) => {
  await page.goto('/');
  const input = page.getByRole('combobox', { name: 'Terminal command' }); await expect(input).toBeVisible();
  for (const width of [320, 270, 410]) {
    await page.locator('#window-terminal').evaluate((window, width) => { window.style.minWidth = '0'; window.style.width = width + 'px'; }, width);
    await expect.poll(() => input.evaluate(input => {
      const label = input.closest('form').querySelector('.prompt-symbol'), range = document.createRange(); range.selectNodeContents(label);
      const end = [...range.getClientRects()].at(-1), caret = input.getBoundingClientRect(), form = input.closest('form').getBoundingClientRect();
      return { sameRow: Math.abs(caret.bottom - end.bottom) < 15, adjacent: caret.left >= end.right && caret.left - end.right < 20, contained: caret.right <= form.right + 1 };
    })).toEqual({ sameRow: true, adjacent: true, contained: true });
    await input.fill('ls'); await expect(input).toHaveValue('ls'); await input.fill('');
  }
});
