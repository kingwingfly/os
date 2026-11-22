import { test, expect } from './test.js';
import { pageMkdirp, pagePut, pageRmrf, promptPath } from './ui.js';

const names = ['alpha.txt', 'alphabet.txt', 'z-alpha.txt', 'a_l_p_h_a.txt', 'GammaSpectrum.txt', 'γάμμα-spectrum.md', 'name "quote".txt'];
let base;
test.beforeEach(async ({ page }) => {
  base = '/home/user/completion-' + Date.now();
  await page.goto('/');
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  for (const path of [base + '/a-dir', base + '/b-dir', base + '/space dir']) await pageMkdirp(page, path, 0o755);
  for (const name of [...names, 'a-dir/inside.txt']) await pagePut(page, base + '/' + name, 'fixture', { mode: 0o644 });
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('cd ' + base); await input.press('Enter');
  await expect(promptPath(page)).toHaveText(base);
});
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base).catch(() => {});
});

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
  await input.fill('hom'); await input.press('Tab'); await expect(input).toHaveValue('home/');
  await input.press('Enter'); await expect(promptPath(page)).toHaveText('/home');
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
  // Local VFS intercepts `fetch('/api/sys')` in-page (`web/local-files.js`), so wrap `window.fetch`
  // to inject deterministic latency on `getdents` batches without hitting the network.
  await page.evaluate(() => {
    const orig = window.fetch.bind(window);
    window.__origFetch = orig;
    window.__getdents = { started: 0, completed: 0 };
    window.fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input?.url ?? '';
      let body = typeof init?.body === 'string' ? init.body : '';
      if (!body && input instanceof Request) {
        try { body = await input.clone().text(); } catch {}
      }
      if (url.includes('/api/sys') && body.includes('getdents')) {
        window.__getdents.started++;
        await new Promise(resolve => setTimeout(resolve, 400));
        try { return await orig(input, init); } finally { window.__getdents.completed++; }
      }
      return orig(input, init);
    };
  });
  try {
    await input.fill('open alp'); await input.press('Tab'); await input.press('Tab'); await input.press('Tab');
    await expect(input).toHaveValue('open alphabet.txt ');
    expect(await page.evaluate(() => window.__getdents.started)).toBeLessThanOrEqual(1);

    const beforeEdit = await page.evaluate(() => window.__getdents.completed);
    await input.fill('open a-dir/in');
    await input.press('Tab'); await input.fill('pwd');
    await expect.poll(() => page.evaluate(() => window.__getdents.completed)).toBeGreaterThan(beforeEdit);
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(input).toHaveValue('pwd'); await expect(page.getByRole('option')).toHaveCount(0);

    const beforeMove = await page.evaluate(() => window.__getdents.completed);
    await input.fill('open space\\ dir/');
    await input.press('Tab'); await input.press('Home');
    await expect.poll(() => page.evaluate(() => window.__getdents.completed)).toBeGreaterThan(beforeMove);
    await expect(input).toHaveValue('open space\\ dir/'); await expect(page.getByRole('option')).toHaveCount(0);
    await input.press('End'); await input.press('Tab'); await expect(page.locator('.completion-hint')).toHaveText('No matches');
  } finally {
    await page.evaluate(() => { if (window.__origFetch) { window.fetch = window.__origFetch; delete window.__origFetch; } });
  }
});

test('a delayed completion cannot steal focus from another desktop app', async ({ page }) => {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await page.evaluate(() => {
    const orig = window.fetch.bind(window);
    window.__origFetch = orig;
    window.__gatePending = false;
    window.__gatePromise = new Promise(resolve => { window.__releaseGate = resolve; });
    window.fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input?.url ?? '';
      let body = typeof init?.body === 'string' ? init.body : '';
      if (!body && input instanceof Request) {
        try { body = await input.clone().text(); } catch {}
      }
      if (url.includes('/api/sys') && body.includes('getdents')) {
        window.__gatePending = true;
        await window.__gatePromise;
      }
      return orig(input, init);
    };
  });
  try {
    await input.fill('open a-dir/in'); await input.press('Tab');
    await expect.poll(() => page.evaluate(() => window.__gatePending)).toBe(true);
    await page.evaluate(() => window.os.localMounts());
    const app = page.locator('#window-mounts'); await app.getByRole('tab', { name: 'Add mount', exact: true }).click();
    await app.locator('[data-add-form] [name=name]').focus();
    await page.evaluate(() => window.__releaseGate());
    await expect(input).toHaveValue('open a-dir/inside.txt ');
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await expect(app).toHaveClass(/window-focused/); await expect(app.locator('[data-add-form] [name=name]')).toBeFocused();
  } finally {
    await page.evaluate(() => {
      window.__releaseGate?.();
      if (window.__origFetch) { window.fetch = window.__origFetch; delete window.__origFetch; }
    });
  }
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

test('a wrapped prompt keeps the input beside its final symbol in narrow windows', async ({ page }) => {
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
