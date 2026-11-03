import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, errno, listing, mkdirp, put } from './sys.js';
// The Files go to `path` of their own: its location typed (files.rs).
async function browse(page, path) {
  const location = page.getByRole('textbox', { name: 'Location' });
  await location.fill(path); await location.press('Enter');
  await expect(location).toHaveValue(path);
}
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
// A line is typed at the prompt, once the one before has ended, as the shell takes no other.
const prompt = page => expect(page.locator('.busy')).toHaveText('↵');
const run = async (page, command) => { const input = page.getByRole('combobox', { name: 'Terminal command' }); await prompt(page); await input.fill(command); await input.press('Enter'); };

test('R2 API enforces auth, same-origin writes, no-overwrite and byte ranges', async ({ request }) => {
  const name = '/test-' + Date.now();
  expect(await errno(request, { mkdir: { path: name, mode: 0o777 } })).toBe('EACCES');
  expect((await api(request, 'login', { headers: { Origin: 'https://elsewhere.invalid' }, data: { password } })).status()).toBe(403);
  expect((await api(request, 'login', { headers: { Origin: origin }, data: { password: 'wrong' } })).status()).toBe(401);
  expect((await api(request, 'login', { headers: { Origin: origin }, data: { password } })).ok()).toBeTruthy();
  await mkdirp(request, name);
  const url = '/api/file?path=' + encodeURIComponent(name + '/With spaces.txt');
  expect((await put(request, url, { headers: { Origin: origin }, data: '0123456789' })).status()).toBe(201);
  expect((await put(request, url, { headers: { Origin: origin }, data: 'replace' })).status()).toBe(409);
  const range = await request.get(url, { headers: { Range: 'bytes=2-4' } });
  expect(range.status()).toBe(206); expect(await range.text()).toBe('234'); expect(range.headers()['content-range']).toBe('bytes 2-4/10');
  expect((await request.get(url, { headers: { Range: 'bytes=99-' } })).status()).toBe(416);
  expect((await request.head(url)).headers()['content-length']).toBe('10');
  expect((await listing(request, name))[0].name).toBe('With spaces.txt');
  const empty = '/api/file?path=' + name + '/empty.txt';
  expect((await put(request, empty, { headers: { Origin: origin, 'Content-Length': '0' }, data: '' })).status()).toBe(201);
  expect(await (await request.get(empty)).text()).toBe('');
  expect((await request.head(empty)).headers()['content-length']).toBe('0');

  // Bytes are written from this site only.
  expect((await request.put('/api/pwrite?fd=3&index=0', { headers: { Origin: 'https://elsewhere.invalid' }, data: 'x' })).status()).toBe(403);
  await api(request, 'logout', { headers: { Origin: origin } });
  expect((await request.get(url)).ok()).toBeTruthy();
  expect((await put(request, '/api/file?path=' + name + '/x.txt', { headers: { Origin: origin }, data: 'x' })).status()).toBe(401);
});

// Tab completes a sole match at once; of several, the first Tab lists them, and the next picks
// the best, whatever else earlier runs left to match.
async function complete(input, text, expected) {
  await prompt(input.page());
  await input.fill(text); await input.press('Tab');
  await expect(input.page().getByRole('option').first()).toBeVisible();
  if (await input.inputValue() !== expected) await input.press('Tab');
  await expect(input).toHaveValue(expected);
}

test('terminal, password modal, upload, sanitized Markdown, slides and media', async ({ page }) => {
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto('/');
  await expect(page.getByRole('navigation', { name: 'Dock' })).toBeVisible();
  await expect(page.locator('.loading')).toHaveCount(0);
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('hel'); await input.press('Tab'); await expect(input).toHaveValue('help ');
  await run(page, 'open welcome.md'); await expect(page.locator('#viewer .markdown h1')).toContainText('R2 Terminal');
  await page.getByRole('button', { name: 'Close preview' }).click();
  await run(page, 'open dem'); await expect(page.locator('.transcript')).toContainText('open: dem: No such file or directory');
  // Every command completes the paths its definition takes: faststart's file, unzip -d's directory.
  await complete(input, 'faststart dem', 'faststart "demo.slides.md"');
  await complete(input, 'unzip -d med', 'unzip -d "media/"');
  await complete(input, 'open dem', 'open "demo.slides.md"');
  await input.press('Enter'); await expect(page.locator('.slides-current .slide:visible')).toBeVisible();
  await page.keyboard.press('ArrowRight'); await expect(page.locator('.slides-current .slide:visible')).toContainText('One filesystem');
  await page.getByRole('button', { name: 'Close preview' }).click();
  const folder = 'browser-test-' + Date.now();
  await run(page, 'su root'); await expect(page.locator('#auth')).toBeVisible();
  await page.getByLabel('Password', { exact: true }).fill(password); await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('.busy')).toHaveText('↵');
  await run(page, 'mkdir ' + folder);
  await complete(input, 'cd ' + folder.slice(0, -1), 'cd "' + folder + '/"'); await input.press('Enter'); await expect(page.locator('label[for=command] .prompt-path')).toHaveText('/' + folder);
  // The Files upload into their own directory.
  await browse(page, '/' + folder);
  const chooserPromise = page.waitForEvent('filechooser'); await page.getByRole('button', { name: '↑ Upload files' }).click();
  await (await chooserPromise).setFiles({ name: 'Safe preview.md', mimeType: 'text/markdown', buffer: Buffer.from('# Rendered safely\n\n<img src="missing" onerror="window.xss=true">\n<script>window.xss=true</script>\n[bad](javascript:alert(1))') });
  await expect(page.locator('.filename').filter({ hasText: 'Safe preview.md' })).toBeVisible();
  await run(page, 'open "Safe preview.md"'); await expect(page.locator('.markdown h1')).toHaveText('Rendered safely');
  expect(await page.evaluate(() => window.xss)).toBeUndefined();
  expect(await page.locator('.markdown [onerror], .markdown script, .markdown a[href^="javascript:"]').count()).toBe(0);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await run(page, 'open /media/signal.wav'); await expect(page.locator('audio')).toBeVisible();
  await expect.poll(() => page.locator('audio').evaluate(e => e.readyState)).toBeGreaterThan(0);
  await page.getByRole('button', { name: 'Close preview' }).click();
  expect(errors.filter(e => !e.includes('Using exceptions for control flow'))).toEqual([]);
  await page.screenshot({ path: 'test-results/terminal.png', fullPage: true });
});

test('drag/drop uploads images and videos, warning of one that is not faststart', async ({ page, request }) => {
  const folder = '/media-test-' + Date.now();
  await page.goto('/');
  await run(page, 'su root');
  await expect(page.locator('#auth')).toBeVisible();
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('.busy')).toHaveText('↵');
  await run(page, 'mkdir ' + folder);
  await run(page, 'cd ' + folder); await expect(page.locator('label[for=command] .prompt-path')).toHaveText(folder);
  await browse(page, folder);
  for (const name of ['pixel.png', 'faststart.mp4', 'tail-moov.mp4']) {
    const bytes = [...await readFile('tests/fixtures/' + name)];
    const transfer = await page.evaluateHandle(({ name, bytes }) => {
      const dt = new DataTransfer(); dt.items.add(new File([new Uint8Array(bytes)], name)); return dt;
    }, { name, bytes });
    // Dropped files upload in the active tab, as its upload command does.
    await expect(page.locator('.busy')).toHaveText('↵');
    await page.dispatchEvent('body', 'drop', { dataTransfer: transfer });
    await expect(page.locator('.filename').filter({ hasText: name })).toBeVisible();
    // Not faststart is uploaded, with what it costs and how to fix it.
    if (name === 'tail-moov.mp4') {
      await expect(page.locator('.transcript')).toContainText('✓ tail-moov.mp4');
      await expect(page.locator('.transcript')).toContainText("⚠ not faststart: its index (moov) is after its media");
      await expect(page.locator('.transcript')).toContainText("run faststart 'tail-moov.mp4' once it has uploaded");
    }
    await transfer.dispose();
  }
  const files = await listing(request, folder);
  expect(files.map(e => e.name).sort()).toEqual(['faststart.mp4', 'pixel.png', 'tail-moov.mp4']);
  await run(page, 'open pixel.png');
  await expect.poll(() => page.locator('.media-frame img').evaluate(e => e.naturalWidth)).toBe(1);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await run(page, 'open faststart.mp4');
  await expect.poll(() => page.locator('video').evaluate(e => e.readyState)).toBeGreaterThan(0);
  await page.locator('video').evaluate(async e => { e.muted = true; await e.play(); e.currentTime = 0.5; });
  await expect.poll(() => page.locator('video').evaluate(e => e.currentTime)).toBeGreaterThanOrEqual(0.5);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: 'test-results/terminal-mobile.png', fullPage: true });
});
