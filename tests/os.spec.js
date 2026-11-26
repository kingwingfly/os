import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, errno, listing, mkdirp, put } from './sys.js';
import {
  browse,
  filesFrame,
  filesProgress,
  pageListing,
  pageMkdirp,
  pagePut,
  promptPath,
  runTerminal,
  terminalScreen,
  waitForDesktopReady,
} from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];

function minimalWav() {
  // 44-byte PCM WAV header + 8000 bytes (0.5s 8kHz mono 8-bit silence) so <audio> loads cleanly offline.
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

test('terminal auto-login, local upload, sanitized Markdown, slides and media', async ({ page }) => {
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto('/');
  await waitForDesktopReady(page);
  await expect(page.getByRole('navigation', { name: 'Dock' })).toBeVisible();
  await expect(page.locator('.loading')).toHaveCount(0);
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user');
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Cloud: Signed out');

  // Seed local docs and media on local `os-cowfs` (zero server dependency).
  await pagePut(page, '/welcome.md', '# OS\n\nLocal offline OS.\n', { mode: 0o644, sudo: true });
  await pagePut(page, '/demo.slides.md', '# Slide 1\n\n---\n\n# One filesystem\n', { mode: 0o644, sudo: true });
  await pageMkdirp(page, '/media', 0o755, { sudo: true });
  await pagePut(page, '/media/signal.wav', minimalWav(), { mode: 0o644, sudo: true });

  await runTerminal(page, 'cd /');
  await runTerminal(page, 'open welcome.md');
  await expect(page.locator('#viewer .markdown h1')).toContainText('OS');
  await page.getByRole('button', { name: 'Close preview' }).click();
  await runTerminal(page, 'open dem');
  await expect(terminalScreen(page)).toContainText('open: dem: No such file or directory');
  await runTerminal(page, 'open demo.slides.md');
  await expect(page.locator('.slides-current .slide:visible')).toBeVisible();
  await page.keyboard.press('ArrowRight'); await expect(page.locator('.slides-current .slide:visible')).toContainText('One filesystem');
  await page.getByRole('button', { name: 'Close preview' }).click();

  // Zero-friction local wheel user can create folders directly in `/home/user` without any login modal.
  const folder = 'browser-test-' + Date.now();
  await runTerminal(page, 'cd ~');
  await expect(promptPath(page)).toHaveText('/home/user');
  await runTerminal(page, 'mkdir ' + folder);
  await runTerminal(page, 'cd ' + folder);
  await expect(promptPath(page)).toHaveText('/home/user/' + folder);
  // The Files upload into their own directory.
  await browse(page, '/home/user/' + folder);
  const chooserPromise = page.waitForEvent('filechooser'); await filesFrame(page).getByRole('button', { name: 'Upload' }).click();
  await (await chooserPromise).setFiles({ name: 'Safe preview.md', mimeType: 'text/markdown', buffer: Buffer.from('# Rendered safely\n\n<img src="missing" onerror="window.xss=true">\n<script>window.xss=true</script>\n[bad](javascript:alert(1))') });
  await expect(filesFrame(page).locator('.filename').filter({ hasText: 'Safe preview.md' })).toBeVisible();
  await runTerminal(page, 'open "Safe preview.md"'); await expect(page.locator('.markdown h1')).toHaveText('Rendered safely');
  expect(await page.evaluate(() => window.xss)).toBeUndefined();
  expect(await page.locator('.markdown [onerror], .markdown script, .markdown a[href^="javascript:"]').count()).toBe(0);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await runTerminal(page, 'open /media/signal.wav'); await expect(page.locator('audio')).toBeVisible();
  await expect.poll(() => page.locator('audio').evaluate(e => e.readyState)).toBeGreaterThan(0);
  await page.getByRole('button', { name: 'Close preview' }).click();
  expect(errors.filter(e => !e.includes('Using exceptions for control flow'))).toEqual([]);
  await page.screenshot({ path: 'test-results/terminal.png', fullPage: true });
});

test('drag/drop uploads images and videos, warning of one that is not faststart', async ({ page }) => {
  const folder = '/home/user/media-test-' + Date.now();
  await page.goto('/');
  await waitForDesktopReady(page);
  await runTerminal(page, 'mkdir ' + folder);
  await runTerminal(page, 'cd ' + folder); await expect(promptPath(page)).toHaveText(folder);
  await browse(page, folder);
  const progress = filesProgress(page);
  for (const name of ['pixel.png', 'faststart.mp4', 'tail-moov.mp4']) {
    const bytes = [...await readFile('tests/fixtures/' + name)];
    const transfer = await page.evaluateHandle(({ name, bytes }) => {
      const dt = new DataTransfer(); dt.items.add(new File([new Uint8Array(bytes)], name)); return dt;
    }, { name, bytes });
    // Dropped files route via `os-files` into Files' current directory and report in Upload progress.
    await page.dispatchEvent('body', 'drop', { dataTransfer: transfer });
    await expect(progress).toContainText('✓ ' + name, { timeout: 20_000 });
    await expect(filesFrame(page).locator('.filename').filter({ hasText: name })).toBeVisible();
    // Not faststart is uploaded, with what it costs and how to fix it.
    if (name === 'tail-moov.mp4') {
      await expect(progress).toContainText('✓ tail-moov.mp4');
      await expect(progress).toContainText('⚠ not faststart: its index (moov) is after its media');
      await expect(progress).toContainText("run faststart 'tail-moov.mp4' once it has uploaded");
    }
    await transfer.dispose();
  }
  const files = await pageListing(page, folder);
  expect(files.map(e => e.name).sort()).toEqual(['faststart.mp4', 'pixel.png', 'tail-moov.mp4']);
  await runTerminal(page, 'open pixel.png');
  await expect.poll(() => page.locator('.media-frame img').evaluate(e => e.naturalWidth)).toBe(1);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await runTerminal(page, 'open faststart.mp4');
  await expect.poll(() => page.locator('video').evaluate(e => e.readyState)).toBeGreaterThan(0);
  await page.locator('video').evaluate(async e => { e.muted = true; await e.play(); e.currentTime = 0.5; });
  await expect.poll(() => page.locator('video').evaluate(e => e.currentTime)).toBeGreaterThanOrEqual(0.5);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBeTruthy();
  await page.screenshot({ path: 'test-results/terminal-mobile.png', fullPage: true });
});
