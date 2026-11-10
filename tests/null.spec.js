import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, call, errno, rmrf } from './sys.js';

const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const nullPath = '/dev/null';
const byteHeaders = { Origin: origin, 'Content-Type': 'application/octet-stream' };
const file = path => '/api/file?path=' + encodeURIComponent(path);
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function run(page, command) {
  const prompt = page.locator('.terminal-panel:not([hidden]) .command-line');
  await expect(prompt).toHaveAttribute('data-state', 'idle');
  await page.locator('#command').fill(command);
  await page.locator('#command').press('Enter');
  await expect(prompt).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}

test('null is a character device with EOF and non-persistent writes through both byte APIs', async ({ request }) => {
  const before = await call(request, { stat: { path: nullPath } });
  expect(before.mode).toBe(0o020666);
  expect(before.rdev).toBe('null');
  expect((await request.get(file(nullPath))).status()).toBe(200);
  expect(await (await request.get(file(nullPath))).body()).toHaveLength(0);
  for (const flags of [0, 1, 2]) {
    const { fd, device } = await call(request, { open: { path: nullPath, flags } });
    expect(device).toBe('null');
    try {
      const read = { pread: { fd, offset: 4567, count: 512 } };
      const write = { pwrite: { fd, index: 123, data: Buffer.from([0, 255, 13]).toString('base64') } };
      if (flags === 1) expect(await errno(request, read)).toBe('EBADF');
      else expect(await call(request, read)).toEqual({ data: '', size: 0 });
      if (flags === 0) {
        expect(await errno(request, write)).toBe('EBADF');
        const denied = await request.put(`/api/pwrite?fd=${fd}&index=0`, { headers: byteHeaders, data: 'denied' });
        expect((await denied.json()).errno).toBe('EBADF');
      } else {
        expect(await call(request, write)).toEqual({ written: 3 });
        const response = await request.put(`/api/pwrite?fd=${fd}&index=0`, { headers: byteHeaders, data: Buffer.alloc(1024 * 1024, 0xff) });
        expect(response.ok(), await response.text()).toBe(true);
        expect(await response.json()).toEqual({ written: 1024 * 1024 });
      }
      expect(await errno(request, { ioctl: { fd, request: 0xdead, arg: null } })).toBe('ENOTTY');
    } finally { await call(request, { close: { fd } }); }
    expect(await errno(request, { pread: { fd, count: 1 } })).toBe('EBADF');
  }
  expect(await call(request, { stat: { path: nullPath } })).toEqual(before);
});

test('null follows ordinary permissions and symlinks; read/write needs both access bits', async ({ request, browser }) => {
  const response = await api(request, 'login', { headers: { 'CF-Connecting-IP': crypto.randomUUID() }, data: { username: 'root', password: rootPassword } });
  expect(response.ok()).toBe(true);
  const guest = await browser.newContext({ baseURL: origin });
  const link = '/guest/null-link-' + crypto.randomUUID();
  try {
    await call(request, { symlink: { target: nullPath, path: link } });
    for (const [mode, allowed] of [[0o222, 1], [0o444, 0], [0o666, 2]]) {
      await call(request, { chmod: { path: nullPath, mode } });
      const opened = await call(guest.request, { open: { path: link, flags: allowed } });
      expect(opened.device).toBe('null');
      await call(guest.request, { close: { fd: opened.fd } });
      if (mode !== 0o666) expect(await errno(guest.request, { open: { path: link, flags: 2 } })).toBe('EACCES');
    }
    await call(request, { chmod: { path: nullPath, mode: 0o600 } });
    expect(await errno(guest.request, { open: { path: link, flags: 0 } })).toBe('EACCES');
    expect(await errno(guest.request, { pread: { path: link, count: 10 } })).toBe('EACCES');
    expect((await guest.request.get(file(link))).ok()).toBe(false);
  } finally {
    await call(request, { chmod: { path: nullPath, mode: 0o666 } });
    await rmrf(request, link);
    await guest.close();
  }
});

test('installed WASI tools read EOF and discard streamed output without uploading it', async ({ page }) => {
  await page.goto('/');
  const uploads = [];
  page.on('request', request => { if (new URL(request.url()).pathname === '/api/pwrite') uploads.push(request.url()); });
  await run(page, 'cat /dev/null | wc -c');
  await expect(last(page)).toHaveText('0');
  await run(page, 'seq 1 200000 | tee /dev/null | tail -n 1');
  await expect(last(page)).toHaveText('200000');
  await run(page, 'printf append | tee -a /dev/null | wc -c');
  await expect(last(page)).toHaveText('6');
  expect(uploads).toEqual([]);
  expect((await call(page.request, { stat: { path: nullPath } })).size).toBe(0);
});

test('dash background stdin and inherited null redirections use the device', async ({ page }) => {
  await page.goto('/');
  await run(page, `sh -c 'cat </dev/null; printf "foreground:%s" "$?"'`);
  await expect(last(page)).toHaveText('foreground:0');
  await run(page, `sh -c '(cat && printf background) & wait $!; printf ":%s" "$?"'`);
  await expect(last(page)).toHaveText('background:0');
  await run(page, `sh -c 'exec 3<>/dev/null; printf hidden >&3; cat <&3; printf "done:%s" "$?"'`);
  await expect(last(page)).toHaveText('done:0');
});
