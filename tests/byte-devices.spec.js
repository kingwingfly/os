import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call, errno, put, rmrf } from './sys.js';

const names = ['zero', 'full', 'random', 'urandom'];
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const file = path => '/api/file?path=' + encodeURIComponent(path);
const prompt = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function run(page, command) {
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
  await page.locator('#command').fill(command); await page.locator('#command').press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}
function checkBytes(name, data, length) {
  expect(data).toHaveLength(length);
  if (name === 'zero' || name === 'full') expect(data.equals(Buffer.alloc(length))).toBe(true);
  // This catches constant/empty output; it does not prove cryptographic quality.
  else if (length > 32) expect(new Set(data).size).toBeGreaterThan(32);
}

test('byte devices preserve metadata and enforce access modes through both write APIs', async ({ request }) => {
  for (const name of names) {
    const path = '/dev/' + name, before = await call(request, { stat: { path } });
    expect(before).toMatchObject({ mode: 0o020666, rdev: name, size: 0 });
    checkBytes(name, Buffer.from((await call(request, { pread: { path, offset: 999999, count: 70001 } })).data, 'base64'), 70001);
    for (const flags of [0, 1, 2]) {
      const opened = await call(request, { open: { path, flags } });
      expect(opened.device).toBe(name);
      const fd = opened.fd;
      try {
        if (flags === 1) expect(await errno(request, { pread: { fd, count: 1 } })).toBe('EBADF');
        else {
          const read = await call(request, { pread: { fd, offset: 987654, count: 70001 } });
          checkBytes(name, Buffer.from(read.data, 'base64'), 70001); expect(read.size).toBe(0);
          expect(await call(request, { pread: { fd, count: 0 } })).toEqual({ data: '', size: 0 });
          expect(await errno(request, { pread: { fd, count: 262145 } })).toBe('EINVAL');
        }
        for (const data of [Buffer.alloc(0), Buffer.from([0, 255, 13])]) {
          const error = flags === 0 ? 'EBADF' : name === 'full' ? 'ENOSPC' : null;
          const write = { pwrite: { fd, index: 123, data: data.toString('base64') } };
          if (error) expect(await errno(request, write)).toBe(error);
          else expect(await call(request, write)).toEqual({ written: data.length });
          const response = await request.put(`/api/pwrite?fd=${fd}&index=123`, { headers: { Origin: origin, 'Content-Type': 'application/octet-stream' }, data });
          if (error) expect((await response.json()).errno).toBe(error);
          else { expect(response.ok()).toBe(true); expect(await response.json()).toEqual({ written: data.length }); }
        }
        expect(await errno(request, { ioctl: { fd, request: 0x80045200 } })).toBe('ENOTTY');
      } finally { await call(request, { close: { fd } }); }
      expect(await errno(request, { pread: { fd, count: 1 } })).toBe('EBADF');
    }
    expect(await call(request, { stat: { path } })).toEqual(before);
  }
});

test('device permissions authorize symlinks and HTTP ranges before any bytes or metadata escape', async ({ request, browser }) => {
  const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': crypto.randomUUID() }, data: { username: 'root', password } })).ok()).toBe(true);
  const guest = await browser.newContext({ baseURL: origin }), foreign = await browser.newContext({ baseURL: origin });
  const link = '/guest/byte-device-' + crypto.randomUUID();
  try {
    for (const name of names) {
      const path = '/dev/' + name;
      await call(request, { symlink: { path: link, target: path } });
      const opened = await call(guest.request, { open: { path: link, flags: 0 } });
      try {
        expect(opened.device).toBe(name);
        expect(await errno(foreign.request, { pread: { fd: opened.fd, count: 1 } })).toBe('EBADF');
        for (const mode of [0o222, 0o444]) {
          await call(request, { chmod: { path, mode } });
          expect(await errno(guest.request, { open: { path: link, flags: 2 } })).toBe('EACCES');
        }
        await call(request, { chmod: { path, mode: 0o600 } });
        expect(await errno(guest.request, { open: { path: link, flags: 0 } })).toBe('EACCES');
        expect(await errno(guest.request, { pread: { path: link, count: 10 } })).toBe('EACCES');
        for (const method of ['get', 'head']) {
          const response = await guest.request[method](file(link), { headers: { Range: 'bytes=0-63', 'If-None-Match': '*' } });
          expect(response.status()).toBe(401);
        }
        checkBytes(name, Buffer.from((await call(guest.request, { pread: { fd: opened.fd, count: 64 } })).data, 'base64'), 64);
      } finally {
        await call(guest.request, { close: { fd: opened.fd } });
        await call(request, { chmod: { path, mode: 0o666 } });
        await rmrf(request, link);
      }
    }
  } finally { await guest.close(); await foreign.close(); }
});

test('HTTP device reads are bounded, non-cacheable and fresh across cryptographic reads', async ({ request }) => {
  for (const name of names) {
    const url = file('/dev/' + name);
    expect((await request.get(url)).status()).toBe(400);
    expect((await request.head(url)).status()).toBe(200);
    for (const range of ['bytes=+1-+2', 'bytes=0-', 'bytes=-20', 'bytes=3-2', 'bytes=0-262144', 'bytes=0-1,2-3']) expect((await request.get(url, { headers: { Range: range } })).status()).toBe(416);
    const first = await request.get(url, { headers: { Range: 'bytes=99-70099', 'If-None-Match': '*' } });
    expect(first.status()).toBe(206); expect(first.headers()['content-range']).toBe('bytes 99-70099/*');
    expect(first.headers()['cache-control']).toContain('no-store'); expect(first.headers().etag).toBeUndefined();
    const bytes = await first.body(); checkBytes(name, bytes, 70001);
    const head = await request.head(url, { headers: { Range: 'bytes=99-70099' } });
    expect(head.status()).toBe(206); expect(head.headers()['content-length']).toBe('70001'); expect(await head.body()).toHaveLength(0);
    if (name.endsWith('random')) expect((await (await request.get(url, { headers: { Range: 'bytes=99-70099' } })).body()).equals(bytes)).toBe(false);
  }
});

test('installed tools use byte devices locally, report full writes and inherit them through dash', async ({ page }) => {
  await page.goto('/');
  const uploads = [];
  page.on('request', request => { if (new URL(request.url()).pathname === '/api/pwrite') uploads.push(request.url()); });
  for (const name of names) {
    await run(page, `head -c 70001 /dev/${name} | wc -c`); await expect(last(page)).toHaveText('70001');
  }
  for (const name of ['zero', 'random', 'urandom']) {
    await run(page, `seq 1 10000 | tee -a /dev/${name} | tail -n 1`); await expect(last(page)).toHaveText('10000');
  }
  await run(page, `sh -c 'printf bad >/dev/full; printf "status:%s" "$?"'`);
  // Dash's builtin deliberately reports a generic I/O error; the WASI probe
  // below checks the exact ENOSPC code independently of program wording.
  await expect(last(page)).toContainText('I/O error'); await expect(last(page)).toContainText('status:1');
  await run(page, `sh -c '/usr/bin/printf bad | tee /dev/full; printf ":status:%s" "$?"'`);
  await expect(last(page)).toContainText('/dev/full'); await expect(last(page)).toContainText('status:1');
  await run(page, `sh -c 'exec 3<>/dev/zero; (head -c 17 <&3 | wc -c); head -c 23 <&3 | wc -c'`);
  await expect(last(page)).toHaveText('17\n23');
  expect(uploads).toEqual([]);
});

for (const name of ['zero', 'urandom']) test(`continuous ${name} reads remain interruptible without terminal output`, async ({ page }) => {
  await page.goto('/');
  await page.locator('#command').fill(`sh -c 'cat /dev/${name} >/dev/null'`); await page.locator('#command').press('Enter');
  await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).some(p => p.argv.includes('/dev/' + name))).toBe(true);
  await page.locator('#command').press('Control+c');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).filter(p => p.pid !== 1).length).toBe(0);
  await run(page, 'printf recovered'); await expect(last(page)).toHaveText('recovered');
});

test('WASI devices report character type, ignore seek offsets and retain I/O errors', async ({ page }) => {
  await page.goto('/');
  const path = '/guest/device-probe-' + crypto.randomUUID() + '.wasm';
  const module = binaryen.parseText(`(module
    (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_pread" (func $pread (param i32 i32 i32 i64 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_pwrite" (func $pwrite (param i32 i32 i32 i64 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_seek" (func $seek (param i32 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_tell" (func $tell (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_filestat_set_size" (func $truncate (param i32 i64) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
    (memory (export "memory") 3)
    ${names.map((name, index) => `(data (i32.const ${1024 + index * 32}) "/dev/${name}")`).join('\n')}
    (data (i32.const 1200) "device-ok")
    (func $assert (param i32) (if (i32.eqz (local.get 0)) (then unreachable)))
    (func $probe (param $path i32) (param $length i32) (param $write_error i32) (local $fd i32)
      (call $assert (i32.eqz (call $open (i32.const 3) (i32.const 1) (local.get $path) (local.get $length) (i32.const 0) (i64.const -1) (i64.const -1) (i32.const 0) (i32.const 100))))
      (local.set $fd (i32.load (i32.const 100)))
      (call $assert (i32.eqz (call $stat (local.get $fd) (i32.const 200))))
      (call $assert (i32.eq (i32.load8_u (i32.const 200)) (i32.const 2)))
      (i32.store (i32.const 32) (i32.const 4096)) (i32.store (i32.const 36) (i32.const 70001))
      (call $assert (i32.eqz (call $read (local.get $fd) (i32.const 32) (i32.const 1) (i32.const 64))))
      (call $assert (i32.eq (i32.load (i32.const 64)) (i32.const 70001)))
      (call $assert (i32.eqz (call $tell (local.get $fd) (i32.const 80))))
      (call $assert (i64.eqz (i64.load (i32.const 80))))
      (call $assert (i32.eqz (call $seek (local.get $fd) (i64.const -99) (i32.const 0) (i32.const 80))))
      (call $assert (i64.eqz (i64.load (i32.const 80))))
      (call $assert (i32.eqz (call $pread (local.get $fd) (i32.const 32) (i32.const 1) (i64.const 999999) (i32.const 64))))
      (call $assert (i32.eq (i32.load (i32.const 64)) (i32.const 70001)))
      (call $assert (i32.eq (call $write (local.get $fd) (i32.const 32) (i32.const 1) (i32.const 64)) (local.get $write_error)))
      (call $assert (i32.eq (call $pwrite (local.get $fd) (i32.const 32) (i32.const 1) (i64.const 77) (i32.const 64)) (local.get $write_error)))
      (i32.store (i32.const 36) (i32.const 0))
      (call $assert (i32.eq (call $write (local.get $fd) (i32.const 32) (i32.const 1) (i32.const 64)) (local.get $write_error)))
      (call $assert (i32.eq (call $truncate (local.get $fd) (i64.const 16)) (i32.const 28)))
      (call $assert (i32.eqz (call $close (local.get $fd))))
      (call $assert (i32.eq (call $read (local.get $fd) (i32.const 32) (i32.const 1) (i32.const 64)) (i32.const 8))))
    (func (export "_start")
      ${names.map((name, index) => `(call $probe (i32.const ${1024 + index * 32}) (i32.const ${('/dev/' + name).length}) (i32.const ${name === 'full' ? 51 : 0}))`).join('\n')}
      (i32.store (i32.const 32) (i32.const 1200)) (i32.store (i32.const 36) (i32.const 9))
      (drop (call $write (i32.const 1) (i32.const 32) (i32.const 1) (i32.const 64)))))`);
  try {
    expect((await put(page.request, file(path), { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true);
    await call(page.request, { chmod: { path, mode: 0o755 } });
    await run(page, path); await expect(last(page)).toHaveText('device-ok');
  } finally { module.dispose(); await rmrf(page.request, path); }
});
