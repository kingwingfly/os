import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import http from 'node:http';
import { api, errno, listing, mkdirp, put, rmrf, sys } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
async function root() {
  const client = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'storage-' + Date.now() } });
  expect((await api(client, 'login', { data: { username: 'root', password: rootPassword } })).status()).toBe(200);
  return client;
}
// pwrite(2) of chunk 0 through the descriptor `fd`, its body arriving slowly, in `parts` pieces
// `delay` ms apart, as a slow page writes one.
function slowWrite(fd, cookie, parts, delay) {
  const url = new URL(`/api/pwrite?fd=${fd}&index=0`, origin);
  const piece = Buffer.alloc(64 * 1024, 'x');
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: 'PUT', headers: { Origin: origin, Cookie: cookie, 'Content-Length': piece.length * parts } }, res => {
      let body = ''; res.on('data', d => body += d); res.on('end', () => resolve({ status: res.statusCode, body, at: Date.now() }));
    });
    req.on('error', reject);
    let sent = 0;
    const next = () => { req.write(piece); if (++sent === parts) req.end(); else setTimeout(next, delay); };
    next();
  });
}
const O_WRONLY = 0o1, O_CREAT = 0o100, O_EXCL = 0o200, O_TRUNC = 0o1000;
// open(2) of `path` to write `size` bytes, as `client`: its result.
async function open(client, path, size, flags = O_WRONLY | O_CREAT | O_EXCL, version) {
  return (await sys(client, [{ open: { path, flags, mode: 0o666, size, ...(version ? { version } : {}) } }]))[0];
}
const close = async (client, fd) => (await sys(client, [{ close: { fd } }]))[0];
const cookieOf = async client => (await client.storageState()).cookies.map(c => `${c.name}=${c.value}`).join('; ');

test('a slow write blocks neither listings nor downloads of other files, and its own download waits for it', async () => {
  const admin = await root(), other = await root();
  const base = '/storage-' + Date.now().toString(36);
  try {
    await mkdirp(admin, base);
    expect((await put(admin, file(base + '/ready.txt'), { data: 'already here' })).status()).toBe(201);
    const { fd } = (await open(admin, base + '/slow.bin', 20 * 64 * 1024)).ok;
    const started = Date.now();
    const writing = slowWrite(fd, await cookieOf(admin), 20, 150);
    await new Promise(r => setTimeout(r, 400));
    // While the chunk streams, other requests answer at once.
    const names = (await listing(other, base)).map(e => e.name); const listed = Date.now();
    expect(names).toEqual(expect.arrayContaining(['ready.txt', 'slow.bin']));
    const ready = await other.get(file(base + '/ready.txt')); const read = Date.now();
    expect(await ready.text()).toBe('already here');
    // An unfinished file says so, and a download of it follows the writing to its end.
    expect((await other.head(file(base + '/slow.bin'))).headers()['x-upload-state']).toBe('uploading');
    const following = other.get(file(base + '/slow.bin')).then(async r => ({ status: r.status(), length: (await r.body()).length, at: Date.now() }));
    const done = await writing;
    expect(done.status, done.body).toBe(200);
    expect(listed).toBeLessThan(done.at); expect(read).toBeLessThan(done.at);
    expect(done.at - started).toBeGreaterThan(2500);
    expect((await close(admin, fd)).ok).toMatchObject({ size: 20 * 64 * 1024, created: true });
    const complete = await following;
    expect(complete).toMatchObject({ status: 200, length: 20 * 64 * 1024 });
    expect(complete.at).toBeGreaterThanOrEqual(done.at - 50);
    // Text may be compressed in transit; the declared length is still the file's.
    expect((await other.head(file(base + '/slow.bin'))).headers()['content-length']).toBe(String(20 * 64 * 1024));
  } finally {
    await rmrf(admin, base);
    await admin.dispose(); await other.dispose();
  }
});

test('an interrupted write commits nothing, and a file replaced shows what it had until closed', async () => {
  const admin = await root(), other = await root();
  const base = '/storage-' + Date.now().toString(36);
  try {
    await mkdirp(admin, base);
    const cookie = await cookieOf(admin);
    // Promise a chunk, send part of it, and hang up: nothing of it is there.
    const broken = (await open(admin, base + '/broken.bin', 1_000_000)).ok;
    await new Promise(resolve => {
      const req = http.request(new URL(`/api/pwrite?fd=${broken.fd}&index=0`, origin), { method: 'PUT', headers: { Origin: origin, Cookie: cookie, 'Content-Length': 1_000_000 } });
      req.on('error', () => resolve()); req.write(Buffer.alloc(1000)); setTimeout(() => { req.destroy(); resolve(); }, 300);
    });
    await new Promise(r => setTimeout(r, 500));
    expect((await listing(other, base)).map(e => [e.name, e.uploaded])).toEqual([['broken.bin', 0]]);
    // Closed unfinished, it waits for a writer to go on with it; removed, it is gone.
    expect((await close(admin, broken.fd)).err.errno).toBe('EIO');
    expect(await errno(admin, { unlink: { path: base + '/broken.bin' } })).toBe(null);
    expect(await listing(other, base)).toEqual([]);
    expect((await put(admin, file(base + '/a.txt'), { data: 'old' })).status()).toBe(201);
    // O_EXCL refuses a name there, before any byte is written.
    expect((await open(admin, base + '/a.txt', 3)).err.errno).toBe('EEXIST');
    const etag = (await other.head(file(base + '/a.txt'))).headers().etag;
    // Replaced, only if it is still the version read, it shows what it had until closed.
    const { fd } = (await open(admin, base + '/a.txt', 6, O_WRONLY | O_TRUNC, etag)).ok;
    const replacing = new Promise((resolve, reject) => {
      const req = http.request(new URL(`/api/pwrite?fd=${fd}&index=0`, origin), { method: 'PUT', headers: { Origin: origin, Cookie: cookie, 'Content-Length': 6 } }, res => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', reject); req.write('new'); setTimeout(() => { req.end('!!!'); }, 600);
    });
    await new Promise(r => setTimeout(r, 300));
    expect(await (await other.get(file(base + '/a.txt'))).text()).toBe('old');
    expect(await replacing).toBe(200);
    expect(await (await other.get(file(base + '/a.txt'))).text()).toBe('old');
    const closed = (await close(admin, fd)).ok;
    expect(closed.size).toBe(6); expect(closed.created).toBeFalsy();
    expect(await (await other.get(file(base + '/a.txt'))).text()).toBe('new!!!');
    expect((await other.head(file(base + '/a.txt'))).headers().etag).not.toBe(etag);
    // The version read before is not the one there now.
    expect((await open(admin, base + '/a.txt', 1, O_WRONLY | O_TRUNC, etag)).err.errno).toBe('ESTALE');
  } finally {
    await rmrf(admin, base);
    await admin.dispose(); await other.dispose();
  }
});
