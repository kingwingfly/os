import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { api, call, descriptors, errno, listing, mkdirp, rmrf, sys } from './sys.js';
// The Files go to `path` of their own: its location typed (files.rs).
async function browse(page, path) {
  const location = page.getByRole('textbox', { name: 'Location' });
  await location.fill(path); await location.press('Enter');
  await expect(location).toHaveValue(path);
}
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const CHUNK = 8 * 1024 * 1024;
const file = path => '/api/file?path=' + encodeURIComponent(path);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
let sequence = 0;
async function root() {
  const client = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'uploads-' + Date.now() + '-' + (++sequence) } });
  expect((await api(client, 'login', { data: { username: 'root', password: rootPassword } })).status()).toBe(200);
  return client;
}
// Two and a half chunks of bytes that differ by position, so that a misplaced chunk shows.
function content() {
  const bytes = Buffer.alloc(CHUNK * 2 + CHUNK / 2);
  for (let i = 0; i < bytes.length; i += 4) bytes.writeUInt32LE(i, i);
  return bytes;
}
const slices = bytes => Array.from({ length: Math.ceil(bytes.length / CHUNK) }, (_, i) => bytes.subarray(i * CHUNK, (i + 1) * CHUNK));
// pwrite(2) of chunk `index` through the descriptor `fd`, which R2 checks against its SHA-256.
async function chunk(client, fd, index, bytes, sha = sha256(bytes)) {
  return client.put(`/api/pwrite?fd=${fd}&index=${index}`, { headers: { 'X-Chunk-SHA256': sha, 'Content-Type': 'application/octet-stream' }, data: bytes });
}
const O_WRONLY = 0o1, O_CREAT = 0o100;
async function login(page) {
  await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'uploads-ui-' + Date.now() });
  await page.goto('/');
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  await input.fill('su root'); await input.press('Enter');
  await expect(page.locator('#auth')).toBeVisible();
  await page.getByLabel('Password', { exact: true }).fill(rootPassword); await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('.busy')).toHaveText('↵');
  return input;
}

test('a file is written in chunks through a descriptor, each checked, readable as it arrives, gone on with elsewhere', async () => {
  const admin = await root(), reader = await root(), other = await root();
  const base = '/uploads-' + Date.now().toString(36), path = base + '/data.bin';
  const bytes = content(), parts = slices(bytes);
  const open = async client => (await sys(client, [{ open: { path, flags: O_WRONLY | O_CREAT, mode: 0o666, size: bytes.length, sha256: sha256(bytes) } }]))[0];
  const close = async (client, fd) => (await sys(client, [{ close: { fd } }]))[0];
  try {
    await mkdirp(admin, base);
    const opened = await open(admin);
    expect(opened.ok).toMatchObject({ created: true, chunk_size: CHUNK });
    const fd = opened.ok.fd;
    // A wrong checksum or length is refused, and nothing is committed.
    expect((await chunk(admin, fd, 0, parts[0], sha256(parts[1]))).status()).toBe(400);
    expect((await chunk(admin, fd, 2, parts[1])).status()).toBe(400);
    expect((await chunk(admin, fd, 3, parts[0])).status()).toBe(400);
    expect((await chunk(admin, fd, 0, parts[0])).status()).toBe(200);
    // A chunk is committed once: sending it again is harmless, other content is refused.
    expect((await chunk(admin, fd, 0, parts[0])).status()).toBe(200);
    expect((await chunk(admin, fd, 0, parts[1])).status()).toBe(409);
    // A descriptor is its session's: another's of the same number is not it.
    const foreign = await chunk(other, fd, 1, parts[1]);
    expect([foreign.status(), (await foreign.json()).errno]).toEqual([409, 'EBADF']);
    // The session lists what it writes, with what has arrived.
    expect(await descriptors(admin)).toEqual([expect.objectContaining({ fd, path, size: bytes.length, received: CHUNK, created: true })]);
    // The file is listed while it is written, with what has arrived so far.
    const entry = (await listing(reader, base))[0];
    expect(entry.name).toBe('data.bin'); expect(entry.uploaded).toBe(CHUNK);
    const head = await reader.head(file(path));
    expect(head.headers()['x-upload-state']).toBe('uploading');
    expect(head.headers()['content-length']).toBe(String(bytes.length));
    // A range of what has arrived is served at once ...
    const first = await reader.get(file(path), { headers: { Range: 'bytes=0-15' } });
    expect(first.status()).toBe(206); expect(Buffer.compare(await first.body(), bytes.subarray(0, 16))).toBe(0);
    // ... and a whole download follows the file as it is written.
    const whole = reader.get(file(path), { headers: { 'Accept-Encoding': 'identity' }, timeout: 60_000 });
    await new Promise(r => setTimeout(r, 1500));
    // One descriptor writes a file at a time: while its session is heard from (any batch keeps
    // its descriptors), the same file opened in another session is refused.
    await sys(admin, []);
    const refused = await open(other);
    expect(refused.err.errno).toBe('EBUSY'); expect(refused.err.detail).toContain('another tab or device');
    // Closed, as a page closes it when it goes, the file waits unfinished (EIO), and another
    // session goes on with it; the closed descriptor writes no more.
    expect((await close(admin, fd)).err.errno).toBe('EIO');
    const again = (await open(other)).ok;
    expect(again).toMatchObject({ resumed: true, committed: [0] });
    const stopped = await chunk(admin, fd, 2, parts[2]);
    expect([stopped.status(), (await stopped.json()).errno]).toEqual([409, 'EBADF']);
    expect((await chunk(other, again.fd, 2, parts[2])).status()).toBe(200);
    // Progress counts every chunk that arrived, as the writing page does, not only those
    // readable from the start.
    expect((await listing(reader, base))[0].uploaded).toBe(CHUNK + parts[2].length);
    // Closed with a chunk missing, it waits again; opened again, it goes on with what is there.
    expect((await close(other, again.fd)).err.errno).toBe('EIO');
    const last = (await open(other)).ok;
    expect(last.committed).toEqual([0, 2]);
    expect((await chunk(other, last.fd, 1, parts[1])).status()).toBe(200);
    // A chunk sent while the file completes never changes the completed file.
    const late = chunk(other, last.fd, 1, parts[0]);
    await new Promise(r => setTimeout(r, 50));
    expect((await close(other, last.fd)).ok).toMatchObject({ path, size: bytes.length, created: true });
    expect((await late).status()).toBe(409);
    const downloaded = await whole;
    expect(downloaded.status()).toBe(200);
    expect(Buffer.compare(await downloaded.body(), bytes)).toBe(0);
    expect(Buffer.compare(await (await reader.get(file(path), { headers: { 'Accept-Encoding': 'identity' } })).body(), bytes)).toBe(0);
    expect((await reader.head(file(path))).headers()['x-upload-state']).toBeUndefined();
    expect(await descriptors(other)).toEqual([]);
    // A file being made goes once removed, from any session that may remove it, and its
    // descriptor writes no more.
    const gone = (await sys(admin, [{ open: { path: base + '/gone.bin', flags: O_WRONLY | O_CREAT, mode: 0o666, size: 10 } }]))[0].ok;
    expect(await errno(other, { unlink: { path: base + '/gone.bin' } })).toBe(null);
    expect((await chunk(admin, gone.fd, 0, Buffer.alloc(10))).status()).toBe(409);
    expect((await listing(reader, base)).map(e => e.name)).toEqual(['data.bin']);
  } finally {
    await rmrf(admin, base);
    await admin.dispose(); await reader.dispose(); await other.dispose();
  }
});

test('the browser resumes an interrupted upload from the chunks already sent, and Cancel removes a partial file', async ({ page }) => {
  const folder = '/browser-uploads-' + Date.now().toString(36);
  const input = await login(page);
  for (const command of ['mkdir ' + folder, 'cd ' + folder]) {
    await input.fill(command); await input.press('Enter'); await expect(page.locator('.busy')).toHaveText('↵');
  }
  await browse(page, folder);
  const bytes = content();
  const sent = [];
  // Drop the connection on the third chunk, until the client gives up after its retries.
  let offline = true;
  await page.route('**/api/pwrite?**', route => {
    const index = Number(new URL(route.request().url()).searchParams.get('index'));
    if (index === 2 && offline) return route.abort('connectionreset');
    sent.push(index); return route.continue();
  });
  // The Files' button uploads into their directory, once the upload before has ended.
  const prompt = () => expect(page.locator('.busy')).toHaveText('↵');
  const button = page.getByRole('button', { name: '↑ Upload files' });
  const choose = async () => { await expect(button).toBeEnabled(); const chooser = page.waitForEvent('filechooser'); await button.click(); await (await chooser).setFiles({ name: 'data.log', mimeType: 'application/octet-stream', buffer: bytes }); };
  await choose();
  // Progress and results show in the Files, not over the page, nor in the terminal.
  const progress = page.getByRole('status', { name: 'Upload progress' });
  await expect(progress).toContainText('choose the same file again to resume', { timeout: 30_000 });
  expect(sent.sort()).toEqual([0, 1]);
  offline = false;
  await expect(page.locator('.filename').filter({ hasText: 'data.log' })).toBeVisible();
  sent.length = 0;
  await choose();
  await expect(progress).toContainText('✓ data.log (resumed)', { timeout: 30_000 });
  expect(sent).toEqual([2]);
  const stored = await page.request.get(file(folder + '/data.log'), { headers: { 'Accept-Encoding': 'identity' } });
  expect(Buffer.compare(await stored.body(), bytes)).toBe(0);
  // Slow chunks down, and cancel during the upload.
  await page.unroute('**/api/pwrite?**');
  // A chunk Cancel stopped meanwhile is not sent on.
  await page.route('**/api/pwrite?**', async route => { await new Promise(r => setTimeout(r, 1500)); return route.continue().catch(() => {}); });
  await expect(button).toBeEnabled(); const chooser = page.waitForEvent('filechooser'); await button.click();
  await (await chooser).setFiles({ name: 'other.log', mimeType: 'application/octet-stream', buffer: bytes.subarray(0, CHUNK + 5) });
  await expect(progress).toContainText('↑ other.log', { timeout: 15_000 });
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(progress).toContainText('✕ other.log: Upload cancelled', { timeout: 15_000 });
  await expect.poll(async () => (await listing(page.request, folder)).map(e => e.name)).toEqual(['data.log']);
  await page.unroute('**/api/pwrite?**');
  // Any file uploads: media are served as such, what is neither text nor media as bytes.
  for (const [name, type] of [['tone.aac', 'audio/aac'], ['report.docx', 'application/octet-stream']]) {
    await expect(button).toBeEnabled(); const chooser = page.waitForEvent('filechooser'); await button.click();
    await (await chooser).setFiles({ name, mimeType: 'application/octet-stream', buffer: Buffer.from([0xFF, 0xF1, 0x50, 0x80, 0x00, 0x1F, 0xFC]) });
    await expect(progress).toContainText('✓ ' + name, { timeout: 15_000 });
    expect((await page.request.head(file(folder + '/' + name))).headers()['content-type']).toBe(type);
  }
  // In the terminal, a chooser the browser closes without saying so, or never opens, leaves
  // upload waiting until Ctrl+C, which gives it no files.
  await page.evaluate(() => { HTMLInputElement.prototype.click = function () {}; });
  await prompt();
  await input.fill('upload'); await input.press('Enter');
  await expect(page.locator('.busy')).toHaveText('Working...');
  await page.locator('#command').press('Control+c');
  await expect(page.locator('.busy')).toHaveText('↵');
  await rmrf(page.request, folder);
});
