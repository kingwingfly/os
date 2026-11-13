import { test, expect } from './test.js';
import { mkdtemp, mkdir, writeFile, readFile, rename, symlink, rm, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import binaryen from 'binaryen';
const adapter = process.env.OS_LOCAL_HELPER_BINARY || join(JSON.parse(execFileSync('cargo', ['metadata', '--no-deps', '--format-version=1'], { encoding: 'utf8' })).target_directory, 'debug/os-local-helper');
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const program = word => { const module = binaryen.parseText(`(module (import "wasi_snapshot_preview1" "fd_write" (func $w (param i32 i32 i32 i32) (result i32))) (memory (export "memory") 1) (data (i32.const 32) "${word}") (func (export "_start") (i32.store (i32.const 0) (i32.const 32)) (i32.store (i32.const 4) (i32.const ${word.length})) (drop (call $w (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`); try { return Buffer.from(module.emitBinary()); } finally { module.dispose(); } };
let base, root, helper, connection;
test.beforeEach(async ({ page }) => {
  base = await mkdtemp(join(tmpdir(), 'os-native-browser-')); root = base + '/root'; await mkdir(root); await mkdir(base + '/outside'); await writeFile(base + '/outside/secret', 'outside');
  helper = spawn(adapter, ['--root', root, '--origin', origin, '--write', '--execute'], { stdio: ['ignore', 'pipe', 'pipe'] });
  let errors = ''; helper.stderr.on('data', data => { errors += data; });
  connection = await new Promise((resolve, reject) => {
    const lines = createInterface({ input: helper.stdout }); const timer = setTimeout(() => reject(new Error('adapter startup timed out: ' + errors)), 5000);
    lines.once('line', line => { clearTimeout(timer); resolve(JSON.parse(line)); }); helper.once('exit', () => { clearTimeout(timer); reject(new Error('adapter exited: ' + errors)); });
  });
  await page.goto('/'); await page.waitForFunction(() => window.os?.mountLocal);
  await page.evaluate(connection => window.os.mountLocal({ name: 'native', url: connection.url, token: connection.token, writable: true, execute: true, cloud: false }), connection);
});
test.afterEach(async () => { helper?.kill('SIGTERM'); if (helper?.exitCode === null && helper?.signalCode === null) await new Promise(resolve => helper.once('exit', resolve)); if (base) await rm(base, { recursive: true, force: true }); });
const run = (page, path, argv = []) => page.evaluate(({ path, argv }) => window.os.exec([{ path, argv: [path, ...argv] }], { cwd: '/mnt/local/native', stdin: '' }), { path, argv });
const batch = (page, calls) => page.evaluate(async calls => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls }) })).json()).results, calls);

test('host build/edit/run uses the native directory without sending executable bytes to cloud', async ({ page, context }) => {
  const one = program('FIRST'), two = program('SECOND'), sent = [];
  context.on('request', request => { if (new URL(request.url()).origin !== origin) return; const body = request.postDataBuffer(); if (body && [one, two, Buffer.from(one.toString('base64')), Buffer.from(two.toString('base64'))].some(bytes => body.includes(bytes))) sent.push(request.url()); });
  await writeFile(root + '/program', one); expect(await run(page, './program')).toMatchObject({ status: 0, stdout: 'FIRST' });
  await writeFile(root + '/new-program', two); await rename(root + '/new-program', root + '/program');
  expect(await run(page, './program')).toMatchObject({ status: 0, stdout: 'SECOND' }); expect(sent).toEqual([]);
  helper.kill('SIGTERM'); await new Promise(resolve => helper.once('exit', resolve));
  await expect(run(page, './program')).rejects.toThrow(/offline|disconnected|ENODEV/);
});

test('native descriptors retain inodes across rebuilds and symlink paths cannot escape', async ({ page }) => {
  await writeFile(root + '/file', 'original'); await symlink('../outside', root + '/escape');
  const [opened] = await batch(page, [{ open: { path: '/mnt/local/native/file', flags: 2 } }]); expect(opened.err).toBeUndefined();
  await rename(root + '/file', root + '/old'); await writeFile(root + '/file', 'replacement');
  const answers = await batch(page, [{ pread: { fd: opened.ok.fd, count: 100 } }, { pwrite: { fd: opened.ok.fd, index: 0, data: Buffer.from('changed!').toString('base64') } }, { close: { fd: opened.ok.fd } }, { pread: { path: '/mnt/local/native/escape/secret', count: 100 } }]);
  expect(Buffer.from(answers[0].ok.data, 'base64').toString()).toBe('original'); expect(answers[1].err).toBeUndefined(); expect(answers[3].err.errno).toBe('ELOOP');
  expect(await readFile(root + '/file', 'utf8')).toBe('replacement'); expect(await readFile(root + '/old', 'utf8')).toBe('changed!'); expect(await readFile(base + '/outside/secret', 'utf8')).toBe('outside');
  const exclusive = await batch(page, [{ open: { path: '/mnt/local/native/file', flags: 0o301 } }]); expect(exclusive[0].err.errno).toBe('EEXIST');
  const retained = await batch(page, [{ open: { path: '/mnt/local/native/file' } }, { unlink: { path: '/mnt/local/native/file' } }, { pread: { fd: { ref: 0 }, count: 100 } }, { fchmod: { fd: { ref: 0 }, mode: 0o400 } }, { close: { fd: { ref: 0 } } }]);
  expect(retained[1].err).toBeUndefined(); expect(Buffer.from(retained[2].ok.data, 'base64').toString()).toBe('replacement'); expect(retained[3].err).toBeUndefined();
});

test('native WASIX fork/exec and redirected writes work through the generic VFS', async ({ page }) => {
  test.setTimeout(180000); await copyFile('dist/usr/bin/coreutils.wasm', root + '/coreutils'); await copyFile('dist/usr/bin/dash.wasm', root + '/dash');
  expect(await run(page, './dash', ['-c', 'printf first > output; printf second >> output; ./coreutils cat output'])).toMatchObject({ status: 0, stdout: 'firstsecond' });
  expect(await readFile(root + '/output', 'utf8')).toBe('firstsecond');
});

test('a streamed Files download retains its opened file across replacement', async ({ page }) => {
  await writeFile(root + '/large', Buffer.alloc(1024 * 1024, 65));
  expect(await page.evaluate(async () => {
    const response = await fetch('/api/file?path=/mnt/local/native/large');
    window.nativeReader = response.body.getReader();
    const first = await window.nativeReader.read(); return { length: first.value.length, byte: first.value[0] };
  })).toEqual({ length: 256 * 1024, byte: 65 });
  await rename(root + '/large', root + '/original'); await writeFile(root + '/large', Buffer.alloc(1024 * 1024, 66));
  const remainder = await page.evaluate(async () => {
    let count = 0, allOriginal = true;
    for (;;) { const { value, done } = await window.nativeReader.read(); if (done) break; count += value.length; allOriginal &&= value.every(byte => byte === 65); }
    return { count, allOriginal };
  });
  expect(remainder).toEqual({ count: 768 * 1024, allOriginal: true });
  expect(await page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/native/large', { headers: { Range: 'bytes=0-0' } })).text())).toBe('B');
});

test('Files previews and editor saves use a live native mount without uploading content', async ({ page }) => {
  const content = 'native edit\n'.repeat(30000);
  const leaked = []; page.on('request', request => { const url = new URL(request.url()); if (url.origin === origin && url.pathname === '/api/file' && url.searchParams.get('path')?.startsWith('/mnt/local/')) leaked.push(url.href); });
  await copyFile('tests/fixtures/pixel.png', root + '/pixel.png'); await writeFile(root + '/notes.txt', content); await writeFile(root + '/doc.md', '# Private\n\n![local](pixel.png)');
  const location = page.getByRole('textbox', { name: 'Location' }); await location.fill('/mnt/local/native'); await location.press('Enter');
  await page.locator('.files .file', { hasText: 'pixel.png' }).click();
  await expect.poll(() => page.locator('#viewer img[src^="blob:"]').first().evaluate(image => image.naturalWidth)).toBe(1);
  await page.getByRole('button', { name: 'Close preview' }).click();
  await page.locator('.files .file', { hasText: 'doc.md' }).click();
  await expect.poll(() => page.locator('#viewer .markdown img[alt=local]').evaluate(image => image.naturalWidth)).toBe(1);
  expect(leaked).toEqual([]); await page.getByRole('button', { name: 'Close preview' }).click();
  const input = page.locator('#command'); await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  await input.fill('vim /mnt/local/native/notes.txt'); await input.press('Enter');
  const editor = page.getByRole('textbox', { name: 'File contents' }); await expect(editor).toBeVisible();
  // Edit an existing large document; injecting 30,000 browser DOM lines with
  // locator.fill measures contenteditable insertion rather than editor/VFS I/O.
  await editor.press('Control+End'); await page.keyboard.insertText('updated'); await page.keyboard.press('Control+s');
  await expect(page.locator('#editor-status')).toHaveText('Saved'); expect(await readFile(root + '/notes.txt', 'utf8')).toBe(content + 'updated');
  await page.keyboard.press('Escape'); await expect(page.locator('#editor')).not.toBeVisible();
});

test('loopback origin and proof checks deny foreign sites and fake native connections', async ({ page, request }) => {
  const refused = await request.post(connection.url, { headers: { Origin: 'https://foreign.invalid', Authorization: 'Bearer ' + connection.token }, data: { op: 'mount', write: true, execute: true } }); expect(refused.status()).toBe(403);
  await expect(page.evaluate(connection => window.os.mountLocal({ name: 'forged', url: connection.url, token: '0'.repeat(64), cloud: false, execute: true }), connection)).rejects.toThrow(/EACCES/);
  await expect(page.evaluate(() => window.os.mountLocal({ name: 'remote', url: 'https://example.com/', token: '0'.repeat(64), cloud: false }))).rejects.toThrow(/loopback/);
});

test('a shared helper subtree denies symlinks and a held file moved outside the export', async ({ page, browser }) => {
  await mkdir(root + '/export'); await writeFile(root + '/export/text', 'PUBLIC'); await writeFile(root + '/secret', 'SECRET'); await symlink('../secret', root + '/export/link');
  const grant = await page.evaluate(() => window.os.shareMount({ path: '/mnt/local/native/export', name: 'subtree', password: 'subtree-password', seconds: 300 }, { p2p: false }));
  const context = await browser.newContext(), receiver = await context.newPage();
  try {
    await receiver.goto('/'); await receiver.waitForFunction(() => window.os?.attachShared);
    await receiver.evaluate(grant => window.os.attachShared({ address: grant.address, password: 'subtree-password', name: 'subtree', cloud: false }, { p2p: false }), grant);
    const [opened, link] = await batch(receiver, [{ open: { path: '/mnt/shared/subtree/text' } }, { open: { path: '/mnt/shared/subtree/link' } }]);
    expect(opened.ok.fd).toBeGreaterThan(0); expect(link.err.errno).toBe('ELOOP');
    await rename(root + '/export/text', root + '/moved'); await writeFile(root + '/export/text', 'REPLACEMENT');
    const [stale] = await batch(receiver, [{ pread: { fd: opened.ok.fd, count: 32 } }]); expect(stale.err.errno).toBe('ESTALE');
  } finally { await context.close(); }
});

test('an older helper cannot publish without the inode identity needed for revocation', async ({ page, context }) => {
  await context.route(connection.url, async route => {
    const response = await route.fetch(), value = await response.json();
    if (value.ok && typeof value.ok === 'object') delete value.ok.identity;
    await route.fulfill({ response, json: value });
  });
  await expect(page.evaluate(() => window.os.shareMount({ path: '/mnt/local/native', name: 'old-helper', password: '', seconds: 300 }))).rejects.toThrow(/Update os-local-helper/);
  expect((await page.evaluate(() => window.os.sharedMounts())).exports).toEqual([]);
});
