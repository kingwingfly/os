import { test, expect } from './storage-test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, sys } from './sys.js';

const coreutils = await readFile('dist/usr/bin/coreutils.wasm');
const dash = await readFile('dist/usr/bin/dash.wasm');
const assemble = wat => { const module = binaryen.parseText(wat); try { return [...module.emitBinary()]; } finally { module.dispose(); } };
const hello = word => assemble(`(module
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 32) "${word}")
  (func (export "_start") (i32.store (i32.const 0) (i32.const 32)) (i32.store (i32.const 4) (i32.const ${word.length}))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);

async function ready(page) {
  await page.goto('/');
  await page.waitForFunction(() => window.os?.exec);
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle');
}
async function storage(page, { cloud = false } = {}) {
  await page.evaluate(() => { void window.os.localMounts(); });
  const dialog = page.locator('#window-mounts');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('tab', { name: 'Add mount', exact: true }).click();
  await dialog.locator('[name=kind]').selectOption('storage');
  await dialog.locator('[data-add-form] [name=writable]').check();
  if (cloud) await dialog.locator('[name=cloud]').check();
  await dialog.getByRole('button', { name: 'Mount storage', exact: true }).click();
  await expect(dialog.locator('[data-selected]')).toHaveText('/mnt/local/project');
  await dialog.getByRole('button', { name: 'Close Mounts', exact: true }).click();
  await expect(dialog).toBeHidden();
}
async function write(page, name, bytes) {
  await page.evaluate(async ({ name, bytes }) => {
    const root = await navigator.storage.getDirectory(), dir = await root.getDirectoryHandle('os-workspace', { create: true });
    const file = await dir.getFileHandle(name, { create: true }), stream = await file.createWritable();
    await stream.write(Uint8Array.from(atob(bytes), c => c.charCodeAt(0))); await stream.close();
  }, { name, bytes: Buffer.from(bytes).toString('base64') });
}
async function run(page, name, argv = [], options = {}) {
  return page.evaluate(async ({ name, argv, options }) => {
    let error = '';
    const result = await window.os.exec([{ path: name, argv: [name, ...argv] }], { cwd: '/mnt/local/project', stdin: '', onOutput: (fd, text) => { if (fd === 2) error += text; }, ...options });
    return { ...result, error };
  }, { name, argv, options });
}

test('login shutdown invalidates private mount access', async ({ page }) => {
  await ready(page); await storage(page); await write(page, 'private', new TextEncoder().encode('SESSION_PRIVATE'));
  const read = () => page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/project/private')).status);
  expect(await read()).toBe(200);
  await page.evaluate(async () => window.os.endLoginSession((await window.os.loginSession()).session));
  await expect.poll(read).not.toBe(200);
  await expect(page.evaluate(() => window.os.localMountList())).rejects.toThrow(/unavailable/);
});

test('an account change cannot reuse the previous account private namespace', async ({ page }) => {
  await ready(page); await storage(page); await write(page, 'private', new TextEncoder().encode('ACCOUNT_PRIVATE'));
  const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
  expect((await api(page.request, 'login', { headers: { 'CF-Connecting-IP': 'local-account-' + Date.now() }, data: { username: 'root', password } })).ok()).toBe(true);
  expect(await page.evaluate(async () => (await fetch('/api/file?path=/mnt/local/project/private')).status)).not.toBe(200);
  // Fresh inspection may find a new empty workspace or require joining the new
  // login scope first; neither state can expose the old account's mount.
  const mounts = await page.evaluate(() => window.os.localMountList().catch(error => ({ denied: error.message })));
  expect(Array.isArray(mounts) ? mounts.length === 0 : /unavailable/.test(mounts.denied)).toBe(true);
});

test('live local edit/run and detach use the real process host without uploading executable bytes', async ({ page, context }) => {
  test.setTimeout(180000);
  const uploaded = [];
  context.on('request', request => {
    const body = request.postDataBuffer();
    if (body && (body.includes(Buffer.from(hello('LOCAL_ONE'))) || body.includes(Buffer.from(hello('LOCAL_TWO'))))) uploaded.push(request.url());
  });
  await ready(page); await storage(page);
  await write(page, 'hello', hello('LOCAL_ONE'));
  expect(await run(page, './hello')).toMatchObject({ status: 0, stdout: 'LOCAL_ONE', error: '' });
  await write(page, 'hello', hello('LOCAL_TWO'));
  expect(await run(page, './hello')).toMatchObject({ status: 0, stdout: 'LOCAL_TWO', error: '' });
  expect(uploaded).toEqual([]);
  const listing = await page.evaluate(async () => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [{ getdents: { path: '/mnt/local/project' } }] }) })).json()).results);
  expect(listing[0].ok.map(entry => entry.name)).toContain('hello');
  await page.evaluate(() => { void window.os.localMounts(); });
  await page.getByRole('button', { name: 'Unmount', exact: true }).click();
  await expect(page.locator('#window-mounts [data-empty]')).toBeVisible();
  await page.locator('#window-mounts').getByRole('button', { name: 'Close Mounts', exact: true }).click();
  await expect(run(page, './hello')).rejects.toThrow(/detached|ENODEV|No such/i);
});

test('ordinary utilities read and write the local VFS and Files previews use the same mount', async ({ page }) => {
  test.setTimeout(180000);
  await ready(page); await storage(page);
  await write(page, 'coreutils', coreutils); await write(page, 'input', Buffer.from('private text\n'));
  expect(await run(page, './coreutils', ['cat', 'input'])).toMatchObject({ status: 0, stdout: 'private text\n', error: '' });
  expect(await run(page, './coreutils', ['ls', '-1'])).toMatchObject({ status: 0, error: '' });
  expect(await run(page, './coreutils', ['mkdir', 'child'])).toMatchObject({ status: 0, error: '' });
  const checked = await run(page, './coreutils', ['syscall', JSON.stringify(['getcreds', { stat: { path: '/usr/bin/coreutils' } }])]);
  const replies = JSON.parse(checked.stdout).results; expect(replies[0].ok).toBeTruthy(); expect(replies[1].err.errno).toBe('EACCES');
  await write(page, 'dash', dash);
  expect(await run(page, './dash', ['-c', './coreutils cat input; ./coreutils echo CHILD_DONE'])).toMatchObject({ status: 0, stdout: 'private text\nCHILD_DONE\n', error: '' });
  expect(await run(page, './dash', ['-c', 'printf written > output; ./coreutils cat output'])).toMatchObject({ status: 0, stdout: 'written', error: '' });
  const read = await page.evaluate(async () => {
    const result = await fetch('/api/file?path=' + encodeURIComponent('/mnt/local/project/input'));
    return { status: result.status, text: await result.text() };
  });
  expect(read).toEqual({ status: 200, text: 'private text\n' });
});

test('a private namespace is absent from a second host and native images fail explicitly', async ({ page, context }) => {
  await ready(page); await storage(page); await write(page, 'native', Buffer.from('\x7fELFnot-wasm'));
  const other = await context.newPage(); await ready(other);
  const hidden = await other.evaluate(async () => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [{ stat: { path: '/mnt/local/project/native' } }] }) })).json()).results);
  expect(hidden[0].err.errno).toBe('ENOENT');
  await page.evaluate(async () => fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [{ chmod: { path: '/mnt/local/project/native', mode: 0o700 } }] }) }));
  await expect(run(page, './native')).rejects.toThrow(/executable|format|wasm|magic|ENOEXEC/i);
  await other.close();
});

test('local code requires explicit matching authority admission before any guest instructions', async ({ page, context }) => {
  await ready(page); await storage(page); await write(page, 'probe', hello('MUST_NOT_RUN'));
  let variant, admitted;
  await context.route('**/api/sys', async route => {
    const body = route.request().postDataJSON();
    if (!body.calls?.some(call => call.execve?.local)) return route.fallback();
    const response = await route.fetch(), answer = await response.json();
    for (const result of answer.results) if (result.ok?.local) {
      admitted = result.ok.pid;
      if (variant === 'missing') delete result.ok.local;
      if (variant === 'cloud') result.ok.local.cloud = true;
      if (variant === 'digest') result.ok.local.digest = '0'.repeat(64);
      if (variant === 'asset') result.ok.asset = '/usr/bin/true';
    }
    await route.fulfill({ response, json: answer });
  });
  for (variant of ['missing', 'cloud', 'digest', 'asset']) {
    admitted = null;
    const result = await page.evaluate(async () => {
      let stdout = '';
      try {
        await window.os.exec([{ path: './probe', argv: ['./probe'] }], {
          cwd: '/mnt/local/project', stdin: '',
          onOutput: (fd, text) => { if (fd === 1) stdout += text; },
        });
        return { rejected: false, stdout };
      } catch (error) { return { rejected: true, stdout, error: error.message }; }
    });
    expect(admitted).toBeTruthy(); expect(result.rejected).toBe(true); expect(result.stdout).toBe('');
    expect(result.error).toMatch(/authority.*local execution/i);
    expect((await sys(page.request, [{ stat: { path: '/proc/' + admitted } }]))[0].err.errno).toBe('ENOENT');
  }
});
