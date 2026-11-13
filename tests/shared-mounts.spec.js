import { test, expect } from './test.js';
import binaryen from 'binaryen';
const batch = (page, calls) => page.evaluate(async calls => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls }) })).json()).results, calls);
async function client(browser) {
  const context = await browser.newContext(), page = await context.newPage();
  await page.goto('/'); await page.waitForFunction(() => window.os?.shareMount);
  const [creds] = await batch(page, ['getcreds']);
  return { context, page, uid: creds.ok.uid };
}
async function dispose(...clients) { for (const client of clients) await client?.context.close(); }
async function write(page, path, text) {
  const results = await batch(page, [{ open: { path, flags: 0o1101 } }, { pwrite: { fd: { ref: 0 }, data: Buffer.from(text).toString('base64') } }, { close: { fd: { ref: 0 } } }]);
  expect(results.every(row => 'ok' in row)).toBe(true);
}
async function mount(page, writable = true) {
  await page.evaluate(writable => window.os.mountLocal({ name: 'source', storage: true, writable, execute: true, cloud: false }), writable);
  if (writable) await write(page, '/mnt/local/source/text', 'OWNER_PRIVATE_DATA');
}
const publish = (owner, options = {}) => owner.page.evaluate(options => window.os.shareMount({ path: '/mnt/local/source', name: 'project', seconds: 300, ...options }, { p2p: options.p2p ?? false }), options);
const attach = (target, grant, options = {}) => target.page.evaluate(({ grant, options }) => window.os.attachShared({ address: grant.address, name: 'project', cloud: false, ...options }, { p2p: options.p2p ?? false }), { grant, options });
const read = (page, name = 'project', file = 'text') => page.evaluate(async ({ name, file }) => { try { const response = await fetch('/api/file?path=' + encodeURIComponent('/mnt/shared/' + name + '/' + file)); return { status: response.status, text: await response.text() }; } catch (error) { return { status: 0, text: error.message }; } }, { name, file });
async function command(page, argv) {
  return page.evaluate(async argv => { let output = ''; const result = await window.os.exec([{ path: argv[0], argv }], { cwd: '/', stdin: '', onOutput: (_fd, text) => { output += text; } }); return { result, output: (result.stdout ?? '') + output }; }, argv);
}
async function allow(owner, target, path = '/mnt/local/source', recursive = true) {
  const result = await command(owner.page, ['setfacl', ...(recursive ? ['-R'] : []), '-m', `u:${target.uid}:rx`, path]);
  expect(result.output).toBe(''); expect(result.result.status).toBe(0);
}

test('distinct guest accounts use normal setfacl and explicitly mount a published address', async ({ browser }) => {
  test.setTimeout(180000); const owner = await client(browser), receiver = await client(browser), stranger = await client(browser);
  try {
    expect(owner.uid).not.toBe(receiver.uid); expect(receiver.uid).not.toBe(stranger.uid);
    await mount(owner.page); const grant = await publish(owner);
    expect(await receiver.page.evaluate(() => window.os.localMountList())).toEqual([]);
    expect(await receiver.page.evaluate(() => window.os.sharedMounts())).toMatchObject({ exports: [] });
    await expect(attach(receiver, grant)).rejects.toThrow();
    await allow(owner, receiver);
    await attach(receiver, grant);
    expect(await read(receiver.page)).toEqual({ status: 200, text: 'OWNER_PRIVATE_DATA' });
    await expect(attach(stranger, grant)).rejects.toThrow();
    const [stat] = await batch(receiver.page, [{ stat: { path: '/mnt/shared/project/text' } }]); expect(stat.ok.uid).toBe(owner.uid);
    const acl = await command(receiver.page, ['getfacl', '-n', '/mnt/shared/project/text']); expect(acl.output).toContain(String(receiver.uid));
    const [denied] = await batch(receiver.page, [{ chmod: { path: '/mnt/shared/project/text', mode: 0o777 } }]); expect(denied.err.errno).toBe('EPERM');
    const [readonly] = await batch(receiver.page, [{ open: { path: '/mnt/shared/project/text', flags: 1 } }]); expect(readonly.err.errno).toBe('EROFS');
  } finally { await dispose(owner, receiver, stranger); }
});

test('a refused mount reports permission denied without a write warning', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page); const grant = await publish(owner);
    await expect(attach(receiver, grant)).rejects.toThrow(/Permission denied/);
    expect(await receiver.page.evaluate(() => window.os.localMountList())).toEqual([]);
  } finally { await dispose(owner, receiver); }
});

test('an ACL refusal is retained when it arrives before the receiver socket', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page);
    const listening = owner.page.waitForEvent('websocket', socket => socket.url().includes('/api/mounts/listen/'));
    const grant = await publish(owner), listener = await listening;
    const refused = listener.waitForEvent('framereceived', event => JSON.parse(String(event.payload)).type === 'disconnected');
    const ticket = await receiver.page.evaluate(async id => (await (await fetch('/api/mounts/connect/' + id, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: '', write: false, execute: false }),
    })).json()), grant.id);
    expect(ticket.ticket).toEqual(expect.any(String));
    await refused;
    const result = await receiver.page.evaluate(ticket => new Promise((resolve, reject) => {
      const url = new URL('/api/mounts/channel/' + ticket.id + '/' + ticket.session + '?ticket=' + ticket.ticket, location.href);
      url.protocol = 'ws:'; const socket = new WebSocket(url);
      socket.onmessage = event => { resolve(JSON.parse(event.data)); socket.close(); };
      socket.onerror = () => reject(new Error('refusal was lost during socket admission'));
    }), ticket);
    expect(result).toEqual({ type: 'closed', errno: 'EACCES' });
  } finally { await dispose(owner, receiver); }
});

test('Files browses an authorized shared directory and its children', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page);
    await batch(owner.page, [{ mkdir: { path: '/mnt/local/source/folder', mode: 0o700 } }]);
    await write(owner.page, '/mnt/local/source/folder/inside.txt', 'INSIDE');
    await allow(owner, receiver); const grant = await publish(owner); await attach(receiver, grant);
    const files = receiver.page.locator('#window-files'), location = files.getByLabel('Location', { exact: true });
    await location.fill('/mnt/shared/project'); await location.press('Enter');
    await expect(files.locator('.filename-text')).toHaveText(['folder/', 'text']);
    await files.locator('.file').filter({ hasText: 'folder/' }).click();
    await expect(files.locator('.filename-text')).toHaveText(['inside.txt']);
    await expect(files.locator('.error')).toHaveCount(0);
    await write(owner.page, '/mnt/local/source/folder/later.txt', 'LATER');
    await allow(owner, receiver, '/mnt/local/source/folder/later.txt', false);
    await files.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(files.locator('.filename-text')).toHaveText(['inside.txt', 'later.txt']);
    await expect(location).toHaveValue('/mnt/shared/project/folder');
  } finally { await dispose(owner, receiver); }
});

test('file ACLs and revoked ACLs apply to existing remote descriptors', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page); await write(owner.page, '/mnt/local/source/secret', 'SECRET');
    await allow(owner, receiver, '/mnt/local/source', false); await allow(owner, receiver, '/mnt/local/source/text', false);
    const grant = await publish(owner); await attach(receiver, grant);
    expect((await read(receiver.page, 'project', 'secret')).status).not.toBe(200);
    const [opened] = await batch(receiver.page, [{ open: { path: '/mnt/shared/project/text' } }]); expect(opened.ok.fd).toBeGreaterThan(0);
    await command(owner.page, ['setfacl', '-x', `u:${receiver.uid}`, '/mnt/local/source/text']);
    const [denied] = await batch(receiver.page, [{ pread: { fd: opened.ok.fd, count: 10 } }]); expect(denied.err.errno).toBe('EACCES');
    const [escape] = await batch(receiver.page, [{ stat: { path: '/mnt/shared/project/../../../etc/passwd' } }]); expect(escape.err.errno).toBe('EACCES');
    await command(owner.page, ['chmod', '700', '/mnt/local/source']);
    expect((await read(receiver.page)).status).not.toBe(200);
  } finally { await dispose(owner, receiver); }
});

test('password bypass is scoped to the export and preserves the receiving account', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page); await batch(owner.page, [{ mkdir: { path: '/mnt/local/source/public', mode: 0o700 } }]);
    await write(owner.page, '/mnt/local/source/public/text', 'PUBLIC');
    const grant = await publish(owner, { path: '/mnt/local/source/public', password: 'export-only-password' });
    await expect(attach(receiver, grant, { password: 'wrong' })).rejects.toThrow(/credentials/);
    await expect(attach(receiver, grant)).rejects.toThrow();
    await attach(receiver, grant, { password: 'export-only-password', writable: true });
    expect(await read(receiver.page)).toEqual({ status: 200, text: 'PUBLIC' });
    await write(receiver.page, '/mnt/shared/project/text', 'UPDATED');
    expect((await read(receiver.page)).text).toBe('UPDATED');
    expect((await batch(receiver.page, ['getcreds']))[0].ok.uid).toBe(receiver.uid);
    const [escape] = await batch(receiver.page, [{ pread: { path: '/mnt/shared/project/../text' } }]); expect(escape.err.errno).toBe('EACCES');
    // Neither a password nor a connection permits access the owner has removed.
    await command(owner.page, ['chmod', '000', '/mnt/local/source/public/text']);
    expect((await read(receiver.page)).status).not.toBe(200);
  } finally { await dispose(owner, receiver); }
});

test('one export serves multiple explicit mounts over P2P and revokes them together', async ({ browser }) => {
  const owner = await client(browser), a = await client(browser), b = await client(browser);
  try {
    await mount(owner.page); await allow(owner, a); await allow(owner, b);
    const grant = await publish(owner, { p2p: true }); await attach(a, grant, { p2p: true }); await attach(b, grant, { p2p: true });
    await expect.poll(async () => (await a.page.evaluate(() => window.os.mountTransports())).mounts[0]?.mode, { timeout: 20000 }).toBe('p2p');
    expect((await read(a.page)).status).toBe(200); expect((await read(b.page)).status).toBe(200);
    await command(owner.page, ['setfacl', '-x', `u:${a.uid}`, '/mnt/local/source/text']);
    expect((await read(a.page)).status).not.toBe(200); expect((await read(b.page)).status).toBe(200);
    await owner.page.evaluate(id => window.os.revokeMount(id), grant.id);
    await expect.poll(async () => (await read(b.page)).status).not.toBe(200);
  } finally { await dispose(owner, a, b); }
});

test('default ACL inheritance applies to new OS files without retroactively opening old files', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page); await allow(owner, receiver, '/mnt/local/source', false);
    expect((await command(owner.page, ['setfacl', '-m', `d:u:${receiver.uid}:rx`, '/mnt/local/source'])).output).toBe('');
    await write(owner.page, '/mnt/local/source/new', 'INHERITED');
    const grant = await publish(owner); await attach(receiver, grant);
    expect((await read(receiver.page, 'project', 'new')).text).toBe('INHERITED');
    expect((await read(receiver.page)).status).not.toBe(200);
  } finally { await dispose(owner, receiver); }
});

test('export admission rejects forged identities, old enrollment and cross-account revocation', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page); const grant = await publish(owner);
    const post = (path, data, headers = {}) => receiver.page.evaluate(async ({ path, data, headers }) => { const response = await fetch('/api/mounts/' + path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(data) }); return { status: response.status, value: await response.json() }; }, { path, data, headers });
    expect((await post('enroll', { label: 'legacy' })).value.errno).toBe('ENOSYS');
    expect((await post('revoke/' + grant.id, {})).value.errno).toBe('EACCES');
    expect((await post('connect/' + grant.id, { password: '', write: false, execute: false }, { 'X-Process-Token': 'fake' })).value.errno).toBe('EACCES');
    // A claimed owner credential cannot enter the trusted listener identity.
    const forged = await post('connect/' + grant.id, { password: '', write: false, execute: false, identity: { id: owner.uid }, authenticated: true }, { 'X-OS-Mount-Identity': JSON.stringify({ id: owner.uid, group: owner.uid, groups: [] }) });
    expect(forged.value.uid).toBe(receiver.uid);
    await expect(attach(receiver, grant)).rejects.toThrow();
    expect(await receiver.page.evaluate(() => window.os.localMountList())).toEqual([]);
  } finally { await dispose(owner, receiver); }
});

test('remote executable transfer requires an explicit execute mount and source authorization', async ({ browser }) => {
  const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page);
    const module = binaryen.parseText('(module (memory (export "memory") 1) (func (export "_start")))'); const bytes = module.emitBinary(); module.dispose();
    await write(owner.page, '/mnt/local/source/tool', bytes); await command(owner.page, ['chmod', '700', '/mnt/local/source/tool']);
    await allow(owner, receiver);
    const grant = await publish(owner); await attach(receiver, grant);
    await expect(command(receiver.page, ['/mnt/shared/project/tool'])).rejects.toThrow(/Permission|EACCES/);
    await attach(receiver, grant, { name: 'tools', execute: true });
    const allowed = await command(receiver.page, ['/mnt/shared/tools/tool']); expect(allowed.result.status).toBe(0);
    await owner.page.evaluate(() => window.os.unmountLocal('/mnt/local/source'));
    await expect.poll(async () => (await read(receiver.page)).status).not.toBe(200);
  } finally { await dispose(owner, receiver); }
});

test('password guessing is bounded and export expiry closes an existing mount', async ({ browser }) => {
  test.setTimeout(60000); const owner = await client(browser), receiver = await client(browser);
  try {
    await mount(owner.page); const grant = await publish(owner, { password: 'short-lived-export', seconds: 30 });
    await attach(receiver, grant, { password: 'short-lived-export' });
    for (let i = 0; i < 4; i++) await expect(attach(receiver, grant, { name: 'wrong-' + i, password: 'incorrect' })).rejects.toThrow(/credentials/);
    await expect(attach(receiver, grant, { name: 'limited', password: 'incorrect' })).rejects.toThrow(/too many password/);
    await expect.poll(async () => (await read(receiver.page)).status, { timeout: 35000, intervals: [1000] }).not.toBe(200);
    expect((await receiver.page.evaluate(() => window.os.localMountList())).map(m => m.path)).toEqual(['/mnt/shared/project']);
  } finally { await dispose(owner, receiver); }
});
