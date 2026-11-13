import { test, expect } from './test.js';
import binaryen from 'binaryen';
import { createHash } from 'node:crypto';
const module = binaryen.parseText('(module (memory (export "memory") 1) (func (export "_start")))');
const bytes = Buffer.from(module.emitBinary()); module.dispose();
const hash = createHash('sha256').update(bytes).digest('hex');
const directory = path => ({ path, uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } });
const manifest = () => ({ format: 'os.image', version: 1, kind: 'sysext', name: 'developer', revision: 'local', abi: 1, level: 1, features: [], provenance: {}, entries: [directory('/'), directory('/usr'), directory('/usr/bin'), { path: '/usr/bin/probe', uid: 0, gid: 0, mode: 0o755, node: { type: 'file', sha256: hash, size: bytes.length } }] });
async function ready(page) { await page.goto('/'); await page.waitForFunction(() => window.os?.activatePrivate); }
async function source(page, image, content = bytes, name = 'source') {
  return page.evaluate(async ({ image, bytes, hash, name }) => window.os.mountLocal({ name, cloud: false, execute: false, files: [new File([JSON.stringify(image)], 'manifest.json'), new File([Uint8Array.from(atob(bytes), c => c.charCodeAt(0))], 'blobs/' + hash)] }), { image, bytes: content.toString('base64'), hash, name });
}
const activate = (page, name = 'dev', source = '/mnt/local/source') => page.evaluate(args => window.os.activatePrivate(args), { name, source, cloud: false });
const run = page => page.evaluate(() => window.os.exec([{ path: '/opt/private/dev/usr/bin/probe', argv: ['probe'] }], { stdin: '' }));

test('an unsigned private package executes without code upload or system activation and another host cannot see it', async ({ page, context, browser }) => {
  const uploaded = [];
  context.on('request', request => { if (request.postDataBuffer()?.includes(bytes)) uploaded.push(request.url()); });
  await ready(page); await source(page, manifest());
  const mount = await activate(page); expect(mount.path).toBe('/opt/private/dev');
  expect((await run(page)).status).toBe(0);
  const other = await context.newPage(); await ready(other);
  await expect(run(other)).rejects.toThrow(/ENOENT|No such file/);
  const foreign = await browser.newContext();
  try {
    const account = await foreign.newPage(); await ready(account);
    await expect(run(account)).rejects.toThrow(/ENOENT|No such file/);
    expect(await account.evaluate(() => window.os.localMountList())).toEqual([]);
  } finally { await foreign.close(); }
  const stat = await page.evaluate(async () => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: ['getcreds', { stat: { path: '/opt/private/dev/usr/bin/probe' } }] }) })).json()).results);
  expect(stat[1].ok.uid).toBe(stat[0].ok.uid); expect(stat[0].ok.uid).not.toBe(0);
  expect(stat[1].ok.mode & 0o6000).toBe(0);
  await page.evaluate(() => window.os.unmountLocal('/mnt/local/source'));
  expect((await run(page)).status).toBe(0); // activation is a verified immutable snapshot
  await page.evaluate(() => window.os.unmountLocal('/opt/private/dev'));
  await expect(run(page)).rejects.toThrow(/ENODEV/); expect(uploaded).toEqual([]); await other.close();
});

test('content corruption, set-ID metadata, incompatible ABI and escaping links fail activation', async ({ page }) => {
  await ready(page);
  const cases = [
    { image: manifest(), bytes: Buffer.from('wrong bytes') },
    { image: { ...manifest(), abi: 99 }, bytes },
    { image: { ...manifest(), entries: manifest().entries.map(entry => entry.node.type === 'file' ? { ...entry, mode: 0o4755 } : entry) }, bytes },
    { image: { ...manifest(), entries: [...manifest().entries, { path: '/usr/escape', uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target: '/etc/shadow' } }] }, bytes },
  ];
  for (let i = 0; i < cases.length; i++) {
    await source(page, cases[i].image, cases[i].bytes, 'bad' + i);
    await expect(activate(page, 'bad' + i, '/mnt/local/bad' + i)).rejects.toThrow();
  }
  expect(await page.evaluate(() => window.os.localMountList())).toHaveLength(cases.length);
});

test('private composition resolves internal symlinks and refuses collisions between extensions', async ({ page }) => {
  await ready(page);
  const image = manifest(); image.entries.push({ path: '/usr/link', uid: 0, gid: 0, mode: 0o777, node: { type: 'symlink', target: '/usr/bin/probe' } });
  await source(page, image); await activate(page);
  const stat = await page.evaluate(async () => (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls: [{ readlink: { path: '/opt/private/dev/usr/link' } }, { stat: { path: '/opt/private/dev/usr/link' } }] }) })).json()).results);
  expect(stat[0].ok).toBe('/opt/private/dev/usr/bin/probe'); expect(stat[1].ok.mode & 0o170000).toBe(0o100000);
  expect((await page.evaluate(() => window.os.exec([{ path: '/opt/private/dev/usr/link', argv: ['link'] }], { stdin: '' }))).status).toBe(0);
  await source(page, manifest(), bytes, 'second');
  await expect(page.evaluate(() => window.os.activatePrivate({ name: 'collision', sources: ['/mnt/local/source', '/mnt/local/second'], cloud: false }))).rejects.toThrow(/collision/);
});
