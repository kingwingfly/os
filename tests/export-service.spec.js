import { test, expect } from './test.js';
import { test as protocolTest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { attachPortTransport, connectExportTransport } from '../web/mount-transport.js';
import { MountRelay } from '../crates/worker/mount-relay.js';

const batch = (page, calls) => page.evaluate(async calls =>
  (await (await fetch('/api/sys', { method: 'POST', body: JSON.stringify({ calls }) })).json()).results, calls);
const exec = (page, ...argv) => page.evaluate(argv => window.os.exec([{ path: argv[0], argv }], { cwd: '/', stdin: '' }), argv);
async function ok(page, ...argv) {
  const r = await exec(page, ...argv);
  expect(r.status, JSON.stringify([argv, r])).toBe(0);
  return r.stdout ?? '';
}
async function start(page) {
  await page.goto('/');
  await page.waitForFunction(() => window.os?.exec && window.os?.shareMount);
  const [who] = await batch(page, ['getcreds']);
  expect(who.ok.uid).toBeGreaterThan(0);
  return who.ok;
}
async function source(page) {
  const who = await start(page);
  const path = who.home + '/export-' + crypto.randomUUID();
  await ok(page, 'mkdir', path);
  await ok(page, 'dash', '-c', 'printf original > "$1/file"', 'sh', path);
  return path;
}

test('E-01 E-04 E-10 offline cowfs publication, service identity and clean shutdown', async ({ page, context }) => {
  const path = await source(page);
  const target = '/mnt/shared/offline';
  const relayRequests = [];
  context.on('request', req => { if (new URL(req.url()).pathname.startsWith('/api/mounts/')) relayRequests.push(req.url()); });
  await context.setOffline(true);
  try {
    const unit = JSON.parse(await ok(page, 'service', '--user', '--json', 'status', 'exportd.service')).unit;
    expect(await ok(page, 'ps')).toMatch(/\bexportd\b/);
    const proc = await ok(page, 'cat', '/proc/' + unit.pid + '/status');
    expect(Number(/^Uid:\s+(\d+)/m.exec(proc)?.[1])).toBeGreaterThan(0);
    const { export: grant } = JSON.parse(await ok(page, 'exportctl', 'publish', '--ipc-only', '--json', '--rw', path));
    expect(grant.transports).toEqual(['ipc']);
    await ok(page, 'mount', '-t', 'sharefs', '-o', 'transport=ipc', 'osfs:' + grant.id, target);
    expect(await ok(page, 'cat', target + '/file')).toBe('original');
    expect(JSON.parse(await ok(page, 'exportctl', 'clients', '--json', grant.id)).clients).toEqual([
      expect.objectContaining({ transport: 'ipc', peer_uid: grant.owner_uid }),
    ]);
    await ok(page, 'service', '--user', 'stop', 'exportd.service');
    expect((await exec(page, 'cat', target + '/file')).status).not.toBe(0);
    expect(await ok(page, 'cat', path + '/file')).toBe('original');
    expect(relayRequests).toEqual([]);
  } finally {
    await context.setOffline(false);
    await exec(page, 'umount', target);
    await exec(page, 'service', '--user', 'start', 'exportd.service');
  }
});

protocolTest('E-02 application uses the userspace export service', async () => {
  const ui = await readFile(new URL('../web/mount-sharing-ui.js', import.meta.url), 'utf8');
  expect(ui).toContain("kernelCall('unix_rpc'");
  expect(ui).not.toMatch(/kernelCall\(['"]mount_(export|revoke|shared|exports)/);
  // Wave 5B removes the reserved old entry points from the shipping image.
  const provider = new URL('../web/kernel/mount-sharing.js', import.meta.url);
  const old = await readFile(provider, 'utf8').catch(error => { if (error.code === 'ENOENT') return ''; throw error; });
  const kernel = await readFile(new URL('../crates/client-kernel/src/vfs_engine.rs', import.meta.url), 'utf8');
  const dispatchers = [...old.matchAll(/function\s+(exportMount|serve)\s*\(/g), ...kernel.matchAll(/fn\s+(export_provider)\s*\(/g)];
  expect(dispatchers.map(match => match[1])).toEqual([]);
});

for (const transport of ['ipc', 'p2p', 'relay']) {
  test(`E-03 E-05 E-06 E-07 E-08 retained descriptors, confinement and inheritance over ${transport}`, async ({ browser, page }) => {
    const path = await source(page);
    const second = transport === 'ipc' ? null : await browser.newContext();
    const receiver = second ? await second.newPage() : page;
    const target = '/mnt/shared/acceptance', password = 'only-this-directory';
    try {
      if (second) await start(receiver);
      await ok(page, 'chmod', '2770', path);
      await ok(page, 'setfacl', '-m', 'd:u::rwx,d:g::r-x,d:o::---', path);
      await ok(page, 'ln', '-s', '../private', path + '/outside');
      const grant = await page.evaluate(({ path, password, transport }) =>
        window.os.shareMount({ path, name: 'acceptance', password, seconds: 120, ipcOnly: transport === 'ipc', writable: true, execute: false },
          { p2p: transport === 'p2p' }), { path, password, transport });
      await receiver.evaluate(({ grant, password, transport }) =>
        window.os.attachShared({ address: grant.address, name: 'acceptance', writable: true, password, transport }, { p2p: transport === 'p2p' }), { grant, password, transport });
      await expect.poll(async () => (await receiver.evaluate(() => window.os.mountTransports())).mounts.find(m => m.path === target)?.mode).toBe(transport);
      const [held, external] = await batch(receiver, [{ open: { path: target + '/file' } }, { open: { path: target + '/outside' } }]);
      expect(held.ok.fd).toEqual(expect.any(Number));
      expect(['EACCES', 'ELOOP']).toContain(external.err.errno);
      await ok(page, 'mv', path, path + '-renamed');
      expect(await ok(receiver, 'cat', target + '/file')).toBe('original');
      await ok(receiver, 'mkdir', target + '/new');
      const [parent, child] = await batch(page, [{ stat: { path: path + '-renamed' } }, { stat: { path: path + '-renamed/new' } }]);
      expect(child.ok.uid).toBe(parent.ok.uid);
      expect(child.ok.gid).toBe(parent.ok.gid);
      expect(child.ok.mode & 0o2777).toBe(0o2750);
      await ok(page, 'chmod', '000', path + '-renamed/file');
      const [denied] = await batch(receiver, [{ pread: { fd: held.ok.fd, count: 10 } }]);
      expect(denied.err.errno).toBe('EACCES');
      await ok(page, 'chmod', '700', path + '-renamed/file');
      const [opened, stat] = await batch(receiver, [{ open: { path: target + '/file' } }, { stat: { path: target + '/file' } }]);
      expect(stat.ok.mode & 0o111).toBe(0);
      await ok(page, 'mv', path + '-renamed/file', path + '-outside');
      const [stale] = await batch(receiver, [{ pread: { fd: opened.ok.fd, count: 10 } }]);
      expect(stale.err.errno).toBe('ESTALE');
      await ok(page, 'touch', path + '-renamed/new/held');
      const [pinned] = await batch(receiver, [{ open: { path: target + '/new/held' } }]);
      await ok(page, 'exportctl', 'revoke', grant.id);
      const [revoked, heldRead] = await batch(receiver, [{ stat: { path: target + '/new' } }, { pread: { fd: pinned.ok.fd, count: 1 } }]);
      expect(revoked.err.errno).toBe('EACCES');
      expect(heldRead.err.errno).toBe('EACCES');
    } finally { await second?.close(); }
  });
}

for (const transport of ['ipc', 'p2p', 'relay']) {
  test(`E-03 E-08 read-only ceiling, handle limit and lease expiry over ${transport}`, async ({ browser, page }) => {
    test.setTimeout(180000);
    const path = await source(page), password = 'limited-directory';
    const other = transport === 'ipc' ? null : await browser.newContext();
    const receiver = other ? await other.newPage() : page;
    const share = async (name, seconds) => {
      const grant = await page.evaluate(({ path, password, seconds, transport }) =>
        window.os.shareMount({ path, password, name: 'limits', writable: false, execute: false, ipcOnly: transport === 'ipc', seconds }),
        { path, password, seconds, transport });
      await receiver.evaluate(({ grant, password, name, transport }) =>
        window.os.attachShared({ address: grant.address, name, password, transport, writable: false }),
        { grant, name, transport, password });
      return { file: '/mnt/shared/' + name + '/file', id: grant.id };
    };
    try {
      if (other) await start(receiver);
      const { file, id } = await share('limits', 180);
      const [write, meta] = await batch(receiver, [{ open: { path: file, flags: 1 } }, { stat: { path: file } }]);
      expect(write.err.errno).toBe('EROFS');
      expect(meta.ok.mode & 0o222).toBe(0);
      const fds = [];
      for (let i = 0; i < 16; i++) {
        const opened = await batch(receiver, Array.from({ length: 8 }, () => ({ open: { path: file } })));
        fds.push(...opened.map(r => r.ok.fd));
      }
      expect((await batch(receiver, [{ open: { path: file } }]))[0].err.errno).toBe('EMFILE');
      for (let i = 0; i < fds.length; i += 8) await batch(receiver, fds.slice(i, i + 8).map(fd => ({ close: { fd } })));
      await ok(page, 'exportctl', 'revoke', id);
      const short = await share('short', 30);
      const [opened] = await batch(receiver, [{ open: { path: short.file } }]);
      await expect.poll(async () => (await batch(receiver, [{ pread: { fd: opened.ok.fd, count: 1 } }]))[0].err?.errno,
        { timeout: 32000 }).toBe('ESTALE');
    } finally { await other?.close(); }
  });
}

protocolTest('E-09 framed MessagePort loss classifies each pending operation separately', async () => {
  const { port1, port2 } = new MessageChannel();
  const client = attachPortTransport(port1);
  const base = { fs: 'vol', node: { ino: 3, generation: 1 } };
  let received = 0;
  port2.onmessage = ({ data }) => {
    if (data.type === 'frame' && ++received === 4) port2.postMessage({ type: 'closed', errno: 'ENOTCONN' });
  };
  try {
    const ops = [
      { op: 'fd', handle: 1, call: { op: 'read', offset: 0, count: 1 } },
      { op: 'at', base, call: { op: 'metadata' } },
      { op: 'at', base, call: { op: 'mkdir', name: 'x', mode: 511, umask: 18 } },
      { op: 'fd', handle: 2, call: { op: 'write', at: 'end', data: 'YQ==' } },
    ];
    const pending = ops.map(r => client.request(r));
    await expect(client.request(ops[0])).rejects.toMatchObject({ errno: 'EAGAIN' });
    const outcomes = await Promise.allSettled(pending);
    expect(outcomes.map(o => o.reason?.errno)).toEqual(['ENOTCONN', 'ENOTCONN', 'EIO', 'EIO']);
    expect(outcomes.map(o => !!o.reason?.uncertain_writes)).toEqual([false, false, true, true]);
    expect(client.uncertain_writes).toBe(true);
  } finally { client.close(); port2.close(); }
});

protocolTest('E-08 authenticated relay claims are publisher-only, single use, scoped to the negotiated transport and lease', async () => {
  const rows = new Map();
  const storage = { get: async key => rows.get(key), put: async (key, value) => rows.set(key, value), setAlarm: async () => {} };
  const relay = new MountRelay({ storage }, {});
  const env = { MOUNTS: { idFromName: name => name, get: () => relay } };
  const account = new MountRelay({ storage }, env);
  const owner = { id: 1001, group: 20, groups: [20, 30] };
  const peer = { id: 2002, group: 40, groups: [40, 50] };
  const post = async (server, path, identity, value) => {
    const request = new Request('https://mount/api/mounts/' + path, {
      method: 'POST', headers: { 'X-OS-Mount-Identity': JSON.stringify(identity) }, body: JSON.stringify(value),
    });
    return (await server.fetch(request)).json();
  };
  const id = crypto.randomUUID();
  const grant = await post(account, 'publish', owner,
    { id, name: 'report', transports: ['relay'], write: false, execute: false, seconds: 60, password: 'protected' });
  expect(grant.id).toBe(id);
  let notice;
  relay.listener = { send: message => { notice = JSON.parse(message); } };
  const connect = (identity, password, transport = 'relay') => post(relay, 'connect/' + id, identity, {
    password, transport, write: false, execute: false, peer_identity: { uid: 0, gid: 0, groups: [0] }, password_auth: true,
  });
  try {
    expect((await connect(peer, '', 'p2p')).errno).toBe('EPROTONOSUPPORT');
    for (const password of ['', 'protected']) {
      const session = await connect(peer, password);
      const ticket = { ticket: notice.admission }, path = 'admit/' + id + '/' + session.session;
      expect((await post(relay, path, peer, ticket)).errno).toBe('EACCES');
      expect(await post(relay, path, owner, ticket)).toEqual({
        export_id: id, session: session.session, transport: 'relay', publisher_account: owner.id,
        peer_identity: { uid: peer.id, gid: peer.group, groups: peer.groups },
        password_auth: !!password, expires_at: grant.expires, rule: { writable: false, execute: false },
      });
      expect((await post(relay, path, owner, ticket)).errno).toBe('EACCES');
    }
    const other = { ...peer, id: 303 };
    for (let i = 0; i < 5; i++) expect((await connect(other, 'incorrect')).errno).toBe('EACCES');
    expect((await connect(other, 'incorrect')).errno).toBe('EAGAIN');
    await relay.alarm();
    expect((await connect(peer, '')).errno).toBe('ESTALE');
  } finally { for (const session of relay.sessions.keys()) relay.closeSession(session, 'ENOTCONN'); }
});

protocolTest('E-03 E-04 a negotiated private IPC port hands its original byte stream to the receiver', async () => {
  const { port1, port2 } = new MessageChannel();
  const client = await connectExportTransport(port1, { transport: 'ipc' });
  const wire = client.takePort();
  try {
    const received = new Promise(resolve => { wire.onmessage = ({ data }) => resolve(data.bytes); });
    const bytes = Uint8Array.of(0, 0, 1, 255, 254).buffer;
    port2.postMessage({ type: 'frame', bytes }, [bytes]);
    expect(new Uint8Array(await received)).toEqual(Uint8Array.of(0, 0, 1, 255, 254));
    await expect(client.request({ op: 'root' })).rejects.toMatchObject({ errno: 'ENOTCONN' });
  } finally { wire.close(); port2.close(); }
});

protocolTest('E-09 confirmed and cancelled requests survive a later transport loss', async () => {
  const { port1, port2 } = new MessageChannel(), client = attachPortTransport(port1);
  const encode = frame => {
    const bytes = new TextEncoder().encode(JSON.stringify(frame));
    const wire = new Uint8Array(bytes.length + 4);
    new DataView(wire.buffer).setUint32(0, bytes.length);
    wire.set(bytes, 4);
    return wire;
  };
  const options = { read: true, write: true, append: false, append_implies_write: false, truncate: true, create: true, create_new: false, exec: false, path: false };
  const open = { op: 'at', base: { fs: 'vol', node: { ino: 1, generation: 1 } }, call: { op: 'open', options } };
  const reply = (request_id, result) => encode({ type: 'reply', request_id, result });
  let seen = 0;
  port2.onmessage = ({ data }) => {
    if (data.type !== 'frame') return;
    if (++seen === 3) {
      const frames = Buffer.concat([reply(1, { Ok: { kind: 'unit' } }), reply(2, { Err: 'ECANCELED' }), reply(3, { Ok: { kind: 'unit' } })]);
      for (const part of [frames.subarray(0, 2), frames.subarray(2)]) port2.postMessage({ type: 'frame', bytes: part });
    } else if (seen === 4) port2.postMessage({ type: 'closed', errno: 'ENOTCONN' });
  };
  try {
    const acked = client.request(open), canceled = client.request(open);
    const cancel = client.request({ op: 'cancel', target_id: canceled.request_id });
    const results = await Promise.allSettled([acked, canceled, cancel]);
    expect(results.map(r => r.status)).toEqual(['fulfilled', 'rejected', 'fulfilled']);
    expect(results[1].reason.errno).toBe('ECANCELED');
    const pathOnly = { ...open, call: { op: 'open', options: { ...options, path: true } } };
    await expect(client.request(pathOnly)).rejects.toMatchObject({ errno: 'ENOTCONN', uncertain_writes: false });
    expect(client.uncertain_writes).toBe(false);
  } finally { client.close(); port2.close(); }
});
