// Requires the built Worker: (cd crates/worker && worker-build --release), then
// node --test tests/cloudfs-authority.mjs. All bindings/storage are disposable.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Miniflare } from 'miniflare';

test('authority binding rejects job credentials for v2 control and data while path grants remain scoped', async t => {
  const mf = new Miniflare({
    port: 0, unsafeInspectDurableObjects: true,
    workers: [{ config: {
      name: 'cloudfs-test',
      compatibilityDate: '2026-10-24',
      manifest: { mainModule: 'harness.js', modules: {
        // Miniflare's storage inspector needs an RPC-capable DO. Delegate service requests
        // unchanged to the actual WASM authority, exposing inspection only in this runtime.
        'harness.js': { type: 'esm', contents: `
          import { DurableObject } from 'cloudflare:workers';
          import { OsAuthority as Service } from './index.js';
          export { default } from './index.js';
          export class OsAuthority extends DurableObject {
            constructor(ctx, env) { super(ctx, env); this.service = new Service(ctx, env); }
            fetch(request) { return this.service.fetch(request); }
            alarm() { return this.service.alarm(); }
            async triggerAlarm() { await this.service.alarm(); }
          }
        ` },
        'index.js': { type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8') },
        'index_bg.wasm': { type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm') },
      } },
      exports: { OsAuthority: { type: 'durable-object', storage: 'sqlite' } },
      env: {
        AUTHORITY: { type: 'durable-object', worker: 'cloudfs-test', exportName: 'OsAuthority' },
        FILES: { type: 'r2', name: 'files' },
        ADMIN_PASSWORD: { type: 'text', value: randomUUID() }, SESSION_SECRET: { type: 'text', value: randomUUID() },
        ASSETS: { type: 'fetcher', handler: () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }) },
      },
    } }],
  });
  t.after(() => mf.dispose());
  const namespace = await mf.getDurableObjectNamespace('AUTHORITY');
  const authority = namespace.get(namespace.idFromName('filesystem'));
  const post = async (path, value) => {
    const body = JSON.stringify(value);
    const response = await authority.fetch('https://authority' + path, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)) }, body,
    });
    return response.json();
  };
  // Initialize the real authority, then install a token/task fixture through the local
  // runtime's storage inspector. No test routes or debug credentials enter production.
  await post('/api/sys', { calls: ['getcreds'] });
  const sql = await mf.unsafeGetDurableObjectStorage('cloudfs-test', 'OsAuthority', { name: 'filesystem' });
  const token = randomUUID(), hash = createHash('sha256').update(token).digest('base64url');
  const job = randomUUID(), now = Math.floor(Date.now() / 1000);
  await sql.exec('INSERT INTO credentials(token,ns,pid,uid,gid,groups,umask,started,owner,expires) VALUES(?,?,?,?,?,?,?,?,?,?)',
    hash, 'anonymous', 42, 0, 0, '[0]', 18, now, 'fixture process', now + 300);
  const rpc = (session, call) => post('/api/fs', { version: 2, credential: token, session, call });
  const connected = await rpc(null, 'connect');
  assert.ok(connected.session, connected.errno);
  const { session, root } = connected;
  const dir = await rpc(session, { mkdir: { dir: root, name: 'job-scope', mode: 0o700, umask: 0o022 } });
  const options = { read: true, write: true, append: false, append_implies_write: false, truncate: false, create: false, create_new: true, exec: false, path: false };
  const created = await rpc(session, { create: { ticket: randomUUID(), dir: dir.handle, name: 'unrelated', mode: 0o600, umask: 0o022, options } });
  assert.ok(Array.isArray(created), created.errno);
  const [entry, open] = created;
  await rpc(session, { create: { ticket: randomUUID(), dir: dir.handle, name: 'output', mode: 0o600, umask: 0o022, options } });
  await sql.exec('INSERT INTO device_tasks(id,lineage,request,device,digest,sid,fd,owner,grants) VALUES(?,?,?,?,?,?,?,?,?)',
    job, 'job ' + job, randomUUID(), '/dev/archive', '', 'job ' + job, 1, 0,
    JSON.stringify([{ directory: '/job-scope', inode: dir.handle.node.ino, name: 'output' }]));
  // Represent a session/open issued before the caller becomes restricted. The per-call
  // check must deny these too, independently of the connect gate.
  await sql.exec('UPDATE credentials SET ns = ?, owner = ? WHERE token = ?', 'jobs', 'job ' + job, hash);
  await sql.exec('UPDATE vfs_sessions SET ns = ? WHERE id = ?', 'jobs', session.id);
  const pathCall = call => post('/api/sys', { proc: token, calls: [call] });
  assert.equal((await pathCall({ unlink: { path: '/job-scope/unrelated' } })).results[0].err.errno, 'EACCES');
  assert.ok('ok' in (await pathCall({ unlink: { path: '/job-scope/output' } })).results[0]);
  assert.equal((await rpc(null, 'connect')).errno, 'EACCES');
  for (const call of [
    'renew', { metadata: { handle: entry.handle } }, { open_metadata: { open } }, { unlink: { dir: dir.handle, name: 'unrelated' } },
    { open: { ticket: randomUUID(), handle: entry.handle, options } },
    { set_len: { open, size: 0 } }, { sync: { open, data_only: false } },
    { try_lock: { open, family: 'flock', kind: 'exclusive', range: { start: 0, end: null } } },
    { release: { open } },
  ]) assert.equal((await rpc(session, call)).errno, 'EACCES');
  for (const operation of [{ read: { offset: 0, length: 1 } }, { write: { at: 'end', length: 1 } }]) {
    const request = { version: 2, credential: token, pid: null, session, open, operation };
    assert.equal((await post('/internal/fs/data', { request })).errno, 'EACCES');
    assert.equal((await post('/internal/fs/commit', { request, id: 'not-issued' })).errno, 'EACCES');
  }
  assert.equal((await sql.exec('SELECT ino FROM nodes WHERE path = ?', '/job-scope/unrelated'))[0].ino, entry.handle.node.ino);
  for (const table of ['vfs_reads', 'vfs_uploads']) assert.equal((await sql.exec(`SELECT count(*) AS n FROM ${table}`))[0].n, 0);
});

test('late upload expiry never discards an already-committed extent and empty writes skip upload state', async t => {
  const mf = new Miniflare({
    port: 0, unsafeInspectDurableObjects: true,
    workers: [{ config: {
      name: 'cloudfs-expiry-test',
      compatibilityDate: '2026-10-24',
      manifest: { mainModule: 'harness.js', modules: {
        'harness.js': { type: 'esm', contents: `
          import { DurableObject } from 'cloudflare:workers';
          import { OsAuthority as Service } from './index.js';
          export { default } from './index.js';
          export class OsAuthority extends DurableObject {
            constructor(ctx, env) { super(ctx, env); this.service = new Service(ctx, env); }
            fetch(request) { return this.service.fetch(request); }
            alarm() { return this.service.alarm(); }
            async triggerAlarm() { await this.service.alarm(); }
          }
        ` },
        'index.js': { type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8') },
        'index_bg.wasm': { type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm') },
      } },
      exports: { OsAuthority: { type: 'durable-object', storage: 'sqlite' } },
      env: {
        AUTHORITY: { type: 'durable-object', worker: 'cloudfs-expiry-test', exportName: 'OsAuthority' },
        FILES: { type: 'r2', name: 'files' },
        ADMIN_PASSWORD: { type: 'text', value: randomUUID() }, SESSION_SECRET: { type: 'text', value: randomUUID() },
        ASSETS: { type: 'fetcher', handler: () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }) },
      },
    } }],
  });
  t.after(() => mf.dispose());
  const namespace = await mf.getDurableObjectNamespace('AUTHORITY');
  const id = namespace.idFromName('filesystem');
  const authority = namespace.get(id);
  const bucket = await mf.getR2Bucket('FILES');
  const post = async (path, value) => {
    const body = JSON.stringify(value);
    const response = await authority.fetch('https://authority' + path, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)) }, body,
    });
    return response.json();
  };
  await post('/api/sys', { calls: ['getcreds'] });
  const sql = await mf.unsafeGetDurableObjectStorage('cloudfs-expiry-test', 'OsAuthority', { name: 'filesystem' });
  const token = randomUUID(), hash = createHash('sha256').update(token).digest('base64url');
  const now = Math.floor(Date.now() / 1000);
  await sql.exec('INSERT INTO credentials(token,ns,pid,uid,gid,groups,umask,started,owner,expires) VALUES(?,?,?,?,?,?,?,?,?,?)',
    hash, 'anonymous', 7, 0, 0, '[0]', 18, now, 'fixture process', now + 300);
  const rpc = (session, call) => post('/api/fs', { version: 2, credential: token, session, call });
  const { session, root } = await rpc(null, 'connect');
  const options = { read: true, write: true, append: false, append_implies_write: false, truncate: false, create: false, create_new: true, exec: false, path: false };
  const [, open] = await rpc(session, { create: { ticket: randomUUID(), dir: root, name: 'upload-race', mode: 0o600, umask: 0o022, options } });

  // 1. Empty write allocates no vfs_uploads or vfs_upload expiry row.
  const emptyPrep = await post('/internal/fs/data', { request: { version: 2, credential: token, pid: 7, session, open, operation: { write: { at: 'end', length: 0 } } } });
  assert.deepEqual(emptyPrep.written, { offset: 0, len: 0 });
  assert.equal((await sql.exec('SELECT count(*) AS n FROM vfs_uploads'))[0].n, 0);
  assert.equal((await sql.exec("SELECT count(*) AS n FROM expiries WHERE kind = 'vfs_upload'"))[0].n, 0);

  // 2. Committed upload survives a stale/racing vfs_upload expiry alarm, while an uncommitted expired upload is discarded.
  const writeReq = { version: 2, credential: token, pid: 7, session, open, operation: { write: { at: 'end', length: 4 } } };
  const prep = await post('/internal/fs/data', { request: writeReq });
  await bucket.put(prep.key, 'kept');
  const committed = await post('/internal/fs/commit', { request: writeReq, id: prep.id });
  assert.deepEqual(committed, { offset: 0, len: 4 });

  const stalePrep = await post('/internal/fs/data', { request: writeReq });
  await bucket.put(stalePrep.key, 'drop');
  await sql.exec("INSERT OR REPLACE INTO expiries(kind, id, due) VALUES('vfs_upload', ?, 0)", prep.id);
  await sql.exec('UPDATE vfs_uploads SET expires = 0 WHERE id = ?', stalePrep.id);
  await sql.exec("UPDATE expiries SET due = 0 WHERE kind = 'vfs_upload' AND id = ?", stalePrep.id);
  await authority.triggerAlarm();
  assert.equal((await sql.exec("SELECT count(*) AS n FROM expiries WHERE kind = 'vfs_upload'"))[0].n, 0);
  assert.equal(await (await bucket.get(prep.key))?.text(), 'kept');
  assert.equal(await bucket.get(stalePrep.key), null);
});

test('large >2^53 sparse files stream over /api/file, upload leases follow renew/release/disconnect, and flock ENOSPC + path uploads stay consistent', async t => {
  const mf = new Miniflare({
    port: 0, unsafeInspectDurableObjects: true,
    workers: [{ config: {
      name: 'cloudfs-regressions',
      compatibilityDate: '2026-10-24',
      manifest: { mainModule: 'harness.js', modules: {
        'harness.js': { type: 'esm', contents: `
          import { DurableObject } from 'cloudflare:workers';
          import { OsAuthority as Service, Machine as M } from './index.js';
          export { default } from './index.js';
          export { M as Machine };
          export class OsAuthority extends DurableObject {
            constructor(ctx, env) { super(ctx, env); this.service = new Service(ctx, env); }
            fetch(request) { return this.service.fetch(request); }
            alarm() { return this.service.alarm(); }
            async triggerAlarm() { await this.service.alarm(); }
          }
        ` },
        'index.js': { type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8') },
        'index_bg.wasm': { type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm') },
      } },
      exports: {
        OsAuthority: { type: 'durable-object', storage: 'sqlite' },
        Machine: { type: 'durable-object', storage: 'sqlite' },
      },
      env: {
        AUTHORITY: { type: 'durable-object', worker: 'cloudfs-regressions', exportName: 'OsAuthority' },
        MACHINE: { type: 'durable-object', worker: 'cloudfs-regressions', exportName: 'Machine' },
        FILES: { type: 'r2', name: 'files' },
        ADMIN_PASSWORD: { type: 'text', value: randomUUID() }, SESSION_SECRET: { type: 'text', value: randomUUID() },
        ASSETS: { type: 'fetcher', handler: () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }) },
      },
    } }],
  });
  t.after(() => mf.dispose());
  const namespace = await mf.getDurableObjectNamespace('AUTHORITY');
  const authority = namespace.get(namespace.idFromName('filesystem'));
  const bucket = await mf.getR2Bucket('FILES');
  const postRaw = async (path, body) => {
    const response = await authority.fetch('https://authority' + path, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)) }, body,
    });
    return response.text();
  };
  const post = async (path, value) => JSON.parse(await postRaw(path, JSON.stringify(value)));
  await post('/api/sys', { calls: ['getcreds'] });
  const sql = await mf.unsafeGetDurableObjectStorage('cloudfs-regressions', 'OsAuthority', { name: 'filesystem' });
  const token = randomUUID(), hash = createHash('sha256').update(token).digest('base64url');
  const now = Math.floor(Date.now() / 1000);
  await sql.exec(
    'INSERT INTO credentials(token,ns,pid,uid,gid,groups,umask,started,owner,expires,cloud_access) VALUES(?,?,?,?,?,?,?,?,?,?,1)',
    hash, 'anonymous', 9, 0, 0, '[0]', 18, now, 'fixture process', now + 600,
  );
  const rpc = (session, call) => post('/api/fs', { version: 2, credential: token, session, call });
  const { session, root } = await rpc(null, 'connect');
  const tmp = await rpc(session, { lookup: { dir: root, name: 'tmp' } });
  const rwOpts = { read: true, write: true, append: false, append_implies_write: false, truncate: false, create: true, create_new: true, exec: false, path: false };

  // 1. >2^53 sparse file streams cleanly over HEAD, Range GET, and un-ranged GET /api/file.
  const [, bigOpen] = await rpc(session, { create: { ticket: randomUUID(), dir: tmp.handle, name: 'huge', mode: 0o644, umask: 0o022, options: rwOpts } });
  assert.equal(await postRaw('/api/fs', `{"version":2,"credential":${JSON.stringify(token)},"session":${JSON.stringify(session)},"call":{"set_len":{"open":${JSON.stringify(bigOpen)},"size":9007199254741007}}}`), 'null');
  const tailReqRaw = `{"request":{"version":2,"credential":${JSON.stringify(token)},"pid":9,"session":${JSON.stringify(session)},"open":${JSON.stringify(bigOpen)},"operation":{"write":{"at":{"offset":9007199254741005},"length":2}}}}`;
  const tailPrep = JSON.parse(await postRaw('/internal/fs/data', tailReqRaw));
  await bucket.put(tailPrep.key, 'hi');
  const tailCommitRaw = `{"request":{"version":2,"credential":${JSON.stringify(token)},"pid":9,"session":${JSON.stringify(session)},"open":${JSON.stringify(bigOpen)},"operation":{"write":{"at":{"offset":9007199254741005},"length":2}}},"id":${JSON.stringify(tailPrep.id)}}`;
  assert.equal(await postRaw('/internal/fs/commit', tailCommitRaw), '{"len":2,"offset":9007199254741005}');

  const headRes = await mf.dispatchFetch('http://localhost/api/file?path=/tmp/huge', { method: 'HEAD' });
  assert.equal(headRes.status, 200);
  assert.equal(headRes.headers.get('content-length'), '9007199254741007');

  const rangeRes = await mf.dispatchFetch('http://localhost/api/file?path=/tmp/huge', {
    method: 'GET', headers: { Range: 'bytes=9007199254741003-9007199254741006' },
  });
  assert.equal(rangeRes.status, 206);
  assert.equal(rangeRes.headers.get('content-range'), 'bytes 9007199254741003-9007199254741006/9007199254741007');
  assert.deepEqual(Buffer.from(await rangeRes.arrayBuffer()), Buffer.from([0, 0, 0x68, 0x69]));

  const fullRes = await mf.dispatchFetch('http://localhost/api/file?path=/tmp/huge', {
    method: 'GET', headers: { 'Accept-Encoding': 'identity' },
  });
  assert.equal(fullRes.status, 200);
  const reader = fullRes.body.getReader();
  const firstChunk = await reader.read();
  assert.equal(firstChunk.done, false);
  assert.ok(firstChunk.value.byteLength > 0);
  assert.ok(firstChunk.value.every(b => b === 0));
  await reader.cancel();
  await rpc(session, { release: { open: bigOpen } });

  // 2. Renew extends vfs_uploads + expiries; release and disconnect clean up pending vfs_uploads + R2 objects.
  const [, upOpen1] = await rpc(session, { create: { ticket: randomUUID(), dir: tmp.handle, name: 'up1', mode: 0o600, umask: 0o022, options: rwOpts } });
  const prep1 = await post('/internal/fs/data', { request: { version: 2, credential: token, pid: 9, session, open: upOpen1, operation: { write: { at: 'end', length: 3 } } } });
  await bucket.put(prep1.key, 'abc');
  await sql.exec('UPDATE vfs_uploads SET expires = 100 WHERE id = ?', prep1.id);
  await sql.exec("UPDATE expiries SET due = 100 WHERE kind = 'vfs_upload' AND id = ?", prep1.id);
  assert.equal(await rpc(session, 'renew'), 120);
  assert.ok((await sql.exec('SELECT expires FROM vfs_uploads WHERE id = ?', prep1.id))[0].expires > now);
  assert.ok((await sql.exec("SELECT due FROM expiries WHERE kind = 'vfs_upload' AND id = ?", prep1.id))[0].due > now);
  await rpc(session, { release: { open: upOpen1 } });
  assert.equal((await sql.exec('SELECT count(*) AS n FROM vfs_uploads WHERE id = ?', prep1.id))[0].n, 0);
  assert.equal((await sql.exec("SELECT count(*) AS n FROM expiries WHERE kind = 'vfs_upload' AND id = ?", prep1.id))[0].n, 0);
  assert.equal((await sql.exec('SELECT count(*) AS n FROM garbage WHERE key = ?', prep1.key))[0].n, 1);
  await authority.triggerAlarm();
  assert.equal(await bucket.get(prep1.key), null);

  const conn2 = await rpc(null, 'connect');
  const [, upOpen2] = await rpc(conn2.session, { create: { ticket: randomUUID(), dir: conn2.root, name: 'up2', mode: 0o600, umask: 0o022, options: rwOpts } });
  const prep2 = await post('/internal/fs/data', { request: { version: 2, credential: token, pid: 9, session: conn2.session, open: upOpen2, operation: { write: { at: 'end', length: 3 } } } });
  await bucket.put(prep2.key, 'xyz');
  await rpc(conn2.session, 'disconnect');
  assert.equal((await sql.exec('SELECT count(*) AS n FROM vfs_uploads WHERE id = ?', prep2.id))[0].n, 0);
  assert.equal((await sql.exec("SELECT count(*) AS n FROM expiries WHERE kind = 'vfs_upload' AND id = ?", prep2.id))[0].n, 0);
  assert.equal((await sql.exec('SELECT count(*) AS n FROM garbage WHERE key = ?', prep2.key))[0].n, 1);
  await authority.triggerAlarm();
  assert.equal(await bucket.get(prep2.key), null);

  // 3. Blocking flock conversion commits release of the caller's old flock even when wait queue hits ENOSPC (4096).
  const [flockEntry, flockA] = await rpc(session, { create: { ticket: randomUUID(), dir: tmp.handle, name: 'flock-full', mode: 0o600, umask: 0o022, options: rwOpts } });
  const openOpts = { ...rwOpts, create: false, create_new: false };
  const flockB = await rpc(session, { open: { ticket: randomUUID(), handle: flockEntry.handle, options: openOpts } });
  const flockC = await rpc(session, { open: { ticket: randomUUID(), handle: flockEntry.handle, options: openOpts } });
  const whole = { start: 0, end: null };
  assert.equal(await rpc(session, { try_lock: { open: flockA, family: 'flock', kind: 'shared', range: whole } }), null);
  assert.equal(await rpc(session, { try_lock: { open: flockB, family: 'flock', kind: 'shared', range: whole } }), null);
  const lockRow = JSON.parse((await sql.exec('SELECT state FROM vfs_locks WHERE ino = ?', flockEntry.handle.node.ino))[0].state);
  lockRow.waits = Array.from({ length: 4096 }, (_, i) => ({
    ticket: `w-${i}`,
    granted: false,
    lock: { owner: 900000 + i, family: 'posix', kind: 'exclusive', range: { start: 0, end: 1 }, ticket: `w-${i}` },
  }));
  await sql.exec('UPDATE vfs_locks SET state = ? WHERE ino = ?', JSON.stringify(lockRow), flockEntry.handle.node.ino);
  assert.equal((await rpc(session, { lock: { ticket: randomUUID(), open: flockA, family: 'flock', kind: 'exclusive', range: whole } })).errno, 'ENOSPC');
  // Releasing flockB now leaves zero flock holders because flockA's shared flock drop was committed on ENOSPC.
  await rpc(session, { unlock: { open: flockB, family: 'flock', range: whole } });
  assert.equal(await rpc(session, { try_lock: { open: flockC, family: 'flock', kind: 'exclusive', range: whole } }), null);
  for (const o of [flockA, flockB, flockC]) await rpc(session, { release: { open: o } });

  // 4. Incomplete path-API uploads reject CloudFS byte opens/creates/links with EBUSY, and discard detaches pinned unlinked inodes.
  const guestCookie = `os_guest=${randomBytes(32).toString('hex')}`;
  const postCookie = async (path, value) => {
    const body = JSON.stringify(value);
    const response = await authority.fetch('https://authority' + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': String(Buffer.byteLength(body)), Cookie: guestCookie },
      body,
    });
    return response.json();
  };
  const sysOpen = await postCookie('/api/sys', { calls: [{ open: { path: '/tmp/in-flight', flags: 1 | 64 | 512, mode: 0o644, size: 100 } }] });
  const uploadFd = sysOpen.results[0].ok.fd;
  const inFlight = await rpc(session, { lookup: { dir: tmp.handle, name: 'in-flight' } });
  assert.equal((await rpc(session, { open: { ticket: randomUUID(), handle: inFlight.handle, options: openOpts } })).errno, 'EBUSY');
  assert.equal((await rpc(session, { create: { ticket: randomUUID(), dir: tmp.handle, name: 'in-flight', mode: 0o644, umask: 0o022, options: { ...rwOpts, create_new: false } } })).errno, 'EBUSY');
  assert.equal((await rpc(session, { link: { target: inFlight.handle, dir: tmp.handle, name: 'in-flight-alias' } })).errno, 'EBUSY');
  const pathOpen = await rpc(session, { open: { ticket: randomUUID(), handle: inFlight.handle, options: { ...openOpts, read: false, write: false, path: true } } });
  assert.ok(pathOpen.id, pathOpen.errno);
  await rpc(session, { unlink: { dir: tmp.handle, name: 'in-flight' } });
  const discarded = await postCookie('/api/sys', { calls: [{ discard: { fd: uploadFd } }] });
  assert.equal(discarded.results[0].ok.discarded, true);
  const pinnedNode = (await sql.exec('SELECT file, size FROM inodes WHERE id = ?', inFlight.handle.node.ino))[0];
  assert.equal(pinnedNode.file, null);
  assert.equal(pinnedNode.size, 0);
  await rpc(session, { release: { open: pathOpen } });
  assert.equal((await sql.exec('SELECT count(*) AS n FROM inodes WHERE id = ?', inFlight.handle.node.ino))[0].n, 0);
});

test('L2 root seeding + EROFS, v2 statfs + non-root mknod, v2 FICLONE, and X-Process-Token v1 boundary enforcement', async t => {
  const adminPassword = 'admin-secret-password-' + randomUUID();
  const mf = new Miniflare({
    port: 0, unsafeInspectDurableObjects: true,
    workers: [{ config: {
      name: 'cloudfs-l2-boundary',
      compatibilityDate: '2026-10-24',
      manifest: { mainModule: 'harness.js', modules: {
        'harness.js': { type: 'esm', contents: `
          import { DurableObject } from 'cloudflare:workers';
          import { OsAuthority as Service, Machine as M } from './index.js';
          export { default } from './index.js';
          export { M as Machine };
          export class OsAuthority extends DurableObject {
            constructor(ctx, env) { super(ctx, env); this.service = new Service(ctx, env); }
            fetch(request) { return this.service.fetch(request); }
            alarm() { return this.service.alarm(); }
            async triggerAlarm() { await this.service.alarm(); }
          }
        ` },
        'index.js': { type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8') },
        'index_bg.wasm': { type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm') },
      } },
      exports: {
        OsAuthority: { type: 'durable-object', storage: 'sqlite' },
        Machine: { type: 'durable-object', storage: 'sqlite' },
      },
      env: {
        AUTHORITY: { type: 'durable-object', worker: 'cloudfs-l2-boundary', exportName: 'OsAuthority' },
        MACHINE: { type: 'durable-object', worker: 'cloudfs-l2-boundary', exportName: 'Machine' },
        FILES: { type: 'r2', name: 'files' },
        ADMIN_PASSWORD: { type: 'text', value: adminPassword },
        SESSION_SECRET: { type: 'text', value: randomUUID() },
        ASSETS: { type: 'fetcher', handler: req => {
          const url = new URL(req.url);
          if (url.pathname === '/usr/manifest.json') {
            return new Response(JSON.stringify({ '/usr/bin/coreutils.wasm': 64 }), { headers: { 'Content-Type': 'application/json' } });
          }
          return new Response(new Uint8Array(64));
        } },
      },
    } }],
  });
  t.after(() => mf.dispose());
  const namespace = await mf.getDurableObjectNamespace('AUTHORITY');
  const authority = namespace.get(namespace.idFromName('filesystem'));
  const bucket = await mf.getR2Bucket('FILES');

  const guestKey = randomBytes(32).toString('hex');
  const guestCookie = `os_guest=${guestKey}`;
  const nsHash = 'guest.' + createHash('sha256').update(guestKey).digest('base64url');
  const postAuthority = async (path, value, headers = {}) => {
    const body = JSON.stringify(value);
    const response = await authority.fetch('https://authority' + path, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': String(Buffer.byteLength(body)),
        Cookie: guestCookie,
        ...headers,
      },
      body,
    });
    return response.json();
  };

  await postAuthority('/api/sys', { calls: ['getcreds'] });
  const sql = await mf.unsafeGetDurableObjectStorage('cloudfs-l2-boundary', 'OsAuthority', { name: 'filesystem' });
  assert.equal((await sql.exec("SELECT v FROM meta WHERE k = 'schema'"))[0].v, '10');

  const now = Math.floor(Date.now() / 1000);
  const rootToken = randomUUID(), rootHash = createHash('sha256').update(rootToken).digest('base64url');
  await sql.exec(
    'INSERT INTO credentials(token,ns,pid,uid,gid,groups,umask,started,owner,expires,cloud_access) VALUES(?,?,?,?,?,?,?,?,?,?,1)',
    rootHash, nsHash, 10, 0, 0, '[0]', 0o022, now, `${nsHash} 10 ${rootHash}`, now + 600,
  );
  await sql.exec(
    "INSERT INTO users(id,name,gid,groups,home,locked,salt,hash) VALUES(1000,'alice',1000,'[1000,27]','/home/alice',0,'','')",
  );
  await sql.exec("INSERT INTO unix_groups(id,name) VALUES(1000,'alice')");
  const aliceToken = randomUUID(), aliceHash = createHash('sha256').update(aliceToken).digest('base64url');
  await sql.exec(
    'INSERT INTO credentials(token,ns,pid,uid,gid,groups,umask,started,owner,expires,cloud_access) VALUES(?,?,?,?,?,?,?,?,?,?,1)',
    aliceHash, nsHash, 11, 1000, 1000, '[1000,27]', 0o022, now, `${nsHash} 11 ${aliceHash}`, now + 600,
  );
  const guestToken = randomUUID(), guestHash = createHash('sha256').update(guestToken).digest('base64url');
  await sql.exec(
    'INSERT INTO credentials(token,ns,pid,uid,gid,groups,umask,started,owner,expires,cloud_access) VALUES(?,?,?,?,?,?,?,?,?,?,1)',
    guestHash, nsHash, 12, 1000001, 65534, '[65534]', 0o022, now, `${nsHash} 12 ${guestHash}`, now + 600,
  );

  const rpcAs = (cred, session, call) => postAuthority('/api/fs', { version: 2, credential: cred, session, call });
  const rpc = (session, call) => rpcAs(rootToken, session, call);
  const { session, root } = await rpc(null, 'connect');

  // (a) Seeded root mountpoints & merged-/usr symlinks over /api/fs v2 + EROFS protection.
  const rootEntries = await rpc(session, { read_dir: { dir: root } });
  const rootNames = new Map(rootEntries.map(e => [e.name, e.file_type]));
  for (const dirName of ['usr', 'sys', 'proc', 'dev', 'etc', 'boot', 'mnt', 'opt', 'run', 'srv', 'tmp', 'var']) {
    assert.equal(rootNames.get(dirName), 'dir', `missing seeded directory /${dirName}`);
  }
  for (const [linkName, target] of [['bin', 'usr/bin'], ['sbin', 'usr/bin'], ['lib', 'usr/lib'], ['lib64', 'usr/lib']]) {
    assert.equal(rootNames.get(linkName), 'symlink', `missing seeded symlink /${linkName}`);
    const looked = await rpc(session, { lookup: { dir: root, name: linkName } });
    assert.equal(looked.metadata.file_type, 'symlink');
    assert.equal(await rpc(session, { read_link: { handle: looked.handle } }), target);
    assert.equal((await rpc(session, { unlink: { dir: root, name: linkName } })).errno, 'EROFS');
  }
  for (const [parts, expectedMode] of [
    [['usr'], 0o755],
    [['sys'], 0o555],
    [['proc'], 0o555],
    [['dev', 'pts'], 0o755],
    [['dev', 'present'], 0o755],
    [['dev', 'snd'], 0o755],
    [['mnt', 'local'], 0o755],
    [['mnt', 'shared'], 0o755],
    [['opt', 'private'], 0o755],
    [['tmp'], 0o1777],
  ]) {
    const walked = await rpc(session, { walk: { dir: root, names: parts } });
    assert.equal(walked.stop, null, `walk failed for /${parts.join('/')}`);
    assert.equal(walked.entries.at(-1).metadata.file_type, 'dir');
    assert.equal(walked.entries.at(-1).metadata.mode, expectedMode);
  }
  const usrEntry = await rpc(session, { lookup: { dir: root, name: 'usr' } });
  const sysEntry = await rpc(session, { lookup: { dir: root, name: 'sys' } });
  const procEntry = await rpc(session, { lookup: { dir: root, name: 'proc' } });
  const etcEntry = await rpc(session, { lookup: { dir: root, name: 'etc' } });
  const passwdEntry = await rpc(session, { lookup: { dir: etcEntry.handle, name: 'passwd' } });
  const groupEntry = await rpc(session, { lookup: { dir: etcEntry.handle, name: 'group' } });
  assert.equal((await rpc(session, { mkdir: { dir: usrEntry.handle, name: 'local2', mode: 0o755, umask: 0o022 } })).errno, 'EROFS');
  assert.equal((await rpc(session, { rmdir: { dir: root, name: 'usr' } })).errno, 'EROFS');
  assert.equal((await rpc(session, { mkdir: { dir: sysEntry.handle, name: 'kernel', mode: 0o755, umask: 0o022 } })).errno, 'EROFS');
  assert.equal((await rpc(session, { rmdir: { dir: root, name: 'sys' } })).errno, 'EROFS');
  assert.equal((await rpc(session, { mkdir: { dir: procEntry.handle, name: 'fake', mode: 0o755, umask: 0o022 } })).errno, 'EROFS');
  assert.equal((await rpc(session, { unlink: { dir: etcEntry.handle, name: 'passwd' } })).errno, 'EROFS');
  assert.equal((await rpc(session, { unlink: { dir: etcEntry.handle, name: 'group' } })).errno, 'EROFS');

  // (b) v2 Statfs free blocks > 0, and non-root signed-in Mknod on /dev/present and /dev/snd.
  const statfs = await rpc(session, 'statfs');
  const expectedFree = Number((1n << 50n) / 4096n);
  assert.equal(statfs.block_size, 4096);
  assert.equal(statfs.blocks_free, expectedFree);
  assert.ok(statfs.blocks >= statfs.blocks_free);
  assert.equal(statfs.files_free, expectedFree);
  assert.ok(statfs.files >= statfs.files_free);
  assert.equal(statfs.name_max, 255);

  const tmp = await rpc(session, { lookup: { dir: root, name: 'tmp' } });
  for (const driver of ['present', 'snd']) {
    const devDir = (await rpc(session, { walk: { dir: root, names: ['dev', driver] } })).entries.at(-1).handle;
    assert.equal(
      (await rpcAs(guestToken, session, { mknod: { dir: devDir, name: 'guest-dev', mode: 0o644, umask: 0o022, rdev: driver } })).errno,
      'EPERM',
    );
    assert.equal(
      (await rpcAs(aliceToken, session, { mknod: { dir: tmp.handle, name: 'wrong-dir', mode: 0o644, umask: 0o022, rdev: driver } })).errno,
      'EPERM',
    );
    const createdDev = await rpcAs(aliceToken, session, {
      mknod: { dir: devDir, name: 'alice-' + driver, mode: 0o666, umask: 0o022, rdev: driver },
    });
    assert.equal(createdDev.metadata.file_type, 'char-device');
    assert.equal(createdDev.metadata.uid, 1000);
    assert.equal(createdDev.metadata.rdev, driver);
    assert.equal(await rpcAs(aliceToken, session, { unlink: { dir: devDir, name: 'alice-' + driver } }), null);
  }

  // (c) remote_fs::Call::Clone (FICLONE) over v2 OpenRefs + access & type denials.
  const opts = (overrides = {}) => ({
    read: false, write: false, append: false, append_implies_write: false,
    truncate: false, create: false, create_new: false, exec: false, path: false,
    ...overrides,
  });
  const [srcEntry, srcInit] = await rpc(session, {
    create: { ticket: randomUUID(), dir: tmp.handle, name: 'clone-src', mode: 0o700, umask: 0, options: opts({ read: true, write: true, create: true, create_new: true }) },
  });
  const writeSrc = { version: 2, credential: rootToken, pid: 10, session, open: srcInit, operation: { write: { at: 'end', length: 12 } } };
  const srcPrep = await postAuthority('/internal/fs/data', { request: writeSrc });
  await bucket.put(srcPrep.key, 'hello world!');
  await postAuthority('/internal/fs/commit', { request: writeSrc, id: srcPrep.id });
  await rpc(session, { release: { open: srcInit } });

  const [dstEntry, dstWrite] = await rpcAs(aliceToken, session, {
    create: { ticket: randomUUID(), dir: tmp.handle, name: 'clone-dst', mode: 0o600, umask: 0, options: opts({ write: true, create: true, create_new: true }) },
  });
  // Alice cannot open root's 0700 clone-src for reading -> EACCES.
  assert.equal((await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: srcEntry.handle, options: opts({ read: true }) } })).errno, 'EACCES');
  await rpc(session, { setattr: { handle: srcEntry.handle, attr: { mode: 0o755, uid: null, gid: null, size: null, atime: 'omit', mtime: 'omit' } } });

  // Exec-only and write-only source OpenRefs cannot clone -> EBADF; read-only target cannot be cloned into -> EBADF.
  const srcExec = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: srcEntry.handle, options: opts({ exec: true }) } });
  assert.equal((await rpcAs(aliceToken, session, { clone: { source: srcExec, target: dstWrite } })).errno, 'EBADF');
  const srcPath = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: srcEntry.handle, options: opts({ path: true }) } });
  assert.equal((await rpcAs(aliceToken, session, { clone: { source: srcPath, target: dstWrite } })).errno, 'EBADF');
  const srcRead = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: srcEntry.handle, options: opts({ read: true }) } });
  const dstRead = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: dstEntry.handle, options: opts({ read: true }) } });
  assert.equal((await rpcAs(aliceToken, session, { clone: { source: srcRead, target: dstRead } })).errno, 'EBADF');
  // Same-inode clone -> EINVAL; directory clone -> EISDIR; generated /etc/passwd source -> EOPNOTSUPP.
  const dstRw = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: dstEntry.handle, options: opts({ read: true, write: true }) } });
  assert.equal((await rpcAs(aliceToken, session, { clone: { source: dstRw, target: dstWrite } })).errno, 'EINVAL');
  const tmpRead = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: tmp.handle, options: opts({ read: true }) } });
  assert.equal((await rpcAs(aliceToken, session, { clone: { source: tmpRead, target: dstWrite } })).errno, 'EISDIR');
  const passwdRead = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: passwdEntry.handle, options: opts({ read: true }) } });
  assert.equal((await rpcAs(aliceToken, session, { clone: { source: passwdRead, target: dstWrite } })).errno, 'EOPNOTSUPP');
  // OpenRef from an unrelated namespace -> EACCES.
  const otherGuestKey = randomBytes(32).toString('hex');
  const otherNs = 'guest.' + createHash('sha256').update(otherGuestKey).digest('base64url');
  const otherToken = randomUUID(), otherHash = createHash('sha256').update(otherToken).digest('base64url');
  await sql.exec(
    'INSERT INTO credentials(token,ns,pid,uid,gid,groups,umask,started,owner,expires,cloud_access) VALUES(?,?,?,?,?,?,?,?,?,?,1)',
    otherHash, otherNs, 99, 0, 0, '[0]', 0o022, now, `${otherNs} 99`, now + 600,
  );
  const otherConn = await postAuthority('/api/fs', { version: 2, credential: otherToken, session: null, call: 'connect' }, { Cookie: `os_guest=${otherGuestKey}` });
  assert.equal((await postAuthority('/api/fs', { version: 2, credential: otherToken, session: otherConn.session, call: { clone: { source: srcRead, target: dstWrite } } }, { Cookie: `os_guest=${otherGuestKey}` })).errno, 'EACCES');

  // Valid O(1) FICLONE succeeds, shares R2 extent key, and survives source unlink + alarm GC.
  assert.equal(await rpcAs(aliceToken, session, { clone: { source: srcRead, target: dstWrite } }), null);
  assert.equal((await rpcAs(aliceToken, session, { open_metadata: { open: dstWrite } })).size, 12);
  const readClonedDenied = await mf.dispatchFetch('http://localhost/api/file?path=/tmp/clone-dst', {
    headers: { Cookie: guestCookie },
  });
  assert.equal(readClonedDenied.status, 401);
  await rpcAs(aliceToken, session, { setattr: { handle: dstEntry.handle, attr: { mode: 0o644, uid: null, gid: null, size: null, atime: 'omit', mtime: 'omit' } } });
  const readCloned = await mf.dispatchFetch('http://localhost/api/file?path=/tmp/clone-dst', {
    headers: { Cookie: guestCookie },
  });
  assert.equal(readCloned.status, 200);
  assert.equal(await readCloned.text(), 'hello world!');
  for (const o of [srcExec, srcPath, srcRead, dstRead, dstRw, tmpRead, passwdRead]) {
    await rpcAs(aliceToken, session, { release: { open: o } });
  }
  await rpc(session, { unlink: { dir: tmp.handle, name: 'clone-src' } });
  await authority.triggerAlarm();
  assert.equal(await (await bucket.get(srcPrep.key))?.text(), 'hello world!');
  await rpcAs(aliceToken, session, { release: { open: dstWrite } });

  // (d) Server boundary denial for non-job X-Process-Token on v1 /api/sys path calls, while
  // /proc status, /api/fs v2 handles, InotifyAddWatch(handle), /dev/archive PathAt.open, and
  // /internal/exec LocalExecutable + chroot/no-usr-fallback work.
  const initRes = await mf.dispatchFetch('http://localhost/api/sys', {
    method: 'POST',
    headers: { Origin: 'http://localhost', Cookie: guestCookie, 'Content-Type': 'application/json', 'X-Registry': '1' },
    body: JSON.stringify({ calls: [{ proc_init: { boot: 'boot-1' } }] }),
  });
  assert.equal(initRes.status, 200);
  const execRes = await mf.dispatchFetch('http://localhost/api/sys', {
    method: 'POST',
    headers: { Origin: 'http://localhost', Cookie: guestCookie, 'Content-Type': 'application/json', 'X-Registry': '1' },
    body: JSON.stringify({
      calls: [{
        execve: {
          path: '/usr/bin/coreutils',
          argv: ['ls', '/tmp'],
          env: [],
          cwd: '/',
          runtime: 'resources-v1',
          local: { digest: 'b'.repeat(64), size: 64, cloud: true },
        },
      }],
    }),
  });
  const execReply = await execRes.json();
  assert.equal(execReply.results[0].err, undefined);
  const liveProc = execReply.results[0].ok;
  assert.ok(liveProc.token);
  assert.equal(liveProc.asset, undefined);

  // Chroot / no-usr-fallback prevents /internal/exec from resolving server /usr behind client's back.
  for (const extraHeaders of [{ 'X-OS-Chroot': '1' }, { 'X-OS-No-Usr-Fallback': '1' }]) {
    const chrootExec = await mf.dispatchFetch('http://localhost/api/sys', {
      method: 'POST',
      headers: {
        Origin: 'http://localhost',
        Cookie: guestCookie,
        'Content-Type': 'application/json',
        'X-Registry': '1',
        ...extraHeaders,
      },
      body: JSON.stringify({ calls: [{ execve: { path: '/usr/bin/coreutils', argv: ['coreutils'], cwd: '/' } }] }),
    });
    assert.equal((await chrootExec.json()).results[0].err.errno, 'ENOENT');
  }

  // Conflicting X-Process-Token header vs JSON proc is rejected with EPERM.
  const conflict = await postAuthority('/api/sys', { proc: aliceToken, calls: ['getcreds'] }, { 'X-Process-Token': liveProc.token });
  assert.equal(conflict.results[0].err.errno, 'EPERM');

  const sysWithHeader = call => postAuthority('/api/sys', { pid: liveProc.pid, calls: [call] }, { 'X-Process-Token': liveProc.token });
  for (const denied of [
    { stat: { path: '/etc/passwd' } },
    { lstat: { path: '/bin' } },
    { getdents: { path: '/' } },
    { access: { path: '/tmp', mode: 4 } },
    { readlink: { path: '/bin' } },
    { mkdir: { path: '/tmp/escaped', mode: 0o755 } },
    { mknod: { path: '/tmp/escaped-reg', mode: 0o644 } },
    { rmdir: { path: '/tmp' } },
    { unlink: { path: '/tmp/clone-dst' } },
    { rename: { from: '/tmp/clone-dst', to: '/tmp/moved' } },
    { link: { from: '/tmp/clone-dst', to: '/tmp/linked' } },
    { symlink: { target: '/etc/passwd', path: '/tmp/sym' } },
    { chmod: { path: '/tmp/clone-dst', mode: 0o644 } },
    { chown: { path: '/tmp/clone-dst', uid: 0 } },
    { utimens: { path: '/tmp/clone-dst' } },
    { statfs: { path: '/' } },
    { getxattr: { path: '/tmp/clone-dst', name: 'user.x' } },
    { listxattr: { path: '/tmp/clone-dst' } },
    { setxattr: { path: '/tmp/clone-dst', name: 'user.x', value: 'YQ==' } },
    { removexattr: { path: '/tmp/clone-dst', name: 'user.x' } },
    { open_at: { dirfd: 3, path: 'passwd', flags: 0 } },
    { fstat_at: { dirfd: 3, path: 'passwd' } },
    { inotify_add_watch: { path: '/tmp' } },
    { open: { path: '/etc/passwd', flags: 0 } },
    { open: { path: '/dev/../etc/passwd', flags: 0 } },
    { stat: { path: '/proc/self/fd/0' } },
    { pread: { path: '/etc/passwd', count: 32 } },
  ]) {
    const res = await sysWithHeader(denied);
    assert.equal(res.results[0].err?.errno, 'EPERM', `expected EPERM for ${JSON.stringify(denied)}, got ${JSON.stringify(res)}`);
  }
  // Body `proc` token is equally gated at the server boundary.
  assert.equal((await postAuthority('/api/sys', { pid: liveProc.pid, proc: liveProc.token, calls: [{ stat: { path: '/etc/passwd' } }] })).results[0].err.errno, 'EPERM');

  // Allowed calls with X-Process-Token: Getcreds, read-only /proc status/cmdline, /api/fs v2 handles,
  // InotifyAddWatch with verified Handle, and /dev/archive with v2 PathAt.open.
  assert.ok((await sysWithHeader('getcreds')).results[0].ok.uid > 0);
  const procStatus = await sysWithHeader({ pread: { path: `/proc/${liveProc.pid}/status`, count: 512 } });
  assert.ok(Buffer.from(procStatus.results[0].ok.data, 'base64').toString().includes(`Pid:\t${liveProc.pid}`));
  const procCmdline = await sysWithHeader({ pread: { path: `/proc/${liveProc.pid}/cmdline`, count: 512 } });
  assert.equal(Buffer.from(procCmdline.results[0].ok.data, 'base64').toString(), 'ls\0/tmp\0');

  const procConn = await rpcAs(liveProc.token, null, 'connect');
  assert.ok(procConn.session);
  const procTmp = await rpcAs(liveProc.token, procConn.session, { lookup: { dir: procConn.root, name: 'tmp' } });
  assert.equal(procTmp.metadata.file_type, 'dir');

  const forgedHandle = { ...procTmp.handle, proof: 'forged-proof' };
  assert.equal((await sysWithHeader({ inotify_add_watch: { path: '/ignored', handle: forgedHandle } })).results[0].err.errno, 'EACCES');
  const watchRes = await sysWithHeader({ inotify_add_watch: { path: '/ignored-outside-chroot', handle: procTmp.handle } });
  assert.equal(typeof watchRes.results[0].ok, 'number');
  assert.equal((await sysWithHeader({ inotify_rm_watch: { wd: watchRes.results[0].ok } })).results[0].ok, null);

  // /dev/archive Open + SUBMIT with PathAt.open (v2 OpenRef) + Close.
  const tmpDirOpen = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: tmp.handle, options: opts({ path: true }) } });
  const dstFileOpen = await rpcAs(aliceToken, session, { open: { ticket: randomUUID(), handle: dstEntry.handle, options: opts({ path: true }) } });
  const sysAlice = call => postAuthority('/api/sys', { pid: 11, calls: [call] }, { 'X-Process-Token': aliceToken });
  const devOpen = await sysAlice({ open: { path: '/dev/archive', flags: 2 } });
  assert.equal(devOpen.results[0].ok.device, 'archive');
  const archiveFd = devOpen.results[0].ok.fd;
  // File OpenRef as directory -> ENOTDIR.
  const badSubmit = await sysAlice({
    ioctl: {
      fd: archiveFd,
      request: 0x54570101,
      arg: {
        version: 1,
        request: 'req-bad',
        operation: {
          operation: 'create',
          format: 'tar',
          output: { directory: 0, open: dstFileOpen, name: 'out.tar' },
          inputs: [{ source: { directory: 0, open: tmpDirOpen, name: 'clone-dst' }, name: 'clone-dst' }],
          recursive: false,
          links: false,
          verbose: false,
        },
      },
    },
  });
  assert.equal(badSubmit.results[0].err.errno, 'ENOTDIR');
  const okSubmit = await sysAlice({
    ioctl: {
      fd: archiveFd,
      request: 0x54570101,
      arg: {
        version: 1,
        request: 'req-ok',
        operation: {
          operation: 'create',
          format: 'tar',
          output: { directory: 0, open: tmpDirOpen, name: 'out.tar' },
          inputs: [{ source: { directory: 0, open: tmpDirOpen, name: 'clone-dst' }, name: 'clone-dst' }],
          recursive: false,
          links: false,
          verbose: false,
        },
      },
    },
  });
  assert.ok(okSubmit.results[0].ok.id, JSON.stringify(okSubmit));
  assert.ok('ok' in (await sysAlice({ close: { fd: archiveFd } })).results[0]);

  // Wheel account with active sudo_until admits LocalExecutable as uid 0 (for ImageFs / chroot sudo).
  const aliceSessionToken = randomBytes(32).toString('hex');
  const aliceSessionKey = createHash('sha256').update(aliceSessionToken).digest('base64url');
  await sql.exec(
    'INSERT INTO sessions(key, uid, expires, sudo_until) VALUES(?, 1000, ?, ?)',
    aliceSessionKey, now + 600, now + 300,
  );
  const aliceCookie = `os_session=${aliceSessionToken}; ${guestCookie}`;
  const sudoInit = await mf.dispatchFetch('http://localhost/api/sys', {
    method: 'POST',
    headers: { Origin: 'http://localhost', Cookie: aliceCookie, 'Content-Type': 'application/json', 'X-Registry': '1' },
    body: JSON.stringify({ calls: [{ proc_init: { boot: 'boot-sudo' } }] }),
  });
  assert.equal(sudoInit.status, 200);
  const sudoExec = await mf.dispatchFetch('http://localhost/api/sys', {
    method: 'POST',
    headers: { Origin: 'http://localhost', Cookie: aliceCookie, 'Content-Type': 'application/json', 'X-Registry': '1' },
    body: JSON.stringify({
      sudo: true,
      calls: [{
        execve: {
          path: '/usr/bin/coreutils',
          argv: ['id'],
          env: [],
          cwd: '/',
          runtime: 'resources-v1:chroot',
          local: { digest: 'c'.repeat(64), size: 64, cloud: true },
        },
      }],
    }),
  });
  const sudoProc = (await sudoExec.json()).results[0].ok;
  assert.ok(sudoProc?.token);
  const sudoCreds = await postAuthority(
    '/api/sys',
    { pid: sudoProc.pid, calls: ['getcreds'] },
    { Cookie: aliceCookie, 'X-Process-Token': sudoProc.token },
  );
  assert.equal(sudoCreds.results[0].ok.uid, 0);

  // Stale schema "9" is refused without SQL migration (contract §2.12).
  const freshStale = namespace.get(namespace.idFromName('stale-schema-9-cold'));
  const coldSql = await mf.unsafeGetDurableObjectStorage('cloudfs-l2-boundary', 'OsAuthority', { name: 'stale-schema-9-cold' });
  await coldSql.exec('CREATE TABLE users(id INTEGER PRIMARY KEY)');
  await coldSql.exec('CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)');
  await coldSql.exec("INSERT INTO meta(k, v) VALUES('schema', '9')");
  await assert.rejects(
    () =>
      freshStale.fetch('https://authority/api/sys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': '22' },
        body: '{"calls":["getcreds"]}',
      }),
    /older version|not migrated/i,
  );
});
