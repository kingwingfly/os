// Requires the built Worker: (cd crates/worker && worker-build --release), then
// node --test tests/cloudfs-authority.mjs. All bindings/storage are disposable.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
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
  const sysOpen = await post('/api/sys', { proc: token, calls: [{ open: { path: '/tmp/in-flight', flags: 1 | 64 | 512, mode: 0o644, size: 100 } }] });
  const uploadFd = sysOpen.results[0].ok.fd;
  const inFlight = await rpc(session, { lookup: { dir: tmp.handle, name: 'in-flight' } });
  assert.equal((await rpc(session, { open: { ticket: randomUUID(), handle: inFlight.handle, options: openOpts } })).errno, 'EBUSY');
  assert.equal((await rpc(session, { create: { ticket: randomUUID(), dir: tmp.handle, name: 'in-flight', mode: 0o644, umask: 0o022, options: { ...rwOpts, create_new: false } } })).errno, 'EBUSY');
  assert.equal((await rpc(session, { link: { target: inFlight.handle, dir: tmp.handle, name: 'in-flight-alias' } })).errno, 'EBUSY');
  const pathOpen = await rpc(session, { open: { ticket: randomUUID(), handle: inFlight.handle, options: { ...openOpts, read: false, write: false, path: true } } });
  assert.ok(pathOpen.id, pathOpen.errno);
  await rpc(session, { unlink: { dir: tmp.handle, name: 'in-flight' } });
  const discarded = await post('/api/sys', { proc: token, calls: [{ discard: { fd: uploadFd } }] });
  assert.equal(discarded.results[0].ok.discarded, true);
  const pinnedNode = (await sql.exec('SELECT file, size FROM inodes WHERE id = ?', inFlight.handle.node.ino))[0];
  assert.equal(pinnedNode.file, null);
  assert.equal(pinnedNode.size, 0);
  await rpc(session, { release: { open: pathOpen } });
  assert.equal((await sql.exec('SELECT count(*) AS n FROM inodes WHERE id = ?', inFlight.handle.node.ino))[0].n, 0);
});
