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
