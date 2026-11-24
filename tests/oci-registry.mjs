// Build crates/worker with worker-build --release first. Every account, DO and bucket here
// belongs to disposable Miniflare instances. Exercises OCI-01..OCI-05 against real SQLite DO + R2.
import {after, before, test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash, pbkdf2Sync, randomBytes, randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {Miniflare} from 'miniflare';

const origin = 'http://localhost';
const workerName = 'oci-registry-test';
const clock = {sec: 1, nsec: 0};

const sha = bytes => createHash('sha256').update(bytes).digest();
const shaHex = bytes => sha(bytes).toString('hex');
const shaDigest = bytes => `sha256:${shaHex(bytes)}`;
const digestArr = bytes => [...sha(bytes)];
const opId = () => [...randomBytes(16)];
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const cat = (...parts) => Buffer.concat(parts.map(p => Buffer.from(p)));

function pbkdf2Hex(password, salt) {
  return pbkdf2Sync(Buffer.from(password, 'utf8'), Buffer.from(salt, 'utf8'), 100000, 32, 'sha256').toString('hex');
}

function pack(blocks) {
  let offset = 0;
  const entries = blocks.map(bytes => {
    const entry = {digest: digestArr(bytes), offset, len: bytes.length, raw_len: bytes.length, flags: 0};
    offset += bytes.length;
    return entry;
  });
  const index = cat(
    'COWP', u16(1), u32(entries.length),
    ...entries.map(e => cat(e.digest, u32(e.offset), u32(e.len), u32(e.raw_len), u16(0))),
  );
  const bytes = cat(...blocks, index, u32(index.length), sha(index), 'COWP');
  return {bytes, entries, id: shaHex(bytes)};
}

function tree(volume, extents = [], generation = 1) {
  function item(ino, kind, tail, value) {
    return cat(u64(ino), [kind], u16(tail.length), tail, u32(value.length), value);
  }
  function inode(isDir, size) {
    return cat(
      [1, isDir ? 2 : 1], u16(isDir ? 0o755 : 0o644), u32(isDir ? 2 : 1), u32(0), u32(0),
      u64(size), u64(1), Buffer.alloc(36), u64(isDir && extents.length ? 2 : 1), [0, 0, 0],
    );
  }
  const items = [item(1, 1, [], inode(true, 0))];
  if (extents.length) {
    const file = Buffer.from('data');
    items.push(
      item(1, 0x20, file, cat(u64(2), u64(1), [1], u64(1))),
      item(1, 0x21, u64(1), cat(u64(2), u64(1), [1], u16(file.length), file)),
      item(2, 1, [], inode(false, extents.reduce((n, e) => n + e.len, 0))),
      item(2, 0x10, cat(u64(1), file), Buffer.alloc(0)),
    );
    let pos = 0;
    for (const e of extents) {
      items.push(item(2, 0x30, u64(pos), cat([1], u32(e.len), e.digest, u32(0))));
      pos += e.len;
    }
  }
  const leaf = cat('COWN', u16(1), [0, 0], u32(items.length), ...items);
  const root = cat(
    'OSCOWFS1', u32(1), u64(0), u16(volume.length), volume, u64(3), u64(generation), [0], u32(1),
    u16(1), '@', sha(leaf),
  );
  return {
    root: digestArr(root),
    rootHex: shaHex(root),
    nodes: [[digestArr(leaf), [...leaf]], [digestArr(root), [...root]]],
    rawNodes: [[sha(leaf), leaf], [sha(root), root]],
  };
}

function encodeNodePack(rawNodes) {
  const sorted = [...rawNodes].sort((a, b) => Buffer.compare(a[0], b[0]));
  return cat(
    'COWNP1\0\0', u16(1), u32(sorted.length),
    ...sorted.map(([d, b]) => cat(d, u32(b.length), b)),
  );
}

function encodeBlockDir(packHexes, entries) {
  // entries: [{digestBuf, packIdx, offset, len}]
  const sorted = [...entries].sort((a, b) => Buffer.compare(a.digestBuf, b.digestBuf));
  return cat(
    'COWBD1\0\0', u16(1), u32(packHexes.length),
    ...packHexes.map(h => Buffer.from(h, 'hex')),
    u32(sorted.length),
    ...sorted.map(e => cat(e.digestBuf, u32(e.packIdx), u32(e.offset), u32(e.len))),
  );
}

function decodeBlockDir(buf) {
  assert.equal(buf.subarray(0, 8).toString('binary'), 'COWBD1\0\0');
  assert.equal(buf.readUInt16BE(8), 1);
  let pos = 10;
  const packCount = buf.readUInt32BE(pos); pos += 4;
  const packs = [];
  for (let i = 0; i < packCount; i++) {
    packs.push(buf.subarray(pos, pos + 32).toString('hex'));
    pos += 32;
  }
  const entryCount = buf.readUInt32BE(pos); pos += 4;
  const blocks = new Map();
  for (let i = 0; i < entryCount; i++) {
    const bHex = buf.subarray(pos, pos + 32).toString('hex'); pos += 32;
    const packIdx = buf.readUInt32BE(pos); pos += 4;
    const offset = buf.readUInt32BE(pos); pos += 4;
    const len = buf.readUInt32BE(pos); pos += 4;
    blocks.set(bHex, {packId: packs[packIdx], offset, len});
  }
  return {packs, blocks};
}

async function createInstance(name = workerName, adminPass = 'root-pass-' + randomUUID()) {
  const classes = ['OsAuthority', 'Machine', 'StorageVolume'];
  const mf = new Miniflare({
    port: 0,
    unsafeInspectDurableObjects: true,
    workers: [{
      config: {
        name,
        compatibilityDate: '2026-10-24',
        manifest: {
          mainModule: 'harness.js',
          modules: {
            'harness.js': {
              type: 'esm',
              contents: `
        import { DurableObject } from 'cloudflare:workers';
        import { OsAuthority as Authority, Machine as Service, StorageVolume as Volume } from './index.js';
        export { default } from './index.js';
        export class OsAuthority extends DurableObject {
          constructor(ctx,env){super(ctx,env);this.impl=new Authority(ctx,env);}
          fetch(r){return this.impl.fetch(r);}
          alarm(){return this.impl.alarm();}
        }
        export class Machine extends DurableObject {
          constructor(ctx,env){super(ctx,env);this.impl=new Service(ctx,env);}
          fetch(r){return this.impl.fetch(r);}
          alarm(){return this.impl.alarm();}
        }
        export class StorageVolume extends DurableObject {
          constructor(ctx,env){super(ctx,env);this.bindings=env;this.impl=new Volume(ctx,env);}
          coldStart(){this.impl=new Volume(this.ctx,this.bindings);}
          fetch(r){return this.impl.fetch(r);}
          alarm(){return this.impl.alarm();}
          async triggerAlarm(){await this.impl.alarm();}
        }`,
            },
            'index.js': {type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8')},
            'index_bg.wasm': {type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm')},
          },
        },
        exports: Object.fromEntries(classes.map(n => [n, {type: 'durable-object', storage: 'sqlite'}])),
        env: {
          ...Object.fromEntries(['AUTHORITY', 'MACHINE', 'STORAGE'].map(
            (binding, i) => [binding, {type: 'durable-object', worker: name, exportName: classes[i]}],
          )),
          FILES: {type: 'r2', name: 'files-' + name},
          ADMIN_PASSWORD: {type: 'text', value: adminPass},
          SESSION_SECRET: {type: 'text', value: 'sec-' + randomUUID()},
          VOLUME_QUOTA_BYTES: {type: 'text', value: String(3 * 1024 * 1024)},
          ASSETS: {
            type: 'fetcher',
            handler: () => new Response('{}', {headers: {'Content-Type': 'application/json'}}),
          },
        },
      },
    }],
  });

  const post = (path, body, headers = {}) => mf.dispatchFetch(origin + path, {
    method: 'POST',
    headers: {Origin: origin, 'Content-Type': 'application/json', ...headers},
    body: JSON.stringify(body),
  });
  const good = async response => {
    const res = await response;
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    return body;
  };

  await good(post('/api/sys', {calls: ['getcreds']}));
  const authoritySql = await mf.unsafeGetDurableObjectStorage(name, 'OsAuthority', {name: 'filesystem'});
  const aliceSalt = randomBytes(16).toString('hex');
  const alicePass = 'alice-pass-' + randomUUID();
  await authoritySql.exec(
    "INSERT INTO users(id,name,gid,groups,home,locked,salt,hash) VALUES(1000,'alice',1000,'[1000]','/home/alice',0,?,?)",
    aliceSalt, pbkdf2Hex(alicePass, aliceSalt),
  );

  const login = async uid => {
    const session = randomBytes(32).toString('hex');
    if (uid !== null) {
      await authoritySql.exec(
        'INSERT INTO sessions(key,uid,expires,sudo_until) VALUES(?,?,?,0)',
        sha(session).toString('base64url'), uid, Math.floor(Date.now() / 1000) + 3600,
      );
    }
    const cookie = uid === null ? `os_guest=${session}` : `os_session=${session}`;
    const instance = 'inst-' + randomUUID();
    const proof = randomBytes(32).toString('hex');
    const auth = value => good(post('/api/service-auth', value, {Cookie: cookie}));
    await auth({attach_instance: {instance: {instance, host: 'test'}, host_proof: proof}});
    const mint = async (scope, limits = {}) => {
      const {cred} = await auth({
        mint_service_cred: {instance_id: instance, host_proof: proof, scope, ...limits},
      });
      return {Cookie: cookie, 'X-OS-Instance': instance, 'X-Process-Token': cred.token};
    };
    return {
      cookie,
      instance,
      session,
      headers: await mint({volumes: true, registry_pull: true, registry_push: true}),
      mint,
      revoke: token => auth({revoke_tokens: {instance_id: instance, host_proof: proof, tokens: [token]}}),
    };
  };

  const root = await login(0);
  const alice = await login(1000);
  const guest = await login(null);
  const rpc = (volume, call, headers = root.headers) => post('/api/volumes/rpc', {version: 1, volume, call}, headers);
  await good(rpc('setup', {op: 'format_version'}));
  const ns = await mf.getDurableObjectNamespace('STORAGE');
  const storage = ns.get(ns.idFromName('tenant:u0'));
  const storageSql = await mf.unsafeGetDurableObjectStorage(name, 'StorageVolume', {name: 'tenant:u0'});
  const bucket = await mf.getR2Bucket('FILES');

  const getToken = async (scope, authHeaders) => {
    const q = scope ? `?service=registry&scope=${encodeURIComponent(scope)}` : '?service=registry';
    const res = await mf.dispatchFetch(origin + '/v2/token' + q, {method: 'GET', headers: authHeaders});
    return res;
  };
  const bearerFor = async (scope, authHeaders = root.headers) => {
    const res = await getToken(scope, authHeaders);
    assert.equal(res.status, 200, `token exchange failed: ${res.status} ${await res.clone().text()}`);
    const data = await res.json();
    assert.ok(data.token && data.token === data.access_token);
    return {Authorization: `Bearer ${data.token}`, _raw: data.token};
  };
  const basicHdr = (u, p) => ({Authorization: `Basic ${Buffer.from(`${u}:${p}`).toString('base64')}`});

  const v2 = (path, {method = 'GET', headers = {}, body} = {}) =>
    mf.dispatchFetch(origin + path, {method, headers, body});

  return {
    mf, authoritySql, storageSql, storage, bucket,
    adminPass, alicePass, root, alice, guest,
    post, good, rpc, getToken, bearerFor, basicHdr, v2,
  };
}

let env;
before(async () => {
  env = await createInstance(workerName);
});
after(async () => {
  if (env?.mf) await env.mf.dispose();
});

test('OCI-01 auth, token exchange, scoping, cross-repo mount, live revocation, and tenant isolation', async () => {
  // Unauthenticated GET /v2/ -> 401 + Docker-Distribution-API-Version + WWW-Authenticate
  const unauth = await env.v2('/v2/');
  assert.equal(unauth.status, 401);
  assert.equal(unauth.headers.get('Docker-Distribution-API-Version'), 'registry/2.0');
  assert.match(unauth.headers.get('WWW-Authenticate') ?? '', /^Bearer realm="/);

  // Bare cookie rejected by /v2/token
  const bareCookie = await env.getToken('repository:org/app:pull', {Cookie: env.root.cookie});
  assert.equal(bareCookie.status, 401);

  // Guest rejected
  const guestTok = await env.getToken('repository:org/app:pull', env.guest.headers);
  assert.ok(guestTok.status === 401 || guestTok.status === 403);

  // HTTP Basic wrong password -> 401; valid root Basic -> 200 + JWT carries only cred_hash (never raw password/token)
  const badBasic = await env.getToken('repository:org/app:pull,push', env.basicHdr('root', 'wrong'));
  assert.equal(badBasic.status, 401);
  const okBasic = await env.bearerFor('repository:org/app:pull,push', env.basicHdr('root', env.adminPass));
  const payload = JSON.parse(Buffer.from(okBasic._raw.split('.')[1], 'base64url').toString('utf8'));
  assert.equal(payload.sub, 'u0');
  assert.equal(payload.cred_hash, undefined, 'Basic JWT must not carry cred_hash');
  assert.ok(!JSON.stringify(payload).includes(env.adminPass), 'Basic JWT must never contain raw password');

  const pingOk = await env.v2('/v2/', {headers: {Authorization: okBasic.Authorization}});
  assert.equal(pingOk.status, 200);
  assert.equal(pingOk.headers.get('Docker-Distribution-API-Version'), 'registry/2.0');

  // C-1 browser compatibility: os_session cookie has Path=/api so browsers send ONLY
  // X-Process-Token + X-OS-Instance (NO Cookie) to /v2/token; must succeed and bind to live session.
  const noCookieHdrs = {
    'X-Process-Token': env.root.headers['X-Process-Token'],
    'X-OS-Instance': env.root.headers['X-OS-Instance'],
  };
  const browserJwt = await env.bearerFor('repository:org/app:pull', noCookieHdrs);
  const browserPayload = JSON.parse(Buffer.from(browserJwt._raw.split('.')[1], 'base64url').toString('utf8'));
  assert.ok(
    browserPayload.cred_hash &&
      !JSON.stringify(browserPayload).includes(env.root.headers['X-Process-Token']),
    'Cookie-less ServiceAuth JWT must carry only cred_hash and never raw token',
  );
  assert.equal((await env.v2('/v2/', {headers: {Authorization: browserJwt.Authorization}})).status, 200);

  // Pull-only scoped ServiceAuth token cannot push, and JWT carries only cred_hash (never raw token)
  const pullOnlyCred = await env.root.mint({registry_pull: true, registry_push: false, registry_repos: ['org/app']});
  const pullOnlyJwt = await env.bearerFor('repository:org/app:pull,push', pullOnlyCred);
  const saPayload = JSON.parse(Buffer.from(pullOnlyJwt._raw.split('.')[1], 'base64url').toString('utf8'));
  assert.ok(
    saPayload.cred_hash && !JSON.stringify(saPayload).includes(pullOnlyCred['X-Process-Token']),
    'ServiceAuth JWT must store only cred_hash and never the raw X-Process-Token',
  );
  const deniedPush = await env.v2('/v2/org/app/blobs/uploads/', {
    method: 'POST',
    headers: {Authorization: pullOnlyJwt.Authorization},
  });
  assert.equal(deniedPush.status, 403);

  // Repo-scoped token (`team/*`) allowed on `team/a`, denied on `other/app`
  const teamCred = await env.root.mint({registry_pull: true, registry_push: true, registry_repos: ['team/*']});
  const teamJwt = await env.bearerFor('repository:team/a:pull,push', teamCred);
  const otherDenied = await env.v2('/v2/other/app/blobs/uploads/', {
    method: 'POST',
    headers: {Authorization: teamJwt.Authorization},
  });
  assert.equal(otherDenied.status, 403);

  // Cross-repo blob mount: upload blob to team/src
  const srcBlob = Buffer.from('cross-repo-secret-blob');
  const srcDig = shaDigest(srcBlob);
  const fullJwt = await env.bearerFor('repository:team/src:pull,push', env.root.headers);
  const up = await env.v2(`/v2/team/src/blobs/uploads/?digest=${encodeURIComponent(srcDig)}`, {
    method: 'POST',
    headers: {Authorization: fullJwt.Authorization, 'Content-Type': 'application/octet-stream'},
    body: srcBlob,
  });
  assert.equal(up.status, 201);

  // Unauthorized cross-repo mount (dst:push ONLY, no src:pull) -> strict 403 DENIED!
  const dstOnlyCred = await env.root.mint({registry_pull: true, registry_push: true, registry_repos: ['team/dst']});
  const dstOnlyJwt = await env.bearerFor('repository:team/dst:push', dstOnlyCred);
  const badMount = await env.v2(
    `/v2/team/dst/blobs/uploads/?mount=${encodeURIComponent(srcDig)}&from=team/src`,
    {method: 'POST', headers: {Authorization: dstOnlyJwt.Authorization}},
  );
  assert.equal(badMount.status, 403);

  // Authorized cross-repo mount (both dst:push AND src:pull) -> 201 Created!
  // Request both scopes via repeated scope query params:
  const bothRes = await env.v2(
    '/v2/token?service=registry&scope=repository:team/dst:push&scope=repository:team/src:pull',
    {headers: env.root.headers},
  );
  assert.equal(bothRes.status, 200);
  const bothTok = (await bothRes.json()).token;
  assert.ok(bothTok);
  const okMount = await env.v2(
    `/v2/team/dst/blobs/uploads/?mount=${encodeURIComponent(srcDig)}&from=team/src`,
    {method: 'POST', headers: {Authorization: `Bearer ${bothTok}`}},
  );
  assert.equal(okMount.status, 201);
  assert.equal(okMount.headers.get('Docker-Content-Digest'), srcDig);

  // Live revocation: RevokeTokens invalidates STILL-UNEXPIRED Bearer JWT immediately!
  const revCred = await env.root.mint({registry_pull: true, registry_push: true});
  const revJwt = await env.bearerFor('repository:team/src:pull', revCred);
  assert.equal((await env.v2('/v2/', {headers: {Authorization: revJwt.Authorization}})).status, 200);
  await env.root.revoke(revCred['X-Process-Token']);
  assert.equal((await env.v2('/v2/', {headers: {Authorization: revJwt.Authorization}})).status, 401);

  // Tenant isolation: alice (u1000) cannot read root's (u0) blob
  const aliceJwt = await env.bearerFor('repository:team/src:pull', env.alice.headers);
  const aliceRead = await env.v2(`/v2/team/src/blobs/${srcDig}`, {
    headers: {Authorization: aliceJwt.Authorization},
  });
  assert.equal(aliceRead.status, 404);

  // Live user lock: UPDATE users SET locked=1 invalidates alice's STILL-UNEXPIRED JWT immediately!
  assert.equal((await env.v2('/v2/', {headers: {Authorization: aliceJwt.Authorization}})).status, 200);
  await env.authoritySql.exec('UPDATE users SET locked=1 WHERE id=1000');
  assert.equal((await env.v2('/v2/', {headers: {Authorization: aliceJwt.Authorization}})).status, 401);
  await env.authoritySql.exec('UPDATE users SET locked=0 WHERE id=1000');
  assert.equal((await env.v2('/v2/', {headers: {Authorization: aliceJwt.Authorization}})).status, 200);
});

test('OCI-02 monolithic & chunked uploads (Content-Range + streaming), Range reads, quota, and io_buckets', async () => {
  const jwt = await env.bearerFor('repository:blobs/demo:pull,push', env.root.headers);
  const authHdr = {Authorization: jwt.Authorization};

  // Monolithic upload + HEAD + GET + Range 206 + Range 416
  const mono = Buffer.from('0123456789abcdefghijklmnopqrstuvwxyz');
  const monoDig = shaDigest(mono);
  const mPut = await env.v2(`/v2/blobs/demo/blobs/uploads/?digest=${encodeURIComponent(monoDig)}`, {
    method: 'POST',
    headers: {...authHdr, 'Content-Type': 'application/octet-stream'},
    body: mono,
  });
  assert.equal(mPut.status, 201);
  assert.equal(mPut.headers.get('Docker-Content-Digest'), monoDig);

  const head = await env.v2(`/v2/blobs/demo/blobs/${monoDig}`, {method: 'HEAD', headers: authHdr});
  assert.equal(head.status, 200);
  assert.equal(head.headers.get('Content-Length'), String(mono.length));
  assert.equal(head.headers.get('Docker-Content-Digest'), monoDig);
  assert.equal(head.headers.get('Accept-Ranges'), 'bytes');

  const part = await env.v2(`/v2/blobs/demo/blobs/${monoDig}`, {
    headers: {...authHdr, Range: 'bytes=4-11'},
  });
  assert.equal(part.status, 206);
  assert.equal(part.headers.get('Content-Range'), `bytes 4-11/${mono.length}`);
  assert.deepEqual(Buffer.from(await part.arrayBuffer()), mono.subarray(4, 12));

  const badRange = await env.v2(`/v2/blobs/demo/blobs/${monoDig}`, {
    headers: {...authHdr, Range: 'bytes=999-1000'},
  });
  assert.equal(badRange.status, 416);

  // Chunked upload: POST -> GET -> PATCH (Content-Range) -> out-of-order 416 -> PATCH (streamed) -> PUT ?digest=
  const init = await env.v2('/v2/blobs/demo/blobs/uploads/', {method: 'POST', headers: authHdr});
  assert.equal(init.status, 202);
  const loc = init.headers.get('Location');
  assert.ok(loc && init.headers.get('Docker-Upload-UUID'));
  assert.equal(init.headers.get('Range'), '0-0');
  assert.equal(init.headers.get('OCI-Chunk-Min-Length'), '1');

  const status0 = await env.v2(loc, {method: 'GET', headers: authHdr});
  assert.equal(status0.status, 204);
  assert.equal(status0.headers.get('Range'), '0-0');

  const c1 = Buffer.from('chunk-one-hello-');
  const c2 = Buffer.from('chunk-two-streamed-');
  const c3 = Buffer.from('chunk-three-final!');
  const fullChunked = Buffer.concat([c1, c2, c3]);
  const fullDig = shaDigest(fullChunked);

  const p1 = await env.v2(loc, {
    method: 'PATCH',
    headers: {...authHdr, 'Content-Type': 'application/octet-stream', 'Content-Range': `0-${c1.length - 1}`},
    body: c1,
  });
  assert.equal(p1.status, 202);
  assert.equal(p1.headers.get('Range'), `0-${c1.length - 1}`);

  // Out-of-order Content-Range -> 416
  const badOrder = await env.v2(loc, {
    method: 'PATCH',
    headers: {...authHdr, 'Content-Type': 'application/octet-stream', 'Content-Range': '99-105'},
    body: Buffer.from('1234567'),
  });
  assert.equal(badOrder.status, 416);

  // Streamed PATCH without Content-Range / Content-Length (Transfer-Encoding: chunked semantics)
  const streamBody = new ReadableStream({
    start(ctrl) {
      ctrl.enqueue(c2.subarray(0, 7));
      ctrl.enqueue(c2.subarray(7));
      ctrl.close();
    },
  });
  const p2 = await env.mf.dispatchFetch(origin + loc, {
    method: 'PATCH',
    headers: {...authHdr, 'Content-Type': 'application/octet-stream'},
    body: streamBody,
    duplex: 'half',
  });
  assert.equal(p2.status, 202);
  assert.equal(p2.headers.get('Range'), `0-${c1.length + c2.length - 1}`);

  // Final PUT with final chunk + digest
  const fin = await env.v2(`${loc}?digest=${encodeURIComponent(fullDig)}`, {
    method: 'PUT',
    headers: {...authHdr, 'Content-Type': 'application/octet-stream'},
    body: c3,
  });
  assert.equal(fin.status, 201);
  assert.equal(fin.headers.get('Docker-Content-Digest'), fullDig);

  const fetched = await env.v2(`/v2/blobs/demo/blobs/${fullDig}`, {headers: authHdr});
  assert.equal(fetched.status, 200);
  assert.deepEqual(Buffer.from(await fetched.arrayBuffer()), fullChunked);

  // Digest mismatch rejected with 400 DIGEST_INVALID
  const badDigestRes = await env.v2(
    `/v2/blobs/demo/blobs/uploads/?digest=sha256:${'0'.repeat(64)}`,
    {method: 'POST', headers: {...authHdr, 'Content-Type': 'application/octet-stream'}, body: Buffer.from('abc')},
  );
  assert.equal(badDigestRes.status, 400);
  const badJson = await badDigestRes.json();
  assert.equal(badJson.errors[0].code, 'DIGEST_INVALID');

  // Quota enforcement (> 3 MiB VOLUME_QUOTA_BYTES rejected with exact 507 EDQUOT!)
  const huge = Buffer.alloc(3 * 1024 * 1024 + 1024, 0x77);
  const quotaRes = await env.v2(
    `/v2/blobs/demo/blobs/uploads/?digest=${encodeURIComponent(shaDigest(huge))}`,
    {method: 'POST', headers: {...authHdr, 'Content-Type': 'application/octet-stream'}, body: huge},
  );
  assert.equal(quotaRes.status, 507);
  assert.equal(quotaRes.headers.get('X-OS-Errno'), 'EDQUOT');

  // Verify Machine DO io_buckets charged read_bytes and write_bytes!
  const nsName = 'session.' + sha(env.root.session).toString('base64url');
  const machineSql = await env.mf.unsafeGetDurableObjectStorage(workerName, 'Machine', {name: nsName});
  const [{r, w}] = await machineSql.exec('SELECT SUM(read_bytes) AS r, SUM(write_bytes) AS w FROM io_buckets');
  assert.ok(r >= mono.length, `expected read_bytes >= ${mono.length}, got ${r}`);
  assert.ok(w >= mono.length + fullChunked.length, `expected write_bytes charged, got ${w}`);
});

test('OCI-03 manifests, tag pagination Link, delete, and OCI 1.1 referrers filtering', async () => {
  const jwt = await env.bearerFor('repository:org/img:pull,push', env.root.headers);
  const authHdr = {Authorization: jwt.Authorization};

  const putBlob = async data => {
    const dig = shaDigest(data);
    const r = await env.v2(`/v2/org/img/blobs/uploads/?digest=${encodeURIComponent(dig)}`, {
      method: 'POST',
      headers: {...authHdr, 'Content-Type': 'application/octet-stream'},
      body: data,
    });
    assert.equal(r.status, 201);
    return {digest: dig, size: data.length};
  };

  const cfg = await putBlob(Buffer.from('{"architecture":"wasm32","os":"wasi","rootfs":{"type":"layers","diff_ids":[]}}'));
  const layer = await putBlob(Buffer.from('layer-payload'));
  const emptyCfg = await putBlob(Buffer.from('{}'));
  const sigBlob = await putBlob(Buffer.from('{"format":"os.signature","version":1,"key":"k1","signature":"aa"}'));
  const sbomBlob = await putBlob(Buffer.from('{"spdxVersion":"SPDX-2.3"}'));

  // Missing blob -> 400 MANIFEST_BLOB_UNKNOWN
  const missingManifest = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {mediaType: 'application/vnd.oci.image.config.v1+json', digest: `sha256:${'f'.repeat(64)}`, size: 2},
    layers: [],
  }));
  const badRef = await env.v2('/v2/org/img/manifests/bad', {
    method: 'PUT',
    headers: {...authHdr, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json'},
    body: missingManifest,
  });
  assert.equal(badRef.status, 400);
  assert.equal((await badRef.json()).errors[0].code, 'MANIFEST_BLOB_UNKNOWN');

  // Digest mismatch on PUT /manifests/sha256:... -> 400 DIGEST_INVALID
  const manifestBytes = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {mediaType: 'application/vnd.oci.image.config.v1+json', digest: cfg.digest, size: cfg.size},
    layers: [{mediaType: 'application/vnd.oci.image.layer.v1.tar', digest: layer.digest, size: layer.size}],
  }));
  const manifestDig = shaDigest(manifestBytes);
  const badDigPut = await env.v2(`/v2/org/img/manifests/sha256:${'1'.repeat(64)}`, {
    method: 'PUT',
    headers: {...authHdr, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json'},
    body: manifestBytes,
  });
  assert.equal(badDigPut.status, 400);
  assert.equal((await badDigPut.json()).errors[0].code, 'DIGEST_INVALID');

  // Push tags v1, v2, v3
  for (const tag of ['v1', 'v2', 'v3']) {
    const r = await env.v2(`/v2/org/img/manifests/${tag}`, {
      method: 'PUT',
      headers: {...authHdr, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json'},
      body: manifestBytes,
    });
    assert.equal(r.status, 201);
    assert.equal(r.headers.get('Docker-Content-Digest'), manifestDig);
  }

  // HEAD/GET preserve exact Content-Type & Docker-Content-Digest
  const mGet = await env.v2('/v2/org/img/manifests/v1', {headers: authHdr});
  assert.equal(mGet.status, 200);
  assert.equal(mGet.headers.get('Content-Type'), 'application/vnd.oci.image.manifest.v1+json');
  assert.equal(mGet.headers.get('Docker-Content-Digest'), manifestDig);
  assert.deepEqual(Buffer.from(await mGet.arrayBuffer()), manifestBytes);

  // tags/list?n=2 pagination with RFC 5988 Link header
  const page1 = await env.v2('/v2/org/img/tags/list?n=2', {headers: authHdr});
  assert.equal(page1.status, 200);
  const p1Json = await page1.json();
  assert.deepEqual(p1Json.tags, ['v1', 'v2']);
  const link = page1.headers.get('Link') ?? '';
  const nextMatch = link.match(/<([^>]+)>;\s*rel="next"/);
  assert.ok(nextMatch, `expected RFC 5988 Link header, got ${link}`);
  const page2 = await env.v2(nextMatch[1], {headers: authHdr});
  assert.equal(page2.status, 200);
  assert.deepEqual((await page2.json()).tags, ['v3']);
  assert.equal(page2.headers.get('Link'), null);

  // Push two OCI 1.1 referrers (signature + sbom) with subject = manifestDig
  const pushReferrer = async (artifactType, blobDesc) => {
    const body = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      artifactType,
      config: {mediaType: 'application/vnd.oci.empty.v1+json', digest: emptyCfg.digest, size: emptyCfg.size},
      layers: [{mediaType: artifactType, digest: blobDesc.digest, size: blobDesc.size}],
      subject: {mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: manifestDig, size: manifestBytes.length},
    }));
    const d = shaDigest(body);
    const r = await env.v2(`/v2/org/img/manifests/${d}`, {
      method: 'PUT',
      headers: {...authHdr, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json'},
      body,
    });
    assert.equal(r.status, 201);
    assert.equal(r.headers.get('OCI-Subject'), manifestDig);
    return d;
  };
  const sigRefDig = await pushReferrer('application/vnd.os.signature.v1+json', sigBlob);
  const sbomRefDig = await pushReferrer('application/vnd.example.sbom+json', sbomBlob);

  // Unfiltered referrers returns both
  const allRefs = await env.v2(`/v2/org/img/referrers/${manifestDig}`, {headers: authHdr});
  assert.equal(allRefs.status, 200);
  assert.equal(allRefs.headers.get('Content-Type'), 'application/vnd.oci.image.index.v1+json');
  const allIdx = await allRefs.json();
  assert.deepEqual(allIdx.manifests.map(m => m.digest).sort(), [sigRefDig, sbomRefDig].sort());

  // Filtered referrers sets OCI-Filters-Applied: artifactType
  const filtRefs = await env.v2(
    `/v2/org/img/referrers/${manifestDig}?artifactType=${encodeURIComponent('application/vnd.os.signature.v1+json')}`,
    {headers: authHdr},
  );
  assert.equal(filtRefs.status, 200);
  assert.equal(filtRefs.headers.get('OCI-Filters-Applied'), 'artifactType');
  const filtIdx = await filtRefs.json();
  assert.deepEqual(filtIdx.manifests.map(m => m.digest), [sigRefDig]);

  // DELETE tag v3 -> 202, GET v3 -> 404 (v1 still exists)
  assert.equal((await env.v2('/v2/org/img/manifests/v3', {method: 'DELETE', headers: authHdr})).status, 202);
  assert.equal((await env.v2('/v2/org/img/manifests/v3', {headers: authHdr})).status, 404);
  assert.equal((await env.v2('/v2/org/img/manifests/v1', {headers: authHdr})).status, 200);
});

test('OCI-04 cross-boundary shared R2 pack GC, abandoned upload sweep, and schema v2 guard', async () => {
  const jwt = await env.bearerFor('repository:gc/shared:pull,push', env.root.headers);
  const authHdr = {Authorization: jwt.Authorization};

  // Create a remote volume and commit a real COWP pack `p`.
  const vol = 'gc-shared-vol';
  const empty = tree(vol);
  await env.good(env.rpc(vol, {
    op: 'create_volume',
    head: {format_version: 1, volume: vol, root: empty.root, incarnation: 1, fence: 0, epoch: 0, updated_at: clock},
    nodes: empty.nodes,
  }));
  const h = (await env.good(env.rpc(vol, {op: 'attach_rw', mode: 'exclusive'}))).attached.head;
  const p = pack([Buffer.from('shared-pack-between-volume-and-oci-registry')]);
  const putPack = await env.mf.dispatchFetch(origin + '/api/volumes/packs/' + p.id, {
    method: 'PUT',
    body: p.bytes,
    headers: {
      Origin: origin,
      ...env.root.headers,
      'X-OS-Volume': h.volume,
      'X-OS-Incarnation': String(h.incarnation),
      'X-OS-Fence': String(h.fence),
    },
  });
  const packMeta = await env.good(putPack);
  const withPack = tree(vol, p.entries, 2);
  const committed = (await env.good(env.rpc(vol, {
    op: 'commit',
    request: {
      op_id: opId(), volume: vol,
      expected_incarnation: h.incarnation, expected_fence: h.fence, expected_epoch: h.epoch,
      new_root: withPack.root, put_nodes: withPack.nodes, put_packs: [packMeta],
      put_blocks: p.entries.map(({digest, ...loc}) => [digest, {pack_id: p.id, ...loc}]),
      committed_at: clock,
    },
  }))).receipt.head;

  // Also register the exact same pack blob & manifest in the OCI registry (shared t/u0/packs/<id>!).
  const packDigest = `sha256:${p.id}`;
  const upPack = await env.v2(`/v2/gc/shared/blobs/uploads/?digest=${encodeURIComponent(packDigest)}`, {
    method: 'POST',
    headers: {...authHdr, 'Content-Type': 'application/octet-stream'},
    body: p.bytes,
  });
  assert.equal(upPack.status, 201);
  const cfgBytes = Buffer.from('{}');
  const cfgDig = shaDigest(cfgBytes);
  assert.equal((await env.v2(`/v2/gc/shared/blobs/uploads/?digest=${encodeURIComponent(cfgDig)}`, {
    method: 'POST', headers: {...authHdr, 'Content-Type': 'application/octet-stream'}, body: cfgBytes,
  })).status, 201);
  const manBytes = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {mediaType: 'application/vnd.oci.empty.v1+json', digest: cfgDig, size: cfgBytes.length},
    layers: [{mediaType: 'application/vnd.os.cowfs.pack.v1', digest: packDigest, size: p.bytes.length}],
  }));
  const manDig = shaDigest(manBytes);
  assert.equal((await env.v2('/v2/gc/shared/manifests/keep', {
    method: 'PUT', headers: {...authHdr, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json'}, body: manBytes,
  })).status, 201);

  // Drop the volume's reference to `p`, expire grace/retention, run GC + alarm().
  const empty2 = tree(vol, [], 3);
  await env.good(env.rpc(vol, {
    op: 'commit',
    request: {
      op_id: opId(), volume: vol,
      expected_incarnation: committed.incarnation, expected_fence: committed.fence, expected_epoch: committed.epoch,
      new_root: empty2.root, put_nodes: empty2.nodes, put_packs: [], put_blocks: [], committed_at: clock,
    },
  }));
  await env.storageSql.exec('UPDATE grace_pins SET expires=0');
  await env.storageSql.exec('UPDATE nodes SET created_at=0');
  await env.storageSql.exec('UPDATE packs SET created_at=0 WHERE pack_id=?', p.id);
  await env.storageSql.exec('UPDATE registry_blobs SET created_at=0 WHERE digest=?', p.id);
  await env.storageSql.exec('UPDATE registry_repo_blobs SET created_at=0 WHERE digest=?', p.id);
  await env.good(env.rpc(vol, {op: 'run_gc'}));
  await env.storageSql.exec('UPDATE gc_pending_deletes SET delete_after=0');
  await env.storage.triggerAlarm();

  // Pack MUST STILL EXIST in R2 because the OCI manifest pins it!
  assert.ok(await env.bucket.head(`t/u0/packs/${p.id}`), 'shared pack must survive while referenced by OCI manifest');

  // Now delete the OCI manifest, expire retention, run GC + alarm() -> pack cleanly swept!
  assert.equal((await env.v2(`/v2/gc/shared/manifests/${manDig}`, {method: 'DELETE', headers: authHdr})).status, 202);
  await env.storageSql.exec('UPDATE registry_blobs SET created_at=0 WHERE digest=?', p.id);
  await env.storageSql.exec('UPDATE registry_repo_blobs SET created_at=0 WHERE digest=?', p.id);
  await env.good(env.rpc(vol, {op: 'run_gc'}));
  await env.storageSql.exec('UPDATE gc_pending_deletes SET delete_after=0');
  await env.storageSql.exec('UPDATE registry_pending_deletes SET delete_after=0');
  await env.storage.triggerAlarm();
  assert.equal(await env.bucket.head(`t/u0/packs/${p.id}`), null, 'pack should be swept after both refs gone');

  // Abandoned chunked upload staging objects swept by alarm()!
  const ab = await env.v2('/v2/gc/shared/blobs/uploads/', {method: 'POST', headers: authHdr});
  assert.equal(ab.status, 202);
  const abLoc = ab.headers.get('Location');
  const abUuid = ab.headers.get('Docker-Upload-UUID');
  assert.equal((await env.v2(abLoc, {
    method: 'PATCH',
    headers: {...authHdr, 'Content-Type': 'application/octet-stream', 'Content-Range': '0-4'},
    body: Buffer.from('stale'),
  })).status, 202);
  const [{r2_key: stagedKey}] = await env.storageSql.exec(
    'SELECT r2_key FROM registry_upload_chunks WHERE upload_id=?',
    abUuid,
  );
  assert.ok(stagedKey.startsWith(`t/u0/uploads/${abUuid}/000000-`), 'upload chunk key should carry per-attempt nonce');
  assert.ok(await env.bucket.head(stagedKey), 'staged upload chunk should exist before expiry');
  await env.storageSql.exec('UPDATE registry_uploads SET expires=0 WHERE upload_id=?', abUuid);
  await env.good(env.rpc(vol, {op: 'run_gc'}));
  await env.storageSql.exec('UPDATE registry_pending_deletes SET delete_after=0');
  await env.storage.triggerAlarm();
  assert.equal(await env.bucket.head(stagedKey), null, 'expired upload chunk must be swept');

  // Verify schema_meta.version == 2, and wrong schema version fails closed with 503 EPROTONOSUPPORT!
  const [{version}] = await env.storageSql.exec('SELECT version FROM schema_meta');
  assert.equal(version, 2);
  await env.storageSql.exec('UPDATE schema_meta SET version=1');
  await env.storage.coldStart();
  const badSchema = await env.v2('/v2/gc/shared/tags/list', {headers: authHdr});
  assert.equal(badSchema.status, 503);
  assert.equal(badSchema.headers.get('X-OS-Errno'), 'EPROTONOSUPPORT');
  // Restore version=2 for cleanliness
  await env.storageSql.exec('UPDATE schema_meta SET version=2');
  await env.storage.coldStart();
});

test('OCI-05 two independent Miniflare registries: sharded cowfs snapshot mirror, origin shutdown, lazy Range read', async () => {
  let regA = await createInstance('oci-origin-a');
  const regB = await createInstance('oci-mirror-b');
  try {
    const authA = {Authorization: (await regA.bearerFor('repository:snap/app:pull,push')).Authorization};
    const authB = {Authorization: (await regB.bearerFor('repository:mirror/app:pull,push')).Authorization};

    const blk1 = Buffer.from('shard-0-block-payload-alpha-1234567890');
    const blk2 = Buffer.from('shard-1-block-payload-beta-abcdefghij');
    const p1 = pack([blk1]);
    const p2 = pack([blk2]);
    const t = tree('snap-vol', [...p1.entries, ...p2.entries], 1);
    const nodePack = encodeNodePack(t.rawNodes);

    const putBlob = async (reg, auth, repo, bytes) => {
      const d = shaDigest(bytes);
      const r = await reg.v2(`/v2/${repo}/blobs/uploads/?digest=${encodeURIComponent(d)}`, {
        method: 'POST', headers: {...auth, 'Content-Type': 'application/octet-stream'}, body: bytes,
      });
      assert.equal(r.status, 201);
      return {digest: d, size: bytes.length};
    };

    const npDesc = await putBlob(regA, authA, 'snap/app', nodePack);
    const shards = [];
    for (const [idx, p] of [p1, p2].entries()) {
      const pDesc = await putBlob(regA, authA, 'snap/app', p.bytes);
      const bdBytes = encodeBlockDir(
        [p.id],
        p.entries.map(e => ({digestBuf: Buffer.from(e.digest), packIdx: 0, offset: e.offset, len: e.len})),
      );
      const bdDesc = await putBlob(regA, authA, 'snap/app', bdBytes);
      const cfgBytes = Buffer.from(JSON.stringify({
        format: 'os.cowfs.snapshot',
        version: 1,
        cowfs_format_version: 1,
        volume_uuid: 'snap-vol',
        root_digest: t.rootHex,
        subvols: {'@': shaHex(t.rawNodes[0][1])},
        shard_index: idx,
        shard_count: 2,
        node_count: idx === 0 ? 2 : 0,
        pack_count: 1,
        total_bytes: p.bytes.length,
      }));
      const cfgDesc = await putBlob(regA, authA, 'snap/app', cfgBytes);
      const layers = [];
      if (idx === 0) layers.push({mediaType: 'application/vnd.os.cowfs.nodepack.v1', ...npDesc});
      layers.push({mediaType: 'application/vnd.os.cowfs.blockdir.v1', ...bdDesc});
      layers.push({mediaType: 'application/vnd.os.cowfs.pack.v1', ...pDesc});
      const shardMan = Buffer.from(JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        artifactType: 'application/vnd.os.cowfs.snapshot.shard.v1',
        config: {mediaType: 'application/vnd.os.cowfs.snapshot.config.v1+json', ...cfgDesc},
        layers,
      }));
      const shardDig = shaDigest(shardMan);
      assert.equal((await regA.v2(`/v2/snap/app/manifests/${shardDig}`, {
        method: 'PUT', headers: {...authA, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json'}, body: shardMan,
      })).status, 201);
      shards.push({mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: shardDig, size: shardMan.length});
    }

    const indexBytes = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      artifactType: 'application/vnd.os.cowfs.snapshot.v1',
      manifests: shards,
    }));
    const indexDig = shaDigest(indexBytes);
    assert.equal((await regA.v2('/v2/snap/app/manifests/v1', {
      method: 'PUT', headers: {...authA, 'Content-Type': 'application/vnd.oci.image.index.v1+json'}, body: indexBytes,
    })).status, 201);

    // Generically mirror OCI Image Index + shard manifests + blobs from Origin A -> Independent Mirror B.
    const idxRes = await regA.v2('/v2/snap/app/manifests/v1', {headers: authA});
    assert.equal(idxRes.status, 200);
    const idxRaw = Buffer.from(await idxRes.arrayBuffer());
    const idxJson = JSON.parse(idxRaw.toString('utf8'));
    for (const child of idxJson.manifests) {
      const mRes = await regA.v2(`/v2/snap/app/manifests/${child.digest}`, {headers: authA});
      const mRaw = Buffer.from(await mRes.arrayBuffer());
      const mJson = JSON.parse(mRaw.toString('utf8'));
      for (const desc of [mJson.config, ...mJson.layers]) {
        const bRes = await regA.v2(`/v2/snap/app/blobs/${desc.digest}`, {headers: authA});
        assert.equal(bRes.status, 200);
        const bRaw = Buffer.from(await bRes.arrayBuffer());
        await putBlob(regB, authB, 'mirror/app', bRaw);
      }
      assert.equal((await regB.v2(`/v2/mirror/app/manifests/${child.digest}`, {
        method: 'PUT', headers: {...authB, 'Content-Type': child.mediaType}, body: mRaw,
      })).status, 201);
    }
    assert.equal((await regB.v2('/v2/mirror/app/manifests/v1', {
      method: 'PUT', headers: {...authB, 'Content-Type': 'application/vnd.oci.image.index.v1+json'}, body: idxRaw,
    })).status, 201);

    // SHUT DOWN Origin Registry A completely!
    await regA.mf.dispose();
    regA = null;

    // Lazily inspect index + BlockDir from Mirror B ONLY (never fetching full COWP packs) and read blocks via HTTP Range!
    const bIdx = await (await regB.v2('/v2/mirror/app/manifests/v1', {headers: authB})).json();
    assert.equal(bIdx.manifests.length, 2);
    const wanted = [blk1, blk2];
    for (let i = 0; i < 2; i++) {
      const shard = await (await regB.v2(`/v2/mirror/app/manifests/${bIdx.manifests[i].digest}`, {headers: authB})).json();
      const bdLayer = shard.layers.find(l => l.mediaType === 'application/vnd.os.cowfs.blockdir.v1');
      assert.ok(bdLayer);
      const bdRaw = Buffer.from(await (await regB.v2(`/v2/mirror/app/blobs/${bdLayer.digest}`, {headers: authB})).arrayBuffer());
      const {blocks} = decodeBlockDir(bdRaw);
      const blkHex = shaHex(wanted[i]);
      const loc = blocks.get(blkHex);
      assert.ok(loc, `block ${i} present in BlockDir`);
      const rangeRes = await regB.v2(`/v2/mirror/app/blobs/sha256:${loc.packId}`, {
        headers: {...authB, Range: `bytes=${loc.offset}-${loc.offset + loc.len - 1}`},
      });
      assert.equal(rangeRes.status, 206);
      const got = Buffer.from(await rangeRes.arrayBuffer());
      assert.deepEqual(got, wanted[i]);
      assert.equal(shaHex(got), blkHex);
    }
    assert.equal(shaDigest(idxRaw), indexDig);
  } finally {
    if (regA?.mf) await regA.mf.dispose();
    await regB.mf.dispose();
  }
});
