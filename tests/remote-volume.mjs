// Build crates/worker with worker-build --release first. Every account, DO and bucket here
// belongs to this disposable Miniflare. Only the test wrappers expose storage inspection.
import {after, before, test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {Miniflare} from 'miniflare';

const origin = 'http://localhost';
const workerName = 'remote-volume-test';
const clock = {
  sec: 1,
  nsec: 0
};
const sha = bytes => createHash('sha256').update(bytes).digest();
const digest = bytes => [...sha(bytes)];
const hex = d => Buffer.from(d).toString('hex');
const key = (id, tenant = 'u0') => `t/${tenant}/packs/${id}`;
const opId = () => [...randomBytes(16)];
const u16 = n => {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
};
const u32 = n => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
};
const u64 = n => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};
const cat = (...parts) => Buffer.concat(parts.map(p => Buffer.from(p)));

// Encode the published v1 binary format independently of the Worker decoder.
function pack(blocks) {
  let offset = 0;
  const entries = blocks.map(bytes => {
    const entry =
        {digest: digest(bytes), offset, len: bytes.length, raw_len: bytes.length, flags: 0};
    offset += bytes.length;
    return entry;
  });
  const index =
      cat('COWP', u16(1), u32(entries.length),
          ...entries.map(e => cat(e.digest, u32(e.offset), u32(e.len), u32(e.raw_len), u16(0))));
  const bytes = cat(...blocks, index, u32(index.length), sha(index), 'COWP');
  return {bytes, entries, id: sha(bytes).toString('hex')};
}
function tree(volume, extents = []) {
  function item(ino, kind, tail, value) {
    return cat(u64(ino), [kind], u16(tail.length), tail, u32(value.length), value);
  }
  function inode(isDir, size) {
    return cat(
        [1, isDir ? 2 : 1], u16(isDir ? 0o755 : 0o644), u32(isDir ? 2 : 1), u32(0), u32(0),
        u64(size), u64(1), Buffer.alloc(36), u64(isDir && extents.length ? 2 : 1), [0, 0, 0]);
  }
  const items = [item(1, 1, [], inode(true, 0))];
  if (extents.length) {
    const file = Buffer.from('data');
    items.push(
        item(1, 0x20, file, cat(u64(2), u64(1), [1], u64(1))),
        item(1, 0x21, u64(1), cat(u64(2), u64(1), [1], u16(file.length), file)),
        item(2, 1, [], inode(false, extents.reduce((n, e) => n + e.len, 0))),
        item(2, 0x10, cat(u64(1), file), Buffer.alloc(0)));
    let pos = 0;
    for (const e of extents) {
      items.push(item(2, 0x30, u64(pos), cat([1], u32(e.len), e.digest, u32(0))));
      pos += e.len;
    }
  }
  const leaf = cat('COWN', u16(1), [0, 0], u32(items.length), ...items);
  const root =
      cat('OSCOWFS1', u32(1), u64(0), u16(volume.length), volume, u64(3), u64(1), [0], u32(1),
          u16(1), '@', sha(leaf));
  return {root: digest(root), nodes: [[digest(leaf), [...leaf]], [digest(root), [...root]]]};
}

let mf, authoritySql, storageSql, bucket, storage, root, alice, guest;
async function post(path, body, headers = {}) {
  return mf.dispatchFetch(origin + path, {
    method: 'POST',
    headers: {Origin: origin, 'Content-Type': 'application/json', ...headers},
    body: JSON.stringify(body)
  });
}
async function good(response) {
  const res = await response;
  const body = await res.json();
  assert.equal(res.status, 200, JSON.stringify(body));
  return body;
}
async function denied(response, errno, status) {
  const res = await response;
  assert.ok(res.status >= 400);
  if (status) assert.equal(res.status, status);
  assert.equal((await res.json()).errno, errno);
}
async function login(uid) {
  const session = randomBytes(32).toString('hex');
  if (uid !== null)
    await authoritySql.exec(
        'INSERT INTO sessions(key,uid,expires,sudo_until) VALUES(?,?,?,0)',
        sha(session).toString('base64url'), uid, Math.floor(Date.now() / 1000) + 3600);
  const cookie = uid === null ? `os_guest=${session}` : `os_session=${session}`;
  const instance = 'inst-' + randomUUID(), proof = randomBytes(32).toString('hex');
  const auth = value => good(post('/api/service-auth', value, {Cookie: cookie}));
  await auth({attach_instance: {instance: {instance, host: 'test'}, host_proof: proof}});
  const mint = async scope => {
    const {cred} =
        await auth({mint_service_cred: {instance_id: instance, host_proof: proof, scope}});
    return {Cookie: cookie, 'X-OS-Instance': instance, 'X-Process-Token': cred.token};
  };
  const derive = async parent => {
    const {cred} = await auth({
      derive_service_cred: {
        instance_id: instance,
        host_proof: proof,
        parent_token: parent['X-Process-Token'],
        scope: {volumes: true},
        cloud_access: false
      }
    });
    return {...parent, 'X-Process-Token': cred.token};
  };
  return {
    headers: await mint({volumes: true}),
    mint,
    derive,
    revoke: token => auth({
      revoke_tokens: {instance_id: instance, host_proof: proof, tokens: [token]},
    })
  };
}
function rpc(volume, call, headers = root.headers) {
  return post('/api/volumes/rpc', {version: 1, volume, call}, headers);
}
async function create(volume, headers = root.headers) {
  const {root: digest, nodes} = tree(volume);
  const head = {
    format_version: 1,
    volume,
    root: digest,
    incarnation: 1,
    fence: 0,
    epoch: 0,
    updated_at: clock
  };
  return (await good(rpc(volume, {op: 'create_volume', head, nodes}, headers))).head;
}
async function attach(volume, mode = 'exclusive', headers = root.headers) {
  return (await good(rpc(volume, {op: 'attach_rw', mode}, headers))).attached.head;
}
const fence = h => ({incarnation: h.incarnation, fence: h.fence});
function put(h, p, headers = root.headers) {
  return mf.dispatchFetch(origin + '/api/volumes/packs/' + p.id, {
    method: 'PUT',
    body: p.bytes,
    headers: {
      Origin: origin,
      ...headers,
      'X-OS-Volume': h.volume,
      'X-OS-Incarnation': String(h.incarnation),
      'X-OS-Fence': String(h.fence),
    }
  });
}
function get(volume, id, headers = root.headers, method = 'GET', range) {
  return mf.dispatchFetch(origin + '/api/volumes/packs/' + id, {
    method,
    headers: {
      ...headers,
      'X-OS-Volume': volume,
      ...(range === undefined ? {} : {Range: range}),
    }
  });
}
function request(h, p, meta, graph) {
  return {
    op_id: opId(),
    volume: h.volume,
    expected_incarnation: h.incarnation,
    expected_fence: h.fence,
    expected_epoch: h.epoch,
    new_root: graph?.root ?? h.root,
    put_nodes: graph?.nodes ?? [],
    put_packs: meta ? [meta] : [],
    put_blocks: p ? p.entries.map(({digest, ...loc}) => [digest, {pack_id: p.id, ...loc}]) : [],
    committed_at: clock
  };
}
const commit = r => rpc(r.volume, {op: 'commit', request: r});

before(async () => {
  const classes = ['OsAuthority', 'Machine', 'StorageVolume'];
  mf = new Miniflare({
    port: 0,
    unsafeInspectDurableObjects: true,
    workers: [{
      config: {
        name: workerName,
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
          constructor(ctx,env){super(ctx,env);this.impl=new Volume(ctx,env);}
          coldStart(){this.impl=new Volume(this.ctx,this.env);}
          expireOnSeal(){this.expire=true;}
          async fetch(r){
            if(this.expire && (await r.clone().json()).action.Seal){
              this.expire=false;this.ctx.storage.sql.exec('UPDATE writer_leases SET expires=0');
            }
            return this.impl.fetch(r);
          }
          alarm(){return this.impl.alarm();}
          async triggerAlarm(){await this.impl.alarm();}
        }`
            },
            'index.js':
                {type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8')},
            'index_bg.wasm':
                {type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm')},
          }
        },
        exports:
            Object.fromEntries(classes.map(n => [n, {type: 'durable-object', storage: 'sqlite'}])),
        env: {
          ...Object.fromEntries(['AUTHORITY', 'MACHINE', 'STORAGE'].map(
              (binding, i) =>
                  [binding, {type: 'durable-object', worker: workerName, exportName: classes[i]}])),
          FILES: {type: 'r2', name: 'files'},
          ADMIN_PASSWORD: {type: 'text', value: randomUUID()},
          SESSION_SECRET: {type: 'text', value: randomUUID()},
          VOLUME_QUOTA_BYTES: {type: 'text', value: String(3 * 1024 * 1024)},
          ASSETS: {
            type: 'fetcher',
            handler: () => new Response('{}', {headers: {'Content-Type': 'application/json'}})
          },
        },
      }
    }]
  });
  await good(post('/api/sys', {calls: ['getcreds']}));
  authoritySql =
      await mf.unsafeGetDurableObjectStorage(workerName, 'OsAuthority', {name: 'filesystem'});
  await authoritySql.exec(
      'INSERT INTO users(id,name,gid,groups,home,locked,salt,hash) VALUES(1000,\'alice\',1000,\'[1000]\',\'/home/alice\',0,\'\',\'\')');
  root = await login(0);
  alice = await login(1000);
  guest = await login(null);
  await good(rpc('setup', {op: 'format_version'}));
  const ns = await mf.getDurableObjectNamespace('STORAGE');
  storage = ns.get(ns.idFromName('tenant:u0'));
  storageSql =
      await mf.unsafeGetDurableObjectStorage(workerName, 'StorageVolume', {name: 'tenant:u0'});
  bucket = await mf.getR2Bucket('FILES');
});
after(async () => {
  if (mf) await mf.dispose();
});

test('RV-01 contention, fork-on-busy and authorized takeover', async () => {
  const v = 'contended';
  await create(v);
  const first = await attach(v);
  await denied(rpc(v, {op: 'attach_rw', mode: 'exclusive'}), 'EBUSY');
  const fork = (await good(rpc(v, {op: 'attach_rw', mode: 'fork-on-busy'}))).attached;
  assert.equal(fork.forked_from, v);
  assert.notEqual(fork.head.volume, v);
  assert.deepEqual(fork.head.root, first.root);
  await create(v, alice.headers);
  await attach(v, 'exclusive', alice.headers);
  await denied(rpc(v, {op: 'attach_rw', mode: 'force-takeover'}, alice.headers), 'EACCES', 403);
  const second = await attach(v, 'force-takeover');
  assert.ok(second.fence > first.fence);
  await denied(rpc(v, {op: 'renew', lease: fence(first)}), 'ESTALE');
  const parent = await root.mint({volumes: true, volume_ids: [v]});
  const mount = await root.derive(parent);
  const pinned = (await good(rpc(v, {op: 'pin_ro'}, mount))).pinned;
  await root.revoke(parent['X-Process-Token']);
  await good(rpc(v, {op: 'renew_ro', pin_id: pinned.pin_id}, mount));
  await root.revoke(mount['X-Process-Token']);
  await denied(rpc(v, {op: 'renew_ro', pin_id: pinned.pin_id}, mount), 'EACCES');
});
test('RV-02 fence wins at unchanged epoch, valid fence compares parent epoch', async () => {
  const v = 'paused';
  await create(v);
  const first = await attach(v);
  const second = await attach(v, 'force-takeover');
  assert.equal(first.epoch, second.epoch);
  await denied(commit(request(first)), 'ESTALE');
  const bad = request(second);
  bad.expected_epoch++;
  await denied(commit(bad), 'EAGAIN');
  assert.deepEqual(
      (await good(rpc(v, {op: 'status', op_id: bad.op_id}))).status, {aborted: {errno: 'EAGAIN'}});
  assert.equal((await good(commit(request(second)))).receipt.head.epoch, 1);
});
test('RV-03 expiry after R2 PUT refuses seal and alarm removes orphan', async () => {
  const v = 'slow';
  await create(v);
  const h = await attach(v);
  const p = pack([Buffer.from('slow payload')]);
  await storage.expireOnSeal();
  await denied(put(h, p), 'ESTALE');
  assert.ok(await bucket.head(key(p.id)));
  await storage.triggerAlarm();
  assert.equal(await bucket.head(key(p.id)), null);
  assert.deepEqual(await storageSql.exec('SELECT * FROM staging_pins WHERE volume=?', v), []);
});
test(
    'RV-04 dropped acknowledgement is queryable and only an identical payload replays',
    async () => {
      const v = 'uncertain';
      await create(v);
      const h = await attach(v);
      const r = request(h);
      assert.equal((await good(rpc(v, {op: 'status', op_id: r.op_id}))).status, 'pending');
      assert.equal((await commit(r)).status, 200);  // discard the reply body
      const status = (await good(rpc(v, {op: 'status', op_id: r.op_id}))).status;
      assert.equal(status.committed.head.epoch, 1);
      assert.deepEqual((await good(commit(r))).receipt, status.committed);
      await denied(commit({...r, committed_at: {sec: 99, nsec: 0}}), 'EINVAL');
      assert.equal((await good(rpc(v, {op: 'read_head'}))).head.epoch, 1);
  const head = status.committed.head;
  const staged = pack([Buffer.from('receive into a mounted volume')]);
  const meta = await good(put(head, staged));
  const graph = tree(v, staged.entries);
  const objects = request(head, staged, meta, graph);
  await good(rpc(v, {op: 'stage_objects', lease: fence(head), nodes: graph.nodes,
    packs: [meta], blocks: objects.put_blocks}));
  assert.deepEqual((await good(rpc(v, {op: 'get_node', digest: graph.root}))).node, graph.nodes[1][1]);
  assert.equal((await get(v, staged.id, root.headers, 'GET', 'bytes=0-2')).status, 206);
  const publish = {...request(head), new_root: graph.root};
  const receive = {op: 'receive', request: publish, snapshot: 'import'};
  const imported = (await good(rpc(v, receive))).receipt;
  assert.equal(imported.head.epoch, 2);
  assert.deepEqual((await good(rpc(v, receive))).receipt, imported);
  assert.deepEqual((await good(rpc(v, {op: 'get_snapshot', name: 'import'}))).snapshot.root, graph.root);
  await denied(rpc(v, {...receive, snapshot: 'different'}), 'EINVAL');
    });
test(
    'RV-05 all independent RO pins and staged uploads survive serialized mark and sweep',
    async () => {
      const v = 'gc';
      await create(v);
      let h = await attach(v);
      const p = pack([Buffer.from('reachable while RO')]);
      const meta = await good(put(h, p));
      h = (await good(commit(request(h, p, meta, tree(v, p.entries))))).receipt.head;
      const pins = await Promise.all(
          Array.from({length: 12}, () => good(rpc(v, {op: 'pin_ro', snapshot: null}))));
      const pending = pack([Buffer.from('still staging')]);
      await good(put(h, pending));
      await good(commit(request(h, null, null, tree(v))));
      await storageSql.exec('UPDATE grace_pins SET expires=0 WHERE volume=?', v);
      await storageSql.exec('UPDATE packs SET created_at=0');
      await storageSql.exec('UPDATE nodes SET created_at=0');
      const gc = () => good(rpc(v, {op: 'run_gc'}));
      await gc();
      await storage.triggerAlarm();
      assert.ok(await bucket.head(key(p.id)));
      assert.ok(await bucket.head(key(pending.id)));
      for (const {pinned} of pins.slice(1))
        await good(rpc(v, {op: 'unpin_ro', pin_id: pinned.pin_id}));
      await gc();
      assert.ok(await bucket.head(key(p.id)));
      await storageSql.exec('UPDATE ro_pins SET expires=0 WHERE pin_id=?', pins[0].pinned.pin_id);
      await gc();
      await storage.triggerAlarm();
      assert.equal(await bucket.head(key(p.id)), null);
      assert.deepEqual(
          await storageSql.exec('SELECT pack_id FROM packs WHERE pack_id=?', p.id), []);
      assert.ok(await bucket.head(key(pending.id)));
      // In-flight deletion cannot be rescued. A queued deletion can.
      await storageSql.exec('UPDATE packs SET status=\'deleting\' WHERE pack_id=?', pending.id);
      await storageSql.exec('INSERT INTO gc_pending_deletes VALUES(?,1)', pending.id);
      await denied(put(h, pending), 'EAGAIN');
      await storageSql.exec(
          'UPDATE gc_pending_deletes SET in_flight=0 WHERE pack_id=?', pending.id);
      await good(put(h, pending));
      assert.deepEqual(
          await storageSql.exec('SELECT * FROM gc_pending_deletes WHERE pack_id=?', pending.id),
          []);
    });
test('RV-06 cold restore compares the external checkpoint and invalidates old leases', async () => {
  const v = 'restore';
  await create(v);
  const h = await attach(v);
  const pinned = (await good(rpc(v, {op: 'pin_ro'}))).pinned;
  const anchor = JSON.parse(await (await bucket.get('t/u0/meta/checkpoint.json')).text());
  await storageSql.exec(
      'UPDATE schema_meta SET checkpoint_seq=checkpoint_seq-1, checkpoint_nonce=?', 'older-nonce');
  await storage.coldStart();
  const current = (await good(rpc(v, {op: 'read_head'}))).head;
  assert.ok(current.incarnation > anchor.store_incarnation);
  assert.deepEqual(current.root, h.root);
  await denied(commit(request(h)), 'ESTALE');
  await good(rpc(v, {op: 'renew_ro', pin_id: pinned.pin_id}));
  const next = await attach(v);
  const rotated = (await good(rpc(v, {op: 'rotate_incarnation'}))).head;
  assert.ok(rotated.incarnation > next.incarnation);
  await denied(rpc(v, {op: 'renew', lease: fence(next)}), 'ESTALE');
});
test(
    'RV-07 two MiB file, 128-byte edit, one delta pack and cold range-verified reads', async () => {
      const v = 'delta';
      await create(v);
      let h = await attach(v);
      const blocks = Array.from({length: 32}, (_, i) => Buffer.alloc(65536, i));
      const p = pack(blocks);
      const initial = await good(put(h, p));
      h = (await good(commit(request(h, p, initial, tree(v, p.entries))))).receipt.head;
      blocks[7].fill(201, 345, 473);
      const delta = pack([blocks[7]]);
      const changed = await good(put(h, delta));
      assert.ok(changed.size < 128 * 1024);
      const entries = [...p.entries];
      entries[7] = delta.entries[0];
      const r = request(h, delta, changed, tree(v, entries));
      h = (await good(commit(r))).receipt.head;
      assert.equal(h.epoch, 2);
      assert.equal(r.put_packs.length, 1);
      const readHeaders = await root.mint({volumes: true, volumes_ro: true, volume_ids: [v]});
      const pin = (await good(rpc(v, {op: 'pin_ro'}, readHeaders))).pinned;
      const readNode = async d => {
        const b = Buffer.from((await good(rpc(v, {op: 'get_node', digest: d}, readHeaders))).node);
        assert.deepEqual(digest(b), d);
        return b;
      };
      const rootBytes = await readNode(pin.head.root);
      const leaf = await readNode([...rootBytes.subarray(-32)]);
      const out = [];
      for (let i = 12; i < leaf.length;) {
        const kind = leaf[i + 8], tail = leaf.readUInt16BE(i + 9);
        i += 11 + tail;
        const size = leaf.readUInt32BE(i);
        i += 4;
        if (kind === 0x30) {
          const d = [...leaf.subarray(i + 5, i + 37)];
          const loc = (await good(rpc(v, {op: 'lookup_block', digest: d}, readHeaders))).block;
          const resp = await get(
              v, loc.pack_id, readHeaders, 'GET',
              `bytes=${loc.offset}-${loc.offset + loc.len - 1}`);
          assert.equal(resp.status, 206);
          const data = Buffer.from(await resp.arrayBuffer());
          assert.deepEqual(digest(data), d);
          out.push(data);
        }
        i += size;
      }
      assert.deepEqual(Buffer.concat(out), Buffer.concat(blocks));
      const headResp = await get(v, p.id, readHeaders, 'HEAD');
      assert.equal(Number(headResp.headers.get('Content-Length')), initial.size);
    });
test('RV-08 live scope, tenant isolation, integrity, resource and version denials', async () => {
  const v = 'security';
  await create(v);
  const h = await attach(v);
  await denied(rpc(v, {op: 'read_head'}, {}), 'EACCES', 403);
  await denied(
      rpc(v, {op: 'read_head'}, {...root.headers, 'X-OS-Instance': 'other'}), 'EACCES', 403);
  await denied(rpc(v, {op: 'read_head'}, guest.headers), 'EACCES', 403);
  const job = await root.mint({volumes: true});
  await authoritySql.exec(
      'UPDATE credentials SET ns=\'jobs\',owner=\'job test\' WHERE token=?',
      sha(job['X-Process-Token']).toString('base64url'));
  await denied(rpc(v, {op: 'read_head'}, job), 'EACCES', 403);
  await denied(rpc(v, {op: 'read_head'}, await root.mint({cloud_fs: true})), 'EACCES', 403);
  await denied(
      rpc(v, {op: 'attach_rw', mode: 'exclusive'},
          await root.mint({volumes: true, volumes_ro: true})),
      'EACCES');
  await denied(
      rpc(v, {op: 'read_head'}, await root.mint({volumes: true, volume_ids: ['other']})), 'EACCES');
  const rev = await root.mint({volumes: true});
  await good(rpc(v, {op: 'read_head'}, rev));
  await root.revoke(rev['X-Process-Token']);
  await denied(rpc(v, {op: 'read_head'}, rev), 'EACCES');
  await denied(rpc(v, {op: 'read_head'}, {...alice.headers, 'X-OS-Tenant': 'u0'}), 'EACCES');
  await denied(rpc(v, {op: 'read_head'}, alice.headers), 'ENOENT');
  await create(v, alice.headers);
  const p = pack([Buffer.from('secret'), Buffer.from('unreferenced private bytes')]);
  await denied(put(h, {...p, id: '0'.repeat(64)}), 'EIO');
  const corrupt = Buffer.from(p.bytes);
  corrupt[corrupt.length - 1] ^= 1;
  await denied(put(h, {id: hex(digest(corrupt)), bytes: corrupt}), 'EIO');
  const falseDigest = Buffer.from(p.bytes);
  falseDigest[0] ^= 1;
  await denied(put(h, {id: hex(digest(falseDigest)), bytes: falseDigest}), 'EIO');
  await denied(put(h, {id: p.id, bytes: Buffer.alloc(8 * 1024 * 1024 + 1)}), 'EFBIG');
  const quota = Buffer.alloc(3 * 1024 * 1024 + 1);
  await denied(put(h, {id: hex(digest(quota)), bytes: quota}), 'EDQUOT');
  const meta = await good(put(h, p));
  const forged = request(h, p, meta, tree(v, p.entries));
  forged.put_blocks[0][1].offset++;
  await denied(commit(forged), 'EIO');
  await denied(
      commit(
          request(h, null, null, tree(v, [{...p.entries[0], digest: [...Buffer.alloc(32, 99)]}]))),
      'EIO');
  await good(commit(request(h, p, meta, tree(v, p.entries.slice(0, 1)))));
  const reader = await root.mint({volumes: true, volume_ids: [v], volumes_ro: true});
  await denied(get(v, p.id, reader), 'EACCES');
  await denied(get(v, p.id, reader, 'GET', 'bytes=6-8'), 'EACCES');
  assert.deepEqual(Buffer.from(await (await get(v, p.id, reader, 'GET', 'bytes=0-5')).arrayBuffer()), Buffer.from('secret'));
  const ns =
      'session.' + sha(root.headers.Cookie.slice('os_session='.length)).toString('base64url');
  const machineSql = await mf.unsafeGetDurableObjectStorage(workerName, 'Machine', {name: ns});
  const counts = async () => (await machineSql.exec(
      'SELECT SUM(read_bytes) AS r,SUM(write_bytes) AS w FROM io_buckets'))[0];
  const before = await counts();
  const charged = await get(v, p.id, root.headers, 'GET', 'bytes=0-2');
  assert.equal(charged.status, 206);
  assert.deepEqual(Buffer.from(await charged.arrayBuffer()), p.bytes.subarray(0, 3));
  await good(put(h, p));
  const after = await counts();
  assert.equal(after.r - before.r, 3);
  assert.equal(after.w - before.w, p.bytes.length);
  await denied(get(v, p.id, alice.headers), 'ENOENT');
  const scoped = await root.mint({volumes: true, volume_ids: ['delta']});
  await denied(get('delta', p.id, scoped), 'ENOENT');
  await authoritySql.exec('UPDATE users SET locked=1 WHERE id=1000');
  await denied(rpc(v, {op: 'read_head'}, alice.headers), 'EACCES');
  await authoritySql.exec('UPDATE users SET locked=0 WHERE id=1000');
  await denied(
      post('/api/volumes/rpc', {version: 9, volume: v, call: {op: 'read_head'}}, root.headers),
      'EPROTONOSUPPORT');
  await denied(
      post(
          '/api/volumes/rpc', {version: 1, volume: v, tenant: 'u1', call: {op: 'read_head'}},
          root.headers),
      'EINVAL');
  await denied(rpc(v, {op: 'read_head', unexpected: true}), 'EINVAL');
  await denied(rpc('hostfs:folder', {op: 'read_head'}), 'ENOTBLK');
  await storageSql.exec('UPDATE volumes SET format_version=9 WHERE volume=?', v);
  await denied(rpc(v, {op: 'read_head'}), 'EPROTONOSUPPORT');
  await storageSql.exec('UPDATE schema_meta SET version=9');
  await storage.coldStart();
  await denied(rpc(v, {op: 'read_head'}), 'EPROTONOSUPPORT');
  assert.equal(
      (await storageSql.exec('SELECT format_version FROM volumes WHERE volume=?', v))[0]
          .format_version,
      9);
});
