// Build crates/worker with worker-build --release first. Every account and DO here belongs
// to this disposable Miniflare instance. Exercises CS-01..CS-08 against real SQLite ClusterState DO,
// alarm(), coldStart(), and Hibernatable WebSockets.
import {after, before, test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {Miniflare} from 'miniflare';

const origin = 'http://localhost';
const workerName = 'cluster-state-test';
const sha = bytes => createHash('sha256').update(bytes).digest();
const b64 = s => Buffer.from(s, 'utf8').toString('base64');
const unb64 = s => Buffer.from(s, 'base64').toString('utf8');

const FULL_CLUSTER = {
  cluster_read: true,
  cluster_write: true,
  cluster_watch: true,
  cluster_lease: true,
  cluster_compact: true,
};

let mf, authoritySql, clusterSql, cluster, root, alice, guest;

async function post(path, body, headers = {}) {
  return mf.dispatchFetch(origin + path, {
    method: 'POST',
    headers: {Origin: origin, 'Content-Type': 'application/json', ...headers},
    body: typeof body === 'string' ? body : JSON.stringify(body),
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
  assert.ok(res.status >= 400, `expected error status, got ${res.status}`);
  if (status !== undefined) assert.equal(res.status, status);
  const body = await res.json();
  assert.equal(body.errno, errno, JSON.stringify(body));
  return body;
}

async function login(uid) {
  const session = randomBytes(32).toString('hex');
  if (uid !== null) {
    await authoritySql.exec(
      'INSERT INTO sessions(key,uid,expires,sudo_until) VALUES(?,?,?,0)',
      sha(session).toString('base64url'),
      uid,
      Math.floor(Date.now() / 1000) + 3600,
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
  const derive = async (parent, scope) => {
    const {cred} = await auth({
      derive_service_cred: {
        instance_id: instance,
        host_proof: proof,
        parent_token: parent['X-Process-Token'],
        scope,
        cloud_access: false,
      },
    });
    return {...parent, 'X-Process-Token': cred.token};
  };
  return {
    cookie,
    session,
    instance,
    headers: await mint(FULL_CLUSTER),
    mint,
    derive,
    revoke: token => auth({
      revoke_tokens: {instance_id: instance, host_proof: proof, tokens: [token]},
    }),
    renew() {
      return auth({
        renew_instance: {
          instance_id: instance,
          host_proof: proof,
          active_tokens: [this.headers['X-Process-Token']],
        },
      });
    },
  };
}

function rpc(call, headers = root.headers, clusterName = 'default') {
  return post('/api/cluster/rpc', {version: 1, cluster: clusterName, call}, headers);
}

async function put(key, val, {leaseId = 0, headers = root.headers, prevKv = false} = {}) {
  const res = await good(rpc({
    op: 'txn',
    compare: [],
    success: [{op: 'put', key, value_b64: b64(val), lease_id: leaseId, prev_kv: prevKv}],
    failure: [],
  }, headers));
  assert.equal(res.succeeded, true);
  return res;
}

async function openWatch({ticket, headers = {}, clusterName = 'default'} = {}) {
  const q = new URLSearchParams({cluster: clusterName});
  if (ticket) q.set('ticket', ticket);
  const res = await mf.dispatchFetch(`${origin}/api/cluster/watch?${q.toString()}`, {
    headers: {Upgrade: 'websocket', Origin: origin, ...headers},
  });
  if (res.status !== 101) {
    return {status: res.status, response: res};
  }
  const ws = res.webSocket;
  assert.ok(ws, '101 response must include webSocket');
  const queue = [];
  const waiters = [];
  let closed = null;
  const closeWaiters = [];
  ws.addEventListener('message', ev => {
    const frame = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString('utf8'));
    if (waiters.length > 0) {
      waiters.shift().resolve(frame);
    } else {
      queue.push(frame);
    }
  });
  ws.addEventListener('close', ev => {
    closed = {code: ev.code, reason: ev.reason};
    while (closeWaiters.length > 0) closeWaiters.shift().resolve(closed);
    while (waiters.length > 0) waiters.shift().reject(new Error(`ws closed (${ev.code}: ${ev.reason})`));
  });
  ws.accept();
  return {
    status: 101,
    ws,
    send: obj => ws.send(JSON.stringify(obj)),
    nextFrame(timeoutMs = 5000) {
      if (queue.length > 0) return Promise.resolve(queue.shift());
      if (closed) return Promise.reject(new Error(`ws already closed (${closed.code})`));
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const idx = waiters.findIndex(w => w.resolve === wrappedResolve);
          if (idx >= 0) waiters.splice(idx, 1);
          reject(new Error(`timed out waiting for WS frame after ${timeoutMs}ms`));
        }, timeoutMs);
        const wrappedResolve = v => { clearTimeout(timer); resolve(v); };
        const wrappedReject = e => { clearTimeout(timer); reject(e); };
        waiters.push({resolve: wrappedResolve, reject: wrappedReject});
      });
    },
    waitClose(timeoutMs = 5000) {
      if (closed) return Promise.resolve(closed);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out waiting for WS close`)), timeoutMs);
        closeWaiters.push({resolve: v => { clearTimeout(timer); resolve(v); }});
      });
    },
    expectNoFrame(ms = 120) {
      if (queue.length > 0) {
        return Promise.reject(new Error(`unexpected WS frame: ${JSON.stringify(queue[0])}`));
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const idx = waiters.findIndex(w => w.resolve === onFrame);
          if (idx >= 0) waiters.splice(idx, 1);
          resolve();
        }, ms);
        const onFrame = f => {
          clearTimeout(timer);
          reject(new Error(`unexpected WS frame: ${JSON.stringify(f)}`));
        };
        waiters.push({resolve: onFrame, reject: () => { clearTimeout(timer); resolve(); }});
      });
    },
    close() {
      try { ws.close(1000, 'done'); } catch {}
    },
  };
}

before(async () => {
  const classes = ['OsAuthority', 'Machine', 'ClusterState'];
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
        import { OsAuthority as Authority, Machine as Service, ClusterState as Cluster } from './index.js';
        export { default } from './index.js';
        export class OsAuthority extends DurableObject {
          constructor(ctx, env) { super(ctx, env); this.impl = new Authority(ctx, env); }
          fetch(r) { return this.impl.fetch(r); }
          alarm() { return this.impl.alarm(); }
        }
        export class Machine extends DurableObject {
          constructor(ctx, env) { super(ctx, env); this.impl = new Service(ctx, env); }
          fetch(r) { return this.impl.fetch(r); }
          alarm() { return this.impl.alarm(); }
        }
        export class ClusterState extends DurableObject {
          constructor(ctx, env) { super(ctx, env); this.impl = new Cluster(ctx, env); }
          coldStart() { this.impl = new Cluster(this.ctx, this.env); }
          fetch(r) { return this.impl.fetch(r); }
          alarm() { return this.impl.alarm(); }
          async triggerAlarm() { await this.impl.alarm(); }
          webSocketMessage(ws, msg) { return this.impl.webSocketMessage(ws, msg); }
          webSocketClose(ws, code, reason, wasClean) { return this.impl.webSocketClose(ws, code, reason, wasClean); }
          webSocketError(ws, err) { return this.impl.webSocketError(ws, err); }
        }`,
            },
            'index.js': {type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8')},
            'index_bg.wasm': {type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm')},
          },
        },
        exports: Object.fromEntries(classes.map(n => [n, {type: 'durable-object', storage: 'sqlite'}])),
        env: {
          ...Object.fromEntries(['AUTHORITY', 'MACHINE', 'CLUSTER_STATE'].map(
            (binding, i) => [binding, {type: 'durable-object', worker: workerName, exportName: classes[i]}],
          )),
          FILES: {type: 'r2', name: 'files-cluster-test'},
          ADMIN_PASSWORD: {type: 'text', value: randomUUID()},
          SESSION_SECRET: {type: 'text', value: randomUUID()},
          ASSETS: {
            type: 'fetcher',
            handler: () => new Response('{}', {headers: {'Content-Type': 'application/json'}}),
          },
        },
      },
    }],
  });
  await good(post('/api/sys', {calls: ['getcreds']}));
  authoritySql = await mf.unsafeGetDurableObjectStorage(workerName, 'OsAuthority', {name: 'filesystem'});
  await authoritySql.exec(
    "INSERT INTO users(id,name,gid,groups,home,locked,salt,hash) VALUES(1000,'alice',1000,'[1000]','/home/alice',0,'','')",
  );
  root = await login(0);
  alice = await login(1000);
  guest = await login(null);
  await good(rpc({op: 'hello', versions: [1]}));
  const ns = await mf.getDurableObjectNamespace('CLUSTER_STATE');
  cluster = ns.get(ns.idFromName('cluster:default'));
  clusterSql = await mf.unsafeGetDurableObjectStorage(workerName, 'ClusterState', {name: 'cluster:default'});
});

after(async () => {
  if (mf) await mf.dispose();
});

test('CS-01 linearizable revisioned KV, MVCC historical Range, pagination, and wire validation', async () => {
  const w = await good(rpc({op: 'hello', versions: [99, 1]}));
  assert.equal(w.kind, 'welcome');
  assert.equal(w.boundary, 'cluster-state');
  assert.equal(w.version, 1);
  assert.equal(w.tenant, 'u0');

  await denied(rpc({op: 'hello', versions: [99]}), 'EPROTONOSUPPORT', 400);
  await denied(post('/api/cluster/rpc', {version: 99, call: {op: 'future_op'}}, root.headers), 'EPROTONOSUPPORT', 400);
  await denied(post('/api/cluster/rpc', {version: 1, tenant: 'u1', call: {op: 'hello', versions: [1]}}, root.headers), 'EINVAL', 400);
  await denied(rpc({op: 'hello', versions: [1], unexpected: true}), 'EINVAL', 400);

  const p1 = await put('/t/u0/cs01/a', 'v1');
  const p2 = await put('/t/u0/cs01/a', 'v2');
  const p3 = await put('/t/u0/cs01/b', 'vb');
  assert.equal(p2.revision, p1.revision + 1);
  assert.equal(p3.revision, p2.revision + 1);

  // Historical Range at p1 reads v1
  const hist = await good(rpc({op: 'range', key: '/t/u0/cs01/a', range_end: 'exact', revision: p1.revision}));
  assert.equal(hist.count, 1);
  assert.equal(unb64(hist.kvs[0].value_b64), 'v1');
  assert.equal(hist.kvs[0].create_revision, p1.revision);
  assert.equal(hist.kvs[0].mod_revision, p1.revision);
  assert.equal(hist.kvs[0].version, 1);

  // Current prefix Range with limit=1
  const paged = await good(rpc({op: 'range', key: '/t/u0/cs01/', range_end: 'prefix', limit: 1}));
  assert.equal(paged.count, 2);
  assert.equal(paged.more, true);
  assert.equal(paged.kvs.length, 1);
  assert.equal(paged.kvs[0].key, '/t/u0/cs01/a');
  assert.equal(unb64(paged.kvs[0].value_b64), 'v2');
  assert.equal(paged.kvs[0].create_revision, p1.revision);
  assert.equal(paged.kvs[0].mod_revision, p2.revision);
  assert.equal(paged.kvs[0].version, 2);

  // Explicit Key(end), keys_only, count_only
  const explicitEnd = await good(rpc({
    op: 'range',
    key: '/t/u0/cs01/a',
    range_end: {key: '/t/u0/cs01/b'},
    keys_only: true,
  }));
  assert.equal(explicitEnd.kvs.length, 1);
  assert.equal(explicitEnd.kvs[0].value_b64, '');

  const countOnly = await good(rpc({
    op: 'range',
    key: '/t/u0/cs01/',
    range_end: 'prefix',
    count_only: true,
  }));
  assert.equal(countOnly.count, 2);
  assert.equal(countOnly.kvs.length, 0);

  // Delete then historical Range at p3 still sees deleted key; re-create resets create_revision & version=1
  const del = await good(rpc({
    op: 'txn',
    compare: [],
    success: [{op: 'delete_range', key: '/t/u0/cs01/a', range_end: 'exact', prev_kv: true}],
    failure: [],
  }));
  assert.equal(del.responses[0].deleted, 1);
  assert.equal(unb64(del.responses[0].prev_kvs[0].value_b64), 'v2');
  const histAfterDel = await good(rpc({op: 'range', key: '/t/u0/cs01/a', range_end: 'exact', revision: p3.revision}));
  assert.equal(histAfterDel.count, 1);
  assert.equal(unb64(histAfterDel.kvs[0].value_b64), 'v2');
  const recreate = await put('/t/u0/cs01/a', 'v3');
  const afterRec = await good(rpc({op: 'range', key: '/t/u0/cs01/a', range_end: 'exact'}));
  assert.equal(afterRec.kvs[0].create_revision, recreate.revision);
  assert.equal(afterRec.kvs[0].version, 1);

  // Future revision rejected
  await denied(rpc({op: 'range', key: '/t/u0/cs01/a', range_end: 'exact', revision: recreate.revision + 50}), 'ERANGE', 400);
});

test('CS-02 atomic conditional Txn compares, atomicity, and pre-compare authz', async () => {
  const lease = await good(rpc({op: 'lease_grant', ttl_secs: 60}));
  const k = '/t/u0/cs02/item';
  const r1 = await good(rpc({
    op: 'txn',
    compare: [{key: k, op: 'equal', target: {version: 0}}],
    success: [
      {op: 'put', key: k, value_b64: b64('alpha'), lease_id: lease.lease_id, prev_kv: false},
      {op: 'put', key: '/t/u0/cs02/side', value_b64: b64('s1'), lease_id: 0, prev_kv: false},
    ],
    failure: [],
  }));
  assert.equal(r1.succeeded, true);

  // Verify all 5 CompareTargets and CompareOps match
  const r2 = await good(rpc({
    op: 'txn',
    compare: [
      {key: k, op: 'equal', target: {version: 1}},
      {key: k, op: 'equal', target: {create_revision: r1.revision}},
      {key: k, op: 'equal', target: {mod_revision: r1.revision}},
      {key: k, op: 'equal', target: {value: b64('alpha')}},
      {key: k, op: 'equal', target: {lease: lease.lease_id}},
      {key: k, op: 'not_equal', target: {value: b64('beta')}},
      {key: k, op: 'less', target: {version: 2}},
      {key: k, op: 'greater', target: {create_revision: 0}},
    ],
    success: [{op: 'put', key: k, value_b64: b64('beta'), lease_id: lease.lease_id, prev_kv: true}],
    failure: [],
  }));
  assert.equal(r2.succeeded, true);
  assert.equal(unb64(r2.responses[0].prev_kv.value_b64), 'alpha');

  // Failed compare runs only failure branch and does not advance revision
  const failed = await good(rpc({
    op: 'txn',
    compare: [{key: k, op: 'equal', target: {value: b64('wrong')}}],
    success: [{op: 'put', key: k, value_b64: b64('nope')}],
    failure: [{op: 'range', key: k, range_end: 'exact'}],
  }));
  assert.equal(failed.succeeded, false);
  assert.equal(failed.revision, r2.revision);
  assert.equal(unb64(failed.responses[0].kvs[0].value_b64), 'beta');

  // Duplicate put or overlapping DeleteRange in one branch fails EINVAL atomically
  await denied(rpc({
    op: 'txn',
    compare: [],
    success: [
      {op: 'put', key: '/t/u0/cs02/dup', value_b64: b64('1')},
      {op: 'put', key: '/t/u0/cs02/dup', value_b64: b64('2')},
    ],
    failure: [],
  }), 'EINVAL', 400);
  await denied(rpc({
    op: 'txn',
    compare: [],
    success: [
      {op: 'delete_range', key: k, range_end: 'exact'},
      {op: 'delete_range', key: k, range_end: 'exact'},
    ],
    failure: [],
  }), 'EINVAL', 400);
  await denied(rpc({
    op: 'txn',
    compare: [],
    success: [
      {op: 'delete_range', key: '/t/u0/cs02/', range_end: 'prefix'},
      {op: 'delete_range', key: k, range_end: 'exact'},
    ],
    failure: [],
  }), 'EINVAL', 400);

  // Pre-compare authz blocks unauthorized op in untaken failure branch!
  const roCred = await root.mint({cluster_read: true});
  await denied(rpc({
    op: 'txn',
    compare: [{key: k, op: 'equal', target: {version: 2}}],
    success: [{op: 'range', key: k, range_end: 'exact'}],
    failure: [{op: 'put', key: k, value_b64: b64('smuggled')}],
  }, roCred), 'EACCES', 403);
});

test('CS-03 Hibernatable Watch tickets, catch-up, Pull pagination, and coldStart survival', async () => {
  // Single-use watch ticket
  const ticketRes = await good(post('/api/cluster/watch-ticket', {version: 1, cluster: 'default'}, root.headers));
  assert.ok(ticketRes.ticket && ticketRes.tenant === 'u0');

  // Open WS with ticket
  const w1 = await openWatch({ticket: ticketRes.ticket});
  assert.equal(w1.status, 101);
  // Second use of the SAME ticket must fail 403 EACCES!
  const reuse = await openWatch({ticket: ticketRes.ticket});
  assert.equal(reuse.status, 403);
  assert.equal((await reuse.response.json()).errno, 'EACCES');

  // Version mismatch on WS Hello closes cleanly with EPROTONOSUPPORT
  const badTicket = await good(post('/api/cluster/watch-ticket', {version: 1}, root.headers));
  const badWs = await openWatch({ticket: badTicket.ticket});
  assert.equal(badWs.status, 101);
  badWs.send({op: 'hello', versions: [99]});
  const badFrame = await badWs.nextFrame();
  assert.equal(badFrame.kind, 'error');
  assert.equal(badFrame.error.errno, 'EPROTONOSUPPORT');
  await badWs.waitClose();

  // Handshake + Ping on w1
  w1.send({op: 'hello', versions: [1]});
  const wel = await w1.nextFrame();
  assert.equal(wel.kind, 'welcome');
  assert.equal(wel.version, 1);

  w1.send({op: 'ping', seq: 7});
  const pong = await w1.nextFrame();
  assert.equal(pong.kind, 'pong');
  assert.equal(pong.seq, 7);

  // Live watch across coldStart() hibernation wakeup!
  const pBefore = await put('/t/u0/cs03/live/k1', 'one');
  w1.send({op: 'subscribe', watch_id: 1, key: '/t/u0/cs03/live/', range_end: 'prefix', from_revision: pBefore.revision, prev_kv: true});
  const subAck = await w1.nextFrame();
  assert.equal(subAck.kind, 'subscribed');
  assert.equal(subAck.watch_id, 1);
  const catchup = await w1.nextFrame();
  assert.equal(catchup.kind, 'events');
  assert.equal(catchup.events.length, 1);
  assert.equal(unb64(catchup.events[0].kv.value_b64), 'one');

  // Simulate DO hibernation eviction & cold wakeup!
  await cluster.coldStart();
  await put('/t/u0/cs03/live/k1', 'two');
  const postCold = await w1.nextFrame();
  assert.equal(postCold.kind, 'events');
  assert.equal(postCold.watch_id, 1);
  assert.equal(postCold.events.length, 1);
  assert.equal(unb64(postCold.events[0].kv.value_b64), 'two');
  assert.equal(unb64(postCold.events[0].prev_kv.value_b64), 'one');

  // Cancel stops future delivery
  w1.send({op: 'cancel', watch_id: 1});
  const canc = await w1.nextFrame();
  assert.equal(canc.kind, 'canceled');
  await put('/t/u0/cs03/live/k1', 'three');
  await w1.expectNoFrame();

  // Direct ServiceAuth header WS upgrade + Pull pagination over 150 events (> 128 batch)
  const startRev = (await put('/t/u0/cs03/bulk/k000', 'v0')).revision;
  for (let i = 1; i < 150; i++) {
    await put(`/t/u0/cs03/bulk/k${String(i).padStart(3, '0')}`, `v${i}`);
  }
  const w2 = await openWatch({headers: root.headers});
  assert.equal(w2.status, 101);
  w2.send({op: 'hello', versions: [1]});
  assert.equal((await w2.nextFrame()).kind, 'welcome');
  w2.send({op: 'subscribe', watch_id: 2, key: '/t/u0/cs03/bulk/', range_end: 'prefix', from_revision: startRev});
  assert.equal((await w2.nextFrame()).kind, 'subscribed');
  const batch1 = await w2.nextFrame();
  assert.equal(batch1.kind, 'events');
  assert.equal(batch1.events.length, 128);
  assert.equal(batch1.more, true);

  w2.send({op: 'pull', watch_id: 2, limit: 128});
  const batch2 = await w2.nextFrame();
  assert.equal(batch2.kind, 'events');
  assert.equal(batch2.events.length, 22);
  assert.equal(batch2.more, false);

  const allKeys = [...batch1.events, ...batch2.events].map(e => e.kv.key);
  assert.equal(allKeys.length, 150);
  assert.equal(allKeys[0], '/t/u0/cs03/bulk/k000');
  assert.equal(allKeys[149], '/t/u0/cs03/bulk/k149');
  assert.equal(new Set(allKeys).size, 150);

  // Max 16 subscriptions per socket enforced (watch_id 2 already active -> add 15 more, 17th fails ENOSPC)
  for (let id = 10; id < 25; id++) {
    w2.send({op: 'subscribe', watch_id: id, key: `/t/u0/cs03/cap/${id}`, range_end: 'exact', from_revision: 0});
    assert.equal((await w2.nextFrame()).kind, 'subscribed');
  }
  w2.send({op: 'subscribe', watch_id: 99, key: '/t/u0/cs03/cap/overflow', range_end: 'exact', from_revision: 0});
  const capErr = await w2.nextFrame();
  assert.equal(capErr.kind, 'error');
  assert.equal(capErr.error.errno, 'ENOSPC');

  // Non-WebSocket GET /api/cluster/watch returns 426 with X-OS-Errno: EINVAL
  const nonWs = await mf.dispatchFetch(`${origin}/api/cluster/watch?cluster=default`, {
    headers: {Origin: origin, ...root.headers},
  });
  assert.equal(nonWs.status, 426);
  assert.equal(nonWs.headers.get('X-OS-Errno'), 'EINVAL');
  assert.equal((await nonWs.json()).errno, 'EINVAL');

  // u64 > i64::MAX watch_id / from_revision and watch_id == 0 rejected with EINVAL (no silent i64::MAX clamping)
  for (const rawFrame of [
    '{"op":"subscribe","watch_id":9223372036854775808,"key":"/t/u0/cs03/bounds","range_end":"exact","from_revision":0}',
    '{"op":"subscribe","watch_id":101,"key":"/t/u0/cs03/bounds","range_end":"exact","from_revision":9223372036854775808}',
    '{"op":"pull","watch_id":9223372036854775808,"limit":10}',
    '{"op":"cancel","watch_id":9223372036854775808}',
    '{"op":"pull","watch_id":0,"limit":10}',
    '{"op":"cancel","watch_id":0}',
  ]) {
    w1.ws.send(rawFrame);
    const errFrame = await w1.nextFrame();
    assert.equal(errFrame.kind, 'error', rawFrame);
    assert.equal(errFrame.error.errno, 'EINVAL', rawFrame);
  }

  w1.close();
  w2.close();
});

test('CS-04 node leases, KeepAlive, Revoke, and alarm() expiration emit Delete watch events', async () => {
  await denied(rpc({op: 'lease_grant', ttl_secs: 4}), 'EINVAL', 400);
  await denied(rpc({op: 'lease_grant', ttl_secs: 3601}), 'EINVAL', 400);

  const ws = await openWatch({headers: root.headers});
  assert.equal(ws.status, 101);
  ws.send({op: 'hello', versions: [1]});
  assert.equal((await ws.nextFrame()).kind, 'welcome');
  ws.send({op: 'subscribe', watch_id: 1, key: '/t/u0/cs04/nodes/', range_end: 'prefix', from_revision: 0, prev_kv: true});
  assert.equal((await ws.nextFrame()).kind, 'subscribed');

  // Grant + attach + TTL + KeepAlive + Revoke
  const l1 = await good(rpc({op: 'lease_grant', ttl_secs: 30, node_id: 'n-rev'}));
  await put('/t/u0/cs04/nodes/n-rev', 'live-rev', {leaseId: l1.lease_id});
  const putEv = await ws.nextFrame();
  assert.equal(putEv.events[0].event_type, 'put');

  const ttl = await good(rpc({op: 'lease_time_to_live', lease_id: l1.lease_id, keys: true}));
  assert.equal(ttl.granted_ttl_secs, 30);
  assert.deepEqual(ttl.keys, ['/t/u0/cs04/nodes/n-rev']);
  await good(rpc({op: 'lease_keep_alive', lease_id: l1.lease_id}));

  const rev = await good(rpc({op: 'lease_revoke', lease_id: l1.lease_id}));
  assert.equal(rev.deleted, 1);
  const delEv = await ws.nextFrame();
  assert.equal(delEv.events[0].event_type, 'delete');
  assert.equal(unb64(delEv.events[0].prev_kv.value_b64), 'live-rev');

  // Alarm-driven lease expiry deletes ephemeral node record while preserving durable node-meta
  const l2 = await good(rpc({op: 'lease_grant', ttl_secs: 10, node_id: 'n-alarm'}));
  await put('/t/u0/cs04/node-meta/n-alarm', 'durable-meta');
  await put('/t/u0/cs04/nodes/n-alarm', 'ephemeral-live', {leaseId: l2.lease_id});
  assert.equal((await ws.nextFrame()).events[0].event_type, 'put');

  await clusterSql.exec('UPDATE leases SET expires_at = 0 WHERE lease_id = ?', l2.lease_id);
  await cluster.triggerAlarm();

  const expEv = await ws.nextFrame();
  assert.equal(expEv.kind, 'events');
  assert.equal(expEv.events[0].event_type, 'delete');
  assert.equal(expEv.events[0].kv.key, '/t/u0/cs04/nodes/n-alarm');
  assert.equal(unb64(expEv.events[0].prev_kv.value_b64), 'ephemeral-live');

  const nodeGone = await good(rpc({op: 'range', key: '/t/u0/cs04/nodes/n-alarm', range_end: 'exact'}));
  assert.equal(nodeGone.count, 0);
  const metaKept = await good(rpc({op: 'range', key: '/t/u0/cs04/node-meta/n-alarm', range_end: 'exact'}));
  assert.equal(metaKept.count, 1);

  ws.close();
});

test('CS-05 compaction, non-resurrection of tombstones, and Compacted{floor} relist recovery', async () => {
  const k = '/t/u0/cs05/key';
  const r1 = (await put(k, 'v1')).revision;
  const r2 = (await put(k, 'v2')).revision;
  // Also create & delete a key BEFORE compaction to verify zero tombstone resurrection!
  const tombKey = '/t/u0/cs05/tomb';
  await put(tombKey, 'gone-soon');
  const rDel = (await good(rpc({
    op: 'txn',
    compare: [],
    success: [{op: 'delete_range', key: tombKey, range_end: 'exact'}],
    failure: [],
  }))).revision;
  const rKeep = (await put(k, 'v3')).revision;

  // Non-admin and prefix-restricted admin cannot compact
  await denied(rpc({op: 'compact', revision: rKeep}, alice.headers), 'EACCES', 403);
  const scopedRoot = await root.mint({...FULL_CLUSTER, cluster_prefixes: ['cs05/*']});
  await denied(rpc({op: 'compact', revision: rKeep}, scopedRoot), 'EACCES', 403);

  // Active lagged WebSocket watcher paused with more:true receives Compacted{floor} during Compact()!
  const lagStart = (await put('/t/u0/cs05/lag/k000', 'v0')).revision;
  for (let i = 1; i < 140; i++) {
    await put(`/t/u0/cs05/lag/k${String(i).padStart(3, '0')}`, `v${i}`);
  }
  const lagFloor = (await put(k, 'v3-final')).revision;
  const lagWs = await openWatch({headers: root.headers});
  assert.equal(lagWs.status, 101);
  lagWs.send({op: 'hello', versions: [1]});
  assert.equal((await lagWs.nextFrame()).kind, 'welcome');
  lagWs.send({op: 'subscribe', watch_id: 7, key: '/t/u0/cs05/lag/', range_end: 'prefix', from_revision: lagStart});
  assert.equal((await lagWs.nextFrame()).kind, 'subscribed');
  const firstLagBatch = await lagWs.nextFrame();
  assert.equal(firstLagBatch.kind, 'events');
  assert.equal(firstLagBatch.events.length, 128);
  assert.equal(firstLagBatch.more, true);

  // Compact past both rKeep and lagWs's paused cursor -> lagWs receives Compacted{floor} immediately!
  const compactRes = await good(rpc({op: 'compact', revision: lagFloor}));
  assert.equal(compactRes.compacted_floor, lagFloor);
  assert.ok(rDel < rKeep && rKeep < lagFloor && r1 < r2);

  const liveCompFrame = await lagWs.nextFrame();
  assert.equal(liveCompFrame.kind, 'compacted');
  assert.equal(liveCompFrame.watch_id, 7);
  assert.equal(liveCompFrame.floor, lagFloor);
  lagWs.close();

  // Historical Range < floor fails 412 ESTALE with compacted.floor
  const staleRange = await denied(
    rpc({op: 'range', key: k, range_end: 'exact', revision: r2}),
    'ESTALE',
    412,
  );
  assert.equal(staleRange.compacted.floor, lagFloor);

  // Historical Range == floor succeeds AND tombstone key does NOT resurrect!
  const atFloor = await good(rpc({op: 'range', key: '/t/u0/cs05/k', range_end: 'prefix', revision: lagFloor}));
  assert.deepEqual(atFloor.kvs.map(kv => kv.key), [k]);
  assert.equal(unb64(atFloor.kvs[0].value_b64), 'v3-final');
  const tombAtFloor = await good(rpc({op: 'range', key: tombKey, range_end: 'exact', revision: lagFloor}));
  assert.equal(tombAtFloor.count, 0);

  // Watch subscribing at r1 < floor receives Compacted{floor}, then recovers via relist + re-subscribe!
  const ws = await openWatch({headers: root.headers});
  assert.equal(ws.status, 101);
  ws.send({op: 'hello', versions: [1]});
  assert.equal((await ws.nextFrame()).kind, 'welcome');
  ws.send({op: 'subscribe', watch_id: 1, key: '/t/u0/cs05/', range_end: 'prefix', from_revision: r1});
  const compFrame = await ws.nextFrame();
  assert.equal(compFrame.kind, 'compacted');
  assert.equal(compFrame.floor, lagFloor);

  // Relist at current revision and re-subscribe at revision + 1
  const relist = await good(rpc({op: 'range', key: '/t/u0/cs05/', range_end: 'prefix'}));
  ws.send({
    op: 'subscribe',
    watch_id: 2,
    key: '/t/u0/cs05/',
    range_end: 'prefix',
    from_revision: relist.revision + 1,
  });
  assert.equal((await ws.nextFrame()).kind, 'subscribed');
  await put(k, 'v4-after-recover');
  const recovered = await ws.nextFrame();
  assert.equal(recovered.kind, 'events');
  assert.equal(unb64(recovered.events[0].kv.value_b64), 'v4-after-recover');

  ws.close();
});

test('CS-06 fenced node registration, attempt claim, cancel, and 5-way fenced result publish', async () => {
  const leaseA = (await good(rpc({op: 'lease_grant', ttl_secs: 30, node_id: 'node-a'}))).lease_id;
  const leaseB = (await good(rpc({op: 'lease_grant', ttl_secs: 30, node_id: 'node-b'}))).lease_id;

  const regNode = async (id, leaseId, gen) => {
    const res = await good(rpc({
      op: 'txn',
      compare: [{key: `/t/u0/nodes/${id}`, op: 'equal', target: {version: 0}}],
      success: [
        {op: 'put', key: `/t/u0/node-meta/${id}`, value_b64: b64(JSON.stringify({node_id: id, host_kind: 'os-native', enrolled_at: 1}))},
        {op: 'put', key: `/t/u0/nodes/${id}`, value_b64: b64(JSON.stringify({node_id: id, node_generation: gen, instance_id: `i-${id}`, lease_id: leaseId, status: 'ready', heartbeat_at: 1})), lease_id: leaseId},
      ],
      failure: [{op: 'range', key: `/t/u0/nodes/${id}`, range_end: 'exact'}],
    }));
    assert.equal(res.succeeded, true);
    return res.revision;
  };

  const nodeARev = await regNode('node-a', leaseA, 1);
  const nodeBRev = await regNode('node-b', leaseB, 1);

  // Admit workload + notice-only outbox
  const wl1Rev = (await good(rpc({
    op: 'txn',
    compare: [{key: '/t/u0/workloads/wl1', op: 'equal', target: {version: 0}}],
    success: [
      {op: 'put', key: '/t/u0/workloads/wl1', value_b64: b64(JSON.stringify({workload_id: 'wl1', image_ref: 'oci:org/app@sha256:00', desired_state: 'pending', current_attempt: 0, created_at: 1}))},
      {op: 'put', key: '/t/u0/outbox/ob1', value_b64: b64(JSON.stringify({outbox_id: 'ob1', workload_id: 'wl1', attempt_generation: 0, kind: 'attempt_ready', created_at: 1}))},
    ],
    failure: [],
  }))).revision;

  // Node A claims attempt 1
  const att1Rev = (await good(rpc({
    op: 'txn',
    compare: [
      {key: '/t/u0/workloads/wl1/canceled', op: 'equal', target: {version: 0}},
      {key: '/t/u0/workloads/wl1', op: 'equal', target: {mod_revision: wl1Rev}},
      {key: '/t/u0/nodes/node-a', op: 'equal', target: {mod_revision: nodeARev}},
      {key: '/t/u0/nodes/node-a', op: 'equal', target: {lease: leaseA}},
      {key: '/t/u0/attempts/wl1/1', op: 'equal', target: {version: 0}},
    ],
    success: [
      {op: 'put', key: '/t/u0/workloads/wl1', value_b64: b64(JSON.stringify({workload_id: 'wl1', image_ref: 'oci:org/app@sha256:00', desired_state: 'running', current_attempt: 1, created_at: 1}))},
      {op: 'put', key: '/t/u0/attempts/wl1/1', value_b64: b64(JSON.stringify({workload_id: 'wl1', attempt_generation: 1, node_id: 'node-a', node_generation: 1, node_lease_id: leaseA, state: 'claimed', claimed_at: 2}))},
    ],
    failure: [],
  }))).revision;

  // Expire Node A's lease via alarm() -> stale publish by Node A MUST fail 5-way fence!
  await clusterSql.exec('UPDATE leases SET expires_at = 0 WHERE lease_id = ?', leaseA);
  await cluster.triggerAlarm();

  const publish5Way = (wl, att, nodeId, nodeRev, leaseId, wlRev, attRev, outRef) => good(rpc({
    op: 'txn',
    compare: [
      {key: `/t/u0/workloads/${wl}/canceled`, op: 'equal', target: {version: 0}},
      {key: `/t/u0/workloads/${wl}`, op: 'equal', target: {mod_revision: wlRev}},
      {key: `/t/u0/nodes/${nodeId}`, op: 'equal', target: {mod_revision: nodeRev}},
      {key: `/t/u0/nodes/${nodeId}`, op: 'equal', target: {lease: leaseId}},
      {key: `/t/u0/attempts/${wl}/${att}`, op: 'equal', target: {mod_revision: attRev}},
      {key: `/t/u0/results/${wl}`, op: 'equal', target: {version: 0}},
    ],
    success: [
      {op: 'put', key: `/t/u0/results/${wl}`, value_b64: b64(JSON.stringify({workload_id: wl, attempt_generation: att, node_id: nodeId, node_generation: 1, exit_code: 0, output_ref: outRef, published_at: 5}))},
    ],
    failure: [
      {op: 'range', key: `/t/u0/workloads/${wl}/canceled`, range_end: 'exact'},
      {op: 'range', key: `/t/u0/results/${wl}`, range_end: 'exact'},
      {op: 'range', key: `/t/u0/nodes/${nodeId}`, range_end: 'exact'},
    ],
  }));

  const stalePub = await publish5Way('wl1', 1, 'node-a', nodeARev, leaseA, att1Rev, att1Rev, 'remote:snapshot:v@stale');
  assert.equal(stalePub.succeeded, false);
  assert.equal(stalePub.responses[2].kvs.length, 0, 'node-a key must be gone after lease expiry');

  // Node B claims attempt 2 and publishes once -> succeeds; duplicate publish rejected!
  const att2Rev = (await good(rpc({
    op: 'txn',
    compare: [
      {key: '/t/u0/workloads/wl1/canceled', op: 'equal', target: {version: 0}},
      {key: '/t/u0/workloads/wl1', op: 'equal', target: {mod_revision: att1Rev}},
      {key: '/t/u0/nodes/node-b', op: 'equal', target: {mod_revision: nodeBRev}},
      {key: '/t/u0/nodes/node-b', op: 'equal', target: {lease: leaseB}},
      {key: '/t/u0/attempts/wl1/2', op: 'equal', target: {version: 0}},
    ],
    success: [
      {op: 'put', key: '/t/u0/workloads/wl1', value_b64: b64(JSON.stringify({workload_id: 'wl1', image_ref: 'oci:org/app@sha256:00', desired_state: 'running', current_attempt: 2, created_at: 1}))},
      {op: 'put', key: '/t/u0/attempts/wl1/2', value_b64: b64(JSON.stringify({workload_id: 'wl1', attempt_generation: 2, node_id: 'node-b', node_generation: 1, node_lease_id: leaseB, state: 'claimed', claimed_at: 3}))},
    ],
    failure: [],
  }))).revision;

  const okPub = await publish5Way('wl1', 2, 'node-b', nodeBRev, leaseB, att2Rev, att2Rev, 'remote:snapshot:v@good');
  assert.equal(okPub.succeeded, true);
  const dupPub = await publish5Way('wl1', 2, 'node-b', nodeBRev, leaseB, att2Rev, att2Rev, 'remote:snapshot:v@dup');
  assert.equal(dupPub.succeeded, false);
  assert.equal(dupPub.responses[1].kvs.length, 1, 'result already published');

  // Canceled workload blocks late publish
  const wl2Rev = (await put('/t/u0/workloads/wl2', JSON.stringify({workload_id: 'wl2'}))).revision;
  const attWl2Rev = (await put('/t/u0/attempts/wl2/1', JSON.stringify({attempt_generation: 1}))).revision;
  await put('/t/u0/workloads/wl2/canceled', JSON.stringify({reason: 'canceled'}));
  const cancelPub = await publish5Way('wl2', 1, 'node-b', nodeBRev, leaseB, wl2Rev, attWl2Rev, 'remote:snapshot:v@late');
  assert.equal(cancelPub.succeeded, false);
  assert.equal(cancelPub.responses[0].kvs.length, 1, 'canceled marker must reject late publish');
});

test('CS-07 auth, monotonic scope, tenant isolation, node binding, live revocation, and quotas', async () => {
  await Promise.all([root.renew(), alice.renew()]);

  // Bare cookie, guest, container job, mismatched instance, cross-origin, non-cluster scope -> 403 EACCES
  await denied(rpc({op: 'hello', versions: [1]}, {Cookie: root.cookie}), 'EACCES', 403);
  await denied(rpc({op: 'hello', versions: [1]}, guest.headers), 'EACCES', 403);
  await denied(rpc({op: 'hello', versions: [1]}, {...root.headers, 'X-OS-Instance': 'wrong'}), 'EACCES', 403);
  await denied(
    mf.dispatchFetch(origin + '/api/cluster/rpc', {
      method: 'POST',
      headers: {Origin: 'https://evil.example', 'Content-Type': 'application/json', ...root.headers},
      body: JSON.stringify({version: 1, call: {op: 'hello', versions: [1]}}),
    }),
    'EACCES',
    403,
  );
  await denied(rpc({op: 'hello', versions: [1]}, await root.mint({cloud_fs: true})), 'EACCES', 403);

  const jobCred = await root.mint(FULL_CLUSTER);
  await authoritySql.exec(
    "UPDATE credentials SET ns='jobs', owner='job test' WHERE token=?",
    sha(jobCred['X-Process-Token']).toString('base64url'),
  );
  await denied(rpc({op: 'hello', versions: [1]}, jobCred), 'EACCES', 403);

  // Bare cookie WS rejected
  const bareWs = await openWatch({headers: {Cookie: root.cookie}});
  assert.equal(bareWs.status, 403);

  // Tenant isolation & X-OS-Tenant rules
  await put('/t/u0/iso/secret', 'root-only');
  await put('/t/u1000/iso/alice', 'alice-only', {headers: alice.headers});
  await denied(rpc({op: 'range', key: '/t/u0/iso/secret', range_end: 'exact'}, alice.headers), 'EACCES', 403);
  await denied(rpc({op: 'range', key: '/t/u0/iso/secret', range_end: 'exact'}, {...alice.headers, 'X-OS-Tenant': 'u0'}), 'EACCES', 403);
  const restrictedRoot = await root.mint({...FULL_CLUSTER, cluster_prefixes: ['iso/*']});
  await denied(rpc({op: 'range', key: '/t/u1000/iso/alice', range_end: 'exact'}, {...restrictedRoot, 'X-OS-Tenant': 'u1000'}), 'EACCES', 403);
  const adminCross = await good(rpc({op: 'range', key: '/t/u1000/iso/alice', range_end: 'exact'}, {...root.headers, 'X-OS-Tenant': 'u1000'}));
  assert.equal(unb64(adminCross.kvs[0].value_b64), 'alice-only');

  // Monotonic derived prefix & node-id binding
  const parentScoped = await root.mint({
    cluster_read: true,
    cluster_write: true,
    cluster_watch: true,
    cluster_lease: true,
    cluster_prefixes: ['cs07/*'],
  });
  const childScoped = await root.derive(parentScoped, FULL_CLUSTER); // cannot widen!
  await put('/t/u0/cs07/ok', '1', {headers: childScoped});
  await denied(rpc({op: 'range', key: '/t/u0/iso/secret', range_end: 'exact'}, childScoped), 'EACCES', 403);
  await denied(rpc({op: 'range', key: '/t/u0/cs07/', range_end: 'open_ended'}, childScoped), 'EACCES', 403);

  const node1Cred = await root.mint({
    cluster_read: true,
    cluster_write: true,
    cluster_lease: true,
    cluster_node_id: 'node-1',
  });
  const n1Lease = (await good(rpc({op: 'lease_grant', ttl_secs: 30, node_id: 'node-1'}, node1Cred))).lease_id;
  await denied(rpc({op: 'lease_grant', ttl_secs: 30, node_id: 'node-2'}, node1Cred), 'EACCES', 403);
  await put('/t/u0/nodes/node-1', 'ok', {leaseId: n1Lease, headers: node1Cred});
  await put('/t/u0/node-meta/node-1', 'meta-ok', {headers: node1Cred});
  await denied(
    rpc({
      op: 'txn',
      compare: [],
      success: [{op: 'put', key: '/t/u0/nodes/node-2', value_b64: b64('bad'), lease_id: n1Lease}],
      failure: [],
    }, node1Cred),
    'EACCES',
    403,
  );
  await denied(
    rpc({
      op: 'txn',
      compare: [],
      success: [{op: 'put', key: '/t/u0/node-meta/node-2', value_b64: b64('bad')}],
      failure: [],
    }, node1Cred),
    'EACCES',
    403,
  );
  for (const protectedDir of ['/t/u0/nodes/', '/t/u0/node-meta/']) {
    await denied(
      rpc({
        op: 'txn',
        compare: [],
        success: [{op: 'delete_range', key: protectedDir, range_end: 'prefix'}],
        failure: [],
      }, node1Cred),
      'EACCES',
      403,
    );
  }

  // Prefix-restricted credential denied on LeaseGrant{node_id}, LeaseRevoke, LeaseKeepAlive,
  // LeaseTimeToLive, and Put(lease_id) when lease holds node/keys outside cluster_prefixes.
  const secretLease = (await good(rpc({op: 'lease_grant', ttl_secs: 60}))).lease_id;
  await put('/t/u0/iso/leased-secret', 'do-not-touch', {leaseId: secretLease});
  await denied(rpc({op: 'lease_grant', ttl_secs: 30, node_id: 'node-1'}, childScoped), 'EACCES', 403);
  for (const forbiddenLease of [n1Lease, secretLease]) {
    await denied(rpc({op: 'lease_keep_alive', lease_id: forbiddenLease}, childScoped), 'EACCES', 403);
    await denied(rpc({op: 'lease_revoke', lease_id: forbiddenLease}, childScoped), 'EACCES', 403);
    await denied(rpc({op: 'lease_time_to_live', lease_id: forbiddenLease, keys: true}, childScoped), 'EACCES', 403);
    await denied(rpc({op: 'lease_time_to_live', lease_id: forbiddenLease, keys: false}, childScoped), 'EACCES', 403);
    await denied(
      rpc({
        op: 'txn',
        compare: [],
        success: [{op: 'put', key: '/t/u0/cs07/attach', value_b64: b64('x'), lease_id: forbiddenLease}],
        failure: [],
      }, childScoped),
      'EACCES',
      403,
    );
  }
  // Verify neither lease nor attached keys were harmed, and childScoped can still use its own in-prefix lease.
  const secretIntact = await good(rpc({op: 'range', key: '/t/u0/iso/leased-secret', range_end: 'exact'}));
  assert.equal(secretIntact.count, 1);
  const scopedOwnLease = (await good(rpc({op: 'lease_grant', ttl_secs: 30}, childScoped))).lease_id;
  await put('/t/u0/cs07/own-leased', 'ok', {leaseId: scopedOwnLease, headers: childScoped});
  await good(rpc({op: 'lease_keep_alive', lease_id: scopedOwnLease}, childScoped));
  const ownTtl = await good(rpc({op: 'lease_time_to_live', lease_id: scopedOwnLease, keys: true}, childScoped));
  assert.deepEqual(ownTtl.keys, ['/t/u0/cs07/own-leased']);
  await good(rpc({op: 'lease_revoke', lease_id: scopedOwnLease}, childScoped));

  // Cross-tenant lease_id existence oracle eliminated:
  // cluster_read-only alice (u1000) gets uniform 403 EACCES on both existing u0 lease and missing lease.
  const aliceRo = await alice.mint({cluster_read: true});
  for (const probeId of [secretLease, 999999]) {
    await denied(rpc({op: 'lease_keep_alive', lease_id: probeId}, aliceRo), 'EACCES', 403);
    await denied(rpc({op: 'lease_revoke', lease_id: probeId}, aliceRo), 'EACCES', 403);
  }
  // cluster_lease alice (u1000) gets uniform 404 ENOENT on u0's lease_id (and on u64 > i64::MAX).
  await denied(rpc({op: 'lease_keep_alive', lease_id: secretLease}, alice.headers), 'ENOENT', 404);
  await denied(rpc({op: 'lease_revoke', lease_id: secretLease}, alice.headers), 'ENOENT', 404);
  await denied(rpc({op: 'lease_time_to_live', lease_id: secretLease, keys: true}, alice.headers), 'ENOENT', 404);
  await denied(
    post(
      '/api/cluster/rpc',
      '{"version":1,"cluster":"default","call":{"op":"lease_keep_alive","lease_id":9223372036854775808}}',
      root.headers,
    ),
    'ENOENT',
    404,
  );

  // Live revocation 1: RevokeTokens invalidates RPC, unused watch-ticket, AND active WebSocket watcher!
  const revCred = await root.mint(FULL_CLUSTER);
  const unusedTicket = (await good(post('/api/cluster/watch-ticket', {version: 1}, revCred))).ticket;
  const revWs = await openWatch({headers: revCred});
  assert.equal(revWs.status, 101);
  revWs.send({op: 'hello', versions: [1]});
  assert.equal((await revWs.nextFrame()).kind, 'welcome');
  revWs.send({op: 'subscribe', watch_id: 1, key: '/t/u0/cs07/rev/', range_end: 'prefix', from_revision: 0});
  assert.equal((await revWs.nextFrame()).kind, 'subscribed');

  await root.revoke(revCred['X-Process-Token']);
  await denied(rpc({op: 'hello', versions: [1]}, revCred), 'EACCES', 403);
  const deadTicketWs = await openWatch({ticket: unusedTicket});
  assert.equal(deadTicketWs.status, 403);
  // Next mutation triggers fan-out -> active WS gets EACCES error frame + close, NEVER the new event!
  await put('/t/u0/cs07/rev/secret', 'must-not-deliver');
  const revErr = await revWs.nextFrame();
  assert.equal(revErr.kind, 'error');
  assert.equal(revErr.error.errno, 'EACCES');
  await revWs.waitClose();

  // Live revocation 2: Account lock (UPDATE users SET locked=1) terminates Alice's RPC & active WS!
  const aliceWs = await openWatch({headers: alice.headers});
  assert.equal(aliceWs.status, 101);
  aliceWs.send({op: 'hello', versions: [1]});
  assert.equal((await aliceWs.nextFrame()).kind, 'welcome');
  aliceWs.send({op: 'subscribe', watch_id: 1, key: '/t/u1000/locktest/', range_end: 'prefix', from_revision: 0});
  assert.equal((await aliceWs.nextFrame()).kind, 'subscribed');

  await authoritySql.exec('UPDATE users SET locked = 1 WHERE id = 1000');
  await denied(rpc({op: 'hello', versions: [1]}, alice.headers), 'EACCES', 403);
  await put('/t/u1000/locktest/x', 'hidden', {headers: {...root.headers, 'X-OS-Tenant': 'u1000'}});
  const lockErr = await aliceWs.nextFrame();
  assert.equal(lockErr.kind, 'error');
  assert.equal(lockErr.error.errno, 'EACCES');
  await aliceWs.waitClose();
  await authoritySql.exec('UPDATE users SET locked = 0 WHERE id = 1000');

  // Live revocation 3: Expired Machine instance lease terminates RPC & active WS!
  const expUser = await login(0);
  const expWs = await openWatch({headers: expUser.headers});
  assert.equal(expWs.status, 101);
  expWs.send({op: 'hello', versions: [1]});
  assert.equal((await expWs.nextFrame()).kind, 'welcome');
  expWs.send({op: 'subscribe', watch_id: 1, key: '/t/u0/cs07/exp/', range_end: 'prefix', from_revision: 0});
  assert.equal((await expWs.nextFrame()).kind, 'subscribed');

  const expNs = 'session.' + sha(expUser.session).toString('base64url');
  const expMachine = await mf.unsafeGetDurableObjectStorage(workerName, 'Machine', {name: expNs});
  await expMachine.exec('UPDATE instances SET expires = 0 WHERE instance_id = ?', expUser.instance);
  await denied(rpc({op: 'hello', versions: [1]}, expUser.headers), 'EACCES', 403);
  await put('/t/u0/cs07/exp/x', 'must-not-deliver');
  const expErr = await expWs.nextFrame();
  assert.equal(expErr.kind, 'error');
  assert.equal(expErr.error.errno, 'EACCES');
  await expWs.waitClose();

  // Bounds & quotas: > 256 KiB value -> EFBIG, > 1 MiB RPC body -> 413 EFBIG, > 64 compares -> 413 E2BIG, > 256 keys/lease -> 507 EDQUOT
  await denied(
    rpc({
      op: 'txn',
      compare: [],
      success: [{op: 'put', key: '/t/u0/cs07/big', value_b64: Buffer.alloc(256 * 1024 + 1).toString('base64')}],
      failure: [],
    }),
    'EFBIG',
    413,
  );
  await denied(post('/api/cluster/rpc', 'x'.repeat(1024 * 1024 + 16), root.headers), 'EFBIG', 413);
  await denied(
    rpc({
      op: 'txn',
      compare: Array.from({length: 65}, (_, i) => ({key: `/t/u0/c/${i}`, op: 'equal', target: {version: 0}})),
      success: [],
      failure: [],
    }),
    'E2BIG',
    413,
  );

  const capLease = (await good(rpc({op: 'lease_grant', ttl_secs: 60}))).lease_id;
  for (let batch = 0; batch < 4; batch++) {
    await good(rpc({
      op: 'txn',
      compare: [],
      success: Array.from({length: 64}, (_, j) => ({
        op: 'put',
        key: `/t/u0/cs07/lcap/${batch * 64 + j}`,
        value_b64: b64('v'),
        lease_id: capLease,
      })),
      failure: [],
    }));
  }
  await denied(
    rpc({
      op: 'txn',
      compare: [],
      success: [{op: 'put', key: '/t/u0/cs07/lcap/overflow', value_b64: b64('v'), lease_id: capLease}],
      failure: [],
    }),
    'EDQUOT',
    507,
  );
  // Attempting to bypass lease quota with duplicate DeleteRange + Put fails 400 EINVAL
  await denied(
    rpc({
      op: 'txn',
      compare: [],
      success: [
        {op: 'delete_range', key: '/t/u0/cs07/lcap/0', range_end: 'exact'},
        {op: 'delete_range', key: '/t/u0/cs07/lcap/0', range_end: 'exact'},
        {op: 'put', key: '/t/u0/cs07/lcap/bypass-1', value_b64: b64('v'), lease_id: capLease},
        {op: 'put', key: '/t/u0/cs07/lcap/bypass-2', value_b64: b64('v'), lease_id: capLease},
      ],
      failure: [],
    }),
    'EINVAL',
    400,
  );
});

test('CS-08 schema v1 version guard and coldStart durability without silent wipe', async () => {
  await put('/t/u0/cs08/persist', 'survives-cold-start');
  await cluster.coldStart();
  const afterCold = await good(rpc({op: 'range', key: '/t/u0/cs08/persist', range_end: 'exact'}));
  assert.equal(unb64(afterCold.kvs[0].value_b64), 'survives-cold-start');

  // Incompatible schema_meta.version fails closed with 503 EPROTONOSUPPORT and never wipes data
  await clusterSql.exec('UPDATE schema_meta SET version = 9');
  await cluster.coldStart();
  const badSchema = await rpc({op: 'range', key: '/t/u0/cs08/persist', range_end: 'exact'});
  assert.equal(badSchema.status, 503);
  assert.equal(badSchema.headers.get('X-OS-Errno'), 'EPROTONOSUPPORT');
  assert.equal((await badSchema.json()).errno, 'EPROTONOSUPPORT');

  // Restoring version = 1 proves zero data was wiped or altered
  await clusterSql.exec('UPDATE schema_meta SET version = 1');
  await cluster.coldStart();
  const intact = await good(rpc({op: 'range', key: '/t/u0/cs08/persist', range_end: 'exact'}));
  assert.equal(unb64(intact.kvs[0].value_b64), 'survives-cold-start');
});
