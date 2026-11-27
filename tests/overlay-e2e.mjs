// Phase 10b (#87) OV-07 Worker / Miniflare + real `os-cni` + real `os-native` Overlay E2E.
//
// Build crates/worker (`worker-build --release`), `os-cni`, and `os-native` first.
// Exercises:
//  1. `/api/overlay/{attach,renew,detach,connect}` auth separation (`session.*` + cookie vs
//     `node.*` rejecting any cookie), CSRF Origin refusal, guest/no-overlay-scope `403 EACCES`,
//     and single-use 30s upgrade ticket replay denial (`403`).
//  2. Real L3 IPv4 ICMP Echo + UDP roundtrip across live `OverlayRelay` SQLite DO (including
//     peer discovery `Welcome`/`PeerJoined`/`PeerLeft`, `KeepAlive`, and `Stats`).
//  3. Hostile direct WebSocket injection of spoofed source-IP and cross-tenant L3 packets:
//     verified dropped & counted in `OverlayRelay` `StatsReply` while peers receive ZERO packets.
//  4. Strictly intra-tenant WebRTC `Signal` forwarding + cross-tenant/unknown-peer `EACCES`
//     rejection + oversized (`> 16 KiB`) signal denial.
//  5. Live credential revocation (`/api/service-auth` `revoke_tokens`) disconnects active
//     `OverlayRelay` WebSocket immediately (`1008`).
//  6. Real compiled `os-cni` CLI binary (`VERSION`, `ADD`, `CHECK`, `DEL`) against live
//     `ClusterState` DO `/api/cluster/rpc`, plus simulated host-loss (wiped local `$stateDir` +
//     expired lease + IP reallocation to a new container + delayed idempotent `DEL` CAS guard
//     proving the new container's IP is NOT freed).
//  7. Real `os-native` (`--overlay-url` opt-in) end-to-end L3 attachment & roundtrip when
//     `os-native` binary is present.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const workerName = 'overlay-e2e-test';
const sha = bytes => createHash('sha256').update(bytes).digest();
const OVERLAY_FRAME_L3_PACKET = 0x01;

function findBin(name) {
  const targetDir = process.env.CARGO_TARGET_DIR || join(ROOT, 'target');
  for (const profile of ['debug', 'release']) {
    const p = join(targetDir, profile, name);
    if (existsSync(p)) return p;
  }
  return null;
}

function ipToBytes(ip) {
  return ip.split('.').map(n => Number(n) & 0xff);
}

function bytesToIp(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

function internetChecksum(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) {
    sum += (buf[i] << 8) | buf[i + 1];
  }
  if (buf.length & 1) {
    sum += buf[buf.length - 1] << 8;
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  return (~sum) & 0xffff;
}

function buildIpv4Packet(srcIp, dstIp, proto, payload) {
  const totalLen = 20 + payload.length;
  const pkt = Buffer.alloc(totalLen);
  pkt[0] = 0x45; // v4, IHL=5
  pkt[1] = 0;
  pkt.writeUInt16BE(totalLen, 2);
  pkt.writeUInt16BE(0x1234, 4);
  pkt.writeUInt16BE(0x4000, 6); // DF
  pkt[8] = 64; // TTL
  pkt[9] = proto;
  pkt.writeUInt16BE(0, 10);
  const src = ipToBytes(srcIp);
  const dst = ipToBytes(dstIp);
  for (let i = 0; i < 4; i++) {
    pkt[12 + i] = src[i];
    pkt[16 + i] = dst[i];
  }
  const hdrSum = internetChecksum(pkt.subarray(0, 20));
  pkt.writeUInt16BE(hdrSum, 10);
  payload.copy(pkt, 20);
  return pkt;
}

function buildIcmpEcho(srcIp, dstIp, type, id, seq, text) {
  const data = Buffer.from(text, 'utf8');
  const icmp = Buffer.alloc(8 + data.length);
  icmp[0] = type; // 8 = request, 0 = reply
  icmp[1] = 0;
  icmp.writeUInt16BE(0, 2);
  icmp.writeUInt16BE(id, 4);
  icmp.writeUInt16BE(seq, 6);
  data.copy(icmp, 8);
  icmp.writeUInt16BE(internetChecksum(icmp), 2);
  return buildIpv4Packet(srcIp, dstIp, 1, icmp);
}

function encodeL3Frame(pkt) {
  const out = new Uint8Array(1 + pkt.length);
  out[0] = OVERLAY_FRAME_L3_PACKET;
  out.set(pkt, 1);
  return out;
}

const OVERLAY_SCOPE = {
  overlay: {
    networks: ['default'],
    max_interfaces: 4,
    max_mtu: 1420,
    max_bytes_per_sec: 10 * 1024 * 1024,
    cni_ipam: true,
    allowed_peer_cidrs: [],
  },
};

const FULL_NODE_CLUSTER_SCOPE = {
  cluster_read: true,
  cluster_write: true,
  cluster_watch: true,
  cluster_lease: true,
  cluster_compact: false,
  cluster_prefixes: ['nodes/*', 'overlay/*'],
  overlay: OVERLAY_SCOPE.overlay,
};

let mf, baseUrl, authoritySql, clusterDo, root, alice, guest, workDir;

async function post(path, body, headers = {}) {
  return mf.dispatchFetch(baseUrl + path, {
    method: 'POST',
    headers: { Origin: baseUrl, 'Content-Type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

async function good(response) {
  const res = await response;
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  assert.equal(res.status, 200, `expected 200, got ${res.status}: ${text}`);
  return body;
}

async function denied(response, errno, status) {
  const res = await response;
  const text = await res.text();
  assert.ok(res.status >= 400, `expected error status, got ${res.status}: ${text}`);
  if (status !== undefined) assert.equal(res.status, status, text);
  let body;
  try { body = JSON.parse(text); } catch { body = { raw: text }; }
  if (errno !== undefined) assert.equal(body.errno, errno, text);
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
  const auth = value => good(post('/api/service-auth', value, { Cookie: cookie }));
  await auth({ attach_instance: { instance: { instance, host: 'overlay-e2e' }, host_proof: proof } });
  const mint = async (scope, limits = {}) => {
    const { cred } = await auth({
      mint_service_cred: { instance_id: instance, host_proof: proof, scope, ...limits },
    });
    return { Cookie: cookie, 'X-OS-Instance': instance, 'X-Process-Token': cred.token };
  };
  return {
    cookie,
    instance,
    proof,
    auth,
    mint,
    revoke: token => auth({
      revoke_tokens: { instance_id: instance, host_proof: proof, tokens: [token] },
    }),
  };
}

async function enrollNode(admin, nodeId) {
  const { bootstrap_token: issued } = await admin.auth({
    mint_bootstrap_token: {
      instance_id: admin.instance,
      host_proof: admin.proof,
      node_id: nodeId,
      cluster: 'default',
      ttl_secs: 300,
      scope: FULL_NODE_CLUSTER_SCOPE,
    },
  });
  const nodeInstance = 'inst-node-' + randomUUID();
  const nodeProof = randomBytes(32).toString('hex');
  const { node_enrolled: nc } = await good(post('/api/service-auth', {
    exchange_bootstrap_token: {
      bootstrap_token: issued.bootstrap_token,
      instance: { instance: nodeInstance, host: 'overlay-node' },
      host_proof: nodeProof,
    },
  }));
  return {
    nodeId,
    token: nc.token,
    instanceId: nc.instance_id,
    headers: {
      'X-OS-Instance': nc.instance_id,
      'X-Process-Token': nc.token,
    },
  };
}

async function openOverlayWs(wsUrlPath, headers = {}) {
  const fullUrl = wsUrlPath.startsWith('http') ? wsUrlPath : `${baseUrl}${wsUrlPath}`;
  const res = await mf.dispatchFetch(fullUrl, {
    headers: { Upgrade: 'websocket', Origin: baseUrl, ...headers },
  });
  if (res.status !== 101) {
    return { status: res.status, response: res };
  }
  const ws = res.webSocket;
  assert.ok(ws, '101 response must include webSocket');
  const textQueue = [];
  const binQueue = [];
  const textWaiters = [];
  const binWaiters = [];
  let closed = null;
  const closeWaiters = [];

  ws.addEventListener('message', ev => {
    if (typeof ev.data === 'string') {
      const msg = JSON.parse(ev.data);
      if (textWaiters.length > 0) textWaiters.shift().resolve(msg);
      else textQueue.push(msg);
    } else {
      const bytes = Buffer.from(ev.data instanceof Uint8Array ? ev.data : new Uint8Array(ev.data));
      if (binWaiters.length > 0) binWaiters.shift().resolve(bytes);
      else binQueue.push(bytes);
    }
  });
  ws.addEventListener('close', ev => {
    closed = { code: ev.code, reason: ev.reason };
    while (closeWaiters.length > 0) closeWaiters.shift().resolve(closed);
    while (textWaiters.length > 0) textWaiters.shift().reject(new Error(`ws closed (${ev.code}: ${ev.reason})`));
    while (binWaiters.length > 0) binWaiters.shift().reject(new Error(`ws closed (${ev.code}: ${ev.reason})`));
  });
  ws.accept();
  ws.send(JSON.stringify({ kind: 'hello', versions: [1] }));

  const waitFrom = (queue, waiters, timeoutMs, label) => {
    if (queue.length > 0) return Promise.resolve(queue.shift());
    if (closed) return Promise.reject(new Error(`ws closed (${closed.code}: ${closed.reason})`));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = waiters.findIndex(w => w.resolve === wrapOk);
        if (idx >= 0) waiters.splice(idx, 1);
        reject(new Error(`timed out waiting for ${label} after ${timeoutMs}ms`));
      }, timeoutMs);
      const wrapOk = v => { clearTimeout(timer); resolve(v); };
      const wrapErr = e => { clearTimeout(timer); reject(e); };
      waiters.push({ resolve: wrapOk, reject: wrapErr });
    });
  };

  return {
    status: 101,
    ws,
    sendJson: obj => ws.send(JSON.stringify(obj)),
    sendL3: pkt => ws.send(encodeL3Frame(pkt)),
    nextJson: (ms = 5000) => waitFrom(textQueue, textWaiters, ms, 'JSON frame'),
    nextBinary: (ms = 5000) => waitFrom(binQueue, binWaiters, ms, 'binary frame'),
    async nextJsonKind(kind, ms = 5000) {
      const deadline = Date.now() + ms;
      while (Date.now() < deadline) {
        const msg = await waitFrom(textQueue, textWaiters, Math.max(50, deadline - Date.now()), `JSON(${kind})`);
        if (msg.kind === kind) return msg;
      }
      throw new Error(`timed out waiting for JSON kind=${kind}`);
    },
    async expectNoBinary(ms = 200) {
      if (binQueue.length > 0) {
        throw new Error(`unexpected binary packet (${binQueue[0].length} bytes)`);
      }
      await new Promise(r => setTimeout(r, ms));
      if (binQueue.length > 0) {
        throw new Error(`unexpected binary packet (${binQueue[0].length} bytes)`);
      }
    },
    waitClose(ms = 5000) {
      if (closed) return Promise.resolve(closed);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for WS close')), ms);
        closeWaiters.push({ resolve: v => { clearTimeout(timer); resolve(v); } });
      });
    },
    close() {
      try { ws.close(1000, 'done'); } catch {}
    },
  };
}

function runCni(cniBin, env, configObj) {
  try {
    const stdout = execFileSync(cniBin, [], {
      input: JSON.stringify(configObj),
      env: { ...process.env, ...env },
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { code: 0, stdout: stdout.trim(), json: stdout.trim() ? JSON.parse(stdout) : null };
  } catch (err) {
    const stdout = (err.stdout || '').toString().trim();
    const stderr = (err.stderr || '').toString().trim();
    let json = null;
    try { json = stdout ? JSON.parse(stdout) : null; } catch {}
    return { code: err.status ?? 1, stdout, stderr, json };
  }
}

before(async () => {
  workDir = mkdtempSync(join(tmpdir(), 'os-overlay-e2e-'));
  const classes = ['OsAuthority', 'Machine', 'ClusterState', 'OverlayRelay'];
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
                import {
                  OsAuthority as Authority,
                  Machine as Service,
                  ClusterState as Cluster,
                  OverlayRelay as Relay,
                } from './index.js';
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
                }
                export class OverlayRelay extends DurableObject {
                  constructor(ctx, env) { super(ctx, env); this.impl = new Relay(ctx, env); }
                  coldStart() { this.impl = new Relay(this.ctx, this.env); }
                  fetch(r) { return this.impl.fetch(r); }
                  alarm() { return this.impl.alarm(); }
                  async triggerAlarm() { await this.impl.alarm(); }
                  webSocketMessage(ws, msg) { return this.impl.webSocketMessage(ws, msg); }
                  webSocketClose(ws, code, reason, wasClean) { return this.impl.webSocketClose(ws, code, reason, wasClean); }
                  webSocketError(ws, err) { return this.impl.webSocketError(ws, err); }
                }`,
            },
            'index.js': { type: 'esm', contents: readFileSync(join(ROOT, 'crates/worker/build/index.js'), 'utf8') },
            'index_bg.wasm': { type: 'wasm', contents: readFileSync(join(ROOT, 'crates/worker/build/index_bg.wasm')) },
          },
        },
        exports: Object.fromEntries(classes.map(n => [n, { type: 'durable-object', storage: 'sqlite' }])),
        env: {
          ...Object.fromEntries(['AUTHORITY', 'MACHINE', 'CLUSTER_STATE', 'OVERLAY_RELAY'].map(
            (binding, i) => [binding, { type: 'durable-object', worker: workerName, exportName: classes[i] }],
          )),
          FILES: { type: 'r2', name: 'files-overlay-e2e' },
          ADMIN_PASSWORD: { type: 'text', value: randomUUID() },
          SESSION_SECRET: { type: 'text', value: randomUUID() },
          ASSETS: {
            type: 'fetcher',
            handler: () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }),
          },
        },
      },
    }],
  });
  const url = await mf.ready;
  baseUrl = url.origin;
  await good(post('/api/sys', { calls: ['getcreds'] }));
  authoritySql = await mf.unsafeGetDurableObjectStorage(workerName, 'OsAuthority', { name: 'filesystem' });
  await authoritySql.exec(
    "INSERT INTO users(id,name,gid,groups,home,locked,salt,hash) VALUES(1000,'alice',1000,'[1000]','/home/alice',0,'','')",
  );
  const clusterNs = await mf.getDurableObjectNamespace('CLUSTER_STATE');
  clusterDo = clusterNs.get(clusterNs.idFromName('cluster:default'));
  root = await login(0);
  alice = await login(1000);
  guest = await login(null);
});

after(async () => {
  if (mf) await mf.dispose();
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

test('OV-07a auth separation (session.* cookie vs node.* no-cookie), CSRF, default-deny, and single-use tickets', async () => {
  // 1. Default-deny: credential without `overlay` scope is refused (`403 EACCES`).
  const noOverlayHdrs = await root.mint({ cloud_fs: true });
  await denied(post('/api/overlay/attach', { network: 'default' }, noOverlayHdrs), 'EACCES', 403);

  // 2. Guest credential is ALWAYS refused even if requesting overlay scope.
  const guestHdrs = await guest.mint(OVERLAY_SCOPE);
  await denied(post('/api/overlay/attach', { network: 'default' }, guestHdrs), 'EACCES', 403);

  // 3. `session.*` credential MUST include matching `os_session` cookie (bare header rejected!).
  const rootHdrs = await root.mint(OVERLAY_SCOPE);
  const rootNoCookie = { 'X-OS-Instance': rootHdrs['X-OS-Instance'], 'X-Process-Token': rootHdrs['X-Process-Token'] };
  await denied(post('/api/overlay/attach', { network: 'default' }, rootNoCookie), 'EACCES', 403);

  // 4. Cross-origin CSRF refused on mutating `session.*` POST!
  await denied(
    post('/api/overlay/attach', { network: 'default' }, { ...rootHdrs, Origin: 'https://evil.example' }),
    'EACCES',
    403,
  );

  // 5. `node.*` credential succeeds WITHOUT cookie, and REJECTS any cookie!
  const node = await enrollNode(root, 'node-ov07-auth');
  await denied(
    post('/api/overlay/attach', { network: 'default' }, { ...node.headers, Cookie: root.cookie }),
    'EACCES',
    403,
  );
  const nodeAttach = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'native' }, node.headers));
  assert.equal(nodeAttach.version, 1);
  assert.equal(nodeAttach.tenant, 'u0');
  assert.ok(nodeAttach.ticket && nodeAttach.ip && nodeAttach.lease_id > 0);

  // 6. Renew succeeds for owner and returns fresh `expires_at`.
  const renewed = await good(post('/api/overlay/renew', {
    endpoint_id: nodeAttach.endpoint_id,
    lease_id: nodeAttach.lease_id,
    network: 'default',
  }, node.headers));
  assert.equal(renewed.lease_id, nodeAttach.lease_id);
  assert.ok(renewed.expires_at >= nodeAttach.expires_at);

  // 7. Single-use ticket: first WS upgrade succeeds (`101`), second replay fails (`403`)!
  const ws1 = await openOverlayWs(nodeAttach.ws_url, node.headers);
  assert.equal(ws1.status, 101);
  const welcome = await ws1.nextJsonKind('welcome');
  assert.equal(welcome.endpoint_id, nodeAttach.endpoint_id);
  assert.equal(welcome.ip, nodeAttach.ip);

  const replay = await openOverlayWs(nodeAttach.ws_url, node.headers);
  assert.equal(replay.status, 403, 'replaying a consumed overlay ticket must fail 403');

  // 8. P0-4 security: cross-node renew/detach/direct-connect & unverified lease_id revocation DENIED!
  const nodeOther = await enrollNode(root, 'node-ov07-other');
  await denied(
    post('/api/overlay/renew', {
      endpoint_id: nodeAttach.endpoint_id,
      lease_id: nodeAttach.lease_id,
      network: 'default',
    }, nodeOther.headers),
    'EACCES',
    403,
  );
  await denied(
    post('/api/overlay/detach', {
      endpoint_id: nodeAttach.endpoint_id,
      lease_id: nodeAttach.lease_id,
      network: 'default',
    }, nodeOther.headers),
    'EACCES',
    403,
  );
  // Detaching a non-existent endpoint with a live lease_id belonging to another endpoint MUST be a
  // harmless idempotent 200 no-op and MUST NOT revoke `nodeAttach.lease_id`!
  await good(post('/api/overlay/detach', {
    endpoint_id: 'ep-nonexistent-000',
    lease_id: nodeAttach.lease_id,
    network: 'default',
  }, nodeOther.headers));
  // Mismatched non-zero `lease_id` from owner MUST return 412 ESTALE without revoking anything.
  await denied(
    post('/api/overlay/detach', {
      endpoint_id: nodeAttach.endpoint_id,
      lease_id: nodeAttach.lease_id + 999999,
      network: 'default',
    }, node.headers),
    'ESTALE',
    412,
  );
  // Direct `?endpoint_id=` reconnect MUST reject `session.*` credentials AND cross-node `node.*` credentials!
  const directPath = `/api/overlay/connect?endpoint_id=${encodeURIComponent(nodeAttach.endpoint_id)}&network=default`;
  const sessionDirect = await openOverlayWs(directPath, rootHdrs);
  assert.equal(sessionDirect.status, 403, 'session.* must not use direct ?endpoint_id= reconnect');
  const otherNodeDirect = await openOverlayWs(directPath, nodeOther.headers);
  assert.equal(otherNodeDirect.status, 403, 'cross-node node.* must not hijack another node endpoint');

  // P1-1 replaced-socket close race: owner direct reconnect replaces `ws1`; closing old `ws1`
  // MUST NOT evict the active `ws2` row!
  const ws2 = await openOverlayWs(directPath, node.headers);
  assert.equal(ws2.status, 101, 'owning node.* direct reconnect must succeed');
  await ws2.nextJsonKind('welcome');
  ws1.close();
  await new Promise(r => setTimeout(r, 100));
  ws2.sendJson({ kind: 'stats' });
  const ws2Stats = await ws2.nextJsonKind('stats_reply');
  assert.equal(ws2Stats.kind, 'stats_reply');
  assert.equal(typeof ws2Stats.tx_packets, 'number');
  ws2.close();

  // Confirm `nodeAttach` lease remained alive through all rejected hostile detach attempts.
  await good(post('/api/overlay/renew', {
    endpoint_id: nodeAttach.endpoint_id,
    lease_id: nodeAttach.lease_id,
    network: 'default',
  }, node.headers));

  await good(post('/api/overlay/detach', {
    endpoint_id: nodeAttach.endpoint_id,
    lease_id: nodeAttach.lease_id,
    network: 'default',
  }, node.headers));

  // 9. P1-2 per-node `max_interfaces` quota enforcement (`max_interfaces: 1`).
  const maxOneHdrs = await root.mint({
    overlay: {
      networks: ['default'],
      max_interfaces: 1,
      max_mtu: 1420,
      max_bytes_per_sec: 10 * 1024 * 1024,
      cni_ipam: false,
      allowed_peer_cidrs: [],
    },
  });
  const q1 = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'browser' }, maxOneHdrs));
  await denied(post('/api/overlay/attach', { network: 'default', host_kind: 'browser' }, maxOneHdrs), 'ENOSPC', 507);
  await good(post('/api/overlay/detach', { endpoint_id: q1.endpoint_id, lease_id: q1.lease_id, network: 'default' }, maxOneHdrs));
  const q2 = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'browser' }, maxOneHdrs));
  await good(post('/api/overlay/detach', { endpoint_id: q2.endpoint_id, lease_id: q2.lease_id, network: 'default' }, maxOneHdrs));
});

test('OV-07b OverlayRelay L3 roundtrip, hostile anti-spoofing/cross-tenant drops, intra-tenant WebRTC signal, and live revocation', async () => {
  const hdrA = await root.mint(OVERLAY_SCOPE);
  const hdrB = await root.mint(OVERLAY_SCOPE);
  const hdrAlice = await alice.mint(OVERLAY_SCOPE);

  const attA = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'native' }, hdrA));
  const attB = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'browser' }, hdrB));
  const attAlice = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'browser' }, hdrAlice));

  assert.equal(attA.tenant, 'u0');
  assert.equal(attB.tenant, 'u0');
  assert.equal(attAlice.tenant, 'u1000');
  assert.notEqual(attA.ip, attB.ip);
  assert.notEqual(attA.cidr, attAlice.cidr, 'distinct tenants must get disjoint CIDRs');

  const wsA = await openOverlayWs(attA.ws_url, hdrA);
  const wsB = await openOverlayWs(attB.ws_url, hdrB);
  const wsAlice = await openOverlayWs(attAlice.ws_url, hdrAlice);
  assert.equal(wsA.status, 101);
  assert.equal(wsB.status, 101);
  assert.equal(wsAlice.status, 101);

  await wsA.nextJsonKind('welcome');
  const welcomeB = await wsB.nextJsonKind('welcome');
  assert.ok(welcomeB.peers.some(p => p.endpoint_id === attA.endpoint_id), 'Peer B must see Peer A in Welcome');
  await wsAlice.nextJsonKind('welcome');

  // 1. Valid intra-tenant L3 ICMP Echo Request A -> B and Reply B -> A
  const pingPkt = buildIcmpEcho(attA.ip, attB.ip, 8, 0x7777, 1, 'ov07-relay-ping');
  wsA.sendL3(pingPkt);
  const rxAtB = await wsB.nextBinary();
  assert.equal(rxAtB[0], OVERLAY_FRAME_L3_PACKET);
  const l3AtB = rxAtB.subarray(1);
  assert.equal(bytesToIp(l3AtB, 12), attA.ip);
  assert.equal(bytesToIp(l3AtB, 16), attB.ip);
  assert.equal(l3AtB.subarray(28).toString('utf8'), 'ov07-relay-ping');

  const pongPkt = buildIcmpEcho(attB.ip, attA.ip, 0, 0x7777, 1, 'ov07-relay-ping');
  wsB.sendL3(pongPkt);
  const rxAtA = await wsA.nextBinary();
  assert.equal(rxAtA[0], OVERLAY_FRAME_L3_PACKET);
  assert.equal(bytesToIp(rxAtA.subarray(1), 12), attB.ip);
  assert.equal(rxAtA.subarray(29).toString('utf8'), 'ov07-relay-ping');

  // 2. Hostile direct WS injection: spoofed source IP (A claims to be B's IP or another IP)
  const spoofPkt = buildIcmpEcho(attB.ip, attB.ip, 8, 1, 1, 'spoof');
  const spoofOther = buildIcmpEcho(attA.gateway, attB.ip, 8, 1, 2, 'spoof-gw');
  wsA.sendL3(spoofPkt);
  wsA.sendL3(spoofOther);

  // 3. Hostile direct WS injection: cross-tenant packet (Tenant u0 A -> Tenant u1000 Alice!)
  const crossPkt = buildIcmpEcho(attA.ip, attAlice.ip, 8, 2, 1, 'cross-tenant-attack');
  wsA.sendL3(crossPkt);

  // Verify neither Peer B nor Tenant u1000 Alice received ANY malicious packet!
  await wsB.expectNoBinary(200);
  await wsAlice.expectNoBinary(200);

  // Query OverlayRelay StatsReply from Peer A and verify server-side drop counters incremented!
  wsA.sendJson({ kind: 'stats' });
  const stats = await wsA.nextJsonKind('stats_reply');
  assert.ok(stats.dropped_spoofed_src >= 2, `expected >=2 spoofed_src drops: ${JSON.stringify(stats)}`);
  assert.ok(stats.dropped_cross_tenant >= 1, `expected >=1 cross_tenant drop: ${JSON.stringify(stats)}`);

  // 4. Intra-tenant WebRTC `Signal` succeeds A -> B; cross-tenant `Signal` A -> Alice fails `EACCES`!
  wsA.sendJson({
    kind: 'signal',
    to_endpoint_id: attB.endpoint_id,
    payload: { type: 'offer', sdp: 'v=0\r\ntest-sdp\r\n' },
  });
  const sigAtB = await wsB.nextJsonKind('signal');
  assert.equal(sigAtB.from_endpoint_id, attA.endpoint_id);
  assert.equal(sigAtB.payload.type, 'offer');

  wsA.sendJson({
    kind: 'signal',
    to_endpoint_id: attAlice.endpoint_id,
    payload: { type: 'offer', sdp: 'cross-tenant-hijack' },
  });
  const sigErr = await wsA.nextJsonKind('error');
  assert.equal(sigErr.errno, 'EACCES');

  // 5. Live revocation: revoking Peer A's credential tears down its active WS immediately on next check/keepalive!
  await root.revoke(hdrA['X-Process-Token']);
  wsA.sendJson({ kind: 'keep_alive', seq: 99 });
  const closedA = await wsA.waitClose(5000);
  assert.equal(closedA.code, 1008, `expected 1008 policy close on revocation, got ${JSON.stringify(closedA)}`);

  wsB.close();
  wsAlice.close();
  await good(post('/api/overlay/detach', { endpoint_id: attB.endpoint_id, lease_id: attB.lease_id, network: 'default' }, hdrB));
  await good(post('/api/overlay/detach', { endpoint_id: attAlice.endpoint_id, lease_id: attAlice.lease_id, network: 'default' }, hdrAlice));
});

test('OV-07c real os-cni CLI binary against live ClusterState DO + host-loss lease expiry + CAS-safe idempotent DEL', async () => {
  const cniBin = findBin('os-cni');
  assert.ok(cniBin, 'compiled `os-cni` binary must exist in target/{debug,release}/os-cni');

  const node = await enrollNode(root, 'node-ov07-cni');
  const cniStateDir = join(workDir, 'cni-state');
  mkdirSync(cniStateDir, { recursive: true });
  const tokenFile = join(workDir, 'cni-node.token');
  writeFileSync(tokenFile, node.token, { mode: 0o600 });

  const netConf = (extra = {}) => ({
    cniVersion: '1.0.0',
    name: 'default',
    type: 'os-cni',
    tenant: 'u0',
    cluster: 'default',
    nodeId: node.nodeId,
    endpointUrl: baseUrl,
    tokenFile,
    instanceId: node.instanceId,
    stateDir: cniStateDir,
    driver: 'userspace',
    leaseTtlSecs: 5,
    ...extra,
  });

  // 1. VERSION
  const ver = runCni(cniBin, { CNI_COMMAND: 'VERSION' }, {});
  assert.equal(ver.code, 0, ver.stderr);
  assert.equal(ver.json.cniVersion, '1.0.0');

  // 2. ADD container-1
  const addEnv1 = {
    CNI_COMMAND: 'ADD',
    CNI_CONTAINERID: 'ctr-ov07-1',
    CNI_NETNS: '/run/netns/ctr-ov07-1',
    CNI_IFNAME: 'tun0',
  };
  const add1 = runCni(cniBin, addEnv1, netConf());
  assert.equal(add1.code, 0, `ADD ctr-1 failed: ${add1.stdout} ${add1.stderr}`);
  assert.equal(add1.json.cniVersion, '1.0.0');
  const ip1Cidr = add1.json.ips[0].address;
  const ip1 = ip1Cidr.split('/')[0];

  // 3. CHECK container-1 while lease is live
  const chk1 = runCni(cniBin, { ...addEnv1, CNI_COMMAND: 'CHECK' }, netConf({ prevResult: add1.json }));
  assert.equal(chk1.code, 0, `CHECK ctr-1 failed: ${chk1.stdout} ${chk1.stderr}`);

  // 4. Simulate host loss: wipe local `$cniStateDir`, let 5s lease expire in ClusterState DO + triggerAlarm!
  rmSync(cniStateDir, { recursive: true, force: true });
  mkdirSync(cniStateDir, { recursive: true });
  await new Promise(r => setTimeout(r, 5300));
  await clusterDo.triggerAlarm();

  // 5. New container-2 requests the SAME IP (`staticIp: ip1`) -> MUST succeed because ctr-1's lease expired!
  const addEnv2 = {
    CNI_COMMAND: 'ADD',
    CNI_CONTAINERID: 'ctr-ov07-2',
    CNI_NETNS: '/run/netns/ctr-ov07-2',
    CNI_IFNAME: 'tun0',
  };
  const add2 = runCni(cniBin, addEnv2, netConf({ staticIp: ip1, leaseTtlSecs: 60 }));
  assert.equal(add2.code, 0, `ADD ctr-2 staticIp failed: ${add2.stdout} ${add2.stderr}`);
  assert.equal(add2.json.ips[0].address, ip1Cidr);

  // 6. Delayed idempotent DEL for lost container-1 MUST succeed (exit 0) AND MUST NOT free ctr-2's IP!
  const del1 = runCni(cniBin, { ...addEnv1, CNI_COMMAND: 'DEL' }, netConf());
  assert.equal(del1.code, 0, `delayed host-loss DEL ctr-1 failed: ${del1.stdout} ${del1.stderr}`);

  // Double DEL is also strictly idempotent.
  const del1Again = runCni(cniBin, { ...addEnv1, CNI_COMMAND: 'DEL' }, netConf());
  assert.equal(del1Again.code, 0, `second DEL ctr-1 failed: ${del1Again.stdout} ${del1Again.stderr}`);

  // Verify container-2's IP & lease are 100% intact via CHECK!
  const chk2 = runCni(cniBin, { ...addEnv2, CNI_COMMAND: 'CHECK' }, netConf({ prevResult: add2.json, leaseTtlSecs: 60 }));
  assert.equal(chk2.code, 0, `ctr-2 CHECK must still pass after ctr-1 delayed DEL: ${chk2.stdout} ${chk2.stderr}`);

  // Clean up container-2.
  const del2 = runCni(cniBin, { ...addEnv2, CNI_COMMAND: 'DEL' }, netConf());
  assert.equal(del2.code, 0, `DEL ctr-2 failed: ${del2.stdout} ${del2.stderr}`);
});

test('OV-07d real compiled os-native --overlay-url L3 ICMP roundtrip through live OverlayRelay DO + clean teardown', async () => {
  const nativeBin = findBin('os-native');
  assert.ok(nativeBin, 'compiled `os-native` binary must exist in target/{debug,release}/os-native');
  const xtaskBin = findBin('xtask');
  assert.ok(xtaskBin, 'compiled `xtask` binary must exist in target/{debug,release}/xtask');
  const distDir = join(ROOT, 'dist');
  assert.ok(existsSync(join(distDir, 'os-config.json')), 'dist/ assets must be built via xtask build');

  // Assemble an ephemeral unsigned dev Release v2 bundle from `dist/` for `os-native run`.
  const bundleDir = join(workDir, 'bundle-ov07d');
  execFileSync(xtaskBin, ['boot', '--assets', distDir, '--out', bundleDir], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
  });
  assert.ok(existsSync(join(bundleDir, 'release.json')), 'xtask boot must emit release.json');

  const nativeNode = await enrollNode(root, 'node-ov07d-native');
  const peerNode = await enrollNode(root, 'node-ov07d-peer');

  // Attach live peer on Tenant u0 echoing L3 ICMP Echo Requests back over OverlayRelay WS.
  const peerAtt = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'native' }, peerNode.headers));
  const peerWs = await openOverlayWs(peerAtt.ws_url, peerNode.headers);
  assert.equal(peerWs.status, 101);
  await peerWs.nextJsonKind('welcome');

  let peerEchoCount = 0;
  let stopEcho = false;
  const echoLoop = (async () => {
    while (!stopEcho) {
      let frame;
      try {
        frame = await peerWs.nextBinary(500);
      } catch {
        continue;
      }
      if (frame.length > 28 && frame[0] === OVERLAY_FRAME_L3_PACKET) {
        const pkt = Buffer.from(frame.subarray(1));
        if ((pkt[0] >> 4) === 4 && pkt[9] === 1 && pkt[20] === 8) {
          const src = bytesToIp(pkt, 12);
          const dst = bytesToIp(pkt, 16);
          const id = pkt.readUInt16BE(24);
          const seq = pkt.readUInt16BE(26);
          const payload = pkt.subarray(28).toString('utf8');
          peerEchoCount += 1;
          peerWs.sendL3(buildIcmpEcho(dst, src, 0, id, seq, payload));
        }
      }
    }
  })();

  // Keep stateDir (and its AF_UNIX seat.sock/ctl.sock paths) well under Linux's 108-byte `sun_path` limit.
  const nativeState = `/tmp/ov07d-${randomBytes(4).toString('hex')}`;
  mkdirSync(nativeState, { recursive: true });
  const sockPath = join(nativeState, 'seat.sock');
  const tokPath = join(nativeState, 'bootstrap.tok');
  const readyPath = join(nativeState, 'ready.json');

  const stderrBuf = [];
  const child = spawn(nativeBin, [
    'run',
    '--bundle', bundleDir,
    '--state', nativeState,
    '--allow-unsigned-dev',
    '--root', 'ephemeral',
    '--no-console-shell',
    '--unix', sockPath,
    '--bootstrap-token-file', tokPath,
    '--ready-file', readyPath,
    '--overlay-url', baseUrl,
    '--overlay-token', nativeNode.token,
    '--overlay-instance', nativeNode.instanceId,
    '--overlay-tenant', 'u0',
    '--overlay-network', 'default',
  ], { stdio: ['ignore', 'pipe', 'pipe'] });
  child.stderr.on('data', d => stderrBuf.push(d.toString()));

  let exited = null;
  child.once('exit', (code, sig) => { exited = { code, sig }; });

  try {
    const deadline = Date.now() + 20_000;
    while (!existsSync(readyPath) || !existsSync(tokPath)) {
      if (exited) {
        throw new Error(`os-native exited early (${JSON.stringify(exited)}): ${stderrBuf.join('')}`);
      }
      if (Date.now() > deadline) {
        throw new Error(`os-native did not become ready in 20s: ${stderrBuf.join('')}`);
      }
      await new Promise(r => setTimeout(r, 100));
    }

    // Execute real `/usr/bin/tunctl probe` inside `os-native` over `/dev/net/tun` -> OverlayRelay -> Peer!
    // MUST use async `spawn` (never `execFileSync`) so this Node process's event loop stays live to
    // drive `echoLoop` on `peerWs` while `tunctl probe` waits for the ICMP Echo Reply!
    const probeRes = await new Promise((resolve, reject) => {
      const p = spawn(nativeBin, [
        'exec',
        '--target', `unix://${sockPath}`,
        '--token-file', tokPath,
        '--',
        '/usr/bin/tunctl', 'probe',
        '--dst', peerAtt.ip,
        '--proto', 'icmp',
        '--payload', 'ov07d-native-ok',
        '--json',
      ], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '', err = '';
      p.stdout.on('data', d => { out += d.toString(); });
      p.stderr.on('data', d => { err += d.toString(); });
      const timer = setTimeout(() => {
        try { p.kill('SIGKILL'); } catch {}
        reject(new Error(`os-native exec timed out; stdout=${out} stderr=${err}`));
      }, 15_000);
      p.once('error', e => { clearTimeout(timer); reject(e); });
      p.once('close', (code, sig) => {
        clearTimeout(timer);
        resolve({ code, sig, stdout: out, stderr: err });
      });
    });

    assert.equal(probeRes.code, 0, `tunctl probe failed (code=${probeRes.code}): ${probeRes.stderr} (host stderr: ${stderrBuf.join('')})`);
    const probeJson = JSON.parse(probeRes.stdout.trim());
    assert.equal(probeJson.reply_src, peerAtt.ip, `unexpected reply_src: ${probeRes.stdout}`);
    assert.equal(probeJson.reply_payload, 'ov07d-native-ok', `unexpected payload: ${probeRes.stdout}`);
    assert.ok(peerEchoCount >= 1, 'peer must have echoed at least 1 real ICMP packet from os-native');

    // Confirm peer observed `peer_left` after `tunctl` closed `/dev/net/tun` and detached cleanly!
    const peerLeft = await peerWs.nextJsonKind('peer_left', 5000);
    assert.ok(peerLeft.endpoint_id, 'expected peer_left after os-native TUN close');
  } finally {
    stopEcho = true;
    if (!exited) {
      child.kill('SIGTERM');
      await new Promise(resolve => {
        const t = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} resolve(); }, 5000);
        child.once('exit', () => { clearTimeout(t); resolve(); });
      });
    }
    peerWs.close();
    await echoLoop.catch(() => {});
    try { rmSync(nativeState, { recursive: true, force: true }); } catch {}
    await good(post('/api/overlay/detach', {
      endpoint_id: peerAtt.endpoint_id,
      lease_id: peerAtt.lease_id,
      network: 'default',
    }, peerNode.headers));
  }
});

test('OV-07e OverlayRelay alarm() evicts expired endpoints, purges expired tickets, and broadcasts peer_left', async () => {
  const hdr1 = await root.mint(OVERLAY_SCOPE);
  const hdr2 = await root.mint(OVERLAY_SCOPE);
  const att1 = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'browser' }, hdr1));
  const att2 = await good(post('/api/overlay/attach', { network: 'default', host_kind: 'browser' }, hdr2));

  const ws1 = await openOverlayWs(att1.ws_url, hdr1);
  const ws2 = await openOverlayWs(att2.ws_url, hdr2);
  assert.equal(ws1.status, 101);
  assert.equal(ws2.status, 101);
  await ws1.nextJsonKind('welcome');
  await ws2.nextJsonKind('welcome');

  const relayName = 'overlay:default:u0:default';
  const relayNs = await mf.getDurableObjectNamespace('OVERLAY_RELAY');
  const relayDo = relayNs.get(relayNs.idFromName(relayName));
  const relaySql = await mf.unsafeGetDurableObjectStorage(workerName, 'OverlayRelay', { name: relayName });

  // Expire endpoint 1's lease row AND insert an already-expired ticket to verify both SQL paths commit.
  await relaySql.exec(
    'UPDATE overlay_endpoints SET lease_expires_at = 1 WHERE endpoint_id = ?',
    att1.endpoint_id,
  );
  await relaySql.exec(
    `INSERT INTO overlay_tickets(
       ticket_hash, endpoint_id, tenant, network, ip, prefix_len, gateway, cidr, ipv6, mtu,
       lease_id, lease_expires_at, host_kind, ns, cred_hash, instance_id,
       allowed_peer_cidrs_json, max_bytes_per_sec, expires_at
     ) VALUES('expired-ticket-ov07e', 'ep-expired', 'u0', 'default', '10.64.0.99', 24, '10.64.0.1',
       '10.64.0.0/24', NULL, 1420, 999, 1, 'browser', 'session.0', 'deadbeef', 'inst-exp', '[]', 0, 1)`,
  );

  await relayDo.triggerAlarm();

  // 1. Expired endpoint 1's WebSocket closes with 1008.
  const closed1 = await ws1.waitClose(5000);
  assert.equal(closed1.code, 1008, `expected 1008 close on lease expiry, got ${JSON.stringify(closed1)}`);

  // 2. Peer 2 receives `peer_left` for expired endpoint 1.
  const left = await ws2.nextJsonKind('peer_left', 5000);
  assert.equal(left.endpoint_id, att1.endpoint_id);

  // 3. Both expired endpoint row AND expired ticket row were purged (proving alarm tx committed!).
  const epRows = [...(await relaySql.exec('SELECT endpoint_id FROM overlay_endpoints WHERE endpoint_id = ?', att1.endpoint_id))];
  assert.equal(epRows.length, 0, 'expired endpoint row must be removed by alarm()');
  const tkRows = [...(await relaySql.exec("SELECT ticket_hash FROM overlay_tickets WHERE ticket_hash = 'expired-ticket-ov07e'"))];
  assert.equal(tkRows.length, 0, 'expired ticket row must be purged by alarm()');

  // 4. Live peer 2 remains healthy and responsive!
  ws2.sendJson({ kind: 'stats' });
  const stats2 = await ws2.nextJsonKind('stats_reply', 5000);
  assert.equal(stats2.kind, 'stats_reply');

  ws2.close();
  await good(post('/api/overlay/detach', { endpoint_id: att2.endpoint_id, lease_id: att2.lease_id, network: 'default' }, hdr2));
});
