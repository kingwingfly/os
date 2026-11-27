// Phase 10a (#86) Worker / Miniflare Outbound Stream Gateway Tests (NT-01..NT-09).
// Build crates/worker first (`crates/worker/build/{index.js,index_bg.wasm}`).
// Exercises `/api/net/ticket`, `/api/net/connect` WebSocket -> `cloudflare:sockets` against
// ephemeral local TCP fixtures permitted ONLY via the two-key `NET_TEST_LOOPBACK_ADDRS` gate.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { Miniflare } from 'miniflare';

const origin = 'http://localhost';
const workerName = 'netd-gateway-test';
const sha = bytes => createHash('sha256').update(bytes).digest();

const TAG_DATA = 0x01;
const TAG_CREDIT = 0x02;
const TAG_HALF_CLOSE = 0x03;
const TAG_CANCEL = 0x04;
const TAG_CLOSED = 0x05;

function encodeWsFrame(tag, payload = new Uint8Array(0)) {
  const out = new Uint8Array(1 + payload.length);
  out[0] = tag;
  out.set(payload, 1);
  return out;
}

function encodeCredit(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return encodeWsFrame(TAG_CREDIT, b);
}

function decodeWsFrame(data) {
  if (typeof data === 'string') {
    return { text: true, json: JSON.parse(data) };
  }
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const tag = bytes[0];
  const payload = bytes.subarray(1);
  if (tag === TAG_DATA) return { tag, data: payload };
  if (tag === TAG_CREDIT) return { tag, credit: new DataView(payload.buffer, payload.byteOffset, 4).getUint32(0, false) };
  if (tag === TAG_HALF_CLOSE) return { tag };
  if (tag === TAG_CANCEL) return { tag };
  if (tag === TAG_CLOSED) return { tag, closed: JSON.parse(Buffer.from(payload).toString('utf8')) };
  return { tag, payload };
}

function listenTcp(handler) {
  return new Promise((resolve, reject) => {
    const server = net.createServer(sock => {
      sock.on('error', () => {});
      handler(sock);
    });
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({ server, port: addr.port });
    });
  });
}

let echoSrv, bulkSrv, holdSrv, unallowedSrv;
let mf, authoritySql, root, guest;

async function post(path, body, headers = {}) {
  return mf.dispatchFetch(origin + path, {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json', ...headers },
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
  if (errno !== undefined) assert.equal(body.errno, errno, JSON.stringify(body));
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
  await auth({ attach_instance: { instance: { instance, host: 'netd-test' }, host_proof: proof } });
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
    mint,
    revoke: token => auth({
      revoke_tokens: { instance_id: instance, host_proof: proof, tokens: [token] },
    }),
  };
}

function exactScope(ports, quota = {}) {
  return {
    net: {
      rules: [
        {
          host: { exact: '127.0.0.1' },
          ports: ports.map(p => ({ start: p, end: p })),
          tls: 'plain_only',
        },
      ],
      quota: {
        max_concurrent_streams: 4,
        max_bytes_per_stream: 4 * 1024 * 1024,
        connect_timeout_ms: 5000,
        idle_timeout_ms: 15000,
        max_stream_lifetime_ms: 60000,
        ...quota,
      },
    },
  };
}

async function openNetWs(query, headers = {}) {
  const res = await mf.dispatchFetch(`${origin}/api/net/connect?${query}`, {
    headers: { Upgrade: 'websocket', Origin: origin, ...headers },
  });
  if (res.status !== 101) {
    return { status: res.status, response: res };
  }
  const ws = res.webSocket;
  assert.ok(ws, '101 response must include webSocket');
  const queue = [];
  const waiters = [];
  let closed = null;
  const closeWaiters = [];
  ws.addEventListener('message', ev => {
    const frame = decodeWsFrame(ev.data);
    if (waiters.length > 0) waiters.shift().resolve(frame);
    else queue.push(frame);
  });
  ws.addEventListener('close', ev => {
    closed = { code: ev.code, reason: ev.reason };
    while (closeWaiters.length > 0) closeWaiters.shift().resolve(closed);
    while (waiters.length > 0) waiters.shift().reject(new Error(`ws closed (${ev.code}: ${ev.reason})`));
  });
  ws.accept();
  return {
    status: 101,
    ws,
    queue,
    sendFrame: bytes => ws.send(bytes),
    nextFrame(timeoutMs = 5000) {
      if (queue.length > 0) return Promise.resolve(queue.shift());
      if (closed) return Promise.reject(new Error(`ws closed (${closed.code})`));
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          const idx = waiters.findIndex(w => w.resolve === wrapOk);
          if (idx >= 0) waiters.splice(idx, 1);
          reject(new Error(`timed out waiting for WS frame after ${timeoutMs}ms`));
        }, timeoutMs);
        const wrapOk = v => { clearTimeout(timer); resolve(v); };
        const wrapErr = e => { clearTimeout(timer); reject(e); };
        waiters.push({ resolve: wrapOk, reject: wrapErr });
      });
    },
    waitClose(timeoutMs = 5000) {
      if (closed) return Promise.resolve(closed);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('timed out waiting for WS close')), timeoutMs);
        closeWaiters.push({ resolve: v => { clearTimeout(timer); resolve(v); } });
      });
    },
    close() {
      try { ws.close(1000, 'done'); } catch {}
    },
  };
}

let holdServerClosedCount = 0;

before(async () => {
  // 1. Echo server that honors half-close (drains client bytes, echoes all, closes on client EOF).
  echoSrv = await listenTcp(sock => {
    sock.on('data', chunk => sock.write(chunk));
    sock.on('end', () => sock.end());
  });
  // 2. Bulk server that sends 512 KiB of deterministic bytes then closes.
  const bulkPayload = Buffer.alloc(512 * 1024);
  for (let i = 0; i < bulkPayload.length; i++) bulkPayload[i] = (i * 31 + 17) & 0xff;
  bulkSrv = await listenTcp(sock => {
    sock.end(bulkPayload);
  });
  bulkSrv.expectedSha = createHash('sha256').update(bulkPayload).digest('hex');
  // 3. Hold server that keeps socket open until peer cancels/closes.
  holdSrv = await listenTcp(sock => {
    sock.on('close', () => { holdServerClosedCount += 1; });
  });
  // 4. Unlisted local TCP listener (NOT in NET_TEST_LOOPBACK_ADDRS!).
  unallowedSrv = await listenTcp(sock => sock.end('forbidden'));

  const allowCsv = `127.0.0.1:${echoSrv.port},127.0.0.1:${bulkSrv.port},127.0.0.1:${holdSrv.port}`;
  const classes = ['OsAuthority', 'Machine'];
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
                import { OsAuthority as Authority, Machine as Service } from './index.js';
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
                }`,
            },
            'index.js': { type: 'esm', contents: readFileSync('crates/worker/build/index.js', 'utf8') },
            'index_bg.wasm': { type: 'wasm', contents: readFileSync('crates/worker/build/index_bg.wasm') },
          },
        },
        exports: Object.fromEntries(classes.map(n => [n, { type: 'durable-object', storage: 'sqlite' }])),
        env: {
          ...Object.fromEntries(['AUTHORITY', 'MACHINE'].map(
            (binding, i) => [binding, { type: 'durable-object', worker: workerName, exportName: classes[i] }],
          )),
          FILES: { type: 'r2', name: 'files-netd-test' },
          ADMIN_PASSWORD: { type: 'text', value: randomUUID() },
          SESSION_SECRET: { type: 'text', value: randomUUID() },
          NET_TEST_LOOPBACK_ADDRS: { type: 'text', value: allowCsv },
          ASSETS: {
            type: 'fetcher',
            handler: () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }),
          },
        },
      },
    }],
  });
  await good(post('/api/sys', { calls: ['getcreds'] }));
  authoritySql = await mf.unsafeGetDurableObjectStorage(workerName, 'OsAuthority', { name: 'filesystem' });
  root = await login(0);
  guest = await login(null);
});

after(async () => {
  if (mf) await mf.dispose();
  for (const s of [echoSrv, bulkSrv, holdSrv, unallowedSrv]) {
    if (s?.server) await new Promise(r => s.server.close(() => r()));
  }
});

test('NT-01/NT-02 auth, default-deny, CSRF, two-key loopback, and SSRF refusal', async () => {
  // Default-deny: credential without `net` scope is refused.
  const noNetHdrs = await root.mint({ cloud_fs: true });
  await denied(post('/api/net/ticket', { host: '127.0.0.1', port: echoSrv.port }, noNetHdrs), 'EACCES', 403);

  // Guest credentials are always refused.
  const guestHdrs = await guest.mint(exactScope([echoSrv.port]));
  await denied(post('/api/net/ticket', { host: '127.0.0.1', port: echoSrv.port }, guestHdrs), 'EACCES', 403);

  // Cross-origin CSRF refused.
  const okHdrs = await root.mint(exactScope([echoSrv.port, unallowedSrv.port]));
  await denied(
    post('/api/net/ticket', { host: '127.0.0.1', port: echoSrv.port }, { ...okHdrs, Origin: 'https://evil.example' }),
    'EACCES',
    403,
  );

  // Two-key loopback: `AnyPublic` NEVER matches allowlisted loopback!
  const anyPubHdrs = await root.mint({
    net: { rules: [{ host: 'any_public', ports: [{ start: 1, end: 65535 }], tls: 'any' }] },
  });
  await denied(post('/api/net/ticket', { host: '127.0.0.1', port: echoSrv.port }, anyPubHdrs), 'EACCES', 403);

  // Unlisted loopback ports (e.g. 8787 and unallowedSrv) are refused even with Exact rule!
  await denied(post('/api/net/ticket', { host: '127.0.0.1', port: unallowedSrv.port }, okHdrs), 'EACCES', 403);
  await denied(post('/api/net/ticket', { host: '127.0.0.1', port: 8787 }, anyPubHdrs), 'EACCES', 403);

  // SSRF / private / IMDS / obfuscated targets are refused.
  for (const [host, port, expectedErrno] of [
    ['169.254.169.254', 80, 'EACCES'],
    ['10.0.0.1', 80, 'EACCES'],
    ['192.168.1.1', 80, 'EACCES'],
    ['::ffff:127.0.0.1', echoSrv.port, 'EACCES'],
    ['localhost', echoSrv.port, 'EACCES'],
    ['metadata.google.internal', 80, 'EACCES'],
    ['2130706433', 80, 'EINVAL'],
    ['0177.0.0.1', 80, 'EINVAL'],
    ['127.1', 80, 'EINVAL'],
  ]) {
    await denied(post('/api/net/ticket', { host, port }, anyPubHdrs), expectedErrno);
  }
});

test('NT-03/NT-08 permitted echo, SHUT_WR half-close, and single-use ticket replay denial', async () => {
  const hdrs = await root.mint(exactScope([echoSrv.port]));
  const { ticket, stream_id } = await good(post('/api/net/ticket', {
    host: '127.0.0.1',
    port: echoSrv.port,
    tls: 'off',
  }, hdrs));
  assert.ok(ticket && stream_id);

  const conn = await openNetWs(`ticket=${encodeURIComponent(ticket)}`, { Cookie: root.cookie });
  assert.equal(conn.status, 101);
  const opened = await conn.nextFrame();
  assert.equal(opened.text, true);
  assert.equal(opened.json.kind, 'opened');
  assert.equal(opened.json.stream_id, stream_id);

  // Replaying the exact same ticket MUST fail 403 EACCES!
  const replay = await openNetWs(`ticket=${encodeURIComponent(ticket)}`, { Cookie: root.cookie });
  assert.equal(replay.status, 403);
  const replayBody = await replay.response.json();
  assert.equal(replayBody.errno, 'EACCES');

  // Send two chunks + HALF_CLOSE, receive echoed payload + remote HALF_CLOSE + clean CLOSED.
  const msg = Buffer.from('hello-phase10a-cloudflare-sockets!');
  conn.sendFrame(encodeWsFrame(TAG_DATA, msg.subarray(0, 12)));
  conn.sendFrame(encodeWsFrame(TAG_DATA, msg.subarray(12)));
  conn.sendFrame(encodeWsFrame(TAG_HALF_CLOSE));

  const chunks = [];
  let sawHalfClose = false;
  let sawClosed = false;
  while (!sawClosed) {
    const f = await conn.nextFrame();
    if (f.tag === TAG_DATA) {
      chunks.push(Buffer.from(f.data));
      conn.sendFrame(encodeCredit(f.data.length));
    } else if (f.tag === TAG_HALF_CLOSE) {
      sawHalfClose = true;
    } else if (f.tag === TAG_CLOSED) {
      sawClosed = true;
      assert.equal(f.closed.errno ?? null, null, JSON.stringify(f.closed));
    }
  }
  assert.equal(Buffer.concat(chunks).toString('utf8'), msg.toString('utf8'));
  assert.equal(sawHalfClose, true);
  await conn.waitClose();
});

test('NT-04 credit-window backpressure stalls 512 KiB stream until CREDIT refills', async () => {
  const hdrs = await root.mint(exactScope([bulkSrv.port]));
  const { ticket } = await good(post('/api/net/ticket', {
    host: '127.0.0.1',
    port: bulkSrv.port,
    tls: 'off',
  }, hdrs));
  const conn = await openNetWs(`ticket=${encodeURIComponent(ticket)}`, { Cookie: root.cookie });
  assert.equal(conn.status, 101);
  const opened = await conn.nextFrame();
  assert.equal(opened.json.kind, 'opened');
  const initialWindow = opened.json.initial_window;
  assert.equal(initialWindow, 65536);

  // Drain ONLY the initial window WITHOUT sending CREDIT yet.
  const chunks = [];
  let gotBytes = 0;
  while (gotBytes < initialWindow) {
    const f = await conn.nextFrame();
    if (f.tag === TAG_DATA) {
      chunks.push(Buffer.from(f.data));
      gotBytes += f.data.length;
    }
  }
  assert.equal(gotBytes, initialWindow, 'gateway must stop forwarding once 64 KiB window is exhausted');

  // Verify gateway remains stalled for 150ms while client holds 0 credit.
  await new Promise(r => setTimeout(r, 150));
  assert.equal(conn.queue.filter(f => f.tag === TAG_DATA).length, 0, 'no DATA may arrive with 0 RX credit');

  // Now trickle credit until all 512 KiB arrive cleanly!
  conn.sendFrame(encodeCredit(gotBytes));
  let sawHalfClose = false;
  while (!sawHalfClose) {
    const f = await conn.nextFrame();
    if (f.tag === TAG_DATA) {
      chunks.push(Buffer.from(f.data));
      gotBytes += f.data.length;
      conn.sendFrame(encodeCredit(f.data.length));
    } else if (f.tag === TAG_HALF_CLOSE || f.tag === TAG_CLOSED) {
      sawHalfClose = true;
    }
  }
  const full = Buffer.concat(chunks);
  assert.equal(full.length, 512 * 1024);
  assert.equal(createHash('sha256').update(full).digest('hex'), bulkSrv.expectedSha);
  conn.sendFrame(encodeWsFrame(TAG_HALF_CLOSE));
  await conn.waitClose();
});

test('NT-06/NT-08 cancellation releases quota slot, concurrency & byte limits return EDQUOT', async () => {
  // Concurrency cap = 1
  const hdrs = await root.mint(exactScope([holdSrv.port, bulkSrv.port], {
    max_concurrent_streams: 1,
    max_bytes_per_stream: 32 * 1024,
  }));
  const t1 = await good(post('/api/net/ticket', { host: '127.0.0.1', port: holdSrv.port }, hdrs));
  // 2nd concurrent reservation MUST fail EDQUOT (507)!
  await denied(post('/api/net/ticket', { host: '127.0.0.1', port: holdSrv.port }, hdrs), 'EDQUOT', 507);

  const beforeClosed = holdServerClosedCount;
  const c1 = await openNetWs(`ticket=${encodeURIComponent(t1.ticket)}`, { Cookie: root.cookie });
  assert.equal((await c1.nextFrame()).json.kind, 'opened');

  // Cancel stream 1 -> upstream socket closes & quota slot frees!
  c1.sendFrame(encodeWsFrame(TAG_CANCEL));
  await c1.waitClose();
  await new Promise(r => setTimeout(r, 150));
  assert.ok(holdServerClosedCount > beforeClosed, 'upstream TCP socket must close on CANCEL');

  // Now a new stream to bulkSrv (512 KiB > 32 KiB max_bytes_per_stream) MUST trip EDQUOT!
  const t2 = await good(post('/api/net/ticket', { host: '127.0.0.1', port: bulkSrv.port }, hdrs));
  const c2 = await openNetWs(`ticket=${encodeURIComponent(t2.ticket)}`, { Cookie: root.cookie });
  assert.equal((await c2.nextFrame()).json.kind, 'opened');
  let sawEdquot = false;
  for (;;) {
    const f = await c2.nextFrame();
    if (f.tag === TAG_DATA) {
      c2.sendFrame(encodeCredit(f.data.length));
    } else if (f.tag === TAG_CLOSED) {
      assert.equal(f.closed.errno, 'EDQUOT', JSON.stringify(f.closed));
      sawEdquot = true;
      break;
    }
  }
  assert.equal(sawEdquot, true);
  await c2.waitClose();
});

test('NT-02/NT-08 StartTls rejected EOPNOTSUPP, session ticket cookie-bound, and live revocation kills active stream', async () => {
  // 1. TlsMode::StartTls is explicitly unsupported (501 EOPNOTSUPP).
  const tlsHdrs = await root.mint({
    net: {
      rules: [{
        host: { exact: '127.0.0.1' },
        ports: [{ start: holdSrv.port, end: holdSrv.port }],
        tls: 'any',
      }],
    },
  });
  await denied(post('/api/net/ticket', {
    host: '127.0.0.1',
    port: holdSrv.port,
    tls: 'start_tls',
  }, tlsHdrs), 'EOPNOTSUPP', 501);

  // 2. session.* ticket without owning os_session cookie (or with wrong session cookie) is rejected 403 EACCES!
  const hdrs = await root.mint(exactScope([holdSrv.port]));
  const { ticket } = await good(post('/api/net/ticket', {
    host: '127.0.0.1',
    port: holdSrv.port,
    tls: 'off',
  }, hdrs));
  const noCookie = await openNetWs(`ticket=${encodeURIComponent(ticket)}`, {});
  assert.equal(noCookie.status, 403);
  assert.equal((await noCookie.response.json()).errno, 'EACCES');

  const wrongCookie = await openNetWs(`ticket=${encodeURIComponent(ticket)}`, {
    Cookie: `os_session=${randomBytes(32).toString('hex')}`,
  });
  assert.equal(wrongCookie.status, 403);
  assert.equal((await wrongCookie.response.json()).errno, 'EACCES');

  // 3. Upgrade with owning session cookie succeeds, then live root.revoke(token) tears down active stream!
  const beforeClosed = holdServerClosedCount;
  const conn = await openNetWs(`ticket=${encodeURIComponent(ticket)}`, { Cookie: root.cookie });
  assert.equal(conn.status, 101);
  assert.equal((await conn.nextFrame()).json.kind, 'opened');

  await root.revoke(hdrs['X-Process-Token']);

  let sawRevoked = false;
  for (;;) {
    const f = await conn.nextFrame(6000);
    if (f.tag === TAG_CLOSED) {
      assert.equal(f.closed.errno, 'EACCES', JSON.stringify(f.closed));
      sawRevoked = true;
      break;
    }
  }
  assert.equal(sawRevoked, true);
  await conn.waitClose();
  await new Promise(r => setTimeout(r, 150));
  assert.ok(holdServerClosedCount > beforeClosed, 'upstream TCP socket must close on live revocation');
});
