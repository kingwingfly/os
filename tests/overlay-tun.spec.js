// Phase 10b (#87) OV-08 & OV-09 Chromium Playwright E2E:
// - OV-08a: Fresh Chromium boot issues ZERO `/api/overlay/*`, `/api/cluster/*`, or
//           `/api/service-auth` requests; unprivileged `tunctl` fails `EACCES`; root `tunctl`
//           without explicit `RemoteScope.overlay` fails closed with zero overlay requests.
// - OV-08b: Authorized browser WASI guest (`/usr/bin/tunctl`) exchanges real L3 IPv4 ICMP Echo
//           and UDP packets with a live external peer through Worker `OverlayRelay`, drops
//           spoofed source-IP packets, denies cross-tenant packets against a live Tenant B peer,
//           and cleanly releases its IPAM lease on close.
// - OV-09:  Browser intra-tenant WebRTC unordered unreliable DataChannel (`label: 'os-overlay-l3'`,
//           `ordered: false`, `maxRetransmits: 0`) signaling & fallback to `OverlayRelay` WS;
//           cross-tenant signaling rejected (`EACCES`).
import { test, expect } from './test.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { execCmd } from './ui.js';

const adminPassword = process.env.OS_TEST_ADMIN_PASSWORD || '';
const OVERLAY_FRAME_L3_PACKET = 0x01;

const OVERLAY_SCOPE = {
  overlay: {
    networks: ['default'],
    max_interfaces: 4,
    max_mtu: 1420,
    max_bytes_per_sec: 10 * 1024 * 1024,
    cni_ipam: false,
    allowed_peer_cidrs: [],
  },
};

function internetChecksum(buf) {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) {
    sum += (buf[i] << 8) | buf[i + 1];
  }
  if (buf.length & 1) sum += buf[buf.length - 1] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return (~sum) & 0xffff;
}

function bytesToIp(buf, off) {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

function flipEchoReply(pkt) {
  const out = Buffer.from(pkt);
  if (out.length < 28 || (out[0] >> 4) !== 4) return null;
  const ihl = (out[0] & 0x0f) * 4;
  const proto = out[9];
  // Swap IPv4 src/dst (1's-complement header checksum stays invariant!).
  const src = Buffer.from(out.subarray(12, 16));
  const dst = Buffer.from(out.subarray(16, 20));
  dst.copy(out, 12);
  src.copy(out, 16);
  if (proto === 1 && out[ihl] === 8) {
    // ICMP Echo Request -> Echo Reply
    out[ihl] = 0;
    out.writeUInt16BE(0, ihl + 2);
    out.writeUInt16BE(internetChecksum(out.subarray(ihl)), ihl + 2);
    return out;
  }
  if (proto === 17 && out.length >= ihl + 8) {
    // UDP: swap src/dst ports, zero optional IPv4 UDP checksum
    const sp = out.readUInt16BE(ihl);
    const dp = out.readUInt16BE(ihl + 2);
    out.writeUInt16BE(dp, ihl);
    out.writeUInt16BE(sp, ihl + 2);
    out.writeUInt16BE(0, ihl + 6);
    return out;
  }
  return null;
}

async function loginAndMintOverlay(origin, { username, password, register = false }) {
  const cfIp = `ov-pw-${randomUUID()}`;
  if (register) {
    const reg = await fetch(`${origin}/api/cloud-auth/register`, {
      method: 'POST',
      headers: { Origin: origin, 'CF-Connecting-IP': cfIp, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, short_password: true, create_home: false }),
    });
    const regText = await reg.text();
    expect(reg.ok, `register ${username} failed: ${regText}`).toBe(true);
  }
  const loginResp = await fetch(`${origin}/api/cloud-auth/login`, {
    method: 'POST',
    headers: { Origin: origin, 'CF-Connecting-IP': cfIp, 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const loginText = await loginResp.text();
  expect(loginResp.ok, `login ${username} failed: ${loginText}`).toBe(true);
  const setCookies = typeof loginResp.headers.getSetCookie === 'function'
    ? loginResp.headers.getSetCookie()
    : [loginResp.headers.get('set-cookie') || ''];
  const cookie = setCookies
    .map(v => v.split(';')[0])
    .find(c => c.startsWith('os_session='));
  expect(cookie, `${username} login must issue os_session cookie`).toBeTruthy();

  const inst = `inst-ov-pw-${randomUUID()}`;
  const proof = randomBytes(32).toString('hex');
  const svcAuth = async body => {
    const r = await fetch(`${origin}/api/service-auth`, {
      method: 'POST',
      headers: { Origin: origin, Cookie: cookie, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const text = await r.text();
    expect(r.status, text).toBe(200);
    return JSON.parse(text);
  };
  await svcAuth({ attach_instance: { instance: { instance: inst, host: 'ov-pw-peer' }, host_proof: proof } });
  const { cred } = await svcAuth({
    mint_service_cred: { instance_id: inst, host_proof: proof, scope: OVERLAY_SCOPE },
  });
  return {
    headers: {
      Origin: origin,
      Cookie: cookie,
      'X-OS-Instance': inst,
      'X-Process-Token': cred.token,
    },
  };
}

async function startExternalOverlayPeer(origin, headers, { echo = true, hostKind = 'native' } = {}) {
  const attResp = await fetch(`${origin}/api/overlay/attach`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify({ network: 'default', host_kind: hostKind }),
  });
  const attText = await attResp.text();
  expect(attResp.status, attText).toBe(200);
  const att = JSON.parse(attText);

  const wsUrl = new URL(att.ws_url, origin);
  wsUrl.protocol = wsUrl.protocol === 'https:' ? 'wss:' : 'ws:';

  // Use Node 22+ built-in WebSocket with Cookie + Origin headers (undici dispatcher/headers).
  const receivedL3 = [];
  const receivedSignals = [];
  const receivedErrors = [];
  const ws = new WebSocket(wsUrl.href, {
    headers: {
      Origin: origin,
      Cookie: headers.Cookie,
      'X-OS-Instance': headers['X-OS-Instance'],
      'X-Process-Token': headers['X-Process-Token'],
    },
  });
  ws.binaryType = 'arraybuffer';

  let resolveWelcome;
  const welcomePromise = new Promise((resolve, reject) => {
    resolveWelcome = resolve;
    ws.addEventListener('open', () => {
      ws.send(JSON.stringify({ kind: 'hello', versions: [1] }));
    });
    ws.addEventListener('error', e => reject(new Error(`peer WS error: ${e.message || e}`)));
  });

  ws.addEventListener('message', ev => {
    if (typeof ev.data === 'string') {
      const msg = JSON.parse(ev.data);
      if (msg.kind === 'welcome') resolveWelcome(msg);
      else if (msg.kind === 'signal') receivedSignals.push(msg);
      else if (msg.kind === 'error') receivedErrors.push(msg);
    } else {
      const buf = Buffer.from(ev.data);
      if (buf.length > 1 && buf[0] === OVERLAY_FRAME_L3_PACKET) {
        const pkt = buf.subarray(1);
        receivedL3.push({ src: bytesToIp(pkt, 12), dst: bytesToIp(pkt, 16), bytes: Buffer.from(pkt) });
        if (echo) {
          const reply = flipEchoReply(pkt);
          if (reply) {
            const frame = new Uint8Array(1 + reply.length);
            frame[0] = OVERLAY_FRAME_L3_PACKET;
            frame.set(reply, 1);
            ws.send(frame);
          }
        }
      }
    }
  });

  await welcomePromise;

  return {
    att,
    receivedL3,
    receivedSignals,
    receivedErrors,
    sendJson(obj) {
      ws.send(JSON.stringify(obj));
    },
    async close() {
      try { ws.close(1000, 'done'); } catch {}
      await fetch(`${origin}/api/overlay/detach`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpoint_id: att.endpoint_id, lease_id: att.lease_id, network: 'default' }),
      }).catch(() => {});
    },
  };
}

test('OV-08a fresh Chromium boot makes zero overlay/cluster/auth network calls and enforces local + default-deny TUN guards', async ({ page }) => {
  const bootCalls = [];
  const onReq = req => {
    const p = new URL(req.url()).pathname;
    if (p.startsWith('/api/overlay/') || p.startsWith('/api/cluster/') || p === '/api/service-auth') {
      bootCalls.push(`${req.method()} ${p}`);
    }
  };
  page.on('request', onReq);

  await page.goto('/');
  await page.waitForFunction(() => !!window.os?.exec && !!window.os?.overlayDebugState, null, { timeout: 30_000 });
  await page.waitForTimeout(500);

  // Hard invariant: ZERO /api/overlay/*, /api/cluster/*, or /api/service-auth requests on fresh boot!
  expect(bootCalls).toEqual([]);

  // Unprivileged user (uid 1000) cannot open `/dev/net/tun` (`0o600` -> EACCES).
  const unpriv = await execCmd(page, ['/usr/bin/tunctl', 'info'], { sudo: false });
  expect(unpriv.status).not.toBe(0);
  expect(unpriv.stderr).toMatch(/EACCES|Permission denied/i);
  expect(bootCalls).toEqual([]);

  // Root (`sudo: true`) without Cloud Sign-In / `RemoteScope.overlay` fails closed with ZERO `/api/overlay/*` calls!
  const noScope = await execCmd(page, ['/usr/bin/tunctl', 'info'], { sudo: true });
  expect(noScope.status).not.toBe(0);
  expect(noScope.stderr).toMatch(/EACCES|ENOTCONN|denied/i);
  expect(bootCalls.filter(c => c.includes('/api/overlay/'))).toEqual([]);

  page.off('request', onReq);
});

test('OV-08b & OV-09 browser /dev/net/tun L3 roundtrip, anti-spoofing, cross-tenant denial, WebRTC unordered DataChannel & lease release', async ({ page, baseURL }) => {
  test.skip(!adminPassword, 'OS_TEST_ADMIN_PASSWORD required for live OverlayRelay E2E');
  const origin = new URL(baseURL).origin;

  await page.goto('/');
  await page.waitForFunction(() => !!window.os?.cloudSignIn && !!window.os?.overlayDebugState, null, { timeout: 30_000 });
  // Ensure mutating test hooks are NOT exposed on production `window.os`.
  const noMutatingHooks = await page.evaluate(
    () => typeof window.os.overlayWebRtcTest === 'undefined' && typeof window.os.overlaySendSignal === 'undefined',
  );
  expect(noMutatingHooks).toBe(true);

  // 1. Authenticate browser session with explicit `RemoteScope.overlay` as cloud root (Tenant u0).
  const signInStatus = await page.evaluate(
    async ({ password, scope }) => window.os.cloudSignIn('root', password, scope),
    { password: adminPassword, scope: OVERLAY_SCOPE },
  );
  expect(signInStatus?.signed_in).toBe(true);

  // 2. Attach live external Peer A (same tenant u0, echoing L3 ICMP & UDP packets)
  //    and live external Peer B (distinct Tenant B user, asserting ZERO leaked packets/signals).
  const peerAAuth = await loginAndMintOverlay(origin, { username: 'root', password: adminPassword });
  const peerA = await startExternalOverlayPeer(origin, peerAAuth.headers, { echo: true, hostKind: 'native' });

  const tenantBUser = `ov08b_${randomBytes(4).toString('hex')}`;
  const tenantBPass = `Pass-${randomBytes(8).toString('hex')}`;
  const peerBAuth = await loginAndMintOverlay(origin, {
    username: tenantBUser,
    password: tenantBPass,
    register: true,
  });
  const peerB = await startExternalOverlayPeer(origin, peerBAuth.headers, { echo: false, hostKind: 'native' });

  try {
    expect(peerA.att.tenant).toBe('u0');
    expect(peerB.att.tenant).not.toBe(peerA.att.tenant);
    expect(peerB.att.cidr).not.toBe(peerA.att.cidr);

    // 3. Browser -> Peer A real L3 ICMP Echo Request/Reply roundtrip via `/dev/net/tun` + `OverlayRelay`!
    const icmpProbe = await execCmd(
      page,
      ['/usr/bin/tunctl', 'probe', '--dst', peerA.att.ip, '--proto', 'icmp', '--payload', 'ov08-icmp-ok', '--json'],
      { sudo: true },
    );
    expect(icmpProbe.status, icmpProbe.stderr).toBe(0);
    const icmpRes = JSON.parse(icmpProbe.stdout.trim());
    expect(icmpRes.reply_src).toBe(peerA.att.ip);
    expect(icmpRes.reply_payload).toBe('ov08-icmp-ok');

    // 4. Browser -> Peer A real L3 UDP-in-IPv4 roundtrip!
    const udpProbe = await execCmd(
      page,
      ['/usr/bin/tunctl', 'probe', '--dst', peerA.att.ip, '--proto', 'udp', '--port', '5555', '--payload', 'ov08-udp-ok', '--json'],
      { sudo: true },
    );
    expect(udpProbe.status, udpProbe.stderr).toBe(0);
    const udpRes = JSON.parse(udpProbe.stdout.trim());
    expect(udpRes.reply_src).toBe(peerA.att.ip);
    expect(udpRes.reply_payload).toBe('ov08-udp-ok');

    // 5. Spoofed source-IP drop: browser sends packet forging `peerA.att.gateway` -> dropped locally & never arrives at Peer A!
    const peerACountBeforeSpoof = peerA.receivedL3.length;
    const spoofRes = await execCmd(
      page,
      ['/usr/bin/tunctl', 'spoof', '--src', peerA.att.gateway, '--dst', peerA.att.ip, '--json'],
      { sudo: true },
    );
    expect(spoofRes.status, spoofRes.stderr).toBe(0);
    const spoofJson = JSON.parse(spoofRes.stdout.trim());
    expect(spoofJson.stats.tx_dropped_spoofed_src).toBeGreaterThanOrEqual(1);
    await page.waitForTimeout(200);
    expect(peerA.receivedL3.length).toBe(peerACountBeforeSpoof);

    // 6. Cross-tenant packet denial: browser (Tenant u0) sends packets addressed to live Tenant B peer -> dropped & Peer B gets ZERO!
    const crossRes = await execCmd(
      page,
      ['/usr/bin/tunctl', 'send', '--dst', peerB.att.ip, '--count', '2', '--json'],
      { sudo: true },
    );
    expect(crossRes.status, crossRes.stderr).toBe(0);
    const crossJson = JSON.parse(crossRes.stdout.trim());
    expect(crossJson.stats.tx_dropped_cross_tenant).toBeGreaterThanOrEqual(2);
    await page.waitForTimeout(250);
    expect(peerB.receivedL3.length).toBe(0);

    // 7. Verify clean IPAM lease release after `tunctl` closed `/dev/net/tun`!
    const afterCloseDbg = await page.evaluate(() => window.os.overlayDebugState());
    expect(afterCloseDbg.activeCount).toBe(0);

    // 8. OV-09: Hold a TUN open in the browser; `Welcome` organically discovers intra-tenant Peer A
    //    and initiates the unordered unreliable WebRTC DataChannel (`label === 'os-overlay-l3'`,
    //    `ordered === false`, `maxRetransmits === 0`), forwarding its SDP offer through `OverlayRelay`
    //    while keeping `fallbackToWs === true`. No mutating `window.os` test hooks required!
    const holdPromise = execCmd(page, ['/usr/bin/tunctl', 'hold', '--duration-ms', '4000'], { sudo: true });

    let activeEp = null;
    await expect.poll(async () => {
      const dbg = await page.evaluate(() => window.os.overlayDebugState());
      activeEp = dbg?.endpoints?.[0] ?? null;
      return activeEp?.dcConfig?.label ?? null;
    }, { timeout: 10_000 }).toBe('os-overlay-l3');

    expect(activeEp.dcConfig?.ordered).toBe(false);
    expect(activeEp.dcConfig?.maxRetransmits).toBe(0);
    expect(activeEp.fallbackToWs).toBe(true);
    expect(activeEp.webrtcAttempts).toBeGreaterThanOrEqual(1);

    // Intra-tenant Peer A organically receives the forwarded WebRTC SDP offer signal from `activeEp`!
    await expect.poll(
      () => peerA.receivedSignals.some(s => s.from_endpoint_id === activeEp.endpoint_id && s.payload?.sdp?.type === 'offer'),
      { timeout: 5_000 },
    ).toBe(true);

    // Cross-tenant signaling to Tenant B Peer B MUST be rejected (`EACCES`) by OverlayRelay and never delivered!
    const errorsBefore = peerA.receivedErrors.length;
    peerA.sendJson({
      kind: 'signal',
      to_endpoint_id: peerB.att.endpoint_id,
      payload: { type: 'offer', sdp: 'cross-tenant-blocked' },
    });
    await expect.poll(
      () => peerA.receivedErrors.slice(errorsBefore).some(e => e.errno === 'EACCES'),
      { timeout: 5_000 },
    ).toBe(true);
    await page.waitForTimeout(150);
    expect(peerB.receivedSignals.length).toBe(0);

    // Wait for `tunctl hold` to exit cleanly and confirm full teardown!
    const holdExit = await holdPromise;
    expect(holdExit.status, holdExit.stderr).toBe(0);
    await expect.poll(async () => (await page.evaluate(() => window.os.overlayDebugState())).activeCount, {
      timeout: 5_000,
    }).toBe(0);
  } finally {
    await peerA.close();
    await peerB.close();
    await page.evaluate(() => window.os.cloudSignOut()).catch(() => {});
  }
});
