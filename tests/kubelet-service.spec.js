// Phase 9.1b (#84) KB-08 Chromium Playwright E2E:
// 1. Default boot makes ZERO outbound `/api/cluster/*` or `/api/service-auth` requests and
//    keeps `kubelet.service` disabled & inactive.
// 2. Enabling (`service enable kubelet`), enrolling with a single-use bootstrap token, and
//    starting (`service start kubelet`) activates `/usr/bin/kubelet`, binds `/run/kubelet/host.sock`,
//    registers the browser node in `ClusterState`, and executes a real OCI WASI task!
// 3. Reloading the tab preserves `kubelet.service` enabled state via `/etc/services/.enabled.json`.
import { test, expect } from './test.js';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { api } from './sys.js';
import { execCmd, pageMkdirp, pagePut, switchLocalUser } from './ui.js';

const adminPassword = process.env.OS_TEST_ADMIN_PASSWORD || '';

async function runService(page, args, { sudo = false } = {}) {
  const res = await execCmd(page, ['/usr/bin/service', ...args], { sudo });
  return `${res.stdout || ''}\n${res.stderr || ''}`;
}

// Minimal valid WASI module that writes "browser-kb08-ok" to /output/.os-task-summary.txt and exits 0.
function minimalSummaryWasm() {
  const pushSec = (out, id, body) => {
    out.push(id);
    let n = body.length;
    do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n);
    out.push(...body);
  };
  const encStr = (s, out) => {
    const b = Buffer.from(s, 'utf8');
    out.push(b.length, ...b);
  };
  const sleb = (v, out) => {
    let val = v;
    for (;;) {
      let byte = val & 0x7f;
      val >>= 7;
      const done = (val === 0 && (byte & 0x40) === 0) || (val === -1 && (byte & 0x40) !== 0);
      if (!done) byte |= 0x80;
      out.push(byte);
      if (done) break;
    }
  };
  const uleb = (v, out) => {
    let n = v >>> 0;
    do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; out.push(b); } while (n);
  };
  const out = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  // Types: 0: proc_exit(i32)->(), 1: path_open(5xi32,2xi64,2xi32)->i32, 2: fd_write(4xi32)->i32, 3: fd_close(i32)->i32, 4: _start()->()
  pushSec(out, 1, [
    5,
    0x60, 1, 0x7f, 0,
    0x60, 9, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 1, 0x7f,
    0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
    0x60, 1, 0x7f, 1, 0x7f,
    0x60, 0, 0,
  ]);
  const imp = [4];
  for (const [name, ty] of [['proc_exit', 0], ['path_open', 1], ['fd_write', 2], ['fd_close', 3]]) {
    encStr('wasi_snapshot_preview1', imp);
    encStr(name, imp);
    imp.push(0x00, ty);
  }
  pushSec(out, 2, imp);
  pushSec(out, 3, [1, 4]); // func 4 -> type 4
  pushSec(out, 5, [1, 0x00, 1]); // 1 page memory
  const exp = [2];
  encStr('memory', exp); exp.push(0x02, 0);
  encStr('_start', exp); exp.push(0x00, 4);
  pushSec(out, 7, exp);

  const pathStr = 'output/.os-task-summary.txt';
  const msgStr = 'browser-kb08-ok';
  const body = [1, 1, 0x7f]; // 1 i32 local (fd)
  const i32c = v => { body.push(0x41); sleb(v, body); };
  const i64c = v => { body.push(0x42); sleb(v, body); };
  // path_open(3, 1, 0x100, pathStr.length, 9 (CREAT|TRUNC), 64 (WRITE), 0, 0, 0x400)
  i32c(3); i32c(1); i32c(0x100); i32c(pathStr.length); i32c(9); i64c(64); i64c(0); i32c(0); i32c(0x400);
  body.push(0x10, 0x01, 0x1a); // call path_open; drop
  // local.0 = i32.load(0x400)
  i32c(0x400); body.push(0x28, 0x02, 0x00, 0x21, 0x00);
  // iovec at 0x410 = { 0x180, msgStr.length }
  i32c(0x410); i32c(0x180); body.push(0x36, 0x02, 0x00);
  i32c(0x414); i32c(msgStr.length); body.push(0x36, 0x02, 0x00);
  // fd_write(local.0, 0x410, 1, 0x420)
  body.push(0x20, 0x00); i32c(0x410); i32c(1); i32c(0x420);
  body.push(0x10, 0x02, 0x1a);
  // fd_close(local.0)
  body.push(0x20, 0x00, 0x10, 0x03, 0x1a);
  // proc_exit(0)
  i32c(0); body.push(0x10, 0x00, 0x0b);

  const code = [1];
  uleb(body.length, code);
  code.push(...body);
  pushSec(out, 10, code);

  const data = [2];
  for (const [off, s] of [[0x100, pathStr], [0x180, msgStr]]) {
    data.push(0x00, 0x41);
    sleb(off, data);
    data.push(0x0b);
    const b = Buffer.from(s, 'utf8');
    uleb(b.length, data);
    data.push(...b);
  }
  pushSec(out, 11, data);
  return Buffer.from(out);
}

function buildSingleFileTar(relPath, content, mode = 0o755) {
  const hdr = Buffer.alloc(512, 0);
  hdr.write(relPath, 0, Math.min(relPath.length, 100), 'utf8');
  hdr.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
  hdr.write('0000000\0', 108, 8, 'ascii');
  hdr.write('0000000\0', 116, 8, 'ascii');
  hdr.write(content.length.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
  hdr.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136, 12, 'ascii');
  hdr.fill(0x20, 148, 156);
  hdr[156] = 0x30;
  hdr.write('ustar\0', 257, 6, 'ascii');
  hdr.write('00', 263, 2, 'ascii');
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += hdr[i];
  hdr.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  const rem = content.length % 512;
  const pad = rem === 0 ? Buffer.alloc(0) : Buffer.alloc(512 - rem, 0);
  return Buffer.concat([hdr, content, pad, Buffer.alloc(1024, 0)]);
}

test('KB-08 kubelet.service is opt-in (zero boot network), executes real task when enabled, and persists enablement across reload', async ({ page, request, baseURL }) => {
  test.skip(!adminPassword, 'OS_TEST_ADMIN_PASSWORD required for isolated KB-08 E2E');
  const origin = new URL(baseURL).origin;

  // 1. Default boot: record EVERY request to /api/cluster/* or /api/service-auth.
  const bootNetwork = [];
  const onReq = req => {
    const p = new URL(req.url()).pathname;
    if (p.startsWith('/api/cluster/') || p === '/api/service-auth') {
      bootNetwork.push(`${req.method()} ${p}`);
    }
  };
  page.on('request', onReq);

  await page.goto('/');
  await page.waitForFunction(() => !!window.os?.exec, null, { timeout: 30_000 });
  let initStatus = '';
  await expect.poll(async () => {
    initStatus = await runService(page, ['status', 'kubelet']);
    return initStatus;
  }, { timeout: 30_000 }).toMatch(/Unit:\s+kubelet\.service/);
  expect(initStatus).toMatch(/State:\s+inactive/i);
  expect(initStatus).toMatch(/Enabled:\s+no/i);
  // Hard invariant: ZERO /api/cluster/* or /api/service-auth calls on default boot!
  expect(bootNetwork).toEqual([]);
  page.off('request', onReq);

  // 2. Authenticate control-plane admin via isolated cookie-scoped fetch (separate from guest page),
  //    mint single-use bootstrap token for `node-browser-kb08`, and push a tiny WASI pod image.
  const loginResp = await api(request, 'login', {
    headers: { Origin: origin, 'CF-Connecting-IP': 'kb08-' + randomUUID() },
    data: { password: adminPassword },
  });
  expect(loginResp.ok()).toBe(true);
  const sessionCookie = loginResp
    .headersArray()
    .filter(h => h.name.toLowerCase() === 'set-cookie')
    .map(h => h.value.split(';')[0])
    .find(c => c.startsWith('os_session='));
  expect(sessionCookie, 'login must issue os_session cookie').toBeTruthy();

  const adminInst = `inst-kb08-${randomUUID()}`;
  const adminProof = randomBytes(32).toString('hex');
  const svcAuth = async body => {
    const r = await fetch(`${origin}/api/service-auth`, {
      method: 'POST',
      headers: { Origin: origin, Cookie: sessionCookie, 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const text = await r.text();
    expect(r.status, text).toBe(200);
    return JSON.parse(text);
  };
  await svcAuth({ attach_instance: { instance: { instance: adminInst, host: 'kb08-test' }, host_proof: adminProof } });

  const fullScope = {
    cluster_read: true, cluster_write: true, cluster_watch: true, cluster_lease: true,
    cluster_compact: true, registry_pull: true, registry_push: true, volumes: true, volumes_ro: false,
  };
  const { cred: adminCred } = await svcAuth({
    mint_service_cred: { instance_id: adminInst, host_proof: adminProof, scope: fullScope },
  });
  const adminHdrs = { Origin: origin, Cookie: sessionCookie, 'X-OS-Instance': adminInst, 'X-Process-Token': adminCred.token };

  const nodeId = `node-kb08-${randomBytes(4).toString('hex')}`;
  const { bootstrap_token: btIssued } = await svcAuth({
    mint_bootstrap_token: {
      instance_id: adminInst,
      host_proof: adminProof,
      node_id: nodeId,
      cluster: 'default',
      ttl_secs: 300,
      scope: fullScope,
      sudo: false,
    },
  });

  // Push minimal WASI pod OCI tar image to /v2/tasks/kb08:v1 (exchanging for OCI Bearer JWT first).
  const basicAuth = 'Basic ' + Buffer.from(`root:${adminPassword}`).toString('base64');
  const tokResp = await request.get(`${origin}/v2/token?service=os-registry&scope=${encodeURIComponent('repository:tasks/kb08:pull,push')}`, {
    headers: { Origin: origin, Authorization: basicAuth, 'CF-Connecting-IP': 'kb08-oci-' + randomUUID() },
  });
  expect(tokResp.status(), await tokResp.text()).toBe(200);
  const { token: ociBearer } = await tokResp.json();
  const ociHdrs = { Origin: origin, Authorization: `Bearer ${ociBearer}` };
  const wasm = minimalSummaryWasm();
  const tar = buildSingleFileTar('usr/bin/hello.wasm', wasm);
  const shaDig = b => 'sha256:' + createHash('sha256').update(b).digest('hex');
  const putBlob = async bytes => {
    const dig = shaDig(bytes);
    const s = await request.post(`${origin}/v2/tasks/kb08/blobs/uploads/`, { headers: ociHdrs });
    expect(s.status()).toBe(202);
    const loc = new URL(s.headers()['location'], origin);
    loc.searchParams.set('digest', dig);
    const f = await request.put(loc.href, {
      headers: { ...ociHdrs, 'Content-Type': 'application/octet-stream' },
      data: bytes,
    });
    expect(f.status()).toBe(201);
    return dig;
  };
  const layerDig = await putBlob(tar);
  const cfgBytes = Buffer.from(JSON.stringify({ architecture: 'wasm', os: 'wasip1', rootfs: { type: 'layers', diff_ids: [layerDig] } }));
  const cfgDig = await putBlob(cfgBytes);
  const manBytes = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: { mediaType: 'application/vnd.oci.image.config.v1+json', digest: cfgDig, size: cfgBytes.length },
    layers: [{ mediaType: 'application/vnd.oci.image.layer.v1.tar', digest: layerDig, size: tar.length }],
  }));
  const mPut = await request.put(`${origin}/v2/tasks/kb08/manifests/v1`, {
    headers: { ...ociHdrs, 'Content-Type': 'application/vnd.oci.image.manifest.v1+json' },
    data: manBytes,
  });
  expect(mPut.status()).toBe(201);
  const imageRef = `oci:tasks/kb08@${shaDig(manBytes)}`;

  // 3. Provision /etc/kubelet/{config.json,bootstrap-token} inside the browser OS as local root,
  //    then enable & start `kubelet.service`!
  await switchLocalUser(page, 'root');
  await pageMkdirp(page, '/etc/kubelet', 0o700);
  await pagePut(page, '/etc/kubelet/config.json', JSON.stringify({
    control_plane_url: origin,
    cluster: 'default',
    node_id: nodeId,
    lease_ttl_secs: 15,
  }), { mode: 0o600 });
  await pagePut(page, '/etc/kubelet/bootstrap-token', btIssued.bootstrap_token + '\n', { mode: 0o600 });

  const enOut = await runService(page, ['enable', 'kubelet']);
  expect(enOut).not.toMatch(/error|failed/i);
  const startOut = await runService(page, ['start', 'kubelet']);
  expect(startOut).not.toMatch(/error|failed/i);
  await expect.poll(async () => runService(page, ['status', 'kubelet']), { timeout: 25_000 }).toMatch(/State:\s+active/i);
  const activeStatus = await runService(page, ['status', 'kubelet']);
  expect(activeStatus).toMatch(/Enabled:\s+yes/i);

  // Verify browser node registered in ClusterState!
  const clusterRpc = async call => {
    const r = await fetch(`${origin}/api/cluster/rpc`, {
      method: 'POST',
      headers: { ...adminHdrs, 'Content-Type': 'application/json' },
      body: JSON.stringify({ version: 1, cluster: 'default', call }),
    });
    const text = await r.text();
    expect(r.status, text).toBe(200);
    return JSON.parse(text);
  };
  await expect.poll(async () => {
    const r = await clusterRpc({ op: 'range', key: `/t/u0/nodes/${nodeId}`, range_end: 'exact', limit: 1 });
    return r.kvs?.length ?? 0;
  }, { timeout: 25_000 }).toBe(1);

  // Submit a real task pinned to this browser node & await fenced ResultRecord!
  const wid = `kb08-wl-${randomBytes(4).toString('hex')}`;
  const wl = {
    workload_id: wid,
    image_ref: imageRef,
    labels: {
      'os.task/sdk_version': '1',
      'os.task/entrypoint': '/usr/bin/hello.wasm',
      'os.task/output_repo': 'results/kb08',
      'os.task/timeout_secs': '60',
      'os.task/memory_max_bytes': String(32 * 1024 * 1024),
      'os.task/pids_max': '8',
      'os.task/required_node': nodeId,
    },
    desired_state: 'pending',
    current_attempt: 0,
    created_at: Math.floor(Date.now() / 1000),
  };
  const admit = await clusterRpc({
    op: 'txn',
    compare: [{ key: `/t/u0/workloads/${wid}`, op: 'equal', target: { version: 0 } }],
    success: [{ op: 'put', key: `/t/u0/workloads/${wid}`, value_b64: Buffer.from(JSON.stringify(wl)).toString('base64'), lease_id: 0, prev_kv: false }],
    failure: [],
  });
  expect(admit.succeeded).toBe(true);

  let result = null;
  await expect.poll(async () => {
    const r = await clusterRpc({ op: 'range', key: `/t/u0/results/${wid}`, range_end: 'exact', limit: 1 });
    if (r.kvs?.length) {
      result = JSON.parse(Buffer.from(r.kvs[0].value_b64, 'base64').toString('utf8'));
      return result.exit_code;
    }
    return null;
  }, { timeout: 30_000 }).toBe(0);
  expect(result.node_id).toBe(nodeId);
  expect(result.summary).toBe('browser-kb08-ok');

  // 4. Reload the tab -> verify `kubelet.service` stayed `enabled` via `/etc/services/.enabled.json`!
  await page.reload();
  await page.waitForFunction(() => !!window.os?.exec, null, { timeout: 30_000 });
  let reloadedStatus = '';
  await expect.poll(async () => {
    reloadedStatus = await runService(page, ['status', 'kubelet']);
    return reloadedStatus;
  }, { timeout: 30_000 }).toMatch(/Unit:\s+kubelet\.service/);
  expect(reloadedStatus).toMatch(/Enabled:\s+yes/i);

  // Clean up opt-in state.
  await switchLocalUser(page, 'root');
  await runService(page, ['stop', 'kubelet']);
  await runService(page, ['disable', 'kubelet']);
  const finalStatus = await runService(page, ['status', 'kubelet']);
  expect(finalStatus).toMatch(/Enabled:\s+no/i);
});
