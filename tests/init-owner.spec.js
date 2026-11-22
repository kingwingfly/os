import { test, expect } from './test.js';
import { api, call } from './sys.js';
import { logoutLocalUser, pageCall, switchLocalUser } from './ui.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const host = () => ({ host: randomUUID(), proof: randomBytes(32).toString('hex') });
const owner = (view, h) => ({ boot: view.boot, generation: view.generation, ...h });

async function signIn(request) {
  expect((await api(request, 'login', {
    headers: { 'CF-Connecting-IP': 'init-owner-' + randomUUID() },
    data: { password },
  })).ok()).toBe(true);
}

async function serviceAuth(request, body) {
  const res = await request.post(origin + '/api/service-auth', {
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    data: body,
  });
  return { status: res.status(), ok: res.ok(), body: await res.json() };
}

async function connect(page) {
  await page.goto('/login');
  await page.evaluate(() => {
    const worker = new Worker('/client-kernel.js');
    const pending = new Map();
    let next = 0;
    worker.onmessage = ({ data }) => {
      if (data?.id != null && pending.has(data.id)) {
        pending.get(data.id)(data);
        pending.delete(data.id);
      }
    };
    window.initOwnerKernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      worker.postMessage({ v: 2, id, type, args });
    });
  });
  const init = await kc(page, 'init');
  expect(init.err, JSON.stringify(init)).toBeUndefined();
}
const kc = (page, type, args = {}) => page.evaluate(([type, args]) => window.initOwnerKernel(type, args), [type, args]);
async function invoke(page, action, { errno } = {}) {
  const res = await kc(page, 'machine_init_action', { action });
  if (errno) {
    expect(res.err?.errno, JSON.stringify(res)).toBe(errno);
    return;
  }
  expect(res.err, JSON.stringify(res)).toBeUndefined();
  return res.ok;
}

const status = page => page.evaluate(() => window.os.machineInit());
async function ready(page) {
  await page.goto('/');
  await expect.poll(async () => (await status(page))?.connected).toBe(true);
  return status(page);
}

test('one instance boot has one local init owner and all mutations require its private proof and generation', async ({ page }) => {
  const sysCalls = [];
  page.on('request', req => {
    if (req.method() === 'POST' && new URL(req.url()).pathname === '/api/sys') sysCalls.push(req.postData() ?? '');
  });
  await connect(page);
  sysCalls.length = 0;
  const initial = await invoke(page, { op: 'inspect' });
  expect(initial.pid).toBe(1);
  // Claiming after releasing any auto-claimed local coordinator tests generation & proof fencing locally.
  const one = host(), two = host();
  let base = initial;
  if (base.owner) {
    // Wait for fresh instance or test directly against a second clean Worker before auto-claim.
    // Reboot requires root; instead test claim/renew/release fencing directly on our local init state.
    await invoke(page, { op: 'claim', owner: owner(base, one) }, { errno: 'EBUSY' });
    await invoke(page, { op: 'renew', owner: { ...owner(base, { host: base.owner, proof: one.proof }) } }, { errno: 'EACCES' });
    await invoke(page, { op: 'release', owner: { ...owner(base, { host: base.owner, proof: one.proof }) } }, { errno: 'EACCES' });
    await invoke(page, { op: 'renew', owner: { ...owner(base, one), boot: 'wrong-boot' } }, { errno: 'ESTALE' });
  } else {
    const claimed = await invoke(page, { op: 'claim', owner: owner(base, one) });
    await invoke(page, { op: 'claim', owner: owner(claimed, two) }, { errno: 'EBUSY' });
    for (const op of ['renew', 'release']) {
      await invoke(page, { op, owner: { ...owner(claimed, one), proof: two.proof } }, { errno: 'EACCES' });
      await invoke(page, { op, owner: { ...owner(claimed, one), boot: 'wrong-boot' } }, { errno: 'ESTALE' });
    }
    const released = await invoke(page, { op: 'release', owner: owner(claimed, one) });
    const next = await invoke(page, { op: 'claim', owner: owner(released, two) });
    expect(next.boot).toBe(base.boot);
    expect(next.generation).toBe(claimed.generation + 1);
    for (const op of ['renew', 'release']) {
      await invoke(page, { op, owner: owner(claimed, one) }, { errno: 'ESTALE' });
    }
    for (const secret of [one.proof, two.proof, 'hash', 'binding']) {
      expect(JSON.stringify(next)).not.toContain(secret);
    }
  }
  await invoke(page, { op: 'claim', owner: owner(base, { ...one, proof: 'short' }) }, { errno: 'EINVAL' });
  await invoke(page, { op: 'claim', owner: owner(base, { ...one, host: 'bad/name' }) }, { errno: 'EINVAL' });
  // Zero MachineInit traffic went to /api/sys.
  expect(sysCalls.filter(body => body.includes('machine_init'))).toEqual([]);
});

test('ServiceAuth v2 AttachInstance fences one live host per instance_id and rejects forged or cross-session proofs', async ({ browser, request }) => {
  await call(request, 'getcreds');

  // Version negotiation: v2 accepted, v1 refused with EPROTONOSUPPORT.
  const okHello = await serviceAuth(request, { hello: { boundary: 'service-auth', versions: [2] } });
  expect(okHello.ok, JSON.stringify(okHello)).toBe(true);
  expect(okHello.body.welcome?.version).toBe(2);

  const badHello = await serviceAuth(request, { hello: { boundary: 'service-auth', versions: [1] } });
  expect(badHello.ok).toBe(false);
  expect(badHello.body.errno).toBe('EPROTONOSUPPORT');

  // Attach an instance with host proof 1.
  const instanceId = `inst-${randomBytes(8).toString('hex')}`;
  const proof1 = randomBytes(32).toString('hex');
  const proof2 = randomBytes(32).toString('hex');

  const attached = await serviceAuth(request, {
    attach_instance: { instance: { instance: instanceId, host: 'browser' }, host_proof: proof1 },
  });
  expect(attached.ok, JSON.stringify(attached)).toBe(true);
  expect(attached.body.attached.instance_id).toBe(instanceId);
  expect(attached.body.attached.host_epoch).toBe(1);

  // Competing host trying to attach the same live instance_id with another proof is fenced (ESTALE).
  const stolen = await serviceAuth(request, {
    attach_instance: { instance: { instance: instanceId, host: 'browser' }, host_proof: proof2 },
  });
  expect(stolen.ok).toBe(false);
  expect(stolen.body.errno).toBe('ESTALE');

  // Renew / Mint with wrong host_proof fail closed with EACCES.
  const badRenew = await serviceAuth(request, {
    renew_instance: { instance_id: instanceId, host_proof: proof2, active_tokens: [] },
  });
  expect(badRenew.ok).toBe(false);
  expect(badRenew.body.errno).toBe('EACCES');

  const badMint = await serviceAuth(request, {
    mint_service_cred: { instance_id: instanceId, host_proof: proof2 },
  });
  expect(badMint.ok).toBe(false);
  expect(badMint.body.errno).toBe('EACCES');

  // A different browser session cannot renew, mint, or detach this session's attached instance_id.
  const other = await browser.newContext();
  try {
    await call(other.request, 'getcreds');
    const crossRenew = await serviceAuth(other.request, {
      renew_instance: { instance_id: instanceId, host_proof: proof1, active_tokens: [] },
    });
    expect(crossRenew.ok).toBe(false);
    expect(crossRenew.body.errno).toBe('EACCES');
    const crossMint = await serviceAuth(other.request, {
      mint_service_cred: { instance_id: instanceId, host_proof: proof1 },
    });
    expect(crossMint.ok).toBe(false);
    expect(crossMint.body.errno).toBe('EACCES');
    const crossDetach = await serviceAuth(other.request, {
      detach_instance: { instance_id: instanceId, host_proof: proof1 },
    });
    expect(crossDetach.ok).toBe(false);
    expect(crossDetach.body.errno).toBe('EACCES');
  } finally {
    await other.close();
  }

  // Detach with forged proof fails EACCES; real host_proof detaches cleanly and frees the fence.
  const badDetach = await serviceAuth(request, {
    detach_instance: { instance_id: instanceId, host_proof: proof2 },
  });
  expect(badDetach.ok).toBe(false);
  expect(badDetach.body.errno).toBe('EACCES');

  const detached = await serviceAuth(request, {
    detach_instance: { instance_id: instanceId, host_proof: proof1 },
  });
  expect(detached.ok, JSON.stringify(detached)).toBe(true);

  // After clean detach, renewing the detached instance fails closed with EACCES.
  const afterDetach = await serviceAuth(request, {
    renew_instance: { instance_id: instanceId, host_proof: proof1, active_tokens: [] },
  });
  expect(afterDetach.ok).toBe(false);
  expect(afterDetach.body.errno).toBe('EACCES');
});

test('server refuses retired MachineInit and X-Registry routes fail closed', async ({ request }) => {
  await call(request, 'getcreds');
  const reg = await request.post(origin + '/api/sys', {
    headers: { Origin: origin, 'Content-Type': 'application/json', 'X-Registry': '1' },
    data: { calls: ['getcreds'] },
  });
  expect(reg.status()).toBe(403);
  const retired = await request.post(origin + '/api/sys', {
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    data: { calls: [{ machine_init: { action: { op: 'inspect' } } }] },
  });
  expect(retired.ok()).toBe(false);
});

test('each tab boots its own independent PID 1 with zero MachineInit RPCs and reload starts a fresh instance', async ({ page, context }) => {
  const machineInitRpcs = [];
  const watch = req => {
    if (req.method() === 'POST' && new URL(req.url()).pathname === '/api/sys' && (req.postData() ?? '').includes('machine_init')) {
      machineInitRpcs.push(req.postData());
    }
  };
  page.on('request', watch);
  await ready(page);
  await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  await expect.poll(async () => (await status(page)).reaper?.state, { timeout: 15_000 }).toBe('running');
  const first = await status(page);

  const other = await context.newPage();
  other.on('request', watch);
  try {
    await ready(other);
    await expect.poll(async () => (await status(other)).coordinator).toBe(true);
    await expect.poll(async () => (await status(other)).reaper?.state, { timeout: 15_000 }).toBe('running');
    const second = await status(other);
    // Per Contract §2.1 & §7: each tab is an isolated OS instance with its own boot & PID 1.
    expect(second.init.boot).not.toBe(first.init.boot);
    expect(second.host).not.toBe(first.host);

    // Reloading Tab 1 creates a brand-new instance without waiting for cross-tab lease expiry.
    await page.reload();
    await expect.poll(async () => (await status(page)).coordinator, { timeout: 15_000 }).toBe(true);
    const reloaded = await status(page);
    expect(reloaded.init.boot).not.toBe(first.init.boot);
    expect(reloaded.host).not.toBe(first.host);
    expect(machineInitRpcs).toEqual([]);
  } finally {
    await other.close();
  }
});

test('local account changes preserve local init ownership and running process credentials', async ({ page }) => {
  await ready(page);
  await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page);
  const initialCreds = await pageCall(page, 'getcreds');
  expect(initialCreds.uid).toBe(1000);
  const input = page.locator('#command');
  await input.fill('sh -i');
  await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input', { timeout: 15_000 });
  await switchLocalUser(page, 'root');
  await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(0);
  await input.pressSequentially('id -u');
  await input.press('Enter');
  await expect(page.locator('.terminal-screen')).toContainText(String(initialCreds.uid));
  await logoutLocalUser(page);
  await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(initialCreds.uid);
  const after = await status(page);
  expect(after.coordinator).toBe(true);
  expect(after.init.boot).toBe(before.init.boot);
  expect(after.init.generation).toBe(before.init.generation);
  await input.pressSequentially('exit');
  await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
});
