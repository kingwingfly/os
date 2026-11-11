import { test, expect } from './test.js';
import { api, call, sys } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const host = () => ({ host: randomUUID(), proof: randomBytes(32).toString('hex') });
const owner = (view, host) => ({ boot: view.boot, generation: view.generation, ...host });
const registry = { 'X-Registry': '1' };
async function invoke(request, action, { errno, options = {}, routed = false } = {}) {
  const [result] = await sys(request, [{ machine_init: { action } }], options, routed ? registry : {});
  if (errno) { expect(result.err?.errno, JSON.stringify(result)).toBe(errno); return; }
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'init-owner-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}
const status = page => page.evaluate(() => window.os.machineInit());
async function ready(page) {
  await page.goto('/');
  await expect.poll(async () => (await status(page))?.connected).toBe(true);
  return status(page);
}

test('one Machine boot has one init owner and all mutations require its private proof and generation', async ({ request }) => {
  await call(request, 'getcreds');
  const initial = await invoke(request, { op: 'inspect' });
  expect(initial.pid).toBe(1); expect(initial.owner).toBe(null);
  const one = host(), two = host();
  const claims = await Promise.all([one, two].map(async host => (await sys(request, [{ machine_init: { action: { op: 'claim', owner: owner(initial, host) } } }]))[0]));
  expect(claims.filter(result => result.ok)).toHaveLength(1);
  expect(claims.filter(result => result.err)[0].err.errno).toBe('ESTALE');
  const current = await invoke(request, { op: 'inspect' }, { routed: true });
  const winner = current.owner === one.host ? one : two, other = current.owner === one.host ? two : one;
  await invoke(request, { op: 'claim', owner: owner(current, other) }, { errno: 'EBUSY' });
  for (const op of ['renew', 'release']) {
    await invoke(request, { op, owner: { ...owner(current, winner), proof: host().proof } }, { errno: 'EACCES' });
    await invoke(request, { op, owner: { ...owner(current, winner), boot: 'wrong-boot' } }, { errno: 'ESTALE' });
  }
  const released = await invoke(request, { op: 'release', owner: owner(current, winner) });
  const next = await invoke(request, { op: 'claim', owner: owner(released, other) });
  expect(next.boot).toBe(initial.boot); expect(next.generation).toBe(current.generation + 1);
  for (const op of ['renew', 'release']) await invoke(request, { op, owner: owner(current, winner) }, { errno: 'ESTALE' });
  for (const secret of [one.proof, two.proof, 'hash', 'binding']) expect(JSON.stringify(next)).not.toContain(secret);
});

test('Machine init ownership spans login replacement and logout without granting root', async ({ request }) => {
  await call(request, 'getcreds');
  const one = host(); const initial = await invoke(request, { op: 'inspect' });
  const held = await invoke(request, { op: 'claim', owner: owner(initial, one) });
  const claim = owner(held, one);
  const before = (await sys(request, [{ proc_init: { boot: 'account-before' } }], {}, registry))[0].ok;
  expect(before.machine_boot).toBe(held.boot);
  await signIn(request);
  expect((await invoke(request, { op: 'renew', owner: claim })).generation).toBe(held.generation);
  await signIn(request); await api(request, 'logout');
  const after = await invoke(request, { op: 'renew', owner: claim });
  expect(after.boot).toBe(held.boot); expect(after.owner).toBe(one.host);
  const reset = (await sys(request, [{ proc_init: { boot: 'account-after' } }], {}, registry))[0].ok;
  expect(reset.machine_boot).toBe(held.boot);
  const [denied] = await sys(request, [{ cgroup_create: { path: '/system/no-root-' + randomUUID() } }], {}, registry);
  expect(denied.err?.errno, JSON.stringify(denied)).toBe('EACCES');
});

test('a different Machine cannot reuse an init proof or boot identifier', async ({ browser, request }) => {
  await call(request, 'getcreds');
  const one = host(); const initial = await invoke(request, { op: 'inspect' });
  const held = await invoke(request, { op: 'claim', owner: owner(initial, one) });
  const context = await browser.newContext();
  try {
    await call(context.request, 'getcreds');
    const other = await invoke(context.request, { op: 'inspect' });
    expect(other.boot).not.toBe(initial.boot);
    for (const op of ['claim', 'renew', 'release']) await invoke(context.request, { op, owner: owner(held, one) }, { errno: 'ESTALE' });
    expect((await invoke(request, { op: 'inspect' })).owner).toBe(one.host);
  } finally { await context.close(); }
});

test('process snapshots, sudo and malformed proofs cannot acquire init ownership', async ({ request }) => {
  await call(request, 'getcreds');
  const initial = await invoke(request, { op: 'inspect' });
  const one = host();
  await invoke(request, { op: 'claim', owner: owner(initial, one) }, { errno: 'EPERM', options: { sudo: true }, routed: true });
  await invoke(request, { op: 'claim', owner: owner(initial, { ...one, proof: 'short' }) }, { errno: 'EINVAL' });
  await invoke(request, { op: 'claim', owner: owner(initial, { ...one, host: 'bad/name' }) }, { errno: 'EINVAL' });
  const process = await call(request, { execve: { path: '/usr/bin/coreutils', argv: ['coreutils', 'true'], env: [], cwd: '/' } });
  try {
    for (const routed of [false, true]) await invoke(request, { op: 'inspect' }, {
      errno: 'EPERM', routed, options: { pid: process.pid, proc: process.token },
    });
  } finally {
    await sys(request, [{ exit: { pid: process.pid, proc: process.token, status: 0 } }, { wait: { pid: String(process.pid), proc: process.token } }], {}, registry);
  }
});

test('tabs share one init host and takeover preserves the survivor command and boot', async ({ page, context }) => {
  await ready(page); await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page); const other = await context.newPage();
  const follower = await ready(other);
  expect(follower.init.boot).toBe(before.init.boot); expect(follower.coordinator).toBe(false);
  const input = other.locator('#command'); await input.fill('cat'); await input.press('Enter');
  await expect(other.locator('.command-line')).toHaveAttribute('data-state', 'input');
  await page.close();
  await expect.poll(async () => (await status(other)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
  const after = await status(other); expect(after.init.boot).toBe(before.init.boot);
  expect(after.init.generation).toBeGreaterThan(before.init.generation);
  await input.pressSequentially('init-takeover-survived'); await input.press('Enter');
  await expect(other.locator('.terminal-screen')).toContainText('init-takeover-survived\ninit-takeover-survived');
  await input.press('Control+d'); await expect(other.locator('.command-line')).toHaveAttribute('data-state', 'idle');
});

test('host reload keeps the Machine boot but obtains a new owner generation', async ({ page }) => {
  await ready(page); await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page); await page.reload();
  await expect.poll(async () => (await status(page)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
  const after = await status(page);
  expect(after.init.boot).toBe(before.init.boot); expect(after.host).not.toBe(before.host);
  expect(after.init.generation).toBeGreaterThan(before.init.generation);
});

test('init ownership expires after kernel death even if its page and public Web Lock remain alive', async ({ page, context }) => {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(url, options) {
        super(url, options);
        if (new URL(url, location.href).pathname.endsWith('/client-kernel.js')) window.initKernel = this;
      }
    };
  });
  await ready(page); await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page); const other = await context.newPage(); await ready(other);
  await page.evaluate(() => window.initKernel.terminate());
  const held = await page.evaluate(async () => (await navigator.locks.query()).held.map(lock => lock.name));
  expect(held.some(name => name.startsWith('tw-tab-'))).toBe(true);
  await expect.poll(async () => (await status(other)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
  const after = await status(other); expect(after.init.boot).toBe(before.init.boot);
  expect(after.init.generation).toBeGreaterThan(before.init.generation);
  await expect.poll(async () => (await status(other)).reaper.state, { timeout: 15_000 }).toBe('running');
});

test('browser login changes preserve init ownership and running process credentials', async ({ page }) => {
  await ready(page); await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page); const guest = await call(page.request, 'getcreds');
  const input = page.locator('#command'); await input.fill('sh -i'); await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input');
  await signIn(page.request); await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(0);
  await input.pressSequentially('id -u'); await input.press('Enter');
  await expect(page.locator('.terminal-screen')).toContainText(String(guest.uid));
  await api(page.request, 'logout'); await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(guest.uid);
  const after = await status(page); expect(after.coordinator).toBe(true);
  expect(after.init.boot).toBe(before.init.boot); expect(after.init.generation).toBe(before.init.generation);
  await input.pressSequentially('exit'); await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
});

test('unavailable init coordination does not block commands or login coordination', async ({ page }) => {
  const block = route => route.request().postData()?.includes('machine_init')
    ? route.fulfill({ status: 503, body: 'unavailable' }) : route.continue();
  await page.route('**/api/sys', block); await page.goto('/');
  await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).connected).toBe(true);
  expect((await status(page)).connected).toBe(false);
  const input = page.locator('#command'); await input.fill('printf init-offline'); await input.press('Enter');
  await expect(page.locator('.output-line').last()).toHaveText('init-offline');
  await page.unroute('**/api/sys', block);
  await expect.poll(async () => (await status(page)).coordinator, { timeout: 15_000 }).toBe(true);
});
