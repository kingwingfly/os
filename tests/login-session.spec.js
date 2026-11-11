import { test, expect } from './test.js';
import { api, call, sys } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const host = () => ({ host: randomUUID(), proof: randomBytes(32).toString('hex') });
const member = (view, host) => ({ session: view.id, ...host });
const registry = { 'X-Registry': '1' };
async function invoke(request, action, { errno, options = {}, routed = false } = {}) {
  const [result] = await sys(request, [{ login_session: { action } }], options, routed ? registry : {});
  if (errno) { expect(result.err?.errno, JSON.stringify(result)).toBe(errno); return; }
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'login-session-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}
const status = page => page.evaluate(() => window.os.loginSession());
async function ready(page) {
  await page.goto('/');
  await expect.poll(async () => (await status(page))?.connected).toBe(true);
  return status(page);
}
test('a login has one fenced coordinator; public names cannot renew, replace or remove it', async ({ request }) => {
  await call(request, 'getcreds');
  const one = host(), two = host();
  const first = await invoke(request, { op: 'join', ...one });
  const second = await invoke(request, { op: 'join', ...two }, { routed: true });
  expect(first.id).toBe(second.id);
  const claims = await Promise.all([one, two].map(async host => (await sys(request, [{ login_session: { action: { op: 'claim', member: member(first, host), generation: 0 } } }]))[0]));
  expect(claims.filter(result => result.ok)).toHaveLength(1);
  expect(claims.filter(result => result.err)[0].err.errno).toBe('ESTALE');
  const current = await invoke(request, { op: 'inspect' });
  const owner = current.owner === one.host ? one : two;
  const other = current.owner === one.host ? two : one;
  await invoke(request, { op: 'claim', member: member(first, other), generation: current.generation }, { errno: 'EBUSY' });
  const forged = { ...member(first, owner), proof: host().proof };
  for (const op of ['keep', 'leave', 'renew']) {
    await invoke(request, { op, member: forged, ...(op === 'renew' ? { generation: current.generation } : {}) }, { errno: 'EACCES' });
  }
  await invoke(request, { op: 'leave', member: member(first, owner) });
  const next = await invoke(request, { op: 'claim', member: member(first, other), generation: current.generation });
  expect(next.generation).toBe(current.generation + 1);
  await invoke(request, { op: 'join', ...owner });
  await invoke(request, { op: 'renew', member: member(first, owner), generation: current.generation }, { errno: 'ESTALE' });
  const encoded = JSON.stringify(next);
  for (const secret of [one.proof, two.proof, 'binding', 'hash']) expect(encoded).not.toContain(secret);
});

test('host capacity is bounded and a proven departure releases capacity', async ({ request }) => {
  await call(request, 'getcreds');
  const members = Array.from({ length: 64 }, host);
  let view;
  for (const host of members) view = await invoke(request, { op: 'join', ...host });
  const extra = host();
  await invoke(request, { op: 'join', ...extra }, { errno: 'ENOSPC' });
  await invoke(request, { op: 'leave', member: member(view, members[0]) });
  expect((await invoke(request, { op: 'join', ...extra })).hosts).toHaveLength(64);
});

test('login replacement selects a new record even for the same account; old proof can only leave', async ({ request }) => {
  await call(request, 'getcreds'); await signIn(request);
  const one = host(); const old = await invoke(request, { op: 'join', ...one });
  await invoke(request, { op: 'claim', member: member(old, one), generation: 0 });
  await signIn(request);
  expect(await invoke(request, { op: 'inspect' })).toBe(null);
  const fresh = await invoke(request, { op: 'join', ...host() });
  expect(fresh.uid).toBe(0); expect(fresh.id).not.toBe(old.id);
  await invoke(request, { op: 'renew', member: member(old, one), generation: 1 }, { errno: 'ESTALE' });
  expect(await invoke(request, { op: 'leave', member: member(old, one) })).toBe(null);
  expect((await invoke(request, { op: 'inspect' })).id).toBe(fresh.id);
  await api(request, 'logout');
  await invoke(request, { op: 'renew', member: member(fresh, one), generation: 1 }, { errno: 'ESTALE' });
});

test('a different browser cannot use another Machine membership even with its proof', async ({ browser, request }) => {
  await call(request, 'getcreds');
  const one = host(), initial = await invoke(request, { op: 'join', ...one });
  const context = await browser.newContext();
  try {
    await call(context.request, 'getcreds');
    await invoke(context.request, { op: 'leave', member: member(initial, one) }, { errno: 'ESTALE' });
    const other = await invoke(context.request, { op: 'join', ...one });
    expect(other.id).not.toBe(initial.id);
    expect((await invoke(request, { op: 'inspect' })).hosts).toHaveLength(1);
  } finally { await context.close(); }
});

test('process snapshots and sudo never acquire browser login coordination', async ({ request }) => {
  await call(request, 'getcreds');
  await invoke(request, { op: 'join', ...host() }, { errno: 'EPERM', options: { sudo: true }, routed: true });
  const process = await call(request, { execve: { path: '/usr/bin/coreutils', argv: ['coreutils', 'true'], env: [], cwd: '/' } });
  try {
    for (const routed of [false, true]) await invoke(request, { op: 'join', ...host() }, {
      errno: 'EPERM', routed, options: { pid: process.pid, proc: process.token },
    });
  } finally {
    await sys(request, [{ exit: { pid: process.pid, proc: process.token, status: 0 } }, { wait: { pid: String(process.pid), proc: process.token } }], {}, registry);
  }
});

test('tabs share one login coordinator and a surviving host takes over without killing its command', async ({ page, context }) => {
  const first = await ready(page); await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const other = await context.newPage(); const second = await ready(other);
  expect(second.session.id).toBe(first.session.id); expect(second.coordinator).toBe(false);
  const input = other.locator('#command'); await input.fill('cat'); await input.press('Enter');
  await expect(other.locator('.command-line')).toHaveAttribute('data-state', 'input');
  const generation = (await status(page)).session.generation;
  await page.close();
  await expect.poll(async () => (await status(other)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
  const next = await status(other); expect(next.session.id).toBe(first.session.id); expect(next.session.generation).toBeGreaterThan(generation);
  await input.pressSequentially('survived-takeover'); await input.press('Enter');
  await expect(other.locator('.terminal-screen')).toContainText('survived-takeover\nsurvived-takeover');
  await input.press('Control+d'); await expect(other.locator('.command-line')).toHaveAttribute('data-state', 'idle');
});

test('reloading a host retains the durable login ID and advances coordinator generation', async ({ page }) => {
  await ready(page); await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page); await page.reload();
  await expect.poll(async () => (await status(page)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
  const after = await status(page);
  expect(after.session.id).toBe(before.session.id); expect(after.host).not.toBe(before.host);
  expect(after.session.generation).toBeGreaterThan(before.session.generation);
});

test('a dead kernel loses its coordinator lease even while its tab and public lock stay alive', async ({ page, context }) => {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(url, options) {
        super(url, options);
        if (new URL(url, location.href).pathname.endsWith('/client-kernel.js')) window.loginKernel = this;
      }
    };
  });
  await ready(page); await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page);
  const other = await context.newPage(); await ready(other);
  await page.evaluate(() => window.loginKernel.terminate());
  const held = await page.evaluate(async () => (await navigator.locks.query()).held.map(lock => lock.name));
  expect(held.some(name => name.startsWith('tw-tab-'))).toBe(true);
  await expect.poll(async () => (await status(other)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
  const after = await status(other);
  expect(after.session.id).toBe(before.session.id);
  expect(after.session.generation).toBeGreaterThan(before.session.generation);
  expect(after.session.hosts.some(member => member.host === before.host)).toBe(false);
});

test('identity changes rejoin the actual login and leave running-process credentials intact', async ({ page }) => {
  const guest = await ready(page);
  const input = page.locator('#command'); await input.fill('sh -i'); await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input');
  await signIn(page.request); await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  await expect.poll(async () => (await status(page)).session?.uid).toBe(0);
  const root = await status(page); expect(root.session.id).not.toBe(guest.session.id);
  await input.pressSequentially('id -u'); await input.press('Enter');
  await expect(page.locator('.terminal-screen')).toContainText(String(guest.session.uid));
  await api(page.request, 'logout'); await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  await expect.poll(async () => (await status(page)).session?.uid).toBe(guest.session.uid);
  await input.pressSequentially('exit'); await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
});

test('coordination failures do not block execution and reconnect restores membership', async ({ page }) => {
  await ready(page);
  const block = route => route.request().postData()?.includes('login_session')
    ? route.fulfill({ status: 503, body: 'unavailable' }) : route.continue();
  await page.route('**/api/sys', block);
  await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  await expect.poll(async () => (await status(page)).connected).toBe(false);
  const input = page.locator('#command'); await input.fill('printf still-running'); await input.press('Enter');
  await expect(page.locator('.output-line').last()).toHaveText('still-running');
  await page.unroute('**/api/sys', block);
  await expect.poll(async () => (await status(page)).connected, { timeout: 15_000 }).toBe(true);
});
