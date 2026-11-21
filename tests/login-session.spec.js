import { test, expect } from './test.js';
import { api, call } from './sys.js';
import { connectKernel, hookPageKernel } from './service-auth.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };

const host = () => ({ host: randomUUID(), proof: randomBytes(32).toString('hex') });
const member = (view, h) => ({ session: view.id, ...h });

async function freshKernel(page, name = '__loginSessKernel') {
  await page.goto('/login');
  const kernel = await connectKernel(page, { name });
  await kernel.value('login_leave');
  await kernel.value('machine_init_leave');
  return kernel;
}

async function invoke(kernel, action, { errno } = {}) {
  const result = await kernel.call('login_session_action', { action });
  if (errno) {
    expect(result.err?.errno, JSON.stringify(result)).toBe(errno);
    return;
  }
  expect(result.err, JSON.stringify(result)).toBeUndefined();
  return result.ok;
}

async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'login-session-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}

const status = page => page.evaluate(() => window.os.loginSession());
async function ready(page) {
  await call(page.request, 'getcreds');
  await page.goto('/');
  await expect.poll(async () => (await status(page))?.connected, { timeout: 20_000 }).toBe(true);
  return status(page);
}

test('a login has one fenced coordinator; public names cannot renew, replace or remove it', async ({ page }) => {
  const kernel = await freshKernel(page);
  try {
    const one = host(), two = host();
    const first = await invoke(kernel, { op: 'join', ...one });
    const second = await invoke(kernel, { op: 'join', ...two });
    expect(first.id).toBe(second.id);
    const claims = await Promise.all(
      [one, two].map(h => kernel.call('login_session_action', { action: { op: 'claim', member: member(first, h), generation: first.generation } })),
    );
    expect(claims.filter(result => result.ok)).toHaveLength(1);
    expect(claims.filter(result => result.err)[0].err.errno).toBe('ESTALE');

    const current = await invoke(kernel, { op: 'inspect' });
    const ownerHost = current.owner === one.host ? one : two;
    const otherHost = current.owner === one.host ? two : one;
    await invoke(kernel, { op: 'claim', member: member(first, otherHost), generation: current.generation }, { errno: 'EBUSY' });

    const forged = { ...member(first, ownerHost), proof: host().proof };
    for (const op of ['keep', 'leave', 'renew']) {
      await invoke(kernel, { op, member: forged, ...(op === 'renew' ? { generation: current.generation } : {}) }, { errno: 'EACCES' });
    }
    await invoke(kernel, { op: 'leave', member: member(first, ownerHost) });
    const next = await invoke(kernel, { op: 'claim', member: member(first, otherHost), generation: current.generation });
    expect(next.generation).toBe(current.generation + 1);
    await invoke(kernel, { op: 'join', ...ownerHost });
    await invoke(kernel, { op: 'renew', member: member(first, ownerHost), generation: current.generation }, { errno: 'ESTALE' });

    const encoded = JSON.stringify(next);
    for (const secret of [one.proof, two.proof, 'binding', 'hash']) expect(encoded).not.toContain(secret);
  } finally {
    await kernel.terminate();
  }
});

test('host capacity is bounded and a proven departure releases capacity', async ({ page }) => {
  const kernel = await freshKernel(page);
  try {
    const members = Array.from({ length: 64 }, host);
    let view;
    for (const h of members) view = await invoke(kernel, { op: 'join', ...h });
    const extra = host();
    await invoke(kernel, { op: 'join', ...extra }, { errno: 'ENOSPC' });
    await invoke(kernel, { op: 'leave', member: member(view, members[0]) });
    expect((await invoke(kernel, { op: 'join', ...extra })).hosts).toHaveLength(64);
  } finally {
    await kernel.terminate();
  }
});

test('login replacement selects a new record even for the same account; old proof can only leave', async ({ page }) => {
  const kernel = await freshKernel(page);
  try {
    await kernel.value('sync_account', ROOT_ACCOUNT);
    const one = host();
    const old = await invoke(kernel, { op: 'join', ...one });
    const claimed = await invoke(kernel, { op: 'claim', member: member(old, one), generation: old.generation });

    // Replacing the login for the same account (logout -> login, or explicit end + restart) allocates a fresh session ID.
    await invoke(kernel, { op: 'end', session: old.id });
    const restarted = await invoke(kernel, { op: 'restart', session: old.id });
    expect(restarted.uid).toBe(0);
    expect(restarted.id).not.toBe(old.id);
    const fresh = await invoke(kernel, { op: 'join', ...host() });
    expect(fresh.uid).toBe(0);
    expect(fresh.id).not.toBe(old.id);

    await invoke(kernel, { op: 'renew', member: member(old, one), generation: claimed.generation }, { errno: 'ESTALE' });
    await invoke(kernel, { op: 'leave', member: member(old, one) }, { errno: 'ESTALE' });
    expect((await invoke(kernel, { op: 'inspect' })).id).toBe(fresh.id);

    await kernel.value('sync_account', GUEST_ACCOUNT);
    await invoke(kernel, { op: 'renew', member: member(fresh, one), generation: fresh.generation }, { errno: 'ESTALE' });
  } finally {
    await kernel.terminate();
  }
});

test('a different browser cannot use another Machine membership even with its proof', async ({ browser, page }) => {
  const kernel = await freshKernel(page);
  const context = await browser.newContext();
  try {
    const one = host(), initial = await invoke(kernel, { op: 'join', ...one });
    const otherPage = await context.newPage();
    const otherKernel = await freshKernel(otherPage, '__loginSessOtherCtx');
    try {
      await invoke(otherKernel, { op: 'leave', member: member(initial, one) }, { errno: 'ESTALE' });
      const other = await invoke(otherKernel, { op: 'join', ...one });
      expect(other.id).not.toBe(initial.id);
      expect((await invoke(kernel, { op: 'inspect' })).hosts).toHaveLength(1);
    } finally {
      await otherKernel.terminate();
    }
  } finally {
    await kernel.terminate();
    await context.close();
  }
});

test('process snapshots and sudo never acquire browser login coordination', async ({ page, request }) => {
  await call(request, 'getcreds');
  const kernel = await freshKernel(page);
  const proc = await kernel.value('exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'true'], env: [], cwd: '/' });
  try {
    // Process-scoped process_call rejects login_session.
    expect((await kernel.call('process_call', { pid: proc.pid, call: { login_session: { action: { op: 'join', ...host() } } } })).err).toBeTruthy();

    // Retired server /api/sys login_session fails closed for both sudo and process tokens (with or without X-Registry).
    for (const headers of [{}, { 'X-Registry': '1' }]) {
      for (const options of [{ sudo: true }, { pid: proc.pid, proc: proc.token || randomBytes(32).toString('hex') }]) {
        const res = await request.post(origin + '/api/sys', {
          headers: { Origin: origin, 'Content-Type': 'application/json', ...headers },
          data: { calls: [{ login_session: { action: { op: 'join', ...host() } } }], ...options },
        });
        expect(res.ok()).toBe(false);
      }
    }
  } finally {
    await kernel.call('exit', { pid: proc.pid, status: 0 });
    await kernel.call('wait', { pid: proc.pid });
    await kernel.terminate();
  }
});

test('tabs isolate login coordinators and same-instance handoff preserves a running command', async ({ page, context }) => {
  const first = await ready(page);
  await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const other = await context.newPage();
  const otherKernel = await hookPageKernel(other);
  try {
    const second = await ready(other);
    await otherKernel.ready();
    // Per Contract v2 §2.1, each tab owns an isolated client-kernel instance & coordinator.
    expect(second.session.id).not.toBe(first.session.id);
    await expect.poll(async () => (await status(other)).coordinator).toBe(true);

    const input = other.locator('#command');
    await input.fill('cat');
    await input.press('Enter');
    await expect(other.locator('.command-line')).toHaveAttribute('data-state', 'input', { timeout: 30_000 });
    const generation = (await status(other)).session.generation;

    // Closing the other tab never disturbs this tab's command, and releasing/reclaiming
    // coordinator ownership within this instance advances generation without killing `cat`.
    await page.close();
    await otherKernel.value('login_leave');
    await expect.poll(async () => (await status(other)).coordinator).toBe(false);
    await otherKernel.value('login_refresh', { fromServer: false });
    await expect.poll(async () => (await status(other)).coordinator, { timeout: 20_000 }).toBe(true);
    const next = await status(other);
    expect(next.session.id).toBe(second.session.id);
    expect(next.session.generation).toBeGreaterThan(generation);

    await input.pressSequentially('survived-takeover');
    await input.press('Enter');
    await expect(other.locator('.terminal-screen')).toContainText('survived-takeover\nsurvived-takeover');
    await input.press('Control+d');
    await expect(other.locator('.command-line')).toHaveAttribute('data-state', 'idle');
  } finally {
    await other.close();
  }
});

test('reconnecting a host advances coordinator generation while reload boots a fresh instance', async ({ page }) => {
  const pageKernel = await hookPageKernel(page);
  await ready(page);
  await pageKernel.ready();
  await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page);

  // Same-instance reconnect retains the instance's login ID and advances coordinator generation.
  await pageKernel.value('login_leave');
  await expect.poll(async () => (await status(page)).coordinator).toBe(false);
  await pageKernel.value('login_refresh', { fromServer: false });
  await expect.poll(async () => (await status(page)).coordinator, { timeout: 20_000 }).toBe(true);
  const reconnected = await status(page);
  expect(reconnected.session.id).toBe(before.session.id);
  expect(reconnected.session.generation).toBeGreaterThan(before.session.generation);

  // Per Contract v2 §2.1, a full reload boots a brand-new isolated client-kernel instance.
  await page.reload();
  await expect.poll(async () => (await status(page)).coordinator, { timeout: 20_000 }).toBe(true);
  const after = await status(page);
  expect(after.session.id).not.toBe(before.session.id);
  expect(after.host).not.toBe(before.host);
});

test('a dead kernel loses its coordinator while another tab stays isolated and unaffected', async ({ page, context }) => {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(url, options) {
        super(url, options);
        if (new URL(url, location.href).pathname.endsWith('/client-kernel.js')) window.loginKernel = this;
      }
    };
  });
  await ready(page);
  await expect.poll(async () => (await status(page)).coordinator).toBe(true);
  const before = await status(page);
  const other = await context.newPage();
  try {
    await ready(other);
    await page.evaluate(() => window.loginKernel.terminate());
    const held = await page.evaluate(async () => (await navigator.locks.query()).held.map(lock => lock.name));
    expect(held.some(name => name.startsWith('tw-tab-'))).toBe(true);
    await expect.poll(async () => (await status(other)).coordinator, { timeout: 20_000 }).toBe(true);
    const after = await status(other);
    expect(after.session.id).not.toBe(before.session.id);
    expect(after.session.hosts.some(m => m.host === before.host)).toBe(false);
  } finally {
    await other.close();
  }
});

test('identity changes rejoin the actual login and leave running-process credentials intact', async ({ page }) => {
  const guest = await ready(page);
  const input = page.locator('#command');
  await input.fill('sh -i');
  await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input');
  await signIn(page.request);
  await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  await expect.poll(async () => (await status(page)).session?.uid).toBe(0);
  const root = await status(page);
  expect(root.session.id).not.toBe(guest.session.id);
  await input.pressSequentially('id -u');
  await input.press('Enter');
  await expect(page.locator('.terminal-screen')).toContainText(String(guest.session.uid));
  await api(page.request, 'logout');
  await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  await expect.poll(async () => (await status(page)).session?.uid).toBe(guest.session.uid);
  await input.pressSequentially('exit');
  await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
});

test('coordination disconnect does not block execution and reconnect restores membership', async ({ page }) => {
  const pageKernel = await hookPageKernel(page);
  await ready(page);
  await pageKernel.ready();
  await pageKernel.value('login_leave');
  await expect.poll(async () => (await status(page)).connected).toBe(false);
  const input = page.locator('#command');
  await input.fill('printf still-running');
  await input.press('Enter');
  await expect(page.locator('.output-line').last()).toHaveText('still-running');
  await pageKernel.value('login_refresh', { fromServer: false });
  await expect.poll(async () => (await status(page)).connected, { timeout: 15_000 }).toBe(true);
});
