import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { call } from './sys.js';
import { pageMkdirp, pagePut, pageRmrf, switchLocalUser } from './ui.js';
import { connectKernel, hookPageKernel } from './service-auth.js';
import { randomBytes, randomUUID } from 'node:crypto';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };

const identity = () => ({ host: randomUUID(), proof: randomBytes(32).toString('hex') });
const proof = p => ({ pid: p.pid, proc: p.token ?? '' });

async function freshKernel(page, name = '__loginSvcKernel') {
  await page.goto('/login');
  const kernel = await connectKernel(page, { name });
  await kernel.value('login_leave');
  await kernel.value('machine_init_leave');
  return kernel;
}

async function invoke(kernel, action, expected) {
  const result = await kernel.call('login_session_action', { action });
  if (expected) {
    expect(result.err?.errno, JSON.stringify(result)).toBe(expected);
    return;
  }
  expect(result.err, JSON.stringify(result)).toBeUndefined();
  return result.ok;
}

async function owner(kernel) {
  const host = identity(), session = await invoke(kernel, { op: 'join', ...host });
  const member = { session: session.id, ...host };
  const view = await invoke(kernel, { op: 'claim', member, generation: session.generation });
  return { member, generation: view.generation };
}

async function spawnProc(kernel, leader = true) {
  const p = await kernel.value('exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'true'], env: [], cwd: '/' });
  if (leader) {
    await kernel.value('session', { pids: [p.pid] });
    return p;
  }
  const child = await kernel.value('fork', { pid: p.pid });
  return { ...child, ppid: p.pid, parent: p };
}

async function endProc(kernel, p) {
  if (!p) return;
  await kernel.call('exit', { pid: p.pid, status: 0 });
  if (p.ppid != null) {
    await kernel.call('waitchild', { ppid: p.ppid, pid: p.pid });
    if (p.parent) await endProc(kernel, p.parent);
  } else {
    await kernel.call('wait', { pid: p.pid });
  }
}

async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'login-services-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}

test('managed attachment needs both private proofs, a leader and a free slot; stale targets cannot be signalled', async ({ page }) => {
  const kernel = await freshKernel(page);
  const other = await connectKernel(page, { name: '__loginSvcStranger' });
  const own = await owner(kernel), one = await spawnProc(kernel), two = await spawnProc(kernel), plain = await spawnProc(kernel, false);
  const foreign = await spawnProc(other);
  try {
    // Process owned by another kernel host cannot be attached here.
    await invoke(kernel, { op: 'attach', ...own, process: { pid: foreign.pid + 999, proc: identity().proof } }, 'ESRCH');
    await invoke(kernel, { op: 'attach', ...own, member: { ...own.member, proof: identity().proof }, process: proof(one) }, 'EACCES');
    await invoke(kernel, { op: 'attach', ...own, process: proof(plain) }, 'EPERM');
    const attached = await invoke(kernel, { op: 'attach', ...own, process: proof(one) });
    expect(attached.managed.pid).toBe(one.pid);
    expect(JSON.stringify(attached)).not.toContain(own.member.proof);
    await invoke(kernel, { op: 'attach', ...own, process: proof(one) });
    await invoke(kernel, { op: 'attach', ...own, process: proof(two) }, 'EBUSY');
    await invoke(kernel, { op: 'signal', ...own, pid: two.pid, signal: 15 }, 'ESTALE');
    await invoke(kernel, { op: 'signal', ...own, pid: one.pid, signal: 32 }, 'EINVAL');
    await endProc(kernel, one);
    expect((await invoke(kernel, { op: 'inspect' })).managed).toBe(null);
    await invoke(kernel, { op: 'attach', ...own, process: proof(two) });
    await invoke(kernel, { op: 'signal', ...own, pid: one.pid, signal: 15 }, 'ESTALE');
  } finally {
    await endProc(kernel, one);
    await endProc(kernel, two);
    await endProc(kernel, plain);
    await endProc(other, foreign);
    await other.terminate();
    await kernel.terminate();
  }
});

test('takeover retains a live managed PID and fences the previous coordinator', async ({ page }) => {
  const kernel = await freshKernel(page);
  const own = await owner(kernel), p = await spawnProc(kernel), other = identity();
  try {
    await invoke(kernel, { op: 'attach', ...own, process: proof(p) });
    const joined = await invoke(kernel, { op: 'join', ...other });
    const member = { session: joined.id, ...other };
    await invoke(kernel, { op: 'signal', member, generation: own.generation, pid: p.pid, signal: 15 }, 'ESTALE');
    await invoke(kernel, { op: 'leave', member: own.member });
    const next = await invoke(kernel, { op: 'claim', member, generation: own.generation });
    expect(next.managed.pid).toBe(p.pid);
    expect(next.managed.generation).toBe(own.generation);
    await invoke(kernel, { op: 'join', host: own.member.host, proof: own.member.proof });
    await invoke(kernel, { op: 'signal', ...own, pid: p.pid, signal: 15 }, 'ESTALE');
    await invoke(kernel, { op: 'signal', member, generation: next.generation, pid: p.pid, signal: 15 });
  } finally {
    await endProc(kernel, p);
    await kernel.terminate();
  }
});

test('login credentials remain authoritative even when a guest knows a root process proof', async ({ page, request, browser }) => {
  await call(request, 'getcreds');
  const kernel = await freshKernel(page);
  await kernel.value('sync_account', ROOT_ACCOUNT);
  const root = await spawnProc(kernel);
  await kernel.value('sync_account', GUEST_ACCOUNT);
  const guest = await owner(kernel);
  try {
    // Guest login session rejects attaching a root process belonging to a different login scope.
    await invoke(kernel, { op: 'attach', ...guest, process: proof(root) }, 'EPERM');
    // Retired server /api/sys login_session route (with sudo or process credentials) fails closed.
    for (const options of [{ sudo: true }, { pid: root.pid, proc: root.token || identity().proof }]) {
      const res = await request.post(origin + '/api/sys', {
        headers: { Origin: origin, 'Content-Type': 'application/json' },
        data: { calls: [{ login_session: { action: { op: 'attach', ...guest, process: proof(root) } } }], ...options },
      });
      expect(res.ok()).toBe(false);
    }
    const context = await browser.newContext();
    try {
      const otherPage = await context.newPage();
      const otherKernel = await freshKernel(otherPage, '__loginSvcOtherCtx');
      try {
        const other = await owner(otherKernel);
        await invoke(otherKernel, { op: 'attach', ...other, process: proof(root) }, 'ESRCH');
      } finally {
        await otherKernel.terminate();
      }
    } finally {
      await context.close();
    }
  } finally {
    await kernel.value('sync_account', ROOT_ACCOUNT);
    await endProc(kernel, root);
    await kernel.terminate();
  }
});

const state = page => page.evaluate(() => window.os.loginSession());
async function ready(page) {
  const pageKernel = await hookPageKernel(page);
  await page.goto('/');
  await pageKernel.ready();
  await expect.poll(async () => (await state(page))?.connected, { timeout: 20_000 }).toBe(true);
  return pageKernel;
}
async function units(page, script) {
  const base = '/tmp/login-services-' + randomUUID();
  await pageMkdirp(page, base, 0o700);
  const file = base + '/units.json';
  await pagePut(
    page,
    file,
    JSON.stringify({ version: 1, units: [{ name: 'managed', argv: ['sh', '-c', script] }] }),
    { mode: 0o644 },
  );
  return { base, file };
}
async function start(page, file, key = 'managed') {
  await page.evaluate(({ file, key }) => {
    const run = window[key] = { output: '' };
    run.done = window.os.startLoginServices(file, {
      tty: true,
      onOutput: (fd, text) => { run.output += text; },
      onJob: group => { run.group = group; },
    }).then(result => { run.result = result; }, error => { run.error = { errno: error.errno, message: error.message }; });
  }, { file, key });
}
async function output(page, expected) {
  await page.waitForFunction(expected => window.managed.output.includes(expected) || window.managed.error || window.managed.result, expected, { timeout: 60_000 });
  const value = await page.evaluate(() => ({ output: window.managed.output, error: window.managed.error }));
  expect(value.error, JSON.stringify(value)).toBeUndefined();
  expect(value.output).toContain(expected);
}
async function done(page, status = 143, key = 'managed') {
  await expect.poll(() => page.evaluate(key => !!window[key].result || !!window[key].error, key), { timeout: 60_000 }).toBe(true);
  const result = await page.evaluate(key => ({ result: window[key].result, error: window[key].error, output: window[key].output }), key);
  expect(result.error, JSON.stringify(result)).toBeUndefined();
  expect(result.result.status, result.output).toBe(status);
}
async function cleanup(page, base) {
  await page.evaluate(async () => {
    for (const key of ['managed', 'duplicate']) {
      window[key]?.group?.signal(9);
      await window[key]?.done;
    }
  }).catch(() => {});
  await pageRmrf(page, base).catch(() => {});
}
const script = 'trap "echo CLEANED; exit 0" TERM; echo READY; while :; do sleep 0.1; done';

test('the login owner runs the ordinary supervisor and releases its slot after graceful shutdown', async ({ page }) => {
  await ready(page);
  const { file, base } = await units(page, script);
  try {
    await start(page, file);
    await output(page, 'READY');
    await expect.poll(async () => (await state(page)).session.managed?.pid).toBeGreaterThan(1);
    const before = (await state(page)).session;
    await page.evaluate(before => window.os.signalLoginServices(before), before);
    await done(page);
    await output(page, 'CLEANED');
    await expect.poll(async () => (await state(page)).session.managed, { timeout: 10_000 }).toBe(null);
    await start(page, file);
    await output(page, 'READY');
    await expect.poll(async () => (await state(page)).session.managed?.pid).toBeGreaterThan(before.managed.pid);
    const next = (await state(page)).session;
    expect(await page.evaluate(async old => { try { await window.os.signalLoginServices(old); } catch (e) { return e.errno; } }, before)).toBe('ESTALE');
    await page.evaluate(next => window.os.signalLoginServices(next), next);
    await done(page);
  } finally {
    await cleanup(page, base);
  }
});

test('a concurrent managed launch is rejected before its units execute', async ({ page }) => {
  await ready(page);
  const { file, base } = await units(page, script);
  try {
    await start(page, file);
    await output(page, 'READY');
    await start(page, file, 'duplicate');
    await expect.poll(() => page.evaluate(() => window.duplicate.error?.errno)).toBe('EBUSY');
    expect(await page.evaluate(() => window.duplicate.output)).toBe('');
    const view = (await state(page)).session;
    await page.evaluate(view => window.os.signalLoginServices(view), view);
    await done(page);
  } finally {
    await cleanup(page, base);
  }
});

test('a new coordinator can stop the original host supervisor without launching a duplicate', async ({ page, context }) => {
  const pageKernel = await ready(page);
  const { file, base } = await units(page, script);
  const other = await context.newPage();
  try {
    await start(page, file);
    await output(page, 'READY');
    const before = (await state(page)).session;

    // Per Contract v2 §2.1, another tab runs its own isolated instance and cannot signal this instance's slot.
    await ready(other);
    expect((await state(other)).session.id).not.toBe(before.id);
    expect(await other.evaluate(async old => { try { await window.os.signalLoginServices(old); } catch (e) { return e.errno; } }, before)).toBe('ESTALE');

    // Join a successor coordinator host inside this instance's login session.
    const successor = identity();
    const joined = await invoke(pageKernel, { op: 'join', ...successor });
    const member = { session: joined.id, ...successor };
    await invoke(pageKernel, { op: 'signal', member, generation: before.generation, pid: before.managed.pid, signal: 15 }, 'ESTALE');

    // Original coordinator departs; successor claims ownership, retains managed PID, blocks duplicate attach, and stops cleanly.
    await pageKernel.value('login_leave');
    await expect.poll(async () => (await state(page)).coordinator).toBe(false);
    const next = await invoke(pageKernel, { op: 'claim', member, generation: before.generation });
    expect(next.managed.pid).toBe(before.managed.pid);
    expect(next.generation).toBeGreaterThan(before.generation);

    const dup = await spawnProc(pageKernel);
    try {
      await invoke(pageKernel, { op: 'attach', member, generation: next.generation, process: proof(dup) }, 'EBUSY');
    } finally {
      await endProc(pageKernel, dup);
    }

    await invoke(pageKernel, { op: 'signal', member, generation: next.generation, pid: next.managed.pid, signal: 15 });
    await done(page);
    await output(page, 'CLEANED');
  } finally {
    await cleanup(page, base);
    await other.close();
  }
});

test('login replacement leaves running credentials intact and cannot control the previous login slot', async ({ page }) => {
  await ready(page);
  const { file, base } = await units(page, script);
  try {
    await start(page, file);
    await output(page, 'READY');
    const before = (await state(page)).session;
    await switchLocalUser(page, 'root');
    await expect.poll(async () => (await state(page)).session?.uid).toBe(0);
    const after = (await state(page)).session;
    expect(after.id).not.toBe(before.id);
    expect(after.managed).toBe(null);
    expect(await page.evaluate(async old => { try { await window.os.signalLoginServices(old); } catch (e) { return e.errno; } }, before)).toBe('ESTALE');
    // The original run's explicit process handle retains its original credentials.
    await page.evaluate(() => window.managed.group.signal(15));
    await done(page);
    await output(page, 'CLEANED');
  } finally {
    await cleanup(page, base);
  }
});

test('ownership lost during image loading prevents guest code from starting', async ({ page }) => {
  let release, intercepted;
  const loading = new Promise(resolve => { intercepted = resolve; });
  const hold = new Promise(resolve => { release = resolve; });
  await page.route(executableAsset('supervise'), async route => {
    intercepted();
    await hold;
    await route.continue();
  });
  await ready(page);
  const { file, base } = await units(page, 'echo MUST_NOT_START');
  try {
    await start(page, file);
    await loading;
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    await expect.poll(async () => (await state(page)).coordinator).toBe(false);
    release();
    await expect.poll(() => page.evaluate(() => window.managed.error?.errno), { timeout: 60_000 }).toBe('EACCES');
    expect(await page.evaluate(() => window.managed.output)).not.toContain('MUST_NOT_START');
  } finally {
    release();
    await cleanup(page, base);
  }
});

test('one process cannot be registered under two logins of the same account', async ({ page }) => {
  const kernel = await freshKernel(page);
  await kernel.value('sync_account', ROOT_ACCOUNT);
  const first = await owner(kernel), p = await spawnProc(kernel);
  try {
    await invoke(kernel, { op: 'attach', ...first, process: proof(p) });
    // Replace the login session (logout + login as root) -> fresh login scope ID.
    await kernel.value('sync_account', GUEST_ACCOUNT);
    await kernel.value('sync_account', ROOT_ACCOUNT);
    const second = await owner(kernel);
    expect(second.member.session).not.toBe(first.member.session);
    const denied = await kernel.call('login_session_action', {
      action: { op: 'attach', ...second, process: proof(p) },
    });
    expect(['EPERM', 'EBUSY']).toContain(denied.err?.errno);
  } finally {
    await endProc(kernel, p);
    await kernel.terminate();
  }
});

test('graceful managed shutdown resumes a stopped supervisor', async ({ page }) => {
  const pageKernel = await ready(page);
  const { file, base } = await units(page, script);
  try {
    await start(page, file);
    await output(page, 'READY');
    const before = (await state(page)).session;
    await pageKernel.value('kill', { pid: before.managed.pid, signal: 19 });
    const [row] = await pageKernel.value('poll', { pids: [before.managed.pid] });
    expect(row.state).toBe('stopped');
    await page.evaluate(before => window.os.signalLoginServices(before), before);
    await done(page);
    await output(page, 'CLEANED');
  } finally {
    await cleanup(page, base);
  }
});
