import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { api, call, errno, put, rmrf, sys } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const registry = { 'X-Registry': '1' };
const identity = () => ({ host: randomUUID(), proof: randomBytes(32).toString('hex') });
const proof = p => ({ pid: p.pid, proc: p.token });
async function invoke(request, action, expected, options = {}) {
  const [result] = await sys(request, [{ login_session: { action } }], options, registry);
  if (expected) { expect(result.err?.errno, JSON.stringify(result)).toBe(expected); return; }
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}
async function owner(request) {
  await call(request, 'getcreds');
  const host = identity(), session = await invoke(request, { op: 'join', ...host });
  const member = { session: session.id, ...host };
  const view = await invoke(request, { op: 'claim', member, generation: session.generation });
  return { member, generation: view.generation };
}
async function process(request, session = true) {
  const p = await call(request, { execve: { path: '/usr/bin/coreutils', argv: ['coreutils', 'true'], env: [], cwd: '/' } });
  if (session) {
    const [result] = await sys(request, [{ proc_session: { processes: [proof(p)] } }], {}, registry);
    expect(result.err).toBeUndefined();
  }
  return p;
}
async function end(request, p) {
  await sys(request, [{ exit: { ...proof(p), status: 0 } }, { wait: { pid: String(p.pid), proc: p.token } }], {}, registry);
}
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'login-services-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}

test('managed attachment needs both private proofs, a leader and a free slot; stale targets cannot be signalled', async ({ request }) => {
  const own = await owner(request), one = await process(request), two = await process(request), plain = await process(request, false);
  try {
    await invoke(request, { op: 'attach', ...own, process: { ...proof(one), proc: identity().proof } }, 'EPERM');
    await invoke(request, { op: 'attach', ...own, member: { ...own.member, proof: identity().proof }, process: proof(one) }, 'EACCES');
    await invoke(request, { op: 'attach', ...own, process: proof(plain) }, 'EPERM');
    const attached = await invoke(request, { op: 'attach', ...own, process: proof(one) });
    expect(attached.managed.pid).toBe(one.pid);
    expect(JSON.stringify(attached)).not.toContain(one.token); expect(JSON.stringify(attached)).not.toContain(own.member.proof);
    await invoke(request, { op: 'attach', ...own, process: proof(one) });
    await invoke(request, { op: 'attach', ...own, process: proof(two) }, 'EBUSY');
    await invoke(request, { op: 'signal', ...own, pid: two.pid, signal: 15 }, 'ESTALE');
    await invoke(request, { op: 'signal', ...own, pid: one.pid, signal: 32 }, 'EINVAL');
    await end(request, one);
    expect((await invoke(request, { op: 'inspect' })).managed).toBe(null);
    await invoke(request, { op: 'attach', ...own, process: proof(two) });
    await invoke(request, { op: 'signal', ...own, pid: one.pid, signal: 15 }, 'ESTALE');
  } finally { await end(request, one); await end(request, two); await end(request, plain); }
});

test('takeover retains a live managed PID and fences the previous coordinator', async ({ request }) => {
  const own = await owner(request), p = await process(request), other = identity();
  try {
    await invoke(request, { op: 'attach', ...own, process: proof(p) });
    const joined = await invoke(request, { op: 'join', ...other });
    const member = { session: joined.id, ...other };
    await invoke(request, { op: 'signal', member, generation: own.generation, pid: p.pid, signal: 15 }, 'ESTALE');
    await invoke(request, { op: 'leave', member: own.member });
    const next = await invoke(request, { op: 'claim', member, generation: own.generation });
    expect(next.managed.pid).toBe(p.pid); expect(next.managed.generation).toBe(own.generation);
    await invoke(request, { op: 'join', host: own.member.host, proof: own.member.proof });
    await invoke(request, { op: 'signal', ...own, pid: p.pid, signal: 15 }, 'ESTALE');
    await invoke(request, { op: 'signal', member, generation: next.generation, pid: p.pid, signal: 15 });
  } finally { await end(request, p); }
});

test('login credentials remain authoritative even when a guest knows a root process proof', async ({ request, browser }) => {
  await call(request, 'getcreds'); await signIn(request);
  const root = await process(request);
  await api(request, 'logout'); const guest = await owner(request);
  try {
    await invoke(request, { op: 'attach', ...guest, process: proof(root) }, 'EPERM');
    await invoke(request, { op: 'attach', ...guest, process: proof(root) }, 'EPERM', { sudo: true });
    await invoke(request, { op: 'attach', ...guest, process: proof(root) }, 'EPERM', { pid: root.pid, proc: root.token });
    const context = await browser.newContext();
    try {
      const other = await owner(context.request);
      await invoke(context.request, { op: 'attach', ...other, process: proof(root) }, 'EPERM');
    } finally { await context.close(); }
  } finally { await end(request, root); }
});

const state = page => page.evaluate(() => window.os.loginSession());
async function ready(page) {
  await page.goto('/'); await expect.poll(async () => (await state(page))?.connected).toBe(true);
}
async function units(page, script) {
  const base = '/guest/login-services-' + randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  const file = base + '/units.json';
  expect((await put(page.request, '/api/file?path=' + file, { data: JSON.stringify({ version: 1, units: [{ name: 'managed', argv: ['sh', '-c', script] }] }) })).ok()).toBe(true);
  return { base, file };
}
async function start(page, file, key = 'managed') {
  await page.evaluate(({ file, key }) => {
    const run = window[key] = { output: '' };
    run.done = window.os.startLoginServices(file, { tty: true, onOutput: (fd, text) => { run.output += text; }, onJob: group => { run.group = group; } })
      .then(result => { run.result = result; }, error => { run.error = { errno: error.errno, message: error.message }; });
  }, { file, key });
}
async function output(page, expected) {
  await page.waitForFunction(expected => window.managed.output.includes(expected) || window.managed.error || window.managed.result, expected, { timeout: 60_000 });
  const value = await page.evaluate(() => ({ output: window.managed.output, error: window.managed.error }));
  expect(value.error, JSON.stringify(value)).toBeUndefined(); expect(value.output).toContain(expected);
}
async function done(page, status = 143, key = 'managed') {
  await expect.poll(() => page.evaluate(key => !!window[key].result || !!window[key].error, key), { timeout: 60_000 }).toBe(true);
  const result = await page.evaluate(key => ({ result: window[key].result, error: window[key].error, output: window[key].output }), key);
  expect(result.error, JSON.stringify(result)).toBeUndefined(); expect(result.result.status, result.output).toBe(status);
}
async function cleanup(page, base) {
  await page.evaluate(async () => { for (const key of ['managed', 'duplicate']) { window[key]?.group?.signal(9); await window[key]?.done; } }).catch(() => {});
  await rmrf(page.request, base);
}
const script = 'trap "echo CLEANED; exit 0" TERM; echo READY; while :; do sleep 0.1; done';

test('the login owner runs the ordinary supervisor and releases its slot after graceful shutdown', async ({ page }) => {
  await ready(page); const { file, base } = await units(page, script);
  try {
    await start(page, file); await output(page, 'READY');
    await expect.poll(async () => (await state(page)).session.managed?.pid).toBeGreaterThan(1);
    const before = (await state(page)).session;
    await page.evaluate(before => window.os.signalLoginServices(before), before); await done(page); await output(page, 'CLEANED');
    await expect.poll(async () => (await state(page)).session.managed, { timeout: 10_000 }).toBe(null);
    await start(page, file); await output(page, 'READY');
    await expect.poll(async () => (await state(page)).session.managed?.pid).toBeGreaterThan(before.managed.pid);
    const next = (await state(page)).session;
    expect(await page.evaluate(async old => { try { await window.os.signalLoginServices(old); } catch (e) { return e.errno; } }, before)).toBe('ESTALE');
    await page.evaluate(next => window.os.signalLoginServices(next), next); await done(page);
  } finally { await cleanup(page, base); }
});

test('a concurrent managed launch is rejected before its units execute', async ({ page }) => {
  await ready(page); const { file, base } = await units(page, script);
  try {
    await start(page, file); await output(page, 'READY');
    await start(page, file, 'duplicate');
    await expect.poll(() => page.evaluate(() => window.duplicate.error?.errno)).toBe('EBUSY');
    expect(await page.evaluate(() => window.duplicate.output)).toBe('');
    const view = (await state(page)).session;
    await page.evaluate(view => window.os.signalLoginServices(view), view); await done(page);
  } finally { await cleanup(page, base); }
});

test('a new coordinator can stop the original host supervisor without launching a duplicate', async ({ page, context }) => {
  await ready(page); const { file, base } = await units(page, script);
  const other = await context.newPage();
  try {
    await start(page, file); await output(page, 'READY'); await ready(other);
    await start(other, file); await expect.poll(() => other.evaluate(() => window.managed.error?.errno)).toBe('EACCES');
    const before = (await state(page)).session;
    // Use the same public kernel-port departure operation as pagehide, keeping the
    // execution host alive to exercise remote control after coordinator takeover.
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    await expect.poll(async () => (await state(other)).coordinator, { timeout: 40_000 }).toBe(true);
    const next = (await state(other)).session;
    expect(next.managed.pid).toBe(before.managed.pid); expect(next.generation).toBeGreaterThan(before.generation);
    await start(other, file); await expect.poll(() => other.evaluate(() => window.managed.error?.errno)).toBe('EBUSY');
    await other.evaluate(next => window.os.signalLoginServices(next), next); await done(page); await output(page, 'CLEANED');
  } finally { await cleanup(page, base); await other.close(); }
});

test('login replacement leaves running credentials intact and cannot control the previous login slot', async ({ page }) => {
  await ready(page); const { file, base } = await units(page, script);
  try {
    await start(page, file); await output(page, 'READY');
    const before = (await state(page)).session;
    await signIn(page.request); await page.evaluate(() => window.dispatchEvent(new Event('os:login-changed')));
    await expect.poll(async () => (await state(page)).session?.uid).toBe(0);
    const after = (await state(page)).session; expect(after.id).not.toBe(before.id); expect(after.managed).toBe(null);
    expect(await page.evaluate(async old => { try { await window.os.signalLoginServices(old); } catch (e) { return e.errno; } }, before)).toBe('ESTALE');
    // The original run's explicit process handle retains its original credentials.
    await page.evaluate(() => window.managed.group.signal(15)); await done(page); await output(page, 'CLEANED');
  } finally { await cleanup(page, base); }
});

test('ownership lost during image loading prevents guest code from starting', async ({ page }) => {
  let release, intercepted;
  const loading = new Promise(resolve => { intercepted = resolve; });
  const hold = new Promise(resolve => { release = resolve; });
  await page.route(executableAsset('supervise'), async route => { intercepted(); await hold; await route.continue(); });
  await ready(page); const { file, base } = await units(page, 'echo MUST_NOT_START');
  try {
    await start(page, file); await loading;
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide')));
    await expect.poll(async () => (await state(page)).coordinator).toBe(false);
    release();
    await expect.poll(() => page.evaluate(() => window.managed.error?.errno), { timeout: 60_000 }).toBe('EACCES');
    expect(await page.evaluate(() => window.managed.output)).not.toContain('MUST_NOT_START');
  } finally { release(); await cleanup(page, base); }
});

test('one process cannot be registered under two logins of the same account', async ({ request }) => {
  await call(request, 'getcreds'); await signIn(request);
  const first = await owner(request), p = await process(request);
  try {
    await invoke(request, { op: 'attach', ...first, process: proof(p) });
    await signIn(request); const second = await owner(request);
    expect(second.member.session).not.toBe(first.member.session);
    await invoke(request, { op: 'attach', ...second, process: proof(p) }, 'EBUSY');
  } finally { await end(request, p); }
});

test('graceful managed shutdown resumes a stopped supervisor', async ({ page }) => {
  await ready(page); const { file, base } = await units(page, script);
  try {
    await start(page, file); await output(page, 'READY');
    const before = (await state(page)).session;
    await call(page.request, { kill: { pid: String(before.managed.pid), signal: 19 } });
    const [row] = await call(page.request, { proc_poll: { pids: [before.managed.pid] } });
    expect(row.state).toBe('stopped');
    await page.evaluate(before => window.os.signalLoginServices(before), before);
    await done(page); await output(page, 'CLEANED');
  } finally { await cleanup(page, base); }
});
