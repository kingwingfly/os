import { executableAsset } from './executable-asset.js';
import { test, expect } from './test.js';
import { api, call, put, rmrf, sys } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const registry = { 'X-Registry': '1' };
const secret = () => randomBytes(32).toString('hex');
async function invoke(request, action, errno, options = {}) {
  const [result] = await sys(request, [{ login_session: { action } }], options, registry);
  if (errno) { expect(result.err?.errno, JSON.stringify(result)).toBe(errno); return; }
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}
async function owner(request) {
  await call(request, 'getcreds');
  const host = { host: randomUUID(), proof: secret() };
  const joined = await invoke(request, { op: 'join', ...host });
  const member = { session: joined.id, ...host };
  const claimed = await invoke(request, { op: 'claim', member, generation: joined.generation });
  return { member, generation: claimed.generation };
}
async function configure(request, own, file = '/guest/units.json') {
  return invoke(request, { op: 'configure', ...own, file });
}
async function begin(request, own, startup) {
  const launch = { revision: startup.revision, proof: secret() };
  await invoke(request, { op: 'begin', ...own, launch }); return launch;
}
async function process(request) {
  const p = await call(request, { execve: { path: '/usr/bin/coreutils', argv: ['true'], env: [], cwd: '/' } });
  expect((await sys(request, [{ proc_session: { processes: [{ pid: p.pid, proc: p.token }] } }], {}, registry))[0].err).toBeUndefined();
  return p;
}
const attach = (own, launch, p) => ({ op: 'attach', ...own, launch, process: { pid: p.pid, proc: p.token } });
const finish = (own, launch, status = 0) => ({ op: 'finish', session: own.member.session, launch, status, error: null });
async function end(request, p) {
  await sys(request, [{ exit: { pid: p.pid, proc: p.token, status: 0 } }, { wait: { pid: String(p.pid), proc: p.token } }], {}, registry);
}
async function signIn(request) {
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'login-boot-' + randomUUID() }, data: { password } })).ok()).toBe(true);
}

test('automatic startup requires coordinator and process proofs and retains its completion across takeover', async ({ request }) => {
  const own = await owner(request);
  await invoke(request, { op: 'configure', ...own, file: 'relative' }, 'EINVAL');
  await invoke(request, { op: 'configure', ...own, member: { ...own.member, proof: secret() }, file: '/units' }, 'EACCES');
  await invoke(request, { op: 'configure', ...own, file: '/units' }, 'EPERM', { sudo: true });
  const selected = await configure(request, own), launch = await begin(request, own, selected.startup);
  await invoke(request, { op: 'begin', ...own, launch });
  await invoke(request, { op: 'begin', ...own, launch: { ...launch, proof: secret() } }, 'ESTALE');
  const p = await process(request);
  try {
    await invoke(request, { op: 'configure', ...own, file: '/units' }, 'EPERM', { pid: p.pid, proc: p.token });
    await invoke(request, { ...attach(own, launch, p), launch: undefined }, 'EBUSY');
    await invoke(request, attach(own, { ...launch, proof: secret() }, p), 'ESTALE');
    const attached = await invoke(request, attach(own, launch, p));
    expect(attached.startup.state).toBe('running'); expect(attached.startup.pid).toBe(p.pid);
    expect(JSON.stringify(attached)).not.toContain(launch.proof); expect(JSON.stringify(attached)).not.toContain(own.member.proof);
    await invoke(request, finish(own, { ...launch, proof: secret() }), 'ESTALE');
    await invoke(request, finish(own, launch), 'EBUSY');
    await end(request, p); await invoke(request, finish(own, launch)); await invoke(request, finish(own, launch));
    await invoke(request, finish(own, launch, 1), 'ESTALE');
    await invoke(request, { op: 'leave', member: own.member }); const next = await owner(request);
    const seen = await invoke(request, { op: 'inspect' }); expect(seen.startup.status).toBe(0); expect(seen.startup.state).toBe('finished');
    await invoke(request, { op: 'begin', ...next, launch: { revision: launch.revision, proof: secret() } }, 'EBUSY');
  } finally { await end(request, p); }
});

test('account configuration follows fresh logins and disabling removes future automatic startup', async ({ request }) => {
  await call(request, 'getcreds'); await signIn(request);
  const root = await owner(request), configured = await configure(request, root, '/root/units.json');
  await api(request, 'logout'); await owner(request);
  expect((await invoke(request, { op: 'inspect' })).startup).toBe(null);
  await signIn(request); const next = await owner(request), seen = await invoke(request, { op: 'inspect' });
  expect(next.member.session).not.toBe(root.member.session); expect(seen.startup.revision).toBe(configured.startup.revision);
  expect(seen.startup.state).toBe('pending');
  await configure(request, next, null);
  await api(request, 'logout'); await signIn(request); await owner(request);
  expect((await invoke(request, { op: 'inspect' })).startup).toBe(null);
});

test('a previous login may report only its ended startup and cannot configure the replacement', async ({ request }) => {
  const own = await owner(request), selected = await configure(request, own), launch = await begin(request, own, selected.startup);
  const p = await process(request); await invoke(request, attach(own, launch, p));
  await signIn(request); const root = await owner(request);
  await invoke(request, { op: 'configure', ...own, file: '/root/units.json' }, 'ESTALE');
  expect(await invoke(request, { op: 'inspect' })).toMatchObject({ uid: 0, startup: null });
  await invoke(request, finish(own, launch), 'EPERM', { pid: p.pid, proc: p.token });
  await invoke(request, finish(own, launch), 'EBUSY'); await end(request, p);
  expect(await invoke(request, finish(own, launch))).toBe(null);
  expect((await invoke(request, { op: 'inspect' })).id).toBe(root.member.session);
  expect((await invoke(request, { op: 'inspect' })).startup).toBe(null);
});

test('pre-execution host loss fences old attempts and stops automatic admission after three losses', async ({ request }) => {
  let own = await owner(request); const selected = await configure(request, own);
  const p = await process(request); let previous;
  try {
    for (let n = 1; n <= 3; n++) {
      const launch = await begin(request, own, selected.startup);
      if (previous) await invoke(request, attach(own, previous, p), 'ESTALE');
      await invoke(request, { op: 'leave', member: own.member }); previous = launch; own = await owner(request);
    }
    const seen = await invoke(request, { op: 'inspect' });
    expect(seen.startup.state).toBe('finished'); expect(seen.startup.attempts).toBe(3);
    await invoke(request, { op: 'begin', ...own, launch: { revision: selected.startup.revision, proof: secret() } }, 'EBUSY');
  } finally { await end(request, p); }
});

test('disabling invalidates an unstarted attempt and does not signal an already running service', async ({ request }) => {
  const own = await owner(request); let selected = await configure(request, own), launch = await begin(request, own, selected.startup);
  const p = await process(request);
  try {
    await configure(request, own, null); await invoke(request, attach(own, launch, p), 'ESTALE');
    selected = await configure(request, own); launch = await begin(request, own, selected.startup);
    await invoke(request, attach(own, launch, p));
    await invoke(request, { op: 'configure', ...own, file: '/replacement.json' }, 'EBUSY');
    const disabled = await configure(request, own, null);
    expect(disabled.startup.enabled).toBe(false); expect(disabled.startup.state).toBe('running');
    const [live] = await sys(request, [{ proc_keep: { processes: [{ pid: p.pid, proc: p.token }] } }], {}, registry);
    expect(live.ok[0].state).toBe('running'); expect(live.ok[0].pending_signals ?? []).toEqual([]);
    await end(request, p); await invoke(request, finish(own, launch));
  } finally { await end(request, p); }
});

const state = page => page.evaluate(() => window.os.loginSession());
async function ready(page) {
  await page.goto('/'); await expect.poll(async () => (await state(page))?.coordinator).toBe(true);
}
async function selected(page, file) { return page.evaluate(file => window.os.configureLoginServices(file), file); }
async function completed(page, status = 0) {
  await expect.poll(async () => (await state(page)).session?.startup?.status, { timeout: 30_000 }).toBe(status);
}
async function units(page, script) {
  const base = '/guest/login-boot-' + randomUUID(); await call(page.request, { mkdir: { path: base, mode: 0o777 } });
  await call(page.request, { chmod: { path: base, mode: 0o777 } });
  const file = base + '/units.json';
  const write = async command => expect((await put(page.request, '/api/file?path=' + file + '&overwrite=true', { data: JSON.stringify({ version: 1, units: [{ name: 'login', argv: ['/usr/bin/sh', '-c', command.replaceAll('$BASE', base)] }] }) })).ok()).toBe(true);
  await write(script); return { base, file, write };
}
async function read(request, path) { return call(request, { pread: { path, offset: 0, count: 65536 } }); }
async function text(request, path) {
  const value = await read(request, path);
  return Buffer.from(value.data, 'base64').toString();
}
async function refresh(page) { await page.evaluate(() => dispatchEvent(new Event('os:login-changed'))); }
async function stop(page) {
  const current = (await state(page)).session;
  if (current?.managed) await page.evaluate(session => window.os.signalLoginServices(session), current).catch(() => {});
}

test('automatic units execute once and a follower does not rerun completed units after takeover', async ({ page, context }) => {
  await ready(page); const { base, file } = await units(page, 'echo BOOT; echo once >> $BASE/count');
  try {
    await selected(page, file); await completed(page);
    expect((await state(page)).services.output).toContain('BOOT'); expect(await text(page.request, base + '/count')).toBe('once\n');
    const before = (await state(page)).session; const other = await context.newPage(); await other.goto('/');
    await expect.poll(async () => (await state(other))?.connected).toBe(true); await page.close();
    await expect.poll(async () => (await state(other)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
    expect((await state(other)).session.id).toBe(before.id); expect((await state(other)).session.startup.status).toBe(0);
    expect(await text(other.request, base + '/count')).toBe('once\n'); await rmrf(other.request, base);
  } finally { if (!page.isClosed()) await rmrf(page.request, base); }
});

test('losing a running execution host records an ended run without repeating its units', async ({ page, context }) => {
  await ready(page); const { base, file } = await units(page, 'echo once >> $BASE/count; echo STARTED; while :; do sleep 1; done');
  const other = await context.newPage();
  try {
    await selected(page, file);
    await expect.poll(async () => (await state(page)).services.output, { timeout: 30_000 }).toContain('STARTED');
    await other.goto('/'); await expect.poll(async () => (await state(other))?.connected).toBe(true);
    await page.close();
    await expect.poll(async () => (await state(other)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
    // Host reclamation polls every ten seconds; login metadata refreshes every five.
    await expect.poll(async () => (await state(other)).session.startup.state, { timeout: 30_000, intervals: [500] }).toBe('finished');
    expect((await state(other)).session.startup.attempts).toBe(1);
    expect((await state(other)).session.managed).toBe(null);
    expect(await text(other.request, base + '/count')).toBe('once\n');
  } finally { await stop(other).catch(() => {}); await rmrf(other.request, base); }
});

test('enabled units start again on a fresh authenticated login while guest startup stays separate', async ({ page }) => {
  await ready(page); const { base, file } = await units(page, 'echo signed-in >> $BASE/count');
  try {
    await signIn(page.request); await refresh(page); await expect.poll(async () => (await state(page)).session?.uid).toBe(0);
    await selected(page, file); await completed(page); const first = (await state(page)).session;
    await api(page.request, 'logout'); await refresh(page); await expect.poll(async () => { const s = await state(page); return s.connected && s.session?.uid > 0; }).toBe(true);
    expect((await state(page)).session.startup).toBe(null); expect((await state(page)).services.output).toBe('');
    await signIn(page.request); await refresh(page); await expect.poll(async () => (await state(page)).session?.uid).toBe(0); await completed(page);
    expect((await state(page)).session.id).not.toBe(first.id); expect(await text(page.request, base + '/count')).toBe('signed-in\nsigned-in\n');
    await selected(page, null);
  } finally { await stop(page); await rmrf(page.request, base); }
});

test('confirmed logout stops automatic services gracefully and preserves an independent process', async ({ page }) => {
  await ready(page); const { base, file } = await units(page, 'trap "id -u > $BASE/stopped; exit 0" TERM; echo PRIVATE-ROOT; while :; do sleep 0.1; done');
  try {
    await signIn(page.request); await refresh(page); await expect.poll(async () => (await state(page)).session?.uid).toBe(0);
    await selected(page, file); await expect.poll(async () => (await state(page)).services.output, { timeout: 30_000 }).toContain('PRIVATE-ROOT');
    await page.evaluate(() => {
      window.independent = { output: '' };
      window.independent.done = window.os.exec([['sh', '-c', 'echo INDEPENDENT; while :; do sleep 0.1; done']], {
        stdin: '', tty: true, onOutput: (_fd, s) => { independent.output += s; }, onJob: job => { independent.job = job; },
      }).then(result => { independent.result = result; });
    });
    await expect.poll(() => page.evaluate(() => independent.output)).toContain('INDEPENDENT');
    await api(page.request, 'logout'); await refresh(page); await expect.poll(async () => { const s = await state(page); return s.connected && s.session?.uid > 0; }).toBe(true);
    expect((await state(page)).services.output).toBe('');
    await expect.poll(async () => { try { return await text(page.request, base + '/stopped'); } catch { return ''; } }, { timeout: 15_000 }).toBe('0\n');
    expect(await page.evaluate(() => independent.result)).toBeUndefined();
  } finally {
    await page.evaluate(async () => { independent?.job?.signal(9); await independent?.done; }).catch(() => {});
    await stop(page); await rmrf(page.request, base);
  }
});

test('takeover while the supervisor image loads abandons the old candidate before guest execution', async ({ page, context }) => {
  await ready(page); const { base, file } = await units(page, 'echo once >> $BASE/count');
  let release, waiting = false; const blocked = new Promise(resolve => { release = resolve; });
  await context.route(executableAsset('supervise'), async route => {
    if (!waiting) { waiting = true; await blocked; }
    await route.continue();
  });
  try {
    await selected(page, file); await expect.poll(() => waiting).toBe(true);
    const other = await context.newPage(); await other.goto('/'); await expect.poll(async () => (await state(other))?.connected).toBe(true);
    await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
    await expect.poll(async () => (await state(other)).coordinator, { timeout: 45_000, intervals: [500] }).toBe(true);
    await completed(other); release(); await other.waitForTimeout(800);
    expect((await state(other)).session.startup.attempts).toBe(2); expect(await text(other.request, base + '/count')).toBe('once\n');
    await rmrf(other.request, base);
  } finally { release(); await rmrf(page.request, base).catch(() => {}); }
});

test('manifest failure stays terminal until explicitly reconfigured, and output remains bounded', async ({ page }) => {
  await ready(page); const { base, file, write } = await units(page, 'echo bad');
  try {
    expect((await put(page.request, '/api/file?path=' + file + '&overwrite=true', { data: JSON.stringify({ version: 99, units: [] }) })).ok()).toBe(true);
    await selected(page, file); await completed(page, 1); const failed = (await state(page)).session.startup;
    await page.waitForTimeout(5500); expect((await state(page)).session.startup.attempts).toBe(1);
    await write('yes LOGIN-OUTPUT | head -n 3000'); await selected(page, file); await completed(page);
    const after = await state(page); expect(after.session.startup.revision).not.toBe(failed.revision);
    expect(after.services.output.length).toBeLessThanOrEqual(8192); expect(after.services.truncated).toBe(true);
    expect(after.services.output).toContain('LOGIN-OUTPUT');
  } finally { await stop(page); await rmrf(page.request, base); }
});
