import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call, put, rmrf } from './sys.js';

const prompt = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const screen = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const SET = 0x540e, DROP = 0x5422, SID = 0x5429;
const assert = expression => `(call $assert ${expression})`;
const eq = (expression, n) => assert(`(i32.eq ${expression} (i32.const ${n}))`);
const ignoreHup = '(drop (call $action (i32.const 1) (i32.const 1) (i32.const 0) (i32.const 0)))';
const noTerminal = `${eq('(call $foreground (i32.const 0))', -59)}
  ${eq('(call $open (i32.const 3) (i32.const 1) (i32.const 160) (i32.const 8) (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 32))', 60)}`;
const fork = eq('(call $fork (i32.const 1) (i32.const 48))', 0);
const wait = `(i32.store8 (i32.const 52) (i32.const 1)) (i32.store (i32.const 56) (i32.load (i32.const 48)))
  ${eq('(call $join (i32.const 52) (i32.const 0) (i32.const 64))', 0)}
  ${eq('(i32.load8_u (i32.const 64))', 1)} ${eq('(i32.load16_u (i32.const 66))', 0)}`;
let base;

async function send(page, text) { await page.locator('#command').fill(text); await page.locator('#command').press('Enter'); }
async function run(page, text) {
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle'); await send(page, text);
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}
const results = async page => (await screen(page).textContent()).split('\n').filter(s => s.startsWith('{')).map(s => JSON.parse(s).results[0]);
test.beforeEach(async ({ page }) => {
  await page.goto('/'); base = '/guest/ctty-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o755 } });
});
test.afterEach(async ({ page }) => { await rmrf(page.request, base); });

// Ordinary programs exercise the local descriptor/ABI boundary; the test cannot edit
// host terminal state or process tokens. Assertions trap on unexpected WASI results.
async function upload(page, name, build) {
  const segments = []; let at = 8192;
  const text = value => {
    const data = Buffer.from(value), ptr = at; at += data.length + 1;
    segments.push(`(data (i32.const ${ptr}) "${[...data].map(n => '\\' + n.toString(16).padStart(2, '0')).join('')}")`);
    return `(i32.const ${ptr}) (i32.const ${data.length})`;
  };
  const q = (request, fd = 0, arg = 0) => `(call $json ${text(JSON.stringify([{ ioctl: { fd, request, arg } }]))})`;
  const say = value => `(call $say ${text(value)})`;
  const body = build({ q, say, text });
  const module = binaryen.parseText(`(module
    (import "os" "sys" (func $sys (param i32 i32) (result i32)))
    (import "os" "reply" (func $reply (param i32)))
    (import "os" "sigaction" (func $action (param i32 i32 i32 i32) (result i32)))
    (import "os" "setsid" (func $setsid (result i32)))
    (import "os" "getpgid" (func $pgid (param i32) (result i32)))
    (import "os" "tcgetpgrp" (func $foreground (param i32) (result i32)))
    (import "os" "waitpid2" (func $wait (param i32 i32 i32) (result i32)))
    (import "os" "sigpending" (func $pending (result i32)))
    (import "os" "sigmask" (func $mask (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $fdstat (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (import "wasix_32v1" "fd_renumber" (func $dup2 (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
    ${body.includes('$fork') ? '(import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32))) (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))' : ''}
    ${body.includes('$exec') ? '(import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))' : ''}
    (memory (export "memory") 2)
    (global $__stack_pointer (export "__stack_pointer") (mut i32) (i32.const 60000))
    (data (i32.const 160) "/dev/tty") (data (i32.const 180) "\\0a")
    ${segments.join('\n')}
    (func $assert (param i32) (if (i32.eqz (local.get 0)) (then unreachable)))
    (func $say (param $ptr i32) (param $len i32)
      (i32.store (i32.const 0) (local.get $ptr)) (i32.store (i32.const 4) (local.get $len))
      ${eq('(call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))', 0)})
    (func $sayerr (param $ptr i32) (param $len i32)
      (i32.store (i32.const 0) (local.get $ptr)) (i32.store (i32.const 4) (local.get $len))
      ${eq('(call $write (i32.const 2) (i32.const 0) (i32.const 1) (i32.const 8))', 0)})
    (func $json (param $ptr i32) (param $len i32) (local $size i32)
      (local.set $size (call $sys (local.get $ptr) (local.get $len)))
      (call $reply (i32.const 4096)) (call $say (i32.const 4096) (local.get $size))
      (call $say (i32.const 180) (i32.const 1)))
    (func (export "_start") ${body}))`);
  const path = base + '/' + name;
  try { expect((await put(page.request, '/api/file?path=' + path, { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true); }
  finally { module.dispose(); }
  await call(page.request, { chmod: { path, mode: 0o755 } }); return path;
}

test('a leader detaches and reacquires its terminal, with descriptor access modes enforced', async ({ page }) => {
  const path = await upload(page, 'leader', ({ q, say }) => `${ignoreHup}
    ${q(SID)} ${q(SET)}
    ${eq('(call $open (i32.const 3) (i32.const 1) (i32.const 160) (i32.const 8) (i32.const 0) (i64.const 64) (i64.const 0) (i32.const 0) (i32.const 32))', 0)}
    ${eq('(call $dup2 (i32.load (i32.const 32)) (i32.const 0))', 0)}
    ${eq('(call $fdstat (i32.const 0) (i32.const 96))', 0)}
    ${assert('(i64.eqz (i64.and (i64.load (i32.const 104)) (i64.const 2)))')}
    ${q(DROP)} ${noTerminal} ${q(SID)} ${q(DROP)} ${q(SET)}
    (i32.store (i32.const 4) (i32.const 0))
    ${eq('(call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))', 8)}
    ${eq('(call $dup2 (i32.const 1) (i32.const 0))', 0)}
    ${q(SET)} ${q(SID)}
    ${assert('(i32.eq (call $foreground (i32.const 0)) (call $pgid (i32.const 0)))')}
    ${eq('(call $open (i32.const 3) (i32.const 1) (i32.const 160) (i32.const 8) (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 32))', 0)}
    ${eq('(call $dup2 (i32.load (i32.const 32)) (i32.const 0))', 0)}
    ${eq('(call $fdstat (i32.const 0) (i32.const 96))', 0)}
    ${assert('(i64.eqz (i64.and (i64.load (i32.const 104)) (i64.const 64)))')}
    (i32.store (i32.const 4) (i32.const 0))
    ${eq('(call $write (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))', 8)}
    ${eq('(call $close (i32.const 0))', 0)} ${q(SID)} ${say('leader-ok\n')}`);
  await run(page, path);
  const r = await results(page); expect(r).toHaveLength(9);
  expect(r[0].ok.sid).toBeGreaterThan(1); expect(r[1]).toEqual({ ok: {} }); expect(r[2]).toEqual({ ok: {} });
  expect(r.slice(3, 6).map(x => x.err.errno)).toEqual(['ENOTTY', 'ENOTTY', 'EPERM']);
  expect(r[6]).toEqual({ ok: {} }); expect(r[7]).toEqual(r[0]); expect(r[8].err.errno).toBe('EBADF');
  await expect(screen(page)).toContainText('leader-ok');
});

test('a nonleader detaches only itself and fork/exec retain that association', async ({ page }) => {
  const check = await upload(page, 'detached', ({ say }) => `${noTerminal} ${say('grandchild-detached\n')}`);
  const child = await upload(page, 'child', ({ q, say, text }) => `
    ${q(SET)} ${q(DROP)} ${noTerminal}
    ${fork} (if (i32.eqz (i32.load (i32.const 48))) (then (call $exec ${text(check)} ${text(check)})))
    ${wait} ${noTerminal} ${say('child-detached\n')}`);
  const parent = await upload(page, 'parent', ({ q, say }) => `${q(SID)} ${say('parent-attached\n')}`);
  await run(page, `sh -c '${child}; ${parent}'`);
  const r = await results(page);
  expect(r).toHaveLength(3); expect(r[0].err.errno).toBe('EPERM'); expect(r[1]).toEqual({ ok: {} }); expect(r[2].ok.sid).toBeGreaterThan(1);
  await expect(screen(page)).toContainText('grandchild-detached\nchild-detached'); await expect(screen(page)).toContainText('parent-attached');
});

test('leader detachment clears the whole session and resumes its stopped foreground child', async ({ page }) => {
  const path = await upload(page, 'detach-session', ({ q, say }) => `${ignoreHup}
    ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      (drop (call $raise (i32.const 19))) ${noTerminal} ${say('child-resumed-detached\n')} (call $exit (i32.const 0))))
    ${assert('(i32.eq (call $wait (i32.load (i32.const 48)) (i32.const 80) (i32.const 2)) (i32.load (i32.const 48)))')}
    ${eq('(i32.and (i32.load (i32.const 80)) (i32.const 255))', 127)}
    ${q(DROP)} ${noTerminal} ${wait} ${say('session-detached\n')}`);
  await run(page, path);
  await expect(screen(page)).toContainText('child-resumed-detached'); await expect(screen(page)).toContainText('session-detached');
  expect(await results(page)).toEqual([{ ok: {} }]);
});

test('an acquired terminal follows fork and is released with HUP when its leader exits', async ({ page }) => {
  const transfer = (fn, fd) => `
    (i32.store (i32.const 0) (i32.const 300)) (i32.store (i32.const 4) (i32.const 1))
    ${eq(`(call $${fn} (i32.load (i32.const ${fd})) (i32.const 0) (i32.const 1) (i32.const 8))`, 0)}
    ${eq('(i32.load (i32.const 8))', 1)}`;
  const path = await upload(page, 'leader-exit', ({ q, say }) => `${ignoreHup} ${q(DROP)}
    ${eq('(call $pipe (i32.const 32) (i32.const 36))', 0)}
    ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      ${assert('(i32.gt_s (call $setsid) (i32.const 1))')} ${q(SET)}
      ${fork}
      (if (i32.eqz (i32.load (i32.const 48))) (then
        ${assert('(i32.eq (call $foreground (i32.const 0)) (call $pgid (i32.const 0)))')}
        (drop (call $mask (i32.const 0) (i32.const 1)))
        (drop (call $action (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0)))
        (i32.store8 (i32.const 300) (i32.const 1)) ${transfer('write', 36)}
        (loop $pending (br_if $pending (i32.eqz (i32.and (call $pending) (i32.const 1)))))
        ${noTerminal} ${transfer('write', 36)} (call $exit (i32.const 0))))
      ${transfer('read', 32)} (call $exit (i32.const 0))))
    ${wait} ${transfer('read', 32)} ${eq('(i32.load8_u (i32.const 300))', 1)}
    ${noTerminal} ${say('leader-exit-ok\n')}`);
  await run(page, path);
  expect(await results(page)).toEqual([{ ok: {} }, { ok: {} }]);
  await expect(screen(page)).toContainText('leader-exit-ok');
  await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).filter(p => p.path === path)).toHaveLength(0);
});

for (const privileged of [false, true]) test(`terminal stealing uses process credentials after browser ${privileged ? 'logout' : 'root login'}`, async ({ page }) => {
  const login = async () => expect((await api(page.request, 'login', { headers: { Origin: origin, 'CF-Connecting-IP': 'ctty-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true);
  if (privileged) { await login(); await page.reload(); }
  try {
    const child = await upload(page, 'claim', ({ q, say }) => `
      ${assert('(i32.gt_s (call $setsid) (i32.const 1))')} ${noTerminal} ${q(SET)}
      ${say('claim-ready\n')}
      (i32.store (i32.const 0) (i32.const 200)) (i32.store (i32.const 4) (i32.const 1))
      ${eq('(call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))', 0)}
      ${q(SET, 0, 1)} ${privileged ? assert('(i32.eq (call $foreground (i32.const 0)) (call $pgid (i32.const 0)))') : noTerminal}
      ${say('claim-complete\n')}`);
    const parent = await upload(page, 'check-parent', ({ q, say }) => `${q(SID)} ${say('parent-complete\n')}`);
    await send(page, `sh -c 'USER=root UID=0; export USER UID; ${child}; ${parent}'`);
    await expect(screen(page)).toContainText('claim-ready', { timeout: 60_000 });
    if (privileged) expect((await api(page.request, 'logout', { headers: { Origin: origin } })).ok()).toBe(true);
    else await login();
    await send(page, 'x');
    await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
    const r = await results(page); expect(r).toHaveLength(3);
    expect(r[0].err.errno).toBe('EPERM');
    if (privileged) { expect(r[1]).toEqual({ ok: {} }); expect(r[2].err.errno).toBe('ENOTTY'); }
    else { expect(r[1].err.errno).toBe('EPERM'); expect(r[2].ok.sid).toBeGreaterThan(1); }
    await expect(screen(page)).toContainText('parent-complete');
  } finally { await login(); }
});

test('terminal control refuses pipes and guessed foreign PTY paths', async ({ page }) => {
  const path = await upload(page, 'pipe', ({ q, text, say }) => `
    ${q(SET)} ${q(DROP)} ${q(SID)}
    ${eq(`(call $open (i32.const 3) (i32.const 1) ${text('/dev/pts/2147483647')} (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 32))`, 44)}
    ${say('pipe-ok\n')}`);
  await run(page, `echo input | ${path}`);
  expect((await results(page)).map(x => x.err.errno)).toEqual(['ENOTTY', 'ENOTTY', 'ENOTTY']);
  await expect(screen(page)).toContainText('pipe-ok');
});

test('a delayed pipeline stage stays detached when the leader reacquires the terminal', async ({ page }) => {
  expect((await api(page.request, 'login', { headers: { Origin: origin, 'CF-Connecting-IP': 'ctty-delay-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true);
  await page.reload();
  const producer = await upload(page, 'producer', ({ q, text }) => `${ignoreHup}
    ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      ${assert('(i32.gt_s (call $setsid) (i32.const 1))')} ${q(SET, 0, 1)} ${q(DROP)} (call $exit (i32.const 0))))
    ${wait} ${q(SET)}
    (call $sayerr ${text('producer-ready\n')})
    (i32.store (i32.const 0) (i32.const 200)) (i32.store (i32.const 4) (i32.const 1))
    ${eq('(call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))', 0)}`);
  const consumer = await upload(page, 'consumer', ({ say }) => `
    (if (i32.const 0) (then ${fork}))
    ${eq('(call $foreground (i32.const 2))', -59)} ${noTerminal} ${say('delayed-detached\n')}`);
  let release, blocked = false;
  const released = new Promise(resolve => { release = resolve; });
  await page.route('**/api/file?**', async route => {
    if (!new URL(route.request().url()).searchParams.has('compile')) return route.continue();
    // Delay only the consumer's real compiler response; the producer forks too.
    const response = await route.fetch(), data = await response.body();
    if (data.includes(Buffer.from('delayed-detached'))) { blocked = true; await released; }
    await route.fulfill({ response, body: data }).catch(() => {});
  });
  try {
    await send(page, `${producer} | ${consumer}`);
    await expect(screen(page)).toContainText('producer-ready', { timeout: 60_000 });
    await expect.poll(() => blocked, { timeout: 60_000 }).toBe(true);
    release();
    await expect(screen(page)).toContainText('delayed-detached', { timeout: 30_000 });
    await send(page, 'x');
    await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  } finally { release(); }
});

test('terminal hangup reaches a foreground stage still waiting for its image', async ({ page }) => {
  const producer = await upload(page, 'hangup', ({ q, text }) => `${ignoreHup} ${q(DROP)} ${q(SET)}
    (call $sayerr ${text('hangup-ready\n')})
    (i32.store (i32.const 0) (i32.const 200)) (i32.store (i32.const 4) (i32.const 1))
    ${eq('(call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))', 0)}`);
  const consumer = await upload(page, 'unstarted', ({ say }) => `(if (i32.const 0) (then ${fork})) ${say('unexpected-start\n')}`);
  const hangups = [];
  page.on('request', request => {
    if (!request.url().endsWith('/api/sys') || request.method() !== 'POST') return;
    for (const call of request.postDataJSON()?.calls ?? []) if (call.exit?.signal === 1) hangups.push(call.exit.pid);
  });
  let release, blocked = false; const released = new Promise(resolve => { release = resolve; });
  await page.route('**/api/file?**', async route => {
    if (!new URL(route.request().url()).searchParams.has('compile')) return route.continue();
    const response = await route.fetch(), data = await response.body();
    if (data.includes(Buffer.from('unexpected-start'))) { blocked = true; await released; }
    await route.fulfill({ response, body: data }).catch(() => {});
  });
  try {
    await send(page, `${producer} | ${consumer}`);
    await expect(screen(page)).toContainText('hangup-ready', { timeout: 60_000 });
    await expect.poll(() => blocked, { timeout: 60_000 }).toBe(true); release();
    await expect.poll(() => hangups.length, { timeout: 30_000 }).toBe(1);
    await send(page, 'x');
    await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
    await expect(screen(page)).not.toContainText('unexpected-start');
  } finally { release(); }
});

test('a fast producer cannot hang up a pipeline consumer still loading its image', async ({ page }) => {
  const producer = await upload(page, 'fast', ({ say }) => say('pipeline-data\n'));
  const consumer = await upload(page, 'late-reader', () => `
    (if (i32.const 0) (then ${fork}))
    (i32.store (i32.const 0) (i32.const 300)) (i32.store (i32.const 4) (i32.const 100))
    ${eq('(call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8))', 0)}
    (call $say (i32.const 300) (i32.load (i32.const 8)))`);
  let exited = false;
  page.on('request', request => {
    if (!request.url().endsWith('/api/sys') || request.method() !== 'POST') return;
    if (request.postDataJSON()?.calls.some(call => call.exit)) exited = true;
  });
  let release, blocked = false; const released = new Promise(resolve => { release = resolve; });
  await page.route('**/api/file?**', async route => {
    if (!new URL(route.request().url()).searchParams.has('compile')) return route.continue();
    const response = await route.fetch(), data = await response.body();
    // Only this pipeline's consumer imports proc_fork. Every ordinary image is
    // now transformed for resource accounting, including the simple producer.
    if (data.includes(Buffer.from('proc_fork'))) { blocked = true; await released; }
    await route.fulfill({ response, body: data }).catch(() => {});
  });
  try {
    await send(page, `${producer} | ${consumer}`);
    await expect.poll(() => exited, { timeout: 60_000 }).toBe(true);
    await expect.poll(() => blocked, { timeout: 60_000 }).toBe(true); release();
    await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
    await expect(screen(page)).toHaveText('pipeline-data');
  } finally { release(); }
});
