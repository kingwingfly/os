import { test, expect } from './test.js';
import { sys, call, api, put, rmrf } from './sys.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';

const sleep = { path: '/usr/bin/sleep', argv: ['sleep', '60'], env: [], cwd: '/' };
const owned = process => ({ pid: process.pid, proc: process.token });
async function invoke(request, process, command, errno) {
  const [result] = await sys(request, [command], owned(process));
  if (errno) { expect(result.err?.errno, JSON.stringify(result)).toBe(errno); return; }
  expect(result.err, JSON.stringify(result)).toBeUndefined();
  return result.ok;
}
async function exec(request) { return call(request, { execve: sleep }); }
async function fork(request, parent) {
  return invoke(request, parent, { fork: { pid: parent.pid } });
}
async function cleanup(request, processes) {
  for (const p of processes.reverse()) {
    await sys(request, [{ kill: { pid: String(p.pid), signal: 9 } }, { wait: { pid: String(p.pid), proc: p.token } }]);
  }
}

test('session and group membership obey parent, exec and session boundaries', async ({ page }) => {
  await page.goto('/');
  const request = page.request, parent = await exec(request), processes = [parent];
  try {
    const session = await invoke(request, parent, 'setsid');
    expect([session.sid, session.pgid]).toEqual([parent.pid, parent.pid]);
    await invoke(request, parent, 'setsid', 'EPERM');
    await invoke(request, parent, { setpgid: { pid: 0, pgid: 0 } }, 'EPERM');
    const child = await fork(request, parent); processes.push(child);
    expect(await invoke(request, child, { getsid: { pid: 0 } })).toMatchObject({ sid: parent.pid, pgid: parent.pid });
    await invoke(request, parent, { setpgid: { pid: child.pid, pgid: child.pid } });
    expect(await invoke(request, child, { getpgid: { pid: 0 } })).toMatchObject({ pgid: child.pid });
    await invoke(request, child, 'setsid', 'EPERM');
    await invoke(request, child, { setpgid: { pid: 0, pgid: parent.pid } });
    expect(await invoke(request, child, 'setsid')).toMatchObject({ sid: child.pid, pgid: child.pid });
    await invoke(request, parent, { setpgid: { pid: child.pid, pgid: parent.pid } }, 'EPERM');
    const foreign = await exec(request); processes.push(foreign);
    await invoke(request, parent, { setpgid: { pid: foreign.pid, pgid: parent.pid } }, 'ESRCH');
    await invoke(request, parent, { setpgid: { pid: -1, pgid: 0 } }, 'EINVAL');
    const next = await fork(request, parent); processes.push(next);
    const replacement = await call(request, { execve: { ...sleep, pid: next.pid, proc: next.token } });
    next.token = replacement.token;
    await invoke(request, parent, { setpgid: { pid: next.pid, pgid: parent.pid } }, 'EACCES');
    expect(await invoke(request, next, { getsid: { pid: 0 } })).toMatchObject({ sid: parent.pid, pgid: parent.pid });
    const [forged] = await sys(request, ['setsid'], { pid: parent.pid, proc: 'forged' });
    expect(forged.err.errno).toBe('EPERM');
  } finally { await cleanup(request, processes); }
});

test('group signals and wait selectors preserve siblings and report each state once', async ({ page }) => {
  await page.goto('/');
  const request = page.request, parent = await exec(request), processes = [parent];
  try {
    await invoke(request, parent, 'setsid');
    const a = await fork(request, parent), b = await fork(request, parent), other = await fork(request, parent);
    processes.push(a, b, other);
    await invoke(request, parent, { setpgid: { pid: a.pid, pgid: a.pid } });
    await invoke(request, parent, { setpgid: { pid: b.pid, pgid: a.pid } });
    await invoke(request, parent, { kill: { pid: String(-a.pid), signal: 0 } });
    await invoke(request, parent, { kill: { pid: String(-a.pid), signal: 19 } });
    for (const child of [a, b]) {
      expect(await invoke(request, parent, { waitpid: { pid: -a.pid, options: 3 } })).toMatchObject({ pid: child.pid, stopped: true, status: 19 * 256 + 127 });
    }
    expect(await invoke(request, parent, { waitpid: { pid: -a.pid, options: 3 } })).toEqual({ nothing: true });
    await invoke(request, parent, { kill: { pid: String(-a.pid), signal: 18 } });
    for (const child of [a, b]) expect(await invoke(request, parent, { waitpid: { pid: -a.pid, options: 9 } })).toMatchObject({ pid: child.pid, continued: true, status: 65535 });
    expect(await invoke(request, parent, { waitpid: { pid: 0, options: 1 } })).toEqual({ nothing: true });
    await invoke(request, parent, { kill: { pid: String(-a.pid), signal: 9 } });
    for (const child of [a, b]) expect(await invoke(request, parent, { waitpid: { pid: -a.pid, options: 1 } })).toMatchObject({ pid: child.pid, signal: 9 });
    await invoke(request, parent, { waitpid: { pid: -a.pid, options: 1 } }, 'ECHILD');
    expect(await invoke(request, parent, { getpgid: { pid: other.pid } })).toMatchObject({ pgid: parent.pid });
    expect(await invoke(request, parent, { waitpid: { pid: other.pid, options: 1 } })).toEqual({ nothing: true });
  } finally { await cleanup(request, processes); }
});

test('session bootstrap checks every proof before changing any process', async ({ page }) => {
  await page.goto('/');
  const request = page.request, a = await exec(request), b = await exec(request), processes = [a, b];
  const bootstrap = proofs => sys(request, [{ proc_session: { processes: proofs } }], {}, { 'X-Registry': '1' });
  try {
    expect((await bootstrap([owned(a), { ...owned(b), proc: 'forged' }]))[0].err.errno).toBe('EPERM');
    expect(await invoke(request, a, { getsid: { pid: 0 } })).toMatchObject({ sid: 1, pgid: 1 });
    expect((await bootstrap([owned(a), owned(a)]))[0].err.errno).toBe('EPERM');
    await invoke(request, a, { proc_session: { processes: [owned(a)] } }, 'EPERM');
    const [started] = await bootstrap([owned(a), owned(b)]);
    expect(started.err).toBeUndefined();
    expect(started.ok.map(row => [row.sid, row.pgid])).toEqual([[a.pid, a.pid], [a.pid, a.pid]]);
    expect((await bootstrap([owned(b)]))[0].err.errno).toBe('EPERM');
  } finally { await cleanup(request, processes); }
});

test('orphaning a stopped group sends HUP and CONT and preserves group identity', async ({ page }) => {
  await page.goto('/');
  const request = page.request, parent = await exec(request), processes = [parent];
  try {
    await invoke(request, parent, 'setsid');
    const child = await fork(request, parent); processes.push(child);
    await invoke(request, parent, { setpgid: { pid: child.pid, pgid: 0 } });
    await invoke(request, parent, { kill: { pid: String(child.pid), signal: 19 } });
    await invoke(request, parent, { exit: { status: 0 } });
    const [kept] = await sys(request, [{ proc_keep: { processes: [owned(child)] } }], {}, { 'X-Registry': '1' });
    expect(kept.ok[0]).toMatchObject({ ppid: 1, sid: parent.pid, pgid: child.pid, state: 'running' });
    expect(kept.ok[0].pending_signals.map(event => event.signal)).toEqual([1, 18]);
  } finally { await cleanup(request, processes); }
});

test('a group signal reaches permitted members without enlarging account authority', async ({ page }) => {
  await page.goto('/');
  const request = page.request;
  const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': crypto.randomUUID() }, data: { username: 'root', password } })).ok()).toBe(true);
  const root = await exec(request), processes = [root];
  try {
    await invoke(request, root, { setpgid: { pid: 0, pgid: 0 } });
    expect((await api(request, 'logout')).ok()).toBe(true);
    const guest = await exec(request); processes.push(guest);
    // The initial compatibility session can hold different credentials, just as
    // setuid execution can. Group membership must never grant signaling rights.
    await invoke(request, guest, { setpgid: { pid: 0, pgid: root.pid } });
    await invoke(request, guest, { kill: { pid: String(-root.pid), signal: 10 } });
    const [kept] = await sys(request, [{ proc_keep: { processes: [owned(root), owned(guest)] } }], {}, { 'X-Registry': '1' });
    expect(kept.ok.find(row => row.pid === root.pid).pending_signals ?? []).toEqual([]);
    expect(kept.ok.find(row => row.pid === guest.pid).pending_signals.map(event => event.signal)).toEqual([10]);
    const metadata = await invoke(request, guest, { getpgid: { pid: root.pid } });
    expect(Object.keys(metadata).sort()).toEqual(['pgid', 'pid', 'ppid', 'sid']);
    await invoke(request, guest, { kill: { pid: String(root.pid), signal: 0 } }, 'EPERM');
  } finally {
    await api(request, 'login', { headers: { 'CF-Connecting-IP': crypto.randomUUID() }, data: { username: 'root', password } });
    await cleanup(request, processes);
  }
});

const prompt = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const screen = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function send(page, text) {
  await page.locator('#command').fill(text);
  await page.locator('#command').press('Enter');
}
async function interactive(page) {
  await page.goto('/'); await send(page, 'sh -i');
  await expect(prompt(page)).toHaveAttribute('data-state', 'input', { timeout: 60_000 });
  await expect(screen(page)).toContainText('$ ');
}

test('dash owns stopped foreground jobs and can resume them without stopping its shell', async ({ page }) => {
  await interactive(page);
  await send(page, 'echo shell:$$');
  await expect(screen(page)).toContainText('shell:');
  await send(page, 'sleep 60');
  await page.waitForTimeout(500);
  await page.locator('#command').press('Control+z');
  await expect(screen(page)).toContainText('Stopped', { timeout: 20_000 });
  await send(page, 'jobs');
  await expect(screen(page)).toContainText('sleep 60');
  await send(page, 'fg');
  await page.waitForTimeout(300);
  await page.locator('#command').press('Control+c');
  await expect(screen(page)).toHaveText(/\$\s*$/);
  await send(page, 'echo recovered; exit');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await expect(screen(page)).toContainText('recovered');
});

test('background reads stop with SIGTTIN and fg gives the child terminal input', async ({ page }) => {
  await interactive(page);
  await send(page, 'cat &');
  await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).some(row => row.argv[0] === 'cat' && row.state === 'stopped')).toBe(true);
  await send(page, 'jobs');
  await expect(screen(page)).toContainText('Stopped', { timeout: 20_000 });
  await send(page, 'fg');
  await page.waitForTimeout(300);
  await send(page, 'foreground-input');
  await expect(screen(page)).toContainText('foreground-input\nforeground-input');
  await page.locator('#command').press('Control+c');
  await expect(screen(page)).toHaveText(/\$\s*$/);
  await send(page, 'exit');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
});

test('Ctrl+C targets the foreground pipeline while a background job and the shell survive', async ({ page }) => {
  await interactive(page);
  await send(page, 'sleep 60 &');
  const rows = () => call(page.request, { proc_poll: { pids: [] } });
  await expect.poll(async () => (await rows()).some(row => row.argv[0] === 'sleep')).toBe(true);
  const background = (await rows()).find(row => row.argv[0] === 'sleep');
  await send(page, 'yes | cat');
  await expect.poll(async () => (await rows()).filter(row => ['yes', 'cat'].includes(row.argv[0])).length).toBe(2);
  const foreground = (await rows()).filter(row => ['yes', 'cat'].includes(row.argv[0]));
  expect(new Set(foreground.map(row => row.pgid)).size).toBe(1);
  expect(foreground[0].pgid).not.toBe(background.pgid);
  await page.locator('#command').press('Control+c');
  await expect(screen(page)).toHaveText(/\$\s*$/);
  expect((await rows()).find(row => row.pid === background.pid)?.state).toBe('running');
  await send(page, 'kill $!; wait $!; echo survived; exit');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await expect(screen(page)).toContainText('survived');
});

test('stty tostop stops background terminal writes and fg lets them complete', async ({ page }) => {
  await interactive(page);
  await send(page, 'stty tostop; echo configured');
  await expect(screen(page)).toContainText('configured\n$');
  await send(page, 'echo background-write &');
  await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).some(row => row.ppid !== 1 && row.state === 'stopped')).toBe(true);
  // Registry stop state can precede dash consuming SIGCHLD/wait status. Each
  // jobs invocation is a snapshot; ask again until the shell has observed it.
  await expect.poll(async () => {
    await send(page, 'jobs');
    return (await screen(page).textContent()).includes('Stopped (tty output)');
  }).toBe(true);
  await send(page, 'fg');
  await expect(screen(page)).toContainText('background-write\n$');
  await send(page, 'stty -tostop; exit');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
});

test('setsid detaches the controlling terminal without closing inherited descriptors', async ({ page }) => {
  await page.goto('/');
  const base = '/guest/session-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o755 } });
  const module = binaryen.parseText(`(module
    (import "os" "getpgid" (func $pgid (param i32) (result i32)))
    (import "os" "getsid" (func $sid (param i32) (result i32)))
    (import "os" "setsid" (func $setsid (result i32)))
    (import "os" "tcgetpgrp" (func $foreground (param i32) (result i32)))
    (import "os" "tcsetpgrp" (func $setfg (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "detached") (data (i32.const 150) "/dev/tty")
    (func $assert (param i32) (if (i32.eqz (local.get 0)) (then unreachable)))
    (func (export "_start") (local $session i32)
      (call $assert (i32.gt_s (call $foreground (i32.const 0)) (i32.const 0)))
      (call $assert (i32.eq (call $setfg (i32.const 0) (i32.const 2147483647)) (i32.const -63)))
      (call $assert (i32.eq (call $pgid (i32.const -1)) (i32.const -28)))
      (local.set $session (call $setsid))
      (call $assert (i32.gt_s (local.get $session) (i32.const 1)))
      (call $assert (i32.eq (call $sid (i32.const 0)) (local.get $session)))
      (call $assert (i32.eq (call $pgid (i32.const 0)) (local.get $session)))
      (call $assert (i32.eq (call $setsid) (i32.const -63)))
      (call $assert (i32.eq (call $foreground (i32.const 0)) (i32.const -59)))
      (call $assert (i32.eq (call $setfg (i32.const 0) (local.get $session)) (i32.const -59)))
      (call $assert (i32.eq (call $open (i32.const 3) (i32.const 1) (i32.const 150) (i32.const 8) (i32.const 0) (i64.const 2) (i64.const 0) (i32.const 0) (i32.const 32)) (i32.const 60)))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 8))
      (call $assert (i32.eqz (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))))))`);
  try {
    expect((await put(page.request, '/api/file?path=' + base + '/probe', { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true);
    await call(page.request, { chmod: { path: base + '/probe', mode: 0o755 } });
    await send(page, `sh -c '${base}/probe; echo :$?'`);
    await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
    await expect(screen(page)).toHaveText('detached:0');
  } finally { module.dispose(); await rmrf(page.request, base); }
});
