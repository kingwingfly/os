import { test, expect } from './test.js';
import binaryen from 'binaryen';
import {
  execCmd,
  execSh,
  pageCall,
  pageMkdirp,
  pagePut,
  pageRmrf,
  runTerminal,
  sendTerminalLine,
  switchLocalUser,
  terminalInput,
  terminalText,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

let base;
test.beforeEach(async ({ page }) => {
  base = '/tmp/signals-' + crypto.randomUUID();
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
  await pageMkdirp(page, base, 0o755);
});
test.afterEach(async ({ page }) => { await pageRmrf(page, base).catch(() => {}); });
async function upload(page, name, wat) {
  const path = base + '/' + name, module = binaryen.parseText(wat);
  let bin;
  try { bin = Buffer.from(module.emitBinary()); }
  finally { module.dispose(); }
  await pagePut(page, path, bin, { mode: 0o755 });
  return path;
}
const signalModule = (body, handler = '(global.set $count (i32.add (global.get $count) (i32.const 1)))', extra = '') => `(module
  (import "os" "sigaction" (func $action (param i32 i32 i32 i32) (result i32)))
  (import "os" "sigmask" (func $mask (param i32 i32) (result i32)))
  (import "os" "sigpending" (func $pending (result i32)))
  (import "os" "sigsuspend" (func $suspend (param i32) (result i32)))
  (import "os" "sigpoll" (func $poll))
  (import "wasix_32v1" "callback_signal" (func $callback (param i32 i32)))
  (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  ${extra}
  (memory (export "memory") 1)
  (global $count (mut i32) (i32.const 0))
  (data (i32.const 100) "caught") (data (i32.const 120) "ok")
  (func $assert (param $value i32) (if (i32.eqz (local.get $value)) (then unreachable)))
  (func (export "caught") (param $n i32) ${handler})
  (func (export "_start")
    (call $callback (i32.const 100) (i32.const 6))
    ${body}
    (i32.store (i32.const 0) (i32.const 120)) (i32.store (i32.const 4) (i32.const 2))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`;

test('libc prompt and identity imports use credentials, including a root process after account switch and exec', async ({ page }) => {
  const localUser = await pageCall(page, 'getcreds');
  const ps1 = await execSh(page, 'USER=root UID=0; export USER UID; printf "%s" "$PS1"', { cwd: base });
  expect(ps1.status, ps1.stderr).toBe(0);
  expect(ps1.stdout).toBe('$ ');
  const identity = uid => `(module
    (import "os" "getuid" (func $uid (result i32)))
    (import "os" "getgid" (func $gid (result i32)))
    (import "os" "getgroups" (func $groups (param i32 i32) (result i32)))
    (memory (export "memory") 1)
    (func (export "_start")
      (if (i32.ne (call $uid) (i32.const ${uid})) (then unreachable))
      (if (i32.lt_s (call $gid) (i32.const 0)) (then unreachable))
      (if (i32.ne (call $groups (i32.const -1) (i32.const 0)) (i32.const -28)) (then unreachable))
      (if (i32.lt_s (call $groups (i32.const 64) (i32.const 32)) (i32.const 0)) (then unreachable))))`;
  await upload(page, 'user-id', identity(localUser.uid));
  const userId = await execSh(page, 'USER=root UID=0 ./user-id; echo user:$?', { cwd: base });
  expect(userId.status, userId.stderr).toBe(0);
  expect(userId.stdout.trim()).toBe('user:0');
  await upload(page, 'root-id', identity(0));
  await switchLocalUser(page, 'root');
  try {
    await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(0);
    // Start an interactive root `sh -i` via window.os.exec so its process credentials snapshot UID 0
    // and survive a subsequent browser account switch back to the unprivileged user.
    await page.evaluate(cwd => {
      const state = (window.__rootSh = { out: '', tty: null, job: null, result: null });
      state.done = window.os.exec([{ path: '/usr/bin/sh', argv: ['sh', '-i'] }], {
        cwd,
        tty: true,
        onOutput(_fd, text) { state.out += text.replace(/\r\n/g, '\n'); },
        onTty(input) { state.tty = input; },
        onJob(job) { state.job = job; },
      }).then(res => { state.result = res; });
    }, base);
    await expect.poll(() => page.evaluate(() => window.__rootSh.out), { timeout: 15_000 }).toBe('# ');
    await switchLocalUser(page, 'user');
    await expect.poll(async () => (await page.evaluate(() => window.os.loginSession())).session?.uid).toBe(localUser.uid);
    await page.evaluate(() => window.__rootSh.tty.write('./root-id; echo root:$?\n'));
    await expect.poll(() => page.evaluate(() => window.__rootSh.out), { timeout: 15_000 }).toContain('\nroot:0\n# ');
    await page.evaluate(() => window.__rootSh.tty.write('exit\n'));
    await expect.poll(() => page.evaluate(() => window.__rootSh.result?.status), { timeout: 15_000 }).toBe(0);
  } finally {
    await page.evaluate(() => window.__rootSh?.job?.signal(9)).catch(() => {});
    await switchLocalUser(page, 'user').catch(() => {});
  }
});

test('shell traps, ignored dispositions across exec, and background wait statuses', async ({ page }) => {
  const caught = await execSh(page, 'trap "echo caught" USR1; kill -USR1 $$; echo after', { cwd: base });
  expect(caught.status, caught.stderr).toBe(0);
  expect(caught.stdout.trim()).toBe('caught\nafter');
  const ignored = await execSh(page, 'trap "" TERM; exec sh -c "kill -TERM \\$\\$; echo ignored"', { cwd: base });
  expect(ignored.status, ignored.stderr).toBe(0);
  expect(ignored.stdout.trim()).toBe('ignored');
  const chld = await execSh(page, 'trap "echo child" CHLD; (exit 7) & wait $!; echo status:$?', { cwd: base });
  expect(chld.status, chld.stderr).toBe(0);
  expect(chld.stdout.trim()).toBe('child\nstatus:7');
  const term = await execSh(page, 'trap "echo wrong" TERM; sh -c "kill -TERM \\$\\$; echo wrong"; echo status:$?', { cwd: base });
  expect(term.stdout + term.stderr).toContain('Terminated');
  expect(term.stdout.trim()).toContain('status:143');
  expect(term.stdout).not.toContain('wrong');
  const killed = await execSh(page, 'sleep 10 & p=$!; kill -KILL $p; wait $p; echo status:$?', { cwd: base });
  expect(killed.stdout).toContain('status:137');
});

test('Ctrl+C recovers the same interactive shell, including while a child writes continuously', async ({ page }) => {
  await waitForTerminalReady(page);
  await runTerminal(page, 'sh -i', { wait: false });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/\n\$\s*$/);
  await sendTerminalLine(page, 'echo shell:$$');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/^shell:(\d+)\s*$/m);
  const pid = (await terminalText(page)).match(/^shell:(\d+)\s*$/m)[1];
  await terminalInput(page).press('Control+c');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/\^C[\s\S]*\n\$\s*$/);
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy');
  await sendTerminalLine(page, 'echo recovered:$$');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(new RegExp(`^recovered:${pid}\\s*$`, 'm'));
  await sendTerminalLine(page, 'yes');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/^y\s*\ny\s*$/m);
  await terminalInput(page).press('Control+c');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/\n\$\s*$/);
  await sendTerminalLine(page, 'echo survived:$$');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(new RegExp(`^survived:${pid}\\s*$`, 'm'));
  await sendTerminalLine(page, 'exit');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
});

test('standard pending signals coalesce, sigsuspend restores the mask, and KILL/STOP cannot be caught or masked', async ({ page }) => {
  await upload(page, 'mask', signalModule(`
    (call $assert (i32.eq (call $action (i32.const 10) (i32.const 2) (i32.const 0) (i32.const 0)) (i32.const 0)))
    (drop (call $mask (i32.const 2) (i32.const 262912)))
    (call $assert (i32.eq (call $mask (i32.const -1) (i32.const 0)) (i32.const 512)))
    (drop (call $raise (i32.const 10))) (drop (call $raise (i32.const 10)))
    (call $assert (i32.eq (call $pending) (i32.const 512)))
    (call $assert (i32.eq (global.get $count) (i32.const 0)))
    (call $assert (i32.eq (call $suspend (i32.const 0)) (i32.const 27)))
    (call $assert (i32.eq (global.get $count) (i32.const 1)))
    (call $assert (i32.eq (call $mask (i32.const -1) (i32.const 0)) (i32.const 512)))
    (call $assert (i32.eqz (call $pending)))
    (call $assert (i32.eq (call $action (i32.const 9) (i32.const 2) (i32.const 0) (i32.const 0)) (i32.const -28)))
    (call $assert (i32.eq (call $action (i32.const 19) (i32.const 1) (i32.const 0) (i32.const 0)) (i32.const -28)))
    (drop (call $action (i32.const 15) (i32.const 1) (i32.const 0) (i32.const 0)))
    (drop (call $raise (i32.const 15)))
    (drop (call $action (i32.const 12) (i32.const 2) (i32.const 0) (i32.const -2147483648)))
    (drop (call $raise (i32.const 12)))
    (call $assert (i32.eq (call $action (i32.const 12) (i32.const -1) (i32.const 0) (i32.const 0)) (i32.const 0)))
    (call $assert (i32.eq (global.get $count) (i32.const 2)))`));
  const res = await execCmd(page, [`${base}/mask`], { cwd: base });
  expect(res.status, res.stderr).toBe(0);
  expect(res.stdout).toBe('ok');
});

test('SA_NODEFER permits nested delivery and a caught SIGPIPE returns EPIPE', async ({ page }) => {
  await upload(page, 'nested', signalModule(`
    (drop (call $action (i32.const 10) (i32.const 2) (i32.const 0) (i32.const 1073741824)))
    (drop (call $raise (i32.const 10)))
    (call $assert (i32.eq (global.get $count) (i32.const 2)))`, `
    (global.set $count (i32.add (global.get $count) (i32.const 1)))
    (if (i32.eq (global.get $count) (i32.const 1)) (then
      (drop (call $raise (i32.const 10)))
      (call $assert (i32.eq (global.get $count) (i32.const 2)))))`));
  const nested = await execCmd(page, [`${base}/nested`], { cwd: base });
  expect(nested.status, nested.stderr).toBe(0);
  expect(nested.stdout).toBe('ok');
  await upload(page, 'broken', signalModule(`
    (drop (call $action (i32.const 13) (i32.const 2) (i32.const 0) (i32.const 0)))
    (drop (call $pipe (i32.const 32) (i32.const 36)))
    (drop (call $close (i32.load (i32.const 32))))
    (i32.store (i32.const 0) (i32.const 120)) (i32.store (i32.const 4) (i32.const 2))
    (call $assert (i32.eq (call $write (i32.load (i32.const 36)) (i32.const 0) (i32.const 1) (i32.const 8)) (i32.const 64)))
    (call $assert (i32.eq (global.get $count) (i32.const 1)))`, undefined, `
    (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))`));
  const broken = await execCmd(page, [`${base}/broken`], { cwd: base });
  expect(broken.status, broken.stderr).toBe(0);
  expect(broken.stdout).toBe('ok');
});

for (const restart of [false, true]) test(`a signal ${restart ? 'restarts' : 'interrupts'} a blocked read according to SA_RESTART`, async ({ page }) => {
  const path = await upload(page, 'reader', signalModule(`
    (drop (call $action (i32.const 10) (i32.const 2) (i32.const 0) (i32.const ${restart ? 0x10000000 : 0})))
    (i32.store (i32.const 32) (i32.const 200)) (i32.store (i32.const 36) (i32.const 1))
    (call $assert (i32.eq (call $read (i32.const 0) (i32.const 32) (i32.const 1) (i32.const 40)) (i32.const ${restart ? 0 : 27})))
    (call $assert (i32.eq (global.get $count) (i32.const 1)))`, `
    (global.set $count (i32.add (global.get $count) (i32.const 1)))
    (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 6))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))`, `
    (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))`));
  await page.evaluate(path => {
    window.signalOutput = ''; window.signalReading = false;
    window.signalRun = window.os.exec([{ path, argv: [path] }], {
      tty: true,
      onOutput: (_, text) => { window.signalOutput += text; },
      onReading: () => { window.signalReading = true; },
      onTty: input => { window.signalInput = input; },
      onJob: job => { window.signalJob = job; },
    });
  }, path);
  const killRpcs = [];
  const watch = req => {
    if (req.method() === 'POST' && new URL(req.url()).pathname === '/api/sys' && (req.postData() ?? '').includes('"kill"')) {
      killRpcs.push(req.postData());
    }
  };
  page.on('request', watch);
  try {
    await page.waitForFunction(() => window.signalReading && window.signalJob.pids.length === 1);
    await page.evaluate(() => window.signalJob.signal(10));
    if (restart) {
      await page.waitForFunction(() => window.signalOutput.length > 0);
      expect(await page.evaluate(() => window.signalOutput)).toBe('caught');
      await page.evaluate(() => window.signalInput.write('x\n'));
    }
    expect((await page.evaluate(() => window.signalRun)).status, await page.evaluate(() => window.signalOutput)).toBe(0);
    expect(await page.evaluate(() => window.signalOutput)).toBe(restart ? 'caughtx\r\nok' : 'caughtok');
    expect(killRpcs).toEqual([]);
  } finally { page.off('request', watch); await page.evaluate(() => window.signalJob?.signal(9)); }
});

test('fork copies handlers and masks without copying the parent pending set', async ({ page }) => {
  await upload(page, 'fork-mask', signalModule(`
    (drop (call $action (i32.const 10) (i32.const 2) (i32.const 0) (i32.const 0)))
    (drop (call $action (i32.const 15) (i32.const 1) (i32.const 0) (i32.const 0)))
    (drop (call $mask (i32.const 2) (i32.const 512)))
    (drop (call $raise (i32.const 10)))
    (drop (call $fork (i32.const 1) (i32.const 500)))
    (if (i32.eqz (i32.load (i32.const 500))) (then
      (call $assert (i32.eqz (call $pending)))
      (call $assert (i32.eq (call $mask (i32.const -1) (i32.const 0)) (i32.const 512)))
      (call $assert (i32.eq (call $action (i32.const 10) (i32.const -1) (i32.const 0) (i32.const 0)) (i32.const 2)))
      (drop (call $raise (i32.const 15)))
      (drop (call $mask (i32.const 2) (i32.const 0)))
      (drop (call $raise (i32.const 10)))
      (call $assert (i32.eq (global.get $count) (i32.const 1)))
      (call $exit (i32.const 0))))
    (i32.store8 (i32.const 504) (i32.const 1))
    (i32.store (i32.const 508) (i32.load (i32.const 500)))
    (call $assert (i32.eqz (call $join (i32.const 504) (i32.const 0) (i32.const 512))))
    (call $assert (i32.eq (i32.load8_u (i32.const 512)) (i32.const 1)))
    (call $assert (i32.eqz (i32.load16_u (i32.const 514))))
    (call $assert (i32.eq (call $pending) (i32.const 512)))
    (drop (call $mask (i32.const 2) (i32.const 0))) (call $poll)
    (call $assert (i32.eq (global.get $count) (i32.const 1)))`, undefined, `
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))`));
  const res = await execCmd(page, [`${base}/fork-mask`], { cwd: base });
  expect(res.status, res.stderr).toBe(0);
  expect(res.stdout).toBe('ok');
});

test('kill %job delivers a caught signal once across registry reconciliation', async ({ page }) => {
  await waitForTerminalReady(page);
  await upload(page, 'job', signalModule(`
    (drop (call $action (i32.const 10) (i32.const 2) (i32.const 0) (i32.const 0)))
    (drop (call $action (i32.const 12) (i32.const 2) (i32.const 0) (i32.const 0)))
    (i32.store (i32.const 0) (i32.const 140)) (i32.store (i32.const 4) (i32.const 6))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
    (i32.store (i32.const 272) (i32.const 1)) (i64.store (i32.const 280) (i64.const 100000000))
    (block $end (loop $waiting
      (br_if $end (global.get $done))
      (drop (call $wait (i32.const 256) (i32.const 320) (i32.const 1) (i32.const 400))) (br $waiting)))
    (call $assert (i32.eq (global.get $count) (i32.const 1)))`, `
    (if (i32.eq (local.get $n) (i32.const 12))
      (then (global.set $done (i32.const 1)))
      (else
        (global.set $count (i32.add (global.get $count) (i32.const 1)))
        (i32.store (i32.const 0) (i32.const 160)) (i32.store (i32.const 4) (i32.const 7))
        (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`, `
    (import "wasi_snapshot_preview1" "poll_oneoff" (func $wait (param i32 i32 i32 i32) (result i32)))
    (global $done (mut i32) (i32.const 0)) (data (i32.const 140) "ready\\0a") (data (i32.const 160) "caught\\0a")`));
  await runTerminal(page, `cd ${base}`);
  await runTerminal(page, './job &');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/(?:^|\$ )ready\s*$/m);
  await runTerminal(page, 'kill -USR1 %1');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/(?:^|\$ )caught\s*$/m);
  // Allow the five-second recovery poll to run before checking the count.
  await page.waitForTimeout(5500);
  await runTerminal(page, 'kill -USR2 %1');
  await expect.poll(() => terminalText(page), { timeout: 15_000 }).toMatch(/ready[\s\S]*caught[\s\S]*ok/);
});

test('a signal interrupting writev preserves the bytes from completed vectors', async ({ page }) => {
  const path = await upload(page, 'writev', signalModule(`
    (drop (call $action (i32.const 10) (i32.const 2) (i32.const 0) (i32.const 0)))
    (drop (call $pipe (i32.const 500) (i32.const 504)))
    (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 6))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
    (i32.store (i32.const 32) (i32.const 4096)) (i32.store (i32.const 36) (i32.const 65472))
    (i32.store (i32.const 40) (i32.const 4096)) (i32.store (i32.const 44) (i32.const 1))
    (call $assert (i32.eqz (call $write (i32.load (i32.const 504)) (i32.const 32) (i32.const 2) (i32.const 48))))
    (call $assert (i32.eq (i32.load (i32.const 48)) (i32.const 65472)))
    (call $assert (i32.eq (global.get $count) (i32.const 1)))`, undefined, `
    (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))`).replace('(memory (export "memory") 1)', '(memory (export "memory") 2)'));
  await page.evaluate(path => {
    window.writevOutput = '';
    window.writevRun = window.os.exec([{ path, argv: [path] }], {
      tty: true, stdin: '',
      onOutput: (_, text) => { window.writevOutput += text; },
      onJob: job => { window.writevJob = job; },
    });
  }, path);
  const killRpcs = [];
  const watch = req => {
    if (req.method() === 'POST' && new URL(req.url()).pathname === '/api/sys' && (req.postData() ?? '').includes('"kill"')) {
      killRpcs.push(req.postData());
    }
  };
  page.on('request', watch);
  try {
    await page.waitForFunction(() => window.writevOutput === 'caught');
    await page.evaluate(() => window.writevJob.signal(10));
    expect((await page.evaluate(() => window.writevRun)).status, await page.evaluate(() => window.writevOutput)).toBe(0);
    expect(await page.evaluate(() => window.writevOutput)).toBe('caughtok');
    expect(killRpcs).toEqual([]);
  } finally { page.off('request', watch); await page.evaluate(() => window.writevJob?.signal(9)); }
});
