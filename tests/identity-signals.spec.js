import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call, put, rmrf } from './sys.js';

const prompt = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function send(page, command) {
  await page.locator('#command').fill(command);
  await page.locator('#command').press('Enter');
}
async function run(page, command) {
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
  await send(page, command);
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}
const shell = (page, script) => run(page, `sh -c '${script}'`);
let base;
test.beforeEach(async ({ page }) => {
  await page.goto('/');
  base = '/guest/signals-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o755 } });
  await run(page, 'cd ' + base);
});
test.afterEach(async ({ page }) => { await rmrf(page.request, base); });
async function upload(page, name, wat) {
  const path = base + '/' + name, module = binaryen.parseText(wat);
  try { expect((await put(page.request, '/api/file?path=' + path, { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true); }
  finally { module.dispose(); }
  await call(page.request, { chmod: { path, mode: 0o755 } });
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

test('libc prompt and identity imports use credentials, including a root process after logout and exec', async ({ page }) => {
  const guest = await call(page.request, 'getcreds');
  await shell(page, 'USER=root UID=0; export USER UID; printf "%s" "$PS1"');
  await expect(last(page)).toHaveText('$ ');
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
  await upload(page, 'guest-id', identity(guest.uid));
  await shell(page, 'USER=root UID=0 ./guest-id; echo guest:$?');
  await expect(last(page)).toHaveText('guest:0');
  await upload(page, 'root-id', identity(0));
  const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
  expect((await api(page.request, 'login', { headers: { 'CF-Connecting-IP': crypto.randomUUID() }, data: { username: 'root', password } })).ok()).toBe(true);
  await send(page, 'sh -i');
  await expect(prompt(page)).toHaveAttribute('data-state', 'input');
  await expect(last(page)).toHaveText('# ');
  expect((await api(page.request, 'logout')).ok()).toBe(true);
  await send(page, './root-id; echo root:$?');
  await expect(last(page)).toContainText('\nroot:0\n# ');
  await send(page, 'exit');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
});

test('shell traps, ignored dispositions across exec, and background wait statuses', async ({ page }) => {
  await shell(page, 'trap "echo caught" USR1; kill -USR1 $$; echo after');
  await expect(last(page)).toHaveText('caught\nafter');
  await shell(page, 'trap "" TERM; exec sh -c "kill -TERM \\$\\$; echo ignored"');
  await expect(last(page)).toHaveText('ignored');
  await shell(page, 'trap "echo child" CHLD; (exit 7) & wait $!; echo status:$?');
  await expect(last(page)).toHaveText('child\nstatus:7');
  await shell(page, 'trap "echo wrong" TERM; sh -c "kill -TERM \\$\\$; echo wrong"; echo status:$?');
  await expect(last(page)).toHaveText('Terminated\nstatus:143');
  await shell(page, 'sleep 10 & p=$!; kill -KILL $p; wait $p; echo status:$?');
  await expect(last(page)).toContainText('status:137');
});

test('Ctrl+C recovers the same interactive shell, including while a child writes continuously', async ({ page }) => {
  await send(page, 'sh -i');
  await expect(prompt(page)).toHaveAttribute('data-state', 'input');
  await send(page, 'echo shell:$$');
  await expect(last(page)).toContainText('\nshell:');
  const pid = (await last(page).textContent()).match(/\nshell:(\d+)/)[1];
  await page.locator('#command').press('Control+c');
  await expect(last(page)).toHaveText(/\^C\n\n\$\s*$/);
  await expect(prompt(page)).toHaveAttribute('data-state', 'input');
  await send(page, 'echo recovered:$$');
  await expect(last(page)).toContainText(`\nrecovered:${pid}\n`);
  await send(page, 'yes');
  await expect(last(page)).toContainText('\ny\ny\n');
  await page.locator('#command').press('Control+c');
  await expect(last(page)).toHaveText(/\$\s*$/);
  await send(page, 'echo survived:$$');
  await expect(last(page)).toContainText(`\nsurvived:${pid}\n`);
  await send(page, 'exit');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
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
  await run(page, './mask');
  await expect(last(page)).toHaveText('ok');
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
  await run(page, './nested');
  await expect(last(page)).toHaveText('ok');
  await upload(page, 'broken', signalModule(`
    (drop (call $action (i32.const 13) (i32.const 2) (i32.const 0) (i32.const 0)))
    (drop (call $pipe (i32.const 32) (i32.const 36)))
    (drop (call $close (i32.load (i32.const 32))))
    (i32.store (i32.const 0) (i32.const 120)) (i32.store (i32.const 4) (i32.const 2))
    (call $assert (i32.eq (call $write (i32.load (i32.const 36)) (i32.const 0) (i32.const 1) (i32.const 8)) (i32.const 64)))
    (call $assert (i32.eq (global.get $count) (i32.const 1)))`, undefined, `
    (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))`));
  await run(page, './broken');
  await expect(last(page)).toHaveText('ok');
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
  try {
    await page.waitForFunction(() => window.signalReading && window.signalJob.pids.length === 1);
    const pid = await page.evaluate(() => window.signalJob.pids[0]);
    await call(page.request, { kill: { pid: String(pid), signal: 10 } });
    if (restart) {
      await page.waitForFunction(() => window.signalOutput.length > 0);
      expect(await page.evaluate(() => window.signalOutput)).toBe('caught');
      await page.evaluate(() => window.signalInput.write('x\n'));
    }
    expect((await page.evaluate(() => window.signalRun)).status, await page.evaluate(() => window.signalOutput)).toBe(0);
    expect(await page.evaluate(() => window.signalOutput)).toBe(restart ? 'caughtx\r\nok' : 'caughtok');
  } finally { await page.evaluate(() => window.signalJob?.signal(9)); }
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
  await run(page, './fork-mask');
  await expect(last(page)).toHaveText('ok');
});

test('kill %job delivers a caught signal once across registry reconciliation', async ({ page }) => {
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
  await run(page, './job &');
  const transcript = page.locator('.terminal-panel:not([hidden]) .transcript');
  await expect(transcript).toContainText('ready');
  await run(page, 'kill -USR1 %1');
  await expect(transcript).toContainText('caught');
  // Allow the five-second recovery poll to run before checking the count.
  await page.waitForTimeout(5500);
  await run(page, 'kill -USR2 %1');
  await expect(transcript).toContainText(/ready\s*caught\s*ok/);
});

test('a signal interrupting writev preserves the bytes from completed vectors', async ({ page }) => {
  const path = await upload(page, 'writev', signalModule(`
    (drop (call $action (i32.const 10) (i32.const 2) (i32.const 0) (i32.const 0)))
    (drop (call $pipe (i32.const 500) (i32.const 504)))
    (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 6))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
    (i32.store (i32.const 32) (i32.const 4096)) (i32.store (i32.const 36) (i32.const 65536))
    (i32.store (i32.const 40) (i32.const 4096)) (i32.store (i32.const 44) (i32.const 1))
    (call $assert (i32.eqz (call $write (i32.load (i32.const 504)) (i32.const 32) (i32.const 2) (i32.const 48))))
    (call $assert (i32.eq (i32.load (i32.const 48)) (i32.const 65536)))
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
  try {
    await page.waitForFunction(() => window.writevOutput === 'caught');
    const pid = await page.evaluate(() => window.writevJob.pids[0]);
    await call(page.request, { kill: { pid: String(pid), signal: 10 } });
    expect((await page.evaluate(() => window.writevRun)).status, await page.evaluate(() => window.writevOutput)).toBe(0);
    expect(await page.evaluate(() => window.writevOutput)).toBe('caughtok');
  } finally { await page.evaluate(() => window.writevJob?.signal(9)); }
});
