import { test, expect } from './test.js';
import {
  execCmd,
  execSh,
  pageCall,
  pageErrno,
  pageGetText,
  pageMkdirp,
  pagePut,
  pageRmrf,
  runTerminal,
  sendTerminalLine,
  terminalInput,
  terminalScreen,
  terminalText,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';
const binaryen = (await import('binaryen')).default;

let base;
test.beforeEach(async ({ page }) => {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
  base = '/home/user/sh-' + crypto.randomUUID();
  await pageMkdirp(page, base, 0o700);
});
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base).catch(() => {});
});

test('installed sh and merged-usr aliases execute from cwd with immutable metadata', async ({ page }) => {
  const image = await pageCall(page, { stat: { path: '/usr/bin/sh' } });
  expect(image.uid).toBe(0);
  expect(image.mode).toBe(0o100755);
  expect(image.size).toBeGreaterThan(100_000);
  expect(await pageCall(page, { readlink: { path: '/usr/bin/sh' } })).toBe('dash');
  expect(await pageErrno(page, { chmod: { path: '/usr/bin/dash', mode: 0o777 } })).toBe('EROFS');
  const unicode = base + '/café-Δ';
  await pageCall(page, { mkdir: { path: unicode, mode: 0o700 } });
  for (const name of ['sh', 'dash', '/usr/bin/sh', '/bin/sh']) {
    const res = await execSh(page, `${name} -c 'pwd; printf "ok:%s" "$PWD"'`, { cwd: unicode });
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toBe(`${unicode}\nok:${unicode}`);
  }
});

test('builtin printf uses redirected files and pipes, preserving stdout afterwards', async ({ page }) => {
  const first = await execSh(page, 'printf "first\\nsecond\\n" > out; cat out; printf "third\\nfourth\\n" | cat; printf final', { cwd: base });
  expect(first.status, first.stderr).toBe(0);
  expect(first.stdout).toBe('first\nsecond\nthird\nfourth\nfinal');
  expect(await pageGetText(page, base + '/out')).toBe('first\nsecond\n');
  const second = await execSh(page, 'printf tail >> out; cat out', { cwd: base });
  expect(second.status, second.stderr).toBe(0);
  expect(second.stdout).toBe('first\nsecond\ntail');
});

test('background wait preserves success, failure and unknown-child statuses', async ({ page }) => {
  const res = await execSh(page, 'true & wait $!; printf "true:%s\\n" "$?"; false & wait $!; printf "false:%s\\n" "$?"; (exit 7) & wait $!; printf "subshell:%s\\n" "$?"; wait 999999; printf "unknown:%s\\n" "$?"; cat & wait $!; printf "stdin:%s" "$?"', { cwd: base });
  expect(res.status, res.stderr).toBe(0);
  expect(res.stdout).toBe('true:0\nfalse:1\nsubshell:7\nunknown:127\nstdin:0');
});

test('fd 3 survives fork and exec while children still access the filesystem', async ({ page }) => {
  const first = await execSh(page, 'printf content > input; exec 3<>/dev/null; (cat input; printf hidden >&3); cat <&3; sh -c "cat input; printf hidden >&3"; stat input >/dev/null; printf "stat:%s\\n" "$?"; printf restored', { cwd: base });
  expect(first.status, first.stderr).toBe(0);
  expect(first.stdout).toBe('contentcontentstat:0\nrestored');
  const second = await execSh(page, 'exec 3< input; cat <&3; cat input; printf done', { cwd: base });
  expect(second.status, second.stderr).toBe(0);
  expect(second.stdout).toBe('contentcontentdone');
});

test('exec preserves empty and newline arguments and environment without granting authority', async ({ page }) => {
  const { uid } = await pageCall(page, 'getcreds');
  expect(uid).toBeGreaterThan(0);
  const res = await execSh(page, 'value=$(printf "two\\nlines"); /usr/bin/printf "<%s><%s>\\n" "" "$value"; export VALUE="$value"; sh -c "printenv VALUE"; id -u; cat /root/denied 2>/dev/null; printf "denied:%s" "$?"', { cwd: base });
  expect(res.status, res.stderr).toBe(0);
  expect(res.stdout).toBe(`<><two\nlines>\ntwo\nlines\n${uid}\ndenied:1`);
  const blocked = base + '/blocked';
  await pagePut(page, blocked, 'not an executable', { mode: 0o600 });
  const execBlocked = await execSh(page, './blocked 2>/dev/null; printf "exec:%s" "$?"', { cwd: base });
  expect(execBlocked.status, execBlocked.stderr).toBe(0);
  expect(execBlocked.stdout).toBe('exec:126');
});

test('Ctrl+C stops a continuous output child of the installed shell', async ({ page }) => {
  await waitForTerminalReady(page);
  // A following command prevents dash's final-command exec optimization: parent waits.
  await runTerminal(page, 'sh -c \'yes; printf "should-%s-run\\n" not\'', { wait: false });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await expect.poll(() => terminalText(page), { timeout: 60_000 }).toMatch(/^y\s*$/m);
  await terminalInput(page).press('Control+c');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 10_000 });
  expect(await terminalText(page)).not.toContain('should-not-run');
  await runTerminal(page, 'sh -c \'printf "rec%s\\n" overed\'');
  await expect(terminalScreen(page)).toContainText('recovered');
});

test('installed interactive sh reads terminal input and returns to the browser prompt', async ({ page }) => {
  await waitForTerminalReady(page);
  await runTerminal(page, 'sh -i', { wait: false });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy', { timeout: 60_000 });
  await expect.poll(() => terminalText(page), { timeout: 60_000 }).toMatch(/\n\$\s*$/);
  await sendTerminalLine(page, 'printf "interactive:%s\\n" ok');
  await expect(terminalScreen(page)).toContainText('interactive:ok', { timeout: 15_000 });
  await sendTerminalLine(page, 'exit');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
  await runTerminal(page, 'sh -c \'printf "ret%s\\n" urned\'');
  await expect(terminalScreen(page)).toContainText('returned');
});

test('installed-image compilation returns a complete cached transform after authorization', async ({ page }) => {
  const url = '/api/file?path=/usr/bin/sh&compile=fork-v4';
  expect((await page.request.head(url)).status()).toBe(400);
  expect((await page.request.get(url, { headers: { 'X-Process-Token': 'invalid' } })).ok()).toBe(false);
  const response = await page.request.get(url, { headers: { Range: 'bytes=0-7', 'If-None-Match': '*' } });
  if (response.status() === 500 || response.status() === 503) {
    test.skip(true, 'ModuleCompiler container unavailable (requires Podman/Cloudflare containers)');
  }
  expect(response.status()).toBe(200);
  const bytes = await response.body();
  const module = await WebAssembly.compile(bytes);
  expect(WebAssembly.Module.exports(module).some(entry => entry.name === '__tw_functions')).toBe(true);
  expect(await (await page.request.get(url)).body()).toEqual(bytes);
});

test('modern WASIX validates exec pointers and preserves only non-CLOEXEC descriptors', async ({ page }) => {
  const child = base + '/child';
  const upload = async (path, wat) => {
    const module = binaryen.parseText(wat);
    try {
      await pagePut(page, path, Buffer.from(module.emitBinary()), { mode: 0o755 });
    } finally { module.dispose(); }
  };
  await upload(child, `(module
    (import "wasix_32v1" "fd_fdflags_get" (func $flags (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "flags-ok")
    (func (export "_start")
      (if (i32.ne (call $stat (i32.const 4) (i32.const 32)) (i32.const 8)) (then unreachable))
      (if (call $flags (i32.const 5) (i32.const 32)) (then unreachable))
      (if (i32.load16_u (i32.const 32)) (then unreachable))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 8))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 24)))))`);
  await upload(base + '/parent', `(module
    (import "wasix_32v1" "path_open2" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32 i32) (result i32)))
    (import "wasix_32v1" "fd_fdflags_get" (func $get (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_fdflags_set" (func $set (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_exec4" (func $exec (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "/dev/null") (data (i32.const 200) "${child}")
    (func (export "_start")
      (if (i32.ne (call $exec (i32.const 200) (i32.const ${child.length}) (i32.const 65535) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)) (i32.const 21)) (then unreachable))
      (if (i32.ne (call $exec (i32.const 200) (i32.const ${child.length}) (i32.const 0) (i32.const 4097) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)) (i32.const 1)) (then unreachable))
      (if (call $open (i32.const 3) (i32.const 0) (i32.const 100) (i32.const 9) (i32.const 0) (i64.const 2) (i64.const 2) (i32.const 0) (i32.const 1) (i32.const 20)) (then unreachable))
      (if (call $get (i32.load (i32.const 20)) (i32.const 32)) (then unreachable))
      (if (i32.ne (i32.load16_u (i32.const 32)) (i32.const 1)) (then unreachable))
      (if (call $open (i32.const 3) (i32.const 0) (i32.const 100) (i32.const 9) (i32.const 0) (i64.const 2) (i64.const 2) (i32.const 0) (i32.const 0) (i32.const 20)) (then unreachable))
      (if (call $set (i32.load (i32.const 20)) (i32.const 1)) (then unreachable))
      (if (call $set (i32.load (i32.const 20)) (i32.const 0)) (then unreachable))
      (drop (call $exec (i32.const 200) (i32.const ${child.length}) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))) unreachable))`);
  const res = await execCmd(page, [`${base}/parent`], { cwd: base });
  expect(res.status, res.stderr).toBe(0);
  expect(res.stdout).toBe('flags-ok');
});
