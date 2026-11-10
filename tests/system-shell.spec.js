import { test, expect } from './test.js';
import { call, errno, put, rmrf } from './sys.js';
const binaryen = (await import('binaryen')).default;

const file = path => '/api/file?path=' + encodeURIComponent(path);
const prompt = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function run(page, command) {
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
  await page.locator('#command').fill(command);
  await page.locator('#command').press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}
const shell = (page, script, name = 'sh') => run(page, `${name} -c '${script}'`);
let base;
test.beforeEach(async ({ page }) => {
  await page.goto('/');
  base = '/guest/sh-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  await run(page, 'cd ' + base);
});
test.afterEach(async ({ page }) => { await rmrf(page.request, base); });

test('installed sh and merged-usr aliases execute from cwd with immutable metadata', async ({ page }) => {
  const image = await call(page.request, { stat: { path: '/usr/bin/sh' } });
  expect(image.uid).toBe(0);
  expect(image.mode).toBe(0o100755);
  expect(image.size).toBeGreaterThan(100_000);
  expect(await call(page.request, { readlink: { path: '/usr/bin/sh' } })).toBe('dash');
  expect(await errno(page.request, { chmod: { path: '/usr/bin/dash', mode: 0o777 } })).toBe('EROFS');
  const unicode = base + '/café-Δ';
  await call(page.request, { mkdir: { path: unicode, mode: 0o700 } });
  await run(page, 'cd ' + unicode);
  for (const name of ['sh', 'dash', '/usr/bin/sh', '/bin/sh']) {
    await shell(page, 'pwd; printf "ok:%s" "$PWD"', name);
    await expect(last(page)).toHaveText(`${unicode}\nok:${unicode}`);
  }
});

test('builtin printf uses redirected files and pipes, preserving stdout afterwards', async ({ page }) => {
  await shell(page, 'printf "first\\nsecond\\n" > out; cat out; printf "third\\nfourth\\n" | cat; printf final');
  await expect(last(page)).toHaveText('first\nsecond\nthird\nfourth\nfinal');
  expect(await (await page.request.get(file(base + '/out'))).text()).toBe('first\nsecond\n');
  await shell(page, 'printf tail >> out; cat out');
  await expect(last(page)).toHaveText('first\nsecond\ntail');
});

test('background wait preserves success, failure and unknown-child statuses', async ({ page }) => {
  await shell(page, 'true & wait $!; printf "true:%s\\n" "$?"; false & wait $!; printf "false:%s\\n" "$?"; (exit 7) & wait $!; printf "subshell:%s\\n" "$?"; wait 999999; printf "unknown:%s\\n" "$?"; cat & wait $!; printf "stdin:%s" "$?"');
  await expect(last(page)).toHaveText('true:0\nfalse:1\nsubshell:7\nunknown:127\nstdin:0');
});

test('fd 3 survives fork and exec while children still access the filesystem', async ({ page }) => {
  await shell(page, 'printf content > input; exec 3<>/dev/null; (cat input; printf hidden >&3); cat <&3; sh -c "cat input; printf hidden >&3"; stat input >/dev/null; printf "stat:%s\\n" "$?"; printf restored');
  await expect(last(page)).toHaveText('contentcontentstat:0\nrestored');
  await shell(page, 'exec 3< input; cat <&3; cat input; printf done');
  await expect(last(page)).toHaveText('contentcontentdone');
});

test('exec preserves empty and newline arguments and environment without granting authority', async ({ page }) => {
  const { uid } = await call(page.request, 'getcreds');
  expect(uid).toBeGreaterThan(0);
  await shell(page, 'value=$(printf "two\\nlines"); /usr/bin/printf "<%s><%s>\\n" "" "$value"; export VALUE="$value"; sh -c "printenv VALUE"; id -u; cat /root/denied 2>/dev/null; printf "denied:%s" "$?"');
  await expect(last(page)).toHaveText(`<><two\nlines>\ntwo\nlines\n${uid}\ndenied:1`);
  const blocked = base + '/blocked';
  expect((await put(page.request, file(blocked), { data: 'not an executable' })).ok()).toBe(true);
  await call(page.request, { chmod: { path: blocked, mode: 0o600 } });
  await shell(page, './blocked 2>/dev/null; printf "exec:%s" "$?"');
  await expect(last(page)).toHaveText('exec:126');
});

test('Ctrl+C stops a continuous output child of the installed shell', async ({ page }) => {
  // A following command prevents dash's final-command exec optimization: parent waits.
  await page.locator('#command').fill('sh -c "yes; printf should-not-run"');
  await page.locator('#command').press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', /^(running|input)$/);
  await expect(last(page)).toContainText('y', { timeout: 60_000 });
  await page.locator('#command').press('Control+c');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 10_000 });
  await shell(page, 'printf recovered');
  await expect(last(page)).toHaveText('recovered');
});

test('installed interactive sh reads terminal input and returns to the browser prompt', async ({ page }) => {
  const input = page.locator('#command');
  await input.fill('sh -i'); await input.press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', 'input', { timeout: 60_000 });
  await input.fill('printf "interactive:%s\\n" ok'); await input.press('Enter');
  await expect(last(page)).toContainText('interactive:ok');
  await input.fill('exit'); await input.press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
  await shell(page, 'printf returned');
  await expect(last(page)).toHaveText('returned');
});

test('installed-image compilation returns a complete cached transform after authorization', async ({ page }) => {
  const url = '/api/file?path=/usr/bin/sh&compile=fork-v4';
  const response = await page.request.get(url, { headers: { Range: 'bytes=0-7', 'If-None-Match': '*' } });
  expect(response.status()).toBe(200);
  const bytes = await response.body();
  const module = await WebAssembly.compile(bytes);
  expect(WebAssembly.Module.exports(module).some(entry => entry.name === '__tw_functions')).toBe(true);
  expect(await (await page.request.get(url)).body()).toEqual(bytes);
  expect((await page.request.head(url)).status()).toBe(400);
  expect((await page.request.get(url, { headers: { 'X-Process-Token': 'invalid' } })).ok()).toBe(false);
});

test('modern WASIX validates exec pointers and preserves only non-CLOEXEC descriptors', async ({ page }) => {
  const child = base + '/child';
  const upload = async (path, wat) => {
    const module = binaryen.parseText(wat);
    try {
      expect((await put(page.request, file(path), { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true);
    } finally { module.dispose(); }
    await call(page.request, { chmod: { path, mode: 0o755 } });
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
  await run(page, './parent');
  await expect(last(page)).toHaveText('flags-ok');
});
