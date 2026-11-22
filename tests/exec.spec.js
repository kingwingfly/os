import { withoutJspi } from './transport.js';
import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, call, mkdirp, put, rmrf } from './sys.js';
import { cloudSignIn, pageCall, pageMkdirp, pagePut, pageRmrf, switchLocalUser } from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || 'test-admin-password-w4b';
const binaryen = (await import('binaryen')).default;
const coreutils = await readFile('dist/usr/bin/coreutils.wasm');
const file = path => '/api/file?path=' + encodeURIComponent(path);
const assemble = wat => Buffer.from(binaryen.parseText(wat).emitBinary());
let base, cloudBase, headers;

// Uploaded wasm, execve'd by its path (issue #20, phase 2): any path with the execute bit runs,
// the loader compiles it once per content, and the kernel's rules hold as for any file: the X
// rule, no setuid, no session of its own. The fixtures are the build's own coreutils, WAT
// modules assembled here, and plain text.
const BAD_IMPORT = assemble('(module (import "foo" "bar" (func)) (memory 1) (func (export "_start")))');
const NO_START = assemble('(module (memory 1))');
const NO_MEMORY = assemble('(module (func (export "_start")))');
// WASIX's shape: an imported memory with its own limits, rather than an exported one. The
// loader must give the process a memory of that type (initial 3), not a fixed two pages.
const IMPORTED_MEMORY = assemble('(module (import "env" "memory" (memory 3 4)) (func (export "_start")))');
const WRONG_MEMORY_NAME = assemble('(module (memory 1) (export "mem" (memory 0)) (func (export "_start")))');
const MEMORY_AS_FUNCTION = assemble('(module (import "env" "memory" (func)) (memory 1) (func (export "_start")))');
const SCRIPT = Buffer.from('echo no\n');

test.beforeEach(async ({ page }) => {
  base = '/exec-' + Date.now().toString(36);
  cloudBase = null;
  headers = { Origin: origin, 'CF-Connecting-IP': 'exec-' + base };
  await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'exec-ui-' + base });
});
test.afterEach(async ({ request, page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
  if (cloudBase) await rmrf(request, cloudBase).catch(() => {});
});

const transcript = page => page.locator('.transcript');
// Screen wrapping inserts visual newlines, including inside JSON string tokens.
const processJson = async page => JSON.parse((await page.locator('.transcript pre').last().innerText()).replaceAll('\n', ''));
// Run `text` to its end, as bin.spec's does.
async function run(page, text, { wait = true } = {}) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form');
  await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await input.fill(text); await input.press('Enter');
  if (wait) await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
}
async function seedLocalFixtures(page) {
  await pageMkdirp(page, base, 0o755, { sudo: true });
  const upload = async (name, data, mode = 0o755) => {
    await pagePut(page, `${base}/${name}`, data, { mode, sudo: true });
  };
  await upload('coreutils', coreutils);
  await upload('script.sh', SCRIPT);
  await upload('bad-import', BAD_IMPORT);
  await upload('no-start', NO_START);
  await upload('no-memory', NO_MEMORY);
  await upload('import-memory', IMPORTED_MEMORY);
  await upload('wrong-memory', WRONG_MEMORY_NAME);
  await upload('memory-func', MEMORY_AS_FUNCTION);
  await upload('plain', coreutils, 0o644);
  await pageMkdirp(page, `${base}/x`, 0o755, { sudo: true });
  await upload('x/coreutils', coreutils, 0o111);
  await pageMkdirp(page, `${base}/sub`, 0o755, { sudo: true });
}
async function terminal(page) {
  await page.goto('/');
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await switchLocalUser(page, 'root');
  await seedLocalFixtures(page);
  await run(page, 'cd ' + base);
}

test('an uploaded wasm runs by its path, with the working directory, environment and pipes', async ({ page }) => {
  await terminal(page);
  await run(page, './coreutils seq 3');
  await expect(page.locator('.transcript pre').last()).toHaveText('1\n2\n3');
  // Its argv, its working directory and its account's environment are the process's.
  await run(page, './coreutils pwd');
  await expect(page.locator('.transcript pre').last()).toHaveText(base);
  await run(page, './coreutils printenv USER');
  await expect(page.locator('.transcript pre').last()).toHaveText('root');
  // Full os.sys as the caller: getcreds says whom it was executed as.
  await run(page, `./coreutils syscall '["getcreds"]'`);
  expect((await processJson(page)).results[0].ok.user).toBe('root');
  // Two of them in one pipeline, each a process, and an in-page head closing the pipe.
  await run(page, './coreutils seq 9 | ./coreutils tail -n 2');
  await expect(page.locator('.transcript pre').last()).toHaveText('8\n9');
  await run(page, './coreutils seq 3 | head -n 2');
  await expect(page.locator('.transcript pre').last()).toHaveText('1\n2');
  // Its module is compiled once per content: the same file runs again from the cache.
  const before = await page.evaluate(() => window.loaderStats.compiled);
  await run(page, './coreutils seq 1');
  await run(page, './coreutils seq 2');
  expect(await page.evaluate(() => window.loaderStats.compiled)).toBe(before);
  // A nonzero status is the process's; the next command still runs.
  await run(page, './coreutils false');
  await run(page, './coreutils echo alive');
  await expect(page.locator('.transcript pre').last()).toHaveText('alive');
  // Ctrl+C kills it, as a process's.
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form');
  await input.fill('./coreutils sleep 30'); await input.press('Enter');
  await expect(busy).not.toHaveAttribute('data-state', 'idle');
  await page.waitForTimeout(500);
  await input.press('Control+c');
  await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 5_000 });
});

// Under L2/#54 + Wave 4B, worker runtime calls to `/mnt/cloud` bridge to client-kernel via
// Atomics/JSPI and hit `/api/fs` & `/api/fs/data` via fetch (never raw XHR or legacy `/api/sys` process writes).
function processCalls(page) {
  const kinds = new Set();
  page.context().on('request', request => {
    if (request.method() !== 'POST') return;
    const path = new URL(request.url()).pathname;
    if (path === '/api/fs' || path === '/api/fs/data') {
      if (request.headers()['x-os-instance']) kinds.add(request.resourceType());
      return;
    }
    if (path !== '/api/sys' || request.headers()['x-registry']) return;
    const body = JSON.parse(request.postData() || '{}');
    if (body.proc && body.calls?.some(call => !call.resource)) kinds.add(request.resourceType());
  });
  return kinds;
}
const hasJspi = page => page.evaluate(() => typeof WebAssembly.Suspending === 'function' && typeof WebAssembly.promising === 'function');

for (const jspi of [true, false]) test(`a process writes a file larger than a batch carries, through its own descriptor (${jspi ? 'JSPI' : 'synchronous XHR'})`, async ({ page, request }) => {
  // Past abi::INLINE_MAX (256 KiB), a process's write to `/mnt/cloud` streams through its own
  // `/api/fs/data` descriptor with its ServiceAuth v2 credential. Calls bridge through
  // client-kernel via fetch whether the process Worker runs with JSPI or synchronous fallback.
  if (!jspi) await withoutJspi(page);
  const calls = processCalls(page);
  cloudBase = '/exec-cloud-' + Date.now().toString(36);
  const big = 'abcdefghijklmnopqrstuvwxyz0123456789\n'.repeat(10_000);
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, cloudBase, 0o755);
  expect((await put(request, file(`${cloudBase}/coreutils`), { headers, data: coreutils })).status()).toBe(201);
  expect(await call(request, { chmod: { path: `${cloudBase}/coreutils`, mode: 0o755 } }, { headers })).toBeNull();
  expect((await put(request, file(`${cloudBase}/big.txt`), { headers, data: big })).status()).toBe(201);
  await page.goto('/');
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  test.skip(jspi && !await hasJspi(page), 'this browser has no JSPI');
  await cloudSignIn(page, 'root', password);
  await run(page, 'cd /mnt/cloud' + cloudBase);
  await run(page, './coreutils cat big.txt | ./coreutils tee copy.txt | ./coreutils wc -l');
  await expect(page.locator('.transcript')).not.toContainText('Bad file descriptor');
  expect(await (await request.get(file(`${cloudBase}/copy.txt`))).text()).toBe(big);
  // What it reads comes back as written: a range of it past the first window, and a pipeline.
  await run(page, './coreutils tail -c 37 copy.txt');
  await expect(page.locator('.transcript pre').last()).toHaveText('abcdefghijklmnopqrstuvwxyz0123456789');
  await run(page, './coreutils cat copy.txt | ./coreutils wc -l');
  await expect(page.locator('.transcript pre').last()).toHaveText('10000');
  // Under L2/#54, worker runtime calls bridge to client-kernel via Atomics/JSPI and hit `/api/fs` via fetch (never raw XHR).
  expect([...calls]).toEqual(['fetch']);
});

test('an image initializer runs once before main after resource instrumentation', async ({ page, request }) => {
  // The resource transform moves the initializer into the prepared entry point,
  // where JSPI can suspend it. Its imported memory and before-main order remain.
  cloudBase = '/exec-init-' + Date.now().toString(36);
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, cloudBase, 0o755);
  expect((await put(request, file(`${cloudBase}/coreutils`), { headers, data: coreutils })).status()).toBe(201);
  const cloudTarget = `mnt/cloud${cloudBase}/coreutils`;
  const started = assemble(`(module
    (import "env" "memory" (memory 1 2))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_filestat_get" (func $stat (param i32 i32 i32 i32 i32) (result i32)))
    (data (i32.const 1024) "started\\n") (data (i32.const 1040) "ran\\n") (data (i32.const 1056) "usr/bin/coreutils")
    (data (i32.const 1120) "${cloudTarget}")
    (func $say (param $ptr i32) (param $len i32)
      (i32.store (i32.const 2048) (local.get $ptr)) (i32.store (i32.const 2052) (local.get $len))
      (drop (call $write (i32.const 1) (i32.const 2048) (i32.const 1) (i32.const 2056))))
    (func $begin (call $say (i32.const 1024) (i32.const 8)))
    (start $begin)
    (func (export "_start")
      (if (i32.and
        (i32.eqz (call $stat (i32.const 3) (i32.const 1) (i32.const 1056) (i32.const 17) (i32.const 3000)))
        (i32.eqz (call $stat (i32.const 3) (i32.const 1) (i32.const 1120) (i32.const ${cloudTarget.length}) (i32.const 3200))))
        (then (call $say (i32.const 1040) (i32.const 4))))))`);
  const calls = processCalls(page);
  await terminal(page);
  await cloudSignIn(page, 'root', password);
  await pagePut(page, `${base}/started`, started, { mode: 0o755, sudo: true });
  await run(page, './started');
  await expect(page.locator('.transcript pre').last()).toHaveText('started\nran');
  expect([...calls]).toEqual(['fetch']);
});

test('the loader and the X rule refuse as Linux refuses, with its words', async ({ page }) => {
  await terminal(page);
  // A text file with the execute bit is not a program; a wasm-looking name does not help it.
  await run(page, './script.sh');
  await expect(transcript(page)).toContainText('./script.sh: Exec format error');
  // Imports the engine does not give, no entry point, no memory: ENOEXEC, saying why.
  await run(page, './bad-import');
  await expect(transcript(page)).toContainText('./bad-import: cannot execute binary file: Exec format error (unknown import foo.bar)');
  await run(page, './no-start');
  await expect(transcript(page)).toContainText('./no-start: cannot execute binary file: Exec format error (no _start)');
  await run(page, './no-memory');
  await expect(transcript(page)).toContainText('./no-memory: cannot execute binary file: Exec format error (no memory)');
  // The X rule, for root too: 0644 is EACCES, a directory EISDIR, a missing name ENOENT.
  await run(page, './plain');
  await expect(transcript(page)).toContainText('./plain: Permission denied');
  // An argument requests execution; a directory alone now performs implicit cd.
  await run(page, './sub argument');
  await expect(transcript(page)).toContainText('./sub: Permission denied');
  await run(page, './missing');
  await expect(transcript(page)).toContainText('./missing: No such file or directory');
  // An x-only file runs: its image is read by the exec token, never by path.
  await run(page, './x/coreutils seq 2');
  await expect(page.locator('.transcript pre').last()).toHaveText('1\n2');
});

test('setuid on an upload does not elevate, and a process cannot sign the browser out', async ({ page }) => {
  const name = 'execann' + Date.now().toString(36), annPassword = 'exec-password-' + Date.now();
  await terminal(page);
  await pageCall(page, { useradd: { name, create_home: false } });
  try {
    await pageCall(page, { passwd: { username: name, password: annPassword, force: true } });
    // root's upload, made setuid by root, still runs as whom it was executed by, not as root.
    await pageCall(page, { chmod: { path: `${base}/coreutils`, mode: 0o4755 } });
    await switchLocalUser(page, name, { password: annPassword, sudo: false });
    await run(page, `cd ${base}`);
    await run(page, `./coreutils syscall '["getcreds"]'`);
    expect((await processJson(page)).results[0].ok.user).toBe(name);
    // A process cannot mutate the browser's session.
    await run(page, `./coreutils syscall '[{"logout":null}]'`);
    expect((await processJson(page)).results[0].err.errno).toBe('EPERM');
    await run(page, 'whoami');
    await expect(page.locator('.transcript pre').last()).toHaveText(name);
    await run(page, 'exit');
  } finally {
    await switchLocalUser(page, 'root').catch(() => {});
    await pageCall(page, { userdel: { name, remove: false } }).catch(() => {});
    await pageCall(page, { groupdel: { name } }).catch(() => {});
  }
});

test('a pipeline answers its last stage\'s status, in whatever order its processes end', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  const status = stages => page.evaluate(async stages => {
    const options = { cwd: '/', home: '/root', user: 'root', tty: false };
    return (await window.os.exec(stages, options)).status;
  }, stages);
  // The last stage ends first: its status is the last's, not the one that finished first.
  expect(await status([{ argv: ['false'] }, { argv: ['sleep', '0.4'] }])).toBe(0);
  expect(await status([{ argv: ['sleep', '0.4'] }, { argv: ['false'] }])).toBe(1);
});

test('a stage that cannot load leaves no process, and its siblings end with the pipeline', async ({ page }) => {
  await terminal(page);
  // The first stage's image is not a program: the load fails after execve. The second, already
  // given a process, must not run on unkilled, and neither may stay for the next boot.
  await run(page, './bad-import | ./coreutils sleep 5');
  await expect(transcript(page)).toContainText('./bad-import: cannot execute binary file: Exec format error');
  await page.waitForTimeout(1_000);
  await run(page, 'ps');
  const listed = await page.locator('.transcript pre').last().innerText();
  expect(listed).not.toContain('bad-import');
  expect(listed).not.toContain('sleep 5');
});

test('the loader reads a memory import\'s own limits, and refuses wrong names and kinds', async ({ page }) => {
  await terminal(page);
  const load = path => page.evaluate(async path => {
    try {
      return { status: (await window.os.exec([{ path, argv: [path] }], {})).status };
    } catch (error) {
      return { error: error.message };
    }
  }, path);
  // An imported memory of three pages links: a fixed two-page memory of the old loader did not.
  expect(await load(`${base}/import-memory`)).toEqual({ status: 0 });
  // The only memory is env.memory, and only as a memory; a module exports one as exactly
  // `memory` to be run.
  expect((await load(`${base}/wrong-memory`)).error).toContain('Exec format error (no memory)');
  expect((await load(`${base}/memory-func`)).error).toContain('Exec format error (unknown import env.memory)');
});

test('sudo snapshots root for an exec of a path or a coreutils applet', async ({ page }) => {
  const name = 'execwheel' + Date.now().toString(36);
  const wheelPassword = 'exec-wheel-password-' + Date.now();
  await terminal(page);
  await pageCall(page, { useradd: { name, create_home: true, groups: 'wheel' } });
  try {
    await pageCall(page, { passwd: { username: name, password: wheelPassword, force: true } });
    await switchLocalUser(page, name, { password: wheelPassword, sudo: false });
    await run(page, 'cd ' + base);
    // Ordinary execution runs as the wheel user, not root.
    await run(page, `./coreutils syscall '["getcreds"]'`);
    expect((await processJson(page)).results[0].ok.user).toBe(name);
    // A path with a slash: the stage the non-sudo shell runs, with sudo snapshotted at exec (wheel NOPASSWD).
    await run(page, `sudo ./coreutils syscall '["getcreds"]'`);
    expect((await processJson(page)).results[0].ok.user).toBe('root');
    // A bare coreutils applet goes the same way.
    await run(page, `sudo syscall '["getcreds"]'`);
    expect((await processJson(page)).results[0].ok.user).toBe('root');
  } finally {
    await switchLocalUser(page, 'root').catch(() => {});
    await pageCall(page, { userdel: { name, remove: true } }).catch(() => {});
    await pageCall(page, { groupdel: { name } }).catch(() => {});
  }
});
