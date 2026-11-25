import { withoutJspi } from './transport.js';
import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, call, mkdirp, put, rmrf } from './sys.js';
import {
  cloudSignIn,
  execCmd,
  execSh,
  pageCall,
  pageMkdirp,
  pagePut,
  pageRmrf,
  runTerminal,
  switchLocalUser,
  terminalInput,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

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

async function execAs(page, stages, { cwd = base, sudo = false, stdin = '' } = {}) {
  const creds = await pageCall(page, 'getcreds');
  return page.evaluate(
    async ({ stages, cwd, sudo, stdin, user, home }) => {
      let stderr = '';
      const result = await window.os.exec(stages, {
        cwd,
        user,
        home,
        sudo,
        stdin,
        onOutput(fd, text) {
          if (fd === 2) stderr += text;
        },
      });
      return { ...result, stderr };
    },
    { stages, cwd, sudo, stdin, user: creds.user, home: creds.home },
  );
}
async function tryExec(page, stages, { cwd = base } = {}) {
  return page.evaluate(
    async ({ stages, cwd }) => {
      try {
        let stderr = '';
        const res = await window.os.exec(stages, {
          cwd,
          stdin: '',
          onOutput(fd, text) {
            if (fd === 2) stderr += text;
          },
        });
        return { status: res.status, stdout: res.stdout, stderr };
      } catch (error) {
        return { error: error.message };
      }
    },
    { stages, cwd },
  );
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
  await waitForTerminalReady(page);
  await switchLocalUser(page, 'root');
  await seedLocalFixtures(page);
}

test('an uploaded wasm runs by its path, with the working directory, environment and pipes', async ({ page }) => {
  await terminal(page);
  const seq = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'seq', '3'] }]);
  expect(seq.status, seq.stderr).toBe(0);
  expect(seq.stdout.trim()).toBe('1\n2\n3');
  // Its argv, its working directory and its account's environment are the process's.
  const pwd = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'pwd'] }]);
  expect(pwd.status, pwd.stderr).toBe(0);
  expect(pwd.stdout.trim()).toBe(base);
  const userEnv = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'printenv', 'USER'] }]);
  expect(userEnv.status, userEnv.stderr).toBe(0);
  expect(userEnv.stdout.trim()).toBe('root');
  // Full os.sys as the caller: getcreds says whom it was executed as.
  const credsRes = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'syscall', '["getcreds"]'] }]);
  expect(credsRes.status, credsRes.stderr).toBe(0);
  expect(JSON.parse(credsRes.stdout).results[0].ok.user).toBe('root');
  // Two of them in one pipeline, each a process, and an in-page head closing the pipe.
  const pipe1 = await execAs(page, [
    { path: `${base}/coreutils`, argv: ['./coreutils', 'seq', '9'] },
    { path: `${base}/coreutils`, argv: ['./coreutils', 'tail', '-n', '2'] },
  ]);
  expect(pipe1.status, pipe1.stderr).toBe(0);
  expect(pipe1.stdout.trim()).toBe('8\n9');
  const pipe2 = await execAs(page, [
    { path: `${base}/coreutils`, argv: ['./coreutils', 'seq', '3'] },
    { path: '/usr/bin/head', argv: ['head', '-n', '2'] },
  ]);
  expect(pipe2.status, pipe2.stderr).toBe(0);
  expect(pipe2.stdout.trim()).toBe('1\n2');
  // Its module is compiled once per content: the same file runs again from the cache.
  const before = await page.evaluate(() => window.loaderStats.compiled);
  await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'seq', '1'] }]);
  await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'seq', '2'] }]);
  expect(await page.evaluate(() => window.loaderStats.compiled)).toBe(before);
  // A nonzero status is the process's; the next command still runs.
  const failed = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'false'] }]);
  expect(failed.status).toBe(1);
  const alive = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'echo', 'alive'] }]);
  expect(alive.status, alive.stderr).toBe(0);
  expect(alive.stdout.trim()).toBe('alive');
  // Ctrl+C kills it, as a process's.
  await runTerminal(page, `cd ${base}`);
  await runTerminal(page, './coreutils sleep 30', { wait: false });
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await page.waitForTimeout(500);
  await terminalInput(page).press('Control+c');
  await expect(terminalViewport(page)).toHaveAttribute('data-state', 'idle', { timeout: 10_000 });
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
  await waitForTerminalReady(page);
  test.skip(jspi && !await hasJspi(page), 'this browser has no JSPI');
  await cloudSignIn(page, 'root', password);
  const cloudDir = '/mnt/cloud' + cloudBase;
  const copied = await execSh(page, './coreutils cat big.txt | ./coreutils tee copy.txt | ./coreutils wc -l', { cwd: cloudDir });
  expect(copied.status, copied.stderr).toBe(0);
  expect(copied.stderr).not.toContain('Bad file descriptor');
  expect(await (await request.get(file(`${cloudBase}/copy.txt`))).text()).toBe(big);
  // What it reads comes back as written: a range of it past the first window, and a pipeline.
  const tail = await execCmd(page, [`${cloudDir}/coreutils`, 'tail', '-c', '37', 'copy.txt'], { cwd: cloudDir });
  expect(tail.status, tail.stderr).toBe(0);
  expect(tail.stdout.trim()).toBe('abcdefghijklmnopqrstuvwxyz0123456789');
  const lines = await execSh(page, './coreutils cat copy.txt | ./coreutils wc -l', { cwd: cloudDir });
  expect(lines.status, lines.stderr).toBe(0);
  expect(lines.stdout.trim()).toBe('10000');
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
  const initRes = await execCmd(page, [`${base}/started`], { cwd: base });
  expect(initRes.status, initRes.stderr).toBe(0);
  expect(initRes.stdout.trim()).toBe('started\nran');
  expect([...calls]).toEqual(['fetch']);
});

test('the loader and the X rule refuse as Linux refuses, with its words', async ({ page }) => {
  await terminal(page);
  // A text file with the execute bit is not a program; a wasm-looking name does not help it.
  expect((await tryExec(page, [{ path: `${base}/script.sh`, argv: ['./script.sh'] }])).error).toContain('./script.sh: Exec format error');
  // Imports the engine does not give, no entry point, no memory: ENOEXEC, saying why.
  expect((await tryExec(page, [{ path: `${base}/bad-import`, argv: ['./bad-import'] }])).error).toContain('./bad-import: cannot execute binary file: Exec format error (unknown import foo.bar)');
  expect((await tryExec(page, [{ path: `${base}/no-start`, argv: ['./no-start'] }])).error).toContain('./no-start: cannot execute binary file: Exec format error (no _start)');
  expect((await tryExec(page, [{ path: `${base}/no-memory`, argv: ['./no-memory'] }])).error).toContain('./no-memory: cannot execute binary file: Exec format error (no memory)');
  // The X rule, for root too: 0644 is EACCES, a directory EISDIR/EACCES, a missing name ENOENT.
  expect((await tryExec(page, [{ path: `${base}/plain`, argv: ['./plain'] }])).error).toContain('./plain: Permission denied');
  expect((await tryExec(page, [{ path: `${base}/sub`, argv: ['./sub', 'argument'] }])).error).toContain('./sub: Permission denied');
  expect((await tryExec(page, [{ path: `${base}/missing`, argv: ['./missing'] }])).error).toContain('./missing: No such file or directory');
  // An x-only file runs: its image is read by the exec token, never by path.
  const xOnly = await tryExec(page, [{ path: `${base}/x/coreutils`, argv: ['./x/coreutils', 'seq', '2'] }]);
  expect(xOnly.status, xOnly.stderr).toBe(0);
  expect(xOnly.stdout.trim()).toBe('1\n2');
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
    const creds = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'syscall', '["getcreds"]'] }]);
    expect(creds.status, creds.stderr).toBe(0);
    expect(JSON.parse(creds.stdout).results[0].ok.user).toBe(name);
    // A process cannot mutate the browser's session.
    const logout = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'syscall', '[{"logout":null}]'] }]);
    expect(logout.status, logout.stderr).toBe(0);
    expect(JSON.parse(logout.stdout).results[0].err.errno).toBe('EPERM');
    const who = await execAs(page, [{ path: '/usr/bin/whoami', argv: ['whoami'] }]);
    expect(who.status, who.stderr).toBe(0);
    expect(who.stdout.trim()).toBe(name);
  } finally {
    await switchLocalUser(page, 'root').catch(() => {});
    await pageCall(page, { userdel: { name, remove: false } }).catch(() => {});
    await pageCall(page, { groupdel: { name } }).catch(() => {});
  }
});

test('a pipeline answers its last stage\'s status, in whatever order its processes end', async ({ page }) => {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
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
  const failed = await tryExec(page, [
    { path: `${base}/bad-import`, argv: ['./bad-import'] },
    { path: `${base}/coreutils`, argv: ['./coreutils', 'sleep', '5'] },
  ]);
  expect(failed.error).toContain('./bad-import: cannot execute binary file: Exec format error');
  await page.waitForTimeout(1_000);
  const ps = await execCmd(page, ['/usr/bin/ps']);
  expect(ps.status, ps.stderr).toBe(0);
  expect(ps.stdout).not.toContain('bad-import');
  expect(ps.stdout).not.toContain('sleep 5');
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
    // Ordinary execution runs as the wheel user, not root.
    const ordinary = await execAs(page, [{ path: `${base}/coreutils`, argv: ['./coreutils', 'syscall', '["getcreds"]'] }]);
    expect(ordinary.status, ordinary.stderr).toBe(0);
    expect(JSON.parse(ordinary.stdout).results[0].ok.user).toBe(name);
    // A path with a slash: the stage the non-sudo shell runs, with sudo snapshotted at exec (wheel NOPASSWD).
    const sudoPath = await execAs(page, [{ path: '/usr/bin/sudo', argv: ['sudo', './coreutils', 'syscall', '["getcreds"]'] }]);
    expect(sudoPath.status, sudoPath.stderr).toBe(0);
    expect(JSON.parse(sudoPath.stdout).results[0].ok.user).toBe('root');
    // A bare coreutils applet goes the same way.
    const sudoApplet = await execAs(page, [{ path: '/usr/bin/sudo', argv: ['sudo', 'syscall', '["getcreds"]'] }]);
    expect(sudoApplet.status, sudoApplet.stderr).toBe(0);
    expect(JSON.parse(sudoApplet.stdout).results[0].ok.user).toBe('root');
  } finally {
    await switchLocalUser(page, 'root').catch(() => {});
    await pageCall(page, { userdel: { name, remove: true } }).catch(() => {});
    await pageCall(page, { groupdel: { name } }).catch(() => {});
  }
});
