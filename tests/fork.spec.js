import { test, expect } from '@playwright/test';

// Phase 3 and the owner's change request 1 (2026-11-02): each browser's processes are its own
// machine's, a Durable Object apart from the filesystem's one authority (crates/worker/src/
// machine.rs). Only execve asks the authority, a pipeline's stages in one request. A fork takes
// a pid the machine lent the client kernel ahead of time; forks, exits and waits happen in the
// client kernel (crates/client-kernel) and are told to the machine in batches. An orphan is
// init's; a zombie orphan, init reaps.

// A port to the browser's client kernel, kept on the page: its SharedWorker, or, where the page
// has none, a dedicated Worker of its own.
async function connect(page) {
  await page.evaluate(() => {
    const shared = typeof SharedWorker === 'function';
    const worker = shared ? new SharedWorker('/client-kernel.js') : new Worker('/client-kernel.js');
    const port = shared ? worker.port : worker;
    const pending = new Map();
    let next = 0;
    port.onmessage = ({ data }) => {
      if (data?.id != null && pending.has(data.id)) {
        pending.get(data.id)(data);
        pending.delete(data.id);
      }
    };
    if (shared) port.start();
    window.__kernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      port.postMessage({ v: 1, id, type, args });
    });
  });
}
const call = (page, type, args = {}) => page.evaluate(([type, args]) => window.__kernel(type, args), [type, args]);
function value(reply) {
  expect(reply.err, JSON.stringify(reply.err)).toBeUndefined();
  return reply.ok;
}
const ENV = ['PWD=/', 'PATH=/usr/bin', 'LANG=C.UTF-8'];
const sleep = { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'], env: ENV, cwd: '/' };

// The terminal, as a person types into it.
async function command(page, text) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form').locator('.busy');
  await expect(busy).toHaveText('↵');
  await input.fill(text); await input.press('Enter');
  await expect(busy).toHaveText('↵', { timeout: 30_000 });
}

test('fork is the kernel\'s: its child is told after; an orphan is init\'s, and a zombie orphan init reaps', async ({ browser }) => {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    await page.goto('/');
    await connect(page);
    value(await call(page, 'init'));
    const parent = value(await call(page, 'exec', sleep));
    const child = value(await call(page, 'fork', { pid: parent.pid }));
    expect(child.pid).not.toBe(parent.pid);
    // The child acts as its parent was executed: the same credentials, the same token.
    expect(child.token).toBe(parent.token);
    expect(value(await call(page, 'getpid', { pid: child.pid }))).toEqual({ pid: child.pid, ppid: parent.pid });
    // The machine heard of it by the next request it got.
    const [seen] = value(await call(page, 'poll', { pids: [child.pid] }));
    expect([seen.pid, seen.ppid, seen.state, seen.argv]).toEqual([child.pid, parent.pid, 'running', sleep.argv]);
    // A grandchild; its parent ends, and it is init's.
    const grandchild = value(await call(page, 'fork', { pid: child.pid }));
    value(await call(page, 'exit', { pid: child.pid, status: 3 }));
    expect(value(await call(page, 'getpid', { pid: grandchild.pid }))).toEqual({ pid: grandchild.pid, ppid: 1 });
    const [orphan] = value(await call(page, 'poll', { pids: [grandchild.pid] }));
    expect(orphan.ppid).toBe(1);
    // The child is a zombie until its parent waits; its parent ends instead, and init reaps it.
    const [zombie] = value(await call(page, 'poll', { pids: [child.pid] }));
    expect(zombie.state).toBe('zombie');
    value(await call(page, 'exit', { pid: parent.pid, status: 0 }));
    expect(value(await call(page, 'wait', { pid: parent.pid })).status).toBe(0);
    expect(value(await call(page, 'poll', { pids: [parent.pid, child.pid] }))).toEqual([]);
    // What init has, it waits for.
    value(await call(page, 'exit', { pid: grandchild.pid, status: 0, signal: 15 }));
    expect(value(await call(page, 'wait', { pid: grandchild.pid })).status).toBe(15);
    expect(value(await call(page, 'poll', { pids: [grandchild.pid] }))).toEqual([]);
    // Init ignores what it has no handler for, as Linux's does; it is not the account's to signal.
    expect((await call(page, 'kill', { pid: 1, signal: 9 })).err.errno).toBe('EPERM');
    // The namespace has room for so many: forks past it fail, as fork(2) does (EAGAIN).
    const many = value(await call(page, 'exec', sleep));
    let refused;
    for (let i = 0; i < 70 && !refused; i++) {
      const forked = await call(page, 'fork', { pid: many.pid });
      if (forked.err) refused = forked.err;
    }
    expect(refused?.errno).toBe('EAGAIN');
  } finally { await context.close(); }
});

test('a pipeline\'s stages are one execve, to the browser\'s machine; nothing else of a process goes to the authority', async ({ browser }) => {
  // A kernel of the tab's own, whose requests the page sees.
  const context = await browser.newContext();
  await context.addInitScript(() => { delete globalThis.SharedWorker; });
  try {
    const page = await context.newPage();
    const sent = [];
    page.on('request', request => {
      if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/sys') {
        sent.push({ registry: request.headers()['x-registry'] === '1', body: request.postData() ?? '' });
      }
    });
    await page.goto('/');
    await command(page, 'seq 1');
    sent.length = 0;
    await command(page, 'seq 3 | tr 123 abc | coreutils cat');
    await expect(page.locator('.transcript pre').last()).toHaveText('a\nb\nc');
    // Exits and waits are told a moment after.
    await expect.poll(() => sent.filter(one => one.body.includes('"wait"')).length).toBeGreaterThan(0);
    const execs = sent.filter(one => one.body.includes('"execve"'));
    expect(execs).toHaveLength(1);
    expect(execs[0].registry).toBe(true);
    expect(JSON.parse(execs[0].body).calls.filter(one => one.execve)).toHaveLength(3);
    const lifecycle = /"(execve|exit|wait|fork|proc_init|pids|seats|gone)"/;
    expect(sent.filter(one => !one.registry && lifecycle.test(one.body))).toEqual([]);
    // A fork asks once to be lent pids, and not again for the next ones.
    await connect(page);
    value(await call(page, 'init'));
    const parent = value(await call(page, 'exec', sleep));
    sent.length = 0;
    const forks = [];
    for (let i = 0; i < 3; i++) forks.push(value(await call(page, 'fork', { pid: parent.pid })));
    expect(sent.filter(one => one.body.includes('"pids":{'))).toHaveLength(1);
    for (const child of [...forks, parent]) {
      value(await call(page, 'exit', { pid: child.pid, status: 0 }));
      value(await call(page, 'wait', { pid: child.pid }));
    }
    // The machine heard of each fork in a batch.
    const told = sent.filter(one => one.body.includes('"fork"'));
    expect(told.length).toBeGreaterThan(0);
    expect(told.every(one => one.registry)).toBe(true);
  } finally { await context.close(); }
});

test('each browser is a machine of its own, and the machine takes only the registry\'s calls', async ({ browser }) => {
  const [first, second] = [await browser.newContext(), await browser.newContext()];
  try {
    const one = await first.newPage(), two = await second.newPage();
    await one.goto('/'); await two.goto('/');
    await connect(one); await connect(two);
    const a = value(await call(one, 'init')), b = value(await call(two, 'init'));
    expect(a.namespace).not.toBe(b.namespace);
    const running = value(await call(one, 'exec', sleep));
    // The other browser's pid 1 is its own init; its table has no process of the first's.
    const theirs = value(await call(two, 'poll', { pids: [] }));
    expect(theirs.map(process => process.argv)).not.toContainEqual(sleep.argv);
    expect(theirs.find(process => process.pid === 1)?.argv).toEqual(['init']);
    // A token is its browser's: another's process token is no credential there.
    const [foreign] = await two.evaluate(async ([pid, proc]) => {
      const response = await fetch('/api/sys', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ calls: [{ getdents: { path: '/' } }], pid, proc }) });
      return (await response.json()).results;
    }, [running.pid, running.token]);
    expect(foreign.err.errno).toBe('EPERM');
    // The filesystem's calls are not the machine's.
    const [refused] = await one.evaluate(async () => {
      const response = await fetch('/api/sys', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Registry': '1' }, body: JSON.stringify({ calls: ['getcreds'] }) });
      return (await response.json()).results;
    });
    expect(refused.err.errno).toBe('ENOSYS');
    // init is everyone's to see, in /proc too.
    await command(one, 'cat /proc/1/status');
    await expect(one.locator('.transcript pre').last()).toContainText(/Name:\s+init/);
    value(await call(one, 'exit', { pid: running.pid, status: 0 }));
    value(await call(one, 'wait', { pid: running.pid }));
  } finally { await first.close(); await second.close(); }
});

// ---- Fork in the terminal's own processes (phase 3): WASIX's fork, execve, wait, pipe and
// setjmp, for any wasm. The fixtures are WAT modules assembled here, which import WASIX's calls
// and were not built for fork: the loader adds asyncify as it loads them. `WASIX_DASH`, if set,
// names the approved WASIX dash (sharrattj/dash@1.0.19), which is not committed.

const binaryen = (await import('binaryen')).default;
const { readFile } = await import('node:fs/promises');
const { api, call: sysCall, mkdirp, put, rmrf } = await import('./sys.js');
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const assemble = wat => Buffer.from(binaryen.parseText(wat).emitBinary());

// A module of WASIX's: its imports, a memory of its own, a shadow stack, and `say`, which
// writes `len` bytes at `ptr` to standard output.
const wasix = (imports, body, data = '') => assemble(`(module
  (import "wasix_32v1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "proc_exit" (func $exit (param i32)))
  ${imports}
  (memory (export "memory") 2)
  (global $sp (mut i32) (i32.const 65536))
  (export "__stack_pointer" (global $sp))
  ${data}
  (func $say (param $ptr i32) (param $len i32)
    (i32.store (i32.const 2048) (local.get $ptr))
    (i32.store (i32.const 2052) (local.get $len))
    (drop (call $write (i32.const 1) (i32.const 2048) (i32.const 1) (i32.const 2056))))
  (func (export "_start") ${body} (call $exit (i32.const 0))))`);
const FORK = '(import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))';
const JOIN = '(import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))';
// Wait for the child whose pid is at 2060: its status at 2080 (tag, then the code at 2082).
const WAIT_CHILD = `(i32.store8 (i32.const 2064) (i32.const 1))
    (i32.store (i32.const 2068) (i32.load (i32.const 2060)))
    (drop (call $join (i32.const 2064) (i32.const 0) (i32.const 2080)))`;
// The child says "child" and exits 7; the parent waits for it, and says "parent 7" if its
// status says it exited 7, else "wrong". Then, rewound from the fork, it asks the kernel (a
// stat of /usr/bin/coreutils, which JSPI suspends it on), and says "stat" if it is there.
const FORK_WAIT = wasix(`${FORK} ${JOIN}
  (import "wasix_32v1" "path_filestat_get" (func $stat (param i32 i32 i32 i32 i32) (result i32)))`, `
    (drop (call $fork (i32.const 1) (i32.const 2060)))
    (if (i32.eqz (i32.load (i32.const 2060)))
      (then (call $say (i32.const 1024) (i32.const 6)) (call $exit (i32.const 7))))
    ${WAIT_CHILD}
    (if (i32.and (i32.eq (i32.load8_u (i32.const 2080)) (i32.const 1)) (i32.eq (i32.load16_u (i32.const 2082)) (i32.const 7)))
      (then (call $say (i32.const 1040) (i32.const 9)))
      (else (call $say (i32.const 1056) (i32.const 6))))
    (if (i32.eqz (call $stat (i32.const 3) (i32.const 1) (i32.const 1104) (i32.const 17) (i32.const 3000)))
      (then (call $say (i32.const 1072) (i32.const 5))))`,
'(data (i32.const 1024) "child\\n") (data (i32.const 1040) "parent 7\\n") (data (i32.const 1056) "wrong\\n") (data (i32.const 1072) "stat\\n") (data (i32.const 1104) "usr/bin/coreutils")');
// The child executes coreutils' echo, by its bare name, as PATH finds it (a stat for each of
// PATH's directories, which JSPI suspends it on, before the image is replaced); the parent waits,
// and says "parent". A second child executes a name PATH has not: it ends with 127, as a shell's
// child does, and its parent says "missing" if its status says so.
const FORK_EXEC = wasix(`${FORK} ${JOIN}
  (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))`, `
    (drop (call $fork (i32.const 1) (i32.const 2060)))
    (if (i32.eqz (i32.load (i32.const 2060)))
      (then (call $exec (i32.const 1104) (i32.const 9) (i32.const 1104) (i32.const 23))))
    ${WAIT_CHILD}
    (call $say (i32.const 1200) (i32.const 7))
    (drop (call $fork (i32.const 1) (i32.const 2060)))
    (if (i32.eqz (i32.load (i32.const 2060)))
      (then (call $exec (i32.const 1300) (i32.const 15) (i32.const 1300) (i32.const 15))))
    ${WAIT_CHILD}
    (if (i32.and (i32.eq (i32.load8_u (i32.const 2080)) (i32.const 1)) (i32.eq (i32.load16_u (i32.const 2082)) (i32.const 127)))
      (then (call $say (i32.const 1216) (i32.const 8))))`,
'(data (i32.const 1104) "coreutils\\necho\\nexecuted") (data (i32.const 1200) "parent\\n") (data (i32.const 1216) "missing\\n") (data (i32.const 1300) "no-such-program")');
// A pipe: the child writes into it and exits; the parent closes its writing end, reads what
// came, says it, and waits.
const FORK_PIPE = wasix(`${FORK} ${JOIN}
  (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
  (import "wasix_32v1" "fd_close" (func $close (param i32) (result i32)))
  (import "wasix_32v1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))`, `
    (drop (call $pipe (i32.const 2100) (i32.const 2104)))
    (drop (call $fork (i32.const 1) (i32.const 2060)))
    (if (i32.eqz (i32.load (i32.const 2060)))
      (then
        (drop (call $close (i32.load (i32.const 2100))))
        (i32.store (i32.const 2048) (i32.const 1024))
        (i32.store (i32.const 2052) (i32.const 13))
        (drop (call $write (i32.load (i32.const 2104)) (i32.const 2048) (i32.const 1) (i32.const 2056)))
        (call $exit (i32.const 0))))
    (drop (call $close (i32.load (i32.const 2104))))
    (i32.store (i32.const 2200) (i32.const 3000))
    (i32.store (i32.const 2204) (i32.const 100))
    (drop (call $read (i32.load (i32.const 2100)) (i32.const 2200) (i32.const 1) (i32.const 2208)))
    (call $say (i32.const 3000) (i32.load (i32.const 2208)))
    ;; Its end of file: the only writer is gone.
    (drop (call $read (i32.load (i32.const 2100)) (i32.const 2200) (i32.const 1) (i32.const 2208)))
    (if (i32.eqz (i32.load (i32.const 2208))) (then (call $say (i32.const 1040) (i32.const 4))))
    ${WAIT_CHILD}`,
'(data (i32.const 1024) "through pipe\\n") (data (i32.const 1040) "eof\\n")');
// setjmp, then longjmp to it with 5: "set", then "jumped" if setjmp returned 5 the second time.
const JUMP = wasix(`(import "wasix_32v1" "stack_checkpoint" (func $setjmp (param i32 i32) (result i32)))
  (import "wasix_32v1" "stack_restore" (func $longjmp (param i32 i64)))`, `
    (drop (call $setjmp (i32.const 2304) (i32.const 2336)))
    (if (i64.eqz (i64.load (i32.const 2336)))
      (then (call $say (i32.const 1024) (i32.const 4)) (call $longjmp (i32.const 2304) (i64.const 5))))
    (if (i64.eq (i64.load (i32.const 2336)) (i64.const 5)) (then (call $say (i32.const 1040) (i32.const 7))))`,
'(data (i32.const 1024) "set\\n") (data (i32.const 1040) "jumped\\n")');

// The child executes `coreutils sleep N`; the parent waits for it (FORK_SLEEP), or ends at once
// (FORK_ORPHAN), leaving it to init.
const sleeper = (seconds, wait) => {
  const args = `coreutils\\nsleep\\n${seconds}`;
  return wasix(`${FORK} ${JOIN}
  (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))`, `
    (drop (call $fork (i32.const 1) (i32.const 2060)))
    (if (i32.eqz (i32.load (i32.const 2060)))
      (then (call $exec (i32.const 1024) (i32.const 18) (i32.const 1104) (i32.const ${16 + String(seconds).length}))))
    ${wait ? WAIT_CHILD : ''}`,
  `(data (i32.const 1024) "/usr/bin/coreutils") (data (i32.const 1104) "${args}")`);
};
const FORK_SLEEP = sleeper(30, true), FORK_ORPHAN = sleeper(3, false);
// The child ends at once, closing what it inherited, the terminal's input with it; the parent
// still reads a line typed there, and says it.
const FORK_READ = wasix(`${FORK} ${JOIN}
  (import "wasix_32v1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))`, `
    (drop (call $fork (i32.const 1) (i32.const 2060)))
    (if (i32.eqz (i32.load (i32.const 2060))) (then (call $exit (i32.const 0))))
    ${WAIT_CHILD}
    (i32.store (i32.const 2200) (i32.const 3000))
    (i32.store (i32.const 2204) (i32.const 100))
    (drop (call $read (i32.const 0) (i32.const 2200) (i32.const 1) (i32.const 2208)))
    (call $say (i32.const 3000) (i32.load (i32.const 2208)))`);

// A file a line shares, then many children of it: it opens `holdersOut` (from /, its preopen),
// and forks 16 children one after another, each ending at once, closing what it inherited. It
// forks one more, which makes no call and is ended by SIGKILL (its host ends it outright, and
// lets go of what it held). Its own write then goes to the file with its close, the last, and it
// says "closed".
const holdersOut = 'tmp/fork-holders-' + Date.now().toString(36);
const FORK_HOLDERS = wasix(`${FORK} ${JOIN}
  (import "wasix_32v1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasix_32v1" "fd_close" (func $close (param i32) (result i32)))
  (import "wasix_32v1" "proc_signal" (func $signal (param i32 i32) (result i32)))`, `
    (local $i i32)
    (drop (call $open (i32.const 3) (i32.const 0) (i32.const 1100) (i32.const ${holdersOut.length}) (i32.const 9) (i64.const -1) (i64.const -1) (i32.const 0) (i32.const 2300)))
    (loop $children
      (drop (call $fork (i32.const 1) (i32.const 2060)))
      (if (i32.eqz (i32.load (i32.const 2060))) (then (call $exit (i32.const 0))))
      ${WAIT_CHILD}
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br_if $children (i32.lt_u (local.get $i) (i32.const 16))))
    (drop (call $fork (i32.const 1) (i32.const 2060)))
    (if (i32.eqz (i32.load (i32.const 2060))) (then (loop $spin (br $spin))))
    (drop (call $signal (i32.load (i32.const 2060)) (i32.const 9)))
    ${WAIT_CHILD}
    (i32.store (i32.const 2048) (i32.const 1040))
    (i32.store (i32.const 2052) (i32.const 5))
    (drop (call $write (i32.load (i32.const 2300)) (i32.const 2048) (i32.const 1) (i32.const 2056)))
    (if (i32.eqz (call $close (i32.load (i32.const 2300)))) (then (call $say (i32.const 1056) (i32.const 7))))`,
`(data (i32.const 1040) "done\\n") (data (i32.const 1056) "closed\\n") (data (i32.const 1100) "${holdersOut}")`);

let base, headers;
async function uploads(request, files) {
  base = '/fork-' + Date.now().toString(36);
  headers = { Origin: origin, 'CF-Connecting-IP': 'fork-' + base };
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  // The page is a guest's, which writes there (mkdir's mode is umask's).
  await mkdirp(request, base, 0o777);
  expect(await sysCall(request, { chmod: { path: base, mode: 0o777 } }, { headers })).toBeNull();
  for (const [name, data] of Object.entries(files)) {
    expect((await put(request, '/api/file?path=' + encodeURIComponent(`${base}/${name}`), { headers, data })).status()).toBe(201);
    expect(await sysCall(request, { chmod: { path: `${base}/${name}`, mode: 0o755 } }, { headers })).toBeNull();
  }
}
const last = page => page.locator('.transcript pre').last();
// How a page's processes ask the kernel, as the browser sends it: by fetch, suspended on it
// (JSPI), or by synchronous XHR.
function processCalls(page) {
  const kinds = new Set();
  page.context().on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/sys' && (request.postData() ?? '').includes('"proc":')) kinds.add(request.resourceType());
  });
  return kinds;
}
// A browser without JSPI, as a process's Worker sees it.
const withoutJspi = page => page.route('**/wasi-process.js', async route => {
  const response = await route.fetch();
  await route.fulfill({ response, body: 'delete WebAssembly.Suspending; delete WebAssembly.promising;\n' + await response.text() });
});
const hasJspi = page => page.evaluate(() => typeof WebAssembly.Suspending === 'function' && typeof WebAssembly.promising === 'function');

test.describe('fork in the terminal', () => {
  test.afterEach(async ({ request }) => { if (base) await rmrf(request, base); });

  // Each way a process makes its calls (request 4): suspended on fetch (JSPI), where the browser
  // has it, and by synchronous XHR, where it does not.
  for (const jspi of [true, false]) test(`an uploaded module that forks (${jspi ? 'JSPI' : 'synchronous XHR'}): the child runs in a process of its own, and its parent waits for its status`, async ({ page, request }) => {
    if (!jspi) await withoutJspi(page);
    const calls = processCalls(page);
    await uploads(request, { 'fork-wait': FORK_WAIT, 'fork-exec': FORK_EXEC, 'fork-pipe': FORK_PIPE, jump: JUMP });
    await page.goto('/');
    test.skip(jspi && !await hasJspi(page), 'this browser has no JSPI');
    await command(page, `cd ${base}`);
    await command(page, './fork-wait');
    await expect(last(page)).toHaveText('child\nparent 7\nstat');
    // fork, then execve in the child: its image replaced, its pid kept, its parent waiting.
    await command(page, './fork-exec');
    const transcript = page.locator('.transcript');
    await expect(transcript).toContainText('executed\nparent');
    await expect(transcript).toContainText('no-such-program: No such file or directory');
    await expect(last(page)).toHaveText('missing');
    // A pipe between them: what the child wrote, then the end of file once it closed.
    await command(page, './fork-pipe');
    await expect(last(page)).toHaveText('through pipe\neof');
    // setjmp and longjmp, asyncify's too.
    await command(page, './jump');
    await expect(last(page)).toHaveText('set\njumped');
    // Nothing of them is left in the machine: every child was waited for.
    await command(page, 'ps');
    await expect(last(page)).not.toContainText('fork-');
    // Their calls to the kernel went as the browser can make them.
    expect([...calls]).toEqual([jspi ? 'fetch' : 'xhr']);
  });

  test('a forked child is of its parent\'s job: Ctrl+C ends both; an orphan is init\'s, and reaped as it ends', async ({ page, request }) => {
    await uploads(request, { 'fork-sleep': FORK_SLEEP, 'fork-orphan': FORK_ORPHAN, 'fork-read': FORK_READ });
    await page.goto('/');
    await command(page, `cd ${base}`);
    await connect(page);
    const sleeping = async () => value(await call(page, 'poll', { pids: [] })).filter(process => process.argv.join(' ') === 'coreutils sleep 30');
    // The parent waits for its child, which sleeps: Ctrl+C reaches both, as the foreground's
    // process group.
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    await input.fill('./fork-sleep'); await input.press('Enter');
    await expect.poll(async () => (await sleeping()).length).toBe(1);
    await input.press('Control+c');
    await expect(page.locator('#command').locator('xpath=ancestor::form').locator('.busy')).toHaveText('↵');
    await expect.poll(async () => (await sleeping()).length).toBe(0);
    // A child's close of the terminal's input closes its own descriptor: its parent reads on.
    await input.fill('./fork-read'); await input.press('Enter');
    await expect(page.locator('#command').locator('xpath=ancestor::form').locator('.busy')).toHaveText('Input ↵');
    await input.fill('typed'); await input.press('Enter');
    await expect(page.locator('#command').locator('xpath=ancestor::form').locator('.busy')).toHaveText('↵');
    await expect(page.locator('.transcript pre').last()).toHaveText('typed');
    // The parent ends first: its child is init's, runs on, and is reaped as it ends.
    await command(page, './fork-orphan');
    const orphan = () => call(page, 'poll', { pids: [] }).then(reply => value(reply).find(process => process.argv.join(' ') === 'coreutils sleep 3'));
    await expect.poll(async () => (await orphan())?.ppid).toBe(1);
    await expect.poll(orphan, { timeout: 15_000 }).toBeUndefined();
  });

  // A file's holders (web/wasi/shared.js), one after another, and then one killed outright: the
  // last close is still the last, and what was written goes to the file with it.
  test('a file shared by many children, one after another, then one killed, still closes with its writer', async ({ page, request }) => {
    await uploads(request, { 'fork-holders': FORK_HOLDERS });
    try {
      await page.goto('/');
      await command(page, `cd ${base}`);
      await command(page, './fork-holders');
      await expect(last(page)).toHaveText('closed', { timeout: 60_000 });
      await command(page, `cat /${holdersOut}`);
      await expect(last(page)).toHaveText('done');
    } finally {
      await rmrf(request, '/' + holdersOut);
    }
  });

  test('dash forks, pipes, executes and redirects', async ({ page, request }) => {
    test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved WASIX dash');
    await uploads(request, { dash: await readFile(process.env.WASIX_DASH) });
    await page.goto('/');
    await command(page, `cd ${base}`);
    await command(page, `./dash -c 'echo one; (echo two); echo three'`);
    await expect(last(page)).toHaveText('one\ntwo\nthree');
    await command(page, `./dash -c 'echo hello | coreutils tr a-z A-Z'`);
    await expect(last(page)).toHaveText('HELLO');
    // Redirections, the shell's own and a child's, into files its children write too. This
    // dash's libc (2023) starts at / whatever its process's directory, as Wasmer starts it; a
    // cd sets both.
    await command(page, `./dash -c 'cd ${base}; coreutils echo saved > out.txt; { echo a; coreutils echo b; } > both.txt; coreutils cat out.txt both.txt'`);
    await expect(last(page)).toHaveText('saved\na\nb');
    // An open file a subshell inherits is the shell's too: its close closes the subshell's
    // descriptor alone, and what it read moves the offset they share.
    await command(page, `./dash -c 'cd ${base}; echo one > lines.txt; echo two >> lines.txt; exec 3< lines.txt; (read a <&3; echo sub $a; exec 3<&-); read b <&3; echo shell $b'`);
    await expect(last(page)).toHaveText('sub one\nshell two');
    // A child's exit status, as its parent waited for it.
    await command(page, `./dash -c 'coreutils false; echo status $?; coreutils true; echo status $?'`);
    await expect(last(page)).toHaveText('status 1\nstatus 0');
    // Interactive: lines typed into the terminal, a forked child's among them, until exit.
    const input = page.getByRole('combobox', { name: 'Terminal command' });
    await input.fill('./dash'); await input.press('Enter');
    const busy = page.locator('#command').locator('xpath=ancestor::form').locator('.busy');
    await expect(busy).toHaveText('Input ↵');
    await input.fill(`cd ${base}; coreutils echo forked`); await input.press('Enter');
    await expect(page.locator('.transcript')).toContainText('forked');
    await input.fill('echo still here'); await input.press('Enter');
    await expect(page.locator('.transcript')).toContainText('still here');
    await input.fill('exit'); await input.press('Enter');
    await expect(busy).toHaveText('↵');
    // Ctrl+Z stops the shell and its child, which waits on it; fg continues both.
    await input.fill(`./dash -c 'coreutils sleep 2; echo slept'`); await input.press('Enter');
    await page.waitForTimeout(500);
    await input.press('Control+z');
    await expect(last(page)).toContainText('Stopped');
    await command(page, 'fg');
    await expect(last(page)).toHaveText('slept');
  });
});
