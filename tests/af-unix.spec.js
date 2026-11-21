import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call, put, rmrf } from './sys.js';

// Wave 4A Track 1 (`#55` L3b): Comprehensive Chromium E2E covering ALL blueprint rows `U-01..11`.
// Runs real WASI/WASIX modules across unrelated process Workers sharing the instance-wide 8 MiB
// `SockArena` SAB in both JSPI and synchronous `Atomics.wait` modes.

const password = process.env.OS_TEST_ADMIN_PASSWORD
  || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];

const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };

const AF_UNIX = 1;
const SOCK_STREAM = 1, SOCK_DGRAM = 2, SOCK_SEQPACKET = 5;
const SOCK_NONBLOCK = 0x800, SOCK_CLOEXEC = 0x80000;
const SHUT_WR = 1;
const SOL_SOCKET = 1, SO_TYPE = 3, SO_ACCEPTCONN = 30;
const MSG_PEEK = 0x2, MSG_CTRUNC = 0x8, MSG_TRUNC = 0x20, MSG_DONTWAIT = 0x40, MSG_NOSIGNAL = 0x4000, MSG_CMSG_CLOEXEC = 0x40000000;

const ERR = {
  EACCES: 2, EADDRINUSE: 3, EAGAIN: 6, EBADF: 8, ECONNREFUSED: 14,
  EINVAL: 28, EMSGSIZE: 35, ENOTSOCK: 57, ENXIO: 60, EPIPE: 64, EPROTOTYPE: 67, ETOOMANYREFS: 109,
};

let loginSeq = 0;
async function loginRoot(page) {
  const res = await api(page.request, 'login', {
    headers: { 'CF-Connecting-IP': `af-unix-${Date.now()}-${++loginSeq}` },
    data: { username: 'root', password },
  });
  expect(res.ok()).toBe(true);
}

// Dedicated `/client-kernel.js` host connection for running concurrent independent process Workers.
async function connectHost(page) {
  await page.evaluate(() => {
    const port = new Worker('/client-kernel.js');
    const pending = new Map();
    const runs = new Map();
    let next = 0;
    const request = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      port.postMessage({ v: 2, id, type, args });
    });
    port.onmessage = ({ data }) => {
      if (data?.id != null) {
        pending.get(data.id)?.(data);
        pending.delete(data.id);
        return;
      }
      const event = data?.value;
      const run = runs.get(event?.run);
      if (!run) return;
      if (event.type === 'output') {
        run.output += event.text;
        void request('run_output_ack', { run: event.run, sequence: event.sequence });
      }
      if (event.type === 'job') run.pids = event.pids;
    };
    window.__afUnix = {
      request,
      runs,
      start(id, path, options = {}) {
        const run = { output: '', pids: [], result: null };
        runs.set(id, run);
        run.done = request('run', {
          run: id,
          stages: [{ path, argv: options.argv ?? [path] }],
          options: { tty: false, streamOutput: true, ...options },
        }).then(result => { run.result = result; });
      },
    };
  });
  await hostCall(page, 'sync_account_from_server');
}

const hostCall = (page, type, args = {}) => page.evaluate(([t, a]) => window.__afUnix.request(t, a), [type, args]);
const startHost = (page, id, path, options = {}) => page.evaluate(([i, p, o]) => window.__afUnix.start(i, p, o), [id, path, options]);
const hostOutput = (page, id) => page.evaluate(i => (window.__afUnix.runs.get(i)?.output ?? '').replace(/\r\n/g, '\n'), id);
const hostReady = async (page, id, text) => {
  const deadline = Date.now() + 20_000;
  for (;;) {
    const state = await page.evaluate(i => {
      const r = window.__afUnix.runs.get(i);
      return { output: (r?.output ?? '').replace(/\r\n/g, '\n'), result: r?.result ?? null };
    }, id);
    if (state.output.includes(text)) return;
    if (state.result) throw new Error(`run ${id} exited early before "${text}": ${JSON.stringify(state)}`);
    if (Date.now() > deadline) throw new Error(`timeout waiting for "${text}" on ${id}: ${JSON.stringify(state)}`);
    await page.waitForTimeout(100);
  }
};
async function hostResult(page, id, expectedStatus = 0) {
  const deadline = Date.now() + 30_000;
  let state;
  for (;;) {
    state = await page.evaluate(i => {
      const r = window.__afUnix.runs.get(i);
      return { output: (r?.output ?? '').replace(/\r\n/g, '\n'), result: r?.result ?? null };
    }, id);
    if (state.result) break;
    if (Date.now() > deadline) throw new Error(`timeout waiting for exit of ${id}: ${JSON.stringify(state)}`);
    await page.waitForTimeout(100);
  }
  expect(state.result, `run ${id} output:\n${state.output}`).toMatchObject({ ok: { status: expectedStatus } });
}
async function closeHost(page, base) {
  await page.evaluate(async dir => {
    if (!window.__afUnix) return;
    const { request, runs } = window.__afUnix;
    await Promise.all([...runs.keys()].map(run => request('run_signal', { run, signal: 9 })));
    const rows = await request('poll', { pids: [] });
    await Promise.all((rows.ok ?? []).filter(p => p.path?.startsWith(dir + '/')).map(p => request('kill', { pid: p.pid, signal: 9 })));
    await request('reconcile');
    await Promise.all([...runs.values()].map(run => run.done));
  }, base);
}

const assertExpr = expr => `(call $assert ${expr})`;
const eq = (expr, n) => assertExpr(`(i32.eq ${expr} (i32.const ${n}))`);

// Compile and upload a WASI/WASIX test module to `${base}/${name}.wasm`.
// When `sync: true`, imports `os.sigaction` to force synchronous `Atomics.wait` mode (`process.js`).
// When `sync: false`, omits `os.sigaction` so Chromium runs in JSPI mode.
async function uploadWasm(page, base, name, build, { sync = false, withFork = false } = {}) {
  let strAt = 8192;
  const segments = [];
  const text = value => {
    const data = Buffer.from(value);
    const ptr = strAt;
    strAt += data.length + 1;
    const escaped = [...data].map(b => '\\' + b.toString(16).padStart(2, '0')).join('');
    segments.push(`(data (i32.const ${ptr}) "${escaped}")`);
    return `(i32.const ${ptr}) (i32.const ${data.length})`;
  };
  const say = s => `(call $say ${text(s)})`;
  const sysJson = obj => `(drop (call $sys ${text(JSON.stringify(obj))}))`;
  const body = build({ text, say, sysJson, eq, assertExpr });

  const wat = `(module
    (import "os" "sys" (func $sys (param i32 i32) (result i32)))
    (import "os" "reply" (func $reply (param i32)))
    (import "os" "open" (func $open (param i32 i32 i32 i32) (result i32)))
    (import "os" "waitpid2" (func $waitpid2 (param i32 i32 i32) (result i32)))
    ${sync ? '(import "os" "sigaction" (func $sigaction (param i32 i32 i32 i32) (result i32)))' : ''}
    (import "os" "sock_socket" (func $sock_socket (param i32 i32 i32 i32) (result i32)))
    (import "os" "sock_socketpair" (func $sock_socketpair (param i32 i32 i32 i32) (result i32)))
    (import "os" "sock_bind" (func $sock_bind (param i32 i32 i32) (result i32)))
    (import "os" "sock_listen" (func $sock_listen (param i32 i32) (result i32)))
    (import "os" "sock_accept" (func $sock_accept (param i32 i32 i32) (result i32)))
    (import "os" "sock_connect" (func $sock_connect (param i32 i32 i32) (result i32)))
    (import "os" "sock_shutdown" (func $sock_shutdown (param i32 i32) (result i32)))
    (import "os" "sock_sendmsg" (func $sock_sendmsg (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
    (import "os" "sock_recvmsg" (func $sock_recvmsg (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
    (import "os" "sock_peercred" (func $sock_peercred (param i32 i32) (result i32)))
    (import "os" "sock_getsockname" (func $sock_getsockname (param i32 i32 i32 i32) (result i32)))
    (import "os" "sock_getpeername" (func $sock_getpeername (param i32 i32 i32 i32) (result i32)))
    (import "os" "sock_getsockopt" (func $sock_getsockopt (param i32 i32 i32 i32) (result i32)))
    (import "os" "sock_setsockopt" (func $sock_setsockopt (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $fd_close (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_seek" (func $fd_seek (param i32 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_set_flags" (func $fd_setflags (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_open" (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_unlink_file" (func $unlink (param i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_filestat_get" (func $path_stat (param i32 i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll_oneoff (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (param i32)))
    (import "wasix_32v1" "fd_pipe" (func $fd_pipe (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_dup" (func $fd_dup (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_renumber" (func $dup2 (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_fdflags_get" (func $fdflags_get (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_id" (func $proc_id (param i32) (result i32)))
    ${withFork ? '(import "wasix_32v1" "proc_fork" (func $proc_fork (param i32 i32) (result i32)))' : ''}
    ${withFork ? '(import "wasix_32v1" "proc_exec" (func $proc_exec (param i32 i32 i32 i32)))' : ''}
    (memory (export "memory") 4)
    (func $assert (param $v i32) (if (i32.eqz (local.get $v)) (then unreachable)))
    (func $write_all (param $fd i32) (param $ptr i32) (param $len i32)
      (local $done i32) (local $n i32)
      (loop $w
        (if (i32.lt_u (local.get $done) (local.get $len)) (then
          (i32.store (i32.const 16) (i32.add (local.get $ptr) (local.get $done)))
          (i32.store (i32.const 20) (i32.sub (local.get $len) (local.get $done)))
          ${eq('(call $fd_write (local.get $fd) (i32.const 16) (i32.const 1) (i32.const 24))', 0)}
          (local.set $n (i32.load (i32.const 24)))
          ${assertExpr('(i32.gt_u (local.get $n) (i32.const 0))')}
          (local.set $done (i32.add (local.get $done) (local.get $n)))
          (br $w)))))
    (func $read_exact (param $fd i32) (param $ptr i32) (param $len i32)
      (local $done i32) (local $n i32)
      (loop $r
        (if (i32.lt_u (local.get $done) (local.get $len)) (then
          (i32.store (i32.const 16) (i32.add (local.get $ptr) (local.get $done)))
          (i32.store (i32.const 20) (i32.sub (local.get $len) (local.get $done)))
          ${eq('(call $fd_read (local.get $fd) (i32.const 16) (i32.const 1) (i32.const 24))', 0)}
          (local.set $n (i32.load (i32.const 24)))
          ${assertExpr('(i32.gt_u (local.get $n) (i32.const 0))')}
          (local.set $done (i32.add (local.get $done) (local.get $n)))
          (br $r)))))
    (func $say (param $ptr i32) (param $len i32)
      (call $write_all (i32.const 1) (local.get $ptr) (local.get $len)))
    (func $say_u32 (param $val i32)
      (local $p i32) (local $v i32)
      (local.set $p (i32.const 512))
      (local.set $v (local.get $val))
      (if (i32.eqz (local.get $v)) (then
        (i32.store8 (i32.const 511) (i32.const 48))
        (call $say (i32.const 511) (i32.const 1))
        (return)))
      (loop $digits
        (if (i32.gt_u (local.get $v) (i32.const 0)) (then
          (local.set $p (i32.sub (local.get $p) (i32.const 1)))
          (i32.store8 (local.get $p) (i32.add (i32.const 48) (i32.rem_u (local.get $v) (i32.const 10))))
          (local.set $v (i32.div_u (local.get $v) (i32.const 10)))
          (br $digits))))
      (call $say (local.get $p) (i32.sub (i32.const 512) (local.get $p))))
    (func $read_once (param $fd i32) (param $ptr i32) (param $cap i32) (result i32)
      (i32.store (i32.const 16) (local.get $ptr))
      (i32.store (i32.const 20) (local.get $cap))
      ${eq('(call $fd_read (local.get $fd) (i32.const 16) (i32.const 1) (i32.const 24))', 0)}
      (i32.load (i32.const 24)))
    (func (export "_start")
      (local $a i32) (local $b i32) (local $c i32) (local $d i32)
      (local $e i32) (local $f i32) (local $i i32) (local $j i32) (local $n i32)
      ${body})
    ${segments.join('\n')}
  )`;

  const mod = binaryen.parseText(wat);
  let bytes;
  try { bytes = mod.emitBinary(); } finally { mod.dispose(); }
  const path = `${base}/${name}.wasm`;
  const putRes = await put(page.request, `/api/file?path=${path}&overwrite=true`, { data: Buffer.from(bytes) });
  expect(putRes.ok()).toBe(true);
  await call(page.request, { chmod: { path, mode: 0o755 } });
  return path;
}

let base;
test.beforeEach(async ({ page }) => {
  base = '/guest/afunix-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o755 } });
  await page.goto('/');
  await connectHost(page);
});
test.afterEach(async ({ page }) => {
  await closeHost(page, base);
  await rmrf(page.request, base);
});

test('U-01 & U-07: SOCK_STREAM across unrelated Workers (>1 MiB SockArena), S_IFSOCK, open->ENXIO, unlink+rebind', async ({ page }) => {
  await loginRoot(page);
  await hostCall(page, 'sync_account', ROOT_ACCOUNT);
  const srvPath = await uploadWasm(page, base, 'u01-srv', ({ text, say, sysJson, eq, assertExpr }) => `
    ;; Create, bind /run/u01.sock, chmod 0666, listen
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_bind (local.get $a) ${text('/run/u01.sock')})`, 0)}
    ${sysJson([{ chmod: { path: '/run/u01.sock', mode: 0o666 } }])}
    ${eq('(call $sock_listen (local.get $a) (i32.const 16))', 0)}

    ;; U-07: open(/run/u01.sock) MUST return -ENXIO (-60); getsockname == "/run/u01.sock"
    ${eq(`(call $open ${text('/run/u01.sock')} (i32.const 0) (i32.const 0))`, -ERR.ENXIO)}
    ${eq('(call $sock_getsockname (local.get $a) (i32.const 4096) (i32.const 128) (i32.const 104))', 0)}
    ${eq('(i32.load (i32.const 104))', 13)}
    ;; path_filestat_get filetype byte at offset 16 MUST be SOCKET_STREAM (6)
    ${eq(`(call $path_stat (i32.const 3) (i32.const 1) ${text('/run/u01.sock')} (i32.const 600))`, 0)}
    ${eq('(i32.load8_u (i32.const 616))', 6)}
    ;; SO_ACCEPTCONN == 1, SO_TYPE == SOCK_STREAM
    ${eq(`(call $sock_getsockopt (local.get $a) (i32.const ${SOL_SOCKET}) (i32.const ${SO_ACCEPTCONN}) (i32.const 108))`, 0)}
    ${eq('(i32.load (i32.const 108))', 1)}
    ${eq(`(call $sock_getsockopt (local.get $a) (i32.const ${SOL_SOCKET}) (i32.const ${SO_TYPE}) (i32.const 108))`, 0)}
    ${eq('(i32.load (i32.const 108))', SOCK_STREAM)}

    ${say('READY\n')}
    ${eq(`(call $sock_accept (local.get $a) (i32.const ${SOCK_CLOEXEC}) (i32.const 112))`, 0)}
    (local.set $b (i32.load (i32.const 112)))

    ;; U-07: unlink /run/u01.sock while listener & accepted peer are live -> immediate re-bind succeeds!
    ${eq(`(call $unlink (i32.const 3) ${text('/run/u01.sock')})`, 0)}
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 116))`, 0)}
    (local.set $c (i32.load (i32.const 116)))
    ${eq(`(call $sock_bind (local.get $c) ${text('/run/u01.sock')})`, 0)}
    ${eq(`(call $unlink (i32.const 3) ${text('/run/u01.sock')})`, 0)}
    ${eq('(call $fd_close (local.get $c))', 0)}

    ;; U-01: Receive 20 x 64 KiB = 1.25 MiB over SockArena, XOR each byte with 0x5A, echo back!
    (local.set $i (i32.const 0))
    (loop $rounds
      (if (i32.lt_u (local.get $i) (i32.const 20)) (then
        (call $read_exact (local.get $b) (i32.const 16384) (i32.const 65536))
        (local.set $j (i32.const 0))
        (loop $xor
          (if (i32.lt_u (local.get $j) (i32.const 65536)) (then
            (local.set $n (i32.and (i32.add (i32.mul (local.get $i) (i32.const 13)) (local.get $j)) (i32.const 255)))
            ${assertExpr('(i32.eq (i32.load8_u (i32.add (i32.const 16384) (local.get $j))) (local.get $n))')}
            (i32.store8 (i32.add (i32.const 16384) (local.get $j)) (i32.xor (local.get $n) (i32.const 90)))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $xor))))
        (call $write_all (local.get $b) (i32.const 16384) (i32.const 65536))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $rounds))))
    ${eq('(call $fd_close (local.get $b))', 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${say('SRV_OK\n')}
  `);

  const cliPath = await uploadWasm(page, base, 'u01-cli', ({ text, say, eq, assertExpr }) => `
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_connect (local.get $a) ${text('/run/u01.sock')})`, 0)}
    ;; Verify getpeername == "/run/u01.sock" and SO_PEERCRED has non-zero pid
    ${eq('(call $sock_getpeername (local.get $a) (i32.const 4096) (i32.const 128) (i32.const 104))', 0)}
    ${eq('(i32.load (i32.const 104))', 13)}
    ${eq('(call $sock_peercred (local.get $a) (i32.const 120))', 0)}
    ${assertExpr('(i32.gt_u (i32.load (i32.const 120)) (i32.const 0))')}

    ;; Full-duplex 20 x 64 KiB = 1.25 MiB roundtrip across unrelated Workers!
    (local.set $i (i32.const 0))
    (loop $rounds
      (if (i32.lt_u (local.get $i) (i32.const 20)) (then
        (local.set $j (i32.const 0))
        (loop $fill
          (if (i32.lt_u (local.get $j) (i32.const 65536)) (then
            (i32.store8 (i32.add (i32.const 16384) (local.get $j))
              (i32.and (i32.add (i32.mul (local.get $i) (i32.const 13)) (local.get $j)) (i32.const 255)))
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $fill))))
        (call $write_all (local.get $a) (i32.const 16384) (i32.const 65536))
        (call $read_exact (local.get $a) (i32.const 131072) (i32.const 65536))
        (local.set $j (i32.const 0))
        (loop $verify
          (if (i32.lt_u (local.get $j) (i32.const 65536)) (then
            (local.set $n (i32.xor (i32.and (i32.add (i32.mul (local.get $i) (i32.const 13)) (local.get $j)) (i32.const 255)) (i32.const 90)))
            ${assertExpr('(i32.eq (i32.load8_u (i32.add (i32.const 131072) (local.get $j))) (local.get $n))')}
            (local.set $j (i32.add (local.get $j) (i32.const 1)))
            (br $verify))))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $rounds))))
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${say('CLI_OK\n')}
  `);

  await startHost(page, 'u01-srv', srvPath);
  await hostReady(page, 'u01-srv', 'READY');
  await startHost(page, 'u01-cli', cliPath);
  await hostResult(page, 'u01-cli', 0);
  await hostResult(page, 'u01-srv', 0);
  expect(await hostOutput(page, 'u01-srv')).toContain('SRV_OK');
  expect(await hostOutput(page, 'u01-cli')).toContain('CLI_OK');

  const stats = (await hostCall(page, 'run_sock_stats')).ok;
  expect(stats).toEqual({ activeSockets: 0, boundInodes: 0, inflightGlobal: 0, allocatedArenaSlots: 0 });
});

test('U-02: socketpair with SOCK_CLOEXEC across fork, dup2, and execve', async ({ page }) => {
  const helperPath = await uploadWasm(page, base, 'u02-helper', ({ text, say, eq }) => `
    ;; Inherited fd 10 (dup2 without O_CLOEXEC) MUST survive execve; fd 5 (SOCK_CLOEXEC $b) MUST be EBADF!
    ${eq(`(call $sock_getsockopt (i32.const 5) (i32.const ${SOL_SOCKET}) (i32.const ${SO_TYPE}) (i32.const 100))`, ERR.EBADF)}
    ${eq(`(call $sock_getsockopt (i32.const 10) (i32.const ${SOL_SOCKET}) (i32.const ${SO_TYPE}) (i32.const 100))`, 0)}
    ${eq('(i32.load (i32.const 100))', SOCK_STREAM)}
    (call $write_all (i32.const 10) ${text('EXEC_OK')})
    ${eq('(call $fd_close (i32.const 10))', 0)}
    ${say('HELPER_OK\n')}
  `);

  const parentPath = await uploadWasm(page, base, 'u02-parent', ({ text, say, eq }) => `
    ;; Pair 1 with SOCK_CLOEXEC -> dup2 child end to fd 11 (keep O_CLOEXEC via sock_socketpair)
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM | SOCK_CLOEXEC}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    (local.set $b (i32.load (i32.const 104)))
    ;; Pair 2 without SOCK_CLOEXEC -> child will dup2 to fd 10
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 108))`, 0)}
    (local.set $c (i32.load (i32.const 108)))
    (local.set $d (i32.load (i32.const 112)))

    ${eq('(call $proc_fork (i32.const 1) (i32.const 120))', 0)}
    (if (i32.eqz (i32.load (i32.const 120))) (then
      ;; Child: verify SOCK_CLOEXEC fd $b works BEFORE execve, dup2 $d -> 10, keep $b as CLOEXEC at its fd (move to 11? use fd_dup2!)
      ;; Actually verify $b has FD_CLOEXEC set, send "PRE" over $b, close $a/$c, dup2 $d -> 10, exec helper!
      ${eq('(call $fdflags_get (local.get $b) (i32.const 124))', 0)}
      ${eq('(i32.load16_u (i32.const 124))', 1)}
      (call $write_all (local.get $b) ${text('PRE')})
      ${eq('(call $dup2 (local.get $d) (i32.const 10))', 0)}
      ;; Also ensure fd 11 is NOT open (or is a CLOEXEC fd — check $b closes on exec by closing parent ends and checking $b via dup2? Wait: dup2 clears CLOEXEC, so leave $b at its own fd OR check fd 11 is EBADF after closing $b? Even better: $b is fd 5, so check fd 5 is EBADF in helper if we didn't close it!)
      ;; Let's close $a, $c, $d (keeping $b with CLOEXEC and 10 without CLOEXEC!)
      ${eq('(call $fd_close (local.get $a))', 0)}
      ${eq('(call $fd_close (local.get $c))', 0)}
      ${eq('(call $fd_close (local.get $d))', 0)}
      (call $proc_exec ${text(helperPath)} ${text(helperPath + '\n')})
      unreachable
    ))
    ;; Parent: close child ends $b and $d, read "PRE" from $a, wait for EOF on $a (proves child's $b closed on execve!), then read "EXEC_OK" from $c!
    ${eq('(call $fd_close (local.get $b))', 0)}
    ${eq('(call $fd_close (local.get $d))', 0)}
    (call $read_exact (local.get $a) (i32.const 4096) (i32.const 3))
    ${eq('(i32.load8_u (i32.const 4096))', 80)} ;; 'P'
    ;; Next read on $a MUST hit EOF (0 bytes) because child's $b had SOCK_CLOEXEC and closed on execve!
    ${eq('(call $read_once (local.get $a) (i32.const 4096) (i32.const 16))', 0)}
    (call $read_exact (local.get $c) (i32.const 4096) (i32.const 7))
    ${eq('(i32.load8_u (i32.const 4096))', 69)} ;; 'E'
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${eq('(call $fd_close (local.get $c))', 0)}
    ${assertExpr('(i32.eq (call $waitpid2 (i32.load (i32.const 120)) (i32.const 128) (i32.const 0)) (i32.load (i32.const 120)))')}
    ${eq('(i32.load (i32.const 128))', 0)}
    ${say('U02_OK\n')}
  `, { withFork: true });

  await startHost(page, 'u02', parentPath);
  await hostResult(page, 'u02', 0);
  const out = await hostOutput(page, 'u02');
  expect(out).toContain('HELPER_OK');
  expect(out).toContain('U02_OK');
});

test('U-03: SOCK_DGRAM multi-client bound server & SOCK_SEQPACKET framing, MSG_PEEK, MSG_TRUNC, EMSGSIZE', async ({ page }) => {
  const dgramSock = '/tmp/u03.dgram';
  const srvPath = await uploadWasm(page, base, 'u03-srv', ({ text, say, sysJson, eq, assertExpr }) => `
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_DGRAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_bind (local.get $a) ${text(dgramSock)})`, 0)}
    ${sysJson([{ chmod: { path: dgramSock, mode: 0o666 } }])}
    ${say('READY\n')}

    ;; Peek then receive first datagram ("client-A", 8 bytes)
    ${eq(`(call $sock_recvmsg (local.get $a) (i32.const 4096) (i32.const 64) (i32.const 0) (i32.const 0) (i32.const 104) (i32.const 120) (i32.const ${MSG_PEEK}) (i32.const 108) (i32.const 112))`, 0)}
    ${eq('(i32.load (i32.const 108))', 8)}
    ${eq('(call $sock_recvmsg (local.get $a) (i32.const 4096) (i32.const 64) (i32.const 0) (i32.const 0) (i32.const 104) (i32.const 120) (i32.const 0) (i32.const 108) (i32.const 112))', 0)}
    ${eq('(i32.load (i32.const 108))', 8)}
    ${eq('(i32.load (i32.const 112))', 0)}
    ${assertExpr('(i32.gt_u (i32.load (i32.const 120)) (i32.const 0))')}

    ;; Receive second datagram ("client-B-longer", 15 bytes) into 6-byte buffer -> MSG_TRUNC!
    ${eq('(call $sock_recvmsg (local.get $a) (i32.const 4096) (i32.const 6) (i32.const 0) (i32.const 0) (i32.const 104) (i32.const 120) (i32.const 0) (i32.const 108) (i32.const 112))', 0)}
    ${eq('(i32.load (i32.const 108))', 6)}
    ${eq(`(i32.and (i32.load (i32.const 112)) (i32.const ${MSG_TRUNC}))`, MSG_TRUNC)}
    ;; Remainder of truncated datagram MUST be discarded (MSG_DONTWAIT -> EAGAIN)
    ${eq(`(call $sock_recvmsg (local.get $a) (i32.const 4096) (i32.const 64) (i32.const 0) (i32.const 0) (i32.const 104) (i32.const 120) (i32.const ${MSG_DONTWAIT}) (i32.const 108) (i32.const 112))`, ERR.EAGAIN)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${eq(`(call $unlink (i32.const 3) ${text(dgramSock)})`, 0)}

    ;; SOCK_SEQPACKET record boundaries & EMSGSIZE (>65536)
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_SEQPACKET}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $b (i32.load (i32.const 100)))
    (local.set $c (i32.load (i32.const 104)))
    ${eq('(call $sock_sendmsg (local.get $b) (i32.const 16384) (i32.const 65537) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))', ERR.EMSGSIZE)}
    ${eq(`(call $sock_sendmsg (local.get $b) ${text('rec1')} (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, 0)}
    ${eq(`(call $sock_sendmsg (local.get $b) ${text('rec2-extra')} (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, 0)}
    ;; Large 1024-byte recv gets ONLY "rec1" (4 bytes), then "rec2-extra" (10 bytes)!
    ${eq('(call $sock_recvmsg (local.get $c) (i32.const 4096) (i32.const 1024) (i32.const 0) (i32.const 0) (i32.const 104) (i32.const 120) (i32.const 0) (i32.const 108) (i32.const 112))', 0)}
    ${eq('(i32.load (i32.const 108))', 4)}
    ${eq('(call $sock_recvmsg (local.get $c) (i32.const 4096) (i32.const 1024) (i32.const 0) (i32.const 0) (i32.const 104) (i32.const 120) (i32.const 0) (i32.const 108) (i32.const 112))', 0)}
    ${eq('(i32.load (i32.const 108))', 10)}
    ${eq('(call $fd_close (local.get $b))', 0)}
    ${eq('(call $fd_close (local.get $c))', 0)}
    ${say('U03_OK\n')}
  `);

  const cliA = await uploadWasm(page, base, 'u03-cliA', ({ text, say, eq }) => `
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_DGRAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('client-A')} (i32.const 0) (i32.const 0) ${text(dgramSock)} (i32.const 0) (i32.const 108))`, 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${say('A_OK\n')}
  `);
  const cliB = await uploadWasm(page, base, 'u03-cliB', ({ text, say, eq }) => `
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_DGRAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('client-B-longer')} (i32.const 0) (i32.const 0) ${text(dgramSock)} (i32.const 0) (i32.const 108))`, 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${say('B_OK\n')}
  `);

  await startHost(page, 'u03-srv', srvPath);
  await hostReady(page, 'u03-srv', 'READY');
  await startHost(page, 'u03-cliA', cliA);
  await hostResult(page, 'u03-cliA', 0);
  await startHost(page, 'u03-cliB', cliB);
  await hostResult(page, 'u03-cliB', 0);
  await hostResult(page, 'u03-srv', 0);
  expect(await hostOutput(page, 'u03-srv')).toContain('U03_OK');
});

for (const syncMode of [false, true]) {
  test(`U-04 & U-05 (${syncMode ? 'sync Atomics.wait' : 'JSPI'}): SCM_RIGHTS file+pipe+PTY+unix-sock+CloudFs & ancillary boundary splitting`, async ({ page }) => {
    const sockName = syncMode ? '/tmp/u04-sync.sock' : '/tmp/u04-jspi.sock';
    const cloudFile = `${base}/cloud-${syncMode ? 'sync' : 'jspi'}.txt`;
    expect((await put(page.request, `/api/file?path=${cloudFile}&overwrite=true`, { data: 'cloud-payload' })).ok()).toBe(true);

    // Receiver Worker binds sockName, accepts sender, verifies boundary splitting ("AAA"+[file,pipe] then "BBB"+[pty,subsock,cloud]).
    const rxPath = await uploadWasm(page, base, `u04-rx-${syncMode ? 'sync' : 'jspi'}`, ({ text, say, sysJson, eq }) => `
      ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
      (local.set $a (i32.load (i32.const 100)))
      ${eq(`(call $sock_bind (local.get $a) ${text(sockName)})`, 0)}
      ${sysJson([{ chmod: { path: sockName, mode: 0o666 } }])}
      ${eq('(call $sock_listen (local.get $a) (i32.const 8))', 0)}
      ${say('RX_READY\n')}
      ${eq('(call $sock_accept (local.get $a) (i32.const 0) (i32.const 104))', 0)}
      (local.set $b (i32.load (i32.const 104)))

      ;; Wait until BOTH sends are queued (sender sends "AAA"+[file,pipe], then "BBB"+[pty,subsock,cloud], then closes -> EOF after BBB).
      ;; Call recvmsg #1 with 64-byte buffer & MSG_CMSG_CLOEXEC -> MUST receive ONLY "AAA" (3 bytes) + 2 fds!
      ${eq(`(call $sock_recvmsg (local.get $b) (i32.const 4096) (i32.const 64) (i32.const 1024) (i32.const 4) (i32.const 108) (i32.const 120) (i32.const ${MSG_CMSG_CLOEXEC}) (i32.const 112) (i32.const 116))`, 0)}
      ${eq('(i32.load (i32.const 112))', 3)}
      ${eq('(i32.load8_u (i32.const 4096))', 65)} ;; 'A'
      ${eq('(i32.load8_u (i32.const 4097))', 65)}
      ${eq('(i32.load8_u (i32.const 4098))', 65)}
      ${eq('(i32.load (i32.const 108))', 2)}
      (local.set $c (i32.load (i32.const 1024))) ;; local file fd
      (local.set $d (i32.load (i32.const 1028))) ;; arena pipe read fd

      ;; Verify MSG_CMSG_CLOEXEC set FD_CLOEXEC on received fds!
      ${eq('(call $fdflags_get (local.get $c) (i32.const 140))', 0)}
      ${eq('(i32.load16_u (i32.const 140))', 1)}
      ${eq('(call $fdflags_get (local.get $d) (i32.const 140))', 0)}
      ${eq('(i32.load16_u (i32.const 140))', 1)}

      ;; Local file MUST preserve shared seek offset 4 -> reads "456789" (6 bytes)!
      ${eq('(call $read_once (local.get $c) (i32.const 4200) (i32.const 32))', 6)}
      ${eq('(i32.load8_u (i32.const 4200))', 52)} ;; '4'
      ${eq('(i32.load8_u (i32.const 4205))', 57)} ;; '9'

      ;; Arena pipe read end MUST read "from-pipe" (9 bytes) across unrelated Workers!
      (call $read_exact (local.get $d) (i32.const 4300) (i32.const 9))
      ${eq('(i32.load8_u (i32.const 4300))', 102)} ;; 'f'
      ${eq('(i32.load8_u (i32.const 4308))', 101)} ;; 'e'
      ${eq('(call $fd_close (local.get $c))', 0)}
      ${eq('(call $fd_close (local.get $d))', 0)}

      ;; Call recvmsg #2 -> MUST receive ONLY "BBB" (3 bytes) + 3 fds [pty, subsock, cloud]!
      ${eq(`(call $sock_recvmsg (local.get $b) (i32.const 4096) (i32.const 64) (i32.const 1024) (i32.const 4) (i32.const 108) (i32.const 120) (i32.const ${MSG_CMSG_CLOEXEC}) (i32.const 112) (i32.const 116))`, 0)}
      ${eq('(i32.load (i32.const 112))', 3)}
      ${eq('(i32.load8_u (i32.const 4096))', 66)} ;; 'B'
      ${eq('(i32.load8_u (i32.const 4098))', 66)}
      ${eq('(i32.load (i32.const 108))', 3)}
      (local.set $c (i32.load (i32.const 1024))) ;; pty slave fd
      (local.set $d (i32.load (i32.const 1028))) ;; sub-unix-sock fd
      (local.set $e (i32.load (i32.const 1032))) ;; CloudFs fd

      ;; Read PTY slave -> gets "pty-hi\\n" (7 bytes)
      (call $read_exact (local.get $c) (i32.const 4400) (i32.const 7))
      ${eq('(i32.load8_u (i32.const 4400))', 112)} ;; 'p'
      ;; Read sub-UnixStream -> gets "sub-sock" (8 bytes)
      (call $read_exact (local.get $d) (i32.const 4500) (i32.const 8))
      ${eq('(i32.load8_u (i32.const 4500))', 115)} ;; 's'
      ;; Read CloudFs open ref -> gets "cloud-payload" (13 bytes)
      (call $read_exact (local.get $e) (i32.const 4600) (i32.const 13))
      ${eq('(i32.load8_u (i32.const 4600))', 99)} ;; 'c'

      ${eq('(call $fd_close (local.get $c))', 0)}
      ${eq('(call $fd_close (local.get $d))', 0)}
      ${eq('(call $fd_close (local.get $e))', 0)}
      ${eq('(call $fd_close (local.get $b))', 0)}
      ${eq('(call $fd_close (local.get $a))', 0)}
      ${eq(`(call $unlink (i32.const 3) ${text(sockName)})`, 0)}
      ${say('U04_U05_OK\n')}
    `, { sync: syncMode });

    // Sender Worker prepares all 5 descriptor types and passes them in 2 adjacent sends ("AAA"+[file,pipe], "BBB"+[pty,subsock,cloud]).
    const txPath = await uploadWasm(page, base, `u04-tx-${syncMode ? 'sync' : 'jspi'}`, ({ text, say, eq, assertExpr }) => `
      ;; 1. Local tmpfs file with seek offset 4
      (local.set $a (call $open ${text('/tmp/u04-shared.txt')} (i32.const ${2 | 0o100 | 0o1000}) (i32.const ${0o600})))
      ${assertExpr('(i32.ge_s (local.get $a) (i32.const 0))')}
      (call $write_all (local.get $a) ${text('0123456789')})
      ${eq('(call $fd_seek (local.get $a) (i64.const 4) (i32.const 0) (i32.const 200))', 0)}

      ;; 2. Arena-backed fd_pipe: write "from-pipe" and close write end
      ${eq('(call $fd_pipe (i32.const 100) (i32.const 104))', 0)}
      (local.set $b (i32.load (i32.const 100))) ;; pipe read
      (local.set $c (i32.load (i32.const 104))) ;; pipe write
      (call $write_all (local.get $c) ${text('from-pipe')})
      ${eq('(call $fd_close (local.get $c))', 0)}

      ;; 3. PTY master/slave: open /dev/ptmx, unlock, open slave, write "pty-hi\\n" to master
      (local.set $c (call $open ${text('/dev/ptmx')} (i32.const 2) (i32.const 0)))
      ${assertExpr('(i32.ge_s (local.get $c) (i32.const 0))')}
      ;; Query TIOCGPTN (0x80045430) & unlock TIOCSPTLCK (0x40045431) via os.sys JSON!
      ;; Build tiny JSON manually? Even simpler: ptmx is fd $c which is deterministic fd 6! Wait: check $c!
      ;; 0,1,2=stdio, 3=preopen, 4=localfile ($a), 5=pipe-r ($b), 6=ptmx ($c) because pipe-w was closed!
      ${eq('(local.get $c)', 6)}
      (local.set $n (call $sys ${text(JSON.stringify([{ ioctl: { fd: 6, request: 0x80045430, arg: 0 } }, { ioctl: { fd: 6, request: 0x40045431, arg: 0 } }]))}))
      (call $reply (i32.const 4096))
      ;; Extract "/dev/pts/..." from JSON reply at 4096 into 5000..
      (local.set $i (i32.const 4096))
      (loop $find_slash
        (if (i32.ne (i32.load8_u (local.get $i)) (i32.const 47)) (then
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $find_slash))))
      (local.set $j (i32.const 0))
      (loop $copy_pts
        (if (i32.ne (i32.load8_u (i32.add (local.get $i) (local.get $j))) (i32.const 34)) (then
          (i32.store8 (i32.add (i32.const 5000) (local.get $j)) (i32.load8_u (i32.add (local.get $i) (local.get $j))))
          (local.set $j (i32.add (local.get $j) (i32.const 1)))
          (br $copy_pts))))
      (local.set $d (call $open (i32.const 5000) (local.get $j) (i32.const 2) (i32.const 0)))
      ${assertExpr('(i32.ge_s (local.get $d) (i32.const 0))')}
      (call $write_all (local.get $c) ${text('pty-hi\n')})

      ;; 4. Another UnixStream pair: write "sub-sock" into peer end and close peer
      ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 112))`, 0)}
      (local.set $e (i32.load (i32.const 112))) ;; subSock to pass
      (local.set $f (i32.load (i32.const 116))) ;; peer end
      (call $write_all (local.get $f) ${text('sub-sock')})
      ${eq('(call $fd_close (local.get $f))', 0)}

      ;; 5. CloudFs open file ref
      (local.set $f (call $open ${text(cloudFile)} (i32.const 0) (i32.const 0)))
      ${assertExpr('(i32.ge_s (local.get $f) (i32.const 0))')}

      ;; Connect to receiver and send TWO adjacent SCM_RIGHTS messages BEFORE receiver drains!
      ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 124))`, 0)}
      (local.set $n (i32.load (i32.const 124)))
      ${eq(`(call $sock_connect (local.get $n) ${text(sockName)})`, 0)}

      ;; Msg 1: "AAA" + [localFile($a), arenaPipe($b)]
      (i32.store (i32.const 1024) (local.get $a))
      (i32.store (i32.const 1028) (local.get $b))
      ${eq(`(call $sock_sendmsg (local.get $n) ${text('AAA')} (i32.const 1024) (i32.const 2) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 132))`, 0)}
      ${eq('(i32.load (i32.const 132))', 3)}

      ;; Msg 2: "BBB" + [ptySlave($d), subSock($e), cloudFd($f)]
      (i32.store (i32.const 1024) (local.get $d))
      (i32.store (i32.const 1028) (local.get $e))
      (i32.store (i32.const 1032) (local.get $f))
      ${eq(`(call $sock_sendmsg (local.get $n) ${text('BBB')} (i32.const 1024) (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 132))`, 0)}
      ${eq('(i32.load (i32.const 132))', 3)}

      ;; Close sender's copies immediately (proves in-flight fds stay alive in kernel until receiver drains!).
      ${eq('(call $fd_close (local.get $a))', 0)}
      ${eq('(call $fd_close (local.get $b))', 0)}
      ${eq('(call $fd_close (local.get $d))', 0)}
      ${eq('(call $fd_close (local.get $e))', 0)}
      ${eq('(call $fd_close (local.get $f))', 0)}
      ;; Keep PTY master $c alive until receiver closes $n (EOF) so slave does not get SIGHUP before read!
      (drop (call $read_once (local.get $n) (i32.const 4096) (i32.const 16)))
      ${eq('(call $fd_close (local.get $c))', 0)}
      ${eq('(call $fd_close (local.get $n))', 0)}
      ${say('TX_OK\n')}
    `, { sync: syncMode });

    await startHost(page, `u04-rx-${syncMode}`, rxPath);
    await hostReady(page, `u04-rx-${syncMode}`, 'RX_READY');
    await startHost(page, `u04-tx-${syncMode}`, txPath);
    await hostResult(page, `u04-rx-${syncMode}`, 0);
    await hostResult(page, `u04-tx-${syncMode}`, 0);
    expect(await hostOutput(page, `u04-rx-${syncMode}`)).toContain('U04_U05_OK');
    expect(await hostOutput(page, `u04-tx-${syncMode}`)).toContain('TX_OK');
  });
}

test('U-06: poll_oneoff readiness & hangup + SIGPIPE / MSG_NOSIGNAL', async ({ page }) => {
  // Part A: poll_oneoff on stream read/write, SHUT_WR hangup, and MSG_NOSIGNAL -> EPIPE without dying.
  const pollPath = await uploadWasm(page, base, 'u06-poll', ({ text, say, eq, assertExpr }) => `
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    (local.set $b (i32.load (i32.const 104)))

    ;; Poll $a for write readiness (type=2) -> immediately ready with room > 0
    (i64.store (i32.const 200) (i64.const 11))
    (i32.store8 (i32.const 208) (i32.const 2))
    (i32.store (i32.const 216) (local.get $a))
    ${eq('(call $poll_oneoff (i32.const 200) (i32.const 300) (i32.const 1) (i32.const 108))', 0)}
    ${eq('(i32.load (i32.const 108))', 1)}
    ${eq('(i32.load16_u (i32.const 308))', 0)}
    ${assertExpr('(i64.gt_u (i64.load (i32.const 316)) (i64.const 0))')}

    ;; Write "hi" to $a, poll $b for read readiness (type=1) -> ready with nbytes == 2, hangup == 0
    (call $write_all (local.get $a) ${text('hi')})
    (i64.store (i32.const 200) (i64.const 22))
    (i32.store8 (i32.const 208) (i32.const 1))
    (i32.store (i32.const 216) (local.get $b))
    ${eq('(call $poll_oneoff (i32.const 200) (i32.const 300) (i32.const 1) (i32.const 108))', 0)}
    ${eq('(i32.load (i32.const 108))', 1)}
    ${assertExpr('(i64.eq (i64.load (i32.const 316)) (i64.const 2))')}
    ${eq('(i32.load16_u (i32.const 324))', 0)}
    (call $read_exact (local.get $b) (i32.const 4096) (i32.const 2))

    ;; SHUT_WR on $a -> poll $b for read reports hangup flag (1)!
    ${eq(`(call $sock_shutdown (local.get $a) (i32.const ${SHUT_WR}))`, 0)}
    ${eq('(call $poll_oneoff (i32.const 200) (i32.const 300) (i32.const 1) (i32.const 108))', 0)}
    ${eq('(i32.load (i32.const 108))', 1)}
    ${eq('(i32.load16_u (i32.const 324))', 1)}

    ;; Close $b, then send on $a with MSG_NOSIGNAL -> returns EPIPE (64) WITHOUT killing process!
    ${eq('(call $fd_close (local.get $b))', 0)}
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('x')} (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const ${MSG_NOSIGNAL}) (i32.const 112))`, ERR.EPIPE)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${say('POLL_NOSIGNAL_OK\n')}
  `);

  // Part B: sendmsg WITHOUT MSG_NOSIGNAL on closed peer kills process with SIGPIPE (exit 128 + 13 = 141)!
  const sigpipePath = await uploadWasm(page, base, 'u06-sigpipe', ({ text, eq }) => `
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    (local.set $b (i32.load (i32.const 104)))
    ${eq('(call $fd_close (local.get $b))', 0)}
    (drop (call $sock_sendmsg (local.get $a) ${text('boom')} (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 112)))
    (call $proc_exit (i32.const 0))
  `);

  await startHost(page, 'u06-poll', pollPath);
  await hostResult(page, 'u06-poll', 0);
  expect(await hostOutput(page, 'u06-poll')).toContain('POLL_NOSIGNAL_OK');

  await startHost(page, 'u06-sigpipe', sigpipePath);
  await hostResult(page, 'u06-sigpipe', 128 + 13);
});

test('U-08 & U-09: SO_PEERCRED anti-spoofing + DAC & POSIX ACL W_OK enforcement on connect', async ({ page }) => {
  await loginRoot(page);
  await hostCall(page, 'sync_account', ROOT_ACCOUNT);

  const srvPath = await uploadWasm(page, base, 'u08-u09-srv', ({ text, say, sysJson, eq, assertExpr }) => `
    ;; Create RO dir /tmp/u09-ro (0555)
    ${sysJson([{ mkdir: { path: '/tmp/u09-ro', mode: 0o555 } }, { chmod: { path: '/tmp/u09-ro', mode: 0o555 } }])}
    ;; Public socket /run/u08-pub.sock (0666)
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_bind (local.get $a) ${text('/run/u08-pub.sock')})`, 0)}
    ${sysJson([{ chmod: { path: '/run/u08-pub.sock', mode: 0o666 } }])}
    ${eq('(call $sock_listen (local.get $a) (i32.const 8))', 0)}

    ;; Private root-only socket /run/u09-priv.sock (0600)
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 104))`, 0)}
    (local.set $b (i32.load (i32.const 104)))
    ${eq(`(call $sock_bind (local.get $b) ${text('/run/u09-priv.sock')})`, 0)}
    ${sysJson([{ chmod: { path: '/run/u09-priv.sock', mode: 0o600 } }])}
    ${eq('(call $sock_listen (local.get $b) (i32.const 8))', 0)}

    ;; Root-only control socket /run/u09-ctl.sock (0600) to signal ACL applied
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 180))`, 0)}
    (local.set $e (i32.load (i32.const 180)))
    ${eq(`(call $sock_bind (local.get $e) ${text('/run/u09-ctl.sock')})`, 0)}
    ${sysJson([{ chmod: { path: '/run/u09-ctl.sock', mode: 0o600 } }])}
    ${eq('(call $sock_listen (local.get $e) (i32.const 4))', 0)}
    ${say('READY\n')}

    ;; Accept guest client on /run/u08-pub.sock -> read spoofed '{"pid":1,"uid":0,"gid":0}' payload
    ;; -> verify SO_PEERCRED refuses spoofing (uid > 0, gid == 65534, NEVER uid == 0)!
    ${eq('(call $sock_accept (local.get $a) (i32.const 0) (i32.const 108))', 0)}
    (local.set $c (i32.load (i32.const 108)))
    ${eq('(call $sock_recvmsg (local.get $c) (i32.const 4096) (i32.const 128) (i32.const 0) (i32.const 0) (i32.const 112) (i32.const 120) (i32.const 0) (i32.const 116) (i32.const 136))', 0)}
    ${assertExpr('(i32.gt_u (i32.load (i32.const 124)) (i32.const 0))')}
    ${eq('(i32.load (i32.const 128))', 65534)}
    ${eq('(call $sock_peercred (local.get $c) (i32.const 140))', 0)}
    ${assertExpr('(i32.gt_u (i32.load (i32.const 140)) (i32.const 1))')}
    ${assertExpr('(i32.eq (i32.load (i32.const 144)) (i32.load (i32.const 124)))')}
    ${eq('(i32.load (i32.const 148))', 65534)}
    ${say('PEER_UID=')} (call $say_u32 (i32.load (i32.const 144))) ${say('\n')}

    ;; Wait for root ACL granter to signal on /run/u09-ctl.sock, then tell guest "ACL_SET" over $c!
    ${eq('(call $sock_accept (local.get $e) (i32.const 0) (i32.const 184))', 0)}
    ${eq('(call $fd_close (i32.load (i32.const 184)))', 0)}
    (call $write_all (local.get $c) ${text('ACL_SET')})

    ;; Accept guest on /run/u09-priv.sock (now allowed by u:<guestUid>:rw POSIX ACL!) and verify authentic uid!
    ${eq('(call $sock_accept (local.get $b) (i32.const 0) (i32.const 152))', 0)}
    (local.set $d (i32.load (i32.const 152)))
    ${eq('(call $sock_peercred (local.get $d) (i32.const 160))', 0)}
    ${assertExpr('(i32.eq (i32.load (i32.const 164)) (i32.load (i32.const 144)))')}

    ${eq('(call $fd_close (local.get $d))', 0)}
    ${eq('(call $fd_close (local.get $c))', 0)}
    ${eq('(call $fd_close (local.get $e))', 0)}
    ${eq('(call $fd_close (local.get $b))', 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${eq(`(call $unlink (i32.const 3) ${text('/run/u08-pub.sock')})`, 0)}
    ${eq(`(call $unlink (i32.const 3) ${text('/run/u09-priv.sock')})`, 0)}
    ${eq(`(call $unlink (i32.const 3) ${text('/run/u09-ctl.sock')})`, 0)}
    ${say('U08_U09_SRV_OK\n')}
  `);

  const guestPath = await uploadWasm(page, base, 'u08-u09-guest', ({ text, say, eq }) => `
    ;; 1. Guest bind in 0555 dir MUST fail EACCES
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_bind (local.get $a) ${text('/tmp/u09-ro/deny.sock')})`, ERR.EACCES)}

    ;; 2. Guest connect to 0600 root:root /run/u09-priv.sock MUST fail EACCES
    ${eq(`(call $sock_connect (local.get $a) ${text('/run/u09-priv.sock')})`, ERR.EACCES)}

    ;; 3. Guest connects to /run/u08-pub.sock and attempts to spoof root peercred in payload!
    ${eq(`(call $sock_connect (local.get $a) ${text('/run/u08-pub.sock')})`, 0)}
    ;; Verify server peercred is root (uid=0)
    ${eq('(call $sock_peercred (local.get $a) (i32.const 120))', 0)}
    ${eq('(i32.load (i32.const 124))', 0)}
    (call $write_all (local.get $a) ${text('{"pid":1,"uid":0,"gid":0}')})

    ;; Wait for server to grant POSIX ACL u:<guestUid>:rw ("ACL_SET")
    (call $read_exact (local.get $a) (i32.const 4096) (i32.const 7))

    ;; 4. Retry connect to /run/u09-priv.sock -> NOW SUCCEEDS via POSIX ACL!
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 104))`, 0)}
    (local.set $b (i32.load (i32.const 104)))
    ${eq(`(call $sock_connect (local.get $b) ${text('/run/u09-priv.sock')})`, 0)}

    ${eq('(call $fd_close (local.get $b))', 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${say('U08_U09_CLI_OK\n')}
  `);

  await startHost(page, 'u08-srv', srvPath);
  await hostReady(page, 'u08-srv', 'READY');

  // Drop ambient session to unprivileged guest while root server keeps uid 0!
  expect((await api(page.request, 'logout')).ok()).toBe(true);
  await hostCall(page, 'sync_account', GUEST_ACCOUNT);

  await startHost(page, 'u08-cli', guestPath);
  await hostReady(page, 'u08-srv', 'PEER_UID=');
  const srvOut = await hostOutput(page, 'u08-srv');
  const guestUid = Number(srvOut.match(/PEER_UID=(\d+)/)[1]);
  expect(guestUid).toBeGreaterThan(0);

  // Log in as root to apply exact POSIX ACL `u:<guestUid>:rw` on `/run/u09-priv.sock` and notify server.
  await loginRoot(page);
  await hostCall(page, 'sync_account', ROOT_ACCOUNT);
  const aclForGuest = Buffer.from(JSON.stringify({
    user: 6, group: 0, other: 0, mask: 6, users: { [guestUid]: 6 }, groups: {},
  })).toString('base64');
  const aclPath = await uploadWasm(page, base, 'u09-acl', ({ text, sysJson, eq }) => `
    ${sysJson([{ setxattr: { path: '/run/u09-priv.sock', name: 'system.posix_acl_access', value: aclForGuest } }])}
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_connect (local.get $a) ${text('/run/u09-ctl.sock')})`, 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
  `);
  await startHost(page, 'u09-acl', aclPath);
  await hostResult(page, 'u09-acl', 0);

  await hostResult(page, 'u08-cli', 0);
  await hostResult(page, 'u08-srv', 0);
  expect(await hostOutput(page, 'u08-srv')).toContain('U08_U09_SRV_OK');
  expect(await hostOutput(page, 'u08-cli')).toContain('U08_U09_CLI_OK');
});

test('U-10: SCM_RIGHTS remote CloudFs open-ref attenuation & revocation on sender SIGKILL', async ({ page }) => {
  await loginRoot(page);
  const secret1 = `${base}/secret-1.txt`;
  const secret2 = `${base}/secret-2.txt`;
  expect((await put(page.request, `/api/file?path=${secret1}&overwrite=true`, { data: 'top-secret-cloud-data' })).ok()).toBe(true);
  expect((await put(page.request, `/api/file?path=${secret2}&overwrite=true`, { data: 'forbidden-second-file' })).ok()).toBe(true);
  await call(page.request, { chmod: { path: secret1, mode: 0o600 } });
  await call(page.request, { chmod: { path: secret2, mode: 0o600 } });
  await hostCall(page, 'sync_account', ROOT_ACCOUNT);

  // Root sender opens secret1 (CloudFs, 0600 root:root), sends open ref over /run/u10.sock, then stays alive until SIGKILLed.
  const srvPath = await uploadWasm(page, base, 'u10-srv', ({ text, say, sysJson, eq, assertExpr }) => `
    (local.set $c (call $open ${text(secret1)} (i32.const 0) (i32.const 0)))
    ${assertExpr('(i32.ge_s (local.get $c) (i32.const 0))')}
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_bind (local.get $a) ${text('/run/u10.sock')})`, 0)}
    ${sysJson([{ chmod: { path: '/run/u10.sock', mode: 0o666 } }])}
    ${eq('(call $sock_listen (local.get $a) (i32.const 4))', 0)}
    ${say('U10_READY\n')}
    ${eq('(call $sock_accept (local.get $a) (i32.const 0) (i32.const 104))', 0)}
    (local.set $b (i32.load (i32.const 104)))
    (i32.store (i32.const 1024) (local.get $c))
    ${eq(`(call $sock_sendmsg (local.get $b) ${text('FD')} (i32.const 1024) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, 0)}
    ;; Block reading $b until Playwright sends SIGKILL!
    (drop (call $read_once (local.get $b) (i32.const 4096) (i32.const 16)))
  `);

  // Guest receiver (uid 65534, cloud_access=false) receives attenuated fd, reads secret1, fails to open secret2,
  // waits for sender SIGKILL (EOF on socket), then retries reading attenuated fd -> MUST fail EACCES!
  const cliPath = await uploadWasm(page, base, 'u10-cli', ({ text, say, eq, assertExpr }) => `
    ${eq(`(call $sock_socket (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    ${eq(`(call $sock_connect (local.get $a) ${text('/run/u10.sock')})`, 0)}
    ${eq('(call $sock_recvmsg (local.get $a) (i32.const 4096) (i32.const 16) (i32.const 1024) (i32.const 4) (i32.const 104) (i32.const 120) (i32.const 0) (i32.const 108) (i32.const 112))', 0)}
    ${eq('(i32.load (i32.const 104))', 1)}
    (local.set $b (i32.load (i32.const 1024))) ;; attenuated CloudFs fd

    ;; 1. Reading attenuated fd succeeds!
    (call $read_exact (local.get $b) (i32.const 4200) (i32.const 21))
    ${eq('(i32.load8_u (i32.const 4200))', 116)} ;; 't'
    ${eq('(i32.load8_u (i32.const 4220))', 97)}  ;; 'a'

    ;; 2. Direct open of another 0600 root CloudFs file MUST fail -EACCES!
    ${eq(`(call $open ${text(secret2)} (i32.const 0) (i32.const 0))`, -ERR.EACCES)}
    ${say('ATTENUATED_OK\n')}

    ;; 3. Wait for sender to be SIGKILLed (EOF on $a)
    ${eq('(call $read_once (local.get $a) (i32.const 4096) (i32.const 16))', 0)}

    ;; 4. After sender's token is revoked, seeking/reading attenuated fd MUST fail with EACCES!
    (local.set $n (call $fd_seek (local.get $b) (i64.const 0) (i32.const 0) (i32.const 200)))
    ${assertExpr(`(i32.eq (local.get $n) (i32.const ${ERR.EACCES}))`)}
    (i32.store (i32.const 16) (i32.const 4200))
    (i32.store (i32.const 20) (i32.const 21))
    ${eq('(call $fd_read (local.get $b) (i32.const 16) (i32.const 1) (i32.const 24))', ERR.EACCES)}

    ${eq('(call $fd_close (local.get $b))', 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${say('REVOKED_OK\n')}
  `);

  await startHost(page, 'u10-srv', srvPath);
  await hostReady(page, 'u10-srv', 'U10_READY');

  // Drop ambient session to unprivileged guest (cloud_access=false) while root sender stays alive.
  expect((await api(page.request, 'logout')).ok()).toBe(true);
  await hostCall(page, 'sync_account', GUEST_ACCOUNT);

  await startHost(page, 'u10-cli', cliPath);
  await hostReady(page, 'u10-cli', 'ATTENUATED_OK');

  // SIGKILL the root sender -> revokes its remote token immediately and closes its socket!
  await hostCall(page, 'run_signal', { run: 'u10-srv', signal: 9 });
  await hostResult(page, 'u10-cli', 0);
  expect(await hostOutput(page, 'u10-cli')).toContain('REVOKED_OK');

  // Clean up /run/u10.sock & log back in as root so afterEach rmrf removes 0600 files cleanly.
  await loginRoot(page);
  await hostCall(page, 'sync_account', ROOT_ACCOUNT);
});

test('U-11: SCM_RIGHTS DoS limits (>64 EINVAL, quota ETOOMANYREFS), invalid-fd atomicity, MSG_CTRUNC at FD_MAX, & cycle GC zero leak', async ({ page }) => {
  const dosPath = await uploadWasm(page, base, 'u11-dos', ({ text, say, eq, assertExpr }) => `
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    (local.set $b (i32.load (i32.const 104)))
    (local.set $c (call $open ${text('/tmp/u11-f.txt')} (i32.const ${2 | 0o100 | 0o1000}) (i32.const ${0o600})))
    ${assertExpr('(i32.ge_s (local.get $c) (i32.const 0))')}

    ;; 1. >64 fds (65) -> EINVAL (28)
    (local.set $i (i32.const 0))
    (loop $fill65
      (if (i32.lt_u (local.get $i) (i32.const 65)) (then
        (i32.store (i32.add (i32.const 1024) (i32.mul (local.get $i) (i32.const 4))) (local.get $c))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $fill65))))
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('bad')} (i32.const 1024) (i32.const 65) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, ERR.EINVAL)}

    ;; 2. Invalid fd atomicity: [valid $c, invalid 9999] -> EBADF (8), ZERO bytes delivered!
    (i32.store (i32.const 1024) (local.get $c))
    (i32.store (i32.const 1028) (i32.const 9999))
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('atomic-nope')} (i32.const 1024) (i32.const 2) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, ERR.EBADF)}
    ${eq(`(call $sock_recvmsg (local.get $b) (i32.const 4096) (i32.const 64) (i32.const 1500) (i32.const 4) (i32.const 112) (i32.const 120) (i32.const ${MSG_DONTWAIT}) (i32.const 116) (i32.const 136))`, ERR.EAGAIN)}

    ;; 3. Per-user in-flight quota (256): 4 x 64 = 256 succeeds, 257th -> ETOOMANYREFS (109)!
    (i32.store (i32.const 1028) (local.get $c))
    (local.set $i (i32.const 0))
    (loop $q4
      (if (i32.lt_u (local.get $i) (i32.const 4)) (then
        ${eq(`(call $sock_sendmsg (local.get $a) ${text('Q')} (i32.const 1024) (i32.const 64) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, 0)}
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $q4))))
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('X')} (i32.const 1024) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, ERR.ETOOMANYREFS)}

    ;; Close $a and $b -> drains all 256 in-flight fds cleanly!
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${eq('(call $fd_close (local.get $b))', 0)}

    ;; 4. Receiver near FD_MAX (1024): open dups until only 3 free fds remain, then recvmsg 8 fds -> installs 3 + sets MSG_CTRUNC!
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    (local.set $b (i32.load (i32.const 104)))
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('TRNC')} (i32.const 1024) (i32.const 8) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, 0)}
    ;; Fill fd table up to fd 1020 (leaving ONLY 1021, 1022, 1023 = 3 slots free!)
    (loop $fill_fds
      (if (i32.eqz (call $fd_dup (local.get $c) (i32.const 140))) (then
        (local.set $d (i32.load (i32.const 140)))
        (if (i32.lt_u (local.get $d) (i32.const 1020)) (then (br $fill_fds))))))
    ;; Recvmsg with cap=8 -> MUST deliver 4 bytes "TRNC", install exactly 3 fds, set MSG_CTRUNC (8), and leak 0 fds!
    ${eq('(call $sock_recvmsg (local.get $b) (i32.const 4096) (i32.const 64) (i32.const 1500) (i32.const 8) (i32.const 112) (i32.const 120) (i32.const 0) (i32.const 116) (i32.const 136))', 0)}
    ${eq('(i32.load (i32.const 116))', 4)}
    ${eq('(i32.load (i32.const 112))', 3)}
    ${eq(`(i32.and (i32.load (i32.const 136)) (i32.const ${MSG_CTRUNC}))`, MSG_CTRUNC)}

    ;; Close all duped fds + $a + $b + $c
    (local.set $i (i32.const 4))
    (loop $close_all
      (if (i32.lt_u (local.get $i) (i32.const 1024)) (then
        (drop (call $fd_close (local.get $i)))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $close_all))))

    ;; 5. Reference cycle GC: socketpair(a, b), send a over a & b over b, close BOTH -> unix_gc reclaims everything!
    ${eq(`(call $sock_socketpair (i32.const ${AF_UNIX}) (i32.const ${SOCK_STREAM}) (i32.const 0) (i32.const 100))`, 0)}
    (local.set $a (i32.load (i32.const 100)))
    (local.set $b (i32.load (i32.const 104)))
    (i32.store (i32.const 1024) (local.get $a))
    ${eq(`(call $sock_sendmsg (local.get $a) ${text('A')} (i32.const 1024) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, 0)}
    (i32.store (i32.const 1024) (local.get $b))
    ${eq(`(call $sock_sendmsg (local.get $b) ${text('B')} (i32.const 1024) (i32.const 1) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 108))`, 0)}
    ${eq('(call $fd_close (local.get $a))', 0)}
    ${eq('(call $fd_close (local.get $b))', 0)}
    ${say('U11_OK\n')}
  `);

  await startHost(page, 'u11', dosPath);
  await hostResult(page, 'u11', 0);
  expect(await hostOutput(page, 'u11')).toContain('U11_OK');

  // Verify ZERO leaked sockets, bound inodes, in-flight fds, or SockArena slots in client-kernel!
  const stats = (await hostCall(page, 'run_sock_stats')).ok;
  expect(stats).toEqual({
    activeSockets: 0,
    boundInodes: 0,
    inflightGlobal: 0,
    allocatedArenaSlots: 0,
  });
});
