import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';
import { api, call, put, rmrf } from './sys.js';

const prompt = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const screen = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
const assert = expression => `(call $assert ${expression})`;
const eq = (expression, n) => assert(`(i32.eq ${expression} (i32.const ${n}))`);
const ignoreHup = '(drop (call $action (i32.const 1) (i32.const 1) (i32.const 0) (i32.const 0)))';
const fork = eq('(call $fork (i32.const 1) (i32.const 48))', 0);
const wait = `${assert('(i32.eq (call $wait (i32.load (i32.const 48)) (i32.const 80) (i32.const 0)) (i32.load (i32.const 48)))')}
  ${eq('(i32.load (i32.const 80))', 0)}`;
const raw = { iflag: 0, oflag: 0, cflag: 0xb0, lflag: 0, cc: Array(32).fill(0) }; raw.cc[6] = 1;
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const login = async page => expect((await api(page.request, 'login', {
  headers: { 'CF-Connecting-IP': 'host-pty-' + crypto.randomUUID() }, data: { password },
})).ok()).toBe(true);
let base;
test.beforeEach(async ({ page }) => { await page.goto('/'); base = '/guest/ptmx-' + crypto.randomUUID(); await call(page.request, { mkdir: { path: base, mode: 0o755 } }); });
test.afterEach(async ({ page }) => { await rmrf(page.request, base); });
async function run(page, path) {
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle');
  await page.locator('#command').fill(path); await page.locator('#command').press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}

// Independent launches through one public kernel port. This exercises host ownership
// without sharing process tokens or reaching into the driver's private maps.
async function connectHost(page) {
  await page.evaluate(() => {
    const port = new Worker('/client-kernel.js'), pending = new Map(), runs = new Map();
    let next = 0;
    const request = (type, args = {}) => new Promise(resolve => {
      const id = ++next; pending.set(id, resolve); port.postMessage({ v: 1, id, type, args });
    });
    port.onmessage = ({ data }) => {
      if (data.id != null) { pending.get(data.id)?.(data); pending.delete(data.id); return; }
      const event = data.value, run = runs.get(event?.run);
      if (!run) return;
      if (event.type === 'output') { run.output += event.text; void request('run_output_ack', { run: event.run, sequence: event.sequence }); }
      if (event.type === 'job') run.pids = event.pids;
      if (event.type === 'device') run.stamp = event.stamp;
    };
    window.ptyHost = { request, runs, start(id, path, options = {}) {
      const run = { output: '', pids: [] }; runs.set(id, run);
      run.done = request('run', { run: id, stages: [{ path, argv: [path] }], options: { tty: true, ...options } })
        .then(result => { run.result = result; });
    } };
  });
}
const startHost = (page, id, path, options) => page.evaluate(([id, path, options]) => window.ptyHost.start(id, path, options), [id, path, options]);
const hostOutput = (page, id) => page.evaluate(id => window.ptyHost.runs.get(id).output.replace(/\r\n/g, '\n'), id);
const hostReady = (page, id, text) => expect.poll(() => hostOutput(page, id), { timeout: 60_000 }).toContain(text);
const hostNumber = async (page, id) => JSON.parse((await hostOutput(page, id)).split('\n').find(s => s.startsWith('{'))).results[0].ok.number;
const hostInput = (page, id, text) => page.evaluate(([run, text]) => window.ptyHost.request('run_input', { run, text, stamp: window.ptyHost.runs.get(run).stamp }), [id, text]);
const hostCall = (page, type, args) => page.evaluate(([type, args]) => window.ptyHost.request(type, args), [type, args]);
async function hostResult(page, id, status = 0) {
  await expect.poll(() => page.evaluate(id => window.ptyHost.runs.get(id).result, id), { timeout: 60_000 }).toMatchObject({ ok: { status } });
}
async function closeHost(page) {
  await page.evaluate(async base => {
    if (!window.ptyHost) return;
    const { request, runs } = window.ptyHost;
    await Promise.all([...runs.keys()].map(run => request('run_signal', { run, signal: 9 })));
    const rows = await request('poll', { pids: [] });
    await Promise.all((rows.ok ?? []).filter(p => p.path?.startsWith(base + '/')).map(p => request('kill', { pid: p.pid, signal: 9 })));
    await request('reconcile');
    await Promise.all([...runs.values()].map(run => run.done));
  }, base);
}
const results = async page => (await screen(page).textContent()).split('\n').filter(s => s.startsWith('{')).map(s => JSON.parse(s).results[0]);
async function upload(page, name, build) {
  let at = 16384; const segments = [];
  const text = value => { const data = Buffer.from(value), ptr = at; at += data.length + 1;
    segments.push(`(data (i32.const ${ptr}) "${[...data].map(n => '\\' + n.toString(16).padStart(2, '0')).join('')}")`);
    return `(i32.const ${ptr}) (i32.const ${data.length})`; };
  const q = (request, fd = 4, arg = 0) => `(call $json ${text(JSON.stringify([{ ioctl: { fd, request, arg } }]))})`;
  const say = value => `(call $say ${text(value)})`;
  const openSlave = (flags = 2, fd = 5) => eq(`(call $open (i32.const 1024) (global.get $nameLen) (i32.const ${flags}) (i32.const 0))`, fd);
  const master = `${eq(`(call $wopen (i32.const 3) (i32.const 1) ${text('/dev/ptmx')} (i32.const 0) (i64.const 66) (i64.const 0) (i32.const 0) (i32.const 32))`, 0)} ${eq('(i32.load (i32.const 32))', 4)}
    ${q(0x80045430)} (call $name)`;
  const setup = (flags = 2) => `${master} ${q(0x40045431)} ${openSlave(flags)}`;
  const write = (fd, value) => `(call $send (i32.const ${fd}) ${text(value)})`;
  const body = build({ q, say, text, openSlave, master, setup, write });
  const module = binaryen.parseText(`(module
    (import "os" "sys" (func $sys (param i32 i32) (result i32)))
    (import "os" "reply" (func $reply (param i32)))
    (import "os" "open" (func $open (param i32 i32 i32 i32) (result i32)))
    (import "os" "setsid" (func $setsid (result i32)))
    (import "os" "tcgetpgrp" (func $fg (param i32) (result i32)))
    (import "os" "getpgid" (func $pgid (param i32) (result i32)))
    (import "os" "waitpid2" (func $wait (param i32 i32 i32) (result i32)))
    (import "os" "sigaction" (func $action (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "path_open" (func $wopen (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $fdstat (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_set_flags" (func $flags (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "clock_time_get" (func $clock (param i32 i64 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_raise" (func $raise (param i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))
    (import "wasix_32v1" "proc_signal" (func $kill (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_renumber" (func $dup2 (param i32 i32) (result i32)))
    (memory (export "memory") 1) (global $nameLen (mut i32) (i32.const 0))
    (func $assert (param $value i32) (if (i32.eqz (local.get $value)) (then unreachable)))
    (func $send (param $fd i32) (param $ptr i32) (param $len i32)
      (i32.store (i32.const 128) (local.get $ptr)) (i32.store (i32.const 132) (local.get $len))
      ${eq('(call $write (local.get $fd) (i32.const 128) (i32.const 1) (i32.const 136))', 0)}
      ${assert('(i32.eq (i32.load (i32.const 136)) (local.get $len))')})
    (func $say (param $ptr i32) (param $len i32) (call $send (i32.const 1) (local.get $ptr) (local.get $len)))
    (func $json (param $ptr i32) (param $len i32) (local $size i32)
      (local.set $size (call $sys (local.get $ptr) (local.get $len))) (call $reply (i32.const 4096))
      (call $say (i32.const 4096) (local.get $size)) (i32.store8 (i32.const 144) (i32.const 10)) (call $say (i32.const 144) (i32.const 1)))
    (func $name (local $at i32) (local $len i32)
      (local.set $at (i32.const 4096))
      (loop $find ${assert('(i32.lt_u (local.get $at) (i32.const 5000))')}
        (if (i32.ne (i32.load8_u (local.get $at)) (i32.const 47)) (then (local.set $at (i32.add (local.get $at) (i32.const 1))) (br $find))))
      (loop $copy (if (i32.ne (i32.load8_u (i32.add (local.get $at) (local.get $len))) (i32.const 34)) (then
        (i32.store8 (i32.add (i32.const 1024) (local.get $len)) (i32.load8_u (i32.add (local.get $at) (local.get $len))))
        (local.set $len (i32.add (local.get $len) (i32.const 1))) (br $copy))))
      (global.set $nameLen (local.get $len)))
    (func $receive (param $fd i32) (param $count i32) (result i32)
      (i32.store (i32.const 128) (i32.const 8192)) (i32.store (i32.const 132) (local.get $count))
      (call $read (local.get $fd) (i32.const 128) (i32.const 1) (i32.const 136)))
    (func (export "_start") (local $n i32) (local $status i32) ${body}) ${segments.join('\n')})`);
  let bytes; try { bytes = module.emitBinary(); } finally { module.dispose(); }
  const path = `${base}/${name}.wasm`; expect((await put(page.request, '/api/file?path=' + path, { data: Buffer.from(bytes) })).ok()).toBe(true); await call(page.request, { chmod: { path, mode: 0o755 } }); return path;
}

test('ptmx locks slaves, enforces modes and transports raw binary data', async ({ page }) => {
  const path = await upload(page, 'binary', ({ master, q, openSlave, say, write }) => `${master}
    ${openSlave(2, -29)} ${q(0x80045439)} ${q(0x540e)} ${q(0x40045431)}
    ${openSlave(2 | 65536, -54)} ${openSlave(0)}
    ${eq('(call $fdstat (i32.const 5) (i32.const 200))', 0)}
    ${assert('(i64.eqz (i64.and (i64.load (i32.const 208)) (i64.const 64)))')}
    (i32.store (i32.const 128) (i32.const 8192)) (i32.store (i32.const 132) (i32.const 1))
    ${eq('(call $write (i32.const 5) (i32.const 128) (i32.const 1) (i32.const 136))', 8)}
    ${eq('(call $close (i32.const 5))', 0)} ${openSlave()} ${q(0x5402, 5, raw)}
    (loop $fill (i32.store8 (i32.add (i32.const 12288) (local.get $n)) (local.get $n))
      (local.set $n (i32.add (local.get $n) (i32.const 1))) (br_if $fill (i32.lt_u (local.get $n) (i32.const 256))))
    (call $send (i32.const 4) (i32.const 12288) (i32.const 256))
    ${eq('(call $receive (i32.const 5) (i32.const 256))', 0)} ${eq('(i32.load (i32.const 136))', 256)}
    (local.set $n (i32.const 0))
    (loop $check ${assert('(i32.eq (i32.load8_u (i32.add (i32.const 8192) (local.get $n))) (local.get $n))')}
      (local.set $n (i32.add (local.get $n) (i32.const 1))) (br_if $check (i32.lt_u (local.get $n) (i32.const 256))))
    (call $send (i32.const 5) (i32.const 8192) (i32.const 256))
    ${eq('(call $receive (i32.const 4) (i32.const 256))', 0)} ${eq('(i32.load (i32.const 136))', 256)}
    ${write(4, 'x')}
    (i32.store (i32.const 128) (i32.const 8192)) (i32.store (i32.const 132) (i32.const 1))
    (i32.store (i32.const 136) (i32.const 8193)) (i32.store (i32.const 140) (i32.const 1))
    ${eq('(call $read (i32.const 5) (i32.const 128) (i32.const 2) (i32.const 148))', 0)}
    ${eq('(i32.load (i32.const 148))', 1)} ${q(0x5441)} ${say('binary-ok\n')}`);
  await run(page, path); await expect(screen(page)).toContainText('binary-ok');
  const r = await results(page); expect(r[1]).toEqual({ ok: { locked: 1 } }); expect(r[2].err.errno).toBe('ENOTTY'); expect(r.at(-1).err.errno).toBe('ENOTTY');
});

test('O_NOCTTY suppresses acquisition and ordinary slave opens acquire only for a session leader', async ({ page }) => {
  const child = await upload(page, 'inherited', ({ say }) => `${assert('(i32.eq (call $fg (i32.const 6)) (call $pgid (i32.const 0)))')} ${say('exec-associated\n')}`);
  const path = await upload(page, 'acquire', ({ setup, openSlave, q, say, text }) => `${ignoreHup} ${q(0x5422, 0)} ${setup(2 | 256)}
    ${eq('(call $fg (i32.const 5))', -59)} ${eq('(call $close (i32.const 5))', 0)}
    ${openSlave()} ${assert('(i32.eq (call $fg (i32.const 5)) (call $pgid (i32.const 0)))')}
    ${eq(`(call $open ${text('/dev/tty')} (i32.const 2) (i32.const 0))`, 6)}
    ${fork} (if (i32.eqz (i32.load (i32.const 48))) (then (call $exec ${text(child)} ${text(child)})))
    ${wait} ${say('acquisition-ok\n')}`);
  await run(page, path); await expect(screen(page)).toContainText('exec-associated'); await expect(screen(page)).toContainText('acquisition-ok');
});

test('a program can fork and exec installed sh on a new PTY', async ({ page }) => {
  const path = await upload(page, 'shell', ({ setup, q, text, write, say }) => `${setup(2 | 256)}
    ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      ${eq('(call $close (i32.const 4))', 0)} ${assert('(i32.gt_s (call $setsid) (i32.const 1))')} ${q(0x540e, 5)}
      ${[0, 1, 2].map(fd => eq(`(call $dup2 (i32.const 5) (i32.const ${fd}))`, 0)).join('\n')}
      ${eq('(call $close (i32.const 5))', 0)}
      (call $exec ${text('/usr/bin/sh')} ${text("sh\n-c\ntty; ls /dev/pts; readlink /proc/self/fd/0; printf 'tty\\n' | xargs -o; stty -echo; read value; printf 'nested:%s\\n' \"$value\"\n")})))
    ${eq('(call $close (i32.const 5))', 0)} ${write(4, 'hello\n')}
    (block $done (loop $drain
      (local.set $status (call $receive (i32.const 4) (i32.const 4096)))
      (br_if $done (i32.eq (local.get $status) (i32.const 29)))
      ${eq('(local.get $status)', 0)} (call $say (i32.const 8192) (i32.load (i32.const 136))) (br $drain)))
    ${wait} ${say('nested-shell-ok\n')}`);
  await run(page, path); await expect(screen(page)).toContainText('nested:hello'); await expect(screen(page)).toContainText('nested-shell-ok');
  await expect(screen(page)).toContainText('/dev/pts/107');
});

test('closing the last master resumes a stopped foreground child and hangs up its slave', async ({ page }) => {
  const path = await upload(page, 'hangup', ({ setup, q, say }) => `${ignoreHup} ${setup(2 | 256)} ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      ${eq('(call $close (i32.const 4))', 0)} ${assert('(i32.gt_s (call $setsid) (i32.const 1))')} ${q(0x540e, 5)}
      (drop (call $raise (i32.const 19))) ${eq('(call $fg (i32.const 5))', -59)}
      ${eq('(call $receive (i32.const 5) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 0)} ${q(0x540e, 5)}
      ${say('hangup-child-ok\n')} (call $exit (i32.const 0))))
    ${assert('(i32.eq (call $wait (i32.load (i32.const 48)) (i32.const 80) (i32.const 2)) (i32.load (i32.const 48)))')}
    ${eq('(i32.and (i32.load (i32.const 80)) (i32.const 255))', 127)}
    ${eq('(call $close (i32.const 5))', 0)} ${eq('(call $close (i32.const 4))', 0)}
    ${wait} ${say('hangup-parent-ok\n')}`);
  await run(page, path); await expect(screen(page)).toContainText('hangup-child-ok'); await expect(screen(page)).toContainText('hangup-parent-ok');
  expect((await results(page)).some(result => result.err?.errno === 'EIO')).toBe(true);
});

test('an outright-killed master holder releases its descriptors before parent wait returns', async ({ page }) => {
  const path = await upload(page, 'kill', ({ setup, say }) => `${setup(2 | 256)} ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      ${eq('(call $close (i32.const 5))', 0)} (drop (call $raise (i32.const 19))) (unreachable)))
    ${assert('(i32.eq (call $wait (i32.load (i32.const 48)) (i32.const 80) (i32.const 2)) (i32.load (i32.const 48)))')}
    ${eq('(call $close (i32.const 4))', 0)} ${eq('(call $kill (i32.load (i32.const 48)) (i32.const 9))', 0)}
    ${assert('(i32.eq (call $wait (i32.load (i32.const 48)) (i32.const 80) (i32.const 0)) (i32.load (i32.const 48)))')}
    ${eq('(i32.load (i32.const 80))', 9)}
    ${eq('(call $receive (i32.const 5) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 0)} ${say('killed-master-ok\n')}`);
  await run(page, path); await expect(screen(page)).toContainText('killed-master-ok');
});

test('nonblocking mode is shared by dup and fork, and CLOEXEC closes only the marked descriptor', async ({ page }) => {
  const next = await upload(page, 'cloexec', ({ say }) => `${eq('(call $receive (i32.const 6) (i32.const 1))', 8)}
    ${eq('(call $receive (i32.const 5) (i32.const 1))', 6)} ${say('cloexec-ok\n')}`);
  const path = await upload(page, 'flags', ({ setup, openSlave, text, q, say }) => `${setup(2 | 256)} ${q(0x5402, 5, raw)}
    ${eq('(call $dup2 (i32.const 5) (i32.const 7))', 0)} ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then ${eq('(call $flags (i32.const 7) (i32.const 4))', 0)} (call $exit (i32.const 0))))
    ${wait} ${eq('(call $receive (i32.const 5) (i32.const 1))', 6)}
    ${eq('(call $fdstat (i32.const 5) (i32.const 200))', 0)} ${eq('(i32.load16_u (i32.const 202))', 4)}
    ${openSlave(2 | 256 | 524288, 6)}
    (call $exec ${text(next)} ${text(next)}) ${say('unexpected\n')}`);
  await run(page, path); await expect(screen(page)).toContainText('cloexec-ok');
});

test('timed raw reads and poll report data, timeout and hangup without blocking the host', async ({ page }) => {
  const timed = structuredClone(raw); timed.cc[6] = 0; timed.cc[5] = 1;
  const path = await upload(page, 'poll', ({ setup, q, write, say }) => `${setup(2 | 256)} ${q(0x5402, 5, timed)}
    ${eq('(call $clock (i32.const 1) (i64.const 0) (i32.const 256))', 0)}
    ${eq('(call $receive (i32.const 5) (i32.const 8))', 0)} ${eq('(i32.load (i32.const 136))', 0)}
    ${eq('(call $clock (i32.const 1) (i64.const 0) (i32.const 264))', 0)}
    ${assert('(i64.ge_u (i64.sub (i64.load (i32.const 264)) (i64.load (i32.const 256))) (i64.const 60000000))')}
    (i64.store (i32.const 300) (i64.const 1)) (i32.store8 (i32.const 308) (i32.const 1)) (i32.store (i32.const 316) (i32.const 5))
    (i64.store (i32.const 348) (i64.const 2)) (i32.store8 (i32.const 356) (i32.const 0))
    (i32.store (i32.const 364) (i32.const 1)) (i64.store (i32.const 372) (i64.const 20000000))
    ${eq('(call $poll (i32.const 300) (i32.const 500) (i32.const 2) (i32.const 580))', 0)}
    ${eq('(i32.load (i32.const 580))', 1)} ${assert('(i64.eq (i64.load (i32.const 500)) (i64.const 2))')}
    ${write(4, 'abc')}
    ${eq('(call $poll (i32.const 300) (i32.const 500) (i32.const 1) (i32.const 580))', 0)}
    ${eq('(i32.load16_u (i32.const 508))', 0)} ${assert('(i64.eq (i64.load (i32.const 516)) (i64.const 3))')}
    ${eq('(call $receive (i32.const 5) (i32.const 8))', 0)} ${eq('(i32.load (i32.const 136))', 3)}
    ${eq('(call $close (i32.const 4))', 0)}
    ${eq('(call $poll (i32.const 300) (i32.const 500) (i32.const 1) (i32.const 580))', 0)}
    ${eq('(i32.load16_u (i32.const 524))', 1)} ${say('poll-timeout-hangup-ok\n')}`);
  await run(page, path); await expect(screen(page)).toContainText('poll-timeout-hangup-ok');
});

test('another execution host cannot open an allocated slave by learning its name', async ({ page, context }) => {
  const owner = await upload(page, 'owner', ({ setup, say }) => `${setup(2 | 256)} ${say('owner-ready\n')}
    ${eq('(call $receive (i32.const 0) (i32.const 1))', 0)} ${say('owner-finished\n')}`);
  await page.locator('#command').fill(owner); await page.locator('#command').press('Enter');
  await expect(screen(page)).toContainText('owner-ready', { timeout: 60_000 });
  const number = (await results(page))[0].ok.number;
  const probe = await upload(page, 'probe', ({ text, say }) => `
    ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, -44)}
    ${say('foreign-pty-denied\n')}`);
  const other = await context.newPage();
  try {
    await other.goto('/'); await run(other, probe); await expect(screen(other)).toContainText('foreign-pty-denied');
  } finally { await other.close(); }
  await page.locator('#command').fill('x'); await page.locator('#command').press('Enter');
  await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
  await expect(screen(page)).toContainText('owner-finished');
});

test('independent runs share host PTYs and last-master close resumes a stopped slave session', async ({ page }) => {
  await connectHost(page);
  const owner = await upload(page, 'host-owner', ({ setup, say, write }) => `${setup(2 | 256)}
    ${write(4, 'hello\n')} ${say('owner-ready\n')}
    ${eq('(call $receive (i32.const 0) (i32.const 1))', 0)}
    ${say('owner-finished\n')}`);
  try {
    await startHost(page, 'owner', owner);
    await hostReady(page, 'owner', 'owner-ready');
    const number = await hostNumber(page, 'owner');
    const client = await upload(page, 'host-client', ({ q, text, say, write }) => `${ignoreHup} ${q(0x5422, 0)}
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, 4)}
      ${assert('(i32.gt_s (call $fg (i32.const 4)) (i32.const 0))')}
      ${eq('(call $receive (i32.const 4) (i32.const 6))', 0)} ${eq('(i32.load (i32.const 136))', 6)}
      (call $send (i32.const 1) (i32.const 8192) (i32.const 6)) ${write(4, 'reply\n')}
      ${say('client-stopping\n')} ${eq('(call $raise (i32.const 19))', 0)}
      ${eq('(call $receive (i32.const 4) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 0)}
      ${eq('(call $fg (i32.const 4))', -59)} ${say('client-resumed-with-eof\n')}`);
    await startHost(page, 'client', client);
    await hostReady(page, 'client', 'hello\nclient-stopping');
    await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).find(p => p.path === client)?.state).toBe('stopped');
    await hostInput(page, 'owner', 'x\n');
    await hostResult(page, 'owner'); await hostResult(page, 'client');
    expect(await hostOutput(page, 'client')).toContain('client-resumed-with-eof');
    const missing = await upload(page, 'host-gone', ({ text, say }) => `
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, -44)} ${say('host-pty-removed\n')}`);
    await startHost(page, 'gone', missing); await hostResult(page, 'gone');
  } finally { await closeHost(page); }
});

test('host PTY input signals the controlling foreground group in another run', async ({ page }) => {
  await connectHost(page);
  const owner = await upload(page, 'signal-owner', ({ setup, say, write }) => `${setup(2 | 256)} ${say('owner-ready\n')}
    ${eq('(call $receive (i32.const 0) (i32.const 8))', 0)} ${write(4, '\x03')}
    ${say('signal-sent\n')} ${eq('(call $receive (i32.const 0) (i32.const 8))', 0)}`);
  try {
    await startHost(page, 'owner', owner); await hostReady(page, 'owner', 'owner-ready');
    const number = await hostNumber(page, 'owner');
    const client = await upload(page, 'signal-client', ({ q, text, say }) => `${ignoreHup} ${q(0x5422, 0)}
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, 4)}
      ${say('client-reading\n')} (drop (call $receive (i32.const 4) (i32.const 1))) unreachable`);
    await startHost(page, 'client', client); await hostReady(page, 'client', 'client-reading');
    await hostInput(page, 'owner', 'x\n'); await hostResult(page, 'client', 130);
    await hostReady(page, 'owner', 'signal-sent');
    expect(await page.evaluate(() => window.ptyHost.runs.get('owner').result)).toBeUndefined();
    await hostInput(page, 'owner', 'x\n'); await hostResult(page, 'owner');
  } finally { await closeHost(page); }
});

test('host PTY permissions use the process snapshot after a browser root login', async ({ page }) => {
  await connectHost(page); await login(page);
  const owner = await upload(page, 'root-owner', ({ setup, say }) => `${setup(2 | 256)} ${say('owner-ready\n')}
    ${eq('(call $receive (i32.const 0) (i32.const 1))', 0)}`);
  try {
    await startHost(page, 'owner', owner); await hostReady(page, 'owner', 'owner-ready');
    const number = await hostNumber(page, 'owner');
    const probe = await upload(page, 'guest-probe', ({ text, say }) => `${say('guest-ready\n')}
      ${eq('(call $receive (i32.const 0) (i32.const 1))', 0)}
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, -2)} ${say('guest-denied\n')}`);
    expect((await api(page.request, 'logout')).ok()).toBe(true);
    await startHost(page, 'probe', probe, { environment: { UID: '0', USER: 'root' } }); await hostReady(page, 'probe', 'guest-ready');
    await login(page); await hostInput(page, 'probe', 'x\n'); await hostResult(page, 'probe');
    expect(await hostOutput(page, 'probe')).toContain('guest-denied');
    const allowed = await upload(page, 'root-peer', ({ text, say }) => `
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, 4)} ${say('root-allowed\n')}`);
    await startHost(page, 'allowed', allowed); await hostResult(page, 'allowed');
    expect(await hostOutput(page, 'allowed')).toContain('root-allowed');
  } finally { await login(page); await closeHost(page); }
});

test('root retains cross-run terminal reassignment authority after browser logout', async ({ page }) => {
  await connectHost(page);
  const owner = await upload(page, 'steal-owner', ({ q, setup, say }) => `${ignoreHup} ${q(0x5422, 0)} ${setup()}
    ${assert('(i32.gt_s (call $fg (i32.const 5)) (i32.const 0))')} ${say('owner-ready\n')}
    ${eq('(call $receive (i32.const 0) (i32.const 1))', 0)}
    ${eq('(call $fg (i32.const 5))', -59)} ${say('old-session-detached\n')}`);
  try {
    await startHost(page, 'owner', owner); await hostReady(page, 'owner', 'owner-ready');
    const number = JSON.parse((await hostOutput(page, 'owner')).split('\n').filter(s => s.startsWith('{'))[1]).results[0].ok.number;
    const denied = await upload(page, 'steal-denied', ({ q, text, say }) => `${ignoreHup} ${q(0x5422, 0)}
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, 4)} ${q(0x540e, 4, 1)}
      ${eq('(call $fg (i32.const 4))', -59)} ${say('guest-reassignment-denied\n')}`);
    await startHost(page, 'denied', denied); await hostResult(page, 'denied');
    const replies = (await hostOutput(page, 'denied')).split('\n').filter(s => s.startsWith('{')).map(s => JSON.parse(s).results[0]);
    expect(replies.at(-1).err.errno).toBe('EPERM');
    await login(page);
    const peer = await upload(page, 'steal-peer', ({ q, text, say }) => `${ignoreHup} ${q(0x5422, 0)} ${say('root-ready\n')}
      ${eq('(call $receive (i32.const 0) (i32.const 1))', 0)}
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, 4)} ${q(0x540e, 4, 1)}
      ${assert('(i32.eq (call $fg (i32.const 4)) (call $pgid (i32.const 0)))')} ${say('root-reassigned\n')}
      ${eq('(call $receive (i32.const 4) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 0)} ${say('root-hung-up\n')}`);
    await startHost(page, 'peer', peer); await hostReady(page, 'peer', 'root-ready');
    expect((await api(page.request, 'logout')).ok()).toBe(true);
    await hostInput(page, 'peer', 'x\n'); await hostReady(page, 'peer', 'root-reassigned');
    await hostInput(page, 'owner', 'x\n'); await hostResult(page, 'owner'); await hostResult(page, 'peer');
    expect(await hostOutput(page, 'owner')).toContain('old-session-detached');
    expect(await hostOutput(page, 'peer')).toContain('root-hung-up');
  } finally { await login(page); await closeHost(page); }
});

test('a child keeps the host PTY alive after its launching run completes', async ({ page }) => {
  await connectHost(page);
  const owner = await upload(page, 'orphan-master', ({ master, q }) => `${ignoreHup} ${master} ${q(0x40045431)} ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      ${eq('(call $receive (i32.const 4) (i32.const 1))', 0)}
      ${eq('(i32.load8_u (i32.const 8192))', 120)}))`);
  try {
    await startHost(page, 'owner', owner); await hostResult(page, 'owner');
    const number = await hostNumber(page, 'owner');
    const peer = await upload(page, 'orphan-peer', ({ text, write, say }) => `
      ${eq(`(call $open ${text(`/dev/pts/${number}`)} (i32.const 2) (i32.const 0))`, 4)} ${write(4, 'x')}
      ${eq('(call $receive (i32.const 4) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 0)} ${say('orphan-master-closed\n')}`);
    await startHost(page, 'peer', peer); await hostResult(page, 'peer');
    expect(await hostOutput(page, 'peer')).toContain('orphan-master-closed');
  } finally { await closeHost(page); }
});

test('host PTY allocation limits span runs and recover when a holder exits', async ({ page }) => {
  await connectHost(page);
  const owner = await upload(page, 'quota-owner', ({ text, say }) => `(loop $allocate
    ${assert(`(i32.ge_s (call $open ${text('/dev/ptmx')} (i32.const 2) (i32.const 0)) (i32.const 4))`)}
    (local.set $n (i32.add (local.get $n) (i32.const 1))) (br_if $allocate (i32.lt_u (local.get $n) (i32.const 32))))
    ${say('quota-ready\n')} ${eq('(call $receive (i32.const 0) (i32.const 1))', 0)}`);
  try {
    await startHost(page, 'a', owner); await hostReady(page, 'a', 'quota-ready');
    await startHost(page, 'b', owner); await hostReady(page, 'b', 'quota-ready');
    const full = await upload(page, 'quota-full', ({ text, say }) => `
      ${eq(`(call $open ${text('/dev/ptmx')} (i32.const 2) (i32.const 0))`, -51)} ${say('host-quota-enforced\n')}`);
    await startHost(page, 'full', full); await hostResult(page, 'full');
    await hostInput(page, 'a', 'x\n'); await hostResult(page, 'a');
    const recovered = await upload(page, 'quota-recovered', ({ master, say }) => `${master} ${say('host-quota-recovered\n')}`);
    await startHost(page, 'recovered', recovered); await hostResult(page, 'recovered');
  } finally { await closeHost(page); }
});

test('console input belongs to exactly one run and explicit foreground selection restores it', async ({ page }) => {
  await connectHost(page);
  const reader = await upload(page, 'console-reader', ({ say }) => `${say('console-ready\n')}
    ${eq('(call $receive (i32.const 0) (i32.const 8))', 0)}
    (call $send (i32.const 1) (i32.const 8192) (i32.load (i32.const 136)))`);
  try {
    await startHost(page, 'a', reader, { terminalId: 'shared' }); await hostReady(page, 'a', 'console-ready');
    await startHost(page, 'b', reader, { terminalId: 'shared' }); await hostReady(page, 'b', 'console-ready');
    expect((await hostInput(page, 'a', 'wrong\n')).err.errno).toBe('EACCES');
    await hostInput(page, 'b', 'second\n'); await hostResult(page, 'b');
    expect(await hostOutput(page, 'b')).toContain('second');
    await hostCall(page, 'run_foreground', { run: 'a', active: true });
    await hostInput(page, 'a', 'first\n'); await hostResult(page, 'a');
    expect(await hostOutput(page, 'a')).not.toContain('wrong');
    expect(await hostOutput(page, 'a')).toContain('first');
  } finally { await closeHost(page); }
});

test('closing a console resumes stopped runs and leaves inherited terminal fds hung up', async ({ page }) => {
  await connectHost(page);
  const reader = await upload(page, 'console-hangup', ({ say, text, q }) => `${ignoreHup}
    ${q(0x80045430, 0)} (call $name) ${q(0x5402, 0, raw)} ${say('console-stopping\n')}
    ${eq('(call $raise (i32.const 19))', 0)}
    ${eq('(call $receive (i32.const 0) (i32.const 8))', 0)} ${eq('(i32.load (i32.const 136))', 0)}
    (i32.store (i32.const 128) (i32.const 8192)) (i32.store (i32.const 132) (i32.const 1))
    ${eq('(call $write (i32.const 1) (i32.const 128) (i32.const 1) (i32.const 136))', 29)}
    ${eq('(call $fg (i32.const 0))', -59)}
    ${eq(`(call $open ${text('/dev/tty')} (i32.const 0) (i32.const 0))`, -60)}
    ${eq('(call $open (i32.const 1024) (global.get $nameLen) (i32.const 256) (i32.const 0))', -44)}
    (i32.store8 (i32.const 308) (i32.const 1)) (i32.store (i32.const 316) (i32.const 0))
    ${eq('(call $poll (i32.const 300) (i32.const 500) (i32.const 1) (i32.const 580))', 0)}
    ${eq('(i32.load16_u (i32.const 524))', 1)}`);
  try {
    for (const id of ['a', 'b']) {
      await startHost(page, id, reader, { terminalId: 'close-me' }); await hostReady(page, id, 'console-stopping');
    }
    await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).filter(p => p.path === reader && p.state === 'stopped').length).toBe(2);
    expect((await hostCall(page, 'console_close', { terminalId: 'close-me' })).err).toBeUndefined();
    await hostResult(page, 'a'); await hostResult(page, 'b');
    const reopened = await upload(page, 'console-reopened', ({ say, q }) => `${q(0x5401, 0)} ${say('new-console-ready\n')}
      ${eq('(call $receive (i32.const 0) (i32.const 8))', 0)}`);
    await startHost(page, 'new', reopened, { terminalId: 'close-me' }); await hostReady(page, 'new', 'new-console-ready');
    expect(JSON.parse((await hostOutput(page, 'new')).split('\n')[0]).results[0].ok.lflag & 8).toBe(8);
    await hostCall(page, 'run_foreground', { run: 'a', active: true });
    await hostInput(page, 'new', 'new\n'); await hostResult(page, 'new');
  } finally { await closeHost(page); }
});

for (const phase of ['authorization', 'image loading', 'input signal', 'job stop']) test(`console ${phase === 'input signal' ? 'interrupt during image loading' : phase === 'job stop' ? 'job stop before authorization' : `close during ${phase}`} cannot enter user code`, async ({ page }) => {
  await connectHost(page);
  const path = await upload(page, 'console-loading', ({ say }) => `${say('must-not-start\n')}`);
  let release, reached;
  const released = new Promise(resolve => { release = resolve; });
  const loading = new Promise(resolve => { reached = resolve; });
  const authorizing = phase === 'authorization' || phase === 'job stop';
  await page.route(authorizing ? '**/api/sys' : '**/api/file?**', async route => {
    if (authorizing
      ? !route.request().postDataJSON()?.calls?.some(call => call.execve)
      : !new URL(route.request().url()).searchParams.has('compile')) return route.continue();
    const response = await route.fetch(); reached(); await released;
    await route.fulfill({ response }).catch(() => {});
  });
  try {
    await startHost(page, 'loading', path, { terminalId: 'loading' }); await loading;
    const result = phase === 'input signal' ? await hostInput(page, 'loading', '\x03')
      : phase === 'job stop' ? await hostCall(page, 'run_signal', { run: 'loading', signal: 20 })
      : await hostCall(page, 'console_close', { terminalId: 'loading' });
    expect(result.err).toBeUndefined();
    release();
    if (phase === 'job stop') {
      await expect.poll(async () => (await call(page.request, { proc_poll: { pids: [] } })).find(p => p.path === path)?.state).toBe('stopped');
      await hostCall(page, 'console_close', { terminalId: 'loading' });
    }
    await hostResult(page, 'loading', phase === 'input signal' ? 130 : 129);
    expect(await hostOutput(page, 'loading')).not.toContain('must-not-start');
  } finally { release(); await closeHost(page); }
});

test('console IDs do not give another execution host control over a live pane', async ({ page, context }) => {
  await connectHost(page);
  const path = await upload(page, 'console-private', ({ say }) => `${say('private-console-ready\n')}
    ${eq('(call $receive (i32.const 0) (i32.const 8))', 0)}`);
  const other = await context.newPage();
  try {
    await other.goto('/'); await connectHost(other);
    for (const target of [page, other]) {
      await startHost(target, 'same-run-id', path, { terminalId: 'same-console-id' });
      await hostReady(target, 'same-run-id', 'private-console-ready');
    }
    await hostCall(other, 'console_close', { terminalId: 'same-console-id' });
    await hostResult(other, 'same-run-id', 129);
    expect(await page.evaluate(() => window.ptyHost.runs.get('same-run-id').result)).toBeUndefined();
    await hostInput(page, 'same-run-id', 'alive\n'); await hostResult(page, 'same-run-id');
  } finally { await closeHost(page); await closeHost(other); await other.close(); }
});

test('raw file ioctls keep their descriptor namespace when local PTY numbers overlap', async ({ page }) => {
  const source = `${base}/source`, target = `${base}/clone`;
  expect((await put(page.request, '/api/file?path=' + source, { data: 'shared file content\n' })).ok()).toBe(true);
  const path = await upload(page, 'namespaces', ({ setup, text }) => `${setup(2 | 256)}
    ${eq('(call $dup2 (i32.const 1) (i32.const 100))', 0)}
    (loop $cover
      (if (i32.ne (local.get $n) (i32.const 4)) (then ${eq('(call $dup2 (i32.const 4) (local.get $n))', 0)}))
      (local.set $n (i32.add (local.get $n) (i32.const 1))) (br_if $cover (i32.lt_u (local.get $n) (i32.const 64))))
    (local.set $status (call $sys ${text(JSON.stringify([
      { open: { path: source, flags: 0 } },
      { open: { path: target, flags: 1 | 64 | 512, mode: 0o600 } },
      { ioctl: { fd: { ref: 1 }, request: 0x40049409, arg: { ref: 0 } } },
      { close: { fd: { ref: 0 } } }, { close: { fd: { ref: 1 } } },
    ]))})) (call $reply (i32.const 4096))
    (local.set $n (i32.const 0))
    (loop $check
      ${assert('(i32.ne (i32.load (i32.add (i32.const 4096) (local.get $n))) (i32.const 1920099618))')}
      (local.set $n (i32.add (local.get $n) (i32.const 1))) (br_if $check (i32.lt_u (local.get $n) (local.get $status))))
    (call $send (i32.const 100) ${text('descriptor-namespaces-ok\n')})`);
  await run(page, path); await expect(screen(page)).toContainText('descriptor-namespaces-ok');
  expect(await (await page.request.get('/api/file?path=' + target)).text()).toBe('shared file content\n');
});

test('killing an unresponsive session leader closes its last master and resumes a stopped foreground child', async ({ page }) => {
  const path = await upload(page, 'killed-leader', ({ master, openSlave, q, say }) => `${ignoreHup}
    ${eq('(call $pipe (i32.const 32) (i32.const 36))', 0)} ${fork}
    (if (i32.eqz (i32.load (i32.const 48))) (then
      ${eq('(call $close (i32.const 4))', 0)} ${assert('(i32.gt_s (call $setsid) (i32.const 1))')}
      ${master} ${q(0x40045431)} ${openSlave(2, 6)} ${fork}
      (if (i32.eqz (i32.load (i32.const 48))) (then
        ${eq('(call $close (i32.const 4))', 0)} (drop (call $raise (i32.const 19)))
        ${eq('(call $fg (i32.const 6))', -59)}
        ${eq('(call $receive (i32.const 6) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 0)}
        ${say('stopped-grandchild-resumed\n')}
        (i32.store8 (i32.const 256) (i32.const 1)) (call $send (i32.const 5) (i32.const 256) (i32.const 1))
        (call $exit (i32.const 0))))
      ${assert('(i32.eq (call $wait (i32.load (i32.const 48)) (i32.const 80) (i32.const 2)) (i32.load (i32.const 48)))')}
      (i32.store8 (i32.const 256) (i32.const 1)) (call $send (i32.const 5) (i32.const 256) (i32.const 1))
      (loop $busy (br $busy))))
    ${eq('(call $close (i32.const 5))', 0)}
    ${eq('(call $receive (i32.const 4) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 1)}
    ${eq('(call $kill (i32.load (i32.const 48)) (i32.const 9))', 0)}
    ${assert('(i32.eq (call $wait (i32.load (i32.const 48)) (i32.const 80) (i32.const 0)) (i32.load (i32.const 48)))')}
    ${eq('(i32.load (i32.const 80))', 9)} ${say('session-leader-killed\n')}
    ${eq('(call $receive (i32.const 4) (i32.const 1))', 0)} ${eq('(i32.load (i32.const 136))', 1)}
    ${say('killed-leader-cleanup-ok\n')}`);
  try {
    await page.locator('#command').fill(path); await page.locator('#command').press('Enter');
    await expect(screen(page)).toContainText('session-leader-killed', { timeout: 60_000 });
    await expect(screen(page)).toContainText('stopped-grandchild-resumed');
    await expect(prompt(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
    await expect(screen(page)).toContainText('killed-leader-cleanup-ok');
  } finally {
    for (const process of await call(page.request, { proc_poll: { pids: [] } }))
      if (process.path === path) await call(page.request, { kill: { pid: process.pid, signal: 9 } }).catch(() => {});
  }
});
