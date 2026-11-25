import { test, expect } from './test.js';
import binaryen from 'binaryen';
import {
  pageCall,
  pageErrno,
  pageGetText,
  pagePut,
  pageRmrf,
  runTerminal,
  sendTerminalLine,
  terminalInput,
  terminalScreen,
  terminalTabs,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';
import { hookPageKernel } from './service-auth.js';

const screen = page => terminalScreen(page);
async function promptSeq(page) {
  return Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
}
async function waitIdleAfter(page, before, timeout = 60_000) {
  await expect.poll(async () => {
    const vp = terminalViewport(page);
    return (await vp.getAttribute('data-state')) === 'idle'
      && Number((await vp.getAttribute('data-prompt-seq')) || '0') > before;
  }, { timeout }).toBe(true);
}
async function runOutput(page, command) {
  const id = crypto.randomUUID().slice(0, 8);
  const start = `__S_${id}__`, end = `__E_${id}__`;
  await runTerminal(page, `echo ${start}; ${command}; echo ${end}`, { timeout: 60_000 });
  await expect(screen(page)).toContainText(end, { timeout: 15_000 });
  const raw = '\n' + (await screen(page).innerText());
  const from = raw.lastIndexOf('\n' + start + '\n');
  expect(from, `start marker ${start} missing`).toBeGreaterThanOrEqual(0);
  const bodyStart = from + start.length + 2;
  const to = raw.indexOf(end, bodyStart);
  expect(to, `end marker ${end} missing`).toBeGreaterThanOrEqual(bodyStart);
  return raw.slice(bodyStart, to).replace(/\n$/, '');
}
async function upload(page, path, data) {
  await waitForTerminalReady(page);
  await pagePut(page, path, data, { mode: 0o755, overwrite: true });
  await pageCall(page, { chmod: { path, mode: 0o755 } });
}
const wat = `(module
  (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
  (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
  (import "wasix_32v1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "\\1b[?1049h\\1b[2J\\1b[1;1HPTY screen\\1b[3;5HREADY")
  (data (i32.const 1200) "\\1b[4;5HUP")
  (data (i32.const 1250) "\\1b[5;5HKEY")
  (data (i32.const 1350) "\\1b[6;5HRESIZED")
  (data (i32.const 1300) "\\1b[?1049lfinished\\0a")
  (func $say (param $ptr i32) (param $len i32)
    (i32.store (i32.const 0) (local.get $ptr)) (i32.store (i32.const 4) (local.get $len))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8))))
  (func (export "_start")
    (drop (call $get (i32.const 200))) (drop (call $get (i32.const 256)))
    (i32.store (i32.const 400) (i32.load (i32.const 200)))
    (i32.store8 (i32.const 219) (i32.const 0)) (i32.store8 (i32.const 220) (i32.const 0))
    (drop (call $set (i32.const 200)))
    (call $say (i32.const 1024) (i32.const 39))
    (block $done (loop $again
      (i32.store (i32.const 16) (i32.const 512)) (i32.store (i32.const 20) (i32.const 64))
      (drop (call $read (i32.const 0) (i32.const 16) (i32.const 1) (i32.const 24)))
      (br_if $done (i32.eqz (i32.load (i32.const 24))))
      (br_if $done (i32.eq (i32.load8_u (i32.const 512)) (i32.const 113)))
      (if (i32.eq (i32.load8_u (i32.const 512)) (i32.const 27))
        (then (call $say (i32.const 1200) (i32.const 8)))
        (else (call $say (i32.const 1250) (i32.const 9))))
      (drop (call $get (i32.const 200)))
      (if (i32.ne (i32.load (i32.const 200)) (i32.load (i32.const 400)))
        (then (call $say (i32.const 1350) (i32.const 13))))
      (br $again)))
    (drop (call $set (i32.const 256)))
    (call $say (i32.const 1300) (i32.const 17))))`;
const module = binaryen.parseText(wat); const fullscreen = Buffer.from(module.emitBinary()); module.dispose();

test('tty/stty expose a stable terminal, persistent modes and actual resized dimensions', async ({ page }) => {
  await page.goto('/');
  await waitForTerminalReady(page);
  const name = await runOutput(page, 'tty');
  expect(name).toMatch(/^\/dev\/pts\/\d+$/);
  expect(await runOutput(page, 'stty -a')).toContain('echo icanon isig -tostop opost onlcr');
  // Run stty -echo and stty -a within one command line before osh restores its line-editor termios.
  expect(await runOutput(page, 'stty -echo; stty -a; stty sane')).toContain('-echo icanon');
  expect(await runOutput(page, 'tty')).toBe(name);
  const before = await runOutput(page, 'stty size');
  await page.setViewportSize({ width: 430, height: 700 });
  await expect.poll(async () => runOutput(page, 'stty size'), { timeout: 10_000 }).not.toBe(before);
  expect(await runOutput(page, 'echo data | tty')).toBe('not a tty');
});

test('closing a terminal pane hangs up its running and stopped jobs while another pane survives', async ({ page }) => {
  const kernel = await hookPageKernel(page);
  await page.goto('/');
  await waitForTerminalReady(page);
  await kernel.ready();
  const rows = async () => kernel.value('poll', { pids: [] });
  const sleep = (process, seconds) => process.argv?.includes('sleep') && process.argv.includes(String(seconds));
  try {
    const seq1 = await promptSeq(page);
    await runTerminal(page, 'sleep 61', { wait: false });
    await expect.poll(async () => (await rows()).some(p => sleep(p, 61)), { timeout: 15_000 }).toBe(true);
    await terminalInput(page).press('Alt+t');
    await expect(terminalTabs(page)).toHaveCount(2, { timeout: 15_000 });
    await waitForTerminalReady(page);
    await runTerminal(page, 'sleep 62 &');
    const seq2 = await promptSeq(page);
    await runTerminal(page, 'sleep 63', { wait: false });
    await expect.poll(async () => (await rows()).some(p => sleep(p, 63)), { timeout: 15_000 }).toBe(true);
    await terminalInput(page).press('Control+z');
    await waitIdleAfter(page, seq2);
    await expect.poll(async () => (await rows()).find(p => sleep(p, 63))?.state, { timeout: 10_000 }).toBe('stopped');
    await terminalTabs(page).nth(1).locator('.term-tab-close').click();
    await expect(terminalTabs(page)).toHaveCount(1, { timeout: 15_000 });
    await expect.poll(async () => (await rows()).filter(p => sleep(p, 62) || sleep(p, 63)).length, { timeout: 15_000 }).toBe(0);
    expect((await rows()).find(p => sleep(p, 61))?.state).toBe('running');
    await terminalInput(page).press('Control+c');
    await waitIdleAfter(page, seq1);
    await runTerminal(page, 'echo console-alive');
    await expect(screen(page)).toContainText('console-alive');
  } finally {
    for (const process of await rows().catch(() => [])) if ([61, 62, 63].some(n => sleep(process, n)))
      await kernel.call('kill', { pid: process.pid, signal: 9 }).catch(() => {});
  }
});

test('a cancelled console launch never creates a process or changes files', async ({ page }) => {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
  const path = `/tmp/cancelled-console-${crypto.randomUUID()}`;
  const started = [];
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/sys' && request.method() === 'POST')
      for (const call of request.postDataJSON()?.calls ?? []) if (call.execve) started.push(call.execve);
  });
  try {
    const result = await page.evaluate(path => window.os.exec([
      { path: '/usr/bin/coreutils', argv: ['coreutils', 'touch', path] },
    ], { terminalId: 'closed-before-launch', cancelled: () => true }), path);
    expect(result.status).toBe(130); expect(started).toEqual([]);
    expect(await pageErrno(page, { stat: { path } })).toBe('ENOENT');
  } finally { await pageRmrf(page, path).catch(() => {}); }
});

test('coreutils cat reads controlling-terminal device paths through ordinary file descriptors', async ({ page }) => {
  await page.goto('/');
  await waitForTerminalReady(page);
  const slave = await runOutput(page, 'tty');
  for (const command of ['echo ignored | cat /dev/tty', `cat ${slave}`]) {
    await runTerminal(page, 'clear');
    const seq = await promptSeq(page);
    await runTerminal(page, `stty -echo; ${command}; stty sane`, { wait: false });
    await expect(terminalViewport(page)).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
    await sendTerminalLine(page, 'device-input');
    await expect(screen(page)).toContainText('device-input', { timeout: 15_000 });
    await terminalInput(page).press('Control+d');
    await waitIdleAfter(page, seq);
    // With -echo active, the line appears once (written by cat, not echoed twice).
    const occurrences = (await screen(page).innerText()).split('device-input').length - 1;
    expect(occurrences).toBe(1);
  }
});

test('WASIX raw input and cursor addressing render a full-screen application and restore the transcript', async ({ page }) => {
  const path = `/tmp/pty-screen-${crypto.randomUUID()}.wasm`;
  await page.goto('/'); await upload(page, path, fullscreen);
  const vp = terminalViewport(page);
  const input = terminalInput(page);
  try {
    let seq = await promptSeq(page);
    await runTerminal(page, path, { wait: false });
    await expect(screen(page)).toHaveAttribute('data-alternate', 'true', { timeout: 20_000 });
    await expect(screen(page)).toContainText('PTY screen');
    await expect(screen(page)).toContainText('    READY');
    await expect(vp).toHaveAttribute('data-state', 'busy');
    await input.press('ArrowUp'); await expect(screen(page)).toContainText('    UP');
    await input.press('x'); await expect(screen(page)).toContainText('    KEY');
    await input.press('Control+z');
    await waitIdleAfter(page, seq);
    seq = await promptSeq(page);
    await runTerminal(page, 'fg', { wait: false });
    await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
    await expect(screen(page)).toContainText('PTY screen');
    await page.setViewportSize({ width: 430, height: 700 });
    await expect.poll(async () => {
      await input.press('r');
      return (await screen(page).innerText()).includes('RESIZED');
    }, { timeout: 10_000, intervals: [150, 300, 500] }).toBe(true);
    await input.press('q');
    await waitIdleAfter(page, seq);
    await expect(screen(page)).toHaveAttribute('data-alternate', 'false');
    await expect(screen(page)).toContainText('finished');
    expect(await runOutput(page, 'stty -a')).toContain('echo icanon');
  } finally { await pageRmrf(page, path).catch(() => {}); }
});

test('PTY Ctrl+C and Ctrl+Z reach the foreground job; descriptors name the slave', async ({ page }) => {
  const kernel = await hookPageKernel(page);
  await page.goto('/');
  await waitForTerminalReady(page);
  await kernel.ready();
  const input = terminalInput(page);
  const vp = terminalViewport(page);
  let seq = await promptSeq(page);
  await runTerminal(page, 'coreutils cat', { wait: false });
  await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  let running;
  await expect.poll(async () => {
    const rows = await kernel.value('poll', { pids: [] });
    running = rows.find(p => p.argv?.includes('cat'));
    return Boolean(running);
  }, { timeout: 15_000 }).toBe(true);
  await expect.poll(async () => {
    const reply = await kernel.call('proc_readlinkat', { pid: running.pid, dirfd: 0x7ffffffd, path: `/proc/${running.pid}/fd/0` });
    return reply.ok;
  }).toMatch(/^\/dev\/pts\/\d+$/);
  await sendTerminalLine(page, 'canonical');
  await expect(screen(page)).toContainText('canonical\ncanonical', { timeout: 15_000 });
  await input.press('Control+z');
  await waitIdleAfter(page, seq);
  expect(await runOutput(page, 'jobs')).toContain('Stopped');
  seq = await promptSeq(page);
  await runTerminal(page, 'fg', { wait: false });
  await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await input.press('Control+c');
  await waitIdleAfter(page, seq);
  expect(await runOutput(page, 'ps')).not.toContain('coreutils cat');
});

test('raw mode without ISIG delivers Ctrl+C and Ctrl+D as input bytes', async ({ page }) => {
  const path = `/tmp/pty-raw-${crypto.randomUUID()}.wasm`;
  await page.goto('/'); await upload(page, path, fullscreen);
  const vp = terminalViewport(page);
  const input = terminalInput(page);
  try {
    const seq = await promptSeq(page);
    await runTerminal(page, `stty raw; ${path}; stty sane`, { wait: false });
    await expect(screen(page)).toHaveAttribute('data-alternate', 'true', { timeout: 20_000 });
    await expect(screen(page)).toContainText('READY');
    await input.press('Control+c'); await expect(screen(page)).toContainText('KEY');
    await expect(vp).toHaveAttribute('data-state', 'busy');
    await input.press('Control+d'); await expect(vp).toHaveAttribute('data-state', 'busy');
    await input.press('q');
    await waitIdleAfter(page, seq);
    await expect(screen(page)).toHaveAttribute('data-alternate', 'false');
  } finally { await pageRmrf(page, path).catch(() => {}); }
});

// Exercise a newly opened slave, rather than only the inherited standard descriptors.
const slaveWat = String.raw`(module
  (import "wasi_snapshot_preview1" "path_open" (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasix_32v1" "tty_get" (func $get (param i32) (result i32)))
  (import "wasix_32v1" "tty_set" (func $set (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 1024) "/dev/tty")
  (data (i32.const 1100) "POLL_WAITED\0a")
  (data (i32.const 1150) "SLAVE_READ\0a")
  (func $say (param $fd i32) (param $ptr i32) (param $len i32)
    (i32.store (i32.const 0) (local.get $ptr)) (i32.store (i32.const 4) (local.get $len))
    (if (call $write (local.get $fd) (i32.const 0) (i32.const 1) (i32.const 8)) (then unreachable)))
  (func (export "_start") (local $fd i32)
    (if (call $open (i32.const 3) (i32.const 0) (i32.const 1024) (i32.const 8) (i32.const 0)
      (i64.const -1) (i64.const -1) (i32.const 0) (i32.const 32)) (then unreachable))
    (local.set $fd (i32.load (i32.const 32)))
    (drop (call $get (i32.const 200))) (drop (call $get (i32.const 256)))
    (i32.store8 (i32.const 219) (i32.const 0)) (drop (call $set (i32.const 200)))
    ;; Read subscription and a 50 ms clock: an empty slave must not claim readiness.
    (i64.store (i32.const 400) (i64.const 1)) (i32.store8 (i32.const 408) (i32.const 1))
    (i32.store (i32.const 416) (local.get $fd))
    (i64.store (i32.const 448) (i64.const 2)) (i32.store (i32.const 464) (i32.const 1))
    (i64.store (i32.const 472) (i64.const 50000000))
    (if (call $poll (i32.const 400) (i32.const 600) (i32.const 2) (i32.const 700)) (then unreachable))
    (if (i32.ne (i32.load (i32.const 700)) (i32.const 1)) (then unreachable))
    (if (i64.ne (i64.load (i32.const 600)) (i64.const 2)) (then unreachable))
    (call $say (local.get $fd) (i32.const 1100) (i32.const 12))
    (if (call $poll (i32.const 400) (i32.const 600) (i32.const 1) (i32.const 700)) (then unreachable))
    (if (i64.ne (i64.load (i32.const 600)) (i64.const 1)) (then unreachable))
    (i32.store (i32.const 16) (i32.const 800)) (i32.store (i32.const 20) (i32.const 64))
    (if (call $read (local.get $fd) (i32.const 16) (i32.const 1) (i32.const 24)) (then unreachable))
    (if (i32.ne (i32.load (i32.const 24)) (i32.const 12)) (then unreachable))
    (drop (call $set (i32.const 256)))
    (call $say (local.get $fd) (i32.const 1150) (i32.const 11))))`;
const slaveModule = binaryen.parseText(slaveWat); const slave = Buffer.from(slaveModule.emitBinary()); slaveModule.dispose();

test('an opened PTY slave polls for real input, reads canonical data and keeps no-echo input private', async ({ page }) => {
  const path = `/tmp/pty-slave-${crypto.randomUUID()}.wasm`;
  let release, blocked = false, producerExited = false;
  const released = new Promise(resolve => { release = resolve; });
  const gatePath = `/__test_pty_gate_${crypto.randomUUID()}`;
  const exitPath = `/__test_pty_exit_${crypto.randomUUID()}`;
  const needleBytes = [...Buffer.from('POLL_WAITED')];
  const gateRoute = async route => {
    blocked = true;
    await released;
    await route.fulfill({ status: 200, body: 'ok' }).catch(() => {});
  };
  const exitRoute = async route => {
    const status = Number(new URL(route.request().url()).searchParams.get('status'));
    if (status === 0) producerExited = true;
    await route.fulfill({ status: 200, body: 'ok' }).catch(() => {});
  };
  const kernelRoute = async route => {
    const response = await route.fetch();
    const shim = `(() => {
      const pat = ${JSON.stringify(needleBytes)};
      const match = buf => {
        if (!buf || buf.length < pat.length) return false;
        outer: for (let i = 0; i <= buf.length - pat.length; i++) {
          for (let j = 0; j < pat.length; j++) if (buf[i + j] !== pat[j]) continue outer;
          return true;
        }
        return false;
      };
      Object.defineProperty(self, 'wasm_bindgen', {
        configurable: true,
        set(wb) {
          Object.defineProperty(self, 'wasm_bindgen', { value: wb, writable: true, configurable: true, enumerable: true });
          const proto = wb?.Kernel?.prototype;
          if (proto?.take_local_exec_bytes && !proto.take_local_exec_bytes.__testPtyGate) {
            const origTake = proto.take_local_exec_bytes;
            proto.take_local_exec_bytes = function(key, checkOnly) {
              const bytes = origTake.call(this, key, checkOnly);
              if (!checkOnly && match(bytes)) return fetch(${JSON.stringify(gatePath)}).then(() => bytes);
              return bytes;
            };
            proto.take_local_exec_bytes.__testPtyGate = true;
          }
          if (proto?.exit && !proto.exit.__testPtyExit) {
            const origExit = proto.exit;
            proto.exit = function(pid, status, signal, host) {
              void fetch(${JSON.stringify(exitPath)} + '?status=' + (status ?? 0)).catch(() => {});
              return origExit.call(this, pid, status, signal, host);
            };
            proto.exit.__testPtyExit = true;
          }
        },
      });
    })();\n`;
    await route.fulfill({ response, body: shim + await response.text() });
  };
  await page.route(`**${gatePath}`, gateRoute);
  await page.route(`**${exitPath}**`, exitRoute);
  await page.route('**/client-kernel.js', kernelRoute);
  await page.goto('/'); await upload(page, path, slave);
  try {
    producerExited = false;
    const seq = await promptSeq(page);
    await runTerminal(page, `echo pipeline | ${path}`, { wait: false });
    // The master must retain input after the first stage closes its slave and
    // before the delayed consumer opens /dev/tty as a new reader.
    await expect.poll(() => blocked && producerExited, { timeout: 60_000 }).toBe(true);
    release();
    await expect(screen(page)).toContainText('POLL_WAITED', { timeout: 30_000 });
    await sendTerminalLine(page, 'secret-text');
    await waitIdleAfter(page, seq);
    await expect(screen(page)).toContainText('SLAVE_READ');
    await expect(screen(page)).not.toContainText('secret-text');
  } finally {
    release();
    await page.unroute('**/client-kernel.js', kernelRoute).catch(() => {});
    await page.unroute(`**${gatePath}`, gateRoute).catch(() => {});
    await page.unroute(`**${exitPath}**`, exitRoute).catch(() => {});
    await pageRmrf(page, path).catch(() => {});
  }
});

test('terminal and filesystem calls preserve descriptor references and failures in mixed batches', async ({ page }) => {
  await page.goto('/');
  await waitForTerminalReady(page);
  const outPath = `/tmp/pty-syscall-${crypto.randomUUID()}.json`;
  const calls = [
    { ioctl: { fd: 0, request: 0x5401 } },
    { close: { fd: { ref: 2 } } },
    { ioctl: { fd: { ref: 0 }, request: 0x5401 } },
    { open: { path: '/guest/missing-' + crypto.randomUUID(), flags: 0 } },
    { close: { fd: { ref: 3 } } },
    { open: { path: '/etc/passwd', flags: 0 } },
    { pread: { fd: { ref: 5 }, offset: 0, count: 4 } },
    { close: { fd: { ref: 5 } } },
  ];
  try {
    await runTerminal(page, `coreutils syscall '${JSON.stringify(calls)}' > ${outPath}`);
    const result = JSON.parse(await pageGetText(page, outPath)).results;
    expect(result[0].ok.lflag).toBeGreaterThan(0);
    expect(result.slice(1, 5).map(item => item.err.errno)).toEqual(['EINVAL', 'EBADF', 'ENOENT', 'ENOENT']);
    expect(result.slice(5).every(item => Object.hasOwn(item, 'ok'))).toBe(true);
  } finally {
    await pageRmrf(page, outPath).catch(() => {});
  }
});
