import { test, expect } from './test.js';
import binaryen from 'binaryen';
import { readFile } from 'node:fs/promises';
import { errno, put, rmrf, sys } from './sys.js';

const busy = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const input = page => page.locator('#command');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function run(page, command) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await input(page).fill(command); await input(page).press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}
async function upload(request, path, data) {
  const response = await put(request, '/api/file?path=' + encodeURIComponent(path), { data, headers: { Origin: process.env.OS_TEST_URL || 'http://127.0.0.1:8787' } });
  expect(response.ok(), await response.text()).toBe(true);
  expect(await errno(request, { chmod: { path, mode: 0o755 } })).toBe(null);
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
  await run(page, 'tty'); const name = await last(page).innerText(); expect(name).toMatch(/^\/dev\/pts\/\d+$/);
  await run(page, 'stty -a'); await expect(last(page)).toContainText('echo icanon isig -tostop opost onlcr');
  await run(page, 'stty -echo'); await run(page, 'stty -a'); await expect(last(page)).toContainText('-echo icanon');
  await run(page, 'stty sane'); await run(page, 'tty'); await expect(last(page)).toHaveText(name);
  await run(page, 'stty size'); const before = await last(page).innerText();
  await page.setViewportSize({ width: 430, height: 700 });
  await run(page, 'stty size'); expect(await last(page).innerText()).not.toBe(before);
  await run(page, 'echo data | tty'); await expect(last(page)).toHaveText('not a tty');
});

test('closing a terminal pane hangs up its running and stopped jobs while another pane survives', async ({ page }) => {
  await page.goto('/');
  const rows = async () => (await sys(page.request, [{ proc_poll: { pids: [] } }]))[0].ok;
  const sleep = (process, seconds) => process.argv?.includes('sleep') && process.argv.includes(String(seconds));
  try {
    await input(page).fill('sleep 61'); await input(page).press('Enter');
    await expect.poll(async () => (await rows()).some(p => sleep(p, 61))).toBe(true);
    await page.keyboard.press('Alt+t');
    await run(page, 'sleep 62 &');
    await input(page).fill('sleep 63'); await input(page).press('Enter');
    await expect.poll(async () => (await rows()).some(p => sleep(p, 63))).toBe(true);
    await input(page).press('Control+z'); await expect(busy(page)).toHaveAttribute('data-state', 'idle');
    await expect.poll(async () => (await rows()).find(p => sleep(p, 63))?.state).toBe('stopped');
    await page.getByRole('button', { name: 'Close tab 2' }).click();
    await expect(page.getByRole('tab')).toHaveCount(1);
    await expect.poll(async () => (await rows()).filter(p => sleep(p, 62) || sleep(p, 63)).length).toBe(0);
    expect((await rows()).find(p => sleep(p, 61))?.state).toBe('running');
    await input(page).press('Control+c'); await expect(busy(page)).toHaveAttribute('data-state', 'idle');
    await run(page, 'echo console-alive'); await expect(last(page)).toContainText('console-alive');
  } finally {
    for (const process of await rows()) if ([61, 62, 63].some(n => sleep(process, n)))
      await sys(page.request, [{ kill: { pid: String(process.pid), signal: 9 } }]);
  }
});

test('a cancelled console launch never creates a process or changes files', async ({ page }) => {
  await page.goto('/');
  const path = `/guest/cancelled-console-${crypto.randomUUID()}`;
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
    expect(await errno(page.request, { stat: { path } })).toBe('ENOENT');
  } finally { await rmrf(page.request, path); }
});

test('coreutils cat reads controlling-terminal device paths through ordinary file descriptors', async ({ page }) => {
  await page.goto('/');
  await run(page, 'tty'); const slave = await last(page).innerText();
  await run(page, 'stty -echo');
  for (const command of ['echo ignored | cat /dev/tty', `cat ${slave}`]) {
    await input(page).fill(command); await input(page).press('Enter');
    await expect(busy(page)).toHaveAttribute('data-state', 'input');
    await input(page).fill('device-input'); await input(page).press('Enter');
    await expect(last(page)).toHaveText('device-input');
    await input(page).press('Control+d');
    await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  }
  await run(page, 'stty sane');
});

test('WASIX raw input and cursor addressing render a full-screen application and restore the transcript', async ({ page, request }) => {
  const path = `/guest/pty-screen-${crypto.randomUUID()}.wasm`;
  await page.goto('/'); await upload(request, path, fullscreen);
  try {
    await input(page).fill(path); await input(page).press('Enter');
    const screen = page.locator('.terminal-screen[data-alternate="true"]');
    await expect(screen).toContainText('PTY screen'); await expect(screen).toContainText('    READY');
    await expect(busy(page)).toHaveAttribute('data-state', 'input');
    await input(page).press('ArrowUp'); await expect(screen).toContainText('    UP');
    await input(page).press('x'); await expect(screen).toContainText('    KEY');
    await input(page).press('Control+z'); await expect(busy(page)).toHaveAttribute('data-state', 'idle');
    await expect(screen).toHaveCount(0);
    await input(page).fill('fg'); await input(page).press('Enter');
    await expect(screen).toContainText('PTY screen');
    await page.setViewportSize({ width: 430, height: 700 });
    await input(page).press('r'); await expect(screen).toContainText('RESIZED');
    await input(page).press('q'); await expect(busy(page)).toHaveAttribute('data-state', 'idle');
    await expect(page.locator('.terminal-screen[data-alternate="true"]')).toHaveCount(0);
    await expect(last(page)).toContainText('finished');
    await run(page, 'stty -a'); await expect(last(page)).toContainText('echo icanon');
  } finally { await rmrf(request, path); }
});

test('PTY Ctrl+C and Ctrl+Z reach the foreground job; descriptors name the slave', async ({ page, request }) => {
  await page.goto('/');
  await input(page).fill('coreutils cat'); await input(page).press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  const rows = await sys(page.request, [{ proc_poll: { pids: [] } }]);
  const running = rows[0].ok.find(p => p.argv.includes('cat'));
  expect(running).toBeTruthy();
  await expect.poll(async () => {
    const result = await sys(page.request, [{ readlink: { path: `/proc/${running.pid}/fd/0` } }]);
    return result[0].ok;
  }).toMatch(/^\/dev\/pts\/\d+$/);
  await input(page).fill('canonical'); await input(page).press('Enter'); await expect(last(page)).toHaveText('canonical\ncanonical');
  await input(page).press('Control+z'); await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await run(page, 'jobs'); await expect(last(page)).toContainText('Stopped');
  await input(page).fill('fg'); await input(page).press('Enter'); await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await input(page).press('Control+c'); await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await run(page, 'ps'); await expect(last(page)).not.toContainText('coreutils cat');
});

test('interactive dash prompts, reads a canonical line, and exits on Ctrl+D', async ({ page, request }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  test.setTimeout(120_000);
  const path = `/guest/pty-dash-${crypto.randomUUID()}.wasm`;
  await page.goto('/'); await upload(request, path, await readFile(process.env.WASIX_DASH));
  try {
    await input(page).fill(`${path} -i`); await input(page).press('Enter');
    await expect(busy(page)).toHaveAttribute('data-state', 'input', { timeout: 90_000 });
    await input(page).fill('echo PTY_DASH'); await input(page).press('Enter');
    await expect(page.locator('.terminal-screen')).toContainText(/\nPTY_DASH\n/);
    await expect(busy(page)).toHaveAttribute('data-state', 'input');
    const screen = page.locator('.terminal-screen');
    await input(page).pressSequentially('ls /usr/bin');
    await expect(screen).toContainText(/# ls \/usr\/bin/);
    await expect(input(page)).toHaveValue('');
    await expect.poll(async () => {
      const caret = await page.locator('.terminal-cursor:not([hidden])').boundingBox();
      const capture = await input(page).boundingBox();
      return caret && capture ? Math.abs(caret.y - capture.y) + Math.abs(caret.x - capture.x) : Infinity;
    }).toBeLessThan(2);
    await input(page).press('Enter');
    // The legacy uploaded shell polls while the external program stats every
    // installed entry. Use the command deadline, not a five-second UI deadline.
    await expect(screen).toContainText('coreutils', { timeout: 60_000 });
    await expect(screen).not.toContainText('Exec format error');
    await expect(page.locator('.error-line')).toHaveCount(0);
    await expect(busy(page)).toHaveAttribute('data-state', 'input');
    await input(page).fill('stty -a'); await input(page).press('Enter');
    await expect(page.locator('.transcript')).toContainText('icanon isig', { timeout: 30_000 });
    await expect(busy(page)).toHaveAttribute('data-state', 'input'); await input(page).press('Control+d');
    await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  } finally { await rmrf(request, path); }
});


test('raw mode without ISIG delivers Ctrl+C and Ctrl+D as input bytes', async ({ page, request }) => {
  const path = `/guest/pty-raw-${crypto.randomUUID()}.wasm`;
  await page.goto('/'); await upload(request, path, fullscreen);
  try {
    await run(page, 'stty raw');
    await input(page).fill(path); await input(page).press('Enter');
    const screen = page.locator('.terminal-screen[data-alternate="true"]');
    await expect(screen).toContainText('READY');
    await input(page).press('Control+c'); await expect(screen).toContainText('KEY');
    await expect(busy(page)).toHaveAttribute('data-state', 'input');
    await input(page).press('Control+d'); await expect(busy(page)).toHaveAttribute('data-state', 'input');
    await input(page).press('q'); await expect(busy(page)).toHaveAttribute('data-state', 'idle');
    await run(page, 'stty sane');
  } finally { await rmrf(request, path); }
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
test('an opened PTY slave polls for real input, reads canonical data and keeps no-echo input private', async ({ page, request }) => {
  const path = `/guest/pty-slave-${crypto.randomUUID()}.wasm`;
  await page.goto('/'); await upload(request, path, slave);
  let release, blocked = false, producerExited = false;
  const released = new Promise(resolve => { release = resolve; });
  page.on('request', request => {
    if (new URL(request.url()).pathname !== '/api/sys' || request.method() !== 'POST') return;
    if (request.postDataJSON()?.calls.some(call => call.exit?.status === 0)) producerExited = true;
  });
  await page.route('**/api/file?**', async route => {
    if (!new URL(route.request().url()).searchParams.has('compile')) return route.continue();
    const response = await route.fetch(), data = await response.body();
    if (data.includes(Buffer.from('POLL_WAITED'))) { blocked = true; await released; }
    await route.fulfill({ response, body: data }).catch(() => {});
  });
  try {
    await input(page).fill(`echo pipeline | ${path}`); await input(page).press('Enter');
    // The master must retain input after the first stage closes its slave and
    // before the delayed consumer opens /dev/tty as a new reader.
    await expect.poll(() => blocked && producerExited, { timeout: 60_000 }).toBe(true);
    release();
    await expect(last(page)).toContainText('POLL_WAITED', { timeout: 30_000 });
    await expect(input(page)).toHaveAttribute('type', 'password');
    await input(page).fill('secret-text'); await input(page).press('Enter');
    await expect(busy(page)).toHaveAttribute('data-state', 'idle');
    await expect(last(page)).toContainText('SLAVE_READ');
    await expect(page.locator('.transcript')).not.toContainText('secret-text');
    await expect(input(page)).toHaveAttribute('type', 'text');
  } finally { release(); await rmrf(request, path); }
});

test('terminal and filesystem calls preserve descriptor references and failures in mixed batches', async ({ page }) => {
  await page.goto('/');
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
  await run(page, `coreutils syscall '${JSON.stringify(calls)}'`);
  const result = JSON.parse((await last(page).innerText()).replaceAll("\n", "")).results;
  expect(result[0].ok.lflag).toBeGreaterThan(0);
  expect(result.slice(1, 5).map(item => item.err.errno)).toEqual(['EINVAL', 'EBADF', 'ENOENT', 'ENOENT']);
  expect(result.slice(5).every(item => Object.hasOwn(item, 'ok'))).toBe(true);
});

test('without isolation the UI explains unavailable terminal input and keeps sequential pipelines working', async ({ page }) => {
  await page.route('**/', async route => {
    const response = await route.fetch(); const headers = { ...response.headers() };
    delete headers['cross-origin-opener-policy']; delete headers['cross-origin-embedder-policy'];
    await route.fulfill({ response, headers });
  });
  await page.goto('/');
  expect(await page.evaluate(() => crossOriginIsolated)).toBe(false);
  await run(page, 'tty');
  await expect(last(page)).toHaveText('not a tty');
  await expect(page.locator('.transcript')).toContainText('Interactive terminal input is unavailable');
  await run(page, 'coreutils seq 3 | coreutils tail -n 1');
  await expect(last(page)).toHaveText('3');
});


test('the shell prompt follows output inside the scrollback instead of a fixed bottom bar', async ({ page }) => {
  await page.goto('/');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  const log = page.locator('.terminal-panel:not([hidden]) .transcript');
  const form = log.locator('.command-line');
  await expect(form).toBeVisible();
  const before = await form.boundingBox(), viewport = await log.boundingBox();
  expect(before.y + before.height).toBeLessThan(viewport.y + viewport.height - 60);
  await run(page, 'echo inline-output');
  const after = await form.boundingBox(), output = await last(page).boundingBox();
  expect(after.y).toBeGreaterThanOrEqual(output.y + output.height - 1);
  expect(after.y - output.y - output.height).toBeLessThan(8);
});

test('foreground commands hide the shell prompt and never flash a working indicator', async ({ page }) => {
  await page.goto('/');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  const prompt = busy(page).locator('label');
  await expect(prompt).toBeVisible();
  await page.evaluate(() => {
    window.osStatusFlashes = [];
    new MutationObserver(() => {
      const text = document.querySelector('.terminal-panel:not([hidden])').innerText;
      if (/Working\.\.\.|Input ↵|Answer ↵/.test(text)) window.osStatusFlashes.push(text);
    }).observe(document.querySelector('.terminal-tabs'), { subtree: true, childList: true, characterData: true, attributes: true });
  });
  await input(page).fill('sleep 1'); await input(page).press('Enter');
  await expect(busy(page)).toHaveAttribute('aria-busy', 'true');
  await expect(prompt).toBeHidden();
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await expect(prompt).toBeVisible();
  await run(page, 'ls /usr/bin');
  expect(await page.evaluate(() => window.osStatusFlashes)).toEqual([]);
  await expect(prompt).toBeVisible();
});

test('continuous terminal output remains responsive to Ctrl+C', async ({ page }) => {
  await page.goto('/');
  for (const command of ['yes', 'yes | cat']) {
    await input(page).fill(command); await input(page).press('Enter');
    await expect(page.locator('.terminal-screen[data-live=true]')).toContainText('y\ny');
    // Let the writer reach steady state rather than interrupting only during startup.
    await page.waitForTimeout(500);
    const start = Date.now();
    await input(page).press('Control+c');
    await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 5000 });
    expect(Date.now() - start).toBeLessThan(5000);
    await run(page, 'printf responsive'); await expect(last(page)).toHaveText('responsive');
  }
  await expect(page.locator('.transcript')).not.toContainText('cut short');
});
