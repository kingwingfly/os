import { test, expect } from './test.js';
import { api, call } from './sys.js';
import { readFile } from 'node:fs/promises';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const state = page => page.evaluate(() => window.os.seatStatus());
const activate = (page, active) => page.evaluate(active => window.os.setSeatActive(active), active);
const output = page => page.evaluate(() => window.seatRun.output.replace(/\r\n/g, '\n'));
test.beforeEach(async ({ page }) => {
  await page.goto('/'); await page.waitForFunction(() => !!window.os?.seatStatus); await state(page);
});
test.afterEach(async ({ page }) => {
  if (!page.isClosed()) await page.evaluate(async () => {
    window.seatRun?.group?.signal(9); await window.seatRun?.done;
  });
});
async function start(page, argv = ['cat'], terminalId = 'seat-test') {
  await page.evaluate(([argv, terminalId]) => {
    const run = { output: '', states: [] }; window.seatRun = run;
    run.done = window.os.exec([{ path: argv[0] === 'sh' ? '/usr/bin/sh' : '/usr/bin/coreutils',
      argv: argv[0] === 'sh' ? argv : ['coreutils', ...argv] }], {
      terminalId, tty: true,
      onOutput: (fd, text) => { run.output = (run.output + text).slice(-131072); },
      onTty: input => { run.input = input; }, onJob: group => { run.group = group; },
      onSize: size => { run.size = size; }, onState: value => run.states.push(value),
    }).then(result => { run.result = result; });
  }, [argv, terminalId]);
  await expect.poll(() => page.evaluate(() => window.seatRun.group?.pids.length > 0), { timeout: 60_000 }).toBe(true);
}
async function inputReady(page) { await expect.poll(() => page.evaluate(() => !!window.seatRun.input)).toBe(true); }
async function recipient(page) {
  const [other] = await Promise.all([page.waitForEvent('popup'), page.evaluate(() => { window.seatTarget = window.open('/'); })]);
  await other.waitForFunction(() => !!window.os?.attachConsole);
  await other.evaluate(() => {
    window.seatPeer = { output: '' };
    addEventListener('message', async event => {
      if (event.source !== opener || event.origin !== location.origin || event.data !== 'seat-port') return;
      window.seatPeer.peer = await window.os.attachConsole(event.ports[0], {
        onTty: input => { window.seatPeer.input = input; },
        onOutput: (fd, text) => { window.seatPeer.output += text; },
        onClose: error => { window.seatPeer.closed = error; },
      });
    });
  });
  await page.evaluate(async () => {
    const channel = new MessageChannel();
    window.seatGrant = await window.os.grantConsole('seat-test', channel.port1, { access: 'control' });
    window.seatTarget.postMessage('seat-port', location.origin, [channel.port2]);
  });
  await expect.poll(() => other.evaluate(() => !!window.seatPeer.input)).toBe(true);
  return other;
}

test('pause revokes local input, EOF and resize handles; resume uses fresh handles without ending the process', async ({ page }) => {
  await start(page); await inputReady(page);
  await page.evaluate(() => {
    window.oldSeatInput = window.seatRun.input;
    window.seatRun.input.resize({ columns: 80, rows: 24, width: 800, height: 480 });
  });
  await expect.poll(() => page.evaluate(() => window.seatRun.size?.columns)).toBe(80);
  const before = await state(page), pids = await page.evaluate(() => window.seatRun.group.pids);
  const paused = await activate(page, false);
  expect(paused.generation).toBe(before.generation + 1); expect(paused.devices).toHaveLength(1);
  expect(await page.evaluate(() => window.seatRun.input)).toBe(null);
  const resumed = await activate(page, true); await inputReady(page);
  expect(resumed.generation).toBe(paused.generation + 1);
  await page.evaluate(() => {
    window.oldSeatInput.write('STALE-KEYBOARD\n'); window.oldSeatInput.eof();
    window.oldSeatInput.resize({ columns: 33, rows: 11, width: 330, height: 220 });
    window.seatRun.input.write('fresh-keyboard\n');
  });
  await expect.poll(() => output(page)).toContain('fresh-keyboard\nfresh-keyboard');
  expect(await output(page)).not.toContain('STALE-KEYBOARD');
  expect(await page.evaluate(() => window.seatRun.size.columns)).toBe(80);
  expect(await page.evaluate(() => window.seatRun.group.pids)).toEqual(pids);
  await page.evaluate(() => window.seatRun.input.eof());
  await expect.poll(() => page.evaluate(() => window.seatRun.result?.status)).toBe(0);
  await expect.poll(async () => (await state(page)).devices.length).toBe(0);
});

test('output and lifecycle control keep working while a seat is paused', async ({ page }) => {
  await start(page, ['yes']); await expect.poll(() => output(page)).toContain('y\ny');
  await activate(page, false);
  await page.evaluate(() => { window.seatRun.output = ''; });
  await expect.poll(() => output(page)).toContain('y\ny');
  await page.evaluate(() => window.seatRun.group.signal(2));
  await expect.poll(() => page.evaluate(() => window.seatRun.result?.status)).toBe(130);
  expect((await state(page)).active).toBe(false);
  expect((await state(page)).devices).toHaveLength(0);
});

test('devices created while paused stay inactive until explicit resume', async ({ page }) => {
  await activate(page, false); await start(page);
  expect(await page.evaluate(() => window.seatRun.input)).toBe(null);
  expect((await state(page)).devices).toHaveLength(1);
  await activate(page, true); await inputReady(page);
  await page.evaluate(() => window.seatRun.input.write('late-activation\n'));
  await expect.poll(() => output(page)).toContain('late-activation\nlate-activation');
});

test('a local pause does not revoke another host\'s explicit console control grant', async ({ page }) => {
  await start(page); await inputReady(page); const other = await recipient(page);
  await activate(page, false);
  await other.evaluate(() => window.seatPeer.input.write('remote-still-active\n'));
  await expect.poll(() => output(page)).toContain('remote-still-active\nremote-still-active');
  expect((await state(other)).active).toBe(true);
  await page.evaluate(() => window.os.revokeConsole(window.seatGrant));
  await expect.poll(() => other.evaluate(() => window.seatPeer.closed?.errno)).toBe('ECANCELED');
  expect(await page.evaluate(() => window.seatRun.input)).toBe(null);
  await activate(page, true); await inputReady(page);
  await page.evaluate(() => window.seatRun.input.write('owner-resumed\n'));
  await expect.poll(() => output(page)).toContain('owner-resumed\nowner-resumed');
});

test('receiver pause fences remote input handles and keeps output attached', async ({ page }) => {
  await start(page, ['sh', '-i']); await inputReady(page); const other = await recipient(page);
  await other.evaluate(async () => {
    window.oldRemoteInput = window.seatPeer.input;
    await window.oldRemoteInput.write('sleep 0.2; echo REMOTE_PAUSED_OUTPUT\n');
  });
  await activate(other, false);
  await expect.poll(() => other.evaluate(() => window.seatPeer.output.replace(/\r\n/g, '\n'))).toContain('\nREMOTE_PAUSED_OUTPUT\n');
  expect(await other.evaluate(() => window.seatPeer.input)).toBe(null);
  const rejected = await other.evaluate(async () => {
    try { await window.oldRemoteInput.write('echo STALE-REMOTE\n'); return 'allowed'; } catch (error) { return error.errno; }
  });
  expect(rejected).toBe('ESTALE');
  expect(await other.evaluate(async () => {
    try { await window.seatPeer.peer.input.write('echo PAUSED-REMOTE\n'); return 'allowed'; } catch (error) { return error.errno; }
  })).toBe('EACCES');
  await activate(other, true);
  await other.evaluate(() => window.seatPeer.input.write('echo remote-resumed\n'));
  await expect.poll(() => other.evaluate(() => window.seatPeer.output.replace(/\r\n/g, '\n'))).toContain('remote-resumed\nremote-resumed');
  expect(await output(page)).not.toContain('STALE-REMOTE'); expect(await output(page)).not.toContain('PAUSED-REMOTE');
});

test('seat activation cannot be replayed against another host or a newer generation', async ({ page, context }) => {
  const other = await context.newPage(); await other.goto('/'); await other.waitForFunction(() => !!window.os?.seatStatus);
  const one = await state(page), two = await state(other); expect(two.id).not.toBe(one.id);
  const result = await page.evaluate(async foreign => {
    const worker = new Worker('/client-kernel.js'), pending = new Map(); let next = 0;
    const call = (type, args = {}) => new Promise(resolve => { const id = ++next; pending.set(id, resolve); worker.postMessage({ v: 1, id, type, args }); });
    worker.onmessage = ({ data }) => { if (data.id != null) { pending.get(data.id)?.(data); pending.delete(data.id); } };
    try {
      const original = (await call('seat_status')).ok;
      const unknown = await call('seat_unknown');
      const wrong = await call('seat_set_active', { active: false, expected: foreign });
      await call('seat_set_active', { active: false, expected: original });
      const stale = await call('seat_set_active', { active: true, expected: original });
      return [wrong.err?.errno, stale.err?.errno, unknown.err?.errno, (await call('seat_status')).ok.active];
    } finally { worker.terminate(); }
  }, two);
  expect(result).toEqual(['ESTALE', 'ESTALE', 'ENOSYS', false]);
  expect((await state(page)).active).toBe(true); expect((await state(other)).active).toBe(true);
});

test('pause survives login changes and preserves the running process identity on resume', async ({ page }) => {
  const guest = await call(page.request, 'getcreds');
  await start(page, ['sh', '-i']); await inputReady(page); await activate(page, false);
  expect((await api(page.request, 'login', { headers: { 'CF-Connecting-IP': 'seat-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true);
  await page.evaluate(() => dispatchEvent(new Event('os:login-changed')));
  expect((await state(page)).active).toBe(false);
  await activate(page, true); await inputReady(page);
  await page.evaluate(() => window.seatRun.input.write('id -u\n'));
  await expect.poll(() => output(page)).toContain(String(guest.uid));
});

test('desktop input is disabled while paused and native keyboard focus returns on resume', async ({ page }) => {
  const input = page.locator('#command'); await input.fill('cat'); await input.press('Enter');
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input');
  await activate(page, false); await expect(input).toBeDisabled();
  await expect(page.locator('.console-status')).toHaveText('Terminal input paused');
  await activate(page, true); await expect(input).toBeEnabled();
  await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'input');
  await page.keyboard.type('resumed-native-focus'); await page.keyboard.press('Enter');
  await expect(page.locator('.terminal-screen')).toContainText('resumed-native-focus\nresumed-native-focus');
  await page.keyboard.press('Control+d'); await expect(page.locator('.command-line')).toHaveAttribute('data-state', 'idle');
});

test('page lifecycle suspends devices and restores only the requested activity state', async ({ page }) => {
  await start(page); await inputReady(page);
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true })));
  await expect.poll(async () => (await state(page)).active).toBe(false);
  await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true })));
  await expect.poll(async () => (await state(page)).active).toBe(true); await inputReady(page);
  await activate(page, false);
  await page.evaluate(() => {
    dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
    dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
  });
  // A queued explicit pause is a barrier behind both lifecycle requests.
  await activate(page, false); expect((await state(page)).active).toBe(false);
  expect(await page.evaluate(() => window.seatRun.input)).toBe(null);
  await activate(page, true); await inputReady(page);
  await page.evaluate(() => window.seatRun.input.write('lifecycle-survived\n'));
  await expect.poll(() => output(page)).toContain('lifecycle-survived\nlifecycle-survived');
});

test('local device activation and terminal input do not require a network round trip', async ({ page }) => {
  await start(page); await inputReady(page);
  const offline = route => route.fulfill({ status: 503, body: 'unavailable' });
  await page.route('**/api/sys', offline);
  try {
    await activate(page, false); await activate(page, true); await inputReady(page);
    await page.evaluate(() => window.seatRun.input.write('local-device\n'));
    await expect.poll(() => output(page)).toContain('local-device\nlocal-device');
  } finally { await page.unroute('**/api/sys', offline); }
});

for (const modal of [true, false]) test(`resume preserves focus in ${modal ? 'a modal' : 'another input field'}`, async ({ page }) => {
  await page.locator('#command').focus(); await activate(page, false);
  await page.evaluate(modal => {
    const container = document.createElement(modal ? 'dialog' : 'div');
    const input = document.createElement('input'); input.id = 'seat-focus-fixture';
    container.append(input); document.body.append(container); window.seatFocusFixture = container;
    if (modal) container.showModal();
    input.focus();
  }, modal);
  await activate(page, true);
  await page.evaluate(() => new Promise(requestAnimationFrame));
  await page.keyboard.type('kept-focus');
  await expect(page.locator('#seat-focus-fixture')).toHaveValue('kept-focus');
  await page.evaluate(() => { window.seatFocusFixture.close?.(); window.seatFocusFixture.remove(); });
});
