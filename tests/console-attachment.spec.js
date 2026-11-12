import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, call } from './sys.js';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
test.beforeEach(async ({ page }) => { await page.goto('/'); await page.waitForFunction(() => !!window.os?.attachConsole); });
test.afterEach(async ({ page }) => {
  if (!page.isClosed()) await page.evaluate(async () => {
    window.consoleRun?.group?.signal(9);
    await window.consoleRun?.done;
  });
});
async function start(page, argv = ['cat'], terminalId = 'attachment-pane', wait = true) {
  await page.evaluate(([argv, terminalId]) => {
    const run = { output: '', states: [] }; window.consoleRun = run;
    run.done = window.os.exec([{ path: argv[0] === 'sh' ? '/usr/bin/sh' : '/usr/bin/coreutils',
      argv: argv[0] === 'sh' ? argv : ['coreutils', ...argv] }], {
      terminalId, tty: true,
      onOutput: (fd, text) => { run.output = (run.output + text).slice(-131072); },
      onTty: input => { run.input = input; }, onJob: group => { run.group = group; },
      onState: state => run.states.push(state),
    }).then(result => { run.result = result; });
  }, [argv, terminalId]);
  if (wait) await expect.poll(() => page.evaluate(() => !!window.consoleRun.input && window.consoleRun.group.pids.length > 0), { timeout: 60_000 }).toBe(true);
}
async function target(page) {
  const [other] = await Promise.all([page.waitForEvent('popup'), page.evaluate(() => { window.consoleTarget = window.open('/'); })]);
  await other.waitForFunction(() => !!window.os?.attachConsole);
  await other.evaluate(() => {
    window.receiving = { output: '', states: [] };
    addEventListener('message', async event => {
      if (event.source !== opener || event.origin !== location.origin || event.data !== 'test-console-port') return;
      const record = window.receiving;
      try {
        record.peer = await window.os.attachConsole(event.ports[0], {
          onOutput: (fd, text) => { record.output = (record.output + text).slice(-131072); },
          onMode: mode => { record.mode = mode; }, onSize: size => { record.size = size; },
          onState: state => record.states.push(state), onTty: input => { record.input = !!input; },
          onClose: error => { record.closed = error; },
        });
      } catch (error) { record.error = { errno: error.errno, message: error.message }; }
    });
  });
  return other;
}
async function connect(page, other, access = 'view', terminalId = 'attachment-pane') {
  const grant = await page.evaluate(async ([access, terminalId]) => {
    const channel = new MessageChannel();
    const grant = await window.os.grantConsole(terminalId, channel.port1, { access });
    window.consoleTarget.postMessage('test-console-port', location.origin, [channel.port2]);
    return grant;
  }, [access, terminalId]);
  await expect.poll(() => other.evaluate(() => window.receiving.peer?.access ?? window.receiving.error), { timeout: 60_000 }).toBe(access);
  return grant;
}
const output = page => page.evaluate(() => window.consoleRun.output.replace(/\r\n/g, '\n'));
const remoteOutput = page => page.evaluate(() => window.receiving.output.replace(/\r\n/g, '\n'));
const write = (page, text) => page.evaluate(text => window.consoleRun.input.write(text), text);
const remoteWrite = (page, text) => page.evaluate(text => window.receiving.peer.input.write(text), text);
const ended = (page, status) => expect.poll(() => page.evaluate(() => window.consoleRun.result?.status), { timeout: 60_000 }).toBe(status);

test('SIGKILL while fetching an admitted image settles as a killed process despite token revocation', async ({page})=>{
  let release, blocked=false;const held=new Promise(resolve=>{release=resolve;});
  await page.route(url=>url.pathname==='/api/file' && url.searchParams.has('compile'),async route=>{
    blocked=true;await held;await route.continue();
  });
  try {
    await start(page,['cat'],'attachment-pane',false);
    await expect.poll(()=>blocked,{timeout:60000}).toBe(true);
    const killed=page.waitForResponse(response=>response.url().endsWith('/api/sys') &&
      response.request().postDataJSON()?.calls?.some(call=>call.kill?.signal===9));
    await page.evaluate(()=>window.consoleRun.group.signal(9));await killed;
    release();await ended(page,137);
  }finally{release();}
});

test('a console grant waits for authenticated process startup', async ({ page }) => {
  let release, continued, blocked = false;
  const waiting = new Promise(resolve => { release = resolve; });
  const continuation = new Promise(resolve => { continued = resolve; });
  const delay = async route => {
    const calls = route.request().postDataJSON()?.calls ?? [];
    if (calls.some(call => call.execve?.argv?.includes('cat'))) {
      blocked = true; await waiting;
      try { await route.continue(); } finally { continued(); }
    } else await route.continue();
  };
  await page.route('**/api/sys', delay);
  try {
    await start(page, ['cat'], 'attachment-pane', false);
    await expect.poll(() => blocked).toBe(true);
    expect(await page.evaluate(async () => {
      const channel = new MessageChannel();
      try { await window.os.grantConsole('attachment-pane', channel.port1); return 'allowed'; }
      catch (error) { return error.errno; } finally { channel.port2.close(); }
    })).toBe('EAGAIN');
  } finally { release(); if (blocked) await continuation; await page.unroute('**/api/sys', delay); }
  await expect.poll(() => page.evaluate(() => !!window.consoleRun.input), { timeout: 60_000 }).toBe(true);
  const other = await target(page); await connect(page, other, 'control');
  await remoteWrite(other, 'authorized\n'); await expect.poll(() => output(page)).toContain('authorized');
});

test('view-only attachment across browser tabs receives output but cannot control the command', async ({ page }) => {
  await start(page); const other = await target(page); const grant = await connect(page, other);
  const denied = await other.evaluate(async () => {
    const input = window.receiving.peer.input, failures = [];
    for (const request of [() => input.write('denied\n'), () => input.eof(), () => input.reply('denied'),
      () => input.resize({ columns: 40, rows: 20, width: 0, height: 0 })]) {
      try { await request(); failures.push('allowed'); } catch (e) { failures.push(e.errno); }
    }
    return failures;
  });
  expect(denied).toEqual(Array(4).fill('EACCES'));
  await write(page, 'owner-input\n'); await expect.poll(() => remoteOutput(other)).toContain('owner-input');
  expect(await output(page)).not.toContain('denied');
  expect(await other.evaluate(() => window.receiving.input)).toBe(false);
  await page.evaluate(grant => window.os.revokeConsole(grant), grant);
  await expect.poll(() => other.evaluate(() => window.receiving.closed?.errno)).toBe('ECANCELED');
  await write(page, 'after-revoke\n'); await expect.poll(() => output(page)).toContain('after-revoke');
  expect(await remoteOutput(other)).not.toContain('after-revoke');
  await page.evaluate(() => window.consoleRun.input.eof()); await ended(page, 0);
});

test('control grants exclusively route remote input, resize and interrupt, then expire with the command', async ({ page }) => {
  await start(page); const other = await target(page); await connect(page, other, 'control');
  await expect.poll(() => other.evaluate(() => window.receiving.input)).toBe(true);
  await write(page, 'local-denied\n');
  await remoteWrite(other, 'remote-accepted\n'); await expect.poll(() => output(page)).toContain('remote-accepted');
  expect(await output(page)).not.toContain('local-denied');
  const pasted = 'paste-' + 'x'.repeat(1024);
  await remoteWrite(other, pasted + '\n'); await expect.poll(() => remoteOutput(other)).toContain(pasted);
  await other.evaluate(() => window.receiving.peer.input.resize({ columns: 93, rows: 29, width: 930, height: 580 }));
  await expect.poll(() => other.evaluate(() => window.receiving.size)).toMatchObject({ columns: 93, rows: 29 });
  await remoteWrite(other, '\x03'); await ended(page, 130);
  await expect.poll(() => other.evaluate(() => window.receiving.closed?.errno)).toBe('EPIPE');
  const before = await remoteOutput(other);
  await start(page); await write(page, 'replacement-private\n'); await expect.poll(() => output(page)).toContain('replacement-private');
  expect(await remoteOutput(other)).toBe(before);
  await page.evaluate(() => window.consoleRun.input.eof()); await ended(page, 0);
});

test('remote EOF flushes a partial canonical line and final output drains before detach', async ({ page }) => {
  await start(page); const other = await target(page); await connect(page, other, 'control');
  await remoteWrite(other, 'final-without-newline');
  await other.evaluate(() => window.receiving.peer.input.eof());
  // The first EOF delivers the pending line; the second ends the next read.
  await expect.poll(() => output(page)).toContain('final-without-newlinefinal-without-newline');
  await other.evaluate(() => window.receiving.peer.input.eof()); await ended(page, 0);
  await expect.poll(() => other.evaluate(() => window.receiving.closed?.errno)).toBe('EPIPE');
  expect(await remoteOutput(other)).toContain('final-without-newlinefinal-without-newline');
});

test('a grant identifier or console name in another host does not authorize attachment or revocation', async ({ page }) => {
  await start(page); const other = await target(page); const grant = await connect(page, other, 'control');
  expect(await other.evaluate(async grant => {
    try { await window.os.revokeConsole(grant); return 'allowed'; } catch (error) { return error.errno; }
  }, grant)).toBe('ENOENT');
  expect(await other.evaluate(async () => {
    const channel = new MessageChannel();
    try { await window.os.grantConsole('attachment-pane', channel.port1, { access: 'control' }); return 'allowed'; }
    catch (error) { return error.errno; } finally { channel.port2.close(); }
  })).toBe('ESRCH');
  expect(await page.evaluate(async () => {
    const channel = new MessageChannel();
    try { await window.os.grantConsole('attachment-pane', channel.port1, { access: 'control' }); return 'allowed'; }
    catch (error) { return error.errno; } finally { channel.port2.close(); }
  })).toBe('EBUSY');
  await remoteWrite(other, 'still-attached\n'); await expect.poll(() => output(page)).toContain('still-attached');
  await other.evaluate(() => window.receiving.peer.detach());
  await expect.poll(() => other.evaluate(() => window.receiving.closed?.errno)).toBe('ECANCELED');
  await expect.poll(async () => { await write(page, 'owner-restored\n'); return output(page); }).toContain('owner-restored');
});

test('a granted run keeps its original process identity across browser login and cannot expose a later root command', async ({ page }) => {
  const guest = await call(page.request, 'getcreds');
  await start(page, ['sh', '-c', 'id -u; read first; id -u; read second']);
  await expect.poll(() => output(page)).toContain(String(guest.uid));
  const other = await target(page); await connect(page, other, 'control');
  expect((await api(page.request, 'login', { headers: { 'CF-Connecting-IP': 'console-attachment-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true);
  await remoteWrite(other, 'continue\n'); await expect.poll(() => remoteOutput(other)).toContain(String(guest.uid));
  await remoteWrite(other, 'finish\n'); await ended(page, 0);
  await expect.poll(() => other.evaluate(() => window.receiving.closed?.errno)).toBe('EPIPE');
  const before = await remoteOutput(other);
  await start(page, ['sh', '-c', 'id -u; read final']);
  await expect.poll(() => output(page)).toMatch(/^0\n/);
  expect(await remoteOutput(other)).toBe(before);
  await write(page, 'root-finish\n'); await ended(page, 0);
});

test('closing the owning console revokes the peer without letting it control a replacement', async ({ page }) => {
  await start(page); const other = await target(page); await connect(page, other, 'control');
  await page.evaluate(() => window.os.closeConsole('attachment-pane'));
  await expect.poll(() => other.evaluate(() => window.receiving.closed?.errno)).toBe('EPIPE');
  await ended(page, 129);
  await start(page); await write(page, 'fresh-console\n'); await expect.poll(() => output(page)).toContain('fresh-console');
  expect(await remoteOutput(other)).not.toContain('fresh-console');
});

test('a closed receiving tab returns input control to the owner after its lease', async ({ page }) => {
  await start(page); const other = await target(page); await connect(page, other, 'control');
  await other.close();
  await expect.poll(async () => { await write(page, 'after-peer-loss\n'); return output(page); },
    { timeout: 45_000, intervals: [1000] }).toContain('after-peer-loss');
  expect(await page.evaluate(() => window.consoleRun.result)).toBeUndefined();
  await page.evaluate(() => window.consoleRun.input.eof()); await ended(page, 0);
});

test('a departing owning host revokes its attachment or closes it by the port lease', async ({ page }) => {
  await start(page); const other = await target(page); await connect(page, other, 'control');
  await page.close();
  // A graceful departure invalidates the sharing policy before the port lease.
  // If that final message is lost, the receiving host still expires the port.
  await expect.poll(() => other.evaluate(() => window.receiving.closed?.errno), { timeout: 45_000, intervals: [1000] }).toMatch(/^(EACCES|ETIMEDOUT)$/);
  expect(await other.evaluate(() => window.receiving.input)).toBe(false);
});
