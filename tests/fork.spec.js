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
