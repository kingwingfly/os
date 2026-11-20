import { test, expect } from './test.js';
import { call, errno, put, rmrf } from './sys.js';
import binaryen from 'binaryen';

const image = { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [] };
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };

async function connect(page) {
  await page.goto('/login');
  await page.evaluate(() => {
    const worker = new Worker('/client-kernel.js');
    const pending = new Map();
    let next = 0;
    worker.onmessage = ({ data }) => {
      if (data?.id != null && pending.has(data.id)) {
        pending.get(data.id)(data);
        pending.delete(data.id);
      }
    };
    window.pidKernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      worker.postMessage({ v: 2, id, type, args });
    });
  });
  await kv(page, 'init');
}
const kc = (page, type, args = {}) => page.evaluate(([type, args]) => window.pidKernel(type, args), [type, args]);
async function kv(page, type, args = {}) {
  const r = await kc(page, type, args);
  expect(r.err, `${type}: ${JSON.stringify(r)}`).toBeUndefined();
  return r.ok;
}
async function denied(page, type, args, expected) {
  expect((await kc(page, type, args)).err?.errno).toBe(expected);
}
const stat = (p, path) => kv(p, 'cgroup_stat', { path });
const limit = (p, path, value) => kv(p, 'cgroup_set', { path, key: 'pids.max', value: String(value) });
const launch = (p, path, extra = {}) => kv(p, 'exec', { ...image, cgroup: path, ...extra });
const fork = (p, parent) => kv(p, 'fork', { pid: parent.pid });
async function finish(p, proc, ppid = null) {
  await kc(p, 'exit', { pid: proc.pid, status: 0 });
  if (ppid != null) await kc(p, 'waitchild', { ppid, pid: proc.pid });
  else await kc(p, 'wait', { pid: proc.pid });
}
async function make(p) {
  const path = '/user/pids-' + crypto.randomUUID();
  await kv(p, 'cgroup_create', { path });
  return path;
}
async function remove(p, path) {
  const s = await kc(p, 'cgroup_stat', { path });
  if (s.err) return;
  await kv(p, 'cgroup_set', { path, key: 'cgroup.kill', value: '1' });
  for (const pid of s.ok['subtree.procs']) await kc(p, 'wait', { pid });
  for (const child of s.ok.children) await remove(p, child);
  await kc(p, 'cgroup_remove', { path });
}

test('hierarchical PID limits count zombies until reap and exec preserves a full slot', async ({ page }) => {
  await connect(page);
  const path = await make(page);
  let parent;
  try {
    await kv(page, 'cgroup_create', { path: path + '/nested' });
    await limit(page, path, 2);
    await limit(page, path + '/nested', 10);
    parent = await launch(page, path + '/nested');
    const child = await fork(page, parent);
    expect((await stat(page, path))['pids.current']).toBe(2);
    await denied(page, 'fork', { pid: parent.pid }, 'EAGAIN');
    const replaced = await kv(page, 'reexec', { ...image, pid: parent.pid });
    expect(replaced.cgroup).toBe(path + '/nested');
    await kv(page, 'exit', { pid: child.pid, status: 0 });
    expect((await stat(page, path))['pids.current']).toBe(2);
    await denied(page, 'fork', { pid: parent.pid }, 'EAGAIN');
    await kv(page, 'waitchild', { ppid: parent.pid, pid: child.pid });
    expect((await stat(page, path))['pids.current']).toBe(1);
    const next = await fork(page, parent);
    await finish(page, next, parent.pid);
    await limit(page, path, 0);
    await denied(page, 'fork', { pid: parent.pid }, 'EAGAIN');
    expect((await stat(page, path))['pids.current']).toBe(1);
    await limit(page, path, 'max');
    await finish(page, await fork(page, parent), parent.pid);
  } finally {
    if (parent) await finish(page, parent);
    await remove(page, path);
  }
});

test('parallel exec admission grants exactly the available slots and isolates a sibling', async ({ page }) => {
  await connect(page);
  const path = await make(page), sibling = path + '-sibling';
  await kv(page, 'cgroup_create', { path: sibling });
  try {
    await limit(page, path, 3);
    const results = await Promise.all(Array.from({ length: 12 }, () => kc(page, 'exec', { ...image, cgroup: path })));
    expect(results.filter(r => r.ok)).toHaveLength(3);
    expect(results.filter(r => r.err).map(r => r.err.errno)).toEqual(Array(9).fill('EAGAIN'));
    expect((await stat(page, path))['pids.current']).toBe(3);
    const other = await launch(page, sibling);
    await finish(page, other);
    for (const r of results.filter(r => r.ok)) await finish(page, r.ok);
    expect((await stat(page, path))['pids.current']).toBe(0);
    await finish(page, await launch(page, path));
  } finally {
    await remove(page, path);
    await remove(page, sibling);
  }
});

test('parallel forks cannot overrun a group', async ({ page }) => {
  await connect(page);
  const path = await make(page);
  let parent;
  try {
    await limit(page, path, 4);
    parent = await launch(page, path);
    const results = await Promise.all(Array.from({ length: 12 }, () => kc(page, 'fork', { pid: parent.pid })));
    expect(results.filter(r => r.ok)).toHaveLength(3);
    expect(results.filter(r => r.err).every(r => r.err.errno === 'EAGAIN')).toBe(true);
    expect((await stat(page, path))['pids.current']).toBe(4);
    for (const r of results.filter(r => r.ok)) await finish(page, r.ok, parent.pid);
    expect((await stat(page, path))['pids.current']).toBe(1);
    const again = await fork(page, parent);
    await finish(page, again, parent.pid);
  } finally {
    if (parent) await finish(page, parent);
    await remove(page, path);
  }
});

test('migration checks only gaining ancestors and refuses overflow without moving the process', async ({ page }) => {
  await connect(page);
  const path = await make(page), outside = await make(page);
  let p, q;
  try {
    for (const name of ['a', 'b']) await kv(page, 'cgroup_create', { path: path + '/' + name });
    await limit(page, path, 1);
    p = await launch(page, path + '/a');
    q = await launch(page, outside);
    await kv(page, 'cgroup_attach', { pid: p.pid, path: path + '/b' });
    await limit(page, path, 0);
    await kv(page, 'cgroup_attach', { pid: p.pid, path: path + '/a' });
    await kv(page, 'cgroup_attach', { pid: p.pid, path: path + '/a' });
    await denied(page, 'cgroup_attach', { pid: q.pid, path: path + '/b' }, 'EAGAIN');
    expect((await stat(page, outside))['cgroup.procs']).toContain(q.pid);
    await denied(page, 'fork', { pid: p.pid }, 'EAGAIN');
    await limit(page, path, 'max');
    await limit(page, path + '/b', 0);
    await denied(page, 'cgroup_attach', { pid: p.pid, path: path + '/b' }, 'EAGAIN');
    expect((await stat(page, path + '/a'))['cgroup.procs']).toContain(p.pid);
  } finally {
    for (const p0 of [p, q]) if (p0) await finish(page, p0);
    await remove(page, path);
    await remove(page, outside);
  }
});

test('parallel migrations share the same atomic destination budget', async ({ page }) => {
  await connect(page);
  const path = await make(page), outside = await make(page);
  const processes = [];
  try {
    for (let i = 0; i < 6; i++) processes.push(await launch(page, outside));
    await limit(page, path, 1);
    const results = await Promise.all(processes.map(p => kc(page, 'cgroup_attach', { pid: p.pid, path })));
    expect(results.filter(r => 'ok' in r)).toHaveLength(1);
    expect(results.filter(r => r.err).map(r => r.err.errno)).toEqual(Array(5).fill('EAGAIN'));
    expect((await stat(page, path))['pids.current']).toBe(1);
    expect((await stat(page, outside))['pids.current']).toBe(5);
  } finally {
    for (const p of processes) await finish(page, p);
    await remove(page, path);
    await remove(page, outside);
  }
});

test('failed authorization uses no PID slot and capability reporting distinguishes stored limits', async ({ page }) => {
  await connect(page);
  const path = await make(page);
  try {
    await limit(page, path, 1);
    for (const value of ['-1', '+1', '1.5', '4294967296', '']) {
      await denied(page, 'cgroup_set', { path, key: 'pids.max', value }, 'EINVAL');
    }
    await kv(page, 'cgroup_set', { path, key: 'memory.max', value: '1024' });
    const s = await stat(page, path);
    expect(s).toMatchObject({ 'pids.current': 0, 'pids.max': 1, 'memory.max': '1024', 'resource.enforced': ['pids.max', 'memory.max', 'io.max'] });
    await denied(page, 'exec', { ...image, cgroup: path, runtime: 'untracked' }, 'EOPNOTSUPP');
    await kv(page, 'cgroup_set', { path, key: 'memory.max', value: 'max' });
    await finish(page, await launch(page, path));
    expect((await stat(page, path))['pids.current']).toBe(0);
  } finally {
    await remove(page, path);
  }
});

test('root-owned PID policy remains authoritative after browser logout', async ({ page }) => {
  await connect(page);
  await kv(page, 'sync_account', ROOT_ACCOUNT);
  const path = await make(page);
  let parent;
  try {
    await limit(page, path, 1);
    parent = await launch(page, path);
    await kv(page, 'sync_account', GUEST_ACCOUNT);
    await denied(page, 'cgroup_set', { path, key: 'pids.max', value: 'max' }, 'EACCES');
    await denied(page, 'fork', { pid: parent.pid }, 'EAGAIN');
    // The running root process still retains its own root credentials after browser logout.
    await kv(page, 'process_call', { pid: parent.pid, call: { cgroup_set: { path, key: 'pids.max', value: '2' } } });
    await finish(page, await fork(page, parent), parent.pid);
  } finally {
    if (parent) {
      await kc(page, 'process_call', { pid: parent.pid, call: { cgroup_attach: { pid: parent.pid, path: '/user' } } });
      await kc(page, 'process_call', { pid: parent.pid, call: { cgroup_remove: { path } } });
      await finish(page, parent);
    }
  }
});

test('exec and migration racing keep the final authorized membership', async ({ page }) => {
  await connect(page);
  const path = await make(page), destination = await make(page);
  let p;
  try {
    await limit(page, path, 1);
    await limit(page, destination, 1);
    p = await launch(page, path);
    for (let i = 0; i < 8; i++) {
      const target = i % 2 ? path : destination;
      await Promise.all([kv(page, 'reexec', { ...image, pid: p.pid }), kv(page, 'cgroup_attach', { pid: p.pid, path: target })]);
      expect((await stat(page, target))['cgroup.procs']).toContain(p.pid);
      expect((await stat(page, target === path ? destination : path))['pids.current']).toBe(0);
    }
  } finally {
    if (p) await finish(page, p);
    await remove(page, path);
    await remove(page, destination);
  }
});

test('client kernel enforces admission locally and allows new forks once capacity returns', async ({ page }) => {
  await connect(page);
  const path = await make(page);
  let parent;
  try {
    await limit(page, path, 1);
    parent = await kv(page, 'exec', { ...image, cgroup: path });
    for (let i = 0; i < 24; i++) expect((await kc(page, 'fork', { pid: parent.pid })).err?.errno).toBe('EAGAIN');
    expect((await stat(page, path))['pids.current']).toBe(1);
    await limit(page, path, 2);
    const child = await kv(page, 'fork', { pid: parent.pid });
    expect((await stat(page, path))['pids.current']).toBe(2);
    await kv(page, 'exit', { pid: child.pid, status: 0 });
    await kv(page, 'waitchild', { ppid: parent.pid, pid: child.pid });
    const replacement = await kv(page, 'fork', { pid: parent.pid });
    expect((await stat(page, path))['cgroup.procs']).toContain(replacement.pid);
    await kv(page, 'exit', { pid: replacement.pid, status: 0 });
    await kv(page, 'waitchild', { ppid: parent.pid, pid: replacement.pid });
  } finally {
    if (parent) await finish(page, parent);
    await remove(page, path);
  }
});

// Capture the page's real dedicated client-kernel Worker so E2E tests can inspect its local cgroups/procs.
async function hookPageKernel(page) {
  await page.addInitScript(() => {
    const NativeWorker = window.Worker;
    window.Worker = class extends NativeWorker {
      constructor(url, options) {
        super(url, options);
        if (new URL(url, location.href).pathname.endsWith('/client-kernel.js')) {
          const worker = this;
          const pending = new Map();
          let next = 900_000;
          worker.addEventListener('message', ({ data }) => {
            if (data?.id != null && pending.has(data.id)) {
              pending.get(data.id)(data);
              pending.delete(data.id);
            }
          });
          window.__pageKernel = (type, args = {}) => new Promise(resolve => {
            const id = ++next;
            pending.set(id, resolve);
            worker.postMessage({ v: 2, id, type, args });
          });
        }
      }
    };
  });
}
const pageKv = async (page, type, args = {}) => {
  const r = await page.evaluate(([type, args]) => window.__pageKernel(type, args), [type, args]);
  expect(r.err, `${type}: ${JSON.stringify(r)}`).toBeUndefined();
  return r.ok;
};

async function run(page, units) {
  await call(page.request, 'getcreds');
  await hookPageKernel(page);
  await page.goto('/');
  await page.waitForFunction(() => !!window.os?.exec && !!window.__pageKernel);
  await page.evaluate(() => window.os.loginSession());
  await pageKv(page, 'sync_account_from_server');
  const base = '/guest/pids-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  const file = base + '/units.json';
  expect((await put(page.request, '/api/file?path=' + file, { data: JSON.stringify({ version: 1, units }) })).ok()).toBe(true);
  await page.evaluate(file => {
    const r = window.pidRun = { output: '' };
    r.done = window.os.exec([{ path: '/usr/bin/supervise', argv: ['supervise', file] }], {
      tty: true, stdin: '', onJob: j => { r.job = j; }, onOutput: (_fd, s) => { r.output += s; },
    }).then(result => { r.result = result; }, e => { r.error = String(e); });
  }, file);
  return base;
}
async function complete(page, status) {
  await expect.poll(() => page.evaluate(() => window.pidRun.result?.status ?? window.pidRun.error), { timeout: 60000 }).toBe(status);
  return page.evaluate(() => window.pidRun.output);
}
async function cleanup(page, base) {
  await page.evaluate(async () => { window.pidRun?.job?.signal(9); await window.pidRun?.done; });
  await rmrf(page.request, base);
}

test('supervisor enforces zero before guest code and allows exec with a single PID slot', async ({ page }) => {
  let base = await run(page, [{ name: 'zero', argv: ['printf', 'UNEXPECTED_GUEST'], limits: { pids: 0 } }]);
  try { expect(await complete(page, 1)).not.toContain('UNEXPECTED_GUEST'); } finally { await cleanup(page, base); }
  base = await run(page, [{ name: 'one', argv: ['sh', '-c', 'exec printf SINGLE_PID_OK'], limits: { pids: 1 } }]);
  try { expect(await complete(page, 0)).toContain('SINGLE_PID_OK'); } finally { await cleanup(page, base); }
});

test('real WASIX fork returns EAGAIN before a denied child can execute', async ({ page }) => {
  await call(page.request, 'getcreds');
  const path = '/guest/pid-fork-' + crypto.randomUUID();
  const module = binaryen.parseText(`(module
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1) (data (i32.const 100) "FORK_DENIED_OK")
    (func (export "_start") (local $i i32)
      (loop $again
        (if (i32.ne (call $fork (i32.const 1) (i32.const 32)) (i32.const 6)) (then unreachable))
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br_if $again (i32.lt_u (local.get $i) (i32.const 16))))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 14))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  try { expect((await put(page.request, '/api/file?path=' + path, { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true); } finally { module.dispose(); }
  await call(page.request, { chmod: { path, mode: 0o755 } });
  const base = await run(page, [
    { name: 'forks', argv: [path], limits: { pids: 1 } },
    { name: 'independent', argv: ['printf', 'OTHER_SERVICE_OK'], limits: { pids: 1 } },
  ]);
  try {
    const output = await complete(page, 0);
    expect(output).toContain('FORK_DENIED_OK');
    expect(output).toContain('OTHER_SERVICE_OK');
  } finally {
    await cleanup(page, base);
    await call(page.request, { unlink: { path } });
  }
});

test('failed service image admission and retries leave no group capacity behind', async ({ page }) => {
  const base = await run(page, [{ name: 'bad', argv: ['/usr/bin/missing-pids-image'], limits: { pids: 1 }, restart: 'on-failure', max_restarts: 2, restart_delay_ms: 100 }]);
  try {
    expect((await complete(page, 1)).match(/start failed:/g)).toHaveLength(3);
    expect((await pageKv(page, 'cgroup_list', { path: '/user' })).filter(p => p.startsWith('/user/supervise-'))).toEqual([]);
  } finally { await cleanup(page, base); }
});

test('killing a parent prevents child execution, sends zero /api/sys fork RPCs, and releases all local rows', async ({ page }) => {
  await call(page.request, 'getcreds');
  await hookPageKernel(page);
  await page.goto('/');
  await page.waitForFunction(() => !!window.os?.exec && !!window.__pageKernel);
  await page.evaluate(() => window.os.loginSession());
  await pageKv(page, 'sync_account_from_server');
  const base = '/guest/late-fork-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
  const marker = base + '/unexpected';
  const forkRpcs = [];
  const watch = req => {
    if (req.method() === 'POST' && new URL(req.url()).pathname === '/api/sys' && (req.postData() ?? '').includes('"fork"')) {
      forkRpcs.push(req.postData());
    }
  };
  page.on('request', watch);
  try {
    await page.evaluate(({ marker }) => {
      const r = window.pidRun = { output: '' };
      r.done = window.os.exec([['sh', '-c', `echo READY; sleep 30 && touch ${marker}`]], {
        tty: true, stdin: '',
        onJob: j => { r.job = j; },
        onOutput: (_fd, text) => { r.output += text; },
      }).then(v => { r.result = v; });
    }, { marker });
    await expect.poll(() => page.evaluate(() => window.pidRun.output), { timeout: 15000 }).toContain('READY');
    await page.evaluate(() => window.pidRun.job.signal(9));
    await complete(page, 137);
    await expect.poll(async () => (await pageKv(page, 'poll', { pids: [] })).filter(p => p.pid !== 1).length, { timeout: 15000 }).toBe(0);
    expect(await errno(page.request, { stat: { path: marker } })).toBe('ENOENT');
    expect(forkRpcs).toEqual([]);
  } finally {
    page.off('request', watch);
    await cleanup(page, base);
  }
});

test('authorized invalid executable loading releases admitted service slots across retries', async ({ page }) => {
  await call(page.request, 'getcreds');
  const path = '/guest/invalid-pid-image-' + crypto.randomUUID();
  expect((await put(page.request, '/api/file?path=' + path, { data: 'not a WebAssembly module' })).ok()).toBe(true);
  await call(page.request, { chmod: { path, mode: 0o755 } });
  const base = await run(page, [
    { name: 'invalid', argv: [path], limits: { pids: 1 }, restart: 'on-failure', max_restarts: 2, restart_delay_ms: 100 },
    { name: 'healthy', argv: ['printf', 'HEALTHY_PID_SLOT'], limits: { pids: 1 } },
  ]);
  try {
    const output = await complete(page, 1);
    expect(output.match(/start failed:/g)).toHaveLength(3);
    expect(output).toContain('HEALTHY_PID_SLOT');
    expect((await pageKv(page, 'cgroup_list', { path: '/user' })).filter(p => p.startsWith('/user/supervise-'))).toEqual([]);
    expect((await pageKv(page, 'poll', { pids: [] })).some(p => p.path === path)).toBe(false);
  } finally {
    await cleanup(page, base);
    await call(page.request, { unlink: { path } });
  }
});
