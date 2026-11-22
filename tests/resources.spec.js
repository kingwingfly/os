import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, put, rmrf } from './sys.js';
import { pagePut, pageRmrf } from './ui.js';
import { connectKernel, hookPageKernel } from './service-auth.js';
import binaryen from 'binaryen';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const CLOUD_SCOPE = { cloud_fs: true, devices: [], containers: false, relay: false };
const PAGE = 65536;
const image = { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], runtime: 'resources-v1' };

async function freshKernel(page, name = '__resourcesKernel') {
  await page.goto('/login');
  const kernel = await connectKernel(page, { name });
  await kernel.value('machine_init_leave');
  return kernel;
}

const set = (kernel, path, key, value) => kernel.value('cgroup_set', { path, key, value: String(value) });
const stat = (kernel, path) => kernel.value('cgroup_stat', { path });
const launch = (kernel, path, extra = {}) => kernel.value('exec', { ...image, cgroup: path, ...extra });
const memory = (kernel, p, bytes) => kernel.call('reserve_memory', { pid: p.pid, bytes });

async function group(kernel) {
  const path = '/user/resources-' + crypto.randomUUID();
  await kernel.value('cgroup_create', { path });
  return path;
}

async function endProc(kernel, p, ppid = null) {
  if (!p) return;
  await kernel.call('exit', { pid: p.pid, status: 0 });
  if (ppid != null) await kernel.call('waitchild', { ppid, pid: p.pid });
  else await kernel.call('wait', { pid: p.pid });
}

async function remove(kernel, path) {
  const s = await kernel.call('cgroup_stat', { path });
  if (s.err) return;
  await kernel.call('cgroup_set', { path, key: 'cgroup.kill', value: '1' });
  for (const pid of s.ok['subtree.procs']) await kernel.call('wait', { pid });
  for (const child of s.ok.children) await remove(kernel, child);
  await kernel.call('cgroup_remove', { path });
}

async function fsRpc(request, credential, session, fsCall, instanceId) {
  const res = await request.post(origin + '/api/fs', {
    headers: { Origin: origin, 'X-OS-Instance': instanceId },
    data: { version: 2, credential, session, call: fsCall },
  });
  return { status: res.status(), ok: res.ok(), body: await res.json() };
}

test('linear-memory limits cover growth, fork, exec, migration, ancestors and exit', async ({ page }) => {
  const kernel = await freshKernel(page);
  const path = await group(kernel), outside = await group(kernel);
  let p, q;
  try {
    await kernel.value('cgroup_create', { path: path + '/nested' });
    await set(kernel, path, 'memory.max', 3 * PAGE);
    p = await launch(kernel, path + '/nested');
    expect((await memory(kernel, p, PAGE)).err).toBeUndefined();
    q = await kernel.value('fork', { pid: p.pid });
    expect((await stat(kernel, path))['memory.current']).toBe(2 * PAGE);
    expect((await memory(kernel, q, 2 * PAGE)).err).toBeUndefined();
    expect((await memory(kernel, p, 2 * PAGE)).err?.errno).toBe('EAGAIN');
    expect((await kernel.call('fork', { pid: p.pid })).err?.errno).toBe('EAGAIN');

    await set(kernel, path, 'memory.max', PAGE);
    await kernel.value('cgroup_attach', { pid: p.pid, path: path + '/nested' });
    await kernel.value('reexec', { ...image, pid: p.pid });
    // reexec replaces p's linear memory (resetting p's charge to 0 while q retains 2 * PAGE).
    expect((await stat(kernel, path))['memory.current']).toBe(2 * PAGE);
    expect((await memory(kernel, p, 0)).err).toBeUndefined();

    await kernel.value('cgroup_attach', { pid: q.pid, path: outside });
    expect((await stat(kernel, path))['memory.current']).toBe(0);
    expect((await kernel.call('cgroup_attach', { pid: q.pid, path })).err?.errno).toBe('EAGAIN');
    expect((await stat(kernel, outside))['memory.current']).toBe(2 * PAGE);

    await kernel.value('exit', { pid: q.pid, status: 0 });
    expect((await stat(kernel, outside))['memory.current']).toBe(0);
    expect((await stat(kernel, outside))['pids.current']).toBe(1);
    await kernel.value('waitchild', { ppid: p.pid, pid: q.pid });
    q = null;
  } finally {
    if (q) await endProc(kernel, q, p?.pid ?? null);
    if (p) await endProc(kernel, p);
    await remove(kernel, path);
    await remove(kernel, outside);
    await kernel.terminate();
  }
});

test('parallel reservations share one budget and legacy hosts cannot claim enforcement', async ({ page, request }) => {
  const kernel = await freshKernel(page);
  const stranger = await connectKernel(page, { name: '__resourcesStranger' });
  const path = await group(kernel), processes = [];
  try {
    await set(kernel, path, 'memory.max', 3 * PAGE);
    // Unowned host cannot reserve memory, and retired server /api/sys resource call fails closed.
    const retired = await request.post(origin + '/api/sys', {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: { calls: [{ resource: { memory: 0 } }] },
    });
    expect(retired.ok()).toBe(false);
    expect((await stranger.call('reserve_memory', { pid: 99999, bytes: 0 })).err?.errno).toBe('ESRCH');
    expect((await kernel.call('exec', { ...image, runtime: 'untracked', cgroup: path })).err?.errno).toBe('EOPNOTSUPP');

    for (let i = 0; i < 8; i++) processes.push(await launch(kernel, path));
    const answers = await Promise.all(processes.map(p => memory(kernel, p, PAGE)));
    expect(answers.filter(ans => !ans.err)).toHaveLength(3);
    expect(answers.filter(ans => ans.err).map(ans => ans.err.errno)).toEqual(Array(5).fill('EAGAIN'));
    expect((await stat(kernel, path))['memory.current']).toBe(3 * PAGE);

    for (const [key, value] of [['cpu.max', '1000 100000'], ['cpu.weight', '200'], ['cgroup.freeze', '1']]) {
      expect((await kernel.call('cgroup_set', { path, key, value })).err?.errno).toBe('EOPNOTSUPP');
    }
    expect((await stat(kernel, path))['resource.unsupported']).toEqual(['cpu.max', 'cpu.weight', 'cgroup.freeze']);
  } finally {
    for (const p of processes) await endProc(kernel, p);
    await remove(kernel, path);
    await stranger.terminate();
    await kernel.terminate();
  }
});

test('memoryless spawn does not copy the parent charge and a small service fits its own memory limit', async ({ page }) => {
  test.setTimeout(180000);
  const kernel = await freshKernel(page);
  const path = await group(kernel);
  let parent, child;
  let file, config;
  try {
    await set(kernel, path, 'memory.max', PAGE);
    parent = await launch(kernel, path);
    expect((await memory(kernel, parent, PAGE)).err).toBeUndefined();
    expect((await kernel.call('fork', { pid: parent.pid })).err?.errno).toBe('EAGAIN');
    child = await kernel.value('fork', { pid: parent.pid, emptyMemory: true });
    expect((await stat(kernel, path))['memory.current']).toBe(PAGE);
    await endProc(kernel, child, parent.pid);
    child = null;
    await endProc(kernel, parent);
    parent = null;
    await remove(kernel, path);
    await kernel.terminate();

    const pageKernel = await hookPageKernel(page);
    await page.goto('/?recovery=1');
    await page.waitForFunction(() => !!window.os?.exec);
    await pageKernel.ready();
    file = await wasm(page, `(module ${output} (memory (export "memory") 1) (data (i32.const 100) "UNIT_OK") (func (export "_start") ${say}))`);
    config = file + '.json';
    await pagePut(page, config, JSON.stringify({ version: 1, units: [{ name: 'small', argv: [file], limits: { memory: PAGE } }] }));
    const answer = await page.evaluate(cfg => window.os.exec([{ path: '/usr/bin/supervise', argv: ['supervise', cfg] }], { stdin: '' }), config);
    expect(answer.status, answer.stderr).toBe(0);
    expect(answer.stdout).toContain('UNIT_OK');
  } finally {
    if (file) await pageRmrf(page, file).catch(() => {});
    if (config) await pageRmrf(page, config).catch(() => {});
  }
});

test('storage I/O is paced across inline and ranged reads and denied writes never commit', async ({ page }) => {
  test.setTimeout(120000);
  const r = page.request;
  expect((await api(r, 'login', { headers: { Origin: origin, 'CF-Connecting-IP': 'res-io-' + crypto.randomUUID() }, data: { username: 'root', password: rootPassword } })).ok()).toBe(true);
  const kernel = await freshKernel(page);
  await kernel.value('cloud_sign_in', { cloudUser: 'root', cloudUid: 0, cloudGid: 0, cloudGroups: [0], scope: CLOUD_SCOPE });
  const instanceId = await kernel.value('instance_id');
  const path = await group(kernel);
  const file = '/guest/io-' + crypto.randomUUID();
  const outFile = file + '-out';
  let p, fsSession, readOpen, writeOpen;
  try {
    expect((await put(r, '/api/file?path=' + file, { data: 'x'.repeat(1000) })).ok()).toBe(true);
    p = await launch(kernel, path, { remote: true });
    expect(p.token).toMatch(/^[0-9a-f]{64}$/);
    await set(kernel, path, 'io.max', 'rbps=1000 wbps=0');

    const conn = await fsRpc(r, p.token, null, 'connect', instanceId);
    expect(conn.ok, JSON.stringify(conn)).toBe(true);
    fsSession = conn.body.session;
    const walked = await fsRpc(r, p.token, fsSession, { walk: { dir: conn.body.root, names: ['guest', file.split('/').pop()] } }, instanceId);
    expect(walked.ok, JSON.stringify(walked)).toBe(true);
    const guestHandle = walked.body.entries[0].handle;
    const fileHandle = walked.body.entries[1].handle;
    const opened = await fsRpc(r, p.token, fsSession, {
      open: {
        ticket: `io-read-${crypto.randomUUID()}`,
        handle: fileHandle,
        options: { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false },
      },
    }, instanceId);
    expect(opened.ok, JSON.stringify(opened)).toBe(true);
    readOpen = opened.body;

    const started = Date.now();
    // 1. /api/fs/data read of 100 bytes + 3 concurrent ranged /api/file reads of 200 bytes (700B total at 1000B/s -> >= 650ms).
    const dataRead = await r.post(origin + '/api/fs/data', {
      headers: {
        Origin: origin,
        'X-OS-Instance': instanceId,
        'X-OS-Filesystem': JSON.stringify({
          version: 2,
          credential: p.token,
          pid: p.pid,
          session: fsSession,
          open: readOpen,
          operation: { read: { offset: 0, length: 100 } },
        }),
      },
    });
    expect(dataRead.ok(), await dataRead.text()).toBe(true);
    expect(await dataRead.body()).toHaveLength(100);

    const headers = { 'X-Process-Token': p.token, 'X-OS-Instance': instanceId, Range: 'bytes=0-199' };
    const reads = await Promise.all(Array.from({ length: 3 }, () => r.get('/api/file?path=' + file, { headers })));
    for (const read of reads) {
      expect(read.status()).toBe(206);
      expect(await read.body()).toHaveLength(200);
    }
    expect(Date.now() - started).toBeGreaterThanOrEqual(650);

    // Missing X-OS-Instance header with a process token fails closed.
    const missingInst = await r.get('/api/file?path=' + file, { headers: { 'X-Process-Token': p.token, Range: 'bytes=0-1' } });
    expect(missingInst.ok()).toBe(false);

    // 2. Denied writes under wbps=0 fail with 429 / EAGAIN and never commit bytes.
    const created = await fsRpc(r, p.token, fsSession, {
      create: {
        ticket: `io-write-${crypto.randomUUID()}`,
        dir: guestHandle,
        name: outFile.split('/').pop(),
        mode: 0o600,
        umask: 0o022,
        options: { read: false, write: true, append: false, append_implies_write: false, truncate: false, create: true, create_new: true, exec: false, path: false },
      },
    }, instanceId);
    expect(created.ok, JSON.stringify(created)).toBe(true);
    writeOpen = created.body[1];

    const doWrite = () => r.post(origin + '/api/fs/data', {
      headers: {
        Origin: origin,
        'X-OS-Instance': instanceId,
        'X-OS-Filesystem': JSON.stringify({
          version: 2,
          credential: p.token,
          pid: p.pid,
          session: fsSession,
          open: writeOpen,
          operation: { write: { at: { offset: 0 }, length: 1 } },
        }),
      },
      data: 'x',
    });
    const deniedWrite = await doWrite();
    expect(deniedWrite.status()).toBe(429);
    expect(await (await r.get('/api/file?path=' + outFile)).body()).toHaveLength(0);

    // 3. Raising wbps=1000 lets the write succeed and commit cleanly.
    await set(kernel, path, 'io.max', 'rbps=max wbps=1000');
    const okWrite = await doWrite();
    expect(okWrite.ok(), await okWrite.text()).toBe(true);
    await fsRpc(r, p.token, fsSession, { release: { open: writeOpen } }, instanceId);
    writeOpen = null;
    expect(await (await r.get('/api/file?path=' + outFile)).text()).toBe('x');

    // 4. Invalid io.max syntax is rejected with EINVAL, and every explicit unlimited spelling restores reads.
    for (const value of ['garbage', 'rbps=-1', 'rbps=1 rbps=2', 'riops=1']) {
      expect((await kernel.call('cgroup_set', { path, key: 'io.max', value })).err?.errno).toBe('EINVAL');
    }
    for (const value of ['max', 'rbps=max wbps=max', 'wbps=max rbps=max']) {
      await set(kernel, path, 'io.max', value);
      const legacy = await r.get('/api/file?path=' + file, {
        headers: { 'X-Process-Token': p.token, 'X-OS-Instance': instanceId, Range: 'bytes=0-1' },
      });
      expect(legacy.status()).toBe(206);
      expect(await legacy.body()).toHaveLength(2);
    }
  } finally {
    if (writeOpen && fsSession && p) await fsRpc(r, p.token, fsSession, { release: { open: writeOpen } }, instanceId).catch(() => {});
    if (readOpen && fsSession && p) await fsRpc(r, p.token, fsSession, { release: { open: readOpen } }, instanceId).catch(() => {});
    if (fsSession && p) await fsRpc(r, p.token, fsSession, 'disconnect', instanceId).catch(() => {});
    if (p) await endProc(kernel, p);
    await remove(kernel, path);
    await kernel.terminate();
    await rmrf(r, file);
    await rmrf(r, outFile);
  }
});

async function wasm(page, wat) {
  const path = '/tmp/memory-' + crypto.randomUUID(), module = binaryen.parseText(wat);
  let bin;
  try { bin = Buffer.from(module.emitBinary()); }
  finally { module.dispose(); }
  await pagePut(page, path, bin, { mode: 0o755 });
  return path;
}
const output = `(import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))`;
const say = `(i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 7)) (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))`;

async function bootRecovery(page) {
  const pageKernel = await hookPageKernel(page);
  await page.goto('/?recovery=1');
  await page.waitForFunction(() => !!window.os?.exec);
  await pageKernel.ready();
  return pageKernel;
}

async function execute(page, path, cgroup) {
  return page.evaluate(async ({ path, cgroup }) => {
    let diagnostic = '';
    const result = await window.os.exec([{ path, argv: [path], cwd: '/', cgroup }], {
      stdin: '',
      onOutput: (_, s) => { diagnostic += s; },
    });
    return { ...result, diagnostic };
  }, { path, cgroup });
}

test('unchanged WASM memory.grow fails at its cgroup ceiling and initial allocation is admitted first', async ({ page }) => {
  test.setTimeout(180000);
  const pageKernel = await bootRecovery(page);
  const path = await group(pageKernel);
  const file = await wasm(page, `(module ${output} (memory (export "memory") 1 10) (data (i32.const 100) "GROW_OK")
    (func (export "_start")
      (if (i32.ne (memory.grow (i32.const 1)) (i32.const 1)) (then unreachable))
      (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1)) (then unreachable)) ${say}))`);
  try {
    await set(pageKernel, path, 'memory.max', 2 * PAGE);
    const answer = await execute(page, file, path);
    expect(answer.status, answer.diagnostic).toBe(0);
    expect(answer.stdout).toBe('GROW_OK');
    await expect.poll(async () => (await stat(pageKernel, path))['memory.current']).toBe(0);

    await set(pageKernel, path, 'memory.max', 0);
    const denied = await execute(page, file, path);
    expect(denied.status).not.toBe(0);
    expect(denied.stdout).toBe('');
    await expect.poll(async () => (await stat(pageKernel, path))['memory.current']).toBe(0);
  } finally {
    await remove(pageKernel, path);
    await pageRmrf(page, file).catch(() => {});
  }
});

test('fork reserves scratch and copied linear memories before starting the child', async ({ page }) => {
  test.setTimeout(180000);
  const pageKernel = await bootRecovery(page);
  const path = await group(pageKernel);
  const file = await wasm(page, `(module ${output}
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (memory (export "memory") 1) (data (i32.const 100) "FORK_OK")
    (func (export "_start")
      (if (i32.ne (call $fork (i32.const 1) (i32.const 32)) (i32.const 6)) (then unreachable)) ${say}))`);
  try {
    await set(pageKernel, path, 'memory.max', 5 * PAGE);
    const answer = await execute(page, file, path);
    expect(answer.status, answer.diagnostic).toBe(0);
    expect(answer.stdout).toBe('FORK_OK');
    await expect.poll(async () => (await stat(pageKernel, path))['memory.current']).toBe(0);
  } finally {
    await remove(pageKernel, path);
    await pageRmrf(page, file).catch(() => {});
  }
});

test('a child killed during its first memory reservation is reaped without a startup diagnostic', async ({ page }) => {
  const pageKernel = await bootRecovery(page);
  const path = await group(pageKernel);
  const file = await wasm(page, `(module ${output}
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_signal" (func $kill (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_join" (func $join (param i32 i32 i32) (result i32)))
    (memory (export "memory") 2)
    (global $__stack_pointer (export "__stack_pointer") (mut i32) (i32.const 60000))
    (data (i32.const 100) "REAP_OK")
    (func (export "_start")
      (if (call $fork (i32.const 1) (i32.const 32)) (then unreachable))
      (if (i32.eqz (i32.load (i32.const 32))) (then unreachable))
      (if (call $kill (i32.load (i32.const 32)) (i32.const 9)) (then unreachable))
      (i32.store8 (i32.const 40) (i32.const 1))
      (i32.store (i32.const 44) (i32.load (i32.const 32)))
      (if (call $join (i32.const 40) (i32.const 0) (i32.const 48)) (then unreachable))
      (if (i32.ne (i32.load8_u (i32.const 48)) (i32.const 2)) (then unreachable))
      (if (i32.ne (i32.load8_u (i32.const 52)) (i32.const 9)) (then unreachable)) ${say}))`);
  try {
    // 1. Deterministic kernel check: a SIGKILLed child's late memory reservation fails ESRCH with zero charge.
    const parent = await launch(pageKernel, path);
    try {
      const child = await pageKernel.value('fork', { pid: parent.pid, emptyMemory: true });
      await pageKernel.value('kill', { pid: child.pid, signal: 9 });
      expect((await memory(pageKernel, child, 2 * PAGE)).err?.errno).toBe('ESRCH');
      expect((await stat(pageKernel, path))['memory.current']).toBe(0);
      expect(await pageKernel.value('waitchild', { ppid: parent.pid, pid: child.pid })).toMatchObject({ pid: child.pid, signal: 9 });
    } finally {
      await endProc(pageKernel, parent);
    }

    // 2. Real WASIX fork + immediate SIGKILL + join settles cleanly with zero startup diagnostic and zero leaked memory.
    const answer = await execute(page, file, path);
    expect(answer.status, answer.diagnostic).toBe(0);
    expect(answer.stdout).toBe('REAP_OK');
    expect(answer.diagnostic).toBe('');
    await expect.poll(async () => (await stat(pageKernel, path))['memory.current']).toBe(0);
  } finally {
    await remove(pageKernel, path);
    await pageRmrf(page, file).catch(() => {});
  }
});

test('guest syscalls cannot forge runtime accounting or import its private callbacks', async ({ page }) => {
  test.setTimeout(180000);
  const pageKernel = await bootRecovery(page);
  const path = await group(pageKernel);
  const request = JSON.stringify([{ resource: { memory: 0 } }]);
  const data = Buffer.from(request).toString('hex').match(/../g).map(b => '\\' + b).join('');
  const file = await wasm(page, `(module ${output}
    (import "os" "sys" (func $sys (param i32 i32) (result i32)))
    (import "os" "reply" (func $reply (param i32)))
    (memory (export "memory") 1) (data (i32.const 100) "${data}")
    (func (export "_start") (local $n i32)
      (local.set $n (call $sys (i32.const 100) (i32.const ${request.length})))
      (call $reply (i32.const 500))
      (if (i32.ne (memory.grow (i32.const 1)) (i32.const -1)) (then unreachable))
      (i32.store (i32.const 0) (i32.const 500)) (i32.store (i32.const 4) (local.get $n))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  const forged = await wasm(page, `(module (import "os_runtime" "memory_grow_pre" (func (param i32 i32) (result i32))) (memory (export "memory") 1) (func (export "_start")))`);
  try {
    await set(pageKernel, path, 'memory.max', PAGE);
    const answer = await execute(page, file, path);
    expect(answer.status, answer.diagnostic).toBe(0);
    expect(answer.stdout).toMatch(/EPERM|EINVAL/);
    await expect(execute(page, forged, path)).rejects.toThrow(/unknown import/);
  } finally {
    await remove(pageKernel, path);
    await pageRmrf(page, file).catch(() => {});
    await pageRmrf(page, forged).catch(() => {});
  }
});
