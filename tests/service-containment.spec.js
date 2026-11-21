import { test, expect } from './test.js';
import { call, errno, put, rmrf } from './sys.js';
import { connectKernel, hookPageKernel } from './service-auth.js';
import binaryen from 'binaryen';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const image = { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [] };
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };

async function freshKernel(page, name = '__containKernel') {
  await page.goto('/login');
  const kernel = await connectKernel(page, { name });
  await kernel.value('machine_init_leave');
  return kernel;
}

async function kcall(kernel, type, args, denied) {
  const answer = await kernel.call(type, args);
  if (denied) {
    if (Array.isArray(denied)) expect(denied, JSON.stringify(answer)).toContain(answer.err?.errno);
    else expect(answer.err?.errno, JSON.stringify(answer)).toBe(denied);
    return;
  }
  expect(answer.err, JSON.stringify(answer)).toBeUndefined();
  return answer.ok;
}

const invoke = (kernel, p, command, denied) => kcall(kernel, 'process_call', { pid: p.pid, call: command }, denied);
const launch = (kernel, extra = {}) => kcall(kernel, 'exec', { ...image, ...extra });
const fork = (kernel, parent) => kcall(kernel, 'fork', { pid: parent.pid });

async function finish(kernel, p) {
  if (!p) return;
  await kernel.call('exit', { pid: p.pid, status: 0 });
  await kernel.call('wait', { pid: p.pid });
}

test('subreapers adopt nearest descendants, survive exec, and are not inherited by fork', async ({ page, request }) => {
  const kernel = await freshKernel(page);
  const root = await launch(kernel);
  try {
    // Unowned pid and retired server /api/sys prctl fail closed.
    await kcall(kernel, 'process_call', { pid: 99999, call: { prctl: { option: 36, value: 1 } } }, 'ESRCH');
    const serverPrctl = await request.post(origin + '/api/sys', {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: { calls: [{ prctl: { option: 36, value: 1 } }] },
    });
    expect((await serverPrctl.json()).results?.[0]?.err?.errno).toBe('ENOSYS');

    await invoke(kernel, root, { prctl: { option: 36, value: 1 } });
    const middle = await fork(kernel, root);
    expect(await invoke(kernel, middle, { prctl: { option: 37 } })).toBe(0);
    await invoke(kernel, middle, { prctl: { option: 36, value: 1 } });
    const parent = await fork(kernel, middle), leaf = await fork(kernel, parent);
    await kcall(kernel, 'reexec', { ...image, pid: root.pid });
    expect(await invoke(kernel, root, { prctl: { option: 37 } })).toBe(1);
    await invoke(kernel, root, { prctl: { option: 999 } }, 'EINVAL');
    await invoke(kernel, leaf, 'setsid');
    await kcall(kernel, 'exit', { pid: parent.pid, status: 0 });
    expect((await invoke(kernel, leaf, 'getpid')).ppid).toBe(middle.pid);
    await invoke(kernel, middle, { waitpid: { pid: parent.pid, options: 1 } });
    await kcall(kernel, 'exit', { pid: middle.pid, status: 0 });
    expect((await invoke(kernel, leaf, 'getpid')).ppid).toBe(root.pid);
    await kcall(kernel, 'exit', { pid: leaf.pid, status: 7 });
    expect((await invoke(kernel, root, { waitpid: { pid: leaf.pid, options: 1 } })).status).toBe(7 << 8);
    await invoke(kernel, root, { waitpid: { pid: middle.pid, options: 1 } });
  } finally {
    await finish(kernel, root);
    await kernel.terminate();
  }
});

test('recursive cgroup kill and owner death contain detached descendants without matching sibling prefixes', async ({ page }) => {
  const kernel = await freshKernel(page);
  const owner = await launch(kernel), path = '/user/bound-' + crypto.randomUUID();
  const sibling = path + '-other';
  try {
    await invoke(kernel, owner, { cgroup_create: { path, lifetime: 'process' } });
    await invoke(kernel, owner, { cgroup_create: { path: path + '/nested' } });
    await invoke(kernel, owner, { cgroup_create: { path: sibling } });
    const child = await fork(kernel, owner), other = await fork(kernel, owner);
    await invoke(kernel, owner, { cgroup_attach: { pid: child.pid, path: path + '/nested' } });
    await invoke(kernel, owner, { cgroup_attach: { pid: other.pid, path: sibling } });
    await invoke(kernel, child, 'setsid');
    await invoke(kernel, owner, { cgroup_set: { path, key: 'cgroup.kill', value: '0' } }, 'EINVAL');
    expect((await invoke(kernel, child, 'getpid')).pid).toBe(child.pid);
    await invoke(kernel, owner, { cgroup_set: { path, key: 'cgroup.kill', value: '1' } });
    expect((await invoke(kernel, owner, { waitpid: { pid: child.pid, options: 1 } })).signal).toBe(9);
    expect((await invoke(kernel, other, 'getpid')).pid).toBe(other.pid);

    const last = await fork(kernel, owner);
    await invoke(kernel, owner, { cgroup_attach: { pid: last.pid, path } });
    await kcall(kernel, 'kill', { pid: owner.pid, signal: 9 });
    await invoke(kernel, last, 'getpid', 'ESRCH');
    expect((await invoke(kernel, other, 'getpid')).pid).toBe(other.pid);
    // Reap the killed descendant (reparented to PID 1) so the retired cgroup prunes cleanly.
    await kcall(kernel, 'wait', { pid: last.pid });
    await kcall(kernel, 'cgroup_stat', { path }, 'ENOENT');
    await finish(kernel, other);
  } finally {
    await finish(kernel, owner);
    await kernel.call('cgroup_remove', { path: sibling });
    await kernel.terminate();
  }
});

test('process lifetime creation requires a real process and enforces bounded ownership', async ({ page, request }) => {
  const kernel = await freshKernel(page);
  const owner = await launch(kernel), basePath = '/user/budget-' + crypto.randomUUID();
  // Non-process / unowned pid cannot create a process-lifetime cgroup; server /api/sys fails closed.
  await kcall(kernel, 'process_call', { pid: 99999, call: { cgroup_create: { path: basePath, lifetime: 'process' } } }, 'ESRCH');
  const serverRes = await request.post(origin + '/api/sys', {
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    data: { calls: [{ cgroup_create: { path: basePath, lifetime: 'process' } }] },
  });
  expect((await serverRes.json()).results?.[0]?.err?.errno).toBe('ENOSYS');
  try {
    for (let i = 0; i < 32; i++) {
      await invoke(kernel, owner, { cgroup_create: { path: basePath + '-' + i, lifetime: 'process' } });
    }
    await invoke(kernel, owner, { cgroup_create: { path: basePath + '-excess', lifetime: 'process' } }, 'ENOSPC');
  } finally {
    await finish(kernel, owner);
  }
  const children = await kcall(kernel, 'cgroup_list', { path: '/user' });
  expect(children.filter(p => p.startsWith(basePath))).toEqual([]);
  await kernel.terminate();
});

test('retiring cgroups reject late attach exec and creation until their zombies are reaped', async ({ page }) => {
  const kernel = await freshKernel(page);
  const owner = await launch(kernel), parent = await launch(kernel), path = '/user/retired-' + crypto.randomUUID();
  try {
    await invoke(kernel, owner, { cgroup_create: { path, lifetime: 'process' } });
    const child = await fork(kernel, parent);
    await invoke(kernel, parent, { cgroup_attach: { pid: child.pid, path } });
    await kcall(kernel, 'kill', { pid: owner.pid, signal: 9 });
    const retiring = await kcall(kernel, 'cgroup_stat', { path });
    expect(retiring.retired === true || retiring.lifetime?.retiring === true).toBe(true);
    await invoke(kernel, parent, { cgroup_attach: { pid: parent.pid, path } }, ['ENOENT', 'ESTALE']);
    await kcall(kernel, 'exec', { ...image, cgroup: path }, ['ENOENT', 'ESTALE']);
    await invoke(kernel, parent, { cgroup_create: { path: path + '/late' } }, ['ENOENT', 'ESTALE']);
    expect((await invoke(kernel, parent, { waitpid: { pid: child.pid, options: 1 } })).signal).toBe(9);
    await kcall(kernel, 'cgroup_stat', { path }, 'ENOENT');
  } finally {
    await finish(kernel, owner);
    await finish(kernel, parent);
    await kernel.terminate();
  }
});

test('guest cannot kill a root cgroup through the registry route', async ({ page, request }) => {
  const kernel = await freshKernel(page);
  await kernel.value('sync_account', ROOT_ACCOUNT);
  const owner = await launch(kernel), path = '/user/root-' + crypto.randomUUID();
  try {
    await invoke(kernel, owner, { cgroup_create: { path, lifetime: 'process' } });
    const child = await fork(kernel, owner);
    await invoke(kernel, owner, { cgroup_attach: { pid: child.pid, path } });

    await kernel.value('sync_account', GUEST_ACCOUNT);
    // Guest cannot kill a root-owned cgroup, and retired X-Registry route fails closed (403).
    await kcall(kernel, 'cgroup_set', { path, key: 'cgroup.kill', value: '1' }, 'EACCES');
    const regResp = await request.post(origin + '/api/sys', {
      headers: { Origin: origin, 'Content-Type': 'application/json', 'X-Registry': '1' },
      data: { calls: [{ cgroup_set: { path, key: 'cgroup.kill', value: '1' } }] },
    });
    expect(regResp.status()).toBe(403);
    expect((await invoke(kernel, child, 'getpid')).pid).toBe(child.pid);

    // The running root owner retains its credentials and can still kill its own cgroup.
    await invoke(kernel, owner, { cgroup_set: { path, key: 'cgroup.kill', value: '1' } });
    expect((await invoke(kernel, owner, { waitpid: { pid: child.pid, options: 1 } })).signal).toBe(9);
  } finally {
    await kernel.value('sync_account', ROOT_ACCOUNT);
    await finish(kernel, owner);
    await kernel.terminate();
  }
});

let base, pageKernel;
async function setup(page) {
  await call(page.request, 'getcreds');
  pageKernel = await hookPageKernel(page);
  await page.goto('/');
  await page.waitForFunction(() => !!window.os?.exec);
  await pageKernel.ready();
  await pageKernel.value('sync_account_from_server');
  base = '/guest/contained-' + crypto.randomUUID();
  await call(page.request, { mkdir: { path: base, mode: 0o700 } });
}
async function start(page, units, { journal = false, shell = false, check = false } = {}) {
  const path = base + '/units.json';
  expect((await put(page.request, '/api/file?path=' + path + '&overwrite=true', { data: JSON.stringify({ version: 1, units }) })).ok()).toBe(true);
  await page.evaluate(({ path, journal, shell, check }) => {
    const run = window.contained = { output: '', lengths: [0, 0, 0] };
    const argv = ['supervise', ...(journal ? ['--journal', journal] : []), ...(check ? ['--check'] : []), path];
    const command = shell ? { path: '/usr/bin/sh', argv: ['sh', '-c', 'supervise "$1" & wait', 'sh', path] } : { path: '/usr/bin/supervise', argv };
    run.done = window.os.exec([command], {
      tty: true,
      stdin: '',
      onOutput: (fd, s) => { run.output = (run.output + s).slice(-262144); run.lengths[fd] += s.length; },
      onJob: j => { run.job = j; },
    }).then(r => { run.result = r; }, e => { run.error = String(e); });
  }, { path, journal: journal ? base + '/journal' : null, shell, check });
}
const output = page => page.evaluate(() => window.contained.output.replace(/\r\n/g, '\n'));
async function seen(page, text) {
  await page.waitForFunction(text => window.contained.output.includes(text) || window.contained.result || window.contained.error, text, { timeout: 60000 });
  expect(await output(page), await page.evaluate(() => JSON.stringify(window.contained.result ?? window.contained.error))).toContain(text);
}
async function done(page, status = 0) {
  await expect.poll(() => page.evaluate(() => window.contained.result?.status ?? window.contained.error), { timeout: 60000 }).toBe(status);
  return output(page);
}
async function cleanup(page) {
  await page.evaluate(async () => {
    window.contained?.job?.signal(9);
    await window.contained?.done;
    window.independent?.job?.signal(9);
    await window.independent?.done;
  });
  await call(page.request, { chmod: { path: base, mode: 0o700 } });
  if (await errno(page.request, { stat: { path: base + '/journal' } }) === null) {
    await call(page.request, { chmod: { path: base + '/journal', mode: 0o700 } });
  }
  await rmrf(page.request, base);
}
const unit = (name, argv, extra = {}) => ({ name, argv, ...extra });
async function daemon(page) {
  // A real double fork and setsid; the final child execs an ordinary sleep image.
  const module = binaryen.parseText(`(module
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32)))
    (import "os" "setsid" (func $setsid (result i32)))
    (import "wasix_32v1" "proc_id" (func $pid (param i32) (result i32)))
    (import "wasix_32v1" "proc_parent" (func $parent (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 100) "DETACHED_READY\\0a") (data (i32.const 200) "/usr/bin/sleep") (data (i32.const 230) "sleep\\0a60")
    (func (export "_start")
      (if (call $fork (i32.const 1) (i32.const 32)) (then unreachable))
      (if (i32.load (i32.const 32)) (then (call $exit (i32.const 0))))
      (if (i32.lt_s (call $setsid) (i32.const 1)) (then unreachable))
      (drop (call $pid (i32.const 40)))
      (if (call $fork (i32.const 1) (i32.const 36)) (then unreachable))
      (if (i32.load (i32.const 36)) (then (call $exit (i32.const 0))))
      (drop (call $pid (i32.const 44)))
      (block $adopted (loop $observe
        (drop (call $parent (i32.load (i32.const 44)) (i32.const 48)))
        (br_if $adopted (i32.and (i32.gt_u (i32.load (i32.const 48)) (i32.const 1))
          (i32.ne (i32.load (i32.const 48)) (i32.load (i32.const 40)))))
        (br $observe)))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 15))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))
      (call $exec (i32.const 200) (i32.const 14) (i32.const 230) (i32.const 8))))`);
  try { expect((await put(page.request, '/api/file?path=' + base + '/daemon', { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true); }
  finally { module.dispose(); }
  await call(page.request, { chmod: { path: base + '/daemon', mode: 0o755 } });
}
async function group() {
  const paths = await pageKernel.value('cgroup_list', { path: '/user' });
  const found = paths.find(p => p.startsWith('/user/supervise-'));
  expect(found).toBeTruthy();
  const st = await pageKernel.value('cgroup_stat', { path: found });
  const supervisorPid = st.lifetime?.pid ?? Number(found.split('/supervise-')[1].split('-')[0]);
  return { path: found, supervisorPid, ...st };
}

for (const stop of ['leader exit', 'TERM', 'supervisor KILL']) test(`double-forked setsid descendants are contained after ${stop}`, async ({ page }) => {
  await setup(page);
  try {
    await daemon(page);
    await page.evaluate(() => {
      const r = window.independent = {};
      r.done = window.os.exec([{ path: '/usr/bin/sleep', argv: ['sleep', '60'] }], { onJob: j => { r.job = j; } }).then(v => { r.result = v; });
    });
    await start(page, [unit('daemon', ['sh', '-c', `${base}/daemon; echo LEADER_READY; while [ ! -f '${base}/release' ]; do sleep 0.1; done`])], { shell: stop === 'supervisor KILL' });
    await seen(page, 'DETACHED_READY');
    await seen(page, 'LEADER_READY');
    const before = await group();
    const rows = await pageKernel.value('poll', { pids: before['subtree.procs'] });
    expect(rows.some(p => p.ppid === before.supervisorPid && p.sid !== rows.find(q => q.pid === q.pgid)?.sid)).toBe(true);
    if (stop === 'leader exit') expect((await put(page.request, '/api/file?path=' + base + '/release', { data: '' })).ok()).toBe(true);
    else await pageKernel.value('kill', { pid: before.supervisorPid, signal: stop === 'TERM' ? 15 : 9 });
    await done(page, stop === 'TERM' ? 143 : 0);
    await expect.poll(async () => (await pageKernel.call('cgroup_stat', { path: before.path })).err?.errno, { timeout: 15000 }).toBe('ENOENT');
    expect(await page.evaluate(() => window.independent.result)).toBeUndefined();
    expect((await pageKernel.value('poll', { pids: before['subtree.procs'] })).filter(p => p.state !== 'zombie')).toEqual([]);
  } finally {
    await cleanup(page);
  }
});

test('journals preserve distinct stdout stderr and lifecycle records with exact binary bytes', async ({ page }) => {
  await setup(page);
  try {
    await start(page, [unit('alpha', ['sh', '-c', "printf '\\360\\237\\246\\200\\000\\377'; printf error >&2"]), unit('beta', ['printf', 'BETA'])], { journal: true });
    const terminal = await done(page);
    expect(terminal).toContain('BETA');
    expect(terminal).toContain('error');
    for (const [i, name] of ['alpha', 'beta'].entries()) {
      const r = await page.request.get('/api/file?path=' + base + `/journal/${i}-${name}.jsonl`);
      expect(r.ok()).toBe(true);
      const records = (await r.text()).trim().split('\n').map(JSON.parse);
      expect(records[0]).toMatchObject({ format: 'os.service-journal', unit: name, dropped: 0, forwarding_dropped_bytes: [0, 0] });
      const bytes = stream => Buffer.concat(records.filter(r => r.stream === stream).map(r => Buffer.from(r.data, 'base64')));
      expect(bytes('stdout')).toEqual(name === 'alpha' ? Buffer.from([240, 159, 166, 128, 0, 255]) : Buffer.from('BETA'));
      expect(bytes('stderr').toString()).toBe(name === 'alpha' ? 'error' : '');
      expect(records.filter(r => r.stream === 'event').map(r => r.text).join('\n')).toContain('exited 0');
      expect(records.slice(1).map(r => r.sequence)).toEqual(records.slice(1).map((_, idx) => idx + 1));
    }
    expect((await call(page.request, { stat: { path: base + '/journal' } })).mode & 0o777).toBe(0o700);
  } finally {
    await cleanup(page);
  }
});

test('noisy journals rotate complete records and retain the final output within 64 KiB', async ({ page }) => {
  await setup(page);
  try {
    await start(page, [unit('noisy', ['sh', '-c', 'head -c 300000 /dev/zero; printf FINAL_STDOUT; printf FINAL_STDERR >&2'])], { journal: true });
    await done(page);
    const r = await page.request.get('/api/file?path=' + base + '/journal/0-noisy.jsonl');
    const bytes = await r.body();
    expect(bytes.length).toBeLessThanOrEqual(65536);
    const records = bytes.toString().trim().split('\n').map(JSON.parse);
    expect(records[0].dropped).toBeGreaterThan(0);
    for (const stream of ['stdout', 'stderr']) {
      expect(Buffer.concat(records.filter(r => r.stream === stream).map(r => Buffer.from(r.data, 'base64'))).toString()).toContain('FINAL_' + stream.toUpperCase());
    }
    // This ASCII/NUL burst may outrun live forwarding. Every missing byte must
    // be counted, including pending output discarded at supervisor exit.
    expect(await page.evaluate(() => window.contained.lengths[1]) + records[0].forwarding_dropped_bytes[0]).toBe(300012);
    expect(records.slice(1).every((r, i, a) => i === 0 || r.sequence === a[i - 1].sequence + 1)).toBe(true);
  } finally {
    await cleanup(page);
  }
});

for (const reader of ['blocked', 'closed']) for (const blocked of ['stdout', 'stderr']) test(`a ${reader} ${blocked} reader cannot delay readiness or shutdown escalation`, async ({ page }) => {
  test.setTimeout(90000);
  await setup(page);
  try {
    const path = base + '/units.json', journal = base + '/journal';
    const units = [
      unit('noisy', ['sh', '-c', `trap '' TERM; yes${blocked === 'stderr' ? ' >&2' : ''}`], { stop_timeout_ms: 100 }),
      unit('silent', ['sh', '-c', "trap '' TERM; while :; do sleep 1; done"], { readiness: 'notify', startup_timeout_ms: 3000, stop_timeout_ms: 100 }),
    ];
    expect((await put(page.request, '/api/file?path=' + path, { data: JSON.stringify({ version: 1, units }) })).ok()).toBe(true);
    await page.evaluate(({ path, journal, blocked, reader }) => {
      const run = window.contained = { output: '' };
      run.done = window.os.exec([{ path: '/usr/bin/sh', argv: ['sh', '-c', `(supervise --journal "$1" "$2"${blocked === 'stderr' ? ' 2>&1' : ''}; printf '%s' "$?" > "$3") | ${reader === 'closed' ? 'head -c 1' : 'sleep 60'}`, 'sh', journal, path, path + '.status'] }], {
        tty: true,
        stdin: '',
        onOutput: (_, s) => { run.output = (run.output + s).slice(-262144); },
        onJob: j => { run.job = j; },
      }).then(r => { run.result = r; }, e => { run.error = String(e); });
    }, { path, journal, blocked, reader });
    const records = async name => {
      const response = await page.request.get('/api/file?path=' + encodeURIComponent(journal + '/' + name));
      return response.ok() ? (await response.text()).trim().split('\n').map(JSON.parse) : [];
    };
    const events = async name => (await records(name)).map(r => r.text ?? '').join('\n');
    await expect.poll(() => events('1-silent.jsonl'), { timeout: 30000 }).toContain('startup deadline exceeded');
    await expect.poll(() => events('1-silent.jsonl'), { timeout: 15000 }).toContain('signal 9');
    const groups = (await pageKernel.value('cgroup_list', { path: '/user' })).filter(p => p.startsWith('/user/supervise-'));
    expect(groups.length).toBeGreaterThan(0);
    const pid = Number(groups[0].split('/supervise-')[1].split('-')[0]);
    await pageKernel.value('kill', { pid, signal: 15 });
    // Draining the remaining noisy pipe can rotate lifecycle records out of its
    // bounded journal. Observe the supervisor's exit and containment directly.
    await expect.poll(async () => {
      const response = await page.request.get('/api/file?path=' + encodeURIComponent(path + '.status'));
      return response.ok() ? response.text() : '';
    }, { timeout: 15000 }).toBe('143');
    await expect.poll(async () => (await pageKernel.value('cgroup_list', { path: '/user' })).filter(p => p.startsWith('/user/supervise-')), { timeout: 15000 }).toEqual([]);
    expect((await records('0-noisy.jsonl'))[0].forwarding_dropped_bytes[blocked === 'stdout' ? 0 : 1]).toBeGreaterThan(0);
  } finally {
    await cleanup(page);
  }
});

test('supervision never changes the parent shell output flags, including after SIGKILL', async ({ page }) => {
  await setup(page);
  const module = binaryen.parseText(`(module
    (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 1)
    (func (export "_start")
      (if (call $stat (i32.const 1) (i32.const 0)) (then unreachable))
      (if (i32.and (i32.load16_u (i32.const 2)) (i32.const 4)) (then (call $exit (i32.const 1))))
      (if (call $stat (i32.const 2) (i32.const 0)) (then unreachable))
      (if (i32.and (i32.load16_u (i32.const 2)) (i32.const 4)) (then (call $exit (i32.const 2))))))`);
  try {
    const checker = base + '/flags', path = base + '/units.json', journal = base + '/journal';
    expect((await put(page.request, '/api/file?path=' + checker, { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true);
    await call(page.request, { chmod: { path: checker, mode: 0o755 } });
    expect((await put(page.request, '/api/file?path=' + path, { data: JSON.stringify({ version: 1, units: [unit('idle', ['sleep', '60'])] }) })).ok()).toBe(true);
    await page.evaluate(({ checker, path, journal }) => {
      const run = window.contained = { output: '' };
      run.done = window.os.exec([{ path: '/usr/bin/sh', argv: ['sh', '-c', 'supervise --journal "$1" "$2" & pid=$!; while [ ! -f "$1/0-idle.jsonl" ]; do sleep 0.1; done; "$3"; before=$?; kill -KILL "$pid"; wait "$pid"; "$3"; after=$?; test "$before" -eq 0 && test "$after" -eq 0', 'sh', journal, path, checker] }], {
        tty: true,
        stdin: '',
        onOutput: (_, s) => { run.output = (run.output + s).slice(-262144); },
        onJob: j => { run.job = j; },
      }).then(r => { run.result = r; }, e => { run.error = String(e); });
    }, { checker, path, journal });
    await done(page);
  } finally {
    module.dispose();
    await cleanup(page);
  }
});

test('pipe flags share across dup and fork, reopen independently, and support nonblocking writes', async ({ page }) => {
  await setup(page);
  const module = binaryen.parseText(`(module
    (import "wasix_32v1" "fd_pipe" (func $pipe (param i32 i32) (result i32)))
    (import "wasix_32v1" "fd_dup2" (func $dup (param i32 i32) (result i32)))
    (import "wasix_32v1" "proc_fork" (func $fork (param i32 i32) (result i32)))
    (import "os" "waitpid2" (func $wait (param i32 i32 i32) (result i32)))
    (import "os" "open" (func $open (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_set_flags" (func $flags (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_fdstat_get" (func $stat (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 2)
    (data (i32.const 200) "/proc/self/fd/50")
    (func $ok (param $e i32) (if (local.get $e) (then unreachable)))
    (func $equal (param $a i32) (param $b i32) (if (i32.ne (local.get $a) (local.get $b)) (then unreachable)))
    (func (export "_start")
      (call $ok (call $pipe (i32.const 32) (i32.const 36)))
      (call $ok (call $flags (i32.load (i32.const 32)) (i32.const 4)))
      (call $ok (call $flags (i32.load (i32.const 36)) (i32.const 4)))
      (i32.store (i32.const 0) (i32.const 1024)) (i32.store (i32.const 4) (i32.const 65536))
      (call $equal (call $read (i32.load (i32.const 32)) (i32.const 0) (i32.const 1) (i32.const 8)) (i32.const 6))
      (call $ok (call $write (i32.load (i32.const 36)) (i32.const 0) (i32.const 1) (i32.const 8)))
      (call $equal (i32.load (i32.const 8)) (i32.const 65536))
      (i32.store (i32.const 4) (i32.const 4096))
      (call $equal (call $write (i32.load (i32.const 36)) (i32.const 0) (i32.const 1) (i32.const 8)) (i32.const 6))
      (i32.store (i32.const 4) (i32.const 2048))
      (call $ok (call $read (i32.load (i32.const 32)) (i32.const 0) (i32.const 1) (i32.const 8)))
      (i32.store (i32.const 4) (i32.const 4096))
      (call $equal (call $write (i32.load (i32.const 36)) (i32.const 0) (i32.const 1) (i32.const 8)) (i32.const 6))
      (i32.store (i32.const 16) (i32.const 1024)) (i32.store (i32.const 20) (i32.const 1024))
      (i32.store (i32.const 24) (i32.const 1024)) (i32.store (i32.const 28) (i32.const 2048))
      (call $equal (call $write (i32.load (i32.const 36)) (i32.const 16) (i32.const 2) (i32.const 8)) (i32.const 6))
      (i32.store (i32.const 4) (i32.const 8192))
      (call $ok (call $write (i32.load (i32.const 36)) (i32.const 0) (i32.const 1) (i32.const 8)))
      (call $equal (i32.load (i32.const 8)) (i32.const 2048))
      (i32.store (i32.const 4) (i32.const 4096))
      (call $ok (call $read (i32.load (i32.const 32)) (i32.const 0) (i32.const 1) (i32.const 8)))
      (i32.store (i32.const 16) (i32.const 1024)) (i32.store (i32.const 20) (i32.const 4096))
      (i32.store (i32.const 24) (i32.const 1024)) (i32.store (i32.const 28) (i32.const 4096))
      (call $ok (call $write (i32.load (i32.const 36)) (i32.const 16) (i32.const 2) (i32.const 8)))
      (call $equal (i32.load (i32.const 8)) (i32.const 4096))
      (call $ok (call $dup (i32.load (i32.const 36)) (i32.const 50)))
      (call $ok (call $stat (i32.const 50) (i32.const 64)))
      (call $equal (i32.load16_u (i32.const 66)) (i32.const 4))
      (call $ok (call $fork (i32.const 1) (i32.const 40)))
      (if (i32.eqz (i32.load (i32.const 40))) (then
        (call $ok (call $flags (i32.const 50) (i32.const 0))) (call $exit (i32.const 0))))
      (call $equal (call $wait (i32.load (i32.const 40)) (i32.const 44) (i32.const 0)) (i32.load (i32.const 40)))
      (call $equal (i32.load (i32.const 44)) (i32.const 0))
      (call $ok (call $stat (i32.load (i32.const 36)) (i32.const 64)))
      (call $equal (i32.load16_u (i32.const 66)) (i32.const 0))
      (i32.store (i32.const 44) (call $open (i32.const 200) (i32.const 16) (i32.const 2049) (i32.const 0)))
      (if (i32.lt_s (i32.load (i32.const 44)) (i32.const 0)) (then unreachable))
      (call $ok (call $stat (i32.load (i32.const 44)) (i32.const 64)))
      (call $equal (i32.load16_u (i32.const 66)) (i32.const 4))
      (call $ok (call $stat (i32.const 50) (i32.const 64)))
      (call $equal (i32.load16_u (i32.const 66)) (i32.const 0))
      (call $equal (call $write (i32.load (i32.const 44)) (i32.const 0) (i32.const 1) (i32.const 8)) (i32.const 6))))`);
  try {
    const path = base + '/nonblocking.wasm';
    expect((await put(page.request, '/api/file?path=' + path, { data: module.emitBinary() })).ok()).toBe(true);
    await call(page.request, { chmod: { path, mode: 0o755 } });
    const result = await page.evaluate(path => window.os.exec([{ path, argv: [path] }], { stdin: '' }), path);
    expect(result.status, JSON.stringify(result)).toBe(0);
  } finally {
    module.dispose();
    await cleanup(page);
  }
});

test('an existing journal directory is rejected before a service starts', async ({ page }) => {
  await setup(page);
  try {
    await call(page.request, { mkdir: { path: base + '/journal', mode: 0o700 } });
    expect((await put(page.request, '/api/file?path=' + base + '/journal/keep', { data: 'KEEP' })).ok()).toBe(true);
    await start(page, [unit('blocked', ['touch', base + '/unexpected'])], { journal: true });
    await done(page, 1);
    expect(await errno(page.request, { stat: { path: base + '/unexpected' } })).toBe('ENOENT');
    expect(await (await page.request.get('/api/file?path=' + base + '/journal/keep')).text()).toBe('KEEP');
  } finally {
    await cleanup(page);
  }
});

test('journal attempts remain isolated and old descendant groups are removed before retry', async ({ page }) => {
  await setup(page);
  try {
    await daemon(page);
    await start(page, [unit('retry', ['sh', '-c', `${base}/daemon; sleep 0.2; if [ ! -f '${base}/tried' ]; then touch '${base}/tried'; exit 1; fi; printf RETRY_DONE`], { restart: 'on-failure', max_restarts: 1, restart_delay_ms: 100 })], { journal: true });
    await done(page);
    const records = (await (await page.request.get('/api/file?path=' + base + '/journal/0-retry.jsonl')).text()).trim().split('\n').map(JSON.parse);
    expect(records.filter(r => r.text?.startsWith('started pid ')).map(r => r.attempt)).toEqual([1, 2]);
    expect(records.filter(r => r.text?.startsWith('exited ')).map(r => r.text)).toEqual(['exited 1', 'exited 0']);
    expect((await pageKernel.value('cgroup_list', { path: '/user' })).filter(p => p.startsWith('/user/supervise-'))).toEqual([]);
  } finally {
    await cleanup(page);
  }
});

test('check-only validates without creating its requested journal directory', async ({ page }) => {
  await setup(page);
  try {
    await start(page, [unit('check', ['touch', base + '/unexpected'])], { journal: true, check: true });
    await done(page);
    for (const path of [base + '/journal', base + '/unexpected']) {
      expect(await errno(page.request, { stat: { path } })).toBe('ENOENT');
    }
  } finally {
    await cleanup(page);
  }
});

test('a journal storage failure stops its services and preserves the last published snapshot', async ({ page }) => {
  await setup(page);
  try {
    await start(page, [unit('writer', ['sh', '-c', 'while :; do echo JOURNAL_TICK; sleep 0.1; done'])], { journal: true });
    const path = base + '/journal/0-writer.jsonl';
    await expect.poll(() => errno(page.request, { stat: { path } }), { timeout: 30000 }).toBe(null);
    await call(page.request, { chmod: { path: base + '/journal', mode: 0o500 } });
    const before = await (await page.request.get('/api/file?path=' + path)).text();
    await done(page, 1);
    expect(await (await page.request.get('/api/file?path=' + path)).text()).toBe(before);
    await expect.poll(async () => (await pageKernel.value('cgroup_list', { path: '/user' })).filter(p => p.startsWith('/user/supervise-')), { timeout: 15000 }).toEqual([]);
  } finally {
    await cleanup(page);
  }
});

test('account reset retires process-owned cgroups without leaving lifetime records', async ({ page }) => {
  const kernel = await freshKernel(page);
  try {
    await kernel.value('sync_account', ROOT_ACCOUNT);
    const owner = await launch(kernel), path = '/user/reset-' + crypto.randomUUID();
    await invoke(kernel, owner, { cgroup_create: { path, lifetime: 'process' } });
    const before = await kernel.value('machine_init_action', { action: { op: 'inspect' } });
    await kernel.value('machine_init_action', { action: { op: 'reboot', boot: before.boot } });
    // Reboot signals the owner; once owner exits and is reaped, its process-owned cgroup is retired and pruned.
    expect((await kernel.value('sync')).find(row => row.pid === owner.pid)?.pending_signals?.map(s => s.signal)).toContain(15);
    await finish(kernel, owner);
    await kcall(kernel, 'cgroup_stat', { path }, 'ENOENT');
  } finally {
    await kernel.terminate();
  }
});

test('spawn rejects unowned descriptors and cgroups before execution and ignores forged descriptor tables', async ({ page }) => {
  await setup(page);
  const encode = value => [...Buffer.from(JSON.stringify(value))].map(b => '\\' + b.toString(16).padStart(2, '0')).join('');
  const common = { argv: ['/usr/bin/touch', base + '/unexpected'], cwd: '/', env: [], stdin: 'inherit' };
  const requests = [{ ...common, dup2: [[65535, 1]] }, { ...common, cgroup: '/system' },
    { ...common, argv: ['/usr/bin/printf', 'CHILD_STDIO'], fds: [], descriptions: [] }];
  const module = binaryen.parseText(`(module
    (import "os" "posix_spawn" (func $spawn (param i32 i32 i32) (result i32)))
    (import "os" "waitpid" (func $wait (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    ${requests.map((r, i) => `(data (i32.const ${1024 + i * 4096}) "${encode(r)}")`).join('\n')}
    (data (i32.const 100) "PARENT_STDIO")
    (func $assert (param i32) (if (i32.eqz (local.get 0)) (then unreachable)))
    (func (export "_start")
      (call $assert (i32.eq (call $spawn (i32.const 1024) (i32.const ${Buffer.byteLength(JSON.stringify(requests[0]))}) (i32.const 64)) (i32.const 8)))
      (call $assert (i32.eq (call $spawn (i32.const 5120) (i32.const ${Buffer.byteLength(JSON.stringify(requests[1]))}) (i32.const 64)) (i32.const 2)))
      (call $assert (i32.eqz (call $spawn (i32.const 9216) (i32.const ${Buffer.byteLength(JSON.stringify(requests[2]))}) (i32.const 64))))
      (call $assert (i32.eqz (call $wait (i32.load (i32.const 64)) (i32.const 68))))
      (call $assert (i32.eqz (i32.load (i32.const 68))))
      (i32.store (i32.const 0) (i32.const 100)) (i32.store (i32.const 4) (i32.const 12))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  try {
    const path = base + '/spawn-probe';
    expect((await put(page.request, '/api/file?path=' + path, { data: Buffer.from(module.emitBinary()) })).ok()).toBe(true);
    await call(page.request, { chmod: { path, mode: 0o755 } });
    await page.evaluate(path => {
      const run = window.contained = { output: '' };
      run.done = window.os.exec([{ path, argv: [path] }], { tty: true, stdin: '', onOutput: (_fd, s) => { run.output += s; }, onJob: j => { run.job = j; } })
        .then(r => { run.result = r; }, e => { run.error = String(e); });
    }, path);
    const out = await done(page);
    expect(out).toBe('CHILD_STDIOPARENT_STDIO');
    expect(await errno(page.request, { stat: { path: base + '/unexpected' } })).toBe('ENOENT');
  } finally {
    module.dispose();
    await cleanup(page);
  }
});
