import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { api } from './sys.js';

const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const executable = { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'], env: [], cwd: '/' };
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
async function batch(request, calls, options = {}) {
  calls = calls.map(call => call.kill ? { kill: { ...call.kill, pid: String(call.kill.pid) } } : call.wait ? { wait: { ...call.wait, pid: String(call.wait.pid) } } : call);
  const response = await request.post('/api/sys', { headers: { 'X-Registry': '1', Origin: origin }, data: { calls, ...options } });
  expect(response.ok(), String(response.status())).toBe(true);
  return (await response.json()).results;
}
const one = async (request, call, options) => (await batch(request, [call], options))[0];

test('terminal descriptor reports need the live process proof and cannot cross namespaces', async ({ browser }) => {
  const owner = await browser.newContext(), other = await browser.newContext();
  try {
    await owner.request.get('/'); await other.request.get('/');
    const { ok: process } = await one(owner.request, { execve: executable });
    const report = { pid: process.pid, proc: process.token, tty: process.pid, fds: [0, 1, 2] };
    expect(await one(owner.request, { proc_tty: { ...report, proc: 'wrong' } })).toHaveProperty('err.errno', 'ESRCH');
    expect(await one(other.request, { proc_tty: report })).toHaveProperty('err.errno', 'ESRCH');
    expect(await one(owner.request, { proc_tty: report })).toHaveProperty('ok');
    const response = await owner.request.post('/api/sys', { headers: { Origin: origin }, data: { calls: [{ readlink: { path: `/proc/${process.pid}/fd/0` } }] } });
    expect((await response.json()).results[0].ok).toBe(`/dev/pts/${process.pid}`);
    await one(owner.request, { kill: { pid: process.pid, signal: 9 } });
    expect(await one(owner.request, { proc_tty: report })).toHaveProperty('err.errno', 'ESRCH');
    await one(owner.request, { wait: { pid: process.pid } });
  } finally { await owner.close(); await other.close(); }
});

test('exec checks cgroup ownership against its verified credentials', async ({ context }) => {
  const request = context.request;
  await request.get('/');
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': `placement-${Date.now()}` }, data: { password } })).ok()).toBe(true);
  expect(await one(request, { cgroup_create: { path: '/user/root-owned' } })).toHaveProperty('ok');
  expect((await api(request, 'logout')).ok()).toBe(true);
  for (const cgroup of ['/system', '/user/root-owned']) {
    expect((await one(request, { execve: { ...executable, cgroup } })).err?.errno).toBe('EACCES');
  }
  expect(await one(request, { cgroup_create: { path: '/user/owned' } })).toHaveProperty('ok');
  const { ok: process } = await one(request, { execve: { ...executable, cgroup: '/user/owned', seat: 'placement-probe' } });
  expect(process.cgroup).toBe('/user/owned');
  expect(process.placement.cgroup).toBe('/user/owned');
  const replaced = await one(request, { execve: { ...executable, pid: process.pid, proc: process.token } });
  expect(replaced.err).toBeUndefined();
  expect(replaced.ok.placement).toEqual(process.placement);
  await one(request, { kill: { pid: process.pid, signal: 9 } });
  await one(request, { wait: { pid: process.pid } });
});

test('concurrent exec and direct fork cannot exceed the namespace process limit', async ({ context }) => {
  const request = context.request;
  await request.get('/');
  const results = await batch(request, Array.from({ length: 62 }, () => ({ execve: executable })));
  expect(results.every(result => result.ok)).toBe(true);
  const parent = results[0].ok;
  try {
    for (let attempt = 0; attempt < 16; attempt++) {
      const answers = await Promise.all([
        one(request, { execve: executable }),
        one(request, { fork: { pid: parent.pid } }, { pid: parent.pid, proc: parent.token }),
      ]);
      const { ok: rows } = await one(request, { proc_poll: { pids: [] } });
      expect(rows.filter(row => row.state !== 'zombie')).toHaveLength(64);
      expect(answers.filter(answer => answer.err?.errno === 'EAGAIN')).toHaveLength(1);
      for (const answer of answers) if (answer.ok) {
        await one(request, { kill: { pid: answer.ok.pid, signal: 9 } });
        await one(request, { wait: { pid: answer.ok.pid } });
      }
    }
  } finally {
    await batch(request, results.map(({ ok }) => ({ kill: { pid: ok.pid, signal: 9 } })));
    await batch(request, results.map(({ ok }) => ({ wait: { pid: ok.pid } })));
  }
});

test('lease reconciliation accepts only the owning token, including after logout', async ({ context }) => {
  const request = context.request;
  await request.get('/');
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': `lease-${Date.now()}` }, data: { password } })).ok()).toBe(true);
  const { ok: process } = await one(request, { execve: executable });
  expect((await api(request, 'logout')).ok()).toBe(true);
  expect((await one(request, { proc_keep: { processes: [{ pid: process.pid, proc: 'wrong' }] } })).ok).toEqual([]);
  const keep = { proc_keep: { processes: [{ pid: process.pid, proc: process.token }] } };
  expect((await one(request, keep)).ok[0]).toMatchObject({ pid: process.pid, uid: 0, state: 'running' });
  await one(request, { exit: { status: 0 } }, { pid: process.pid, proc: process.token });
  expect((await one(request, keep)).ok[0].state).toBe('zombie');
  await one(request, { wait: { pid: process.pid, proc: process.token } });
});
