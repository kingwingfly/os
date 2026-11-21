import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { api, call } from './sys.js';
import { attachInstance, connectKernel, serviceAuth } from './service-auth.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const executable = { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'], env: [], cwd: '/' };
const ROOT_ACCOUNT = { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true };
const GUEST_ACCOUNT = { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', home: '/tmp', shell: '/usr/bin/dash', signed_in: false };
const OS_FD_ROOT = 0x7ffffffd;

async function freshKernel(page, name = '__readinessKernel') {
  const kernel = await connectKernel(page, { name });
  await kernel.value('machine_init_leave');
  return kernel;
}

function decodeBytes(raw) {
  if (typeof raw === 'string') return raw;
  const arr = Array.isArray(raw) ? raw : Object.values(raw ?? {});
  return Buffer.from(arr).toString('utf8');
}

test('terminal descriptor reports need the live process proof and cannot cross namespaces', async ({ browser }) => {
  const owner = await browser.newContext(), other = await browser.newContext();
  try {
    const ownerPage = await owner.newPage(), otherPage = await other.newPage();
    await ownerPage.goto('/login');
    await otherPage.goto('/login');
    const kOwner = await freshKernel(ownerPage, '__ownerTtyKernel');
    const kStranger = await freshKernel(ownerPage, '__strangerTtyKernel');
    const kOther = await freshKernel(otherPage, '__otherTtyKernel');
    try {
      const proc = await kOwner.value('exec', executable);
      const report = { pid: proc.pid, tty: proc.pid, fds: [0, 1, 2] };
      // Neither another local kernel instance nor another browser context may report tty fds for `proc`.
      expect((await kStranger.call('tty_fds', report)).err?.errno).toBe('ESRCH');
      expect((await kOther.call('tty_fds', report)).err?.errno).toBe('ESRCH');
      expect((await kOwner.call('tty_fds', report)).err).toBeUndefined();

      // Local /proc/<pid>/stat reflects the recorded controlling terminal number (field 7).
      const opened = await kOwner.value('proc_openat', {
        pid: proc.pid,
        dirfd: OS_FD_ROOT,
        path: `/proc/${proc.pid}/stat`,
        oflags: 0,
        mode: 0,
        cloexec: false,
      });
      try {
        const raw = await kOwner.value('kfd_read', { pid: proc.pid, kfd: opened.kfd, len: 1024 });
        const statText = decodeBytes(raw);
        const afterComm = statText.slice(statText.lastIndexOf(') ') + 2).trim().split(/\s+/);
        expect(afterComm[4]).toBe(String(proc.pid));
      } finally {
        await kOwner.value('kfd_close', { pid: proc.pid, kfd: opened.kfd });
      }

      await kOwner.value('kill', { pid: proc.pid, signal: 9 });
      expect((await kOwner.call('tty_fds', report)).err?.errno).toBe('ESRCH');
      await kOwner.value('wait', { pid: proc.pid });
    } finally {
      await kOther.terminate();
      await kStranger.terminate();
      await kOwner.terminate();
    }
  } finally {
    await owner.close();
    await other.close();
  }
});

test('exec checks cgroup ownership against its verified credentials', async ({ page }) => {
  await page.goto('/login');
  const kernel = await freshKernel(page);
  let proc;
  try {
    await kernel.value('sync_account', ROOT_ACCOUNT);
    await kernel.value('cgroup_create', { path: '/user/root-owned' });
    await kernel.value('sync_account', GUEST_ACCOUNT);
    for (const cgroup of ['/system', '/user/root-owned']) {
      expect((await kernel.call('exec', { ...executable, cgroup })).err?.errno).toBe('EACCES');
    }
    await kernel.value('cgroup_create', { path: '/user/owned' });
    proc = await kernel.value('exec', { ...executable, cgroup: '/user/owned' });
    expect(proc.cgroup).toBe('/user/owned');
    expect(proc.placement.cgroup).toBe('/user/owned');
    const replaced = await kernel.value('reexec', { ...executable, pid: proc.pid });
    expect(replaced.placement).toEqual(proc.placement);
    await kernel.value('kill', { pid: proc.pid, signal: 9 });
    await kernel.value('wait', { pid: proc.pid });
    proc = null;
  } finally {
    if (proc) {
      await kernel.call('kill', { pid: proc.pid, signal: 9 });
      await kernel.call('wait', { pid: proc.pid });
    }
    await kernel.call('cgroup_remove', { path: '/user/owned' });
    await kernel.value('sync_account', ROOT_ACCOUNT);
    await kernel.call('cgroup_remove', { path: '/user/root-owned' });
    await kernel.terminate();
  }
});

test('concurrent exec and direct fork cannot exceed the namespace process limit', async ({ page }) => {
  await page.goto('/login');
  const kernel = await freshKernel(page);
  const procs = [];
  try {
    for (let i = 0; i < 62; i++) {
      procs.push(await kernel.value('exec', executable));
    }
    const parent = procs[0];
    for (let attempt = 0; attempt < 16; attempt++) {
      const [execAns, forkAns] = await Promise.all([
        kernel.call('exec', executable),
        kernel.call('fork', { pid: parent.pid }),
      ]);
      const rows = await kernel.value('poll', { pids: [] });
      expect(rows.filter(row => row.state !== 'zombie')).toHaveLength(64);
      expect([execAns, forkAns].filter(answer => answer.err?.errno === 'EAGAIN')).toHaveLength(1);
      if (execAns.ok) {
        await kernel.value('kill', { pid: execAns.ok.pid, signal: 9 });
        await kernel.value('wait', { pid: execAns.ok.pid });
      }
      if (forkAns.ok) {
        await kernel.value('kill', { pid: forkAns.ok.pid, signal: 9 });
        await kernel.value('waitchild', { ppid: parent.pid, pid: forkAns.ok.pid });
      }
    }
  } finally {
    for (const p of procs) {
      await kernel.call('kill', { pid: p.pid, signal: 9 });
      await kernel.call('wait', { pid: p.pid });
    }
    await kernel.terminate();
  }
});

test('lease reconciliation accepts only the owning token, including after logout', async ({ page, context }) => {
  const request = context.request;
  await call(request, 'getcreds');
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': `lease-${Date.now()}` }, data: { password } })).ok()).toBe(true);
  await page.goto('/login');
  const kernel = await freshKernel(page, '__leaseOwnerKernel');
  const stranger = await freshKernel(page, '__leaseStrangerKernel');
  let inst;
  try {
    // 1. Local process reconciliation keeps the process's uid 0 snapshot across logout and rejects foreign hosts.
    await kernel.value('sync_account', ROOT_ACCOUNT);
    const proc = await kernel.value('exec', { ...executable, remote: true });
    expect((await api(request, 'logout')).ok()).toBe(true);
    await kernel.value('sync_account', GUEST_ACCOUNT);
    expect((await stranger.value('sync')).filter(row => row.pid === proc.pid)).toEqual([]);
    expect((await kernel.value('sync')).find(row => row.pid === proc.pid)).toMatchObject({
      pid: proc.pid,
      uid: 0,
      state: 'running',
    });
    await kernel.value('exit', { pid: proc.pid, status: 0 });
    expect((await kernel.value('sync')).find(row => row.pid === proc.pid)?.state).toBe('zombie');
    await kernel.value('sync_account', ROOT_ACCOUNT);
    await kernel.value('wait', { pid: proc.pid });

    // 2. Server-side ServiceAuth v2 lease reconciliation accepts only the owning host_proof & token, including after logout.
    expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': `lease-v2-${Date.now()}` }, data: { password } })).ok()).toBe(true);
    inst = await attachInstance(request, { origin });
    const cred = await inst.mint();
    expect(cred.uid).toBe(0);
    expect((await api(request, 'logout')).ok()).toBe(true);

    const wrongHost = await serviceAuth(
      request,
      { renew_instance: { instance_id: inst.instanceId, host_proof: randomBytes(32).toString('hex'), active_tokens: [cred.token] } },
      {},
      { origin },
    );
    expect(wrongHost.ok).toBe(false);
    expect(wrongHost.body.errno).toBe('EACCES');

    const badToken = await inst.renew(['wrong']);
    expect(badToken.revoked).toContain('wrong');

    const kept = await inst.renew([cred.token]);
    expect(kept.revoked ?? []).toEqual([]);

    await inst.revoke([cred.token]);
    const afterRevoke = await inst.renew([cred.token]);
    expect(afterRevoke.revoked).toContain(cred.token);
  } finally {
    if (inst) await inst.detach().catch(() => {});
    await stranger.terminate();
    await kernel.terminate();
  }
});
