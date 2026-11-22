import { test, expect } from './test.js';
import { api, sys, call } from './sys.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const CLOUD_SCOPE = { cloud_fs: true, devices: [], containers: false, relay: false };
const OS_FD_ROOT = 0x7ffffffd;
const O_RDONLY = 0;

const image = {
  path: '/mnt/local/project/probe',
  argv: ['probe'],
  cwd: '/',
  runtime: 'resources-v1',
  local: { digest: 'a'.repeat(64), size: 8, cloud: false },
};

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
    window.localAdmKernel = (type, args = {}) => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      worker.postMessage({ v: 2, id, type, args });
    });
  });
  const init = await kc(page, 'init');
  expect(init.err, JSON.stringify(init)).toBeUndefined();
}
async function mountCloudAsNonRoot(page) {
  const uname = 'locadm' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5);
  const res = await api(page.request, 'register', {
    headers: { Origin: origin, 'CF-Connecting-IP': 'locadm-' + crypto.randomUUID() },
    data: { username: uname, password: 'local-adm-pass-1234', create_home: false },
  });
  expect(res.ok(), await res.text()).toBe(true);
  const creds = await call(page.request, 'getcreds');
  await kv(page, 'cloud_sign_in', {
    cloudUser: uname,
    cloudUid: creds.uid,
    cloudGid: creds.gid,
    cloudGroups: creds.groups,
    scope: CLOUD_SCOPE,
  });
}
const kc = (page, type, args = {}) => page.evaluate(([type, args]) => window.localAdmKernel(type, args), [type, args]);
async function kv(page, type, args = {}) {
  const r = await kc(page, type, args);
  expect(r.err, `${type}: ${JSON.stringify(r)}`).toBeUndefined();
  return r.ok;
}
async function end(page, proc) {
  if (!proc) return;
  await kc(page, 'exit', { pid: proc.pid, status: 0 });
  await kc(page, 'wait', { pid: proc.pid });
}

const fsRpc = async (request, credential, session, fsCall, instanceId) =>
  (await request.post('/api/fs', {
    headers: { Origin: origin, ...(instanceId ? { 'X-OS-Instance': instanceId } : {}) },
    data: { version: 2, credential, session, call: fsCall },
  })).json();

test('local admission grants process resources but no implicit cloud filesystem authority', async ({ page }) => {
  await connect(page);
  await mountCloudAsNonRoot(page);
  let proc;
  try {
    proc = await kv(page, 'exec', image);
    expect(proc.local).toEqual(image.local);
    expect(proc.asset).toBeUndefined();
    expect(proc.fd).toBeUndefined();
    expect(proc.token).toBe('');

    const creds = await kv(page, 'getcreds_proc', { pid: proc.pid });
    expect(creds.uid).not.toBe(0);
    expect(creds.cloud_access).toBe(false);
    expect(creds.has_remote).toBe(false);

    // Local linear-memory reservation succeeds without touching any remote server.
    await kv(page, 'reserve_memory', { pid: proc.pid, bytes: 65536 });

    // Cloud filesystem access (`/mnt/cloud`) & remote credential minting are refused for cloud:false processes.
    expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/mnt/cloud/etc/passwd', follow: true })).err?.errno).toBe('EACCES');
    expect((await kc(page, 'proc_openat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/mnt/cloud/etc/passwd', oflags: O_RDONLY, mode: 0, cloexec: false })).err?.errno).toBe('EACCES');
    expect((await kc(page, 'mint_remote_cred', { pid: proc.pid })).err?.errno).toBe('EACCES');

    // Re-exec cannot escalate cloud:false -> cloud:true.
    proc = await kv(page, 'reexec', { ...image, pid: proc.pid, local: { ...image.local, cloud: true } });
    expect(proc.local.cloud).toBe(false);
    expect(proc.token).toBe('');
    expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/mnt/cloud/etc/passwd', follow: true })).err?.errno).toBe('EACCES');
    expect((await kc(page, 'mint_remote_cred', { pid: proc.pid })).err?.errno).toBe('EACCES');
  } finally {
    await end(page, proc);
  }
});

test('local fork and replacement preserve attenuation, while an explicitly delegated launch keeps ordinary ACL checks', async ({ page }) => {
  const request = page.request;
  await connect(page);
  await mountCloudAsNonRoot(page);
  const instanceId = await kv(page, 'instance_id');
  let parent, child, delegated;
  try {
    parent = await kv(page, 'exec', image);
    child = await kv(page, 'fork', { pid: parent.pid });
    expect(child.token).toBe('');
    expect((await kc(page, 'proc_statat', { pid: child.pid, dirfd: OS_FD_ROOT, path: '/mnt/cloud/etc/passwd', follow: true })).err?.errno).toBe('EACCES');

    // Re-exec of forked child preserves attenuation (cloud:false cannot escalate to cloud:true).
    child = await kv(page, 'reexec', { ...image, pid: child.pid, local: { ...image.local, cloud: true } });
    expect(child.local.cloud).toBe(false);
    expect(child.token).toBe('');
    expect((await fsRpc(request, '0'.repeat(64), null, 'connect', instanceId)).errno).toBe('EACCES');

    // Explicitly delegated launch with cloud:true + remote:true receives a ServiceAuth v2 credential.
    delegated = await kv(page, 'exec', { ...image, local: { ...image.local, cloud: true }, remote: true });
    expect(delegated.token).toMatch(/^[0-9a-f]{64}$/);
    // Direct v1 /api/sys path calls with a process credential are refused at the server boundary.
    const [directStat] = await sys(request, [{ stat: { path: '/etc/passwd' } }], { pid: delegated.pid, proc: delegated.token }, { 'X-OS-Instance': instanceId });
    expect(directStat.err?.errno).toBe('EPERM');

    // /api/fs v2 honors ordinary ACL checks: /etc/passwd readable, /etc/shadow denied.
    const conn = await fsRpc(request, delegated.token, null, 'connect', instanceId);
    expect(conn.session, JSON.stringify(conn)).toBeTruthy();
    try {
      const passwdWalk = await fsRpc(request, delegated.token, conn.session, { walk: { dir: conn.root, names: ['etc', 'passwd'] } }, instanceId);
      expect(passwdWalk.stop).toBeNull();
      expect(passwdWalk.entries).toHaveLength(2);
      const shadowWalk = await fsRpc(request, delegated.token, conn.session, { walk: { dir: conn.root, names: ['etc', 'shadow'] } }, instanceId);
      if (shadowWalk.entries?.length === 2 && !shadowWalk.stop) {
        const shadowOpen = await fsRpc(request, delegated.token, conn.session, {
          open: {
            ticket: 'shadow-acl-check',
            handle: shadowWalk.entries[1].handle,
            options: { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false },
          },
        }, instanceId);
        expect(['EACCES', 'ENOENT']).toContain(shadowOpen.errno);
      } else {
        expect(shadowWalk.stop).toBeTruthy();
      }
    } finally {
      await fsRpc(request, delegated.token, conn.session, 'disconnect', instanceId);
    }
  } finally {
    if (child) {
      await kc(page, 'exit', { pid: child.pid, status: 0 });
      await kc(page, 'waitchild', { ppid: parent.pid, pid: child.pid });
    }
    await end(page, parent);
    await end(page, delegated);
  }
});

test('invalid local descriptors and uninstrumented claims are rejected before admission', async ({ page }) => {
  const request = page.request;
  await call(request, 'getcreds');
  await connect(page);
  for (const changed of [
    { local: { ...image.local, size: 0 } },
    { local: { ...image.local, size: 128 * 1024 * 1024 + 1 } },
    { local: { ...image.local, digest: 'Z'.repeat(64) } },
  ]) {
    expect((await kc(page, 'exec', { ...image, ...changed })).err?.errno).toBe('EINVAL');
  }
  // Under a memory.max cgroup, uninstrumented runtime claims fail with EOPNOTSUPP.
  const cg = '/user/local-adm-' + crypto.randomUUID();
  await kv(page, 'cgroup_create', { path: cg });
  try {
    await kv(page, 'cgroup_set', { path: cg, key: 'memory.max', value: '65536' });
    expect((await kc(page, 'exec', { ...image, cgroup: cg, runtime: 'untracked' })).err?.errno).toBe('EOPNOTSUPP');
  } finally {
    await kc(page, 'cgroup_remove', { path: cg });
  }
  // Retired server-side execve route fails closed on /api/sys.
  const res = await request.post(origin + '/api/sys', {
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    data: { calls: [{ execve: image }] },
  });
  expect(res.ok()).toBe(false);
});
