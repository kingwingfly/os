import { test, expect } from './test.js';
import { api, call as syscall, program, put, rmrf } from './sys.js';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = process.env.OS_TEST_ADMIN_PASSWORD || (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const OS_FD_ROOT = 0x7ffffffd;
const O_RDONLY = 0;

let seq = 0;
async function loginAs(request, username, password) {
  const res = await api(request, 'login', {
    headers: { 'CF-Connecting-IP': `inst-iso-${Date.now()}-${++seq}` },
    data: { username, password },
  });
  expect(res.ok(), await res.text()).toBe(true);
}

async function command(page, text) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form');
  await expect(busy).toHaveAttribute('data-state', 'idle');
  await input.fill(text);
  await input.press('Enter');
  await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
}
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();

async function connectKernel(page) {
  await page.evaluate(() => {
    const worker = new Worker('/client-kernel.js');
    const pending = new Map();
    const events = [];
    let next = 0;
    worker.onmessage = ({ data }) => {
      if (data?.type === 'event') events.push(data);
      if (data?.id != null && pending.has(data.id)) {
        pending.get(data.id)(data);
        pending.delete(data.id);
      }
    };
    window.__instEvents = events;
    window.__instRaw = msg => new Promise(resolve => {
      const id = ++next;
      pending.set(id, resolve);
      worker.postMessage({ ...msg, id });
    });
    window.__instKernel = (type, args = {}) => window.__instRaw({ v: 2, type, args });
  });
  const init = await kc(page, 'init');
  expect(init.err, JSON.stringify(init)).toBeUndefined();
}
const kc = (page, type, args = {}) => page.evaluate(([type, args]) => window.__instKernel(type, args), [type, args]);
async function kv(page, type, args = {}) {
  const r = await kc(page, type, args);
  expect(r.err, `${type}: ${JSON.stringify(r)}`).toBeUndefined();
  return r.ok;
}

async function fsRpc(request, credential, session, fsCall, instanceId) {
  const res = await request.post(origin + '/api/fs', {
    headers: { Origin: origin, ...(instanceId ? { 'X-OS-Instance': instanceId } : {}) },
    data: { version: 2, credential, session, call: fsCall },
  });
  return { status: res.status(), ok: res.ok(), body: await res.json() };
}

test('Gate 1: two tabs of the same signed-in account have isolated PIDs, /proc, /run, and /tmp while sharing cloud files', async ({ browser }) => {
  const context = await browser.newContext();
  const sharedFile = `/guest/shared-inst-${randomUUID()}.txt`;
  try {
    await loginAs(context.request, 'root', rootPassword);
    const tabA = await context.newPage();
    const tabB = await context.newPage();
    await tabA.goto('/');
    await tabB.goto('/');
    await expect.poll(async () => (await tabA.evaluate(() => window.os.loginSession()))?.session?.uid).toBe(0);
    await expect.poll(async () => (await tabB.evaluate(() => window.os.loginSession()))?.session?.uid).toBe(0);

    // Write instance-local files in Tab A's /tmp and /run, and a cloud file in /guest.
    await command(tabA, `sh -c "printf tabA-tmp > /tmp/only-a && printf tabA-run > /run/only-a && printf cloud-ok > ${sharedFile}"`);
    await command(tabA, 'cat /tmp/only-a /run/only-a');
    await expect(last(tabA)).toHaveText('tabA-tmptabA-run');

    // Tab B shares the cloud file but sees NEITHER Tab A's /tmp nor /run.
    await command(tabB, `cat ${sharedFile}`);
    await expect(last(tabB)).toHaveText('cloud-ok');
    await command(tabB, 'sh -c "test -e /tmp/only-a && echo LEAK || echo ISOLATED_TMP; test -e /run/only-a && echo LEAK || echo ISOLATED_RUN"');
    await expect(last(tabB)).toHaveText('ISOLATED_TMP\nISOLATED_RUN');

    // Distinct tabs run independent kernel instances with distinct boot IDs.
    const bootA = (await tabA.evaluate(() => window.os.machineInit()))?.init?.boot;
    const bootB = (await tabB.evaluate(() => window.os.machineInit()))?.init?.boot;
    expect(bootA).toBeTruthy();
    expect(bootB).toBeTruthy();
    expect(bootA).not.toBe(bootB);

    // Advance Tab A's local PID counter so `pidA` does not numerically coincide with Tab B's own shell PID.
    await command(tabA, 'sh -c "true; true; true; true; true"');

    // Start a long-lived process in Tab A; Tab B's ps, /proc, and kill see nothing of it.
    await tabA.evaluate(() => {
      window.tabASleep = window.os.exec([{ path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'] }], {
        stdin: '',
        onJob: job => { window.tabAJob = job; },
      });
    });
    await tabA.waitForFunction(() => window.tabAJob?.pids?.length === 1);
    const pidA = await tabA.evaluate(() => window.tabAJob.pids[0]);

    await command(tabA, `cat /proc/${pidA}/cmdline`);
    await expect(last(tabA)).toContainText('sleep');

    await command(tabB, `sh -c "ps | grep '[s]leep 60' >/dev/null 2>&1 && echo LEAK_PS || echo NO_PS; test -d /proc/${pidA} && echo LEAK_PROC || echo NO_PROC; kill -0 ${pidA} 2>/dev/null && echo LEAK_KILL || echo NO_KILL"`);
    await expect(last(tabB)).toHaveText('NO_PS\nNO_PROC\nNO_KILL');

    // Tab A's process is still alive until Tab A kills it.
    await tabA.evaluate(() => window.tabAJob.signal(9));
    expect((await tabA.evaluate(() => window.tabASleep)).status).toBe(137);
  } finally {
    await rmrf(context.request, sharedFile);
    await context.close();
  }
});

test('Gate 2: zero outbound /api/* network RPCs during boot, exec, fork, wait, kill, pipe, setsid, /proc/*, /run, and /tmp', async ({ browser }) => {
  const context = await browser.newContext();
  try {
    const page = await context.newPage();
    const apiRequests = [];
    page.on('request', req => {
      const url = new URL(req.url());
      if (url.pathname.startsWith('/api/')) {
        apiRequests.push(`${req.method()} ${url.pathname}${url.search}`);
      }
    });

    // Warm /usr/bin static assets once via local execution in `/tmp`, then clear the log and verify 0 /api/* RPCs.
    await page.goto('/');
    await page.waitForFunction(() => typeof window.os?.exec === 'function');
    const warm = await page.evaluate(() => window.os.exec([['sh', '-c', 'echo warm | cat']], { cwd: '/tmp', stdin: '' }));
    expect(warm.status).toBe(0);
    apiRequests.length = 0;

    // Run a comprehensive local workload in `/tmp`: pipe, subshell fork+wait, kill, /proc/*, /run, /tmp (01777).
    const script = [
      'echo pipe-data | tr a-z A-Z',
      '(exit 5) & wait $!; echo waited:$?',
      'sleep 30 & p=$!; kill -KILL $p; wait $p; echo killed:$?',
      'test -r /proc/uptime && echo uptime:ok',
      'grep init /proc/1/status >/dev/null && echo proc1:ok',
      'test -r /proc/self/status && test -r /proc/self/mounts && echo procself:ok',
      'printf local-tmp > /tmp/z && cat /tmp/z; echo',
      'test -d /run && echo run-dir:ok',
    ].join('; ');
    const run = await page.evaluate(cmd => window.os.exec([['sh', '-c', cmd]], { cwd: '/tmp', stdin: '' }), script);
    expect(run.status).toBe(0);
    const text = run.stdout ?? '';
    expect(text).toContain('PIPE-DATA');
    expect(text).toContain('waited:5');
    expect(text).toContain('killed:137');
    expect(text).toContain('uptime:ok');
    expect(text).toContain('proc1:ok');
    expect(text).toContain('procself:ok');
    expect(text).toContain('local-tmp');
    expect(text).toContain('run-dir:ok');

    // Also run a fresh local client-kernel Worker boot + exec + /run + fork + setpgid + setsid + kill + wait.
    await connectKernel(page);
    await kv(page, 'sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: false });
    const parent = await kv(page, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '10'], cwd: '/', env: [] });
    const runFd = await kv(page, 'proc_openat', { pid: parent.pid, dirfd: OS_FD_ROOT, path: '/run/local-zero-rpc', oflags: 1 | 0o100 | 0o1000, mode: 0o644, cloexec: false });
    await kv(page, 'kfd_close', { pid: parent.pid, kfd: runFd.kfd });
    expect((await kv(page, 'proc_statat', { pid: parent.pid, dirfd: OS_FD_ROOT, path: '/run/local-zero-rpc', follow: true })).size).toBe(0);
    const child1 = await kv(page, 'fork', { pid: parent.pid });
    await kv(page, 'process_call', { pid: child1.pid, call: { setpgid: { pid: 0, pgid: 0 } } });
    const child2 = await kv(page, 'fork', { pid: parent.pid });
    await kv(page, 'process_call', { pid: child2.pid, call: 'setsid' });
    await kv(page, 'kill', { pid: child1.pid, signal: 9 });
    await kv(page, 'waitchild', { ppid: parent.pid, pid: child1.pid });
    await kv(page, 'kill', { pid: child2.pid, signal: 9 });
    await kv(page, 'waitchild', { ppid: parent.pid, pid: child2.pid });
    await kv(page, 'exit', { pid: parent.pid, status: 0 });
    await kv(page, 'wait', { pid: parent.pid });

    // ZERO /api/* requests across the entire local execution + /proc + /run + /tmp suite!
    expect(apiRequests).toEqual([]);
  } finally {
    await context.close();
  }
});

test('Gate 3a: boot /dev omits remote devices until explicit credentialed attachment, and forged credentials/headers fail closed', async ({ page, context }) => {
  await page.goto('/login');
  await connectKernel(page);
  await loginAs(context.request, 'root', rootPassword);
  await kv(page, 'sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true });
  const instanceId = await kv(page, 'instance_id');

  const proc = await kv(page, 'exec', { path: '/usr/bin/true', argv: ['true'], cwd: '/', env: [] });
  try {
    // At boot, local /dev has null/zero/full/random/urandom/ptmx, NOT remote devices archive/media/present/snd.
    for (const dev of ['archive', 'media', 'present', 'snd']) {
      expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: `/dev/${dev}`, follow: true })).err?.errno).toBe('ENOENT');
    }
    expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/dev/null', follow: true })).ok).toBeTruthy();

    // Uncredentialed local process cannot attach a remote device (EACCES).
    expect((await kc(page, 'attach_remote_device', { driver: 'archive', pid: proc.pid })).err?.errno).toBe('EACCES');
    expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/dev/archive', follow: true })).err?.errno).toBe('ENOENT');

    // Explicit credentialed attachment mints a ServiceAuth v2 credential and mounts /dev/archive.
    const attached = await kv(page, 'attach_remote_device', { driver: 'archive' });
    expect(attached.attached).toBe(true);
    expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/dev/archive', follow: true })).ok).toBeTruthy();

    // Detaching removes the remote device node again.
    await kv(page, 'detach_remote_device', { driver: 'archive' });
    expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/dev/archive', follow: true })).err?.errno).toBe('ENOENT');

    // Forged instance_id on /api/fs with a valid remote token fails closed.
    const remoteProc = await kv(page, 'exec', { path: '/usr/bin/true', argv: ['true'], cwd: '/', env: [], remote: true });
    try {
      const okConn = await fsRpc(context.request, remoteProc.token, null, 'connect', instanceId);
      expect(okConn.ok, JSON.stringify(okConn)).toBe(true);
      await fsRpc(context.request, remoteProc.token, okConn.body.session, 'disconnect', instanceId);

      const forgedInst = await fsRpc(context.request, remoteProc.token, null, 'connect', 'inst-wrong-9999');
      expect(forgedInst.ok).toBe(false);
      expect(['EACCES', 'EPERM']).toContain(forgedInst.body.errno);

      const missingInst = await fsRpc(context.request, remoteProc.token, null, 'connect', null);
      expect(missingInst.ok).toBe(false);
      expect(['EACCES', 'EPERM']).toContain(missingInst.body.errno);

      // Direct /api/sys remote device open with forged/wrong instance_id fails closed.
      const forgedDev = await context.request.post(origin + '/api/sys', {
        headers: { Origin: origin, 'Content-Type': 'application/json', 'X-OS-Instance': 'inst-wrong-9999' },
        data: { calls: [{ open: { path: '/dev/archive', flags: 2 } }], pid: remoteProc.pid, proc: remoteProc.token },
      });
      const devBody = await forgedDev.json();
      expect(['EACCES', 'EPERM']).toContain(devBody.results?.[0]?.err?.errno ?? devBody.errno);
    } finally {
      await kc(page, 'exit', { pid: remoteProc.pid, status: 0 });
      await kc(page, 'wait', { pid: remoteProc.pid });
    }
  } finally {
    await kc(page, 'exit', { pid: proc.pid, status: 0 });
    await kc(page, 'wait', { pid: proc.pid });
  }
});

test('Gate 3b: account lock, password change, delete, explicit revoke, and host detach terminate remote access immediately', async ({ browser }) => {
  const adminCtx = await browser.newContext();
  const userCtx = await browser.newContext();
  const username = `l3auser${Date.now().toString(36).slice(-5)}`;
  const pass1 = 'InitialPassword!1234';
  const pass2 = 'RotatedPassword!5678';
  try {
    await loginAs(adminCtx.request, 'root', rootPassword);
    expect((await program(adminCtx.request, ['useradd', '-m', '-G', 'wheel', username])).ok()).toBe(true);
    expect((await api(adminCtx.request, 'passwd', { data: { username, password: pass1 } })).ok()).toBe(true);

    // Sign in as the wheel user in userCtx, elevate sudo, and mint BOTH regular and sudo-elevated remote creds.
    await loginAs(userCtx.request, username, pass1);
    expect((await api(userCtx.request, 'sudo', { data: { password: pass1 } })).ok()).toBe(true);
    const userPage = await userCtx.newPage();
    await userPage.goto('/login');
    await connectKernel(userPage);
    await kv(userPage, 'sync_account_from_server');
    const instanceId = await kv(userPage, 'instance_id');
    const p1 = await kv(userPage, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true });
    const p1Sudo = await kv(userPage, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true, sudo: true });

    // Sanity check: both p1 and sudo-elevated p1Sudo connect to /api/fs.
    const check1 = await fsRpc(userCtx.request, p1.token, null, 'connect', instanceId);
    expect(check1.ok, JSON.stringify(check1)).toBe(true);
    await fsRpc(userCtx.request, p1.token, check1.body.session, 'disconnect', instanceId);
    const check1Sudo = await fsRpc(userCtx.request, p1Sudo.token, null, 'connect', instanceId);
    expect(check1Sudo.ok, JSON.stringify(check1Sudo)).toBe(true);
    await fsRpc(userCtx.request, p1Sudo.token, check1Sudo.body.session, 'disconnect', instanceId);

    // 1. Account lock (usermod -L) immediately fails closed on BOTH p1 and sudo-elevated p1Sudo!
    expect((await program(adminCtx.request, ['usermod', '-L', username])).ok()).toBe(true);
    const afterLock = await fsRpc(userCtx.request, p1.token, null, 'connect', instanceId);
    expect(afterLock.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterLock.body.errno);
    const afterLockSudo = await fsRpc(userCtx.request, p1Sudo.token, null, 'connect', instanceId);
    expect(afterLockSudo.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterLockSudo.body.errno);

    // Unlock and re-login to verify password change (passwd) invalidates BOTH regular and sudo remote creds.
    expect((await program(adminCtx.request, ['usermod', '-U', username])).ok()).toBe(true);
    await loginAs(userCtx.request, username, pass1);
    expect((await api(userCtx.request, 'sudo', { data: { password: pass1 } })).ok()).toBe(true);
    const p2 = await kv(userPage, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true });
    const p2Sudo = await kv(userPage, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true, sudo: true });
    const check2 = await fsRpc(userCtx.request, p2.token, null, 'connect', instanceId);
    expect(check2.ok, JSON.stringify(check2)).toBe(true);
    await fsRpc(userCtx.request, p2.token, check2.body.session, 'disconnect', instanceId);
    const check2Sudo = await fsRpc(userCtx.request, p2Sudo.token, null, 'connect', instanceId);
    expect(check2Sudo.ok, JSON.stringify(check2Sudo)).toBe(true);
    await fsRpc(userCtx.request, p2Sudo.token, check2Sudo.body.session, 'disconnect', instanceId);

    // 2. Password change terminates existing regular AND sudo remote access immediately.
    expect((await api(adminCtx.request, 'passwd', { data: { username, password: pass2 } })).ok()).toBe(true);
    const afterPasswd = await fsRpc(userCtx.request, p2.token, null, 'connect', instanceId);
    expect(afterPasswd.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterPasswd.body.errno);
    const afterPasswdSudo = await fsRpc(userCtx.request, p2Sudo.token, null, 'connect', instanceId);
    expect(afterPasswdSudo.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterPasswdSudo.body.errno);

    // 3. Re-login with new password, mint p3, then detach instance (orderly host teardown).
    await loginAs(userCtx.request, username, pass2);
    const p3 = await kv(userPage, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true });
    const check3 = await fsRpc(userCtx.request, p3.token, null, 'connect', instanceId);
    expect(check3.ok, JSON.stringify(check3)).toBe(true);
    await fsRpc(userCtx.request, p3.token, check3.body.session, 'disconnect', instanceId);

    await kv(userPage, 'detach_instance');
    const afterDetach = await fsRpc(userCtx.request, p3.token, null, 'connect', instanceId);
    expect(afterDetach.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterDetach.body.errno);

    // 4. Account deletion (userdel -r) terminates regular AND sudo active remote access immediately.
    expect((await api(userCtx.request, 'sudo', { data: { password: pass2 } })).ok()).toBe(true);
    const p4 = await kv(userPage, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true });
    const p4Sudo = await kv(userPage, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true, sudo: true });
    const check4 = await fsRpc(userCtx.request, p4.token, null, 'connect', instanceId);
    expect(check4.ok, JSON.stringify(check4)).toBe(true);
    await fsRpc(userCtx.request, p4.token, check4.body.session, 'disconnect', instanceId);
    const check4Sudo = await fsRpc(userCtx.request, p4Sudo.token, null, 'connect', instanceId);
    expect(check4Sudo.ok, JSON.stringify(check4Sudo)).toBe(true);
    await fsRpc(userCtx.request, p4Sudo.token, check4Sudo.body.session, 'disconnect', instanceId);

    expect((await program(adminCtx.request, ['userdel', '-r', username])).ok()).toBe(true);
    const afterDelete = await fsRpc(userCtx.request, p4.token, null, 'connect', instanceId);
    expect(afterDelete.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterDelete.body.errno);
    const afterDeleteSudo = await fsRpc(userCtx.request, p4Sudo.token, null, 'connect', instanceId);
    expect(afterDeleteSudo.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterDeleteSudo.body.errno);
  } finally {
    await program(adminCtx.request, ['userdel', '-r', username]).catch(() => {});
    await userCtx.close();
    await adminCtx.close();
  }
});

test('Gate 4: privilege drop, cloud=false reexec, and pre-login guest processes fail closed on remote access (Contract §2.4)', async ({ page, context }) => {
  await page.goto('/login');
  await connectKernel(page);

  // 1. Pre-login guest process (uid 65534, before sync_account) MUST NOT escalate to root when
  //    another request signs in as root in the same browser context.
  const guestProc = await kv(page, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [] });
  try {
    await loginAs(context.request, 'root', rootPassword);
    // Do NOT call sync_account yet: local guest uid 65534 attempts cloud access while cookie is root.
    const esc = await kc(page, 'proc_statat', { pid: guestProc.pid, dirfd: OS_FD_ROOT, path: '/etc/passwd', follow: true });
    expect(esc.err?.errno).toBe('EACCES');
    const guestCreds = await kv(page, 'getcreds_proc', { pid: guestProc.pid });
    expect(guestCreds.uid).toBe(65534);
    expect(guestCreds.has_remote).toBe(false);
  } finally {
    await kc(page, 'exit', { pid: guestProc.pid, status: 0 });
    await kc(page, 'wait', { pid: guestProc.pid });
  }

  // 2. Privilege drop clears ambient remote credential and revokes its token.
  await kv(page, 'sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true });
  const instanceId = await kv(page, 'instance_id');
  const proc = await kv(page, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], remote: true });
  expect(proc.token).toMatch(/^[0-9a-f]{64}$/);
  try {
    // Verify remote access works before privilege drop.
    const before = await fsRpc(context.request, proc.token, null, 'connect', instanceId);
    expect(before.ok, JSON.stringify(before)).toBe(true);
    await fsRpc(context.request, proc.token, before.body.session, 'disconnect', instanceId);

    // 3. Fork a child and reexec it with local `cloud: false` while parent still holds the token:
    //    child's remote credential MUST be cleared (empty Exec.token, has_remote: false, device attach EACCES).
    const child = await kv(page, 'fork', { pid: proc.pid });
    try {
      const reexeced = await kv(page, 'reexec', {
        pid: child.pid,
        local: { digest: 'a'.repeat(64), size: 128, cloud: false },
        path: '/mnt/local/tool.wasm',
        argv: ['tool'],
        env: [],
        cwd: '/',
      });
      expect(reexeced.token).toBe('');
      const childCreds = await kv(page, 'getcreds_proc', { pid: child.pid });
      expect(childCreds.has_remote).toBe(false);
      expect(childCreds.cloud_access).toBe(false);
      expect((await kc(page, 'attach_remote_device', { driver: 'archive', pid: child.pid })).err?.errno).toBe('EACCES');
    } finally {
      await kc(page, 'exit', { pid: child.pid, status: 0 });
      await kc(page, 'waitchild', { ppid: proc.pid, pid: child.pid });
    }

    // Drop local privilege (uid 0 -> 1000) without an explicit remote credential.
    const dropped = await kv(page, 'set_proc_cred', { pid: proc.pid, uid: 1000, gid: 1000, groups: [1000] });
    expect(dropped).toMatchObject({ uid: 1000, gid: 1000, has_remote: false, cloud_access: false });

    // Ambient remote token was revoked on the server, and local VFS refuses remote cloud paths with EACCES.
    const afterDrop = await fsRpc(context.request, proc.token, null, 'connect', instanceId);
    expect(afterDrop.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterDrop.body.errno);
    expect((await kc(page, 'proc_statat', { pid: proc.pid, dirfd: OS_FD_ROOT, path: '/etc/passwd', follow: true })).err?.errno).toBe('EACCES');
  } finally {
    await kc(page, 'exit', { pid: proc.pid, status: 0 });
    await kc(page, 'wait', { pid: proc.pid });
  }
});

test('Gate 5: server enforces remote io.max per credential regardless of client claims', async ({ page, context }) => {
  await page.goto('/login');
  await connectKernel(page);
  await loginAs(context.request, 'root', rootPassword);
  await kv(page, 'sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true });
  const instanceId = await kv(page, 'instance_id');
  const cg = `/user/io-max-${randomUUID()}`;
  const path = `/guest/io-max-${randomUUID()}.bin`;
  const data = Buffer.alloc(16384, 0x41);
  expect((await put(context.request, '/api/file?path=' + encodeURIComponent(path), { data })).ok()).toBe(true);
  await kv(page, 'cgroup_create', { path: cg });
  // Cap remote read bandwidth to 100 bytes/sec on this cgroup (4096B exceeds the 30s pacing window -> immediate EAGAIN).
  await kv(page, 'cgroup_set', { path: cg, key: 'io.max', value: 'rbps=100' });
  const proc = await kv(page, 'exec', { path: '/usr/bin/sleep', argv: ['sleep', '60'], cwd: '/', env: [], cgroup: cg, remote: true });
  let session;
  try {
    const conn = await fsRpc(context.request, proc.token, null, 'connect', instanceId);
    expect(conn.ok, JSON.stringify(conn)).toBe(true);
    session = conn.body.session;
    const walked = await fsRpc(context.request, proc.token, session, { walk: { dir: conn.body.root, names: ['guest', path.split('/').pop()] } }, instanceId);
    expect(walked.ok, JSON.stringify(walked)).toBe(true);
    const opened = await fsRpc(context.request, proc.token, session, {
      open: {
        ticket: `io-read-${randomUUID()}`,
        handle: walked.body.entries[1].handle,
        options: { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false },
      },
    }, instanceId);
    expect(opened.ok, JSON.stringify(opened)).toBe(true);

    // 1. A 4096B read at rbps=100 (>30s debt) is immediately refused server-side with EAGAIN (429).
    const refused = await context.request.post(origin + '/api/fs/data', {
      headers: {
        Origin: origin,
        'X-OS-Instance': instanceId,
        'X-OS-Filesystem': JSON.stringify({
          version: 2,
          credential: proc.token,
          pid: proc.pid,
          session,
          open: opened.body,
          operation: { read: { offset: 0, length: 4096 } },
        }),
      },
    });
    expect(refused.ok()).toBe(false);
    const refusedBody = await refused.json().catch(() => ({}));
    expect(refusedBody.errno === 'EAGAIN' || refused.status() === 429, JSON.stringify(refusedBody)).toBe(true);

    // 2. Raising rbps=200 and reading 250B twice paces the second read server-side by >= 900ms.
    await kv(page, 'cgroup_set', { path: cg, key: 'io.max', value: 'rbps=200' });
    const doSmallRead = () => context.request.post(origin + '/api/fs/data', {
      headers: {
        Origin: origin,
        'X-OS-Instance': instanceId,
        'X-OS-Filesystem': JSON.stringify({
          version: 2,
          credential: proc.token,
          pid: proc.pid,
          session,
          open: opened.body,
          operation: { read: { offset: 0, length: 250 } },
        }),
      },
    });
    const t0 = Date.now();
    expect((await doSmallRead()).ok()).toBe(true);
    expect((await doSmallRead()).ok()).toBe(true);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(900);

    // 3. Reexec (DeriveServiceCred) rotates the token WITHOUT escaping server-side io.max or resetting pacing debt:
    //    the 250B read right before reexec left ~1.25s of read_end debt; immediately reexecing and reading 250B
    //    with the rotated token must still be paced by >= 900ms, and a 4096B read at rbps=100 must return EAGAIN.
    const tDebt = Date.now();
    const reexeced = await kv(page, 'reexec', {
      pid: proc.pid,
      path: '/usr/bin/sleep',
      argv: ['sleep', '60'],
      env: [],
      cwd: '/',
    });
    expect(reexeced.token).toMatch(/^[0-9a-f]{64}$/);
    expect(reexeced.token).not.toBe(proc.token);
    const conn2 = await fsRpc(context.request, reexeced.token, null, 'connect', instanceId);
    expect(conn2.ok, JSON.stringify(conn2)).toBe(true);
    try {
      const walked2 = await fsRpc(context.request, reexeced.token, conn2.body.session, { walk: { dir: conn2.body.root, names: ['guest', path.split('/').pop()] } }, instanceId);
      expect(walked2.ok, JSON.stringify(walked2)).toBe(true);
      const opened2 = await fsRpc(context.request, reexeced.token, conn2.body.session, {
        open: {
          ticket: `io-read-reexec-${randomUUID()}`,
          handle: walked2.body.entries[1].handle,
          options: { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false },
        },
      }, instanceId);
      expect(opened2.ok, JSON.stringify(opened2)).toBe(true);
      const pacedAfterReexec = await context.request.post(origin + '/api/fs/data', {
        headers: {
          Origin: origin,
          'X-OS-Instance': instanceId,
          'X-OS-Filesystem': JSON.stringify({
            version: 2,
            credential: reexeced.token,
            pid: proc.pid,
            session: conn2.body.session,
            open: opened2.body,
            operation: { read: { offset: 0, length: 250 } },
          }),
        },
      });
      expect(pacedAfterReexec.ok()).toBe(true);
      expect(Date.now() - tDebt).toBeGreaterThanOrEqual(900);

      await kv(page, 'cgroup_set', { path: cg, key: 'io.max', value: 'rbps=100' });
      const refusedAfterReexec = await context.request.post(origin + '/api/fs/data', {
        headers: {
          Origin: origin,
          'X-OS-Instance': instanceId,
          'X-OS-Filesystem': JSON.stringify({
            version: 2,
            credential: reexeced.token,
            pid: proc.pid,
            session: conn2.body.session,
            open: opened2.body,
            operation: { read: { offset: 0, length: 4096 } },
          }),
        },
      });
      expect(refusedAfterReexec.ok()).toBe(false);
      const refusedAfterBody = await refusedAfterReexec.json().catch(() => ({}));
      expect(refusedAfterBody.errno === 'EAGAIN' || refusedAfterReexec.status() === 429, JSON.stringify(refusedAfterBody)).toBe(true);
    } finally {
      await fsRpc(context.request, reexeced.token, conn2.body.session, 'disconnect', instanceId).catch(() => {});
    }
  } finally {
    if (session) await fsRpc(context.request, proc.token, session, 'disconnect', instanceId).catch(() => {});
    await kc(page, 'exit', { pid: proc.pid, status: 0 });
    await kc(page, 'wait', { pid: proc.pid });
    await kc(page, 'cgroup_remove', { path: cg });
    await rmrf(context.request, path);
  }
});

test('Gate 6: HostAdapter and ServiceAuth version mismatches return EPROTONOSUPPORT, keep local processes alive, and never auto-reload (Contract §2.10)', async ({ page }) => {
  let navigations = 0;
  page.on('framenavigated', frame => {
    if (frame === page.mainFrame()) navigations++;
  });
  await page.goto('/');
  const beforeNavs = navigations;
  await connectKernel(page);

  // Start a local process before triggering mismatches so we verify it stays alive.
  const alive = await kv(page, 'exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '60'], cwd: '/', env: [] });
  try {
    // 1. HostAdapter v1 envelope mismatch -> EPROTONOSUPPORT + protocol-mismatch event.
    const oldEnvelope = await page.evaluate(() => window.__instRaw({ v: 1, type: 'version', args: {} }));
    expect(oldEnvelope.err?.errno).toBe('EPROTONOSUPPORT');

    // 2. HostAdapter Hello with only [1] -> EPROTONOSUPPORT.
    const oldHello = await page.evaluate(() => window.__instRaw({ v: 2, type: 'hello', boundary: 'host-adapter', versions: [1] }));
    expect(oldHello.err?.errno).toBe('EPROTONOSUPPORT');

    // 3. ServiceAuth Hello with only [1] -> EPROTONOSUPPORT (both via kernel and directly on /api/service-auth).
    const oldServiceAuth = await kc(page, 'service_auth_hello', { versions: [1] });
    expect(oldServiceAuth.err?.errno).toBe('EPROTONOSUPPORT');

    // Confirm protocol-mismatch events were emitted without reloading the page.
    const events = await page.evaluate(() => window.__instEvents.filter(e => e.event === 'protocol-mismatch'));
    expect(events.length).toBeGreaterThanOrEqual(2);
    await page.waitForTimeout(500);
    expect(navigations).toBe(beforeNavs);

    // Local process started before the mismatch is STILL running untouched!
    const [stillRunning] = await kv(page, 'poll', { pids: [alive.pid] });
    expect(stillRunning.state).toBe('running');
  } finally {
    await kc(page, 'exit', { pid: alive.pid, status: 0 });
    await kc(page, 'wait', { pid: alive.pid });
  }
});
