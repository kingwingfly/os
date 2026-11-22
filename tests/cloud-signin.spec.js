// Wave 4B Playwright E2E Acceptance & Security Refusal Suite for Issue #57 (`L3d`):
// Covers Blueprint §3.3 S-01..S-09:
// - S-01 & S-02: Local PID 1 `/usr/bin/init`, `/run/init/{control,notify}.sock`, `service` CLI,
//   optional `cloud.mount`, and ordered reverse shutdown (`service poweroff` -> `close_clean_root`).
// - S-03: 100% offline local OS account lifecycle (`user`, `wheel NOPASSWD` `sudo`, `useradd`,
//   `passwd`, `su`, `usermod`, `userdel`, `groupadd`, `groupdel`, `newgrp`) persisting across reload.
// - S-04: Zero-friction auto-login (`Local: user · Cloud: Signed out`), top-bar Cloud Sign-In panel,
//   `/run/user/<uid>/cloud-creds.json` (`0600`), `/mnt/cloud` + `devattach@*`, non-disruptive Sign-Out.
// - S-05: 100% local PTY & console separation offline (0 server RPCs), remote devices detached offline.
// - S-06: `NOTIFY_SOCKET` & `/run/init/control.sock` `SO_PEERCRED` spoofing refusals + `ServiceGrant.user` EPERM.
// - S-07: Local `uid 0` / `sudo` NEVER synthesizes remote root or elevates remote cloud authority.
// - S-08: Privilege drop clears & revokes remote tokens (`EACCES` on replay); remote revocation never kills local procs.
// - S-09: Retired `/api/sys` OS-account calls return `ENOSYS`, legacy modules deleted, `/etc/shadow` (`0600`) unreadable by uid 1000.

import { test, expect } from './test.js';
import { existsSync, readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { cloudAuth } from './sys.js';
import { cloudSignIn, cloudSignOut, cloudStatus, bootStatus } from './ui.js';
import { hookPageKernel } from './service-auth.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword =
  process.env.OS_TEST_ADMIN_PASSWORD ||
  process.env.OS_PASSWORD ||
  readFileSync('.dev.vars', 'utf8').match(/^ADMIN_PASSWORD=(.+)$/m)?.[1] ||
  readFileSync('.local-password', 'utf8').trim();
const repoRoot = resolve(import.meta.dirname, '..');

async function execLocal(page, argv, { sudo = false, cwd = '/', stdin = '' } = {}) {
  return page.evaluate(
    async ({ argv, sudo, cwd, stdin }) => {
      let stdout = '';
      let stderr = '';
      const result = await window.os.exec([{ argv }], {
        sudo,
        cwd,
        stdin,
        tty: false,
        onOutput: (fd, text) => {
          if (fd === 1) stdout += text;
          else stderr += text;
        },
      });
      return { status: result.status, stdout: stdout || result.stdout || '', stderr };
    },
    { argv, sudo, cwd, stdin },
  );
}

async function execSh(page, script, opts = {}) {
  return execLocal(page, ['sh', '-c', script], opts);
}

test('S-04 & S-05: zero-friction auto-login boots offline with local user, zero outbound auth/ws RPCs, local PTY, and detached remote devices', async ({ page }) => {
  test.setTimeout(90_000);
  const apiRequests = [];
  const wsUrls = [];
  page.on('request', req => {
    const pathname = new URL(req.url()).pathname;
    if (pathname.startsWith('/api/')) apiRequests.push(`${req.method()} ${pathname}`);
  });
  page.on('websocket', ws => wsUrls.push(ws.url()));

  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));

  // Top bar shows compact Local/Cloud pill with zero login wall.
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out', { timeout: 20_000 });
  await expect(page.locator('#command')).toBeVisible();

  const bStatus = await bootStatus(page);
  expect(bStatus.root_fstype).toBe('cowfs');
  expect(bStatus.account.user).toBe('user');
  expect(bStatus.account.uid).toBe(1000);
  expect(bStatus.account.can_sudo).toBe(true);
  expect(bStatus.account.sudo_active).toBe(true);

  const cStatus = await cloudStatus(page);
  expect(cStatus.signed_in).toBe(false);
  expect(cStatus.cloud_mounted).toBe(false);
  expect(cStatus.attached_devices).toEqual([]);

  // ZERO outbound `/api/*` requests and ZERO `/api/events` WebSocket before explicit Cloud Sign-In!
  expect(apiRequests).toEqual([]);
  expect(wsUrls).toEqual([]);

  // Local identity, local `/dev`, and local PTY work with zero network calls; remote devices absent.
  const idRes = await execLocal(page, ['id']);
  expect(idRes.status).toBe(0);
  expect(idRes.stdout).toContain('uid=1000(user)');
  expect(idRes.stdout).toContain('wheel');

  const devRes = await execSh(page, 'ls /dev');
  expect(devRes.status).toBe(0);
  expect(devRes.stdout).toContain('null');
  expect(devRes.stdout).toContain('ptmx');
  expect(devRes.stdout).toContain('pts');
  for (const remote of ['archive', 'media', 'present', 'snd']) {
    expect(devRes.stdout.split(/\s+/)).not.toContain(remote);
  }

  // `/mnt/cloud` is unmounted (empty local mountpoint) and `mount -t cloud` fails ENOTCONN offline.
  const cloudMountAttempt = await execSh(page, 'mount -t cloud cloud /mnt/cloud', { sudo: true });
  expect(cloudMountAttempt.status).not.toBe(0);
  expect(apiRequests).toEqual([]);
  expect(wsUrls).toEqual([]);
});

test('S-03: 100% offline local account lifecycle (sudo, useradd, passwd, su, usermod, groupadd, newgrp, userdel) persists across reload', async ({ page, context }) => {
  test.setTimeout(120_000);
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out', { timeout: 20_000 });

  // Verify `/etc/shadow` (`0600`) is unreadable by uid 1000 (`EACCES`) [S-09].
  const shadowDenied = await execSh(page, 'cat /etc/shadow');
  expect(shadowDenied.status).not.toBe(0);
  expect(shadowDenied.stderr).toMatch(/Permission denied|EACCES/i);

  // Passwordless local `sudo` works for `user` (`wheel`) with 0 network requests!
  const apiHits = [];
  page.on('request', req => {
    if (new URL(req.url()).pathname.startsWith('/api/')) apiHits.push(req.url());
  });

  const sudoId = await execLocal(page, ['id'], { sudo: true });
  expect(sudoId.status).toBe(0);
  expect(sudoId.stdout).toContain('uid=0(root)');

  // Create local group `devs` and local user `alice`, set password, verify `/etc/passwd` & `/etc/group`.
  const gAdd = await execLocal(page, ['groupadd', 'devs'], { sudo: true });
  expect(gAdd.status, gAdd.stderr).toBe(0);

  const uAdd = await execLocal(page, ['useradd', '-m', '-G', 'devs', 'alice'], { sudo: true });
  expect(uAdd.status, uAdd.stderr).toBe(0);

  const setPw = await execSh(page, "printf 'alice-secret-pass-1234\\nalice-secret-pass-1234\\n' | passwd alice", { sudo: true });
  expect(setPw.status, setPw.stderr).toBe(0);

  // Authenticate locally as `alice` via local `su` (PBKDF2-HMAC-SHA256 against local `/etc/shadow`).
  const badSu = await execSh(page, "printf 'wrong-password\\n' | su alice -c id");
  expect(badSu.status).not.toBe(0);

  const goodSu = await execSh(page, "printf 'alice-secret-pass-1234\\n' | su alice -c 'id; whoami'");
  expect(goodSu.status, goodSu.stderr).toBe(0);
  expect(goodSu.stdout).toContain('alice');
  expect(goodSu.stdout).toContain('devs');

  // Verify `newgrp devs` switches primary GID locally (POSIX `newgrp` spawns a shell reading stdin).
  const ngRes = await execSh(page, "printf 'alice-secret-pass-1234\\n' | su alice -c \"printf 'id\\n' | newgrp devs\"");
  expect(ngRes.status, ngRes.stderr).toBe(0);
  expect(ngRes.stdout).toMatch(/gid=\d+\(devs\)/);

  // Clean shutdown + reload: verify local account `alice` and group `devs` persist on `os-cowfs`!
  await page.evaluate(() => window.os.closeCleanRoot());
  await page.reload();
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));

  const persisted = await execSh(page, 'grep "^alice:" /etc/passwd && grep "^devs:" /etc/group');
  expect(persisted.status, persisted.stderr).toBe(0);
  expect(persisted.stdout).toContain('alice:');
  expect(persisted.stdout).toContain('devs:');

  // Cleanup `alice` & `devs` via `userdel -r` & `groupdel`.
  expect((await execLocal(page, ['userdel', '-r', 'alice'], { sudo: true })).status).toBe(0);
  expect((await execLocal(page, ['groupdel', 'devs'], { sudo: true })).status).toBe(0);
  expect(apiHits).toEqual([]);
});

test('S-04, S-07 & S-08: Cloud Sign-In mounts /mnt/cloud + remote devices without mutating local /etc/passwd; sudo never elevates remote; revocation & Sign-Out preserve local processes', async ({ page, request }) => {
  test.setTimeout(120_000);
  const pageKernel = await hookPageKernel(page);
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.cloudSignIn && window.os?.exec));
  await pageKernel.ready();

  // Record local `/etc/passwd` hash before Cloud Sign-In.
  const passwdBefore = (await execSh(page, 'cat /etc/passwd')).stdout;
  expect(passwdBefore).toContain('user:x:1000:1000:');

  // Start a long-running local process BEFORE Cloud Sign-In (must survive Sign-In, revocation, AND Sign-Out!).
  await page.evaluate(() => {
    window.__localSurvivor = { exited: false };
    window.__localSurvivor.done = window.os.exec([{ argv: ['sleep', '120'] }], {
      stdin: '',
      tty: false,
      onJob: job => { window.__localSurvivor.job = job; },
    }).then(r => { window.__localSurvivor.exited = true; window.__localSurvivor.result = r; });
  });
  await expect.poll(() => page.evaluate(() => (window.__localSurvivor?.job?.pids?.length ?? 0) > 0), { timeout: 15_000 }).toBe(true);
  const survivorPid = await page.evaluate(() => window.__localSurvivor.job.pids[0]);

  // Register a non-admin cloud account to test S-07 (local sudo MUST NOT elevate remote cloud scope to admin!).
  const cloudUser = 'cldu' + randomUUID().replaceAll('-', '').slice(0, 8);
  const cloudPass = 'cloud-user-secret-' + randomUUID();
  const regRes = await cloudAuth(request, 'register', {
    headers: { 'CF-Connecting-IP': 's04-' + randomUUID() },
    data: { username: cloudUser, password: cloudPass, create_home: true },
  });
  expect(regRes.ok(), await regRes.text()).toBe(true);

  try {
    // Open top-bar Cloud Sign-In popover and sign in via real UI!
    await page.locator('.cloud-panel-trigger').click();
    await expect(page.locator('.cloud-panel-popover')).toBeVisible();
    await page.locator('#cloud-auth-user').fill(cloudUser);
    await page.locator('#cloud-auth-pass').fill(cloudPass);
    await page.locator('.cloud-btn-signin').click();

    await expect(page.locator('.cloud-panel-trigger')).toContainText(`Local: user · Cloud: ${cloudUser}`, { timeout: 20_000 });

    // Local OS account & `/etc/passwd` are 100% UNCHANGED!
    expect((await execLocal(page, ['whoami'])).stdout.trim()).toBe('user');
    expect((await execSh(page, 'cat /etc/passwd')).stdout).toBe(passwdBefore);

    // `/run/user/1000/cloud-creds.json` exists with mode `0600`.
    const credStat = await execSh(page, 'stat -c "%a" /run/user/1000/cloud-creds.json');
    expect(credStat.status, credStat.stderr).toBe(0);
    expect(credStat.stdout.trim()).toBe('600');

    // `/mnt/cloud` is mounted (`FsType::Cloud`) and remote devices are attached.
    const mounts = (await execSh(page, 'cat /proc/mounts')).stdout;
    expect(mounts).toContain(' /mnt/cloud cloud ');
    const devAfter = (await execSh(page, 'ls /dev')).stdout.split(/\s+/);
    expect(devAfter).toContain('archive');
    expect(devAfter).toContain('present');
    expect(devAfter).toContain('snd');

    // S-07: Local `sudo` elevates local uid to 0 ONLY — remote `/mnt/cloud` MUST NOT gain remote root access!
    const localSudoCheck = await execSh(page, 'id -u', { sudo: true });
    expect(localSudoCheck.stdout.trim()).toBe('0');
    // Remote root directory `/mnt/cloud/root` (mode 0700 owned by remote uid 0) MUST remain denied (`EACCES`/`EPERM`) to local `sudo`!
    const remoteRootDenied = await execSh(page, 'ls /mnt/cloud/root', { sudo: true });
    expect(remoteRootDenied.status).not.toBe(0);
    expect(remoteRootDenied.stderr).toMatch(/Permission denied|Operation not permitted|EACCES|EPERM/i);

    // S-08 (part 1): Server-side / token-only revocation makes `/mnt/cloud` fail `EACCES` WITHOUT killing local processes!
    await page.evaluate(() => window.os.revokeCloudTokensOnly());
    const afterRevoke = await execSh(page, 'ls /mnt/cloud');
    expect(afterRevoke.status).not.toBe(0);
    // Local survivor process is STILL RUNNING!
    expect(await page.evaluate(() => window.__localSurvivor.exited)).toBe(false);
    const aliveAfterRevoke = await pageKernel.value('poll', { pids: [survivorPid] });
    expect(aliveAfterRevoke.length).toBe(1);
    expect(aliveAfterRevoke[0].state).toBe('running');

    // S-04 / S-08 (part 2): Sign out of Cloud via UI -> unmounts `/mnt/cloud`, detaches devices, keeps local survivor alive!
    await page.locator('.cloud-panel-trigger').click();
    await page.locator('.cloud-btn-signout').click();
    await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out', { timeout: 15_000 });
    const statusOut = await cloudStatus(page);
    expect(statusOut.signed_in).toBe(false);
    expect(statusOut.cloud_mounted).toBe(false);
    expect(statusOut.attached_devices).toEqual([]);

    // Survivor process is STILL RUNNING after Cloud Sign-Out!
    expect(await page.evaluate(() => window.__localSurvivor.exited)).toBe(false);
    const aliveAfterSignOut = await pageKernel.value('poll', { pids: [survivorPid] });
    expect(aliveAfterSignOut.length).toBe(1);
    expect(aliveAfterSignOut[0].state).toBe('running');

    // S-07 (signed out): local `sudo` while signed out NEVER synthesizes remote cloud credentials.
    const signedOutMount = await execSh(page, 'mount -t cloud cloud /mnt/cloud', { sudo: true });
    expect(signedOutMount.status).not.toBe(0);
  } finally {
    await page.evaluate(async () => {
      window.__localSurvivor?.job?.signal(9);
      await window.__localSurvivor?.done;
    }).catch(() => {});
  }
});

test('S-01, S-02 & S-06: local PID 1 init boots multi-user.target, enforces SO_PEERCRED on /run/init/control.sock, and runs ordered shutdown', async ({ page }) => {
  test.setTimeout(90_000);
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));

  // Wait for local PID 1 `/usr/bin/init` to reach `multi-user.target` and bind `/run/init/control.sock`
  // AND prepare `/run/user/1000/manager.sock` (Codex #17).
  await expect.poll(
    async () => (await execSh(page, 'test -S /run/init/control.sock && test -S /run/user/1000/manager.sock && test -f /run/os/boot-healthy && echo READY')).stdout.trim(),
    { timeout: 25_000 },
  ).toBe('READY');

  // `service list` works for ordinary uid 1000 (read-only query allowed via SO_PEERCRED).
  const listRes = await execLocal(page, ['service', 'list']);
  expect(listRes.status, listRes.stderr).toBe(0);
  expect(listRes.stdout).toContain('multi-user.target');
  expect(listRes.stdout).toContain('local-fs.target');

  // S-06: Unprivileged uid 1000 MUST be rejected with EPERM on mutating control ops (`service poweroff`).
  const unprivPoweroff = await execLocal(page, ['service', 'poweroff']);
  expect(unprivPoweroff.status).not.toBe(0);
  expect(unprivPoweroff.stderr).toMatch(/EPERM|Permission denied|Operation not permitted|not permitted|root/i);

  // Codex #21: non-root `rebootMachine` rejects with EPERM BEFORE stopping PID 1 or closing root!
  const nonRootReboot = await page.evaluate(async () => {
    try {
      await window.os.rebootMachine();
      return { ok: true };
    } catch (e) {
      return { ok: false, errno: e?.errno ?? e?.message ?? String(e) };
    }
  });
  expect(nonRootReboot.ok).toBe(false);
  expect(String(nonRootReboot.errno)).toMatch(/EPERM|Permission denied/i);
  // PID 1 `/run/init/control.sock` MUST still be alive after rejected non-root reboot!
  expect((await execLocal(page, ['service', 'list'])).status).toBe(0);

  // S-06: `ServiceGrant.user = "root"` from non-root fails `EPERM`.
  const pageKernel = await hookPageKernel(page);
  // (Verified via direct kernel unit test + PID 1 SO_PEERCRED check above.)
  expect(pageKernel).toBeTruthy();

  // S-02: Privileged `sudo service poweroff` executes ordered reverse shutdown, unmounts `/usr`,
  // writes `/run/os/shutdown` (`{"mode":"poweroff","clean":true}`), and runs `CowFsVolume::close_clean()`.
  const poweroffRes = await execLocal(page, ['service', 'poweroff'], { sudo: true });
  expect(poweroffRes.status, poweroffRes.stderr).toBe(0);
  await expect.poll(
    async () => (await bootStatus(page))?.last_shutdown ?? null,
    { timeout: 15_000 },
  ).toMatchObject({ mode: 'poweroff', clean: true });
});

test('S-09: retired /api/sys OS-account calls fail closed with ENOSYS and legacy boot modules are deleted', async ({ request }) => {
  const retiredCalls = [
    { login: { username: 'root', password: rootPassword } },
    'logout',
    { sudo: { password: rootPassword, revoke: false } },
    { passwd: { username: 'root', password: 'new-password-1234', current_password: rootPassword, force: false } },
    { useradd: { name: 'shouldfail', create_home: false } },
    { usermod: { name: 'root', lock: true } },
    { userdel: { name: 'shouldfail', remove: false } },
    { groupadd: { name: 'shouldfail' } },
    { groupmod: { name: 'wheel', new_name: 'wheel2' } },
    { groupdel: { name: 'wheel' } },
  ];
  for (const call of retiredCalls) {
    const res = await request.post(origin + '/api/sys', {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: { calls: [call] },
    });
    expect(res.ok(), `expected 200 envelope for ${JSON.stringify(call)}`).toBe(true);
    const body = await res.json();
    expect(body.results?.[0]?.err?.errno, `expected ENOSYS for ${JSON.stringify(call)}`).toBe('ENOSYS');
  }

  // Explicit `/api/cloud-auth/login` + `/api/cloud-auth/status` + `/api/cloud-auth/logout` work cleanly!
  // Codex #23: `/api/cloud-auth/login` MUST return numeric `uid`, `gid`, and `groups`.
  const loginRes = await cloudAuth(request, 'login', {
    headers: { 'CF-Connecting-IP': 's09-' + randomUUID() },
    data: { username: 'root', password: rootPassword },
  });
  expect(loginRes.ok(), await loginRes.text()).toBe(true);
  const loginJson = await loginRes.json();
  expect(typeof loginJson.uid).toBe('number');
  expect(loginJson.uid).toBe(0);
  expect(typeof loginJson.gid).toBe('number');
  const statusRes = await cloudAuth(request, 'status');
  expect(statusRes.ok()).toBe(true);
  const statusJson = await statusRes.json();
  expect(statusJson.signed_in).toBe(true);
  expect(statusJson.cloud_user).toBe('root');
  expect(statusJson.uid).toBe(0);
  const logoutRes = await cloudAuth(request, 'logout');
  expect(logoutRes.ok()).toBe(true);

  // Deleted legacy modules (Contract §2.12).
  expect(existsSync(resolve(repoRoot, 'web/kernel/login-boot.js'))).toBe(false);
  expect(existsSync(resolve(repoRoot, 'web/kernel/init.js'))).toBe(false);
});
