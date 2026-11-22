// Wave 4B Local OS Accounts E2E Suite (migrated for #57 L3d, Contract v2 §2.1 & §2.12).
// Verifies 100% offline local `/etc/{passwd,group,shadow,sudoers}`, passwordless `wheel` sudo,
// local `useradd`/`usermod`/`userdel`/`groupadd`/`groupmod`/`groupdel`/`passwd`/`su`/`newgrp`
// persistence across reload, strict `/etc/shadow` `0600` protection, and `ENOSYS` on retired
// `/api/sys` OS-account calls.
import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword =
  process.env.OS_TEST_ADMIN_PASSWORD ||
  process.env.OS_PASSWORD ||
  (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];

const busy = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();

async function run(page, text) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await page.locator('#command').fill(text);
  await page.locator('#command').press('Enter');
}

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

test('default local user auto-logs in with wheel NOPASSWD sudo and 0 outbound auth requests', async ({ page }) => {
  const apiHits = [];
  page.on('request', req => {
    if (new URL(req.url()).pathname.startsWith('/api/')) apiHits.push(req.url());
  });
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out', { timeout: 20_000 });

  await run(page, 'whoami');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 15_000 });
  await expect(last(page)).toHaveText('user');

  const sudoId = await execLocal(page, ['id'], { sudo: true });
  expect(sudoId.status).toBe(0);
  expect(sudoId.stdout).toContain('uid=0(root)');

  // `/etc/shadow` is mode 0600 owned by root: unprivileged uid 1000 cannot read it.
  const shadowDenied = await execLocal(page, ['cat', '/etc/shadow']);
  expect(shadowDenied.status).not.toBe(0);
  expect(shadowDenied.stderr).toMatch(/Permission denied|EACCES/i);

  // Local `/dev` starts with local byte/PTY devices only; remote `/dev/present` and `/dev/snd` stay detached until Cloud Sign-In.
  const devList = (await execLocal(page, ['ls', '/dev'])).stdout.split(/\s+/);
  expect(devList).toContain('null');
  expect(devList).toContain('ptmx');
  expect(devList).not.toContain('present');
  expect(devList).not.toContain('snd');
  expect(apiHits).toEqual([]);
});

test('local useradd, usermod, passwd, su, groupadd, groupmod, groupdel, and userdel enforce root permission and persist across reload', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));

  const uname = 'loc' + Date.now().toString(36).slice(-5);
  const gname = 'grp' + Date.now().toString(36).slice(-5);
  const gname2 = gname + 'r';
  const pw = 'local-secret-password-' + Date.now();

  // Unprivileged uid 1000 cannot mutate `/etc/{passwd,group,shadow}` directly.
  const deniedAdd = await execLocal(page, ['useradd', '-m', uname]);
  expect(deniedAdd.status).not.toBe(0);
  const deniedGroup = await execLocal(page, ['groupadd', gname]);
  expect(deniedGroup.status).not.toBe(0);

  // Root (`sudo`) creates group, renames group, adds user with home, sets password, and locks/unlocks.
  expect((await execLocal(page, ['groupadd', gname], { sudo: true })).status).toBe(0);
  expect((await execLocal(page, ['groupmod', '-n', gname2, gname], { sudo: true })).status).toBe(0);
  expect((await execLocal(page, ['useradd', '-m', '-G', gname2, uname], { sudo: true })).status).toBe(0);

  const passwdRes = await execLocal(page, ['sh', '-c', `printf '%s\\n%s\\n' '${pw}' '${pw}' | passwd '${uname}'`], { sudo: true });
  expect(passwdRes.status, passwdRes.stderr).toBe(0);

  const suOk = await execLocal(page, ['sh', '-c', `printf '%s\\n' '${pw}' | su '${uname}' -c 'id; pwd'`]);
  expect(suOk.status, suOk.stderr).toBe(0);
  expect(suOk.stdout).toContain(`(${uname})`);
  expect(suOk.stdout).toContain(`(${gname2})`);

  // Lock account -> `su` fails with EACCES; unlock -> `su` succeeds again.
  expect((await execLocal(page, ['usermod', '-L', uname], { sudo: true })).status).toBe(0);
  const suLocked = await execLocal(page, ['sh', '-c', `printf '%s\\n' '${pw}' | su '${uname}' -c id`]);
  expect(suLocked.status).not.toBe(0);
  expect((await execLocal(page, ['usermod', '-U', uname], { sudo: true })).status).toBe(0);
  const suUnlocked = await execLocal(page, ['sh', '-c', `printf '%s\\n' '${pw}' | su '${uname}' -c id`]);
  expect(suUnlocked.status, suUnlocked.stderr).toBe(0);

  // Reload page -> local account & home persist on `os-cowfs`!
  await page.evaluate(() => window.os.closeCleanRoot());
  await page.reload();
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));

  const checkAfter = await execLocal(page, ['sh', '-c', `grep "^${uname}:" /etc/passwd && test -d "/home/${uname}"`]);
  expect(checkAfter.status, checkAfter.stderr).toBe(0);

  // Non-root cannot delete another account; root `userdel -r` deletes account & home cleanly.
  expect((await execLocal(page, ['userdel', '-r', uname])).status).not.toBe(0);
  expect((await execLocal(page, ['userdel', '-r', uname], { sudo: true })).status).toBe(0);
  expect((await execLocal(page, ['groupdel', gname2], { sudo: true })).status).toBe(0);
  const gone = await execLocal(page, ['sh', '-c', `test ! -e "/home/${uname}" && ! grep -q "^${uname}:" /etc/passwd`]);
  expect(gone.status).toBe(0);
});

test('server /api/sys fails closed with ENOSYS on retired OS account mutations', async ({ request }) => {
  for (const op of [
    { login: { username: 'root', password: rootPassword } },
    'logout',
    { sudo: { password: rootPassword, revoke: false } },
    { useradd: { name: 'noserver', create_home: false } },
    { userdel: { name: 'noserver', remove: false } },
    { groupadd: { name: 'noserver' } },
  ]) {
    const res = await request.post(origin + '/api/sys', {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: { calls: [op] },
    });
    expect(res.ok()).toBe(true);
    const body = await res.json();
    expect(body.results?.[0]?.err?.errno).toBe('ENOSYS');
  }
});
