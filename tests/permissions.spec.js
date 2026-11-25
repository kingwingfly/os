// Wave 4B Local OS Permissions, DAC & Account Security E2E Suite (migrated for #57 L3d, Contract v2).
// Verifies owner/group/other DAC, supplementary group sharing, directory traversal & unsearchable
// destination hiding, sudo/wheel enforcement & live revocation, home moves, password/lock
// enforcement, groupmod/groupdel by name (never numeric GID), local terminal account workflow
// with Cloud Sign-In top-bar panel, and fail-closed CSRF + ENOSYS on retired server /api/sys calls.
import { test, expect } from './test.js';
import {
  pageCall,
  pageErrno,
  pageGetText,
  pageMkdirp,
  pagePut,
  pageRmrf,
  pageSys,
  runTerminal,
  switchLocalUser,
  terminalScreen,
  waitForDesktopReady,
} from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = 'testing-long-passphrase-8274';

async function bootLocal(page) {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.bootStatus && window.os?.exec));
  await waitForDesktopReady(page, 25_000);
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
          if (fd === 2) stderr += text;
          else stdout += text;
        },
      });
      return { status: result.status, stdout: result.stdout || stdout, stderr };
    },
    { argv, sudo, cwd, stdin },
  );
}

async function execSh(page, script, opts = {}) {
  return execLocal(page, ['sh', '-c', script], opts);
}

async function asRoot(page) {
  return switchLocalUser(page, 'root', { password, sudo: false });
}

async function setupLocalAccounts(page) {
  const suffix = Date.now().toString(36).slice(-5) + Math.random().toString(36).slice(2, 4);
  const a = 'alice' + suffix;
  const b = 'bob' + suffix;
  const team = 'team' + suffix;
  await switchLocalUser(page, 'root');
  await pageCall(page, { passwd: { username: 'root', password, force: true } });
  await pageCall(page, { passwd: { username: 'user', password, force: true } });
  expect((await execLocal(page, ['groupadd', team])).status).toBe(0);
  for (const name of [a, b]) {
    const add = await execLocal(page, ['useradd', '-m', '-G', team, name]);
    expect(add.status, add.stderr).toBe(0);
    await pageCall(page, { passwd: { username: name, password, force: true } });
  }
  return {
    a,
    b,
    team,
    home: '/home/' + a,
    async cleanup() {
      await asRoot(page).catch(() => {});
      for (const name of [a, b]) await execLocal(page, ['userdel', '-r', name]).catch(() => {});
      for (const name of [a, b, team]) await execLocal(page, ['groupdel', name]).catch(() => {});
      await switchLocalUser(page, 'user', { password, sudo: false }).catch(() => {});
    },
  };
}

test('owner/group/other, traversal, revocation, root bypass, and cross-origin CSRF are enforced', async ({ page, request }) => {
  await bootLocal(page);
  const f = await setupLocalAccounts(page);
  const { a, b, team, home } = f;
  const path = home + '/private.txt';
  try {
    // Alice writes private file inside her 0700 home directory.
    await switchLocalUser(page, a, { password, sudo: false });
    await pagePut(page, path, '0123456789', { mode: 0o600 });

    // Bob (another non-root user) is denied reading and stating inside alice's 0700 home.
    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageGetText(page, path)).toBe(null);
    expect(await pageErrno(page, { stat: { path } })).toBe('EACCES');

    // Alice opens home to 0750 (still owned by alice:alice) -> bob still denied.
    await switchLocalUser(page, a, { password, sudo: false });
    expect((await execLocal(page, ['chmod', '750', home])).status).toBe(0);
    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageGetText(page, path)).toBe(null);

    // Alice shares via supplementary group `team` (0750 dir, 0640 file) -> bob can read.
    await switchLocalUser(page, a, { password, sudo: false });
    expect((await execLocal(page, ['chown', ':' + team, home])).status).toBe(0);
    expect((await execLocal(page, ['chown', ':' + team, path])).status).toBe(0);
    expect((await execLocal(page, ['chmod', '640', path])).status).toBe(0);

    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageGetText(page, path)).toBe('0123456789');
    const rangeRes = await page.evaluate(async p => {
      const r = await fetch('/api/file?path=' + encodeURIComponent(p), { headers: { Range: 'bytes=2-4' } });
      return { status: r.status, text: await r.text() };
    }, path);
    expect(rangeRes).toEqual({ status: 206, text: '234' });

    // Alice revokes group read (`g-r`) -> bob immediately denied.
    await switchLocalUser(page, a, { password, sudo: false });
    expect((await execLocal(page, ['chmod', 'g-r', path])).status).toBe(0);
    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageGetText(page, path)).toBe(null);

    // Mode 0604: group membership chooses group bits (0) even when other bits permit reading (4)!
    await switchLocalUser(page, a, { password, sudo: false });
    expect((await execLocal(page, ['chmod', '604', path])).status).toBe(0);
    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageGetText(page, path)).toBe(null);
    expect((await execLocal(page, ['chmod', '777', path])).status).not.toBe(0);

    // Non-root cannot chown file to root:root.
    await switchLocalUser(page, a, { password, sudo: false });
    expect((await execLocal(page, ['chown', 'root:root', path])).status).not.toBe(0);

    // Mode 0711 on home allows `user` (not in `team`) to read `path` via other bits (604),
    // while denying `getdents` on `home`.
    expect((await execLocal(page, ['chmod', '711', home])).status).toBe(0);
    await switchLocalUser(page, 'user', { password, sudo: false });
    expect(await pageGetText(page, path)).toBe('0123456789');
    expect(await pageErrno(page, { getdents: { path: home } })).toBe('EACCES');

    // Mode 0000 blocks non-root, while local root bypasses DAC.
    await switchLocalUser(page, a, { password, sudo: false });
    expect((await execLocal(page, ['chmod', '000', home])).status).toBe(0);
    await asRoot(page);
    expect(await pageGetText(page, path)).toBe('0123456789');
    expect((await execLocal(page, ['chmod', '700', home])).status).toBe(0);

    // Traversal `..` into `/root` is denied for non-root.
    await switchLocalUser(page, a, { password, sudo: false });
    expect(await pageErrno(page, { stat: { path: '/home/../root/secret.txt' } })).toBe('EACCES');

    // Cross-origin CSRF on `/api/sys` fails closed with 403 on the server boundary.
    const csrf = await request.post(origin + '/api/sys', {
      headers: { Origin: 'https://evil.invalid' },
      data: { calls: [{ chmod: { path: home, mode: 0o777 } }] },
    });
    expect(csrf.status()).toBe(403);
  } finally {
    await f.cleanup();
  }
});

test('local sudo verifies wheel membership, revokes immediately, moves homes, and enforces lock/passwd', async ({ page }) => {
  await bootLocal(page);
  const f = await setupLocalAccounts(page);
  const { a, b, team, home } = f;
  const next = '/home/moved-' + a;
  try {
    // Non-wheel user cannot use sudo.
    await switchLocalUser(page, a, { password, sudo: false });
    await expect(execLocal(page, ['id', '-u'], { sudo: true })).rejects.toThrow(/Operation not permitted|EPERM/i);

    // Adding `a` to `wheel` enables local sudo (`id -u == 0`), while ordinary commands remain uid of `a`.
    await asRoot(page);
    expect((await execLocal(page, ['usermod', '-aG', 'wheel', a])).status).toBe(0);
    await switchLocalUser(page, a, { password, sudo: false });
    expect((await execLocal(page, ['id', '-u'], { sudo: true })).stdout.trim()).toBe('0');
    expect((await execLocal(page, ['whoami'])).stdout.trim()).toBe(a);
    expect(await pageErrno(page, { getdents: { path: '/root' } })).toBe('EACCES');

    // Removing `a` from `wheel` revokes sudo immediately!
    await asRoot(page);
    expect((await execLocal(page, ['usermod', '-G', team, a])).status).toBe(0);
    await switchLocalUser(page, a, { password, sudo: false });
    expect(await pageErrno(page, { sudo: { password, revoke: false } })).toBe('EPERM');

    // Home move (`usermod -d <next> -m`) preserves contents, mode `0600`, and owner; moving inside self fails.
    await pagePut(page, home + '/kept.txt', 'preserve bytes', { mode: 0o600 });
    await asRoot(page);
    const mvHome = await execLocal(page, ['usermod', '-d', next, '-m', a]);
    expect(mvHome.status, mvHome.stderr).toBe(0);
    await switchLocalUser(page, a, { password, sudo: false });
    expect(await pageGetText(page, home + '/kept.txt')).toBe(null);
    expect(await pageGetText(page, next + '/kept.txt')).toBe('preserve bytes');
    const st = await pageCall(page, { stat: { path: next + '/kept.txt' } });
    expect(st.mode & 0o777).toBe(0o600);
    expect(st.user).toBe(a);
    await asRoot(page);
    expect((await execLocal(page, ['usermod', '-d', next + '/inside', '-m', a])).status).not.toBe(0);

    // Locking (`usermod -L`) blocks non-root local password login until unlocked (`usermod -U`).
    expect((await execLocal(page, ['usermod', '-L', a])).status).toBe(0);
    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageErrno(page, { login: { username: a, password } })).toBe('EACCES');
    await asRoot(page);
    expect((await execLocal(page, ['usermod', '-U', a])).status).toBe(0);

    // Changing password invalidates old password and accepts new password for non-root callers.
    await pageCall(page, { passwd: { username: a, password: password + 'new', force: true } });
    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageErrno(page, { login: { username: a, password } })).toBe('EACCES');
    const okLogin = await pageCall(page, { login: { username: a, password: password + 'new' } });
    expect(okLogin.user).toBe(a);

    // Protected system user `root` cannot be deleted; failed useradd does not leak private group.
    await asRoot(page);
    expect((await execLocal(page, ['userdel', 'root'])).status).not.toBe(0);
    expect((await execLocal(page, ['useradd', '-m', '-d', next, b + 'bad'])).status).not.toBe(0);
    expect((await execLocal(page, ['groupadd', b + 'bad'])).status).toBe(0);
    expect((await execLocal(page, ['groupdel', b + 'bad'])).status).toBe(0);
  } finally {
    await asRoot(page).catch(() => {});
    await pageRmrf(page, next).catch(() => {});
    await f.cleanup();
  }
});

test('public directory write, file overwrite, recursive deletion, and group renames', async ({ page }) => {
  await bootLocal(page);
  const f = await setupLocalAccounts(page);
  const { a, b, team } = f;
  const shared = '/tmp/shared-' + a;
  try {
    await asRoot(page);
    await pageMkdirp(page, shared, 0o755);
    expect((await execLocal(page, ['chmod', '777', shared])).status).toBe(0);

    // Another user writes and unlinks in world-writable dir; mode 755 blocks writes.
    await switchLocalUser(page, b, { password, sudo: false });
    await pagePut(page, shared + '/other.txt', 'other data');
    expect(await pageErrno(page, { unlink: { path: shared + '/other.txt' } })).toBe(null);

    await asRoot(page);
    expect((await execLocal(page, ['chmod', '755', shared])).status).toBe(0);
    await switchLocalUser(page, b, { password, sudo: false });
    await expect(pagePut(page, shared + '/denied.txt', 'x')).rejects.toThrow();

    // Group-writable dir (`770`): read-only file (`444`) cannot be overwritten, yet parent dir permits unlink!
    await asRoot(page);
    expect((await execLocal(page, ['chown', a + ':' + team, shared])).status).toBe(0);
    expect((await execLocal(page, ['chmod', '770', shared])).status).toBe(0);

    await switchLocalUser(page, a, { password, sudo: false });
    await pagePut(page, shared + '/locked.txt', 'old', { mode: 0o444 });
    await expect(pagePut(page, shared + '/locked.txt', 'new', { overwrite: true })).rejects.toThrow();

    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageErrno(page, { unlink: { path: shared + '/locked.txt' } })).toBe(null);

    // Private subdirectory owned by `a` (`0700`) cannot be recursively removed by `b`.
    await switchLocalUser(page, a, { password, sudo: false });
    await pageMkdirp(page, shared + '/private', 0o700);
    await pagePut(page, shared + '/private/keep.txt', 'intact');
    await switchLocalUser(page, b, { password, sudo: false });
    expect(await pageRmrf(page, shared)).toBe('EACCES');

    // `groupmod -n` renames the group reflected by stat, and primary user groups cannot be deleted.
    await asRoot(page);
    expect((await execLocal(page, ['groupmod', '-n', team + 'new', team])).status).toBe(0);
    expect((await pageCall(page, { stat: { path: shared } })).group).toBe(team + 'new');
    expect((await execLocal(page, ['groupdel', team + 'new'])).status).toBe(0);
    expect((await execLocal(page, ['groupadd', team])).status).toBe(0);
    expect((await execLocal(page, ['groupdel', a])).status).not.toBe(0);
  } finally {
    await asRoot(page).catch(() => {});
    await pageRmrf(page, shared).catch(() => {});
    await f.cleanup();
  }
});

test('file write and rename permissions follow current directory and file ownership', async ({ page }) => {
  await bootLocal(page);
  const f = await setupLocalAccounts(page);
  const { a } = f;
  const dir = '/tmp/upload-' + a;
  try {
    await asRoot(page);
    await pageMkdirp(page, dir, 0o755);
    expect((await execLocal(page, ['chown', a, dir])).status).toBe(0);

    await switchLocalUser(page, a, { password, sudo: false });
    await pagePut(page, dir + '/a.txt', 'init');

    // Shut `a` out of `dir` (`root:root`, `0700`) -> `a` cannot stat or write `dir/a.txt`.
    await asRoot(page);
    expect((await execLocal(page, ['chown', 'root', dir])).status).toBe(0);
    expect((await execLocal(page, ['chmod', '700', dir])).status).toBe(0);
    await switchLocalUser(page, a, { password, sudo: false });
    expect(await pageErrno(page, { stat: { path: dir + '/a.txt' } })).toBe('EACCES');
    await expect(pagePut(page, dir + '/a.txt', 'abcd')).rejects.toThrow();

    // Let `a` back in (`0755`), still owning `a.txt` -> write succeeds.
    await asRoot(page);
    expect((await execLocal(page, ['chmod', '755', dir])).status).toBe(0);
    await switchLocalUser(page, a, { password, sudo: false });
    await pagePut(page, dir + '/a.txt', 'abcd');
    expect(await pageGetText(page, dir + '/a.txt')).toBe('abcd');

    // Moving a file owned by `a` inside `a`'s directory preserves contents.
    await asRoot(page);
    expect((await execLocal(page, ['chown', a, dir])).status).toBe(0);
    await switchLocalUser(page, a, { password, sudo: false });
    await pagePut(page, dir + '/b.txt', 'wxyz');
    expect((await execLocal(page, ['mv', dir + '/b.txt', dir + '/c.txt'])).status).toBe(0);
    expect(await pageGetText(page, dir + '/c.txt')).toBe('wxyz');

    // Giving a file to `root` (`0600`) revokes `a`'s write permission.
    await pagePut(page, dir + '/d.txt', 'mine', { mode: 0o600 });
    await asRoot(page);
    expect((await execLocal(page, ['chown', 'root', dir + '/d.txt'])).status).toBe(0);
    await switchLocalUser(page, a, { password, sudo: false });
    await expect(pagePut(page, dir + '/d.txt', '1234')).rejects.toThrow();
  } finally {
    await asRoot(page).catch(() => {});
    await pageRmrf(page, dir).catch(() => {});
    await f.cleanup();
  }
});

test('cp and mv reveal nothing of destinations below a directory the caller may not search', async ({ page }) => {
  await bootLocal(page);
  const f = await setupLocalAccounts(page);
  const { a, home } = f;
  const hiddenRoot = '/root/acl-hidden-' + a;
  const dst = '/tmp/acl-merge-' + a;
  const hidden = dst + '/src/private';
  try {
    await asRoot(page);
    await pageMkdirp(page, hiddenRoot, 0o700);
    await switchLocalUser(page, a, { password, sudo: false });
    for (const name of ['one.txt', 'two.txt']) {
      await pagePut(page, home + '/' + name, name);
    }

    // Both existing and missing destinations under `/root` return identical `EACCES` & identical `mv` stderr (zero oracle).
    const mvErrors = [];
    for (const target of [hiddenRoot, '/root/acl-missing-' + a]) {
      expect(await pageErrno(page, { stat: { path: target } }), target).toBe('EACCES');
      expect(await pageErrno(page, { open: { path: target + '/one.txt', flags: 0o301, mode: 0o644, size: 3 } }), target).toBe('EACCES');
      const mvRes = await execLocal(page, ['mv', home + '/one.txt', home + '/two.txt', target]);
      expect(mvRes.status, target).not.toBe(0);
      mvErrors.push(mvRes.stderr.replace(target, '<TARGET>'));
    }
    expect(mvErrors[0]).toBe(mvErrors[1]);

    // Same below a deep unsearchable `0700` directory.
    await asRoot(page);
    await pageMkdirp(page, hidden, 0o700);
    expect((await execLocal(page, ['chmod', '777', dst, dst + '/src'])).status).toBe(0);
    expect((await execLocal(page, ['chmod', '700', hidden])).status).toBe(0);
    for (const leaf of [true, false]) {
      await asRoot(page);
      if (leaf) await pagePut(page, hidden + '/probe.txt', 'kept');
      else expect(await pageErrno(page, { unlink: { path: hidden + '/probe.txt' } })).toBe(null);
      await switchLocalUser(page, a, { password, sudo: false });
      expect(await pageErrno(page, { lstat: { path: hidden + '/probe.txt' } }), String(leaf)).toBe('EACCES');
    }
  } finally {
    await asRoot(page).catch(() => {});
    await pageRmrf(page, hiddenRoot).catch(() => {});
    await pageRmrf(page, dst).catch(() => {});
    await f.cleanup();
  }
});

test('groupmod and groupdel take a group by its name, as on Linux, never by number', async ({ page }) => {
  await bootLocal(page);
  const f = await setupLocalAccounts(page);
  const { a, team } = f;
  try {
    await switchLocalUser(page, 'root');
    // System group numbers cannot bypass name protection.
    for (const [gid, name] of [['0', 'root'], ['27', 'wheel']]) {
      expect((await execLocal(page, ['groupmod', '-n', 'renamed-' + team, gid])).status).not.toBe(0);
      expect((await execLocal(page, ['groupdel', gid])).status).not.toBe(0);
      expect((await execLocal(page, ['groupadd', name])).status).not.toBe(0);
    }
    const idOut = (await execLocal(page, ['id', a])).stdout;
    const gid = idOut.match(new RegExp('(\\d+)\\(' + team + '\\)'))[1];
    const delByNum = await execLocal(page, ['groupdel', gid]);
    expect(delByNum.status).not.toBe(0);
    expect((await execLocal(page, ['id', a])).stdout).toContain(`${gid}(${team})`);
  } finally {
    await f.cleanup();
  }
});

test('local terminal workflow enforces sudo, su, local accounts, top-bar Cloud panel, and server ENOSYS', async ({ page, request }) => {
  await bootLocal(page);
  const username = 'ui' + Date.now().toString(36).slice(-5);
  const home = '/home/' + username;
  const run = text => runTerminal(page, text);
  const screen = terminalScreen(page);

  try {
    // Auto-login as local `user` (uid 1000 in `wheel`), signed out of Cloud — zero login wall!
    await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: user · Cloud: Signed out', { timeout: 15_000 });
    await run('whoami');
    await expect(screen).toContainText('user');

    // Ordinary `user` cannot enter `/root`, but passwordless `wheel` `sudo` succeeds locally!
    await run('cd /root');
    await expect(screen).toContainText('Permission denied');
    await run('echo "SUDO_UID=$(sudo id -u)"');
    await expect(screen).toContainText('SUDO_UID=0');

    // Create a local non-wheel user with home directory & password via local `sudo`.
    await run('sudo useradd -m ' + username);
    await pageCall(page, { passwd: { username, password, force: true } }, { sudo: true });

    // `su <username>` authenticates locally, enters user's home, creates `0700` dir, and cannot sudo.
    const suCheck = await execSh(
      page,
      `printf '${password}\\n' | su - ${username} -c 'pwd && mkdir secrets && chmod 700 secrets && ls -ld secrets'`,
    );
    expect(suCheck.status, suCheck.stderr).toBe(0);
    expect(suCheck.stdout).toContain(home);
    expect(suCheck.stdout).toContain('drwx------');
    expect(suCheck.stdout).toContain(username);

    // Non-wheel user is refused local `sudo`.
    const suSudo = await execSh(page, `printf '${password}\\n' | su ${username} -c 'sudo id -u'`);
    expect(suSudo.status).not.toBe(0);

    // Retired server `/api/sys` account mutations fail closed with `ENOSYS`.
    const retired = await request.post(origin + '/api/sys', {
      headers: { Origin: origin, 'Content-Type': 'application/json' },
      data: { calls: [{ useradd: { name: 'nope', create_home: false } }, { groupadd: { name: 'nope' } }] },
    });
    const body = await retired.json();
    for (const row of body.results) {
      expect(row.err?.errno).toBe('ENOSYS');
    }
  } finally {
    await switchLocalUser(page, 'root').catch(() => {});
    await execLocal(page, ['userdel', '-r', username]).catch(() => {});
    await execLocal(page, ['groupdel', username]).catch(() => {});
    await switchLocalUser(page, 'user').catch(() => {});
  }
});
