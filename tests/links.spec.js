import { test, expect } from './test.js';
import { api, entry, errno, mkdirp, rmrf } from './sys.js';
import {
  cloudSignIn,
  logoutLocalUser,
  pageCall,
  pageErrno,
  pageGetText,
  pageMkdirp,
  pagePut,
  pageRmrf,
  switchLocalUser,
  waitForTerminalReady,
} from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = process.env.OS_TEST_ADMIN_PASSWORD || process.env.OS_PASSWORD || 'test-admin-password-w4b';
let base, cloudBase, headers;

test.beforeEach(async ({ page }) => {
  base = '/links-' + Date.now().toString(36);
  cloudBase = null;
  headers = { Origin: origin, 'CF-Connecting-IP': 'links-' + base };
  await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'links-ui-' + base });
});
test.afterEach(async ({ request, page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
  if (cloudBase) await rmrf(request, cloudBase).catch(() => {});
});

async function runSh(page, script, { cwd = '/', sudo = false } = {}) {
  const creds = await pageCall(page, 'getcreds');
  return page.evaluate(
    async ({ script, cwd, sudo, user, home }) => {
      let stderr = '';
      const result = await window.os.exec([{ path: '/usr/bin/sh', argv: ['sh', '-c', script] }], {
        cwd,
        user,
        home,
        sudo,
        stdin: '',
        onOutput(fd, text) {
          if (fd === 2) stderr += text;
        },
      });
      return { status: result.status, stdout: result.stdout ?? '', stderr };
    },
    { script, cwd, sudo, user: creds.user, home: creds.home },
  );
}
async function okSh(page, script, opts) {
  const res = await runSh(page, script, opts);
  expect(res.status, `${script}: ${res.stderr}`).toBe(0);
  return res.stdout.trim();
}
async function terminal(page) {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
  await switchLocalUser(page, 'root');
  for (const dir of ['', '/docs']) await pageMkdirp(page, base + dir, 0o755);
  for (const [name, text] of Object.entries({ 'a.md': 'alpha\n', 'docs/b.md': 'beta\n' })) {
    await pagePut(page, base + '/' + name, text, { mode: 0o644 });
  }
}

test('ln makes symbolic and hard links that behave as on Linux', async ({ page, request }) => {
  await terminal(page);
  const inBase = { cwd: base };
  await okSh(page, 'ln -s docs/b.md link.md', inBase);
  await okSh(page, 'ln a.md a-too.md', inBase);
  // ls -l shows where a link points, and how many names a file has.
  // Piped, a listing is text, a line an entry.
  const long = await okSh(page, 'ls -l | cat', inBase);
  expect(long).toMatch(/^lrwxrwxrwx +1 root root +9 [A-Z][a-z]{2} [ \d]\d [ \d:]{5} link\.md -> docs\/b\.md$/m);
  expect(long).toMatch(/^-rw-r--r-- +2 root root +6 [A-Z][a-z]{2} [ \d]\d [ \d:]{5} a-too\.md$/m);
  expect(await okSh(page, 'cat link.md', inBase)).toBe('beta');
  expect(await okSh(page, 'readlink link.md', inBase)).toBe('docs/b.md');
  expect(await okSh(page, 'readlink -f link.md', inBase)).toBe(base + '/docs/b.md');
  // Writing through one name of a file changes it under every name; chmod too.
  await pagePut(page, base + '/a-too.md', 'changed\n', { mode: 0o644, overwrite: true });
  expect(await pageGetText(page, base + '/a.md')).toBe('changed\n');
  await okSh(page, 'chmod 600 a-too.md', inBase);
  expect(await okSh(page, 'ls -l a.md', inBase)).toMatch(/^-rw------- +2 /);
  // rm removes a link, not what it points to; a name, not the file's other names.
  await okSh(page, 'rm link.md a.md', inBase);
  expect(await pageGetText(page, base + '/docs/b.md')).toBe('beta\n');
  expect(await pageGetText(page, base + '/a-too.md')).toBe('changed\n');
  // A link to a directory is entered by its name, and left the same way.
  await okSh(page, 'ln -s docs d', inBase);
  expect(await okSh(page, 'cd d && pwd && ls && cd .. && pwd', inBase)).toBe(`${base}/d\nb.md\n${base}`);
  // ls -ld shows the link itself; a trailing slash follows it.
  expect(await okSh(page, 'ls -ld d', inBase)).toContain('d -> docs');
  expect(await okSh(page, 'ls d/', inBase)).toBe('b.md');
  // Diagnostics belong to the installed uutils/WASI program.
  for (const [line, message] of [['ln docs hard', 'hard link not allowed for directory'], ['ln -s a-too.md docs/b.md', 'Already exists'], ['ln -s loop loop', '']]) {
    const res = await runSh(page, line, inBase);
    if (message) expect(res.stderr).toContain(message);
    else expect(res.status, res.stderr).toBe(0);
  }
  // The WASI platform adapter recognizes ELOOP and uses cat's normal diagnostic.
  const loopRes = await runSh(page, 'cat loop', inBase);
  expect(loopRes.status).not.toBe(0);
  expect(loopRes.stderr.trim()).toBe('cat: loop: Too many levels of symbolic links');
  // ln -sf repoints a link; fd -t l finds links.
  await okSh(page, 'ln -sfn a-too.md d', inBase);
  expect(await okSh(page, 'readlink d', inBase)).toBe('a-too.md');
  expect(await okSh(page, 'fd -t l | sort', inBase)).toBe('d\nloop');
  // cp follows a link named; -r copies links as links; -a keeps names of a file together.
  await okSh(page, 'ln a-too.md docs/a3.md', inBase);
  // The copy of a file with mode 600 is 600 too: the umask only takes away.
  await okSh(page, 'cp d plain.md', inBase);
  expect(await okSh(page, 'ls -l plain.md', inBase)).toMatch(/^-rw------- +1 /);
  await okSh(page, 'cp -r . ../copy-' + base.slice(1), inBase);
  expect(await okSh(page, `readlink ../copy-${base.slice(1)}/d`, inBase)).toBe('a-too.md');
  await okSh(page, 'cp -a . ../kept-' + base.slice(1), inBase);
  expect(await okSh(page, `ls -l ../kept-${base.slice(1)}/docs/a3.md`, inBase)).toMatch(/^-rw------- +2 /);
  for (const dir of ['copy', 'kept']) await pageRmrf(page, `/${dir}-${base.slice(1)}`);
  // ln -f replaces a name only once its link can be made: one that cannot leaves what was there.
  await okSh(page, 'mkdir t', inBase);
  for (const name of ['docs', 'a-too.md']) await pagePut(page, `${base}/t/${name}`, 'keep\n', { mode: 0o644 });
  const lnFail = await runSh(page, 'ln -f a-too.md docs t', inBase);
  expect(lnFail.stderr).toContain('hard link not allowed for directory');
  expect(await pageGetText(page, base + '/t/docs')).toBe('keep\n');
  expect(await pageGetText(page, base + '/t/a-too.md')).toBe('changed\n');
  // On CloudFs (`/mnt/cloud`), a file still uploading is copied once whole, also when a link leads to it.
  cloudBase = '/links-cloud-' + Date.now().toString(36);
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, cloudBase);
  expect(await errno(request, { open: { path: cloudBase + '/up.bin', flags: 0o101, size: 4 } })).toBe(null);
  await cloudSignIn(page, 'root', password);
  const inCloud = { cwd: '/mnt/cloud' + cloudBase };
  await okSh(page, 'mkdir withlink && ln -s ../up.bin withlink/l', inCloud);
  const cpBusy = await runSh(page, 'cp -rL withlink taken', inCloud);
  expect(cpBusy.stderr).toContain('Device or resource busy');
  expect(await entry(request, cloudBase + '/taken/l')).toBe(null);
  const lnBusy = await runSh(page, 'ln up.bin up-too.bin', inCloud);
  expect(lnBusy.stderr).toContain('Resource busy');
  expect(await entry(request, cloudBase + '/up-too.bin')).toBe(null);
});

async function switchAndSync(page, username, opts) {
  await switchLocalUser(page, username, opts);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('os:changed')));
  await expect(page.locator('.cloud-panel-trigger')).toContainText('Local: ' + username, { timeout: 10_000 });
}

test('local accounts share files with ACLs, sticky /tmp, and extended attributes', async ({ page }) => {
  const ada = 'ada' + Date.now().toString(36), bob = 'bob' + Date.now().toString(36), pass = 'local-acl-password-' + Date.now();
  await page.goto('/');
  await waitForTerminalReady(page);
  // Default auto-login is local `user` (uid 1000, in wheel).
  const id = await okSh(page, 'id');
  expect(id).toBe('uid=1000(user) gid=1000(user) groups=10(wheel),1000(user)');
  // Create two local accounts with private 0700 home directories via local `sudo`.
  await okSh(page, 'sudo useradd -m ' + ada);
  await okSh(page, 'sudo useradd -m ' + bob);
  try {
    await pageCall(page, { passwd: { username: ada, password: pass, force: true } }, { sudo: true });
    await pageCall(page, { passwd: { username: bob, password: pass, force: true } }, { sudo: true });
    await switchAndSync(page, ada, { password: pass, sudo: false });
    const adaHome = { cwd: '/home/' + ada };
    expect(await okSh(page, 'cd ~ && pwd')).toBe('/home/' + ada);
    expect(await okSh(page, 'groups', adaHome)).toBe(ada);
    expect(await okSh(page, 'ls -ld /tmp | cat', adaHome)).toMatch(/^drwxrwxrwt +\d+ root root/);
    expect(await okSh(page, 'ls -ld . | cat', adaHome)).toMatch(new RegExp(`^drwxr-x--- +2 ${ada} ${ada}`));
    // Homes are their owners' only.
    await okSh(page, 'touch note.txt', adaHome);
    await switchAndSync(page, bob, { password: pass, sudo: false });
    expect(await pageGetText(page, `/home/${ada}/note.txt`)).toBe(null);
    // ada lets bob through her home and read the note: named entries, bounded by the mask.
    await switchAndSync(page, ada, { password: pass, sudo: false });
    await okSh(page, `setfacl -m u:${bob}:x .`, adaHome);
    await okSh(page, `setfacl -m u:${bob}:rw note.txt`, adaHome);
    await switchAndSync(page, bob, { password: pass, sudo: false });
    expect(await pageGetText(page, `/home/${ada}/note.txt`)).toBe('');
    await switchAndSync(page, ada, { password: pass, sudo: false });
    expect(await okSh(page, 'ls -l note.txt', adaHome)).toMatch(/^-rw-rw-r--\+ /);
    await okSh(page, 'chmod g-w note.txt', adaHome);
    // Capture bytes before terminal tab expansion; the ACL and effective mask stay exact.
    await okSh(page, 'getfacl note.txt | tee acl.txt', adaHome);
    expect((await pageGetText(page, `/home/${ada}/acl.txt`)).trim()).toBe(`# file: home/${ada}/note.txt\n# owner: ${ada}\n# group: ${ada}\nuser::rw-\nuser:${bob}:rw-\t#effective:r--\ngroup::r--\nmask::r--\nother::r--`);
    await switchAndSync(page, bob, { password: pass, sudo: false });
    await expect(pagePut(page, `/home/${ada}/note.txt`, 'x', { overwrite: true })).rejects.toThrow();
    // A default ACL is what new files get.
    await switchAndSync(page, ada, { password: pass, sudo: false });
    await okSh(page, `setfacl -d -m u:${bob}:rw .`, adaHome);
    await okSh(page, 'touch later.txt', adaHome);
    expect(await okSh(page, 'getfacl -c later.txt', adaHome)).toContain(`user:${bob}:rw-`);
    // /tmp is sticky: anyone may put a file there, and only its owner remove it.
    await okSh(page, `touch /tmp/${ada}-shared.txt`, adaHome);
    await switchAndSync(page, bob, { password: pass, sudo: false });
    expect(await pageRmrf(page, `/tmp/${ada}-shared.txt`)).toBe('EPERM');
    await switchAndSync(page, ada, { password: pass, sudo: false });
    await okSh(page, `rm /tmp/${ada}-shared.txt`, adaHome);
    // Extended attributes go with the file, for whoever may write it.
    await okSh(page, 'setfattr -n user.status -v reviewed note.txt', adaHome);
    expect(await okSh(page, 'getfattr -d note.txt', adaHome)).toBe(`# file: home/${ada}/note.txt\nuser.status="reviewed"`);
    const trustedErr = await runSh(page, 'setfattr -n trusted.tag -v x note.txt', adaHome);
    expect(trustedErr.stderr).toContain('Operation not permitted');
    // Protected system users (`root`, `nobody`) cannot be deleted.
    await logoutLocalUser(page);
    expect(await pageErrno(page, { userdel: { name: 'nobody', remove: false } }, { sudo: true })).not.toBeNull();
    expect(await pageErrno(page, { userdel: { name: 'root', remove: false } }, { sudo: true })).not.toBeNull();
  } finally {
    await logoutLocalUser(page).catch(() => {});
    await switchLocalUser(page, 'root').catch(() => {});
    for (const name of [ada, bob]) {
      await pageCall(page, { userdel: { name, remove: true } }).catch(() => {});
      await pageCall(page, { groupdel: { name } }).catch(() => {});
    }
    await switchLocalUser(page, 'user').catch(() => {});
  }
});
