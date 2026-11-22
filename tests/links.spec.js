import { test, expect } from './test.js';
import { api, entry, errno, mkdirp, rmrf } from './sys.js';
import { cloudSignIn, pageCall, pageErrno, pageGetText, pageMkdirp, pagePut, pageRmrf, switchLocalUser } from './ui.js';

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

const busy = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function run(page, text) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
  await page.locator('#command').fill(text); await page.locator('#command').press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
}
async function output(page, text) { await run(page, text); return (await last(page).textContent()).trim(); }
async function terminal(page) {
  await page.goto('/');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await switchLocalUser(page, 'root');
  for (const dir of ['', '/docs']) await pageMkdirp(page, base + dir, 0o755);
  for (const [name, text] of Object.entries({ 'a.md': 'alpha\n', 'docs/b.md': 'beta\n' })) {
    await pagePut(page, base + '/' + name, text, { mode: 0o644 });
  }
  await run(page, 'cd ' + base);
}

test('ln makes symbolic and hard links that behave as on Linux', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'ln -s docs/b.md link.md'); await run(page, 'ln a.md a-too.md');
  // ls -l shows where a link points, and how many names a file has.
  // Piped, a listing is text, a line an entry.
  const long = await output(page, 'ls -l | cat');
  expect(long).toMatch(/^lrwxrwxrwx +1 root root +9 [A-Z][a-z]{2} [ \d]\d [ \d:]{5} link\.md -> docs\/b\.md$/m);
  expect(long).toMatch(/^-rw-r--r-- +2 root root +6 [A-Z][a-z]{2} [ \d]\d [ \d:]{5} a-too\.md$/m);
  expect(await output(page, 'cat link.md')).toBe('beta');
  expect(await output(page, 'readlink link.md')).toBe('docs/b.md');
  expect(await output(page, 'readlink -f link.md')).toBe(base + '/docs/b.md');
  // Writing through one name of a file changes it under every name; chmod too.
  await pagePut(page, base + '/a-too.md', 'changed\n', { mode: 0o644, overwrite: true });
  expect(await pageGetText(page, base + '/a.md')).toBe('changed\n');
  await run(page, 'chmod 600 a-too.md');
  expect(await output(page, 'ls -l a.md')).toMatch(/^-rw------- +2 /);
  // rm removes a link, not what it points to; a name, not the file's other names.
  await run(page, 'rm link.md a.md');
  expect(await pageGetText(page, base + '/docs/b.md')).toBe('beta\n');
  expect(await pageGetText(page, base + '/a-too.md')).toBe('changed\n');
  // A link to a directory is entered by its name, and left the same way.
  await run(page, 'ln -s docs d'); await run(page, 'cd d');
  expect(await output(page, 'pwd')).toBe(base + '/d');
  expect(await output(page, 'ls')).toBe('b.md');
  await run(page, 'cd ..'); expect(await output(page, 'pwd')).toBe(base);
  // ls -ld shows the link itself; a trailing slash follows it.
  expect(await output(page, 'ls -ld d')).toContain('d -> docs');
  expect(await output(page, 'ls d/')).toBe('b.md');
  // Diagnostics belong to the installed uutils/WASI program.
  for (const [line, message] of [['ln docs hard', 'hard link not allowed for directory'], ['ln -s a-too.md docs/b.md', 'Already exists'], ['ln -s loop loop', '']]) {
    await run(page, line);
    if (message) await expect(last(page)).toContainText(message);
  }
  // The WASI platform adapter recognizes ELOOP and uses cat's normal diagnostic.
  await run(page, 'cat loop'); await expect(last(page)).toHaveText('cat: loop: Too many levels of symbolic links');
  // ln -sf repoints a link; fd -t l finds links.
  await run(page, 'ln -sfn a-too.md d'); expect(await output(page, 'readlink d')).toBe('a-too.md');
  expect(await output(page, 'fd -t l | sort')).toBe('d\nloop');
  // cp follows a link named; -r copies links as links; -a keeps names of a file together.
  await run(page, 'ln a-too.md docs/a3.md');
  // The copy of a file with mode 600 is 600 too: the umask only takes away.
  await run(page, 'cp d plain.md'); expect(await output(page, 'ls -l plain.md')).toMatch(/^-rw------- +1 /);
  await run(page, 'cp -r . ../copy-' + base.slice(1));
  expect(await output(page, `readlink ../copy-${base.slice(1)}/d`)).toBe('a-too.md');
  await run(page, 'cp -a . ../kept-' + base.slice(1));
  expect(await output(page, `ls -l ../kept-${base.slice(1)}/docs/a3.md`)).toMatch(/^-rw------- +2 /);
  for (const dir of ['copy', 'kept']) await pageRmrf(page, `/${dir}-${base.slice(1)}`);
  // ln -f replaces a name only once its link can be made: one that cannot leaves what was there.
  await run(page, 'mkdir t');
  for (const name of ['docs', 'a-too.md']) await pagePut(page, `${base}/t/${name}`, 'keep\n', { mode: 0o644 });
  await run(page, 'ln -f a-too.md docs t');
  await expect(page.locator('.terminal-panel:not([hidden]) .transcript')).toContainText('hard link not allowed for directory');
  expect(await pageGetText(page, base + '/t/docs')).toBe('keep\n');
  expect(await pageGetText(page, base + '/t/a-too.md')).toBe('changed\n');
  // On CloudFs (`/mnt/cloud`), a file still uploading is copied once whole, also when a link leads to it.
  cloudBase = '/links-cloud-' + Date.now().toString(36);
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, cloudBase);
  expect(await errno(request, { open: { path: cloudBase + '/up.bin', flags: 0o101, size: 4 } })).toBe(null);
  await cloudSignIn(page, 'root', password);
  await run(page, 'cd /mnt/cloud' + cloudBase);
  await run(page, 'mkdir withlink'); await run(page, 'ln -s ../up.bin withlink/l');
  await run(page, 'cp -rL withlink taken'); await expect(last(page)).toContainText('Device or resource busy');
  expect(await entry(request, cloudBase + '/taken/l')).toBe(null);
  await run(page, 'ln up.bin up-too.bin'); await expect(last(page)).toContainText('Resource busy');
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
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  // Default auto-login is local `user` (uid 1000, in wheel).
  const id = await output(page, 'id');
  expect(id).toBe('uid=1000(user) gid=1000(user) groups=10(wheel),1000(user)');
  // Create two local accounts with private 0700 home directories via local `sudo`.
  await run(page, 'sudo useradd -m ' + ada);
  await run(page, 'sudo useradd -m ' + bob);
  try {
    await pageCall(page, { passwd: { username: ada, password: pass, force: true } }, { sudo: true });
    await pageCall(page, { passwd: { username: bob, password: pass, force: true } }, { sudo: true });
    await switchAndSync(page, ada, { password: pass, sudo: false });
    await run(page, 'cd ~');
    expect(await output(page, 'pwd')).toBe('/home/' + ada);
    expect(await output(page, 'groups')).toBe(ada);
    expect(await output(page, 'ls -ld /tmp | cat')).toMatch(/^drwxrwxrwt +\d+ root root/);
    expect(await output(page, 'ls -ld . | cat')).toMatch(new RegExp(`^drwxr-x--- +2 ${ada} ${ada}`));
    // Homes are their owners' only.
    await run(page, 'touch note.txt');
    await switchAndSync(page, bob, { password: pass, sudo: false });
    expect(await pageGetText(page, `/home/${ada}/note.txt`)).toBe(null);
    // ada lets bob through her home and read the note: named entries, bounded by the mask.
    await switchAndSync(page, ada, { password: pass, sudo: false });
    await run(page, `setfacl -m u:${bob}:x .`); await run(page, `setfacl -m u:${bob}:rw note.txt`);
    await switchAndSync(page, bob, { password: pass, sudo: false });
    expect(await pageGetText(page, `/home/${ada}/note.txt`)).toBe('');
    await switchAndSync(page, ada, { password: pass, sudo: false });
    expect(await output(page, 'ls -l note.txt')).toMatch(/^-rw-rw-r--\+ /);
    await run(page, 'chmod g-w note.txt');
    // Capture bytes before terminal tab expansion; the ACL and effective mask stay exact.
    await run(page, 'getfacl note.txt | tee acl.txt');
    expect((await pageGetText(page, `/home/${ada}/acl.txt`)).trim()).toBe(`# file: home/${ada}/note.txt\n# owner: ${ada}\n# group: ${ada}\nuser::rw-\nuser:${bob}:rw-\t#effective:r--\ngroup::r--\nmask::r--\nother::r--`);
    await switchAndSync(page, bob, { password: pass, sudo: false });
    await expect(pagePut(page, `/home/${ada}/note.txt`, 'x', { overwrite: true })).rejects.toThrow();
    // A default ACL is what new files get.
    await switchAndSync(page, ada, { password: pass, sudo: false });
    await run(page, `setfacl -d -m u:${bob}:rw .`); await run(page, 'touch later.txt');
    expect(await output(page, `getfacl -c later.txt`)).toContain(`user:${bob}:rw-`);
    // /tmp is sticky: anyone may put a file there, and only its owner remove it.
    await run(page, `touch /tmp/${ada}-shared.txt`);
    await switchAndSync(page, bob, { password: pass, sudo: false });
    expect(await pageRmrf(page, `/tmp/${ada}-shared.txt`)).toBe('EPERM');
    await switchAndSync(page, ada, { password: pass, sudo: false });
    await run(page, `rm /tmp/${ada}-shared.txt`);
    // Extended attributes go with the file, for whoever may write it.
    await run(page, 'setfattr -n user.status -v reviewed note.txt');
    expect(await output(page, 'getfattr -d note.txt')).toBe(`# file: home/${ada}/note.txt\nuser.status="reviewed"`);
    await run(page, 'setfattr -n trusted.tag -v x note.txt'); await expect(last(page)).toContainText('Operation not permitted');
    // Protected system users (`root`, `nobody`) cannot be deleted.
    await run(page, 'exit');
    expect(await pageErrno(page, { userdel: { name: 'nobody', remove: false } }, { sudo: true })).not.toBeNull();
    expect(await pageErrno(page, { userdel: { name: 'root', remove: false } }, { sudo: true })).not.toBeNull();
  } finally {
    await switchLocalUser(page, 'root').catch(() => {});
    for (const name of [ada, bob]) {
      await pageCall(page, { userdel: { name, remove: true } }).catch(() => {});
      await pageCall(page, { groupdel: { name } }).catch(() => {});
    }
    await switchLocalUser(page, 'user').catch(() => {});
  }
});
