import { test, expect } from './test.js';
import { pageSys, cloudStatus } from './ui.js';

// Under Contract v2 (#56 L3c + #57 L3d), every browser instance boots directly into its own
// local `os-cowfs` root with zero-friction auto-login as local `user` (uid 1000, gid 1000,
// `wheel` with passwordless `sudo`, home `/home/user`) and Cloud initially signed out.
// Separate browser contexts have completely isolated local filesystems and `/etc/passwd`.

async function localSession(browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
  const [result] = await pageSys(page, ['getcreds']);
  expect(result.ok).toBeTruthy();
  return { context, page, creds: result.ok };
}

async function passwd(page) {
  const parts = [];
  let offset = 0;
  for (;;) {
    const [part] = await pageSys(page, [{ pread: { path: '/etc/passwd', offset, count: 65536 } }]);
    const bytes = Buffer.from(part.ok.data, 'base64');
    parts.push(bytes);
    offset += bytes.length;
    if (bytes.length < 65536) return Buffer.concat(parts).toString();
  }
}

test('a fresh browser auto-enters local user (uid 1000, wheel) with Cloud signed out and zero login wall', async ({ browser }) => {
  const one = await localSession(browser);
  try {
    const { creds } = one;
    expect(creds.user).toBe('user');
    expect(creds.uid).toBe(1000);
    expect(creds.gid).toBe(1000);
    expect(creds.groups).toEqual(expect.arrayContaining([10, 1000]));
    expect(creds.home).toBe('/home/user');
    expect(creds.signed_in).toBe(true);
    expect(creds.can_sudo).toBe(true);
    expect(creds.sudo_active).toBe(true);

    // Cloud is initially signed out, with no `/mnt/cloud` mounted.
    const cs = await cloudStatus(one.page);
    expect(cs.signed_in).toBe(false);
    expect(cs.cloud_mounted).toBe(false);

    // `/etc/passwd` names the local user, and `/home/user` is owned by 1000:1000 (0750).
    expect(await passwd(one.page)).toContain('user:x:1000:1000:');
    const [home] = await pageSys(one.page, [{ stat: { path: '/home/user' } }]);
    expect(home.ok).toMatchObject({ uid: 1000, gid: 1000, mode: 0o040750 });

    // `whoami` in the terminal prints `user` with zero login prompt.
    await one.page.getByRole('combobox', { name: 'Terminal command' }).fill('whoami');
    await one.page.getByRole('combobox', { name: 'Terminal command' }).press('Enter');
    await expect(one.page.locator('.transcript pre').last()).toHaveText('user');
  } finally {
    await one.context.close();
  }
});

test('two browser contexts have isolated local filesystems and cannot see each other’s files', async ({ browser }) => {
  const one = await localSession(browser);
  const two = await localSession(browser);
  try {
    const path = `/home/user/private-note-${Date.now()}`;
    const [made] = await pageSys(one.page, [{ mknod: { path, mode: 0o600 } }]);
    expect(made.ok).toBeNull();
    const [mine] = await pageSys(one.page, [{ stat: { path } }]);
    expect([mine.ok.user, mine.ok.uid, mine.ok.mode]).toEqual(['user', 1000, 0o100600]);

    // Browser context two has its own independent local `os-cowfs` root.
    const [theirs] = await pageSys(two.page, [{ stat: { path } }]);
    expect(theirs.err?.errno).toBe('ENOENT');

    const [removed] = await pageSys(one.page, [{ unlink: { path } }]);
    expect(removed.ok).toBeNull();
  } finally {
    await Promise.all([one.context.close(), two.context.close()]);
  }
});

test('local wheel user can create and delete a local account with home directory offline', async ({ browser }) => {
  const one = await localSession(browser);
  try {
    const name = 'localadd' + Date.now().toString(36);
    const password = 'local-add-password-' + Date.now();
    const [made] = await pageSys(
      one.page,
      [{ useradd: { name, password, short_password: true, create_home: true } }],
      { sudo: true },
    );
    expect(made.ok).toBeTruthy();

    const [home] = await pageSys(one.page, [{ stat: { path: `/home/${name}` } }], { sudo: true });
    expect(home.ok).toMatchObject({ user: name });
    expect(await passwd(one.page)).toContain(`${name}:x:`);

    const [deleted] = await pageSys(
      one.page,
      [{ userdel: { name, remove: true, password } }],
      { sudo: true },
    );
    expect(deleted.ok).toBeTruthy();
    const [gone] = await pageSys(one.page, [{ stat: { path: `/home/${name}` } }], { sudo: true });
    expect(gone.err?.errno).toBe('ENOENT');
  } finally {
    await one.context.close();
  }
});
