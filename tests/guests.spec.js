import { test, expect } from './test.js';

// Signed-out browsers are each `guest-<uuid>:guest` (owner's decision, 2026-11-01): a uid of
// their own from the anonymous range, so what they make in the shared /guest is theirs, and
// /etc/passwd names them. No per-guest home is made; HOME stays the shared /guest.

async function sys(page, calls, options = {}) {
  return page.evaluate(async ([calls, options]) => {
    const response = await fetch('/api/sys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ calls, ...options }),
    });
    return (await response.json()).results;
  }, [calls, options]);
}

async function guest(browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto('/');
  const [result] = await sys(page, ['getcreds']);
  expect(result.ok).toBeTruthy();
  return { context, page, creds: result.ok };
}

const read = result => Buffer.from(result.ok.data, 'base64').toString();

test('a signed-out browser is guest-<uuid>:guest, with no home of its own', async ({ browser }) => {
  const one = await guest(browser);
  const { creds } = one;
  expect(creds.user).toMatch(/^guest-[0-9a-f]{16}$/);
  expect(creds.uid).toBeGreaterThanOrEqual(1_000_000);
  expect(creds.uid).toBeLessThan(2_000_000);
  expect([creds.group, creds.groups, creds.home, creds.signed_in]).toEqual(['guest', [65534], '/guest', false]);
  // No /guest/<uuid> is made.
  expect(creds.user.slice('guest-'.length)).toMatch(/^[0-9a-f]{16}$/);
  const [home] = await sys(one.page, [{ stat: { path: `/guest/${creds.user.slice(6)}` } }]);
  expect(home.err.errno).toBe('ENOENT');
  const [listed] = await sys(one.page, [{ getdents: { path: '/guest' } }]);
  expect(listed.ok.map(entry => entry.name)).not.toContain(creds.user.slice(6));
  // /etc/passwd names it, and its home is the shared /guest.
  const [passwd] = await sys(one.page, [{ pread: { path: '/etc/passwd', count: 65536 } }]);
  expect(read(passwd)).toContain(`${creds.user}:x:${creds.uid}:65534::/guest:/bin/sh`);
  // whoami says the same.
  await one.page.getByRole('combobox', { name: 'Terminal command' }).fill('whoami');
  await one.page.getByRole('combobox', { name: 'Terminal command' }).press('Enter');
  await expect(one.page.locator('.transcript pre').last()).toHaveText(creds.user);
  await one.context.close();
});

test('what one guest makes in /guest is its own, and another guest may not take it', async ({ browser }) => {
  const one = await guest(browser);
  const two = await guest(browser);
  expect(one.creds.uid).not.toBe(two.creds.uid);
  expect(one.creds.user).not.toBe(two.creds.user);
  const path = `/guest/${one.creds.user.slice(6)}-note`;
  const [made] = await sys(one.page, [{ mknod: { path, mode: 0o644 } }]);
  expect(made.ok).toBeNull();
  const [mine] = await sys(one.page, [{ stat: { path } }]);
  expect([mine.ok.user, mine.ok.uid, mine.ok.mode]).toEqual([one.creds.user, one.creds.uid, 0o100644]);
  // The other guest sees whose it is, may read it (0644), may not write or take it (sticky).
  const [theirs] = await sys(two.page, [{ stat: { path } }]);
  expect(theirs.ok.user).toBe(one.creds.user);
  const [readable] = await sys(two.page, [{ access: { path, mode: 4 } }]);
  expect(readable.ok).toBeNull();
  const [writable] = await sys(two.page, [{ open: { path, flags: 1, mode: 0o644 } }]);
  expect(writable.err.errno).toBe('EACCES');
  const [removed] = await sys(two.page, [{ unlink: { path } }]);
  expect(removed.err.errno).toBe('EPERM');
  // The owner may take it.
  const [own] = await sys(one.page, [{ unlink: { path } }]);
  expect(own.ok).toBeNull();
  await Promise.all([one.context.close(), two.context.close()]);
});

test('signed out, useradd still makes a real account with its home, as before', async ({ browser }) => {
  const one = await guest(browser);
  const name = 'guestadd' + Date.now().toString(36);
  const password = 'guest-add-password-' + Date.now();
  const [made] = await sys(one.page, [{ useradd: { name: name, password, short_password: true, create_home: true } }]);
  expect(made.ok).toBeTruthy();
  // The session is the new account's, and its home is a directory it owns.
  const [creds] = await sys(one.page, ['getcreds']);
  expect([creds.ok.user, creds.ok.signed_in, creds.ok.home]).toEqual([name, true, `/guest/${name}`]);
  const [home] = await sys(one.page, [{ stat: { path: `/guest/${name}` } }]);
  expect(home.ok).toMatchObject({ user: name, mode: 0o40700 });
  // It is a real account, not a guest: /etc/passwd has it. Root removes it, home and all.
  const [passwd] = await sys(one.page, [{ pread: { path: '/etc/passwd', count: 65536 } }]);
  expect(read(passwd)).toContain(`${name}:x:`);
  // An account in group guest deletes itself with its password, home and all.
  const [deleted] = await sys(one.page, [{ userdel: { name, remove: true, password } }]);
  expect(deleted.ok).toBeTruthy();
  const [gone] = await sys(one.page, [{ stat: { path: `/guest/${name}` } }]);
  expect(gone.err.errno).toBe('ENOENT');
  await one.context.close();
});
