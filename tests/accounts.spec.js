import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, entry, mkdirp, program, rmrf } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
let sequence = 0;
const address = name => `accounts-${name}-${Date.now()}-${++sequence}`;

const busy = page => page.locator('.terminal-panel:not([hidden]) .busy');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
async function run(page, text) {
  await expect(busy(page)).toHaveText('↵');
  await page.locator('#command').fill(text); await page.locator('#command').press('Enter');
}
async function output(page, text) { await run(page, text); await expect(busy(page)).toHaveText('↵'); return (await last(page).textContent()).trim(); }
async function visitor(browser) {
  const context = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address('visitor') } });
  const page = await context.newPage(); await page.goto(origin + '/');
  await expect(busy(page)).toHaveText('↵');
  return { context, page };
}
// Fill and send the account dialog: a new password twice, or the account's own once.
async function answer(page, password, confirm = true) {
  await page.getByLabel(confirm ? 'New password' : 'Password', { exact: true }).fill(password);
  if (confirm) await page.getByLabel('Confirm new password').fill(password);
  await page.locator('#auth button[type=submit]').click();
}

let root;
test.beforeAll(async () => {
  root = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('api') } });
  expect((await api(root, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
});
test.afterAll(async () => { await root.dispose(); });
const stat = path => entry(root, path);
const command = args => program(root, args);

test('/dev, /dev/present and /dev/snd are there from the start, root\'s', async () => {
  for (const directory of ['/dev', '/dev/present', '/dev/snd']) {
    const node = await stat(directory);
    expect(node, directory).not.toBe(null);
    expect([node.directory, node.owner, node.mode]).toEqual([true, 'root', 0o755]);
  }
});

test('signed out, useradd makes an account of one\'s own: a home with -m, other options with sudo only', async ({ browser }) => {
  const plain = 'plain' + Date.now().toString(36), homed = 'homed' + Date.now().toString(36);
  const one = await visitor(browser), two = await visitor(browser);
  try {
    // --force is no option: what it was is --short-password.
    await run(one.page, `useradd --force ${plain}`);
    await expect(last(one.page)).toContainText("unexpected argument '--force'");
    await run(one.page, `useradd -G wheel ${plain}`);
    await expect(last(one.page)).toContainText('useradd: -G needs sudo');
    // Without -m, no home, as useradd makes none.
    await run(one.page, `useradd ${plain}`);
    await expect(one.page.locator('#auth-description')).toContainText(`Your home, /guest/${plain}, will not be made (useradd -m makes it)`);
    await answer(one.page, 'plain-password-' + Date.now());
    await expect(last(one.page)).toContainText(`Created user ${plain} and signed in; no home (/guest/${plain} is not made)`);
    expect(await stat('/guest/' + plain)).toBe(null);
    expect(await output(one.page, 'groups')).toBe(`${plain} guest`);
    // Its home, not made yet, is its own to make: no one else takes its path in /guest.
    await run(two.page, `mkdir /guest/${plain}`);
    await expect(last(two.page)).toContainText(`/guest/${plain} is another account's home`);
    await output(one.page, `mkdir /guest/${plain}`);
    expect((await stat('/guest/' + plain)).owner).toBe(plain);
    // With -m, its home, and --short-password lets the password be short.
    await run(two.page, `useradd -m --short-password ${homed}`);
    await expect(two.page.locator('#auth-description')).toContainText(`Your home will be /guest/${homed}, which only you may enter`);
    await answer(two.page, '1234');
    await expect(last(two.page)).toContainText(`Created user ${homed} and signed in; home /guest/${homed}`);
    const home = await stat('/guest/' + homed);
    expect([home.directory, home.owner, home.mode]).toEqual([true, homed, 0o700]);
  } finally {
    for (const name of [plain, homed]) { await command(['userdel', '-r', name]); await command(['groupdel', name]); }
    await one.context.close(); await two.context.close();
  }
});

test('an account in group guest deletes itself with its password; others need root', async ({ browser }) => {
  const self = 'self' + Date.now().toString(36), kept = 'kept' + Date.now().toString(36), password = 'self-password-' + Date.now();
  const one = await visitor(browser);
  // An account root made, in no group guest.
  expect((await command(['useradd', '-m', kept])).ok()).toBe(true);
  expect((await api(root, 'passwd', { data: { username: kept, password } })).ok()).toBe(true);
  try {
    await run(one.page, `useradd -m ${self}`); await answer(one.page, password);
    await expect(last(one.page)).toContainText(`Created user ${self} and signed in`);
    await run(one.page, `touch note.txt`);
    // Another account is root's to delete.
    await run(one.page, `userdel ${kept}`);
    await expect(last(one.page)).toContainText('Root permission required');
    // Its own, it is asked for its password: a wrong one deletes nothing.
    await run(one.page, `userdel -r ${self}`);
    await expect(one.page.locator('#auth-title')).toHaveText(`Delete account ${self}`);
    await expect(one.page.locator('#auth-description')).toContainText(`-r removes its home, /guest/${self}`);
    await answer(one.page, 'wrong-password', false);
    await expect(one.page.locator('#auth-error')).toHaveText('Incorrect password');
    await answer(one.page, password, false);
    await expect(last(one.page)).toContainText(`Deleted user ${self}; signed out as guest`);
    await expect(one.page.locator('.lock')).toContainText('guest');
    expect(await stat('/guest/' + self)).toBe(null);
    // Its group went with it, as userdel's does: the name may be taken again.
    await run(one.page, `useradd ${self}`); await answer(one.page, password);
    await expect(last(one.page)).toContainText(`Created user ${self} and signed in`);
    // -r keeps a home that is not the account's own: root's directory, here.
    await mkdirp(root, '/guest/' + self);
    await run(one.page, `userdel -r ${self}`); await answer(one.page, password, false);
    await expect(last(one.page)).toContainText(`Deleted user ${self}; /guest/${self} is not ${self}'s, not removed; signed out as guest`);
    expect(await stat('/guest/' + self)).not.toBe(null);
    await rmrf(root, '/guest/' + self);
    const again = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address('again') } });
    expect((await api(again, 'login', { data: { username: self, password } })).ok()).toBe(false);
    await again.dispose();
    // An account in no group guest is root's to delete, itself too.
    const other = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': address('kept') } });
    expect((await api(other.request, 'login', { headers: { Origin: origin }, data: { username: kept, password } })).ok()).toBe(true);
    const page = await other.newPage(); await page.goto(origin + '/');
    await expect(page.locator('.lock')).toContainText(kept);
    await run(page, `userdel ${kept}`);
    await expect(last(page)).toContainText('Root permission required');
    expect((await api(other.request, 'unregister', { headers: { Origin: origin }, data: { password } })).status()).toBe(403);
    await other.close();
  } finally {
    for (const name of [self, kept]) { await command(['userdel', '-r', name]); await command(['groupdel', name]); }
    await one.context.close();
  }
});
