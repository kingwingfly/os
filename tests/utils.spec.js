import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, call, mkdirp, put, rmrf } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
let base, headers;

// The programs of user space, with the times the kernel keeps: touch sets them, stat and ls -l
// show them, cp -p keeps them; and df.
test.beforeEach(async ({ request, page }) => {
  base = '/utils-' + Date.now().toString(36);
  headers = { Origin: origin, 'CF-Connecting-IP': 'utils-' + base };
  await page.setExtraHTTPHeaders({ 'CF-Connecting-IP': 'utils-ui-' + base });
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  await mkdirp(request, base);
  for (const [name, text] of Object.entries({ 'old.txt': 'old\n', 'big.txt': 'a much bigger file\n', 'new.txt': 'n\n' })) {
    expect((await put(request, file(base + '/' + name), { headers, data: text })).status()).toBe(201);
  }
});
test.afterEach(async ({ request }) => { await rmrf(request, base); });

const last = page => page.locator('.transcript pre').last();
async function run(page, text, { wait = true } = {}) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form').locator('.busy');
  await expect(busy).toHaveText('↵');
  await input.fill(text); await input.press('Enter');
  if (wait) await expect(busy).toHaveText('↵', { timeout: 30_000 });
}
async function terminal(page) {
  await page.goto('/');
  await run(page, 'su root', { wait: false });
  await page.getByLabel('Password', { exact: true }).fill(password); await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('#auth')).not.toBeVisible();
  await run(page, 'cd ' + base);
}

test('touch sets times as told, stat shows them to the nanosecond, ls sorts and shows them', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'touch -d "2020-02-03 04:05:06.5" old.txt');
  const old = await call(request, { stat: { path: base + '/old.txt' } }, { headers });
  expect([old.mtime, old.mtime_nsec, old.atime]).toEqual([Date.UTC(2020, 1, 3, 4, 5, 6) / 1000, 500000000, old.mtime]);
  await run(page, 'stat old.txt');
  await expect(last(page)).toContainText('Modify: 2020-02-03 04:05:06.500000000 +0000');
  await expect(last(page)).toContainText('Access: 2020-02-03 04:05:06.500000000 +0000');
  await expect(last(page)).toContainText(' Birth: -');
  // -m sets one time only; -r takes another file's; -t a stamp.
  await run(page, 'touch -m -t 202101010000 new.txt');
  const changed = await call(request, { stat: { path: base + '/new.txt' } }, { headers });
  expect(changed.mtime).toBe(Date.UTC(2021, 0, 1) / 1000);
  expect(changed.atime).toBeGreaterThan(changed.mtime);
  await run(page, 'touch -r old.txt made.txt');
  expect((await call(request, { stat: { path: base + '/made.txt' } }, { headers })).mtime).toBe(old.mtime);
  await run(page, 'touch -d "not a date" old.txt');
  await expect(last(page)).toContainText("touch: invalid date format 'not a date'");
  await run(page, "stat -c '%n %s %a %U %Y' old.txt big.txt");
  await expect(last(page)).toHaveText(`old.txt 4 644 root ${old.mtime}\nbig.txt 19 644 root ${(await call(request, { stat: { path: base + '/big.txt' } }, { headers })).mtime}`);
  // ls -l shows when content changed; -t sorts by it, -S by size, -r the other way.
  await run(page, 'ls -l old.txt');
  await expect(last(page)).toContainText('Feb  3  2020');
  await run(page, 'ls -t | head -n 2');
  await expect(last(page)).toHaveText('big.txt\nnew.txt');
  await run(page, 'ls -Sr | head -n 1');
  await expect(last(page)).toHaveText('made.txt');
});

test('cp -p keeps times; df tells of the store and of /proc', async ({ page, request }) => {
  await terminal(page);
  await run(page, 'touch -d 2019-07-08 old.txt');
  await run(page, 'cp -p old.txt kept.txt');
  await run(page, 'cp old.txt fresh.txt');
  const [kept, fresh] = await Promise.all(['kept', 'fresh'].map(name => call(request, { stat: { path: `${base}/${name}.txt` } }, { headers })));
  expect(kept.mtime).toBe(Date.UTC(2019, 6, 8) / 1000);
  expect(fresh.mtime).toBeGreaterThan(kept.mtime);
  await run(page, 'df -h');
  await expect(last(page)).toContainText('Filesystem');
  await expect(last(page)).toContainText(/^r2 +\S+ +\S+ +1\.0P +\d+% \/$/m);
  await run(page, 'df /proc');
  await expect(last(page)).toContainText(/^proc +0 +0 +0 +- \/proc$/m);
});
