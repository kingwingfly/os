import { test, expect } from './test.js';
import { execSh, pageCall, pageMkdirp, pagePut, pageRmrf, switchLocalUser } from './ui.js';

// External utilities inherit the browser timezone; timestamp fixtures below use UTC.
test.use({ timezoneId: 'UTC' });
let base;

// The programs of user space, with the times the kernel keeps: touch sets them, stat and ls -l
// show them, cp -p keeps them; and df.
test.beforeEach(async () => {
  base = '/utils-' + Date.now().toString(36);
});
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
});

const runSh = (page, script) => execSh(page, `export TZ=UTC; ${script}`, { cwd: base });
async function okSh(page, script) {
  const res = await runSh(page, script);
  expect(res.status, `${script}: ${res.stderr}`).toBe(0);
  return res.stdout;
}
async function terminal(page) {
  await page.goto('/');
  await page.waitForFunction(() => Boolean(window.os?.exec));
  await switchLocalUser(page, 'root');
  await pageMkdirp(page, base, 0o755);
  for (const [name, text] of Object.entries({ 'old.txt': 'old\n', 'big.txt': 'a much bigger file\n', 'new.txt': 'n\n' })) {
    await pagePut(page, base + '/' + name, text, { mode: 0o644 });
  }
}

test('touch sets times as told, stat shows them to the nanosecond, ls sorts and shows them', async ({ page }) => {
  await terminal(page);
  await okSh(page, 'touch -d "2020-02-03 04:05:06.5" old.txt');
  const old = await pageCall(page, { stat: { path: base + '/old.txt' } });
  expect([old.mtime, old.mtime_nsec, old.atime]).toEqual([Date.UTC(2020, 1, 3, 4, 5, 6) / 1000, 500000000, old.mtime]);
  const statOut = await okSh(page, 'stat old.txt');
  expect(statOut).toContain('Modify: 2020-02-03 04:05:06.500000000 +0000');
  expect(statOut).toContain('Access: 2020-02-03 04:05:06.500000000 +0000');
  expect(statOut).toContain(' Birth: -');
  // -m sets one time only; -r takes another file's; -t a stamp.
  await okSh(page, 'touch -m -t 202101010000 new.txt');
  const changed = await pageCall(page, { stat: { path: base + '/new.txt' } });
  expect(changed.mtime).toBe(Date.UTC(2021, 0, 1) / 1000);
  expect(changed.atime).toBeGreaterThan(changed.mtime);
  await okSh(page, 'touch -r old.txt made.txt');
  expect((await pageCall(page, { stat: { path: base + '/made.txt' } })).mtime).toBe(old.mtime);
  const badDate = await runSh(page, 'touch -d "not a date" old.txt');
  expect(badDate.status).not.toBe(0);
  expect(badDate.stderr).toContain('touch: Unable to parse date: not a date');
  const statFmt = (await okSh(page, "stat -c '%n %s %a %U %Y' old.txt big.txt")).trim();
  expect(statFmt).toBe(`old.txt 4 644 root ${old.mtime}\nbig.txt 19 644 root ${(await pageCall(page, { stat: { path: base + '/big.txt' } })).mtime}`);
  // ls -l shows when content changed; -t sorts by it, -S by size, -r the other way.
  expect(await okSh(page, 'ls -l old.txt')).toContain('Feb  3  2020');
  expect((await okSh(page, 'ls -t | head -n 2')).trim()).toBe('big.txt\nnew.txt');
  expect((await okSh(page, 'ls -Sr | head -n 1')).trim()).toBe('made.txt');
});

test('cp -p keeps times; df tells of the store and of /proc', async ({ page }) => {
  await terminal(page);
  await okSh(page, 'touch -d 2019-07-08 old.txt');
  await okSh(page, 'cp -p old.txt kept.txt');
  await okSh(page, 'cp old.txt fresh.txt');
  const [kept, fresh] = await Promise.all(['kept', 'fresh'].map(name => pageCall(page, { stat: { path: `${base}/${name}.txt` } })));
  expect(kept.mtime).toBe(Date.UTC(2019, 6, 8) / 1000);
  expect(fresh.mtime).toBeGreaterThan(kept.mtime);
  const dfH = await okSh(page, 'df -h');
  expect(dfH).toContain('Filesystem');
  expect(dfH).toMatch(/^cowfs:\S+ +\S+ +\S+ +\S+ +\d+% \/$/m);
  const dfProc = await okSh(page, 'df /proc');
  expect(dfProc).toMatch(/^proc +0 +0 +0 +- \/proc$/m);
});
