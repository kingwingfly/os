import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import { pageCall, pageGetBytes, pageGetText, pageMkdirp, pagePut, pageRmrf, switchLocalUser } from './ui.js';

const coreutilsImage = await readFile('dist/usr/bin/coreutils.wasm');
let base;

// /bin's programs: uutils' coreutils, built for wasm32-wasip1, each run as a process of its own
// in the page's WASI engine, its calls the kernel's.
test.beforeEach(async () => {
  base = '/bin-' + Date.now().toString(36);
});
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
});

const transcript = page => page.locator('.transcript');
// Run `text` to its end.
async function run(page, text, { wait = true } = {}) {
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form');
  await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await input.fill(text); await input.press('Enter');
  if (wait) await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 30_000 });
}
async function terminal(page) {
  await page.goto('/');
  await expect(page.locator('#command').locator('xpath=ancestor::form')).toHaveAttribute('data-state', 'idle', { timeout: 20_000 });
  await switchLocalUser(page, 'root');
  await pageMkdirp(page, base, 0o755);
  await pagePut(page, base + '/names.txt', 'ann:3\nbob:1\ncid:2\n', { mode: 0o644 });
  await run(page, 'cd ' + base);
}

test('uutils runs as programs of /bin: arguments, the working directory, pipes and exit statuses', async ({ page }) => {
  await terminal(page);
  await run(page, 'seq 3');
  await expect(transcript(page)).toContainText('1\n2\n3');
  // Relative paths are the shell's directory's, as PWD says.
  await run(page, 'cut -d: -f1 names.txt');
  await expect(transcript(page)).toContainText('ann\nbob\ncid');
  // What the shell's own commands write goes on to them, and theirs to the shell's.
  await run(page, 'cat names.txt | tr a-z A-Z | cut -c1-3');
  await expect(transcript(page)).toContainText('ANN\nBOB\nCID');
  await run(page, 'printf "%s-%s\\n" one two');
  await expect(transcript(page)).toContainText('one-two');
  await run(page, 'sha256sum names.txt');
  await expect(transcript(page)).toContainText('names.txt');
  // A failure is the program's own words, on stderr, and a status the shell sees.
  await run(page, 'cut -d: -f1 missing.txt');
  await expect(transcript(page)).toContainText("cut: missing.txt: No such file or directory");
  await run(page, 'basename /a/b/c.txt .txt');
  await expect(page.locator('.transcript pre').last()).toHaveText('c');
  // A path to /usr/bin, or through /bin, runs what the name does.
  await run(page, '/bin/ls');
  await expect(transcript(page)).toContainText('names.txt');
  await run(page, '/usr/bin/cut -d: -f2 names.txt');
  await expect(page.locator('.transcript pre').last()).toHaveText('3\n1\n2');
  await run(page, '/usr/bin/nothing');
  await expect(transcript(page)).toContainText('/usr/bin/nothing: No such file or directory');
  // An uploaded copy of the same image runs by its path (execve of uploaded wasm, phase 2);
  // /usr/bin/ls is the same coreutils program in every shell.
  await pagePut(page, base + '/coreutils', coreutilsImage, { mode: 0o755 });
  await run(page, './coreutils seq 3');
  await expect(page.locator('.transcript pre').last()).toHaveText('1\n2\n3');
  await run(page, '/usr/bin/ls');
  await expect(transcript(page)).toContainText('names.txt');
  // A program of /bin reaches the kernel's own calls too, which WASI has no words for, through
  // the engine's os.sys: the batch goes as it is.
  await run(page, `syscall '["getcreds",{"lstat":{"path":"names.txt"}},{"stat":{"path":"${base}/names.txt"}}]'`);
  const syscallOut = (await page.locator('.transcript pre').last().innerText()).replace(/\n/g, '');
  expect(syscallOut).toContain('"user":"root"');
  // The kernel takes absolute paths only, as user space makes them.
  expect(syscallOut).toContain('{"err":{"detail":"a path must be absolute","errno":"EINVAL"}}');
  expect(syscallOut).toContain('"mode":33188');
  await run(page, 'coreutils');
  await expect(transcript(page)).toContainText('coreutils (uutils 0.12.0, multi-call binary)');
  await expect(transcript(page)).toContainText('Usage: coreutils UTILITY [ARGUMENT]...');
  // help lists them, and man says where their help is.
  await run(page, 'help');
  await expect(page.locator('.transcript pre').last()).toContainText("/usr/bin, from uutils' coreutils (processes of their own)");
  await expect(page.locator('.transcript pre').last()).toContainText('sha256sum');
  await run(page, 'man cut');
  await expect(transcript(page)).toContainText("cut is /bin's (uutils): cut --help says how to use it");
});

test('a program of /bin writes files through the kernel, as its account', async ({ page }) => {
  await terminal(page);
  // Written anew in order, closed whole.
  await run(page, 'seq 1000 | tee counted.txt | tail -n 1');
  await expect(transcript(page)).toContainText('1000');
  const counted = await pageGetText(page, base + '/counted.txt');
  expect(counted.split('\n').length).toBe(1001);
  // Changed in place: what is there is read, changed and written back whole.
  await run(page, 'truncate -s 4 names.txt');
  expect(await pageGetText(page, base + '/names.txt')).toBe('ann:');
  // Appended to: the same.
  await run(page, 'echo more | tee -a names.txt');
  expect(await pageGetText(page, base + '/names.txt')).toBe('ann:more\n');
  await run(page, '/bin/mkdir -p made/deeper');
  await run(page, '/bin/touch made/deeper/x');
  const made = await pageCall(page, { stat: { path: base + '/made/deeper/x' } });
  expect([made.user, made.size]).toEqual(['root', 0]);
  // The kernel decides: returning to unprivileged local `user` cannot remove root's file in root's 0755 dir.
  await run(page, 'logout');
  await run(page, 'cd ' + base);
  await run(page, '/bin/rm counted.txt');
  await expect(transcript(page)).toContainText("rm: cannot remove 'counted.txt': Permission denied");
});

test('/usr is the build\'s, read-only: /usr/bin contains executable images and their applet links', async ({ page }) => {
  await terminal(page);
  await run(page, 'readlink /bin');
  await expect(page.locator('.transcript pre').last()).toHaveText('usr/bin');
  await run(page, 'ls -l /usr/bin | cat');
  const listed = await page.locator('.transcript pre').last().innerText();
  // Browser actions like `open` have no fake executable image; local OS utilities (`passwd`, `sudo`, `su`) are real applets.
  expect(listed).not.toMatch(/ open$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* passwd -> utilities$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* sudo -> utilities$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* chmod -> utilities$/m);
  expect(listed).toMatch(/^-rwxr-xr-x +1 root root +\d+ .* utilities$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* ls -> coreutils$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* cut -> coreutils$/m);
  expect(listed).toMatch(/^-rwxr-xr-x +1 root root +\d{6,} .* coreutils$/m);
  // The shell's builtins are no files; root may change nothing of it.
  await run(page, "ls /usr/bin | grep -c '^cd$'");
  await expect(page.locator('.transcript pre').last()).toHaveText('0');
  await run(page, 'rm /usr/bin/cut');
  await expect(transcript(page)).toContainText("rm: cannot remove '/usr/bin/cut': Read-only file system");
  await run(page, 'mkdir /usr/new-directory');
  await expect(transcript(page)).toContainText(/mkdir:.*\/usr\/new-directory.*Read-only file system/);
  // Its binaries read as the build has them.
  const coreutils = await pageGetBytes(page, '/usr/bin/cut');
  expect(coreutils).not.toBeNull();
  expect([...coreutils.subarray(0, 4)]).toEqual([0, 0x61, 0x73, 0x6d]);
  await run(page, 'df /usr');
  await expect(page.locator('.transcript pre').last()).toContainText(/^\S+ +\d+ +\d+ +0 +100% \/usr$/m);
});

test('what programs write for a terminal shows as they mean it: colours, styles and links', async ({ page }) => {
  await terminal(page);
  await run(page, "printf '\\033[1;31mred\\033[0m plain \\033[38;5;208morange\\033[m \\033]8;;https://example.com/\\033\\\\site\\033]8;;\\033\\\\\\n'");
  const last = page.locator('.transcript pre').last();
  await expect(last).toHaveText('red plain orange site');
  await expect(last.locator('span', { hasText: 'red' })).toHaveAttribute('style', 'color:var(--ansi-1);font-weight:700;');
  await expect(last.locator('span', { hasText: 'orange' })).toHaveAttribute('style', 'color:rgb(255,135,0);');
  await expect(last.locator('a', { hasText: 'site' })).toHaveAttribute('href', 'https://example.com/');
  // uutils' ls colours what it lists, at a terminal.
  await run(page, 'mkdir -p coloured');
  await run(page, 'coreutils ls --color=auto');
  await expect(page.locator('.transcript pre').last().locator('span', { hasText: 'coloured' })).toHaveAttribute('style', /color:var\(--ansi-4\)/);
});

test('/ is laid out as Arch\'s', async ({ page }) => {
  await terminal(page);
  await run(page, 'ls / | cat');
  const names = (await page.locator('.transcript pre').last().innerText()).split('\n');
  for (const name of ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var']) expect(names).toContain(name);
  await run(page, 'readlink /sbin /lib /lib64 /usr/sbin /usr/lib64');
  await expect(page.locator('.transcript pre').last()).toHaveText('usr/bin\nusr/lib\nusr/lib\nbin\nlib');
  await run(page, "stat -c '%a %U' /tmp /root /sys /usr/local");
  await expect(page.locator('.transcript pre').last()).toHaveText('1777 root\n700 root\n555 root\n755 root');
  await run(page, 'ls /usr | cat');
  await expect(page.locator('.transcript pre').last()).toHaveText('bin\ninclude\nlib\nlib64\nlibexec\nlocal\nsbin\nshare\nsrc');
  // A program is found through any of them.
  await run(page, '/sbin/seq 2');
  await expect(page.locator('.transcript pre').last()).toHaveText('1\n2');
});

test('Ctrl+C kills a pipeline; head closes its input; streaming pipes wait for EOF', async ({ page }) => {
  await terminal(page);
  const input = page.getByRole('combobox', { name: 'Terminal command' });
  const busy = page.locator('#command').locator('xpath=ancestor::form');
  await input.fill('sleep 30'); await input.press('Enter');
  await expect(busy).not.toHaveAttribute('data-state', 'idle');
  await page.waitForTimeout(500);
  await input.press('Control+c');
  await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 5_000 });
  // head takes its lines and closes the pipe: yes hears SIGPIPE, and ends.
  await run(page, 'yes | head -n 2');
  await expect(page.locator('.transcript pre').last()).toHaveText('y\ny');
  await expect(transcript(page)).not.toContainText('cut short');
  // wc counts until EOF. An infinite producer stays running, with bounded pipe buffers,
  // rather than being truncated by a browser text-filter limit.
  await input.fill('yes | wc -l'); await input.press('Enter');
  await expect(busy).toHaveAttribute('aria-busy', 'true');
  await page.waitForTimeout(500);
  await expect(busy).toHaveAttribute('aria-busy', 'true');
  await input.press('Control+c');
  await expect(busy).toHaveAttribute('data-state', 'idle', { timeout: 5_000 });
  await expect(transcript(page)).not.toContainText('cut short');
});
