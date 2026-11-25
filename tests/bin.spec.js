import { test, expect } from './test.js';
import { readFile } from 'node:fs/promises';
import {
  execCmd,
  execSh,
  logoutLocalUser,
  pageCall,
  pageGetBytes,
  pageGetText,
  pageMkdirp,
  pagePut,
  pageRmrf,
  runTerminal,
  switchLocalUser,
  terminalInput,
  terminalScreen,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';

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

async function bootRoot(page) {
  await page.goto('/');
  await waitForTerminalReady(page);
  await switchLocalUser(page, 'root');
  await pageMkdirp(page, base, 0o755);
  await pagePut(page, base + '/names.txt', 'ann:3\nbob:1\ncid:2\n', { mode: 0o644 });
}

test('uutils runs as programs of /bin: arguments, the working directory, pipes and exit statuses', async ({ page }) => {
  await bootRoot(page);
  expect((await execCmd(page, ['seq', '3'], { cwd: base })).stdout).toBe('1\n2\n3\n');
  // Relative paths are the process's working directory.
  expect((await execCmd(page, ['cut', '-d:', '-f1', 'names.txt'], { cwd: base })).stdout).toBe('ann\nbob\ncid\n');
  // Pipelines join programs over standard streams.
  expect((await execSh(page, 'cat names.txt | tr a-z A-Z | cut -c1-3', { cwd: base })).stdout).toBe('ANN\nBOB\nCID\n');
  expect((await execCmd(page, ['printf', '%s-%s\n', 'one', 'two'], { cwd: base })).stdout).toBe('one-two\n');
  expect((await execCmd(page, ['sha256sum', 'names.txt'], { cwd: base })).stdout).toContain('names.txt');
  // A failure is the program's own words, on stderr, and a non-zero exit status.
  const missing = await execCmd(page, ['cut', '-d:', '-f1', 'missing.txt'], { cwd: base });
  expect(missing.status).not.toBe(0);
  expect(missing.stderr).toContain('cut: missing.txt: No such file or directory');
  expect((await execCmd(page, ['basename', '/a/b/c.txt', '.txt'], { cwd: base })).stdout.trim()).toBe('c');
  // A path to /usr/bin, or through /bin, runs what the name does.
  expect((await execCmd(page, ['/bin/ls'], { cwd: base })).stdout).toContain('names.txt');
  expect((await execCmd(page, ['/usr/bin/cut', '-d:', '-f2', 'names.txt'], { cwd: base })).stdout.trim()).toBe('3\n1\n2');
  const noProg = await execCmd(page, ['/usr/bin/osh', '-c', '/usr/bin/nothing'], { cwd: base });
  expect(noProg.status).not.toBe(0);
  expect(noProg.stderr).toContain('/usr/bin/nothing: No such file or directory');
  // An uploaded copy of the same image runs by its path (execve of uploaded wasm, phase 2);
  // /usr/bin/ls is the same coreutils program in every shell.
  await pagePut(page, base + '/coreutils', coreutilsImage, { mode: 0o755 });
  expect((await execCmd(page, [base + '/coreutils', 'seq', '3'], { cwd: base })).stdout.trim()).toBe('1\n2\n3');
  expect((await execCmd(page, ['/usr/bin/ls'], { cwd: base })).stdout).toContain('names.txt');
  // A program of /bin reaches the kernel's own calls too, which WASI has no words for, through
  // the engine's os.sys: the batch goes as it is.
  const batch = JSON.stringify(['getcreds', { lstat: { path: 'names.txt' } }, { stat: { path: `${base}/names.txt` } }]);
  const syscallOut = (await execCmd(page, ['syscall', batch], { cwd: base })).stdout.replace(/\n/g, '');
  expect(syscallOut).toContain('"user":"root"');
  // The kernel takes absolute paths only, as user space makes them.
  expect(syscallOut).toContain('{"err":{"detail":"a path must be absolute","errno":"EINVAL"}}');
  expect(syscallOut).toContain('"mode":33188');
  const cu = await execCmd(page, ['coreutils'], { cwd: base });
  expect(cu.stdout + cu.stderr).toContain('coreutils (uutils 0.12.0, multi-call binary)');
  expect(cu.stdout + cu.stderr).toContain('Usage: coreutils UTILITY [ARGUMENT]...');
  // osh `help` lists uutils commands; `man` reports missing entries while `--help` documents uutils tools.
  const helpOut = await execCmd(page, ['/usr/bin/osh', '-c', 'help'], { cwd: base });
  expect(helpOut.status).toBe(0);
  expect(helpOut.stdout).toContain("/usr/bin, from uutils' coreutils (processes of their own)");
  expect(helpOut.stdout).toContain('sha256sum');
  const manCut = await execCmd(page, ['man', 'cut'], { cwd: base });
  expect(manCut.status).not.toBe(0);
  expect(manCut.stderr).toContain('no manual entry for cut');
  const cutHelp = await execCmd(page, ['cut', '--help'], { cwd: base });
  expect(cutHelp.status).toBe(0);
  expect(cutHelp.stdout).toContain('Usage:');
});

test('a program of /bin writes files through the kernel, as its account', async ({ page }) => {
  await bootRoot(page);
  // Written anew in order, closed whole.
  expect((await execSh(page, 'seq 1000 | tee counted.txt | tail -n 1', { cwd: base })).stdout.trim()).toBe('1000');
  const counted = await pageGetText(page, base + '/counted.txt');
  expect(counted.split('\n').length).toBe(1001);
  // Changed in place: what is there is read, changed and written back whole.
  expect((await execCmd(page, ['truncate', '-s', '4', 'names.txt'], { cwd: base })).status).toBe(0);
  expect(await pageGetText(page, base + '/names.txt')).toBe('ann:');
  // Appended to: the same.
  expect((await execSh(page, 'echo more | tee -a names.txt', { cwd: base })).status).toBe(0);
  expect(await pageGetText(page, base + '/names.txt')).toBe('ann:more\n');
  expect((await execCmd(page, ['/bin/mkdir', '-p', 'made/deeper'], { cwd: base })).status).toBe(0);
  expect((await execCmd(page, ['/bin/touch', 'made/deeper/x'], { cwd: base })).status).toBe(0);
  const made = await pageCall(page, { stat: { path: base + '/made/deeper/x' } });
  expect([made.user, made.size]).toEqual(['root', 0]);
  // The kernel decides: returning to unprivileged local `user` cannot remove root's file in root's 0755 dir.
  await logoutLocalUser(page);
  const removed = await execCmd(page, ['/bin/rm', 'counted.txt'], { cwd: base });
  expect(removed.status).not.toBe(0);
  expect(removed.stderr).toContain("rm: cannot remove 'counted.txt': Permission denied");
});

test('/usr is the build\'s, read-only: /usr/bin contains executable images and their applet links', async ({ page }) => {
  await bootRoot(page);
  expect((await execCmd(page, ['readlink', '/bin'])).stdout.trim()).toBe('usr/bin');
  const listed = (await execCmd(page, ['ls', '-l', '/usr/bin'])).stdout;
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* passwd -> utilities$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* sudo -> utilities$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* chmod -> utilities$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* open -> utilities$/m);
  expect(listed).toMatch(/^-rwxr-xr-x +1 root root +\d+ .* utilities$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* ls -> coreutils$/m);
  expect(listed).toMatch(/^lrwxrwxrwx +1 root root .* cut -> coreutils$/m);
  expect(listed).toMatch(/^-rwxr-xr-x +1 root root +\d{6,} .* coreutils$/m);
  // The shell's builtins are no files; root may change nothing of it.
  expect((await execSh(page, "ls /usr/bin | grep -c '^cd$'")).stdout.trim()).toBe('0');
  const rmCut = await execCmd(page, ['rm', '/usr/bin/cut']);
  expect(rmCut.status).not.toBe(0);
  expect(rmCut.stderr).toContain("rm: cannot remove '/usr/bin/cut': Read-only file system");
  const mkUsr = await execCmd(page, ['mkdir', '/usr/new-directory']);
  expect(mkUsr.status).not.toBe(0);
  expect(mkUsr.stderr).toMatch(/mkdir:.*\/usr\/new-directory.*Read-only file system/);
  // Its binaries read as the build has them.
  const coreutils = await pageGetBytes(page, '/usr/bin/cut');
  expect(coreutils).not.toBeNull();
  expect([...coreutils.subarray(0, 4)]).toEqual([0, 0x61, 0x73, 0x6d]);
  expect((await execCmd(page, ['df', '/usr'])).stdout).toMatch(/^\S+ +\d+ +\d+ +0 +100% \/usr$/m);
});

test('what programs write for a terminal shows as they mean it: colours, styles and links', async ({ page }) => {
  await bootRoot(page);
  await pageMkdirp(page, base + '/coloured', 0o755);
  const screen = terminalScreen(page);
  await runTerminal(page, "printf '\\033[1;31mred\\033[0m plain \\033[38;5;208morange\\033[m \\033]8;;https://example.com/\\033\\\\site\\033]8;;\\033\\\\\\n'");
  await expect(screen).toContainText('red plain orange site');
  await expect(screen.locator('span[style*="color:"]', { hasText: 'red' }).last()).toHaveAttribute('style', 'color:var(--ansi-1);font-weight:700;');
  await expect(screen.locator('span[style*="color:"]', { hasText: 'orange' }).last()).toHaveAttribute('style', 'color:rgb(255,135,0);');
  await expect(screen.locator('a', { hasText: 'site' }).last()).toHaveAttribute('href', 'https://example.com/');
  // uutils' ls colours what it lists, at a terminal.
  await runTerminal(page, `cd ${base} && coreutils ls --color=auto`);
  await expect(screen.locator('span[style*="color:"]', { hasText: 'coloured' }).last()).toHaveAttribute('style', /color:var\(--ansi-4\)/);
});

test('/ is laid out as Arch\'s', async ({ page }) => {
  await bootRoot(page);
  const names = (await execCmd(page, ['ls', '/'])).stdout.trim().split('\n');
  for (const name of ['bin', 'boot', 'dev', 'etc', 'home', 'lib', 'lib64', 'mnt', 'opt', 'proc', 'root', 'run', 'sbin', 'srv', 'sys', 'tmp', 'usr', 'var']) expect(names).toContain(name);
  expect((await execCmd(page, ['readlink', '/sbin', '/lib', '/lib64', '/usr/sbin', '/usr/lib64'])).stdout.trim()).toBe('usr/bin\nusr/lib\nusr/lib\nbin\nlib');
  expect((await execCmd(page, ['stat', '-c', '%a %U', '/tmp', '/root', '/sys', '/usr/local'])).stdout.trim()).toBe('1777 root\n700 root\n555 root\n755 root');
  expect((await execCmd(page, ['ls', '/usr'])).stdout.trim()).toBe('bin\ninclude\nlib\nlib64\nlibexec\nlocal\nsbin\nshare\nsrc');
  // A program is found through any of them.
  expect((await execCmd(page, ['/sbin/seq', '2'])).stdout.trim()).toBe('1\n2');
});

test('Ctrl+C kills a pipeline; head closes its input; streaming pipes wait for EOF', async ({ page }) => {
  await bootRoot(page);
  const input = terminalInput(page);
  const vp = terminalViewport(page);
  const screen = terminalScreen(page);
  const beforeSleep = Number((await vp.getAttribute('data-prompt-seq')) || '0');
  await runTerminal(page, 'sleep 30', { wait: false });
  await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await page.waitForTimeout(500);
  await input.press('Control+c');
  await expect.poll(async () => (await vp.getAttribute('data-state')) === 'idle' && Number((await vp.getAttribute('data-prompt-seq')) || '0') > beforeSleep, { timeout: 10_000 }).toBe(true);
  // head takes its lines and closes the pipe: yes hears SIGPIPE, and ends.
  expect((await execSh(page, 'yes | head -n 2')).stdout.trim()).toBe('y\ny');
  await runTerminal(page, 'yes | head -n 2');
  await expect(screen).toContainText('y\ny');
  await expect(screen).not.toContainText('cut short');
  // wc counts until EOF. An infinite producer stays running, with bounded pipe buffers,
  // rather than being truncated by a browser text-filter limit.
  const beforePipe = Number((await vp.getAttribute('data-prompt-seq')) || '0');
  await runTerminal(page, 'yes | wc -l', { wait: false });
  await expect(vp).toHaveAttribute('data-state', 'busy', { timeout: 15_000 });
  await page.waitForTimeout(500);
  await expect(vp).toHaveAttribute('data-state', 'busy');
  await input.press('Control+c');
  await expect.poll(async () => (await vp.getAttribute('data-state')) === 'idle' && Number((await vp.getAttribute('data-prompt-seq')) || '0') > beforePipe, { timeout: 10_000 }).toBe(true);
  await expect(screen).not.toContainText('cut short');
});
