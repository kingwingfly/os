import { test, expect } from './test.js';
import binaryen from 'binaryen';
import { readFile } from 'node:fs/promises';
import {
  execCmd,
  execSh,
  logoutLocalUser,
  pageCall,
  pageErrno,
  pageGetText,
  pageMkdirp,
  pagePut,
  pageRmrf,
  runTerminal,
  sendTerminalLine,
  switchLocalUser,
  terminalInput,
  terminalScreen,
  terminalViewport,
  waitForTerminalReady,
} from './ui.js';
import { hookPageKernel } from './service-auth.js';

let base, pageKernel;
async function sh(page, script, opts = {}) {
  return execSh(page, script, { cwd: base, ...opts });
}
async function output(page, script) {
  const res = await sh(page, script);
  return res.stdout.trim();
}
async function promptSeq(page) {
  return Number((await terminalViewport(page).getAttribute('data-prompt-seq')) || '0');
}
async function waitIdleAfter(page, before, timeout = 30_000) {
  await expect.poll(async () => {
    const vp = terminalViewport(page);
    return (await vp.getAttribute('data-state')) === 'idle'
      && Number((await vp.getAttribute('data-prompt-seq')) || '0') > before;
  }, { timeout }).toBe(true);
}

test.beforeEach(async ({ page }) => {
  base = '/tmp/exec-resolution-' + crypto.randomUUID();
  pageKernel = await hookPageKernel(page);
  await page.goto('/');
  await waitForTerminalReady(page);
  await switchLocalUser(page, 'root');
  await pageMkdirp(page, base + '/directory', 0o755);
  for (const name of ['alpha.txt', 'beta.txt', '.hidden']) {
    await pagePut(page, base + '/' + name, 'content\n', { mode: 0o644 });
  }
});
test.afterEach(async ({ page }) => {
  if (base) await pageRmrf(page, base, { sudo: true }).catch(() => {});
});

test('ls names and executable paths share program options, help and pipe output', async ({ page }) => {
  const expected = 'alpha.txt\nbeta.txt\ndirectory';
  for (const executable of ['ls', '/usr/bin/ls', '/bin/ls', '/sbin/ls', '/usr/sbin/ls', 'coreutils ls']) {
    expect(await output(page, executable + ' -1 --color=never')).toBe(expected);
  }
  // -h belongs to ls (human-readable sizes), not the browser's old help interceptor.
  expect(await output(page, 'ls -1h')).toBe(expected);
  expect(await output(page, 'ls -A1')).toBe('.hidden\n' + expected);
  const help = await output(page, 'ls --help');
  expect(help).toContain('--sort');
  expect(await output(page, '/usr/bin/ls --help')).toBe(help);
  // osh `help <cmd>` matches `<cmd> --help` for commands defined in os_core::cli.
  expect((await execCmd(page, ['/usr/bin/osh', '-c', 'help cp'], { cwd: base })).stdout.trim()).toBe(await output(page, 'cp --help'));
  expect(await output(page, 'echo alpha.txt | xargs /usr/bin/ls -1')).toBe('alpha.txt');
  expect(await output(page, 'sudo ls -1')).toBe(expected);
  expect(await output(page, 'sudo /usr/bin/ls -1')).toBe(expected);
});

test('coreutils receives real POSIX ownership, modes, hard links, symlinks and ACL metadata', async ({ page }) => {
  await sh(page, 'chmod 640 alpha.txt && ln alpha.txt hard.txt && ln -s alpha.txt symbolic.txt');
  expect(await output(page, 'ls -l alpha.txt')).toMatch(/^-rw-r----- +2 root root +8 /);
  expect(await output(page, 'ls -ln alpha.txt')).toMatch(/^-rw-r----- +2 0 +0 +8 /);
  expect(await output(page, 'ls -l symbolic.txt')).toMatch(/^lrwxrwxrwx +1 root root .* symbolic.txt -> alpha.txt$/);
  expect(await output(page, 'ls -lL symbolic.txt')).toMatch(/^-rw-r----- +2 root root +8 /);
  await sh(page, 'setfacl -m u:nobody:r alpha.txt');
  expect(await output(page, 'ls -l alpha.txt')).toMatch(/^-rw-r-----\+ +2 root root /);
  await sh(page, 'chmod 755 beta.txt');
  expect(await output(page, 'ls -F beta.txt')).toBe('beta.txt*');
  await sh(page, 'ls -1 | tee listing.txt');
  expect(await pageGetText(page, base + '/listing.txt')).toContain('alpha.txt\n');
});

test('explicit paths reach execution authorization and never become browser commands', async ({ page }) => {
  expect((await execCmd(page, ['/usr/bin/cat', '--help'], { cwd: base })).stdout).toContain('--show-all');
  expect((await execCmd(page, ['/usr/bin/chmod', '--help'], { cwd: base })).stdout).toContain('Usage: chmod');
  const missing = await execCmd(page, ['/usr/bin/osh', '-c', '/usr/bin/does-not-exist --help'], { cwd: base });
  expect(missing.status).not.toBe(0);
  expect(missing.stderr).toContain('/usr/bin/does-not-exist: No such file or directory');
  const image = await readFile('dist/usr/bin/coreutils.wasm');
  await pagePut(page, base + '/ls', image, { mode: 0o644 });
  const denied = await execCmd(page, ['/usr/bin/osh', '-c', './ls --help'], { cwd: base });
  expect(denied.status).not.toBe(0);
  expect(denied.stderr).toContain('Permission denied');
  await pageCall(page, { chmod: { path: base + '/ls', mode: 0o111 } });
  expect(await output(page, './ls -1 alpha.txt')).toBe('alpha.txt');
  await sh(page, 'mkdir private && chmod 700 private');
  await logoutLocalUser(page);
  const priv = await execCmd(page, ['ls', base + '/private']);
  expect(priv.status).not.toBe(0);
  expect(priv.stderr).toContain('Permission denied');
});

test('dash and the browser execute the same utilities, including redirection and exit status', async ({ page }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  await pagePut(page, base + '/dash.wasm', await readFile(process.env.WASIX_DASH), { mode: 0o755 });
  const browserListing = await output(page, 'ls -l alpha.txt');
  const dashListing = await output(page, `./dash.wasm -c 'cd ${base}; ls -l alpha.txt'`);
  expect(dashListing).toBe(browserListing);
  await sh(page, `./dash.wasm -c 'cd ${base}; ls -1 alpha.txt beta.txt > dash-list.txt'`);
  expect(await pageGetText(page, base + '/dash-list.txt')).toBe('alpha.txt\nbeta.txt\n');
  const statusRes = await sh(page, `./dash.wasm -c 'cd ${base}; ls missing; echo status=$?'`);
  expect(statusRes.stdout.trim()).toMatch(/status=2$/);
  expect(statusRes.stderr).toContain('No such file or directory');
  expect(await output(page, `./dash.wasm -c 'cd ${base}; chmod 600 alpha.txt; id -u'`)).toBe('0');
  expect((await pageCall(page, { stat: { path: base + '/alpha.txt' } })).mode & 0o777).toBe(0o600);
});

test('packaged utilities use process credentials and ordinary streams', async ({ page }) => {
  for (const command of ['chmod', '/bin/chmod', 'utilities chmod']) {
    expect((await sh(page, command + ' 600 alpha.txt')).status).toBe(0);
    expect((await pageCall(page, { stat: { path: base + '/alpha.txt' } })).mode & 0o777).toBe(0o600);
    expect((await sh(page, 'chmod 644 alpha.txt')).status).toBe(0);
  }
  expect(await output(page, 'cat -n alpha.txt')).toMatch(/1\s+content/);
  expect(await output(page, 'printf "z\\na\\na\\n" | sort | uniq | grep -n a')).toBe('1:a');
  expect((await execCmd(page, ['/usr/bin/id', '-u'], { cwd: base })).stdout.trim()).toBe('0');
  expect(await output(page, 'id -un')).toBe('root');
  expect(await output(page, 'id -Gn')).toContain('root');
  const badGrep = await execCmd(page, ['grep', '--no-such-option'], { cwd: base });
  expect(badGrep.status).not.toBe(0);
  expect(badGrep.stderr).toMatch(/^grep: unexpected argument/);
  expect((await pageCall(page, { lstat: { path: '/usr/bin/chmod' } })).link).toBe('utilities');
  await logoutLocalUser(page);
  const denied = await execCmd(page, ['chmod', '777', base + '/alpha.txt']);
  expect(denied.status).not.toBe(0);
  expect(denied.stderr).toContain('Operation not permitted');
  expect((await pageCall(page, { stat: { path: base + '/alpha.txt' } })).mode & 0o777).toBe(0o644);
});

test('PATH resolves user-installed programs and explicit paths bypass it', async ({ page }) => {
  const image = Buffer.from(binaryen.parseText(`(module
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 64) "PATH")
    (func (export "_start")
      (i32.store (i32.const 0) (i32.const 64))
      (i32.store (i32.const 4) (i32.const 4))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`).emitBinary());
  const path = base + '/hello';
  await pagePut(page, path, image, { mode: 0o755 });
  const osh = script => execCmd(page, ['/usr/bin/osh', '-c', script], { cwd: base });
  expect((await osh(`export PATH=${base}:/usr/bin; hello`)).stdout).toBe('PATH');
  expect((await osh(`export PATH=${base}:/usr/bin; printf "first\\nsecond\\n" | xargs -n1 hello`)).stdout).toBe('PATHPATH');
  expect((await osh(`export PATH=${base}:/usr/bin; fd -F alpha.txt -x hello`)).stdout).toBe('PATH');
  expect((await osh(`export PATH=/nowhere; ${path}`)).stdout).toBe('PATH');
  const missing = await osh('export PATH=/nowhere; hello');
  expect(missing.status).not.toBe(0);
  expect(missing.stderr).toContain('No such file or directory');
  expect((await osh('export PATH=/usr/bin; ls -1 alpha.txt')).stdout.trim()).toBe('alpha.txt');
});

test('copy, move and remove names share one installed implementation and preserve metadata', async ({ page }) => {
  for (const name of ['cp', 'mv', 'rm', 'fd', 'xargs']) {
    expect((await pageCall(page, { lstat: { path: '/usr/bin/' + name } })).link).toBe('utilities');
    const help = await output(page, name + ' --help');
    expect(await output(page, '/bin/' + name + ' --help')).toBe(help);
    expect(await output(page, 'utilities ' + name + ' --help')).toBe(help);
  }
  await sh(page, 'chmod 640 alpha.txt && setfacl -m u:nobody:r alpha.txt && ln alpha.txt directory/hard.txt && cp -a directory cloned');
  expect((await pageCall(page, { stat: { path: base + '/cloned/hard.txt' } })).mode & 0o777).toBe(0o640);
  expect(await output(page, 'getfacl -c cloned/hard.txt')).toContain('user:nobody:r--');
  await sh(page, '/bin/mv cloned moved');
  expect(await output(page, 'cat moved/hard.txt')).toBe('content');
  await sh(page, '/usr/bin/rm -r moved');
  const gone = await execCmd(page, ['ls', 'moved'], { cwd: base });
  expect(gone.status).not.toBe(0);
  expect(gone.stderr).toContain('No such file or directory');
});

test('native rm preserves interactive decisions, recursive prompts and force ordering', async ({ page }) => {
  // Terminal's `/usr/bin/osh` runs as local `user`; stage a `user`-owned working directory.
  await logoutLocalUser(page);
  const rmBase = '/tmp/exec-rm-' + crypto.randomUUID();
  await pageMkdirp(page, rmBase + '/directory', 0o755);
  for (const name of ['alpha.txt', 'beta.txt']) {
    await pagePut(page, rmBase + '/' + name, 'content\n', { mode: 0o644 });
  }
  try {
    await runTerminal(page, 'cd ' + rmBase);
    const start = async command => {
      await runTerminal(page, 'clear');
      const seq = await promptSeq(page);
      await runTerminal(page, command, { wait: false });
      return seq;
    };
    const answer = async (question, text) => {
      await expect(terminalScreen(page)).toContainText(question, { timeout: 20_000 });
      await sendTerminalLine(page, text);
    };
    let seq = await start('rm -fi alpha.txt');
    await answer("remove regular file 'alpha.txt'?", 'n');
    await waitIdleAfter(page, seq);
    expect(await pageErrno(page, { stat: { path: rmBase + '/alpha.txt' } })).toBeNull();
    await runTerminal(page, 'rm -if beta.txt');
    expect(await pageErrno(page, { stat: { path: rmBase + '/beta.txt' } })).toBe('ENOENT');
    await runTerminal(page, 'touch directory/empty');
    seq = await start('rm -ri directory');
    await answer("descend into directory 'directory'?", 'n');
    await waitIdleAfter(page, seq);
    expect(await pageErrno(page, { stat: { path: rmBase + '/directory/empty' } })).toBeNull();
    seq = await start('/bin/rm -ri directory');
    await answer("descend into directory 'directory'?", 'y');
    await answer("remove regular empty file 'directory/empty'?", 'y');
    await answer("remove directory 'directory'?", 'y');
    await waitIdleAfter(page, seq);
    expect(await pageErrno(page, { stat: { path: rmBase + '/directory/empty' } })).toBe('ENOENT');
    seq = await start('rm -i alpha.txt');
    await expect(terminalScreen(page)).toContainText("remove regular file 'alpha.txt'?", { timeout: 20_000 });
    await terminalInput(page).press('Control+c');
    await waitIdleAfter(page, seq);
    expect(await pageGetText(page, rmBase + '/alpha.txt')).toBe('content\n');
  } finally {
    await pageRmrf(page, rmBase, { sudo: true }).catch(() => {});
  }
});

test('dash launches native utilities and their children with ordinary status, stdin and redirection', async ({ page }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  const path = base + '/dash.wasm';
  await pagePut(page, path, await readFile(process.env.WASIX_DASH), { mode: 0o755 });
  const dash = async script => output(page, `./dash.wasm -c 'cd ${base}; ${script}'`);
  expect(await dash('cp alpha.txt copied; mv copied moved; cat moved; rm moved; echo status=$?')).toBe('content\nstatus=0');
  expect(await dash('/usr/bin/printf "a b c" | xargs -n1 echo > args.txt; cat args.txt')).toBe('a\nb\nc');
  expect(await dash('fd -F alpha.txt -x cat > found.txt; cat found.txt')).toBe('content');
  // A child must not consume the argument stream. cat gets EOF, then echo reports success.
  expect(await dash('/usr/bin/printf "one two" | xargs -n1 cat; echo status=$?')).toContain('status=123');
  expect(await dash('/usr/bin/printf ignored | xargs -I {} cat; echo stdin=$?')).toBe('stdin=0');
  expect(await dash('echo item | xargs no-such-program; echo missing=$?')).toContain('missing=127');
  expect(await dash('echo item | xargs ./alpha.txt; echo denied=$?')).toContain('denied=126');
  expect(await dash('echo item | xargs false; echo failed=$?')).toBe('failed=123');
  expect(await dash('echo item | xargs -I {} ./dash.wasm -c "exit 255"; echo stopped=$?')).toContain('stopped=124');
  expect(await dash('echo item | xargs -I {} ./dash.wasm -c "kill -TERM \\$\\$"; echo signal=$?')).toContain('signal=125');
});

test('sequential children consume one inherited stdin stream', async ({ page }) => {
  const module = binaryen.parseText(`(module
    (import "wasi_snapshot_preview1" "fd_read" (func $read (param i32 i32 i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (func (export "_start")
      (i32.store (i32.const 0) (i32.const 64)) (i32.store (i32.const 4) (i32.const 4096))
      (drop (call $read (i32.const 0) (i32.const 0) (i32.const 1) (i32.const 8)))
      (i32.store (i32.const 4) (i32.load (i32.const 8)))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  const image = Buffer.from(module.emitBinary()); module.dispose();
  const path = base + '/reader.wasm';
  await pagePut(page, path, image, { mode: 0o755 });
  // pwd is a shell builtin, so this stage feeds stdin into fd -x.
  // Each reader must share its offset: only the first child can consume those bytes.
  expect(await output(page, 'pwd | fd -e txt -x ./reader.wasm')).toBe(base);
});

test('streaming xargs runs before EOF and Ctrl+C reaps both parent and children', async ({ page }) => {
  await pageKernel.ready();
  const seq = await promptSeq(page);
  await runTerminal(page, 'yes item | xargs -n1 echo', { wait: false });
  await expect(terminalScreen(page)).toContainText('item\nitem', { timeout: 20_000 });
  await expect.poll(async () => (await pageKernel.value('poll', { pids: [] })).some(row => row.argv?.[0] === 'xargs'), { timeout: 10_000 }).toBe(true);
  await terminalInput(page).press('Control+c');
  await waitIdleAfter(page, seq, 10_000);
  await runTerminal(page, 'echo responsive');
  await expect(terminalScreen(page)).toContainText('responsive');
  await expect.poll(async () => {
    const rows = await pageKernel.value('poll', { pids: [] });
    return rows.filter(row => ['yes', 'xargs', 'echo'].includes(row.argv?.[0]));
  }, { timeout: 10_000 }).toEqual([]);
});

test('spawned children retain process credentials across logout and new commands use the default local user identity', async ({ page }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  const path = base + '/dash.wasm';
  await pagePut(page, path, await readFile(process.env.WASIX_DASH), { mode: 0o755 });
  await sh(page, 'chmod 600 alpha.txt');
  await page.evaluate(({ base }) => {
    const run = { out: '' };
    window.__credRun = run;
    run.done = window.os.exec(
      [['/bin/sh', '-c', 'echo item | xargs -I {} ./dash.wasm -c "echo READY; sleep 2; id -u"']],
      { cwd: base, stdin: '', onOutput: (fd, text) => { if (fd === 1) run.out += text; } },
    ).then(result => { run.result = result; });
  }, { base });
  await expect.poll(() => page.evaluate(() => window.__credRun.out.trim()), { timeout: 60_000 }).toBe('READY');
  await logoutLocalUser(page);
  await expect.poll(() => page.evaluate(() => window.__credRun.result?.status), { timeout: 30_000 }).toBe(0);
  expect(await page.evaluate(() => window.__credRun.result.stdout.trim())).toBe('READY\n0');
  // New commands after logout run as unprivileged local `user` (uid 1000).
  expect(await output(page, 'echo item | xargs -I {} id -u')).not.toBe('0');
  expect((await sh(page, 'fd -F alpha.txt -x cat')).stderr).toContain('Permission denied');
  expect((await sh(page, 'echo alpha.txt | xargs chmod 777')).stderr).toContain('Operation not permitted');
  expect((await pageCall(page, { stat: { path: base + '/alpha.txt' } }, { sudo: true })).mode & 0o777).toBe(0o600);
});

test('WASIX PATH search skips denied candidates and honors an empty PATH', async ({ page }) => {
  const wasm = source => {
    const module = binaryen.parseText(source);
    try { return Buffer.from(module.emitBinary()); } finally { module.dispose(); }
  };
  const hello = wasm(`(module
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 64) "PATH")
    (func (export "_start")
      (i32.store (i32.const 0) (i32.const 64)) (i32.store (i32.const 4) (i32.const 4))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
  const launcher = wasm(`(module
    (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 64) "hello")
    (func (export "_start")
      (drop (call $exec (i32.const 64) (i32.const 5) (i32.const 64) (i32.const 5)))))`);
  await pageMkdirp(page, base + '/denied', 0o755);
  for (const [name, data, mode] of [['hello', hello, 0o755], ['denied/hello', hello, 0o644], ['launcher.wasm', launcher, 0o755]]) {
    await pagePut(page, base + '/' + name, data, { mode });
  }
  const osh = script => execCmd(page, ['/usr/bin/osh', '-c', script], { cwd: base });
  expect((await osh(`export PATH=${base}/denied:${base}; ./launcher.wasm`)).stdout).toBe('PATH');
  expect((await osh('export PATH=; ./launcher.wasm')).stdout).toBe('PATH');
  const denied = await osh(`export PATH=${base}/denied:/no-such-directory; ./launcher.wasm`);
  expect((denied.stdout + denied.stderr).trim()).toBe('hello: Permission denied');
});

test('mkdir creates explicit modes atomically and preserves default ACL and setgid inheritance', async ({ page }) => {
  for (const [program, directory] of [['mkdir', 'bare'], ['/usr/bin/mkdir', 'path']]) {
    expect((await sh(page, `${program} -p -m 0711 ${directory}/leaf`)).status).toBe(0);
    expect((await pageCall(page, { stat: { path: base + '/' + directory } })).mode & 0o7777).toBe(0o755);
    expect((await pageCall(page, { stat: { path: base + '/' + directory + '/leaf' } })).mode & 0o7777).toBe(0o711);
    expect((await sh(page, `rmdir -p ${directory}/leaf`)).status).toBe(0);
  }
  await sh(page, 'mkdir -m 2775 inherited && setfacl -d -m u:nobody:rwx inherited && mkdir -m 700 inherited/private');
  const privateDir = await pageCall(page, { stat: { path: base + '/inherited/private' } });
  expect(privateDir.mode & 0o7777).toBe(0o2700);
  expect(privateDir.acl).toBe(true);
  expect(await output(page, 'getfacl -c inherited/private')).toContain('user:nobody:rwx');
  await sh(page, 'mkdir -p -m 777 inherited/private');
  expect((await pageCall(page, { stat: { path: base + '/inherited/private' } })).mode & 0o7777).toBe(0o2700);
});

test('mkdir shapes a restrictive process umask for parents and explicit leaf permissions', async ({ page }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  const path = base + '/dash.wasm';
  await pagePut(page, path, await readFile(process.env.WASIX_DASH), { mode: 0o755 });
  // Both exec and fork must inherit the mask. The command after mkdir prevents
  // dash from optimizing its last command into exec without a fork.
  const argv = `dash\n-c\n/usr/bin/mkdir -p -m 0777 ${base}/masked/leaf; /usr/bin/mkdir ${base}/masked/plain; echo item | xargs -I {} /usr/bin/mkdir ${base}/spawn-mask; echo done`;
  const module = binaryen.parseText(`(module
    (import "os" "umask" (func $umask (param i32) (result i32)))
    (import "wasix_32v1" "proc_exec" (func $exec (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 64) "${path}")
    (data (i32.const 256) "${argv.replaceAll('\n', '\\0a')}")
    (func (export "_start")
      (drop (call $umask (i32.const 511)))
      (drop (call $exec (i32.const 64) (i32.const ${path.length}) (i32.const 256) (i32.const ${argv.length})))))`);
  const image = Buffer.from(module.emitBinary()); module.dispose();
  await pagePut(page, base + '/masked.wasm', image, { mode: 0o755 });
  const res = await execCmd(page, [base + '/masked.wasm'], { cwd: base });
  expect(res.stdout.trim()).toBe('done');
  expect((await pageCall(page, { stat: { path: base + '/masked' } })).mode & 0o777).toBe(0o300);
  expect((await pageCall(page, { stat: { path: base + '/masked/leaf' } })).mode & 0o777).toBe(0o777);
  expect((await pageCall(page, { stat: { path: base + '/masked/plain' } })).mode & 0o777).toBe(0);
  expect((await pageCall(page, { stat: { path: base + '/spawn-mask' } })).mode & 0o777).toBe(0);
});

test('link, canonical path and timestamp programs use normal syscalls, including symlink timestamps', async ({ page }) => {
  await sh(page, 'ln alpha.txt hard.txt && ln -s alpha.txt link.txt');
  expect(await output(page, 'readlink link.txt')).toBe('alpha.txt');
  expect(await output(page, 'realpath link.txt')).toBe(base + '/alpha.txt');
  expect((await pageCall(page, { stat: { path: base + '/hard.txt' } })).nlink).toBe(2);
  await sh(page, 'touch -d @1600000000 alpha.txt && touch -h -d @1500000000 link.txt');
  expect((await pageCall(page, { lstat: { path: base + '/link.txt' } })).mtime).toBe(1500000000);
  expect((await pageCall(page, { stat: { path: base + '/alpha.txt' } })).mtime).toBe(1600000000);
  await sh(page, 'touch -r alpha.txt copy.txt');
  expect((await pageCall(page, { stat: { path: base + '/copy.txt' } })).mtime).toBe(1600000000);
});
