import { test, expect } from './test.js';
import binaryen from 'binaryen';
import { readFile } from 'node:fs/promises';
import { api, call, mkdirp, put, rmrf, processes } from './sys.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const file = path => '/api/file?path=' + encodeURIComponent(path);
const busy = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();
let base;
async function run(page, command) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await page.locator('#command').fill(command);
  await page.locator('#command').press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}
async function output(page, command) {
  await run(page, command + ' | cat');
  return (await last(page).innerText()).trim();
}

test.beforeEach(async ({ page, request }) => {
  base = '/guest/exec-resolution-' + crypto.randomUUID();
  const headers = { Origin: origin, 'CF-Connecting-IP': base };
  expect((await api(request, 'login', { headers, data: { password } })).ok()).toBe(true);
  expect((await api(page.request, 'login', { headers: { ...headers, 'CF-Connecting-IP': base + '-page' }, data: { password } })).ok()).toBe(true);
  await mkdirp(request, base + '/directory');
  for (const name of ['alpha.txt', 'beta.txt', '.hidden']) {
    expect((await put(request, file(base + '/' + name), { data: 'content\n' })).ok()).toBe(true);
  }
  await page.goto('/');
  await run(page, 'cd ' + base);
});
test.afterEach(async ({ request }) => { await rmrf(request, base); });

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
  expect(await output(page, 'help ls')).toBe(help);
  expect(await output(page, 'echo alpha.txt | xargs /usr/bin/ls -1')).toBe('alpha.txt');
  expect(await output(page, 'sudo ls -1')).toBe(expected);
  expect(await output(page, 'sudo /usr/bin/ls -1')).toBe(expected);
});

test('coreutils receives real POSIX ownership, modes, hard links, symlinks and ACL metadata', async ({ page, request }) => {
  await run(page, 'chmod 640 alpha.txt');
  await run(page, 'ln alpha.txt hard.txt');
  await run(page, 'ln -s alpha.txt symbolic.txt');
  expect(await output(page, 'ls -l alpha.txt')).toMatch(/^-rw-r----- +2 root root +8 /);
  expect(await output(page, 'ls -ln alpha.txt')).toMatch(/^-rw-r----- +2 0 +0 +8 /);
  expect(await output(page, 'ls -l symbolic.txt')).toMatch(/^lrwxrwxrwx +1 root root .* symbolic.txt -> alpha.txt$/);
  expect(await output(page, 'ls -lL symbolic.txt')).toMatch(/^-rw-r----- +2 root root +8 /);
  await run(page, 'setfacl -m u:guest:r alpha.txt');
  expect(await output(page, 'ls -l alpha.txt')).toMatch(/^-rw-r-----\+ +2 root root /);
  await run(page, 'chmod 755 beta.txt');
  expect(await output(page, 'ls -F beta.txt')).toBe('beta.txt*');
  await run(page, 'ls -1 | tee listing.txt');
  expect(await (await request.get(file(base + '/listing.txt'))).text()).toContain('alpha.txt\n');
});

test('explicit paths reach execution authorization and never become browser commands', async ({ page, request }) => {
  await run(page, '/usr/bin/cat --help');
  await expect(last(page)).toContainText('--show-all');
  await run(page, '/usr/bin/chmod --help');
  await expect(last(page)).toContainText('Usage: chmod');
  // Browser actions have no fake executable image.
  await run(page, '/usr/bin/open --help');
  await expect(last(page)).toContainText('No such file or directory');
  await run(page, '/usr/bin/does-not-exist --help');
  await expect(page.locator('.transcript')).toContainText('/usr/bin/does-not-exist: No such file or directory');
  const image = await readFile('dist/usr/bin/coreutils.wasm');
  expect((await put(request, file(base + '/ls'), { data: image })).ok()).toBe(true);
  await call(request, { chmod: { path: base + '/ls', mode: 0o644 } });
  await run(page, './ls --help');
  await expect(page.locator('.transcript')).toContainText('Permission denied');
  await call(request, { chmod: { path: base + '/ls', mode: 0o111 } });
  expect(await output(page, './ls -1 alpha.txt')).toBe('alpha.txt');
  await run(page, 'mkdir private'); await run(page, 'chmod 700 private');
  await run(page, 'logout');
  await run(page, 'ls ' + base + '/private');
  await expect(page.locator('.transcript')).toContainText('Permission denied');
});

test('dash and the browser execute the same utilities, including redirection and exit status', async ({ page, request }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  expect((await put(request, file(base + '/dash.wasm'), { data: await readFile(process.env.WASIX_DASH) })).ok()).toBe(true);
  await call(request, { chmod: { path: base + '/dash.wasm', mode: 0o755 } });
  const browserListing = await output(page, 'ls -l alpha.txt');
  const dashListing = await output(page, `./dash.wasm -c 'cd ${base}; ls -l alpha.txt'`);
  expect(dashListing).toBe(browserListing);
  await run(page, `./dash.wasm -c 'cd ${base}; ls -1 alpha.txt beta.txt > dash-list.txt'`);
  expect(await (await request.get(file(base + '/dash-list.txt'))).text()).toBe('alpha.txt\nbeta.txt\n');
  const status = await output(page, `./dash.wasm -c 'cd ${base}; ls missing; echo status=$?'`);
  expect(status).toMatch(/status=2$/);
  expect(await output(page, `./dash.wasm -c 'cd ${base}; chmod 600 alpha.txt; id -u'`)).toBe('0');
  expect((await call(request, { stat: { path: base + '/alpha.txt' } })).mode & 0o777).toBe(0o600);
  await expect(page.locator('.transcript')).toContainText('No such file or directory');
});


test('packaged utilities use process credentials and ordinary streams', async ({ page, request }) => {
  for (const command of ['chmod', '/bin/chmod', 'utilities chmod']) {
    await run(page, command + ' 600 alpha.txt');
    expect((await call(request, { stat: { path: base + '/alpha.txt' } })).mode & 0o777).toBe(0o600);
    await run(page, 'chmod 644 alpha.txt');
  }
  expect(await output(page, 'cat -n alpha.txt')).toMatch(/1\s+content/);
  expect(await output(page, 'printf "z\\na\\na\\n" | sort | uniq | grep -n a')).toBe('1:a');
  await run(page, '/usr/bin/id -u');
  await expect(last(page)).toHaveText('0');
  expect(await output(page, 'id -un')).toBe('root');
  expect(await output(page, 'id -Gn')).toContain('root');
  await run(page, 'grep --no-such-option');
  await expect(last(page)).toContainText(/^grep: unexpected argument/);
  expect((await call(request, { lstat: { path: '/usr/bin/chmod' } })).link).toBe('utilities');
  await run(page, 'logout');
  await run(page, 'chmod 777 ' + base + '/alpha.txt');
  await expect(last(page)).toContainText('Operation not permitted');
  expect((await call(request, { stat: { path: base + '/alpha.txt' } })).mode & 0o777).toBe(0o644);
});

test('PATH resolves user-installed programs and explicit paths bypass it', async ({ page, request }) => {
  const image = Buffer.from(binaryen.parseText(`(module
    (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
    (memory (export "memory") 1)
    (data (i32.const 64) "PATH")
    (func (export "_start")
      (i32.store (i32.const 0) (i32.const 64))
      (i32.store (i32.const 4) (i32.const 4))
      (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`).emitBinary());
  const path = base + '/hello';
  expect((await put(request, file(path), { data: image })).ok()).toBe(true);
  await call(request, { chmod: { path, mode: 0o755 } });
  await run(page, 'export PATH=' + base + ':/usr/bin');
  await run(page, 'hello'); await expect(last(page)).toHaveText('PATH');
  expect(await output(page, 'printf "first\\nsecond\\n" | xargs -n1 hello')).toBe('PATHPATH');
  expect(await output(page, 'fd -F alpha.txt -x hello')).toBe('PATH');
  await run(page, 'export PATH=/nowhere');
  await run(page, path); await expect(last(page)).toHaveText('PATH');
  await run(page, 'hello'); await expect(last(page)).toContainText('No such file or directory');
  await run(page, 'export PATH=/usr/bin');
  expect(await output(page, 'ls -1 alpha.txt')).toBe('alpha.txt');
});

test('copy, move and remove names share one installed implementation and preserve metadata', async ({ page, request }) => {
  for (const name of ['cp', 'mv', 'rm', 'fd', 'xargs']) {
    expect((await call(request, { lstat: { path: '/usr/bin/' + name } })).link).toBe('utilities');
    const help = await output(page, name + ' --help');
    expect(await output(page, '/bin/' + name + ' --help')).toBe(help);
    expect(await output(page, 'utilities ' + name + ' --help')).toBe(help);
  }
  await run(page, 'chmod 640 alpha.txt');
  await run(page, 'setfacl -m u:guest:r alpha.txt');
  await run(page, 'ln alpha.txt directory/hard.txt');
  await run(page, 'cp -a directory cloned');
  expect((await call(request, { stat: { path: base + '/cloned/hard.txt' } })).mode & 0o777).toBe(0o640);
  expect(await output(page, 'getfacl -c cloned/hard.txt')).toContain('user:guest:r--');
  await run(page, '/bin/mv cloned moved');
  expect(await output(page, 'cat moved/hard.txt')).toBe('content');
  await run(page, '/usr/bin/rm -r moved');
  await run(page, 'ls moved'); await expect(last(page)).toContainText('No such file or directory');
});

test('native rm preserves interactive decisions, recursive prompts and force ordering', async ({ page, request }) => {
  const start = async command => {
    await expect(busy(page)).toHaveAttribute('data-state', 'idle');
    await page.locator('#command').fill(command); await page.locator('#command').press('Enter');
  };
  const answer = async (question, text) => {
    await expect(busy(page)).toHaveAttribute('data-state', 'input');
    await expect(last(page)).toContainText(question);
    await page.locator('#command').fill(text); await page.locator('#command').press('Enter');
  };
  await start('rm -fi alpha.txt');
  await answer("remove regular file 'alpha.txt'?", 'n');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  expect((await request.get(file(base + '/alpha.txt'))).status()).toBe(200);
  await run(page, 'rm -if beta.txt');
  expect((await request.get(file(base + '/beta.txt'))).status()).toBe(404);
  await run(page, 'touch directory/empty');
  await start('rm -ri directory');
  await answer("descend into directory 'directory'?", 'n');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  expect((await request.get(file(base + '/directory/empty'))).status()).toBe(200);
  await start('/bin/rm -ri directory');
  await answer("descend into directory 'directory'?", 'y');
  await answer("remove regular empty file 'directory/empty'?", 'y');
  await answer("remove directory 'directory'?", 'y');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  expect((await request.get(file(base + '/directory/empty'))).status()).toBe(404);
  await start('rm -i alpha.txt');
  await expect(busy(page)).toHaveAttribute('data-state', 'input');
  await page.locator('#command').press('Control+c');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  expect(await (await request.get(file(base + '/alpha.txt'))).text()).toBe('content\n');
});

test('dash launches native utilities and their children with ordinary status, stdin and redirection', async ({ page, request }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  const path = base + '/dash.wasm';
  expect((await put(request, file(path), { data: await readFile(process.env.WASIX_DASH) })).ok()).toBe(true);
  await call(request, { chmod: { path, mode: 0o755 } });
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

test('sequential children consume one inherited stdin stream', async ({ page, request }) => {
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
  await put(request, file(path), { data: image });
  await call(request, { chmod: { path, mode: 0o755 } });
  // pwd is a shell builtin, so this stage starts with buffered stdin rather than a pipe.
  // Each reader must share its offset: only the first child can consume those bytes.
  expect(await output(page, 'pwd | fd -e txt -x ./reader.wasm')).toBe(base);
});

test('streaming xargs runs before EOF and Ctrl+C reaps both parent and children', async ({ page }) => {
  await page.locator('#command').fill('yes item | xargs -n1 echo');
  await page.locator('#command').press('Enter');
  await expect(last(page)).toContainText('item\nitem');
  expect((await processes(page.request)).some(row => row.cmdline[0] === 'xargs')).toBe(true);
  await page.locator('#command').press('Control+c');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 5000 });
  await run(page, 'echo responsive'); await expect(last(page)).toHaveText('responsive');
  await expect.poll(async () => {
    const rows = await processes(page.request);
    return rows.filter(row => ['yes', 'xargs', 'echo'].includes(row.cmdline[0]));
  }).toEqual([]);
});

test('spawned children retain process credentials across logout and new commands use the guest identity', async ({ page, request }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  const path = base + '/dash.wasm';
  await put(request, file(path), { data: await readFile(process.env.WASIX_DASH) });
  await call(request, { chmod: { path, mode: 0o755 } });
  await run(page, 'chmod 600 alpha.txt');
  await page.locator('#command').fill(`echo item | xargs -I {} ./dash.wasm -c "echo READY; sleep 2; id -u"`);
  await page.locator('#command').press('Enter');
  await expect(last(page)).toHaveText('READY', { timeout: 60_000 });
  expect((await api(page.request, 'logout', { headers: { Origin: origin } })).ok()).toBe(true);
  await expect(busy(page)).toHaveAttribute('data-state', 'idle');
  await expect(last(page)).toHaveText('READY\n0');
  // Refresh the page's account state while retaining the same browser namespace.
  await page.reload(); await run(page, 'cd ' + base);
  expect(await output(page, 'echo item | xargs -I {} id -u')).not.toBe('0');
  await run(page, 'fd -F alpha.txt -x cat'); await expect(last(page)).toContainText('Permission denied');
  await run(page, 'echo alpha.txt | xargs chmod 777'); await expect(last(page)).toContainText('Operation not permitted');
  expect((await call(request, { stat: { path: base + '/alpha.txt' } })).mode & 0o777).toBe(0o600);
});

test('command-name completion enumerates executable PATH entries and skips denied images', async ({ page, request }) => {
  await run(page, 'cp /usr/bin/true directory/custom-tool');
  await run(page, 'chmod 755 directory/custom-tool');
  await run(page, 'cp /usr/bin/true directory/custom-denied');
  await run(page, 'chmod 644 directory/custom-denied');
  await run(page, 'ln -s custom-tool directory/custom-link');
  await run(page, 'export PATH=directory:/usr/bin');
  await page.locator('#command').fill('custom-t'); await page.locator('#command').press('Tab');
  await expect(page.locator('#command')).toHaveValue('custom-tool ');
  await page.locator('#command').fill('custom-l'); await page.locator('#command').press('Tab');
  await expect(page.locator('#command')).toHaveValue('custom-link ');
  await page.locator('#command').fill('custom-d'); await page.locator('#command').press('Tab');
  await expect(page.locator('#command')).toHaveValue('custom-d');
  await expect(page.getByRole('option')).toHaveCount(0);
  await page.locator('#command').fill('');
  await run(page, 'export PATH=/usr/bin');
  await page.locator('#command').fill('custom-t'); await page.locator('#command').press('Tab');
  await expect(page.locator('#command')).toHaveValue('custom-t');
  await expect(page.getByRole('option')).toHaveCount(0);
});

test('WASIX PATH search skips denied candidates and honors an empty PATH', async ({ page, request }) => {
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
  await mkdirp(request, base + '/denied');
  for (const [name, data, mode] of [['hello', hello, 0o755], ['denied/hello', hello, 0o644], ['launcher.wasm', launcher, 0o755]]) {
    const path = base + '/' + name;
    expect((await put(request, file(path), { data })).ok()).toBe(true);
    await call(request, { chmod: { path, mode } });
  }
  await run(page, `export PATH=${base}/denied:${base}`);
  await run(page, './launcher.wasm'); await expect(last(page)).toHaveText('PATH');
  await run(page, 'export PATH=');
  await run(page, './launcher.wasm'); await expect(last(page)).toHaveText('PATH');
  await run(page, `export PATH=${base}/denied:/no-such-directory`);
  await run(page, './launcher.wasm'); await expect(last(page)).toHaveText('hello: Permission denied');
});

test('mkdir creates explicit modes atomically and preserves default ACL and setgid inheritance', async ({ page, request }) => {
  for (const [program, directory] of [['mkdir', 'bare'], ['/usr/bin/mkdir', 'path']]) {
    await run(page, `${program} -p -m 0711 ${directory}/leaf`);
    expect((await call(request, { stat: { path: base + '/' + directory } })).mode & 0o7777).toBe(0o755);
    expect((await call(request, { stat: { path: base + '/' + directory + '/leaf' } })).mode & 0o7777).toBe(0o711);
    await run(page, `rmdir -p ${directory}/leaf`);
  }
  await run(page, 'mkdir -m 2775 inherited');
  await run(page, 'setfacl -d -m u:guest:rwx inherited');
  await run(page, 'mkdir -m 700 inherited/private');
  const privateDir = await call(request, { stat: { path: base + '/inherited/private' } });
  expect(privateDir.mode & 0o7777).toBe(0o2700);
  expect(privateDir.acl).toBe(true);
  expect(await output(page, 'getfacl -c inherited/private')).toContain('user:guest:rwx');
  await run(page, 'mkdir -p -m 777 inherited/private');
  expect((await call(request, { stat: { path: base + '/inherited/private' } })).mode & 0o7777).toBe(0o2700);
});

test('mkdir shapes a restrictive process umask for parents and explicit leaf permissions', async ({ page, request }) => {
  test.skip(!process.env.WASIX_DASH, 'set WASIX_DASH to the approved fixture');
  const path = base + '/dash.wasm';
  expect((await put(request, file(path), { data: await readFile(process.env.WASIX_DASH) })).ok()).toBe(true);
  await call(request, { chmod: { path, mode: 0o755 } });
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
  expect((await put(request, file(base + '/masked.wasm'), { data: image })).ok()).toBe(true);
  await call(request, { chmod: { path: base + '/masked.wasm', mode: 0o755 } });
  await run(page, './masked.wasm');
  await expect(last(page)).toHaveText('done');
  expect((await call(request, { stat: { path: base + '/masked' } })).mode & 0o777).toBe(0o300);
  expect((await call(request, { stat: { path: base + '/masked/leaf' } })).mode & 0o777).toBe(0o777);
  expect((await call(request, { stat: { path: base + '/masked/plain' } })).mode & 0o777).toBe(0);
  expect((await call(request, { stat: { path: base + '/spawn-mask' } })).mode & 0o777).toBe(0);
});

test('link, canonical path and timestamp programs use normal syscalls, including symlink timestamps', async ({ page, request }) => {
  await run(page, 'ln alpha.txt hard.txt');
  await run(page, 'ln -s alpha.txt link.txt');
  expect(await output(page, 'readlink link.txt')).toBe('alpha.txt');
  expect(await output(page, 'realpath link.txt')).toBe(base + '/alpha.txt');
  expect((await call(request, { stat: { path: base + '/hard.txt' } })).nlink).toBe(2);
  await run(page, 'touch -d @1600000000 alpha.txt');
  await run(page, 'touch -h -d @1500000000 link.txt');
  expect((await call(request, { lstat: { path: base + '/link.txt' } })).mtime).toBe(1500000000);
  expect((await call(request, { stat: { path: base + '/alpha.txt' } })).mtime).toBe(1600000000);
  await run(page, 'touch -r alpha.txt copy.txt');
  expect((await call(request, { stat: { path: base + '/copy.txt' } })).mtime).toBe(1600000000);
});
