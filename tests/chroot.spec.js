import { test, expect, request as playwrightRequest } from './test.js';
import { readFile } from 'node:fs/promises';
import { api, call, mkdirp, program, put, rmrf } from './sys.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const userPassword = 'chroot-spec-password-7391';
const fileUrl = path => '/api/file?path=' + encodeURIComponent(path);

let ipSeq = 0;
const nextIp = label => `chroot-e2e-${label}-${Date.now()}-${++ipSeq}`;

const busy = page => page.locator('.terminal-panel:not([hidden]) .command-line');
const last = page => page.locator('.terminal-panel:not([hidden]) .transcript pre').last();

async function runCli(page, command) {
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
  await page.locator('#command').fill(command);
  await page.locator('#command').press('Enter');
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
}

async function cliOutput(page, command) {
  await runCli(page, `${command} | cat`);
  return (await last(page).innerText()).trim();
}

async function execCmd(page, argv, { cwd = '/', sudo = false, stdin = '', environment } = {}) {
  return page.evaluate(
    async ({ argv, cwd, sudo, stdin, environment }) => {
      let stdout = '';
      let stderr = '';
      const res = await window.os.exec([{ path: argv[0], argv }], {
        cwd,
        sudo,
        stdin,
        ...(environment ? { environment } : {}),
        onOutput(fd, text) {
          if (fd === 1) stdout += text;
          else if (fd === 2) stderr += text;
        },
      });
      return {
        status: res.status,
        stdout: stdout || res.stdout || '',
        stderr,
      };
    },
    { argv, cwd, sudo, stdin, environment },
  );
}

let rootApi;
test.beforeAll(async () => {
  rootApi = await playwrightRequest.newContext({
    baseURL: origin,
    extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': nextIp('root-admin') },
  });
  expect((await api(rootApi, 'login', { data: { password: rootPassword } })).ok()).toBe(true);
});

test.afterAll(async () => {
  await rootApi?.dispose();
});

test('sudo chroot /tmp/jail clamps ../../.. at /, resolves #! interpreters inside the jail, and leaves parent root intact', async ({ browser }) => {
  test.setTimeout(120_000);
  const username = `chruser${Date.now().toString(36)}`;
  expect((await program(rootApi, ['useradd', '-m', '-G', 'wheel', username])).ok()).toBe(true);
  expect((await api(rootApi, 'passwd', { data: { username, password: userPassword } })).ok()).toBe(true);

  const base = `/tmp/chroot-suite-${crypto.randomUUID()}`;
  const jail = `${base}/jail`;
  const emptyJail = `${base}/empty`;
  const outsideSentinel = `${base}/outside-only.txt`;
  const outsideTool = `${base}/outside-true`;

  const shebangScript = [
    '#!/bin/sh -e',
    'pwd',
    'cat /jail-id.txt',
    'cd /../../../..',
    'pwd',
    'cat /../../../../jail-id.txt',
    'if [ -e /outside-only.txt ] || [ -e /tmp/outside-only.txt ]; then echo ESCAPED; exit 9; fi',
    'echo "arg=$1"',
    '',
  ].join('\n');

  const ip = nextIp(username);
  const context = await browser.newContext({ extraHTTPHeaders: { 'CF-Connecting-IP': ip } });
  const headers = { Origin: origin, 'CF-Connecting-IP': ip };
  expect((await api(context.request, 'login', { headers, data: { username, password: userPassword } })).ok()).toBe(true);
  expect((await api(context.request, 'sudo', { headers, data: { password: userPassword } })).ok()).toBe(true);

  const page = await context.newPage();
  try {
    await page.goto(origin + '/');
    await page.waitForFunction(() => Boolean(window.os?.exec));
    await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });

    // Stage the chroot tree inside the browser instance's own tmpfs `/tmp` (Contract v2 §2.1).
    const stageRes = await execCmd(page, [
      '/usr/bin/sh',
      '-ec',
      [
        `mkdir -p "${jail}/usr" "${jail}/tmp" "${emptyJail}"`,
        `chmod 1777 "${jail}/tmp"`,
        `ln -s usr/bin "${jail}/bin"`,
        `printf 'host-outside\\n' > "${outsideSentinel}"`,
        `printf 'jailed-root\\n' > "${jail}/jail-id.txt"`,
        `cat > "${jail}/run-inside.sh"`,
        `chmod 755 "${jail}/run-inside.sh"`,
        `printf '#!/usr/bin/sh\\necho unreachable\\n' > "${emptyJail}/dangling-shebang.sh"`,
        `chmod 755 "${emptyJail}/dangling-shebang.sh"`,
      ].join('\n'),
    ], { stdin: shebangScript });
    expect(stageRes.status, stageRes.stderr).toBe(0);

    // Create an executable binary outside the jail
    await runCli(page, `cp /usr/bin/true ${outsideTool} && chmod 755 ${outsideTool}`);

    // Bind-mount /usr into /tmp/.../jail/usr so /bin/sh and coreutils exist inside jail
    await runCli(page, `sudo mount --bind /usr ${jail}/usr`);

    // 1. Execute #! script inside jail via interactive CLI and via window.os.exec
    const cliOut = await cliOutput(page, `sudo chroot ${jail} /run-inside.sh ok-token`);
    expect(cliOut.split('\n').map(s => s.trim())).toEqual([
      '/',
      'jailed-root',
      '/',
      'jailed-root',
      'arg=ok-token',
    ]);

    // Parent shell root is untouched after chroot exits
    expect(await cliOutput(page, `cat ${outsideSentinel}`)).toBe('host-outside');
    const hostCheck = await execCmd(page, ['/usr/bin/stat', '/jail-id.txt']);
    expect(hostCheck.status).not.toBe(0);

    // 2. Missing outside-root binaries & missing #! interpreters inside jail return exit 127 (ENOENT)
    const missingOutsidePath = await execCmd(page, ['/usr/bin/chroot', jail, outsideTool], { sudo: true });
    expect(missingOutsidePath.status).toBe(127);
    expect(missingOutsidePath.stderr).toMatch(/No such file/i);

    const noUsrFallback = await execCmd(page, ['/usr/bin/chroot', emptyJail, '/usr/bin/ls'], { sudo: true });
    expect(noUsrFallback.status).toBe(127);
    expect(noUsrFallback.stderr).toMatch(/No such file/i);

    const noUsrPathSearch = await execCmd(page, ['/usr/bin/chroot', emptyJail, 'ls'], { sudo: true });
    expect(noUsrPathSearch.status).toBe(127);
    expect(noUsrPathSearch.stderr).toMatch(/No such file/i);

    const missingInterpreter = await execCmd(page, ['/usr/bin/chroot', emptyJail, '/dangling-shebang.sh'], { sudo: true });
    expect(missingInterpreter.status).toBe(127);
    expect(missingInterpreter.stderr).toMatch(/No such file/i);

    // 3. Unprivileged chroot returns exit 125 (EPERM)
    const unpriv = await execCmd(page, ['/usr/bin/chroot', jail, '/bin/true'], { sudo: false });
    expect(unpriv.status).toBe(125);
    expect(unpriv.stderr).toMatch(/Operation not permitted/i);

    // 4. Unsupported chroot options (--userspec=..., --skip-chdir) return exit 125 with clear diagnostic
    const badUserspec = await execCmd(page, ['/usr/bin/chroot', '--userspec=0:0', jail, '/bin/true'], { sudo: true });
    expect(badUserspec.status).toBe(125);
    expect(badUserspec.stderr).toContain("unsupported option '--userspec=0:0'");

    const badSkipChdir = await execCmd(page, ['/usr/bin/chroot', '--skip-chdir', jail, '/bin/true'], { sudo: true });
    expect(badSkipChdir.status).toBe(125);
    expect(badSkipChdir.stderr).toContain("unsupported option '--skip-chdir'");
  } finally {
    await execCmd(page, ['/usr/bin/umount', '-l', `${jail}/usr`], { sudo: true }).catch(() => {});
    await context.close();
    await rmrf(rootApi, base);
    await program(rootApi, ['userdel', '-r', username]);
    await program(rootApi, ['groupdel', username]);
  }
});
