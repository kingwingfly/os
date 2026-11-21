import { test, expect, request as playwrightRequest } from './test.js';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import binaryen from 'binaryen';
import { api, call, mkdirp, program, put, rmrf } from './sys.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const userPassword = 'mount-isolation-pass-9482';
const fileUrl = path => '/api/file?path=' + encodeURIComponent(path);

let ipSeq = 0;
const nextIp = label => `mount-iso-${label}-${Date.now()}-${++ipSeq}`;

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

async function execCmd(page, argv, { cwd = '/', sudo = false, stdin = '' } = {}) {
  return page.evaluate(
    async ({ argv, cwd, sudo, stdin }) => {
      let stdout = '';
      let stderr = '';
      const res = await window.os.exec([{ path: argv[0], argv }], {
        cwd,
        sudo,
        stdin,
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
    { argv, cwd, sudo, stdin },
  );
}

function flattenFindmnt(nodes, out = []) {
  for (const node of nodes || []) {
    out.push(node);
    if (Array.isArray(node.children)) flattenFindmnt(node.children, out);
  }
  return out;
}

async function createWheelUser(rootApi, prefix) {
  const username = `${prefix}${Date.now().toString(36)}${(++ipSeq).toString(36)}`;
  expect((await program(rootApi, ['useradd', '-m', '-G', 'wheel', username])).ok()).toBe(true);
  expect((await api(rootApi, 'passwd', { data: { username, password: userPassword } })).ok()).toBe(true);
  return username;
}

async function openUserSession(browser, username, { sudo = false } = {}) {
  const ip = nextIp(username);
  const context = await browser.newContext({
    extraHTTPHeaders: { 'CF-Connecting-IP': ip },
  });
  const headers = { Origin: origin, 'CF-Connecting-IP': ip };
  expect((await api(context.request, 'login', { headers, data: { username, password: userPassword } })).ok()).toBe(true);
  if (sudo) {
    expect((await api(context.request, 'sudo', { headers, data: { password: userPassword } })).ok()).toBe(true);
  }
  const page = await context.newPage();
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.exec && window.os?.localMounts));
  await expect(busy(page)).toHaveAttribute('data-state', 'idle', { timeout: 60_000 });
  return { context, page };
}

function buildUnshareHelperWasm(scriptPath) {
  // Calls os.unshare(CLONE_NEWNS = 0x20000); on failure exits with -ret (e.g. EPERM = 1).
  // On success calls os.execve({"file":"/usr/bin/sh","argv":["sh",scriptPath],"env":[],"search":false}).
  const reqJson = JSON.stringify({
    file: '/usr/bin/sh',
    argv: ['sh', scriptPath],
    env: ['PATH=/usr/bin:/bin'],
    search: false,
  });
  const escaped = Array.from(Buffer.from(reqJson, 'utf8'), b => '\\' + b.toString(16).padStart(2, '0')).join('');
  const reqLen = Buffer.byteLength(reqJson, 'utf8');
  const mod = binaryen.parseText(`(module
    (import "os" "unshare" (func $unshare (param i32) (result i32)))
    (import "os" "execve" (func $execve (param i32 i32) (result i32)))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (memory (export "memory") 1)
    (data (i32.const 64) "${escaped}")
    (func (export "_start")
      (local $rc i32)
      (local.set $rc (call $unshare (i32.const 131072)))
      (if (i32.lt_s (local.get $rc) (i32.const 0))
        (then (call $exit (i32.sub (i32.const 0) (local.get $rc)))))
      (local.set $rc (call $execve (i32.const 64) (i32.const ${reqLen})))
      (call $exit (i32.sub (i32.const 0) (local.get $rc)))))`);
  try {
    return Buffer.from(mod.emitBinary());
  } finally {
    mod.dispose();
  }
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

test('CLI sudo mount -t tmpfs syncs across findmnt, mount, df, Files UI, and Mounts UI, and sudo umount removes it everywhere', async ({ browser }) => {
  test.setTimeout(120_000);
  const alice = await createWheelUser(rootApi, 'mntsync');
  const scratch = `/tmp/scratch-${crypto.randomUUID()}`;
  let session;
  try {
    session = await openUserSession(browser, alice, { sudo: true });
    const { page } = session;

    await runCli(page, `mkdir -p ${scratch}`);
    await runCli(page, `sudo mount -t tmpfs -o size=4194304,mode=1777 tmpfs ${scratch}`);
    await runCli(page, `/usr/bin/sh -c 'printf "hello-tmpfs\\n" > ${scratch}/visible.txt'`);

    // 1. findmnt -J
    const findmntRaw = await cliOutput(page, '/usr/bin/findmnt -J');
    const mounted = flattenFindmnt(JSON.parse(findmntRaw).filesystems);
    const scratchEntry = mounted.find(m => m.target === scratch);
    expect(scratchEntry, findmntRaw).toBeTruthy();
    expect(scratchEntry.fstype).toBe('tmpfs');

    // 2. mount listing
    const mountOut = await cliOutput(page, '/usr/bin/mount');
    expect(mountOut).toContain(`on ${scratch} type tmpfs`);

    // 3. df listing (a 99-col row wraps across terminal columns on .terminal-screen)
    const dfOut = await cliOutput(page, '/usr/bin/df');
    expect(dfOut.replace(/\n/g, '')).toContain(scratch);

    // 4. Files UI
    const filesWin = page.locator('#window-files');
    const location = filesWin.getByLabel('Location', { exact: true });
    await location.fill(scratch);
    await location.press('Enter');
    await expect(filesWin.locator('.filename-text')).toHaveText(['visible.txt']);

    // 5. Mounts UI
    const mountsWin = page.locator('#window-mounts');
    await page.evaluate(() => window.os.localMounts());
    await expect(mountsWin).toBeVisible();
    await expect(mountsWin.locator('[data-mounts]')).toContainText(scratch);

    // Navigate Files away before unmounting so nothing holds scratch open, then unmount via CLI
    await location.fill('/tmp');
    await location.press('Enter');
    await runCli(page, `sudo umount ${scratch}`);

    // Verify removed everywhere
    const afterFindmnt = flattenFindmnt(JSON.parse(await cliOutput(page, '/usr/bin/findmnt -J')).filesystems);
    expect(afterFindmnt.some(m => m.target === scratch)).toBe(false);
    expect(await cliOutput(page, '/usr/bin/mount')).not.toContain(`on ${scratch} `);
    expect((await cliOutput(page, '/usr/bin/df')).replace(/\n/g, '')).not.toContain(scratch);
    await expect(mountsWin.locator('[data-mounts]')).not.toContainText(scratch);

    await location.fill(scratch);
    await location.press('Enter');
    await expect(filesWin.locator('.filename-text')).toHaveCount(0);
  } finally {
    if (session) {
      await execCmd(session.page, ['/usr/bin/umount', '-l', scratch], { sudo: true }).catch(() => {});
      await session.context.close();
    }
    await rmrf(rootApi, scratch);
    await program(rootApi, ['userdel', '-r', alice]);
    await program(rootApi, ['groupdel', alice]);
  }
});

test('child unshare(CLONE_NEWNS) requires privilege and keeps child mounts invisible to parent shell and Files UI', async ({ browser }) => {
  test.setTimeout(120_000);
  const alice = await createWheelUser(rootApi, 'nsiso');
  const work = `/guest/unshare-${crypto.randomUUID()}`;
  const mnt = `${work}/mnt`;
  const script = `${work}/child.sh`;
  const helperBin = `${work}/unshare-exec.wasm`;
  const releaseGate = `${work}/release`;
  await mkdirp(rootApi, mnt, 0o755);

  const scriptText = [
    '#!/bin/sh',
    'set -e',
    `mount -t tmpfs tmpfs "${mnt}"`,
    `printf "isolated\\n" > "${mnt}/secret.txt"`,
    `findmnt -M "${mnt}" -n -o FSTYPE`,
    'echo CHILD_READY',
    `while [ ! -f "${releaseGate}" ]; do sleep 0.1; done`,
    `cat "${mnt}/secret.txt"`,
    '',
  ].join('\n');
  expect((await put(rootApi, fileUrl(script), { data: scriptText })).ok()).toBe(true);
  await call(rootApi, { chmod: { path: script, mode: 0o755 } });
  expect((await put(rootApi, fileUrl(helperBin), { data: buildUnshareHelperWasm(script) })).ok()).toBe(true);
  await call(rootApi, { chmod: { path: helperBin, mode: 0o755 } });

  let session;
  try {
    session = await openUserSession(browser, alice, { sudo: true });
    const { page } = session;

    // Unprivileged unshare(CLONE_NEWNS) must fail with WASI EPERM (63, per crates/posix/src/lib.rs)
    const denied = await execCmd(page, [helperBin], { sudo: false });
    expect(denied.status).toBe(63);

    // Privileged child unshares CLONE_NEWNS, mounts tmpfs, and holds it open while we inspect parent
    await page.evaluate(
      ({ helperBin }) => {
        const state = (window.__unshareRun = { output: '', done: null, result: null });
        state.done = window.os
          .exec([{ path: helperBin, argv: ['unshare-exec'] }], {
            cwd: '/',
            sudo: true,
            stdin: '',
            streamOutput: true,
            onOutput(_fd, text) {
              state.output += text;
            },
          })
          .then(res => {
            state.result = res;
          });
      },
      { helperBin },
    );

    await page.waitForFunction(() => window.__unshareRun?.output.includes('CHILD_READY'), null, { timeout: 60_000 });
    expect(await page.evaluate(() => window.__unshareRun.output)).toContain('tmpfs');

    // While child is still alive with mnt mounted in its cloned namespace:
    // 1. Parent findmnt does NOT see mnt
    const parentMounts = flattenFindmnt(JSON.parse(await cliOutput(page, '/usr/bin/findmnt -J')).filesystems);
    expect(parentMounts.some(m => m.target === mnt)).toBe(false);

    // 2. Files UI in parent session sees an empty underlying directory
    const filesWin = page.locator('#window-files');
    const location = filesWin.getByLabel('Location', { exact: true });
    await location.fill(mnt);
    await location.press('Enter');
    await expect(filesWin.locator('.filename-text')).toHaveCount(0);

    // Release child and confirm it still read its own isolated mount cleanly
    expect((await put(rootApi, fileUrl(releaseGate), { data: 'go\n' })).ok()).toBe(true);
    await expect.poll(() => page.evaluate(() => window.__unshareRun?.result?.status), { timeout: 30_000 }).toBe(0);
    expect(await page.evaluate(() => window.__unshareRun.output)).toContain('isolated');
  } finally {
    if (session) await session.context.close();
    await rmrf(rootApi, work);
    await program(rootApi, ['userdel', '-r', alice]);
    await program(rootApi, ['groupdel', alice]);
  }
});

test('two accounts cannot see or traverse each other user mounts (/mnt/local/*, /opt/private/*), even via sudo uid 0 (EACCES)', async ({ browser }) => {
  test.setTimeout(120_000);
  const alice = await createWheelUser(rootApi, 'aliceiso');
  const bob = await createWheelUser(rootApi, 'bobiso');

  const probeMod = binaryen.parseText('(module (memory (export "memory") 1) (func (export "_start")))');
  const probeBytes = Buffer.from(probeMod.emitBinary());
  probeMod.dispose();
  const probeHash = createHash('sha256').update(probeBytes).digest('hex');
  const dirEntry = path => ({ path, uid: 0, gid: 0, mode: 0o755, node: { type: 'directory' } });
  const extManifest = {
    format: 'os.image',
    version: 2,
    kind: 'sysext',
    name: 'alicepkg',
    revision: '1',
    abi: 1,
    level: 1,
    features: [],
    provenance: {},
    entries: [
      dirEntry('/'),
      dirEntry('/usr'),
      dirEntry('/usr/bin'),
      { path: '/usr/bin/probe', uid: 0, gid: 0, mode: 0o755, node: { type: 'file', sha256: probeHash, size: probeBytes.length, chunk_size: 262144, chunks: [probeHash] } },
    ],
  };

  let aliceSession;
  let bobSession;
  try {
    aliceSession = await openUserSession(browser, alice, { sudo: true });
    bobSession = await openUserSession(browser, bob, { sudo: true });

    // Alice mounts /mnt/local/notes and activates /opt/private/alice-ext
    await aliceSession.page.evaluate(
      async ({ manifest, bytesB64, hash }) => {
        const raw = Uint8Array.from(atob(bytesB64), c => c.charCodeAt(0));
        await window.os.mountLocal({
          name: 'notes',
          cloud: false,
          execute: false,
          files: [new File(['alice-only-note\n'], 'secret.txt')],
        });
        await window.os.mountLocal({
          name: 'pkgsrc',
          cloud: false,
          execute: false,
          files: [new File([JSON.stringify(manifest)], 'manifest.json'), new File([raw], 'blobs/' + hash)],
        });
        await window.os.activatePrivate({ name: 'alice-ext', source: '/mnt/local/pkgsrc', cloud: false });
      },
      { manifest: extManifest, bytesB64: probeBytes.toString('base64'), hash: probeHash },
    );

    // Alice herself can read /mnt/local/notes/secret.txt and execute /opt/private/alice-ext/usr/bin/probe
    const aliceRead = await execCmd(aliceSession.page, ['/usr/bin/cat', '/mnt/local/notes/secret.txt']);
    expect(aliceRead.status).toBe(0);
    expect(aliceRead.stdout.trim()).toBe('alice-only-note');
    const aliceExec = await execCmd(aliceSession.page, ['/opt/private/alice-ext/usr/bin/probe']);
    expect(aliceExec.status).toBe(0);

    // Even inside Alice's own session namespace, sudo (instance uid 0) hits the owner-UID ceiling -> EACCES!
    const sudoReadLocal = await execCmd(aliceSession.page, ['/usr/bin/cat', '/mnt/local/notes/secret.txt'], { sudo: true });
    expect(sudoReadLocal.status).not.toBe(0);
    expect(sudoReadLocal.stderr).toMatch(/Permission denied/i);

    const sudoStatExt = await execCmd(aliceSession.page, ['/usr/bin/stat', '/opt/private/alice-ext/usr/bin/probe'], { sudo: true });
    expect(sudoStatExt.status).not.toBe(0);
    expect(sudoStatExt.stderr).toMatch(/Permission denied/i);

    // Switch the SAME client-kernel tab/instance session from Alice to Bob (without page reload)
    const switchIp = nextIp('switch-bob');
    expect(
      (
        await api(aliceSession.context.request, 'login', {
          headers: { Origin: origin, 'CF-Connecting-IP': switchIp },
          data: { username: bob, password: userPassword },
        })
      ).ok(),
    ).toBe(true);
    expect(
      (
        await api(aliceSession.context.request, 'sudo', {
          headers: { Origin: origin, 'CF-Connecting-IP': switchIp },
          data: { password: userPassword },
        })
      ).ok(),
    ).toBe(true);
    await aliceSession.page.evaluate(() => {
      window.dispatchEvent(new Event('os:login-changed'));
      window.dispatchEvent(new CustomEvent('os:changed'));
    });
    await expect(aliceSession.page.locator('.lock')).toContainText(bob);

    // Check both the switched-account tab on the same instance AND Bob's separate session
    for (const page of [aliceSession.page, bobSession.page]) {
      expect(await page.evaluate(() => window.os.localMountList())).toEqual([]);

      const mounts = flattenFindmnt(JSON.parse(await cliOutput(page, '/usr/bin/findmnt -J')).filesystems);
      expect(mounts.some(m => m.target === '/mnt/local/notes' || m.target === '/opt/private/alice-ext')).toBe(false);

      const bobLocal = await execCmd(page, ['/usr/bin/cat', '/mnt/local/notes/secret.txt']);
      expect(bobLocal.status).not.toBe(0);
      expect(bobLocal.stderr).toMatch(/No such file|Permission denied/i);

      const bobSudoLocal = await execCmd(page, ['/usr/bin/cat', '/mnt/local/notes/secret.txt'], { sudo: true });
      expect(bobSudoLocal.status).not.toBe(0);
      expect(bobSudoLocal.stderr).toMatch(/No such file|Permission denied/i);

      const bobSudoExt = await execCmd(page, ['/usr/bin/ls', '/opt/private/alice-ext'], { sudo: true });
      expect(bobSudoExt.status).not.toBe(0);
      expect(bobSudoExt.stderr).toMatch(/No such file|Permission denied/i);
    }
  } finally {
    await aliceSession?.context.close();
    await bobSession?.context.close();
    for (const user of [alice, bob]) {
      await program(rootApi, ['userdel', '-r', user]);
      await program(rootApi, ['groupdel', user]);
    }
  }
});

test('ordinary umount fails with EBUSY while open descriptors or cwd hold a mount, whereas umount -l detaches immediately and preserves open files', async ({ browser }) => {
  test.setTimeout(120_000);
  const alice = await createWheelUser(rootApi, 'busylazy');
  const base = `/guest/busy-${crypto.randomUUID()}`;
  const mnt = `${base}/mnt`;
  const stopFlag = `${base}/stop`;
  await mkdirp(rootApi, mnt, 0o755);

  let session;
  try {
    session = await openUserSession(browser, alice, { sudo: true });
    const { page } = session;

    await runCli(page, `sudo mount -t tmpfs -o mode=1777 tmpfs ${mnt}`);
    await runCli(page, `/usr/bin/sh -c 'printf "kept-across-lazy-detach\\n" > ${mnt}/held.txt'`);

    // Background shell holds both cwd and open fd 3 on mnt/held.txt
    await page.evaluate(
      ({ mnt, stopFlag }) => {
        const holder = (window.__busyHolder = { output: '', result: null });
        holder.done = window.os
          .exec(
            [
              {
                path: '/usr/bin/sh',
                argv: [
                  'sh',
                  '-c',
                  `cd "${mnt}" && exec 3<held.txt && echo HOLDER_OPEN && while [ ! -f "${stopFlag}" ]; do sleep 0.1; done && cat <&3`,
                ],
              },
            ],
            {
              cwd: '/',
              stdin: '',
              streamOutput: true,
              onOutput(_fd, text) {
                holder.output += text;
              },
            },
          )
          .then(res => {
            holder.result = res;
          });
      },
      { mnt, stopFlag },
    );

    await page.waitForFunction(() => window.__busyHolder?.output.includes('HOLDER_OPEN'), null, { timeout: 60_000 });

    // Ordinary umount must fail with EBUSY
    const busyRes = await execCmd(page, ['/usr/bin/umount', mnt], { sudo: true });
    expect(busyRes.status).not.toBe(0);
    expect(busyRes.stderr).toMatch(/busy/i);

    const stillMounted = flattenFindmnt(JSON.parse(await cliOutput(page, '/usr/bin/findmnt -J')).filesystems);
    expect(stillMounted.some(m => m.target === mnt)).toBe(true);

    // Lazy detach (umount -l) succeeds immediately and removes mount from namespace
    const lazyRes = await execCmd(page, ['/usr/bin/umount', '-l', mnt], { sudo: true });
    expect(lazyRes.status, lazyRes.stderr).toBe(0);

    const afterDetach = flattenFindmnt(JSON.parse(await cliOutput(page, '/usr/bin/findmnt -J')).filesystems);
    expect(afterDetach.some(m => m.target === mnt)).toBe(false);
    const newLookup = await execCmd(page, ['/usr/bin/cat', `${mnt}/held.txt`]);
    expect(newLookup.status).not.toBe(0);

    // Release holder and verify its already-open fd 3 still reads the detached tmpfs file cleanly
    expect((await put(rootApi, fileUrl(stopFlag), { data: 'done\n' })).ok()).toBe(true);
    await expect.poll(() => page.evaluate(() => window.__busyHolder?.result?.status), { timeout: 30_000 }).toBe(0);
    expect(await page.evaluate(() => window.__busyHolder.output)).toContain('kept-across-lazy-detach');
  } finally {
    if (session) {
      await execCmd(session.page, ['/usr/bin/umount', '-l', mnt], { sudo: true }).catch(() => {});
      await session.context.close();
    }
    await rmrf(rootApi, base);
    await program(rootApi, ['userdel', '-r', alice]);
    await program(rootApi, ['groupdel', alice]);
  }
});
