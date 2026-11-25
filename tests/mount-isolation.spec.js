import { test, expect } from './test.js';
import { createHash } from 'node:crypto';
import binaryen from 'binaryen';
import { pageCall, pageMkdirp, pagePut, pageRmrf, switchLocalUser, waitForTerminalReady } from './ui.js';

const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const userPassword = 'mount-isolation-pass-9482';

let userSeq = 0;

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

async function createLocalWheelUser(page, prefix) {
  const username = `${prefix}${Date.now().toString(36)}${(++userSeq).toString(36)}`;
  const add = await execCmd(page, ['/usr/bin/useradd', '-m', '-G', 'wheel', username], { sudo: true });
  expect(add.status, add.stderr).toBe(0);
  await pageCall(page, { passwd: { username, password: userPassword, force: true } }, { sudo: true });
  return username;
}

async function openLocalSession(browser) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(origin + '/');
  await page.waitForFunction(() => Boolean(window.os?.exec && window.os?.localMounts));
  await waitForTerminalReady(page, 60_000);
  return { context, page };
}

async function loginLocalWheelUser(page, username, { sudo = false } = {}) {
  await switchLocalUser(page, username, { password: userPassword, sudo: false });
  if (sudo) {
    await pageCall(page, { sudo: { password: userPassword, revoke: false } });
  }
  await page.evaluate(() => window.dispatchEvent(new CustomEvent('os:changed')));
  await expect(page.locator('.cloud-panel-trigger')).toContainText(`Local: ${username}`);
}

function buildUnshareHelperWasm(scriptPath) {
  // Calls os.unshare(CLONE_NEWNS = 0x20000); on failure exits with -ret (e.g. EPERM = 63).
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

test('CLI sudo mount -t tmpfs syncs across findmnt, mount, df, Files UI, and Mounts UI, and sudo umount removes it everywhere', async ({ browser }) => {
  test.setTimeout(120_000);
  const scratch = `/tmp/scratch-${crypto.randomUUID()}`;
  let session;
  try {
    session = await openLocalSession(browser);
    const { page } = session;
    const alice = await createLocalWheelUser(page, 'mntsync');
    await loginLocalWheelUser(page, alice, { sudo: true });

    expect((await execCmd(page, ['/usr/bin/mkdir', '-p', scratch])).status).toBe(0);
    const mntRes = await execCmd(page, ['/usr/bin/mount', '-t', 'tmpfs', '-o', 'size=4194304,mode=1777', 'tmpfs', scratch], { sudo: true });
    expect(mntRes.status, mntRes.stderr).toBe(0);
    const writeRes = await execCmd(page, ['/usr/bin/sh', '-c', `printf "hello-tmpfs\\n" > ${scratch}/visible.txt`]);
    expect(writeRes.status, writeRes.stderr).toBe(0);

    // 1. findmnt -J
    const findmntRaw = (await execCmd(page, ['/usr/bin/findmnt', '-J'])).stdout.trim();
    const mounted = flattenFindmnt(JSON.parse(findmntRaw).filesystems);
    const scratchEntry = mounted.find(m => m.target === scratch);
    expect(scratchEntry, findmntRaw).toBeTruthy();
    expect(scratchEntry.fstype).toBe('tmpfs');

    // 2. mount listing
    const mountOut = (await execCmd(page, ['/usr/bin/mount'])).stdout.trim();
    expect(mountOut).toContain(`on ${scratch} type tmpfs`);

    // 3. df listing
    const dfOut = (await execCmd(page, ['/usr/bin/df'])).stdout.trim();
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
    const umntRes = await execCmd(page, ['/usr/bin/umount', scratch], { sudo: true });
    expect(umntRes.status, umntRes.stderr).toBe(0);

    // Verify removed everywhere
    const afterFindmnt = flattenFindmnt(JSON.parse((await execCmd(page, ['/usr/bin/findmnt', '-J'])).stdout.trim()).filesystems);
    expect(afterFindmnt.some(m => m.target === scratch)).toBe(false);
    expect((await execCmd(page, ['/usr/bin/mount'])).stdout).not.toContain(`on ${scratch} `);
    expect((await execCmd(page, ['/usr/bin/df'])).stdout.replace(/\n/g, '')).not.toContain(scratch);
    await expect(mountsWin.locator('[data-mounts]')).not.toContainText(scratch);

    await location.fill(scratch);
    await location.press('Enter');
    await expect(filesWin.locator('.filename-text')).toHaveCount(0);
  } finally {
    if (session) {
      await execCmd(session.page, ['/usr/bin/umount', '-l', scratch], { sudo: true }).catch(() => {});
      await pageRmrf(session.page, scratch, { sudo: true }).catch(() => {});
      await session.context.close();
    }
  }
});

test('child unshare(CLONE_NEWNS) requires privilege and keeps child mounts invisible to parent shell and Files UI', async ({ browser }) => {
  test.setTimeout(120_000);
  let session;
  let work;
  try {
    session = await openLocalSession(browser);
    const { page } = session;
    const alice = await createLocalWheelUser(page, 'nsiso');
    await loginLocalWheelUser(page, alice, { sudo: true });

    work = `/home/${alice}/unshare-${crypto.randomUUID()}`;
    const mnt = `${work}/mnt`;
    const script = `${work}/child.sh`;
    const helperBin = `${work}/unshare-exec.wasm`;
    const releaseGate = `${work}/release`;
    await pageMkdirp(page, mnt, 0o755);

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
    await pagePut(page, script, scriptText, { mode: 0o755 });
    await pagePut(page, helperBin, buildUnshareHelperWasm(script), { mode: 0o755 });

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
    const parentMounts = flattenFindmnt(JSON.parse((await execCmd(page, ['/usr/bin/findmnt', '-J'])).stdout.trim()).filesystems);
    expect(parentMounts.some(m => m.target === mnt)).toBe(false);

    // 2. Files UI in parent session sees an empty underlying directory
    const filesWin = page.locator('#window-files');
    const location = filesWin.getByLabel('Location', { exact: true });
    await location.fill(mnt);
    await location.press('Enter');
    await expect(filesWin.locator('.filename-text')).toHaveCount(0);

    // Release child and confirm it still read its own isolated mount cleanly
    await pagePut(page, releaseGate, 'go\n');
    await expect.poll(() => page.evaluate(() => window.__unshareRun?.result?.status), { timeout: 30_000 }).toBe(0);
    expect(await page.evaluate(() => window.__unshareRun.output)).toContain('isolated');
  } finally {
    if (session) {
      if (work) await pageRmrf(session.page, work, { sudo: true }).catch(() => {});
      await session.context.close();
    }
  }
});

test('two accounts cannot see or traverse each other user mounts (/mnt/local/*, /opt/private/*), even via sudo uid 0 (EACCES)', async ({ browser }) => {
  test.setTimeout(120_000);

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
    aliceSession = await openLocalSession(browser);
    bobSession = await openLocalSession(browser);

    const alice = await createLocalWheelUser(aliceSession.page, 'aliceiso');
    const bob = await createLocalWheelUser(aliceSession.page, 'bobiso');
    const bobOther = await createLocalWheelUser(bobSession.page, 'bobiso');
    await loginLocalWheelUser(aliceSession.page, alice, { sudo: true });
    await loginLocalWheelUser(bobSession.page, bobOther, { sudo: true });

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

    for (const flag of ['suid', 'dev']) {
      const remount = await execCmd(aliceSession.page, ['/usr/bin/mount', '-o', 'remount,' + flag, '/mnt/local/notes']);
      expect(remount.status).not.toBe(0);
      expect(remount.stderr).toMatch(/EPERM|permitted/i);
    }

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
    await loginLocalWheelUser(aliceSession.page, bob, { sudo: true });
    await aliceSession.page.evaluate(() => {
      window.dispatchEvent(new CustomEvent('os:changed'));
    });

    // Check both the switched-account tab on the same instance AND Bob's separate session
    for (const page of [aliceSession.page, bobSession.page]) {
      expect(await page.evaluate(() => window.os.localMountList())).toEqual([]);

      const mounts = flattenFindmnt(JSON.parse((await execCmd(page, ['/usr/bin/findmnt', '-J'])).stdout.trim()).filesystems);
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
  }
});

test('ordinary umount fails with EBUSY while open descriptors or cwd hold a mount, whereas umount -l detaches immediately and preserves open files', async ({ browser }) => {
  test.setTimeout(120_000);
  let session;
  let base;
  let mnt;
  try {
    session = await openLocalSession(browser);
    const { page } = session;
    const alice = await createLocalWheelUser(page, 'busylazy');
    await loginLocalWheelUser(page, alice, { sudo: true });

    base = `/tmp/busy-${crypto.randomUUID().slice(0, 8)}`;
    mnt = `${base}/mnt`;
    const stopFlag = `${base}/stop`;
    await pageMkdirp(page, mnt, 0o755);

    const mntRes = await execCmd(page, ['/usr/bin/mount', '-t', 'tmpfs', '-o', 'mode=1777', 'tmpfs', mnt], { sudo: true });
    expect(mntRes.status, mntRes.stderr).toBe(0);
    const heldRes = await execCmd(page, ['/usr/bin/sh', '-c', `printf "kept-across-lazy-detach\\n" > ${mnt}/held.txt`]);
    expect(heldRes.status, heldRes.stderr).toBe(0);

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

    const stillMounted = flattenFindmnt(JSON.parse((await execCmd(page, ['/usr/bin/findmnt', '-J'])).stdout.trim()).filesystems);
    expect(stillMounted.some(m => m.target === mnt)).toBe(true);

    // Lazy detach (umount -l) succeeds immediately and removes mount from namespace
    const lazyRes = await execCmd(page, ['/usr/bin/umount', '-l', mnt], { sudo: true });
    expect(lazyRes.status, lazyRes.stderr).toBe(0);

    const afterDetach = flattenFindmnt(JSON.parse((await execCmd(page, ['/usr/bin/findmnt', '-J'])).stdout.trim()).filesystems);
    expect(afterDetach.some(m => m.target === mnt)).toBe(false);
    const newLookup = await execCmd(page, ['/usr/bin/cat', `${mnt}/held.txt`]);
    expect(newLookup.status).not.toBe(0);

    // Release holder and verify its already-open fd 3 still reads the detached tmpfs file cleanly
    await pagePut(page, stopFlag, 'done\n');
    await expect.poll(() => page.evaluate(() => window.__busyHolder?.result?.status), { timeout: 30_000 }).toBe(0);
    expect(await page.evaluate(() => window.__busyHolder.output)).toContain('kept-across-lazy-detach');
  } finally {
    if (session) {
      if (mnt) await execCmd(session.page, ['/usr/bin/umount', '-l', mnt], { sudo: true }).catch(() => {});
      if (base) await pageRmrf(session.page, base, { sudo: true }).catch(() => {});
      await session.context.close();
    }
  }
});
