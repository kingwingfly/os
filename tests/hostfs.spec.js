import { test, expect } from './storage-test.js';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { accessSync, constants as fsConstants, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { mkdtemp, readdir, readFile, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Real Chromium multi-tab integration tests for Track C (#48 / #49 / #50):
// - OPFS (`os-workspace`) durable profile-wide IndexedDB metadata, 53-bit st_dev/st_ino,
//   ACLs, xattrs, umask/setgid, cross-tab open-unlink, abrupt tab-crash orphan sweep,
//   hard links, symlinks, O_EXCL, RENAME_NOREPLACE, fsync/fdatasync, and multi-tab
//   flock + fcntl byte-range locks (F_SETLK / F_SETLKW / F_GETLK / EDEADLK / tab crash).
// - Chromium Host Directory Handle (via CDP real OS directory drop) `isSameEntry` UUID
//   matching across tabs, zero sidecar files in the user's host folder, (path, fingerprint)
//   outside-edit ESTALE + private-default metadata reset, and EPERM for link/symlink.
// - Store format versioning (§2.12): older format resets metadata once while preserving
//   OPFS file bytes; newer format fails with EPROTONOSUPPORT without mutating the store.

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const sourceModules = [
  'web/release.js',
  'web/kernel/workspace.js',
  'web/kernel/workspaces.js',
  'web/kernel/fs-store.js',
  'web/kernel/mount-sharing.js',
  'web/kernel/local-mounts.js',
  'web/kernel/local-transform.js',
  'web/kernel/transform.js',
  'web/kernel/asyncify.js',
  'web/kernel/memory.js',
  'web/kernel/image.js',
  'web/kernel/loader.js',
  'web/kernel/native-mount.js',
  'web/kernel/private-extension.js',
  'web/wasi/fork.js',
];

function resolveCargoTargetDir() {
  if (process.env.CARGO_TARGET_DIR) return process.env.CARGO_TARGET_DIR;
  try {
    const dir = JSON.parse(
      execFileSync('cargo', ['metadata', '--no-deps', '--format-version=1'], {
        cwd: repoRoot,
        encoding: 'utf8',
      }),
    ).target_directory;
    mkdirSync(dir, { recursive: true });
    accessSync(dir, fsConstants.W_OK);
    return dir;
  } catch {
    return join(tmpdir(), 'os-client-kernel-target');
  }
}

let server;
let origin;
let assets;
let wasmDir;

test.beforeAll(async () => {
  const targetDir = resolveCargoTargetDir();
  wasmDir = mkdtempSync(join(tmpdir(), 'os-hostfs-wasm-'));
  execFileSync(
    'cargo',
    ['build', '--quiet', '--locked', '-p', 'os-client-kernel', '--target', 'wasm32-unknown-unknown', '--target-dir', targetDir],
    {
      cwd: repoRoot,
      stdio: 'inherit',
      env: { ...process.env, CARGO_PROFILE_DEV_DEBUG: process.env.CARGO_PROFILE_DEV_DEBUG ?? '0' },
    },
  );
  execFileSync(
    'wasm-bindgen',
    [
      '--target', 'no-modules',
      '--no-typescript',
      '--out-dir', wasmDir,
      '--out-name', 'client_kernel',
      join(targetDir, 'wasm32-unknown-unknown/debug/os_client_kernel.wasm'),
    ],
    { cwd: repoRoot, stdio: 'inherit' },
  );

  assets = new Map(
    await Promise.all(
      sourceModules.map(async rel => ['/' + rel, await readFile(join(repoRoot, rel))]),
    ),
  );
  assets.set('/client_kernel.js', await readFile(join(wasmDir, 'client_kernel.js')));
  assets.set('/client_kernel_bg.wasm', await readFile(join(wasmDir, 'client_kernel_bg.wasm')));
  assets.set(
    '/',
    Buffer.from(
      '<!doctype html><meta charset="utf-8"><title>HostFs conformance</title><script src="/client_kernel.js"></script>',
    ),
  );

  server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
    const body = assets.get(pathname);
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cache-Control', 'no-store');
    if (!body || req.method !== 'GET') {
      res.writeHead(404).end();
      return;
    }
    const contentType = pathname.endsWith('.js')
      ? 'text/javascript; charset=utf-8'
      : pathname.endsWith('.wasm')
        ? 'application/wasm'
        : 'text/html; charset=utf-8';
    res.setHeader('Content-Type', contentType);
    res.end(body);
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  if (server) await new Promise(done => server.close(done));
  if (wasmDir) {
    try { rmSync(wasmDir, { recursive: true, force: true }); } catch {}
  }
});

async function setupTab(page) {
  await page.goto(origin + '/');
  await page.evaluate(async () => {
    // eslint-disable-next-line no-undef
    await wasm_bindgen('/client_kernel_bg.wasm');
    // eslint-disable-next-line no-undef
    globalThis.wasm_bindgen = wasm_bindgen;
    const { Workspace } = await import('/web/kernel/workspace.js');
    const { exportMount, attachMount } = await import('/web/kernel/mount-sharing.js');
    Object.assign(globalThis, {
      Workspace,
      exportMount,
      attachMount,
      b64: text => btoa(text),
      unb64: data => atob(data),
      aclB64: entries => btoa(JSON.stringify(entries)),
      callOne: async (ws, call, opts = {}) => {
        const [res] = await ws.calls([call], ws.scope, async () => [{ err: { errno: 'ENOENT' } }], opts);
        if (res.err) {
          const err = new Error(res.err.detail || res.err.errno);
          err.errno = res.err.errno;
          throw err;
        }
        return res.ok;
      },
      callErr: async (ws, call, opts = {}) => {
        const [res] = await ws.calls([call], ws.scope, async () => [{ err: { errno: 'ENOENT' } }], opts);
        return res.err ? res.err.errno : null;
      },
    });
  });
}

test('OPFS os-workspace persists 53-bit st_dev/st_ino, modes, POSIX ACLs, xattrs, umask, and setgid across tabs, aliases, and remounts', async ({ page, context }) => {
  const tab1 = page;
  const tab2 = await context.newPage();
  await setupTab(tab1);
  await setupTab(tab2);

  const created = await tab1.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getDirectoryHandle('os-workspace', { create: true });
    globalThis.ws1 = new Workspace({ id: 's1', uid: 1000, gid: 1000, groups: [1000] });
    ws1.scope = ws1.scope();
    await ws1.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: true, cloud: false });
    await ws1.mount({ name: 'alias', handle, originPrivate: true, writable: true, execute: true, cloud: false });

    const sfs = await callOne(ws1, { statfs: { path: '/mnt/local/work' } });
    await callOne(ws1, { mkdir: { path: '/mnt/local/work/sgid', mode: 0o770 } }, { umask: 0o007 });
    await callOne(ws1, { chmod: { path: '/mnt/local/work/sgid', mode: 0o2770 } });
    await callOne(ws1, {
      setxattr: {
        path: '/mnt/local/work/sgid',
        name: 'system.posix_acl_access',
        value: aclB64({ user: 7, group: 7, other: 0, users: { 1002: 7 }, groups: {}, mask: 7 }),
      },
    });
    await callOne(ws1, {
      setxattr: {
        path: '/mnt/local/work/sgid',
        name: 'system.posix_acl_default',
        value: aclB64({ user: 7, group: 7, other: 0, users: { 1002: 6 }, groups: {}, mask: 6 }),
      },
    });
    await callOne(ws1, {
      setxattr: {
        path: '/mnt/local/work/sgid',
        name: 'user.project',
        value: b64('os-browser'),
      },
    });
    const dirWork = await callOne(ws1, { stat: { path: '/mnt/local/work/sgid' } });
    const dirAlias = await callOne(ws1, { stat: { path: '/mnt/local/alias/sgid' } });
    return { fsId: ws1.mounts.get('/mnt/local/work').provider.fsId, sfs, dirWork, dirAlias };
  });

  expect(created.fsId).toMatch(/^opfs:[0-9a-f-]{36}$/);
  expect(created.sfs.bsize).toBe(4096);
  expect(created.sfs.namelen).toBe(255);
  expect(Number.isSafeInteger(created.dirWork.dev)).toBe(true);
  expect(created.dirWork.dev).toBeGreaterThan(0);
  expect(created.dirWork.dev).toBe(created.dirAlias.dev);
  expect(created.dirWork.ino).toBe(created.dirAlias.ino);

  // Before root (0o700) grants traverse, uid 1002 is denied; after chmod 0o711 on root, uid 1002 traverses into sgid/
  const deniedBeforeRootTraverse = await tab2.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getDirectoryHandle('os-workspace', { create: false });
    globalThis.ws2 = new Workspace({ id: 's2', uid: 1002, gid: 1002, groups: [1002] });
    ws2.scope = ws2.scope();
    await ws2.mount({ name: 'peer', handle, originPrivate: true, writable: true, execute: true, cloud: false });
    return await callErr(ws2, { stat: { path: '/mnt/local/peer/sgid' } });
  });
  expect(deniedBeforeRootTraverse).toBe('EACCES');
  await tab1.evaluate(async () => {
    await callOne(ws1, { chmod: { path: '/mnt/local/work', mode: 0o711 } });
  });

  // Tab 2 (uid 1002, gid 1002) now traverses root and creates a child inside sgid/
  const fromTab2 = await tab2.evaluate(async () => {
    const sfs = await callOne(ws2, { statfs: { path: '/mnt/local/peer' } });
    const dir = await callOne(ws2, { stat: { path: '/mnt/local/peer/sgid' } });
    const xattr = unb64(await callOne(ws2, { getxattr: { path: '/mnt/local/peer/sgid', name: 'user.project' } }));

    // Create child file under setgid + default ACL (umask ignored when default ACL present per POSIX)
    const opened = await callOne(
      ws2,
      { open: { path: '/mnt/local/peer/sgid/doc.txt', flags: 0o102, mode: 0o666 } },
      { umask: 0o077 },
    );
    await callOne(ws2, { pwrite: { fd: opened.fd, offset: 0, data: b64('hello from tab2') } });
    await callOne(ws2, { fsync: { fd: opened.fd, data_only: false } });
    await callOne(ws2, { close: { fd: opened.fd } });
    const doc = await callOne(ws2, { stat: { path: '/mnt/local/peer/sgid/doc.txt' } });
    const subDir = await callOne(ws2, { mkdir: { path: '/mnt/local/peer/sgid/nested', mode: 0o777 } });
    const nested = await callOne(ws2, { stat: { path: '/mnt/local/peer/sgid/nested' } });
    return { fsId: ws2.mounts.get('/mnt/local/peer').provider.fsId, sfs, dir, xattr, doc, subDir, nested };
  });

  expect(fromTab2.fsId).toBe(created.fsId);
  expect(fromTab2.dir.dev).toBe(created.dirWork.dev);
  expect(fromTab2.dir.ino).toBe(created.dirWork.ino);
  expect(fromTab2.xattr).toBe('os-browser');
  // setgid inherited parent's gid (1000) instead of caller's gid (1002), and nested dir kept S_ISGID!
  expect(fromTab2.doc.gid).toBe(1000);
  expect(fromTab2.nested.gid).toBe(1000);
  expect(fromTab2.nested.mode & 0o2000).toBe(0o2000);

  // Close both mounts, open a fresh Tab 3, remount, and confirm everything persisted!
  await tab1.evaluate(() => ws1.close());
  await tab2.evaluate(() => ws2.close());
  await tab2.close();

  const tab3 = await context.newPage();
  await setupTab(tab3);
  const remounted = await tab3.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getDirectoryHandle('os-workspace', { create: false });
    const ws3 = new Workspace({ id: 's3', uid: 1000, gid: 1000, groups: [1000] });
    const scope = ws3.scope();
    ws3.scope = scope;
    await ws3.mount({ name: 'again', handle, originPrivate: true, writable: true, execute: true, cloud: false });
    const doc = await callOne(ws3, { stat: { path: '/mnt/local/again/sgid/doc.txt' } });
    const read = unb64((await callOne(ws3, { pread: { path: '/mnt/local/again/sgid/doc.txt', offset: 0, count: 64 } })).data);
    const acl = JSON.parse(unb64(await callOne(ws3, { getxattr: { path: '/mnt/local/again/sgid/doc.txt', name: 'system.posix_acl_access' } })));
    ws3.close();
    return { doc, read, acl };
  });
  await tab3.close();

  expect(remounted.doc.dev).toBe(created.dirWork.dev);
  expect(remounted.doc.ino).toBe(fromTab2.doc.ino);
  expect(remounted.read).toBe('hello from tab2');
  expect(remounted.acl.users['1002']).toBe(6);
});

test('OPFS enforces cross-tab open-unlink (nlink == 0), sweeps crashed-tab orphans via Web Locks, and supports links, O_EXCL, RENAME_NOREPLACE, and fsync', async ({ page, context }) => {
  const tab1 = page;
  const tab2 = await context.newPage();
  await setupTab(tab1);
  await setupTab(tab2);

  // Mount os-workspace in both tabs
  const fsUuid = await tab1.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getDirectoryHandle('os-workspace', { create: true });
    globalThis.ws1 = new Workspace({ id: 't1', uid: 1000, gid: 1000, groups: [1000] });
    ws1.scope = ws1.scope();
    await ws1.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: true, cloud: false });
    return ws1.mounts.get('/mnt/local/work').provider.fsId.slice('opfs:'.length);
  });
  await tab2.evaluate(async () => {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getDirectoryHandle('os-workspace', { create: false });
    globalThis.ws2 = new Workspace({ id: 't2', uid: 1000, gid: 1000, groups: [1000] });
    ws2.scope = ws2.scope();
    await ws2.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: true, cloud: false });
  });

  // 1. Cross-tab open-unlink: Tab 1 opens live.txt, Tab 2 unlinks it while Tab 1 keeps fd open
  const liveOpen = await tab1.evaluate(async () => {
    const opened = await callOne(ws1, { open: { path: '/mnt/local/work/live.txt', flags: 0o1102, mode: 0o600 } });
    await callOne(ws1, { pwrite: { fd: opened.fd, offset: 0, data: b64('alive-before-unlink') } });
    await callOne(ws1, { fsync: { fd: opened.fd, data_only: false } });
    const st = await callOne(ws1, { fstat: { fd: opened.fd } });
    return { fd: opened.fd, ino: st.ino };
  });

  const tab2Unlink = await tab2.evaluate(async () => {
    await callOne(ws2, { unlink: { path: '/mnt/local/work/live.txt' } });
    return await callErr(ws2, { stat: { path: '/mnt/local/work/live.txt' } });
  });
  expect(tab2Unlink).toBe('ENOENT');

  const afterUnlink = await tab1.evaluate(async ({ fd, uuid, ino }) => {
    const fstat = await callOne(ws1, { fstat: { fd } });
    await callOne(ws1, { pwrite: { fd, offset: 19, data: b64('+after') } });
    await callOne(ws1, { fsync: { fd, data_only: true } });
    const data = unb64((await callOne(ws1, { pread: { fd, offset: 0, count: 64 } })).data);
    const root = await navigator.storage.getDirectory();
    const orphanDir = await (await root.getDirectoryHandle('os-orphans')).getDirectoryHandle(uuid);
    const hasOrphanWhileOpen = await orphanDir.getFileHandle(String(ino)).then(() => true, () => false);
    await callOne(ws1, { close: { fd } });
    const hasOrphanAfterClose = await orphanDir.getFileHandle(String(ino)).then(() => true, () => false);
    return { nlink: fstat.nlink, data, hasOrphanWhileOpen, hasOrphanAfterClose };
  }, { fd: liveOpen.fd, uuid: fsUuid, ino: liveOpen.ino });

  expect(afterUnlink).toEqual({
    nlink: 0,
    data: 'alive-before-unlink+after',
    hasOrphanWhileOpen: true,
    hasOrphanAfterClose: false,
  });

  // 2. Hard links, symlinks, O_EXCL, RENAME_NOREPLACE, open-rename, and fsync errors
  const opsResult = await tab1.evaluate(async () => {
    const f = await callOne(ws1, { open: { path: '/mnt/local/work/orig.txt', flags: 0o302, mode: 0o644 } });
    await callOne(ws1, { pwrite: { fd: f.fd, offset: 0, data: b64('hardlink-data') } });
    const exclDup = await callErr(ws1, { open: { path: '/mnt/local/work/orig.txt', flags: 0o302, mode: 0o644 } });
    await callOne(ws1, { link: { from: '/mnt/local/work/orig.txt', to: '/mnt/local/work/hard.txt' } });
    const st2 = await callOne(ws1, { stat: { path: '/mnt/local/work/hard.txt' } });
    await callOne(ws1, { symlink: { target: 'hard.txt', path: '/mnt/local/work/sym.txt' } });
    const target = await callOne(ws1, { readlink: { path: '/mnt/local/work/sym.txt' } });
    const symRead = unb64((await callOne(ws1, { pread: { path: '/mnt/local/work/sym.txt', offset: 0, count: 64 } })).data);
    const noreplaceErr = await callErr(ws1, { rename: { from: '/mnt/local/work/orig.txt', to: '/mnt/local/work/hard.txt', noreplace: true } });
    // Open file survives rename
    await callOne(ws1, { rename: { from: '/mnt/local/work/orig.txt', to: '/mnt/local/work/moved.txt', noreplace: true } });
    const viaOpenFd = unb64((await callOne(ws1, { pread: { fd: f.fd, offset: 0, count: 64 } })).data);
    await callOne(ws1, { close: { fd: f.fd } });
    const badFsync = await callErr(ws1, { fsync: { fd: f.fd, data_only: false } });
    const dirFd = await callOne(ws1, { open: { path: '/mnt/local/work', flags: 0o200000 } });
    const dirFsync = await callErr(ws1, { fsync: { fd: dirFd.fd, data_only: false } });
    await callOne(ws1, { close: { fd: dirFd.fd } });
    const roGrant = Object.freeze({ readOnly: true });
    ws1.mounts.set('/opt/private/roext', {
      path: '/opt/private/roext',
      name: 'roext',
      grant: roGrant,
      provider: { grant: roGrant, async stat() { return { kind: 'file', size: 2, readOnly: true }; }, unmount() {} },
      cloud: false,
      active: true,
    });
    const extFd = await callOne(ws1, { open: { path: '/opt/private/roext/bin', flags: 0 } });
    const nonSyncableFsync = await callErr(ws1, { fsync: { fd: extFd.fd, data_only: false } });
    await callOne(ws1, { close: { fd: extFd.fd } });
    ws1.unmount('/opt/private/roext');
    return { exclDup, nlink: st2.nlink, target, symRead, noreplaceErr, viaOpenFd, badFsync, dirFsync, nonSyncableFsync };
  });
  expect(opsResult).toEqual({
    exclDup: 'EEXIST',
    nlink: 2,
    target: 'hard.txt',
    symRead: 'hardlink-data',
    noreplaceErr: 'EEXIST',
    viaOpenFd: 'hardlink-data',
    badFsync: 'EBADF',
    dirFsync: null,
    nonSyncableFsync: 'EINVAL',
  });

  // 3. Abrupt tab crash sweep: Tab 2 holds an unlinked open file, then crashes without closing!
  const crashIno = await tab2.evaluate(async () => {
    const opened = await callOne(ws2, { open: { path: '/mnt/local/work/crash-orphan.txt', flags: 0o1102, mode: 0o600 } });
    await callOne(ws2, { pwrite: { fd: opened.fd, offset: 0, data: b64('left-by-crashed-tab') } });
    await callOne(ws2, { fsync: { fd: opened.fd, data_only: false } });
    return (await callOne(ws2, { fstat: { fd: opened.fd } })).ino;
  });

  // Tab 1 unlinks crash-orphan.txt while Tab 2 still holds the open fd + Web Lock
  const orphanBeforeCrash = await tab1.evaluate(async ({ uuid, ino }) => {
    await callOne(ws1, { unlink: { path: '/mnt/local/work/crash-orphan.txt' } });
    const root = await navigator.storage.getDirectory();
    const orphanDir = await (await root.getDirectoryHandle('os-orphans')).getDirectoryHandle(uuid);
    const present = await orphanDir.getFileHandle(String(ino)).then(() => true, () => false);
    ws1.close();
    return present;
  }, { uuid: fsUuid, ino: crashIno });
  expect(orphanBeforeCrash).toBe(true);

  // Crash/close Tab 2 abruptly without unload cleanup -> Web Lock releases automatically
  await tab2.close({ runBeforeUnload: false });

  // Mount os-workspace in a new Tab 3 -> startup orphan sweep cleans up /os-orphans/<uuid>/<ino>!
  const tab3 = await context.newPage();
  await setupTab(tab3);
  const orphanAfterSweep = await tab3.evaluate(async ({ uuid, ino }) => {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getDirectoryHandle('os-workspace', { create: false });
    const ws3 = new Workspace({ id: 't3', uid: 1000, gid: 1000, groups: [1000] });
    ws3.scope = ws3.scope();
    await ws3.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: true, cloud: false });
    const orphanDir = await (await root.getDirectoryHandle('os-orphans')).getDirectoryHandle(uuid);
    const present = await orphanDir.getFileHandle(String(ino)).then(() => true, () => false);
    ws3.close();
    return present;
  }, { uuid: fsUuid, ino: crashIno });
  await tab3.close();
  expect(orphanAfterSweep).toBe(false);
});

test('Multi-tab flock and fcntl byte-range locks coordinate via Web Locks with F_SETLKW wakeup, EDEADLK detection, and tab-crash release', async ({ page, context }) => {
  const tab1 = page;
  const tab2 = await context.newPage();
  await setupTab(tab1);
  await setupTab(tab2);

  for (const [tab, id] of [[tab1, 'l1'], [tab2, 'l2']]) {
    await tab.evaluate(async sessionId => {
      const root = await navigator.storage.getDirectory();
      const handle = await root.getDirectoryHandle('os-workspace', { create: true });
      globalThis.ws = new Workspace({ id: sessionId, uid: 1000, gid: 1000, groups: [1000] });
      ws.scope = ws.scope();
      await ws.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: true, cloud: false });
    }, id);
  }

  // Tab 1 opens lockfile.bin and acquires exclusive fcntl byte-range [0, 10)
  const fd1 = await tab1.evaluate(async () => {
    const f = await callOne(ws, { open: { path: '/mnt/local/work/lockfile.bin', flags: 0o1102, mode: 0o600 } });
    await callOne(ws, { try_lock: { fd: f.fd, family: 'posix', kind: 'exclusive', start: 0, end: 10 } });
    return f.fd;
  });

  // Tab 2 checks F_GETLK, F_SETLK conflict -> EAGAIN, non-overlapping [20, 30) -> ok
  const tab2Check = await tab2.evaluate(async () => {
    const f = await callOne(ws, { open: { path: '/mnt/local/work/lockfile.bin', flags: 0o2 } });
    globalThis.fd2 = f.fd;
    const conflict = await callOne(ws, { test_lock: { fd: f.fd, kind: 'exclusive', start: 5, end: 15 } });
    const eagain = await callErr(ws, { try_lock: { fd: f.fd, family: 'posix', kind: 'exclusive', start: 5, end: 15 } });
    await callOne(ws, { try_lock: { fd: f.fd, family: 'posix', kind: 'exclusive', start: 20, end: 30 } });
    return { conflict, eagain };
  });
  expect(tab2Check.eagain).toBe('EAGAIN');
  expect(tab2Check.conflict?.kind).toBe('exclusive');

  // Cross-tab 2-cycle EDEADLK: Tab 1 holds [0, 10), Tab 2 holds [20, 30).
  // Tab 1 blocks in F_SETLKW on [20, 30); Tab 2 then requests F_SETLKW on [0, 10) -> EDEADLK!
  await tab1.evaluate(fd => {
    globalThis.tab1WaitDone = false;
    globalThis.tab1WaitPromise = callOne(ws, { lock: { fd, family: 'posix', kind: 'exclusive', start: 20, end: 30 } })
      .then(() => { globalThis.tab1WaitDone = true; });
  }, fd1);
  await tab1.waitForTimeout(80);
  expect(await tab1.evaluate(() => globalThis.tab1WaitDone)).toBe(false);

  const deadlk = await tab2.evaluate(async () => {
    return await callErr(ws, { lock: { fd: fd2, family: 'posix', kind: 'exclusive', start: 0, end: 10 } });
  });
  expect(deadlk).toBe('EDEADLK');

  // When Tab 2 unlocks [20, 30), Tab 1 wakes up via Web Locks and acquires [20, 30)!
  await tab2.evaluate(async () => {
    await callOne(ws, { unlock: { fd: fd2, family: 'posix', start: 20, end: 30 } });
  });
  await expect.poll(() => tab1.evaluate(() => globalThis.tab1WaitDone)).toBe(true);
  await tab1.evaluate(async fd => {
    await globalThis.tab1WaitPromise;
    await callOne(ws, { close: { fd } });
  }, fd1);

  // Tab crash releases flock automatically: Tab 2 acquires flock(LOCK_EX) and crashes!
  await tab2.evaluate(async () => {
    await callOne(ws, { try_lock: { fd: fd2, family: 'flock', kind: 'exclusive' } });
  });
  const blockedWhileAlive = await tab1.evaluate(async () => {
    const f = await callOne(ws, { open: { path: '/mnt/local/work/lockfile.bin', flags: 0o2 } });
    globalThis.fd1b = f.fd;
    return await callErr(ws, { try_lock: { fd: f.fd, family: 'flock', kind: 'exclusive' } });
  });
  expect(blockedWhileAlive).toBe('EAGAIN');

  await tab2.close({ runBeforeUnload: false });

  // Tab 1 now acquires flock(LOCK_EX) without error because Tab 2's open-handle Web Lock released!
  const acquiredAfterCrash = await tab1.evaluate(async () => {
    const err = await callErr(ws, { try_lock: { fd: fd1b, family: 'flock', kind: 'exclusive' } });
    await callOne(ws, { close: { fd: fd1b } });
    ws.close();
    return err;
  });
  expect(acquiredAfterCrash).toBeNull();
});

test('Chromium host directory handle shares UUID across tabs via isSameEntry, writes zero sidecar files, and resets metadata + returns ESTALE on outside edit', async ({ page, context, browserName }) => {
  test.skip(browserName !== 'chromium', 'Chromium provides host directory handles and CDP drag selection.');
  const hostDir = await mkdtemp(join(tmpdir(), 'os-hostfs-dir-'));
  try {
    const filePath = join(hostDir, 'note.txt');
    await writeFile(filePath, 'initial host text');

    const tab1 = page;
    const tab2 = await context.newPage();
    await setupTab(tab1);
    await setupTab(tab2);

    // Drop the exact same OS folder into both tabs via CDP so each receives a real FileSystemDirectoryHandle
    for (const tab of [tab1, tab2]) {
      await tab.evaluate(() => {
        addEventListener('dragover', event => event.preventDefault());
        addEventListener(
          'drop',
          event => {
            event.preventDefault();
            globalThis.droppedFolder = event.dataTransfer.items[0].getAsFileSystemHandle();
          },
          { once: true },
        );
      });
      const cdp = await context.newCDPSession(tab);
      for (const type of ['dragEnter', 'dragOver', 'drop']) {
        await cdp.send('Input.dispatchDragEvent', {
          type,
          x: 200,
          y: 200,
          data: { items: [], files: [hostDir], dragOperationsMask: 1 },
        });
      }
      await tab.evaluate(async () => {
        FileSystemHandle.prototype.queryPermission = async () => 'granted';
        globalThis.hostHandle = await globalThis.droppedFolder;
      });
    }

    const tab1Info = await tab1.evaluate(async () => {
      globalThis.ws1 = new Workspace({ id: 'h1', uid: 1000, gid: 1000, groups: [1000] });
      ws1.scope = ws1.scope();
      await ws1.mount({ name: 'host', handle: globalThis.hostHandle, originPrivate: false, writable: true, execute: false, cloud: false });
      const sfs = await callOne(ws1, { statfs: { path: '/mnt/local/host' } });
      await callOne(ws1, { chmod: { path: '/mnt/local/host/note.txt', mode: 0o644 } });
      await callOne(ws1, {
        setxattr: {
          path: '/mnt/local/host/note.txt',
          name: 'system.posix_acl_access',
          value: aclB64({ user: 6, group: 4, other: 4, users: { 1002: 4 }, groups: {}, mask: 4 }),
        },
      });
      await callOne(ws1, { setxattr: { path: '/mnt/local/host/note.txt', name: 'user.tag', value: b64('v1') } });
      const st = await callOne(ws1, { stat: { path: '/mnt/local/host/note.txt' } });
      const linkErr = await callErr(ws1, { link: { from: '/mnt/local/host/note.txt', to: '/mnt/local/host/hard.txt' } });
      const symErr = await callErr(ws1, { symlink: { target: 'note.txt', path: '/mnt/local/host/sym.txt' } });
      const opened = await callOne(ws1, { open: { path: '/mnt/local/host/note.txt', flags: 0 } });
      globalThis.openHostFd = opened.fd;
      return { fsId: ws1.mounts.get('/mnt/local/host').provider.fsId, sfs, st, linkErr, symErr };
    });

    expect(tab1Info.fsId).toMatch(/^hostfs:[0-9a-f-]{36}$/);
    expect(tab1Info.sfs.bsize).toBe(4096);
    expect(tab1Info.linkErr).toBe('EPERM');
    expect(tab1Info.symErr).toBe('EPERM');

    // Verify ZERO sidecar files were created in the user's real OS directory!
    expect(await readdir(hostDir)).toEqual(['note.txt']);

    // Tab 2 attaches its own FileSystemDirectoryHandle to the same folder -> matches via isSameEntry!
    const tab2Before = await tab2.evaluate(async () => {
      globalThis.ws2 = new Workspace({ id: 'h2', uid: 1000, gid: 1000, groups: [1000] });
      ws2.scope = ws2.scope();
      await ws2.mount({ name: 'same', handle: globalThis.hostHandle, originPrivate: false, writable: true, execute: false, cloud: false });
      const sfs = await callOne(ws2, { statfs: { path: '/mnt/local/same' } });
      const st = await callOne(ws2, { stat: { path: '/mnt/local/same/note.txt' } });
      const tag = unb64(await callOne(ws2, { getxattr: { path: '/mnt/local/same/note.txt', name: 'user.tag' } }));
      return { fsId: ws2.mounts.get('/mnt/local/same').provider.fsId, sfs, st, tag };
    });

    expect(tab2Before.fsId).toBe(tab1Info.fsId);
    expect(tab2Before.st.dev).toBe(tab1Info.st.dev);
    expect(tab2Before.st.ino).toBe(tab1Info.st.ino);
    expect(tab2Before.st.mode & 0o777).toBe(0o644);
    expect(tab2Before.tag).toBe('v1');

    // Modify note.txt from OUTSIDE the OS (changing size + mtime)
    await writeFile(filePath, 'replaced outside OS by host editor!!');
    const future = new Date(Date.now() + 5000);
    await utimes(filePath, future, future);

    // Tab 1's open fd sees ESTALE; fresh stat resets metadata to private defaults (0o600, no ACL/xattr)!
    const afterOutsideEdit = await tab1.evaluate(async () => {
      const staleRead = await callErr(ws1, { pread: { fd: globalThis.openHostFd, offset: 0, count: 64 } });
      await callOne(ws1, { close: { fd: globalThis.openHostFd } });
      const st = await callOne(ws1, { stat: { path: '/mnt/local/host/note.txt' } });
      const tagErr = await callErr(ws1, { getxattr: { path: '/mnt/local/host/note.txt', name: 'user.tag' } });
      const aclErr = await callErr(ws1, { getxattr: { path: '/mnt/local/host/note.txt', name: 'system.posix_acl_access' } });
      const text = unb64((await callOne(ws1, { pread: { path: '/mnt/local/host/note.txt', offset: 0, count: 128 } })).data);
      ws1.close();
      return { staleRead, mode: st.mode & 0o777, tagErr, aclErr, text };
    });
    await tab2.evaluate(() => ws2.close());
    await tab2.close();

    expect(afterOutsideEdit).toEqual({
      staleRead: 'ESTALE',
      mode: 0o600,
      tagErr: 'ENODATA',
      aclErr: 'ENODATA',
      text: 'replaced outside OS by host editor!!',
    });
    expect(await readdir(hostDir)).toEqual(['note.txt']);
  } finally {
    await rm(hostDir, { recursive: true, force: true });
  }
});

test('Store format versioning (§2.12): older format resets metadata once preserving user bytes; newer format fails with EPROTONOSUPPORT untouched', async ({ page }) => {
  await setupTab(page);

  const result = await page.evaluate(async () => {
    const putFormatVersion = (dbName, version) =>
      new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('meta', 'readwrite');
          tx.objectStore('meta').put(version, 'version');
          tx.oncomplete = () => { db.close(); resolve(); };
          tx.onerror = () => { db.close(); reject(tx.error); };
        };
      });

    const getFormatVersion = dbName =>
      new Promise((resolve, reject) => {
        const req = indexedDB.open(dbName, 1);
        req.onerror = () => reject(req.error);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('meta', 'readonly');
          const getReq = tx.objectStore('meta').get('version');
          getReq.onsuccess = () => { db.close(); resolve(getReq.result); };
          getReq.onerror = () => { db.close(); reject(getReq.error); };
        };
      });

    const root = await navigator.storage.getDirectory();
    const handle = await root.getDirectoryHandle('os-workspace', { create: true });

    // 1. Write user file & custom metadata under current format version (1)
    const ws1 = new Workspace({ id: 'v1', uid: 1000, gid: 1000, groups: [1000] });
    ws1.scope = ws1.scope();
    globalThis.ws = ws1;
    await ws1.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: false, cloud: false });
    const f = await callOne(ws1, { open: { path: '/mnt/local/work/precious.txt', flags: 0o1102, mode: 0o644 } }, { umask: 0 });
    await callOne(ws1, { pwrite: { fd: f.fd, offset: 0, data: b64('precious user bytes') } });
    await callOne(ws1, { fsync: { fd: f.fd, data_only: false } });
    await callOne(ws1, { close: { fd: f.fd } });
    await callOne(ws1, { setxattr: { path: '/mnt/local/work/precious.txt', name: 'user.note', value: b64('old-meta') } });
    ws1.close();

    // 2. Downgrade store format version to 0 -> remount resets metadata once to private defaults, keeps user bytes!
    await putFormatVersion('os-fs-opfs:os-workspace', 0);
    const ws2 = new Workspace({ id: 'v2', uid: 1000, gid: 1000, groups: [1000] });
    ws2.scope = ws2.scope();
    await ws2.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: false, cloud: false });
    const stAfterUpgrade = await callOne(ws2, { stat: { path: '/mnt/local/work/precious.txt' } });
    const xattrAfterUpgrade = await callErr(ws2, { getxattr: { path: '/mnt/local/work/precious.txt', name: 'user.note' } });
    const bytesAfterUpgrade = unb64((await callOne(ws2, { pread: { path: '/mnt/local/work/precious.txt', offset: 0, count: 64 } })).data);
    ws2.close();
    const upgradedVersion = await getFormatVersion('os-fs-opfs:os-workspace');

    // 3. Upgrade store format version to 99 -> mount refuses with EPROTONOSUPPORT and leaves version 99 untouched!
    await putFormatVersion('os-fs-opfs:os-workspace', 99);
    const ws3 = new Workspace({ id: 'v3', uid: 1000, gid: 1000, groups: [1000] });
    ws3.scope = ws3.scope();
    const futureMountErr = await ws3
      .mount({ name: 'work', handle, originPrivate: true, writable: true, execute: false, cloud: false })
      .then(() => null, err => err.errno);
    ws3.close();
    const untouchedFutureVersion = await getFormatVersion('os-fs-opfs:os-workspace');

    return {
      modeAfterUpgrade: stAfterUpgrade.mode & 0o777,
      xattrAfterUpgrade,
      bytesAfterUpgrade,
      upgradedVersion,
      futureMountErr,
      untouchedFutureVersion,
    };
  });

  expect(result).toEqual({
    modeAfterUpgrade: 0o600,
    xattrAfterUpgrade: 'ENODATA',
    bytesAfterUpgrade: 'precious user bytes',
    upgradedVersion: 1,
    futureMountErr: 'EPROTONOSUPPORT',
    untouchedFutureVersion: 99,
  });
});
