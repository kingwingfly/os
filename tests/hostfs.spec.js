import { test, expect } from './storage-test.js';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { accessSync, constants as fsConstants, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, rm, utimes, writeFile } from 'node:fs/promises';
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
  'web/kernel/protocol.js',
  'web/mount-sharing-ui.js',
  'web/mount-transport.js',
  'web/kernel/local-mounts.js',
  'web/kernel/local-transform.js',
  'web/kernel/transform.js',
  'web/kernel/asyncify.js',
  'web/kernel/memory.js',
  'web/kernel/image.js',
  'web/kernel/loader.js',
  'web/kernel/native-mount.js',
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
    const { prepareUserMount, CLIENT_PAGE_FD_BASE } = await import('/web/kernel/workspace.js');
    const OS_FD_ROOT = 0x7ffffffd;
    const decodeB64Bytes = data => {
      const bin = atob(data);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    };
    const encodeB64Bytes = u8 => {
      let text = '';
      for (let i = 0; i < u8.length; i += 0x8000) {
        text += String.fromCharCode(...u8.subarray(i, i + 0x8000));
      }
      return btoa(text);
    };
    const errPayload = err => ({
      errno: err?.errno ?? 'EIO',
      detail: err?.detail ?? err?.message ?? String(err ?? 'EIO'),
    });

    class TestSession {
      constructor({ id, uid, gid = uid, groups = [gid] }) {
        this.id = id;
        this.identity = Object.freeze({ id, uid, gid, groups: Object.freeze([...groups]) });
        this.kernel = new wasm_bindgen.Kernel(`inst-${crypto.randomUUID()}`, `k-${crypto.randomUUID()}`);
        this.alive = true;
        this.cleanups = new Map();
        this.mounts = new Map();
        this._nextPid = 200;
        this.page = 200;
        this._spawnedPids = new Set([200]);
        this._ready = (async () => {
          await this.kernel.session_begin(id, uid, gid, new Uint32Array(groups));
          await this.kernel.proc_spawn_init(JSON.stringify({
            pid: 200,
            ppid: 1,
            sessionId: id,
            uid,
            gid,
            groups,
            umask: 0o022,
            cwd: '/',
          }));
        })();
      }
      check() {
        if (!this.alive) throw Object.assign(new Error('workspace is closed'), { errno: 'ENODEV' });
      }
      scope() {
        return ++this._nextPid;
      }
      async _ensureScope(pid = this.page) {
        await this._ready;
        const p = typeof pid === 'number' ? pid : this.page;
        if (!this._spawnedPids.has(p)) {
          this._spawnedPids.add(p);
          await this.kernel.proc_spawn_init(JSON.stringify({
            pid: p,
            ppid: 1,
            sessionId: this.id,
            uid: this.identity.uid,
            gid: this.identity.gid,
            groups: [...this.identity.groups],
            umask: 0o022,
            cwd: '/',
          }));
        }
        return p;
      }
      async mount(args) {
        await this._ready;
        this.check();
        const prepared = await prepareUserMount(args, this.identity);
        let summary;
        try {
          this.check();
          summary = await this.kernel.mount_user(this.id, JSON.stringify(prepared.spec), prepared.hostObj);
        } catch (err) {
          try { prepared.cleanup?.(); } catch {}
          throw err;
        }
        if (prepared.cleanup) this.cleanups.set(summary.path, prepared.cleanup);
        const fsId = summary.fsId;
        const rec = { ...summary, fsId, provider: { fsId }, active: true };
        this.mounts.set(summary.path, rec);
        return rec;
      }
      async unmount(path, flags = 2) {
        await this._ready;
        await this.kernel.unmount_user(this.id, path, flags);
        this.mounts.delete(path);
        const cleanup = this.cleanups.get(path);
        if (cleanup) {
          this.cleanups.delete(path);
          try { cleanup(); } catch {}
        }
      }
      close() {
        if (!this.alive) return;
        this.alive = false;
        for (const fn of this.cleanups.values()) {
          try { fn?.(); } catch {}
        }
        this.cleanups.clear();
        this.mounts.clear();
        void this._ready.then(async () => {
          for (const pid of this._spawnedPids) {
            await this.kernel.proc_exit(pid).catch(() => {});
          }
          await this.kernel.session_end(this.id).catch(() => {});
        });
      }
      async calls(calls, scope = this.page, _cloudFn = null, opts = {}) {
        await this._ready;
        this.check();
        const pid = await this._ensureScope(scope);
        const results = [];
        for (const c of calls) {
          const [key, val] = Object.entries(c)[0];
          try {
            if (key === 'open') {
              const prevUmask = opts.umask !== undefined ? this.kernel.proc_set_umask(pid, opts.umask) : null;
              try {
                const opened = await this.kernel.proc_openat(pid, OS_FD_ROOT, val.path, val.flags ?? 0, val.mode ?? 0o666, false);
                results.push({ ok: { fd: opened.kfd, ...(opened.stat ?? {}) } });
              } finally {
                if (prevUmask !== null) this.kernel.proc_set_umask(pid, prevUmask);
              }
            } else if (key === 'close') {
              await this.kernel.kfd_close(pid, val.fd);
              results.push({ ok: null });
            } else if (key === 'pread') {
              if (typeof val.fd === 'number') {
                const bytes = val.fd >= CLIENT_PAGE_FD_BASE
                  ? decodeB64Bytes(JSON.parse(await this.kernel.vfs_sys(this.id, JSON.stringify({ calls: [c], sudo: !!opts.sudo, umask: opts.umask }))).results[0].ok.data)
                  : await this.kernel.kfd_pread(pid, val.fd, val.count ?? 4096, BigInt(val.offset ?? 0));
                results.push({ ok: { data: encodeB64Bytes(bytes) } });
              } else {
                const opened = await this.kernel.proc_openat(pid, OS_FD_ROOT, val.path, 0, 0, false);
                try {
                  const bytes = await this.kernel.kfd_pread(pid, opened.kfd, val.count ?? 4096, BigInt(val.offset ?? 0));
                  results.push({ ok: { data: encodeB64Bytes(bytes) } });
                } finally {
                  await this.kernel.kfd_close(pid, opened.kfd).catch(() => {});
                }
              }
            } else if (key === 'pwrite') {
              const bytes = decodeB64Bytes(val.data);
              const written = val.fd >= CLIENT_PAGE_FD_BASE
                ? await this.kernel.vfs_pwrite_chunk(this.id, val.fd, BigInt(val.offset ?? 0), bytes)
                : await this.kernel.kfd_pwrite(pid, val.fd, bytes, BigInt(val.offset ?? 0));
              results.push({ ok: typeof written === 'number' ? { written } : written });
            } else if (key === 'fstat') {
              const st = val.fd >= CLIENT_PAGE_FD_BASE
                ? await this.kernel.vfs_fstat_fd(this.id, val.fd)
                : await this.kernel.kfd_fstat(pid, val.fd);
              results.push({ ok: st });
            } else if (key === 'fsync') {
              if (val.fd >= CLIENT_PAGE_FD_BASE) {
                await this.kernel.vfs_fsync_fd(this.id, val.fd, !!val.data_only);
              } else {
                await this.kernel.kfd_fsync(pid, val.fd, !!val.data_only);
              }
              results.push({ ok: null });
            } else if (key === 'ftruncate') {
              if (val.fd >= CLIENT_PAGE_FD_BASE) {
                await this.kernel.vfs_ftruncate_fd(this.id, val.fd, BigInt(val.size ?? 0));
              } else {
                await this.kernel.kfd_ftruncate(pid, val.fd, BigInt(val.size ?? 0));
              }
              results.push({ ok: null });
            } else if (key === 'try_lock') {
              await this.kernel.kfd_lock(pid, val.fd, val.family, val.kind, BigInt(val.start ?? 0), val.end != null ? BigInt(val.end) : undefined, false);
              results.push({ ok: null });
            } else if (key === 'lock') {
              await this.kernel.kfd_lock(pid, val.fd, val.family, val.kind, BigInt(val.start ?? 0), val.end != null ? BigInt(val.end) : undefined, true);
              results.push({ ok: null });
            } else if (key === 'unlock') {
              await this.kernel.kfd_unlock(pid, val.fd, val.family, BigInt(val.start ?? 0), val.end != null ? BigInt(val.end) : undefined);
              results.push({ ok: null });
            } else if (key === 'test_lock') {
              const res = await this.kernel.kfd_test_lock(pid, val.fd, val.kind, BigInt(val.start ?? 0), val.end != null ? BigInt(val.end) : undefined);
              results.push({ ok: res });
            } else {
              const raw = await this.kernel.vfs_sys(
                this.id,
                JSON.stringify({ calls: [c], sudo: !!opts.sudo, umask: opts.umask }),
              );
              results.push(JSON.parse(raw).results[0]);
            }
          } catch (err) {
            results.push({ err: errPayload(err) });
          }
        }
        return results;
      }
    }

    Object.assign(globalThis, {
      Workspace: TestSession,
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

test('exportd serves a mounted browser directory over the same-host ShareFs transport', async ({ page }) => {
  await page.goto('/');
  await page.waitForFunction(() => window.os?.mountLocal);
  const result = await page.evaluate(async () => {
    const local = await window.os.mountLocal({ name: 'hostfs-export', storage: true, writable: true, cloud: false });
    const writer = await window.os.exec([{ argv: ['dash', '-c', 'printf "%s" "hostfs over ipc" > "$1/published.txt"', 'sh', local.path] }], { stdin: '' });
    if (writer.status !== 0) throw new Error('Failed to create the published file');
    const grant = await window.os.shareMount({ name: 'hostfs-export', path: local.path, ipcOnly: true, writable: false });
    try {
      const share = await window.os.attachShared({ address: grant.address, name: 'hostfs-peer', transport: 'ipc', writable: false });
      try {
        const result = await window.os.exec([{ argv: ['cat', share.path + '/published.txt'] }], { stdin: '' });
        return [result.status, result.stdout];
      } finally { await window.os.unmountLocal(share.path); }
    } finally { await window.os.revokeMount(grant.id); await window.os.unmountLocal(local.path); }
  });
  expect(result).toEqual([0, 'hostfs over ipc']);
});

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
    const devNullFd = await callOne(ws1, { open: { path: '/dev/null', flags: 0 } });
    const nonSyncableFsync = await callErr(ws1, { fsync: { fd: devNullFd.fd, data_only: false } });
    await callOne(ws1, { close: { fd: devNullFd.fd } });
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

  // Tab 1 now acquires flock(LOCK_EX) without error because Tab 2's open-handle Web Lock released
  // (wait briefly for browser renderer teardown to release Web Locks across tabs).
  let acquiredAfterCrash = 'EAGAIN';
  await expect.poll(async () => {
    acquiredAfterCrash = await tab1.evaluate(async () => {
      return await callErr(ws, { try_lock: { fd: fd1b, family: 'flock', kind: 'exclusive' } });
    });
    return acquiredAfterCrash;
  }, { timeout: 5000 }).toBeNull();
  await tab1.evaluate(async () => {
    await callOne(ws, { close: { fd: fd1b } });
    ws.close();
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

    // 1. Write user file & custom metadata under current format version (3)
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
    upgradedVersion: 3,
    futureMountErr: 'EPROTONOSUPPORT',
    untouchedFutureVersion: 99,
  });
});

test('OPFS and directory mounts refuse overlapping subpaths/ancestors, and cross-tab unlock wakes blocked lock waiters without closing fd', async ({ page, context }) => {
  const hostParent = await mkdtemp(join(tmpdir(), 'os-hostfs-overlap-'));
  await mkdir(join(hostParent, 'nested'), { recursive: true });
  await writeFile(join(hostParent, 'nested', 'data.txt'), 'secret');
  const hostParent2 = await mkdtemp(join(tmpdir(), 'os-hostfs-desc-'));
  await mkdir(join(hostParent2, 'inner'), { recursive: true });
  await writeFile(join(hostParent2, 'inner', 'secret.txt'), 'parent-owned');

  const tab1 = page;
  const tab2 = await context.newPage();
  await setupTab(tab1);
  await setupTab(tab2);

  try {
    // 1. OPFS rejects root, `os-orphans`, and nested `os-workspace/*` subdirs; permits `os-workspace`.
    const opfsChecks = await tab1.evaluate(async () => {
      const opfsRoot = await navigator.storage.getDirectory();
      const wsDir = await opfsRoot.getDirectoryHandle('os-workspace', { create: true });
      const nestedDir = await wsDir.getDirectoryHandle('sub', { create: true });
      const orphanDir = await opfsRoot.getDirectoryHandle('os-orphans', { create: true });

      const ws = new Workspace({ id: 'opfs-ov', uid: 1000, gid: 1000, groups: [1000] });
      ws.scope = ws.scope();

      const tryMount = async (name, handle) => ws
        .mount({ name, handle, originPrivate: true, writable: true, execute: false, cloud: false })
        .then(() => null, err => err.errno);

      const rootErr = await tryMount('badroot', opfsRoot);
      const orphanErr = await tryMount('badorph', orphanDir);
      const subErr = await tryMount('badsub', nestedDir);
      const okErr = await tryMount('work', wsDir);

      // Keep a locked file ready for cross-tab unlock wakeup test below.
      const opened = await callOne(ws, { open: { path: '/mnt/local/work/wake.txt', flags: 0o1102, mode: 0o600 } });
      await callOne(ws, { try_lock: { fd: opened.fd, family: 'flock', kind: 'exclusive' } });
      globalThis.wakeWs = ws;
      globalThis.wakeFd = opened.fd;
      return { rootErr, orphanErr, subErr, okErr };
    });
    expect(opfsChecks).toEqual({
      rootErr: 'EACCES',
      orphanErr: 'EACCES',
      subErr: 'EACCES',
      okErr: null,
    });

    // 2. Cross-tab `unlock` while keeping fd open immediately wakes a blocked waiter in tab 2!
    await tab2.evaluate(async () => {
      const root = await navigator.storage.getDirectory();
      const wsDir = await root.getDirectoryHandle('os-workspace', { create: false });
      const ws2 = new Workspace({ id: 'opfs-w2', uid: 1000, gid: 1000, groups: [1000] });
      ws2.scope = ws2.scope();
      await ws2.mount({ name: 'peer', handle: wsDir, originPrivate: true, writable: true, execute: false, cloud: false });
      const opened = await callOne(ws2, { open: { path: '/mnt/local/peer/wake.txt', flags: 2 } });
      globalThis.peerWs = ws2;
      globalThis.peerFd = opened.fd;
      globalThis.peerBlockingLock = callOne(ws2, { lock: { fd: opened.fd, family: 'flock', kind: 'exclusive' } }).then(() => 'unlocked-woke');
    });

    // Give tab 2 a tick to enqueue in IndexedDB and enter wait_for_change.
    await tab1.waitForTimeout(150);

    // Tab 1 unlocks WITHOUT closing `wakeFd`!
    await tab1.evaluate(async () => {
      await callOne(globalThis.wakeWs, { unlock: { fd: globalThis.wakeFd, family: 'flock' } });
    });
    const wokeResult = await tab2.evaluate(() => globalThis.peerBlockingLock);
    expect(wokeResult).toBe('unlocked-woke');

    await tab1.evaluate(async () => {
      await callOne(globalThis.wakeWs, { close: { fd: globalThis.wakeFd } });
      globalThis.wakeWs.close();
    });
    await tab2.evaluate(async () => {
      await callOne(globalThis.peerWs, { unlock: { fd: globalThis.peerFd, family: 'flock' } });
      await callOne(globalThis.peerWs, { close: { fd: globalThis.peerFd } });
      globalThis.peerWs.close();
    });

    // 3. Directory handles reject descendant/ancestor overlaps against already-registered handles.
    const cdp = await context.newCDPSession(tab1);
    await tab1.evaluate(() => {
      globalThis.droppedFolder = new Promise(resolve => {
        window.addEventListener('drop', async e => {
          e.preventDefault();
          const item = e.dataTransfer?.items?.[0];
          resolve(await item.getAsFileSystemHandle());
        }, { once: true });
        window.addEventListener('dragover', e => e.preventDefault());
      });
      FileSystemHandle.prototype.queryPermission = async () => 'granted';
    });
    for (const type of ['dragEnter', 'dragOver', 'drop']) {
      await cdp.send('Input.dispatchDragEvent', {
        type,
        x: 200,
        y: 200,
        data: { items: [], files: [hostParent], dragOperationsMask: 1 },
      });
    }
    const dirOverlap = await tab1.evaluate(async () => {
      const parentHandle = await globalThis.droppedFolder;
      const subHandle = await parentHandle.getDirectoryHandle('nested', { create: false });
      const ws = new Workspace({ id: 'dir-ov', uid: 1000, gid: 1000, groups: [1000] });
      ws.scope = ws.scope();

      // Mount `nested` first, then ensure mounting ancestor `parentHandle` fails with EACCES while exact `subHandle` succeeds!
      await ws.mount({ name: 'child', handle: subHandle, originPrivate: false, writable: true, execute: false, cloud: false });
      const ancestorErr = await ws
        .mount({ name: 'anc', handle: parentHandle, originPrivate: false, writable: true, execute: false, cloud: false })
        .then(() => null, err => err.errno);
      await ws.mount({ name: 'same', handle: subHandle, originPrivate: false, writable: true, execute: false, cloud: false });
      ws.close();
      return { ancestorErr };
    });
    expect(dirOverlap).toEqual({ ancestorErr: 'EACCES' });

    // Reverse overlap direction: mount parent first, then verify descendant subdirectory is refused!
    await tab1.evaluate(() => {
      globalThis.droppedFolder2 = new Promise(resolve => {
        window.addEventListener('drop', async e => {
          e.preventDefault();
          const item = e.dataTransfer?.items?.[0];
          resolve(await item.getAsFileSystemHandle());
        }, { once: true });
        window.addEventListener('dragover', e => e.preventDefault());
      });
    });
    for (const type of ['dragEnter', 'dragOver', 'drop']) {
      await cdp.send('Input.dispatchDragEvent', {
        type,
        x: 200,
        y: 200,
        data: { items: [], files: [hostParent2], dragOperationsMask: 1 },
      });
    }
    const descOverlap = await tab1.evaluate(async () => {
      const parentHandle = await globalThis.droppedFolder2;
      const subHandle = await parentHandle.getDirectoryHandle('inner', { create: false });
      const ws = new Workspace({ id: 'dir-desc', uid: 1000, gid: 1000, groups: [1000] });
      ws.scope = ws.scope();

      await ws.mount({ name: 'rootdir', handle: parentHandle, originPrivate: false, writable: true, execute: false, cloud: false });
      const descErr = await ws
        .mount({ name: 'childdir', handle: subHandle, originPrivate: false, writable: true, execute: false, cloud: false })
        .then(() => null, err => err.errno);
      ws.close();
      return { descErr };
    });
    expect(descOverlap).toEqual({ descErr: 'EACCES' });
  } finally {
    await tab2.close();
    await rm(hostParent, { recursive: true, force: true });
    await rm(hostParent2, { recursive: true, force: true });
  }
});

test('pre-existing overlapping dir handles fail closed on remount and failed createFile cleans stray OPFS entries', async ({ page }) => {
  await setupTab(page);

  const hostParent = await mkdtemp(join(tmpdir(), 'os-hostfs-legacy-ov-'));
  await mkdir(join(hostParent, 'nested'), { recursive: true });
  try {
    // 1. Codex #6: Pre-existing overlapping handles in `os-fs-handles` IDB (parent + child)
    // must still be refused with EACCES when remounting child via exact `isSameEntry` match.
    const cdp = await page.context().newCDPSession(page);
    await page.evaluate(() => {
      globalThis.droppedLegacy = new Promise(resolve => {
        window.addEventListener('drop', async e => {
          e.preventDefault();
          resolve(await e.dataTransfer?.items?.[0].getAsFileSystemHandle());
        }, { once: true });
        window.addEventListener('dragover', e => e.preventDefault());
      });
      FileSystemHandle.prototype.queryPermission = async () => 'granted';
    });
    for (const type of ['dragEnter', 'dragOver', 'drop']) {
      await cdp.send('Input.dispatchDragEvent', {
        type,
        x: 200,
        y: 200,
        data: { items: [], files: [hostParent], dragOperationsMask: 1 },
      });
    }

    const legacyOverlapErr = await page.evaluate(async () => {
      const parentHandle = await globalThis.droppedLegacy;
      const subHandle = await parentHandle.getDirectoryHandle('nested', { create: false });
      const ws1 = new Workspace({ id: 'ov-seed', uid: 1000, gid: 1000, groups: [1000] });
      ws1.scope = ws1.scope();
      await ws1.mount({ name: 'p', handle: parentHandle, originPrivate: false, writable: true, execute: false, cloud: false });
      ws1.close();

      await new Promise((resolve, reject) => {
        const req = indexedDB.open('os-fs-handles', 1);
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('handles', 'readwrite');
          tx.objectStore('handles').put({
            uuid: '11111111-2222-4333-8444-555555555555',
            handle: subHandle,
            createdAt: Date.now(),
          });
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
          tx.onerror = () => reject(tx.error);
        };
        req.onerror = () => reject(req.error);
      });

      const ws2 = new Workspace({ id: 'ov-remount', uid: 1000, gid: 1000, groups: [1000] });
      ws2.scope = ws2.scope();
      const errno = await ws2
        .mount({ name: 'c', handle: subHandle, originPrivate: false, writable: true, execute: false, cloud: false })
        .then(() => null, err => err.errno);
      ws2.close();
      return errno;
    });
    expect(legacyOverlapErr).toBe('EACCES');

    // 2. Codex #8: `createFile(..., createNew: true)` removes stray OPFS host entry when
    // `createWritable` / `stream.close` fails with quota error so O_EXCL retry succeeds.
    const createCleanupResult = await page.evaluate(async () => {
      const root = await navigator.storage.getDirectory();
      const handle = await root.getDirectoryHandle('os-workspace', { create: true });
      const ws = new Workspace({ id: 'opfs-c8', uid: 1000, gid: 1000, groups: [1000] });
      ws.scope = ws.scope();
      await ws.mount({ name: 'work', handle, originPrivate: true, writable: true, execute: true, cloud: false });

      const origCreateWritable = FileSystemFileHandle.prototype.createWritable;
      let armed = true;
      FileSystemFileHandle.prototype.createWritable = async function (...args) {
        if (armed && this.name === 'quota-stray.txt') {
          armed = false;
          throw new DOMException('Quota exceeded', 'QuotaExceededError');
        }
        return origCreateWritable.apply(this, args);
      };
      let firstErr = null;
      try {
        firstErr = await callErr(ws, { open: { path: '/mnt/local/work/quota-stray.txt', flags: 0o302, mode: 0o600 } });
      } finally {
        FileSystemFileHandle.prototype.createWritable = origCreateWritable;
      }

      const presentOnHost = await handle.getFileHandle('quota-stray.txt').then(() => true, () => false);
      const retry = await callOne(ws, { open: { path: '/mnt/local/work/quota-stray.txt', flags: 0o302, mode: 0o600 } });
      await callOne(ws, { pwrite: { fd: retry.fd, offset: 0, data: b64('clean-retry') } });
      await callOne(ws, { close: { fd: retry.fd } });
      const readBack = unb64((await callOne(ws, { pread: { path: '/mnt/local/work/quota-stray.txt', offset: 0, count: 32 } })).data);
      ws.close();
      return { firstErr, presentOnHost, readBack };
    });
    expect(createCleanupResult).toEqual({
      firstErr: 'EDQUOT',
      presentOnHost: false,
      readBack: 'clean-retry',
    });
  } finally {
    await rm(hostParent, { recursive: true, force: true });
  }
});
