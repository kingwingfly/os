// Browser Playwright E2E suite for Issue #56 (`L3c` — Two-Stage Standalone Offline Boot,
// Blueprint §3.2 `B-01`, `B-02`, `B-03`, `B-08`, `docs/architecture/contract.md` §5).
//
// Proves in a real Chromium browser with real OPFS `FileSystemSyncAccessHandle`, strict IndexedDB,
// Service Worker Cache Storage, and real compiled `client_kernel_bg.wasm`:
// - B-01: After online install of signed Release v2, clearing cookies + `context.setOffline(true)`
//   + aborting every network route yields ZERO outbound HTTP requests when opening & reloading
//   `/console.html`.
// - B-02: First boot provisions a persistent `os-cowfs` volume, persists `volume_uuid` in
//   `os-boot-profile-v1`, atomically seeds `RootTemplate` with exact `/etc/{passwd,group,shadow,sudoers}`
//   modes (`shadow` 0600, `sudoers` 0440 with `%wheel ALL=(ALL:ALL) NOPASSWD: ALL`), persists
//   `/etc/motd` & `/home/user/notes.txt` across offline cold reload, reports `statfs("/") == 0x4f534357`
//   (`OS_COWFS_MAGIC`), mounts `/` = `cowfs`, `/usr` = `image ro,nodev`, `/tmp` = `tmpfs`, and seeds
//   ZERO remote devices in `/dev`.
// - B-03: `switch_root` preserves PID 1 (`pid === 1`, original `started`), drops Stage 1 `tmpfs`
//   completely (zero leaked references, `/initramfs_marker` unreachable), preserves `/run/os/root`
//   and `/run/os/boot-profile.json`, and detaches Stage 1 `/usr`.
// - B-08: Calling `switch_root` as non-PID-1 fails `EPERM`, and calling `switch_root` once `/` is
//   `os-cowfs` (not `tmpfs`) fails `EINVAL`.

import { test, expect } from './test.js';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { accessSync, constants as fsConstants, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.sig': 'application/json; charset=utf-8',
};

let tmpRoot, bundleDir, releaseId, trust, server, origin;
const serverHits = [];

function resolveTargetDir() {
  if (process.env.CARGO_TARGET_DIR) return process.env.CARGO_TARGET_DIR;
  const local = join(repoRoot, 'target');
  if (existsSync(local)) return local;
  return undefined;
}

function runXtask(args) {
  const targetDir = resolveTargetDir();
  const xtaskBin = targetDir ? join(targetDir, 'release', 'xtask') : null;
  if (xtaskBin && existsSync(xtaskBin)) {
    return execFileSync(xtaskBin, args, { cwd: repoRoot, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }).trim();
  }
  const env = { ...process.env, CARGO_NET_OFFLINE: 'true' };
  if (targetDir) env.CARGO_TARGET_DIR = targetDir;
  return execFileSync('cargo', ['run', '--locked', '--offline', '--release', '-p', 'xtask', '--', ...args], {
    cwd: repoRoot,
    env,
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
  }).trim();
}

function startStaticBootServer(distDir, bootDir, defaultId, trustObj) {
  return new Promise((resolveStart, rejectStart) => {
    const srv = http.createServer(async (req, res) => {
      try {
        const url = new URL(req.url, 'http://127.0.0.1');
        serverHits.push(`${req.method} ${url.pathname}`);
        const baseHeaders = {
          'Cross-Origin-Opener-Policy': 'same-origin',
          'Cross-Origin-Embedder-Policy': 'require-corp',
          'Cross-Origin-Resource-Policy': 'same-origin',
        };
        if (url.pathname === '/boot/entries') {
          const body = JSON.stringify({
            format: 'os.boot',
            version: 2,
            default: defaultId,
            protocol: 2,
            schema: 10,
            trust: trustObj,
          });
          res.writeHead(200, {
            ...baseHeaders,
            'Content-Type': 'application/json; charset=utf-8',
            'Cache-Control': 'no-store',
          });
          res.end(body);
          return;
        }
        const relPath = decodeURIComponent(url.pathname === '/' ? '/index.html' : url.pathname);
        if (relPath.includes('..') || relPath.includes('\0')) {
          res.writeHead(400, baseHeaders);
          res.end('bad path');
          return;
        }
        const isBoot = relPath.startsWith('/boot/');
        const rootDir = resolve(isBoot ? bootDir : distDir);
        const subPath = isBoot ? relPath.slice('/boot'.length) : relPath;
        const filePath = resolve(rootDir, '.' + subPath);
        if (!filePath.startsWith(rootDir)) {
          res.writeHead(403, baseHeaders);
          res.end('forbidden');
          return;
        }
        const st = await stat(filePath).catch(() => null);
        if (!st || !st.isFile()) {
          res.writeHead(404, baseHeaders);
          res.end('not found');
          return;
        }
        const data = await readFile(filePath);
        const contentType = MIME[extname(filePath)] ?? 'application/octet-stream';
        const etag = url.pathname.startsWith('/boot/blobs/')
          ? `"${url.pathname.slice('/boot/blobs/'.length)}"`
          : undefined;
        const rangeHeader = req.headers.range;
        if (rangeHeader && rangeHeader.startsWith('bytes=')) {
          const [startStr, endStr] = rangeHeader.slice(6).split('-');
          const start = Number.parseInt(startStr, 10);
          const end = endStr ? Math.min(Number.parseInt(endStr, 10), data.length - 1) : data.length - 1;
          if (!Number.isFinite(start) || start < 0 || start > end || end >= data.length) {
            res.writeHead(416, { ...baseHeaders, 'Content-Range': `bytes */${data.length}` });
            res.end();
            return;
          }
          const slice = data.subarray(start, end + 1);
          res.writeHead(206, {
            ...baseHeaders,
            ...(etag ? { ETag: etag } : {}),
            'Content-Type': contentType,
            'Content-Range': `bytes ${start}-${end}/${data.length}`,
            'Content-Length': String(slice.length),
          });
          res.end(slice);
          return;
        }
        res.writeHead(200, {
          ...baseHeaders,
          ...(etag ? { ETag: etag } : {}),
          'Content-Type': contentType,
          'Content-Length': String(data.length),
        });
        res.end(data);
      } catch (err) {
        res.writeHead(500);
        res.end(String(err));
      }
    });
    srv.on('error', rejectStart);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      resolveStart({ srv, url: `http://127.0.0.1:${addr.port}` });
    });
  });
}

test.beforeAll(async () => {
  const srcDist = join(repoRoot, 'dist');
  accessSync(join(srcDist, 'client_kernel_bg.wasm'), fsConstants.R_OK);
  tmpRoot = await mkdtemp(join(tmpdir(), 'os-l3c-offline-boot-'));
  bundleDir = join(tmpRoot, 'bundle');
  const keyPath = join(tmpRoot, 'TEST-KEY');
  await writeFile(keyPath, Buffer.alloc(32, 71), { mode: 0o600 });

  releaseId = runXtask(['boot', '--assets', srcDist, '--out', bundleDir, '--name', 'standalone']);
  runXtask(['sign', '--bundle', bundleDir, '--key-file', keyPath]);
  const pub = JSON.parse(await readFile(join(bundleDir, 'publisher.json'), 'utf8'));
  trust = { keys: pub.keys, revoked: [] };

  const started = await startStaticBootServer(srcDist, bundleDir, releaseId, trust);
  server = started.srv;
  origin = started.url;
});

test.afterAll(async () => {
  if (server) await new Promise(r => server.close(r));
  if (tmpRoot) await rm(tmpRoot, { recursive: true, force: true });
});

test('B-01..03 & B-08: installed Release v2 boots /console.html offline (0 requests, 0 cookies), seeds RootTemplate, persists across cold reload, and enforces switch_root invariants', async ({ page, context }) => {
  test.setTimeout(180_000);
  const pageErrors = [];
  page.on('pageerror', err => pageErrors.push(err.message));

  // 1. Online install ONCE: register offline Service Worker + install signed Release v2 generation.
  await page.goto(`${origin}/offline-boot.html`);
  await page.waitForFunction(() => Boolean(window.osOffline?.installer));
  const installRes = await page.evaluate(async id => {
    await window.osOffline.registerOfflineServiceWorker('/offline-sw.js');
    const result = await window.osOffline.installer.install(id);
    return {
      releaseId: result.releaseId,
      active: result.state.active,
      pinnedBlobs: result.pinnedBlobs,
      pinnedBootAssets: result.pinnedBootAssets,
    };
  }, releaseId);
  expect(installRes.releaseId).toBe(releaseId);
  expect(installRes.active).toBe(releaseId);
  expect(installRes.pinnedBlobs).toBeGreaterThan(0);

  // Ensure Service Worker actively controls this origin before severing the network.
  await page.waitForFunction(() => Boolean(navigator.serviceWorker.controller));

  // 2. B-01: Clear cookies, go completely offline, abort every outbound network route, AND
  //    literally shut down the local HTTP server so network access is physically impossible!
  await context.clearCookies();
  await context.setOffline(true);
  const outboundRequests = [];
  await context.route('**/*', route => {
    outboundRequests.push(route.request().url());
    return route.abort();
  });
  await new Promise(r => server.close(r));
  server = null;
  serverHits.length = 0;

  // 3. First offline boot of `/console.html` -> Stage 0 -> Stage 1 -> RootTemplate seed -> switch_root -> Stage 2!
  await page.goto(`${origin}/console.html`);
  await page.waitForFunction(() => Boolean(window.__osStandaloneBoot));
  const boot1 = await page.evaluate(() => window.__osStandaloneBoot);

  expect(boot1.error, JSON.stringify(boot1)).toBeUndefined();
  expect(boot1.status.stage).toBe('stage2');
  expect(boot1.releaseId).toBe(releaseId);
  expect(boot1.status.mounted_root.first_boot_seeded).toBe(true);
  expect(boot1.status.mounted_root.base_epoch).toBe(1);
  expect(boot1.bootProfile.root.cow_fs.volume_uuid).toBe(boot1.status.mounted_root.volume_uuid);
  expect(boot1.pagerStats.totalNetworkFetches).toBe(0);
  expect(outboundRequests).toEqual([]);
  expect(serverHits).toEqual([]);

  // 4. B-02: Verify exact RootTemplate account files, statfs magic, `/proc/mounts`, and zero remote `/dev` nodes.
  const inspect1 = await page.evaluate(async () => {
    const c = window.osStandaloneConsole;
    const shadowSt = await c.stat('/etc/shadow', false);
    const sudoersSt = await c.stat('/etc/sudoers', false);
    const sudoersText = await c.readText('/etc/sudoers');
    const homeSt = await c.stat('/home/user', false);
    const sfRoot = await c.statfs('/');
    const mounts = await c.readText('/proc/mounts');
    const mountinfo = await c.readText('/proc/self/mountinfo');
    const devEntries = await c.readdir('/dev');
    const runRoot = JSON.parse(await c.readText('/run/os/root'));
    const runProfile = JSON.parse(await c.readText('/run/os/boot-profile.json'));

    // Write persistent files and commit transaction group.
    await c.writeFile('/etc/motd', 'hello standalone offline\n', 0o644);
    await c.writeFile('/home/user/notes.txt', 'persisted across offline reboot\n', 0o644);
    const syncedHead = await c.syncFs();

    // B-03: Stage 1 marker must be absent, and Stage 1 tmpfs must be dropped.
    let markerErrno = null;
    try {
      await c.stat('/initramfs_marker', false);
    } catch (e) {
      markerErrno = e.errno ?? e.message;
    }

    // B-08: switch_root refusals (non-PID-1 -> EPERM; `/` is cowfs -> EINVAL).
    let nonPid1Errno = null;
    try {
      await c.switchRootAttempt(99, '/sysroot', '/usr/bin/init');
    } catch (e) {
      nonPid1Errno = e.errno ?? e.message;
    }
    let cowfsRootErrno = null;
    try {
      await c.switchRootAttempt(1, '/sysroot', '/usr/bin/init');
    } catch (e) {
      cowfsRootErrno = e.errno ?? e.message;
    }

    // Interactive console built-in command execution.
    const uname = await c.exec('uname');
    const fsck = await c.exec('cowfsck');

    return {
      shadowMode: shadowSt.mode & 0o7777,
      shadowUid: shadowSt.uid,
      shadowGid: shadowSt.gid,
      sudoersMode: sudoersSt.mode & 0o7777,
      sudoersUid: sudoersSt.uid,
      sudoersGid: sudoersSt.gid,
      sudoersText,
      homeMode: homeSt.mode & 0o7777,
      homeUid: homeSt.uid,
      homeGid: homeSt.gid,
      rootMagic: sfRoot.f_type,
      mounts,
      mountinfo,
      devEntries,
      runRoot,
      runProfile,
      syncedEpoch: syncedHead.epoch,
      markerErrno,
      nonPid1Errno,
      cowfsRootErrno,
      uname,
      fsck,
    };
  });

  expect(inspect1.shadowMode).toBe(0o600);
  expect(inspect1.shadowUid).toBe(0);
  expect(inspect1.shadowGid).toBe(0);
  expect(inspect1.sudoersMode).toBe(0o440);
  expect(inspect1.sudoersUid).toBe(0);
  expect(inspect1.sudoersGid).toBe(0);
  expect(inspect1.sudoersText).toContain('%wheel ALL=(ALL:ALL) NOPASSWD: ALL');
  expect(inspect1.homeMode).toBe(0o750);
  expect(inspect1.homeUid).toBe(1000);
  expect(inspect1.homeGid).toBe(1000);
  expect(inspect1.rootMagic).toBe(0x4f534357);
  expect(inspect1.mounts).toContain(' / cowfs ');
  expect(inspect1.mounts).toContain(' /usr image ro,nodev');
  expect(inspect1.mounts).toContain(' /tmp tmpfs ');
  expect(inspect1.mountinfo).not.toContain('initramfs-usr');
  for (const remote of ['archive', 'media', 'present', 'snd']) {
    expect(inspect1.devEntries).not.toContain(remote);
  }
  expect(inspect1.devEntries).toContain('vd0');
  expect(inspect1.devEntries).toContain('null');
  expect(inspect1.runRoot.volume_uuid).toBe(boot1.status.mounted_root.volume_uuid);
  expect(inspect1.runProfile.root.cow_fs.volume_uuid).toBe(boot1.status.mounted_root.volume_uuid);
  expect(inspect1.syncedEpoch).toBeGreaterThan(1);
  expect(inspect1.markerErrno).toBe('ENOENT');
  expect(inspect1.nonPid1Errno).toBe('EPERM');
  expect(inspect1.cowfsRootErrno).toBe('EINVAL');
  expect(inspect1.uname.code).toBe(0);
  expect(inspect1.fsck.code).toBe(0);
  expect(boot1.status.pid1.pid).toBe(1);
  expect(boot1.status.pid1.path).toBe('/usr/bin/init');
  expect(boot1.status.stage1_reclaimed_entries).toBeGreaterThan(0);
  expect(boot1.status.stage1_tmpfs_dropped).toBe(true);

  // Clean shutdown before cold offline reload.
  const closeRes = await page.evaluate(() => window.osStandaloneConsole.closeClean());
  expect(closeRes.retained).toBe(true);
  expect(closeRes.pruned).toBe(false);

  // 5. Cold offline reload -> MUST boot existing volume without re-seeding & preserve edits with ZERO network requests!
  await page.reload();
  await page.waitForFunction(() => Boolean(window.__osStandaloneBoot));
  const boot2 = await page.evaluate(() => window.__osStandaloneBoot);
  expect(boot2.error, JSON.stringify(boot2)).toBeUndefined();
  expect(boot2.status.stage).toBe('stage2');
  expect(boot2.status.mounted_root.volume_uuid).toBe(boot1.status.mounted_root.volume_uuid);
  expect(boot2.status.mounted_root.first_boot_seeded).toBe(false);

  const persisted = await page.evaluate(async () => ({
    motd: await window.osStandaloneConsole.readText('/etc/motd'),
    notes: await window.osStandaloneConsole.readText('/home/user/notes.txt'),
  }));
  expect(persisted.motd).toBe('hello standalone offline\n');
  expect(persisted.notes).toBe('persisted across offline reboot\n');

  await page.evaluate(() => window.osStandaloneConsole.closeClean());
  expect(outboundRequests).toEqual([]);
  expect(serverHits).toEqual([]);
  expect(pageErrors).toEqual([]);
});
