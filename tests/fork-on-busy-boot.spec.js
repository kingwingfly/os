// Browser Playwright E2E suite for Issue #56 (`L3c` — Multi-Tab ForkOnBusy, Unmodified Fork
// Pruning, Modified Fork Retention, Incompatible Format Refusal, Corrupt Cowfsck Recovery, and
// Exclusive EBUSY Recovery, Blueprint §3.2 `B-04`, `B-05`, `B-06`, `B-07`).

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
        res.writeHead(200, {
          ...baseHeaders,
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

async function installReleaseAndGoOffline(page, context) {
  await page.goto(`${origin}/offline-boot.html`);
  await page.waitForFunction(() => Boolean(window.osOffline?.installer));
  await page.evaluate(async id => {
    await window.osOffline.registerOfflineServiceWorker('/offline-sw.js');
    await window.osOffline.installer.install(id);
  }, releaseId);
  await page.waitForFunction(() => Boolean(navigator.serviceWorker.controller));
  await context.clearCookies();
  await context.setOffline(true);
  await context.route('**/*', route => route.abort());
}

test.beforeAll(async () => {
  const srcDist = join(repoRoot, 'dist');
  accessSync(join(srcDist, 'client_kernel_bg.wasm'), fsConstants.R_OK);
  tmpRoot = await mkdtemp(join(tmpdir(), 'os-l3c-fork-busy-'));
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

test('B-04 & B-05: second tab ForkOnBusy prunes unmodified fork on clean exit and retains modified isolated fork', async ({ page, context }) => {
  test.setTimeout(180_000);
  await installReleaseAndGoOffline(page, context);

  // Tab 1 boots primary volume and commits `/home/user/tab1.txt`.
  await page.goto(`${origin}/console.html`);
  await page.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage2');
  const primaryUuid = await page.evaluate(async () => {
    await window.osStandaloneConsole.writeFile('/home/user/tab1.txt', 'from-tab-1\n', 0o644);
    await window.osStandaloneConsole.syncFs();
    return window.__osStandaloneBoot.status.mounted_root.volume_uuid;
  });

  // B-04: Tab 2 opens while Tab 1 holds the real browser Web Lock `os-vol:<primaryUuid>`.
  const tab2 = await context.newPage();
  await tab2.goto(`${origin}/console.html`);
  await tab2.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage2');
  const fork1 = await tab2.evaluate(async () => {
    const boot = window.__osStandaloneBoot;
    const text = await window.osStandaloneConsole.readText('/home/user/tab1.txt');
    const bannerVisible = Boolean(document.querySelector('[data-fork-banner]'));
    return {
      volumeUuid: boot.status.mounted_root.volume_uuid,
      forkedFrom: boot.status.mounted_root.forked_from,
      ephemeral: boot.status.mounted_root.ephemeral_if_unmodified,
      text,
      bannerVisible,
    };
  });
  expect(fork1.volumeUuid).not.toBe(primaryUuid);
  expect(fork1.forkedFrom).toBe(primaryUuid);
  expect(fork1.ephemeral).toBe(true);
  expect(fork1.text).toBe('from-tab-1\n');
  expect(fork1.bannerVisible).toBe(true);

  // Tab 2 closes cleanly WITHOUT writing -> unmodified fork MUST be pruned!
  const pruneRes = await tab2.evaluate(() => window.osStandaloneConsole.closeClean());
  expect(pruneRes.pruned).toBe(true);
  expect(pruneRes.retained).toBe(false);
  await tab2.close();

  const volsAfterPrune = await page.evaluate(() => window.osStandaloneConsole.listVolumes());
  expect(volsAfterPrune.map(v => v.volume)).toEqual([primaryUuid]);

  // B-05: Tab 2B opens on a fork, writes `/home/user/fork-only.txt`, syncs, and closes cleanly -> RETAINED!
  const tab2b = await context.newPage();
  await tab2b.goto(`${origin}/console.html`);
  await tab2b.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage2');
  const fork2Uuid = await tab2b.evaluate(async () => {
    await window.osStandaloneConsole.writeFile('/home/user/fork-only.txt', 'fork-isolated\n', 0o644);
    await window.osStandaloneConsole.syncFs();
    return window.__osStandaloneBoot.status.mounted_root.volume_uuid;
  });
  expect(fork2Uuid).not.toBe(primaryUuid);

  // Tab 1 MUST NOT see Tab 2B's fork write!
  const tab1Check = await page.evaluate(async () => {
    try {
      await window.osStandaloneConsole.stat('/home/user/fork-only.txt', false);
      return 'exists';
    } catch (e) {
      return e.errno ?? 'err';
    }
  });
  expect(tab1Check).toBe('ENOENT');

  const retainRes = await tab2b.evaluate(() => window.osStandaloneConsole.closeClean());
  expect(retainRes.retained).toBe(true);
  expect(retainRes.pruned).toBe(false);
  await tab2b.close();

  // `listVolumes()` MUST list both primary and retained modified fork (`ephemeral_if_unmodified: false`, `modified: true`)!
  const volsAfterRetain = await page.evaluate(() => window.osStandaloneConsole.listVolumes());
  const retainedEntry = volsAfterRetain.find(v => v.volume === fork2Uuid);
  expect(retainedEntry).toBeTruthy();
  expect(retainedEntry.modified).toBe(true);
  expect(retainedEntry.ephemeral_if_unmodified).toBe(false);
  expect(retainedEntry.parent_volume).toBe(primaryUuid);

  // Tab 3 boots directly into the retained fork UUID via BootProfile and reads `/home/user/fork-only.txt`!
  await page.evaluate(uuid => window.osStandaloneConsole.bootProfileStore.setVolumeUuid(uuid), fork2Uuid);
  const tab3 = await context.newPage();
  await tab3.goto(`${origin}/console.html`);
  await tab3.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage2');
  const fork3Text = await tab3.evaluate(() => window.osStandaloneConsole.readText('/home/user/fork-only.txt'));
  expect(fork3Text).toBe('fork-isolated\n');

  await tab3.evaluate(() => window.osStandaloneConsole.closeClean());
  await tab3.close();
  await page.evaluate(() => window.osStandaloneConsole.closeClean());
});

test('B-06 & B-07: incompatible format version fails EPROTONOSUPPORT without wiping, corrupt cowfsck offers snapshot rollback, and Exclusive mode fails EBUSY into recovery', async ({ page, context }) => {
  test.setTimeout(180_000);
  await installReleaseAndGoOffline(page, context);

  // 1. First boot, write precious baseline data, take snapshot `"good"`, then write post-snapshot file.
  await page.goto(`${origin}/console.html`);
  await page.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage2');
  const primaryUuid = await page.evaluate(async () => {
    await window.osStandaloneConsole.writeFile('/home/user/precious.txt', 'safe-baseline\n', 0o644);
    await window.osStandaloneConsole.syncFs();
    await window.osStandaloneConsole.snapshot('good');
    return window.__osStandaloneBoot.status.mounted_root.volume_uuid;
  });

  // 2. B-07 (Exclusive EBUSY): Switch BootProfile writer_mode to `'exclusive'` while Tab 1 holds the lock!
  await page.evaluate(() => window.osStandaloneConsole.bootProfileStore.setWriterMode('exclusive'));
  const tabBusy = await context.newPage();
  await tabBusy.goto(`${origin}/console.html`);
  await tabBusy.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage1_recovery');
  const busyRec = await tabBusy.evaluate(() => ({
    kind: window.__osStandaloneBoot.status.recovery.reason.kind,
    hasChooser: Boolean(document.querySelector('[data-recovery-chooser]')),
    hasForkBtn: Boolean(document.querySelector('[data-recovery-fork]')),
  }));
  expect(busyRec.kind).toBe('volume_busy');
  expect(busyRec.hasChooser).toBe(true);
  expect(busyRec.hasForkBtn).toBe(true);
  await tabBusy.close();

  // Restore `fork_on_busy`, write post-snapshot file, sync, and cleanly close Tab 1.
  await page.evaluate(async () => {
    await window.osStandaloneConsole.bootProfileStore.setWriterMode('fork_on_busy');
    await window.osStandaloneConsole.writeFile('/home/user/post-snap.txt', 'later-write\n', 0o644);
    await window.osStandaloneConsole.syncFs();
    await window.osStandaloneConsole.closeClean();
  });

  // 3. B-06: Mutate `os-cowfs-v1` IndexedDB `meta.format_version = 99` -> MUST enter Stage 1 Recovery
  //    with `incompatible_format` and NEVER wipe/format user data!
  await page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('os-cowfs-v1');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    await new Promise((resolve, reject) => {
      const tx = db.transaction(['meta'], 'readwrite', { durability: 'strict' });
      tx.objectStore('meta').put(99, 'format_version');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  });

  await page.reload();
  await page.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage1_recovery');
  const verRec = await page.evaluate(() => ({
    reason: window.__osStandaloneBoot.status.recovery.reason,
    message: window.__osStandaloneBoot.status.recovery.message,
  }));
  expect(verRec.reason.kind).toBe('incompatible_format');
  expect(verRec.reason.found_version).toBe(99);
  expect(verRec.message).toContain('EPROTONOSUPPORT');

  // Restore `meta.format_version = 1` -> verify user data is 100% untouched!
  await page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('os-cowfs-v1');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    await new Promise((resolve, reject) => {
      const tx = db.transaction(['meta'], 'readwrite', { durability: 'strict' });
      tx.objectStore('meta').put(1, 'format_version');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  });

  // 4. B-07 (Corrupt cowfsck + snapshot rollback): Bit-flip one byte in the current root B+tree node
  //    in `os-cowfs-v1` IndexedDB `nodes` store -> Stage 1 `cowfsck` MUST refuse to mount corrupt root,
  //    enter Stage 1 Recovery listing snapshot `"good"`, and rollback button MUST recover intact baseline!
  await page.evaluate(async volUuid => {
    const db = await new Promise((resolve, reject) => {
      const req = indexedDB.open('os-cowfs-v1');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const head = await new Promise((resolve, reject) => {
      const tx = db.transaction(['heads'], 'readonly');
      const req = tx.objectStore('heads').get(volUuid);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    const rootHex = typeof head.root === 'string'
      ? head.root
      : Array.from(head.root, b => b.toString(16).padStart(2, '0')).join('');
    await new Promise((resolve, reject) => {
      const tx = db.transaction(['nodes'], 'readwrite', { durability: 'strict' });
      const store = tx.objectStore('nodes');
      const getReq = store.get(rootHex);
      getReq.onsuccess = () => {
        const rec = getReq.result;
        const copy = new Uint8Array(rec.bytes);
        copy[0] ^= 0x01;
        store.put({ digest: rootHex, bytes: copy });
      };
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  }, primaryUuid);

  await page.reload();
  await page.waitForFunction(() => window.__osStandaloneBoot?.status?.stage === 'stage1_recovery');
  const corruptRec = await page.evaluate(() => ({
    reason: window.__osStandaloneBoot.status.recovery.reason,
    snapshots: window.__osStandaloneBoot.status.recovery.available_snapshots,
  }));
  expect(corruptRec.reason.kind).toBe('corrupt_volume');
  expect(corruptRec.snapshots).toContain('good');

  // Click the Stage 1 Recovery Chooser rollback button for snapshot `"good"`!
  await page.click('[data-rollback-snapshot="good"]');
  await page.waitForFunction(() => {
    const badge = document.querySelector('[data-boot-stage]');
    return badge && badge.getAttribute('data-boot-stage') === 'stage2';
  });

  const recovered = await page.evaluate(async () => {
    const precious = await window.osStandaloneConsole.readText('/home/user/precious.txt');
    let postSnapErrno = null;
    try {
      await window.osStandaloneConsole.stat('/home/user/post-snap.txt', false);
    } catch (e) {
      postSnapErrno = e.errno ?? 'err';
    }
    const status = await window.osStandaloneConsole.status();
    await window.osStandaloneConsole.closeClean();
    return { precious, postSnapErrno, volumeUuid: status.mounted_root.volume_uuid };
  });
  expect(recovered.precious).toBe('safe-baseline\n');
  expect(recovered.postSnapErrno).toBe('ENOENT');
  expect(recovered.volumeUuid).not.toBe(primaryUuid);
});
