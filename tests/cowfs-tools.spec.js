// Browser Playwright E2E suite for Issue #79 (`L2.5c` — Storage Tools, Merkle Delta Stream v1,
// and `/dev/loopN` Read-Only `.cowpack` Archive Mounting; Blueprint §4.1 `C-01..C-09`).
//
// Boots a real standalone offline Release v2 `/console.html` session in Chromium (real OPFS,
// strict IndexedDB, Web Locks, compiled `client_kernel_bg.wasm`, and compiled WASI `/usr/bin/*`
// applets: `mkfs.cowfs`, `cowfs`, `losetup`, `cowfsck`, `mount`, `umount`) and exercises the full
// CLI lifecycle end-to-end with ZERO external network requests.

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
    return execFileSync(xtaskBin, args, {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    }).trim();
  }
  const env = { ...process.env, CARGO_NET_OFFLINE: 'true' };
  if (targetDir) env.CARGO_TARGET_DIR = targetDir;
  return execFileSync(
    'cargo',
    ['run', '--locked', '--offline', '--release', '-p', 'xtask', '--', ...args],
    {
      cwd: repoRoot,
      env,
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
    },
  ).trim();
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
  tmpRoot = await mkdtemp(join(tmpdir(), 'os-l25c-cowfs-tools-'));
  bundleDir = join(tmpRoot, 'bundle');
  const keyPath = join(tmpRoot, 'TEST-KEY');
  await writeFile(keyPath, Buffer.alloc(32, 79), { mode: 0o600 });

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

test('C-01..C-09: mkfs.cowfs, cowfs subvol/snapshot/send/receive, losetup, /dev/loop0 .cowpack RO mount, and cowfsck --archive E2E', async ({
  page,
  context,
}) => {
  test.setTimeout(240_000);
  const pageErrors = [];
  page.on('pageerror', err => pageErrors.push(err.message));

  // 1. Install signed Release v2 into Cache Storage + OPFS, then go 100% offline.
  await page.goto(`${origin}/offline-boot.html`);
  await page.waitForFunction(() => Boolean(window.osOffline?.installer));
  await page.evaluate(async id => {
    await window.osOffline.registerOfflineServiceWorker('/offline-sw.js');
    await window.osOffline.installer.install(id);
  }, releaseId);
  await page.waitForFunction(() => Boolean(navigator.serviceWorker.controller));

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

  // 2. Boot standalone offline `/console.html` to Stage 2.
  await page.goto(`${origin}/console.html`);
  await page.waitForFunction(() => Boolean(window.__osStandaloneBoot));
  const boot = await page.evaluate(() => window.__osStandaloneBoot);
  expect(boot.error, JSON.stringify(boot)).toBeUndefined();
  expect(boot.status.stage).toBe('stage2');

  // 3. Exercise C-02..C-09 via real compiled WASI applets in `osStandaloneConsole.exec`.
  const results = await page.evaluate(async () => {
    const c = window.osStandaloneConsole;
    const log = [];
    const run = async cmd => {
      const r = await c.exec(cmd);
      const entry = { cmd, code: r.code, output: r.output ?? '' };
      log.push(entry);
      return entry;
    };
    const must = async (label, fn) => {
      try {
        return await fn();
      } catch (err) {
        throw new Error(
          `${label}: ${err?.errno ?? err?.message ?? String(err)}\nlog=${JSON.stringify(log)}`,
        );
      }
    };

    const devEntries = await must('readdir /dev', () => c.readdir('/dev'));

    // C-02: mkfs.cowfs permissions, non-block refusal, mounted refusal, format, EEXIST, -f reformat.
    const mkNonRoot = await run('mkfs.cowfs /dev/vd1');
    const mkDir = await run('sudo mkfs.cowfs /tmp');
    const mkMounted = await run('sudo mkfs.cowfs /dev/vd0');
    const mkOk = await run('sudo mkfs.cowfs --label data-vol --json /dev/vd1');
    const mkExist = await run('sudo mkfs.cowfs /dev/vd1');
    const mkForce = await run('sudo mkfs.cowfs -f --label data-v2 --json /dev/vd1');

    // C-03: mount /dev/vd1, create/list/delete subvols, refuse @, mount subvol=sub1 concurrently!
    const mntPrep = await run('sudo mkdir -p /mnt/data /mnt/subdata /mnt/replica /mnt/pkg');
    const mntVd1 = await run('sudo mount -t cowfs /dev/vd1 /mnt/data');
    const svCreate = await run('sudo cowfs subvol create /mnt/data sub1');
    const svList = await run('cowfs subvol list --json /mnt/data');
    const svDelRoot = await run('sudo cowfs subvol delete /mnt/data @');
    const mntSub1 = await run('sudo mount -t cowfs -o subvol=sub1 /dev/vd1 /mnt/subdata');
    const subWrite = await run('sudo sh -c "echo in-root > /mnt/data/root.txt && echo in-sub1 > /mnt/subdata/sub.txt"');
    const subCheck = await run('cat /mnt/data/root.txt && cat /mnt/subdata/sub.txt && test ! -e /mnt/data/sub.txt');
    const umntSub1 = await run('sudo umount /mnt/subdata');
    const svDelSub1 = await run('sudo cowfs subvol delete /mnt/data sub1');

    // Populate multi-file dataset (including > 70 KiB multi-block payload) & snapshots A, B (C-04).
    const bigPayload = new Uint8Array(72 * 1024);
    for (let i = 0; i < bigPayload.length; i++) bigPayload[i] = ((i * 13) ^ (i >> 5) ^ (i >> 16)) & 0xff;
    await must('write /tmp/big.bin', () => c.writeFile('/tmp/big.bin', bigPayload, 0o644));
    const cpBig = await run('sudo cp /tmp/big.bin /mnt/data/big.bin');
    const seedA = await run(
      "sudo sh -c 'for i in 01 02 03 04 05 06 07 08 09 10 11 12; do echo payload-$i > /mnt/data/f$i.txt; done'",
    );
    const snapA = await run('sudo cowfs snapshot create --json /mnt/data snapA');
    const snapList = await run('cowfs snapshot list --json /mnt/data');
    const fsckSnapA = await run('cowfsck --snapshot snapA --json /mnt/data');

    // Modify one small file -> snapshot B.
    const modB = await run('sudo sh -c "echo updated-in-B > /mnt/data/f05.txt"');
    const snapB = await run('sudo cowfs snapshot create --json /mnt/data snapB');

    // C-05 & C-06: Pipe full send|receive AND redirected incremental send/receive + negative tests!
    const pipeFull = await run(
      'sudo cowfs send /mnt/data snapA | sudo cowfs receive --volume vol-replica --snapshot snapA --json /dev/vd1',
    );
    const sendFullB = await run('sudo cowfs send /mnt/data snapB > /tmp/full-b.stream');
    const sendIncAB = await run('sudo cowfs send --parent snapA /mnt/data snapB > /tmp/inc-ab.stream');
    const fullBStat = await must('stat full-b.stream', () => c.stat('/tmp/full-b.stream', false));
    const incABStat = await must('stat inc-ab.stream', () => c.stat('/tmp/inc-ab.stream', false));

    // Missing parent -> ENOENT!
    const recvMissingParent = await run(
      'sudo cowfs receive --volume vol-no-parent /dev/vd1 < /tmp/inc-ab.stream',
    );

    // Bit-flip corruption -> EIO & zero mutation!
    const origStream = await must('readFile full-b.stream', () => c.readFile('/tmp/full-b.stream'));
    const badStream = new Uint8Array(origStream);
    badStream[Math.floor(badStream.length / 2)] ^= 0x01;
    await must('writeFile corrupt.stream', () => c.writeFile('/tmp/corrupt.stream', badStream, 0o644));
    const recvCorrupt = await run(
      'sudo cowfs receive --volume vol-corrupt /dev/vd1 < /tmp/corrupt.stream',
    );
    const fsckCorruptVol = await run('sudo cowfsck volume:vol-corrupt');

    // Valid incremental receive into `vol-replica` -> mount & verify byte-for-byte!
    const recvIncOk = await run(
      'sudo cowfs receive --volume vol-replica --snapshot snapB --json /dev/vd1 < /tmp/inc-ab.stream',
    );
    const mntReplica = await run('sudo mount -t cowfs -o ro volume:vol-replica /mnt/replica');
    const replicaCopy = await run('cp /mnt/replica/f05.txt /tmp/replica-f05.txt && cp /mnt/replica/big.bin /tmp/replica-big.bin');
    const replicaText = await must('readText replica-f05.txt', () => c.readText('/tmp/replica-f05.txt'));
    const replicaBig = await must('readFile replica-big.bin', () => c.readFile('/tmp/replica-big.bin'));
    let replicaBigMatch = replicaBig.length === bigPayload.length;
    if (replicaBigMatch) {
      for (let i = 0; i < bigPayload.length; i++) {
        if (replicaBig[i] !== bigPayload[i]) {
          replicaBigMatch = false;
          break;
        }
      }
    }
    const umntReplica = await run('sudo umount /mnt/replica');

    // C-07, C-08, C-09: Export `.cowpack` archive, losetup lifecycle, zero-copy RO mount, cowfsck --archive!
    const sendArchive = await run(
      'sudo cowfs send --archive -o /tmp/release.cowpack /mnt/data snapB',
    );
    const fsckArchiveOk = await run('cowfsck --archive --json /tmp/release.cowpack');

    const loNonRoot = await run('losetup -f');
    const loAttach = await run('sudo losetup -f --show /tmp/release.cowpack');
    const loList = await run('sudo losetup -a -J');
    const mkLoop = await run('sudo mkfs.cowfs /dev/loop0');
    const mntExt4 = await run('sudo mount -t ext4 -o ro /dev/loop0 /mnt/pkg');
    const mntLoopRw = await run('sudo mount -t cowfs /dev/loop0 /mnt/pkg');
    const mntLoopRo = await run('sudo mount -t cowfs -o ro /dev/loop0 /mnt/pkg');
    const pkgCopy = await run('cp /mnt/pkg/f05.txt /tmp/pkg-f05.txt && cp /mnt/pkg/big.bin /tmp/pkg-big.bin');
    const pkgF05 = await must('readText pkg-f05.txt', () => c.readText('/tmp/pkg-f05.txt'));
    const pkgBig = await must('readFile pkg-big.bin', () => c.readFile('/tmp/pkg-big.bin'));
    let pkgBigMatch = pkgBig.length === bigPayload.length;
    if (pkgBigMatch) {
      for (let i = 0; i < bigPayload.length; i++) {
        if (pkgBig[i] !== bigPayload[i]) {
          pkgBigMatch = false;
          break;
        }
      }
    }
    const pkgWriteFail = await run('sudo sh -c "echo nope > /mnt/pkg/forbidden.txt"');
    const loDetachBusy = await run('sudo losetup -d /dev/loop0');
    const fsckLoop = await run('sudo cowfsck --json /dev/loop0');
    const umntPkg = await run('sudo umount /mnt/pkg');
    const loDetachOk = await run('sudo losetup -d /dev/loop0');
    const umntData = await run('sudo umount /mnt/data');

    // C-09: Flip a byte in `.cowpack` archive -> `cowfsck --archive` MUST exit 4!
    const archBytes = await must('readFile release.cowpack', () => c.readFile('/tmp/release.cowpack'));
    const badArch = new Uint8Array(archBytes);
    badArch[32] ^= 0x01;
    await must('writeFile corrupt.cowpack', () => c.writeFile('/tmp/corrupt.cowpack', badArch, 0o644));
    const fsckArchiveBad = await run('cowfsck --archive /tmp/corrupt.cowpack');

    return {
      devEntries,
      mkNonRoot,
      mkDir,
      mkMounted,
      mkOk,
      mkExist,
      mkForce,
      mntPrep,
      mntVd1,
      svCreate,
      svList,
      svDelRoot,
      mntSub1,
      subWrite,
      subCheck,
      umntSub1,
      svDelSub1,
      cpBig,
      seedA,
      snapA,
      snapList,
      fsckSnapA,
      modB,
      snapB,
      pipeFull,
      sendFullB,
      sendIncAB,
      fullBSize: fullBStat.size,
      incABSize: incABStat.size,
      recvMissingParent,
      recvCorrupt,
      fsckCorruptVol,
      recvIncOk,
      mntReplica,
      replicaCopy,
      replicaText,
      replicaBigMatch,
      umntReplica,
      sendArchive,
      fsckArchiveOk,
      loNonRoot,
      loAttach,
      loList,
      mkLoop,
      mntExt4,
      mntLoopRw,
      mntLoopRo,
      pkgCopy,
      pkgF05,
      pkgBigMatch,
      pkgWriteFail,
      loDetachBusy,
      fsckLoop,
      umntPkg,
      loDetachOk,
      umntData,
      fsckArchiveBad,
    };
  });

  // Verify `/dev` nodes exist locally (`vd0`, `vd1`, `loop-control`, `loop0`).
  expect(results.devEntries).toContain('vd0');
  expect(results.devEntries).toContain('vd1');
  expect(results.devEntries).toContain('loop-control');
  expect(results.devEntries).toContain('loop0');

  // C-02 assertions.
  expect(results.mkNonRoot.code).not.toBe(0);
  expect(results.mkNonRoot.output).toContain('EPERM');
  expect(results.mkDir.code).not.toBe(0);
  expect(results.mkDir.output).toContain('ENOTBLK');
  expect(results.mkMounted.code).not.toBe(0);
  expect(results.mkMounted.output).toContain('EBUSY');
  expect(results.mkOk.code, JSON.stringify(results.mkOk)).toBe(0);
  expect(JSON.parse(results.mkOk.output).incarnation).toBe(1);
  expect(results.mkExist.code).not.toBe(0);
  expect(results.mkExist.output).toContain('EEXIST');
  expect(results.mkForce.code, JSON.stringify(results.mkForce)).toBe(0);
  expect(JSON.parse(results.mkForce.output).incarnation).toBe(2);

  // C-03 assertions.
  expect(results.mntPrep.code).toBe(0);
  expect(results.mntVd1.code, JSON.stringify(results.mntVd1)).toBe(0);
  expect(results.svCreate.code, JSON.stringify(results.svCreate)).toBe(0);
  const subvols = JSON.parse(results.svList.output).subvols.map(s => s.name);
  expect(subvols).toContain('@');
  expect(subvols).toContain('sub1');
  expect(results.svDelRoot.code).not.toBe(0);
  expect(results.svDelRoot.output).toContain('EBUSY');
  expect(results.mntSub1.code, JSON.stringify(results.mntSub1)).toBe(0);
  expect(results.subWrite.code, JSON.stringify(results.subWrite)).toBe(0);
  expect(results.subCheck.code, JSON.stringify(results.subCheck)).toBe(0);
  expect(results.umntSub1.code).toBe(0);
  expect(results.svDelSub1.code, JSON.stringify(results.svDelSub1)).toBe(0);

  // C-04 assertions.
  expect(results.cpBig.code, JSON.stringify(results.cpBig)).toBe(0);
  expect(results.seedA.code).toBe(0);
  expect(results.snapA.code, JSON.stringify(results.snapA)).toBe(0);
  expect(JSON.parse(results.snapList.output).snapshots.map(s => s.name)).toContain('snapA');
  expect(results.fsckSnapA.code, JSON.stringify(results.fsckSnapA)).toBe(0);
  expect(JSON.parse(results.fsckSnapA.output).ok).toBe(true);
  expect(results.modB.code).toBe(0);
  expect(results.snapB.code).toBe(0);

  // C-05 & C-06 assertions.
  expect(results.pipeFull.code, JSON.stringify(results.pipeFull)).toBe(0);
  expect(JSON.parse(results.pipeFull.output).blocks_received).toBeGreaterThanOrEqual(2);
  expect(results.sendFullB.code, JSON.stringify(results.sendFullB)).toBe(0);
  expect(results.sendIncAB.code, JSON.stringify(results.sendIncAB)).toBe(0);
  expect(results.incABSize).toBeLessThan(results.fullBSize);
  expect(results.recvMissingParent.code).not.toBe(0);
  expect(results.recvMissingParent.output).toContain('ENOENT');
  expect(results.recvCorrupt.code).not.toBe(0);
  expect(results.recvCorrupt.output).toContain('EIO');
  expect(results.fsckCorruptVol.code).toBe(8);
  expect(results.recvIncOk.code, JSON.stringify(results.recvIncOk)).toBe(0);
  expect(JSON.parse(results.recvIncOk.output).blocks_received).toBe(0);
  expect(results.mntReplica.code, JSON.stringify(results.mntReplica)).toBe(0);
  expect(results.replicaCopy.code, JSON.stringify(results.replicaCopy)).toBe(0);
  expect(results.replicaText).toBe('updated-in-B\n');
  expect(results.replicaBigMatch).toBe(true);
  expect(results.umntReplica.code).toBe(0);

  // C-07, C-08, C-09 assertions.
  expect(results.sendArchive.code, JSON.stringify(results.sendArchive)).toBe(0);
  expect(results.fsckArchiveOk.code, JSON.stringify(results.fsckArchiveOk)).toBe(0);
  expect(JSON.parse(results.fsckArchiveOk.output).ok).toBe(true);
  expect(results.loNonRoot.code).not.toBe(0);
  expect(results.loNonRoot.output).toContain('EPERM');
  expect(results.loAttach.code, JSON.stringify(results.loAttach)).toBe(0);
  expect(results.loAttach.output.trim()).toBe('/dev/loop0');
  const loJson = JSON.parse(results.loList.output);
  expect(loJson.loopdevices.length).toBe(1);
  expect(loJson.loopdevices[0].archive_format).toBe('cowpack-v1');
  expect(loJson.loopdevices[0].read_only).toBe(true);
  expect(results.mkLoop.code).not.toBe(0);
  expect(results.mntExt4.code).not.toBe(0);
  expect(results.mntLoopRw.code).not.toBe(0);
  expect(results.mntLoopRo.code, JSON.stringify(results.mntLoopRo)).toBe(0);
  expect(results.pkgCopy.code, JSON.stringify(results.pkgCopy)).toBe(0);
  expect(results.pkgF05).toBe('updated-in-B\n');
  expect(results.pkgBigMatch).toBe(true);
  expect(results.pkgWriteFail.code).not.toBe(0);
  expect(results.loDetachBusy.code).not.toBe(0);
  expect(results.loDetachBusy.output).toContain('EBUSY');
  expect(results.fsckLoop.code, JSON.stringify(results.fsckLoop)).toBe(0);
  expect(JSON.parse(results.fsckLoop.output).ok).toBe(true);
  expect(results.umntPkg.code).toBe(0);
  expect(results.loDetachOk.code, JSON.stringify(results.loDetachOk)).toBe(0);
  expect(results.umntData.code).toBe(0);
  expect(results.fsckArchiveBad.code, JSON.stringify(results.fsckArchiveBad)).toBe(4);

  await page.evaluate(() => window.osStandaloneConsole.closeClean());
  expect(outboundRequests).toEqual([]);
  expect(serverHits).toEqual([]);
  expect(pageErrors).toEqual([]);
});
