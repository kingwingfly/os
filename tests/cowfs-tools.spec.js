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
import binaryen from 'binaryen';

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

    // C-03 + Fixes #2/#3: mount /dev/vd1, create/list/delete subvols, refuse @, refuse deleting
    // mounted sub1 (EBUSY), unmount @ BEFORE -o subvol=sub1 keeping sub1 live, then clean delete!
    const mntPrep = await run('sudo mkdir -p /mnt/data /mnt/subdata /mnt/replica /mnt/pkg /mnt/fork1');
    const mntVd1 = await run('sudo mount -t cowfs /dev/vd1 /mnt/data');
    const svCreate = await run('sudo cowfs subvol create /mnt/data sub1');
    const svList = await run('cowfs subvol list --json /mnt/data');
    const svDelRoot = await run('sudo cowfs subvol delete /mnt/data @');
    const mntSub1 = await run('sudo mount -t cowfs -o subvol=sub1 /dev/vd1 /mnt/subdata');
    const subWrite = await run('sudo sh -c "echo in-root > /mnt/data/root.txt && echo in-sub1 > /mnt/subdata/sub.txt"');
    const subCheck = await run('cat /mnt/data/root.txt && cat /mnt/subdata/sub.txt && test ! -e /mnt/data/sub.txt');
    // Fix #3: deleting sub1 while mounted at /mnt/subdata MUST fail EBUSY!
    const svDelSub1Busy = await run('sudo cowfs subvol delete /mnt/data sub1');
    // Fix #2: unmounting /mnt/data (@) FIRST MUST keep shared CowFs & /mnt/subdata live!
    const umntDataFirst = await run('sudo umount /mnt/data');
    const subStillAlive = await run(
      'sudo sh -c "echo alive-after-root-umount > /mnt/subdata/alive.txt" && cat /mnt/subdata/sub.txt && cat /mnt/subdata/alive.txt',
    );
    const umntSub1 = await run('sudo umount /mnt/subdata');
    const remntVd1 = await run('sudo mount -t cowfs /dev/vd1 /mnt/data');
    const svDelSub1 = await run('sudo cowfs subvol delete /mnt/data sub1');

    // Fix #1: unattached `volume:<id>` MUST fail closed with ENODEV (never touch `/dev/vd0`)!
    const unattachedInfo = await run('cowfs info volume:nonexistent-vol');
    const unattachedSnapDel = await run('sudo cowfs snapshot delete volume:nonexistent-vol snapA');
    const unattachedSend = await run('sudo cowfs send volume:nonexistent-vol snapA');

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

    // Complete C-04: `cowfs fork` (+ `--ephemeral`) & post-fork write isolation!
    const forkMain = await run('sudo cowfs fork --snapshot snapA --json /mnt/data vol-fork1');
    const forkEph = await run('sudo cowfs fork --ephemeral --snapshot snapA --json /mnt/data vol-fork-eph');
    const mntFork1 = await run('sudo mount -t cowfs volume:vol-fork1 /mnt/fork1');
    const forkWrite = await run('sudo sh -c "echo only-in-fork > /mnt/fork1/fork-only.txt"');
    const forkIsolated = await run('cat /mnt/fork1/fork-only.txt && test ! -e /mnt/data/fork-only.txt');
    const umntFork1 = await run('sudo umount /mnt/fork1');

    // Modify one small file -> snapshot B.
    const modB = await run('sudo sh -c "echo updated-in-B > /mnt/data/f05.txt"');
    const snapB = await run('sudo cowfs snapshot create --json /mnt/data snapB');

    // C-05 & C-06: Pipe full send|receive, `-v` verbose send, `--name` receive alias, & negative tests!
    const pipeFull = await run(
      'sudo cowfs send /mnt/data snapA | sudo cowfs receive --volume vol-replica --snapshot snapA --json /dev/vd1',
    );
    const sendFullB = await run('sudo cowfs send -v /mnt/data snapB > /tmp/full-b.stream');
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

    // Valid incremental receive into `vol-replica` using `--name` alias -> mount RO & verify!
    const recvIncOk = await run(
      'sudo cowfs receive --volume vol-replica --name snapB --json /dev/vd1 < /tmp/inc-ab.stream',
    );
    const mntReplica = await run('sudo mount -t cowfs -o ro volume:vol-replica /mnt/replica');
    // Fix #4: `mkfs.cowfs --force` on a mounted read-only volume MUST fail EBUSY!
    const mkForceRoVol = await run('sudo mkfs.cowfs --force volume:vol-replica');
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

    // Complete C-04: `cowfs snapshot delete` & `cowfs gc`!
    const snapDelA = await run('sudo cowfs snapshot delete --json /mnt/data snapA');
    const snapListAfterDel = await run('cowfs snapshot list --json /mnt/data');
    const gcRun = await run('sudo cowfs gc --grace 0 --json /mnt/data');
    const umntData = await run('sudo umount /mnt/data');

    // Fix #4: mount `/dev/vd1` `-o ro` -> `mkfs.cowfs --force /dev/vd1` MUST fail EBUSY, then succeed after umount!
    const mntVd1Ro = await run('sudo mount -t cowfs -o ro /dev/vd1 /mnt/data');
    const mkForceRoDev = await run('sudo mkfs.cowfs --force /dev/vd1');
    const umntVd1Ro = await run('sudo umount /mnt/data');
    const mkForceAfterRoUmnt = await run('sudo mkfs.cowfs --force --json /dev/vd1');

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
      svDelSub1Busy,
      umntDataFirst,
      subStillAlive,
      umntSub1,
      remntVd1,
      svDelSub1,
      unattachedInfo,
      unattachedSnapDel,
      unattachedSend,
      cpBig,
      seedA,
      snapA,
      snapList,
      fsckSnapA,
      forkMain,
      forkEph,
      mntFork1,
      forkWrite,
      forkIsolated,
      umntFork1,
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
      mkForceRoVol,
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
      snapDelA,
      snapListAfterDel,
      gcRun,
      umntData,
      mntVd1Ro,
      mkForceRoDev,
      umntVd1Ro,
      mkForceAfterRoUmnt,
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

  // C-03 + Fixes #1/#2/#3 assertions.
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
  expect(results.svDelSub1Busy.code, JSON.stringify(results.svDelSub1Busy)).not.toBe(0);
  expect(results.svDelSub1Busy.output).toContain('EBUSY');
  expect(results.umntDataFirst.code, JSON.stringify(results.umntDataFirst)).toBe(0);
  expect(results.subStillAlive.code, JSON.stringify(results.subStillAlive)).toBe(0);
  expect(results.subStillAlive.output).toContain('alive-after-root-umount');
  expect(results.umntSub1.code).toBe(0);
  expect(results.remntVd1.code, JSON.stringify(results.remntVd1)).toBe(0);
  expect(results.svDelSub1.code, JSON.stringify(results.svDelSub1)).toBe(0);
  expect(results.unattachedInfo.code).not.toBe(0);
  expect(results.unattachedInfo.output).toContain('ENODEV');
  expect(results.unattachedSnapDel.code).not.toBe(0);
  expect(results.unattachedSnapDel.output).toContain('ENODEV');
  expect(results.unattachedSend.code).not.toBe(0);
  expect(results.unattachedSend.output).toContain('ENODEV');

  // C-04 assertions (snapshots, fork, post-fork isolation, snapshot delete, GC).
  expect(results.cpBig.code, JSON.stringify(results.cpBig)).toBe(0);
  expect(results.seedA.code).toBe(0);
  expect(results.snapA.code, JSON.stringify(results.snapA)).toBe(0);
  expect(JSON.parse(results.snapList.output).snapshots.map(s => s.name)).toContain('snapA');
  expect(results.fsckSnapA.code, JSON.stringify(results.fsckSnapA)).toBe(0);
  expect(JSON.parse(results.fsckSnapA.output).ok).toBe(true);
  expect(results.forkMain.code, JSON.stringify(results.forkMain)).toBe(0);
  expect(JSON.parse(results.forkMain.output).volume).toBe('vol-fork1');
  expect(results.forkEph.code, JSON.stringify(results.forkEph)).toBe(0);
  expect(results.mntFork1.code, JSON.stringify(results.mntFork1)).toBe(0);
  expect(results.forkWrite.code, JSON.stringify(results.forkWrite)).toBe(0);
  expect(results.forkIsolated.code, JSON.stringify(results.forkIsolated)).toBe(0);
  expect(results.umntFork1.code).toBe(0);
  expect(results.modB.code).toBe(0);
  expect(results.snapB.code).toBe(0);

  // C-05 & C-06 assertions.
  expect(results.pipeFull.code, JSON.stringify(results.pipeFull)).toBe(0);
  expect(JSON.parse(results.pipeFull.output).blocks_received).toBeGreaterThanOrEqual(2);
  expect(results.sendFullB.code, JSON.stringify(results.sendFullB)).toBe(0);
  expect(results.sendFullB.output).toContain('sent ');
  expect(results.sendIncAB.code, JSON.stringify(results.sendIncAB)).toBe(0);
  expect(results.incABSize).toBeLessThan(results.fullBSize);
  expect(results.recvMissingParent.code).not.toBe(0);
  expect(results.recvMissingParent.output).toContain('ENOENT');
  expect(results.recvCorrupt.code).not.toBe(0);
  expect(results.recvCorrupt.output).toContain('EIO');
  expect(results.fsckCorruptVol.code).toBe(8);
  expect(results.recvIncOk.code, JSON.stringify(results.recvIncOk)).toBe(0);
  expect(JSON.parse(results.recvIncOk.output).blocks_received).toBe(0);
  expect(JSON.parse(results.recvIncOk.output).snapshot).toBe('snapB');
  expect(results.mntReplica.code, JSON.stringify(results.mntReplica)).toBe(0);
  expect(results.mkForceRoVol.code, JSON.stringify(results.mkForceRoVol)).not.toBe(0);
  expect(results.mkForceRoVol.output).toContain('EBUSY');
  expect(results.replicaCopy.code, JSON.stringify(results.replicaCopy)).toBe(0);
  expect(results.replicaText).toBe('updated-in-B\n');
  expect(results.replicaBigMatch).toBe(true);
  expect(results.umntReplica.code).toBe(0);

  // C-07, C-08, C-09 assertions + RO-dev mkfs EBUSY + snapshot delete + GC.
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
  expect(results.snapDelA.code, JSON.stringify(results.snapDelA)).toBe(0);
  expect(JSON.parse(results.snapDelA.output).deleted).toBe('snapA');
  expect(JSON.parse(results.snapListAfterDel.output).snapshots.map(s => s.name)).not.toContain('snapA');
  expect(results.gcRun.code, JSON.stringify(results.gcRun)).toBe(0);
  expect(JSON.parse(results.gcRun.output).live_roots).toBeGreaterThanOrEqual(1);
  expect(results.umntData.code).toBe(0);
  expect(results.mntVd1Ro.code, JSON.stringify(results.mntVd1Ro)).toBe(0);
  expect(results.mkForceRoDev.code, JSON.stringify(results.mkForceRoDev)).not.toBe(0);
  expect(results.mkForceRoDev.output).toContain('EBUSY');
  expect(results.umntVd1Ro.code).toBe(0);
  expect(results.mkForceAfterRoUmnt.code, JSON.stringify(results.mkForceAfterRoUmnt)).toBe(0);
  expect(JSON.parse(results.mkForceAfterRoUmnt.output).incarnation).toBe(3);
  expect(results.fsckArchiveBad.code, JSON.stringify(results.fsckArchiveBad)).toBe(4);

  await page.evaluate(() => window.osStandaloneConsole.closeClean());
  expect(outboundRequests).toEqual([]);
  expect(serverHits).toEqual([]);
  expect(pageErrors).toEqual([]);
});

test('web/wasi/process.js guest-fd translation for LOOP_SET_FD, FICLONERANGE, COWFS_IOC_SEND, COWFS_IOC_RECEIVE (valid + invalid/closed -> EBADF)', async ({
  page,
}) => {
  const srcDist = join(repoRoot, 'dist');
  const workerBytes = await readFile(join(srcDist, 'wasi-process.js'));
  const probeSrv = http.createServer((req, res) => {
    const headers = {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cache-Control': 'no-store',
    };
    if (req.url === '/') {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<!doctype html><meta charset="utf-8"><title>wasi-fd-probe</title>');
      return;
    }
    if (req.url === '/wasi-process.js') {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/javascript; charset=utf-8' });
      res.end(workerBytes);
      return;
    }
    res.writeHead(404, headers);
    res.end('not found');
  });
  await new Promise(r => probeSrv.listen(0, '127.0.0.1', r));
  const probeOrigin = `http://127.0.0.1:${probeSrv.address().port}`;

  try {
    const LOOP_SET_FD = 0x4c00;
    const FICLONERANGE = 0x4020940d;
    const COWFS_IOC_SEND = 0x54570209;
    const COWFS_IOC_RECEIVE = 0x5457020a;

    const calls = [
      // 0: open target device -> guest fd 4, kfd 400
      { open: { path: '/dev/loop0', flags: 0, mode: 0 } },
      // 1: open backing/stream file -> guest fd 5, kfd 500
      { open: { path: '/tmp/backing.bin', flags: 2, mode: 0o644 } },
      // 2..5: valid `{ ref: 1 }` batch refs -> MUST translate to kfd 500!
      { ioctl: { fd: { ref: 0 }, request: LOOP_SET_FD, arg: { ref: 1 } } },
      { ioctl: { fd: { ref: 0 }, request: FICLONERANGE, arg: { src_fd: { ref: 1 }, src_offset: 0, src_length: 0, dest_offset: 0 } } },
      { ioctl: { fd: { ref: 0 }, request: COWFS_IOC_SEND, arg: { snapshot: 's', stream_fd: { ref: 1 }, archive: false } } },
      { ioctl: { fd: { ref: 0 }, request: COWFS_IOC_RECEIVE, arg: { stream_fd: { ref: 1 } } } },
      // 6..9: valid explicit guest fd 5 -> MUST translate to kfd 500!
      { ioctl: { fd: 4, request: LOOP_SET_FD, arg: 5 } },
      { ioctl: { fd: 4, request: FICLONERANGE, arg: { src_fd: 5, src_offset: 0, src_length: 0, dest_offset: 0 } } },
      { ioctl: { fd: 4, request: COWFS_IOC_SEND, arg: { snapshot: 's', stream_fd: 5, archive: false } } },
      { ioctl: { fd: 4, request: COWFS_IOC_RECEIVE, arg: { stream_fd: 5 } } },
      // 10..13: invalid guest fd 999 -> MUST translate to 0xffffffff -> EBADF!
      { ioctl: { fd: 4, request: LOOP_SET_FD, arg: 999 } },
      { ioctl: { fd: 4, request: FICLONERANGE, arg: { src_fd: 999, src_offset: 0, src_length: 0, dest_offset: 0 } } },
      { ioctl: { fd: 4, request: COWFS_IOC_SEND, arg: { snapshot: 's', stream_fd: 999, archive: false } } },
      { ioctl: { fd: 4, request: COWFS_IOC_RECEIVE, arg: { stream_fd: 999 } } },
      // 14: close guest fd 5
      { close: { fd: 5 } },
      // 15..18: closed guest fd 5 -> MUST translate to 0xffffffff -> EBADF!
      { ioctl: { fd: 4, request: LOOP_SET_FD, arg: 5 } },
      { ioctl: { fd: 4, request: FICLONERANGE, arg: { src_fd: 5, src_offset: 0, src_length: 0, dest_offset: 0 } } },
      { ioctl: { fd: 4, request: COWFS_IOC_SEND, arg: { snapshot: 's', stream_fd: 5, archive: false } } },
      { ioctl: { fd: 4, request: COWFS_IOC_RECEIVE, arg: { stream_fd: 5 } } },
    ];
    const jsonBytes = Buffer.from(JSON.stringify(calls), 'utf8');
    const escaped = [...jsonBytes].map(b => '\\' + b.toString(16).padStart(2, '0')).join('');
    const wat = `(module
      (import "os" "sys" (func $sys (param i32 i32) (result i32)))
      (import "os" "reply" (func $reply (param i32)))
      (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 2)
      (data (i32.const 1024) "${escaped}")
      (func (export "_start")
        (local $rlen i32)
        (local.set $rlen (call $sys (i32.const 1024) (i32.const ${jsonBytes.length})))
        (call $reply (i32.const 16384))
        (i32.store (i32.const 0) (i32.const 16384))
        (i32.store (i32.const 4) (local.get $rlen))
        (drop (call $fd_write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`;
    const mod = binaryen.parseText(wat);
    let wasmBytes;
    try {
      wasmBytes = [...mod.emitBinary()];
    } finally {
      mod.dispose();
    }

    await page.goto(`${probeOrigin}/`);
    const outcome = await page.evaluate(async wasmArr => {
      const compiled = await WebAssembly.compile(new Uint8Array(wasmArr));
      const sab = new SharedArrayBuffer(128 * 1024);
      const state = new Int32Array(sab, 0, 2);
      const payload = new Uint8Array(sab, 8);
      const control = new SharedArrayBuffer(1024);
      const worker = new Worker('/wasi-process.js');
      const seenIoctls = [];
      const events = [];
      let stdout = '';
      let stderr = '';
      let nextKfd = 400;

      const replyHost = obj => {
        const enc = new TextEncoder().encode(JSON.stringify(obj));
        payload.set(enc, 0);
        Atomics.store(state, 1, enc.length);
        Atomics.store(state, 0, 1);
        Atomics.notify(state, 0);
      };

      const done = await new Promise((resolveDone, rejectDone) => {
        const timer = setTimeout(() => {
          rejectDone(new Error(`worker timed out; stderr=${stderr}; stdout=${stdout}; events=${JSON.stringify(events)}`));
        }, 15_000);
        const finish = fn => val => { clearTimeout(timer); fn(val); };
        worker.onerror = err => finish(rejectDone)(new Error(`worker error: ${err.message}; stderr=${stderr}; events=${JSON.stringify(events)}`));
        worker.onmessage = ({ data }) => {
          if (data.out) {
            const text = new TextDecoder().decode(data.out);
            if (data.fd === 2) stderr += text;
            else stdout += text;
            return;
          }
          if (data.exit !== undefined) {
            finish(resolveDone)({ code: data.exit, signal: data.signal ?? null });
            return;
          }
          if (data.host) {
            const { type, args } = data.host;
            events.push({ type, op: args?.op ?? null });
            if (type !== 'vfs') {
              replyHost({});
              return;
            }
            if (args.op === 'openat') {
              const kfd = nextKfd;
              nextKfd += 100;
              replyHost({ kfd, stat: { mode: 0o100644, size: 64 }, size: 64 });
              return;
            }
            if (args.op === 'close') {
              replyHost({});
              return;
            }
            if (args.op === 'sys') {
              const results = (args.batch?.calls ?? []).map(call => {
                if (call.open || call.open_at) {
                  const kfd = nextKfd;
                  nextKfd += 100;
                  return { ok: { fd: kfd, stat: { mode: 0o100644, size: 64 }, size: 64 } };
                }
                if (call.close) return { ok: null };
                if (call.ioctl) {
                  const { fd, request, arg } = call.ioctl;
                  const innerFd =
                    request === 0x4c00
                      ? arg
                      : request === 0x4020940d
                        ? arg?.src_fd
                        : arg?.stream_fd;
                  seenIoctls.push({ fd, request, innerFd });
                  if (innerFd === 500) return { ok: { translated: innerFd } };
                  if (innerFd === 0xffffffff) return { err: { errno: 'EBADF' } };
                  return { err: { errno: 'EINVAL' } };
                }
                return { ok: null };
              });
              replyHost({ results });
              return;
            }
            replyHost({});
          } else {
            events.push({ other: Object.keys(data) });
          }
        };
        worker.postMessage({
          pid: 77,
          ppid: 1,
          cwd: '/',
          umask: 0o022,
          argv: ['probe'],
          env: [],
          module: compiled,
          channel: sab,
          control,
          stdin: { data: new Uint8Array(0) },
          stdout: {},
          stderr: {},
        });
      });
      worker.terminate();
      return { done, seenIoctls, stdout, stderr };
    }, wasmBytes);

    expect(outcome.done.code, outcome.stdout).toBe(0);
    const parsed = JSON.parse(outcome.stdout);
    // 16 ioctls total: 8 valid (4 via {ref}, 4 explicit guest fd 5) -> kfd 500;
    // 8 invalid/closed (4 with fd 999, 4 with closed fd 5) -> 0xffffffff -> EBADF!
    expect(outcome.seenIoctls.length).toBe(16);
    for (let i = 0; i < 8; i++) {
      expect(outcome.seenIoctls[i].fd).toBe(400);
      expect(outcome.seenIoctls[i].innerFd).toBe(500);
      expect(parsed.results[2 + i]).toEqual({ ok: { translated: 500 } });
    }
    for (let i = 0; i < 4; i++) {
      expect(outcome.seenIoctls[8 + i].innerFd).toBe(0xffffffff);
      expect(parsed.results[10 + i]).toEqual({ err: { errno: 'EBADF' } });
    }
    for (let i = 0; i < 4; i++) {
      expect(outcome.seenIoctls[12 + i].innerFd).toBe(0xffffffff);
      expect(parsed.results[15 + i]).toEqual({ err: { errno: 'EBADF' } });
    }
  } finally {
    await new Promise(r => probeSrv.close(r));
  }
});
