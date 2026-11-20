// Browser Playwright verification for `os-cowfs` (#77, Blueprint §3.2):
// Runs real compiled `os-client-kernel` wasm32 + `web/kernel/cowfs-store.js` inside a real
// Chromium dedicated Web Worker (exercising real browser OPFS `FileSystemSyncAccessHandle`,
// lock-free `getFile().slice()`, IndexedDB `{durability: "strict"}`, and real cross-tab Web Locks
// `os-vol:<uuid>`) served from an isolated ephemeral-port local HTTP server with ZERO external
// network requests.

import { test, expect } from './test.js';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { accessSync, constants as fsConstants, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('..', import.meta.url));
let server, origin, assets, wasmOutDir;

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

const workerScript = `
import init, {
  CowFsVolume,
  cowfs_format_volume,
  cowfs_verify_volume,
  cowfs_collect_garbage,
} from '/wasm/client_kernel.js';
import { createCowfsStore } from '/web/kernel/cowfs-store.js';

let initialized = false;
const handles = new Map();
let nextHandle = 1;
const stores = new Map();

function getStore(dbName = 'os-cowfs-e2e') {
  let s = stores.get(dbName);
  if (!s) {
    s = createCowfsStore({ dbName });
    stores.set(dbName, s);
  }
  return s;
}

self.onmessage = async ({ data }) => {
  const { id, cmd, args = {} } = data;
  try {
    if (!initialized) {
      await init('/wasm/client_kernel_bg.wasm');
      initialized = true;
    }
    const store = getStore(args.dbName);
    let result;
    switch (cmd) {
      case 'format':
        result = await cowfs_format_volume(store, args.volume, args.mode ?? 0o755);
        break;
      case 'open_rw': {
        const vol = await CowFsVolume.open_rw(store, args.volume, args.mode ?? 'exclusive');
        const hid = nextHandle++;
        handles.set(hid, vol);
        result = { hid, volumeId: vol.volume_id(), forkedFrom: vol.forked_from() ?? null, info: vol.info() };
        break;
      }
      case 'open_ro': {
        const vol = await CowFsVolume.open_ro(store, args.volume);
        const hid = nextHandle++;
        handles.set(hid, vol);
        result = { hid, volumeId: vol.volume_id(), info: vol.info() };
        break;
      }
      case 'open_snapshot': {
        const vol = await CowFsVolume.open_snapshot(store, args.volume, args.snapshot);
        const hid = nextHandle++;
        handles.set(hid, vol);
        result = { hid, volumeId: vol.volume_id(), info: vol.info() };
        break;
      }
      case 'mkdir':
        await handles.get(args.hid).mkdir(args.path, args.mode ?? 0o755, args.identity ?? null);
        result = true;
        break;
      case 'write_file':
        result = await handles.get(args.hid).write_file(
          args.path,
          new Uint8Array(args.bytes),
          args.mode ?? 0o644,
          args.identity ?? null,
        );
        break;
      case 'write_pattern': {
        const buf = new Uint8Array(args.size);
        for (let i = 0; i < buf.length; i += 65536) {
          buf.fill((i / 65536) & 0xff, i, Math.min(i + 65536, buf.length));
        }
        result = await handles.get(args.hid).write_file(args.path, buf, 0o644, null);
        break;
      }
      case 'write_at_offset':
        result = await handles.get(args.hid).write_at_offset(
          args.path,
          args.offset,
          new Uint8Array(args.bytes),
          0o644,
          null,
        );
        break;
      case 'truncate':
        await handles.get(args.hid).truncate(args.path, args.size, null);
        result = true;
        break;
      case 'read_file':
        result = [...(await handles.get(args.hid).read_file(args.path, args.identity ?? null))];
        break;
      case 'read_range':
        result = [...(await handles.get(args.hid).read_range(args.path, args.offset, args.len, null))];
        break;
      case 'stat':
        result = await handles.get(args.hid).stat(args.path, args.follow ?? true, args.identity ?? null);
        break;
      case 'setxattr':
        await handles.get(args.hid).setxattr(args.path, args.name, new Uint8Array(args.value), args.flags ?? 0, args.identity ?? null);
        result = true;
        break;
      case 'getxattr':
        result = [...(await handles.get(args.hid).getxattr(args.path, args.name, args.identity ?? null))];
        break;
      case 'symlink':
        await handles.get(args.hid).symlink(args.target, args.linkpath, args.identity ?? null);
        result = true;
        break;
      case 'readlink':
        result = await handles.get(args.hid).readlink(args.path, args.identity ?? null);
        break;
      case 'link':
        await handles.get(args.hid).link(args.oldpath, args.newpath, args.identity ?? null);
        result = true;
        break;
      case 'unlink':
        await handles.get(args.hid).unlink(args.path, args.identity ?? null);
        result = true;
        break;
      case 'rename':
        await handles.get(args.hid).rename(args.from, args.to, Boolean(args.noreplace), args.identity ?? null);
        result = true;
        break;
      case 'create_many': {
        const vol = handles.get(args.hid);
        await vol.mkdir(args.dir, 0o755, null);
        const empty = new Uint8Array(0);
        for (let i = 0; i < args.count; i++) {
          await vol.write_file(args.dir + '/e' + String(i).padStart(5, '0'), empty, 0o644, null);
        }
        result = args.count;
        break;
      }
      case 'page_dir_all': {
        const vol = handles.get(args.hid);
        let cookie = 0;
        let count = 0;
        let pages = 0;
        const seen = new Set();
        while (true) {
          const page = await vol.read_dir_page(args.dir, cookie, args.pageSize ?? 256, null);
          pages++;
          for (const e of page.entries) {
            if (seen.has(e.name)) throw new Error('duplicate entry ' + e.name);
            seen.add(e.name);
            count++;
          }
          if (page.next_cookie == null) break;
          cookie = page.next_cookie;
        }
        result = { count, pages };
        break;
      }
      case 'ficlone':
        await handles.get(args.hid).ficlone(args.src, args.dst, null);
        result = true;
        break;
      case 'ficlone_other':
        await handles.get(args.hid).ficlone_from_other(handles.get(args.otherHid), args.src, args.dst, null);
        result = true;
        break;
      case 'sync_fs':
        result = await handles.get(args.hid).sync_fs();
        break;
      case 'snapshot':
        result = await handles.get(args.hid).snapshot(args.name);
        break;
      case 'fork':
        result = await handles.get(args.hid).fork(args.snapshot ?? null, args.newVolume, Boolean(args.ephemeral));
        break;
      case 'ioctl':
        result = await handles.get(args.hid).ioctl(args.request, args.payload ?? '', args.identity ?? null);
        break;
      case 'mkfs_target':
        result = await handles.get(args.hid).mkfs_target(args.target, Boolean(args.force), args.identity ?? null);
        break;
      case 'arena_stats':
        result = handles.get(args.hid).arena_stats();
        break;
      case 'drop_caches':
        handles.get(args.hid).drop_clean_caches();
        result = true;
        break;
      case 'close_clean': {
        const vol = handles.get(args.hid);
        await vol.close_clean();
        handles.delete(args.hid);
        result = true;
        break;
      }
      case 'verify':
        result = await cowfs_verify_volume(store, args.volume);
        break;
      case 'gc':
        result = await cowfs_collect_garbage(store, args.graceBeforeSec ?? 0);
        break;
      case 'store_stats':
        result = { ...store.stats };
        break;
      case 'reset_store_stats':
        store.resetStats();
        result = true;
        break;
      case 'read_head':
        result = await store.readHead(args.volume);
        break;
      default:
        throw new Error('unknown cmd: ' + cmd);
    }
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, errno: err?.errno ?? null, message: err?.message ?? String(err) });
  }
};
`;

const pageHtml = `<!doctype html>
<meta charset="utf-8">
<title>os-cowfs browser conformance</title>
<script type="module">
  const worker = new Worker('/worker.js', { type: 'module' });
  let nextId = 1;
  const pending = new Map();
  worker.onmessage = ({ data }) => {
    const p = pending.get(data.id);
    if (!p) return;
    pending.delete(data.id);
    if (data.ok) p.resolve(data.result);
    else p.reject(Object.assign(new Error(data.message), { errno: data.errno }));
  };
  globalThis.rpc = (cmd, args = {}) => new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, cmd, args });
  });
  globalThis.rpcErrno = (cmd, args = {}) =>
    globalThis.rpc(cmd, args).then(() => 'UNEXPECTED_OK', err => err.errno ?? err.message);
</script>`;

test.beforeAll(async () => {
  const targetDir = resolveCargoTargetDir();
  wasmOutDir = await mkdtemp(join(tmpdir(), 'os-l25a-web-wasm-'));
  execFileSync(
    'cargo',
    [
      'build',
      '--quiet',
      '--locked',
      '--offline',
      '-p',
      'os-client-kernel',
      '--target',
      'wasm32-unknown-unknown',
      '--target-dir',
      targetDir,
    ],
    {
      cwd: repoRoot,
      stdio: 'inherit',
      env: { ...process.env, CARGO_PROFILE_DEV_DEBUG: process.env.CARGO_PROFILE_DEV_DEBUG ?? '0' },
    },
  );
  execFileSync(
    'wasm-bindgen',
    [
      '--target',
      'web',
      '--no-typescript',
      '--out-dir',
      wasmOutDir,
      '--out-name',
      'client_kernel',
      join(targetDir, 'wasm32-unknown-unknown/debug/os_client_kernel.wasm'),
    ],
    { cwd: repoRoot, stdio: 'inherit' },
  );

  assets = new Map([
    ['/', { body: Buffer.from(pageHtml), type: 'text/html' }],
    ['/worker.js', { body: Buffer.from(workerScript), type: 'text/javascript' }],
    [
      '/web/kernel/cowfs-store.js',
      { body: await readFile(join(repoRoot, 'web/kernel/cowfs-store.js')), type: 'text/javascript' },
    ],
    [
      '/wasm/client_kernel.js',
      { body: await readFile(join(wasmOutDir, 'client_kernel.js')), type: 'text/javascript' },
    ],
    [
      '/wasm/client_kernel_bg.wasm',
      { body: await readFile(join(wasmOutDir, 'client_kernel_bg.wasm')), type: 'application/wasm' },
    ],
  ]);

  server = http.createServer((req, res) => {
    const asset = assets.get(req.url);
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cache-Control', 'no-store');
    if (!asset || req.method !== 'GET') {
      res.writeHead(404).end();
      return;
    }
    res.setHeader('Content-Type', asset.type);
    res.end(asset.body);
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  origin = `http://127.0.0.1:${server.address().port}`;
});

test.afterAll(async () => {
  if (server) await new Promise(done => server.close(done));
  if (wasmOutDir) await rm(wasmOutDir, { recursive: true, force: true });
});

test('browser OPFS SyncAccessHandle + strict IDB: POSIX ops, O(1) snapshot/fork/FICLONE, 8 GiB sparse read, paged dir, & /dev/vd0 ioctls', async ({ page }) => {
  await page.goto(origin + '/');
  const res = await page.evaluate(async () => {
    const dbName = 'os-cowfs-spec-1';
    const volName = 'vol-browser-1';
    const volOther = 'vol-browser-2';
    await rpc('format', { dbName, volume: volName });
    await rpc('format', { dbName, volume: volOther });

    const { hid } = await rpc('open_rw', { dbName, volume: volName, mode: 'exclusive' });
    const { hid: otherHid } = await rpc('open_rw', { dbName, volume: volOther, mode: 'exclusive' });

    // POSIX: mkdir, symlink, hard link, xattr, rename NOREPLACE.
    await rpc('mkdir', { dbName, hid, path: '/dir', mode: 0o755 });
    await rpc('write_file', { dbName, hid, path: '/dir/hello.txt', bytes: [...new TextEncoder().encode('hello cowfs')] });
    await rpc('link', { dbName, hid, oldpath: '/dir/hello.txt', newpath: '/dir/hard.txt' });
    await rpc('symlink', { dbName, hid, target: 'hello.txt', linkpath: '/dir/sym.txt' });
    await rpc('setxattr', { dbName, hid, path: '/dir/hello.txt', name: 'user.note', value: [...new TextEncoder().encode('ok')] });
    const xattr = new TextDecoder().decode(new Uint8Array(await rpc('getxattr', { dbName, hid, path: '/dir/hard.txt', name: 'user.note' })));
    const linkTarget = await rpc('readlink', { dbName, hid, path: '/dir/sym.txt' });
    const noreplaceErr = await rpcErrno('rename', { dbName, hid, from: '/dir/hello.txt', to: '/dir/hard.txt', noreplace: true });

    // Write 10 MiB file -> exercises SyncAccessHandle + >8 MiB dirty arena backpressure!
    const TEN_MIB = 10 * 1024 * 1024;
    await rpc('write_pattern', { dbName, hid, path: '/ten.bin', size: TEN_MIB });
    await rpc('sync_fs', { dbName, hid });
    const storeAfterWrite = await rpc('store_stats', { dbName });

    // O(1) snapshot + fork + FICLONE copy 0 pack bytes!
    await rpc('reset_store_stats', { dbName });
    await rpc('snapshot', { dbName, hid, name: 'snap1' });
    await rpc('fork', { dbName, hid, snapshot: 'snap1', newVolume: 'vol-browser-fork' });
    await rpc('ficlone', { dbName, hid, src: '/ten.bin', dst: '/ten-clone.bin' });
    await rpc('sync_fs', { dbName, hid });
    const storeAfterO1 = await rpc('store_stats', { dbName });

    // Cross-volume FICLONE -> EXDEV.
    const xdevErr = await rpcErrno('ficlone_other', { dbName, hid: otherHid, otherHid: hid, src: '/ten.bin', dst: '/x.bin' });

    // Mutate 4 bytes in clone -> CoW only touched 64 KiB block; original intact!
    await rpc('write_at_offset', { dbName, hid, path: '/ten-clone.bin', offset: 0, bytes: [77, 85, 84, 69] });
    await rpc('sync_fs', { dbName, hid });
    const origHead = await rpc('read_range', { dbName, hid, path: '/ten.bin', offset: 0, len: 4 });
    const cloneHead = await rpc('read_range', { dbName, hid, path: '/ten-clone.bin', offset: 0, len: 4 });

    // 8 GiB sparse cold read + paged directory enumeration within 32 MiB arena.
    const EIGHT_GIB = 8 * 1024 * 1024 * 1024;
    await rpc('write_file', { dbName, hid, path: '/8g.bin', bytes: [] });
    await rpc('truncate', { dbName, hid, path: '/8g.bin', size: EIGHT_GIB });
    const marker = [...new TextEncoder().encode('browser-8gib-ok')];
    await rpc('write_at_offset', { dbName, hid, path: '/8g.bin', offset: EIGHT_GIB - 4096, bytes: marker });
    await rpc('create_many', { dbName, hid, dir: '/many', count: 2500 });
    await rpc('sync_fs', { dbName, hid });
    await rpc('drop_caches', { dbName, hid });
    const sparseRead = await rpc('read_range', { dbName, hid, path: '/8g.bin', offset: EIGHT_GIB - 4096, len: marker.length });
    const paged = await rpc('page_dir_all', { dbName, hid, dir: '/many', pageSize: 200 });
    const arena = await rpc('arena_stats', { dbName, hid });

    // /dev/vd0 ioctls (root vs non-root EPERM) + mkfs ENOTBLK.
    const blkInfo = await rpc('ioctl', { dbName, hid, request: 0x5457_0210 });
    const nonRootSnap = await rpcErrno('ioctl', {
      dbName,
      hid,
      request: 0x5457_0201,
      payload: JSON.stringify({ name: 'denied' }),
      identity: { id: 1000, group: 1000, groups: [1000] },
    });
    const enotblk = await rpcErrno('mkfs_target', { dbName, hid, target: '/dir' });

    await rpc('close_clean', { dbName, hid: otherHid });
    await rpc('close_clean', { dbName, hid });
    const fsck = await rpc('verify', { dbName, volume: volName });

    return {
      xattr,
      linkTarget,
      noreplaceErr,
      syncHandleWrites: storeAfterWrite.syncHandleWrites,
      o1PackBytes: storeAfterO1.packBytesWritten,
      xdevErr,
      origHead,
      cloneHead,
      sparseOk: JSON.stringify(sparseRead) === JSON.stringify(marker),
      paged,
      arena,
      blkInfo,
      nonRootSnap,
      enotblk,
      fsckOk: fsck.ok,
      fsckErrors: fsck.errors,
    };
  });

  expect(res.xattr).toBe('ok');
  expect(res.linkTarget).toBe('hello.txt');
  expect(res.noreplaceErr).toBe('EEXIST');
  expect(res.syncHandleWrites).toBeGreaterThan(0);
  expect(res.o1PackBytes).toBe(0);
  expect(res.xdevErr).toBe('EXDEV');
  expect(res.origHead).toEqual([0, 0, 0, 0]);
  expect(res.cloneHead).toEqual([77, 85, 84, 69]);
  expect(res.sparseOk).toBe(true);
  expect(res.paged.count).toBe(2500);
  expect(res.paged.pages).toBeGreaterThanOrEqual(12);
  expect(res.arena.backpressure_flushes).toBeGreaterThan(0);
  expect(res.arena.peak_tree_lru_bytes).toBeLessThanOrEqual(8 * 1024 * 1024);
  expect(res.arena.peak_clean_data_bytes).toBeLessThanOrEqual(16 * 1024 * 1024);
  expect(res.arena.peak_dirty_bytes).toBeLessThanOrEqual(8 * 1024 * 1024);
  expect(res.arena.peak_total_bytes).toBeLessThanOrEqual(32 * 1024 * 1024);
  expect(res.blkInfo.volume).toBe('vol-browser-1');
  expect(res.nonRootSnap).toBe('EPERM');
  expect(res.enotblk).toBe('ENOTBLK');
  expect(res.fsckOk).toBe(true);
  expect(res.fsckErrors).toEqual([]);
});

test('two browser tabs sharing profile Web Locks: Exclusive EBUSY, ForkOnBusy auto-prune vs keep, lock-free RO slice reads, and ForceTakeover ESTALE', async ({ context }) => {
  const tab1 = await context.newPage();
  const tab2 = await context.newPage();
  await tab1.goto(origin + '/');
  await tab2.goto(origin + '/');

  const dbName = 'os-cowfs-tabs';
  const volName = 'vol-shared-profile';

  // Tab 1 formats & holds exclusive Web Lock `os-vol:vol-shared-profile`.
  const t1 = await tab1.evaluate(async ({ dbName, volName }) => {
    await rpc('format', { dbName, volume: volName });
    const opened = await rpc('open_rw', { dbName, volume: volName, mode: 'exclusive' });
    await rpc('write_file', { dbName, hid: opened.hid, path: '/t1.bin', bytes: [...new Uint8Array(65536).fill(0x22)] });
    await rpc('sync_fs', { dbName, hid: opened.hid });
    return opened;
  }, { dbName, volName });

  // Tab 2 checks:
  // (a) Exclusive -> EBUSY
  // (b) ForkOnBusy unmodified -> auto-pruned on close_clean
  // (c) ForkOnBusy modified -> kept on close_clean
  // (d) RO mount reads concurrently via lock-free getFile().slice() while Tab 1 holds writer lock!
  const t2 = await tab2.evaluate(async ({ dbName, volName }) => {
    const exclErr = await rpcErrno('open_rw', { dbName, volume: volName, mode: 'exclusive' });

    const fUnmod = await rpc('open_rw', { dbName, volume: volName, mode: 'fork-on-busy' });
    await rpc('close_clean', { dbName, hid: fUnmod.hid });
    const unmodAfter = await rpcErrno('read_head', { dbName, volume: fUnmod.volumeId });

    const fMod = await rpc('open_rw', { dbName, volume: volName, mode: 'fork-on-busy' });
    await rpc('write_file', { dbName, hid: fMod.hid, path: '/from-t2.txt', bytes: [...new TextEncoder().encode('saved')] });
    await rpc('close_clean', { dbName, hid: fMod.hid });
    const modHead = await rpc('read_head', { dbName, volume: fMod.volumeId });

    const ro = await rpc('open_ro', { dbName, volume: volName });
    const roBytes = await rpc('read_file', { dbName, hid: ro.hid, path: '/t1.bin' });
    const roStats = await rpc('store_stats', { dbName });
    await rpc('close_clean', { dbName, hid: ro.hid });

    // ForceTakeover bumps local_fence -> Tab 1's next commit must fail with ESTALE!
    const taken = await rpc('open_rw', { dbName, volume: volName, mode: 'force-takeover' });
    return {
      exclErr,
      forkedFrom: fUnmod.forkedFrom,
      unmodAfter,
      modKept: modHead.modified,
      roLen: roBytes.length,
      sliceReads: roStats.sliceReads,
      takenHid: taken.hid,
      takenFence: taken.info.fence,
    };
  }, { dbName, volName });

  expect(t2.exclErr).toBe('EBUSY');
  expect(t2.forkedFrom).toBe(volName);
  expect(t2.unmodAfter).toBe('ENOENT');
  expect(t2.modKept).toBe(true);
  expect(t2.roLen).toBe(65536);
  expect(t2.sliceReads).toBeGreaterThan(0);
  expect(t2.takenFence).toBeGreaterThan(t1.info.fence);

  // Tab 1 attempts to commit after ForceTakeover -> MUST fail with ESTALE!
  const t1Stale = await tab1.evaluate(async ({ dbName, hid }) => {
    await rpc('write_file', { dbName, hid, path: '/stale.txt', bytes: [1, 2, 3] });
    return await rpcErrno('sync_fs', { dbName, hid });
  }, { dbName, hid: t1.hid });
  expect(t1Stale).toBe('ESTALE');

  // Tab 2 commits cleanly and verifies volume integrity!
  const t2Clean = await tab2.evaluate(async ({ dbName, volName, hid }) => {
    await rpc('write_file', { dbName, hid, path: '/winner.txt', bytes: [...new TextEncoder().encode('tab2')] });
    await rpc('close_clean', { dbName, hid });
    return await rpc('verify', { dbName, volume: volName });
  }, { dbName, volName, hid: t2.takenHid });
  expect(t2Clean.ok).toBe(true);
  expect(t2Clean.errors).toEqual([]);

  await tab1.close();
  await tab2.close();
});
