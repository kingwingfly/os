import { test, expect } from './test.js';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import binaryen from 'binaryen';

// Component conformance, not process admission or the Phase 8.1 completion gate. Serve
// fixed source modules and the actual built compiler Worker. No authority/cloud compiler
// is present, and every unexpected network request (including Worker requests) fails.
const source = ['web/release.js', 'web/kernel/loader.js', 'web/kernel/local-mounts.js',
  'web/kernel/local-transform.js', 'web/kernel/transform.js', 'web/kernel/asyncify.js',
  'web/kernel/memory.js', 'web/kernel/image.js', 'web/wasi/fork.js'];
let server, origin, assets, requests;
const prefix = '/boot/releases/' + 'a'.repeat(64) + '/assets';
function wasm(wat) { const module = binaryen.parseText(wat); try { return [...module.emitBinary()]; } finally { module.dispose(); } }
const program = word => wasm(`(module
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1 3)
  (data (i32.const 32) "${word}")
  (func (export "grow") (result i32) (memory.grow (i32.const 1)))
  (func (export "_start")
    (i32.store (i32.const 0) (i32.const 32))
    (i32.store (i32.const 4) (i32.const ${word.length}))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);

test.beforeAll(async () => {
  assets = new Map(await Promise.all(source.map(async path => ['/' + path, await readFile(new URL('../' + path, import.meta.url))])));
  assets.set('/local-compiler.js', await readFile(new URL('../dist/local-compiler.js', import.meta.url)));
  assets.set('/', Buffer.from('<!doctype html><meta charset="utf-8"><title>Local provider conformance</title><input type="file" multiple>'));
  server = http.createServer((req, res) => {
    requests.push({ method: req.method, path: req.url });
    const path = req.url.startsWith(prefix) ? req.url.slice(prefix.length) : req.url;
    const value = assets.get(path);
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : 'text/html');
    if (!value || req.method !== 'GET') { res.writeHead(403).end(); return; }
    res.end(value);
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  origin = `http://127.0.0.1:${server.address().port}`;
});
test.afterAll(async () => { if (server) await new Promise(done => server.close(done)); });
test.beforeEach(async ({ context }) => {
  requests = [];
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    const path = url.pathname.startsWith(prefix) ? url.pathname.slice(prefix.length) : url.pathname;
    if (url.origin === origin && assets.has(path) && !url.search && route.request().method() === 'GET') return route.continue();
    requests.push({ unexpected: route.request().url(), method: route.request().method() });
    return route.abort();
  });
});
test.afterEach(() => {
  expect(requests.filter(request => request.unexpected || request.method !== 'GET' || request.path.includes('/api/'))).toEqual([]);
});

async function setup(page, path = '/') {
  await page.goto(origin + path);
  await page.evaluate(async () => {
    const { LocalMounts } = await import('/web/kernel/local-mounts.js');
    const { loadLocal, stats } = await import('/web/kernel/loader.js');
    Object.assign(globalThis, { LocalMounts, loadLocal, loaderStats: stats, mounts: new LocalMounts() });
    globalThis.failure = promise => promise.then(() => 'unexpected success', error => error.errno);
    globalThis.writeFile = async (root, name, bytes) => {
      const handle = await root.getFileHandle(name, { create: true });
      const stream = await handle.createWritable(); await stream.write(new Uint8Array(bytes)); await stream.close();
      return handle;
    };
    globalThis.run = async loaded => {
      let instance, output = '', allowGrow = false, reservations = 0;
      instance = await WebAssembly.instantiate(loaded.module, {
        wasi_snapshot_preview1: { fd_write(fd, iovs, count, written) {
          if (fd !== 1 || count !== 1) throw new Error('unexpected stdout call');
          const view = new DataView(instance.exports.memory.buffer);
          const address = view.getUint32(iovs, true), length = view.getUint32(iovs + 4, true);
          output += new TextDecoder().decode(new Uint8Array(instance.exports.memory.buffer, address, length));
          view.setUint32(written, length, true); return 0;
        } },
        os_runtime: { memory_grow_pre: (_, delta) => { reservations++; return allowGrow ? delta : -1; }, memory_grow_post: (_, result) => result },
      });
      instance.exports.__tw_initialize?.(); instance.exports._start();
      const denied = instance.exports.grow(); allowGrow = true;
      return { output, denied, grown: instance.exports.grow(), reservations, memoryBytes: loaded.memoryBytes };
    };
  });
}

test('OPFS edit/pin/load keeps old bytes, recompiles new bytes, and instruments memory without uploads', async ({ page }) => {
  await setup(page);
  expect(requests.some(request => request.path?.includes('local-compiler'))).toBe(false);
  const result = await page.evaluate(async ([one, two]) => {
    const root = await navigator.storage.getDirectory();
    const project = await root.getDirectoryHandle('project', { create: true });
    await writeFile(project, 'program', one);
    const grant = await mounts.mountDirectory(project, { execute: true, originPrivate: true });
    const first = await mounts.pin(grant, 'program');
    await writeFile(project, 'program', two);
    const second = await mounts.pin(grant, 'program');
    const loaded = await loadLocal(first);
    const old = await run(loaded), next = await run(await loadLocal(second));
    return { old, next, changed: first.digest !== second.digest, cached: loaded.module === (await loadLocal(first)).module,
      compiled: loaderStats.compiled, kind: grant.kind, listing: (await mounts.list(grant)).entries };
  }, [program('before'), program('after')]);
  expect(result).toEqual({ old: { output: 'before', denied: -1, grown: 1, reservations: 2, memoryBytes: 65536 },
    next: { output: 'after', denied: -1, grown: 1, reservations: 2, memoryBytes: 65536 }, changed: true, cached: true,
    compiled: 2, kind: 'browser-storage', listing: [{ name: 'program', kind: 'file' }] });
});

test('selected-file fallback copies bytes and unmount invalidates pins even on a cache hit', async ({ page }) => {
  await setup(page);
  await page.locator('input').setInputFiles({ name: 'test.wasm', mimeType: 'application/wasm', buffer: Buffer.from(program('selected')) });
  const result = await page.evaluate(async () => {
    const grant = await mounts.mountFiles([...document.querySelector('input').files], { execute: true });
    const pin = await mounts.pin(grant, 'test.wasm');
    const first = await loadLocal(pin);
    const foreign = await failure(new LocalMounts().read(grant, 'test.wasm'));
    const forged = await failure(loadLocal(structuredClone(pin)));
    mounts.unmount(grant);
    return { kind: grant.kind, output: (await run(first)).output, foreign, forged, stale: await failure(loadLocal(pin)) };
  });
  expect(result).toEqual({ kind: 'snapshot', output: 'selected', foreign: 'EACCES', forged: 'EACCES', stale: 'ENODEV' });
});

test('local WASIX transform forks through the existing engine', async ({ page }) => {
  await setup(page);
  const bytes = wasm(await readFile(new URL('./fixtures/wasix-fork.wat', import.meta.url), 'utf8'));
  const result = await page.evaluate(async bytes => {
    const { Engine } = await import('/web/wasi/fork.js');
    const grant = await mounts.mountFiles([new File([new Uint8Array(bytes)], 'fork')], { execute: true });
    const loaded = await loadLocal(await mounts.pin(grant, 'fork'));
    const output = [];
    class Exit { constructor(code) { this.code = code; } }
    async function process(snapshot) {
      const self = {}, memory = () => self.instance.exports.memory;
      self.instance = await WebAssembly.instantiate(loaded.module, { wasix_32v1: {
        proc_fork: (_, ptr) => {
          if (self.engine.rewinding) new DataView(memory().buffer).setUint32(ptr, self.engine.resume().pid, true);
          else self.engine.unwind({ kind: 'fork' });
          return 0;
        },
        fd_write: (_, iovs, count, written) => {
          const view = new DataView(memory().buffer), length = view.getUint32(iovs + 4, true);
          output.push(new TextDecoder().decode(new Uint8Array(memory().buffer, view.getUint32(iovs, true), length)));
          view.setUint32(written, length, true); return 0;
        }, proc_exit: code => { throw new Exit(code); },
      } });
      self.engine = snapshot ? Engine.child(self.instance, memory, snapshot) : new Engine(self.instance, memory);
      if (!snapshot) self.instance.exports.__tw_initialize?.();
      return self;
    }
    const parent = await process(); parent.instance.exports._start();
    const request = parent.engine.unwound();
    const child = await process(parent.engine.snapshot());
    const exit = self => { try { self.instance.exports._start(); } catch (error) { if (error instanceof Exit) return error.code; throw error; } };
    child.engine.rewind({ pid: 0 }); const childExit = exit(child);
    parent.engine.rewind({ pid: 2 }); const parentExit = exit(parent);
    return { output, request, childExit, parentExit, memoryBytes: loaded.memoryBytes };
  }, bytes);
  expect(result).toEqual({ output: ['child\n', 'parent\n'], request: { kind: 'fork' }, childExit: 0, parentExit: 0, memoryBytes: 6 * 65536 });
});

test('unsupported native images and forged runtime imports/exports fail before transformation', async ({ page }) => {
  await setup(page);
  const result = await page.evaluate(async images => {
    const errors = [];
    for (const bytes of images) {
      const grant = await mounts.mountFiles([new File([new Uint8Array(bytes)], 'program')], { execute: true });
      errors.push(await failure(loadLocal(await mounts.pin(grant, 'program')))); mounts.unmount(grant);
    }
    return errors;
  }, [[127, 69, 76, 70], wasm('(module (memory (export "memory") 1))'),
    wasm('(module (import "os_runtime" "memory_grow_pre" (func $f)) (memory (export "memory") 1) (func (export "_start") (call $f)))'),
    wasm('(module (memory (export "memory") 1) (func (export "_start")) (func (export "__tw_initialize")))')]);
  expect(result).toEqual(['ENOEXEC', 'ENOEXEC', 'ENOEXEC', 'ENOEXEC']);
  expect(requests.some(request => request.path?.includes('local-compiler'))).toBe(false);
});

test('imported memory limits survive and the initializer runs only when the runtime asks', async ({ page }) => {
  await setup(page);
  const result = await page.evaluate(async bytes => {
    const grant = await mounts.mountFiles([new File([new Uint8Array(bytes)], 'program')], { execute: true });
    const loaded = await loadLocal(await mounts.pin(grant, 'program'));
    const memory = new WebAssembly.Memory(loaded.memory);
    const instance = await WebAssembly.instantiate(loaded.module, { env: { memory } });
    const before = new Int32Array(memory.buffer)[0];
    instance.exports.__tw_initialize();
    let cannotGrow = false; try { memory.grow(1); } catch (error) { cannotGrow = error instanceof RangeError; }
    return { before, after: new Int32Array(memory.buffer)[0], cannotGrow, memory: loaded.memory,
      memoryBytes: loaded.memoryBytes, start: loaded.startSection };
  }, wasm('(module (import "env" "memory" (memory 1 1)) (func $init (i32.store (i32.const 0) (i32.const 42))) (start $init) (func (export "_start")))'));
  expect(result).toEqual({ before: 0, after: 42, cannotGrow: true, memory: { initial: 1, maximum: 1, shared: false }, memoryBytes: 65536, start: false });
});

test('revocation during compilation rejects the launch; an independent grant can reuse the code', async ({ page }) => {
  await setup(page);
  const result = await page.evaluate(async bytes => {
    const file = new File([new Uint8Array(bytes)], 'program');
    const grant = await mounts.mountFiles([file], { execute: true });
    const other = await mounts.mountFiles([file], { execute: true });
    const pin = await mounts.pin(grant, 'program');
    const NativeWorker = globalThis.Worker;
    globalThis.Worker = class extends NativeWorker {
      postMessage(...args) { super.postMessage(...args); mounts.unmount(grant); }
    };
    try {
      const stale = await failure(loadLocal(pin));
      const current = await loadLocal(await mounts.pin(other, 'program'));
      return { stale, output: (await run(current)).output, compiled: loaderStats.compiled };
    } finally { globalThis.Worker = NativeWorker; }
  }, program('retained'));
  expect(result).toEqual({ stale: 'ENODEV', output: 'retained', compiled: 1 });
});

test('worker load failures never fall back to cloud and a subsequent load retries', async ({ page, context }) => {
  await setup(page);
  await context.route('**/local-compiler.js', route => route.fulfill({ status: 503, contentType: 'text/javascript', body: '' }));
  const first = await page.evaluate(async bytes => {
    const grant = await mounts.mountFiles([new File([new Uint8Array(bytes)], 'program')], { execute: true });
    globalThis.pin = await mounts.pin(grant, 'program');
    return failure(loadLocal(pin));
  }, program('retry'));
  expect(first).toBe('EIO');
  await context.unroute('**/local-compiler.js');
  expect(await page.evaluate(async () => (await run(await loadLocal(pin))).output)).toBe('retry');
});

test('cached snapshots can be loaded offline and the compiler follows the pinned release', async ({ page, context }) => {
  await setup(page, prefix + '/');
  await page.evaluate(async bytes => {
    const grant = await mounts.mountFiles([new File([new Uint8Array(bytes)], 'program')], { execute: true });
    globalThis.pin = await mounts.pin(grant, 'program');
    await loadLocal(pin);
  }, program('offline'));
  expect(requests.some(request => request.path === prefix + '/local-compiler.js')).toBe(true);
  await context.setOffline(true);
  expect(await page.evaluate(async () => (await run(await loadLocal(pin))).output)).toBe('offline');
  await context.setOffline(false);
});

test('writable OPFS descriptors retain file identity and append operations serialize', async ({ page }) => {
  await setup(page);
  const result = await page.evaluate(async () => {
    const root = await navigator.storage.getDirectory(), dir = await root.getDirectoryHandle('descriptors', { create: true });
    const original = await writeFile(dir, 'file', new TextEncoder().encode('A'));
    const grant = await mounts.mountDirectory(dir, { originPrivate: true, writable: true });
    const held = await mounts.hold(grant, 'file');
    await Promise.all(['B', 'C', 'D'].map(text => mounts.write(grant, held, new TextEncoder().encode(text), { append: true })));
    const appended = new TextDecoder().decode(await mounts.read(grant, held));
    await dir.removeEntry('file'); await writeFile(dir, 'file', new TextEncoder().encode('replacement'));
    const stale = await failure(mounts.read(grant, held));
    const replacement = new TextDecoder().decode(await mounts.read(grant, 'file'));
    return { appended, stale, replacement, readOnly: grant.readOnly };
  });
  expect(result.appended).toBe('ABCD'); expect(['ESTALE', 'ENOENT', 'EIO']).toContain(result.stale);
  expect(result.replacement).toBe('replacement'); expect(result.readOnly).toBe(false);
});
