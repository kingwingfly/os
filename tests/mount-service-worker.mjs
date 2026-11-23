// Browser Worker primitives for running the packaged kernel and its actual WASI children in Node.
// Only release assets are available. An HTTP request from an offline mount fails the test.
import { Worker, parentPort, workerData } from 'node:worker_threads';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { runInThisContext, constants } from 'node:vm';

const root = new URL('../dist/', import.meta.url);
const asset = path => new URL(path.slice(1), root);
registerHooks({ resolve(specifier, context, next) {
  return next(specifier.startsWith('/') ? asset(specifier).href : specifier, context);
} });
globalThis.self = globalThis;
globalThis.crossOriginIsolated = true;
globalThis.location = new URL(workerData, 'http://os.test/');
globalThis.fetch = async input => {
  const path = new URL(input.url ?? input, location).pathname;
  if (path.startsWith('/api/')) throw Error('Unexpected network request ' + path);
  try {
    return new Response(readFileSync(asset(path)), { headers: { 'Content-Type': path.endsWith('.wasm') ? 'application/wasm' : 'application/octet-stream' } });
  } catch (error) { if (error.code !== 'ENOENT') throw error; return new Response(null, { status: 404 }); }
};
globalThis.postMessage = (data, transfer) => parentPort.postMessage(data, transfer);
globalThis.Worker = class {
  constructor(path) {
    this.worker = new Worker(new URL(import.meta.url), { workerData: new URL(path, location).pathname });
    this.worker.on('message', data => this.onmessage?.({ data }));
    this.worker.on('error', error => this.onerror?.(error));
  }
  postMessage(data, transfer) { this.worker.postMessage(data, transfer); }
  terminate() { return this.worker.terminate(); }
};
globalThis.importScripts = path => runInThisContext(readFileSync(asset(path), 'utf8'), {
  filename: path, importModuleDynamically: constants.USE_MAIN_CONTEXT_DEFAULT_LOADER,
});
globalThis.importScripts(workerData);
parentPort.on('message', async data => {
  if (data.type === 'test_page_fsync') {
    const { session, fd } = data.args;
    try {
      await globalThis.kernel.vfs_fsync_fd(session, fd, false);
      parentPort.postMessage({ id: data.id, ok: null });
    } catch (err) {
      parentPort.postMessage({ id: data.id, err: { errno: err.errno ?? 'EIO', detail: String(err) } });
    }
  } else globalThis.onmessage({ data });
});
