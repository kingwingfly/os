// Compilation only: uploaded modules are parsed and transformed, never instantiated.
import http from 'node:http';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';

const LIMIT = 128 * 1024 * 1024;
if (!isMainThread) {
  try {
    const binaryen = (await import('binaryen')).default;
    const { asyncify } = await import('../../web/kernel/asyncify.js');
    const original = await WebAssembly.compile(workerData);
    const imports = WebAssembly.Module.imports(original);
    for (const entry of imports) {
      if (entry.kind === 'function' && ['wasi_snapshot_preview1', 'os', 'terminal', 'wasix_32v1'].includes(entry.module)) continue;
      if (entry.kind === 'memory' && entry.module === 'env' && entry.name === 'memory') continue;
      throw new Error(`unsupported import ${entry.module}.${entry.name}`);
    }
    const unwinds = imports.filter(entry => entry.module === 'wasix_32v1' && ['proc_fork', 'stack_checkpoint', 'stack_restore'].includes(entry.name)).map(entry => `${entry.module}.${entry.name}`);
    const built = WebAssembly.Module.exports(original).some(entry => entry.name === 'asyncify_start_unwind');
    const bytes = asyncify(binaryen, workerData, unwinds, !built);
    if (bytes.byteLength > LIMIT) throw new Error('transformed image exceeds 128 MiB');
    await WebAssembly.compile(bytes);
    parentPort.postMessage({ bytes }, [bytes.buffer]);
  } catch (error) { parentPort.postMessage({ error: String(error?.message ?? error) }); }
} else {
  // Node is PID 1 in the container. Handle termination explicitly so destroying a
  // finished per-image compiler does not wait for the runtime's forced-kill timeout.
  process.once('SIGTERM', () => process.exit(0));
  let busy = false;
  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/status') { res.end('ready'); return; }
    if (req.method !== 'POST' || req.url !== '/compile') { res.writeHead(404).end(); return; }
    if (busy) { res.writeHead(503).end(); return; }
    busy = true;
    let compiler;
    const deadline = setTimeout(() => { compiler?.terminate(); res.destroy(); }, 60_000);
    try {
      const chunks = []; let length = 0;
      for await (const chunk of req) {
        length += chunk.length;
        if (length > LIMIT) { res.writeHead(413).end(); return; }
        chunks.push(chunk);
      }
      const bytes = new Uint8Array(Buffer.concat(chunks));
      const answer = await new Promise((resolve, reject) => {
        compiler = new Worker(new URL(import.meta.url), { workerData: bytes, transferList: [bytes.buffer], resourceLimits: { maxOldGenerationSizeMb: 512 } });
        compiler.once('message', resolve); compiler.once('error', reject);
        compiler.once('exit', code => { if (code !== 0) reject(new Error('compiler stopped')); });
      });
      if (answer.error) { res.writeHead(422, { 'Content-Type': 'application/json' }).end(JSON.stringify({ errno: 'ENOEXEC', error: answer.error })); return; }
      res.writeHead(200, { 'Content-Type': 'application/wasm', 'Content-Length': answer.bytes.byteLength }).end(answer.bytes);
    } catch (error) { if (!res.headersSent) res.writeHead(422).end(JSON.stringify({ errno: 'ENOEXEC', error: String(error.message) })); }
    finally { clearTimeout(deadline); await compiler?.terminate(); busy = false; }
  });
  server.requestTimeout = 65_000;
  server.listen(Number(process.env.PORT || 8080), '0.0.0.0', () => process.send?.({ port: server.address().port }));
}
