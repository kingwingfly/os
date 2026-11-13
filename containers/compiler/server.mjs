// Compilation only: uploaded modules are parsed and transformed, never instantiated.
import http from 'node:http';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { IMAGE_MAX as LIMIT, transformImage } from '../../web/kernel/transform.js';

if (!isMainThread) {
  try {
    const binaryen = (await import('binaryen')).default;
    const { bytes: input, profile } = workerData;
    const bytes = await transformImage(binaryen, input, profile);
    parentPort.postMessage({ bytes }, [bytes.buffer]);
  } catch (error) { parentPort.postMessage({ error: String(error?.message ?? error) }); }
} else {
  // Node is PID 1 in the container. Handle termination explicitly so destroying a
  // finished per-image compiler does not wait for the runtime's forced-kill timeout.
  process.once('SIGTERM', () => process.exit(0));
  let busy = false;
  const server = http.createServer(async (req, res) => {
    if (req.method === 'GET' && req.url === '/status') { res.end('ready'); return; }
    if (req.method !== 'POST' || !['/compile', '/compile?profile=resources-v1'].includes(req.url)) { res.writeHead(404).end(); return; }
    const profile = req.url.includes('?') ? 'resources-v1' : 'fork-v4';
    if (busy) { res.writeHead(503).end(); return; }
    busy = true;
    let compiler;
    const deadline = setTimeout(() => { compiler?.terminate(); res.destroy(); }, 60_000);
    let releasing;
    // A completed response must release its worker slot before the next request.
    // Otherwise sequential clients can race teardown and receive a spurious 503.
    const release = () => releasing ??= (async () => {
      clearTimeout(deadline); await compiler?.terminate(); busy = false;
    })();
    try {
      const chunks = []; let length = 0;
      for await (const chunk of req) {
        length += chunk.length;
        if (length > LIMIT) { await release(); res.writeHead(413).end(); return; }
        chunks.push(chunk);
      }
      const bytes = new Uint8Array(Buffer.concat(chunks));
      const answer = await new Promise((resolve, reject) => {
        compiler = new Worker(new URL(import.meta.url), { workerData: { bytes, profile }, transferList: [bytes.buffer], resourceLimits: { maxOldGenerationSizeMb: 512 } });
        compiler.once('message', resolve); compiler.once('error', reject);
        compiler.once('exit', code => { if (code !== 0) reject(new Error('compiler stopped')); });
      });
      await release();
      if (answer.error) { res.writeHead(422, { 'Content-Type': 'application/json' }).end(JSON.stringify({ errno: 'ENOEXEC', error: answer.error })); return; }
      res.writeHead(200, { 'Content-Type': 'application/wasm', 'Content-Length': answer.bytes.byteLength }).end(answer.bytes);
    } catch (error) { await release(); if (!res.headersSent) res.writeHead(422).end(JSON.stringify({ errno: 'ENOEXEC', error: String(error.message) })); }
    finally { await release(); }
  });
  server.requestTimeout = 65_000;
  server.listen(Number(process.env.PORT || 8080), '0.0.0.0', () => process.send?.({ port: server.address().port }));
}
