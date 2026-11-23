// A private OS instance using the same host-adapter protocol as a browser tab.
import { Worker } from 'node:worker_threads';
export function serviceHost() {
  const worker = new Worker(new URL('./mount-service-worker.mjs', import.meta.url), { workerData: '/client-kernel.js' });
  const pending = new Map();
  const output = new Map();
  let sequence = 0;
  function call(type, args = {}, transfer = []) {
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ v: 2, tab: 'offline-test', id, type, args }, transfer);
    });
  }
  worker.on('message', ({ id, ok, err, event, value }) => {
    if (event === 'run' && value.type === 'output') {
      const stream = output.get(value.run);
      if (stream) stream[value.fd === 1 ? 'stdout' : 'stderr'] += value.text;
      void call('run_output_ack', { run: value.run, sequence: value.sequence });
      return;
    }
    const request = pending.get(id);
    if (!request) return;
    pending.delete(id);
    if (err) request.reject(Object.assign(new Error(err.detail ?? err.errno), err));
    else request.resolve(ok);
  });
  worker.on('error', error => { for (const request of pending.values()) request.reject(error); pending.clear(); });
  async function exec(argv) {
    const run = crypto.randomUUID(), stream = { stdout: '', stderr: '' };
    output.set(run, stream);
    try {
      const result = await call('run', { run, stages: [{ path: '/usr/bin/' + argv[0], argv }], options: { cwd: '/', stdin: '' } });
      return { status: result.status, stdout: result.stdout || stream.stdout, stderr: stream.stderr };
    } finally { output.delete(run); }
  }
  return { call, exec, close: () => worker.terminate() };
}
