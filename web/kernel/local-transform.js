import { asset } from '../release.js';

// A bound on concurrent compiler memory, including its embedded Binaryen runtime. A new
// launch can retry EAGAIN; identical images already share the loader's pending promise.
let busy = false;
export function transformLocal(bytes) {
  if (busy) return Promise.reject(Object.assign(new Error('local compiler is busy'), { errno: 'EAGAIN' }));
  if (typeof Worker !== 'function') return Promise.reject(Object.assign(new Error('local compilation requires a Worker'), { errno: 'ENOTSUP' }));
  busy = true;
  return new Promise((resolve, reject) => {
    let worker, timer, settled = false;
    const done = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer); worker?.terminate(); busy = false;
      if (error) reject(error); else resolve(result);
    };
    try {
      worker = new Worker(asset('/local-compiler.js'), { type: 'module', name: 'os-local-compiler' });
      timer = setTimeout(() => done(Object.assign(new Error('local compilation timed out'), { errno: 'ETIMEDOUT' })), 60_000);
      worker.onerror = event => {
        event.preventDefault();
        done(Object.assign(new Error('local compiler unavailable: ' + event.message), { errno: 'EIO' }));
      };
      worker.onmessageerror = () => done(Object.assign(new Error('invalid local compiler response'), { errno: 'EIO' }));
      worker.onmessage = ({ data }) => {
        if (data?.bytes instanceof Uint8Array) done(null, data.bytes);
        else done(Object.assign(new Error(data?.error ?? 'invalid local compiler response'), { errno: 'ENOEXEC' }));
      };
      // The loader owns this copy; the provider's pinned snapshot is never detached.
      worker.postMessage(bytes, [bytes.buffer]);
    } catch (error) { done(Object.assign(new Error('local compiler unavailable: ' + error.message), { errno: 'EIO' })); }
  });
}
