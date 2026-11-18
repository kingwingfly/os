import { test, expect } from './test.js';
import { sys, call } from './sys.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const fsRpc = async (request, credential, session, fsCall) =>
  (await request.post('/api/fs', { headers: { Origin: origin }, data: { version: 2, credential, session, call: fsCall } })).json();
const image = { path: '/mnt/local/project/probe', argv: ['probe'], cwd: '/', runtime: 'resources-v1', local: { digest: 'a'.repeat(64), size: 8, cloud: false } };
const proof = process => ({ pid: process.pid, proc: process.token });
const result = async (request, call, options = {}) => (await sys(request, [call], options))[0];
async function end(request, process) { if (process) await sys(request, [{ exit: { ...proof(process), status: 0 } }, { wait: { pid: String(process.pid), proc: process.token } }], {}, { 'X-Registry': '1' }); }

test('local admission grants process resources but no implicit cloud filesystem authority', async ({ request }) => {
  await call(request, 'getcreds'); let process;
  try {
    const admitted = await result(request, { execve: image }); expect(admitted.err).toBeUndefined(); process = admitted.ok;
    expect(process.local).toEqual(image.local); expect(process.asset).toBeUndefined(); expect(process.fd).toBeUndefined();
    const calls = await sys(request, ['getcreds', { stat: { path: '/usr/bin/coreutils' } }, { open: { path: '/usr/bin/coreutils', flags: 0 } }, { resource: { memory: 65536 } }], proof(process));
    expect(calls[0].ok.uid).not.toBe(0); expect(calls[1].err.errno).toBe('EACCES'); expect(calls[2].err.errno).toBe('EACCES'); expect(calls[3].err).toBeUndefined();
    const bytes = await request.get('/api/file?path=/usr/bin/coreutils', { headers: { 'X-Process-Token': process.token, 'X-Process-Pid': String(process.pid) } }); expect(bytes.ok()).toBe(false);
    const escalation = await result(request, { execve: { ...image, ...proof(process), local: { ...image.local, cloud: true } } });
    expect(escalation.err).toBeUndefined(); process = escalation.ok; expect(process.local.cloud).toBe(false);
    expect((await result(request, { stat: { path: '/usr/bin/coreutils' } }, proof(process))).err.errno).toBe('EACCES');
    expect((await result(request, { execve: { path: '/usr/bin/true', argv: ['true'], runtime: 'resources-v1', ...proof(process) } })).err.errno).toBe('EACCES');
  } finally { await end(request, process); }
});

test('local fork and replacement preserve attenuation, while an explicitly delegated launch keeps ordinary ACL checks', async ({ request }) => {
  await call(request, 'getcreds'); let parent, child, delegated;
  try {
    parent = (await result(request, { execve: image })).ok;
    child = { ...(await result(request, { fork: { pid: parent.pid } }, proof(parent))).ok, token: parent.token };
    expect((await result(request, { stat: { path: '/usr/bin/coreutils' } }, proof(child))).err.errno).toBe('EACCES');
    const replacement = await result(request, { execve: { ...image, ...proof(child), local: { ...image.local, cloud: true } } }); expect(replacement.err).toBeUndefined(); child = replacement.ok; expect(child.local.cloud).toBe(false);
    expect((await fsRpc(request, parent.token, null, 'connect')).errno).toBe('EACCES');
    delegated = (await result(request, { execve: { ...image, local: { ...image.local, cloud: true } } })).ok;
    // Ordinary processes resolve files via /api/fs v2 handles; direct /api/sys path calls are refused at the server boundary.
    expect((await result(request, { stat: { path: '/usr/bin/coreutils' } }, proof(delegated))).err.errno).toBe('EPERM');
    const conn = await fsRpc(request, delegated.token, null, 'connect');
    expect(conn.session).toBeTruthy();
    try {
      const passwdWalk = await fsRpc(request, delegated.token, conn.session, { walk: { dir: conn.root, names: ['etc', 'passwd'] } });
      expect(passwdWalk.stop).toBeNull();
      expect(passwdWalk.entries).toHaveLength(2);
      const shadowWalk = await fsRpc(request, delegated.token, conn.session, { walk: { dir: conn.root, names: ['etc', 'shadow'] } });
      if (shadowWalk.entries?.length === 2 && !shadowWalk.stop) {
        const shadowOpen = await fsRpc(request, delegated.token, conn.session, { open: { ticket: 'shadow-acl-check', handle: shadowWalk.entries[1].handle, options: { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false } } });
        expect(['EACCES', 'ENOENT']).toContain(shadowOpen.errno);
      } else {
        expect(shadowWalk.stop).toBeTruthy();
      }
    } finally {
      await fsRpc(request, delegated.token, conn.session, 'disconnect');
    }
  } finally { await end(request, child); await end(request, parent); await end(request, delegated); }
});

test('invalid local descriptors and uninstrumented claims are rejected before admission', async ({ request }) => {
  await call(request, 'getcreds');
  for (const changed of [{ runtime: null }, { local: { ...image.local, size: 0 } }, { local: { ...image.local, size: 128 * 1024 * 1024 + 1 } }, { local: { ...image.local, digest: 'Z'.repeat(64) } }]) {
    expect((await result(request, { execve: { ...image, ...changed } })).err).toBeTruthy();
  }
});
