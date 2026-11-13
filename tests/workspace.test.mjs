import test from 'node:test';
import { evaluatePolicy } from './mount-policy-engine.mjs';
import assert from 'node:assert/strict';
import { Workspace, localPath, localFdPath, LOCAL_FD } from '../web/kernel/workspace.js';
import { currentWorkspace, mountRequest, endWorkspace } from '../web/kernel/workspaces.js';
const file = (name, text) => new File([text], name, { lastModified: 1700000000123 });
const cloud = async calls => calls.map(() => ({ err: { errno: 'ENOENT' } }));
const create = async () => {
  const space = new Workspace({ id: 'test-session', uid: 12 }, { evaluate: evaluatePolicy });
  await space.mount({ name: 'project', files: [file('text', 'abc')], execute: false, cloud: false });
  return space;
};
test('browser host mounts retain handles without reading a tree at admission', async () => {
  const space = new Workspace({ id: 'host', uid: 12 }, { evaluate: evaluatePolicy });
  let content = 'first', reads = 0, lookups = 0, permission = 'granted';
  const fileHandle = { kind: 'file', name: 'note', async getFile() { reads++; return file('note', content); } };
  const handle = {
    kind: 'directory', name: 'project',
    async queryPermission() { return permission; },
    async resolve(child) { return child === handle ? [] : child === fileHandle ? ['note'] : null; },
    async *entries() { throw new Error('must not enumerate at mount'); },
    async getDirectoryHandle() { lookups++; throw new DOMException('file', 'TypeMismatchError'); },
    async getFileHandle() { lookups++; return fileHandle; },
  };
  const mount = await space.mount({ handle, execute: false, cloud: false });
  assert.equal(mount.kind, 'directory'); assert.equal(reads, 0); assert.equal(lookups, 0);
  const read = async () => {
    const fd = await space.open('/mnt/local/project/note', 0, space.page);
    try { return atob((await space.read(fd.fd, 0, 32, space.page)).data); }
    finally { await space.closeFd(fd.fd, space.page); }
  };
  assert.equal(await read(), 'first'); content = 'edited on host';
  assert.equal(await read(), 'edited on host'); permission = 'denied';
  await assert.rejects(read(), { errno: 'EACCES' }); space.close();
});
test('a folder selection cannot be attached to a different login', async () => {
  const previous = globalThis.kernelRequest;
  let id = 'picker-owner';
  try {
    globalThis.kernelRequest = async () => ({ id, uid: 12 });
    const login = await mountRequest('mount_identity');
    id = 'picker-other';
    await assert.rejects(mountRequest('mount_attach', { login, name: 'project', cloud: false, files: [file('note', 'private')] }), { errno: 'EACCES' });
    assert.deepEqual(await mountRequest('mount_list'), []);
  } finally { endWorkspace('picker-owner'); endWorkspace('picker-other'); globalThis.kernelRequest = previous; }
});
test('a new account joins its workspace but explicit shutdown is never revived', async () => {
  const previous = globalThis.kernelRequest;
  let joined = false, refreshes = 0, shutdown = false;
  try {
    globalThis.kernelRequest = async type => {
      if (type === 'login_refresh') { joined = true; refreshes++; return; }
      if (type === 'workspace_credentials') return { uid: 42 };
      assert.equal(type, 'login_lifecycle');
      return joined ? { id: 'new-account', uid: 42, shutdown } : null;
    };
    assert.equal((await currentWorkspace()).identity.uid, 42);
    assert.equal(refreshes, 1);
    shutdown = true;
    await assert.rejects(currentWorkspace(), { errno: 'EACCES' });
    assert.equal(refreshes, 1);
  } finally { endWorkspace('new-account'); globalThis.kernelRequest = previous; }
});
test('descriptors are private to their process lineage and revoked on unmount', async () => {
  const space = await create(), scope = space.scope(), foreign = space.scope();
  const fd = await space.open('/mnt/local/project/text', 0, scope);
  assert.equal(atob((await space.read(fd.fd, 0, 3, scope)).data), 'abc');
  await assert.rejects(space.read(fd.fd, 0, 3, foreign), { errno: 'EBADF' });
  space.unmount('/mnt/local/project');
  await assert.rejects(space.read(fd.fd, 0, 3, scope), { errno: 'EBADF' });
  await assert.rejects(space.stat('/mnt/local/project/text'), { errno: 'ENODEV' });
});
test('local paths cannot escape through dot segments or cross-provider rename', async () => {
  const space = await create();
  await assert.rejects(space.stat('/mnt/local/project/../../../etc/passwd'), { errno: 'EACCES' });
  const [result] = await space.calls([{ rename: { from: '/cloud', to: '/mnt/local/project/new' } }], space.page, () => assert.fail('cross-provider mutation reached cloud'));
  assert.equal(result.err.errno, 'EXDEV');
});
test('mixed local batches retain fd reference indices and never forward private fds', async () => {
  const space = await create();
  const answers = await space.calls([{ stat: { path: '/cloud' } }, { open: { path: '/mnt/local/project/text' } }, { pread: { fd: { ref: 1 }, count: 3 } }, { close: { fd: { ref: 1 } } }], space.page, cloud);
  assert.equal(answers[0].err.errno, 'ENOENT'); assert.equal(atob(answers[2].ok.data), 'abc'); assert.equal(space.fds.size, 0);
});
test('metadata describes granted virtual permissions and cannot claim root ownership', async () => {
  const space = await create(), stat = await space.stat('/mnt/local/project/text');
  assert.equal(stat.uid, 12); assert.equal(stat.mode & 0o7777, 0o400);
  assert.equal(stat.mtime, 1700000000); assert.equal(stat.mtime_nsec, 123000000);
  const [denied] = await space.calls([{ chmod: { path: '/mnt/local/project/text', mode: 0o4755 } }], space.page, cloud);
  assert.equal(denied.ok, null);
  const [chown] = await space.calls([{ chown: { path: '/mnt/local/project/text', uid: 0, gid: null, nofollow: false } }], space.page, cloud);
  assert.equal(chown.err.errno, 'EPERM');
  assert.equal((await space.stat('/mnt/local/project/text')).uid, 12);
  await assert.rejects(space.image('/mnt/local/project/text', '/'), { errno: 'EACCES' });
});

test('concurrent mount admission cannot exceed the workspace mount limit', async () => {
  const space = new Workspace({ id: 'bounded', uid: 12 });
  for (let i = 0; i < 15; i++) await space.mount({ name: 'm' + i, files: [file('text', 'abc')], execute: false, cloud: false });
  const results = await Promise.allSettled(['last', 'overflow'].map(name => space.mount({ name, files: [file('text', 'abc')], execute: false, cloud: false })));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  assert.equal(results.find(result => result.status === 'rejected').reason.errno, 'ENOSPC');
  assert.equal(space.list().length, 16); space.close();
});

test('an absent login can bypass only the root overlay and never retry dispatched filesystem calls', async () => {
  const previousKernel = globalThis.kernelRequest, previousFetch = globalThis.fetch;
  try {
    globalThis.kernelRequest = async () => { throw { errno: 'ENOENT' }; };
    assert.equal(await mountRequest('mount_overlay', { calls: [{ getdents: { path: '/' } }] }), null);
    await assert.rejects(mountRequest('mount_sys', { calls: [{ stat: { path: '/mnt/local/project/text' } }] }), { errno: 'ENOENT' });
    await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/mnt/local/project/text' } }] }), { errno: 'EACCES' });
    await assert.rejects(mountRequest('mount_overlay', { calls: [{ stat: { path: '/mnt/./local/project/text' } }] }), { errno: 'EACCES' });
    let calls = 0;
    globalThis.kernelRequest = async () => ({ id: 'overlay-test', uid: 12 });
    globalThis.fetch = async () => { calls++; throw new Error('lost response'); };
    const result = await mountRequest('mount_overlay', { calls: [{ stat: { path: '/' } }] });
    assert.equal(result[0].err.errno, 'EIO'); assert.equal(calls, 1);
  } finally { endWorkspace('overlay-test'); globalThis.kernelRequest = previousKernel; globalThis.fetch = previousFetch; }
});

test('normalized private path aliases and descriptor paths cannot fall through to cloud', () => {
  assert.equal(localPath('/mnt/./local/project/text'), true);
  assert.equal(localPath('/opt/scratch/../private/dev/text'), true);
  assert.equal(localPath('/mnt/local/project/../../../etc/passwd'), true);
  assert.equal(localPath('/usr/bin/ls'), false);
  assert.equal(localFdPath('/proc/self/./fd/' + LOCAL_FD), true);
  assert.equal(localFdPath('/proc/self/fd/3'), false);
});

test('shutdown revokes private descriptors but permits credential-checked process cleanup', async () => {
  const space = await create(), scope = space.scope();
  const opened = await space.open('/mnt/local/project/text', 0, scope); space.close();
  const forwarded = [];
  const results = await space.calls([{ stat: { path: '/' } }, { stat: { path: '/mnt/local/project/text' } }, { pread: { fd: opened.fd, count: 3 } }, 'getcreds'], scope, async calls => {
    forwarded.push(...calls); return calls.map(() => ({ ok: 'authorized by server' }));
  }, { allowClosedCloud: true });
  assert.deepEqual(forwarded, [{ stat: { path: '/' } }, 'getcreds']);
  assert.equal(results[1].err.errno, 'ENODEV'); assert.equal(results[2].err.errno, 'ENODEV');
  await assert.rejects(space.calls([{ stat: { path: '/' } }], scope, cloud), { errno: 'ENODEV' });
});
