import test from 'node:test';
import assert from 'node:assert/strict';
import { LocalMounts, localImage } from '../web/kernel/local-mounts.js';

const errno = code => reason => reason.errno === code;
const text = bytes => new TextDecoder().decode(bytes);
const selected = (content, name) => new File([content], name, { lastModified: 1234 });
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

// Fault injection only. Browser conformance uses real OPFS directory/file handles.
function directory(name = 'project') {
  const children = new Map();
  const dir = {
    name, kind: 'directory', permission: 'granted', children,
    async queryPermission() { return dir.permission; },
    async resolve(handle) {
      if (handle === dir) return [];
      for (const [name, child] of children) {
        if (child === handle) return [name];
        if (child.kind === 'directory') { const tail = await child.resolve(handle); if (tail) return [name, ...tail]; }
      }
      return null;
    },
    async getDirectoryHandle(name) { return find(name, 'directory'); },
    async getFileHandle(name) { return find(name, 'file'); },
    async *entries() { yield* children; },
    put(name, contents) {
      const handle = { name, kind: 'file', async getFile() { return handle.file; }, file: selected(contents, name) };
      children.set(name, handle); return handle;
    },
  };
  function find(name, kind) {
    const handle = children.get(name);
    if (!handle) throw new DOMException('not found', 'NotFoundError');
    if (handle.kind !== kind) throw new DOMException('wrong kind', 'TypeMismatchError');
    return handle;
  }
  return dir;
}

test('selected files are private read-only snapshots with explicit execution permission', async () => {
  const mounts = new LocalMounts(), other = new LocalMounts();
  const grant = await mounts.mountFiles([selected('first', 'hello.wasm')]);
  assert.equal(grant.kind, 'snapshot'); assert.equal(grant.readOnly, true);
  assert.equal(text(await mounts.read(grant, 'hello.wasm', 1, 3)), 'irs');
  assert.equal((await mounts.read(grant, 'hello.wasm', 100)).length, 0);
  assert.deepEqual(await mounts.stat(grant, 'hello.wasm'), { kind: 'file', name: 'hello.wasm', readOnly: true, size: 5, lastModified: 1234, executable: false });
  await assert.rejects(mounts.pin(grant, 'hello.wasm'), errno('EACCES'));
  assert.equal(text(await mounts.read(grant, 'hello.wasm')), 'first');
  await assert.rejects(other.read(grant, 'hello.wasm'), errno('EACCES'));
  await assert.rejects(mounts.read({ ...grant }, 'hello.wasm'), errno('EACCES'));
  assert.throws(() => { grant.execute = true; }, TypeError);
  mounts.close();
  await assert.rejects(mounts.read(grant, 'hello.wasm'), errno('ENODEV'));
});

test('snapshots retain selected bytes even if the supplied file later becomes unreadable', async () => {
  const mounts = new LocalMounts(), file = selected('pinned', 'file');
  const grant = await mounts.mountFiles([file]);
  file.arrayBuffer = () => { throw new DOMException('changed', 'NotReadableError'); };
  assert.equal(text(await mounts.read(grant, 'file')), 'pinned');
});

test('directory reads see host changes, executable pins retain their original bytes', async () => {
  const mounts = new LocalMounts(), root = directory(), handle = root.put('prog', 'one');
  const grant = await mounts.mountDirectory(root, { execute: true });
  const first = await mounts.pin(grant, 'prog');
  handle.file = selected('two', 'prog');
  const second = await mounts.pin(grant, 'prog');
  assert.equal(text(await mounts.read(grant, 'prog')), 'two');
  assert.equal(text((await localImage(first)).bytes), 'one');
  assert.equal(text((await localImage(second)).bytes), 'two');
  assert.notEqual(first.digest, second.digest);
  const copy = await localImage(first); copy.bytes.fill(0);
  assert.equal(text((await localImage(first)).bytes), 'one');
  await assert.rejects(localImage({ ...first }), errno('EACCES'));
  mounts.unmount(grant);
  await assert.rejects(localImage(first), errno('ENODEV'));
});

test('relative paths cannot escape, and percent-encoded names remain literal', async () => {
  const mounts = new LocalMounts();
  const grant = await mounts.mountFiles([selected('literal', '%2e%2e'), selected('unicode', 'λ #?.txt')]);
  for (const path of ['../secret', '/etc/passwd', 'child/../../secret', 'child/../secret']) {
    await assert.rejects(mounts.read(grant, path), errno('EACCES'), path);
  }
  for (const path of ['bad\0name', 'child\\secret']) await assert.rejects(mounts.read(grant, path), errno('EINVAL'));
  assert.equal(text(await mounts.read(grant, './%2e%2e')), 'literal');
  assert.equal(text(await mounts.read(grant, 'λ #?.txt')), 'unicode');
  for (const path of ['%2e%2e/', '%2e%2e/.', '%2e%2e/child']) await assert.rejects(mounts.stat(grant, path), errno('ENOTDIR'));
});

test('selected directory hierarchy lists immediate children with bounded pages', async () => {
  const mounts = new LocalMounts();
  const files = ['a/one', 'a/two', 'b/nested/three', 'top'].map(name => selected(name, name));
  const grant = await mounts.mountFiles(files);
  assert.deepEqual(await mounts.list(grant, '', { limit: 2 }), { entries: [{ name: 'a', kind: 'directory' }, { name: 'b', kind: 'directory' }], next: 2 });
  assert.deepEqual(await mounts.list(grant, '', { offset: 2, limit: 2 }), { entries: [{ name: 'top', kind: 'file' }], next: null });
  assert.deepEqual((await mounts.list(grant, 'a/')).entries.map(entry => entry.name), ['one', 'two']);
  await assert.rejects(mounts.read(grant, 'a'), errno('EISDIR'));
  await assert.rejects(mounts.list(grant, 'top'), errno('ENOTDIR'));
  await assert.rejects(mounts.stat(grant, 'missing'), errno('ENOENT'));
});

test('duplicate selected paths, file-directory collisions and invalid selections fail atomically', async () => {
  const mounts = new LocalMounts();
  for (const names of [['a', 'a'], ['a', 'a/file'], ['a/file', 'a'], ['', 'b'], ['../outside']]) {
    await assert.rejects(mounts.mountFiles(names.map(name => selected('', name))));
  }
  await assert.rejects(mounts.mountFiles([]), errno('EINVAL'));
  await assert.rejects(mounts.mountFiles(Array(1025).fill(selected('', 'a'))), errno('EINVAL'));
  const large = selected('', 'large'); Object.defineProperty(large, 'size', { value: 128 * 1024 * 1024 + 1 });
  await assert.rejects(mounts.mountFiles([large]), errno('EFBIG'));
  // Failed attachments release their slots.
  for (let i = 0; i < 16; i++) await mounts.mountFiles([selected('', 'ok')]);
  await assert.rejects(mounts.mountFiles([selected('', 'full')]), errno('ENOSPC'));
  mounts.close(); await mounts.mountFiles([selected('', 'again')]);
});

test('bad read ranges and directory page limits fail before reading', async () => {
  const mounts = new LocalMounts(), grant = await mounts.mountFiles([selected('', 'file')]);
  for (const [offset, length] of [[-1, 1], [0, -1], [0, 1024 * 1024 + 1], [0.5, 1], [Number.MAX_SAFE_INTEGER, 1]]) {
    await assert.rejects(mounts.read(grant, 'file', offset, length), errno('EINVAL'));
  }
  for (const options of [{ offset: -1 }, { offset: 100001 }, { limit: 0 }, { limit: 257 }]) await assert.rejects(mounts.list(grant, '', options), errno('EINVAL'));
});

test('permission loss invalidates the mount and all old executable pins without prompting', async () => {
  const mounts = new LocalMounts(), root = directory(); root.put('file', 'contents');
  root.requestPermission = () => assert.fail('background operations cannot request permission');
  const grant = await mounts.mountDirectory(root, { execute: true }), pin = await mounts.pin(grant, 'file');
  root.permission = 'prompt';
  await assert.rejects(localImage(pin), errno('EACCES'));
  root.permission = 'granted';
  await assert.rejects(mounts.read(grant, 'file'), errno('ENODEV'));
  await assert.rejects(localImage(pin), errno('ENODEV'));
});

test('denied and unsupported directory permissions never produce a live grant', async () => {
  const mounts = new LocalMounts(), root = directory(); root.permission = 'denied';
  await assert.rejects(mounts.mountDirectory(root), errno('EACCES'));
  delete root.queryPermission;
  await assert.rejects(mounts.mountDirectory(root), errno('ENOTSUP'));
  await assert.rejects(mounts.mountDirectory({ kind: 'directory' }), errno('EINVAL'));
});

test('labelling a host directory as browser storage does not bypass permission checks', async () => {
  const mounts = new LocalMounts(), root = directory(), foreign = directory('foreign');
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { storage: { getDirectory: async () => root } } });
  try {
    await assert.rejects(mounts.mountDirectory(foreign, { originPrivate: true }), errno('EACCES'));
  } finally {
    if (previous) Object.defineProperty(globalThis, 'navigator', previous); else delete globalThis.navigator;
  }
});

test('closing the provider during directory permission checks cannot resurrect a mount', async () => {
  const mounts = new LocalMounts(), root = directory(), started = deferred(), finish = deferred();
  root.queryPermission = async () => { started.resolve(); await finish.promise; return 'granted'; };
  const pending = mounts.mountDirectory(root);
  await started.promise; mounts.close(); finish.resolve();
  await assert.rejects(pending, errno('ENODEV'));
});

test('an entry moved outside the root is refused even if an old handle remains', async () => {
  const mounts = new LocalMounts(), root = directory(); root.put('file', 'secret');
  const grant = await mounts.mountDirectory(root);
  root.resolve = async handle => handle === root ? [] : null;
  await assert.rejects(mounts.read(grant, 'file'), errno('EACCES'));
});

test('moving a file out while getFile is pending cannot expose bytes or executable pins', async () => {
  for (const operation of ['read', 'pin', 'stat']) {
    const mounts = new LocalMounts(), root = directory(), handle = root.put('file', 'secret');
    const grant = await mounts.mountDirectory(root, { execute: true });
    handle.getFile = async () => { root.children.delete('file'); return handle.file; };
    await assert.rejects(mounts[operation](grant, 'file'), errno('EACCES'));
  }
});

test('unmount wins an in-flight read and pin, including pins being hashed', async () => {
  for (const operation of ['read', 'pin']) {
    const mounts = new LocalMounts(), root = directory(), file = root.put('file', 'secret').file;
    const started = deferred(), finish = deferred();
    const delayed = async () => { started.resolve(); await finish.promise; return new TextEncoder().encode('secret').buffer; };
    file.arrayBuffer = delayed; file.slice = () => ({ arrayBuffer: delayed });
    const grant = await mounts.mountDirectory(root, { execute: true });
    const pending = mounts[operation](grant, 'file');
    await started.promise; mounts.unmount(grant); finish.resolve();
    await assert.rejects(pending, errno('ENODEV'));
  }
});

test('directory disappearance and changed/unreadable files fail without a network fallback', async () => {
  const mounts = new LocalMounts(), root = directory(), handle = root.put('file', 'before');
  const grant = await mounts.mountDirectory(root, { execute: true });
  handle.getFile = async () => { throw new DOMException('device unavailable', 'NotReadableError'); };
  await assert.rejects(mounts.pin(grant, 'file'), errno('EIO'));
  root.children.delete('file');
  await assert.rejects(mounts.read(grant, 'file'), errno('ENOENT'));
});
