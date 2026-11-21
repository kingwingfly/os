import { test, expect, request as playwrightRequest } from './test.js';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { api, program, put, rmrf } from './sys.js';
import { attachInstance, connectKernel, FULL_SCOPE } from './service-auth.js';
const origin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
let sequence = 0;
const address = name => `sys-${name}-${Date.now()}-${++sequence}`;

// A process of user space: its session, and the calls it makes, a batch a request.
async function session(username, password) {
  const context = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address(username || 'guest') } });
  if (username) expect((await api(context, 'login', { data: { username, password } })).ok()).toBe(true);
  // A batch, as a page sends it, or with extra headers (e.g. X-OS-Instance).
  const batch = async (calls, options = {}, extraHeaders = {}) => {
    const headers = typeof extraHeaders === 'boolean' ? (extraHeaders ? { 'X-Registry': '1' } : {}) : extraHeaders;
    const response = await context.post('/api/sys', { data: { calls, ...options }, headers });
    expect(response.status()).toBe(200);
    return (await response.json()).results;
  };
  // One call: its value, or its errno.
  const sys = async (call, options, extraHeaders) => { const [result] = await batch([call], options, extraHeaders); return 'ok' in result ? result.ok : result.err.errno; };
  return { context, batch, sys };
}

let root, ann, base;
const name = 'sysann' + Date.now().toString(36), password = 'sys-password-' + Date.now();
test.beforeAll(async () => {
  root = await session('root', rootPassword);
  expect((await program(root.context, ['useradd', '-m', name])).ok()).toBe(true);
  expect((await api(root.context, 'passwd', { data: { username: name, password } })).ok()).toBe(true);
  ann = await session(name, password);
  base = '/sys-' + Date.now().toString(36);
});
test.afterAll(async () => {
  await rmrf(root.context, base);
  await program(root.context, ['userdel', '-r', name]);
  for (const { context } of [root, ann]) await context.dispose();
});

test('names: each call alone, answered with its value or its errno, as Linux would', async () => {
  const results = await root.batch([
    { mkdir: { path: base, mode: 0o777 } },
    { mkdir: { path: base, mode: 0o777 } },
    { mknod: { path: base + '/file', mode: 0o666 } },
    { stat: { path: base + '/file' } },
    { rmdir: { path: base + '/missing' } },
    { symlink: { target: 'file', path: base + '/link' } },
    { readlink: { path: base + '/link' } },
    { getdents: { path: base } },
  ], { umask: 0o027 });
  expect(results[0]).toEqual({ ok: null });
  // A batch is not a transaction: the second mkdir fails, the rest go on.
  expect(results[1]).toEqual({ err: { errno: 'EEXIST' } });
  const stat = results[3].ok;
  expect([stat.mode, stat.user, stat.size, stat.nlink]).toEqual([0o100640, 'root', 0, 1]);
  expect(stat.mtime).toBeGreaterThan(0);
  expect(results[4]).toEqual({ err: { errno: 'ENOENT' } });
  expect(results[6]).toEqual({ ok: 'file' });
  expect(results[7].ok.map(entry => entry.name).sort()).toEqual(['file', 'link']);
  // The directory is 0750 after the umask 027: others may not look inside.
  expect((await root.sys({ stat: { path: base } })).mode).toBe(0o40750);
  expect(await ann.sys({ getdents: { path: base } })).toBe('EACCES');
  expect(await ann.sys({ stat: { path: base + '/file' } })).toBe('EACCES');
  expect(await root.sys({ chmod: { path: base, mode: 0o1777 } })).toBe(null);
  // Sticky: ann makes her own, and may not take root's away; links followed, `..` physical.
  expect(await ann.sys({ mknod: { path: base + '/hers', mode: 0o644 } })).toBe(null);
  expect((await ann.sys({ stat: { path: base + '/hers' } })).user).toBe(name);
  expect(await ann.sys({ unlink: { path: base + '/file' } })).toBe('EPERM');
  expect(await ann.sys({ rename: { from: base + '/hers', to: base + '/file' } })).toBe('EPERM');
  expect((await ann.sys({ stat: { path: base + '/link/../hers' } }))).toBe('ENOTDIR');
  expect(await root.sys({ rmdir: { path: base } })).toBe('ENOTEMPTY');
  expect(await root.sys({ unlink: { path: base } })).toBe('EISDIR');
  expect(await root.sys({ mkdir: { path: 'relative', mode: 0o777 } })).toBe('EINVAL');
});

test('ACLs are extended attributes, set by the owner, that decide as setfacl\'s do', async () => {
  const dir = base + '-acl';
  expect(await root.sys({ mkdir: { path: dir, mode: 0o755 } })).toBe(null);
  expect(await root.sys({ mknod: { path: dir + '/secret', mode: 0o600 } })).toBe(null);
  expect(await ann.sys({ access: { path: dir + '/secret', mode: 4 } })).toBe('EACCES');
  // No ACL yet beyond its mode.
  expect(await root.sys({ getxattr: { path: dir + '/secret', name: 'system.posix_acl_access' } })).toBe('ENODATA');
  const creds = await ann.sys('getcreds');
  expect([creds.user, creds.signed_in, creds.uid]).toEqual([name, true, creds.uid]);
  const entries = { user: 6, group: 0, other: 0, mask: 4, users: { [creds.uid]: 4 }, groups: {} };
  const value = Buffer.from(JSON.stringify(entries)).toString('base64');
  expect(await ann.sys({ setxattr: { path: dir + '/secret', name: 'system.posix_acl_access', value } })).toBe('EPERM');
  expect(await root.sys({ setxattr: { path: dir + '/secret', name: 'system.posix_acl_access', value } })).toBe(null);
  expect(await ann.sys({ access: { path: dir + '/secret', mode: 4 } })).toBe(null);
  expect(await ann.sys({ access: { path: dir + '/secret', mode: 2 } })).toBe('EACCES');
  const stat = await ann.sys({ stat: { path: dir + '/secret' } });
  expect([stat.acl, stat.mode]).toEqual([true, 0o100640]);
  expect(await ann.sys({ listxattr: { path: dir + '/secret' } })).toEqual(['system.posix_acl_access']);
  const read = JSON.parse(Buffer.from(await ann.sys({ getxattr: { path: dir + '/secret', name: 'system.posix_acl_access' } }), 'base64').toString());
  expect(read.users[creds.uid]).toBe(4);
  // user.* on what may be written; trusted.* root's, unseen by others.
  expect(await ann.sys({ setxattr: { path: dir + '/secret', name: 'user.note', value: 'aGk=' } })).toBe('EACCES');
  expect(await root.sys({ setxattr: { path: dir + '/secret', name: 'trusted.mark', value: 'MQ==' } })).toBe(null);
  expect(await ann.sys({ getxattr: { path: dir + '/secret', name: 'trusted.mark' } })).toBe('ENODATA');
  await root.batch([{ removexattr: { path: dir + '/secret', name: 'system.posix_acl_access' } }]);
  expect(await ann.sys({ access: { path: dir + '/secret', mode: 4 } })).toBe('EACCES');
  await root.batch([{ unlink: { path: dir + '/secret' } }, { rmdir: { path: dir } }]);
});

test('a guest is guest-<uuid>:guest; sudo runs a batch as root only once its account has authenticated', async () => {
  const guest = await session();
  const creds = await guest.sys('getcreds');
  expect(creds.user).toMatch(/^guest-[0-9a-f]{16}$/);
  expect(creds.uid).toBeGreaterThanOrEqual(1_000_000);
  expect([creds.signed_in, creds.can_sudo, creds.home]).toEqual([false, false, '/guest']);
  expect(await guest.sys({ mkdir: { path: '/nope-' + Date.now(), mode: 0o777 } })).toBe('EACCES');
  // ann is no wheel member: sudo is refused, whatever the call.
  const refused = await ann.batch([{ stat: { path: '/' } }], { sudo: true });
  expect(refused[0].err.errno).toBe('EPERM');
  // Root's own session is root already.
  expect((await root.sys('getcreds', { sudo: true })).uid).toBe(0);
  await guest.context.dispose();
});

test('descriptors are their session\'s, a browser signed out its own; a clone shares content; a stale version is refused', async () => {
  const O_WRONLY = 0o1, O_CREAT = 0o100, O_EXCL = 0o200, O_TRUNC = 0o1000, FICLONE = 0x40049409;
  const dir = base + '/fds';
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }, { mkdir: { path: dir, mode: 0o777 } }, { chmod: { path: dir, mode: 0o1777 } }]);
  const write = (session, path, text) => async () => {
    const opened = await session.sys({ open: { path, flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o644, size: text.length } });
    expect((await session.context.put(`/api/pwrite?fd=${opened.fd}&index=0`, { data: text })).ok()).toBe(true);
    return session.sys({ close: { fd: opened.fd } });
  };
  // Two browsers signed out, each a session of its own by the cookie it is given: each has its
  // own descriptor 3, and neither writes through the other's.
  const one = await session(), two = await session();
  try {
    const first = await one.sys({ open: { path: dir + '/one.txt', flags: O_WRONLY | O_CREAT, mode: 0o644, size: 3 } });
    const second = await two.sys({ open: { path: dir + '/two.txt', flags: O_WRONLY | O_CREAT, mode: 0o644, size: 3 } });
    expect([first.fd, second.fd]).toEqual([3, 3]);
    // /proc/self/fd lists the session's own, each a link to what it has open.
    const links = await two.sys({ getdents: { path: '/proc/self/fd' } });
    expect(links.map(link => [link.name, link.stat.link, link.stat.mode])).toEqual([['3', dir + '/two.txt', 0o120700]]);
    expect((await two.context.put(`/api/pwrite?fd=3&index=0`, { data: 'two' })).ok()).toBe(true);
    expect((await one.context.put(`/api/pwrite?fd=3&index=0`, { data: 'one' })).ok()).toBe(true);
    expect((await one.sys({ close: { fd: 3 } })).path).toBe(dir + '/one.txt');
    expect(await one.sys({ close: { fd: 3 } })).toBe('EBADF');
    expect((await two.sys({ close: { fd: 3 } })).created).toBe(true);
    expect(await (await root.context.get('/api/file?path=' + encodeURIComponent(dir + '/one.txt'))).text()).toBe('one');
    expect(await (await root.context.get('/api/file?path=' + encodeURIComponent(dir + '/two.txt'))).text()).toBe('two');
  } finally { await one.context.dispose(); await two.context.dispose(); }
  // A clone takes the content it reads, shared: the same version, nothing copied.
  expect((await write(ann, dir + '/a.txt', 'alpha')()).size).toBe(5);
  const [reading, writing] = await ann.batch([
    { open: { path: dir + '/a.txt', flags: 0 } },
    { open: { path: dir + '/b.txt', flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o600, size: 5 } },
  ]);
  const cloned = await ann.batch([
    { ioctl: { fd: writing.ok.fd, request: FICLONE, arg: reading.ok.fd } },
    { close: { fd: writing.ok.fd } }, { close: { fd: reading.ok.fd } },
  ]);
  expect(cloned.map(r => 'ok' in r)).toEqual([true, true, true]);
  expect(cloned[1].ok.version).toBe(cloned[2].ok.version);
  expect(await (await ann.context.get('/api/file?path=' + encodeURIComponent(dir + '/b.txt'))).text()).toBe('alpha');
  // Replacing what is not the version given, or reading what may not be read, is refused.
  expect(await ann.sys({ open: { path: dir + '/a.txt', flags: O_WRONLY | O_TRUNC, size: 1, version: '"old"' } })).toBe('ESTALE');
  expect(await root.sys({ open: { path: dir + '/b.txt', flags: 0 } })).toEqual(expect.objectContaining({ size: 5 }));
  const guest = await session();
  try { expect(await guest.sys({ open: { path: dir + '/b.txt', flags: 0 } })).toBe('EACCES'); }
  finally { await guest.context.dispose(); }
  // Unknown requests are not ioctls of a file.
  const [held] = await ann.batch([{ open: { path: dir + '/a.txt', flags: 0 } }]);
  expect(await ann.sys({ ioctl: { fd: held.ok.fd, request: 1 } })).toBe('ENOTTY');
  expect((await ann.sys({ close: { fd: held.ok.fd } })).path).toBe(dir + '/a.txt');
});

test('fchmod changes the file a descriptor has open; discard lets go of what it was writing', async () => {
  const O_WRONLY = 0o1, O_CREAT = 0o100, O_EXCL = 0o200, O_TRUNC = 0o1000;
  const dir = base + '/fchmod';
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }, { mkdir: { path: dir, mode: 0o777 } }, { chmod: { path: dir, mode: 0o1777 } }]);
  // A new file's mode, past the umask, through the descriptor its open made, in one batch.
  const made = await ann.batch([
    { open: { path: `${dir}/new`, flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o644, size: 1 } },
    { fchmod: { fd: { ref: 0 }, mode: 0o4775 } },
  ]);
  expect(made[1], JSON.stringify(made)).toEqual({ ok: null });
  expect((await ann.sys({ lstat: { path: `${dir}/new` } })).mode & 0o7777).toBe(0o4775);
  // An open that failed (EEXIST) leaves nothing for the fchmod after it to change.
  const refused = await ann.batch([
    { open: { path: `${dir}/new`, flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o644, size: 1 } },
    { fchmod: { fd: { ref: 0 }, mode: 0o777 } },
  ]);
  expect(refused.map(result => result.err?.errno)).toEqual(['EEXIST', 'EEXIST']);
  expect((await ann.sys({ lstat: { path: `${dir}/new` } })).mode & 0o7777).toBe(0o4775);
  // discard: a new file the descriptor was writing goes, by its content, whatever its name now.
  expect((await ann.sys({ discard: { fd: made[0].ok.fd } })).discarded).toBe(true);
  expect(await ann.sys({ lstat: { path: `${dir}/new` } })).toBe('ENOENT');
  // A file written over keeps its old content.
  const old = await ann.sys({ open: { path: `${dir}/kept`, flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o644, size: 3 } });
  expect((await ann.context.put(`/api/pwrite?fd=${old.fd}&index=0`, { data: 'old' })).ok()).toBe(true);
  await ann.sys({ close: { fd: old.fd } });
  const over = await ann.sys({ open: { path: `${dir}/kept`, flags: O_WRONLY | O_TRUNC, size: 3 } });
  expect((await ann.sys({ discard: { fd: over.fd } })).discarded).toBe(true);
  expect(await (await ann.context.get(`/api/file?path=${encodeURIComponent(dir + '/kept')}`)).text()).toBe('old');
  // A descriptor whose file is complete, or that only reads, closes as close(2) does.
  const read = await ann.sys({ open: { path: `${dir}/kept`, flags: 0 } });
  expect((await ann.sys({ discard: { fd: read.fd } })).path).toBe(`${dir}/kept`);
});

test('a batch has a limit, and what is not a batch is refused', async () => {
  const response = await root.context.post('/api/sys', { data: { calls: Array.from({ length: 257 }, () => 'getcreds') } });
  expect(response.status()).toBe(400);
  const invalid = await root.context.post('/api/sys', { data: { calls: [{ frobnicate: {} }] } });
  expect(invalid.status()).toBe(400);
});

test('a batch passes a descriptor on, and carries small reads and writes', async () => {
  const O_WRONLY = 1, O_CREAT = 0o100, O_TRUNC = 0o1000;
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }]);
  const path = base + '/small.txt';
  const text = 'written in one round trip\n';
  // open, write and close in one request: each later call takes the descriptor the first made.
  const [opened, wrote, closed] = await ann.batch([
    { open: { path, flags: O_WRONLY | O_CREAT | O_TRUNC, mode: 0o644 } },
    { pwrite: { fd: { ref: 0 }, index: 0, data: Buffer.from(text).toString('base64') } },
    { close: { fd: { ref: 0 } } },
  ]);
  expect(opened.ok.fd).toBeGreaterThanOrEqual(3);
  expect(wrote).toEqual({ ok: { committed: 0 } });
  expect([closed.ok.path, closed.ok.size]).toEqual([path, text.length]);
  const read = await ann.sys({ pread: { path, offset: 8, count: 6 } });
  expect([Buffer.from(read.data, 'base64').toString(), read.size]).toEqual(['in one', text.length]);
  expect(await (await ann.context.get('/api/file?path=' + encodeURIComponent(path))).text()).toBe(text);
  // Opened and read in one request, through the descriptor.
  const [, through] = await ann.batch([{ open: { path, flags: 0 } }, { pread: { fd: { ref: 0 }, count: 1024 } }, { close: { fd: { ref: 0 } } }]);
  expect(Buffer.from(through.ok.data, 'base64').toString()).toBe(text);
  // What refers to a call that failed fails as it did.
  const refused = await ann.batch([
    { open: { path: '/root/nope', flags: O_WRONLY | O_CREAT, mode: 0o644 } },
    { pwrite: { fd: { ref: 0 }, index: 0, data: '' } },
    { close: { fd: { ref: 2 } } },
  ]);
  expect(refused.map(result => result.err?.errno)).toEqual(['EACCES', 'EACCES', 'EINVAL']);
  // A writer that gives no size writes in order: a short chunk is the last.
  const [grown, short, after] = await ann.batch([
    { open: { path, flags: O_WRONLY | O_TRUNC } },
    { pwrite: { fd: { ref: 0 }, index: 0, data: Buffer.from('new').toString('base64') } },
    { pwrite: { fd: { ref: 0 }, index: 1, data: Buffer.from('more').toString('base64') } },
  ]);
  expect([grown.ok.created, short.ok, after.err.errno]).toEqual([undefined, { committed: 0 }, 'EINVAL']);
  // Truncated as it opened: the file is what was written, readable before it closes.
  expect(Buffer.from((await ann.sys({ pread: { path, count: 100 } })).data, 'base64').toString()).toBe('new');
  expect((await ann.sys({ close: { fd: grown.ok.fd } })).size).toBe(3);
  // An empty file is a file: opened, written nothing, closed.
  const empty = base + '/empty';
  const [made] = await ann.batch([{ open: { path: empty, flags: O_WRONLY | O_CREAT | O_TRUNC, mode: 0o600 } }, { close: { fd: { ref: 0 } } }]);
  expect(made.ok.created).toBe(true);
  const stat = await ann.sys({ stat: { path: empty } });
  expect([stat.size, stat.mode, stat.writing]).toEqual([0, 0o100600, undefined]);
  // The kernel's own files read too, and a batch carries no more than 256 KiB a call.
  expect(Buffer.from((await ann.sys({ pread: { path: '/etc/passwd', count: 5 } })).data, 'base64').toString()).toBe('root:');
  expect(await ann.sys({ pread: { path, count: 256 * 1024 + 1 } })).toBe('EINVAL');
  expect(await ann.sys({ pread: { path: base, count: 1 } })).toBe('EISDIR');
});

test('times: nanoseconds, an access time reading leaves, and utimensat as Linux allows it', async () => {
  const O_WRONLY = 1, O_CREAT = 0o100, O_TRUNC = 0o1000;
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }]);
  const path = base + '/timed.txt';
  await ann.batch([{ open: { path, flags: O_WRONLY | O_CREAT | O_TRUNC, mode: 0o666 } }, { pwrite: { fd: { ref: 0 }, index: 0, data: 'eA==' } }, { close: { fd: { ref: 0 } } }]);
  const made = await ann.sys({ stat: { path } });
  expect(made.atime).toBe(made.mtime);
  expect(made.mtime_nsec ?? 0).toBeLessThan(1e9);
  // Reading says nothing of it: the store is noatime.
  await ann.sys({ pread: { path, count: 1 } });
  expect((await ann.sys({ stat: { path } })).atime).toBe(made.atime);
  // A time given is its owner's (or root's) to set; now, a writer's too.
  const given = { sec: 1700000000, nsec: 123456789 };
  expect(await root.sys({ chmod: { path, mode: 0o666 } })).toBe(null);
  expect(await root.sys({ chown: { path, uid: 0 } })).toBe(null);
  expect(await ann.sys({ utimens: { path, atime: 'omit', mtime: given } })).toBe('EPERM');
  expect(await ann.sys({ utimens: { path } })).toBe(null);
  expect(await root.sys({ utimens: { path, atime: given, mtime: 'omit' } })).toBe(null);
  const set = await ann.sys({ stat: { path } });
  expect([set.atime, set.atime_nsec]).toEqual([given.sec, given.nsec]);
  expect(set.mtime).toBeGreaterThan(given.sec);
  expect(set.ctime).toBeGreaterThanOrEqual(set.mtime);
});

test('/proc: the session\'s descriptors as magic links, directory descriptors, and nothing to change', async () => {
  const O_DIRECTORY = 0o200000;
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }]);
  await ann.batch([{ mkdir: { path: base + '/dir', mode: 0o755 } }, { mknod: { path: base + '/dir/a', mode: 0o644 } }, { mknod: { path: base + '/dir/b', mode: 0o644 } }, { mknod: { path: base + '/dir/c', mode: 0o644 } }]);
  // A directory opens to read; a path through its descriptor names what is in it, as openat does.
  const dir = (await ann.sys({ open: { path: base + '/dir', flags: O_DIRECTORY } })).fd;
  const through = `/proc/self/fd/${dir}`;
  expect((await ann.sys({ getdents: { path: through } })).map(entry => entry.name)).toEqual(['a', 'b', 'c']);
  expect((await ann.sys({ stat: { path: through + '/b' } })).mode).toBe(0o100644);
  expect(await ann.sys({ chmod: { path: through + '/b', mode: 0o600 } })).toBe(null);
  expect((await ann.sys({ stat: { path: base + '/dir/b' } })).mode).toBe(0o100600);
  // The link itself: lstat and readlink see it, stat what it names.
  expect(await ann.sys({ readlink: { path: through } })).toBe(base + '/dir');
  expect((await ann.sys({ lstat: { path: through } })).mode).toBe(0o120700);
  expect((await ann.sys({ stat: { path: through } })).mode).toBe(0o40755);
  const info = Buffer.from((await ann.sys({ pread: { path: `/proc/self/fdinfo/${dir}`, count: 4096 } })).data, 'base64').toString();
  expect(info).toContain(`flags:\t0${O_DIRECTORY.toString(8)}`);
  expect(await (await ann.context.get(`/api/file?path=${encodeURIComponent('/proc/self/fdinfo/' + dir)}`)).text()).toBe(info);
  // Another session has descriptors of its own: the same number is another's, or none.
  expect(await root.sys({ readlink: { path: through } })).not.toBe(base + '/dir');
  // Paged, as getdents reads a buffer at a time.
  expect((await ann.sys({ getdents: { path: base + '/dir', cookie: 1, count: 1 } })).map(entry => entry.name)).toEqual(['b']);
  // /proc is read, not changed; O_DIRECTORY opens only directories, and a directory opens only to read.
  expect((await ann.sys({ getdents: { path: '/proc' } })).map(entry => entry.name)).toContain('self');
  expect(await ann.sys({ mkdir: { path: '/proc/x', mode: 0o755 } })).toBe('EACCES');
  expect(await ann.sys({ unlink: { path: through } })).toBe('EACCES');
  expect(await ann.sys({ open: { path: base + '/dir/a', flags: O_DIRECTORY } })).toBe('ENOTDIR');
  expect(await ann.sys({ open: { path: base + '/dir', flags: 1 } })).toBe('EISDIR');
  expect(await ann.sys({ pread: { fd: dir, count: 1 } })).toBe('EISDIR');
  expect((await ann.sys({ close: { fd: dir } })).path).toBe(base + '/dir');
  expect(await ann.sys({ stat: { path: through } })).toBe('ENOENT');
  // statfs: the store's blocks, its names at most 255 bytes.
  const fs = await ann.sys({ statfs: { path: base } });
  expect([fs.bsize, fs.namelen, fs.bavail > 0]).toEqual([4096, 255, true]);
});

test('inotify: a session watches directories it may list, each once, and at most 128', async () => {
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }, { mkdir: { path: base + '/closed', mode: 0o700 } }, { mknod: { path: base + '/file', mode: 0o644 } }]);
  const [first, again, file, closed, missing] = await ann.batch([
    { inotify_add_watch: { path: base } },
    { inotify_add_watch: { path: base + '/' } },
    { inotify_add_watch: { path: base + '/file' } },
    { inotify_add_watch: { path: base + '/closed' } },
    { inotify_add_watch: { path: base + '/missing' } },
  ]);
  expect(first.ok).toBeGreaterThan(0);
  expect(again.ok).toBe(first.ok);
  expect([file.err.errno, closed.err.errno, missing.err.errno]).toEqual(['ENOTDIR', 'EACCES', 'ENOENT']);
  expect(await ann.sys({ inotify_rm_watch: { wd: first.ok } })).toBe(null);
  expect(await ann.sys({ inotify_rm_watch: { wd: first.ok } })).toBe('EINVAL');
  // As many as fs.inotify.max_user_watches allows, and no more.
  const dirs = Array.from({ length: 129 }, (_, i) => `${base}/w${i}`);
  await ann.batch(dirs.map(path => ({ mkdir: { path, mode: 0o755 } })));
  const watched = await ann.batch(dirs.map(path => ({ inotify_add_watch: { path } })));
  expect(watched.filter(result => 'ok' in result).length).toBe(128);
  expect(watched.at(-1).err.errno).toBe('ENOSPC');
});

test('read tokens: a whole file read by its descriptor\'s token, by its session alone', async () => {
  const O_WRONLY = 1, O_CREAT = 0o100, O_TRUNC = 0o1000;
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }]);
  const path = base + '/played.txt', text = 'a file a player reads in many ranges\n';
  await ann.batch([{ open: { path, flags: O_WRONLY | O_CREAT | O_TRUNC, mode: 0o644 } }, { pwrite: { fd: { ref: 0 }, index: 0, data: Buffer.from(text).toString('base64') } }, { close: { fd: { ref: 0 } } }]);
  const opened = await ann.sys({ open: { path, flags: 0 } });
  expect(opened.token).toMatch(/^[0-9a-f]{64}$/);
  const byToken = url => `/api/file?token=${encodeURIComponent(opened.token)}`;
  expect(await (await ann.context.get(byToken())).text()).toBe(text);
  const ranged = await ann.context.get(byToken(), { headers: { Range: 'bytes=2-5' } });
  expect([ranged.status(), await ranged.text()]).toEqual([206, 'file']);
  // Another session's request with it is refused: the token is its session's.
  expect((await root.context.get(byToken())).status()).toBeGreaterThanOrEqual(400);
  // Closed before it was read, it reads nothing.
  const closed = await ann.sys({ open: { path, flags: 0 } });
  await ann.sys({ close: { fd: closed.fd } });
  expect((await ann.context.get(`/api/file?token=${closed.token}`)).status()).toBeGreaterThanOrEqual(400);
  // A directory, and a file still being written, have none.
  expect((await ann.sys({ open: { path: base, flags: 0o200000 } })).token).toBeUndefined();
  const writing = await ann.sys({ open: { path: base + '/growing', flags: O_WRONLY | O_CREAT, mode: 0o644 } });
  expect((await ann.sys({ open: { path: base + '/growing', flags: 0 } })).token).toBeUndefined();
  await ann.sys({ close: { fd: writing.fd } });
  await ann.sys({ close: { fd: opened.fd } });
});

test('a session\'s numbers are given once; sudo\'s descriptors stream as root; what has no content is not cloned; /usr reads through a descriptor; /sys is read-only', async () => {
  const O_WRONLY = 1, O_CREAT = 0o100, O_EXCL = 0o200, FICLONE = 0x40049409;
  const dir = base + '/review';
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }, { mkdir: { path: dir, mode: 0o777 } }, { chmod: { path: dir, mode: 0o1777 } }]);
  // A number closed is not given again: a page of the session may still hold it.
  const first = await ann.sys({ open: { path: '/etc/passwd', flags: 0 } });
  await ann.sys({ close: { fd: first.fd } });
  const second = await ann.sys({ open: { path: '/etc/passwd', flags: 0 } });
  expect(second.fd).toBeGreaterThan(first.fd);
  expect(await ann.sys({ close: { fd: first.fd } })).toBe('EBADF');
  await ann.sys({ close: { fd: second.fd } });
  // A wheel member's descriptor opened under sudo writes, closes and is read as root, through
  // the Worker's streams too, as a descriptor keeps the access it was opened with.
  const wheel = 'syswheel' + Date.now().toString(36);
  expect((await program(root.context, ['useradd', '-m', '-G', 'wheel', wheel])).ok()).toBe(true);
  expect((await api(root.context, 'passwd', { data: { username: wheel, password } })).ok()).toBe(true);
  const admin = await session(wheel, password);
  try {
    expect((await api(admin.context, 'sudo', { data: { password } })).ok()).toBe(true);
    const secret = dir + '/secret', big = Buffer.alloc(300 * 1024, 'x');
    await root.batch([{ mkdir: { path: secret, mode: 0o700 } }]);
    const opened = await admin.sys({ open: { path: secret + '/big', flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o600, size: big.length } }, { sudo: true });
    expect((await admin.context.put(`/api/pwrite?fd=${opened.fd}&index=0`, { data: big })).ok()).toBe(true);
    expect((await admin.sys({ close: { fd: opened.fd } })).size).toBe(big.length);
    const reading = await admin.sys({ open: { path: secret + '/big', flags: 0 } }, { sudo: true });
    const read = await admin.context.get(`/api/file?token=${encodeURIComponent(reading.token)}`);
    expect([read.status(), (await read.body()).length]).toEqual([200, big.length]);
    await admin.sys({ close: { fd: reading.fd } });
    expect(await admin.sys({ open: { path: secret + '/big', flags: 0 } })).toBe('EACCES');
  } finally {
    await admin.context.dispose();
    await program(root.context, ['userdel', '-r', wheel]);
  }
  // What the kernel makes as it is read has no content to share: cp reads it instead.
  const [passwd, copy] = await ann.batch([
    { open: { path: '/etc/passwd', flags: 0 } },
    { open: { path: dir + '/passwd', flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o644 } },
  ]);
  expect(await ann.sys({ ioctl: { fd: copy.ok.fd, request: FICLONE, arg: passwd.ok.fd } })).toBe('EOPNOTSUPP');
  await ann.batch([{ close: { fd: copy.ok.fd } }, { close: { fd: passwd.ok.fd } }]);
  // A binary of /usr is the build's content, shared as any is, and read through a descriptor.
  const [binary, ls] = await ann.batch([
    { open: { path: '/usr/bin/ls', flags: 0 } },
    { open: { path: dir + '/ls', flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o755 } },
  ]);
  const shared = await ann.batch([
    { ioctl: { fd: ls.ok.fd, request: FICLONE, arg: binary.ok.fd } },
    { close: { fd: ls.ok.fd } }, { close: { fd: binary.ok.fd } },
  ]);
  expect(shared.map(result => 'ok' in result)).toEqual([true, true, true]);
  expect((await ann.sys({ stat: { path: dir + '/ls' } })).size).toBe((await ann.sys({ stat: { path: '/usr/bin/ls' } })).size);
  const copied = await ann.context.get('/api/file?path=' + encodeURIComponent(dir + '/ls'));
  expect((await copied.body()).subarray(0, 4).toString('latin1')).toBe('\0asm');
  const [, head] = await ann.batch([{ open: { path: '/usr/bin/coreutils', flags: 0 } }, { pread: { fd: { ref: 0 }, offset: 0, count: 4 } }, { close: { fd: { ref: 0 } } }]);
  expect(Buffer.from(head.ok.data, 'base64').toString('latin1')).toBe('\0asm');
  // Past 4 GiB, a read is past the end, not at the start again.
  const [, far] = await ann.batch([{ open: { path: '/etc/passwd', flags: 0 } }, { pread: { fd: { ref: 0 }, offset: 2 ** 32, count: 16 } }, { close: { fd: { ref: 0 } } }]);
  expect(far.ok.data).toBe('');
  // /sys is the image's, read-only, what is below it too.
  expect(await root.sys({ mkdir: { path: '/sys/x', mode: 0o755 } })).toBe('EROFS');
});

const fsOrigin = process.env.OS_TEST_URL || 'http://127.0.0.1:8787';
async function fsRpc(ctx, credential, session, call, instanceId) {
  const response = await ctx.post(fsOrigin + '/api/fs', {
    headers: { Origin: fsOrigin, ...(instanceId ? { 'X-OS-Instance': instanceId } : {}) },
    data: { version: 2, credential, session, call },
  });
  const body = await response.json();
  return { ok: response.ok(), status: response.status(), body };
}
async function fsReadData(ctx, credential, pid, session, open, offset = 0, length = 64, instanceId) {
  const response = await ctx.post(fsOrigin + '/api/fs/data', {
    headers: {
      Origin: fsOrigin,
      ...(instanceId ? { 'X-OS-Instance': instanceId } : {}),
      'X-OS-Filesystem': JSON.stringify({ version: 2, credential, pid, session, open, operation: { read: { offset, length } } }),
    },
    data: Buffer.alloc(0),
  });
  return { ok: response.ok(), status: response.status(), body: response.ok() ? await response.body() : await response.json() };
}

test('execve runs /usr binaries, snapshots the caller, and refuses what Linux refuses', async ({ page }) => {
  // The test's directory, when only this test is selected.
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }]);

  // 1. ServiceAuth v2 mints a remote credential bound to an instance, denies v1 /api/sys mutations,
  //    refuses logout, and creates cloud files over /api/fs v2 as the snapshotted caller.
  const inst = await attachInstance(root.context, { origin: fsOrigin });
  const cred = await inst.mint({ scope: FULL_SCOPE, cloud_access: true });
  try {
    expect(cred.token).toMatch(/^[0-9a-f]{64}$/);
    const instHeaders = { 'X-OS-Instance': inst.instanceId };
    // A process token cannot sign the browser out.
    const [logout] = await root.batch([{ logout: null }], { proc: cred.token }, instHeaders);
    expect(logout.err.errno).toBe('EPERM');
    // Direct v1 /api/sys path calls with { proc } are refused at the server boundary;
    // processes mutate cloud files via /api/fs v2 handles using their snapshotted identity.
    const [deniedV1] = await root.batch([{ mknod: { path: base + '/from-process', mode: 0o644 } }], { proc: cred.token }, instHeaders);
    expect(deniedV1.err.errno).toBe('EPERM');
    const fsConn = await fsRpc(root.context, cred.token, null, 'connect', inst.instanceId);
    expect(fsConn.ok, JSON.stringify(fsConn.body)).toBe(true);
    const walkBase = await fsRpc(root.context, cred.token, fsConn.body.session, {
      walk: { dir: fsConn.body.root, names: base.split('/').filter(Boolean) },
    }, inst.instanceId);
    expect(walkBase.ok, JSON.stringify(walkBase.body)).toBe(true);
    const baseHandle = walkBase.body.entries[walkBase.body.entries.length - 1].handle;
    const created = await fsRpc(root.context, cred.token, fsConn.body.session, {
      create: {
        ticket: 'sys-from-process-' + Date.now(),
        dir: baseHandle,
        name: 'from-process',
        mode: 0o644,
        umask: 0o022,
        options: { read: true, write: true, append: false, append_implies_write: false, truncate: false, create: true, create_new: true, exec: false, path: false },
      },
    }, inst.instanceId);
    expect(created.ok, JSON.stringify(created.body)).toBe(true);
    await fsRpc(root.context, cred.token, fsConn.body.session, { release: { open: created.body[1] } }, inst.instanceId);

    // 2. Clone of /usr/bin/coreutils and hard link of that clone share content; exec permission checks
    //    (EISDIR, ENOENT, EACCES on 0644 even for root, ok on 0111) hold on /api/fs v2.
    const FICLONE = 0x40049409, O_WRONLY = 1, O_CREAT = 0o100, O_EXCL = 0o200;
    const copied = base + '/copied-coreutils', hard = copied + '-hard';
    await root.batch([{ mkdir: { path: base + '/linked', mode: 0o755 } }]);
    const [source, target] = await root.batch([
      { open: { path: '/usr/bin/coreutils', flags: 0 } },
      { open: { path: copied, flags: O_WRONLY | O_CREAT | O_EXCL, mode: 0o755 } },
    ]);
    expect(source.ok).toBeTruthy();
    expect(target.ok).toBeTruthy();
    expect(await root.sys({ ioctl: { fd: target.ok.fd, request: FICLONE, arg: source.ok.fd } })).toBeNull();
    await root.batch([{ close: { fd: target.ok.fd } }, { close: { fd: source.ok.fd } }]);
    const [made] = await root.batch([{ link: { from: copied, to: hard } }]);
    expect(made).toEqual({ ok: null });
    for (const rel of ['copied-coreutils', 'copied-coreutils-hard']) {
      const walked = await fsRpc(root.context, cred.token, fsConn.body.session, { lookup: { dir: baseHandle, name: rel } }, inst.instanceId);
      expect(walked.ok, JSON.stringify(walked.body)).toBe(true);
      const execOpen = await fsRpc(root.context, cred.token, fsConn.body.session, {
        open: {
          ticket: 'sys-clone-exec-' + rel + '-' + Date.now(),
          handle: walked.body.handle,
          options: { read: false, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: true, path: false },
        },
      }, inst.instanceId);
      expect(execOpen.ok, JSON.stringify(execOpen.body)).toBe(true);
      const magic = await fsReadData(root.context, cred.token, cred.pid, fsConn.body.session, execOpen.body, 0, 4, inst.instanceId);
      expect(magic.ok).toBe(true);
      expect(magic.body.toString('latin1')).toBe('\0asm');
      await fsRpc(root.context, cred.token, fsConn.body.session, { release: { open: execOpen.body } }, inst.instanceId);
    }

    const dir = base + '/execve';
    await root.batch([
      { mkdir: { path: dir, mode: 0o755 } },
      { mknod: { path: dir + '/plain', mode: 0o644 } },
      { mknod: { path: dir + '/xonly', mode: 0o111 } },
      { mkdir: { path: dir + '/sub', mode: 0o755 } },
    ]);
    const dirHandle = (await fsRpc(root.context, cred.token, fsConn.body.session, { lookup: { dir: baseHandle, name: 'execve' } }, inst.instanceId)).body.handle;
    const plainHandle = (await fsRpc(root.context, cred.token, fsConn.body.session, { lookup: { dir: dirHandle, name: 'plain' } }, inst.instanceId)).body.handle;
    const xonlyHandle = (await fsRpc(root.context, cred.token, fsConn.body.session, { lookup: { dir: dirHandle, name: 'xonly' } }, inst.instanceId)).body.handle;
    const execOpts = { read: false, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: true, path: false };
    expect((await fsRpc(root.context, cred.token, fsConn.body.session, { open: { ticket: 'exec-dir-' + Date.now(), handle: dirHandle, options: execOpts } }, inst.instanceId)).body.errno).toBe('EACCES');
    expect((await fsRpc(root.context, cred.token, fsConn.body.session, { lookup: { dir: dirHandle, name: 'missing' } }, inst.instanceId)).body.errno).toBe('ENOENT');
    expect((await fsRpc(root.context, cred.token, fsConn.body.session, { open: { ticket: 'exec-plain-' + Date.now(), handle: plainHandle, options: execOpts } }, inst.instanceId)).body.errno).toBe('EACCES');
    const xonlyOpen = await fsRpc(root.context, cred.token, fsConn.body.session, { open: { ticket: 'exec-xonly-' + Date.now(), handle: xonlyHandle, options: execOpts } }, inst.instanceId);
    expect(xonlyOpen.ok, JSON.stringify(xonlyOpen.body)).toBe(true);
    await fsRpc(root.context, cred.token, fsConn.body.session, { release: { open: xonlyOpen.body } }, inst.instanceId);
    await fsRpc(root.context, cred.token, fsConn.body.session, 'disconnect', inst.instanceId);
    expect((await root.sys({ stat: { path: base + '/from-process' } })).user).toBe('root');
  } finally {
    await inst.detach().catch(() => {});
  }

  // 3. Local client-kernel exec: /usr binary returns asset, getpid/exit/wait work locally,
  //    and argv over Linux's E2BIG limit fails before execution.
  await page.goto('/login');
  const k = await connectKernel(page);
  await k.value('sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true });
  const localProc = await k.value('exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'seq', '3'], env: ['LANG=C'], cwd: '/' });
  expect(localProc.asset).toBe('/usr/bin/coreutils.wasm');
  expect(localProc.pid).toBeGreaterThan(1);
  expect(await k.value('getpid', { pid: localProc.pid })).toEqual({ pid: localProc.pid, ppid: 1 });
  await k.value('exit', { pid: localProc.pid, status: 5 });
  const waited = await k.value('wait', { pid: localProc.pid });
  expect(waited.status).toBe(5 << 8);
  expect(waited.pid).toBe(localProc.pid);
  const tooBig = await k.call('exec', { path: '/usr/bin/coreutils', argv: ['x'.repeat(129 * 1024)], env: [], cwd: '/' });
  expect(tooBig.err?.errno).toBe('E2BIG');
  await k.terminate();
});

test('proc_init begins a browser namespace, and a new boot reaps what the old one left running', async ({ page }) => {
  // Server-side proc_init and X-Registry are retired under Contract v2 (#54).
  const retiredRegistry = await ann.context.post('/api/sys', {
    data: { calls: [{ proc_init: { boot: 'retired' } }] },
    headers: { 'X-Registry': '1' },
  });
  expect(retiredRegistry.status()).toBe(403);
  const retiredPlain = await ann.context.post('/api/sys', {
    data: { calls: [{ proc_init: { boot: 'retired' } }] },
  });
  expect(retiredPlain.ok()).toBe(false);

  // Each browser instance boots its own local client-kernel namespace; reboot reaps old processes cleanly.
  await page.goto('/login');
  const k = await connectKernel(page);
  await k.value('sync_account', { uid: 0, gid: 0, groups: [0], user: 'root', group: 'root', home: '/root', shell: '/usr/bin/dash', signed_in: true });
  const boot1 = (await k.value('machine_inspect')).boot;
  const proc = await k.value('exec', { path: '/usr/bin/coreutils', argv: ['coreutils', 'sleep', '30'], env: [], cwd: '/' });
  const running = await k.value('poll', { pids: [proc.pid] });
  expect(running[0]?.state).toBe('running');
  await k.value('machine_reboot', { boot: boot1 });
  const afterReboot = await k.value('poll', { pids: [proc.pid] });
  expect(afterReboot[0]?.pending_signals?.map(s => s.signal)).toEqual(expect.arrayContaining([1, 15]));
  await k.terminate();

  // A fresh client-kernel boot starts a clean isolated namespace containing only PID 1.
  const k2 = await connectKernel(page, { name: '__testKernel2' });
  const initRow = await k2.value('poll', { pids: [1] });
  expect(initRow[0]?.state).toBe('running');
  const gone = await k2.value('poll', { pids: [proc.pid] });
  expect(gone).toEqual([]);
  await k2.terminate();
});

test('uploaded wasm execves, its image read by the process token alone', async () => {
  const WASM = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x00, 0x00, 0x00, 0x00]);
  const dir = base + '/wasm';
  await root.batch([{ mkdir: { path: base, mode: 0o777 } }, { chmod: { path: base, mode: 0o1777 } }]);
  await ann.batch([{ mkdir: { path: dir, mode: 0o755 } }]);
  const execOpts = { read: false, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: true, path: false };
  const readOpts = { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false };

  // ann's uploaded wasm, executable by its mode; a plain 0644 file is EACCES for exec, for root too.
  expect((await put(ann.context, `${origin}/api/file?path=${dir}/hello.wasm&overwrite=true`, { data: WASM })).status()).toBe(201);
  expect((await put(ann.context, `${origin}/api/file?path=${dir}/plain.wasm&overwrite=true`, { data: WASM })).status()).toBe(201);
  expect(await ann.sys({ chmod: { path: dir + '/hello.wasm', mode: 0o755 } })).toBe(null);

  const annInst = await attachInstance(ann.context, { origin: fsOrigin });
  const rootInst = await attachInstance(root.context, { origin: fsOrigin });
  try {
    const annCred = await annInst.mint({ scope: FULL_SCOPE, cloud_access: true });
    const rootCred = await rootInst.mint({ scope: FULL_SCOPE, cloud_access: true });
    const annConn = await fsRpc(ann.context, annCred.token, null, 'connect', annInst.instanceId);
    const rootConn = await fsRpc(root.context, rootCred.token, null, 'connect', rootInst.instanceId);
    expect(annConn.ok).toBe(true);
    expect(rootConn.ok).toBe(true);

    const annDir = (await fsRpc(ann.context, annCred.token, annConn.body.session, { walk: { dir: annConn.body.root, names: dir.split('/').filter(Boolean) } }, annInst.instanceId)).body.entries.at(-1).handle;
    const rootDir = (await fsRpc(root.context, rootCred.token, rootConn.body.session, { walk: { dir: rootConn.body.root, names: dir.split('/').filter(Boolean) } }, rootInst.instanceId)).body.entries.at(-1).handle;
    const annPlain = (await fsRpc(ann.context, annCred.token, annConn.body.session, { lookup: { dir: annDir, name: 'plain.wasm' } }, annInst.instanceId)).body.handle;
    const rootPlain = (await fsRpc(root.context, rootCred.token, rootConn.body.session, { lookup: { dir: rootDir, name: 'plain.wasm' } }, rootInst.instanceId)).body.handle;
    expect((await fsRpc(ann.context, annCred.token, annConn.body.session, { open: { ticket: 'ann-plain-' + Date.now(), handle: annPlain, options: execOpts } }, annInst.instanceId)).body.errno).toBe('EACCES');
    expect((await fsRpc(root.context, rootCred.token, rootConn.body.session, { open: { ticket: 'root-plain-' + Date.now(), handle: rootPlain, options: execOpts } }, rootInst.instanceId)).body.errno).toBe('EACCES');

    // ann opens hello.wasm with Access::Exec via /api/fs v2 and reads the exact WASM bytes.
    const annHello = (await fsRpc(ann.context, annCred.token, annConn.body.session, { lookup: { dir: annDir, name: 'hello.wasm' } }, annInst.instanceId)).body.handle;
    const execOpen = await fsRpc(ann.context, annCred.token, annConn.body.session, { open: { ticket: 'ann-hello-' + Date.now(), handle: annHello, options: execOpts } }, annInst.instanceId);
    expect(execOpen.ok, JSON.stringify(execOpen.body)).toBe(true);
    const image = await fsReadData(ann.context, annCred.token, annCred.pid, annConn.body.session, execOpen.body, 0, WASM.length, annInst.instanceId);
    expect(image.ok).toBe(true);
    expect(Buffer.from(image.body)).toEqual(WASM);

    // Another browser session, another credential, wrong session secret, wrong instance, or forged token cannot use ann's credential or OpenRef.
    expect((await fsRpc(root.context, annCred.token, null, 'connect', annInst.instanceId)).ok).toBe(false);
    expect((await fsRpc(root.context, rootCred.token, annConn.body.session, { open_metadata: { open: execOpen.body } }, rootInst.instanceId)).ok).toBe(false);
    expect((await fsReadData(ann.context, annCred.token, annCred.pid, { ...annConn.body.session, secret: 'forged' }, execOpen.body, 0, WASM.length, annInst.instanceId)).ok).toBe(false);
    expect((await fsReadData(ann.context, annCred.token, annCred.pid, annConn.body.session, execOpen.body, 0, WASM.length, 'inst-wrong')).ok).toBe(false);
    expect((await fsReadData(ann.context, 'f'.repeat(64), annCred.pid, annConn.body.session, execOpen.body, 0, WASM.length, annInst.instanceId)).ok).toBe(false);
    const [foreign] = await root.batch(['getcreds'], { proc: annCred.token }, { 'X-OS-Instance': annInst.instanceId });
    expect(foreign.err.errno).toBe('EPERM');
    const [unknown] = await ann.batch(['getcreds'], { proc: 'f'.repeat(64) }, { 'X-OS-Instance': annInst.instanceId });
    expect(unknown.err.errno).toBe('EPERM');

    // Revoking annCred immediately terminates access to the OpenRef and /api/sys.
    await annInst.revoke([annCred.token]);
    expect((await fsReadData(ann.context, annCred.token, annCred.pid, annConn.body.session, execOpen.body, 0, WASM.length, annInst.instanceId)).ok).toBe(false);
    const [reaped] = await ann.batch(['getcreds'], { proc: annCred.token }, { 'X-OS-Instance': annInst.instanceId });
    expect(reaped.err.errno).toBe('EPERM');

    // x-only (0111): path read and Access::Read are denied, while Access::Exec reads the image.
    expect((await put(ann.context, `${origin}/api/file?path=${dir}/xonly.wasm&overwrite=true`, { data: WASM })).status()).toBe(201);
    expect(await ann.sys({ chmod: { path: dir + '/xonly.wasm', mode: 0o111 } })).toBe(null);
    expect((await ann.context.get(`${origin}/api/file?path=${dir}/xonly.wasm`)).status()).toBe(403);
    const annCred2 = await annInst.mint({ scope: FULL_SCOPE, cloud_access: true });
    const annConn2 = await fsRpc(ann.context, annCred2.token, null, 'connect', annInst.instanceId);
    const annDir2 = (await fsRpc(ann.context, annCred2.token, annConn2.body.session, { walk: { dir: annConn2.body.root, names: dir.split('/').filter(Boolean) } }, annInst.instanceId)).body.entries.at(-1).handle;
    const xonlyHandle = (await fsRpc(ann.context, annCred2.token, annConn2.body.session, { lookup: { dir: annDir2, name: 'xonly.wasm' } }, annInst.instanceId)).body.handle;
    expect((await fsRpc(ann.context, annCred2.token, annConn2.body.session, { open: { ticket: 'xonly-rd-' + Date.now(), handle: xonlyHandle, options: readOpts } }, annInst.instanceId)).body.errno).toBe('EACCES');
    const xonlyOpen = await fsRpc(ann.context, annCred2.token, annConn2.body.session, { open: { ticket: 'xonly-ex-' + Date.now(), handle: xonlyHandle, options: execOpts } }, annInst.instanceId);
    expect(xonlyOpen.ok, JSON.stringify(xonlyOpen.body)).toBe(true);
    const xonlyBytes = await fsReadData(ann.context, annCred2.token, annCred2.pid, annConn2.body.session, xonlyOpen.body, 0, WASM.length, annInst.instanceId);
    expect(xonlyBytes.ok).toBe(true);
    expect(Buffer.from(xonlyBytes.body)).toEqual(WASM);
    await fsRpc(ann.context, annCred2.token, annConn2.body.session, { release: { open: xonlyOpen.body } }, annInst.instanceId);

    // The exec X rule holds for root too: 0755 passes Access::Exec, chmod 0644 fails EACCES.
    expect((await put(ann.context, `${origin}/api/file?path=${dir}/rootx.wasm&overwrite=true`, { data: WASM })).status()).toBe(201);
    expect(await ann.sys({ chmod: { path: dir + '/rootx.wasm', mode: 0o755 } })).toBe(null);
    const rootxHandle = (await fsRpc(root.context, rootCred.token, rootConn.body.session, { lookup: { dir: rootDir, name: 'rootx.wasm' } }, rootInst.instanceId)).body.handle;
    const rootxOpen = await fsRpc(root.context, rootCred.token, rootConn.body.session, { open: { ticket: 'rootx-1-' + Date.now(), handle: rootxHandle, options: execOpts } }, rootInst.instanceId);
    expect(rootxOpen.ok).toBe(true);
    await fsRpc(root.context, rootCred.token, rootConn.body.session, { release: { open: rootxOpen.body } }, rootInst.instanceId);
    expect(await root.sys({ chmod: { path: dir + '/rootx.wasm', mode: 0o644 } })).toBe(null);
    expect((await fsRpc(root.context, rootCred.token, rootConn.body.session, { open: { ticket: 'rootx-2-' + Date.now(), handle: rootxHandle, options: execOpts } }, rootInst.instanceId)).body.errno).toBe('EACCES');

    // One still uploading is ETXTBSY (or EBUSY on unfinished upload).
    const [opened] = await ann.batch([{ open: { path: dir + '/busy.wasm', flags: 0o1 | 0o100, mode: 0o755, size: WASM.length } }]);
    expect(opened.ok).toBeTruthy();
    const busyHandle = (await fsRpc(ann.context, annCred2.token, annConn2.body.session, { lookup: { dir: annDir2, name: 'busy.wasm' } }, annInst.instanceId)).body.handle;
    const busyExec = await fsRpc(ann.context, annCred2.token, annConn2.body.session, { open: { ticket: 'busy-ex-' + Date.now(), handle: busyHandle, options: execOpts } }, annInst.instanceId);
    expect(busyExec.ok).toBe(false);
    expect(['ETXTBSY', 'EBUSY']).toContain(busyExec.body.errno);
    await ann.batch([{ close: { fd: opened.ok.fd } }]);
    await fsRpc(ann.context, annCred2.token, annConn2.body.session, 'disconnect', annInst.instanceId);
    await fsRpc(root.context, rootCred.token, rootConn.body.session, 'disconnect', rootInst.instanceId);
  } finally {
    await annInst.detach().catch(() => {});
    await rootInst.detach().catch(() => {});
  }
});

test('a process uses its own descriptors, and a page its own: neither reaches the other\'s', async () => {
  const page = await session('root', rootPassword);
  const inst = await attachInstance(page.context, { origin: fsOrigin });
  try {
    const mine = await page.sys({ open: { path: '/etc/passwd', flags: 0 } });
    const cred = await inst.mint({ scope: FULL_SCOPE, cloud_access: true });
    const as = { proc: cred.token };
    const instHeaders = { 'X-OS-Instance': inst.instanceId };
    // Process credentials cannot read a page /api/sys descriptor, and direct v1 path opens from a process are refused.
    expect(await page.sys({ pread: { fd: mine.fd, count: 64 } }, as, instHeaders)).toBe('EBADF');
    expect(await page.sys({ open: { path: '/etc/group', flags: 0 } }, as, instHeaders)).toBe('EPERM');

    // Process opens /etc/group via its own /api/fs v2 session and OpenRef, isolated from the page's fd table.
    const fsConn = await fsRpc(page.context, cred.token, null, 'connect', inst.instanceId);
    expect(fsConn.ok, JSON.stringify(fsConn.body)).toBe(true);
    const groupWalk = await fsRpc(page.context, cred.token, fsConn.body.session, {
      walk: { dir: fsConn.body.root, names: ['etc', 'group'] },
    }, inst.instanceId);
    expect(groupWalk.ok, JSON.stringify(groupWalk.body)).toBe(true);
    const groupOpen = await fsRpc(page.context, cred.token, fsConn.body.session, {
      open: {
        ticket: 'sys-own-' + Date.now(),
        handle: groupWalk.body.entries[1].handle,
        options: { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false },
      },
    }, inst.instanceId);
    expect(groupOpen.ok, JSON.stringify(groupOpen.body)).toBe(true);
    const groupBytes = await fsReadData(page.context, cred.token, cred.pid, fsConn.body.session, groupOpen.body, 0, 64, inst.instanceId);
    expect(groupBytes.ok).toBe(true);
    expect(groupBytes.body.toString()).toMatch(/^root:x:0:/);

    // Another credential cannot use the process's /api/fs session/OpenRef, and the page's fd still points to /etc/passwd.
    const hijack = await fsReadData(page.context, 'forged-token', cred.pid, fsConn.body.session, groupOpen.body, 0, 64, inst.instanceId);
    expect(hijack.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(hijack.body.errno);
    const link = { readlink: { path: `/proc/self/fd/${mine.fd}` } };
    expect(await page.sys(link)).toBe('/etc/passwd');
    expect(Buffer.from((await page.sys({ pread: { fd: mine.fd, offset: 0, count: 64 } })).data, 'base64').toString()).toMatch(/^root:x:0:0:/);

    // Revoking the process credential revokes its /api/fs access while leaving the page's descriptor intact.
    await inst.revoke([cred.token]);
    const afterExit = await fsReadData(page.context, cred.token, cred.pid, fsConn.body.session, groupOpen.body, 0, 64, inst.instanceId);
    expect(afterExit.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterExit.body.errno);
    expect(await page.sys(link)).toBe('/etc/passwd');
    expect((await page.sys({ getdents: { path: '/proc/self/fd' } })).map(entry => entry.name)).toEqual([String(mine.fd)]);
    expect(await page.sys({ close: { fd: mine.fd } })).toBeTruthy();
  } finally {
    await inst.detach().catch(() => {});
    await page.context.dispose();
  }
});

test('a process keeps its descriptors and credentials when its page changes account', async () => {
  const page = await session('root', rootPassword);
  const inst = await attachInstance(page.context, { origin: fsOrigin });
  const path = '/tmp/process-account-' + Date.now().toString(36);
  try {
    expect((await put(page.context, `/api/file?path=${path}`, { data: 'root-only content' })).ok()).toBe(true);
    expect(await page.sys({ chmod: { path, mode: 0o600 } })).toBeNull();
    const cred = await inst.mint({ scope: FULL_SCOPE, cloud_access: true });
    const as = { proc: cred.token };
    const instHeaders = { 'X-OS-Instance': inst.instanceId };
    const fsConn = await fsRpc(page.context, cred.token, null, 'connect', inst.instanceId);
    expect(fsConn.ok, JSON.stringify(fsConn.body)).toBe(true);
    const walkFile = await fsRpc(page.context, cred.token, fsConn.body.session, {
      walk: { dir: fsConn.body.root, names: path.split('/').filter(Boolean) },
    }, inst.instanceId);
    expect(walkFile.ok, JSON.stringify(walkFile.body)).toBe(true);
    const opened = await fsRpc(page.context, cred.token, fsConn.body.session, {
      open: {
        ticket: 'sys-account-' + Date.now(),
        handle: walkFile.body.entries[walkFile.body.entries.length - 1].handle,
        options: { read: true, write: false, append: false, append_implies_write: false, truncate: false, create: false, create_new: false, exec: false, path: false },
      },
    }, inst.instanceId);
    expect(opened.ok, JSON.stringify(opened.body)).toBe(true);
    const before = await page.sys('getcreds', as, instHeaders);
    const read = () => fsReadData(page.context, cred.token, cred.pid, fsConn.body.session, opened.body, 0, 64, inst.instanceId);
    const first = await read();
    expect(first.ok).toBe(true);
    expect(first.body.toString()).toBe('root-only content');
    expect((await api(page.context, 'login', { data: { username: name, password } })).ok()).toBe(true);
    expect((await page.sys('getcreds')).user).toBe(name);
    expect(await page.sys({ open: { path, flags: 0 } })).toBe('EACCES');
    expect(await page.sys('getcreds', as, instHeaders)).toMatchObject({
      uid: before.uid, user: before.user, gid: before.gid, group: before.group,
      groups: before.groups, home: before.home,
    });
    const afterLogin = await read();
    expect(afterLogin.ok).toBe(true);
    expect(afterLogin.body.toString()).toBe('root-only content');
    await inst.revoke([cred.token]);
    const afterExit = await read();
    expect(afterExit.ok).toBe(false);
    expect(['EACCES', 'EPERM']).toContain(afterExit.body.errno);
  } finally {
    await inst.detach().catch(() => {});
    await rmrf(root.context, path);
    await page.context.dispose();
  }
});
