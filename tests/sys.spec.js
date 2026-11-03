import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { api, program, rmrf } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
let sequence = 0;
const address = name => `sys-${name}-${Date.now()}-${++sequence}`;

// A process of user space: its session, and the calls it makes, a batch a request.
async function session(username, password) {
  const context = await playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': address(username || 'guest') } });
  if (username) expect((await api(context, 'login', { data: { username, password } })).ok()).toBe(true);
  const batch = async (calls, options = {}) => {
    const response = await context.post('/api/sys', { data: { calls, ...options } });
    expect(response.status()).toBe(200);
    return (await response.json()).results;
  };
  // One call: its value, or its errno.
  const sys = async (call, options) => { const [result] = await batch([call], options); return 'ok' in result ? result.ok : result.err.errno; };
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

test('a guest is uid guest; sudo runs a batch as root only once its account has authenticated', async () => {
  const guest = await session();
  const creds = await guest.sys('getcreds');
  expect([creds.user, creds.signed_in, creds.can_sudo]).toEqual(['guest', false, false]);
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
