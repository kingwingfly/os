// System calls from tests, as user space makes them (owner's design, 2026-10-29): what the tests
// need to make, find and clean up files, now that the kernel's API is its system calls.
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const headers = { Origin: origin, 'Content-Type': 'application/json' };

// `calls`, one batch, for the session of `request` (an APIRequestContext): each one's result,
// `{ok}` or `{err: {errno, detail}}`.
// `extra`, request headers, as a test's own address (CF-Connecting-IP), which rate limits count.
export async function sys(request, calls, options = {}, extra = {}) {
  const response = await request.post(origin + '/api/sys', { headers: { ...headers, ...extra }, data: { calls, ...options } });
  if (!response.ok()) throw new Error(`/api/sys: ${response.status()} ${await response.text()}`);
  return (await response.json()).results;
}

// The account system calls, as a request answered them before they were calls: `name` (login,
// logout, sudo, passwd, register, unregister, session) with `data`, answered with a status an
// errno says (401 refused, 403 not permitted, 404, 409, 429 too many) and the call's value.
export async function api(request, name, { headers: extra = {}, data = {} } = {}) {
  const status = err => ({ EACCES: 401, EPERM: 403, ENOENT: 404, EEXIST: 409, EAGAIN: 429, ESTALE: 412 })[err.errno] ?? 400;
  const answer = (code, body) => ({ status: () => code, ok: () => code < 300, json: async () => body, text: async () => JSON.stringify(body) });
  const one = async (call, options = {}, made = 200) => {
    // A request refused as a whole (from another site, say) is answered as it is.
    const response = await request.post(origin + '/api/sys', { headers: { ...headers, ...extra }, data: { calls: [call], ...options } });
    if (!response.ok()) return response;
    const [result] = (await response.json()).results;
    return 'ok' in result ? answer(made, result.ok ?? {}) : answer(status(result.err), { error: result.err.detail || result.err.errno, errno: result.err.errno });
  };
  switch (name) {
    case 'login': return one({ login: { username: data.username ?? 'root', password: data.password ?? '' } }, { sudo: !!data.sudo });
    case 'logout': return one('logout');
    case 'sudo': return one({ sudo: { password: data.password ?? '', revoke: !!data.revoke } });
    case 'passwd': return one({ passwd: { username: data.username ?? null, password: data.password ?? '', current_password: data.current_password ?? null, force: !!data.force } }, { sudo: !!data.sudo });
    case 'register': return one({ useradd: { name: data.username, password: data.password ?? '', short_password: !!data.short_password, create_home: !!data.create_home } }, {}, 201);
    case 'unregister': {
      const creds = await call(request, 'getcreds');
      return one({ userdel: { name: creds.user, remove: !!data.remove, password: data.password ?? '' } });
    }
    case 'session': {
      const creds = await call(request, 'getcreds');
      return answer(200, { username: creds.user, uid: creds.uid, authenticated: creds.signed_in, writable: creds.signed_in, home: creds.home,
        group: creds.group, groups: creds.group_names, can_sudo: creds.can_sudo, sudo_active: creds.sudo_active });
    }
  }
  throw new Error('no such account call: ' + name);
}

// A whole file written as a page writes one, through a descriptor (open, pwrite, close): `url`
// names it as a read does (/api/file?path=P, &overwrite=true to replace one), and an If-Match
// header is the version it must still be. Answered as a request is: 201 made, 200 replaced;
// 409 there already, 403 refused (401 to a guest), 404, 412 changed meanwhile; the errno in
// the body.
export async function put(request, url, { data = '', headers: given = {} } = {}) {
  const query = new URL(url, origin).searchParams;
  const path = query.get('path'), overwrite = query.get('overwrite') === 'true';
  const bytes = Buffer.from(data);
  const version = given['If-Match'];
  const flags = 0o1 | 0o100 | (overwrite ? 0o1000 : 0o200);
  const [opened] = await sys(request, [{ open: { path, flags, mode: 0o666, size: bytes.length, ...(version ? { version } : {}) } }]);
  if (opened.err) return refusal(request, opened.err);
  const { fd, created, chunk_size: chunk = 8 * 1024 * 1024 } = opened.ok;
  for (let index = 0; index * chunk < bytes.length; index++) {
    const written = await request.put(`${origin}/api/pwrite?fd=${fd}&index=${index}`, { headers: { Origin: origin, 'Content-Type': 'application/octet-stream' }, data: bytes.subarray(index * chunk, (index + 1) * chunk) });
    if (!written.ok()) {
      await sys(request, [{ close: { fd } }, ...(created ? [{ unlink: { path } }] : [])]);
      return written;
    }
  }
  const [closed] = await sys(request, [{ close: { fd } }]);
  if (closed.err) return refusal(request, closed.err);
  return answer(closed.ok.created ? 201 : 200, { path: closed.ok.path, size: closed.ok.size, etag: closed.ok.version });
}
const answer = (code, body) => ({ status: () => code, ok: () => code < 300, json: async () => body, text: async () => JSON.stringify(body) });
async function refusal(request, err) {
  let code = { ENOENT: 404, EEXIST: 409, EISDIR: 409, EBUSY: 409, EBADF: 409, ESTALE: 412, EFBIG: 413 }[err.errno] ?? 400;
  if (err.errno === 'EACCES' || err.errno === 'EPERM') code = (await call(request, 'getcreds')).signed_in ? 403 : 401;
  return answer(code, { error: err.detail || err.errno, errno: err.errno });
}

// One call: its errno, or null if it was done.
export async function errno(request, call, options) {
  const [result] = await sys(request, [call], options);
  return 'err' in result ? result.err.errno : null;
}

// One call: its value; failed, an error that says its errno.
export async function call(request, call, options) {
  const [result] = await sys(request, [call], options);
  if ('ok' in result) return result.ok;
  const error = new Error(`${Object.keys(call)[0]}: ${result.err.detail || result.err.errno}`);
  error.errno = result.err.errno;
  throw error;
}

// mkdir -p: `path` and each directory above it that is not there.
// The session's descriptors, as /proc/self/fd and /proc/self/fdinfo tell of them.
export async function descriptors(request, options) {
  const links = await call(request, { getdents: { path: '/proc/self/fd' } }, options);
  const infos = await sys(request, links.map(link => ({ pread: { path: '/proc/self/fdinfo/' + link.name, count: 4096 } })), options);
  return links.map((link, i) => {
    const info = Object.fromEntries(Buffer.from(infos[i].ok?.data ?? '', 'base64').toString().split('\n').filter(Boolean).map(line => line.split(':\t')));
    return { fd: Number(link.name), path: link.stat.link, flags: parseInt(info.flags, 8), size: Number(info.size), received: Number(info.received), created: info.created === '1' };
  });
}

// The account's processes, as /proc tells of them: PID, state and command line.
export async function processes(request, options) {
  const pids = (await call(request, { getdents: { path: '/proc' } }, options)).map(entry => entry.name).filter(name => name !== 'self');
  const read = await sys(request, pids.flatMap(pid => [{ pread: { path: `/proc/${pid}/status`, count: 4096 } }, { pread: { path: `/proc/${pid}/cmdline`, count: 4096 } }]), options);
  return pids.map((pid, i) => {
    const status = Object.fromEntries(Buffer.from(read[2 * i].ok?.data ?? '', 'base64').toString().split('\n').filter(Boolean).map(line => line.split(':\t')));
    return { pid, state: status.State, name: status.Name, cmdline: Buffer.from(read[2 * i + 1].ok?.data ?? '', 'base64').toString().split('\0').filter(Boolean) };
  });
}

export async function mkdirp(request, path, mode = 0o777) {
  const parts = path.split('/').filter(Boolean);
  const results = await sys(request, parts.map((_, i) => ({ mkdir: { path: '/' + parts.slice(0, i + 1).join('/'), mode } })));
  const failed = results.findLast(result => result.err && result.err.errno !== 'EEXIST');
  if (failed) { const error = new Error(`mkdir -p ${path}: ${failed.err.detail || failed.err.errno}`); error.errno = failed.err.errno; throw error; }
}

// rm -rf: `path` and what is below it, as user space removes a tree; its first failure's errno,
// or null. One not there is fine.
export async function rmrf(request, path) {
  const [found] = await sys(request, [{ lstat: { path } }]);
  if (found.err) return found.err.errno === 'ENOENT' ? null : found.err.errno;
  if ((found.ok.mode & 0o170000) !== 0o040000) return errno(request, { unlink: { path } });
  const [listed] = await sys(request, [{ getdents: { path } }]);
  if (listed.err) return listed.err.errno;
  let failure = null;
  for (const entry of listed.ok) failure ??= await rmrf(request, path.replace(/\/$/, '') + '/' + entry.name);
  return failure ?? errno(request, { rmdir: { path } });
}

// The names in the directory `path`, as getdents gives them.
export async function names(request, path) {
  return (await call(request, { getdents: { path } })).map(entry => entry.name);
}

// What stat says of `path`, as the tests look at a node: whether it is a directory, its owner's
// and group's names, its permission bits, size, link, and whether it is being recorded; null if
// it is not there.
export async function entry(request, path) {
  const [found] = await sys(request, [{ stat: { path } }]);
  if (found.err?.errno === 'ENOENT') return null;
  if (found.err) { const error = new Error(`stat ${path}: ${found.err.errno}`); error.errno = found.err.errno; throw error; }
  const stat = found.ok;
  return { directory: (stat.mode & 0o170000) === 0o040000, owner: stat.user, group: stat.group, mode: stat.mode & 0o7777,
    size: stat.size, link: stat.link, recording: !!stat.writing?.recording, uploaded: stat.writing?.received };
}

// The entries of the directory `path`, as the terminal lists them: directories first, then by
// name, each as `entry` describes a node (and its name).
export async function listing(request, path) {
  const entries = (await call(request, { getdents: { path } })).map(({ name, stat }) => ({ name,
    directory: !!stat && (stat.mode & 0o170000) === 0o040000, owner: stat?.user, group: stat?.group, mode: stat ? stat.mode & 0o7777 : 0,
    size: stat?.size, link: stat?.link, uploaded: stat?.writing?.received }));
  return entries.sort((a, b) => (b.directory - a.directory) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

// The programs of user space the tests run as an account, for what they set up and check:
// chmod, chown, chgrp, touch, rm, mkdir, mv, ln -s and setfacl -m, made of system calls as the
// terminal's are (crates/userland), answered as a request is (200; 403 refused, 401 to a guest;
// 404 not there; 409 there already); anything else goes to the commands the server still runs.
const MOVED = new Set(['chmod', 'chown', 'chgrp', 'touch', 'rm', 'mkdir', 'mv', 'ln', 'setfacl']);
const readText = async (request, path) => { const response = await request.get(origin + '/api/file?path=' + encodeURIComponent(path)); return response.ok() ? response.text() : ''; };
async function idsOf(request, path) {
  return new Map((await readText(request, path)).split('\n').filter(Boolean).map(line => line.split(':')).map(fields => [fields[0], fields]));
}
// The bits a symbolic mode (`go-w`, `u+x,o=r`) or an octal one leaves of `mode`.
function changed(mode, spec, directory) {
  if (/^[0-7]{3,4}$/.test(spec)) return parseInt(spec, 8);
  for (const clause of spec.split(',')) {
    const [, who = 'a', op, perms] = clause.match(/^([ugoa]*)([+=-])([rwxXst]*)$/) || [];
    if (!op) throw new Error(`invalid mode: ${spec}`);
    const classes = (who === 'a' || who === '') ? 'ugo' : who.replace('a', 'ugo');
    let bits = 0;
    for (const c of classes) {
      const shift = { u: 6, g: 3, o: 0 }[c];
      let p = 0;
      for (const ch of perms) p |= { r: 4, w: 2, x: 1, X: directory || mode & 0o111 ? 1 : 0, s: 0, t: 0 }[ch];
      bits |= p << shift;
      if (op === '=') mode &= ~(7 << shift);
    }
    if (perms.includes('s')) bits |= (classes.includes('u') ? 0o4000 : 0) | (classes.includes('g') ? 0o2000 : 0);
    if (perms.includes('t')) bits |= 0o1000;
    mode = op === '-' ? mode & ~bits : mode | bits;
  }
  return mode;
}
// Each node below the directory `path`, and it, deepest last.
async function tree(request, path, options) {
  const [found] = await sys(request, [{ lstat: { path } }], options);
  if (found.err || (found.ok.mode & 0o170000) !== 0o040000) return [path];
  const [listed] = await sys(request, [{ getdents: { path } }], options);
  const below = [];
  for (const entry of listed.ok ?? []) below.push(...await tree(request, path.replace(/\/$/, '') + '/' + entry.name, options));
  return [path, ...below];
}
// The account programs, as user space makes them of their calls (crates/userland accounts.rs),
// answered as a request is: the call's errno as a status, and what it said.
async function accountProgram(request, args, sudo) {
  const answer = (code, body) => ({ status: () => code, ok: () => code < 300, json: async () => body, text: async () => JSON.stringify(body) });
  const [name, ...rest] = args;
  const flags = {}, operands = [];
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg.startsWith('--')) flags[arg.slice(2)] = true;
    else if (arg.startsWith('-') && arg.length > 1) {
      for (const [j, flag] of [...arg.slice(1)].entries()) {
        if ('dgGln'.includes(flag)) { flags[flag] = arg.slice(j + 2) || rest[++i]; break; }
        flags[flag] = true;
      }
    } else operands.push(arg);
  }
  const options = { sudo };
  const said = async op => {
    const [result] = await sys(request, [op], options);
    if ('ok' in result) return answer(200, { output: result.ok?.message ?? '' });
    const code = { EACCES: 401, EPERM: 403, ENOENT: 404, EEXIST: 409, EAGAIN: 429 }[result.err.errno] ?? 400;
    return answer(code === 401 && (await call(request, 'getcreds', options).catch(() => ({ signed_in: true }))).signed_in ? 403 : code, { error: result.err.detail || result.err.errno, errno: result.err.errno });
  };
  switch (name) {
    case 'useradd': return said({ useradd: { name: operands[0], create_home: !!flags.m, home: flags.d ?? null, group: flags.g ?? null, groups: flags.G ?? null } });
    case 'usermod': return said({ usermod: { name: operands[0], append: !!flags.a, groups: flags.G ?? null, group: flags.g ?? null, home: flags.d ?? null, move_home: !!flags.m, rename: flags.l ?? null, lock: !!flags.L, unlock: !!flags.U } });
    case 'userdel': return said({ userdel: { name: operands[0], remove: !!flags.r } });
    case 'groupadd': return said({ groupadd: { name: operands[0] } });
    case 'groupdel': return said({ groupdel: { name: operands[0] } });
    case 'groupmod': return said({ groupmod: { name: operands[0], new_name: flags.n } });
  }
  // whoami, id, users: of /etc/passwd and /etc/group, as the session (under sudo) is.
  const [creds] = await sys(request, ['getcreds'], options);
  if ('err' in creds) return answer(403, { error: creds.err.detail || creds.err.errno, errno: creds.err.errno });
  const passwd = await idsOf(request, '/etc/passwd'), group = await idsOf(request, '/etc/group');
  const groupName = gid => [...group.values()].find(fields => fields[2] === String(gid))?.[0] ?? String(gid);
  if (name === 'whoami') return answer(200, { output: creds.ok.user });
  if (name === 'users') {
    if (creds.ok.uid !== 0) return answer(403, { error: 'Only root can list accounts' });
    return answer(200, { output: [...passwd.values()].map(fields => `${fields[0]}\tuid=${fields[2]}\t${fields[5]}`).join('\n') });
  }
  if (name === 'id') {
    const user = operands[0] ? passwd.get(operands[0]) : null;
    if (operands[0] && !user) return answer(404, { error: 'User does not exist' });
    const uid = user ? Number(user[2]) : creds.ok.uid, gid = user ? Number(user[3]) : creds.ok.gid;
    const members = user ? [gid, ...[...group.values()].filter(fields => (fields[3] || '').split(',').includes(operands[0])).map(fields => Number(fields[2]))] : creds.ok.groups;
    const ids = [...new Set(members)].sort((a, b) => a - b);
    return answer(200, { output: `uid=${uid}(${user ? user[0] : creds.ok.user}) gid=${gid}(${groupName(gid)}) groups=${ids.map(id => `${id}(${groupName(id)})`).join(',')}` });
  }
  throw new Error('no such program here: ' + name);
}
export async function program(request, args, { cwd = '/', sudo = false, ...extra } = {}) {
  if (!MOVED.has(args[0])) return accountProgram(request, args, sudo);
  const options = { sudo };
  const creds = await call(request, 'getcreds', options);
  const absolute = p => p === '~' ? creds.home : p.startsWith('~/') ? creds.home + p.slice(1) : p.startsWith('/') ? p : (cwd === '/' ? '' : cwd) + '/' + p;
  const [name, ...rest] = args;
  const flags = new Set(), operands = [];
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '--') { operands.push(...rest.slice(i + 1)); break; }
    if (rest[i].startsWith('-') && rest[i].length > 1 && !(name === 'chmod' && /^-[rwxXst]+$/.test(rest[i]))) {
      for (const flag of rest[i].slice(1)) flags.add(flag);
      if (name === 'setfacl' && rest[i] === '-m') { flags.add('m'); operands.push(rest[++i]); }
    } else operands.push(rest[i]);
  }
  let failure = null;
  const run = async c => { const e = await errno(request, c, options); failure ??= e; return e; };
  switch (name) {
    case 'chmod': case 'chown': case 'chgrp': {
      const [spec, ...paths] = operands;
      let uid, gid;
      if (name !== 'chmod') {
        const users = await idsOf(request, '/etc/passwd'), groups = await idsOf(request, '/etc/group');
        const [user, group] = name === 'chgrp' ? ['', spec] : spec.split(':');
        uid = user ? Number(users.get(user)?.[2] ?? user) : undefined;
        gid = group ? Number(groups.get(group)?.[2] ?? group) : group === '' && user ? Number(users.get(user)?.[3]) : undefined;
      }
      for (const typed of paths) {
        const targets = flags.has('R') ? await tree(request, absolute(typed), options) : [absolute(typed)];
        for (const path of targets) {
          if (name === 'chmod') {
            const [found] = await sys(request, [{ stat: { path } }], options);
            if (found.err) { failure ??= found.err.errno; continue; }
            await run({ chmod: { path, mode: changed(found.ok.mode & 0o7777, spec, (found.ok.mode & 0o170000) === 0o040000) } });
          } else await run({ chown: { path, uid, gid, nofollow: flags.has('h') } });
        }
      }
      break;
    }
    case 'touch':
      for (const typed of operands) {
        const path = absolute(typed);
        const e = await errno(request, { utimens: { path } }, options);
        if (e === 'ENOENT' && !flags.has('c')) await run({ mknod: { path, mode: 0o666 } });
        else if (e !== 'ENOENT') failure ??= e;
      }
      break;
    case 'rm':
      for (const typed of operands) {
        const e = flags.has('r') || flags.has('R') ? await rmrf(request, absolute(typed)) : await errno(request, { unlink: { path: absolute(typed) } }, options);
        if (!(flags.has('f') && e === 'ENOENT')) failure ??= e;
      }
      break;
    case 'mkdir':
      for (const typed of operands) {
        if (flags.has('p')) { try { await mkdirp(request, absolute(typed)); } catch (error) { failure ??= error.errno; } }
        else await run({ mkdir: { path: absolute(typed), mode: 0o777 } });
      }
      break;
    case 'mv': {
      const sources = operands.slice(0, -1).map(absolute), to = absolute(operands.at(-1));
      const [found] = await sys(request, [{ stat: { path: to } }], options);
      const into = found.ok && (found.ok.mode & 0o170000) === 0o040000;
      if (!into && (sources.length > 1 || (found.err && found.err.errno !== 'ENOENT'))) { failure = found.err?.errno ?? 'ENOTDIR'; break; }
      for (const from of sources) await run({ rename: { from, to: into ? to.replace(/\/$/, '') + '/' + from.split('/').filter(Boolean).pop() : to } });
      break;
    }
    case 'ln':
      await run({ symlink: { target: operands[0], path: absolute(operands[1]) } });
      break;
    case 'setfacl': {
      const [spec, ...paths] = operands;
      const users = await idsOf(request, '/etc/passwd'), groups = await idsOf(request, '/etc/group');
      for (const typed of paths) {
        const path = absolute(typed);
        const [found, current] = await sys(request, [{ stat: { path } }, { getxattr: { path, name: 'system.posix_acl_access' } }], options);
        if (found.err) { failure ??= found.err.errno; continue; }
        const mode = found.ok.mode;
        const entries = current.ok ? JSON.parse(Buffer.from(current.ok, 'base64').toString()) : { user: mode >> 6 & 7, group: mode >> 3 & 7, other: mode & 7, mask: null, users: {}, groups: {} };
        entries.users ??= {}; entries.groups ??= {};
        let masked = false;
        for (const entry of spec.split(',')) {
          const [tag, who, perms] = entry.split(':');
          const bits = [...perms].reduce((sum, ch) => sum | ({ r: 4, w: 2, x: 1 }[ch] ?? 0), 0);
          if (tag.startsWith('u')) { if (who) entries.users[users.get(who)?.[2] ?? who] = bits; else entries.user = bits; }
          else if (tag.startsWith('g')) { if (who) entries.groups[groups.get(who)?.[2] ?? who] = bits; else entries.group = bits; }
          else if (tag.startsWith('m')) { entries.mask = bits; masked = true; }
          else entries.other = bits;
        }
        if (!masked) entries.mask = [entries.group, ...Object.values(entries.users), ...Object.values(entries.groups)].reduce((a, b) => a | b, 0);
        await run({ setxattr: { path, name: 'system.posix_acl_access', value: Buffer.from(JSON.stringify(entries)).toString('base64') } });
      }
      break;
    }
  }
  const status = failure === null ? 200
    : ['EACCES', 'EPERM'].includes(failure) ? (creds.uid === 65534 ? 401 : 403)
    : failure === 'ENOENT' ? 404 : ['EEXIST', 'ENOTEMPTY', 'EISDIR', 'EBUSY'].includes(failure) ? 409 : 400;
  return { status: () => status, ok: () => status === 200, json: async () => ({ errno: failure }), text: async () => failure ?? '' };
}

// A kernel for a test's page that runs no server: it answers the system calls the page makes
// about the files `files` gives (a map, or a function making one, of absolute path to {size,
// mode, user}), all in `/`, and the directory itself.
export function fakeKernel(files) {
  const stat = (path, { size = 0, mode = 0o644, user = 'guest' } = {}, directory = false) => ({ ino: 1, mode: (directory ? 0o040000 : 0o100000) | mode,
    nlink: 1, uid: 1000, gid: 1000, user, group: user, size, mtime: 0, ctime: 0 });
  return route => {
    const known = typeof files === 'function' ? files() : files;
    const { calls } = JSON.parse(route.request().postData());
    const answer = call => {
      if (call === 'getcreds') return { ok: { uid: 65534, gid: 65534, groups: [65534], user: 'guest', group: 'guest', group_names: ['guest'], home: '/', signed_in: false, can_sudo: false, sudo_active: false } };
      const [name, args] = Object.entries(call)[0];
      const path = args.path;
      if (name === 'getdents') return { ok: Object.entries(known).filter(([p]) => p.lastIndexOf('/') === 0).map(([p, f]) => ({ name: p.slice(1), stat: stat(p, f) })) };
      if (path === '/') return { ok: name === 'access' ? null : stat('/', { mode: 0o755 }, true) };
      if (!(path in known)) return { err: { errno: 'ENOENT' } };
      return { ok: name === 'access' ? null : ['stat', 'lstat'].includes(name) ? stat(path, known[path]) : null };
    };
    return route.fulfill({ json: { results: calls.map(answer) } });
  };
}
