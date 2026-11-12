import { test, expect } from './test.js';
import { api, call, put, rmrf, sys } from './sys.js';
import { readFile } from 'node:fs/promises';
const fixtures = process.env.OS_RELEASE_FIXTURES ? JSON.parse(await readFile(process.env.OS_RELEASE_FIXTURES, 'utf8')) : null;
test.skip(!fixtures, 'requires signed fixtures and an isolated authority; see tests/release-fixtures.mjs');
const ids = fixtures?.ids ?? {}, control = 0x4f530001;
const view = id => ({ 'X-OS-Release': id });
async function answer(request, command, options = {}, headers = {}) {
  return (await sys(request, [command], options, headers))[0];
}
async function ok(request, command, options = {}, headers = {}) {
  const result = await answer(request, command, options, headers);
  expect(result.err, JSON.stringify(result)).toBeUndefined(); return result.ok;
}
async function login(request) {
  const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
  expect((await api(request, 'login', { headers: { 'CF-Connecting-IP': 'release-' + crypto.randomUUID() }, data: { password } })).ok()).toBe(true);
}
async function open(request, flags = 2) { return (await ok(request, { open: { path: '/dev/system', flags } })).fd; }
const ioctl = (request, fd, arg) => ok(request, { ioctl: { fd, request: control, arg } });
const status = (request, fd) => ioctl(request, fd, { op: 'status' });
async function activate(request, fd, id, op = 'activate') {
  const active = (await status(request, fd)).active;
  return ioctl(request, fd, { op, id, expected: active });
}
const read = async (request, path, id, options = {}) => {
  const result = await ok(request, { pread: { path, offset: 0, count: 1024 } }, options, view(id));
  return Buffer.from(result.data, 'base64').toString();
};

test('signed boot filenames preserve Unicode and URL delimiters through staging and byte responses', async ({ request }) => {
  test.setTimeout(180_000);
  await login(request); const fd = await open(request);
  try {
    expect((await ioctl(request, fd, { op: 'stage', id: ids.encoded })).state).toBe('verified');
    const prefix = `/boot/releases/${ids.encoded}/assets/`;
    for (const name of fixtures.encodedPaths) {
      const path = prefix + encodeURIComponent(name);
      const response = await request.get(path);
      expect(response.status(), name).toBe(200);
      expect(await response.text()).toBe('encoded asset contents\n');
      const range = await request.get(path, { headers: { Range: 'bytes=0-6' } });
      expect(range.status(), name).toBe(206); expect(await range.text()).toBe('encoded');
      expect((await request.get(path, { headers: { 'If-None-Match': response.headers().etag } })).status()).toBe(304);
      expect((await request.head(path)).status()).toBe(200);
    }
    for (const path of ['literal%2Fname.txt', 'bad%00name.txt', 'bad%FFname.txt', '%2Fplain.txt']) {
      expect((await request.get(prefix + path)).status(), path).toBe(409);
    }
  } finally { await ok(request, { close: { fd } }); }
});

test('only authenticated root can stage; signatures, bytes and schema fail closed', async ({ request }) => {
  await call(request, 'getcreds');
  expect((await answer(request, { open: { path: '/dev/system', flags: 2 } })).err?.errno).toBe('EACCES');
  const readonly = await open(request, 0);
  expect((await answer(request, { ioctl: { fd: readonly, request: control, arg: { op: 'stage', id: ids.a } } })).err?.errno).toBe('EPERM');
  await login(request); const fd = await open(request); const before = (await status(request, fd)).active;
  for (const id of [ids.untrusted, ids.incompatible]) {
    expect((await answer(request, { ioctl: { fd, request: control, arg: { op: 'stage', id } } })).err?.errno).toBe('EINVAL');
  }
  expect((await answer(request, { ioctl: { fd, request: control, arg: { op: 'stage', id: ids.tampered } } })).err?.errno).toBe('EIO');
  expect((await status(request, fd)).active).toBe(before);
  expect((await answer(request, { stat: { path: '/etc/phase6/generation' } }, {}, view(ids.tampered))).err?.errno).toBe('ESTALE');
  await ok(request, { close: { fd } });
});

test('activation is atomic, preserves writable data, and pins processes and descriptors across rollback', async ({ request }) => {
  test.setTimeout(180_000);
  await login(request); const fd = await open(request);
  for (const id of [ids.a, ids.b]) expect((await ioctl(request, fd, { op: 'stage', id })).state).toBe('verified');
  await activate(request, fd, ids.a);
  expect(await read(request, '/etc/phase6/generation', ids.a)).toBe('generation A\n');
  const file = (await ok(request, { open: { path: '/etc/phase6/generation', flags: 0 } }, {}, view(ids.a))).fd;
  const directory = (await ok(request, { open: { path: '/etc/phase6', flags: 0o200000 } }, {}, view(ids.a))).fd;
  const launched = await ok(request, { execve: { path: '/usr/bin/sleep', argv: ['sleep','60'], cwd: '/', env: [] } }, {}, { ...view(ids.a), 'X-Registry':'1' });
  const proof = { pid: launched.pid, proc: launched.token };
  const marker = '/tmp/release-data-' + crypto.randomUUID();
  expect((await put(request, '/api/file?path=' + marker, { data: 'keep me' })).ok()).toBe(true);
  await activate(request, fd, ids.b);
  expect(await read(request, '/etc/phase6/generation', ids.b)).toBe('generation B\n');
  expect(await read(request, '/etc/phase6/generation', ids.b, proof)).toBe('generation A\n');
  expect(await read(request, `/proc/self/fd/${directory}/generation`, ids.b)).toBe('generation A\n');
  const old = await ok(request, { pread: { fd: file, offset: 0, count: 1024 } }, {}, view(ids.b));
  expect(Buffer.from(old.data,'base64').toString()).toBe('generation A\n');
  for (const command of [
    { open: { path: '/etc/phase6/generation', flags: 0o1001 } },
    { mkdir: { path: '/etc/phase6/new', mode: 0o755 } },
    { chmod: { path: '/etc/phase6/generation', mode: 0o777 } },
    { fchmod: { fd: file, mode: 0o777 } },
    { rename: { from: '/etc/phase6/generation', to: '/tmp/escape' } },
  ]) expect((await answer(request, command, {}, view(ids.b))).err?.errno).toBe('EROFS');
  expect((await answer(request, { ioctl: { fd, request: control, arg: { op: 'activate', id: ids.a, expected: 'stale' } } })).err?.errno).toBe('ESTALE');
  await activate(request, fd, ids.a, 'rollback');
  expect(await read(request, marker, ids.a)).toBe('keep me');
  await sys(request, [{ exit: { ...proof, status: 0 } }, { wait: { pid: String(launched.pid), proc: launched.token } }], {}, { 'X-Registry': '1' });
  await sys(request, [{ close: { fd: file } }, { close: { fd: directory } }, { close: { fd } }, { unlink: { path: marker } }]);
});

test('a signed browser generation boots its installed shell and keeps all code assets pinned', async ({ page, request }) => {
  test.setTimeout(180_000);
  await login(request); const fd = await open(request);
  await ioctl(request, fd, { op: 'stage', id: ids.a }); await activate(request, fd, ids.a);
  const assets = [], errors = [];
  page.on('request', request => { const url = new URL(request.url()); if (/\.(js|wasm|css)$/.test(url.pathname)) assets.push(url.pathname); });
  page.on('pageerror', error => errors.push(error.message));
  await page.goto('/'); await page.waitForFunction(() => !!window.os?.exec);
  expect(page.url()).toContain(`/boot/releases/${ids.a}/assets/`);
  const output = await page.evaluate(async () => {
    let output = '';
    const result = await window.os.exec([{ path: '/usr/bin/sh', argv: ['sh','-c','cat /etc/phase6/generation; /opt/phase6/bin/probe; imagectl status'], cwd: '/' }], { tty:true, stdin:'', onOutput: (_, text) => { output += text; } });
    return { output, status: result.status };
  });
  expect(output.status, output.output).toBe(0); expect(output.output).toContain('generation A');
  expect(output.output).toContain(ids.a); expect(output.output).toContain('sysext ready'); expect(errors).toEqual([]);
  expect(assets.filter(p => !p.startsWith(`/boot/releases/${ids.a}/assets/`))).toEqual([]);
  const identity = await page.evaluate(async () => {
    const response = await fetch('/api/file?path=/etc/passwd'); return response.text();
  });
  expect(identity).toContain('root:');
  await ok(request, { close: { fd } });
});

test('old and new browser hosts coexist with distinct complete configuration generations', async ({ page, request, context }) => {
  test.setTimeout(180_000);
  await login(request); const fd = await open(request);
  for (const id of [ids.a,ids.b]) await ioctl(request,fd,{op:'stage',id});
  await activate(request,fd,ids.a);
  await page.goto('/');await page.waitForFunction(()=>!!window.os?.exec);
  await activate(request,fd,ids.b);
  const next=await context.newPage();await next.goto('/');await next.waitForFunction(()=>!!window.os?.exec);
  const cat=page=>page.evaluate(async()=>{
    const result=await window.os.exec([{path:'/usr/bin/cat',argv:['cat','/etc/phase6/generation'],cwd:'/'}],{stdin:''});
    return {status:result.status,stdout:result.stdout};
  });
  const [old,current]=await Promise.all([cat(page),cat(next)]);
  expect(old).toEqual({status:0,stdout:'generation A\n'});
  expect(current).toEqual({status:0,stdout:'generation B\n'});
  expect(page.url()).toContain(ids.a);expect(next.url()).toContain(ids.b);
  await activate(request,fd,ids.a,'rollback');
  expect(await cat(next)).toEqual({status:0,stdout:'generation B\n'});
  await next.close();await ok(request,{close:{fd}});
});

test('activation refuses to hide mutable configuration or traverse a mutable symlink', async ({ request }) => {
  await login(request);const fd=await open(request);
  await ioctl(request,fd,{op:'stage',id:ids.a});await ioctl(request,fd,{op:'stage',id:ids.b});
  await activate(request,fd,ids.a);const before=(await status(request,fd)).active;
  const path='/etc/phase6';
  try {
    await ok(request,{mkdir:{path,mode:0o755}});
    expect((await put(request,'/api/file?path='+path+'/keep',{data:'mutable state'})).ok()).toBe(true);
    expect((await answer(request,{ioctl:{fd,request:control,arg:{op:'activate',id:ids.b,expected:before}}})).err?.errno).toBe('EEXIST');
    expect((await status(request,fd)).active).toBe(before);
    expect(await read(request,path+'/keep','legacy')).toBe('mutable state');
    await rmrf(request,path);
    await ok(request,{symlink:{target:'/tmp',path}});
    expect((await answer(request,{ioctl:{fd,request:control,arg:{op:'activate',id:ids.b,expected:before}}})).err?.errno).toBe('EEXIST');
    expect(await read(request,'/etc/phase6/generation',ids.a)).toBe('generation A\n');
  } finally { await rmrf(request,path);await ok(request,{close:{fd}}); }
});

test('interrupted preparation can be retried without changing the selected generation', async ({ request }) => {
  test.setTimeout(180_000);
  await login(request);const fd=await open(request);const before=(await status(request,fd)).active;
  const origin=process.env.OS_TEST_URL||'http://127.0.0.1:8787';
  await request.post('/api/sys',{timeout:50,headers:{Origin:origin,'Content-Type':'application/json'},data:{calls:[{ioctl:{fd,request:control,arg:{op:'stage',id:ids.interrupted}}}]}}).catch(error=>{
    expect(error.message).toMatch(/Timeout/);
  });
  expect((await status(request,fd)).active).toBe(before);
  const prepared=await ioctl(request,fd,{op:'stage',id:ids.interrupted});
  expect(prepared.state).toBe('verified');expect(JSON.stringify(prepared)).not.toContain('ticket');
  expect((await status(request,fd)).active).toBe(before);
  expect((await answer(request,{stat:{path:'/etc/phase6/generation'}},{},view(ids.interrupted))).err?.errno).toBe('ESTALE');
  await ok(request,{close:{fd}});
});

test('root release selection preserves opener isolation for authorized window attachments',async({page,request})=>{
  await login(request);const fd=await open(request);
  await ioctl(request,fd,{op:'stage',id:ids.b});await activate(request,fd,ids.b);
  try {
    await page.goto('/');
    const [other]=await Promise.all([page.waitForEvent('popup'),page.evaluate(()=>window.open('/'))]);
    await other.waitForLoadState('domcontentloaded');
    expect(other.url()).toContain(ids.b);
    expect(await other.evaluate(()=>!!opener && crossOriginIsolated)).toBe(true);
    await other.close();
  }finally{await ok(request,{close:{fd}});}
});
