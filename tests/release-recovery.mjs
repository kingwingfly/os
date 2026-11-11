// Destructive only to the explicitly supplied LOCAL fixture configuration/signatures.
// Stop its server first. The same private authority directory survives every restart.
import assert from 'node:assert/strict';
import { readFile, writeFile, open } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createPrivateKey, createPublicKey, createHash, sign } from 'node:crypto';
import { request, chromium, firefox } from '@playwright/test';
import { api, sys, put } from './sys.js';
import { device, directory } from './accelerator.js';
import { zipOf } from './archive-fixtures.js';

const { OS_RELEASE_FIXTURES: fixturePath, OS_RECOVERY_CONFIG: config, OS_RECOVERY_STATE: state,
  OS_RECOVERY_LOG: logPath, OS_TEST_URL: origin } = process.env;
if (!fixturePath || !config || !state || !logPath || !origin?.startsWith('http://127.0.0.1:')) {
  throw new Error('Supply OS_RELEASE_FIXTURES, OS_RECOVERY_CONFIG/STATE/LOG and loopback OS_TEST_URL; stop that server first');
}
const fixtures = JSON.parse(await readFile(fixturePath, 'utf8'));
const { ids, trust, oldKey } = fixtures;
const originalConfig = await readFile(config, 'utf8');
const assets = originalConfig.match(/^directory = "([^"]+)"/m)?.[1];
assert(assets && state !== '.wrangler/state');
const log = await open(logPath, 'a');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
let server;
async function stop() {
  if (!server) return;
  const child = server; server = null;
  const ended = once(child, 'exit'); child.kill('SIGINT');
  await Promise.race([ended, delay(15_000).then(() => { throw new Error('local server did not stop'); })]);
  await delay(500);
}
async function start(policy) {
  await writeFile(config, originalConfig.replace(/^OS_IMAGE_TRUST = .*$/m,
    () => 'OS_IMAGE_TRUST = ' + JSON.stringify(JSON.stringify(policy))));
  server = spawn('node', ['scripts/dev.mjs', '--ip', '127.0.0.1', '--config', config,
    '--persist-to', state, '--port', new URL(origin).port, '--inspector-port', '9234'],
  { stdio: ['ignore', log.fd, log.fd], env: process.env });
  for (let i = 0; i < 120; i++) {
    if (server.exitCode !== null) throw new Error('local server exited');
    try {
      const response = await fetch(origin + '/boot/entries');
      if (response.ok || policy.revoked.length && response.status === 503) return;
    } catch { /* startup */ }
    await delay(500);
  }
  throw new Error('local server did not start');
}
const context = await request.newContext({ baseURL: origin });
const call = async command => {
  const [value] = await sys(context, [command]);
  assert(!value.err, JSON.stringify(value)); return value.ok;
};
let fd;
const control = arg => call({ ioctl: { fd, request: 0x4f530001, arg } });
const activate = async (id, op = 'activate') => control({ op, id, expected: (await control({ op: 'status' })).active });
const read = async (path, id) => {
  const [result] = await sys(context, [{ pread: { path, count: 1024 } }], {}, { 'X-OS-Release': id });
  return result;
};
const signatures = new Map();
const marker = '/tmp/release-recovery-' + crypto.randomUUID();
let provider, providerPolicy, pendingTask, loginView, seatPolicy;
try {
  await start(trust);
  const password = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
  assert((await api(context, 'login', { headers: { 'CF-Connecting-IP': crypto.randomUUID() }, data: { password } })).ok());
  const identity = await call('getcreds');
  provider = await device(context);
  providerPolicy = await provider.ioctl('policy', {});
  const configured = await provider.ioctl('configure', { ...providerPolicy, max_active: 2, max_seconds: 300 });
  loginView = await call({ login_session: { action: { op:'join',host:crypto.randomUUID(),proof:createHash('sha256').update(crypto.randomUUID()).digest('hex') } } });
  seatPolicy = loginView.seat_policy;
  loginView = await call({ login_session: { action: { op:'seat_policy',session:loginView.id,expected:loginView.seat_policy.revision,sharing:'view' } } });
  fd = (await call({ open: { path: '/dev/system', flags: 2 } })).fd;
  for (const id of [ids.a, ids.b, ids.interrupted]) {
    await control({ op: 'stage', id }); await activate(id);
  }
  await activate(ids.a);
  assert((await put(context, '/api/file?path=' + marker, { data: 'survives rotation and recovery' })).ok());
  await call({ mkdir:{path:marker+'-dest',mode:0o700} });
  assert((await put(context,'/api/file?path='+marker+'-source.zip',{data:zipOf([['file.txt','replacement']])})).ok());
  assert((await put(context,'/api/file?path='+marker+'-dest/file.txt',{data:'keep'})).ok());
  const at=await directory(context,'/tmp'), name=marker.slice('/tmp/'.length);
  pendingTask=await provider.submit({operation:'extract',format:'zip',source:at(name+'-source.zip'),destination:at(name+'-dest'),existing:'ask',members:[],verbose:false});
  for(let i=0;i<120 && (await pendingTask.poll()).state!=='question';i++)await delay(500);
  assert.equal((await pendingTask.poll()).state,'question');
  await pendingTask.detach(); await pendingTask.close(); await call({close:{fd:at('.').directory}});
  await stop();
  // Rotate only detached proofs, preserving all content addresses and approved state.
  const key = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 73),
  ]) });
  const publicKey = createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32);
  const keyId = createHash('sha256').update(publicKey).digest('hex');
  const releasePath = `${assets}/boot/releases/${ids.a}`;
  const manifest = JSON.parse(await readFile(releasePath + '/manifest.json', 'utf8'));
  const files = [[releasePath + '/manifest.json', releasePath + '/signature.json', 'os.release.v1'],
    ...[manifest.boot, manifest.base, ...manifest.sysext, ...manifest.confext]
      .map(id => [`${assets}/boot/images/${id}.json`, `${assets}/boot/images/${id}.sig`, 'os.image.v1'])];
  for (const [input, output, domain] of files) {
    signatures.set(output, await readFile(output));
    const signature = sign(null, Buffer.concat([Buffer.from(domain + '\0'), await readFile(input)]), key).toString('hex');
    await writeFile(output, JSON.stringify({ format: 'os.signature', version: 1, key: keyId, signature }));
  }
  await start(trust);
  // The old approved package remains readable during replacement verification.
  const pending = control({ op: 'stage', id: ids.a });
  assert.equal(Buffer.from((await read('/etc/phase6/generation', ids.a)).ok.data, 'base64').toString(), 'generation A\n');
  assert.equal((await pending).state, 'verified');
  await activate(ids.interrupted);
  await stop();
  await start({ ...trust, revoked: [oldKey] });
  assert.equal((await context.get('/')).status(), 503);
  assert.equal((await context.get('/?recovery=1')).status(), 200);
  assert.equal((await read('/etc/phase6/generation', ids.interrupted)).err?.errno, 'EINVAL');
  assert.equal(Buffer.from((await read('/etc/phase6/generation', ids.a)).ok.data, 'base64').toString(), 'generation A\n');
  await activate(ids.b, 'rollback');
  const denied = (await sys(context, [{ ioctl: { fd, request: 0x4f530001,
    arg: { op: 'rollback', id: ids.interrupted, expected: ids.b } } }]))[0];
  assert(denied.err, 'revoked rollback must fail');
  assert.equal((await call('getcreds')).uid, identity.uid);
  provider=await device(context);
  assert.deepEqual(await provider.ioctl('policy',{}),configured);
  assert.deepEqual((await call({login_session:{action:{op:'inspect'}}})).seat_policy,loginView.seat_policy);
  const resumed=await provider.attach(pendingTask.id);
  assert.equal((await resumed.poll()).state,'question');
  await resumed.cancel();await resumed.close();
  const reset=await device(context);await reset.ioctl('configure',{...providerPolicy,revision:configured.revision});await call({close:{fd:reset.fd}});
  await call({login_session:{action:{op:'seat_policy',session:loginView.id,expected:loginView.seat_policy.revision,sharing:seatPolicy.sharing}}});
  assert.equal(Buffer.from((await read(marker, ids.b)).ok.data, 'base64').toString(), 'survives rotation and recovery');
  for (const browserType of [chromium, firefox]) {
    const browser = await browserType.launch();
    try {
      const page = await browser.newPage(); await page.goto(origin);
      await page.waitForFunction(() => !!window.os?.exec);
      assert(page.url().includes(ids.b));
      const result = await page.evaluate(() => window.os.exec([{ path: '/usr/bin/cat', argv: ['cat', '/etc/phase6/generation'], cwd: '/' }], { stdin: '' }));
      assert.equal(result.status, 0); assert.equal(result.stdout, 'generation B\n');
    } finally { await browser.close(); }
  }
  await call({ unlink: { path: marker } }); await call({ close: { fd } });
  for(const path of [marker+'-source.zip',marker+'-dest/file.txt'])await call({unlink:{path}});
  await call({rmdir:{path:marker+'-dest'}});
  console.log('PASS: signature refresh, revoked active boot, authenticated recovery/rollback, both browsers, persistent identity/data/sharing/provider policy and detached container task across three restarts');
} finally {
  // Restore this isolated operator's preferences even if an assertion fails.
  if (server && providerPolicy) try {
    const reset=await device(context),current=await reset.ioctl('policy',{});
    if(pendingTask){const task=await reset.attach(pendingTask.id);await task.cancel();}
    await reset.ioctl('configure',{...providerPolicy,revision:current.revision});
    await call({close:{fd:reset.fd}});
    if(seatPolicy){const current=await call({login_session:{action:{op:'inspect'}}});await call({login_session:{action:{op:'seat_policy',session:current.id,expected:current.seat_policy.revision,sharing:seatPolicy.sharing}}});}
  } catch { /* retain the failed isolated store for investigation */ }
  await context.dispose(); await stop(); await writeFile(config, originalConfig);
  for (const [path, bytes] of signatures) await writeFile(path, bytes);
  await log.close();
}
