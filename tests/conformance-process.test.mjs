import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, rm, open } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { start, stop } from '../scripts/conformance/process.mjs';
import { startPodman, egressImage } from '../scripts/conformance/podman.mjs';
import { helperConnection } from '../scripts/conformance/fixtures.mjs';
const moduleURL=new URL('../scripts/conformance/process.mjs',import.meta.url).href;
const exists=pid=>{try {process.kill(pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;throw error;}};
const firstLine=child=>new Promise((resolve,reject)=>{
  let text='';child.stdout.on('data',chunk=>{text+=chunk;if(text.includes('\n'))resolve(text.split('\n')[0]);});
  child.once('error',reject);child.once('exit',()=>reject(new Error('fixture exited before ready')));
});

test('shared stop handles failed spawn and escalates a resistant owned process',async()=>{
  const missing=start('/does-not-exist-conformance',[],{detached:true,stdio:'pipe'});
  await once(missing,'error');await stop(missing);
  const child=start(process.execPath,['-e',"process.on('SIGTERM',()=>{});console.log('ready');setInterval(()=>{},1000)"],{detached:true,stdio:'pipe'});
  try {await firstLine(child);await stop(child,{timeout:30});assert.equal(child.signalCode,'SIGKILL');await stop(child);}
  finally {await stop(child,{timeout:30});}
});

for(const event of ['SIGINT','SIGTERM','uncaughtException','unhandledRejection'])test('shutdown scope cleans detached resources on '+event,async()=>{
  const script=`import {ShutdownScope,start,stop} from ${JSON.stringify(moduleURL)};
    import net from 'node:net';
    const scope=new ShutdownScope();
    scope.add('retained state notice',()=>console.error('Retained fixture state: /tmp/conformance-notice'));
    const child=scope.own('detached child',()=>start(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'}),stop);
    const server=await scope.acquire('listener',()=>new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>resolve(s));}),s=>new Promise(resolve=>s.close(resolve)));
    console.log(JSON.stringify({pid:child.pid,port:server.address().port}));
    if(${JSON.stringify(event)}==='uncaughtException')setTimeout(()=>{throw new Error('fixture callback failure');},50);
    if(${JSON.stringify(event)}==='unhandledRejection')setTimeout(()=>{void Promise.reject(new Error('fixture rejection'));},50);`;
  const child=start(process.execPath,['--input-type=module','-e',script],{detached:true,stdio:['ignore','pipe','pipe']});
  let owned,errorText='';child.stderr.on('data',chunk=>{errorText+=chunk;});const exited=once(child,'exit');
  try {
    owned=JSON.parse(await firstLine(child));
    if(event.startsWith('SIG'))child.kill(event);
    const [code]=await exited;assert.equal(code,event==='SIGINT'?130:event==='SIGTERM'?143:1);
    assert.match(errorText,/Retained fixture state: \/tmp\/conformance-notice/);
    assert(!exists(owned.pid),'owned child survived cleanup');
    await assert.rejects(fetch('http://127.0.0.1:'+owned.port));
  } finally {
    await stop(child,{timeout:30});
    if(owned&&exists(owned.pid))process.kill(-owned.pid,'SIGKILL');
  }
});

test('shutdown waits for an acquisition already starting and disposes its result',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-pending-')),marker=join(dir,'closed');
  const script=`import {ShutdownScope} from ${JSON.stringify(moduleURL)};import {writeFile} from 'node:fs/promises';
    const scope=new ShutdownScope();
    void scope.acquire('pending',()=>new Promise(resolve=>setTimeout(()=>resolve('resource'),100)),async()=>writeFile(${JSON.stringify(marker)},'closed')).catch(()=>{});
    console.log('ready');setInterval(()=>{},1000);`;
  const child=start(process.execPath,['--input-type=module','-e',script],{detached:true,stdio:['ignore','pipe','pipe']});
  const exited=once(child,'exit');
  try {await firstLine(child);child.kill('SIGTERM');assert.equal((await exited)[0],143);assert.equal(await readFile(marker,'utf8'),'closed');}
  finally {await stop(child,{timeout:30});await rm(dir,{recursive:true,force:true});}
});

test('invalid helper JSON and helper spawn errors reject through the cleanup path',async()=>{
  for(const cmd of [process.execPath,'/missing-conformance-helper']) {
    const child=start(cmd,['-e',"console.log('not JSON');setInterval(()=>{},1000)"],{detached:true,stdio:['ignore','pipe','pipe']});
    try {await assert.rejects(helperConnection(child,1000),cmd===process.execPath?/invalid helper connection JSON/:/ENOENT/);}
    finally {await stop(child,{timeout:30});}
  }
});

test('a second signal interrupts a hung cleanup',async()=>{
  const script=`import {ShutdownScope} from ${JSON.stringify(moduleURL)};
    const scope=new ShutdownScope();scope.add('hung',()=>{console.log('cleaning');return new Promise(()=>{});});console.log('ready');setInterval(()=>{},1000);`;
  const child=start(process.execPath,['--input-type=module','-e',script],{detached:true,stdio:['ignore','pipe','pipe']});
  const exited=once(child,'exit');
  try {
    await firstLine(child);const cleaning=firstLine(child);child.kill('SIGTERM');await cleaning;child.kill('SIGINT');
    assert.equal((await exited)[0],130);
  } finally {await stop(child,{timeout:30});}
});

test('stop does not send termination signals to an absent process group',async()=>{
  const child=start(process.execPath,['-e',''],{detached:true,stdio:'ignore'});
  await once(child,'exit');
  const original=process.kill;const signals=[];
  try {process.kill=(...args)=>{signals.push(args);return original(...args);};await stop(child);assert.deepEqual(signals,[[-child.pid,0]]);}
  finally {process.kill=original;}
});

for(const early of [false,true])test('stop waits for a resistant group member after leader exit '+(early?'before stop':'during stop'),async()=>{
  const worker=`process.on('SIGTERM',()=>{});const s=require('node:net').createServer();s.listen(0,'127.0.0.1',()=>console.log(JSON.stringify({pid:process.pid,port:s.address().port})));`;
  const script=`const {spawn}=require('node:child_process');
    process.on('SIGTERM',()=>process.exit(0));
    const child=spawn(process.execPath,['-e',${JSON.stringify(worker)}],{stdio:['ignore','pipe','inherit']});
    child.stdout.once('data',text=>{process.stdout.write(text,()=>{if(${early})process.exit(0);});});`;
  const child=start(process.execPath,['-e',script],{detached:true,stdio:['ignore','pipe','pipe']});
  const exited=once(child,'exit');
  try {
    const member=JSON.parse(await firstLine(child));
    if(early)await exited;
    assert(exists(member.pid));assert.doesNotThrow(()=>process.kill(-child.pid,0));
    await stop(child,{timeout:80});
    assert.throws(()=>process.kill(-child.pid,0),{code:'ESRCH'});
    assert(!exists(member.pid),'group member survived cleanup');
    const socket=(await import('node:net')).connect(member.port,'127.0.0.1');
    await assert.rejects(once(socket,'connect'),{code:'ECONNREFUSED'});socket.destroy();
    await stop(child,{timeout:80});
  } finally {try {process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}await stop(child,{timeout:80});}
});

test('a failure during cleanup is reported, not discarded',async()=>{
  const script=`import {ShutdownScope} from ${JSON.stringify(moduleURL)};
    const scope=new ShutdownScope();
    scope.add('slow',()=>{setTimeout(()=>{throw new Error('late fixture failure');},20);return new Promise(resolve=>setTimeout(resolve,200));});
    console.log('ready');setInterval(()=>{},1000);`;
  const child=start(process.execPath,['--input-type=module','-e',script],{detached:true,stdio:['ignore','pipe','pipe']});
  let errors='';child.stderr.on('data',chunk=>{errors+=chunk;});const exited=once(child,'exit');
  try {await firstLine(child);child.kill('SIGTERM');assert.equal((await exited)[0],143);assert.match(errors,/During cleanup: Error: late fixture failure/);}
  finally {await stop(child,{timeout:30});}
});

// A fake `podman` on PATH records its PID and listens where `system service` is told to.
const fakePodman=(dir,listen=true)=>writeFile(join(dir,'podman'),'#!'+process.execPath+'\n'+`
  require('node:fs').writeFileSync(process.env.CONFORMANCE_MARKER,String(process.pid));
  ${listen?"require('node:net').createServer().listen(process.argv.at(-1).slice(7));":''}
  setInterval(()=>{},1000);`,{mode:0o755});
const miniflare=()=>'DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "cloudflare/sidecar:tag"';

test('egress image: an explicit setting wins; otherwise Miniflare names it, qualified for Podman',()=>{
  assert.equal(egressImage({MINIFLARE_CONTAINER_EGRESS_IMAGE:'registry.example/custom:tag'},()=>{throw new Error('lookup must be skipped');}),'registry.example/custom:tag');
  assert.equal(egressImage({},miniflare),'docker.io/cloudflare/sidecar:tag');
  assert.equal(egressImage({},()=>'DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "registry.example/sidecar:tag"'),'registry.example/sidecar:tag');
});

for(const missing of ['declaration','file'])test('missing egress '+missing+' fails before the service starts and leaves the environment alone',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-egress-')),marker=join(dir,'pid');
  const env={PATH:dir,CONFORMANCE_MARKER:marker};
  try {
    await fakePodman(dir);
    const readMiniflare=missing==='file'?()=>{throw Object.assign(new Error('absent'),{code:'ENOENT'});}:()=>'export const unrelated = "fixture";';
    await assert.rejects(startPodman(env,{socket:join(dir,'engine.sock'),readMiniflare}),missing==='file'?{code:'ENOENT'}:/Miniflare egress image not found/);
    await assert.rejects(readFile(marker),{code:'ENOENT'});
    assert.deepEqual(env,{PATH:dir,CONFORMANCE_MARKER:marker});
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('the service publishes engine settings once its socket exists, and close stops it',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-podman-')),marker=join(dir,'pid'),socket=join(dir,'engine.sock');let service;
  const env={PATH:dir,CONFORMANCE_MARKER:marker};
  try {
    await fakePodman(dir);
    service=await startPodman(env,{socket,readMiniflare:miniflare});
    assert.equal(env.WRANGLER_DOCKER_HOST,'unix://'+socket);
    assert.match(env.WRANGLER_DOCKER_BIN,/scripts\/podman-docker\.sh$/);
    assert.equal(env.MINIFLARE_CONTAINER_EGRESS_IMAGE,'docker.io/cloudflare/sidecar:tag');
    const pid=Number(await readFile(marker,'utf8'));
    await service.close();service=null;
    assert(!exists(pid),'Podman service survived close');
  } finally {await service?.close();await rm(dir,{recursive:true,force:true});}
});

test('an existing socket is refused, and a service that never listens is stopped at the deadline',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-podman-strict-')),marker=join(dir,'pid');
  const env={PATH:dir,CONFORMANCE_MARKER:marker};
  try {
    await writeFile(join(dir,'taken.sock'),'');
    await assert.rejects(startPodman(env,{socket:join(dir,'taken.sock'),readMiniflare:miniflare}),/already exists/);
    await fakePodman(dir,false);
    await assert.rejects(startPodman(env,{socket:join(dir,'engine.sock'),readMiniflare:miniflare,startupTimeout:300}),/did not start/);
    const pid=Number(await readFile(marker,'utf8'));
    assert(!exists(pid),'timed-out Podman service survived');
    assert(!Object.hasOwn(env,'WRANGLER_DOCKER_HOST'));
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('helper startup stderr survives its failed connection announcement in the runner log',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-helper-log-')),path=join(dir,'server.log');
  const log=await open(path,'w');let child;
  try {
    child=start(process.execPath,['-e',"console.error('openat2 fixture failure');process.exit(1)"],{stdio:['ignore','pipe',log.fd]});
    await assert.rejects(helperConnection(child),/helper exited/);
    assert.match(await readFile(path,'utf8'),/openat2 fixture failure/);
  } finally {await stop(child);await log.close();await rm(dir,{recursive:true,force:true});}
});
