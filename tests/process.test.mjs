import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import { mkdtemp, writeFile, readFile, rm, symlink, stat, open } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { start, stop } from '../scripts/process.mjs';
import { startPodman, socketLive, podmanEnvironment } from '../scripts/podman.mjs';
import { helperConnection } from '../scripts/conformance/fixtures.mjs';
const moduleURL=new URL('../scripts/process.mjs',import.meta.url).href;
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

test('dev starts Wrangler after optional Podman failure; strict bootstrap times out and cleans its child',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-dev-'));
  const env={...process.env,PATH:dir,TMPDIR:dir,CONFORMANCE_NPX_LOG:join(dir,'npx.log')};
  delete env.DOCKER_HOST;delete env.WRANGLER_DOCKER_HOST;
  try {
    await symlink('/bin/sh',join(dir,'sh'));
    await writeFile(join(dir,'podman'),'#!/bin/sh\nexit 1\n',{mode:0o755});
    await writeFile(join(dir,'npx'),'#!/bin/sh\nprintf "%s\\n" "$@" > "$CONFORMANCE_NPX_LOG"\n',{mode:0o755});
    const child=start(process.execPath,['scripts/dev.mjs','--port','12345'],{env,stdio:['ignore','pipe','pipe']});
    let error='';child.stderr.on('data',chunk=>{error+=chunk;});
    assert.equal((await once(child,'exit'))[0],0);
    assert.match(error,/Podman unavailable; starting Wrangler/);
    assert.deepEqual((await readFile(env.CONFORMANCE_NPX_LOG,'utf8')).trim().split('\n'),['wrangler','dev','--port','12345']);
    await writeFile(join(dir,'podman'),'#!/bin/sh\nprintf "%s" "$$" > "$CONFORMANCE_PID"\nexec /bin/sleep 30\n',{mode:0o755});
    const pidfile=join(dir,'pid');
    await assert.rejects(startPodman({...env,CONFORMANCE_PID:pidfile},{socket:join(dir,'podman.sock'),proxySocket:join(dir,'proxy.sock'),detached:true,startupTimeout:50}),/did not start/);
    const pid=await readFile(pidfile,'utf8').catch(error=>{if(error.code!=='ENOENT')throw error;return null;});
    if(pid)assert(!exists(Number(pid))); // A pre-exec timeout may precede the PID write.
  } finally {await rm(dir,{recursive:true,force:true});}
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

test('optional dev bootstrap retains a late Podman service and wires the proxy',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-late-podman-'));let service;
  const env={...process.env,PATH:dir,CONFORMANCE_SOCKET:join(dir,'podman.sock')};
  try {
    await writeFile(join(dir,'podman'),'#!/bin/sh\n/bin/sleep 0.2\n: > "$CONFORMANCE_SOCKET"\nexec /bin/sleep 30\n',{mode:0o755});
    service=await startPodman(env,{socket:env.CONFORMANCE_SOCKET,proxySocket:join(dir,'proxy.sock'),detached:true,startupTimeout:10,allowLate:true});
    assert.equal(env.WRANGLER_DOCKER_HOST,'unix://'+join(dir,'proxy.sock'));
    const until=Date.now()+5000;
    while(true){try {await readFile(env.CONFORMANCE_SOCKET);break;}catch(error){if(error.code!=='ENOENT'||Date.now()>until)throw error;await new Promise(r=>setTimeout(r,20));}}
  } finally {await service?.close();await rm(dir,{recursive:true,force:true});}
});


test('reuse connects without waiting for an API response and never unlinks or owns a live shared socket',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-borrow-')),socket=join(dir,'shared.sock'),marker=join(dir,'invoked');
  const server=http.createServer((_req,res)=>res.end('shared owner'));let borrowed;
  const get=()=>new Promise((resolve,reject)=>{http.get({socketPath:socket,path:'/_ping'},res=>{let value='';res.on('data',c=>{value+=c;});res.on('end',()=>resolve(value));}).on('error',reject);});
  try {
    // The old version probe times out here and then deletes the live socket.
    await writeFile(join(dir,'podman'),'#!/bin/sh\nprintf invoked > "$CONFORMANCE_MARKER"\nexec /bin/sleep 30\n',{mode:0o755});
    server.listen(socket);await once(server,'listening');const inode=(await stat(socket)).ino;
    borrowed=await startPodman({...process.env,PATH:dir,CONFORMANCE_MARKER:marker},{socket,proxySocket:join(dir,'borrow.sock'),reuse:true,detached:true,startupTimeout:30});
    assert.equal((await stat(socket)).ino,inode);assert.equal(await get(),'shared owner');
    await assert.rejects(readFile(marker),{code:'ENOENT'});
    await borrowed.close();borrowed=null;
    assert.equal((await stat(socket)).ino,inode);assert.equal(await get(),'shared owner');
  } finally {await borrowed?.close();await new Promise(resolve=>server.close(resolve));await rm(dir,{recursive:true,force:true});}
});

test('stop never signals a reaped process group',async()=>{
  const child=start(process.execPath,['-e',''],{detached:true,stdio:'ignore'});
  await once(child,'exit');
  const original=process.kill;const signals=[];
  try {process.kill=(...args)=>{signals.push(args);};await stop(child);assert.deepEqual(signals,[]);}
  finally {process.kill=original;}
});

test('stale shared socket gets a private service without unlinking the shared name',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-stale-')),socket=join(dir,'shared.sock');let service;
  const child=start(process.execPath,['-e',`require('node:net').createServer().listen(${JSON.stringify(socket)},()=>console.log('ready'))`],{stdio:['ignore','pipe','pipe']});
  try {
    await firstLine(child);const exited=once(child,'exit');child.kill('SIGKILL');await exited;
    assert.equal(await socketLive(socket),false);const inode=(await stat(socket)).ino;
    await writeFile(join(dir,'podman'),'#!'+process.execPath+'\n'+`require('node:net').createServer().listen(process.argv.at(-1).slice(7));\n`,{mode:0o755});
    service=await startPodman({...process.env,PATH:dir},{socket,proxySocket:join(dir,'proxy.sock'),reuse:true,detached:true});
    assert.notEqual(service.socket,socket);assert.equal(await socketLive(service.socket),true);
    assert.equal((await stat(socket)).ino,inode);
    const owned=service.socket;await service.close();service=null;
    await assert.rejects(stat(owned),{code:'ENOENT'});assert.equal((await stat(socket)).ino,inode);
  } finally {await service?.close();await stop(child);await rm(dir,{recursive:true,force:true});}
});

test('Podman configuration leaves the environment untouched on lookup failure',()=>{
  const env={ORIGINAL:'retained'};
  assert.throws(()=>podmanEnvironment(env,'/tmp/proxy',{}),/match/);
  assert.deepEqual(env,{ORIGINAL:'retained'});
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
