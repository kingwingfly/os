import test from 'node:test';
import assert from 'node:assert/strict';
import { once, EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { mkdtemp, writeFile, readFile, rm, open } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { start, stop, ShutdownScope } from '../scripts/conformance/process.mjs';
import { startPodman, egressImage } from '../scripts/conformance/podman.mjs';
import { helperConnection } from '../scripts/conformance/fixtures.mjs';
import { recoverInterrupted, startTime, RunRecord, runPrefix } from '../scripts/conformance/recovery.mjs';
import { mkdir } from 'node:fs/promises';
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

// Records every signal stop() sends, without changing what is sent.
const recording=()=>{const signals=[];return {signals,kill:(...args)=>{signals.push(args);return process.kill(...args);}};};
const waitFor=async(condition,timeout=5000)=>{const until=Date.now()+timeout;while(!condition()){if(Date.now()>until)throw new Error('condition not reached');await new Promise(r=>setTimeout(r,20));}};

test('a group already empty when its leader exits is never signalled',async()=>{
  const child=start(process.execPath,['-e',''],{detached:true,stdio:'ignore'});
  await once(child,'exit');
  assert.equal(child.groupGone,true);
  const {signals,kill}=recording();await stop(child,{kill});assert.deepEqual(signals,[]);
});

test('a group whose last member exits after the leader is never signalled again',async()=>{
  // The leader exits at once; its member lives 300 ms, then the group is empty.
  const script=`require('node:child_process').spawn(process.execPath,['-e','setTimeout(()=>{},300)'],{stdio:'ignore'}).unref();`;
  const child=start(process.execPath,['-e',script],{detached:true,stdio:'ignore'});
  await once(child,'exit');
  assert.notEqual(child.groupGone,true,'member should still be running');
  await waitFor(()=>child.groupGone===true);
  const {signals,kill}=recording();await stop(child,{kill});assert.deepEqual(signals,[]);
});

test('a reused group number is never signalled',async()=>{
  // An unrelated live group stands in for one that has taken over our reaped leader's number.
  const unrelated=start(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});
  try {
    await waitFor(()=>existsSync('/proc/'+unrelated.pid));
    const ours=Object.assign(new EventEmitter(),{pid:unrelated.pid,processGroup:true,exitCode:0,signalCode:null});
    const {signals,kill}=recording();await stop(ours,{kill});
    assert.deepEqual(signals,[]);assert(exists(unrelated.pid),'unrelated group was signalled');
  } finally {await stop(unrelated,{timeout:30});}
});

test('escalation is bounded: survivors are reported and dependents retained',async()=>{
  // A group that never disappears, as with a member in uninterruptible I/O.
  const stuck=Object.assign(new EventEmitter(),{pid:process.pid,processGroup:true,exitCode:null,signalCode:null});
  const signals=[];const kill=(...args)=>{signals.push(args[1]);};
  const error=await stop(stuck,{timeout:20,killTimeout:60,kill}).then(()=>null,error=>error);
  assert.match(error?.message??'',/process group \d+ still running 60 ms after SIGKILL/);
  assert.equal(error.retainDependents,true);assert(Array.isArray(error.survivors));
  assert.equal(signals[1],'SIGTERM');assert(signals.includes('SIGKILL'));
});

test('a failed stop is retried by the next call, as after a transient EPERM',async()=>{
  const gone=start(process.execPath,['-e',''],{stdio:'ignore'});await once(gone,'exit');
  const target=Object.assign(new EventEmitter(),{pid:gone.pid,processGroup:true,exitCode:null,signalCode:null});
  await assert.rejects(stop(target,{kill:()=>{throw Object.assign(new Error('not permitted'),{code:'EPERM'});}}),{code:'EPERM'});
  target.exitCode=0;
  const calls=[];await stop(target,{kill:(...args)=>{calls.push(args);throw Object.assign(new Error('absent'),{code:'ESRCH'});}});
  assert.equal(calls.length,1);assert.equal(target.groupGone,true);
});

test('a scope keeps what a process that could not be stopped may still use',async()=>{
  const scope=new ShutdownScope();const disposed=[];
  scope.add('image store',()=>{disposed.push('image store');});
  scope.add('notice',()=>{disposed.push('notice');},{always:true});
  scope.add('engine',()=>{disposed.push('engine');});
  scope.add('server',()=>{throw Object.assign(new Error('still running'),{retainDependents:true});});
  scope.add('browser',()=>{disposed.push('browser');});
  const errors=await scope.close();
  assert.deepEqual(disposed,['browser','notice']);
  assert.deepEqual(errors.map(e=>[e.name,e.error.message]),[['server','still running'],['engine','retained because server is still running'],['image store','retained because server is still running']]);
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

test('recovery stops only the proven groups of runs whose runner has died, once',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-recovery-')),fake=join(dir,'bin');const owned=[];
  const longLived=()=>{const child=start(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});owned.push(child);return child;};
  try {
    // The interrupted run: its runner has exited.
    const runner=start(process.execPath,['-e','setTimeout(()=>{},100)'],{stdio:'ignore'});
    await waitFor(()=>startTime(runner.pid));const runnerStart=startTime(runner.pid);await once(runner,'exit');
    const server=longLived(),impostor=longLived();
    // A group whose leader has exited while a member still runs.
    const leader=start(process.execPath,['-e',`require('node:child_process').spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'}).unref();setTimeout(()=>{},100)`],{detached:true,stdio:'ignore'});
    owned.push(leader);await waitFor(()=>startTime(leader.pid));const leaderStart=startTime(leader.pid);await once(leader,'exit');
    await waitFor(()=>startTime(server.pid)&&startTime(impostor.pid));
    const dead=join(dir,runPrefix+'dead');await mkdir(dead);
    await writeFile(join(dead,'storage.conf'),'[storage]\n');
    // A process of the run that is in no recorded group, as the browser is: its command line names the state directory.
    const browser=start(process.execPath,['-e','setInterval(()=>{},1000)','--',join(dead,'profile')],{detached:true,stdio:'ignore'});owned.push(browser);
    await waitFor(()=>startTime(browser.pid));
    await writeFile(join(dead,'run.json'),JSON.stringify({runner:{pid:runner.pid,start:runnerStart},containers:{engine:'podman',label:'os.conformance.run=x'},groups:[
      {name:'server',pid:server.pid,start:startTime(server.pid)},
      {name:'impostor',pid:impostor.pid,start:'1'},
      {name:'helper',pid:leader.pid,start:leaderStart},
    ]}));
    // A live run (this process) is never touched.
    const live=join(dir,runPrefix+'live');await mkdir(live);
    const record=new RunRecord(live);await record.addGroup('server',impostor.pid);
    // A fake podman lists the containers it removed, and the storage configuration it used.
    await mkdir(fake);
    await writeFile(join(fake,'podman'),'#!'+process.execPath+'\nconsole.log("c1\\nc2");require("node:fs").writeFileSync(process.env.CONTAINERS_STORAGE_CONF+".used",process.argv.slice(2).join(" "));\n',{mode:0o755});
    const recovered=await recoverInterrupted({dir,env:{PATH:fake},timeout:500});
    assert.equal(recovered.length,1);const [run]=recovered;
    assert.equal(run.state,dead);assert.deepEqual(run.stopped,['server']);assert.deepEqual(run.survived,[]);
    assert.deepEqual(run.unverified.sort(),['helper','impostor']);assert.deepEqual(run.containers,{removed:2});
    assert.deepEqual(run.processes,{stopped:1,remaining:0});await waitFor(()=>!exists(browser.pid));
    assert.match(await readFile(join(dead,'storage.conf.used'),'utf8'),/rm --all --force --time 0/);
    await waitFor(()=>!exists(server.pid));
    assert(exists(impostor.pid),'a group not proved to be the run\'s own was signalled');
    assert.deepEqual(await recoverInterrupted({dir,env:{PATH:fake},timeout:500}),[]);
  } finally {
    for(const child of owned)try {process.kill(-child.pid,'SIGKILL');}catch {}
    await rm(dir,{recursive:true,force:true});
  }
});
