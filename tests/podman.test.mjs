// The shared Podman bootstrap (scripts/podman.mjs), with a fake `podman` on PATH.
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { start, stop } from '../scripts/process.mjs';
import { startPodman, egressImage, configureWrangler } from '../scripts/podman.mjs';
const exists=pid=>{try {process.kill(pid,0);return true;}catch(error) {if(error.code==='ESRCH')return false;throw error;}};
const waitFor=async(condition,timeout=5000)=>{const until=Date.now()+timeout;while(!await condition()) {if(Date.now()>until)throw new Error('condition not reached');await new Promise(r=>setTimeout(r,20));}};
const podmanModule=new URL('../scripts/podman.mjs',import.meta.url).href;
// Records its PID, then listens where `system service` is told to (or exits, or never listens).
const fakePodman=(dir,mode='listen')=>writeFile(join(dir,'podman'),'#!'+process.execPath+'\n'+`
  require('node:fs').writeFileSync(process.env.CONFORMANCE_MARKER,String(process.pid));
  ${mode==='listen'?"require('node:net').createServer().listen(process.argv.at(-1).slice(7));":mode==='exit'?'process.exit(1);':''}
  setInterval(()=>{},1000);`,{mode:0o755});
const miniflare=()=>'DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "cloudflare/sidecar:tag"';
const fixture=async name=>{const dir=await mkdtemp(join(tmpdir(),name));return {dir,marker:join(dir,'pid'),env:{PATH:dir,CONFORMANCE_MARKER:join(dir,'pid')}};};
const servicePid=async marker=>{let pid;await waitFor(async()=>{pid=Number(await readFile(marker,'utf8').catch(()=>''));return pid>0;});return pid;};

test('egress image: an explicit setting wins; Miniflare names it otherwise; strict decides what a missing one means',()=>{
  assert.equal(egressImage({MINIFLARE_CONTAINER_EGRESS_IMAGE:'registry.example/custom:tag'},{readMiniflare:()=>{throw new Error('lookup must be skipped');}}),'registry.example/custom:tag');
  assert.equal(egressImage({},{readMiniflare:miniflare}),'docker.io/cloudflare/sidecar:tag');
  assert.equal(egressImage({},{readMiniflare:()=>'DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "registry.example/sidecar:tag"'}),'registry.example/sidecar:tag');
  for(const readMiniflare of [()=>'export const unrelated = "fixture";',()=>{throw Object.assign(new Error('absent'),{code:'ENOENT'});}]) {
    // Development keeps containers and skips only the override; the harness stops.
    assert.equal(egressImage({},{readMiniflare}),undefined);
    assert.throws(()=>egressImage({},{strict:true,readMiniflare}));
  }
});

test('Wrangler is pointed at the socket, with the shim and the egress image',()=>{
  const env={};configureWrangler(env,{host:'/run/proxy.sock',egress:'docker.io/cloudflare/sidecar:tag'});
  assert.equal(env.WRANGLER_DOCKER_HOST,'unix:///run/proxy.sock');assert.match(env.WRANGLER_DOCKER_BIN,/scripts\/podman-docker\.sh$/);
  assert.equal(env.MINIFLARE_CONTAINER_EGRESS_IMAGE,'docker.io/cloudflare/sidecar:tag');
  const plain={};configureWrangler(plain,{host:'/run/proxy.sock'});assert(!Object.hasOwn(plain,'MINIFLARE_CONTAINER_EGRESS_IMAGE'));
});

test('the service runs in its own process group, leaves the environment alone, and close stops it',async()=>{
  const {dir,marker,env}=await fixture('podman-start-');let service;
  try {
    await fakePodman(dir);
    service=await startPodman(env,{socket:join(dir,'engine.sock')});
    assert.equal(service.socket,join(dir,'engine.sock'));assert.deepEqual(Object.keys(env),['PATH','CONFORMANCE_MARKER']);
    const pid=await servicePid(marker);
    // Not in this process's group: a terminal signal to the owner's group never reaches it.
    assert.notEqual(Number((await readFile(`/proc/${pid}/stat`,'utf8')).split(') ')[1].split(' ')[2]),Number((await readFile('/proc/self/stat','utf8')).split(') ')[1].split(' ')[2]));
    await service.close();service=null;
    assert(!exists(pid),'Podman service survived close');
  } finally {await service?.close();await rm(dir,{recursive:true,force:true});}
});

test('an existing socket is refused; a service that exits or never listens fails, and is stopped',async()=>{
  const {dir,marker,env}=await fixture('podman-strict-');
  try {
    await writeFile(join(dir,'taken.sock'),'');
    await assert.rejects(startPodman(env,{socket:join(dir,'taken.sock')}),/already exists/);
    await fakePodman(dir,'exit');
    await assert.rejects(startPodman(env,{socket:join(dir,'exits.sock')}),/exited before opening its socket/);
    await fakePodman(dir,'silent');
    await assert.rejects(startPodman(env,{socket:join(dir,'silent.sock'),startupTimeout:300}),/did not start/);
    assert(!exists(await servicePid(marker)),'timed-out Podman service survived');
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('allowLate keeps a service still opening its socket at the deadline',async()=>{
  const {dir,marker,env}=await fixture('podman-late-');let service;
  try {
    await fakePodman(dir,'silent');
    service=await startPodman(env,{socket:join(dir,'late.sock'),startupTimeout:100,allowLate:true});
    const pid=await servicePid(marker);assert(exists(pid));
    await service.close();service=null;assert(!exists(pid));
  } finally {await service?.close();await rm(dir,{recursive:true,force:true});}
});

test('the service stops when its owner is killed outright',async()=>{
  const {dir,marker,env}=await fixture('podman-owner-');let owner;
  try {
    await fakePodman(dir);
    const script=`import {startPodman} from ${JSON.stringify(podmanModule)};
      await startPodman(process.env,{socket:${JSON.stringify(join(dir,'owned.sock'))}});console.log('ready');setInterval(()=>{},1000);`;
    owner=start(process.execPath,['--input-type=module','-e',script],{env:{...process.env,...env,PATH:dir+':'+process.env.PATH},stdio:['ignore','pipe','inherit']});
    await once(owner.stdout,'data');
    const pid=await servicePid(marker);assert(exists(pid));
    owner.kill('SIGKILL');
    await waitFor(()=>!exists(pid));
  } finally {await stop(owner);await rm(dir,{recursive:true,force:true});}
});
