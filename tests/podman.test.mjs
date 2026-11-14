// The shared Podman bootstrap (scripts/podman.mjs), with a fake `podman` on PATH.
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { start, stop, startTime } from '../scripts/process.mjs';
import { startPodman, egressImage, configureWrangler, sessionDirectory } from '../scripts/podman.mjs';
import { exists, waitFor, fakePodman, eventLines, podmanPid } from './helpers.mjs';
const podmanModule=new URL('../scripts/podman.mjs',import.meta.url).href;
const miniflare=()=>'DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "cloudflare/sidecar:tag"';
// The fake podman comes first on PATH; the system part provides `sleep` for the lifeline.
async function fixture(mode) {
  const dir=await mkdtemp(join(tmpdir(),'podman-test-')),events=join(dir,'events');
  if(mode)await fakePodman(dir,mode);
  return {dir,events,env:{PATH:dir+':/usr/bin:/bin',FAKE_EVENTS:events},done:()=>rm(dir,{recursive:true,force:true})};
}
const pgrp=async pid=>Number((await readFile(`/proc/${pid}/stat`,'utf8')).split(') ')[1].split(' ')[2]);

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
  const f=await fixture('listen');let service;
  try {
    service=await startPodman(f.env,{socket:join(f.dir,'engine.sock')});
    assert.equal(service.socket,join(f.dir,'engine.sock'));assert.equal(service.late,false);assert.equal(await service.ready,true);
    assert.deepEqual(Object.keys(f.env),['PATH','FAKE_EVENTS']);
    const pid=await podmanPid(f.events);
    // Not in this process's group: a terminal signal to the owner's group never reaches it.
    assert.notEqual(await pgrp(pid),await pgrp(process.pid));
    await service.close();service=null;
    assert(!exists(pid),'Podman service survived close');
    assert((await eventLines(f.events)).includes('podman-stopped'));
  } finally {await service?.close();await f.done();}
});

test('an existing socket is refused; a service that exits or never listens fails, and is stopped',async()=>{
  const f=await fixture();
  try {
    await writeFile(join(f.dir,'taken.sock'),'');
    await assert.rejects(startPodman(f.env,{socket:join(f.dir,'taken.sock')}),/already exists/);
    await fakePodman(f.dir,'exit');
    await assert.rejects(startPodman(f.env,{socket:join(f.dir,'exits.sock')}),/exited before opening its socket/);
    await rm(f.events,{force:true});await fakePodman(f.dir,'silent');
    await assert.rejects(startPodman(f.env,{socket:join(f.dir,'silent.sock'),startupTimeout:300}),/did not start/);
    assert(!exists(await podmanPid(f.events)),'timed-out Podman service survived');
  } finally {await f.done();}
});

for(const [mode,expected] of [['late',true],['late-exit',false]])test(`allowLate: a service past its deadline reports ${expected?'when it listens':'that it exited'}`,async()=>{
  const f=await fixture(mode);let service;
  try {
    service=await startPodman(f.env,{socket:join(f.dir,'late.sock'),startupTimeout:50,allowLate:true});
    assert.equal(service.late,true);
    assert.equal(await service.ready,expected);
    await service.close();service=null;
  } finally {await service?.close();await f.done();}
});

for(const mode of ['listen','stubborn'])test(`the service stops when its owner is killed outright${mode==='stubborn'?', with SIGKILL if it ignores SIGTERM':''}`,async()=>{
  const f=await fixture(mode);let owner;
  try {
    const script=`import {startPodman} from ${JSON.stringify(podmanModule)};
      await startPodman(process.env,{socket:${JSON.stringify(join(f.dir,'owned.sock'))}});console.log('ready');setInterval(()=>{},1000);`;
    owner=start(process.execPath,['--input-type=module','-e',script],{env:{...process.env,...f.env},stdio:['ignore','pipe','inherit']});
    await once(owner.stdout,'data');
    const pid=await podmanPid(f.events);assert(exists(pid));
    owner.kill('SIGKILL');
    await waitFor(()=>!exists(pid),mode==='stubborn'?9000:4000);
    assert((await eventLines(f.events)).includes('podman-got-SIGTERM'));
  } finally {await stop(owner);await f.done();}
});

test('session directories record their owner; those of dead owners are swept',async()=>{
  const base=await mkdtemp(join(tmpdir(),'podman-sessions-'));
  try {
    const dead=start(process.execPath,['-e','setTimeout(()=>{},100)'],{stdio:'ignore'});
    await waitFor(()=>startTime(dead.pid));const deadStart=startTime(dead.pid);await once(dead,'exit');
    const make=async(name,owner)=>{await mkdir(join(base,name),{mode:0o700});if(owner)await writeFile(join(base,name,'owner.json'),JSON.stringify(owner));};
    await make('os-podman-Dead01',{pid:dead.pid,start:deadStart});
    await make('os-podman-Live01',{pid:process.pid,start:startTime(process.pid)});
    await make('os-podman-NoOwnr',null);
    await writeFile(join(base,`os-podman-${process.getuid()}.sock`),'');
    const dir=sessionDirectory(base);
    const owner=JSON.parse(await readFile(join(dir,'owner.json'),'utf8'));
    assert.deepEqual(owner,{pid:process.pid,start:startTime(process.pid)});
    const names=(await readdir(base)).sort();
    assert(!names.includes('os-podman-Dead01'));
    for(const kept of ['os-podman-Live01','os-podman-NoOwnr',`os-podman-${process.getuid()}.sock`])assert(names.includes(kept),kept);
  } finally {await rm(base,{recursive:true,force:true});}
});
