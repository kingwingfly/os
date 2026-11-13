import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { conformanceConfig, putFile, attempt, reattachAfter, unmountOutcome } from '../scripts/conformance/fixtures.mjs';
import { podmanEnvironment } from '../scripts/podman.mjs';
import { saveRun } from '../scripts/conformance/results.mjs';
import { run, revision } from '../scripts/conformance/common.mjs';

test('temporary configuration uses absolute paths, removes build/archive sections and rejects drift',async()=>{
  const source=await readFile('wrangler.toml','utf8');
  const config=conformanceConfig(source,'/tmp/repository');
  assert.match(config,/main = "\/tmp\/repository\/crates\/worker\/entry.js"/);
  assert.match(config,/directory = "\/tmp\/repository\/dist"/);
  assert(!config.includes('[build]'));assert(!config.includes('command = "worker-build'));
  assert(!config.includes('containers/jobs'));assert(!config.includes('watch_dir ='));
  assert.equal((config.match(/image_build_context/g)||[]).length,1);
  assert.doesNotThrow(()=>conformanceConfig(source.replace('"crates/worker/entry.js"','"./crates/worker/entry.js"'),'/tmp/repository'));
  const build=source.match(/\[build\][\s\S]*?(?=\n\[)/)[0];
  assert(!conformanceConfig(source.replace(build,'')+'\n'+build,'/tmp/repository').includes('watch_dir'));
  for(const bad of [source.replace('class_name = "JobRunner"\nimage','image'),source.replace('directory = "./dist"','directory = "other"'),source.replaceAll('image_build_context = "."','image_build_context = "other"')])assert.throws(()=>conformanceConfig(bad,'/tmp/repository'),/conformance config/);
});

test('fixture writes use provider chunk sizes and integer indices beyond 64 KiB',async()=>{
  for(const chunk_size of [65536,1024*1024]) {
    const bytes=Buffer.alloc(2*1024*1024+37);for(let i=0;i<bytes.length;i++)bytes[i]=i%251;
    const chunks=[];let closed=false;
    await putFile(async([call])=>{
      if(call.open)return [{fd:7,chunk_size}];
      if(call.pwrite){const p=call.pwrite;assert.equal(p.index,chunks.length);chunks.push(Buffer.from(p.data,'base64'));assert(chunks.at(-1).length<=chunk_size);}
      if(call.close)closed=true;
      return [null];
    },'/fixture',bytes);
    assert(closed);assert.deepEqual(Buffer.concat(chunks),bytes);
  }
});

test('EBUSY is recorded and keeps the original attachment; successful detach reattaches once',async()=>{
  let attaches=0;
  const busy=await attempt('remount','detach','umount(mount)',()=>{throw {errno:'EBUSY'};});
  await reattachAfter(busy,()=>attaches++);assert.equal(attaches,0);assert.equal(busy.errno,'EBUSY');
  const detached=await attempt('remount','detach','umount(mount)',()=>{});
  await reattachAfter(detached,()=>attaches++);assert.equal(attaches,1);
});

test('shared Podman bootstrap respects configured egress images',()=>{
  const custom={MINIFLARE_CONTAINER_EGRESS_IMAGE:'registry.example/custom:tag'};
  podmanEnvironment(custom,'/tmp/proxy.sock','DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "cloudflare/sidecar:tag"');
  assert.equal(custom.MINIFLARE_CONTAINER_EGRESS_IMAGE,'registry.example/custom:tag');
  const defaults={};podmanEnvironment(defaults,'/tmp/proxy.sock','DEFAULT_CONTAINER_EGRESS_INTERCEPTOR_IMAGE = "cloudflare/sidecar:tag"');
  assert.equal(defaults.MINIFLARE_CONTAINER_EGRESS_IMAGE,'docker.io/cloudflare/sidecar:tag');
});

test('browser detach errors retain errno across a serialization boundary',async()=>{
  const original=globalThis.window;
  globalThis.window={os:{unmountLocal:()=>{throw {errno:'EBUSY',message:'busy mount'};}}};
  try {
    // Only plain returned data crosses the browser boundary; throwing would
    // lose errno and surface as a generic Playwright Error instead.
    assert.deepEqual(JSON.parse(JSON.stringify(await unmountOutcome('/mount'))),{errno:'EBUSY'});
  } finally {if(original===undefined)delete globalThis.window;else globalThis.window=original;}
});

test('provenance records HEAD and dirtiness without any remote-tracking reference',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-git-'));
  try {
    run('git',['init','--quiet',dir]);await writeFile(join(dir,'source'),'one');
    run('git',['add','source'],{cwd:dir});
    run('git',['-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--quiet','-m','fixture'],{cwd:dir});
    assert.deepEqual(revision(dir),{head:run('git',['rev-parse','HEAD'],{cwd:dir}).trim(),dirty:false});
    await writeFile(join(dir,'source'),'two');assert.equal(revision(dir).dirty,true);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('essential baseline is saved before auxiliary evidence even when an auxiliary save fails',async()=>{
  const writes=[],baseline={schema:1,linux:[],os:{}};
  await assert.rejects(saveRun('/unused',baseline,'os',{observations:{cloud:[]},latencies:{}},{revision:{head:'fixture',dirty:false}},async(_out,name)=>{writes.push(name);if(name==='evidence.json')throw new Error('disk failure');}),/disk failure/);
  assert.deepEqual(writes,['baseline.json','latency.json','evidence.json']);
  assert.deepEqual(baseline.os,{cloud:[]});
});

test('all ABI errno names are covered by the probe mapping (ENODATA uses the named ABI on WASI)',async()=>{
  const abi=await readFile('crates/abi/src/lib.rs','utf8'),platform=await readFile('crates/conformance/src/platform.rs','utf8');
  for(const name of abi.split('pub enum Errno {')[1].split('}')[0].match(/E[A-Z0-9]+/g))assert(platform.includes(`"${name}"`),name);
});
