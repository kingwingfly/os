import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, mkdir, rm, chmod, symlink, stat, readdir } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { conformanceConfig, replaceExactly, compilerConfig, compilerImage, isSleep, sameSleep, withCleanup, helperConnection, recordReattach, putFile, mountOutcome, startHeld, resumeHeld, heldState, heldRows, heldProbe } from '../scripts/conformance/fixtures.mjs';
import { saveRun } from '../scripts/conformance/results.mjs';
import { run, revision, ports, generatedFiles, requireProbeSuccess } from '../scripts/conformance/common.mjs';
import { imageStore } from '../scripts/conformance/storage.mjs';
import { relocateManifest, workspaceManifest } from '../scripts/conformance/manifest.mjs';
import { report } from '../scripts/conformance/report.mjs';

test('latency preparation preserves its phase and original errno',()=>{
  for(const phase of ['native latency prepare failed','OS latency prepare failed']) {
    for(const errno of ['ENOSPC','EACCES'])assert.throws(()=>requireProbeSuccess([{case:'latency',step:'prepare',errno}],phase),error=>error.message.includes(phase)&&error.message.includes(errno));
    const prepared=[{case:'latency',step:'prepare',ok:null}];assert.equal(requireProbeSuccess(prepared,phase),prepared);
  }
});

test('artifact writers and provenance use the same complete filename registry',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-artifacts-'));
  const baseline=JSON.parse(await readFile('docs/compat/baseline.json','utf8'));
  try {
    await saveRun(dir,baseline,'linux',{observations:baseline.linux,process:baseline.process.linux,latency:[]},{});
    await saveRun(dir,baseline,'os',{observations:baseline.os,process:baseline.process.os,latencies:{}},{});
    await report(dir);
    assert.deepEqual((await readdir(dir)).sort(),Object.values(generatedFiles).sort());
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('compiler image rejects command flags before invoking the engine',()=>{
  for(const value of ['--privileged','-x','','image;command','image with spaces'])assert.throws(()=>compilerImage(value),/invalid compiler image/);
  for(const value of ['localhost/compiler:baseline','registry.example:5000/compiler@sha256:abcdef'])assert.equal(compilerImage(value),value);
});

test('tab visibility requires matching executable and argv as well as PID',()=>{
  const fixture={pid:42,path:'/usr/bin/sleep',argv:['sleep','60']};
  assert(isSleep(fixture));assert(sameSleep({...fixture},fixture));
  for(const other of [{...fixture,pid:43},{...fixture,path:'/usr/bin/sh',argv:['sh']},{...fixture,argv:['sleep','1']}])assert(!sameSleep(other,fixture));
});

test('readiness diagnostics survive a simultaneous cleanup failure',async()=>{
  const primary=new Error('startup service readiness: {"output":"partial","done":false}'),cleanup=new Error('cleanup timed out');
  await assert.rejects(withCleanup(async()=>{throw primary;},async()=>{throw cleanup;}),error=>{
    assert(error instanceof AggregateError);assert.deepEqual(error.errors,[primary,cleanup]);assert.equal(error.cause,primary);
    assert.match(error.message,/startup service readiness:.*partial/);assert.match(error.message,/cleanup timed out/);return true;
  });
  await assert.rejects(withCleanup(async()=>{},async()=>{throw cleanup;}),error=>error===cleanup);
  await assert.rejects(withCleanup(async()=>{throw primary;},async()=>{}),error=>error===primary);
  assert.equal(await withCleanup(async()=>42,async()=>{}),42);
});

test('image store rejects shared permissions and symlinks before loading images',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-store-'));
  try {
    await assert.rejects(imageStore(''),/OS_CONFORMANCE_PODMAN_DIR must not be empty/);
    const path=join(dir,'images');assert.equal(await imageStore(path),path);
    assert.equal((await stat(path)).mode&0o777,0o700);
    assert.equal(await imageStore(path),path);
    await chmod(path,0o755);await assert.rejects(imageStore(path),/owned directory with mode 0700/);
    await chmod(path,0o700);await symlink(path,join(dir,'link'));
    await assert.rejects(imageStore(join(dir,'link')),/owned directory with mode 0700/);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('server and inspector ports are reserved together and then released',async()=>{
  const selected=await ports(8);assert.equal(new Set(selected).size,8);
  for(const port of selected) {
    const s=createServer();
    try {await new Promise((resolve,reject)=>s.once('error',reject).listen(port,'127.0.0.1',resolve));}
    finally {await new Promise(resolve=>s.close(resolve));}
  }
});

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
  const busy={errno:'EBUSY'};
  await recordReattach([],busy,()=>{attaches++;return {ok:null};},'unmount-open');assert.equal(attaches,0);assert.equal(busy.errno,'EBUSY');
  const detached={ok:null};
  await recordReattach([],detached,()=>{attaches++;return {ok:null};},'unmount-open');assert.equal(attaches,1);
});

test('browser detach errors retain errno across a serialization boundary',async()=>{
  const original=globalThis.window;
  globalThis.window={os:{unmountLocal:()=>{throw {errno:'EBUSY',message:'busy mount'};}}};
  try {
    // Only plain returned data crosses the browser boundary; throwing would
    // lose errno and surface as a generic Playwright Error instead.
    assert.deepEqual(JSON.parse(JSON.stringify(await mountOutcome({operation:'detach',path:'/mount'}))),{errno:'EBUSY'});
  } finally {if(original===undefined)delete globalThis.window;else globalThis.window=original;}
});

test('provenance records HEAD and dirtiness without any remote-tracking reference',async()=>{
  const dir=await mkdtemp(join(tmpdir(),'conformance-git-'));
  try {
    await writeFile(join(dir,'hostile-config'),'[commit]\n gpgSign = true\n[gpg]\n program = /bin/false\n[core]\n hooksPath = /nonexistent/hooks\n[init]\n templateDir = /nonexistent/template\n');
    const env={...process.env,GIT_CONFIG_GLOBAL:join(dir,'hostile-config'),GIT_CONFIG_NOSYSTEM:'1'};
    run('git',['init','--template=','--quiet',dir],{env});
    await writeFile(join(dir,'.git/hostile-config'),await readFile(join(dir,'hostile-config')));await rm(join(dir,'hostile-config'));env.GIT_CONFIG_GLOBAL=join(dir,'.git/hostile-config');await writeFile(join(dir,'source'),'one');
    const out=join(dir,'docs/compat');await mkdir(out,{recursive:true});await writeFile(join(out,'latency.json'),'initial');
    run('git',['add','source','docs/compat/latency.json'],{cwd:dir});
    run('git',['-c','core.hooksPath=/dev/null','-c','commit.gpgSign=false','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--no-gpg-sign','--no-verify','--quiet','-m','fixture'],{cwd:dir,env});
    assert.deepEqual(revision(dir),{head:run('git',['rev-parse','HEAD'],{cwd:dir}).trim(),dirty:false});
    await writeFile(join(out,'latency.json'),'generated');
    assert.equal(revision(dir).dirty,true);assert.equal(revision(dir,out).dirty,false);
    const subdir=join(dir,'nested/runner');await mkdir(subdir,{recursive:true});
    // This is an isolated Git fixture, not the repository's unrelated worktrees.
    await mkdir(join(dir,'.worktrees'));await writeFile(join(dir,'.worktrees/unrelated'),'fixture');
    assert.deepEqual(revision(subdir,out),revision(dir,out));
    const other=join(dir,'out [literal]');await mkdir(other);await writeFile(join(other,'baseline.json'),'generated');
    await writeFile(join(out,'latency.json'),'initial');assert.equal(revision(dir,other).dirty,false);
    assert.equal(revision(dir,dir).dirty,true); // --out=. must not hide the source tree.
    for(const file of ['expected-differences.toml','follow-up-issues.json','README.md','extra-source.mjs']) {
      await writeFile(join(other,file),'manual input');assert.equal(revision(dir,other).dirty,true,file);
      await rm(join(other,file));
    }
    await rm(other,{recursive:true});assert.equal(revision(dir,out).dirty,false);
    await writeFile(join(out,'README.md'),'input');
    run('git',['add','docs/compat/README.md'],{cwd:dir});
    run('git',['-c','core.hooksPath=/dev/null','-c','commit.gpgSign=false','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--no-gpg-sign','--no-verify','--quiet','-m','input'],{cwd:dir,env});
    assert.equal(revision(dir,out).dirty,false);
    await writeFile(join(out,'README.md'),'edited input');assert.equal(revision(dir,out).dirty,true);
    assert.equal(revision(subdir,out).dirty,true);
    await writeFile(join(dir,'source'),'two');assert.equal(revision(dir,other).dirty,true);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('essential baseline is saved before auxiliary evidence even when an auxiliary save fails',async()=>{
  const writes=[],baseline={schema:2,linux:[],os:{},process:{linux:[],os:[]}};
  await assert.rejects(saveRun('/unused',baseline,'os',{observations:{cloud:[]},process:[],latencies:{}},{revision:{head:'fixture',dirty:false}},async(_out,name)=>{writes.push(name);if(name==='evidence.json')throw new Error('disk failure');}),/disk failure/);
  assert.deepEqual(writes,['baseline.json','latency.json','evidence.json']);
  assert.deepEqual(baseline.os,{cloud:[]});
});

test('all ABI errno names are covered by the probe mapping (ENODATA uses the named ABI on WASI)',async()=>{
  const abi=await readFile('crates/abi/src/lib.rs','utf8'),platform=await readFile('crates/conformance/src/platform.rs','utf8');
  for(const name of abi.split('pub enum Errno {')[1].split('}')[0].match(/E[A-Z0-9]+/g))assert(platform.includes(`"${name}"`),name);
});

test('replacement paths preserve dollar replacement tokens for regex and string patterns',async()=>{
  const root="/tmp/$&-$1-$$-$`-$'/repository";
  assert.equal(replaceExactly('x',/x/,root,'test'),root);
  assert.equal(replaceExactly('x','x',root,'test'),root);
  const config=conformanceConfig(await readFile('wrangler.toml','utf8'),root);
  assert(config.includes('directory = '+JSON.stringify(root+'/dist')));
  assert(config.includes('main = '+JSON.stringify(root+'/crates/worker/entry.js')));
});

test('attach and detach errors normalize in the browser before serialization',async()=>{
  const previous=globalThis.window;
  try {
    for(const error of [{errno:'EACCES',message:'variable path'},Object.assign(new Error('variable stack'),{code:'EBUSY'}),new Error('variable URL and stack')]) {
      globalThis.window={os:{mountLocal:()=>{throw error;},attachShared:()=>{throw error;},unmountLocal:()=>{throw error;}}};
      for(const args of [{operation:'attach',filesystem:'browser-storage'},{operation:'attach',filesystem:'relay'},{operation:'detach'}])assert.deepEqual(JSON.parse(JSON.stringify(await mountOutcome(args))),{errno:error.errno||error.code||'UNCLASSIFIED_ERROR'});
    }
  } finally {globalThis.window=previous;}
});

test('held probes preserve early EACCES and launch rejection without waiting for a barrier',async()=>{
  const previous=globalThis.window;
  try {
    for(const reject of [false,true]) {
      globalThis.window={os:{exec:async(_pipeline,options)=>{
        if(reject)throw {errno:'ENOEXEC',message:'variable path'};
        options.onOutput(1,JSON.stringify({case:'unmount-open',step:'open',call:'open(O_RDWR)',errno:'EACCES'})+'\n');
        return {status:0};
      }}};
      startHeld({tool:'/probe',args:[],timeout:1000});await window.conformanceHeld.promise;
      const state=heldState();assert(state.done);assert(!state.timedOut);assert(!state.ready);
      const rows=heldRows(state,'unmount-open',{case:'unmount-open',step:'unmount',call:'umount(mount)',skipped:'early completion'});
      assert.equal(rows[0].errno,reject?'ENOEXEC':'EACCES');assert(rows.at(-1).skipped);
    }
  } finally {globalThis.window=previous;}
});

test('the barrier deadline ends at the barrier; resuming starts the completion deadline',async()=>{
  const previous=globalThis.window;
  try {
    let finish,options;const written=[];
    globalThis.window={os:{exec:(_p,o)=>{options=o;return new Promise(resolve=>{finish=resolve;});}}};
    startHeld({tool:'/probe',args:[],timeout:20});await Promise.resolve();
    options.onTty({write:text=>written.push(text)});options.onOutput(1,'{"barrier":"unmount-open"}\n');assert(heldState().ready);
    // Waiting at the barrier (while the runner detaches) is not the probe's timeout.
    await new Promise(resolve=>setTimeout(resolve,40));assert.equal(heldState().timedOut,null);assert(!options.cancelled());
    resumeHeld({timeout:20});assert.deepEqual(written,['continue\n']);
    await new Promise(resolve=>setTimeout(resolve,40));assert.equal(heldState().timedOut,'completion');assert(options.cancelled());
    finish({status:130});await window.conformanceHeld.promise;
    assert.equal(heldRows(heldState(),'unmount-open',{skipped:'timeout'}).find(r=>r.step==='completion').errno,'ETIMEDOUT');
  } finally {globalThis.window=previous;}
});

// A page whose evaluate runs the browser functions here, against a fake window.os.
const fakePage={
  evaluate:async(fn,arg)=>fn(arg),
  waitForFunction:async(fn,_arg,{timeout})=>{
    const until=Date.now()+timeout;
    while(!fn()) {if(Date.now()>until)throw Object.assign(new Error(`Timeout ${timeout}ms exceeded.`),{name:'TimeoutError'});await new Promise(r=>setTimeout(r,5));}
    return true;
  },
};
// A fake held probe. barrier: print the barrier; resume: finish after `continue`; obeyCancel: exit when cancelled.
function fakeOs({barrier=true,resume=true,obeyCancel=true,detach=async()=>{}}) {
  return {unmountLocal:detach,exec:(_p,o)=>new Promise(resolve=>{
    let input='';
    o.onTty({write:text=>{input+=text;if(resume&&input.includes('continue')) {o.onOutput(1,JSON.stringify({case:'unmount-open',step:'read',call:'pread(fd) after detach',ok:'hello'})+'\n');resolve({status:0});}}});
    if(barrier)o.onOutput(1,'{"barrier":"unmount-open"}\n');
    const poll=setInterval(()=>{if(obeyCancel&&o.cancelled()){clearInterval(poll);resolve({status:130});}},5);
    poll.unref?.();
  })};
}
const heldCase=extra=>heldProbe(fakePage,{tool:'/probe',args:[],caseName:'unmount-open',path:'/mnt/local/primary',barrierTimeout:50,detachTimeout:50,completionTimeout:50,exitTimeout:100,...extra});
const step=(rows,name)=>rows.find(r=>r.step===name);

test('held probe: an ordinary run detaches, resumes and needs no failure',async()=>{
  const previous=globalThis.window;
  try {
    globalThis.window={os:fakeOs({})};
    const {rows,detach,failure}=await heldCase();
    assert.equal(failure,null);assert.deepEqual(detach.ok,null);
    assert.equal(step(rows,'read').ok,'hello');assert.equal(step(rows,'completion'),undefined);assert.equal(step(rows,'exit'),undefined);
  } finally {globalThis.window=previous;}
});

test('held probe: a missing barrier is a barrier timeout; the cancelled probe exits; no detach',async()=>{
  const previous=globalThis.window;
  try {
    let detached=false;globalThis.window={os:fakeOs({barrier:false,detach:async()=>{detached=true;}})};
    const {rows,detach,failure}=await heldCase();
    assert.equal(failure,null);assert(!detached);assert.match(detach.skipped,/did not reach barrier/);
    assert.equal(step(rows,'barrier').errno,'ETIMEDOUT');assert.equal(step(rows,'exit'),undefined);
  } finally {globalThis.window=previous;}
});

test('held probe: a detach that does not finish cancels the probe and stops the fixture',async()=>{
  const previous=globalThis.window;
  try {
    globalThis.window={os:fakeOs({detach:()=>new Promise(()=>{})})};
    const {rows,detach,failure}=await heldCase();
    assert.equal(detach.errno,'ETIMEDOUT');assert.match(failure?.message??'',/detach did not finish within 50 ms; the mount state is unknown/);
    assert.match(step(rows,'completion').skipped,/detach did not finish/);assert.equal(step(rows,'exit'),undefined);
  } finally {globalThis.window=previous;}
});

test('held probe: a stalled continuation times out in its own phase; the probe still exits before re-attach',async()=>{
  const previous=globalThis.window;
  try {
    globalThis.window={os:fakeOs({resume:false})};
    const {rows,detach,failure}=await heldCase();
    assert.deepEqual(detach.ok,null);assert.equal(failure,null);
    assert.equal(step(rows,'completion').errno,'ETIMEDOUT');assert.equal(step(rows,'exit'),undefined);
  } finally {globalThis.window=previous;}
});

test('held probe: a cancelled probe that never exits is recorded and stops the fixture',async()=>{
  const previous=globalThis.window;
  try {
    globalThis.window={os:fakeOs({resume:false,obeyCancel:false})};
    const {rows,failure}=await heldCase();
    assert.match(failure?.message??'',/cancelled probe did not exit within 100 ms/);
    assert.equal(step(rows,'completion').errno,'ETIMEDOUT');assert.equal(step(rows,'exit').errno,'ETIMEDOUT');
  } finally {globalThis.window=previous;}
});

test('compiler rewrite uses the same literal escaping as initial configuration',async()=>{
  const root='/tmp/quoted"back\\slash-$&';
  const config=conformanceConfig(await readFile('wrangler.toml','utf8'),root);
  const rewritten=compilerConfig(config,root,'/tmp/Compiler.Dockerfile');
  assert(rewritten.includes('image = "/tmp/Compiler.Dockerfile"'));
});

test('failed re-attach is saved and stops the next dependent probe immediately',async()=>{
  const rows=[],persisted=[];let next=false;
  await assert.rejects(async()=>{
    await recordReattach(rows,{ok:null},async()=>({errno:'EBUSY'}),'unmount-open',rows=>persisted.push(structuredClone(rows)));
    next=true;
  },/unmount-open re-attach failed: EBUSY/);
  assert(!next);assert.equal(persisted[0][0].errno,'EBUSY');assert.equal(rows[0].step,'attach');
});

test('malformed terminal output retains valid rows, status and contextual diagnostics',()=>{
  const valid={case:'unmount-open',step:'read',call:'read(fd)',errno:'EBADF'},diagnostics=[];
  const rows=heldRows({output:JSON.stringify(valid)+'\nwarning: /variable/path\n{"partial":',stderr:'panic details',status:101},'unmount-open',{case:'unmount-open',step:'detach',call:'detach',ok:null},diagnostics);
  assert.deepEqual(rows[0],valid);assert(rows.find(r=>r.step==='output').skipped);
  assert.equal(rows.find(r=>r.step==='completion').ok.status,101);
  assert.deepEqual(diagnostics.map(d=>[d.case,d.stream]),[['unmount-open',2],['unmount-open',1],['unmount-open',1]]);
  assert(!JSON.stringify(rows).includes('/variable/path'));assert(diagnostics[1].text.includes('/variable/path'));
});

test('copied manifests keep local dependencies but not their own file paths',()=>{
  const manifest=['[package]','name = "os-abi"','build = "build.rs"','','[lib]','path = "src/lib.rs"','',
    '[dependencies]','local = { path = "../local", version = "0.1" }','remote = "1"','',
    "[target.'cfg(unix)'.dependencies]",'unixy = { path = "../unixy" }','',
    '[dependencies.dotted]','path = "../dotted"','','[dev-dependencies]','absolute = { path = "/opt/absolute" }','',
    '[patch.crates-io]','patched = { path = "vendor/patched" }'].join('\n');
  const out=relocateManifest(manifest,'/repo/crates/abi').split('\n');
  assert(out.includes('path = "src/lib.rs"'));assert(out.includes('build = "build.rs"'));
  assert(out.includes('local = { path = "/repo/crates/local", version = "0.1" }'));
  assert(out.includes('unixy = { path = "/repo/crates/unixy" }'));assert(out.includes('path = "/repo/crates/dotted"'));
  assert(out.includes('absolute = { path = "/opt/absolute" }'));assert(out.includes('patched = { path = "/repo/crates/abi/vendor/patched" }'));
});

test('the gate workspace is the repository workspace with only its members changed',()=>{
  const root=['[workspace]','members = [','  "crates/abi",','  "xtask",',']','resolver = "2"','','[workspace.dependencies]','serde = { version = "1" }','tool = { path = "crates/tool" }','','[profile.release]','opt-level = "s"'].join('\n');
  const out=workspaceManifest(root,'/repo',['abi','audit']);
  assert.match(out,/^members = \["abi","audit"\]$/m);assert(!out.includes('xtask'));
  assert(out.includes('tool = { path = "/repo/crates/tool" }'));assert(out.includes('opt-level = "s"'));assert(out.includes('serde = { version = "1" }'));
  assert.throws(()=>workspaceManifest('[workspace]\nresolver = "2"','/repo',['abi']),/no members list/);
  assert.throws(()=>workspaceManifest(root+'\ndefault-members = ["xtask"]','/repo',['abi']),/default-members/);
});
