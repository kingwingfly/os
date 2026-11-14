// `npm run dev` (scripts/dev.mjs) with Podman, using fake `podman` and `npx` programs on PATH.
import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import http from 'node:http';
import { mkdtemp, writeFile, readFile, readdir, rm, symlink, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { start, stop } from '../scripts/process.mjs';
const exists=pid=>{try {process.kill(pid,0);return true;}catch(error) {if(error.code==='ESRCH')return false;throw error;}};
const waitFor=async(condition,timeout=8000)=>{const until=Date.now()+timeout;while(!await condition()) {if(Date.now()>until)throw new Error('condition not reached');await new Promise(r=>setTimeout(r,20));}};
const record=`const record=s=>require('node:fs').appendFileSync(process.env.DEV_EVENTS,s+'\\n');`;

// podman: serves HTTP on its socket; SIGTERM (from its lifeline) stops it, and a terminal
// signal reaching it directly is recorded as a failure.
// npx (Wrangler): on a signal, drains for 150 ms, makes one cleanup request through the engine,
// then exits. With hang, it never exits.
async function session({npx=true,hang=false,podman='listen'}={}) {
  const dir=await mkdtemp(join(tmpdir(),'dev-session-')),events=join(dir,'events');
  await symlink('/bin/sh',join(dir,'sh'));
  await writeFile(join(dir,'podman'),'#!'+process.execPath+'\n'+record+`
    record('podman-started '+process.pid);
    ${podman==='exit'?'process.exit(1);':''}
    const s=require('node:http').createServer((req,res)=>{record('podman-request '+req.url);res.end('alive');});
    s.listen(process.argv.at(-1).slice(7));
    for(const signal of ['SIGINT','SIGHUP'])process.on(signal,()=>{record('podman-got-'+signal);process.exit(2);});
    process.on('SIGTERM',()=>{record('podman-stopped');s.close(()=>process.exit(0));});`,{mode:0o755});
  if(npx)await writeFile(join(dir,'npx'),'#!'+process.execPath+'\n'+record+`
    require('node:fs').writeFileSync(process.env.DEV_EVENTS+'.engine',process.env.WRANGLER_DOCKER_HOST??'none');
    let draining=false;
    for(const signal of ['SIGINT','SIGTERM','SIGHUP'])process.on(signal,async()=>{
      if(draining)return;draining=true;record('wrangler-draining');
      ${hang?'return;':''}
      await new Promise(r=>setTimeout(r,150));
      require('node:http').get({socketPath:process.env.WRANGLER_DOCKER_HOST.slice(7),path:'/cleanup'},res=>{
        res.resume();res.on('end',()=>{record('wrangler-finished');process.exit(0);});
      }).on('error',error=>{record('wrangler-engine-error '+error.code);process.exit(1);});
    });
    console.log('WRANGLER_READY');setInterval(()=>{},1000);`,{mode:0o755});
  const env={...process.env,PATH:dir,TMPDIR:dir,DEV_EVENTS:events};
  delete env.DOCKER_HOST;delete env.WRANGLER_DOCKER_HOST;delete env.MINIFLARE_CONTAINER_EGRESS_IMAGE;
  // Its own process group stands in for the terminal's foreground group.
  const dev=start(process.execPath,['scripts/dev.mjs'],{env,detached:true,stdio:['ignore','pipe','pipe']});
  let output='',errors='';dev.stdout.on('data',c=>{output+=c;});dev.stderr.on('data',c=>{errors+=c;});
  const exited=once(dev,'exit');
  const lines=async()=>(await readFile(events,'utf8').catch(()=>'')).trim().split('\n').filter(Boolean);
  const podmanPid=async()=>Number((await lines()).find(l=>l.startsWith('podman-started'))?.split(' ')[1]);
  const ready=()=>waitFor(()=>output.includes('WRANGLER_READY'));
  const close=async()=>{await stop(dev,{timeout:200});const pid=await podmanPid();if(pid&&exists(pid))process.kill(pid,'SIGKILL');await rm(dir,{recursive:true,force:true});};
  return {dir,dev,exited,lines,podmanPid,ready,close,engine:()=>readFile(events+'.engine','utf8'),output:()=>output,errors:()=>errors};
}

for(const delivery of ['pid','terminal group'])for(const signal of ['SIGINT','SIGTERM','SIGHUP'])test(`Podman stays until Wrangler has finished: ${signal} to the ${delivery}`,async()=>{
  const s=await session();
  try {
    await s.ready();
    if(delivery==='pid')s.dev.kill(signal);else process.kill(-s.dev.pid,signal);
    const [code]=await s.exited;assert.equal(code,0,s.errors());
    assert.deepEqual((await s.lines()).filter(l=>!l.startsWith('podman-started')),['wrangler-draining','podman-request /cleanup','wrangler-finished','podman-stopped']);
    assert(!exists(await s.podmanPid()));
  } finally {await s.close();}
});

test('Podman stops when dev is killed outright',async()=>{
  const s=await session();
  try {
    await s.ready();const pid=await s.podmanPid();assert(exists(pid));
    s.dev.kill('SIGKILL');
    await waitFor(()=>!exists(pid));
    assert(!(await s.lines()).some(l=>l.startsWith('podman-got-')));
  } finally {try {process.kill(-s.dev.pid,'SIGKILL');}catch {}await s.close();}
});

test('a second signal exits at once when shutdown is stuck, and Podman still stops',async()=>{
  const s=await session({hang:true});
  try {
    await s.ready();const pid=await s.podmanPid();
    s.dev.kill('SIGTERM');await waitFor(async()=>(await s.lines()).includes('wrangler-draining'));
    s.dev.kill('SIGTERM');
    const [code]=await s.exited;assert.equal(code,143);
    await waitFor(()=>!exists(pid));
    // The private socket directory is removed even on this path.
    assert.deepEqual((await readdir(s.dir)).filter(name=>name.startsWith('os-podman-')),[]);
  } finally {try {process.kill(-s.dev.pid,'SIGKILL');}catch {}await s.close();}
});

test('concurrent sessions have their own services; one ending leaves the other working',async()=>{
  const a=await session(),b=await session();
  try {
    await Promise.all([a.ready(),b.ready()]);
    const [podmanA,podmanB]=[await a.podmanPid(),await b.podmanPid()];assert.notEqual(podmanA,podmanB);
    a.dev.kill('SIGTERM');await a.exited;
    await waitFor(()=>!exists(podmanA));assert(exists(podmanB));
    const engine=(await b.engine()).slice(7);
    const body=await new Promise((resolve,reject)=>http.get({socketPath:engine,path:'/_ping'},res=>{let t='';res.on('data',c=>{t+=c;});res.on('end',()=>resolve(t));}).on('error',reject));
    assert.equal(body,'alive');
  } finally {await a.close();await b.close();}
});

test('the old shared socket name is neither borrowed nor removed',async()=>{
  const s=await session();
  try {
    // A stale (or another user's) file at the name development used to share, under TMPDIR.
    const legacy=join(s.dir,`os-podman-${process.getuid()}.sock`);await writeFile(legacy,'');const inode=(await stat(legacy)).ino;
    await s.ready();
    const engine=(await s.engine()).slice(7);
    assert.match(engine,new RegExp('^'+s.dir+'/os-podman-[^/]+/docker\\.sock$'));
    assert.equal((await stat(legacy)).ino,inode);
    s.dev.kill('SIGTERM');await s.exited;assert.equal((await stat(legacy)).ino,inode);
  } finally {await s.close();}
});

test('a Wrangler that cannot start still stops Podman',async()=>{
  const s=await session({npx:false});
  try {
    const [code]=await s.exited;assert.equal(code,1);assert.match(s.errors(),/Wrangler failed to start/);
    await waitFor(async()=>!exists(await s.podmanPid()));
  } finally {await s.close();}
});

test('without a working Podman, Wrangler starts without containers',async()=>{
  const s=await session({podman:'exit'});
  try {
    await s.ready();
    assert.match(s.errors(),/Podman unavailable; starting Wrangler without container bootstrap/);
    assert.equal(await s.engine(),'none');
  } finally {await s.close();}
});
