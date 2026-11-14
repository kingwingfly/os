// `npm run dev` with Podman, through the real npm. Each test builds a small project with the
// repository's dev script and scripts/, a stub Wrangler package where dev resolves it, and a
// fake `podman` on PATH, so npm's own signal handling is part of what is tested.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, readdir, copyFile, symlink, stat, rm } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { start, stop } from '../scripts/process.mjs';
import { exists, waitFor, fakePodman, eventLines, podmanPid } from './helpers.mjs';
const repo=fileURLToPath(new URL('..',import.meta.url));
let npmCli=null;
try {npmCli=realpathSync(execFileSync('sh',['-c','command -v npm'],{encoding:'utf8'}).trim());} catch {}
const which=command=>realpathSync(execFileSync('sh',['-c','command -v '+command],{encoding:'utf8'}).trim());

// Stub Wrangler: on its first signal it drains for 300 ms, makes one cleanup request through
// the engine and exits; with FAKE_WRANGLER=hang it never exits.
const stubWrangler=`const fs=require('node:fs'),http=require('node:http');
const record=s=>fs.appendFileSync(process.env.FAKE_EVENTS,s+'\\n');
record('wrangler-started '+process.pid+' '+process.ppid+' '+process.argv.slice(2).join(' '));
fs.writeFileSync(process.env.FAKE_EVENTS+'.engine',process.env.WRANGLER_DOCKER_HOST??'none');
let draining=false;
for(const signal of ['SIGINT','SIGTERM','SIGHUP'])process.on(signal,()=>{
  record('wrangler-got-'+signal);
  if(draining)return;draining=true;record('wrangler-draining');
  if(process.env.FAKE_WRANGLER==='hang')return;
  if(!process.env.WRANGLER_DOCKER_HOST)process.exit(0);
  setTimeout(()=>http.get({socketPath:process.env.WRANGLER_DOCKER_HOST.slice(7),path:'/cleanup'},res=>{
    res.resume();res.on('end',()=>{record('wrangler-finished');process.exit(0);});
  }).on('error',error=>{record('wrangler-engine-error '+error.code);process.exit(1);}),300);
});
console.log('WRANGLER_READY');setInterval(()=>{},1000);
`;

async function session({podman='listen',wrangler=true,hang=false,tmp}={}) {
  const root=await mkdtemp(join(tmpdir(),'dev-npm-')),project=join(root,'project'),bin=join(root,'bin');
  tmp??=join(root,'tmp');
  const events=join(tmp,'events');
  await mkdir(join(project,'scripts'),{recursive:true});await mkdir(bin);await mkdir(tmp,{recursive:true});
  const manifest=JSON.parse(await readFile(join(repo,'package.json'),'utf8'));
  await writeFile(join(project,'package.json'),JSON.stringify({name:'dev-fixture',private:true,type:manifest.type,scripts:{dev:manifest.scripts.dev}}));
  for(const file of ['dev.mjs','podman.mjs','engine-proxy.mjs','process.mjs','podman-docker.sh'])await copyFile(join(repo,'scripts',file),join(project,'scripts',file));
  if(wrangler) {
    await mkdir(join(project,'node_modules/wrangler/bin'),{recursive:true});
    await writeFile(join(project,'node_modules/wrangler/package.json'),JSON.stringify({name:'wrangler',version:'0.0.0',bin:{wrangler:'./bin/wrangler.js'}}));
    await writeFile(join(project,'node_modules/wrangler/bin/wrangler.js'),stubWrangler);
  }
  // PATH holds only what dev needs, so a real docker or podman on this host is never found.
  for(const [name,target] of [['sh','/bin/sh'],['node',process.execPath],['sleep',which('sleep')]])await symlink(target,join(bin,name));
  await fakePodman(bin,podman);
  const env={PATH:bin,HOME:root,TMPDIR:tmp,FAKE_EVENTS:events,npm_config_cache:join(root,'npm-cache'),npm_config_update_notifier:'false',npm_config_fund:'false'};
  if(hang)env.FAKE_WRANGLER='hang';
  // npm leads its own process group, standing in for the terminal's foreground group.
  const npm=start(process.execPath,[npmCli,'run','dev'],{cwd:project,env,detached:true,stdio:['ignore','pipe','pipe']});
  let output='';npm.stdout.on('data',c=>{output+=c;});npm.stderr.on('data',c=>{output+=c;});
  const lines=()=>eventLines(events);
  const wranglerPids=async()=>{
    let line;await waitFor(async()=>(line=(await lines()).find(l=>l.startsWith('wrangler-started'))));
    const [,pid,ppid,...args]=line.split(' ');return {wrangler:Number(pid),dev:Number(ppid),args};
  };
  const close=async()=>{
    try {process.kill(-npm.pid,'SIGKILL');} catch {}
    await stop(npm,{timeout:200});
    for(const line of await lines())if(/^(podman|wrangler)-started/.test(line))try {process.kill(Number(line.split(' ')[1]),'SIGKILL');} catch {}
    await rm(root,{recursive:true,force:true});
  };
  return {root,tmp,npm,events,lines,wranglerPids,podmanPid:()=>podmanPid(events),ready:()=>waitFor(()=>output.includes('WRANGLER_READY')),output:()=>output,engine:()=>readFile(events+'.engine','utf8'),close};
}
const skip=!npmCli&&'npm is not available';
const after=(lines,a,b)=>lines.indexOf(a)>=0&&lines.indexOf(b)>lines.indexOf(a);

// Ctrl-C, a SIGTERM to the whole group, a SIGTERM to npm alone, and a closed terminal.
for(const [signal,target] of [['SIGINT','group'],['SIGTERM','group'],['SIGTERM','npm'],['SIGHUP','group']])test(`npm run dev: Podman stays until Wrangler has finished, after ${signal} to the ${target}`,{skip},async()=>{
  const s=await session();
  try {
    await s.ready();const {wrangler,dev}=await s.wranglerPids();const podman=await s.podmanPid();
    if(target==='group')process.kill(-s.npm.pid,signal);else s.npm.kill(signal);
    await waitFor(()=>!exists(dev)&&!exists(podman),10000);
    const lines=await s.lines();
    assert(after(lines,'wrangler-draining','podman-request /cleanup'),lines.join('\n'));
    assert(after(lines,'wrangler-finished','podman-stopped'),lines.join('\n'));
    assert.equal(lines.filter(l=>l==='wrangler-draining').length,1);
    assert(!lines.some(l=>/^podman-got-SIG(INT|HUP)$/.test(l)),'a terminal signal reached Podman');
    assert(!exists(wrangler));
  } finally {await s.close();}
});

test('npm run dev: the copy npm relays is not a second signal; a later one exits at once',{skip},async()=>{
  const s=await session({hang:true});
  try {
    await s.ready();const {dev}=await s.wranglerPids();const podman=await s.podmanPid();
    process.kill(-s.npm.pid,'SIGINT');
    await waitFor(async()=>(await s.lines()).includes('wrangler-draining'));
    // dev received this Ctrl-C twice (terminal and npm) and must still be waiting for Wrangler.
    await new Promise(resolve=>setTimeout(resolve,800));
    assert(exists(dev),'dev exited on the relayed copy of one Ctrl-C');assert(exists(podman),'Podman stopped while Wrangler was draining');
    process.kill(-s.npm.pid,'SIGINT');
    await waitFor(()=>!exists(dev)&&!exists(podman),8000);
  } finally {await s.close();}
});

test('npm run dev: Podman stops when dev is killed outright, and the next session removes its directory',{skip},async()=>{
  const first=await session();
  let second;
  try {
    await first.ready();const {dev}=await first.wranglerPids();const podman=await first.podmanPid();
    const sessions=async()=>(await readdir(first.tmp)).filter(name=>/^os-podman-.{6}$/.test(name));
    const [left]=await sessions();assert(left);
    process.kill(dev,'SIGKILL');
    await waitFor(()=>!exists(podman),8000);
    assert.deepEqual(await sessions(),[left]);
    second=await session({tmp:first.tmp});await second.ready();
    assert(!(await sessions()).includes(left),'the dead session directory was not removed');
  } finally {await second?.close();await first.close();}
});

test('npm run dev: concurrent sessions have their own services; one ending leaves the other working',{skip},async()=>{
  const a=await session(),b=await session();
  try {
    await Promise.all([a.ready(),b.ready()]);
    const [podmanA,podmanB]=[await a.podmanPid(),await b.podmanPid()];assert.notEqual(podmanA,podmanB);
    process.kill(-a.npm.pid,'SIGINT');
    await waitFor(()=>!exists(podmanA),10000);assert(exists(podmanB));
    const engine=(await b.engine()).slice('unix://'.length);
    const body=await new Promise((resolve,reject)=>http.get({socketPath:engine,path:'/_ping'},res=>{let t='';res.on('data',c=>{t+=c;});res.on('end',()=>resolve(t));}).on('error',reject));
    assert.equal(body,'alive');
  } finally {await a.close();await b.close();}
});

test('npm run dev: the old shared socket name is neither borrowed nor removed',{skip},async()=>{
  const root=await mkdtemp(join(tmpdir(),'dev-legacy-')),tmp=join(root,'tmp');await mkdir(tmp);
  const legacy=join(tmp,`os-podman-${process.getuid()}.sock`);await writeFile(legacy,'');const inode=(await stat(legacy)).ino;
  const s=await session({tmp});
  try {
    await s.ready();
    const engine=(await s.engine()).slice('unix://'.length);
    assert.equal(dirname(dirname(engine)),tmp);assert(dirname(engine).startsWith(join(tmp,'os-podman-')));assert(engine.endsWith('/docker.sock'));
    assert.equal((await stat(legacy)).ino,inode);
    process.kill(-s.npm.pid,'SIGINT');await waitFor(async()=>!exists(await s.podmanPid()),10000);
    assert.equal((await stat(legacy)).ino,inode);
  } finally {await s.close();await rm(root,{recursive:true,force:true});}
});

test('npm run dev: Wrangler is started from its entry point with the dev arguments',{skip},async()=>{
  const s=await session();
  try {
    await s.ready();const {args}=await s.wranglerPids();
    const manifest=JSON.parse(await readFile(join(repo,'package.json'),'utf8'));
    assert.deepEqual(args,['dev',...manifest.scripts.dev.split(' ').slice(2)]);
  } finally {await s.close();}
});

test('npm run dev: a Wrangler that cannot be found still stops Podman',{skip},async()=>{
  const s=await session({wrangler:false});
  try {
    const [code]=await new Promise(resolve=>s.npm.once('exit',(...args)=>resolve(args)));
    assert.equal(code,1);assert.match(s.output(),/Wrangler failed to start/);
    await waitFor(async()=>!exists(await s.podmanPid()));
  } finally {await s.close();}
});

test('npm run dev: without a working Podman, Wrangler starts without containers',{skip},async()=>{
  const s=await session({podman:'exit'});
  try {
    await s.ready();
    assert.match(s.output(),/Podman unavailable; starting Wrangler without container bootstrap/);
    assert.equal(await s.engine(),'none');
  } finally {await s.close();}
});
