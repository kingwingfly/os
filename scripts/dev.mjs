// Start `wrangler dev` with the arguments given. Archive jobs run in a container, which needs a
// Docker-compatible engine: where Docker is absent and Podman present, this starts a private
// Podman API service for the session (scripts/podman.mjs) and points wrangler at it, through a
// proxy that fixes up what Podman would refuse (scripts/engine-proxy.mjs).
//
// Shutdown order: Ctrl-C, SIGTERM or a closed terminal reach dev and Wrangler, never Podman, which
// stays available while Wrangler removes its containers and is stopped after Wrangler exits.
// A second signal exits at once. If dev itself is killed, Podman stops with it.
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { needsPodman, egressImage, startPodman, configureWrangler } from './podman.mjs';
import { engineProxy } from './engine-proxy.mjs';

const env={...process.env};
const codes={SIGINT:130,SIGTERM:143,SIGHUP:129};
let podman,proxy,dir,wrangler,interrupted,finishing;
// After a terminal closes, writing to it fails; that must not cut the shutdown short.
for(const stream of [process.stdout,process.stderr])stream.on('error',()=>{});
// The private socket directory goes even when a second signal exits at once.
process.on('exit',()=>{if(dir)rmSync(dir,{recursive:true,force:true});});
const bootstrap=new AbortController();
async function release() {
  proxy?.destroyAllSockets();proxy?.close();
  await podman?.close();
}
const finish=code=>finishing??=release().catch(error=>console.error('Podman cleanup failed: '+error.message)).finally(()=>process.exit(code));
for(const signal of Object.keys(codes))process.on(signal,()=>{
  if(interrupted)process.exit(codes[signal]);
  interrupted=signal;
  if(wrangler)wrangler.kill(signal);
  else bootstrap.abort(new Error('interrupted by '+signal));
});

if(needsPodman(env)) {
  try {
    dir=mkdtempSync(join(tmpdir(),'os-podman-'));
    const egress=egressImage(env);
    podman=await startPodman(env,{socket:join(dir,'podman.sock'),allowLate:true,signal:bootstrap.signal});
    proxy=engineProxy(join(dir,'docker.sock'),{socketPath:podman.socket},{stripMemorySwappiness:true});
    await once(proxy,'listening');
    configureWrangler(env,{host:join(dir,'docker.sock'),egress});
    console.log(`Containers run with Podman, through ${podman.socket}`);
  } catch(error) {
    await release().catch(()=>{});podman=proxy=null;
    if(interrupted)await finish(codes[interrupted]);
    console.warn(`Podman unavailable; starting Wrangler without container bootstrap: ${error.message}`);
  }
}
if(interrupted)await finish(codes[interrupted]);
wrangler=spawn('npx',['wrangler','dev',...process.argv.slice(2)],{stdio:'inherit',env});
wrangler.on('error',error=>{console.error('Wrangler failed to start: '+error.message);void finish(1);});
wrangler.on('exit',(code,signal)=>{void finish(code??codes[signal]??1);});
