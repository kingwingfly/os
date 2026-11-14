// Start `wrangler dev` with the arguments given. Archive jobs run in a container, which needs a
// Docker-compatible engine: where Docker is absent and Podman present, this starts a private
// Podman API service for the session (scripts/podman.mjs) and points wrangler at it, through a
// proxy that fixes up what Podman would refuse (scripts/engine-proxy.mjs).
//
// Wrangler is started from its own entry point, not through npx, so the signals sent and the
// exit seen are Wrangler's. Shutdown uses the shared cleanup scope (scripts/process.mjs): the
// first SIGINT, SIGTERM or SIGHUP (a closed terminal) is passed on to Wrangler, which removes
// its containers while Podman, out of reach of terminal signals, keeps serving; Podman stops
// after Wrangler exits. The copy of the same signal that npm relays is not a second signal; a
// later one exits at once, and Podman then stops with its lifeline.
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { readFileSync, rmSync } from 'node:fs';
import { once } from 'node:events';
import { dirname, join, resolve } from 'node:path';
import { needsPodman, egressImage, startPodman, configureWrangler, sessionDirectory } from './podman.mjs';
import { engineProxy } from './engine-proxy.mjs';
import { ShutdownScope, signalCodes } from './process.mjs';

const env={...process.env};
// After a terminal closes, writing to it fails; that must not cut the shutdown short.
for(const stream of [process.stdout,process.stderr])stream.on('error',()=>{});
const scope=new ShutdownScope();

function wranglerEntry() {
  const manifest=createRequire(import.meta.url).resolve('wrangler/package.json');
  const {bin}=JSON.parse(readFileSync(manifest,'utf8'));
  return resolve(dirname(manifest),typeof bin==='string'?bin:bin.wrangler);
}
async function exit(code) {await scope.close();process.exit(code);}

if(needsPodman(env)) {
  let dir,podman,proxy;
  try {
    dir=sessionDirectory();
    // Removed even when a second signal exits at once.
    process.on('exit',()=>rmSync(dir,{recursive:true,force:true}));
    const egress=egressImage(env);
    podman=await startPodman(env,{socket:join(dir,'podman.sock'),allowLate:true,signal:scope.controller.signal});
    proxy=engineProxy(join(dir,'docker.sock'),{socketPath:podman.socket},{stripMemorySwappiness:true});
    await once(proxy,'listening');
    configureWrangler(env,{host:join(dir,'docker.sock'),egress});
    // Disposed in reverse order, after Wrangler: the proxy, then Podman.
    scope.add('Podman',()=>podman.close());
    scope.add('engine proxy',()=>{proxy.destroyAllSockets();return new Promise(resolve=>proxy.close(()=>resolve()));});
    if(podman.late) {
      console.log(`Podman is still starting; containers will be available once it listens at ${podman.socket}`);
      podman.ready.then(ok=>ok?console.log('Podman is now listening.'):console.warn('Podman exited before opening its socket; containers are unavailable in this session.'));
    } else console.log(`Containers run with Podman, through ${podman.socket}`);
  } catch(error) {
    if(scope.closing)await new Promise(()=>{}); // a signal arrived: the scope is exiting
    proxy?.destroyAllSockets();proxy?.close();
    await podman?.close().catch(()=>{});
    console.warn(`Podman unavailable; starting Wrangler without container bootstrap: ${error.message}`);
  }
}

let entry;
try {entry=wranglerEntry();}
catch(error) {console.error('Wrangler failed to start: '+error.message);await exit(1);}
const wrangler=scope.own('Wrangler',()=>spawn(process.execPath,[entry,'dev',...process.argv.slice(2)],{stdio:'inherit',env}),async child=>{
  if(child.exitCode!==null||child.signalCode!==null||child.spawnError)return;
  const exited=once(child,'exit');
  child.kill(scope.signal??'SIGTERM');
  await exited;
});
wrangler.on('error',error=>{wrangler.spawnError=error;console.error('Wrangler failed to start: '+error.message);if(!scope.closing)void exit(1);});
wrangler.on('exit',(code,signal)=>{if(!scope.closing)void exit(code??signalCodes[signal]??1);});
