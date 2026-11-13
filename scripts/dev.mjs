// Start wrangler with a Docker-compatible engine; reuse an existing default
// Podman service when available, and stop only the service this session starts.
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { needsPodman, startPodman } from './podman.mjs';
const env={...process.env};
const bootstrap=new AbortController();
let podman,wrangler,pendingSignal,closing;
const signalCode=signal=>signal==='SIGINT'?130:signal==='SIGTERM'?143:1;
const finish=code=>closing??=(async()=>{await podman?.close();process.exit(code);})().catch(error=>{console.error('Podman cleanup failed:',error.message);process.exit(1);});
const forward=signal=>{
  pendingSignal??=signal;
  if(wrangler)wrangler.kill(signal);
  else bootstrap.abort(new Error('dev bootstrap interrupted by '+signal));
};
process.on('SIGINT',()=>forward('SIGINT'));
process.on('SIGTERM',()=>forward('SIGTERM'));
if(needsPodman(env)) {
  const socket=join(tmpdir(),`os-podman-${process.getuid()}.sock`);
  try {
    podman=await startPodman(env,{socket,proxySocket:join(tmpdir(),`os-podman-${process.getuid()}-${process.pid}.sock`),reuse:true,allowLate:true,detached:true,signal:bootstrap.signal});
    console.log(`Containers run with Podman, through ${podman.socket}`);
  } catch(error) {
    // Preserve ordinary dev startup when the optional container service fails.
    // Isolated conformance calls startPodman directly and requires it to succeed.
    if(!pendingSignal)console.warn(`Podman unavailable; starting Wrangler without container bootstrap: ${error.message}`);
  }
}
if(pendingSignal)await finish(signalCode(pendingSignal));
wrangler=spawn('npx',['wrangler','dev',...process.argv.slice(2)],{stdio:'inherit',env});
// Wrangler still needs its engine connection while draining/removing containers.
// The exit handler owns Podman cleanup after Wrangler has finished.
wrangler.on('error',error=>{console.error('Wrangler failed to start:',error.message);void finish(1);});
wrangler.on('exit',(code,signal)=>{void finish(code??signalCode(signal));});
