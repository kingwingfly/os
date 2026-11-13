// Start wrangler with a Docker-compatible engine; reuse an existing default
// Podman service when available, and stop only the service this session starts.
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { needsPodman, startPodman } from './podman.mjs';
const env={...process.env};
let podman;
if(needsPodman(env)) {
  const socket=join(tmpdir(),`os-podman-${process.getuid()}.sock`);
  podman=await startPodman(env,{socket,proxySocket:join(tmpdir(),`os-podman-${process.getuid()}-${process.pid}.sock`),reuse:true});
  console.log(`Containers run with Podman, through ${socket}`);
}
const wrangler=spawn('npx',['wrangler','dev',...process.argv.slice(2)],{stdio:'inherit',env});
const stop=signal=>{wrangler.kill(signal);void podman?.close();};
process.on('SIGINT',()=>stop('SIGINT'));
process.on('SIGTERM',()=>stop('SIGTERM'));
wrangler.on('exit',async code=>{try {await podman?.close();} finally {process.exit(code??0);}});
