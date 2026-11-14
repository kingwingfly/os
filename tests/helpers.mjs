// Shared by the process, Podman and development tests. Not a test file itself.
import { writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';

export const exists=pid=>{try {process.kill(pid,0);return true;}catch(error) {if(error.code==='ESRCH')return false;throw error;}};
// Wait for a condition, which may be async.
export async function waitFor(condition,timeout=8000) {
  const until=Date.now()+timeout;
  while(!await condition()) {
    if(Date.now()>until)throw new Error('condition not reached within '+timeout+' ms');
    await new Promise(resolve=>setTimeout(resolve,20));
  }
}
export const firstLine=child=>new Promise((resolve,reject)=>{
  let text='';child.stdout.on('data',chunk=>{text+=chunk;if(text.includes('\n'))resolve(text.split('\n')[0]);});
  child.once('error',reject);child.once('exit',()=>reject(new Error('fixture exited before ready')));
});

// A fake `podman` for PATH. It appends to $FAKE_EVENTS: "podman-started PID", each request,
// each signal ("podman-got-SIGTERM", ...) and "podman-stopped". Modes: listen on the socket
// `system service` is given; exit at once; silent (never listen); late (listen after 300 ms);
// late-exit (exit after 300 ms without listening); stubborn (listen and ignore SIGTERM).
export function fakePodman(dir,mode='listen') {
  return writeFile(join(dir,'podman'),'#!'+process.execPath+`
const fs=require('node:fs'),record=s=>fs.appendFileSync(process.env.FAKE_EVENTS,s+'\\n');
const mode=${JSON.stringify(mode)},socket=process.argv.at(-1).slice(7);
record('podman-started '+process.pid);
if(mode==='exit')process.exit(1);
const listen=()=>require('node:http').createServer((req,res)=>{record('podman-request '+req.url);res.end('alive');}).listen(socket);
if(mode==='listen'||mode==='stubborn')listen();
if(mode==='late')setTimeout(listen,300);
if(mode==='late-exit')setTimeout(()=>process.exit(1),300);
for(const signal of ['SIGINT','SIGHUP'])process.on(signal,()=>{record('podman-got-'+signal);process.exit(2);});
process.on('SIGTERM',()=>{record('podman-got-SIGTERM');if(mode==='stubborn')return;record('podman-stopped');process.exit(0);});
setInterval(()=>{},1000);
`,{mode:0o755});
}
export const eventLines=async file=>(await readFile(file,'utf8').catch(()=>'')).split('\n').filter(Boolean);
export async function podmanPid(file) {
  let pid;
  await waitFor(async()=>{pid=Number((await eventLines(file)).find(line=>line.startsWith('podman-started'))?.split(' ')[1]);return pid>0;});
  return pid;
}
