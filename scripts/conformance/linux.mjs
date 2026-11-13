import { mkdtemp, mkdir, rm, readFile, chmod, readlink, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { run, targetDir, jsonLines, skip, operations, probeOperations, save } from './common.mjs';
export function buildProbe() {
  run('cargo',['build','--locked','-p','os-conformance','--release'],{stdio:'inherit'});
  return join(targetDir(),'release/os-conformance');
}
export async function linux({namespaceProbe=spawnSync,binary=buildProbe(),measureLatency=true}={}) {
  const dir=await realpath(await mkdtemp(join(tmpdir(),'os-conformance-linux-')));
  let success=false;
  const observations=[],evidence={};
  // Keep every complete JSON row even if the process later panics or is killed.
  const invoke=(cmd,args)=>{
    const result=spawnSync(cmd,args,{encoding:'utf8',maxBuffer:32<<20});
    const invalid=[];
    for(const line of (result.stdout||'').split('\n').filter(Boolean)) {
      try {observations.push(JSON.parse(line));}catch {invalid.push(line);}
    }
    if(result.status!==0||result.error||invalid.length)throw Object.assign(new Error('Linux probe failed; partial observations retained'),{
      command:cmd,args,status:result.status,signal:result.signal,stdout:result.stdout,stderr:result.stderr,invalid,spawnError:result.error?.message,
    });
  };
  try {
    await chmod(dir,0o755);
    const available=namespaceProbe('unshare',['-Urm','true'],{encoding:'utf8'});
    const mapped=namespaceProbe('unshare',['-Urm','--map-auto','true'],{encoding:'utf8'});
    evidence.namespaces={mount:available.stderr?.trim()||available.error?.message||null,mapped:mapped.stderr?.trim()||mapped.error?.message||null};
    if (available.status===0) {
      invoke('unshare',['-Urm',...(mapped.status===0?['--map-auto']:[]),binary,'namespace',dir,dir,dir,'0','0']);
    } else {
      const tree=join(dir,'tree');await mkdir(tree);
      invoke(binary,['no-mounts',tree,tree,tree,String(process.getuid()),String(process.getgid())]);
    }
    const two=join(dir,'two');await mkdir(two);
    if (mapped.status===0) invoke('unshare',['-Urm','--map-auto',binary,'two-linux',two,two,two,'0','0']);
    else observations.push(skip('two-accounts','subuid/subgid mappings unavailable; see linux-evidence.json'));
    const observe=async action=>{try{return {ok:await action()};}catch(e){return {errno:e.code||'UNKNOWN_ERROR'};}};
    evidence.startup={
      cmdline:await observe(async()=>(await readFile('/proc/1/cmdline','utf8')).split('\0')[0].split('/').at(-1)),
      executable:await observe(()=>readlink('/proc/1/exe')),
    };
    const processRows=[];
    processRows.push(skip('startup','host PID 1 details are environmental evidence in linux-evidence.json, not a portable OS comparison'));
    processRows.push(skip('gui-processes','headless Linux reference has no Files/Editor/Preview/Mounts desktop applications'));
    processRows.push(skip('tab-pids','Linux reference has no browser OS tabs; process visibility is namespace-scoped'));
    if(!measureLatency){success=true;return {observations,process:processRows,evidence};}
    const timingRoot=join(dir,'timing');await mkdir(timingRoot);
    const args=['latency',timingRoot,timingRoot,timingRoot,String(process.getuid()),String(process.getgid())];
    run(binary,[...args,'prepare']);const latency=[];
    for (const operation of operations) {
      const samples=[];
      for (const temperature of ['cold','warm']) {
        const started=performance.now();let elapsed;
        if(operation==='shell-first-prompt') {
          elapsed=await new Promise((resolve,reject)=>{
            const shell=spawn('/bin/sh',['-i'],{env:{...process.env,ENV:undefined,PS1:'CONFORMANCE_PROMPT> '},cwd:timingRoot});
            let output='',done=false;
            const timeout=setTimeout(()=>{shell.kill();reject(new Error('native shell prompt timeout'));},10000);
            shell.stderr.on('data',data=>{output+=data;if(!done&&output.includes('CONFORMANCE_PROMPT>')){done=true;elapsed=performance.now()-started;shell.stdin.end('exit\n');}});
            shell.once('exit',code=>{clearTimeout(timeout);if(!done||code!==0)reject(new Error('native shell prompt failed'));else resolve(elapsed);});
          });
        } else {
          if(operation==='ls-usr-bin')run('/bin/ls',['-l','/usr/bin'],{cwd:timingRoot});
          else {const result=jsonLines(run(binary,[...args,probeOperations[operation]]));if(result.some(r=>r.errno))throw new Error('native timing operation failed');}
          elapsed=performance.now()-started;
        }
        samples.push({temperature,milliseconds:Number(elapsed.toFixed(3))});
      }
      latency.push({operation,samples});
    }
    success=true;return {observations,process:processRows,latency,evidence};
  } catch(error) {
    error.stateDir=dir;
    await save(dir,'observations.json',observations);
    await save(dir,'failure.json',{...evidence,message:error.message,command:error.command,args:error.args,status:error.status,signal:error.signal,spawnError:error.spawnError,stdout:error.stdout?.toString(),stderr:error.stderr?.toString(),invalid:error.invalid});
    console.error('Linux run retained partial observations and diagnostics at '+dir);
    throw error;
  } finally {if(success)await rm(dir,{recursive:true,force:true});}
}
