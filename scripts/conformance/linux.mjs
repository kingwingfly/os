import { mkdtemp, mkdir, rm, readFile, writeFile, chmod, readlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { run, targetDir, jsonLines, skip, operations, probeOperations } from './common.mjs';
export async function linux({namespaceProbe=spawnSync}={}) {
  run('cargo',['build','--locked','-p','os-conformance','--release'],{stdio:'inherit'});
  const binary=join(targetDir(),'release/os-conformance');
  const dir=await mkdtemp(join(tmpdir(),'os-conformance-linux-'));
  try {
    await chmod(dir,0o755);
    let observations=[];
    const evidence={};
    const available=namespaceProbe('unshare',['-Urm','true'],{encoding:'utf8'});
    const mapped=namespaceProbe('unshare',['-Urm','--map-auto','true'],{encoding:'utf8'});
    evidence.namespaces={mount:available.stderr?.trim()||available.error?.message||null,mapped:mapped.stderr?.trim()||mapped.error?.message||null};
    if (available.status===0) {
      observations.push(...jsonLines(run('unshare',['-Urm',...(mapped.status===0?['--map-auto']:[]),binary,'namespace',dir,dir,dir,'0','0'])));
    } else {
      for (const name of ['alias','remount','unmount-open','unmount-cwd','cross-rename','absolute-symlink','mount-parent','mount-api','umount-api','chroot-api']) observations.push(skip(name,'rootless mount namespace unavailable; see linux-evidence.json'));
      const tree=join(dir,'tree');await mkdir(tree);
      // Keep even the discarded cross-mount probe well formed. The fallback
      // cannot measure mount crossings and must never turn ENOENT into a pass.
      await writeFile(join(tree,'target'),'target');
      const rows=jsonLines(run(binary,['basic',tree,tree,tree,String(process.getuid()),String(process.getgid())]));
      observations.push(...rows.filter(row=>!observations.some(old=>old.case===row.case)));
      observations.push(skip('cloud-to-provider','rootless mount namespace unavailable'));
    }
    const two=join(dir,'two');await mkdir(two);
    if (mapped.status===0) observations.push(...jsonLines(run('unshare',['-Urm','--map-auto',binary,'two-linux',two,two,two,'0','0'])));
    else observations.push(skip('two-accounts','subuid/subgid mappings unavailable; see linux-evidence.json'));
    const observe=async action=>{try{return {ok:await action()};}catch(e){return {errno:e.code||'UNKNOWN_ERROR'};}};
    evidence.startup={
      cmdline:await observe(async()=>(await readFile('/proc/1/cmdline','utf8')).split('\0')[0].split('/').at(-1)),
      executable:await observe(()=>readlink('/proc/1/exe')),
    };
    observations.push(skip('startup','host PID 1 details are environmental evidence in linux-evidence.json, not a portable OS comparison'));
    observations.push(skip('gui-processes','headless Linux reference has no Files/Editor/Preview/Mounts desktop applications'));
    observations.push(skip('tab-pids','Linux reference has no browser OS tabs; process visibility is namespace-scoped'));
    const timingRoot=join(dir,'timing');await mkdir(timingRoot);
    const args=['latency',timingRoot,timingRoot,timingRoot,String(process.getuid()),String(process.getgid())];
    run(binary,[...args,'prepare']);const latency=[];
    for (const operation of operations) {
      const samples=[];
      for (const temperature of ['cold','warm']) {
        const started=performance.now();let elapsed;
        if(operation==='shell-first-prompt') {
          elapsed=await new Promise((resolve,reject)=>{
            const shell=spawn('/bin/sh',['-i'],{env:{...process.env,PS1:'CONFORMANCE_PROMPT> '},cwd:timingRoot});
            let output='',done=false;
            const timeout=setTimeout(()=>{shell.kill();reject(new Error('native shell prompt timeout'));},10000);
            shell.stderr.on('data',data=>{output+=data;if(!done&&output.includes('CONFORMANCE_PROMPT>')){done=true;elapsed=performance.now()-started;shell.stdin.end('exit\n');}});
            shell.once('exit',code=>{clearTimeout(timeout);if(!done||code!==0)reject(new Error('native shell prompt failed'));else resolve(elapsed);});
          });
        } else {
          if(operation==='ls-usr-bin')run('/bin/ls',['-l','/usr/bin']);
          else {const result=jsonLines(run(binary,[...args,probeOperations[operation]]));if(result.some(r=>r.errno))throw new Error('native timing operation failed');}
          elapsed=performance.now()-started;
        }
        samples.push({temperature,milliseconds:Number(elapsed.toFixed(3))});
      }
      latency.push({operation,samples});
    }
    return {observations,latency,evidence};
  } finally {await rm(dir,{recursive:true,force:true});}
}
