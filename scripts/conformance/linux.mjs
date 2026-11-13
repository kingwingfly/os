import { mkdtemp, mkdir, rm, readFile, chmod, readlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync, spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { run, targetDir, jsonLines, skip, ok } from './common.mjs';
export async function linux() {
  run('cargo',['build','--locked','-p','os-conformance'],{stdio:'inherit'});
  const binary=join(targetDir(),'debug/os-conformance');
  const dir=await mkdtemp(join(tmpdir(),'os-conformance-linux-'));
  try {
    await chmod(dir,0o755);
    let observations=[];
    const available=spawnSync('unshare',['-Urm','true'],{encoding:'utf8'});
    const mapped=spawnSync('unshare',['-Urm','--map-auto','true'],{encoding:'utf8'});
    if (available.status===0) {
      observations.push(...jsonLines(run('unshare',['-Urm',...(mapped.status===0?['--map-auto']:[]),binary,'namespace',dir,dir,dir,'0','0'])));
    } else {
      for (const name of ['alias','remount','unmount-open','unmount-cwd','cross-rename','mount-parent','mount-api','umount-api','chroot-api']) observations.push(skip(name,'rootless unshare -Urm unavailable: '+(available.stderr||available.error?.message).trim()));
      const tree=join(dir,'tree');await mkdir(tree);
      const rows=jsonLines(run(binary,['basic',tree,tree,tree,String(process.getuid()),String(process.getgid())]));
      observations.push(...rows.filter(row=>!observations.some(old=>old.case===row.case)));
      observations.push(skip('cloud-to-provider','rootless mount namespace unavailable'));
    }
    const two=join(dir,'two');await mkdir(two);
    if (mapped.status===0) observations.push(...jsonLines(run('unshare',['-Urm','--map-auto',binary,'two-linux',two,two,two,'0','0'])));
    else observations.push(skip('two-accounts','subuid/subgid mappings unavailable: '+(mapped.stderr||mapped.error?.message).trim()));
    const comm=(await readFile('/proc/1/cmdline','utf8')).split('\0')[0].split('/').at(-1);
    observations.push(ok('startup','pid1','read /proc/1/cmdline',{comm}));
    observations.push(ok('startup','ownership','inspect /proc/1 and native boot/service launcher',{owner:'host PID 1',evidence:'/proc/1/cmdline; /proc/1/exe', executable:await readlink('/proc/1/exe').catch(()=> 'permission denied')}));
    observations.push(skip('gui-processes','headless Linux reference has no Files/Editor/Preview/Mounts desktop applications'));
    observations.push(skip('tab-pids','Linux reference has no browser OS tabs; process visibility is namespace-scoped'));
    const timingRoot=join(dir,'timing');await mkdir(timingRoot);
    const args=['latency',timingRoot,timingRoot,timingRoot,String(process.getuid()),String(process.getgid())];
    run(binary,[...args,'prepare']);const latency=[];
    for (const operation of ['stat-eight-deep','read-1mib','write-1mib','ls-usr-bin','shell-first-prompt']) {
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
          else {const result=jsonLines(run(binary,[...args,{'stat-eight-deep':'stat','read-1mib':'read','write-1mib':'write'}[operation]]));if(result.some(r=>r.errno))throw new Error('native timing operation failed');}
          elapsed=performance.now()-started;
        }
        samples.push({temperature,milliseconds:Number(elapsed.toFixed(3))});
      }
      latency.push({operation,samples});
    }
    return {observations,latency};
  } finally {await rm(dir,{recursive:true,force:true});}
}
