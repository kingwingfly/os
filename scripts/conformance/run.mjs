import { parseArgs } from 'node:util';
import { readFile, mkdtemp, copyFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { run, revision, generatedFiles } from './common.mjs';
import { saveRun } from './results.mjs';
import { report } from './report.mjs';
const {values}=parseArgs({options:{target:{type:'string'},out:{type:'string',default:'docs/compat'},check:{type:'boolean'},recorded:{type:'boolean'},report:{type:'boolean'}}});
const out=resolve(values.out);
// The runners build and read repository files by relative path. Resolve --out against the
// caller's directory first, then work from the repository root wherever this was started.
const script=fileURLToPath(import.meta.url);
process.chdir(fileURLToPath(new URL('../..',import.meta.url)));
if(values.recorded&&!values.check)throw new Error('--recorded requires --check');
if(values.check||values.report) {
  if(values.target||values.check&&values.report)throw new Error('choose --target, --check, or --report');
  await report(out,!!values.check);
  if(values.check&&!values.recorded)await freshCheck();
} else {
  if(!['linux','os'].includes(values.target))throw new Error('usage: cargo xtask conformance --target linux|os [--out DIR] | --check | --report');
  const empty=()=>({schema:2,linux:[],os:{},process:{linux:[],os:[]}});
  let baseline=empty();
  try{baseline=JSON.parse(await readFile(join(out,generatedFiles.baseline),'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
  if(baseline.schema!==2) {console.log('Baseline schema changed; rerun both targets.');baseline=empty();}
  const provenance={revision:revision('.',out),platform:run('uname',['-srmo']).trim(),rust:run('rustc',['--version']).trim(),node:process.version};
  const result=await (await import('./'+values.target+'.mjs'))[values.target]();
  await saveRun(out,baseline,values.target,result,provenance);
  if(baseline.linux.length&&Object.keys(baseline.os).length&&baseline.process.linux.length&&baseline.process.os.length)await report(out);
  console.log('Saved '+values.target+' observations in '+out);
}

// Rerun both targets into a fresh directory and require the same baseline. Each rerun has its
// own process group, so a terminal Ctrl-C reaches only this process, which passes it on once:
// the rerun's cleanup scope then finishes, and a second signal still stops it at once. Either
// way the retained directory is reported before exiting.
async function freshCheck() {
  const fresh=await mkdtemp(join(tmpdir(),'os-conformance-check-'));
  let child,interrupted;
  const forward=signal=>{interrupted??=signal;if(child&&child.exitCode===null&&child.signalCode===null)child.kill(signal);};
  const handlers=[['SIGINT',()=>forward('SIGINT')],['SIGTERM',()=>forward('SIGTERM')]];
  for(const [event,handler] of handlers)process.on(event,handler);
  try {
    // A missing registry means no listed differences, as report() reads it.
    await copyFile(join(out,'expected-differences.toml'),join(fresh,'expected-differences.toml')).catch(error=>{if(error.code!=='ENOENT')throw error;});
    for(const target of ['linux','os']) {
      if(interrupted)throw new Error('interrupted by '+interrupted);
      child=spawn(process.execPath,[script,'--target',target,'--out',fresh],{stdio:['ignore','inherit','inherit'],detached:true});
      const [code,signal]=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>resolve([code,signal]));});
      child=null;
      if(interrupted)throw new Error('interrupted by '+interrupted);
      if(code!==0)throw new Error(`fresh ${target} run failed with ${signal??'status '+code}`);
    }
    await report(fresh,true);
    if(await readFile(join(out,generatedFiles.baseline),'utf8')!==await readFile(join(fresh,generatedFiles.baseline),'utf8'))throw new Error('fresh baseline differs from committed baseline.json');
    await rm(fresh,{recursive:true,force:true});
    console.log('Fresh Linux and OS runs reproduce baseline.json byte for byte.');
  } catch(error) {
    console.error('Fresh evidence retained at '+fresh);
    if(!interrupted)throw error;
    console.error(error.message);
    process.exit(interrupted==='SIGINT'?130:143);
  } finally {for(const [event,handler] of handlers)process.off(event,handler);}
}
