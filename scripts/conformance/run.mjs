import { parseArgs } from 'node:util';
import { readFile, mkdtemp, copyFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { save, run } from './common.mjs';
import { report } from './report.mjs';
const {values}=parseArgs({options:{target:{type:'string'},out:{type:'string',default:'docs/compat'},check:{type:'boolean'},recorded:{type:'boolean'},report:{type:'boolean'}}});
const out=resolve(values.out);
if(values.recorded&&!values.check)throw new Error('--recorded requires --check');
if(values.check||values.report) {
  if(values.target||values.check&&values.report)throw new Error('choose --target, --check, or --report');
  await report(out,!!values.check);
  if(values.check&&!values.recorded) {
    const fresh=await mkdtemp(join(tmpdir(),'os-conformance-check-'));
    try {
      await copyFile(join(out,'expected-differences.toml'),join(fresh,'expected-differences.toml'));
      for(const target of ['linux','os'])run(process.execPath,['scripts/conformance/run.mjs','--target',target,'--out',fresh],{stdio:'inherit'});
      await report(fresh,true);
      if(await readFile(join(out,'baseline.json'),'utf8')!==await readFile(join(fresh,'baseline.json'),'utf8'))throw new Error('fresh baseline differs from committed baseline.json');
      await rm(fresh,{recursive:true,force:true});
      console.log('Fresh Linux and OS runs reproduce baseline.json byte for byte.');
    } catch(error) {console.error('Fresh evidence retained at '+fresh);throw error;}
  }
} else {
  if(!['linux','os'].includes(values.target))throw new Error('usage: cargo xtask conformance --target linux|os [--out DIR] | --check | --report');
  let baseline={schema:1,linux:[],os:{}};
  try{baseline=JSON.parse(await readFile(join(out,'baseline.json'),'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
  if(values.target==='linux') {
    const result=await (await import('./linux.mjs')).linux();baseline.linux=result.observations;
    await save(out,'linux-latency.json',{schema:1,unit:'milliseconds',method:'First invocation and immediate repeat in a temporary host filesystem; no page-cache eviction. Command wall time; shell ends at first prompt.',operations:result.latency});
  }
  else {
    const result=await (await import('./os.mjs')).os();baseline.os=result.observations;
    await save(out,'latency.json',{schema:1,unit:'milliseconds',method:'First operation in a fresh filesystem/profile and immediate repeat; browser wall time including process launch and return. No OS/provider cache eviction.',filesystems:result.latencies});
    await save(out,'evidence.json',{runtime_base:run('git',['rev-parse','origin/dev']).trim(),browser:result.browser,platform:run('uname',['-srmo']).trim(),rust:run('rustc',['--version']).trim(),node:process.version,source:result.evidence,compiler:result.compiler});
  }
  await save(out,'baseline.json',baseline);
  if(baseline.linux.length&&Object.keys(baseline.os).length)await report(out);
  console.log('Saved '+values.target+' observations in '+out);
}
