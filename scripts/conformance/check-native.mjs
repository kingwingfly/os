// Explicit integration gate: excluded from routine npm test.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { linux, buildProbe } from './linux.mjs';
import { run, jsonLines } from './common.mjs';

const dir=await mkdtemp(join(tmpdir(),'conformance-native-check-'));
const binary=buildProbe();
const previousTmp=process.env.TMPDIR;
try {
  const physical=join(dir,'physical'),linked=join(dir,'linked');
  await mkdir(physical);await symlink(physical,linked);
  process.env.TMPDIR=physical;
  const first=await linux({binary,measureLatency:false,namespaceProbe:()=>({status:1,stderr:'fixture denies namespace creation'})});
  process.env.TMPDIR=linked;
  const second=await linux({binary,measureLatency:false,namespaceProbe:()=>({status:1,stderr:'different diagnostic'})});
  assert.deepEqual(first.observations,second.observations);
  for(const name of ['alias','remount','unmount-open','unmount-cwd','cross-rename','absolute-symlink','mount-parent','mount-api','umount-api','chroot-api','cloud-to-provider']) {
    const rows=first.observations.filter(r=>r.case===name);
    assert.equal(rows.length,1);assert(rows[0].skipped,name);
  }
  assert(!JSON.stringify(second.observations).includes(dir));
  for(const mode of ['creator','latency']) {
    const result=spawnSync(binary,[mode,dir,dir,dir,'1','1'],{encoding:'utf8'});
    assert.equal(result.status,2);assert.match(result.stderr,/MODE ROOT/);assert(!result.stderr.includes('panicked'));
  }
  const available=spawnSync('unshare',['-Urm','true'],{encoding:'utf8'});
  assert.equal(available.status,0,'integration gate needs rootless namespaces');
  const partial=await linux({binary,measureLatency:false,namespaceProbe:(_cmd,args)=>args.includes('--map-auto')?{status:1,stderr:'fixture disables subordinate mapping'}:available});
  for(const [caseName,steps] of [['alias',['setfacl','acl']],['creation',['default-acl','create','stat','acl']],['remount',['setfacl','stat','acl']]]) {
    for(const step of steps)assert(partial.observations.find(r=>r.case===caseName&&r.step===step)?.skipped,caseName+'/'+step);
  }
  assert(!partial.observations.some(r=>['alias','creation','remount'].includes(r.case)&&r.errno==='EINVAL'));
  const denied=join(dir,'denied');await mkdir(denied);
  const rows=jsonLines(run('unshare',['-Urm','setpriv','--bounding-set=-setgid',binary,'two-linux',denied,denied,denied,'0','0']));
  assert.equal(rows.length,1);assert.match(rows[0].skipped,/supplementary groups/);
  const short=join(dir,'short-map');await mkdir(short);
  const shortRows=jsonLines(run('unshare',['-Urm','--map-auto','unshare','-Urm','--map-users=0:0:10000','--map-groups=0:0:10000',binary,'two-linux',short,short,short,'0','0']));
  assert.equal(shortRows.length,1);assert.match(shortRows[0].skipped,/65534.*not mapped/);
  // Inject a real bind-mount failure after the held-open case has emitted rows.
  const wrapper=join(dir,'fail-attach.mjs');
  await writeFile(wrapper,'#!'+process.execPath+'\n'+
    `import {spawnSync} from 'node:child_process';const r=spawnSync('strace',['-qq','-e','trace=mount','-e','inject=mount:error=EBUSY:when=5',${JSON.stringify(binary)},...process.argv.slice(2)],{stdio:'inherit'});process.exit(r.status??1);\n`,{mode:0o755});
  let failed;
  try {await linux({binary:wrapper,measureLatency:false});}catch(error){failed=error;}
  assert(failed?.stateDir,'injected mount failure was not reached');
  try {
    const kept=JSON.parse(await readFile(join(failed.stateDir,'observations.json'),'utf8'));
    assert(kept.some(r=>r.case==='alias'&&r.step==='create'));
    assert.equal(kept.find(r=>r.case==='unmount-open'&&r.step==='attach').errno,'EBUSY');
    assert(!kept.some(r=>r.case==='unmount-cwd'));
    const diagnostic=JSON.parse(await readFile(join(failed.stateDir,'failure.json'),'utf8'));
    assert.equal(diagnostic.status,101);assert.match(diagnostic.stderr,/held-case re-attach failed/);
  } finally {await rm(failed.stateDir,{recursive:true,force:true});}
  const timing=join(dir,'latency');await mkdir(timing);
  const timingArgs=['latency',timing,timing,timing,'0','0'];
  run(binary,[...timingArgs,'prepare']);
  const trace=join(dir,'stat.trace');
  run('strace',['-qq','-o',trace,'-e','trace=%file',binary,...timingArgs,'stat']);
  const calls=(await readFile(trace,'utf8')).split('\n');
  assert.equal(calls.filter(line=>line.includes(JSON.stringify(join(timing,'1/2/3/4/5/6/7/file')))).length,1);
  assert.equal(calls.filter(line=>line.includes(JSON.stringify(join(timing,'1/2/3/4/5/6/7')))).length,0);
  const full=await linux({binary,measureLatency:false});
  for(const name of ['unmount-open','unmount-cwd']) {
    const rows=full.observations.filter(r=>r.case===name);
    assert.equal(rows.find(r=>r.step==='unmount').errno,'EBUSY');
    assert.equal(rows.find(r=>r.step==='detach').ok,null);
    assert.equal(rows.find(r=>r.step==='attach').ok,null);
  }
  assert.equal(full.observations.find(r=>r.case==='unmount-open'&&r.step==='read').ok,'hello');
  assert.equal(full.observations.find(r=>r.case==='unmount-cwd'&&r.step==='getcwd').errno,'ENOENT');
  assert(!Object.hasOwn(full,'latency'));
  const creators=full.observations.filter(r=>r.case==='two-accounts');
  for(const name of ['a','b']) {
    assert.equal(creators.find(r=>r.step===name+'-create').ok,null);
    assert.equal(creators.find(r=>r.step===name+'-stat').ok.owner_is_caller,true);
    assert.deepEqual(creators.find(r=>r.step===name+'-inheritance').ok,{group_is_parent:true,group_is_caller:false});
  }
  if(previousTmp===undefined)delete process.env.TMPDIR;else process.env.TMPDIR=previousTmp;
  const ordinary=await linux({binary,measureLatency:false});
  assert.deepEqual(ordinary.observations,full.observations,'private TMPDIR ancestors changed measured semantics');
  const cloud=join(dir,'cloud'),cross=join(dir,'cross');await mkdir(cloud);await mkdir(cross);
  const cloudRows=jsonLines(run(binary,['basic-cloud',cloud,cloud,cross,String(process.getuid()),String(process.getgid())]));
  for(const name of ['alias','mount-parent','remount','unmount-open','unmount-cwd']) {
    const rows=cloudRows.filter(r=>r.case===name);assert.equal(rows.length,1);assert(rows[0].skipped,name);
  }
  await assert.rejects(readFile(join(cloud,'alias-file')),{code:'ENOENT'});

  console.log('Native integration: actual MNT_DETACH with retained fd/cwd, fallback repetition, symlinked TMPDIR, partial/10000-ID mappings, denied setgroups, retained panic output, single-stat timing, private TMPDIR creator parity, probe-owned cloud skips and CLI usage passed.');
} finally {
  if(previousTmp===undefined)delete process.env.TMPDIR;else process.env.TMPDIR=previousTmp;
  await rm(dir,{recursive:true,force:true});
}
