// Explicit integration gate: excluded from routine npm test.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, symlink } from 'node:fs/promises';
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
  console.log('Native integration: actual MNT_DETACH with retained fd/cwd, fallback repetition, symlinked TMPDIR, partial mappings, denied setgroups and CLI usage passed.');
} finally {
  if(previousTmp===undefined)delete process.env.TMPDIR;else process.env.TMPDIR=previousTmp;
  await rm(dir,{recursive:true,force:true});
}
