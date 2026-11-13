import test from 'node:test';
import assert from 'node:assert/strict';
import { cases, filesystems, operations, ok, cleanup, revision } from '../scripts/conformance/common.mjs';
import { differences, check, parseExpected, matrix, checkLatency } from '../scripts/conformance/report.mjs';
const fixture=()=>{
  const rows=cases.map(name=>ok(name,'call',name,null));
  return {schema:1,linux:structuredClone(rows),os:Object.fromEntries(filesystems.map(fs=>[fs,structuredClone(rows)]))};
};
test('conformance rejects unlisted, stale, and changed differences',()=>{
  const baseline=fixture();baseline.os.cloud[0].ok='different';
  const rows=differences(baseline),different=rows.find(r=>!r.same);
  assert.throws(()=>check(rows,[]),/unlisted difference: cloud\/alias/);
  const expected=[{id:different.id,issue:'#48',reason:'fixture',signature:different.signature}];
  assert.doesNotThrow(()=>check(rows,expected));
  assert.throws(()=>check(differences(fixture()),expected),/stale difference/);
  baseline.os.cloud[0].ok='another result';
  assert.throws(()=>check(differences(baseline),expected),/changed observation/);
});
test('conformance fails missing cases, profiles and duplicate steps instead of blessing incomplete runs',()=>{
  const baseline=fixture();baseline.os.cloud.pop();assert.throws(()=>differences(baseline),/missing case/);
  const missing=fixture();delete missing.os.relay;assert.throws(()=>differences(missing),/filesystem profile/);
  const duplicate=fixture();duplicate.linux.push(duplicate.linux[0]);assert.throws(()=>differences(duplicate),/duplicate observation/);
});
test('skips remain incomparable and evidence ordering is normalized',()=>{
  const baseline=fixture();for(const rows of [baseline.linux,...Object.values(baseline.os)]){delete rows[0].ok;rows[0].skipped='no mount support';}
  assert.equal(differences(baseline).filter(r=>!r.same).length,5);
  const ordered=fixture();ordered.os.cloud.reverse();assert(differences(ordered).every(r=>r.same));
});
test('difference policy requires an owning issue or explicit permanent limit',()=>{
  const valid='[[difference]]\nid = "cloud/alias"\nissue = "#48"\nreason = "pending object model"\nsignature = "abc"\n';
  assert.equal(parseExpected(valid)[0].issue,'#48');
  for(const bad of [valid.replace('#48','#44'),valid+'unexpected = "ignored"\n',valid+valid,valid.replace('issue = "#48"\n','')])assert.throws(()=>parseExpected(bad));
  assert.match(matrix(differences(fixture()),[]),/\| alias \| cloud .* yes \|/);
});

test('latency coverage requires both successful finite samples for every operation and filesystem',()=>{
  const samples=operations.map(operation=>({operation,samples:[{temperature:'cold',milliseconds:1},{temperature:'warm',milliseconds:0.5}]}));
  const record={schema:1,unit:'milliseconds',filesystems:Object.fromEntries(filesystems.map(fs=>[fs,structuredClone(samples)]))};
  assert.doesNotThrow(()=>checkLatency(record));
  delete record.filesystems.cloud;assert.throws(()=>checkLatency(record),/missing latency/);
  const native={schema:1,unit:'milliseconds',operations:samples};native.operations[0].samples[1].milliseconds=null;
  assert.throws(()=>checkLatency(native,true),/invalid cold\/warm/);
});


test('policy rejects array-valued scalar fields and accepts new issue IDs only through data',()=>{
  const valid='[[difference]]\nid = "cloud/alias"\nissue = "#48"\nreason = "pending"\nsignature = "abc"\n';
  for(const key of ['id','issue','reason','signature']) {
    const bad=valid.replace(new RegExp(key+' = ("[^"\\n]*")'),key+' = [$1]');
    assert.throws(()=>parseExpected(bad));
  }
  assert.throws(()=>parseExpected(valid.replace('issue = "#48"','permanent = []')));
  assert.throws(()=>parseExpected(valid.replace('issue = "#48"','issues = [["#48"]]')));
  assert.throws(()=>parseExpected(valid.replace('#48','#67')));
  assert.equal(parseExpected(valid.replace('#48','#67'),['#67'])[0].issue,'#67');
});

test('process facts are explicitly observational, detect changes, and can be reclassified when a Linux counterpart exists',()=>{
  const b=fixture(),i=cases.indexOf('startup');
  b.linux[i]={case:'startup',step:'unavailable',call:'startup',skipped:'environment evidence only'};
  const rows=differences(b), entries=rows.filter(r=>!r.same).map(r=>({kind:'observation',id:r.id,signature:r.signature}));
  assert(rows.filter(r=>r.kind==='observation').length===5);
  assert.doesNotThrow(()=>check(rows,entries));
  assert.match(matrix(rows,[]),/observation:/);
  b.os.cloud[i].ok='changed service ownership';
  assert.throws(()=>check(differences(b),entries),/changed observation/);
  assert.throws(()=>check(differences(fixture()),entries),/stale difference/);
});

test('cleanup failures do not prevent subsequent cleanup or restoring the process umask',async()=>{
  const seen=[],mask=process.umask();
  const errors=await cleanup([
    ['podman ps',()=>{throw new Error('engine unavailable');}],
    ['service',()=>seen.push('stopped')],['log',()=>seen.push('closed')],['umask',()=>process.umask(mask)],
  ]);
  assert.deepEqual(seen,['stopped','closed']);assert.equal(process.umask(),mask);
  assert.equal(errors[0].error.message,'engine unavailable');
});

test('retained-fd device limits do not prevent convergence on observable fields',()=>{
  const baseline=fixture(),i=cases.indexOf('open-rename');
  baseline.linux[i]=ok('open-rename','identity','fstat(fd)',{same_dev:true,same_ino:true});
  baseline.os.cloud[i]=ok('open-rename','identity','fstat(fd)',{same_dev:{unavailable:'st_dev not exposed by both observations'},same_ino:true});
  const row=()=>differences(baseline).find(r=>r.id==='cloud/open-rename');
  assert(row().same);assert(row().limited);assert.equal(row().linux[0].ok.same_dev,true);
  assert.throws(()=>check([row()],[{id:row().id,signature:row().signature}]),/stale difference/);
  const signature=row().signature;
  baseline.os.cloud[i].ok.same_ino=false;assert(!row().same);
  baseline.os.cloud[i].ok.same_ino={unavailable:'st_ino not exposed by both observations'};assert(!row().same);
  baseline.os.cloud[i].ok={same_dev:false,same_ino:true};assert(!row().same);assert(!row().limited);assert.notEqual(row().signature,signature);
});
