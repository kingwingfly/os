import test from 'node:test';
import assert from 'node:assert/strict';
import { cases, filesystems, ok } from '../scripts/conformance/common.mjs';
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
  const operations=['stat-eight-deep','read-1mib','write-1mib','ls-usr-bin','shell-first-prompt'].map(operation=>({operation,samples:[{temperature:'cold',milliseconds:1},{temperature:'warm',milliseconds:0.5}]}));
  const record={schema:1,unit:'milliseconds',filesystems:Object.fromEntries(filesystems.map(fs=>[fs,structuredClone(operations)]))};
  assert.doesNotThrow(()=>checkLatency(record));
  delete record.filesystems.cloud;assert.throws(()=>checkLatency(record),/missing latency/);
  const native={schema:1,unit:'milliseconds',operations};native.operations[0].samples[1].milliseconds=null;
  assert.throws(()=>checkLatency(native,true),/invalid cold\/warm/);
});
