import test from 'node:test';
import assert from 'node:assert/strict';
import { linux } from '../scripts/conformance/linux.mjs';

test('no-unshare runs stay explicit and independent of diagnostic/host startup strings',async()=>{
  const first=await linux({namespaceProbe:()=>({status:1,stderr:'fixture: namespaces denied'})});
  const second=await linux({namespaceProbe:()=>({status:1,stderr:'different host diagnostic'})});
  assert.deepEqual(first.observations,second.observations);
  const crossing=first.observations.filter(r=>r.case==='absolute-symlink');
  assert.equal(crossing.length,1);assert(crossing[0].skipped);assert(!crossing[0].errno);
  assert(first.evidence.startup.cmdline);assert(!JSON.stringify(first.observations).includes('/usr/lib/systemd'));
});
