import test from 'node:test';
import assert from 'node:assert/strict';
import { withoutMountNamespace } from '../scripts/conformance/linux.mjs';

test('no-namespace assembly replaces mount-dependent results with explicit skips',()=>{
  const rows=[{case:'absolute-symlink',step:'read',call:'read(link)',errno:'ENOENT'},
    {case:'alias',step:'identity',call:'stat',ok:true},
    {case:'open-rename',step:'read',call:'read(fd)',ok:'hello'}];
  const result=withoutMountNamespace(rows);
  assert.deepEqual(result.filter(r=>r.case==='open-rename'),[rows[2]]);
  for(const name of ['alias','absolute-symlink','cloud-to-provider','mount-api']) {
    const found=result.filter(r=>r.case===name);assert.equal(found.length,1);assert(found[0].skipped);assert(!found[0].errno);
  }
  assert(!JSON.stringify(result).includes('ENOENT'));
});
