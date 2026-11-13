import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { cases, filesystems, operations, observationCases, serialize } from './common.mjs';
const followups=JSON.parse(readFileSync(new URL('../../docs/compat/follow-up-issues.json',import.meta.url),'utf8')).issues;
const hash=value=>createHash('sha256').update(serialize(value)).digest('hex');
function group(rows) {
  const result=new Map();const keys=new Set();
  for(const row of rows) {
    if(!cases.includes(row.case)||typeof row.step!=='string'||typeof row.call!=='string')throw new Error('invalid observation '+JSON.stringify(row));
    if(['ok','errno','skipped'].filter(k=>Object.hasOwn(row,k)).length!==1)throw new Error('observation must contain exactly one outcome');
    const key=row.case+'/'+row.step;if(keys.has(key))throw new Error('duplicate observation '+key);keys.add(key);
    if(!result.has(row.case))result.set(row.case,[]);result.get(row.case).push(row);
  }
  for(const name of cases)if(!result.has(name))throw new Error('missing case '+name);
  for(const rows of result.values())rows.sort((a,b)=>a.step.localeCompare(b.step,'en'));
  return result;
}
// Preserve raw evidence/signatures, but do not make an unobservable device field
// a permanent retained-fd mismatch. Inode, calls, errors and all other data still
// participate. Path identity is unaffected; new exposed dev evidence is checked.
function comparable(left,right,name) {
  if(!['open-rename','open-unlink'].includes(name))return {left,right,limited:false};
  const l=structuredClone(left),r=structuredClone(right);
  const a=l.find(row=>row.step==='identity'),b=r.find(row=>row.step==='identity');
  const unavailable=value=>value?.unavailable==='st_dev not exposed by both observations';
  if(a?.ok&&b?.ok&&(unavailable(a.ok.same_dev)||unavailable(b.ok.same_dev))) {
    delete a.ok.same_dev;delete b.ok.same_dev;
    return {left:l,right:r,limited:true};
  }
  return {left,right,limited:false};
}
export function differences(baseline) {
  if(baseline.schema!==1)throw new Error('unknown baseline schema');
  const linux=group(baseline.linux), result=[];
  if(Object.keys(baseline.os).sort().join()!==[...filesystems].sort().join())throw new Error('missing/unknown filesystem profile');
  for(const fs of filesystems) {
    const os=group(baseline.os[fs]);
    for(const name of cases) {
      const left=linux.get(name),right=os.get(name);
      // Calls/step names are part of the trace, and skips never become passes.
      const compared=comparable(left,right,name);
      const same=serialize(compared.left)===serialize(compared.right)&&![...left,...right].some(r=>r.skipped);
      const kind=observationCases.includes(name)&&left.some(r=>r.skipped)?'observation':'difference';
      result.push({id:fs+'/'+name,filesystem:fs,case:name,kind,limited:compared.limited,linux:left,os:right,same,signature:hash({linux:left,os:right})});
    }
  }
  return result;
}
// Deliberately small, strict TOML subset: array-of-tables with JSON-compatible
// quoted strings. Reject everything else instead of silently ignoring policy.
export function parseExpected(text,allowedIssues=followups) {
  const entries=[];let row;
  for(const raw of text.split('\n')) {
    const line=raw.trim();if(!line||line.startsWith('#'))continue;
    if(['[[difference]]','[[observation]]'].includes(line)){row={kind:line.slice(2,-2)};entries.push(row);continue;}
    const m=line.match(/^(id|issue|issues|permanent|reason|signature) = (".*"|\[.*\])$/);
    if(!row||!m||Object.hasOwn(row,m[1]))throw new Error('invalid expected-differences.toml line: '+line);
    row[m[1]]=JSON.parse(m[2]);
  }
  const ids=new Set();
  for(const row of entries) {
    const nonempty=value=>typeof value==='string'&&value.trim().length>0;
    if(!['id','reason','signature'].every(key=>nonempty(row[key]))||['issue','issues','permanent'].filter(key=>Object.hasOwn(row,key)).length!==1)throw new Error('incomplete difference '+JSON.stringify(row));
    if(Object.hasOwn(row,'issue')&&!nonempty(row.issue)||Object.hasOwn(row,'permanent')&&!nonempty(row.permanent))throw new Error('issue/permanent must be nonempty strings');
    const issues=Object.hasOwn(row,'issues')?row.issues:(row.issue?[row.issue]:[]);
    if(!Array.isArray(issues)||Object.hasOwn(row,'issues')&&!issues.length||issues.some(issue=>!nonempty(issue)||!allowedIssues.includes(issue)))throw new Error('difference must name a sub-issue listed in follow-up-issues.json');
    if(ids.has(row.id))throw new Error('duplicate difference '+row.id);ids.add(row.id);
  }
  return entries;
}
export function check(rows,expected) {
  const errors=[], actual=new Map(rows.filter(r=>!r.same).map(r=>[r.id,r]));
  const listed=new Map(expected.map(r=>[r.id,r]));
  for(const [id,row] of actual) {
    if(!listed.has(id))errors.push('unlisted difference: '+id);
    else if((listed.get(id).kind||'difference')!==row.kind)errors.push('comparison kind changed (review required): '+id);
    else if(listed.get(id).signature!==row.signature)errors.push('changed observation (review required): '+id);
  }
  for(const id of listed.keys())if(!actual.has(id))errors.push('stale difference: '+id);
  if(errors.length)throw new Error(errors.join('\n'));
}
const cell=rows=>rows.map(r=>`${r.step}: ${r.errno|| (r.skipped?'skipped: '+r.skipped:JSON.stringify(r.ok))}`).join('<br>').replaceAll('|','\\|').replaceAll('\n',' ');
export function matrix(rows,expected) {
  const listed=new Map(expected.map(r=>[r.id,r]));
  return '# L0a measured compatibility baseline\n\nGenerated by `cargo xtask conformance --target linux` and `--target os`; verified by `cargo xtask conformance --check`. See [reproduction and scope](README.md). No target architecture is selected here. `same` compares the normalized call trace on observable fields; retained-fd device identity is excluded when unavailable on either target (raw evidence is shown below). Inode and all other fields still compare; skipped cases are explicitly incomparable. Rows labeled `observation` have no portable Linux counterpart: they detect changed facts, not convergence or stale compatibility differences.\n\n| Case | Filesystem | Linux observation | OS observation | Same? / follow-up |\n| --- | --- | --- | --- | --- |\n'+rows.map(r=>{
    const e=listed.get(r.id), issues=e?.issues||(e?.issue?[e.issue]:[]);const status=r.same?'yes':issues.length?issues.map(issue=>`[${issue}](https://github.com/kingwingfly/os/issues/${issue.slice(1)})`).join(', '):e?.permanent||'UNLISTED';
    return `| ${r.case} | ${r.filesystem} | ${cell(r.linux)} | ${cell(r.os)} | ${r.kind==='observation'?'observation: ':''}${status}${r.limited?' (fd st_dev incomparable)':''} |`;
  }).join('\n')+'\n';
}
export function checkLatency(record,native=false) {
  if(record.schema!==1||record.unit!=='milliseconds')throw new Error('invalid latency schema');
  const groups=native?[record.operations]:filesystems.map(fs=>record.filesystems?.[fs]);
  for(const rows of groups) {
    if(!Array.isArray(rows)||rows.length!==operations.length||new Set(rows.map(r=>r.operation)).size!==operations.length)throw new Error('missing latency operations');
    for(const row of rows) {
      if(!operations.includes(row.operation)||row.samples?.length!==2||row.samples[0].temperature!=='cold'||row.samples[1].temperature!=='warm'||row.samples.some(s=>!Number.isFinite(s.milliseconds)||s.milliseconds<0))throw new Error('invalid cold/warm latency samples');
    }
  }
}
export async function report(out,checking=false) {
  const baseline=JSON.parse(await readFile(join(out,'baseline.json'),'utf8'));
  const rows=differences(baseline);
  let expected=[];
  try{expected=parseExpected(await readFile(join(out,'expected-differences.toml'),'utf8'));}catch(e){if(e.code!=='ENOENT')throw e;}
  const rendered=matrix(rows,expected);
  if(checking) {
    check(rows,expected);
    checkLatency(JSON.parse(await readFile(join(out,'latency.json'),'utf8')));
    checkLatency(JSON.parse(await readFile(join(out,'linux-latency.json'),'utf8')),true);
    if(await readFile(join(out,'matrix.md'),'utf8')!==rendered)throw new Error('matrix.md is stale');
    console.log(`Checked ${rows.length} rows: ${rows.filter(r=>r.same).length} same, ${rows.filter(r=>!r.same&&r.kind==='difference').length} differences/skips, ${rows.filter(r=>r.kind==='observation').length} observational records.`);
  }else await writeFile(join(out,'matrix.md'),rendered);
}
