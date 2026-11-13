import { execFileSync } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve, relative, isAbsolute } from 'node:path';
import { existsSync, realpathSync } from 'node:fs';
import { start as spawnOwned } from '../process.mjs';
export { stop } from '../process.mjs';
export const filesystems = ['cloud', 'browser-storage', 'directory-handle', 'local-helper', 'relay'];
export const operations = ['stat-eight-deep','read-1mib','write-1mib','ls-usr-bin','shell-first-prompt'];
export const probeOperations = {'stat-eight-deep':'stat','read-1mib':'read','write-1mib':'write'};
export const observationCases = ['startup','gui-processes','tab-pids'];
export const cases = ['alias','remount','open-rename','open-unlink','unmount-open','unmount-cwd','flush','mount-parent','link-dotdot','cloud-to-provider','absolute-symlink','cwd-rename','cwd-remove','cross-rename','exclusive','append','noreplace','hard-link','symlink','creation','two-accounts','chroot-api','mount-api','umount-api'];
export const run = (cmd,args,options={}) => execFileSync(cmd,args,{encoding:'utf8',maxBuffer:32<<20,...options});
export const targetDir = () => JSON.parse(run('cargo',['metadata','--no-deps','--format-version=1'])).target_directory;
export const jsonLines = s => s.trim().split('\n').filter(Boolean).map(line=>JSON.parse(line));
export const skip = (name,reason) => ({case:name,step:'unavailable',call:name,skipped:reason});
export const ok = (name,step,call,value) => ({case:name,step,call,ok:value});
export function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value==='object') return Object.fromEntries(Object.keys(value).sort().map(k=>[k,canonical(value[k])]));
  return value;
}
export const serialize = value => JSON.stringify(canonical(value),null,2)+'\n';
export async function save(out,name,value) {await mkdir(out,{recursive:true});await writeFile(join(out,name),serialize(value));}
export async function ports(count) {
  const listeners=[];
  try {
    for(let i=0;i<count;i++) {
      const s=createServer();listeners.push(s);
      await new Promise((resolve,reject)=>s.once('error',reject).listen(0,'127.0.0.1',resolve));
    }
    return listeners.map(s=>s.address().port);
  } finally {await Promise.all(listeners.map(s=>new Promise(resolve=>s.close(resolve))));}
}
export async function port() {return (await ports(1))[0];}
export function start(cmd,args,options={}) {return spawnOwned(cmd,args,{detached:true,...options});}
export async function sourceEvidence(path,fragments) {
  const text=await readFile(path,'utf8');
  return {path,fragments:fragments.map(fragment=>({text:fragment,found:text.includes(fragment)}))};
}
export function revision(cwd='.',out=null) {
  const exclusions=[':!.worktrees'];
  if(out) {
    const root=run('git',['rev-parse','--show-toplevel'],{cwd}).trim();
    const output=resolve(out),path=relative(root,existsSync(output)?realpathSync(output):output);
    // Never exclude the whole source tree when --out is the repository root.
    if(path!=='..'&&!path.startsWith('../')&&!isAbsolute(path)) {
      for(const file of ['baseline.json','latency.json','linux-latency.json','evidence.json','linux-evidence.json','matrix.md'])exclusions.push(':(exclude,literal)'+join(path,file));
    }
  }
  return {
    head:run('git',['rev-parse','HEAD'],{cwd}).trim(),
    dirty:!!run('git',['status','--porcelain','--untracked-files=all','--',':/',...exclusions],{cwd}).trim(),
  };
}
