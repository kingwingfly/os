import { execFileSync, spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
export const filesystems = ['cloud', 'browser-storage', 'directory-handle', 'local-helper', 'relay'];
export const operations = ['stat-eight-deep','read-1mib','write-1mib','ls-usr-bin','shell-first-prompt'];
export const probeOperations = {'stat-eight-deep':'stat','read-1mib':'read','write-1mib':'write'};
export const observationCases = ['startup','gui-processes','tab-pids'];
export const cases = ['alias','remount','open-rename','open-unlink','unmount-open','unmount-cwd','flush','mount-parent','link-dotdot','cloud-to-provider','absolute-symlink','cwd-rename','cwd-remove','cross-rename','exclusive','append','noreplace','hard-link','symlink','creation','two-accounts','chroot-api','mount-api','umount-api','startup','gui-processes','tab-pids'];
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
export async function port() {const s=createServer();await new Promise((resolve,reject)=>s.once('error',reject).listen(0,'127.0.0.1',resolve));const port=s.address().port;await new Promise(resolve=>s.close(resolve));return port;}
export async function stop(child) {
  if (!child || child.exitCode!==null || child.signalCode!==null) return;
  const exited=new Promise(resolve=>child.once('exit',resolve));
  try {process.kill(-child.pid,'SIGTERM');} catch {child.kill('SIGTERM');}
  const timer=setTimeout(()=>{try {process.kill(-child.pid,'SIGKILL');} catch {}},5000);
  await exited;clearTimeout(timer);
}
export function start(cmd,args,options={}) {return spawn(cmd,args,{detached:true,...options});}
export async function sourceEvidence(path,fragments) {
  const text=await readFile(path,'utf8');
  return {path,fragments:fragments.map(fragment=>({text:fragment,found:text.includes(fragment)}))};
}
// Run every teardown even if another one fails. The caller can preserve its
// original exception and still report cleanup failures independently.
export async function cleanup(actions) {
  const errors=[];
  for (const [name,action] of actions) {
    try {await action();} catch(error) {errors.push({name,error});}
  }
  return errors;
}
export function revision(cwd='.') {
  return {
    head:run('git',['rev-parse','HEAD'],{cwd}).trim(),
    dirty:!!run('git',['status','--porcelain','--untracked-files=normal','--','.',':!.worktrees'],{cwd}).trim(),
  };
}
