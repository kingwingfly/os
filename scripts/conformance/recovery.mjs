// Interrupted OS runs. A runner killed outright (SIGKILL, a closed terminal) cannot clean up:
// its server, helper and Podman service run in their own process groups, and its containers
// keep running. Each run therefore records, in <state>/run.json, its runner and every process
// group it starts, by PID and start time. A later run finds runs whose runner is gone, stops
// the groups whose leader is provably the one recorded, and removes that run's containers
// through its private Podman metadata (transient, in its own runroot). A live run, or a
// process that cannot be proved to be the recorded one, is never touched.
import { readdirSync, readFileSync, existsSync, lstatSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
export const runPrefix='os-conformance-os-';

// A process's start time since boot, from /proc; with the PID it identifies one process.
export function startTime(pid) {
  try {const stat=readFileSync(`/proc/${pid}/stat`,'utf8');return stat.slice(stat.lastIndexOf(')')+2).split(' ')[19];}
  catch {return null;}
}
const sameProcess=entry=>!!entry?.pid&&!!entry.start&&startTime(entry.pid)===entry.start;

export class RunRecord {
  constructor(state) {
    this.path=join(state,'run.json');
    this.record={runner:{pid:process.pid,start:startTime(process.pid)},groups:[],containers:null};
  }
  save() {return writeFile(this.path,JSON.stringify(this.record,null,2)+'\n');}
  // Record a process group leader as soon as it exists.
  addGroup(name,pid) {if(!pid)return Promise.resolve();this.record.groups.push({name,pid,start:startTime(pid)});return this.save();}
  setContainers(containers) {this.record.containers=containers;return this.save();}
}

// Processes of this user whose command line names `state`, a unique random directory: the
// run's browser (its profile), server, helper and Podman service, whichever are still there.
export function stateProcesses(state) {
  const pids=[];
  for(const entry of readdirSync('/proc')) {
    if(!/^\d+$/.test(entry)||Number(entry)===process.pid)continue;
    try {
      if(lstatSync('/proc/'+entry).uid!==process.getuid())continue;
      const args=readFileSync(`/proc/${entry}/cmdline`,'utf8').split('\0');
      if(args.some(arg=>arg===state||arg.includes(state+'/')))pids.push({pid:Number(entry),start:startTime(entry)});
    } catch {}
  }
  return pids;
}
async function stopProcesses(processes,kill,timeout) {
  const alive=()=>processes.filter(sameProcess);
  for(const signal of ['SIGTERM','SIGKILL']) {
    for(const {pid} of alive())try {kill(pid,signal);}catch {}
    const until=Date.now()+timeout;
    while(alive().length&&Date.now()<until)await new Promise(resolve=>setTimeout(resolve,50));
  }
  return alive().length;
}
async function stopGroup(pgid,kill,timeout) {
  const alive=()=>{try {kill(-pgid,0);return true;}catch(error) {if(error.code==='ESRCH')return false;throw error;}};
  for(const signal of ['SIGTERM','SIGKILL']) {
    if(!alive())return true;
    try {kill(-pgid,signal);}catch(error) {if(error.code==='ESRCH')return true;throw error;}
    const until=Date.now()+timeout;
    while(alive()&&Date.now()<until)await new Promise(resolve=>setTimeout(resolve,50));
  }
  return !alive();
}

export async function recoverInterrupted({dir=tmpdir(),env=process.env,kill=process.kill,timeout=5000}={}) {
  const recovered=[];
  let names=[];try {names=readdirSync(dir);}catch {return recovered;}
  for(const name of names.filter(name=>name.startsWith(runPrefix)).sort()) {
    const state=join(dir,name),path=join(state,'run.json');
    let record;
    try {
      const info=lstatSync(state);
      if(!info.isDirectory()||info.uid!==process.getuid())continue;
      record=JSON.parse(readFileSync(path,'utf8'));
    } catch {continue;}
    if(record.recovered||sameProcess(record.runner))continue;
    const stopped=[],survived=[],unverified=[];
    for(const group of record.groups??[]) {
      if(sameProcess(group)) {(await stopGroup(group.pid,kill,timeout)?stopped:survived).push(group.name);continue;}
      // The leader is gone. Remaining members cannot be told apart from a group that has since
      // reused the number, so they are reported, not signalled.
      try {kill(-group.pid,0);unverified.push(group.name);}catch {}
    }
    // Anything else of the run that names its state directory, such as the browser, which
    // Playwright starts in a process group of its own.
    const others=stateProcesses(state);
    const remaining=others.length?await stopProcesses(others,kill,timeout):0;
    const processes={stopped:others.length-remaining,remaining};
    let containers=null;
    const storage=join(state,'storage.conf');
    if(record.containers?.engine==='podman'&&existsSync(storage)) {
      // The run's Podman metadata is private to it, so every container it lists is the run's.
      const cgroups=env.DBUS_SESSION_BUS_ADDRESS?[]:['--cgroup-manager=cgroupfs'];
      const result=spawnSync('podman',[...cgroups,'rm','--all','--force','--time','0'],{env:{...env,CONTAINERS_STORAGE_CONF:storage},encoding:'utf8'});
      containers=result.status===0?{removed:result.stdout.split('\n').filter(Boolean).length}:{error:(result.stderr||result.error?.message||'').trim().split('\n')[0]||'status '+result.status};
    } else if(record.containers?.label) {
      containers={remove:`docker rm -f $(docker ps -aq --filter label=${record.containers.label})`};
    }
    record.recovered={at:new Date().toISOString(),stopped,survived,unverified,processes,containers};
    await writeFile(path,JSON.stringify(record,null,2)+'\n');
    recovered.push({state,...record.recovered});
  }
  return recovered;
}
