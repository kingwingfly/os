// Process ownership for the conformance runners: owned process groups and one cleanup scope.
// The runners are Linux-only; process facts come from /proc.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
const stopping=new WeakMap();
const groupPoll=250;

// Whether any process (or thread) currently has this ID.
const idInUse=id=>existsSync('/proc/'+id);
// Live members of process group `pgid`, for diagnostics.
export function groupMembers(pgid) {
  const members=[];
  for(const entry of readdirSync('/proc')) {
    if(!/^\d+$/.test(entry))continue;
    try {
      const stat=readFileSync(`/proc/${entry}/stat`,'utf8');
      // Fields after the parenthesized command: state, ppid, pgrp, ...
      const [state,,pgrp]=stat.slice(stat.lastIndexOf(')')+2).split(' ');
      if(Number(pgrp)===pgid)members.push({pid:Number(entry),state});
    } catch {}
  }
  return members;
}
const groupExists=pgid=>{
  try {process.kill(-pgid,0);return true;}
  catch(error) {return error.code!=='ESRCH';}
};

export function start(cmd,args,options={}) {
  const child=spawn(cmd,args,options);
  child.processGroup=!!options.detached;
  // Spawn failures are asynchronous. Consumers inspect this or await 'error';
  // never let an unhandled ChildProcess error bypass their cleanup scope.
  child.on('error',error=>{child.spawnError=error;});
  if(child.processGroup&&child.pid) {
    // After the leader exits, the group's number stays ours only while a member remains: the
    // kernel does not reuse an ID that still names a process group. Once the group has been
    // seen empty, it is gone for good, so stop() never signals a number that may since have
    // been given to another group.
    child.once('exit',()=>{
      const check=()=>{if(!child.groupGone&&(!groupExists(child.pid)||idInUse(child.pid)))child.groupGone=true;if(child.groupGone)clearInterval(watch);};
      const watch=setInterval(check,groupPoll);watch.unref();check();
    });
  }
  return child;
}

// Stop an owned process, or its whole process group: SIGTERM, then SIGKILL after `timeout`.
// If anything is still running `killTimeout` after SIGKILL (a member in uninterruptible I/O,
// or an unreaped zombie), this rejects with the survivors and `retainDependents`, so callers
// keep what that process may still use. A rejected stop is not cached: calling stop() again
// checks and signals again. `kill` is replaceable for tests.
export function stop(child,{timeout=5000,killTimeout=5000,kill=process.kill}={}) {
  if(!child?.pid)return Promise.resolve();
  if(stopping.has(child))return stopping.get(child);
  const done=(async()=>{
    const leaderExited=()=>child.exitCode!==null||child.signalCode!==null;
    const exited=leaderExited()?Promise.resolve():new Promise(resolve=>child.once('exit',resolve));
    // The number still names our group while the leader lives. After the leader is reaped it
    // does until the group is first seen empty, and never once the ID is in use again.
    const ours=()=>!child.groupGone&&(!leaderExited()||!idInUse(child.pid));
    const signalGroup=signal=>{
      if(!ours()) {child.groupGone=true;return false;}
      try {kill(-child.pid,signal);return true;}
      catch(error) {if(error.code!=='ESRCH')throw error;child.groupGone=true;return false;}
    };
    const alive=()=>child.processGroup?signalGroup(0):!leaderExited();
    const send=signal=>child.processGroup?signalGroup(signal):!leaderExited()&&child.kill(signal);
    if(alive()) {
      send('SIGTERM');
      const term=Date.now()+timeout;let killed=null;
      while(alive()) {
        if(Date.now()>=term) {
          killed??=Date.now();send('SIGKILL');
          if(Date.now()-killed>=killTimeout) {
            const survivors=child.processGroup?groupMembers(child.pid):[{pid:child.pid}];
            const listed=survivors.map(s=>s.pid+(s.state?' ('+s.state+')':'')).join(', ')||'unlisted';
            throw Object.assign(new Error(`${child.processGroup?'process group':'process'} ${child.pid} still running ${killTimeout} ms after SIGKILL: ${listed}`),{survivors,retainDependents:true});
          }
        }
        await new Promise(resolve=>setTimeout(resolve,20));
      }
    }
    await exited;
  })();
  stopping.set(child,done);
  done.catch(()=>{if(stopping.get(child)===done)stopping.delete(child);});
  return done;
}

// Register each resource at acquisition, including promises still starting when
// an interrupt arrives. Cleanup is idempotent and runs in reverse ownership order.
// When a disposal fails with `retainDependents` (an owned process that could not be
// stopped), everything acquired before it is kept, since that process may still use it;
// only actions registered with {always:true}, such as notices, still run.
export class ShutdownScope {
  constructor() {
    this.actions=[];this.closing=false;this.controller=new AbortController();
    this.handlers=new Map([
      ['SIGINT',()=>this.terminate(new Error('interrupted by SIGINT'),130,true)],
      ['SIGTERM',()=>this.terminate(new Error('interrupted by SIGTERM'),143,true)],
      ['uncaughtException',error=>this.terminate(error,1)],
      ['unhandledRejection',error=>this.terminate(error,1)],
    ]);
    for(const [event,handler] of this.handlers)process.on(event,handler);
  }
  check() {if(this.closing)throw new Error('resource scope is closing');}
  add(name,dispose,{always=false}={}) {this.check();this.actions.push({name,dispose,always});}
  own(name,create,dispose) {this.check();const value=create();this.add(name,()=>dispose(value));return value;}
  acquire(name,create,dispose) {
    this.check();
    const pending=Promise.resolve().then(()=>{this.check();return create(this.controller.signal);});
    this.add(name,async()=>{let value;try {value=await pending;}catch{return;}await dispose(value);});
    return pending.then(value=>{this.check();return value;});
  }
  close() {
    if(this.closed)return this.closed;
    this.closing=true;this.controller.abort();
    return this.closed=(async()=>{
      const errors=[];let stuck=null;
      for(const {name,dispose,always} of [...this.actions].reverse()) {
        if(stuck&&!always) {
          const error=new Error(`retained because ${stuck} is still running`);
          errors.push({name,error});console.error(`Cleanup ${name}: ${error.message}`);continue;
        }
        try {await dispose();}catch(error){
          errors.push({name,error});console.error(`Cleanup ${name}: ${error.message}`);
          if(error?.retainDependents)stuck??=name;
        }
      }
      for(const [event,handler] of this.handlers)process.off(event,handler);
      return errors;
    })();
  }
  async terminate(error,code,signal=false) {
    if(this.fatal) {
      if(signal)process.exit(code);
      // Cleanup is already running. Report a later failure instead of discarding it.
      console.error('During cleanup: '+(error instanceof Error?error.stack:String(error)));
      return;
    }
    this.fatal=true;
    console.error(error instanceof Error?error.stack:String(error));
    await this.close();process.exit(code);
  }
}
