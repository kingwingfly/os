// Process ownership for the conformance runners: owned process groups and one cleanup scope.
import { spawn } from 'node:child_process';
const stopping=new WeakMap();
export function start(cmd,args,options={}) {
  const child=spawn(cmd,args,options);
  child.processGroup=!!options.detached;
  // Spawn failures are asynchronous. Consumers inspect this or await 'error';
  // never let an unhandled ChildProcess error bypass their cleanup scope.
  child.on('error',error=>{child.spawnError=error;});
  return child;
}
export function stop(child,{timeout=5000}={}) {
  if(!child?.pid)return Promise.resolve();
  if(stopping.has(child))return stopping.get(child);
  const done=(async()=>{
    let gone=false;
    const leaderExited=()=>child.exitCode!==null||child.signalCode!==null;
    const exited=leaderExited()?Promise.resolve():new Promise(resolve=>child.once('exit',resolve));
    const signalGroup=signal=>{
      if(gone)return false;
      try {process.kill(-child.pid,signal);return true;}
      catch(error) {if(error.code!=='ESRCH')throw error;gone=true;return false;}
    };
    const alive=()=>child.processGroup?signalGroup(0):!leaderExited();
    const kill=signal=>child.processGroup?signalGroup(signal):!leaderExited()&&child.kill(signal);
    // A PGID remains allocated while any member exists, including descendants
    // of a reaped leader. Stop polling/signalling permanently at the first ESRCH.
    if(alive()) {
      kill('SIGTERM');const deadline=Date.now()+timeout;
      while(alive()) {
        if(Date.now()>=deadline)kill('SIGKILL');
        await new Promise(resolve=>setTimeout(resolve,20));
      }
    }
    await exited;
  })();
  stopping.set(child,done);return done;
}

// Register each resource at acquisition, including promises still starting when
// an interrupt arrives. Cleanup is idempotent and runs in reverse ownership order.
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
  add(name,dispose) {this.check();this.actions.push([name,dispose]);}
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
      const errors=[];
      for(const [name,dispose] of [...this.actions].reverse()) {
        try {await dispose();}catch(error){errors.push({name,error});console.error(`Cleanup ${name}: ${error.message}`);}
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
