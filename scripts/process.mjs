// Process ownership shared by dev bootstrap and disposable integration runners.
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
    const kill=signal=>{
      try {if(child.processGroup)process.kill(-child.pid,signal);else child.kill(signal);}
      catch(error) {if(error.code!=='ESRCH')throw error;}
    };
    if(child.exitCode!==null||child.signalCode!==null) {
      if(child.processGroup)kill('SIGKILL');
      return;
    }
    const exited=new Promise(resolve=>child.once('exit',resolve));
    kill('SIGTERM');const timer=setTimeout(()=>kill('SIGKILL'),timeout);
    try {await exited;} finally {
      clearTimeout(timer);
      // A detached leader can exit before its descendants. Reap its entire group.
      if(child.processGroup)kill('SIGKILL');
    }
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
    if(this.fatal) {if(signal)process.exit(code);return;}
    this.fatal=true;
    console.error(error instanceof Error?error.stack:String(error));
    await this.close();process.exit(code);
  }
}
