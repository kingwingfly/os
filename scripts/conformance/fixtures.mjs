import { createInterface } from 'node:readline';

export function replaceExactly(text,pattern,replacement,label,count=1) {
  const regex=typeof pattern==='string'?null:new RegExp(pattern.source,pattern.flags.includes('g')?pattern.flags:pattern.flags+'g');
  const matches=regex?[...text.matchAll(regex)].length:text.split(pattern).length-1;
  if(matches!==count)throw new Error(`conformance config: ${label}: expected ${count} matches, found ${matches}`);
  return regex?text.replace(regex,()=>replacement):text.replaceAll(pattern,()=>replacement);
}
export function conformanceConfig(source,root) {
  let text=replaceExactly(source,/^main = "(?:\.\/)?crates\/worker\/entry\.js"$/m,`main = ${JSON.stringify(root+'/crates/worker/entry.js')}`,'Worker entry');
  text=replaceExactly(text,/^\[build\][\s\S]*?(?=\n\[|(?![\s\S]))/m,'','build section');
  text=replaceExactly(text,/^\[\[containers\]\]\nclass_name = "JobRunner"[\s\S]*?(?=\n\[|(?![\s\S]))/m,'','unused JobRunner container');
  text=replaceExactly(text,'directory = "./dist"',`directory = ${JSON.stringify(root+'/dist')}`,'assets directory');
  text=replaceExactly(text,'image_build_context = "."',`image_build_context = ${JSON.stringify(root)}`,'compiler build context');
  return replaceExactly(text,'image = "./containers/compiler/Dockerfile"',`image = ${JSON.stringify(root+'/containers/compiler/Dockerfile')}`,'compiler Dockerfile');
}
export function compilerConfig(source,root,dockerfile) {
  return replaceExactly(source,`image = ${JSON.stringify(root+'/containers/compiler/Dockerfile')}`,`image = ${JSON.stringify(dockerfile)}`,'prebuilt compiler Dockerfile');
}
// A capture listener must run before the application's bubbling upload handler.
export function captureDirectoryDrop() {
  const over=event=>{event.preventDefault();event.stopImmediatePropagation();};
  addEventListener('dragover',over,{capture:true});
  addEventListener('drop',event=>{
    event.preventDefault();event.stopImmediatePropagation();
    removeEventListener('dragover',over,{capture:true});
    window.conformanceHandle=event.dataTransfer.items[0].getAsFileSystemHandle();
  },{capture:true,once:true});
}
export function helperConnection(child,timeout=10000) {
  return new Promise((resolve,reject)=>{
    if(child.spawnError)return reject(child.spawnError);
    const lines=createInterface({input:child.stdout});
    const finish=(error,value)=>{
      clearTimeout(timer);lines.close();child.off('error',failed);child.off('exit',exited);
      if(error)reject(error);else resolve(value);
    };
    const failed=error=>finish(error),exited=()=>finish(new Error('helper exited before announcing its connection'));
    const timer=setTimeout(()=>finish(new Error('helper startup timeout')),timeout);
    child.once('error',failed);child.once('exit',exited);
    lines.once('line',line=>{try {finish(null,JSON.parse(line));}catch(error){finish(new Error('invalid helper connection JSON',{cause:error}));}});
  });
}
// Re-attach is fixture recovery. Preserve its result before failing immediately;
// no subsequent probe may run against a mount that failed to come back.
export async function recordReattach(rows,detach,attach,caseName,persist=async()=>{}) {
  if(!Object.hasOwn(detach,'ok'))return;
  const result=await attach();
  const row={case:caseName,step:'attach',call:'mount(source, mount)',...result};
  rows.push(row);await persist(rows);
  if(!Object.hasOwn(result,'ok'))throw new Error(`${caseName} re-attach failed: ${result.errno??'invalid outcome'}`);
}
export async function putFile(call,path,bytes) {
  const [opened]=await call([{open:{path,flags:0o1101,mode:0o666}}]);
  const chunk=opened.chunk_size??65536;
  if(!Number.isSafeInteger(chunk)||chunk<=0)throw new Error('invalid provider chunk_size');
  for(let offset=0,index=0;offset<bytes.length;offset+=chunk,index++) {
    await call([{pwrite:{fd:opened.fd,index,data:bytes.subarray(offset,offset+chunk).toString('base64')}}]);
  }
  await call([{close:{fd:opened.fd}}]);
}
// These callbacks execute in the browser: only returned data crosses Playwright.
// Keep all mount-operation error handling here, including held-process detach.
export async function mountOutcome({operation,path,filesystem,name,connection,address}) {
  try {
    if(operation==='detach')await window.os.unmountLocal(path);
    else if(operation!=='attach')throw new Error('invalid mount operation');
    else if(filesystem==='relay')await window.os.attachShared({address,name,writable:true,cloud:true},{p2p:false});
    else await window.os.mountLocal({name,writable:true,cloud:true,
      ...(filesystem==='browser-storage'?{storage:true}:filesystem==='directory-handle'?{handle:window.conformanceHandle}:connection)});
    return {ok:null};
  } catch(error) {
    const name=error.errno||error.code||error.message;
    return {errno:typeof name==='string'&&/^E[A-Z0-9_]+$/.test(name)?name:'UNCLASSIFIED_ERROR'};
  }
}

export function startHeld({tool,args,timeout=60000}) {
  const state=window.conformanceHeld={output:'',stderr:'',input:null,barrier:false,done:false,cancelled:false};
  state.timer=setTimeout(()=>{state.timedOut=true;state.cancelled=true;},timeout);
  state.promise=Promise.resolve().then(()=>window.os.exec([{path:tool,argv:[tool,...args]}],{
    cwd:'/',stdin:null,tty:true,cancelled:()=>state.cancelled,
    onTty:input=>{state.input=input;},
    onOutput:(fd,text)=>{if(fd===2)state.stderr+=text;if(fd===1){state.output+=text;state.barrier=state.output.split('\n').some(line=>{try{return typeof JSON.parse(line).barrier==='string';}catch{return false;}});}},
  })).then(result=>{state.status=result.status;},error=>{
    const name=error.errno||error.code||error.message;
    state.error=typeof name==='string'&&/^E[A-Z0-9_]+$/.test(name)?name:'UNCLASSIFIED_ERROR';
  }).finally(()=>{state.done=true;clearTimeout(state.timer);});
}
export function heldState() {
  const s=window.conformanceHeld;
  return {output:s.output,stderr:s.stderr,ready:s.barrier&&!!s.input,done:s.done,status:s.status,error:s.error,timedOut:!!s.timedOut};
}
export function heldRows(state,caseName,detach,diagnostics=[]) {
  const rows=[];let invalid=false;
  if(state.stderr)diagnostics.push({case:caseName,stream:2,text:state.stderr});
  for(const line of state.output.replaceAll('\r','').split('\n').filter(line=>line.trim())) {
    try {
      const row=JSON.parse(line);
      if(typeof row?.barrier==='string')continue;
      if(row?.case!==caseName||typeof row.step!=='string'||typeof row.call!=='string'||['ok','errno','skipped'].filter(key=>Object.hasOwn(row,key)).length!==1)throw new Error('invalid probe row');
      rows.push(row);
    } catch {
      invalid=true;diagnostics.push({case:caseName,stream:1,text:line});
    }
  }
  if(invalid)rows.push({case:caseName,step:'output',call:'decode probe JSON lines',skipped:'non-JSON or malformed probe output; see evidence.json diagnostics'});
  if(state.error)rows.push({case:caseName,step:'launch',call:'exec(probe)',errno:state.error});
  else if(state.timedOut)rows.push({case:caseName,step:'completion',call:'wait(probe)',errno:'ETIMEDOUT'});
  else if(state.status!==0)rows.push({case:caseName,step:'completion',call:'wait(probe)',ok:{status:state.status}});
  rows.push(detach);return rows;
}
