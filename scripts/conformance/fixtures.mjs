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
export async function putFile(call,path,bytes) {
  const [opened]=await call([{open:{path,flags:0o1101,mode:0o666}}]);
  const chunk=opened.chunk_size??65536;
  if(!Number.isSafeInteger(chunk)||chunk<=0)throw new Error('invalid provider chunk_size');
  for(let offset=0,index=0;offset<bytes.length;offset+=chunk,index++) {
    await call([{pwrite:{fd:opened.fd,index,data:bytes.subarray(offset,offset+chunk).toString('base64')}}]);
  }
  await call([{close:{fd:opened.fd}}]);
}
export async function reattachAfter(detach,attach) {
  if(Object.hasOwn(detach,'ok'))return attach();
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

// Fail closed on source-layout drift: this guard understands only the current
// top-level Call/Target layout, never an arbitrary slice produced by indexOf(-1).
export function checkAbsentMountCalls(abi) {
  const headers=[...abi.matchAll(/^pub enum Call \{$/gm)];
  const ends=[...abi.matchAll(/^pub enum Target<'a> \{$/gm)];
  if(headers.length!==1||ends.length!==1||ends[0].index<=headers[0].index)throw new Error('cannot locate ABI Call boundaries');
  const section=abi.slice(headers[0].index,ends[0].index);
  const closes=[...section.matchAll(/^\}$/gm)];
  if(closes.length!==1||/^pub (?:enum|struct|fn|type) /m.test(section.slice(headers[0][0].length)))throw new Error('unexpected ABI Call boundaries');
  const body=section.slice(headers[0][0].length,closes[0].index);
  // Every variant currently starts at four spaces. Reject unrecognized layout.
  const variants=[...body.matchAll(/^    ([A-Z][A-Za-z0-9_]*)\b/gm)].map(m=>m[1]);
  if(!variants.length||body.split('\n').some(line=>/^\s*(Chroot|Mount|Umount|Unmount)\b/.test(line)))throw new Error('Mount/chroot ABI changed: replace the unavailable probes with executable calls');
}

export function startHeld({tool,args,timeout=60000}) {
  const state=window.conformanceHeld={output:'',input:null,barrier:false,done:false,cancelled:false};
  state.timer=setTimeout(()=>{state.timedOut=true;state.cancelled=true;},timeout);
  state.promise=Promise.resolve().then(()=>window.os.exec([{path:tool,argv:[tool,...args]}],{
    cwd:'/',stdin:null,tty:true,cancelled:()=>state.cancelled,
    onTty:input=>{state.input=input;},
    onOutput:(fd,text)=>{if(fd===1){state.output+=text;state.barrier=state.output.split('\n').some(line=>{try{return typeof JSON.parse(line).barrier==='string';}catch{return false;}});}},
  })).then(result=>{state.status=result.status;},error=>{
    const name=error.errno||error.code||error.message;
    state.error=typeof name==='string'&&/^E[A-Z0-9_]+$/.test(name)?name:'UNCLASSIFIED_ERROR';
  }).finally(()=>{state.done=true;clearTimeout(state.timer);});
}
export function heldState() {
  const s=window.conformanceHeld;
  return {output:s.output,ready:s.barrier&&!!s.input,done:s.done,status:s.status,error:s.error,timedOut:!!s.timedOut};
}
export function heldRows(state,caseName,detach) {
  const rows=state.output.replaceAll('\r','').split('\n').filter(line=>line.trim()).map(line=>JSON.parse(line)).filter(row=>!row.barrier);
  if(state.error)rows.push({case:caseName,step:'launch',call:'exec(probe)',errno:state.error});
  else if(state.timedOut)rows.push({case:caseName,step:'completion',call:'wait(probe)',errno:'ETIMEDOUT'});
  else if(state.status!==0)rows.push({case:caseName,step:'completion',call:'wait(probe)',ok:{status:state.status}});
  rows.push(detach);return rows;
}
