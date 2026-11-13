import { ok } from './common.mjs';

export function replaceExactly(text,pattern,replacement,label,count=1) {
  const regex=typeof pattern==='string'?null:new RegExp(pattern.source,pattern.flags.includes('g')?pattern.flags:pattern.flags+'g');
  const matches=regex?[...text.matchAll(regex)].length:text.split(pattern).length-1;
  if(matches!==count)throw new Error(`conformance config: ${label}: expected ${count} matches, found ${matches}`);
  return regex?text.replace(regex,replacement):text.replaceAll(pattern,replacement);
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
export async function attempt(caseName,step,call,operation) {
  try {await operation();return ok(caseName,step,call,null);}
  catch(e) {return {case:caseName,step,call,errno:e.errno||e.code||e.message};}
}
export async function reattachAfter(detach,attach) {
  if(Object.hasOwn(detach,'ok'))return attach();
}
// This function executes in the browser. Serialize the errno there: Playwright
// does not retain custom properties on exceptions crossing its boundary.
export async function unmountOutcome(path) {
  try {await window.os.unmountLocal(path);return {ok:null};}
  catch(error) {return {errno:error.errno||error.code||error.message};}
}
