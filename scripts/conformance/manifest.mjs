// Cargo manifests copied out of the repository for the ABI compile gate (check-abi.mjs).
import { isAbsolute, resolve } from 'node:path';

const dependencyTable=/(^|\.)(dev-|build-)?dependencies(\.|$)|^patch\./;
// Make every relative dependency or patch `path` absolute from `base`, the manifest's original
// directory, so a copy keeps its local dependencies. Other paths ([lib], [[bin]], build) stay
// relative: they name the copy's own files.
export function relocateManifest(text,base) {
  let table='';
  return text.split('\n').map(line=>{
    const header=line.match(/^\s*\[\[?([^\]]+)\]\]?\s*(#.*)?$/);
    if(header) {table=header[1].trim();return line;}
    if(!dependencyTable.test(table))return line;
    return line.replace(/(\bpath\s*=\s*)"([^"]+)"/g,(match,key,path)=>isAbsolute(path)?match:key+JSON.stringify(resolve(base,path)));
  }).join('\n');
}
// The repository's workspace manifest with only `members` changed, so inherited dependencies,
// package fields, lints, profiles and patches resolve exactly as in the repository.
export function workspaceManifest(text,base,members) {
  const pattern=/^members\s*=\s*\[[^\]]*\]/m;
  if(!pattern.test(text))throw new Error('workspace manifest has no members list');
  if(/^(default-members|exclude)\s*=/m.test(text))throw new Error('workspace default-members/exclude are not supported by the ABI gate');
  return relocateManifest(text.replace(pattern,'members = '+JSON.stringify(members)),base);
}
