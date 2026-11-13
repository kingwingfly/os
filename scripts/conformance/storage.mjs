import { mkdir, lstat } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

// The persistent image cache is executable input. Never accept a pre-created
// foreign/shared directory (or a symlink), including explicit cache overrides.
export async function imageStore(path=join(homedir(),'.os-conformance-images')) {
  const cache=resolve(path);
  await mkdir(cache,{recursive:true,mode:0o700});
  const info=await lstat(cache);
  if(!info.isDirectory()||info.uid!==process.getuid()||(info.mode&0o777)!==0o700)
    throw new Error('Podman image store must be an owned directory with mode 0700: '+cache);
  return cache;
}
