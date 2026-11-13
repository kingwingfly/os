// Explicit compile gate: verify the actual Call type, not source layout regexes.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, cp } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
const dir=await mkdtemp(join(tmpdir(),'conformance-abi-check-'));
try {
  await cp('crates/abi/src',join(dir,'abi/src'),{recursive:true});await mkdir(join(dir,'src'));
  await writeFile(join(dir,'Cargo.toml'),'[package]\nname="conformance-abi-check"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\nabi={package="os-abi",path="abi"}\n');
  await writeFile(join(dir,'abi/Cargo.toml'),'[package]\nname="os-abi"\nversion="0.1.0"\nedition="2024"\n[dependencies]\nserde={version="1",features=["derive"]}\nserde_json="1"\nbase64="0.22"\n');
  await writeFile(join(dir,'src/main.rs'),`#[path=${JSON.stringify(resolve('crates/conformance/src/abi_audit.rs'))}] mod audit;\nfn main() {}\n`);
  const source=await readFile('crates/abi/src/lib.rs','utf8');
  const check=async text=>{
    await writeFile(join(dir,'abi/src/lib.rs'),text);
    return spawnSync('cargo',['check','--offline','--manifest-path',join(dir,'Cargo.toml')],{encoding:'utf8'});
  };
  // Ordinary impl/comment additions leave the actual Call type unchanged.
  const harmless=source+'\n/// MountTree in a comment is not a new call.\nimpl Call {}\n';
  const unchanged=await check(harmless);assert.equal(unchanged.status,0,unchanged.stderr);
  for(const name of ['MountTree','Pivot']) {
    const changed=await check(source.replace('pub enum Call {','pub enum Call {\n    '+name+','));
    assert.notEqual(changed.status,0);assert.match(changed.stderr,/non-exhaustive patterns/);assert.match(changed.stderr,/abi_audit.rs/);assert(changed.stderr.includes(name));
  }
  console.log('ABI compile gate: ordinary impl/comment changes pass; MountTree and Pivot additions fail the exhaustive probe audit.');
} finally {await rm(dir,{recursive:true,force:true});}
