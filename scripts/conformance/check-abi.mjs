// Explicit compile gate: verify the actual Call type, not source layout regexes. The ABI crate
// is copied with its real manifest into a workspace made from the repository's own workspace
// manifest and lockfile, so dependencies, features, build scripts and workspace inheritance
// behave as in the repository; only the copied source is changed.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm, cp, copyFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { relocateManifest, workspaceManifest } from './manifest.mjs';
const repo=resolve('.'),dir=await mkdtemp(join(tmpdir(),'conformance-abi-check-'));
try {
  await writeFile(join(dir,'Cargo.toml'),workspaceManifest(await readFile('Cargo.toml','utf8'),repo,['abi','audit']));
  await copyFile('Cargo.lock',join(dir,'Cargo.lock'));
  await cp('crates/abi',join(dir,'abi'),{recursive:true});
  const manifest=relocateManifest(await readFile('crates/abi/Cargo.toml','utf8'),resolve('crates/abi'));
  await mkdir(join(dir,'audit/src'),{recursive:true});
  await writeFile(join(dir,'audit/Cargo.toml'),'[package]\nname = "conformance-abi-audit"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n[dependencies]\nabi = { package = "os-abi", path = "../abi" }\n');
  await writeFile(join(dir,'audit/src/main.rs'),`#[path=${JSON.stringify(resolve('crates/conformance/src/abi_audit.rs'))}] mod audit;\nfn main() {}\n`);
  const source=await readFile('crates/abi/src/lib.rs','utf8');
  const check=async(text,{cargoToml=manifest,build=null,args=[]}={})=>{
    await writeFile(join(dir,'abi/src/lib.rs'),text);
    await writeFile(join(dir,'abi/Cargo.toml'),cargoToml);
    if(build===null)await rm(join(dir,'abi/build.rs'),{force:true});else await writeFile(join(dir,'abi/build.rs'),build);
    return spawnSync('cargo',['check','--offline','--manifest-path',join(dir,'Cargo.toml'),'-p','conformance-abi-audit',...args],{encoding:'utf8'});
  };
  const unchanged=await check(source);assert.equal(unchanged.status,0,unchanged.stderr);
  // Ordinary impl/comment additions leave the actual Call type unchanged.
  const harmless=await check(source+'\n/// MountTree in a comment is not a new call.\nimpl Call {}\n');assert.equal(harmless.status,0,harmless.stderr);
  // So do ordinary manifest changes: a feature, a build script, and another locked dependency.
  const ordinary=await check(source+'\n#[cfg(all(gate_build, feature = "gate-feature"))]\npub const GATE: u32 = libc::EINVAL as u32;\n#[cfg(not(all(gate_build, feature = "gate-feature")))]\ncompile_error!("the build script or the feature was not applied");\n',{
    cargoToml:manifest+'\n[dependencies.libc]\nversion = "0.2"\n\n[features]\ngate-feature = []\n',
    build:'fn main() {\n    println!("cargo::rustc-check-cfg=cfg(gate_build)");\n    println!("cargo::rustc-cfg=gate_build");\n}\n',
    args:['--features','abi/gate-feature'],
  });
  assert.equal(ordinary.status,0,ordinary.stderr);
  for(const name of ['MountTree','Pivot']) {
    const changed=await check(source.replace('pub enum Call {','pub enum Call {\n    '+name+','));
    assert.notEqual(changed.status,0);assert.match(changed.stderr,/non-exhaustive patterns/);assert.match(changed.stderr,/abi_audit.rs/);assert(changed.stderr.includes(name));
  }
  console.log('ABI compile gate: the real manifest and workspace compile; impl/comment, feature, build-script and dependency changes pass; MountTree and Pivot additions fail the exhaustive probe audit.');
} finally {await rm(dir,{recursive:true,force:true});}
