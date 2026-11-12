// Run before starting the isolated test server. Never modifies a running deployment.
// Keys here are deliberately public test fixtures, not operator credentials.
import { mkdir, writeFile, readFile, cp, chmod } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { parseArgs } from 'node:util';
import binaryen from 'binaryen';
const { values } = parseArgs({ options: { assets: { type: 'string' }, out: { type: 'string' } } });
if (!values.assets || !values.out) throw new Error('Usage: node tests/release-fixtures.mjs --assets dist --out EXTERNAL_DIRECTORY');
const assets = resolve(values.assets), root = resolve(values.out), bundle = join(root, 'bundle');
await mkdir(root, { recursive: true });
const run = args => execFileSync('cargo', ['run', '--locked', '--release', '-p', 'xtask', '--', ...args], { encoding: 'utf8', maxBuffer: 1024 * 1024 }).trim();
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const seed = Buffer.alloc(32, 71), keyPath = join(root, 'TEST-ONLY-SEED');
await writeFile(keyPath, seed, { mode: 0o600 });
const ids = {};
const rotatedKey = join(root, 'ROTATED-TEST-SEED');
await writeFile(rotatedKey, Buffer.alloc(32,73), { mode:0o600 });
const trust = { keys:{}, revoked:[] };
const extension = join(root,'extension'), extensionPackage = join(root,'extension-package');
await mkdir(join(extension,'opt/phase6/bin'),{recursive:true});
for(const path of ['opt','opt/phase6','opt/phase6/bin']) await chmod(join(extension,path),0o755);
const module = binaryen.parseText(`(module
  (import "wasi_snapshot_preview1" "fd_write" (func $write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 16) "sysext ready\\0a")
  (func (export "_start")
    (i32.store (i32.const 0) (i32.const 16))
    (i32.store (i32.const 4) (i32.const 13))
    (drop (call $write (i32.const 1) (i32.const 0) (i32.const 1) (i32.const 8)))))`);
await writeFile(join(extension,'opt/phase6/bin/probe'),module.emitBinary());module.dispose();
await chmod(join(extension,'opt/phase6/bin/probe'),0o755);
run(['image','--root',extension,'--kind','sysext','--out',extensionPackage,'--name','probe']);
for (const [name, value] of [['a','generation A\n'], ['b','generation B\n'], ['tampered','tamper fixture\n']]) {
  const tree = join(root, name, 'tree'), pkg = join(root, name, 'package');
  await mkdir(join(tree, 'etc/phase6'), { recursive: true });
  await writeFile(join(tree, 'etc/phase6/generation'), value);
  for (const directory of ['etc', 'etc/phase6']) await chmod(join(tree, directory), 0o755);
  await chmod(join(tree, 'etc/phase6/generation'), 0o644);
  run(['image', '--root', tree, '--kind', 'confext', '--out', pkg, '--name', name]);
  ids[name] = run(['boot', '--assets', assets, '--out', bundle, '--name', name, '--confext', pkg, '--sysext',extensionPackage]);
  run(['sign', '--bundle', bundle, '--key-file', name==='b'?rotatedKey:keyPath]);
  Object.assign(trust.keys,JSON.parse(await readFile(join(bundle,'publisher.json'),'utf8')).keys);
  if (name === 'tampered') await writeFile(join(bundle, 'blobs', sha(Buffer.from(value))), 'corrupted bytes');
}
const unknownKey = join(root, 'UNKNOWN-TEST-SEED');
await writeFile(unknownKey, Buffer.alloc(32, 72), { mode: 0o600 });
ids.untrusted = run(['boot', '--assets', assets, '--out', bundle, '--name', 'untrusted']);
run(['sign', '--bundle', bundle, '--key-file', unknownKey]);

// Invalid compatibility is still invalid when signed by an allowed publisher.
const release = JSON.parse(await readFile(join(bundle, `releases/${ids.b}/manifest.json`), 'utf8'));
release.schema = { min: 8, max: 8 };
const bytes = Buffer.from(JSON.stringify(release)); ids.incompatible = sha(bytes);
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32);
const signature = { format: 'os.signature', version: 1, key: sha(publicKey), signature: sign(null, Buffer.concat([Buffer.from('os.release.v1\0'), bytes]), privateKey).toString('hex') };
await mkdir(join(bundle, `releases/${ids.incompatible}`), { recursive: true });
await writeFile(join(bundle, `releases/${ids.incompatible}/manifest.json`), bytes);
await writeFile(join(bundle, `releases/${ids.incompatible}/signature.json`), JSON.stringify(signature));

// A complete candidate for an interrupted preparation. No selected release changes here.
release.schema={min:7,max:7};release.name='interrupted';
const interrupted=Buffer.from(JSON.stringify(release));ids.interrupted=sha(interrupted);
await mkdir(join(bundle,`releases/${ids.interrupted}`),{recursive:true});
await writeFile(join(bundle,`releases/${ids.interrupted}/manifest.json`),interrupted);
await writeFile(join(bundle,`releases/${ids.interrupted}/signature.json`),JSON.stringify({...signature,signature:sign(null,Buffer.concat([Buffer.from('os.release.v1\0'),interrupted]),privateKey).toString('hex')}));
await cp(join(bundle,`releases/${ids.b}/assets`),join(bundle,`releases/${ids.interrupted}/assets`),{recursive:true});
// Shared image signatures rotate to the new key too. Existing approved generations
// refresh their detached proofs via stage before the old publisher is revoked.
await writeFile(join(bundle,'release.json'),await readFile(join(bundle,`releases/${ids.b}/manifest.json`)));
run(['sign','--bundle',bundle,'--key-file',rotatedKey]);

// Synthetic signed boot paths exercise URL encoding independently of build provenance.
const encodedRelease = JSON.parse(await readFile(join(bundle, `releases/${ids.b}/manifest.json`), 'utf8'));
const encodedBoot = JSON.parse(await readFile(join(bundle, `images/${encodedRelease.boot}.json`), 'utf8'));
const encodedPaths = ['plain.txt', 'with space.txt', '文件.txt', 'hash#name.txt', 'query?name.txt', 'literal%2Fname.txt'];
const encodedContent = Buffer.from('encoded asset contents\n');
await writeFile(join(bundle, 'blobs', sha(encodedContent)), encodedContent);
for (const name of encodedPaths) encodedBoot.entries.push({ path: '/' + name, uid: 0, gid: 0, mode: 0o644, node: { type: 'file', sha256: sha(encodedContent), size: encodedContent.length } });
encodedBoot.entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const encodedBootBytes = Buffer.from(JSON.stringify(encodedBoot)); encodedRelease.boot = sha(encodedBootBytes); encodedRelease.name = 'encoded paths';
const encodedReleaseBytes = Buffer.from(JSON.stringify(encodedRelease)); ids.encoded = sha(encodedReleaseBytes);
const encodedKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 73)]), format: 'der', type: 'pkcs8' });
const encodedKeyId = sha(createPublicKey(encodedKey).export({ format: 'der', type: 'spki' }).subarray(-32));
const signed = (domain, bytes) => JSON.stringify({ format: 'os.signature', version: 1, key: encodedKeyId, signature: sign(null, Buffer.concat([Buffer.from(domain + '\0'), bytes]), encodedKey).toString('hex') });
await writeFile(join(bundle, `images/${encodedRelease.boot}.json`), encodedBootBytes);
await writeFile(join(bundle, `images/${encodedRelease.boot}.sig`), signed('os.image.v1', encodedBootBytes));
await cp(join(bundle, `releases/${ids.b}/assets`), join(bundle, `releases/${ids.encoded}/assets`), { recursive: true });
for (const name of encodedPaths) await writeFile(join(bundle, `releases/${ids.encoded}/assets/${name}`), encodedContent);
await writeFile(join(bundle, `releases/${ids.encoded}/manifest.json`), encodedReleaseBytes);
await writeFile(join(bundle, `releases/${ids.encoded}/signature.json`), signed('os.release.v1', encodedReleaseBytes));
await cp(bundle, join(assets, 'boot'), { recursive: true });
const file = join(root, 'fixtures.json');
await writeFile(file, JSON.stringify({ ids, trust, encodedPaths, oldKey:sha(publicKey) }));
console.log(file);
