// Phase 9.1b (#84) Multi-Node Conformance E2E: KB-03, KB-04, KB-05, KB-06, KB-07.
//
// Exercises REAL `os-native kubelet` (Node A) + REAL `web/kernel/kubelet-agent.js` backed by
// REAL compiled `dist/client_kernel_bg.wasm` `SandboxKernel` & `web/kernel/sandbox-worker.js`
// (Node B) against a LIVE Miniflare Worker (`OsAuthority`, `Machine`, `StorageVolume`,
// `ClusterState`, R2 `FILES`). ZERO mocks, ZERO fakes.
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import { Miniflare } from 'miniflare';
import { KubeletAgent } from '../web/kernel/kubelet-agent.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const sha = bytes => createHash('sha256').update(bytes).digest();
const shaHex = bytes => sha(bytes).toString('hex');
const shaDigest = bytes => `sha256:${shaHex(bytes)}`;
const b64 = s => Buffer.from(s, 'utf8').toString('base64');
const unb64 = s => Buffer.from(s, 'base64').toString('utf8');
const u16 = n => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const cat = (...parts) => Buffer.concat(parts.map(p => Buffer.from(p)));

const FULL_CLUSTER_AND_OCI = {
  cluster_read: true,
  cluster_write: true,
  cluster_watch: true,
  cluster_lease: true,
  cluster_compact: true,
  registry_pull: true,
  registry_push: true,
  volumes: true,
  volumes_ro: false,
};

function findOsNativeBin() {
  const targetDir = process.env.CARGO_TARGET_DIR || join(ROOT, 'target');
  for (const profile of ['debug', 'release']) {
    const p = join(targetDir, profile, 'os-native');
    if (existsSync(p)) return p;
  }
  throw new Error(`os-native binary not found in ${targetDir}/{debug,release}/os-native`);
}

async function loadSandboxKernelClass() {
  const glue = readFileSync(join(ROOT, 'dist/client_kernel.js'), 'utf8');
  const wasm = readFileSync(join(ROOT, 'dist/client_kernel_bg.wasm'));
  const scope = { ...globalThis };
  const fn = new Function('self', `${glue}\nreturn wasm_bindgen;`);
  const wb = fn(scope);
  await wb(wasm);
  assert.ok(wb.SandboxKernel, 'dist/client_kernel_bg.wasm must export SandboxKernel');
  return wb.SandboxKernel;
}

function compileWasiPod(workDir, name, rustSrc) {
  const rsPath = join(workDir, `${name}.rs`);
  const wasmPath = join(workDir, `${name}.wasm`);
  writeFileSync(rsPath, rustSrc, 'utf8');
  execFileSync('rustc', ['--edition=2021', '--target', 'wasm32-wasip1', '-O', '-o', wasmPath, rsPath], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return readFileSync(wasmPath);
}

// Build a clean USTAR tar archive for standard OCI image layers (StrictConfined-safe).
function buildTar(entries) {
  const blocks = [];
  for (const { path, content, mode = 0o755 } of entries) {
    const clean = path.replace(/^\/+/, '');
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content);
    const hdr = Buffer.alloc(512, 0);
    hdr.write(clean, 0, Math.min(clean.length, 100), 'utf8');
    hdr.write(mode.toString(8).padStart(7, '0') + '\0', 100, 8, 'ascii');
    hdr.write('0000000\0', 108, 8, 'ascii'); // uid
    hdr.write('0000000\0', 116, 8, 'ascii'); // gid
    hdr.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
    hdr.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136, 12, 'ascii');
    hdr.fill(0x20, 148, 156); // chksum placeholder
    hdr[156] = 0x30; // '0' regular file
    hdr.write('ustar\0', 257, 6, 'ascii');
    hdr.write('00', 263, 2, 'ascii');
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += hdr[i];
    hdr.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
    blocks.push(hdr);
    if (data.length > 0) {
      blocks.push(data);
      const rem = data.length % 512;
      if (rem !== 0) blocks.push(Buffer.alloc(512 - rem, 0));
    }
  }
  blocks.push(Buffer.alloc(1024, 0));
  return Buffer.concat(blocks);
}

async function ociBearerHeaders(baseUrl, authHeaders, repo, actions = 'pull,push') {
  const url = `${baseUrl}/v2/token?service=os-registry&scope=${encodeURIComponent(`repository:${repo}:${actions}`)}`;
  const res = await fetch(url, { headers: authHeaders });
  const text = await res.text();
  assert.equal(res.status, 200, `OCI token exchange failed (${res.status}): ${text}`);
  const { token } = JSON.parse(text);
  return { Authorization: `Bearer ${token}` };
}

async function ociPutBlob(baseUrl, authHeaders, repo, bytes) {
  const bearer = await ociBearerHeaders(baseUrl, authHeaders, repo, 'pull,push');
  const digest = shaDigest(bytes);
  const start = await fetch(`${baseUrl}/v2/${repo}/blobs/uploads/`, {
    method: 'POST',
    headers: { ...bearer },
  });
  assert.equal(start.status, 202, `blob upload start failed: ${start.status} ${await start.text()}`);
  const loc = start.headers.get('location');
  const putUrl = new URL(loc, baseUrl);
  putUrl.searchParams.set('digest', digest);
  const fin = await fetch(putUrl.href, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream', ...bearer },
    body: bytes,
  });
  assert.equal(fin.status, 201, `blob upload finish failed: ${fin.status} ${await fin.text()}`);
  return digest;
}

async function pushOciTarImage(baseUrl, authHeaders, repo, tag, files) {
  const bearer = await ociBearerHeaders(baseUrl, authHeaders, repo, 'pull,push');
  const tar = buildTar(files);
  const layerDigest = await ociPutBlob(baseUrl, authHeaders, repo, tar);
  const configBytes = Buffer.from(JSON.stringify({
    architecture: 'wasm',
    os: 'wasip1',
    rootfs: { type: 'layers', diff_ids: [layerDigest] },
  }));
  const configDigest = await ociPutBlob(baseUrl, authHeaders, repo, configBytes);
  const manifestBytes = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    config: {
      mediaType: 'application/vnd.oci.image.config.v1+json',
      digest: configDigest,
      size: configBytes.length,
    },
    layers: [{
      mediaType: 'application/vnd.oci.image.layer.v1.tar',
      digest: layerDigest,
      size: tar.length,
    }],
  }));
  const mResp = await fetch(`${baseUrl}/v2/${repo}/manifests/${encodeURIComponent(tag)}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/vnd.oci.image.manifest.v1+json',
      ...bearer,
    },
    body: manifestBytes,
  });
  assert.equal(mResp.status, 201, `manifest put failed: ${mResp.status} ${await mResp.text()}`);
  return `oci:${repo}@${shaDigest(manifestBytes)}`;
}

// Build & push an OCI COWFS_SNAPSHOT_ARTIFACT_TYPE containing a flat map of root files.
async function pushOciCowfsSnapshot(baseUrl, authHeaders, repo, tag, filesObj) {
  const fileNames = Object.keys(filesObj).sort();
  const blocks = [];
  const fileEntries = [];
  let offset = 0;
  for (let i = 0; i < fileNames.length; i++) {
    const name = fileNames[i];
    const data = Buffer.from(filesObj[name]);
    const digest = sha(data);
    blocks.push(data);
    fileEntries.push({ ino: i + 2, name, data, digest, offset, len: data.length });
    offset += data.length;
  }
  const index = cat(
    'COWP', u16(1), u32(fileEntries.length),
    ...fileEntries.map(e => cat(e.digest, u32(e.offset), u32(e.len), u32(e.len), u16(0))),
  );
  const packBytes = cat(...blocks, index, u32(index.length), sha(index), 'COWP');
  const packHex = shaHex(packBytes);

  function item(ino, kind, tail, value) {
    return cat(u64(ino), [kind], u16(tail.length), tail, u32(value.length), value);
  }
  function inode(isDir, size, nextDirOff = 1) {
    return cat(
      [1, isDir ? 2 : 1], u16(isDir ? 0o755 : 0o444), u32(isDir ? 2 : 1), u32(0), u32(0),
      u64(size), u64(1), Buffer.alloc(36), u64(nextDirOff), [0, 0, 0],
    );
  }
  const items = [item(1, 1, [], inode(true, 0, fileEntries.length + 1))];
  for (let i = 0; i < fileEntries.length; i++) {
    const e = fileEntries[i];
    const nb = Buffer.from(e.name, 'utf8');
    const cookie = i + 1;
    items.push(item(1, 0x20, nb, cat(u64(e.ino), u64(1), [1], u64(cookie))));
    items.push(item(1, 0x21, u64(cookie), cat(u64(e.ino), u64(1), [1], u16(nb.length), nb)));
  }
  for (const e of fileEntries) {
    const nb = Buffer.from(e.name, 'utf8');
    items.push(item(e.ino, 1, [], inode(false, e.len, 1)));
    items.push(item(e.ino, 0x10, cat(u64(1), nb), Buffer.alloc(0)));
    if (e.len > 0) {
      items.push(item(e.ino, 0x30, u64(0), cat([1], u32(e.len), e.digest, u32(0))));
    }
  }
  // Sort B+Tree leaf items by (ino, kind, tail) ascending!
  items.sort((a, b) => {
    const inoCmp = Buffer.compare(a.subarray(0, 8), b.subarray(0, 8));
    if (inoCmp !== 0) return inoCmp;
    if (a[8] !== b[8]) return a[8] - b[8];
    const aTailLen = a.readUInt16BE(9);
    const bTailLen = b.readUInt16BE(9);
    return Buffer.compare(a.subarray(11, 11 + aTailLen), b.subarray(11, 11 + bTailLen));
  });
  const leaf = cat('COWN', u16(1), [0, 0], u32(items.length), ...items);
  const volName = Buffer.from(`in-${tag}`, 'utf8');
  const rootNode = cat(
    'OSCOWFS1', u32(1), u64(0), u16(volName.length), volName, u64(fileEntries.length + 2), u64(1),
    [0], u32(1), u16(1), '@', sha(leaf),
  );
  const rawNodes = [[sha(leaf), leaf], [sha(rootNode), rootNode]].sort((a, b) => Buffer.compare(a[0], b[0]));
  const nodePack = cat(
    'COWNP1\0\0', u16(1), u32(rawNodes.length),
    ...rawNodes.map(([d, b]) => cat(d, u32(b.length), b)),
  );
  const sortedBlocks = [...fileEntries].sort((a, b) => Buffer.compare(a.digest, b.digest));
  const blockDir = cat(
    'COWBD1\0\0', u16(1), u32(1), Buffer.from(packHex, 'hex'), u32(sortedBlocks.length),
    ...sortedBlocks.map(e => cat(e.digest, u32(0), u32(e.offset), u32(e.len))),
  );
  const cfgBytes = Buffer.from(JSON.stringify({
    format: 'os.cowfs.snapshot',
    version: 1,
    cowfs_format_version: 1,
    volume_uuid: `in-${tag}`,
    root_digest: shaHex(rootNode),
    subvols: { '@': shaHex(leaf) },
    shard_index: 0,
    shard_count: 1,
    node_count: 2,
    pack_count: 1,
    total_bytes: packBytes.length,
  }));

  const cfgDigest = await ociPutBlob(baseUrl, authHeaders, repo, cfgBytes);
  const npDigest = await ociPutBlob(baseUrl, authHeaders, repo, nodePack);
  const bdDigest = await ociPutBlob(baseUrl, authHeaders, repo, blockDir);
  const pkDigest = await ociPutBlob(baseUrl, authHeaders, repo, packBytes);

  const manifestBytes = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    artifactType: 'application/vnd.os.cowfs.snapshot.v1',
    config: {
      mediaType: 'application/vnd.os.cowfs.snapshot.config.v1+json',
      digest: cfgDigest,
      size: cfgBytes.length,
    },
    layers: [
      { mediaType: 'application/vnd.os.cowfs.nodepack.v1', digest: npDigest, size: nodePack.length },
      { mediaType: 'application/vnd.os.cowfs.blockdir.v1', digest: bdDigest, size: blockDir.length },
      { mediaType: 'application/vnd.os.cowfs.pack.v1', digest: pkDigest, size: packBytes.length },
    ],
  }));
  const bearer = await ociBearerHeaders(baseUrl, authHeaders, repo, 'pull,push');
  const mResp = await fetch(`${baseUrl}/v2/${repo}/manifests/${encodeURIComponent(tag)}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/vnd.oci.image.manifest.v1+json',
      ...bearer,
    },
    body: manifestBytes,
  });
  assert.equal(mResp.status, 201, `cowfs snapshot manifest put failed: ${mResp.status} ${await mResp.text()}`);
  return `oci:${repo}@${shaDigest(manifestBytes)}`;
}

// Read a single root file from a pushed `COWFS_SNAPSHOT_ARTIFACT_TYPE` manifest in the live OCI registry
// (verifying manifest, nodepack, blockdir, and COWP data packs survive intact!).
async function readCowfsSnapshotFile(baseUrl, authHeaders, repo, reference, fileName) {
  const bearer = await ociBearerHeaders(baseUrl, authHeaders, repo, 'pull');
  const mResp = await fetch(`${baseUrl}/v2/${repo}/manifests/${reference}`, {
    headers: { Accept: 'application/vnd.oci.image.manifest.v1+json', ...bearer },
  });
  assert.equal(mResp.status, 200, `GET manifest ${repo}@${reference} failed: ${mResp.status}`);
  const manifest = await mResp.json();
  const getBlob = async digest => {
    const r = await fetch(`${baseUrl}/v2/${repo}/blobs/${digest}`, { headers: bearer });
    assert.equal(r.status, 200, `GET blob ${digest} failed: ${r.status}`);
    return Buffer.from(await r.arrayBuffer());
  };
  const npLayer = manifest.layers.find(l => l.mediaType === 'application/vnd.os.cowfs.nodepack.v1');
  const bdLayer = manifest.layers.find(l => l.mediaType === 'application/vnd.os.cowfs.blockdir.v1');
  assert.ok(npLayer && bdLayer, 'missing nodepack or blockdir layer');
  const np = await getBlob(npLayer.digest);
  const bd = await getBlob(bdLayer.digest);

  // Parse blockdir -> map blockDigestHex -> { packHex, offset, len }
  let pos = 10;
  const packCount = bd.readUInt32BE(pos); pos += 4;
  const packHexes = [];
  for (let i = 0; i < packCount; i++) {
    packHexes.push(bd.subarray(pos, pos + 32).toString('hex')); pos += 32;
  }
  const entryCount = bd.readUInt32BE(pos); pos += 4;
  const blocks = new Map();
  for (let i = 0; i < entryCount; i++) {
    const bHex = bd.subarray(pos, pos + 32).toString('hex'); pos += 32;
    const pIdx = bd.readUInt32BE(pos); pos += 4;
    const off = bd.readUInt32BE(pos); pos += 4;
    const len = bd.readUInt32BE(pos); pos += 4;
    blocks.set(bHex, { packHex: packHexes[pIdx], offset: off, len });
  }

  // Parse nodepack -> scan COWN leaves for dir entry `fileName` -> ino -> extent(s)
  let npPos = 10;
  const nodeCount = np.readUInt32BE(npPos); npPos += 4;
  const dirEntries = new Map();
  const sizesByIno = new Map();
  const extentsByIno = new Map();
  for (let i = 0; i < nodeCount; i++) {
    npPos += 32; // digest
    const nLen = np.readUInt32BE(npPos); npPos += 4;
    const node = np.subarray(npPos, npPos + nLen); npPos += nLen;
    if (node.subarray(0, 4).toString('ascii') === 'COWN' && node[6] === 0) {
      let cPos = 8;
      const count = node.readUInt32BE(cPos); cPos += 4;
      for (let j = 0; j < count; j++) {
        const ino = Number(node.readBigUInt64BE(cPos)); cPos += 8;
        const kind = node[cPos++];
        const tLen = node.readUInt16BE(cPos); cPos += 2;
        const tail = node.subarray(cPos, cPos + tLen); cPos += tLen;
        const vLen = node.readUInt32BE(cPos); cPos += 4;
        const val = node.subarray(cPos, cPos + vLen); cPos += vLen;
        if (kind === 1 && vLen >= 24) {
          sizesByIno.set(ino, Number(val.readBigUInt64BE(16)));
        } else if (ino === 1 && kind === 0x20) {
          dirEntries.set(tail.toString('utf8'), Number(val.readBigUInt64BE(0)));
        } else if (kind === 0x30) {
          const fileOff = Number(tail.readBigUInt64BE(0));
          const extKind = val[0];
          if (!extentsByIno.has(ino)) extentsByIno.set(ino, []);
          if (extKind === 0) {
            const inLen = val.readUInt16BE(1);
            extentsByIno.get(ino).push({ fileOff, inlineBytes: val.subarray(3, 3 + inLen) });
          } else if (extKind === 1) {
            const extLen = val.readUInt32BE(1);
            const extDigest = val.subarray(5, 37).toString('hex');
            const blockOff = val.readUInt32BE(37);
            extentsByIno.get(ino).push({ fileOff, extLen, extDigest, blockOff });
          }
        }
      }
    }
  }
  const targetIno = dirEntries.get(fileName);
  assert.ok(targetIno, `file ${fileName} not found in cowfs snapshot ${repo}@${reference}`);
  const exts = (extentsByIno.get(targetIno) || []).sort((a, b) => a.fileOff - b.fileOff);
  const packCache = new Map();
  const chunks = [];
  for (const ext of exts) {
    if (ext.inlineBytes) {
      chunks.push(ext.inlineBytes);
      continue;
    }
    const loc = blocks.get(ext.extDigest);
    assert.ok(loc, `missing block ${ext.extDigest} in blockdir`);
    let packBuf = packCache.get(loc.packHex);
    if (!packBuf) {
      packBuf = await getBlob(`sha256:${loc.packHex}`);
      packCache.set(loc.packHex, packBuf);
    }
    chunks.push(packBuf.subarray(loc.offset + (ext.blockOff || 0), loc.offset + (ext.blockOff || 0) + ext.extLen));
  }
  const full = Buffer.concat(chunks);
  const sz = sizesByIno.get(targetIno);
  return sz != null ? full.subarray(0, sz) : full;
}

// Rust WASI pod sources compiled offline with `rustc --target wasm32-wasip1 -O`.
const MAP_POD_RS = `
use std::collections::BTreeMap;
use std::fs;
fn main() {
    let text = fs::read_to_string("/input/shard.txt").expect("read /input/shard.txt");
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut total = 0u64;
    for w in text.split_whitespace() {
        *counts.entry(w.to_string()).or_insert(0) += 1;
        total += 1;
    }
    let mut out = String::from("{");
    for (i, (k, v)) in counts.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push_str(&format!("\\"{k}\\":{v}"));
    }
    out.push('}');
    fs::write("/output/partial.json", &out).expect("write /output/partial.json");
    let node_id = std::env::var("OS_TASK_NODE_ID").unwrap_or_else(|_| "unknown".into());
    fs::write("/output/.os-task-summary.txt", format!("map-ok:{node_id}:{total}")).expect("write summary");
}
`;

const REDUCE_POD_RS = `
use std::collections::BTreeMap;
use std::fs;
fn parse_flat_json(s: &str, acc: &mut BTreeMap<String, u64>) {
    let trimmed = s.trim().trim_start_matches('{').trim_end_matches('}');
    for pair in trimmed.split(',') {
        let pair = pair.trim();
        if pair.is_empty() { continue; }
        let mut it = pair.splitn(2, ':');
        let k = it.next().unwrap().trim().trim_matches('"').to_string();
        let v: u64 = it.next().unwrap().trim().parse().unwrap();
        *acc.entry(k).or_insert(0) += v;
    }
}
fn main() {
    let mut acc = BTreeMap::new();
    parse_flat_json(&fs::read_to_string("/input/shard-0/partial.json").expect("shard-0"), &mut acc);
    parse_flat_json(&fs::read_to_string("/input/shard-1/partial.json").expect("shard-1"), &mut acc);
    let mut out = String::from("{");
    for (i, (k, v)) in acc.iter().enumerate() {
        if i > 0 { out.push(','); }
        out.push_str(&format!("\\"{k}\\":{v}"));
    }
    out.push('}');
    fs::write("/output/final.json", &out).expect("write /output/final.json");
    let a = acc.get("alpha").copied().unwrap_or(0);
    let b = acc.get("beta").copied().unwrap_or(0);
    let g = acc.get("gamma").copied().unwrap_or(0);
    fs::write("/output/.os-task-summary.txt", format!("reduce-ok:{a},{b},{g}")).expect("write summary");
}
`;

const SLOW_POD_RS = `
use std::fs;
use std::time::Duration;
fn main() {
    std::thread::sleep(Duration::from_millis(2500));
    let node = std::env::var("OS_TASK_NODE_ID").unwrap_or_default();
    let att = std::env::var("OS_TASK_ATTEMPT_GEN").unwrap_or_default();
    fs::write("/output/slow.txt", format!("node={node} attempt={att}")).expect("write slow.txt");
    // Write a > 2 KiB payload so COWP data packs are created & exercised across failover cleanup!
    let bulk = format!("pack:{node}:{att}:").repeat(256);
    fs::write("/output/pack.bin", bulk.as_bytes()).expect("write pack.bin");
    fs::write("/output/.os-task-summary.txt", format!("slow-ok:{node}:{att}")).expect("write summary");
}
`;

const LOOP_POD_RS = `
fn main() {
    let mut x = 1u64;
    loop {
        x = std::hint::black_box(x.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
}
`;

const PROBE_POD_RS = `
use std::fs;
fn main() {
    assert!(fs::read("/etc/shadow").is_err(), "/etc/shadow MUST NOT be readable");
    assert!(fs::read("/dev/vd0").is_err(), "/dev/vd0 MUST NOT exist");
    assert!(fs::OpenOptions::new().read(true).open("/dev/null").is_ok(), "/dev/null MUST exist");
    assert!(fs::read_to_string("/proc/1/stat").is_ok(), "/proc/1/stat MUST exist");
    assert!(fs::read_to_string("/proc/2/stat").is_err(), "/proc/2/stat MUST NOT exist");
    assert!(fs::write("/input/escape.txt", b"bad").is_err(), "/input MUST be read-only");
    for (k, v) in std::env::vars() {
        let low = format!("{k}={v}").to_lowercase();
        assert!(!low.contains("osbt_"), "bootstrap token leaked into env");
        assert!(!low.contains("os_session"), "session cookie leaked into env");
        assert!(!low.contains("host_proof"), "host_proof leaked into env");
    }
    let node = std::env::var("OS_TASK_NODE_ID").unwrap_or_default();
    fs::write("/output/probe.txt", format!("probe-clean:{node}")).expect("write probe.txt");
    fs::write("/output/.os-task-summary.txt", format!("probe-clean:{node}")).expect("write summary");
}
`;

const FAST_POD_RS = `
use std::fs;
fn main() {
    let node = std::env::var("OS_TASK_NODE_ID").unwrap_or_default();
    fs::write("/output/fast.txt", format!("fast:{node}")).expect("write fast.txt");
    fs::write("/output/.os-task-summary.txt", format!("fast-ok:{node}")).expect("write summary");
}
`;

let mf, baseUrl, authoritySql, clusterStub, root, osNativeBin, SandboxKernelClass;
let workDir, stateDirA, readyFileA, childA = null, agentB = null;
let imgMap, imgReduce, imgSlow, imgLoop, imgProbe, imgFast, imgElf;
let snapShard0, snapShard1;

async function postJson(path, body, headers = {}) {
  const res = await fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { Origin: baseUrl, 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body),
  });
  return res;
}

async function goodJson(resPromise) {
  const res = await resPromise;
  const text = await res.text();
  assert.equal(res.status, 200, `expected 200, got ${res.status}: ${text}`);
  return JSON.parse(text);
}

async function clusterRpc(call, headers = root.headers) {
  return goodJson(postJson('/api/cluster/rpc', { version: 1, cluster: 'default', call }, headers));
}

async function admitTask(spec) {
  const now = Math.floor(Date.now() / 1000);
  const labels = {
    'os.task/sdk_version': '1',
    'os.task/entrypoint': spec.entrypoint,
    'os.task/output_repo': spec.output_repo,
    'os.task/timeout_secs': String(spec.timeout_secs ?? 60),
    'os.task/memory_max_bytes': String(spec.memory_max_bytes ?? 64 * 1024 * 1024),
    'os.task/pids_max': String(spec.pids_max ?? 8),
  };
  if (spec.args?.length) labels['os.task/args_json'] = JSON.stringify(spec.args);
  if (spec.env && Object.keys(spec.env).length) labels['os.task/env_json'] = JSON.stringify(spec.env);
  if (spec.extra_inputs && Object.keys(spec.extra_inputs).length) {
    labels['os.task/extra_inputs_json'] = JSON.stringify(spec.extra_inputs);
  }
  if (spec.required_host) labels['os.task/required_host'] = spec.required_host;
  if (spec.required_node) labels['os.task/required_node'] = spec.required_node;
  const wl = {
    workload_id: spec.workload_id,
    image_ref: spec.image_ref,
    ...(spec.input_snapshot_ref ? { input_snapshot_ref: spec.input_snapshot_ref } : {}),
    labels,
    desired_state: 'pending',
    current_attempt: 0,
    created_at: now,
  };
  const key = `/t/u0/workloads/${spec.workload_id}`;
  const res = await clusterRpc({
    op: 'txn',
    compare: [{ key, op: 'equal', target: { version: 0 } }],
    success: [{ op: 'put', key, value_b64: b64(JSON.stringify(wl)), lease_id: 0, prev_kv: false }],
    failure: [],
  });
  assert.equal(res.succeeded, true, `admit ${spec.workload_id} failed`);
  return wl;
}

async function cancelWorkload(wid, reason = 'test-cancel') {
  const wlK = `/t/u0/workloads/${wid}`;
  const cancelK = `/t/u0/workloads/${wid}/canceled`;
  const resK = `/t/u0/results/${wid}`;
  const marker = { workload_id: wid, reason, canceled_at: Math.floor(Date.now() / 1000) };
  const res = await clusterRpc({
    op: 'txn',
    compare: [
      { key: wlK, op: 'greater', target: { version: 0 } },
      { key: resK, op: 'equal', target: { version: 0 } },
    ],
    success: [{ op: 'put', key: cancelK, value_b64: b64(JSON.stringify(marker)), lease_id: 0, prev_kv: false }],
    failure: [],
  });
  assert.equal(res.succeeded, true, `cancel ${wid} failed`);
}

async function getKeyJson(key) {
  const r = await clusterRpc({ op: 'range', key, range_end: 'exact', limit: 1 });
  if (!r.kvs?.length) return null;
  return { kv: r.kvs[0], value: JSON.parse(unb64(r.kvs[0].value_b64)) };
}

async function waitForKey(key, timeoutMs = 30_000, predicate = () => true) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const hit = await getKeyJson(key);
    if (hit && predicate(hit)) return hit;
    await new Promise(r => setTimeout(r, 150));
  }
  throw new Error(`timed out waiting for cluster key ${key} after ${timeoutMs}ms`);
}

async function listRepoTags(repo) {
  const bearer = await ociBearerHeaders(baseUrl, root.headers, repo, 'pull');
  const r = await fetch(`${baseUrl}/v2/${repo}/tags/list`, { headers: bearer });
  if (r.status === 404) return [];
  assert.equal(r.status, 200);
  const body = await r.json();
  return body.tags || [];
}

function spawnNativeKubelet(stateDir, readyFile, leaseTtl = 6) {
  try { rmSync(readyFile, { force: true }); } catch {}
  const child = spawn(osNativeBin, [
    'kubelet', 'run',
    '--state', stateDir,
    '--lease-ttl', String(leaseTtl),
    '--ready-file', readyFile,
  ], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });
  child._getStderr = () => stderr;
  return child;
}

async function waitReadyFile(path, timeoutMs = 15_000, child = null) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(path)) {
      try { return JSON.parse(readFileSync(path, 'utf8')); } catch {}
    }
    if (child && child.exitCode !== null) {
      throw new Error(`os-native kubelet exited early (${child.exitCode}): ${child._getStderr?.()}`);
    }
    await new Promise(r => setTimeout(r, 100));
  }
  throw new Error(`timed out waiting for ready file ${path}: ${child?._getStderr?.()}`);
}

function createInMemStorage() {
  let saved = null;
  return {
    async load() { return saved; },
    async save(v) { saved = v; },
    async clear() { saved = null; },
  };
}

before(async () => {
  osNativeBin = findOsNativeBin();
  SandboxKernelClass = await loadSandboxKernelClass();
  workDir = mkdtempSync(join(tmpdir(), 'os-kb-e2e-'));
  stateDirA = join(workDir, 'state-native-a');
  readyFileA = join(workDir, 'ready-a.json');
  mkdirSync(stateDirA, { recursive: true });

  const workerName = 'kubelet-multinode-e2e';
  const classes = ['OsAuthority', 'Machine', 'StorageVolume', 'ClusterState'];
  mf = new Miniflare({
    host: '127.0.0.1',
    port: 0,
    unsafeInspectDurableObjects: true,
    workers: [{
      config: {
        name: workerName,
        compatibilityDate: '2026-10-24',
        manifest: {
          mainModule: 'harness.js',
          modules: {
            'harness.js': {
              type: 'esm',
              contents: `
        import { DurableObject } from 'cloudflare:workers';
        import {
          OsAuthority as Authority,
          Machine as Service,
          StorageVolume as Volume,
          ClusterState as Cluster,
        } from './index.js';
        export { default } from './index.js';
        export class OsAuthority extends DurableObject {
          constructor(ctx, env) { super(ctx, env); this.impl = new Authority(ctx, env); }
          fetch(r) { return this.impl.fetch(r); }
          alarm() { return this.impl.alarm(); }
        }
        export class Machine extends DurableObject {
          constructor(ctx, env) { super(ctx, env); this.impl = new Service(ctx, env); }
          fetch(r) { return this.impl.fetch(r); }
          alarm() { return this.impl.alarm(); }
        }
        export class StorageVolume extends DurableObject {
          constructor(ctx, env) { super(ctx, env); this.impl = new Volume(ctx, env); }
          fetch(r) { return this.impl.fetch(r); }
          alarm() { return this.impl.alarm(); }
        }
        export class ClusterState extends DurableObject {
          constructor(ctx, env) { super(ctx, env); this.impl = new Cluster(ctx, env); }
          fetch(r) { return this.impl.fetch(r); }
          alarm() { return this.impl.alarm(); }
          async triggerAlarm() { await this.impl.alarm(); }
          webSocketMessage(ws, msg) { return this.impl.webSocketMessage(ws, msg); }
          webSocketClose(ws, code, reason, wasClean) { return this.impl.webSocketClose(ws, code, reason, wasClean); }
          webSocketError(ws, err) { return this.impl.webSocketError(ws, err); }
        }`,
            },
            'index.js': { type: 'esm', contents: readFileSync(join(ROOT, 'crates/worker/build/index.js'), 'utf8') },
            'index_bg.wasm': { type: 'wasm', contents: readFileSync(join(ROOT, 'crates/worker/build/index_bg.wasm')) },
          },
        },
        exports: Object.fromEntries(classes.map(n => [n, { type: 'durable-object', storage: 'sqlite' }])),
        env: {
          ...Object.fromEntries(['AUTHORITY', 'MACHINE', 'STORAGE', 'CLUSTER_STATE'].map(
            (binding, i) => [binding, { type: 'durable-object', worker: workerName, exportName: classes[i] }],
          )),
          FILES: { type: 'r2', name: 'files-kubelet-e2e' },
          ADMIN_PASSWORD: { type: 'text', value: randomUUID() },
          SESSION_SECRET: { type: 'text', value: randomUUID() },
          ASSETS: {
            type: 'fetcher',
            handler: () => new Response('{}', { headers: { 'Content-Type': 'application/json' } }),
          },
        },
      },
    }],
  });

  const url = await mf.ready;
  baseUrl = url.origin;

  // Bootstrap Authority + root session + attached admin instance.
  await goodJson(postJson('/api/sys', { calls: ['getcreds'] }));
  authoritySql = await mf.unsafeGetDurableObjectStorage(workerName, 'OsAuthority', { name: 'filesystem' });
  const session = randomBytes(32).toString('hex');
  await authoritySql.exec(
    'INSERT INTO sessions(key,uid,expires,sudo_until) VALUES(?,?,?,0)',
    sha(session).toString('base64url'),
    0,
    Math.floor(Date.now() / 1000) + 3600,
  );
  const cookie = `os_session=${session}`;
  const instance = `inst-admin-${randomUUID()}`;
  const proof = randomBytes(32).toString('hex');
  const auth = body => goodJson(postJson('/api/service-auth', body, { Cookie: cookie }));
  await auth({ attach_instance: { instance: { instance, host: 'test-admin' }, host_proof: proof } });
  const { cred } = await auth({
    mint_service_cred: { instance_id: instance, host_proof: proof, scope: FULL_CLUSTER_AND_OCI },
  });
  root = {
    cookie,
    instance,
    proof,
    auth,
    headers: { Cookie: cookie, 'X-OS-Instance': instance, 'X-Process-Token': cred.token },
  };
  const clusterNs = await mf.getDurableObjectNamespace('CLUSTER_STATE');
  clusterStub = clusterNs.get(clusterNs.idFromName('cluster:default'));

  // Compile real wasm32-wasip1 pods & push OCI images + input cowfs snapshots!
  const mapWasm = compileWasiPod(workDir, 'map', MAP_POD_RS);
  const reduceWasm = compileWasiPod(workDir, 'reduce', REDUCE_POD_RS);
  const slowWasm = compileWasiPod(workDir, 'slow', SLOW_POD_RS);
  const loopWasm = compileWasiPod(workDir, 'loop', LOOP_POD_RS);
  const probeWasm = compileWasiPod(workDir, 'probe', PROBE_POD_RS);
  const fastWasm = compileWasiPod(workDir, 'fast', FAST_POD_RS);
  const fakeElf = Buffer.from('\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00', 'binary');

  imgMap = await pushOciTarImage(baseUrl, root.headers, 'tasks/map', 'v1', [{ path: 'usr/bin/map.wasm', content: mapWasm }]);
  imgReduce = await pushOciTarImage(baseUrl, root.headers, 'tasks/reduce', 'v1', [{ path: 'usr/bin/reduce.wasm', content: reduceWasm }]);
  imgSlow = await pushOciTarImage(baseUrl, root.headers, 'tasks/slow', 'v1', [{ path: 'usr/bin/slow.wasm', content: slowWasm }]);
  imgLoop = await pushOciTarImage(baseUrl, root.headers, 'tasks/loop', 'v1', [{ path: 'usr/bin/loop.wasm', content: loopWasm }]);
  imgProbe = await pushOciTarImage(baseUrl, root.headers, 'tasks/probe', 'v1', [{ path: 'usr/bin/probe.wasm', content: probeWasm }]);
  imgFast = await pushOciTarImage(baseUrl, root.headers, 'tasks/fast', 'v1', [{ path: 'usr/bin/fast.wasm', content: fastWasm }]);
  imgElf = await pushOciTarImage(baseUrl, root.headers, 'tasks/elf', 'v1', [{ path: 'usr/bin/elf-pod', content: fakeElf }]);

  snapShard0 = await pushOciCowfsSnapshot(baseUrl, root.headers, 'inputs/mr', 'shard-0', {
    'shard.txt': 'alpha beta alpha\n',
  });
  snapShard1 = await pushOciCowfsSnapshot(baseUrl, root.headers, 'inputs/mr', 'shard-1', {
    'shard.txt': 'beta gamma alpha\n',
  });
});

after(async () => {
  if (agentB) await agentB.stop().catch(() => {});
  if (childA && childA.exitCode === null) {
    try { childA.kill('SIGKILL'); } catch {}
  }
  if (mf) await mf.dispose();
  if (workDir) rmSync(workDir, { recursive: true, force: true });
});

test('KB-03 single-use bootstrap enrollment, direct-use rejection, and instant live revocation', async () => {
  const mintBootstrap = async nodeId => {
    const res = await root.auth({
      mint_bootstrap_token: {
        instance_id: root.instance,
        host_proof: root.proof,
        node_id: nodeId,
        cluster: 'default',
        ttl_secs: 300,
        scope: FULL_CLUSTER_AND_OCI,
        sudo: false,
      },
    });
    assert.ok(res.bootstrap_token?.bootstrap_token?.startsWith('osbt_'));
    return res.bootstrap_token.bootstrap_token;
  };

  const btA = await mintBootstrap('node-native-a');
  const btB = await mintBootstrap('node-browser-b');
  const btC = await mintBootstrap('node-revoke-c');

  // 1. Bootstrap token MUST NEVER work directly on /api/cluster/rpc, /v2/, or /api/volumes/rpc!
  const directHeaders = { 'X-OS-Instance': 'fake-inst', 'X-Process-Token': btA };
  const rCluster = await postJson('/api/cluster/rpc', { version: 1, cluster: 'default', call: { op: 'hello', versions: [1] } }, directHeaders);
  assert.equal(rCluster.status, 403, 'bootstrap token must be rejected on /api/cluster/rpc');
  const rOciTok = await fetch(`${baseUrl}/v2/token?service=os-registry&scope=${encodeURIComponent('repository:tasks/map:pull')}`, { headers: directHeaders });
  assert.ok(rOciTok.status === 401 || rOciTok.status === 403, `bootstrap token must be rejected on /v2/token (got ${rOciTok.status})`);
  const rVol = await postJson('/api/volumes/rpc', { op: 'read_head', volume: 'v1' }, directHeaders);
  assert.equal(rVol.status, 403, 'bootstrap token must be rejected on /api/volumes/rpc');

  // 2. Enroll Node A via REAL `os-native kubelet enroll`.
  execFileSync(osNativeBin, [
    'kubelet', 'enroll',
    '--url', baseUrl,
    '--bootstrap-token', btA,
    '--state', stateDirA,
  ], { stdio: 'inherit' });

  // 3. Replaying btA a second time MUST FAIL (atomic single-use consumption)!
  const replay = await postJson('/api/service-auth', {
    exchange_bootstrap_token: {
      bootstrap_token: btA,
      instance: { instance: `replay-${randomUUID()}`, host: 'os-native' },
      host_proof: randomBytes(32).toString('hex'),
    },
  });
  assert.ok(replay.status === 403 || replay.status === 404, `replayed bootstrap token must fail (got ${replay.status})`);

  // 4. Enroll Node B via REAL `KubeletAgent.enroll(btB)` backed by real `SandboxKernel` & `sandbox-worker.js`.
  agentB = new KubeletAgent({
    baseUrl,
    hostKind: 'browser',
    leaseTtlSecs: 6,
    storage: createInMemStorage(),
    getSandboxKernel: () => SandboxKernelClass,
    createSandboxWorker: () => new Worker(new URL('../web/kernel/sandbox-worker.js', import.meta.url)),
  });
  const enB = await agentB.enroll(btB);
  assert.equal(enB.node_id, 'node-browser-b');
  assert.ok(enB.ns.startsWith('node.'));

  // 4b. Security regression (Finding #1): a u0-enrolled node credential MUST NEVER obtain
  //     cross-tenant OCI Bearer tokens or cluster/volume grants (even with X-OS-Tenant: u1000).
  const nodeHdrs = { 'X-OS-Instance': enB.instance_id, 'X-Process-Token': enB.token };
  const xTenantOci = await fetch(
    `${baseUrl}/v2/token?service=os-registry&scope=${encodeURIComponent('repository:tasks/map:pull,push')}`,
    { headers: { ...nodeHdrs, 'X-OS-Tenant': 'u1000' } },
  );
  assert.ok(
    xTenantOci.status === 401 || xTenantOci.status === 403,
    `u0 node must be denied cross-tenant OCI token (got ${xTenantOci.status})`,
  );
  const xTenantCluster = await postJson(
    '/api/cluster/rpc',
    { version: 1, cluster: 'default', call: { op: 'hello', versions: [1] } },
    { ...nodeHdrs, 'X-OS-Tenant': 'u1000' },
  );
  assert.equal(xTenantCluster.status, 403, 'u0 node must be denied cross-tenant cluster RPC');

  // 4c. Security regression (Finding #7): browser holding BOTH os_guest and os_session cookies
  //     uses session.<key> consistently across ServiceAuth v2, /api/cluster/rpc, and /v2/token.
  const dualCookie = `${root.cookie}; os_guest=${randomBytes(32).toString('hex')}`;
  const dualCluster = await postJson(
    '/api/cluster/rpc',
    { version: 1, cluster: 'default', call: { op: 'hello', versions: [1] } },
    { ...root.headers, Cookie: dualCookie },
  );
  assert.equal(dualCluster.status, 200, 'dual-cookie signed-in session must work on /api/cluster/rpc');
  const dualOci = await fetch(
    `${baseUrl}/v2/token?service=os-registry&scope=${encodeURIComponent('repository:tasks/map:pull')}`,
    { headers: { ...root.headers, Cookie: dualCookie } },
  );
  assert.equal(dualOci.status, 200, 'dual-cookie signed-in session must work on /v2/token');

  // 5. Enroll node-revoke-c, open a live WS watch, then revoke via RevokeNode -> instant disconnect & 403!
  const agentC = new KubeletAgent({
    baseUrl,
    hostKind: 'browser',
    storage: createInMemStorage(),
    getSandboxKernel: () => SandboxKernelClass,
  });
  const enC = await agentC.enroll(btC);
  const ticketRes = await goodJson(postJson('/api/cluster/watch-ticket', { version: 1, cluster: 'default' }, {
    'X-OS-Instance': enC.instance_id,
    'X-Process-Token': enC.token,
  }));
  const wsUrl = `${baseUrl.replace(/^http/, 'ws')}/api/cluster/watch?cluster=default&ticket=${encodeURIComponent(ticketRes.ticket)}`;
  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', reject, { once: true });
  });
  const closedPromise = new Promise(resolve => ws.addEventListener('close', ev => resolve(ev.code), { once: true }));
  ws.send(JSON.stringify({ op: 'hello', versions: [1] }));
  ws.send(JSON.stringify({ op: 'subscribe', watch_id: 1, key: '/t/u0/workloads/', range_end: 'prefix', from_revision: 0 }));
  await new Promise(r => setTimeout(r, 150));

  const rev = await root.auth({
    revoke_node: {
      instance_id: root.instance,
      host_proof: root.proof,
      node_id: 'node-revoke-c',
    },
  });
  assert.ok(rev.node_revoked?.revoked >= 1, `expected >=1 revoked: ${JSON.stringify(rev)}`);

  // Live watch MUST close promptly upon RevokeNode!
  const closeCode = await Promise.race([
    closedPromise,
    new Promise((_, rej) => setTimeout(() => rej(new Error('live WS watch did not disconnect on RevokeNode')), 5000)),
  ]);
  assert.ok(typeof closeCode === 'number');

  // Subsequent RPC with revoked token MUST fail with 403!
  const afterRev = await postJson('/api/cluster/rpc', { version: 1, cluster: 'default', call: { op: 'hello', versions: [1] } }, {
    'X-OS-Instance': enC.instance_id,
    'X-Process-Token': enC.token,
  });
  assert.equal(afterRev.status, 403, 'revoked node token must fail closed with 403');
});

test('KB-04 multi-node Map-Reduce across os-native Node A and browser Node B with OCI cowfs handoff', async () => {
  childA = spawnNativeKubelet(stateDirA, readyFileA, 6);
  const readyA = await waitReadyFile(readyFileA, 15_000, childA);
  assert.equal(readyA.node_id, 'node-native-a');

  await agentB.start({ leaseTtlSecs: 6 });

  // Both nodes registered with distinct host_kind metadata.
  const metaA = await waitForKey('/t/u0/node-meta/node-native-a');
  const metaB = await waitForKey('/t/u0/node-meta/node-browser-b');
  assert.equal(metaA.value.host_kind, 'os-native');
  assert.equal(metaB.value.host_kind, 'browser');

  // Submit 2 map shards: shard-0 pinned to os-native, shard-1 pinned to browser.
  await admitTask({
    workload_id: 'mr-map-0',
    image_ref: imgMap,
    entrypoint: '/usr/bin/map.wasm',
    input_snapshot_ref: snapShard0,
    output_repo: 'results/mr',
    required_host: 'os-native',
  });
  await admitTask({
    workload_id: 'mr-map-1',
    image_ref: imgMap,
    entrypoint: '/usr/bin/map.wasm',
    input_snapshot_ref: snapShard1,
    output_repo: 'results/mr',
    required_host: 'browser',
  });

  const res0 = (await waitForKey('/t/u0/results/mr-map-0', 30_000)).value;
  const res1 = (await waitForKey('/t/u0/results/mr-map-1', 30_000)).value;
  assert.equal(res0.exit_code, 0, JSON.stringify(res0));
  assert.equal(res0.node_id, 'node-native-a');
  assert.equal(res0.summary, 'map-ok:node-native-a:3');
  assert.ok(res0.output_ref?.startsWith('oci:results/mr@sha256:'));

  assert.equal(res1.exit_code, 0, JSON.stringify(res1));
  assert.equal(res1.node_id, 'node-browser-b');
  assert.equal(res1.summary, 'map-ok:node-browser-b:3');
  assert.ok(res1.output_ref?.startsWith('oci:results/mr@sha256:'));

  // Submit reducer taking BOTH cross-host outputs as extra_inputs!
  await admitTask({
    workload_id: 'mr-reduce',
    image_ref: imgReduce,
    entrypoint: '/usr/bin/reduce.wasm',
    extra_inputs: { 'shard-0': res0.output_ref, 'shard-1': res1.output_ref },
    output_repo: 'results/mr',
    required_host: 'os-native',
  });
  const resR = (await waitForKey('/t/u0/results/mr-reduce', 30_000)).value;
  assert.equal(resR.exit_code, 0, JSON.stringify(resR));
  assert.equal(resR.summary, 'reduce-ok:3,2,1');

  // Independently verify promoted `result-mr-reduce` cowfs snapshot & COWP pack data!
  const finalJson = JSON.parse(
    (await readCowfsSnapshotFile(baseUrl, root.headers, 'results/mr', 'result-mr-reduce', 'final.json')).toString('utf8'),
  );
  assert.deepEqual(finalJson, { alpha: 3, beta: 2, gamma: 1 });
});

test('KB-05 SIGSTOP pause + lease-expiry failover + SIGCONT stale-node fencing + SIGKILL failover + staging survival', async () => {
  // Pause Node B claiming briefly so Node A is guaranteed to claim attempt 1.
  agentB.draining = true;
  await admitTask({
    workload_id: 'slow-stop',
    image_ref: imgSlow,
    entrypoint: '/usr/bin/slow.wasm',
    output_repo: 'results/failover',
  });
  const att1 = await waitForKey('/t/u0/attempts/slow-stop/1', 15_000);
  assert.equal(att1.value.node_id, 'node-native-a');

  // Freeze Node A with SIGSTOP right after it claims attempt 1, then re-enable Node B!
  childA.kill('SIGSTOP');
  agentB.draining = false;

  // Wait for Node A's 6s lease to expire and Node B to reclaim attempt 2 & publish result!
  const stopRes = (await waitForKey('/t/u0/results/slow-stop', 25_000)).value;
  assert.equal(stopRes.exit_code, 0, JSON.stringify(stopRes));
  assert.equal(stopRes.node_id, 'node-browser-b');
  assert.equal(stopRes.attempt_generation, 2);
  assert.equal(stopRes.summary, 'slow-ok:node-browser-b:2');

  // Resume stale Node A with SIGCONT! It must NOT overwrite results/slow-stop and must clean up its staging tag.
  childA.kill('SIGCONT');
  await new Promise(r => setTimeout(r, 4000));

  const afterCont = (await getKeyJson('/t/u0/results/slow-stop')).value;
  assert.equal(afterCont.node_id, 'node-browser-b');
  assert.equal(afterCont.attempt_generation, 2);

  // Verify zero staging tags left behind and winner's result-slow-stop + COWP packs remain 100% readable!
  const tags = await listRepoTags('results/failover');
  assert.ok(!tags.some(t => t.startsWith('staging-slow-stop-')), `stale staging tag leaked: ${JSON.stringify(tags)}`);
  assert.ok(tags.includes('result-slow-stop'), `winner tag missing: ${JSON.stringify(tags)}`);
  const slowOut = (await readCowfsSnapshotFile(baseUrl, root.headers, 'results/failover', 'result-slow-stop', 'slow.txt')).toString('utf8');
  assert.equal(slowOut, 'node=node-browser-b attempt=2');
  const packOut = (await readCowfsSnapshotFile(baseUrl, root.headers, 'results/failover', 'result-slow-stop', 'pack.bin')).toString('utf8');
  assert.equal(packOut, 'pack:node-browser-b:2:'.repeat(256));

  // Node A must have re-registered at a strictly higher monotonic node_generation!
  const nodeAAfter = await waitForKey('/t/u0/nodes/node-native-a', 15_000, hit => hit.value.node_generation >= 2);
  assert.ok(nodeAAfter.value.node_generation >= 2);

  // Now test SIGKILL hard crash failover!
  agentB.draining = true;
  await admitTask({
    workload_id: 'slow-kill',
    image_ref: imgSlow,
    entrypoint: '/usr/bin/slow.wasm',
    output_repo: 'results/failover',
  });
  const killAtt1 = await waitForKey('/t/u0/attempts/slow-kill/1', 15_000);
  assert.equal(killAtt1.value.node_id, 'node-native-a');

  childA.kill('SIGKILL');
  await new Promise(r => childA.once('exit', r));
  agentB.draining = false;

  const killRes = (await waitForKey('/t/u0/results/slow-kill', 25_000)).value;
  assert.equal(killRes.exit_code, 0, JSON.stringify(killRes));
  assert.equal(killRes.node_id, 'node-browser-b');
  assert.equal(killRes.attempt_generation, 2);

  // Restart Node A for KB-06 & KB-07 and confirm monotonic generation increased again.
  childA = spawnNativeKubelet(stateDirA, readyFileA, 6);
  const restarted = await waitReadyFile(readyFileA, 15_000, childA);
  assert.ok(restarted.node_generation > nodeAAfter.value.node_generation);
});

test('KB-06 live cancellation preempts infinite-loop pods on BOTH os-native and browser', async () => {
  await admitTask({
    workload_id: 'loop-native',
    image_ref: imgLoop,
    entrypoint: '/usr/bin/loop.wasm',
    output_repo: 'results/cancel',
    required_host: 'os-native',
  });
  await admitTask({
    workload_id: 'loop-browser',
    image_ref: imgLoop,
    entrypoint: '/usr/bin/loop.wasm',
    output_repo: 'results/cancel',
    required_host: 'browser',
  });

  await waitForKey('/t/u0/attempts/loop-native/1', 15_000);
  await waitForKey('/t/u0/attempts/loop-browser/1', 15_000);

  const t0 = Date.now();
  await cancelWorkload('loop-native');
  await cancelWorkload('loop-browser');

  // Submit quick follow-up tasks to BOTH nodes: if either infinite loop wasn't preempted,
  // these tasks would starve and time out!
  await admitTask({
    workload_id: 'after-cancel-native',
    image_ref: imgFast,
    entrypoint: '/usr/bin/fast.wasm',
    output_repo: 'results/cancel',
    required_host: 'os-native',
  });
  await admitTask({
    workload_id: 'after-cancel-browser',
    image_ref: imgFast,
    entrypoint: '/usr/bin/fast.wasm',
    output_repo: 'results/cancel',
    required_host: 'browser',
  });

  const fA = (await waitForKey('/t/u0/results/after-cancel-native', 10_000)).value;
  const fB = (await waitForKey('/t/u0/results/after-cancel-browser', 10_000)).value;
  const elapsed = Date.now() - t0;
  assert.equal(fA.exit_code, 0);
  assert.equal(fB.exit_code, 0);
  assert.ok(elapsed < 10_000, `cancellation recovery took too long: ${elapsed}ms`);

  // Canceled workloads must NEVER publish results or leave staging tags!
  assert.equal(await getKeyJson('/t/u0/results/loop-native'), null);
  assert.equal(await getKeyJson('/t/u0/results/loop-browser'), null);
  const cancelTags = await listRepoTags('results/cancel');
  assert.ok(!cancelTags.some(t => t.startsWith('staging-loop-')), `leaked cancel staging tags: ${JSON.stringify(cancelTags)}`);
});

test('KB-07 ELF binaries rejected with ENOEXEC and sandbox isolation verified on BOTH hosts', async () => {
  await admitTask({
    workload_id: 'elf-native',
    image_ref: imgElf,
    entrypoint: '/usr/bin/elf-pod',
    output_repo: 'results/sec',
    required_host: 'os-native',
  });
  await admitTask({
    workload_id: 'elf-browser',
    image_ref: imgElf,
    entrypoint: '/usr/bin/elf-pod',
    output_repo: 'results/sec',
    required_host: 'browser',
  });

  const eA = (await waitForKey('/t/u0/results/elf-native', 15_000)).value;
  const eB = (await waitForKey('/t/u0/results/elf-browser', 15_000)).value;
  assert.equal(eA.exit_code, 126, JSON.stringify(eA));
  assert.match(eA.summary || '', /ENOEXEC/i);
  assert.equal(eB.exit_code, 126, JSON.stringify(eB));
  assert.match(eB.summary || '', /ENOEXEC/i);

  await admitTask({
    workload_id: 'probe-native',
    image_ref: imgProbe,
    entrypoint: '/usr/bin/probe.wasm',
    input_snapshot_ref: snapShard0,
    output_repo: 'results/sec',
    required_host: 'os-native',
  });
  await admitTask({
    workload_id: 'probe-browser',
    image_ref: imgProbe,
    entrypoint: '/usr/bin/probe.wasm',
    input_snapshot_ref: snapShard0,
    output_repo: 'results/sec',
    required_host: 'browser',
  });

  const pA = (await waitForKey('/t/u0/results/probe-native', 15_000)).value;
  const pB = (await waitForKey('/t/u0/results/probe-browser', 15_000)).value;
  assert.equal(pA.exit_code, 0, JSON.stringify(pA));
  assert.equal(pA.summary, 'probe-clean:node-native-a');
  assert.equal(pB.exit_code, 0, JSON.stringify(pB));
  assert.equal(pB.summary, 'probe-clean:node-browser-b');
});
