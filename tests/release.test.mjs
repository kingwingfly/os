import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign, webcrypto } from 'node:crypto';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
let sequence = 0;
async function fixture(change = () => {}) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), key = hash(raw);
  const bytes = Buffer.from(JSON.stringify({ format:'os.release',version:1,protocol:{min:1,max:1},schema:{min:7,max:7} }));
  const id = hash(bytes), prefix = `/boot/releases/${id}/assets`;
  const signature = { format:'os.signature',version:1,key,signature:sign(null,Buffer.concat([Buffer.from('os.release.v1\0'),bytes]),privateKey).toString('hex') };
  const entries = { format:'os.boot',version:1,protocol:1,schema:7,default:id,trust:{keys:{[key]:raw.toString('hex')},revoked:[]} };
  const state = { entries, signature, bytes, id, key }; change(state);
  const saved = { location:globalThis.location, fetch:globalThis.fetch, flag:globalThis.__osReleaseFetch };
  const requests = [];
  globalThis.location = { pathname:prefix+'/index.html',href:'https://os.test'+prefix+'/index.html',origin:'https://os.test' };
  globalThis.fetch = async (input, init) => {
    const path = new URL(input instanceof Request ? input.url : input, location.href).pathname;
    requests.push({ path, headers:input instanceof Request ? input.headers : new Headers(init?.headers) });
    if (path === '/boot/entries') return Response.json(state.entries);
    if (path.endsWith('/manifest.json')) return new Response(state.bytes);
    if (path.endsWith('/signature.json')) return Response.json(state.signature);
    return Response.json({});
  };
  delete globalThis.__osReleaseFetch;
  const module = await import(`../web/release.js?test=${sequence++}`);
  return { ...module, requests, id, prefix, close() { globalThis.location=saved.location;globalThis.fetch=saved.fetch;globalThis.__osReleaseFetch=saved.flag; } };
}
test('release handshake verifies exact bytes and asset/API requests retain the selected generation', async () => {
  assert.ok(webcrypto.subtle);
  const f = await fixture();
  try {
    await f.verifyRelease();
    assert.equal(f.asset('/client-kernel.js'),f.prefix+'/client-kernel.js');
    assert.equal(f.asset('/api/sys'),'/api/sys');
    assert.equal(f.asset('/boot/blobs/abc'),'/boot/blobs/abc');
    assert.equal(f.asset('//another.test/script.js'),'//another.test/script.js');
    await fetch('https://os.test/api/sys',{method:'POST',body:'{}'});
    assert.equal(f.requests.at(-1).headers.get('X-OS-Release'),f.id);
    await fetch('https://os.test/os-config.json');
    assert.equal(f.requests.at(-1).path,f.prefix+'/os-config.json');
  } finally { f.close(); }
});
for (const [name, change, message] of [
  ['byte tampering', s => { s.bytes=Buffer.concat([s.bytes,Buffer.from(' ')]); }, /digest mismatch/],
  ['revoked publisher', s => s.entries.trust.revoked.push(s.key), /not trusted/],
  ['unknown publisher', s => { s.entries.trust.keys={}; }, /not trusted/],
  ['signature tampering', s => { s.signature.signature='00'.repeat(64); }, /Invalid release signature/],
  ['incompatible authority', s => { s.entries.schema=8; }, /incompatible/],
]) test(`release handshake rejects ${name} before application initialization`,async()=>{
  const f=await fixture(change);try{await assert.rejects(f.verifyRelease(),message);}finally{f.close();}
});

test('recovery navigation keeps child entry points on the same fallback generation', async () => {
  const saved = { location:globalThis.location, flag:globalThis.__osReleaseFetch };
  globalThis.location = { pathname:'/', search:'?recovery=1', href:'https://os.test/?recovery=1', origin:'https://os.test' };
  globalThis.__osReleaseFetch=true;
  try {
    const f=await import(`../web/release.js?test=${sequence++}`);
    assert.equal(f.entry('/console.html'),'/console.html?recovery=1');
    assert.equal(f.entry('/shell.html'),'/shell.html?recovery=1');
    assert.equal(f.entry('/shell.html?managed=1#status'),'/shell.html?managed=1&recovery=1#status');
    assert.equal(f.entry('/shell.html?managed=1&recovery=0'),'/shell.html?managed=1&recovery=1');
    assert.equal(f.asset('/client-kernel.js'),'/client-kernel.js');
  }finally{globalThis.location=saved.location;globalThis.__osReleaseFetch=saved.flag;}
});
