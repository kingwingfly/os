import { readFile, readdir } from 'node:fs/promises';
const port = process.env.TERMINAL_PORT || '8787';
if (!/^\d+$/.test(port)) throw new Error('Invalid local port');
const origin = `http://127.0.0.1:${port}`; // Deliberately local-only; never seed a remote account.
const vars = await readFile('.dev.vars', 'utf8');
const password = process.env.TERMINAL_PASSWORD || vars.match(/^ADMIN_PASSWORD=(.+)$/m)?.[1];
if (!password) throw new Error('Run npm run setup first');
// Sign in as root (the login system call), whose session cookie the calls below carry.
const login = await fetch(origin + '/api/sys', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ calls: [{ login: { username: 'root', password } }] }) });
const [signed] = login.ok ? (await login.clone().json()).results : [{ err: { errno: login.status } }];
if (!signed.ok) throw new Error(`Local login failed: ${signed.err?.detail || signed.err?.errno}`);
const cookie = login.headers.getSetCookie().map(set => set.split(';')[0]).find(set => set.startsWith('terminal_session='));
const headers = { Origin: origin, Cookie: cookie };
// System calls, as a page makes them: each call's `{ok}` or `{err}`.
async function sys(calls) {
  const response = await fetch(origin + '/api/sys', { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ calls }) });
  if (!response.ok) throw new Error(`/api/sys: ${response.status} ${await response.text()}`);
  return (await response.json()).results;
}
// A new file, through a descriptor: open, one pwrite, close. One there already is kept.
async function upload(path, body) {
  const [opened] = await sys([{ open: { path, flags: 0o1 | 0o100 | 0o200, mode: 0o644, size: body.length } }]);
  if (opened.err?.errno === 'EEXIST') return console.log(`Keeping existing ${path}`);
  if (opened.err) throw new Error(`${path}: ${opened.err.detail || opened.err.errno}`);
  const fd = opened.ok.fd;
  if (body.length) {
    const written = await fetch(`${origin}/api/pwrite?fd=${fd}&index=0`, { method: 'PUT', headers, body });
    if (!written.ok) throw new Error(`${path}: ${written.status} ${await written.text()}`);
  }
  const [closed] = await sys([{ close: { fd } }]);
  if (closed.err) throw new Error(`${path}: ${closed.err.detail || closed.err.errno}`);
  console.log(`Wrote ${path}`);
}
for (const name of await readdir('seed')) await upload('/' + name, await readFile('seed/' + name));
// mkdir(2); one that is there already is fine.
const [result] = await sys([{ mkdir: { path: '/media', mode: 0o755 } }]);
if (result.err && result.err.errno !== 'EEXIST') throw new Error(`mkdir /media: ${result.err.detail || result.err.errno}`);
// A generated, quiet two-second sine wave; no external media or network dependencies.
const sampleRate = 22050, count = sampleRate * 2, wav = Buffer.alloc(44 + count * 2);
wav.write('RIFF', 0); wav.writeUInt32LE(wav.length - 8, 4); wav.write('WAVEfmt ', 8); wav.writeUInt32LE(16, 16);
wav.writeUInt16LE(1, 20); wav.writeUInt16LE(1, 22); wav.writeUInt32LE(sampleRate, 24); wav.writeUInt32LE(sampleRate * 2, 28);
wav.writeUInt16LE(2, 32); wav.writeUInt16LE(16, 34); wav.write('data', 36); wav.writeUInt32LE(count * 2, 40);
for (let i = 0; i < count; i++) wav.writeInt16LE(Math.round(Math.sin(i / sampleRate * Math.PI * 220 * 2) * 1000 * Math.sin(Math.PI * i / count)), 44 + i * 2);
await upload('/media/signal.wav', wav);
console.log('Local examples are ready.');
