// Test the production Rust VFS, without a JS ACL implementation or stale dist.
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { after } from 'node:test';
const process = spawn('cargo', ['run', '--quiet', '--locked', '-p', 'os-kernel', '--example', 'mount_policy_probe'], { cwd: new URL('..', import.meta.url), stdio: ['pipe', 'pipe', 'pipe'] });
const waiting = []; let failure, diagnostics = '';
process.stderr.on('data', data => { diagnostics = (diagnostics + data).slice(-16384); });
const fail = error => { failure = error; for (const pending of waiting.splice(0)) { clearTimeout(pending.timer); pending.reject(error); } };
process.on('error', fail);
const ended = new Promise(resolve => process.on('close', code => { if (code) fail(new Error('VFS test adapter exited: ' + diagnostics)); resolve(); }));
createInterface({ input: process.stdout }).on('line', line => {
  const pending = waiting.shift(); if (!pending) return;
  clearTimeout(pending.timer); try { pending.resolve(JSON.parse(line)); } catch (error) { pending.reject(error); }
});
export const evaluatePolicy = input => new Promise((resolve, reject) => {
  if (failure) { reject(failure); return; }
  const timer = setTimeout(() => { fail(new Error('VFS test adapter timed out: ' + diagnostics)); process.kill(); }, 120000);
  waiting.push({ resolve, reject, timer }); process.stdin.write(JSON.stringify(input) + '\n');
});
after(async () => { process.stdin.end(); await ended; });
