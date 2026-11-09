import test from 'node:test';
import assert from 'node:assert/strict';
import { execCandidates, resolveExecs } from '../web/wasi/resolve.mjs';

test('PATH search preserves argv, searches past access denials, and bypasses PATH for explicit paths', async () => {
  const asked = [];
  const results = await resolveExecs([
    { path: 'tool', argv: ['tool', '--help'], env: ['PATH=/first::/usr/bin'] },
    { path: './exact', argv: ['./exact'], env: ['PATH=/ignored'] },
  ], async stages => stages.map(stage => {
    asked.push(stage);
    if (stage.path === '/first/tool') return { err: { errno: 'EACCES' } };
    if (stage.path === './tool') return { err: { errno: 'ENOENT' } };
    return { ok: { pid: stage.path === './exact' ? 1 : 2 } };
  }));
  assert.deepEqual(results, [{ ok: { pid: 2 } }, { ok: { pid: 1 } }]);
  assert.deepEqual(asked.map(stage => stage.path), ['/first/tool', './exact', './tool', '/usr/bin/tool']);
  assert.deepEqual(asked[3].argv, ['tool', '--help']);
});

test('PATH failure retains EACCES and transport failure releases already-created peers', async () => {
  const denied = await resolveExecs([{ path: 'tool', env: ['PATH=/first:/last'] }], async ([stage]) => [
    { err: { errno: stage.path.startsWith('/first') ? 'EACCES' : 'ENOENT' } },
  ]);
  assert.equal(denied[0].err.errno, 'EACCES');
  const released = [];
  let calls = 0;
  await assert.rejects(resolveExecs([
    { path: 'missing', env: ['PATH=/first:/last'] }, { path: '/ok' },
  ], async () => {
    if (++calls > 1) throw new Error('transport failed');
    return [{ err: { errno: 'ENOENT' } }, { ok: { pid: 7 } }];
  }, async image => released.push(image.pid)), /transport failed/);
  assert.deepEqual(released, [7]);
});

test('an empty PATH searches cwd while an unset PATH uses the system directory', () => {
  assert.deepEqual(execCandidates('tool', ''), ['./tool']);
  assert.deepEqual(execCandidates('tool'), ['/usr/bin/tool']);
  assert.deepEqual(execCandidates('./tool', '/ignored'), ['./tool']);
});
