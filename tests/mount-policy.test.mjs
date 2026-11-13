import test from 'node:test';
import assert from 'node:assert/strict';
import { PermissionMount } from '../web/kernel/mount-policy.js';
import { LocalMounts, localImage } from '../web/kernel/local-mounts.js';
import { evaluatePolicy } from './mount-policy-engine.mjs';
const encoder = new TextEncoder();
const acl = (users, mask = 5, group = 0, other = 0) => ({ user: 7, group, other, mask, users, groups: {} });
const attr = entries => ({ name: 'system.posix_acl_access', value: btoa(JSON.stringify(entries)), flags: 0, nofollow: false });
async function fixture() {
  const raw = new LocalMounts(), grant = await raw.mountFiles([new File(['private'], 'text'), new File([new Uint8Array([0,97,115,109,1,0,0,0])], 'tool')], { execute: true });
  const owner = new PermissionMount(raw, grant, { uid: 12, gid: 9, groups: [9] }, evaluatePolicy);
  const peer = owner.forIdentity({ id: 13, group: 10, groups: [10] }, '');
  return { raw, owner, peer, grant };
}
test('the Rust VFS ACL checks apply to the root, each file and retained handles', async () => {
  const { owner, peer, grant } = await fixture();
  await assert.rejects(peer.read(grant, 'text', 0, 8), { errno: 'EACCES' });
  await owner.policy(grant, '', 'setxattr', attr(acl({ 13: 5 })));
  await assert.rejects(peer.read(grant, 'text', 0, 8), { errno: 'EACCES' });
  await owner.policy(grant, 'text', 'setxattr', attr(acl({ 13: 4 }, 4)));
  const held = await peer.hold(grant, 'text');
  assert.equal(new TextDecoder().decode(await peer.read(grant, held, 0, 8)), 'private');
  assert.equal((await peer.stat(grant, held)).vfs.uid, 12);
  await owner.policy(grant, 'text', 'chmod', { mode: 0o700 });
  await assert.rejects(peer.read(grant, held, 0, 8), { errno: 'EACCES' });
  await peer.release(grant, held);
  await assert.rejects(peer.policy(grant, '', 'chmod', { mode: 0o777 }), { errno: 'EPERM' });
});
test('ACL masks, supplementary groups and source ceilings remain authoritative', async () => {
  const { owner, grant } = await fixture();
  const peer = owner.forIdentity({ id: 13, group: 10, groups: [9, 10] }, '');
  for (const path of ['', 'text']) await owner.policy(grant, path, 'setxattr', attr(acl({}, 5, 5)));
  assert.equal(new TextDecoder().decode(await peer.read(grant, 'text', 0, 8)), 'private');
  await assert.rejects(peer.write(grant, 'text', encoder.encode('no')), { errno: 'EROFS' });
  await assert.rejects(peer.access(grant, 'text', 2), { errno: 'EROFS' });
  await owner.policy(grant, 'text', 'setxattr', attr(acl({ 13: 0 }, 5, 5, 5)));
  // A named-user denial takes precedence over membership in an allowed group.
  await assert.rejects(peer.read(grant, 'text', 0, 8), { errno: 'EACCES' });
});
test('an already pinned executable loses authorization after a policy change', async () => {
  const { owner, peer, grant } = await fixture();
  for (const path of ['', 'tool']) await owner.policy(grant, path, 'setxattr', attr(acl({ 13: 5 })));
  const pin = await peer.pin(grant, 'tool'); assert.equal((await localImage(pin)).bytes.length, 8);
  await owner.policy(grant, 'tool', 'chmod', { mode: 0o700 });
  await assert.rejects(localImage(pin), { errno: 'ESTALE' });
});
test('a narrowed export cannot walk its parent even when that parent is readable', async () => {
  const { owner, grant } = await fixture();
  const scoped = owner.forIdentity({ id: 12, group: 9, groups: [9] }, 'folder');
  await assert.rejects(scoped.read(grant, 'text', 0, 4), { errno: 'EACCES' });
  await assert.rejects(scoped.read(grant, 'folder/../text', 0, 4), { errno: 'EACCES' });
});
