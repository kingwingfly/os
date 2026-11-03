import { test, expect, request as playwrightRequest } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { api, call, entry, errno, mkdirp, program, put, rmrf, sys } from './sys.js';
const origin = process.env.TERMINAL_TEST_URL || 'http://127.0.0.1:8787';
const rootPassword = (await readFile('.dev.vars', 'utf8')).match(/^ADMIN_PASSWORD=(.+)$/m)[1];
const password = 'testing-long-passphrase-8274';
const file = path => '/api/file?path=' + encodeURIComponent(path);
let sequence = 0;
async function client() { return playwrightRequest.newContext({ baseURL: origin, extraHTTPHeaders: { Origin: origin, 'CF-Connecting-IP': 'acl-test-' + Date.now() + '-' + (++sequence) } }); }
async function command(client, args, extra = {}) { return program(client, args, extra); }
async function ok(response, status = 200) { expect(response.status(), await response.text()).toBe(status); return response; }
async function login(client, username, secret = password) { return ok(await api(client, 'login', { data: { username, password: secret } })); }
async function setup() {
 const root = await client(), alice = await client(), bob = await client(), guest = await client();
 await login(root, 'root', rootPassword);
 const suffix = Date.now().toString(36), a = 'alice' + suffix, b = 'bob' + suffix, team = 'team' + suffix;
 await ok(await command(root, ['groupadd', team]));
 for (const name of [a,b]) {
  await ok(await command(root, ['useradd', '-m', '-G', team, name]));
  await ok(await api(root, 'passwd', { data: { username: name, password } }));
 }
 await login(alice,a); await login(bob,b);
 return { root, alice, bob, guest, a, b, team, home: '/home/' + a, async cleanup() {
  for (const name of [a,b]) await command(root,['userdel','-r',name]);
  for (const name of [a,b,team]) await command(root,['groupdel',name]);
  for (const context of [root,alice,bob,guest]) await context.dispose();
 } };
}

test('owner/group/other, traversal, ranges, revocation and root bypass are enforced by the API', async () => {
 const f = await setup(); const {root,alice,bob,guest,a,team,home} = f; const path=home+'/private.txt';
 try {
  await ok(await put(alice, file(path),{data:'0123456789'}),201);
  for (const client of [bob,guest]) for (const method of ['get','head']) expect((await client[method](file(path))).status()).toBe(client===guest?401:403);
  await ok(await command(alice,['chmod','750',home]));
  // A user's private group is different from their supplementary sharing group.
  expect((await bob.get(file(path))).status()).toBe(403);
  await ok(await command(alice,['chown',':'+team,home]));
  await ok(await command(alice,['chown',':'+team,path]));
  await ok(await command(alice,['chmod','640',path]));
  const shared=await ok(await bob.get(file(path))); expect(await shared.text()).toBe('0123456789');
  const etag=shared.headers().etag;
  const range=await ok(await bob.get(file(path),{headers:{Range:'bytes=2-4'}}),206);expect(await range.text()).toBe('234');
  await ok(await command(alice,['chmod','g-r',path]));
  for (const headers of [{Range:'bytes=2-4'},{'If-None-Match':etag}]) expect((await bob.get(file(path),{headers})).status()).toBe(403);
  expect((await bob.head(file(path))).status()).toBe(403);
  await ok(await command(alice,['chmod','604',path]));
  // Group membership chooses group bits even when the other bits permit reading.
  expect((await bob.get(file(path))).status()).toBe(403);
  expect((await command(bob,['chmod','777',path])).status()).toBe(403);
  expect((await command(alice,['chown','root:root',path])).status()).toBe(403);
  await ok(await command(alice,['chmod','711',home]));
  await ok(await guest.get(file(path))); expect(await errno(guest, { getdents: { path: home } })).toBe('EACCES');
  await ok(await command(alice,['chmod','000',home]));
  await ok(await root.get(file(path))); await ok(await command(root,['chmod','700',home]));
  expect((await alice.get(file('/home/../root/secret.txt'))).status()).toBe(403);
  expect((await alice.post('/api/sys',{headers:{Origin:'https://evil.invalid'},data:{calls:[{chmod:{path:home,mode:0o777}}]}})).status()).toBe(403);
  expect(shared.headers()['cache-control']).toContain('no-store');
 } finally { await f.cleanup(); }
});

test('sudo verifies the caller, stays per-command, revokes membership immediately; home moves and passwords invalidate old access', async () => {
 const f=await setup();const {root,alice,bob,guest,a,b,home}=f;
 try {
  expect((await api(guest, 'sudo',{data:{password:rootPassword}})).status()).toBe(401);
  expect((await api(guest, 'login',{data:{username:'root',sudo:true,password:rootPassword}})).status()).toBe(401);
  expect((await api(alice, 'login',{data:{username:'root',sudo:true,password:rootPassword}})).status()).toBe(403);
  expect((await command(alice,['useradd','intruder'],{sudo:true})).status()).toBe(403);
  expect((await api(alice, 'sudo',{data:{password:rootPassword}})).status()).toBe(403);
  await ok(await command(root,['usermod','-aG','wheel',a]));
  expect((await command(alice,['users'],{sudo:true})).status()).toBe(403);
  expect((await api(alice, 'sudo',{data:{password:'incorrect-password'}})).status()).toBe(401);
  await ok(await api(alice, 'sudo',{data:{password}}));
  const originalCookie=(await alice.storageState()).cookies.find(c=>c.name==='terminal_session').value;
  await ok(await command(alice,['users'],{sudo:true}));
  expect((await (await api(alice, 'session')).json()).username).toBe(a);
  expect((await alice.storageState()).cookies.find(c=>c.name==='terminal_session').value).toBe(originalCookie);
  expect(await errno(alice, { getdents: { path: '/root' } })).toBe('EACCES');
  await ok(await api(alice, 'sudo',{data:{revoke:true}}));
  expect((await command(alice,['users'],{sudo:true})).status()).toBe(403);
  await ok(await api(alice, 'sudo',{data:{password}}));
  await ok(await command(root,['usermod','-G',f.team,a]));
  expect((await command(alice,['users'],{sudo:true})).status()).toBe(403);
  await ok(await put(alice, file(home+'/kept.txt'),{data:'preserve bytes'}),201);
  await ok(await command(alice,['chmod','600',home+'/kept.txt']));
  const next='/home/moved-'+a;
  await ok(await command(root,['usermod','-d',next,'-m',a]));
  expect((await alice.get(file(home+'/kept.txt'))).status()).toBe(404);
  expect(await (await ok(await alice.get(file(next+'/kept.txt')))).text()).toBe('preserve bytes');
  const metadata=await entry(alice, next+'/kept.txt');expect(metadata.mode).toBe(0o600);expect(metadata.owner).toBe(a);
  expect((await command(root,['usermod','-d',next+'/inside','-m',a])).status()).toBe(400);
  await ok(await command(root,['usermod','-L',a]));
  expect((await alice.get(file(next+'/kept.txt'))).status()).toBe(401);
  expect((await api(guest, 'login',{data:{username:a,password}})).status()).toBe(401);
  await ok(await command(root,['usermod','-U',a]));await login(alice,a);
  await ok(await api(root, 'passwd',{data:{username:a,password:password+'new'}}));
  expect((await alice.get(file(next+'/kept.txt'))).status()).toBe(401);
  expect((await api(guest, 'login',{data:{username:a,password}})).status()).toBe(401);
  await login(alice,a,password+'new');
  const oldCookie=(await alice.storageState()).cookies.find(c=>c.name==='terminal_session').value;
  await ok(await api(alice, 'logout'));
  expect((await guest.get(file(next+'/kept.txt'),{headers:{Cookie:'terminal_session='+oldCookie}})).status()).toBe(401);
  // Failed account creation is atomic, including automatic private-group allocation.
  expect((await command(root,['useradd','-m','-d',next,b+'bad'])).status()).toBe(400);
  await ok(await command(root,['groupadd',b+'bad']));await ok(await command(root,['groupdel',b+'bad']));
  expect((await command(root,['userdel','root'])).status()).toBe(400);
 } finally {await f.cleanup();}
});

test('public directory write, file overwrite, recursive deletion, concurrent updates and group renames', async () => {
 const f=await setup();const {root,alice,bob,guest,a,b,home,team}=f;const shared='/shared-'+a;
 try {
  await ok(await command(root,['mkdir',shared]));await ok(await command(root,['chmod','o+wx',shared]));
  await ok(await put(guest, file(shared+'/guest.txt'),{data:'guest data'}),201);
  expect(await errno(guest, { unlink: { path: shared+'/guest.txt' } })).toBe(null);
  await ok(await command(root,['chmod','755',shared]));expect((await put(guest, file(shared+'/denied.txt'),{data:'x'})).status()).toBe(401);
  await ok(await command(root,['chown',a+':'+team,shared]));await ok(await command(root,['chmod','770',shared]));
  await ok(await put(alice, file(shared+'/locked.txt'),{data:'old'}),201);await ok(await command(alice,['chmod','444',shared+'/locked.txt']));
  expect((await put(alice, file(shared+'/locked.txt')+'&overwrite=true',{data:'new'})).status()).toBe(403);
  // Deletion is controlled by the parent, not by the file's write bits.
  expect(await errno(bob, { unlink: { path: shared+'/locked.txt' } })).toBe(null);
  await mkdirp(alice, shared+'/private');await ok(await command(alice,['chmod','700',shared+'/private']));
  // rm -r takes what it may, as on Linux: what alice's private directory holds, it may not.
  expect(await rmrf(bob, shared)).toBe('EACCES');
  await ok(await put(alice, file(shared+'/private/keep.txt'),{data:'intact'}),201);
  await Promise.all([ok(await command(root,['usermod','-aG','wheel',a])),ok(await command(root,['chmod','750',shared]))]);
  const results=await Promise.all([command(root,['groupadd',team+'one']),command(root,['groupadd',team+'two'])]);for(const result of results)await ok(result);
  await ok(await command(root,['groupmod','-n',team+'new',team]));
  expect((await entry(root, shared)).group).toBe(team+'new');
  await ok(await command(root,['groupdel',team+'new']));await ok(await command(root,['groupadd',team]));
  for(const name of [team+'one',team+'two'])await ok(await command(root,['groupdel',name]));
  expect((await command(root,['groupdel',a])).status()).toBe(400);
 } finally {await command(root,['rm','-r',shared]);await f.cleanup();}
});

test('a file is written only while its account may still write where it is', async () => {
 const f=await setup();const {root,alice,a}=f;const dir='/upload-'+a;
 const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
 // A descriptor of a new file of four bytes; each write and the close ask again.
 const begin=async path=>(await call(alice,{open:{path,flags:0o101,mode:0o666,size:4}})).fd;
 const chunk=(fd,text)=>alice.put(`/api/pwrite?fd=${fd}&index=0`,{headers:{'X-Chunk-SHA256':sha(Buffer.from(text)),'Content-Type':'application/octet-stream'},data:Buffer.from(text)});
 const complete=async fd=>(await sys(alice,[{close:{fd}}]))[0];
 try {
  await ok(await command(root,['mkdir',dir]));await ok(await command(root,['chown',a,dir]));
  // Shut out of the directory, the writer may not write the file.
  const revoked=await begin(dir+'/a.txt');
  await ok(await command(root,['chown','root',dir]));await ok(await command(root,['chmod','700',dir]));
  expect(await errno(alice, { stat: { path: dir+'/a.txt' } })).toBe('EACCES');
  const shut=await chunk(revoked,'abcd');
  expect([shut.status(),(await shut.json()).errno]).toEqual([403,'EACCES']);
  // Let back in, the file being still hers, it goes on.
  await ok(await command(root,['chmod','755',dir]));
  await ok(await chunk(revoked,'abcd'));expect((await complete(revoked)).ok).toMatchObject({path:dir+'/a.txt',created:true});
  expect(await (await root.get(file(dir+'/a.txt'))).text()).toBe('abcd');
  // Moved while it is written, a new file is written, and complete, where it is now.
  await ok(await command(root,['chown',a,dir]));
  const moved=await begin(dir+'/b.txt');
  await ok(await command(alice,['mv',dir+'/b.txt',dir+'/c.txt']));
  await ok(await chunk(moved,'wxyz'));
  expect((await complete(moved)).ok.path).toBe(dir+'/c.txt');
  expect(await (await alice.get(file(dir+'/c.txt'))).text()).toBe('wxyz');
  // Given to an account that alone may write it, it is the writer's no more.
  const given=await begin(dir+'/d.txt');
  await ok(await command(root,['chown','root',dir+'/d.txt']));
  expect((await chunk(given,'1234')).status()).toBe(403);
  expect((await complete(given)).err.errno).toBe('EACCES');
 } finally {await command(root,['rm','-r',dir]);await f.cleanup();}
});

test('cp and mv tell nothing of a destination below a directory the caller may not search', async () => {
 const f=await setup();const {root,alice,home}=f;
 try {
  await ok(await command(root,['mkdir','/root/acl-hidden-'+f.a]));
  for (const name of ['one.txt','two.txt']) await ok(await put(alice, file(home+'/'+name),{data:name}),201);
  // What they look at and make there is refused alike, whether it is there or not: the kernel
  // says only EACCES, which is all user space's cp and mv can say.
  for (const dest of ['/root/acl-hidden-'+f.a,'/root/acl-missing-'+f.a]) {
   expect(await errno(alice, { stat: { path: dest } }),dest).toBe('EACCES');
   expect(await errno(alice, { open: { path: dest+'/one.txt', flags: 0o301, size: 3 } }),dest).toBe('EACCES');
   const reply=await command(alice,['mv',home+'/one.txt',home+'/two.txt',dest]);
   expect([reply.status(),(await reply.json()).errno],dest).toEqual([403,'EACCES']);
  }
  // Nor below one deep in a merge: a file there is as hidden as one that is not.
  const dst='/acl-merge-'+f.a,hidden=dst+'/src/private';
  await ok(await command(root,['mkdir','-p',hidden]));await ok(await command(root,['chmod','777',dst,dst+'/src']));await ok(await command(root,['chmod','700',hidden]));
  for (const leaf of [true,false]) {
   if (leaf) await ok(await put(root, file(hidden+'/probe.txt'),{data:'kept'}),201); else expect(await errno(root, { unlink: { path: hidden+'/probe.txt' } })).toBe(null);
   expect(await errno(alice, { lstat: { path: hidden+'/probe.txt' } }),String(leaf)).toBe('EACCES');
  }
  await command(root,['rm','-r',dst]);
 } finally {await command(root,['rm','-r','/root/acl-hidden-'+f.a]);await f.cleanup();}
});

test('groupmod and groupdel take a group by its name, as on Linux, never by number', async () => {
 const f=await setup();const {root,team}=f;
 try {
  // A system group's number is no way around its protection.
  for (const [gid,name] of [['0','root'],['27','wheel']]) {
   expect((await command(root,['groupmod','-n','renamed-'+team,gid])).status()).toBe(404);
   expect((await command(root,['groupdel',gid])).status()).toBe(404);
   // Still there, by its name.
   expect((await command(root,['groupadd',name])).status()).toBe(409);
  }
  const groups=(await (await command(root,['id',f.a])).json()).output;
  const gid=groups.match(new RegExp('(\\d+)\\('+team+'\\)'))[1];
  const reply=await command(root,['groupdel',gid]);
  expect(reply.status()).toBe(404);expect((await reply.json()).error).toBe('Group does not exist: '+gid);
  expect((await (await command(root,['id',f.a])).json()).output).toContain(`${gid}(${team})`);
 } finally {await f.cleanup();}
});

test('terminal account workflow uses password dialogs, su homes and a caller-authenticated sudo prompt', async ({ page }) => {
 const root = await client(); await login(root,'root',rootPassword);
 const username='ui'+Date.now().toString(36), home='/home/'+username;
 const run=async text=>{const input=page.getByRole('combobox',{name:'Terminal command'});await expect(page.locator('.busy')).toHaveText('↵');await input.fill(text);await input.press('Enter');};
 const last=()=>page.locator('.transcript pre').last();
 await page.setExtraHTTPHeaders({'CF-Connecting-IP':'ui-acl-'+Date.now()});
 try {
  await page.goto('/');await run('su root');
  await expect(page.locator('#auth')).toBeVisible();await page.getByLabel('Password',{exact:true}).fill(rootPassword);await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('.lock')).toContainText('root');
  await run('useradd -m -G wheel '+username);await expect(last()).toContainText('Created user');
  await run('passwd '+username);await page.getByLabel('New password',{exact:true}).fill(password);await page.getByLabel('Confirm new password',{exact:true}).fill(password);await page.locator('#auth button[type=submit]').click();await expect(last()).toContainText('Password updated');
  await run('su - '+username);await expect(page.locator('label[for=command] .prompt-path')).toContainText(home);await expect(page.locator('.lock')).toContainText(username);
  await run('pwd');await expect(last()).toHaveText(home);
  // Silent on success, as GNU's are; ls -l shows what they did.
  await run('mkdir secrets');await run('chmod 700 secrets');
  await run('ls -l');await expect(last()).toContainText('drwx------');await expect(last()).toContainText(username);
  await run('sudo ls -l /root');await expect(page.locator('#auth-title')).toContainText('sudo');await page.getByLabel('Password',{exact:true}).fill(password);await page.locator('#auth button[type=submit]').click();await expect(page.locator('.busy')).toHaveText('↵');
  await run('whoami');await expect(last()).toHaveText(username);
  await run('cd /root');await expect(last()).toContainText('Permission denied');
  await run('sudo -k');await expect(last()).toContainText('revoked');
  await run('sudo -u root');
  await expect(page.locator('#auth-title')).toContainText('sudo');
  await page.getByLabel('Password',{exact:true}).fill(password);await page.locator('#auth button[type=submit]').click();
  await expect(page.locator('.lock')).toContainText('root');await expect(page.locator('label[for=command] .prompt-path')).toContainText('/root');
  await run('whoami');await expect(last()).toHaveText('root');
  await run('exit');await expect(page.locator('.lock')).toContainText('guest');await expect(page.locator('label[for=command] .prompt-path')).not.toContainText(home);
  expect(await page.locator('.transcript').innerText()).not.toContain(password);
  // Login as a non-root user through the same modal; su - selects their home.
  await run('su - '+username);await page.getByLabel('Password',{exact:true}).fill(password);await page.locator('#auth button[type=submit]').click();await expect(page.locator('label[for=command] .prompt-path')).toContainText(home);
  await run('cd ~');await expect(page.locator('label[for=command] .prompt-path')).toContainText(home);
  await run('exit');await expect(page.locator('.lock')).toContainText('guest');
  await run('sudo users');await expect(last()).toContainText('guest cannot use sudo');
  await expect(page.locator('#auth')).not.toBeVisible();
 } finally {await command(root,['userdel','-r',username]);await command(root,['groupdel',username]);await root.dispose();}
});

test('sudo account switching checks live membership, replaces sessions and clears cached elevation', async () => {
 const f=await setup();const {root,alice,guest,a,b}=f;
 try {
  await ok(await command(root,['usermod','-aG','wheel',a]));
  expect((await api(alice, 'login',{data:{username:b,sudo:true}})).status()).toBe(403);
  await ok(await api(alice, 'sudo',{data:{password}}));
  await ok(await command(root,['usermod','-L',b]));
  expect((await api(alice, 'login',{data:{username:b,sudo:true}})).status()).toBeGreaterThanOrEqual(400);
  expect((await (await api(alice, 'session')).json()).username).toBe(a);
  await ok(await command(root,['usermod','-U',b]));
  const cookie=(await alice.storageState()).cookies.find(c=>c.name==='terminal_session').value;
  await ok(await api(alice, 'login',{data:{username:b,sudo:true}}));
  const current=await (await api(alice, 'session')).json();
  expect(current.username).toBe(b);expect(current.sudo_active).toBe(false);
  expect((await (await api(guest, 'session',{headers:{Cookie:'terminal_session='+cookie}})).json()).username).toBe('guest');
  expect((await api(alice, 'login',{data:{username:'root',sudo:true}})).status()).toBe(403);
  await login(alice,a);await ok(await api(alice, 'sudo',{data:{password}}));
  await ok(await command(root,['usermod','-G',f.team,a]));
  expect((await api(alice, 'login',{data:{username:'root',sudo:true}})).status()).toBe(403);
 } finally {await f.cleanup();}
});
