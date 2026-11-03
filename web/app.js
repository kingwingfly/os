import { inspectFaststart } from './faststart.mjs';
import { uploadFile, Cancelled } from './upload.mjs';
import { record, clock } from './record.mjs';
import { speak, listen as hearLive } from './sound.mjs';
import * as dev from './dev.mjs';
import { exec } from './wasi/exec.mjs';
import { answered as resultOf, call, sys } from './http.mjs';

let configuration;
export const ready = fetch('/terminal-config.json').then(async response => {
  if (!response.ok) throw new Error('Cannot read terminal configuration');
  configuration = await response.json();
  document.title = configuration.branding.name + configuration.branding.subtitle;
  document.querySelector('meta[name="description"]').content = configuration.branding.description;
});

const $ = id => document.getElementById(id);
const fileUrl = path => '/api/file?path=' + encodeURIComponent(path);
// Previews render in Rust (crates/frontend/src/viewer.rs), through window.terminalPreview.
let directory = '/', opener, viewerVersion = 0, releasePreview;
// Lists and the account may have changed: the tabs ask again. With a reason, the account changed
// from elsewhere, which the tabs say: 'ended', this session ended; 'window', another window
// of this browser signed in or out.
const changed = (reason = null) => window.dispatchEvent(new CustomEvent('terminal:changed', { detail: reason }));
async function api(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) { let error; try { error = (await response.json()).error; } catch {} const failure = new Error(error || `Request failed (${response.status})`); failure.status = response.status; throw failure; }
  return response;
}
// Who this session is (getcreds), and whether it may write in the directory `path` (access).
async function session(path = directory) {
  const [creds, writable] = await sys(['getcreds', { access: { path, mode: 3 } }]);
  const who = resultOf(creds);
  return { authenticated: who.signed_in, writable: who.signed_in, username: who.user, uid: who.uid, group: who.group,
    groups: who.group_names, home: who.home, can_sudo: who.can_sudo, sudo_active: who.sudo_active, can_write: 'ok' in writable };
}
// The account calls that change this browser's session. The session one replaces ends as it
// answers, which this page hears of before its own identityChanged: until then, that is not
// news.
const SESSION_CHANGES = new Set(['login', 'logout', 'passwd', 'register', 'unregister']);
let changingSession = 0;
async function post(endpoint, data) {
  const changes = SESSION_CHANGES.has(endpoint);
  if (changes) changingSession++;
  try { return await postJson(endpoint, data); } catch (error) { if (changes) changingSession--; throw error; }
}
// The account system calls, as the dialogs below ask them (crates/worker/src/sys.rs).
async function postJson(endpoint, data) {
  switch (endpoint) {
    case 'login': return call('login', { username: data.username ?? 'root', password: data.password ?? '' }, { sudo: !!data.sudo });
    case 'logout': return call('logout');
    case 'sudo': return call('sudo', { password: data.password ?? '', revoke: !!data.revoke });
    case 'passwd': return call('passwd', { username: data.username ?? null, password: data.password ?? '', current_password: data.current_password ?? null, force: !!data.force }, { sudo: !!data.sudo });
    case 'register': return call('useradd', { name: data.username, password: data.password ?? '', short_password: !!data.short_password, create_home: !!data.create_home });
    case 'unregister': return call('userdel', { name: (await call('getcreds')).user, remove: !!data.remove, password: data.password ?? '' });
  }
  throw new Error('no such account call: ' + endpoint);
}
// One dialog at a time: a request made while another is open, as from another tab, waits for it
// to close and then asks its own question, rather than receiving the other's answer.
let dialogs = Promise.resolve();
function credentials(options) {
  const answer = dialogs.then(() => askCredentials(options));
  dialogs = answer.catch(() => {});
  return answer;
}
function askCredentials({ title, description, username, chooseUser = false, newPassword = false, currentPassword = false, action, submit }) {
  return new Promise(resolve => {
    const dialog = $('auth'), form = $('auth-form'), password = $('password'), user = $('username');
    $('auth-title').textContent = title; $('auth-description').textContent = description; $('auth-error').textContent = '';
    $('username-field').hidden = !chooseUser; user.value = username || 'root'; user.required = chooseUser;
    $('current-password-field').hidden = !currentPassword; $('current-password').required = currentPassword;
    $('confirm-password-field').hidden = !newPassword; $('confirm-password').required = newPassword;
    $('password-label').textContent = newPassword ? 'New password' : 'Password';
    password.autocomplete = newPassword ? 'new-password' : 'current-password';
    for (const id of ['password', 'current-password', 'confirm-password']) $(id).value = '';
    const button = form.querySelector('[type=submit]'); button.textContent = action || (newPassword ? 'Save password' : 'Confirm'); button.disabled = false;
    let completed = false;
    const finish = result => {
      if (completed) return; completed = true;
      for (const id of ['password', 'current-password', 'confirm-password']) $(id).value = '';
      dialog.close(); form.onsubmit = null; dialog.oncancel = null; $('cancel-auth').onclick = null;
      resolve(result);
    };
    form.onsubmit = async event => {
      event.preventDefault(); button.disabled = true;
      try {
        if (newPassword && password.value !== $('confirm-password').value) throw new Error('New passwords do not match');
        const result = await submit({ username: user.value.trim(), password: password.value, current_password: $('current-password').value });
        finish(result);
      } catch (error) { $('auth-error').textContent = error.message; }
      finally { for (const id of ['password', 'current-password', 'confirm-password']) $(id).value = ''; button.disabled = false; }
    };
    dialog.oncancel = event => { event.preventDefault(); if (!button.disabled) finish(null); };
    $('cancel-auth').onclick = () => { if (!button.disabled) finish(null); };
    dialog.showModal(); (currentPassword ? $('current-password') : password).focus();
  });
}
// What others change, as it happens: the kernel tells this page what changed in the directories
// its session watches (inotify, the watches its Rust side makes as it lists them; crates/frontend
// sys.rs), which forget what they knew of them at once, and the tabs that show one list it again,
// a burst of changes as one. Pings keep proxies and tunnels from closing a quiet line; a line that
// drops opens again, and what was missed meanwhile is listed again.
let events, eventsRetry = 0, pendingTimer;
function listen() {
  events?.close();
  const socket = events = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/events`);
  let ping;
  socket.onopen = () => {
    const reconnected = eventsRetry > 0;
    if (eventsRetry) changed(); eventsRetry = 0; ping = setInterval(() => socket.send('ping'), 30000);
    // A new line follows what the page follows (and hears where it is), and asks what it waited
    // to ask.
    if (following || hearing) socket.send(JSON.stringify({ follow: followed() }));
    // A deck shown here asks where its account is now, as turns made elsewhere while the line
    // was down were not heard; unless it turned itself meanwhile, which goes out below.
    const turned = outbox.some(message => message.present?.path === shown?.path);
    if (reconnected && shown && !following && !turned) outbox.push({ where: shown.path });
    for (const message of outbox.splice(0)) socket.send(JSON.stringify(message));
  };
  socket.onmessage = event => {
    // A line this page replaced, as its account changed, has nothing more to say.
    if (events !== socket) return;
    let message; try { message = JSON.parse(event.data); } catch { return; }
    // This page's session ended elsewhere, not by its own sign in or out: it is a guest's now.
    if (message.session === 'ended') { if (!changingSession) void identityChanged('ended'); return; }
    if (message.present) { presented(message.present); return; }
    // A live sound, or a listener's voice, started in a presentation this page follows or
    // presents; listeners asking to speak, and the answers to this page's ask.
    if (message.sound) { soundStarted(message.sound); return; }
    if (message.asking) { asksChanged(message.asking); return; }
    if (message.asked || message.granted || message.denied) { answered(message); return; }
    // A device followed shows something else now: followed again, if it still may be.
    if (message.device?.replaced) { followAgain(message.device.name, true, true); return; }
    // What a device followed is, as the authority says on following it: one replaced while this
    // page's line was down (another file, account or sound) is not what the page shows.
    if (message.followed) {
      const { name, version } = message.followed;
      followAgain(name, following?.device === name && following.version !== version, hearing?.device === name && hearing.version !== version);
      return;
    }
    // The presentation followed ended, or may not be followed; a sound heard ended; or a device
    // of this page's account ended, which its bar shows, or this page sends (rm /dev/snd/NAME).
    if (message.device) {
      const { name, version } = message.device;
      if (following?.device === name) following.ended = true;
      if (hearing?.device === name) stopHearing();
      if (voices.has(name)) stopVoice(name);
      if (message.device.ended) deviceEnded(name, version);
      window.dispatchEvent(new CustomEvent('terminal:device', { detail: message.device }));
      return;
    }
    if (!Array.isArray(message.inotify)) return;
    window.dispatchEvent(new CustomEvent('terminal:inotify', { detail: message.inotify }));
    clearTimeout(pendingTimer);
    pendingTimer = setTimeout(() => window.dispatchEvent(new CustomEvent('terminal-remote')), 250);
  };
  socket.onclose = () => { clearInterval(ping); if (events === socket) setTimeout(listen, Math.min(30000, 1000 * 2 ** eventsRetry++)); };
}
// The line opens once the browser has its session, signed out too (its terminal_guest cookie,
// which the first request is given): a driver's news to it is for that session.
sys(['getcreds']).catch(() => {}).finally(listen);
// Slides and PDFs presented follow each other (owner's request, 2026-10-28): the place a page
// presents (viewer.rs calls present) shows in this browser's other windows showing that file,
// and in the account's pages signed in elsewhere, which the authority tells (store.rs relay).
const presenting = 'BroadcastChannel' in window ? new BroadcastChannel('terminal-present') : null;
// The last place this page heard of or showed, by path, which a deck shown later starts at
// (viewer.rs follow_presenting): one may come while its file is still being read.
const heard = new Map();
const presented = detail => { heard.set(detail.path, detail.at); window.dispatchEvent(new CustomEvent('terminal:present', { detail })); };
if (presenting) presenting.onmessage = event => presented(event.data);
function present(path, column, row) {
  const place = { path, at: [column, row] };
  heard.set(path, place.at);
  presenting?.postMessage(place);
  // While the line is down, only the last place of each file waits for it.
  const waiting = outbox.findIndex(message => message.present?.path === path);
  if (waiting >= 0) outbox.splice(waiting, 1);
  say({ present: place });
}
// Said once the line is open, if it is not yet: what this page asks, as it opens a deck.
const outbox = [];
function say(message) { if (events?.readyState === WebSocket.OPEN) events.send(JSON.stringify(message)); else outbox.push(message); }
// Where the account last showed the file at `path`, on any device, which the authority answers
// with a present message; a page opens a deck there (viewer.rs).
function ask(path) { say({ where: path }); }
// The presentation this page follows (devices.rs), as /api/device described it: /dev/present/NAME,
// the file it shows, whose it is, and whether this page's account turns it.
let following = null;
// Each attend, and each unfollow, starts anew: an answer for an older one is not applied, as the
// page has left the presentation, or gone to another, meanwhile.
let followings = 0;
// The devices this page follows, which the authority tells it the end of: a presentation, its
// sound and voices, and the voice this page sends.
const followed = () => [following?.device, hearing?.device, ...voices.keys(), speaking?.device].filter(Boolean);
const follows = () => say({ follow: followed() });
async function attend(device) {
  const turn = ++followings;
  // An answer, or a failure, for an attend the page has left since says nothing.
  let info;
  try { info = await dev.attend(device); }
  catch (error) { if (turn === followings) throw error; return; }
  if (turn !== followings) return;
  if (following?.device !== info.device) declined = null;
  following = info; follows();
  // Slides and sound together: the presenter's live sound, and the listeners speaking.
  if (info.sound && hearing?.device !== info.sound && declined !== info.device) hear(info.sound).catch(error => console.warn('No live sound', error));
  for (const voice of info.voices ?? []) if (voice.ask !== bar.asking?.id) void hearVoice(voice);
  // Shown as the presenter shows it, from where they are.
  if (info.kind === 'pdf') setPlace(info.path, { present: true, ...(info.place ? { page: info.place[0] } : {}) });
  else setPlace(info.path, { slides: true, ...(info.place ? { slide: info.place } : {}) });
  return open(info.path, info.kind, false, true);
}
function unfollow() {
  followings++;
  if (!following) return;
  // Leaving the presentation withdraws an ask to speak, and ends the voice sent.
  if (bar.asking) { if (bar.asking.state === 'asking') void dev.ask(bar.asking.presentation, true).catch(() => {}); void stopSpeaking(); }
  following = null; follows();
}
// Follow the device `name` again, as it shows something else now: the presentation followed, the
// sound heard, or both; if that may no longer be, the page says so.
function followAgain(name, presentation, sound) {
  const again = error => window.dispatchEvent(new CustomEvent('terminal:device', { detail: { name, error: error.message } }));
  if (presentation && following?.device === name) attend(name).catch(again);
  if (sound && hearing?.device === name) hear(name).catch(again);
}
// A speaker view, which a deck's S opened (viewer.rs): it shows the deck its address names once
// the terminal runs.
export function started() {
  const files = $('window-files');
  if (files) new ResizeObserver(measureNames).observe(files);
  const deck = new URLSearchParams(location.search).get('speaker');
  if (!deck) return;
  document.title = 'Speaker view · ' + deck.split('/').pop();
  void open(deck, /\.slides\.md$/i.test(deck) ? 'slides' : 'markdown');
}
// Windows of this browser share its session cookie: each tells the others when it changes it,
// so that none goes on showing one account while its requests are another's.
const windows = 'BroadcastChannel' in window ? new BroadcastChannel('terminal-session') : null;
if (windows) windows.onmessage = () => void identityChanged('window');
async function identityChanged(reason = null) {
  if (!reason) changingSession = 0;
  // A new account hears of what it may list: the line opens again with its session.
  listen();
  if (!reason) windows?.postMessage('changed');
  // A private preview must not survive switching to a less privileged account.
  if ($('viewer').open) await closeViewer();
  changed(reason);
}
async function signIn(username, switching = false) {
  let result;
  if (switching && (await session()).uid === 0) result = await post('login', { username, switch: true });
  else result = await credentials({ title: switching ? `Switch to ${username}` : 'Sign in', description: 'Access is determined by the file owner, group, and rwx permissions.', username, chooseUser: !switching,
    submit: fields => post('login', { username: switching ? username : fields.username, password: fields.password, switch: switching }) });
  if (result) await identityChanged();
  return result;
}
async function unlock(path = directory) {
  const current = await session(path);
  if (current.authenticated || current.can_write) return true;
  throw new Error('Permission denied: sign in with su USER before retrying; your account will not change automatically');
}

async function sudoAuthenticate() {
  // A sudo another tab is asking for may make this one unnecessary.
  await dialogs;
  const current = await session();
  if (!current.authenticated) throw new Error('guest cannot use sudo; sign in to a wheel account with su USER first');
  if (!current.can_sudo) throw new Error('Current account is not in the wheel group');
  if (current.sudo_active) return true;
  return !!await credentials({ title: `sudo · ${current.username}`, description: 'Verify your own password. sudo authorization lasts 5 minutes; ordinary operations still use your current account.',
    submit: fields => post('sudo', { password: fields.password }) });
}
async function accountCommand(args, cwd) {
  // Help (-h, help) is the terminal's own, from the commands' definitions in Rust, as are the
  // manual's pages; this shows them.
  if (args[0] === 'man') {
    if (args.length > 2) throw new Error('Usage: man [COMMAND]');
    const text = args[1] ? window.terminalManual.page(args[1]) : window.terminalManual.index();
    if ((text === undefined || text === null) && window.terminalManual.bin(args[1])) throw new Error(`${args[1]} is /bin's (uutils): ${args[1]} --help says how to use it`);
    if (text === undefined || text === null) throw new Error(`No manual entry for ${args[1]}. Enter man for the index.`);
    const version = await cleanupViewer(); if (version !== viewerVersion) return {};
    trail.length = 0; showTrail();
    viewerTitle(args[1] ? 'man · ' + args[1] : 'Terminal Worker · Manual'); $('download').hidden = true;
    const article = document.createElement('article'); article.className = 'markdown manual'; article.innerHTML = window.terminalPreview.markdown(text, '/'); $('viewer-content').replaceChildren(article);
    if (!$('viewer').open) { opener = document.activeElement; showWindow($('viewer')); placePlayer(); }
    return {};
  }
  if (args[0] === 'vim') {
    if (args.length !== 2) throw new Error('Usage: vim <PATH>');
    let value = args[1]; const current = await session();
    if (value === '~') value = current.home; else if (value.startsWith('~/')) value = current.home + value.slice(1);
    if (/[\\\x00-\x1f]/.test(value)) throw new Error('Invalid file path');
    const parts = []; for (const part of (value.startsWith('/') ? value : cwd + '/' + value).split('/')) { if (part === '..') parts.pop(); else if (part && part !== '.') parts.push(part); }
    const { edit } = await import('./editor.mjs'); await edit('/' + parts.join('/'), { api, fileUrl, unlock, changed }); return {};
  }
  let sudo = args[0] === 'sudo';
  if (sudo) {
    args = args.slice(1);
    if (args.length === 1 && args[0] === '-k') { await post('sudo', { revoke: true }); return { output: 'sudo authorization revoked' }; }
    if (!args.length) throw new Error('Usage: sudo <COMMAND> / sudo -u USER / sudo -k');
    if (args[0] === '-u') {
      if (args.length !== 2 || args[1].startsWith('-')) throw new Error('Usage: sudo -u USER (switch accounts; exit returns to guest)');
      if (!await sudoAuthenticate()) throw new Error('sudo canceled');
      const result = await post('login', { username: args[1], sudo: true });
      await identityChanged();
      return { output: `Current account: ${result.username}`, home: result.home };
    }
    if (!await sudoAuthenticate()) throw new Error('sudo canceled');
  }
  if (args[0] === 'passwd') {
    const force = args.includes('--force');
    const rest = args.slice(1).filter(arg => arg !== '--force');
    if (rest.length > 1 || rest[0]?.startsWith('-') || args.filter(arg => arg === '--force').length > 1) throw new Error('Usage: passwd [--force] [USER]; enter the password in the dialog');
    let current = await session();
    if (!current.authenticated) throw new Error('Sign in with su USER before changing a password');
    const username = rest[0] || current.username;
    const result = await credentials({ title: `Change password for ${username}`, description: (force ? '--force enabled: short passwords are allowed, but cannot be empty. ' : 'Use at least 12 characters, or run passwd --force to allow a short password. ') + 'Saving revokes all previous sessions for this account.', newPassword: true, currentPassword: !sudo && current.uid !== 0,
      submit: fields => post('passwd', { username, password: fields.password, current_password: fields.current_password, sudo, force }) });
    if (!result) throw new Error('Password change canceled');
    await identityChanged(); return { output: `Password updated for ${username}` };
  }
  // Signed out, useradd NAME makes an account of one's own, with the password given here: its
  // home is /guest/NAME, which -m makes, and it is in group guest; other options need sudo. The
  // shell gives the options as useradd's definition spells them (shell.rs).
  if (args[0] === 'useradd' && !sudo && !(await session()).authenticated) {
    let createHome = false, shortPassword = false, username = null, operands = false;
    for (const arg of args.slice(1)) {
      if (!operands && arg === '--') operands = true;
      else if (!operands && arg === '-m') createHome = true;
      else if (!operands && arg === '-M') createHome = false;
      else if (!operands && arg === '--short-password') shortPassword = true;
      else if (!operands && arg.startsWith('-')) throw new Error(`useradd: ${arg} needs sudo; signed out, useradd [-m|-M] [--short-password] NAME makes an account of your own, home /guest/NAME, in group guest`);
      else if (username === null) username = arg;
      else throw new Error('Usage: useradd [-m|-M] [--short-password] NAME');
    }
    if (!username) throw new Error('Usage: useradd [-m|-M] [--short-password] NAME');
    const home = `/guest/${username}`;
    const result = await credentials({ title: `Create account ${username}`, description: (shortPassword ? '--short-password: short passwords are allowed, but cannot be empty. ' : 'Use at least 12 characters, or run useradd --short-password NAME to allow a short password. ') + (createHome ? `Your home will be ${home}, which only you may enter; ` : `Your home, ${home}, will not be made (useradd -m makes it); `) + 'you will be signed in.', newPassword: true, action: 'Create account',
      submit: fields => post('register', { username, password: fields.password, short_password: shortPassword, create_home: createHome }) });
    if (!result) throw new Error('Account creation canceled');
    await identityChanged();
    return result.created_home
      ? { output: `Created user ${username} and signed in; home ${result.home}`, home: result.home }
      : { output: `Created user ${username} and signed in; no home (${result.home} is not made)` };
  }
  // An account of group guest's deletes itself (userdel [-r] NAME, signed in as NAME), as its
  // password confirms; others, and root, go to the server, which takes root.
  if (args[0] === 'userdel' && !sudo) {
    const remove = args.slice(1).some(arg => arg === '-r' || arg === '--remove');
    const named = args.slice(1).filter(arg => !arg.startsWith('-'));
    const current = await session();
    if (current.authenticated && current.uid !== 0 && current.groups?.includes('guest') && named.length === 1 && named[0] === current.username) {
      const result = await credentials({ title: `Delete account ${current.username}`, description: `This deletes your account, ends its sessions and signs you out; ${remove ? `-r removes its home, ${current.home}, and everything in it` : 'its home and files stay'}. It cannot be undone.`, action: 'Delete account',
        submit: fields => post('unregister', { password: fields.password, remove }) });
      if (!result) throw new Error('Account deletion canceled');
      await identityChanged();
      return { output: `Deleted user ${result.deleted}${result.kept ? `; ${result.kept}` : ''}; signed out as guest`, home: '/' };
    }
  }
  if (['su', 'login'].includes(args[0])) {
    if (sudo) throw new Error('Use su root to switch accounts');
    const loginShell = args[0] === 'login' || args[1] === '-';
    const rest = args.slice(args[1] === '-' ? 2 : 1);
    if (rest.length > 1 || rest[0]?.startsWith('-')) throw new Error('Usage: su [-] [USER] / login [USER]');
    const result = await signIn(rest[0] || 'root', args[0] === 'su');
    if (!result) throw new Error('Sign-in canceled');
    return { output: `Current account: ${result.username}`, home: loginShell ? result.home : undefined };
  }
  if (['logout', 'exit'].includes(args[0])) {
    if (sudo || args.length !== 1) throw new Error(`Usage: ${args[0]}`);
    await post('logout', {}); await identityChanged(); return { output: 'Signed out as guest (access depends on directory permissions)', home: '/' };
  }
  // The rest are user space's programs, which the shell runs (crates/userland).
  return { program: true };
}
let uploading = null;
// Upload `files` into `path`, one after another, in chunks that resume if interrupted;
// `progress` hears how each goes. Settles with a line per file. Cancelling (cancelUploads) stops
// the batch and removes the unfinished file.
async function uploadFiles(files, path, progress) {
  if (!files.length) return [];
  if (uploading) throw new Error('An upload is already in progress in another tab; wait for it, or cancel it there');
  const controller = uploading = new AbortController();
  const results = [];
  try {
    if (!await unlock(path)) return [];
    const rust = window.terminalUploads;
    for (const file of files) {
      if (controller.signal.aborted) { results.push(`✕ ${file.name}: Upload cancelled`); continue; }
      try {
        if (file.size > rust.maxFile) throw new Error(`Exceeds the ${rust.maxFile / 1e9} GB limit`);
        // Not faststart is only a warning: such a file uploads, and plays once its index has.
        let warning = null;
        if (/\.(mp4|m4v|mov|m4a)$/i.test(file.name)) {
          progress(`↑ ${file.name} · checking faststart`);
          warning = await faststartWarning(file);
        }
        const flagged = warning ? ' · ⚠ not faststart' : '';
        const destination = (path === '/' ? '' : path.replace(/\/$/, '')) + '/' + file.name;
        const done = await uploadFile(file, destination, { signal: controller.signal,
          progress: state => { progress(`↑ ${file.name} · ${state}${flagged}`); if (!state.startsWith('hashing')) changed(); } });
        results.push(`✓ ${file.name}${done.resumed ? ' (resumed)' : ''}`);
        if (warning) results.push(`  ⚠ ${warning}`);
      } catch (error) { results.push(`✕ ${file.name}: ${error instanceof Cancelled ? 'Upload cancelled' : error.message}`); }
    }
    return results;
  } finally { uploading = null; changed(); }
}
// Why `file`, an MP4-family video or audio, will not stream, if it will not: its index (moov)
// after its media (mdat) makes players fetch the end before they start, which a file still
// uploading does not have yet. Null when it is faststart.
async function faststartWarning(file) {
  const fix = `to stream it, run faststart '${file.name.replaceAll("'", "'\\''")}' once it has uploaded`;
  try {
    if ((await inspectFaststart(file)).faststart) return null;
    return `not faststart: its index (moov) is after its media, so it plays only once the end has downloaded, and not until its upload completes; ${fix}`;
  } catch (error) {
    return `faststart could not be checked (${error.message}); if it does not play while downloading, ${fix}`;
  }
}
// Cancel the uploads in progress, if any; whether there were.
function cancelUploads() { if (!uploading) return false; uploading.abort(); return true; }
// The microphone this page records (stream FILE), into `path`, and sends live as /dev/snd/NAME
// when it may (sound.mjs); `progress` hears how it goes. Ctrl+C in its tab stops it
// (stopRecording), which saves what was recorded. Settles with what was saved.
let recording = null;
async function recordSound(path, name, acl, told) {
  if (recording) throw new Error('This page is recording already; stop it with Ctrl+C in its tab');
  const controller = recording = new AbortController();
  // The bar shows it too (viewer.rs LiveControls), and stops it.
  bar.sound = { device: null, version: null, recording: path, since: Date.now(), progress: '' }; barChanged();
  const progress = text => { if (bar.sound) { bar.sound.progress = text; barChanged(); } told(text); };
  const sending = sent => { live = sent; if (bar.sound) Object.assign(bar.sound, { device: sent.device, version: sent.version }); barChanged(); };
  let microphone, live = null, liveNote = '', speaking = Promise.resolve();
  try {
    try { microphone = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } }); }
    catch (error) { throw new Error('No microphone: ' + error.message); }
    // Live only, kept nowhere: until Ctrl+C, or the microphone ends.
    if (!path) {
      sending(await speak(name, microphone, { acl }));
      const started = performance.now(), track = microphone.getAudioTracks()[0];
      const seconds = () => (performance.now() - started) / 1000;
      const say = () => progress(`● live as ${live.device} · ${clock(seconds())}`);
      const ticking = setInterval(say, 1000); say();
      try { await new Promise(resolve => { controller.signal.addEventListener('abort', resolve, { once: true }); track.addEventListener('ended', resolve, { once: true }); }); }
      finally { clearInterval(ticking); }
      return { seconds: seconds(), device: live.device, note: track.readyState === 'ended' && !controller.signal.aborted ? ' · the microphone stopped' : '' };
    }
    const saved = await record(path, microphone, { acl, signal: controller.signal, progress: text => progress(text + liveNote),
      // Live once the file is there, which its device links to; a recording all the same if not.
      begun: () => { speaking = speak(name, microphone, { acl }).then(sent => { sending(sent); liveNote = ` · live as ${sent.device}`; }, error => { liveNote = ` · not live: ${error.message}`; }); } });
    await speaking;
    return { ...saved, device: live?.device ?? null, note: liveNote + (saved.stopped ? ` · ${saved.stopped}` : '') };
  } finally {
    recording = null; bar.sound = null; barChanged();
    microphone?.getTracks().forEach(track => track.stop());
    // A recording that failed may still be connecting its live sound, which ends with it.
    await speaking;
    await live?.end();
    changed();
  }
}
function stopRecording() { if (!recording) return false; recording.abort(); return true; }
// What this page hears live (/dev/snd/NAME), in a small player of its own, which goes on playing
// whatever the viewer shows: a sound, and the voices of the listeners let speak in the
// presentation it follows (owner's request, 2026-10-28), each in an audio element of its own.
let hearing = null;
// The sound the player shows, heard or connecting.
let tuned = null;
// Which hear() is the latest: one stopped, or replaced by another, while it connects is let go.
let hearings = 0;
// The voices heard, by device: who speaks, and what stops it.
const voices = new Map();
// The presentation whose sound this page's reader stopped, which its sound starting again does
// not bring back.
let declined = null;
let muted = false;
// A sound whose connection failed, once made, is heard again after these waits, while it may be.
const AGAIN = [1000, 2000, 5000, 10000, 20000];
async function hear(device, again = 0) {
  stopHearing(again > 0);
  const turn = ++hearings;
  tuned = device;
  // The sound plays from outside the player and the viewer, so that moving them never stops it.
  const player = $('listening'), audio = Object.assign(document.createElement('audio'), { id: 'listening-audio', autoplay: true, hidden: true, muted });
  document.body.append(audio);
  player.dataset.state = 'connecting'; showPlayer();
  // A sound, or a failure, for a hear the page has left since says nothing.
  let heard;
  const lost = () => { if (turn === hearings) hearAgain(device, 0); };
  try { heard = await hearLive(device, audio, lost); }
  catch (error) {
    if (turn !== hearings) { audio.remove(); return; }
    // Heard again, it is tried again, unless it is gone or may not be heard.
    if (again && again < AGAIN.length && !(error.status >= 400 && error.status < 500)) { audio.remove(); hearAgain(device, again); return; }
    stopHearing(); throw error;
  }
  if (turn !== hearings) { heard.stop(); audio.remove(); return; }
  hearing = { device, stop: heard.stop, version: heard.version }; player.dataset.state = 'live'; follows();
  // A browser that wants a tap to play sound shows Listen.
  try { await audio.play(); } catch { if (turn === hearings) player.dataset.state = 'paused'; }
}
function hearAgain(device, again) {
  if (again >= AGAIN.length) { stopHearing(); return; }
  const turn = hearings;
  $('listening').dataset.state = 'connecting';
  setTimeout(() => { if (turn === hearings) hear(device, again + 1).catch(error => console.warn('The sound could not be heard again', error)); }, AGAIN[again]);
}
// Stop the sound; `keep`: to hear it again at once, the player as it is.
function stopHearing(keep = false) {
  hearings++;
  hearing?.stop(); hearing = null;
  $('listening-audio')?.remove();
  if (keep) return;
  tuned = null; follows(); showPlayer();
}
async function hearVoice(voice, again = 0) {
  if (voices.has(voice.device) && !again) return;
  stopVoice(voice.device, true);
  const audio = Object.assign(document.createElement('audio'), { className: 'voice-audio', autoplay: true, hidden: true, muted });
  document.body.append(audio);
  const heard = { ...voice, audio, stop: () => {} };
  voices.set(voice.device, heard); showPlayer();
  const lost = () => { if (voices.get(voice.device) === heard && again < AGAIN.length) setTimeout(() => { if (voices.get(voice.device) === heard) void hearVoice(voice, again + 1); }, AGAIN[again]); };
  try {
    const sound = await hearLive(voice.device, audio, lost);
    if (voices.get(voice.device) !== heard) { sound.stop(); return; }
    heard.stop = sound.stop; follows();
    if (!$('listening').dataset.state || $('listening').dataset.state === 'connecting' && !tuned) $('listening').dataset.state = 'live';
    await audio.play().catch(() => { $('listening').dataset.state = 'paused'; });
  } catch (error) {
    if (voices.get(voice.device) === heard) stopVoice(voice.device);
    console.warn('No voice', error);
  }
}
function stopVoice(device, quietly = false) {
  const heard = voices.get(device);
  if (!heard) return;
  voices.delete(device); heard.stop(); heard.audio.remove();
  if (!quietly) { follows(); showPlayer(); }
}
// The player shows the sound and the voices heard, while there are any.
function showPlayer() {
  const player = $('listening'), names = [tuned, ...[...voices.values()].map(voice => `${voice.speaker} speaking`)].filter(Boolean);
  player.hidden = !names.length;
  if (!names.length) delete player.dataset.state;
  else if (!player.dataset.state) player.dataset.state = 'connecting';
  $('listening-name').textContent = names.join(' · ');
}
const audios = () => [$('listening-audio'), ...[...voices.values()].map(voice => voice.audio)].filter(Boolean);
$('listening-play').onclick = () => { Promise.all(audios().map(audio => audio.play())).then(() => { $('listening').dataset.state = 'live'; }, () => {}); };
$('listening-mute').onclick = () => { muted = !muted; for (const audio of audios()) audio.muted = muted; $('listening-mute').textContent = muted ? 'Unmute' : 'Mute'; };
// Stopped by its reader, the presentation's sound does not come back by itself.
$('listening-stop').onclick = () => { declined = following?.device ?? null; for (const device of [...voices.keys()]) stopVoice(device); stopHearing(); };

// The bar of the deck or PDF the viewer shows (viewer.rs LiveControls; owner's request,
// 2026-10-28): what this account presents of it, the sound this page sends, the listeners asking
// to speak in its presentations and speaking; and, following another's presentation, this
// page's ask to speak. It hears of each change (terminal:bar).
const bar = { path: null, user: null, presented: [], asks: [], voices: [], sound: null, asking: null, note: '' };
// The asks this page allowed, whose voices it hears.
const allowed = new Set();
let barTurns = 0, noteTimer;
function barChanged() {
  const presented = bar.presented.map(presentation => presentation.device), sound = bar.sound;
  const detail = { path: bar.path, user: bar.user, presented, note: bar.note, asking: bar.asking && { state: bar.asking.state, error: bar.asking.error ?? null },
    asks: bar.asks.filter(ask => presented.includes(ask.presentation)), voices: bar.voices.filter(voice => presented.includes(voice.presentation)),
    sound: sound && { device: sound.device, recording: sound.recording, since: sound.since, progress: sound.progress } };
  window.dispatchEvent(new CustomEvent('terminal:bar', { detail }));
}
// Say `note` in the bar a while: what failed, or what was saved.
function barNote(note) { bar.note = note; barChanged(); clearTimeout(noteTimer); noteTimer = setTimeout(() => { bar.note = ''; barChanged(); }, 8000); }
// The bar now shows the file at `path`: what this account presents of it, as the authority says.
async function barOf(path) {
  const turn = ++barTurns;
  Object.assign(bar, { path, presented: [], asks: [], voices: [], note: '' });
  barChanged();
  try {
    const presented = await dev.presented(path);
    if (turn !== barTurns) return;
    Object.assign(bar, { user: presented.user, presented: presented.devices, asks: presented.asks, voices: presented.voices });
  } catch (error) { if (turn === barTurns) bar.note = error.message; }
  barChanged();
}
// Present the file to others, as /dev/present/NAME, or stop presenting it.
async function togglePresenting(path) {
  try {
    if (bar.presented.length) {
      for (const { device } of bar.presented) await dev.stop(device);
      bar.presented = [];
    } else {
      const made = await dev.present(path);
      bar.presented = [{ device: made.device, version: made.version }];
    }
    barChanged();
  } catch (error) { barNote(error.message); }
}
// Send the microphone live, as stream does, the account's name its device's; `keep`: recorded
// too, beside the file shown, as NAME-DATE-TIME.weba. Live already, it stops.
function goLive(path, keep) {
  if (stopRecording()) return;
  const slash = path.lastIndexOf('/'), file = path.slice(slash + 1);
  const stem = file.replace(/\.slides\.md$/i, '').replace(/\.[^.]*$/, '') || file;
  const now = new Date(), two = number => String(number).padStart(2, '0');
  const stamp = `${now.getFullYear()}${two(now.getMonth() + 1)}${two(now.getDate())}-${two(now.getHours())}${two(now.getMinutes())}`;
  const destination = keep ? `${path.slice(0, slash)}/${stem}-${stamp}.weba` : null;
  recordSound(destination, null, null, () => {}).then(
    saved => { if (destination) barNote(`Saved ${destination} · ${clock(saved.seconds ?? 0)}`); },
    error => barNote(error.message));
}
// The account's device `name` ended: presented no more, or a sound this page sends stops, as
// rm /dev/snd/NAME stops stream (owner's request, 2026-10-28), unless it is another of that name.
function deviceEnded(name, version) {
  if (bar.sound?.device === name && (!version || bar.sound.version === version)) stopRecording();
  if (bar.asking?.presentation === name || speaking?.device === name) void stopSpeaking();
  bar.presented = bar.presented.filter(presentation => presentation.device !== name);
  bar.voices = bar.voices.filter(voice => voice.device !== name);
  barChanged();
}
// A live sound started: the presentation followed has its sound, unless its reader stopped it;
// a voice, which the presentation's listeners hear, and the presenter's page that allowed it.
function soundStarted(sound) {
  if ('speaker' in sound) {
    if (bar.presented.some(presentation => presentation.device === sound.presentation)) {
      bar.voices = [...bar.voices.filter(voice => voice.device !== sound.device), sound]; barChanged();
      if (allowed.has(sound.ask)) void hearVoice(sound);
    } else if (following?.device === sound.presentation && sound.ask !== bar.asking?.id) void hearVoice(sound);
    return;
  }
  if (following?.device === sound.presentation && !hearing && !tuned && declined !== following.device) hear(sound.device).catch(error => console.warn('No live sound', error));
}
// Listeners asking to speak in this account's presentations, or no longer.
function asksChanged(asking) {
  bar.asks = bar.asks.filter(ask => ask.id !== asking.id);
  if (!asking.gone && !asking.error) bar.asks.push(asking);
  if (asking.error) barNote(asking.error);
  barChanged();
  // Full screen, the bars show, to be seen by a presenter mid-talk.
  if (fullscreen()) showChrome();
}
// Ask to speak in the presentation followed; asking, withdraw; speaking, stop.
function askToSpeak() {
  const presentation = following?.device;
  if (!presentation) return;
  if (bar.asking?.state === 'asking') { void dev.ask(presentation, true).catch(() => {}); bar.asking = null; }
  else if (bar.asking && ['connecting', 'speaking'].includes(bar.asking.state)) { void stopSpeaking(); return; }
  else {
    bar.asking = { presentation, state: 'asking' };
    dev.ask(presentation).then(asked => answered({ asked }), error => answered({ asked: { presentation, error: error.message } }));
  }
  barChanged();
}
// The presenter answers an ask to speak: allowed, everyone following hears them.
function answerAsk(id, allow) {
  const asked = bar.asks.find(ask => ask.id === id);
  if (!asked) return;
  if (allow) allowed.add(id);
  dev.answer(asked.presentation, id, allow).catch(error => barNote(error.message));
  bar.asks = bar.asks.filter(ask => ask.id !== id); barChanged();
}
// End a listener's voice, as its presenter.
async function endVoice(device) {
  try { await dev.stop(device); }
  catch (error) { barNote(error.message); }
}
// What the presenter said to this page's ask: noted, allowed (with a descriptor to speak through, a guest's), or
// not now.
function answered({ asked, granted, denied }) {
  const answer = asked ?? granted ?? denied;
  if (bar.asking?.presentation !== answer.presentation) return;
  if (asked?.error) bar.asking = { ...bar.asking, state: 'error', error: asked.error };
  else if (asked) bar.asking.id = asked.id;
  else if (granted) { void startSpeaking(granted); return; }
  else { bar.asking = { ...bar.asking, state: 'denied' }; setTimeout(() => { if (bar.asking?.state === 'denied') { bar.asking = null; barChanged(); } }, 5000); }
  barChanged();
  if (fullscreen()) showChrome();
}
// The voice this page sends, allowed: what it is, what ends it, and the microphone. A guest
// speaks through the descriptor its presenter passed to its session (`granted.fd`); an
// account, through one it opens, its presenter's ACL entry letting it.
let speaking = null;
async function startSpeaking(granted) {
  bar.asking = { ...bar.asking, state: 'connecting' }; barChanged();
  let microphone;
  try {
    microphone = await navigator.mediaDevices.getUserMedia({ audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true } });
    const sent = await speak(null, microphone, { presentation: granted.presentation, fd: granted.fd ?? null, ask: granted.id });
    // Withdrawn meanwhile.
    if (bar.asking?.state !== 'connecting') { microphone.getTracks().forEach(track => track.stop()); await sent.end(); return; }
    speaking = { ...sent, microphone };
    bar.asking = { ...bar.asking, state: 'speaking' }; follows();
    microphone.getAudioTracks()[0].addEventListener('ended', () => void stopSpeaking(), { once: true });
  } catch (error) {
    microphone?.getTracks().forEach(track => track.stop());
    bar.asking = bar.asking && { ...bar.asking, state: 'error', error: error.message };
  }
  barChanged();
}
async function stopSpeaking() {
  const sent = speaking; speaking = null;
  bar.asking = null; barChanged();
  if (!sent) return;
  follows();
  sent.microphone.getTracks().forEach(track => track.stop());
  await sent.end();
}
function placePlayer() { ($('viewer').open ? $('viewer-surface') : document.body).append($('listening')); }
// Open the file chooser now, while the tap or the key that asked for it lets a page open one:
// phones refuse once a request has been awaited. Settles with the files chosen; none if closed.
const chooser = Object.assign(document.createElement('input'), { type: 'file', multiple: true });
let choosing = null;
// Settle the chooser with no files, if it is open: Ctrl+C, as a browser may close it without
// saying so (no cancel event), or not open it at all, which would leave its command waiting.
function cancelChoosing() { if (!choosing) return false; choosing([]); return true; }
function chooseFiles() {
  choosing?.([]);
  return new Promise(resolve => {
    choosing = files => { choosing = null; chooser.onchange = chooser.oncancel = null; resolve(files); };
    chooser.value = '';
    chooser.onchange = () => choosing?.([...chooser.files]);
    chooser.oncancel = () => choosing?.([]);
    chooser.click();
  });
}
let depth = 0;
window.addEventListener('dragenter', e => { if (e.dataTransfer?.types.includes('Files')) { e.preventDefault(); depth++; $('dropzone').hidden = false; } });
window.addEventListener('dragover', e => { if (e.dataTransfer?.types.includes('Files')) e.preventDefault(); });
window.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; $('dropzone').hidden = true; } });
// Dropped files go to the active tab, which uploads them as its upload command would.
// Dropped on the Files, files go into its directory; anywhere else, the terminal's.
window.addEventListener('drop', e => { e.preventDefault(); depth = 0; $('dropzone').hidden = true; if (e.dataTransfer?.files.length) window.dispatchEvent(new CustomEvent(e.target?.closest?.('#window-files') ? 'files-dropped' : 'terminal-files', { detail: [...e.dataTransfer.files] })); });

// Where each file's preview was left, by path, kept in this browser for the last 200 files, so
// that opening one again continues there: the page code records how far it was scrolled and
// played; slides and PDFs record their slide, page and zoom (viewer.rs).
const PLACES = 'terminal-places';
function places() { try { return JSON.parse(localStorage.getItem(PLACES) || '[]'); } catch { return []; } }
function place(path) { return places().find(([p]) => p === path)?.[1] ?? null; }
function setPlace(path, value) {
  try {
    const list = places(), old = list.find(([p]) => p === path)?.[1];
    localStorage.setItem(PLACES, JSON.stringify([[path, { ...old, ...value }], ...list.filter(([p]) => p !== path)].slice(0, 200)));
  } catch {}
}
// The file the viewer shows, and those it showed before, as links led from one to the next:
// Back returns to them. A file opened from the terminal starts afresh.
let shown = null;
const trail = [];
function showTrail() { $('viewer-back').hidden = !trail.length; $('viewer-back').title = trail.length ? `Back to ${trail.at(-1).path}` : ''; }
async function follow(path, kind) { if (shown) trail.push(shown); return open(path, kind, true); }
$('viewer-back').onclick = () => { const previous = trail.pop(); if (previous) void open(previous.path, previous.kind, true); };
// The viewer's title. A path too long for the bar loses its start, not its file name: the title
// A window of the desktop opened, the preview's or the editor's (a non-modal dialog, which the
// compositor lays out): it has the keyboard.
function showWindow(dialog) { dialog.show(); dialog.focus({ preventScroll: true }); }
// overflows right to left (style.css), and <bdi> keeps the path's own order.
function viewerTitle(text) { const title = document.createElement('bdi'); title.textContent = text; $('viewer-title').replaceChildren(title); }
async function cleanupViewer() {
  const version = ++viewerVersion;
  const releases = [];
  if (shown) {
    const media = $('viewer-content').querySelector('video,audio');
    setPlace(shown.path, { scroll: $('viewer-content').scrollTop, ...(media && media.currentTime > 1 ? { time: media.currentTime } : {}) });
    // Kept once: the dialog's close cleans up again, after the content is gone.
    shown = null;
  }
  for (const frame of $('viewer-content').querySelectorAll('iframe')) {
    try { releases.push(frame.contentWindow?.signal?.dispose?.()); } catch (error) { console.warn('Failed to release game audio', error); }
  }
  for (const media of $('viewer-content').querySelectorAll('video,audio')) { media.pause(); media.removeAttribute('src'); media.load(); }
  if (releasePreview) { releasePreview(); releasePreview = null; }
  // AudioContext.close() completes asynchronously. Keep the frame alive until
  // its audio resources are released; an old cleanup must not erase a new open.
  await Promise.allSettled(releases);
  if (version === viewerVersion) {
    $('viewer-content').replaceChildren(); $('viewer').classList.remove('slides-view', 'game-view'); $('viewer-content').classList.remove('viewer-error');
    $('fullscreen-error').hidden = true;
  }
  return version;
}
async function closeViewer() {
  // Release a game's audio while its iframe is still visible and active.
  // Waiting for the dialog's queued close event can be too late in Chromium.
  const exit = document.fullscreenElement && $('viewer-surface').contains(document.fullscreenElement)
    ? document.exitFullscreen().catch(error => console.warn('Failed to exit preview fullscreen', error)) : Promise.resolve();
  const version = await cleanupViewer();
  await exit;
  if (version === viewerVersion) $('viewer').close();
}
$('viewer').addEventListener('cancel', event => { event.preventDefault(); void closeViewer(); });
// Escape closes a modal dialog (a password asked), or else the window that has the keyboard (the
// preview, the editor: windows of the desktop, crates/frontend/src/desktop.rs), and nothing else.
// Left to the browser, Safari also leaves its full-screen window, so the page takes the key and
// asks the dialog to cancel, which each one handles as its own Escape (the viewer closes, the
// editor asks about unsaved changes). Keys handled inside a dialog first, as the preview search's
// and the editor's, are left alone.
document.addEventListener('keydown', event => {
  // A preview shown full screen leaves that first, as the browser does with Escape.
  if (event.key !== 'Escape' || event.defaultPrevented || event.isComposing || document.fullscreenElement) return;
  const dialog = document.querySelector('dialog[open]:modal') ?? document.activeElement?.closest?.('dialog[open]');
  if (!dialog) return;
  event.preventDefault();
  if (dialog.dispatchEvent(new Event('cancel', { cancelable: true }))) dialog.close();
});
$('viewer').addEventListener('close', async () => {
  unfollow(); placePlayer();
  const returnFocus = opener;
  // Start exiting before removing a fullscreen child (e.g. a video or iframe),
  // and restore focus after the browser finishes its fullscreen transition.
  const exit = document.fullscreenElement && $('viewer-surface').contains(document.fullscreenElement)
    ? document.exitFullscreen() : Promise.resolve();
  const closedVersion = await cleanupViewer();
  await exit.catch(error => console.warn('Failed to exit preview fullscreen', error));
  if (viewerVersion === closedVersion && !$('viewer').open && !$('auth').open) {
    (returnFocus?.isConnected ? returnFocus : $('command'))?.focus();
  }
});
$('close-viewer').onclick = closeViewer;
$('fullscreen').onclick = async () => {
  const status = $('fullscreen-error'); status.hidden = true;
  try {
    if (document.fullscreenElement) await document.exitFullscreen();
    else {
      // A dialog itself is not an eligible fullscreen element. Its ordinary
      // descendant can enter fullscreen while retaining modal focus handling.
      const surface = $('viewer-surface');
      if (typeof surface.requestFullscreen !== 'function') throw new Error('Fullscreen API is unavailable in this environment');
      if (document.fullscreenEnabled === false) throw new Error('Fullscreen is not permitted for this page');
      await surface.requestFullscreen();
    }
  } catch (error) { status.textContent = `Fullscreen failed: ${error.message}`; status.hidden = false; }
};
// Full screen, the preview's bars float over the content, hidden until the pointer moves, as a
// video player's controls are; they stay while the pointer, or the keyboard's focus, is on one
// (a button clicked keeps the focus, but not :focus-visible), and while a listener asks to speak.
const bars = ':is(.viewer-bar, .preview-bar, .slides-bar, .pdf-toolbar)';
let chromeTimer;
function showChrome() {
  const surface = $('viewer-surface');
  surface.classList.add('chrome'); clearTimeout(chromeTimer);
  chromeTimer = setTimeout(() => {
    if (surface.querySelector(`${bars}:hover, ${bars}:has(:focus-visible), .live-hands.asked`)) showChrome();
    else surface.classList.remove('chrome');
  }, 2000);
}
const fullscreen = () => document.fullscreenElement === $('viewer-surface');
// A button clicked in the viewer leaves the focus where it was, so that keys go on turning slides
// and pages: Space would press it again (Fullscreen, say). One tabbed to takes Space and Enter.
$('viewer-surface').addEventListener('mousedown', event => { if (event.target instanceof Element && event.target.closest('button')) event.preventDefault(); });
// A tap moves no pointer: pointerdown shows them on touch screens.
for (const type of ['pointermove', 'pointerdown']) $('viewer-surface').addEventListener(type, () => { if (fullscreen()) showChrome(); });
$('viewer-surface').addEventListener('focusin', event => { if (fullscreen() && event.target.closest(bars)) showChrome(); });
document.addEventListener('fullscreenchange', () => {
  const active = !!document.fullscreenElement;
  $('fullscreen').setAttribute('aria-label', active ? 'Exit fullscreen' : 'Fullscreen');
  $('fullscreen').setAttribute('aria-pressed', String(active));
  // Shown a moment on entering, so that the way out is seen.
  if (fullscreen()) showChrome();
  else { clearTimeout(chromeTimer); $('viewer-surface').classList.remove('chrome'); }
});
window.addEventListener('message', event => { if (event.origin === location.origin && event.source === $('viewer-content').querySelector('iframe')?.contentWindow && event.data === 'close-game') closeViewer(); });
async function open(path, kind, followed = false, attending = false) {
  if (/^\/dev\/present\/[^/]+$/.test(path)) return attend(path);
  if (/^\/dev\/snd\/[^/]+$/.test(path)) return hear(path);
  if (!attending && following?.path !== path) unfollow();
  if (!followed) trail.length = 0;
  const version = await cleanupViewer();
  if (version !== viewerVersion) return;
  shown = { path, kind }; showTrail();
  const content = $('viewer-content'), dialog = $('viewer');
  $('download').hidden = false;
  viewerTitle(path); $('download').href = fileUrl(path); $('download').download = path.split('/').pop();
  if (!dialog.open) { opener = document.activeElement; showWindow(dialog); placePlayer(); }
  content.textContent = 'Loading...';
  try {
    if (kind === 'game') {
      const meta = await api(fileUrl(path), { method: 'HEAD' });
      if (Number(meta.headers.get('Content-Length')) > 2_000_000) throw new Error('Text exceeds 2 MB; use the download button in the top right.');
      const text = await (await api(fileUrl(path))).text();
      if (version !== viewerVersion) return;
      const manifest = JSON.parse(text);
      if (manifest.engine !== 'bevy' || !Object.hasOwn(configuration.games, manifest.entry)) throw new Error('Game entry is not registered; add it to the site content configuration and rebuild');
      content.replaceChildren(); dialog.classList.add('game-view');
      const iframe = document.createElement('iframe'); iframe.src = configuration.games[manifest.entry]; iframe.title = manifest.title || manifest.entry; iframe.allow = 'autoplay; fullscreen'; content.append(iframe); iframe.focus();
      return;
    }
    if (kind === 'slides') dialog.classList.add('slides-view');
    // The preview mounts only while the viewer still shows this file.
    content.dataset.version = String(version);
    const release = await window.terminalPreview.show(content, path, kind, String(version));
    if (version === viewerVersion) releasePreview = release; else return release();
    // Back where it was left.
    const saved = place(path);
    if (saved?.scroll) requestAnimationFrame(() => { content.scrollTop = saved.scroll; });
    const media = content.querySelector('video,audio');
    if (media && saved?.time) media.addEventListener('loadedmetadata', () => { if (saved.time < media.duration - 1) media.currentTime = saved.time; }, { once: true });
  } catch (error) { if (version === viewerVersion) { content.textContent = error.message; content.classList.add('viewer-error'); } }
}
// Leptos updates the DOM asynchronously. Observe committed output, then scroll
// at the next layout frame instead of measuring the previous command's height.
// Every tab's transcript follows its output; a tab shown again scrolls to its end, as does one
// that the on-screen keyboard shrinks.
const observedTranscripts = new WeakSet();
function observeTranscript() {
  for (const log of document.querySelectorAll('.transcript')) {
    let frame;
    const scroll = () => { cancelAnimationFrame(frame); frame = requestAnimationFrame(() => { log.scrollTop = log.scrollHeight; }); };
    if (!observedTranscripts.has(log)) {
      observedTranscripts.add(log);
      new MutationObserver(scroll).observe(log, { childList: true, subtree: true, characterData: true });
      new ResizeObserver(scroll).observe(log);
    }
    scroll();
  }
}
// Phones: the app takes the part of the screen that is visible, which the on-screen keyboard
// shrinks, so that the command line stays above it (--app-height and --app-top, style.css); while
// the keyboard is open, the page is marked .keyboard, and the header and the files make room.
if (window.visualViewport) {
  const viewport = window.visualViewport;
  let tallest = 0, width = 0;
  const fit = () => {
    const root = document.documentElement;
    if (viewport.width !== width) { width = viewport.width; tallest = 0; }
    tallest = Math.max(tallest, viewport.height);
    root.style.setProperty('--app-height', `${viewport.height}px`);
    root.style.setProperty('--app-top', `${viewport.offsetTop}px`);
    root.classList.toggle('keyboard', viewport.height < tallest * 0.8);
    if (document.activeElement?.classList.contains('command-input')) document.activeElement.scrollIntoView({ block: 'nearest' });
  };
  viewport.addEventListener('resize', fit); viewport.addEventListener('scroll', fit); fit();
}
window.terminal = { config: () => configuration.branding, exec, open, follow, place, setPlace, present, presentFile: (path, name) => dev.present(path, name ?? undefined), stopPresenting: name => dev.stop(`${dev.PRESENT}/${name}`).then(() => ({ device: `${dev.PRESENT}/${name}` })), presented: path => heard.get(path) ?? null, ask, recordSound, stopRecording, barOf, togglePresenting, goLive, askToSpeak, answerAsk, endVoice, attending: path => following?.path === path ? following : null, unlock, sudo: sudoAuthenticate, chooseFiles, cancelChoosing, uploadFiles, cancelUploads, accountCommand, completionFocus: (value, insideQuote) => {
  requestAnimationFrame(() => {
    const input = $('command');
    if (input?.value !== value || document.querySelector('dialog[open]:modal')) return;
    // Text selected since (the line chosen whole, to type over) is the typist's: the caret stays.
    if (document.activeElement === input && input.selectionStart !== input.selectionEnd) return;
    input.focus({ preventScroll: true });
    const end = value.length - (insideQuote && value.endsWith('"') ? 1 : 0);
    input.setSelectionRange(end, end);
    document.querySelector('.completion-options [aria-selected="true"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  });
}, setDirectory: path => { directory = path; }, focusInput: () => {
  observeTranscript();
  restoreTerminalFocus();
} };

// A file name keeps to one line; one that does not fit slides to show the rest (style.css). Each
// gets how far it overflows, measured as the list changes, and as the Files window is shown,
// hidden or resized (started()).
let namesFrame;
function measureNames() {
  cancelAnimationFrame(namesFrame);
  namesFrame = requestAnimationFrame(() => {
    for (const name of document.querySelectorAll('.files .filename')) {
      const overflow = name.scrollWidth - name.clientWidth;
      if (overflow > 2) {
        name.dataset.overflow = '';
        name.style.setProperty('--overflow', `-${overflow}px`);
        name.style.setProperty('--duration', `${Math.max(3, overflow / 40)}s`);
      } else delete name.dataset.overflow;
    }
  });
}
new MutationObserver(changes => { if (changes.some(change => change.target.closest?.('.files'))) measureNames(); })
  .observe($('app'), { childList: true, subtree: true, characterData: true });

// Dialog focus restoration and Leptos updates may finish after the command promise.
// Wait for the browser's next layout; never steal focus from another open modal.
let resetTerminalFocus = false;
// The window up (crates/frontend/src/desktop.rs), if not the terminal: the keyboard is its.
const otherWindow = () => document.querySelector('.window-focused:not(#window-terminal)');
function restoreTerminalFocus() {
  requestAnimationFrame(() => {
    const input = $('command');
    // Not while a password is asked, nor from another window that has the keyboard (the Files,
    // the preview, the editor), nor while a command runs.
    if (document.querySelector('dialog[open]:modal') || otherWindow() || document.activeElement?.closest?.('dialog[open], .window:not(#window-terminal)') || !['↵', 'Answer ↵', 'Input ↵'].includes(input?.closest('form')?.querySelector('.busy')?.textContent)) return;
    // After closing a modal Chromium can report this input as active while its
    // native text-editing focus still belongs to the closed dialog. Reacquire it.
    if (resetTerminalFocus && document.activeElement === input) input.blur();
    resetTerminalFocus = false;
    input?.focus({ preventScroll: true });
  });
}
for (const id of ['auth', 'editor']) {
  $(id).addEventListener('close', () => { resetTerminalFocus = true; restoreTerminalFocus(); });
}

// Redirect ordinary typing only when the surrounding shell is idle. Preserve
// selection, shortcuts, button activation, IME and every modal/editor input; what is typed in
// another window is that window's.
document.addEventListener('keydown', event => {
  if (event.defaultPrevented || event.isComposing || event.ctrlKey || event.metaKey || event.altKey || document.querySelector('dialog[open]:modal') || event.target?.closest?.('dialog[open], .window:not(#window-terminal)')) return;
  const target = event.target;
  // Another window up, whose focus fell to the page as what had it went (a box closed, a mode
  // changed): the key is its, and so is the focus again.
  const up = otherWindow();
  if (up) { if (!up.contains(document.activeElement)) up.focus({ preventScroll: true }); return; }
  if (!(target instanceof Element) || (target.closest('input,textarea,select,[contenteditable="true"]') && target.getClientRects().length) || window.getSelection()?.toString()) return;
  if (target.closest('button,a') && ['Enter', ' ', 'Tab'].includes(event.key)) return;
  const input = $('command'); if (!input || !['↵', 'Answer ↵', 'Input ↵'].includes(input.closest('form')?.querySelector('.busy')?.textContent)) return;
  if (event.key.length === 1) {
    event.preventDefault(); input.focus({ preventScroll: true });
    input.setRangeText(event.key, input.selectionStart ?? input.value.length, input.selectionEnd ?? input.value.length, 'end');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  } else if (['ArrowUp','ArrowDown','Backspace'].includes(event.key)) {
    event.preventDefault(); input.focus({ preventScroll: true });
    if (event.key === 'Backspace') { const end=input.selectionEnd??input.value.length,start=input.selectionStart??end; input.setRangeText('',start===end?Math.max(0,start-1):start,end,'end');input.dispatchEvent(new Event('input',{bubbles:true})); }
    else input.dispatchEvent(new KeyboardEvent('keydown',{key:event.key,bubbles:true,cancelable:true}));
  }
});
document.addEventListener('click', event => {
  if (!document.querySelector('dialog[open]:modal') && !window.getSelection()?.toString() && event.target instanceof Element && event.target.closest('.terminal-panel') && !event.target.closest('button,a,input,textarea,select,[contenteditable="true"]')) $('command')?.focus({preventScroll:true});
});
