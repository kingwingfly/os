// /dev from user space (owner's design, 2026-10-29): presentations and live sounds are character
// devices (crates/worker/src/dev), and what the page does with them is system calls: mknod
// makes one, open a descriptor that reads (follow, hear, ask) or writes (show, turn, speak,
// send) it, and its driver's requests (ioctl) do the rest. Whether one may is the device's mode
// and ACL's to say, checked by the kernel; the page asks, and is told.
import { O_WRONLY, answered, call, hold, sys } from './http.mjs';

export const PRESENT = '/dev/present', SOUND = '/dev/snd';
// The drivers' requests (abi::PRESENT_*, abi::SND_*).
const PRESENT_SHOW = 0x5001, PRESENT_ASK = 0x5002, PRESENT_ANSWER = 0x5003, PRESENT_SPEAK = 0x5004;
const SND_PUBLISH = 0x5101, SND_LISTEN = 0x5102, SND_ANSWER = 0x5103;
const O_RDONLY = 0;
const ACL = 'system.posix_acl_access';

/** A presentation's name for the file at `path`, as present names one (core devices::default_name). */
export function defaultName(path) {
  const file = path.slice(path.lastIndexOf('/') + 1);
  const stem = /\.slides\.md$/i.test(file) ? file.slice(0, -'.slides.md'.length) : file.includes('.') ? file.slice(0, file.lastIndexOf('.')) : file;
  return stem || file;
}

// `request` of the device the descriptor `fd` opens, about `arg`.
const ioctl = (fd, request, arg = null) => call('ioctl', { fd, request, arg });
// Open `device` as `flags` ask, make `request` of it, and close it: its answer.
async function once(device, flags, request, arg) {
  const { fd } = await call('open', { path: device, flags });
  try { return await ioctl(fd, request, arg); }
  finally { await sys([{ close: { fd } }]).catch(() => {}); }
}

/** What reading the device at `path` tells: its driver's state (cat /dev/present/NAME). */
export async function read(path) {
  const response = await fetch('/api/file?path=' + encodeURIComponent(path));
  let body = {}; try { body = await response.json(); } catch {}
  if (!response.ok) { const error = new Error(body.error || `Request failed (${response.status})`); error.status = response.status; throw error; }
  return body;
}

/** Present the file at `path` as /dev/present/NAME (the file's own name by default): the device,
 * which gets the file's mode and ACL, so that whoever may read the file follows it, and where
 * it is. One of that name of the account's is replaced. */
export async function present(path, name = defaultName(path)) {
  const device = `${PRESENT}/${name}`;
  const [found, acl] = await sys([{ stat: { path } }, { getxattr: { path, name: ACL } }]);
  const stat = answered(found);
  answered((await sys([{ mknod: { path: device, mode: stat.mode & 0o666, rdev: 'present' } }]))[0]);
  if ('ok' in acl) await sys([{ setxattr: { path: device, name: ACL, value: acl.ok } }]);
  return { ...await once(device, O_WRONLY, PRESENT_SHOW, { path }), device };
}

/** Stop presenting `device`: removed, it hangs up, and its followers hear so. */
export async function stop(device) { await call('unlink', { path: device }); }

/** What the account presents of the file at `path`, for its bar: who it is, its presentations of
 * it, the listeners asking to speak in them and those speaking. */
export async function presented(path) {
  const creds = await call('getcreds');
  if (!creds.signed_in) return { user: null, devices: [], asks: [], voices: [] };
  const [listed] = await sys([{ getdents: { path: PRESENT } }]);
  const own = (listed.ok ?? []).filter(entry => entry.stat?.uid === creds.uid).map(entry => `${PRESENT}/${entry.name}`);
  const states = (await Promise.all(own.map(device => read(device).catch(() => null)))).filter(state => state?.device?.path === path).map(state => state.device);
  return { user: creds.user, devices: states.map(state => ({ device: state.device, version: state.version })),
    asks: states.flatMap(state => state.asks ?? []), voices: states.flatMap(state => state.voices ?? []) };
}

/** Follow the presentation `device`: what it shows, whose it is, whether this page turns it too,
 * where it is, its sound and voices. */
export async function attend(device) { return (await read(device)).device; }

/** Ask to speak in the presentation `device` (`withdraw` to ask no more): the ask's id. */
export async function ask(device, withdraw = false) { return once(device, O_RDONLY, PRESENT_ASK, withdraw ? { withdraw: true } : null); }

/** Answer the ask `id` in the presentation `device`, as its presenter. */
export async function answer(device, id, allow) { return once(device, O_WRONLY, PRESENT_ANSWER, { id, allow }); }

// A descriptor that writes a device, kept while it is used (http.mjs hold), and closed when
// done, or when the page goes.
function kept(fd) {
  const release = hold(fd);
  const leaving = () => navigator.sendBeacon('/api/sys', new Blob([JSON.stringify({ calls: [{ close: { fd } }] })], { type: 'application/json' }));
  addEventListener('pagehide', leaving);
  return async () => { release(); removeEventListener('pagehide', leaving); await sys([{ close: { fd } }]).catch(() => {}); };
}

/** Send what `offer` describes (an SDP and its track's mid) as the sound /dev/snd/NAME, made
 * now, with the ACL entries `acl` (stream -m); or, with `presentation`, as a voice in it,
 * through the descriptor `fd` passed to this session or one opened now, which the presenter's
 * leave lets write it. Settles with the device, its answer (sdp), what it is, and what ends it:
 * closing the descriptor. */
export async function send(offer, { name, acl = null, presentation = null, fd = null }) {
  if (presentation) {
    const writing = fd ?? (await call('open', { path: presentation, flags: O_WRONLY })).fd;
    const end = kept(writing);
    try { return { ...await ioctl(writing, PRESENT_SPEAK, offer), end }; }
    catch (error) { await end(); throw error; }
  }
  const device = `${SOUND}/${name}`;
  answered((await sys([{ mknod: { path: device, mode: 0o666, rdev: 'snd' } }]))[0]);
  if (acl) {
    const why = await window.terminalUploads.setfacl(device, acl);
    if (why) { await sys([{ unlink: { path: device } }]); throw new Error(why.replace(/^setfacl:/, 'stream -m:')); }
  }
  const { fd: writing } = await call('open', { path: device, flags: O_WRONLY });
  const end = kept(writing);
  try { return { ...await ioctl(writing, SND_PUBLISH, offer), end }; }
  catch (error) { await end(); throw error; }
}

/** Hear the sound `device`: Realtime's offer of a session that pulls it, and what the device is;
 * `reply(sdp)` answers it. */
export async function hear(device) {
  const { fd } = await call('open', { path: device, flags: O_RDONLY });
  try {
    const offered = await ioctl(fd, SND_LISTEN);
    return { ...offered, reply: sdp => ioctl(fd, SND_ANSWER, { session: offered.session, sdp }).finally(() => sys([{ close: { fd } }]).catch(() => {})) };
  } catch (error) { await sys([{ close: { fd } }]).catch(() => {}); throw error; }
}
