// Recording sound into a file that grows as it is heard (`stream FILE`): Opus in WebM, which
// every browser records. It is a new file opened to append (O_APPEND), there at once, empty,
// readable while it grows, in chunks smaller than an upload's (api::RECORDING_CHUNK); this page
// keeps its descriptor as an upload's (upload.mjs), and writes each chunk in order as soon as
// it is whole. Stopping writes the rest as the last, short, chunk and closes the file, which is
// then complete. If the page goes, the kernel keeps what arrived (api::RECORDING_IDLE).
import { O_APPEND, O_CREAT, O_EXCL, O_WRONLY, call, closeOnLeaving, hold, pwrite, sys } from './http.mjs';

const RETRIES = 3;
export const RECORDED = 'audio/webm;codecs=opus';

// `bytes`, in the unit they make at least one of.
const size = bytes => bytes < 1e3 ? `${bytes} B` : bytes < 1e6 ? `${(bytes / 1e3).toFixed(1)} KB` : `${(bytes / 1e6).toFixed(1)} MB`;
/** `seconds` as minutes and seconds, as a recording's line and a live sound's show them. */
export const clock = seconds => `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(Math.floor(seconds % 60)).padStart(2, '0')}`;

/** Record `microphone`, a MediaStream, into a new file at `destination`, made with the ACL
 * entries `acl` (stream -m), until `signal` stops it, reporting progress; `begun` hears once the
 * file is there. Settles with what was saved. */
export async function record(destination, microphone, { acl = null, progress = () => {}, begun: there = () => {}, signal }) {
  if (!window.MediaRecorder?.isTypeSupported(RECORDED)) throw new Error('This browser cannot record Opus in WebM');
  const rust = window.terminalUploads;
  let begun;
  try { begun = await call('open', { path: destination, flags: O_WRONLY | O_CREAT | O_EXCL | O_APPEND, mode: 0o666 }); }
  catch (error) { throw error.errno === 'EEXIST' ? new Error('File already exists; rename it before recording') : error; }
  const fd = begun.fd, chunkSize = begun.chunk_size;
  // Who may hear it, as it is made (stream -m), or it is not made.
  if (acl) {
    const why = await rust.setfacl(destination, acl);
    if (why) { await sys([{ close: { fd } }, { unlink: { path: destination } }]).catch(() => {}); throw new Error(why.replace(/^setfacl:/, 'stream -m:')); }
  }
  const leaving = () => closeOnLeaving([fd]);
  addEventListener('pagehide', leaving);
  there(begun);
  // `full`: the file reached the largest a file may be, and takes no more.
  let failure = null, full = false, sent = 0, index = 0, pending = new Uint8Array(0);
  // Chunks go one at a time, in order: the file is what arrived, from its start.
  let queue = Promise.resolve();
  const send = bytes => {
    const at = index++;
    queue = queue.then(async () => {
      for (let attempt = 0; ; attempt++) {
        // Failed meanwhile (the hold lost, say), or full: nothing more goes.
        if (failure || full) return;
        try {
          await pwrite(fd, at, bytes, rust.sha256(bytes)); sent += bytes.length; return;
        } catch (error) {
          // Refused, it is over; a 400 says R2 did not take it (files.rs), which goes again a few
          // times, as an upload's chunk does. Unreachable, it goes again for as long as the
          // network is down, while what is recorded meanwhile waits its turn; once stopped, a few
          // times more.
          if (error.status === 413) { full = true; return; }
          const refused = error.status >= 400 && error.status < 500 && (error.status !== 400 || attempt + 1 >= RETRIES);
          if (refused || (signal.aborted && attempt + 1 >= RETRIES)) { failure = error; return; }
          await new Promise(resolve => setTimeout(resolve, Math.min(10000, 1000 * 2 ** attempt)));
        }
      }
    });
  };
  const recorder = new MediaRecorder(microphone, { mimeType: RECORDED, audioBitsPerSecond: 64000 });
  // It stops when told to, and on its own: the microphone ended (unplugged, or taken back), or
  // the recorder failed. Either way, what was recorded is saved.
  let ended = false;
  const stopped = new Promise(resolve => { recorder.onstop = () => { ended = true; resolve(); }; });
  recorder.onerror = () => { ended = true; };
  // Read in the order recorded, as each read waits.
  let reading = Promise.resolve();
  recorder.ondataavailable = event => {
    reading = reading.then(async () => {
      const bytes = new Uint8Array(await event.data.arrayBuffer());
      const joined = new Uint8Array(pending.length + bytes.length); joined.set(pending); joined.set(bytes, pending.length);
      pending = joined;
      while (pending.length >= chunkSize) { send(pending.slice(0, chunkSize)); pending = pending.slice(chunkSize); }
    });
  };
  const started = performance.now();
  const say = () => progress(`● ${clock((performance.now() - started) / 1000)} · ${size(sent + pending.length)}`);
  const ticking = setInterval(say, 1000); say();
  // Still here, while it records: the page keeps its descriptor, and hears if it was closed
  // elsewhere (jobs cancel).
  const lease = hold(fd, () => { failure ??= Object.assign(new Error('closed elsewhere'), { errno: 'EBADF', status: 409 }); });
  try {
    recorder.start(1000);
    // Until stopped, here or by the recorder itself, or a chunk or the hold fails.
    await new Promise(resolve => { const check = setInterval(() => { if (failure || full || signal.aborted || ended || recorder.state === 'inactive') { clearInterval(check); resolve(); } }, 250); });
    const itself = !signal.aborted && !failure && !full;
    if (recorder.state !== 'inactive') recorder.stop();
    // A recorder that failed may say so without stopping as it should; it is not waited for long.
    await Promise.race([stopped, new Promise(resolve => setTimeout(resolve, 2000))]); await reading;
    // What is left is the last chunk, short.
    if (pending.length) { send(pending); pending = new Uint8Array(0); }
    await queue;
    // Stopped elsewhere (jobs cancel), or taken from this page: the file is what arrived.
    if (failure) throw failure.status === 409 ? new Error('stopped elsewhere; what arrived is kept') : failure;
    const done = await call('close', { fd });
    return { ...done, seconds: (performance.now() - started) / 1000, ...(full ? { stopped: 'it reached the largest a file may be (1 GB)' } : itself ? { stopped: 'the microphone stopped' } : {}) };
  } finally {
    clearInterval(ticking); lease(); removeEventListener('pagehide', leaving);
    if (recorder.state !== 'inactive') recorder.stop();
  }
}
