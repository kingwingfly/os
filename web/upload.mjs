// Chunked, resumable uploads, through a file descriptor (system calls: open, pwrite, close). A
// file is hashed first: its SHA-256 and size, opened at its destination, go on with the chunks
// the kernel already has of it, so choosing the same file again, on this device or another
// signed in to the same account, resumes it. One descriptor writes a file at a time: its page
// keeps it (http.mjs hold), and no other session goes on with it until this one has not been
// heard from for a while (fds::LEASE). Each chunk carries its own SHA-256, which R2 checks.
// Others can read a file while it uploads.
import { O_CREAT, O_WRONLY, call, closeOnLeaving, hold, sys } from './http.mjs';

const PARALLEL = 3;
const RETRIES = 3;

// The descriptors this page writes, closed as it goes, so that another may go on with them.
const writing = new Set();
addEventListener('pagehide', () => closeOnLeaving([...writing]));

export class Cancelled extends Error { constructor() { super('Upload cancelled'); this.name = 'Cancelled'; } }

// As the file panel counts it (lib.rs upload_progress): whole percents of the bytes arrived.
const percent = (done, total) => total ? Math.floor(done * 100 / total) + '%' : '100%';

// The SHA-256 of `file`, and of each of its chunks.
async function hash(file, size, progress, signal) {
  const rust = window.terminalUploads, whole = rust.hasher(), parts = [];
  const count = Math.ceil(file.size / size);
  for (let index = 0; index < count; index++) {
    if (signal.aborted) throw new Cancelled();
    const bytes = new Uint8Array(await file.slice(index * size, Math.min((index + 1) * size, file.size)).arrayBuffer());
    whole.update(bytes); parts.push(rust.sha256(bytes));
    progress('hashing ' + percent(index + 1, count));
  }
  return { sha256: whole.hex(), parts };
}

// pwrite(2) of chunk `index`, as an XMLHttpRequest, which stops when asked.
function send(fd, index, blob, sha256, requests) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest(); requests.add(xhr);
    xhr.open('PUT', `/api/pwrite?fd=${fd}&index=${index}`);
    xhr.setRequestHeader('X-Chunk-SHA256', sha256);
    const done = () => requests.delete(xhr);
    xhr.onload = () => {
      done();
      if (xhr.status >= 200 && xhr.status < 300) return resolve();
      let reply = {}; try { reply = JSON.parse(xhr.responseText); } catch {}
      const error = new Error(reply.error || `Chunk ${index} failed (${xhr.status})`); error.status = xhr.status; error.errno = reply.errno; reject(error);
    };
    xhr.onerror = () => { done(); reject(new Error('Network connection failed')); };
    xhr.onabort = () => { done(); reject(new Cancelled()); };
    xhr.send(blob);
  });
}
// Send a chunk, again after a moment if the network or the server failed; a refusal is final.
// `halted` says whether the upload stopped meanwhile, as another chunk failed.
async function sendWithRetries(fd, index, blob, sha256, requests, signal, halted) {
  for (let attempt = 0; ; attempt++) {
    try { return await send(fd, index, blob, sha256, requests); }
    catch (error) {
      if (signal.aborted || error instanceof Cancelled) throw new Cancelled();
      if (attempt + 1 >= RETRIES || (error.status >= 400 && error.status < 500 && error.status !== 400)) throw error;
      await new Promise(resolve => setTimeout(resolve, 1000 * 2 ** attempt));
      if (halted()) throw new Cancelled();
    }
  }
}

// Why opening `destination` was refused, as the uploader is told.
function refused(error) {
  if (error.errno === 'EEXIST') return new Error('File already exists; rename it before uploading');
  if (error.errno === 'EISDIR') return new Error('A directory with this name already exists');
  return error;
}

/** Upload `file` to `destination`, reporting progress, until done or `signal` cancels it. */
export async function uploadFile(file, destination, { progress = () => {}, signal = new AbortController().signal } = {}) {
  const size = window.terminalUploads.chunkSize;
  const count = Math.ceil(file.size / size);
  const { sha256, parts } = await hash(file, size, progress, signal);
  if (signal.aborted) throw new Cancelled();
  // A new file, or the same one, gone on with: refused while another page writes it.
  let opened;
  try { opened = await call('open', { path: destination, flags: O_WRONLY | O_CREAT, mode: 0o666, size: file.size, sha256 }); }
  catch (error) { throw refused(error); }
  const fd = opened.fd;
  const committed = new Set(opened.committed || []);
  const resumed = Boolean(opened.resumed);
  const length = index => Math.min(size, file.size - index * size);
  let arrived = 0; committed.forEach(index => { arrived += length(index); });
  progress(percent(arrived, file.size));
  const pending = []; for (let index = 0; index < count; index++) if (!committed.has(index)) pending.push(index);
  // Once one chunk fails for good, the others stop too, rather than go on sending after the
  // upload has been reported as failed.
  let halted = false, failure;
  const requests = new Set(), abort = () => { halted = true; requests.forEach(xhr => xhr.abort()); };
  signal.addEventListener('abort', abort, { once: true });
  writing.add(fd);
  // Still here, while it sends: the page keeps its descriptor; another page going on with the
  // file, or its removal, stops the next chunk (EBADF).
  const lease = hold(fd);
  try {
    await Promise.all(Array.from({ length: Math.min(PARALLEL, pending.length) }, async () => {
      while (pending.length && !halted) {
        if (signal.aborted) throw new Cancelled();
        const index = pending.shift();
        try {
          await sendWithRetries(fd, index, file.slice(index * size, Math.min((index + 1) * size, file.size)), parts[index], requests, signal, () => halted);
        } catch (error) { if (!(error instanceof Cancelled)) failure ??= error; abort(); throw error; }
        committed.add(index); arrived += length(index);
        progress(percent(arrived, file.size));
      }
    }));
    if (signal.aborted) throw new Cancelled();
    // The lease may stop the upload between chunks, when none is in flight to fail.
    if (failure) throw failure;
  } catch (error) {
    lease(); abort();
    // Only Cancel cancels the upload, and only while this page writes it: a file it made goes.
    if (signal.aborted || (error instanceof Cancelled && !failure)) {
      const [closed] = await sys([{ close: { fd } }]).catch(() => [{}]);
      if (opened.created && closed && (closed.ok || closed.err?.errno === 'EIO')) await sys([{ unlink: { path: destination } }]).catch(() => {});
      throw new Cancelled();
    }
    // Let go, so that choosing the file again goes on with it now, here or elsewhere.
    await sys([{ close: { fd } }]).catch(() => {});
    // Nothing to go on with here: another page went on with it, someone removed it, or it
    // expired.
    const reason = failure || error;
    if (reason.errno === 'EBADF') throw new Error('stopped: ' + (/another tab or device/.test(reason.message) ? reason.message : 'the file was removed, or its upload cancelled, elsewhere'));
    throw new Error(reason.message + '; choose the same file again to resume');
  } finally { lease(); writing.delete(fd); signal.removeEventListener('abort', abort); }
  const done = await call('close', { fd });
  return { ...done, resumed };
}
