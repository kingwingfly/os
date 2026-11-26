// Ephemeral, isolated WASI sandbox Worker for kubelet task execution (Phase 9.1b #84).
//
// Runs identically in a browser dedicated Web Worker (`self`) OR Node `worker_threads`
// (`parentPort`). Holds ZERO credentials, ZERO cookies, ZERO network handles, and ZERO access to
// the host OS kernel. All filesystem, device, and `/proc` syscalls traverse a `SharedArrayBuffer`
// doorbell into the parent `SandboxKernel` (`crates/client-kernel/src/sandbox.rs`).
//
// Preemption on cancellation, timeout, or self-fencing is enforced by the parent calling
// `worker.terminate()`, which immediately aborts even infinite-loop Wasm code.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const WASI_ESUCCESS = 0;
const WASI_EBADF = 8;
const WASI_EINVAL = 28;
const WASI_EIO = 29;
const WASI_ENOMEM = 48;
const WASI_ENOSYS = 52;
const WASI_ERANGE = 68;

const ALL_RIGHTS = (1n << 29n) - 1n;
const sleepFutex = new Int32Array(new SharedArrayBuffer(4));

function writeFilestat(dv, ptr, st) {
  dv.setBigUint64(ptr + 0, BigInt(st.dev ?? 1), true);
  dv.setBigUint64(ptr + 8, BigInt(st.ino ?? 1), true);
  dv.setUint8(ptr + 16, Number(st.filetype ?? 4));
  dv.setBigUint64(ptr + 24, BigInt(st.nlink ?? 1), true);
  dv.setBigUint64(ptr + 32, BigInt(st.size ?? 0), true);
  dv.setBigUint64(ptr + 40, BigInt(st.atim ?? 0), true);
  dv.setBigUint64(ptr + 48, BigInt(st.mtim ?? 0), true);
  dv.setBigUint64(ptr + 56, BigInt(st.ctim ?? 0), true);
}

async function runSandbox(msg, post) {
  const { wasmBytes, argv = [], env = [], memoryMaxBytes = 0, sab } = msg;
  const bytes = wasmBytes instanceof Uint8Array ? wasmBytes : new Uint8Array(wasmBytes);
  // Defense in depth: reject ELF or non-Wasm even before compilation.
  if (bytes.byteLength < 8 ||
      (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) ||
      bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    post({ type: 'error', errno: 'ENOEXEC', code: 126, message: 'ENOEXEC: non-Wasm or ELF binary rejected' });
    return;
  }

  const ctrl = new Int32Array(sab, 0, 16);
  const data = new Uint8Array(sab, 64);

  function callHost(reqObj, binBytes = null) {
    const reqJson = encoder.encode(JSON.stringify(reqObj));
    const binLen = binBytes ? binBytes.byteLength : 0;
    if (reqJson.byteLength + binLen > data.byteLength) {
      return { errno: WASI_EINVAL, json: {}, bytes: new Uint8Array(0) };
    }
    data.set(reqJson, 0);
    if (binLen > 0) data.set(binBytes, reqJson.byteLength);
    Atomics.store(ctrl, 1, reqJson.byteLength);
    Atomics.store(ctrl, 2, binLen);
    Atomics.store(ctrl, 0, 1);
    post({ type: 'wasi_req' });
    while (Atomics.load(ctrl, 0) === 1) {
      Atomics.wait(ctrl, 0, 1, 50);
    }
    const state = Atomics.load(ctrl, 0);
    if (state !== 2) {
      return { errno: WASI_EIO, json: {}, bytes: new Uint8Array(0) };
    }
    const errno = Atomics.load(ctrl, 5);
    const respJsonLen = Atomics.load(ctrl, 3);
    const respBinLen = Atomics.load(ctrl, 4);
    const json = respJsonLen > 0
      ? JSON.parse(decoder.decode(data.slice(0, respJsonLen)))
      : {};
    const outBytes = respBinLen > 0
      ? data.slice(respJsonLen, respJsonLen + respBinLen)
      : new Uint8Array(0);
    Atomics.store(ctrl, 0, 0);
    return { errno, json, bytes: outBytes };
  }

  const encodedArgs = argv.map(s => encoder.encode(String(s) + '\0'));
  const encodedEnv = env.map(s => encoder.encode(String(s) + '\0'));
  let memory = null;

  const memU8 = () => new Uint8Array(memory.buffer);
  const memDV = () => new DataView(memory.buffer);
  const readStr = (ptr, len) => decoder.decode(memU8().subarray(ptr, ptr + len));

  const effectiveMemoryMax = Number.isFinite(memoryMaxBytes) && memoryMaxBytes > 0
    ? memoryMaxBytes
    : 128 * 1024 * 1024;
  function checkMemoryBound() {
    if (memory && memory.buffer.byteLength > effectiveMemoryMax) {
      throw { __wasiOom: true, message: `sandbox memory ${memory.buffer.byteLength} exceeds memory.max ${effectiveMemoryMax}` };
    }
  }

  const wasi = {
    args_sizes_get(argcPtr, argvBufSizePtr) {
      const dv = memDV();
      dv.setUint32(argcPtr, encodedArgs.length, true);
      let total = 0;
      for (const a of encodedArgs) total += a.byteLength;
      dv.setUint32(argvBufSizePtr, total, true);
      return WASI_ESUCCESS;
    },
    args_get(argvPtr, argvBufPtr) {
      const dv = memDV();
      const u8 = memU8();
      let bufPos = argvBufPtr;
      for (let i = 0; i < encodedArgs.length; i++) {
        dv.setUint32(argvPtr + i * 4, bufPos, true);
        u8.set(encodedArgs[i], bufPos);
        bufPos += encodedArgs[i].byteLength;
      }
      return WASI_ESUCCESS;
    },
    environ_sizes_get(countPtr, bufSizePtr) {
      const dv = memDV();
      dv.setUint32(countPtr, encodedEnv.length, true);
      let total = 0;
      for (const e of encodedEnv) total += e.byteLength;
      dv.setUint32(bufSizePtr, total, true);
      return WASI_ESUCCESS;
    },
    environ_get(environPtr, environBufPtr) {
      const dv = memDV();
      const u8 = memU8();
      let bufPos = environBufPtr;
      for (let i = 0; i < encodedEnv.length; i++) {
        dv.setUint32(environPtr + i * 4, bufPos, true);
        u8.set(encodedEnv[i], bufPos);
        bufPos += encodedEnv[i].byteLength;
      }
      return WASI_ESUCCESS;
    },
    clock_res_get(id, resPtr) {
      if (id !== 0 && id !== 1) return WASI_EINVAL;
      memDV().setBigUint64(resPtr, 1_000_000n, true);
      return WASI_ESUCCESS;
    },
    clock_time_get(id, _precision, timePtr) {
      const dv = memDV();
      if (id === 0) {
        dv.setBigUint64(timePtr, BigInt(Date.now()) * 1_000_000n, true);
        return WASI_ESUCCESS;
      }
      if (id === 1) {
        const ms = typeof performance !== 'undefined' ? performance.now() : Date.now();
        dv.setBigUint64(timePtr, BigInt(Math.floor(ms * 1_000_000)), true);
        return WASI_ESUCCESS;
      }
      return WASI_EINVAL;
    },
    random_get(bufPtr, bufLen) {
      const u8 = memU8();
      let off = 0;
      while (off < bufLen) {
        const step = Math.min(65536, bufLen - off);
        crypto.getRandomValues(u8.subarray(bufPtr + off, bufPtr + off + step));
        off += step;
      }
      return WASI_ESUCCESS;
    },
    fd_prestat_get(fd, bufPtr) {
      if (fd !== 3) return WASI_EBADF;
      const dv = memDV();
      dv.setUint8(bufPtr, 0); // PREOPENTYPE_DIR
      dv.setUint32(bufPtr + 4, 1, true); // "/".length
      return WASI_ESUCCESS;
    },
    fd_prestat_dir_name(fd, pathPtr, pathLen) {
      if (fd !== 3) return WASI_EBADF;
      if (pathLen < 1) return WASI_ERANGE;
      memU8()[pathPtr] = 0x2f; // '/'
      return WASI_ESUCCESS;
    },
    fd_fdstat_get(fd, statPtr) {
      const res = callHost({ op: 'fd_fdstat_get', fd });
      if (res.errno !== 0) return res.errno;
      const dv = memDV();
      dv.setUint8(statPtr + 0, Number(res.json.filetype ?? 4));
      dv.setUint16(statPtr + 2, Number(res.json.fdflags ?? 0), true);
      dv.setBigUint64(statPtr + 8, ALL_RIGHTS, true);
      dv.setBigUint64(statPtr + 16, ALL_RIGHTS, true);
      return WASI_ESUCCESS;
    },
    fd_fdstat_set_flags(fd, flags) {
      return callHost({ op: 'fd_fdstat_set_flags', fd, flags }).errno;
    },
    fd_fdstat_set_rights() { return WASI_ESUCCESS; },
    fd_advise() { return WASI_ESUCCESS; },
    fd_allocate() { return WASI_ESUCCESS; },
    fd_filestat_get(fd, bufPtr) {
      const res = callHost({ op: 'fd_filestat_get', fd });
      if (res.errno !== 0) return res.errno;
      writeFilestat(memDV(), bufPtr, res.json);
      return WASI_ESUCCESS;
    },
    fd_filestat_set_size(fd, size) {
      return callHost({ op: 'fd_filestat_set_size', fd, size: Number(size) }).errno;
    },
    fd_filestat_set_times() { return WASI_ESUCCESS; },
    fd_sync(fd) { return callHost({ op: 'fd_sync', fd }).errno; },
    fd_datasync(fd) { return callHost({ op: 'fd_datasync', fd }).errno; },
    fd_close(fd) { return callHost({ op: 'fd_close', fd }).errno; },
    fd_read(fd, iovsPtr, iovsLen, nreadPtr) {
      checkMemoryBound();
      const dv = memDV();
      let totalWant = 0;
      const iovs = [];
      for (let i = 0; i < iovsLen; i++) {
        const base = dv.getUint32(iovsPtr + i * 8, true);
        const len = dv.getUint32(iovsPtr + i * 8 + 4, true);
        iovs.push([base, len]);
        totalWant += len;
      }
      if (totalWant === 0) {
        dv.setUint32(nreadPtr, 0, true);
        return WASI_ESUCCESS;
      }
      const res = callHost({ op: 'fd_read', fd, len: Math.min(totalWant, 1024 * 1024) });
      if (res.errno !== 0) return res.errno;
      const u8 = memU8();
      let srcOff = 0;
      for (const [base, len] of iovs) {
        if (srcOff >= res.bytes.byteLength) break;
        const take = Math.min(len, res.bytes.byteLength - srcOff);
        u8.set(res.bytes.subarray(srcOff, srcOff + take), base);
        srcOff += take;
      }
      memDV().setUint32(nreadPtr, srcOff, true);
      return WASI_ESUCCESS;
    },
    fd_pread(fd, iovsPtr, iovsLen, offset, nreadPtr) {
      checkMemoryBound();
      const dv = memDV();
      let totalWant = 0;
      const iovs = [];
      for (let i = 0; i < iovsLen; i++) {
        const base = dv.getUint32(iovsPtr + i * 8, true);
        const len = dv.getUint32(iovsPtr + i * 8 + 4, true);
        iovs.push([base, len]);
        totalWant += len;
      }
      if (totalWant === 0) {
        dv.setUint32(nreadPtr, 0, true);
        return WASI_ESUCCESS;
      }
      const res = callHost({ op: 'fd_pread', fd, len: Math.min(totalWant, 1024 * 1024), offset: Number(offset) });
      if (res.errno !== 0) return res.errno;
      const u8 = memU8();
      let srcOff = 0;
      for (const [base, len] of iovs) {
        if (srcOff >= res.bytes.byteLength) break;
        const take = Math.min(len, res.bytes.byteLength - srcOff);
        u8.set(res.bytes.subarray(srcOff, srcOff + take), base);
        srcOff += take;
      }
      memDV().setUint32(nreadPtr, srcOff, true);
      return WASI_ESUCCESS;
    },
    fd_write(fd, iovsPtr, iovsLen, nwrittenPtr) {
      checkMemoryBound();
      const dv = memDV();
      const u8 = memU8();
      let total = 0;
      const chunks = [];
      for (let i = 0; i < iovsLen; i++) {
        const base = dv.getUint32(iovsPtr + i * 8, true);
        const len = dv.getUint32(iovsPtr + i * 8 + 4, true);
        if (len > 0) {
          chunks.push(u8.subarray(base, base + len));
          total += len;
        }
      }
      if (total === 0) {
        dv.setUint32(nwrittenPtr, 0, true);
        return WASI_ESUCCESS;
      }
      const merged = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
      const res = callHost({ op: 'fd_write', fd }, merged);
      if (res.errno !== 0) return res.errno;
      memDV().setUint32(nwrittenPtr, Number(res.json.written ?? total), true);
      return WASI_ESUCCESS;
    },
    fd_pwrite(fd, iovsPtr, iovsLen, offset, nwrittenPtr) {
      checkMemoryBound();
      const dv = memDV();
      const u8 = memU8();
      let total = 0;
      const chunks = [];
      for (let i = 0; i < iovsLen; i++) {
        const base = dv.getUint32(iovsPtr + i * 8, true);
        const len = dv.getUint32(iovsPtr + i * 8 + 4, true);
        if (len > 0) {
          chunks.push(u8.subarray(base, base + len));
          total += len;
        }
      }
      if (total === 0) {
        dv.setUint32(nwrittenPtr, 0, true);
        return WASI_ESUCCESS;
      }
      const merged = new Uint8Array(total);
      let off = 0;
      for (const c of chunks) { merged.set(c, off); off += c.byteLength; }
      const res = callHost({ op: 'fd_pwrite', fd, offset: Number(offset) }, merged);
      if (res.errno !== 0) return res.errno;
      memDV().setUint32(nwrittenPtr, Number(res.json.written ?? total), true);
      return WASI_ESUCCESS;
    },
    fd_seek(fd, offset, whence, newOffsetPtr) {
      const res = callHost({ op: 'fd_seek', fd, offset: Number(offset), whence });
      if (res.errno !== 0) return res.errno;
      memDV().setBigUint64(newOffsetPtr, BigInt(res.json.pos ?? 0), true);
      return WASI_ESUCCESS;
    },
    fd_tell(fd, offsetPtr) {
      const res = callHost({ op: 'fd_tell', fd });
      if (res.errno !== 0) return res.errno;
      memDV().setBigUint64(offsetPtr, BigInt(res.json.pos ?? 0), true);
      return WASI_ESUCCESS;
    },
    fd_readdir(fd, bufPtr, bufLen, cookie, bufUsedPtr) {
      const res = callHost({ op: 'fd_readdir', fd });
      if (res.errno !== 0) return res.errno;
      const entries = Array.isArray(res.json.entries) ? res.json.entries : [];
      const u8 = memU8();
      const dv = memDV();
      const start = Number(cookie);
      let pos = 0;
      for (let i = start; i < entries.length; i++) {
        const e = entries[i];
        const nameBytes = encoder.encode(String(e.name ?? ''));
        const rec = new Uint8Array(24 + nameBytes.byteLength);
        const rdv = new DataView(rec.buffer);
        rdv.setBigUint64(0, BigInt(i + 1), true);
        rdv.setBigUint64(8, BigInt(e.ino ?? (i + 1)), true);
        rdv.setUint32(16, nameBytes.byteLength, true);
        rdv.setUint8(20, Number(e.filetype ?? 4));
        rec.set(nameBytes, 24);
        const avail = bufLen - pos;
        if (avail <= 0) break;
        const copyLen = Math.min(avail, rec.byteLength);
        u8.set(rec.subarray(0, copyLen), bufPtr + pos);
        pos += copyLen;
        if (copyLen < rec.byteLength) break;
      }
      dv.setUint32(bufUsedPtr, pos, true);
      return WASI_ESUCCESS;
    },
    path_open(dirFd, _dirFlags, pathPtr, pathLen, oflags, rightsBase, _rightsInh, fdflags, openedFdPtr) {
      checkMemoryBound();
      const path = readStr(pathPtr, pathLen);
      const res = callHost({
        op: 'path_open',
        dir_fd: dirFd,
        path,
        oflags,
        fdflags,
        rights_base: Number(BigInt.asUintN(32, BigInt(rightsBase))),
      });
      if (res.errno !== 0) return res.errno;
      memDV().setUint32(openedFdPtr, Number(res.json.fd), true);
      return WASI_ESUCCESS;
    },
    path_filestat_get(dirFd, flags, pathPtr, pathLen, bufPtr) {
      const path = readStr(pathPtr, pathLen);
      const res = callHost({ op: 'path_filestat_get', dir_fd: dirFd, path, follow: (flags & 1) !== 0 });
      if (res.errno !== 0) return res.errno;
      writeFilestat(memDV(), bufPtr, res.json);
      return WASI_ESUCCESS;
    },
    path_filestat_set_times() { return WASI_ESUCCESS; },
    path_create_directory(dirFd, pathPtr, pathLen) {
      return callHost({ op: 'path_create_directory', dir_fd: dirFd, path: readStr(pathPtr, pathLen) }).errno;
    },
    path_unlink_file(dirFd, pathPtr, pathLen) {
      return callHost({ op: 'path_unlink_file', dir_fd: dirFd, path: readStr(pathPtr, pathLen) }).errno;
    },
    path_remove_directory(dirFd, pathPtr, pathLen) {
      return callHost({ op: 'path_remove_directory', dir_fd: dirFd, path: readStr(pathPtr, pathLen) }).errno;
    },
    path_rename(oldFd, oldPathPtr, oldPathLen, newFd, newPathPtr, newPathLen) {
      return callHost({
        op: 'path_rename',
        old_fd: oldFd,
        old_path: readStr(oldPathPtr, oldPathLen),
        new_fd: newFd,
        new_path: readStr(newPathPtr, newPathLen),
      }).errno;
    },
    path_readlink(dirFd, pathPtr, pathLen, bufPtr, bufLen, bufUsedPtr) {
      const res = callHost({ op: 'path_readlink', dir_fd: dirFd, path: readStr(pathPtr, pathLen) });
      if (res.errno !== 0) return res.errno;
      const targetBytes = encoder.encode(String(res.json.target ?? ''));
      const take = Math.min(bufLen, targetBytes.byteLength);
      memU8().set(targetBytes.subarray(0, take), bufPtr);
      memDV().setUint32(bufUsedPtr, take, true);
      return WASI_ESUCCESS;
    },
    path_link() { return WASI_ENOSYS; },
    path_symlink() { return WASI_ENOSYS; },
    poll_oneoff(inPtr, outPtr, nsubscriptions, neventsPtr) {
      const dv = memDV();
      if (nsubscriptions === 0) {
        dv.setUint32(neventsPtr, 0, true);
        return WASI_EINVAL;
      }
      let minWaitMs = Infinity;
      const events = [];
      for (let i = 0; i < nsubscriptions; i++) {
        const sub = inPtr + i * 48;
        const userdata = dv.getBigUint64(sub, true);
        const tag = dv.getUint8(sub + 8);
        if (tag === 0) { // EVENTTYPE_CLOCK
          const clockId = dv.getUint32(sub + 16, true);
          const timeoutNs = dv.getBigUint64(sub + 24, true);
          const subFlags = dv.getUint16(sub + 40, true);
          let waitNs = timeoutNs;
          if ((subFlags & 1) !== 0) {
            const nowNs = clockId === 0
              ? BigInt(Date.now()) * 1_000_000n
              : BigInt(Math.floor((typeof performance !== 'undefined' ? performance.now() : Date.now()) * 1_000_000));
            waitNs = timeoutNs > nowNs ? timeoutNs - nowNs : 0n;
          }
          const waitMs = Number(waitNs / 1_000_000n);
          if (waitMs < minWaitMs) minWaitMs = waitMs;
          events.push({ userdata, type: 0 });
        } else {
          minWaitMs = 0;
          events.push({ userdata, type: tag });
        }
      }
      if (Number.isFinite(minWaitMs) && minWaitMs > 0) {
        Atomics.wait(sleepFutex, 0, 0, Math.min(minWaitMs, 60_000));
      }
      let outCount = 0;
      for (const ev of events) {
        const ep = outPtr + outCount * 32;
        dv.setBigUint64(ep + 0, ev.userdata, true);
        dv.setUint16(ep + 8, 0, true);
        dv.setUint8(ep + 10, ev.type);
        outCount++;
      }
      dv.setUint32(neventsPtr, outCount, true);
      return WASI_ESUCCESS;
    },
    proc_exit(code) {
      throw { __wasiExit: true, code: code >>> 0 };
    },
    proc_raise() { return WASI_ENOSYS; },
    sched_yield() { return WASI_ESUCCESS; },
    sock_accept() { return WASI_ENOSYS; },
    sock_recv() { return WASI_ENOSYS; },
    sock_send() { return WASI_ENOSYS; },
    sock_shutdown() { return WASI_ENOSYS; },
  };

  try {
    const mod = await WebAssembly.compile(bytes);
    const instance = await WebAssembly.instantiate(mod, {
      wasi_snapshot_preview1: wasi,
      wasix_32v1: { proc_id: () => 1 },
    });
    memory = instance.exports.memory;
    if (!memory) {
      post({ type: 'error', errno: 'ENOEXEC', code: 126, message: 'WASI module missing exported memory' });
      return;
    }
    checkMemoryBound();
    if (typeof instance.exports._start !== 'function') {
      post({ type: 'error', errno: 'ENOEXEC', code: 126, message: 'WASI module missing _start entrypoint' });
      return;
    }
    instance.exports._start();
    checkMemoryBound();
    post({ type: 'exit', code: 0 });
  } catch (err) {
    if (err && err.__wasiExit) {
      post({ type: 'exit', code: err.code });
    } else if (err && err.__wasiOom) {
      post({ type: 'error', errno: 'ENOMEM', code: 137, message: err.message });
    } else {
      post({ type: 'error', errno: 'EIO', code: 1, message: String(err?.message ?? err) });
    }
  }
}

// Bootstrap in EITHER Node `worker_threads` OR a browser dedicated Web Worker.
if (typeof process !== 'undefined' && process.versions?.node) {
  import('node:worker_threads').then(({ parentPort }) => {
    if (!parentPort) return;
    parentPort.on('message', msg => {
      if (msg?.type === 'boot') {
        void runSandbox(msg, m => parentPort.postMessage(m));
      }
    });
  });
} else if (typeof self !== 'undefined') {
  self.onmessage = ev => {
    if (ev.data?.type === 'boot') {
      void runSandbox(ev.data, m => self.postMessage(m));
    }
  };
}
