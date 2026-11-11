// Process-created PTYs share their execution host's devpts namespace. Slave opens
// check the creator's uid; private descriptions carry access through dup/fork/exec.
// Byte queues are bounded and never enter cloud storage.
import { Pty, IOCTL } from './pty.js';

const fail = errno => { throw Object.assign(new Error(errno), { errno }); };
const LIMIT = 1024 * 1024;
export const PTY_MAX = 64;
// Browser seats already use process IDs as stable slave numbers. Keep allocated
// devices in a disjoint range, without recycling names during this host's lifetime.
let nextNumber = 0x40000000;

export class PtyDevices {
  constructor({ signal = () => {}, hangup = async () => {} } = {}) {
    this.pairs = new Map(); this.handles = new Map(); this.nextHandle = 1;
    this.signal = signal; this.hangup = hangup;
  }
  path(path, ctty = 0) {
    if (path === '/dev/ptmx') return { master: true };
    const number = path === '/dev/tty' ? ctty : /^\/dev\/pts\/([1-9][0-9]*)$/.exec(path)?.[1];
    const pair = this.pairs.get(Number(number));
    return pair && !pair.masterClosed ? { pair, master: false } : null;
  }
  open(process, path, { readable = true, writable = true, nonblock = false } = {}) {
    if (this.handles.size >= 4096) fail('EMFILE');
    const target = this.path(path, process.ctty);
    if (!target) fail(path === '/dev/tty' ? 'ENXIO' : 'ENOENT');
    let { pair, master } = target;
    if (master) {
      if (this.pairs.size >= PTY_MAX || nextNumber >= 0x7fffffff) fail('ENOSPC');
      pair = { number: nextNumber++, uid: process.uid, locked: true, masterClosed: false,
        masters: 0, slaves: 0, opened: false, output: new Uint8Array(LIMIT), head: 0, queued: 0 };
      pair.terminal = new Pty({ echo: text => this.output(pair, new TextEncoder().encode(text)),
        signal: number => this.signal(pair.terminal, number) });
      Object.assign(pair.terminal, { number: pair.number, name: `/dev/pts/${pair.number}` });
      this.pairs.set(pair.number, pair);
    } else {
      if (pair.uid !== process.uid && process.uid !== 0) fail('EACCES');
      if (pair.locked) fail('EIO');
      pair.opened = true;
    }
    const handle = this.nextHandle++;
    const description = { handle, pair, master, readable, writable, nonblock, holders: new Map([[process.pid, 1]]) };
    this.handles.set(handle, description);
    pair[master ? 'masters' : 'slaves']++;
    return { handle, number: pair.number, master, readable, writable };
  }
  get(pid, handle) {
    const description = this.handles.get(handle);
    if (!description?.holders.has(pid)) fail('EBADF');
    return description;
  }
  hold(from, to, handle, count = 1) {
    const description = this.get(from, handle);
    description.holders.set(to, (description.holders.get(to) ?? 0) + count);
  }
  async close(pid, handle, all = false) {
    const description = this.get(pid, handle), { pair, holders, master } = description;
    const count = holders.get(pid);
    if (!all && count > 1) { holders.set(pid, count - 1); return; }
    holders.delete(pid);
    if (holders.size) return;
    this.handles.delete(handle);
    pair[master ? 'masters' : 'slaves']--;
    if (master && !pair.masters) {
      pair.masterClosed = true;
      pair.terminal.close();
      await this.hangup(pair.terminal);
    }
    if (!pair.masters && !pair.slaves) {
      pair.terminal.close(); this.pairs.delete(pair.number);
      pair.output = new Uint8Array(0); pair.queued = 0;
    }
  }
  async release(pid) {
    for (const [handle, description] of [...this.handles]) if (description.holders.has(pid)) await this.close(pid, handle, true);
  }
  output(pair, data) {
    if (!data.length) return;
    if (pair.queued + data.length > LIMIT) fail('EAGAIN');
    const at = (pair.head + pair.queued) % LIMIT, first = Math.min(data.length, LIMIT - at);
    pair.output.set(data.subarray(0, first), at); pair.output.set(data.subarray(first), 0);
    pair.queued += data.length;
  }
  read(pid, handle, count) {
    const description = this.get(pid, handle), { pair, master, readable, nonblock } = description;
    if (!readable) fail('EBADF');
    if (!Number.isInteger(count) || count < 0 || count > 65536) fail('EINVAL');
    if (!count) return new Uint8Array(0);
    if (master) {
      if (pair.queued) {
        const out = new Uint8Array(Math.min(count, pair.queued)), first = Math.min(out.length, LIMIT - pair.head);
        out.set(pair.output.subarray(pair.head, pair.head + first));
        out.set(pair.output.subarray(0, out.length - first), first);
        pair.head = (pair.head + out.length) % LIMIT; pair.queued -= out.length;
        return out;
      }
      if (pair.opened && !pair.slaves) fail('EIO');
    } else {
      if (pair.masterClosed) return new Uint8Array(0);
      const pipe = pair.terminal.pipe;
      if (!pipe.empty) return pipe.read(count, undefined, pair.terminal.state.canonical);
    }
    return { wait: true, nonblock };
  }
  write(pid, handle, data) {
    const description = this.get(pid, handle), { pair, master, writable, nonblock } = description;
    if (!writable) fail('EBADF');
    if (data.length > 4096) fail('EINVAL');
    if (!master && pair.masterClosed) fail('EIO');
    if (!data.length) return { count: 0 };
    if (master) {
      const tty = pair.terminal;
      // Reserve for echo/control-character expansion and a complete canonical
      // line erase. Retry before mutating the discipline, never after partial input.
      if (tty.queue.length + data.length > 65536 || pair.queued + 32768 > LIMIT || tty.queued + tty.pipe.queued + data.length > LIMIT - 4096)
        return { wait: true, nonblock };
      tty.writeBytes(data);
    } else {
      const output = pair.terminal.state.output(data);
      if (pair.queued + output.length > LIMIT) return { wait: true, nonblock };
      this.output(pair, output);
    }
    return { count: data.length };
  }
  poll(pid, handle, writing) {
    const { pair, master, readable, writable } = this.get(pid, handle);
    if (writing ? !writable : !readable) fail('EBADF');
    const hangup = master ? pair.opened && !pair.slaves : pair.masterClosed;
    const nbytes = writing ? Math.max(0, Math.min(LIMIT - pair.queued - (master ? 32768 : 8192), master ? LIMIT - 8192 - pair.terminal.queued - pair.terminal.pipe.queued : LIMIT))
      : master ? pair.queued : pair.terminal.pipe.queued;
    return { ready: hangup || nbytes > 0 || !writing && !master && pair.terminal.pipe.ending, nbytes, hangup };
  }
  ioctl(pid, handle, request, arg) {
    const { pair, master } = this.get(pid, handle);
    if (request === IOCTL.TIOCGPTN) return { name: pair.terminal.name, number: pair.number };
    if (![IOCTL.TIOCSPTLCK, IOCTL.TIOCGPTLCK].includes(request) || !master) fail('ENOTTY');
    if (request === IOCTL.TIOCSPTLCK) {
      if (!Number.isInteger(arg)) fail('EINVAL');
      pair.locked = arg !== 0; return {};
    }
    return { locked: pair.locked ? 1 : 0 };
  }
}
