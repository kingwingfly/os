// A PTY's master belongs to the dedicated client kernel. Only its slave buffers reach
// process Workers. Termios and winsize are shared across fork and exec, like a tty device.
import { PAGE, Pipe, pipeBuffer } from '../wasi/pipe.js';

export const IOCTL = { TCGETS: 0x5401, TCSETS: 0x5402, TCSETSW: 0x5403, TCSETSF: 0x5404,
  TIOCSCTTY: 0x540e, TIOCNOTTY: 0x5422, TIOCGSID: 0x5429,
  TIOCGPGRP: 0x540f, TIOCSPGRP: 0x5410, TIOCGWINSZ: 0x5413, TIOCSWINSZ: 0x5414,
  TIOCGPTN: 0x80045430, TIOCSPTLCK: 0x40045431, TIOCGPTLCK: 0x80045439 };
export const IF = { IGNCR: 128, ICRNL: 256, INLCR: 64 };
export const OF = { OPOST: 1, ONLCR: 4 };
export const LF = { ISIG: 1, ICANON: 2, ECHO: 8, ECHOE: 16, ECHOK: 32, ECHONL: 64, NOFLSH: 128, TOSTOP: 256, ECHOCTL: 512 };
export const CC = { VINTR: 0, VQUIT: 1, VERASE: 2, VKILL: 3, VEOF: 4, VTIME: 5, VMIN: 6, VSUSP: 10 };
const IFLAG = 0, OFLAG = 1, LFLAG = 2, COLS = 3, ROWS = 4, WIDTH = 5, HEIGHT = 6, CONTROL = 8;
const encoder = new TextEncoder();
const error = errno => Object.assign(new Error(errno), { errno });

export class TtyState {
  constructor(buffer) { this.buffer = buffer; this.words = new Int32Array(buffer); }
  static create({ columns = 80, rows = 24, width = 0, height = 0 } = {}) {
    const state = new TtyState(new SharedArrayBuffer(40 * 4));
    state.set(IFLAG, IF.ICRNL); state.set(OFLAG, OF.OPOST | OF.ONLCR);
    state.set(LFLAG, LF.ISIG | LF.ICANON | LF.ECHO | LF.ECHOE | LF.ECHOK | LF.ECHOCTL);
    for (const [cc, value] of [[CC.VINTR, 3], [CC.VQUIT, 28], [CC.VERASE, 127], [CC.VKILL, 21], [CC.VEOF, 4], [CC.VMIN, 1], [CC.VSUSP, 26]]) state.set(CONTROL + cc, value);
    state.resize({ columns, rows, width, height });
    return state;
  }
  get(index) { return Atomics.load(this.words, index); }
  set(index, value) { Atomics.store(this.words, index, value); }
  get canonical() { return !!(this.get(LFLAG) & LF.ICANON); }
  get echo() { return !!(this.get(LFLAG) & LF.ECHO); }
  cc(index) { return this.get(CONTROL + index); }
  matches(index, byte) { return this.cc(index) !== 0 && this.cc(index) === byte; }
  get size() { return { columns: this.get(COLS), rows: this.get(ROWS), width: this.get(WIDTH), height: this.get(HEIGHT) }; }
  resize({ columns, rows, width = 0, height = 0 }) {
    for (const value of [columns, rows, width, height]) if (!Number.isInteger(value) || value < 0 || value > 65535) throw error('EINVAL');
    if (!columns || !rows) throw error('EINVAL');
    for (const [index, value] of [[COLS, columns], [ROWS, rows], [WIDTH, width], [HEIGHT, height]]) this.set(index, value);
  }
  get termios() { return { iflag: this.get(IFLAG), oflag: this.get(OFLAG), cflag: 0xb0, lflag: this.get(LFLAG), cc: Array.from({ length: 32 }, (_, n) => this.cc(n)) }; }
  configure(termios) {
    if (!termios || !Array.isArray(termios.cc) || termios.cc.length !== 32 ||
      termios.cc.some(n => !Number.isInteger(n) || n < 0 || n > 255) ||
      ['iflag', 'oflag', 'cflag', 'lflag'].some(key => !Number.isInteger(termios[key]) || termios[key] < 0 || termios[key] > 0xffffffff)) throw error('EINVAL');
    // Refuse unsupported modes rather than claiming to implement flow/parity/baud control.
    if (termios.cflag !== 0xb0 || (termios.iflag & ~(IF.IGNCR | IF.ICRNL | IF.INLCR)) || (termios.oflag & ~(OF.OPOST | OF.ONLCR)) ||
      (termios.lflag & ~Object.values(LF).reduce((a, b) => a | b, 0))) throw error('EOPNOTSUPP');
    this.set(IFLAG, termios.iflag); this.set(OFLAG, termios.oflag); this.set(LFLAG, termios.lflag);
    termios.cc.forEach((n, index) => this.set(CONTROL + index, n));
  }
  wasix(view, ptr, descriptors) {
    const size = this.size;
    [size.columns, size.rows, size.width, size.height].forEach((n, i) => view.setUint32(ptr + i * 4, n, true));
    descriptors.forEach((tty, n) => view.setUint8(ptr + 16 + n, tty ? 1 : 0));
    view.setUint8(ptr + 19, this.echo ? 1 : 0); view.setUint8(ptr + 20, this.canonical ? 1 : 0);
    view.setUint8(ptr + 21, this.get(IFLAG) & IF.IGNCR ? 1 : 0);
    view.setUint16(ptr + 22, 0, true);
  }
  output(data) {
    if ((this.get(OFLAG) & (OF.OPOST | OF.ONLCR)) !== (OF.OPOST | OF.ONLCR)) return data;
    const extra = data.reduce((n, byte) => n + (byte === 10), 0);
    if (!extra) return data;
    const out = new Uint8Array(data.length + extra);
    let at = 0;
    for (const byte of data) { if (byte === 10) out[at++] = 13; out[at++] = byte; }
    return out;
  }
}

// Ownership belongs to one PTY, independently of the terminal tab's saved modes.
// Only the client kernel changes it; process Workers read it at job-control checks.
export class TtyControl {
  constructor(buffer = new SharedArrayBuffer(12)) { this.buffer = buffer; this.words = new Int32Array(buffer); }
  get pgrp() { return Atomics.load(this.words, 0); }
  set pgrp(value) { Atomics.store(this.words, 0, value); }
  get session() { return Atomics.load(this.words, 1); }
  set session(value) { Atomics.store(this.words, 1, value); }
  get hungup() { return !!Atomics.load(this.words, 2); }
  set hungup(value) { Atomics.store(this.words, 2, value ? 1 : 0); }
}

export class Pty {
  constructor({ state = TtyState.create(), echo = () => {}, signal = () => {}, mode = () => {} } = {}) {
    this.state = state; this.echo = echo; this.signal = signal; this.mode = mode;
    this.control = new TtyControl();
    this.pipe = new Pipe(pipeBuffer()); this.pipe.hold(PAGE, 'w');
    // The master owns the input buffer even between slave readers. A pipeline's
    // first stage may exit before a later stage opens its controlling terminal.
    this.pipe.hold(PAGE, 'r');
    this.line = []; this.queue = []; this.queued = 0; this.timer = null; this.closed = false;
  }
  get session() { return this.control.session; }
  set session(value) { this.control.session = value; }
  get transferable() { return { state: this.state.buffer, control: this.control.buffer, input: this.pipe.buffer, number: this.number }; }
  pump() {
    this.timer = null;
    if (this.closed || this.pipe.readerGone) { this.queue = []; this.queued = 0; return; }
    while (this.queue.length) {
      if (this.pipe.ending) break;
      const next = this.queue[0];
      if (next === null) { this.pipe.endOfFile(); this.queue.shift(); continue; }
      const count = this.pipe.put(next); this.queued -= count;
      if (count < next.length) { this.queue[0] = next.subarray(count); break; }
      this.queue.shift();
    }
    if (this.queue.length) this.timer = setTimeout(() => this.pump(), 10);
  }
  enqueue(data) {
    if (this.closed) return;
    if (this.queue.length >= 65536 || this.queued + (data?.length ?? 0) > 1024 * 1024) throw error('EAGAIN');
    this.queue.push(data); this.queued += data?.length ?? 0;
    if (this.timer === null) this.pump();
  }
  flushLine() { if (this.line.length) { this.enqueue(Uint8Array.from(this.line)); this.line = []; } }
  erase() {
    if (!this.line.length) return;
    // Remove one UTF-8 character, keeping a pasted Unicode line valid.
    let at = this.line.length - 1;
    while (at > 0 && (this.line[at] & 0xc0) === 0x80) at--;
    const removed = this.line.splice(at);
    if (this.state.echo && this.state.get(LFLAG) & LF.ECHOE) this.echo('\b \b'.repeat(removed[0] < 32 ? 2 : 1));
  }
  write(text) {
    return this.writeBytes(encoder.encode(text));
  }
  writeBytes(data) {
    if (this.closed) return;
    if (this.queued + data.length > 1024 * 1024) throw error('EAGAIN');
    for (let byte of data) {
      const local = this.state.get(LFLAG), input = this.state.get(IFLAG);
      if (byte === 13) { if (input & IF.IGNCR) continue; if (input & IF.ICRNL) byte = 10; }
      else if (byte === 10 && input & IF.INLCR) byte = 13;
      const signal = local & LF.ISIG ? [[CC.VINTR, 2], [CC.VQUIT, 3], [CC.VSUSP, 20]].find(([cc]) => this.state.matches(cc, byte))?.[1] : null;
      if (signal) {
        if (!(local & LF.NOFLSH)) { this.line = []; this.queue = []; this.queued = 0; this.pipe.discard(); }
        if (local & LF.ECHO) this.echo(`^${String.fromCharCode(byte + 64)}\r\n`);
        this.signal(signal); continue;
      }
      if (this.state.canonical) {
        if (this.state.matches(CC.VERASE, byte) || byte === 8) { this.erase(); continue; }
        if (this.state.matches(CC.VKILL, byte)) { while (this.line.length) this.erase(); continue; }
        if (this.state.matches(CC.VEOF, byte)) { this.eof(); continue; }
        if (this.line.length >= 4095 && byte !== 10) continue;
        this.line.push(byte);
      } else this.enqueue(Uint8Array.of(byte));
      if (local & LF.ECHO || byte === 10 && local & LF.ECHONL) {
        // Decode as a stream so multi-byte input is echoed once, without replacement chars.
        this.decoder ??= new TextDecoder();
        const shown = byte === 10 ? '\r\n' : byte < 32 && byte !== 9 && local & LF.ECHOCTL ? `^${String.fromCharCode(byte + 64)}` : this.decoder.decode(Uint8Array.of(byte), { stream: true });
        if (shown) this.echo(shown);
      }
      if (this.state.canonical && byte === 10) this.flushLine();
    }
  }
  eof() { if (this.line.length) this.flushLine(); else this.enqueue(null); }
  configure(termios, flush = false) {
    this.state.configure(termios);
    if (flush) { this.line = []; this.queue = []; this.queued = 0; this.pipe.discard(); }
    else if (!this.state.canonical) this.flushLine();
    this.mode({ raw: !this.state.canonical, echo: this.state.echo });
  }
  close() { this.closed = true; this.control.hungup = true; clearTimeout(this.timer); this.queue = []; this.line = []; this.pipe.release(PAGE); }
}
