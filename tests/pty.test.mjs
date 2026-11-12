import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Pty, TtyState, TtyControl, LF, OF, CC } from '../web/kernel/pty.js';

const decode = data => new TextDecoder().decode(data);
test('the open terminal master retains input between slave readers', () => {
  const tty = new Pty();
  try {
    tty.pipe.hold(10, 'r'); tty.pipe.drop(10, 'r');
    assert.equal(tty.pipe.readerGone, false);
    const settings = tty.state.termios; settings.lflag &= ~LF.ECHO; tty.configure(settings);
    tty.write('secret-text\r');
    tty.pipe.hold(11, 'r');
    assert.equal(tty.pipe.queued, 12);
    assert.equal(decode(tty.pipe.read(100, null, true)), 'secret-text\n');
    tty.pipe.drop(11, 'r'); tty.close();
    assert.equal(tty.pipe.readerGone, true); assert.equal(tty.pipe.writerGone, true);
    assert.equal(tty.pipe.held('r'), 0); assert.equal(tty.pipe.held('w'), 0);
  } finally { tty.close(); }
});
test('concurrent PTYs share saved terminal modes without sharing ownership or foreground groups', () => {
  const state = TtyState.create(), a = new Pty({ state }), b = new Pty({ state });
  try {
    a.session = 10; a.control.pgrp = 11;
    b.session = 20; b.control.pgrp = 21;
    const inherited = new TtyControl(a.transferable.control);
    a.control.pgrp = 12;
    assert.equal(inherited.pgrp, 12); assert.equal(inherited.session, 10);
    assert.equal(b.control.pgrp, 21); assert.equal(b.session, 20);
    const settings = state.termios; settings.lflag &= ~LF.ECHO; a.configure(settings);
    assert.equal(b.state.echo, false);
    a.session = 0; a.control.pgrp = 0;
    assert.equal(inherited.session, 0); assert.equal(b.session, 20);
    a.close(); assert.equal(inherited.hungup, true); assert.equal(b.control.hungup, false);
  } finally { a.close(); b.close(); }
});
test('canonical PTY editing, Unicode erase, one line per read and EOF without closing', () => {
  let echo = ''; const tty = new Pty({ echo: text => { echo += text; } });
  try {
    tty.write('one界\x7f!'); assert.equal(tty.pipe.queued, 0);
    tty.write('\rsecond\r');
    assert.equal(decode(tty.pipe.read(100, null, true)), 'one!\n');
    assert.equal(decode(tty.pipe.read(100, null, true)), 'second\n');
    assert.ok(echo.includes('界\b \b'));
    tty.write('partial\x04'); assert.equal(decode(tty.pipe.read(100)), 'partial');
    assert.equal(tty.pipe.ending, false);
    tty.eof(); assert.equal(tty.pipe.read(100).length, 0); assert.equal(tty.pipe.writerGone, false);
    tty.write('again\r'); assert.equal(decode(tty.pipe.read(100)), 'again\n');
  } finally { tty.close(); }
});
test('raw/no-echo and ISIG are independent; a signal flushes pending input', () => {
  let echo = ''; const signals = [];
  const tty = new Pty({ echo: s => { echo += s; }, signal: n => signals.push(n) });
  try {
    tty.write('discard\x03'); assert.deepEqual(signals, [2]); assert.deepEqual(tty.line, []);
    const settings = tty.state.termios; settings.lflag &= ~(LF.ICANON | LF.ECHO | LF.ISIG);
    tty.configure(settings); const before = echo;
    tty.write('x\x03\x04\x1a'); assert.equal(decode(tty.pipe.read(100)), 'x\x03\x04\x1a');
    assert.equal(echo, before); assert.deepEqual(signals, [2]);
    settings.lflag |= LF.ISIG; tty.configure(settings); tty.write('\x1a'); assert.deepEqual(signals, [2, 20]);
  } finally { tty.close(); }
});
test('slave termios/winsize remain shared, and output processing honors OPOST', () => {
  const original = TtyState.create({ columns: 95, rows: 32 });
  const fork = new TtyState(original.buffer);
  original.resize({ columns: 120, rows: 40 }); assert.equal(fork.size.columns, 120);
  const settings = fork.termios; settings.lflag &= ~LF.ECHO; settings.cc[CC.VMIN] = 4; fork.configure(settings);
  assert.equal(original.echo, false); assert.equal(original.cc(CC.VMIN), 4);
  assert.equal(decode(original.output(new TextEncoder().encode('a\nb'))), 'a\r\nb');
  settings.oflag &= ~OF.OPOST; original.configure(settings);
  assert.equal(decode(fork.output(new TextEncoder().encode('a\nb'))), 'a\nb');
  assert.throws(() => original.resize({ columns: 0, rows: 2 }), /EINVAL/);
  assert.throws(() => original.configure({ ...settings, iflag: 0x8000 }), /EOPNOTSUPP/);
  assert.throws(() => original.configure({ ...settings, cflag: 0 }), /EOPNOTSUPP/);
});
