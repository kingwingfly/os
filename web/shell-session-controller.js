// Owns one real interactive shell per page. Cookie changes never rewrite its credentials.
export class ShellSession {
  constructor({ identity, execute, close, emit, expectedSession, setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = id => clearTimeout(id) }) {
    Object.assign(this, { identity, execute, close, emit, expectedSession, setTimer, clearTimer });
    this.message = ''; this.run = null;
  }
  notify() {
    const run = this.run;
    this.emit({ type: 'status', text: this.message, live: !!run, restartable: !this.expectedSession,
      input: !!run?.input && !run.stopping && !run.stopped && (!this.expectedSession || run.ready), stopped: !!run?.stopped });
  }
  start() {
    if (this.run) return this.run.done;
    const run = { input: null, job: null, stopping: false, stopped: false, ready: false };
    this.run = run; this.message = 'Starting shell…';
    this.emit({ type: 'reset' }); this.notify();
    run.done = this.launch(run);
    return run.done;
  }
  async launch(run) {
    try {
      const who = await this.identity();
      if (run.stopping) { this.message = 'Shell ended'; return { status: 130 }; }
      const result = await this.execute([['/usr/bin/sh', '-i']], {
        cwd: who.home, home: who.home, user: who.user, stdin: null, tty: true, terminalId: 'session-shell',
        expectedSession: this.expectedSession,
        // Once dash is reading, let its HUP handler finish. Cancelling the host run
        // would inject SIGINT while that cleanup is still doing filesystem I/O.
        cancelled: () => run.stopping && (!run.ready || !!run.hardStop),
        onOutput: (_fd, text) => { if (this.run === run) this.emit({ type: 'output', text }); },
        onMode: mode => { if (this.run === run) this.emit({ type: 'mode', echo: mode.echo }); },
        onSize: size => { if (this.run === run) this.emit({ type: 'size', columns: size.columns, rows: size.rows }); },
        onTty: input => {
          if (this.run !== run) return;
          run.input = input;
          if (!run.stopping && (!this.expectedSession || run.ready)) this.message = run.stopped ? 'Shell stopped' : '';
          this.notify();
        },
        onReading: () => {
          if (this.run !== run || run.stopping || run.ready) return;
          run.ready = true; this.message = run.stopped ? 'Shell stopped' : '';
          this.notify(); this.emit({ type: 'ready' });
        },
        onState: state => {
          if (this.run !== run) return;
          run.stopped = state === 'stopped';
          if (!run.stopping) this.message = run.stopped ? 'Shell stopped' : '';
          this.notify();
        },
        onJob: job => { if (this.run !== run) return; run.job = job; if (run.stopping) this.signalStop(run); },
      });
      this.message = `Shell exited (${result.status})`;
      return result;
    } catch (error) {
      this.message = `Shell could not start: ${String(error.message ?? error).slice(0, 256)}`;
      return { status: 126 };
    } finally {
      this.clearTimer(run.deadline);
      if (this.run === run) {
        // A fresh session gets a fresh PTY, including canonical/echo modes.
        this.close('session-shell'); this.run = null; this.notify();
      }
    }
  }
  signalStop(run) {
    if (!run.job) return;
    if (run.hardStop) run.job.signal(9);
    else if (!run.stopSignalled) { run.stopSignalled = true; run.job.signal(1); run.job.signal(18); }
  }
  stop() {
    const run = this.run;
    if (!run || run.stopping) return run?.done;
    run.stopping = true; run.input = null; this.message = 'Ending shell…'; this.notify();
    this.signalStop(run);
    run.deadline = this.setTimer(() => { run.hardStop = true; this.close('session-shell'); run.job?.signal(9); }, 5000);
    return run.done;
  }
  send(operation, text) {
    const run = this.run;
    if (!run || run.stopping) return;
    if (operation === 'resume') { run.job?.signal(18); return; }
    if (!run.input || run.stopped || !['write', 'reply'].includes(operation)) return;
    if (text.length > 65536) { this.message = 'Input is too large; paste a smaller amount.'; this.notify(); return; }
    run.input[operation](text);
  }
}
