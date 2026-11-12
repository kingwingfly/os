// User-space startup orchestration. The Machine admits each run and the ordinary
// supervisor owns unit semantics; neither coordinator metadata nor this loop is a credential.
export class LoginStartup {
  constructor({ begin, execute, finish, token, changed = () => {}, setTimer = (fn, ms) => setTimeout(fn, ms), clearTimer = id => clearTimeout(id) }) {
    Object.assign(this, { begin, execute, finish, token, changed, setTimer, clearTimer });
    this.runs = new Map(); this.completions = new Map(); this.logs = new Map();
  }
  current(status) {
    // Never expose a previous account's output through a replacement login or offline view.
    const session = status.connected ? status.session?.id : null;
    const revision = status.session?.startup?.revision;
    const foundLog = session && this.logs.get(session), foundRun = session && this.runs.get(session);
    const log = foundLog?.revision === revision ? foundLog : null;
    const run = foundRun?.launch.revision === revision ? foundRun : null;
    return { local: !!(run || log), state: run ? (run.stopping ? 'stopping' : run.attached ? 'running' : 'starting') : 'idle',
      output: log?.text ?? '', truncated: log?.truncated ?? false };
  }
  output(run, text) {
    const log = this.logs.get(run.session);
    if (!log || log.revision !== run.launch.revision) return;
    log.text += text;
    if (log.text.length > 8192) {
      let start = log.text.length - 8192;
      const unit = log.text.charCodeAt(start), previous = log.text.charCodeAt(start - 1);
      if (unit >= 0xdc00 && unit <= 0xdfff && previous >= 0xd800 && previous <= 0xdbff) start++;
      log.text = log.text.slice(start); log.truncated = true;
    }
    this.notification ??= this.setTimer(() => { this.notification = null; this.changed(); }, 100);
  }
  async flush() {
    if (this.flushing) return this.flushing;
    this.flushing = (async () => {
      for (const [key, value] of this.completions) {
        try { await this.finish(value); this.completions.delete(key); }
        catch (error) {
          // A superseded revision/expired login has nothing left for this receipt to change.
          if (['ESTALE', 'EACCES', 'EPERM', 'EINVAL'].includes(error.errno)) this.completions.delete(key);
        }
      }
    })();
    try { await this.flushing; } finally { this.flushing = null; }
  }
  update(status) {
    void this.flush();
    const session = status.session;
    for (const run of this.runs.values()) {
      const same = status.connected && session?.id === run.session;
      if (!run.attached && (!same || !status.coordinator || session.generation !== run.expected.generation ||
          session.startup?.revision !== run.launch.revision || !session.startup.enabled)) run.cancelled = true;
      if (run.attached && status.connected && (session?.id !== run.session || session.shutdown) && !run.stopping) {
        run.stopping = true;
        void run.stop?.();
        // Unit shutdown allows at most 30 seconds. Bound a failed supervisor/host too.
        run.deadline = this.setTimer(() => { run.cancelled = true; run.job?.signal(9); }, 35000);
      }
    }
    // Completed logs are bounded to the current login; active old runs keep their private log
    // only until shutdown. Public snapshots above still hide it immediately on login change.
    for (const id of this.logs.keys()) if (id !== session?.id && !this.runs.has(id)) this.logs.delete(id);
    const startup = session?.startup;
    if (!status.coordinator || !startup?.enabled || startup.state !== 'pending' || session.managed ||
        this.runs.has(session.id) || this.completions.has(session.id)) return;
    const run = { session: session.id, expected: { session: session.id, generation: session.generation },
      launch: { revision: startup.revision, proof: this.token() }, file: startup.file,
      cancelled: false, attached: false, stopping: false };
    this.runs.set(run.session, run);
    this.logs.set(run.session, { revision: startup.revision, text: '', truncated: false });
    run.done = this.run(run);
  }
  async run(run) {
    let status = 126, error = null;
    try {
      await this.begin(run.expected, run.launch);
      if (run.cancelled) throw { errno: 'ESTALE', detail: 'login startup ownership changed' };
      const result = await this.execute(run, (fd, text) => this.output(run, text));
      status = result.status;
    } catch (failure) {
      error = String(failure.detail ?? failure.message ?? failure.errno ?? failure).slice(-256);
      this.output(run, `startup: ${error}\n`);
    } finally {
      this.clearTimer(run.deadline);
      this.runs.delete(run.session);
      this.completions.set(run.session, { session: run.session, launch: run.launch, status, error });
      await this.flush();
      this.changed();
    }
  }
}
