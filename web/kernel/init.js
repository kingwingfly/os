// The init host lease belongs to the Machine, independently of cookie login sessions.
// Its proof stays in this dedicated Worker. Public status never authorizes execution.
export class InitCoordinator {
  constructor({ call, host, proof, changed = () => {}, now = () => performance.now() }) {
    Object.assign(this, { call, host, proof, changed, now });
    this.epoch = 0; this.retired = new Map(); this.until = 0;
  }
  current() {
    const connected = !!this.connected && this.now() < this.until;
    return { host: this.host, init: this.view ?? null, connected,
      coordinator: connected && !!this.ownership && !this.view?.shutdown };
  }
  notify() { this.changed(this.current()); }
  retire(owner) { if (owner) this.retired.set(`${owner.boot}/${owner.generation}`, owner); }
  async cleanup() {
    for (const [key, owner] of this.retired) {
      this.retired.delete(key);
      try { await this.call({ op: 'release', owner }); } catch { /* the lease still expires */ }
    }
  }
  async stop() {
    this.stopped = true; this.epoch++;
    this.retire(this.ownership); this.ownership = null; this.connected = false;
    clearTimeout(this.deadline); this.notify();
    await this.pending; await this.cleanup();
  }
  resume() {
    this.stopped = false;
    return (this.pending ?? Promise.resolve()).then(() => this.tick());
  }
  tick() {
    if (this.stopped) return Promise.resolve(this.current());
    return this.pending ??= this.step().finally(() => { this.pending = null; });
  }
  async step() {
    const epoch = this.epoch, started = this.now();
    let owned = null;
    await this.cleanup();
    if (epoch !== this.epoch || this.stopped) return this.current();
    try {
      let view;
      if (this.ownership) {
        try { view = await this.call({ op: 'renew', owner: this.ownership }); owned = this.ownership; }
        catch (error) {
          if (!['ESTALE', 'EACCES'].includes(error.errno)) throw error;
          this.ownership = null;
        }
      }
      view ??= await this.call({ op: 'inspect' });
      if (epoch !== this.epoch || this.stopped) {
        this.retire(owned); await this.cleanup(); return this.current();
      }
      if (!owned && (view.owner === null || view.owner === this.host)) {
        const owner = { boot: view.boot, host: this.host, proof: this.proof, generation: view.generation };
        try {
          // Renew also recovers a claim whose success response was lost in transit.
          view = await this.call({ op: view.owner === null ? 'claim' : 'renew', owner });
          owned = { ...owner, generation: view.generation };
        } catch (error) {
          if (!['ESTALE', 'EBUSY', 'EACCES'].includes(error.errno)) throw error;
          view = await this.call({ op: 'inspect' });
        }
      }
      if (epoch !== this.epoch || this.stopped) {
        this.retire(owned); await this.cleanup(); return this.current();
      }
      this.view = view; this.ownership = owned; this.connected = true;
      // Account for request latency and whole-second server timestamps. A suspended
      // host cannot keep cached ownership merely because its timer did not run.
      const expires = owned ? view.owner_expires : view.now + view.lease;
      this.until = started + Math.max(0, expires - view.now - 1) * 1000;
      clearTimeout(this.deadline);
      this.deadline = setTimeout(() => this.notify(), Math.max(0, this.until - this.now()));
      this.notify(); return this.current();
    } catch {
      if (epoch === this.epoch && !this.stopped) { this.connected = false; this.notify(); }
      return this.current();
    }
  }
}

// A kernel tolerates at most three failed boot attempts. Losing ownership cancels local execution;
// each completion releases only the captured generation, never a successor's lease.
export class InitReaper {
  constructor({ start, release, token, changed = () => {}, exhausted = () => {} }) {
    Object.assign(this, { start, release, token, changed, exhausted });
    this.attempts = 0; this.failures = 0; this.state = 'waiting';
  }
  current() { return { state: this.state, attempts: this.attempts, error: this.error ?? null }; }
  update(status, owner) {
    const boot = status.init?.boot ?? owner?.boot;
    if (boot && boot !== this.boot) {
      this.boot = boot; this.attempts = 0; this.failures = 0; this.error = null;
    }
    const key = status.coordinator && owner ? `${owner.boot}/${owner.generation}` : null;
    if (this.run && this.run.key !== key) this.run.cancelled = true;
    if (!key || this.run || this.failures >= 3) return;
    const run = { key, owner: { ...owner }, cancelled: false };
    this.run = run; this.attempts++; this.state = 'loading'; this.error = null;
    this.changed();
    run.done = (async () => {
      try {
        await this.start(run.owner, this.token(), () => run.cancelled, () => {
          if (!run.cancelled) { this.state = 'running'; this.changed(); }
        });
        this.state = run.cancelled ? 'stopped' : 'failed';
        if (!run.cancelled) { this.failures++; this.error = 'init exited'; }
      } catch (error) {
        this.state = run.cancelled ? 'stopped' : 'failed';
        if (!run.cancelled) { this.failures++; this.error = error.detail ?? error.message ?? error.errno ?? 'init failed'; }
      } finally {
        try { await this.release(run.owner); } catch { /* the lease still expires */ }
        if (this.run === run) this.run = null;
        this.changed();
        if (this.failures >= 3) this.exhausted();
      }
    })();
  }
}
