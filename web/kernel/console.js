// Console records belong to this execution host. IDs select a local pane, never
// authorize attachment to another host. Running leases cannot be evicted.
import { TtyState } from './pty.js';

export class Consoles {
  constructor(limit = 64) { this.limit = limit; this.entries = new Map(); }
  acquire(key, run, options = {}) {
    let entry = this.entries.get(key);
    if (entry?.closed) throw { errno: 'EPIPE', detail: 'console is closing' };
    if (!entry) {
      if (this.entries.size >= this.limit) {
        const idle = [...this.entries].find(([, value]) => !value.runs.size && !value.closed);
        if (!idle) throw { errno: 'ENOSPC', detail: 'too many active consoles' };
        this.entries.delete(idle[0]);
      }
      entry = { key, state: globalThis.crossOriginIsolated ? TtyState.create(options) : undefined,
        runs: new Set(), active: null, closed: false };
    }
    // Refresh idle-state recency without changing a live console's identity.
    this.entries.delete(key); this.entries.set(key, entry);
    entry.runs.add(run); run.console = entry;
    this.foreground(run, true);
    return entry.state;
  }
  foreground(run, active) {
    const entry = run.console;
    if (!entry || entry.closed) return;
    if (active && entry.active !== run) {
      const previous = entry.active;
      if (previous) { previous.foreground = false; previous.group?.foreground(false); previous.focus?.(false); }
      entry.active = run;
    } else if (!active && entry.active === run) entry.active = null;
    run.foreground = !!active;
    run.group?.foreground(!!active);
    run.focus?.(!!active);
    if (active) run.refresh?.();
  }
  accepts(run, controller = null) { return !run.console?.closed && run.console?.active === run && (run.controller ?? null) === controller; }
  release(run) {
    const entry = run.console;
    if (!entry) return;
    entry.runs.delete(run);
    if (entry.active === run) entry.active = null;
  }
  async close(key) {
    const entry = this.entries.get(key);
    if (!entry) return;
    if (entry.closing) return entry.closing;
    entry.closed = true; entry.active = null;
    entry.closing = Promise.allSettled([...entry.runs].map(run => {
      run.closed = true;
      run.detach?.();
      for (const resolve of run.displayed.values()) resolve();
      run.displayed.clear();
      return run.group?.hangup();
    })).then(() => { if (this.entries.get(key) === entry) this.entries.delete(key); });
    return entry.closing;
  }
}
