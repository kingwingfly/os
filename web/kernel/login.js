export { LoginStartup } from './login-boot.js';
// Login coordination belongs to a dedicated host. Names are public; its membership
// proof stays here and is never returned through the page protocol or a Web Lock.
export class LoginCoordinator {
  constructor({ call, host, proof, changed = () => {}, now = () => performance.now() }) {
    Object.assign(this, { call, host, proof, changed, now });
    this.epoch = 0; this.retired = new Map(); this.until = 0;
  }
  current() {
    const connected = !!this.connected && this.now() < this.until;
    return { host: this.host, session: this.view ?? null, connected,
      coordinator: connected && this.view?.owner === this.host };
  }
  notify() { this.changed(this.current()); }
  capture(expected) {
    const status = this.current();
    if (!status.coordinator || !this.member) throw { errno: 'EACCES', detail: 'this host does not own login service management' };
    if (expected?.session !== this.member.session || expected?.generation !== this.view.generation) {
      throw { errno: 'ESTALE', detail: 'login service ownership changed' };
    }
    return { ...expected, member: { ...this.member }, epoch: this.epoch };
  }
  checked(ticket, view) {
    this.capture(ticket);
    if (ticket.epoch !== this.epoch || view?.id !== ticket.session || view?.generation !== ticket.generation || view?.owner !== this.host) {
      throw { errno: 'ESTALE', detail: 'login service ownership changed' };
    }
    if (view.now >= (this.view?.now ?? 0)) { this.view = view; this.notify(); }
    return view;
  }
  async control(op, values, expected) {
    const ticket = this.capture(expected);
    const view = await this.call({ ...values, op, member: ticket.member, generation: ticket.generation });
    return this.checked(ticket, view);
  }
  retire() {
    if (this.member) this.retired.set(this.member.session, this.member);
    this.member = null; this.view = null; this.connected = false;
    clearTimeout(this.deadline); this.notify();
  }
  async cleanup() {
    for (const [id, member] of this.retired) {
      this.retired.delete(id);
      try { await this.call({ op: 'leave', member }); } catch { /* the server lease still expires */ }
    }
  }
  reset() {
    this.stopped = false; this.epoch++; this.retire();
    return (this.pending ?? Promise.resolve()).then(() => this.tick());
  }
  async stop() {
    this.stopped = true; this.epoch++; this.retire();
    await this.pending; await this.cleanup();
  }
  tick() {
    if (this.stopped) return Promise.resolve(this.current());
    return this.pending ??= this.step().finally(() => { this.pending = null; });
  }
  async step(recover = true) {
    const epoch = this.epoch, started = this.now();
    await this.cleanup();
    if (epoch !== this.epoch || this.stopped) return this.current();
    let member = this.member;
    try {
      let view = await this.call(member
        ? { op: this.view?.owner === this.host ? 'renew' : 'keep', member,
            ...(this.view?.owner === this.host ? { generation: this.view.generation } : {}) }
        : { op: 'join', host: this.host, proof: this.proof });
      member = { session: view.id, host: this.host, proof: this.proof };
      if (epoch !== this.epoch || this.stopped) {
        this.retired.set(member.session, member); await this.cleanup(); return this.current();
      }
      this.member = member;
      if (view.owner === null && !view.shutdown) {
        try { view = await this.call({ op: 'claim', member, generation: view.generation }); }
        catch (error) {
          if (!['ESTALE', 'EBUSY'].includes(error.errno)) throw error;
          view = await this.call({ op: 'keep', member });
        }
      }
      if (epoch !== this.epoch || this.stopped) {
        this.retired.set(member.session, member); await this.cleanup(); return this.current();
      }
      this.view = view; this.connected = true;
      const expires = view.hosts.find(value => value.host === this.host)?.expires ?? view.now;
      const deadline = view.owner === this.host ? Math.min(expires, view.owner_expires) : expires;
      // Request latency counts against the lease. A suspended tab cannot treat a
      // stale cached success as ownership when it wakes, even before its timer runs.
      // Server timestamps are whole seconds; discard their partial second too.
      this.until = started + Math.max(0, deadline - view.now - 1) * 1000;
      clearTimeout(this.deadline);
      this.deadline = setTimeout(() => this.notify(), Math.max(0, this.until - this.now()));
      this.notify(); return this.current();
    } catch (error) {
      if (epoch !== this.epoch || this.stopped) return this.current();
      this.connected = false; this.notify();
      if (member && ['ESTALE', 'EACCES'].includes(error.errno)) {
        this.retire(); await this.cleanup();
        if (recover) return this.step(false);
      }
      return this.current();
    }
  }
}
