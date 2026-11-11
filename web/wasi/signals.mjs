// Standard Linux signals, coalesced while pending. Shared words are host-visible;
// handlers and their masks belong to this image and are copied only by fork.
export const CONTROL_WORDS = 5;
export const bit = signal => 1 << (signal - 1);
export const valid = signal => Number.isInteger(signal) && signal > 0 && signal < 32;
export const unmaskable = bit(9) | bit(19);
export const ignoredByDefault = new Set([17, 23, 28]);
export const stoppedByDefault = new Set([19, 20, 21, 22]);
export const SA_RESTART = 0x10000000, SA_NODEFER = 0x40000000, SA_RESETHAND = 0x80000000;
export class Signals {
  constructor(control, state) {
    this.words = control ?? new Int32Array(CONTROL_WORDS);
    this.actions = state?.actions ?? Array.from({ length: 32 }, () => ({ kind: 0, mask: 0, flags: 0 }));
    this.callback = state?.callback ?? null;
    this.mask = state?.mask ?? 0;
    this.publish();
  }
  publish() {
    let ignored = 0, caught = 0;
    for (let n = 1; n < 32; n++) {
      if (this.actions[n].kind === 1) ignored |= bit(n);
      if (this.actions[n].kind === 2) caught |= bit(n);
    }
    Atomics.store(this.words, 3, ignored); Atomics.store(this.words, 4, caught);
  }
  get mask() { return Atomics.load(this.words, 2); }
  set mask(value) { Atomics.store(this.words, 2, value & 0x7fffffff & ~unmaskable); }
  get pending() { return Atomics.load(this.words, 1) & this.mask; }
  action(n, kind, mask, flags) {
    if (!valid(n) || kind < -1 || kind > 2) return -28;
    if (kind === -1) return this.actions[n].kind;
    if (unmaskable & bit(n) || flags & ~(SA_RESTART | SA_NODEFER | SA_RESETHAND)) return -28;
    this.actions[n] = { kind, mask: mask & ~unmaskable, flags };
    if (kind === 1) Atomics.and(this.words, 1, ~bit(n));
    this.publish(); return 0;
  }
  queue(n) {
    if (!valid(n)) return 28;
    if (!(Atomics.load(this.words, 3) & bit(n))) Atomics.or(this.words, 1, bit(n));
    return 0;
  }
  take() {
    const ready = Atomics.load(this.words, 1) & ~this.mask;
    if (!ready) return null;
    const n = 32 - Math.clz32(ready & -ready);
    Atomics.and(this.words, 1, ~bit(n));
    return { n, ...this.actions[n] };
  }
  snapshot() { return { actions: structuredClone(this.actions), mask: this.mask, callback: this.callback }; }
  exec() {
    this.callback = null;
    this.actions = this.actions.map(action => action.kind === 1 ? action : { kind: 0, mask: 0, flags: 0 });
    this.publish();
  }
}
