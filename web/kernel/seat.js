// A browser execution host owns one local input seat. The owning kernel port and
// explicit console grants authorize access; these public stamps only fence reuse.
export class SeatDevices {
  constructor({ limit = 128, id = () => crypto.randomUUID() } = {}) {
    this.id = id(); this.nextId = id; this.limit = limit;
    this.generation = 1; this.active = true; this.devices = new Map();
  }
  current() {
    return { id: this.id, generation: this.generation, active: this.active,
      devices: [...this.devices.values()].map(({ id, kind }) => ({ id, kind })) };
  }
  open(kind) {
    if (!['console', 'attachment'].includes(kind)) throw { errno: 'EINVAL', detail: 'unsupported seat device' };
    if (this.devices.size >= this.limit) throw { errno: 'ENOSPC', detail: 'too many seat devices' };
    const device = { id: this.nextId(), kind };
    this.devices.set(device.id, device); return device;
  }
  close(device) { if (device && this.devices.get(device.id) === device) this.devices.delete(device.id); }
  stamp(device) { return { seat: this.id, generation: this.generation, device: device.id }; }
  change(active, expected) {
    if (typeof active !== 'boolean') throw { errno: 'EINVAL', detail: 'seat activity must be boolean' };
    if (expected?.id !== this.id || expected.generation !== this.generation)
      throw { errno: 'ESTALE', detail: 'seat activation has changed' };
    if (active !== this.active) {
      if (this.generation === Number.MAX_SAFE_INTEGER) throw { errno: 'ENOSPC', detail: 'seat generation exhausted' };
      this.generation++; this.active = active;
    }
    return this.current();
  }
  check(device, stamp) {
    if (!device || this.devices.get(device.id) !== device) throw { errno: 'ENODEV', detail: 'seat device is closed' };
    if (stamp?.seat !== this.id || stamp.generation !== this.generation || stamp.device !== device.id)
      throw { errno: 'ESTALE', detail: 'seat device activation has changed' };
    if (!this.active) throw { errno: 'EACCES', detail: 'terminal input is paused' };
  }
}
