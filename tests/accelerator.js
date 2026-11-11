// Public, typed device protocol helpers. No command parsing or privileged test transport.
import { randomUUID } from 'node:crypto';
import { call } from './sys.js';
export const ACCEL = { info: 0x54570100, submit: 0x54570101, poll: 0x54570102,
  answer: 0x54570103, cancel: 0x54570104, detach: 0x54570105, attach: 0x54570106, policy: 0x54570107, configure: 0x54570108 };
export async function device(request, path = '/dev/archive', options = {}) {
  const { fd } = await call(request, { open: { path, flags: 2 } }, options);
  const ioctl = (op, arg) => call(request, { ioctl: { fd, request: ACCEL[op], arg } }, options);
  const control = id => ({
    id, fd,
    poll: (after = 0, limit = 128) => ioctl('poll', { version: 1, id, after, limit }),
    answer: (sequence, decisions) => ioctl('answer', { version: 1, id, sequence, decisions }),
    cancel: () => ioctl('cancel', { version: 1, id }),
    detach: () => ioctl('detach', { version: 1, id }),
    close: () => call(request, { close: { fd } }, options),
  });
  return { fd, ioctl, control,
    attach: async id => { await ioctl('attach', { version: 1, id }); return control(id); },
    submit: async (operation, retry = randomUUID()) => {
      const result = await ioctl('submit', { version: 1, request: retry, operation });
      if ('token' in result || '_launch' in result) throw new Error('executor credential exposed');
      return { ...control(result.id), request: retry };
    },
  };
}
export async function directory(request, path, options = {}) {
  const { fd } = await call(request, { open: { path, flags: 0o10000000 | 0o200000 } }, options);
  return name => ({ directory: fd, name });
}
