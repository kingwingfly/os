import { kernelCall } from './kernel/protocol.js';
import { mountTransport, mountListener } from './mount-transport.js';

export async function shareMount(args, options) {
  const transport = mountListener(options);
  try { return await kernelCall('mount_export', { ...args, port: transport.port }, [transport.port]); }
  catch (error) { transport.close(); throw error; }
}
export async function attachShared(args, options) {
  const transport = mountTransport(options);
  try { return await kernelCall('mount_shared', { ...args, port: transport.port }, [transport.port]); }
  catch (error) { transport.close(); throw error; }
}
export const sharedMounts = () => kernelCall('mount_exports');
export const revokeMount = id => kernelCall('mount_revoke', { export: id });
export const mountTransports = () => kernelCall('mount_transports');

export async function sharingDialog() {
  const { openMountManager } = await import('./mount-manager.js');
  openMountManager('sharing');
}
