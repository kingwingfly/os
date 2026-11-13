// Check the capabilities the process engine actually uses, not the browser name.
export function executionSupport(scope = globalThis) {
  if (!scope.crossOriginIsolated) return {
    supported: false,
    reason: 'Command execution needs an isolated browser page. Open OS over HTTPS or localhost, and ensure the server enables cross-origin isolation.',
  };
  if (typeof scope.SharedArrayBuffer !== 'function' || typeof scope.Atomics?.wait !== 'function') return {
    supported: false,
    reason: 'This browser does not provide the shared memory needed to run commands. Use a browser with shared-memory support enabled.',
  };
  return { supported: true, reason: '' };
}

export function requireExecutionSupport(scope = globalThis) {
  const support = executionSupport(scope);
  if (!support.supported) throw Object.assign(new Error(support.reason), { errno: 'ENOTSUP' });
}
