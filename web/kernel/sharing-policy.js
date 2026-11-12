// The authenticated login refresh supplies policy. A preference limits explicit
// MessagePort grants; neither a public revision nor a device ID grants access.
export function sharingAllowed(status, access) {
  if (!status?.connected || status.session?.shutdown) return false;
  const mode = status.session?.seat_policy?.sharing;
  return mode === 'control' || mode === 'view' && access === 'view';
}
