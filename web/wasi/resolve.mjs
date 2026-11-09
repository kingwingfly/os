// Shared candidate construction for shell launches and WASIX execvp-style calls.
export function execCandidates(name, path = '/usr/bin') {
  return name.includes('/') ? [name]
    : path.split(':').map(directory => `${directory || '.'}/${name}`);
}

// execvp's user-space PATH search. Every candidate still goes through execve authorization.
// A failed candidate creates no process. Successful stages are retained while peers search.
export async function resolveExecs(stages, launch, release = async () => {}) {
  const results = new Array(stages.length);
  let pending = stages.map((stage, index) => {
    const name = stage.path ?? stage.argv?.[0] ?? '';
    const path = stage.env?.find(value => value.startsWith('PATH='))?.slice(5) ?? '/usr/bin';
    const candidates = execCandidates(name, path);
    return { stage, index, candidates, at: 0, denied: null };
  });
  try {
    while (pending.length) {
      const replies = await launch(pending.map(({ stage, candidates, at }) => ({ ...stage, path: candidates[at] })));
      const again = [];
      pending.forEach((request, i) => {
        const result = replies[i] ?? { err: { errno: 'EIO' } };
        if (result.err?.errno === 'EACCES') request.denied = result;
        if (['ENOENT', 'ENOTDIR', 'EACCES'].includes(result.err?.errno)) {
          if (++request.at < request.candidates.length) { again.push(request); return; }
          results[request.index] = request.denied ?? result;
        } else {
          results[request.index] = result;
        }
      });
      pending = again;
    }
    return results;
  } catch (error) {
    await Promise.allSettled(results.filter(result => result?.ok).map(result => release(result.ok)));
    throw error;
  }
}
