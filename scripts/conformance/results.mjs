import { save, generatedFiles } from './common.mjs';

// Complete the essential observations first. Provenance is collected before the
// expensive run, and no remote-tracking ref is needed to publish its results.
export async function saveRun(out,baseline,target,result,provenance,write=save) {
  baseline[target]=result.observations;
  baseline.process[target]=result.process;
  await write(out,generatedFiles.baseline,baseline);
  if(target==='linux') {
    await write(out,generatedFiles.linuxLatency,{schema:1,unit:'milliseconds',build_profile:'release',method:'First invocation and immediate repeat; no page-cache eviction. Release probe, command wall time; shell ends at first prompt.',operations:result.latency});
    await write(out,generatedFiles.linuxEvidence,{...provenance,...result.evidence});
  } else {
    await write(out,generatedFiles.latency,{schema:1,unit:'milliseconds',build_profile:'release',method:'First operation in a fresh filesystem/profile and immediate repeat; browser wall time including process launch and return; release WASI probe and release local-helper. No OS/provider cache eviction.',filesystems:result.latencies});
    await write(out,generatedFiles.evidence,{...provenance,browser:result.browser,diagnostics:result.diagnostics,source:result.evidence,compiler:result.compiler});
  }
}
