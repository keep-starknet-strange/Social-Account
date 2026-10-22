// Can this browser run the prover? Kept apart from local-prover.ts so an app can ask before
// login without loading garaga and the prover glue.

export type ProverBuild = 'standard' | 'memory';

/** The smallest valid module with a memory64 memory: `(module (memory i64 1))`. */
const MEMORY64_MODULE = new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 5, 3, 1, 4, 1]);

export function localProvingSupport(): { ok: true } | { ok: false; reason: string } {
  if (typeof Worker === 'undefined') return { ok: false, reason: 'Web Workers are not available' };
  if (typeof WebAssembly === 'undefined' || !WebAssembly.validate(MEMORY64_MODULE))
    return { ok: false, reason: 'WebAssembly memory64 is not supported (desktop Chromium is)' };
  return { ok: true };
}

/**
 * Mirror of the prover's own `recommendedBuild`: the standard build needs about 14 GB of wasm
 * memory, so it is suggested only on 32 GB+ machines. `deviceMemory` is a coarse hint and absent
 * outside Chromium. The user may still pick either build.
 */
export function recommendedBuild(): ProverBuild {
  return ((navigator as { deviceMemory?: number }).deviceMemory ?? 0) >= 32 ? 'standard' : 'memory';
}
