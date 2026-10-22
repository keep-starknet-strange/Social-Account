import { loadMemory64 } from "./sequencer-memory64.mjs";
import { PROVER_BUILDS } from "./prover-builds.mjs";
self.onmessage = async (event) => {
  // Dedicated Worker messages have an empty origin and no Window source.
  // Reject window-style and synthetic events before reading their payload.
  if (event.origin !== "" || event.source !== null || !event.isTrusted) return;
  if (!event.data || typeof event.data !== "object") return;
  const { id, pie, expectedWasm, build = "standard" } = event.data;
  const start = performance.now(),
    send = (data) => self.postMessage({ id, ...data });
  try {
    if (!(pie instanceof ArrayBuffer) || !pie.byteLength)
      throw Error("Missing browser-generated PIE");
    if (!Object.hasOwn(PROVER_BUILDS, build))
      throw Error("Unknown prover build");
    const loadStarted = performance.now();
    const api = await loadMemory64(
      PROVER_BUILDS[build].url,
      (message) => send({ kind: "panic", message }),
      (stage) => send({ kind: "stage", ...stage }),
      // Always hash the module so every receipt records which bytes proved it.
      expectedWasm ?? {
        sha256: PROVER_BUILDS[build].sha256,
        bytes: PROVER_BUILDS[build].bytes,
      },
    );
    const load_ms = performance.now() - loadStarted;
    let t = performance.now();
    api.init();
    const init_ms = performance.now() - t;
    send({ kind: "phase", phase: "recursive proving" });
    t = performance.now();
    const result = api.prove(new Uint8Array(pie)),
      prove_ms = performance.now() - t;
    const sha = async (b) =>
      Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", b)),
        (x) => x.toString(16).padStart(2, "0"),
      ).join("");
    send({
      kind: "proof",
      ok: true,
      proof: Array.from(result.proof),
      output_preimage: result.output_preimage,
      report: {
        runtime: "browser Worker memory64",
        prover_build: build,
        ...api.identity,
        userAgent: navigator.userAgent,
        pie_sha256: await sha(pie),
        proof_sha256: await sha(result.proof),
        proof_bytes: result.proof.length,
        load_ms,
        init_ms,
        prove_ms,
        total_ms: performance.now() - start,
        ...api.memory(),
        scope:
          "Sequencer transaction-service 3035dd recursive proving; native verification separate",
      },
    });
  } catch (error) {
    send({
      kind: "error",
      ok: false,
      error: String(error),
      stack: error.stack,
    });
  }
};
