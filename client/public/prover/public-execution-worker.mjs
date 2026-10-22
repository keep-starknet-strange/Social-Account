import init, {
  allocation_metrics,
  public_preexecute,
  run_virtual_os,
} from "./auth/browser_virtual_os.js";
import {
  AnchoredRpc,
  liveTransport,
  replayProvider,
  digest,
} from "./anchored-rpc.mjs";
import { preparePublicInvocation } from "./public-pipeline.mjs";
const encode = (v) => new TextEncoder().encode(JSON.stringify(v));
self.onmessage = async (event) => {
  // Dedicated Worker messages have an empty origin and no Window source.
  // Reject window-style and synthetic events before reading their payload.
  if (event.origin !== "" || event.source !== null || !event.isTrusted) return;
  if (!event.data || typeof event.data !== "object") return;
  const { id, request, source } = event.data;
  const start = performance.now(),
    send = (data) => self.postMessage({ id, ...data });
  try {
    if (!request || !source)
      throw Error("A signed execution request and state source are required");
    const wasm = await init(),
      init_ms = performance.now() - start;
    const rpc = source.capture
      ? await replayProvider(source.capture)
      : new AnchoredRpc(liveTransport(source.endpoint), {
          endpoint: source.endpoint,
        });
    // Replay must use the exact discovery request saved in the capture.
    const discovery = source.capture?.records.find(
      (r) => r.method === "starknet_getBlockWithTxHashes",
    );
    await rpc.resolve(
      discovery?.params.block_id ?? source.block_id ?? "latest",
    );
    send({
      kind: "phase",
      phase: "authenticated acquisition and execution",
      anchor: rpc.anchor,
    });
    const t = performance.now(),
      prepared = await preparePublicInvocation(public_preexecute, rpc, request);
    const acquisition_execution_witness_ms = performance.now() - t;
    send({ kind: "phase", phase: "virtual OS and PIE" });
    const osStart = performance.now(),
      result = run_virtual_os(encode(prepared.result.hints));
    let pie, output;
    try {
      pie = result.pie_bytes();
      output = JSON.parse(result.output_json());
    } finally {
      result.free();
    }
    const virtual_os_ms = performance.now() - osStart;
    const sha = async (b) =>
      Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", b)),
        (x) => x.toString(16).padStart(2, "0"),
      ).join("");
    const report = {
      runtime: "browser Worker wasm32",
      userAgent: navigator.userAgent,
      init_ms,
      acquisition_execution_witness_ms,
      virtual_os_ms,
      total_ms: performance.now() - start,
      wasm_linear_memory_bytes: wasm.memory.buffer.byteLength,
      ...JSON.parse(allocation_metrics()),
      process_rss_bytes: null,
      pie_bytes: pie.byteLength,
      pie_sha256: await sha(pie),
      request_sha256: await digest(request),
      capture_sha256: prepared.capture.sha256,
      scope:
        "Browser public-state invocation execution and PIE; recursive proof verification and network admission separate",
    };
    self.postMessage(
      {
        id,
        kind: "execution",
        ok: true,
        pie: pie.buffer,
        output,
        execution: prepared.result.execution,
        proof_input: prepared.proofInput,
        class_input: prepared.classInput,
        capture: prepared.capture,
        request,
        anchor: rpc.anchor,
        report,
      },
      [pie.buffer],
    );
  } catch (error) {
    send({
      kind: "error",
      ok: false,
      error: String(error),
      stack: error.stack,
    });
  }
};
