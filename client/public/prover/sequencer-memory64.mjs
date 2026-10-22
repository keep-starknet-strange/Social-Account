// Explicit memory64 host ABI. Bounded views avoid constructing a >4-GiB Uint8Array.
export function checkedRange(ptr, len, memoryBytes) {
  if (typeof ptr !== "bigint" || typeof len !== "bigint" ||
      ptr < 0n || len < 0n || ptr > BigInt(Number.MAX_SAFE_INTEGER) ||
      len > 0xffffffffn || ptr + len > BigInt(memoryBytes))
    throw Error("Invalid memory64 pointer/length");
  return [Number(ptr), Number(len)];
}

export async function loadMemory64(url, onPanic, onStage, expectedIdentity) {
  let wasm,
    randomCalls = 0,
    randomBytes = 0;
  const view = (ptr, len) =>
    new Uint8Array(wasm.memory.buffer, ...checkedRange(ptr, len, wasm.memory.buffer.byteLength));
  const text = (ptr, len) => new TextDecoder().decode(view(ptr, len));
  // Unused wasm-bindgen exports are retained by transitive crates. This raw ABI
  // never invokes them. Fail closed if any real execution reaches that machinery.
  const unsupportedBindgen = () => {
    throw Error("Unexpected wasm-bindgen call in raw memory64 ABI");
  };
  const imports = {
    __wbindgen_placeholder__: {
      __wbindgen_describe: unsupportedBindgen,
      __wbg___wbindgen_throw_6b64449b9b9ed33c: unsupportedBindgen,
    },
    __wbindgen_externref_xform__: {
      __wbindgen_externref_table_set_null: unsupportedBindgen,
      __wbindgen_externref_table_grow: unsupportedBindgen,
    },
    browser: {
      random_fill(ptr, len) {
        try {
          const [start, count] = checkedRange(ptr, len, wasm.memory.buffer.byteLength);
          randomCalls++;
          randomBytes += count;
          for (let offset = 0; offset < count; offset += 65536) {
            const size = Math.min(65536, count - offset);
            const random = new Uint8Array(size);
            crypto.getRandomValues(random);
            new Uint8Array(wasm.memory.buffer, start + offset, size).set(
              random,
            );
          }
          return 0;
        } catch {
          return 1;
        }
      },
      report_panic(ptr, len) {
        onPanic(text(ptr, len));
      },
      report_progress(ptr, len) {
        onStage({
          ...JSON.parse(text(ptr, len)),
          wasm_linear_memory_bytes: wasm.memory.buffer.byteLength,
        });
      },
    },
  };
  // Default path: cached streaming compile, unchanged from upstream.
  // Validation path: hash and instantiate the same uncached bytes.
  let identity = {}, result;
  if (!expectedIdentity) {
    const response = await fetch(url);
    if (!response.ok) throw Error(`Wasm HTTP ${response.status}`);
    result = await WebAssembly.instantiateStreaming(response, imports);
  } else {
    // Vendored edit: upstream used cache: "no-store"; the hash check below keeps a cached copy honest.
    const response = await fetch(url);
    if (!response.ok) throw Error(`Wasm HTTP ${response.status}`);
    const bytes = await response.arrayBuffer();
    identity = {
      wasm_bytes: bytes.byteLength,
      wasm_sha256: Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
        (x) => x.toString(16).padStart(2, "0")).join(""),
    };
    if (identity.wasm_sha256 !== expectedIdentity.sha256 ||
        identity.wasm_bytes !== expectedIdentity.bytes)
      throw Error("Prover WASM identity mismatch");
    result = await WebAssembly.instantiate(bytes, imports);
  }
  wasm = result.instance.exports;
  const check = (code) => {
    if (code !== 0)
      throw Error(text(wasm.spike_error_ptr(), wasm.spike_error_len()));
  };
  return {
    identity,
    init() {
      check(wasm.spike_init());
    },
    prove(bytes) {
      const len = BigInt(bytes.length),
        ptr = wasm.spike_alloc(len);
      try {
        view(ptr, len).set(bytes);
        check(wasm.spike_prove(ptr, len));
      } finally {
        wasm.spike_dealloc(ptr, len);
      }
      return {
        proof: view(wasm.spike_proof_ptr(), wasm.spike_proof_len()).slice(),
        output_preimage: JSON.parse(
          text(wasm.spike_output_ptr(), wasm.spike_output_len()),
        ),
      };
    },
    memory() {
      wasm.spike_measure();
      return {
        wasm_linear_memory_bytes: wasm.memory.buffer.byteLength,
        webcrypto_random_calls: randomCalls,
        webcrypto_random_bytes: randomBytes,
        ...JSON.parse(text(wasm.spike_metrics_ptr(), wasm.spike_metrics_len())),
      };
    },
  };
}
