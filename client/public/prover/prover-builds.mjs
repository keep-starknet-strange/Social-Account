// Selectable prover modules. Stats are coinflip-heads medians from the paired browser campaigns
// (standard: docs/port/benchmark-sparse-merkle-01.json; memory: docs/port/benchmark-round2-01.json,
// same machine). The memory figures were measured on the campaign module 4ebd702b, built from the
// same sources as the released fba4188d. The memory build's prove time is the v0.2.0-memory figure:
// round 2 measured a 0.997 paired time ratio on balance, and its CoinFlip times failed the
// stability gate.
// Proofs are byte-identical across builds; only memory and time differ.
export const PROVER_BUILDS = Object.freeze({
  standard: Object.freeze({
    label: "Standard",
    note: "Unchanged pinned prover (v0.1.0)",
    url: "./sequencer-prover.wasm",
    sha256: "1f76da1636c1e0e5f9952b3b49fc23d5a93493c2b94d3a2ec221965aa802a8aa",
    bytes: 91384741,
    peak_bytes: 13826136697,
    linear_bytes: 14366539776,
    prove_ms: 59400,
    need: "about 14 GiB",
  }),
  memory: Object.freeze({
    label: "Memory-optimised",
    note: "Opt-in prover-memory profile (v0.3.0-memory)",
    url: "./prover-memory.wasm",
    sha256: "fba4188d5a2f73d41534e8f7e2b6e312766ea9b8a2c0de098bf4d9f7accf4029",
    bytes: 94897180,
    peak_bytes: 1562659763,
    linear_bytes: 2251816960,
    prove_ms: 80415,
    need: "about 2.5 GiB",
  }),
});

// ponytail: navigator.deviceMemory is a coarse, rounded RAM hint (Chromium reports
// 32 on a 32 GB Mac, rounded down to a power of two; Safari/Firefox report nothing).
// Standard needs ~14.4 GB of Wasm memory plus the browser, too tight for 16-31 GB, so it
// is chosen only at 32+; otherwise the memory build, which runs anywhere standard does.
// Upgrade path: add better signals (free memory, a memory64 grow probe, timing) here.
export function recommendedBuild(nav = globalThis.navigator) {
  return (nav?.deviceMemory ?? 0) >= 32 ? "standard" : "memory";
}

export const gb = (n) => (n / 1e9).toFixed(2) + " GB";
const s = (ms) => (ms / 1000).toFixed(1) + " s";

// Renders radio cards into `root` and returns a getter for the selected build key.
export function buildPicker(root, onChange = () => {}) {
  const recommended = recommendedBuild();
  let selected = recommended;
  root.replaceChildren();
  root.setAttribute("role", "radiogroup");
  for (const [key, b] of Object.entries(PROVER_BUILDS)) {
    const label = document.createElement("label");
    label.className = "build-option";
    const input = document.createElement("input");
    Object.assign(input, { type: "radio", name: "prover-build", value: key });
    input.checked = key === selected;
    input.onchange = () => {
      selected = key;
      onChange(key, b);
    };
    const body = document.createElement("span");
    body.innerHTML = `<b></b><small></small><span class="build-stats">
      <span>WASM MEMORY<strong>${gb(b.linear_bytes)}</strong></span>
      <span>RUST HEAP<strong>${gb(b.peak_bytes)}</strong></span>
      <span>PROVE<strong>${s(b.prove_ms)}</strong></span></span>`;
    body.querySelector("b").textContent = b.label;
    body.querySelector("small").textContent =
      b.note + (key === recommended ? " · Recommended for this device" : "");
    label.append(input, body);
    root.append(label);
  }
  onChange(selected, PROVER_BUILDS[selected]);
  return {
    get: () => selected,
    disable: (d) =>
      root.querySelectorAll("input").forEach((i) => (i.disabled = d)),
  };
}

// One-line summary of what this browser actually measured for a proof receipt.
export function measuredSummary(report, key) {
  const b = PROVER_BUILDS[key] ?? PROVER_BUILDS.standard;
  return `${b.label}: proved in ${s(report.prove_ms)} (reference ${s(b.prove_ms)}) · linear memory ${gb(report.wasm_linear_memory_bytes)} · Rust heap peak ${gb(report.rust_requested_peak_bytes)} · module ${report.wasm_sha256.slice(0, 8)}… verified`;
}
