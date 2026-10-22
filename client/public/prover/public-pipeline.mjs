import { felt, canonical } from "./anchored-rpc.mjs";
const encode = (value) => new TextEncoder().encode(JSON.stringify(value));
function check(signal) {
  if (signal?.aborted) throw new DOMException("Cancelled", "AbortError");
}
// Read-only demand acquisition. Only the Rust entry point may turn these provisional RPC
// results into execution inputs, after header/path/class verification on every attempt.
export async function preparePublicInvocation(
  prepare,
  rpc,
  request,
  { signal, maxRequests = 256 } = {},
) {
  check(signal);
  if (
    !Number.isSafeInteger(maxRequests) ||
    maxRequests < 1 ||
    maxRequests > 256
  )
    throw Error("maxRequests must be an integer from 1 to 256");
  const anchor = rpc.anchor;
  if (felt(request.captured_chain_id) !== felt(anchor.chain_id))
    throw Error("Request chain differs from captured chain");
  const contracts = new Map(),
    classes = new Map(),
    storage = new Map(),
    seen = new Set(),
    requests = [];
  async function classData(hash) {
    hash = felt(hash);
    if (hash === "0x0") throw Error("Cannot execute an absent contract class");
    if (!classes.has(hash)) classes.set(hash, await rpc.getClass(hash));
    check(signal);
  }
  async function contractData(address) {
    address = felt(address);
    if (contracts.has(address)) return;
    const classHash = await rpc.read({ kind: "class_hash", address });
    const nonce = await rpc.read({ kind: "nonce", address });
    check(signal);
    contracts.set(address, {
      class_hash: felt(classHash.value),
      nonce: felt(nonce.value),
    });
    if (felt(classHash.value) !== "0x0") await classData(classHash.value);
  }
  await contractData(request.transaction.sender_address);
  for (;;) {
    check(signal);
    const query = {
      class_hashes: [...classes.keys()].sort(),
      contract_addresses: [...contracts.keys()].sort(),
      contracts_storage_keys: [...storage]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([contract_address, keys]) => ({
          contract_address,
          storage_keys: [...keys.keys()].sort(),
        })),
    };
    const { proof } = await rpc.getStorageProof(query);
    check(signal);
    for (let i = 0; i < query.contract_addresses.length; i++) {
      const expected = contracts.get(query.contract_addresses[i]),
        leaf = proof.contracts_proof.contract_leaves_data[i];
      if (
        felt(leaf.class_hash) !== expected.class_hash ||
        felt(leaf.nonce) !== expected.nonce
      )
        throw Error("RPC contract read disagrees with proof leaf");
    }
    const storage_reads = [...storage].flatMap(([address, keys]) =>
      [...keys].map(([key, value]) => ({ address, key, value })),
    );
    const proofInput = {
      header: anchor.header,
      block_hash: anchor.header.block_hash,
      state_root: anchor.header.new_root,
      query,
      proof,
      storage_reads,
    };
    const classInput = [...classes].map(([class_hash, contractClass]) => ({
      class_hash,
      class: contractClass,
    }));
    try {
      const result = JSON.parse(
        prepare(encode(proofInput), encode(classInput), encode(request)),
      );
      check(signal);
      const capture = await rpc.capture();
      check(signal);
      return { result, proofInput, classInput, requests, capture };
    } catch (error) {
      check(signal);
      const match = String(error).match(/BROWSER_STATE_MISS:(\{[^}\n]+\})/);
      if (!match) throw error;
      const read = JSON.parse(match[1]),
        identity = canonical(read);
      if (seen.has(identity))
        throw Error("Public provider made no progress for " + identity);
      if (requests.length >= maxRequests)
        throw Error("Public state read limit exceeded");
      seen.add(identity);
      requests.push(read);
      switch (read.kind) {
        case "nonce":
        case "class_hash":
          await contractData(read.address);
          break;
        case "storage": {
          const address = felt(read.address),
            key = felt(read.key);
          await contractData(address);
          const value = await rpc.read({ kind: "storage", address, key });
          check(signal);
          if (!storage.has(address)) storage.set(address, new Map());
          storage.get(address).set(key, felt(value.value));
          break;
        }
        case "class":
        case "compiled_class_hash":
          await classData(read.class_hash);
          break;
        default:
          throw Error("Unsupported public state miss kind");
      }
    }
  }
}
