// JWK rotator service that mirrors Google's RS256 signing keys into the JwkRegistry contract
//
// How it works under the hood:
// 1. Fetches Google's JWKS
// 2. Compiles the `JwkRegistry`s `KeySet` and `KeyRemoved` events
// 3. Based on what gathered on chain, gathers a list of keys to add and keys to remove
// 4. Updates the contract
// 5. Sleeps for as long the `Cache-Controll` header suggests and then repeats.
//
// Env: 
// - RPC_URL, 
// - OWNER_ADDRESS, 
// - OWNER_PRIVATE_KEY
// - <CHAIN>_REGISTRY_ADDRESS 
// - <CHAIN>_REGISTRY_BLOCK.

import { Account, CallData, RpcProvider, byteArray, hash, type Call } from 'starknet';
import { chainName, env, makeProvider } from '../../env';
import { fetchJwks, type Jwk } from '../../jwk/google';

// Garaga RSA2048PublicKey: 
// - 6_u384 chunks x 4_u96 limbs, low to high
const LIMB_BITS = 96n;
const LIMBS = 24;
// Minimum retry time
const RETRY_MS = 5 * 60_000;

export function modulusLimbs(nBase64url: string): bigint[] {
  const bytes = Buffer.from(nBase64url, 'base64url');
  if (bytes.length !== 256) throw new Error(`modulus is ${bytes.length} bytes, need 256`);
  const n = BigInt('0x' + bytes.toString('hex'));
  const mask = (1n << LIMB_BITS) - 1n;
  return Array.from({ length: LIMBS }, (_, i) => (n >> (LIMB_BITS * BigInt(i))) & mask);
}

export function filterEligibleKeys(keys: Jwk[]): Map<string, bigint[]> {
  const out = new Map<string, bigint[]>();
  for (const k of keys) {
    if (k.kty !== 'RSA' || k.alg !== 'RS256' || k.use !== 'sig' || k.e !== 'AQAB') continue;
    out.set(k.kid, modulusLimbs(k.n));
  }
  return out;
}

export function extractRefreshDelay(headers: Headers): number {
  const maxAgeHeader = headers.get('cache-control') ?? '';
  const maxAgeString = /max-age=(\d+)/.exec(maxAgeHeader)?.[1] ?? 3600;
  const maxAgeMS = Number(maxAgeString) * 1000;
  return Math.min(Math.max(maxAgeMS, RETRY_MS), 24 * 3_600_000); // delay in 5m..24h
}

/** A Cairo ByteArray as it appears in event data: [len, ...words, pending_word, pending_word_len]. */
export function byteArrayFromFelts(d: string[]): string {
  const len = Number(BigInt(d[0]));
  return byteArray.stringFromByteArray({
    data: d.slice(1, 1 + len),
    pending_word: d[1 + len],
    pending_word_len: Number(BigInt(d[2 + len])),
  });
}

const KEY_SET_SELECTOR = hash.getSelectorFromName('KeySet');
const KEY_REMOVED_SELECTOR = hash.getSelectorFromName('KeyRemoved');

async function onChainKids(
  provider: RpcProvider,
  registryContractAddress: string,
  fromBlock: number
) {
  const kids = new Set<string>();
  let continuation_token: string | undefined;
  do {
    const chunk = await provider.getEvents({
      address: registryContractAddress,
      from_block: { block_number: fromBlock },
      to_block: 'latest',
      keys: [[KEY_SET_SELECTOR, KEY_REMOVED_SELECTOR]],
      chunk_size: 1000,
      continuation_token,
    });
    for (const e of chunk.events) {
      const kid = byteArrayFromFelts(e.data);
      if (BigInt(e.keys[0]) === BigInt(KEY_SET_SELECTOR)) kids.add(kid);
      else kids.delete(kid);
    }
    continuation_token = chunk.continuation_token;
  } while (continuation_token);
  return kids;
}

async function syncOnce(
  registryOwner: Account,
  provider: RpcProvider,
  registryContractAddress: string,
  fromBlock: number
) {
  const { keys, headers } = await fetchJwks();
  const upToDateGoogleKeys = filterEligibleKeys(keys);
  const onChainKeys = await onChainKids(provider, registryContractAddress, fromBlock);
  let setCount = 0;
  let removeCount = 0;

  // Find keys to set
  const calls: Call[] = [];
  for (const [kid, limbs] of upToDateGoogleKeys) {
    if (onChainKeys.has(kid)) continue;
    // Key does not exist, use `set_key`
    calls.push({
      contractAddress: registryContractAddress,
      entrypoint: 'set_key',
      calldata: CallData.compile([byteArray.byteArrayFromString(kid), ...limbs]),
    });
    setCount++;
  }

  // Find keys to remove
  for (const kid of onChainKeys) {
    if (upToDateGoogleKeys.has(kid)) continue;

    calls.push({
      contractAddress: registryContractAddress,
      entrypoint: 'remove_key',
      calldata: CallData.compile([byteArray.byteArrayFromString(kid)]),
    });
    removeCount++;
  }

  if (calls.length === 0) {
    console.log(new Date().toISOString(), `in sync (${onChainKeys.size} keys)`);
  } else {
    console.log(new Date().toISOString(), `Updating keys:\n\t+${setCount} keys\n\t-${removeCount} keys`);
    const { transaction_hash } = await registryOwner.execute(calls);
    await provider.waitForTransaction(transaction_hash);
    console.log('TX', transaction_hash);
  }
  return extractRefreshDelay(headers);
}

// MAIN SCRIPT
if (import.meta.main) {
  const provider = makeProvider();
  const chain = await chainName(provider);
  const rotatorOwner = new Account({
    provider,
    address: env('OWNER_ADDRESS'),
    signer: env('OWNER_PRIVATE_KEY'),
  });
  const registryContractAddress = env(`${chain}_REGISTRY_ADDRESS`);
  const fromBlock = Number(env(`${chain}_REGISTRY_BLOCK`));
  const once = process.argv.includes('--once');

  while (true) {
    let delay = RETRY_MS;
    try {
      delay = await syncOnce(rotatorOwner, provider, registryContractAddress, fromBlock);
    } catch (e) {
      console.error(new Date().toISOString(), 'sync failed:', e);
    }
    if (once) break;

    await Bun.sleep(delay);
  }
}
