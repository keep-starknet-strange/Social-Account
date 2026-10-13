// JWK rotator service that mirrors the supported issuers' RS256 signing keys into the JwkRegistry contract
//
// How it works under the hood:
// One independent loop per issuer in `ISSUERS`:
// 1. Fetches the issuer's JWKS
// 2. Compiles the `JwkRegistry`s `KeySet` and `KeyRemoved` events for that issuer
// 3. Based on what gathered on chain, gathers a list of keys to add and keys to remove
// 4. Updates the contract
// 5. Sleeps for as long the `Cache-Control` header suggests and then repeats.
//
// Env: 
// - RPC_URL, 
// - OWNER_ADDRESS, 
// - OWNER_PRIVATE_KEY
// - <CHAIN>_REGISTRY_ADDRESS 
// - <CHAIN>_REGISTRY_BLOCK.

import { Account, CallData, RpcProvider, byteArray, hash, type Call } from 'starknet';
import { chainName, env, makeProvider } from '../../env';
import { ISSUERS, fetchJwks, type Jwk } from '../../jwk/verification';

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

/** Consecutive Cairo ByteArrays as they appear in event data: [len, ...words, pending_word, pending_word_len]... */
export function byteArraysFromFelts(d: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < d.length;) {
    const len = Number(BigInt(d[i]));
    out.push(
      byteArray.stringFromByteArray({
        data: d.slice(i + 1, i + 1 + len),
        pending_word: d[i + 1 + len],
        pending_word_len: Number(BigInt(d[i + 2 + len])),
      }),
    );
    i += len + 3;
  }
  return out;
}

const KEY_SET_SELECTOR = hash.getSelectorFromName('KeySet');
const KEY_REMOVED_SELECTOR = hash.getSelectorFromName('KeyRemoved');

type Ctx = { registryOwner: Account; provider: RpcProvider; registryContractAddress: string; fromBlock: number };

/** The kids currently set on chain for `iss`. */
async function onChainKids({ provider, registryContractAddress, fromBlock }: Ctx, iss: string) {
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
      const [eventIss, kid] = byteArraysFromFelts(e.data);
      if (eventIss !== iss) continue;
      if (BigInt(e.keys[0]) === BigInt(KEY_SET_SELECTOR)) kids.add(kid);
      else kids.delete(kid);
    }
    continuation_token = chunk.continuation_token;
  } while (continuation_token);
  return kids;
}

// ponytail: one owner account, one nonce. Issuer loops run concurrently, so submissions are serialized.
let txLock: Promise<unknown> = Promise.resolve();
function submitKeyUpdates({ registryOwner, provider }: Ctx, calls: Call[]): Promise<string> {
  const run = txLock.then(async () => {
    const { transaction_hash } = await registryOwner.execute(calls);
    await provider.waitForTransaction(transaction_hash);
    return transaction_hash;
  });
  txLock = run.catch(() => { });
  return run;
}

/** Mirrors one issuer's JWKS into the registry. Returns the delay until the next sync. */
async function syncOnce(ctx: Ctx, iss: string) {
  const { keys, headers } = await fetchJwks(iss);
  const upToDateKeys = filterEligibleKeys(keys);
  const onChainKeys = await onChainKids(ctx, iss);
  const issuer = ISSUERS.find((i) => i.iss === iss)!.variant;
  let setCount = 0;
  let removeCount = 0;

  // Find keys to set
  const calls: Call[] = [];
  for (const [kid, limbs] of upToDateKeys) {
    if (onChainKeys.has(kid)) continue;
    // Key does not exist, use `set_key`
    calls.push({
      contractAddress: ctx.registryContractAddress,
      entrypoint: 'set_key',
      calldata: CallData.compile([issuer, byteArray.byteArrayFromString(kid), ...limbs]),
    });
    setCount++;
  }

  // Find keys to remove
  for (const kid of onChainKeys) {
    if (upToDateKeys.has(kid)) continue;

    calls.push({
      contractAddress: ctx.registryContractAddress,
      entrypoint: 'remove_key',
      calldata: CallData.compile([issuer, byteArray.byteArrayFromString(kid)]),
    });
    removeCount++;
  }

  if (calls.length === 0) {
    console.log(new Date().toISOString(), `${iss} in sync (${onChainKeys.size} keys)`);
  } else {
    console.log(new Date().toISOString(), `${iss} updating keys:\n\t+${setCount} keys\n\t-${removeCount} keys`);
    console.log('TX', await submitKeyUpdates(ctx, calls));
  }
  return extractRefreshDelay(headers);
}

/** Syncs `iss` on its own cache cadence. Resolves only with `once`. */
async function syncForever(ctx: Ctx, iss: string, once: boolean) {
  while (true) {
    let delay = RETRY_MS;
    try {
      delay = await syncOnce(ctx, iss);
    } catch (e) {
      console.error(new Date().toISOString(), `${iss} sync failed:`, e);
    }
    if (once) break;

    await Bun.sleep(delay);
  }
}

// MAIN SCRIPT
if (import.meta.main) {
  const provider = makeProvider();
  const chain = await chainName(provider);
  const ctx: Ctx = {
    provider,
    registryOwner: new Account({
      provider,
      address: env('OWNER_ADDRESS'),
      signer: env('OWNER_PRIVATE_KEY'),
    }),
    registryContractAddress: env(`${chain}_REGISTRY_ADDRESS`),
    fromBlock: Number(env(`${chain}_REGISTRY_BLOCK`)),
  };
  const once = process.argv.includes('--once');

  await Promise.all(ISSUERS.map((i) => syncForever(ctx, i.iss, once)));
}
