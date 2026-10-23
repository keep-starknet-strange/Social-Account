import { init, rsa2048Sha256CalldataBuilder } from 'garaga';
import { Account, CallData, RpcProvider, byteArray, type Call } from 'starknet';
import type { Jwk, Jwt } from '../../jwk/verification';

// Garaga init
await init();

const ZERO_GAS = { max_amount: 0n, max_price_per_unit: 0n };
const NO_FEE = {
  l1_gas: ZERO_GAS,
  l2_gas: { max_amount: 1_000_000_000n, max_price_per_unit: 0n },
  l1_data_gas: ZERO_GAS,
};

export type Proof = {
  proof: string;
  proof_facts: string[];
  l2_to_l1_messages?: unknown[];
};

/** The prover answered with an error, or did not answer. */
export class ProverError extends Error { }

/**
 * Is the prover there? Any JSON-RPC answer counts, including "method not found": the service
 * has no health route, and a real proof request would take minutes. Returns the reason when not.
 */
export async function proverHealth(url: string): Promise<{ reachable: boolean; reason?: string }> {
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'ping', params: [] }),
      signal: AbortSignal.timeout(3_000),
    });
    const body = (await res.json().catch(() => null)) as { jsonrpc?: string } | null;
    return body?.jsonrpc === '2.0' ? { reachable: true } : { reachable: false, reason: `unexpected answer: HTTP ${res.status}` };
  } catch (e) {
    return { reachable: false, reason: (e as Error).message };
  }
}

/**
 * Extract the RSA hint, which is valuable for asserting the signature
 * in cairo.
 */
export function rsaHint(token: Jwt, jwk: Jwk): bigint[] {
  const bigIntFromBytes = (b: Uint8Array) => BigInt('0x' + Buffer.from(b).toString('hex'));

  return rsa2048Sha256CalldataBuilder(
    bigIntFromBytes(token.signature),
    token.messageToSign,
    bigIntFromBytes(Buffer.from(jwk.n, 'base64url')),
    false
  );
}

/**
 * Calldata for prove_jwt(header_b64, payload_b64, kid, hint, new_pubkey, blinding).
 *
 * The token is split and the kid read here, not in Cairo, to keep that work out of the proven
 * function. The contract re-checks the signature over `header.payload` with the registry key named
 * by kid, so a wrong split or kid just fails, and the third segment (signature) is already inside
 * the hint.
 */
export function proveJwtCalldata(rawJwt: string, token: Jwt, jwk: Jwk, newPubkey: string, blinding: string) {
  const [header, payload] = rawJwt.split('.');
  return CallData.compile([
    byteArray.byteArrayFromString(header),
    byteArray.byteArrayFromString(payload),
    byteArray.byteArrayFromString(token.kid),
    rsaHint(token, jwk),
    newPubkey,
    blinding,
  ]);
}

/** Runs `call` as a virtual transaction from the prover account on the latest block and returns the proof. */
export async function proveJwt(
  call: Call,
  provider: RpcProvider,
  proverAccount: Account,
  proverUrl: string,
): Promise<Proof> {
  const tx = await proverAccount.getSignedTransaction(call, { resourceBounds: NO_FEE, tip: 0n });
  const block_number = await provider.getBlockNumber();
  return prove(proverUrl, block_number, tx);
}

type SignedTx = Awaited<ReturnType<Account['getSignedTransaction']>>;

async function prove(
  url: string,
  blockNumber: number,
  transaction: SignedTx
): Promise<Proof> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'starknet_proveTransaction',
      params: { block_id: { block_number: blockNumber }, transaction },
    }),
    signal: AbortSignal.timeout(10 * 60_000),
  }).catch((e) => {
    throw new ProverError(`prover unreachable: ${(e as Error).message}`);
  });
  const body = (await res.json()) as {
    result?: Proof;
    error?: { message: string; data?: unknown };
  };
  if (!body.result) throw new ProverError(`prover: ${body.error?.message ?? res.status} ${JSON.stringify(body.error?.data ?? '')}`);
  return body.result;
}
