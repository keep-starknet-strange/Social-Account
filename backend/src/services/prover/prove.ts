import { init, rsa2048Sha256CalldataBuilder } from 'garaga';
import { Account, CallData, RpcProvider, byteArray } from 'starknet';
import { expectedNonce, extractIdentity } from '../../social-account';
import { extractJwt, fetchJwks, verifyJwt, type Jwt, type Jwk } from '../../jwk/google';

// Garaga init
await init();

const ZERO_GAS = { max_amount: 0n, max_price_per_unit: 0n };
const NO_FEE = {
  l1_gas: ZERO_GAS,
  l2_gas: { max_amount: 1_000_000_000n, max_price_per_unit: 0n },
  l1_data_gas: ZERO_GAS,
};

export type ProveRequest = { jwt: string; account: string; newPubkey: string };
export type ProveResult = {
  block_number: number;
  proof: string;
  proof_facts: string[];
  l2_to_l1_messages?: unknown[];
};
export type Proof = Omit<ProveResult, 'block_number'>;

/** The prover answered with an error, or did not answer. */
export class ProverError extends Error { }

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

export async function proveJwt(
  req: ProveRequest,
  provider: RpcProvider,
  proverAccount: Account,
  proverUrl: string,
): Promise<ProveResult> {
  const jwt = extractJwt(req.jwt);
  const jwKeys = (await fetchJwks()).keys;
  const jwk = await verifyJwt(jwt, jwKeys);
  // The contract parses the claim as lowercase 0x hex.
  if (!/^0x[0-9a-f]+$/.test(jwt.nonce)) throw new Error('BAD_NONCE');

  const contract = (entrypoint: string) => provider.callContract({ contractAddress: req.account, entrypoint });
  const [identity] = await contract('identity');
  if (BigInt(identity) !== BigInt(extractIdentity(jwt))) {
    throw new Error('WRONG_GOOGLE_ACCOUNT');
  }

  const [currentPubkey] = await contract('get_public_key');
  if (BigInt(jwt.nonce) !== expectedNonce(req.account, req.newPubkey, currentPubkey)) {
    throw new Error('NONCE_MISMATCH');
  }

  // call prove_jwt(header_b64, payload_b64, kid, hint, new_pubkey). The token is split and the
  // kid read here, not in Cairo: the contract re-checks the signature over `header.payload` with
  // the registry key named by kid, so a wrong split or kid just fails, and the third segment is
  // already inside the hint.
  const [header, payload] = req.jwt.split('.');
  const calldata = CallData.compile([
    byteArray.byteArrayFromString(header),
    byteArray.byteArrayFromString(payload),
    byteArray.byteArrayFromString(jwt.kid),
    rsaHint(jwt, jwk),
    req.newPubkey
  ]);
  const tx = await proverAccount.getSignedTransaction(
    { contractAddress: req.account, entrypoint: 'prove_jwt', calldata },
    { resourceBounds: NO_FEE, tip: 0n },
  );
  const block_number = await provider.getBlockNumber();
  const response = await prove(proverUrl, block_number, tx)
  return { block_number, ...response };
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
