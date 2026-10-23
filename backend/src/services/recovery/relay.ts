// POST /relay: submits `recover` with a proof the browser generated. The JWT never reaches this
// backend. Everything below runs before the relayer pays: shape, markers, a base block old enough to have a stored hash, one relay
// per account at a time, the account's class and keys, and that the facts bind exactly the
// recovery requested (account, identity, new key, current key, override flag). What slips past
// still reverts at the free fee estimate in relayRecover.
import { RpcError, shortString } from 'starknet';
import { accountAddress, recoverMessageHash } from '../../social-account';
import { HOUR, HttpError, allow } from '../../http';
import { HEX, relayRecover, type RecoverContext } from './recover';

export type RelayRequest = {
  account: string;
  newPubkey: string;
  signature: string[];
  /** The SNIP-36 proof, base64. */
  proof: string;
  /** 9 felts: PROOF1, VIRTUAL_SNOS, program hash, VIRTUAL_SNOS0, base block, base hash, config hash, 1, message hash. */
  proofFacts: string[];
  override?: boolean;
};
export type RelayResult = { address: string; identity: string; transaction_hash: string; override: boolean };

/** Decoded proof cap enforced by the gateway (max_proof_size on 0.14.5). */
export const MAX_PROOF_BYTES = 480_000;
/**
 * The chain only accepts a proof whose base block has a stored hash: at least this many blocks
 * old (STORED_BLOCK_HASH_BUFFER in the blockifier). There is no upper bound; an old proof is
 * valid until the key it binds changes.
 */
export const MIN_PROOF_AGE_BLOCKS = 10;
const OVERRIDES_PER_IP = 5;
const tag = (s: string) => BigInt(shortString.encodeShortString(s));
const MARKERS: [number, bigint][] = [[0, tag('PROOF1')], [1, tag('VIRTUAL_SNOS')], [3, tag('VIRTUAL_SNOS0')], [7, 1n]];

export type ParsedRelay = RelayRequest & { override: boolean; baseBlock: number; proofBytes: number };

export function parseRelayRequest(req: RelayRequest): ParsedRelay {
  if (!HEX.test(req.account)) {
    throw new HttpError(400, 'BAD_ACCOUNT');
  }
  if (!HEX.test(req.newPubkey)) {
    throw new HttpError(400, 'BAD_PUBLIC_KEY');
  }
  if (!Array.isArray(req.signature) || req.signature.length !== 2 || !req.signature.every((s) => HEX.test(s))) {
    throw new HttpError(400, 'BAD_SIGNATURE_FORMAT');
  }
  if (!Array.isArray(req.proofFacts) || req.proofFacts.length !== 9 || !req.proofFacts.every((f) => typeof f === 'string' && HEX.test(f))) {
    throw new HttpError(400, 'BAD_PROOF_FACTS');
  }
  if (typeof req.proof !== 'string' || req.proof.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(req.proof)) {
    throw new HttpError(400, 'BAD_PROOF');
  }

  const proofBytes = Buffer.from(req.proof, 'base64').length;
  if (proofBytes < 1 || proofBytes > MAX_PROOF_BYTES) {
    throw new HttpError(400, 'BAD_PROOF');
  }

  for (const [i, value] of MARKERS) {
    if (BigInt(req.proofFacts[i]) !== value) {
      throw new HttpError(400, 'BAD_PROOF_FACTS');
    }
  }

  const baseBlock = Number(BigInt(req.proofFacts[4]));
  if (!Number.isSafeInteger(baseBlock)) {
    throw new HttpError(400, 'BAD_PROOF_FACTS');
  }

  return { ...req, override: req.override === true, baseBlock, proofBytes };
}

export type ChainView = { head: number; classHash: string; identity: string; currentPubkey: string };

export function checkRelay(req: ParsedRelay, chain: ChainView, ctx: Pick<RecoverContext, 'classHash' | 'audiences'>): string {
  if (chain.head - req.baseBlock < MIN_PROOF_AGE_BLOCKS) {
    throw new HttpError(400, 'PROOF_TOO_RECENT');
  }

  if (BigInt(chain.classHash) !== BigInt(ctx.classHash)) {
    throw new HttpError(400, 'WRONG_CLASS');
  }

  const expected = recoverMessageHash(req.account, chain.identity, req.newPubkey, chain.currentPubkey, req.override);
  if (BigInt(req.proofFacts[8]) !== expected) {
    throw new HttpError(400, 'PROOF_MISMATCH');
  }

  if (!req.override && !Object.values(ctx.audiences).some((aud) => BigInt(accountAddress(aud, chain.identity, ctx.classHash)) === BigInt(req.account))) {
    throw new HttpError(400, 'WRONG_AUDIENCE');
  }

  return chain.identity;
}

const inFlight = new Set<string>();

export async function relayProof(body: RelayRequest, ip: string, ctx: RecoverContext): Promise<RelayResult> {
  // Validate the request
  const req = parseRelayRequest(body);
  const head = await ctx.provider.getBlockNumber();

  // Avoid duplicate requests
  const key = BigInt(req.account).toString(16);
  if (inFlight.has(key)) {
    throw new HttpError(409, 'IN_PROGRESS');
  }

  inFlight.add(key);

  try {
    let classHash: string;
    try {
      classHash = await ctx.provider.getClassHashAt(req.account);
    } catch (e) {
      if (e instanceof RpcError && e.isType('CONTRACT_NOT_FOUND')) throw new HttpError(400, 'ACCOUNT_NOT_DEPLOYED');
      throw e;
    }

    const [[identity], [currentPubkey]] = await Promise.all([
      ctx.provider.callContract({ contractAddress: req.account, entrypoint: 'identity' }),
      ctx.provider.callContract({ contractAddress: req.account, entrypoint: 'get_public_key' }),
    ]);

    checkRelay(req, { head, classHash, identity, currentPubkey }, ctx);

    if (req.override && !allow(`override:${ip}`, OVERRIDES_PER_IP, HOUR)) {
      throw new HttpError(429, 'RATE_LIMITED');
    }

    const transaction_hash = await relayRecover(req.account, req.newPubkey, req.signature, req.proof, req.proofFacts, ctx);
    console.log(new Date().toISOString(), `${req.override ? 'pending override recovery for' : 'recovered'} ${req.account} tx ${transaction_hash} (local proof, ${req.proofBytes} bytes)`);

    return {
      address: req.account,
      identity,
      transaction_hash,
      override: req.override
    };
  } finally {
    inFlight.delete(key);
  }
}
