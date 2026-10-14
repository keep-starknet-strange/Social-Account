import { Account, CallData, RpcError, RpcProvider, type Call } from 'starknet';
import { extractJwt, fetchJwks, verifyJwt } from '../../jwk/verification';
import { accountAddress, deployCall, expectedNonce, extractIdentity } from '../../social-account';
import { proveJwt, proveJwtCalldata } from '../prover/prove';

export type RecoverContext = {
  provider: RpcProvider;
  /** Funded. Deploys accounts and submits recover. */
  relayer: Account;
  /** The SNIP-36 prover and the unfunded account that signs its virtual transaction. */
  prover: { account: Account; url: string };
  classHash: string;
  /** The `aud` this backend serves per `iss`. A token from an issuer not listed here is refused. */
  audiences: Record<string, string>;
};
export type RecoverRequest = {
  jwt: string;
  account: string;
  newPubkey: string;
  blinding: string;
  signature: string[];
  /** 
   * This flag is used to denote that a recovery override is requested
   * 
   * The JWT's aud is a whitelisted recovery aud, not the one `account` 
   * was created with. 
   */
  override?: boolean;
};
export type RecoverResult = { address: string; identity: string; transaction_hash: string };

const HEX = /^0x[0-9a-fA-F]+$/;

export async function recoverAccount(req: RecoverRequest, ctx: RecoverContext): Promise<RecoverResult> {
  if (!Array.isArray(req.signature) || req.signature.length !== 2 || !req.signature.every((s) => HEX.test(s)))
    throw new Error('BAD_SIGNATURE_FORMAT');
  if (!HEX.test(req.newPubkey)) throw new Error('BAD_PUBLIC_KEY');
  if (!HEX.test(req.blinding)) throw new Error('BAD_BLINDING');

  const token = extractJwt(req.jwt);
  const jwk = await verifyJwt(token, (await fetchJwks(token.iss)).keys);
  if (token.aud !== ctx.audiences[token.iss]) throw new Error('WRONG_AUDIENCE');
  if (!/^0x[0-9a-f]+$/.test(token.nonce)) throw new Error('BAD_NONCE');
  if (BigInt(token.nonce) !== expectedNonce(req.newPubkey, req.blinding)) throw new Error('NONCE_MISMATCH');
  let address: string;
  let identity: string;
  if (req.override) {
    // The account belongs to another aud. prove_jwt checks h(iss, original_aud, sub) and the whitelist.
    if (!/^0x[0-9a-fA-F]+$/.test(req.account)) throw new Error('BAD_ACCOUNT');
    if (!(await isDeployed(ctx.provider, req.account))) throw new Error('ACCOUNT_NOT_DEPLOYED');
    address = req.account;
    [identity] = await ctx.provider.callContract({ contractAddress: address, entrypoint: 'identity' });
  } else {
    identity = extractIdentity(token);
    address = accountAddress(token.aud, identity, ctx.classHash);
    if (BigInt(address) !== BigInt(req.account)) throw new Error('WRONG_ACCOUNT');

    if (!(await isDeployed(ctx.provider, address))) {
      const { transaction_hash } = await ctx.relayer.execute(deployCall(token.aud, identity, ctx.classHash));
      await ctx.provider.waitForTransaction(transaction_hash);
      console.log(new Date().toISOString(), `deployed ${address} tx ${transaction_hash}`);
    }
  }

  const prove: Call = {
    contractAddress: address,
    entrypoint: 'prove_jwt',
    calldata: proveJwtCalldata(req.jwt, token, jwk, req.newPubkey, req.blinding),
  };
  const { proof, proof_facts } = await proveJwt(prove, ctx.provider, ctx.prover.account, ctx.prover.url);
  // The gateway rejects a decoded proof above max_proof_size (480,000 bytes on 0.14.5).
  console.log(new Date().toISOString(), `proof for ${address}: ${Buffer.from(proof, 'base64').length} bytes, ${proof_facts.length} facts`);

  const { transaction_hash } = await ctx.relayer.execute(
    { contractAddress: address, entrypoint: 'recover', calldata: CallData.compile([req.newPubkey, req.signature]) },
    { proof, proofFacts: proof_facts },
  );
  await ctx.provider.waitForTransaction(transaction_hash);
  console.log(new Date().toISOString(), `${req.override ? 'pending override recovery for' : 'recovered'} ${address} tx ${transaction_hash}`);
  return { address, identity, transaction_hash };
}

/** True when a contract lives at `address`. Only "contract not found" counts as no. */
async function isDeployed(provider: RpcProvider, address: string): Promise<boolean> {
  try {
    await provider.getClassHashAt(address);
    return true;
  } catch (e) {
    if (e instanceof RpcError && e.isType('CONTRACT_NOT_FOUND')) return false;
    throw e;
  }
}
