import { Account, CallData, RpcError, RpcProvider, type Call } from 'starknet';
import { extractJwt, fetchJwks, verifyJwt } from '../../jwk/google';
import { accountAddress, deployCall, expectedNonce, extractIdentity } from '../../social-account';
import { proveJwt, proveJwtCalldata } from '../prover/prove';

export type RecoverContext = {
  provider: RpcProvider;
  /** Funded. Deploys accounts, submits recover, and runs prove_jwt on chain when there is no prover. */
  relayer: Account;
  /** The SNIP-36 prover and the unfunded account that signs its virtual transaction. Undefined: run prove_jwt on chain. */
  prover?: { account: Account; url: string };
  classHash: string;
  googleClientId: string;
};
export type RecoverRequest = { jwt: string; account: string; newPubkey: string; signature: string[] };
export type RecoverResult = { address: string; identity: string; transaction_hash: string };

const HEX = /^0x[0-9a-fA-F]+$/;

export async function recoverAccount(req: RecoverRequest, ctx: RecoverContext): Promise<RecoverResult> {
  if (!Array.isArray(req.signature) || req.signature.length !== 2 || !req.signature.every((s) => HEX.test(s)))
    throw new Error('BAD_SIGNATURE_FORMAT');
  if (!HEX.test(req.newPubkey)) throw new Error('BAD_PUBLIC_KEY');


  const token = extractJwt(req.jwt);
  const jwk = await verifyJwt(token, (await fetchJwks()).keys);
  if (token.aud !== ctx.googleClientId) throw new Error('WRONG_AUDIENCE');
  if (!/^0x[0-9a-f]+$/.test(token.nonce)) throw new Error('BAD_NONCE');
  const identity = extractIdentity(token);
  const address = accountAddress(identity, ctx.classHash);
  if (BigInt(address) !== BigInt(req.account)) throw new Error('WRONG_ACCOUNT');


  if (!(await isDeployed(ctx.provider, address))) {
    const { transaction_hash } = await ctx.relayer.execute(deployCall(identity, ctx.classHash));
    await ctx.provider.waitForTransaction(transaction_hash);
    console.log(new Date().toISOString(), `deployed ${address} tx ${transaction_hash}`);
  }

  if (BigInt(token.nonce) !== expectedNonce(req.newPubkey)) throw new Error('NONCE_MISMATCH');

  const prove: Call = {
    contractAddress: address,
    entrypoint: 'prove_jwt',
    calldata: proveJwtCalldata(req.jwt, token, jwk, req.newPubkey),
  };
  let attached: { proof: string; proofFacts: string[] } | undefined;
  if (ctx.prover) {
    const { proof, proof_facts } = await proveJwt(prove, ctx.provider, ctx.prover.account, ctx.prover.url);
    attached = { proof, proofFacts: proof_facts };
  } else {
    const { transaction_hash } = await ctx.relayer.execute(prove);
    await ctx.provider.waitForTransaction(transaction_hash);
    console.log(new Date().toISOString(), `prove_jwt on chain for ${address} tx ${transaction_hash}`);
  }

  const { transaction_hash } = await ctx.relayer.execute(
    { contractAddress: address, entrypoint: 'recover', calldata: CallData.compile([req.newPubkey, token.iat, req.signature]) },
    attached,
  );
  await ctx.provider.waitForTransaction(transaction_hash);
  console.log(new Date().toISOString(), `recovered ${address} tx ${transaction_hash}`);
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
