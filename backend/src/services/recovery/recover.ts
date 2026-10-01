// The work behind POST /recover: prove the Google token against the account (see prove.ts), then
// have the relayer submit `recover(new_pubkey, signature)` with the proof attached.
//
// `signature` is the new key accepting ownership, which OpenZeppelin's set_public_key demands:
// sign(poseidon('StarkNet Message', 'accept_ownership', account, current_pubkey)) by the new key.
// The client produces it, since only the client holds the new private key.

import { Account, CallData, RpcProvider } from 'starknet';
import { extractJwt } from '../../jwk/google';
import { extractIdentity } from '../../social-account';
import { proveJwt, type ProveRequest } from '../prover/prove';

export type RecoverRequest = ProveRequest & { signature: string[] };
export type RecoverResult = { address: string; identity: string; transaction_hash: string };

export async function recoverAccount(
  req: RecoverRequest,
  provider: RpcProvider,
  proverAccount: Account,
  proverUrl: string,
  relayer: Account,
): Promise<RecoverResult> {
  if (!Array.isArray(req.signature) || req.signature.length !== 2 || !req.signature.every((s) => /^0x[0-9a-fA-F]+$/.test(s)))
    throw new Error('BAD_SIGNATURE_FORMAT');

  const { proof, proof_facts } = await proveJwt(req, provider, proverAccount, proverUrl);
  // ponytail: the registry owner doubles as relayer; give it its own funded account if roles need separating.
  const { transaction_hash } = await relayer.execute(
    { contractAddress: req.account, entrypoint: 'recover', calldata: CallData.compile([req.newPubkey, req.signature]) },
    { proof, proofFacts: proof_facts },
  );
  await provider.waitForTransaction(transaction_hash);
  console.log(new Date().toISOString(), `recovered ${req.account} tx ${transaction_hash}`);
  return { address: req.account, identity: extractIdentity(extractJwt(req.jwt)), transaction_hash };
}
