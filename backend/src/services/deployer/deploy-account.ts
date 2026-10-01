// The work behind POST /deploy-account: check the Google token, derive the identity from it, and
// have avnu's paymaster deploy a SocialAccount bound to that identity, fee sponsored. The token is
// verified first so sponsored gas is only ever spent on a real login for this app.
//
// Idempotent: the address is derived from the public key and the identity, and an account that
// already exists there is simply reported back.

import type { DeployTransaction, ExecutionParameters, PaymasterRpc, RpcProvider } from 'starknet';
import { extractJwt, fetchJwks, verifyJwt } from '../../jwk/google';
import { accountAddress, constructorCalldata, extractIdentity } from '../../social-account';

export type DeployRequest = { jwt: string; publicKey: string };
export type DeployResult = { address: string; identity: string; created: boolean };
export type SocialAccountConfig = { classHash: string; registry: string; googleClientId: string };

/** The paymaster answered with an error, or did not answer. */
export class PaymasterError extends Error {}

const SPONSORED: ExecutionParameters = { version: '0x1', feeMode: { mode: 'sponsored' } };

export async function deployAccount(
  req: DeployRequest,
  provider: RpcProvider,
  paymaster: PaymasterRpc,
  cfg: SocialAccountConfig,
): Promise<DeployResult> {
  const token = extractJwt(req.jwt);
  await verifyJwt(token, (await fetchJwks()).keys);
  if (token.aud !== cfg.googleClientId) throw new Error('WRONG_AUDIENCE');
  if (!/^0x[0-9a-fA-F]+$/.test(req.publicKey)) throw new Error('BAD_PUBLIC_KEY');

  const identity = extractIdentity(token);
  const address = accountAddress(req.publicKey, identity, cfg.classHash, cfg.registry);
  if (await isDeployed(provider, address)) return { address, identity, created: false };

  const tx: DeployTransaction = {
    type: 'deploy',
    deployment: {
      address,
      class_hash: cfg.classHash,
      salt: req.publicKey,
      calldata: constructorCalldata(req.publicKey, identity, cfg.registry),
      version: 1,
    },
  };
  try {
    const prepared = await paymaster.buildTransaction(tx, SPONSORED);
    if (prepared.type !== 'deploy') throw new Error(`unexpected transaction type ${prepared.type}`);
    const { transaction_hash } = await paymaster.executeTransaction(
      { type: 'deploy', deployment: prepared.deployment },
      prepared.parameters,
    );
    console.log(new Date().toISOString(), `deployed ${address} tx ${transaction_hash}`);
    return { address, identity, created: true };
  } catch (e) {
    throw new PaymasterError(`paymaster: ${(e as Error).message}`);
  }
}

/** True when a contract lives at `address`. Only "contract not found" (RPC error 20) counts as no. */
async function isDeployed(provider: RpcProvider, address: string): Promise<boolean> {
  try {
    await provider.getClassHashAt(address);
    return true;
  } catch (e) {
    if ((e as { baseError?: { code?: number } }).baseError?.code === 20) return false;
    throw e;
  }
}
