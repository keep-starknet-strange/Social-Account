// Pure helpers about the SocialAccount contract, shared by the recover flow and its tests.

import { CallData, Deployer, byteArray, hash, type Call } from 'starknet';
import type { Jwt } from './jwk/google';

/**
 * Identity is derived from `poseidon(iss, aud, sub)`.
 * Individual values are converted to byte arrays and then compiled as calldata.
 *
 * @see `identity` function in social_account/src/jwt/types.cairo
 */
export function extractIdentity(token: Jwt): string {
  return hash.computePoseidonHashOnElements(
    CallData.compile([token.iss, token.aud, token.sub].map(byteArray.byteArrayFromString)),
  );
}

/**
 * The nonce the account expects `poseidon(account, new_pubkey, current_pubkey)`.
 * Same implementation as the cairo counterpart.
 */
export function expectedNonce(account: string, newPubkey: string, currentPubkey: string): bigint {
  return BigInt(hash.computePoseidonHashOnElements([account, newPubkey, currentPubkey]));
}

/** UDC deploy_contract(class, salt = identity, from_zero, [identity]). The caller is not part of the address. */
export function deployCall(identity: string, classHash: string): Call {
  return new Deployer().buildDeployerCall(
    { classHash, salt: identity, unique: false, constructorCalldata: [identity] },
    '0x0',
  ).calls[0];
}

/** Where deployCall lands: deployer 0, salt = identity, calldata = [identity]. The client SDK derives the same. */
export function accountAddress(identity: string, classHash: string): string {
  return hash.calculateContractAddressFromHash(identity, classHash, [identity], 0);
}
