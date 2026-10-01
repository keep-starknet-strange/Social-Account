// Pure helpers about the SocialAccount contract, shared by the prover and the deployer.

import { CallData, byteArray, hash, num } from 'starknet';
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

/** SocialAccount::constructor(public_key, identity, jwk_registry), as 0x felts: SNIP-29 rejects decimals. */
export function constructorCalldata(publicKey: string, identity: string, registry: string): string[] {
  return CallData.compile([publicKey, identity, registry]).map(num.toHex);
}

/** The address a paymaster deployment lands on: salt is the public key, deployer address is zero. */
export function accountAddress(publicKey: string, identity: string, classHash: string, registry: string): string {
  return hash.calculateContractAddressFromHash(publicKey, classHash, constructorCalldata(publicKey, identity, registry), 0);
}
