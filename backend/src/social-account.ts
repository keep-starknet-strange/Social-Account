// Pure helpers about the SocialAccount contract, shared by the recover flow and its tests.
import { poseidonHashMany } from "@scure/starknet";
import { CallData, Deployer, byteArray, hash, type Call } from 'starknet';
import type { Jwt } from './jwk/verification';

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
 * The nonce the account expects `poseidon(new_pubkey, blinding)`.
 * Same implementation as the cairo counterpart.
 */
export function expectedNonce(newPubkey: string, blinding: string): bigint {
  return poseidonHashMany([BigInt(newPubkey), BigInt(blinding)])
}

/** SocialAccount constructor(aud: ByteArray, identity: felt252), compiled as calldata. */
export function constructorCalldata(aud: string, identity: string): string[] {
  return CallData.compile([byteArray.byteArrayFromString(aud), identity]);
}

/** UDC deploy_contract(class, salt = identity, from_zero, [aud, identity]). The caller is not part of the address. */
export function deployCall(aud: string, identity: string, classHash: string): Call {
  return new Deployer().buildDeployerCall(
    { classHash, salt: identity, unique: false, constructorCalldata: constructorCalldata(aud, identity) },
    '0x0',
  ).calls[0];
}

/** Where deployCall lands: deployer 0, salt = identity, calldata = [aud, identity]. The client SDK derives the same. */
export function accountAddress(aud: string, identity: string, classHash: string): string {
  return hash.calculateContractAddressFromHash(identity, classHash, constructorCalldata(aud, identity), 0);
}
