// Pure Stark-curve helpers for the recovery flow. No SDK imports, so this file is testable in Bun.

import { poseidonHashMany, sign } from '@scure/starknet';

export const toHex = (n: bigint): string => '0x' + n.toString(16);

/** A Cairo short string ('StarkNet Message') as a felt: big-endian ASCII bytes. */
export function shortString(s: string): bigint {
  return BigInt(
    '0x' +
      Array.from(s, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join(
        '',
      ),
  );
}

/** The nonce SocialComponent::prove_jwt expects in the token: poseidon(account, new_pubkey, current_pubkey), lowercase 0x hex. */
export function recoveryNonce(
  account: string,
  newPubkey: string,
  currentPubkey: string,
): string {
  return toHex(
    poseidonHashMany([
      BigInt(account),
      BigInt(newPubkey),
      BigInt(currentPubkey),
    ]),
  );
}

/** What OpenZeppelin's set_public_key wants signed by the new key: poseidon('StarkNet Message', 'accept_ownership', account, current_pubkey). */
export function acceptOwnershipHash(
  account: string,
  currentPubkey: string,
): bigint {
  return poseidonHashMany([
    shortString('StarkNet Message'),
    shortString('accept_ownership'),
    BigInt(account),
    BigInt(currentPubkey),
  ]);
}

/** [r, s] over acceptOwnershipHash, signed with the new private key. */
export function acceptOwnershipSignature(
  account: string,
  currentPubkey: string,
  newPrivateKey: string,
): [string, string] {
  const { r, s } = sign(
    toHex(acceptOwnershipHash(account, currentPubkey)),
    newPrivateKey,
  );
  return [toHex(r), toHex(s)];
}
