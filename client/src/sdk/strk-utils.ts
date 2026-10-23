import { getStarkKey, poseidonHashMany, sign } from "@scure/starknet";
import { CairoFelt252 } from "starknet";
import type { KeyPair } from "./client";

export function toHex(n: BigInt): string {
    return '0x' + n.toString(16)
}

export function toHexSanitized(s: string): string {
    const num = BigInt(s)
    return toHex(num)
}

/** 31 random bytes as hex: always below the Stark curve order. Used for private keys and the Google nonce. */
export function randomFelt(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(31));
    return (
        '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
    );
}

export function newKeyPair(): KeyPair {
    const privateKey = randomFelt();
    return { privateKey, publicKey: getStarkKey(privateKey) };
}

// H(new_pubkey, blinding)
export function nonce(
    newPubKey: string,
    blinding: string
): string {
    return toHex(poseidonHashMany([BigInt(newPubKey), BigInt(blinding)]));
}

/** [r, s] over acceptOwnershipHash, signed with the new private key. */
export function acceptOwnershipSignature(
    account: string,
    currentPubkey: string,
    newPrivateKey: string,
): [string, string] {
    const { r, s } = sign(toHex(acceptOwnershipHash(account, currentPubkey)), newPrivateKey);
    return [toHex(r), toHex(s)];
}

/**
 * The one L2->L1 message hash that `prove_jwt` "posts".
 * poseidon(from = account, to = 0, len = 5, account, identity, new_pubkey, current_pubkey, is_override).
 * See `verify` in social_account/src/social/proof_facts.cairo.
 */
export function recoverMessageHash(
    account: string,
    identity: string,
    newPubkey: string,
    currentPubkey: string,
    override: boolean,
): bigint {
    return poseidonHashMany([
        BigInt(account), 0n, 5n,
        BigInt(account), BigInt(identity), BigInt(newPubkey), BigInt(currentPubkey), override ? 1n : 0n,
    ]);
}

function shortString(value: string): bigint {
    return new CairoFelt252(value).toBigInt();
}

// poseidon('StarkNet Message', 'accept_ownership', account, current_pubkey)
function acceptOwnershipHash(account: string, currentPubkey: string): bigint {
    return poseidonHashMany([
        shortString('StarkNet Message'),
        shortString('accept_ownership'),
        BigInt(account),
        BigInt(currentPubkey),
    ]);
}


