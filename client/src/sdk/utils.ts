import { getStarkKey, poseidonHashMany, sign } from "@scure/starknet";
import { CairoByteArray, CairoFelt252, hash } from "starknet";
import type { JwtPayload, KeyPair } from "./client";

export const toHex = (n: bigint): string => '0x' + n.toString(16);

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

export function decodeJwtPayload(jwt: string): JwtPayload {
    const payload = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(payload));
}

// H(new_pubkey, blinding)
export function nonce(
    newPubKey: string,
    blinding: string
): string {
    return toHex(poseidonHashMany([BigInt(newPubKey), BigInt(blinding)]));
}

const serializeByteArray = (s: string): string[] =>
    new CairoByteArray(new TextEncoder().encode(s)).toApiRequest();

// H(iss, aud, sub)
export function identity(jwtPayload: JwtPayload): string {
    const felts = [jwtPayload.iss, jwtPayload.aud, jwtPayload.sub].flatMap(serializeByteArray).map(BigInt);
    return toHex(poseidonHashMany(felts));
}

// SocialAccount constructor(aud: ByteArray, identity: felt252)
export function constructorCalldata(jwtPayload: JwtPayload): string[] {
    return [...serializeByteArray(jwtPayload.aud), identity(jwtPayload)];
}

// udc_address(class, salt = identity, from_zero, [aud, identity])
export function accountAddressFromJwt(jwtPayload: JwtPayload, classHash: string): string {
    return hash.calculateContractAddressFromHash(identity(jwtPayload), classHash, constructorCalldata(jwtPayload), 0);
}

// poseidon('StarkNet Message', 'accept_ownership', account, current_pubkey)
export function acceptOwnershipHash(account: string, currentPubkey: string): bigint {
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
