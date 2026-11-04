import { poseidonHashMany } from "@scure/starknet";
import { CairoByteArray, hash, RpcProvider } from "starknet";
import { JWK_REGISTRY_ADDRESS } from "./constants";
import { init, rsa2048Sha256CalldataBuilder } from "garaga";

export type Jwt = {
    header: JwtHeader,
    payload: JwtPayload,
    signature: string,
    raw: string
};

export type JwtHeader = {
    alg: string,
    kid: string,
    typ: string
};

export type JwtPayload = {
    iss: string;
    aud: string;
    sub: string;
    nonce: string;
    exp: number;
    iat: number;
};

export function decodeJwt(jwt: string): Jwt {
    const [headerB64, payloadB64, signatureB64] = jwt.split('.');

    const header = JSON.parse(decodeBase64(headerB64)) as JwtHeader;
    const payload = JSON.parse(decodeBase64(payloadB64)) as JwtPayload;
    const signature = decodeBase64(signatureB64)

    return {
        header,
        payload,
        signature,
        raw: jwt
    }
}

export function jwtMessage(jwt: Jwt): { header: string, payload: string } {
    const [header, payload, _] = jwt.raw.split('.');
    return { header, payload };
}

export function jwtMessageString(jwt: Jwt): string {
    const { header, payload } = jwtMessage(jwt);
    return `${header}.${payload}`;
}

/** The pepper every client sends until a pepper service exists. Accounts made with it stay linkable. */
// ponytail: constant pepper, replace with the service's VUF output when one is decided.
export const NO_PEPPER = '0x0';

// H(iss, aud, sub, pepper)
export function identity(jwtPayload: JwtPayload, pepper: string): string {
    const felts = [...[jwtPayload.iss, jwtPayload.aud, jwtPayload.sub].flatMap(serializeByteArray), pepper].map(BigInt);
    return toHex(poseidonHashMany(felts));
}

// SocialAccount constructor(aud: ByteArray, identity: felt252)
export function constructorCalldata(jwtPayload: JwtPayload, pepper: string): string[] {
    return [...serializeByteArray(jwtPayload.aud), identity(jwtPayload, pepper)];
}

// udc_address(class, salt = identity, from_zero, [aud, identity])
export function accountAddressFromJwt(jwtPayload: JwtPayload, classHash: string, pepper: string): string {
    return hash.calculateContractAddressFromHash(
        identity(jwtPayload, pepper),
        classHash,
        constructorCalldata(jwtPayload, pepper),
        0
    );
}

export async function getJWKRegistryModulus(provider: RpcProvider, jwt: Jwt): Promise<bigint> {
    const limbs = await provider.callContract({
        contractAddress: JWK_REGISTRY_ADDRESS,
        entrypoint: 'get_key',
        calldata: [...serializeByteArray(jwt.payload.iss), ...serializeByteArray(jwt.header.kid)],
    });

    if (limbs.length !== 24) {
        throw new Error(`BAD_KEY: ${limbs.length} limbs`);
    }

    return limbs.reduce((n, limb, i) => n | (BigInt(limb) << (96n * BigInt(i))), 0n);
}

/** 
 * garaga's reduction hint for RS256 over `header.payload`
 */
export async function calculateRsaHint(jwt: Jwt, modulus: bigint): Promise<bigint[]> {
    await init();

    const signatureBytes = Uint8Array.from(jwt.signature, (c) => c.charCodeAt(0));
    const signatureNum = BigInt('0x' + Array.from(signatureBytes, (x) => x.toString(16).padStart(2, '0')).join(''));

    return rsa2048Sha256CalldataBuilder(
        signatureNum,
        new TextEncoder().encode(jwtMessageString(jwt)),
        modulus,
        false,
    );
}

function decodeBase64(base64: string): string {
    const formatted = base64.replace(/-/g, '+').replace(/_/g, '/');
    const padded = formatted.padEnd(formatted.length + ((4 - (formatted.length % 4)) % 4), '=')
    return atob(padded);
}

function toHex(n: bigint): string {
    return '0x' + n.toString(16);
}

function serializeByteArray(s: string): string[] {
    return new CairoByteArray(new TextEncoder().encode(s)).toApiRequest();
}
