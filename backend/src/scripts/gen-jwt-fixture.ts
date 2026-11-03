// Writes social_account/tests/data/test_jwt.txt: a self-signed RS256 ID token whose nonce
// preimage is known, so the SocialComponent recovery flows can be tested end to end. The
// registry accepts any key for an issuer, so the tests set this key under Google's `iss`.
//
// Layout, one felt per line: header ByteArray, payload ByteArray, the 24 u96 modulus limbs
// (low to high, as `set_key` takes them), then the garaga hint for this exact token.
// Keep the constants in sync with social_account/tests/test_prove_jwt.cairo.
// Run from backend/: bun run src/scripts/gen-jwt-fixture.ts
import { generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { init, rsa2048Sha256CalldataBuilder } from 'garaga';
import { CallData, byteArray, hash } from 'starknet';

const KID = 'test-kid';
const ISS = 'https://accounts.google.com';
const AUD = 'aud';
const SUB = 'sub-1';
const NEW_PUBKEY = 0x222n;
const BLINDING = 0x333n;
const IAT = 1_000_000;
const EXP = 2_000_000;
const OUT = new URL('../../../social_account/tests/data/test_jwt.txt', import.meta.url);

const b64url = (s: string) => Buffer.from(s).toString('base64url');
const nonce = '0x' + BigInt(hash.computePoseidonHashOnElements([NEW_PUBKEY, BLINDING])).toString(16);
const header = b64url(JSON.stringify({ alg: 'RS256', kid: KID, typ: 'JWT' }));
const payload = b64url(JSON.stringify({ iss: ISS, aud: AUD, sub: SUB, nonce, iat: IAT, exp: EXP }));
const message = Buffer.from(`${header}.${payload}`);

await init();
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
const signature = sign('RSA-SHA256', message, privateKey);
const toBig = (b: Buffer) => BigInt('0x' + b.toString('hex'));
const n = toBig(Buffer.from(publicKey.export({ format: 'jwk' }).n as string, 'base64url'));
const limbs = Array.from({ length: 24 }, (_, i) => (n >> (96n * BigInt(i))) & ((1n << 96n) - 1n));
const hint = rsa2048Sha256CalldataBuilder(toBig(signature), new Uint8Array(message), n, false);

const felts = [
  ...(CallData.compile([byteArray.byteArrayFromString(header), byteArray.byteArrayFromString(payload)]) as string[]).map(BigInt),
  ...limbs,
  ...hint,
];
writeFileSync(OUT, felts.map(String).join('\n') + '\n');
console.log(`wrote ${felts.length} felts to ${OUT.pathname}\nnonce ${nonce}`);
