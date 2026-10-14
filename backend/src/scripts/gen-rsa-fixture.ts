// Writes social_account/tests/data/rsa_sha256_vector.txt: a fresh RSA-2048 key, an RS256
// signature over MESSAGE, and the garaga reduction hint for it, as one felt per line in the
// layout `rsa2048Sha256CalldataBuilder(..., true)` produces (modulus first).
// Run from backend/: bun run src/scripts/gen-rsa-fixture.ts
import { generateKeyPairSync, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { init, rsa2048Sha256CalldataBuilder } from 'garaga';

// Keep in sync with the tests in social_account/src/jwt/rsa.cairo.
const MESSAGE = 'SocialAccount RS256 test vector';
const OUT = new URL('../../../social_account/tests/data/rsa_sha256_vector.txt', import.meta.url);

await init();
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
const message = Buffer.from(MESSAGE);
const signature = sign('RSA-SHA256', message, privateKey);
const n = Buffer.from(publicKey.export({ format: 'jwk' }).n as string, 'base64url');
const toBig = (b: Buffer) => BigInt('0x' + b.toString('hex'));

const felts = rsa2048Sha256CalldataBuilder(toBig(signature), new Uint8Array(message), toBig(n), true);
writeFileSync(OUT, felts.map(String).join('\n') + '\n');
console.log(`wrote ${felts.length} felts to ${OUT.pathname}`);
