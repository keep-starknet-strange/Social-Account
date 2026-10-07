import { expect, test } from 'bun:test';
import { CURVE, computeHashOnElements, getPublicKey, getStarkKey, verify } from '@scure/starknet';
import type { JwtPayload } from './client';
import {
  acceptOwnershipHash,
  acceptOwnershipSignature,
  accountAddressFromJwt,
  decodeJwtPayload,
  identity,
  newKeyPair,
  nonce,
  randomFelt,
  toHex,
} from './utils';

// Google-shaped claims. The identity vector below was printed by a Cairo test with these exact strings.
const PAYLOAD: JwtPayload = {
  iss: 'https://accounts.google.com',
  aud: 'REDACTED_CLIENT_ID',
  sub: '123456789012345678901',
  nonce: '0x0',
  exp: 0,
};

test('toHex: lowercase 0x hex, no padding', () => {
  expect(toHex(0n)).toBe('0x0');
  expect(toHex(255n)).toBe('0xff');
  expect(toHex(2n ** 251n)).toBe('0x8' + '0'.repeat(62));
});

test('randomFelt: 31 bytes, below the curve order, fresh each call', () => {
  const a = randomFelt();
  expect(a).toMatch(/^0x[0-9a-f]{62}$/);
  expect(BigInt(a) < CURVE.n).toBe(true);
  expect(randomFelt()).not.toBe(a);
});

test('newKeyPair: public key is the Stark key of the private key', () => {
  const { privateKey, publicKey } = newKeyPair();
  expect(privateKey).toMatch(/^0x[0-9a-f]{62}$/);
  expect(publicKey).toBe(getStarkKey(privateKey));
});

test('decodeJwtPayload: base64url payload with - and _ and no padding', () => {
  // '~~~???' right after `"iss":"` yields '+' and '/' in plain base64, so the url-safe form carries '-' and '_'.
  const payload = { ...PAYLOAD, iss: '~~~???' };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  expect(encoded).toMatch(/[-_]/);
  expect(encoded).not.toContain('=');
  expect(decodeJwtPayload(`header.${encoded}.signature`)).toEqual(payload);
});

test('nonce matches the Cairo reference (poseidon_hash_span([new_pubkey, blinding]))', () => {
  // Checked by a Cairo test: poseidon_hash_span([0x1, 0x2])
  expect(nonce('0x1', '0x2')).toBe(
    toHex(1557996165160500454210437319447297236715335099509187222888255133199463084263n),
  );
  expect(nonce('0x1', '0x2')).toMatch(/^0x[0-9a-f]+$/);
});

test('identity matches the Cairo reference (jwt/types.cairo::identity over serialized ByteArrays)', () => {
  expect(BigInt(identity(PAYLOAD))).toBe(
    1660514014410290187817945875953752948376545195007282069889771726296515203202n,
  );
});

test('accountAddressFromJwt: UDC from_zero address, salt = identity, calldata = [identity]', () => {
  const classHash = '0x6a215818fdd42b93b10dced979b6423168c438549a7e1530b5ee08dcd77aa00';
  const id = BigInt(identity(PAYLOAD));
  // Starknet address formula, composed by hand: h(prefix, deployer = 0, salt, class_hash, h(calldata)) mod 2^251 - 256
  const prefix = BigInt('0x' + Buffer.from('STARKNET_CONTRACT_ADDRESS').toString('hex'));
  const raw = BigInt(computeHashOnElements([prefix, 0n, id, BigInt(classHash), BigInt(computeHashOnElements([id]))]));
  expect(BigInt(accountAddressFromJwt(PAYLOAD, classHash))).toBe(raw % (2n ** 251n - 256n));
  expect(accountAddressFromJwt(PAYLOAD, classHash)).toMatch(/^0x[0-9a-f]+$/);
});

test('accept-ownership hash matches the Cairo reference (PoseidonTrait chain in OZ set_public_key)', () => {
  // Printed by a Cairo test: poseidon_hash_span(['StarkNet Message', 'accept_ownership', 0x1234, 0x5678])
  expect(acceptOwnershipHash('0x1234', '0x5678')).toBe(
    465466797905939915483557105077695068228386375723873429055834603320358766351n,
  );
});

test('acceptOwnershipSignature: verifies under the new key for that message only', () => {
  const { privateKey } = newKeyPair();
  const [r, s] = acceptOwnershipSignature('0x1', '0x2', privateKey);
  const compact = r.slice(2).padStart(64, '0') + s.slice(2).padStart(64, '0');
  const pub = getPublicKey(privateKey);
  expect(verify(compact, toHex(acceptOwnershipHash('0x1', '0x2')), pub)).toBe(true);
  expect(verify(compact, toHex(acceptOwnershipHash('0x1', '0x3')), pub)).toBe(false);
});
