import { expect, test } from 'bun:test';
import { CallData, byteArray } from 'starknet';
import { byteArrayFromFelts, modulusLimbs, extractRefreshDelay, filterEligibleKeys } from './jwk-rotator';

import { GOOGLE_JWK } from '../../test-fixtures';
const { kid: KID, n: N } = GOOGLE_JWK;

test('modulus splits into the 24 limbs the Cairo fixture holds', async () => {
  const fixture = (await Bun.file('../social_account/tests/data/google_jwk_pub_key.txt').text())
    .trim()
    .split('\n')
    .map(BigInt);
  expect(modulusLimbs(N)).toEqual(fixture);
});

test('only RS256 signing keys with e=65537 are mirrored', () => {
  const good = { kid: KID, kty: 'RSA', alg: 'RS256', use: 'sig', n: N, e: 'AQAB' };
  const keys = filterEligibleKeys([good, { ...good, kid: 'x', alg: 'ES256' }, { ...good, kid: 'y', e: 'AQAC' }]);
  expect([...keys.keys()]).toEqual([KID]);
});

test('kid survives the ByteArray calldata round trip and cache header parses', () => {
  const felts = CallData.compile([byteArray.byteArrayFromString(KID)]) as string[];
  expect(byteArrayFromFelts(felts)).toBe(KID);
  expect(extractRefreshDelay(new Headers({ 'cache-control': 'public, max-age=18490' }))).toBe(18_490_000);
});
