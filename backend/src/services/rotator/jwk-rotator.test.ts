import { expect, test } from 'bun:test';
import { CallData, byteArray } from 'starknet';
import { byteArraysFromFelts, modulusLimbs, extractRefreshDelay, filterEligibleKeys } from './jwk-rotator';

import { TEST_JWK, cairoFixture } from '../../test-fixtures';
const { kid: KID, n: N } = TEST_JWK;

test('modulus splits into the 24 limbs the Cairo fixture holds', async () => {
  expect(modulusLimbs(N)).toEqual((await cairoFixture()).limbs);
});

test('only RS256 signing keys with e=65537 are mirrored', () => {
  const good = { kid: KID, kty: 'RSA', alg: 'RS256', use: 'sig', n: N, e: 'AQAB' };
  const keys = filterEligibleKeys([good, { ...good, kid: 'x', alg: 'ES256' }, { ...good, kid: 'y', e: 'AQAC' }]);
  expect([...keys.keys()]).toEqual([KID]);
});

test('iss and kid survive the ByteArray calldata round trip and cache header parses', () => {
  const ISS = 'https://accounts.google.com';
  const felts = CallData.compile([byteArray.byteArrayFromString(ISS), byteArray.byteArrayFromString(KID)]) as string[];
  expect(byteArraysFromFelts(felts)).toEqual([ISS, KID]);
  expect(extractRefreshDelay(new Headers({ 'cache-control': 'public, max-age=18490' }))).toBe(18_490_000);
});
