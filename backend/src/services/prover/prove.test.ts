import { expect, test } from 'bun:test';
import { extractJwt, verifyJwt } from '../../jwk/verification';
import { rsaHint } from './prove';
import { TEST_JWK, TEST_JWT, cairoFixture } from '../../test-fixtures';

test('hint equals the Cairo fixture for the same token', async () => {
  expect(rsaHint(extractJwt(TEST_JWT), TEST_JWK)).toEqual((await cairoFixture()).hint);
});

test('fixture token: signature valid, but expired; a forged signature is rejected first', async () => {
  const token = extractJwt(TEST_JWT);
  expect(token.kid).toBe(TEST_JWK.kid);
  await expect(verifyJwt(token, [TEST_JWK])).rejects.toThrow('TOKEN_EXPIRED');
  await expect(verifyJwt({ ...token, signature: new Uint8Array(256) }, [TEST_JWK])).rejects.toThrow('BAD_SIGNATURE');
  await expect(verifyJwt(token, [])).rejects.toThrow('UNKNOWN_KID');
});
