import { expect, test } from 'bun:test';
import { extractJwt, verifyJwt } from '../../jwk/verification';
import { rsaHint } from './prove';
import { GOOGLE_JWK, GOOGLE_JWT } from '../../test-fixtures';

test('hint equals the Cairo fixture for the same token', async () => {
  const fixture = (await Bun.file('../social_account/tests/data/google_jwt_rsa_hint.txt').text())
    .trim()
    .split('\n')
    .map(BigInt);
  expect(rsaHint(extractJwt(GOOGLE_JWT), GOOGLE_JWK)).toEqual(fixture);
});

test('fixture token: signature valid, but expired; a forged signature is rejected first', async () => {
  const token = extractJwt(GOOGLE_JWT);
  expect(token.kid).toBe(GOOGLE_JWK.kid);
  await expect(verifyJwt(token, [GOOGLE_JWK])).rejects.toThrow('TOKEN_EXPIRED');
  await expect(verifyJwt({ ...token, signature: new Uint8Array(256) }, [GOOGLE_JWK])).rejects.toThrow('BAD_SIGNATURE');
  await expect(verifyJwt(token, [])).rejects.toThrow('UNKNOWN_KID');
});
