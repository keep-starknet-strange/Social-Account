import { expect, test } from 'bun:test';
import { Deployer } from 'starknet';
import type { Jwt } from './jwk/google';
import { accountAddress, deployCall, extractIdentity } from './social-account';

test('identity matches the Cairo reference (jwt/types.cairo::identity over serialized ByteArrays)', () => {
  // Printed by a Cairo test: identity(@iss, @aud, @sub) with these exact strings
  const token = {
    iss: 'https://accounts.google.com',
    aud: 'REDACTED_CLIENT_ID',
    sub: '123456789012345678901',
  } as Jwt;
  expect(BigInt(extractIdentity(token))).toBe(
    1660514014410290187817945875953752948376545195007282069889771726296515203202n,
  );
});

test('accountAddress is where deployCall lands (UDC from_zero, salt = identity, calldata = [identity])', () => {
  const identity = '0x1234';
  const classHash = '0x4';
  const { addresses } = new Deployer().buildDeployerCall(
    { classHash, salt: identity, unique: false, constructorCalldata: [identity] },
    '0xdeadbeef', // any caller: not part of a from_zero address
  );
  expect(BigInt(accountAddress(identity, classHash))).toBe(BigInt(addresses[0]));
  expect(accountAddress(identity, classHash)).toMatch(/^0x[0-9a-f]+$/);
  expect(deployCall(identity, classHash).entrypoint).toBe('deploy_contract');
});
