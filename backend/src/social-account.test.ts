import { expect, test } from 'bun:test';
import { Deployer } from 'starknet';
import type { Jwt } from './jwk/verification';
import { accountAddress, constructorCalldata, deployCall, extractIdentity } from './social-account';

test('identity matches the Cairo reference (jwt/types.cairo::tests::identity_reference)', () => {
  // Printed by that Cairo test: identity(pepper = 0) with these exact strings
  const token = {
    iss: 'https://accounts.google.com',
    aud: '123-abc.apps.googleusercontent.com',
    sub: '123456789012345678901',
  } as Jwt;
  expect(BigInt(extractIdentity(token, '0x0'))).toBe(
    3390181075934669139936153450168116728521076354543506169098880721240937364581n,
  );
  expect(extractIdentity(token, '0x1')).not.toBe(extractIdentity(token, '0x0'));
});

test('constructorCalldata serializes (aud: ByteArray, identity: felt252)', () => {
  // ByteArray: [data_len, ...data words, pending_word, pending_word_len], then the identity felt
  expect(constructorCalldata('aud', '0x1234').map(BigInt)).toEqual([0n, 0x617564n, 3n, 0x1234n]);
});

test('accountAddress is where deployCall lands (UDC from_zero, salt = identity, calldata = [aud, identity])', () => {
  const aud = '123-abc.apps.googleusercontent.com';
  const identity = '0x1234';
  const classHash = '0x4';
  const { addresses } = new Deployer().buildDeployerCall(
    { classHash, salt: identity, unique: false, constructorCalldata: constructorCalldata(aud, identity) },
    '0xdeadbeef', // any caller: not part of a from_zero address
  );
  expect(BigInt(accountAddress(aud, identity, classHash))).toBe(BigInt(addresses[0]));
  expect(accountAddress(aud, identity, classHash)).toMatch(/^0x[0-9a-f]+$/);
  expect(deployCall(aud, identity, classHash).entrypoint).toBe('deploy_contract');
});
