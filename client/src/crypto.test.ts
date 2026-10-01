import { expect, test } from 'bun:test';
import { getPublicKey, verify } from '@scure/starknet';
import {
  acceptOwnershipHash,
  acceptOwnershipSignature,
  recoveryNonce,
  shortString,
  toHex,
} from './crypto';

test('accept-ownership hash matches the Cairo reference (PoseidonTrait chain in OZ set_public_key)', () => {
  // Printed by a Cairo test: poseidon_hash_span(['StarkNet Message', 'accept_ownership', 0x1234, 0x5678])
  expect(acceptOwnershipHash('0x1234', '0x5678')).toBe(
    465466797905939915483557105077695068228386375723873429055834603320358766351n,
  );
  expect(toHex(shortString('StarkNet Message'))).toBe(
    '0x537461726b4e6574204d657373616765',
  );
});

test('the new key signs the accept-ownership hash verifiably; nonce is lowercase 0x hex', () => {
  const priv =
    '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd'; // 31 bytes, like randomFelt()
  const [r, s] = acceptOwnershipSignature('0x1', '0x2', priv);
  const compact = r.slice(2).padStart(64, '0') + s.slice(2).padStart(64, '0');
  expect(
    verify(
      compact,
      toHex(acceptOwnershipHash('0x1', '0x2')),
      getPublicKey(priv),
    ),
  ).toBe(true);
  expect(recoveryNonce('0x1', '0x2', '0x3')).toMatch(/^0x[0-9a-f]+$/);
});
