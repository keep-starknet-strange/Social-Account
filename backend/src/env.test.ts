import { expect, test } from 'bun:test';
import { decodeChainId, upsertEnv } from './env';

test('chain ids decode to the env prefix', () => {
  expect(decodeChainId('0x534e5f5345504f4c4941')).toBe('SN_SEPOLIA');
  expect(decodeChainId('0x534e5f4d41494e')).toBe('SN_MAIN');
});

test('upsertEnv replaces an existing key and appends a new one', () => {
  const text = '# registries\nSN_SEPOLIA_REGISTRY_ADDRESS=0x1\nSN_SEPOLIA_REGISTRY_BLOCK=5';
  const out = upsertEnv(text, { SN_SEPOLIA_REGISTRY_ADDRESS: '0x2', SN_MAIN_REGISTRY_ADDRESS: '0x3' });
  expect(out).toBe(
    '# registries\nSN_SEPOLIA_REGISTRY_ADDRESS=0x2\nSN_SEPOLIA_REGISTRY_BLOCK=5\nSN_MAIN_REGISTRY_ADDRESS=0x3\n',
  );
  expect(upsertEnv('', { A: '1' })).toBe('A=1\n');
});
