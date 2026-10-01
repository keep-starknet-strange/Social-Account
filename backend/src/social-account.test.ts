import { expect, test } from 'bun:test';
import { accountAddress, constructorCalldata } from './social-account';

test('constructor calldata is 0x hex, as SNIP-29 requires', () => {
  expect(constructorCalldata('0x1', '0x2', '0x3')).toEqual(['0x1', '0x2', '0x3']);
  expect(accountAddress('0x1', '0x2', '0x4', '0x3')).toMatch(/^0x[0-9a-f]+$/);
});
