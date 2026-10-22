// In-browser proving of `prove_jwt`. The JWT never leaves the page: this module builds the
// virtual transaction, lets the vendored SNIP-36 prover (public/prover/) execute and prove it in
// Workers, checks the facts bind the recovery we are about to ask for, and hands proof + facts to
// the app's `submit` hook. Loaded with a dynamic import, so the server path never pays for garaga.
import { init, rsa2048Sha256CalldataBuilder } from 'garaga';
import { CallData, RpcProvider, byteArray, hash, num } from 'starknet';
import type { KeyPair, ProofRecoverRequest, SocialAccount, SocialAccountClientConfig } from '../client';
import { acceptOwnershipSignature, decodeJwtPayload, identity as identityOf, recoverMessageHash, toHex } from '../utils';
import type { ProverBuild } from './support';

/** Pinned like `JWK_REGISTRY_ADDRESS` in social_account/src/social/component.cairo: same on every chain. */
export const JWK_REGISTRY_ADDRESS = '0x654508b46a551c5b3dd8425e0ec4f06af316d28c68500bb83f9b815ba3fb3db';
const PROVE_JWT = hash.getSelectorFromName('prove_jwt');
const PROOF1 = '0x50524f4f4631';
const VIRTUAL_SNOS = '0x5649525455414c5f534e4f53';
/** `l2_gas.max_amount` the backend prover runs with (backend/src/services/prover/prove.ts). */
const L2_GAS = '0x3b9aca00';
const MIN_TOKEN_LIFE_S = 15 * 60;
const TIMEOUT_MS = 20 * 60_000;

const STRK = '0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';
/** `chain_info` the prover's executor expects, keyed by chain id felt. Mainnet is unverified. */
const CHAIN_INFO: Record<string, object> = {
  '0x534e5f5345504f4c4941': {
    chain_id: 'SN_SEPOLIA',
    fee_token_addresses: {
      eth_fee_token_address: '0x216e06f4761eb833ec9fbc9d08ae554427a2e6f23539d669a26d7e9997222b3',
      strk_fee_token_address: STRK,
    },
    is_l3: false,
  },
  '0x534e5f4d41494e': {
    chain_id: 'SN_MAIN',
    fee_token_addresses: {
      eth_fee_token_address: '0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7',
      strk_fee_token_address: STRK,
    },
    is_l3: false,
  },
};

const serializeByteArray = (s: string): string[] => CallData.compile([byteArray.byteArrayFromString(s)]);

export function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '=')), (c) => c.charCodeAt(0));
}
const bytesToBigInt = (b: Uint8Array) => BigInt('0x' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join(''));

/** The modulus the contract will use: `get_key(iss, kid)` returns 24 u96 limbs, low to high. */
export async function registryModulus(provider: RpcProvider, iss: string, kid: string): Promise<bigint> {
  const limbs = await provider.callContract({
    contractAddress: JWK_REGISTRY_ADDRESS,
    entrypoint: 'get_key',
    calldata: [...serializeByteArray(iss), ...serializeByteArray(kid)],
  });
  return modulusFromLimbs(limbs);
}

/** Inverse of `modulusLimbs` in backend/src/services/rotator/jwk-rotator.ts. */
export function modulusFromLimbs(limbs: string[]): bigint {
  if (limbs.length !== 24) throw new Error(`BAD_KEY: ${limbs.length} limbs`);
  return limbs.reduce((n, limb, i) => n | (BigInt(limb) << (96n * BigInt(i))), 0n);
}

/** garaga's reduction hint for RS256 over `header.payload`; what the backend's `rsaHint` builds. */
export async function rsaHint(rawJwt: string, modulus: bigint): Promise<bigint[]> {
  const [header, payload, signature] = rawJwt.split('.');
  await init();
  return rsa2048Sha256CalldataBuilder(
    bytesToBigInt(b64urlToBytes(signature)),
    new TextEncoder().encode(`${header}.${payload}`),
    modulus,
    false,
  );
}

/** Same calldata as backend/src/services/prover/prove.ts `proveJwtCalldata`. */
export function proveJwtCalldata(rawJwt: string, kid: string, hint: bigint[], newPubkey: string, blinding: string): string[] {
  const [header, payload] = rawJwt.split('.');
  return CallData.compile([
    byteArray.byteArrayFromString(header),
    byteArray.byteArrayFromString(payload),
    byteArray.byteArrayFromString(kid),
    hint,
    newPubkey,
    blinding,
  ]).map((v) => num.toHex(v));
}

/** The virtual INVOKE v3 the prover executes: sent by the keyless executor, one `prove_jwt` call, no fee. */
export function virtualRequest(chainId: string, executor: string, account: string, calldata: string[], nonce: string) {
  const chain_info = CHAIN_INFO[toHex(BigInt(chainId))];
  if (!chain_info) throw new Error(`UNSUPPORTED_CHAIN: ${chainId}`);
  const zero = { max_amount: '0x0', max_price_per_unit: '0x0' };
  return {
    captured_chain_id: toHex(BigInt(chainId)),
    chain_info,
    transaction: {
      sender_address: toHex(BigInt(executor)),
      calldata: ['0x1', toHex(BigInt(account)), PROVE_JWT, toHex(BigInt(calldata.length)), ...calldata],
      // The executor ignores the signature; the prover's transport wants a non-empty array.
      signature: ['0x0', '0x0'],
      nonce: toHex(BigInt(nonce)),
      resource_bounds: { l1_gas: zero, l2_gas: { max_amount: L2_GAS, max_price_per_unit: '0x0' }, l1_data_gas: zero },
      tip: '0x0',
      paymaster_data: [],
      account_deployment_data: [],
      nonce_data_availability_mode: 'L1',
      fee_data_availability_mode: 'L1',
    },
  };
}

/**
 * The proof facts `recover` reads, from the prover's bootloader output. Shape as the gateway
 * expects it: [PROOF1, VIRTUAL_SNOS, program hash, VIRTUAL_SNOS0, base block, base hash, config
 * hash, message count, message hash]. The program and config hashes are not pinned here: a wrong
 * one is rejected by the gateway before anyone pays.
 */
export function proofFacts(preimage: string[]): string[] {
  if (preimage.length < 3 || BigInt(preimage[0]) !== 1n || BigInt(preimage[1]) !== BigInt(preimage.length - 1))
    throw new Error('BAD_OUTPUT_PREIMAGE');
  return [PROOF1, VIRTUAL_SNOS, ...preimage.slice(2).map((v) => toHex(BigInt(v)))];
}

export function proofBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}

type Receipt = { kind: string; ok?: boolean; proof?: number[]; output_preimage?: string[]; report?: Record<string, unknown> };
type Status = { kind: string; phase?: string; message?: string; error?: string; stage?: string };
type Controller = { start(request: object, source: object, opts: { build: ProverBuild }): string; cancel(): void };
type ControllerModule = {
  PublicRunController: new (hooks: {
    workerFactory: (url: string) => Worker;
    save: (r: Receipt) => Promise<void>;
    onStatus: (s: Status) => void;
    onComplete: (r: Receipt) => void;
  }) => Controller;
};

export type ProveLocallyParams = {
  config: SocialAccountClientConfig & { localProver: NonNullable<SocialAccountClientConfig['localProver']> };
  provider: RpcProvider;
  jwt: string;
  account: string;
  keypair: KeyPair;
  blinding: string;
  /** `get_public_key` of the account as deployed; `0x0` right after deployment. */
  currentPubKey: string;
  override: boolean;
  build: ProverBuild;
};

export async function proveLocally(p: ProveLocallyParams): Promise<SocialAccount> {
  const { localProver } = p.config;
  const status = localProver.onStatus ?? (() => {});
  const [headerB64] = p.jwt.split('.');
  const header = JSON.parse(atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'))) as { kid?: string };
  const payload = decodeJwtPayload(p.jwt) as ReturnType<typeof decodeJwtPayload> & { iat: number };
  if (!header.kid) throw new Error('BAD_JWT: no kid');
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp - now < MIN_TOKEN_LIFE_S) throw new Error('TOKEN_EXPIRES_SOON: proving takes minutes, sign in again');

  // Prechecks that would otherwise surface as a revert after minutes of work.
  const rpcUrl = localProver.rpcUrl ?? p.config.rpcUrl;
  const rpc = rpcUrl === p.config.rpcUrl ? p.provider : new RpcProvider({ nodeUrl: rpcUrl });
  let identity: string;
  if (p.override) {
    [identity] = await p.provider.callContract({ contractAddress: p.account, entrypoint: 'identity' });
  } else {
    identity = identityOf(payload);
    const lastRecovery = await p.provider.getStorageAt(p.account, hash.getSelectorFromName('last_recovery'));
    if (BigInt(payload.iat) <= BigInt(String(lastRecovery))) throw new Error('STALE_IAT: token older than the last recovery');
  }

  status('Preparing the RSA hint');
  const modulus = await registryModulus(p.provider, payload.iss, header.kid);
  const hint = await rsaHint(p.jwt, modulus);
  const calldata = proveJwtCalldata(p.jwt, header.kid, hint, p.keypair.publicKey, p.blinding);

  // Anchor at the newest block and start at once: public nodes serve storage proofs only for
  // recent blocks (about two minutes on the demo's node).
  const [chainId, block] = await Promise.all([rpc.getChainId(), rpc.getBlockWithTxHashes('latest')]);
  const nonce = await rpc.getNonceForAddress(localProver.executor, block.block_hash);
  const request = virtualRequest(chainId, localProver.executor, p.account, calldata, nonce);

  const base = new URL(localProver.assetsUrl ?? '/prover/', location.origin);
  const { PublicRunController } = (await import(/* @vite-ignore */ new URL('public-run-controller.mjs', base).href)) as ControllerModule;
  const receipt = await new Promise<Receipt>((resolve, reject) => {
    const controller = new PublicRunController({
      workerFactory: (url) => new Worker(new URL(url, base), { type: 'module' }),
      save: async () => {},
      onStatus: (s) => {
        if (s.kind === 'error') reject(new Error(`PROVER_FAILED: ${s.error}`));
        else if (s.kind === 'cancelled') reject(new Error('PROVER_TIMEOUT'));
        else status(s.phase ?? s.message ?? (s.kind === 'stage' ? `Proving: ${s.stage ?? ''}` : 'Loading the prover'));
      },
      onComplete: resolve,
    });
    const timer = setTimeout(() => controller.cancel(), TIMEOUT_MS);
    controller.start(request, { endpoint: rpcUrl, block_id: { block_hash: block.block_hash } }, { build: p.build });
    void timer;
  });
  if (receipt.kind !== 'proof' || !receipt.proof || !receipt.output_preimage) throw new Error('PROVER_FAILED: no proof');

  const facts = proofFacts(receipt.output_preimage);
  const expected = recoverMessageHash(p.account, identity, p.keypair.publicKey, p.currentPubKey, p.override);
  if (BigInt(facts[7]) !== 1n || BigInt(facts[8]) !== expected) throw new Error('PROOF_MISMATCH: facts do not bind this recovery');

  status('Submitting the proof');
  const [r, s] = acceptOwnershipSignature(p.account, p.currentPubKey, p.keypair.privateKey);
  const req: ProofRecoverRequest = {
    account: p.account,
    newPubkey: p.keypair.publicKey,
    signature: { r, s },
    proof: proofBase64(Uint8Array.from(receipt.proof)),
    proofFacts: facts,
    override: p.override,
  };
  return localProver.submit(req);
}
