// In-browser proving of `prove_jwt`. The JWT never leaves the page: this module builds the
// virtual transaction, lets the vendored SNIP-36 prover (public/prover/) execute and prove it in
// Workers, checks the facts bind the recovery we are about to ask for, and hands proof + facts to
// the app's `submit` hook. Loaded with a dynamic import, so the server path does not pull it in.

import { CallData, RpcProvider, byteArray, hash, num, RPC } from 'starknet';
import type { KeyPair, ProofRecoverRequest, ProverEvent, SocialAccount, SocialAccountClientConfig } from '../client';
import type { ProverBuild } from './support';
import { acceptOwnershipSignature, recoverMessageHash, toHex, toHexSanitized } from '../strk-utils';
import { calculateRsaHint, getJWKRegistryModulus, identity, Jwt, jwtMessage } from '../jwt';

type VirtualTx = {
  captured_chain_id: string;
  chain_info: (typeof CHAIN_INFO)[string];
  transaction: Omit<RPC.RPCSPEC09.INVOKE_TXN_V3, 'type' | 'version'>
};
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

function proveJwtCalldata(jwt: Jwt, hint: bigint[], newPubkey: string, blinding: string, pepper: string): string[] {
  const { header, payload } = jwtMessage(jwt);
  return CallData.compile([
    byteArray.byteArrayFromString(header),
    byteArray.byteArrayFromString(payload),
    byteArray.byteArrayFromString(jwt.header.kid),
    hint,
    newPubkey,
    blinding,
    pepper,
  ]).map((v) => num.toHex(v));
}

export function createVirtualTx(chainId: string, executor: string, account: string, calldata: string[], nonce: string): VirtualTx {
  const chain_info = CHAIN_INFO[toHexSanitized(chainId)];
  if (!chain_info) {
    throw new Error(`UNSUPPORTED_CHAIN: ${chainId}`);
  }

  const zero = { max_amount: '0x0', max_price_per_unit: '0x0' };
  return {
    captured_chain_id: toHexSanitized(chainId),
    chain_info,
    transaction: {
      sender_address: toHexSanitized(executor),
      calldata: ['0x1', toHexSanitized(account), PROVE_JWT, toHex(BigInt(calldata.length)), ...calldata],
      // The executor ignores the signature; the prover's transport wants a non-empty array.
      signature: ['0x0', '0x0'],
      nonce: toHexSanitized(nonce),
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
  return [PROOF1, VIRTUAL_SNOS, ...preimage.slice(2).map((v) => toHexSanitized(v))];
}

export function proofBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}

type Receipt = { kind: string; ok?: boolean; proof?: number[]; output_preimage?: string[]; report?: Record<string, unknown> };
/** Controller events: the prover's own, plus the controller's terminal ones. */
type Status = ProverEvent | { kind: 'error'; error: string } | { kind: 'cancelled' };
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
  jwt: Jwt;
  account: string;
  keypair: KeyPair;
  blinding: string;
  pepper: string;
  /** `get_public_key` of the account as deployed, `0x0` right after deployment. */
  currentPubKey: string;
  override: boolean;
  build: ProverBuild;
};

export async function proveLocally(p: ProveLocallyParams): Promise<SocialAccount> {
  const { localProver } = p.config;
  const onStatus = localProver.onStatus ?? (() => { });

  // Save some time by checking JWT, saving minutes of proving time in case
  // of a stale JWT.

  // Check almost stale JWT
  const now = Math.floor(Date.now() / 1000);
  if (p.jwt.payload.exp - now < MIN_TOKEN_LIFE_S) {
    throw new Error('TOKEN_EXPIRES_SOON: proving takes minutes, sign in again');
  }

  const rpcUrl = localProver.rpcUrl ?? p.config.rpcUrl;
  const rpc = rpcUrl === p.config.rpcUrl ? p.provider : new RpcProvider({ nodeUrl: rpcUrl });

  let id: string;
  if (p.override) {
    [id] = await p.provider.callContract({ contractAddress: p.account, entrypoint: 'identity' });
  } else {
    id = identity(p.jwt.payload, p.pepper);

    // Check stale JWT
    const lastRecovery = (await p.provider.getStorageAt(p.account, hash.getSelectorFromName('last_recovery'))) as { value: string };
    if (BigInt(p.jwt.payload.iat) <= BigInt(lastRecovery.value)) {
      throw new Error('STALE_IAT: token older than the last recovery');
    }
  }

  onStatus('Calculating RSA Hint');
  const modulus = await getJWKRegistryModulus(p.provider, p.jwt);
  const hint = await calculateRsaHint(p.jwt, modulus);
  const calldata = proveJwtCalldata(p.jwt, hint, p.keypair.publicKey, p.blinding, p.pepper);

  // Anchor at the newest block and start at once.
  const [chainId, block] = await Promise.all([rpc.getChainId(), rpc.getBlockWithTxHashes('latest')]);
  const nonce = await rpc.getNonceForAddress(localProver.executor, block.block_hash);
  const request = createVirtualTx(chainId, localProver.executor, p.account, calldata, nonce);

  onStatus('Setting up the prover...');
  const base = new URL(localProver.assetsUrl ?? '/prover/', location.origin);
  const { PublicRunController } = (await import(/* @vite-ignore */ new URL('public-run-controller.mjs', base).href)) as ControllerModule;
  const receipt = await new Promise<Receipt>((resolve, reject) => {
    const controller = new PublicRunController({
      workerFactory: (url) => new Worker(new URL(url, base), { type: 'module' }),
      save: async () => { },
      onStatus: (s) => {
        if (s.kind === 'error') reject(new Error(`PROVER_FAILED: ${s.error}`));
        else if (s.kind === 'cancelled') reject(new Error('PROVER_TIMEOUT'));
        else onStatus(s);
      },
      onComplete: resolve,
    });

    const timer = setTimeout(() => controller.cancel(), TIMEOUT_MS);
    controller.start(
      request,
      {
        endpoint: rpcUrl,
        block_id: { block_hash: block.block_hash }
      },
      {
        build: p.build
      }
    );
    void timer;
  });
  if (receipt.kind !== 'proof' || !receipt.proof || !receipt.output_preimage) {
    throw new Error('PROVER_FAILED: no proof');
  }

  const facts = proofFacts(receipt.output_preimage);
  const expected = recoverMessageHash(p.account, id, p.keypair.publicKey, p.currentPubKey, p.override);
  if (BigInt(facts[7]) !== 1n || BigInt(facts[8]) !== expected) {
    throw new Error('PROOF_MISMATCH: facts do not bind this recovery');
  }

  onStatus('Submitting the proof');
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
