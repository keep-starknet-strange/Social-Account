// The backend API.
//
// POST /prove          {jwt, account, newPubkey} => { block_number, proof, proof_facts, l2_to_l1_messages }
// POST /deploy-account {jwt, publicKey}          => { address, identity, created }  (idempotent)
// POST /recover        {jwt, account, newPubkey, signature: [r, s]} => { address, identity, transaction_hash }
//
// Run: bun run service:api.
// Env (.env.local): PORT (3000), RPC_URL, PROVER_URL (http://localhost:9900), PROVER_ACCOUNT_ADDRESS,
//   PROVER_ACCOUNT_PRIVATE_KEY, PAYMASTER_API_KEY, PAYMASTER_URL (avnu sepolia by default),
//   OWNER_ADDRESS, OWNER_PRIVATE_KEY (relays `recover`)
// Env (.env): GOOGLE_CLIENT_ID, SOCIAL_ACCOUNT_CLASS_HASH, <CHAIN>_REGISTRY_ADDRESS

import { Account } from 'starknet';
import { chainName, env, makePaymaster, makeProvider } from '../../env';
import { PaymasterError, deployAccount, type DeployRequest } from '../deployer/deploy-account';
import { ProverError, proveJwt, type ProveRequest } from '../prover/prove';
import { recoverAccount, type RecoverRequest } from '../recovery/recover';

const provider = makeProvider();
const chain = await chainName(provider);
const proverAccount = new Account({
  provider,
  address: env('PROVER_ACCOUNT_ADDRESS'),
  signer: env('PROVER_ACCOUNT_PRIVATE_KEY'),
});
const proverUrl = process.env.PROVER_URL ?? 'http://localhost:9900';
/** Funded account that submits `recover` with the proof attached. */
const relayer = new Account({ provider, address: env('OWNER_ADDRESS'), signer: env('OWNER_PRIVATE_KEY') });
const paymaster = makePaymaster();
const socialAccount = {
  classHash: env('SOCIAL_ACCOUNT_CLASS_HASH'),
  registry: env(`${chain}_REGISTRY_ADDRESS`),
  googleClientId: env('GOOGLE_CLIENT_ID'),
};

/** JSON in, JSON out. A missing string field is 400, an upstream failure (prover, paymaster) is 502, anything else 400. */
function route<T extends Record<string, unknown>>(fields: (keyof T & string)[], handler: (body: T) => Promise<unknown>) {
  return async (req: Request) => {
    const body = (await req.json().catch(() => null)) as T | null;
    if (!body || fields.some((f) => typeof body[f] !== 'string'))
      return Response.json({ error: 'BAD_REQUEST', detail: `body must be {${fields.join(', ')}}` }, { status: 400 });
    try {
      return Response.json(await handler(body));
    } catch (e) {
      const message = (e as Error).message;
      console.error(new Date().toISOString(), `${new URL(req.url).pathname} failed:`, message);
      const upstream = e instanceof ProverError || e instanceof PaymasterError;
      return Response.json({ error: message }, { status: upstream ? 502 : 400 });
    }
  };
}

const server = Bun.serve({
  port: Number(process.env.PORT ?? 3000),
  routes: {
    '/prove': { POST: route<ProveRequest>(['jwt', 'account', 'newPubkey'], (b) => proveJwt(b, provider, proverAccount, proverUrl)) },
    '/deploy-account': { POST: route<DeployRequest>(['jwt', 'publicKey'], (b) => deployAccount(b, provider, paymaster, socialAccount)) },
    '/recover': { POST: route<RecoverRequest>(['jwt', 'account', 'newPubkey'], (b) => recoverAccount(b, provider, proverAccount, proverUrl, relayer)) },
  },
});
console.log(`api on http://localhost:${server.port} (${chain}), prover at ${proverUrl}`);
