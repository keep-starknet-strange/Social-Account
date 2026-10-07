// The backend API. One endpoint:
//
// POST /recover {jwt, account, newPubkey, blinding, signature: [r, s]} => { address, identity, transaction_hash }
//   Deploys the account when missing, runs prove_jwt, relays recover. See recovery/recover.ts.
//
// Run: bun run service:api.
// Env (.env.local): PORT (3000), RPC_URL, RELAYER_ADDRESS, RELAYER_PRIVATE_KEY (funded: deploys and relays),
//   PROVER_MODE (local | onchain), and for local: PROVER_URL (http://localhost:9900), PROVER_ACCOUNT_ADDRESS,
//   PROVER_ACCOUNT_PRIVATE_KEY
// Env (.env): GOOGLE_CLIENT_ID, SOCIAL_ACCOUNT_CLASS_HASH

import { Account } from 'starknet';
import { chainName, env, makeProvider } from '../../env';
import { ProverError } from '../prover/prove';
import { recoverAccount, type RecoverContext, type RecoverRequest } from '../recovery/recover';

const provider = makeProvider();
const chain = await chainName(provider);

const proverMode = process.env.PROVER_MODE ?? 'local';
if (proverMode !== 'local' && proverMode !== 'onchain') throw new Error('PROVER_MODE must be local or onchain');

const ctx: RecoverContext = {
  provider,
  relayer: new Account({ provider, address: env('RELAYER_ADDRESS'), signer: env('RELAYER_PRIVATE_KEY') }),
  prover:
    proverMode === 'local'
      ? {
        account: new Account({ provider, address: env('PROVER_ACCOUNT_ADDRESS'), signer: env('PROVER_ACCOUNT_PRIVATE_KEY') }),
        url: process.env.PROVER_URL ?? 'http://localhost:9900',
      }
      : undefined,
  classHash: env('SOCIAL_ACCOUNT_CLASS_HASH'),
  googleClientId: env('GOOGLE_CLIENT_ID'),
};

/** JSON in, JSON out. A missing string field is 400, a prover failure is 502, anything else 400. */
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
      return Response.json({ error: message }, { status: e instanceof ProverError ? 502 : 400 });
    }
  };
}

const server = Bun.serve({
  port: Number(process.env.PORT ?? 3000),
  routes: {
    '/recover': { POST: route<RecoverRequest>(['jwt', 'account', 'newPubkey', 'blinding'], (b) => recoverAccount(b, ctx)) },
  },
});
console.log(
  `api on http://localhost:${server.port} (${chain}), prove_jwt ${ctx.prover ? `in prover at ${ctx.prover.url}` : 'on chain'}`,
);
