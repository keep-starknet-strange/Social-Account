// The backend API. Three endpoints:
//
// POST /recover {jwt, account, newPubkey, blinding, signature: [r, s], override?} => { address, identity, transaction_hash }
//   Deploys the account when missing, runs prove_jwt, relays recover. See recovery/recover.ts.
//   With override: true the account was created under another aud; it must exist and recover only
//   records a pending recovery that finalize_override_recovery completes after the delay.
// POST /deploy {aud, identity} => { address, transaction_hash | null }
//   Deploys the social account for a browser that proves locally. See recovery/deploy.ts.
// POST /relay {account, newPubkey, signature: [r, s], proof, proofFacts, override?} => { address, identity, transaction_hash, override }
//   Relays recover with a browser-generated proof. The JWT never arrives here. See recovery/relay.ts.
// GET /health => { chain, prover: { reachable, reason? }, deploys: boolean }
//   Whether /recover can prove right now (the docker prover is up) and whether /deploy is enabled.
//
// Run: bun run service:api.
// Env (.env.local): PORT (3000), RPC_URL, RELAYER_ADDRESS, RELAYER_PRIVATE_KEY (funded: deploys and relays),
//   PROVER_URL (http://localhost:9900), PROVER_ACCOUNT_ADDRESS, PROVER_ACCOUNT_PRIVATE_KEY,
//   DEPLOYS_PER_HOUR (30; 0 disables /deploy)
// Env (.env): AUTHORIZED_GOOGLE_RECOVERY_CLIENT_ID, AUTHORIZED_APPLE_RECOVERY_CLIENT_ID (the Services ID), SOCIAL_ACCOUNT_CLASS_HASH

import type { Server } from 'bun';
import { Account } from 'starknet';
import { chainName, env, makeProvider } from '../../env';
import { HttpError } from '../../http';
import { ProverError, proverHealth } from '../prover/prove';
import { deployAccount, type DeployRequest } from '../recovery/deploy';
import { recoverAccount, type RecoverContext, type RecoverRequest } from '../recovery/recover';
import { relayProof, type RelayRequest } from '../recovery/relay';

const provider = makeProvider();
const chain = await chainName(provider);

const ctx: RecoverContext = {
  provider,
  relayer: new Account({ provider, address: env('RELAYER_ADDRESS'), signer: env('RELAYER_PRIVATE_KEY') }),
  prover: {
    account: new Account({ provider, address: env('PROVER_ACCOUNT_ADDRESS'), signer: env('PROVER_ACCOUNT_PRIVATE_KEY') }),
    url: process.env.PROVER_URL ?? 'http://localhost:9900',
  },
  classHash: env('SOCIAL_ACCOUNT_CLASS_HASH'),
  audiences: {
    'https://accounts.google.com': env('AUTHORIZED_GOOGLE_RECOVERY_CLIENT_ID'),
    'https://appleid.apple.com': env('AUTHORIZED_APPLE_RECOVERY_CLIENT_ID'),
  },
  deploysPerHour: Number(process.env.DEPLOYS_PER_HOUR ?? 30),
};

/** JSON in, JSON out. A missing string field is 400, a prover failure is 502, an HttpError its status, anything else 400. */
function route<T extends Record<string, unknown>>(fields: (keyof T & string)[], handler: (body: T, ip: string) => Promise<unknown>) {
  return async (req: Request, srv: Server<undefined>) => {
    const body = (await req.json().catch(() => null)) as T | null;
    if (!body || fields.some((f) => typeof body[f] !== 'string'))
      return Response.json({ error: 'BAD_REQUEST', detail: `body must be {${fields.join(', ')}}` }, { status: 400 });
    try {
      return Response.json(await handler(body, srv.requestIP(req)?.address ?? 'unknown'));
    } catch (e) {
      const message = (e as Error).message;
      console.error(new Date().toISOString(), `${new URL(req.url).pathname} failed:`, message);
      const status = e instanceof HttpError ? e.status : e instanceof ProverError ? 502 : 400;
      return Response.json({ error: message }, { status });
    }
  };
}

const server = Bun.serve({
  port: Number(process.env.PORT ?? 3000),
  // A relayed proof is up to 480,000 bytes, 640 KB as base64.
  maxRequestBodySize: 1_000_000,
  routes: {
    '/recover': { POST: route<RecoverRequest>(['jwt', 'account', 'newPubkey', 'blinding'], (b) => recoverAccount(b, ctx)) },
    '/deploy': { POST: route<DeployRequest>(['aud', 'identity'], (b, ip) => deployAccount(b, ip, ctx)) },
    '/relay': { POST: route<RelayRequest>(['account', 'newPubkey', 'proof'], (b, ip) => relayProof(b, ip, ctx)) },
    '/health': {
      GET: async () => Response.json({ chain, prover: await proverHealth(ctx.prover.url), deploys: ctx.deploysPerHour > 0 }),
    },
  },
});
console.log(
  `api on http://localhost:${server.port} (${chain}), prover at ${ctx.prover.url}`,
);
