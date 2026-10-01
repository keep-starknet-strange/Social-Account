// Keys, Google, the backend call, and balance reads through starkzap. No signing happens here yet.

import {
  StarkSigner,
  StarkZap,
  fromAddress,
  sepoliaTokens,
  type Amount,
} from 'starkzap';

export const CHAIN_NAME = 'Sepolia';
const GOOGLE_CLIENT_ID: string = import.meta.env.VITE_GOOGLE_CLIENT_ID;

// starkzap's Sepolia preset brings its own public RPC, so the client needs no node URL.
const sdk = new StarkZap({ network: 'sepolia' });
export const TOKENS = [
  sepoliaTokens.STRK,
  sepoliaTokens.ETH,
  sepoliaTokens.USDC,
];

export type KeyPair = { privateKey: string; publicKey: string };
export type Deployed = { address: string; identity: string; created: boolean };
export type Account = KeyPair & Omit<Deployed, 'created'>;

/** 31 random bytes as hex: always below the Stark curve order. Used for private keys and the Google nonce. */
export function randomFelt(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return (
    '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
  );
}

export async function newKeyPair(): Promise<KeyPair> {
  const privateKey = randomFelt();
  return {
    privateKey,
    publicKey: await new StarkSigner(privateKey).getPubKey(),
  };
}

/** Google's implicit flow: the ID token comes back in the URL fragment of /callback, no client secret needed. */
export function googleLoginUrl(nonce: string, state: string): string {
  const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  url.search = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: `${location.origin}/callback`,
    response_type: 'id_token',
    scope: 'openid',
    nonce,
    state,
    prompt: 'select_account',
  }).toString();
  return url.toString();
}

export type IdToken = {
  iss: string;
  aud: string;
  sub: string;
  nonce: string;
  exp: number;
};

/** The claims only, for the nonce check. The backend verifies the signature. */
export function decodeIdToken(jwt: string): IdToken {
  const payload = jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(atob(payload));
}

/** Asks the backend for the SocialAccount of this token and public key: deploys it (avnu pays) unless it already exists. */
export async function deployAccount(
  jwt: string,
  publicKey: string,
): Promise<Deployed> {
  const res = await fetch('/api/deploy-account', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jwt, publicKey }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `backend: HTTP ${res.status}`);
  return body;
}

/** The account's current public key, read from chain. Recovery needs it for the nonce and the acceptance signature. */
export async function currentPublicKey(address: string): Promise<string> {
  const [pubkey] = await sdk.callContract({
    contractAddress: address,
    entrypoint: 'get_public_key',
    calldata: [],
  });
  return pubkey;
}

export type Recovered = {
  address: string;
  identity: string;
  transaction_hash: string;
};

/** Asks the backend to prove the token and relay `recover(newPubkey, signature)` for an existing account. */
export async function recoverAccount(
  jwt: string,
  account: string,
  newPubkey: string,
  signature: string[],
): Promise<Recovered> {
  const res = await fetch('/api/recover', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jwt, account, newPubkey, signature }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `backend: HTTP ${res.status}`);
  return body;
}

/** ERC20 balances of the account for TOKENS, in the same order. */
export async function balances(account: Account): Promise<Amount[]> {
  const wallet = await sdk.connectWallet({
    account: { signer: new StarkSigner(account.privateKey) },
    accountAddress: fromAddress(account.address),
  });
  return Promise.all(TOKENS.map((token) => wallet.balanceOf(token)));
}
