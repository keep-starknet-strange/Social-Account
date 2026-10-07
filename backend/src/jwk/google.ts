export const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
export const ISSUER = 'https://accounts.google.com';

export type Jwk = {
  kid: string;
  kty: string;
  alg?: string;
  use?: string;
  n: string;
  e: string
};

export async function fetchJwks(): Promise<{ keys: Jwk[]; headers: Headers }> {
  const res = await fetch(JWKS_URL);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  return { keys: ((await res.json()) as { keys: Jwk[] }).keys, headers: res.headers };
}

export type Jwt = {
  kid: string;
  iss: string;
  aud: string;
  sub: string;
  nonce: string;
  exp: number;
  iat: number;
  // `header`.`payload` is the message signed and produced the `signature`
  messageToSign: Uint8Array<ArrayBuffer>;
  signature: Uint8Array<ArrayBuffer>;
};

export function extractJwt(jwt: string): Jwt {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error('BAD_JWT');

  const [header, payload, signature] = parts;
  const json = (s: string) => JSON.parse(Buffer.from(s, 'base64url').toString());
  const h = json(header) as { alg?: string; kid?: string };
  const p = json(payload) as Partial<Pick<Jwt, 'iss' | 'aud' | 'sub' | 'nonce' | 'exp' | 'iat'>>;

  if (h.alg !== 'RS256' || !h.kid) throw new Error('UNSUPPORTED_ALG');
  if (!p.iss || !p.aud || !p.sub || !p.nonce || !p.exp || !p.iat) throw new Error('BAD_PAYLOAD');

  return {
    kid: h.kid,
    iss: p.iss,
    aud: p.aud,
    sub: p.sub,
    nonce: p.nonce,
    exp: p.exp,
    iat: p.iat,
    messageToSign: new Uint8Array(new TextEncoder().encode(`${header}.${payload}`)),
    signature: new Uint8Array(Buffer.from(signature, 'base64url')),
  };
}

/** 
 * Verifies JWT with RS256 against Google's JWK. Checks expiry based
 * on `Date.now()` and allows well-known `iss`.
*/
export async function verifyJwt(token: Jwt, keys: Jwk[]): Promise<Jwk> {
  const jwk = keys.find((k) => k.kid === token.kid);
  if (!jwk) throw new Error('UNKNOWN_KID');

  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify'],
  );
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, token.signature, token.messageToSign);
  if (!ok) throw new Error('BAD_SIGNATURE');

  if (token.iss !== ISSUER) throw new Error('WRONG_ISSUER');
  if (token.exp <= Date.now() / 1000) throw new Error('TOKEN_EXPIRED');

  return jwk;
}
