import type { Jwk } from './jwk/verification';

export const GOOGLE_JWK: Jwk = {
  kid: 'REDACTED_KID',
  kty: 'RSA',
  alg: 'RS256',
  use: 'sig',
  e: 'AQAB',
  n: '4rY5uwZK1dQ-UVgB5s4NLyC-u5LC2MT7b8GWZztiNgMsp0Nnqx0pM7Ofx0ws32N2aZcx10-J8ydQxnNb9uAcf-7LyhyOIcv_WEyzaSbUAMOgoF-nQmJetckxNg6ekhNfaFcTQS0T-29ql2_CBLIML6CvSh-r0fgWRsqN2ayB7wCl74Gv6OOVbvagUWhj5z2L6o_plmsPDwLVuvA7o3WDEDjoq-IXafRQowj92kQUenrOKD4YCopuLIBhel6VH8doFRNZ6KISQhMcOivWaLU_UtKKAMloGJieTf_3r-_nErs2h5wB7T7FrMCScmO7mvFQXKh8_4P-MlbfgS9CUvQksw',
};

export const GOOGLE_JWT = 'REDACTED_JWT_HEADER.REDACTED_JWT_PAYLOAD0.REDACTED_JWT_SIGNATURE';
