import type { JSX } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import type { Call } from 'starknet';
import {
  Amount,
  fromAddress,
  sepoliaTokens,
  StarkSigner,
  StarkZap,
  type Token,
  type Wallet,
} from 'starkzap';
import {
  localProvingSupport,
  recommendedBuild,
  SocialAccountClient,
  type KeyPair,
  type ProofRecoverRequest,
  type Provider,
  type ProverBuild,
  type ProverStatus,
  type RecoverRequest,
  type SocialAccount,
} from './sdk/client';
import { newKeyPair } from './sdk/strk-utils';

/** The key pair must survive the two provider redirects, so it waits in sessionStorage until login completes. */
const KEYPAIR_KEY = 'keypair';

const CLIENT_IDS: Partial<Record<Provider, string>> = {
  google: import.meta.env.VITE_GOOGLE_CLIENT_ID,
  apple: import.meta.env.VITE_APPLE_CLIENT_ID || undefined,
};

/** The SDK reports proving progress here; the App component points it at its log. */
let onProverStatus: (status: ProverStatus) => void = () => {};

const mb = (bytes: number) => `${(bytes / 1048576).toFixed(1)} MB`;

function formatStatus(s: ProverStatus): string {
  if (typeof s === 'string') return s;
  switch (s.kind) {
    case 'phase':
      return `phase: ${s.phase}`;
    case 'panic':
      return `panic: ${s.message}`;
    case 'stage': {
      const {
        rust_requested_live_bytes: live,
        rust_requested_peak_bytes: peak,
      } = s.metrics;
      return `${s.message} (live ${mb(live)}, peak ${mb(peak)}, wasm ${mb(s.wasm_linear_memory_bytes)})`;
    }
  }
}

const client = new SocialAccountClient({
  clientIds: CLIENT_IDS,
  callbackUrl: `${location.origin}/callback`,
  socialAccountClassHash: import.meta.env.VITE_SOCIAL_ACCOUNT_CLASS_HASH,
  rpcUrl: import.meta.env.VITE_RPC_URL,
  recover: recoverViaBackend,
  // The backend deploys the account and pays for it. Local proving needs the account to exist
  // before prove_jwt runs, so this is a separate request; in server mode /recover would do it too.
  deploy: deployViaBackend,
  localProver: {
    executor: import.meta.env.VITE_PROVER_EXECUTOR_ADDRESS,
    rpcUrl: import.meta.env.VITE_PROVER_RPC_URL || undefined,
    assetsUrl: import.meta.env.VITE_PROVER_ASSETS_URL || undefined,
    submit: relayViaBackend,
    onStatus: (s) => onProverStatus(s),
  },
});

const LOCAL_SUPPORT = localProvingSupport();

const SERVICES = ['api', 'prover', 'rotator'] as const;
type Service = (typeof SERVICES)[number];
type IssuerSync = {
  lastSync: string | null;
  nextSync: string | null;
  error: string | null;
};
/** GET /api/health/<service>. `ok` is the verdict; the rest is whatever that service reports. */
type ServiceHealth = {
  ok: boolean;
  reason?: string;
  chain?: string;
  deploys?: boolean;
  issuers?: Record<string, IssuerSync>;
};
/** undefined until the first answer arrives. */
type Services = Partial<Record<Service, ServiceHealth>>;

const HEALTH_POLL_MS = 15_000;

async function serviceHealth(name: Service): Promise<ServiceHealth> {
  try {
    const res = await fetch(`/api/health/${name}`, {
      signal: AbortSignal.timeout(5_000),
    });
    return res.ok ? res.json() : { ok: false, reason: `HTTP ${res.status}` };
  } catch (e) {
    return { ok: false, reason: errorText(e) };
  }
}
/** The two prover builds in public/prover/. Proofs are byte-identical; only memory and time differ. */
const BUILDS: { key: ProverBuild; label: string; note: string }[] = [
  {
    key: 'standard',
    label: 'Standard',
    note: 'Unchanged pinned prover. Needs about 14 GB; may abort on machines under 32 GB.',
  },
  {
    key: 'memory',
    label: 'Memory-optimised',
    note: 'Needs about 3 GB. Runs anywhere the standard build does; slower.',
  },
];
/** Chromium's coarse RAM hint, rounded to a power of two; other browsers report nothing. */
const DEVICE_MEMORY_GB = (navigator as { deviceMemory?: number }).deviceMemory;

const sdk = new StarkZap({
  network: 'sepolia',
  rpcUrl: import.meta.env.VITE_RPC_URL,
});
const TOKENS: Token[] = [
  sepoliaTokens.STRK,
  sepoliaTokens.ETH,
  sepoliaTokens.USDC,
];

const errorText = (e: unknown) => String((e as Error).message ?? e);

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error ?? `backend: HTTP ${res.status}`);
  return json;
}

/** POST /api/recover: the JWT goes to the backend, which proves and relays. The backend wants the signature as [r, s]. */
function recoverViaBackend(req: RecoverRequest): Promise<SocialAccount> {
  return postJson('/api/recover', {
    ...req,
    signature: [req.signature.r, req.signature.s],
  });
}

/** POST /api/relay: only the proof goes to the backend, which relays recover. */
function relayViaBackend(req: ProofRecoverRequest): Promise<SocialAccount> {
  return postJson('/api/relay', {
    ...req,
    signature: [req.signature.r, req.signature.s],
  });
}

/** POST /api/deploy: the backend's relayer deploys the account the identity derives to. */
async function deployViaBackend(
  _call: Call,
  account: { aud: string; identity: string },
): Promise<string> {
  const { transaction_hash } = await postJson<{
    transaction_hash: string | null;
  }>('/api/deploy', account);
  if (!transaction_hash)
    throw new Error(
      'DEPLOY_RACE: the account appeared while deploying; sign in again',
    );
  return transaction_hash;
}

type Session = SocialAccount & KeyPair;

/** Copies `text`; the label flips to "Copied" for a moment. */
function CopyButton({
  text,
  label = 'Copy',
}: {
  text: string;
  label?: string;
}) {
  const [done, setDone] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(text);
    setDone(true);
    setTimeout(() => setDone(false), 1500);
  }
  return (
    <button type="button" class="btn-ghost" onClick={copy}>
      {done ? 'Copied' : label}
    </button>
  );
}

/** A labelled felt or hash in monospace with a copy button and an optional hint underneath. */
function Field({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div class="field">
      <div class="field-label">{label}</div>
      <div class="field-row">
        <code class="field-value">{value}</code>
        <CopyButton text={value} />
      </div>
      {hint && <p class="hint">{hint}</p>}
    </div>
  );
}

/** Brand logos for the sign-in buttons, drawn to each provider's button guidelines. */
const LOGOS: Record<Provider, JSX.Element> = {
  google: (
    <svg viewBox="0 0 48 48" width="20" height="20" aria-hidden="true">
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
    </svg>
  ),
  apple: (
    <svg viewBox="0 0 814 1000" width="16" height="20" aria-hidden="true">
      <path
        fill="currentColor"
        d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76.5 0-103.7 40.8-165.9 40.8s-105.6-57-155.5-127C46.7 790.7 0 663 0 541.8c0-194.4 126.4-297.5 250.8-297.5 66.1 0 121.2 43.4 162.7 43.4 39.5 0 101.1-46 176.3-46 28.5 0 130.9 2.6 198.3 99.2zm-234-181.5c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z"
      />
    </svg>
  ),
};

function ProviderButton({
  provider,
  disabled,
  onClick,
}: {
  provider: Provider;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button class={`btn-${provider}`} disabled={disabled} onClick={onClick}>
      {LOGOS[provider]}
      <span>Continue with {provider === 'google' ? 'Google' : 'Apple'}</span>
    </button>
  );
}

const KEY_HINT =
  'Generated for this tab and kept only in memory. Your Google or Apple identity (the JWT) is what proves you own it; signing in recovers the account onto this key.';

/** "3 min ago" for an ISO time, "never" for null. */
function ago(iso: string | null): string {
  if (!iso) return 'never';
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

const SERVICE_LABEL: Record<Service, string> = {
  api: 'API',
  prover: 'Prover server',
  rotator: 'JWK rotator',
};

/** One line of detail per service: what it reports when fine, why not otherwise. */
function serviceDetail(name: Service, h: ServiceHealth | undefined): string {
  if (!h) return 'checking …';
  if (!h.ok && !h.issuers) return h.reason ?? 'down';
  switch (name) {
    case 'api':
      return `${h.chain ?? ''}${h.deploys ? ', deploys enabled' : ', deploys disabled'}`;
    case 'prover':
      return 'ready to prove';
    case 'rotator':
      return Object.entries(h.issuers ?? {})
        .map(
          ([iss, s]) =>
            `${new URL(iss).hostname}: ${s.error ? `failed (${s.error})` : `synced ${ago(s.lastSync)}`}`,
        )
        .join('; ');
  }
}

function HealthPanel({ services }: { services: Services }) {
  return (
    <aside class="card panel">
      <h2>Services</h2>
      <ul class="services">
        {SERVICES.map((name) => {
          const h = services[name];
          const state = h === undefined ? 'unknown' : h.ok ? 'ok' : 'bad';
          return (
            <li key={name}>
              <span class={`dot dot-${state}`} />
              <span>
                <span class="service-name">{SERVICE_LABEL[name]}</span>
                <span class="service-detail">{serviceDetail(name, h)}</span>
              </span>
            </li>
          );
        })}
      </ul>
    </aside>
  );
}

export function App() {
  // Session only: the key pair and the account live in memory and vanish with the tab.
  const [session, setSession] = useState<Session | null>(null);
  const [keypair, setKeypair] = useState<KeyPair>(() => newKeyPair());
  const [status, setStatus] = useState('');
  const [log, setLog] = useState<{ at: Date; text: string }[]>([]);
  const [error, setError] = useState('');
  const [localChoice, setLocalChoice] = useState(false);
  const [build, setBuild] = useState<ProverBuild>(recommendedBuild());
  const [services, setServices] = useState<Services>({});
  const apiDown = services.api?.ok === false;
  const proverDown = services.prover?.ok === false;

  // Where the proof is made. A dead prover server forces local; an unsupported browser forces remote.
  const forcedLocal = proverDown && LOCAL_SUPPORT.ok;
  const forcedRemote = !LOCAL_SUPPORT.ok;
  const local = forcedLocal || (!forcedRemote && localChoice);
  const busy = !!status;

  useEffect(() => {
    onProverStatus = (s) =>
      setLog((l) => [...l, { at: new Date(), text: formatStatus(s) }]);
    void finishLogin();
    const poll = () =>
      SERVICES.forEach((name) =>
        serviceHealth(name).then((h) =>
          setServices((s) => ({ ...s, [name]: h })),
        ),
      );
    poll();
    const timer = setInterval(poll, HEALTH_POLL_MS);
    return () => clearInterval(timer);
  }, []);

  function login(provider: Provider) {
    setError('');
    setLog([]);
    sessionStorage.setItem(KEYPAIR_KEY, JSON.stringify(keypair));
    try {
      client.login(keypair, provider, { local, build });
    } catch (e) {
      sessionStorage.removeItem(KEYPAIR_KEY);
      setError(errorText(e));
    }
  }

  /** Runs on every load. The SDK tells whether this load is a provider callback and which hop it is. */
  async function finishLogin() {
    const stored = sessionStorage.getItem(KEYPAIR_KEY);
    if (!stored) return;
    const keypair: KeyPair = JSON.parse(stored);
    setKeypair(keypair);
    setStatus(
      'Signing in. If the account needs recovery, proving takes a minute on the server, a few in the browser …',
    );
    try {
      const result = await client.onLoginRedirect(keypair);
      if (result !== 'idle') {
        sessionStorage.removeItem(KEYPAIR_KEY);
        setSession({ ...result, ...keypair });
      }
      setStatus('');
    } catch (e) {
      sessionStorage.removeItem(KEYPAIR_KEY);
      setStatus('');
      setError(errorText(e));
    }
  }

  function logout() {
    setSession(null);
    setKeypair(newKeyPair());
    setLog([]);
  }

  return (
    <>
      <header class="topbar">
        <span class="brand">Social account</span>
        <span class="pill">Sepolia</span>
      </header>
      <div class="layout">
        <main>
          {session ? (
            <LoggedIn session={session} onLogout={logout} />
          ) : (
            <section class="card">
              <h2>Sign in</h2>
              <p>
                Sign in with Google or Apple. Your social account address is
                derived from your identity at the provider. The account is
                deployed on first login and recovered onto the key below.
              </p>

              <Field
                label="Ephemeral signing key"
                value={keypair.publicKey}
                hint={KEY_HINT}
              />

              {apiDown && (
                <p class="error">
                  The backend is not reachable. Neither sign-in path can finish.
                </p>
              )}

              <div class="field">
                <div class="field-label">Proving</div>
                <label class="switch-row">
                  <span class={local ? '' : 'strong'}>Remote</span>
                  <input
                    type="checkbox"
                    role="switch"
                    class="switch"
                    checked={local}
                    disabled={forcedLocal || forcedRemote || busy}
                    onChange={(e) => setLocalChoice(e.currentTarget.checked)}
                  />
                  <span class={local ? 'strong' : ''}>Local</span>
                </label>
                <p class="hint">
                  {local
                    ? 'The token never leaves this browser. Downloads the prover once (about 220 MB); desktop Chromium.'
                    : 'The token goes to the backend, which proves and relays the recovery.'}
                </p>
                {forcedLocal && (
                  <p class="hint warn">
                    The prover server is down ({services.prover?.reason}), so
                    proving stays local.
                  </p>
                )}
                {forcedRemote && (
                  <p class="hint warn">
                    Local proving is unavailable here:{' '}
                    {LOCAL_SUPPORT.ok ? '' : LOCAL_SUPPORT.reason}.
                  </p>
                )}
              </div>

              {local && (
                <div class="field">
                  <div class="field-label">Prover build</div>
                  <div class="build-cards" role="radiogroup">
                    {BUILDS.map((b) => (
                      <label key={b.key} class="build-card">
                        <input
                          type="radio"
                          name="build"
                          value={b.key}
                          checked={build === b.key}
                          disabled={busy}
                          onChange={() => setBuild(b.key)}
                        />
                        <b>{b.label}</b>
                        <small>
                          {b.note}
                          {b.key === recommendedBuild() &&
                            ' Recommended for this device.'}
                        </small>
                        {b.key === 'standard' && (
                          <small
                            class={
                              DEVICE_MEMORY_GB !== undefined &&
                              DEVICE_MEMORY_GB < 32
                                ? 'warn'
                                : ''
                            }
                          >
                            {DEVICE_MEMORY_GB === undefined
                              ? 'This browser does not report device memory.'
                              : `Chrome reports ${DEVICE_MEMORY_GB} GB of RAM on this device; the standard build wants 32 GB or more.`}
                          </small>
                        )}
                      </label>
                    ))}
                  </div>
                </div>
              )}

              <div class="actions stack">
                <ProviderButton
                  provider="google"
                  disabled={busy || apiDown || !CLIENT_IDS.google}
                  onClick={() => login('google')}
                />
                <ProviderButton
                  provider="apple"
                  disabled={busy || apiDown || !CLIENT_IDS.apple}
                  onClick={() => login('apple')}
                />
              </div>
              {status && <p class="status">{status}</p>}
              {error && <p class="error">{error}</p>}
            </section>
          )}
          {log.length > 0 && <ProverLog entries={log} />}
        </main>
        <HealthPanel services={services} />
      </div>
    </>
  );
}

function ProverLog({ entries }: { entries: { at: Date; text: string }[] }) {
  const pre = useRef<HTMLPreElement>(null);
  const text = entries
    .map((e) => `${e.at.toISOString().slice(11, 23)} ${e.text}`)
    .join('\n');
  // Follow the newest line, as a terminal would.
  useEffect(() => {
    if (pre.current) pre.current.scrollTop = pre.current.scrollHeight;
  }, [entries.length]);
  return (
    <section class="card">
      <div class="card-head">
        <h2>Prover log</h2>
        <CopyButton text={text} label="Copy log" />
      </div>
      <pre class="log" ref={pre}>
        {text}
      </pre>
    </section>
  );
}

function LoggedIn({
  session,
  onLogout,
}: {
  session: Session;
  onLogout: () => void;
}) {
  const [wallet, setWallet] = useState<Wallet | null>(null);
  const [balances, setBalances] = useState<Amount[]>([]);
  const [token, setToken] = useState(0);
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [status, setStatus] = useState('');
  const [txUrl, setTxUrl] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    sdk
      .connectWallet({
        account: { signer: new StarkSigner(session.privateKey) },
        accountAddress: fromAddress(session.address),
      })
      .then(async (w) => {
        setWallet(w);
        await refreshBalances(w);
      })
      .catch((e) => setError(errorText(e)));
  }, [session]);

  async function refreshBalances(w: Wallet) {
    setBalances(await Promise.all(TOKENS.map((t) => w.balanceOf(t))));
  }

  async function transfer(e: Event) {
    e.preventDefault();
    if (!wallet) return;
    const t = TOKENS[token];
    setError('');
    setTxUrl('');
    try {
      setStatus('Sending …');
      const tx = await wallet.transfer(t, [
        { to: fromAddress(to), amount: Amount.parse(amount, t) },
      ]);
      setStatus('Waiting for confirmation …');
      await tx.wait();
      setStatus('');
      setTxUrl(tx.explorerUrl);
      setAmount('');
      await refreshBalances(wallet);
    } catch (e) {
      setStatus('');
      setError(errorText(e));
    }
  }

  return (
    <>
      <section class="card">
        <div class="card-head">
          <h2>Account</h2>
          <button class="btn-ghost" onClick={onLogout}>
            Log out
          </button>
        </div>
        <Field label="Address" value={session.address} />
        <Field
          label="Identity"
          value={session.identity}
          hint="Poseidon hash of the provider, audience and subject of your token."
        />
        <Field
          label="Ephemeral signing key"
          value={session.publicKey}
          hint={KEY_HINT}
        />
      </section>

      <section class="card">
        <div class="card-head">
          <h2>Balances</h2>
          <button
            class="btn-ghost"
            onClick={() => wallet && refreshBalances(wallet)}
            disabled={!wallet}
          >
            Refresh
          </button>
        </div>
        <table class="balances">
          <tbody>
            {TOKENS.map((t, i) => (
              <tr key={t.symbol}>
                <td>{t.symbol}</td>
                <td class="num">{balances[i]?.toFormatted() ?? '…'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section class="card">
        <h2>Transfer</h2>
        <form class="form" onSubmit={transfer}>
          <label>
            <span class="field-label">Token</span>
            <select
              value={token}
              onChange={(e) => setToken(Number(e.currentTarget.value))}
            >
              {TOKENS.map((t, i) => (
                <option key={t.symbol} value={i}>
                  {t.symbol}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span class="field-label">Recipient</span>
            <input
              placeholder="0x…"
              value={to}
              onInput={(e) => setTo(e.currentTarget.value)}
              required
            />
          </label>
          <label>
            <span class="field-label">Amount</span>
            <input
              placeholder="0.0"
              value={amount}
              onInput={(e) => setAmount(e.currentTarget.value)}
              required
              inputMode="decimal"
            />
          </label>
          <div class="actions">
            <button
              class="btn-primary"
              type="submit"
              disabled={!wallet || !!status}
            >
              Send
            </button>
          </div>
        </form>
        {status && <p class="status">{status}</p>}
        {txUrl && (
          <p>
            Sent.{' '}
            <a href={txUrl} target="_blank" rel="noreferrer">
              View on explorer
            </a>
          </p>
        )}
        {error && <p class="error">{error}</p>}
      </section>
    </>
  );
}
