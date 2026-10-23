import { useEffect, useState } from 'preact/hooks';
import type { Call } from 'starknet';
import { Amount, fromAddress, sepoliaTokens, StarkSigner, StarkZap, type Token, type Wallet } from 'starkzap';
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
let onProverStatus: (status: ProverStatus) => void = () => { };

const mb = (bytes: number) => `${(bytes / 1048576).toFixed(1)} MB`;

function formatStatus(s: ProverStatus): string {
  if (typeof s === 'string') return s;
  switch (s.kind) {
    case 'phase':
      return `phase: ${s.phase}`;
    case 'panic':
      return `panic: ${s.message}`;
    case 'stage': {
      const { rust_requested_live_bytes: live, rust_requested_peak_bytes: peak } = s.metrics;
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

type Health = { chain: string; prover: { reachable: boolean; reason?: string }; deploys: boolean };

/** What the backend can do right now, or null when it does not answer. */
async function backendHealth(): Promise<Health | null> {
  try {
    const res = await fetch('/api/health');
    return res.ok ? res.json() : null;
  } catch {
    return null;
  }
}
const BUILDS: { key: ProverBuild; label: string; note: string }[] = [
  { key: 'standard', label: 'Standard', note: 'Unchanged pinned prover. Needs about 14 GB of free memory; may abort on smaller machines.' },
  { key: 'memory', label: 'Memory-optimised', note: 'Needs about 3 GB of free memory; slower.' },
];

const sdk = new StarkZap({ network: 'sepolia', rpcUrl: import.meta.env.VITE_RPC_URL });
const TOKENS: Token[] = [sepoliaTokens.STRK, sepoliaTokens.ETH, sepoliaTokens.USDC];

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const json = await res.json();
  if (!res.ok) throw new Error(json.error ?? `backend: HTTP ${res.status}`);
  return json;
}

/** POST /api/recover: the JWT goes to the backend, which proves and relays. The backend wants the signature as [r, s]. */
function recoverViaBackend(req: RecoverRequest): Promise<SocialAccount> {
  return postJson('/api/recover', { ...req, signature: [req.signature.r, req.signature.s] });
}

/** POST /api/relay: only the proof goes to the backend, which relays recover. */
function relayViaBackend(req: ProofRecoverRequest): Promise<SocialAccount> {
  return postJson('/api/relay', { ...req, signature: [req.signature.r, req.signature.s] });
}

/** POST /api/deploy: the backend's relayer deploys the account the identity derives to. */
async function deployViaBackend(_call: Call, account: { aud: string; identity: string }): Promise<string> {
  const { transaction_hash } = await postJson<{ transaction_hash: string | null }>('/api/deploy', account);
  if (!transaction_hash) throw new Error('DEPLOY_RACE: the account appeared while deploying; sign in again');
  return transaction_hash;
}

type Session = SocialAccount & KeyPair;

export function App() {
  // Session only: the key pair and the account live in memory and vanish with the tab.
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState('');
  const [log, setLog] = useState<{ at: Date; text: string }[]>([]);
  const [error, setError] = useState('');
  const [local, setLocal] = useState(false);
  const [build, setBuild] = useState<ProverBuild>(recommendedBuild());
  const [health, setHealth] = useState<Health | null | undefined>(undefined);

  useEffect(() => {
    onProverStatus = (s) => setLog((l) => [...l, { at: new Date(), text: formatStatus(s) }]);
    void finishLogin();
    void backendHealth().then(setHealth);
  }, []);

  function login(provider: Provider) {
    setError('');
    setLog([]);
    const keypair = newKeyPair()
    sessionStorage.setItem(KEYPAIR_KEY, JSON.stringify(keypair));
    try {
      client.login(keypair, provider, { local, build });
    } catch (e) {
      sessionStorage.removeItem(KEYPAIR_KEY);
      setError(String((e as Error).message ?? e));
    }
  }

  /** Runs on every load. The SDK tells whether this load is a provider callback and which hop it is. */
  async function finishLogin() {
    const stored = sessionStorage.getItem(KEYPAIR_KEY);
    if (!stored) return;
    const keypair: KeyPair = JSON.parse(stored);
    setStatus('Signing in. If the account needs recovery, proving takes a minute on the server, a few in the browser …');
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
      setError(String((e as Error).message ?? e));
    }
  }

  return (
    <>
      <div class="banner">Network: Sepolia</div>
      <main>
        <h1>Social account</h1>
        {session ? (
          <LoggedIn session={session} onLogout={() => setSession(null)} />
        ) : (
          <section>
            <p>
              Sign in with Google or Apple. A key pair is created for this tab, and your
              social account address is derived from your identity at the provider. The
              account is deployed on first login and recovered onto the new key.
            </p>
            {health === null && <p class="error">The backend is not reachable. Neither sign-in path can finish.</p>}
            {health && !health.prover.reachable && !local && (
              <p class="error">
                The backend's prover is down ({health.prover.reason}). Signing in without "Prove locally" will fail.
              </p>
            )}
            <p>
              <label>
                <input
                  type="checkbox"
                  checked={local}
                  disabled={!LOCAL_SUPPORT.ok || !!status}
                  onChange={(e) => setLocal(e.currentTarget.checked)}
                />{' '}
                Prove locally: the token never leaves this browser. Downloads the prover once
                (about 220 MB); desktop Chromium.
              </label>
              {!LOCAL_SUPPORT.ok && <span class="error"> Unavailable here: {LOCAL_SUPPORT.reason}.</span>}
            </p>
            {local && (
              <p class="builds">
                {BUILDS.map((b) => (
                  <label key={b.key}>
                    <input
                      type="radio"
                      name="build"
                      value={b.key}
                      checked={build === b.key}
                      disabled={!!status}
                      onChange={() => setBuild(b.key)}
                    />{' '}
                    <b>{b.label}</b>
                    {b.key === recommendedBuild() && ' (recommended for this device)'}: {b.note}
                  </label>
                ))}
              </p>
            )}
            <button onClick={() => login('google')} disabled={!!status || !CLIENT_IDS.google}>
              Login with Google
            </button>{' '}
            <button onClick={() => login('apple')} disabled={!!status || !CLIENT_IDS.apple}>
              Login with Apple
            </button>
            {status && <p>{status}</p>}
            {error && <p class="error">{error}</p>}
          </section>
        )}
        {log.length > 0 && (
          <section>
            <h2>Prover log</h2>
            <pre>{log.map((e) => `${e.at.toISOString().slice(11, 23)} ${e.text}`).join('\n')}</pre>
          </section>
        )}
      </main>
    </>
  );
}

function LoggedIn({ session, onLogout }: { session: Session; onLogout: () => void }) {
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
      .catch((e) => setError(String((e as Error).message ?? e)));
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
      const tx = await wallet.transfer(t, [{ to: fromAddress(to), amount: Amount.parse(amount, t) }]);
      setStatus('Waiting for confirmation …');
      await tx.wait();
      setStatus('');
      setTxUrl(tx.explorerUrl);
      setAmount('');
      await refreshBalances(wallet);
    } catch (e) {
      setStatus('');
      setError(String((e as Error).message ?? e));
    }
  }

  return (
    <>
      <section>
        <h2>Logged in</h2>
        <p>
          Address: <code>{session.address}</code>
        </p>
        <p>
          Identity: <code>{session.identity}</code>
        </p>
        <p>
          <button onClick={onLogout}>Log out</button>
        </p>
        <p>The key lives only in this tab. Logging in again recovers the account onto a fresh key.</p>
      </section>

      <section>
        <h2>Balances</h2>
        <table>
          <tbody>
            {TOKENS.map((t, i) => (
              <tr key={t.symbol}>
                <td>{t.symbol}</td>
                <td>{balances[i]?.toFormatted() ?? '…'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <button onClick={() => wallet && refreshBalances(wallet)} disabled={!wallet}>
          Refresh
        </button>
      </section>

      <section>
        <h2>Transfer</h2>
        <form onSubmit={transfer}>
          <p>
            <select value={token} onChange={(e) => setToken(Number(e.currentTarget.value))}>
              {TOKENS.map((t, i) => (
                <option key={t.symbol} value={i}>
                  {t.symbol}
                </option>
              ))}
            </select>
          </p>
          <p>
            <input
              placeholder="Recipient 0x…"
              value={to}
              onInput={(e) => setTo(e.currentTarget.value)}
              required
              size={70}
            />
          </p>
          <p>
            <input
              placeholder="Amount"
              value={amount}
              onInput={(e) => setAmount(e.currentTarget.value)}
              required
              inputMode="decimal"
            />
          </p>
          <button type="submit" disabled={!wallet || !!status}>
            Send
          </button>
        </form>
        {status && <p>{status}</p>}
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
