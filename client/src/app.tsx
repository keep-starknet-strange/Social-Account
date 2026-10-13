import { useEffect, useState } from 'preact/hooks';
import { Amount, fromAddress, sepoliaTokens, StarkSigner, StarkZap, type Token, type Wallet } from 'starkzap';
import {
  SocialAccountClient,
  type KeyPair,
  type Provider,
  type RecoverRequest,
  type SocialAccount,
} from './sdk/client';
import { newKeyPair } from './sdk/utils';

/** The key pair must survive the two provider redirects, so it waits in sessionStorage until login completes. */
const KEYPAIR_KEY = 'keypair';

const CLIENT_IDS: Partial<Record<Provider, string>> = {
  google: import.meta.env.VITE_GOOGLE_CLIENT_ID,
  apple: import.meta.env.VITE_APPLE_CLIENT_ID || undefined,
};

const client = new SocialAccountClient({
  clientIds: CLIENT_IDS,
  callbackUrl: `${location.origin}/callback`,
  socialAccountClassHash: import.meta.env.VITE_SOCIAL_ACCOUNT_CLASS_HASH,
  rpcUrl: import.meta.env.VITE_RPC_URL,
  recover: recoverViaBackend,
  // deploy: left out on purpose. The backend deploys the account and pays for it.
});

const sdk = new StarkZap({ network: 'sepolia', rpcUrl: import.meta.env.VITE_RPC_URL });
const TOKENS: Token[] = [sepoliaTokens.STRK, sepoliaTokens.ETH, sepoliaTokens.USDC];

/** POST /api/recover. The backend wants the signature as [r, s]. */
async function recoverViaBackend(req: RecoverRequest): Promise<SocialAccount> {
  const res = await fetch('/api/recover', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ...req, signature: [req.signature.r, req.signature.s] }),
  });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `backend: HTTP ${res.status}`);
  return body;
}

type Session = SocialAccount & KeyPair;

export function App() {
  // Session only: the key pair and the account live in memory and vanish with the tab.
  const [session, setSession] = useState<Session | null>(null);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    void finishLogin();
  }, []);

  function login(provider: Provider) {
    setError('');
    const keypair = newKeyPair()
    sessionStorage.setItem(KEYPAIR_KEY, JSON.stringify(keypair));
    client.login(keypair, provider);
  }

  /** Runs on every load. The SDK tells whether this load is a provider callback and which hop it is. */
  async function finishLogin() {
    const stored = sessionStorage.getItem(KEYPAIR_KEY);
    if (!stored) return;
    const keypair: KeyPair = JSON.parse(stored);
    setStatus('Signing in. If the account needs recovery, proving takes about a minute …');
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
