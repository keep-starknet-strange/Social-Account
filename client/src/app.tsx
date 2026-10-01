import { useEffect, useState } from 'preact/hooks';
import type { Amount } from 'starkzap';
import { acceptOwnershipSignature, recoveryNonce } from './crypto';
import * as social from './social';

/**
 * State carried across the Google redirect. The page reloads there, so it cannot live in memory.
 * TODO(temporary): sessionStorage for the redirect hop only; it is cleared as soon as we are back.
 */
type Pending = social.KeyPair & {
  state: string;
  nonce: string;
  recover?: { address: string; currentPublicKey: string };
};

export function App() {
  // Session only: the key pair and the account live in memory and vanish with the tab.
  const [account, setAccount] = useState<social.Account | null>(null);
  const [existing, setExisting] = useState('');
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    void finishLogin();
  }, []);

  /** New account: random nonce. Recovery: the nonce the contract expects, built from the address the user remembers. */
  async function login() {
    setError('');
    try {
      const pair = await social.newKeyPair();
      const address = existing.trim();
      const pending: Pending = {
        ...pair,
        state: crypto.randomUUID(),
        nonce: social.randomFelt(),
      };
      if (address) {
        const currentPublicKey = await social.currentPublicKey(address);
        pending.nonce = recoveryNonce(
          address,
          pair.publicKey,
          currentPublicKey,
        );
        pending.recover = { address, currentPublicKey };
      }
      sessionStorage.setItem('pending', JSON.stringify(pending));
      location.assign(social.googleLoginUrl(pending.nonce, pending.state));
    } catch (e) {
      setError(String((e as Error).message ?? e));
    }
  }

  /** Runs when Google sends the browser back to /callback#id_token=... */
  async function finishLogin() {
    const params = new URLSearchParams(location.hash.slice(1));
    if (!params.has('id_token') && !params.has('error')) return;
    history.replaceState(null, '', '/');
    const pending: Pending | null = JSON.parse(
      sessionStorage.getItem('pending') ?? 'null',
    );
    sessionStorage.removeItem('pending');
    try {
      if (params.has('error'))
        throw new Error(`google: ${params.get('error')}`);
      if (!pending || params.get('state') !== pending.state)
        throw new Error('state mismatch');
      const idToken = params.get('id_token')!;
      if (social.decodeIdToken(idToken).nonce !== pending.nonce)
        throw new Error('nonce mismatch');

      let result: { address: string; identity: string };
      if (pending.recover) {
        setStatus('Recovering your account. Proving takes about a minute …');
        const signature = acceptOwnershipSignature(
          pending.recover.address,
          pending.recover.currentPublicKey,
          pending.privateKey,
        );
        result = await social.recoverAccount(
          idToken,
          pending.recover.address,
          pending.publicKey,
          signature,
        );
      } else {
        setStatus('Deploying your account …');
        result = await social.deployAccount(idToken, pending.publicKey);
      }
      setAccount({
        privateKey: pending.privateKey,
        publicKey: pending.publicKey,
        address: result.address,
        identity: result.identity,
      });
      setStatus('');
    } catch (e) {
      setStatus('');
      setError(String((e as Error).message ?? e));
    }
  }

  return (
    <>
      <div class="banner">Network: {social.CHAIN_NAME}</div>
      <main>
        <h1>Social account</h1>
        {account ? (
          <LoggedIn account={account} onLogout={() => setAccount(null)} />
        ) : (
          <section>
            <p>
              Sign in with Google. A key pair is created for this tab. With no
              address below, a new social account bound to your Google identity
              is deployed (avnu pays). With the address of an account you
              already own, that account is recovered onto the new key.
            </p>
            <p>
              <label>
                Existing account address (optional)
                <br />
                <input
                  value={existing}
                  onInput={(e) =>
                    setExisting((e.target as HTMLInputElement).value)
                  }
                  placeholder="0x…"
                  size={70}
                  disabled={!!status}
                />
              </label>
            </p>
            <button onClick={login} disabled={!!status}>
              Login with Google
            </button>
            {status && <p>{status}</p>}
            {error && <p class="error">{error}</p>}
          </section>
        )}
      </main>
    </>
  );
}

function LoggedIn({
  account,
  onLogout,
}: {
  account: social.Account;
  onLogout: () => void;
}) {
  const [balances, setBalances] = useState<Amount[] | null>(null);
  const [error, setError] = useState('');

  function load() {
    setBalances(null);
    setError('');
    social
      .balances(account)
      .then(setBalances, (e) => setError(String((e as Error).message ?? e)));
  }
  useEffect(load, [account.address]);

  return (
    <section>
      <h2>Logged in</h2>
      <p>
        Address: <code>{account.address}</code>
      </p>
      <h3>Balances</h3>
      {balances ? (
        <ul>
          {balances.map((b, i) => (
            <li key={social.TOKENS[i].symbol}>{b.toFormatted()}</li>
          ))}
        </ul>
      ) : (
        !error && <p>Loading …</p>
      )}
      {error && <p class="error">{error}</p>}
      <p>
        <button onClick={load}>Refresh</button>{' '}
        <button onClick={onLogout}>Log out</button>
      </p>
      <p>
        The key lives only in this tab. Keep your address: it is what you need
        to recover next time.
      </p>
    </section>
  );
}
