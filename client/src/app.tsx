import { useEffect, useState } from 'preact/hooks';
import {
  SocialAccountClient,
  type KeyPair,
  type RecoverRequest,
  type SocialAccount,
} from './sdk/client';
import { newKeyPair } from './sdk/utils';

/** The key pair must survive the two Google redirects, so it waits in sessionStorage until login completes. */
const KEYPAIR_KEY = 'keypair';

const client = new SocialAccountClient({
  clientId: import.meta.env.VITE_GOOGLE_CLIENT_ID,
  callbackUrl: `${location.origin}/callback`,
  socialAccountClassHash: import.meta.env.VITE_SOCIAL_ACCOUNT_CLASS_HASH,
  rpcUrl: import.meta.env.VITE_RPC_URL,
  recover: recoverViaBackend,
  // deploy: left out on purpose. The backend deploys the account and pays for it.
});

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

  function login() {
    setError('');
    sessionStorage.setItem(KEYPAIR_KEY, JSON.stringify(newKeyPair()));
    client.login();
  }

  /** Runs on every load. The SDK tells whether this load is a Google callback and which hop it is. */
  async function finishLogin() {
    const stored = sessionStorage.getItem(KEYPAIR_KEY);
    if (!stored) return;
    const keypair: KeyPair = JSON.parse(stored);
    setStatus('Signing in. If the account needs recovery, proving takes about a minute …');
    try {
      const result = await client.onLoginRedirect(keypair);
      if (result === 'redirecting') return; // second Google hop, the page is navigating away
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
              Sign in with Google. A key pair is created for this tab, and your
              social account address is derived from your Google identity. The
              account is deployed on first login and recovered onto the new key.
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

function LoggedIn({ session, onLogout }: { session: Session; onLogout: () => void }) {
  return (
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
  );
}
