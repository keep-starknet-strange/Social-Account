import { Call, CallData, Deployer, RpcError, RpcProvider } from "starknet";
import { localProvingSupport, recommendedBuild, type ProverBuild } from "./prover/support";
import { acceptOwnershipSignature, nonce, randomFelt } from "./strk-utils";
import { NO_PEPPER, accountAddressFromJwt, constructorCalldata, decodeJwt, identity } from "./jwt";

export { localProvingSupport, recommendedBuild, type ProverBuild };

const AUTH_URLS = {
    google: 'https://accounts.google.com/o/oauth2/v2/auth',
    apple: 'https://appleid.apple.com/auth/authorize',
} as const;
const SESSION_DATA_KEY = "session_data";

export type Provider = keyof typeof AUTH_URLS;
export type KeyPair = { privateKey: string; publicKey: string };
/** What the vendored prover reports while it runs (public/prover/*-worker.mjs). */
export type ProverEvent =
    | { kind: 'phase'; phase: string; anchor?: unknown }
    /** Progress from the prover wasm: what it is doing and how much memory it holds. */
    | {
        kind: 'stage';
        message: string;
        metrics: { rust_requested_live_bytes: number; rust_requested_peak_bytes: number };
        wasm_linear_memory_bytes: number;
    }
    | { kind: 'panic'; message: string };
/** The SDK's own steps as text, the prover's events as they arrive. */
export type ProverStatus = string | ProverEvent;

export type SocialAccountClientConfig = {
    /** The `aud` per provider: a Google OAuth client ID, an Apple Services ID. Leave out the providers not offered. */
    clientIds: Partial<Record<Provider, string>>,
    /** Apple only accepts an https URL on a registered domain, never localhost. */
    callbackUrl: string
    socialAccountClassHash: string,
    rpcUrl: string,

    /**
     * Run the recover request to the backend that owns the prover. 
     * 
     * @param request Includes the jwt, the account's address, the newly minted public key and the signature
     *                that validates the newly minted private key.
     * @returns The social account's identity along with the associated account address.
     */
    recover: (request: RecoverRequest) => Promise<SocialAccount>,

    /**
     * Setup the client to deploy the newly minted account. Leave it undefined 
     * for the server to do that instead. Local proving needs it: the account
     * must exist before `prove_jwt` can run against it.
     * 
     * @param call The deploy call to be handled.
     * @param account The `aud` and identity the address derives from, for a backend that
     *                wants to derive and check the address itself.
     * @returns The tx hash of the deploy transaction.
     */
    deploy?: (call: Call, account: { aud: string; identity: string }) => Promise<string>;

    /**
     * Enables `login(..., { local: true })`: the proof is generated in this browser and only
     * the proof reaches `submit`. The JWT never leaves the page. Needs the prover files served
     * from `assetsUrl` (see client/public/prover/) and a node that serves storage proofs.
     */
    localProver?: {
        /** The keyless ProverExecutor account that sends the virtual transaction. */
        executor: string;
        /** Where public/prover/ is served. Default `${location.origin}/prover/`. */
        assetsUrl?: string;
        /** A node serving `starknet_getStorageProof` and `starknet_getCompiledCasm` with CORS. Default `rpcUrl`. */
        rpcUrl?: string;
        /** Relay `recover` with the proof attached (a backend relayer, or the user's own wallet). */
        submit: (request: ProofRecoverRequest) => Promise<SocialAccount>;
        /** Progress: the SDK's own steps and the prover's events. */
        onStatus?: (status: ProverStatus) => void;
    };
};

export type SocialAccount = {
    address: string;
    identity: string;
};
export type RecoverRequest = {
    jwt: string,
    account: string,
    newPubkey: string,
    blinding: string,
    pepper: string,
    signature: { r: string, s: string },
    /** 
     * This flag is used to denote that a recovery override is requested
     * 
     * The JWT's aud is a whitelisted recovery aud, not the one `account` 
     * was created with. 
     */
    override?: boolean,
}
export type SocialAccountResult = 'idle' | SocialAccount;

/** 
 * What a locally generated proof needs from the relayer: 
 * - `recover(newPubkey, signature)` 
 * - proof 
 * - facts
 */
export type ProofRecoverRequest = {
    account: string,
    newPubkey: string,
    signature: { r: string, s: string },
    /** The SNIP-36 proof, base64. */
    proof: string,
    /** The 9 proof facts the gateway and `recover` check. */
    proofFacts: string[],
    override?: boolean,
};
export type LoginOptions = {
    /** 
     * Prove in this browser instead of sending the JWT to a backend's `recover`. 
     * Needs `localProver` in the config. 
     */
    local?: boolean,
    /** 
     * Which prover module to run locally. Default `recommendedBuild()`. 
     */
    build?: ProverBuild,
};


type SessionData = {
    provider: Provider,
    nonce: string,
    state: string,
    blinding: string,
    /** 
     * Set by recoverOverride.
     * 
     * The locked-out account to recover instead of the one derived from the token. 
     */
    overrideAccount?: string,
    /** 
     * Prove locally after the redirect. Decided before the token exists. 
     */
    local?: boolean,
    build?: ProverBuild,
};

export interface ISocialAccountClient {
    /**
     * Redirect to the provider. The result arrives in `onLoginRedirect` after the callback.
     *
     * @param keypair The newly minted key pair the account will be recovered onto. Keep it
     *                across the redirect.
     * @param provider The issuer to sign in with. Needs a client ID in the config.
     */
    login(keypair: KeyPair, provider: Provider, opts?: LoginOptions): void;

    /**
     * Recover `account`, created under another aud that is no longer available, through this
     * client's aud, which must be whitelisted in the JwkRegistry. The redirect lands in
     * `onLoginRedirect` like a normal login. The contract only records a pending recovery;
     * after RECOVERY_DELAY submit `finalizeOverrideCall` with the same key pair.
     *
     * @param keypair The newly minted key pair. Keep it until the recovery is finalized.
     * @param account The locked-out account's address.
     * @param provider The issuer to sign in with. Must be the issuer the account was created under.
     */
    recoverOverride(keypair: KeyPair, account: string, provider: Provider, opts?: LoginOptions): void;

    /**
     * Call on the callback page. Verifies the session, derives or restores the account
     * address, deploys when needed and asks the backend to recover.
     *
     * @param keypair The key pair passed to `login` or `recoverOverride`.
     * @returns 'idle' when the page is not a provider callback, otherwise the account's address
     *          and identity.
     */
    onLoginRedirect(keypair: KeyPair): Promise<SocialAccountResult>;

    /**
     * The call that completes an override recovery once RECOVERY_DELAY has passed. Anyone can
     * submit it, so the app may use a relayer or the hook it uses for deploys.
     *
     * @param keypair The key pair passed to `recoverOverride`.
     * @param account The account with the pending recovery.
     * @returns The `finalize_override_recovery` call, signed for the account's current key.
     */
    finalizeOverrideCall(keypair: KeyPair, account: string): Promise<Call>;

    /**
     * The call that drops a pending override recovery. The contract accepts it only from the
     * account itself, so the current owner submits it as a transaction of `account`.
     *
     * @param account The account with the pending recovery.
     * @returns The `cancel_override_recovery` call.
     */
    cancelOverrideCall(account: string): Call;
}

export class SocialAccountClient implements ISocialAccountClient {

    private readonly config: SocialAccountClientConfig;
    private readonly provider: RpcProvider;

    constructor(config: SocialAccountClientConfig) {
        this.config = config;
        this.provider = new RpcProvider({ nodeUrl: config.rpcUrl })
    }

    public login(keypair: KeyPair, provider: Provider, opts: LoginOptions = {}) {
        this.startLogin(keypair, provider, this.localOptions(opts));
    }

    public recoverOverride(keypair: KeyPair, account: string, provider: Provider, opts: LoginOptions = {}) {
        this.startLogin(keypair, provider, { overrideAccount: account, ...this.localOptions(opts) });
    }

    private localOptions(opts: LoginOptions): Pick<SessionData, 'local' | 'build'> {
        if (!opts.local) return {};
        if (!this.config.localProver) throw new Error('NO_LOCAL_PROVER');
        const support = localProvingSupport();
        if (!support.ok) throw new Error(`LOCAL_PROVING_UNSUPPORTED: ${support.reason}`);
        return { local: true, build: opts.build ?? recommendedBuild() };
    }

    private startLogin(keypair: KeyPair, provider: Provider, extra: Pick<SessionData, 'overrideAccount' | 'local' | 'build'>) {
        const blinding = randomFelt();
        const nonceRequest = nonce(keypair.publicKey, blinding);
        const state = crypto.randomUUID()
        const url = this.getLoginUrl(provider, nonceRequest, state);

        const sessionData: SessionData = {
            provider,
            nonce: nonceRequest,
            state,
            blinding,
            ...extra,
        }
        sessionStorage.setItem(SESSION_DATA_KEY, JSON.stringify(sessionData));

        location.assign(url);
    }

    public async onLoginRedirect(keypair: KeyPair): Promise<SocialAccountResult> {
        const params = new URLSearchParams(location.hash.slice(1));
        // Not a provider callback: nothing to do, and the pending session must survive
        if (!params.has('id_token') && !params.has('error')) return 'idle';

        const sessionDataJson = sessionStorage.getItem(SESSION_DATA_KEY);
        if (!sessionDataJson) {
            throw new Error('INVALID_SESSION');
        }

        const sessionData: SessionData | null = JSON.parse(sessionDataJson);
        if (!sessionData) {
            throw new Error('INVALID_SESSION');
        }

        sessionStorage.removeItem(SESSION_DATA_KEY);
        history.replaceState(null, '', '/');

        if (params.has('error')) {
            throw new Error(`${sessionData.provider}: ${params.get('error')}`);
        }

        if (params.get('state') !== sessionData.state) {
            throw new Error('STATE_MISMATCH');
        }

        const idToken = params.get('id_token')!;
        console.log("Token:", idToken);
        const jwt = decodeJwt(idToken)
        if (jwt.payload.nonce !== sessionData.nonce) {
            throw new Error('NONCE_MISMATCH');
        }

        const override = sessionData.overrideAccount !== undefined;
        const local = sessionData.local === true;
        // A pepper service would be asked here, once the token exists.
        const pepper = NO_PEPPER;
        const accountAddress = sessionData.overrideAccount ?? accountAddressFromJwt(jwt.payload, this.config.socialAccountClassHash, pepper);
        let currentPubKey = await this.getPublicKey(accountAddress);
        if (override && currentPubKey === null) {
            throw new Error('ACCOUNT_NOT_DEPLOYED');
        }
        if (currentPubKey === null && local && !this.config.deploy) {
            throw new Error('LOCAL_MODE_NEEDS_DEPLOY');
        }
        if (currentPubKey === null && this.config.deploy) {
            const { calls } = new Deployer().buildDeployerCall(
                {
                    classHash: this.config.socialAccountClassHash,
                    salt: identity(jwt.payload, pepper),
                    unique: false,
                    constructorCalldata: constructorCalldata(jwt.payload, pepper)
                },
                '0x0',
            );
            const txHash = await this.config.deploy(calls[0], { aud: jwt.payload.aud, identity: identity(jwt.payload, pepper) });
            await this.provider.waitForTransaction(txHash);
            // The proof binds the key the account has at the base block: zero right after deployment.
            currentPubKey = '0x0';
        }

        const blinding = sessionData.blinding;
        if (local) {
            if (!this.config.localProver) throw new Error('NO_LOCAL_PROVER');
            const { proveLocally } = await import('./prover/local-prover');
            return proveLocally({
                config: { ...this.config, localProver: this.config.localProver },
                provider: this.provider,
                jwt: jwt,
                account: accountAddress,
                keypair,
                blinding,
                pepper,
                currentPubKey: currentPubKey ?? '0x0',
                override,
                build: sessionData.build ?? recommendedBuild(),
            });
        }

        const socialAccount = await this.requestRecovery(
            idToken,
            accountAddress,
            keypair,
            blinding,
            pepper,
            currentPubKey,
            override,
        );

        return socialAccount;
    }

    public async finalizeOverrideCall(keypair: KeyPair, account: string): Promise<Call> {
        const currentPubKey = await this.getPublicKey(account);
        if (currentPubKey === null) {
            throw new Error('ACCOUNT_NOT_DEPLOYED');
        }
        const [r, s] = acceptOwnershipSignature(account, currentPubKey, keypair.privateKey);
        return {
            contractAddress: account,
            entrypoint: 'finalize_override_recovery',
            calldata: CallData.compile([keypair.publicKey, [r, s]]),
        };
    }

    public cancelOverrideCall(account: string): Call {
        return { contractAddress: account, entrypoint: 'cancel_override_recovery', calldata: [] };
    }

    private getLoginUrl(provider: Provider, nonce: string, state: string): string {
        const clientId = this.config.clientIds[provider];
        if (!clientId) throw new Error(`${provider}: NO_CLIENT_ID`);
        const url = new URL(AUTH_URLS[provider]);
        const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: this.config.callbackUrl,
            nonce,
            state,
            ...(provider === 'google'
                ? { response_type: 'id_token', scope: 'openid', prompt: 'select_account' }
                // Apple refuses a bare id_token, and any scope forces form_post. Without a scope the
                // token lands in the fragment like Google's. The code that comes with it is ignored.
                : { response_type: 'code id_token', response_mode: 'fragment' }),
        });
        url.search = params.toString();
        return url.toString();
    }

    private async getPublicKey(accountAddress: string): Promise<string | null> {
        try {
            const [pubkey] = await this.provider.callContract({
                contractAddress: accountAddress,
                entrypoint: "get_public_key",
                calldata: [],
            });
            return pubkey;
        } catch (error) {
            if (error instanceof RpcError && error.isType('CONTRACT_NOT_FOUND')) {
                return null
            }
            throw error;
        };
    }

    private async requestRecovery(
        jwt: string,
        accountAddress: string,
        newKeyPair: KeyPair,
        blinding: string,
        pepper: string,
        currentPubKey: string | null,
        override: boolean,
    ): Promise<SocialAccount> {
        const signature = acceptOwnershipSignature(accountAddress, currentPubKey ?? '0x0', newKeyPair.privateKey)

        const requestBody: RecoverRequest = {
            jwt,
            account: accountAddress,
            newPubkey: newKeyPair.publicKey,
            signature: { r: signature[0], s: signature[1] },
            blinding,
            pepper,
            override,
        };
        return this.config.recover(requestBody);
    }
}