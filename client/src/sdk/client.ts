import { Call, Deployer, RpcError, RpcProvider } from "starknet";
import { acceptOwnershipSignature, accountAddressFromJwt, decodeJwtPayload, identity, nonce, randomFelt } from "./utils";

const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const SESSION_DATA_KEY = "session_data";

export type KeyPair = { privateKey: string; publicKey: string };
export type SocialAccountClientConfig = {
    clientId: string,
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
     * for the server to do that instead.
     * 
     * @param call The deploy call to be handled.
     * @returns The tx hash of the deploy transaction.
     */
    deploy?: (call: Call) => Promise<string>;
};
export type JwtPayload = {
    iss: string;
    aud: string;
    sub: string;
    nonce: string;
    exp: number;
};
export type SocialAccount = {
    address: string;
    identity: string;
};
export type RecoverRequest = {
    jwt: string,
    account: string,
    newPubkey: string,
    signature: { r: string, s: string }
}
export type SocialAccountResult = 'idle' | 'redirecting' | SocialAccount;


type GoogleAuthPromptType = 'select_account' | 'consent' | 'none';
type SessionData = {
    nonce: string,
    state: string,
    sub?: string
};

export class SocialAccountClient {

    private readonly config: SocialAccountClientConfig;
    private readonly provider: RpcProvider;

    constructor(config: SocialAccountClientConfig) {
        this.config = config;
        this.provider = new RpcProvider({ nodeUrl: config.rpcUrl })
    }

    public login() {
        // Attempt first login with random nonce to receive "sub"
        const nonce = randomFelt();
        const state = crypto.randomUUID()
        const url = this.getLoginUrl(nonce, state, 'select_account');

        const sessionData: SessionData = {
            nonce,
            state
        }
        sessionStorage.setItem(SESSION_DATA_KEY, JSON.stringify(sessionData));

        location.assign(url);
    }

    public async onLoginRedirect(keypair: KeyPair): Promise<SocialAccountResult> {
        const params = new URLSearchParams(location.hash.slice(1));
        // Not a Google callback: nothing to do, and the pending session must survive
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
            throw new Error(`google: ${params.get('error')}`);
        }

        if (params.get('state') !== sessionData.state) {
            throw new Error('STATE_MISMATCH');
        }

        const idToken = params.get('id_token')!;
        const jwtPayload = decodeJwtPayload(idToken);
        if (jwtPayload.nonce !== sessionData.nonce) {
            throw new Error('NONCE_MISMATCH');
        }

        const accountAddress = accountAddressFromJwt(jwtPayload, this.config.socialAccountClassHash);

        if (sessionData.sub) {
            if (jwtPayload.sub != sessionData.sub) {
                throw new Error('SUB_MISMATCH');
            }
            const currentPubKey = await this.getPublicKey(accountAddress);

            if (currentPubKey === null && this.config.deploy) {
                const id = identity(jwtPayload);
                const { calls } = new Deployer().buildDeployerCall(
                    {
                        classHash: this.config.socialAccountClassHash,
                        salt: id,
                        unique: false,
                        constructorCalldata: [id]
                    },
                    '0x0',
                );
                const txHash = await this.config.deploy(calls[0]);
                await this.provider.waitForTransaction(txHash);
            }

            const socialAccount = await this.requestRecovery(
                idToken,
                accountAddress,
                keypair,
                currentPubKey
            );

            return socialAccount;
        } else {
            // Just learned about sub, make a request with real nonce
            const currentPubKey = await this.getPublicKey(accountAddress) ?? '0';

            const sessionDataWithSub: SessionData = {
                ...sessionData,
                nonce: nonce(
                    accountAddress,
                    keypair.publicKey,
                    currentPubKey
                ),
                state: crypto.randomUUID(),
                sub: jwtPayload.sub
            }
            sessionStorage.setItem(SESSION_DATA_KEY, JSON.stringify(sessionDataWithSub));

            // login_hint = sub: lets Google pick the account silently when several are signed in
            const url = this.getLoginUrl(sessionDataWithSub.nonce, sessionDataWithSub.state, 'none', jwtPayload.sub);
            location.assign(url);
            return 'redirecting';
        }
    }

    private getLoginUrl(
        nonce: string,
        state: string,
        prompt: GoogleAuthPromptType,
        loginHint?: string,
    ): string {
        const url = new URL(GOOGLE_AUTH_URL);
        const params = new URLSearchParams({
            client_id: this.config.clientId,
            redirect_uri: this.config.callbackUrl,
            response_type: 'id_token',
            scope: 'openid',
            nonce,
            state,
            prompt: prompt,
        });
        if (loginHint) params.set('login_hint', loginHint);
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
        currentPubKey: string | null,
    ): Promise<SocialAccount> {
        const signature = acceptOwnershipSignature(accountAddress, currentPubKey ?? '0x0', newKeyPair.privateKey)

        const requestBody: RecoverRequest = {
            jwt, account: accountAddress, newPubkey: newKeyPair.publicKey, signature: { r: signature[0], s: signature[1] }
        };
        return this.config.recover(requestBody);
    }
}