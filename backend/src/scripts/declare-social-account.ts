// Declares the SocialAccount class
// Stores SOCIAL_ACCOUNT_CLASS_HASH in backend/.env.

import { Account, config, json } from 'starknet';
import { chainName, env, makeProvider, upsertEnv } from '../env';

const CONTRACT_DIR = `${import.meta.dir}/../../../social_account`;
const ARTIFACT = `${CONTRACT_DIR}/target/dev/social_account_SocialAccount`;
const ENV_FILE = `${import.meta.dir}/../../.env`;

const build = Bun.spawnSync(['scarb', 'build'], { cwd: CONTRACT_DIR, stdout: 'inherit', stderr: 'inherit' });
if (build.exitCode !== 0) process.exit(build.exitCode);

// The class is large (garaga RSA), so declaring it costs tens of STRK. starknet.js caps the fee at
// 1.5x the estimated amount times 1.5x the price, 2.25x in total, and the sender must hold that
// cap. A 10% margin keeps the cap close to the real cost of a one-off declaration.
const margin = { max_amount: 10, max_price_per_unit: 10 };
config.set('resourceBoundsOverhead', { l1_gas: margin, l2_gas: margin, l1_data_gas: margin });

const provider = makeProvider();
const chain = await chainName(provider);
const owner = new Account({ provider, address: env('OWNER_ADDRESS'), signer: env('OWNER_PRIVATE_KEY') });
const contract = json.parse(await Bun.file(`${ARTIFACT}.contract_class.json`).text());
const casm = json.parse(await Bun.file(`${ARTIFACT}.compiled_contract_class.json`).text());

console.log(`declaring SocialAccount on ${chain} from ${owner.address}`);
const { class_hash, transaction_hash } = await owner.declareIfNot({ contract, casm });
if (transaction_hash) {
  console.log(`tx ${transaction_hash}`);
  console.log(`class hash ${class_hash}`);
  await provider.waitForTransaction(transaction_hash);
} else {
  console.log('already declared class hash: ' + class_hash);
}

// A class hash is a hash of the code, so it is the same on every chain; only the declaration is per chain.
const vars = { SOCIAL_ACCOUNT_CLASS_HASH: class_hash };
await Bun.write(ENV_FILE, upsertEnv(await Bun.file(ENV_FILE).text().catch(() => ''), vars));
