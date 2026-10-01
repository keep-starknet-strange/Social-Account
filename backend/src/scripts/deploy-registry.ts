import { Account, json } from 'starknet';
import { chainName, env, makeProvider, upsertEnv } from '../env';

const CONTRACT_DIR = `${import.meta.dir}/../../../social_account`;
const ARTIFACT = `${CONTRACT_DIR}/target/dev/social_account_JwkRegistry`;
const ENV_FILE = `${import.meta.dir}/../../.env`;

const build = Bun.spawnSync(['scarb', 'build'], { cwd: CONTRACT_DIR, stdout: 'inherit', stderr: 'inherit' });
if (build.exitCode !== 0) process.exit(build.exitCode);

const provider = makeProvider();
const chain = await chainName(provider);
const ownerAccount = new Account({
  provider,
  address: env('OWNER_ADDRESS'),
  signer: env('OWNER_PRIVATE_KEY'),
});
const contract = json.parse(await Bun.file(`${ARTIFACT}.contract_class.json`).text());
const casm = json.parse(await Bun.file(`${ARTIFACT}.compiled_contract_class.json`).text());

console.log(`Deploying JwkRegistry on ${chain}, owner ${ownerAccount.address}`);
const blockBefore = await provider.getBlockNumber();
const { declare, deploy } = await ownerAccount.declareAndDeploy({
  contract,
  casm,
  constructorCalldata: [ownerAccount.address],
});
console.log(`Class ${declare.class_hash}\nDeploy tx ${deploy.transaction_hash}`);
const receipt = (await provider.waitForTransaction(deploy.transaction_hash)) as { block_number?: number };

const vars = {
  [`${chain}_REGISTRY_ADDRESS`]: deploy.contract_address,
  [`${chain}_REGISTRY_BLOCK`]: String(receipt.block_number ?? blockBefore),
};
await Bun.write(ENV_FILE, upsertEnv(await Bun.file(ENV_FILE).text().catch(() => ''), vars));
console.log(vars);
