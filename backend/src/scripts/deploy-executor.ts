// Declares and deploys ProverExecutor, the keyless sender of virtual prove_jwt transactions
// (social_account/src/social/prover_executor.cairo). UDC deploy from zero with a fixed salt and
// no calldata, so the address depends on the class hash alone and is the same on every chain.
// Stores PROVER_EXECUTOR_ADDRESS in backend/.env. Copy it to VITE_PROVER_EXECUTOR_ADDRESS in client/.env.

import { Account, hash, json } from 'starknet';
import { chainName, env, makeProvider, upsertEnv } from '../env';

const CONTRACT_DIR = `${import.meta.dir}/../../../social_account`;
const ARTIFACT = `${CONTRACT_DIR}/target/dev/social_account_ProverExecutor`;
const ENV_FILE = `${import.meta.dir}/../../.env`;

const build = Bun.spawnSync(['scarb', 'build'], { cwd: CONTRACT_DIR, stdout: 'inherit', stderr: 'inherit' });
if (build.exitCode !== 0) process.exit(build.exitCode);

const provider = makeProvider();
const chain = await chainName(provider);
const owner = new Account({ provider, address: env('OWNER_ADDRESS'), signer: env('OWNER_PRIVATE_KEY') });
const contract = json.parse(await Bun.file(`${ARTIFACT}.contract_class.json`).text());
const casm = json.parse(await Bun.file(`${ARTIFACT}.compiled_contract_class.json`).text());

const salt = '0x70726f7665725f6578656375746f725f7631'; // hex("prover_executor_v1")
const classHash = hash.computeContractClassHash(contract);
const address = hash.calculateContractAddressFromHash(salt, classHash, [], 0);
const deployed = await provider.getClassHashAt(address).then(() => true, () => false);

console.log(`ProverExecutor on ${chain} at ${address}, class ${classHash}`);
if (deployed) {
  console.log('Already deployed');
} else {
  const { declare, deploy } = await owner.declareAndDeploy({ contract, casm, salt, unique: false, constructorCalldata: [] });
  console.log(`Declare tx ${declare.transaction_hash || '(already declared)'}\nDeploy tx ${deploy.transaction_hash}`);
  await provider.waitForTransaction(deploy.transaction_hash);
}
await Bun.write(ENV_FILE, upsertEnv(await Bun.file(ENV_FILE).text().catch(() => ''), { PROVER_EXECUTOR_ADDRESS: address }));
