import { Account, CallData, byteArray, hash, json } from 'starknet';
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

const defaultRecoveryAud = {
  iss: env('REGISTRY_RECOVERY_DEFAULT_ISSUER'),
  aud: env('REGISTRY_RECOVERY_DEFAULT_AUDIENCE')
};

// Address = f(salt, class hash, [owner]) on every network. iss/aud are set after, so they may differ per network.
const salt = '0x6a776b5f72656769737472795f7631'; // "hex(jwk_registry_v1)"
const constructorCalldata = [ownerAccount.address];
const classHash = hash.computeContractClassHash(contract);
const address = hash.calculateContractAddressFromHash(salt, classHash, constructorCalldata, 0);
const deployed = await provider.getClassHashAt(address).then(() => true, () => false);

console.log(`JwkRegistry on ${chain} at ${address}, owner ${ownerAccount.address}, recovery aud ${defaultRecoveryAud.aud}`);
if (deployed) {
  console.log('Already deployed');
} else {
  const blockBefore = await provider.getBlockNumber();
  const { declare, deploy } = await ownerAccount.declareAndDeploy({
    contract,
    casm,
    salt,
    unique: false,
    constructorCalldata,
  });
  console.log(`Class ${declare.class_hash}\nDeploy tx ${deploy.transaction_hash}`);
  const receipt = (await provider.waitForTransaction(deploy.transaction_hash)) as { block_number?: number };
  const vars = {
    [`${chain}_REGISTRY_ADDRESS`]: address,
    [`${chain}_REGISTRY_BLOCK`]: String(receipt.block_number ?? blockBefore),
  };
  await Bun.write(ENV_FILE, upsertEnv(await Bun.file(ENV_FILE).text().catch(() => ''), vars));
  console.log(vars);
}

const [initialized] = await provider.callContract({ contractAddress: address, entrypoint: 'is_initialized' });
if (BigInt(initialized) === 1n) {
  console.log('Already initialized');
} else {
  const init = await ownerAccount.execute({
    contractAddress: address,
    entrypoint: 'initialize',
    calldata: CallData.compile([
      byteArray.byteArrayFromString(defaultRecoveryAud.iss),
      byteArray.byteArrayFromString(defaultRecoveryAud.aud),
    ]),
  });
  await provider.waitForTransaction(init.transaction_hash);
  console.log(`Initialize tx ${init.transaction_hash}`);
}
