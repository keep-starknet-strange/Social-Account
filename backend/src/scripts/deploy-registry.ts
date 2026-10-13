import { Account, CallData, byteArray, hash, json } from 'starknet';
import { chainName, env, makeProvider, upsertEnv } from '../env';
import { ISSUERS } from '../jwk/verification';

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

// Recovery audiences seeded on initialize, same client ids the API accepts.
const recoveryAudiences = [
  { issuer: ISSUERS[0].variant, aud: env('AUTHORIZED_GOOGLE_RECOVERY_CLIENT_ID') },
  { issuer: ISSUERS[1].variant, aud: env('AUTHORIZED_APPLE_RECOVERY_CLIENT_ID') },
];

// Address = f(salt, class hash, [owner]) on every network. iss/aud are set after, so they may differ per network.
const salt = '0x6a776b5f72656769737472795f76315f31'; // hex("jwk_registry_v1_1")
const constructorCalldata = [ownerAccount.address];
const classHash = hash.computeContractClassHash(contract);
const address = hash.calculateContractAddressFromHash(salt, classHash, constructorCalldata, 0);
const deployed = await provider.getClassHashAt(address).then(() => true, () => false);

console.log(`JwkRegistry on ${chain} at ${address}, owner ${ownerAccount.address}, recovery auds ${recoveryAudiences.map((a) => a.aud).join(', ')}`);
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
      recoveryAudiences.length,
      ...recoveryAudiences.flatMap((a) => [a.issuer, byteArray.byteArrayFromString(a.aud)]),
    ]),
  });
  await provider.waitForTransaction(init.transaction_hash);
  console.log(`Initialize tx ${init.transaction_hash}`);
}
