//! `prove_jwt` only runs inside the prover, but its checks are plain Cairo. They run here
//! against a self-signed token (tests/data/test_jwt.txt) whose nonce preimage is known. The
//! registry accepts any key for an issuer, so the test key is set under Google's `iss`.

use garaga::signatures::rsa::RSA2048PublicKey;
use snforge_std::fs::{FileTrait, read_txt};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, MessageToL1, MessageToL1SpyAssertionsTrait, declare,
    spy_messages_to_l1, start_cheat_block_timestamp, start_cheat_caller_address, store,
};
use social_account::jwt::registry::{IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait};
use social_account::jwt::types::{Issuer, JwtPayload, JwtPayloadTrait};
use social_account::social::component::{
    ISocialRecoverableSafeDispatcher, ISocialRecoverableSafeDispatcherTrait, JWK_REGISTRY_ADDRESS,
};
use starknet::{ContractAddress, SyscallResultTrait};

// Must match backend/src/scripts/gen-jwt-fixture.ts.
const NEW_KEY: felt252 = 0x222;
const BLINDING: felt252 = 0x333;
const IAT: u64 = 1_000_000;
const EXP: u64 = 2_000_000;

#[derive(Drop)]
struct Token {
    header: ByteArray,
    payload: ByteArray,
    key: RSA2048PublicKey,
    hint: Span<felt252>,
}

fn token() -> Token {
    let mut felts = read_txt(@FileTrait::new("tests/data/test_jwt.txt")).span();
    let header = Serde::<ByteArray>::deserialize(ref felts).unwrap();
    let payload = Serde::<ByteArray>::deserialize(ref felts).unwrap();
    let key = Serde::<RSA2048PublicKey>::deserialize(ref felts).unwrap();
    Token { header, payload, key, hint: felts }
}

/// poseidon(iss, aud, sub) for the token's iss and sub.
fn identity(aud: ByteArray) -> felt252 {
    JwtPayload { iss: "https://accounts.google.com", aud, sub: "sub-1", nonce: 0, exp: 0, iat: 0 }
        .identity()
}

/// The registry at the pinned address: the test key under Google's iss, `recovery_auds`
/// whitelisted.
fn deploy_registry(recovery_auds: Array<ByteArray>) {
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let class = declare("JwkRegistry").unwrap_syscall().contract_class();
    class.deploy_at(@array![owner.into()], JWK_REGISTRY_ADDRESS).unwrap_syscall();
    start_cheat_caller_address(JWK_REGISTRY_ADDRESS, owner);
    let registry = IJwkRegistryDispatcher { contract_address: JWK_REGISTRY_ADDRESS };
    let mut auds = array![];
    for aud in recovery_auds {
        auds.append((Issuer::Google, aud));
    }
    registry.initialize(auds);
    registry.set_key(Issuer::Google, "test-kid", token().key);
}

fn deploy_account(original_aud: ByteArray, identity: felt252) -> ContractAddress {
    let class = declare("SocialAccount").unwrap_syscall().contract_class();
    let mut calldata = array![];
    original_aud.serialize(ref calldata);
    calldata.append(identity);
    let (account, _) = class.deploy(@calldata).unwrap_syscall();
    account
}

#[feature("safe_dispatcher")]
fn prove(account: ContractAddress, blinding: felt252) -> Result<(), Array<felt252>> {
    let t = token();
    ISocialRecoverableSafeDispatcher { contract_address: account }
        .prove_jwt(t.header, t.payload, "test-kid", t.hint, NEW_KEY, blinding)
}

fn error(result: Result<(), Array<felt252>>) -> felt252 {
    match result {
        Ok(_) => panic!("prove_jwt passed"),
        Err(e) => *e.at(0),
    }
}

/// The L2->L1 message `recover` later checks the proof facts against.
fn message(
    account: ContractAddress, identity: felt252, is_override: bool,
) -> (ContractAddress, MessageToL1) {
    let payload = array![account.into(), identity, NEW_KEY, 0, is_override.into()];
    (account, MessageToL1 { to_address: 0.try_into().unwrap(), payload })
}

#[test]
#[feature("safe_dispatcher")]
fn same_aud_token_proves_a_normal_recovery() {
    deploy_registry(array!["recovery"]);
    let account = deploy_account("aud", identity("aud"));
    let mut spy = spy_messages_to_l1();
    prove(account, BLINDING).unwrap();
    spy.assert_sent(@array![message(account, identity("aud"), false)]);
}

#[test]
#[feature("safe_dispatcher")]
fn whitelisted_aud_token_proves_an_override() {
    deploy_registry(array!["aud"]);
    let account = deploy_account("original", identity("original"));
    let mut spy = spy_messages_to_l1();
    prove(account, BLINDING).unwrap();
    spy.assert_sent(@array![message(account, identity("original"), true)]);
}

#[test]
#[feature("safe_dispatcher")]
fn other_aud_token_is_refused_unless_whitelisted() {
    deploy_registry(array!["other"]);
    let account = deploy_account("original", identity("original"));
    assert!(error(prove(account, BLINDING)) == 'INVALID_RECOVERY_AUD');
}

#[test]
#[feature("safe_dispatcher")]
fn token_for_another_user_is_refused() {
    deploy_registry(array!["aud"]);
    let account = deploy_account("original", 0xabc);
    assert!(error(prove(account, BLINDING)) == 'WRONG_IDENTITY');
}

#[test]
#[feature("safe_dispatcher")]
fn expired_token_is_refused() {
    deploy_registry(array!["recovery"]);
    let account = deploy_account("aud", identity("aud"));
    start_cheat_block_timestamp(account, EXP);
    assert!(error(prove(account, BLINDING)) == 'TOKEN_EXPIRED');
}

#[test]
#[feature("safe_dispatcher")]
fn nonce_must_bind_the_new_key() {
    deploy_registry(array!["recovery"]);
    let account = deploy_account("aud", identity("aud"));
    assert!(error(prove(account, BLINDING + 1)) == 'NONCE_MISMATCH');
}

#[test]
#[feature("safe_dispatcher")]
fn token_older_than_the_last_recovery_is_refused() {
    deploy_registry(array!["recovery"]);
    let account = deploy_account("aud", identity("aud"));
    store(account, selector!("last_recovery"), array![IAT.into()].span());
    assert!(error(prove(account, BLINDING)) == 'STALE_IAT');
}
