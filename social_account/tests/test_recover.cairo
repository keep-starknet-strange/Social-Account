//! `recover` is the only part of SocialAccount that runs on the live chain. Without proof facts
//! it must be refused everywhere, mainnet or not.

use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::PoseidonTrait;
use openzeppelin_interfaces::accounts::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait, ISRC6_ID};
use openzeppelin_interfaces::introspection::{ISRC5Dispatcher, ISRC5DispatcherTrait};
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::signature::{KeyPairTrait, SignerTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, load, start_cheat_caller_address,
    start_cheat_chain_id, store,
};
use social_account::social::component::{
    ISocialRecoverableSafeDispatcher, ISocialRecoverableSafeDispatcherTrait,
};
use starknet::{ContractAddress, SyscallResultTrait};

/// poseidon(iss, aud, sub) in real life; any felt works here.
const IDENTITY: felt252 = 0xabc;
const NEW_KEY: felt252 = 0x222;

fn deploy() -> ContractAddress {
    let class = declare("SocialAccount").unwrap_syscall().contract_class();
    let mut calldata = array![];
    let aud: ByteArray = "aud";
    aud.serialize(ref calldata);
    calldata.append(IDENTITY);
    let (account, _) = class.deploy(@calldata).unwrap_syscall();
    account
}

#[test]
#[feature("safe_dispatcher")]
fn recover_without_proof_facts_is_refused_on_every_chain() {
    let account = deploy();
    let safe = ISocialRecoverableSafeDispatcher { contract_address: account };

    for chain in ['SN_MAIN', 'SN_SEPOLIA'].span() {
        start_cheat_chain_id(account, *chain);
        match safe.recover(NEW_KEY, array![].span()) {
            Ok(_) => panic!("recovered without a proof"),
            Err(e) => assert!(*e.at(0) == 'NO_PROOF_FACTS'),
        }
    }
}

/// The constructor must register SRC6, or wallets and relayers will not see this as an account.
#[test]
fn deployed_account_advertises_src6() {
    let account = deploy();
    let src5 = ISRC5Dispatcher { contract_address: account };
    assert(src5.supports_interface(ISRC6_ID), 'SRC6_NOT_REGISTERED');
}

/// A direct key rotation must drop a pending override. Otherwise the record revives if the
/// account ever returns to the key it was proven against (issue #2).
#[test]
fn key_change_clears_pending_override() {
    let account = deploy();
    store(account, selector!("pending_recovery"), array![0x777].span());
    store(account, selector!("pending_ready_at"), array![1].span());

    // Sign OpenZeppelin's accept_ownership message with the new key; current key is 0.
    let key = KeyPairTrait::from_secret_key(0x1);
    let message = PoseidonTrait::new()
        .update_with('StarkNet Message')
        .update_with('accept_ownership')
        .update_with(account)
        .update_with(0)
        .finalize();
    let (r, s) = key.sign(message).unwrap();

    start_cheat_caller_address(account, account);
    IPublicKeyDispatcher { contract_address: account }
        .set_public_key(key.public_key, array![r, s].span());

    assert(load(account, selector!("pending_recovery"), 1) == array![0], 'PENDING_NOT_CLEARED');
    assert(load(account, selector!("pending_ready_at"), 1) == array![0], 'READY_AT_NOT_CLEARED');
}
