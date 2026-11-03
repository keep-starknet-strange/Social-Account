//! `recover` is the only part of SocialAccount that runs on the live chain. Without proof facts
//! it must be refused everywhere, mainnet or not.

use openzeppelin_interfaces::accounts::ISRC6_ID;
use openzeppelin_interfaces::introspection::{ISRC5Dispatcher, ISRC5DispatcherTrait};
use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_chain_id};
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
