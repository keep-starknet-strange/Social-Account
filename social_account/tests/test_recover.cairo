//! `recover` is the only part of SocialAccount that runs on the live chain. Without proof facts it
//! must be refused on mainnet, and elsewhere it may only consume the approval an on-chain
//! `prove_jwt` left behind (the POC escape hatch in SocialComponent).

use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_chain_id};
use social_account::social::interface::{
    ISocialRecoverableSafeDispatcher, ISocialRecoverableSafeDispatcherTrait,
};
use starknet::ContractAddress;

/// poseidon(iss, aud, sub) in real life; any felt works here.
const IDENTITY: felt252 = 0xabc;
const NEW_KEY: felt252 = 0x222;

fn deploy() -> ContractAddress {
    let class = declare("SocialAccount").unwrap().contract_class();
    let (account, _) = class.deploy(@array![IDENTITY]).unwrap();
    account
}

#[test]
#[feature("safe_dispatcher")]
fn recover_without_proof_facts_is_refused_on_mainnet_and_needs_an_approval_elsewhere() {
    let account = deploy();
    let safe = ISocialRecoverableSafeDispatcher { contract_address: account };

    start_cheat_chain_id(account, 'SN_MAIN');
    match safe.recover(NEW_KEY, array![].span()) {
        Ok(_) => panic!("mainnet recovered without a proof"),
        Err(e) => assert!(*e.at(0) == 'NO_PROOF_FACTS'),
    }

    // Same call off mainnet reaches the escape hatch, which has nothing to consume yet.
    start_cheat_chain_id(account, 'SN_SEPOLIA');
    match safe.recover(NEW_KEY, array![].span()) {
        Ok(_) => panic!("recovered without a proof or an on-chain approval"),
        Err(e) => assert!(*e.at(0) == 'NOT_APPROVED'),
    }
}
