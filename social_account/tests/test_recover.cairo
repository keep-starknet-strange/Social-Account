//! `recover` is the only part of SocialAccount that runs on the live chain. Without proof facts it
//! must be refused on mainnet, and elsewhere it may only consume the approval an on-chain
//! `prove_jwt` left behind (the POC escape hatch in SocialComponent).

use core::poseidon::poseidon_hash_span;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_timestamp,
    start_cheat_chain_id, store,
};
use social_account::social::interface::{
    ISocialRecoverableSafeDispatcher, ISocialRecoverableSafeDispatcherTrait,
};
use starknet::{ContractAddress, SyscallResultTrait};

/// poseidon(iss, aud, sub) in real life; any felt works here.
const IDENTITY: felt252 = 0xabc;
const NEW_KEY: felt252 = 0x222;

fn deploy() -> ContractAddress {
    let class = declare("SocialAccount").unwrap_syscall().contract_class();
    let (account, _) = class.deploy(@array![IDENTITY]).unwrap_syscall();
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

#[test]
#[feature("safe_dispatcher")]
fn an_on_chain_approval_dies_with_its_token() {
    let account = deploy();
    let safe = ISocialRecoverableSafeDispatcher { contract_address: account };
    start_cheat_chain_id(account, 'SN_SEPOLIA');

    // What prove_jwt leaves behind: the approval for (NEW_KEY, current key = 0) and the token's
    // exp.
    let approval = poseidon_hash_span([NEW_KEY, 0].span());
    store(account, selector!("testnet_approved_recovery"), array![approval].span());
    store(account, selector!("testnet_approved_until"), array![1000].span());

    start_cheat_block_timestamp(account, 1000);
    match safe.recover(NEW_KEY, array![].span()) {
        Ok(_) => panic!("recovered with an expired approval"),
        Err(e) => assert!(*e.at(0) == 'APPROVAL_EXPIRED'),
    }

    // Before exp the approval is consumed and the call goes on to the signature check.
    start_cheat_block_timestamp(account, 999);
    match safe.recover(NEW_KEY, array![].span()) {
        Ok(_) => panic!("recovered without a signature"),
        Err(e) => assert!(*e.at(0) != 'APPROVAL_EXPIRED' && *e.at(0) != 'NOT_APPROVED'),
    }
}
