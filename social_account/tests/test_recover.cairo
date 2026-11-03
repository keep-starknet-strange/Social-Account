//! `recover` is the only part of SocialAccount that runs on the live chain. Without proof facts
//! it must be refused everywhere, mainnet or not.

use core::hash::{HashStateExTrait, HashStateTrait};
use core::poseidon::{PoseidonTrait, poseidon_hash_span};
use openzeppelin_interfaces::accounts::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait, ISRC6_ID};
use openzeppelin_interfaces::introspection::{ISRC5Dispatcher, ISRC5DispatcherTrait};
use snforge_std::signature::stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl};
use snforge_std::signature::{KeyPairTrait, SignerTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait, declare, load, spy_events,
    start_cheat_block_number, start_cheat_block_timestamp, start_cheat_caller_address,
    start_cheat_chain_id, start_cheat_proof_facts, store,
};
use social_account::jwt::rec_aud_component::{
    IWhitelistedAudienceRecoverableDispatcher, IWhitelistedAudienceRecoverableDispatcherTrait,
};
use social_account::jwt::registry::{IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait};
use social_account::jwt::types::Issuer;
use social_account::social::component::{
    FINALIZE_WINDOW, ISocialRecoverableSafeDispatcher, ISocialRecoverableSafeDispatcherTrait,
    JWK_REGISTRY_ADDRESS, PROOF_VALIDITY_BLOCKS, PendingOverrideRecoveryCanceledEvent,
    PendingOverrideRecoveryEvent, RECOVERY_DELAY, RecoveredEvent, SocialComponent,
};
use social_account::social::proof_facts::{VIRTUAL_SNOS, VIRTUAL_SNOS0};
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

    let (new_key, signature) = accept_ownership(account);
    start_cheat_caller_address(account, account);
    IPublicKeyDispatcher { contract_address: account }.set_public_key(new_key, signature);

    assert(load(account, selector!("pending_recovery"), 1) == array![0], 'PENDING_NOT_CLEARED');
    assert(load(account, selector!("pending_ready_at"), 1) == array![0], 'READY_AT_NOT_CLEARED');
}

/// A fresh key and its signature over OpenZeppelin's accept_ownership message, current key 0.
fn accept_ownership(account: ContractAddress) -> (felt252, Span<felt252>) {
    let key = KeyPairTrait::from_secret_key(0x1);
    let message = PoseidonTrait::new()
        .update_with('StarkNet Message')
        .update_with('accept_ownership')
        .update_with(account)
        .update_with(0)
        .finalize();
    let (r, s) = key.sign(message).unwrap();
    (key.public_key, array![r, s].span())
}

/// The registry at the address the component pins, with two recovery auds so one can go.
fn deploy_registry() -> IJwkRegistryDispatcher {
    let owner: ContractAddress = 'owner'.try_into().unwrap();
    let class = declare("JwkRegistry").unwrap_syscall().contract_class();
    class.deploy_at(@array![owner.into()], JWK_REGISTRY_ADDRESS).unwrap_syscall();
    start_cheat_caller_address(JWK_REGISTRY_ADDRESS, owner);
    let registry = IJwkRegistryDispatcher { contract_address: JWK_REGISTRY_ADDRESS };
    registry.initialize(array![(Issuer::Google, "aud"), (Issuer::Google, "aud2")]);
    registry
}

/// An override queued for `new_key` over current key 0, ready at `ready_at`, revocation count 0.
fn queue_override(account: ContractAddress, new_key: felt252, ready_at: u64) {
    let hash = core::poseidon::poseidon_hash_span([new_key, 0].span());
    store(account, selector!("pending_recovery"), array![hash].span());
    store(account, selector!("pending_ready_at"), array![ready_at.into()].span());
}

#[feature("safe_dispatcher")]
fn finalize(
    account: ContractAddress, new_key: felt252, signature: Span<felt252>,
) -> Result<(), Array<felt252>> {
    ISocialRecoverableSafeDispatcher { contract_address: account }
        .finalize_override_recovery(new_key, signature)
}

#[test]
#[feature("safe_dispatcher")]
fn finalize_works_until_the_window_closes() {
    deploy_registry();
    let account = deploy();
    let (new_key, signature) = accept_ownership(account);
    queue_override(account, new_key, 1000);

    start_cheat_block_timestamp(account, 1000 + FINALIZE_WINDOW + 1);
    match finalize(account, new_key, signature) {
        Ok(_) => panic!("expired override finalized"),
        Err(e) => assert!(*e.at(0) == 'PENDING_RECOVERY_EXPIRED'),
    }

    start_cheat_block_timestamp(account, 1000 + FINALIZE_WINDOW);
    finalize(account, new_key, signature).unwrap();
    assert!(IPublicKeyDispatcher { contract_address: account }.get_public_key() == new_key);
}

#[test]
#[feature("safe_dispatcher")]
fn finalize_refuses_after_a_registry_revocation() {
    let registry = deploy_registry();
    let account = deploy();
    let (new_key, signature) = accept_ownership(account);
    queue_override(account, new_key, 1000);
    start_cheat_block_timestamp(account, 1000);

    IWhitelistedAudienceRecoverableDispatcher { contract_address: registry.contract_address }
        .remove_whitelisted(Issuer::Google, "aud2");

    match finalize(account, new_key, signature) {
        Ok(_) => panic!("finalized after a revocation"),
        Err(e) => assert!(*e.at(0) == 'REVOKED_SINCE_PENDING'),
    }
}

/// Proof facts as the sequencer would attach them, with one L2->L1 message hash. The facts the
/// sequencer itself checks (program hash, config hash, base block hash) are arbitrary here.
fn facts(variant: felt252, base_block: u64, message_hash: felt252) -> Span<felt252> {
    array![1, variant, 0x11, VIRTUAL_SNOS0, base_block.into(), 0x22, 0x33, 1, message_hash].span()
}

/// Hash of the message `prove_jwt` emits for this recovery, current key 0.
fn message_hash(account: ContractAddress, new_key: felt252, is_override: bool) -> felt252 {
    let message = array![
        account.into(), 0, 5, account.into(), IDENTITY, new_key, 0, is_override.into(),
    ];
    poseidon_hash_span(message.span())
}

#[feature("safe_dispatcher")]
fn recover(
    account: ContractAddress, new_key: felt252, signature: Span<felt252>,
) -> Result<(), Array<felt252>> {
    ISocialRecoverableSafeDispatcher { contract_address: account }.recover(new_key, signature)
}

#[test]
#[feature("safe_dispatcher")]
fn recover_with_valid_facts_sets_the_key() {
    deploy_registry();
    let account = deploy();
    let (new_key, signature) = accept_ownership(account);
    start_cheat_proof_facts(
        account, facts(VIRTUAL_SNOS, 10, message_hash(account, new_key, false)),
    );
    start_cheat_block_number(account, 10 + PROOF_VALIDITY_BLOCKS);
    start_cheat_block_timestamp(account, 500);

    let mut spy = spy_events();
    recover(account, new_key, signature).unwrap();

    assert!(IPublicKeyDispatcher { contract_address: account }.get_public_key() == new_key);
    assert!(load(account, selector!("last_recovery"), 1) == array![500]);
    spy
        .assert_emitted(
            @array![
                (
                    account,
                    SocialComponent::Event::Recovered(RecoveredEvent { new_pubkey: new_key }),
                ),
            ],
        );
}

#[test]
#[feature("safe_dispatcher")]
fn recover_refuses_stale_mismatched_or_foreign_facts() {
    deploy_registry();
    let account = deploy();
    let (new_key, signature) = accept_ownership(account);
    let rejected = |facts: Span<felt252>, block: u64, reason: felt252| {
        start_cheat_proof_facts(account, facts);
        start_cheat_block_number(account, block);
        match recover(account, new_key, signature) {
            Ok(_) => panic!("recovered"),
            Err(e) => assert!(*e.at(0) == reason),
        }
    };
    let good = facts(VIRTUAL_SNOS, 10, message_hash(account, new_key, false));
    rejected(good, 10 + PROOF_VALIDITY_BLOCKS + 1, 'STALE_PROOF');
    rejected(
        facts(VIRTUAL_SNOS, 10, message_hash(account, new_key + 1, false)), 10, 'PROOF_MISMATCH',
    );
    rejected(
        facts('OTHER_PROGRAM', 10, message_hash(account, new_key, false)),
        10,
        'BAD_PROGRAM_VARIANT',
    );
}

#[test]
#[feature("safe_dispatcher")]
fn override_facts_queue_a_pending_recovery() {
    let registry = deploy_registry();
    IWhitelistedAudienceRecoverableDispatcher { contract_address: registry.contract_address }
        .remove_whitelisted(Issuer::Google, "aud2");
    let account = deploy();
    start_cheat_proof_facts(account, facts(VIRTUAL_SNOS, 10, message_hash(account, NEW_KEY, true)));
    start_cheat_block_number(account, 10);
    start_cheat_block_timestamp(account, 500);

    let mut spy = spy_events();
    recover(account, NEW_KEY, array![].span()).unwrap();

    let ready_at = 500 + RECOVERY_DELAY;
    assert!(IPublicKeyDispatcher { contract_address: account }.get_public_key() == 0);
    let pending = poseidon_hash_span([NEW_KEY, 0].span());
    assert!(load(account, selector!("pending_recovery"), 1) == array![pending]);
    assert!(load(account, selector!("pending_ready_at"), 1) == array![ready_at.into()]);
    assert!(load(account, selector!("pending_revocation_count"), 1) == array![1]);
    spy
        .assert_emitted(
            @array![
                (
                    account,
                    SocialComponent::Event::PendingOverrideRecovery(
                        PendingOverrideRecoveryEvent { new_pubkey: NEW_KEY, ready_at },
                    ),
                ),
            ],
        );
}

#[test]
#[feature("safe_dispatcher")]
fn only_the_account_cancels_a_pending_override() {
    let account = deploy();
    queue_override(account, NEW_KEY, 1);
    let safe = ISocialRecoverableSafeDispatcher { contract_address: account };

    match safe.cancel_override_recovery() {
        Ok(_) => panic!("stranger canceled"),
        Err(e) => assert!(*e.at(0) == 'Account: unauthorized'),
    }

    let mut spy = spy_events();
    start_cheat_caller_address(account, account);
    safe.cancel_override_recovery().unwrap();
    assert!(load(account, selector!("pending_recovery"), 1) == array![0]);
    assert!(load(account, selector!("pending_ready_at"), 1) == array![0]);
    spy
        .assert_emitted(
            @array![
                (
                    account,
                    SocialComponent::Event::PendingOverrideRecoveryCanceled(
                        PendingOverrideRecoveryCanceledEvent {},
                    ),
                ),
            ],
        );
}
