// //! `recover` is the only part of SocialAccount that runs on the live chain, so it is the part
// //! worth a test. The prover is simulated by cheating `tx_info.proof_facts` to what a prover
// would //! return after `verify_login(_, new_pubkey, counter)` ran on the account in a virtual
// block.

// use snforge_std::{
//     ContractClassTrait, DeclareResultTrait, declare, start_cheat_block_number,
//     start_cheat_proof_facts,
// };
// use social_account::social::interface::{
//     ISocialRecoverableDispatcher, ISocialRecoverableDispatcherTrait,
//     ISocialRecoverableSafeDispatcher, ISocialRecoverableSafeDispatcherTrait,
// };
// use social_account::social::proof_facts::{ProofFacts, VIRTUAL_SNOS, VIRTUAL_SNOS0};
// use social_account::{message_hash, recovery_payload};
// use starknet::ContractAddress;

// /// Just enough of OpenZeppelin's IPublicKey to read the key back.
// #[starknet::interface]
// trait IPublicKey<T> {
//     fn get_public_key(self: @T) -> felt252;
// }

// const OLD_KEY: felt252 = 0x111;
// const NEW_KEY: felt252 = 0x222;
// /// poseidon(iss, aud, sub) in real life; any felt works here.
// const IDENTITY: felt252 = 0xabc;
// const BASE_BLOCK: u64 = 100;

// fn deploy() -> ContractAddress {
//     let class = declare("SocialAccount").unwrap().contract_class();
//     let jwk_registry: ContractAddress = 0xdead.try_into().unwrap();
//     let (account, _) = class.deploy(@array![OLD_KEY, IDENTITY, jwk_registry.into()]).unwrap();
//     account
// }

// /// Proof facts a prover would return once `verify_login` emitted its message on `account`.
// fn facts_for(account: ContractAddress, new_pubkey: felt252, counter: u64) -> Span<felt252> {
//     let payload = recovery_payload(account, IDENTITY, new_pubkey, counter);
//     let facts = ProofFacts {
//         proof_version: 0,
//         program_variant: VIRTUAL_SNOS,
//         virtual_program_hash: 0,
//         starknet_os_output_version: VIRTUAL_SNOS0,
//         base_block_number: BASE_BLOCK,
//         base_block_hash: 0,
//         starknet_os_config_hash: 0,
//         message_to_l1_hashes: [message_hash(account, payload)].span(),
//     };
//     let mut serialized = array![];
//     facts.serialize(ref serialized);
//     serialized.span()
// }

// #[test]
// fn recover_rotates_key_when_proof_facts_match() {
//     let account = deploy();
//     start_cheat_proof_facts(account, facts_for(account, NEW_KEY, 1));
//     start_cheat_block_number(account, BASE_BLOCK + 5);

//     ISocialRecoverableDispatcher { contract_address: account }.recover(NEW_KEY, 1);

//     assert_eq!(IPublicKeyDispatcher { contract_address: account }.get_public_key(), NEW_KEY);
//     assert_eq!(ISocialRecoverableDispatcher { contract_address: account }.recovery_counter(), 1);
// }

// #[test]
// #[feature("safe_dispatcher")]
// fn recover_rejects_proof_bound_to_another_key() {
//     let account = deploy();
//     start_cheat_proof_facts(account, facts_for(account, NEW_KEY, 1));
//     start_cheat_block_number(account, BASE_BLOCK + 5);

//     let result = ISocialRecoverableSafeDispatcher { contract_address: account }.recover(0x333,
//     1);

//     match result {
//         Result::Ok(_) => panic!("accepted a proof made for a different key"),
//         Result::Err(panic_data) => assert_eq!(*panic_data.span().at(0), 'PROOF_MISMATCH'),
//     }
// }

// #[test]
// #[feature("safe_dispatcher")]
// fn recover_rejects_replay_of_a_used_proof() {
//     let account = deploy();
//     start_cheat_proof_facts(account, facts_for(account, NEW_KEY, 1));
//     start_cheat_block_number(account, BASE_BLOCK + 5);
//     ISocialRecoverableDispatcher { contract_address: account }.recover(NEW_KEY, 1);

//     let result = ISocialRecoverableSafeDispatcher { contract_address: account }.recover(NEW_KEY,
//     1);

//     match result {
//         Result::Ok(_) => panic!("accepted the same proof twice"),
//         Result::Err(panic_data) => assert_eq!(*panic_data.span().at(0), 'REPLAY'),
//     }
// }
