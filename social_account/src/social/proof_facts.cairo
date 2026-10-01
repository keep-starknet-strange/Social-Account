use core::iter::Extend;
use core::num::traits::Zero;
use core::poseidon::poseidon_hash_span;
use starknet::{ContractAddress, ExecutionInfo, get_block_number};

pub const VIRTUAL_SNOS: felt252 = 'VIRTUAL_SNOS';
pub const VIRTUAL_SNOS0: felt252 = 'VIRTUAL_SNOS0';


/// Proof facts as deserialized from a TXV3 transaction's `proof_facts: Vec<felt252>`
/// The structure is taken from
/// [here](https://github.com/starkware-libs/starknet-privacy/blob/b40bf109c8e5b97d9d6e8ec6db48b16b9d10a106/packages/privacy/src/utils.cairo#L509)
#[derive(Drop, Serde, Debug, Copy)]
pub struct ProofFacts {
    /// The proof version.
    pub proof_version: felt252,
    /// The proven program variant; enforced to be
    /// [`VIRTUAL_SNOS`](privacy::utils::constants::VIRTUAL_SNOS).
    pub program_variant: felt252,
    /// The hash of the virtual Starknet OS program.
    pub virtual_program_hash: felt252,
    /// The output version; enforced to be
    /// [`VIRTUAL_SNOS0`](privacy::utils::constants::VIRTUAL_SNOS0).
    pub starknet_os_output_version: felt252,
    /// The base block number.
    pub base_block_number: u64,
    /// The base block hash.
    pub base_block_hash: felt252,
    /// The hash of the Starknet OS config.
    pub starknet_os_config_hash: felt252,
    /// Hashes of messages from L2 to L1.
    pub message_to_l1_hashes: Span<felt252>,
}

#[generate_trait]
pub impl ProofFactsVerificationImpl of ProofFactsVerificationTrait {
    fn extract_verified_program(info: Box<ExecutionInfo>) -> ProofFacts {
        let mut facts_span = info.tx_info.proof_facts;
        assert(!facts_span.is_empty(), 'NO_PROOF_FACTS');
        let facts: ProofFacts = Serde::deserialize(ref facts_span).expect('BAD_PROOF_FACTS');
        assert(facts_span.is_empty(), 'BAD_PROOF_FACTS');

        assert(facts.program_variant == VIRTUAL_SNOS, 'BAD_PROGRAM_VARIANT');
        assert(facts.starknet_os_output_version == VIRTUAL_SNOS0, 'BAD_OS_OUTPUT_VERSION');

        facts
    }

    fn assert(
        self: @ProofFacts,
        max_validity_blocks: u64,
        contract_address: ContractAddress,
        message_payload: Array<felt252>,
    ) {
        let now = get_block_number();
        assert(now <= *self.base_block_number + max_validity_blocks, 'STALE_PROOF');

        let mut message = array![contract_address.into(), 0_felt252, message_payload.len().into()];
        message.extend(message_payload);
        let expected_message_hash = poseidon_hash_span(message.span());
        assert(*self.message_to_l1_hashes == [expected_message_hash].span(), 'PROOF_MISMATCH');
    }
}
