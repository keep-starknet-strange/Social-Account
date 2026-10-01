#[starknet::component]
pub mod SocialComponent {
    use SRC5Component::InternalTrait;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use interface::ISocialRecoverable;
    use openzeppelin_interfaces::accounts::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
    use openzeppelin_introspection::src5::SRC5Component;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::{
        ContractAddress, SyscallResultTrait, get_block_timestamp, get_contract_address,
        get_execution_info,
    };
    use crate::jwt::verification::verify_and_extract;
    use crate::social::events::RecoveredEvent;
    use crate::social::interface;
    use crate::social::proof_facts::{ProofFacts, ProofFactsVerificationTrait};

    /// How many blocks after its base block a proof stays usable.
    pub const PROOF_VALIDITY_BLOCKS: u64 = 100;

    #[storage]
    pub struct Storage {
        // TODO: Maybe add issuer
        /// poseidon(iss, aud, sub) of the Google account allowed to recover this one.
        identity: felt252,
        /// The shared JwkRegistry.
        jwk_registry: ContractAddress,
    }

    #[event]
    #[derive(Drop, Debug, PartialEq, starknet::Event)]
    pub enum Event {
        Recovered: RecoveredEvent,
    }

    #[embeddable_as(SocialRecoverableImpl)]
    impl SocialRecoverable<
        TContractState, +HasComponent<TContractState>,
    > of ISocialRecoverable<ComponentState<TContractState>> {
        fn prove_jwt(
            self: @ComponentState<TContractState>,
            header_b64: ByteArray,
            payload_b64: ByteArray,
            kid: ByteArray,
            rsa_hint: Span<felt252>,
            new_pubkey: felt252,
        ) {
            let claims = verify_and_extract(
                header_b64, payload_b64, kid, rsa_hint, self.jwk_registry.read(),
            );

            let identity = self.identity.read();
            assert(claims.identity == identity, 'WRONG_GOOGLE_ACCOUNT');
            assert(claims.exp > get_block_timestamp(), 'TOKEN_EXPIRED');

            let account_address = get_contract_address();
            let current_pubkey = IPublicKeyDispatcher { contract_address: account_address }
                .get_public_key();

            let nonce = poseidon_hash_span(
                [account_address.into(), new_pubkey, current_pubkey].span(),
            );
            assert(claims.nonce == nonce, 'NONCE_MISMATCH');

            send_message_to_l1_syscall(
                to_address: Zero::zero(),
                payload: [account_address.into(), identity, new_pubkey, current_pubkey].span(),
            )
                .unwrap_syscall();
        }

        fn recover(
            ref self: ComponentState<TContractState>, new_pubkey: felt252, signature: Span<felt252>,
        ) {
            let info = get_execution_info();

            let facts = ProofFactsVerificationTrait::extract_verified_program(info);

            let current_pubkey = IPublicKeyDispatcher { contract_address: get_contract_address() }
                .get_public_key();
            let account_address = get_contract_address();
            let identity = self.identity.read();

            facts
                .assert(
                    PROOF_VALIDITY_BLOCKS,
                    account_address,
                    array![account_address.into(), identity, new_pubkey, current_pubkey],
                );

            IPublicKeyDispatcher { contract_address: get_contract_address() }
                .set_public_key(new_pubkey, signature);

            self.emit(RecoveredEvent { new_pubkey });
        }

        fn identity(self: @ComponentState<TContractState>) -> felt252 {
            self.identity.read()
        }
    }

    #[generate_trait]
    pub impl InternalSocialComponentImpl<
        TContractState,
        +HasComponent<TContractState>,
        impl SRC5: SRC5Component::HasComponent<TContractState>,
        +Drop<TContractState>,
    > of InternalSocialComponentTrait<TContractState> {
        fn initializer(
            ref self: ComponentState<TContractState>,
            identity: felt252,
            jwk_registry: ContractAddress,
        ) {
            let mut src5_component = get_dep_component_mut!(ref self, SRC5);
            src5_component.register_interface(interface::SOCIAL_ID);

            self.identity.write(identity);
            self.jwk_registry.write(jwk_registry);
        }
    }
}
