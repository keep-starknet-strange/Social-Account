#[starknet::component]
pub mod SocialComponent {
    use SRC5Component::InternalTrait;
    use core::num::traits::Zero;
    use core::poseidon::poseidon_hash_span;
    use interface::{ISocialRecoverable, JWK_REGISTRY_ADDRESS, PROOF_VALIDITY_BLOCKS};
    use openzeppelin_interfaces::accounts::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
    use openzeppelin_introspection::src5::SRC5Component;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::syscalls::send_message_to_l1_syscall;
    use starknet::{
        SyscallResultTrait, get_block_timestamp, get_contract_address, get_execution_info,
    };
    use crate::jwt::verification::verify_and_extract;
    use crate::social::events::RecoveredEvent;
    use crate::social::interface;
    use crate::social::proof_facts::ProofFactsVerificationTrait;


    #[storage]
    pub struct Storage {
        /// poseidon(iss, aud, sub) of the Google account allowed to recover this one.
        identity: felt252,
        /// iat issued at the last recovery.
        last_recovery_iat: u64,
        /// poseidon(new_pubkey, current_pubkey) left by a prove_jwt that ran on chain. 0 when none.
        /// POC escape hatch while the prover cannot run garaga's builtins. A recover
        /// without proof facts consumes it.
        approved_recovery: felt252,
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
            ref self: ComponentState<TContractState>,
            header_b64: ByteArray,
            payload_b64: ByteArray,
            kid: ByteArray,
            rsa_hint: Span<felt252>,
            new_pubkey: felt252,
        ) {
            let claims = verify_and_extract(
                header_b64, payload_b64, kid, rsa_hint, JWK_REGISTRY_ADDRESS,
            );

            let identity = self.identity.read();
            let last_iat = self.last_recovery_iat.read();
            let nonce = poseidon_hash_span([new_pubkey].span());
            assert(claims.identity == identity, 'WRONG_GOOGLE_ACCOUNT');
            assert(claims.exp > get_block_timestamp(), 'TOKEN_EXPIRED');
            assert(claims.nonce == nonce, 'NONCE_MISMATCH');
            assert(claims.iat > last_iat, 'STALE_IAT');

            let account_address = get_contract_address();
            let current_pubkey = IPublicKeyDispatcher { contract_address: account_address }
                .get_public_key();

            // In a production environment, since this will be a virtual method run in a virtual
            // block, this write will stay there. For the POC, since this method is run on chain,
            // this value will be checked against the claim of the recover function.
            self.approved_recovery.write(poseidon_hash_span([new_pubkey, current_pubkey].span()));

            send_message_to_l1_syscall(
                to_address: Zero::zero(),
                payload: [
                    account_address.into(), identity, new_pubkey, current_pubkey, claims.iat.into(),
                ]
                    .span(),
            )
                .unwrap_syscall();
        }

        fn recover(
            ref self: ComponentState<TContractState>,
            new_pubkey: felt252,
            iat: u64,
            signature: Span<felt252>,
        ) {
            let info = get_execution_info();
            let account_address = get_contract_address();
            let current_pubkey = IPublicKeyDispatcher { contract_address: account_address }
                .get_public_key();
            let identity = self.identity.read();
            let last_iat = self.last_recovery_iat.read();
            assert(iat > last_iat, 'STALE_IAT');

            if info.tx_info.proof_facts.is_empty() {
                // No proof attached. This case is only run for the POC.
                assert(info.tx_info.chain_id != 'SN_MAIN', 'NO_PROOF_FACTS');
                let approval = poseidon_hash_span([new_pubkey, current_pubkey].span());
                assert(approval == self.approved_recovery.read(), 'NOT_APPROVED');
                self.approved_recovery.write(0);
            } else {
                let facts = ProofFactsVerificationTrait::extract_verified_program(info);
                facts
                    .assert(
                        PROOF_VALIDITY_BLOCKS,
                        account_address,
                        array![
                            account_address.into(), identity, new_pubkey, current_pubkey,
                            iat.into(),
                        ],
                    );
            }

            IPublicKeyDispatcher { contract_address: account_address }
                .set_public_key(new_pubkey, signature);
            self.last_recovery_iat.write(iat);

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
        fn initializer(ref self: ComponentState<TContractState>, identity: felt252) {
            let mut src5_component = get_dep_component_mut!(ref self, SRC5);
            src5_component.register_interface(interface::SOCIAL_ID);

            self.identity.write(identity);
        }
    }
}
