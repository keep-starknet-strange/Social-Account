//! SocialAccount: a stock OpenZeppelin account plus Google-login recovery.
//!
//! The token check lives in this contract (SocialComponent) but only ever runs inside the
//! prover, as a "virtual" call. The chain only ever runs `recover`, which checks the proof facts.
//!
//! Other contracts involved (not in this file):
//!
//! * JwkRegistry (on-chain, shared). Holds Google's current RSA public keys, keyed by the token's
//!   `kid` header. A trusted operator updates it when Google rotates keys. `prove_jwt` reads it
//!   inside the prover, so what it sees is the base block's state.
//!
//! * Prover account (an account the backend controls, holding no funds).
//!   Because this social account cannot pass its own `__validate__` (when the private key is lost).
//!   The prover account acts as a vessel for the `prove_jwt` function to run.
//!
//! * Transaction prover (off-chain). Executes the virtual tx on top of a base block and returns
//!   { proof, proof_facts, l2_to_l1_messages }. The message `prove_jwt` emits ends up, hashed,
//!   in `proof_facts.message_to_l1_hashes`.
//!
//! * Paymaster or SNIP-9 relayer (on-chain). Submits the real `recover(new_pubkey, signature)`
//!   transaction with `proof` and `proof_facts` attached since the user has no working key to pay
//!   with, as they are in recovery mode.

mod jwt;
pub mod social;

#[starknet::contract(account)]
mod SocialAccount {
    use SocialComponent::InternalSocialComponentTrait;
    use openzeppelin_account::AccountComponent;
    use openzeppelin_introspection::src5::SRC5Component;
    use crate::social::component::SocialComponent;

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: SocialComponent, storage: social, event: SocialEvent);

    #[abi(embed_v0)]
    impl SRC6Impl = AccountComponent::SRC6Impl<ContractState>;
    #[abi(embed_v0)]
    impl SRC6CamelOnlyImpl = AccountComponent::SRC6CamelOnlyImpl<ContractState>;
    #[abi(embed_v0)]
    impl DeclarerImpl = AccountComponent::DeclarerImpl<ContractState>;
    #[abi(embed_v0)]
    impl PublicKeyImpl = AccountComponent::PublicKeyImpl<ContractState>;
    #[abi(embed_v0)]
    impl PublicKeyCamelImpl = AccountComponent::PublicKeyCamelImpl<ContractState>;
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;
    #[abi(embed_v0)]
    impl SocialRecoverableImpl =
        SocialComponent::SocialRecoverableImpl<ContractState>;


    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: AccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        social: SocialComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        SocialEvent: SocialComponent::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, aud: ByteArray, identity: felt252) {
        // Key 0 until the first recovery. The initializer also registers SRC6 in SRC5.
        self.account.initializer(0);
        self.social.initializer(aud, identity);
    }
}
