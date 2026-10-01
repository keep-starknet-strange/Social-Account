use openzeppelin_account::utils::signature;
use starknet::ContractAddress;

pub const SOCIAL_ID: felt252 = 0x0; // TODO

#[starknet::interface]
pub trait ISocialRecoverable<T> {
    fn prove_jwt(
        self: @T,
        header_b64: ByteArray,
        payload_b64: ByteArray,
        kid: ByteArray,
        rsa_hint: Span<felt252>,
        new_pubkey: felt252,
    );
    fn recover(ref self: T, new_pubkey: felt252, signature: Span<felt252>);
    fn identity(self: @T) -> felt252;
}

#[starknet::interface]
pub trait ISocialDeployable<T> {
    fn __validate_deploy__(
        self: @T,
        class_hash: felt252,
        contract_address_salt: felt252,
        public_key: felt252,
        identity: felt252,
        jwk_registry: ContractAddress,
    ) -> felt252;
}
