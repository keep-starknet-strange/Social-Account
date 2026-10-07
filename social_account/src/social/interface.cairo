use starknet::ContractAddress;

pub const SOCIAL_ID: felt252 = 0x0; // TODO
/// How many blocks after its base block a proof stays usable.
pub const PROOF_VALIDITY_BLOCKS: u64 = 100;
pub const JWK_REGISTRY_ADDRESS: ContractAddress =
    0x580f53e4f654c23e78ca3f68b5369a16b004cb078bfe3fa3ee8d2ce9232af76;

#[starknet::interface]
pub trait ISocialRecoverable<T> {
    fn prove_jwt(
        ref self: T,
        header_b64: ByteArray,
        payload_b64: ByteArray,
        kid: ByteArray,
        rsa_hint: Span<felt252>,
        new_pubkey: felt252,
    );
    fn recover(ref self: T, new_pubkey: felt252, iat: u64, signature: Span<felt252>);
    fn identity(self: @T) -> felt252;
}
