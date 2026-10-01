/// Felts in a serialized garaga `RSA2048PublicKey`: 6 chunks of u384, 4 limbs of u96 each.
pub const MODULUS_FELTS: usize = 24;

/// One u384 chunk as garaga serializes it: four u96 limbs, low to high.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct Chunk {
    pub l0: felt252,
    pub l1: felt252,
    pub l2: felt252,
    pub l3: felt252,
}

/// The 24 felts of a garaga `RSA2048PublicKey`, in the same order.
#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct RsaModulus {
    pub w0: Chunk,
    pub w1: Chunk,
    pub w2: Chunk,
    pub w3: Chunk,
    pub w4: Chunk,
    pub w5: Chunk,
}
