//! JwkRegistry: the RS256 public keys the accounts trust, keyed by the token header's `kid`.
//!
//! One registry per issuer. Every SocialAccount stores the address of the registry it trusts.
//! `verify_and_extract` reads it inside the prover, so a key counts if it was set at the base
//! block.
//!
//! The owner can insert any modulus, and any modulus can forge a recovery. Put a multisig or a
//! timelock behind `owner` before real funds sit behind this.

use garaga::signatures::rsa::RSA2048PublicKey;
use starknet::storage_access::StorePacking;

#[starknet::interface]
pub trait IJwkRegistry<T> {
    /// The garaga public key for `kid`. Panics with 'UNKNOWN_KID'.
    fn get_key(self: @T, kid: ByteArray) -> RSA2048PublicKey;
    /// Insert or replace the key for `kid`. Owner only.
    fn set_key(ref self: T, kid: ByteArray, key: RSA2048PublicKey);
    /// Stop accepting `kid`. Owner only.
    fn remove_key(ref self: T, kid: ByteArray);
}

/// Four u96 limbs of one u384, low to high, widened to felts so storage can hold them.
#[derive(Copy, Drop, Serde, starknet::Store)]
struct Chunk {
    l0: felt252,
    l1: felt252,
    l2: felt252,
    l3: felt252,
}

/// Storage mirror of `RSA2048Chunks`: same six chunks, same limb order.
#[derive(Copy, Drop, Serde, starknet::Store)]
struct PackedKey {
    w0: Chunk,
    w1: Chunk,
    w2: Chunk,
    w3: Chunk,
    w4: Chunk,
    w5: Chunk,
}

/// garaga's u96 limbs have no `Store`, so the key is packed through its own Serde output.
/// Both sides serialize to the same 24 felts, so the round trip is exact.
impl RSA2048PublicKeyPacking of StorePacking<RSA2048PublicKey, PackedKey> {
    fn pack(value: RSA2048PublicKey) -> PackedKey {
        let mut felts: Array<felt252> = array![];
        value.serialize(ref felts);
        let mut span = felts.span();
        Serde::<PackedKey>::deserialize(ref span).unwrap()
    }

    fn unpack(value: PackedKey) -> RSA2048PublicKey {
        let mut felts: Array<felt252> = array![];
        value.serialize(ref felts);
        let mut span = felts.span();
        Serde::<RSA2048PublicKey>::deserialize(ref span).unwrap()
    }
}

#[starknet::contract]
pub mod JwkRegistry {
    use core::poseidon::poseidon_hash_span;
    use garaga::signatures::rsa::RSA2048PublicKey;
    use openzeppelin_access::ownable::OwnableComponent;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use super::IJwkRegistry;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        /// Keyed by poseidon(kid). None for a kid that was never set or was removed.
        keys: Map<felt252, Option<RSA2048PublicKey>>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        KeySet: KeySet,
        KeyRemoved: KeyRemoved,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct KeySet {
        pub kid: ByteArray,
    }

    #[derive(Drop, starknet::Event)]
    pub struct KeyRemoved {
        pub kid: ByteArray,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl JwkRegistryImpl of IJwkRegistry<ContractState> {
        fn get_key(self: @ContractState, kid: ByteArray) -> RSA2048PublicKey {
            self.keys.read(slot(kid)).expect('UNKNOWN_KID')
        }

        fn set_key(ref self: ContractState, kid: ByteArray, key: RSA2048PublicKey) {
            self.ownable.assert_only_owner();
            self.keys.write(slot(kid.clone()), Some(key));
            self.emit(KeySet { kid });
        }

        fn remove_key(ref self: ContractState, kid: ByteArray) {
            self.ownable.assert_only_owner();
            self.keys.write(slot(kid.clone()), None);
            self.emit(KeyRemoved { kid });
        }
    }

    /// Storage cannot key a Map by ByteArray, so the kid is hashed first.
    fn slot(kid: ByteArray) -> felt252 {
        let mut data: Array<felt252> = array![];
        kid.serialize(ref data);
        poseidon_hash_span(data.span())
    }
}

#[cfg(test)]
mod tests {
    use garaga::signatures::rsa::RSA2048PublicKey;
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address};
    use starknet::ContractAddress;
    use starknet::syscalls::call_contract_syscall;
    use super::{
        IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait, IJwkRegistrySafeDispatcher,
        IJwkRegistrySafeDispatcherTrait,
    };

    fn owner() -> ContractAddress {
        'owner'.try_into().unwrap()
    }

    fn deploy() -> ContractAddress {
        let class = declare("JwkRegistry").unwrap().contract_class();
        let (address, _) = class.deploy(@array![owner().into()]).unwrap();
        address
    }

    /// 24 distinct limbs, as the calldata builder would emit them.
    fn key() -> RSA2048PublicKey {
        let mut felts: Array<felt252> = array![];
        for i in 0_u32..24 {
            felts.append(i.into() + 1);
        }
        let mut span = felts.span();
        Serde::<RSA2048PublicKey>::deserialize(ref span).unwrap()
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn owner_sets_reads_and_removes() {
        let address = deploy();
        let registry = IJwkRegistryDispatcher { contract_address: address };
        let safe = IJwkRegistrySafeDispatcher { contract_address: address };
        start_cheat_caller_address(address, owner());

        match safe.get_key("kid-1") {
            Ok(_) => panic!("unset kid resolved"),
            Err(e) => assert!(*e.at(0) == 'UNKNOWN_KID'),
        }
        registry.set_key("kid-1", key());
        assert!(registry.get_key("kid-1") == key());
        registry.remove_key("kid-1");
        match safe.get_key("kid-1") {
            Ok(_) => panic!("removed kid resolved"),
            Err(e) => assert!(*e.at(0) == 'UNKNOWN_KID'),
        }
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn stranger_cannot_write() {
        let address = deploy();
        let safe = IJwkRegistrySafeDispatcher { contract_address: address };
        start_cheat_caller_address(address, 'stranger'.try_into().unwrap());
        match safe.set_key("kid-1", key()) {
            Ok(_) => panic!("stranger wrote a key"),
            Err(e) => assert!(*e.at(0) == 'NOT_OWNER'),
        }
    }

    #[test]
    fn rejects_limb_wider_than_u96() {
        let address = deploy();
        start_cheat_caller_address(address, owner());
        let mut calldata: Array<felt252> = array![];
        let kid: ByteArray = "kid-1";
        kid.serialize(ref calldata);
        calldata.append(0x1000000000000000000000000); // 2^96, one too many bits
        for _ in 0_u32..23 {
            calldata.append(1);
        }
        let result = call_contract_syscall(address, selector!("set_key"), calldata.span());
        assert!(result.is_err(), "oversized limb accepted");
    }
}
