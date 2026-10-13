//! JwkRegistry: the RS256 public keys the accounts trust, keyed by the
//! the issuer and the token header's kid.
//!
//! The address of this contract is pinned in the `SocialComponent` component.
//! `prove_jwt` virtual method reads it inside the prover, so a key counts
//! if it was set at the base block.

use garaga::signatures::rsa::RSA2048PublicKey;
use starknet::storage_access::StorePacking;
use crate::jwt::types::Issuer;

#[starknet::interface]
pub trait IJwkRegistry<T> {
    /// Seed the recovery (issuer, aud) pairs. Owner only, once. Panics with 'ALREADY_INITIALIZED'
    /// and with 'NO_AUDIENCES' on an empty list.
    /// Kept out of the constructor so the address depends only on the owner.
    fn initialize(ref self: T, audiences: Array<(Issuer, ByteArray)>);
    fn is_initialized(self: @T) -> bool;
    /// The garaga public key for `kid`. `iss` is the raw claim from the token, so the prover
    /// looks up without mapping it to an `Issuer`. Panics with 'UNKNOWN_KID'.
    fn get_key(self: @T, iss: ByteArray, kid: ByteArray) -> RSA2048PublicKey;
    /// Insert or replace the key for `kid`. Owner only.
    fn set_key(ref self: T, issuer: Issuer, kid: ByteArray, key: RSA2048PublicKey);
    /// Stop accepting `kid`. Owner only.
    fn remove_key(ref self: T, issuer: Issuer, kid: ByteArray);
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
    use RecoveryAudienceComponent::RecoveryAudienceInternalTrait;
    use garaga::signatures::rsa::RSA2048PublicKey;
    use openzeppelin_access::ownable::OwnableComponent;
    use openzeppelin_interfaces::upgrades::IUpgradeable;
    use openzeppelin_upgrades::UpgradeableComponent;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ClassHash, ContractAddress};
    use crate::jwt::rec_aud_component::RecoveryAudienceComponent;
    use crate::jwt::types::{Issuer, IssuerTrait, slot};
    use super::IJwkRegistry;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);
    component!(
        path: RecoveryAudienceComponent, storage: recovery_audience, event: RecoveryAudienceEvent,
    );

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl InternalImpl = OwnableComponent::InternalImpl<ContractState>;
    impl UpgradeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;
    #[abi(embed_v0)]
    impl RecoveryAudienceImpl =
        RecoveryAudienceComponent::WhitelistedAudienceRecoverableImpl<ContractState>;
    impl RecoveryAudienceInternalImpl =
        RecoveryAudienceComponent::RecoveryAudienceInternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        #[substorage(v0)]
        recovery_audience: RecoveryAudienceComponent::Storage,
        /// Keyed by (poseidon(iss), poseidon(kid)).
        /// None for a kid that was never set or was removed.
        keys: Map<(felt252, felt252), Option<RSA2048PublicKey>>,
        /// Set once by `initialize`.
        initialized: bool,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        Initialized: Initialized,
        KeySet: KeySet,
        KeyRemoved: KeyRemoved,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
        #[flat]
        RecoveryAudienceEvent: RecoveryAudienceComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct Initialized {}

    #[derive(Drop, starknet::Event)]
    pub struct KeySet {
        pub iss: ByteArray,
        pub kid: ByteArray,
    }

    #[derive(Drop, starknet::Event)]
    pub struct KeyRemoved {
        pub iss: ByteArray,
        pub kid: ByteArray,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl JwkRegistryImpl of IJwkRegistry<ContractState> {
        fn initialize(ref self: ContractState, audiences: Array<(Issuer, ByteArray)>) {
            self.ownable.assert_only_owner();
            assert(!self.initialized.read(), 'ALREADY_INITIALIZED');
            assert(audiences.len() > 0, 'NO_AUDIENCES');
            self.initialized.write(true);
            for (issuer, aud) in audiences {
                self.recovery_audience.add_in_whitelist(issuer, aud);
            }
            self.emit(Initialized {});
        }

        fn is_initialized(self: @ContractState) -> bool {
            self.initialized.read()
        }

        fn get_key(self: @ContractState, iss: ByteArray, kid: ByteArray) -> RSA2048PublicKey {
            let map_key = (slot(@iss), slot(@kid));
            self.keys.read(map_key).expect('UNKNOWN_KID')
        }

        fn set_key(ref self: ContractState, issuer: Issuer, kid: ByteArray, key: RSA2048PublicKey) {
            self.ownable.assert_only_owner();
            let iss = issuer.iss();
            let map_key = (slot(@iss), slot(@kid));
            self.keys.write(map_key, Some(key));
            self.emit(KeySet { iss, kid });
        }

        fn remove_key(ref self: ContractState, issuer: Issuer, kid: ByteArray) {
            self.ownable.assert_only_owner();
            let iss = issuer.iss();
            let map_key = (slot(@iss), slot(@kid));
            self.keys.write(map_key, None);
            self.emit(KeyRemoved { iss, kid });
        }
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(new_class_hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use garaga::signatures::rsa::RSA2048PublicKey;
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address};
    use starknet::syscalls::call_contract_syscall;
    use starknet::{ContractAddress, SyscallResultTrait};
    use crate::jwt::types::Issuer;
    use super::{
        IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait, IJwkRegistrySafeDispatcher,
        IJwkRegistrySafeDispatcherTrait,
    };

    fn owner() -> ContractAddress {
        'owner'.try_into().unwrap()
    }

    fn deploy_uninitialized() -> ContractAddress {
        let class = declare("JwkRegistry").unwrap_syscall().contract_class();
        let (address, _) = class.deploy(@array![owner().into()]).unwrap_syscall();
        start_cheat_caller_address(address, owner());
        address
    }

    fn deploy() -> ContractAddress {
        let address = deploy_uninitialized();
        IJwkRegistryDispatcher { contract_address: address }
            .initialize(array![(Issuer::Google, "aud")]);
        address
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn initializes_once() {
        let address = deploy();
        let registry = IJwkRegistryDispatcher { contract_address: address };
        let safe = IJwkRegistrySafeDispatcher { contract_address: address };
        assert!(registry.is_initialized());
        match safe.initialize(array![(Issuer::Google, "aud2")]) {
            Ok(_) => panic!("initialized twice"),
            Err(e) => assert!(*e.at(0) == 'ALREADY_INITIALIZED'),
        }
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn initialize_rejects_empty_list() {
        let address = deploy_uninitialized();
        let registry = IJwkRegistryDispatcher { contract_address: address };
        let safe = IJwkRegistrySafeDispatcher { contract_address: address };
        match safe.initialize(array![]) {
            Ok(_) => panic!("initialized with nothing"),
            Err(e) => assert!(*e.at(0) == 'NO_AUDIENCES'),
        }
        assert!(!registry.is_initialized());
    }

    #[test]
    fn initialize_rejects_unknown_issuer_index() {
        let address = deploy_uninitialized();
        // [len=1, variant=2 (no such issuer), aud "a"]
        let calldata: Array<felt252> = array![1, 2, 0, 'a', 1];
        let result = call_contract_syscall(address, selector!("initialize"), calldata.span());
        assert!(result.is_err(), "unknown issuer accepted");
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

        match safe.get_key("https://accounts.google.com", "kid-1") {
            Ok(_) => panic!("unset kid resolved"),
            Err(e) => assert!(*e.at(0) == 'UNKNOWN_KID'),
        }
        registry.set_key(Issuer::Google, "kid-1", key());
        assert!(registry.get_key("https://accounts.google.com", "kid-1") == key());
        match safe.get_key("https://appleid.apple.com", "kid-1") {
            Ok(_) => panic!("kid resolved under the wrong iss"),
            Err(e) => assert!(*e.at(0) == 'UNKNOWN_KID'),
        }
        registry.remove_key(Issuer::Google, "kid-1");
        match safe.get_key("https://accounts.google.com", "kid-1") {
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
        match safe.set_key(Issuer::Google, "kid-1", key()) {
            Ok(_) => panic!("stranger wrote a key"),
            Err(e) => assert!(*e.at(0) == 'Caller is not the owner'),
        }
    }

    #[test]
    fn rejects_limb_wider_than_u96() {
        let address = deploy();
        start_cheat_caller_address(address, owner());
        let mut calldata: Array<felt252> = array![];
        Issuer::Google.serialize(ref calldata);
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
