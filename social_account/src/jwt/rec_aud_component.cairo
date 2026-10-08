#[starknet::interface]
pub trait IWhitelistedAudienceRecoverable<T> {
    fn is_whitelisted(self: @T, iss: ByteArray, aud: ByteArray) -> bool;
    fn add_whitelisted(ref self: T, iss: ByteArray, aud: ByteArray);
    fn remove_whitelisted(ref self: T, iss: ByteArray, aud: ByteArray);
}

#[derive(Drop, Debug, PartialEq, starknet::Event)]
pub struct WhitelistAddedEvent {
    pub iss: felt252,
    pub aud: felt252,
}

#[derive(Drop, Debug, PartialEq, starknet::Event)]
pub struct WhitelistRemovedEvent {
    pub iss: felt252,
    pub aud: felt252,
}

#[starknet::component]
pub mod RecoveryAudienceComponent {
    use OwnableComponent::InternalTrait;
    use openzeppelin_access::ownable::OwnableComponent;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use crate::jwt::types::slot;
    use super::{IWhitelistedAudienceRecoverable, WhitelistAddedEvent, WhitelistRemovedEvent};

    #[storage]
    pub struct Storage {
        /// (h(iss), h(aud)) => allowed to recover any account under iss.
        whitelist: Map<(felt252, felt252), bool>,
        /// h(iss) => how many auds are whitelisted.
        count: Map<felt252, u32>,
    }

    #[event]
    #[derive(Drop, Debug, PartialEq, starknet::Event)]
    pub enum Event {
        WhitelistAdded: WhitelistAddedEvent,
        WhitelistRemoved: WhitelistRemovedEvent,
    }

    #[embeddable_as(WhitelistedAudienceRecoverableImpl)]
    pub impl WhitelistedAudienceRecoverable<
        TContractState,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
        impl Owner: OwnableComponent::HasComponent<TContractState>,
    > of IWhitelistedAudienceRecoverable<ComponentState<TContractState>> {
        fn is_whitelisted(
            self: @ComponentState<TContractState>, iss: ByteArray, aud: ByteArray,
        ) -> bool {
            let iss = slot(@iss);
            let aud = slot(@aud);
            self.whitelist.entry((iss, aud)).read()
        }

        fn add_whitelisted(
            ref self: ComponentState<TContractState>, iss: ByteArray, aud: ByteArray,
        ) {
            let ownable_component = get_dep_component!(@self, Owner);
            ownable_component.assert_only_owner();
            self.add_in_whitelist(iss, aud);
        }

        fn remove_whitelisted(
            ref self: ComponentState<TContractState>, iss: ByteArray, aud: ByteArray,
        ) {
            let ownable_component = get_dep_component!(@self, Owner);
            ownable_component.assert_only_owner();
            self.remove_from_whitelist(iss, aud);
        }
    }

    #[generate_trait]
    pub impl RecoveryAudienceInternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of RecoveryAudienceInternalTrait<TContractState> {
        fn initializer(ref self: ComponentState<TContractState>, iss: ByteArray, aud: ByteArray) {
            self.add_in_whitelist(iss, aud);
        }

        fn add_in_whitelist(
            ref self: ComponentState<TContractState>, iss: ByteArray, aud: ByteArray,
        ) {
            let iss = slot(@iss);
            let aud = slot(@aud);
            assert(!self.whitelist.entry((iss, aud)).read(), 'ALREADY_WHITELISTED');
            let n = self.count.entry(iss).read();
            self.whitelist.entry((iss, aud)).write(true);
            self.count.entry(iss).write(n + 1);
            self.emit(WhitelistAddedEvent { iss, aud });
        }

        fn remove_from_whitelist(
            ref self: ComponentState<TContractState>, iss: ByteArray, aud: ByteArray,
        ) {
            let iss = slot(@iss);
            let aud = slot(@aud);
            assert(self.whitelist.entry((iss, aud)).read(), 'NOT_WHITELISTED');
            let aud_count = self.count.entry(iss).read();
            assert(aud_count > 1, 'LAST_AUD_FOR_ISS');
            self.whitelist.entry((iss, aud)).write(false);
            self.count.entry(iss).write(aud_count - 1);
            self.emit(WhitelistRemovedEvent { iss, aud })
        }
    }
}

#[cfg(test)]
mod tests {
    use snforge_std::{ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address};
    use starknet::{ContractAddress, SyscallResultTrait};
    use crate::jwt::registry::{IJwkRegistryDispatcher, IJwkRegistryDispatcherTrait};
    use super::{
        IWhitelistedAudienceRecoverableDispatcher, IWhitelistedAudienceRecoverableDispatcherTrait,
        IWhitelistedAudienceRecoverableSafeDispatcher,
        IWhitelistedAudienceRecoverableSafeDispatcherTrait,
    };

    fn owner() -> ContractAddress {
        'owner'.try_into().unwrap()
    }

    fn deploy() -> (
        IWhitelistedAudienceRecoverableDispatcher, IWhitelistedAudienceRecoverableSafeDispatcher,
    ) {
        let class = declare("JwkRegistry").unwrap_syscall().contract_class();
        let (address, _) = class.deploy(@array![owner().into()]).unwrap_syscall();
        start_cheat_caller_address(address, owner());
        IJwkRegistryDispatcher { contract_address: address }.initialize("iss", "aud");
        (
            IWhitelistedAudienceRecoverableDispatcher { contract_address: address },
            IWhitelistedAudienceRecoverableSafeDispatcher { contract_address: address },
        )
    }

    fn error(result: Result<(), Array<felt252>>) -> felt252 {
        match result {
            Ok(_) => panic!("call succeeded"),
            Err(e) => *e.at(0),
        }
    }

    #[test]
    fn initialize_seeds_one_aud_per_iss() {
        let (list, _) = deploy();
        assert!(list.is_whitelisted("iss", "aud"));
        assert!(!list.is_whitelisted("iss", "other"));
        assert!(!list.is_whitelisted("other", "aud"));
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn owner_adds_once() {
        let (list, safe) = deploy();
        list.add_whitelisted("iss", "aud2");
        assert!(list.is_whitelisted("iss", "aud2"));
        assert!(error(safe.add_whitelisted("iss", "aud2")) == 'ALREADY_WHITELISTED');
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn the_last_aud_of_an_iss_cannot_be_removed() {
        let (list, safe) = deploy();
        assert!(error(safe.remove_whitelisted("iss", "aud")) == 'LAST_AUD_FOR_ISS');

        list.add_whitelisted("iss", "aud2");
        list.remove_whitelisted("iss", "aud");
        assert!(!list.is_whitelisted("iss", "aud"));
        assert!(list.is_whitelisted("iss", "aud2"));
        assert!(error(safe.remove_whitelisted("iss", "aud2")) == 'LAST_AUD_FOR_ISS');
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn counts_are_per_iss() {
        let (list, safe) = deploy();
        list.add_whitelisted("iss2", "aud");
        // iss has one aud and iss2 has one aud: neither can lose it, even though the aud is shared.
        assert!(error(safe.remove_whitelisted("iss2", "aud")) == 'LAST_AUD_FOR_ISS');
        assert!(error(safe.remove_whitelisted("iss", "aud")) == 'LAST_AUD_FOR_ISS');
        assert!(error(safe.remove_whitelisted("iss", "missing")) == 'NOT_WHITELISTED');
    }

    #[test]
    #[feature("safe_dispatcher")]
    fn stranger_cannot_write() {
        let (_, safe) = deploy();
        start_cheat_caller_address(safe.contract_address, 'stranger'.try_into().unwrap());
        assert!(error(safe.add_whitelisted("iss", "aud2")) == 'Caller is not the owner');
        assert!(error(safe.remove_whitelisted("iss", "aud")) == 'Caller is not the owner');
    }
}
