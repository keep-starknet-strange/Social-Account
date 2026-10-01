#[derive(Drop, Debug, PartialEq, starknet::Event)]
pub struct RecoveredEvent {
    pub new_pubkey: felt252,
}
