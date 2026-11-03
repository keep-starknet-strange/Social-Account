use openzeppelin_account::utils::QUERY_OFFSET;
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_resource_bounds, start_cheat_tip,
    start_cheat_transaction_version,
};
use starknet::account::Call;
use starknet::{ContractAddress, ResourcesBounds, SyscallResultTrait};

#[starknet::interface]
trait IExecutor<T> {
    fn __validate__(self: @T, calls: Array<Call>) -> felt252;
}

fn deploy() -> ContractAddress {
    let class = declare("ProverExecutor").unwrap_syscall().contract_class();
    let (executor, _) = class.deploy(@array![]).unwrap_syscall();
    executor
}

fn call(selector: felt252) -> Call {
    Call { to: 0x123.try_into().unwrap(), selector, calldata: array![].span() }
}

fn bounds(price: u128) -> Span<ResourcesBounds> {
    array![
        ResourcesBounds { resource: 'L1_GAS', max_amount: 0, max_price_per_unit: 0 },
        ResourcesBounds { resource: 'L2_GAS', max_amount: 1000000000, max_price_per_unit: price },
        ResourcesBounds { resource: 'L1_DATA', max_amount: 0, max_price_per_unit: 0 },
    ]
        .span()
}

#[feature("safe_dispatcher")]
fn validate(executor: ContractAddress, calls: Array<Call>) -> Result<felt252, Array<felt252>> {
    IExecutorSafeDispatcher { contract_address: executor }.__validate__(calls)
}

#[test]
#[feature("safe_dispatcher")]
fn accepts_one_zero_price_prove_jwt_call() {
    let executor = deploy();
    start_cheat_resource_bounds(executor, bounds(0));
    assert!(validate(executor, array![call(selector!("prove_jwt"))]) == Ok(starknet::VALIDATED));
}

#[test]
#[feature("safe_dispatcher")]
fn rejects_anything_else() {
    let executor = deploy();
    start_cheat_resource_bounds(executor, bounds(0));
    let prove = call(selector!("prove_jwt"));
    let rejected = |calls: Array<Call>, reason: felt252| {
        match validate(executor, calls) {
            Ok(_) => panic!("validated"),
            Err(e) => assert!(*e.at(0) == reason),
        }
    };
    rejected(array![call(selector!("transfer"))], 'PROVE_JWT_ONLY');
    rejected(array![prove, prove], 'ONE_CALL_ONLY');
    rejected(array![], 'ONE_CALL_ONLY');

    start_cheat_resource_bounds(executor, bounds(1));
    rejected(array![prove], 'VIRTUAL_ONLY');

    start_cheat_resource_bounds(executor, bounds(0));
    start_cheat_tip(executor, 1);
    rejected(array![prove], 'NO_TIP');

    start_cheat_tip(executor, 0);
    start_cheat_resource_bounds(executor, array![].span());
    rejected(array![prove], 'NO_BOUNDS');

    start_cheat_resource_bounds(executor, bounds(0));
    start_cheat_transaction_version(executor, 1);
    rejected(array![prove], 'V3_ONLY');
    start_cheat_transaction_version(executor, 4);
    rejected(array![prove], 'V3_ONLY');
}

#[test]
#[feature("safe_dispatcher")]
fn accepts_the_fee_estimation_version() {
    let executor = deploy();
    start_cheat_resource_bounds(executor, bounds(0));
    let query_v3: felt252 = (QUERY_OFFSET + 3).try_into().unwrap();
    start_cheat_transaction_version(executor, query_v3);
    assert!(validate(executor, array![call(selector!("prove_jwt"))]) == Ok(starknet::VALIDATED));
}
