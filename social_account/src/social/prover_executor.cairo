//! ProverExecutor: the keyless sender of the virtual `prove_jwt` transaction.
//!
//! `prove_jwt` only ever runs inside the prover, but a virtual transaction still needs a sender
//! that passes `__validate__` at the base block.
//!
//! * In case of proving with a backend, the backend can sign with its own account kept secret.
//! * In case of proving on browser, this executor can be put as a sender to run the `prove_jwt`
//! call.`
//!   - Accepts any signature
//!   - Allows only the `prove_jwt` method
//!   - Allows only zero tips and zero fees
//! * No storage and no params in constructor.

#[starknet::contract(account)]
mod ProverExecutor {
    use core::num::traits::Zero;
    use starknet::account::Call;
    use starknet::syscalls::call_contract_syscall;
    use starknet::{SyscallResultTrait, get_caller_address, get_tx_info};

    #[storage]
    struct Storage {}

    fn check(calls: Span<Call>) {
        assert(calls.len() == 1, 'ONE_CALL_ONLY');
        assert(*calls.at(0).selector == selector!("prove_jwt"), 'PROVE_JWT_ONLY');
        let info = get_tx_info().unbox();
        assert(info.tip == 0, 'NO_TIP');
        for bound in info.resource_bounds {
            assert(*bound.max_price_per_unit == 0, 'VIRTUAL_ONLY');
        }
    }

    #[external(v0)]
    fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
        check(calls.span());
        starknet::VALIDATED
    }

    #[external(v0)]
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        assert(get_caller_address().is_zero(), 'DIRECT_ONLY');
        check(calls.span());
        let call = calls.at(0);
        array![call_contract_syscall(*call.to, *call.selector, *call.calldata).unwrap_syscall()]
    }
}
