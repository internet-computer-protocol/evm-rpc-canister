//! Conversion between ckETH types and EVM RPC types.
//! This module is meant to be temporary and should be removed once the dependency on ckETH is removed,
//! see https://github.com/internet-computer-protocol/evm-rpc-canister/issues/243

use cketh_common::checked_amount::CheckedAmountOf;
use cketh_common::eth_rpc::Quantity;
use evm_rpc_types::{BlockTag, Nat256};

fn into_checked_amount_of<Unit>(value: Nat256) -> CheckedAmountOf<Unit> {
    CheckedAmountOf::from_be_bytes(value.into_be_bytes())
}

fn from_checked_amount_of<Unit>(value: CheckedAmountOf<Unit>) -> Nat256 {
    Nat256::from_be_bytes(value.to_be_bytes())
}

pub(super) fn into_quantity(value: Nat256) -> Quantity {
    Quantity::from_be_bytes(value.into_be_bytes())
}

pub(super) fn into_block_spec(value: BlockTag) -> cketh_common::eth_rpc::BlockSpec {
    use cketh_common::eth_rpc::{self, BlockSpec};
    match value {
        BlockTag::Number(n) => BlockSpec::Number(into_checked_amount_of(n)),
        BlockTag::Latest => BlockSpec::Tag(eth_rpc::BlockTag::Latest),
        BlockTag::Safe => BlockSpec::Tag(eth_rpc::BlockTag::Safe),
        BlockTag::Finalized => BlockSpec::Tag(eth_rpc::BlockTag::Finalized),
        BlockTag::Earliest => BlockSpec::Tag(eth_rpc::BlockTag::Earliest),
        BlockTag::Pending => BlockSpec::Tag(eth_rpc::BlockTag::Pending),
    }
}

pub(super) fn from_fee_history(
    value: cketh_common::eth_rpc::FeeHistory,
) -> evm_rpc_types::FeeHistory {
    evm_rpc_types::FeeHistory {
        oldest_block: from_checked_amount_of(value.oldest_block),
        base_fee_per_gas: value
            .base_fee_per_gas
            .into_iter()
            .map(from_checked_amount_of)
            .collect(),
        gas_used_ratio: value.gas_used_ratio,
        reward: value
            .reward
            .into_iter()
            .map(|x| x.into_iter().map(from_checked_amount_of).collect())
            .collect(),
    }
}
