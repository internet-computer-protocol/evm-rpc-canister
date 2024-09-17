//! Conversion between ckETH types and EVM RPC types.
//! This module is meant to be temporary and should be removed once the dependency on ckETH is removed,
//! see <https://github.com/internet-computer-protocol/evm-rpc-canister/issues/243>

use crate::rpc_client::checked_amount::CheckedAmountOf;
use crate::rpc_client::eth_rpc::{Hash, Quantity};
use evm_rpc_types::{BlockTag, Hex, Hex20, Hex256, Hex32, HexByte, Nat256};
/**/
pub(super) fn into_block_spec(value: BlockTag) -> crate::rpc_client::eth_rpc::BlockSpec {
    use crate::rpc_client::eth_rpc::{self, BlockSpec};
    match value {
        BlockTag::Number(n) => BlockSpec::Number(into_checked_amount_of(n)),
        BlockTag::Latest => BlockSpec::Tag(eth_rpc::BlockTag::Latest),
        BlockTag::Safe => BlockSpec::Tag(eth_rpc::BlockTag::Safe),
        BlockTag::Finalized => BlockSpec::Tag(eth_rpc::BlockTag::Finalized),
        BlockTag::Earliest => BlockSpec::Tag(eth_rpc::BlockTag::Earliest),
        BlockTag::Pending => BlockSpec::Tag(eth_rpc::BlockTag::Pending),
    }
}

pub(super) fn into_get_logs_param(
    value: evm_rpc_types::GetLogsArgs,
) -> crate::rpc_client::requests::GetLogsParam {
    crate::rpc_client::requests::GetLogsParam {
        from_block: value.from_block.map(into_block_spec).unwrap_or_default(),
        to_block: value.to_block.map(into_block_spec).unwrap_or_default(),
        address: value
            .addresses
            .into_iter()
            .map(|address| ic_ethereum_types::Address::new(address.into()))
            .collect(),
        topics: value
            .topics
            .unwrap_or_default()
            .into_iter()
            .map(|topic| {
                topic
                    .into_iter()
                    .map(|t| crate::rpc_client::eth_rpc::FixedSizeData(t.into()))
                    .collect()
            })
            .collect(),
    }
}

pub(super) fn from_log_entries(
    value: Vec<crate::rpc_client::responses::LogEntry>,
) -> Vec<evm_rpc_types::LogEntry> {
    value.into_iter().map(from_log_entry).collect()
}

fn from_log_entry(value: crate::rpc_client::responses::LogEntry) -> evm_rpc_types::LogEntry {
    evm_rpc_types::LogEntry {
        address: from_address(value.address),
        topics: value.topics.into_iter().map(|t| t.0.into()).collect(),
        data: value.data.0.into(),
        block_hash: value.block_hash.map(|x| x.0.into()),
        block_number: value.block_number.map(from_checked_amount_of),
        transaction_hash: value.transaction_hash.map(|x| x.0.into()),
        transaction_index: value.transaction_index.map(from_checked_amount_of),
        log_index: value.log_index.map(from_checked_amount_of),
        removed: value.removed,
    }
}

pub(super) fn into_fee_history_params(
    value: evm_rpc_types::FeeHistoryArgs,
) -> crate::rpc_client::eth_rpc::FeeHistoryParams {
    crate::rpc_client::eth_rpc::FeeHistoryParams {
        block_count: into_quantity(value.block_count),
        highest_block: into_block_spec(value.newest_block),
        reward_percentiles: value.reward_percentiles.unwrap_or_default(),
    }
}

pub(super) fn from_fee_history(
    value: crate::rpc_client::eth_rpc::FeeHistory,
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

pub(super) fn into_get_transaction_count_params(
    value: evm_rpc_types::GetTransactionCountArgs,
) -> crate::rpc_client::requests::GetTransactionCountParams {
    crate::rpc_client::requests::GetTransactionCountParams {
        address: ic_ethereum_types::Address::new(value.address.into()),
        block: into_block_spec(value.block),
    }
}

pub(super) fn from_transaction_receipt(
    value: crate::rpc_client::responses::TransactionReceipt,
) -> evm_rpc_types::TransactionReceipt {
    evm_rpc_types::TransactionReceipt {
        block_hash: Hex32::from(value.block_hash.0),
        block_number: from_checked_amount_of(value.block_number),
        effective_gas_price: from_checked_amount_of(value.effective_gas_price),
        gas_used: from_checked_amount_of(value.gas_used),
        status: match value.status {
            crate::rpc_client::responses::TransactionStatus::Success => Nat256::from(1_u8),
            crate::rpc_client::responses::TransactionStatus::Failure => Nat256::from(0_u8),
        },
        transaction_hash: Hex32::from(value.transaction_hash.0),
        // TODO 243: responses types from querying JSON-RPC providers should be strongly typed
        // for all the following fields: contract_address, from, logs_bloom, to, transaction_index, tx_type
        contract_address: value
            .contract_address
            .map(|address| Hex20::try_from(address).unwrap()),
        from: Hex20::try_from(value.from).unwrap(),
        logs: from_log_entries(value.logs),
        logs_bloom: Hex256::try_from(value.logs_bloom).unwrap(),
        to: Hex20::try_from(value.to).unwrap(),
        transaction_index: from_checked_amount_of(value.transaction_index),
        tx_type: HexByte::try_from(value.r#type).unwrap(),
    }
}

pub(super) fn from_block(value: crate::rpc_client::eth_rpc::Block) -> evm_rpc_types::Block {
    evm_rpc_types::Block {
        base_fee_per_gas: value.base_fee_per_gas.map(from_checked_amount_of),
        number: from_checked_amount_of(value.number),
        difficulty: value.difficulty.map(from_checked_amount_of),
        extra_data: Hex::try_from(value.extra_data).unwrap(),
        gas_limit: from_checked_amount_of(value.gas_limit),
        gas_used: from_checked_amount_of(value.gas_used),
        hash: Hex32::try_from(value.hash).unwrap(),
        logs_bloom: Hex256::try_from(value.logs_bloom).unwrap(),
        miner: Hex20::try_from(value.miner).unwrap(),
        mix_hash: Hex32::try_from(value.mix_hash).unwrap(),
        nonce: from_checked_amount_of(value.nonce),
        parent_hash: Hex32::try_from(value.parent_hash).unwrap(),
        receipts_root: Hex32::try_from(value.receipts_root).unwrap(),
        sha3_uncles: Hex32::try_from(value.sha3_uncles).unwrap(),
        size: from_checked_amount_of(value.size),
        state_root: Hex32::try_from(value.state_root).unwrap(),
        timestamp: from_checked_amount_of(value.timestamp),
        total_difficulty: value.total_difficulty.map(from_checked_amount_of),
        transactions: value
            .transactions
            .into_iter()
            .map(|tx| Hex32::try_from(tx).unwrap())
            .collect(),
        transactions_root: value.transactions_root.map(|x| Hex32::try_from(x).unwrap()),
        uncles: value
            .uncles
            .into_iter()
            .map(|tx| Hex32::try_from(tx).unwrap())
            .collect(),
    }
}

pub(super) fn from_send_raw_transaction_result(
    transaction_hash: Option<Hex32>,
    value: crate::rpc_client::eth_rpc::SendRawTransactionResult,
) -> evm_rpc_types::SendRawTransactionStatus {
    match value {
        crate::rpc_client::eth_rpc::SendRawTransactionResult::Ok => {
            evm_rpc_types::SendRawTransactionStatus::Ok(transaction_hash)
        }
        crate::rpc_client::eth_rpc::SendRawTransactionResult::InsufficientFunds => {
            evm_rpc_types::SendRawTransactionStatus::InsufficientFunds
        }
        crate::rpc_client::eth_rpc::SendRawTransactionResult::NonceTooLow => {
            evm_rpc_types::SendRawTransactionStatus::NonceTooLow
        }
        crate::rpc_client::eth_rpc::SendRawTransactionResult::NonceTooHigh => {
            evm_rpc_types::SendRawTransactionStatus::NonceTooHigh
        }
    }
}

pub(super) fn into_hash(value: Hex32) -> Hash {
    Hash(value.into())
}

fn into_checked_amount_of<Unit>(value: Nat256) -> CheckedAmountOf<Unit> {
    CheckedAmountOf::from_be_bytes(value.into_be_bytes())
}

pub(super) fn from_checked_amount_of<Unit>(value: CheckedAmountOf<Unit>) -> Nat256 {
    Nat256::from_be_bytes(value.to_be_bytes())
}

fn into_quantity(value: Nat256) -> Quantity {
    Quantity::from_be_bytes(value.into_be_bytes())
}

fn from_address(value: ic_ethereum_types::Address) -> evm_rpc_types::Hex20 {
    // TODO 243: ic_ethereum_types::Address should expose the underlying [u8; 20]
    // so that there is no artificial error handling here.
    value
        .to_string()
        .parse()
        .expect("BUG: Ethereum address cannot be parsed")
}
