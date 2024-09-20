//! Conversion between ckETH types and EVM RPC types.
//! This module is meant to be temporary and should be removed once the dependency on ckETH is removed,
//! see <https://github.com/internet-computer-protocol/evm-rpc-canister/issues/243>

use crate::rpc_client::json::requests::BlockSpec;
use crate::rpc_client::json::Hash;
use evm_rpc_types::{BlockTag, Hex, Hex20, Hex256, Hex32, HexByte, Nat256};

pub(super) fn into_block_spec(value: BlockTag) -> BlockSpec {
    use crate::rpc_client::json::requests;
    match value {
        BlockTag::Number(n) => BlockSpec::Number(n.into()),
        BlockTag::Latest => BlockSpec::Tag(requests::BlockTag::Latest),
        BlockTag::Safe => BlockSpec::Tag(requests::BlockTag::Safe),
        BlockTag::Finalized => BlockSpec::Tag(requests::BlockTag::Finalized),
        BlockTag::Earliest => BlockSpec::Tag(requests::BlockTag::Earliest),
        BlockTag::Pending => BlockSpec::Tag(requests::BlockTag::Pending),
    }
}

pub(super) fn from_log_entries(
    value: Vec<crate::rpc_client::json::responses::LogEntry>,
) -> Vec<evm_rpc_types::LogEntry> {
    value.into_iter().map(from_log_entry).collect()
}

fn from_log_entry(value: crate::rpc_client::json::responses::LogEntry) -> evm_rpc_types::LogEntry {
    evm_rpc_types::LogEntry {
        address: from_address(value.address),
        topics: value.topics.into_iter().map(|t| t.0.into()).collect(),
        data: value.data.0.into(),
        block_hash: value.block_hash.map(|x| x.0.into()),
        block_number: value.block_number.map(Nat256::from),
        transaction_hash: value.transaction_hash.map(|x| x.0.into()),
        transaction_index: value.transaction_index.map(Nat256::from),
        log_index: value.log_index.map(Nat256::from),
        removed: value.removed,
    }
}

pub(super) fn into_fee_history_params(
    value: evm_rpc_types::FeeHistoryArgs,
) -> crate::rpc_client::json::requests::FeeHistoryParams {
    crate::rpc_client::json::requests::FeeHistoryParams {
        block_count: value.block_count.into(),
        highest_block: into_block_spec(value.newest_block),
        reward_percentiles: value.reward_percentiles.unwrap_or_default(),
    }
}

pub(super) fn from_fee_history(
    value: crate::rpc_client::json::responses::FeeHistory,
) -> evm_rpc_types::FeeHistory {
    evm_rpc_types::FeeHistory {
        oldest_block: value.oldest_block.into(),
        base_fee_per_gas: value
            .base_fee_per_gas
            .into_iter()
            .map(Nat256::from)
            .collect(),
        gas_used_ratio: value.gas_used_ratio,
        reward: value
            .reward
            .into_iter()
            .map(|x| x.into_iter().map(Nat256::from).collect())
            .collect(),
    }
}

pub(super) fn into_get_transaction_count_params(
    value: evm_rpc_types::GetTransactionCountArgs,
) -> crate::rpc_client::json::requests::GetTransactionCountParams {
    crate::rpc_client::json::requests::GetTransactionCountParams {
        address: ic_ethereum_types::Address::new(value.address.into()),
        block: into_block_spec(value.block),
    }
}

pub(super) fn from_transaction_receipt(
    value: crate::rpc_client::json::responses::TransactionReceipt,
) -> evm_rpc_types::TransactionReceipt {
    evm_rpc_types::TransactionReceipt {
        block_hash: Hex32::from(value.block_hash.0),
        block_number: value.block_number.into(),
        effective_gas_price: value.effective_gas_price.into(),
        gas_used: value.gas_used.into(),
        status: match value.status {
            crate::rpc_client::json::responses::TransactionStatus::Success => Nat256::from(1_u8),
            crate::rpc_client::json::responses::TransactionStatus::Failure => Nat256::from(0_u8),
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
        transaction_index: value.transaction_index.into(),
        tx_type: HexByte::try_from(value.r#type).unwrap(),
    }
}

pub(super) fn from_block(value: crate::rpc_client::json::responses::Block) -> evm_rpc_types::Block {
    evm_rpc_types::Block {
        base_fee_per_gas: value.base_fee_per_gas.map(Nat256::from),
        number: value.number.into(),
        difficulty: value.difficulty.map(Nat256::from),
        extra_data: Hex::try_from(value.extra_data).unwrap(),
        gas_limit: value.gas_limit.into(),
        gas_used: value.gas_used.into(),
        hash: Hex32::try_from(value.hash).unwrap(),
        logs_bloom: Hex256::try_from(value.logs_bloom).unwrap(),
        miner: Hex20::try_from(value.miner).unwrap(),
        mix_hash: Hex32::try_from(value.mix_hash).unwrap(),
        nonce: value.nonce.into(),
        parent_hash: Hex32::try_from(value.parent_hash).unwrap(),
        receipts_root: Hex32::try_from(value.receipts_root).unwrap(),
        sha3_uncles: Hex32::try_from(value.sha3_uncles).unwrap(),
        size: value.size.into(),
        state_root: Hex32::try_from(value.state_root).unwrap(),
        timestamp: value.timestamp.into(),
        total_difficulty: value.total_difficulty.map(Nat256::from),
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
    value: crate::rpc_client::json::responses::SendRawTransactionResult,
) -> evm_rpc_types::SendRawTransactionStatus {
    match value {
        crate::rpc_client::json::responses::SendRawTransactionResult::Ok => {
            evm_rpc_types::SendRawTransactionStatus::Ok(transaction_hash)
        }
        crate::rpc_client::json::responses::SendRawTransactionResult::InsufficientFunds => {
            evm_rpc_types::SendRawTransactionStatus::InsufficientFunds
        }
        crate::rpc_client::json::responses::SendRawTransactionResult::NonceTooLow => {
            evm_rpc_types::SendRawTransactionStatus::NonceTooLow
        }
        crate::rpc_client::json::responses::SendRawTransactionResult::NonceTooHigh => {
            evm_rpc_types::SendRawTransactionStatus::NonceTooHigh
        }
    }
}

pub(super) fn into_hash(value: Hex32) -> Hash {
    Hash(value.into())
}

fn from_address(value: ic_ethereum_types::Address) -> evm_rpc_types::Hex20 {
    // TODO 243: ic_ethereum_types::Address should expose the underlying [u8; 20]
    // so that there is no artificial error handling here.
    value
        .to_string()
        .parse()
        .expect("BUG: Ethereum address cannot be parsed")
}
