//! Conversion between ckETH types and EVM RPC types.
//! This module is meant to be temporary and should be removed once the dependency on ckETH is removed,
//! see <https://github.com/internet-computer-protocol/evm-rpc-canister/issues/243>

use crate::rpc_client::checked_amount::CheckedAmountOf;
use crate::rpc_client::eth_rpc::{Hash, Quantity};
use evm_rpc_types::{BlockTag, Hex, Hex20, Hex256, Hex32, HexByte, Nat256};

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
) -> crate::rpc_client::eth_rpc::GetLogsParam {
    crate::rpc_client::eth_rpc::GetLogsParam {
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
    value: Vec<crate::rpc_client::eth_rpc::LogEntry>,
) -> Vec<evm_rpc_types::LogEntry> {
    value.into_iter().map(from_log_entry).collect()
}

fn from_log_entry(value: crate::rpc_client::eth_rpc::LogEntry) -> evm_rpc_types::LogEntry {
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
    value: cketh_common::eth_rpc::SendRawTransactionResult,
) -> evm_rpc_types::SendRawTransactionStatus {
    match value {
        cketh_common::eth_rpc::SendRawTransactionResult::Ok => {
            evm_rpc_types::SendRawTransactionStatus::Ok(transaction_hash)
        }
        cketh_common::eth_rpc::SendRawTransactionResult::InsufficientFunds => {
            evm_rpc_types::SendRawTransactionStatus::InsufficientFunds
        }
        cketh_common::eth_rpc::SendRawTransactionResult::NonceTooLow => {
            evm_rpc_types::SendRawTransactionStatus::NonceTooLow
        }
        cketh_common::eth_rpc::SendRawTransactionResult::NonceTooHigh => {
            evm_rpc_types::SendRawTransactionStatus::NonceTooHigh
        }
    }
}

pub(super) fn into_ethereum_network(
    source: &evm_rpc_types::RpcServices,
) -> crate::rpc_client::EthereumNetwork {
    match &source {
        evm_rpc_types::RpcServices::Custom { chain_id, .. } => {
            crate::rpc_client::EthereumNetwork::from(*chain_id)
        }
        evm_rpc_types::RpcServices::EthMainnet(_) => crate::rpc_client::EthereumNetwork::MAINNET,
        evm_rpc_types::RpcServices::EthSepolia(_) => crate::rpc_client::EthereumNetwork::SEPOLIA,
        evm_rpc_types::RpcServices::ArbitrumOne(_) => crate::rpc_client::EthereumNetwork::ARBITRUM,
        evm_rpc_types::RpcServices::BaseMainnet(_) => crate::rpc_client::EthereumNetwork::BASE,
        evm_rpc_types::RpcServices::OptimismMainnet(_) => {
            crate::rpc_client::EthereumNetwork::OPTIMISM
        }
    }
}

#[cfg(test)]
pub(super) fn into_rpc_service(
    source: evm_rpc_types::RpcService,
) -> cketh_common::eth_rpc_client::providers::RpcService {
    fn map_eth_mainnet_service(
        service: evm_rpc_types::EthMainnetService,
    ) -> cketh_common::eth_rpc_client::providers::EthMainnetService {
        match service {
            evm_rpc_types::EthMainnetService::Alchemy => {
                cketh_common::eth_rpc_client::providers::EthMainnetService::Alchemy
            }
            evm_rpc_types::EthMainnetService::Ankr => {
                cketh_common::eth_rpc_client::providers::EthMainnetService::Ankr
            }
            evm_rpc_types::EthMainnetService::BlockPi => {
                cketh_common::eth_rpc_client::providers::EthMainnetService::BlockPi
            }
            evm_rpc_types::EthMainnetService::PublicNode => {
                cketh_common::eth_rpc_client::providers::EthMainnetService::PublicNode
            }
            evm_rpc_types::EthMainnetService::Cloudflare => {
                cketh_common::eth_rpc_client::providers::EthMainnetService::Cloudflare
            }
            evm_rpc_types::EthMainnetService::Llama => {
                cketh_common::eth_rpc_client::providers::EthMainnetService::Llama
            }
        }
    }

    fn map_eth_sepolia_service(
        service: evm_rpc_types::EthSepoliaService,
    ) -> cketh_common::eth_rpc_client::providers::EthSepoliaService {
        match service {
            evm_rpc_types::EthSepoliaService::Alchemy => {
                cketh_common::eth_rpc_client::providers::EthSepoliaService::Alchemy
            }
            evm_rpc_types::EthSepoliaService::Ankr => {
                cketh_common::eth_rpc_client::providers::EthSepoliaService::Ankr
            }
            evm_rpc_types::EthSepoliaService::BlockPi => {
                cketh_common::eth_rpc_client::providers::EthSepoliaService::BlockPi
            }
            evm_rpc_types::EthSepoliaService::PublicNode => {
                cketh_common::eth_rpc_client::providers::EthSepoliaService::PublicNode
            }
            evm_rpc_types::EthSepoliaService::Sepolia => {
                cketh_common::eth_rpc_client::providers::EthSepoliaService::Sepolia
            }
        }
    }

    fn map_l2_mainnet_service(
        service: evm_rpc_types::L2MainnetService,
    ) -> cketh_common::eth_rpc_client::providers::L2MainnetService {
        match service {
            evm_rpc_types::L2MainnetService::Alchemy => {
                cketh_common::eth_rpc_client::providers::L2MainnetService::Alchemy
            }
            evm_rpc_types::L2MainnetService::Ankr => {
                cketh_common::eth_rpc_client::providers::L2MainnetService::Ankr
            }
            evm_rpc_types::L2MainnetService::BlockPi => {
                cketh_common::eth_rpc_client::providers::L2MainnetService::BlockPi
            }
            evm_rpc_types::L2MainnetService::PublicNode => {
                cketh_common::eth_rpc_client::providers::L2MainnetService::PublicNode
            }
            evm_rpc_types::L2MainnetService::Llama => {
                cketh_common::eth_rpc_client::providers::L2MainnetService::Llama
            }
        }
    }

    match source {
        evm_rpc_types::RpcService::Chain(id) => {
            cketh_common::eth_rpc_client::providers::RpcService::Chain(id)
        }
        evm_rpc_types::RpcService::Provider(id) => {
            cketh_common::eth_rpc_client::providers::RpcService::Provider(id)
        }
        evm_rpc_types::RpcService::Custom(rpc) => {
            cketh_common::eth_rpc_client::providers::RpcService::Custom(
                cketh_common::eth_rpc_client::providers::RpcApi {
                    url: rpc.url,
                    headers: rpc.headers,
                },
            )
        }
        evm_rpc_types::RpcService::EthMainnet(service) => {
            cketh_common::eth_rpc_client::providers::RpcService::EthMainnet(
                map_eth_mainnet_service(service),
            )
        }
        evm_rpc_types::RpcService::EthSepolia(service) => {
            cketh_common::eth_rpc_client::providers::RpcService::EthSepolia(
                map_eth_sepolia_service(service),
            )
        }
        evm_rpc_types::RpcService::ArbitrumOne(service) => {
            cketh_common::eth_rpc_client::providers::RpcService::ArbitrumOne(
                map_l2_mainnet_service(service),
            )
        }
        evm_rpc_types::RpcService::BaseMainnet(service) => {
            cketh_common::eth_rpc_client::providers::RpcService::BaseMainnet(
                map_l2_mainnet_service(service),
            )
        }
        evm_rpc_types::RpcService::OptimismMainnet(service) => {
            cketh_common::eth_rpc_client::providers::RpcService::OptimismMainnet(
                map_l2_mainnet_service(service),
            )
        }
    }
}

pub(super) fn into_rpc_api(
    rpc: evm_rpc_types::RpcApi,
) -> cketh_common::eth_rpc_client::providers::RpcApi {
    cketh_common::eth_rpc_client::providers::RpcApi {
        url: rpc.url,
        headers: rpc.headers,
    }
}

pub(super) fn into_rpc_services(
    source: evm_rpc_types::RpcServices,
    default_eth_mainnet_services: &[evm_rpc_types::EthMainnetService],
    default_eth_sepolia_services: &[evm_rpc_types::EthSepoliaService],
    default_l2_mainnet_services: &[evm_rpc_types::L2MainnetService],
) -> Vec<evm_rpc_types::RpcService> {
    match source {
        evm_rpc_types::RpcServices::Custom {
            chain_id: _,
            services,
        } => services
            .into_iter()
            .map(|service| evm_rpc_types::RpcService::Custom(service))
            .collect(),
        evm_rpc_types::RpcServices::EthMainnet(services) => services
            .unwrap_or_else(|| default_eth_mainnet_services.to_vec())
            .into_iter()
            .map(|service| evm_rpc_types::RpcService::EthMainnet(service))
            .collect(),
        evm_rpc_types::RpcServices::EthSepolia(services) => services
            .unwrap_or_else(|| default_eth_sepolia_services.to_vec())
            .into_iter()
            .map(|service| evm_rpc_types::RpcService::EthSepolia(service))
            .collect(),
        evm_rpc_types::RpcServices::ArbitrumOne(services) => services
            .unwrap_or_else(|| default_l2_mainnet_services.to_vec())
            .into_iter()
            .map(|service| evm_rpc_types::RpcService::ArbitrumOne(service))
            .collect(),
        evm_rpc_types::RpcServices::BaseMainnet(services) => services
            .unwrap_or_else(|| default_l2_mainnet_services.to_vec())
            .into_iter()
            .map(|service| evm_rpc_types::RpcService::BaseMainnet(service))
            .collect(),
        evm_rpc_types::RpcServices::OptimismMainnet(services) => services
            .unwrap_or_else(|| default_l2_mainnet_services.to_vec())
            .into_iter()
            .map(|service| evm_rpc_types::RpcService::OptimismMainnet(service))
            .collect(),
    }
}

pub(super) fn from_rpc_service(
    service: cketh_common::eth_rpc_client::providers::RpcService,
) -> evm_rpc_types::RpcService {
    fn map_eth_mainnet_service(
        service: cketh_common::eth_rpc_client::providers::EthMainnetService,
    ) -> evm_rpc_types::EthMainnetService {
        match service {
            cketh_common::eth_rpc_client::providers::EthMainnetService::Alchemy => {
                evm_rpc_types::EthMainnetService::Alchemy
            }
            cketh_common::eth_rpc_client::providers::EthMainnetService::Ankr => {
                evm_rpc_types::EthMainnetService::Ankr
            }
            cketh_common::eth_rpc_client::providers::EthMainnetService::BlockPi => {
                evm_rpc_types::EthMainnetService::BlockPi
            }
            cketh_common::eth_rpc_client::providers::EthMainnetService::PublicNode => {
                evm_rpc_types::EthMainnetService::PublicNode
            }
            cketh_common::eth_rpc_client::providers::EthMainnetService::Cloudflare => {
                evm_rpc_types::EthMainnetService::Cloudflare
            }
            cketh_common::eth_rpc_client::providers::EthMainnetService::Llama => {
                evm_rpc_types::EthMainnetService::Llama
            }
        }
    }

    fn map_eth_sepolia_service(
        service: cketh_common::eth_rpc_client::providers::EthSepoliaService,
    ) -> evm_rpc_types::EthSepoliaService {
        match service {
            cketh_common::eth_rpc_client::providers::EthSepoliaService::Alchemy => {
                evm_rpc_types::EthSepoliaService::Alchemy
            }
            cketh_common::eth_rpc_client::providers::EthSepoliaService::Ankr => {
                evm_rpc_types::EthSepoliaService::Ankr
            }
            cketh_common::eth_rpc_client::providers::EthSepoliaService::BlockPi => {
                evm_rpc_types::EthSepoliaService::BlockPi
            }
            cketh_common::eth_rpc_client::providers::EthSepoliaService::PublicNode => {
                evm_rpc_types::EthSepoliaService::PublicNode
            }
            cketh_common::eth_rpc_client::providers::EthSepoliaService::Sepolia => {
                evm_rpc_types::EthSepoliaService::Sepolia
            }
        }
    }

    fn map_l2_mainnet_service(
        service: cketh_common::eth_rpc_client::providers::L2MainnetService,
    ) -> evm_rpc_types::L2MainnetService {
        match service {
            cketh_common::eth_rpc_client::providers::L2MainnetService::Alchemy => {
                evm_rpc_types::L2MainnetService::Alchemy
            }
            cketh_common::eth_rpc_client::providers::L2MainnetService::Ankr => {
                evm_rpc_types::L2MainnetService::Ankr
            }
            cketh_common::eth_rpc_client::providers::L2MainnetService::BlockPi => {
                evm_rpc_types::L2MainnetService::BlockPi
            }
            cketh_common::eth_rpc_client::providers::L2MainnetService::PublicNode => {
                evm_rpc_types::L2MainnetService::PublicNode
            }
            cketh_common::eth_rpc_client::providers::L2MainnetService::Llama => {
                evm_rpc_types::L2MainnetService::Llama
            }
        }
    }

    match service {
        cketh_common::eth_rpc_client::providers::RpcService::Chain(id) => {
            evm_rpc_types::RpcService::Chain(id)
        }
        cketh_common::eth_rpc_client::providers::RpcService::Provider(id) => {
            evm_rpc_types::RpcService::Provider(id)
        }
        cketh_common::eth_rpc_client::providers::RpcService::Custom(rpc) => {
            evm_rpc_types::RpcService::Custom(evm_rpc_types::RpcApi {
                url: rpc.url,
                headers: rpc.headers.map(|headers| {
                    headers
                        .into_iter()
                        .map(|header| evm_rpc_types::HttpHeader {
                            name: header.name,
                            value: header.value,
                        })
                        .collect()
                }),
            })
        }
        cketh_common::eth_rpc_client::providers::RpcService::EthMainnet(service) => {
            evm_rpc_types::RpcService::EthMainnet(map_eth_mainnet_service(service))
        }
        cketh_common::eth_rpc_client::providers::RpcService::EthSepolia(service) => {
            evm_rpc_types::RpcService::EthSepolia(map_eth_sepolia_service(service))
        }
        cketh_common::eth_rpc_client::providers::RpcService::ArbitrumOne(service) => {
            evm_rpc_types::RpcService::ArbitrumOne(map_l2_mainnet_service(service))
        }
        cketh_common::eth_rpc_client::providers::RpcService::BaseMainnet(service) => {
            evm_rpc_types::RpcService::BaseMainnet(map_l2_mainnet_service(service))
        }
        cketh_common::eth_rpc_client::providers::RpcService::OptimismMainnet(service) => {
            evm_rpc_types::RpcService::OptimismMainnet(map_l2_mainnet_service(service))
        }
    }
}

pub(super) fn into_provider_error(
    error: evm_rpc_types::ProviderError,
) -> cketh_common::eth_rpc::ProviderError {
    match error {
        evm_rpc_types::ProviderError::NoPermission => {
            cketh_common::eth_rpc::ProviderError::NoPermission
        }
        evm_rpc_types::ProviderError::TooFewCycles { expected, received } => {
            cketh_common::eth_rpc::ProviderError::TooFewCycles { expected, received }
        }
        evm_rpc_types::ProviderError::ProviderNotFound => {
            cketh_common::eth_rpc::ProviderError::ProviderNotFound
        }
        evm_rpc_types::ProviderError::MissingRequiredProvider => {
            cketh_common::eth_rpc::ProviderError::MissingRequiredProvider
        }
    }
}

pub(super) fn into_rpc_error(value: evm_rpc_types::RpcError) -> cketh_common::eth_rpc::RpcError {
    fn map_http_outcall_error(
        error: evm_rpc_types::HttpOutcallError,
    ) -> cketh_common::eth_rpc::HttpOutcallError {
        match error {
            evm_rpc_types::HttpOutcallError::IcError { code, message } => {
                cketh_common::eth_rpc::HttpOutcallError::IcError { code, message }
            }
            evm_rpc_types::HttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error,
            } => cketh_common::eth_rpc::HttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error,
            },
        }
    }

    fn map_json_rpc_error(
        error: evm_rpc_types::JsonRpcError,
    ) -> cketh_common::eth_rpc::JsonRpcError {
        cketh_common::eth_rpc::JsonRpcError {
            code: error.code,
            message: error.message,
        }
    }

    fn map_validation_error(
        error: evm_rpc_types::ValidationError,
    ) -> cketh_common::eth_rpc::ValidationError {
        match error {
            evm_rpc_types::ValidationError::Custom(message) => {
                cketh_common::eth_rpc::ValidationError::Custom(message)
            }
            evm_rpc_types::ValidationError::InvalidHex(message) => {
                cketh_common::eth_rpc::ValidationError::InvalidHex(message)
            }
        }
    }

    match value {
        evm_rpc_types::RpcError::ProviderError(error) => into_provider_error(error).into(),
        evm_rpc_types::RpcError::HttpOutcallError(error) => map_http_outcall_error(error).into(),
        evm_rpc_types::RpcError::JsonRpcError(error) => map_json_rpc_error(error).into(),
        evm_rpc_types::RpcError::ValidationError(error) => map_validation_error(error).into(),
    }
}

fn from_provider_error(
    error: cketh_common::eth_rpc::ProviderError,
) -> evm_rpc_types::ProviderError {
    match error {
        cketh_common::eth_rpc::ProviderError::NoPermission => {
            evm_rpc_types::ProviderError::NoPermission
        }
        cketh_common::eth_rpc::ProviderError::TooFewCycles { expected, received } => {
            evm_rpc_types::ProviderError::TooFewCycles { expected, received }
        }
        cketh_common::eth_rpc::ProviderError::ProviderNotFound => {
            evm_rpc_types::ProviderError::ProviderNotFound
        }
        cketh_common::eth_rpc::ProviderError::MissingRequiredProvider => {
            evm_rpc_types::ProviderError::MissingRequiredProvider
        }
    }
}

pub(super) fn from_rpc_error(value: cketh_common::eth_rpc::RpcError) -> evm_rpc_types::RpcError {
    fn map_http_outcall_error(
        error: cketh_common::eth_rpc::HttpOutcallError,
    ) -> evm_rpc_types::HttpOutcallError {
        match error {
            cketh_common::eth_rpc::HttpOutcallError::IcError { code, message } => {
                evm_rpc_types::HttpOutcallError::IcError { code, message }
            }
            cketh_common::eth_rpc::HttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error,
            } => evm_rpc_types::HttpOutcallError::InvalidHttpJsonRpcResponse {
                status,
                body,
                parsing_error,
            },
        }
    }

    fn map_json_rpc_error(
        error: cketh_common::eth_rpc::JsonRpcError,
    ) -> evm_rpc_types::JsonRpcError {
        evm_rpc_types::JsonRpcError {
            code: error.code,
            message: error.message,
        }
    }

    fn map_validation_error(
        error: cketh_common::eth_rpc::ValidationError,
    ) -> evm_rpc_types::ValidationError {
        match error {
            cketh_common::eth_rpc::ValidationError::Custom(message) => {
                evm_rpc_types::ValidationError::Custom(message)
            }
            cketh_common::eth_rpc::ValidationError::InvalidHex(message) => {
                evm_rpc_types::ValidationError::InvalidHex(message)
            }
        }
    }

    match value {
        cketh_common::eth_rpc::RpcError::ProviderError(error) => from_provider_error(error).into(),
        cketh_common::eth_rpc::RpcError::HttpOutcallError(error) => {
            map_http_outcall_error(error).into()
        }
        cketh_common::eth_rpc::RpcError::JsonRpcError(error) => map_json_rpc_error(error).into(),
        cketh_common::eth_rpc::RpcError::ValidationError(error) => {
            map_validation_error(error).into()
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
    // TODO 243: cketh_common::address::Address should expose the underlying [u8; 20]
    // so that there is no artificial error handling here.
    value
        .to_string()
        .parse()
        .expect("BUG: Ethereum address cannot be parsed")
}
